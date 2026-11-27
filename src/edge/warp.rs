//! `/cdn-cgi/fucf-warp`: edge-local streaming proxy endpoint (e.g. Xray xhttp).
//!
//! Requests for `/cdn-cgi/fucf-warp` and everything below it end at the edge
//! node they reach: no origin DNS lookup, no zone, no WAF, no cache, and no
//! CDN traffic-quota metering are involved, and any host name works.
//!
//! When `--warp-upstream` (`FUCF_WARP_UPSTREAM`) is configured (e.g.
//! `h2c://127.0.0.1:10002/ray`, `https://127.0.0.1:10002/ray`, or
//! `h2c://127.0.0.1:2443/`), requests are streamed directly to that local
//! backend with `/cdn-cgi/fucf-warp` rewritten to the upstream's base path.
//! Without `--warp-upstream`, every request receives `501 Not Implemented`.

use super::upstream::{Target, Tls};
use super::{cache, cgi, streaming, Body, Edge, EdgeError};
use bytes::Bytes;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Under this name (in place of a zone id) the endpoint's objects are kept
/// in the edge cache, and its purges are recorded in the configuration.
pub const CACHE_SCOPE: &str = "cdn-cgi:fucf-warp";
const MOUNT_PREFIX: &str = "/cdn-cgi/fucf-warp";

/// Configured local streaming backend for `/cdn-cgi/fucf-warp`.
#[derive(Debug, Clone)]
pub struct WarpUpstream {
    pub target: Target,
    pub base_path: String,
}

impl WarpUpstream {
    /// Parse `http://`, `h2c://`, or `https://` upstream URL (with optional base path).
    pub fn parse(url: &str) -> Result<Self, String> {
        let (tls, h2, default_port, rest) = if let Some(r) = url.strip_prefix("h2c://") {
            (Tls::Off, true, 80, r)
        } else if let Some(r) = url.strip_prefix("https://") {
            (Tls::NoVerify, true, 443, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (Tls::Off, false, 80, r)
        } else {
            return Err(format!("--warp-upstream '{url}' must start with http://, h2c://, or https://"));
        };
        let uri: Uri = format!("http://{rest}").parse().map_err(|e| format!("invalid --warp-upstream '{url}': {e}"))?;
        let authority = uri.authority().ok_or_else(|| format!("--warp-upstream '{url}' has no host"))?;
        let host = authority.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let port = authority.port_u16().unwrap_or(default_port);
        let base_path = uri.path().trim_end_matches('/').to_string();
        Ok(WarpUpstream {
            target: Target {
                host: host.clone(),
                alternates: Vec::new(),
                port,
                tls,
                sni: host.clone(),
                host_header: host,
                h2,
                block_private_ips: false,
            },
            base_path,
        })
    }
}

fn rewrite_path_and_query(pq: &str, base_path: &str) -> String {
    let (path, query) = pq.split_once('?').map_or((pq, None), |(p, q)| (p, Some(q)));
    let tail = path
        .strip_prefix("/cdn-cgi/warp")
        .or_else(|| path.strip_prefix(MOUNT_PREFIX))
        .unwrap_or("");
    let joined = match (base_path.is_empty(), tail.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => tail.to_string(),
        (false, true) => base_path.to_string(),
        (false, false) => format!("{base_path}{tail}"),
    };
    match query {
        Some(q) => format!("{joined}?{q}"),
        None => joined,
    }
}

fn cache_key(key: &str) -> String {
    format!("{CACHE_SCOPE}|{key}")
}

/// The object stored under `key`, unless it has expired.
#[allow(dead_code)]
pub fn cached(edge: &Edge, key: &str) -> Option<Arc<cache::Entry>> {
    edge.cache.get(&cache_key(key)).filter(|entry| entry.fresh())
}

/// Keep an object for `ttl`. Purges name objects by `key`: exactly, or by a prefix of it.
#[allow(dead_code)]
pub fn store(edge: &Edge, key: &str, status: StatusCode, headers: HeaderMap, body: Bytes, ttl: Duration) {
    let entry = cache::Entry { status, headers, body, stored: Instant::now(), ttl, zone_id: CACHE_SCOPE.to_string(), url: key.to_string() };
    edge.cache.put(cache_key(key), entry);
}

/// Who is asking, as far as the edge knows.
#[allow(dead_code)]
pub struct Visitor<'a> {
    pub ip: IpAddr,
    /// Did the request come in over TLS?
    pub ssl: bool,
    /// The host name the request was made for.
    pub host: &'a str,
    pub ray: &'a str,
}

const HOP_BY_HOP: &[&str] = &["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

pub async fn handle(edge: Arc<Edge>, visitor: Visitor<'_>, req: Request<Body>) -> Result<Response<Body>, EdgeError> {
    let Some(up) = edge.warp_upstream.get() else {
        return Ok(cgi::plain(501, "fucf-warp is reserved: this endpoint does not do anything yet.\n"));
    };

    let (parts, body) = req.into_parts();
    let pq = parts.uri.path_and_query().map(|x| x.as_str()).unwrap_or(MOUNT_PREFIX);
    let rewritten = rewrite_path_and_query(pq, &up.base_path);
    let uri: Uri = rewritten
        .parse()
        .map_err(|_| EdgeError::new(400, "Bad request", "invalid path for warp upstream"))?;

    let mut out = Request::builder().method(parts.method).uri(uri);
    for (name, value) in &parts.headers {
        let lower = name.as_str();
        if lower == "host" || HOP_BY_HOP.contains(&lower) {
            continue;
        }
        out = out.header(name, value);
    }
    if let Ok(v) = HeaderValue::from_str(visitor.host) {
        out = out.header(header::HOST, v);
    }
    if let Ok(v) = HeaderValue::from_str(&visitor.ip.to_string()) {
        out = out.header("x-forwarded-for", v.clone()).header("x-real-ip", v);
    }
    out = out.header("x-forwarded-proto", if visitor.ssl { "https" } else { "http" });

    let out_req = out.body(body).map_err(|e| EdgeError::new(502, "Bad gateway", e.to_string()))?;
    let resp = edge
        .upstream
        .send(&up.target, out_req)
        .await
        .map_err(|_| EdgeError::new(404, "Not found", "there is no such endpoint on this edge"))?;

    // Mask any 4xx/5xx from the local xhttp backend (such as HTTP 400 on a
    // bare browser GET) as fucf's standard 404 so probes cannot distinguish
    // /cdn-cgi/warp from any non-existent /cdn-cgi/* path.
    if resp.status().is_client_error() || resp.status().is_server_error() {
        return Err(EdgeError::new(404, "Not found", "there is no such endpoint on this edge"));
    }

    let (mut rparts, rbody) = resp.into_parts();
    for h in HOP_BY_HOP {
        rparts.headers.remove(*h);
    }
    Ok(Response::from_parts(rparts, streaming(rbody)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_warp_upstream_and_rewrites_paths() {
        let u = WarpUpstream::parse("h2c://127.0.0.1:10002/ray").unwrap();
        assert_eq!((u.target.host.as_str(), u.target.port, u.target.tls, u.target.h2, u.base_path.as_str()), ("127.0.0.1", 10002, Tls::Off, true, "/ray"));
        assert_eq!(rewrite_path_and_query("/cdn-cgi/warp", &u.base_path), "/ray");
        assert_eq!(rewrite_path_and_query("/cdn-cgi/warp/abc/0?x=1", &u.base_path), "/ray/abc/0?x=1");
        assert_eq!(rewrite_path_and_query("/cdn-cgi/fucf-warp", &u.base_path), "/ray");
        assert_eq!(rewrite_path_and_query("/cdn-cgi/fucf-warp/abc/0?x=1", &u.base_path), "/ray/abc/0?x=1");

        let root = WarpUpstream::parse("h2c://127.0.0.1:2443/").unwrap();
        assert_eq!(root.base_path, "");
        assert_eq!(rewrite_path_and_query("/cdn-cgi/warp", &root.base_path), "/");
        assert_eq!(rewrite_path_and_query("/cdn-cgi/warp/abc/0", &root.base_path), "/abc/0");

        let tls = WarpUpstream::parse("https://127.0.0.1:10002/ray").unwrap();
        assert_eq!((tls.target.tls, tls.target.h2), (Tls::NoVerify, true));
    }
}
