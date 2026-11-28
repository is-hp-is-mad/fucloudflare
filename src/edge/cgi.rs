//! The edge's own endpoints under `/cdn-cgi/`.
//!
//! Whatever the host name, a request for a path in this namespace is
//! answered by the node it reaches and never passed to an origin (nor to
//! the WAF, the rules or the cache of a zone):
//!
//! - `/cdn-cgi/fucf-trace`: what the node sees of the visitor, as
//!   `key=value` lines in the manner of Cloudflare's `/cdn-cgi/trace`;
//! - `/cdn-cgi/fucf-warp` and everything below it: reserved, see [`super::warp`];
//! - `/cdn-cgi/limit/*`: the resources of the over-limit notice, see [`crate::limits`];
//! - `/cdn-cgi/challenge-platform/*`: the human check, see [`super::challenge`]
//!   (a zone's) and [`super::widget`] (the one sites embed, and its siteverify);
//! - anything else: 404.

use super::{full, warp, Body, Edge, EdgeError, TlsInfo};
use crate::limits::{self, State};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response};
use std::net::IpAddr;
use std::sync::Arc;

/// The part of a path after `/cdn-cgi/`, if it is in the namespace at all
/// (`/cdn-cgi` itself gives the empty string, `/cdn-cgi-bin` nothing).
pub fn endpoint(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/cdn-cgi")?;
    if rest.is_empty() {
        return Some("");
    }
    rest.strip_prefix('/')
}

fn text(body: String) -> Response<Body> {
    let mut resp = Response::new(full(body));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

impl Edge {
    /// Answer a request for `/cdn-cgi/<endpoint>`.
    pub(super) async fn cdn_cgi(
        self: Arc<Self>,
        endpoint: &str,
        ip: IpAddr,
        ssl: bool,
        req: Request<Body>,
        host: &str,
        ray: &str,
    ) -> Result<Response<Body>, EdgeError> {
        if endpoint == "challenge-platform/verify" {
            // the human check's answer (see `super::challenge`)
            // nothing borrowed may live across the await (a `Send` that is not general enough)
            let (waf, ray) = (self.waf.clone(), ray.to_string());
            return super::challenge::verify(waf, ip, ssl, req, ray).await;
        }
        if super::widget::handles(endpoint) {
            // the human check that sites put into their own pages, and its siteverify (see `super::widget`)
            let (edge, endpoint, host, ray) = (self.clone(), endpoint.to_string(), host.to_string(), ray.to_string());
            return Ok(super::widget::serve(edge, endpoint, ip, ssl, req, host, ray).await);
        }
        if endpoint == "challenge-platform/fcf.js" {
            // the script put into the site's pages (see `super::inject_script`)
            return Ok(super::challenge::injected_script());
        }
        if endpoint == "challenge-platform/ticket" {
            // a ticket for the injected script to pass the check in the background
            let snap = self.store.snapshot();
            let Some(zone) = snap.find_zone(host).filter(|z| Self::serves(z, host)) else { return Err(not_found()) };
            let ua = req.headers().get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default();
            let level = super::challenge::Level::of(&zone.zone.settings.security_level);
            return Ok(super::challenge::ticket_answer(&self.waf, &zone.zone.id, ip, ua, level));
        }
        let (name, below) = endpoint.split_once('/').map_or((endpoint, None), |(name, below)| (name, Some(below)));
        let internal = is_fucf_node(ip, &self.store.snapshot().nodes);
        let resp = match (name, below) {
            ("fucf-trace", None) => self.trace(ip, ssl, &req, host, ray),
            ("warp", _) if self.warp_upstream.get().is_some() => return warp::handle(self.clone(), warp::Visitor { ip, ssl, host, ray }, req).await,
            ("fucf-warp", _) => return warp::handle(self.clone(), warp::Visitor { ip, ssl, host, ray }, req).await,
            // The notice of a node over its traffic allowance takes its looks
            // from other nodes; asked for them itself (a stale DNS answer, or
            // someone trying to make it spend traffic), it has one line to say.
            ("limit", Some(_)) if !internal && self.limits.state() == State::Limited => limits::bare_notice(),
            ("limit", Some(asset)) => limits::asset(asset).ok_or_else(not_found)?,
            _ => return Err(not_found()),
        };
        if !internal {
            self.limits.add(hyper::body::Body::size_hint(resp.body()).exact().unwrap_or(0));
        }
        Ok(resp)
    }

    /// What this node sees of the visitor.
    fn trace(&self, ip: IpAddr, ssl: bool, req: &Request<Body>, host: &str, ray: &str) -> Response<Body> {
        let tls = req.extensions().get::<TlsInfo>();
        let location = self.geo.get().map(|geo| geo.locate(ip)).unwrap_or_default();
        let (_, limit) = self.limits.own();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let snap = self.store.snapshot();
        let zone = snap.find_zone(host).filter(|z| Self::serves(z, host)).map_or("-", |z| z.zone.name.as_str());
        let http = match req.version() {
            _ if req.extensions().get::<super::front::ViaFront>().is_some() => "http/3",
            hyper::Version::HTTP_3 => "http/3",
            hyper::Version::HTTP_2 => "http/2",
            hyper::Version::HTTP_10 => "http/1.0",
            _ => "http/1.1",
        };
        let agent = req.headers().get(header::USER_AGENT).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()).unwrap_or_default();
        let warp = warp_status(ip, &snap.nodes, location.asn);
        let Here { colo, dc, fl } = self.here();
        let user_agent = req.headers().get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
        let assessment = self.reputation.get().map(|r| r.assess(ip, location.asn.unwrap_or(0) as i64, location.as_org.as_deref().unwrap_or(""), user_agent)).unwrap_or_default();
        // scored as the rules would score it
        let scored = crate::expr::ReqInfo {
            ssl,
            headers: super::header_pairs(req.headers()),
            ja4: tls.map(|t| t.ja4.clone()).unwrap_or_default(),
            threat: assessment.score as i64,
            ..Default::default()
        };
        let bot = super::botscore::score(&super::botscore::Signals::of(req, &scored, assessment.verified_crawler()));
        // The first keys are Cloudflare's, with their meaning; ours follow.
        let lines = [
            ("fl", fl),
            ("h", host.to_string()),
            ("ip", ip.to_string()),
            ("ts", format!("{}.{:03}", now.as_secs(), now.subsec_millis())),
            ("visit_scheme", if ssl { "https" } else { "http" }.to_string()),
            ("uag", agent),
            ("colo", colo),
            ("dc", dc.to_string()),
            ("http", http.to_string()),
            ("loc", location.country.unwrap_or_else(|| "XX".into())),
            ("tls", tls.map_or("off", |t| t.version).to_string()),
            ("sni", if tls.is_some_and(|t| t.sni) { "plaintext" } else { "off" }.to_string()),
            ("warp", warp.to_string()),
            ("kex", tls.map(|t| t.kex.clone()).unwrap_or_default()),
            ("ja4", tls.map(|t| t.ja4.clone()).unwrap_or_default()),
            ("ray", ray.to_string()),
            ("asn", location.asn.map(|n| n.to_string()).unwrap_or_default()),
            ("zone", zone.to_string()),
            ("limit", limit.as_str().to_string()),
            ("threat", assessment.score.to_string()),
            ("bot", bot.to_string()),
            // a client certificate `--mtls-ca` verified (crate::edge::mtls)
            ("client_cert", if tls.is_some_and(|t| t.client_cert_verified) { "verified" } else { "none" }.to_string()),
            ("region", location.region.unwrap_or_default()),
        ];
        let body: String = lines.iter().map(|(key, value)| format!("{key}={value}\n")).collect();
        let mut resp = text(body);
        resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        resp
    }
}

fn not_found() -> EdgeError {
    EdgeError::new(404, "Not found", "there is no such endpoint on this edge")
}

/// A short plain-text answer with a status of the edge's own.
pub(super) fn plain(status: u16, body: &str) -> Response<Body> {
    let mut resp = text(body.to_string());
    *resp.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    resp
}

/// Split a node name into `(COLO, dc)`: trailing digits become `dc` (default 1),
/// e.g. `us` -> `("US", 1)`, `us2` -> `("US", 2)`, unless overridden by `configured_dc`.
/// Where this node is, as visitors are told (trace, error pages).
pub struct Here {
    /// Airport code of the location.
    pub colo: String,
    /// Which machine at that location.
    pub dc: u32,
    /// `<dc>f<process>`: tells machines (and restarts) apart, like Cloudflare's `fl`.
    pub fl: String,
}

impl Edge {
    pub(super) fn here(&self) -> Here {
        let (node, _) = self.limits.own();
        let node = if node.is_empty() { "local".to_string() } else { node };
        let snap = self.store.snapshot();
        let me = snap.nodes.iter().find(|n| n.name.eq_ignore_ascii_case(&node));
        let (colo, dc) = colo_and_dc(&node, me.and_then(|n| n.colo.as_deref()), me.and_then(|n| n.dc));
        Here { fl: format!("{dc}f{}", std::process::id()), colo, dc }
    }
}

fn colo_and_dc(node: &str, configured_colo: Option<&str>, configured_dc: Option<u32>) -> (String, u32) {
    let trimmed = node.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = &node[trimmed.len()..];
    let colo = configured_colo.unwrap_or(if trimmed.is_empty() { node } else { trimmed }).to_ascii_uppercase();
    let dc = configured_dc.unwrap_or_else(|| digits.parse::<u32>().ok().filter(|&n| n >= 1).unwrap_or(1));
    (colo, dc)
}

/// Whether `ip` belongs to one of our own configured fucf edge nodes (`warp=fucf`),
/// excluding Cloudflare and all other external visitors.
pub(super) fn is_fucf_node(ip: IpAddr, nodes: &[crate::items::EdgeNode]) -> bool {
    let ip = ip.to_canonical();
    nodes.iter().any(|n| match ip {
        IpAddr::V4(v4) => n.ipv4 == Some(v4),
        IpAddr::V6(v6) => n.ipv6 == Some(v6),
    })
}

/// Value of `warp=` in `/cdn-cgi/fucf-trace`:
/// - `fucf` when the visitor IP matches any configured CDN edge node;
/// - `cloudflare` when the visitor IP belongs to Cloudflare (official IP ranges or AS13335);
/// - `off` otherwise.
fn warp_status(ip: IpAddr, nodes: &[crate::items::EdgeNode], asn: Option<u32>) -> &'static str {
    let ip = ip.to_canonical();
    if is_fucf_node(ip, nodes) {
        return "fucf";
    }
    if asn == Some(13335) || is_cloudflare_ip(ip) {
        return "cloudflare";
    }
    "off"
}

fn is_cloudflare_ip(ip: IpAddr) -> bool {
    const CF_V4: [([u8; 4], u32); 15] = [
        ([173, 245, 48, 0], 20),
        ([103, 21, 244, 0], 22),
        ([103, 22, 200, 0], 22),
        ([103, 31, 4, 0], 22),
        ([141, 101, 64, 0], 18),
        ([108, 162, 192, 0], 18),
        ([190, 93, 240, 0], 20),
        ([188, 114, 96, 0], 20),
        ([197, 234, 240, 0], 22),
        ([198, 41, 128, 0], 17),
        ([162, 158, 0, 0], 15),
        ([104, 16, 0, 0], 13),
        ([104, 24, 0, 0], 14),
        ([172, 64, 0, 0], 13),
        ([131, 0, 72, 0], 22),
    ];
    const CF_V6: [([u16; 8], u32); 7] = [
        ([0x2400, 0xcb00, 0, 0, 0, 0, 0, 0], 32),
        ([0x2606, 0x4700, 0, 0, 0, 0, 0, 0], 32),
        ([0x2803, 0xf800, 0, 0, 0, 0, 0, 0], 32),
        ([0x2405, 0xb500, 0, 0, 0, 0, 0, 0], 32),
        ([0x2405, 0x8100, 0, 0, 0, 0, 0, 0], 32),
        ([0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0], 29),
        ([0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0], 32),
    ];
    match ip {
        IpAddr::V4(v4) => {
            let addr = u32::from(v4);
            CF_V4.iter().any(|(net, prefix)| {
                let mask = u32::MAX.checked_shl(32 - *prefix).unwrap_or(0);
                (addr & mask) == (u32::from_be_bytes(*net) & mask)
            })
        }
        IpAddr::V6(v6) => {
            let addr = u128::from(v6);
            CF_V6.iter().any(|(net, prefix)| {
                let mut n = 0u128;
                for seg in net {
                    n = (n << 16) | (*seg as u128);
                }
                let mask = u128::MAX.checked_shl(128 - *prefix).unwrap_or(0);
                (addr & mask) == (n & mask)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::EdgeNode;

    #[test]
    fn trace_warp_identifies_fucf_and_cloudflare() {
        let node: EdgeNode = serde_json::from_value(serde_json::json!({
            "name": "sgp",
            "ipv4": "198.51.100.10",
            "ipv6": "2001:db8::10"
        }))
        .unwrap();
        let nodes = [node];
        assert_eq!(warp_status("198.51.100.10".parse().unwrap(), &nodes, None), "fucf");
        assert_eq!(warp_status("2001:db8::10".parse().unwrap(), &nodes, None), "fucf");
        assert_eq!(warp_status("104.16.132.229".parse().unwrap(), &nodes, None), "cloudflare");
        assert_eq!(warp_status("172.68.10.5".parse().unwrap(), &nodes, None), "cloudflare");
        assert_eq!(warp_status("2606:4700:4700::1111".parse().unwrap(), &nodes, None), "cloudflare");
        assert_eq!(warp_status("8.8.8.8".parse().unwrap(), &nodes, Some(13335)), "cloudflare");
        assert_eq!(warp_status("127.0.0.1".parse().unwrap(), &nodes, None), "off");
        assert_eq!(warp_status("192.0.2.1".parse().unwrap(), &nodes, Some(15169)), "off");
        assert_eq!(colo_and_dc("us", None, None), ("US".into(), 1));
        assert_eq!(colo_and_dc("us2", None, None), ("US".into(), 2));
        assert_eq!(colo_and_dc("sgp", None, None), ("SGP".into(), 1));
        assert_eq!(colo_and_dc("us", None, Some(3)), ("US".into(), 3));
        assert_eq!(colo_and_dc("us2", Some("cmh"), None), ("CMH".into(), 2));
        assert_eq!(colo_and_dc("jp", Some("NRT"), Some(1)), ("NRT".into(), 1));
    }
}
