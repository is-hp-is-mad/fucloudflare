//! Native high-performance reverse proxy (`LocalProxyRule`) and Hysteria 2
//! masquerade fallback.

use super::{full, set_headers, streaming, strip_hop_by_hop, Body, Edge, EdgeError, ORIGIN_COOLDOWN};
use crate::items::{LocalProxyRule, ProxyUpstream};
use bytes::Bytes;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Metadata attached by edge/front/proxy listeners so `LocalProxyRule`
/// matching knows the listener port and whether fallback catch-all applies.
#[derive(Clone, Debug)]
pub struct ListenerInfo {
    pub port: u16,
    pub is_proxy: bool,
    pub is_front: bool,
}

pub fn host_matches(hosts: &[String], host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    hosts.iter().any(|pat| {
        let pat = pat.trim().trim_end_matches('.').to_ascii_lowercase();
        if pat == "*" || pat == host {
            return true;
        }
        if let Some(suffix) = pat.strip_prefix("*.") {
            return host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
        }
        false
    })
}

pub fn path_matches(prefix: &str, exact: bool, path: &str) -> bool {
    if exact {
        return path == prefix;
    }
    if prefix == "/" {
        return true;
    }
    if prefix.ends_with('/') {
        return path.starts_with(prefix);
    }
    path == prefix || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

fn rule_scope_ok(rule: &LocalProxyRule, node_name: Option<&str>, listener: Option<&ListenerInfo>) -> bool {
    if !rule.enabled {
        return false;
    }
    if !rule.nodes.is_empty() && !node_name.is_some_and(|n| rule.nodes.iter().any(|rn| rn.eq_ignore_ascii_case(n))) {
        return false;
    }
    if let Some(port) = rule.listen_port {
        if !listener.is_some_and(|l| l.port == port) {
            return false;
        }
    }
    true
}

/// Match a non-fallback `LocalProxyRule` by node, port, host, and path.
/// `rules` is expected to be pre-sorted by `(priority, !exact_path, Reverse(path_prefix.len()))`.
pub fn match_rule<'a>(
    rules: &'a [LocalProxyRule],
    node_name: Option<&str>,
    listener: Option<&ListenerInfo>,
    host: &str,
    path: &str,
) -> Option<&'a LocalProxyRule> {
    rules.iter().find(|r| {
        if r.is_fallback || !rule_scope_ok(r, node_name, listener) {
            return false;
        }
        let host_ok = if r.hosts.is_empty() {
            r.listen_port.is_some() && listener.is_some_and(|l| l.port == r.listen_port.unwrap())
        } else {
            host_matches(&r.hosts, host)
        };
        host_ok && path_matches(&r.path_prefix, r.exact_path, path)
    })
}

/// Match a catch-all fallback rule (`is_fallback == true`) on Hysteria 2 front
/// or `--proxy-listen` / `--proxy-tls-listen` listeners.
pub fn match_fallback<'a>(
    rules: &'a [LocalProxyRule],
    node_name: Option<&str>,
    listener: Option<&ListenerInfo>,
    host: &str,
    path: &str,
) -> Option<&'a LocalProxyRule> {
    let l = listener?;
    if !(l.is_front || l.is_proxy) {
        return None;
    }
    rules.iter().find(|r| {
        if !r.is_fallback || !rule_scope_ok(r, node_name, Some(l)) {
            return false;
        }
        let host_ok = r.hosts.is_empty() || host_matches(&r.hosts, host);
        host_ok && path_matches(&r.path_prefix, r.exact_path, path)
    })
}

/// Weighted round-robin selection with passive health cooldown ordering.
fn ordered_upstreams(edge: &Edge, rule: &LocalProxyRule) -> Vec<ProxyUpstream> {
    let now = Instant::now();
    let down = edge.down.lock().unwrap();
    let (mut healthy, mut cooled): (Vec<ProxyUpstream>, Vec<ProxyUpstream>) = rule
        .upstreams
        .iter()
        .cloned()
        .partition(|u| !down.get(&u.url).is_some_and(|until| *until > now));
    drop(down);

    if healthy.is_empty() {
        healthy = std::mem::take(&mut cooled);
    }
    if healthy.len() > 1 {
        let total: u64 = healthy.iter().map(|u| u64::from(u.weight.max(1))).sum();
        let pick = (edge.rr.fetch_add(1, Ordering::Relaxed) as u64) % total.max(1);
        let mut acc = 0u64;
        let mut start = 0usize;
        for (i, u) in healthy.iter().enumerate() {
            acc += u64::from(u.weight.max(1));
            if pick < acc {
                start = i;
                break;
            }
        }
        healthy.rotate_left(start);
    }
    healthy.extend(cooled);
    healthy
}

fn join_upstream_path(base: &str, req_pq: &str) -> String {
    if base.is_empty() {
        return req_pq.to_string();
    }
    if req_pq == "/" {
        return base.to_string();
    }
    format!("{base}{req_pq}")
}

fn rewrite_proxy_pq(rule: &LocalProxyRule, req_pq: &str) -> String {
    let (path, query) = req_pq.split_once('?').map_or((req_pq, None), |(p, q)| (p, Some(q)));
    let mut new_path = path.to_string();
    if rule.strip_prefix && rule.path_prefix != "/" {
        let prefix = rule.path_prefix.trim_end_matches('/');
        if let Some(rest) = new_path.strip_prefix(prefix) {
            new_path = if rest.is_empty() {
                "/".to_string()
            } else if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{rest}")
            };
        }
    }
    if let Some(rp) = &rule.rewrite_path {
        if rule.strip_prefix {
            let base = rp.trim_end_matches('/');
            new_path = if new_path == "/" {
                if base.is_empty() { "/".to_string() } else { base.to_string() }
            } else {
                format!("{base}{new_path}")
            };
        } else {
            new_path = rp.clone();
        }
    }
    match query {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    }
}

/// Forward a request through a matched `LocalProxyRule` with streaming bodies,
/// WebSocket `101` splicing, header manipulation, and multi-upstream failover.
pub async fn forward(
    edge: &Edge,
    rule: &LocalProxyRule,
    ip: IpAddr,
    ssl: bool,
    host: &str,
    mut req: Request<Body>,
) -> Result<Response<Body>, EdgeError> {
    if rule.https_redirect && !ssl {
        let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let authority = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        let mut out = Response::new(full(Bytes::new()));
        *out.status_mut() = StatusCode::PERMANENT_REDIRECT;
        if let Ok(hv) = HeaderValue::from_str(&format!("https://{authority}{pq}")) {
            out.headers_mut().insert(header::LOCATION, hv);
        }
        return Ok(out);
    }
    if let Some(loc) = &rule.redirect_url {
        let code = rule.redirect_status.unwrap_or(302);
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FOUND);
        let mut out = Response::new(full(Bytes::new()));
        *out.status_mut() = status;
        if let Ok(hv) = HeaderValue::from_str(loc) {
            out.headers_mut().insert(header::LOCATION, hv);
        }
        for name in &rule.strip_response_headers {
            if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
                out.headers_mut().remove(hn);
            }
        }
        set_headers(out.headers_mut(), &rule.set_response_headers);
        return Ok(out);
    }

    // a fixed answer (Caddy's `respond`) or files (`file_server`): no upstream involved
    let local = if let Some(r) = &rule.respond {
        let mut out = Response::new(full(if req.method() == Method::HEAD { Bytes::new() } else { Bytes::from(r.body.clone()) }));
        *out.status_mut() = StatusCode::from_u16(r.status).unwrap_or(StatusCode::OK);
        let ct = r.content_type.as_deref().unwrap_or("text/plain; charset=utf-8");
        if let Ok(v) = HeaderValue::from_str(ct) {
            out.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        Some(out)
    } else if let Some(root) = &rule.file_root {
        let raw_pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let pq = rewrite_proxy_pq(rule, raw_pq);
        let path = pq.split('?').next().unwrap_or("/");
        Some(super::files::serve(root, &rule.index_files, path, req.method(), req.headers()).await)
    } else {
        None
    };
    if let Some(mut out) = local {
        for name in &rule.strip_response_headers {
            if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
                out.headers_mut().remove(hn);
            }
        }
        set_headers(out.headers_mut(), &rule.set_response_headers);
        return Ok(out);
    }

    let orig_host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| host.to_string());

    let is_upgrade = req.version() == hyper::Version::HTTP_11 && req.headers().contains_key(header::UPGRADE);
    let on_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut req));
    let upgrade_proto = req.headers().get(header::UPGRADE).cloned().filter(|_| is_upgrade);

    let (parts, body) = req.into_parts();
    let method = parts.method;
    let raw_pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let req_pq = rewrite_proxy_pq(rule, raw_pq);

    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);
    headers.remove(header::HOST);
    if let Some(proto) = &upgrade_proto {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, proto.clone());
    }

    let ip_str = ip.to_string();
    let prev_xff: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let xff = if prev_xff.is_empty() {
        ip_str.clone()
    } else {
        format!("{}, {ip_str}", prev_xff.join(", "))
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    if let Ok(v) = HeaderValue::from_str(&ip_str) {
        headers.insert("x-real-ip", v);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static(if ssl { "https" } else { "http" }));
    let hops: u8 = headers
        .get("fucf-loop")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if let Ok(v) = HeaderValue::from_str(&(hops.saturating_add(1)).to_string()) {
        headers.insert("fucf-loop", v);
    }
    set_headers(&mut headers, &rule.set_request_headers);

    let empty_body = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE)
        && headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            == 0
        && !headers.contains_key(header::TRANSFER_ENCODING)
        && !is_upgrade;

    let candidates = ordered_upstreams(edge, rule);
    let mut body_opt = if empty_body { None } else { Some(body) };
    let mut resp_opt = None;
    let mut last_err = None;

    for (idx, up) in candidates.iter().enumerate() {
        let (mut target, base_path) = super::upstream::Target::from_proxy_url(&up.url, up.tls_insecure)
            .map_err(|e| EdgeError::origin(502, super::ORIGIN_MISCONFIGURED, e))?;
        if rule.preserve_host {
            target.host_header = orig_host_header.clone();
        }
        let upstream_uri: hyper::Uri = join_upstream_path(&base_path, &req_pq)
            .parse()
            .map_err(|_| EdgeError::new(400, "Bad request", "invalid request URI"))?;

        let attempt_body = if empty_body {
            full(Bytes::new())
        } else {
            body_opt.take().unwrap_or_else(|| full(Bytes::new()))
        };

        let mut out_req = Request::new(attempt_body);
        *out_req.method_mut() = method.clone();
        *out_req.uri_mut() = upstream_uri;
        *out_req.headers_mut() = headers.clone();

        match edge.upstream.send(&target, out_req).await {
            Ok(resp) => {
                resp_opt = Some(resp);
                break;
            }
            Err(e) => {
                if matches!(e, super::upstream::UpstreamError::Down(_) | super::upstream::UpstreamError::Timeout) {
                    edge.down.lock().unwrap().insert(up.url.clone(), Instant::now() + ORIGIN_COOLDOWN);
                }
                let more = idx + 1 < candidates.len();
                let retryable = empty_body && matches!(e, super::upstream::UpstreamError::Down(_) | super::upstream::UpstreamError::Timeout);
                last_err = Some(EdgeError::from(e));
                if !(more && retryable) {
                    break;
                }
            }
        }
    }

    let mut resp = match resp_opt {
        Some(r) => r,
        None => return Err(last_err.unwrap_or_else(|| EdgeError::origin(502, super::ORIGIN_NOT_CONFIGURED, "no upstream available"))),
    };

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_side) = on_upgrade else {
            return Err(EdgeError::origin(502, super::ORIGIN_BAD_RESPONSE, "unexpected protocol switch by upstream"));
        };
        let origin_side = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            if let (Ok(c), Ok(o)) = tokio::join!(client_side, origin_side) {
                let _ = super::copy_bidirectional_idle(
                    &mut TokioIo::new(c),
                    &mut TokioIo::new(o),
                    std::time::Duration::from_secs(300),
                )
                .await;
            }
        });
        let (mut rparts, _) = resp.into_parts();
        for name in &rule.strip_response_headers {
            if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
                rparts.headers.remove(hn);
            }
        }
        set_headers(&mut rparts.headers, &rule.set_response_headers);
        let mut out = Response::new(full(Bytes::new()));
        *out.status_mut() = rparts.status;
        *out.headers_mut() = rparts.headers;
        return Ok(out);
    }

    let (mut rparts, rbody) = resp.into_parts();
    strip_hop_by_hop(&mut rparts.headers);
    for name in &rule.strip_response_headers {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            rparts.headers.remove(hn);
        }
    }
    set_headers(&mut rparts.headers, &rule.set_response_headers);
    if rule.mask_upstream_errors && rparts.status.as_u16() >= 400 {
        let mut out = Response::new(full(Bytes::from_static(b"not found")));
        *out.status_mut() = StatusCode::NOT_FOUND;
        out.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
        for name in &rule.strip_response_headers {
            if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
                out.headers_mut().remove(hn);
            }
        }
        set_headers(out.headers_mut(), &rule.set_response_headers);
        return Ok(out);
    }
    Ok(Response::from_parts(rparts, streaming(rbody)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::cache::Cache;
    use crate::edge::waf::Waf;
    use crate::store::Store;
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioTimer;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_http_server<F, Fut>(handler: F) -> std::net::SocketAddr
    where
        F: Fn(Request<hyper::body::Incoming>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response<Body>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let h = handler.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let h = h.clone();
                        async move { Ok::<_, std::convert::Infallible>(h(req).await) }
                    });
                    let mut b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                    b.http1().timer(TokioTimer::new());
                    b.http2().timer(TokioTimer::new());
                    let _ = b.serve_connection_with_upgrades(TokioIo::new(stream), svc).await;
                });
            }
        });
        addr
    }

    fn make_store() -> (Arc<Store>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("fucf-proxy-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(Store::open(&dir.join("state.json"), vec![]).unwrap());
        (store, dir)
    }

    fn make_edge(store: Arc<Store>) -> Arc<Edge> {
        Arc::new(Edge::new(store, Arc::new(Cache::new(1 << 20)), Arc::new(Waf::new()), vec![]).unwrap())
    }

    #[test]
    fn host_and_path_matching_and_ordering() {
        let (store, dir) = make_store();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "prefix-short",
                    "hosts": ["app.example.com"],
                    "path_prefix": "/api",
                    "upstreams": [{"url": "http://127.0.0.1:9001"}],
                    "priority": 10
                }),
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "prefix-long",
                    "hosts": ["*.example.com"],
                    "path_prefix": "/api/v2",
                    "upstreams": [{"url": "http://127.0.0.1:9002"}],
                    "priority": 10
                }),
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "exact",
                    "hosts": ["app.example.com"],
                    "path_prefix": "/api/v2",
                    "exact_path": true,
                    "upstreams": [{"url": "http://127.0.0.1:9003"}],
                    "priority": 10
                }),
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "high-prio",
                    "hosts": ["app.example.com"],
                    "path_prefix": "/admin",
                    "upstreams": [{"url": "http://127.0.0.1:9004"}],
                    "priority": 1
                }),
            )
            .unwrap();

        let snap = store.snapshot();
        // exact_path beats prefix at same priority & length
        assert_eq!(
            match_rule(&snap.local_proxy_rules, None, None, "app.example.com", "/api/v2").unwrap().name,
            "exact"
        );
        // longer prefix matches subpaths
        assert_eq!(
            match_rule(&snap.local_proxy_rules, None, None, "app.example.com", "/api/v2/users").unwrap().name,
            "prefix-long"
        );
        // boundary-aware prefix: /apiv2 does not match /api
        assert!(match_rule(&snap.local_proxy_rules, None, None, "app.example.com", "/apiv2").is_none());
        // wildcard *.example.com does not match apex example.com
        assert!(match_rule(&snap.local_proxy_rules, None, None, "example.com", "/api/v2/users").is_none());
        // priority 1
        assert_eq!(
            match_rule(&snap.local_proxy_rules, None, None, "app.example.com", "/admin/panel").unwrap().name,
            "high-prio"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn weighted_lb_failover_and_headers() {
        let c1 = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::new(AtomicUsize::new(0));
        let c1_clone = c1.clone();
        let addr1 = spawn_http_server(move |req| {
            let c1 = c1_clone.clone();
            async move {
                c1.fetch_add(1, Ordering::Relaxed);
                let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let custom = req.headers().get("x-req-add").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let xff = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let mut resp = Response::new(full(format!("up1:{host}:{custom}:{xff}")));
                resp.headers_mut().insert("x-strip-me", HeaderValue::from_static("secret"));
                resp
            }
        })
        .await;

        let c2_clone = c2.clone();
        let addr2 = spawn_http_server(move |_req| {
            let c2 = c2_clone.clone();
            async move {
                c2.fetch_add(1, Ordering::Relaxed);
                Response::new(full("up2"))
            }
        })
        .await;

        // Dead port for failover test
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let (store, dir) = make_store();
        let r1 = store
            .save_proxy_rule(
                None,
                json!({
                    "name": "lb-and-headers",
                    "hosts": ["svc.example.com"],
                    "upstreams": [
                        {"url": format!("http://{dead_addr}"), "weight": 100},
                        {"url": format!("http://{addr1}"), "weight": 1},
                        {"url": format!("http://{addr2}"), "weight": 1}
                    ],
                    "preserve_host": true,
                    "strip_response_headers": ["x-strip-me"],
                    "set_request_headers": {"x-req-add": "hello"},
                    "set_response_headers": {"x-resp-add": "world"}
                }),
            )
            .unwrap();

        let edge = make_edge(store.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(crate::edge::serve_proxy_with_resolver(listener, edge.clone(), None, false));

        // Send requests via proxy listener
        for _ in 0..4 {
            let mut req = Request::new(full(Bytes::new()));
            *req.uri_mut() = format!("http://{proxy_addr}/test").parse().unwrap();
            req.headers_mut().insert(header::HOST, HeaderValue::from_static("svc.example.com"));
            let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
            let resp = client.request(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(resp.headers().get("x-strip-me").is_none());
            assert_eq!(resp.headers().get("x-resp-add").unwrap(), "world");
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let text = String::from_utf8_lossy(&body);
            if text.starts_with("up1:") {
                assert!(text.contains("svc.example.com:hello:"), "got {text}");
            } else {
                assert_eq!(text, "up2");
            }
        }
        assert!(c1.load(Ordering::Relaxed) >= 1 && c2.load(Ordering::Relaxed) >= 1);

        // Verify dead_addr was cooled down
        assert!(edge.down.lock().unwrap().contains_key(&format!("http://{dead_addr}")));
        let _ = r1;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn h2c_upstream_and_streaming_body() {
        let addr = spawn_http_server(|req| async move {
            assert_eq!(req.version(), hyper::Version::HTTP_2);
            let body = req.into_body().collect().await.unwrap().to_bytes();
            Response::new(full(body))
        })
        .await;

        let (store, dir) = make_store();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "h2c-stream",
                    "hosts": ["grpc.example.com"],
                    "upstreams": [{"url": format!("h2c://{addr}")}],
                    "preserve_host": false
                }),
            )
            .unwrap();

        let edge = make_edge(store);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(crate::edge::serve_proxy_with_resolver(listener, edge, None, false));

        // 2 MiB streaming payload (> INSPECT_LIMIT)
        let payload = vec![b'z'; 2 * 1024 * 1024];
        let mut req = Request::new(full(Bytes::from(payload.clone())));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = format!("http://{proxy_addr}/stream").parse().unwrap();
        req.headers_mut().insert(header::HOST, HeaderValue::from_static("grpc.example.com"));
        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(got.len(), payload.len());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn websocket_upgrade_tunnel() {
        let ws_addr = spawn_http_server(|mut req| async move {
            let on_up = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                if let Ok(upgraded) = on_up.await {
                    let mut io = TokioIo::new(upgraded);
                    let mut buf = [0u8; 64];
                    if let Ok(n) = io.read(&mut buf).await {
                        let _ = io.write_all(&buf[..n]).await;
                    }
                }
            });
            let mut resp = Response::new(full(Bytes::new()));
            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            resp.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            resp.headers_mut().insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            resp
        })
        .await;

        let (store, dir) = make_store();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "ws-proxy",
                    "hosts": ["ws.example.com"],
                    "upstreams": [{"url": format!("ws://{ws_addr}")}]
                }),
            )
            .unwrap();

        let edge = make_edge(store);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(crate::edge::serve_proxy_with_resolver(listener, edge, None, false));

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(
                b"GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(head.contains("101 Switching Protocols"), "got: {head}");

        stream.write_all(b"ping-ws").await.unwrap();
        let mut echo = [0u8; 7];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping-ws");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn hy2_front_fallback_serves_unmatched_hosts_and_preserves_zones() {
        let fb_addr = spawn_http_server(|req| async move {
            let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            Response::new(full(format!("hy2-fallback:{host}:{}", req.uri().path())))
        })
        .await;
        let zone_origin = spawn_http_server(|_req| async move { Response::new(full("zone-origin")) }).await;

        let (store, dir) = make_store();
        let z = store.create_zone("hosted.example").unwrap();
        store
            .create_record(
                &z.id,
                crate::store::RecordInput {
                    name: "www.hosted.example".into(),
                    rtype: "A".into(),
                    content: "127.0.0.1".into(),
                    ttl: 300,
                    priority: None,
                    proxied: true,
                    comment: None,
                    origin: Some(crate::store::RecordOrigin {
                        port: Some(zone_origin.port()),
                        scheme: Some("http".into()),
                        ..Default::default()
                    }),
                },
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "hy2-masquerade-catchall",
                    "is_fallback": true,
                    "upstreams": [{"url": format!("http://{fb_addr}")}]
                }),
            )
            .unwrap();

        let edge = make_edge(store);
        let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front_listener.local_addr().unwrap();
        tokio::spawn(crate::edge::front::serve_with_limit(front_listener, edge, 64));

        let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();

        // 1. Unmatched host on front goes to Hy2 fallback instead of 404
        let mut req = Request::new(full(Bytes::new()));
        *req.uri_mut() = format!("http://{front_addr}/ray/abc").parse().unwrap();
        req.headers_mut().insert(header::HOST, HeaderValue::from_static("hy2.example.com"));
        req.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&body), "hy2-fallback:hy2.example.com:/ray/abc");

        // 2. Hosted zone on front still routes through Zone pipeline
        let mut req2 = Request::new(full(Bytes::new()));
        *req2.uri_mut() = format!("http://{front_addr}/").parse().unwrap();
        req2.headers_mut().insert(header::HOST, HeaderValue::from_static("www.hosted.example"));
        req2.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
        let resp2 = client.request(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&body2), "zone-origin");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn node_and_port_scoping_and_case_insensitive_hosts() {
        let (store, dir) = make_store();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "au-port-3443",
                    "nodes": ["AU"],
                    "listen_port": 3443,
                    "hosts": [],
                    "upstreams": [{"url": "http://127.0.0.1:9001"}]
                }),
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "eu-host",
                    "nodes": ["eu"],
                    "hosts": ["App.Example.COM"],
                    "upstreams": [{"url": "http://127.0.0.1:9002"}]
                }),
            )
            .unwrap();

        let snap = store.snapshot();
        let l3443 = ListenerInfo { port: 3443, is_proxy: true, is_front: false };
        let l443 = ListenerInfo { port: 443, is_proxy: false, is_front: false };

        // Case-insensitive node_name match + empty hosts on matching listen_port
        assert_eq!(
            match_rule(&snap.local_proxy_rules, Some("AU"), Some(&l3443), "anything.invalid", "/").unwrap().name,
            "au-port-3443"
        );
        assert_eq!(
            match_rule(&snap.local_proxy_rules, Some("au"), Some(&l3443), "anything.invalid", "/").unwrap().name,
            "au-port-3443"
        );
        // Wrong port or wrong node does not match
        assert!(match_rule(&snap.local_proxy_rules, Some("au"), Some(&l443), "anything.invalid", "/").is_none());
        assert!(match_rule(&snap.local_proxy_rules, Some("sgp"), Some(&l3443), "anything.invalid", "/").is_none());
        // Case-insensitive host_matches
        assert_eq!(
            match_rule(&snap.local_proxy_rules, Some("EU"), Some(&l443), "APP.EXAMPLE.COM.", "/v1").unwrap().name,
            "eu-host"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn tls_proxy_listener_and_insecure_https_base_path_upstream() {
        // Self-signed HTTPS origin
        let cert = rcgen::generate_simple_self_signed(vec!["origin.internal".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let origin_tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(crate::edge::tls::crypto())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap(),
        );
        let origin_acceptor = tokio_rustls::TlsAcceptor::from(origin_tls);
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = origin_listener.accept().await {
                let acc = origin_acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acc.accept(stream).await {
                        let svc = hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async move {
                            let proto = req
                                .headers()
                                .get("x-forwarded-proto")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            Ok::<_, std::convert::Infallible>(Response::new(full(format!(
                                "https-origin:{}:{proto}",
                                req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
                            ))))
                        });
                        let mut b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                        b.http1().timer(TokioTimer::new());
                        b.http2().timer(TokioTimer::new());
                        let _ = b.serve_connection(TokioIo::new(tls), svc).await;
                    }
                });
            }
        });

        let (store, dir) = make_store();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "tls-base-path",
                    "hosts": ["tls.example.com"],
                    "upstreams": [{"url": format!("https://{origin_addr}/base"), "tls_insecure": true}]
                }),
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "tls-fallback",
                    "is_fallback": true,
                    "upstreams": [{"url": format!("https://{origin_addr}/fb"), "tls_insecure": true}]
                }),
            )
            .unwrap();

        let edge = make_edge(store.clone());
        let (cfg, resolver) = crate::edge::tls::server_config_with_resolver(store).unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(crate::edge::serve_proxy_with_resolver(
            proxy_listener,
            edge,
            Some((cfg, Some(resolver))),
            false,
        ));

        let client_tls = crate::edge::tls::client_config(false).unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_tls);

        // 1. Matched host via --proxy-tls-listen path
        let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let tls = connector
            .connect(rustls::pki_types::ServerName::try_from("tls.example.com").unwrap(), tcp)
            .await
            .unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        let mut req = Request::new(full(Bytes::new()));
        *req.uri_mut() = "/items?a=1".parse().unwrap();
        req.headers_mut().insert(header::HOST, HeaderValue::from_static("tls.example.com"));
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&body), "https-origin:/base/items?a=1:https");

        // 2. Unmatched host on TLS proxy listener hits is_fallback rule
        let mut req2 = Request::new(full(Bytes::new()));
        *req2.uri_mut() = "/".parse().unwrap();
        req2.headers_mut().insert(header::HOST, HeaderValue::from_static("unknown.example.com"));
        let resp2 = sender.send_request(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&body2), "https-origin:/fb:https");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn caddy_parity_rewrite_redirect_mask_and_h3_proxy_listener() {
        let dir = std::env::temp_dir().join(format!("fucf-proxy-caddy-{}", uuid::Uuid::new_v4().simple()));
        let store = Arc::new(Store::open(&dir.join("cfg.json"), vec![]).unwrap());
        let cache = Arc::new(Cache::new(4 << 20));
        let edge = Arc::new(Edge::new(store.clone(), cache, Arc::new(Waf::new()), vec![]).unwrap());
        let _ = edge.node_name.set("jp".into());

        let up_addr = spawn_http_server(|req| async move {
            let pq = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
            if pq.starts_with("/err") {
                return Response::builder().status(502).body(full(Bytes::from("internal err"))).unwrap();
            }
            Response::new(full(Bytes::from(format!("up:{pq}"))))
        })
        .await;

        // 1. redirect_url (exact_path "/")
        store.save_proxy_rule(None, json!({
            "name": "root-redir",
            "hosts": ["caddy.example.com"],
            "path_prefix": "/",
            "exact_path": true,
            "redirect_url": "/admin",
            "redirect_status": 302,
            "priority": 1
        })).unwrap();

        // 2. strip_prefix + rewrite_path
        store.save_proxy_rule(None, json!({
            "name": "strip-rw",
            "hosts": ["caddy.example.com"],
            "path_prefix": "/api",
            "strip_prefix": true,
            "rewrite_path": "/v2",
            "upstreams": [{"url": format!("http://{up_addr}")}],
            "priority": 2
        })).unwrap();

        // 3. mask_upstream_errors
        store.save_proxy_rule(None, json!({
            "name": "mask-err",
            "hosts": ["caddy.example.com"],
            "path_prefix": "/err",
            "mask_upstream_errors": true,
            "upstreams": [{"url": format!("http://{up_addr}")}],
            "priority": 3
        })).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        tokio::spawn(crate::edge::serve_proxy_with_resolver(listener, edge.clone(), None, false));

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await.unwrap();
        tokio::spawn(conn);

        // Test redirect_url
        let mut r1 = Request::new(full(Bytes::new()));
        *r1.uri_mut() = "/".parse().unwrap();
        r1.headers_mut().insert(header::HOST, HeaderValue::from_static("caddy.example.com"));
        let res1 = sender.send_request(r1).await.unwrap();
        assert_eq!(res1.status(), StatusCode::FOUND);
        assert_eq!(res1.headers().get(header::LOCATION).unwrap(), "/admin");

        // Test strip_prefix + rewrite_path
        let mut r2 = Request::new(full(Bytes::new()));
        *r2.uri_mut() = "/api/users?q=1".parse().unwrap();
        r2.headers_mut().insert(header::HOST, HeaderValue::from_static("caddy.example.com"));
        let res2 = sender.send_request(r2).await.unwrap();
        assert_eq!(res2.status(), StatusCode::OK);
        let b2 = res2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&b2), "up:/v2/users?q=1");

        // Test mask_upstream_errors
        let mut r3 = Request::new(full(Bytes::new()));
        *r3.uri_mut() = "/err/boom".parse().unwrap();
        r3.headers_mut().insert(header::HOST, HeaderValue::from_static("caddy.example.com"));
        let res3 = sender.send_request(r3).await.unwrap();
        assert_eq!(res3.status(), StatusCode::NOT_FOUND);
        let b3 = res3.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&b3), "not found");

        // Test h3::serve_with_proxy(..., is_proxy: true) routing through LocalProxyRule
        let z = store.create_zone("caddy.example.com").unwrap().id;
        let cert = rcgen::generate_simple_self_signed(vec!["caddy.example.com".into()]).unwrap();
        store.save_item::<crate::items::Certificate>(&z, None, json!({
            "hosts": ["caddy.example.com"],
            "certificate": cert.cert.pem(),
            "private_key": cert.signing_key.serialize_pem(),
        }), true).unwrap();
        let quic = crate::edge::h3::endpoint("127.0.0.1:0".parse().unwrap(), store.clone()).unwrap();
        let h3_port = quic.local_addr().unwrap().port();
        tokio::spawn(crate::edge::h3::serve_with_proxy(quic, edge.clone(), true));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec())).unwrap();
        let mut tls_cfg = rustls::ClientConfig::builder_with_provider(crate::edge::tls::crypto())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
        let q_cfg = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg).unwrap()));
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(q_cfg);
        let conn = client_ep.connect(([127, 0, 0, 1], h3_port).into(), "caddy.example.com").unwrap().await.unwrap();
        let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move { let _ = futures_util_poll(&mut driver).await; });
        let req_h3 = Request::get("https://caddy.example.com/api/h3").body(()).unwrap();
        let mut stream = send_req.send_request(req_h3).await.unwrap();
        stream.finish().await.unwrap();
        let resp_h3 = stream.recv_response().await.unwrap();
        assert_eq!(resp_h3.status(), StatusCode::OK);
        let chunk = stream.recv_data().await.unwrap().unwrap();
        use bytes::Buf;
        let bytes = chunk.chunk();
        assert_eq!(String::from_utf8_lossy(bytes), "up:/v2/h3");

        let _ = std::fs::remove_dir_all(dir);
    }

    async fn futures_util_poll<T, C>(driver: &mut h3::client::Connection<C, T>)
    where
        C: h3::quic::Connection<T>,
        T: bytes::Buf,
    {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    }
}
