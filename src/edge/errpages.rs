//! Custom error pages: a zone may replace the pages the edge writes by
//! itself (origin errors, the firewall's block page, the rate limit page and
//! the node's other notices) with HTML of its own, through the zone setting
//! `error_pages`.
//!
//! Only pages meant for a browser are replaced. gRPC clients, `fetch` / XHR
//! and API clients (see [`super::challenge::is_navigation`]) keep what they
//! get today, and so do the human check's pages, which carry their own
//! script and must stay exactly as the edge builds them. The status code and
//! every header stay as they are; only the body (and its length) changes.
//!
//! Which template answers which page:
//!
//! | key | page |
//! | --- | --- |
//! | `5xx` | an error in reaching the origin, written by the edge (502, 521, 522, 525, 530: every [`EdgeError`] that carries an origin fault) |
//! | `block` | the firewall's block page (403: managed rules and firewall rules with `block`) |
//! | `ratelimit` | the rate limit page (429) |
//! | `1xxx` | every other page the node writes for a request of the zone: unreadable requests (400), payload too large (413), HTTP/3 not enabled (421), worker failures (500, 503), ... |
//!
//! Pages written before the request is known to belong to a zone are never
//! replaced: unknown hosts, the node's own `/cdn-cgi/` endpoints, loops, the
//! node's traffic limit, the "node updating" page. There is no zone whose
//! template could apply.

use super::{full, Body, Edge, EdgeError};
use crate::store::StoreError;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{self, HeaderValue};
use hyper::Response;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Largest template, in bytes of UTF-8: the page is held in every node's
/// configuration and copied with it, so a zone cannot make it arbitrarily big.
pub const MAX_BYTES: usize = 64 * 1024;

/// The templates a zone may set, keyed as in the setting.
pub const KEYS: [&str; 4] = ["5xx", "block", "ratelimit", "1xxx"];

/// The placeholders a template may use, each replaced once, in one pass.
const PLACEHOLDERS: [&str; 6] = ["::RAY_ID::", "::STATUS::", "::CLIENT_IP::", "::HOST::", "::NODE::", "::ERROR_BOX::"];

/// The zone setting `error_pages`: HTML templates by [`KEYS`].
///
/// Reading it is lenient (unknown keys from a newer node are kept and
/// ignored, so a zone still loads and syncs); [`ErrorPages::validate`] is
/// what refuses them when someone sets the value. An empty template is the
/// same as none and is dropped as it is read, so it never shows up as set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ErrorPages(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for ErrorPages {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut pages = BTreeMap::<String, String>::deserialize(d)?;
        pages.retain(|_, html| !html.is_empty());
        Ok(ErrorPages(pages))
    }
}

impl ErrorPages {
    /// The template for one kind of page, if the zone set one.
    pub fn get(&self, kind: Kind) -> Option<&str> {
        self.0.get(kind.key()).map(String::as_str)
    }

    /// Only the four known keys, each at most [`MAX_BYTES`]: a typo in a key
    /// would otherwise be a template that silently never shows.
    pub fn validate(&self) -> Result<(), StoreError> {
        for (key, html) in &self.0 {
            if !KEYS.contains(&key.as_str()) {
                return Err(StoreError::Invalid(format!("error_pages: unknown key '{key}' (the keys are {})", KEYS.join(", "))));
            }
            if html.len() > MAX_BYTES {
                return Err(StoreError::Invalid(format!("error_pages.{key} is {} bytes; at most {MAX_BYTES}", html.len())));
            }
        }
        Ok(())
    }
}

/// Which of the edge's own pages a response is. The edge puts it on the
/// response (as an extension) where it builds the page, because only there
/// is it known: the block page and the human check share a status code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An error in reaching the origin.
    Origin,
    /// The firewall's block page.
    Block,
    /// The rate limit page.
    RateLimit,
    /// Any other notice of the node.
    Node,
}

impl Kind {
    /// The key of the template for this kind of page.
    pub fn key(self) -> &'static str {
        match self {
            Kind::Origin => "5xx",
            Kind::Block => "block",
            Kind::RateLimit => "ratelimit",
            Kind::Node => "1xxx",
        }
    }

    /// The kind of the page answering an error of the pipeline.
    pub fn of(e: &EdgeError) -> Kind {
        if e.origin.is_some() {
            Kind::Origin
        } else {
            Kind::Node
        }
    }
}

/// Tag a page the edge built by itself, so [`apply`] knows what it is.
pub fn mark(mut resp: Response<Body>, kind: Kind) -> Response<Body> {
    resp.extensions_mut().insert(kind);
    resp
}

/// What the placeholders stand for, unescaped. `error_box` is HTML the edge
/// wrote itself and goes in as it is; everything else is escaped.
pub struct Values<'a> {
    pub ray: &'a str,
    pub status: u16,
    pub client_ip: &'a str,
    pub host: &'a str,
    pub node: &'a str,
    pub error_box: &'a str,
}

/// For text and for attributes in either kind of quotes.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Fill in a template in a single pass over it: a value that itself looks
/// like a placeholder (a host name cannot, but a template author should not
/// have to think about it) is never expanded again.
pub fn render(template: &str, v: &Values) -> String {
    let values = [escape(v.ray), v.status.to_string(), escape(v.client_ip), escape(v.host), escape(v.node)];
    let mut out = String::with_capacity(template.len() + v.error_box.len());
    let mut rest = template;
    while let Some(at) = rest.find("::") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        match PLACEHOLDERS.iter().position(|p| tail.starts_with(p)) {
            Some(i) => {
                out.push_str(if i < values.len() { &values[i] } else { v.error_box });
                rest = &tail[PLACEHOLDERS[i].len()..];
            }
            // not a placeholder here, but one may start at the next colon (":::HOST::")
            None => {
                out.push(':');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `::ERROR_BOX::`: the main part of the default page -- its stylesheet and
/// the contents of its `<body>` (the text in both languages with the switch
/// between them, the path of the request, Ray ID and node). Every value the
/// default page takes from the request is escaped where that page is built
/// (`super::page_with` and `super::path_html` run them through `escape`),
/// so the markers searched for here cannot come from the request.
fn error_box(page: &str) -> String {
    let between = |open: &str, close: &str| -> Option<String> {
        let start = page.find(open)? + open.len();
        let end = page.rfind(close)?;
        (start <= end).then(|| page[start..end].to_string())
    };
    let style = between("<style>", "</style>").map(|css| format!("<style>{css}</style>")).unwrap_or_default();
    style + &between("<body>", "</body>").unwrap_or_default()
}

/// Replace a page the edge built by itself with the zone's template, where
/// one is set and the request came from a browser. Everything else passes
/// through untouched: a response the edge did not [`mark`], a request that is
/// not a page load (`browser` false), one that belongs to no zone (`zone` is
/// `(zone id, host)` as the pipeline saw it), a zone without that template.
pub(super) async fn apply(edge: &Edge, resp: Response<Body>, browser: bool, zone: Option<(&str, &str)>, client: IpAddr, ray: &str) -> Response<Body> {
    let Some(&kind) = resp.extensions().get::<Kind>() else { return resp };
    let Some((zone_id, host)) = zone.filter(|_| browser) else { return resp };
    let snap = edge.store.snapshot();
    let template = snap.host_zone(host).filter(|z| z.zone.id == zone_id).and_then(|z| z.zone.settings.error_pages.get(kind));
    let Some(template) = template else { return resp };
    let (mut parts, body) = resp.into_parts();
    // the edge's pages are whole in memory: this does not wait on anything
    let default = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };
    let client = client.to_string();
    let node = edge.here().colo;
    let error_box = error_box(&String::from_utf8_lossy(&default));
    let values = Values { ray, status: parts.status.as_u16(), client_ip: &client, host, node: &node, error_box: &error_box };
    let html = render(template, &values);
    parts.headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    if parts.headers.contains_key(header::CONTENT_LENGTH) {
        parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(html.len()));
    }
    Response::from_parts(parts, full(html))
}

#[cfg(test)]
mod tests {
    use super::super::{respond, Cache, Waf};
    use super::*;
    use crate::items::{FirewallRule, OriginRule, RateLimit, Settings};
    use crate::store::testutil::{rec, temp_store};
    use crate::store::Store;
    use hyper::{Request, StatusCode, Version};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn values<'a>(host: &'a str, error_box: &'a str) -> Values<'a> {
        Values { ray: "0123456789abcdef", status: 502, client_ip: "198.51.100.7", host, node: "SIN", error_box }
    }

    fn pages(v: Value) -> Result<ErrorPages, String> {
        let pages: ErrorPages = serde_json::from_value(v).map_err(|e| e.to_string())?;
        pages.validate().map_err(|e| format!("{e:?}"))?;
        Ok(pages)
    }

    #[test]
    fn every_placeholder_is_replaced_and_its_value_escaped() {
        let html = render(
            "<p>::RAY_ID:: ::STATUS:: ::CLIENT_IP:: ::HOST:: ::NODE::</p><a title='::HOST::'>x</a>",
            &values("<b>\"x\"&'y'.example.com", ""),
        );
        assert_eq!(
            html,
            "<p>0123456789abcdef 502 198.51.100.7 &lt;b&gt;&quot;x&quot;&amp;&#39;y&#39;.example.com SIN</p>\
             <a title='&lt;b&gt;&quot;x&quot;&amp;&#39;y&#39;.example.com'>x</a>"
        );
    }

    #[test]
    fn the_error_box_goes_in_as_the_edge_wrote_it() {
        let html = render("<div>::ERROR_BOX::</div>", &values("example.com", "<main><h1>Error</h1></main>"));
        assert_eq!(html, "<div><main><h1>Error</h1></main></div>");
    }

    #[test]
    fn a_value_that_looks_like_a_placeholder_is_not_expanded_again() {
        let html = render("::HOST::|::ERROR_BOX::", &values("::RAY_ID::", "::STATUS::"));
        assert_eq!(html, "::RAY_ID::|::STATUS::");
    }

    #[test]
    fn colons_that_are_no_placeholder_stay_as_they_are() {
        assert_eq!(render(":::HOST::::", &values("example.com", "")), ":example.com::");
        assert_eq!(render("a::b ::ray_id:: ::RAY_ID ::", &values("example.com", "")), "a::b ::ray_id:: ::RAY_ID ::");
        assert_eq!(render("::RAY_ID::RAY_ID::", &values("example.com", "")), "0123456789abcdefRAY_ID::");
        assert_eq!(render("", &values("example.com", "")), "");
        assert_eq!(render("::", &values("example.com", "")), "::");
        // multi-byte text around the placeholders is kept whole
        assert_eq!(render("出错了：::STATUS::。", &values("example.com", "")), "出错了：502。");
    }

    #[test]
    fn the_four_keys_are_accepted_and_others_refused() {
        let all = pages(json!({ "5xx": "a", "block": "b", "ratelimit": "c", "1xxx": "d" })).unwrap();
        assert_eq!((all.get(Kind::Origin), all.get(Kind::Block), all.get(Kind::RateLimit), all.get(Kind::Node)), (Some("a"), Some("b"), Some("c"), Some("d")));
        for bad in ["500", "5XX", "Block", "rate_limit", " 5xx", "", "1000"] {
            assert!(pages(json!({ bad: "x" })).unwrap_err().contains("unknown key"), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_template_may_be_64_kib_and_not_one_byte_more() {
        assert!(pages(json!({ "5xx": "x".repeat(MAX_BYTES) })).is_ok());
        let err = pages(json!({ "5xx": "x".repeat(MAX_BYTES + 1) })).unwrap_err();
        assert!(err.contains("65537 bytes") && err.contains("65536"), "{err}");
        // the limit counts bytes, not characters
        let wide = "é".repeat(MAX_BYTES / 2);
        assert!(pages(json!({ "block": wide })).is_ok());
        assert!(pages(json!({ "block": format!("{wide}x") })).is_err());
    }

    #[test]
    fn an_empty_template_is_the_same_as_none() {
        let p = pages(json!({ "5xx": "", "block": "b" })).unwrap();
        assert_eq!((p.get(Kind::Origin), p.get(Kind::Block)), (None, Some("b")));
        assert_eq!(serde_json::to_value(&p).unwrap(), json!({ "block": "b" }));
        assert_eq!(pages(json!({})).unwrap(), ErrorPages::default());
    }

    #[test]
    fn values_other_than_a_map_of_strings_are_refused() {
        for bad in [json!(null), json!("<p>x</p>"), json!(["5xx"]), json!({ "5xx": 1 }), json!({ "5xx": null }), json!({ "5xx": { "html": "x" } })] {
            assert!(pages(bad.clone()).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn unknown_keys_still_load_but_never_render() {
        // what a newer node may have stored must not break reading the zone
        let p: ErrorPages = serde_json::from_value(json!({ "9xx": "x", "5xx": "y" })).unwrap();
        assert!(p.validate().is_err());
        assert_eq!(p.get(Kind::Origin), Some("y"));
    }

    #[test]
    fn settings_carry_the_pages_and_check_them() {
        let s: Settings = serde_json::from_value(json!({ "error_pages": { "ratelimit": "<p>slow down</p>" } })).unwrap();
        assert_eq!(s.error_pages.get(Kind::RateLimit), Some("<p>slow down</p>"));
        assert!(s.validate().is_ok());
        let s: Settings = serde_json::from_value(json!({ "error_pages": { "teapot": "x" } })).unwrap();
        assert!(s.validate().is_err());
        assert_eq!(Settings::default().error_pages, ErrorPages::default());
        assert_eq!(serde_json::to_value(Settings::default()).unwrap()["error_pages"], json!({}));
    }

    #[test]
    fn the_error_box_is_the_style_and_body_of_the_default_page() {
        let page = "<!doctype html><html><head><style>p{x:1}</style></head><body><main>m</main><script>s</script></body></html>";
        assert_eq!(error_box(page), "<style>p{x:1}</style><main>m</main><script>s</script>");
        assert_eq!(error_box("no markup at all"), "");
    }

    // ------------------------------------------------- through the edge ----

    struct Env {
        store: Arc<Store>,
        edge: Arc<Edge>,
        zone: String,
    }

    /// A zone whose names go to the local machine and whose origin is a port
    /// nothing listens on, so any request that gets that far fails with 521.
    fn env() -> Env {
        let store = Arc::new(temp_store());
        let zone = store.create_zone("example.com").unwrap().id;
        for name in ["@", "*"] {
            let mut r = rec(name, "A", "127.0.0.1");
            r.proxied = true;
            store.create_record(&zone, r).unwrap();
        }
        store.save_item::<OriginRule>(&zone, None, json!({ "expression": "", "origin_port": 1, "priority": 100 }), true).unwrap();
        let fw = json!({ "expression": "http.request.uri.path eq \"/admin\"", "action": "block" });
        store.save_item::<FirewallRule>(&zone, None, fw, true).unwrap();
        let check = json!({ "expression": "http.request.uri.path eq \"/shop\"", "action": "managed_challenge" });
        store.save_item::<FirewallRule>(&zone, None, check, true).unwrap();
        let limit = json!({ "expression": "http.request.uri.path eq \"/login\"", "threshold": 1, "period": 60, "mitigation_timeout": 60 });
        store.save_item::<RateLimit>(&zone, None, limit, true).unwrap();
        let edge = Arc::new(Edge::new(store.clone(), Arc::new(Cache::new(1 << 20)), Arc::new(Waf::new()), vec![]).unwrap());
        Env { store, edge, zone }
    }

    const PAGES: &str = "::RAY_ID::|::STATUS::|::CLIENT_IP::|::HOST::|::NODE::";

    fn set_all(env: &Env) {
        let v = json!({ "5xx": format!("origin {PAGES}"), "block": format!("block {PAGES}"), "ratelimit": format!("limit {PAGES}"), "1xxx": format!("node {PAGES}") });
        env.store.update_setting(&env.zone, "error_pages", v).unwrap();
    }

    struct Got {
        status: StatusCode,
        headers: hyper::HeaderMap,
        body: String,
    }

    async fn ask(env: &Env, version: Version, host: &str, path: &str, headers: &[(&str, &str)]) -> Got {
        let mut req = Request::builder().version(version).uri(path).header("host", host);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let peer: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let resp = respond(env.edge.clone(), peer, false, req.body(full(Bytes::new())).unwrap()).await;
        let (parts, body) = resp.into_parts();
        let body = body.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
        Got { status: parts.status, headers: parts.headers, body: String::from_utf8_lossy(&body).into_owned() }
    }

    async fn page(env: &Env, path: &str) -> Got {
        ask(env, Version::HTTP_11, "www.example.com", path, &[("accept", "text/html")]).await
    }

    fn ray(got: &Got) -> &str {
        got.headers.get("fucf-ray").and_then(|v| v.to_str().ok()).unwrap()
    }

    #[tokio::test]
    async fn each_kind_of_page_gets_its_own_template() {
        let env = env();
        set_all(&env);
        let colo = env.edge.here().colo;
        for (path, status, word) in [("/", 521, "origin"), ("/admin", 403, "block")] {
            let got = page(&env, path).await;
            assert_eq!(got.status.as_u16(), status);
            assert_eq!(got.body, format!("{word} {}|{status}|198.51.100.7|www.example.com|{colo}", ray(&got)), "{path}");
            assert_eq!(got.headers.get("content-type").unwrap(), "text/html; charset=utf-8");
            assert_eq!(got.headers.get("cache-control").unwrap(), "no-store");
        }
        assert_eq!(page(&env, "/login").await.status, 521, "the first request is within the limit");
        let limited = page(&env, "/login").await;
        assert_eq!(limited.status, 429);
        assert!(limited.body.starts_with("limit ") && limited.body.contains("|429|"), "{}", limited.body);
        assert!(limited.headers.get("retry-after").is_some(), "headers stay as they are");
        // the node's own notice: HTTP/3 is switched off for the zone
        env.store.update_setting(&env.zone, "http3", json!(false)).unwrap();
        let node = ask(&env, Version::HTTP_3, "www.example.com", "/", &[("accept", "text/html")]).await;
        assert_eq!(node.status, 421);
        assert!(node.body.starts_with("node ") && node.body.contains("|421|"), "{}", node.body);
    }

    #[tokio::test]
    async fn the_error_box_carries_the_default_page() {
        let env = env();
        env.store.update_setting(&env.zone, "error_pages", json!({ "5xx": "<h1>Example</h1>::ERROR_BOX::<p>::STATUS::</p>" })).unwrap();
        let got = page(&env, "/").await;
        assert!(got.body.starts_with("<h1>Example</h1><style>"), "{}", got.body);
        assert!(got.body.contains("Origin error") && got.body.contains(super::super::ORIGIN_DOWN.zh) && got.body.contains(ray(&got)), "{}", got.body);
        assert!(got.body.ends_with("</script><p>521</p>"), "{}", got.body);
        assert!(!got.body.contains("<html") && !got.body.contains("<body>"), "only the main part, not a page in a page");
    }

    #[tokio::test]
    async fn without_a_template_the_default_page_is_sent() {
        let env = env();
        env.store.update_setting(&env.zone, "error_pages", json!({ "block": "custom" })).unwrap();
        let got = page(&env, "/").await;
        assert_eq!(got.status, 521);
        assert!(got.body.starts_with("<!doctype html>") && got.body.contains("Origin error"), "{}", got.body);
        // an empty template is no template
        env.store.update_setting(&env.zone, "error_pages", json!({ "block": "" })).unwrap();
        assert!(page(&env, "/admin").await.body.contains("Access denied"));
        assert_eq!(env.store.get_zone(&env.zone).unwrap().settings.error_pages, ErrorPages::default());
    }

    #[tokio::test]
    async fn requests_that_are_not_page_loads_keep_the_default_answer() {
        let env = env();
        set_all(&env);
        let fetch = ask(&env, Version::HTTP_11, "www.example.com", "/admin", &[("sec-fetch-mode", "cors")]).await;
        assert!(fetch.status == 403 && fetch.body.contains("Access denied"), "{}", fetch.body);
        let xhr = ask(&env, Version::HTTP_11, "www.example.com", "/", &[("accept", "text/html"), ("x-requested-with", "XMLHttpRequest")]).await;
        assert!(xhr.status == 521 && xhr.body.contains("Origin error"), "{}", xhr.body);
        let api = ask(&env, Version::HTTP_11, "www.example.com", "/", &[("accept", "application/json")]).await;
        assert!(api.body.contains("Origin error"), "{}", api.body);
        // gRPC gets its status in its own terms (an HTTP 200 carrying grpc-status), as before
        let grpc = ask(&env, Version::HTTP_2, "www.example.com", "/admin", &[("content-type", "application/grpc"), ("accept", "text/html")]).await;
        assert_eq!((grpc.status, grpc.body.as_str()), (StatusCode::OK, ""));
        assert_eq!(grpc.headers.get("grpc-status").unwrap(), "7");
        assert_eq!(grpc.headers.get("content-type").unwrap(), "application/grpc");
    }

    #[tokio::test]
    async fn the_human_check_and_hosts_of_no_zone_are_never_replaced() {
        let env = env();
        set_all(&env);
        let check = page(&env, "/shop").await;
        assert_eq!(check.status, 403);
        assert!(!check.body.starts_with("block ") && check.headers.get("fcf-mitigated").is_some(), "{}", check.body);
        let unknown = ask(&env, Version::HTTP_11, "www.example.net", "/", &[("accept", "text/html")]).await;
        assert!(unknown.status == 404 && unknown.body.contains("Unknown host"), "{}", unknown.body);
    }

    #[tokio::test]
    async fn one_zones_templates_do_not_answer_for_another() {
        let env = env();
        let other = env.store.create_zone("example.net").unwrap().id;
        let mut r = rec("@", "A", "127.0.0.1");
        r.proxied = true;
        env.store.create_record(&other, r).unwrap();
        env.store.update_setting(&other, "error_pages", json!({ "5xx": "other zone", "block": "other zone" })).unwrap();
        let got = page(&env, "/admin").await;
        assert!(got.body.contains("Access denied"), "{}", got.body);
    }

    #[tokio::test]
    async fn a_hostile_host_name_is_escaped_in_the_page() {
        let env = env();
        env.store.update_setting(&env.zone, "error_pages", json!({ "block": "<p>::HOST::</p>" })).unwrap();
        // the wildcard record serves any name under the zone
        let got = ask(&env, Version::HTTP_11, "a'b.example.com", "/admin", &[("accept", "text/html")]).await;
        assert_eq!(got.status, 403);
        assert_eq!(got.body, "<p>a&#39;b.example.com</p>");
    }

    #[tokio::test]
    async fn an_unmarked_or_unconfigured_response_passes_through_unchanged() {
        let env = env();
        let built = || {
            let mut r = Response::new(full("<p>default</p>"));
            *r.status_mut() = StatusCode::BAD_GATEWAY;
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            r.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(14));
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        };
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let zone = Some((env.zone.as_str(), "example.com"));
        let check = |resp: Response<Body>| async move {
            let (parts, body) = resp.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            assert_eq!(parts.status, StatusCode::BAD_GATEWAY);
            assert_eq!(&bytes[..], b"<p>default</p>");
            assert_eq!(parts.headers, built().headers().clone());
        };
        // nothing configured: a marked page is left alone, to the byte
        check(apply(&env.edge, mark(built(), Kind::Origin), true, zone, ip, "r").await).await;
        env.store.update_setting(&env.zone, "error_pages", json!({ "5xx": "custom ::STATUS::" })).unwrap();
        // configured, but not one of the edge's pages, not a browser, or not this zone
        check(apply(&env.edge, built(), true, zone, ip, "r").await).await;
        check(apply(&env.edge, mark(built(), Kind::Origin), false, zone, ip, "r").await).await;
        check(apply(&env.edge, mark(built(), Kind::Origin), true, None, ip, "r").await).await;
        check(apply(&env.edge, mark(built(), Kind::Origin), true, Some(("no-such-zone", "example.com")), ip, "r").await).await;
        check(apply(&env.edge, mark(built(), Kind::Block), true, zone, ip, "r").await).await;
        // and when it applies, the length follows the new body
        let (parts, body) = apply(&env.edge, mark(built(), Kind::Origin), true, zone, ip, "r").await.into_parts();
        assert_eq!(&body.collect().await.unwrap().to_bytes()[..], b"custom 502");
        assert_eq!(parts.headers.get(header::CONTENT_LENGTH).unwrap(), "10");
        assert_eq!(parts.headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    }

    #[tokio::test]
    async fn the_setting_is_refused_through_the_store_when_wrong() {
        let env = env();
        assert!(env.store.update_setting(&env.zone, "error_pages", json!({ "500": "x" })).is_err());
        assert!(env.store.update_setting(&env.zone, "error_pages", json!({ "5xx": "x".repeat(MAX_BYTES + 1) })).is_err());
        assert!(env.store.update_setting(&env.zone, "error_pages", json!("<p>x</p>")).is_err());
        assert_eq!(env.store.get_zone(&env.zone).unwrap().settings.error_pages, ErrorPages::default(), "nothing was stored");
        let z = env.store.update_setting(&env.zone, "error_pages", json!({ "5xx": "x".repeat(MAX_BYTES) })).unwrap();
        assert_eq!(z.settings.error_pages.get(Kind::Origin).map(str::len), Some(MAX_BYTES));
        // other settings still change while templates are set
        assert!(env.store.update_setting(&env.zone, "waf", json!("log")).is_ok());
        // and an empty map clears them all
        env.store.update_setting(&env.zone, "error_pages", json!({})).unwrap();
        assert_eq!(env.store.get_zone(&env.zone).unwrap().settings.error_pages, ErrorPages::default());
    }
}
