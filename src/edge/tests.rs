//! End-to-end tests: a real origin server, a real edge listener and raw
//! HTTP clients, exercising the whole request pipeline.

use super::*;
use crate::items::{CacheRule, FirewallRule, OriginRule, RateLimit, RedirectRule, TransformRule, WorkerRoute};
use crate::store::testutil::{rec, temp_store};
use axum::extract::Request as AxRequest;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Env {
    store: Arc<Store>,
    edge: Arc<Edge>,
    zone: String,
    port: u16,
    tls_port: u16,
    origin_port: u16,
    hits: Arc<AtomicUsize>,
}

/// Makes the origin answer 503 for paths containing "flaky".
static FLAKY_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The length of the test origin's large objects (paths under `/vid/`):
/// three whole cache chunks and a part.
const VIDEO_LEN: u64 = 3 * chunked::CHUNK + 12_345;
/// The version of the objects under `/vid/` whose path holds "shifty".
static SHIFTY: AtomicUsize = AtomicUsize::new(0);
/// The range requests the origin got for paths under `/vid/`: path, `Range`, `If-Range`.
static VIDEO_RANGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// The bytes of a large test object, different in each chunk and version.
fn video_bytes(version: usize) -> Vec<u8> {
    (0..VIDEO_LEN).map(|i| b'a' + ((i * 31 + version as u64 * 7 + i / chunked::CHUNK) % 26) as u8).collect()
}

/// A large object as an origin serves it. Paths with "norange" ignore
/// `Range`; those with "shifty" honour it but ignore `If-Range` (so they
/// can answer a part of another version); the others honour both
/// ("unvalidated" ones have no entity tag, nor any other validator). "brief"
/// ones are fresh for a second ("brief-swr" ones may then be answered stale
/// while they are fetched anew).
fn video(path: &str, range: Option<&str>, if_range: Option<&str>) -> axum::response::Response {
    let version = if path.contains("shifty") { SHIFTY.load(Ordering::SeqCst) } else { 0 };
    let etag = format!("\"vid{version}\"");
    let data = video_bytes(version);
    if let Some(r) = range {
        VIDEO_RANGES.lock().unwrap().push(format!("{path} {r} {}", if_range.unwrap_or("-")));
    }
    let honoured = !path.contains("norange") && (path.contains("shifty") || if_range.is_none_or(|v| v == etag));
    let part = range.filter(|_| honoured).and_then(|r| {
        let (a, b) = r.strip_prefix("bytes=")?.split_once('-')?;
        let a: u64 = a.parse().ok()?;
        let b = if b.is_empty() { VIDEO_LEN - 1 } else { b.parse::<u64>().ok()?.min(VIDEO_LEN - 1) };
        (a <= b).then_some((a, b))
    });
    let cc = match (path.contains("brief"), path.contains("swr")) {
        (true, true) => "public, max-age=1, stale-while-revalidate=60",
        (true, false) => "public, max-age=1",
        _ => "public, max-age=60",
    };
    let mut builder = axum::http::Response::builder().header("cache-control", cc).header("cache-tag", "videos").header("content-type", "video/mp4");
    if !path.contains("unvalidated") {
        builder = builder.header("etag", &etag);
    }
    match part {
        Some((a, b)) => builder
            .status(206)
            .header("content-range", format!("bytes {a}-{b}/{VIDEO_LEN}"))
            .body(axum::body::Body::from(data[a as usize..=b as usize].to_vec()))
            .unwrap(),
        None => builder.body(axum::body::Body::from(data)).unwrap(),
    }
}

/// A 400 x 200 PNG, red on the left and blue on the right; under
/// `/img/anim` it carries an `acTL` chunk, as an animated PNG does, and
/// under `/img/notes` the origin sends text.
fn picture(path: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let headers = [("cache-control", "public, max-age=60"), ("content-type", "image/png")];
    if path.starts_with("/img/notes") {
        return ([("cache-control", "public, max-age=60"), ("content-type", "text/plain")], "not a picture").into_response();
    }
    let img = image::RgbImage::from_fn(400, 200, |x, _| if x < 200 { image::Rgb([255, 0, 0]) } else { image::Rgb([0, 0, 255]) });
    let mut png = std::io::Cursor::new(Vec::new());
    img.write_to(&mut png, image::ImageFormat::Png).unwrap();
    let mut png = png.into_inner();
    if path.starts_with("/img/anim") {
        let tail = png.split_off(33);
        png.extend_from_slice(b"\0\0\0\x08acTL\0\0\0\x02\0\0\0\0\0\0\0\0");
        png.extend_from_slice(&tail);
    }
    (headers, png).into_response()
}

/// A body sent without announcing its length.
struct Chunks(std::collections::VecDeque<Bytes>);

impl hyper::body::Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        std::task::Poll::Ready(self.0.pop_front().map(|chunk| Ok(hyper::body::Frame::data(chunk))))
    }
}

/// Origin that describes the request it received.
async fn origin(hits: Arc<AtomicUsize>, name: &'static str) -> u16 {
    let app = axum::Router::new().fallback(move |req: AxRequest| {
        let hits = hits.clone();
        async move {
            let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
            let h_inm = req.headers().get("if-none-match").and_then(|v| v.to_str().ok()).map(String::from);
            let (h_range, h_if_range) = (req.headers().get("range").and_then(|v| v.to_str().ok()).map(String::from), req.headers().get("if-range").and_then(|v| v.to_str().ok()).map(String::from));
            let h_ae = req.headers().get("accept-encoding").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let (path, line) = {
            let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
            let path = req.uri().path().to_string();
            let line = format!(
                "origin={name} {} {} host={} xff={} ip={} proto={} added={} country={} hit={n}",
                req.method(),
                req.uri(),
                h("host"),
                h("x-forwarded-for"),
                h("cf-connecting-ip"),
                h("x-forwarded-proto"),
                h("x-added"),
                h("cf-ipcountry"),
            );
            (path, line)
            };
            let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
            let text = format!("{line} body={}", String::from_utf8_lossy(&body));
            let cc = if path.contains("private") { "private" } else { "max-age=60" };
            use axum::response::IntoResponse;
            if path.starts_with("/vid/") {
                return video(&path, h_range.as_deref(), h_if_range.as_deref());
            }
            if path.starts_with("/img/") {
                return picture(&path);
            }
            if path.contains("etag") {
                let status = if h_inm.as_deref() == Some("\"v1\"") { 304 } else { 200 };
                let body = if status == 304 { String::new() } else { format!("etag-body hit={n}") };
                return (axum::http::StatusCode::from_u16(status).unwrap(), [("etag", "\"v1\""), ("cache-control", "public, max-age=1")], body)
                    .into_response();
            }
            if path.contains("csp.html") {
                // a page whose origin sets policies of its own
                let headers = [("content-type", "text/html"), ("content-security-policy", "default-src 'self'"), ("content-security-policy-report-only", "img-src 'self'")];
                return (headers, "<!doctype html><p>csp</p>").into_response();
            }
            if path.contains("page.html") {
                let html = "<!doctype html><html><HEAD><title>t</title></HEAD><body>hello</body></html>";
                if path.contains("gz") {
                    use std::io::Write;
                    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    gz.write_all(html.as_bytes()).unwrap();
                    return ([("content-type", "text/html; charset=utf-8"), ("content-encoding", "gzip"), ("cf-ray", "abc-SIN")], gz.finish().unwrap()).into_response();
                }
                if path.contains("zs") {
                    let packed = zstd::bulk::compress(html.as_bytes(), 3).unwrap();
                    return ([("content-type", "text/html; charset=utf-8"), ("content-encoding", "zstd")], packed).into_response();
                }
                return ([("content-type", "text/html; charset=utf-8"), ("cf-ray", "abc-SIN")], html).into_response();
            }
            if path.starts_with("/zstd-origin/") {
                // zstd when asked for it, or always under /always/ (an origin that ignores Accept-Encoding)
                let headers = [("content-type", "text/css"), ("cache-control", "public, max-age=60")];
                if path.contains("/always/") || crate::edge::compress::accepts(&h_ae, "zstd") {
                    let packed = zstd::bulk::compress(format!("zstd hit={n}").as_bytes(), 3).unwrap();
                    return (headers, [("content-encoding", "zstd")], packed).into_response();
                }
                return (headers, format!("plain hit={n}")).into_response();
            }
            if path.contains("big") {
                return ([("content-type", "text/plain; charset=utf-8")], "compress me ".repeat(500)).into_response();
            }
            if path.contains("binary") {
                return vec![0xffu8, 0xfe, 0x00, 0x80].into_response();
            }
            if path.contains("chunked") {
                let chunks = match path.contains("huge") {
                    true => (0..9).map(|_| Bytes::from(vec![b'x'; 1024 * 1024])).collect(),
                    false => (0..3).map(|i| Bytes::from(format!("chunk-{i};"))).collect(),
                };
                return ([("cache-control", "public, max-age=60")], axum::body::Body::new(Chunks(chunks))).into_response();
            }
            if path.contains("blob") {
                return vec![b'x'; 400_000].into_response();
            }
            if path.contains("altsvc") {
                return ([("alt-svc", "h3=\":443\"; ma=86400"), ("cache-control", "public, max-age=60")], "behind another CDN").into_response();
            }
            if path.contains("swr") {
                return ([("cache-control", "public, max-age=1, stale-while-revalidate=60")], format!("swr hit={n}")).into_response();
            }
            if path.contains("lastmod") {
                return ([("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")], "dated").into_response();
            }
            if path.contains("flaky") {
                if FLAKY_DOWN.load(Ordering::SeqCst) {
                    return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "origin broken").into_response();
                }
                return ([("cache-control", "public, max-age=1")], format!("flaky hit={n}")).into_response();
            }
            ([("cache-control", cc)], text).into_response()
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

async fn setup() -> Env {
    let store = Arc::new(temp_store());
    let zone = store.create_zone("example.com").unwrap().id;
    for (name, proxied) in [("@", true), ("www", true), ("direct", false)] {
        let mut r = rec(name, "A", "127.0.0.1");
        r.proxied = proxied;
        store.create_record(&zone, r).unwrap();
    }
    let mut alias = rec("alias", "CNAME", "www.example.com");
    alias.proxied = true;
    store.create_record(&zone, alias).unwrap();

    let hits = Arc::new(AtomicUsize::new(0));
    let origin_port = origin(hits.clone(), "main").await;
    // every request goes to the test origin's port unless a rule says otherwise
    store
        .save_item::<OriginRule>(&zone, None, json!({ "expression": "", "origin_port": origin_port, "priority": 100 }), true)
        .unwrap();

    let cache = Arc::new(Cache::new(64 << 20));
    let edge = Arc::new(Edge::new(store.clone(), cache, Arc::new(Waf::new()), vec![]).unwrap());
    edge.allow_subrequest_loopback.store(true, std::sync::atomic::Ordering::Relaxed);
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (port, tls_port) = (http.local_addr().unwrap().port(), https.local_addr().unwrap().port());
    tokio::spawn(serve(http, edge.clone(), None, false));
    tokio::spawn(serve(https, edge.clone(), Some(tls::server_config(store.clone()).unwrap()), false));
    let quic = h3::endpoint(([127, 0, 0, 1], tls_port).into(), store.clone()).unwrap();
    let _ = edge.alt_svc.set(format!("h3=\":{tls_port}\"; ma=86400").parse().unwrap());
    tokio::spawn(h3::serve(quic, edge.clone()));
    Env { store, edge, zone, port, tls_port, origin_port, hits }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then_some(v.trim())
        })
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, raw: String) -> Reply {
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    Reply { status, head: head.to_string(), body: body.to_string() }
}

fn raw(method: &str, host: &str, uri: &str, extra: &str, body: &str) -> String {
    format!("{method} {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n{body}", body.len())
}

async fn send(env: &Env, method: &str, host: &str, uri: &str, extra: &str, body: &str) -> Reply {
    let s = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    exchange(s, raw(method, host, uri, extra, body)).await
}

async fn get(env: &Env, host: &str, uri: &str) -> Reply {
    send(env, "GET", host, uri, "", "").await
}

#[tokio::test]
async fn proxies_to_origin() {
    let env = setup().await;
    let r = get(&env, "example.com", "/hello?a=1").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("origin=main GET /hello?a=1 host=example.com xff=127.0.0.1 ip=127.0.0.1 proto=http"), "{}", r.body);
    assert_eq!(r.header("server"), Some("fucf"));
    assert_eq!(r.header("fcf-cache-status"), Some("DYNAMIC"));
    assert_eq!(r.header("fucf-ray").map(str::len), Some(16));

    // request bodies and an existing X-Forwarded-For chain are passed on
    let r = send(&env, "POST", "www.example.com", "/submit", "X-Forwarded-For: 10.9.9.9\r\n", "name=fucf").await;
    assert!(r.body.contains("POST /submit") && r.body.contains("xff=10.9.9.9, 127.0.0.1") && r.body.ends_with("body=name=fucf"), "{}", r.body);

    // a proxied CNAME is followed inside the zone; the Host header is preserved
    let r = get(&env, "alias.example.com", "/").await;
    assert!(r.status == 200 && r.body.contains("host=alias.example.com"), "{}", r.body);

    // names that are not proxied, unknown zones and loops are refused
    assert_eq!(get(&env, "direct.example.com", "/").await.status, 404);
    assert_eq!(get(&env, "nope.example.com", "/").await.status, 404);
    assert_eq!(get(&env, "other.org", "/").await.status, 404);
    assert_eq!(send(&env, "GET", "example.com", "/", "CDN-Loop: fucf\r\n", "").await.status, 508);
    assert_eq!(env.hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn records_carry_their_own_origin_options() {
    let env = setup().await;
    let add = |zone: &str, name: &str, rtype: &str, content: &str, origin: serde_json::Value| {
        let mut r = rec(name, rtype, content);
        (r.proxied, r.origin) = (true, serde_json::from_value(origin).unwrap());
        env.store.create_record(zone, r).unwrap();
    };
    let target = |host: &str, path: &str| {
        let snap = env.store.snapshot();
        let zone = snap.find_zone(host).unwrap();
        let info = ReqInfo { host: host.into(), path: path.into(), ..Default::default() };
        env.edge.resolve_target(&snap, zone, &info).unwrap()
    };

    // what this is for: an origin behind another CDN, reached at one of that CDN's
    // addresses under one name (the TLS server name) and asked for another (Host)
    add(&env.zone, "saas", "A", "127.0.0.1", json!({ "sni": "edge.cdn.example", "host_header": "app.origin.example" }));
    let t = target("saas.example.com", "/");
    assert_eq!((t.host.as_str(), t.sni.as_str(), t.host_header.as_str()), ("127.0.0.1", "edge.cdn.example", "app.origin.example"));
    assert_eq!((t.tls, t.port), (Tls::NoVerify, env.origin_port), "a server name means TLS, even where the zone talks plain HTTP to its origins; the port is the rule's");
    env.store.update_setting(&env.zone, "ssl", json!("strict")).unwrap();
    assert_eq!(target("saas.example.com", "/").tls, Tls::Verify);
    env.store.update_setting(&env.zone, "ssl", json!("flexible")).unwrap();
    // other records of the zone are reached as before
    let t = target("www.example.com", "/");
    assert_eq!((t.tls, t.sni.as_str(), t.host_header.as_str()), (Tls::Off, "www.example.com", "www.example.com"));

    // only one of the two set: the other follows the usual
    add(&env.zone, "plain", "A", "127.0.0.1", json!({ "host_header": "backend.internal" }));
    let t = target("plain.example.com", "/");
    assert_eq!((t.tls, t.sni.as_str(), t.host_header.as_str()), (Tls::Off, "backend.internal", "backend.internal"));
    let r = get(&env, "plain.example.com", "/x").await;
    assert!(r.status == 200 && r.body.contains("GET /x host=backend.internal"), "{}", r.body);
    add(&env.zone, "named", "A", "127.0.0.1", json!({ "sni": "edge.cdn.example" }));
    let t = target("named.example.com", "/");
    assert_eq!((t.sni.as_str(), t.host_header.as_str()), ("edge.cdn.example", "named.example.com"));

    // an origin rule that matches still has the last word, field by field ...
    let rule = |v| env.store.save_item::<OriginRule>(&env.zone, None, v, true).unwrap();
    rule(json!({ "expression": "http.request.uri.path eq \"/ruled\"", "host_header": "from.the.rule", "priority": 1 }));
    let t = target("saas.example.com", "/ruled");
    assert_eq!((t.sni.as_str(), t.host_header.as_str(), t.tls), ("edge.cdn.example", "from.the.rule", Tls::NoVerify));
    // ... and one that sends the request elsewhere leaves the record's options behind
    rule(json!({ "expression": "http.request.uri.path eq \"/elsewhere\"", "origin_host": "localhost", "priority": 2 }));
    let t = target("saas.example.com", "/elsewhere");
    assert_eq!((t.host.as_str(), t.sni.as_str(), t.host_header.as_str(), t.tls), ("localhost", "saas.example.com", "saas.example.com", Tls::Off));

    // a zone without any rule: port and scheme of the record; a proxied CNAME has options too
    let other = env.store.create_zone("other.org").unwrap().id;
    add(&other, "app", "A", "192.0.2.7", json!({ "port": 8443, "scheme": "https" }));
    let t = target("app.other.org", "/");
    assert_eq!((t.host.as_str(), t.port, t.tls, t.sni.as_str()), ("192.0.2.7", 8443, Tls::NoVerify, "app.other.org"));
    add(&other, "alias", "CNAME", "pool.cdn.example", json!({ "sni": "edge.cdn.example", "host_header": "app.origin.example", "port": 2053 }));
    let t = target("alias.other.org", "/");
    assert_eq!((t.host.as_str(), t.port, t.sni.as_str(), t.host_header.as_str()), ("pool.cdn.example", 2053, "edge.cdn.example", "app.origin.example"));

    // several addresses under one name: only those reached the same way stand in for each other
    for (addr, origin) in [("192.0.2.1", json!({ "sni": "edge.cdn.example" })), ("192.0.2.2", json!({ "sni": "edge.cdn.example" })), ("192.0.2.3", json!(null))] {
        add(&other, "pool", "A", addr, origin);
    }
    let mut seen = std::collections::HashSet::new();
    for _ in 0..12 {
        let t = target("pool.other.org", "/");
        match t.host.as_str() {
            "192.0.2.3" => assert!(t.alternates.is_empty() && t.sni == "pool.other.org" && t.tls == Tls::Off, "{t:?}"),
            first => {
                let twin = if first == "192.0.2.1" { "192.0.2.2" } else { "192.0.2.1" };
                assert!(t.alternates == [twin] && t.sni == "edge.cdn.example" && t.tls == Tls::NoVerify, "{t:?}");
            }
        }
        seen.insert(t.host);
    }
    assert_eq!(seen.len(), 3, "every address gets its turn");
}

#[tokio::test]
async fn caches_static_content() {
    let env = setup().await;
    let first = get(&env, "example.com", "/assets/app.js?v=1").await;
    assert_eq!((first.status, first.header("fcf-cache-status")), (200, Some("MISS")));
    let second = get(&env, "example.com", "/assets/app.js?v=1").await;
    assert_eq!(second.header("fcf-cache-status"), Some("HIT"));
    assert!(second.header("age").is_some());
    // every response tells whether it came from the cache
    assert!(first.header("x-cache").is_some_and(|v| v.starts_with("MISS from ")), "{}", first.head);
    assert!(second.header("x-cache").is_some_and(|v| v.starts_with("HIT from ")), "{}", second.head);
    let own = get(&env, "nowhere.test", "/").await;
    assert_eq!((own.status, own.header("fcf-cache-status")), (404, Some("NONE")));
    assert!(own.header("x-cache").is_some_and(|v| v.starts_with("MISS from ")));
    assert_eq!(first.body, second.body);
    assert_eq!(env.hits.load(Ordering::SeqCst), 1);

    // different query string / host = different object; HEAD is served from cache without a body
    assert_eq!(get(&env, "example.com", "/assets/app.js?v=2").await.header("fcf-cache-status"), Some("MISS"));
    assert_eq!(get(&env, "www.example.com", "/assets/app.js?v=1").await.header("fcf-cache-status"), Some("MISS"));
    let head = send(&env, "HEAD", "example.com", "/assets/app.js?v=1", "", "").await;
    assert_eq!((head.header("fcf-cache-status"), head.body.as_str()), (Some("HIT"), ""));

    // not cached: dynamic paths, private responses, authorized requests, non-GET
    assert_eq!(get(&env, "example.com", "/api/data").await.header("fcf-cache-status"), Some("DYNAMIC"));
    assert_eq!(get(&env, "example.com", "/private/a.css").await.header("fcf-cache-status"), Some("BYPASS"));
    assert_eq!(get(&env, "example.com", "/private/a.css").await.header("fcf-cache-status"), Some("BYPASS"));
    let auth = send(&env, "GET", "example.com", "/assets/app.js?v=1", "Authorization: Bearer x\r\n", "").await;
    assert_eq!(auth.header("fcf-cache-status"), Some("DYNAMIC"));
    assert_eq!(send(&env, "POST", "example.com", "/assets/app.js?v=1", "", "").await.header("fcf-cache-status"), Some("DYNAMIC"));

    // purge by URL, then everything
    assert_eq!(env.edge.cache.purge_urls(&env.zone, &["https://example.com/assets/app.js?v=1".into()], false), 1);
    assert_eq!(get(&env, "example.com", "/assets/app.js?v=1").await.header("fcf-cache-status"), Some("MISS"));
    assert_eq!(env.edge.cache.purge_zone(&env.zone), 3);
    assert_eq!(get(&env, "example.com", "/assets/app.js?v=2").await.header("fcf-cache-status"), Some("MISS"));

    // development mode bypasses the cache entirely
    env.store.update_setting(&env.zone, "development_mode", json!("on")).unwrap();
    assert_eq!(get(&env, "example.com", "/assets/app.js?v=2").await.header("fcf-cache-status"), Some("DYNAMIC"));
}

#[tokio::test]
async fn a_rule_on_the_bot_score_stops_scripts_and_lets_browsers_through() {
    let env = setup().await;
    let rule = env
        .store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "fcf.bot_score lt 30", "action": "block" }), true)
        .unwrap();
    let browser = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0\r\nAccept: text/html\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n";
    assert_eq!(send(&env, "GET", "example.com", "/", browser, "").await.status, 200);
    assert_eq!(send(&env, "GET", "example.com", "/", "User-Agent: curl/8.5.0\r\nAccept: */*\r\n", "").await.status, 403);
    assert_eq!(get(&env, "example.com", "/").await.status, 403, "no headers at all");
    assert_eq!(env.hits.load(Ordering::SeqCst), 1, "only the browser reached the origin");

    // the Cloudflare name works the same, here the other way round
    env.store
        .save_item::<FirewallRule>(&env.zone, Some(&rule.meta.id), json!({ "expression": "cf.bot_management.score gt 50" }), false)
        .unwrap();
    assert_eq!(send(&env, "GET", "example.com", "/", browser, "").await.status, 403);
    assert_eq!(get(&env, "example.com", "/").await.status, 200);
}

#[tokio::test]
async fn waf_blocks_and_logs() {
    let env = setup().await;
    let fw = |v| env.store.save_item::<FirewallRule>(&env.zone, None, v, true).unwrap();

    // managed ruleset, in the URL and in a form body
    let r = get(&env, "example.com", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E").await;
    assert!(r.status == 403 && r.body.contains("100002"), "{}", r.body);
    assert_eq!(send(&env, "POST", "example.com", "/login", "", "user=admin'+OR+'1'='1").await.status, 403);
    assert_eq!(get(&env, "example.com", "/.env").await.status, 403);
    assert_eq!(env.hits.load(Ordering::SeqCst), 0, "blocked requests must never reach the origin");
    assert_eq!(get(&env, "example.com", "/search?q=shoes").await.status, 200);

    // custom rules: block, then an earlier skip rule that exempts one client header
    let block = fw(json!({ "expression": "starts_with(http.request.uri.path, \"/admin\")", "action": "block", "description": "no admin" }));
    assert_eq!(get(&env, "example.com", "/admin/users").await.status, 403);
    fw(json!({ "expression": "http.request.headers[\"x-internal\"] eq \"yes\"", "action": "skip", "priority": -1 }));
    assert_eq!(send(&env, "GET", "example.com", "/admin/users", "X-Internal: yes\r\n", "").await.status, 200);
    // skip also bypasses the managed rules
    assert_eq!(send(&env, "GET", "example.com", "/.env", "X-Internal: yes\r\n", "").await.status, 200);

    // disabled rules do nothing
    env.store.save_item::<FirewallRule>(&env.zone, Some(&block.meta.id), json!({ "enabled": false }), false).unwrap();
    assert_eq!(get(&env, "example.com", "/admin/users").await.status, 200);

    // managed rules in log mode let the request through but record it
    env.store.update_setting(&env.zone, "waf", json!("log")).unwrap();
    assert_eq!(get(&env, "example.com", "/.git/config").await.status, 200);

    let events = env.edge.waf.events(&env.zone, 100);
    let has = |source: &str, action: &str, rule: &str| {
        events.iter().any(|e| e.source == source && e.action == action && e.rule_id == rule)
    };
    assert!(has("managed", "block", "100002") && has("managed", "block", "100001") && has("managed", "log", "100005"));
    assert!(has("firewall", "block", &block.meta.id));
    assert!(events.iter().all(|e| e.client_ip == "127.0.0.1" && e.host == "example.com"));
}

#[tokio::test]
async fn rate_limits_and_challenges() {
    let env = setup().await;
    env.store
        .save_item::<RateLimit>(
            &env.zone,
            None,
            json!({ "expression": "http.request.uri.path eq \"/login\"", "threshold": 3, "period": 60, "mitigation_timeout": 120 }),
            true,
        )
        .unwrap();
    for _ in 0..3 {
        assert_eq!(get(&env, "example.com", "/login").await.status, 200);
    }
    let limited = get(&env, "example.com", "/login").await;
    assert_eq!(limited.status, 429);
    assert!(limited.header("retry-after").unwrap().parse::<u64>().unwrap() > 100);
    assert_eq!(get(&env, "example.com", "/other").await.status, 200, "only matching requests are limited");
    assert_eq!(env.hits.load(Ordering::SeqCst), 4);

    // JS challenge: the page no longer hands out the clearance itself (the human check grants it,
    // see the_human_check_lets_a_person_through_and_keeps_automation_out)
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "http.request.uri.path eq \"/shop\"", "action": "js_challenge" }), true)
        .unwrap();
    let page = get(&env, "example.com", "/shop").await;
    assert!(page.status == 403 && page.body.contains("Checking your browser"));
    assert_eq!(page.header("fcf-mitigated"), Some("challenge"));
    assert!(!page.body.contains("fucf_clearance="), "the clearance is never in the page");
    let forged = send(&env, "GET", "example.com", "/shop", "Cookie: fucf_clearance=9999999999.abcd\r\n", "").await;
    assert_eq!(forged.status, 403);
}

#[tokio::test]
async fn origin_rules_and_errors() {
    let env = setup().await;
    let second = origin(Arc::new(AtomicUsize::new(0)), "second").await;
    let rule = |v| env.store.save_item::<OriginRule>(&env.zone, None, v, true).unwrap();

    // send /api/* to another origin with a rewritten Host header
    rule(json!({
        "expression": "starts_with(http.request.uri.path, \"/api/\")",
        "origin_host": "localhost", "origin_port": second, "host_header": "backend.internal", "priority": 1,
    }));
    let api = get(&env, "example.com", "/api/users").await;
    assert!(api.body.contains("origin=second") && api.body.contains("host=backend.internal"), "{}", api.body);
    let page = get(&env, "example.com", "/index").await;
    assert!(page.body.contains("origin=main") && page.body.contains("host=example.com"), "{}", page.body);

    let target = |path: &str| {
        let snap = env.store.snapshot();
        let zone = snap.find_zone("example.com").unwrap();
        let info = ReqInfo { host: "example.com".into(), path: path.into(), ..Default::default() };
        env.edge.resolve_target(&snap, zone, &info).unwrap()
    };
    // ssl modes and SNI overrides
    assert_eq!(target("/").tls, Tls::Off);
    env.store.update_setting(&env.zone, "ssl", json!("full")).unwrap();
    assert_eq!((target("/").tls, target("/").sni.as_str()), (Tls::NoVerify, "example.com"));
    env.store.update_setting(&env.zone, "ssl", json!("strict")).unwrap();
    rule(json!({ "expression": "http.request.uri.path eq \"/s\"", "sni": "tls.backend.internal", "origin_scheme": "https", "priority": 2 }));
    let t = target("/s");
    assert_eq!((t.tls, t.sni.as_str(), t.host_header.as_str(), t.port), (Tls::Verify, "tls.backend.internal", "example.com", env.origin_port));
    let t = target("/api/x");
    assert_eq!((t.host.as_str(), t.port, t.sni.as_str()), ("localhost", second, "backend.internal"));
    assert!(env.store.update_setting(&env.zone, "ssl", json!("bogus")).is_err());
    env.store.update_setting(&env.zone, "ssl", json!("flexible")).unwrap();

    // origin down -> 521 error page; plain HTTP redirected when always_use_https is on
    rule(json!({ "expression": "http.request.uri.path eq \"/down\"", "origin_port": 1, "priority": 0 }));
    let down = get(&env, "example.com", "/down").await;
    assert!(down.status == 521 && down.body.contains("回源错误") && down.body.contains("Origin error") && down.body.contains(ORIGIN_DOWN.zh), "{} {}", down.status, down.body);
    // the visitor learns the kind of failure, not where the origin is
    assert!(!down.body.contains("127.0.0.1") && !down.body.contains(":1 ") && !down.body.contains("refused ("), "{}", down.body);
    let logged = env.edge.waf.events(&env.zone, 100);
    let e = logged.iter().find(|e| e.source == "origin").expect("origin error is logged for the dashboard");
    assert!(e.rule_id == "521" && e.description == ORIGIN_DOWN.zh && e.uri == "/down" && e.method == "GET", "{e:?}");
    let _ = get(&env, "example.com", "/down").await;
    assert_eq!(env.edge.waf.events(&env.zone, 100).iter().filter(|e| e.source == "origin").count(), 1, "once a minute per host and status");
    env.store.update_setting(&env.zone, "always_use_https", json!(true)).unwrap();
    let redirect = get(&env, "example.com", "/a?b=1").await;
    assert_eq!((redirect.status, redirect.header("location")), (301, Some("https://example.com/a?b=1")));
}

#[tokio::test]
async fn serves_https_with_sni_certificates() {
    let env = setup().await;
    let connect = |sni: &'static str| async move {
        let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls::client_config(false).unwrap());
        connector.connect(rustls::pki_types::ServerName::try_from(sni).unwrap(), tcp).await.unwrap()
    };
    let leaf = |s: &tokio_rustls::client::TlsStream<TcpStream>| s.get_ref().1.peer_certificates().unwrap()[0].to_vec();

    let s = connect("example.com").await;
    let generated = leaf(&s);
    let r = exchange(s, raw("GET", "example.com", "/secure", "", "")).await;
    assert!(r.status == 200 && r.body.contains("proto=https"), "{}", r.body);

    // an uploaded certificate replaces the generated one for its hosts
    let custom = rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()]).unwrap();
    let cert: crate::items::Certificate = env
        .store
        .save_item(
            &env.zone,
            None,
            json!({ "hosts": ["www.example.com"], "certificate": custom.cert.pem(), "private_key": custom.signing_key.serialize_pem() }),
            true,
        )
        .unwrap();
    assert!(crate::items::Item::public(&cert).get("private_key").is_none());
    assert_eq!(leaf(&connect("www.example.com").await), custom.cert.der().to_vec());
    assert_eq!(leaf(&connect("example.com").await), generated);
    let bad = env.store.save_item::<crate::items::Certificate>(
        &env.zone,
        None,
        json!({ "hosts": ["evil.org"], "certificate": custom.cert.pem(), "private_key": custom.signing_key.serialize_pem() }),
        true,
    );
    assert!(bad.is_err(), "certificates may only cover hosts of their own zone");
}

/// What a client presents to servers that ask for a certificate (none: nothing).
type Identity = Option<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)>;

/// One request over TLS to `port` presenting `identity`: the status and the
/// whole answer, or None when the handshake or the exchange failed.
async fn ask_tls(port: u16, identity: Identity, path: &str) -> Option<(u16, String)> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls::client_config_presenting(false, identity).unwrap());
    let mut s = connector.connect(rustls::pki_types::ServerName::try_from("example.com").unwrap(), tcp).await.ok()?;
    s.write_all(raw("GET", "example.com", path, "", "").as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split(' ').nth(1).and_then(|s| s.parse().ok())?;
    Some((status, text))
}

#[tokio::test]
async fn a_zone_with_mtls_on_takes_only_visitors_with_a_verified_client_certificate() {
    let env = setup().await;
    let ca = mtls::test_certs::ca("fucf test client CA");
    let (cfg, _) = tls::server_config_verifying(env.store.clone(), Some(tls::visitor_verifier(&ca.pem).unwrap())).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, env.edge.clone(), Some(cfg), false));
    let valid = || Some(mtls::test_certs::client(&ca));
    let foreign = || Some(mtls::test_certs::client(&mtls::test_certs::ca("another CA")));
    let line = |text: &str, wanted: &str| text.lines().any(|l| l == wanted);

    // off (the default): a certificate is asked for, not needed; the trace tells which
    assert_eq!(env.store.get_zone(&env.zone).unwrap().settings.mtls, "off");
    let (status, text) = ask_tls(port, None, "/hello").await.expect("no certificate is fine");
    assert!(status == 200 && text.contains("origin=main"), "{text}");
    let (status, text) = ask_tls(port, None, "/cdn-cgi/fucf-trace").await.unwrap();
    assert!(status == 200 && line(&text, "client_cert=none"), "{text}");
    let (status, text) = ask_tls(port, valid(), "/cdn-cgi/fucf-trace").await.unwrap();
    assert!(status == 200 && line(&text, "client_cert=verified"), "{text}");
    // one that does not verify fails the handshake, whatever the zone
    assert!(ask_tls(port, foreign(), "/hello").await.is_none_or(|(status, _)| status != 200));
    // rules see it
    let rule = env
        .store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "not cf.tls_client_auth.cert_verified and http.request.uri.path eq \"/ruled\"", "action": "block" }), true)
        .unwrap();
    assert_eq!(ask_tls(port, None, "/ruled").await.unwrap().0, 403);
    assert_eq!(ask_tls(port, valid(), "/ruled").await.unwrap().0, 200);
    env.store.delete_item::<FirewallRule>(&env.zone, &rule.meta.id).unwrap();

    // on: nobody without a verified certificate gets anything of the zone, by any way in
    assert!(env.store.update_setting(&env.zone, "mtls", json!("yes")).is_err());
    assert!(env.store.update_setting(&env.zone, "mtls", json!(true)).is_err());
    env.store.update_setting(&env.zone, "mtls", json!("on")).unwrap();
    let (status, text) = ask_tls(port, valid(), "/hello").await.unwrap();
    assert!(status == 200 && text.contains("origin=main"), "{text}");
    assert_eq!(ask_tls(port, valid(), "/cdn-cgi/fucf-trace").await.unwrap().0, 200);
    for path in ["/hello", "/cdn-cgi/fucf-trace", "/.well-known/acme-challenge/nothing-here"] {
        assert_eq!(ask_tls(port, None, path).await.map(|(status, _)| status), Some(403), "{path}");
    }
    assert!(ask_tls(port, foreign(), "/hello").await.is_none_or(|(status, _)| status == 403));
    // other names of the zone, plain HTTP, and a listener that asks for no certificate (it never sees one)
    assert_eq!(ask_tls(port, None, "/hello").await.unwrap().0, 403);
    assert_eq!(get(&env, "www.example.com", "/hello").await.status, 403);
    assert_eq!(get(&env, "direct.example.com", "/hello").await.status, 403);
    assert_eq!(get(&env, "example.com", "/hello").await.status, 403);
    assert_eq!(send(&env, "GET", "example.com", "/ws", "Upgrade: websocket\r\nConnection: upgrade\r\n", "").await.status, 403);
    assert_eq!(ask_tls(env.tls_port, valid(), "/hello").await.unwrap().0, 403);
    // the HTTP/3 front passes on no certificate
    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_port = front_listener.local_addr().unwrap().port();
    tokio::spawn(front::serve(front_listener, env.edge.clone()));
    let forwarded = "X-Forwarded-For: 198.51.100.7\r\nX-Forwarded-Proto: https\r\n";
    let r = exchange(TcpStream::connect(("127.0.0.1", front_port)).await.unwrap(), raw("GET", "example.com", "/hello", forwarded, "")).await;
    assert_eq!(r.status, 403, "{}", r.body);
    // nor does HTTP/3 without a certificate
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint.connect(([127, 0, 0, 1], env.tls_port).into(), "example.com").unwrap().await.unwrap();
    let (mut driver, mut h3_sender) = ::h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut stream = h3_sender.send_request(Request::builder().uri("https://example.com/hello").body(()).unwrap()).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::FORBIDDEN);
    // HTTP/3 on a QUIC listener that asks for certificates: with one, and without
    let (quic_tls, _) = tls::server_config_verifying(env.store.clone(), Some(tls::visitor_verifier(&ca.pem).unwrap())).unwrap();
    let mut quic_tls = (*quic_tls).clone();
    quic_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(quic_tls)).unwrap();
    let quic = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)), "127.0.0.1:0".parse().unwrap()).unwrap();
    let quic_port = quic.local_addr().unwrap().port();
    tokio::spawn(h3::serve(quic, env.edge.clone()));
    for (identity, expected) in [(valid(), StatusCode::OK), (None, StatusCode::FORBIDDEN)] {
        let mut client_tls = (*tls::client_config_presenting(false, identity).unwrap()).clone();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap())));
        let conn = endpoint.connect(([127, 0, 0, 1], quic_port).into(), "example.com").unwrap().await.unwrap();
        let (mut driver, mut h3_sender) = ::h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut stream = h3_sender.send_request(Request::builder().uri("https://example.com/hello").body(()).unwrap()).await.unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), expected);
    }
    // a host of no zone is not concerned
    assert_eq!(get(&env, "stranger.org", "/cdn-cgi/fucf-trace").await.status, 200);

    // off again: as before
    env.store.update_setting(&env.zone, "mtls", json!("off")).unwrap();
    assert_eq!(ask_tls(port, None, "/hello").await.unwrap().0, 200);
    assert_eq!(get(&env, "example.com", "/hello").await.status, 200);
}

#[tokio::test]
async fn proxies_protocol_upgrades() {
    let env = setup().await;
    // a raw origin that accepts an upgrade and then echoes bytes
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let mut seen = Vec::new();
        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            seen.extend_from_slice(&buf[..n]);
        }
        assert!(String::from_utf8_lossy(&seen).to_ascii_lowercase().contains("upgrade: echo"));
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\n").await.unwrap();
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&buf[..n]).await.unwrap();
        }
    });
    env.store
        .save_item::<OriginRule>(&env.zone, None, json!({ "expression": "http.request.uri.path eq \"/ws\"", "origin_port": ws_port, "priority": 0 }), true)
        .unwrap();

    let mut s = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    s.write_all(b"GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let mut head = Vec::new();
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed before the upgrade completed");
        head.extend_from_slice(&buf[..n]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
    for msg in [&b"ping"[..], b"second message"] {
        s.write_all(msg).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], msg);
    }
}

fn deploy(env: &Env, name: &str, pattern: &str, script: &str) {
    crate::workers::check_syntax(script).unwrap();
    env.store.put_worker(name, Some(script.to_string()), None).unwrap();
    env.store.save_item::<WorkerRoute>(&env.zone, None, json!({ "pattern": pattern, "script": name }), true).unwrap();
}

#[tokio::test]
async fn workers_generate_and_transform_responses() {
    let env = setup().await;

    // module syntax, URL parsing, env bindings, custom status and headers
    deploy(
        &env,
        "hello",
        "example.com/w/hello*",
        r#"export default {
             async fetch(request, env, ctx) {
               const url = new URL(request.url);
               const name = url.searchParams.get("name") || "world";
               console.log("greeting", name);
               return new Response(`${env.GREETING}, ${name}! ${request.method} ${url.pathname} ua=${request.headers.get("user-agent")}`, {
                 status: 201,
                 headers: { "x-worker": "hello", "content-type": "text/plain" },
               });
             }
           }"#,
    );
    env.store.put_worker("hello", None, Some([("GREETING".to_string(), "Bonjour".to_string())].into())).unwrap();
    let r = send(&env, "GET", "example.com", "/w/hello?name=fucf%20user", "User-Agent: test/1\r\n", "").await;
    assert_eq!(r.status, 201, "{}", r.body);
    assert_eq!(r.body, "Bonjour, fucf user! GET /w/hello ua=test/1");
    assert_eq!((r.header("x-worker"), r.header("server")), (Some("hello"), Some("fucf")));
    assert_eq!(env.hits.load(Ordering::SeqCst), 0, "this worker never contacts the origin");

    // fetch the origin, then rewrite the response (headers and body)
    deploy(
        &env,
        "rewrite",
        "example.com/w/rewrite/*",
        r#"export default {
             async fetch(request) {
               const upstream = await fetch(request);
               const text = await upstream.text();
               const res = new Response(text.replace("origin=main", "origin=REWRITTEN"), upstream);
               res.headers.set("x-upstream-status", String(upstream.status));
               res.headers.delete("cache-control");
               return res;
             }
           }"#,
    );
    let r = get(&env, "example.com", "/w/rewrite/page?x=1").await;
    assert!(r.status == 200 && r.body.contains("origin=REWRITTEN GET /w/rewrite/page?x=1 host=example.com"), "{}", r.body);
    assert_eq!((r.header("x-upstream-status"), r.header("cache-control")), (Some("200"), None));

    // request bodies, JSON helpers, service-worker syntax
    deploy(
        &env,
        "api",
        "example.com/w/api",
        r#"addEventListener("fetch", (event) => {
             event.respondWith((async () => {
               const data = await event.request.json();
               return Response.json({ sum: data.a + data.b, method: event.request.method });
             })());
           });"#,
    );
    let r = send(&env, "POST", "example.com", "/w/api", "Content-Type: application/json\r\n", r#"{"a":2,"b":40}"#).await;
    assert_eq!((r.status, r.body.as_str(), r.header("content-type")), (200, r#"{"sum":42,"method":"POST"}"#, Some("application/json")));
}

#[tokio::test]
async fn workers_proxy_route_and_fail_safely() {
    let env = setup().await;
    let second = origin(Arc::new(AtomicUsize::new(0)), "second").await;

    // untouched binary bodies survive the trip through a worker; subrequests may target other hosts
    deploy(
        &env,
        "proxy",
        "example.com/p/*",
        &format!(
            r#"export default {{
                 async fetch(request) {{
                   const url = new URL(request.url);
                   if (url.pathname === "/p/external") return fetch("http://127.0.0.1:{second}/from-worker", {{ headers: {{ "x-a": "b" }} }});
                   if (url.pathname === "/p/redirect") return Response.redirect("https://example.com/new", 307);
                   const res = await fetch(request);
                   const out = new Response(res.body, res);
                   out.headers.set("x-proxied-by", "worker");
                   return out;
                 }}
               }}"#
        ),
    );
    let s = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    let mut s = s;
    s.write_all(raw("GET", "example.com", "/p/binary", "", "").as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    s.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.ends_with(&[b'\n', 0xff, 0xfe, 0x00, 0x80]), "{:?}", &bytes[bytes.len() - 8..]);
    assert!(String::from_utf8_lossy(&bytes).to_ascii_lowercase().contains("x-proxied-by: worker"));

    let r = get(&env, "example.com", "/p/external").await;
    assert!(r.body.contains("origin=second GET /from-worker host=127.0.0.1"), "{}", r.body);
    let r = get(&env, "example.com", "/p/redirect").await;
    assert_eq!((r.status, r.header("location")), (307, Some("https://example.com/new")));

    // the most specific route wins, and a route without a script disables workers
    deploy(&env, "inner", "example.com/p/inner/*", "export default { fetch() { return new Response('inner'); } }");
    assert_eq!(get(&env, "example.com", "/p/inner/x").await.body, "inner");
    env.store.save_item::<WorkerRoute>(&env.zone, None, json!({ "pattern": "example.com/p/inner/off/*", "script": null }), true).unwrap();
    assert!(get(&env, "example.com", "/p/inner/off/x").await.body.contains("origin=main"));
    assert!(get(&env, "www.example.com", "/p/inner/x").await.body.contains("origin=main"), "routes are host-specific");

    // failures become a 500 page: exceptions, runaway loops, missing return value
    deploy(&env, "throws", "example.com/bad/throw", "export default { fetch() { throw new Error('boom'); } }");
    deploy(&env, "spins", "example.com/bad/spin", "export default { fetch() { while (true) {} } }");
    deploy(&env, "nothing", "example.com/bad/nothing", "export default { async fetch() { return 42; } }");
    for path in ["/bad/throw", "/bad/spin", "/bad/nothing"] {
        let r = get(&env, "example.com", path).await;
        assert!(r.status == 500 && r.body.contains("Worker threw exception") && !r.body.contains("boom"), "{path}: {} {}", r.status, r.body);
    }

    // the WAF runs before workers; scripts in use cannot be deleted
    assert_eq!(get(&env, "example.com", "/p/x?q=%3Cscript%3Ealert(1)%3C/script%3E").await.status, 403);
    assert!(env.store.delete_worker("proxy").is_err());
    assert!(env.store.save_item::<WorkerRoute>(&env.zone, None, json!({ "pattern": "other.org/*", "script": "proxy" }), true).is_err());
    assert!(env.store.save_item::<WorkerRoute>(&env.zone, None, json!({ "pattern": "example.com/zz", "script": "missing" }), true).is_err());
}

fn client_tls(alpn: &[u8]) -> rustls::ClientConfig {
    let mut cfg = (*tls::client_config(false).unwrap()).clone();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg
}

#[tokio::test]
async fn serves_http2() {
    let env = setup().await;
    let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"h2")));
    let stream = connector.connect(rustls::pki_types::ServerName::try_from("example.com").unwrap(), tcp).await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);

    // two multiplexed requests on one connection
    let req = |method: &str, path: &str, body: &'static str| {
        Request::builder().method(method).uri(format!("https://example.com{path}")).body(full(body)).unwrap()
    };
    let (a, b) = tokio::join!(sender.clone().send_request(req("GET", "/h2/a.js", "")), sender.send_request(req("POST", "/h2/form", "k=v")));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!((a.version(), a.status()), (hyper::Version::HTTP_2, StatusCode::OK));
    assert_eq!(a.headers()["fcf-cache-status"], "MISS");
    assert!(a.headers()["alt-svc"].to_str().unwrap().starts_with("h3=\":"), "HTTPS responses advertise HTTP/3");
    let text = |r: Response<Incoming>| async { String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap() };
    assert!(text(a).await.contains("GET /h2/a.js host=example.com") );
    let b = text(b).await;
    assert!(b.contains("POST /h2/form") && b.contains("proto=https") && b.ends_with("body=k=v"), "{b}");
}

#[tokio::test]
async fn serves_http3() {
    use bytes::Buf;
    let env = setup().await;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint.connect(([127, 0, 0, 1], env.tls_port).into(), "example.com").unwrap().await.unwrap();
    let (mut driver, mut sender) = ::h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut call = async |method: &str, path: &str, body: &'static str| {
        let req = Request::builder().method(method).uri(format!("https://example.com{path}")).body(()).unwrap();
        let mut stream = sender.send_request(req).await.unwrap();
        if !body.is_empty() {
            stream.send_data(Bytes::from(body)).await.unwrap();
        }
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        let mut data = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        (resp, String::from_utf8(data).unwrap())
    };

    let (resp, body) = call("GET", "/h3/page?x=1", "").await;
    assert_eq!((resp.version(), resp.status()), (hyper::Version::HTTP_3, StatusCode::OK));
    assert!(body.contains("origin=main GET /h3/page?x=1 host=example.com") && body.contains("proto=https"), "{body}");
    assert_eq!(resp.headers()["server"], "fucf");

    // request bodies, the cache and the WAF all work over HTTP/3
    let (_, body) = call("POST", "/h3/submit", "payload-over-quic").await;
    assert!(body.ends_with("body=payload-over-quic"), "{body}");
    assert_eq!(call("GET", "/h3/app.css", "").await.0.headers()["fcf-cache-status"], "MISS");
    assert_eq!(call("GET", "/h3/app.css", "").await.0.headers()["fcf-cache-status"], "HIT");
    let (resp, body) = call("GET", "/h3/?q=%3Cscript%3Ealert(1)%3C/script%3E", "").await;
    assert!(resp.status() == StatusCode::FORBIDDEN && body.contains("Access denied"));
}

#[tokio::test]
async fn redirect_transform_and_cache_rules() {
    let env = setup().await;

    // redirects answer at the edge
    let redirect = |v| env.store.save_item::<RedirectRule>(&env.zone, None, v, true).unwrap();
    redirect(json!({ "expression": "http.request.uri.path eq \"/old\"", "target_url": "https://example.com/new", "status_code": 301, "preserve_query_string": true }));
    redirect(json!({ "expression": "http.host eq \"www.example.com\" and starts_with(http.request.uri.path, \"/go\")", "target_url": "/landing" }));
    let r = get(&env, "example.com", "/old?a=1&b=2").await;
    assert_eq!((r.status, r.header("location")), (301, Some("https://example.com/new?a=1&b=2")));
    let r = get(&env, "www.example.com", "/go/x?a=1").await;
    assert_eq!((r.status, r.header("location")), (302, Some("/landing")));
    assert_eq!(env.hits.load(Ordering::SeqCst), 0);
    assert!(env.store.save_item::<RedirectRule>(&env.zone, None, json!({ "target_url": "javascript:alert(1)" }), true).is_err());

    // transforms: path rewrite, request and response headers
    let transform = |v| env.store.save_item::<TransformRule>(&env.zone, None, v, true).unwrap();
    transform(json!({
        "expression": "starts_with(http.request.uri.path, \"/app/\")",
        "rewrite_path": "/internal/app",
        "set_request_headers": { "X-Added": "by-edge" }, "remove_request_headers": ["X-Forwarded-For"],
        "set_response_headers": { "X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=600" },
        "remove_response_headers": ["Cache-Control"],
    }));
    let r = send(&env, "GET", "example.com", "/app/page?q=1", "X-Forwarded-For: 10.1.1.1\r\n", "").await;
    assert!(r.body.contains("GET /internal/app?q=1") && r.body.contains("added=by-edge") && r.body.contains("xff=127.0.0.1 "), "{}", r.body);
    assert_eq!((r.header("x-frame-options"), r.header("cache-control")), (Some("DENY"), None));
    let r = get(&env, "example.com", "/other").await;
    assert!(r.body.contains("added=- ") && r.header("x-frame-options").is_none() && r.header("cache-control").is_some());
    assert!(env.store.save_item::<TransformRule>(&env.zone, None, json!({ "set_request_headers": { "Host": "evil" } }), true).is_err());
    assert!(env.store.save_item::<TransformRule>(&env.zone, None, json!({ "expression": "ssl" }), true).is_err());

    // cache rules: cache everything under /pages with a fixed TTL, never cache /assets/live
    let cache = |v| env.store.save_item::<CacheRule>(&env.zone, None, v, true).unwrap();
    cache(json!({ "expression": "starts_with(http.request.uri.path, \"/pages/\")", "cache": true, "edge_ttl": 300 }));
    cache(json!({ "expression": "starts_with(http.request.uri.path, \"/assets/live/\")", "cache": false }));
    assert_eq!(get(&env, "example.com", "/pages/home").await.header("fcf-cache-status"), Some("MISS"));
    assert_eq!(get(&env, "example.com", "/pages/home").await.header("fcf-cache-status"), Some("HIT"));
    // edge_ttl overrides an origin that says "private"
    assert_eq!(get(&env, "example.com", "/pages/private").await.header("fcf-cache-status"), Some("MISS"));
    assert_eq!(get(&env, "example.com", "/pages/private").await.header("fcf-cache-status"), Some("HIT"));
    assert_eq!(get(&env, "example.com", "/assets/live/feed.js").await.header("fcf-cache-status"), Some("BYPASS"));
    assert_eq!(get(&env, "example.com", "/assets/live/feed.js").await.header("fcf-cache-status"), Some("BYPASS"));
    assert_eq!(get(&env, "example.com", "/assets/other.js").await.header("fcf-cache-status"), Some("MISS"));
}

#[tokio::test]
async fn a_cache_rule_keeps_one_copy_per_value_of_the_headers_and_cookies_it_names() {
    let env = setup().await;
    let rule = json!({
        "expression": "starts_with(http.request.uri.path, \"/keyed/\")", "cache": true,
        "cache_key_headers": ["X-Lang"], "cache_key_cookies": ["variant"],
    });
    let saved = env.store.save_item::<CacheRule>(&env.zone, None, rule, true).unwrap();
    assert_eq!(saved.cache_key_headers, vec!["x-lang"], "header names are kept in lower case");
    let ask = |extra: String| {
        let env = &env;
        async move {
            let r = send(env, "GET", "example.com", "/keyed/page?x=1", &extra, "").await;
            let hit = r.body.rsplit("hit=").next().unwrap_or("").split(' ').next().unwrap_or("").to_string();
            (r.header("fcf-cache-status").map(String::from), hit)
        }
    };
    let s = |v: &str| v.to_string();
    let first = ask(s("X-Lang: en\r\n")).await;
    assert_eq!(first.0.as_deref(), Some("MISS"));
    assert_eq!(ask(s("X-Lang: en\r\n")).await, (Some(s("HIT")), first.1.clone()));
    assert_eq!(ask(s("x-lang: en\r\nCookie: other=1\r\n")).await, (Some(s("HIT")), first.1.clone()), "other cookies do not count");
    assert_eq!(ask(s("X-Lang: de\r\n")).await.0.as_deref(), Some("MISS"), "another value, another copy");
    assert_eq!(ask(s("")).await.0.as_deref(), Some("MISS"), "a missing header is a value of its own");
    let with_cookie = ask(s("X-Lang: en\r\nCookie: a=1;  variant=b\r\n")).await;
    assert_eq!(with_cookie.0.as_deref(), Some("MISS"));
    assert_eq!(ask(s("X-Lang: en\r\nCookie: variant=b; a=2\r\n")).await, (Some(s("HIT")), with_cookie.1.clone()));
    assert_eq!(ask(s("X-Lang: de\r\n")).await.0.as_deref(), Some("HIT"));

    // a purge by URL finds every copy of it, whatever the values
    assert_eq!(env.edge.cache.purge_urls(&env.zone, &["https://example.com/keyed/page?x=1".into()], false), 4);
    assert_eq!(ask(s("X-Lang: en\r\n")).await.0.as_deref(), Some("MISS"));
    assert_eq!(env.edge.cache.purge_urls(&env.zone, &["example.com/keyed/".into()], true), 1, "and a purge by prefix");

    // values that would make the key too long are neither stored nor looked up
    let long = format!("X-Lang: {}\r\n", "l".repeat(crate::edge::cachekey::MAX_KEY));
    let a = ask(long.clone()).await;
    let b = ask(long).await;
    assert_eq!((a.0.as_deref(), b.0.as_deref()), (Some("BYPASS"), Some("BYPASS")));
    assert_ne!(a.1, b.1, "both went to the origin");

    // without the rule's names, the key is the URL's as before: headers and cookies do not count
    let plain = |extra: &'static str| send(&env, "GET", "example.com", "/plain/app.js", extra, "");
    assert_eq!(plain("X-Lang: en\r\n").await.header("fcf-cache-status"), Some("MISS"));
    assert_eq!(plain("X-Lang: de\r\nCookie: variant=b\r\n").await.header("fcf-cache-status"), Some("HIT"));
    let long = format!("X-Lang: {}\r\n", "l".repeat(crate::edge::cachekey::MAX_KEY));
    let r = send(&env, "GET", "example.com", "/plain/app.js", &long, "").await;
    assert_eq!(r.header("fcf-cache-status"), Some("HIT"), "the limit is only for keys a rule added to");

    // names the rule may not hold are refused
    for bad in [json!({ "cache_key_headers": ["x a"] }), json!({ "cache_key_cookies": ["a=b"] }), json!({ "cache_key_headers": [""] })] {
        let mut body = json!({ "expression": "", "cache": true });
        body.as_object_mut().unwrap().extend(bad.as_object().unwrap().clone());
        assert!(env.store.save_item::<CacheRule>(&env.zone, None, body, true).is_err(), "{bad}");
    }
}

#[tokio::test]
async fn revalidates_and_answers_conditional_requests() {
    let env = setup().await;
    let first = get(&env, "example.com", "/etag/doc").await;
    assert_eq!((first.status, first.header("fcf-cache-status"), first.body.as_str()), (200, Some("MISS"), "etag-body hit=1"));

    // a client that already has the object gets 304 straight from the cache
    let cond = send(&env, "GET", "example.com", "/etag/doc", "If-None-Match: W/\"v1\"\r\n", "").await;
    assert_eq!((cond.status, cond.header("fcf-cache-status"), cond.body.as_str()), (304, Some("HIT"), ""));
    let other = send(&env, "GET", "example.com", "/etag/doc", "If-None-Match: \"v0\"\r\n", "").await;
    assert_eq!((other.status, other.body.as_str()), (200, "etag-body hit=1"));
    assert_eq!(env.hits.load(Ordering::SeqCst), 1);

    // once stale, the edge revalidates with the origin (a 304 without body) and keeps serving its copy
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let again = get(&env, "example.com", "/etag/doc").await;
    assert_eq!((again.status, again.header("fcf-cache-status"), again.body.as_str()), (200, Some("REVALIDATED"), "etag-body hit=1"));
    assert_eq!(env.hits.load(Ordering::SeqCst), 2);
    assert_eq!(get(&env, "example.com", "/etag/doc").await.header("fcf-cache-status"), Some("HIT"));
    assert_eq!(env.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn compresses_responses() {
    let env = setup().await;
    let plain_len = "compress me ".repeat(500).len();
    let fetch = |accept: &'static str| {
        let port = env.port;
        async move {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let extra = if accept.is_empty() { String::new() } else { format!("Accept-Encoding: {accept}\r\n") };
            s.write_all(raw("GET", "example.com", "/big/file.txt", &extra, "").as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            (String::from_utf8_lossy(&buf[..split]).to_ascii_lowercase(), buf[split + 4..].to_vec())
        }
    };

    let (head, body) = fetch("").await;
    assert!(!head.contains("content-encoding") && body.len() == plain_len);

    let (head, body) = fetch("gzip, deflate").await;
    assert!(head.contains("content-encoding: gzip") && head.contains("vary: accept-encoding"), "{head}");
    assert!(body.len() < plain_len / 10 && head.contains(&format!("content-length: {}", body.len())));
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&body[..]), &mut text).unwrap();
    assert_eq!(text.len(), plain_len);

    let (head, body) = fetch("gzip, br").await;
    assert!(head.contains("content-encoding: br"), "{head}");
    let mut out = Vec::new();
    brotli::BrotliDecompress(&mut &body[..], &mut out).unwrap();
    assert_eq!(out.len(), plain_len);

    let (head, body) = fetch("gzip, zstd").await;
    assert!(head.contains("content-encoding: zstd") && head.contains(&format!("content-length: {}", body.len())), "{head}");
    assert_eq!(zstd::stream::decode_all(&body[..]).unwrap().len(), plain_len);
    let (head, _) = fetch("zstd;q=0, gzip").await;
    assert!(head.contains("content-encoding: gzip"), "{head}");

    // small bodies and non-text types are left alone
    let small = send(&env, "GET", "example.com", "/hello", "Accept-Encoding: gzip\r\n", "").await;
    assert!(small.header("content-encoding").is_none() && small.body.contains("origin=main"));
}

#[tokio::test]
async fn a_visitor_that_does_not_take_zstd_never_gets_a_zstd_body_from_the_cache() {
    let env = setup().await;
    let (chrome, safari) = ("Accept-Encoding: gzip, deflate, br, zstd\r\n", "Accept-Encoding: gzip, deflate, br\r\n");
    let hits = || env.hits.load(Ordering::SeqCst);

    let first = send(&env, "GET", "example.com", "/zstd-origin/a.css", chrome, "").await;
    assert_eq!((first.header("content-encoding"), first.header("fcf-cache-status")), (Some("zstd"), Some("MISS")), "{}", first.head);
    let again = send(&env, "GET", "example.com", "/zstd-origin/a.css", chrome, "").await;
    assert_eq!((again.header("content-encoding"), again.header("fcf-cache-status")), (Some("zstd"), Some("HIT")));
    assert_eq!(hits(), 1);
    // a client that takes less gets the origin's plain answer, never the zstd copy;
    // that plain copy then serves every client, zstd-only ones included
    let r = send(&env, "GET", "example.com", "/zstd-origin/a.css", safari, "").await;
    assert!(r.header("content-encoding").is_none() && r.body == "plain hit=2" && r.header("fcf-cache-status") == Some("MISS"), "{} {}", r.head, r.body);
    for extra in ["Accept-Encoding: zstd;q=0, gzip\r\n", "", "Accept-Encoding: ZSTD\r\n", safari] {
        let r = send(&env, "GET", "example.com", "/zstd-origin/a.css", extra, "").await;
        assert!(r.header("content-encoding").is_none() && r.body == "plain hit=2" && r.header("fcf-cache-status") == Some("HIT"), "{extra}: {} {}", r.head, r.body);
    }
    let again = send(&env, "GET", "example.com", "/zstd-origin/a.css", chrome, "").await;
    assert_eq!(again.header("content-encoding"), Some("zstd"), "the compressed copy is still there for those that take it");
    assert_eq!(hits(), 2);

    // an origin that sends zstd to anyone: passed on as it came, never kept for the next visitor
    let before = hits();
    for extra in [safari, safari, ""] {
        let r = send(&env, "GET", "example.com", "/zstd-origin/always/b.css", extra, "").await;
        assert_eq!(r.header("content-encoding"), Some("zstd"));
        assert_ne!(r.header("fcf-cache-status"), Some("HIT"));
    }
    assert_eq!(hits(), before + 3, "each one went to the origin");
}

#[tokio::test]
async fn fails_over_between_origins_and_counts_traffic() {
    let env = setup().await;
    // lb.example.com has two addresses; the first one (127.0.0.2) has nothing listening
    for ip in ["127.0.0.2", "127.0.0.1"] {
        let mut r = rec("lb", "A", ip);
        r.proxied = true;
        env.store.create_record(&env.zone, r).unwrap();
    }
    for i in 0..6 {
        let r = get(&env, "lb.example.com", &format!("/lb/{i}")).await;
        assert!(r.status == 200 && r.body.contains("host=lb.example.com"), "request {i}: {} {}", r.status, r.body);
    }
    // POST bodies that were buffered are replayed on the healthy origin too
    let r = send(&env, "POST", "lb.example.com", "/lb/post", "", "payload").await;
    assert!(r.status == 200 && r.body.ends_with("body=payload"), "{}", r.body);

    // analytics: counts by status class, cache and WAF outcome
    get(&env, "example.com", "/s/a.css").await;
    get(&env, "example.com", "/s/a.css").await;
    get(&env, "example.com", "/.env").await;
    let stats = env.edge.stats.summary(60).remove(&env.zone).unwrap_or_default();
    assert_eq!((stats.requests, stats.status_2xx, stats.status_4xx, stats.cached, stats.threats), (10, 9, 1, 1, 1));
    assert!(stats.http1 == 10 && stats.bytes > 500);
}

#[tokio::test]
async fn serves_ranges_unsized_objects_and_stale_copies() {
    let env = setup().await;
    let hits = || env.hits.load(Ordering::SeqCst);
    let ranged = |uri: &'static str, range: &'static str| {
        let extra = format!("Range: {range}\r\n");
        let env = &env;
        async move { send(env, "GET", "example.com", uri, &extra, "").await }
    };

    // parts are cut from a cached object
    let whole = get(&env, "example.com", "/r/app.js").await;
    let len = whole.body.len();
    assert_eq!((whole.header("fcf-cache-status"), hits()), (Some("MISS"), 1));
    let part = ranged("/r/app.js", "bytes=7-11").await;
    assert_eq!((part.status, part.header("fcf-cache-status")), (206, Some("HIT")));
    assert_eq!(part.header("content-range"), Some(format!("bytes 7-11/{len}").as_str()));
    assert_eq!((part.header("content-length"), part.body.as_str()), (Some("5"), &whole.body[7..=11]));
    assert_eq!(ranged("/r/app.js", "bytes=-4").await.body, whole.body[len - 4..]);
    let open = ranged("/r/app.js", "bytes=10-").await;
    assert_eq!((open.status, open.body.as_str()), (206, &whole.body[10..]));
    let beyond = ranged("/r/app.js", "bytes=99999-").await;
    assert_eq!((beyond.status, beyond.header("content-range")), (416, Some(format!("bytes */{len}").as_str())));
    // several ranges, or a range of another version: the whole object
    let multi = ranged("/r/app.js", "bytes=0-1,4-5").await;
    assert_eq!((multi.status, multi.body.len(), multi.header("accept-ranges")), (200, len, Some("bytes")));
    let other = send(&env, "GET", "example.com", "/r/app.js", "Range: bytes=0-1\r\nIf-Range: \"v0\"\r\n", "").await;
    assert_eq!((other.status, other.body.len()), (200, len));
    let head = send(&env, "HEAD", "example.com", "/r/app.js", "Range: bytes=0-1\r\n", "").await;
    assert_eq!((head.status, head.header("content-length"), head.body.as_str()), (206, Some("2"), ""));
    assert_eq!(hits(), 1, "all of that came from the cache");
    // without a cached copy the request goes to the origin as it is, and its answer is not kept
    assert_eq!(ranged("/r/cold.js", "bytes=0-3").await.header("fcf-cache-status"), Some("DYNAMIC"));
    assert_eq!(get(&env, "example.com", "/r/cold.js").await.header("fcf-cache-status"), Some("MISS"));

    // If-Modified-Since is a date comparison
    assert_eq!(get(&env, "example.com", "/lm/lastmod.css").await.header("fcf-cache-status"), Some("MISS"));
    let since = |date: &'static str| {
        let extra = format!("If-Modified-Since: {date}\r\n");
        let env = &env;
        async move { send(env, "GET", "example.com", "/lm/lastmod.css", &extra, "").await }
    };
    assert_eq!(since("Thu, 22 Oct 2015 00:00:00 GMT").await.status, 304);
    assert_eq!(since("Wed, 21 Oct 2015 07:28:00 GMT").await.status, 304);
    let older = since("Tue, 20 Oct 2015 00:00:00 GMT").await;
    assert_eq!((older.status, older.body.as_str()), (200, "dated"));

    // a response without Content-Length is stored once it was read
    let before = hits();
    let first = get(&env, "example.com", "/c/chunked.js").await;
    assert_eq!((first.header("fcf-cache-status"), first.body.as_str()), (Some("MISS"), "chunk-0;chunk-1;chunk-2;"));
    assert_eq!(first.header("content-length"), Some("24"));
    let second = get(&env, "example.com", "/c/chunked.js").await;
    assert_eq!((second.header("fcf-cache-status"), second.body.as_str(), hits()), (Some("HIT"), "chunk-0;chunk-1;chunk-2;", before + 1));
    // ... unless it is too long for that: then it is passed on as it comes
    for _ in 0..2 {
        let huge = get(&env, "example.com", "/c/huge-chunked.js").await;
        assert!(huge.status == 200 && huge.body.len() >= 9 << 20, "{} {}", huge.status, huge.body.len());
    }
    assert_eq!(hits(), before + 3);

    // an expired copy is served while the origin fails
    let fresh = get(&env, "example.com", "/f/flaky.css").await;
    assert_eq!((fresh.status, fresh.header("fcf-cache-status")), (200, Some("MISS")));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    FLAKY_DOWN.store(true, Ordering::SeqCst);
    let stale = get(&env, "example.com", "/f/flaky.css").await;
    assert_eq!((stale.status, stale.header("fcf-cache-status"), &stale.body), (200, Some("STALE"), &fresh.body));
    // ... or cannot be reached at all
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let rule = json!({ "expression": "http.request.uri.path contains \"flaky\"", "origin_port": closed, "priority": 1 });
    env.store.save_item::<OriginRule>(&env.zone, None, rule, true).unwrap();
    let stale = get(&env, "example.com", "/f/flaky.css").await;
    assert_eq!((stale.status, stale.header("fcf-cache-status"), &stale.body), (200, Some("STALE"), &fresh.body));
    // without a copy the error is what the visitor gets
    assert_eq!(get(&env, "example.com", "/f/flaky-too.css").await.status, 521);
    FLAKY_DOWN.store(false, Ordering::SeqCst);
}

#[tokio::test]
async fn decoy_names_get_nothing_and_a_leaving_node_says_it_is_updating() {
    let env = setup().await;
    assert_eq!(get(&env, "nope.example.com", "/").await.status, 404, "an unknown name, decoys off");
    env.store.update_setting(&env.zone, "decoy_subdomains", json!(true)).unwrap();

    // plain HTTP: the connection is closed without a byte
    let r = get(&env, "nope.example.com", "/").await;
    assert!(r.status == 0 && r.head.is_empty(), "{}", r.head);
    assert_eq!(get(&env, "www.example.com", "/").await.status, 200, "real names are served as before");
    // HTTPS: no handshake for a decoy name
    let handshake = |sni: &'static str| async move {
        let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls::client_config(false).unwrap());
        connector.connect(rustls::pki_types::ServerName::try_from(sni).unwrap(), tcp).await.is_ok()
    };
    assert!(!handshake("deep.nope.example.com").await);
    assert!(handshake("www.example.com").await);

    // about to go: every visitor gets the page that reloads itself
    env.edge.leave(false, Duration::from_millis(10)).await;
    let r = get(&env, "www.example.com", "/").await;
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), Some("30"));
    assert!(r.body.contains("<meta http-equiv=\"refresh\" content=\"30\">") && r.body.contains("边缘节点正在更新"), "{}", r.body);
    assert!(r.body.contains("This edge node is updating") && r.body.contains("class=\"hop warn\""), "{}", r.body);
    env.edge.resume();
    assert_eq!(get(&env, "www.example.com", "/").await.status, 200);
}

#[tokio::test]
async fn the_human_check_lets_a_person_through_and_keeps_automation_out() {
    let env = setup().await;
    let rule = json!({ "expression": "http.request.uri.path eq \"/guarded\"", "action": "managed_challenge" });
    env.store.save_item::<FirewallRule>(&env.zone, None, rule, true).unwrap();
    const UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15";
    let browser = format!("User-Agent: {UA}\r\nAccept-Language: zh-CN,zh;q=0.9\r\n");

    let r = send(&env, "GET", "example.com", "/guarded", &browser, "").await;
    assert_eq!((r.status, r.header("fcf-mitigated")), (403, Some("challenge")));
    assert!(r.body.contains("Verify you are human") && r.body.contains("challenge-platform/verify"), "{}", r.body);
    assert_eq!(env.hits.load(Ordering::SeqCst), 0);
    let config: serde_json::Value = {
        let start = r.body.find("<script type=\"application/json\" id=\"fc\">").unwrap() + 40;
        let end = start + r.body[start..].find("</script>").unwrap();
        serde_json::from_str(&r.body[start..end]).unwrap()
    };
    let ticket = config["t"].as_str().unwrap().to_string();
    let bits = config["b"].as_u64().unwrap() as u8;
    let n = (0u64..).find(|n| challenge::work_done(&ticket, *n, bits)).unwrap();

    let report = |signals: serde_json::Value, mode: &str| {
        json!({ "t": ticket, "n": n, "m": mode, "s": signals,
            "c": { "trusted": true, "dt": 1200, "detail": 1, "pt": "mouse" },
            "ev": { "moves": 30, "dist": 500, "first": 200, "keys": 0, "touch": 0, "scroll": 0, "age": 1500 } })
        .to_string()
    };
    let safari = json!({ "wd": false, "auto": [], "ua": UA, "uad": null, "langs": 2, "plug": 5, "hc": 8, "scr": [1512, 982, 1512, 944, 30],
        "win": [1512, 860, 1512, 944], "tz": "Asia/Shanghai", "touch": 0, "chrome": false, "own": 0, "wdp": true, "nat": 0,
        "gl": "Apple Inc. / Apple GPU", "cdp": false, "notif": "default", "perm": "prompt" });
    let env = &env;
    let post = |body: String| {
        let headers = format!("{browser}Content-Type: application/json\r\n");
        async move { send(&env, "POST", "example.com", "/cdn-cgi/challenge-platform/verify", &headers, &body).await }
    };

    // a managed challenge needs the click
    let r = post(report(safari.clone(), "auto")).await;
    assert!(r.status == 200 && r.body.contains("\"need\":\"click\""), "{}", r.body);
    // a driven browser fails, even with a click
    let mut driven = safari.clone();
    driven["wd"] = json!(true);
    let r = post(report(driven, "click")).await;
    assert!(r.status == 403 && r.body.contains("webdriver") && r.header("set-cookie").is_none(), "{}", r.body);
    // the work has to be done
    let lazy = report(safari.clone(), "click").replace(&format!("\"n\":{n}"), &format!("\"n\":{}", n + 1));
    let r = post(lazy).await;
    assert!(r.status == 403 && r.body.contains("bad_work") || challenge::work_done(&ticket, n + 1, bits), "{}", r.body);
    // a person clicks: cleared
    let r = post(report(safari, "click")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let cookie = r.header("set-cookie").unwrap().to_string();
    assert!(cookie.starts_with("fucf_clearance=") && cookie.contains("HttpOnly"), "{cookie}");
    let pair = cookie.split(';').next().unwrap();
    let r = send(&env, "GET", "example.com", "/guarded", &format!("{browser}Cookie: {pair}\r\n"), "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    // another browser cannot use the ticket
    let r = send(&env, "POST", "example.com", "/cdn-cgi/challenge-platform/verify", "User-Agent: curl/8\r\nContent-Type: application/json\r\n", &report(json!({}), "click")).await;
    assert!(r.status == 403 && r.body.contains("other_visitor"), "{}", r.body);
}

#[tokio::test]
async fn zone_settings_shape_requests_and_responses() {
    let env = setup().await;
    let set = |name: &str, value: serde_json::Value| env.store.update_setting(&env.zone, name, value);

    // under attack: a JavaScript challenge before anything else
    set("security_level", json!("under_attack")).unwrap();
    let r = get(&env, "example.com", "/").await;
    assert!(r.status == 403 && r.body.contains("Checking your browser"), "{}", r.body);
    assert_eq!(env.hits.load(Ordering::SeqCst), 0);
    let cleared = format!("Cookie: {}={}\r\n", waf::CLEARANCE_COOKIE, env.edge.waf.clearance_token(&env.zone, "127.0.0.1".parse().unwrap()));
    assert_eq!(send(&env, "GET", "example.com", "/", &cleared, "").await.status, 200);
    // a skip rule exempts clients that cannot run JavaScript
    let skip = json!({ "expression": "http.request.uri.path eq \"/api/hook\"", "action": "skip" });
    env.store.save_item::<FirewallRule>(&env.zone, None, skip, true).unwrap();
    assert_eq!(get(&env, "example.com", "/api/hook").await.status, 200);
    assert!(env.edge.waf.events(&env.zone, 10).iter().any(|e| e.source == "security_level" && e.action == "js_challenge"));
    assert!(set("security_level", json!("paranoid")).is_err());
    set("security_level", json!("medium")).unwrap();
    assert_eq!(get(&env, "example.com", "/").await.status, 200);

    // browser cache TTL: raises the lifetime of what the edge caches, leaves the rest alone
    set("browser_cache_ttl", json!(3600)).unwrap();
    for expected in ["MISS", "HIT"] {
        let r = get(&env, "example.com", "/s/site.css").await;
        assert_eq!((r.header("fcf-cache-status"), r.header("cache-control")), (Some(expected), Some("public, max-age=3600")));
    }
    assert_eq!(get(&env, "example.com", "/page").await.header("cache-control"), Some("max-age=60"));
    set("browser_cache_ttl", json!(30)).unwrap();
    assert_eq!(get(&env, "example.com", "/s/site.css").await.header("cache-control"), Some("max-age=60"), "a longer lifetime from the origin stands");

    // HSTS: only over HTTPS
    set("hsts_max_age", json!(31536000)).unwrap();
    set("hsts_include_subdomains", json!("on")).unwrap();
    assert!(get(&env, "example.com", "/").await.header("strict-transport-security").is_none());
    let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(tls::client_config(false).unwrap());
    let s = connector.connect(rustls::pki_types::ServerName::try_from("example.com").unwrap(), tcp).await.unwrap();
    let r = exchange(s, raw("GET", "example.com", "/", "", "")).await;
    assert_eq!(r.header("strict-transport-security"), Some("max-age=31536000; includeSubDomains"));
    assert!(set("hsts_max_age", json!(99_999_999)).is_err());

    // the origin is told the visitor's country as the edge sees it, never as the client claims
    let r = send(&env, "GET", "example.com", "/", "CF-IPCountry: US\r\n", "").await;
    assert!(r.body.contains("country=- "), "{}", r.body);
}

#[tokio::test]
async fn node_limits_stop_and_slow_the_node() {
    use crate::limits::State;
    let env = setup().await;
    let _ = env.edge.assets_host.set("limit.cdn.example.net".into());
    let limits = &env.edge.limits;
    let hits = || env.hits.load(Ordering::SeqCst);
    // this node's limits, `dns` / `hard` bytes above what it has used so far
    let allow = |dns: u64, hard: u64, mbps: Option<f64>| {
        let used = limits.usage().used_bytes;
        let gb = |extra: u64| (used + extra) as f64 / 1e9;
        let mut node: crate::items::EdgeNode = serde_json::from_value(json!({
            "name": "au", "ipv4": "203.0.113.1", "traffic_dns_gb": gb(dns), "traffic_limit_gb": gb(hard), "rate_limit_mbps": mbps,
        }))
        .unwrap();
        node.validate(&[]).unwrap();
        limits.configure("au", Some(&node));
    };
    // what a response costs is booked when it has been sent
    let settled = |wanted: State| async move {
        for _ in 0..200 {
            if limits.state() == wanted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the node did not become {wanted:?}: {:?}", limits.usage());
    };

    // a node with allowance left serves the notice's resources, whatever the host
    let css = get(&env, "limit.cdn.example.net", "/cdn-cgi/limit/page.css").await;
    assert!(css.status == 200 && css.header("content-type") == Some("text/css; charset=utf-8") && css.body.contains("font:"), "{}", css.head);
    assert_eq!(get(&env, "example.com", "/cdn-cgi/limit/mark.svg").await.header("content-type"), Some("image/svg+xml"));
    assert!(limits.usage().used_bytes > 500, "they count as traffic too");

    // past the DNS threshold the node keeps serving
    allow(200, 4000, None);
    assert_eq!(limits.state(), State::Ok);
    for _ in 0..3 {
        assert_eq!(get(&env, "example.com", "/hello").await.status, 200);
    }
    settled(State::DnsLimited).await;
    assert_eq!(get(&env, "example.com", "/hello").await.status, 200);

    // past the hard limit it serves the notice and nothing else
    assert_eq!(get(&env, "example.com", "/big").await.status, 200);
    settled(State::Limited).await;
    let (origin_hits, used) = (hits(), limits.usage().used_bytes);
    let refused = get(&env, "example.com", "/hello").await;
    assert_eq!((refused.status, refused.header("cache-control"), refused.header("retry-after")), (509, Some("no-store"), Some("300")));
    assert!(refused.header("fucf-ray").is_some() && refused.header("content-type") == Some("text/html; charset=utf-8"));
    // ... which takes its looks from a name that resolves to other nodes
    assert!(refused.body.contains("href=\"https://limit.cdn.example.net/cdn-cgi/limit/page.css\""), "{}", refused.body);
    assert!(refused.body.contains("src=\"https://limit.cdn.example.net/cdn-cgi/limit/mark.svg\"") && refused.body.contains("DNS"));
    assert!(refused.body.len() < 2000 && !refused.body.contains("font:"));
    assert_eq!(get(&env, "other.org", "/").await.status, 509, "whatever the host");
    // asked for those resources itself, it returns nothing (empty 509)
    for path in ["/cdn-cgi/limit/page.css", "/cdn-cgi/limit/mark.svg", "/cdn-cgi/limit/anything"] {
        let bare = get(&env, "limit.cdn.example.net", path).await;
        assert_eq!((bare.status, bare.header("content-type")), (509, Some("text/plain; charset=utf-8")), "{path}");
        assert!(bare.body.is_empty(), "expected empty body, got: {}", bare.body);
    }
    assert_eq!(hits(), origin_hits, "nothing reaches the origin");
    assert!(limits.usage().used_bytes > used, "the notices are traffic as well");
    // a gRPC client is told in its own terms
    let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"h2")));
    let stream = connector.connect(rustls::pki_types::ServerName::try_from("example.com").unwrap(), tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let call = Request::builder().method("POST").uri("https://example.com/pkg.Echo/Once").header("content-type", "application/grpc").body(full("ping")).unwrap();
    let resp = sender.send_request(call).await.unwrap();
    assert_eq!((resp.status(), resp.headers()["grpc-status"].to_str().unwrap()), (StatusCode::OK, "8"));

    // a higher limit puts the node back to work
    allow(1 << 30, 1 << 31, None);
    assert_eq!((limits.state(), get(&env, "example.com", "/hello").await.status), (State::Ok, 200));

    // speed limit: 2 Mbit/s is 250 kB/s, so 400 kB take over a second -- from the origin and from the cache
    let timed = |uri: &'static str| {
        let env = &env;
        async move {
            let started = Instant::now();
            let reply = get(env, "example.com", uri).await;
            (reply.header("fcf-cache-status").map(String::from), reply.body.len(), started.elapsed())
        }
    };
    let (_, len, unlimited) = timed("/dl/blob-a.bin").await;
    assert!(len == 400_000 && unlimited < Duration::from_millis(900), "{len} {unlimited:?}");
    allow(1 << 30, 1 << 31, Some(2.0));
    for expected in ["MISS", "HIT"] {
        let (label, len, took) = timed("/dl/blob-b.bin").await;
        assert_eq!((label.as_deref(), len), (Some(expected), 400_000));
        assert!(took > Duration::from_millis(1000) && took < Duration::from_secs(8), "{expected}: {took:?}");
    }
    allow(1 << 30, 1 << 31, None);
    assert!(timed("/dl/blob-b.bin").await.2 < Duration::from_millis(900));
}

#[tokio::test]
async fn http3_front_hands_over_its_visitors() {
    let env = setup().await;
    // another QUIC server holds UDP 443; its certificate covers example.com and the panel's name, nothing else
    let cert_path = std::env::temp_dir().join(format!("fucf-front-{}.crt", uuid::Uuid::new_v4().simple()));
    let names = vec!["example.com".to_string(), "panel.example.net".to_string()];
    std::fs::write(&cert_path, rcgen::generate_simple_self_signed(names).unwrap().cert.pem()).unwrap();
    let _ = env.edge.front.set(Arc::new(front::Front::new(443, Some(cert_path.clone()))));
    std::fs::remove_file(&cert_path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_port = listener.local_addr().unwrap().port();
    tokio::spawn(front::serve(listener, env.edge.clone()));
    let via_front = async |host: &str, uri: &str, extra: &str| {
        exchange(TcpStream::connect(("127.0.0.1", front_port)).await.unwrap(), raw("GET", host, uri, extra, "")).await
    };

    // what a Hysteria masquerade sends: the visitor appended to X-Forwarded-For, the host name as asked for
    let forwarded = "X-Forwarded-For: 10.9.9.9, 198.51.100.7\r\nX-Forwarded-Host: example.com\r\nX-Forwarded-Proto: https\r\n";
    let r = via_front("127.0.0.1:18480", "/hello", forwarded).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("GET /hello host=example.com xff=10.9.9.9, 198.51.100.7 ip=198.51.100.7 proto=https"), "{}", r.body);
    // HTTP/3 works for this name (the front's certificate covers it): it stays on offer, on the front's port
    assert_eq!(r.header("alt-svc"), Some("h3=\":443\"; ma=86400"));
    // the edge sees the visitor as the visitor came: over HTTP/3 and TLS, from an address of its own
    let r = via_front("example.com", "/cdn-cgi/fucf-trace", forwarded).await;
    for line in ["h=example.com", "ip=198.51.100.7", "http=http/3", "visit_scheme=https", "tls=TLSv1.3", "sni=plaintext"] {
        assert!(r.body.lines().any(|l| l == line), "{line} in {}", r.body);
    }
    // a name the front's certificate does not cover is pointed at our own QUIC listener instead
    let r = via_front("www.example.com", "/hello", "X-Forwarded-For: 198.51.100.7\r\n").await;
    assert!(r.body.contains("host=www.example.com xff=198.51.100.7 ip=198.51.100.7 proto=https"), "{}", r.body);
    assert_eq!(r.header("alt-svc").map(String::from), Some(format!("h3=\":{}\"; ma=86400", env.tls_port)));
    // the security rules see the real visitor
    env.store.save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "ip.src eq 198.51.100.7", "action": "block" }), true).unwrap();
    assert_eq!(via_front("example.com", "/hello", forwarded).await.status, 403);
    assert_eq!(via_front("example.com", "/hello", "X-Forwarded-For: 198.51.100.7, 198.51.100.8\r\n").await.status, 200, "a claimed address is not the visitor's");
    // what an origin says about its own HTTP/3 endpoints is not passed on, fresh or from the cache:
    // only what works here is on offer
    for expected in ["MISS", "HIT"] {
        let r = get(&env, "www.example.com", "/altsvc/app.js").await;
        assert_eq!((r.header("fcf-cache-status"), r.header("alt-svc"), r.body.as_str()), (Some(expected), None, "behind another CDN"));
    }
    let r = via_front("www.example.com", "/altsvc/app.js", "X-Forwarded-For: 198.51.100.9\r\n").await;
    assert_eq!((r.body.as_str(), r.header("alt-svc").map(String::from)), ("behind another CDN", Some(format!("h3=\":{}\"; ma=86400", env.tls_port))));
    // the management panel is ours too: it is reached over HTTP/3 like a site, and says so
    let _ = env.edge.panel.set(("panel.example.net".to_string(), ([127, 0, 0, 1], env.origin_port).into()));
    let r = via_front("panel.example.net", "/client/v4/system", "X-Forwarded-For: 198.51.100.9\r\n").await;
    assert!(r.status == 200 && r.body.contains("GET /client/v4/system host=panel.example.net xff=198.51.100.9"), "{}", r.body);
    assert_eq!(r.header("alt-svc"), Some("h3=\":443\"; ma=86400"));
    assert_eq!(get(&env, "panel.example.net", "/").await.header("alt-svc"), None, "not over plain HTTP");
    // plain HTTP passed on by a front is plain HTTP
    let r = via_front("example.com", "/cdn-cgi/fucf-trace", "X-Forwarded-For: 198.51.100.9\r\nX-Forwarded-Proto: http\r\n").await;
    assert!(r.body.contains("visit_scheme=http\n") && r.body.contains("http=http/1.1\n") && r.header("alt-svc").is_none(), "{}", r.body);
    // requests that reach the edge directly are as before: nobody is believed about X-Forwarded-For
    let r = send(&env, "GET", "example.com", "/cdn-cgi/fucf-trace", "X-Forwarded-For: 198.51.100.7\r\n", "").await;
    assert!(r.body.contains("ip=127.0.0.1\n"), "{}", r.body);
}

#[tokio::test]
async fn cdn_cgi_is_the_edge_itself() {
    use std::collections::HashMap;
    let env = setup().await;
    env.edge.limits.configure("au", None);
    let hits = || env.hits.load(Ordering::SeqCst);
    let fields = |body: &str| -> HashMap<String, String> {
        body.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
    };

    // the trace: what the node sees of the visitor, in Cloudflare's format
    let r = send(&env, "GET", "example.com", "/cdn-cgi/fucf-trace", "User-Agent: probe/1.0\r\n", "").await;
    assert_eq!((r.status, r.header("content-type"), r.header("cache-control")), (200, Some("text/plain; charset=utf-8"), Some("no-store")));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    let t = fields(&r.body);
    let expected = [
        ("h", "example.com"), ("ip", "127.0.0.1"), ("visit_scheme", "http"), ("uag", "probe/1.0"), ("colo", "AU"), ("dc", "1"),
        ("http", "http/1.1"), ("loc", "XX"), ("tls", "off"), ("sni", "off"), ("warp", "off"), ("zone", "example.com"), ("limit", "ok"),
        ("client_cert", "none"),
    ];
    for (key, value) in expected {
        assert_eq!(t.get(key).map(String::as_str), Some(value), "{key} in {}", r.body);
    }
    assert_eq!(t["ray"], r.header("fucf-ray").unwrap());
    // a tool's User-Agent and no browser headers: the bot side of the score
    assert!(t["bot"].parse::<i64>().is_ok_and(|bot| (1..30).contains(&bot)), "{}", r.body);
    assert!(t["ts"].split_once('.').is_some_and(|(secs, millis)| secs.len() == 10 && millis.len() == 3), "{}", t["ts"]);
    assert!(t["fl"].split_once('f').is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit())), "{}", t["fl"]);
    assert!(r.body.starts_with(&format!("fl={}\nh=example.com\nip=127.0.0.1\nts=", t["fl"])), "Cloudflare's keys come first, in its order: {}", r.body);

    // over TLS and HTTP/2, for a host nobody configured, with the visitor located
    let mut geo = crate::geo::Geo::default();
    let located = crate::geo::Location { continent: Some("AS".into()), country: Some("CN".into()), region: None, asn: Some(4134), as_org: Some("chinanet".into()) };
    geo.fixed.insert("127.0.0.1".parse().unwrap(), located);
    let _ = env.edge.geo.set(Arc::new(geo));
    let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"h2")));
    let stream = connector.connect(rustls::pki_types::ServerName::try_from("stranger.org").unwrap(), tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder().uri("https://stranger.org/cdn-cgi/fucf-trace").body(full("")).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let t = fields(&body);
    let expected = [("h", "stranger.org"), ("visit_scheme", "https"), ("http", "http/2"), ("tls", "TLSv1.3"), ("sni", "plaintext"), ("loc", "CN"), ("asn", "4134"), ("zone", "-")];
    for (key, value) in expected {
        assert_eq!(t.get(key).map(String::as_str), Some(value), "{key} in {body}");
    }
    // the client config is the edge's own (origin pulls), which offers the post-quantum hybrid first
    assert_eq!(t["kex"], "X25519MLKEM768", "{body}");
    let bot: i64 = t["bot"].parse().unwrap();
    assert!((1..=99).contains(&bot), "{body}");

    // and over HTTP/3
    use bytes::Buf;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint.connect(([127, 0, 0, 1], env.tls_port).into(), "example.com").unwrap().await.unwrap();
    let (mut driver, mut h3_sender) = ::h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut stream = h3_sender.send_request(Request::builder().uri("https://example.com/cdn-cgi/fucf-trace").body(()).unwrap()).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(stream.recv_response().await.unwrap().status(), StatusCode::OK);
    let mut data = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    let t = fields(std::str::from_utf8(&data).unwrap());
    assert_eq!((t["http"].as_str(), t["tls"].as_str(), t["visit_scheme"].as_str()), ("http/3", "TLSv1.3", "https"));

    // the zone's WAF and rules have no say here
    let block = json!({ "expression": "http.request.uri.path contains \"cdn-cgi\"", "action": "block" });
    env.store.save_item::<FirewallRule>(&env.zone, None, block, true).unwrap();
    assert_eq!(get(&env, "example.com", "/cdn-cgi/fucf-trace?q=%3Cscript%3Ealert(1)%3C/script%3E").await.status, 200);

    // the reserved endpoint: the edge's, with everything below it, and not doing anything yet
    for (method, path) in [("GET", "/cdn-cgi/fucf-warp"), ("POST", "/cdn-cgi/fucf-warp"), ("GET", "/cdn-cgi/fucf-warp/"), ("PUT", "/cdn-cgi/fucf-warp/any/thing?x=1")] {
        let r = send(&env, method, "example.com", path, "", "").await;
        assert_eq!((r.status, r.header("content-type")), (501, Some("text/plain; charset=utf-8")), "{method} {path}");
        assert!(r.body.contains("reserved"), "{}", r.body);
    }
    // ... but with a part of the edge cache to itself, purged apart from the zones'
    let keep = |key: &str, ttl: u64| warp::store(&env.edge, key, StatusCode::OK, HeaderMap::new(), Bytes::from("kept"), Duration::from_millis(ttl));
    keep("a/1", 60_000);
    keep("a/2", 60_000);
    keep("b", 60_000);
    keep("brief", 1);
    assert_eq!(warp::cached(&env.edge, "a/1").map(|e| e.body.clone()), Some(Bytes::from("kept")));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(warp::cached(&env.edge, "brief").is_none() && warp::cached(&env.edge, "nope").is_none());
    assert_eq!(env.edge.cache.purge_zone(&env.zone), 0, "a zone's purge leaves it alone");
    assert_eq!(env.edge.cache.purge_urls(warp::CACHE_SCOPE, &["a/".into()], true), 2);
    assert_eq!(env.edge.cache.purge_urls(env.zone.as_str(), &["b".into()], false), 0);
    assert!(warp::cached(&env.edge, "a/1").is_none() && warp::cached(&env.edge, "b").is_some());
    assert_eq!(env.edge.cache.purge_zone(warp::CACHE_SCOPE), 2);
    assert!(warp::cached(&env.edge, "b").is_none());

    // nothing else exists under /cdn-cgi, and nothing of it ever reaches an origin
    for path in ["/cdn-cgi", "/cdn-cgi/", "/cdn-cgi/trace", "/cdn-cgi/fucf-trace/more", "/cdn-cgi/fucf-warped", "/cdn-cgi/limit", "/cdn-cgi/limit/nothing.css", "/cdn-cgi/l/email-protection"] {
        assert_eq!(get(&env, "example.com", path).await.status, 404, "{path}");
    }
    assert_eq!(send(&env, "POST", "www.example.com", "/cdn-cgi/rum", "", "payload").await.status, 404);
    assert_eq!(hits(), 0, "the origin saw none of this");
    // ... while a path that merely looks alike is the origin's
    env.store.delete_item::<FirewallRule>(&env.zone, &env.store.items::<FirewallRule>(&env.zone).unwrap()[0].meta.id).unwrap();
    assert_eq!(get(&env, "example.com", "/cdn-cgi-bin/x").await.status, 200);
    assert_eq!(hits(), 1);
    // none of it shows in the zone's analytics
    assert_eq!(env.edge.stats.summary(60).remove(&env.zone).unwrap_or_default().requests, 1);
    assert!(env.edge.limits.usage().used_bytes > 500, "but it counts as traffic of the node");
}

// ---- gRPC ----

/// A gRPC-like origin: answers at once, echoes every message of the call as
/// it arrives and closes with the status in trailers.
struct GrpcEcho {
    inner: Incoming,
    done: bool,
}

impl hyper::body::Body for GrpcEcho {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        use std::task::Poll;
        if self.done {
            return Poll::Ready(None);
        }
        loop {
            return match std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) if data.is_empty() => continue, // the end of the stream may come as an empty frame
                    Ok(data) => Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from([b"echo:", &data[..]].concat()))))),
                    Err(_) => continue,
                },
                Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
                None => {
                    self.done = true;
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", HeaderValue::from_static("0"));
                    trailers.insert("grpc-message", HeaderValue::from_static("fine"));
                    Poll::Ready(Some(Ok(hyper::body::Frame::trailers(trailers))))
                }
            };
        }
    }
}

async fn grpc_origin(req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_else(|| h("host"));
    let saw = format!("{:?} authority={authority} te={} type={} path={}", req.version(), h("te"), h("content-type"), req.uri().path());
    let body = GrpcEcho { inner: req.into_body(), done: false }.boxed();
    Ok(Response::builder().header("content-type", "application/grpc").header("x-origin-saw", saw).body(body).unwrap())
}

/// Serve `grpc_origin` (HTTP/1.1 and HTTP/2) on a new port, behind TLS if given a configuration.
async fn grpc_listener(tls: Option<Arc<rustls::ServerConfig>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = tls.clone();
            tokio::spawn(async move {
                let builder = auto::Builder::new(TokioExecutor::new());
                let service = hyper::service::service_fn(grpc_origin);
                match tls {
                    None => drop(builder.serve_connection(TokioIo::new(stream), service).await),
                    Some(config) => {
                        if let Ok(stream) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await {
                            drop(builder.serve_connection(TokioIo::new(stream), service).await);
                        }
                    }
                }
            });
        }
    });
    port
}

fn origin_tls(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["backend.internal".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut config = rustls::ServerConfig::builder_with_provider(crate::edge::tls::crypto())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A request body fed message by message.
struct Outbound(tokio::sync::mpsc::Receiver<Bytes>);

impl hyper::body::Body for Outbound {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx).map(|message| message.map(|m| Ok(hyper::body::Frame::data(m))))
    }
}

#[tokio::test]
async fn proxies_grpc() {
    assert!(is_grpc(&HeaderMap::from_iter([(header::CONTENT_TYPE, HeaderValue::from_static("application/grpc"))])));
    assert!(is_grpc(&HeaderMap::from_iter([(header::CONTENT_TYPE, HeaderValue::from_static("application/grpc+proto"))])));
    assert!(!is_grpc(&HeaderMap::from_iter([(header::CONTENT_TYPE, HeaderValue::from_static("application/grpc-web+proto"))])));
    assert!(!is_grpc(&HeaderMap::new()));

    let env = setup().await;
    for name in ["grpc", "grpcs"] {
        let mut r = rec(name, "A", "127.0.0.1");
        r.proxied = true;
        env.store.create_record(&env.zone, r).unwrap();
    }
    // origins: HTTP/2 without TLS, HTTP/2 with TLS, and one whose TLS does not offer HTTP/2
    let (plain, secure, old) = (grpc_listener(None).await, grpc_listener(Some(origin_tls(&[b"h2", b"http/1.1"]))).await, grpc_listener(Some(origin_tls(&[]))).await);
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let rule = |v| env.store.save_item::<OriginRule>(&env.zone, None, v, true).unwrap();
    rule(json!({ "expression": "http.host eq \"grpc.example.com\"", "origin_port": plain, "priority": 1 }));
    rule(json!({ "expression": "http.host eq \"grpcs.example.com\"", "origin_port": secure, "origin_scheme": "https", "host_header": "backend.internal", "priority": 1 }));
    rule(json!({ "expression": "http.request.uri.path contains \"/down\"", "origin_port": closed, "priority": 0 }));
    rule(json!({ "expression": "http.request.uri.path contains \"/no-h2\"", "origin_port": old, "origin_scheme": "https", "priority": 0 }));
    let block = json!({ "expression": "http.request.uri.path contains \"/forbidden\"", "action": "block" });
    env.store.save_item::<FirewallRule>(&env.zone, None, block, true).unwrap();

    let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"h2")));
    let stream = connector.connect(rustls::pki_types::ServerName::try_from("grpc.example.com").unwrap(), tcp).await.unwrap();
    let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let request = |host: &str, path: &str, content_type: &str, body: Body| {
        Request::builder()
            .method("POST")
            .uri(format!("https://{host}{path}"))
            .header("content-type", content_type)
            .header("te", "trailers")
            .body(body)
            .unwrap()
    };

    // a call in both directions at once: every message is answered before the next one is sent
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let mut call = sender.clone();
    let resp = call.send_request(request("grpc.example.com", "/pkg.Echo/Chat", "application/grpc", Outbound(rx).boxed())).await.unwrap();
    assert_eq!((resp.status(), resp.headers()["content-type"].to_str().unwrap()), (StatusCode::OK, "application/grpc"));
    assert_eq!(resp.headers()["x-origin-saw"], "HTTP/2.0 authority=grpc.example.com te=trailers type=application/grpc path=/pkg.Echo/Chat");
    let mut body = resp.into_body();
    for message in ["one", "two", "three"] {
        tx.send(Bytes::from(message)).await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame()).await.expect("the answer is not held back").unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), format!("echo:{message}"));
    }
    drop(tx);
    let trailers = body.frame().await.unwrap().unwrap().into_trailers().expect("the call ends with trailers");
    assert_eq!((trailers["grpc-status"].to_str().unwrap(), trailers["grpc-message"].to_str().unwrap()), ("0", "fine"));
    assert!(body.frame().await.is_none());

    // a whole call: response head, messages, trailers
    let unary = |host: &'static str, path: &'static str, content_type: &'static str| {
        let mut call = sender.clone();
        let req = request(host, path, content_type, full("ping"));
        async move {
            let (parts, mut body) = call.send_request(req).await.unwrap().into_parts();
            let (mut data, mut trailers) = (Vec::new(), None);
            while let Some(frame) = body.frame().await {
                match frame.unwrap().into_data() {
                    Ok(chunk) => data.extend_from_slice(&chunk),
                    Err(other) => trailers = other.into_trailers().ok(),
                }
            }
            (parts, String::from_utf8(data).unwrap(), trailers)
        }
    };
    let status = |parts: &hyper::http::response::Parts| {
        let get = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
        (parts.status.as_u16(), get("content-type"), get("grpc-status"), get("grpc-message"))
    };

    // an origin behind TLS, under the name the origin rule gives it
    let (parts, data, trailers) = unary("grpcs.example.com", "/pkg.Echo/Once", "application/grpc+proto").await;
    assert_eq!(parts.headers["x-origin-saw"], "HTTP/2.0 authority=backend.internal te=trailers type=application/grpc+proto path=/pkg.Echo/Once");
    assert_eq!((data.as_str(), trailers.unwrap()["grpc-status"].to_str().unwrap()), ("echo:ping", "0"));

    // what the edge refuses or cannot deliver reaches the client as a gRPC status, not as a page
    let (parts, data, _) = unary("grpc.example.com", "/pkg.Echo/down", "application/grpc").await;
    let (code, kind, grpc_status, message) = status(&parts);
    assert_eq!((code, kind.as_str(), grpc_status.as_str(), data.as_str()), (200, "application/grpc", "14", ""));
    assert_eq!(message, format!("Origin error: {}", ORIGIN_DOWN.en));
    let (parts, _, _) = unary("grpc.example.com", "/pkg.Echo/forbidden", "application/grpc").await;
    assert_eq!(status(&parts).2, "7");
    let (parts, _, _) = unary("grpc.example.com", "/pkg.Echo/no-h2", "application/grpc").await;
    let (_, _, grpc_status, message) = status(&parts);
    assert!(grpc_status == "14" && message.contains("does not offer HTTP/2"), "{grpc_status} {message}");
    let (parts, _, _) = unary("nowhere.example.com", "/pkg.Echo/Once", "application/grpc").await;
    assert_eq!(status(&parts).2, "12");
    // the zone's analytics see those as the errors they are
    let stats = env.edge.stats.summary(60).remove(&env.zone).unwrap_or_default();
    assert_eq!((stats.status_2xx, stats.status_4xx, stats.status_5xx, stats.threats), (2, 1, 2, 1));

    // gRPC-Web is ordinary HTTP; and with the setting off so is everything
    let (parts, _, _) = unary("grpc.example.com", "/pkg.Echo/Web", "application/grpc-web+proto").await;
    assert!(parts.headers["x-origin-saw"].to_str().unwrap().starts_with("HTTP/1.1 authority=grpc.example.com te=- "));
    env.store.update_setting(&env.zone, "grpc", json!(false)).unwrap();
    let (parts, _, _) = unary("grpc.example.com", "/pkg.Echo/Once", "application/grpc").await;
    assert!(parts.headers["x-origin-saw"].to_str().unwrap().starts_with("HTTP/1.1 "));
    env.store.update_setting(&env.zone, "grpc", json!(true)).unwrap();

    // HTTP/3 clients get the trailers too
    use bytes::Buf;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(b"h3")).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint.connect(([127, 0, 0, 1], env.tls_port).into(), "grpc.example.com").unwrap().await.unwrap();
    let (mut driver, mut h3_sender) = ::h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = request("grpc.example.com", "/pkg.Echo/Quic", "application/grpc", full("")).map(|_| ());
    let mut stream = h3_sender.send_request(req).await.unwrap();
    stream.send_data(Bytes::from("over quic")).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert!(resp.headers()["x-origin-saw"].to_str().unwrap().starts_with("HTTP/2.0 authority=grpc.example.com te=trailers "));
    let mut data = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(data, b"echo:over quic");
    assert_eq!(stream.recv_trailers().await.unwrap().expect("trailers over HTTP/3")["grpc-status"], "0");
}

#[tokio::test]
async fn proxy_protocol_carries_the_client_address() {
    let env = setup().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, env.edge.clone(), None, true));

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"PROXY TCP4 203.0.113.77 10.0.0.1 51234 443\r\n").await.unwrap();
    let r = exchange(s, raw("GET", "example.com", "/pp", "", "")).await;
    assert!(r.status == 200 && r.body.contains("xff=203.0.113.77 ip=203.0.113.77"), "{}", r.body);

    // the WAF sees the real client too
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "ip.src eq 203.0.113.99", "action": "block" }), true)
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"PROXY TCP4 203.0.113.99 10.0.0.1 51234 443\r\n").await.unwrap();
    assert_eq!(exchange(s, raw("GET", "example.com", "/pp", "", "")).await.status, 403);

    // connections without the header are dropped
    let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert_eq!(exchange(s, raw("GET", "example.com", "/pp", "", "")).await.status, 0);
}

#[tokio::test]
async fn protocol_selection_and_geo_blocking() {
    let env = setup().await;
    let negotiated = |alpn: &'static [&'static [u8]]| {
        let port = env.tls_port;
        async move {
            let mut cfg = (*tls::client_config(false).unwrap()).clone();
            cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(rustls::pki_types::ServerName::try_from("example.com").unwrap(), tcp)
                .await
                .unwrap();
            let proto = s.get_ref().1.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned());
            (proto, exchange(s, raw("GET", "example.com", "/proto", "", "")).await)
        }
    };
    let offer: &[&[u8]] = &[b"h2", b"http/1.1"];
    assert_eq!(negotiated(offer).await.0.as_deref(), Some("h2"));
    let (proto, reply) = negotiated(&[b"http/1.1"]).await;
    assert_eq!(proto.as_deref(), Some("http/1.1"));
    assert!(reply.header("alt-svc").is_some());

    // HTTP/2 off: the same client is negotiated down to HTTP/1.1; HTTP/3 off: no Alt-Svc
    env.store.update_setting(&env.zone, "http2", json!(false)).unwrap();
    env.store.update_setting(&env.zone, "http3", json!(false)).unwrap();
    let (proto, reply) = negotiated(offer).await;
    assert_eq!((proto.as_deref(), reply.status, reply.header("alt-svc")), (Some("http/1.1"), 200, None));

    // CDN-level blocking by visitor country / network operator
    let mut geo = crate::geo::Geo::default();
    geo.fixed.insert(
        "127.0.0.1".parse().unwrap(),
        crate::geo::Location { continent: Some("AS".into()), country: Some("CN".into()), region: None, asn: Some(4134), as_org: Some("chinanet".into()) },
    );
    let _ = env.edge.geo.set(Arc::new(geo));
    let located = get(&env, "example.com", "/").await;
    assert!(located.status == 200 && located.body.contains("country=CN "), "the origin learns the country: {}", located.body);
    let rule = env
        .store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "ip.geoip.country eq \"US\"", "action": "block" }), true)
        .unwrap();
    assert_eq!(get(&env, "example.com", "/").await.status, 200);
    env.store
        .save_item::<FirewallRule>(&env.zone, Some(&rule.meta.id), json!({ "expression": "ip.geoip.country eq \"CN\" and ip.geoip.asnum in {4134 4809}" }), false)
        .unwrap();
    assert_eq!(get(&env, "example.com", "/").await.status, 403);
}

#[tokio::test]
async fn fucf_internal_bypasses_limits_and_throttling() {
    let env = setup().await;
    // Register one of our own fucf nodes in the store.
    let node = env
        .store
        .save_node(
            None,
            json!({
                "name": "sgp",
                "ipv4": "198.51.100.10",
                "traffic_limit_gb": 0.000001,
                "rate_limit_mbps": 0.001,
            }),
        )
        .unwrap();
    env.edge.limits.configure("sgp", Some(&node));
    env.edge.limits.add(2_000); // push into State::Limited
    assert_eq!(env.edge.limits.state(), crate::limits::State::Limited);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, env.edge.clone(), None, true));

    let ask = |client_ip: &'static str, path: &'static str| async move {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("PROXY TCP4 {client_ip} 10.0.0.1 51234 443\r\n").as_bytes()).await.unwrap();
        exchange(s, raw("GET", "example.com", path, "", "")).await
    };

    // 1. Our own CDN node (warp=fucf) bypasses 509 hard limit and does not increment usage.
    let before = env.edge.limits.usage().used_bytes;
    let internal = ask("198.51.100.10", "/hello").await;
    assert_eq!(internal.status, 200, "warp=fucf must bypass 509: {}", internal.body);
    assert_eq!(env.edge.limits.usage().used_bytes, before, "warp=fucf must not consume CDN traffic quota");

    // 2. Cloudflare IP (warp=cloudflare) and regular visitors (warp=off) are STILL blocked with 509.
    assert_eq!(ask("104.16.0.1", "/hello").await.status, 509, "Cloudflare IP must NOT bypass fucf limits");
    assert_eq!(ask("203.0.113.5", "/hello").await.status, 509, "external visitor must still hit 509");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_blocking_tokio_worker_regression() {
    let dir = std::env::temp_dir().join(format!("fucf-nonblock-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(Store::open(&dir.join("state.json"), vec![]).unwrap());
    let accounts = Arc::new(crate::auth::Accounts::open(dir.join("accounts.json"), None));
    accounts.spawn_writer();
    let (cfg, resolver) = tls::server_config_with_resolver(store.clone()).unwrap();
    let _ = cfg;
    tokio::spawn(resolver.clone().watch());

    // Background latency probe: must keep waking every 10ms without long stalls while
    // concurrent store mutations + cert pre-warming + session reads happen.
    let max_gap = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (max_gap_bg, stop_bg) = (max_gap.clone(), stop.clone());
    let probe = tokio::spawn(async move {
        let mut last = Instant::now();
        while !stop_bg.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let gap = last.elapsed().as_millis() as u64;
            max_gap_bg.fetch_max(gap, Ordering::Relaxed);
            last = Instant::now();
        }
    });

    for i in 0..12 {
        let z = store.create_zone_as_async(&format!("zone{i}.example"), "full").await.unwrap();
        resolver.warm_sni(&format!("www.{}", z.name)).await;
        let _ = accounts.session("nonexistent-token");
    }
    stop.store(true, Ordering::Relaxed);
    probe.await.unwrap();
    let worst_ms = max_gap.load(Ordering::Relaxed);
    assert!(worst_ms < 250, "worker thread stalled for {worst_ms}ms during mutations/keygen");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn initial_read_timeout_drops_slowloris_without_hanging() {
    // Wrap a silent stream in InitialTimeoutIo with a short timeout and verify
    // hyper's auto::Builder terminates promptly instead of hanging ReadVersion.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(InitialTimeoutIo::new(stream, Duration::from_millis(120)));
        let service = hyper::service::service_fn(|_req: Request<Incoming>| async {
            Ok::<_, Infallible>(Response::new(full("ok")))
        });
        let started = Instant::now();
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_millis(120));
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(200)
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .keep_alive_timeout(Duration::from_secs(10))
            .max_header_list_size(64 * 1024);
        let res = builder.serve_connection(io, service).await;
        assert!(res.is_err(), "silent slowloris connection must fail on ReadVersion timeout");
        assert!(started.elapsed() < Duration::from_secs(2), "took too long: {:?}", started.elapsed());
    });

    let _client = TcpStream::connect(addr).await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn ssrf_guard_blocks_private_and_metadata_ips() {
    let store = Arc::new(temp_store());
    // Default Edge::new() has allow_subrequest_loopback = false.
    let edge = Arc::new(Edge::new(store.clone(), Arc::new(Cache::new(1 << 20)), Arc::new(Waf::new()), vec![]).unwrap());
    let snap = store.snapshot();
    let parent = ReqInfo::default();
    for blocked in [
        "http://127.0.0.1:80/",
        "http://[::1]:80/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://100.64.0.1/",
        "http://[fc00::1]/",
    ] {
        let err = edge.subrequest(&snap, &parent, "GET", blocked, vec![], Bytes::new()).await.unwrap_err();
        assert!(
            err.contains("refusing") || err.contains("PermissionDenied") || err.contains("private") || err.contains("link-local"),
            "SSRF target {blocked} should be blocked, got: {err}"
        );
    }
}

#[tokio::test]
async fn accel_hosts_forced_ip_returns_403() {
    let env = setup().await;
    let _ = env.edge.node_name.set("acc1".into());
    env.edge.accelerate.store(true, std::sync::atomic::Ordering::Relaxed);
    env.store.save_node(None, json!({
        "name": "acc1",
        "ipv4": "192.0.2.10",
        "role": "accelerate",
        "accel_hosts": ["www.example.com"]
    })).unwrap();

    let allowed = get(&env, "www.example.com", "/ok").await;
    assert_eq!(allowed.status, 200);

    let blocked = get(&env, "example.com", "/secret").await;
    assert_eq!(blocked.status, 403);

    // the node's own sites (proxy rules scoped to it by name) need no allowlist entry ...
    env.store.save_proxy_rule(None, json!({
        "name": "own-site", "nodes": ["acc1"], "hosts": ["own.example.net"],
        "respond": { "status": 200, "body": "own" }
    })).unwrap();
    let own = get(&env, "own.example.net", "/").await;
    assert_eq!((own.status, own.body.as_str()), (200, "own"));
    // ... the fleet's rules do
    env.store.save_proxy_rule(None, json!({
        "name": "fleet-site", "hosts": ["fleet.example.net"],
        "respond": { "status": 200, "body": "fleet" }
    })).unwrap();
    assert_eq!(get(&env, "fleet.example.net", "/").await.status, 403);
}

#[tokio::test]
async fn cdn_cgi_local_proxy_rule_override() {
    let env = setup().await;
    let doh_port = origin(Arc::new(AtomicUsize::new(0)), "doh").await;
    env.store.save_proxy_rule(None, json!({
        "name": "doh-override",
        "hosts": ["example.com"],
        "path_prefix": "/cdn-cgi/dns-query",
        "upstreams": [{"url": format!("http://127.0.0.1:{doh_port}")}],
        "priority": 1
    })).unwrap();

    let doh = get(&env, "example.com", "/cdn-cgi/dns-query?name=a").await;
    assert_eq!(doh.status, 200);
    assert!(doh.body.contains("origin=doh"), "{}", doh.body);

    // Built-in /cdn-cgi/fucf-trace still works when no rule overrides it.
    let trace = get(&env, "example.com", "/cdn-cgi/fucf-trace").await;
    assert_eq!(trace.status, 200);
    assert!(trace.body.contains("fl="), "{}", trace.body);
}

#[tokio::test]
async fn origin_node_self_loopback_and_loop_508() {
    let env = setup().await;
    let _ = env.edge.node_name.set("jp".into());
    env.store.save_node(None, json!({
        "name": "jp",
        "ipv4": "192.0.2.50"
    })).unwrap();
    let local_svc = origin(Arc::new(AtomicUsize::new(0)), "jp-local").await;
    env.store.save_item::<OriginRule>(&env.zone, None, json!({
        "expression": "http.request.uri.path eq \"/internal\"",
        "origin_node": "jp",
        "origin_port": local_svc,
        "origin_scheme": "http",
        "priority": 1
    }), true).unwrap();

    let r = get(&env, "example.com", "/internal").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("origin=jp-local"), "{}", r.body);

    // Loop prevention: fucf-loop: 4 returns 508 Loop Detected
    let looped = send(&env, "GET", "example.com", "/", "fucf-loop: 4\r\n", "").await;
    assert_eq!(looped.status, 508);
}

#[tokio::test]
async fn serves_http2_websocket_rfc8441() {
    let env = setup().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let mut seen = Vec::new();
        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            seen.extend_from_slice(&buf[..n]);
        }
        let head = String::from_utf8_lossy(&seen).to_ascii_lowercase();
        assert!(head.contains("upgrade: websocket"), "{head}");
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            s.write_all(&buf[..n]).await.unwrap();
        }
    });
    env.store
        .save_item::<OriginRule>(
            &env.zone,
            None,
            json!({ "expression": "http.request.uri.path eq \"/ws2\"", "origin_port": ws_port, "priority": 0 }),
            true,
        )
        .unwrap();

    let tcp = TcpStream::connect(("127.0.0.1", env.tls_port)).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls(b"h2")));
    let stream = connector
        .connect(rustls::pki_types::ServerName::try_from("example.com").unwrap(), tcp)
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);

    let mut req = Request::builder()
        .method(hyper::Method::CONNECT)
        .uri("https://example.com/ws2")
        .body(full(""))
        .unwrap();
    req.extensions_mut().insert(hyper::ext::Protocol::from_static("websocket"));
    let mut resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upgraded = hyper::upgrade::on(&mut resp).await.unwrap();
    let mut io = TokioIo::new(upgraded);
    let mut buf = vec![0u8; 256];
    for msg in [&b"h2-ping"[..], b"h2-pong"] {
        io.write_all(msg).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(3), io.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], msg);
    }
}

#[tokio::test]
async fn origin_that_is_the_edge_itself_is_explained_on_the_dashboard_only() {
    let env = setup().await;
    // an edge whose own address is the one the records point at (127.0.0.1)
    let edge = Arc::new(Edge::new(env.store.clone(), Arc::new(Cache::new(1 << 20)), Arc::new(Waf::new()), vec!["127.0.0.1".parse().unwrap()]).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, edge.clone(), None, false));
    let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let r = exchange(s, raw("GET", "example.com", "/x", "", "")).await;
    assert!(r.status == 530 && r.body.contains("回源错误") && r.body.contains(ORIGIN_MISCONFIGURED.zh), "{} {}", r.status, r.body);
    assert!(!r.body.contains("127.0.0.1") && !r.body.contains("origin_node") && !r.body.contains("FUCF_EDGE_IPS"), "no detail for visitors: {}", r.body);
    let events = edge.waf.events(&env.zone, 10);
    let e = events.iter().find(|e| e.source == "origin").expect("logged for the dashboard");
    assert!(e.rule_id == "530" && e.description.contains("origin_node") && e.description.starts_with(ORIGIN_MISCONFIGURED.zh), "{e:?}");
}

#[cfg(unix)] // a file root is a Unix path
#[tokio::test]
async fn proxy_rules_answer_by_themselves_and_serve_files() {
    let env = setup().await;
    let base = std::env::temp_dir().join(format!("fucf-www-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(base.join("site/docs")).unwrap();
    std::fs::write(base.join("site/docs/index.html"), "<p>docs</p>").unwrap();
    std::fs::write(base.join("site/app.js"), "console.log(1)").unwrap();
    super::files::set_allowed_roots(vec![base.clone()]);
    env.store.save_proxy_rule(None, json!({
        "name": "well-known",
        "hosts": ["example.com"],
        "path_prefix": "/.well-known/matrix/server",
        "exact_path": true,
        "respond": { "status": 200, "body": "{\"m.server\":\"example.com:443\"}", "content_type": "application/json" },
        "set_response_headers": { "access-control-allow-origin": "*" },
        "priority": 1
    })).unwrap();
    env.store.save_proxy_rule(None, json!({
        "name": "static",
        "hosts": ["example.com"],
        "path_prefix": "/static",
        "strip_prefix": true,
        "file_root": base.join("site").to_str().unwrap(),
        "priority": 2
    })).unwrap();
    assert!(env.store.save_proxy_rule(None, json!({ "name": "nothing", "hosts": ["example.com"] })).is_err(), "a rule has to do something");
    assert!(env.store.save_proxy_rule(None, json!({ "name": "rel", "hosts": ["x.example"], "file_root": "www/../etc" })).is_err());

    let r = get(&env, "example.com", "/.well-known/matrix/server").await;
    assert_eq!((r.status, r.header("content-type"), r.header("access-control-allow-origin")), (200, Some("application/json"), Some("*")));
    assert_eq!(r.body, "{\"m.server\":\"example.com:443\"}");
    let r = get(&env, "example.com", "/static/app.js").await;
    assert_eq!((r.status, r.header("content-type"), r.body.as_str()), (200, Some("text/javascript; charset=utf-8"), "console.log(1)"));
    let r = get(&env, "example.com", "/static/docs/").await;
    assert_eq!((r.status, r.body.as_str()), (200, "<p>docs</p>"));
    assert_eq!(get(&env, "example.com", "/static/../Cargo.toml").await.status, 404);
    // what no rule covers still goes to the origin
    assert!(get(&env, "example.com", "/hello").await.body.contains("origin=main"));
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn request_hosts_are_normalized() {
    for (raw, want) in [
        ("Example.COM.", "example.com"),
        ("example.com:8443", "example.com"),
        ("192.0.2.7:443", "192.0.2.7"),
        ("[2001:DB8:0::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
    ] {
        assert_eq!(request_host(raw), want, "{raw}");
    }
}

#[tokio::test]
async fn error_pages_show_where_the_request_broke() {
    let env = setup().await;
    let hops = |body: &str| -> Vec<String> {
        body.split("<div class=\"hop ").skip(1).map(|h| h.split('"').next().unwrap_or_default().to_string()).collect()
    };
    // answered by the edge itself: the origin is not involved
    let r = get(&env, "nowhere.test", "/").await;
    assert_eq!((r.status, hops(&r.body)), (404, vec!["ok".to_string(), "bad".into(), "".into()]), "{}", r.body);
    assert!(r.body.contains("与源站无关") && r.body.contains("nowhere.test") && r.body.contains("fl="), "{}", r.body);
    let r = get(&env, "example.com", "/cdn-cgi/no-such-thing").await;
    assert_eq!((r.status, hops(&r.body)), (404, vec!["ok".to_string(), "bad".into(), "".into()]), "{}", r.body);
    // the origin failed: browser and edge worked
    env.store.save_item::<OriginRule>(&env.zone, None, json!({ "expression": "http.request.uri.path eq \"/down\"", "origin_port": 1 }), true).unwrap();
    let r = get(&env, "example.com", "/down").await;
    assert_eq!((r.status, hops(&r.body)), (521, vec!["ok".to_string(), "ok".into(), "bad".into()]), "{}", r.body);
    assert!(r.body.contains("回源失败") && r.body.contains("重新加载"), "{}", r.body);
}

#[test]
fn error_pages_pick_the_visitors_language() {
    let lang = |v: &str| {
        let mut h = HeaderMap::new();
        if !v.is_empty() {
            h.insert(header::ACCEPT_LANGUAGE, v.parse().unwrap());
        }
        Lang::from_headers(&h)
    };
    assert_eq!(lang(""), Lang::Zh);
    assert_eq!(lang("zh-CN,zh;q=0.9,en;q=0.8"), Lang::Zh);
    assert_eq!(lang("en-US,en;q=0.9"), Lang::En);
    assert_eq!(lang("en;q=0.5,zh-TW;q=0.8"), Lang::Zh);
    assert_eq!(lang("ja,fr;q=0.8"), Lang::En);
}

#[tokio::test]
async fn error_pages_carry_both_languages() {
    let env = setup().await;
    let r = get(&env, "nowhere.test", "/").await;
    for text in ["未知的主机名", "Unknown host", "这个主机名没有接入本边缘节点。", "What happened?", "Not involved", "data-lang=\"zh\"", "id=\"lang\""] {
        assert!(r.body.contains(text), "{text}: {}", r.body);
    }
}

#[test]
fn panel_origin_is_an_address_reached_under_the_panel_name() {
    let t = panel_origin("203.0.113.7", "dashboard.example.com").unwrap();
    assert_eq!((t.host.as_str(), t.port, t.tls, t.sni.as_str(), t.host_header.as_str()), ("203.0.113.7", 443, Tls::Verify, "dashboard.example.com", "dashboard.example.com"));
    let t = panel_origin("https://[2001:db8::1]:8443/", "dashboard.example.com").unwrap();
    assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 8443));
    assert!(panel_origin("dashboard.example.com", "dashboard.example.com").is_err(), "an address, not a name to resolve");
}

#[tokio::test]
async fn a_zone_can_add_preload_hints_to_its_pages_and_only_to_them() {
    let env = setup().await;
    assert!(get(&env, "example.com", "/page.html").await.header("link").is_none(), "none by default");
    let hints = json!(["</app.css>; rel=preload; as=style", "<https://cdn.example.net>; rel=preconnect; crossorigin"]);
    env.store.update_setting(&env.zone, "early_hints_links", hints).unwrap();
    let r = get(&env, "example.com", "/page.html").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("link"), Some("</app.css>; rel=preload; as=style, <https://cdn.example.net>; rel=preconnect; crossorigin"), "{}", r.head);
    assert!(!r.head.starts_with("HTTP/1.1 103"), "no informational answer is sent");
    for uri in ["/hello", "/big/file.txt"] {
        assert!(get(&env, "example.com", uri).await.header("link").is_none(), "{uri} is not a page");
    }
    // the edge's own pages are not the zone's: an unknown host gets none
    assert!(get(&env, "nope.example.com", "/page.html").await.header("link").is_none());

    for bad in [json!(["</a.css>; rel=stylesheet"]), json!(["</a.css>; rel=preload; as=style\r\nX-Evil: 1"]), json!("</a.css>; rel=preload; as=style"), json!([1])] {
        assert!(env.store.update_setting(&env.zone, "early_hints_links", bad.clone()).is_err(), "{bad}");
    }
    env.store.update_setting(&env.zone, "early_hints_links", json!([])).unwrap();
    assert!(get(&env, "example.com", "/page.html").await.header("link").is_none(), "cleared");
}

#[tokio::test]
async fn page_shield_adds_its_policy_to_html_pages_and_counts_the_scripts_browsers_report() {
    let env = setup().await;
    let report = "/cdn-cgi/script_monitor/report";
    let csp2 = |document: &str, blocked: &str| json!({ "csp-report": { "document-uri": document, "blocked-uri": blocked, "effective-directive": "script-src-elem" } }).to_string();
    let post = |ctype: &str, body: String| {
        let extra = format!("Content-Type: {ctype}\r\n");
        let env = &env;
        async move { send(env, "POST", "example.com", report, &extra, &body).await }
    };
    assert!(get(&env, "example.com", "/page.html").await.header("content-security-policy-report-only").is_none(), "off by default");
    // a zone without Page Shield takes nothing, and says nothing about it
    assert_eq!(post("application/csp-report", csp2("https://example.com/page.html", "https://cdn.example.net/early.js")).await.status, 204);
    assert!(env.edge.page_shield.scripts(&env.zone).is_empty());

    env.store.update_setting(&env.zone, "page_shield", json!({ "enabled": true })).unwrap();
    let r = get(&env, "example.com", "/page.html").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-security-policy-report-only"), Some("script-src 'none'; report-uri /cdn-cgi/script_monitor/report"), "{}", r.head);
    assert!(r.header("content-security-policy").is_none() && r.header("reporting-endpoints").is_none(), "plain HTTP: report-uri only\n{}", r.head);
    assert!(get(&env, "example.com", "/hello").await.header("content-security-policy-report-only").is_none(), "not a page");

    // the origin's own policies stay as they are, ours is one more line
    let r = get(&env, "example.com", "/csp.html").await;
    let lines = |name: &str| r.head.lines().filter(|l| l.split_once(':').is_some_and(|(k, _)| k.eq_ignore_ascii_case(name))).map(|l| l.split_once(':').unwrap().1.trim().to_string()).collect::<Vec<_>>();
    assert_eq!(lines("content-security-policy"), vec!["default-src 'self'"], "{}", r.head);
    assert_eq!(lines("content-security-policy-report-only"), vec!["img-src 'self'", "script-src 'none'; report-uri /cdn-cgi/script_monitor/report"], "{}", r.head);

    // both report formats; the query string of a script is never kept
    assert_eq!(post("application/csp-report", csp2("https://example.com/page.html", "https://cdn.example.net/lib.js?v=1&token=abc")).await.status, 204);
    let batch = json!([
        { "type": "csp-violation", "url": "https://example.com/", "body": { "documentURL": "https://example.com/", "blockedURL": "https://CDN.example.net:443/app.js#x", "effectiveDirective": "script-src-elem" } },
        { "type": "csp-violation", "url": "https://example.net/", "body": { "documentURL": "https://example.net/", "blockedURL": "https://cdn.example.net/elsewhere.js", "effectiveDirective": "script-src-elem" } },
        { "type": "csp-violation", "url": "https://example.com/", "body": { "documentURL": "https://example.com/", "blockedURL": "https://cdn.example.net/style.css", "effectiveDirective": "style-src-elem" } },
    ]);
    assert_eq!(post("application/reports+json", batch.to_string()).await.status, 204);
    let mut seen: Vec<(String, u64)> = env.edge.page_shield.scripts(&env.zone).into_iter().map(|(url, s)| (url, s.count)).collect();
    seen.sort();
    assert_eq!(seen, vec![("https://cdn.example.net/app.js".to_string(), 1), ("https://cdn.example.net/lib.js".to_string(), 1)], "another page's report and a style are not scripts of this zone");

    // what the endpoint refuses
    assert_eq!(get(&env, "example.com", report).await.status, 405);
    assert_eq!(post("text/plain", csp2("https://example.com/", "https://cdn.example.net/x.js")).await.status, 415);
    assert_eq!(post("application/csp-report", "{not json".to_string()).await.status, 400);
    // a body declared too large is refused before it is read
    let big = format!("POST {report} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Type: application/csp-report\r\nContent-Length: {}\r\n\r\n{{", pageshield::MAX_BODY + 1);
    assert_eq!(exchange(TcpStream::connect(("127.0.0.1", env.port)).await.unwrap(), big).await.status, 413);
    assert_eq!(env.edge.page_shield.scripts(&env.zone).len(), 2);

    assert!(env.store.update_setting(&env.zone, "page_shield", json!({ "enabled": true, "policy": "script-src 'self'\r\nX-Evil: 1" })).is_err());
    assert!(env.store.update_setting(&env.zone, "page_shield", json!({ "enabled": true, "mode": "enforce" })).is_err(), "enforce needs a policy of its own");
    env.store.update_setting(&env.zone, "page_shield", json!({ "enabled": true, "mode": "enforce", "policy": "script-src 'self'" })).unwrap();
    let r = get(&env, "example.com", "/page.html").await;
    assert_eq!(r.header("content-security-policy"), Some("script-src 'self'; report-uri /cdn-cgi/script_monitor/report"), "{}", r.head);
}

/// An answer with its body as bytes (a picture is no text).
async fn fetch(env: &Env, method: &str, host: &str, uri: &str, extra: &str) -> (Reply, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", env.port)).await.unwrap();
    s.write_all(raw(method, host, uri, extra, "").as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map_or(buf.len(), |i| i + 4);
    let head = String::from_utf8_lossy(&buf[..end]).trim_end().to_string();
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (Reply { status, head, body: String::new() }, buf[end..].to_vec())
}

#[tokio::test]
async fn images_are_resized_for_a_zone_that_turns_it_on_and_only_from_its_own_paths() {
    let env = setup().await;
    let url = "/cdn-cgi/image/width=100,format=webp/img/a.png";
    let (r, _) = fetch(&env, "GET", "example.com", url, "").await;
    assert!(r.header("fcf-resized").is_none(), "off by default: the path goes to the origin as it is");
    env.store.update_setting(&env.zone, "image_resizing", json!(true)).unwrap();
    let before = env.hits.load(Ordering::SeqCst);

    let (r, body) = fetch(&env, "GET", "example.com", url, "").await;
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!((r.header("content-type"), r.header("fcf-resized"), r.header("fcf-cache-status")), (Some("image/webp"), Some("100x50"), Some("MISS")), "{}", r.head);
    assert_eq!(r.header("content-length"), Some(body.len().to_string().as_str()));
    let img = image::load_from_memory(&body).unwrap();
    assert_eq!((img.width(), img.height()), (100, 50));
    assert_eq!(img.to_rgb8().get_pixel(10, 25).0, [255, 0, 0]);
    let etag = r.header("etag").unwrap().to_string();

    let (r, again) = fetch(&env, "GET", "example.com", url, "").await;
    assert_eq!((r.header("fcf-cache-status"), again.len()), (Some("HIT"), body.len()), "{}", r.head);
    assert_eq!(env.hits.load(Ordering::SeqCst), before + 1, "the original came from the origin once");
    let (r, _) = fetch(&env, "GET", "example.com", url, &format!("If-None-Match: {etag}\r\n")).await;
    assert_eq!(r.status, 304, "{}", r.head);
    let (r, head_body) = fetch(&env, "HEAD", "example.com", url, "").await;
    assert_eq!((r.status, r.header("content-type"), head_body.len()), (200, Some("image/webp"), 0), "{}", r.head);

    // other options are another result, and the host may be written in full
    let (r, body) = fetch(&env, "GET", "example.com", "/cdn-cgi/image/w=50,h=50,fit=cover/https://example.com/img/a.png", "").await;
    assert_eq!((r.header("content-type"), r.header("fcf-resized")), (Some("image/png"), Some("50x50")), "{}", r.head);
    assert_eq!(image::guess_format(&body).unwrap(), image::ImageFormat::Png);

    // what is not to be transformed goes as it came
    for (path, why) in [("/cdn-cgi/image/width=100/img/anim.png", "original; animated"), ("/cdn-cgi/image/width=100/img/notes.txt", "original; unsupported"), ("/cdn-cgi/image/blur=9/img/a.png", "original; unchanged")] {
        let (r, _) = fetch(&env, "GET", "example.com", path, "").await;
        assert_eq!((r.status, r.header("fcf-resized")), (200, Some(why)), "{path}: {}", r.head);
    }

    // no open proxy, and nothing but GET and HEAD
    for (method, path, status) in [
        ("GET", "/cdn-cgi/image/width=100/https://other.example.net/img/a.png", 400),
        ("GET", "/cdn-cgi/image/width=100//other.example.net/img/a.png", 400),
        ("GET", "/cdn-cgi/image/width=100/https://user@example.com/img/a.png", 400),
        ("GET", "/cdn-cgi/image/width=100", 400),
        ("GET", "/cdn-cgi/image/width=100/cdn-cgi/fucf-trace", 400),
        ("POST", url, 405),
    ] {
        let (r, _) = fetch(&env, method, "example.com", path, "").await;
        assert_eq!(r.status, status, "{method} {path}: {}", r.head);
    }
    let hits = env.hits.load(Ordering::SeqCst);

    // the firewall sees the original's path
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "starts_with(http.request.uri.path, \"/img/secret\")", "action": "block" }), true)
        .unwrap();
    let (r, _) = fetch(&env, "GET", "example.com", "/cdn-cgi/image/width=10/img/secret.png", "").await;
    assert_eq!((r.status, r.header("fcf-resized")), (403, None), "{}", r.head);
    assert_eq!(env.hits.load(Ordering::SeqCst), hits, "a blocked original is never fetched");

    // a host the edge does not serve for a zone gets nothing of it
    let (r, _) = fetch(&env, "GET", "nope.example.com", url, "").await;
    assert!(r.header("fcf-resized").is_none() && r.status != 200, "{}", r.head);
    assert!(env.store.update_setting(&env.zone, "image_resizing", json!("yes")).is_err());
}

#[tokio::test]
async fn pages_get_the_script_and_scripts_get_json() {
    let env = setup().await;
    let r = get(&env, "example.com", "/page.html").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains(&format!("<title>t</title>{}</HEAD>", super::SCRIPT_TAG)), "{}", r.body);
    assert!(r.header("cf-ray").is_none(), "nothing cf- goes out");
    assert!(r.header("fcf-cache-status").is_some() && r.header("cf-cache-status").is_none());
    let r = get(&env, "example.com", "/gz/page.html").await;
    assert!(r.body.contains(super::SCRIPT_TAG) && r.body.contains("hello"), "{}", r.body);
    let r = get(&env, "example.com", "/zs/page.html").await;
    assert!(r.body.contains(super::SCRIPT_TAG) && r.body.contains("hello") && r.header("content-encoding").is_none(), "{}", r.body);
    let r = get(&env, "example.com", "/cdn-cgi/challenge-platform/fcf.js").await;
    assert!(r.status == 200 && r.body.contains("fcf-mitigated") && r.header("content-type").unwrap().contains("javascript"));
    let r = get(&env, "example.com", "/cdn-cgi/challenge-platform/ticket").await;
    let cfg: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert!(cfg["t"].as_str().is_some_and(|t| t.contains('.')) && cfg["c"] == false, "{}", r.body);

    // off: the pages stay as they are
    env.store.update_setting(&env.zone, "challenge_script", json!(false)).unwrap();
    let r = get(&env, "example.com", "/page.html").await;
    assert!(!r.body.contains("fcf.js"), "{}", r.body);

    // a challenged fetch gets JSON the script can settle
    let rule = json!({ "expression": "http.request.uri.path eq \"/api/x\"", "action": "js_challenge" });
    env.store.save_item::<FirewallRule>(&env.zone, None, rule, true).unwrap();
    let r = send(&env, "GET", "example.com", "/api/x", "Sec-Fetch-Mode: cors\r\nAccept: application/json\r\n", "").await;
    assert_eq!((r.status, r.header("fcf-mitigated")), (403, Some("challenge")));
    let j: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert!(j["challenge"]["t"].is_string() && j["challenge"]["v"] == "/cdn-cgi/challenge-platform/verify", "{}", r.body);
    let r = send(&env, "GET", "example.com", "/api/x", "Sec-Fetch-Mode: navigate\r\n", "").await;
    assert!(r.status == 403 && r.body.contains("<!doctype html>"));
    // the levels: high challenges a data centre address, medium does not
    env.store.update_setting(&env.zone, "security_level", json!("high")).unwrap();
    assert!(env.store.update_setting(&env.zone, "security_level", json!("bogus")).is_err());
}

#[tokio::test]
async fn the_panel_is_answered_here_when_its_node_is_gone() {
    let env = setup().await;
    let _ = env.edge.panel.set(("panel.example.net".to_string(), ([127, 0, 0, 1], env.origin_port).into()));
    // the panel's node: nobody listens there
    let _ = env.edge.panel_origin.set(panel_origin("127.0.0.1:1", "panel.example.net").unwrap());
    let r = send(&env, "POST", "panel.example.net", "/client/v4/auth/login", "Content-Type: application/json\r\n", "{\"email\":\"a\"}").await;
    assert!(r.status == 200 && r.body.contains("POST /client/v4/auth/login") && r.body.contains("body={\"email\":\"a\"}"), "{}", r.body);
    // and goes on doing so for a while, without trying the gone node first
    let r = get(&env, "panel.example.net", "/client/v4/system").await;
    assert!(r.status == 200 && r.body.contains("GET /client/v4/system"), "{}", r.body);
}

#[tokio::test]
async fn a_stale_copy_is_served_at_once_while_a_new_one_is_fetched() {
    let env = setup().await;
    tokio::spawn(env.edge.clone().refresh_stale());
    let ask = || get(&env, "www.example.com", "/swr/app.js");
    let first = ask().await;
    assert_eq!((first.header("fcf-cache-status"), ask().await.header("fcf-cache-status")), (Some("MISS"), Some("HIT")));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    // past its freshness: the old copy at once ...
    let stale = ask().await;
    assert_eq!((stale.header("fcf-cache-status"), stale.body.as_str()), (Some("UPDATING"), first.body.as_str()));
    // ... and the one fetched meanwhile from then on
    tokio::time::sleep(Duration::from_millis(400)).await;
    let fresh = ask().await;
    assert_eq!(fresh.header("fcf-cache-status"), Some("HIT"));
    assert_ne!(fresh.body, first.body, "fetched anew behind the visitor's back");
}

#[tokio::test]
async fn a_node_named_by_its_address_answers_sync_itself() {
    let env = setup().await;
    let _ = env.edge.panel.set(("panel.example.net".to_string(), ([127, 0, 0, 1], env.origin_port).into()));
    // the panel's node: nobody listens there, and that it was tried is remembered
    let _ = env.edge.panel_origin.set(panel_origin("127.0.0.1:1", "panel.example.net").unwrap());
    let _ = env.edge.panel_seal.set("seal".into());
    let tried = || env.edge.panel_down_until.swap(0, Ordering::Relaxed) > 0;
    let sync = |extra: &'static str| send(&env, "GET", "panel.example.net", "/client/v4/replication/sync?since=0", extra, "");
    // sealed, but not from a node of the fleet: passed on like the rest of the panel
    sync("fucf-sync-direct: seal\r\n").await;
    assert!(tried());
    env.store.save_node(None, json!({ "name": "peer", "ipv4": "127.0.0.1" })).unwrap();
    // sealed, from a node: this node's own API answers, the panel's node is left alone
    let r = sync("fucf-sync-direct: seal\r\n").await;
    assert!(r.status == 200 && r.body.contains("origin=main GET /client/v4/replication/sync?since=0 host=panel.example.net"), "{}", r.body);
    assert!(!tried());
    // a node that found this one by the panel's name (no seal), a wrong seal, another API: the panel's node
    sync("").await;
    assert!(tried());
    sync("fucf-sync-direct: other\r\n").await;
    assert!(tried());
    send(&env, "GET", "panel.example.net", "/client/v4/zones", "fucf-sync-direct: seal\r\n", "").await;
    assert!(tried());
}

#[tokio::test]
async fn every_answered_request_lands_in_the_request_log() {
    let env = setup().await;
    let all = || reqlog::Filter { zone_id: env.zone.clone(), ..Default::default() };
    let ua = format!("Mozilla/5.0 {}", "中".repeat(100));
    let r = send(&env, "POST", "www.example.com", "/submit/form?token=test-token", &format!("User-Agent: {ua}\r\n"), "a=1").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let page = env.edge.reqlog.query(None, 10, &all());
    assert_eq!(page.entries.len(), 1);
    let (seq, e) = &page.entries[0];
    assert_eq!(*seq, 1);
    assert_eq!((e.method.as_str(), e.host.as_str(), e.path.as_str(), e.status), ("POST", "www.example.com", "/submit/form", 200), "no query string");
    assert_eq!(e.zone_id, env.zone);
    assert_eq!(Some(e.ray.as_str()), r.header("fucf-ray"), "the ray the visitor was given");
    assert_eq!((e.cache.as_str(), e.protocol, e.action), ("DYNAMIC", "HTTP/1.1", ""));
    assert_eq!(e.client_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(e.node, "local");
    assert!(e.user_agent.len() <= reqlog::UA_MAX && ua.starts_with(e.user_agent.as_str()), "{}", e.user_agent);
    assert!(e.user_agent.len() > reqlog::UA_MAX - 3, "cut at the last whole character");

    // blocked and challenged requests are logged with what was done to them
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "starts_with(http.request.uri.path, \"/admin\")", "action": "block" }), true)
        .unwrap();
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "http.request.uri.path eq \"/shop\"", "action": "js_challenge" }), true)
        .unwrap();
    assert_eq!(get(&env, "example.com", "/admin/users").await.status, 403);
    assert_eq!(get(&env, "example.com", "/shop").await.status, 403);
    let long = format!("/{}", "a".repeat(reqlog::PATH_MAX + 50));
    get(&env, "example.com", &long).await;
    let page = env.edge.reqlog.query(Some(1), 10, &all());
    let got: Vec<(u16, &str, usize)> = page.entries.iter().map(|(_, e)| (e.status, e.action, e.path.len())).collect();
    assert_eq!(got.len(), 3);
    assert_eq!(got[..2], [(403, "block", "/admin/users".len()), (403, "challenge", "/shop".len())]);
    assert_eq!(got[2].2, reqlog::PATH_MAX, "long paths are cut");

    // hosts that belong to no zone are in nobody's log
    assert_eq!(get(&env, "other.org", "/").await.status, 404);
    assert_eq!(env.edge.reqlog.newest(), 4);
}

#[tokio::test]
async fn a_full_waiting_room_queues_page_loads_and_lets_admitted_visitors_through() {
    let env = setup().await;
    let room: waiting::WaitingRoom = env
        .store
        .save_item(&env.zone, None, json!({ "name": "all", "host": "www.example.com", "total_active_users": 1, "new_users_per_minute": 1 }), true)
        .unwrap();
    let set_cookies = |r: &Reply| -> Vec<String> {
        r.head
            .lines()
            .filter_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.trim().to_string()))
            .collect()
    };
    let value_of = |set_cookie: &str| set_cookie.split(';').next().unwrap().to_string();

    // the first visitor gets in and is given its admission
    let first = get(&env, "www.example.com", "/").await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert!(first.body.contains("origin=main GET /"), "{}", first.body);
    let given = set_cookies(&first);
    assert_eq!(given.len(), 1, "{given:?}");
    assert!(given[0].starts_with(&format!("{}={}.", waiting::COOKIE, room.meta.id)), "{}", given[0]);
    assert!(given[0].ends_with("; Path=/; Max-Age=300; HttpOnly; SameSite=Lax"), "plain HTTP: no Secure: {}", given[0]);
    let admission = value_of(&given[0]);

    // the room is full: the next page load waits, the origin never sees it
    let hits = env.hits.load(Ordering::SeqCst);
    let queued = send(&env, "GET", "www.example.com", "/page", "Accept: text/html\r\n", "").await;
    assert_eq!(queued.status, 200);
    assert_eq!(queued.header("fcf-waiting-room"), Some("queued"));
    assert_eq!(queued.header("cache-control"), Some("no-store"));
    assert_eq!(queued.header("retry-after"), Some(waiting::REFRESH_SECS.to_string().as_str()));
    assert!(queued.body.contains("http-equiv=\"refresh\""), "{}", queued.body);
    let ticket = set_cookies(&queued);
    assert!(ticket.len() == 1 && ticket[0].starts_with(&format!("{}=", waiting::TICKET_COOKIE)), "{ticket:?}");
    // shown again, the ticket keeps its place (and the line does not grow)
    let again = send(&env, "GET", "www.example.com", "/page", &format!("Cookie: {}\r\n", value_of(&ticket[0])), "").await;
    assert_eq!(again.header("fcf-waiting-room"), Some("queued"));
    assert_eq!(env.edge.waiting.counts(&room.meta.id), (1, 1));
    assert_eq!(env.hits.load(Ordering::SeqCst), hits);

    // the admitted visitor passes
    let back = send(&env, "GET", "www.example.com", "/page", &format!("Cookie: a=b; {admission}\r\n"), "").await;
    assert!(back.status == 200 && back.header("fcf-waiting-room").is_none(), "{}", back.body);
    assert!(set_cookies(&back).is_empty(), "a fresh session is not renewed");
    // a tampered admission counts as none
    let forged = admission.replacen('.', ".0", 1);
    let r = send(&env, "GET", "www.example.com", "/page", &format!("Cookie: {forged}\r\n"), "").await;
    assert_eq!(r.header("fcf-waiting-room"), Some("queued"));

    // what does not wait: assets and API calls, posts, /cdn-cgi/, another host, what a skip rule lets through
    for extra in ["Accept: image/png\r\n", "Sec-Fetch-Mode: no-cors\r\n", "X-Requested-With: XMLHttpRequest\r\n"] {
        let r = send(&env, "GET", "www.example.com", "/app.js", extra, "").await;
        assert!(r.header("fcf-waiting-room").is_none(), "{extra}");
    }
    let r = send(&env, "POST", "www.example.com", "/form", "Accept: text/html\r\n", "a=1").await;
    assert!(r.header("fcf-waiting-room").is_none(), "a post is not a page load");
    assert!(get(&env, "www.example.com", "/cdn-cgi/anything").await.header("fcf-waiting-room").is_none());
    assert!(get(&env, "example.com", "/").await.header("fcf-waiting-room").is_none());
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "http.request.headers[\"x-internal\"] eq \"yes\"", "action": "skip" }), true)
        .unwrap();
    let r = send(&env, "GET", "www.example.com", "/", "X-Internal: yes\r\n", "").await;
    assert!(r.status == 200 && r.header("fcf-waiting-room").is_none(), "{}", r.body);

    // a disabled room lets everybody through
    env.store.save_item::<waiting::WaitingRoom>(&env.zone, Some(&room.meta.id), json!({ "enabled": false }), false).unwrap();
    let r = get(&env, "www.example.com", "/page").await;
    assert!(r.status == 200 && r.header("fcf-waiting-room").is_none() && set_cookies(&r).is_empty(), "{}", r.body);
}

#[tokio::test]
async fn the_admission_cookie_is_scoped_to_the_rooms_path() {
    let env = setup().await;
    env.store
        .save_item::<waiting::WaitingRoom>(
            &env.zone,
            None,
            json!({ "name": "shop", "host": "example.com", "path_prefix": "/shop", "total_active_users": 5, "new_users_per_minute": 5, "session_minutes": 2 }),
            true,
        )
        .unwrap();
    let r = get(&env, "example.com", "/shopping").await;
    assert!(r.header("set-cookie").is_none(), "/shopping is not under /shop");
    let r = get(&env, "example.com", "/shop/cart").await;
    assert_eq!(r.status, 200);
    let c = r.header("set-cookie").unwrap_or_default().to_string();
    assert!(c.ends_with("; Path=/shop; Max-Age=120; HttpOnly; SameSite=Lax"), "{c}");
}

/// The cache key of a plain-HTTP request for `path` on example.com that
/// takes no compression (as the raw test requests are).
fn video_key(path: &str) -> String {
    cache::cache_key(false, "example.com", path, "", &HeaderMap::new())
}

/// Which of the four chunks of the object at `path` the cache has (of any fill).
async fn video_chunks(env: &Env, path: &str) -> Vec<bool> {
    let base = Cache::shared_key(&video_key(path));
    let mut out = Vec::new();
    for n in 0..4 {
        out.push(env.edge.cache.lookup_exact(&chunked::chunk_key(&base, n)).await.is_some());
    }
    out
}

/// The cache's entry for the object at `path`, if any.
async fn video_entry(env: &Env, path: &str) -> Option<Arc<cache::Entry>> {
    env.edge.cache.lookup(&video_key(path)).await
}

fn forget_chunk(env: &Env, path: &str, n: u64) {
    env.edge.cache.remove(&chunked::chunk_key(&Cache::shared_key(&video_key(path)), n));
}

/// The range requests the origin got for `path`.
fn ranges_asked(path: &str) -> Vec<String> {
    VIDEO_RANGES.lock().unwrap().iter().filter(|l| l.split(' ').next() == Some(path)).cloned().collect()
}

/// Is the entry of the object at `path` gone, and which of its chunks are left?
async fn video_gone(env: &Env, path: &str) -> (bool, Vec<bool>) {
    (video_entry(env, path).await.is_none(), video_chunks(env, path).await)
}

async fn ranged(env: &Env, path: &str, range: &str) -> Reply {
    send(env, "GET", "example.com", path, &format!("Range: {range}\r\n"), "").await
}

const C: u64 = chunked::CHUNK;

#[tokio::test]
async fn large_objects_are_kept_in_chunks_and_served_whole_and_by_range() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let hits = || env.hits.load(Ordering::SeqCst);
    let path = "/vid/ranged-whole.bin";
    let data = video_bytes(0);

    let first = get(&env, "example.com", path).await;
    assert_eq!((first.status, first.header("fcf-cache-status")), (200, Some("MISS")));
    assert!(first.body.as_bytes() == data, "the first visitor gets the whole object");
    assert_eq!(first.header("content-length"), Some(VIDEO_LEN.to_string().as_str()));
    let entry = video_entry(&env, path).await.unwrap();
    assert!(entry.body.is_empty() && matches!(&entry.piece, Some(cache::Piece::Meta { total, .. }) if *total == VIDEO_LEN), "{:?}", entry.piece);
    assert_eq!(video_chunks(&env, path).await, [true; 4]);

    let again = get(&env, "example.com", path).await;
    assert_eq!((again.status, again.header("fcf-cache-status"), hits()), (200, Some("HIT"), 1));
    assert!(again.body.as_bytes() == data);
    assert_eq!((again.header("content-length"), again.header("accept-ranges"), again.header("etag")), (Some(VIDEO_LEN.to_string().as_str()), Some("bytes"), Some("\"vid0\"")));
    assert!(again.header("fucf-chunked").is_none() && again.header("cache-tag").is_none(), "nothing of how it is kept shows");

    let part = ranged(&env, path, "bytes=100-199").await;
    assert_eq!((part.status, part.header("fcf-cache-status"), part.header("content-range")), (206, Some("HIT"), Some(format!("bytes 100-199/{VIDEO_LEN}").as_str())));
    assert!(part.body.as_bytes() == &data[100..200]);
    let across = ranged(&env, path, &format!("bytes={}-{}", C - 5, 2 * C + 5)).await;
    assert!(across.status == 206 && across.body.as_bytes() == &data[(C - 5) as usize..=(2 * C + 5) as usize], "a range over three chunks");
    let tail = ranged(&env, path, "bytes=-10").await;
    assert!(tail.status == 206 && tail.body.as_bytes() == &data[data.len() - 10..]);
    let open = ranged(&env, path, &format!("bytes={}-", 3 * C)).await;
    assert!(open.status == 206 && open.body.as_bytes() == &data[3 * C as usize..], "the last, partial chunk");
    let beyond = ranged(&env, path, &format!("bytes={VIDEO_LEN}-")).await;
    assert_eq!((beyond.status, beyond.header("content-range")), (416, Some(format!("bytes */{VIDEO_LEN}").as_str())));
    let head = send(&env, "HEAD", "example.com", path, "", "").await;
    assert_eq!((head.status, head.header("content-length"), head.body.as_str()), (200, Some(VIDEO_LEN.to_string().as_str()), ""));
    let unchanged = send(&env, "GET", "example.com", path, "If-None-Match: \"vid0\"\r\n", "").await;
    assert_eq!((unchanged.status, unchanged.body.as_str()), (304, ""));
    assert_eq!(hits(), 1, "all of that came from the cache");
    assert!(ranges_asked(path).is_empty(), "and the origin was never asked for a range");
}

#[tokio::test]
async fn a_chunk_the_cache_let_go_is_fetched_again_by_itself() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let hits = || env.hits.load(Ordering::SeqCst);
    let path = "/vid/ranged-refill.bin";
    let data = video_bytes(0);
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("MISS"));

    forget_chunk(&env, path, 2);
    let part = ranged(&env, path, "bytes=0-9").await;
    assert_eq!((part.status, part.header("fcf-cache-status"), hits()), (206, Some("HIT"), 1), "what is there is served");
    let whole = get(&env, "example.com", path).await;
    assert_eq!((whole.status, whole.header("fcf-cache-status"), hits()), (200, Some("MISS"), 2));
    assert!(whole.body.as_bytes() == data, "the whole object, the missing chunk from the origin");
    assert_eq!(ranges_asked(path), [format!("{path} bytes={}-{} \"vid0\"", 2 * C, 3 * C - 1)], "just that chunk, of that version");
    assert_eq!(video_chunks(&env, path).await, [true; 4], "and it is kept again");
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("HIT"));

    // two missing chunks: one request from the first to the last of them
    forget_chunk(&env, path, 1);
    forget_chunk(&env, path, 3);
    let range = format!("bytes={}-{}", C + 5, 3 * C + 5);
    let part = ranged(&env, path, &range).await;
    assert_eq!((part.status, part.header("fcf-cache-status")), (206, Some("MISS")));
    assert!(part.body.as_bytes() == &data[(C + 5) as usize..=(3 * C + 5) as usize]);
    assert_eq!(ranges_asked(path)[1], format!("{path} bytes={C}-{} \"vid0\"", VIDEO_LEN - 1));
    assert_eq!((hits(), video_chunks(&env, path).await), (3, vec![true; 4]));
    let again = ranged(&env, path, &range).await;
    assert_eq!((again.header("fcf-cache-status"), hits()), (Some("HIT"), 3));
}

#[tokio::test]
async fn an_origin_that_ignores_ranges_gets_the_object_kept_whole_once() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let hits = || env.hits.load(Ordering::SeqCst);
    let path = "/vid/norange-a.bin";
    let data = video_bytes(0);
    get(&env, "example.com", path).await;
    assert_eq!(video_chunks(&env, path).await, [true; 4], "an origin's whole answer is kept in chunks all the same");

    forget_chunk(&env, path, 1);
    let whole = get(&env, "example.com", path).await;
    assert_eq!((whole.status, whole.header("fcf-cache-status"), hits()), (200, Some("MISS"), 2), "one request, its whole answer used");
    assert!(whole.body.as_bytes() == data);
    assert_eq!(ranges_asked(path).len(), 1);
    let entry = video_entry(&env, path).await.unwrap();
    assert!(entry.piece.is_none() && entry.body.len() as u64 == VIDEO_LEN, "now kept whole");
    let part = ranged(&env, path, "bytes=5-9").await;
    assert_eq!((part.status, part.header("fcf-cache-status"), hits()), (206, Some("HIT"), 2));
    assert!(part.body.as_bytes() == &data[5..10]);

    // a range request whose chunk is gone: the origin's whole answer goes to the visitor, as without chunks
    let path = "/vid/norange-b.bin";
    get(&env, "example.com", path).await;
    forget_chunk(&env, path, 0);
    let part = ranged(&env, path, "bytes=0-9").await;
    assert_eq!((part.status, part.header("fcf-cache-status"), hits()), (200, Some("DYNAMIC"), 4));
    assert!(part.body.as_bytes() == data);
    assert!(video_entry(&env, path).await.is_none(), "the entry whose chunks could not be had is gone");
}

#[tokio::test]
async fn chunks_of_two_versions_are_never_served_together() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    SHIFTY.store(0, Ordering::SeqCst);
    let hits = || env.hits.load(Ordering::SeqCst);
    let path = "/vid/shifty-a.bin";
    assert!(get(&env, "example.com", path).await.body.as_bytes() == video_bytes(0));

    // the object changes at the origin while a chunk is gone: the range the origin answers
    // is of the new version, so it is not used; the object is fetched whole instead
    SHIFTY.store(1, Ordering::SeqCst);
    forget_chunk(&env, path, 2);
    let whole = get(&env, "example.com", path).await;
    assert_eq!((whole.status, whole.header("fcf-cache-status"), whole.header("etag"), hits()), (200, Some("MISS"), Some("\"vid1\""), 3));
    assert!(whole.body.as_bytes() == video_bytes(1), "all of the new version, nothing of the old");
    assert_eq!(ranges_asked(path), [format!("{path} bytes={}-{} \"vid0\"", 2 * C, 3 * C - 1)]);
    let entry = video_entry(&env, path).await.unwrap();
    assert!(entry.piece.is_none(), "kept whole this once");
    let again = get(&env, "example.com", path).await;
    assert!(again.header("fcf-cache-status") == Some("HIT") && again.body.as_bytes() == video_bytes(1));
    SHIFTY.store(0, Ordering::SeqCst);
}

#[tokio::test]
async fn purges_remove_every_chunk_of_an_object() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let path = "/vid/ranged-purged.bin";
    let purges: [(&str, Box<dyn Fn(&Env) -> usize>); 4] = [
        ("url", Box::new(|env: &Env| env.edge.cache.purge_urls(&env.zone, &[format!("https://example.com{path}")], false))),
        ("host", Box::new(|env: &Env| env.edge.cache.purge_urls(&env.zone, &["example.com/".into()], true))),
        ("tag", Box::new(|env: &Env| env.edge.cache.purge_tags(&env.zone, &["videos".into()]))),
        ("everything", Box::new(|env: &Env| env.edge.cache.purge_zone(&env.zone))),
    ];
    for (how, purge) in purges {
        assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("MISS"), "{how}");
        assert_eq!(video_gone(&env, path).await, (false, vec![true; 4]));
        assert_eq!(purge(&env), 1, "{how}: one object");
        assert_eq!(video_gone(&env, path).await, (true, vec![false; 4]), "{how}");
    }
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("MISS"));
}

#[tokio::test]
async fn an_expired_chunked_object_is_fetched_anew_or_served_stale() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let path = "/vid/ranged-brief.bin";
    let data = video_bytes(0);
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("MISS"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let renewed = get(&env, "example.com", path).await;
    assert!(renewed.header("fcf-cache-status") == Some("EXPIRED") && renewed.body.as_bytes() == data);
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("HIT"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let rule = json!({ "expression": "http.request.uri.path contains \"ranged-brief\"", "origin_port": closed, "priority": 1 });
    env.store.save_item::<OriginRule>(&env.zone, None, rule, true).unwrap();
    let stale = get(&env, "example.com", path).await;
    assert_eq!((stale.status, stale.header("fcf-cache-status")), (200, Some("STALE")));
    assert!(stale.body.as_bytes() == data);
    // without a chunk it needs, the error is what the visitor gets
    forget_chunk(&env, path, 3);
    assert_eq!(get(&env, "example.com", path).await.status, 521);
}

#[tokio::test]
async fn with_chunking_off_large_objects_are_cached_whole_as_before() {
    let env = setup().await;
    let hits = || env.hits.load(Ordering::SeqCst);
    for bad in [json!(1), json!(C - 1), json!(cache::MAX_OBJECT + 1), json!(-1), json!("on")] {
        assert!(env.store.update_setting(&env.zone, "cache_chunking", bad.clone()).is_err(), "{bad}");
    }
    assert_eq!(env.store.snapshot().zones.values().next().unwrap().zone.settings.cache_chunking, 0, "off by default");
    let path = "/vid/ranged-off.bin";
    let data = video_bytes(0);
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("MISS"));
    let entry = video_entry(&env, path).await.unwrap();
    assert!(entry.piece.is_none() && entry.body.len() as u64 == VIDEO_LEN, "one whole entry");
    assert_eq!(video_chunks(&env, path).await, [false; 4]);
    let part = ranged(&env, path, "bytes=100-199").await;
    assert!(part.status == 206 && part.header("fcf-cache-status") == Some("HIT") && part.body.as_bytes() == &data[100..200]);
    assert_eq!(hits(), 1);
    // a range request for what is not cached goes to the origin as it is, as before
    let cold = ranged(&env, "/vid/ranged-off-cold.bin", "bytes=0-9").await;
    assert_eq!((cold.status, cold.header("fcf-cache-status")), (206, Some("DYNAMIC")));
    assert!(cold.body.as_bytes() == &data[..10]);
    assert!(video_entry(&env, "/vid/ranged-off-cold.bin").await.is_none());

    // switched on, what is kept whole is still served whole ...
    for value in [json!(C), json!(cache::MAX_OBJECT)] {
        env.store.update_setting(&env.zone, "cache_chunking", value).unwrap();
    }
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("HIT"));
    // ... and once kept in chunks, switching off makes it a miss, fetched and kept whole again
    env.edge.cache.purge_zone(&env.zone);
    get(&env, "example.com", path).await;
    assert_eq!(video_chunks(&env, path).await, [true; 4]);
    env.store.update_setting(&env.zone, "cache_chunking", json!(0)).unwrap();
    let off = get(&env, "example.com", path).await;
    assert!(off.header("fcf-cache-status") == Some("MISS") && off.body.as_bytes() == data);
    assert!(video_entry(&env, path).await.unwrap().piece.is_none());
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("HIT"));
    // an object smaller than the threshold is kept whole too
    env.store.update_setting(&env.zone, "cache_chunking", json!(VIDEO_LEN + 1)).unwrap();
    let path = "/vid/ranged-under.bin";
    get(&env, "example.com", path).await;
    assert!(video_entry(&env, path).await.unwrap().piece.is_none());
    assert!(ranges_asked("/vid/ranged-off.bin").is_empty() && ranges_asked(path).is_empty());
}

#[tokio::test]
async fn an_expired_chunked_object_is_answered_at_once_while_it_is_fetched_anew() {
    let env = setup().await;
    tokio::spawn(env.edge.clone().refresh_stale());
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let hits = || env.hits.load(Ordering::SeqCst);
    let path = "/vid/ranged-brief-swr.bin";
    let data = video_bytes(0);
    assert_eq!(get(&env, "example.com", path).await.header("fcf-cache-status"), Some("MISS"));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let stale = get(&env, "example.com", path).await;
    assert!(stale.header("fcf-cache-status") == Some("UPDATING") && stale.body.as_bytes() == data);
    for _ in 0..40 {
        if hits() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(hits(), 2, "fetched anew behind the visitor's back");
    let fresh = get(&env, "example.com", path).await;
    assert!(fresh.header("fcf-cache-status") == Some("HIT") && fresh.body.as_bytes() == data);
    assert_eq!(video_chunks(&env, path).await, [true; 4]);
    // an expired object missing a chunk is not answered stale: the visitor waits for the origin
    tokio::time::sleep(Duration::from_millis(1200)).await;
    forget_chunk(&env, path, 0);
    let expired = get(&env, "example.com", path).await;
    assert!(expired.header("fcf-cache-status") == Some("EXPIRED") && expired.body.as_bytes() == data);
    assert_eq!(hits(), 3);
}

#[tokio::test]
async fn a_chunked_object_without_a_validator_is_fetched_whole_when_a_chunk_is_gone() {
    let env = setup().await;
    env.store.update_setting(&env.zone, "cache_chunking", json!(C)).unwrap();
    let hits = || env.hits.load(Ordering::SeqCst);
    let path = "/vid/ranged-unvalidated.bin";
    let data = video_bytes(0);
    get(&env, "example.com", path).await;
    assert_eq!(video_chunks(&env, path).await, [true; 4]);
    forget_chunk(&env, path, 1);
    // nothing to ask for the chunk by that would tell another version: a miss
    let whole = get(&env, "example.com", path).await;
    assert_eq!((whole.status, whole.header("fcf-cache-status"), hits()), (200, Some("MISS"), 2));
    assert!(whole.body.as_bytes() == data);
    assert!(ranges_asked(path).is_empty());
    assert_eq!(video_chunks(&env, path).await, [true; 4], "kept in chunks again");
    // a range request then goes to the origin as it is, as for anything not cached
    forget_chunk(&env, path, 0);
    let part = ranged(&env, path, "bytes=0-9").await;
    assert_eq!((part.status, part.header("fcf-cache-status"), hits()), (206, Some("DYNAMIC"), 3));
    assert!(part.body.as_bytes() == &data[..10]);
    assert_eq!(ranges_asked(path), [format!("{path} bytes=0-9 -")], "the visitor's own range");
    assert!(video_entry(&env, path).await.is_none());
}

#[tokio::test]
async fn an_active_custom_hostname_is_served_as_its_zone_with_its_own_host_and_cache() {
    use crate::custom_hostnames::{CustomHostname, ACTIVE};
    let env = setup().await;
    let h = env.store.save_item::<CustomHostname>(&env.zone, None, json!({ "hostname": "store.example.net", "custom_origin_server": "www.example.com" }), true).unwrap();
    let get_item = || env.store.item::<CustomHostname>(&env.zone, &h.meta.id).unwrap();

    // pending: not served; the request is noted as its first visitor, a name nobody created is not
    let version = env.store.version();
    assert_eq!(get(&env, "other.example.net", "/").await.status, 404);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(env.store.version(), version, "nothing written for an unknown name");
    assert_eq!(get(&env, "store.example.net", "/").await.status, 404);
    for _ in 0..100 {
        if get_item().seen_at.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(get_item().seen_at.is_some());
    assert_eq!(env.hits.load(Ordering::SeqCst), 0);

    // active (as when its certificate arrived): the zone serves it under its own name
    env.store
        .update_item_async::<CustomHostname, _>(&env.zone, &h.meta.id, |h| {
            h.status = ACTIVE.into();
            true
        })
        .await
        .unwrap();
    let r = get(&env, "store.example.net", "/hello").await;
    assert!(r.status == 200 && r.body.contains("GET /hello host=store.example.net"), "{}", r.body);

    // the zone's firewall applies to it, and can tell it apart
    let block = json!({ "expression": "http.host eq \"store.example.net\" and http.request.uri.path eq \"/admin\"", "action": "block" });
    env.store.save_item::<FirewallRule>(&env.zone, None, block, true).unwrap();
    assert_eq!(get(&env, "store.example.net", "/admin").await.status, 403);
    assert_eq!(get(&env, "www.example.com", "/admin").await.status, 200);

    // the zone's cache, with keys of its own
    assert_eq!(get(&env, "store.example.net", "/assets/app.js").await.header("fcf-cache-status"), Some("MISS"));
    assert_eq!(get(&env, "store.example.net", "/assets/app.js").await.header("fcf-cache-status"), Some("HIT"));
    assert_eq!(get(&env, "www.example.com", "/assets/app.js").await.header("fcf-cache-status"), Some("MISS"));

    // names around it are not served, and deleting it ends it
    assert_eq!(get(&env, "x.store.example.net", "/").await.status, 404);
    env.store.delete_item::<CustomHostname>(&env.zone, &h.meta.id).unwrap();
    assert_eq!(get(&env, "store.example.net", "/hello").await.status, 404);
}

#[tokio::test]
async fn api_shield_checks_bodies_and_unknown_endpoints_by_the_zone_settings() {
    use crate::edge::apishield::ApiOperation;
    let env = setup().await;
    let save = |v| env.store.save_item::<ApiOperation>(&env.zone, None, v, true).unwrap();
    let users = save(json!({
        "method": "POST", "host": "example.com", "endpoint": "/api/users",
        "request_body_schema": { "type": "object", "required": ["name"], "properties": { "name": { "type": "string", "maxLength": 8 } } },
        "request_body_required": true,
    }));
    save(json!({ "method": "GET", "host": "example.com", "endpoint": "/api/users/{id}" }));
    let json_ct = "Content-Type: application/json\r\n";
    let good = r#"{"name":"ann"}"#;

    // by default the findings only feed the rules: nothing is stopped
    assert_eq!(send(&env, "POST", "example.com", "/api/users", json_ct, "{}").await.status, 200);
    assert_eq!(get(&env, "example.com", "/api/admin").await.status, 200);

    env.store.update_setting(&env.zone, "api_shield_schema_action", json!("block")).unwrap();
    env.store.update_setting(&env.zone, "api_shield_fallthrough_action", json!("log")).unwrap();
    let before = env.hits.load(Ordering::SeqCst);
    for (body, extra) in [("{}", json_ct), (r#"{"name":"far too long"}"#, json_ct), ("", json_ct), (good, "Content-Type: text/plain\r\n"), ("{\"name\":", json_ct)] {
        let r = send(&env, "POST", "example.com", "/api/users", extra, body).await;
        assert_eq!(r.status, 403, "{body:?} {extra:?}");
        assert!(r.body.contains("schema_validation"), "{}", r.body);
    }
    assert_eq!(env.hits.load(Ordering::SeqCst), before, "a blocked request never reaches the origin");
    // a good body is checked and still reaches the origin whole
    let r = send(&env, "POST", "example.com", "/%61pi//users/", json_ct, good).await;
    assert!(r.status == 200 && r.body.contains(&format!("body={good}")), "{} {}", r.status, r.body);
    // a body over what the edge reads cannot be checked, so it does not pass
    let padded = format!(r#"{{"name":"ann","pad":"{}"}}"#, "x".repeat(1_100_000));
    let r = send(&env, "POST", "example.com", "/api/users", json_ct, &padded).await;
    assert!(r.status == 403 && r.body.contains("schema_validation"), "{}", r.status);
    // templates match one segment; other hosts and the edge's own paths are not covered
    assert_eq!(get(&env, "example.com", "/api/users/42").await.status, 200);
    assert_eq!(get(&env, "example.com", "/api/admin").await.status, 200, "a fallthrough is only logged");
    assert_eq!(send(&env, "POST", "www.example.com", "/api/users", json_ct, "{}").await.status, 200, "no operations on www");

    env.store.update_setting(&env.zone, "api_shield_fallthrough_action", json!("block")).unwrap();
    let r = get(&env, "example.com", "/api/users/42/x").await;
    assert!(r.status == 403 && r.body.contains("fallthrough"), "{}", r.status);
    assert_eq!(send(&env, "DELETE", "example.com", "/api/users/42", "", "").await.status, 403, "matching is per method");
    assert_ne!(get(&env, "example.com", "/cdn-cgi/trace").await.status, 403);

    // a custom rule sees the fields first: a skip rule spares a client, a block rule needs no setting
    env.store.update_setting(&env.zone, "api_shield_fallthrough_action", json!("none")).unwrap();
    env.store.update_setting(&env.zone, "api_shield_schema_action", json!("none")).unwrap();
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "cf.api_gateway.fallthrough_detected and http.request.uri.path contains \"/admin\"", "action": "block" }), true)
        .unwrap();
    assert_eq!(get(&env, "example.com", "/api/admin").await.status, 403);
    assert_eq!(get(&env, "example.com", "/api/other").await.status, 200);
    env.store.update_setting(&env.zone, "api_shield_schema_action", json!("block")).unwrap();
    env.store.save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "http.request.headers[\"x-internal\"] eq \"yes\"", "action": "skip", "priority": -1 }), true).unwrap();
    assert_eq!(send(&env, "POST", "example.com", "/api/users", &format!("{json_ct}X-Internal: yes\r\n"), "{}").await.status, 200);

    let events = env.edge.waf.events(&env.zone, 100);
    let found = |rule: &str, action: &str| events.iter().any(|e| e.source == "api_shield" && e.rule_id == rule && e.action == action);
    assert!(found("schema_validation", "block") && found("fallthrough", "log") && found("fallthrough", "block"));
    let reason = events.iter().find(|e| e.rule_id == "schema_validation").map(|e| e.description.clone()).unwrap_or_default();
    assert!(reason.contains(&users.meta.id) && !reason.contains("far too long"), "{reason}");

    // deleting the operations ends the checks
    for op in env.store.items::<ApiOperation>(&env.zone).unwrap() {
        env.store.delete_item::<ApiOperation>(&env.zone, &op.meta.id).unwrap();
    }
    assert_eq!(send(&env, "POST", "example.com", "/api/users", json_ct, "{}").await.status, 200);
}

/// What a tracing subscriber writes, kept for a test to search.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_leaked_password_reaches_the_rules_and_never_the_logs_or_traces() {
    // everything the process traces while the requests go through, at every level
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_ansi(false).with_writer(move || writer.clone()).finish();
    let _traced = tracing::subscriber::set_default(subscriber);

    let env = setup().await;
    let leaked = "hunter2-example-leak";
    let fresh = "correct-horse-example-fresh";
    let hex: String = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, leaked.as_bytes()).as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let path = std::env::temp_dir().join(format!("fucf-leaked-edge-{}.txt", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, format!("# test table\n{}:12\n", hex.to_ascii_uppercase())).unwrap();
    env.edge.leaked_passwords.set(credcheck::LeakedPasswords::open(&path).unwrap()).unwrap();
    std::fs::remove_file(&path).unwrap();

    // the rules decide: blocked on /login, a header for the origin on the API
    env.store
        .save_item::<FirewallRule>(&env.zone, None, json!({ "expression": "cf.waf.credential_check.password_leaked and not http.request.uri.path contains \"/api/\"", "action": "block" }), true)
        .unwrap();
    env.store
        .save_item::<TransformRule>(&env.zone, None, json!({ "expression": "cf.waf.credential_check.password_leaked", "set_request_headers": { "X-Added": "leaked" } }), true)
        .unwrap();
    let form = "Content-Type: application/x-www-form-urlencoded\r\n";
    let json_ct = "Content-Type: application/json\r\n";
    let login = |pw: &str| format!("username=ann%40example.com&password={pw}");

    // the zone has not opted in yet: nothing is looked up
    assert_eq!(send(&env, "POST", "example.com", "/login", form, &login(leaked)).await.status, 200);
    // Tests running beside this one may have registered the edge's log lines
    // while no subscriber wanted them; now that they are registered, have
    // them ask again, so that this subscriber sees every one from here on.
    tracing::callsite::rebuild_interest_cache();
    env.store.update_setting(&env.zone, "leaked_credential_checks", json!({ "enabled": true, "paths": ["/login", "/api/session"] })).unwrap();

    assert_eq!(send(&env, "POST", "example.com", "/login", form, &login(leaked)).await.status, 403);
    // the way an origin reads a path does not walk past the check
    assert_eq!(send(&env, "POST", "example.com", "/%6Cogin/", form, &login(leaked)).await.status, 403);
    let r = send(&env, "POST", "example.com", "/login", form, &login(fresh)).await;
    assert!(r.status == 200 && r.body.contains("added=-"), "{}", r.body);
    let r = send(&env, "POST", "example.com", "/api/session", json_ct, &format!(r#"{{"user": {{"email": "ann@example.com", "password": "{leaked}"}}}}"#)).await;
    assert!(r.status == 200 && r.body.contains("added=leaked"), "{}", r.body);
    // paths the zone did not list, and requests that are no login, are not looked at
    let r = send(&env, "POST", "example.com", "/comment", form, &login(leaked)).await;
    assert!(r.status == 200 && r.body.contains("added=-"), "{}", r.body);
    let r = send(&env, "POST", "example.com", "/api/session", json_ct, &format!(r#"{{"password": "{leaked}"}}"#)).await;
    assert!(r.body.contains("added=-"), "{}", r.body);
    let trace = get(&env, "example.com", "/cdn-cgi/fucf-trace").await;
    assert_eq!(trace.status, 200);

    // nothing the edge keeps or writes holds the password, its hash or the hash's prefix
    let filter = reqlog::Filter { zone_id: env.zone.clone(), ..Default::default() };
    let page = env.edge.reqlog.query(None, 100, &filter);
    assert!(page.entries.len() >= 7, "the requests are in the log");
    let log = String::from_utf8(reqlog::ndjson(&page.entries).to_vec()).unwrap();
    let api_log = env.edge.reqlog.answer(&reqlog::LogQuery::parse(&env.zone, &Default::default()).unwrap(), "test").to_string();
    let events = env.edge.waf.events(&env.zone, 100);
    assert!(events.iter().any(|e| e.action == "block"), "the block is a security event");
    let events = serde_json::to_string(&events).unwrap();
    let traced = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(traced.contains("/api/session"), "the subscriber saw the requests:\n{traced}");
    for (what, text) in [("request log", &log), ("request log API", &api_log), ("security events", &events), ("tracing", &traced), ("fucf-trace", &trace.body)] {
        let lower = text.to_ascii_lowercase();
        assert!(!text.contains(leaked) && !text.contains(&login(leaked)), "the password is in the {what}");
        assert!(!lower.contains(&hex) && !lower.contains(&hex[..credcheck::PREFIX_HEX]), "its hash is in the {what}");
    }
}
