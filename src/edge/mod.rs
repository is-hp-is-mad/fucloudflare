//! The edge data plane: HTTP/HTTPS listeners and the per-request pipeline
//! (host lookup -> WAF -> worker -> cache -> origin).

pub mod cache;
pub mod certdir;
pub mod cgi;
pub mod files;
pub mod compress;
pub mod front;
pub mod h3;
pub mod proxy;
pub mod quic_mux;
pub mod stats;
pub mod tls;
pub mod upstream;
pub mod waf;
pub mod warp;

use crate::expr::ReqInfo;
use crate::store::{Snapshot, Store, ZoneSnap};
use bytes::Bytes;
use cache::{Cache, Decision};
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use upstream::{Target, Tls, Upstream, UpstreamError};
use waf::{Verdict, Waf};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = BoxBody<Bytes, BoxError>;

const MAX_CONNECTIONS: usize = 20_000;
/// Request bodies up to this size are buffered so the WAF can inspect them.
const INSPECT_LIMIT: u64 = 1024 * 1024;
/// Largest body a worker may read or produce.
pub const WORKER_BODY_LIMIT: usize = 16 * 1024 * 1024;
const LOOP_TOKEN: &str = "fucf";
/// How long an origin address that failed is tried last.
const ORIGIN_COOLDOWN: Duration = Duration::from_secs(10);

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into()).map_err(|e| match e {}).boxed()
}

fn streaming(body: Incoming) -> Body {
    body.map_err(BoxError::from).boxed()
}

/// An error answered with a Cloudflare-style error page.
#[derive(Debug)]
pub struct EdgeError {
    pub status: u16,
    pub title: &'static str,
    /// What went wrong, in full. For origin errors this may name origin
    /// addresses: it goes to the log, never to the visitor.
    pub detail: String,
    /// Set for errors in reaching the origin, see [`OriginFault`].
    pub origin: Option<OriginFault>,
}

/// Why the origin could not be reached, told without naming it.
#[derive(Clone, Copy, Debug)]
pub struct OriginFault {
    /// What visitors see: the kind of failure, nothing about the origin itself.
    pub reason: Reason,
    /// For the site's admins only (dashboard): how this comes about and how to fix it.
    pub hint: Option<&'static str>,
}

/// A kind of origin failure, in the visitor's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reason {
    pub zh: &'static str,
    pub en: &'static str,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}（{}）。", self.zh, self.en)
    }
}

/// The title of every error page about the origin.
pub const ORIGIN_ERROR: &str = "回源错误 Origin error";

impl EdgeError {
    pub fn new(status: u16, title: &'static str, detail: impl Into<String>) -> Self {
        EdgeError { status, title, detail: detail.into(), origin: None }
    }

    /// The origin could not be reached or answered badly. `reason` is what the
    /// visitor is told; `detail` is only logged.
    pub fn origin(status: u16, reason: Reason, detail: impl Into<String>) -> Self {
        EdgeError { status, title: ORIGIN_ERROR, detail: detail.into(), origin: Some(OriginFault { reason, hint: None }) }
    }

    /// Add a note for the dashboard on how to fix this (never shown to visitors).
    pub fn hint(mut self, hint: &'static str) -> Self {
        if let Some(fault) = self.origin.as_mut() {
            fault.hint = Some(hint);
        }
        self
    }

    /// The text the visitor gets.
    pub fn public_detail(&self) -> String {
        match &self.origin {
            Some(fault) => format!("{} 边缘节点工作正常，但没能从源站得到有效的响应。", fault.reason),
            None => self.detail.clone(),
        }
    }

    /// Which part of the path failed.
    pub fn hop(&self) -> Hop {
        match (self.origin.is_some(), self.status) {
            (true, _) => Hop::Origin,
            (false, 400 | 411 | 413 | 414 | 431) => Hop::Browser,
            _ => Hop::Edge,
        }
    }

    /// One line for clients that cannot read a page (gRPC): ASCII, nothing about the origin.
    pub fn public_line(&self) -> String {
        match &self.origin {
            Some(fault) => format!("Origin error: {}", fault.reason.en),
            None => format!("{}: {}", self.title, self.detail),
        }
    }
}

/// The three stops of a request, as an error page draws them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hop {
    /// The request itself is malformed or too large.
    Browser,
    /// The edge answered by itself (unknown host, `/cdn-cgi/*`, security
    /// rules, limits): the origin was not involved.
    Edge,
    /// The edge could not get a usable answer from the origin.
    Origin,
}

/// What an error page tells about where it comes from.
pub struct PageCtx {
    pub hop: Hop,
    /// The host name the visitor asked for (never the origin's address).
    pub host: String,
    pub here: cgi::Here,
}

/// Origin-side failures as visitors are told about them.
pub const ORIGIN_DOWN: Reason = Reason { zh: "源站拒绝连接或无法连通", en: "connection refused or unreachable" };
pub const ORIGIN_TIMEOUT: Reason = Reason { zh: "连接源站超时", en: "connection timed out" };
pub const ORIGIN_TLS: Reason = Reason { zh: "与源站的 TLS 握手失败", en: "SSL handshake failed" };
pub const ORIGIN_BAD_RESPONSE: Reason = Reason { zh: "源站的响应无效或中途断开", en: "bad gateway" };
pub const ORIGIN_NOT_CONFIGURED: Reason = Reason { zh: "这个主机名没有配置源站", en: "no origin configured" };
pub const ORIGIN_UNRESOLVED: Reason = Reason { zh: "源站地址无法解析", en: "origin DNS error" };
pub const ORIGIN_NO_H2: Reason = Reason { zh: "源站不支持 gRPC 所需的 HTTP/2", en: "the origin does not offer HTTP/2, which gRPC needs" };
pub const ORIGIN_MISCONFIGURED: Reason = Reason { zh: "源站配置有误", en: "origin misconfigured" };

/// Dashboard note for an origin that is this very edge node.
pub const HINT_ORIGIN_IS_EDGE: &str = "这条记录的源站地址是处理请求的边缘节点自己的公网 IP（在 FUCF_EDGE_IPS 里），\
fucf 会把它当作回环而拒绝回源。修复：在该记录的回源设置里把“回源节点”(origin_node) 设为这个节点，\
同一节点上会改为回源 127.0.0.1，其余节点回源到它的 IP；或者把源站改成真实的源站地址。";

impl From<UpstreamError> for EdgeError {
    fn from(e: UpstreamError) -> Self {
        match e {
            UpstreamError::Down(d) => EdgeError::origin(521, ORIGIN_DOWN, d),
            UpstreamError::Timeout => EdgeError::origin(522, ORIGIN_TIMEOUT, "the origin did not respond in time"),
            UpstreamError::Tls(d) => EdgeError::origin(525, ORIGIN_TLS, d),
            UpstreamError::Other(d) if d.contains("does not offer HTTP/2") => EdgeError::origin(502, ORIGIN_NO_H2, d),
            UpstreamError::Other(d) => EdgeError::origin(502, ORIGIN_BAD_RESPONSE, d),
        }
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The look of the edge's own pages (errors, the browser check): warm
/// neutrals, a serif headline and buttons that give a little when pressed.
const PAGE_CSS: &str = "\
:root{color-scheme:light dark;--bg:#faf9f5;--fg:#141413;--sub:#5e5d59;--faint:#87867f;--line:#e8e6dc;--chip:#f0eee6;--btn:#141413;--btnfg:#faf9f5;--clay:#d97757}\
@media (prefers-color-scheme:dark){:root{--bg:#262624;--fg:#faf9f5;--sub:#b0aea5;--faint:#87867f;--line:#3d3d3a;--chip:#30302e;--btn:#faf9f5;--btnfg:#141413}}\
*{box-sizing:border-box}html{height:100%}\
body{margin:0;min-height:100%;display:grid;place-items:center;background:var(--bg);color:var(--fg);\
font:16px/1.65 ui-sans-serif,system-ui,-apple-system,'Segoe UI','PingFang SC','Noto Sans SC','Microsoft YaHei',sans-serif;-webkit-font-smoothing:antialiased}\
main{width:min(36rem,100%);padding:3rem 1.5rem}\
.mark{display:block;width:40px;height:40px;margin-bottom:1.75rem;color:var(--clay)}\
.code{display:inline-block;font:500 13px/1 ui-monospace,'SF Mono',Consolas,monospace;color:var(--sub);background:var(--chip);border-radius:999px;padding:6px 10px;margin-bottom:1rem}\
h1{font:500 clamp(1.75rem,4vw,2.25rem)/1.2 ui-serif,'Iowan Old Style',Georgia,'Songti SC','Noto Serif SC',serif;letter-spacing:-.015em;margin:0 0 .75rem}\
p{margin:0 0 1rem;color:var(--sub)}\
.acts{display:flex;gap:12px;margin-top:1.75rem;flex-wrap:wrap}\
button{position:relative;overflow:hidden;display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 20px;border:0;border-radius:.6rem;\
background:var(--btn);color:var(--btnfg);font-family:inherit;font-size:15px;font-weight:500;line-height:1.5;cursor:pointer;-webkit-user-select:none;user-select:none;backface-visibility:hidden;will-change:transform;\
transition:transform .15s cubic-bezier(.165,.85,.45,1)}\
button::after{content:'';position:absolute;inset:0;opacity:0;transform:translateY(8px);background:radial-gradient(at bottom,rgba(255,255,255,.2),transparent);transition:opacity .2s,transform .2s}\
button:hover{transform:scaleY(1.015) scaleX(1.005)}button:hover::after{opacity:1;transform:none}button:active{transform:scale(.985)}\
button:focus-visible{outline:2px solid #c46849;outline-offset:2px}\
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);font-size:13px;color:var(--faint);display:flex;gap:6px 16px;flex-wrap:wrap}\
footer code{font:12.5px ui-monospace,'SF Mono',Consolas,monospace;color:var(--sub)}\
.spin{width:28px;height:28px;border-radius:50%;border:2.5px solid var(--line);border-top-color:var(--clay);animation:r 0.9s linear infinite;margin-bottom:1.75rem}\
@keyframes r{to{transform:rotate(360deg)}}\
.path{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin:2rem 0 1.5rem;padding:1.25rem .5rem;border:1px solid var(--line);border-radius:1rem}\
.hop{position:relative;text-align:center;min-width:0}\
.hop:not(:last-child)::after{content:'';position:absolute;top:22px;left:calc(50% + 30px);right:calc(-50% + 22px);border-top:2px dashed var(--line)}\
.hop i{display:grid;place-items:center;width:44px;height:44px;margin:0 auto .6rem;border-radius:50%;background:var(--chip);color:var(--sub)}\
.hop i svg{width:22px;height:22px}\
.hop b{display:block;font-size:14px;font-weight:500;line-height:1.35}\
.hop small{display:block;font:12px/1.4 ui-monospace,'SF Mono',Consolas,monospace;color:var(--faint);overflow-wrap:anywhere}\
.hop em{display:inline-block;margin-top:.5rem;padding:3px 9px;border-radius:999px;font:500 12px/1.4 inherit;font-style:normal;background:var(--chip);color:var(--faint)}\
.hop.ok i,.hop.ok em{background:rgba(74,155,110,.14);color:#2f7a52}\
.hop.bad i,.hop.bad em{background:rgba(217,119,87,.16);color:#b5462a}\
@media (prefers-color-scheme:dark){.hop.ok i,.hop.ok em{color:#7cc49b}.hop.bad i,.hop.bad em{color:#f0a283}}\
.what h2{font-size:15px;font-weight:600;margin:1.25rem 0 .25rem}.what p{font-size:15px;margin:0}\
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}";

/// A small mark for the edge's pages (an open sector: the edge between visitor and origin).
const PAGE_MARK: &str = "<svg class=\"mark\" viewBox=\"0 0 40 40\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.5\" stroke-linecap=\"round\" aria-hidden=\"true\"><path d=\"M6 28a14 14 0 0 1 28 0\"/><path d=\"M20 28l8-10\"/><circle cx=\"20\" cy=\"28\" r=\"2\" fill=\"currentColor\"/></svg>";

fn html_page(status: StatusCode, title: &str, body: &str) -> Response<Body> {
    let html = format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\">\
         <title>{title}</title><style>{PAGE_CSS}</style></head><body><main>{body}</main></body></html>"
    );
    let mut resp = Response::new(full(html));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

const ICON_BROWSER: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"3.5\" y=\"4.5\" width=\"17\" height=\"15\" rx=\"2\"/><path d=\"M3.5 9h17M7 6.8h.01M9.5 6.8h.01\"/></svg>";
const ICON_EDGE: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.9\" stroke-linecap=\"round\"><path d=\"M4 17a8 8 0 0 1 16 0\"/><path d=\"M12 17l4.5-5.5\"/><circle cx=\"12\" cy=\"17\" r=\"1.3\" fill=\"currentColor\"/></svg>";
const ICON_ORIGIN: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><rect x=\"4\" y=\"4.5\" width=\"16\" height=\"6\" rx=\"1.5\"/><rect x=\"4\" y=\"13.5\" width=\"16\" height=\"6\" rx=\"1.5\"/><path d=\"M7.5 7.5h.01M7.5 16.5h.01\"/></svg>";

/// The path of the request and where it broke, like Cloudflare's 5xx pages.
fn path_html(ctx: &PageCtx) -> String {
    let state = |hop: Hop| -> (&str, &str) {
        match (ctx.hop, hop) {
            (failed, h) if failed == h => ("bad", "出错 Error"),
            (Hop::Browser, _) | (Hop::Edge, Hop::Origin) => ("", "未涉及 Not involved"),
            _ => ("ok", "正常 Working"),
        }
    };
    let stop = |hop: Hop, icon: &str, name: &str, sub: &str| {
        let (class, text) = state(hop);
        format!("<div class=\"hop {class}\"><i aria-hidden=\"true\">{icon}</i><b>{name}</b><small>{}</small><em>{text}</em></div>", escape(sub))
    };
    let host = if ctx.host.is_empty() { "-" } else { ctx.host.as_str() };
    format!(
        "<div class=\"path\" role=\"img\" aria-label=\"请求路径：浏览器、边缘节点 {colo}、源站\">{}{}{}</div>",
        stop(Hop::Browser, ICON_BROWSER, "你的浏览器", "Browser"),
        stop(Hop::Edge, ICON_EDGE, "边缘节点", &format!("fucf · {}", ctx.here.colo)),
        stop(Hop::Origin, ICON_ORIGIN, "源站", host),
        colo = escape(&ctx.here.colo),
    )
}

/// What happened and what to do, by where it broke.
fn advice(status: u16, ctx: &PageCtx) -> (String, &'static str) {
    let colo = escape(&ctx.here.colo);
    match ctx.hop {
        Hop::Origin => (
            format!("请求已到达边缘节点 {colo}，但回源失败：问题在源站或回源配置，与你的浏览器和网络无关。"),
            "访客：几分钟后重新加载即可。站点管理员：凭下方 Ray ID 在面板「分析 → 回源错误」查看原因与修复方法。",
        ),
        Hop::Browser => (
            format!("这次请求的格式或大小不被接受，边缘节点 {colo} 没有处理它，也没有转发到源站。"),
            "请检查网址，或清除这个站点的 Cookie 后再试。",
        ),
        Hop::Edge => (
            format!("这次请求由边缘节点 {colo} 直接作答，没有转发到源站，与源站无关。"),
            match status {
                404 => "请检查网址是否正确；如果这个地址本应可用，请联系站点管理员核对 fucf 中的域名与规则配置。",
                403 => "如果你认为不该被拦截，请把下方 Ray ID 告诉站点管理员。",
                429 => "请求太频繁了，请稍等片刻再试。",
                _ if status >= 500 => "这通常是暂时的，请稍后重新加载；持续出现时请把 Ray ID 告诉站点管理员。",
                _ => "请检查网址；持续出现时请把 Ray ID 告诉站点管理员。",
            },
        ),
    }
}

fn page(status: u16, title: &str, detail: &str, ray: &str, ctx: &PageCtx) -> Response<Body> {
    let (t, d) = (escape(title), escape(detail));
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    // a retry helps with what is temporary; a 4xx will not change by itself
    let retry = if status >= 500 { "<div class=\"acts\"><button type=\"button\" onclick=\"location.reload()\">重新加载</button></div>" } else { "" };
    let when = crate::store::now();
    let (what, todo) = advice(status, ctx);
    let (colo, fl) = (escape(&ctx.here.colo), escape(&ctx.here.fl));
    html_page(
        code,
        &format!("{status} · {t}"),
        &format!(
            "{PAGE_MARK}<span class=\"code\">Error {status}</span><h1>{t}</h1><p>{d}</p>{path}\
             <div class=\"what\"><h2>发生了什么</h2><p>{what}</p><h2>可以怎么做</h2><p>{todo}</p></div>{retry}\
             <footer><span>Ray ID <code>{ray}</code></span><span>节点 <code>{colo}</code> · <code>fl={fl}</code></span><span>{when}</span><span>fucf</span></footer>",
            path = path_html(ctx),
        ),
    )
}

fn challenge_page(token: &str, ray: &str) -> Response<Body> {
    html_page(
        StatusCode::FORBIDDEN,
        "Just a moment...",
        &format!(
            "<div class=\"spin\" aria-hidden=\"true\"></div><h1>Checking your browser...</h1>\
             <p>正在确认您的浏览器，几秒后会自动继续。This takes a few seconds.</p>\
             <noscript><p>Please enable JavaScript to continue. 请启用 JavaScript 后继续。</p></noscript>\
             <script>document.cookie=\"{cookie}={token}; path=/; max-age=1800; SameSite=Lax\";location.reload();</script>\
             <footer><span>Ray ID <code>{ray}</code></span><span>fucf</span></footer>",
            cookie = waf::CLEARANCE_COOKIE,
        ),
    )
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Headers named by `Connection` are hop-by-hop too.
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in named {
        headers.remove(n);
    }
    for n in HOP_BY_HOP {
        headers.remove(*n);
    }
}

/// Read a whole body, failing once it exceeds `limit` bytes.
async fn collect_limited(mut body: Body, limit: usize) -> Result<Bytes, String> {
    let mut buf = bytes::BytesMut::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.map_err(|e| e.to_string())?.into_data() {
            if buf.len() + data.len() > limit {
                return Err("body too large".into());
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(buf.freeze())
}

/// What is known of the TLS session a request came in on.
#[derive(Clone)]
pub struct TlsInfo {
    /// `TLSv1.3` or `TLSv1.2`.
    pub version: &'static str,
    /// Did the client name the server it wanted?
    pub sni: bool,
    /// Key exchange group, as far as known.
    pub kex: String,
}

/// Is this a gRPC request? (gRPC-Web is not: that one is plain HTTP.)
fn is_grpc(headers: &HeaderMap) -> bool {
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    content_type.strip_prefix("application/grpc").is_some_and(|rest| rest.is_empty() || rest.starts_with(['+', ';']))
}

/// What a gRPC client gets instead of an error page: a response that
/// consists of a status only, derived from the HTTP status the usual way.
fn grpc_error(http: StatusCode, message: &str) -> Response<Body> {
    use percent_encoding::{utf8_percent_encode, CONTROLS};
    let code = match http.as_u16() {
        400 => 13,                             // INTERNAL
        401 => 16,                             // UNAUTHENTICATED
        403 => 7,                              // PERMISSION_DENIED
        404 => 12,                             // UNIMPLEMENTED
        509 => 8,                              // RESOURCE_EXHAUSTED
        429 | 502 | 503 | 504 | 520..=530 => 14, // UNAVAILABLE
        _ => 2,                                // UNKNOWN
    };
    let mut resp = Response::new(full(Bytes::new()));
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    resp.headers_mut().insert("grpc-status", HeaderValue::from(code as u16));
    const ESCAPED: &percent_encoding::AsciiSet = &CONTROLS.add(b'%');
    let message = utf8_percent_encode(message, ESCAPED).to_string();
    if let Ok(v) = HeaderValue::from_str(&message) {
        resp.headers_mut().insert("grpc-message", v);
    }
    resp
}

/// Marks a response produced by the WAF (for analytics).
#[derive(Clone)]
struct WafHit;

/// On a response for a host name that belongs to no zone but is ours all the
/// same (the management panel): HTTP/3 is on offer for it like for a site.
#[derive(Clone)]
struct OffersHttp3(String);

/// The host a request is for, from its URI or `Host` header: without the
/// port, the brackets of an IPv6 literal and a trailing dot, lowercase, IP
/// addresses in their canonical form (so rules match `2001:db8::1` however
/// the client wrote it).
pub(crate) fn request_host(raw: &str) -> String {
    let raw = raw.trim();
    let host = match raw.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => match raw.rsplit_once(':') {
            Some((h, port)) if !h.is_empty() && !h.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => raw,
        },
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.parse::<IpAddr>().map(|ip| ip.to_string()).unwrap_or(host)
}

/// May an `accelerate` node serve `host`? It serves the hosts on its
/// allowlist (`accel_hosts`) and its own sites: proxy rules scoped to this
/// node by name. Rules for every node do not count -- the allowlist is what
/// keeps the fleet's sites off an accelerate node.
fn accelerate_allows(edge: &Edge, snap: &crate::store::Snapshot, host: &str, path: &str, listener: Option<&proxy::ListenerInfo>) -> bool {
    let me = crate::fleet::self_name(&edge.store, &edge.edge_ips, edge.node_name.get().map(String::as_str));
    if snap.nodes.iter().find(|n| n.name == me).is_some_and(|n| crate::items::accel_host_matches(&n.accel_hosts, host)) {
        return true;
    }
    proxy::match_rule(&snap.local_proxy_rules, Some(&me), listener, host, path)
        .or_else(|| proxy::match_fallback(&snap.local_proxy_rules, Some(&me), listener, host, path))
        .is_some_and(|rule| rule.nodes.iter().any(|n| n.eq_ignore_ascii_case(&me)))
}

/// What the pipeline learned about a request before it finished or failed:
/// enough for analytics and for the edge's own response headers.
struct Seen {
    zone_id: String,
    http3: bool,
    host: String,
    path: String,
    country: String,
}

/// Counts the body bytes handed to the client and books them once the
/// response is over, however it ends.
struct Metered {
    inner: Body,
    sent: u64,
    stats: Arc<stats::Stats>,
    limits: Option<Arc<crate::limits::Limits>>,
    zone_id: String,
}

/// Holds a response body back to the node's speed limit. The limit is one
/// bucket for the whole node; large pieces are cut up so that they cannot
/// rush through at once.
struct Throttled {
    inner: Body,
    limits: Arc<crate::limits::Limits>,
    /// Read from `inner`, not passed on yet.
    held: Bytes,
    wait: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl hyper::body::Body for Throttled {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        use std::task::Poll;
        const PIECE: usize = 16 * 1024;
        loop {
            if let Some(wait) = self.wait.as_mut() {
                std::task::ready!(std::future::Future::poll(wait.as_mut(), cx));
                self.wait = None;
            }
            if !self.held.is_empty() {
                let n = self.held.len().min(PIECE);
                let piece = self.held.split_to(n);
                // what was sent is paid for by the wait before the next piece
                let pause = self.limits.throttle(n);
                if !pause.is_zero() {
                    self.wait = Some(Box::pin(tokio::time::sleep(pause)));
                }
                return Poll::Ready(Some(Ok(hyper::body::Frame::data(piece))));
            }
            match std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => self.held = data,
                    Err(other) => return Poll::Ready(Some(Ok(other))),
                },
                other => return Poll::Ready(other),
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.held.is_empty() && self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        let (inner, held) = (self.inner.size_hint(), self.held.len() as u64);
        let mut hint = hyper::body::SizeHint::new();
        hint.set_lower(inner.lower() + held);
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper + held);
        }
        hint
    }
}

impl hyper::body::Body for Metered {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(frame))) = &polled {
            self.sent += frame.data_ref().map_or(0, |d| d.len() as u64);
        }
        polled
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Metered {
    fn drop(&mut self) {
        if self.sent > 0 {
            self.stats.add_bytes(&self.zone_id, self.sent);
            if let Some(limits) = &self.limits {
                limits.add(self.sent);
            }
        }
    }
}

fn set_headers(headers: &mut HeaderMap, values: &std::collections::BTreeMap<String, String>) {
    for (name, value) in values {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            headers.insert(n, v);
        }
    }
}

/// The client's own cache validators, and the part it asks for.
struct Conditional {
    none_match: Option<HeaderValue>,
    modified_since: Option<HeaderValue>,
    range: Option<HeaderValue>,
    /// The version (entity tag or date) the range refers to.
    if_range: Option<HeaderValue>,
}

impl Conditional {
    fn of(headers: &HeaderMap) -> Self {
        let get = |name| headers.get(name).cloned();
        Conditional {
            none_match: get(header::IF_NONE_MATCH),
            modified_since: get(header::IF_MODIFIED_SINCE),
            range: get(header::RANGE),
            if_range: get(header::IF_RANGE),
        }
    }
}

/// Has the client's copy (as of `since`) seen the last change?
fn unchanged_since(modified: &HeaderValue, since: &HeaderValue) -> bool {
    match (cache::http_date(modified), cache::http_date(since)) {
        (Some(modified), Some(since)) => modified <= since,
        _ => modified == since,
    }
}

/// A body whose beginning was already read.
struct Prefixed<B> {
    head: std::collections::VecDeque<Bytes>,
    rest: B,
}

impl<B> hyper::body::Body for Prefixed<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        if let Some(chunk) = self.head.pop_front() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))));
        }
        std::pin::Pin::new(&mut self.rest).poll_frame(cx).map_err(Into::into)
    }
}

/// Read a body of unknown length: all of it if it stays within `limit`
/// (then the second value is `None`), else what was read and the rest.
async fn read_up_to<B>(mut body: B, limit: usize) -> Result<(Vec<Bytes>, Option<B>), BoxError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let (mut chunks, mut size) = (Vec::new(), 0);
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.map_err(Into::into)?.into_data() {
            size += data.len();
            chunks.push(data);
            if size > limit {
                return Ok((chunks, Some(body)));
            }
        }
    }
    Ok((chunks, None))
}

/// Weak comparison of an `If-None-Match` list against an entity tag.
fn etag_matches(none_match: &HeaderValue, etag: &HeaderValue) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").to_string();
    let (Ok(list), Ok(etag)) = (none_match.to_str(), etag.to_str()) else { return false };
    list.split(',').any(|t| t.trim() == "*" || strip(t) == strip(etag))
}

/// Answer from a cache entry: the body or the part of it that was asked
/// for, or `304` if the client has it already.
fn cached_response(entry: &cache::Entry, method: &Method, cond: &Conditional, label: &'static str) -> Response<Body> {
    let validator_hit = match (&cond.none_match, &cond.modified_since) {
        (Some(inm), _) => entry.headers.get(header::ETAG).is_some_and(|etag| etag_matches(inm, etag)),
        (None, Some(since)) => entry.headers.get(header::LAST_MODIFIED).is_some_and(|modified| unchanged_since(modified, since)),
        _ => false,
    };
    let (mut status, mut body, mut headers) = (entry.status, entry.body.clone(), entry.headers.clone());
    if validator_hit && entry.status == StatusCode::OK {
        (status, body) = (StatusCode::NOT_MODIFIED, Bytes::new());
        headers.remove(header::CONTENT_LENGTH);
    } else if entry.status == StatusCode::OK {
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        let len = entry.body.len() as u64;
        // A range only applies to the version the client has a part of.
        let same_version = cond.if_range.as_ref().is_none_or(|v| {
            entry.headers.get(header::ETAG) == Some(v) || entry.headers.get(header::LAST_MODIFIED) == Some(v)
        });
        let range = cond.range.as_ref().filter(|_| same_version).and_then(|v| v.to_str().ok());
        let content_range = match range.map(|r| cache::parse_range(r, len)) {
            Some(cache::Range::Part(first, last)) => {
                (status, body) = (StatusCode::PARTIAL_CONTENT, entry.body.slice(first as usize..=last as usize));
                Some(format!("bytes {first}-{last}/{len}"))
            }
            Some(cache::Range::Unsatisfiable) => {
                (status, body) = (StatusCode::RANGE_NOT_SATISFIABLE, Bytes::new());
                Some(format!("bytes */{len}"))
            }
            _ => None,
        };
        if let Some(value) = content_range.and_then(|v| HeaderValue::from_str(&v).ok()) {
            headers.insert(header::CONTENT_RANGE, value);
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        }
    }
    let mut resp = Response::new(full(if method == Method::HEAD { Bytes::new() } else { body }));
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp.headers_mut().insert(header::AGE, HeaderValue::from(entry.stored.elapsed().as_secs()));
    resp.headers_mut().insert("cf-cache-status", HeaderValue::from_static(label));
    resp
}

/// Label for a response that was not stored: a cache rule's BYPASS survives,
/// MISS/EXPIRED (nothing ended up cached) reads as DYNAMIC.
fn status_label_for_uncached(label: &'static str) -> &'static str {
    if label == "BYPASS" { "BYPASS" } else { "DYNAMIC" }
}

/// A request body that is either fully buffered or still on the wire.
pub enum ReqBody {
    Buffered(Bytes),
    Stream(Body),
}

impl ReqBody {
    fn into_body(self) -> Body {
        match self {
            ReqBody::Buffered(b) => full(b),
            ReqBody::Stream(s) => s,
        }
    }
    async fn collect(self, limit: usize) -> Result<Bytes, EdgeError> {
        match self {
            ReqBody::Buffered(b) => Ok(b),
            ReqBody::Stream(s) => collect_limited(s, limit)
                .await
                .map_err(|_| EdgeError::new(413, "Payload too large", "request body too large or interrupted")),
        }
    }
}

/// A request on its way to the cache / origin.
pub struct Outgoing {
    pub info: ReqInfo,
    pub headers: HeaderMap,
    pub body: ReqBody,
    pub on_upgrade: Option<OnUpgrade>,
    /// A gRPC call: goes to the origin over HTTP/2, trailers and all.
    pub grpc: bool,
}

pub struct Edge {
    pub store: Arc<Store>,
    pub cache: Arc<Cache>,
    pub waf: Arc<Waf>,
    pub upstream: Upstream,
    pub edge_ips: Vec<IpAddr>,
    /// `Alt-Svc` value advertising HTTP/3, once the QUIC listener is up.
    pub alt_svc: std::sync::OnceLock<HeaderValue>,
    /// Another QUIC server on this node that passes HTTP/3 visitors on to us.
    pub front: std::sync::OnceLock<Arc<front::Front>>,
    /// Host name under which the management panel/API is published, and
    /// the local API address it is forwarded to.
    pub panel: std::sync::OnceLock<(String, SocketAddr)>,
    /// Internal loopback listeners of this node (API, HTTP/3 front) that
    /// worker subrequests must not reach directly.
    pub internal_listeners: std::sync::OnceLock<Vec<SocketAddr>>,
    /// Visitor geolocation for the `ip.geoip.*` rule fields.
    pub geo: std::sync::OnceLock<Arc<crate::geo::Geo>>,
    pub stats: Arc<stats::Stats>,
    /// This node's traffic allowance and speed limit.
    pub limits: Arc<crate::limits::Limits>,
    /// This node's mainland-China (GFW) reachability status.
    pub gfw: Arc<crate::gfw::GfwMonitor>,
    /// Host name from which the over-limit notice loads its resources.
    pub assets_host: std::sync::OnceLock<String>,
    /// Optional local webroot for external ACME HTTP-01 challenges (e.g. `/var/www/acme`),
    /// allowing fucf to replace Caddy/nginx on port 80 cleanly.
    pub acme_webroot: std::sync::OnceLock<std::path::PathBuf>,
    /// Optional local streaming backend for `/cdn-cgi/fucf-warp` (e.g. Xray xhttp).
    pub warp_upstream: std::sync::OnceLock<warp::WarpUpstream>,
    pub kv: std::sync::OnceLock<Arc<crate::workers::kv::KvStore>>,
    pub d1: std::sync::OnceLock<Arc<crate::workers::db::D1Store>>,
    /// Configured node name (for `LocalProxyRule.nodes` matching).
    pub node_name: std::sync::OnceLock<String>,
    /// True when this node runs in `--role accelerate` mode.
    pub accelerate: std::sync::atomic::AtomicBool,
    /// Explicitly trust `X-Forwarded-Host` from the local HTTP/3 front.
    pub trust_forwarded_host: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub allow_subrequest_loopback: std::sync::atomic::AtomicBool,
    /// Origin addresses that recently refused connections or timed out.
    down: std::sync::Mutex<std::collections::HashMap<String, Instant>>,
    rr: AtomicUsize,
}

struct IdleTimeoutIo<S> {
    inner: S,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
    timeout: Duration,
}

impl<S> IdleTimeoutIo<S> {
    fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep(timeout)),
            timeout,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleTimeoutIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    let next = tokio::time::Instant::now() + self.timeout;
                    self.deadline.as_mut().reset(next);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => {
                if std::future::Future::poll(self.deadline.as_mut(), cx).is_ready() {
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "websocket idle timeout",
                    )))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleTimeoutIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => {
                if n > 0 {
                    let next = tokio::time::Instant::now() + self.timeout;
                    self.deadline.as_mut().reset(next);
                }
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn copy_bidirectional_idle<A, B>(
    a: &mut A,
    b: &mut B,
    timeout: Duration,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut a_idle = IdleTimeoutIo::new(a, timeout);
    let mut b_idle = IdleTimeoutIo::new(b, timeout);
    tokio::io::copy_bidirectional(&mut a_idle, &mut b_idle).await
}

pub(crate) async fn open_upstream_websocket(
    edge: &Edge,
    ip: IpAddr,
    ssl: bool,
    listener: Option<&proxy::ListenerInfo>,
    req_parts: &hyper::http::request::Parts,
) -> Result<(HeaderMap, hyper::upgrade::Upgraded), EdgeError> {
    let raw_host = req_parts
        .uri
        .host()
        .map(str::to_string)
        .or_else(|| req_parts.headers.get(header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string))
        .ok_or_else(|| EdgeError::new(400, "Bad request", "missing Host header"))?;
    let host = request_host(&raw_host);

    let hops: u8 = req_parts
        .headers
        .get("fucf-loop")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if hops >= 4 {
        return Err(EdgeError::new(508, "Loop detected", "maximum internal forwarding hops exceeded"));
    }
    if edge.accelerate.load(Ordering::Relaxed)
        && !accelerate_allows(edge, &edge.store.snapshot(), &host, req_parts.uri.path(), req_parts.extensions.get::<proxy::ListenerInfo>())
    {
        return Err(EdgeError::new(403, "Forbidden", "host is not in this accelerate node's allowlist"));
    }

    let snap = edge.store.snapshot();
    let node_name = edge.node_name.get().map(String::as_str);
    let path = req_parts.uri.path();
    let pq = req_parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");

    let mut headers = req_parts.headers.clone();
    strip_hop_by_hop(&mut headers);
    headers.remove(header::HOST);
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    if !headers.contains_key("sec-websocket-key") {
        headers.insert("sec-websocket-key", HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="));
    }
    if !headers.contains_key("sec-websocket-version") {
        headers.insert("sec-websocket-version", HeaderValue::from_static("13"));
    }
    if let Ok(v) = HeaderValue::from_str(&(hops.saturating_add(1)).to_string()) {
        headers.insert("fucf-loop", v);
    }
    if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
        headers.insert("x-forwarded-for", v);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static(if ssl { "https" } else { "http" }));

    let (target, upstream_pq) = if let Some(rule) = proxy::match_rule(&snap.local_proxy_rules, node_name, listener, &host, path)
        .or_else(|| proxy::match_fallback(&snap.local_proxy_rules, node_name, listener, &host, path))
    {
        let up = rule.upstreams.first().ok_or_else(|| EdgeError::origin(502, ORIGIN_NOT_CONFIGURED, "no upstream available"))?;
        let (mut target, base_path) = upstream::Target::from_proxy_url(&up.url, up.tls_insecure)
            .map_err(|e| EdgeError::origin(502, ORIGIN_MISCONFIGURED, e))?;
        if rule.preserve_host {
            target.host_header = raw_host;
        }
        let joined = if base_path.is_empty() {
            pq.to_string()
        } else if pq == "/" {
            base_path
        } else {
            format!("{base_path}{pq}")
        };
        (target, joined)
    } else if let Some(zone) = snap.find_zone(&host).filter(|z| Edge::serves(z, &host)) {
        let info = ReqInfo {
            ip: Some(ip),
            ssl,
            method: "GET".into(),
            host: host.clone(),
            path: path.to_string(),
            query: req_parts.uri.query().unwrap_or("").to_string(),
            headers: header_pairs(&req_parts.headers),
            ..Default::default()
        };
        let target = edge.resolve_target(&snap, zone, &info)?;
        (target, pq.to_string())
    } else {
        return Err(EdgeError::new(404, "Unknown host", "this host name is not proxied by this edge"));
    };

    let uri: hyper::Uri = upstream_pq
        .parse()
        .map_err(|_| EdgeError::new(400, "Bad request", "invalid request URI"))?;
    let mut out_req = Request::new(full(Bytes::new()));
    *out_req.method_mut() = Method::GET;
    *out_req.uri_mut() = uri;
    *out_req.headers_mut() = headers;

    let mut resp = edge.upstream.send(&target, out_req).await?;
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(EdgeError::origin(502, ORIGIN_BAD_RESPONSE, "upstream rejected WebSocket upgrade"));
    }
    let ws_headers = resp.headers().clone();
    let origin_ws = hyper::upgrade::on(&mut resp)
        .await
        .map_err(|e| EdgeError::origin(502, ORIGIN_BAD_RESPONSE, format!("websocket upgrade failed: {e}")))?;
    Ok((ws_headers, origin_ws))
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers.iter().map(|(n, v)| (n.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect()
}

fn is_addr(rtype: &str) -> bool {
    rtype == "A" || rtype == "AAAA"
}

impl Edge {
    pub fn new(store: Arc<Store>, cache: Arc<Cache>, waf: Arc<Waf>, edge_ips: Vec<IpAddr>) -> anyhow::Result<Self> {
        Ok(Edge {
            store,
            cache,
            waf,
            upstream: Upstream::new()?,
            edge_ips,
            alt_svc: Default::default(),
            front: Default::default(),
            panel: Default::default(),
            internal_listeners: Default::default(),
            geo: Default::default(),
            stats: Default::default(),
            limits: Default::default(),
            gfw: Default::default(),
            assets_host: Default::default(),
            acme_webroot: Default::default(),
            warp_upstream: Default::default(),
            kv: Default::default(),
            d1: Default::default(),
            node_name: Default::default(),
            accelerate: std::sync::atomic::AtomicBool::new(false),
            trust_forwarded_host: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            allow_subrequest_loopback: std::sync::atomic::AtomicBool::new(false),
            down: Default::default(),
            rr: AtomicUsize::new(0),
        })
    }

    /// Is `host` a proxied name of this zone?
    fn serves(zone: &ZoneSnap, host: &str) -> bool {
        zone.records_for(host).iter().any(|r| r.proxied)
    }

    /// Decide where a request goes: DNS record, then origin rule overrides.
    pub fn resolve_target(&self, snap: &Snapshot, zone: &ZoneSnap, info: &ReqInfo) -> Result<Target, EdgeError> {
        let (mut host_header, mut sni, mut origin_host, mut origin_node, mut port, mut scheme) =
            (None, None, None, None, None, None);
        for (rule, expr) in &zone.origin_rules {
            if expr.matches(info) {
                // rules are in priority order: the first one to set a field wins
                host_header = host_header.or(rule.host_header.clone());
                sni = sni.or(rule.sni.clone());
                origin_host = origin_host.or(rule.origin_host.clone());
                origin_node = origin_node.or(rule.origin_node.clone());
                port = port.or(rule.origin_port);
                scheme = scheme.or(rule.origin_scheme.clone());
            }
        }

        // Rotate through the addresses; ones that failed recently go last.
        let order = |addrs: Vec<&str>| -> Vec<String> {
            let start = self.rr.fetch_add(1, Ordering::Relaxed);
            let (down, now) = (self.down.lock().unwrap(), Instant::now());
            let mut list: Vec<String> = (0..addrs.len()).map(|i| addrs[(start + i) % addrs.len()].to_string()).collect();
            list.sort_by_key(|h| down.get(h).is_some_and(|until| *until > now));
            list
        };
        let records: Vec<&crate::store::Record> = zone.records_for(&info.host).iter().filter(|r| r.proxied).collect();
        // The origin options of the record the origin is taken from. A rule
        // that names another origin leaves them behind: they describe how to
        // talk to what the record points at.
        let mut options: Option<&crate::store::RecordOrigin> = None;
        if origin_node.is_none() && origin_host.is_none() {
            options = records.iter().find_map(|r| r.origin.as_ref());
            origin_node = options.and_then(|o| o.node.clone());
        }

        let (host, candidates) = if let Some(target_node) = origin_node {
            let me = crate::fleet::self_name(&self.store, &self.edge_ips, self.node_name.get().map(String::as_str));
            if target_node.eq_ignore_ascii_case(&me) {
                ("127.0.0.1".to_string(), Vec::new())
            } else {
                let node = snap
                    .nodes
                    .iter()
                    .find(|n| n.name.eq_ignore_ascii_case(&target_node))
                    .ok_or_else(|| {
                        EdgeError::origin(530, ORIGIN_MISCONFIGURED, format!("origin_node '{target_node}' not found"))
                            .hint("记录指定的回源节点不在节点列表里：在回源设置里改成存在的节点，或清空回源节点。")
                    })?;
                let mut ips = Vec::new();
                if let Some(v4) = node.ipv4 {
                    ips.push(v4.to_string());
                }
                if let Some(v6) = node.ipv6 {
                    ips.push(v6.to_string());
                }
                if ips.is_empty() {
                    return Err(EdgeError::origin(530, ORIGIN_MISCONFIGURED, format!("origin_node '{target_node}' has no IP"))
                        .hint("记录指定的回源节点没有登记 IPv4/IPv6 地址：在“节点”里补上它的地址。"));
                }
                let primary = ips.remove(0);
                (primary, ips)
            }
        } else {
            let mut candidates = match origin_host {
                Some(h) => vec![h],
                None => {
                    let addrs: Vec<&str> =
                        records.iter().filter(|r| is_addr(&r.rtype)).map(|r| r.content.as_str()).collect();
                    if !addrs.is_empty() {
                        let mut list = order(addrs);
                        let of = |addr: &str| records.iter().find(|r| is_addr(&r.rtype) && r.content == addr).and_then(|r| r.origin.as_ref());
                        options = of(&list[0]);
                        // an address that is reached differently is no stand-in for this one
                        list.retain(|addr| of(addr) == options);
                        list
                    } else {
                        // CNAME: follow it through zones we host, else leave it to system DNS.
                        let cname = records
                            .iter()
                            .find(|r| r.rtype == "CNAME")
                            .ok_or_else(|| EdgeError::origin(530, ORIGIN_NOT_CONFIGURED, "no origin configured for this host"))?;
                        options = cname.origin.as_ref();
                        let mut name = cname.content.clone();
                        let mut resolved = None;
                        for _ in 0..8 {
                            let Some(z) = snap.find_zone(&name) else { break };
                            let recs = z.records_for(&name);
                            let addrs: Vec<&str> =
                                recs.iter().filter(|r| is_addr(&r.rtype)).map(|r| r.content.as_str()).collect();
                            if !addrs.is_empty() {
                                resolved = Some(order(addrs));
                                break;
                            }
                            match recs.iter().find(|r| r.rtype == "CNAME") {
                                Some(c) => name = c.content.clone(),
                                None => {
                                    return Err(EdgeError::origin(
                                        530,
                                        ORIGIN_UNRESOLVED,
                                        format!("CNAME target {name} has no address"),
                                    ))
                                }
                            }
                        }
                        resolved.unwrap_or_else(|| vec![name])
                    }
                }
            };
            let host = candidates.remove(0);
            if host.parse::<IpAddr>().is_ok_and(|ip| self.edge_ips.contains(&ip)) {
                return Err(EdgeError::origin(530, ORIGIN_MISCONFIGURED, format!("the origin {host} is this edge node's own address"))
                    .hint(HINT_ORIGIN_IS_EDGE));
            }
            (host, candidates)
        };

        // What the rules did not decide, the record may: a server name to
        // present means TLS, unless the record says otherwise.
        if let Some(options) = options {
            host_header = host_header.or(options.host_header.clone());
            sni = sni.or(options.sni.clone());
            port = port.or(options.port);
            scheme = scheme.or(options.scheme.clone()).or(options.sni.as_ref().map(|_| "https".to_string()));
        }
        let ssl_mode = zone.zone.settings.ssl.as_str();
        let https = match scheme.as_deref() {
            Some(s) => s == "https",
            None => ssl_mode != "flexible",
        };
        let host_header = host_header.unwrap_or_else(|| info.host.clone());
        Ok(Target {
            host,
            alternates: candidates,
            port: port.unwrap_or(if https { 443 } else { 80 }),
            tls: match (https, ssl_mode) {
                (false, _) => Tls::Off,
                (true, "strict") => Tls::Verify,
                (true, _) => Tls::NoVerify,
            },
            sni: sni.unwrap_or_else(|| host_header.clone()),
            host_header,
            h2: false,
            block_private_ips: false,
        })
    }

    /// Serve from cache or pull from the origin (no WAF, no workers).
    pub async fn fetch(&self, snap: &Snapshot, zone: &ZoneSnap, out: Outgoing) -> Result<Response<Body>, EdgeError> {
        let Outgoing { info, mut headers, body, on_upgrade, grpc } = out;
        let method = Method::from_bytes(info.method.as_bytes())
            .map_err(|_| EdgeError::new(400, "Bad request", "invalid method"))?;
        let uri = info.uri();
        let settings = &zone.zone.settings;
        let rule = zone.cache_rules.iter().find(|(_, e)| e.matches(&info)).map(|(r, _)| r);
        let (force, ttl_override) = (rule.is_some_and(|r| r.cache), rule.and_then(|r| r.edge_ttl).map(u64::from));
        let eligible = !zone.zone.paused && !settings.development_mode && cache::request_cacheable(&method, &headers);
        let use_cache = eligible && rule.is_none_or(|r| r.cache);
        let key = cache::cache_key(info.ssl, &info.host, &uri, &headers);
        let conditional = Conditional::of(&headers);

        let mut status_label = if eligible && !use_cache { "BYPASS" } else { "DYNAMIC" };
        // `stale`: our expired copy, to revalidate. `fallback`: served if the origin fails.
        let (mut stale, mut fallback) = (None, None);
        // May what the origin answers be stored?
        let mut storable = use_cache;
        if use_cache {
            match self.cache.get(&key) {
                Some(entry) if entry.fresh() => return Ok(cached_response(&entry, &method, &conditional, "HIT")),
                // A part is cut from what we have; otherwise the request goes
                // to the origin as it is, and its partial answer is not kept.
                _ if conditional.range.is_some() => storable = false,
                Some(entry) => {
                    status_label = "EXPIRED";
                    fallback = Some(entry.clone()).filter(|e| e.stored.elapsed() < e.ttl + cache::STALE_IF_ERROR);
                    stale = Some(entry).filter(|e| e.has_validator());
                }
                None => status_label = "MISS",
            }
        }

        let mut target = self.resolve_target(snap, zone, &info)?;
        target.h2 = grpc;

        // Build the origin request.
        let upgrade = headers.get(header::UPGRADE).cloned().filter(|_| on_upgrade.is_some());
        strip_hop_by_hop(&mut headers);
        headers.remove(header::HOST);
        if grpc {
            // "I can take trailers": where a gRPC server puts the status of a call
            headers.insert(header::TE, HeaderValue::from_static("trailers"));
        }
        if let Some(proto) = &upgrade {
            headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            headers.insert(header::UPGRADE, proto.clone());
        }
        if let Some(ip) = info.ip {
            let ip = ip.to_string();
            let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                Some(prev) => format!("{prev}, {ip}"),
                None => ip.clone(),
            };
            for (name, value) in [("x-forwarded-for", xff), ("cf-connecting-ip", ip)] {
                if let Ok(v) = HeaderValue::from_str(&value) {
                    headers.insert(name, v);
                }
            }
        }
        let hops: u8 = headers
            .get("fucf-loop")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if let Ok(v) = HeaderValue::from_str(&(hops.saturating_add(1)).to_string()) {
            headers.insert("fucf-loop", v);
        }
        // The visitor's country as the edge sees it, never as the client claims.
        headers.remove("cf-ipcountry");
        if let Some(country) = HeaderValue::from_str(&info.country).ok().filter(|v| !v.is_empty()) {
            headers.insert("cf-ipcountry", country);
        }
        headers.insert("x-forwarded-proto", HeaderValue::from_static(if info.ssl { "https" } else { "http" }));
        headers.append("cdn-loop", HeaderValue::from_static(LOOP_TOKEN));
        if let Some(entry) = &stale {
            // Revalidate our stale copy instead of downloading it again.
            headers.remove(header::IF_NONE_MATCH);
            headers.remove(header::IF_MODIFIED_SINCE);
            if let Some(etag) = entry.headers.get(header::ETAG) {
                headers.insert(header::IF_NONE_MATCH, etag.clone());
            } else if let Some(modified) = entry.headers.get(header::LAST_MODIFIED) {
                headers.insert(header::IF_MODIFIED_SINCE, modified.clone());
            }
        }
        let origin_uri: hyper::Uri =
            uri.parse().map_err(|_| EdgeError::new(400, "Bad request", "invalid request URI"))?;

        // Try the origin's addresses in turn. A request is only re-sent when
        // nothing was listening (so it cannot have been processed) and its
        // body is still available.
        let mut hosts: Vec<String> = std::iter::once(&target.host).chain(&target.alternates).take(3).cloned().collect();
        hosts.reverse();
        let mut body = Some(body);
        let outcome = loop {
            let Some(host) = hosts.pop() else {
                break Err(EdgeError::origin(530, ORIGIN_NOT_CONFIGURED, "no origin available"));
            };
            let replayable = matches!(body, Some(ReqBody::Buffered(_)));
            let attempt_body = if let Some(ReqBody::Buffered(b)) = &body {
                full(b.clone())
            } else {
                body.take().map(ReqBody::into_body).unwrap_or_else(|| full(Bytes::new()))
            };
            let mut req = Request::new(attempt_body);
            *req.method_mut() = method.clone();
            *req.uri_mut() = origin_uri.clone();
            *req.headers_mut() = headers.clone();
            let attempt = Target { host: host.clone(), ..target.clone() };
            let last = hosts.is_empty();
            match self.upstream.send(&attempt, req).await {
                Ok(resp) => break Ok(resp),
                Err(e) => {
                    if matches!(e, UpstreamError::Down(_) | UpstreamError::Timeout) {
                        self.down.lock().unwrap().insert(host, Instant::now() + ORIGIN_COOLDOWN);
                    }
                    if !(matches!(e, UpstreamError::Down(_)) && replayable && !last) {
                        break Err(EdgeError::from(e));
                    }
                }
            }
        };
        // The origin is unreachable or broken: an expired copy beats an error page.
        let failed = match &outcome {
            Ok(resp) => matches!(resp.status().as_u16(), 500 | 502 | 503 | 504),
            Err(_) => true,
        };
        if let Some(entry) = fallback.filter(|_| failed) {
            return Ok(cached_response(&entry, &method, &conditional, "STALE"));
        }
        let mut resp = outcome?;

        // WebSocket and other protocol upgrades: splice the two connections.
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(client_side) = on_upgrade else {
                return Err(EdgeError::origin(502, ORIGIN_BAD_RESPONSE, "unexpected protocol switch by the origin"));
            };
            let origin_side = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(c), Ok(o)) = tokio::join!(client_side, origin_side) {
                    let _ = copy_bidirectional_idle(&mut TokioIo::new(c), &mut TokioIo::new(o), Duration::from_secs(300)).await;
                }
            });
            let (parts, _) = resp.into_parts();
            let mut out = Response::new(full(Bytes::new()));
            *out.status_mut() = parts.status;
            *out.headers_mut() = parts.headers;
            return Ok(out);
        }

        // The origin confirmed our stale copy: renew it and serve it.
        if let (StatusCode::NOT_MODIFIED, Some(entry)) = (resp.status(), &stale) {
            let mut merged = entry.headers.clone();
            for name in [header::CACHE_CONTROL, header::EXPIRES, header::ETAG, header::LAST_MODIFIED, header::DATE] {
                if let Some(v) = resp.headers().get(&name) {
                    merged.insert(name, v.clone());
                }
            }
            let ttl = match cache::decide(&info.path, entry.status, &merged, force, ttl_override) {
                Decision::Store(ttl) => ttl,
                _ => entry.ttl,
            };
            let renewed = cache::Entry {
                status: entry.status,
                headers: merged,
                body: entry.body.clone(),
                stored: Instant::now(),
                ttl,
                zone_id: entry.zone_id.clone(),
                url: entry.url.clone(),
            };
            let out = cached_response(&renewed, &method, &conditional, "REVALIDATED");
            self.cache.put(key, renewed);
            return Ok(out);
        }

        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let decision = if storable {
            cache::decide(&info.path, parts.status, &parts.headers, force, ttl_override)
        } else {
            Decision::Dynamic
        };
        let length = parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        let unreadable = |e: BoxError| EdgeError::origin(502, ORIGIN_BAD_RESPONSE, format!("reading origin response: {e}"));

        // Read what is to be stored: a body of announced length entirely, one
        // of unknown length (chunked) as far as the limit allows.
        let (whole, body) = match (&decision, length) {
            (Decision::Store(_), Some(len)) if method == Method::GET && len <= cache::MAX_OBJECT => {
                (Some(Limited::new(body, len as usize).collect().await.map_err(unreadable)?.to_bytes()), None)
            }
            (Decision::Store(_), None) if method == Method::GET => match read_up_to(body, cache::MAX_UNSIZED).await.map_err(unreadable)? {
                (chunks, None) => (Some(Bytes::from(chunks.concat())), None),
                (chunks, Some(rest)) => (None, Some(Prefixed { head: chunks.into(), rest }.boxed())),
                },
            _ => (None, Some(streaming(body))),
        };
        let body = match (whole, &decision) {
            (Some(data), Decision::Store(ttl)) => {
                parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(data.len()));
                self.cache.put(
                    key,
                    cache::Entry {
                        status: parts.status,
                        headers: parts.headers.clone(),
                        body: data.clone(),
                        stored: Instant::now(),
                        ttl: *ttl,
                        zone_id: zone.zone.id.clone(),
                        url: format!("{}{}", info.host, uri),
                    },
                );
                full(data)
            }
            (_, _) => body.unwrap_or_else(|| full(Bytes::new())),
        };
        let label = match decision {
            Decision::Store(_) => status_label,
            Decision::Bypass => "BYPASS",
            Decision::Dynamic => status_label_for_uncached(status_label),
        };
        let mut out = Response::from_parts(parts, body);
        out.headers_mut().insert("cf-cache-status", HeaderValue::from_static(label));
        Ok(out)
    }

    /// `fetch()` as seen by a worker: hosts served by this edge go through
    /// cache and origin selection, anything else is fetched directly.
    pub async fn subrequest(
        &self,
        snap: &Snapshot,
        parent: &ReqInfo,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<(u16, Vec<(String, String)>, Bytes), String> {
        let uri: hyper::Uri = url.parse().map_err(|e| format!("invalid URL '{url}': {e}"))?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(format!("unsupported URL '{url}': only http(s) is allowed")),
        };
        let host = uri.host().unwrap_or_default().to_ascii_lowercase();
        let mut map = HeaderMap::new();
        for (n, v) in &headers {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(n.as_bytes()), HeaderValue::from_str(v)) {
                map.append(n, v);
            }
        }
        map.remove(header::CONTENT_LENGTH);
        let info = ReqInfo {
            ip: parent.ip,
            ssl: https,
            method: method.to_ascii_uppercase(),
            host: host.clone(),
            path: uri.path().to_string(),
            query: uri.query().unwrap_or("").to_string(),
            headers: headers.clone(),
            ..Default::default()
        };

        let resp = match snap.find_zone(&host).filter(|z| Self::serves(z, &host)) {
            Some(zone) => {
                let out = Outgoing { info, headers: map, body: ReqBody::Buffered(body), on_upgrade: None, grpc: false };
                self.fetch(snap, zone, out).await.map_err(|e| format!("{} {}: {}", e.status, e.title, e.detail))?
            }
            None => {
                let authority = uri.authority().map(|a| a.as_str().to_string()).unwrap_or_default();
                let target_host = host.trim_start_matches('[').trim_end_matches(']').to_string();
                let target_port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
                let is_local = target_host == "localhost"
                    || target_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
                if is_local
                    && self
                        .internal_listeners
                        .get()
                        .is_some_and(|list| list.iter().any(|a| a.port() == target_port))
                {
                    return Err("refusing to fetch this node's internal management or front listener".into());
                }
                #[cfg(test)]
                let block_private_ips = !self.allow_subrequest_loopback.load(std::sync::atomic::Ordering::Relaxed);
                #[cfg(not(test))]
                let block_private_ips = true;
                let target = Target {
                    host: target_host,
                    alternates: Vec::new(),
                    port: target_port,
                    tls: if https { Tls::Verify } else { Tls::Off },
                    sni: host.clone(),
                    host_header: authority,
                    h2: false,
                    block_private_ips,
                };
                strip_hop_by_hop(&mut map);
                map.append("cdn-loop", HeaderValue::from_static(LOOP_TOKEN));
                let mut req = Request::new(full(body));
                *req.method_mut() =
                    Method::from_bytes(info.method.as_bytes()).map_err(|_| "invalid method".to_string())?;
                *req.uri_mut() = info.uri().parse().map_err(|_| "invalid URL path".to_string())?;
                *req.headers_mut() = map;
                let resp = self.upstream.send(&target, req).await.map_err(|e| format!("fetch failed: {e:?}"))?;
                let (mut parts, body) = resp.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                Response::from_parts(parts, streaming(body))
            }
        };
        let (parts, body) = resp.into_parts();
        let data = collect_limited(body, WORKER_BODY_LIMIT).await.map_err(|e| format!("reading response body: {e}"))?;
        Ok((parts.status.as_u16(), header_pairs(&parts.headers), data))
    }

    /// The full pipeline for one client request.
    async fn process(
        self: Arc<Self>,
        ip: IpAddr,
        ssl: bool,
        mut req: Request<Body>,
        ray: &str,
        seen: &mut Option<Seen>,
    ) -> Result<Response<Body>, EdgeError> {
        let host = req
            .uri()
            .host()
            .map(str::to_string)
            .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string))
            .ok_or_else(|| EdgeError::new(400, "Bad request", "missing Host header"))?;
        let host = request_host(&host);

        // This node proving a name of its own (automatic HTTPS): whatever the
        // node's role or rules, the CA has to get its answer.
        if let Some(answer) = req.uri().path().strip_prefix("/.well-known/acme-challenge/").and_then(crate::site_acme::http01) {
            let mut resp = Response::new(full(answer));
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            return Ok(resp);
        }

        let looped = req.headers().get_all("cdn-loop").iter().any(|v| v.to_str().is_ok_and(|v| v.contains(LOOP_TOKEN)));
        if looped {
            return Err(EdgeError::new(508, "Loop detected", "this request already passed through this edge"));
        }
        const MAX_FUCF_HOPS: u8 = 4;
        let hops: u8 = req
            .headers()
            .get("fucf-loop")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if hops >= MAX_FUCF_HOPS {
            return Err(EdgeError::new(508, "Loop detected", "maximum internal forwarding hops exceeded"));
        }

        if self.accelerate.load(Ordering::Relaxed)
            && !accelerate_allows(&self, &self.store.snapshot(), &host, req.uri().path(), req.extensions().get::<proxy::ListenerInfo>())
        {
            return Err(EdgeError::new(403, "Forbidden", "host is not in this accelerate node's allowlist"));
        }

        // HTTP/2 WebSocket Extended CONNECT (RFC 8441)
        if req.method() == Method::CONNECT
            && req
                .extensions()
                .get::<hyper::ext::Protocol>()
                .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket"))
        {
            let client_upgrade = hyper::upgrade::on(&mut req);
            let (parts, _) = req.into_parts();
            let (ws_headers, origin_ws) = open_upstream_websocket(
                &self,
                ip,
                ssl,
                parts.extensions.get::<proxy::ListenerInfo>(),
                &parts,
            )
            .await?;
            tokio::spawn(async move {
                if let Ok(client_ws) = client_upgrade.await {
                    let _ = copy_bidirectional_idle(
                        &mut TokioIo::new(client_ws),
                        &mut TokioIo::new(origin_ws),
                        Duration::from_secs(300),
                    )
                    .await;
                }
            });
            let mut resp = Response::new(full(Bytes::new()));
            *resp.status_mut() = StatusCode::OK;
            if let Some(proto) = ws_headers.get("sec-websocket-protocol") {
                resp.headers_mut().insert("sec-websocket-protocol", proto.clone());
            }
            return Ok(resp);
        }

        // A CA validating an ACME HTTP-01 challenge, for whatever host.
        if let Some(token) = req.uri().path().strip_prefix("/.well-known/acme-challenge/") {
            if let Some(key_authorization) = self.store.snapshot().acme_http.get(token) {
                let mut resp = Response::new(full(key_authorization.clone()));
                resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                return Ok(resp);
            }
            let safe_token = !token.is_empty()
                && token.len() <= 128
                && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if safe_token {
                if let Some(root) = self.acme_webroot.get() {
                    let path = root.join(".well-known").join("acme-challenge").join(token);
                    if let Ok(meta) = tokio::fs::metadata(&path).await {
                        if meta.is_file() && meta.len() <= 4096 {
                            if let Ok(body) = tokio::fs::read(&path).await {
                                let mut resp = Response::new(full(body));
                                resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                                return Ok(resp);
                            }
                        }
                    }
                }
            }
        }

        // The edge's own `/cdn-cgi/*` endpoints: allow explicit LocalProxyRule
        // (per-node or global) or WorkerRoute overrides before built-in fallback.
        if let Some(endpoint) = cgi::endpoint(req.uri().path()).map(str::to_string) {
            let snap_cgi = self.store.snapshot();
            let listener_cgi = req.extensions().get::<proxy::ListenerInfo>().cloned();
            let node_name_cgi = self.node_name.get().map(String::as_str);
            if let Some(rule) = proxy::match_rule(
                &snap_cgi.local_proxy_rules,
                node_name_cgi,
                listener_cgi.as_ref(),
                &host,
                req.uri().path(),
            )
            .cloned()
            {
                return proxy::forward(&self, &rule, ip, ssl, &host, req).await;
            }
            if let Some(zone) = snap_cgi.find_zone(&host).filter(|z| Self::serves(z, &host)) {
                let path = req.uri().path().to_string();
                if let Some(route) = zone.routes.iter().find(|r| r.matches(&host, &path)) {
                    if let Some(script_name) = &route.script {
                        if let Some(script) = snap_cgi.workers.get(script_name).cloned() {
                            let query = req.uri().query().unwrap_or("").to_string();
                            let info = ReqInfo {
                                ip: Some(ip),
                                ssl,
                                method: req.method().as_str().to_string(),
                                host: host.clone(),
                                path,
                                query,
                                headers: header_pairs(req.headers()),
                                ..Default::default()
                            };
                            let (_, body) = req.into_parts();
                            let bytes = body
                                .collect()
                                .await
                                .map_err(|_| EdgeError::new(400, "Bad request", "could not read the request body"))?
                                .to_bytes();
                            return crate::workers::run(self.clone(), snap_cgi.clone(), script, info, bytes).await;
                        }
                    }
                }
            }
            return self.cdn_cgi(&endpoint, ip, ssl, req, &host, ray).await;
        }

        if let Some((_, api)) = self.panel.get().filter(|(panel_host, _)| *panel_host == host) {
            // The management panel and API: always over HTTPS (except loopback),
            // forwarded as-is to the local API.
            if !ssl && !ip.is_loopback() {
                let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
                let mut resp = Response::new(full(Bytes::new()));
                *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
                if let Ok(loc) = HeaderValue::from_str(&format!("https://{host}{path}")) {
                    resp.headers_mut().insert(header::LOCATION, loc);
                }
                return Ok(resp);
            }
            let target = Target {
                host: api.ip().to_string(),
                alternates: Vec::new(),
                port: api.port(),
                tls: Tls::Off,
                sni: String::new(),
                host_header: host.clone(),
                h2: false,
                block_private_ips: false,
            };
            strip_hop_by_hop(req.headers_mut());
            if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
                req.headers_mut().insert("x-forwarded-for", v);
            }
            let (mut parts, body) = self.upstream.send(&target, req).await?.into_parts();
            strip_hop_by_hop(&mut parts.headers);
            if ssl {
                parts.headers.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
            }
            parts.extensions.insert(OffersHttp3(host));
            return Ok(Response::from_parts(parts, streaming(body)));
        }

        let snap = self.store.snapshot();
        let internal = cgi::is_fucf_node(ip, &snap.nodes);

        // Over its traffic allowance this node serves nothing but a notice
        // (whose resources come from other nodes, see `cgi`), except for
        // internal traffic coming from our own fucf edge nodes (`warp=fucf`).
        if !internal && self.limits.state() == crate::limits::State::Limited {
            if req.version() >= hyper::Version::HTTP_2 && is_grpc(req.headers()) {
                return Err(EdgeError::new(509, "Traffic limit reached", "this edge node has used up its traffic allowance"));
            }
            let resp = crate::limits::notice(self.assets_host.get().map(String::as_str), ray);
            self.limits.add(hyper::body::Body::size_hint(resp.body()).exact().unwrap_or(0));
            return Ok(resp);
        }

        let listener = req.extensions().get::<proxy::ListenerInfo>().cloned();
        let node_name = self.node_name.get().map(String::as_str);
        if let Some(rule) = proxy::match_rule(&snap.local_proxy_rules, node_name, listener.as_ref(), &host, req.uri().path()).cloned() {
            return proxy::forward(&self, &rule, ip, ssl, &host, req).await;
        }

        let Some(zone) = snap.find_zone(&host).filter(|z| Self::serves(z, &host)) else {
            if let Some(rule) = proxy::match_fallback(&snap.local_proxy_rules, node_name, listener.as_ref(), &host, req.uri().path()).cloned() {
                return proxy::forward(&self, &rule, ip, ssl, &host, req).await;
            }
            return Err(EdgeError::new(404, "Unknown host", "this host name is not proxied by this edge"));
        };
        let settings = &zone.zone.settings;

        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let mut info = ReqInfo {
            ip: Some(ip),
            ssl,
            method: req.method().as_str().to_string(),
            host,
            path,
            query,
            headers: header_pairs(req.headers()),
            ..Default::default()
        };

        if let Some(geo) = self.geo.get() {
            let loc = geo.locate(ip);
            info.country = loc.country.unwrap_or_default();
            info.continent = loc.continent.unwrap_or_default();
            info.asn = loc.asn.unwrap_or(0) as i64;
            info.as_org = loc.as_org.unwrap_or_default();
        }
        *seen = Some(Seen {
            zone_id: zone.zone.id.clone(),
            http3: settings.http3,
            host: info.host.clone(),
            path: info.path.clone(),
            country: info.country.clone(),
        });
        if req.version() == hyper::Version::HTTP_3 && !settings.http3 {
            return Err(EdgeError::new(421, "Misdirected request", "HTTP/3 is not enabled for this site"));
        }

        if settings.always_use_https && !ssl && !zone.zone.paused {
            let mut resp = Response::new(full(Bytes::new()));
            *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
            if let Ok(loc) = HeaderValue::from_str(&format!("https://{}{}", info.host, info.uri())) {
                resp.headers_mut().insert(header::LOCATION, loc);
            }
            return Ok(resp);
        }

        let is_upgrade = req.version() == hyper::Version::HTTP_11 && req.headers().contains_key(header::UPGRADE);
        let on_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut req));
        let grpc = settings.grpc && req.version() >= hyper::Version::HTTP_2 && is_grpc(req.headers());
        let (parts, incoming) = req.into_parts();
        let declared = parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        let has_body_method = matches!(parts.method, Method::POST | Method::PUT | Method::PATCH);
        let (body, inspect_prefix) = match declared {
            // messages of a gRPC call are passed on as they come, in both directions
            _ if grpc || is_upgrade => (ReqBody::Stream(incoming), None),
            Some(0) => (ReqBody::Buffered(Bytes::new()), None),
            Some(n) if n <= INSPECT_LIMIT => {
                (ReqBody::Buffered(ReqBody::Stream(incoming).collect(INSPECT_LIMIT as usize).await?), None)
            }
            None if has_body_method && !zone.zone.paused => {
                // Chunked / unknown-length bodies still get WAF inspection up to INSPECT_LIMIT.
                match read_up_to(incoming, INSPECT_LIMIT as usize).await {
                    Ok((chunks, None)) => (ReqBody::Buffered(Bytes::from(chunks.concat())), None),
                    Ok((chunks, Some(rest))) => {
                        let prefix = Bytes::from(chunks.concat());
                        (ReqBody::Stream(Prefixed { head: chunks.into(), rest }.boxed()), Some(prefix))
                    }
                    Err(_) => return Err(EdgeError::new(400, "Bad request", "reading request body failed")),
                }
            }
            _ => (ReqBody::Stream(incoming), None),
        };

        let mut headers = parts.headers;
        let mut response_rules = Vec::new();
        let mut worker = None;
        if !zone.zone.paused {
            let inspect = match (&body, &inspect_prefix) {
                (ReqBody::Buffered(b), _) if !b.is_empty() => Some(&b[..]),
                (_, Some(p)) if !p.is_empty() => Some(&p[..]),
                _ => None,
            };
            let stopped = match self.waf.check(zone, &info, inspect, ray) {
                Verdict::Pass => None,
                Verdict::Block { rule_id } => {
                    let detail = format!("This request was blocked by the security rules of this site (rule {rule_id}).");
                    Some(page(403, "Access denied", &detail, ray, &PageCtx { hop: Hop::Edge, host: info.host.clone(), here: self.here() }))
                }
                Verdict::RateLimited { retry_after } => {
                    let ctx = PageCtx { hop: Hop::Edge, host: info.host.clone(), here: self.here() };
                    let mut resp = page(429, "Too many requests", "You are being rate limited.", ray, &ctx);
                    resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
                    Some(resp)
                }
                Verdict::Challenge { token } => Some(challenge_page(&token, ray)),
            };
            if let Some(mut resp) = stopped {
                resp.extensions_mut().insert(WafHit);
                return Ok(resp);
            }

            if let Some((rule, _)) = zone.redirects.iter().find(|(_, e)| e.matches(&info)) {
                let mut location = rule.target_url.clone();
                if rule.preserve_query_string && !info.query.is_empty() {
                    location.push(if location.contains('?') { '&' } else { '?' });
                    location.push_str(&info.query);
                }
                let mut resp = Response::new(full(Bytes::new()));
                *resp.status_mut() = StatusCode::from_u16(rule.status_code).unwrap_or(StatusCode::FOUND);
                if let Ok(v) = HeaderValue::from_str(&location) {
                    resp.headers_mut().insert(header::LOCATION, v);
                }
                return Ok(resp);
            }

            // Every matching transform rule applies; all are matched against
            // the request as the client sent it.
            let matching: Vec<_> = zone.transforms.iter().filter(|(_, e)| e.matches(&info)).map(|(r, _)| r).collect();
            for rule in &matching {
                if let Some(path) = &rule.rewrite_path {
                    info.path = path.clone();
                }
                for name in &rule.remove_request_headers {
                    headers.remove(name.as_str());
                }
                set_headers(&mut headers, &rule.set_request_headers);
            }
            if !matching.is_empty() {
                info.headers = header_pairs(&headers);
            }
            response_rules = matching;

            let route = zone.routes.iter().find(|r| r.matches(&info.host, &info.path));
            worker = route.and_then(|r| r.script.as_ref()).and_then(|name| snap.workers.get(name));
        }

        let mut resp = match worker {
            Some(script) => {
                if info.path == "/__scheduled" {
                    let q = info.query.trim_start_matches('?');
                    let cron_expr = if q.is_empty() {
                        None
                    } else {
                        q.split('&').find_map(|kv| {
                            let (k, v) = kv.split_once('=')?;
                            if k == "cron" {
                                let plus_fixed = v.replace('+', " ");
                                Some(percent_encoding::percent_decode_str(&plus_fixed).decode_utf8_lossy().into_owned())
                            } else {
                                None
                            }
                        })
                    }
                    .unwrap_or_else(|| script.crons.first().cloned().unwrap_or_else(|| "* * * * *".into()));
                    if let Err(e) = crate::workers::cron::CronExpr::parse(&cron_expr) {
                        return Err(EdgeError::new(400, "Invalid cron expression", e));
                    }
                    let ms = crate::sync::clock::unix_ms();
                    crate::workers::run_scheduled(self.clone(), snap.clone(), script.clone(), &cron_expr, ms)
                        .await
                        .map_err(|e| EdgeError::new(500, "Scheduled worker failed", e))?;
                    Response::new(full(Bytes::from_static(b"ok")))
                } else {
                    let body = body.collect(WORKER_BODY_LIMIT).await?;
                    crate::workers::run(self.clone(), snap.clone(), script.clone(), info, body).await?
                }
            }
            None => self.fetch(&snap, zone, Outgoing { info, headers, body, on_upgrade, grpc }).await?,
        };
        // What the zone's settings add to an answer (rules may still change it).
        if ssl && settings.hsts_max_age > 0 {
            let subdomains = if settings.hsts_include_subdomains { "; includeSubDomains" } else { "" };
            if let Ok(v) = HeaderValue::from_str(&format!("max-age={}{subdomains}", settings.hsts_max_age)) {
                resp.headers_mut().insert(header::STRICT_TRANSPORT_SECURITY, v);
            }
        }
        let browser_ttl = u64::from(settings.browser_cache_ttl);
        let cacheable = resp.headers().get("cf-cache-status").is_some_and(|label| label != "DYNAMIC" && label != "BYPASS")
            && matches!(resp.status().as_u16(), 200 | 206 | 304);
        if browser_ttl > 0 && cacheable && cache::max_age(resp.headers()).is_none_or(|given| given < browser_ttl) {
            if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={browser_ttl}")) {
                resp.headers_mut().insert(header::CACHE_CONTROL, v);
                resp.headers_mut().remove(header::EXPIRES);
            }
        }
        for rule in response_rules {
            for name in &rule.remove_response_headers {
                resp.headers_mut().remove(name.as_str());
            }
            set_headers(resp.headers_mut(), &rule.set_response_headers);
        }
        Ok(resp)
    }
}

/// Run the pipeline and stamp the edge's own response headers.
pub async fn respond(edge: Arc<Edge>, peer: SocketAddr, ssl: bool, req: Request<Body>) -> Response<Body> {
    let ray = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
    let started = Instant::now();
    let line = format!("{:?} {} {}", req.version(), req.method(), req.uri());
    // through the HTTP/3 front, HTTP/3 is what the visitor spoke
    let version = if req.extensions().get::<front::ViaFront>().is_some() { hyper::Version::HTTP_3 } else { req.version() };
    let head = req.method() == Method::HEAD;
    let accept = req.headers().get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).map(String::from);
    let grpc = req.version() >= hyper::Version::HTTP_2 && is_grpc(req.headers());
    // for the error page: the name the visitor asked for, if it is a sane one
    let asked_host = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string))
        .map(|h| request_host(&h))
        .filter(|h| h.len() <= 253 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b)))
        .unwrap_or_default();
    let mut seen = None;
    // `refusal`: why the edge answered by itself instead of passing on the origin's answer
    let (resp, refusal) = match edge.clone().process(peer.ip().to_canonical(), ssl, req, &ray, &mut seen).await {
        Ok(r) => {
            let by_waf = r.extensions().get::<WafHit>().map(|_| match r.status() {
                StatusCode::TOO_MANY_REQUESTS => "rate limited by the edge".to_string(),
                _ => "refused by the security rules of this site".to_string(),
            });
            (r, by_waf)
        }
        Err(e) => {
            let public = e.public_detail();
            if let Some(fault) = e.origin {
                // the whole story (origin addresses included) is for the log and the dashboard only
                let host = seen.as_ref().map(|s| s.host.as_str()).unwrap_or("-");
                tracing::warn!(%ray, host, status = e.status, client = %peer.ip(), "origin error: {}", e.detail);
                if let Some(s) = &seen {
                    edge.waf.origin_error(&s.zone_id, &ray, e.status, fault.reason, fault.hint, &s.host, &line, peer.ip().to_canonical(), &s.country);
                }
            }
            let host = seen.as_ref().map(|s| s.host.clone()).unwrap_or(asked_host);
            let ctx = PageCtx { hop: e.hop(), host, here: edge.here() };
            (page(e.status, e.title, &public, &ray, &ctx), Some(e.public_line()))
        }
    };
    // HTTP/3 is on offer where it works: through the front for the names its
    // certificate covers, else on our own QUIC listener. For the sites of a
    // zone that has it switched on, and for the panel.
    let offered = match &seen {
        Some(s) => Some(s.host.clone()).filter(|_| s.http3),
        None => resp.extensions().get::<OffersHttp3>().map(|panel| panel.0.clone()),
    };
    let is_v6 = peer.ip().to_canonical().is_ipv6();
    let cn_udp_blocked = seen.as_ref().is_some_and(|s| s.country == "CN") && edge.gfw.get().is_blocked(is_v6, true);
    let alt_svc = offered.filter(|_| ssl && !cn_udp_blocked).and_then(|host| {
        edge.front.get().and_then(|front| front.alt_svc(&host)).or_else(|| edge.alt_svc.get().cloned())
    });
    let page_host = seen.as_ref().map(|s| s.host.clone()).unwrap_or_default();
    let mut resp = compress::apply(accept, head, resp, || PageCtx { hop: Hop::Origin, host: page_host, here: edge.here() }).await;
    let internal = cgi::is_fucf_node(peer.ip().to_canonical(), &edge.store.snapshot().nodes);
    let is_cdn = seen.is_some();
    if let Some(seen) = seen {
        edge.stats.record(stats::Sample {
            zone_id: &seen.zone_id,
            version,
            status: resp.status().as_u16(),
            cache: resp.headers().get("cf-cache-status").and_then(|v| v.to_str().ok()),
            threat: resp.extensions().get::<WafHit>().is_some(),
            bytes: 0, // booked by `Metered` as the body is actually sent
            country: &seen.country,
            host: &seen.host,
            path: &seen.path,
        });
        let limits = (!internal).then(|| edge.limits.clone());
        resp = resp.map(|inner| Metered { inner, sent: 0, stats: edge.stats.clone(), limits, zone_id: seen.zone_id }.boxed());
    }
    tracing::debug!(%ray, client = %peer.ip(), status = resp.status().as_u16(), ms = started.elapsed().as_millis() as u64, "{line}");
    if let Some(reason) = refusal.filter(|_| grpc) {
        // a gRPC client cannot read an error page: tell it in its own terms
        resp = grpc_error(resp.status(), &reason);
    }
    if is_cdn && !internal && edge.limits.throttled() {
        let limits = edge.limits.clone();
        resp = resp.map(|inner| Throttled { inner, limits, held: Bytes::new(), wait: None }.boxed());
    }
    resp.headers_mut().insert(header::SERVER, HeaderValue::from_static("fucf"));
    if let Ok(v) = HeaderValue::from_str(&ray) {
        resp.headers_mut().insert("fucf-ray", v);
    }
    // An origin's Alt-Svc is about the origin's own endpoints (it may sit
    // behind another CDN): visitors must not be sent looking for those here.
    resp.headers_mut().remove(header::ALT_SVC);
    if let Some(alt) = alt_svc {
        resp.headers_mut().insert(header::ALT_SVC, alt);
    }
    resp
}

async fn handle(
    edge: Arc<Edge>,
    peer: SocketAddr,
    tls: Option<TlsInfo>,
    listener_info: Option<proxy::ListenerInfo>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let (ssl, mut req) = (tls.is_some(), req.map(streaming));
    if let Some(tls) = tls {
        req.extensions_mut().insert(tls);
    }
    if let Some(info) = listener_info {
        req.extensions_mut().insert(info);
    }
    Ok(respond(edge, peer, ssl, req).await)
}

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Bounds initial `ReadVersion` / HTTP/2 preface reads so slowloris TCP or TLS
/// clients cannot hold connection semaphore permits indefinitely.
struct InitialTimeoutIo<IO> {
    inner: IO,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
    armed: bool,
    pos: usize,
}

impl<IO> InitialTimeoutIo<IO> {
    fn new(inner: IO, timeout: Duration) -> Self {
        InitialTimeoutIo {
            inner,
            sleep: Box::pin(tokio::time::sleep(timeout)),
            armed: true,
            pos: 0,
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for InitialTimeoutIo<IO> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::future::Future;
        use std::task::Poll;
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let newly = &buf.filled()[before..];
                if self.armed && !newly.is_empty() {
                    for &b in newly {
                        if self.pos < H2_PREFACE.len() && b == H2_PREFACE[self.pos] {
                            self.pos += 1;
                            if self.pos >= H2_PREFACE.len() {
                                self.armed = false;
                                break;
                            }
                        } else {
                            // Not HTTP/2 preface: http1 header_read_timeout takes over.
                            self.armed = false;
                            break;
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if self.armed && self.sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "initial HTTP version/preface read timed out",
                    )));
                }
                Poll::Pending
            }
        }
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for InitialTimeoutIo<IO> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn serve_conn<IO>(
    io: IO,
    peer: SocketAddr,
    tls: Option<TlsInfo>,
    alpn_h2: bool,
    listener_info: Option<proxy::ListenerInfo>,
    edge: Arc<Edge>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_conn_with_timeout(io, peer, tls, alpn_h2, listener_info, edge, Duration::from_secs(15)).await;
}

async fn serve_conn_with_timeout<IO>(
    io: IO,
    peer: SocketAddr,
    tls: Option<TlsInfo>,
    alpn_h2: bool,
    listener_info: Option<proxy::ListenerInfo>,
    edge: Arc<Edge>,
    initial_timeout: Duration,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(initial_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .max_concurrent_streams(200)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10))
        .max_header_list_size(64 * 1024);
    let builder = if alpn_h2 { builder.http2_only() } else { builder };
    let service = hyper::service::service_fn(move |req| handle(edge.clone(), peer, tls.clone(), listener_info.clone(), req));
    let io = InitialTimeoutIo::new(io, initial_timeout);
    let _ = builder.serve_connection_with_upgrades(TokioIo::new(io), service).await;
}

/// Consume a PROXY protocol v1 line (`PROXY TCP4 src dst sport dport\r\n`)
/// and return the client address it carries.
async fn read_proxy_header(stream: &mut tokio::net::TcpStream) -> Option<SocketAddr> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 108];
    let line_len = loop {
        let got = stream.peek(&mut buf).await.ok()?;
        if got == 0 {
            return None;
        }
        if let Some(pos) = buf[..got].windows(2).position(|w| w == b"\r\n") {
            break pos + 2;
        }
        if got >= 107 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    stream.read_exact(&mut buf[..line_len]).await.ok()?;
    let line = std::str::from_utf8(&buf[..line_len - 2]).ok()?;
    let mut fields = line.split(' ');
    if fields.next()? != "PROXY" || !matches!(fields.next()?, "TCP4" | "TCP6") {
        return None;
    }
    let source: IpAddr = fields.next()?.parse().ok()?;
    let _destination = fields.next()?;
    Some(SocketAddr::new(source, fields.next()?.parse().ok()?))
}

/// Accept loop for plain HTTP (`tls` = None) or HTTPS. With `proxy_protocol`
/// every connection must start with a PROXY v1 header naming the real client
/// (only enable this behind a trusted TCP load balancer).
pub async fn serve(
    listener: TcpListener,
    edge: Arc<Edge>,
    tls: Option<Arc<rustls::ServerConfig>>,
    proxy_protocol: bool,
) {
    serve_with_resolver(listener, edge, tls.map(|c| (c, None)), proxy_protocol).await;
}

pub async fn serve_with_resolver(
    listener: TcpListener,
    edge: Arc<Edge>,
    tls: Option<(Arc<rustls::ServerConfig>, Option<Arc<tls::CertResolver>>)>,
    proxy_protocol: bool,
) {
    serve_with_options(listener, edge, tls, proxy_protocol, false).await;
}

pub async fn serve_proxy_with_resolver(
    listener: TcpListener,
    edge: Arc<Edge>,
    tls: Option<(Arc<rustls::ServerConfig>, Option<Arc<tls::CertResolver>>)>,
    proxy_protocol: bool,
) {
    serve_with_options(listener, edge, tls, proxy_protocol, true).await;
}

async fn serve_with_options(
    listener: TcpListener,
    edge: Arc<Edge>,
    tls: Option<(Arc<rustls::ServerConfig>, Option<Arc<tls::CertResolver>>)>,
    proxy_protocol: bool,
    is_proxy: bool,
) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let listener_info = Some(proxy::ListenerInfo { port, is_proxy, is_front: false });
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // Two TLS configurations: zones may switch HTTP/2 off, which is decided
    // per connection from the SNI before the handshake completes.
    // A third one answers CAs that validate ACME TLS-ALPN-01 challenges.
    let acceptor = tls.map(|(both, resolver)| {
        let mut h1 = (*both).clone();
        h1.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut acme = (*both).clone();
        acme.alpn_protocols = vec![tls::ACME_TLS_ALPN.to_vec()];
        (both, Arc::new(h1), Arc::new(acme), resolver)
    });
    loop {
        let Ok(permit) = limit.clone().acquire_owned().await else { return };
        let (mut stream, mut peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("edge accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let (edge, acceptor, linfo) = (edge.clone(), acceptor.clone(), listener_info.clone());
        tokio::spawn(async move {
            let _permit = permit;
            if proxy_protocol {
                match tokio::time::timeout(Duration::from_secs(5), read_proxy_header(&mut stream)).await {
                    Ok(Some(client)) => peer = client,
                    _ => return,
                }
            }
            match acceptor {
                None => serve_conn(stream, peer, None, false, linfo, edge).await,
                Some((both, h1_only, acme, resolver)) => {
                    let hello = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                    let Ok(Ok(start)) = tokio::time::timeout(Duration::from_secs(10), hello).await else { return };
                    if start.client_hello().alpn().is_some_and(|mut offered| offered.any(|p| p == tls::ACME_TLS_ALPN)) {
                        // The handshake (with the challenge certificate) is the whole exchange.
                        if let Ok(Ok(mut tls)) = tokio::time::timeout(Duration::from_secs(10), start.into_stream(acme)).await {
                            let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
                        }
                        return;
                    }
                    let sni = start.client_hello().server_name().map(str::to_ascii_lowercase);
                    if let (Some(res), Some(name)) = (resolver.as_ref(), sni.as_deref()) {
                        res.warm_sni(name).await;
                    }
                    let http2 = sni
                        .and_then(|name| edge.store.snapshot().find_zone(&name).map(|z| z.zone.settings.http2))
                        .unwrap_or(true);
                    let config = if http2 { both } else { h1_only };
                    if let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), start.into_stream(config)).await {
                        let session = tls.get_ref().1;
                        let alpn_h2 = session.alpn_protocol() == Some(b"h2");
                        let info = TlsInfo {
                            version: match session.protocol_version() {
                                Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
                                _ => "TLSv1.3",
                            },
                            sni: session.server_name().is_some(),
                            kex: session.negotiated_key_exchange_group().map(|group| format!("{:?}", group.name())).unwrap_or_default(),
                        };
                        serve_conn(tls, peer, Some(info), alpn_h2, linfo, edge).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;
