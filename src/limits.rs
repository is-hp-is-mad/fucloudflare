//! Traffic limits of an edge node.
//!
//! A node may be given an allowance of traffic per period (a month or a
//! day) and a speed limit. The allowance has up to three thresholds:
//!
//! - past the DNS threshold the node is left out of DNS answers, so new
//!   visitors go elsewhere while it keeps serving those who still reach it;
//! - past the throttling threshold its speed limit sets in (without that
//!   threshold a speed limit applies all the time);
//! - past the hard limit it serves nothing but a short notice. What that
//!   notice shows (style sheet, picture) is loaded from a name that only
//!   resolves to nodes with allowance left -- and a node over its limit
//!   answers requests for those very resources with one line of text, so
//!   that the notice cannot be used to make it spend traffic.
//!
//! Every node counts and enforces by itself. For DNS the nodes need to know
//! about each other: they report to the primary, which keeps the list of
//! limited nodes in the replicated configuration.

use crate::edge::{full, Body};
use crate::items::EdgeNode;
use crate::store::Store;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Paths under which the resources of the notice are served.
pub const ASSET_PREFIX: &str = "/cdn-cgi/limit/";
/// The notice's resources are loaded from this name under the CNAME base.
pub const ASSET_LABEL: &str = "limit";
/// "Bandwidth Limit Exceeded": not in any RFC, but what it is commonly called.
const STATUS: u16 = 509;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Ok,
    /// Past the DNS threshold: not handed out by DNS any more, still serving.
    DnsLimited,
    /// Past the throttling threshold: serving, but slowed down.
    Throttled,
    /// Past the hard limit: serves nothing but the notice.
    Limited,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::DnsLimited => "dns_limited",
            State::Throttled => "throttled",
            State::Limited => "limited",
        }
    }
}

/// What a node says about its allowance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Usage {
    pub state: State,
    /// Bytes served in the current period.
    pub used_bytes: u64,
    pub period_start: String,
    /// Probability (0-100) that DNS queries offload away from this node.
    pub offload_pct: u8,
}

#[derive(Default)]
struct Config {
    /// Name of the node this process runs on.
    name: String,
    /// Thresholds in bytes.
    dns: Option<u64>,
    throttle: Option<u64>,
    hard: Option<u64>,
    daily: bool,
    reset_day: u32,
    offload_linear: bool,
    dns_silent: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    period_start: i64,
    used: u64,
}

pub struct Limits {
    /// Where the count is kept across restarts.
    path: Option<PathBuf>,
    config: RwLock<Config>,
    used: AtomicU64,
    /// Unix time the current period began at; 0 before the first look at the clock.
    period_start: AtomicI64,
    /// Speed limit in bytes per second, as the bits of an `f64`; 0 for none.
    rate: AtomicU64,
    /// Bytes of the period after which the speed limit applies (0: always).
    throttle_from: AtomicU64,
    /// Token bucket of the speed limit: bytes that may be sent now (negative: owed), as of when.
    bucket: Mutex<(f64, Instant)>,
    dirty: AtomicBool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            path: None,
            config: RwLock::default(),
            used: AtomicU64::new(0),
            period_start: AtomicI64::new(0),
            rate: AtomicU64::new(0),
            throttle_from: AtomicU64::new(0),
            bucket: Mutex::new((0.0, Instant::now())),
            dirty: AtomicBool::new(false),
        }
    }
}

/// Start of the period `now` falls into (UTC): today, or the last `reset_day` of a month.
fn period_start(now: i64, daily: bool, reset_day: u32) -> i64 {
    use chrono::Datelike;
    let today = chrono::DateTime::from_timestamp(now, 0).unwrap_or_default().date_naive();
    let start = if daily {
        today
    } else {
        let day = reset_day.clamp(1, 28);
        let (year, month) = match (today.day() >= day, today.month()) {
            (true, m) => (today.year(), m),
            (false, 1) => (today.year() - 1, 12),
            (false, m) => (today.year(), m - 1),
        };
        chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap_or(today)
    };
    start.and_hms_opt(0, 0, 0).map_or(now, |t| t.and_utc().timestamp())
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Limits {
    pub fn load(path: &Path) -> Limits {
        let saved: Saved = std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Limits {
            path: Some(path.to_path_buf()),
            used: AtomicU64::new(saved.used),
            period_start: AtomicI64::new(saved.period_start),
            ..Default::default()
        }
    }

    /// Ephemeral in-memory limits (`--role accelerate`): never reads or writes `usage.json`.
    pub fn open_ephemeral() -> Limits {
        Limits::default()
    }

    /// Write the count down if it changed since the last time.
    pub fn save(&self) {
        let Some(path) = self.path.as_ref().filter(|_| self.dirty.swap(false, Relaxed)) else { return };
        let saved = Saved { period_start: self.period_start.load(Relaxed), used: self.used.load(Relaxed) };
        let tmp = path.with_extension("json.tmp");
        let written = std::fs::write(&tmp, serde_json::to_vec(&saved).unwrap_or_default()).and_then(|_| std::fs::rename(&tmp, path));
        if let Err(e) = written {
            tracing::warn!("cannot save the traffic count to {}: {e}", path.display());
        }
    }

    /// Take over the limits configured for this node (`None`: it has no entry, so no limits).
    pub fn configure(&self, name: &str, node: Option<&EdgeNode>) {
        let bytes = |gb: Option<f64>| gb.map(|g| (g * 1e9) as u64);
        let mut config = self.config.write().unwrap();
        *config = Config {
            name: name.to_string(),
            dns: bytes(node.and_then(|n| n.traffic_dns_gb)),
            throttle: bytes(node.and_then(|n| n.traffic_throttle_gb)),
            hard: bytes(node.and_then(|n| n.traffic_limit_gb)),
            daily: node.is_some_and(|n| n.traffic_period == "day"),
            reset_day: node.map_or(1, |n| n.traffic_reset_day),
            offload_linear: node.is_some_and(|n| n.dns_offload_mode == "linear"),
            dns_silent: node.is_some_and(|n| n.dns_silent_on_limit),
        };
        let rate = node.and_then(|n| n.rate_limit_mbps).map_or(0.0, |mbps| mbps * 1e6 / 8.0);
        self.rate.store(rate.to_bits(), Relaxed);
        self.throttle_from.store(config.throttle.unwrap_or(0), Relaxed);
    }

    /// Start counting from zero when a new period has begun.
    pub fn roll(&self, now: i64) {
        let start = {
            let config = self.config.read().unwrap();
            period_start(now, config.daily, config.reset_day)
        };
        let before = self.period_start.swap(start, Relaxed);
        if start > before && before != 0 {
            self.used.store(0, Relaxed);
        }
        if start != before {
            self.dirty.store(true, Relaxed);
        }
    }

    /// Find this node's entry in the configuration and apply it.
    pub fn refresh(&self, store: &Store, edge_ips: &[IpAddr], explicit_name: Option<&str>) {
        let name = crate::fleet::self_name(store, edge_ips, explicit_name);
        let nodes = store.list_nodes();
        self.configure(&name, nodes.iter().find(|n| n.name == name));
        self.roll(unix_now());
    }

    /// Follow the configuration and the calendar, and keep the count on disk.
    pub async fn run(self: Arc<Self>, store: Arc<Store>, edge_ips: Vec<IpAddr>, explicit_name: Option<String>) {
        let mut changes = store.subscribe();
        let mut saved = Instant::now();
        loop {
            self.refresh(&store, &edge_ips, explicit_name.as_deref());
            if saved.elapsed() >= Duration::from_secs(30) {
                saved = Instant::now();
                let this = self.clone();
                let _ = tokio::task::spawn_blocking(move || this.save()).await;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Count bytes sent to visitors.
    pub fn add(&self, bytes: u64) {
        if bytes > 0 {
            self.used.fetch_add(bytes, Relaxed);
            self.dirty.store(true, Relaxed);
        }
    }

    pub fn state(&self) -> State {
        let used = self.used.load(Relaxed);
        let config = self.config.read().unwrap();
        if config.hard.is_some_and(|limit| used >= limit) {
            State::Limited
        } else if config.throttle.is_some_and(|limit| used >= limit) {
            State::Throttled
        } else if config.dns.is_some_and(|limit| used >= limit) {
            State::DnsLimited
        } else {
            State::Ok
        }
    }

    /// This node's name and state.
    pub fn own(&self) -> (String, State) {
        // Never hold the guard while state() reads the lock again: std's RwLock
        // lets a queued writer (configure) go first, so a nested read deadlocks.
        let name = self.config.read().unwrap().name.clone();
        (name, self.state())
    }

    /// Probability (0-100) that DNS queries should offload away from this node.
    pub fn offload_pct(&self) -> u8 {
        let used = self.used.load(Relaxed);
        let config = self.config.read().unwrap();
        if config.hard.is_some_and(|limit| used >= limit) {
            return 100;
        }
        if let Some(dns) = config.dns.filter(|limit| used >= *limit) {
            if config.offload_linear {
                if let Some(hard) = config.hard.filter(|limit| *limit > dns) {
                    let frac = (used - dns) as f64 / (hard - dns) as f64;
                    return (frac * 100.0).clamp(0.0, 100.0).round() as u8;
                }
            }
            return 100;
        }
        if config.throttle.is_some_and(|limit| used >= limit) {
            return 100;
        }
        0
    }

    /// This node's name and DNS offload probability (0-100).
    pub fn own_offload(&self) -> (String, u8) {
        let name = self.config.read().unwrap().name.clone();
        (name, self.offload_pct())
    }

    /// Should this node stay silent on public DNS (port 53)?
    pub fn dns_silent(&self) -> bool {
        let silent = self.config.read().unwrap().dns_silent;
        silent && self.state() >= State::DnsLimited
    }

    pub fn usage(&self) -> Usage {
        Usage {
            state: self.state(),
            used_bytes: self.used.load(Relaxed),
            period_start: crate::store::rfc3339(self.period_start.load(Relaxed)),
            offload_pct: self.offload_pct(),
        }
    }

    /// The speed limit in force right now, in bytes per second (0: none).
    fn rate(&self) -> f64 {
        match self.used.load(Relaxed) >= self.throttle_from.load(Relaxed) {
            true => f64::from_bits(self.rate.load(Relaxed)),
            false => 0.0,
        }
    }

    /// Is a speed limit in force?
    pub fn throttled(&self) -> bool {
        self.rate() > 0.0
    }

    /// Book `bytes` against the speed limit; returns how long to hold back
    /// what comes after them.
    pub fn throttle(&self, bytes: usize) -> Duration {
        let rate = self.rate();
        if rate <= 0.0 {
            return Duration::ZERO;
        }
        let burst = (rate / 4.0).max(65536.0);
        let mut bucket = self.bucket.lock().unwrap();
        let now = Instant::now();
        bucket.0 = (bucket.0 + now.duration_since(bucket.1).as_secs_f64() * rate).min(burst) - bytes as f64;
        bucket.1 = now;
        if bucket.0 >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-bucket.0 / rate)
        }
    }
}

// ------------------------------------------------------------ notices ----

const STYLE: &str = "\
html{height:100%}
body{margin:0;min-height:100%;display:grid;place-items:center;background:#faf9f5;color:#141413;font:16px/1.65 ui-sans-serif,system-ui,-apple-system,'PingFang SC','Noto Sans SC','Microsoft YaHei',sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:36rem;padding:3rem 1.5rem}
.mark{display:block;width:56px;height:56px;margin-bottom:1.75rem}
h1{font:500 clamp(1.6rem,4vw,2.1rem)/1.25 ui-serif,'Iowan Old Style',Georgia,'Songti SC','Noto Serif SC',serif;letter-spacing:-.015em;margin:0 0 .9rem}
p{margin:.6em 0;color:#3d3d3a}
p.en{color:#73726c;font-size:.92em}
hr{border:0;border-top:1px solid #e8e6dc;margin:2.2em 0 1em}
small{color:#87867f;font-size:13px}
@media (prefers-color-scheme:dark){body{background:#262624;color:#faf9f5}p{color:#d1cfc5}p.en{color:#9c9a92}hr{border-color:#3d3d3a}small{color:#87867f}}
";

const MARK: &str = "\
<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 72 72\" fill=\"none\" stroke=\"#d97757\" stroke-width=\"4\" stroke-linecap=\"round\">\
<path d=\"M10 50a26 26 0 1 1 52 0\"/><path d=\"M36 50 52 30\"/><circle cx=\"36\" cy=\"50\" r=\"3\" fill=\"#d97757\"/>\
<path d=\"M10 62h52\" stroke-width=\"3\" stroke-dasharray=\"2 7\"/></svg>";

fn answer(status: u16, content_type: &'static str, cache: &'static str, body: String) -> Response<Body> {
    let mut resp = Response::new(full(body));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    resp
}

/// The page a node over its limit answers with. Its looks come from
/// `assets` (a host name that resolves to nodes with allowance left), so the
/// node itself sends these few hundred bytes and nothing else.
pub fn notice(assets: Option<&str>, ray: &str) -> Response<Body> {
    let (link, mark) = match assets {
        Some(host) => (
            format!("<link rel=\"stylesheet\" href=\"https://{host}{ASSET_PREFIX}page.css\">"),
            format!("<img class=\"mark\" src=\"https://{host}{ASSET_PREFIX}mark.svg\" alt=\"\" width=\"72\" height=\"72\">"),
        ),
        None => Default::default(),
    };
    let html = format!(
        "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{STATUS} · 节点流量已用尽</title>{link}</head><body><main>{mark}\
         <h1>{STATUS} · 该节点的流量已用尽</h1>\
         <p>您连接到的边缘节点已经用完本周期的流量配额，暂时不再提供服务；其他节点仍在正常工作。</p>\
         <p>请稍后重试。如果一直看到此页面，说明本机的 DNS 缓存还指向这个节点，请刷新 DNS 缓存或检查 DNS 设置。</p>\
         <p class=\"en\">This edge node has used up its traffic allowance. Other nodes are still serving: \
         if this page keeps coming back, flush your DNS cache or check your DNS settings.</p>\
         <hr><small>Ray ID: {ray} · fucf</small></main></body></html>"
    );
    let mut resp = answer(STATUS, "text/html; charset=utf-8", "no-store", html);
    resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("300"));
    resp
}

/// What a node over its limit says when asked for the notice's own
/// resources: those are meant to come from other nodes, so whoever forces
/// requests here gets an empty 509 response (zero body bytes).
pub fn bare_notice() -> Response<Body> {
    answer(STATUS, "text/plain; charset=utf-8", "no-store", String::new())
}

/// A resource of the notice, as a node with allowance left serves it.
pub fn asset(name: &str) -> Option<Response<Body>> {
    let (content_type, body) = match name {
        "page.css" => ("text/css; charset=utf-8", STYLE),
        "mark.svg" => ("image/svg+xml", MARK),
        _ => return None,
    };
    let mut resp = answer(200, content_type, "public, max-age=86400", body.to_string());
    resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(v: serde_json::Value) -> EdgeNode {
        let mut body = json!({ "name": "au", "ipv4": "203.0.113.1" });
        body.as_object_mut().unwrap().extend(v.as_object().unwrap().clone());
        let mut node: EdgeNode = serde_json::from_value(body).unwrap();
        node.validate(&[]).unwrap();
        node
    }

    fn at(date: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(date).unwrap().timestamp()
    }

    #[test]
    fn periods() {
        let start = |now: &str, daily, day| crate::store::rfc3339(period_start(at(now), daily, day));
        assert_eq!(start("2026-11-20T13:45:00Z", true, 1), "2026-11-20T00:00:00Z");
        assert_eq!(start("2026-11-20T13:45:00Z", false, 1), "2026-11-01T00:00:00Z");
        assert_eq!(start("2026-11-20T13:45:00Z", false, 20), "2026-11-20T00:00:00Z");
        assert_eq!(start("2026-11-20T13:45:00Z", false, 21), "2026-10-21T00:00:00Z");
        assert_eq!(start("2027-01-03T00:00:00Z", false, 15), "2026-12-15T00:00:00Z");
    }

    #[test]
    fn thresholds_periods_and_restarts() {
        let path = std::env::temp_dir().join(format!("fucf-usage-{}.json", uuid::Uuid::new_v4().simple()));
        let limits = Limits::load(&path);
        assert_eq!(limits.state(), State::Ok);
        limits.add(5_000_000);
        assert_eq!(limits.state(), State::Ok, "without an entry for this node nothing is limited");

        // 2 MB for DNS, 6 MB hard: a node that used 5 MB is taken out of DNS but keeps serving
        limits.configure("au", Some(&node(json!({ "traffic_dns_gb": 0.002, "traffic_limit_gb": 0.006 }))));
        limits.roll(at("2026-11-20T10:00:00Z"));
        assert_eq!(limits.own(), ("au".to_string(), State::DnsLimited));
        limits.add(1_000_000);
        assert_eq!(limits.state(), State::Limited);
        let usage = limits.usage();
        assert_eq!((usage.used_bytes, usage.period_start.as_str()), (6_000_000, "2026-11-01T00:00:00Z"));
        assert_eq!(serde_json::to_value(&usage).unwrap()["state"], "limited");

        // the count survives a restart ...
        limits.save();
        let restarted = Limits::load(&path);
        restarted.configure("au", Some(&node(json!({ "traffic_limit_gb": 0.006 }))));
        restarted.roll(at("2026-11-30T23:59:59Z"));
        assert_eq!(restarted.state(), State::Limited);
        // ... a higher limit lifts the restriction, and so does the next period
        restarted.configure("au", Some(&node(json!({ "traffic_limit_gb": 1 }))));
        assert_eq!(restarted.state(), State::Ok);
        restarted.configure("au", Some(&node(json!({ "traffic_limit_gb": 0.006 }))));
        restarted.roll(at("2026-12-01T00:00:00Z"));
        assert_eq!((restarted.state(), restarted.usage().used_bytes), (State::Ok, 0));
        // per day: over at midnight (UTC)
        restarted.configure("au", Some(&node(json!({ "traffic_limit_gb": 0.001, "traffic_period": "day" }))));
        restarted.roll(at("2026-12-01T08:00:00Z"));
        restarted.add(2_000_000);
        restarted.roll(at("2026-12-01T23:00:00Z"));
        assert_eq!(restarted.state(), State::Limited);
        restarted.roll(at("2026-12-02T00:00:01Z"));
        assert_eq!(restarted.state(), State::Ok);
        std::fs::remove_file(&path).ok();

        // limits must make sense
        let invalid = |v| serde_json::from_value::<EdgeNode>(v).unwrap().validate(&[]).is_err();
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_dns_gb": 5, "traffic_limit_gb": 2 })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_limit_gb": -1 })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_period": "week" })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_reset_day": 31 })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "rate_limit_mbps": 0 })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_throttle_gb": 3, "traffic_limit_gb": 2, "rate_limit_mbps": 5 })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_dns_gb": 3, "traffic_throttle_gb": 2, "rate_limit_mbps": 5 })));
        assert!(invalid(json!({ "name": "x", "ipv4": "203.0.113.1", "traffic_throttle_gb": 2 })), "a threshold without a speed");
    }

    #[test]
    fn three_steps() {
        // leave DNS at 1 TB, slow down to 10 Mbit/s at 1.25 TB, stop at 1.4 TB
        let limits = Limits::default();
        let steps = json!({ "traffic_dns_gb": 1000, "traffic_throttle_gb": 1250, "traffic_limit_gb": 1400, "rate_limit_mbps": 10 });
        limits.configure("us", Some(&node(steps)));
        let expected = [(999, State::Ok, false), (1, State::DnsLimited, false), (250, State::Throttled, true), (150, State::Limited, true)];
        for (more_gb, state, slowed) in expected {
            limits.add(more_gb * 1_000_000_000);
            assert_eq!((limits.state(), limits.throttled()), (state, slowed), "after another {more_gb} GB");
            assert_eq!(limits.throttle(50_000_000).is_zero(), !slowed);
        }
        assert!(State::Ok < State::DnsLimited && State::DnsLimited < State::Throttled && State::Throttled < State::Limited);
        for state in [State::Ok, State::DnsLimited, State::Throttled, State::Limited] {
            assert_eq!(serde_json::to_value(state).unwrap(), state.as_str());
        }
    }

    #[test]
    fn speed_limit_is_a_token_bucket() {
        let limits = Limits::default();
        assert!(!limits.throttled() && limits.throttle(10_000_000).is_zero());
        // 8 Mbit/s = 1 MB/s, with a quarter of a second of burst
        limits.configure("au", Some(&node(json!({ "rate_limit_mbps": 8 }))));
        assert!(limits.throttled());
        *limits.bucket.lock().unwrap() = (250_000.0, Instant::now());
        assert!(limits.throttle(200_000).is_zero(), "within the burst");
        let wait = limits.throttle(550_000).as_secs_f64();
        assert!((0.45..=0.51).contains(&wait), "half a megabyte over: half a second, got {wait}");
        let wait = limits.throttle(1_000_000).as_secs_f64();
        assert!((1.45..=1.51).contains(&wait), "debts add up: {wait}");
    }

    #[test]
    fn notices() {
        let page = notice(Some("limit.cdn.example.net"), "abc");
        assert_eq!((page.status().as_u16(), page.headers()["cache-control"].to_str().unwrap()), (509, "no-store"));
        assert!(asset("page.css").is_some() && asset("mark.svg").is_some() && asset("../state.json").is_none());
        let bare = bare_notice();
        assert_eq!(bare.status().as_u16(), 509);
        assert_eq!(hyper::body::Body::size_hint(bare.body()).exact(), Some(0));
    }

    #[test]
    fn linear_offload_and_dns_silence() {
        let limits = Limits::default();
        let cfg = node(json!({
            "name": "sgp",
            "traffic_dns_gb": 400,
            "traffic_limit_gb": 700,
            "dns_offload_mode": "linear",
            "dns_silent_on_limit": true
        }));
        limits.configure("sgp", Some(&cfg));
        assert_eq!((limits.state(), limits.offload_pct(), limits.dns_silent()), (State::Ok, 0, false));
        limits.add(399 * 1_000_000_000);
        assert_eq!((limits.state(), limits.offload_pct(), limits.dns_silent()), (State::Ok, 0, false));
        // 400 GB: enters Tier 2, silent on port 53, 0% offload at exact boundary
        limits.add(1 * 1_000_000_000);
        assert_eq!((limits.state(), limits.offload_pct(), limits.dns_silent()), (State::DnsLimited, 0, true));
        // 550 GB: halfway between 400 and 700 -> 50% offload
        limits.add(150 * 1_000_000_000);
        assert_eq!((limits.state(), limits.offload_pct(), limits.dns_silent()), (State::DnsLimited, 50, true));
        // 700 GB: Tier 3 -> 100% offload, silent on port 53
        limits.add(150 * 1_000_000_000);
        assert_eq!((limits.state(), limits.offload_pct(), limits.dns_silent()), (State::Limited, 100, true));
        // linear mode without traffic_limit_gb is rejected
        let bad: EdgeNode = serde_json::from_value(json!({
            "name": "bad",
            "ipv4": "203.0.113.1",
            "traffic_dns_gb": 400,
            "dns_offload_mode": "linear"
        }))
        .unwrap();
        assert!(bad.clone().validate(&[]).is_err());
    }
}
