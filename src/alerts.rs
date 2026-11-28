//! Alerts: the panel's node watches the fleet and tells people when
//! something goes wrong, through channels they set up (a webhook that gets
//! JSON, or a Telegram chat).
//!
//! Every [`CHECK_EVERY`] the node that runs the panel gathers what it knows
//! ([`observe`]) and hands it to [`evaluate`], a pure function of what was
//! seen, the time and the alerts of the check before: it says which alerts
//! fire now and what to tell the channels. An alert is told when it starts,
//! again every [`RESEND_SECS`] while it lasts, and once when it is over.
//! Nothing of this is stored: after a restart, what still fires is told again.
//!
//! The channels themselves are part of the configuration (replicated like
//! steering rules); their secrets (a webhook URL, a bot token) are never
//! shown back, see [`AlertChannel::public`].

use crate::edge::waf::Waf;
use crate::edge::Edge;
use crate::fleet::Fleet;
use crate::items::CertificatePack;
use crate::store::{Store, StoreError};
use crate::sync::SyncMeta;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The events a channel can ask for, in the order they are listed.
pub const EVENTS: [&str; 6] = ["node_offline", "sync_lagging", "certificate_failing", "traffic_limit", "under_attack", "origin_errors"];

/// How often the fleet is looked at.
const CHECK_EVERY: Duration = Duration::from_secs(30);
/// Checks in a row a node must be missing before it counts as offline (one
/// missed report is a hiccup, not an outage).
const OFFLINE_CHECKS: u32 = 3;
/// How long a node may be online with an older configuration.
const LAG_SECS: u64 = 300;
/// A certificate this close to its end is failing to renew.
const CERT_DAYS: u64 = 14;
/// The window in which origin errors are counted.
const ORIGIN_WINDOW: u64 = 300;
/// Origin error events of one zone within [`ORIGIN_WINDOW`] that make an
/// alert. The edge logs a failing host at most once a minute per status and
/// node, so this is about three minutes of one failing host, sooner when
/// more of them fail.
pub const ORIGIN_ERRORS_THRESHOLD: usize = 3;
/// While an alert lasts it is told again this often.
const RESEND_SECS: u64 = 6 * 3600;
/// After the process starts, nodes have not reported yet: none counts as
/// offline before this has passed.
const STARTUP_GRACE: u64 = 120;
/// How many channels there may be (each one is a message per check).
pub const MAX_CHANNELS: usize = 20;
/// How long one delivery may take.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// At most this many alerts are listed in one message.
const MAX_LINES: usize = 30;
/// Telegram takes up to 4096 characters.
const MAX_TEXT: usize = 4000;
/// What a secret looks like in the API's answers.
pub const MASK: &str = "***";

fn yes() -> bool {
    true
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

/// Where alerts go. A global object, replicated with the configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// `webhook` (a JSON POST to `url`) or `telegram` (a message from the bot
    /// `bot_token` to `chat_id`).
    #[serde(default)]
    pub kind: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The events this channel is told of: names from [`EVENTS`], at least one.
    #[serde(default)]
    pub events: Vec<String>,
    /// The webhook's URL (https only). Secret: often the URL is the credential.
    #[serde(default)]
    pub url: String,
    /// The Telegram bot's token. Secret.
    #[serde(default)]
    pub bot_token: String,
    /// The Telegram chat: a numeric id or `@channelname`.
    #[serde(default)]
    pub chat_id: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl AlertChannel {
    /// Check and tidy a channel about to be saved. `old` is the stored one it
    /// replaces: a secret sent back masked (or left empty) keeps the stored
    /// value, so a client may send back what it was shown.
    pub fn validate(&mut self, old: Option<&AlertChannel>) -> Result<(), StoreError> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.chars().count() > 64 || self.name.chars().any(char::is_control) {
            return invalid("a channel needs a name (at most 64 characters, no control characters)");
        }
        self.kind = self.kind.trim().to_ascii_lowercase();
        let mut wanted = Vec::new();
        for e in &self.events {
            let e = e.trim();
            if !EVENTS.contains(&e) {
                return invalid(format!("unknown event '{e}' (known: {})", EVENTS.join(", ")));
            }
            wanted.push(e.to_string());
        }
        // in the order of EVENTS, each once
        self.events = EVENTS.iter().filter(|e| wanted.iter().any(|w| w == *e)).map(|e| e.to_string()).collect();
        if self.events.is_empty() {
            return invalid(format!("events must name at least one of: {}", EVENTS.join(", ")));
        }
        let same_kind = old.filter(|o| o.kind == self.kind);
        match self.kind.as_str() {
            "webhook" => {
                // a channel changing kind keeps no secret of the other kind
                self.bot_token.clear();
                self.chat_id.clear();
                let url = self.url.trim().to_string();
                let stored = same_kind.map(|o| o.url.clone()).filter(|u| !u.is_empty());
                self.url = match stored {
                    Some(stored) if url.is_empty() || url == mask_url(&stored) => stored,
                    _ => {
                        check_webhook_url(&url)?;
                        url
                    }
                };
            }
            "telegram" => {
                self.url.clear();
                let token = self.bot_token.trim().to_string();
                let stored = same_kind.map(|o| o.bot_token.clone()).filter(|t| !t.is_empty());
                self.bot_token = match stored {
                    Some(stored) if token.is_empty() || token == MASK => stored,
                    _ if token.is_empty() || token == MASK => return invalid("a telegram channel needs bot_token"),
                    _ => {
                        check_bot_token(&token)?;
                        token
                    }
                };
                self.chat_id = self.chat_id.trim().to_string();
                check_chat_id(&self.chat_id)?;
            }
            "" => return invalid("kind is required: webhook or telegram"),
            other => return invalid(format!("unknown kind '{other}' (webhook or telegram)")),
        }
        Ok(())
    }

    /// The channel as the API shows it: secrets masked, no replication data.
    /// A masked value sent back on update keeps the stored secret.
    pub fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.remove("sync");
            o.insert("url".into(), json!(if self.url.is_empty() { String::new() } else { mask_url(&self.url) }));
            o.insert("bot_token".into(), json!(if self.bot_token.is_empty() { "" } else { MASK }));
        }
        v
    }

    fn wants(&self, event: &str) -> bool {
        self.enabled && self.events.iter().any(|e| e == event)
    }
}

/// A webhook URL as shown: scheme and host only, the rest (where the
/// credential usually is) masked. Comparing with this is how a masked URL
/// sent back is recognised.
pub fn mask_url(url: &str) -> String {
    match url.parse::<hyper::Uri>() {
        Ok(uri) => match (uri.scheme_str(), uri.authority()) {
            (Some(scheme), Some(authority)) => format!("{scheme}://{}/{MASK}", authority.as_str()),
            _ => MASK.to_string(),
        },
        Err(_) => MASK.to_string(),
    }
}

/// A webhook must be https (alerts carry the fleet's state, and the URL is a
/// secret), name a public host, and carry no credentials of its own.
fn check_webhook_url(url: &str) -> Result<(), StoreError> {
    if url.is_empty() {
        return invalid("a webhook channel needs url");
    }
    if url.len() > 2048 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return invalid("url must be at most 2048 characters, with no spaces");
    }
    if url.contains(MASK) {
        return invalid("url is masked: send the whole URL, or the masked value unchanged to keep the stored one");
    }
    if !url.starts_with("https://") {
        return invalid("url must start with https://");
    }
    let uri: hyper::Uri = url.parse().map_err(|_| StoreError::Invalid("url is not a valid URL".into()))?;
    let Some(authority) = uri.authority() else { return invalid("url names no host") };
    if authority.as_str().contains('@') {
        return invalid("url must not carry a user name or password");
    }
    let host = authority.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        if crate::edge::upstream::is_private_or_reserved_ip(ip) || ip.is_multicast() {
            return invalid("url must not point at a private, loopback or reserved address");
        }
    } else if host.is_empty() || !host.contains('.') || host == "localhost" || host.ends_with(".localhost") {
        return invalid("url must name a public host");
    }
    if authority.port_u16() == Some(0) {
        return invalid("url has port 0");
    }
    crate::edge::upstream::Target::from_url(url).map_err(|_| StoreError::Invalid("url cannot be reached as given".into()))?;
    Ok(())
}

/// `<bot id>:<secret>`, the shape BotFather hands out.
fn check_bot_token(token: &str) -> Result<(), StoreError> {
    let ok = token.split_once(':').is_some_and(|(id, secret)| {
        (1..=20).contains(&id.len())
            && id.bytes().all(|b| b.is_ascii_digit())
            && (30..=100).contains(&secret.len())
            && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    if ok {
        Ok(())
    } else {
        invalid("bot_token must look like <bot id>:<secret> as BotFather gives it")
    }
}

/// A numeric chat id (groups and channels are negative) or `@channelname`.
fn check_chat_id(chat: &str) -> Result<(), StoreError> {
    let digits = chat.strip_prefix('-').unwrap_or(chat);
    let numeric = (1..=20).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit());
    let named = chat.strip_prefix('@').is_some_and(|n| {
        (4..=32).contains(&n.len()) && n.bytes().next().is_some_and(|b| b.is_ascii_alphabetic()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    });
    if numeric || named {
        Ok(())
    } else {
        invalid("chat_id must be a numeric chat id or @channelname")
    }
}

// ------------------------------------------------------------ evaluation ----

/// One node as the panel's node sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeSeen {
    pub name: String,
    /// It reported (itself or through a peer) within the last minute.
    pub online: bool,
    /// It runs the configuration this node has.
    pub in_sync: bool,
}

/// One certificate pack.
#[derive(Debug, Clone, PartialEq)]
pub struct CertSeen {
    pub id: String,
    pub zone: String,
    pub hosts: Vec<String>,
    /// Issuing failed and there is no certificate at all.
    pub failed: bool,
    pub error: String,
    /// When the certificate in use ends (unix seconds), if there is one.
    pub expires_at: Option<u64>,
}

/// Everything the checks look at, gathered by [`observe`]: plain data, so
/// that [`evaluate`] needs neither clock nor network.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observed {
    /// The enabled nodes besides the one looking.
    pub nodes: Vec<NodeSeen>,
    pub certificates: Vec<CertSeen>,
    /// Nodes past a threshold of their traffic allowance, with the tier
    /// (`dns_limited`, `throttled`, `limited`).
    pub limited: BTreeMap<String, String>,
    /// Zones the automatic firewall switched to under attack mode.
    pub under_attack: Vec<String>,
    /// Per zone: origin error events within [`ORIGIN_WINDOW`].
    pub origin_errors: BTreeMap<String, usize>,
}

/// An alert that fires.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    /// `event:subject id`, what tells two alerts apart.
    pub key: String,
    pub event: String,
    /// What it is about, for people (a node, a zone, a certificate's names).
    pub subject: String,
    /// A finer state where the event has one (the traffic tier, `failed` or
    /// `expiring`); a change of it is told like a new alert.
    pub level: String,
    pub message: String,
    /// When it started firing (unix seconds).
    pub since: u64,
    /// When it was last told.
    pub last_sent: u64,
}

impl Alert {
    fn json(&self) -> Value {
        json!({
            "key": self.key, "event": self.event, "subject": self.subject, "level": self.level, "message": self.message,
            "since": crate::store::rfc3339(self.since as i64), "last_sent": crate::store::rfc3339(self.last_sent as i64),
        })
    }
}

/// What the checks remember from one round to the next (in memory only).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AlertState {
    /// The alerts that fire, by key.
    pub active: BTreeMap<String, Alert>,
    /// Per node: checks in a row it was missing.
    offline_checks: BTreeMap<String, u32>,
    /// Per node: since when it has been online with an older configuration.
    lagging_since: BTreeMap<String, u64>,
}

/// Something to tell the channels.
#[derive(Debug, Clone, PartialEq)]
pub struct Notice {
    pub event: String,
    pub subject: String,
    /// `firing` or `resolved`.
    pub state: &'static str,
    /// A reminder of an alert that was told before and still fires.
    pub repeat: bool,
    pub level: String,
    pub message: String,
    pub since: u64,
    pub at: u64,
}

impl Notice {
    fn of(a: &Alert, state: &'static str, repeat: bool, at: u64) -> Notice {
        Notice { event: a.event.clone(), subject: a.subject.clone(), state, repeat, level: a.level.clone(), message: a.message.clone(), since: a.since, at }
    }

    fn json(&self) -> Value {
        json!({
            "event": self.event, "subject": self.subject, "state": self.state, "repeat": self.repeat, "level": self.level,
            "message": self.message, "since": crate::store::rfc3339(self.since as i64), "at": crate::store::rfc3339(self.at as i64),
        })
    }
}

/// A condition that holds now: an alert before it gets its times.
struct Firing {
    key: String,
    event: &'static str,
    subject: String,
    level: String,
    message: String,
}

fn firing(event: &'static str, id: &str, subject: String, level: &str, message: String) -> Firing {
    Firing { key: format!("{event}:{id}"), event, subject, level: level.to_string(), message }
}

/// The alerts that fire now and what to tell, from what was `seen`, the
/// state the previous check left, the time and when the process started.
/// Pure: the same inputs always give the same answer.
pub fn evaluate(prev: &AlertState, seen: &Observed, now: u64, started: u64) -> (AlertState, Vec<Notice>) {
    let mut next = AlertState::default();
    let mut found: BTreeMap<String, Firing> = BTreeMap::new();
    let mut add = |f: Firing| {
        found.insert(f.key.clone(), f);
    };
    // nodes have not reported yet right after a start: nothing counts then
    let in_grace = now < started.saturating_add(STARTUP_GRACE);

    for n in &seen.nodes {
        let missed = if n.online || in_grace { 0 } else { prev.offline_checks.get(&n.name).copied().unwrap_or(0).saturating_add(1) };
        if missed > 0 {
            next.offline_checks.insert(n.name.clone(), missed);
        }
        if missed >= OFFLINE_CHECKS {
            add(firing("node_offline", &n.name, n.name.clone(), "", format!("节点 {0} 连续 {missed} 次检查不在线 · node {0} missed {missed} checks in a row", n.name)));
        }
        if n.online && !n.in_sync {
            let since = prev.lagging_since.get(&n.name).copied().unwrap_or(now);
            next.lagging_since.insert(n.name.clone(), since);
            let mins = now.saturating_sub(since) / 60;
            if now.saturating_sub(since) >= LAG_SECS {
                add(firing("sync_lagging", &n.name, n.name.clone(), "", format!("节点 {0} 已有 {mins} 分钟没有同步到最新配置 · node {0} has not caught up with the configuration for {mins} minutes", n.name)));
            }
        }
    }

    for c in &seen.certificates {
        let subject = format!("{} ({})", c.zone, c.hosts.join(", "));
        if c.failed {
            let why = if c.error.is_empty() { String::new() } else { format!(": {}", c.error.chars().take(300).collect::<String>()) };
            add(firing("certificate_failing", &c.id, subject.clone(), "failed", format!("证书签发失败 · the certificate could not be issued{why}")));
        } else if let Some(until) = c.expires_at.filter(|until| *until <= now.saturating_add(CERT_DAYS * 86_400)) {
            let message = if until <= now {
                "证书已过期 · the certificate has expired".to_string()
            } else {
                let days = (until - now) / 86_400;
                format!("证书 {days} 天内到期，续期没有成功 · the certificate ends within {days} days and was not renewed")
            };
            add(firing("certificate_failing", &c.id, subject, "expiring", message));
        }
    }

    for (node, tier) in &seen.limited {
        add(firing("traffic_limit", node, node.clone(), tier, format!("节点 {node} 的流量到档：{tier} · node {node} is past a traffic threshold: {tier}")));
    }

    for zone in &seen.under_attack {
        add(firing("under_attack", zone, zone.clone(), "", format!("{zone} 被自动切到受攻击模式 · {zone} was switched to under attack mode automatically")));
    }

    for (zone, count) in &seen.origin_errors {
        // once firing, it lasts until a whole window passes without errors (no flapping at the threshold)
        let was = prev.active.contains_key(&format!("origin_errors:{zone}"));
        if *count >= ORIGIN_ERRORS_THRESHOLD || (was && *count > 0) {
            let mins = ORIGIN_WINDOW / 60;
            add(firing("origin_errors", zone, zone.clone(), "", format!("{zone} 在 {mins} 分钟内有 {count} 次回源错误 · {zone} had {count} origin errors within {mins} minutes")));
        }
    }

    let mut notices = Vec::new();
    for (key, f) in found {
        let alert = match prev.active.get(&key) {
            None => {
                let a = Alert { key: key.clone(), event: f.event.into(), subject: f.subject, level: f.level, message: f.message, since: now, last_sent: now };
                notices.push(Notice::of(&a, "firing", false, now));
                a
            }
            Some(old) => {
                let mut a = Alert { subject: f.subject, level: f.level, message: f.message, ..old.clone() };
                if a.level != old.level {
                    a.last_sent = now;
                    notices.push(Notice::of(&a, "firing", false, now));
                } else if now >= old.last_sent.saturating_add(RESEND_SECS) {
                    a.last_sent = now;
                    notices.push(Notice::of(&a, "firing", true, now));
                }
                a
            }
        };
        next.active.insert(key, alert);
    }
    for (key, old) in &prev.active {
        if !next.active.contains_key(key) {
            notices.push(Notice::of(old, "resolved", false, now));
        }
    }
    (next, notices)
}

/// Which channel is told what: each enabled channel gets the notices of
/// the events it asked for, or nothing.
pub fn route(channels: &[AlertChannel], notices: &[Notice]) -> Vec<(AlertChannel, Vec<Notice>)> {
    channels
        .iter()
        .filter_map(|c| {
            let mine: Vec<Notice> = notices.iter().filter(|n| c.wants(&n.event)).cloned().collect();
            (!mine.is_empty()).then(|| (c.clone(), mine))
        })
        .collect()
}

/// The message for people (Telegram, and `text` in a webhook's JSON).
pub fn text(notices: &[Notice], node: &str) -> String {
    let mut out = format!("fucf 告警 · alerts from {node}\n");
    for (i, n) in notices.iter().enumerate() {
        let head = match (n.state, n.repeat) {
            ("resolved", _) => "已恢复 · RESOLVED",
            (_, true) => "仍在触发 · STILL FIRING",
            _ => "触发 · FIRING",
        };
        let entry = format!("\n{head} {} {}\n{}\n", n.event, n.subject, n.message);
        // what does not fit is counted, not cut off unsaid (room is kept for that line)
        if i > 0 && (i == MAX_LINES || out.chars().count() + entry.chars().count() > MAX_TEXT - 100) {
            let more = notices.len() - i;
            out.push_str(&format!("\n另有 {more} 条 · and {more} more\n"));
            break;
        }
        out.push_str(&entry);
    }
    if out.chars().count() > MAX_TEXT {
        out = out.chars().take(MAX_TEXT - 1).collect::<String>() + "…";
    }
    out
}

/// The JSON a webhook gets.
pub fn payload(notices: &[Notice], node: &str, now: u64, test: bool) -> Value {
    json!({
        "source": "fucf",
        "node": node,
        "sent_at": crate::store::rfc3339(now as i64),
        "test": test,
        "alerts": notices.iter().map(Notice::json).collect::<Vec<_>>(),
        "text": if test { test_text(node) } else { text(notices, node) },
    })
}

fn test_text(node: &str) -> String {
    format!("fucf 测试消息 · test message from {node}: this channel works")
}

fn secs(at: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(at).ok().map(|t| t.timestamp().max(0) as u64)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Gather what the checks look at: the fleet as this node knows it (`me`
/// is this node, never checked against itself), the certificate packs and
/// zone settings in the store, and the security events.
pub fn observe(store: &Store, fleet: &Fleet, waf: &Waf, me: &str, now: u64) -> Observed {
    let version = store.version();
    let nodes = store
        .list_nodes()
        .into_iter()
        .filter(|n| n.enabled && n.name != me)
        .map(|n| {
            let status = fleet.status(&n.name, &version);
            let flag = |k: &str| status.as_ref().is_some_and(|s| s[k] == true);
            NodeSeen { online: flag("online"), in_sync: flag("in_sync"), name: n.name }
        })
        .collect();
    let limited = store.limited_nodes().into_iter().filter(|(_, s)| *s != crate::limits::State::Ok).map(|(n, s)| (n, s.as_str().to_string())).collect();
    let mut seen = Observed { nodes, limited, ..Observed::default() };
    for zone in store.list_zones() {
        for p in store.items::<CertificatePack>(&zone.id).unwrap_or_default() {
            seen.certificates.push(CertSeen {
                id: p.meta.id,
                zone: zone.name.clone(),
                hosts: p.hosts,
                failed: p.status == "failed",
                error: p.error,
                expires_at: p.expires_on.as_deref().and_then(secs),
            });
        }
        if zone.settings.security_level == "under_attack" && zone.settings.auto_level_until > 0 {
            seen.under_attack.push(zone.name.clone());
        }
        let errors = waf
            .events(&zone.id, usize::MAX)
            .iter()
            .filter(|e| e.source == "origin" && secs(&e.occurred_at).is_some_and(|at| at.saturating_add(ORIGIN_WINDOW) >= now && at <= now.saturating_add(60)))
            .count();
        if errors > 0 {
            seen.origin_errors.insert(zone.name.clone(), errors);
        }
    }
    seen
}

// --------------------------------------------------------------- sending ----

/// A delivery error with the channel's secrets taken out (errors may quote
/// the URL they were about).
fn scrub(msg: &str, channel: &AlertChannel) -> String {
    let mut out = msg.to_string();
    if !channel.bot_token.is_empty() {
        out = out.replace(&channel.bot_token, MASK);
    }
    if !channel.url.is_empty() {
        out = out.replace(&channel.url, &mask_url(&channel.url));
        if let Some(pq) = channel.url.parse::<hyper::Uri>().ok().and_then(|u| u.path_and_query().map(|p| p.as_str().to_string())) {
            if pq.len() > 1 {
                out = out.replace(&pq, &format!("/{MASK}"));
            }
        }
    }
    out
}

/// POST `body` as JSON. Never to a private or loopback address, whatever
/// the name resolves to; redirects are not followed.
async fn post(edge: &Edge, url: &str, body: String) -> Result<(), String> {
    use http_body_util::BodyExt;
    let mut target = crate::edge::upstream::Target::from_url(url)?;
    target.block_private_ips = true;
    let uri: hyper::Uri = url.parse().map_err(|_| "invalid URL".to_string())?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(path)
        .header("user-agent", concat!("fucf/", env!("CARGO_PKG_VERSION")))
        .header("content-type", "application/json")
        .body(crate::edge::full(body))
        .map_err(|e| e.to_string())?;
    let exchange = async {
        let resp = edge.upstream.send(&target, req).await.map_err(|e| format!("{e:?}"))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let answer = http_body_util::Limited::new(resp.into_body(), 16 << 10).collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        // Telegram says what was wrong in `description`
        let why = serde_json::from_slice::<Value>(&answer).ok().and_then(|v| v["description"].as_str().map(|d| d.chars().take(200).collect::<String>()));
        Err(match why {
            Some(why) => format!("HTTP {status}: {why}"),
            None => format!("HTTP {status}"),
        })
    };
    tokio::time::timeout(SEND_TIMEOUT, exchange).await.map_err(|_| "timed out".to_string())?
}

/// Deliver one message to a channel. The error says why it did not arrive,
/// without the channel's secrets.
pub async fn send(edge: &Edge, channel: &AlertChannel, text: &str, payload: &Value) -> Result<(), String> {
    let result = match channel.kind.as_str() {
        "webhook" => post(edge, &channel.url, payload.to_string()).await,
        "telegram" => {
            let url = format!("https://api.telegram.org/bot{}/sendMessage", channel.bot_token);
            let body = json!({ "chat_id": channel.chat_id, "text": text, "disable_web_page_preview": true });
            post(edge, &url, body.to_string()).await
        }
        other => Err(format!("unknown kind '{other}'")),
    };
    result.map_err(|e| scrub(&e, channel))
}

/// Send one test message, enabled or not, whatever events it has.
pub async fn send_test(edge: &Edge, channel: &AlertChannel, node: &str) -> Result<(), String> {
    send(edge, channel, &test_text(node), &payload(&[], node, unix_now(), true)).await
}

// --------------------------------------------------------- the running loop ----

/// What the last check found, for `GET /alerts/active`; `None` where no
/// checks run (a node that does not run the panel).
struct Board {
    checked_at: Option<u64>,
    alerts: Vec<Alert>,
}

static BOARD: Mutex<Option<Board>> = Mutex::new(None);

/// The alerts that fire, as the last check left them.
pub fn active() -> Value {
    let board = BOARD.lock().unwrap();
    board_json(board.as_ref())
}

fn board_json(board: Option<&Board>) -> Value {
    match board {
        None => json!({ "evaluating": false, "checked_at": null, "alerts": [] }),
        Some(b) => json!({
            "evaluating": true,
            "checked_at": b.checked_at.map(|t| crate::store::rfc3339(t as i64)),
            "alerts": b.alerts.iter().map(Alert::json).collect::<Vec<_>>(),
        }),
    }
}

/// Check the fleet every [`CHECK_EVERY`] and tell the channels (on the node
/// that runs the panel only: one sender for the fleet).
pub fn spawn(store: Arc<Store>, fleet: Arc<Fleet>, waf: Arc<Waf>, edge: Arc<Edge>, edge_ips: Vec<IpAddr>, node_name: Option<String>) {
    let started = unix_now();
    *BOARD.lock().unwrap() = Some(Board { checked_at: None, alerts: Vec::new() });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut state = AlertState::default();
        loop {
            tick.tick().await;
            if store.is_read_only() {
                continue;
            }
            let now = unix_now();
            let me = crate::fleet::self_name(&store, &edge_ips, node_name.as_deref());
            let seen = observe(&store, &fleet, &waf, &me, now);
            let (next, notices) = evaluate(&state, &seen, now, started);
            state = next;
            *BOARD.lock().unwrap() = Some(Board { checked_at: Some(now), alerts: state.active.values().cloned().collect() });
            if notices.is_empty() {
                continue;
            }
            for (channel, batch) in route(&store.list_alert_channels(), &notices) {
                let body = payload(&batch, &me, now, false);
                if let Err(e) = send(&edge, &channel, &text(&batch, &me), &body).await {
                    tracing::warn!(channel = %channel.name, kind = %channel.kind, "alert not delivered: {e}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    /// Long after the start: no grace.
    const STARTED: u64 = NOW - 3600;

    /// A token of the shape BotFather gives, made up here (never a real one).
    fn fake_token() -> String {
        format!("{}:{}", 12345, "test-token-".repeat(3))
    }

    fn webhook(url: &str, events: &[&str]) -> AlertChannel {
        serde_json::from_value(json!({ "name": "ops", "kind": "webhook", "url": url, "events": events })).unwrap()
    }

    fn telegram(events: &[&str]) -> AlertChannel {
        serde_json::from_value(json!({ "name": "chat", "kind": "telegram", "bot_token": fake_token(), "chat_id": "-1001234", "events": events })).unwrap()
    }

    fn node(name: &str, online: bool, in_sync: bool) -> NodeSeen {
        NodeSeen { name: name.into(), online, in_sync }
    }

    /// Run the checks over `seen` at `times`, from `state`; the notices of each round.
    fn rounds(state: &mut AlertState, seen: &Observed, times: impl IntoIterator<Item = u64>, started: u64) -> Vec<Vec<Notice>> {
        times
            .into_iter()
            .map(|t| {
                let (next, notices) = evaluate(state, seen, t, started);
                *state = next;
                notices
            })
            .collect()
    }

    fn told(notices: &[Notice]) -> Vec<(String, &'static str, bool)> {
        notices.iter().map(|n| (format!("{} {}", n.event, n.subject), n.state, n.repeat)).collect()
    }

    #[test]
    fn a_node_is_offline_only_after_three_missed_checks_in_a_row() {
        let mut state = AlertState::default();
        let down = Observed { nodes: vec![node("eu", false, false), node("us", true, true)], ..Observed::default() };
        let got = rounds(&mut state, &down, [NOW, NOW + 30], STARTED);
        assert!(got.iter().all(Vec::is_empty), "two missed checks are not an outage");
        // it comes back once: the count starts over
        let back = Observed { nodes: vec![node("eu", true, true), node("us", true, true)], ..Observed::default() };
        assert!(rounds(&mut state, &back, [NOW + 60], STARTED)[0].is_empty());
        let got = rounds(&mut state, &down, [NOW + 90, NOW + 120, NOW + 150], STARTED);
        assert!(got[0].is_empty() && got[1].is_empty());
        assert_eq!(told(&got[2]), vec![("node_offline eu".to_string(), "firing", false)]);
        assert!(got[2][0].message.contains("3"));
        // still down: nothing new to tell
        assert!(rounds(&mut state, &down, [NOW + 180], STARTED)[0].is_empty());
        assert_eq!(state.active["node_offline:eu"].since, NOW + 150);
        // back: told once that it is over
        let got = rounds(&mut state, &back, [NOW + 210, NOW + 240], STARTED);
        assert_eq!(told(&got[0]), vec![("node_offline eu".to_string(), "resolved", false)]);
        assert!(got[1].is_empty());
        assert!(state.active.is_empty());
    }

    #[test]
    fn no_node_is_offline_within_two_minutes_of_the_start_and_the_count_starts_after_it() {
        let started = NOW;
        let mut state = AlertState::default();
        let down = Observed { nodes: vec![node("eu", false, false)], ..Observed::default() };
        let got = rounds(&mut state, &down, (0..4).map(|i| NOW + i * 30), started);
        assert!(got.iter().all(Vec::is_empty), "{got:?}");
        assert!(state.offline_checks.is_empty(), "checks within the grace do not count");
        // from the end of the grace: three more checks
        let got = rounds(&mut state, &down, [NOW + 120, NOW + 150, NOW + 180], started);
        assert!(got[0].is_empty() && got[1].is_empty());
        assert_eq!(told(&got[2]), vec![("node_offline eu".to_string(), "firing", false)]);
    }

    #[test]
    fn the_grace_after_the_start_holds_only_for_offline_nodes() {
        let mut state = AlertState::default();
        let seen = Observed { under_attack: vec!["example.com".into()], limited: [("eu".to_string(), "throttled".to_string())].into(), ..Observed::default() };
        let got = rounds(&mut state, &seen, [NOW], NOW);
        assert_eq!(told(&got[0]), vec![("traffic_limit eu".to_string(), "firing", false), ("under_attack example.com".to_string(), "firing", false)]);
    }

    #[test]
    fn a_node_online_with_an_old_configuration_lags_after_five_minutes() {
        let mut state = AlertState::default();
        let lagging = Observed { nodes: vec![node("eu", true, false)], ..Observed::default() };
        let got = rounds(&mut state, &lagging, [NOW, NOW + 150, NOW + 299], STARTED);
        assert!(got.iter().all(Vec::is_empty));
        let got = rounds(&mut state, &lagging, [NOW + 300], STARTED);
        assert_eq!(told(&got[0]), vec![("sync_lagging eu".to_string(), "firing", false)]);
        assert!(got[0][0].message.contains("5 分钟") && got[0][0].message.contains("5 minutes"));
        // caught up
        let fine = Observed { nodes: vec![node("eu", true, true)], ..Observed::default() };
        let got = rounds(&mut state, &fine, [NOW + 330], STARTED);
        assert_eq!(told(&got[0]), vec![("sync_lagging eu".to_string(), "resolved", false)]);
        // lagging again: the five minutes start over
        assert!(rounds(&mut state, &lagging, [NOW + 360, NOW + 600], STARTED).iter().all(Vec::is_empty));
        assert_eq!(rounds(&mut state, &lagging, [NOW + 660], STARTED)[0].len(), 1);
    }

    #[test]
    fn an_offline_node_is_not_also_lagging() {
        let mut state = AlertState::default();
        let down = Observed { nodes: vec![node("eu", false, false)], ..Observed::default() };
        let got = rounds(&mut state, &down, (0..20).map(|i| NOW + i * 30), STARTED);
        let all: Vec<_> = got.iter().flat_map(|n| told(n)).collect();
        assert_eq!(all, vec![("node_offline eu".to_string(), "firing", false)]);
        assert!(state.lagging_since.is_empty());
    }

    fn cert(id: &str, failed: bool, expires_at: Option<u64>) -> CertSeen {
        CertSeen { id: id.into(), zone: "example.com".into(), hosts: vec!["example.com".into(), "*.example.com".into()], failed, error: "the CA said no".into(), expires_at }
    }

    #[test]
    fn a_certificate_fails_when_issuing_failed_or_it_ends_within_fourteen_days() {
        let mut state = AlertState::default();
        let seen = Observed {
            certificates: vec![
                cert("a", true, None),
                cert("b", false, Some(NOW + 13 * 86_400)),
                cert("c", false, Some(NOW + 15 * 86_400)),
                cert("d", false, None),
                cert("e", false, Some(NOW - 10)),
            ],
            ..Observed::default()
        };
        let got = rounds(&mut state, &seen, [NOW], STARTED);
        let keys: Vec<&str> = state.active.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["certificate_failing:a", "certificate_failing:b", "certificate_failing:e"]);
        assert_eq!(got[0].len(), 3);
        assert_eq!(state.active["certificate_failing:a"].level, "failed");
        assert!(state.active["certificate_failing:a"].message.contains("the CA said no"));
        assert_eq!(state.active["certificate_failing:b"].level, "expiring");
        assert!(state.active["certificate_failing:b"].message.contains("13"));
        assert!(state.active["certificate_failing:e"].message.contains("expired"));
        assert_eq!(state.active["certificate_failing:a"].subject, "example.com (example.com, *.example.com)");
        // renewed: over
        let renewed = Observed { certificates: vec![cert("a", false, Some(NOW + 90 * 86_400)), cert("b", false, Some(NOW + 90 * 86_400))], ..Observed::default() };
        let got = rounds(&mut state, &renewed, [NOW + 30], STARTED);
        assert_eq!(got[0].iter().filter(|n| n.state == "resolved").count(), 3, "a, b renewed and e is gone");
        assert!(state.active.is_empty());
    }

    #[test]
    fn a_traffic_tier_fires_and_a_new_tier_is_told_again() {
        let mut state = AlertState::default();
        let at = |tier: &str| Observed { limited: [("eu".to_string(), tier.to_string())].into(), ..Observed::default() };
        let got = rounds(&mut state, &at("dns_limited"), [NOW, NOW + 30], STARTED);
        assert_eq!(told(&got[0]), vec![("traffic_limit eu".to_string(), "firing", false)]);
        assert!(got[1].is_empty());
        let got = rounds(&mut state, &at("limited"), [NOW + 60], STARTED);
        assert_eq!((got[0].len(), got[0][0].state, got[0][0].level.as_str()), (1, "firing", "limited"));
        assert_eq!(state.active["traffic_limit:eu"].since, NOW, "the same alert, a new tier");
        let got = rounds(&mut state, &Observed::default(), [NOW + 90], STARTED);
        assert_eq!(told(&got[0]), vec![("traffic_limit eu".to_string(), "resolved", false)]);
    }

    #[test]
    fn under_attack_fires_while_the_zone_is_switched_and_recovers() {
        let mut state = AlertState::default();
        let on = Observed { under_attack: vec!["example.com".into()], ..Observed::default() };
        let got = rounds(&mut state, &on, [NOW, NOW + 30], STARTED);
        assert_eq!(told(&got[0]), vec![("under_attack example.com".to_string(), "firing", false)]);
        assert!(got[1].is_empty());
        let got = rounds(&mut state, &Observed::default(), [NOW + 60], STARTED);
        assert_eq!(told(&got[0]), vec![("under_attack example.com".to_string(), "resolved", false)]);
    }

    #[test]
    fn origin_errors_fire_at_the_threshold_and_last_until_a_quiet_window() {
        let mut state = AlertState::default();
        let errors = |n: usize| Observed { origin_errors: [("example.com".to_string(), n)].into(), ..Observed::default() };
        assert!(rounds(&mut state, &errors(ORIGIN_ERRORS_THRESHOLD - 1), [NOW], STARTED)[0].is_empty());
        let got = rounds(&mut state, &errors(ORIGIN_ERRORS_THRESHOLD), [NOW + 30], STARTED);
        assert_eq!(told(&got[0]), vec![("origin_errors example.com".to_string(), "firing", false)]);
        // below the threshold but not quiet: still firing, nothing told
        assert!(rounds(&mut state, &errors(1), [NOW + 60], STARTED)[0].is_empty());
        assert!(state.active.contains_key("origin_errors:example.com"));
        assert!(state.active["origin_errors:example.com"].message.contains(" 1 "), "the message follows the count");
        let got = rounds(&mut state, &Observed::default(), [NOW + 90], STARTED);
        assert_eq!(told(&got[0]), vec![("origin_errors example.com".to_string(), "resolved", false)]);
        // and a count below the threshold does not start it again
        assert!(rounds(&mut state, &errors(1), [NOW + 120], STARTED)[0].is_empty());
    }

    #[test]
    fn an_alert_that_lasts_is_told_again_every_six_hours() {
        let mut state = AlertState::default();
        let on = Observed { under_attack: vec!["example.com".into()], ..Observed::default() };
        assert_eq!(rounds(&mut state, &on, [NOW], STARTED)[0].len(), 1);
        assert!(rounds(&mut state, &on, [NOW + 3600, NOW + RESEND_SECS - 1], STARTED).iter().all(Vec::is_empty));
        let got = rounds(&mut state, &on, [NOW + RESEND_SECS], STARTED);
        assert_eq!(told(&got[0]), vec![("under_attack example.com".to_string(), "firing", true)]);
        assert_eq!(got[0][0].since, NOW, "a reminder says since when");
        assert!(rounds(&mut state, &on, [NOW + RESEND_SECS + 30, NOW + 2 * RESEND_SECS - 1], STARTED).iter().all(Vec::is_empty));
        assert_eq!(rounds(&mut state, &on, [NOW + 2 * RESEND_SECS], STARTED)[0].len(), 1);
        // over: told once, not as a repeat
        let got = rounds(&mut state, &Observed::default(), [NOW + 2 * RESEND_SECS + 30], STARTED);
        assert_eq!(told(&got[0]), vec![("under_attack example.com".to_string(), "resolved", false)]);
    }

    #[test]
    fn the_same_inputs_always_give_the_same_answer() {
        let seen = Observed { nodes: vec![node("eu", false, false)], under_attack: vec!["example.net".into()], ..Observed::default() };
        let prev = AlertState::default();
        assert_eq!(evaluate(&prev, &seen, NOW, STARTED), evaluate(&prev, &seen, NOW, STARTED));
        assert_eq!(evaluate(&prev, &Observed::default(), NOW, STARTED), (AlertState::default(), Vec::new()));
    }

    #[test]
    fn each_enabled_channel_gets_the_events_it_asked_for() {
        let mut off = webhook("https://hooks.example.com/a", &["under_attack"]);
        off.enabled = false;
        let channels = vec![webhook("https://hooks.example.com/b", &["under_attack", "node_offline"]), telegram(&["traffic_limit"]), off];
        let mut state = AlertState::default();
        let seen = Observed { under_attack: vec!["example.com".into()], nodes: vec![], ..Observed::default() };
        let notices = rounds(&mut state, &seen, [NOW], STARTED).remove(0);
        let routed = route(&channels, &notices);
        assert_eq!(routed.len(), 1, "the telegram channel asked for other events, the third is off");
        assert_eq!(routed[0].0.url, "https://hooks.example.com/b");
        assert_eq!(routed[0].1.len(), 1);
        assert!(route(&channels, &[]).is_empty());
    }

    #[test]
    fn the_message_lists_what_happened_and_stays_within_telegram_limits() {
        let mut state = AlertState::default();
        let zones: Vec<String> = (0..40).map(|i| format!("z{i}.example.com")).collect();
        let notices = rounds(&mut state, &Observed { under_attack: zones, ..Observed::default() }, [NOW], STARTED).remove(0);
        let t = text(&notices, "eu");
        assert!(t.starts_with("fucf 告警 · alerts from eu"));
        assert!(t.contains("触发 · FIRING under_attack z0.example.com"));
        let listed = t.matches("FIRING under_attack").count();
        assert!((1..=MAX_LINES).contains(&listed), "{listed}");
        assert!(t.contains(&format!("and {} more", 40 - listed)), "{t}");
        assert!(t.chars().count() <= MAX_TEXT);
        let p = payload(&notices, "eu", NOW, false);
        assert_eq!((p["alerts"].as_array().unwrap().len(), p["test"].clone(), p["node"].clone()), (40, json!(false), json!("eu")));
        assert_eq!(p["alerts"][0]["state"], "firing");
        assert_eq!(p["alerts"][0]["since"], crate::store::rfc3339(NOW as i64));
        let resolved = rounds(&mut state, &Observed::default(), [NOW + 30], STARTED).remove(0);
        assert!(text(&resolved, "eu").contains("已恢复 · RESOLVED under_attack"));
        let t = payload(&[], "eu", NOW, true);
        assert_eq!((t["test"].clone(), t["alerts"].clone()), (json!(true), json!([])));
        // a very long message is cut
        let long = Notice { event: "origin_errors".into(), subject: "example.com".into(), state: "firing", repeat: false, level: String::new(), message: "x".repeat(10_000), since: NOW, at: NOW };
        assert_eq!(text(&[long], "eu").chars().count(), MAX_TEXT);
    }

    #[test]
    fn a_webhook_channel_is_checked_before_it_is_kept() {
        let ok = |url: &str| webhook(url, &["node_offline"]).validate(None);
        assert!(ok("https://hooks.example.com/services/T000/B000/test").is_ok());
        assert!(ok("https://hooks.example.com:8443/x?key=test").is_ok());
        assert!(ok("https://198.51.100.7/hook").is_ok());
        for bad in [
            "",
            "http://hooks.example.com/x",
            "ftp://hooks.example.com/x",
            "javascript:alert(1)",
            "hooks.example.com/x",
            "https://",
            "https://user:pass@hooks.example.com/x",
            "https://localhost/x",
            "https://a.localhost/x",
            "https://intranet/x",
            "https://127.0.0.1/x",
            "https://10.1.2.3/x",
            "https://192.168.1.1/x",
            "https://169.254.169.254/latest",
            "https://[::1]/x",
            "https://[fd00::1]/x",
            "https://0.0.0.0/x",
            "https://224.0.0.1/x",
            "https://hooks.example.com/***",
            "https://hooks.example.com/a b",
            "https://hooks.example.com:0/x",
        ] {
            assert!(ok(bad).is_err(), "{bad} was taken");
        }
        assert!(ok(&format!("https://hooks.example.com/{}", "a".repeat(2100))).is_err());
        let mut c = webhook("  https://hooks.example.com/x  ", &["origin_errors", "node_offline", "origin_errors"]);
        c.validate(None).unwrap();
        assert_eq!(c.url, "https://hooks.example.com/x");
        assert_eq!(c.events, vec!["node_offline", "origin_errors"], "in the order of the list, each once");
    }

    #[test]
    fn a_channel_needs_a_name_a_known_kind_and_known_events() {
        let check = |v: Value| serde_json::from_value::<AlertChannel>(v).unwrap().validate(None).map_err(|e| format!("{e:?}"));
        let base = json!({ "name": "ops", "kind": "webhook", "url": "https://hooks.example.com/x", "events": ["node_offline"] });
        assert!(check(base.clone()).is_ok());
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            b
        };
        assert!(check(with("name", json!("  "))).unwrap_err().contains("name"));
        assert!(check(with("name", json!("x".repeat(65)))).is_err());
        assert!(check(with("name", json!("a\nb"))).is_err());
        assert!(check(with("kind", json!(""))).unwrap_err().contains("kind is required"));
        assert!(check(with("kind", json!("email"))).unwrap_err().contains("unknown kind"));
        assert!(check(with("events", json!([]))).unwrap_err().contains("at least one"), "a channel told of nothing is refused");
        assert!(check(with("events", json!(["node_offline", "everything"]))).unwrap_err().contains("unknown event 'everything'"));
        assert!(check(with("events", json!([""]))).is_err());
        let mut upper = serde_json::from_value::<AlertChannel>(with("kind", json!(" WebHook "))).unwrap();
        upper.validate(None).unwrap();
        assert_eq!(upper.kind, "webhook");
        assert!(upper.enabled, "a new channel is on unless it says otherwise");
    }

    #[test]
    fn a_telegram_channel_needs_a_token_and_a_chat_of_the_right_shape() {
        let check = |token: &str, chat: &str| {
            serde_json::from_value::<AlertChannel>(json!({ "name": "c", "kind": "telegram", "bot_token": token, "chat_id": chat, "events": ["under_attack"] }))
                .unwrap()
                .validate(None)
        };
        let token = fake_token();
        for chat in ["-1001234", "42", "@example_alerts"] {
            assert!(check(&token, chat).is_ok(), "{chat}");
        }
        for chat in ["", "-", "@ab", "@1abc", "@bad-name", "12a", "--1", &"9".repeat(21)] {
            assert!(check(&token, chat).is_err(), "{chat}");
        }
        for bad in ["", MASK, "12345", ":test-token-test-token-test-token-", "abc:test-token-test-token-test-token-", "12345:short", "12345:test token test token test token", &format!("12345:{}", "a".repeat(101))] {
            assert!(check(bad, "42").is_err(), "{bad}");
        }
        let mut c = telegram(&["under_attack"]);
        c.url = "https://hooks.example.com/left-over".into();
        c.validate(None).unwrap();
        assert!(c.url.is_empty(), "nothing of another kind is kept");
    }

    #[test]
    fn secrets_never_show_in_what_the_api_returns() {
        let mut hook = webhook("https://hooks.example.com/services/T000/B000/test-secret?sig=test-sig", &["node_offline"]);
        hook.validate(None).unwrap();
        let shown = hook.public().to_string();
        assert!(!shown.contains("test-secret") && !shown.contains("test-sig"), "{shown}");
        assert_eq!(hook.public()["url"], "https://hooks.example.com/***");
        assert_eq!(hook.public()["bot_token"], "");
        assert!(hook.public().get("sync").is_none());
        let mut tg = telegram(&["node_offline"]);
        tg.validate(None).unwrap();
        let shown = tg.public().to_string();
        assert!(!shown.contains(&fake_token()) && !shown.contains("test-token"), "{shown}");
        assert_eq!(tg.public()["bot_token"], MASK);
        assert_eq!(tg.public()["chat_id"], "-1001234", "the chat is no secret");
        assert_eq!(mask_url("https://hooks.example.com:8443/x"), "https://hooks.example.com:8443/***");
        assert_eq!(mask_url("not a url"), MASK);
    }

    #[test]
    fn a_masked_secret_sent_back_keeps_the_stored_one() {
        let mut stored = webhook("https://hooks.example.com/services/test-secret", &["node_offline"]);
        stored.validate(None).unwrap();
        // what the panel was shown, sent back with another name
        let mut back: AlertChannel = serde_json::from_value(stored.public()).unwrap();
        back.name = "renamed".into();
        back.validate(Some(&stored)).unwrap();
        assert_eq!((back.url.as_str(), back.name.as_str()), ("https://hooks.example.com/services/test-secret", "renamed"));
        // empty keeps it too
        back.url.clear();
        back.validate(Some(&stored)).unwrap();
        assert_eq!(back.url, stored.url);
        // a new URL replaces it
        back.url = "https://hooks.example.net/other".into();
        back.validate(Some(&stored)).unwrap();
        assert_eq!(back.url, "https://hooks.example.net/other");
        // a mask of another host is not the stored URL, and is refused rather than kept as is
        back.url = "https://hooks.example.net/***".into();
        assert!(back.validate(Some(&stored)).is_err());
        // with no stored channel, a mask is no URL
        let mut fresh: AlertChannel = serde_json::from_value(stored.public()).unwrap();
        assert!(fresh.validate(None).is_err());

        let mut tg = telegram(&["node_offline"]);
        tg.validate(None).unwrap();
        let mut back: AlertChannel = serde_json::from_value(tg.public()).unwrap();
        assert_eq!(back.bot_token, MASK);
        back.chat_id = "@example_alerts".into();
        back.validate(Some(&tg)).unwrap();
        assert_eq!((back.bot_token.as_str(), back.chat_id.as_str()), (fake_token().as_str(), "@example_alerts"));
        back.bot_token.clear();
        back.validate(Some(&tg)).unwrap();
        assert_eq!(back.bot_token, fake_token());
        // switching kind keeps no secret of the old kind, and the new one needs its own
        let mut switched: AlertChannel = serde_json::from_value(tg.public()).unwrap();
        switched.kind = "webhook".into();
        assert!(switched.validate(Some(&tg)).is_err(), "no url");
        switched.url = "https://hooks.example.com/x".into();
        switched.validate(Some(&tg)).unwrap();
        assert!(switched.bot_token.is_empty() && switched.chat_id.is_empty());
        let mut to_tg: AlertChannel = serde_json::from_value(stored.public()).unwrap();
        (to_tg.kind, to_tg.chat_id, to_tg.bot_token) = ("telegram".into(), "42".into(), MASK.into());
        assert!(to_tg.validate(Some(&stored)).is_err(), "a webhook has no token to keep");
    }

    #[test]
    fn delivery_errors_carry_no_secret() {
        let mut tg = telegram(&["node_offline"]);
        tg.validate(None).unwrap();
        let msg = format!("cannot reach https://api.telegram.org/bot{}/sendMessage", tg.bot_token);
        let clean = scrub(&msg, &tg);
        assert!(!clean.contains(&tg.bot_token), "{clean}");
        let hook = webhook("https://hooks.example.com/services/test-secret?sig=test-sig", &["node_offline"]);
        let clean = scrub("POST https://hooks.example.com/services/test-secret?sig=test-sig failed; /services/test-secret?sig=test-sig", &hook);
        assert!(!clean.contains("test-secret") && !clean.contains("test-sig"), "{clean}");
    }

    fn temp_store(tag: &str) -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!("fucf-alerts-{tag}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("store.json"), vec![]).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn a_webhook_never_reaches_a_private_address_even_if_one_was_stored() {
        let (dir, store) = temp_store("ssrf");
        let edge = Edge::new(Arc::new(store), Arc::new(crate::edge::cache::Cache::new(1 << 20)), Arc::new(Waf::new()), vec![]).unwrap();
        // bypassing the checks on purpose: the sender guards on its own
        let hook = webhook("https://127.0.0.1:9/services/test-secret", &["node_offline"]);
        let err = send(&edge, &hook, "x", &json!({})).await.unwrap_err();
        assert!(!err.contains("test-secret"), "{err}");
        assert!(err.contains("refusing") || err.contains("private"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn what_is_observed_comes_from_the_fleet_the_store_and_the_events() {
        let (dir, store) = temp_store("observe");
        let now = unix_now();
        for (i, (name, enabled)) in [("au", true), ("eu", true), ("us", true), ("off", false)].into_iter().enumerate() {
            store.save_node_async(None, json!({ "name": name, "enabled": enabled, "ipv4": format!("192.0.2.{}", i + 1) })).await.unwrap();
        }
        let zone = store.create_zone("example.com").unwrap();
        let other = store.create_zone("example.net").unwrap();
        store.update_setting(&other.id, "security_level", json!("under_attack")).unwrap();
        store.update_setting(&other.id, "auto_level_until", json!(now + 3600)).unwrap();
        // under attack by hand: not the automatic switch
        store.update_setting(&zone.id, "security_level", json!("under_attack")).unwrap();
        let pack = store.save_item_async::<CertificatePack>(&zone.id, None, json!({}), true).await.unwrap();
        store.update_pack(&pack.meta.id, |p| (p.status, p.error) = ("failed".into(), "the CA said no".into())).unwrap();
        store.record_peer_telemetry_async("eu".into(), crate::limits::State::Throttled, 0, None).await.unwrap();
        let waf = Waf::new();
        let event = |at: u64, source: &str| crate::edge::waf::Event {
            ray_id: "r".into(),
            occurred_at: crate::store::rfc3339(at as i64),
            zone_id: zone.id.clone(),
            source: source.into(),
            rule_id: "502".into(),
            description: String::new(),
            action: "origin_error".into(),
            client_ip: "203.0.113.9".into(),
            country: String::new(),
            node: String::new(),
            host: "example.com".into(),
            method: "GET".into(),
            uri: "/".into(),
            user_agent: String::new(),
            asn: 0,
            threat: 0,
        };
        waf.absorb("eu", vec![event(now, "origin"), event(now - 60, "origin"), event(now - 400, "origin"), event(now, "firewall")]);

        // (after the last change: what eu runs is the version now)
        let fleet = Fleet::default();
        fleet.seen("eu", &store.version(), "test");
        fleet.seen("us", "an-older-version", "test");
        let seen = observe(&store, &fleet, &waf, "au", now);
        assert_eq!(seen.nodes, vec![node("eu", true, true), node("us", true, false)], "itself and disabled nodes are not checked; au never asked about");
        let fleet_quiet = observe(&store, &Fleet::default(), &waf, "au", now);
        assert_eq!(fleet_quiet.nodes, vec![node("eu", false, false), node("us", false, false)], "never heard of is offline");
        assert_eq!(seen.under_attack, vec!["example.net".to_string()]);
        assert_eq!(seen.certificates.len(), 1);
        assert!(seen.certificates[0].failed && seen.certificates[0].zone == "example.com" && seen.certificates[0].error == "the CA said no");
        assert_eq!(seen.limited, [("eu".to_string(), "throttled".to_string())].into());
        assert_eq!(seen.origin_errors, [("example.com".to_string(), 2)].into(), "within five minutes, origin events only");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn channels_are_kept_in_the_store_with_their_secrets_and_a_limit() {
        let (dir, store) = temp_store("store");
        let version = store.version();
        let c = store
            .save_alert_channel_async(None, json!({ "name": "ops", "kind": "webhook", "url": "https://hooks.example.com/test-secret", "events": ["node_offline"] }))
            .await
            .unwrap();
        assert_ne!(store.version(), version);
        assert!(!c.id.is_empty() && !c.created_on.is_empty());
        // the panel sends back what it was shown
        let back = store.save_alert_channel_async(Some(&c.id), json!({ "url": mask_url(&c.url), "name": "ops 2" })).await.unwrap();
        assert_eq!((back.url.as_str(), back.name.as_str(), back.created_on.as_str()), ("https://hooks.example.com/test-secret", "ops 2", c.created_on.as_str()));
        assert_eq!(store.get_alert_channel(&c.id).unwrap().url, "https://hooks.example.com/test-secret");
        assert!(matches!(store.save_alert_channel_async(Some("no-such-id"), json!({ "name": "x" })).await, Err(StoreError::NotFound)));
        assert!(matches!(store.save_alert_channel_async(None, json!(["not", "an", "object"])).await, Err(StoreError::Invalid(_))));
        assert!(matches!(store.save_alert_channel_async(Some(&c.id), json!({ "events": ["bogus"] })).await, Err(StoreError::Invalid(_))));
        assert_eq!(store.get_alert_channel(&c.id).unwrap().events, vec!["node_offline"], "a refused change changes nothing");
        for i in 1..MAX_CHANNELS {
            store.save_alert_channel_async(None, json!({ "name": format!("c{i}"), "kind": "webhook", "url": "https://hooks.example.com/x", "events": ["node_offline"] })).await.unwrap();
        }
        let over = store.save_alert_channel_async(None, json!({ "name": "one too many", "kind": "webhook", "url": "https://hooks.example.com/x", "events": ["node_offline"] })).await;
        assert!(matches!(over, Err(StoreError::Invalid(_))));
        // changing one is still fine at the limit
        store.save_alert_channel_async(Some(&c.id), json!({ "enabled": false })).await.unwrap();
        store.delete_alert_channel_async(&c.id).await.unwrap();
        assert!(store.get_alert_channel(&c.id).is_none());
        assert!(matches!(store.delete_alert_channel_async(&c.id).await, Err(StoreError::NotFound)));
        assert_eq!(store.list_alert_channels().len(), MAX_CHANNELS - 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_fleet_without_channels_has_the_configuration_version_it_always_had() {
        // older nodes know nothing of channels: an empty list must not change the fingerprint
        let data = crate::store::Data::default();
        let text = serde_json::to_string(&data).unwrap();
        assert!(!text.contains("alert_channels"), "{text}");
    }

    #[test]
    fn the_active_alerts_say_whether_this_node_checks_at_all() {
        assert_eq!(board_json(None), json!({ "evaluating": false, "checked_at": null, "alerts": [] }));
        let mut state = AlertState::default();
        rounds(&mut state, &Observed { under_attack: vec!["example.com".into()], ..Observed::default() }, [NOW], STARTED);
        let b = Board { checked_at: Some(NOW), alerts: state.active.values().cloned().collect() };
        let v = board_json(Some(&b));
        assert_eq!(v["evaluating"], true);
        assert_eq!(v["alerts"][0]["key"], "under_attack:example.com");
        assert_eq!(v["alerts"][0]["since"], crate::store::rfc3339(NOW as i64));
    }
}
