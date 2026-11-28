//! Page Shield: which scripts the pages of a zone load.
//!
//! With the zone setting `page_shield.enabled`, every HTML answer of the
//! zone carries a Content Security Policy, in report-only mode unless the
//! zone asks for `enforce`. The policy is the zone's own (validated, see
//! [`PageShieldSettings::validate`]) or [`DEFAULT_POLICY`], which reports
//! every script a page loads and blocks none of them. The edge adds where
//! the reports go: `report-uri` [`REPORT_PATH`] on the page's own host, and
//! over HTTPS also `report-to`, with a `Reporting-Endpoints` header naming the
//! same path. Browsers send the first as CSP level 2 `application/csp-report`
//! and the second as Reporting API `application/reports+json`; both are taken.
//!
//! An origin's own `Content-Security-Policy` or `-Report-Only` header is
//! never replaced: ours is one more header line, and a browser applies every
//! policy it is given, each on its own. Where the origin already sends
//! `Reporting-Endpoints`, ours is left out (and with it `report-to`), so that
//! a header of the origin's we cannot read cannot take our reports with it.
//!
//! The report endpoint is public by nature (anybody can post anything to
//! it), so it takes little and keeps less: a body of at most [`MAX_BODY`],
//! [`RATE_PER_IP`] reports a minute per address (IPv6 per /64), only
//! violations of `script-src*` on a page of the very host the report was
//! posted to, and of a script only `scheme://host[:port]/path`: never its
//! query, fragment or user info. A zone keeps at most [`MAX_SCRIPTS`] scripts;
//! a new one makes room by letting go of the one seen longest ago.
//!
//! Where the list lives: like the analytics (crate::edge::stats), not like
//! configuration. Every node counts what its visitors report in memory; what
//! changed since its last report goes out with its next one (crate::reports,
//! every 15 to 60 seconds, counted once however it travels), and every peer
//! merges it into its own list (earliest first sight, latest last sight, the
//! counts added up) and writes that list to `page-shield.json` in its data
//! directory together with the analytics. Store items would make every new
//! script and every count a configuration write replicated to every node,
//! and an accelerate node cannot write the store at all; the reports channel
//! already carries this kind of data, batched and deduplicated.
//!
//! A script seen for the first time can raise the `new_script` alert
//! (crate::alerts), for zones that opt in with `page_shield.alerts`.

use super::{full, Body, Edge};
use crate::store::{Store, StoreError};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Where the zone's pages send their reports (on their own host).
pub const REPORT_PATH: &str = "/cdn-cgi/script_monitor/report";
/// The name `report-to` uses, and the `Reporting-Endpoints` header that defines it.
const ENDPOINT_NAME: &str = "fucf-page-shield";
const ENDPOINTS_VALUE: &str = "fucf-page-shield=\"/cdn-cgi/script_monitor/report\"";
const REPORTING_ENDPOINTS: &str = "reporting-endpoints";
/// The policy of a zone that sets none: every script is reported, none blocked.
pub const DEFAULT_POLICY: &str = "script-src 'none'";
/// How the policy is sent: `report_only` (the default) or `enforce`.
pub const MODES: [&str; 2] = ["report_only", "enforce"];
/// Bytes of a zone's policy.
pub const MAX_POLICY: usize = 2048;
/// Directives in a zone's policy.
const MAX_DIRECTIVES: usize = 32;
/// Bytes of one report body.
pub const MAX_BODY: usize = 64 * 1024;
/// Violations read from one body (the Reporting API sends them in batches).
const MAX_VIOLATIONS: usize = 100;
/// Scripts kept per zone.
pub const MAX_SCRIPTS: usize = 2000;
/// Scripts kept on a node, all zones together (a bound on its memory).
const MAX_TOTAL: usize = 100_000;
/// Bytes of a kept script URL.
const MAX_URL: usize = 1024;
/// Reports one address (an IPv6 /64) may post in [`RATE_WINDOW`] seconds.
pub const RATE_PER_IP: u32 = 120;
const RATE_WINDOW: u64 = 60;
/// Addresses counted at once; when there are more, new ones are refused
/// until the window turns (a flood is not let in by its own size).
const MAX_CLIENTS: usize = 10_000;
/// A script not seen for this long is forgotten.
const RETENTION_SECS: u64 = 30 * 86_400;
/// Scripts waiting to be told to the other nodes.
const MAX_OUTBOX: usize = 5_000;
/// Scripts one report tells (the rest wait for the next one).
const REPORT_BATCH: usize = 1_000;
/// A script first seen this recently is new, for the alert.
pub const ALERT_WINDOW: u64 = 3600;
/// How far ahead of this node's clock another node's times may be.
const SKEW_SECS: u64 = 300;

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

// ----------------------------------------------------------- settings ----

/// The zone setting `page_shield`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PageShieldSettings {
    /// Send the policy with the zone's HTML answers and take their reports.
    pub enabled: bool,
    /// One of [`MODES`].
    pub mode: String,
    /// The zone's policy without `report-uri` / `report-to` (the edge adds
    /// them); empty: [`DEFAULT_POLICY`].
    pub policy: String,
    /// Raise the `new_script` alert when a script is first seen.
    pub alerts: bool,
}

impl Default for PageShieldSettings {
    fn default() -> Self {
        PageShieldSettings { enabled: false, mode: MODES[0].into(), policy: String::new(), alerts: false }
    }
}

impl PageShieldSettings {
    /// Checked as part of the zone's settings, whichever way they are written.
    pub fn validate(&self) -> Result<(), StoreError> {
        if !MODES.contains(&self.mode.as_str()) {
            return invalid(format!("page_shield.mode is one of: {}", MODES.join(", ")));
        }
        if !self.policy.trim().is_empty() {
            directives(&self.policy).map_err(|e| StoreError::Invalid(format!("page_shield.policy: {e}")))?;
        } else if self.mode == "enforce" {
            // the default reports every script: enforced, it would block them all
            return invalid("page_shield.mode enforce needs a policy of the zone's own");
        }
        Ok(())
    }

    fn enforced(&self) -> bool {
        self.mode == "enforce"
    }

    /// The header the policy goes in.
    pub fn header_name(&self) -> HeaderName {
        if self.enforced() {
            header::CONTENT_SECURITY_POLICY
        } else {
            header::CONTENT_SECURITY_POLICY_REPORT_ONLY
        }
    }
}

/// A policy's directives, each written one way (single spaces, no empty
/// ones). One policy only: no commas (they separate policies in a header),
/// printable ASCII only (no line breaks: it goes into a header), and no
/// `report-uri` / `report-to` of its own.
fn directives(policy: &str) -> Result<Vec<String>, String> {
    if policy.len() > MAX_POLICY {
        return Err(format!("at most {MAX_POLICY} bytes"));
    }
    if !policy.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err("printable ASCII only, on one line".into());
    }
    if policy.contains(',') {
        return Err("one policy only: no commas".into());
    }
    let mut out = Vec::new();
    for piece in policy.split(';') {
        let words: Vec<&str> = piece.split(' ').filter(|w| !w.is_empty()).collect();
        let Some(name) = words.first() else { continue };
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("'{name}' is not a directive name"));
        }
        if name.eq_ignore_ascii_case("report-uri") || name.eq_ignore_ascii_case("report-to") {
            return Err("the edge adds report-uri and report-to itself".into());
        }
        out.push(words.join(" "));
    }
    if out.is_empty() {
        return Err("no directive".into());
    }
    if out.len() > MAX_DIRECTIVES {
        return Err(format!("at most {MAX_DIRECTIVES} directives"));
    }
    Ok(out)
}

/// The value of the policy header: the zone's directives (or the default)
/// and where reports go; `report_to` adds the Reporting API's way.
pub fn header_value(s: &PageShieldSettings, report_to: bool) -> Option<String> {
    let mut parts = if s.policy.trim().is_empty() { vec![DEFAULT_POLICY.to_string()] } else { directives(&s.policy).ok()? };
    parts.push(format!("report-uri {REPORT_PATH}"));
    if report_to {
        parts.push(format!("report-to {ENDPOINT_NAME}"));
    }
    Some(parts.join("; "))
}

/// Add the zone's policy to an answer that is HTML (whatever its status).
/// Headers the origin set stay as they are (see the module's notes); the
/// Reporting API is offered over HTTPS only (its endpoints must be secure).
pub fn apply(resp: &mut Response<Body>, s: &PageShieldSettings, ssl: bool) {
    if !s.enabled {
        return;
    }
    let html = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|t| t.trim_start().to_ascii_lowercase().starts_with("text/html"));
    if !html {
        return;
    }
    let report_to = ssl && !resp.headers().contains_key(REPORTING_ENDPOINTS);
    let Some(text) = header_value(s, report_to) else { return };
    let Ok(value) = HeaderValue::from_str(&text) else { return };
    resp.headers_mut().append(s.header_name(), value);
    if report_to {
        resp.headers_mut().insert(REPORTING_ENDPOINTS, HeaderValue::from_static(ENDPOINTS_VALUE));
    }
}

/// `GET /zones/{id}/page_shield`.
pub fn view(s: &PageShieldSettings) -> Value {
    json!({
        "enabled": s.enabled,
        "mode": s.mode,
        "policy": s.policy,
        "alerts": s.alerts,
        "header": s.header_name().as_str(),
        "effective_policy": header_value(s, true),
        "report_uri": REPORT_PATH,
    })
}

/// The settings after `PATCH /zones/{id}/page_shield` (or Cloudflare's PUT):
/// the fields given replace the stored ones. Cloudflare's two flags about
/// its own reporting endpoint are taken and have no effect here; anything
/// else unknown is refused.
pub fn patch(current: &PageShieldSettings, body: &Value) -> Result<PageShieldSettings, StoreError> {
    let Some(fields) = body.as_object() else { return invalid("the body is a JSON object") };
    let mut next = current.clone();
    for (key, value) in fields {
        match key.as_str() {
            "enabled" | "alerts" | "use_cloudflare_reporting_endpoint" | "use_connection_url_path" => {
                let Some(on) = value.as_bool() else { return invalid(format!("{key} is true or false")) };
                match key.as_str() {
                    "enabled" => next.enabled = on,
                    "alerts" => next.alerts = on,
                    _ => {}
                }
            }
            "mode" => next.mode = value.as_str().ok_or_else(|| StoreError::Invalid("mode is a string".into()))?.trim().to_string(),
            "policy" => {
                next.policy = match value {
                    Value::Null => String::new(),
                    Value::String(s) => s.trim().to_string(),
                    _ => return invalid("policy is a string, or null for the default"),
                }
            }
            other => return invalid(format!("unknown field '{other}' (known: enabled, mode, policy, alerts)")),
        }
    }
    next.validate()?;
    Ok(next)
}

// ------------------------------------------------------------ reports ----

/// One violation, as either report format tells it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Violation {
    pub document: String,
    pub blocked: String,
    pub directive: String,
}

/// Why a report was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Method,
    TooLarge,
    MediaType,
    Unreadable,
    TooMany,
}

impl Refusal {
    fn status(self) -> StatusCode {
        match self {
            Refusal::Method => StatusCode::METHOD_NOT_ALLOWED,
            Refusal::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Refusal::MediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Refusal::Unreadable => StatusCode::BAD_REQUEST,
            Refusal::TooMany => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}

/// A CSP level 2 report: `{"csp-report": {"document-uri", "blocked-uri", ...}}`.
fn csp2(v: &Value) -> Option<Violation> {
    let r = v.get("csp-report").filter(|r| r.is_object())?;
    let directive = Some(text(r, "effective-directive")).filter(|d| !d.is_empty()).unwrap_or_else(|| text(r, "violated-directive"));
    Some(Violation { document: text(r, "document-uri"), blocked: text(r, "blocked-uri"), directive })
}

/// A Reporting API batch: `[{"type": "csp-violation", "url", "body": {"documentURL", "blockedURL", ...}}]`;
/// reports of other types are passed over.
fn reporting(items: &[Value]) -> Vec<Violation> {
    items
        .iter()
        .take(MAX_VIOLATIONS)
        .filter(|item| item["type"] == "csp-violation")
        .filter_map(|item| {
            let b = item.get("body").filter(|b| b.is_object())?;
            let document = Some(text(b, "documentURL")).filter(|d| !d.is_empty()).unwrap_or_else(|| text(item, "url"));
            let directive = Some(text(b, "effectiveDirective")).filter(|d| !d.is_empty()).unwrap_or_else(|| text(b, "violatedDirective"));
            Some(Violation { document, blocked: text(b, "blockedURL"), directive })
        })
        .collect()
}

/// Is this a media type a report comes as? (`application/json` too: some
/// browsers have sent CSP reports as that; it is read by its shape.)
fn accepted(media: &str) -> bool {
    matches!(media, "application/csp-report" | "application/reports+json" | "application/json")
}

/// The violations in a report body of type `media`.
pub fn violations(media: &str, body: &[u8]) -> Result<Vec<Violation>, Refusal> {
    if !accepted(media) {
        return Err(Refusal::MediaType);
    }
    let v: Value = serde_json::from_slice(body).map_err(|_| Refusal::Unreadable)?;
    match (media, &v) {
        ("application/csp-report" | "application/json", Value::Object(_)) => csp2(&v).map(|one| vec![one]).ok_or(Refusal::Unreadable),
        ("application/reports+json" | "application/json", Value::Array(items)) => Ok(reporting(items)),
        _ => Err(Refusal::Unreadable),
    }
}

/// Does the directive concern scripts? (`script-src`, `script-src-elem`,
/// `script-src-attr`; CSP 2 may name it with its value.)
fn is_script(directive: &str) -> bool {
    directive.split(' ').next().unwrap_or_default().to_ascii_lowercase().starts_with("script-src")
}

/// An http(s) URL, taken apart.
#[derive(Debug, PartialEq)]
struct Url {
    scheme: &'static str,
    /// Lowercase; an IP address as `IpAddr` writes it (IPv6 without brackets).
    host: String,
    v6: bool,
    /// Only one that is not the scheme's default.
    port: Option<u16>,
    path: String,
}

impl Url {
    /// What is kept of a script: `scheme://host[:port]/path`.
    fn kept(&self) -> String {
        let host = if self.v6 { format!("[{}]", self.host) } else { self.host.clone() };
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("{}://{host}{port}{}", self.scheme, self.path)
    }
}

/// A byte that may stand in a URL path as browsers write it (RFC 3986:
/// unreserved, sub-delims, `:`, `@`, `/` and percent escapes): nothing else
/// is kept, so a kept URL is safe to show anywhere as text.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/%".contains(&b)
}

fn host_and_port(hostport: &str) -> Option<(String, bool, Option<&str>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let addr: Ipv6Addr = inside.parse().ok()?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        return Some((addr.to_string(), true, port));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (hostport, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || host.split('.').any(|label| label.is_empty() || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
        return None;
    }
    let host = host.parse::<Ipv4Addr>().map(|a| a.to_string()).unwrap_or(host);
    Some((host, false, port))
}

fn parse_url(raw: &str) -> Option<Url> {
    let raw = raw.trim();
    if raw.len() > 8 * MAX_URL {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    let (scheme, default_port): (&'static str, u16) = match scheme.to_ascii_lowercase().as_str() {
        "http" => ("http", 80),
        "https" => ("https", 443),
        _ => return None,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, v6, port) = host_and_port(hostport)?;
    let port = match port {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) && p.len() <= 5 => Some(p.parse::<u16>().ok().filter(|&p| p != 0)?),
        Some(_) => return None,
    }
    .filter(|&p| p != default_port);
    let path = &tail[..tail.find(['?', '#']).unwrap_or(tail.len())];
    let path = if path.is_empty() { "/" } else { path };
    if !path.bytes().all(path_byte) {
        return None;
    }
    Some(Url { scheme, host, v6, port, path: path.to_string() })
}

/// What is kept of a script's URL: `scheme://host[:port]/path`, without user
/// info, query or fragment; nothing for what is not an http(s) URL
/// (`inline`, `eval`, `data:`, ...).
pub fn script_url(raw: &str) -> Option<String> {
    Some(parse_url(raw)?.kept()).filter(|u| u.len() <= MAX_URL)
}

/// The scripts a report tells of, for pages of `host` (the host it was
/// posted to: a page of another host is not the zone's to report). Each
/// once; the edge's own scripts under `/cdn-cgi/` are left out.
pub fn scripts_of(host: &str, list: &[Violation]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for v in list {
        if !is_script(&v.directive) || parse_url(&v.document).is_none_or(|d| d.host != host) {
            continue;
        }
        let Some(script) = parse_url(&v.blocked) else { continue };
        if script.host == host && script.path.starts_with("/cdn-cgi/") {
            continue;
        }
        let url = script.kept();
        if url.len() <= MAX_URL {
            out.insert(url);
        }
    }
    out.into_iter().collect()
}

// ---------------------------------------------------------- the list ----

/// What is known of one script of a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// When it was first and last reported (unix seconds).
    pub first: u64,
    pub last: u64,
    /// Reports of it.
    pub count: u64,
}

impl Seen {
    fn once(at: u64) -> Seen {
        Seen { first: at, last: at, count: 1 }
    }

    fn merge(&mut self, other: Seen) {
        self.first = self.first.min(other.first);
        self.last = self.last.max(other.last);
        self.count = self.count.saturating_add(other.count);
    }
}

/// One script as a node tells the others: what it saw since its last report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptSeen {
    pub zone: String,
    pub url: String,
    pub first: u64,
    pub last: u64,
    pub count: u64,
}

impl ScriptSeen {
    /// What another node tells, if it makes sense: a zone id, a URL as this
    /// node would keep it, and times that are not in the future.
    fn checked(&self, now: u64) -> Option<Seen> {
        let zone_ok = !self.zone.is_empty() && self.zone.len() <= 64 && self.zone.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        let url_ok = script_url(&self.url).as_deref() == Some(self.url.as_str());
        let times_ok = self.first > 0 && self.first <= self.last && self.last <= now.saturating_add(SKEW_SECS);
        (zone_ok && url_ok && times_ok && self.count > 0).then(|| Seen { first: self.first, last: self.last, count: self.count.min(1 << 40) })
    }
}

/// `scripts` of a report, taken leniently (like `rate`, see
/// crate::edge::fleetrate::lenient): what cannot be read is left out
/// without failing the report.
pub fn lenient<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<ScriptSeen>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(items) => items.into_iter().take(REPORT_BATCH).filter_map(|v| serde_json::from_value(v).ok()).collect(),
        _ => Vec::new(),
    })
}

type Tables = HashMap<String, HashMap<String, Seen>>;

/// Put what was seen of `url` into the zone's table: merged with what is
/// there, or added. A full table (or a node at [`MAX_TOTAL`]) makes room by
/// letting go of the zone's script seen longest ago (of those, the one
/// reported least), unless that one was seen more lately than this one.
/// False when it was not kept.
fn keep(zones: &mut Tables, zone: &str, url: &str, seen: Seen) -> bool {
    if let Some(had) = zones.get_mut(zone).and_then(|t| t.get_mut(url)) {
        had.merge(seen);
        return true;
    }
    let total: usize = zones.values().map(HashMap::len).sum();
    if zones.get(zone).map_or(0, HashMap::len) >= MAX_SCRIPTS || total >= MAX_TOTAL {
        let Some(table) = zones.get_mut(zone) else { return false };
        let oldest = table.iter().min_by(|a, b| a.1.last.cmp(&b.1.last).then(a.1.count.cmp(&b.1.count)).then(a.0.cmp(b.0))).map(|(u, s)| (u.clone(), s.last));
        let Some((oldest, at)) = oldest else { return false };
        if at > seen.last {
            return false;
        }
        table.remove(&oldest);
    }
    zones.entry(zone.to_string()).or_default().insert(url.to_string(), seen);
    true
}

type Outbox = HashMap<(String, String), Seen>;

/// Add to what the next report tells, up to [`MAX_OUTBOX`] scripts.
fn to_tell(outbox: &mut Outbox, key: (String, String), seen: Seen) {
    let len = outbox.len();
    match outbox.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut had) => had.get_mut().merge(seen),
        std::collections::hash_map::Entry::Vacant(slot) if len < MAX_OUTBOX => {
            slot.insert(seen);
        }
        std::collections::hash_map::Entry::Vacant(_) => {}
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Inner {
    #[serde(default)]
    zones: Tables,
    /// Seen here, not told to the other nodes yet.
    #[serde(skip)]
    outbox: Outbox,
    #[serde(skip)]
    dirty: bool,
}

/// Reports counted per address in the current window.
#[derive(Default)]
struct Clients {
    window: u64,
    counts: HashMap<IpAddr, u32>,
}

/// An address as the rate counts it: IPv6 by its /64 (one host has many).
fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
        v4 => v4,
    }
}

/// The scripts of every zone as this node knows them, the ones to tell the
/// others, and the rate of the report endpoint.
#[derive(Default)]
pub struct PageShield {
    inner: Mutex<Inner>,
    /// Keep an outbox for the reports to the other nodes.
    reporting: AtomicBool,
    /// Written to disk (see [`PageShield::load`]); an accelerate node's is not.
    persist: bool,
    clients: Mutex<Clients>,
}

impl PageShield {
    /// The list saved at `path` (none yet, or unreadable: an empty one).
    pub fn load(path: &Path) -> PageShield {
        let inner = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Inner>(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring the unreadable Page Shield list in {}: {e}", path.display());
                Inner::default()
            }),
            Err(_) => Inner::default(),
        };
        PageShield { inner: Mutex::new(inner), persist: true, ..PageShield::default() }
    }

    /// Write the list to `path` if it changed: zones not in `zones` and
    /// scripts not seen for [`RETENTION_SECS`] are let go first. The JSON is
    /// written outside the lock.
    pub fn save(&self, path: &Path, zones: &HashSet<String>) -> std::io::Result<()> {
        if !self.persist {
            return Ok(());
        }
        let now = unix_now();
        let kept = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.dirty {
                return Ok(());
            }
            inner.zones.retain(|id, _| zones.contains(id));
            inner.outbox.retain(|(id, _), _| zones.contains(id));
            for table in inner.zones.values_mut() {
                table.retain(|_, s| s.last.saturating_add(RETENTION_SECS) >= now);
            }
            inner.zones.retain(|_, t| !t.is_empty());
            inner.dirty = false;
            inner.zones.clone()
        };
        let bytes = serde_json::to_vec(&json!({ "zones": kept })).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, path))
    }

    /// Start keeping an outbox for [`PageShield::take_outbox`].
    pub fn set_reporting(&self) {
        self.reporting.store(true, Ordering::Relaxed);
    }

    /// May `ip` post another report now?
    pub fn allow(&self, ip: IpAddr, now: u64) -> bool {
        let key = client_key(ip);
        let window = now / RATE_WINDOW;
        let mut c = self.clients.lock().unwrap();
        if c.window != window {
            c.window = window;
            c.counts.clear();
        }
        let full = c.counts.len() >= MAX_CLIENTS;
        match c.counts.get_mut(&key) {
            Some(n) if *n >= RATE_PER_IP => false,
            Some(n) => {
                *n += 1;
                true
            }
            None if full => false,
            None => {
                c.counts.insert(key, 1);
                true
            }
        }
    }

    /// A visitor's page loaded `url` (a URL as [`script_url`] keeps it).
    pub fn record_at(&self, zone: &str, url: &str, now: u64) {
        let seen = Seen::once(now);
        let mut inner = self.inner.lock().unwrap();
        if keep(&mut inner.zones, zone, url, seen) && self.reporting.load(Ordering::Relaxed) {
            to_tell(&mut inner.outbox, (zone.to_string(), url.to_string()), seen);
        }
        inner.dirty = true;
    }

    /// What the next report tells the other nodes (at most [`REPORT_BATCH`]
    /// scripts; the rest wait for the report after).
    pub fn take_outbox(&self) -> Vec<ScriptSeen> {
        let mut inner = self.inner.lock().unwrap();
        let keys: Vec<(String, String)> = inner.outbox.keys().take(REPORT_BATCH).cloned().collect();
        keys.into_iter()
            .filter_map(|key| {
                let s = inner.outbox.remove(&key)?;
                Some(ScriptSeen { zone: key.0, url: key.1, first: s.first, last: s.last, count: s.count })
            })
            .collect()
    }

    /// A report that reached no other node: what it told goes back into the outbox.
    pub fn restore_outbox(&self, list: Vec<ScriptSeen>) {
        let mut inner = self.inner.lock().unwrap();
        for s in list {
            let seen = Seen { first: s.first, last: s.last, count: s.count };
            to_tell(&mut inner.outbox, (s.zone, s.url), seen);
        }
    }

    /// What another node told (each report once: see crate::reports).
    pub fn absorb(&self, list: &[ScriptSeen]) {
        self.absorb_at(list, unix_now());
    }

    fn absorb_at(&self, list: &[ScriptSeen], now: u64) {
        if list.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        let mut changed = false;
        for s in list.iter().take(REPORT_BATCH) {
            if let Some(seen) = s.checked(now) {
                changed |= keep(&mut inner.zones, &s.zone, &s.url, seen);
            }
        }
        inner.dirty |= changed;
    }

    /// A zone's scripts.
    pub fn scripts(&self, zone: &str) -> Vec<(String, Seen)> {
        let inner = self.inner.lock().unwrap();
        inner.zones.get(zone).map(|t| t.iter().map(|(u, s)| (u.clone(), *s)).collect()).unwrap_or_default()
    }
}

/// Take a report body posted to `host` for the zone `zone_id`: the scripts
/// it tells of are counted. How many there were.
pub fn take(shield: &PageShield, zone_id: &str, host: &str, media: &str, body: &[u8], now: u64) -> Result<usize, Refusal> {
    let urls = scripts_of(host, &violations(media, body)?);
    for url in &urls {
        shield.record_at(zone_id, url, now);
    }
    Ok(urls.len())
}

// ----------------------------------------------------------- endpoint ----

/// An answer with no body (browsers do not read it).
fn answer(status: StatusCode) -> Response<Body> {
    let mut resp = Response::new(full(Bytes::new()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status == StatusCode::METHOD_NOT_ALLOWED {
        resp.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST"));
    }
    resp
}

fn media_type(headers: &HeaderMap) -> String {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    ct.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
}

/// A request body of at most `max` bytes, frame by frame (as the human
/// check reads its answer, see crate::edge::widget).
async fn read_body(mut body: Body, max: usize) -> Result<Vec<u8>, Refusal> {
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Refusal::Unreadable)?;
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
        if bytes.len() > max {
            return Err(Refusal::TooLarge);
        }
    }
    Ok(bytes)
}

/// Is `endpoint` (what follows `/cdn-cgi/`) the report endpoint?
pub fn handles(endpoint: &str) -> bool {
    REPORT_PATH.strip_prefix("/cdn-cgi/") == Some(endpoint)
}

/// `POST /cdn-cgi/script_monitor/report` on a host of a zone. A host whose
/// zone does not have Page Shield on gets `204` and nothing is read: the
/// answer does not tell which zones have it. Everything it needs is owned
/// and nothing borrowed lives across its awaits, so the future is `Send`.
pub async fn serve(edge: Arc<Edge>, ip: IpAddr, req: Request<Body>, host: String) -> Response<Body> {
    if req.method() != Method::POST {
        return answer(Refusal::Method.status());
    }
    let zone_id = {
        let snap = edge.store.snapshot();
        match snap.edge_zone(&host) {
            Some(z) if z.zone.settings.page_shield.enabled => z.zone.id.clone(),
            _ => return answer(StatusCode::NO_CONTENT),
        }
    };
    let now = unix_now();
    if !edge.page_shield.allow(ip, now) {
        return answer(Refusal::TooMany.status());
    }
    let (parts, body) = req.into_parts();
    let declared = parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY as u64) {
        return answer(Refusal::TooLarge.status());
    }
    let media = media_type(&parts.headers);
    if !accepted(&media) {
        return answer(Refusal::MediaType.status());
    }
    let bytes = match read_body(body, MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(refusal) => return answer(refusal.status()),
    };
    match take(&edge.page_shield, &zone_id, &host, &media, &bytes, now) {
        Ok(_) => answer(StatusCode::NO_CONTENT),
        Err(refusal) => answer(refusal.status()),
    }
}

// ---------------------------------------------------------------- API ----

/// The id of a script of a zone: stable, and the same on every node.
pub fn script_id(zone_id: &str, url: &str) -> String {
    crate::release::sha256_hex(format!("page shield\n{zone_id}\n{url}").as_bytes())[..32].to_string()
}

fn script_json(zone_id: &str, url: &str, s: &Seen) -> Value {
    let host = parse_url(url).map(|u| u.host).unwrap_or_default();
    let first = crate::store::rfc3339(s.first as i64);
    json!({
        "id": script_id(zone_id, url),
        "url": url,
        "host": host,
        "added_at": first,
        "first_seen_at": first,
        "last_seen_at": crate::store::rfc3339(s.last as i64),
        "count": s.count,
    })
}

/// `GET /zones/{id}/page_shield/scripts`: the zone's scripts, filtered by
/// `host` (exact) and `url` (contains), ordered by `order_by`
/// (`last_seen_at`, the default, `first_seen_at`, `count` or `url`) in
/// `direction` (`desc`, the default, or `asc`). Unknown parameters and
/// values are refused (`page` and `per_page` are the pager's).
pub fn list(shield: &PageShield, zone_id: &str, q: &HashMap<String, String>) -> Result<Vec<Value>, String> {
    for key in q.keys() {
        if !["page", "per_page", "host", "url", "order_by", "direction"].contains(&key.as_str()) {
            return Err(format!("unknown parameter '{key}' (known: host, url, order_by, direction, page, per_page)"));
        }
    }
    let order = q.get("order_by").map_or("last_seen_at", String::as_str);
    if !["last_seen_at", "first_seen_at", "count", "url"].contains(&order) {
        return Err("order_by is last_seen_at, first_seen_at, count or url".into());
    }
    let desc = match q.get("direction").map(String::as_str) {
        None | Some("desc") => true,
        Some("asc") => false,
        Some(_) => return Err("direction is asc or desc".into()),
    };
    let host = q.get("host").map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase());
    let part = q.get("url").map(|u| u.to_ascii_lowercase());
    let mut found: Vec<(String, Seen)> = shield
        .scripts(zone_id)
        .into_iter()
        .filter(|(url, _)| host.as_ref().is_none_or(|h| parse_url(url).is_some_and(|u| &u.host == h)))
        .filter(|(url, _)| part.as_ref().is_none_or(|p| url.to_ascii_lowercase().contains(p.as_str())))
        .collect();
    found.sort_by(|a, b| {
        let by = match order {
            "first_seen_at" => a.1.first.cmp(&b.1.first),
            "count" => a.1.count.cmp(&b.1.count),
            "url" => a.0.cmp(&b.0),
            _ => a.1.last.cmp(&b.1.last),
        };
        let by = if desc { by.reverse() } else { by };
        by.then_with(|| a.0.cmp(&b.0))
    });
    Ok(found.iter().map(|(url, s)| script_json(zone_id, url, s)).collect())
}

/// `GET /zones/{id}/page_shield/scripts/{script_id}`.
pub fn script(shield: &PageShield, zone_id: &str, id: &str) -> Option<Value> {
    shield.scripts(zone_id).iter().find(|(url, _)| script_id(zone_id, url) == id).map(|(url, s)| script_json(zone_id, url, s))
}

/// For the `new_script` alert: per zone name, the scripts first seen within
/// [`ALERT_WINDOW`], newest first, of the zones that have Page Shield and
/// its alerts on.
pub fn new_scripts(store: &Store, shield: &PageShield, now: u64) -> BTreeMap<String, Vec<(String, u64)>> {
    let since = now.saturating_sub(ALERT_WINDOW);
    let mut out = BTreeMap::new();
    for zone in store.list_zones() {
        let s = &zone.settings.page_shield;
        if !(s.enabled && s.alerts) {
            continue;
        }
        let mut fresh: Vec<(String, u64)> = shield.scripts(&zone.id).into_iter().filter(|(_, seen)| seen.first >= since && seen.first <= now.saturating_add(60)).map(|(url, seen)| (url, seen.first)).collect();
        if fresh.is_empty() {
            continue;
        }
        fresh.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out.insert(zone.name, fresh);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const HOST: &str = "www.example.com";

    fn on() -> PageShieldSettings {
        PageShieldSettings { enabled: true, ..PageShieldSettings::default() }
    }

    fn html(extra: &[(&str, &str)]) -> Response<Body> {
        let mut resp = Response::new(full("<p>hi</p>"));
        resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        for (k, v) in extra {
            resp.headers_mut().append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        resp
    }

    fn all(resp: &Response<Body>, name: &str) -> Vec<String> {
        resp.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_string()).collect()
    }

    fn csp2_body(document: &str, blocked: &str, directive: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({ "csp-report": {
            "document-uri": document, "referrer": "", "violated-directive": directive, "effective-directive": directive,
            "original-policy": "script-src 'none'; report-uri /cdn-cgi/script_monitor/report", "disposition": "report",
            "blocked-uri": blocked, "status-code": 200, "script-sample": "" } }))
        .unwrap()
    }

    fn reporting_item(document: &str, blocked: &str, directive: &str) -> Value {
        json!({ "type": "csp-violation", "age": 3, "url": document, "user_agent": "Mozilla/5.0", "body": {
            "documentURL": document, "blockedURL": blocked, "effectiveDirective": directive, "disposition": "report",
            "originalPolicy": "script-src 'none'", "statusCode": 200, "sample": "", "referrer": "" } })
    }

    #[test]
    fn an_html_answer_gets_a_report_only_policy_that_reports_to_the_zones_own_endpoint() {
        let mut resp = html(&[]);
        apply(&mut resp, &on(), true);
        assert_eq!(
            all(&resp, "content-security-policy-report-only"),
            vec!["script-src 'none'; report-uri /cdn-cgi/script_monitor/report; report-to fucf-page-shield"]
        );
        assert_eq!(all(&resp, "reporting-endpoints"), vec![ENDPOINTS_VALUE]);
        assert_eq!(ENDPOINTS_VALUE, format!("{ENDPOINT_NAME}=\"{REPORT_PATH}\""));
        assert!(resp.headers().get("content-security-policy").is_none(), "nothing is enforced by default");

        // over plain HTTP the Reporting API would not accept the endpoint: report-uri alone
        let mut resp = html(&[]);
        apply(&mut resp, &on(), false);
        assert_eq!(all(&resp, "content-security-policy-report-only"), vec!["script-src 'none'; report-uri /cdn-cgi/script_monitor/report"]);
        assert!(resp.headers().get("reporting-endpoints").is_none());
    }

    #[test]
    fn nothing_is_added_when_it_is_off_or_the_answer_is_not_html() {
        let mut resp = html(&[]);
        apply(&mut resp, &PageShieldSettings::default(), true);
        assert!(resp.headers().get("content-security-policy-report-only").is_none());
        for ct in ["application/json", "text/javascript", "image/svg+xml", "text/plain"] {
            let mut resp = Response::new(full("x"));
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(ct).unwrap());
            apply(&mut resp, &on(), true);
            assert!(resp.headers().get("content-security-policy-report-only").is_none(), "{ct}");
        }
        let mut untyped = Response::new(full("x"));
        apply(&mut untyped, &on(), true);
        assert!(untyped.headers().is_empty());
        // whatever the status: a 404 page loads scripts too
        let mut missing = html(&[]);
        *missing.status_mut() = StatusCode::NOT_FOUND;
        apply(&mut missing, &on(), true);
        assert_eq!(all(&missing, "content-security-policy-report-only").len(), 1);
    }

    #[test]
    fn the_origins_own_policies_are_kept_and_ours_comes_as_one_more_line() {
        let origin = [
            ("content-security-policy", "default-src 'self'"),
            ("content-security-policy-report-only", "img-src 'none'; report-uri https://reports.example.net/csp"),
        ];
        let mut resp = html(&origin);
        apply(&mut resp, &on(), true);
        assert_eq!(all(&resp, "content-security-policy"), vec!["default-src 'self'"]);
        assert_eq!(
            all(&resp, "content-security-policy-report-only"),
            vec!["img-src 'none'; report-uri https://reports.example.net/csp".to_string(), header_value(&on(), true).unwrap()]
        );

        // enforced: still one more policy, the origin's stays
        let mut enforce = on();
        enforce.mode = "enforce".into();
        enforce.policy = "script-src 'self' https://cdn.example.net".into();
        let mut resp = html(&origin);
        apply(&mut resp, &enforce, true);
        assert_eq!(
            all(&resp, "content-security-policy"),
            vec!["default-src 'self'", "script-src 'self' https://cdn.example.net; report-uri /cdn-cgi/script_monitor/report; report-to fucf-page-shield"]
        );
        assert_eq!(all(&resp, "content-security-policy-report-only").len(), 1, "the origin's report-only policy alone");
    }

    #[test]
    fn an_origins_reporting_endpoints_header_is_left_alone_and_report_to_is_not_used() {
        let mut resp = html(&[("reporting-endpoints", "main=\"https://reports.example.net/r\"")]);
        apply(&mut resp, &on(), true);
        assert_eq!(all(&resp, "reporting-endpoints"), vec!["main=\"https://reports.example.net/r\""]);
        assert_eq!(all(&resp, "content-security-policy-report-only"), vec!["script-src 'none'; report-uri /cdn-cgi/script_monitor/report"]);
    }

    #[test]
    fn a_policy_is_one_line_of_directives_without_report_destinations_of_its_own() {
        let with = |policy: &str, mode: &str| PageShieldSettings { enabled: true, mode: mode.into(), policy: policy.into(), alerts: false };
        for ok in ["script-src 'self'", "  script-src   'self' https://cdn.example.net ;; object-src 'none' ;", "default-src 'self'; script-src-elem 'self'"] {
            assert!(with(ok, "report_only").validate().is_ok(), "{ok}");
        }
        assert_eq!(
            header_value(&with("  script-src   'self'  ;; object-src 'none' ;", "report_only"), false).unwrap(),
            "script-src 'self'; object-src 'none'; report-uri /cdn-cgi/script_monitor/report"
        );
        let long = format!("script-src {}", "a".repeat(MAX_POLICY));
        let many = (0..=MAX_DIRECTIVES).map(|i| format!("x{i} 'self'")).collect::<Vec<_>>().join("; ");
        for bad in [
            "script-src 'self'\r\nX-Injected: 1",
            "script-src 'self'\n",
            "script-src\t'self'",
            "script-src 'self', img-src 'none'",
            "script-src 'self'; report-uri https://reports.example.net/",
            "script-src 'self'; REPORT-TO other",
            "script-src 'self' https://例え.example.com",
            "script_src 'self'",
            ";;;",
            long.as_str(),
            many.as_str(),
        ] {
            assert!(with(bad, "report_only").validate().is_err(), "{bad:?}");
        }
        assert!(with("", "report_only").validate().is_ok(), "empty is the default policy");
        assert!(with("  ", "report_only").validate().is_ok());
        assert!(with("", "enforce").validate().is_err(), "the default policy is never enforced");
        assert!(with("script-src 'self'", "enforce").validate().is_ok());
        assert!(with("script-src 'self'", "block").validate().is_err());
        assert!(with("script-src 'self'", "").validate().is_err());
    }

    #[test]
    fn a_patch_changes_only_what_it_names_and_is_checked() {
        let base = PageShieldSettings::default();
        let next = patch(&base, &json!({ "enabled": true })).unwrap();
        assert_eq!(next, PageShieldSettings { enabled: true, ..base.clone() });
        let next = patch(&next, &json!({ "policy": "  script-src 'self'  ", "alerts": true })).unwrap();
        assert_eq!((next.enabled, next.policy.as_str(), next.alerts, next.mode.as_str()), (true, "script-src 'self'", true, "report_only"));
        let next = patch(&next, &json!({ "mode": "enforce" })).unwrap();
        assert_eq!(next.mode, "enforce");
        assert!(patch(&next, &json!({ "policy": null })).is_err(), "enforce keeps needing a policy");
        let back = patch(&next, &json!({ "mode": "report_only", "policy": null })).unwrap();
        assert_eq!(back.policy, "");
        // Cloudflare's own flags are taken and change nothing
        assert_eq!(patch(&back, &json!({ "use_cloudflare_reporting_endpoint": true, "use_connection_url_path": false })).unwrap(), back);
        for bad in [json!({ "enabled": "yes" }), json!({ "mode": 1 }), json!({ "policy": ["a"] }), json!({ "colour": "red" }), json!([]), json!("on"), json!({ "use_connection_url_path": 1 })] {
            assert!(patch(&back, &bad).is_err(), "{bad}");
        }
        let v = view(&back);
        assert_eq!(v["header"], "content-security-policy-report-only");
        assert_eq!(v["report_uri"], REPORT_PATH);
        assert_eq!(v["effective_policy"], "script-src 'none'; report-uri /cdn-cgi/script_monitor/report; report-to fucf-page-shield");
    }

    #[test]
    fn both_report_formats_are_read() {
        let one = violations("application/csp-report", &csp2_body("https://www.example.com/a", "https://cdn.example.net/lib.js?v=3", "script-src-elem")).unwrap();
        assert_eq!(one, vec![Violation { document: "https://www.example.com/a".into(), blocked: "https://cdn.example.net/lib.js?v=3".into(), directive: "script-src-elem".into() }]);

        // CSP 2 browsers without effective-directive name the directive with its value
        let old = serde_json::to_vec(&json!({ "csp-report": { "document-uri": "https://www.example.com/", "blocked-uri": "https://cdn.example.net/x.js", "violated-directive": "script-src 'none'" } })).unwrap();
        let got = violations("application/csp-report", &old).unwrap();
        assert!(is_script(&got[0].directive));

        let batch = serde_json::to_vec(&json!([
            reporting_item("https://www.example.com/a", "https://cdn.example.net/a.js", "script-src-elem"),
            { "type": "deprecation", "url": "https://www.example.com/a", "body": { "id": "x" } },
            reporting_item("https://www.example.com/b", "https://cdn.example.net/b.js#top", "script-src-elem"),
            { "type": "csp-violation", "url": "https://www.example.com/c" },
        ]))
        .unwrap();
        let got = violations("application/reports+json", &batch).unwrap();
        assert_eq!(got.iter().map(|v| v.blocked.as_str()).collect::<Vec<_>>(), vec!["https://cdn.example.net/a.js", "https://cdn.example.net/b.js#top"]);
        // the document falls back to the report's url
        let no_doc = serde_json::to_vec(&json!([{ "type": "csp-violation", "url": "https://www.example.com/d", "body": { "blockedURL": "https://cdn.example.net/d.js", "effectiveDirective": "script-src" } }])).unwrap();
        assert_eq!(violations("application/reports+json", &no_doc).unwrap()[0].document, "https://www.example.com/d");

        // application/json is read by its shape
        assert_eq!(violations("application/json", &csp2_body("https://www.example.com/", "https://cdn.example.net/x.js", "script-src")).unwrap().len(), 1);
        assert_eq!(violations("application/json", &batch).unwrap().len(), 2);
    }

    #[test]
    fn a_report_of_the_wrong_type_or_shape_is_refused() {
        let body = csp2_body("https://www.example.com/", "https://cdn.example.net/x.js", "script-src");
        for media in ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""] {
            assert_eq!(violations(media, &body), Err(Refusal::MediaType), "{media}");
        }
        assert_eq!(violations("application/csp-report", b"{not json"), Err(Refusal::Unreadable));
        assert_eq!(violations("application/csp-report", b""), Err(Refusal::Unreadable));
        assert_eq!(violations("application/csp-report", b"[]"), Err(Refusal::Unreadable), "CSP 2 is one object");
        assert_eq!(violations("application/csp-report", br#"{"csp-report": "x"}"#), Err(Refusal::Unreadable));
        assert_eq!(violations("application/csp-report", br#"{"other": {}}"#), Err(Refusal::Unreadable));
        assert_eq!(violations("application/reports+json", &body), Err(Refusal::Unreadable), "the Reporting API sends an array");
        assert_eq!(violations("application/reports+json", b"[]"), Ok(vec![]));
        assert_eq!(violations("application/reports+json", b"7"), Err(Refusal::Unreadable));
        // a batch is read up to its first hundred
        let many: Vec<Value> = (0..150).map(|i| reporting_item("https://www.example.com/", &format!("https://cdn.example.net/{i}.js"), "script-src")).collect();
        assert_eq!(violations("application/reports+json", &serde_json::to_vec(&many).unwrap()).unwrap().len(), MAX_VIOLATIONS);
    }

    #[test]
    fn only_scheme_host_and_path_of_a_script_are_kept() {
        for (raw, want) in [
            ("https://cdn.example.net/lib.js?v=1&token=secret#frag", Some("https://cdn.example.net/lib.js")),
            ("https://user:password@cdn.example.net/lib.js", Some("https://cdn.example.net/lib.js")),
            ("HTTPS://CDN.Example.NET./Lib.js", Some("https://cdn.example.net/Lib.js")),
            ("https://cdn.example.net:443/a.js", Some("https://cdn.example.net/a.js")),
            ("http://cdn.example.net:80/a.js", Some("http://cdn.example.net/a.js")),
            ("https://cdn.example.net:8443/a.js", Some("https://cdn.example.net:8443/a.js")),
            ("https://cdn.example.net:/a.js", Some("https://cdn.example.net/a.js")),
            ("https://cdn.example.net", Some("https://cdn.example.net/")),
            ("https://cdn.example.net?x=1", Some("https://cdn.example.net/")),
            ("https://[2001:DB8::1]:8443/a.js", Some("https://[2001:db8::1]:8443/a.js")),
            ("https://192.0.2.7/a.js", Some("https://192.0.2.7/a.js")),
            ("https://cdn.example.net/a%20b.js", Some("https://cdn.example.net/a%20b.js")),
            ("inline", None),
            ("eval", None),
            ("data", None),
            ("data:text/javascript,alert(1)", None),
            ("blob:https://www.example.com/1", None),
            ("javascript:alert(1)", None),
            ("ftp://cdn.example.net/a.js", None),
            ("https:///a.js", None),
            ("https://cdn..example.net/a.js", None),
            ("https://cdn.example.net:99999/a.js", None),
            ("https://cdn.example.net:0/a.js", None),
            ("https://cdn.example.net:x/a.js", None),
            ("https://[2001:db8::zz]/a.js", None),
            ("https://cdn.example.net/a b.js", None),
            ("https://cdn.example.net/<script>.js", None),
            ("https://cdn.example.net/\"x\".js", None),
            ("https://cdn.example.net/a.js\r\nX: 1", None),
            ("https://cdn.exa mple.net/a.js", None),
            ("", None),
        ] {
            assert_eq!(script_url(raw).as_deref(), want, "{raw:?}");
        }
        assert!(script_url(&format!("https://cdn.example.net/{}", "a".repeat(MAX_URL))).is_none(), "too long to keep");
    }

    #[test]
    fn only_script_violations_on_pages_of_the_reporting_host_count_each_once() {
        let v = |document: &str, blocked: &str, directive: &str| Violation { document: document.into(), blocked: blocked.into(), directive: directive.into() };
        let list = vec![
            v("https://www.example.com/a", "https://cdn.example.net/lib.js?v=1", "script-src-elem"),
            v("https://www.example.com/b", "https://cdn.example.net/lib.js?v=2", "script-src"),
            v("https://WWW.example.com:8443/c", "https://www.example.com/app.js", "script-src-elem"),
            v("https://www.example.com/", "https://cdn.example.net/style.css", "style-src-elem"),
            v("https://www.example.com/", "https://cdn.example.net/img.png", "img-src"),
            v("https://www.example.com/", "inline", "script-src-elem"),
            v("https://www.example.com/", "https://www.example.com/cdn-cgi/challenge-platform/fcf.js", "script-src-elem"),
            v("https://other.example.com/", "https://cdn.example.net/other.js", "script-src-elem"),
            v("https://www.example.com.example.net/", "https://cdn.example.net/spoof.js", "script-src-elem"),
            v("not a url", "https://cdn.example.net/nodoc.js", "script-src-elem"),
            v("", "https://cdn.example.net/nodoc.js", "script-src-elem"),
        ];
        assert_eq!(scripts_of(HOST, &list), vec!["https://cdn.example.net/lib.js", "https://www.example.com/app.js"]);
        // another host's /cdn-cgi/ is not the edge's own
        let foreign = [v("https://www.example.com/", "https://cdn.example.net/cdn-cgi/x.js", "script-src")];
        assert_eq!(scripts_of(HOST, &foreign), vec!["https://cdn.example.net/cdn-cgi/x.js"]);
    }

    #[test]
    fn reports_add_up_per_zone_with_first_and_last_sight() {
        let shield = PageShield::default();
        let body = csp2_body("https://www.example.com/a", "https://cdn.example.net/lib.js?v=1", "script-src-elem");
        assert_eq!(take(&shield, "z1", HOST, "application/csp-report", &body, NOW), Ok(1));
        assert_eq!(take(&shield, "z1", HOST, "application/csp-report", &body, NOW + 10), Ok(1));
        assert_eq!(take(&shield, "z1", HOST, "application/csp-report", &body, NOW + 5), Ok(1), "late reports do not move the times back");
        assert_eq!(take(&shield, "z2", HOST, "application/csp-report", &body, NOW + 20), Ok(1));
        assert_eq!(shield.scripts("z1"), vec![("https://cdn.example.net/lib.js".to_string(), Seen { first: NOW, last: NOW + 10, count: 3 })]);
        assert_eq!(shield.scripts("z2"), vec![("https://cdn.example.net/lib.js".to_string(), Seen { first: NOW + 20, last: NOW + 20, count: 1 })]);
        assert!(shield.scripts("z3").is_empty());
        // a report about another host's page counts nothing
        let elsewhere = csp2_body("https://other.example.org/", "https://cdn.example.net/x.js", "script-src");
        assert_eq!(take(&shield, "z1", HOST, "application/csp-report", &elsewhere, NOW), Ok(0));
        assert_eq!(take(&shield, "z1", HOST, "text/plain", &body, NOW), Err(Refusal::MediaType));
        assert_eq!(shield.scripts("z1")[0].1.count, 3);
    }

    #[test]
    fn a_zone_keeps_at_most_its_cap_and_lets_go_of_the_script_seen_longest_ago() {
        let shield = PageShield::default();
        let url = |i: usize| format!("https://cdn.example.net/{i}.js");
        for i in 0..MAX_SCRIPTS {
            shield.record_at("z1", &url(i), NOW + i as u64);
        }
        // seen again: no longer the oldest
        shield.record_at("z1", &url(0), NOW + 10_000);
        shield.record_at("z1", &url(MAX_SCRIPTS), NOW + 10_001);
        let kept: HashMap<String, Seen> = shield.scripts("z1").into_iter().collect();
        assert_eq!(kept.len(), MAX_SCRIPTS);
        assert!(kept.contains_key(&url(0)) && kept.contains_key(&url(MAX_SCRIPTS)));
        assert!(!kept.contains_key(&url(1)), "the one seen longest ago went");
        // something seen before everything kept does not push a newer one out
        let mut zones: Tables = HashMap::new();
        zones.insert("z1".into(), kept);
        assert!(!keep(&mut zones, "z1", "https://cdn.example.net/ancient.js", Seen::once(NOW - 1)));
        assert_eq!(zones["z1"].len(), MAX_SCRIPTS);
        // other zones are not touched by one zone's cap
        shield.record_at("z2", &url(1), NOW);
        assert_eq!(shield.scripts("z2").len(), 1);
    }

    #[test]
    fn a_node_keeps_at_most_its_total_across_zones() {
        let mut zones: Tables = HashMap::new();
        let per = MAX_SCRIPTS;
        for z in 0..MAX_TOTAL / per {
            let table = zones.entry(format!("z{z}")).or_default();
            for i in 0..per {
                table.insert(format!("https://cdn.example.net/{i}.js"), Seen::once(NOW + i as u64));
            }
        }
        assert!(!keep(&mut zones, "fresh", "https://cdn.example.net/a.js", Seen::once(NOW + 99_999)), "a zone with nothing to let go cannot add at the total");
        assert!(!zones.contains_key("fresh"));
        assert!(keep(&mut zones, "z0", "https://cdn.example.net/new.js", Seen::once(NOW + 99_999)), "a zone with scripts makes room among its own");
        assert_eq!(zones.values().map(HashMap::len).sum::<usize>(), MAX_TOTAL);
    }

    #[test]
    fn each_address_posts_a_limited_number_of_reports_a_minute() {
        let shield = PageShield::default();
        let a: IpAddr = "192.0.2.7".parse().unwrap();
        let b: IpAddr = "198.51.100.9".parse().unwrap();
        for _ in 0..RATE_PER_IP {
            assert!(shield.allow(a, NOW));
        }
        assert!(!shield.allow(a, NOW), "over the rate");
        assert!(shield.allow(b, NOW), "another address has its own count");
        assert!(shield.allow(a, NOW + RATE_WINDOW), "a new window");
        // an IPv6 host has its whole /64, and an IPv4-mapped address is the IPv4 one
        let v6 = |s: &str| s.parse::<IpAddr>().unwrap();
        for i in 0..RATE_PER_IP {
            assert!(shield.allow(v6(&format!("2001:db8:1:2::{:x}", i + 1)), NOW + 2 * RATE_WINDOW));
        }
        assert!(!shield.allow(v6("2001:db8:1:2:ffff::1"), NOW + 2 * RATE_WINDOW));
        assert!(shield.allow(v6("2001:db8:1:3::1"), NOW + 2 * RATE_WINDOW));
        let mapped = v6("::ffff:192.0.2.8");
        for _ in 0..RATE_PER_IP {
            assert!(shield.allow(mapped, NOW + 3 * RATE_WINDOW));
        }
        assert!(!shield.allow("192.0.2.8".parse().unwrap(), NOW + 3 * RATE_WINDOW));
    }

    #[test]
    fn a_flood_of_addresses_does_not_grow_the_counts_without_bound() {
        let shield = PageShield::default();
        // each one a /64 of its own, all in the documentation prefix
        let host = |i: usize| -> IpAddr { format!("2001:db8:0:{i:x}::1").parse().unwrap() };
        for i in 0..MAX_CLIENTS {
            assert!(shield.allow(host(i), NOW));
        }
        assert!(!shield.allow("203.0.113.1".parse().unwrap(), NOW), "full: new addresses wait for the next window");
        assert!(shield.allow(host(0), NOW), "the ones counted go on");
        assert!(shield.allow("203.0.113.1".parse().unwrap(), NOW + RATE_WINDOW));
        assert_eq!(shield.clients.lock().unwrap().counts.len(), 1);
    }

    #[test]
    fn what_a_node_saw_is_told_once_and_merged_by_the_others() {
        let here = PageShield::default();
        here.set_reporting();
        here.record_at("z1", "https://cdn.example.net/a.js", NOW);
        here.record_at("z1", "https://cdn.example.net/a.js", NOW + 30);
        let told = here.take_outbox();
        assert_eq!(told, vec![ScriptSeen { zone: "z1".into(), url: "https://cdn.example.net/a.js".into(), first: NOW, last: NOW + 30, count: 2 }]);
        assert!(here.take_outbox().is_empty(), "nothing twice");

        let there = PageShield::default();
        there.record_at("z1", "https://cdn.example.net/a.js", NOW + 100);
        there.absorb_at(&told, NOW + 200);
        assert_eq!(there.scripts("z1"), vec![("https://cdn.example.net/a.js".to_string(), Seen { first: NOW, last: NOW + 100, count: 3 })]);
        assert!(there.take_outbox().is_empty(), "a node that does not report keeps no outbox, and what it absorbed is not told on");

        // a report that reached nobody is told with the next one
        here.record_at("z1", "https://cdn.example.net/b.js", NOW + 40);
        let lost = here.take_outbox();
        here.record_at("z1", "https://cdn.example.net/b.js", NOW + 50);
        here.restore_outbox(lost);
        assert_eq!(here.take_outbox(), vec![ScriptSeen { zone: "z1".into(), url: "https://cdn.example.net/b.js".into(), first: NOW + 40, last: NOW + 50, count: 2 }]);
    }

    #[test]
    fn what_another_node_tells_is_checked_before_it_is_kept() {
        let shield = PageShield::default();
        let s = |zone: &str, url: &str, first: u64, last: u64, count: u64| ScriptSeen { zone: zone.into(), url: url.into(), first, last, count };
        shield.absorb_at(
            &[
                s("z1", "https://cdn.example.net/ok.js", NOW, NOW, 1),
                s("z1", "https://cdn.example.net/q.js?token=x", NOW, NOW, 1),
                s("z1", "HTTPS://cdn.example.net/upper.js", NOW, NOW, 1),
                s("z1", "inline", NOW, NOW, 1),
                s("", "https://cdn.example.net/nozone.js", NOW, NOW, 1),
                s("z/1", "https://cdn.example.net/badzone.js", NOW, NOW, 1),
                s("z1", "https://cdn.example.net/zero.js", NOW, NOW, 0),
                s("z1", "https://cdn.example.net/backwards.js", NOW + 5, NOW, 1),
                s("z1", "https://cdn.example.net/future.js", NOW, NOW + 3600, 1),
                s("z1", "https://cdn.example.net/never.js", 0, NOW, 1),
            ],
            NOW,
        );
        assert_eq!(shield.scripts("z1").into_iter().map(|(u, _)| u).collect::<Vec<_>>(), vec!["https://cdn.example.net/ok.js"]);

        // a report of another build: what cannot be read is left out, the rest is taken
        #[derive(Deserialize)]
        struct Shaped {
            #[serde(default, deserialize_with = "lenient")]
            scripts: Vec<ScriptSeen>,
        }
        let shaped: Shaped = serde_json::from_value(json!({ "scripts": [{ "zone": "z1", "url": "https://cdn.example.net/a.js", "first": NOW, "last": NOW, "count": 1 }, { "zone": 5 }, "x"] })).unwrap();
        assert_eq!(shaped.scripts.len(), 1);
        let shaped: Shaped = serde_json::from_value(json!({ "scripts": { "z1": [] } })).unwrap();
        assert!(shaped.scripts.is_empty());
        let shaped: Shaped = serde_json::from_value(json!({})).unwrap();
        assert!(shaped.scripts.is_empty());
    }

    #[test]
    fn the_list_is_saved_and_loaded_without_deleted_zones_or_forgotten_scripts() {
        let dir = std::env::temp_dir().join(format!("fucf-pageshield-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("page-shield.json");
        let now = unix_now();
        let shield = PageShield::load(&path);
        shield.record_at("z1", "https://cdn.example.net/a.js", now);
        shield.record_at("z1", "https://cdn.example.net/old.js", now - RETENTION_SECS - 10);
        shield.record_at("gone", "https://cdn.example.net/b.js", now);
        shield.save(&path, &HashSet::from(["z1".to_string()])).unwrap();
        let back = PageShield::load(&path);
        assert_eq!(back.scripts("z1").into_iter().map(|(u, _)| u).collect::<Vec<_>>(), vec!["https://cdn.example.net/a.js"]);
        assert!(back.scripts("gone").is_empty());
        // nothing new: nothing written
        std::fs::remove_file(&path).unwrap();
        back.save(&path, &HashSet::from(["z1".to_string()])).unwrap();
        assert!(!path.exists());
        // a list that is not loaded from a file (an accelerate node's) is never written
        let ephemeral = PageShield::default();
        ephemeral.record_at("z1", "https://cdn.example.net/a.js", now);
        ephemeral.save(&path, &HashSet::from(["z1".to_string()])).unwrap();
        assert!(!path.exists());
        // an unreadable file is an empty list
        std::fs::write(&path, b"{oops").unwrap();
        assert!(PageShield::load(&path).scripts("z1").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_api_lists_filters_and_orders_a_zones_scripts() {
        let shield = PageShield::default();
        shield.record_at("z1", "https://cdn.example.net/a.js", NOW);
        shield.record_at("z1", "https://cdn.example.net/a.js", NOW + 1);
        shield.record_at("z1", "https://static.example.org/b.js", NOW + 50);
        shield.record_at("z2", "https://cdn.example.net/other.js", NOW);
        let q = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>();
        let urls = |list: Vec<Value>| list.iter().map(|v| v["url"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(urls(list(&shield, "z1", &q(&[])).unwrap()), vec!["https://static.example.org/b.js", "https://cdn.example.net/a.js"]);
        assert_eq!(urls(list(&shield, "z1", &q(&[("order_by", "count")])).unwrap()), vec!["https://cdn.example.net/a.js", "https://static.example.org/b.js"]);
        assert_eq!(urls(list(&shield, "z1", &q(&[("order_by", "url"), ("direction", "asc")])).unwrap()), vec!["https://cdn.example.net/a.js", "https://static.example.org/b.js"]);
        assert_eq!(urls(list(&shield, "z1", &q(&[("host", "CDN.example.net")])).unwrap()), vec!["https://cdn.example.net/a.js"]);
        assert_eq!(urls(list(&shield, "z1", &q(&[("url", "B.JS")])).unwrap()), vec!["https://static.example.org/b.js"]);
        assert!(list(&shield, "z3", &q(&[])).unwrap().is_empty());
        for bad in [q(&[("order_by", "size")]), q(&[("direction", "up")]), q(&[("status", "active")])] {
            assert!(list(&shield, "z1", &bad).is_err(), "{bad:?}");
        }
        let first = &list(&shield, "z1", &q(&[("order_by", "first_seen_at"), ("direction", "asc")])).unwrap()[0];
        assert_eq!(first["host"], "cdn.example.net");
        assert_eq!(first["count"], 2);
        assert_eq!(first["first_seen_at"], crate::store::rfc3339(NOW as i64));
        assert_eq!(first["last_seen_at"], crate::store::rfc3339(NOW as i64 + 1));
        let id = first["id"].as_str().unwrap();
        assert_eq!(id.len(), 32);
        assert_eq!(script(&shield, "z1", id).unwrap()["url"], "https://cdn.example.net/a.js");
        assert!(script(&shield, "z2", id).is_none(), "the same id does not open another zone's script");
        assert!(script(&shield, "z1", "0".repeat(32).as_str()).is_none());
        assert_ne!(script_id("z1", "https://cdn.example.net/a.js"), script_id("z2", "https://cdn.example.net/a.js"));
    }

    #[tokio::test]
    async fn a_body_is_read_up_to_the_cap_and_refused_past_it_whatever_length_it_declares() {
        assert_eq!(read_body(full(vec![b'x'; MAX_BODY]), MAX_BODY).await.map(|b| b.len()), Ok(MAX_BODY));
        assert_eq!(read_body(full(vec![b'x'; MAX_BODY + 1]), MAX_BODY).await, Err(Refusal::TooLarge));
        assert_eq!(read_body(full(Vec::<u8>::new()), MAX_BODY).await, Ok(Vec::new()));
    }

    #[test]
    fn new_scripts_are_those_first_seen_within_the_hour_of_zones_that_ask() {
        let dir = std::env::temp_dir().join(format!("fucf-pageshield-alert-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("store.json"), vec![]).unwrap();
        let asks = store.create_zone("example.com").unwrap();
        let quiet = store.create_zone("example.net").unwrap();
        let on_with = |alerts: bool| json!({ "enabled": true, "mode": "report_only", "policy": "", "alerts": alerts });
        store.update_setting(&asks.id, "page_shield", on_with(true)).unwrap();
        store.update_setting(&quiet.id, "page_shield", on_with(false)).unwrap();
        let shield = PageShield::default();
        shield.record_at(&asks.id, "https://cdn.example.net/old.js", NOW - ALERT_WINDOW - 1);
        shield.record_at(&asks.id, "https://cdn.example.net/old.js", NOW);
        shield.record_at(&asks.id, "https://cdn.example.net/a.js", NOW - 100);
        shield.record_at(&asks.id, "https://cdn.example.net/b.js", NOW - 10);
        shield.record_at(&quiet.id, "https://cdn.example.net/c.js", NOW);
        let got = new_scripts(&store, &shield, NOW);
        assert_eq!(got, BTreeMap::from([("example.com".to_string(), vec![("https://cdn.example.net/b.js".to_string(), NOW - 10), ("https://cdn.example.net/a.js".to_string(), NOW - 100)])]));
        assert!(new_scripts(&store, &shield, NOW + ALERT_WINDOW).is_empty(), "an hour later nothing is new");
        // the setting is checked with the zone's other settings
        assert!(store.update_setting(&asks.id, "page_shield", json!({ "enabled": true, "policy": "script-src 'self'\nX: 1" })).is_err());
        assert!(store.update_setting(&asks.id, "page_shield", json!({ "mode": "enforce" })).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
