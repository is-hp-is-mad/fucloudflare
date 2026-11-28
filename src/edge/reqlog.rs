//! The request log: every request a zone's sites get on this node, kept in
//! memory for a while, and pushed elsewhere by the zones' log jobs.
//!
//! Each node keeps only what it answered itself, the newest [`CAPACITY`]
//! requests across all zones. Every entry gets the next number of a
//! sequence that only grows while the process lives; clients poll with the
//! last number they saw (`since`) and get what came after it. Nothing is
//! written to disk and nothing is shared between nodes: the API answers
//! from the node it reaches.
//!
//! A [`LogJob`] names a zone and an HTTPS address. Every node posts its own
//! entries of that zone to the address, as NDJSON, once per
//! `batch_seconds`. A batch that does not get through is dropped with one
//! warning: the log is a window onto recent traffic, not an archive, so a
//! destination that is down must not make the node hold on to (or keep
//! resending) visitor data.

use super::{Edge, Seen, WafHit};
use crate::items::{Item, Meta};
use crate::store::{Data, StoreError, Zone};
use crate::sync::SyncMeta;
use bytes::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, Version};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Entries each node keeps (all zones together).
pub const CAPACITY: usize = 5000;
/// Longest path kept, in bytes (cut at a character boundary).
pub const PATH_MAX: usize = 512;
/// Longest User-Agent kept, in bytes (cut at a character boundary).
pub const UA_MAX: usize = 256;
/// Entries per API answer when the client does not say.
pub const DEFAULT_LIMIT: usize = 100;
/// Most entries per API answer.
pub const MAX_LIMIT: usize = 1000;
/// Bounds of a log job's `batch_seconds`: often enough to be near real
/// time, seldom enough that a node does not post several times a second.
pub const BATCH_MIN: u32 = 10;
pub const BATCH_MAX: u32 = 3600;
const BATCH_DEFAULT: u32 = 60;
/// How long one push may take, connecting included.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the push loop looks whether a job is due.
const PUSH_TICK: Duration = Duration::from_secs(1);

/// `s` cut to at most `max` bytes without splitting a character, so a
/// multi-byte character at the edge is dropped whole rather than leaving
/// invalid UTF-8 (or a panic) behind.
pub fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// One request, as the edge answered it.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// Unix milliseconds when the response was ready.
    pub time_ms: i64,
    pub ray: String,
    /// The node that answered.
    pub node: String,
    pub zone_id: String,
    pub host: String,
    pub method: String,
    /// Without the query string (it often carries tokens), at most [`PATH_MAX`] bytes.
    pub path: String,
    pub status: u16,
    /// `fcf-cache-status`, empty when the response has none.
    pub cache: String,
    /// The body size as the response declared it; `None` for a body
    /// streamed without a known length.
    pub bytes: Option<u64>,
    /// Until the response head was ready (the body may take longer).
    pub duration_ms: u64,
    pub client_ip: IpAddr,
    /// Two-letter country code, empty without a GeoIP database.
    pub country: String,
    /// 0 when unknown.
    pub asn: u32,
    /// At most [`UA_MAX`] bytes.
    pub user_agent: String,
    pub protocol: &'static str,
    /// What the security rules did to the request: `block`, `challenge`,
    /// `rate_limit`, or empty when they let it through.
    pub action: &'static str,
}

impl Entry {
    /// The entry as the API shows it and as it is pushed (one NDJSON line).
    pub fn to_json(&self, seq: u64) -> Value {
        let time = chrono::DateTime::from_timestamp_millis(self.time_ms)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_default();
        json!({
            "seq": seq,
            "time": time,
            "ray": self.ray,
            "node": self.node,
            "zone_id": self.zone_id,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "cache": self.cache,
            "bytes": self.bytes,
            "duration_ms": self.duration_ms,
            "client_ip": self.client_ip.to_string(),
            "country": self.country,
            "asn": (self.asn != 0).then_some(self.asn),
            "user_agent": self.user_agent,
            "protocol": self.protocol,
            "action": self.action,
        })
    }
}

/// How the visitor spoke to us.
pub fn protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "",
    }
}

/// What the security rules did, from the response they produced: a
/// challenge says so in `fcf-mitigated`, a rate limit answers 429, anything
/// else the WAF answered is a block.
pub fn action(by_waf: bool, status: u16, mitigated: Option<&HeaderValue>) -> &'static str {
    if !by_waf {
        ""
    } else if mitigated.is_some_and(|v| v.as_bytes() == b"challenge") {
        "challenge"
    } else if status == 429 {
        "rate_limit"
    } else {
        "block"
    }
}

/// Book one answered request. Called from `respond` for every request that
/// reached a zone; the entry is built before the log's lock is taken.
pub(super) fn record(edge: &Edge, seen: &Seen, ray: &str, ip: IpAddr, version: Version, resp: &Response<super::Body>, took: Duration) {
    let (node, _) = edge.limits.own();
    let status = resp.status().as_u16();
    let headers = resp.headers();
    edge.reqlog.push(Entry {
        time_ms: chrono::Utc::now().timestamp_millis(),
        ray: ray.to_string(),
        node: if node.is_empty() { "local".to_string() } else { node },
        zone_id: seen.zone_id.clone(),
        host: seen.host.clone(),
        method: seen.method.as_str().to_string(),
        path: clip(&seen.path, PATH_MAX).to_string(),
        status,
        cache: headers.get("fcf-cache-status").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string(),
        bytes: hyper::body::Body::size_hint(resp.body()).exact(),
        duration_ms: u64::try_from(took.as_millis()).unwrap_or(u64::MAX),
        client_ip: ip.to_canonical(),
        country: seen.country.clone(),
        asn: seen.asn,
        user_agent: clip(&seen.user_agent, UA_MAX).to_string(),
        protocol: protocol(version),
        action: action(resp.extensions().get::<WafHit>().is_some(), status, headers.get("fcf-mitigated")),
    });
}

// ------------------------------------------------------------ the ring ----

/// Fixed-size ring of the newest entries. Sequence numbers are contiguous
/// (`first` is the front's), so a cursor turns into an index by arithmetic.
struct Ring {
    entries: VecDeque<Arc<Entry>>,
    /// Sequence number of `entries[0]`; starts at 1, so 0 is "before everything".
    first: u64,
    cap: usize,
}

impl Ring {
    /// Sequence number of the newest entry, `first - 1` (0 at the start) when empty.
    fn newest(&self) -> u64 {
        self.first + self.entries.len() as u64 - 1
    }
}

/// This node's request log.
pub struct RequestLog {
    ring: Mutex<Ring>,
}

impl Default for RequestLog {
    fn default() -> Self {
        Self::with_capacity(CAPACITY)
    }
}

/// One page of the log.
pub struct Page {
    /// Oldest first, with their sequence numbers.
    pub entries: Vec<(u64, Arc<Entry>)>,
    /// What to send as `since` next time.
    pub cursor: u64,
    /// Entries between the given cursor and the oldest one kept were
    /// dropped before anybody read them.
    pub gap: bool,
}

impl RequestLog {
    pub fn with_capacity(cap: usize) -> Self {
        RequestLog { ring: Mutex::new(Ring { entries: VecDeque::new(), first: 1, cap: cap.max(1) }) }
    }

    /// The ring stays usable even if a holder of the lock panicked: what it
    /// holds is never left half-changed by any of the short sections below.
    fn lock(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.ring.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add an entry, dropping the oldest when full; returns its sequence number.
    pub fn push(&self, entry: Entry) -> u64 {
        let entry = Arc::new(entry);
        let (seq, evicted) = {
            let mut ring = self.lock();
            let seq = ring.first + ring.entries.len() as u64;
            let evicted = if ring.entries.len() >= ring.cap {
                ring.first += 1;
                ring.entries.pop_front()
            } else {
                None
            };
            ring.entries.push_back(entry);
            (seq, evicted)
        };
        // freed here, outside the lock
        drop(evicted);
        seq
    }

    /// Sequence number of the newest entry (0 before the first).
    pub fn newest(&self) -> u64 {
        self.lock().newest()
    }

    /// Up to `limit` entries that `filter` lets through.
    ///
    /// - `since: None`: the newest such entries, the cursor at the newest
    ///   entry of the log (a client's first look).
    /// - `since: Some(n)`: the entries after `n`, oldest first. A cursor
    ///   older than the oldest entry kept starts from the oldest one and
    ///   sets `gap`. A cursor at or beyond the newest entry (from before a
    ///   restart, say) gets nothing, and the newest entry's number back to
    ///   go on from.
    /// - The cursor is the last entry returned when `limit` cut the page,
    ///   otherwise the newest entry looked at, so a filter that skips
    ///   everything still moves the client along.
    ///
    /// Only reference counts are taken under the lock; turning entries
    /// into JSON is left to the caller.
    pub fn query(&self, since: Option<u64>, limit: usize, filter: &Filter) -> Page {
        let ring = self.lock();
        let newest = ring.newest();
        let mut entries = Vec::new();
        match since {
            None => {
                for (i, e) in ring.entries.iter().enumerate().rev() {
                    if entries.len() == limit {
                        break;
                    }
                    if filter.matches(e) {
                        entries.push((ring.first + i as u64, e.clone()));
                    }
                }
                entries.reverse();
                Page { entries, cursor: newest, gap: false }
            }
            Some(since) if since >= newest => Page { entries, cursor: newest, gap: false },
            Some(since) => {
                let gap = since + 1 < ring.first;
                let start = usize::try_from((since + 1).saturating_sub(ring.first)).unwrap_or(usize::MAX);
                let mut cursor = newest;
                for (i, e) in ring.entries.iter().enumerate().skip(start) {
                    if filter.matches(e) {
                        entries.push((ring.first + i as u64, e.clone()));
                        if entries.len() == limit {
                            cursor = ring.first + i as u64;
                            break;
                        }
                    }
                }
                Page { entries, cursor, gap }
            }
        }
    }

    /// The API's answer: one page of one zone's log, as JSON.
    pub fn answer(&self, q: &LogQuery, node: &str) -> Value {
        let page = self.query(q.since, q.limit, &q.filter);
        let entries: Vec<Value> = page.entries.iter().map(|(seq, e)| e.to_json(*seq)).collect();
        json!({ "entries": entries, "cursor": page.cursor, "gap": page.gap, "node": node })
    }
}

// ------------------------------------------------------------- filters ----

/// A status code, or a class of them (`4xx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusMatch {
    Exact(u16),
    Class(u16),
}

/// Which entries a query or a log job wants. Always one zone's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    pub zone_id: String,
    pub status: Option<StatusMatch>,
    /// At least this status code (a log job's `status_min`; 0 for all).
    pub status_min: u16,
    /// Exact host, lowercase.
    pub host: Option<String>,
    /// Paths starting with this.
    pub path_prefix: Option<String>,
    pub ip: Option<IpAddr>,
}

impl Filter {
    pub fn matches(&self, e: &Entry) -> bool {
        e.zone_id == self.zone_id
            && e.status >= self.status_min
            && match self.status {
                None => true,
                Some(StatusMatch::Exact(s)) => e.status == s,
                Some(StatusMatch::Class(c)) => e.status / 100 == c,
            }
            && self.host.as_ref().is_none_or(|h| &e.host == h)
            && self.path_prefix.as_ref().is_none_or(|p| e.path.starts_with(p.as_str()))
            && self.ip.is_none_or(|ip| e.client_ip == ip)
    }
}

/// A `GET /zones/{id}/logs/requests` query, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct LogQuery {
    pub since: Option<u64>,
    pub limit: usize,
    pub filter: Filter,
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

impl LogQuery {
    /// Every parameter is checked and a bad or unknown one refused: a typo
    /// in a filter name must not quietly hand back everything.
    pub fn parse(zone_id: &str, params: &HashMap<String, String>) -> Result<LogQuery, String> {
        let mut q = LogQuery { since: None, limit: DEFAULT_LIMIT, filter: Filter { zone_id: zone_id.to_string(), ..Default::default() } };
        for (key, raw) in params {
            let v = raw.trim();
            if v.is_empty() {
                return Err(format!("'{key}' is empty"));
            }
            match key.as_str() {
                "since" => {
                    q.since = Some(v.parse().ok().filter(|_| digits(v)).ok_or("'since' must be the cursor (a whole number) of an earlier answer")?);
                }
                "limit" => {
                    q.limit = v
                        .parse::<usize>()
                        .ok()
                        .filter(|n| digits(v) && (1..=MAX_LIMIT).contains(n))
                        .ok_or(format!("'limit' must be a number from 1 to {MAX_LIMIT}"))?;
                }
                "status" => q.filter.status = Some(parse_status(v)?),
                "host" => {
                    let h = v.to_ascii_lowercase();
                    if h.len() > 253 || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:_".contains(&b)) {
                        return Err("'host' must be a host name".into());
                    }
                    q.filter.host = Some(h);
                }
                "path" => {
                    if !v.starts_with('/') || v.len() > PATH_MAX || v.chars().any(char::is_control) {
                        return Err(format!("'path' must start with / and be at most {PATH_MAX} bytes"));
                    }
                    q.filter.path_prefix = Some(v.to_string());
                }
                "ip" => {
                    let ip: IpAddr = v.parse().map_err(|_| "'ip' must be an IPv4 or IPv6 address".to_string())?;
                    q.filter.ip = Some(ip.to_canonical());
                }
                other => return Err(format!("unknown parameter '{other}' (since, limit, status, host, path and ip are known)")),
            }
        }
        Ok(q)
    }
}

/// `404` or `4xx`.
fn parse_status(v: &str) -> Result<StatusMatch, String> {
    let bad = || "'status' must be a status code like 404 or a class like 4xx".to_string();
    let b = v.as_bytes();
    if b.len() == 3 && (b'1'..=b'5').contains(&b[0]) && b[1..].eq_ignore_ascii_case(b"xx") {
        return Ok(StatusMatch::Class(u16::from(b[0] - b'0')));
    }
    match v.parse::<u16>() {
        Ok(code) if digits(v) && (100..=599).contains(&code) => Ok(StatusMatch::Exact(code)),
        _ => Err(bad()),
    }
}

// ------------------------------------------------------------ log jobs ----

fn yes() -> bool {
    true
}

fn batch_default() -> u32 {
    BATCH_DEFAULT
}

/// Pushes one zone's request log to an HTTPS address. Every node posts its
/// own entries there; the object itself is configuration like any other
/// and reaches every node with the rest of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogJob {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub name: String,
    /// `https://...`: where the NDJSON batches are posted.
    #[serde(default)]
    pub destination: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Only requests answered with at least this status (0: all of them).
    #[serde(default)]
    pub status_min: u16,
    /// How often each node posts what it collected.
    #[serde(default = "batch_default")]
    pub batch_seconds: u32,
}

impl Item for LogJob {
    fn vec(d: &Data) -> &Vec<Self> {
        &d.log_jobs
    }
    fn vec_mut(d: &mut Data) -> &mut Vec<Self> {
        &mut d.log_jobs
    }
    fn tombstones(d: &Data) -> &BTreeMap<String, SyncMeta> {
        &d.tombstones.log_jobs
    }
    fn tombstones_mut(d: &mut Data) -> &mut BTreeMap<String, SyncMeta> {
        &mut d.tombstones.log_jobs
    }
    fn meta(&self) -> &Meta {
        &self.meta
    }
    fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
    fn validate(&mut self, _: &Zone, _: &Data) -> Result<(), StoreError> {
        let invalid = |m: String| Err(StoreError::Invalid(m));
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.chars().count() > 64 || self.name.chars().any(char::is_control) {
            return invalid("a log job needs a name (max 64 characters)".into());
        }
        self.destination = self.destination.trim().to_string();
        check_destination(&self.destination).or_else(invalid)?;
        if self.status_min != 0 && !(100..=599).contains(&self.status_min) {
            return invalid("status_min must be 0 (every request) or a status code from 100 to 599".into());
        }
        if !(BATCH_MIN..=BATCH_MAX).contains(&self.batch_seconds) {
            return invalid(format!("batch_seconds must be between {BATCH_MIN} and {BATCH_MAX}"));
        }
        Ok(())
    }
}

/// A destination must be HTTPS (the batches hold visitor addresses), name a
/// host without credentials in the URL (they would not be sent, and would
/// end up wherever the configuration goes), and not be a private, loopback
/// or link-local address written out (the node must not be made to post
/// into its own network). Names that resolve to such addresses are refused
/// when connecting.
pub fn check_destination(url: &str) -> Result<(), String> {
    if url.is_empty() || url.len() > 2048 {
        return Err("destination must be an https:// URL of at most 2048 characters".into());
    }
    let uri: hyper::Uri = url.parse().map_err(|_| "destination is not a valid URL".to_string())?;
    if !uri.scheme_str().is_some_and(|s| s.eq_ignore_ascii_case("https")) {
        return Err("destination must be an https:// URL: the batches hold visitor addresses".into());
    }
    let Some(authority) = uri.authority() else { return Err("destination names no host".into()) };
    if authority.as_str().contains('@') {
        return Err("destination must not hold a user name or password; put a token in the path or query instead".into());
    }
    let host = authority.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if host.is_empty() {
        return Err("destination names no host".into());
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Err("destination must not be this machine".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if super::upstream::is_private_or_reserved_ip(ip) {
            return Err("destination must not be a private, loopback or link-local address".into());
        }
    }
    super::upstream::Target::from_url(url).map(|_| ())
}

// -------------------------------------------------------------- pushing ----

/// One batch due to go out.
#[derive(Debug, Clone, PartialEq)]
pub struct Batch {
    pub job_id: String,
    pub destination: String,
    /// NDJSON: one entry per line.
    pub body: Bytes,
    pub entries: usize,
}

/// The entries as NDJSON, each line ending in `\n`.
pub fn ndjson(entries: &[(u64, Arc<Entry>)]) -> Bytes {
    let mut out = Vec::new();
    for (seq, e) in entries {
        if serde_json::to_writer(&mut out, &e.to_json(*seq)).is_ok() {
            out.push(b'\n');
        }
    }
    Bytes::from(out)
}

/// Where each job of this node stands.
struct JobState {
    /// The last entry already handed to this job.
    cursor: u64,
    /// Unix seconds when the next batch is due.
    next_at: u64,
}

/// Decides which batches go out when; holds no connection and does no I/O,
/// so it is tested on its own.
#[derive(Default)]
pub struct Pusher {
    jobs: HashMap<String, JobState>,
}

impl Pusher {
    /// The batches due at `now` (unix seconds). A job seen for the first
    /// time (or enabled again) starts at the newest entry: it gets what
    /// comes from now on, not what the node happened to keep before. A
    /// batch is handed out once; whether it got through is not tracked.
    pub fn plan(&mut self, jobs: &[LogJob], now: u64, log: &RequestLog) -> Vec<Batch> {
        let mut out = Vec::new();
        let mut live = HashSet::new();
        for job in jobs.iter().filter(|j| j.enabled) {
            live.insert(job.meta.id.clone());
            let every = u64::from(job.batch_seconds.clamp(BATCH_MIN, BATCH_MAX));
            let state = self.jobs.entry(job.meta.id.clone()).or_insert_with(|| JobState { cursor: log.newest(), next_at: now + every });
            if now < state.next_at {
                continue;
            }
            state.next_at = now + every;
            let filter = Filter { zone_id: job.meta.zone_id.clone(), status_min: job.status_min, ..Default::default() };
            let page = log.query(Some(state.cursor), CAPACITY, &filter);
            state.cursor = page.cursor;
            if page.entries.is_empty() {
                continue;
            }
            out.push(Batch { job_id: job.meta.id.clone(), destination: job.destination.clone(), body: ndjson(&page.entries), entries: page.entries.len() });
        }
        self.jobs.retain(|id, _| live.contains(id));
        out
    }
}

/// Run the log jobs on this node: every node pushes the requests it
/// answered itself.
pub fn spawn_push(edge: Arc<Edge>) {
    tokio::spawn(async move {
        let mut pusher = Pusher::default();
        let mut tick = tokio::time::interval(PUSH_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let jobs = edge.store.all_items::<LogJob>();
            if jobs.is_empty() {
                continue;
            }
            let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
            for batch in pusher.plan(&jobs, now, &edge.reqlog) {
                if let Err(why) = post(&edge, &batch).await {
                    // the destination's path and query may hold a token: only its host is named
                    let host = batch.destination.parse::<hyper::Uri>().ok().and_then(|u| u.host().map(str::to_string)).unwrap_or_default();
                    tracing::warn!(job = %batch.job_id, %host, entries = batch.entries, "request log push failed ({why}); the batch is dropped");
                }
            }
        }
    });
}

/// Post one batch. The reasons given are fixed words, never the
/// destination or an error text that might quote it.
async fn post(edge: &Edge, batch: &Batch) -> Result<(), String> {
    let mut target = super::upstream::Target::from_url(&batch.destination).map_err(|_| "the destination is not a usable URL".to_string())?;
    // what the name resolves to is checked too, like for Worker subrequests
    target.block_private_ips = true;
    let uri: hyper::Uri = batch.destination.parse().map_err(|_| "the destination is not a usable URL".to_string())?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::USER_AGENT, concat!("fucf/", env!("CARGO_PKG_VERSION")))
        .body(super::full(batch.body.clone()))
        .map_err(|_| "the request could not be built".to_string())?;
    let exchange = async {
        let resp = edge.upstream.send(&target, req).await.map_err(|e| {
            match e {
                super::upstream::UpstreamError::Timeout => "timed out",
                super::upstream::UpstreamError::Tls(_) => "the TLS handshake or certificate check failed",
                super::upstream::UpstreamError::Down(m) | super::upstream::UpstreamError::Other(m) if m.contains("refusing to connect") => {
                    "the destination resolves to a private or reserved address"
                }
                super::upstream::UpstreamError::Down(_) => "could not connect",
                super::upstream::UpstreamError::Other(_) => "the request failed",
            }
            .to_string()
        })?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", resp.status().as_u16()))
        }
    };
    tokio::time::timeout(PUSH_TIMEOUT, exchange).await.map_err(|_| "timed out".to_string())?
}

#[cfg(test)]
pub(crate) fn sample(zone_id: &str, status: u16, path: &str) -> Entry {
    Entry {
        time_ms: 1_767_225_600_000,
        ray: "0123456789abcdef".into(),
        node: "test-node".into(),
        zone_id: zone_id.into(),
        host: "www.example.com".into(),
        method: "GET".into(),
        path: path.into(),
        status,
        cache: "MISS".into(),
        bytes: Some(42),
        duration_ms: 3,
        client_ip: "192.0.2.10".parse().unwrap(),
        country: "NL".into(),
        asn: 64496,
        user_agent: "test-agent/1.0".into(),
        protocol: "HTTP/1.1",
        action: "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::temp_store;

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn zone(id: &str) -> Filter {
        Filter { zone_id: id.into(), ..Default::default() }
    }

    fn seqs(page: &Page) -> Vec<u64> {
        page.entries.iter().map(|(s, _)| *s).collect()
    }

    #[test]
    fn the_ring_keeps_the_newest_entries_up_to_its_capacity() {
        let log = RequestLog::with_capacity(3);
        assert_eq!(log.newest(), 0, "nothing yet");
        for i in 1..=5u64 {
            assert_eq!(log.push(sample("z1", 200, &format!("/{i}"))), i);
        }
        assert_eq!(log.newest(), 5);
        let page = log.query(None, MAX_LIMIT, &zone("z1"));
        assert_eq!(seqs(&page), vec![3, 4, 5]);
        assert_eq!(page.entries.iter().map(|(_, e)| e.path.as_str()).collect::<Vec<_>>(), vec!["/3", "/4", "/5"]);
        assert_eq!(page.cursor, 5);

        // the real size
        let log = RequestLog::default();
        for _ in 0..CAPACITY + 1 {
            log.push(sample("z1", 200, "/"));
        }
        let page = log.query(Some(0), MAX_LIMIT, &zone("z1"));
        assert_eq!(page.entries.first().map(|(s, _)| *s), Some(2), "the very first entry is gone");
        assert!(page.gap);
        assert_eq!(log.query(None, CAPACITY + 10, &zone("z1")).entries.len(), CAPACITY);
    }

    #[test]
    fn a_cursor_older_than_the_oldest_entry_starts_from_the_oldest_and_says_so() {
        let log = RequestLog::with_capacity(3);
        for _ in 0..5 {
            log.push(sample("z1", 200, "/"));
        }
        for since in [0, 1] {
            let page = log.query(Some(since), MAX_LIMIT, &zone("z1"));
            assert_eq!(seqs(&page), vec![3, 4, 5], "since {since}");
            assert!(page.gap, "entries 2 (and 1) were never read");
            assert_eq!(page.cursor, 5);
        }
        let page = log.query(Some(2), MAX_LIMIT, &zone("z1"));
        assert_eq!(seqs(&page), vec![3, 4, 5]);
        assert!(!page.gap, "nothing after 2 was lost");
        let page = log.query(Some(3), MAX_LIMIT, &zone("z1"));
        assert_eq!(seqs(&page), vec![4, 5]);
    }

    #[test]
    fn a_cursor_from_the_future_returns_nothing_and_the_newest_cursor() {
        let log = RequestLog::with_capacity(10);
        for _ in 0..4 {
            log.push(sample("z1", 200, "/"));
        }
        for since in [4, 5, 1_000_000, u64::MAX] {
            let page = log.query(Some(since), MAX_LIMIT, &zone("z1"));
            assert!(page.entries.is_empty(), "since {since}");
            assert_eq!((page.cursor, page.gap), (4, false), "since {since}: go on from the newest");
        }
        // a client that took the cursor back gets what comes next
        log.push(sample("z1", 200, "/next"));
        assert_eq!(seqs(&log.query(Some(4), MAX_LIMIT, &zone("z1"))), vec![5]);

        // an empty log
        let empty = RequestLog::with_capacity(10);
        for since in [None, Some(0), Some(7)] {
            let page = empty.query(since, MAX_LIMIT, &zone("z1"));
            assert!(page.entries.is_empty());
            assert_eq!((page.cursor, page.gap), (0, false));
        }
    }

    #[test]
    fn without_a_cursor_the_newest_entries_come_back_oldest_first() {
        let log = RequestLog::with_capacity(100);
        for i in 0..10 {
            log.push(sample("z1", 200, &format!("/{i}")));
        }
        let page = log.query(None, 3, &zone("z1"));
        assert_eq!(seqs(&page), vec![8, 9, 10]);
        assert_eq!(page.cursor, 10);
    }

    #[test]
    fn a_limit_cuts_the_page_and_the_cursor_goes_on_after_the_last_entry() {
        let log = RequestLog::with_capacity(100);
        for i in 0..10 {
            log.push(sample("z1", if i % 2 == 0 { 200 } else { 404 }, "/"));
        }
        let only_404 = Filter { status: Some(StatusMatch::Exact(404)), ..zone("z1") };
        let mut since = 0;
        let mut seen = Vec::new();
        for _ in 0..10 {
            let page = log.query(Some(since), 2, &only_404);
            if page.entries.is_empty() {
                break;
            }
            seen.extend(seqs(&page));
            since = page.cursor;
        }
        assert_eq!(seen, vec![2, 4, 6, 8, 10], "every match once, in order");
        assert_eq!(since, 10);

        // a filter that matches nothing still moves the cursor to the newest
        let page = log.query(Some(3), 2, &Filter { status: Some(StatusMatch::Exact(500)), ..zone("z1") });
        assert!(page.entries.is_empty());
        assert_eq!(page.cursor, 10);
    }

    #[test]
    fn filters_match_the_zone_status_host_path_prefix_and_address() {
        let mut other_host = sample("z1", 503, "/api/v1/users");
        other_host.host = "api.example.com".into();
        other_host.client_ip = "2001:db8::7".parse().unwrap();
        let entries = [sample("z1", 200, "/"), sample("z1", 404, "/api/v1"), other_host, sample("z2", 404, "/api/v1")];
        let log = RequestLog::with_capacity(10);
        for e in entries {
            log.push(e);
        }
        let hits = |f: Filter| seqs(&log.query(Some(0), MAX_LIMIT, &f));
        assert_eq!(hits(zone("z1")), vec![1, 2, 3]);
        assert_eq!(hits(zone("z2")), vec![4], "another zone's entries never show");
        assert!(hits(zone("nope")).is_empty());
        assert_eq!(hits(Filter { status: Some(StatusMatch::Exact(404)), ..zone("z1") }), vec![2]);
        assert_eq!(hits(Filter { status: Some(StatusMatch::Class(5)), ..zone("z1") }), vec![3]);
        assert_eq!(hits(Filter { status: Some(StatusMatch::Class(3)), ..zone("z1") }), Vec::<u64>::new());
        assert_eq!(hits(Filter { status_min: 400, ..zone("z1") }), vec![2, 3]);
        assert_eq!(hits(Filter { host: Some("api.example.com".into()), ..zone("z1") }), vec![3]);
        assert_eq!(hits(Filter { path_prefix: Some("/api".into()), ..zone("z1") }), vec![2, 3]);
        assert_eq!(hits(Filter { path_prefix: Some("/api/v1/".into()), ..zone("z1") }), vec![3]);
        assert_eq!(hits(Filter { path_prefix: Some("/v1".into()), ..zone("z1") }), Vec::<u64>::new(), "a prefix, not a substring");
        assert_eq!(hits(Filter { ip: Some("2001:db8::7".parse().unwrap()), ..zone("z1") }), vec![3]);
        assert_eq!(hits(Filter { ip: Some("192.0.2.10".parse().unwrap()), status: Some(StatusMatch::Class(4)), ..zone("z1") }), vec![2], "filters add up");
    }

    #[test]
    fn clipping_keeps_whole_characters() {
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abcd", 3), "abc");
        assert_eq!(clip("", 3), "");
        // two-, three- and four-byte characters straddling the limit are dropped whole
        assert_eq!(clip("aé", 2), "a");
        assert_eq!(clip("aé", 3), "aé");
        assert_eq!(clip("中文", 4), "中");
        assert_eq!(clip("中文", 5), "中");
        assert_eq!(clip("中文", 6), "中文");
        assert_eq!(clip("x\u{1D11E}", 4), "x");
        assert_eq!(clip("\u{1D11E}", 3), "");

        let long_path = format!("/{}", "路".repeat(400));
        let p = clip(&long_path, PATH_MAX);
        assert!(p.len() <= PATH_MAX && p.len() > PATH_MAX - 3 && long_path.starts_with(p));
        let long_ua = "Mozilla/5.0 ".to_string() + &"é".repeat(300);
        let ua = clip(&long_ua, UA_MAX);
        assert!(ua.len() <= UA_MAX && ua.len() >= UA_MAX - 1 && long_ua.starts_with(ua));
        assert_eq!(ua.chars().last(), Some('é'));
    }

    #[test]
    fn query_parameters_are_checked_and_unknown_ones_refused() {
        let q = LogQuery::parse("z1", &params(&[])).unwrap();
        assert_eq!((q.since, q.limit, q.filter.clone()), (None, DEFAULT_LIMIT, zone("z1")));
        let q = LogQuery::parse(
            "z1",
            &params(&[("since", "42"), ("limit", "1000"), ("status", "5XX"), ("host", "WWW.Example.com"), ("path", "/api"), ("ip", "::ffff:192.0.2.1")]),
        )
        .unwrap();
        assert_eq!(q.since, Some(42));
        assert_eq!(q.limit, 1000);
        assert_eq!(q.filter.status, Some(StatusMatch::Class(5)));
        assert_eq!(q.filter.host.as_deref(), Some("www.example.com"));
        assert_eq!(q.filter.path_prefix.as_deref(), Some("/api"));
        assert_eq!(q.filter.ip, Some("192.0.2.1".parse().unwrap()), "v4-mapped addresses match their IPv4 form");
        assert_eq!(LogQuery::parse("z1", &params(&[("status", "404")])).unwrap().filter.status, Some(StatusMatch::Exact(404)));
        assert_eq!(LogQuery::parse("z1", &params(&[("since", "0")])).unwrap().since, Some(0));
        assert_eq!(LogQuery::parse("z1", &params(&[("limit", "1")])).unwrap().limit, 1);

        let bad = [
            ("since", "-1"),
            ("since", "+5"),
            ("since", "abc"),
            ("since", "1.5"),
            ("since", "99999999999999999999999"),
            ("since", ""),
            ("since", "  "),
            ("limit", "0"),
            ("limit", "1001"),
            ("limit", "-3"),
            ("limit", "ten"),
            ("limit", ""),
            ("status", "4x"),
            ("status", "6xx"),
            ("status", "0xx"),
            ("status", "99"),
            ("status", "600"),
            ("status", "+404"),
            ("status", "4044"),
            ("status", "abc"),
            ("status", ""),
            ("host", "bad host"),
            ("host", "example.com/path"),
            ("host", &"a".repeat(254)),
            ("host", ""),
            ("path", "api"),
            ("path", &format!("/{}", "a".repeat(PATH_MAX))),
            ("path", "/a\u{7}b"),
            ("path", ""),
            ("ip", "999.1.1.1"),
            ("ip", "192.0.2.0/24"),
            ("ip", "example.com"),
            ("ip", ""),
            ("foo", "1"),
            ("page", "2"),
        ];
        for (k, v) in bad {
            assert!(LogQuery::parse("z1", &params(&[(k, v)])).is_err(), "{k}={v:?} must be refused");
        }
    }

    #[test]
    fn blocking_actions_and_protocols_are_named() {
        let challenge = HeaderValue::from_static("challenge");
        assert_eq!(action(false, 403, None), "");
        assert_eq!(action(false, 403, Some(&challenge)), "", "an origin's own header does not count");
        assert_eq!(action(true, 403, None), "block");
        assert_eq!(action(true, 403, Some(&challenge)), "challenge");
        assert_eq!(action(true, 429, None), "rate_limit");
        assert_eq!(protocol(Version::HTTP_10), "HTTP/1.0");
        assert_eq!(protocol(Version::HTTP_11), "HTTP/1.1");
        assert_eq!(protocol(Version::HTTP_2), "HTTP/2");
        assert_eq!(protocol(Version::HTTP_3), "HTTP/3");
    }

    #[test]
    fn an_entry_is_shown_with_its_fields_and_ndjson_has_one_line_each() {
        let mut quiet = sample("z1", 200, "/");
        quiet.asn = 0;
        quiet.bytes = None;
        let entries = vec![(7, Arc::new(sample("z1", 404, "/missing"))), (8, Arc::new(quiet))];
        let v = entries[0].1.to_json(7);
        assert_eq!(v["seq"], 7);
        assert_eq!(v["time"], "2026-01-01T00:00:00.000Z");
        for (k, want) in [
            ("ray", json!("0123456789abcdef")),
            ("node", json!("test-node")),
            ("zone_id", json!("z1")),
            ("host", json!("www.example.com")),
            ("method", json!("GET")),
            ("path", json!("/missing")),
            ("status", json!(404)),
            ("cache", json!("MISS")),
            ("bytes", json!(42)),
            ("duration_ms", json!(3)),
            ("client_ip", json!("192.0.2.10")),
            ("country", json!("NL")),
            ("asn", json!(64496)),
            ("user_agent", json!("test-agent/1.0")),
            ("protocol", json!("HTTP/1.1")),
            ("action", json!("")),
        ] {
            assert_eq!(v[k], want, "{k}");
        }
        let body = ndjson(&entries);
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.ends_with('\n'));
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!((lines[0]["seq"].clone(), lines[1]["seq"].clone()), (json!(7), json!(8)));
        assert_eq!((lines[1]["asn"].clone(), lines[1]["bytes"].clone()), (Value::Null, Value::Null), "unknown is null, not 0");
        assert!(ndjson(&[]).is_empty());
    }

    fn job(id: &str, zone_id: &str, status_min: u16, batch_seconds: u32) -> LogJob {
        LogJob {
            meta: Meta { id: id.into(), zone_id: zone_id.into(), ..Default::default() },
            name: id.into(),
            destination: format!("https://logs.example.com/{id}"),
            enabled: true,
            status_min,
            batch_seconds,
        }
    }

    fn batch_seqs(b: &Batch) -> Vec<u64> {
        std::str::from_utf8(&b.body).unwrap().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["seq"].as_u64().unwrap()).collect()
    }

    #[test]
    fn a_job_gets_what_comes_after_it_starts_once_per_period_filtered() {
        let log = RequestLog::with_capacity(100);
        log.push(sample("z1", 500, "/before"));
        let jobs = vec![job("errors", "z1", 500, 10), job("all-z2", "z2", 0, 30)];
        let mut pusher = Pusher::default();
        assert!(pusher.plan(&jobs, 1000, &log).is_empty(), "first sight: nothing is due yet");

        log.push(sample("z1", 200, "/ok")); // 2
        log.push(sample("z1", 502, "/bad")); // 3
        log.push(sample("z2", 404, "/other")); // 4
        log.push(sample("z1", 503, "/worse")); // 5
        assert!(pusher.plan(&jobs, 1009, &log).is_empty(), "not before batch_seconds");
        let due = pusher.plan(&jobs, 1010, &log);
        assert_eq!(due.len(), 1, "the z2 job waits 30 seconds");
        assert_eq!(due[0].job_id, "errors");
        assert_eq!(due[0].destination, "https://logs.example.com/errors");
        assert_eq!(batch_seqs(&due[0]), vec![3, 5], "z1 only, status 500 and up, not what came before the job");
        assert_eq!(due[0].entries, 2);

        assert!(pusher.plan(&jobs, 1015, &log).is_empty());
        assert!(pusher.plan(&jobs, 1020, &log).is_empty(), "nothing new: no empty batch");
        log.push(sample("z1", 504, "/again")); // 6
        let due = pusher.plan(&jobs, 1030, &log);
        assert_eq!(due.iter().map(|b| (b.job_id.as_str(), batch_seqs(b))).collect::<Vec<_>>(), vec![("errors", vec![6]), ("all-z2", vec![4])]);
        assert!(pusher.plan(&jobs, 1040, &log).is_empty(), "each entry goes out once");
    }

    #[test]
    fn a_disabled_or_deleted_job_sends_nothing_and_starts_afresh() {
        let log = RequestLog::with_capacity(100);
        let mut j = job("j", "z1", 0, 10);
        let mut pusher = Pusher::default();
        assert!(pusher.plan(std::slice::from_ref(&j), 0, &log).is_empty());
        log.push(sample("z1", 200, "/1"));
        j.enabled = false;
        assert!(pusher.plan(std::slice::from_ref(&j), 10, &log).is_empty());
        log.push(sample("z1", 200, "/2"));
        j.enabled = true;
        assert!(pusher.plan(std::slice::from_ref(&j), 20, &log).is_empty(), "enabled again: starts at the newest entry");
        log.push(sample("z1", 200, "/3"));
        let due = pusher.plan(std::slice::from_ref(&j), 30, &log);
        assert_eq!(due.len(), 1);
        assert_eq!(batch_seqs(&due[0]), vec![3], "what came while it was off is not sent");

        assert!(pusher.plan(&[], 40, &log).is_empty());
        assert!(pusher.jobs.is_empty(), "a deleted job's place is forgotten");
    }

    #[test]
    fn a_job_that_fell_behind_the_ring_gets_what_is_left() {
        let log = RequestLog::with_capacity(3);
        let j = job("j", "z1", 0, 10);
        let mut pusher = Pusher::default();
        pusher.plan(std::slice::from_ref(&j), 0, &log);
        for _ in 0..5 {
            log.push(sample("z1", 200, "/"));
        }
        let due = pusher.plan(std::slice::from_ref(&j), 10, &log);
        assert_eq!(batch_seqs(&due[0]), vec![3, 4, 5]);
    }

    #[test]
    fn destinations_must_be_public_https_urls_without_credentials() {
        for ok in ["https://logs.example.com/ingest", "https://logs.example.com:8443/ingest?token=test-token", "https://203.0.113.5/x", "https://[2001:db8::5]/x", "HTTPS://logs.example.net/"] {
            assert_eq!(check_destination(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "http://logs.example.com/ingest",
            "ftp://logs.example.com/",
            "logs.example.com/ingest",
            "https://",
            "https://user:test-password@logs.example.com/",
            "https://localhost/ingest",
            "https://box.localhost/ingest",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://192.168.1.1/",
            "https://169.254.169.254/latest",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://logs example.com/",
            &format!("https://logs.example.com/{}", "a".repeat(2048)),
        ] {
            assert!(check_destination(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn log_jobs_are_checked_belong_to_their_zone_and_go_with_it() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let other = store.create_zone("example.net").unwrap().id;
        let j: LogJob = store.save_item(&z, None, json!({ "name": " errors ", "destination": "https://logs.example.com/in" }), true).unwrap();
        assert_eq!((j.name.as_str(), j.enabled, j.status_min, j.batch_seconds), ("errors", true, 0, BATCH_DEFAULT));
        assert_eq!(j.meta.zone_id, z);
        let forged: LogJob = store.save_item(&z, None, json!({ "name": "x", "destination": "https://logs.example.com/in", "zone_id": other }), true).unwrap();
        assert_eq!(forged.meta.zone_id, z, "the zone is the one in the path, not in the body");

        let base = json!({ "name": "j", "destination": "https://logs.example.com/in" });
        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b[k] = v;
            b
        };
        for bad in [
            with("destination", json!("http://logs.example.com/in")),
            with("destination", json!("https://10.1.2.3/in")),
            with("destination", json!("")),
            with("destination", json!(42)),
            with("name", json!("")),
            with("name", json!("   ")),
            with("name", json!("n".repeat(65))),
            with("status_min", json!(50)),
            with("status_min", json!(600)),
            with("status_min", json!(-1)),
            with("status_min", json!("500")),
            with("batch_seconds", json!(BATCH_MIN - 1)),
            with("batch_seconds", json!(BATCH_MAX + 1)),
            with("batch_seconds", json!(0)),
            with("enabled", json!("yes")),
            json!("not an object"),
        ] {
            let r = store.save_item::<LogJob>(&z, None, bad.clone(), true);
            assert!(matches!(r, Err(StoreError::Invalid(_))), "{bad} must be refused");
        }
        let edge_values: LogJob = store
            .save_item(&z, None, json!({ "name": "n".repeat(64), "destination": "https://logs.example.com/in", "status_min": 599, "batch_seconds": BATCH_MAX }), true)
            .unwrap();
        assert_eq!(edge_values.batch_seconds, BATCH_MAX);
        assert!(store.save_item::<LogJob>(&z, None, with("batch_seconds", json!(BATCH_MIN)), true).is_ok());
        assert!(store.save_item::<LogJob>(&z, None, with("status_min", json!(100)), true).is_ok());

        // another zone's job cannot be read, changed or deleted through this one
        assert!(matches!(store.item::<LogJob>(&other, &j.meta.id), Err(StoreError::NotFound)));
        assert!(matches!(store.save_item::<LogJob>(&other, Some(&j.meta.id), json!({ "enabled": false }), false), Err(StoreError::NotFound)));
        assert!(matches!(store.delete_item::<LogJob>(&other, &j.meta.id), Err(StoreError::NotFound)));
        assert!(matches!(store.save_item::<LogJob>("no-such-zone", None, base.clone(), true), Err(StoreError::ZoneNotFound)));
        assert!(matches!(store.item::<LogJob>(&z, "no-such-job"), Err(StoreError::NotFound)));

        let off: LogJob = store.save_item(&z, Some(&j.meta.id), json!({ "enabled": false }), false).unwrap();
        assert!(!off.enabled && off.destination == "https://logs.example.com/in", "a patch keeps the rest");
        assert_eq!(store.all_items::<LogJob>().len(), 5);
        store.delete_zone(&z).unwrap();
        assert!(store.all_items::<LogJob>().is_empty(), "a zone's jobs go with it");
    }
}
