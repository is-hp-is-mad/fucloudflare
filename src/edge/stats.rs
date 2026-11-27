//! Traffic analytics: per-zone counters in time buckets.
//!
//! Every node records the requests it serves. Replicas hand what they
//! recorded to the primary in periodic reports, so the primary holds the
//! fleet-wide picture, split by node. Minute buckets cover the last day and
//! hour buckets the last 30 days; the hour buckets of the last week also
//! carry breakdowns by country, status, cache status, host and path.
//! Everything survives restarts through a file in the data directory.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const MINUTES_KEPT: u64 = 25 * 60;
const HOURS_KEPT: u64 = 30 * 24;
/// Hour buckets older than this keep their counters but lose their breakdowns.
const BREAKDOWN_HOURS_KEPT: u64 = 7 * 24;
/// Longest window a query may ask for, in minutes.
pub const MAX_WINDOW: u64 = HOURS_KEPT * 60;
/// Distinct values tracked while an hour is being recorded ...
const HOSTS_CAP: usize = 50;
const PATHS_CAP: usize = 100;
/// ... and kept once it is over.
const SETTLED_CAP: usize = 20;
const SETTLED_COUNTRIES: usize = 60;
const OTHER: &str = "(other)";
/// Label of the node's own buckets until it is given a name for display.
const SELF: &str = "";

fn zero(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counters {
    #[serde(skip_serializing_if = "zero")]
    pub requests: u64,
    /// Response body bytes sent to visitors.
    #[serde(skip_serializing_if = "zero")]
    pub bytes: u64,
    /// Served from the edge cache (HIT, REVALIDATED, STALE or UPDATING).
    #[serde(skip_serializing_if = "zero")]
    pub cached: u64,
    /// Stopped by the WAF (blocked, rate limited or challenged).
    #[serde(skip_serializing_if = "zero")]
    pub threats: u64,
    #[serde(skip_serializing_if = "zero")]
    pub status_2xx: u64,
    #[serde(skip_serializing_if = "zero")]
    pub status_3xx: u64,
    #[serde(skip_serializing_if = "zero")]
    pub status_4xx: u64,
    #[serde(skip_serializing_if = "zero")]
    pub status_5xx: u64,
    #[serde(skip_serializing_if = "zero")]
    pub http1: u64,
    #[serde(skip_serializing_if = "zero")]
    pub http2: u64,
    #[serde(skip_serializing_if = "zero")]
    pub http3: u64,
}

impl Counters {
    pub fn add(&mut self, o: &Counters) {
        self.requests += o.requests;
        self.bytes += o.bytes;
        self.cached += o.cached;
        self.threats += o.threats;
        self.status_2xx += o.status_2xx;
        self.status_3xx += o.status_3xx;
        self.status_4xx += o.status_4xx;
        self.status_5xx += o.status_5xx;
        self.http1 += o.http1;
        self.http2 += o.http2;
        self.http3 += o.http3;
    }

    /// Every field, zero or not (what API clients get).
    pub fn json(&self) -> Value {
        json!({
            "requests": self.requests, "bytes": self.bytes, "cached": self.cached, "threats": self.threats,
            "status_2xx": self.status_2xx, "status_3xx": self.status_3xx,
            "status_4xx": self.status_4xx, "status_5xx": self.status_5xx,
            "http1": self.http1, "http2": self.http2, "http3": self.http3,
        })
    }
}

/// Request counts by a few dimensions.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dims {
    pub countries: BTreeMap<String, u64>,
    pub statuses: BTreeMap<String, u64>,
    pub cache: BTreeMap<String, u64>,
    pub hosts: BTreeMap<String, u64>,
    pub paths: BTreeMap<String, u64>,
}

/// Count `n` under `key`; once the map holds `cap` keys, new ones are lumped together.
fn bump(map: &mut BTreeMap<String, u64>, key: &str, n: u64, cap: usize) {
    if let Some(v) = map.get_mut(key) {
        *v += n;
    } else if map.len() >= cap {
        *map.entry(OTHER.to_string()).or_default() += n;
    } else {
        map.insert(key.to_string(), n);
    }
}

/// Keep the `cap` largest entries, folding the rest into one.
fn trim(map: &mut BTreeMap<String, u64>, cap: usize) {
    if map.len() <= cap + 1 {
        return;
    }
    let mut rest = map.remove(OTHER).unwrap_or(0);
    let mut entries: Vec<(String, u64)> = std::mem::take(map).into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rest += entries.iter().skip(cap).map(|(_, n)| n).sum::<u64>();
    map.extend(entries.into_iter().take(cap));
    if rest > 0 {
        map.insert(OTHER.to_string(), rest);
    }
}

impl Dims {
    fn add(&mut self, o: &Dims) {
        let all = [
            (&mut self.countries, &o.countries, usize::MAX),
            (&mut self.statuses, &o.statuses, usize::MAX),
            (&mut self.cache, &o.cache, usize::MAX),
            (&mut self.hosts, &o.hosts, HOSTS_CAP),
            (&mut self.paths, &o.paths, PATHS_CAP),
        ];
        for (mine, theirs, cap) in all {
            for (k, n) in theirs {
                *mine.entry(k.clone()).or_default() += n;
            }
            if cap != usize::MAX {
                trim(mine, cap);
            }
        }
    }

    /// Shrink the breakdowns of an hour that is over to their largest entries.
    fn settle(&mut self) {
        trim(&mut self.countries, SETTLED_COUNTRIES);
        trim(&mut self.hosts, SETTLED_CAP);
        trim(&mut self.paths, SETTLED_CAP);
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HourBucket {
    pub c: Counters,
    pub d: Dims,
}

/// The buckets of one zone as recorded by one node.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Series {
    /// Unix minute -> counters.
    pub minutes: BTreeMap<u64, Counters>,
    /// Unix hour -> counters and breakdowns.
    pub hours: BTreeMap<u64, HourBucket>,
}

/// One served request.
pub struct Sample<'a> {
    pub zone_id: &'a str,
    pub version: hyper::Version,
    pub status: u16,
    /// The response's `cf-cache-status`, when the request reached the cache logic.
    pub cache: Option<&'a str>,
    pub threat: bool,
    pub bytes: u64,
    /// ISO country code of the visitor, empty when unknown.
    pub country: &'a str,
    pub host: &'a str,
    pub path: &'a str,
}

/// Was a response with this `cf-cache-status` served from the cache?
pub fn served_from_cache(label: &str) -> bool {
    matches!(label, "HIT" | "REVALIDATED" | "STALE" | "UPDATING")
}

impl Series {
    fn record(&mut self, now: u64, s: &Sample) {
        let mut c = Counters { requests: 1, bytes: s.bytes, ..Default::default() };
        c.cached = s.cache.is_some_and(served_from_cache) as u64;
        c.threats = s.threat as u64;
        match s.status / 100 {
            2 => c.status_2xx = 1,
            3 => c.status_3xx = 1,
            4 => c.status_4xx = 1,
            5 => c.status_5xx = 1,
            _ => {}
        }
        match s.version {
            hyper::Version::HTTP_2 => c.http2 = 1,
            hyper::Version::HTTP_3 => c.http3 = 1,
            _ => c.http1 = 1,
        }
        self.minutes.entry(now / 60).or_default().add(&c);
        let hour = self.hours.entry(now / 3600).or_default();
        hour.c.add(&c);
        let country = if s.country.is_empty() { "XX" } else { s.country };
        bump(&mut hour.d.countries, country, 1, usize::MAX);
        bump(&mut hour.d.statuses, &s.status.to_string(), 1, usize::MAX);
        bump(&mut hour.d.cache, s.cache.unwrap_or("NONE"), 1, usize::MAX);
        bump(&mut hour.d.hosts, s.host, 1, HOSTS_CAP);
        let path: String = s.path.chars().take(120).collect();
        bump(&mut hour.d.paths, &path, 1, PATHS_CAP);
    }

    fn add_bytes(&mut self, now: u64, bytes: u64) {
        self.minutes.entry(now / 60).or_default().bytes += bytes;
        self.hours.entry(now / 3600).or_default().c.bytes += bytes;
    }

    fn merge(&mut self, other: &Series) {
        for (t, c) in &other.minutes {
            self.minutes.entry(*t).or_default().add(c);
        }
        for (t, b) in &other.hours {
            let mine = self.hours.entry(*t).or_default();
            mine.c.add(&b.c);
            mine.d.add(&b.d);
        }
    }

    fn prune(&mut self, now: u64) {
        let (first_minute, first_hour) = ((now / 60).saturating_sub(MINUTES_KEPT), (now / 3600).saturating_sub(HOURS_KEPT));
        self.minutes = self.minutes.split_off(&first_minute);
        self.hours = self.hours.split_off(&first_hour);
        let (current, detailed_from) = (now / 3600, (now / 3600).saturating_sub(BREAKDOWN_HOURS_KEPT));
        for (hour, bucket) in self.hours.iter_mut() {
            if *hour < detailed_from {
                bucket.d = Dims::default();
            } else if *hour < current {
                bucket.d.settle();
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.minutes.is_empty() && self.hours.is_empty()
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Inner {
    /// Zone id -> node label -> buckets. The empty label is this node itself.
    zones: HashMap<String, HashMap<String, Series>>,
    /// Recorded here and not yet handed to the primary (replicas only).
    outbox: HashMap<String, Series>,
    #[serde(skip)]
    dirty: bool,
}

#[derive(Default)]
pub struct Stats {
    inner: Mutex<Inner>,
    /// This node reports its outbox to peers.
    reporting: AtomicBool,
    /// `accelerate` mode: keep only the outbox, skipping 30-day in-RAM zone history.
    outbox_only: AtomicBool,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Largest entries of a breakdown, as `[{"name", "count"}]`.
fn top(map: &BTreeMap<String, u64>, n: usize) -> Value {
    let mut entries: Vec<(&String, &u64)> = map.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    Value::Array(entries.into_iter().take(n).map(|(k, v)| json!({ "name": k, "count": v })).collect())
}

/// Step (in minutes) that draws a window with about a hundred points.
fn auto_step(window: u64, finest: u64) -> u64 {
    const STEPS: &[u64] = &[1, 5, 15, 30, 60, 120, 360, 720, 1440];
    STEPS.iter().copied().find(|s| *s >= finest && window.div_ceil(*s) <= 100).unwrap_or(1440)
}

impl Stats {
    pub fn new_ephemeral_reporting() -> Stats {
        Stats {
            inner: Mutex::default(),
            reporting: AtomicBool::new(true),
            outbox_only: AtomicBool::new(true),
        }
    }

    /// Start keeping an outbox of what is recorded, for [`Stats::take_outbox`].
    pub fn set_reporting(&self) {
        self.reporting.store(true, Ordering::Relaxed);
    }

    pub fn record(&self, s: Sample) {
        self.record_at(now_secs(), s);
    }

    pub fn record_at(&self, now: u64, s: Sample) {
        let mut inner = self.inner.lock().unwrap();
        if !self.outbox_only.load(Ordering::Relaxed) {
            inner.zones.entry(s.zone_id.to_string()).or_default().entry(SELF.to_string()).or_default().record(now, &s);
        }
        if self.reporting.load(Ordering::Relaxed) {
            inner.outbox.entry(s.zone_id.to_string()).or_default().record(now, &s);
        }
        inner.dirty = true;
    }

    /// Book response body bytes sent for a zone (they are known only once a
    /// response is over, after its request was recorded).
    pub fn add_bytes(&self, zone_id: &str, bytes: u64) {
        let now = now_secs();
        let mut inner = self.inner.lock().unwrap();
        if !self.outbox_only.load(Ordering::Relaxed) {
            inner.zones.entry(zone_id.to_string()).or_default().entry(SELF.to_string()).or_default().add_bytes(now, bytes);
        }
        if self.reporting.load(Ordering::Relaxed) {
            inner.outbox.entry(zone_id.to_string()).or_default().add_bytes(now, bytes);
        }
        inner.dirty = true;
    }

    /// What was recorded since the last call, for delivery to the primary.
    pub fn take_outbox(&self) -> HashMap<String, Series> {
        let mut inner = self.inner.lock().unwrap();
        inner.dirty |= !inner.outbox.is_empty();
        std::mem::take(&mut inner.outbox)
    }

    /// Primary side: add what `node` recorded.
    pub fn absorb(&self, node: &str, delta: &HashMap<String, Series>) {
        let now = now_secs();
        let mut inner = self.inner.lock().unwrap();
        for (zone, series) in delta {
            let mine = inner.zones.entry(zone.clone()).or_default().entry(node.to_string()).or_default();
            mine.merge(series);
            mine.prune(now);
        }
        inner.dirty = true;
    }

    /// Totals of every zone over the last `window` minutes.
    pub fn summary(&self, window: u64) -> HashMap<String, Counters> {
        self.summary_at(now_secs(), window)
    }

    fn summary_at(&self, now: u64, window: u64) -> HashMap<String, Counters> {
        let window = window.clamp(1, MAX_WINDOW);
        let inner = self.inner.lock().unwrap();
        let mut out = HashMap::new();
        for (zone, nodes) in &inner.zones {
            let mut total = Counters::default();
            for series in nodes.values() {
                if window <= 24 * 60 {
                    let first = (now / 60 + 1).saturating_sub(window);
                    series.minutes.range(first..).for_each(|(_, c)| total.add(c));
                } else {
                    let first = (now / 3600 + 1).saturating_sub(window / 60);
                    series.hours.range(first..).for_each(|(_, b)| total.add(&b.c));
                }
            }
            out.insert(zone.clone(), total);
        }
        out
    }

    /// Analytics of one zone over the last `window` minutes: totals (also
    /// flattened into the top level), a time series, the split by node and
    /// the breakdowns. `self_name` labels this node's own share.
    pub fn report(&self, zone_id: &str, self_name: &str, window: u64, step: Option<u64>) -> Value {
        self.report_at(now_secs(), zone_id, self_name, window, step)
    }

    pub fn report_at(&self, now: u64, zone_id: &str, self_name: &str, window: u64, step: Option<u64>) -> Value {
        let window = window.clamp(1, MAX_WINDOW);
        // Up to a day comes from the minute buckets, anything longer from the hour buckets.
        let fine = window <= 24 * 60;
        let unit = if fine { 60 } else { 3600 };
        let finest = if fine { 1 } else { 60 };
        let step = step.filter(|s| *s >= finest && *s <= window.max(finest)).unwrap_or_else(|| auto_step(window, finest));
        let step_units = (step * 60 / unit).max(1);
        let last = now / unit;
        let first = ((last + 1).saturating_sub(window * 60 / unit) / step_units) * step_units;
        let slots = ((last - first) / step_units + 1) as usize;

        let inner = self.inner.lock().unwrap();
        let empty = HashMap::new();
        let nodes = inner.zones.get(zone_id).unwrap_or(&empty);
        let mut points = vec![Counters::default(); slots];
        let mut by_node: BTreeMap<String, Counters> = BTreeMap::new();
        let mut dims = Dims::default();
        for (label, series) in nodes {
            let name = if label == SELF { self_name } else { label.as_str() };
            let node_total = by_node.entry(name.to_string()).or_default();
            let mut add = |t: u64, c: &Counters| {
                points[((t - first) / step_units) as usize].add(c);
                node_total.add(c);
            };
            if fine {
                series.minutes.range(first..=last).for_each(|(t, c)| add(*t, c));
            } else {
                series.hours.range(first..=last).for_each(|(t, b)| add(*t, &b.c));
            }
            // Breakdowns only exist per hour, and for the last week: take
            // every such hour the window touches.
            let first_hour = (first * unit / 3600).max((now / 3600).saturating_sub(BREAKDOWN_HOURS_KEPT));
            series.hours.range(first_hour..).for_each(|(_, b)| dims.add(&b.d));
        }
        drop(inner);

        let mut totals = Counters::default();
        points.iter().for_each(|p| totals.add(p));
        let series: Vec<Value> = points
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut v = p.json();
                v["t"] = json!(rfc3339((first + i as u64 * step_units) * unit));
                v
            })
            .collect();
        let mut out = totals.json();
        out["since"] = json!(rfc3339(first * unit));
        out["until"] = json!(rfc3339(now));
        out["window"] = json!(window);
        out["step"] = json!(step_units * unit / 60);
        out["totals"] = totals.json();
        out["series"] = Value::Array(series);
        out["by_node"] = Value::Object(by_node.iter().filter(|(_, c)| c.requests > 0).map(|(k, c)| (k.clone(), c.json())).collect());
        out["top"] = json!({
            "countries": top(&dims.countries, 20),
            "statuses": top(&dims.statuses, 20),
            "cache": top(&dims.cache, 10),
            "hosts": top(&dims.hosts, 15),
            "paths": top(&dims.paths, 15),
        });
        out
    }

    // ---- persistence ----

    pub fn load(path: &Path) -> Stats {
        let inner = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Inner>(&bytes).unwrap_or_else(|e| {
                tracing::warn!("ignoring unreadable analytics file {}: {e}", path.display());
                Inner::default()
            }),
            Err(_) => Inner::default(),
        };
        Stats { inner: Mutex::new(inner), reporting: AtomicBool::new(false), outbox_only: AtomicBool::new(false) }
    }

    /// Write the buckets to `path` if anything changed since the last save.
    /// Buckets past their retention and zones not in `zones` are dropped first.
    /// Serialization and disk I/O run outside `inner: Mutex`.
    pub fn save(&self, path: &Path, zones: &HashSet<String>) -> std::io::Result<()> {
        if self.outbox_only.load(Ordering::Relaxed) {
            return Ok(());
        }
        let now = now_secs();
        let snapshot = {
            let mut inner = self.inner.lock().unwrap();
            if !inner.dirty {
                return Ok(());
            }
            inner.zones.retain(|id, _| zones.contains(id));
            inner.outbox.retain(|id, _| zones.contains(id));
            for nodes in inner.zones.values_mut() {
                nodes.values_mut().for_each(|s| s.prune(now));
                nodes.retain(|_, s| !s.is_empty());
            }
            inner.outbox.values_mut().for_each(|s| s.prune(now));
            inner.dirty = false;
            Inner { zones: inner.zones.clone(), outbox: inner.outbox.clone(), dirty: false }
        };
        let bytes = serde_json::to_vec(&snapshot).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, path)) {
            self.inner.lock().unwrap().dirty = true;
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>(zone: &'a str, status: u16, cache: Option<&'a str>, country: &'a str, path: &'a str) -> Sample<'a> {
        Sample { zone_id: zone, version: hyper::Version::HTTP_2, status, cache, threat: status == 403, bytes: 100, country, host: "example.com", path }
    }

    #[test]
    fn buckets_windows_and_breakdowns() {
        let stats = Stats::default();
        let now = 1_800_000_000 + 30; // half a minute into a minute
        // 3 requests now, 2 ten minutes ago, 1 three hours ago, 1 two days ago
        for _ in 0..3 {
            stats.record_at(now, sample("z", 200, Some("HIT"), "CN", "/a.js"));
        }
        stats.record_at(now - 600, sample("z", 200, Some("MISS"), "US", "/a.js"));
        stats.record_at(now - 600, sample("z", 403, None, "", "/admin"));
        stats.record_at(now - 3 * 3600, sample("z", 502, Some("DYNAMIC"), "CN", "/api"));
        stats.record_at(now - 48 * 3600, sample("z", 200, Some("HIT"), "DE", "/old"));
        stats.record_at(now, sample("other", 200, None, "CN", "/"));

        // the last hour, minute resolution
        let r = stats.report_at(now, "z", "au", 60, None);
        assert_eq!((r["requests"].as_u64(), r["cached"].as_u64(), r["threats"].as_u64()), (Some(5), Some(3), Some(1)));
        assert_eq!((r["status_2xx"].as_u64(), r["status_4xx"].as_u64(), r["http2"].as_u64()), (Some(4), Some(1), Some(5)));
        assert_eq!(r["bytes"], 500);
        assert_eq!(r["totals"]["requests"], 5);
        let series = r["series"].as_array().unwrap();
        assert_eq!((r["step"].as_u64(), series.len()), (Some(1), 60));
        assert_eq!(series.last().unwrap()["requests"], 3);
        assert_eq!(series[series.len() - 11]["requests"], 2);
        assert_eq!(series.iter().map(|p| p["requests"].as_u64().unwrap()).sum::<u64>(), 5);
        assert_eq!(r["by_node"]["au"]["requests"], 5);

        // a day: coarser steps, the request of three hours ago is in
        let r = stats.report_at(now, "z", "au", 24 * 60, None);
        assert_eq!((r["requests"].as_u64(), r["status_5xx"].as_u64(), r["step"].as_u64()), (Some(6), Some(1), Some(15)));
        assert!(r["series"].as_array().unwrap().len() <= 97);
        assert_eq!(r["top"]["countries"][0], json!({ "name": "CN", "count": 4 }));
        assert_eq!(r["top"]["paths"][0], json!({ "name": "/a.js", "count": 4 }));
        assert!(r["top"]["countries"].as_array().unwrap().contains(&json!({ "name": "XX", "count": 1 })));
        assert!(r["top"]["cache"].as_array().unwrap().contains(&json!({ "name": "NONE", "count": 1 })));
        assert!(r["top"]["statuses"].as_array().unwrap().contains(&json!({ "name": "403", "count": 1 })));

        // a week comes from the hour buckets and reaches the oldest request
        let r = stats.report_at(now, "z", "au", 7 * 24 * 60, None);
        assert_eq!((r["requests"].as_u64(), r["step"].as_u64()), (Some(7), Some(120)));
        assert_eq!(r["series"].as_array().unwrap().iter().map(|p| p["requests"].as_u64().unwrap()).sum::<u64>(), 7);
        // an explicit step is honoured; an unknown zone is all zeroes
        assert_eq!(stats.report_at(now, "z", "au", 60, Some(15))["series"].as_array().unwrap().len(), 5);
        assert_eq!(stats.report_at(now, "nope", "au", 60, None)["requests"], 0);

        let all = stats.summary_at(now, 60);
        assert_eq!((all["z"].requests, all["other"].requests), (5, 1));
        assert_eq!(stats.summary_at(now, 7 * 24 * 60)["z"].requests, 7);
    }

    #[test]
    fn replicas_report_to_the_primary() {
        let (primary, replica) = (Stats::default(), Stats::default());
        replica.set_reporting();
        let now = now_secs();
        primary.record_at(now, sample("z", 200, Some("HIT"), "AU", "/"));
        replica.record_at(now, sample("z", 200, Some("MISS"), "SE", "/"));
        replica.record_at(now, sample("z", 404, None, "SE", "/nope"));

        let delta = replica.take_outbox();
        assert!(replica.take_outbox().is_empty(), "the outbox is handed over once");
        // what travels is plain JSON
        let delta: HashMap<String, Series> = serde_json::from_str(&serde_json::to_string(&delta).unwrap()).unwrap();
        primary.absorb("eu", &delta);
        replica.record_at(now, sample("z", 200, None, "SE", "/"));
        primary.absorb("eu", &replica.take_outbox());

        let r = primary.report_at(now, "z", "au", 60, None);
        assert_eq!(r["requests"], 4);
        assert_eq!((r["by_node"]["au"]["requests"].as_u64(), r["by_node"]["eu"]["requests"].as_u64()), (Some(1), Some(3)));
        assert_eq!(r["top"]["countries"][0], json!({ "name": "SE", "count": 3 }));
        // the replica still has its own view
        assert_eq!(replica.report_at(now, "z", "eu", 60, None)["requests"], 3);
    }

    #[test]
    fn survives_restarts_and_forgets_old_data() {
        let path = std::env::temp_dir().join(format!("fucf-stats-{}.json", uuid::Uuid::new_v4().simple()));
        let stats = Stats::default();
        let now = now_secs();
        stats.record_at(now, sample("z", 200, Some("HIT"), "CN", "/"));
        stats.record_at(now - 40 * 24 * 3600, sample("z", 200, None, "CN", "/ancient"));
        stats.record_at(now, sample("deleted", 200, None, "CN", "/"));
        let zones: HashSet<String> = ["z".to_string()].into();
        stats.save(&path, &zones).unwrap();

        let loaded = Stats::load(&path);
        let r = loaded.report_at(now, "z", "n", MAX_WINDOW, None);
        assert_eq!(r["requests"], 1, "buckets past the retention are dropped");
        assert_eq!(loaded.report_at(now, "deleted", "n", 60, None)["requests"], 0);
        // nothing changed: no rewrite
        std::fs::remove_file(&path).unwrap();
        stats.save(&path, &zones).unwrap();
        assert!(!path.exists());
        assert_eq!(Stats::load(&path).report_at(now, "z", "n", 60, None)["requests"], 0);
    }

    #[test]
    fn breakdowns_are_bounded() {
        let mut series = Series::default();
        for i in 0..500 {
            let path = format!("/p{i}");
            series.record(1_800_000_000, &sample("z", 200, None, "CN", &path));
        }
        let hour = series.hours.values().next().unwrap();
        assert_eq!(hour.d.paths.len(), PATHS_CAP + 1);
        assert_eq!(hour.d.paths[OTHER], 400);
        // once the hour is over only the largest entries are kept; after a week none
        series.prune(1_800_000_000 + 3600);
        let hour = series.hours.values().next().unwrap();
        assert_eq!((hour.d.paths.len(), hour.d.paths.values().sum::<u64>()), (SETTLED_CAP + 1, 500));
        series.prune(1_800_000_000 + (BREAKDOWN_HOURS_KEPT + 2) * 3600);
        let hour = series.hours.values().next().unwrap();
        assert!(hour.d.paths.is_empty() && hour.c.requests == 500, "old hours keep their counters only");
        // merging keeps the largest entries
        let mut a = Dims::default();
        for i in 0..150u64 {
            a.hosts.insert(format!("h{i:03}"), i + 1);
        }
        let mut merged = Dims::default();
        merged.add(&a);
        assert_eq!(merged.hosts.len(), HOSTS_CAP + 1);
        assert!(merged.hosts.contains_key("h149") && !merged.hosts.contains_key("h000"));
        assert_eq!(merged.hosts.values().sum::<u64>(), (1..=150).sum::<u64>());
    }
}
