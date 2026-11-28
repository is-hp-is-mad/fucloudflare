//! The origins of a name with several addresses: which of them are up, as
//! this node's own checks say (a zone's `origin_check_path` is asked of every
//! address every `origin_check_interval` seconds), and in which order a
//! request tries them (by their weights, the same visitor to the same one
//! with `session_affinity`; an address that fails its check goes last).

use super::upstream::Target;
use super::Edge;
use crate::expr::ReqInfo;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long an origin has to answer a check.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Checks in a row an address has to fail before requests avoid it.
const FAILS: u32 = 2;

/// (zone id, name, address)
type Key = (String, String, String);

#[derive(Clone, Default)]
struct Check {
    fails: u32,
    down: bool,
    asked: Option<Instant>,
    checked_at: String,
    detail: String,
}

#[derive(Default)]
pub struct Health {
    checks: Mutex<HashMap<Key, Check>>,
}

impl Health {
    /// Does the address fail its check, asked for `name` of that zone?
    pub fn is_down(&self, zone: &str, name: &str, addr: &str) -> bool {
        self.checks.lock().unwrap().get(&(zone.to_string(), name.to_string(), addr.to_string())).is_some_and(|c| c.down)
    }

    /// Is it time to check again? Says so once per interval.
    fn due(&self, key: &Key, every: Duration) -> bool {
        let mut checks = self.checks.lock().unwrap();
        let check = checks.entry(key.clone()).or_default();
        if check.asked.is_some_and(|at| at.elapsed() < every) {
            return false;
        }
        check.asked = Some(Instant::now());
        true
    }

    /// The outcome of a check (the status, or why there was none). Whether the
    /// address went down or came back with it.
    fn settle(&self, key: &Key, outcome: Result<u16, String>) -> Option<bool> {
        let mut checks = self.checks.lock().unwrap();
        let check = checks.entry(key.clone()).or_default();
        check.checked_at = crate::store::now();
        let was = check.down;
        match outcome {
            Ok(status) if (200..400).contains(&status) => {
                (check.fails, check.down, check.detail) = (0, false, format!("HTTP {status}"));
            }
            other => {
                check.fails = check.fails.saturating_add(1);
                check.down = check.fails >= FAILS;
                check.detail = other.map_or_else(|e| e, |status| format!("HTTP {status}"));
            }
        }
        (check.down != was).then_some(check.down)
    }

    /// Drop what is no longer checked.
    fn keep_only(&self, live: &HashSet<Key>) {
        self.checks.lock().unwrap().retain(|key, _| live.contains(key));
    }

    /// What this node's checks say about the origins of a zone.
    pub fn report(&self, zone: &str) -> Value {
        let checks = self.checks.lock().unwrap();
        let mut list: Vec<(&Key, &Check)> = checks.iter().filter(|(key, _)| key.0 == zone).collect();
        list.sort_by(|a, b| a.0.cmp(b.0));
        Value::Array(
            list.into_iter()
                .map(|((_, name, addr), c)| json!({ "name": name, "address": addr, "healthy": !c.down, "failures": c.fails, "checked_at": c.checked_at, "detail": c.detail }))
                .collect(),
        )
    }
}

/// Which of the addresses (by their weights; none: the first) turn number
/// `turn` starts with.
pub fn pick(weights: &[u32], turn: usize) -> usize {
    let total: usize = weights.iter().map(|w| (*w).max(1) as usize).sum();
    if total == 0 {
        return 0;
    }
    let mut at = turn % total;
    for (i, w) in weights.iter().enumerate() {
        let w = (*w).max(1) as usize;
        if at < w {
            return i;
        }
        at -= w;
    }
    0
}

/// A visitor's place among the turns: the same for the same address.
pub fn turn_of(ip: IpAddr) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.finish() as usize
}

async fn ask(edge: &Edge, target: &Target, path: &str) -> Result<u16, String> {
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(path)
        .header("user-agent", concat!("fucf-health/", env!("CARGO_PKG_VERSION")))
        .body(super::full(bytes::Bytes::new()))
        .map_err(|e| e.to_string())?;
    match tokio::time::timeout(TIMEOUT, edge.upstream.send(target, req)).await {
        Err(_) => Err("no answer in time".into()),
        Ok(Err(e)) => Err(format!("{e:?}")),
        Ok(Ok(resp)) => Ok(resp.status().as_u16()),
    }
}

/// Check the origins of the zones that ask for it, for as long as the process runs.
pub async fn run(edge: Arc<Edge>) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let snap = edge.store.snapshot();
        let mut live = HashSet::new();
        for zone in snap.zones.values() {
            let settings = &zone.zone.settings;
            if settings.origin_check_path.is_empty() || zone.zone.paused {
                continue;
            }
            let every = Duration::from_secs(u64::from(settings.origin_check_interval.max(10)));
            for (name, records) in zone.names.iter().filter(|(name, _)| !name.starts_with("*.")) {
                for record in records.iter().filter(|r| r.proxied && matches!(r.rtype.as_str(), "A" | "AAAA")) {
                    let key: Key = (zone.zone.id.clone(), name.clone(), record.content.clone());
                    live.insert(key.clone());
                    if !edge.origins.due(&key, every) {
                        continue;
                    }
                    // as a request for that name would reach it; a rule that sends the name elsewhere leaves its addresses unasked
                    let info = ReqInfo { host: name.clone(), method: "GET".into(), path: settings.origin_check_path.clone(), ssl: true, ..Default::default() };
                    let Ok(target) = edge.resolve_target(&snap, zone, &info) else { continue };
                    if target.host != record.content && !target.alternates.contains(&record.content) {
                        continue;
                    }
                    let target = Target { host: record.content.clone(), alternates: Vec::new(), ..target };
                    let (edge, path) = (edge.clone(), settings.origin_check_path.clone());
                    tokio::spawn(async move {
                        let outcome = ask(&edge, &target, &path).await;
                        let said = outcome.as_ref().map_or_else(|e| e.clone(), |status| format!("HTTP {status}"));
                        match edge.origins.settle(&key, outcome) {
                            Some(true) => tracing::warn!("origin {} of {} fails its health check ({said}): requests go to the others", key.2, key.1),
                            Some(false) => tracing::info!("origin {} of {} passes its health check again", key.2, key.1),
                            None => {}
                        }
                    });
                }
            }
        }
        edge.origins.keep_only(&live);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_avoided_after_two_failed_checks_and_taken_back_after_one_good() {
        let health = Health::default();
        let key: Key = ("z".into(), "app.example.com".into(), "192.0.2.1".into());
        assert!(health.due(&key, Duration::from_secs(30)) && !health.due(&key, Duration::from_secs(30)), "once per interval");
        assert_eq!(health.settle(&key, Err("connection refused".into())), None);
        assert!(!health.is_down("z", "app.example.com", "192.0.2.1"));
        assert_eq!(health.settle(&key, Ok(503)), Some(true));
        assert!(health.is_down("z", "app.example.com", "192.0.2.1") && !health.is_down("z", "other.example.com", "192.0.2.1"));
        assert_eq!(health.report("z")[0]["detail"], "HTTP 503");
        assert_eq!((health.settle(&key, Ok(500)), health.settle(&key, Ok(302))), (None, Some(false)));
        assert_eq!((health.report("z")[0]["healthy"].as_bool(), health.report("other").as_array().map(Vec::len)), (Some(true), Some(0)));
        health.keep_only(&HashSet::new());
        assert_eq!(health.report("z"), json!([]));
    }

    #[test]
    fn turns_follow_the_weights() {
        let weights = [3, 1, 0];
        let starts: Vec<usize> = (0..10).map(|turn| pick(&weights, turn)).collect();
        assert_eq!(starts, [0, 0, 0, 1, 2, 0, 0, 0, 1, 2], "a weight of 0 counts as 1");
        assert_eq!((pick(&[], 7), pick(&[5], 7)), (0, 0));
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(turn_of(ip), turn_of(ip));
    }
}
