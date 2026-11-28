//! How far the visitors are from each node, as the nodes measure it: the
//! round trip of a visitor's TLS 1.3 or QUIC handshake, kept per network
//! (the country, the province or state where it is known, the operator's AS
//! number) and told to the other nodes with the reports. The DNS can then
//! send a network to the node that answers it fastest (a steering rule with
//! the action `fastest`) instead of the one a hand-written rule guesses.

use crate::edge::stats::now_secs;
use crate::geo::Location;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

/// Networks kept per node.
const MAX_KEYS: usize = 4000;
/// A measurement older than this tells nothing: routes change.
const FRESH_SECS: u64 = 24 * 3600;
/// Handshakes it takes before a node's measurement of a network counts.
const MIN_SAMPLES: u32 = 5;
/// Weight of a new handshake in the running mean.
const WEIGHT: f32 = 0.2;

/// What a node measured for one network.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Measure {
    /// Running mean of the round trip, in milliseconds.
    pub ms: f32,
    /// Handshakes that went into it.
    pub n: u32,
    /// When the last one did (unix seconds).
    pub at: u64,
}

#[derive(Default)]
struct Own {
    table: HashMap<String, Measure>,
    /// The networks measured since the other nodes were last told (see
    /// [`Rtt::take_changed`]). A set, not a time: a handshake in the same
    /// second as the last report is told in the next one, and nothing twice.
    changed: HashSet<String>,
}

#[derive(Default)]
pub struct Rtt {
    /// What this node measured.
    own: Mutex<Own>,
    /// What the other nodes measured, by node.
    others: Mutex<HashMap<String, HashMap<String, Measure>>>,
}

/// The networks a place belongs to, the most precise first: `CN-JS/4134`,
/// `CN/4134`, `CN-JS`, `CN`. None without a country.
pub fn keys(loc: &Location) -> Vec<String> {
    let Some(country) = loc.country.as_deref() else { return Vec::new() };
    let mut keys = Vec::with_capacity(4);
    if let (Some(region), Some(asn)) = (&loc.region, loc.asn) {
        keys.push(format!("{country}-{region}/{asn}"));
    }
    if let Some(asn) = loc.asn {
        keys.push(format!("{country}/{asn}"));
    }
    if let Some(region) = &loc.region {
        keys.push(format!("{country}-{region}"));
    }
    keys.push(country.to_string());
    keys
}

impl Rtt {
    /// A visitor at `loc` took `rtt` for one round trip with this node.
    pub fn sample(&self, loc: &Location, rtt: Duration) {
        self.sample_at(now_secs(), loc, rtt);
    }

    fn sample_at(&self, now: u64, loc: &Location, rtt: Duration) {
        let ms = rtt.as_secs_f32() * 1000.0;
        if !(0.05..5000.0).contains(&ms) {
            return;
        }
        let mut own = self.own.lock().unwrap();
        for key in keys(loc) {
            if !own.table.contains_key(&key) && own.table.len() >= MAX_KEYS {
                own.table.retain(|_, m| now.saturating_sub(m.at) < FRESH_SECS);
                if own.table.len() >= MAX_KEYS {
                    continue;
                }
            }
            let m = own.table.entry(key.clone()).or_insert(Measure { ms, n: 0, at: now });
            m.ms += (ms - m.ms) * WEIGHT;
            (m.n, m.at) = (m.n.saturating_add(1), now);
            own.changed.insert(key);
        }
    }

    /// What this node measured since it last told the others.
    pub fn take_changed(&self) -> HashMap<String, Measure> {
        self.take_changed_at(now_secs())
    }

    fn take_changed_at(&self, now: u64) -> HashMap<String, Measure> {
        let mut own = self.own.lock().unwrap();
        let changed = std::mem::take(&mut own.changed);
        // (a network evicted since it was measured is no longer there to tell)
        changed.into_iter().filter_map(|k| own.table.get(&k).filter(|m| now.saturating_sub(m.at) < FRESH_SECS).map(|m| (k, *m))).collect()
    }

    /// What another node measured, from one of its reports: the later
    /// measurement of a network stays, in whatever order the reports come.
    pub fn merge(&self, node: &str, measured: &HashMap<String, Measure>) {
        if measured.is_empty() {
            return;
        }
        let mut others = self.others.lock().unwrap();
        let table = others.entry(node.to_string()).or_default();
        for (key, m) in measured {
            let room = table.len() < MAX_KEYS;
            match table.get_mut(key) {
                Some(have) if have.at >= m.at => {}
                Some(have) => *have = *m,
                None if room => {
                    table.insert(key.clone(), *m);
                }
                None => {}
            }
        }
    }

    fn of(&self, node: &str, me: &str, key: &str, now: u64) -> Option<Measure> {
        let m = if node == me { self.own.lock().unwrap().table.get(key).copied() } else { self.others.lock().unwrap().get(node)?.get(key).copied() }?;
        (m.n >= MIN_SAMPLES && now.saturating_sub(m.at) < FRESH_SECS).then_some(m)
    }

    /// The `candidates` that measured the visitors at `loc`, fastest first,
    /// with the network the comparison is for: the most precise one that at
    /// least two of them have enough fresh handshakes of. None when nothing
    /// tells them apart. `me` is this node's name.
    pub fn ranking(&self, loc: &Location, candidates: &[&str], me: &str) -> Option<(String, Vec<(String, f32)>)> {
        self.ranking_at(now_secs(), loc, candidates, me)
    }

    fn ranking_at(&self, now: u64, loc: &Location, candidates: &[&str], me: &str) -> Option<(String, Vec<(String, f32)>)> {
        keys(loc).into_iter().find_map(|key| {
            let mut measured: Vec<(String, f32)> =
                candidates.iter().filter_map(|node| Some((node.to_string(), self.of(node, me, &key, now)?.ms))).collect();
            if measured.len() < 2 {
                return None;
            }
            measured.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            Some((key, measured))
        })
    }

    /// Everything measured, for the panel: network -> node -> measurement.
    pub fn table(&self, me: &str) -> Value {
        let now = now_secs();
        let mut out: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        let mut add = |node: &str, table: &HashMap<String, Measure>| {
            for (key, m) in table.iter().filter(|(_, m)| now.saturating_sub(m.at) < FRESH_SECS) {
                out.entry(key.clone()).or_default().insert(node.to_string(), json!({ "ms": (m.ms * 10.0).round() / 10.0, "samples": m.n, "age": now.saturating_sub(m.at) }));
            }
        };
        add(me, &self.own.lock().unwrap().table);
        for (node, table) in self.others.lock().unwrap().iter() {
            add(node, table);
        }
        json!(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(country: &str, region: Option<&str>, asn: Option<u32>) -> Location {
        Location { country: Some(country.into()), region: region.map(String::from), asn, ..Default::default() }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_place_belongs_to_networks_from_precise_to_coarse() {
        assert_eq!(keys(&at("CN", Some("JS"), Some(4134))), ["CN-JS/4134", "CN/4134", "CN-JS", "CN"]);
        assert_eq!(keys(&at("DE", None, Some(3320))), ["DE/3320", "DE"]);
        assert_eq!(keys(&at("DE", None, None)), ["DE"]);
        assert!(keys(&Location::default()).is_empty());
    }

    #[test]
    fn the_fastest_node_for_a_network_is_told_from_what_the_nodes_measured() {
        let (here, there) = (Rtt::default(), Rtt::default());
        let js = at("CN", Some("JS"), Some(4134));
        let now = 1_000_000;
        // too few handshakes tell nothing yet
        for _ in 0..MIN_SAMPLES - 1 {
            here.sample_at(now, &js, ms(40));
        }
        assert_eq!(here.ranking_at(now, &js, &["a", "b"], "a"), None);
        here.sample_at(now, &js, ms(40));
        // one node alone is nothing to compare
        assert_eq!(here.ranking_at(now, &js, &["a", "b"], "a"), None);
        // b measures the same network and tells a
        for _ in 0..MIN_SAMPLES {
            there.sample_at(now, &js, ms(90));
        }
        let told = there.take_changed_at(now);
        assert_eq!(told.len(), 4);
        assert!(there.take_changed_at(now + 10).is_empty(), "told once");
        here.merge("b", &told);
        let (key, order) = here.ranking_at(now, &js, &["b", "a", "c"], "a").unwrap();
        assert_eq!((key.as_str(), order.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()), ("CN-JS/4134", vec!["a", "b"]));
        assert!((order[0].1 - 40.0).abs() < 0.01 && (order[1].1 - 90.0).abs() < 0.01, "{order:?}");
        // a visitor of another province on the same operator: compared by what is common to them
        let (key, _) = here.ranking_at(now, &at("CN", Some("SD"), Some(4134)), &["a", "b"], "a").unwrap();
        assert_eq!(key, "CN/4134");
        // b gets closer (a new route): the mean follows, and an older report coming late changes nothing
        for _ in 0..40 {
            there.sample_at(now + 60, &js, ms(10));
        }
        let later = there.take_changed_at(now + 60);
        here.merge("b", &later);
        here.merge("b", &told);
        assert_eq!(here.ranking_at(now + 60, &js, &["a", "b"], "a").unwrap().1[0].0, "b");
        // a day on, nothing of it counts any more
        assert_eq!(here.ranking_at(now + 60 + FRESH_SECS, &js, &["a", "b"], "a"), None);
    }

    #[test]
    fn a_handshake_in_the_same_second_as_a_report_is_told_in_the_next() {
        let rtt = Rtt::default();
        let de = at("DE", None, None);
        rtt.sample_at(5, &de, ms(30));
        assert_eq!(rtt.take_changed_at(5).len(), 1);
        assert!(rtt.take_changed_at(5).is_empty(), "nothing twice");
        rtt.sample_at(5, &de, ms(30));
        assert_eq!(rtt.take_changed_at(6).len(), 1, "not lost because the second is the same");
        rtt.sample_at(7, &de, ms(30));
        assert!(rtt.take_changed_at(7 + FRESH_SECS).is_empty(), "too old to tell by then");
    }

    #[test]
    fn what_is_not_a_round_trip_is_left_out() {
        let rtt = Rtt::default();
        let de = at("DE", None, None);
        rtt.sample_at(1, &de, Duration::from_secs(9));
        rtt.sample_at(1, &de, Duration::ZERO);
        rtt.sample_at(1, &Location::default(), ms(20));
        assert!(rtt.take_changed_at(2).is_empty());
    }
}
