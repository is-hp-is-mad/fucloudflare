//! Rate limits counted across the fleet, approximately.
//!
//! Every node counts the requests of a client in its own fixed windows (see
//! `super::waf`). Left at that, a client spread over five nodes gets five
//! times its limit. So each node tells the others, with the reports it sends
//! anyway (`rate` in `crate::reports::Report`), the hottest of its counts:
//! the keys whose count passed half of the rule's limit, at most
//! [`REPORT_KEYS`] of them, each with the end of the window it was counted in.
//! A node keeps what the others told it in a remote view and weighs it in:
//! the count a request is judged by is its local count plus
//! [`REMOTE_WEIGHT`] times the sum of the other nodes' counts for the same
//! rule and key.
//!
//! This is approximate, not exact: reports come every 15 to 60 seconds, the
//! windows of the nodes do not line up, and a key that stays under half the
//! limit on every node is never reported. It narrows the gap, it does not
//! close it.
//!
//! What the view holds, and why:
//! - per (rule, key), one count per node: a node that reports the same key
//!   again in the same window replaces its count (a report sent twice, or a
//!   later one with the count grown, must not add up); a newer window
//!   replaces an older one; an older one that arrives late is ignored;
//! - a count stops counting when its window ends; a window said to end more
//!   than [`MAX_PERIOD_SECS`] from now is cut to that (a clock far ahead);
//! - a node's own reports never come into its view (they echo back through
//!   the peers);
//! - bounded: [`VIEW_KEYS`] keys, [`NODES_PER_KEY`] nodes a key, [`HOT_KEYS`]
//!   local keys kept for the reports, keys and rule ids over a length cap are
//!   never sent nor taken, so a flood of distinct keys cannot grow memory.
//!
//! The keys hold what the rule tells clients apart by: visitor addresses,
//! header and cookie values. They only travel inside the fleet's own
//! authenticated report channel, and are never logged.
//!
//! The decision itself ([`over`]) is a pure function of the two counts and
//! the limit, as are the merge, expiry and caps ([`merge`], [`remote_sum`],
//! [`note`], [`top`]); [`FleetRate`] only puts them behind two std mutexes
//! (never held across an `.await`, never both taken the other way round).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

/// What the other nodes' counts weigh against this node's own. One half:
/// the remote counts are up to a report old and their windows do not line
/// up with ours (a count of a window that is about to end here may be one
/// that just began there), so counting them in full would hold back clients
/// that are in fact under the limit. With a half, a client spread evenly
/// over N nodes is held back after about N/2 times its limit (4/3 of it on
/// two nodes, where the half-limit report gate does not bind) instead of N
/// times; it can never be held back before it sent the limit fleet-wide,
/// stale reports aside, since every remote count is a real count.
pub const REMOTE_WEIGHT: f64 = 0.5;
/// Keys one report carries at most (the hottest), and takes at most.
pub const REPORT_KEYS: usize = 64;
/// Local keys kept for the reports.
pub const HOT_KEYS: usize = 1024;
/// Keys the remote view holds.
pub const VIEW_KEYS: usize = 4096;
/// Nodes one key of the remote view holds counts of.
pub const NODES_PER_KEY: usize = 64;
/// Longer keys are counted on their node only (a header value can be long).
pub const MAX_KEY_BYTES: usize = 512;
/// Longer rule ids are not ids of ours.
pub const MAX_RULE_BYTES: usize = 128;
/// The longest `period` a rate limit may have (see `crate::items::RateLimit`).
pub const MAX_PERIOD_SECS: u64 = 86400;

/// One count of a node, as the nodes tell each other.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RateCount {
    /// The rate limit's id.
    pub rule: String,
    /// What the client is counted under (see `crate::items::RateLimit::key`).
    pub key: String,
    pub count: u32,
    /// When the window the requests were counted in ends (unix seconds).
    pub until: u64,
}

/// Is a client over `threshold` with `local` requests here and `remote` on
/// the other nodes (their sum, unweighted)?
pub fn over(local: u32, remote: u64, threshold: u32) -> bool {
    effective(local, remote) > f64::from(threshold)
}

/// The count a request is judged by.
pub fn effective(local: u32, remote: u64) -> f64 {
    f64::from(local) + REMOTE_WEIGHT * remote as f64
}

/// Is a local count hot enough to tell the other nodes: past half the limit.
pub fn worth_reporting(count: u32, threshold: u32) -> bool {
    u64::from(count) * 2 > u64::from(threshold)
}

fn sendable(rule: &str, key: &str) -> bool {
    !rule.is_empty() && rule.len() <= MAX_RULE_BYTES && key.len() <= MAX_KEY_BYTES
}

/// The hot local counts: (rule, key) to (count, end of window).
pub type Hot = HashMap<(String, String), (u32, u64)>;

/// Keep a local count for the reports. Its own node's count is the truth, so
/// it replaces what was kept (a new window starts over from a lower count).
/// When [`HOT_KEYS`] are kept, the ones whose window is over go first; then
/// the smallest one, if it is smaller than this.
pub fn note(hot: &mut Hot, rule: &str, key: &str, count: u32, until: u64, now: u64) {
    if !sendable(rule, key) {
        return;
    }
    let id = (rule.to_string(), key.to_string());
    if let Some(have) = hot.get_mut(&id) {
        *have = (count, until);
        return;
    }
    if hot.len() >= HOT_KEYS {
        hot.retain(|_, (_, until)| *until > now);
    }
    if hot.len() >= HOT_KEYS {
        let smallest = hot.iter().min_by_key(|(_, (count, until))| (*count, *until)).map(|(id, (count, _))| (id.clone(), *count));
        match smallest {
            Some((gone, small)) if small < count => {
                hot.remove(&gone);
            }
            _ => return,
        }
    }
    hot.insert(id, (count, until));
}

/// The hottest `n` local counts whose window is not over, hottest first.
pub fn top(hot: &Hot, now: u64, n: usize) -> Vec<RateCount> {
    let mut live: Vec<RateCount> = hot
        .iter()
        .filter(|(_, (_, until))| *until > now)
        .map(|((rule, key), (count, until))| RateCount { rule: rule.clone(), key: key.clone(), count: *count, until: *until })
        .collect();
    live.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.rule.cmp(&b.rule)).then_with(|| a.key.cmp(&b.key)));
    live.truncate(n);
    live
}

/// What the other nodes told: (rule, key) to node to (count, end of window).
pub type View = HashMap<(String, String), HashMap<String, (u32, u64)>>;

/// Take what `node` reported into the view; the number of counts taken.
/// Nothing from `me` (its own reports, come back), nothing empty, over, too
/// long, or past the first [`REPORT_KEYS`].
pub fn merge(view: &mut View, me: &str, node: &str, counts: &[RateCount], now: u64) -> usize {
    if node.is_empty() || node == me {
        return 0;
    }
    let mut taken = 0;
    for c in counts.iter().take(REPORT_KEYS) {
        if c.count == 0 || c.until <= now || !sendable(&c.rule, &c.key) {
            continue;
        }
        let until = c.until.min(now.saturating_add(MAX_PERIOD_SECS));
        let id = (c.rule.clone(), c.key.clone());
        if !view.contains_key(&id) && !make_room(view, now) {
            continue;
        }
        let nodes = view.entry(id).or_default();
        match nodes.get_mut(node) {
            // the same window again (a report sent twice, or the count grown): replaced, not added
            Some(have) if have.1 == until => have.0 = have.0.max(c.count),
            Some(have) if have.1 < until => *have = (c.count, until),
            // a report of an older window, come late
            Some(_) => continue,
            None => {
                if nodes.len() >= NODES_PER_KEY {
                    nodes.retain(|_, (_, until)| *until > now);
                }
                if nodes.len() >= NODES_PER_KEY {
                    continue;
                }
                nodes.insert(node.to_string(), (c.count, until));
            }
        }
        taken += 1;
    }
    taken
}

/// Room for one more key: the keys whose windows are all over go first,
/// then the one counting least (the oldest of those). Always makes room
/// unless [`VIEW_KEYS`] is 0: a new count is likelier to matter than the
/// smallest old one.
fn make_room(view: &mut View, now: u64) -> bool {
    if view.len() < VIEW_KEYS {
        return true;
    }
    view.retain(|_, nodes| {
        nodes.retain(|_, (_, until)| *until > now);
        !nodes.is_empty()
    });
    if view.len() < VIEW_KEYS {
        return true;
    }
    let least = view
        .iter()
        .map(|(id, nodes)| (nodes.values().map(|(count, _)| u64::from(*count)).sum::<u64>(), nodes.values().map(|(_, until)| *until).max().unwrap_or(0), id))
        .min_by_key(|(sum, until, _)| (*sum, *until))
        .map(|(_, _, id)| id.clone());
    match least {
        Some(id) => view.remove(&id).is_some(),
        None => false,
    }
}

/// The other nodes' counts for (rule, key) whose window is not over, summed.
pub fn remote_sum(view: &View, rule: &str, key: &str, now: u64) -> u64 {
    view.get(&(rule.to_string(), key.to_string())).map_or(0, |nodes| nodes.values().filter(|(_, until)| *until > now).map(|(count, _)| u64::from(*count)).sum())
}

/// `rate` of a report, taken leniently: a node of a later build may send it
/// in another shape. What cannot be read is left out, it does not fail the
/// report (and with it the whole batch the report came in).
pub fn lenient<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<RateCount>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(items) => items.into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect(),
        _ => Vec::new(),
    })
}

/// The local hot counts and the remote view of one node.
#[derive(Default)]
pub struct FleetRate {
    hot: Mutex<Hot>,
    view: Mutex<View>,
}

impl FleetRate {
    /// A local count (see [`note`]).
    pub fn note(&self, rule: &str, key: &str, count: u32, until: u64, now: u64) {
        note(&mut self.hot.lock().unwrap(), rule, key, count, until, now);
    }

    /// What this node's next report tells (see [`top`]).
    pub fn report(&self, now: u64) -> Vec<RateCount> {
        let mut hot = self.hot.lock().unwrap();
        hot.retain(|_, (_, until)| *until > now);
        top(&hot, now, REPORT_KEYS)
    }

    /// What another node reported (see [`merge`]).
    pub fn absorb(&self, me: &str, node: &str, counts: &[RateCount], now: u64) -> usize {
        if counts.is_empty() {
            return 0;
        }
        merge(&mut self.view.lock().unwrap(), me, node, counts, now)
    }

    /// The other nodes' live counts for (rule, key), unweighted.
    pub fn remote(&self, rule: &str, key: &str, now: u64) -> u64 {
        let view = self.view.lock().unwrap();
        if view.is_empty() {
            return 0;
        }
        remote_sum(&view, rule, key, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn count(rule: &str, key: &str, count: u32, until: u64) -> RateCount {
        RateCount { rule: rule.into(), key: key.into(), count, until }
    }

    #[test]
    fn counts_of_several_nodes_add_up_and_their_own_node_is_never_among_them() {
        let mut view = View::new();
        assert_eq!(merge(&mut view, "me", "a", &[count("r", "198.51.100.7", 4, 160)], 100), 1);
        assert_eq!(merge(&mut view, "me", "b", &[count("r", "198.51.100.7", 3, 150), count("r", "198.51.100.8", 9, 150)], 100), 2);
        assert_eq!(remote_sum(&view, "r", "198.51.100.7", 100), 7);
        assert_eq!(remote_sum(&view, "r", "198.51.100.8", 100), 9);
        assert_eq!(remote_sum(&view, "other", "198.51.100.7", 100), 0);
        // its own report, come back through a peer, and one with no node: not taken
        assert_eq!(merge(&mut view, "me", "me", &[count("r", "198.51.100.7", 50, 160)], 100), 0);
        assert_eq!(merge(&mut view, "me", "", &[count("r", "198.51.100.7", 50, 160)], 100), 0);
        assert_eq!(remote_sum(&view, "r", "198.51.100.7", 100), 7);
    }

    #[test]
    fn a_node_reporting_the_same_key_again_replaces_its_count_instead_of_adding_to_it() {
        let mut view = View::new();
        let first = [count("r", "k", 5, 160)];
        merge(&mut view, "me", "a", &first, 100);
        // the same report sent again
        merge(&mut view, "me", "a", &first, 101);
        assert_eq!(remote_sum(&view, "r", "k", 101), 5);
        // the count grew in the same window
        merge(&mut view, "me", "a", &[count("r", "k", 8, 160)], 110);
        assert_eq!(remote_sum(&view, "r", "k", 110), 8);
        // an earlier report of the same window that overtook it on the way: the larger count stays
        merge(&mut view, "me", "a", &[count("r", "k", 6, 160)], 111);
        assert_eq!(remote_sum(&view, "r", "k", 111), 8);
        // a new window starts over from a smaller count
        merge(&mut view, "me", "a", &[count("r", "k", 2, 220)], 165);
        assert_eq!(remote_sum(&view, "r", "k", 165), 2);
        // a late report of the window before changes nothing
        assert_eq!(merge(&mut view, "me", "a", &[count("r", "k", 9, 200)], 166), 0);
        assert_eq!(remote_sum(&view, "r", "k", 166), 2);
    }

    #[test]
    fn a_remote_count_counts_until_its_window_ends_and_not_a_second_longer() {
        let mut view = View::new();
        merge(&mut view, "me", "a", &[count("r", "k", 5, 160)], 100);
        merge(&mut view, "me", "b", &[count("r", "k", 3, 130)], 100);
        assert_eq!(remote_sum(&view, "r", "k", 129), 8);
        assert_eq!(remote_sum(&view, "r", "k", 130), 5, "b's window ends at 130");
        assert_eq!(remote_sum(&view, "r", "k", 159), 5);
        assert_eq!(remote_sum(&view, "r", "k", 160), 0);
        // a report whose window is over by the time it comes is not taken
        assert_eq!(merge(&mut view, "me", "c", &[count("r", "k", 3, 100), count("r", "k", 0, 900)], 100), 0);
    }

    #[test]
    fn a_one_second_window_counts_in_its_own_second_only() {
        // a rule of period 1: counted at 100, the window ends at 101
        let mut hot = Hot::new();
        note(&mut hot, "r", "k", 2, 101, 100);
        let told = top(&hot, 100, REPORT_KEYS);
        assert!(top(&hot, 101, REPORT_KEYS).is_empty());
        let mut view = View::new();
        assert_eq!(merge(&mut view, "me", "a", &told, 100), 1);
        assert_eq!((remote_sum(&view, "r", "k", 100), remote_sum(&view, "r", "k", 101)), (2, 0));
        // come a second late, it is not taken at all
        assert_eq!(merge(&mut View::new(), "me", "a", &told, 101), 0);
    }

    #[test]
    fn a_window_said_to_end_far_ahead_lasts_one_longest_period_at_most() {
        let mut view = View::new();
        merge(&mut view, "me", "a", &[count("r", "k", 5, u64::MAX)], 100);
        assert_eq!(remote_sum(&view, "r", "k", 100 + MAX_PERIOD_SECS - 1), 5);
        assert_eq!(remote_sum(&view, "r", "k", 100 + MAX_PERIOD_SECS), 0);
    }

    #[test]
    fn a_report_carries_and_gives_at_most_its_hottest_keys() {
        let mut hot = Hot::new();
        for i in 0..(REPORT_KEYS as u32 + 10) {
            note(&mut hot, "r", &format!("k{i}"), i + 1, 200, 100);
        }
        let report = top(&hot, 100, REPORT_KEYS);
        assert_eq!(report.len(), REPORT_KEYS);
        assert_eq!(report[0].count, REPORT_KEYS as u32 + 10, "hottest first");
        assert!(report.iter().all(|c| c.count > 10), "the coldest are left out");
        // a node that takes it takes no more than that either
        let many: Vec<RateCount> = (0..200).map(|i| count("r", &format!("k{i}"), 1, 200)).collect();
        let mut view = View::new();
        assert_eq!(merge(&mut view, "me", "a", &many, 100), REPORT_KEYS);
        assert_eq!(view.len(), REPORT_KEYS);
    }

    #[test]
    fn the_hot_counts_are_bounded_and_a_window_that_is_over_is_not_reported() {
        let mut hot = Hot::new();
        for i in 0..(HOT_KEYS as u32 * 3) {
            note(&mut hot, "r", &format!("198.51.100.{i}"), 5, 200, 100);
        }
        assert_eq!(hot.len(), HOT_KEYS);
        // a hotter key pushes out the smallest; one no hotter than all is left out
        note(&mut hot, "r", "hotter", 6, 200, 100);
        assert!(hot.contains_key(&("r".to_string(), "hotter".to_string())));
        note(&mut hot, "r", "colder", 1, 200, 100);
        assert!(!hot.contains_key(&("r".to_string(), "colder".to_string())));
        assert_eq!(hot.len(), HOT_KEYS);
        // once their windows are over they make room, and they are not reported
        note(&mut hot, "r", "later", 1, 400, 300);
        assert_eq!(hot.len(), 1);
        assert_eq!(top(&hot, 300, REPORT_KEYS), vec![count("r", "later", 1, 400)]);
        assert!(top(&hot, 400, REPORT_KEYS).is_empty());
        // its own count replaces what was kept, a new window from a lower one
        note(&mut hot, "r", "later", 3, 500, 450);
        assert_eq!(top(&hot, 450, REPORT_KEYS), vec![count("r", "later", 3, 500)]);
    }

    #[test]
    fn the_remote_view_is_bounded_whatever_the_peers_send() {
        let mut view = View::new();
        for batch in 0..(VIEW_KEYS / REPORT_KEYS + 20) {
            let counts: Vec<RateCount> = (0..REPORT_KEYS).map(|i| count("r", &format!("{batch}-{i}"), 1 + (batch % 3) as u32, 1000)).collect();
            merge(&mut view, "me", "a", &counts, 100);
        }
        assert_eq!(view.len(), VIEW_KEYS);
        // the newest keys are in
        assert_eq!(remote_sum(&view, "r", &format!("{}-0", VIEW_KEYS / REPORT_KEYS + 19), 100), 1 + ((VIEW_KEYS / REPORT_KEYS + 19) % 3) as u64);
        // keys whose windows are over make room first
        let mut view = View::new();
        let old: Vec<RateCount> = (0..VIEW_KEYS).map(|i| count("r", &format!("old{i}"), 9, 150)).collect();
        for chunk in old.chunks(REPORT_KEYS) {
            merge(&mut view, "me", "a", chunk, 100);
        }
        assert_eq!(view.len(), VIEW_KEYS);
        merge(&mut view, "me", "b", &[count("r", "new", 1, 400)], 200);
        assert_eq!((view.len(), remote_sum(&view, "r", "new", 200)), (1, 1));
        // and a key holds the counts of so many nodes at most
        let mut view = View::new();
        for n in 0..(NODES_PER_KEY + 5) {
            merge(&mut view, "me", &format!("node{n}"), &[count("r", "k", 1, 200)], 100);
        }
        assert_eq!(remote_sum(&view, "r", "k", 100), NODES_PER_KEY as u64);
    }

    #[test]
    fn keys_and_rule_ids_too_long_or_empty_are_neither_sent_nor_taken() {
        let long = "x".repeat(MAX_KEY_BYTES + 1);
        let mut hot = Hot::new();
        note(&mut hot, "r", &long, 9, 200, 100);
        note(&mut hot, "", "k", 9, 200, 100);
        note(&mut hot, &"r".repeat(MAX_RULE_BYTES + 1), "k", 9, 200, 100);
        assert!(hot.is_empty());
        let mut view = View::new();
        assert_eq!(merge(&mut view, "me", "a", &[count("r", &long, 9, 200), count("", "k", 9, 200)], 100), 0);
        assert!(view.is_empty());
        // an empty key (a header nobody sent) is a key like any other
        assert_eq!(merge(&mut view, "me", "a", &[count("r", "", 9, 200)], 100), 1);
    }

    #[test]
    fn the_remote_counts_alone_put_a_client_over_its_limit() {
        // 8 here of a limit of 10: under; with 6 on the others (weighing 3) it is over
        assert!(!over(8, 0, 10));
        assert!(!over(8, 4, 10), "8 + 2 is the limit, not over it");
        assert!(over(8, 6, 10));
        assert_eq!(effective(8, 6), 11.0);
        // a client the other nodes saw a lot is over at its first request here
        assert!(over(1, 1000, 10));
        let mut view = View::new();
        merge(&mut view, "me", "a", &[count("r", "k", 7, 160)], 100);
        merge(&mut view, "me", "b", &[count("r", "k", 7, 160)], 100);
        assert!(over(4, remote_sum(&view, "r", "k", 100), 10));
        assert!(!over(4, remote_sum(&view, "r", "k", 160), 10), "their windows are over");
    }

    #[test]
    fn a_limit_of_one_and_a_limit_of_zero() {
        // a limit of 1: the first request alone passes, one more anywhere in the fleet stops the next
        assert!(!over(1, 0, 1));
        assert!(over(1, 1, 1));
        assert!(over(2, 0, 1));
        assert!(worth_reporting(1, 1), "past half of 1");
        // 0 is refused when a rule is saved; were it to come, nothing passes and everything is told
        assert!(over(1, 0, 0) && worth_reporting(1, 0));
        // half of 10: 5 is not past it, 6 is
        assert!(!worth_reporting(5, 10) && worth_reporting(6, 10));
        assert!(worth_reporting(u32::MAX, u32::MAX));
    }

    #[test]
    fn rate_counts_in_another_shape_are_left_out_without_failing_the_rest() {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default, deserialize_with = "lenient")]
            rate: Vec<RateCount>,
            #[serde(default)]
            other: u32,
        }
        let read = |v: Value| serde_json::from_value::<Holder>(v).unwrap();
        let held = read(json!({ "rate": [{ "rule": "r", "key": "k", "count": 3, "until": 9 }, { "rule": "r", "count": -1 }, "x", { "rule": "s", "count": 1, "until": 9, "window": "later" }], "other": 7 }));
        assert_eq!(held.rate, [count("r", "k", 3, 9), count("s", "", 1, 9)]);
        assert_eq!(held.other, 7);
        assert!(read(json!({ "rate": "not a list", "other": 1 })).rate.is_empty());
        assert!(read(json!({ "rate": null })).rate.is_empty());
        assert!(read(json!({ "other": 1 })).rate.is_empty());
    }

    #[test]
    fn the_struct_puts_it_together() {
        let fleet = FleetRate::default();
        assert_eq!(fleet.remote("r", "k", 100), 0);
        fleet.note("r", "k", 6, 160, 100);
        let told = fleet.report(100);
        assert_eq!(told, [count("r", "k", 6, 160)]);
        assert!(fleet.report(160).is_empty(), "its window is over");
        let there = FleetRate::default();
        assert_eq!(there.absorb("b", "a", &told, 100), 1);
        assert_eq!(there.absorb("b", "a", &[], 100), 0);
        assert_eq!(there.remote("r", "k", 100), 6);
        assert_eq!(there.remote("r", "k", 160), 0);
    }
}
