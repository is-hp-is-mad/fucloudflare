//! What every node says about itself (the traffic it served, its security
//! events, where it stands), kept by every peer. A report reaches the peers
//! it was sent to, and they pass it on (the `reports` sync domain), so the
//! panel shows the whole fleet on whichever node answers it, and a peer that
//! was away takes on its return what the others kept meanwhile. A report
//! counts once, whichever ways it comes (see [`Fleet::mark_report`]).

use crate::edge::stats::{now_secs, Series, Stats};
use crate::edge::waf::{Event, Waf};
use crate::fleet::Fleet;
use crate::limits::Usage;
use crate::sync::{DomainDelta, HlcClock, SyncProvider};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// For how long reports are kept for the peers, and how much of them at most.
const KEPT_SECS: u64 = 6 * 3600;
const KEPT_BYTES: usize = 16 << 20;
/// How much of them one answer to a peer carries.
const BATCH_BYTES: usize = 2 << 20;
/// A report older than this says nothing about whether its node is there now.
const LIVE_SECS: u64 = 60;

/// One report of a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub node: String,
    pub role: String,
    /// The configuration version and the build the node ran then.
    pub version: String,
    pub build: String,
    /// One run of the node's process, and the number of the report in it.
    pub boot: String,
    pub seq: u64,
    /// When the node made it (unix seconds); 0 from a build that does not say.
    pub at: u64,
    pub stats: HashMap<String, Series>,
    pub events: Vec<Event>,
    pub usage: Option<Usage>,
    pub status: Value,
    /// What it measured of its visitors' round trips since its report before (see crate::rtt).
    pub rtt: HashMap<String, crate::rtt::Measure>,
    /// The clients it put over a rate limit since its report before.
    pub blocks: Vec<crate::edge::waf::Block>,
}

struct Kept {
    rev: u64,
    since: u64,
    size: usize,
    report: Report,
}

#[derive(Default)]
struct Log {
    /// Number of the last report kept (they are numbered as they come).
    rev: u64,
    bytes: usize,
    kept: VecDeque<Kept>,
}

pub struct Reports {
    stats: Arc<Stats>,
    waf: Arc<Waf>,
    fleet: Arc<Fleet>,
    rtt: Arc<crate::rtt::Rtt>,
    /// The name of this node: its own reports come back from the peers.
    me: Box<dyn Fn() -> String + Send + Sync>,
    /// One run of this process: a peer that knew another one starts over.
    epoch: String,
    /// Reports made before this are left alone: without marks from before
    /// (see [`Reports::load`]) they may already be in the saved analytics.
    floor: AtomicU64,
    log: Mutex<Log>,
}

impl Reports {
    pub fn new(stats: Arc<Stats>, waf: Arc<Waf>, fleet: Arc<Fleet>, rtt: Arc<crate::rtt::Rtt>, me: impl Fn() -> String + Send + Sync + 'static) -> Reports {
        Reports {
            stats,
            waf,
            fleet,
            rtt,
            me: Box::new(me),
            epoch: uuid::Uuid::new_v4().simple().to_string(),
            floor: AtomicU64::new(now_secs()),
            log: Mutex::default(),
        }
    }

    /// Bring back the marks written by [`Reports::save`]: with them, what the
    /// peers kept while this node was away is taken on its return; without
    /// them (a first start), only what is reported from now on.
    pub fn load(&self, path: &Path) {
        let Ok(bytes) = std::fs::read(path) else { return };
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut saved) => {
                self.fleet.restore_report_marks(saved["marks"].take());
                self.floor.store(0, Ordering::Relaxed);
            }
            Err(e) => tracing::warn!("ignoring the unreadable report marks in {}: {e}", path.display()),
        }
    }

    /// Write down which reports were taken (with the analytics they went into).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(&json!({ "marks": self.fleet.report_marks() })).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).and_then(|_| std::fs::rename(&tmp, path))
    }

    /// A report of this node itself: kept for the peers (what it tells is
    /// counted here already).
    pub fn own(&self, report: Report) -> bool {
        if report.node.is_empty() {
            return false;
        }
        self.keep(report);
        true
    }

    /// A report of another node, from the node itself (`direct`: made just
    /// now, whatever its clock says) or by way of a peer: taken (once), and
    /// kept for the peers. False when it was taken before.
    pub fn take(&self, mut report: Report, direct: bool) -> bool {
        let now = now_secs();
        if direct || report.at == 0 {
            report.at = now;
        }
        if report.node.is_empty() || report.node == (self.me)() {
            return false;
        }
        let Some(latest) = self.fleet.mark_report(&report.node, &report.boot, report.seq) else { return false };
        if report.at < self.floor.load(Ordering::Relaxed) {
            return false;
        }
        self.stats.absorb(&report.node, &report.stats);
        self.waf.absorb(&report.node, report.events.clone());
        self.rtt.merge(&report.node, &report.rtt);
        self.waf.absorb_blocks(&report.blocks);
        if latest && now.saturating_sub(report.at) < LIVE_SECS {
            self.fleet.heard(&report.node, &report.version, &report.build, &report.role);
            if let Some(usage) = report.usage.clone() {
                self.fleet.set_usage(&report.node, usage);
            }
            if !report.status.is_null() {
                self.fleet.set_status(&report.node, report.status.clone());
            }
        }
        self.keep(report);
        true
    }

    fn keep(&self, report: Report) {
        let now = now_secs();
        let size = serde_json::to_vec(&report).map(|b| b.len()).unwrap_or(0);
        let mut log = self.log.lock().unwrap();
        log.rev += 1;
        log.bytes += size;
        let rev = log.rev;
        log.kept.push_back(Kept { rev, since: now, size, report });
        while log.kept.front().is_some_and(|k| log.bytes > KEPT_BYTES || now.saturating_sub(k.since) > KEPT_SECS) {
            let gone = log.kept.pop_front().map_or(0, |k| k.size);
            log.bytes -= gone;
        }
    }
}

impl SyncProvider for Reports {
    fn domain(&self) -> &'static str {
        "reports"
    }

    fn current_rev(&self) -> u64 {
        self.log.lock().unwrap().rev
    }

    fn epoch(&self) -> String {
        self.epoch.clone()
    }

    fn passive(&self) -> bool {
        true
    }

    /// The reports kept after number `since_rev` (all of them for a peer that
    /// knew another run of this process), a batch at a time.
    fn export_since(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
        let known = peer_epoch == Some(self.epoch.as_str());
        let since = if known { since_rev } else { 0 };
        let log = self.log.lock().unwrap();
        let (mut reports, mut size, mut to_rev) = (Vec::new(), 0, since);
        for kept in log.kept.iter().filter(|k| k.rev > since) {
            if size > 0 && size + kept.size > BATCH_BYTES {
                break;
            }
            reports.push(serde_json::to_value(&kept.report).map_err(|e| e.to_string())?);
            (size, to_rev) = (size + kept.size, kept.rev);
        }
        if reports.is_empty() {
            // nothing newer is kept: the peer stands where this node does
            to_rev = log.rev;
        }
        Ok(DomainDelta { domain: "reports".into(), epoch: self.epoch.clone(), from_rev: since, to_rev, full_resync: !known, payload: json!({ "reports": reports }) })
    }

    fn merge_delta(&self, delta: &DomainDelta, _: &HlcClock) -> Result<bool, String> {
        let reports: Vec<Report> = serde_json::from_value(delta.payload["reports"].clone()).map_err(|e| e.to_string())?;
        Ok(reports.into_iter().fold(false, |any, report| self.take(report, false) | any))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::stats::Sample;

    struct Node {
        stats: Arc<Stats>,
        fleet: Arc<Fleet>,
        reports: Reports,
    }

    fn node(name: &'static str) -> Node {
        let (stats, fleet) = (Arc::new(Stats::default()), Arc::new(Fleet::default()));
        let reports = Reports::new(stats.clone(), Arc::new(Waf::new()), fleet.clone(), Arc::default(), move || name.to_string());
        reports.floor.store(0, Ordering::Relaxed);
        Node { stats, fleet, reports }
    }

    /// A report of `node` made `ago` seconds ago: `n` requests for zone "z".
    fn report(node: &str, boot: &str, seq: u64, n: usize, ago: u64) -> Report {
        let made = Stats::new_ephemeral_reporting();
        for _ in 0..n {
            made.record(Sample { zone_id: "z", version: hyper::Version::HTTP_11, status: 200, cache: None, threat: false, bytes: 0, country: "", host: "h", path: "/" });
        }
        Report { node: node.into(), role: "accelerate".into(), version: "v1".into(), boot: boot.into(), seq, at: now_secs() - ago, stats: made.take_outbox(), ..Default::default() }
    }

    fn requests(node: &Node) -> u64 {
        node.stats.summary(60).get("z").map_or(0, |c| c.requests)
    }

    /// `to` fetches from `from` as the sync does: from where it stood with it.
    fn fetch(to: &Node, from: &Node, cursor: &mut (String, u64)) -> bool {
        let delta = from.reports.export_since(cursor.1, Some(&cursor.0)).unwrap();
        *cursor = (delta.epoch.clone(), delta.to_rev);
        to.reports.merge_delta(&delta, &HlcClock::default()).unwrap()
    }

    #[test]
    fn a_report_counts_once_whichever_ways_it_comes() {
        let (a, b, c) = (node("a"), node("b"), node("c"));
        let (mut b_from_a, mut c_from_b, mut a_from_c, mut b_from_c) = <((String, u64), (String, u64), (String, u64), (String, u64))>::default();
        // x reports to a; b has it from a, c from b: every peer counts its 3 requests
        assert!(a.reports.take(report("x", "run", 0, 3, 0), false));
        assert!(fetch(&b, &a, &mut b_from_a) && fetch(&c, &b, &mut c_from_b));
        assert_eq!((requests(&a), requests(&b), requests(&c)), (3, 3, 3));
        // it comes back to a, and x sends it again: taken already
        assert!(!fetch(&a, &c, &mut a_from_c) && !a.reports.take(report("x", "run", 0, 3, 0), false));
        assert_eq!(requests(&a), 3);
        // the next two overtake each other on the way to c: each counts once
        assert!(c.reports.take(report("x", "run", 2, 10, 0), false) && c.reports.take(report("x", "run", 1, 100, 0), false));
        assert!(fetch(&b, &c, &mut b_from_c) && !fetch(&b, &a, &mut b_from_a));
        assert_eq!((requests(&b), requests(&c)), (113, 113));
        // b stands where c does: nothing more to fetch
        assert_eq!(c.reports.export_since(b_from_c.1, Some(&b_from_c.0)).unwrap().payload["reports"], json!([]));
        // c starts again (another run): b fetches all it keeps, and counts nothing twice
        let again = node("c");
        again.reports.take(report("x", "run", 2, 10, 0), false);
        assert!(!fetch(&b, &again, &mut b_from_c));
        assert_eq!((requests(&b), b_from_c.1), (113, 1));
    }

    #[test]
    fn its_own_reports_are_kept_for_the_peers_and_not_taken_back() {
        let (a, b) = (node("a"), node("b"));
        let (mut b_from_a, mut a_from_b) = <((String, u64), (String, u64))>::default();
        assert!(a.reports.own(Report { node: "a".into(), ..report("", "run", 0, 5, 0) }));
        assert!(fetch(&b, &a, &mut b_from_a));
        assert!(!fetch(&a, &b, &mut a_from_b), "its own report, back from b");
        assert_eq!((requests(&a), requests(&b)), (0, 5), "a counted its requests as it served them, not here");
    }

    #[test]
    fn an_old_report_says_what_was_served_but_not_that_the_node_is_there() {
        let a = node("a");
        assert!(a.reports.take(report("x", "run", 0, 2, 3600), false));
        assert_eq!((requests(&a), a.fleet.status("x", "v1")), (2, None));
        assert!(a.reports.take(report("x", "run", 5, 1, 0), false));
        let status = a.fleet.status("x", "v1").unwrap();
        assert_eq!((status["online"].as_bool(), status["in_sync"].as_bool(), status["role"].as_str()), (Some(true), Some(true), Some("accelerate")));
        // a late one of before counts, and does not put the node's state back
        assert!(a.reports.take(Report { version: "v0".into(), ..report("x", "run", 3, 1, 0) }, false));
        assert_eq!((requests(&a), a.fleet.status("x", "v1").unwrap()["in_sync"].as_bool()), (4, Some(true)));
        // from the node itself a report is of now, whatever its clock says
        assert!(a.reports.take(report("y", "run", 0, 0, 3600), true));
        assert_eq!(a.fleet.status("y", "v1").unwrap()["online"].as_bool(), Some(true));
    }

    #[test]
    fn without_marks_from_before_only_what_is_reported_from_now_on_is_taken() {
        let dir = std::env::temp_dir().join(format!("fucf-reports-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("reports.json");
        let first = node("a");
        first.reports.floor.store(now_secs(), Ordering::Relaxed);
        first.reports.load(&path);
        assert!(!first.reports.take(report("x", "run", 0, 4, 30), false), "made before this node kept marks: it may be counted already");
        assert!(first.reports.take(report("x", "run", 1, 1, 0), false));
        assert_eq!(requests(&first), 1);
        first.reports.save(&path).unwrap();
        // started again with its marks: what the peers kept meanwhile is taken, what it had is not
        let second = node("a");
        second.reports.floor.store(now_secs(), Ordering::Relaxed);
        second.reports.load(&path);
        assert!(!second.reports.take(report("x", "run", 1, 1, 0), false));
        assert!(second.reports.take(report("x", "run", 2, 7, 30), false));
        assert_eq!(requests(&second), 7);
        let _ = std::fs::remove_dir_all(dir);
    }
}
