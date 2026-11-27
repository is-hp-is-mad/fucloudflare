//! The primary's view of the fleet: which replicas report in, and which
//! configuration version each of them has adopted.

use crate::gfw::{GfwMonitor, GfwStatus};
use crate::limits::{Limits, State, Usage};
use crate::store::Store;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A replica that has not reported for this long is considered gone.
const FRESH: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Peer {
    /// Configuration version the replica runs with.
    version: String,
    /// Software version of the replica.
    build: String,
    /// Node role ("peer" or "accelerate").
    role: String,
    seen: Option<Instant>,
    seen_at: String,
    /// What the replica says about the binary it runs (see crate::release).
    exe: PeerExe,
    /// What the replica last said about itself (see crate::node).
    status: Value,
}

/// A replica's word on its binary and on the releases it has tried.
#[derive(Default, Clone, PartialEq, Debug)]
pub struct PeerExe {
    /// Digest of the binary it runs.
    pub sha256: String,
    /// That binary is not on trial.
    pub trusted: bool,
    /// The last submission it heard of, and the releases that failed there.
    pub submission: String,
    pub rejected: Vec<String>,
}

impl Peer {
    fn age(&self) -> Duration {
        self.seen.map_or(Duration::MAX, |at| at.elapsed())
    }
}

#[derive(Default)]
pub struct Fleet {
    peers: Mutex<HashMap<String, Peer>>,
    /// Per replica: the run of its process and the last report of that run.
    reports: Mutex<HashMap<String, (String, u64)>>,
    /// Per replica: what it last said about its traffic allowance.
    usage: Mutex<HashMap<String, Usage>>,
    /// Per replica: what it last said about mainland-China reachability.
    gfw: Mutex<HashMap<String, GfwStatus>>,
    /// Per replica: what it is to do when it next gets in touch.
    commands: Mutex<HashMap<String, Vec<String>>>,
}

impl Fleet {
    /// A replica got in touch, running configuration `version`.
    pub fn seen(&self, node: &str, version: &str, build: &str) {
        let mut peers = self.peers.lock().unwrap();
        let peer = peers.entry(node.to_string()).or_default();
        (peer.version, peer.build) = (version.to_string(), build.to_string());
        if peer.role.is_empty() {
            peer.role = "peer".into();
        }
        (peer.seen, peer.seen_at) = (Some(Instant::now()), crate::store::now());
    }

    pub fn set_role(&self, node: &str, role: &str) {
        let mut peers = self.peers.lock().unwrap();
        let peer = peers.entry(node.to_string()).or_default();
        peer.role = role.to_string();
    }

    pub fn role(&self, node: &str) -> String {
        self.peers
            .lock()
            .unwrap()
            .get(node)
            .map(|p| if p.role.is_empty() { "peer".into() } else { p.role.clone() })
            .unwrap_or_else(|| "peer".into())
    }

    /// Names of recently seen `peer` nodes (excluding `accelerate` nodes).
    pub fn online_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        let mut out: Vec<String> = peers
            .iter()
            .filter(|(_, p)| p.age() < FRESH && p.role != "accelerate")
            .map(|(n, _)| n.clone())
            .collect();
        out.sort();
        out
    }

    /// A replica described its state.
    pub fn set_status(&self, node: &str, status: Value) {
        if let Some(g) = status.get("gfw").and_then(|v| serde_json::from_value::<GfwStatus>(v.clone()).ok()) {
            if !g.is_empty() {
                self.gfw.lock().unwrap().insert(node.to_string(), g);
            }
        }
        self.peers.lock().unwrap().entry(node.to_string()).or_default().status = status;
    }

    /// Have a replica do something when it next gets in touch (within seconds).
    pub fn command(&self, node: &str, action: &str) {
        let mut commands = self.commands.lock().unwrap();
        let queue = commands.entry(node.to_string()).or_default();
        if !queue.iter().any(|a| a == action) {
            queue.push(action.to_string());
        }
    }

    /// What a replica is to do now; handed out once.
    pub fn take_commands(&self, node: &str) -> Vec<String> {
        self.commands.lock().unwrap().remove(node).unwrap_or_default()
    }

    /// A replica said what binary it runs.
    pub fn runs(&self, node: &str, exe: PeerExe) {
        self.peers.lock().unwrap().entry(node.to_string()).or_default().exe = exe;
    }

    /// The replicas as the roll-out of release sha256 (submitted as
    /// submission) sees them; version is the current configuration.
    pub fn views(&self, version: &str, submission: &str, sha256: &str) -> Vec<crate::release::PeerView> {
        let peers = self.peers.lock().unwrap();
        let mut views: Vec<crate::release::PeerView> = peers
            .iter()
            .map(|(name, p)| crate::release::PeerView {
                name: name.clone(),
                online: p.age() < FRESH,
                in_sync: p.version == version,
                exe: p.exe.sha256.clone(),
                trusted: p.exe.trusted,
                // what it said before it heard of this submission does not count
                rejected: p.exe.submission == submission && p.exe.rejected.iter().any(|r| r == sha256),
            })
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));
        views
    }

    /// Is report `seq` of run `boot` new? False when this very report was
    /// already processed and is being re-sent because the reply got lost.
    pub fn fresh_report(&self, node: &str, boot: &str, seq: u64) -> bool {
        let mut reports = self.reports.lock().unwrap();
        if reports.get(node).is_some_and(|(b, last)| b == boot && seq <= *last) {
            return false;
        }
        reports.insert(node.to_string(), (boot.to_string(), seq));
        true
    }

    pub fn set_usage(&self, node: &str, usage: Usage) {
        self.usage.lock().unwrap().insert(node.to_string(), usage);
    }

    pub fn usage(&self, node: &str) -> Option<Usage> {
        self.usage.lock().unwrap().get(node).cloned()
    }

    /// The nodes over a threshold of their allowance: the replicas as they
    /// last reported, and this node (`own`) itself.
    pub fn limited(&self, own: (String, State)) -> BTreeMap<String, State> {
        let usage = self.usage.lock().unwrap();
        let mut limited: BTreeMap<String, State> = usage.iter().map(|(name, u)| (name.clone(), u.state)).collect();
        limited.insert(own.0, own.1);
        limited.retain(|_, state| *state != State::Ok);
        limited
    }

    /// Per-node DNS offload probability (0-100): replicas as they last
    /// reported, and this node (`own`) itself.
    pub fn offloads(&self, own: (String, u8)) -> BTreeMap<String, u8> {
        let usage = self.usage.lock().unwrap();
        let mut offloads: BTreeMap<String, u8> = usage.iter().map(|(name, u)| (name.clone(), u.offload_pct)).collect();
        offloads.insert(own.0, own.1);
        offloads.retain(|_, pct| *pct > 0);
        offloads
    }

    /// Per-node mainland-China reachability: replicas as they last reported, and this node itself.
    pub fn gfw_statuses(&self, own: (String, GfwStatus)) -> BTreeMap<String, GfwStatus> {
        let mut map: BTreeMap<String, GfwStatus> = self.gfw.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        if !own.1.is_empty() {
            map.insert(own.0, own.1);
        }
        map
    }

    /// Replicas heard from recently that have not adopted `version` yet.
    pub fn lagging(&self, version: &str) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        let mut out: Vec<String> =
            peers.iter().filter(|(_, p)| p.age() < FRESH && p.version != version).map(|(n, _)| n.clone()).collect();
        out.sort();
        out
    }

    /// What is known about replica `node`, if it ever got in touch.
    pub fn status(&self, node: &str, version: &str) -> Option<Value> {
        let peers = self.peers.lock().unwrap();
        let p = peers.get(node)?;
        Some(json!({
            "version": p.version,
            "in_sync": p.version == version,
            "build": p.build,
            "role": if p.role.is_empty() { "peer" } else { &p.role },
            "last_seen": p.seen_at,
            "age": p.age().as_secs(),
            "online": p.age() < FRESH,
            "exe": p.exe.sha256,
            "trusted": p.exe.trusted,
            "status": p.status,
        }))
    }

    /// Every replica that ever got in touch, by name.
    pub fn all(&self, version: &str) -> Value {
        let names: Vec<String> = self.peers.lock().unwrap().keys().cloned().collect();
        Value::Object(names.into_iter().filter_map(|n| Some((n.clone(), self.status(&n, version)?))).collect())
    }
}

/// Keep this node's own self-reported traffic limit and CN reachability in
/// `Store`'s CRDT `node_telemetry` map (and absorb any legacy `/replication/report`
/// data if peers pushed via compat endpoint), so every node's DNS sees them.
pub async fn publish_limits(store: Arc<Store>, fleet: Arc<Fleet>, limits: Arc<Limits>, gfw: Arc<GfwMonitor>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let known: Vec<String> = store.list_nodes().into_iter().map(|n| n.name).collect();
        let (own_name, own_state) = limits.own();
        let own_offload = limits.own_offload().1;
        let own_gfw = gfw.get();
        let gfw_opt = if own_gfw.is_empty() { None } else { Some(own_gfw) };
        if !own_name.is_empty() && known.contains(&own_name) {
            if let Err(e) = store.set_self_telemetry_async(own_name.clone(), own_state, own_offload, gfw_opt).await {
                tracing::warn!("cannot record self node telemetry: {e:?}");
            }
        }
        // Compat: absorb any peer telemetry reported only via legacy POST /replication/report.
        let mut limited = fleet.limited(limits.own());
        limited.retain(|name, _| known.contains(name) && *name != own_name);
        let mut offload = fleet.offloads(limits.own_offload());
        offload.retain(|name, _| known.contains(name) && *name != own_name);
        let mut gfw_map = fleet.gfw_statuses((own_name.clone(), gfw.get()));
        gfw_map.retain(|name, _| known.contains(name) && *name != own_name);
        for name in known {
            if name == own_name {
                continue;
            }
            let st = limited.get(&name).copied().unwrap_or(State::Ok);
            let off = offload.get(&name).copied().unwrap_or(0);
            let gf = gfw_map.get(&name).cloned();
            if st != State::Ok || off > 0 || gf.is_some() {
                let _ = store.record_peer_telemetry_async(name, st, off, gf).await;
            }
        }
    }
}

/// The name of the node this process runs on: the one given on the command
/// line, else the configured edge node that owns one of our addresses.
pub fn self_name(store: &Store, edge_ips: &[IpAddr], explicit: Option<&str>) -> String {
    if let Some(name) = explicit.map(str::trim).filter(|n| !n.is_empty()) {
        return name.to_ascii_lowercase();
    }
    let owns = |n: &crate::items::EdgeNode| {
        n.ipv4.is_some_and(|a| edge_ips.contains(&IpAddr::V4(a))) || n.ipv6.is_some_and(|a| edge_ips.contains(&IpAddr::V6(a)))
    };
    match store.list_nodes().into_iter().find(owns) {
        Some(node) => node.name,
        None => "local".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tracks_replicas_and_ignores_resent_reports() {
        let fleet = Fleet::default();
        assert!(fleet.lagging("v2").is_empty());
        fleet.seen("eu", "v1", "0.1.0");
        fleet.seen("us", "v2", "0.1.0");
        assert_eq!(fleet.lagging("v2"), ["eu"]);
        fleet.seen("eu", "v2", "0.1.0");
        assert!(fleet.lagging("v2").is_empty());

        assert!(fleet.fresh_report("eu", "boot-a", 0));
        assert!(!fleet.fresh_report("eu", "boot-a", 0), "the same report again carries no new data");
        assert!(fleet.fresh_report("eu", "boot-a", 1));
        assert!(fleet.fresh_report("eu", "boot-c", 0), "a restarted replica starts over");
        assert!(fleet.fresh_report("us", "boot-a", 0), "reports are tracked per replica");
        let status = fleet.status("eu", "v2").unwrap();
        assert_eq!((status["in_sync"].as_bool(), status["online"].as_bool()), (Some(true), Some(true)));
        assert!(fleet.status("au", "v2").is_none());
        assert_eq!(fleet.all("v3")["us"]["in_sync"], false);

        // what the replicas run: a report without that does not blank it
        assert!(fleet.views("v2", "s1", "new").iter().all(|p| p.online && p.exe.is_empty() && !p.rejected));
        fleet.runs("eu", PeerExe { sha256: "old".into(), trusted: true, submission: "s0".into(), rejected: vec!["new".into()] });
        fleet.seen("eu", "v2", "0.1.0");
        let views = fleet.views("v2", "s1", "new");
        assert_eq!(views.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["eu", "us"]);
        assert!(views[0].exe == "old" && views[0].trusted && views[0].in_sync);
        assert!(!views[0].rejected, "it failed there before this submission");
        fleet.runs("eu", PeerExe { sha256: "old".into(), trusted: true, submission: "s1".into(), rejected: vec!["new".into()] });
        assert!(fleet.views("v2", "s1", "new")[0].rejected && !fleet.views("v2", "s1", "newer")[0].rejected);
        assert!(!fleet.views("v3", "s1", "new")[0].in_sync);
        assert_eq!(fleet.status("eu", "v2").unwrap()["exe"], "old");

        // what a replica says about itself, and what it is told to do: once each
        fleet.set_status("eu", json!({ "uptime_seconds": 5 }));
        fleet.seen("eu", "v2", "0.1.0");
        assert_eq!(fleet.status("eu", "v2").unwrap()["status"]["uptime_seconds"], 5);
        (fleet.command("eu", "restart"), fleet.command("eu", "purge_cache"), fleet.command("eu", "restart"));
        assert_eq!((fleet.take_commands("eu"), fleet.take_commands("eu"), fleet.take_commands("us")), (vec!["restart".to_string(), "purge_cache".to_string()], vec![], vec![]));

        // traffic allowances: the replicas' word, and the primary's own state
        assert!(fleet.limited(("au".into(), State::Ok)).is_empty());
        fleet.set_usage("eu", Usage { state: State::DnsLimited, used_bytes: 9, period_start: String::new(), offload_pct: 100 });
        fleet.set_usage("us", Usage::default());
        fleet.set_usage("au", Usage { state: State::Limited, ..Default::default() });
        let limited = fleet.limited(("au".into(), State::Ok));
        assert_eq!(limited, BTreeMap::from([("eu".to_string(), State::DnsLimited)]), "a node knows its own state best");
        assert_eq!(fleet.limited(("au".into(), State::Limited)).len(), 2);
        assert_eq!(fleet.usage("eu").unwrap().used_bytes, 9);
    }

    #[test]
    fn finds_its_own_name() {
        let store = crate::store::testutil::temp_store();
        let ips: Vec<IpAddr> = vec!["203.0.113.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        assert_eq!(self_name(&store, &ips, None), "local");
        store.save_node(None, json!({ "name": "us", "ipv4": "203.0.113.1" })).unwrap();
        store.save_node(None, json!({ "name": "eu", "ipv6": "2001:db8::2" })).unwrap();
        assert_eq!(self_name(&store, &ips, None), "eu");
        assert_eq!(self_name(&store, &ips, Some(" Edge-7 ")), "edge-7");
        assert_eq!(self_name(&store, &[], None), "local");
    }
}
