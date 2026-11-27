//! Masterless peer-to-peer state synchronization and node role coordination.
//!
//! - `NodeRole::Peer`: full read/write control plane, bidirectional anti-entropy
//!   gossip (`GET/POST /client/v4/replication/sync`) + debounced push-notify.
//! - `NodeRole::Accelerate`: pull-only in-memory runtime state, zero local
//!   persistent control-plane files, rejects writes (`409 Conflict`), suppresses
//!   public authoritative NS participation, and pushes telemetry back to peers.

pub mod acme_lease;
pub mod clock;

pub use acme_lease::AcmeLease;
pub use clock::{resolve_sync_node_id, unix_ms, HlcClock, SyncMeta};

use crate::auth::Accounts;
use crate::edge::Edge;
use crate::fleet::Fleet;
use crate::node::NodeInfo;
use crate::release::Updater;
use crate::store::Store;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};

/// Node role on the fleet (`--role <peer|accelerate>`, `FUCF_ROLE`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    #[default]
    Peer,
    Accelerate,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeRole::Peer => "peer",
            NodeRole::Accelerate => "accelerate",
        }
    }

    pub fn is_accelerate(self) -> bool {
        self == NodeRole::Accelerate
    }
}

/// Incremental (or full resync) state delta for a single replicated domain
/// (`"config"`, `"accounts"`, and extensible `"kv"` / `"d1"` in M2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDelta {
    pub domain: String,
    pub epoch: String,
    pub from_rev: u64,
    pub to_rev: u64,
    #[serde(default)]
    pub full_resync: bool,
    pub payload: Value,
}

/// Extensible replication provider implemented by `Store`, `Accounts`, and
/// future M2/M3 storage domains (`KV`, `D1`, etc.).
pub trait SyncProvider: Send + Sync + 'static {
    fn domain(&self) -> &'static str;
    fn current_rev(&self) -> u64;
    fn epoch(&self) -> String;
    fn export_since(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String>;
    fn merge_delta(&self, delta: &DomainDelta, clock: &HlcClock) -> Result<bool, String>;
}

/// Normalize a peer specification (bare hostname -> `https://<host>`, or full `http(s)://host:port`).
pub fn peer_target(spec: &str) -> anyhow::Result<crate::edge::upstream::Target> {
    let spec = spec.trim();
    let url = if spec.contains("://") { spec.to_string() } else { format!("https://{spec}") };
    crate::edge::upstream::Target::from_url(&url).map_err(|e| anyhow::anyhow!("invalid peer '{spec}': {e}"))
}

#[derive(Default)]
struct PeerCursor {
    remote_config_epoch: String,
    remote_config_rev: u64,
    remote_accounts_epoch: String,
    remote_accounts_rev: u64,
    remote_domain_cursors: HashMap<String, (String, u64)>,
    last_pushed_config_rev: u64,
    last_pushed_accounts_rev: u64,
    last_pushed_domain_revs: HashMap<String, u64>,
    failing: bool,
}

/// Coordinates periodic anti-entropy pull/push sync, immediate push-notify on
/// mutations, telemetry reporting, and rolling-update directive following.
pub struct PeerSync {
    pub role: NodeRole,
    pub peers: Vec<crate::edge::upstream::Target>,
    pub edge: Arc<Edge>,
    pub store: Arc<Store>,
    pub accounts: Arc<Accounts>,
    pub fleet: Arc<Fleet>,
    pub clock: Arc<HlcClock>,
    pub token: String,
    pub edge_ips: Vec<IpAddr>,
    pub node_name: Option<String>,
    pub updater: Arc<Updater>,
    pub info: Arc<NodeInfo>,
    pub polled: Arc<AtomicBool>,
    /// Extra extensible domain providers (M2 KV / D1).
    pub providers: std::sync::RwLock<Vec<Arc<dyn SyncProvider>>>,
    cursors: Mutex<Vec<PeerCursor>>,
    push_notify: Arc<Notify>,
    boot_id: String,
    report_seq: std::sync::atomic::AtomicU64,
    pending_telemetry: Mutex<Option<(Value, Value)>>,
    last_told_usage: Mutex<Option<crate::limits::Usage>>,
    last_report_at: Mutex<std::time::Instant>,
}

impl PeerSync {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: NodeRole,
        peers: Vec<crate::edge::upstream::Target>,
        edge: Arc<Edge>,
        store: Arc<Store>,
        accounts: Arc<Accounts>,
        fleet: Arc<Fleet>,
        clock: Arc<HlcClock>,
        token: String,
        edge_ips: Vec<IpAddr>,
        node_name: Option<String>,
        updater: Arc<Updater>,
        info: Arc<NodeInfo>,
        polled: Arc<AtomicBool>,
    ) -> Arc<Self> {
        let n = peers.len();
        Arc::new(PeerSync {
            role,
            peers,
            edge,
            store,
            accounts,
            fleet,
            clock,
            token,
            edge_ips,
            node_name,
            updater,
            info,
            polled,
            providers: std::sync::RwLock::new(Vec::new()),
            cursors: Mutex::new((0..n).map(|_| PeerCursor::default()).collect()),
            push_notify: Arc::new(Notify::new()),
            boot_id: uuid::Uuid::new_v4().simple().to_string(),
            report_seq: std::sync::atomic::AtomicU64::new(0),
            pending_telemetry: Mutex::new(None),
            last_told_usage: Mutex::new(None),
            last_report_at: Mutex::new(std::time::Instant::now() - Duration::from_secs(60)),
        })
    }

    pub fn register_provider(&self, provider: Arc<dyn SyncProvider>) {
        self.providers.write().unwrap().push(provider);
    }

    pub fn node(&self) -> String {
        crate::fleet::self_name(&self.store, &self.edge_ips, self.node_name.as_deref())
    }

    #[allow(dead_code)]
    pub fn wake_push(&self) {
        self.push_notify.notify_one();
    }

    /// Push pending local deltas to all peers immediately, bounded by `timeout`
    /// (used for auth-critical mutations and ACME lease claims).
    pub async fn push_now_bounded(&self, timeout: Duration) {
        if self.peers.is_empty() || self.role.is_accelerate() {
            return;
        }
        let _ = tokio::time::timeout(timeout, self.push_all(false)).await;
    }

    async fn exchange(
        &self,
        target: &crate::edge::upstream::Target,
        method: hyper::Method,
        path: &str,
        body: Option<Vec<u8>>,
        limit: Duration,
    ) -> Result<bytes::Bytes, String> {
        use http_body_util::BodyExt;
        let exchange = async {
            let mut req = hyper::Request::builder()
                .method(method)
                .uri(format!("/client/v4{path}"))
                .header("authorization", format!("Bearer {}", self.token))
                .header("x-fucf-node-role", self.role.as_str());
            if body.is_some() {
                req = req.header("content-type", "application/json");
            }
            let req = req.body(crate::edge::full(body.unwrap_or_default())).map_err(|e| e.to_string())?;
            let resp = self.edge.upstream.send(target, req).await.map_err(|e| format!("{e:?}"))?;
            let status = resp.status();
            let bytes = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
            if !status.is_success() {
                return Err(format!("peer answered {status}"));
            }
            Ok(bytes)
        };
        match tokio::time::timeout(limit, exchange).await {
            Ok(res) => res,
            Err(_) => Err("timed out".into()),
        }
    }

    async fn call_peer(
        &self,
        target: &crate::edge::upstream::Target,
        method: hyper::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Value, String> {
        let bytes = self.exchange(target, method, path, body, Duration::from_secs(30)).await?;
        let mut reply: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok(reply["result"].take())
    }

    /// Pull deltas from peer `idx`. Returns `true` if a new state was adopted.
    async fn pull_peer(&self, idx: usize) -> Result<bool, String> {
        let target = &self.peers[idx];
        let (since_cfg, ep_cfg, since_acc, ep_acc, domain_cursors) = {
            let cursors = self.cursors.lock().await;
            let c = &cursors[idx];
            (
                c.remote_config_rev,
                c.remote_config_epoch.clone(),
                c.remote_accounts_rev,
                c.remote_accounts_epoch.clone(),
                c.remote_domain_cursors.clone(),
            )
        };
        let node = self.node();
        let mut path = format!(
            "/replication/sync?since={}&epoch={}&since_accounts={}&epoch_accounts={}&node={}&role={}&version={}&build={}",
            since_cfg,
            utf8_percent_encode(&ep_cfg, NON_ALPHANUMERIC),
            since_acc,
            utf8_percent_encode(&ep_acc, NON_ALPHANUMERIC),
            utf8_percent_encode(&node, NON_ALPHANUMERIC),
            self.role.as_str(),
            utf8_percent_encode(&self.store.version(), NON_ALPHANUMERIC),
            utf8_percent_encode(env!("CARGO_PKG_VERSION"), NON_ALPHANUMERIC),
        );
        if self.updater.enabled() {
            let (trusted, submission, rejected) = self.updater.standing();
            path += &format!(
                "&exe={}&trusted={}&submission={}&rejected={}",
                self.updater.own(),
                u8::from(trusted),
                utf8_percent_encode(&submission, NON_ALPHANUMERIC),
                rejected.join(",")
            );
        }
        if !domain_cursors.is_empty() || !self.providers.read().unwrap().is_empty() {
            let encoded = serde_json::to_string(&domain_cursors).unwrap_or_default();
            path += &format!("&domains={}", utf8_percent_encode(&encoded, NON_ALPHANUMERIC));
        }

        let mut res = self.call_peer(target, hyper::Method::GET, &path, None).await?;
        self.polled.store(true, Ordering::Relaxed);

        if let (Some(ms), Some(seq)) = (res["hlc"]["ms"].as_u64(), res["hlc"]["seq"].as_u64()) {
            self.clock.observe(ms, seq);
        }

        if let Some(peer_node) = res["node"].as_str().filter(|s| !s.is_empty()) {
            let peer_ver = res["version"].as_str().unwrap_or_default();
            let peer_build = res["build"].as_str().unwrap_or_default();
            self.fleet.seen(peer_node, peer_ver, peer_build);
            if let Some(role_str) = res["role"].as_str() {
                self.fleet.set_role(peer_node, role_str);
            }
        }

        // Execute commands queued for this node.
        for action in res["commands"].as_array().into_iter().flatten().filter_map(|a| a.as_str()) {
            match self.info.run(action).await {
                Ok(said) => tracing::info!("asked from panel: {action}: {said}"),
                Err(e) => tracing::warn!("asked from panel: {e}"),
            }
        }

        let mut adopted = false;

        if !res["config"].is_null() {
            let delta: DomainDelta = serde_json::from_value(res["config"].take()).map_err(|e| format!("bad config delta: {e}"))?;
            let new_ep = delta.epoch.clone();
            let new_rev = delta.to_rev;
            let changed = self.store.merge_delta_async(&delta).await.map_err(|e| format!("{e:?}"))?;
            adopted |= changed;
            let mut cursors = self.cursors.lock().await;
            cursors[idx].remote_config_epoch = new_ep;
            cursors[idx].remote_config_rev = new_rev;
        }

        if !res["accounts"].is_null() {
            let delta: DomainDelta = serde_json::from_value(res["accounts"].take()).map_err(|e| format!("bad accounts delta: {e}"))?;
            let new_ep = delta.epoch.clone();
            let new_rev = delta.to_rev;
            let acc = self.accounts.clone();
            let clk = self.clock.clone();
            let changed = tokio::task::spawn_blocking(move || acc.merge_delta(&delta, &clk))
                .await
                .map_err(|e| e.to_string())??;
            adopted |= changed;
            let mut cursors = self.cursors.lock().await;
            cursors[idx].remote_accounts_epoch = new_ep;
            cursors[idx].remote_accounts_rev = new_rev;
        }

        if let Some(domains_arr) = res["domains"].as_array() {
            let providers = self.providers.read().unwrap().clone();
            for dv in domains_arr {
                if let Ok(delta) = serde_json::from_value::<DomainDelta>(dv.clone()) {
                    if let Some(p) = providers.iter().find(|p| p.domain() == delta.domain).cloned() {
                        let dname = delta.domain.clone();
                        let ep = delta.epoch.clone();
                        let to_rev = delta.to_rev;
                        let clk = self.clock.clone();
                        let changed = tokio::task::spawn_blocking(move || p.merge_delta(&delta, &clk))
                            .await
                            .map_err(|e| e.to_string())??;
                        if changed {
                            adopted = true;
                        }
                        self.cursors.lock().await[idx].remote_domain_cursors.insert(dname, (ep, to_rev));
                    }
                }
            }
        }

        let release = res["release"].take();
        if !release.is_null() {
            self.follow_release(target, &release).await;
        }

        Ok(adopted)
    }

    /// Push local deltas (and telemetry if due) to peer `idx`.
    async fn push_peer(&self, idx: usize, telemetry: Option<&Value>) -> Result<(), String> {
        let target = &self.peers[idx];
        let (last_cfg, last_acc, last_doms) = {
            let cursors = self.cursors.lock().await;
            let c = &cursors[idx];
            (c.last_pushed_config_rev, c.last_pushed_accounts_rev, c.last_pushed_domain_revs.clone())
        };

        let mut cfg_delta: Option<DomainDelta> = None;
        let mut acc_delta: Option<DomainDelta> = None;
        let mut dom_deltas: Vec<DomainDelta> = Vec::new();
        let mut new_cfg_rev = last_cfg;
        let mut new_acc_rev = last_acc;
        let mut new_dom_revs = last_doms.clone();

        if !self.role.is_accelerate() {
            let cur_cfg = self.store.current_rev();
            if cur_cfg > last_cfg {
                let d = self.store.export_since_async(last_cfg, Some(&self.store.epoch())).await?;
                new_cfg_rev = d.to_rev;
                cfg_delta = Some(d);
            }
            let cur_acc = self.accounts.current_rev();
            if cur_acc > last_acc {
                let acc = self.accounts.clone();
                let ep = acc.epoch();
                let d = tokio::task::spawn_blocking(move || acc.export_since(last_acc, Some(&ep)))
                    .await
                    .map_err(|e| e.to_string())??;
                new_acc_rev = d.to_rev;
                acc_delta = Some(d);
            }
            let providers = self.providers.read().unwrap().clone();
            for p in providers {
                let since = last_doms.get(p.domain()).copied().unwrap_or(0);
                if p.current_rev() > since {
                    let dom = p.domain().to_string();
                    let ep = p.epoch();
                    let d = tokio::task::spawn_blocking(move || p.export_since(since, Some(&ep)))
                        .await
                        .map_err(|e| e.to_string())??;
                    new_dom_revs.insert(dom, d.to_rev);
                    dom_deltas.push(d);
                }
            }
        }

        if cfg_delta.is_none() && acc_delta.is_none() && dom_deltas.is_empty() && telemetry.is_none() {
            return Ok(());
        }

        let (ms, seq) = self.clock.current();
        let mut body = json!({
            "node": self.node(),
            "role": self.role.as_str(),
            "version": self.store.version(),
            "build": env!("CARGO_PKG_VERSION"),
            "hlc": { "ms": ms, "seq": seq },
        });
        if let Some(d) = cfg_delta {
            body["config"] = serde_json::to_value(d).unwrap_or(Value::Null);
        }
        if let Some(d) = acc_delta {
            body["accounts"] = serde_json::to_value(d).unwrap_or(Value::Null);
        }
        if !dom_deltas.is_empty() {
            body["domains"] = serde_json::to_value(dom_deltas).unwrap_or(Value::Null);
        }
        if let Some(t) = telemetry {
            body["telemetry"] = t.clone();
        }

        let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let res = self.call_peer(target, hyper::Method::POST, "/replication/sync", Some(bytes)).await?;
        if let Some(peer_node) = res["node"].as_str().filter(|s| !s.is_empty()) {
            let peer_ver = res["version"].as_str().unwrap_or_default();
            let peer_build = res["build"].as_str().unwrap_or_default();
            self.fleet.seen(peer_node, peer_ver, peer_build);
            if let Some(role_str) = res["role"].as_str() {
                self.fleet.set_role(peer_node, role_str);
            }
        }

        let mut cursors = self.cursors.lock().await;
        cursors[idx].last_pushed_config_rev = new_cfg_rev;
        cursors[idx].last_pushed_accounts_rev = new_acc_rev;
        cursors[idx].last_pushed_domain_revs = new_dom_revs;
        Ok(())
    }

    async fn build_telemetry_if_due(&self, force: bool) -> Option<(Value, Option<(Value, Value)>, crate::limits::Usage)> {
        let elapsed = self.last_report_at.lock().await.elapsed();
        if !force && elapsed < Duration::from_secs(15) {
            return None;
        }
        let seq = self.report_seq.load(Ordering::Relaxed);
        let pending = self.pending_telemetry.lock().await.take();
        let (stats, events) = match pending {
            Some(p) => p,
            None => (
                serde_json::to_value(self.edge.stats.take_outbox()).unwrap_or_default(),
                serde_json::to_value(self.edge.waf.take_outbox()).unwrap_or_default(),
            ),
        };
        let usage = self.edge.limits.usage();
        let nothing_new =
            stats.as_object().is_none_or(|o| o.is_empty()) && events.as_array().is_none_or(|a| a.is_empty());
        let same_usage = self.last_told_usage.lock().await.as_ref() == Some(&usage);
        if !force && seq > 0 && nothing_new && same_usage && elapsed < Duration::from_secs(60) {
            return None;
        }
        let status = self.info.status_async().await;
        let payload = json!({
            "boot": self.boot_id,
            "seq": seq,
            "stats": &stats,
            "events": &events,
            "usage": &usage,
            "status": status,
        });
        Some((payload, Some((stats, events)), usage))
    }

    async fn push_all(&self, include_telemetry: bool) {
        let tele = if include_telemetry {
            self.build_telemetry_if_due(false).await
        } else {
            None
        };
        let tele_val = tele.as_ref().map(|(v, _, _)| v);
        let mut futs = Vec::with_capacity(self.peers.len());
        for idx in 0..self.peers.len() {
            futs.push(self.push_peer(idx, tele_val));
        }
        let results = futures_join_all(futs).await;
        let any_ok = results.iter().any(Result::is_ok);
        if let Some((_, raw, usage)) = tele {
            if any_ok {
                self.report_seq.fetch_add(1, Ordering::Relaxed);
                *self.last_told_usage.lock().await = Some(usage);
                *self.last_report_at.lock().await = std::time::Instant::now();
            } else {
                *self.pending_telemetry.lock().await = raw;
            }
        }
    }

    async fn follow_release(&self, target: &crate::edge::upstream::Target, release: &Value) {
        let updater = &self.updater;
        let (Some(id), Some(sha), Some(signature)) =
            (release["id"].as_str(), release["sha256"].as_str(), release["signature"].as_str())
        else {
            return;
        };
        if !updater.enabled() {
            return;
        }
        let u = updater.clone();
        let (id_s, sha_s) = (id.to_string(), sha.to_string());
        let _ = tokio::task::spawn_blocking(move || u.forgive(&id_s, &sha_s)).await;

        let revert = release["revert"] == true && updater.own() == sha;
        if revert {
            tracing::warn!("release {sha} is taken back: going back to what ran before");
            let u = updater.clone();
            let sha_s = sha.to_string();
            if let Err(e) = tokio::task::spawn_blocking(move || u.reject(&sha_s)).await.unwrap_or_else(|e| Err(e.to_string())) {
                tracing::error!("{e}");
            }
        } else if release["go"] == true && updater.own() != sha && !updater.rejected().iter().any(|r| r == sha) {
            let bytes = match self
                .exchange(target, hyper::Method::GET, &format!("/releases/{sha}/binary"), None, Duration::from_secs(600))
                .await
            {
                Ok(b) => b,
                Err(e) => return tracing::warn!("cannot fetch release {sha} (trying again): {e}"),
            };
            tracing::info!("release {sha}: it is this node's turn ({} bytes)", bytes.len());
            let (installer, digest, sig) = (updater.clone(), sha.to_string(), signature.to_string());
            let installing = move || installer.install(&digest, &sig, &bytes).and_then(|_| installer.activate(&digest));
            if let Err(e) = tokio::task::spawn_blocking(installing).await.unwrap_or_else(|e| Err(e.to_string())) {
                tracing::error!("cannot take release {sha}: {e}");
                let u = updater.clone();
                let sha_s = sha.to_string();
                let _ = tokio::task::spawn_blocking(move || u.reject(&sha_s)).await;
                return;
            }
        } else {
            return;
        }
        let starter = updater.clone();
        let failure = tokio::task::spawn_blocking(move || starter.relaunch()).await.unwrap_or_else(|e| e.to_string());
        tracing::error!("{failure}");
        if revert {
            std::process::exit(1);
        }
        let u = updater.clone();
        let sha_s = sha.to_string();
        let _ = tokio::task::spawn_blocking(move || u.reject(&sha_s)).await;
    }

    /// Run background anti-entropy pull/push and debounced mutation push-notify.
    pub async fn run(self: Arc<Self>) {
        if self.peers.is_empty() {
            return;
        }
        // Wake push whenever local Store or Accounts mutate (only in peer role).
        if !self.role.is_accelerate() {
            let mut store_rx = self.store.subscribe();
            let n1 = self.push_notify.clone();
            tokio::spawn(async move {
                while store_rx.changed().await.is_ok() {
                    n1.notify_one();
                }
            });
            let mut acc_rx = self.accounts.subscribe();
            let n2 = self.push_notify.clone();
            tokio::spawn(async move {
                while acc_rx.changed().await.is_ok() {
                    n2.notify_one();
                }
            });
        }

        // Initial pull on startup so accelerate / restarted peers converge immediately.
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut just_adopted = false;
        loop {
            let mut adopted_any = false;
            for idx in 0..self.peers.len() {
                match self.pull_peer(idx).await {
                    Ok(adopted) => {
                        let mut cursors = self.cursors.lock().await;
                        cursors[idx].failing = false;
                        adopted_any |= adopted;
                    }
                    Err(e) => {
                        let mut cursors = self.cursors.lock().await;
                        if !cursors[idx].failing {
                            tracing::warn!("sync pull from {} failing: {e}", self.peers[idx].host);
                            cursors[idx].failing = true;
                        }
                    }
                }
            }
            self.push_all(true).await;

            just_adopted = adopted_any && !just_adopted;
            if just_adopted {
                // Confirm adoption to peers quickly (helps ACME wait_for_fleet).
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.push_notify.notified() => {
                    // Debounce rapid bursts of mutations before pushing.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    self.push_all(false).await;
                }
            }
        }
    }
}

async fn futures_join_all<F: std::future::Future>(futs: Vec<F>) -> Vec<F::Output> {
    let mut out = Vec::with_capacity(futs.len());
    let mut pinned: Vec<Option<(usize, std::pin::Pin<Box<F>>)>> =
        futs.into_iter().enumerate().map(|(i, f)| Some((i, Box::pin(f)))).collect();
    out.resize_with(pinned.len(), || None);
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for slot in &mut pinned {
            if let Some((idx, fut)) = slot {
                match fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(val) => {
                        out[*idx] = Some(val);
                        *slot = None;
                    }
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().map(|o| o.expect("all futures completed")).collect()
}
