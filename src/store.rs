//! Persistent control-plane state (zones + records) and the immutable
//! lookup snapshot the data plane reads from.
//!
//! Writes go through a mutex, are persisted atomically to a JSON file and
//! then published as a fresh `Arc<Snapshot>`; readers never block on writers.

use crate::dns::wire::{self, normalize_name};
use crate::expr::Expr;
use crate::items::{
    AcmeChallenge, CacheRule, Certificate, CertificatePack, EdgeNode, EmailRule, FirewallRule, Item, LocalProxyRule, Meta,
    NodeTelemetry, OriginRule, PurgeOp, RateLimit, RedirectRule, Settings, SpectrumApp, SteerRule, TransformRule,
    WorkerRoute, WorkerScript,
};
use crate::lists::{IpList, ListSets};
use crate::sync::{unix_ms, AcmeLease, DomainDelta, HlcClock, SyncMeta, SyncProvider};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

const DURABLE_TOMBSTONE_TTL_MS: u64 = 30 * 86_400_000;
const EPHEMERAL_TOMBSTONE_TTL_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    pub paused: bool,
    pub name_servers: Vec<String>,
    pub serial: u32,
    /// `full`: the domain's NS records point at us. `partial`: the domain
    /// stays with another DNS provider and CNAMEs individual hosts to us.
    /// `cert`: only certificates are managed for it (DNS-01 through a CNAME
    /// delegation of `_acme-challenge`); it is not served -- no DNS answers,
    /// no CDN, not exported to the SNI split -- so its names can belong to
    /// other services or to proxy rules.
    #[serde(default = "Zone::default_kind", rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<crate::dns::dnssec::DnssecConfig>,
    /// The key forwarded mail of this zone is signed with (crate::dkim);
    /// kept here rather than in `settings`, which the API shows as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_dkim: Option<crate::dkim::DkimKey>,
    /// The zone's private CA for origin certificates (crate::origin_ca); its
    /// key, like the DKIM key, is never answered by the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_ca: Option<crate::origin_ca::OriginCa>,
    /// The id of the user the zone belongs to (crate::tenancy); none: the
    /// administrators' only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub created_on: String,
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl Zone {
    fn default_kind() -> String {
        "full".into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub content: String,
    /// 1 means "automatic" (served as 300), like Cloudflare.
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub proxied: bool,
    #[serde(default)]
    pub comment: Option<String>,
    /// Proxied records: how to talk to the origin, where the usual does not do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RecordOrigin>,
    pub created_on: String,
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

/// How the edge reaches the origin behind a proxied record, where that
/// differs from the usual: the visitor's host name as Host header and TLS
/// server name, the scheme that goes with the zone's ssl mode, its default
/// port. The case this is for: an origin that itself sits behind another
/// CDN, reached at an address of that CDN under one name (the server name)
/// while being asked for another (the Host header).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecordOrigin {
    /// TLS server name presented to the origin. Having one means HTTPS,
    /// unless the scheme says otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Host header sent to the origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_header: Option<String>,
    /// Port of the origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Route internally to this edge node (`127.0.0.1:<port>` if self, else `<node_ip>:<port>`).
    #[serde(default, alias = "origin_node", skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// http or https, whatever the zone's ssl mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Share of the requests among the addresses of the name (1 to 100; 1 when not given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

impl RecordOrigin {
    pub fn is_empty(&self) -> bool {
        *self == RecordOrigin::default()
    }

    /// How the origin is reached, whatever its share of the requests: two
    /// addresses reached the same way can stand in for each other.
    pub fn way(origin: Option<&RecordOrigin>) -> Option<RecordOrigin> {
        origin.map(|o| RecordOrigin { weight: None, ..o.clone() }).filter(|o| !o.is_empty())
    }

    /// Normalized and checked; nothing if no option is set.
    fn validated(self) -> Result<Option<RecordOrigin>, StoreError> {
        let host = |what: &str, value: Option<String>| match value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            Some(v) => crate::items::check_host(what, &v).map(Some),
            None => Ok(None),
        };
        let origin = RecordOrigin {
            sni: host("origin.sni", self.sni)?,
            host_header: host("origin.host_header", self.host_header)?,
            port: self.port,
            node: self.node.map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()),
            scheme: self.scheme.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()),
            weight: self.weight,
        };
        if origin.weight.is_some_and(|w| !(1..=100).contains(&w)) {
            return invalid("origin.weight must be between 1 and 100");
        }
        if origin.port == Some(0) {
            return invalid("origin.port must be between 1 and 65535");
        }
        match origin.scheme.as_deref() {
            None | Some("https") => {}
            Some("http") if origin.sni.is_some() => return invalid("origin.sni is a TLS server name: it cannot go with the scheme http"),
            Some("http") => {}
            Some(other) => return invalid(format!("origin.scheme must be http or https, not '{other}'")),
        }
        Ok(Some(origin).filter(|o| !o.is_empty()))
    }
}

/// Fully-specified record fields, as supplied by the API layer.
#[derive(Debug, Clone)]
pub struct RecordInput {
    pub name: String,
    pub rtype: String,
    pub content: String,
    pub ttl: u32,
    pub priority: Option<u16>,
    pub proxied: bool,
    pub comment: Option<String>,
    pub origin: Option<RecordOrigin>,
}

#[derive(Debug)]
pub enum StoreError {
    ZoneNotFound,
    RecordNotFound,
    NotFound,
    /// This node only mirrors the primary's configuration.
    ReadOnly,
    Conflict(String),
    Invalid(String),
    Io(String),
}

/// Per-collection soft-delete tombstones replicated via LWW.
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Tombstones {
    pub zones: BTreeMap<String, SyncMeta>,
    pub records: BTreeMap<String, SyncMeta>,
    pub firewall_rules: BTreeMap<String, SyncMeta>,
    pub rate_limits: BTreeMap<String, SyncMeta>,
    pub origin_rules: BTreeMap<String, SyncMeta>,
    pub certificates: BTreeMap<String, SyncMeta>,
    pub certificate_packs: BTreeMap<String, SyncMeta>,
    pub spectrum_apps: BTreeMap<String, SyncMeta>,
    pub workers: BTreeMap<String, SyncMeta>,
    pub worker_routes: BTreeMap<String, SyncMeta>,
    pub redirect_rules: BTreeMap<String, SyncMeta>,
    pub transform_rules: BTreeMap<String, SyncMeta>,
    pub cache_rules: BTreeMap<String, SyncMeta>,
    pub email_rules: BTreeMap<String, SyncMeta>,
    pub log_jobs: BTreeMap<String, SyncMeta>,
    /// (Left out while empty, like `alert_channels`.)
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub waiting_rooms: BTreeMap<String, SyncMeta>,
    pub nodes: BTreeMap<String, SyncMeta>,
    pub steering: BTreeMap<String, SyncMeta>,
    pub local_proxy_rules: BTreeMap<String, SyncMeta>,
    pub purges: BTreeMap<String, SyncMeta>,
    pub acme_challenges: BTreeMap<String, SyncMeta>,
    pub node_telemetry: BTreeMap<String, SyncMeta>,
    pub ip_lists: BTreeMap<String, SyncMeta>,
    /// (Left out while empty: nodes that know no alert channels compute the same version.)
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub alert_channels: BTreeMap<String, SyncMeta>,
    /// (Left out while empty, like alert channels.)
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub challenge_widgets: BTreeMap<String, SyncMeta>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Data {
    pub zones: Vec<Zone>,
    pub records: Vec<Record>,
    pub firewall_rules: Vec<FirewallRule>,
    pub rate_limits: Vec<RateLimit>,
    pub origin_rules: Vec<OriginRule>,
    pub certificates: Vec<Certificate>,
    pub spectrum_apps: Vec<SpectrumApp>,
    pub workers: Vec<WorkerScript>,
    pub worker_routes: Vec<WorkerRoute>,
    pub redirect_rules: Vec<RedirectRule>,
    pub transform_rules: Vec<TransformRule>,
    pub cache_rules: Vec<CacheRule>,
    pub email_rules: Vec<EmailRule>,
    pub log_jobs: Vec<crate::edge::reqlog::LogJob>,
    /// Queues in front of the origin (crate::edge::waiting); left out while
    /// empty, so that the configuration version stays the one nodes without
    /// waiting rooms compute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waiting_rooms: Vec<crate::edge::waiting::WaitingRoom>,
    pub nodes: Vec<EdgeNode>,
    pub steering: Vec<SteerRule>,
    pub local_proxy_rules: Vec<LocalProxyRule>,
    pub purges: Vec<PurgeOp>,
    pub certificate_packs: Vec<CertificatePack>,
    pub acme_challenges: Vec<AcmeChallenge>,
    /// Address lists that rule expressions name as `$name` (crate::lists).
    pub ip_lists: Vec<IpList>,
    /// Legacy traffic-limit & GFW projections (synchronized from `node_telemetry`).
    pub limited_nodes: BTreeMap<String, crate::limits::State>,
    #[serde(default)]
    pub limited_offload: BTreeMap<String, u8>,
    #[serde(default)]
    pub gfw_status: BTreeMap<String, crate::gfw::GfwStatus>,
    /// Self-owned per-node telemetry replicated across peers.
    #[serde(default)]
    pub node_telemetry: BTreeMap<String, NodeTelemetry>,
    /// Distributed ACME leader lease across peer nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_lease: Option<AcmeLease>,
    /// Where alerts go (see crate::alerts); left out while empty, so that the
    /// configuration version stays the one nodes without alerts compute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alert_channels: Vec<crate::alerts::AlertChannel>,
    /// The human checks sites embed (see crate::edge::widget); left out
    /// while empty, so that the configuration version stays the same.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub challenge_widgets: Vec<crate::edge::widget::ChallengeWidget>,
    /// Replication epoch UUID (changes if state is re-initialized).
    #[serde(default)]
    pub epoch: String,
    /// Local monotonic revision counter for `?since=` incremental deltas.
    #[serde(default)]
    pub local_rev: u64,
    /// Highest `local_rev` of any pruned tombstone (forces `full_resync` if `?since < gc_floor_rev`).
    #[serde(default)]
    pub gc_floor_rev: u64,
    #[serde(default)]
    pub tombstones: Tombstones,
}

// ------------------------------------------------------------ snapshot ----

pub struct ZoneSnap {
    pub zone: Zone,
    /// Records keyed by owner name (FQDN, lowercase, no trailing dot).
    pub names: HashMap<String, Vec<Record>>,
    /// Every existing node: owners, empty non-terminals and the apex.
    pub nodes: HashSet<String>,
    /// Host names of Spectrum apps; they resolve to the edge.
    pub spectrum_names: HashSet<String>,
    /// Enabled rules with their compiled expressions, in evaluation order.
    pub firewall: Vec<(FirewallRule, Expr)>,
    pub rate_limits: Vec<(RateLimit, Expr)>,
    pub origin_rules: Vec<(OriginRule, Expr)>,
    pub redirects: Vec<(RedirectRule, Expr)>,
    pub transforms: Vec<(TransformRule, Expr)>,
    pub cache_rules: Vec<(CacheRule, Expr)>,
    /// Worker routes, most specific (longest) pattern first.
    pub routes: Vec<WorkerRoute>,
    /// Enabled e-mail routing rules.
    pub email_rules: Vec<EmailRule>,
    /// Enabled waiting rooms (crate::edge::waiting::pick chooses among them).
    pub waiting_rooms: Vec<crate::edge::waiting::WaitingRoom>,
    /// Compiled DNSSEC signer when DNSSEC is enabled on this zone.
    pub dnssec: Option<Arc<crate::dns::dnssec::DnssecSigner>>,
}

impl ZoneSnap {
    /// Records stored at `host`, or at the wildcard covering it (RFC 4592).
    pub fn records_for(&self, host: &str) -> &[Record] {
        if self.nodes.contains(host) {
            return self.names.get(host).map(Vec::as_slice).unwrap_or(&[]);
        }
        let mut encloser = host;
        loop {
            encloser = encloser.split_once('.').map(|(_, p)| p).unwrap_or("");
            if encloser.is_empty() || self.nodes.contains(encloser) {
                break;
            }
        }
        self.names.get(&format!("*.{encloser}")).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether `host` is one of the zone's decoy names (see
    /// `Settings::decoy_subdomains`): below the apex, with nothing at it,
    /// no wildcard covering it, not a Spectrum app, not delegated away.
    pub fn is_decoy(&self, host: &str) -> bool {
        let zone = &self.zone.name;
        if !self.zone.settings.decoy_subdomains || host.len() <= zone.len() + 1 || !host.ends_with(zone.as_str()) || !host[..host.len() - zone.len()].ends_with('.') {
            return false;
        }
        if self.nodes.contains(host) || self.spectrum_names.contains(host) || !self.records_for(host).is_empty() || reserved(host) {
            return false;
        }
        let mut n = host;
        while n.len() > zone.len() {
            if self.names.get(n).is_some_and(|rs| rs.iter().any(|r| r.rtype == "NS")) {
                return false;
            }
            n = n.split_once('.').map(|(_, p)| p).unwrap_or("");
        }
        true
    }
}

/// Names this node answers for by itself (the CNAME base and everything
/// below it, the panel host): they are never decoy names, even when they
/// fall in a zone that has decoys and holds no records for them.
static RESERVED: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

pub fn reserve_names(names: Vec<String>) {
    let _ = RESERVED.set(names.into_iter().map(|n| n.trim_end_matches('.').to_ascii_lowercase()).filter(|n| !n.is_empty()).collect());
}

fn reserved(host: &str) -> bool {
    RESERVED.get().is_some_and(|names| names.iter().any(|n| host == n || host.strip_suffix(n.as_str()).is_some_and(|rest| rest.ends_with('.'))))
}

#[derive(Default)]
pub struct Snapshot {
    pub zones: HashMap<String, ZoneSnap>,
    pub workers: HashMap<String, Arc<WorkerScript>>,
    pub spectrum_apps: Vec<SpectrumApp>,
    /// Uploaded and managed certificates by host pattern (`example.com`,
    /// `*.example.com`); an uploaded one wins.
    pub certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    /// Pending ACME challenges: TXT values by validated name, challenge
    /// certificates by server name, key authorizations by token.
    pub acme_dns: HashMap<String, Vec<String>>,
    pub acme_tls: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    pub acme_http: HashMap<String, String>,
    /// Nodes over a threshold of their traffic allowance.
    pub limited: HashMap<String, crate::limits::State>,
    /// Per-node DNS offload probability (0-100).
    pub limited_offload: HashMap<String, u8>,
    /// Per-node mainland-China (GFW) reachability status.
    pub gfw_status: HashMap<String, crate::gfw::GfwStatus>,
    /// Enabled edge nodes.
    pub nodes: Vec<EdgeNode>,
    /// Enabled steering rules, in priority order.
    pub steering: Vec<SteerRule>,
    /// Enabled local reverse-proxy rules, ordered by `(priority, !exact_path, Reverse(path_prefix.len()))`.
    pub local_proxy_rules: Vec<LocalProxyRule>,
    pub purges: Vec<PurgeOp>,
}

/// Enabled rules of one zone, compiled, sorted by `key`. `$name` in an
/// expression is resolved against `lists` here, once per snapshot.
fn compile<T: Item, K: Ord>(
    all: &[T],
    zone_id: &str,
    lists: &ListSets,
    enabled: impl Fn(&T) -> bool,
    expr: impl Fn(&T) -> &str,
    key: impl Fn(&T) -> K,
) -> Vec<(T, Expr)> {
    let mut out: Vec<(T, Expr)> = all
        .iter()
        .filter(|r| r.meta().zone_id == zone_id && enabled(r))
        .filter_map(|r| Some((r.clone(), Expr::parse_with(expr(r), lists).ok()?)))
        .collect();
    out.sort_by_key(|(r, _)| key(r));
    out
}

impl Snapshot {
    fn build(data: &Data) -> Self {
        let lists = crate::lists::sets(&data.ip_lists);
        let mut by_id: HashMap<&str, ZoneSnap> = data
            .zones
            .iter()
            // certificate-only zones are not served (their packs still count, see `certs` below)
            .filter(|z| z.kind != "cert")
            .map(|z| {
                let id = z.id.as_str();
                let mut routes: Vec<WorkerRoute> =
                    data.worker_routes.iter().filter(|r| r.meta.zone_id == id).cloned().collect();
                routes.sort_by_key(|r| std::cmp::Reverse(r.pattern.len()));
                let snap = ZoneSnap {
                    zone: z.clone(),
                    names: HashMap::new(),
                    nodes: HashSet::from([z.name.clone()]),
                    spectrum_names: HashSet::new(),
                    firewall: compile(&data.firewall_rules, id, &lists, |r| r.enabled, |r| &r.expression, |r| r.priority),
                    rate_limits: compile(&data.rate_limits, id, &lists, |r| r.enabled, |r| &r.expression, |_| 0),
                    origin_rules: compile(&data.origin_rules, id, &lists, |r| r.enabled, |r| &r.expression, |r| r.priority),
                    redirects: compile(&data.redirect_rules, id, &lists, |r| r.enabled, |r| &r.expression, |r| r.priority),
                    transforms: compile(&data.transform_rules, id, &lists, |r| r.enabled, |r| &r.expression, |r| r.priority),
                    cache_rules: compile(&data.cache_rules, id, &lists, |r| r.enabled, |r| &r.expression, |r| r.priority),
                    routes,
                    email_rules: data.email_rules.iter().filter(|r| r.enabled && r.meta.zone_id == z.id).cloned().collect(),
                    waiting_rooms: data.waiting_rooms.iter().filter(|r| r.enabled && r.meta.zone_id == z.id).cloned().collect(),
                    dnssec: z.dnssec.as_ref().and_then(|cfg| crate::dns::dnssec::DnssecSigner::from_config(&z.name, cfg)),
                };
                (id, snap)
            })
            .collect();
        fn add_node(zs: &mut ZoneSnap, name: &str) {
            let mut n = name;
            while n.len() > zs.zone.name.len() && zs.nodes.insert(n.to_string()) {
                n = n.split_once('.').map(|(_, rest)| rest).unwrap_or("");
            }
        }
        for r in &data.records {
            let Some(zs) = by_id.get_mut(r.zone_id.as_str()) else { continue };
            add_node(zs, &r.name);
            zs.names.entry(r.name.clone()).or_default().push(r.clone());
        }
        for app in &data.spectrum_apps {
            let Some(zs) = by_id.get_mut(app.meta.zone_id.as_str()) else { continue };
            add_node(zs, &app.dns.name);
            zs.spectrum_names.insert(app.dns.name.clone());
        }
        let mut certs = HashMap::new();
        for c in &data.certificates {
            if let Ok(key) = crate::edge::tls::parse_cert(&c.certificate, &c.private_key) {
                for h in &c.hosts {
                    certs.insert(h.clone(), key.clone());
                }
            }
        }
        for p in data.certificate_packs.iter().filter(|p| !p.certificate.is_empty()) {
            if let Ok(key) = crate::edge::tls::parse_cert(&p.certificate, &p.private_key) {
                for h in &p.hosts {
                    certs.entry(h.clone()).or_insert_with(|| key.clone());
                }
            }
        }
        let (mut acme_dns, mut acme_tls, mut acme_http) = (HashMap::<String, Vec<String>>::new(), HashMap::new(), HashMap::new());
        for c in &data.acme_challenges {
            match c.kind.as_str() {
                "dns-01" => acme_dns.entry(c.host.clone()).or_default().push(crate::acme::b64(&c.digest())),
                "tls-alpn-01" => {
                    if let Some(cert) = crate::edge::tls::acme_challenge_cert(&c.host, &c.digest()) {
                        acme_tls.insert(c.host.clone(), cert);
                    }
                }
                _ => {
                    acme_http.insert(c.token.clone(), c.key_authorization.clone());
                }
            }
        }
        let mut limited: HashMap<String, crate::limits::State> =
            data.limited_nodes.iter().map(|(name, state)| (name.clone(), *state)).collect();
        let mut limited_offload: HashMap<String, u8> =
            data.limited_offload.iter().map(|(name, pct)| (name.clone(), *pct)).collect();
        let mut gfw_status: HashMap<String, crate::gfw::GfwStatus> =
            data.gfw_status.iter().map(|(name, st)| (name.clone(), st.clone())).collect();
        for (name, t) in &data.node_telemetry {
            if t.limit_state == crate::limits::State::Ok {
                limited.remove(name);
            } else {
                limited.insert(name.clone(), t.limit_state);
            }
            if t.offload_pct == 0 {
                limited_offload.remove(name);
            } else {
                limited_offload.insert(name.clone(), t.offload_pct);
            }
            if let Some(g) = &t.gfw {
                if !g.is_empty() {
                    gfw_status.insert(name.clone(), g.clone());
                }
            }
        }
        Snapshot {
            acme_dns,
            acme_tls,
            acme_http,
            limited,
            limited_offload,
            gfw_status,
            zones: by_id.into_values().map(|zs| (zs.zone.name.clone(), zs)).collect(),
            workers: data.workers.iter().map(|w| (w.name.clone(), Arc::new(w.clone()))).collect(),
            spectrum_apps: data.spectrum_apps.clone(),
            certs,
            nodes: data.nodes.iter().filter(|n| n.enabled).cloned().collect(),
            steering: {
                let mut rules: Vec<SteerRule> = data.steering.iter().filter(|r| r.enabled).cloned().collect();
                rules.sort_by_key(|r| r.priority);
                rules
            },
            local_proxy_rules: {
                let mut rules: Vec<LocalProxyRule> =
                    data.local_proxy_rules.iter().filter(|r| r.enabled).cloned().collect();
                rules.sort_by_key(|r| {
                    (r.priority, !r.exact_path, std::cmp::Reverse(r.path_prefix.len()), r.id.clone())
                });
                rules
            },
            purges: data.purges.clone(),
        }
    }

    /// Longest-suffix match of `name` against the hosted zones.
    pub fn find_zone(&self, name: &str) -> Option<&ZoneSnap> {
        let mut n = name;
        loop {
            if let Some(z) = self.zones.get(n) {
                return Some(z);
            }
            n = n.split_once('.')?.1;
        }
    }
}

// --------------------------------------------------------------- store ----

pub struct Store {
    path: Option<PathBuf>,
    default_ns: Vec<String>,
    data: Mutex<Data>,
    write_gate: tokio::sync::Mutex<()>,
    sync_lock: Mutex<()>,
    snap: RwLock<Arc<Snapshot>>,
    changed: tokio::sync::watch::Sender<()>,
    read_only: AtomicBool,
    /// Hash of the current configuration.
    version: RwLock<String>,
    clock: Arc<HlcClock>,
    sync_node_id: RwLock<String>,
}

/// Overlay a JSON body on the existing global object `id` (or on nothing).
fn merge_global<T: Serialize + serde::de::DeserializeOwned>(
    list: &[T],
    id: Option<&str>,
    body: serde_json::Value,
    get_id: fn(&T) -> &String,
    _created: fn(&T) -> &String,
) -> Result<T, StoreError> {
    use serde_json::Value;
    let Value::Object(body) = body else { return invalid("request body must be a JSON object") };
    let mut merged = match id {
        Some(id) => match serde_json::to_value(list.iter().find(|x| get_id(x) == id).ok_or(StoreError::NotFound)?) {
            Ok(Value::Object(o)) => o,
            _ => Default::default(),
        },
        None => Default::default(),
    };
    merged.extend(body);
    serde_json::from_value(Value::Object(merged)).map_err(|e| StoreError::Invalid(e.to_string()))
}

/// `(id, created_on, modified_on)` for a global object being saved.
fn stamp<T>(list: &[T], id: Option<&str>, get_id: fn(&T) -> &String, created: fn(&T) -> &String) -> (String, String, String) {
    let ts = now();
    match id.and_then(|id| list.iter().find(|x| get_id(x) == id)) {
        Some(old) => (get_id(old).clone(), created(old).clone(), ts),
        None => (new_id(), ts.clone(), ts),
    }
}

fn upsert<T>(list: &mut Vec<T>, item: T, get_id: fn(&T) -> &String) {
    match list.iter().position(|x| get_id(x) == get_id(&item)) {
        Some(i) => list[i] = item,
        None => list.push(item),
    }
}

fn fingerprint(data: &Data) -> String {
    let mut normalized = data.clone();
    normalized.epoch.clear();
    normalized.local_rev = 0;
    normalized.gc_floor_rev = 0;
    let bytes = serde_json::to_vec(&normalized).unwrap_or_default();
    ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()[..12].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Unix seconds as an RFC 3339 timestamp.
pub fn rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// One step of [`Store::batch_items_async`].
pub enum ItemOp {
    /// Create (`id` None) or update an item, as [`Store::save_item_async`]
    /// does. `at` names where the body came from (`rules[2]`), so that a
    /// rejected value says which one it was.
    Save { id: Option<String>, body: serde_json::Value, replace: bool, at: String },
    Delete(String),
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

fn persist_to(path: Option<&Path>, data: &Data) -> Result<(), StoreError> {
    let Some(path) = path else { return Ok(()) };
    let io = |e: std::io::Error| StoreError::Io(e.to_string());
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(data).map_err(|e| StoreError::Io(e.to_string()))?;
    crate::auth::write_private(&tmp, &bytes).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

fn stamp_next(d: &mut Data, clock: &HlcClock, node: &str, deleted: bool) -> SyncMeta {
    d.local_rev = d.local_rev.saturating_add(1);
    clock.stamp(node, deleted, d.local_rev)
}

fn sync_telemetry_projections(d: &mut Data) {
    for (name, t) in &d.node_telemetry {
        if t.limit_state == crate::limits::State::Ok {
            d.limited_nodes.remove(name);
        } else {
            d.limited_nodes.insert(name.clone(), t.limit_state);
        }
        if t.offload_pct == 0 {
            d.limited_offload.remove(name);
        } else {
            d.limited_offload.insert(name.clone(), t.offload_pct);
        }
        if let Some(g) = &t.gfw {
            if !g.is_empty() {
                d.gfw_status.insert(name.clone(), g.clone());
            }
        }
    }
}

fn normalize_loaded_data(d: &mut Data, clock: &HlcClock) {
    if d.epoch.is_empty() {
        d.epoch = new_id();
    }
    let had_rev = d.local_rev > 0;
    let mut max_ver = (0u64, 0u64);
    let mut bump = |m: &mut SyncMeta| {
        if m.is_unset() {
            m.updated_ms = 1;
            m.node = "legacy".into();
        }
        if (m.updated_ms, m.seq) > max_ver {
            max_ver = (m.updated_ms, m.seq);
        }
        if m.local_rev == 0 {
            if !had_rev {
                d.local_rev = d.local_rev.saturating_add(1);
            }
            m.local_rev = d.local_rev;
        } else if m.local_rev > d.local_rev {
            d.local_rev = m.local_rev;
        }
    };
    for z in &mut d.zones {
        bump(&mut z.sync);
    }
    for r in &mut d.records {
        bump(&mut r.sync);
    }
    for w in &mut d.workers {
        bump(&mut w.sync);
    }
    for n in &mut d.nodes {
        bump(&mut n.sync);
    }
    for s in &mut d.steering {
        bump(&mut s.sync);
    }
    for r in &mut d.local_proxy_rules {
        bump(&mut r.sync);
    }
    for p in &mut d.purges {
        bump(&mut p.sync);
    }
    for c in &mut d.acme_challenges {
        bump(&mut c.sync);
    }
    for l in &mut d.ip_lists {
        bump(&mut l.sync);
    }
    for t in d.node_telemetry.values_mut() {
        bump(&mut t.sync);
    }
    for c in &mut d.alert_channels {
        bump(&mut c.sync);
    }
    for w in &mut d.challenge_widgets {
        bump(&mut w.sync);
    }
    if let Some(l) = &mut d.acme_lease {
        bump(&mut l.sync);
    }
    macro_rules! bump_items {
        ($($field:ident),* $(,)?) => {
            $(for x in &mut d.$field { bump(&mut x.meta.sync); })*
        };
    }
    bump_items!(
        firewall_rules,
        rate_limits,
        origin_rules,
        certificates,
        certificate_packs,
        spectrum_apps,
        worker_routes,
        redirect_rules,
        transform_rules,
        cache_rules,
        email_rules,
        log_jobs,
        waiting_rooms,
    );
    macro_rules! bump_tombs {
        ($($field:ident),* $(,)?) => {
            $(for m in d.tombstones.$field.values_mut() {
                m.deleted = true;
                bump(m);
            })*
        };
    }
    bump_tombs!(
        zones,
        records,
        firewall_rules,
        rate_limits,
        origin_rules,
        certificates,
        certificate_packs,
        spectrum_apps,
        workers,
        worker_routes,
        redirect_rules,
        transform_rules,
        cache_rules,
        email_rules,
        log_jobs,
        waiting_rooms,
        nodes,
        steering,
        local_proxy_rules,
        purges,
        acme_challenges,
        node_telemetry,
        ip_lists,
        alert_channels,
        challenge_widgets,
    );
    sync_telemetry_projections(d);
    clock.advance_floor(max_ver.0, max_ver.1);
}

fn gc_tombstones(d: &mut Data, now_ms: u64, durable_ttl_ms: u64, ephemeral_ttl_ms: u64) {
    let mut prune = |map: &mut BTreeMap<String, SyncMeta>, ttl: u64| {
        map.retain(|_, m| {
            let keep = now_ms.saturating_sub(m.updated_ms) <= ttl;
            if !keep {
                d.gc_floor_rev = d.gc_floor_rev.max(m.local_rev);
            }
            keep
        });
    };
    prune(&mut d.tombstones.zones, durable_ttl_ms);
    prune(&mut d.tombstones.records, durable_ttl_ms);
    prune(&mut d.tombstones.firewall_rules, durable_ttl_ms);
    prune(&mut d.tombstones.rate_limits, durable_ttl_ms);
    prune(&mut d.tombstones.origin_rules, durable_ttl_ms);
    prune(&mut d.tombstones.certificates, durable_ttl_ms);
    prune(&mut d.tombstones.certificate_packs, durable_ttl_ms);
    prune(&mut d.tombstones.spectrum_apps, durable_ttl_ms);
    prune(&mut d.tombstones.workers, durable_ttl_ms);
    prune(&mut d.tombstones.worker_routes, durable_ttl_ms);
    prune(&mut d.tombstones.redirect_rules, durable_ttl_ms);
    prune(&mut d.tombstones.transform_rules, durable_ttl_ms);
    prune(&mut d.tombstones.cache_rules, durable_ttl_ms);
    prune(&mut d.tombstones.email_rules, durable_ttl_ms);
    prune(&mut d.tombstones.log_jobs, durable_ttl_ms);
    prune(&mut d.tombstones.waiting_rooms, durable_ttl_ms);
    prune(&mut d.tombstones.nodes, durable_ttl_ms);
    prune(&mut d.tombstones.steering, durable_ttl_ms);
    prune(&mut d.tombstones.local_proxy_rules, durable_ttl_ms);
    prune(&mut d.tombstones.node_telemetry, durable_ttl_ms);
    prune(&mut d.tombstones.ip_lists, durable_ttl_ms);
    prune(&mut d.tombstones.alert_channels, durable_ttl_ms);
    prune(&mut d.tombstones.challenge_widgets, durable_ttl_ms);
    prune(&mut d.tombstones.purges, ephemeral_ttl_ms);
    prune(&mut d.tombstones.acme_challenges, ephemeral_ttl_ms);
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct ConfigDeltaPayload {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    zones: Vec<Zone>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<Record>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    firewall_rules: Vec<FirewallRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rate_limits: Vec<RateLimit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    origin_rules: Vec<OriginRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    certificates: Vec<Certificate>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    certificate_packs: Vec<CertificatePack>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spectrum_apps: Vec<SpectrumApp>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    workers: Vec<WorkerScript>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    worker_routes: Vec<WorkerRoute>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redirect_rules: Vec<RedirectRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transform_rules: Vec<TransformRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cache_rules: Vec<CacheRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    email_rules: Vec<EmailRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    log_jobs: Vec<crate::edge::reqlog::LogJob>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    waiting_rooms: Vec<crate::edge::waiting::WaitingRoom>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nodes: Vec<EdgeNode>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    steering: Vec<SteerRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    local_proxy_rules: Vec<LocalProxyRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    purges: Vec<PurgeOp>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    acme_challenges: Vec<AcmeChallenge>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_lists: Vec<IpList>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    node_telemetry: BTreeMap<String, NodeTelemetry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acme_lease: Option<AcmeLease>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    alert_channels: Vec<crate::alerts::AlertChannel>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    challenge_widgets: Vec<crate::edge::widget::ChallengeWidget>,
    tombstones: Tombstones,
}

impl Store {
    pub fn open(path: &Path, default_ns: Vec<String>) -> anyhow::Result<Self> {
        let clock = Arc::new(HlcClock::default());
        let mut data: Data = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("corrupt state file {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e.into()),
        };
        normalize_loaded_data(&mut data, &clock);
        let snap = RwLock::new(Arc::new(Snapshot::build(&data)));
        let changed = tokio::sync::watch::channel(()).0;
        let version = RwLock::new(fingerprint(&data));
        let sync_node_id = crate::sync::resolve_sync_node_id(path.parent(), "local");
        Ok(Store {
            path: Some(path.to_path_buf()),
            default_ns,
            data: Mutex::new(data),
            write_gate: tokio::sync::Mutex::new(()),
            sync_lock: Mutex::new(()),
            snap,
            changed,
            read_only: AtomicBool::new(false),
            version,
            clock,
            sync_node_id: RwLock::new(sync_node_id),
        })
    }

    /// Open a purely in-memory ephemeral store (`--role accelerate`). Never
    /// reads or writes `state.json`.
    pub fn open_ephemeral(default_ns: Vec<String>) -> Self {
        let clock = Arc::new(HlcClock::default());
        let mut data = Data::default();
        normalize_loaded_data(&mut data, &clock);
        let snap = RwLock::new(Arc::new(Snapshot::build(&data)));
        let changed = tokio::sync::watch::channel(()).0;
        let version = RwLock::new(fingerprint(&data));
        let sync_node_id = crate::sync::resolve_sync_node_id(None, "local");
        Store {
            path: None,
            default_ns,
            data: Mutex::new(data),
            write_gate: tokio::sync::Mutex::new(()),
            sync_lock: Mutex::new(()),
            snap,
            changed,
            read_only: AtomicBool::new(true),
            version,
            clock,
            sync_node_id: RwLock::new(sync_node_id),
        }
    }

    pub fn clock(&self) -> Arc<HlcClock> {
        self.clock.clone()
    }

    pub fn sync_node_id(&self) -> String {
        self.sync_node_id.read().unwrap().clone()
    }

    pub fn set_sync_node_id(&self, id: String) {
        *self.sync_node_id.write().unwrap() = id;
    }

    pub fn current_rev(&self) -> u64 {
        self.data.lock().unwrap().local_rev
    }

    pub fn epoch(&self) -> String {
        self.data.lock().unwrap().epoch.clone()
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.read().unwrap().clone()
    }

    /// Notified after every successful mutation.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.changed.subscribe()
    }

    /// Synchronous mutation for unit tests and non-async contexts. Never holds
    /// `data: Mutex<Data>` during `Snapshot::build`, `fingerprint`, or disk I/O.
    fn mutate<T>(&self, f: impl FnOnce(&mut Data, &HlcClock, &str) -> Result<T, StoreError>) -> Result<T, StoreError> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err(StoreError::ReadOnly);
        }
        let _sync = self.sync_lock.lock().unwrap();
        let mut candidate = self.data.lock().unwrap().clone();
        let node = self.sync_node_id();
        let out = f(&mut candidate, &self.clock, &node)?;
        gc_tombstones(&mut candidate, unix_ms(), DURABLE_TOMBSTONE_TTL_MS, EPHEMERAL_TOMBSTONE_TTL_MS);
        let snap = Snapshot::build(&candidate);
        let ver = fingerprint(&candidate);
        persist_to(self.path.as_deref(), &candidate)?;
        *self.data.lock().unwrap() = candidate;
        *self.snap.write().unwrap() = Arc::new(snap);
        *self.version.write().unwrap() = ver;
        self.changed.send_replace(());
        Ok(out)
    }

    /// Non-blocking async mutation: clones under short lock, executes CPU &
    /// disk persistence inside `tokio::task::spawn_blocking`, then swaps
    /// in-memory state under short locks.
    async fn mutate_async<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Data, &HlcClock, &str) -> Result<T, StoreError> + Send + 'static,
    {
        if self.read_only.load(Ordering::Relaxed) {
            return Err(StoreError::ReadOnly);
        }
        let _gate = self.write_gate.lock().await;
        let mut candidate = self.data.lock().unwrap().clone();
        let path = self.path.clone();
        let clock = self.clock.clone();
        let node = self.sync_node_id();
        let (candidate, snap, ver, out) = tokio::task::spawn_blocking(move || {
            let out = f(&mut candidate, &clock, &node)?;
            gc_tombstones(&mut candidate, unix_ms(), DURABLE_TOMBSTONE_TTL_MS, EPHEMERAL_TOMBSTONE_TTL_MS);
            let snap = Snapshot::build(&candidate);
            let ver = fingerprint(&candidate);
            persist_to(path.as_deref(), &candidate)?;
            Ok::<_, StoreError>((candidate, snap, ver, out))
        })
        .await
        .map_err(|e| StoreError::Io(e.to_string()))??;
        *self.data.lock().unwrap() = candidate;
        *self.snap.write().unwrap() = Arc::new(snap);
        *self.version.write().unwrap() = ver;
        self.changed.send_replace(());
        Ok(out)
    }

    // ---- replication ----

    #[allow(dead_code)]
    pub fn set_read_only(&self, ro: bool) {
        self.read_only.store(ro, Ordering::Relaxed);
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn is_replica(&self) -> bool {
        self.is_read_only()
    }

    pub fn version(&self) -> String {
        self.version.read().unwrap().clone()
    }

    /// The whole configuration, for legacy `/replication/state` callers.
    pub fn export(&self) -> serde_json::Value {
        let cloned = self.data.lock().unwrap().clone();
        serde_json::to_value(&cloned).unwrap_or_default()
    }

    #[allow(dead_code)]
    pub async fn export_async(&self) -> serde_json::Value {
        let cloned = self.data.lock().unwrap().clone();
        tokio::task::spawn_blocking(move || serde_json::to_value(&cloned).unwrap_or_default())
            .await
            .unwrap_or_default()
    }

    /// Adopt a configuration exported by a legacy `/replication/state` endpoint.
    #[allow(dead_code)]
    pub fn replace(&self, exported: serde_json::Value, version: &str) -> Result<(), StoreError> {
        let mut new: Data = serde_json::from_value(exported).map_err(|e| StoreError::Invalid(e.to_string()))?;
        normalize_loaded_data(&mut new, &self.clock);
        let snap = Snapshot::build(&new);
        persist_to(self.path.as_deref(), &new)?;
        *self.data.lock().unwrap() = new;
        *self.snap.write().unwrap() = Arc::new(snap);
        *self.version.write().unwrap() = version.to_string();
        self.changed.send_replace(());
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn replace_async(&self, exported: serde_json::Value, version: &str) -> Result<(), StoreError> {
        let _gate = self.write_gate.lock().await;
        let path = self.path.clone();
        let clock = self.clock.clone();
        let ver = version.to_string();
        let (new, snap) = tokio::task::spawn_blocking(move || {
            let mut new: Data = serde_json::from_value(exported).map_err(|e| StoreError::Invalid(e.to_string()))?;
            normalize_loaded_data(&mut new, &clock);
            let snap = Snapshot::build(&new);
            persist_to(path.as_deref(), &new)?;
            Ok::<_, StoreError>((new, snap))
        })
        .await
        .map_err(|e| StoreError::Io(e.to_string()))??;
        *self.data.lock().unwrap() = new;
        *self.snap.write().unwrap() = Arc::new(snap);
        *self.version.write().unwrap() = ver;
        self.changed.send_replace(());
        Ok(())
    }

    pub async fn export_since_async(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
        let d = self.data.lock().unwrap().clone();
        let peer_epoch = peer_epoch.map(str::to_string);
        tokio::task::spawn_blocking(move || export_since_data(&d, since_rev, peer_epoch.as_deref()))
            .await
            .map_err(|e| e.to_string())?
    }

    pub async fn merge_delta_async(&self, delta: &DomainDelta) -> Result<bool, StoreError> {
        let _gate = self.write_gate.lock().await;
        let mut candidate = self.data.lock().unwrap().clone();
        let path = self.path.clone();
        let clock = self.clock.clone();
        let node = self.sync_node_id();
        let delta = delta.clone();
        let accel = self.read_only.load(Ordering::Relaxed);
        let (candidate, snap, ver, changed) = tokio::task::spawn_blocking(move || {
            let changed = merge_delta_data(&mut candidate, &delta, &clock, &node, accel)
                .map_err(StoreError::Invalid)?;
            if !changed {
                return Ok::<_, StoreError>((candidate, None, None, false));
            }
            gc_tombstones(&mut candidate, unix_ms(), DURABLE_TOMBSTONE_TTL_MS, EPHEMERAL_TOMBSTONE_TTL_MS);
            let snap = Snapshot::build(&candidate);
            let ver = fingerprint(&candidate);
            persist_to(path.as_deref(), &candidate)?;
            Ok((candidate, Some(snap), Some(ver), true))
        })
        .await
        .map_err(|e| StoreError::Io(e.to_string()))??;
        if changed {
            *self.data.lock().unwrap() = candidate;
            if let Some(snap) = snap {
                *self.snap.write().unwrap() = Arc::new(snap);
            }
            if let Some(ver) = ver {
                *self.version.write().unwrap() = ver;
            }
            self.changed.send_replace(());
        }
        Ok(changed)
    }

    pub fn acme_lease(&self) -> Option<AcmeLease> {
        self.data.lock().unwrap().acme_lease.clone()
    }

    pub async fn set_acme_lease_async(&self, lease: AcmeLease) -> Result<(), StoreError> {
        self.mutate_async(move |d, clock, node| {
            let mut l = lease;
            l.sync = stamp_next(d, clock, node, false);
            d.acme_lease = Some(l);
            Ok(())
        })
        .await
    }

    /// Record this node's own traffic-limit & GFW telemetry when changed.
    pub async fn set_self_telemetry_async(
        &self,
        node_name: String,
        limit_state: crate::limits::State,
        offload_pct: u8,
        gfw: Option<crate::gfw::GfwStatus>,
    ) -> Result<bool, StoreError> {
        let gfw = gfw.filter(|g| !g.is_empty());
        let unchanged = {
            let d = self.data.lock().unwrap();
            d.node_telemetry.get(&node_name).is_some_and(|t| {
                t.limit_state == limit_state && t.offload_pct == offload_pct && t.gfw == gfw
            })
        };
        if unchanged {
            return Ok(false);
        }
        self.mutate_async(move |d, clock, sync_node| {
            let sync = stamp_next(d, clock, sync_node, false);
            d.tombstones.node_telemetry.remove(&node_name);
            d.node_telemetry.insert(
                node_name.clone(),
                NodeTelemetry { node: node_name, limit_state, offload_pct, gfw, sync },
            );
            sync_telemetry_projections(d);
            Ok(true)
        })
        .await
    }

    /// Record another node's telemetry (received from an `accelerate` node over sync/report).
    pub async fn record_peer_telemetry_async(
        &self,
        node_name: String,
        limit_state: crate::limits::State,
        offload_pct: u8,
        gfw: Option<crate::gfw::GfwStatus>,
    ) -> Result<(), StoreError> {
        let gfw = gfw.filter(|g| !g.is_empty());
        let unchanged = {
            let d = self.data.lock().unwrap();
            d.node_telemetry.get(&node_name).is_some_and(|t| {
                t.limit_state == limit_state && t.offload_pct == offload_pct && t.gfw == gfw
            })
        };
        if unchanged || self.read_only.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.mutate_async(move |d, clock, sync_node| {
            let sync = stamp_next(d, clock, sync_node, false);
            d.tombstones.node_telemetry.remove(&node_name);
            d.node_telemetry.insert(
                node_name.clone(),
                NodeTelemetry { node: node_name, limit_state, offload_pct, gfw, sync },
            );
            sync_telemetry_projections(d);
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    pub fn force_tombstone_gc_for_test(&self, age_ms: u64) {
        let mut d = self.data.lock().unwrap();
        let cutoff = unix_ms().saturating_add(age_ms);
        gc_tombstones(&mut d, cutoff, DURABLE_TOMBSTONE_TTL_MS, EPHEMERAL_TOMBSTONE_TTL_MS);
    }

    // ---- edge nodes ----

    pub fn list_nodes(&self) -> Vec<EdgeNode> {
        self.data.lock().unwrap().nodes.clone()
    }

    /// Create (`id` = None) or update a node from a JSON object (updates merge).
    pub fn save_node(&self, id: Option<&str>, body: serde_json::Value) -> Result<EdgeNode, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate(move |d, clock, sync_node| apply_save_node(d, clock, sync_node, id_owned.as_deref(), body))
    }

    pub async fn save_node_async(&self, id: Option<&str>, body: serde_json::Value) -> Result<EdgeNode, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate_async(move |d, clock, sync_node| apply_save_node(d, clock, sync_node, id_owned.as_deref(), body))
            .await
    }

    pub fn delete_node(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate(move |d, clock, sync_node| apply_delete_node(d, clock, sync_node, &id_owned))
    }

    pub async fn delete_node_async(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_node(d, clock, sync_node, &id_owned))
            .await
    }

    pub fn limited_nodes(&self) -> BTreeMap<String, crate::limits::State> {
        self.data.lock().unwrap().limited_nodes.clone()
    }

    #[allow(dead_code)]
    pub fn limited_offload(&self) -> BTreeMap<String, u8> {
        self.data.lock().unwrap().limited_offload.clone()
    }

    #[allow(dead_code)]
    pub fn gfw_status(&self) -> BTreeMap<String, crate::gfw::GfwStatus> {
        self.data.lock().unwrap().gfw_status.clone()
    }

    /// Record per-node mainland-China reachability status.
    pub fn set_gfw_status(&self, gfw: BTreeMap<String, crate::gfw::GfwStatus>) -> Result<(), StoreError> {
        self.mutate(move |d, clock, sync_node| {
            apply_set_gfw_status(d, clock, sync_node, gfw);
            Ok(())
        })
    }

    /// Record which nodes are over a threshold of their traffic allowance.
    #[cfg(test)]
    pub fn set_limited_nodes(&self, limited: BTreeMap<String, crate::limits::State>) -> Result<(), StoreError> {
        self.mutate(move |d, clock, sync_node| {
            let offload = d.limited_offload.clone();
            apply_set_limited_state(d, clock, sync_node, limited, offload);
            Ok(())
        })
    }

    /// Record both traffic-limit states and DNS offload probabilities atomically.
    pub fn set_limited_state(
        &self,
        limited: BTreeMap<String, crate::limits::State>,
        offload: BTreeMap<String, u8>,
    ) -> Result<(), StoreError> {
        self.mutate(move |d, clock, sync_node| {
            apply_set_limited_state(d, clock, sync_node, limited, offload);
            Ok(())
        })
    }

    // ---- steering rules ----

    pub fn list_steering(&self) -> Vec<SteerRule> {
        self.data.lock().unwrap().steering.clone()
    }

    pub fn save_steering(&self, id: Option<&str>, body: serde_json::Value) -> Result<SteerRule, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate(move |d, clock, sync_node| apply_save_steering(d, clock, sync_node, id_owned.as_deref(), body))
    }

    pub async fn save_steering_async(&self, id: Option<&str>, body: serde_json::Value) -> Result<SteerRule, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate_async(move |d, clock, sync_node| apply_save_steering(d, clock, sync_node, id_owned.as_deref(), body))
            .await
    }

    pub fn delete_steering(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate(move |d, clock, sync_node| apply_delete_steering(d, clock, sync_node, &id_owned))
    }

    pub async fn delete_steering_async(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_steering(d, clock, sync_node, &id_owned))
            .await
    }

    // ---- IP lists (crate::lists) ----

    /// Look at the configuration as it is, without copying all of it. `f`
    /// runs under the store's lock, so it must be quick and must not wait.
    pub fn inspect<T>(&self, f: impl FnOnce(&Data) -> T) -> T {
        f(&self.data.lock().unwrap())
    }

    /// Add, change or remove one IP list in one write. `change` sees the
    /// whole configuration (other lists' names, the rules that use the list)
    /// and the list `id` names as it is now (`None` when adding); it answers
    /// the list as it should be, or `None` to remove it. Ids, timestamps
    /// and the checks belong to crate::lists; replication belongs here.
    pub async fn change_ip_list_async<F>(&self, id: Option<String>, change: F) -> Result<Option<IpList>, StoreError>
    where
        F: FnOnce(&Data, Option<&IpList>) -> Result<Option<IpList>, StoreError> + Send + 'static,
    {
        self.mutate_async(move |d, clock, sync_node| {
            let current = match &id {
                Some(id) => Some(d.ip_lists.iter().find(|l| &l.id == id).cloned().ok_or(StoreError::NotFound)?),
                None => None,
            };
            match (change(d, current.as_ref())?, current) {
                (Some(mut list), current) => {
                    if let Some(c) = current {
                        list.id = c.id;
                    }
                    list.sync = stamp_next(d, clock, sync_node, false);
                    d.tombstones.ip_lists.remove(&list.id);
                    upsert(&mut d.ip_lists, list.clone(), |l| &l.id);
                    Ok(Some(list))
                }
                (None, Some(old)) => {
                    d.ip_lists.retain(|l| l.id != old.id);
                    let tomb = stamp_next(d, clock, sync_node, true);
                    d.tombstones.ip_lists.insert(old.id, tomb);
                    Ok(None)
                }
                (None, None) => Ok(None),
            }
        })
        .await
    }

    // ---- alert channels (see crate::alerts) ----

    pub fn list_alert_channels(&self) -> Vec<crate::alerts::AlertChannel> {
        self.data.lock().unwrap().alert_channels.clone()
    }

    pub fn get_alert_channel(&self, id: &str) -> Option<crate::alerts::AlertChannel> {
        self.data.lock().unwrap().alert_channels.iter().find(|c| c.id == id).cloned()
    }

    pub async fn save_alert_channel_async(&self, id: Option<&str>, body: serde_json::Value) -> Result<crate::alerts::AlertChannel, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate_async(move |d, clock, sync_node| apply_save_alert_channel(d, clock, sync_node, id_owned.as_deref(), body)).await
    }

    pub async fn delete_alert_channel_async(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_alert_channel(d, clock, sync_node, &id_owned)).await
    }

    // ---- challenge widgets (see crate::edge::widget) ----

    pub fn list_challenge_widgets(&self) -> Vec<crate::edge::widget::ChallengeWidget> {
        self.data.lock().unwrap().challenge_widgets.clone()
    }

    pub fn get_challenge_widget(&self, id: &str) -> Option<crate::edge::widget::ChallengeWidget> {
        self.data.lock().unwrap().challenge_widgets.iter().find(|w| w.id == id).cloned()
    }

    /// Create (`id` none) or change a widget. `secret_sha256`: the digest of
    /// a new secret, for a creation or a rotation; otherwise the stored one stays.
    pub async fn save_challenge_widget_async(
        &self,
        id: Option<&str>,
        body: serde_json::Value,
        secret_sha256: Option<String>,
    ) -> Result<crate::edge::widget::ChallengeWidget, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate_async(move |d, clock, sync_node| apply_save_challenge_widget(d, clock, sync_node, id_owned.as_deref(), body, secret_sha256)).await
    }

    pub async fn delete_challenge_widget_async(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_challenge_widget(d, clock, sync_node, &id_owned)).await
    }

    // ---- local proxy rules ----

    pub fn list_proxy_rules(&self) -> Vec<LocalProxyRule> {
        self.data.lock().unwrap().local_proxy_rules.clone()
    }

    pub fn get_proxy_rule(&self, id: &str) -> Option<LocalProxyRule> {
        self.data.lock().unwrap().local_proxy_rules.iter().find(|r| r.id == id).cloned()
    }

    #[allow(dead_code)]
    pub fn save_proxy_rule(&self, id: Option<&str>, body: serde_json::Value) -> Result<LocalProxyRule, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate(move |d, clock, sync_node| apply_save_proxy_rule(d, clock, sync_node, id_owned.as_deref(), body))
    }

    pub async fn save_proxy_rule_async(&self, id: Option<&str>, body: serde_json::Value) -> Result<LocalProxyRule, StoreError> {
        let id_owned = id.map(str::to_string);
        self.mutate_async(move |d, clock, sync_node| apply_save_proxy_rule(d, clock, sync_node, id_owned.as_deref(), body))
            .await
    }

    pub async fn delete_proxy_rule_async(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_proxy_rule(d, clock, sync_node, &id_owned))
            .await
    }

    /// Record a cache purge so that every node applies it.
    #[allow(dead_code)]
    pub fn add_purge(&self, zone_id: &str, everything: bool, files: Vec<String>, prefixes: Vec<String>) -> Result<String, StoreError> {
        let z = zone_id.to_string();
        self.mutate(move |d, clock, sync_node| apply_add_purge(d, clock, sync_node, &z, everything, files, prefixes, Vec::new()))
    }

    pub async fn add_purge_async(&self, zone_id: &str, everything: bool, files: Vec<String>, prefixes: Vec<String>, tags: Vec<String>) -> Result<String, StoreError> {
        let z = zone_id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_add_purge(d, clock, sync_node, &z, everything, files, prefixes, tags))
            .await
    }

    // ---- managed certificates ----

    /// The certificate packs of every zone.
    pub fn all_packs(&self) -> Vec<CertificatePack> {
        self.data.lock().unwrap().certificate_packs.clone()
    }

    pub fn update_pack(&self, id: &str, change: impl FnOnce(&mut CertificatePack)) -> Result<CertificatePack, StoreError> {
        self.mutate(move |d, clock, sync_node| {
            let idx = d.certificate_packs.iter().position(|p| p.meta.id == id).ok_or(StoreError::NotFound)?;
            change(&mut d.certificate_packs[idx]);
            let meta = stamp_next(d, clock, sync_node, false);
            d.certificate_packs[idx].meta.modified_on = now();
            d.certificate_packs[idx].meta.sync = meta;
            Ok(d.certificate_packs[idx].clone())
        })
    }

    pub async fn update_pack_async<F>(&self, id: &str, change: F) -> Result<CertificatePack, StoreError>
    where
        F: FnOnce(&mut CertificatePack) + Send + 'static,
    {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| {
            let idx = d.certificate_packs.iter().position(|p| p.meta.id == id_owned).ok_or(StoreError::NotFound)?;
            change(&mut d.certificate_packs[idx]);
            let meta = stamp_next(d, clock, sync_node, false);
            d.certificate_packs[idx].meta.modified_on = now();
            d.certificate_packs[idx].meta.sync = meta;
            Ok(d.certificate_packs[idx].clone())
        })
        .await
    }

    pub fn pending_challenges(&self) -> usize {
        self.data.lock().unwrap().acme_challenges.len()
    }

    /// Publish the ACME challenges of one pack, replacing its earlier ones
    /// (`None`: drop the challenges of every pack).
    pub fn set_challenges(&self, pack_id: Option<&str>, challenges: Vec<AcmeChallenge>) -> Result<(), StoreError> {
        let pack_owned = pack_id.map(str::to_string);
        self.mutate(move |d, clock, sync_node| {
            apply_set_challenges(d, clock, sync_node, pack_owned.as_deref(), challenges);
            Ok(())
        })
    }

    pub async fn set_challenges_async(&self, pack_id: Option<&str>, challenges: Vec<AcmeChallenge>) -> Result<(), StoreError> {
        let pack_owned = pack_id.map(str::to_string);
        self.mutate_async(move |d, clock, sync_node| {
            apply_set_challenges(d, clock, sync_node, pack_owned.as_deref(), challenges);
            Ok(())
        })
        .await
    }

    // ---- generic zone-scoped items ----

    pub fn items<T: Item>(&self, zone_id: &str) -> Result<Vec<T>, StoreError> {
        let data = self.data.lock().unwrap();
        if !data.zones.iter().any(|z| z.id == zone_id) {
            return Err(StoreError::ZoneNotFound);
        }
        Ok(T::vec(&data).iter().filter(|i| i.meta().zone_id == zone_id).cloned().collect())
    }

    /// Every zone's items of one kind, for work that runs across zones
    /// (the push loop of the request log).
    pub fn all_items<T: Item>(&self) -> Vec<T> {
        T::vec(&self.data.lock().unwrap()).clone()
    }

    pub fn item<T: Item>(&self, zone_id: &str, id: &str) -> Result<T, StoreError> {
        self.items::<T>(zone_id)?.into_iter().find(|i| i.meta().id == id).ok_or(StoreError::NotFound)
    }

    /// Create (`id` = None) or update an item from a JSON object. Updates
    /// overlay `body` on the existing item unless `replace` is set.
    pub fn save_item<T: Item>(
        &self,
        zone_id: &str,
        id: Option<&str>,
        body: serde_json::Value,
        replace: bool,
    ) -> Result<T, StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.map(str::to_string));
        self.mutate(move |d, clock, sync_node| apply_save_item::<T>(d, clock, sync_node, &z, id_owned.as_deref(), body, replace))
    }

    pub async fn save_item_async<T: Item>(
        &self,
        zone_id: &str,
        id: Option<&str>,
        body: serde_json::Value,
        replace: bool,
    ) -> Result<T, StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.map(str::to_string));
        self.mutate_async(move |d, clock, sync_node| apply_save_item::<T>(d, clock, sync_node, &z, id_owned.as_deref(), body, replace))
            .await
    }

    pub fn delete_item<T: Item>(&self, zone_id: &str, id: &str) -> Result<(), StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.to_string());
        self.mutate(move |d, clock, sync_node| apply_delete_item::<T>(d, clock, sync_node, &z, &id_owned))
    }

    pub async fn delete_item_async<T: Item>(&self, zone_id: &str, id: &str) -> Result<(), StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.to_string());
        self.mutate_async(move |d, clock, sync_node| apply_delete_item::<T>(d, clock, sync_node, &z, &id_owned))
            .await
    }

    /// Save and delete several items of one kind as one change: `plan` sees
    /// the zone's items as they are at that moment and says what to do, and
    /// either every step lands or, if one fails, none does. The Rulesets API
    /// (crate::rulesets) replaces a whole phase this way, so a bad rule in
    /// the middle of a list never leaves the phase half rewritten.
    pub async fn batch_items_async<T, F>(&self, zone_id: &str, plan: F) -> Result<(), StoreError>
    where
        T: Item,
        F: FnOnce(Vec<T>) -> Result<Vec<ItemOp>, StoreError> + Send + 'static,
    {
        let z = zone_id.to_string();
        self.mutate_async(move |d, clock, sync_node| {
            if !d.zones.iter().any(|zone| zone.id == z) {
                return Err(StoreError::ZoneNotFound);
            }
            let current: Vec<T> = T::vec(d).iter().filter(|i| i.meta().zone_id == z).cloned().collect();
            for op in plan(current)? {
                match op {
                    ItemOp::Save { id, body, replace, at } => {
                        apply_save_item::<T>(d, clock, sync_node, &z, id.as_deref(), body, replace).map_err(|e| match e {
                            StoreError::Invalid(m) if !at.is_empty() => StoreError::Invalid(format!("{at}: {m}")),
                            other => other,
                        })?;
                    }
                    ItemOp::Delete(id) => apply_delete_item::<T>(d, clock, sync_node, &z, &id)?,
                }
            }
            Ok(())
        })
        .await
    }

    // ---- zone settings ----

    /// Set one setting. Accepts Cloudflare-style `"on"`/`"off"` for booleans.
    pub fn update_setting(&self, zone_id: &str, name: &str, value: serde_json::Value) -> Result<Zone, StoreError> {
        let (z, n) = (zone_id.to_string(), name.to_string());
        self.mutate(move |d, clock, sync_node| apply_update_setting(d, clock, sync_node, &z, &n, value))
    }

    pub async fn update_setting_async(&self, zone_id: &str, name: &str, value: serde_json::Value) -> Result<Zone, StoreError> {
        let (z, n) = (zone_id.to_string(), name.to_string());
        self.mutate_async(move |d, clock, sync_node| apply_update_setting(d, clock, sync_node, &z, &n, value))
            .await
    }

    // ---- worker scripts ----

    pub fn list_workers(&self) -> Vec<WorkerScript> {
        self.data.lock().unwrap().workers.clone()
    }

    pub fn get_worker(&self, name: &str) -> Result<WorkerScript, StoreError> {
        self.list_workers().into_iter().find(|w| w.name == name).ok_or(StoreError::NotFound)
    }

    /// Create or update a script; `None` leaves that part unchanged.
    pub fn put_worker(
        &self,
        name: &str,
        script: Option<String>,
        vars: Option<BTreeMap<String, String>>,
    ) -> Result<WorkerScript, StoreError> {
        let name_owned = name.to_string();
        self.mutate(move |d, clock, sync_node| apply_put_worker(d, clock, sync_node, &name_owned, script, vars, None, None, None))
    }

    pub async fn put_worker_async(
        &self,
        name: &str,
        script: Option<String>,
        vars: Option<BTreeMap<String, String>>,
    ) -> Result<WorkerScript, StoreError> {
        let name_owned = name.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_put_worker(d, clock, sync_node, &name_owned, script, vars, None, None, None))
            .await
    }

    pub async fn patch_worker_bindings_async(
        &self,
        name: &str,
        vars: Option<BTreeMap<String, String>>,
        kv_bindings: Option<BTreeMap<String, String>>,
        d1_bindings: Option<BTreeMap<String, String>>,
        crons: Option<Vec<String>>,
    ) -> Result<WorkerScript, StoreError> {
        let name_owned = name.to_string();
        self.mutate_async(move |d, clock, sync_node| {
            apply_put_worker(d, clock, sync_node, &name_owned, None, vars, kv_bindings, d1_bindings, crons)
        })
        .await
    }

    pub fn delete_worker(&self, name: &str) -> Result<(), StoreError> {
        let name_owned = name.to_string();
        self.mutate(move |d, clock, sync_node| apply_delete_worker(d, clock, sync_node, &name_owned))
    }

    pub async fn delete_worker_async(&self, name: &str) -> Result<(), StoreError> {
        let name_owned = name.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_worker(d, clock, sync_node, &name_owned))
            .await
    }

    // ---- zones ----

    pub fn list_zones(&self) -> Vec<Zone> {
        self.data.lock().unwrap().zones.clone()
    }

    pub fn get_zone(&self, id: &str) -> Result<Zone, StoreError> {
        let data = self.data.lock().unwrap();
        data.zones.iter().find(|z| z.id == id).cloned().ok_or(StoreError::ZoneNotFound)
    }

    #[cfg(test)]
    pub fn create_zone(&self, name: &str) -> Result<Zone, StoreError> {
        self.create_zone_as(name, "full")
    }

    pub fn create_zone_as(&self, name: &str, kind: &str) -> Result<Zone, StoreError> {
        let (name_owned, kind_owned, ns) = (name.to_string(), kind.to_string(), self.default_ns.clone());
        self.mutate(move |d, clock, sync_node| apply_create_zone(d, clock, sync_node, &name_owned, &kind_owned, ns))
    }

    pub async fn create_zone_as_async(&self, name: &str, kind: &str) -> Result<Zone, StoreError> {
        self.create_zone_owned_async(name, kind, None, false).await
    }

    /// A zone that belongs to `owner` (crate::tenancy). `guarded`: made by
    /// somebody who is not an administrator, so it may not overlap a zone
    /// of anybody else (checked inside the write).
    pub async fn create_zone_owned_async(&self, name: &str, kind: &str, owner: Option<String>, guarded: bool) -> Result<Zone, StoreError> {
        let (name_owned, kind_owned, ns) = (name.to_string(), kind.to_string(), self.default_ns.clone());
        self.mutate_async(move |d, clock, sync_node| create_owned(d, clock, sync_node, &name_owned, &kind_owned, ns, owner, guarded))
            .await
    }

    #[cfg(test)]
    pub fn create_zone_owned(&self, name: &str, kind: &str, owner: Option<String>, guarded: bool) -> Result<Zone, StoreError> {
        let (name_owned, kind_owned, ns) = (name.to_string(), kind.to_string(), self.default_ns.clone());
        self.mutate(move |d, clock, sync_node| create_owned(d, clock, sync_node, &name_owned, &kind_owned, ns, owner, guarded))
    }

    /// Give a zone to another user, or (none) to the administrators only.
    pub async fn set_zone_owner_async(&self, id: &str, owner: Option<String>) -> Result<Zone, StoreError> {
        let id = id.to_string();
        self.mutate_async(move |d, clock, sync_node| {
            let pos = d.zones.iter().position(|z| z.id == id).ok_or(StoreError::ZoneNotFound)?;
            let sync = stamp_next(d, clock, sync_node, false);
            let z = &mut d.zones[pos];
            (z.owner, z.modified_on, z.sync) = (owner, now(), sync);
            Ok(z.clone())
        })
        .await
    }

    pub fn get_dnssec(&self, zone_id: &str) -> Result<serde_json::Value, StoreError> {
        let d = self.data.lock().unwrap();
        let z = d.zones.iter().find(|z| z.id == zone_id).ok_or(StoreError::NotFound)?;
        Ok(match &z.dnssec {
            Some(cfg) => cfg.api_view(),
            None => serde_json::json!({ "status": "disabled" }),
        })
    }

    #[allow(dead_code)]
    pub fn set_dnssec(&self, zone_id: &str, enable: bool) -> Result<serde_json::Value, StoreError> {
        let z = zone_id.to_string();
        self.mutate(move |d, clock, sync_node| apply_set_dnssec(d, clock, sync_node, &z, enable))
    }

    pub async fn set_dnssec_async(&self, zone_id: &str, enable: bool) -> Result<serde_json::Value, StoreError> {
        let z = zone_id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_set_dnssec(d, clock, sync_node, &z, enable))
            .await
    }

    /// Set or remove a zone's DKIM key (crate::dkim::patch). `update` gets
    /// the zone as it is inside the write, so that a key it keeps from
    /// before is the one stored at that moment, not one read earlier.
    pub async fn set_email_dkim_async<F>(&self, zone_id: &str, update: F) -> Result<Zone, StoreError>
    where
        F: FnOnce(&Zone) -> Result<Option<crate::dkim::DkimKey>, StoreError> + Send + 'static,
    {
        let zone_id = zone_id.to_string();
        self.mutate_async(move |d, clock, sync_node| {
            let pos = d.zones.iter().position(|z| z.id == zone_id).ok_or(StoreError::ZoneNotFound)?;
            let key = update(&d.zones[pos])?;
            let sync = stamp_next(d, clock, sync_node, false);
            let z = &mut d.zones[pos];
            (z.email_dkim, z.modified_on, z.sync) = (key, now(), sync);
            Ok(z.clone())
        })
        .await
    }

    /// Make or remove a zone's origin CA (crate::origin_ca). As with the DKIM
    /// key, `update` sees the zone inside the write, so two requests at once
    /// cannot both find it without a CA.
    pub async fn set_origin_ca_async<F>(&self, zone_id: &str, update: F) -> Result<Zone, StoreError>
    where
        F: FnOnce(&Zone) -> Result<Option<crate::origin_ca::OriginCa>, StoreError> + Send + 'static,
    {
        let zone_id = zone_id.to_string();
        self.mutate_async(move |d, clock, sync_node| {
            let pos = d.zones.iter().position(|z| z.id == zone_id).ok_or(StoreError::ZoneNotFound)?;
            let ca = update(&d.zones[pos])?;
            let sync = stamp_next(d, clock, sync_node, false);
            let z = &mut d.zones[pos];
            (z.origin_ca, z.modified_on, z.sync) = (ca, now(), sync);
            Ok(z.clone())
        })
        .await
    }

    #[allow(dead_code)]
    pub fn set_zone_kind(&self, id: &str, kind: &str) -> Result<Zone, StoreError> {
        let (id_owned, kind_owned) = (id.to_string(), kind.to_string());
        self.mutate(move |d, clock, sync_node| apply_set_zone_kind(d, clock, sync_node, &id_owned, &kind_owned))
    }

    pub async fn set_zone_kind_async(&self, id: &str, kind: &str) -> Result<Zone, StoreError> {
        let (id_owned, kind_owned) = (id.to_string(), kind.to_string());
        self.mutate_async(move |d, clock, sync_node| apply_set_zone_kind(d, clock, sync_node, &id_owned, &kind_owned))
            .await
    }

    #[allow(dead_code)]
    pub fn set_zone_paused(&self, id: &str, paused: bool) -> Result<Zone, StoreError> {
        let id_owned = id.to_string();
        self.mutate(move |d, clock, sync_node| apply_set_zone_paused(d, clock, sync_node, &id_owned, paused))
    }

    pub async fn set_zone_paused_async(&self, id: &str, paused: bool) -> Result<Zone, StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_set_zone_paused(d, clock, sync_node, &id_owned, paused))
            .await
    }

    pub fn delete_zone(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate(move |d, clock, sync_node| apply_delete_zone(d, clock, sync_node, &id_owned))
    }

    pub async fn delete_zone_async(&self, id: &str) -> Result<(), StoreError> {
        let id_owned = id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_delete_zone(d, clock, sync_node, &id_owned))
            .await
    }

    // ---- records ----

    pub fn list_records(&self, zone_id: &str) -> Result<(Zone, Vec<Record>), StoreError> {
        let data = self.data.lock().unwrap();
        let zone = data.zones.iter().find(|z| z.id == zone_id).cloned().ok_or(StoreError::ZoneNotFound)?;
        Ok((zone, data.records.iter().filter(|r| r.zone_id == zone_id).cloned().collect()))
    }

    pub fn get_record(&self, zone_id: &str, id: &str) -> Result<(Zone, Record), StoreError> {
        let (zone, records) = self.list_records(zone_id)?;
        let rec = records.into_iter().find(|r| r.id == id).ok_or(StoreError::RecordNotFound)?;
        Ok((zone, rec))
    }

    pub fn create_record(&self, zone_id: &str, input: RecordInput) -> Result<(Zone, Record), StoreError> {
        let z = zone_id.to_string();
        self.mutate(move |d, clock, sync_node| apply_create_record(d, clock, sync_node, &z, input))
    }

    pub async fn create_record_async(&self, zone_id: &str, input: RecordInput) -> Result<(Zone, Record), StoreError> {
        let z = zone_id.to_string();
        self.mutate_async(move |d, clock, sync_node| apply_create_record(d, clock, sync_node, &z, input))
            .await
    }

    pub fn update_record(&self, zone_id: &str, id: &str, input: RecordInput) -> Result<(Zone, Record), StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.to_string());
        self.mutate(move |d, clock, sync_node| apply_update_record(d, clock, sync_node, &z, &id_owned, input))
    }

    pub async fn update_record_async(&self, zone_id: &str, id: &str, input: RecordInput) -> Result<(Zone, Record), StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.to_string());
        self.mutate_async(move |d, clock, sync_node| apply_update_record(d, clock, sync_node, &z, &id_owned, input))
            .await
    }

    pub fn delete_record(&self, zone_id: &str, id: &str) -> Result<(), StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.to_string());
        self.mutate(move |d, clock, sync_node| apply_delete_record(d, clock, sync_node, &z, &id_owned))
    }

    pub async fn delete_record_async(&self, zone_id: &str, id: &str) -> Result<(), StoreError> {
        let (z, id_owned) = (zone_id.to_string(), id.to_string());
        self.mutate_async(move |d, clock, sync_node| apply_delete_record(d, clock, sync_node, &z, &id_owned))
            .await
    }
}

impl SyncProvider for Store {
    fn domain(&self) -> &'static str {
        "config"
    }

    fn current_rev(&self) -> u64 {
        self.data.lock().unwrap().local_rev
    }

    fn epoch(&self) -> String {
        self.data.lock().unwrap().epoch.clone()
    }

    fn export_since(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
        let d = self.data.lock().unwrap().clone();
        export_since_data(&d, since_rev, peer_epoch)
    }

    fn merge_delta(&self, delta: &DomainDelta, clock: &HlcClock) -> Result<bool, String> {
        let _sync = self.sync_lock.lock().unwrap();
        let mut candidate = self.data.lock().unwrap().clone();
        let node = self.sync_node_id();
        let accel = self.read_only.load(Ordering::Relaxed);
        let changed = merge_delta_data(&mut candidate, delta, clock, &node, accel)?;
        if !changed {
            return Ok(false);
        }
        gc_tombstones(&mut candidate, unix_ms(), DURABLE_TOMBSTONE_TTL_MS, EPHEMERAL_TOMBSTONE_TTL_MS);
        let snap = Snapshot::build(&candidate);
        let ver = fingerprint(&candidate);
        persist_to(self.path.as_deref(), &candidate).map_err(|e| format!("{e:?}"))?;
        *self.data.lock().unwrap() = candidate;
        *self.snap.write().unwrap() = Arc::new(snap);
        *self.version.write().unwrap() = ver;
        self.changed.send_replace(());
        Ok(true)
    }
}

fn apply_save_node(d: &mut Data, clock: &HlcClock, sync_node: &str, id: Option<&str>, body: serde_json::Value) -> Result<EdgeNode, StoreError> {
    let mut node: EdgeNode = merge_global(&d.nodes, id, body, |n| &n.id, |n| &n.created_on)?;
    (node.id, node.created_on, node.modified_on) = stamp(&d.nodes, id, |n| &n.id, |n| &n.created_on);
    node.validate(&d.nodes)?;
    node.sync = stamp_next(d, clock, sync_node, false);
    d.tombstones.nodes.remove(&node.id);
    upsert(&mut d.nodes, node.clone(), |n| &n.id);
    Ok(node)
}

fn apply_delete_node(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str) -> Result<(), StoreError> {
    let Some(node) = d.nodes.iter().find(|n| n.id == id) else { return Err(StoreError::NotFound) };
    if d.steering.iter().any(|r| r.nodes.contains(&node.name)) {
        return Err(StoreError::Conflict("node is still used by a steering rule".into()));
    }
    let name = node.name.clone();
    d.limited_nodes.remove(&name);
    d.limited_offload.remove(&name);
    d.gfw_status.remove(&name);
    if d.node_telemetry.remove(&name).is_some() {
        let t = stamp_next(d, clock, sync_node, true);
        d.tombstones.node_telemetry.insert(name, t);
    }
    d.nodes.retain(|n| n.id != id);
    let tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.nodes.insert(id.to_string(), tomb);
    Ok(())
}

fn apply_set_gfw_status(d: &mut Data, clock: &HlcClock, sync_node: &str, gfw: BTreeMap<String, crate::gfw::GfwStatus>) {
    d.gfw_status = gfw.clone();
    let mut names: HashSet<String> = d.node_telemetry.keys().cloned().collect();
    names.extend(gfw.keys().cloned());
    for name in names {
        let next_gfw = gfw.get(&name).cloned();
        let needs = d.node_telemetry.get(&name).is_none_or(|e| e.gfw != next_gfw);
        if needs {
            let meta = stamp_next(d, clock, sync_node, false);
            let entry = d.node_telemetry.entry(name.clone()).or_insert_with(|| NodeTelemetry {
                node: name,
                ..Default::default()
            });
            entry.gfw = next_gfw;
            entry.sync = meta;
        }
    }
}

fn apply_set_limited_state(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    limited: BTreeMap<String, crate::limits::State>,
    offload: BTreeMap<String, u8>,
) {
    d.limited_nodes = limited.clone();
    d.limited_offload = offload.clone();
    let mut names: HashSet<String> = d.node_telemetry.keys().cloned().collect();
    names.extend(limited.keys().cloned());
    names.extend(offload.keys().cloned());
    for name in names {
        let next_state = limited.get(&name).copied().unwrap_or(crate::limits::State::Ok);
        let next_off = offload.get(&name).copied().unwrap_or(0);
        let needs = d
            .node_telemetry
            .get(&name)
            .is_none_or(|e| e.limit_state != next_state || e.offload_pct != next_off);
        if needs {
            let meta = stamp_next(d, clock, sync_node, false);
            let entry = d.node_telemetry.entry(name.clone()).or_insert_with(|| NodeTelemetry {
                node: name,
                ..Default::default()
            });
            entry.limit_state = next_state;
            entry.offload_pct = next_off;
            entry.sync = meta;
        }
    }
}

fn apply_save_steering(d: &mut Data, clock: &HlcClock, sync_node: &str, id: Option<&str>, body: serde_json::Value) -> Result<SteerRule, StoreError> {
    let mut rule: SteerRule = merge_global(&d.steering, id, body, |r| &r.id, |r| &r.created_on)?;
    (rule.id, rule.created_on, rule.modified_on) = stamp(&d.steering, id, |r| &r.id, |r| &r.created_on);
    rule.validate(&d.nodes)?;
    rule.sync = stamp_next(d, clock, sync_node, false);
    d.tombstones.steering.remove(&rule.id);
    upsert(&mut d.steering, rule.clone(), |r| &r.id);
    Ok(rule)
}

fn apply_delete_steering(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str) -> Result<(), StoreError> {
    let before = d.steering.len();
    d.steering.retain(|r| r.id != id);
    if d.steering.len() == before {
        return Err(StoreError::NotFound);
    }
    let tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.steering.insert(id.to_string(), tomb);
    Ok(())
}

fn apply_save_alert_channel(d: &mut Data, clock: &HlcClock, sync_node: &str, id: Option<&str>, body: serde_json::Value) -> Result<crate::alerts::AlertChannel, StoreError> {
    if id.is_none() && d.alert_channels.len() >= crate::alerts::MAX_CHANNELS {
        return invalid(format!("at most {} alert channels", crate::alerts::MAX_CHANNELS));
    }
    let old = id.and_then(|id| d.alert_channels.iter().find(|c| c.id == id)).cloned();
    let mut channel: crate::alerts::AlertChannel = merge_global(&d.alert_channels, id, body, |c| &c.id, |c| &c.created_on)?;
    (channel.id, channel.created_on, channel.modified_on) = stamp(&d.alert_channels, id, |c| &c.id, |c| &c.created_on);
    channel.validate(old.as_ref())?;
    channel.sync = stamp_next(d, clock, sync_node, false);
    d.tombstones.alert_channels.remove(&channel.id);
    upsert(&mut d.alert_channels, channel.clone(), |c| &c.id);
    Ok(channel)
}

fn apply_delete_alert_channel(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str) -> Result<(), StoreError> {
    let before = d.alert_channels.len();
    d.alert_channels.retain(|c| c.id != id);
    if d.alert_channels.len() == before {
        return Err(StoreError::NotFound);
    }
    let tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.alert_channels.insert(id.to_string(), tomb);
    Ok(())
}

fn apply_save_challenge_widget(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    id: Option<&str>,
    body: serde_json::Value,
    secret_sha256: Option<String>,
) -> Result<crate::edge::widget::ChallengeWidget, StoreError> {
    let old = match id {
        Some(id) => Some(d.challenge_widgets.iter().find(|w| w.id == id).cloned().ok_or(StoreError::NotFound)?),
        None => None,
    };
    let mut widget = crate::edge::widget::ChallengeWidget::build(old.as_ref(), body, secret_sha256, d.challenge_widgets.len())?;
    (widget.id, widget.created_on, widget.modified_on) = stamp(&d.challenge_widgets, id, |w| &w.id, |w| &w.created_on);
    widget.sync = stamp_next(d, clock, sync_node, false);
    d.tombstones.challenge_widgets.remove(&widget.id);
    upsert(&mut d.challenge_widgets, widget.clone(), |w| &w.id);
    Ok(widget)
}

fn apply_delete_challenge_widget(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str) -> Result<(), StoreError> {
    let before = d.challenge_widgets.len();
    d.challenge_widgets.retain(|w| w.id != id);
    if d.challenge_widgets.len() == before {
        return Err(StoreError::NotFound);
    }
    let tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.challenge_widgets.insert(id.to_string(), tomb);
    Ok(())
}

fn apply_save_proxy_rule(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    id: Option<&str>,
    body: serde_json::Value,
) -> Result<LocalProxyRule, StoreError> {
    let mut rule: LocalProxyRule = merge_global(&d.local_proxy_rules, id, body, |r| &r.id, |r| &r.created_on)?;
    (rule.id, rule.created_on, rule.modified_on) = stamp(&d.local_proxy_rules, id, |r| &r.id, |r| &r.created_on);
    rule.validate()?;
    rule.sync = stamp_next(d, clock, sync_node, false);
    d.tombstones.local_proxy_rules.remove(&rule.id);
    upsert(&mut d.local_proxy_rules, rule.clone(), |r| &r.id);
    Ok(rule)
}

fn apply_delete_proxy_rule(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str) -> Result<(), StoreError> {
    let before = d.local_proxy_rules.len();
    d.local_proxy_rules.retain(|r| r.id != id);
    if d.local_proxy_rules.len() == before {
        return Err(StoreError::NotFound);
    }
    let tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.local_proxy_rules.insert(id.to_string(), tomb);
    Ok(())
}

fn apply_add_purge(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    zone_id: &str,
    everything: bool,
    files: Vec<String>,
    prefixes: Vec<String>,
    tags: Vec<String>,
) -> Result<String, StoreError> {
    let sync = stamp_next(d, clock, sync_node, false);
    let op = PurgeOp { id: new_id(), zone_id: zone_id.to_string(), everything, files, prefixes, tags, sync };
    d.purges.push(op.clone());
    let excess = d.purges.len().saturating_sub(50);
    d.purges.drain(..excess);
    Ok(op.id)
}

fn apply_set_challenges(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    pack_id: Option<&str>,
    challenges: Vec<AcmeChallenge>,
) {
    let incoming_keys: HashSet<String> = challenges.iter().map(AcmeChallenge::sync_key).collect();
    let mut removed_keys = Vec::new();
    d.acme_challenges.retain(|c| {
        let keep = pack_id.is_some_and(|id| c.pack_id != id);
        if !keep {
            let k = c.sync_key();
            if !incoming_keys.contains(&k) {
                removed_keys.push(k);
            }
        }
        keep
    });
    for key in removed_keys {
        let tomb = stamp_next(d, clock, sync_node, true);
        d.tombstones.acme_challenges.insert(key, tomb);
    }
    for mut c in challenges {
        let k = c.sync_key();
        d.tombstones.acme_challenges.remove(&k);
        c.sync = stamp_next(d, clock, sync_node, false);
        d.acme_challenges.push(c);
    }
}

fn apply_save_item<T: Item>(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    zone_id: &str,
    id: Option<&str>,
    body: serde_json::Value,
    replace: bool,
) -> Result<T, StoreError> {
    use serde_json::Value;
    let zone = d.zones.iter().find(|z| z.id == zone_id).cloned().ok_or(StoreError::ZoneNotFound)?;
    let Value::Object(body) = body else { return invalid("request body must be a JSON object") };
    let existing = match id {
        Some(id) => Some(
            T::vec(d)
                .iter()
                .find(|i| i.meta().id == id && i.meta().zone_id == zone_id)
                .cloned()
                .ok_or(StoreError::NotFound)?,
        ),
        None => None,
    };
    let mut merged = match (&existing, replace) {
        (Some(e), false) => match serde_json::to_value(e) {
            Ok(Value::Object(o)) => o,
            _ => Default::default(),
        },
        _ => Default::default(),
    };
    merged.extend(body);
    let mut item: T = serde_json::from_value(Value::Object(merged)).map_err(|e| StoreError::Invalid(e.to_string()))?;
    let ts = now();
    *item.meta_mut() = Meta {
        id: existing.as_ref().map(|e| e.meta().id.clone()).unwrap_or_else(new_id),
        zone_id: zone_id.to_string(),
        created_on: existing.as_ref().map(|e| e.meta().created_on.clone()).unwrap_or_else(|| ts.clone()),
        modified_on: ts,
        sync: SyncMeta::default(),
    };
    item.validate(&zone, d)?;
    let id = item.meta().id.clone();
    item.meta_mut().sync = stamp_next(d, clock, sync_node, false);
    T::tombstones_mut(d).remove(&id);
    let list = T::vec_mut(d);
    match list.iter_mut().find(|i| i.meta().id == id) {
        Some(slot) => *slot = item.clone(),
        None => list.push(item.clone()),
    }
    Ok(item)
}

fn apply_delete_item<T: Item>(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    zone_id: &str,
    id: &str,
) -> Result<(), StoreError> {
    if !d.zones.iter().any(|z| z.id == zone_id) {
        return Err(StoreError::ZoneNotFound);
    }
    let list = T::vec_mut(d);
    let before = list.len();
    list.retain(|i| !(i.meta().id == id && i.meta().zone_id == zone_id));
    if list.len() == before {
        return Err(StoreError::NotFound);
    }
    let tomb = stamp_next(d, clock, sync_node, true);
    T::tombstones_mut(d).insert(id.to_string(), tomb);
    Ok(())
}

fn apply_update_setting(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    zone_id: &str,
    name: &str,
    value: serde_json::Value,
) -> Result<Zone, StoreError> {
    use serde_json::Value;
    let (settings, ts) = {
        let z = d.zones.iter_mut().find(|z| z.id == zone_id).ok_or(StoreError::ZoneNotFound)?;
        let Ok(Value::Object(mut obj)) = serde_json::to_value(&z.settings) else {
            return invalid("settings unavailable");
        };
        let Some(slot) = obj.get_mut(name) else { return invalid(format!("unknown setting '{name}'")) };
        *slot = match (slot.is_boolean(), value.as_str()) {
            (true, Some("on")) => Value::Bool(true),
            (true, Some("off")) => Value::Bool(false),
            _ => value,
        };
        let settings: Settings = serde_json::from_value(Value::Object(obj))
            .map_err(|e| StoreError::Invalid(format!("invalid value for '{name}': {e}")))?;
        settings.validate()?;
        (settings, now())
    };
    let sync = stamp_next(d, clock, sync_node, false);
    let z = d.zones.iter_mut().find(|z| z.id == zone_id).ok_or(StoreError::ZoneNotFound)?;
    z.settings = settings;
    z.modified_on = ts;
    z.sync = sync;
    Ok(z.clone())
}

fn apply_put_worker(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    name: &str,
    script: Option<String>,
    vars: Option<BTreeMap<String, String>>,
    kv_bindings: Option<BTreeMap<String, String>>,
    d1_bindings: Option<BTreeMap<String, String>>,
    crons: Option<Vec<String>>,
) -> Result<WorkerScript, StoreError> {
    let valid_name = !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid_name {
        return invalid("script names may contain a-z, 0-9, '-' and '_' (max 63 characters)");
    }
    if script.as_ref().is_some_and(|s| s.len() > 1024 * 1024) {
        return invalid("script exceeds 1 MiB");
    }
    let ts = now();
    if let Some(pos) = d.workers.iter().position(|w| w.name == name) {
        let sync = stamp_next(d, clock, sync_node, false);
        d.tombstones.workers.remove(name);
        let w = &mut d.workers[pos];
        if let Some(s) = script {
            w.script = s;
        }
        if let Some(v) = vars {
            w.vars = v;
        }
        if let Some(kv) = kv_bindings {
            w.kv_bindings = kv;
        }
        if let Some(d1) = d1_bindings {
            w.d1_bindings = d1;
        }
        if let Some(c) = crons {
            w.crons = c;
        }
        w.modified_on = ts;
        w.sync = sync;
        return Ok(w.clone());
    }
    let script = script.ok_or(StoreError::NotFound)?;
    let sync = stamp_next(d, clock, sync_node, false);
    d.tombstones.workers.remove(name);
    let w = WorkerScript {
        name: name.to_string(),
        script,
        vars: vars.unwrap_or_default(),
        kv_bindings: kv_bindings.unwrap_or_default(),
        d1_bindings: d1_bindings.unwrap_or_default(),
        crons: crons.unwrap_or_default(),
        created_on: ts.clone(),
        modified_on: ts,
        sync,
    };
    d.workers.push(w.clone());
    Ok(w)
}

fn apply_delete_worker(d: &mut Data, clock: &HlcClock, sync_node: &str, name: &str) -> Result<(), StoreError> {
    if d.worker_routes.iter().any(|r| r.script.as_deref() == Some(name)) {
        return Err(StoreError::Conflict("script is still referenced by a route".into()));
    }
    let before = d.workers.len();
    d.workers.retain(|w| w.name != name);
    if d.workers.len() == before {
        return Err(StoreError::NotFound);
    }
    let tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.workers.insert(name.to_string(), tomb);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_owned(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    name: &str,
    kind: &str,
    default_ns: Vec<String>,
    owner: Option<String>,
    guarded: bool,
) -> Result<Zone, StoreError> {
    if guarded {
        let normalized = normalize_name(name).map_err(StoreError::Invalid)?;
        crate::tenancy::may_create(&d.zones, &normalized, owner.as_deref()).map_err(StoreError::Conflict)?;
    }
    let zone = apply_create_zone(d, clock, sync_node, name, kind, default_ns)?;
    let z = d.zones.iter_mut().find(|z| z.id == zone.id).ok_or(StoreError::ZoneNotFound)?;
    z.owner = owner;
    Ok(z.clone())
}

fn apply_create_zone(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    name: &str,
    kind: &str,
    default_ns: Vec<String>,
) -> Result<Zone, StoreError> {
    if !matches!(kind, "full" | "partial" | "cert") {
        return invalid("zone type must be 'full', 'partial' or 'cert'");
    }
    let name = normalize_name(name).map_err(StoreError::Invalid)?;
    if !name.contains('.') || name.contains(['*', '_']) {
        return invalid(format!("'{name}' is not a valid registrable domain"));
    }
    if d.zones.iter().any(|z| z.name == name) {
        return Err(StoreError::Conflict(format!("zone '{name}' already exists")));
    }
    let ts = now();
    let sync = stamp_next(d, clock, sync_node, false);
    let zone = Zone {
        id: new_id(),
        name,
        status: "active".into(),
        paused: false,
        name_servers: default_ns,
        serial: chrono::Utc::now().timestamp() as u32,
        kind: kind.to_string(),
        settings: Settings::default(),
        dnssec: None,
        email_dkim: None,
        origin_ca: None,
        owner: None,
        created_on: ts.clone(),
        modified_on: ts,
        sync,
    };
    d.tombstones.zones.remove(&zone.id);
    d.zones.push(zone.clone());
    Ok(zone)
}

fn apply_set_dnssec(d: &mut Data, clock: &HlcClock, sync_node: &str, zone_id: &str, enable: bool) -> Result<serde_json::Value, StoreError> {
    let Some(pos) = d.zones.iter().position(|z| z.id == zone_id) else {
        return Err(StoreError::NotFound);
    };
    if enable && d.zones[pos].dnssec.is_none() {
        let cfg = crate::dns::dnssec::DnssecConfig::generate(&d.zones[pos].name).map_err(StoreError::Invalid)?;
        d.zones[pos].dnssec = Some(cfg);
    } else if enable {
        if let Some(cfg) = &mut d.zones[pos].dnssec {
            cfg.enabled = true;
        }
    } else if let Some(cfg) = &mut d.zones[pos].dnssec {
        cfg.enabled = false;
    }
    let sync = stamp_next(d, clock, sync_node, false);
    let z = &mut d.zones[pos];
    z.serial = z.serial.wrapping_add(1);
    z.modified_on = now();
    z.sync = sync;
    Ok(match &z.dnssec {
        Some(cfg) => cfg.api_view(),
        None => serde_json::json!({ "status": "disabled" }),
    })
}

fn apply_set_zone_kind(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str, kind: &str) -> Result<Zone, StoreError> {
    if !matches!(kind, "full" | "partial" | "cert") {
        return invalid("zone type must be 'full', 'partial' or 'cert'");
    }
    if !d.zones.iter().any(|z| z.id == id) {
        return Err(StoreError::ZoneNotFound);
    }
    let sync = stamp_next(d, clock, sync_node, false);
    let z = d.zones.iter_mut().find(|z| z.id == id).ok_or(StoreError::ZoneNotFound)?;
    z.kind = kind.to_string();
    z.modified_on = now();
    z.sync = sync;
    Ok(z.clone())
}

fn apply_set_zone_paused(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str, paused: bool) -> Result<Zone, StoreError> {
    if !d.zones.iter().any(|z| z.id == id) {
        return Err(StoreError::ZoneNotFound);
    }
    let sync = stamp_next(d, clock, sync_node, false);
    let z = d.zones.iter_mut().find(|z| z.id == id).ok_or(StoreError::ZoneNotFound)?;
    z.paused = paused;
    z.modified_on = now();
    z.sync = sync;
    Ok(z.clone())
}

fn apply_delete_zone(d: &mut Data, clock: &HlcClock, sync_node: &str, id: &str) -> Result<(), StoreError> {
    let before = d.zones.len();
    d.zones.retain(|z| z.id != id);
    if d.zones.len() == before {
        return Err(StoreError::ZoneNotFound);
    }
    let z_tomb = stamp_next(d, clock, sync_node, true);
    d.tombstones.zones.insert(id.to_string(), z_tomb);

    let mut rm_rec = Vec::new();
    d.records.retain(|r| {
        if r.zone_id == id {
            rm_rec.push(r.id.clone());
            false
        } else {
            true
        }
    });
    for rid in rm_rec {
        let t = stamp_next(d, clock, sync_node, true);
        d.tombstones.records.insert(rid, t);
    }

    macro_rules! cascade_items {
        ($field:ident) => {
            let mut removed = Vec::new();
            d.$field.retain(|x| {
                if x.meta.zone_id == id {
                    removed.push(x.meta.id.clone());
                    false
                } else {
                    true
                }
            });
            for item_id in removed {
                let t = stamp_next(d, clock, sync_node, true);
                d.tombstones.$field.insert(item_id, t);
            }
        };
    }
    cascade_items!(firewall_rules);
    cascade_items!(rate_limits);
    cascade_items!(origin_rules);
    cascade_items!(certificates);
    cascade_items!(spectrum_apps);
    cascade_items!(worker_routes);
    cascade_items!(redirect_rules);
    cascade_items!(transform_rules);
    cascade_items!(cache_rules);
    cascade_items!(email_rules);
    cascade_items!(log_jobs);
    cascade_items!(waiting_rooms);
    cascade_items!(certificate_packs);

    let packs: HashSet<String> = d.certificate_packs.iter().map(|p| p.meta.id.clone()).collect();
    let mut rm_chal = Vec::new();
    d.acme_challenges.retain(|c| {
        if packs.contains(&c.pack_id) {
            true
        } else {
            rm_chal.push(c.sync_key());
            false
        }
    });
    for key in rm_chal {
        let t = stamp_next(d, clock, sync_node, true);
        d.tombstones.acme_challenges.insert(key, t);
    }
    Ok(())
}

fn apply_create_record(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    zone_id: &str,
    input: RecordInput,
) -> Result<(Zone, Record), StoreError> {
    let zone = d.zones.iter().find(|z| z.id == zone_id).cloned().ok_or(StoreError::ZoneNotFound)?;
    let input = validate(d, &zone, input, None)?;
    let z_sync = stamp_next(d, clock, sync_node, false);
    let r_sync = stamp_next(d, clock, sync_node, false);
    let zone = touch_zone(d, zone_id, z_sync)?;
    let ts = now();
    let rec = Record {
        id: new_id(),
        zone_id: zone_id.to_string(),
        name: input.name,
        rtype: input.rtype,
        content: input.content,
        ttl: input.ttl,
        priority: input.priority,
        proxied: input.proxied,
        comment: input.comment,
        origin: input.origin,
        created_on: ts.clone(),
        modified_on: ts,
        sync: r_sync,
    };
    d.tombstones.records.remove(&rec.id);
    d.records.push(rec.clone());
    Ok((zone, rec))
}

fn apply_update_record(
    d: &mut Data,
    clock: &HlcClock,
    sync_node: &str,
    zone_id: &str,
    id: &str,
    input: RecordInput,
) -> Result<(Zone, Record), StoreError> {
    let zone = d.zones.iter().find(|z| z.id == zone_id).cloned().ok_or(StoreError::ZoneNotFound)?;
    if !d.records.iter().any(|r| r.zone_id == zone_id && r.id == id) {
        return Err(StoreError::RecordNotFound);
    }
    let input = validate(d, &zone, input, Some(id))?;
    let z_sync = stamp_next(d, clock, sync_node, false);
    let r_sync = stamp_next(d, clock, sync_node, false);
    let zone = touch_zone(d, zone_id, z_sync)?;
    let rec = d
        .records
        .iter_mut()
        .find(|r| r.zone_id == zone_id && r.id == id)
        .ok_or(StoreError::RecordNotFound)?;
    rec.name = input.name;
    rec.rtype = input.rtype;
    rec.content = input.content;
    rec.ttl = input.ttl;
    rec.priority = input.priority;
    rec.proxied = input.proxied;
    rec.comment = input.comment;
    rec.origin = input.origin;
    rec.modified_on = now();
    rec.sync = r_sync;
    Ok((zone, rec.clone()))
}

fn apply_delete_record(d: &mut Data, clock: &HlcClock, sync_node: &str, zone_id: &str, id: &str) -> Result<(), StoreError> {
    if !d.zones.iter().any(|z| z.id == zone_id) {
        return Err(StoreError::ZoneNotFound);
    }
    if !d.records.iter().any(|r| r.zone_id == zone_id && r.id == id) {
        return Err(StoreError::RecordNotFound);
    }
    let z_sync = stamp_next(d, clock, sync_node, false);
    let r_tomb = stamp_next(d, clock, sync_node, true);
    touch_zone(d, zone_id, z_sync)?;
    d.records.retain(|r| !(r.zone_id == zone_id && r.id == id));
    d.tombstones.records.insert(id.to_string(), r_tomb);
    Ok(())
}

/// Bump the SOA serial of a zone that is about to change.
fn touch_zone(d: &mut Data, zone_id: &str, sync: SyncMeta) -> Result<Zone, StoreError> {
    let z = d.zones.iter_mut().find(|z| z.id == zone_id).ok_or(StoreError::ZoneNotFound)?;
    z.serial = z.serial.wrapping_add(1);
    z.modified_on = now();
    z.sync = sync;
    Ok(z.clone())
}

fn filter_tombs(map: &BTreeMap<String, SyncMeta>, since: u64) -> BTreeMap<String, SyncMeta> {
    map.iter().filter(|(_, m)| m.local_rev > since).map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn export_since_data(d: &Data, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
    let full_resync = since_rev == 0 || peer_epoch != Some(d.epoch.as_str()) || since_rev < d.gc_floor_rev;
    let since = if full_resync { 0 } else { since_rev };
    let payload = ConfigDeltaPayload {
        zones: d.zones.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        records: d.records.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        firewall_rules: d.firewall_rules.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        rate_limits: d.rate_limits.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        origin_rules: d.origin_rules.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        certificates: d.certificates.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        certificate_packs: d.certificate_packs.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        spectrum_apps: d.spectrum_apps.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        workers: d.workers.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        worker_routes: d.worker_routes.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        redirect_rules: d.redirect_rules.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        transform_rules: d.transform_rules.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        cache_rules: d.cache_rules.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        email_rules: d.email_rules.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        log_jobs: d.log_jobs.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        waiting_rooms: d.waiting_rooms.iter().filter(|x| full_resync || x.meta.sync.local_rev > since).cloned().collect(),
        nodes: d.nodes.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        steering: d.steering.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        local_proxy_rules: d.local_proxy_rules.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        purges: d.purges.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        acme_challenges: d.acme_challenges.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        ip_lists: d.ip_lists.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        node_telemetry: d
            .node_telemetry
            .iter()
            .filter(|(_, x)| full_resync || x.sync.local_rev > since)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        acme_lease: d.acme_lease.as_ref().filter(|l| full_resync || l.sync.local_rev > since).cloned(),
        alert_channels: d.alert_channels.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        challenge_widgets: d.challenge_widgets.iter().filter(|x| full_resync || x.sync.local_rev > since).cloned().collect(),
        tombstones: Tombstones {
            zones: filter_tombs(&d.tombstones.zones, since),
            records: filter_tombs(&d.tombstones.records, since),
            firewall_rules: filter_tombs(&d.tombstones.firewall_rules, since),
            rate_limits: filter_tombs(&d.tombstones.rate_limits, since),
            origin_rules: filter_tombs(&d.tombstones.origin_rules, since),
            certificates: filter_tombs(&d.tombstones.certificates, since),
            certificate_packs: filter_tombs(&d.tombstones.certificate_packs, since),
            spectrum_apps: filter_tombs(&d.tombstones.spectrum_apps, since),
            workers: filter_tombs(&d.tombstones.workers, since),
            worker_routes: filter_tombs(&d.tombstones.worker_routes, since),
            redirect_rules: filter_tombs(&d.tombstones.redirect_rules, since),
            transform_rules: filter_tombs(&d.tombstones.transform_rules, since),
            cache_rules: filter_tombs(&d.tombstones.cache_rules, since),
            email_rules: filter_tombs(&d.tombstones.email_rules, since),
            log_jobs: filter_tombs(&d.tombstones.log_jobs, since),
            waiting_rooms: filter_tombs(&d.tombstones.waiting_rooms, since),
            nodes: filter_tombs(&d.tombstones.nodes, since),
            steering: filter_tombs(&d.tombstones.steering, since),
            local_proxy_rules: filter_tombs(&d.tombstones.local_proxy_rules, since),
            purges: filter_tombs(&d.tombstones.purges, since),
            acme_challenges: filter_tombs(&d.tombstones.acme_challenges, since),
            node_telemetry: filter_tombs(&d.tombstones.node_telemetry, since),
            ip_lists: filter_tombs(&d.tombstones.ip_lists, since),
            alert_channels: filter_tombs(&d.tombstones.alert_channels, since),
            challenge_widgets: filter_tombs(&d.tombstones.challenge_widgets, since),
        },
    };
    Ok(DomainDelta {
        domain: "config".into(),
        epoch: d.epoch.clone(),
        from_rev: since,
        to_rev: d.local_rev,
        full_resync,
        payload: serde_json::to_value(&payload).map_err(|e| e.to_string())?,
    })
}

fn observe_meta(clock: &HlcClock, m: &mut SyncMeta, now_ms: u64) {
    if m.updated_ms > 0 {
        m.clamp_skew(now_ms);
        clock.observe(m.updated_ms, m.seq);
    }
}

fn merge_collection<T>(
    d_local_rev: &mut u64,
    clock: &HlcClock,
    active: &mut Vec<T>,
    tombs: &mut BTreeMap<String, SyncMeta>,
    incoming: Vec<T>,
    in_tombs: BTreeMap<String, SyncMeta>,
    key_of: impl Fn(&T) -> String,
    sync_of: impl Fn(&T) -> &SyncMeta,
    sync_mut: impl Fn(&mut T) -> &mut SyncMeta,
) -> bool {
    let now_ms = crate::sync::clock::unix_ms();
    let mut changed = false;
    for mut item in incoming {
        observe_meta(clock, sync_mut(&mut item), now_ms);
        let k = key_of(&item);
        let in_meta = sync_of(&item);
        let cur_best = active
            .iter()
            .find(|x| key_of(x) == k)
            .map(&sync_of)
            .into_iter()
            .chain(tombs.get(&k))
            .max_by(|a, b| a.version_key().cmp(&b.version_key()));
        if cur_best.is_none_or(|b| in_meta.wins_over(b)) {
            *d_local_rev = d_local_rev.saturating_add(1);
            sync_mut(&mut item).local_rev = *d_local_rev;
            sync_mut(&mut item).deleted = false;
            tombs.remove(&k);
            if let Some(pos) = active.iter().position(|x| key_of(x) == k) {
                active[pos] = item;
            } else {
                active.push(item);
            }
            changed = true;
        }
    }
    for (k, mut tomb) in in_tombs {
        tomb.deleted = true;
        observe_meta(clock, &mut tomb, now_ms);
        let cur_best = active
            .iter()
            .find(|x| key_of(x) == k)
            .map(&sync_of)
            .into_iter()
            .chain(tombs.get(&k))
            .max_by(|a, b| a.version_key().cmp(&b.version_key()));
        if cur_best.is_none_or(|b| tomb.wins_over(b)) {
            *d_local_rev = d_local_rev.saturating_add(1);
            tomb.local_rev = *d_local_rev;
            active.retain(|x| key_of(x) != k);
            tombs.insert(k, tomb);
            changed = true;
        }
    }
    changed
}

fn resolve_natural_key_collisions<T, NK>(
    d_local_rev: &mut u64,
    active: &mut Vec<T>,
    tombs: &mut BTreeMap<String, SyncMeta>,
    id_of: impl Fn(&T) -> String,
    nat_of: impl Fn(&T) -> NK,
    sync_of: impl Fn(&T) -> &SyncMeta,
) -> bool
where
    NK: Ord,
{
    if active.len() < 2 {
        return false;
    }
    // Sort so highest (sync.updated_ms, sync.seq, sync.node, id) comes first.
    active.sort_by(|a, b| {
        (sync_of(b).updated_ms, sync_of(b).seq, sync_of(b).node.as_str(), id_of(b))
            .cmp(&(sync_of(a).updated_ms, sync_of(a).seq, sync_of(a).node.as_str(), id_of(a)))
    });
    let mut seen = BTreeMap::<NK, usize>::new();
    let mut keep = vec![true; active.len()];
    let mut removed = false;
    for (i, item) in active.iter().enumerate() {
        let nk = nat_of(item);
        if seen.contains_key(&nk) {
            keep[i] = false;
            removed = true;
        } else {
            seen.insert(nk, i);
        }
    }
    if !removed {
        return false;
    }
    let mut next = Vec::with_capacity(seen.len());
    for (i, item) in active.drain(..).enumerate() {
        if keep[i] {
            next.push(item);
        } else {
            let mut tomb = sync_of(&item).clone();
            tomb.deleted = true;
            *d_local_rev = d_local_rev.saturating_add(1);
            tomb.local_rev = *d_local_rev;
            tombs.insert(id_of(&item), tomb);
        }
    }
    *active = next;
    true
}

fn merge_delta_data(
    d: &mut Data,
    delta: &DomainDelta,
    clock: &HlcClock,
    _sync_node: &str,
    is_accelerate: bool,
) -> Result<bool, String> {
    let payload: ConfigDeltaPayload = serde_json::from_value(delta.payload.clone()).map_err(|e| e.to_string())?;
    let mut changed = false;

    // On full_resync in `accelerate` mode, reconcile deleted items whose tombstones
    // may already have expired on the peer by removing items absent from the full snapshot.
    if delta.full_resync && is_accelerate {
        let z_ids: HashSet<String> = payload.zones.iter().map(|z| z.id.clone()).collect();
        let before = (d.zones.len(), d.records.len(), d.workers.len(), d.nodes.len(), d.steering.len(), d.ip_lists.len());
        d.zones.retain(|z| z_ids.contains(&z.id));
        let r_ids: HashSet<String> = payload.records.iter().map(|r| r.id.clone()).collect();
        d.records.retain(|r| r_ids.contains(&r.id));
        let w_ids: HashSet<String> = payload.workers.iter().map(|w| w.name.clone()).collect();
        d.workers.retain(|w| w_ids.contains(&w.name));
        let n_ids: HashSet<String> = payload.nodes.iter().map(|n| n.id.clone()).collect();
        d.nodes.retain(|n| n_ids.contains(&n.id));
        let s_ids: HashSet<String> = payload.steering.iter().map(|s| s.id.clone()).collect();
        d.steering.retain(|s| s_ids.contains(&s.id));
        let l_ids: HashSet<String> = payload.ip_lists.iter().map(|l| l.id.clone()).collect();
        d.ip_lists.retain(|l| l_ids.contains(&l.id));
        let c_keys: HashSet<String> = payload.acme_challenges.iter().map(AcmeChallenge::sync_key).collect();
        d.acme_challenges.retain(|c| c_keys.contains(&c.sync_key()));
        if (d.zones.len(), d.records.len(), d.workers.len(), d.nodes.len(), d.steering.len(), d.ip_lists.len()) != before {
            changed = true;
        }
    }

    let mut rev = d.local_rev;
    let zones_before: HashMap<String, SyncMeta> = d.zones.iter().map(|z| (z.id.clone(), z.sync.clone())).collect();
    let recs_before: usize = d.records.len();

    changed |= merge_collection(&mut rev, clock, &mut d.zones, &mut d.tombstones.zones, payload.zones, payload.tombstones.zones, |z| z.id.clone(), |z| &z.sync, |z| &mut z.sync);
    let recs_changed = merge_collection(&mut rev, clock, &mut d.records, &mut d.tombstones.records, payload.records, payload.tombstones.records, |r| r.id.clone(), |r| &r.sync, |r| &mut r.sync);
    changed |= recs_changed;

    macro_rules! merge_items {
        ($field:ident) => {
            changed |= merge_collection(
                &mut rev,
                clock,
                &mut d.$field,
                &mut d.tombstones.$field,
                payload.$field,
                payload.tombstones.$field,
                |x| x.meta.id.clone(),
                |x| &x.meta.sync,
                |x| &mut x.meta.sync,
            );
        };
    }
    merge_items!(firewall_rules);
    merge_items!(rate_limits);
    merge_items!(origin_rules);
    merge_items!(certificates);
    merge_items!(certificate_packs);
    merge_items!(spectrum_apps);
    merge_items!(worker_routes);
    merge_items!(redirect_rules);
    merge_items!(transform_rules);
    merge_items!(cache_rules);
    merge_items!(email_rules);
    merge_items!(log_jobs);
    merge_items!(waiting_rooms);

    changed |= merge_collection(&mut rev, clock, &mut d.workers, &mut d.tombstones.workers, payload.workers, payload.tombstones.workers, |w| w.name.clone(), |w| &w.sync, |w| &mut w.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.nodes, &mut d.tombstones.nodes, payload.nodes, payload.tombstones.nodes, |n| n.id.clone(), |n| &n.sync, |n| &mut n.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.steering, &mut d.tombstones.steering, payload.steering, payload.tombstones.steering, |s| s.id.clone(), |s| &s.sync, |s| &mut s.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.ip_lists, &mut d.tombstones.ip_lists, payload.ip_lists, payload.tombstones.ip_lists, |l| l.id.clone(), |l| &l.sync, |l| &mut l.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.local_proxy_rules, &mut d.tombstones.local_proxy_rules, payload.local_proxy_rules, payload.tombstones.local_proxy_rules, |r| r.id.clone(), |r| &r.sync, |r| &mut r.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.purges, &mut d.tombstones.purges, payload.purges, payload.tombstones.purges, |p| p.id.clone(), |p| &p.sync, |p| &mut p.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.acme_challenges, &mut d.tombstones.acme_challenges, payload.acme_challenges, payload.tombstones.acme_challenges, AcmeChallenge::sync_key, |c| &c.sync, |c| &mut c.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.alert_channels, &mut d.tombstones.alert_channels, payload.alert_channels, payload.tombstones.alert_channels, |c| c.id.clone(), |c| &c.sync, |c| &mut c.sync);
    changed |= merge_collection(&mut rev, clock, &mut d.challenge_widgets, &mut d.tombstones.challenge_widgets, payload.challenge_widgets, payload.tombstones.challenge_widgets, |w| w.id.clone(), |w| &w.sync, |w| &mut w.sync);

    // Keep purge ring bounded by newest `updated_ms`.
    if d.purges.len() > 50 {
        d.purges.sort_by_key(|p| p.sync.updated_ms);
        let excess = d.purges.len() - 50;
        d.purges.drain(..excess);
    }

    // Merge per-node telemetry.
    let now_ms = crate::sync::clock::unix_ms();
    for (k, mut t) in payload.node_telemetry {
        observe_meta(clock, &mut t.sync, now_ms);
        let cur_best = d
            .node_telemetry
            .get(&k)
            .map(|x| &x.sync)
            .into_iter()
            .chain(d.tombstones.node_telemetry.get(&k))
            .max_by(|a, b| a.version_key().cmp(&b.version_key()));
        if cur_best.is_none_or(|b| t.sync.wins_over(b)) {
            rev = rev.saturating_add(1);
            t.sync.local_rev = rev;
            t.sync.deleted = false;
            d.tombstones.node_telemetry.remove(&k);
            d.node_telemetry.insert(k, t);
            changed = true;
        }
    }
    for (k, mut tomb) in payload.tombstones.node_telemetry {
        tomb.deleted = true;
        observe_meta(clock, &mut tomb, now_ms);
        let cur_best = d
            .node_telemetry
            .get(&k)
            .map(|x| &x.sync)
            .into_iter()
            .chain(d.tombstones.node_telemetry.get(&k))
            .max_by(|a, b| a.version_key().cmp(&b.version_key()));
        if cur_best.is_none_or(|b| tomb.wins_over(b)) {
            rev = rev.saturating_add(1);
            tomb.local_rev = rev;
            d.node_telemetry.remove(&k);
            d.tombstones.node_telemetry.insert(k, tomb);
            changed = true;
        }
    }
    sync_telemetry_projections(d);

    // Merge AcmeLease via LWW.
    if let Some(mut lease) = payload.acme_lease {
        observe_meta(clock, &mut lease.sync, now_ms);
        let wins = d.acme_lease.as_ref().is_none_or(|cur| lease.sync.wins_over(&cur.sync));
        if wins {
            rev = rev.saturating_add(1);
            lease.sync.local_rev = rev;
            d.acme_lease = Some(lease);
            changed = true;
        }
    }

    // Natural-key collision resolution (deterministic LWW across all peers).
    changed |= resolve_natural_key_collisions(&mut rev, &mut d.zones, &mut d.tombstones.zones, |z| z.id.clone(), |z| z.name.clone(), |z| &z.sync);
    changed |= resolve_natural_key_collisions(&mut rev, &mut d.nodes, &mut d.tombstones.nodes, |n| n.id.clone(), |n| n.name.clone(), |n| &n.sync);
    changed |= resolve_natural_key_collisions(&mut rev, &mut d.worker_routes, &mut d.tombstones.worker_routes, |r| r.meta.id.clone(), |r| r.pattern.clone(), |r| &r.meta.sync);
    changed |= resolve_natural_key_collisions(&mut rev, &mut d.email_rules, &mut d.tombstones.email_rules, |r| r.meta.id.clone(), |r| (r.meta.zone_id.clone(), r.address.clone()), |r| &r.meta.sync);
    changed |= resolve_natural_key_collisions(&mut rev, &mut d.spectrum_apps, &mut d.tombstones.spectrum_apps, |a| a.meta.id.clone(), |a| a.protocol.clone(), |a| &a.meta.sync);

    // Cascade zone deletion tombstones to children older than the zone tombstone.
    if !d.tombstones.zones.is_empty() {
        let mut rm_recs = Vec::new();
        d.records.retain(|r| {
            if let Some(zt) = d.tombstones.zones.get(&r.zone_id) {
                if !r.sync.wins_over(zt) {
                    rm_recs.push((r.id.clone(), zt.clone()));
                    return false;
                }
            }
            true
        });
        for (id, mut t) in rm_recs {
            rev = rev.saturating_add(1);
            t.deleted = true;
            t.local_rev = rev;
            d.tombstones.records.insert(id, t);
            changed = true;
        }
        macro_rules! cascade_tomb {
            ($field:ident) => {
                let mut rm = Vec::new();
                d.$field.retain(|x| {
                    if let Some(zt) = d.tombstones.zones.get(&x.meta.zone_id) {
                        if !x.meta.sync.wins_over(zt) {
                            rm.push((x.meta.id.clone(), zt.clone()));
                            return false;
                        }
                    }
                    true
                });
                for (id, mut t) in rm {
                    rev = rev.saturating_add(1);
                    t.deleted = true;
                    t.local_rev = rev;
                    d.tombstones.$field.insert(id, t);
                    changed = true;
                }
            };
        }
        cascade_tomb!(firewall_rules);
        cascade_tomb!(rate_limits);
        cascade_tomb!(origin_rules);
        cascade_tomb!(certificates);
        cascade_tomb!(spectrum_apps);
        cascade_tomb!(worker_routes);
        cascade_tomb!(redirect_rules);
        cascade_tomb!(transform_rules);
        cascade_tomb!(cache_rules);
        cascade_tomb!(email_rules);
        cascade_tomb!(log_jobs);
        cascade_tomb!(waiting_rooms);
        cascade_tomb!(certificate_packs);
    }

    // Bump SOA serial locally when records changed without the zone itself changing.
    if recs_changed || d.records.len() != recs_before {
        let mut rec_zones = HashSet::new();
        for r in &d.records {
            rec_zones.insert(r.zone_id.as_str());
        }
        for z in &mut d.zones {
            if rec_zones.contains(z.id.as_str()) && zones_before.get(&z.id) == Some(&z.sync) {
                z.serial = z.serial.wrapping_add(1);
            }
        }
    }

    d.local_rev = rev;
    Ok(changed)
}

pub fn proxiable(rtype: &str) -> bool {
    matches!(rtype, "A" | "AAAA" | "CNAME")
}

/// Normalize and validate a record against the zone and its sibling records.
fn validate(d: &Data, zone: &Zone, mut r: RecordInput, exclude: Option<&str>) -> Result<RecordInput, StoreError> {
    r.rtype = r.rtype.trim().to_ascii_uppercase();
    if !wire::SUPPORTED_TYPES.contains(&r.rtype.as_str()) {
        return invalid(format!("unsupported record type '{}'", r.rtype));
    }

    let raw = r.name.trim().trim_end_matches('.').to_ascii_lowercase();
    let suffix = format!(".{}", zone.name);
    let fqdn = if raw == "@" || raw == zone.name {
        zone.name.clone()
    } else if raw.ends_with(&suffix) {
        raw
    } else {
        format!("{raw}{suffix}")
    };
    r.name = normalize_name(&fqdn).map_err(StoreError::Invalid)?;
    if r.name.split('.').skip(1).any(|l| l == "*") {
        return invalid("a wildcard '*' is only allowed as the leftmost label");
    }
    let at_apex = r.name == zone.name;

    if !matches!(r.rtype.as_str(), "MX" | "SRV") {
        r.priority = None;
    }
    r.content = wire::normalize_content(&r.rtype, &r.content, r.priority).map_err(StoreError::Invalid)?;

    if r.ttl != 1 && !(30..=86400).contains(&r.ttl) {
        return invalid("ttl must be 1 (automatic) or between 30 and 86400");
    }
    if r.proxied && !proxiable(&r.rtype) {
        return invalid(format!("{} records cannot be proxied", r.rtype));
    }
    r.origin = match r.origin.take() {
        Some(origin) => origin.validated()?,
        None => None,
    };
    if r.origin.is_some() && !proxiable(&r.rtype) {
        return invalid(format!("origin options are for records that can be proxied (A, AAAA, CNAME), not {}", r.rtype));
    }
    if at_apex && r.rtype == "NS" {
        return invalid("apex NS records are managed by the platform");
    }
    if let Some(c) = &r.comment {
        if c.len() > 500 {
            return invalid("comment exceeds 500 characters");
        }
    }

    let siblings = d
        .records
        .iter()
        .filter(|o| o.zone_id == zone.id && o.name == r.name && Some(o.id.as_str()) != exclude);
    for o in siblings {
        let either_cname = o.rtype == "CNAME" || r.rtype == "CNAME";
        // At the apex a CNAME is flattened into addresses when answering, so
        // it only excludes other sources of addresses (and a second CNAME).
        let both_addresses = [&o.rtype, &r.rtype].iter().all(|t| matches!(t.as_str(), "CNAME" | "A" | "AAAA"));
        if either_cname && at_apex && both_addresses {
            return Err(StoreError::Conflict("a CNAME at the zone apex cannot coexist with address records or another CNAME".into()));
        }
        if either_cname && !at_apex {
            return Err(StoreError::Conflict(format!(
                "a CNAME record cannot coexist with other records at '{}'",
                r.name
            )));
        }
        if o.rtype == r.rtype && o.content == r.content && o.priority == r.priority {
            return Err(StoreError::Conflict("an identical record already exists".into()));
        }
    }
    Ok(r)
}

#[cfg(test)]
pub mod testutil {
    use super::*;

    pub fn temp_store() -> Store {
        let path = std::env::temp_dir().join(format!("fucf-test-{}.json", new_id()));
        Store::open(&path, vec!["ns1.fucf.test".into(), "ns2.fucf.test".into()]).unwrap()
    }

    pub fn rec(name: &str, rtype: &str, content: &str) -> RecordInput {
        RecordInput {
            name: name.into(),
            rtype: rtype.into(),
            content: content.into(),
            ttl: 1,
            priority: if rtype == "MX" { Some(10) } else { None },
            proxied: false,
            comment: None,
            origin: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn validation_and_persistence() {
        let s = temp_store();
        let z = s.create_zone("Example.COM.").unwrap();
        assert_eq!(z.name, "example.com");
        assert!(matches!(s.create_zone("example.com"), Err(StoreError::Conflict(_))));

        let (_, r) = s.create_record(&z.id, rec("www", "A", "1.2.3.4")).unwrap();
        assert_eq!(r.name, "www.example.com");
        assert!(matches!(s.create_record(&z.id, rec("www", "A", "1.2.3.4")), Err(StoreError::Conflict(_))));
        assert!(matches!(s.create_record(&z.id, rec("www", "CNAME", "x.example.com")), Err(StoreError::Conflict(_))));
        // at the apex a CNAME is allowed (it is flattened), next to anything but addresses
        let (_, apex) = s.create_record(&z.id, rec("@", "CNAME", "x.example.org")).unwrap();
        let (_, mx) = s.create_record(&z.id, rec("@", "MX", "mail.example.com")).unwrap();
        assert!(matches!(s.create_record(&z.id, rec("@", "A", "1.2.3.4")), Err(StoreError::Conflict(_))));
        assert!(matches!(s.create_record(&z.id, rec("@", "CNAME", "y.example.org")), Err(StoreError::Conflict(_))));
        s.delete_record(&z.id, &apex.id).unwrap();
        s.create_record(&z.id, rec("@", "A", "1.2.3.4")).unwrap();
        assert!(matches!(s.create_record(&z.id, rec("@", "CNAME", "x.example.org")), Err(StoreError::Conflict(_))));
        s.delete_record(&z.id, &mx.id).unwrap();
        assert!(matches!(s.create_record(&z.id, rec("a.*.b", "A", "1.1.1.1")), Err(StoreError::Invalid(_))));
        let mut p = rec("mail", "MX", "mx.example.com");
        p.proxied = true;
        assert!(matches!(s.create_record(&z.id, p), Err(StoreError::Invalid(_))));
        // a failed mutation must not bump the serial
        assert_eq!(s.get_zone(&z.id).unwrap().serial, z.serial.wrapping_add(6));

        // updating a record to its own values is not a self-conflict
        s.update_record(&z.id, &r.id, rec("www.example.com", "A", "1.2.3.4")).unwrap();

        // origin options of a proxied record: checked, normalized, and gone when emptied
        let with = |origin: serde_json::Value| {
            let mut input = rec("www", "A", "1.2.3.4");
            (input.proxied, input.origin) = (true, Some(serde_json::from_value(origin).unwrap()));
            s.update_record(&z.id, &r.id, input)
        };
        let saved = with(serde_json::json!({ "sni": " Edge.CDN.example. ", "host_header": "App.Origin.example", "port": 8443 })).unwrap().1.origin.unwrap();
        assert_eq!((saved.sni.as_deref(), saved.host_header.as_deref(), saved.port, saved.scheme.as_deref()), (Some("edge.cdn.example"), Some("app.origin.example"), Some(8443), None));
        assert_eq!(serde_json::to_value(&saved).unwrap(), serde_json::json!({ "sni": "edge.cdn.example", "host_header": "app.origin.example", "port": 8443 }));
        assert_eq!(with(serde_json::json!({ "scheme": "HTTPS" })).unwrap().1.origin.unwrap().scheme.as_deref(), Some("https"));
        for bad in [
            serde_json::json!({ "sni": "not a host" }),
            serde_json::json!({ "host_header": "*.example.com" }),
            serde_json::json!({ "port": 0 }),
            serde_json::json!({ "scheme": "ftp" }),
            serde_json::json!({ "scheme": "http", "sni": "edge.cdn.example" }),
        ] {
            assert!(matches!(with(bad.clone()), Err(StoreError::Invalid(_))), "{bad}");
        }
        assert!(with(serde_json::json!({ "sni": "", "host_header": " ", "scheme": "" })).unwrap().1.origin.is_none(), "nothing set is no options");
        assert!(!serde_json::to_string(&s.get_record(&z.id, &r.id).unwrap().1).unwrap().contains("origin"), "records without options look as they always did");
        let mut txt = rec("note", "TXT", "hello");
        txt.origin = Some(RecordOrigin { sni: Some("edge.cdn.example".into()), ..Default::default() });
        assert!(matches!(s.create_record(&z.id, txt), Err(StoreError::Invalid(_))));
        with(serde_json::json!({ "sni": "edge.cdn.example", "host_header": "app.origin.example" })).unwrap();

        let path = s.path.as_deref().unwrap();
        let reopened = Store::open(path, vec![]).unwrap();
        assert_eq!(reopened.list_records(&z.id).unwrap().1.len(), 2);
        assert_eq!(reopened.get_record(&z.id, &r.id).unwrap().1.origin.unwrap().sni.as_deref(), Some("edge.cdn.example"));
        assert!(reopened.snapshot().find_zone("a.b.example.com").is_some());
        assert!(reopened.snapshot().find_zone("example.org").is_none());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn two_peer_bidirectional_convergence() {
        let a = temp_store();
        a.set_sync_node_id("au".into());
        let b = temp_store();
        b.set_sync_node_id("eu".into());

        let z = a.create_zone("sync.test").unwrap();
        let (_, r1) = a.create_record(&z.id, rec("www", "A", "1.1.1.1")).unwrap();

        // Sync A -> B
        let d_a = a.export_since(0, None).unwrap();
        assert!(b.merge_delta(&d_a, &b.clock()).unwrap());

        // Concurrently B adds R2 and updates R1, while A adds R3
        let (_, r2) = b.create_record(&z.id, rec("api", "A", "2.2.2.2")).unwrap();
        b.update_record(&z.id, &r1.id, rec("www", "A", "1.1.1.9")).unwrap();
        let (_, r3) = a.create_record(&z.id, rec("cdn", "A", "3.3.3.3")).unwrap();

        // Bidirectional sync A <-> B
        let d_b = b.export_since(0, None).unwrap();
        let d_a2 = a.export_since(0, None).unwrap();
        a.merge_delta(&d_b, &a.clock()).unwrap();
        b.merge_delta(&d_a2, &b.clock()).unwrap();

        let (_, recs_a) = a.list_records(&z.id).unwrap();
        let (_, recs_b) = b.list_records(&z.id).unwrap();
        assert_eq!(recs_a.len(), 3);
        assert_eq!(recs_b.len(), 3);
        assert_eq!(a.get_record(&z.id, &r1.id).unwrap().1.content, "1.1.1.9");
        assert_eq!(b.get_record(&z.id, &r1.id).unwrap().1.content, "1.1.1.9");
        assert!(recs_a.iter().any(|r| r.id == r2.id) && recs_b.iter().any(|r| r.id == r3.id));
    }

    #[test]
    fn natural_key_lww_conflict_resolution() {
        let a = temp_store();
        a.set_sync_node_id("au".into());
        let b = temp_store();
        b.set_sync_node_id("eu".into());

        let za = a.create_zone("dup.test").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let zb = b.create_zone("dup.test").unwrap();
        assert_ne!(za.id, zb.id);

        let d_a = a.export_since(0, None).unwrap();
        let d_b = b.export_since(0, None).unwrap();
        a.merge_delta(&d_b, &a.clock()).unwrap();
        b.merge_delta(&d_a, &b.clock()).unwrap();

        assert_eq!(a.list_zones().len(), 1);
        assert_eq!(b.list_zones().len(), 1);
        assert_eq!(a.list_zones()[0].id, zb.id);
        assert_eq!(b.list_zones()[0].id, zb.id);
        assert!(a.snapshot().zones.contains_key("dup.test"));
    }

    #[test]
    fn tombstone_delete_and_gc_resync() {
        let a = temp_store();
        a.set_sync_node_id("au".into());
        let b = temp_store();
        b.set_sync_node_id("eu".into());

        let z = a.create_zone("del.test").unwrap();
        let (_, r) = a.create_record(&z.id, rec("gone", "A", "9.9.9.9")).unwrap();
        a.put_worker("w1", Some("export default { fetch() { return new Response('ok'); } }".into()), None).unwrap();

        let d0 = a.export_since(0, None).unwrap();
        b.merge_delta(&d0, &b.clock()).unwrap();
        let cursor_b = d0.to_rev;
        let epoch_a = d0.epoch;
        assert_eq!(b.list_records(&z.id).unwrap().1.len(), 1);

        // Delete record & worker on A
        a.delete_record(&z.id, &r.id).unwrap();
        a.delete_worker("w1").unwrap();

        // Sync incremental tombstones to B
        let d1 = a.export_since(cursor_b, Some(&epoch_a)).unwrap();
        assert!(!d1.full_resync);
        b.merge_delta(&d1, &b.clock()).unwrap();
        assert!(b.list_records(&z.id).unwrap().1.is_empty());
        assert!(b.list_workers().is_empty());

        // Advance tombstone GC on A past cursor_b -> old cursor triggers full_resync
        a.force_tombstone_gc_for_test(DURABLE_TOMBSTONE_TTL_MS + 10_000);
        let d_gc = a.export_since(cursor_b, Some(&epoch_a)).unwrap();
        assert!(d_gc.full_resync);
    }

    #[test]
    fn restart_persistence_of_sync_state() {
        let s = temp_store();
        s.set_sync_node_id("au".into());
        let z = s.create_zone("persist.test").unwrap();
        let (_, r) = s.create_record(&z.id, rec("a", "A", "1.2.3.4")).unwrap();
        s.delete_record(&z.id, &r.id).unwrap();
        let rev_before = s.current_rev();
        let epoch_before = s.epoch();
        let path = s.path.clone().unwrap();
        drop(s);

        let reopened = Store::open(&path, vec![]).unwrap();
        assert_eq!(reopened.current_rev(), rev_before);
        assert_eq!(reopened.epoch(), epoch_before);
        assert!(reopened.data.lock().unwrap().tombstones.records.contains_key(&r.id));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn incremental_cursor_delta_size() {
        let s = temp_store();
        s.set_sync_node_id("au".into());
        let mut last_z = String::new();
        for i in 0..50 {
            last_z = s.create_zone(&format!("z{i}.test")).unwrap().id;
        }
        let prev_rev = s.current_rev();
        s.create_record(&last_z, rec("www", "A", "1.2.3.4")).unwrap();
        let delta = s.export_since(prev_rev, Some(&s.epoch())).unwrap();
        assert!(!delta.full_resync);
        let payload: ConfigDeltaPayload = serde_json::from_value(delta.payload).unwrap();
        assert_eq!(payload.zones.len(), 1, "only touched zone emitted");
        assert_eq!(payload.records.len(), 1, "only new record emitted");
    }

    #[test]
    fn ephemeral_store_rejects_writes_and_writes_no_files() {
        let peer = temp_store();
        peer.set_sync_node_id("au".into());
        let z = peer.create_zone("accel.test").unwrap();
        peer.create_record(&z.id, rec("www", "A", "1.2.3.4")).unwrap();

        let accel = Store::open_ephemeral(vec![]);
        assert!(accel.is_read_only());
        assert!(matches!(accel.create_zone("nope.test"), Err(StoreError::ReadOnly)));
        let delta = peer.export_since(0, None).unwrap();
        assert!(accel.merge_delta(&delta, &accel.clock()).unwrap());
        assert!(accel.snapshot().find_zone("www.accel.test").is_some());
    }
}
