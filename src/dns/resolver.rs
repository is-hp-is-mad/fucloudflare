//! Authoritative answer logic: zone selection, delegations, CNAME chasing,
//! wildcards, NODATA/NXDOMAIN, "proxied" records answered with edge IPs and
//! CNAMEs at the apex answered with the addresses of their target.

use super::wire::{self, rcode, rtype, ParseError, RData, Response, RR};
use crate::geo::{Geo, Health};
use crate::items::EdgeNode;
use crate::store::{Record, Snapshot, Store, ZoneSnap};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Fast lock-free pseudo-random percentage (0..100) for probabilistic DNS offloading.
fn roll_pct() -> u8 {
    static SEED: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut z = SEED.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    ((z ^ (z >> 31)) % 100) as u8
}

/// Fallback continents in rough geographic proximity order when a continent's
/// own nodes are offloaded or over their traffic allowance.
fn nearby_continents(continent: &str) -> &'static [&'static str] {
    match continent {
        "AS" => &["OC", "EU", "NA", "AF", "SA"],
        "OC" => &["AS", "NA", "EU", "SA", "AF"],
        "EU" => &["AF", "NA", "AS", "SA", "OC"],
        "NA" => &["SA", "EU", "OC", "AS", "AF"],
        "SA" => &["NA", "EU", "AF", "OC", "AS"],
        "AF" => &["EU", "AS", "SA", "NA", "OC"],
        "AN" => &["OC", "SA", "AF", "AS", "NA", "EU"],
        _ => &[],
    }
}

const AUTO_TTL: u32 = 300;
const NEGATIVE_TTL: u32 = 1800;
const NS_TTL: u32 = 86400;
const MAX_CNAME_CHAIN: usize = 8;
/// TTL of addresses answered in place of a CNAME at the apex.
const FLATTENED_TTL: u32 = 60;
/// Out of a hundred answers of a `fastest` steering rule, how many go to a
/// node picked at random: every candidate keeps being measured, and a node
/// that got faster is found out.
const EXPLORE_PCT: u8 = 5;

/// Names outside our zones that the CNAMEs at zone apexes lead to.
fn external_targets(snap: &Snapshot) -> HashSet<String> {
    let mut out = HashSet::new();
    for z in snap.zones.values() {
        let apex = z.names.get(&z.zone.name).into_iter().flatten();
        for cname in apex.filter(|r| r.rtype == "CNAME") {
            let mut name = cname.content.clone();
            for _ in 0..MAX_CNAME_CHAIN {
                let Some(hosted) = snap.find_zone(&name) else {
                    out.insert(name);
                    break;
                };
                match hosted.records_for(&name).iter().find(|r| r.rtype == "CNAME") {
                    Some(next) => name = next.content.clone(),
                    None => break,
                }
            }
        }
    }
    out
}

/// CNAME flattening: a CNAME cannot be served at a zone apex, so the
/// addresses of its target are answered instead. Targets we do not host are
/// looked up in the background (answering never waits for a lookup).
#[derive(Default)]
pub struct Flattener {
    table: RwLock<HashMap<String, Vec<IpAddr>>>,
}

impl Flattener {
    pub fn lookup(&self, name: &str) -> Vec<IpAddr> {
        self.table.read().unwrap().get(name).cloned().unwrap_or_default()
    }

    /// Look up every target the configuration refers to. A lookup that
    /// fails keeps the addresses known so far.
    pub async fn refresh(&self, snap: &Snapshot) {
        let mut table = HashMap::new();
        for name in external_targets(snap) {
            let found = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((name.clone(), 0))).await;
            let mut addrs: Vec<IpAddr> = match found {
                Ok(Ok(addrs)) => addrs.map(|a| a.ip().to_canonical()).collect(),
                _ => Vec::new(),
            };
            addrs.sort();
            addrs.dedup();
            if addrs.is_empty() {
                addrs = self.lookup(&name);
            }
            table.insert(name, addrs);
        }
        *self.table.write().unwrap() = table;
    }

    /// Keep the table current: once a minute, and whenever the configuration changes.
    pub async fn run(self: Arc<Self>, store: Arc<Store>) {
        let mut changes = store.subscribe();
        loop {
            self.refresh(&store.snapshot()).await;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }
}
/// Where a CA looks for the answer to a DNS-01 challenge.
const ACME_LABEL: &str = "_acme-challenge.";

/// TXT records answering the pending ACME challenges for `host`.
fn acme_txt(snap: &Snapshot, owner: &str, host: &str) -> Vec<RR> {
    let values = snap.acme_dns.get(host).into_iter().flatten();
    values.map(|v| RR { name: owner.to_string(), ttl: 5, data: RData::Txt(vec![v.as_bytes().to_vec()]) }).collect()
}

pub struct Resolver {
    pub store: Arc<Store>,
    /// Addresses of our edge (CDN/WAF) nodes, answered for proxied records.
    pub edge_v4: Vec<Ipv4Addr>,
    pub edge_v6: Vec<Ipv6Addr>,
    pub geo: Arc<Geo>,
    pub health: Arc<Health>,
    /// Names under this domain resolve to the edge for every client; it is
    /// the CNAME target of zones that are not fully delegated to us.
    pub cname_base: Option<String>,
    pub name_servers: Vec<String>,
    /// UDP port of the edge's HTTP/3 listener, advertised in HTTPS records.
    pub h3_port: Option<u16>,
    /// Another QUIC server that takes HTTP/3 for us, under its own
    /// certificate: advertised for the names that certificate covers.
    pub h3_front: Option<Arc<crate::edge::front::Front>>,
    /// TTL of the answers that point at the edge (proxied records: at most
    /// the usual 300 seconds; names under the CNAME base: as it is). A
    /// node that fails or runs out of allowance keeps getting visitors for
    /// this long; every lookup after it costs a round trip to us.
    pub edge_ttl: u32,
    pub flat: Arc<Flattener>,
    /// This node's own traffic allowance.
    pub limits: Arc<crate::limits::Limits>,
    /// Accelerate nodes suppress public authoritative DNS (only loopback answers).
    pub accelerate: bool,
    /// What the nodes measured of their visitors' round trips: `fastest` steering rules go by it.
    pub rtt: Arc<crate::rtt::Rtt>,
}

/// The queries this node answered for a zone since it started.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct QueryCount {
    pub total: u64,
    pub by_type: std::collections::BTreeMap<String, u64>,
    /// By answer: NOERROR, NXDOMAIN, REFUSED, ...
    pub by_rcode: std::collections::BTreeMap<String, u64>,
}

static QUERIES: std::sync::LazyLock<std::sync::Mutex<HashMap<String, QueryCount>>> = std::sync::LazyLock::new(Default::default);

/// What [`QueryCount`] holds for a zone (by its id).
pub fn query_count(zone_id: &str) -> QueryCount {
    QUERIES.lock().unwrap().get(zone_id).cloned().unwrap_or_default()
}

fn counted(zone_id: &str, qtype: u16, rcode: u16) {
    let answer = match rcode {
        0 => "NOERROR".to_string(),
        rcode::NXDOMAIN => "NXDOMAIN".to_string(),
        rcode::REFUSED => "REFUSED".to_string(),
        other => format!("RCODE{other}"),
    };
    let mut queries = QUERIES.lock().unwrap();
    let count = queries.entry(zone_id.to_string()).or_default();
    count.total += 1;
    *count.by_type.entry(wire::type_name(qtype)).or_default() += 1;
    *count.by_rcode.entry(answer).or_default() += 1;
}

/// Edge addresses to hand to one particular client.
struct Edges {
    v4: Vec<Ipv4Addr>,
    v6: Vec<Ipv6Addr>,
    /// The choice depended on where the client is.
    by_location: bool,
    /// A steering rule denies resolution to this client.
    blocked: bool,
}

enum Step {
    Answer(Vec<RR>),
    Cname(RR, String),
    NoData,
    NxDomain,
}

fn ttl_of(r: &Record) -> u32 {
    if r.ttl <= 1 { AUTO_TTL } else { r.ttl }
}

pub(super) fn to_rr(r: &Record, owner: &str) -> Option<RR> {
    let data = wire::parse_rdata(&r.rtype, &r.content, r.priority).ok()?;
    Some(RR { name: owner.to_string(), ttl: ttl_of(r), data })
}

fn parent(name: &str) -> &str {
    name.split_once('.').map(|(_, p)| p).unwrap_or("")
}

pub(super) fn soa(z: &ZoneSnap) -> RR {
    let zone = &z.zone;
    RR {
        name: zone.name.clone(),
        ttl: NEGATIVE_TTL,
        data: RData::Soa {
            mname: zone.name_servers.first().cloned().unwrap_or_else(|| format!("ns.{}", zone.name)),
            rname: format!("hostmaster.{}", zone.name),
            serial: zone.serial,
            refresh: 10000,
            retry: 2400,
            expire: 604800,
            minimum: NEGATIVE_TTL,
        },
    }
}

impl Resolver {
    /// Handle one DNS message; `None` means "drop without answering".
    pub fn handle(&self, buf: &[u8], udp: bool, peer: IpAddr) -> Option<Vec<u8>> {
        if !peer.is_loopback() && (self.accelerate || self.limits.dns_silent()) {
            return None;
        }
        let q = match wire::parse_query(buf) {
            Ok(q) => q,
            Err(ParseError::TooShort) => return None,
            Err(ParseError::FormErr { id, flags }) => {
                if flags & 0x8000 != 0 {
                    return None;
                }
                let r = Response { id, query_flags: flags, rcode: rcode::FORMERR, ..Default::default() };
                return Some(r.encode(512));
            }
        };
        if q.flags & 0x8000 != 0 {
            return None; // never answer responses (reflection loops)
        }
        let mut resp = Response {
            id: q.id,
            query_flags: q.flags,
            question: Some((q.qname_raw.clone(), q.qtype, q.qclass)),
            edns: q.edns.is_some(),
            do_bit: q.edns.is_some_and(|e| e.do_bit),
            ..Default::default()
        };
        let max = match (udp, q.edns) {
            (false, _) => u16::MAX as usize,
            (true, Some(e)) => e.udp_size.clamp(512, wire::EDNS_UDP_SIZE) as usize,
            (true, None) => 512,
        };
        if (q.flags >> 11) & 0xF != 0 {
            resp.rcode = rcode::NOTIMP;
        } else if q.edns.is_some_and(|e| e.version > 0) {
            resp.rcode = rcode::BADVERS;
        } else if q.qclass != 1 {
            resp.rcode = rcode::REFUSED;
        } else {
            // Prefer the end user's network (EDNS Client Subnet) over the resolver's address.
            let client = q.ecs.map(|e| e.addr).unwrap_or(peer.to_canonical());
            let mut by_location = false;
            self.answer(&q.qname, q.qtype, client, &mut by_location, &mut resp);
            if let Some(z) = self.store.snapshot().find_zone(&q.qname) {
                counted(&z.zone.id, q.qtype, resp.rcode);
            }
            if resp.do_bit && resp.aa {
                let snap = self.store.snapshot();
                if let Some(z) = snap.find_zone(&q.qname) {
                    if let Some(signer) = &z.dnssec {
                        let now = chrono::Utc::now().timestamp() as u32;
                        if resp.rcode == rcode::NXDOMAIN {
                            // RFC 4470 Black Lies: minimal NSEC proves non-existence without zone walking.
                            resp.rcode = 0;
                            resp.authority.push(super::dnssec::DnssecSigner::minimal_nsec(&q.qname, &[], NEGATIVE_TTL));
                        } else if resp.rcode == 0 && resp.answers.is_empty() {
                            let mut types = Vec::new();
                            if q.qname == z.zone.name {
                                types.extend_from_slice(&[rtype::SOA, rtype::NS, rtype::DNSKEY]);
                            }
                            for r in z.records_for(&q.qname) {
                                if let Some(rt) = wire::type_from_str(&r.rtype) {
                                    types.push(rt);
                                }
                            }
                            types.retain(|&t| t != q.qtype);
                            resp.authority.push(super::dnssec::DnssecSigner::minimal_nsec(&q.qname, &types, NEGATIVE_TTL));
                        }
                        signer.sign_section(&mut resp.answers, now);
                        signer.sign_section(&mut resp.authority, now);
                    }
                }
            }
            resp.ecs = q.ecs.map(|e| (e, if by_location { e.source_prefix } else { 0 }));
        }
        Some(resp.encode(max))
    }

    /// Pick the edge nodes for a client. In order: the zone's pinned nodes
    /// (if any) restrict the pool; over-limit / offloaded nodes are filtered;
    /// unhealthy nodes are left out while any healthy one remains; the first
    /// matching steering rule names the node; otherwise the nodes assigned to
    /// the client's continent (falling back to nearby continents when offloaded).
    fn edges(&self, snap: &Snapshot, pinned: &[String], client: IpAddr, strict_limit: bool, qname: Option<&str>) -> Edges {
        let mut pool: Vec<&EdgeNode> = snap.nodes.iter().collect();
        if pool.is_empty() {
            return Edges { v4: self.edge_v4.clone(), v6: self.edge_v6.clone(), by_location: false, blocked: false };
        }
        pool.retain(|n| {
            !n.role.eq_ignore_ascii_case("accelerate")
                || qname.is_some_and(|q| crate::items::accel_host_matches(&n.accel_hosts, q))
        });
        if pool.is_empty() {
            return Edges { v4: Vec::new(), v6: Vec::new(), by_location: false, blocked: false };
        }
        let chosen: Vec<&EdgeNode> = pool.iter().copied().filter(|n| pinned.contains(&n.name)).collect();
        if !chosen.is_empty() {
            pool = chosen;
        }
        let by_location = pool.len() > 1;
        // Nodes over their traffic allowance are left out as long as another
        // node remains: first the ones that serve nothing any more, then
        // probabilistic/hard DNS offload, then throttled. A node knows its own
        // state at once, the others' through the configuration.
        use crate::limits::State;
        let (me, mine) = self.limits.own();
        let my_offload = self.limits.offload_pct();
        let state = |n: &EdgeNode| {
            let known = snap.limited.get(&n.name).copied().unwrap_or_default();
            if n.name == me { known.max(mine) } else { known }
        };
        let offload_pct = |n: &EdgeNode| -> u8 {
            let st = state(n);
            if st == State::Ok {
                return 0;
            }
            if st == State::Limited || strict_limit || n.dns_offload_mode != "linear" {
                return 100;
            }
            let known = snap.limited_offload.get(&n.name).copied().unwrap_or(0);
            if n.name == me { known.max(my_offload) } else { known }
        };
        let before_limit = pool.len();
        // Always remove hard-limited (Tier 3) nodes first while any other node remains.
        let non_limited: Vec<&EdgeNode> = pool.iter().copied().filter(|n| state(n) < State::Limited).collect();
        if !non_limited.is_empty() {
            pool = non_limited;
        }
        if strict_limit {
            for worst in [State::Throttled, State::DnsLimited] {
                let rest: Vec<&EdgeNode> = pool.iter().copied().filter(|n| state(n) < worst).collect();
                if !rest.is_empty() {
                    pool = rest;
                }
            }
        } else {
            let kept: Vec<&EdgeNode> = pool
                .iter()
                .copied()
                .filter(|n| {
                    let pct = offload_pct(n);
                    pct == 0 || (pct < 100 && roll_pct() >= pct)
                })
                .collect();
            if !kept.is_empty() {
                pool = kept;
            } else {
                // Everyone was offloaded on this roll: prefer full-speed over throttled.
                for worst in [State::Throttled, State::DnsLimited] {
                    let rest: Vec<&EdgeNode> = pool.iter().copied().filter(|n| state(n) < worst).collect();
                    if !rest.is_empty() {
                        pool = rest;
                    }
                }
            }
        }
        let had_traffic_shed = pool.len() < before_limit;
        let up: Vec<&EdgeNode> = pool.iter().copied().filter(|n| self.health.is_up(&n.name)).collect();
        if !up.is_empty() {
            pool = up;
        }
        let loc = self.geo.locate(client);
        let is_cn = loc.country.as_deref() == Some("CN");
        let tcp_blocked = |n: &EdgeNode, v6: bool| {
            is_cn && snap.gfw_status.get(&n.name).is_some_and(|g| g.is_blocked(v6, false))
        };
        let udp_blocked = |n: &EdgeNode, v6: bool| {
            is_cn && snap.gfw_status.get(&n.name).is_some_and(|g| g.is_blocked(v6, true))
        };
        let of_list = |nodes: &[&EdgeNode]| -> Edges {
            let pick = |v6: bool| -> Vec<&EdgeNode> {
                let mut list: Vec<&EdgeNode> = nodes
                    .iter()
                    .copied()
                    .filter(|n| if v6 { n.ipv6.is_some() } else { n.ipv4.is_some() })
                    .collect();
                if is_cn && list.len() > 1 {
                    let ok_tcp: Vec<&EdgeNode> = list.iter().copied().filter(|n| !tcp_blocked(n, v6)).collect();
                    if !ok_tcp.is_empty() {
                        list = ok_tcp;
                    }
                    // Prefer nodes whose UDP/QUIC is also reachable in CN, keeping relative order.
                    list.sort_by_key(|n| udp_blocked(n, v6));
                }
                list
            };
            Edges {
                v4: pick(false).into_iter().filter_map(|n| n.ipv4).collect(),
                v6: pick(true).into_iter().filter_map(|n| n.ipv6).collect(),
                by_location,
                blocked: false,
            }
        };
        if snap.steering.iter().find(|r| r.matches(&loc)).is_some_and(|r| r.action == "block") {
            return Edges { v4: Vec::new(), v6: Vec::new(), by_location: true, blocked: true };
        }
        if pool.len() > 1 {
            for rule in snap.steering.iter().filter(|r| r.action != "block" && r.matches(&loc)) {
                let fastest = rule.action == "fastest";
                // Pick the first healthy (and for CN, TCP-unblocked) node independently per IP family;
                // for a `fastest` rule, the one that answers the visitor's network soonest.
                let pick_rule = |v6: bool| -> Option<&EdgeNode> {
                    let listed: Vec<&EdgeNode> = if fastest && rule.nodes.is_empty() {
                        pool.clone()
                    } else {
                        rule.nodes.iter().filter_map(|name| pool.iter().copied().find(|n| &n.name == name)).collect()
                    };
                    let avail: Vec<&EdgeNode> = listed.into_iter().filter(|n| if v6 { n.ipv6.is_some() } else { n.ipv4.is_some() }).collect();
                    if avail.is_empty() {
                        return None;
                    }
                    let open: Vec<&EdgeNode> = if is_cn { avail.iter().copied().filter(|n| !tcp_blocked(n, v6)).collect() } else { Vec::new() };
                    if fastest {
                        return Some(self.fastest(&loc, if open.is_empty() { &avail } else { &open }, &me));
                    }
                    open.first().or(avail.first()).copied()
                };
                let (n4, n6) = (pick_rule(false), pick_rule(true));
                if n4.is_some() || n6.is_some() {
                    return Edges {
                        v4: n4.and_then(|n| n.ipv4).into_iter().collect(),
                        v6: n6.and_then(|n| n.ipv6).into_iter().collect(),
                        by_location,
                        blocked: false,
                    };
                }
            }
            if let Some(continent) = &loc.continent {
                let near: Vec<&EdgeNode> = pool.iter().copied().filter(|n| n.continents.contains(continent)).collect();
                if !near.is_empty() {
                    return of_list(&near);
                }
                if had_traffic_shed {
                    for alt in nearby_continents(continent) {
                        let fallback: Vec<&EdgeNode> = pool.iter().copied().filter(|n| n.continents.iter().any(|c| c == alt)).collect();
                        if !fallback.is_empty() {
                            return of_list(&fallback);
                        }
                    }
                }
            }
        }
        of_list(&pool)
    }

    /// Of `nodes` (not empty), the one whose visitors from the network at
    /// `loc` shake hands soonest, as the nodes measured it (see crate::rtt).
    /// Each in turn while nothing tells them apart, and now and then anyway.
    fn fastest<'a>(&self, loc: &crate::geo::Location, nodes: &[&'a EdgeNode], me: &str) -> &'a EdgeNode {
        let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
        let any = || nodes[usize::from(roll_pct()) % nodes.len()];
        match self.rtt.ranking(loc, &names, me) {
            Some((_, order)) if roll_pct() >= EXPLORE_PCT => nodes.iter().copied().find(|n| n.name == order[0].0).unwrap_or_else(any),
            _ => any(),
        }
    }

    /// Where decoy names point (see `Settings::decoy_subdomains`): the node
    /// with the most traffic to spare -- one without a traffic limit first,
    /// then by the size of its limit -- that is up and not over its
    /// allowance, one address per family. Accelerate nodes never.
    fn decoy_edges(&self, snap: &Snapshot) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
        use crate::limits::State;
        let (me, mine) = self.limits.own();
        let state = |n: &EdgeNode| {
            let known = snap.limited.get(&n.name).copied().unwrap_or_default();
            if n.name == me { known.max(mine) } else { known }
        };
        let mut nodes: Vec<&EdgeNode> = snap.nodes.iter().filter(|n| !n.role.eq_ignore_ascii_case("accelerate")).collect();
        nodes.sort_by(|a, b| {
            let rank = |n: &EdgeNode| (state(n) != State::Ok, !self.health.is_up(&n.name));
            let room = |n: &EdgeNode| n.traffic_limit_gb.filter(|gb| *gb > 0.0).unwrap_or(f64::INFINITY);
            rank(a).cmp(&rank(b)).then(room(b).total_cmp(&room(a))).then(a.name.cmp(&b.name))
        });
        (nodes.iter().find_map(|n| n.ipv4), nodes.iter().find_map(|n| n.ipv6))
    }

    /// HTTPS records for a name served by the edge: HTTP/3 on its port first,
    /// HTTP/2 on 443 for clients without QUIC.
    fn https_rrs(&self, owner: &str, http3: bool) -> Vec<RR> {
        let fronted = self.h3_front.as_ref().filter(|front| front.covers(owner)).map(|front| front.port);
        let Some(port) = fronted.or(self.h3_port).filter(|_| http3) else { return Vec::new() };
        let rr = |priority, alpn, port| RR { name: owner.to_string(), ttl: AUTO_TTL, data: RData::Https { priority, alpn, port } };
        vec![rr(1, vec!["h3"], Some(port).filter(|p| *p != 443)), rr(2, vec!["h2"], None)]
    }

    /// Answer for a name under the CNAME base: always the edge.
    fn answer_base(&self, snap: &Snapshot, base: &str, qname: &str, qtype: u16, edges: &Edges, resp: &mut Response) {
        resp.aa = true;
        let rr = |data| RR { name: qname.to_string(), ttl: self.edge_ttl, data };
        // `_acme-challenge.<host>.<base>`: where zones hosted elsewhere
        // delegate their DNS-01 challenges to (by CNAME).
        let challenged = qname.strip_prefix(ACME_LABEL).and_then(|n| n.strip_suffix(base)?.strip_suffix('.'));
        match qtype {
            rtype::TXT if challenged.is_some() => resp.answers.extend(acme_txt(snap, qname, challenged.unwrap_or_default())),
            rtype::A => resp.answers.extend(edges.v4.iter().map(|ip| rr(RData::A(*ip)))),
            rtype::AAAA => resp.answers.extend(edges.v6.iter().map(|ip| rr(RData::Aaaa(*ip)))),
            rtype::HTTPS => resp.answers.extend(self.https_rrs(qname, true)),
            rtype::NS if qname == base => {
                resp.answers.extend(self.name_servers.iter().map(|ns| RR {
                    name: qname.to_string(),
                    ttl: NS_TTL,
                    data: RData::Ns(ns.clone()),
                }));
            }
            _ => {}
        }
        let soa = RR {
            name: base.to_string(),
            ttl: NEGATIVE_TTL,
            data: RData::Soa {
                mname: self.name_servers.first().cloned().unwrap_or_else(|| format!("ns.{base}")),
                rname: format!("hostmaster.{base}"),
                serial: 1,
                refresh: 10000,
                retry: 2400,
                expire: 604800,
                minimum: 60,
            },
        };
        if qtype == rtype::SOA && qname == base {
            resp.answers.push(soa);
        } else if resp.answers.is_empty() {
            resp.authority.push(soa);
        }
    }

    fn answer(&self, qname: &str, qtype: u16, client: IpAddr, by_location: &mut bool, resp: &mut Response) {
        let snap = self.store.snapshot();
        if let Some(base) = self.cname_base.as_deref().filter(|b| qname == *b || qname.ends_with(&format!(".{b}"))) {
            let is_asset_host = qname == format!("{}.{base}", crate::limits::ASSET_LABEL);
            let edges = self.edges(&snap, &[], client, is_asset_host, Some(qname));
            *by_location = edges.by_location;
            if edges.blocked {
                resp.rcode = rcode::REFUSED;
                return;
            }
            return self.answer_base(&snap, base, qname, qtype, &edges, resp);
        }
        let Some(z) = snap.find_zone(qname) else {
            resp.rcode = rcode::REFUSED; // not authoritative, and we never recurse
            return;
        };
        let edges = self.edges(&snap, &z.zone.settings.edge_nodes, client, false, Some(qname));
        *by_location = edges.by_location;
        if edges.blocked {
            resp.rcode = rcode::REFUSED;
            return;
        }
        resp.aa = true;
        let edges = &edges;

        if qtype == rtype::ANY {
            // RFC 8482: minimal answer instead of an amplification vector.
            let data = RData::Hinfo { cpu: "RFC8482".into(), os: String::new() };
            resp.answers.push(RR { name: qname.to_string(), ttl: 3789, data });
            return;
        }

        if let Some(cut) = delegation(z, qname) {
            if qtype == rtype::DS && cut == qname {
                // the DS of a name this zone delegates is this zone's to answer
                resp.answers = z.names[cut].iter().filter(|r| r.rtype == "DS").filter_map(|r| to_rr(r, cut)).collect();
                if resp.answers.is_empty() {
                    resp.authority.push(soa(z));
                }
                return;
            }
            resp.aa = false;
            resp.authority = z.names[cut].iter().filter(|r| r.rtype == "NS").filter_map(|r| to_rr(r, cut)).collect();
            resp.additional = glue(z, &resp.authority);
            return;
        }

        // A pending ACME challenge exists at its name for as long as it is
        // pending, whatever the zone itself holds there.
        let own = z.names.get(qname).map(Vec::as_slice).unwrap_or(&[]);
        if let Some(host) = qname.strip_prefix(ACME_LABEL).filter(|_| !own.iter().any(|r| r.rtype == "CNAME")) {
            let mut txt = acme_txt(&snap, qname, host);
            if !txt.is_empty() && qtype == rtype::TXT {
                txt.extend(own.iter().filter(|r| r.rtype == "TXT").filter_map(|r| to_rr(r, qname)));
                resp.answers = txt;
                return;
            }
            if !txt.is_empty() && !z.nodes.contains(qname) {
                resp.authority.push(soa(z)); // the name exists, this type does not
                return;
            }
        }

        if z.is_decoy(qname) {
            // a decoy name exists for every query: addresses for A/AAAA, NODATA for the rest
            let (v4, v6) = self.decoy_edges(&snap);
            let rr = |data| RR { name: qname.to_string(), ttl: self.edge_ttl, data };
            match qtype {
                rtype::A => resp.answers.extend(v4.map(|ip| rr(RData::A(ip)))),
                rtype::AAAA => resp.answers.extend(v6.map(|ip| rr(RData::Aaaa(ip)))),
                _ => {}
            }
            if resp.answers.is_empty() {
                resp.authority.push(soa(z));
            }
            return;
        }

        let mut name = qname.to_string();
        for _ in 0..MAX_CNAME_CHAIN {
            match self.step(z, &name, qtype, edges) {
                Step::Answer(rrs) => {
                    resp.answers.extend(rrs);
                    resp.additional = glue(z, &resp.answers);
                    return;
                }
                Step::Cname(rr, target) => {
                    resp.answers.push(rr);
                    let in_zone = snap.find_zone(&target).is_some_and(|t| t.zone.id == z.zone.id);
                    if !in_zone || delegation(z, &target).is_some() {
                        return; // the client's resolver follows the chain
                    }
                    name = target;
                }
                Step::NoData => {
                    resp.authority.push(soa(z));
                    return;
                }
                Step::NxDomain => {
                    resp.rcode = rcode::NXDOMAIN;
                    resp.authority.push(soa(z));
                    return;
                }
            }
        }
        resp.rcode = rcode::SERVFAIL; // CNAME loop
        resp.answers.clear();
    }

    fn step(&self, z: &ZoneSnap, name: &str, qtype: u16, edges: &Edges) -> Step {
        if z.nodes.contains(name) {
            return self.rrset(z, name, name, qtype, edges);
        }
        // Wildcard synthesis (RFC 4592): only `*.<closest encloser>` applies.
        let mut encloser = parent(name);
        while !z.nodes.contains(encloser) {
            encloser = parent(encloser);
        }
        let wildcard = format!("*.{encloser}");
        if z.names.contains_key(&wildcard) {
            self.rrset(z, &wildcard, name, qtype, edges)
        } else {
            Step::NxDomain
        }
    }

    /// Records of `qtype` stored at `node`, presented with owner name `owner`.
    fn rrset(&self, z: &ZoneSnap, node: &str, owner: &str, qtype: u16, edges: &Edges) -> Step {
        let zone = &z.zone;
        let mut out = Vec::new();
        if node == zone.name {
            match qtype {
                rtype::SOA => out.push(soa(z)),
                rtype::DNSKEY => {
                    if let Some(signer) = &z.dnssec {
                        out.push(signer.dnskey_rr());
                    }
                }
                rtype::NS => out.extend(zone.name_servers.iter().map(|ns| RR {
                    name: owner.to_string(),
                    ttl: NS_TTL,
                    data: RData::Ns(ns.clone()),
                })),
                _ => {}
            }
        }
        let records = z.names.get(node).map(Vec::as_slice).unwrap_or(&[]);
        let is_addr = qtype == rtype::A || qtype == rtype::AAAA;

        let has_edge = !(edges.v4.is_empty() && edges.v6.is_empty());
        let spectrum = has_edge && z.spectrum_names.contains(node);
        if is_addr && (spectrum || has_edge && !zone.paused && records.iter().any(|r| r.proxied)) {
            // Hide the origin: hand out our edge addresses instead.
            let rr = |data| RR { name: owner.to_string(), ttl: self.edge_ttl.min(AUTO_TTL), data };
            if qtype == rtype::A {
                out.extend(edges.v4.iter().map(|ip| rr(RData::A(*ip))));
            } else {
                out.extend(edges.v6.iter().map(|ip| rr(RData::Aaaa(*ip))));
            }
        } else if qtype == rtype::HTTPS && has_edge && !zone.paused && records.iter().any(|r| r.proxied) {
            out.extend(self.https_rrs(owner, zone.settings.http3));
        } else if let Some(c) = records.iter().find(|r| r.rtype == "CNAME").filter(|_| node != zone.name) {
            if let Some(rr) = to_rr(c, owner) {
                if qtype != rtype::CNAME {
                    return Step::Cname(rr, c.content.clone());
                }
                out.push(rr);
            }
        } else {
            // A CNAME at the apex never shows: its target's addresses do.
            if let Some(c) = records.iter().find(|r| r.rtype == "CNAME").filter(|_| is_addr) {
                let rr = |data| RR { name: owner.to_string(), ttl: FLATTENED_TTL, data };
                out.extend(self.flattened(&c.content, qtype, edges).into_iter().map(rr));
            }
            let wanted = records.iter().filter(|r| r.rtype != "CNAME" && wire::type_from_str(&r.rtype) == Some(qtype));
            out.extend(wanted.filter_map(|r| to_rr(r, owner)));
        }

        if out.is_empty() { Step::NoData } else { Step::Answer(out) }
    }

    /// The addresses (of the family `qtype` asks for) that `target` leads
    /// to: through the zones we host as far as it stays in them, else as
    /// last looked up in the background.
    fn flattened(&self, target: &str, qtype: u16, edges: &Edges) -> Vec<RData> {
        let pick = |ip: IpAddr| match ip {
            IpAddr::V4(a) if qtype == rtype::A => Some(RData::A(a)),
            IpAddr::V6(a) if qtype == rtype::AAAA => Some(RData::Aaaa(a)),
            _ => None,
        };
        let snap = self.store.snapshot();
        let has_edge = !(edges.v4.is_empty() && edges.v6.is_empty());
        let mut name = target.to_string();
        for _ in 0..MAX_CNAME_CHAIN {
            let Some(z) = snap.find_zone(&name) else {
                return self.flat.lookup(&name).into_iter().filter_map(pick).collect();
            };
            let records = z.records_for(&name);
            if has_edge && !z.zone.paused && records.iter().any(|r| r.proxied) {
                let ours = edges.v4.iter().map(|a| IpAddr::V4(*a)).chain(edges.v6.iter().map(|a| IpAddr::V6(*a)));
                return ours.filter_map(pick).collect();
            }
            match records.iter().find(|r| r.rtype == "CNAME") {
                Some(next) => name = next.content.clone(),
                None => return records.iter().filter_map(|r| r.content.parse().ok()).filter_map(pick).collect(),
            }
        }
        Vec::new()
    }
}

/// The delegation point (closest to the apex) at or above `name`, if any.
fn delegation<'a>(z: &ZoneSnap, name: &'a str) -> Option<&'a str> {
    let mut cut = None;
    let mut n = name;
    while n.len() > z.zone.name.len() {
        if z.names.get(n).is_some_and(|rs| rs.iter().any(|r| r.rtype == "NS")) {
            cut = Some(n);
        }
        n = parent(n);
    }
    cut
}

/// In-zone addresses for the targets of NS/MX/SRV records.
fn glue(z: &ZoneSnap, rrs: &[RR]) -> Vec<RR> {
    let mut out: Vec<RR> = Vec::new();
    for rr in rrs {
        let target = match &rr.data {
            RData::Ns(t) | RData::Mx { exchange: t, .. } | RData::Srv { target: t, .. } => t,
            _ => continue,
        };
        if out.iter().any(|g| &g.name == target) {
            continue;
        }
        let records = z.names.get(target).into_iter().flatten();
        out.extend(records.filter(|r| matches!(r.rtype.as_str(), "A" | "AAAA")).filter_map(|r| to_rr(r, target)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::testutil::query;
    use crate::store::testutil::{rec, temp_store};

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    struct Msg {
        rcode: u8,
        aa: bool,
        an: u16,
        ns: u16,
        ar: u16,
        raw: Vec<u8>,
    }

    fn ask(r: &Resolver, name: &str, qtype: u16) -> Msg {
        let raw = r.handle(&query(1, name, qtype, false), false, PEER).unwrap();
        let c = |i: usize| u16::from_be_bytes([raw[i], raw[i + 1]]);
        Msg { rcode: raw[3] & 0xF, aa: raw[2] & 0x04 != 0, an: c(6), ns: c(8), ar: c(10), raw }
    }

    fn contains(m: &Msg, bytes: &[u8]) -> bool {
        m.raw.windows(bytes.len()).any(|w| w == bytes)
    }

    fn setup() -> Resolver {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let add = |name: &str, t: &str, content: &str, proxied: bool| {
            let mut r = rec(name, t, content);
            r.proxied = proxied;
            store.create_record(&z, r).unwrap();
        };
        add("@", "A", "192.0.2.1", false);
        add("www", "CNAME", "example.com", false);
        add("ext", "CNAME", "target.example.org", false);
        add("*.wild", "A", "192.0.2.7", false);
        add("deep.a.b", "TXT", "hello", false);
        add("@", "MX", "mail.example.com", false);
        add("mail", "A", "192.0.2.25", false);
        add("sub", "NS", "ns.sub.example.com", false);
        add("ns.sub", "A", "192.0.2.53", false);
        add("app", "A", "198.51.100.9", true);
        add("loop1", "CNAME", "loop2.example.com", false);
        add("loop2", "CNAME", "loop1.example.com", false);
        Resolver {
            store: Arc::new(store),
            edge_v4: vec!["203.0.113.10".parse().unwrap()],
            edge_v6: vec![],
            geo: Arc::new(Geo::default()),
            health: Arc::default(),
            cname_base: None,
            name_servers: vec![],
            h3_port: None, h3_front: None, edge_ttl: 60,
            flat: Arc::default(), limits: Arc::default(),
            accelerate: false,
            rtt: Arc::default(),
        }
    }

    #[test]
    fn leaves_out_nodes_over_their_traffic_allowance() {
        use crate::limits::{Limits, State};
        use serde_json::json;
        use std::collections::BTreeMap;
        let mut r = setup();
        let mut nodes = Vec::new();
        for (name, ip) in [("us", "203.0.113.1"), ("eu", "203.0.113.2"), ("au", "203.0.113.3")] {
            nodes.push(r.store.save_node(None, json!({ "name": name, "ipv4": ip, "traffic_dns_gb": 1 })).unwrap());
        }
        // which of the three nodes a proxied name resolves to
        let answered = |r: &Resolver| {
            let m = ask(r, "app.example.com", rtype::A);
            let which: Vec<&str> = [("us", 1u8), ("eu", 2), ("au", 3)].iter().filter(|(_, last)| contains(&m, &[203, 0, 113, *last])).map(|(n, _)| *n).collect();
            assert_eq!(m.an as usize, which.len());
            which.join(" ")
        };
        let limited = |states: &[(&str, State)]| {
            let map: BTreeMap<String, State> = states.iter().map(|(n, s)| (n.to_string(), *s)).collect();
            r.store.set_limited_nodes(map).unwrap();
        };
        assert_eq!(answered(&r), "us eu au");
        // over the DNS threshold or over the hard limit: out of the answers
        limited(&[("eu", State::DnsLimited)]);
        assert_eq!(answered(&r), "us au");
        limited(&[("eu", State::DnsLimited), ("us", State::Limited)]);
        assert_eq!(answered(&r), "au");
        // somebody has to answer: rather a node that still serves than one that does not
        limited(&[("eu", State::DnsLimited), ("us", State::Limited), ("au", State::Limited)]);
        assert_eq!(answered(&r), "eu");
        limited(&[("eu", State::Throttled), ("us", State::Limited), ("au", State::DnsLimited)]);
        assert_eq!(answered(&r), "au", "a node at full speed before a slowed one");
        limited(&[("eu", State::Limited), ("us", State::Limited), ("au", State::Limited)]);
        assert_eq!(answered(&r), "us eu au");
        // steering rules fall through to their next node
        limited(&[("eu", State::DnsLimited)]);
        r.store.save_steering(None, json!({ "name": "all", "nodes": ["eu", "au", "us"] })).unwrap();
        assert_eq!(answered(&r), "au");

        // a node knows its own state before the configuration says so
        limited(&[]);
        assert_eq!(answered(&r), "eu");
        let own = Limits::default();
        own.configure("eu", Some(&nodes[1]));
        own.add(2_000_000_000);
        assert_eq!(own.own(), ("eu".to_string(), State::DnsLimited));
        r.limits = Arc::new(own);
        assert_eq!(answered(&r), "au");
        // deleting a node forgets its state
        limited(&[("us", State::Limited)]);
        r.store.delete_steering(&r.store.list_steering()[0].id).unwrap();
        r.store.delete_node(&nodes[0].id).unwrap();
        assert!(r.store.limited_nodes().is_empty());
    }

    #[tokio::test]
    async fn flattens_cnames_at_the_apex() {
        let r = setup();
        let zone = |name: &str, target: &str, proxied: bool| {
            let id = r.store.create_zone(name).unwrap().id;
            let mut cname = rec("@", "CNAME", target);
            cname.proxied = proxied;
            r.store.create_record(&id, cname).unwrap();
            id
        };
        // outside our zones: answered from the background lookups
        let outside = zone("outside.org", "localhost", false);
        r.store.create_record(&outside, rec("@", "MX", "mail.outside.org")).unwrap();
        r.store.create_record(&outside, rec("@", "TXT", "v=spf1 -all")).unwrap();
        let m = ask(&r, "outside.org", rtype::A);
        assert_eq!((m.rcode, m.aa, m.an, m.ns), (0, true, 0, 1), "nothing is known yet: no data, but no error either");
        assert_eq!(external_targets(&r.store.snapshot()), HashSet::from(["localhost".to_string()]));
        r.flat.refresh(&r.store.snapshot()).await;
        let m = ask(&r, "outside.org", rtype::A);
        assert!((m.rcode, m.aa, m.an) == (0, true, 1) && contains(&m, &[127, 0, 0, 1]), "one A record and no CNAME");
        assert!(!contains(&m, b"localhost"));
        // the CNAME itself is not visible, and does not stand in the way of the other types
        let m = ask(&r, "outside.org", rtype::CNAME);
        assert_eq!((m.rcode, m.an, m.ns), (0, 0, 1));
        assert_eq!(ask(&r, "outside.org", rtype::MX).an, 1);
        assert_eq!(ask(&r, "outside.org", rtype::TXT).an, 1);
        assert_eq!(ask(&r, "outside.org", rtype::SOA).an, 1);
        assert_eq!(ask(&r, "outside.org", rtype::NS).an, 2);
        // a lookup that fails keeps what was known; a target nobody refers to any more is dropped
        r.flat.table.write().unwrap().insert("gone.invalid".into(), vec!["192.0.2.99".parse().unwrap()]);
        r.flat.refresh(&r.store.snapshot()).await;
        assert!(r.flat.lookup("gone.invalid").is_empty() && !r.flat.lookup("localhost").is_empty());

        // into a zone we host: followed there (www -> apex -> 192.0.2.1), no lookup needed
        zone("inside.org", "www.example.com", false);
        let m = ask(&r, "inside.org", rtype::A);
        assert!(m.an == 1 && contains(&m, &[192, 0, 2, 1]));
        assert_eq!(ask(&r, "inside.org", rtype::AAAA).an, 0);
        // ... where a proxied name means the edge
        zone("via-edge.org", "app.example.com", false);
        let m = ask(&r, "via-edge.org", rtype::A);
        assert!(m.an == 1 && contains(&m, &[203, 0, 113, 10]) && !contains(&m, &[198, 51, 100, 9]));
        // a proxied apex CNAME is the edge itself
        zone("proxied.org", "origin.elsewhere.net", true);
        let m = ask(&r, "proxied.org", rtype::A);
        assert!(m.an == 1 && contains(&m, &[203, 0, 113, 10]));
        assert_eq!(external_targets(&r.store.snapshot()).len(), 2);
    }

    #[test]
    fn authoritative_answers() {
        let r = setup();

        let m = ask(&r, "example.com", rtype::A);
        assert!((m.rcode, m.aa, m.an) == (0, true, 1) && contains(&m, &[192, 0, 2, 1]));

        // CNAME chased inside the zone, left alone outside of it
        let m = ask(&r, "www.example.com", rtype::A);
        assert!(m.an == 2 && contains(&m, &[192, 0, 2, 1]));
        let m = ask(&r, "ext.example.com", rtype::A);
        assert_eq!((m.rcode, m.an), (0, 1));
        assert_eq!(ask(&r, "www.example.com", rtype::CNAME).an, 1);

        // apex SOA / NS are synthesized; MX carries glue
        assert_eq!(ask(&r, "example.com", rtype::SOA).an, 1);
        assert_eq!(ask(&r, "example.com", rtype::NS).an, 2);
        let m = ask(&r, "example.com", rtype::MX);
        assert_eq!((m.an, m.ar), (1, 1));

        // NODATA vs NXDOMAIN, both with SOA in the authority section
        let m = ask(&r, "example.com", rtype::AAAA);
        assert_eq!((m.rcode, m.an, m.ns), (0, 0, 1));
        let m = ask(&r, "nope.example.com", rtype::A);
        assert_eq!((m.rcode, m.an, m.ns), (3, 0, 1));
        // empty non-terminal exists => NODATA, not NXDOMAIN
        assert_eq!(ask(&r, "a.b.example.com", rtype::A).rcode, 0);
        assert_eq!(ask(&r, "b.example.com", rtype::TXT).rcode, 0);

        // not our zone
        let m = ask(&r, "example.org", rtype::A);
        assert_eq!((m.rcode, m.aa), (5, false));
        assert_eq!(ask(&r, "loop1.example.com", rtype::A).rcode, 2);
    }

    #[test]
    fn wildcards() {
        let r = setup();
        let m = ask(&r, "anything.wild.example.com", rtype::A);
        assert!(m.an == 1 && contains(&m, &[192, 0, 2, 7]));
        assert!(ask(&r, "x.y.wild.example.com", rtype::A).an == 1);
        let m = ask(&r, "anything.wild.example.com", rtype::TXT);
        assert_eq!((m.rcode, m.an), (0, 0));
        // "wild" itself is an empty non-terminal; the wildcard does not cover it
        assert_eq!(ask(&r, "wild.example.com", rtype::A).an, 0);
        // closest encloser of x.a.b is a.b (exists), which has no wildcard
        assert_eq!(ask(&r, "x.a.b.example.com", rtype::A).rcode, 3);
    }

    #[test]
    fn delegation_and_proxy() {
        let r = setup();
        let m = ask(&r, "host.sub.example.com", rtype::A);
        assert_eq!((m.rcode, m.aa, m.an, m.ns, m.ar), (0, false, 0, 1, 1));

        // proxied record: the origin address must never leak
        let m = ask(&r, "app.example.com", rtype::A);
        assert!(m.an == 1 && contains(&m, &[203, 0, 113, 10]) && !contains(&m, &[198, 51, 100, 9]));
        let m = ask(&r, "app.example.com", rtype::AAAA);
        assert_eq!((m.rcode, m.an), (0, 0));

        // without edge nodes configured, proxied records resolve to the origin
        let plain = Resolver { store: r.store.clone(), edge_v4: vec![], edge_v6: vec![], geo: Arc::new(Geo::default()), health: Arc::default(), cname_base: None, name_servers: vec![], h3_port: None, h3_front: None, edge_ttl: 60, flat: Arc::default(), limits: Arc::default(), accelerate: false, rtt: Arc::default() };
        assert!(contains(&ask(&plain, "app.example.com", rtype::A), &[198, 51, 100, 9]));
    }

    #[test]
    fn protocol_edge_cases() {
        let r = setup();
        let m = ask(&r, "example.com", rtype::ANY);
        assert!(m.an == 1 && contains(&m, b"RFC8482"));

        // responses are dropped, garbage is dropped, bad opcode is NOTIMP
        let mut q = query(1, "example.com", 1, false);
        q[2] |= 0x80;
        assert!(r.handle(&q, true, PEER).is_none());
        assert!(r.handle(&[1, 2, 3], true, PEER).is_none());
        let mut q = query(1, "example.com", 1, false);
        q[2] |= 0x28; // opcode 5 (UPDATE)
        assert_eq!(r.handle(&q, true, PEER).unwrap()[3] & 0xF, 4);

        // 0x20 case is echoed in the question
        let m = ask(&r, "ExAmPlE.cOm", rtype::A);
        assert!(m.an == 1 && contains(&m, b"ExAmPlE"));

        // large answers are truncated over UDP without EDNS, intact over TCP
        let z = r.store.list_zones()[0].id.clone();
        for i in 0..6 {
            r.store.create_record(&z, rec("big", "TXT", &format!("{i}{}", "x".repeat(200)))).unwrap();
        }
        let udp = r.handle(&query(1, "big.example.com", rtype::TXT, false), true, PEER).unwrap();
        assert!(udp.len() <= 512 && udp[2] & 0x02 != 0);
        let tcp = r.handle(&query(1, "big.example.com", rtype::TXT, false), false, PEER).unwrap();
        assert!(tcp.len() > 1200 && tcp[2] & 0x02 == 0);
    }

    #[test]
    fn steers_by_client_location() {
        use serde_json::json;
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let mut app = rec("app", "A", "198.51.100.9");
        app.proxied = true;
        store.create_record(&z, app).unwrap();
        store.save_node(None, json!({ "name": "us", "ipv4": "203.0.113.1", "ipv6": "2001:db8::1", "continents": ["NA", "SA"] })).unwrap();
        store.save_node(None, json!({ "name": "eu", "ipv4": "203.0.113.2", "continents": ["EU", "AF"] })).unwrap();
        let au = store.save_node(None, json!({ "name": "au", "ipv4": "203.0.113.3", "continents": ["AS", "OC"] })).unwrap();
        assert!(store.save_node(None, json!({ "name": "us", "ipv4": "203.0.113.9" })).is_err(), "names are unique");
        assert!(store.save_node(None, json!({ "name": "x", "continents": ["EU"] })).is_err(), "a node needs an address");
        assert!(store.save_node(None, json!({ "name": "x", "ipv4": "203.0.113.9", "continents": ["XX"] })).is_err());

        let (berlin, tokyo, lima, nowhere): (IpAddr, IpAddr, IpAddr, IpAddr) =
            ("192.0.2.10".parse().unwrap(), "192.0.2.20".parse().unwrap(), "192.0.2.30".parse().unwrap(), "192.0.2.99".parse().unwrap());
        let (cmcc, cucc, ctcc): (IpAddr, IpAddr, IpAddr) =
            ("192.0.2.40".parse().unwrap(), "192.0.2.41".parse().unwrap(), "192.0.2.42".parse().unwrap());
        let at = |continent: &str, country: &str, asn: u32, org: &str| crate::geo::Location {
            continent: Some(continent.into()),
            country: Some(country.into()),
            region: None,
            asn: Some(asn),
            as_org: Some(org.into()),
        };
        let mut geo = Geo::default();
        geo.fixed = [
            (berlin, at("EU", "DE", 3320, "deutsche telekom ag")),
            (tokyo, at("AS", "JP", 2516, "kddi corporation")),
            (lima, at("SA", "PE", 6147, "telefonica del peru")),
            (cmcc, at("AS", "CN", 9808, "china mobile communications group co., ltd.")),
            (cucc, at("AS", "CN", 4837, "china unicom china169 backbone")),
            (ctcc, at("AS", "CN", 4134, "chinanet")),
        ]
        .into();
        let r = Resolver {
            store: Arc::new(store),
            edge_v4: vec![],
            edge_v6: vec![],
            geo: Arc::new(geo),
            health: Arc::default(),
            cname_base: Some("cdn.example.net".into()),
            name_servers: vec!["ns1.example.net".into(), "ns2.example.net".into()],
            h3_port: Some(4433), h3_front: None, edge_ttl: 60,
            flat: Arc::default(), limits: Arc::default(),
            accelerate: false,
            rtt: Arc::default(),
        };
        let from = |peer: IpAddr, name: &str, qtype: u16| {
            let raw = r.handle(&query(1, name, qtype, false), false, peer).unwrap();
            let an = u16::from_be_bytes([raw[6], raw[7]]);
            (an, raw)
        };
        let has = |raw: &[u8], last: u8| raw.windows(4).any(|w| w == [203, 0, 113, last]);

        // each client gets the node assigned to its continent
        let (an, raw) = from(berlin, "app.example.com", rtype::A);
        assert!(an == 1 && has(&raw, 2));
        let (an, raw) = from(tokyo, "app.example.com", rtype::A);
        assert!(an == 1 && has(&raw, 3));
        let (an, raw) = from(lima, "app.example.com", rtype::A);
        assert!(an == 1 && has(&raw, 1));
        assert_eq!(from(lima, "app.example.com", rtype::AAAA).0, 1);
        assert_eq!(from(berlin, "app.example.com", rtype::AAAA).0, 0, "the eu node has no IPv6");
        // unknown location: every node
        assert_eq!(from(nowhere, "app.example.com", rtype::A).0, 3);

        // names under the CNAME base resolve to the edge without any zone
        let (an, raw) = from(tokyo, "anything.cdn.example.net", rtype::A);
        assert!(an == 1 && has(&raw, 3));
        assert_eq!(from(tokyo, "cdn.example.net", rtype::NS).0, 2);
        assert_eq!(from(tokyo, "cdn.example.net", rtype::SOA).0, 1);
        let (an, raw) = from(tokyo, "x.cdn.example.net", rtype::TXT);
        assert_eq!((an, raw[3] & 0xF, u16::from_be_bytes([raw[8], raw[9]])), (0, 0, 1));

        // HTTPS records advertise HTTP/3 on its own port, then HTTP/2
        for name in ["app.example.com", "x.cdn.example.net"] {
            let (an, raw) = from(tokyo, name, rtype::HTTPS);
            assert_eq!(an, 2, "{name}");
            // priority 1, target ".", alpn=h3, port=4433
            assert!(raw.windows(15).any(|w| w == [0, 1, 0, 0, 1, 0, 3, 2, b'h', b'3', 0, 3, 0, 2, 0x11]), "{name}");
            assert!(raw.windows(10).any(|w| w == [0, 2, 0, 0, 1, 0, 3, 2, b'h', b'2']), "{name}");
        }

        // answers under the CNAME base live as long as configured
        let ttl_of = |raw: &[u8]| u32::from_be_bytes(raw[raw.len() - 10..raw.len() - 6].try_into().unwrap());
        assert_eq!(ttl_of(&from(tokyo, "anything.cdn.example.net", rtype::A).1), 60);
        let patient = Resolver { store: r.store.clone(), geo: r.geo.clone(), cname_base: r.cname_base.clone(), edge_ttl: 300, edge_v4: vec![], edge_v6: vec![], health: Arc::default(), name_servers: vec![], h3_port: None, h3_front: None, flat: Arc::default(), limits: Arc::default(), accelerate: false, rtt: Arc::default() };
        let raw = patient.handle(&query(1, "anything.cdn.example.net", rtype::A, false), false, tokyo).unwrap();
        assert_eq!((u16::from_be_bytes([raw[6], raw[7]]), ttl_of(&raw)), (1, 300));

        // with an HTTP/3 front, its port is advertised -- for the names its certificate covers
        let cert_path = std::env::temp_dir().join(format!("fucf-front-{}.crt", uuid::Uuid::new_v4().simple()));
        let cert = rcgen::generate_simple_self_signed(vec!["app.example.com".to_string()]).unwrap().cert.pem();
        std::fs::write(&cert_path, cert).unwrap();
        let front = Arc::new(crate::edge::front::Front::new(443, Some(cert_path.clone())));
        std::fs::remove_file(&cert_path).unwrap();
        let fronted = Resolver { h3_front: Some(front), ..patient };
        let ask = |name: &str| fronted.handle(&query(1, name, rtype::HTTPS, false), false, tokyo).unwrap();
        let raw = ask("app.example.com");
        // priority 1, target ".", alpn=h3 and nothing else (port 443 is the default); then HTTP/2
        assert!(raw.windows(16).any(|w| w == [0, 1, 0, 0, 1, 0, 3, 2, b'h', b'3', 0, 0, 0x29, 0, 0, 0] || w[..10] == [0, 1, 0, 0, 1, 0, 3, 2, b'h', b'3']), "{raw:?}");
        assert!(!raw.windows(4).any(|w| w == [0, 3, 0, 2]), "no port parameter: {raw:?}");
        assert_eq!(u16::from_be_bytes([raw[6], raw[7]]), 2);
        // a name it does not cover: HTTP/3 would fail there, so nothing is said (there is no listener of our own here)
        assert_eq!(u16::from_be_bytes([ask("x.cdn.example.net")[6], ask("x.cdn.example.net")[7]]), 0);

        // EDNS Client Subnet wins over the resolver's address and is echoed with a scope
        let mut q = query(1, "app.example.com", rtype::A, true);
        let rdlen_at = q.len() - 2;
        q[rdlen_at..].copy_from_slice(&[0, 11]);
        q.extend_from_slice(&[0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2]);
        let raw = r.handle(&q, true, lima).unwrap();
        assert_eq!(u16::from_be_bytes([raw[6], raw[7]]), 3, "answered for the subnet (location unknown), not for the resolver in Lima");
        assert!(raw.windows(7).any(|w| w == [0, 1, 24, 24, 192, 0, 2]), "ECS echoed with scope /24");

        // steering rules: operator-level routing for one country, with failover order
        let rule = |v| r.store.save_steering(None, v).unwrap();
        rule(json!({ "name": "CN unicom", "countries": ["cn"], "asns": [4837], "nodes": ["eu", "au"], "priority": 1 }));
        rule(json!({ "name": "CN telecom", "countries": ["CN"], "as_orgs": ["ChinaNet", "china telecom"], "nodes": ["au", "eu"], "priority": 2 }));
        rule(json!({ "name": "CN other", "countries": ["CN"], "nodes": ["au", "eu"], "priority": 9 }));
        assert!(r.store.save_steering(None, json!({ "name": "bad", "nodes": ["nope"] })).is_err());
        let node_of = |peer: IpAddr| {
            let (an, raw) = from(peer, "app.example.com", rtype::A);
            assert_eq!(an, 1);
            (1..=3u8).find(|n| has(&raw, *n)).unwrap()
        };
        assert_eq!((node_of(cucc), node_of(ctcc), node_of(cmcc)), (2, 3, 3));
        assert_eq!(node_of(tokyo), 3, "non-CN clients still follow the continent assignment");
        // health-based failover follows the rule's order and never reaches for the us node
        r.health.set("eu", false);
        assert_eq!(node_of(cucc), 3, "unicom falls back to au, not us");
        let (an, raw) = from(berlin, "app.example.com", rtype::A);
        assert!(an == 2 && !has(&raw, 2), "the down node is not answered to anyone");
        r.health.set("eu", true);
        r.health.set("au", false);
        assert_eq!((node_of(ctcc), node_of(cmcc)), (2, 2));
        r.health.set("au", true);
        assert!(r.store.delete_node(&au.id).is_err(), "nodes referenced by a rule cannot be deleted");

        // DNS-level blocking: matching visitors are refused, everyone else is unaffected
        let block = r.store.save_steering(None, json!({ "name": "no peru", "countries": ["PE"], "action": "block", "priority": -5 })).unwrap();
        let (_, raw) = from(lima, "app.example.com", rtype::A);
        assert_eq!(raw[3] & 0xF, 5);
        assert_eq!(from(lima, "x.cdn.example.net", rtype::A).1[3] & 0xF, 5);
        assert_eq!(node_of(tokyo), 3);
        r.store.delete_steering(&block.id).unwrap();
        // HTTP/3 switched off for the zone: no HTTPS record advertises it
        r.store.update_setting(&z, "http3", json!(false)).unwrap();
        assert_eq!(from(tokyo, "app.example.com", rtype::HTTPS).0, 0);
        r.store.update_setting(&z, "http3", json!("on")).unwrap();

        // a zone pinned to one node ignores location; disabled nodes are never answered
        r.store.update_setting(&z, "edge_nodes", json!(["us"])).unwrap();
        let (an, raw) = from(tokyo, "app.example.com", rtype::A);
        assert!(an == 1 && has(&raw, 1));
        r.store.update_setting(&z, "edge_nodes", json!([])).unwrap();
        r.store.save_node(Some(&au.id), json!({ "enabled": false })).unwrap();
        let (an, raw) = from(tokyo, "app.example.com", rtype::A);
        assert!(an == 2 && !has(&raw, 3), "no enabled node serves AS: fall back to all enabled nodes");
        assert_eq!(node_of(ctcc), 2, "a disabled node is skipped in steering rules as well");
    }

    #[test]
    fn a_fastest_rule_sends_a_network_to_the_node_that_answers_it_soonest() {
        use serde_json::json;
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let mut app = rec("app", "A", "198.51.100.9");
        app.proxied = true;
        store.create_record(&z, app).unwrap();
        for (name, ip) in [("a", "203.0.113.1"), ("b", "203.0.113.2"), ("c", "203.0.113.3")] {
            store.save_node(None, json!({ "name": name, "ipv4": ip, "continents": ["AS"] })).unwrap();
        }
        assert!(store.save_steering(None, json!({ "name": "no nodes", "countries": ["CN"], "action": "route" })).is_err());
        store.save_steering(None, json!({ "name": "cn", "countries": ["CN"], "action": "fastest", "nodes": ["a", "b"] })).unwrap();
        let visitor: IpAddr = "192.0.2.40".parse().unwrap();
        let loc = crate::geo::Location { continent: Some("AS".into()), country: Some("CN".into()), region: Some("JS".into()), asn: Some(4134), as_org: None };
        let mut geo = Geo::default();
        geo.fixed = [(visitor, loc.clone())].into();
        let rtt = Arc::new(crate::rtt::Rtt::default());
        let r = Resolver { store: Arc::new(store), edge_v4: vec![], edge_v6: vec![], geo: Arc::new(geo), health: Arc::default(), cname_base: None, name_servers: vec![], h3_port: None, h3_front: None, edge_ttl: 60, flat: Arc::default(), limits: Arc::default(), accelerate: false, rtt: rtt.clone() };
        let answered = |r: &Resolver| -> HashSet<[u8; 4]> {
            (0..400)
                .map(|i| {
                    let raw = r.handle(&query(i, "app.example.com", rtype::A, false), false, visitor).unwrap();
                    raw[raw.len() - 4..].try_into().unwrap()
                })
                .collect()
        };
        // nothing measured: the candidates of the rule in turn, never the node it does not name
        assert_eq!(answered(&r), HashSet::from([[203, 0, 113, 1], [203, 0, 113, 2]]));
        // b answers that network sooner than a (as b told): nearly always b, a now and then to keep measuring it
        let told = |ms: u64| {
            let there = crate::rtt::Rtt::default();
            (0..10).for_each(|_| there.sample(&loc, Duration::from_millis(ms)));
            there.take_changed()
        };
        rtt.merge("a", &told(180));
        rtt.merge("b", &told(45));
        let to_b = (0..400).filter(|i| r.handle(&query(*i, "app.example.com", rtype::A, false), false, visitor).unwrap().ends_with(&[203, 0, 113, 2])).count();
        assert!((340..400).contains(&to_b), "{to_b} of 400 answers went to the faster node");
        // the answers that point at the edge live as long as configured (at most the usual 300 seconds)
        let raw = r.handle(&query(1, "app.example.com", rtype::A, false), false, visitor).unwrap();
        assert_eq!(u32::from_be_bytes(raw[raw.len() - 10..raw.len() - 6].try_into().unwrap()), 60);
    }

    #[test]
    fn probabilistic_offload_proximity_fallback_and_port53_silence() {
        use crate::limits::{Limits, State};
        use serde_json::json;
        use std::collections::BTreeMap;

        let mut r = setup();
        r.cname_base = Some("cdn.example.net".into());
        let sgp = r.store.save_node(None, json!({
            "name": "sgp", "ipv4": "203.0.113.10", "continents": ["AS"],
            "traffic_dns_gb": 400, "traffic_limit_gb": 700,
            "dns_offload_mode": "linear", "dns_silent_on_limit": true
        })).unwrap();
        r.store.save_node(None, json!({ "name": "au", "ipv4": "203.0.113.20", "continents": ["OC"] })).unwrap();
        r.store.save_node(None, json!({ "name": "us", "ipv4": "203.0.113.30", "continents": ["NA"] })).unwrap();

        let tokyo: IpAddr = "192.0.2.20".parse().unwrap();
        let mut geo = Geo::default();
        geo.fixed.insert(tokyo, crate::geo::Location {
            continent: Some("AS".into()), country: Some("JP".into()), region: None, asn: None, as_org: None
        });
        r.geo = Arc::new(geo);

        let ask_from = |r: &Resolver, peer: IpAddr, name: &str| {
            r.handle(&query(1, name, rtype::A, false), true, peer)
        };
        let has_last = |raw: &[u8], last: u8| raw.windows(4).any(|w| w == [203, 0, 113, last]);

        // Tier 1 (<400 GB): Tokyo gets sgp
        let raw = ask_from(&r, tokyo, "app.example.com").unwrap();
        assert!(has_last(&raw, 10) && !has_last(&raw, 20));

        // Tier 2 (550 GB = 50% linear offload): Tokyo splits between sgp and OC fallback (au), never us
        r.store.set_limited_state(
            BTreeMap::from([("sgp".into(), State::DnsLimited)]),
            BTreeMap::from([("sgp".into(), 50u8)]),
        ).unwrap();
        let (mut got_sgp, mut got_au, mut got_us) = (0usize, 0usize, 0usize);
        for _ in 0..200 {
            let raw = ask_from(&r, tokyo, "app.example.com").unwrap();
            if has_last(&raw, 10) { got_sgp += 1; }
            if has_last(&raw, 20) { got_au += 1; }
            if has_last(&raw, 30) { got_us += 1; }
        }
        assert!(got_sgp > 50 && got_au > 50 && got_us == 0, "expected ~50/50 sgp/au split, got sgp={got_sgp} au={got_au} us={got_us}");

        // Error-page asset host (`limit.cdn.example.net`) strictly avoids DnsLimited/Limited nodes
        for _ in 0..20 {
            let raw = ask_from(&r, tokyo, "limit.cdn.example.net").unwrap();
            assert!(!has_last(&raw, 10) && has_last(&raw, 20), "assets must come from ample-traffic node (au)");
        }

        // Tier 3 (700 GB+): sgp never appears globally; Tokyo goes 100% to au
        r.store.set_limited_state(
            BTreeMap::from([("sgp".into(), State::Limited)]),
            BTreeMap::from([("sgp".into(), 100u8)]),
        ).unwrap();
        for _ in 0..20 {
            let raw = ask_from(&r, tokyo, "app.example.com").unwrap();
            assert!(!has_last(&raw, 10) && has_last(&raw, 20));
        }

        // Port 53 silence on the node itself once >= 400 GB, while loopback still answers
        let own = Limits::default();
        own.configure("sgp", Some(&sgp));
        own.add(450 * 1_000_000_000);
        assert!(own.dns_silent());
        r.limits = Arc::new(own);
        assert!(ask_from(&r, tokyo, "app.example.com").is_none(), "external peer gets no reply on port 53");
        assert!(ask_from(&r, PEER, "app.example.com").is_some(), "loopback still answers for local health checks");
    }

    #[test]
    fn region_steering_and_gfw_cn_scheduling() {
        use crate::geo::Location;
        use crate::gfw::GfwStatus;
        use serde_json::json;
        use std::collections::BTreeMap;

        let mut r = setup();
        r.store.save_node(None, json!({ "name": "jp", "ipv4": "203.0.113.10", "ipv6": "2001:db8::10", "continents": [] })).unwrap();
        r.store.save_node(None, json!({ "name": "sgp", "ipv4": "203.0.113.20", "ipv6": "2001:db8::20", "continents": ["AS"] })).unwrap();
        r.store.save_steering(None, json!({
            "name": "East China -> jp",
            "countries": ["CN"],
            "regions": ["JS", "ZJ", "SH", "SD", "AH"],
            "nodes": ["jp", "sgp"],
            "priority": 1,
        })).unwrap();

        let shanghai: IpAddr = "198.51.100.1".parse().unwrap();
        let guangdong: IpAddr = "198.51.100.2".parse().unwrap();
        let mut geo = Geo::default();
        geo.fixed.insert(shanghai, Location { continent: Some("AS".into()), country: Some("CN".into()), region: Some("SH".into()), ..Default::default() });
        geo.fixed.insert(guangdong, Location { continent: Some("AS".into()), country: Some("CN".into()), region: Some("GD".into()), ..Default::default() });
        r.geo = Arc::new(geo);

        let ask_q = |peer: IpAddr, qt: u16| r.handle(&query(1, "app.example.com", qt, false), true, peer).unwrap();
        let has_v4 = |raw: &[u8], last: u8| raw.windows(4).any(|w| w == [203, 0, 113, last]);
        let has_v6 = |raw: &[u8], last: u8| raw.windows(16).any(|w| w == Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, last as u16).octets());

        // Shanghai (SH) gets jp; Guangdong (GD) does NOT match regions and gets sgp.
        assert!(has_v4(&ask_q(shanghai, rtype::A), 10));
        assert!(has_v6(&ask_q(shanghai, rtype::AAAA), 0x10));
        assert!(has_v4(&ask_q(guangdong, rtype::A), 20) && !has_v4(&ask_q(guangdong, rtype::A), 10));

        // If jp's IPv4 TCP is blocked in CN while IPv6 TCP is fine:
        // Shanghai A falls back to sgp, while Shanghai AAAA still resolves to jp!
        r.store.set_gfw_status(BTreeMap::from([(
            "jp".into(),
            GfwStatus { v4_tcp: Some(false), v4_udp: Some(false), v6_tcp: Some(true), v6_udp: Some(true), checked_at: String::new() },
        )])).unwrap();
        assert!(has_v4(&ask_q(shanghai, rtype::A), 20), "CN A must skip v4_tcp-blocked jp");
        assert!(has_v6(&ask_q(shanghai, rtype::AAAA), 0x10), "CN AAAA keeps v6_tcp-healthy jp");
    }

    #[test]
    fn decoy_names_resolve_to_the_node_with_the_most_room() {
        use crate::limits::State;
        use serde_json::json;
        use std::collections::BTreeMap;
        let r = setup();
        let zone = r.store.snapshot().find_zone("example.com").unwrap().zone.id.clone();
        r.store.save_node(None, json!({ "name": "small", "ipv4": "203.0.113.1", "traffic_limit_gb": 100 })).unwrap();
        r.store.save_node(None, json!({ "name": "big", "ipv4": "203.0.113.2", "ipv6": "2001:db8::2", "traffic_limit_gb": 2000 })).unwrap();
        r.store.save_node(None, json!({ "name": "free", "ipv4": "203.0.113.3" })).unwrap();
        r.store.save_node(None, json!({ "name": "jp", "ipv4": "203.0.113.4", "role": "accelerate", "accel_hosts": ["*.example.com"] })).unwrap();

        // off: a name that does not exist does not
        assert_eq!(ask(&r, "nothing.example.com", rtype::A).rcode as u16, rcode::NXDOMAIN);
        r.store.update_setting(&zone, "decoy_subdomains", json!(true)).unwrap();

        // on: the node without a limit, then the one with the larger limit; never an accelerate node
        let m = ask(&r, "nothing.example.com", rtype::A);
        assert!(m.rcode == 0 && m.an == 1 && contains(&m, &[203, 0, 113, 3]), "free first");
        let m = ask(&r, "a.b.c.example.com", rtype::AAAA);
        assert!(m.an == 1 && contains(&m, &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets()), "the only node with IPv6");
        let m = ask(&r, "nothing.example.com", rtype::TXT);
        assert!(m.rcode == 0 && m.an == 0 && m.ns == 1, "NODATA for other types");
        r.store.set_limited_nodes(BTreeMap::from([("free".to_string(), State::Throttled)])).unwrap();
        assert!(contains(&ask(&r, "nothing.example.com", rtype::A), &[203, 0, 113, 2]), "then by the size of the limit");

        // what exists stays as it is: records, wildcards, empty non-terminals, delegations
        assert!(contains(&ask(&r, "mail.example.com", rtype::A), &[192, 0, 2, 25]));
        assert!(contains(&ask(&r, "x.wild.example.com", rtype::A), &[192, 0, 2, 7]));
        let ent = ask(&r, "a.b.example.com", rtype::A);
        assert!(ent.rcode == 0 && ent.an == 0, "empty non-terminal");
        assert!(!ask(&r, "x.sub.example.com", rtype::A).aa, "delegated");
        let snap = r.store.snapshot();
        let z = snap.find_zone("example.com").unwrap();
        assert!(z.is_decoy("nothing.example.com") && !z.is_decoy("mail.example.com") && !z.is_decoy("example.com"));
        assert!(!z.is_decoy("x.sub.example.com") && !z.is_decoy("a.b.example.com") && !z.is_decoy("x.wild.example.com"));
        assert!(!z.is_decoy("badexample.com"));
        // the CNAME base (health probes, the over-limit notice's assets) and the panel are the node's own
        crate::store::reserve_names(vec!["cdn.example.com".into(), "panel.example.com".into()]);
        assert!(!z.is_decoy("cdn.example.com") && !z.is_decoy("limit.cdn.example.com") && !z.is_decoy("panel.example.com"));
        assert!(z.is_decoy("xcdn.example.com") && z.is_decoy("panel2.example.com"));
    }

    #[test]
    fn accelerate_suppresses_public_dns_but_allows_loopback() {
        let mut r = setup();
        r.accelerate = true;
        let public_peer: IpAddr = "203.0.113.55".parse().unwrap();
        assert!(r.handle(&query(1, "app.example.com", rtype::A, false), true, public_peer).is_none());
        assert!(r.handle(&query(2, "app.example.com", rtype::A, false), false, public_peer).is_none());
        assert!(r.handle(&query(3, "app.example.com", rtype::A, false), true, PEER).is_some());
    }

    #[test]
    fn accelerate_node_accel_hosts_dns_filtering() {
        use serde_json::json;
        let r = setup();
        let z = r.store.create_zone("accel.test").unwrap().id;
        for sub in ["allowed", "sub.wild", "blocked"] {
            let mut r_in = rec(sub, "A", "198.51.100.99");
            r_in.proxied = true;
            r.store.create_record(&z, r_in).unwrap();
        }
        r.store.save_node(None, json!({ "name": "peer1", "ipv4": "192.0.2.1", "continents": ["AS"] })).unwrap();
        r.store.save_node(None, json!({
            "name": "accel1",
            "ipv4": "192.0.2.2",
            "continents": ["AS"],
            "role": "accelerate",
            "accel_hosts": ["allowed.accel.test", "*.wild.accel.test"]
        })).unwrap();
        r.store.save_node(None, json!({
            "name": "accel-empty",
            "ipv4": "192.0.2.3",
            "continents": ["AS"],
            "role": "accelerate",
            "accel_hosts": []
        })).unwrap();
        r.store.save_steering(None, json!({ "name": "prefer-accel", "nodes": ["accel-empty", "accel1", "peer1"], "priority": 1 })).unwrap();

        assert!(contains(&ask(&r, "allowed.accel.test", rtype::A), &[192, 0, 2, 2]));
        assert!(contains(&ask(&r, "sub.wild.accel.test", rtype::A), &[192, 0, 2, 2]));
        assert!(contains(&ask(&r, "blocked.accel.test", rtype::A), &[192, 0, 2, 1]));
    }
}
