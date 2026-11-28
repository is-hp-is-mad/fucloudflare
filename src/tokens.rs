//! API tokens the Cloudflare way: a token holds policies, each allowing (or
//! denying) a set of permission groups on a set of resources, optionally
//! only from some addresses and only for a while. The owner's role still
//! bounds what a token can do: a viewer's token never writes.
//!
//! Resources are named like Cloudflare's: `com.cloudflare.api.account.zone.<zone id>`
//! (or `.zone.*`), `com.cloudflare.api.account.<account id>` (or `.account.*`,
//! optionally holding zone resources), `com.cloudflare.api.user.<user id>`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::net::IpAddr;
use std::sync::LazyLock;

/// The one account everything here belongs to (Cloudflare clients look it up).
pub fn account_id() -> &'static str {
    static ID: LazyLock<String> = LazyLock::new(|| {
        let d = ring::digest::digest(&ring::digest::SHA256, b"fucloudflare account");
        d.as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect()
    });
    &ID
}

pub const ACCOUNT_NAME: &str = "fucloudflare";

const ZONE: &str = "com.cloudflare.api.account.zone";
const ACCOUNT: &str = "com.cloudflare.api.account";
const USER: &str = "com.cloudflare.api.user";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Zone,
    Account,
    User,
}

impl Scope {
    fn key(self) -> &'static str {
        match self {
            Scope::Zone => ZONE,
            Scope::Account => ACCOUNT,
            Scope::User => USER,
        }
    }
}

/// What part of the API a request is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Zone,
    ZoneSettings,
    Dns,
    CachePurge,
    Firewall,
    Ssl,
    OriginRules,
    RedirectRules,
    TransformRules,
    CacheRules,
    WorkersRoutes,
    EmailRouting,
    Spectrum,
    Analytics,
    /// The request log (visitor addresses included) and its push jobs.
    Logs,
    /// Waiting rooms (crate::edge::waiting): they decide who reaches the origin.
    WaitingRooms,
    /// API Shield (crate::edge::apishield): the API inventory and what the
    /// edge does with requests that break it.
    ApiGateway,
    /// Page Shield (crate::edge::pageshield): the policy sent with the zone's pages and the scripts they load.
    PageShield,
    WorkersScripts,
    WorkersKv,
    D1,
    Fleet,
    AccountAnalytics,
    AuditLogs,
    Backup,
    Notifications,
    Tokens,
    /// IP lists (crate::lists): kept for the whole account, used by the
    /// rules of any zone.
    Lists,
    /// The human-check widgets that sites embed (crate::edge::widget), kept
    /// for the whole account like Cloudflare's Turnstile sites.
    Turnstile,
}

impl Area {
    fn scope(self) -> Scope {
        match self {
            Area::WorkersScripts | Area::WorkersKv | Area::D1 | Area::Fleet | Area::AccountAnalytics | Area::AuditLogs | Area::Backup | Area::Lists | Area::Notifications | Area::Turnstile => {
                Scope::Account
            }
            Area::Tokens => Scope::User,
            _ => Scope::Zone,
        }
    }
}

pub struct Group {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    area: Area,
    write: bool,
}

macro_rules! groups {
    ($( $id:literal $name:literal $area:ident $write:literal $desc:literal ;)*) => {
        pub static GROUPS: &[Group] = &[ $( Group { id: $id, name: $name, area: Area::$area, write: $write, description: $desc }, )* ];
    };
}

groups! {
    "c8fed203ed3043cba015a93ad1616f1f" "Zone Read" Zone false "List zones and read their details";
    "e6d2666161e84845a636613608cee8d5" "Zone Write" Zone true "Add, change, pause and delete zones";
    "517b21aee92c4d89936c976ba6e4be55" "Zone Settings Read" ZoneSettings false "Read zone settings and DNSSEC";
    "3030687196b94b638145a3953da2b699" "Zone Settings Write" ZoneSettings true "Change zone settings and DNSSEC (decoy subdomains included)";
    "82e64a83756745bbbb1c9c2701bf816b" "DNS Read" Dns false "Read DNS records";
    "4755a26eedb94da69e1066d98aa820be" "DNS Write" Dns true "Change DNS records: proxying and per-record origin (port, SNI, Host, node) included";
    "e17beae8b8cb423a99b1730f21238bed" "Cache Purge" CachePurge true "Purge the cache";
    "4ec32dfcb35641c5bb32d5ef1ab963b4" "Firewall Services Read" Firewall false "Read firewall rules, rate limits and security events";
    "43137f8d07884d3198dc0ee77ca6e79b" "Firewall Services Write" Firewall true "Change firewall rules (human check included) and rate limits";
    "7b7216b327b04b8fbc8f524e1f9b7531" "SSL and Certificates Read" Ssl false "Read certificate packs, custom certificates and custom hostnames";
    "c03055bc037c4ea9afb9a9f104b7b721" "SSL and Certificates Write" Ssl true "Order, retry and upload certificates; add custom hostnames";
    "a6b3a2d2b9f04d7f8ad2f54b7b5bd1a1" "Origin Rules Read" OriginRules false "Read origin rules";
    "b7c4b3e3cae14e8f9be3e65c8c6ce2b2" "Origin Rules Write" OriginRules true "Change origin rules";
    "c8d5c4f4dbf2408fa0f4f76d9d7df3c3" "Dynamic Redirect Read" RedirectRules false "Read redirect rules";
    "d9e6d5a5ec034190b1a5a87eae8e04d4" "Dynamic Redirect Write" RedirectRules true "Change redirect rules";
    "eaf7e6b6fd14420ac2b6b98fbf9f15e5" "Transform Rules Read" TransformRules false "Read transform rules";
    "fb08f7c70e25431bd3c7ca90a0a026f6" "Transform Rules Write" TransformRules true "Change transform rules";
    "0c1908d81f3644209ed8db01b1b13707" "Cache Rules Read" CacheRules false "Read cache rules";
    "1d2a19e92047455aaf9ec12c2c24818a" "Cache Rules Write" CacheRules true "Change cache rules";
    "2e3b2afa3158466bb0afd23d3d35592b" "Workers Routes Read" WorkersRoutes false "Read Workers routes";
    "28f4b596e7d643029c524985477ae49a" "Workers Routes Write" WorkersRoutes true "Change Workers routes";
    "5272e56105d04b5897466995b9bd4643" "Email Routing Rules Read" EmailRouting false "Read e-mail routing";
    "79b3ec0d10ce4148a8f8bdc0cc5f97f2" "Email Routing Rules Write" EmailRouting true "Change e-mail routing rules and the DKIM key";
    "3f4c3d0b2a6947a3b0c5d1e2f3a4b5c6" "Zone Spectrum Read" Spectrum false "Read Spectrum applications";
    "4a5d4e1c3b7a48b4c1d6e2f3a4b5c6d7" "Zone Spectrum Write" Spectrum true "Change Spectrum applications";
    "9c88f9c5bce24ce7af9a958ba9c504db" "Analytics Read" Analytics false "Read zone analytics";
    "26b532d014a248b19255e21c73660d14" "Logs Read" Logs false "Read the request log (visitor addresses included) and the log push jobs";
    "ddf5587f37134125868a20ce6a3f1420" "Logs Write" Logs true "Change the jobs that push the request log to another server";
    "a4ea74d0fb8545a0a16b1c15e6429a26" "Waiting Rooms Read" WaitingRooms false "Read waiting rooms";
    "f67470076141448daf90b83b8aeb1a3d" "Waiting Rooms Write" WaitingRooms true "Change waiting rooms, which decide who reaches the origin";
    "45c4f56798224e3f9ba6d7ca4c24ca5e" "API Gateway Read" ApiGateway false "Read the API operations of API Shield and its settings";
    "14528d5b247140e38a5be7baccbe95dd" "API Gateway Write" ApiGateway true "Change the API operations of API Shield (OpenAPI uploads included) and what it blocks";
    "4c2a9f0e81d54b6fa3e07c19d2b8e655" "Page Shield Read" PageShield false "Read Page Shield settings and the scripts the zone's pages load";
    "9e5b3d71c0a2486f8b14d6e2a7c39f08" "Page Shield Write" PageShield true "Change Page Shield: the content security policy sent with the zone's pages";
    "1a71c399035b4950a1bd1466bbe4f420" "Workers Scripts Read" WorkersScripts false "Read Workers scripts and their settings";
    "e086da7e2179491d91ee5f35b3ca210a" "Workers Scripts Write" WorkersScripts true "Upload, configure, run and delete Workers scripts";
    "8b47d2786a534c08a1f94ee8f9f599ef" "Workers KV Storage Read" WorkersKv false "Read Workers KV namespaces and values";
    "f7f0eda5697f475c90846e879bab8666" "Workers KV Storage Write" WorkersKv true "Change Workers KV namespaces and values";
    "192192df92ee43ac90f2aeeffce67e35" "D1 Read" D1 false "Read D1 databases";
    "09b2857d1c31407795e75e3fed8617a1" "D1 Write" D1 true "Create, query and delete D1 databases";
    "5b6c5d2e4f8b49c5d2e7f3a4b5c6d7e8" "Fleet Read" Fleet false "Read nodes, fleet state, steering, local proxy rules and releases";
    "6c7d6e3f5a9c4ad6e3f8a4b5c6d7e8f9" "Fleet Write" Fleet true "Change nodes, steering and local proxy rules; act on nodes; roll out releases";
    "b89a480218d04ceb98b4fe57ca29dc1f" "Account Analytics Read" AccountAnalytics false "Read account-wide analytics";
    "b05b28e839c54467a7d6cba5d3abb5a3" "Audit Logs Read" AuditLogs false "Read the audit log";
    "7d8e7f405b0d4be7f4a9b5c6d7e8f9a0" "Backup Read" Backup false "Download a full backup (everything, secrets included: guard the token)";
    "1ac9ee17d4e442a0ad48b35521db27f3" "Account Filter Lists Read" Lists false "Read IP lists and their items";
    "9766e73b0e034208a4262fa492b80b2a" "Account Filter Lists Write" Lists true "Change IP lists and their items (the rules that use a list follow it)";
    "88f2d624e0de496d81a02bd4776852a1" "Notifications Read" Notifications false "Read alert channels (secrets masked) and the alerts that fire";
    "8b36fa19ef584f57aa26509f91963eb5" "Notifications Write" Notifications true "Change alert channels and send test messages";
    "7fcfc7f29e92439b935403501f842172" "Turnstile Sites Read" Turnstile false "Read the human-check widgets (never their secrets)";
    "3c07d4b298994a9397d3f2df9c6efe4e" "Turnstile Sites Write" Turnstile true "Create, change and delete human-check widgets and rotate their secrets";
    "0cc3a61731504c89b99ec1be78b77aa0" "API Tokens Read" Tokens false "List your API tokens";
    "686d18d5ac6c441c867cbf6771e58a0a" "API Tokens Write" Tokens true "Create, change, roll and delete your API tokens";
}

pub fn group(id: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.id == id)
}

/// `/user/tokens/permission_groups`.
pub fn groups_json() -> Vec<Value> {
    GROUPS
        .iter()
        .map(|g| json!({ "id": g.id, "name": g.name, "description": g.description, "scopes": [g.area.scope().key()] }))
        .collect()
}

/// What a request is about, from its path (below `/client/v4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Need {
    /// Fine for any valid token (verifying itself, who it belongs to, the account).
    Open,
    /// Never with a token: sign-in, accounts, users, replication.
    Closed,
    /// One area of one zone, or of all zones if no zone is named.
    Zone(Area, Option<String>),
    Account(Area),
    User(Area),
}

pub fn need(path: &str) -> Need {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segs.as_slice() {
        ["user"] | ["user", "tokens", "verify"] | ["accounts"] | ["accounts", _] => Need::Open,
        ["user", "tokens", ..] => Need::User(Area::Tokens),
        ["zones"] => Need::Zone(Area::Zone, None),
        ["zones", z] => Need::Zone(Area::Zone, Some(z.to_string())),
        ["zones", z, first, ..] => {
            let area = match *first {
                "dns_records" => Area::Dns,
                "settings" | "dnssec" => Area::ZoneSettings,
                "purge_cache" => Area::CachePurge,
                "firewall" | "rate_limits" | "security" => Area::Firewall,
                "ssl" | "custom_certificates" | "custom_hostnames" | "origin_ca" => Area::Ssl,
                "origin_rules" => Area::OriginRules,
                "redirect_rules" => Area::RedirectRules,
                "transform_rules" => Area::TransformRules,
                "cache_rules" => Area::CacheRules,
                "rulesets" => crate::rulesets::area(z, &segs[3..]),
                "workers" => Area::WorkersRoutes,
                "email" => Area::EmailRouting,
                "spectrum" => Area::Spectrum,
                "analytics" | "origins" | "dns_analytics" => Area::Analytics,
                "logs" | "logpush" => Area::Logs,
                "waiting_rooms" => Area::WaitingRooms,
                "api_gateway" => Area::ApiGateway,
                "page_shield" => Area::PageShield,
                _ => return Need::Closed,
            };
            Need::Zone(area, Some(z.to_string()))
        }
        ["workers", ..] => Need::Account(Area::WorkersScripts),
        ["kv", ..] => Need::Account(Area::WorkersKv),
        ["d1", ..] => Need::Account(Area::D1),
        ["audit", ..] => Need::Account(Area::AuditLogs),
        ["backup"] => Need::Account(Area::Backup),
        ["alerts", ..] => Need::Account(Area::Notifications),
        ["analytics", ..] => Need::Account(Area::AccountAnalytics),
        ["rules", "lists", ..] => Need::Account(Area::Lists),
        ["challenges", "widgets", ..] => Need::Account(Area::Turnstile),
        ["fleet", ..] | ["nodes", ..] | ["steering", ..] | ["proxy", ..] | ["system", ..] | ["releases", ..] | ["warp", ..] | ["email", "status"] => {
            Need::Account(Area::Fleet)
        }
        _ => Need::Closed,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GroupRef {
    /// Either the id or the name will do.
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub id: String,
    /// allow or deny
    #[serde(default = "allow")]
    pub effect: String,
    #[serde(default)]
    pub resources: Map<String, Value>,
    #[serde(default)]
    pub permission_groups: Vec<GroupRef>,
}

fn allow() -> String {
    "allow".into()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IpList {
    #[serde(default, rename = "in", skip_serializing_if = "Vec::is_empty")]
    pub inside: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_in: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    #[serde(default, rename = "request.ip", alias = "request_ip", skip_serializing_if = "Option::is_none")]
    pub request_ip: Option<IpList>,
}

fn parse_net(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = match s.trim().split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (s.trim(), None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    (prefix <= max).then_some((ip, prefix))
}

fn in_net(ip: IpAddr, (net, prefix): (IpAddr, u8)) -> bool {
    let canon = |ip: IpAddr| match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        v4 => v4,
    };
    match (canon(ip), canon(net)) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Check what a token is given before keeping it.
pub fn validate(policies: &mut [Policy], condition: &Condition) -> Result<(), String> {
    if policies.is_empty() {
        return Err("a token needs at least one policy".into());
    }
    for (i, p) in policies.iter_mut().enumerate() {
        if p.effect != "allow" && p.effect != "deny" {
            return Err(format!("policy {}: effect must be allow or deny", i + 1));
        }
        if p.permission_groups.is_empty() {
            return Err(format!("policy {}: no permission groups", i + 1));
        }
        for g in &mut p.permission_groups {
            let known = group(&g.id).or_else(|| GROUPS.iter().find(|k| k.name.eq_ignore_ascii_case(&g.name)));
            let Some(known) = known else { return Err(format!("policy {}: unknown permission group '{}'", i + 1, g.id)) };
            g.id = known.id.into();
            g.name = known.name.into();
        }
        if p.resources.is_empty() {
            return Err(format!("policy {}: no resources", i + 1));
        }
        for (k, v) in &p.resources {
            let ok_key = k.starts_with(&format!("{ZONE}.")) || k.starts_with(&format!("{ACCOUNT}.")) || k.starts_with(&format!("{USER}."));
            if !ok_key {
                return Err(format!("policy {}: unknown resource '{k}'", i + 1));
            }
            match v {
                Value::String(s) if s == "*" => {}
                Value::Object(inner) if k.starts_with(&format!("{ACCOUNT}.")) && !k.starts_with(&format!("{ZONE}.")) => {
                    if inner.iter().any(|(ik, iv)| !ik.starts_with(&format!("{ZONE}.")) || iv != "*") {
                        return Err(format!("policy {}: an account resource holds only zone resources set to \"*\"", i + 1));
                    }
                }
                _ => return Err(format!("policy {}: resource '{k}' must be \"*\"", i + 1)),
            }
        }
        if p.id.is_empty() {
            p.id = uuid::Uuid::new_v4().simple().to_string();
        }
    }
    if let Some(l) = &condition.request_ip {
        for net in l.inside.iter().chain(&l.not_in) {
            if parse_net(net).is_none() {
                return Err(format!("'{net}' is not an address or CIDR range"));
            }
        }
    }
    Ok(())
}

/// What a valid token may do.
#[derive(Debug, Clone)]
pub struct Grant {
    pub token_id: String,
    pub policies: Vec<Policy>,
}

/// Is the request's address one the token may be used from?
pub fn ip_allowed(condition: &Condition, ip: Option<IpAddr>) -> bool {
    let Some(l) = &condition.request_ip else { return true };
    if l.inside.is_empty() && l.not_in.is_empty() {
        return true;
    }
    let Some(ip) = ip else { return false };
    let nets = |list: &[String]| list.iter().filter_map(|n| parse_net(n)).any(|n| in_net(ip, n));
    (l.inside.is_empty() || nets(&l.inside)) && !nets(&l.not_in)
}

impl Policy {
    fn covers(&self, scope: Scope, target: Option<&str>, user_id: &str) -> bool {
        let account_key = |k: &str| k == format!("{ACCOUNT}.*") || k == format!("{ACCOUNT}.{}", account_id());
        let zone_key = |k: &str| match target {
            Some(z) => k == format!("{ZONE}.*") || k == format!("{ZONE}.{z}"),
            None => k == format!("{ZONE}.*"),
        };
        self.resources.iter().any(|(k, v)| match scope {
            Scope::Zone if k.starts_with(&format!("{ZONE}.")) => zone_key(k),
            Scope::Zone if account_key(k) => match v {
                Value::Object(inner) => inner.keys().any(|ik| zone_key(ik)),
                _ => true,
            },
            Scope::Account => account_key(k),
            Scope::User => *k == format!("{USER}.{user_id}") || *k == format!("{USER}.*"),
            _ => false,
        })
    }

    /// Does any of this policy's groups give `area` (`write` asks for more than reading)?
    fn gives(&self, area: Area, write: bool) -> bool {
        self.permission_groups.iter().filter_map(|g| group(&g.id)).any(|g| {
            // anything at all on a zone lets one see the zone itself
            let area_ok = g.area == area || (area == Area::Zone && !write && g.area.scope() == Scope::Zone);
            area_ok && (g.write || !write)
        })
    }

    /// Does this policy name any zone, so that the zone list is not empty?
    fn names_zone(&self, zone_id: &str) -> bool {
        self.permission_groups.iter().filter_map(|g| group(&g.id)).any(|g| g.area.scope() == Scope::Zone)
            && self.covers(Scope::Zone, Some(zone_id), "")
    }
}

impl Grant {
    fn decide(&self, area: Area, write: bool, scope: Scope, target: Option<&str>, user_id: &str) -> bool {
        let matches = |p: &&Policy| p.gives(area, write) && p.covers(scope, target, user_id);
        if self.policies.iter().filter(|p| p.effect == "deny").any(|p| matches(&p)) {
            return false;
        }
        self.policies.iter().filter(|p| p.effect == "allow").any(|p| matches(&p))
    }

    /// May the token make this request (the owner's role is checked besides)?
    pub fn allows(&self, method: &str, path: &str, user_id: &str) -> bool {
        let write = !matches!(method, "GET" | "HEAD");
        match need(path) {
            Need::Open => true,
            Need::Closed => false,
            // the zone list is cut down to the zones the token names
            Need::Zone(Area::Zone, None) if !write => true,
            Need::Zone(area, zone) => self.decide(area, write, Scope::Zone, zone.as_deref(), user_id),
            Need::Account(area) => self.decide(area, write, Scope::Account, None, user_id),
            Need::User(area) => self.decide(area, write, Scope::User, None, user_id),
        }
    }

    /// Is this zone one the token may see?
    pub fn sees_zone(&self, zone_id: &str) -> bool {
        let denied = self.policies.iter().filter(|p| p.effect == "deny").any(|p| p.gives(Area::Zone, false) && p.covers(Scope::Zone, Some(zone_id), ""));
        !denied && self.policies.iter().filter(|p| p.effect == "allow").any(|p| p.names_zone(zone_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(effect: &str, resources: Value, groups: &[&str]) -> Policy {
        let mut p = Policy {
            id: String::new(),
            effect: effect.into(),
            resources: resources.as_object().unwrap().clone(),
            permission_groups: groups.iter().map(|n| GroupRef { id: String::new(), name: n.to_string() }).collect(),
        };
        validate(std::slice::from_mut(&mut p), &Condition::default()).unwrap();
        p
    }

    #[test]
    fn group_ids_are_unique_and_every_path_has_a_place() {
        let mut ids: Vec<&str> = GROUPS.iter().map(|g| g.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), GROUPS.len());
        assert!(GROUPS.iter().all(|g| g.id.len() == 32 && g.id.bytes().all(|b| b.is_ascii_hexdigit())));
        assert_eq!(need("/zones/z1/dns_records/r1"), Need::Zone(Area::Dns, Some("z1".into())));
        assert_eq!(need("/zones/z1/purge_cache"), Need::Zone(Area::CachePurge, Some("z1".into())));
        assert_eq!(need("/kv/namespaces"), Need::Account(Area::WorkersKv));
        assert_eq!(need("/account/password"), Need::Closed);
        assert_eq!(need("/users"), Need::Closed);
        assert_eq!(need("/replication/sync"), Need::Closed);
        assert_eq!(need("/user/tokens/verify"), Need::Open);
        assert_eq!(need("/zones/z1/whatever"), Need::Closed);
        assert_eq!(need("/zones/z1/rulesets"), Need::Zone(Area::Firewall, Some("z1".into())));
        assert_eq!(need("/alerts/channels/c1/test"), Need::Account(Area::Notifications));
        assert_eq!(need("/alerts/active"), Need::Account(Area::Notifications));
        assert_eq!(need("/challenges/widgets"), Need::Account(Area::Turnstile));
        assert_eq!(need("/challenges/widgets/k1/rotate_secret"), Need::Account(Area::Turnstile));
        assert_eq!(need("/challenges"), Need::Closed);
        assert_eq!(
            need("/zones/z1/rulesets/phases/http_request_cache_settings/entrypoint"),
            Need::Zone(Area::CacheRules, Some("z1".into()))
        );
        assert_eq!(need("/zones/z1/logs/requests"), Need::Zone(Area::Logs, Some("z1".into())));
        assert_eq!(need("/zones/z1/logpush/jobs/j1"), Need::Zone(Area::Logs, Some("z1".into())));
        assert_eq!(need("/logpush/jobs"), Need::Closed);
        assert_eq!(need("/zones/z1/waiting_rooms"), Need::Zone(Area::WaitingRooms, Some("z1".into())));
        assert_eq!(need("/zones/z1/waiting_rooms/w1"), Need::Zone(Area::WaitingRooms, Some("z1".into())));
        assert_eq!(need("/zones/z1/page_shield"), Need::Zone(Area::PageShield, Some("z1".into())));
        assert_eq!(need("/zones/z1/page_shield/scripts/abc"), Need::Zone(Area::PageShield, Some("z1".into())));
        assert_eq!(need("/waiting_rooms"), Need::Closed);
        assert_eq!(need("/zones/z1/api_gateway/operations"), Need::Zone(Area::ApiGateway, Some("z1".into())));
        assert_eq!(need("/zones/z1/api_gateway/settings/schema_validation"), Need::Zone(Area::ApiGateway, Some("z1".into())));
        assert_eq!(need("/api_gateway/operations"), Need::Closed);
        assert_eq!(need("/zones/z1/custom_hostnames"), Need::Zone(Area::Ssl, Some("z1".into())));
        assert_eq!(need("/zones/z1/custom_hostnames/h1"), Need::Zone(Area::Ssl, Some("z1".into())));
        assert_eq!(need("/custom_hostnames"), Need::Closed);
    }

    #[test]
    fn policies_decide_per_zone_and_deny_wins() {
        let dns_one = Grant {
            token_id: "t".into(),
            policies: vec![policy("allow", json!({ "com.cloudflare.api.account.zone.z1": "*" }), &["Zone Read", "DNS Write"])],
        };
        assert!(dns_one.allows("GET", "/zones", "u"));
        assert!(dns_one.allows("GET", "/zones/z1", "u"));
        assert!(dns_one.allows("POST", "/zones/z1/dns_records", "u"));
        assert!(dns_one.allows("GET", "/zones/z1/dns_records", "u"), "write includes read");
        assert!(!dns_one.allows("POST", "/zones/z2/dns_records", "u"));
        assert!(!dns_one.allows("GET", "/zones/z2", "u"));
        assert!(!dns_one.allows("POST", "/zones/z1/purge_cache", "u"));
        assert!(!dns_one.allows("DELETE", "/zones/z1", "u"));
        assert!(!dns_one.allows("POST", "/zones", "u"));
        assert!(!dns_one.allows("GET", "/kv/namespaces", "u"));
        assert!(!dns_one.allows("GET", "/user/tokens", "u"));
        assert!(dns_one.sees_zone("z1") && !dns_one.sees_zone("z2"));

        let all_but = Grant {
            token_id: "t".into(),
            policies: vec![
                policy("allow", json!({ "com.cloudflare.api.account.zone.*": "*" }), &["DNS Write", "Zone Write"]),
                policy("deny", json!({ "com.cloudflare.api.account.zone.z2": "*" }), &["DNS Write"]),
            ],
        };
        assert!(all_but.allows("PUT", "/zones/z1/dns_records/r", "u"));
        assert!(!all_but.allows("PUT", "/zones/z2/dns_records/r", "u"));
        assert!(all_but.allows("POST", "/zones", "u"), "all zones may add zones");

        let account = Grant {
            token_id: "t".into(),
            policies: vec![
                policy(
                    "allow",
                    json!({ format!("com.cloudflare.api.account.{}", account_id()): { "com.cloudflare.api.account.zone.*": "*" } }),
                    &["Cache Purge"],
                ),
                policy("allow", json!({ format!("com.cloudflare.api.account.{}", account_id()): "*" }), &["Workers KV Storage Read"]),
                policy("allow", json!({ "com.cloudflare.api.user.u": "*" }), &["API Tokens Write"]),
            ],
        };
        assert!(account.allows("POST", "/zones/z9/purge_cache", "u"));
        assert!(account.allows("GET", "/kv/namespaces/n/keys", "u"));
        assert!(!account.allows("PUT", "/kv/namespaces/n/values/k", "u"));
        assert!(account.allows("POST", "/user/tokens", "u"));
        assert!(!account.allows("POST", "/user/tokens", "someone-else"));
        assert!(!account.allows("POST", "/account/password", "u"));
    }

    #[test]
    fn ip_lists_are_an_account_area_that_zone_tokens_do_not_reach() {
        assert_eq!(need("/rules/lists"), Need::Account(Area::Lists));
        assert_eq!(need("/rules/lists/l1/items"), Need::Account(Area::Lists));
        assert_eq!(need("/rules/lists/bulk_operations/op1"), Need::Account(Area::Lists));
        assert_eq!(need("/rules"), Need::Closed);
        assert_eq!(need("/rules/other"), Need::Closed);
        let account = json!({ format!("com.cloudflare.api.account.{}", account_id()): "*" });
        let read = Grant { token_id: "t".into(), policies: vec![policy("allow", account.clone(), &["Account Filter Lists Read"])] };
        assert!(read.allows("GET", "/rules/lists", "u") && read.allows("GET", "/rules/lists/l1/items", "u"));
        for (method, path) in [("POST", "/rules/lists"), ("PUT", "/rules/lists/l1"), ("DELETE", "/rules/lists/l1"), ("POST", "/rules/lists/l1/items"), ("DELETE", "/rules/lists/l1/items")] {
            assert!(!read.allows(method, path, "u"), "read only: {method} {path}");
        }
        let write = Grant { token_id: "t".into(), policies: vec![policy("allow", account.clone(), &["Account Filter Lists Write"])] };
        assert!(write.allows("PUT", "/rules/lists/l1/items", "u") && write.allows("GET", "/rules/lists", "u"));
        assert!(!write.allows("GET", "/zones/z1/firewall/rules", "u"), "lists give no zone");
        let zones = Grant {
            token_id: "t".into(),
            policies: vec![policy("allow", json!({ "com.cloudflare.api.account.zone.*": "*" }), &["Firewall Services Write", "Zone Write"])],
        };
        assert!(!zones.allows("GET", "/rules/lists", "u") && !zones.allows("POST", "/rules/lists/l1/items", "u"), "a zone token cannot touch lists");
        let zones_in_account = Grant {
            token_id: "t".into(),
            policies: vec![policy("allow", json!({ format!("com.cloudflare.api.account.{}", account_id()): { "com.cloudflare.api.account.zone.*": "*" } }), &["Firewall Services Write"])],
        };
        assert!(!zones_in_account.allows("GET", "/rules/lists", "u"));
        let denied = Grant {
            token_id: "t".into(),
            policies: vec![policy("allow", account.clone(), &["Account Filter Lists Write"]), policy("deny", account, &["Account Filter Lists Write"])],
        };
        assert!(!denied.allows("GET", "/rules/lists", "u"), "deny wins");
    }

    #[test]
    fn checking_what_a_token_is_given() {
        let mut bad = vec![Policy { id: String::new(), effect: "allow".into(), resources: Map::new(), permission_groups: vec![] }];
        assert!(validate(&mut bad, &Condition::default()).is_err());
        let mut unknown = vec![policy("allow", json!({ "com.cloudflare.api.account.zone.*": "*" }), &["DNS Read"])];
        unknown[0].permission_groups.push(GroupRef { id: "nope".into(), name: String::new() });
        assert!(validate(&mut unknown, &Condition::default()).is_err());
        let p = policy("allow", json!({ "com.cloudflare.api.account.zone.*": "*" }), &["dns read"]);
        assert_eq!(p.permission_groups[0].id, "82e64a83756745bbbb1c9c2701bf816b");
        assert_eq!(p.permission_groups[0].name, "DNS Read");
        let cond = Condition { request_ip: Some(IpList { inside: vec!["nonsense".into()], not_in: vec![] }) };
        assert!(validate(&mut [p], &cond).is_err());
    }

    #[test]
    fn address_conditions() {
        let cond: Condition = serde_json::from_value(json!({ "request.ip": { "in": ["198.51.100.0/24", "2001:db8::/32"], "not_in": ["198.51.100.9"] } })).unwrap();
        let ip = |s: &str| Some(s.parse().unwrap());
        assert!(ip_allowed(&cond, ip("198.51.100.7")));
        assert!(!ip_allowed(&cond, ip("198.51.100.9")));
        assert!(!ip_allowed(&cond, ip("203.0.113.1")));
        assert!(ip_allowed(&cond, ip("2001:db8::1")));
        assert!(ip_allowed(&cond, ip("::ffff:198.51.100.7")));
        assert!(!ip_allowed(&cond, None));
        assert!(ip_allowed(&Condition::default(), None));
        assert_eq!(serde_json::to_value(&cond).unwrap()["request.ip"]["in"][0], "198.51.100.0/24");
    }
}
