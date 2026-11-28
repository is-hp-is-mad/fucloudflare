//! Zone-scoped configuration objects managed through the generic CRUD layer:
//! firewall rules, rate limits, origin rules, certificates, Spectrum apps
//! and worker routes. Each type only supplies its fields and validation.

use crate::dns::wire::normalize_name;
use crate::expr::Expr;
use crate::store::{Data, StoreError, Zone};
use crate::sync::SyncMeta;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Meta {
    pub id: String,
    pub zone_id: String,
    pub created_on: String,
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

pub trait Item: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {
    fn vec(d: &Data) -> &Vec<Self>;
    fn vec_mut(d: &mut Data) -> &mut Vec<Self>;
    #[allow(dead_code)]
    fn tombstones(d: &Data) -> &BTreeMap<String, SyncMeta>;
    fn tombstones_mut(d: &mut Data) -> &mut BTreeMap<String, SyncMeta>;
    fn meta(&self) -> &Meta;
    fn meta_mut(&mut self) -> &mut Meta;
    /// Normalize and validate; `d` still holds the previous version (if any).
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError>;
    /// JSON representation returned by the API.
    fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("sync");
        }
        v
    }
}

macro_rules! item_boilerplate {
    ($field:ident) => {
        fn vec(d: &Data) -> &Vec<Self> {
            &d.$field
        }
        fn vec_mut(d: &mut Data) -> &mut Vec<Self> {
            &mut d.$field
        }
        fn tombstones(d: &Data) -> &BTreeMap<String, SyncMeta> {
            &d.tombstones.$field
        }
        fn tombstones_mut(d: &mut Data) -> &mut BTreeMap<String, SyncMeta> {
            &mut d.tombstones.$field
        }
        fn meta(&self) -> &Meta {
            &self.meta
        }
        fn meta_mut(&mut self) -> &mut Meta {
            &mut self.meta
        }
    };
}

fn yes() -> bool {
    true
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

/// The expression parses, and every IP list it names (`$name`) exists.
fn check_expr(src: &str, d: &Data) -> Result<(), StoreError> {
    Expr::parse(src)
        .and_then(|e| crate::lists::check_refs(&e, d))
        .map_err(|e| StoreError::Invalid(format!("invalid expression: {e}")))
}

fn one_of(what: &str, value: &str, allowed: &[&str]) -> Result<(), StoreError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        invalid(format!("{what} must be one of: {}", allowed.join(", ")))
    }
}

/// Is `name` the zone apex or below it?
pub fn in_zone(zone: &Zone, name: &str) -> bool {
    name == zone.name || name.ends_with(&format!(".{}", zone.name))
}

/// A host name or an IP literal.
pub(crate) fn check_host(what: &str, h: &str) -> Result<String, StoreError> {
    if h.parse::<std::net::IpAddr>().is_ok() {
        return Ok(h.to_string());
    }
    let n = normalize_name(h).map_err(|e| StoreError::Invalid(format!("{what}: {e}")))?;
    if n.contains(['*', '_']) {
        return invalid(format!("{what}: '{n}' is not a valid host"));
    }
    Ok(n)
}

// ----------------------------------------------------------- settings ----

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// How the edge talks to the origin: `flexible` (HTTP), `full` (HTTPS,
    /// certificate not verified) or `strict` (HTTPS, verified).
    pub ssl: String,
    pub always_use_https: bool,
    /// Managed WAF ruleset: `off`, `log` or `block`.
    pub waf: String,
    /// Bypass the edge cache.
    pub development_mode: bool,
    /// Names of the edge nodes that serve this zone; empty means all nodes,
    /// chosen by visitor location.
    pub edge_nodes: Vec<String>,
    /// Offer HTTP/2 to visitors of this zone (off: HTTP/1.1 only over TCP).
    pub http2: bool,
    /// Offer HTTP/3 (QUIC): advertised through Alt-Svc and HTTPS DNS records.
    pub http3: bool,
    /// Who has to pass the human check before anything else happens
    /// (firewall `skip` rules exempt), by the threat score of their address
    /// (crate::edge::reputation): `off`, `low` (80 and up), `medium` (50 and
    /// up), `high` (25 and up: data centres too), `under_attack` (everybody).
    /// Higher levels also ask for more work and tolerate less doubt.
    pub security_level: String,
    /// Put the fucf script into the site's HTML pages (when the zone can
    /// challenge at all): it passes the check quietly in the background, and
    /// settles challenges of fetch / XHR requests without reloading the page.
    pub challenge_script: bool,
    /// Seconds browsers may keep what the edge caches; raises a shorter
    /// lifetime given by the origin. 0 leaves the origin's headers alone.
    pub browser_cache_ttl: u32,
    /// `max-age` of the `Strict-Transport-Security` header sent with HTTPS
    /// responses; 0 sends none.
    pub hsts_max_age: u32,
    pub hsts_include_subdomains: bool,
    /// Proxy gRPC: requests with a gRPC content type that arrive over
    /// HTTP/2 or HTTP/3 are passed to the origin over HTTP/2.
    pub grpc: bool,
    /// Take mail for addresses of this zone and pass it on as its e-mail
    /// routing rules say (see crate::mail).
    pub email_routing: bool,
    /// Decoy subdomains: every name under the zone that has no records
    /// resolves anyway (to the edge nodes with the most traffic to spare,
    /// never accelerate nodes), and the edge refuses it -- the TLS handshake
    /// fails, plain HTTP is hung up on. Enumerating the zone's names by
    /// resolving them tells nothing then.
    pub decoy_subdomains: bool,
    /// The automatic firewall (crate::edge::autofw): addresses with
    /// `auto_firewall_threshold` attacks within `auto_firewall_window`
    /// seconds are banned for `auto_firewall_ban` seconds, by a firewall rule
    /// with `auto_firewall_action` (block or managed_challenge).
    pub auto_firewall: bool,
    pub auto_firewall_threshold: u32,
    pub auto_firewall_window: u32,
    pub auto_firewall_ban: u32,
    pub auto_firewall_action: String,
    /// Also challenge whole networks (ASNs) from which at least
    /// `auto_firewall_network_ips` data centre / VPN / listed addresses attacked.
    pub auto_firewall_networks: bool,
    pub auto_firewall_network_ips: u32,
    /// So many different attackers within the window put the zone into
    /// under attack mode for an hour (0: never).
    pub auto_firewall_surge: u32,
    /// Kept by the automatic firewall while it holds the zone in under attack
    /// mode: the level to go back to, and until when (unix seconds).
    pub auto_level_restore: String,
    pub auto_level_until: u64,
    /// The zone's own HTML for the pages the edge writes by itself, by kind
    /// (`5xx`, `block`, `ratelimit`, `1xxx`; see crate::edge::errpages).
    pub error_pages: crate::edge::errpages::ErrorPages,
    /// Path every node asks of each origin address of the zone's proxied names
    /// (see crate::edge::origins); empty: no health checks.
    pub origin_check_path: String,
    /// Seconds between two checks of an address.
    pub origin_check_interval: u32,
    /// A visitor keeps going to the same origin address of a name with several.
    pub session_affinity: bool,
    /// Secondary name servers (addresses, or networks as `address/prefix`) that may
    /// transfer the zone (AXFR); the single addresses are sent a NOTIFY when it changes.
    pub dns_transfer_to: Vec<String>,
    /// Tiered cache: the node the others fetch cacheable requests through (empty: every
    /// node asks the origin itself).
    pub cache_tier_node: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            ssl: "flexible".into(),
            always_use_https: false,
            waf: "block".into(),
            development_mode: false,
            edge_nodes: Vec::new(),
            http2: true,
            http3: true,
            security_level: "medium".into(),
            challenge_script: true,
            browser_cache_ttl: 0,
            hsts_max_age: 0,
            hsts_include_subdomains: false,
            grpc: true,
            email_routing: false,
            decoy_subdomains: false,
            auto_firewall: false,
            auto_firewall_threshold: 10,
            auto_firewall_window: 600,
            auto_firewall_ban: 86400,
            auto_firewall_action: "block".into(),
            auto_firewall_networks: true,
            auto_firewall_network_ips: 10,
            auto_firewall_surge: 50,
            auto_level_restore: String::new(),
            auto_level_until: 0,
            error_pages: Default::default(),
            origin_check_path: String::new(),
            origin_check_interval: 30,
            session_affinity: false,
            dns_transfer_to: Vec::new(),
            cache_tier_node: String::new(),
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), StoreError> {
        one_of("ssl", &self.ssl, &["flexible", "full", "strict"])?;
        one_of("waf", &self.waf, &["off", "log", "block"])?;
        one_of("security_level", &self.security_level, &["off", "essentially_off", "low", "medium", "high", "under_attack"])?;
        one_of("auto_firewall_action", &self.auto_firewall_action, &["block", "managed_challenge", "js_challenge"])?;
        if !(1..=100_000).contains(&self.auto_firewall_threshold)
            || !(60..=86_400).contains(&self.auto_firewall_window)
            || !(60..=30 * 86_400).contains(&self.auto_firewall_ban)
        {
            return invalid("auto_firewall_threshold is 1 to 100000, auto_firewall_window 60 to 86400 and auto_firewall_ban 60 to 2592000 seconds");
        }
        if !(2..=100_000).contains(&self.auto_firewall_network_ips) || (self.auto_firewall_surge != 0 && !(5..=1_000_000).contains(&self.auto_firewall_surge)) {
            return invalid("auto_firewall_network_ips is 2 to 100000, auto_firewall_surge 0 (off) or 5 to 1000000");
        }
        if !self.auto_level_restore.is_empty() {
            one_of("auto_level_restore", &self.auto_level_restore, &["off", "essentially_off", "low", "medium", "high", "under_attack"])?;
        }
        let path = &self.origin_check_path;
        if !path.is_empty() && (!path.starts_with('/') || path.len() > 256 || path.bytes().any(|b| b <= b' ' || b == 0x7f)) {
            return invalid("origin_check_path is a path like /healthz (at most 256 bytes), or empty for no checks");
        }
        if self.dns_transfer_to.len() > 16 || self.dns_transfer_to.iter().any(|e| !crate::dns::transfer::valid(e)) {
            return invalid("dns_transfer_to holds at most 16 addresses or networks (address/prefix)");
        }
        if self.cache_tier_node.len() > 64 {
            return invalid("cache_tier_node is the name of a node, or empty");
        }
        if !(10..=3600).contains(&self.origin_check_interval) {
            return invalid("origin_check_interval is 10 to 3600 seconds");
        }
        if self.browser_cache_ttl > 31_536_000 || self.hsts_max_age > 63_072_000 {
            return invalid("browser_cache_ttl is at most 31536000 and hsts_max_age at most 63072000 seconds");
        }
        self.error_pages.validate()?;
        Ok(())
    }
}

// ----------------------------------------------------- firewall rules ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    #[serde(flatten)]
    pub meta: Meta,
    pub expression: String,
    /// `block`, `js_challenge` (the human check, which asks for a click only
    /// when the browser looks doubtful), `managed_challenge` (always one
    /// click), `log` or `skip` (allow, bypassing the WAF).
    pub action: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Lower runs first.
    #[serde(default)]
    pub priority: i32,
    /// `auto_firewall` for the rule the automatic firewall keeps (see
    /// crate::edge::autofw); empty for rules people write.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub managed_by: String,
    /// The automatic rule's addresses and until when (unix seconds) each is banned.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub auto_bans: BTreeMap<String, u64>,
}

impl Item for FirewallRule {
    item_boilerplate!(firewall_rules);
    fn validate(&mut self, _: &Zone, d: &Data) -> Result<(), StoreError> {
        check_expr(&self.expression, d)?;
        one_of("action", &self.action, &["block", "js_challenge", "managed_challenge", "log", "skip"])
    }
}

// -------------------------------------------------------- rate limits ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    #[serde(flatten)]
    pub meta: Meta,
    /// Which requests are counted; empty counts everything.
    #[serde(default)]
    pub expression: String,
    /// Requests allowed per client IP per `period` seconds.
    pub threshold: u32,
    pub period: u32,
    /// Seconds a client stays blocked once over the threshold.
    #[serde(default)]
    pub mitigation_timeout: u32,
    /// What tells one client from another: `ip` (alone when nothing is given), `asn`,
    /// `country`, `host`, `path`, `header:NAME`, `cookie:NAME`; several make one key.
    #[serde(default)]
    pub characteristics: Vec<String>,
    /// Count only the requests answered with one of these statuses (counted once
    /// the answer is there: failed sign-ins, say); empty counts every matching request.
    #[serde(default, deserialize_with = "lenient_codes")]
    pub status_codes: Vec<u16>,
    #[serde(default = "RateLimit::default_action")]
    pub action: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl RateLimit {
    fn default_action() -> String {
        "block".into()
    }

    /// What the requests of one client are counted under.
    pub fn key(&self, info: &crate::expr::ReqInfo, ip: std::net::IpAddr) -> String {
        if self.characteristics.is_empty() {
            return ip.to_string();
        }
        let cookie = |name: &str| info.header("cookie").split(';').filter_map(|kv| kv.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string()).unwrap_or_default();
        let part = |c: &String| match c.split_once(':') {
            Some(("header", name)) => info.header(name).to_string(),
            Some(("cookie", name)) => cookie(name),
            _ => match c.as_str() {
                "asn" => info.asn.to_string(),
                "country" => info.country.clone(),
                "host" => info.host.clone(),
                "path" => info.path.clone(),
                _ => ip.to_string(),
            },
        };
        self.characteristics.iter().map(part).collect::<Vec<_>>().join("\u{1f}")
    }
}

/// Status codes given as numbers or as their digits (as a form sends them).
fn lenient_codes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u16>, D::Error> {
    let raw: Vec<Value> = Deserialize::deserialize(d)?;
    raw.iter()
        .map(|v| v.as_u64().or_else(|| v.as_str()?.trim().parse().ok()).and_then(|n| u16::try_from(n).ok()).ok_or_else(|| serde::de::Error::custom(format!("{v} is not a status code"))))
        .collect()
}

impl Item for RateLimit {
    item_boilerplate!(rate_limits);
    fn validate(&mut self, _: &Zone, d: &Data) -> Result<(), StoreError> {
        check_expr(&self.expression, d)?;
        one_of("action", &self.action, &["block", "log"])?;
        if self.threshold == 0 || !(1..=86400).contains(&self.period) || self.mitigation_timeout > 86400 {
            return invalid("threshold must be >= 1, period 1-86400 and mitigation_timeout 0-86400");
        }
        for c in &mut self.characteristics {
            let given = c.trim();
            // cookie names keep their case, the rest is lower case
            *c = match given.split_once(':') {
                Some((kind, name)) if kind.eq_ignore_ascii_case("cookie") => format!("cookie:{}", name.trim()),
                _ => given.to_ascii_lowercase(),
            };
            let named = c.split_once(':').is_some_and(|(kind, name)| {
                matches!(kind, "header" | "cookie") && !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
            if !named && !matches!(c.as_str(), "ip" | "asn" | "country" | "host" | "path") {
                return invalid(format!("characteristic '{c}' is not ip, asn, country, host, path, header:NAME or cookie:NAME"));
            }
        }
        if self.characteristics.len() > 4 || self.status_codes.len() > 20 || self.status_codes.iter().any(|s| !(100..=599).contains(s)) {
            return invalid("at most 4 characteristics, and at most 20 status_codes between 100 and 599");
        }
        Ok(())
    }
}

// ------------------------------------------------------- origin rules ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginRule {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    /// Override the `Host` header sent to the origin.
    #[serde(default)]
    pub host_header: Option<String>,
    /// Override the TLS server name presented to the origin.
    #[serde(default)]
    pub sni: Option<String>,
    /// Send matching requests to this host/IP instead of the DNS record's.
    #[serde(default)]
    pub origin_host: Option<String>,
    /// Route matching requests internally to this edge node (`127.0.0.1:<port>`
    /// if self, else `<node_ip>:<port>`).
    #[serde(default)]
    pub origin_node: Option<String>,
    #[serde(default)]
    pub origin_port: Option<u16>,
    /// `http` or `https`, overriding the zone's ssl setting.
    #[serde(default)]
    pub origin_scheme: Option<String>,
}

impl Item for OriginRule {
    item_boilerplate!(origin_rules);
    fn validate(&mut self, _: &Zone, d: &Data) -> Result<(), StoreError> {
        check_expr(&self.expression, d)?;
        for (what, field) in
            [("host_header", &mut self.host_header), ("sni", &mut self.sni), ("origin_host", &mut self.origin_host)]
        {
            if let Some(h) = field {
                *h = check_host(what, h)?;
            }
        }
        if let Some(n) = &mut self.origin_node {
            let trimmed = n.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                self.origin_node = None;
            } else {
                *n = trimmed;
            }
        }
        if let Some(s) = &self.origin_scheme {
            one_of("origin_scheme", s, &["http", "https"])?;
        }
        if self.origin_port == Some(0) {
            return invalid("origin_port must be between 1 and 65535");
        }
        let any = self.host_header.is_some()
            || self.sni.is_some()
            || self.origin_host.is_some()
            || self.origin_node.is_some()
            || self.origin_port.is_some()
            || self.origin_scheme.is_some();
        if !any {
            return invalid(
                "an origin rule needs at least one of host_header, sni, origin_host, origin_node, origin_port, origin_scheme",
            );
        }
        Ok(())
    }
}

// ------------------------------------------------------- certificates ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(flatten)]
    pub meta: Meta,
    /// Host names served with this certificate (`*.example.com` allowed).
    /// Defaults to the apex and its wildcard.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// PEM certificate chain, leaf first.
    pub certificate: String,
    /// PEM private key. Never returned by the API.
    pub private_key: String,
}

impl Item for Certificate {
    item_boilerplate!(certificates);
    fn validate(&mut self, zone: &Zone, _: &Data) -> Result<(), StoreError> {
        crate::edge::tls::parse_cert(&self.certificate, &self.private_key).map_err(StoreError::Invalid)?;
        if self.hosts.is_empty() {
            self.hosts = vec![zone.name.clone(), format!("*.{}", zone.name)];
        }
        for h in &mut self.hosts {
            *h = normalize_name(h).map_err(StoreError::Invalid)?;
            if !in_zone(zone, h.trim_start_matches("*.")) {
                return invalid(format!("host '{h}' is not part of zone {}", zone.name));
            }
        }
        Ok(())
    }
    fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("private_key");
            if let Some((_, until)) = crate::edge::tls::pem_validity(&self.certificate) {
                o.insert("expires_on".into(), crate::store::rfc3339(until).into());
            }
        }
        v
    }
}

// -------------------------------------------- managed certificates ----

/// A certificate obtained from an ACME certificate authority and renewed
/// automatically (Cloudflare calls these certificate packs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CertificatePack {
    #[serde(flatten)]
    pub meta: Meta,
    /// Names on the certificate (`*.example.com` allowed). Defaults to the
    /// apex and its wildcard.
    pub hosts: Vec<String>,
    /// How control of the names is proven: `dns`, `tls-alpn`, `http`, or
    /// `auto` (DNS for wildcards and fully hosted zones, else TLS-ALPN).
    pub validation_method: String,
    /// `pending` (no certificate yet), `active` or `failed`.
    pub status: String,
    /// Why the last attempt failed; empty after a success.
    pub error: String,
    /// PEM certificate chain, leaf first.
    pub certificate: String,
    /// PEM private key. Never returned by the API.
    pub private_key: String,
    pub issued_on: Option<String>,
    pub expires_on: Option<String>,
    /// Failed attempts in a row, and when the next one is due.
    pub attempts: u32,
    pub next_attempt: Option<String>,
}

impl Item for CertificatePack {
    item_boilerplate!(certificate_packs);
    fn validate(&mut self, zone: &Zone, _: &Data) -> Result<(), StoreError> {
        if self.hosts.is_empty() {
            self.hosts = vec![zone.name.clone(), format!("*.{}", zone.name)];
        }
        if self.hosts.len() > 100 {
            return invalid("a certificate covers at most 100 names");
        }
        for h in &mut self.hosts {
            *h = normalize_name(h).map_err(StoreError::Invalid)?;
            let base = h.strip_prefix("*.").unwrap_or(h);
            if base.contains(['*', '_']) {
                return invalid(format!("'{h}' cannot be put on a certificate"));
            }
            if !in_zone(zone, base) {
                return invalid(format!("host '{h}' is not part of zone {}", zone.name));
            }
        }
        let mut seen = std::collections::HashSet::new();
        self.hosts.retain(|h| seen.insert(h.clone()));
        if self.validation_method.is_empty() {
            self.validation_method = "auto".into();
        }
        one_of("validation_method", &self.validation_method, &["auto", "dns", "tls-alpn", "http"])?;
        if matches!(self.validation_method.as_str(), "tls-alpn" | "http") && self.hosts.iter().any(|h| h.starts_with("*.")) {
            return invalid("wildcard names can only be validated through DNS");
        }
        if self.status.is_empty() {
            self.status = "pending".into();
        }
        Ok(())
    }
    fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("private_key");
        }
        v
    }
}

/// A pending ACME challenge. It is part of the replicated configuration so
/// that whichever node the CA's validators reach can answer it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallenge {
    pub pack_id: String,
    /// The name being validated (without `*.`).
    pub host: String,
    /// `dns-01`, `tls-alpn-01` or `http-01`.
    pub kind: String,
    pub token: String,
    pub key_authorization: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl AcmeChallenge {
    /// SHA-256 of the key authorization: what DNS and TLS answers carry.
    pub fn digest(&self) -> [u8; 32] {
        crate::acme::sha256(self.key_authorization.as_bytes())
    }

    pub fn sync_key(&self) -> String {
        format!("{}:{}:{}", self.pack_id, self.host, self.kind)
    }
}

// ------------------------------------------------------ spectrum apps ----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpectrumDns {
    #[serde(default, rename = "type")]
    pub rtype: String,
    pub name: String,
}

/// A raw TCP/UDP port forwarded from the edge to an origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectrumApp {
    #[serde(flatten)]
    pub meta: Meta,
    /// Edge listener, e.g. `tcp/2222` or `udp/5000`.
    pub protocol: String,
    /// Host name that resolves to the edge for this app.
    pub dns: SpectrumDns,
    /// Origins, e.g. `["tcp://192.0.2.1:22"]`; one is picked per connection.
    pub origin_direct: Vec<String>,
    /// `off` or `v1` (TCP only): prepend a PROXY protocol header.
    #[serde(default = "SpectrumApp::default_pp")]
    pub proxy_protocol: String,
}

impl SpectrumApp {
    fn default_pp() -> String {
        "off".into()
    }

    /// `(is_udp, port)` of the edge listener.
    pub fn listener(&self) -> Option<(bool, u16)> {
        let (proto, port) = self.protocol.split_once('/')?;
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        match proto {
            "tcp" => Some((false, port)),
            "udp" => Some((true, port)),
            _ => None,
        }
    }

    /// Origins as `host:port`.
    pub fn origins(&self) -> Vec<String> {
        self.origin_direct.iter().filter_map(|o| o.split_once("://").map(|(_, a)| a.to_string())).collect()
    }
}

impl Item for SpectrumApp {
    item_boilerplate!(spectrum_apps);
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError> {
        self.protocol = self.protocol.trim().to_ascii_lowercase();
        let Some((udp, _)) = self.listener() else {
            return invalid("protocol must look like 'tcp/2222' or 'udp/5000'");
        };
        if d.spectrum_apps.iter().any(|a| a.protocol == self.protocol && a.meta.id != self.meta.id) {
            return Err(StoreError::Conflict(format!("{} is already used by another app", self.protocol)));
        }

        self.dns.rtype = "CNAME".into();
        let raw = self.dns.name.trim().trim_end_matches('.').to_ascii_lowercase();
        let fqdn = if in_zone(zone, &raw) { raw } else { format!("{raw}.{}", zone.name) };
        self.dns.name = normalize_name(&fqdn).map_err(StoreError::Invalid)?;
        if self.dns.name.contains('*') {
            return invalid("dns.name must not be a wildcard");
        }

        let scheme = if udp { "udp" } else { "tcp" };
        if self.origin_direct.is_empty() {
            return invalid("origin_direct needs at least one origin");
        }
        for o in &self.origin_direct {
            let addr = o.strip_prefix(scheme).and_then(|r| r.strip_prefix("://"));
            let parts = addr.and_then(|a| a.rsplit_once(':'));
            let ok = parts.is_some_and(|(host, port)| {
                let host = host.trim_start_matches('[').trim_end_matches(']');
                check_host("origin", host).is_ok() && port.parse::<u16>().is_ok_and(|p| p != 0)
            });
            if !ok {
                return invalid(format!("origin '{o}' must look like '{scheme}://host:port'"));
            }
        }
        one_of("proxy_protocol", &self.proxy_protocol, &["off", "v1"])?;
        if udp && self.proxy_protocol != "off" {
            return invalid("proxy_protocol is only supported for TCP apps");
        }
        Ok(())
    }
}

// ------------------------------------------------------------ workers ----

/// A script (global, like Cloudflare's account-level scripts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerScript {
    pub name: String,
    pub script: String,
    /// Plain-text bindings exposed to the script as `env`.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// KV namespace bindings: binding name -> kv_namespace_id.
    #[serde(default)]
    pub kv_bindings: BTreeMap<String, String>,
    /// D1 database bindings: binding name -> d1_database_id.
    #[serde(default)]
    pub d1_bindings: BTreeMap<String, String>,
    /// 5-field UTC cron expressions for `scheduled(controller, env, ctx)`.
    #[serde(default)]
    pub crons: Vec<String>,
    pub created_on: String,
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRoute {
    #[serde(flatten)]
    pub meta: Meta,
    /// `host/path` glob, e.g. `example.com/api/*` or `*.example.com/*`.
    pub pattern: String,
    /// Script to run; `null` disables workers for matching requests.
    #[serde(default)]
    pub script: Option<String>,
}

impl WorkerRoute {
    pub fn matches(&self, host: &str, path: &str) -> bool {
        glob(self.pattern.as_bytes(), format!("{host}{path}").as_bytes())
    }
}

/// `*` matches any run of characters (including none).
fn glob(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if p < pat.len() && pat[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pat[p..].iter().all(|c| *c == b'*')
}

impl Item for WorkerRoute {
    item_boilerplate!(worker_routes);
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError> {
        let p = self.pattern.trim().to_string();
        let p = p.strip_prefix("https://").or(p.strip_prefix("http://")).unwrap_or(&p).to_string();
        let (host, path) = match p.find('/') {
            Some(i) => (p[..i].to_ascii_lowercase(), p[i..].to_string()),
            None => (p.to_ascii_lowercase(), "/".to_string()),
        };
        if !in_zone(zone, host.trim_start_matches("*.").trim_start_matches('*')) {
            return invalid(format!("route pattern host must belong to zone {}", zone.name));
        }
        self.pattern = format!("{host}{path}");
        if d.worker_routes.iter().any(|r| r.pattern == self.pattern && r.meta.id != self.meta.id) {
            return Err(StoreError::Conflict("a route with this pattern already exists".into()));
        }
        if let Some(s) = &self.script {
            if !d.workers.iter().any(|w| &w.name == s) {
                return invalid(format!("worker script '{s}' does not exist"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn route_globs() {
        let m = |p: &str, t: &str| glob(p.as_bytes(), t.as_bytes());
        assert!(m("example.com/api/*", "example.com/api/v1/users"));
        assert!(m("example.com/api/*", "example.com/api/"));
        assert!(!m("example.com/api/*", "example.com/other"));
        assert!(m("*.example.com/*", "a.b.example.com/x"));
        assert!(!m("*.example.com/*", "example.com/x"));
        assert!(m("*example.com/*.jpg", "www.example.com/img/a.jpg"));
        assert!(m("example.com/", "example.com/"));
        assert!(!m("example.com/", "example.com/x"));
    }
}

// -------------------------------------------------------- e-mail rules ----

/// What happens to mail for an address of the zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRule {
    #[serde(flatten)]
    pub meta: Meta,
    /// The address this rule is for: its part before the @ (or the whole
    /// address, which must be in the zone or below it), or "*" for every
    /// address no other rule is for.
    pub address: String,
    /// forward: pass the mail on to the destinations. drop: take it and
    /// throw it away. worker: hand the message to a Worker script's `email()` handler.
    #[serde(default = "EmailRule::forward")]
    pub action: String,
    /// Mailboxes elsewhere that get the mail (when `action == "forward"`).
    #[serde(default)]
    pub destinations: Vec<String>,
    /// Worker script name (when `action == "worker"`).
    #[serde(default)]
    pub worker: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// A mailbox: local@domain, lower-cased domain. Not the full grammar of
/// RFC 5321, just what a sane address looks like.
pub fn check_mailbox(what: &str, address: &str) -> Result<String, StoreError> {
    const SPECIALS: &[u8] = b"!#$%&'*+-/=?^_`{|}~.";
    let address = address.trim();
    let Some((local, domain)) = address.rsplit_once('@') else { return invalid(format!("{what}: '{address}' is not an e-mail address")) };
    let local_ok = !local.is_empty() && local.len() <= 64 && local.bytes().all(|b| b.is_ascii_alphanumeric() || SPECIALS.contains(&b));
    if !local_ok || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return invalid(format!("{what}: '{address}' is not an e-mail address"));
    }
    let domain = check_host(what, domain)?;
    if !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok() {
        return invalid(format!("{what}: '{address}' is not an e-mail address"));
    }
    Ok(format!("{local}@{domain}"))
}

impl EmailRule {
    fn forward() -> String {
        "forward".into()
    }
}

impl Item for EmailRule {
    item_boilerplate!(email_rules);
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError> {
        one_of("action", &self.action, &["forward", "drop", "worker"])?;
        let address = self.address.trim().to_ascii_lowercase();
        self.address = if address == "*" {
            address
        } else {
            // a bare local part means "at the zone's own name"
            let full = if address.contains('@') { address } else { format!("{address}@{}", zone.name) };
            let full = check_mailbox("address", &full)?;
            let domain = full.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
            if domain != zone.name && !domain.ends_with(&format!(".{}", zone.name)) {
                return invalid(format!("address: '{full}' is not an address of {}", zone.name));
            }
            full
        };
        let taken = d.email_rules.iter().any(|r| r.meta.zone_id == zone.id && r.meta.id != self.meta.id && r.address == self.address);
        if taken {
            return Err(StoreError::Conflict(format!("there is a rule for {} already", self.address)));
        }
        if self.action == "drop" {
            self.destinations.clear();
            self.worker = None;
        } else if self.action == "worker" {
            self.destinations.clear();
            let name = self.worker.as_deref().map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| {
                StoreError::Invalid("a worker email rule requires a worker script name".into())
            })?;
            if !d.workers.iter().any(|w| w.name == name) {
                return invalid(format!("worker script '{name}' does not exist"));
            }
            self.worker = Some(name.to_string());
        } else {
            self.worker = None;
            let mut destinations = Vec::new();
            for destination in &self.destinations {
                let mailbox = check_mailbox("destinations", destination)?;
                let domain = mailbox.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
                // (forwarding into a zone we route ourselves would only go in circles)
                let ours = |z: &Zone| domain == z.name || domain.ends_with(&format!(".{}", z.name));
                if ours(zone) || d.zones.iter().any(|z| z.settings.email_routing && ours(z)) {
                    return invalid(format!("destinations: {mailbox} is an address of a zone whose mail is routed here"));
                }
                if !destinations.contains(&mailbox) {
                    destinations.push(mailbox);
                }
            }
            if destinations.is_empty() || destinations.len() > 10 {
                return invalid("a forwarding rule has between 1 and 10 destinations");
            }
            self.destinations = destinations;
        }
        if self.description.len() > 200 {
            return invalid("description exceeds 200 characters");
        }
        Ok(())
    }
}

// ----------------------------------------------------- redirect rules ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectRule {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub expression: String,
    /// Absolute URL or a path starting with `/`.
    pub target_url: String,
    #[serde(default = "RedirectRule::default_status")]
    pub status_code: u16,
    /// Append the request's query string to the target.
    #[serde(default)]
    pub preserve_query_string: bool,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
}

impl RedirectRule {
    fn default_status() -> u16 {
        302
    }
}

impl Item for RedirectRule {
    item_boilerplate!(redirect_rules);
    fn validate(&mut self, _: &Zone, d: &Data) -> Result<(), StoreError> {
        check_expr(&self.expression, d)?;
        let t = &self.target_url;
        let well_formed = (t.starts_with("https://") || t.starts_with("http://") || t.starts_with('/'))
            && t.bytes().all(|b| b.is_ascii_graphic());
        if !well_formed {
            return invalid("target_url must be an http(s) URL or a path starting with '/'");
        }
        if ![301, 302, 303, 307, 308].contains(&self.status_code) {
            return invalid("status_code must be 301, 302, 303, 307 or 308");
        }
        Ok(())
    }
}

// ---------------------------------------------------- transform rules ----

/// Rewrites the request before it reaches workers/origin and the response
/// before it reaches the client. All matching rules apply, in priority order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformRule {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    /// Replace the request path (the query string is kept).
    #[serde(default)]
    pub rewrite_path: Option<String>,
    #[serde(default)]
    pub set_request_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub remove_request_headers: Vec<String>,
    #[serde(default)]
    pub set_response_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub remove_response_headers: Vec<String>,
}

impl Item for TransformRule {
    item_boilerplate!(transform_rules);
    fn validate(&mut self, _: &Zone, d: &Data) -> Result<(), StoreError> {
        check_expr(&self.expression, d)?;
        const PROTECTED: &[&str] = &["host", "content-length", "transfer-encoding", "connection", "upgrade"];
        let check_name = |n: &str| {
            let name = n.to_ascii_lowercase();
            if hyper::header::HeaderName::from_bytes(name.as_bytes()).is_err() || PROTECTED.contains(&name.as_str()) {
                return invalid(format!("header '{n}' cannot be modified"));
            }
            Ok(name)
        };
        for map in [&mut self.set_request_headers, &mut self.set_response_headers] {
            let mut normalized = BTreeMap::new();
            for (k, v) in map.iter() {
                if hyper::header::HeaderValue::from_str(v).is_err() {
                    return invalid(format!("invalid value for header '{k}'"));
                }
                normalized.insert(check_name(k)?, v.clone());
            }
            *map = normalized;
        }
        for list in [&mut self.remove_request_headers, &mut self.remove_response_headers] {
            *list = list.iter().map(|n| check_name(n)).collect::<Result<_, _>>()?;
        }
        if let Some(p) = &self.rewrite_path {
            if !p.starts_with('/') || p.contains(['?', '#']) || !p.bytes().all(|b| b.is_ascii_graphic()) {
                return invalid("rewrite_path must be a path starting with '/' without query or fragment");
            }
        }
        let empty = self.rewrite_path.is_none()
            && self.set_request_headers.is_empty()
            && self.remove_request_headers.is_empty()
            && self.set_response_headers.is_empty()
            && self.remove_response_headers.is_empty();
        if empty {
            return invalid("a transform rule needs at least one action");
        }
        Ok(())
    }
}

// -------------------------------------------------------- cache rules ----

/// Overrides the default cache eligibility; the first matching rule wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub expression: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    /// `true`: cache matching responses whatever their file type
    /// ("cache everything"); `false`: never cache them.
    pub cache: bool,
    /// Seconds to keep matching responses, ignoring the origin's
    /// `Cache-Control`.
    #[serde(default)]
    pub edge_ttl: Option<u32>,
    /// One copy whatever the query string: the key is the path alone.
    #[serde(default)]
    pub ignore_query: bool,
}

impl Item for CacheRule {
    item_boilerplate!(cache_rules);
    fn validate(&mut self, _: &Zone, d: &Data) -> Result<(), StoreError> {
        check_expr(&self.expression, d)?;
        if self.edge_ttl.is_some_and(|t| t == 0 || t > 31_536_000) {
            return invalid("edge_ttl must be between 1 and 31536000 seconds");
        }
        Ok(())
    }
}

// --------------------------------------------------------- edge nodes ----

/// One edge server of the fleet and the part of the world it serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeNode {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub ipv4: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Continents (AF AN AS EU NA OC SA) whose visitors are sent here.
    #[serde(default)]
    pub continents: Vec<String>,
    /// Disabled nodes are left out of DNS answers.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Traffic the node may serve per period, in GB (10^9 bytes of response
    /// bodies). Past `traffic_dns_gb` it is left out of DNS answers; past
    /// `traffic_throttle_gb` its speed limit sets in; past
    /// `traffic_limit_gb` it answers every request with a notice.
    #[serde(default)]
    pub traffic_dns_gb: Option<f64>,
    #[serde(default)]
    pub traffic_throttle_gb: Option<f64>,
    #[serde(default)]
    pub traffic_limit_gb: Option<f64>,
    /// `month` or `day` (UTC).
    #[serde(default = "EdgeNode::monthly")]
    pub traffic_period: String,
    /// Day of the month (1-28) on which a monthly allowance starts over.
    #[serde(default = "EdgeNode::first")]
    pub traffic_reset_day: u32,
    /// Upper bound on the speed at which the node sends responses, in
    /// Mbit/s: always, or from `traffic_throttle_gb` on if that is set.
    #[serde(default)]
    pub rate_limit_mbps: Option<f64>,
    /// How DNS treats this node past `traffic_dns_gb`: `drop` (100% removed
    /// immediately) or `linear` (probabilistically offloaded from 0% at
    /// `traffic_dns_gb` to 100% at `traffic_limit_gb`).
    #[serde(default = "EdgeNode::drop_mode")]
    pub dns_offload_mode: String,
    /// When true and the node is past `traffic_dns_gb`, its public DNS
    /// listener (port 53) stops replying so recursive resolvers move to
    /// other name servers. Loopback queries still answer for health checks.
    #[serde(default)]
    pub dns_silent_on_limit: bool,
    /// Optional data-center index reported as `dc=<n>` in `/cdn-cgi/fucf-trace`
    /// (defaults to trailing digits in `name`, or 1 when omitted).
    #[serde(default)]
    pub dc: Option<u32>,
    /// Location code shown as `colo=` in the trace and on the edge's error
    /// pages: the IATA code of the nearest airport, like Cloudflare's (`NRT`,
    /// `CMH`). Several machines at one place share it and differ in `dc`
    /// (and so in `fl`). Defaults to the node name without trailing digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colo: Option<String>,
    /// Node role (`"peer"` or `"accelerate"`, empty defaults to `"peer"`).
    #[serde(default)]
    pub role: String,
    /// Per-subdomain allowlist when this node runs in `accelerate` mode
    /// (exact or `*.domain` wildcard; empty = never returned in DNS / 403 on edge).
    #[serde(default)]
    pub accel_hosts: Vec<String>,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl EdgeNode {
    fn monthly() -> String {
        "month".into()
    }

    fn first() -> u32 {
        1
    }

    fn drop_mode() -> String {
        "drop".into()
    }

    pub fn validate(&mut self, others: &[EdgeNode]) -> Result<(), StoreError> {
        self.colo = self.colo.as_deref().map(|c| c.trim().to_ascii_uppercase()).filter(|c| !c.is_empty());
        if self.colo.as_deref().is_some_and(|c| c.len() != 3 || !c.bytes().all(|b| b.is_ascii_uppercase())) {
            return invalid("colo must be a three-letter airport code (e.g. NRT), or null");
        }
        if self.dc.is_some_and(|n| n == 0 || n > 999) {
            return invalid("dc must be between 1 and 999");
        }
        let amounts = [
            ("traffic_dns_gb", self.traffic_dns_gb),
            ("traffic_throttle_gb", self.traffic_throttle_gb),
            ("traffic_limit_gb", self.traffic_limit_gb),
            ("rate_limit_mbps", self.rate_limit_mbps),
        ];
        for (what, value) in amounts {
            if value.is_some_and(|v| !(v > 0.0 && v.is_finite())) {
                return invalid(format!("{what} must be a positive number (null for none)"));
            }
        }
        // the thresholds come in this order: leave DNS, slow down, stop serving
        let steps: Vec<f64> = [self.traffic_dns_gb, self.traffic_throttle_gb, self.traffic_limit_gb].into_iter().flatten().collect();
        if steps.windows(2).any(|pair| pair[0] > pair[1]) {
            return invalid("the traffic thresholds must not decrease: traffic_dns_gb <= traffic_throttle_gb <= traffic_limit_gb");
        }
        if self.traffic_throttle_gb.is_some() && self.rate_limit_mbps.is_none() {
            return invalid("traffic_throttle_gb needs rate_limit_mbps: the speed to slow down to");
        }
        one_of("dns_offload_mode", &self.dns_offload_mode, &["drop", "linear"])?;
        if self.dns_offload_mode == "linear" && self.traffic_dns_gb.is_some() && self.traffic_limit_gb.is_none() {
            return invalid("dns_offload_mode 'linear' needs traffic_limit_gb as the 100% upper bound");
        }
        one_of("traffic_period", &self.traffic_period, &["month", "day"])?;
        if !(1..=28).contains(&self.traffic_reset_day) {
            return invalid("traffic_reset_day must be between 1 and 28");
        }
        if self.dc == Some(0) {
            return invalid("dc must be >= 1");
        }
        self.name = self.name.trim().to_ascii_lowercase();
        let name_ok = !self.name.is_empty()
            && self.name.len() <= 32
            && self.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok {
            return invalid("node names may contain a-z, 0-9 and '-' (max 32 characters)");
        }
        if others.iter().any(|n| n.name == self.name && n.id != self.id) {
            return Err(StoreError::Conflict(format!("a node named '{}' already exists", self.name)));
        }
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return invalid("a node needs an IPv4 or IPv6 address");
        }
        for c in &mut self.continents {
            *c = c.trim().to_ascii_uppercase();
            if !crate::geo::CONTINENTS.contains(&c.as_str()) {
                return invalid(format!("unknown continent '{c}' (use AF, AN, AS, EU, NA, OC, SA)"));
            }
        }
        self.continents.sort();
        self.continents.dedup();
        self.role = self.role.trim().to_ascii_lowercase();
        if !self.role.is_empty() {
            one_of("role", &self.role, &["peer", "accelerate"])?;
        }
        let mut normalized_accel = Vec::with_capacity(self.accel_hosts.len());
        for h in &self.accel_hosts {
            let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
            if h.is_empty() {
                continue;
            }
            if h != "*" {
                let check = h.strip_prefix("*.").unwrap_or(&h);
                check_host("accel_hosts", check)?;
            }
            if !normalized_accel.contains(&h) {
                normalized_accel.push(h);
            }
        }
        self.accel_hosts = normalized_accel;
        Ok(())
    }
}

/// Returns true if `host` matches any entry in `allowlist` (exact, `*.domain`, or `*`).
/// Empty `allowlist` always returns `false`.
pub fn accel_host_matches(allowlist: &[String], host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || allowlist.is_empty() {
        return false;
    }
    allowlist.iter().any(|pat| {
        if pat == "*" {
            true
        } else if let Some(suffix) = pat.strip_prefix("*.") {
            h.ends_with(&format!(".{suffix}")) && h.len() > suffix.len() + 1
        } else {
            h == *pat
        }
    })
}

/// A cache purge, replicated so every node drops the same objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeOp {
    pub id: String,
    pub zone_id: String,
    #[serde(default)]
    pub everything: bool,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// What the origin tagged with one of these (`Cache-Tag`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

/// Self-owned per-node traffic-limit and mainland-China reachability telemetry
/// replicated across peers via LWW without primary-only overwrites.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeTelemetry {
    pub node: String,
    pub limit_state: crate::limits::State,
    pub offload_pct: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gfw: Option<crate::gfw::GfwStatus>,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

/// Steers a class of visitors (by country, continent and/or network
/// operator) to an ordered list of edge nodes: the first healthy one is
/// answered. Rules are tried in priority order before the per-continent
/// assignment of the nodes themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteerRule {
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// ISO country codes; empty matches any country.
    #[serde(default)]
    pub countries: Vec<String>,
    /// ISO 3166-2 subdivision codes (provinces/states, e.g. `JS`, `ZJ`, `SH`, `SD`, `AH`); empty matches any region.
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub continents: Vec<String>,
    /// Autonomous system numbers of the visitor's network.
    #[serde(default)]
    pub asns: Vec<u32>,
    /// Substrings of the operator name (case-insensitive), as an alternative to `asns`.
    #[serde(default)]
    pub as_orgs: Vec<String>,
    /// `route` (default): answer the first healthy node of `nodes`.
    /// `block`: refuse to resolve for these visitors (DNS-level blocking).
    #[serde(default = "SteerRule::route")]
    pub action: String,
    /// Node names in order of preference.
    #[serde(default)]
    pub nodes: Vec<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl SteerRule {
    fn route() -> String {
        "route".into()
    }

    pub fn matches(&self, loc: &crate::geo::Location) -> bool {
        let in_list = |list: &[String], value: &Option<String>| list.is_empty() || value.as_ref().is_some_and(|v| list.contains(v));
        let network = (self.asns.is_empty() && self.as_orgs.is_empty())
            || loc.asn.is_some_and(|a| self.asns.contains(&a))
            || loc.as_org.as_ref().is_some_and(|org| self.as_orgs.iter().any(|k| org.contains(k.as_str())));
        in_list(&self.countries, &loc.country)
            && in_list(&self.regions, &loc.region)
            && in_list(&self.continents, &loc.continent)
            && network
    }

    pub fn validate(&mut self, nodes: &[EdgeNode]) -> Result<(), StoreError> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.len() > 64 {
            return invalid("a steering rule needs a name (max 64 characters)");
        }
        for c in &mut self.countries {
            *c = c.trim().to_ascii_uppercase();
            if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
                return invalid(format!("'{c}' is not a two-letter country code"));
            }
        }
        for r in &mut self.regions {
            *r = r.trim().to_ascii_uppercase();
            if r.is_empty() || r.len() > 8 || !r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return invalid(format!("'{r}' is not a valid region/subdivision code"));
            }
        }
        self.regions.sort();
        self.regions.dedup();
        for c in &mut self.continents {
            *c = c.trim().to_ascii_uppercase();
            if !crate::geo::CONTINENTS.contains(&c.as_str()) {
                return invalid(format!("unknown continent '{c}'"));
            }
        }
        self.as_orgs = self.as_orgs.iter().map(|o| o.trim().to_ascii_lowercase()).filter(|o| !o.is_empty()).collect();
        one_of("action", &self.action, &["route", "fastest", "block"])?;
        if self.action == "block" {
            self.nodes.clear();
        } else if self.nodes.is_empty() && self.action == "route" {
            return invalid("a routing rule needs at least one node");
        }
        for n in &self.nodes {
            if !nodes.iter().any(|e| &e.name == n) {
                return invalid(format!("node '{n}' does not exist"));
            }
        }
        Ok(())
    }
}

// --------------------------------------------------- local proxy rules ----

/// One backend endpoint in a `LocalProxyRule`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyUpstream {
    /// Upstream URL: `http://`, `https://`, `h2c://`, `ws://`, or `wss://`.
    pub url: String,
    /// Relative weight for weighted load balancing (default 1, must be >= 1).
    #[serde(default = "ProxyUpstream::default_weight")]
    pub weight: u32,
    /// Skip TLS certificate verification when connecting to `https://` or `wss://`.
    #[serde(default)]
    pub tls_insecure: bool,
}

impl ProxyUpstream {
    fn default_weight() -> u32 {
        1
    }
}

impl Default for ProxyUpstream {
    fn default() -> Self {
        ProxyUpstream {
            url: String::new(),
            weight: 1,
            tls_insecure: false,
        }
    }
}

/// A fixed answer for a `LocalProxyRule` (Caddy's `respond`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticResponse {
    /// HTTP status (100-599, default 200).
    pub status: u16,
    pub body: String,
    /// `Content-Type` of the body (default `text/plain; charset=utf-8`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

impl Default for StaticResponse {
    fn default() -> Self {
        StaticResponse { status: 200, body: String::new(), content_type: None }
    }
}

/// Native reverse-proxy rule (Caddy replacement) + Hysteria 2 masquerade fallback.
///
/// What a matching request gets, in this order: `redirect_url`, `respond`,
/// files from `file_root`, or the `upstreams`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalProxyRule {
    pub id: String,
    pub name: String,
    /// Edge node names this rule applies to; empty means all nodes.
    pub nodes: Vec<String>,
    /// Optional listener port scope (e.g. `3443` or `18480`); `None` matches any port.
    pub listen_port: Option<u16>,
    /// Hostnames matched by this rule (exact or `*.domain` or `*`). Empty matches any
    /// host on `listen_port`/proxy listeners or in `is_fallback` mode.
    pub hosts: Vec<String>,
    /// Path prefix (or exact path when `exact_path == true`), e.g. `/` or `/api`.
    pub path_prefix: String,
    pub exact_path: bool,
    /// Optional replacement path (or prefix when `strip_prefix` is true) before forwarding.
    pub rewrite_path: Option<String>,
    /// Strip `path_prefix` from the request path before forwarding (prepending `rewrite_path` if set).
    pub strip_prefix: bool,
    /// Immediate HTTP redirect target (e.g. `"/admin"` or `"https://example.com"`), bypassing upstreams.
    pub redirect_url: Option<String>,
    /// HTTP status for `redirect_url` (300-399, default 302).
    pub redirect_status: Option<u16>,
    /// Mask upstream >= 400 responses as `404 Not Found` (`"not found"`).
    pub mask_upstream_errors: bool,
    pub upstreams: Vec<ProxyUpstream>,
    /// Answer with this instead of forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respond: Option<StaticResponse>,
    /// Serve files from this directory instead of forwarding (only below the
    /// directories a node allows with `--file-root-allow`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_root: Option<String>,
    /// What is tried for a directory under `file_root` (default `index.html`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub index_files: Vec<String>,
    /// On the nodes the rule names explicitly, obtain a certificate for its
    /// concrete hosts (no wildcards) when no other one covers them, like
    /// Caddy's automatic HTTPS. The node proves the names itself.
    #[serde(default = "yes")]
    pub auto_https: bool,
    /// Answer plain-HTTP requests with a permanent redirect to `https://`.
    pub https_redirect: bool,
    /// Keep the visitor's `Host` header when forwarding to the upstream.
    #[serde(default = "yes")]
    pub preserve_host: bool,
    pub strip_response_headers: Vec<String>,
    pub set_response_headers: BTreeMap<String, String>,
    pub set_request_headers: BTreeMap<String, String>,
    /// Catch-all fallback rule (used on Hysteria 2 masquerade front or unmatched proxy hosts).
    pub is_fallback: bool,
    /// Lower runs first.
    pub priority: i32,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub created_on: String,
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl Default for LocalProxyRule {
    fn default() -> Self {
        LocalProxyRule {
            id: String::new(),
            name: String::new(),
            nodes: Vec::new(),
            listen_port: None,
            hosts: Vec::new(),
            path_prefix: "/".into(),
            exact_path: false,
            rewrite_path: None,
            strip_prefix: false,
            redirect_url: None,
            redirect_status: None,
            mask_upstream_errors: false,
            upstreams: Vec::new(),
            respond: None,
            file_root: None,
            index_files: Vec::new(),
            auto_https: true,
            https_redirect: false,
            preserve_host: true,
            strip_response_headers: Vec::new(),
            set_response_headers: BTreeMap::new(),
            set_request_headers: BTreeMap::new(),
            is_fallback: false,
            priority: 0,
            enabled: true,
            created_on: String::new(),
            modified_on: String::new(),
            sync: SyncMeta::default(),
        }
    }
}

impl LocalProxyRule {
    pub fn validate(&mut self) -> Result<(), StoreError> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.len() > 128 {
            return invalid("a proxy rule needs a name (1-128 characters)");
        }
        if self.listen_port == Some(0) {
            return invalid("listen_port must be between 1 and 65535");
        }
        for n in &mut self.nodes {
            *n = n.trim().to_ascii_lowercase();
        }
        self.nodes.retain(|n| !n.is_empty());
        self.nodes.sort();
        self.nodes.dedup();

        let mut normalized_hosts = Vec::with_capacity(self.hosts.len());
        for h in &self.hosts {
            let h = h.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
            if h.is_empty() {
                continue;
            }
            // IP addresses in canonical form, as requests are matched
            let h = h.parse::<std::net::IpAddr>().map(|ip| ip.to_string()).unwrap_or(h);
            if h != "*" {
                let check = h.strip_prefix("*.").unwrap_or(&h);
                check_host("hosts", check)?;
            }
            if !normalized_hosts.contains(&h) {
                normalized_hosts.push(h);
            }
        }
        self.hosts = normalized_hosts;

        self.path_prefix = self.path_prefix.trim().to_string();
        if self.path_prefix.is_empty() {
            self.path_prefix = "/".into();
        }
        if !self.path_prefix.starts_with('/') || self.path_prefix.contains(['?', '#']) {
            return invalid("path_prefix must start with '/' and must not contain '?' or '#'");
        }

        if let Some(rp) = &mut self.rewrite_path {
            let t = rp.trim().to_string();
            if t.is_empty() {
                self.rewrite_path = None;
            } else if !t.starts_with('/') || t.contains(['?', '#']) {
                return invalid("rewrite_path must start with '/' and must not contain '?' or '#'");
            } else {
                *rp = t;
            }
        }
        if let Some(ru) = &mut self.redirect_url {
            let t = ru.trim().to_string();
            if t.is_empty() {
                self.redirect_url = None;
            } else {
                *ru = t;
            }
        }
        if let Some(rs) = self.redirect_status {
            if !(300..=399).contains(&rs) {
                return invalid("redirect_status must be between 300 and 399");
            }
        }

        if let Some(r) = &mut self.respond {
            if !(100..=599).contains(&r.status) {
                return invalid("respond.status must be between 100 and 599");
            }
            if r.body.len() > 64 * 1024 {
                return invalid("respond.body is limited to 64 KiB");
            }
            if let Some(ct) = &mut r.content_type {
                *ct = ct.trim().to_string();
                if ct.is_empty() {
                    r.content_type = None;
                } else if hyper::header::HeaderValue::from_str(ct).is_err() {
                    return invalid("respond.content_type is not a valid header value");
                }
            }
        }
        if let Some(root) = &mut self.file_root {
            let t = root.trim().trim_end_matches('/').to_string();
            if t.is_empty() && root.trim() != "/" {
                self.file_root = None;
            } else if !t.starts_with('/') || t.split('/').any(|seg| seg == "..") {
                return invalid("file_root must be an absolute path without '..'");
            } else {
                *root = t;
            }
        }
        for name in &mut self.index_files {
            *name = name.trim().to_string();
            if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
                return invalid("index_files are plain file names (index.html, index.htm, ...)");
            }
        }
        if self.upstreams.is_empty() && self.redirect_url.is_none() && self.respond.is_none() && self.file_root.is_none() {
            return invalid("a proxy rule needs at least one upstream (or redirect_url, respond or file_root)");
        }
        for u in &mut self.upstreams {
            u.url = u.url.trim().to_string();
            let uri: hyper::Uri = u.url.parse().map_err(|e| StoreError::Invalid(format!("invalid upstream URL '{}': {e}", u.url)))?;
            let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
            if !matches!(scheme.as_str(), "http" | "https" | "h2c" | "ws" | "wss") {
                return invalid(format!("upstream '{}' must use http://, https://, h2c://, ws://, or wss://", u.url));
            }
            if uri.authority().is_none_or(|a| a.host().is_empty()) {
                return invalid(format!("upstream '{}' must include a host", u.url));
            }
            if u.weight == 0 {
                return invalid("upstream weight must be >= 1");
            }
        }

        for list in [&mut self.strip_response_headers] {
            for h in list.iter_mut() {
                let name = h.trim().to_ascii_lowercase();
                if hyper::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return invalid(format!("invalid header name '{h}'"));
                }
                *h = name;
            }
        }
        for map in [&mut self.set_request_headers, &mut self.set_response_headers] {
            let mut normalized = BTreeMap::new();
            for (k, v) in map.iter() {
                let name = k.trim().to_ascii_lowercase();
                if hyper::header::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return invalid(format!("invalid header name '{k}'"));
                }
                if hyper::header::HeaderValue::from_str(v).is_err() {
                    return invalid(format!("invalid value for header '{k}'"));
                }
                normalized.insert(name, v.clone());
            }
            *map = normalized;
        }
        Ok(())
    }
}
