//! Custom hostnames (Cloudflare's "SSL for SaaS"): a name that belongs to
//! somebody else (`shop.example.net`, a customer of a SaaS) is served as one
//! of the zones of this fleet (the SaaS's `example.com`), with a certificate
//! the fleet obtains for it.
//!
//! A [`CustomHostname`] belongs to one zone (`/zones/{id}/custom_hostnames`,
//! so the zone's owner and the SSL token permissions decide who may touch
//! it). Its name must be a public host name a CA could certify: no IP, no
//! wildcard, not a zone of this fleet nor above or below one (whoever's),
//! not a name the fleet keeps for itself, and not already another zone's
//! custom hostname. It cannot be renamed.
//!
//! **Proving it.** Serving a name and getting a certificate for it must take
//! the consent of whoever runs its DNS, and the fleet cannot look at other
//! people's DNS (it is the authority for its own zones only, and makes no
//! outside lookups). What a CA's validation of an HTTP-01 or TLS-ALPN-01
//! challenge would show is only that the name reaches *some* node of the
//! fleet, which is equally true when it points at another user's zone; a
//! visitor's TLS handshake or request shows even less (anybody can send any
//! server name). So the proof is a DNS-01 challenge that the name's owner
//! delegates to this one custom hostname: the owner adds
//!
//! ```text
//! _acme-challenge.shop.example.net. CNAME _acme-challenge.<verify_txt>.example.com.
//! ```
//!
//! (for a zone whose DNS is hosted elsewhere, `_acme-challenge.<verify_txt>.example.com.<cname base>.`),
//! where `verify_txt` is a random label made for this custom hostname when it
//! is created. While an order runs, the fleet's DNS answers the challenge's
//! TXT record at that name and nowhere else, so the CA validates only when
//! the owner pointed the delegation at this zone's own custom hostname.
//! Authorizations the CA remembers from earlier orders are not taken
//! (crate::acme::Acme::issue_fleet `fresh`).
//!
//! **When.** Issuance is lazy, so that nothing is ordered for a name whose
//! DNS does not point here (yet): a created custom hostname
//! stays `pending` until a visitor asks for it (a TLS handshake with its
//! server name or a request with its Host, which shows that its DNS points
//! here), and only then is a certificate ordered, by the node holding the
//! fleet's ACME lease. A handshake for a name that is not a created custom
//! hostname does nothing at all. A visitor's request is only the trigger;
//! the CA's validation is the proof. Then `active` (served, renewed in the
//! last third of the certificate's life, whoever visits), or `failed` with
//! the CA's reason, retried later. Attempts back off per hostname (10
//! minutes, doubling up to a day) and are limited per zone and for the whole
//! fleet per hour, so that a stream of visitors or of new custom hostnames
//! cannot make the fleet hammer the CA.
//!
//! **Serving.** Requests for an active custom hostname go through the owning
//! zone's pipeline (firewall, rules, cache, the zone's settings) with their
//! own Host, so cache keys and `http.host`
//! stay the custom hostname's; the origin is that of `custom_origin_server`
//! (a proxied host of the zone, the apex when empty). A zone that is added
//! later at or above the name takes it over: the custom hostname is then
//! neither served nor renewed.

use crate::acme::Acme;
use crate::items::{in_zone, Item, Meta};
use crate::store::{Data, Snapshot, Store, StoreError, Zone, ZoneSnap};
use crate::sync::SyncMeta;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Custom hostnames per zone.
pub const MAX_PER_ZONE: usize = 100;
/// Certificate orders per zone and hour, renewals included.
pub const ZONE_ATTEMPTS_PER_HOUR: usize = 10;
/// Certificate orders for custom hostnames per hour, the whole fleet together.
pub const FLEET_ATTEMPTS_PER_HOUR: usize = 30;
/// Orders one look at the work starts at most (looks come every minute and
/// on every configuration change).
pub const ATTEMPTS_PER_LOOK: usize = 3;
/// A node notes a visitor of the same waiting custom hostname at most this often.
const NOTE_EVERY: Duration = Duration::from_secs(600);
/// What a node keeps of the visitors it noted.
const NOTED_MAX: usize = 4096;
/// The CA's reason, as much of it as is kept.
const ERROR_MAX: usize = 512;
/// The label under which a CA looks for a DNS-01 answer.
const ACME_LABEL: &str = "_acme-challenge";

pub const PENDING: &str = "pending";
pub const ACTIVE: &str = "active";
pub const FAILED: &str = "failed";

// --------------------------------------------------------------- the item ----

/// One name served as a zone of this fleet. Everything below `hostname` and
/// `custom_origin_server` is the server's: whatever a request body says about
/// it is ignored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomHostname {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub hostname: String,
    /// A host of the zone with a proxied record: where requests for the
    /// custom hostname go (its records' origin). Empty: the zone apex.
    #[serde(default)]
    pub custom_origin_server: String,
    /// `pending`, `active` or `failed`.
    #[serde(default)]
    pub status: String,
    /// The random label of the DNS-01 delegation target (see the module).
    #[serde(default)]
    pub verify_txt: String,
    /// Why the last order failed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// When a visitor first asked for it (what lets the first order start).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_at: Option<String>,
    /// Failed orders in a row.
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    /// Never shown by the API.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
}

fn conflict<T>(m: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Conflict(m.into()))
}

/// The name as stored, or why it cannot be a custom hostname: lower case,
/// no trailing dot, at most 253 characters, ASCII only (internationalized
/// names in their `xn--` form), no IP address or wildcard, and a public name
/// a CA could certify (crate::site_acme::eligible: no `.test`, `.local`, ...).
pub fn check_hostname(raw: &str) -> Result<String, String> {
    let h = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return Err("hostname is required".into());
    }
    if h.len() > 253 {
        return Err("hostname: at most 253 characters".into());
    }
    if h.parse::<std::net::IpAddr>().is_ok() || h.starts_with('[') {
        return Err(format!("hostname: '{h}' is an IP address; a custom hostname is a DNS name"));
    }
    if h.contains('*') {
        return Err("hostname: wildcards cannot be custom hostnames".into());
    }
    if !h.is_ascii() {
        return Err("hostname: write an internationalized name in its ASCII (xn--) form".into());
    }
    if !crate::site_acme::eligible(&h) {
        return Err(format!("hostname: '{h}' is not a public host name a certificate authority could certify"));
    }
    Ok(h)
}

/// Is one of the names the other one or below it?
fn overlaps(zone: &str, host: &str) -> bool {
    let under = |a: &str, b: &str| a == b || a.strip_suffix(b).is_some_and(|rest| rest.ends_with('.'));
    under(host, zone) || under(zone, host)
}

/// Is `host` a zone's name or below one? Such a zone answers for it.
fn covered(zones: &[Zone], host: &str) -> bool {
    zones.iter().any(|z| in_zone(z, host))
}

impl Item for CustomHostname {
    fn vec(d: &Data) -> &Vec<Self> {
        &d.custom_hostnames
    }
    fn vec_mut(d: &mut Data) -> &mut Vec<Self> {
        &mut d.custom_hostnames
    }
    fn tombstones(d: &Data) -> &BTreeMap<String, SyncMeta> {
        &d.tombstones.custom_hostnames
    }
    fn tombstones_mut(d: &mut Data) -> &mut BTreeMap<String, SyncMeta> {
        &mut d.tombstones.custom_hostnames
    }
    fn meta(&self) -> &Meta {
        &self.meta
    }
    fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError> {
        let invalid = |m: String| Err(StoreError::Invalid(m));
        if zone.kind == "cert" {
            return invalid("a certificate-only zone is not proxied: it cannot serve custom hostnames".into());
        }
        let id = self.meta.id.clone();
        match d.custom_hostnames.iter().find(|h| h.meta.id == id) {
            Some(before) => {
                // the name is what was proven: it does not change under its certificate
                let asked = self.hostname.trim().trim_end_matches('.').to_ascii_lowercase();
                if asked != before.hostname {
                    return invalid("hostname cannot be changed: delete this custom hostname and create one for the new name".into());
                }
                let (origin, meta) = (self.custom_origin_server.clone(), self.meta.clone());
                *self = before.clone();
                (self.custom_origin_server, self.meta) = (origin, meta);
            }
            None => {
                if d.custom_hostnames.iter().filter(|h| h.meta.zone_id == zone.id).count() >= MAX_PER_ZONE {
                    return invalid(format!("a zone has at most {MAX_PER_ZONE} custom hostnames"));
                }
                let host = check_hostname(&self.hostname).map_err(StoreError::Invalid)?;
                // which zone is not said: it may be another user's
                if d.zones.iter().any(|z| overlaps(&z.name, &host)) {
                    return conflict(format!("'{host}' is a zone of this fleet, or above or below one: it cannot be a custom hostname"));
                }
                if crate::store::reserved(&host) {
                    return conflict(format!("'{host}' is a name this fleet keeps for itself"));
                }
                if d.custom_hostnames.iter().any(|h| h.hostname == host) {
                    return conflict(format!("'{host}' is already a custom hostname"));
                }
                let (origin, meta) = (self.custom_origin_server.clone(), self.meta.clone());
                *self = CustomHostname {
                    meta,
                    hostname: host,
                    custom_origin_server: origin,
                    status: PENDING.into(),
                    verify_txt: uuid::Uuid::new_v4().simple().to_string(),
                    ..Default::default()
                };
            }
        }

        let origin = self.custom_origin_server.trim().trim_end_matches('.').to_ascii_lowercase();
        if !origin.is_empty() {
            let n = crate::dns::wire::normalize_name(&origin).map_err(|e| StoreError::Invalid(format!("custom_origin_server: {e}")))?;
            if n.contains(['*', '_']) {
                return invalid(format!("custom_origin_server: '{n}' must be one host name, not a pattern"));
            }
            if !in_zone(zone, &n) {
                return invalid(format!("custom_origin_server '{n}' is not part of zone {}", zone.name));
            }
            if let Some(inner) = d.zones.iter().find(|z| z.id != zone.id && z.name.len() > zone.name.len() && in_zone(z, &n)) {
                return invalid(format!("custom_origin_server '{n}' is served by zone {}, not by {}", inner.name, zone.name));
            }
            self.custom_origin_server = n;
        } else {
            self.custom_origin_server = String::new();
        }
        Ok(())
    }
    fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.remove("sync");
            o.remove("private_key");
        }
        v
    }
}

/// A custom hostname as the API shows it: the item, plus the CNAME record its
/// owner adds to prove it (`dcv_delegation`, null when this fleet cannot
/// answer it: a zone hosted elsewhere and no CNAME base) and where its
/// traffic should point (`cname_target`).
pub fn view(h: &CustomHostname, zone: &Zone, cname_base: Option<&str>) -> Value {
    let mut v = h.public();
    let delegation = match (zone.kind.as_str(), cname_base) {
        ("full", _) => Some(format!("{ACME_LABEL}.{}.{}", h.verify_txt, zone.name)),
        (_, Some(base)) => Some(format!("{ACME_LABEL}.{}.{}.{base}", h.verify_txt, zone.name)),
        _ => None,
    };
    v["dcv_delegation"] = match delegation {
        Some(content) => json!({ "type": "CNAME", "name": format!("{ACME_LABEL}.{}", h.hostname), "content": content }),
        None => Value::Null,
    };
    v["cname_target"] = json!(if h.custom_origin_server.is_empty() { zone.name.as_str() } else { h.custom_origin_server.as_str() });
    v
}

/// Whether a custom hostname may be created in `zone` here: its DCV
/// delegation needs a name this fleet's DNS answers.
pub fn may_create(zone: &Zone, cname_base: Option<&str>) -> Result<(), String> {
    match (zone.kind.as_str(), cname_base) {
        ("full", _) | ("partial", Some(_)) => Ok(()),
        ("cert", _) => Err("a certificate-only zone is not proxied: it cannot serve custom hostnames".into()),
        _ => Err("this zone's DNS is hosted elsewhere and this fleet has no CNAME base (--cname-base): the fleet could not answer the certificate challenge of a custom hostname".into()),
    }
}

// ------------------------------------------------------------- the index ----

/// The custom hostnames that count, oldest first: one per name (two zones
/// that created the same name on two nodes at once: the older one keeps
/// it, the same on every node), none a zone answers for, none of a zone
/// that is gone.
fn counted<'a>(items: &'a [CustomHostname], zones: &[Zone]) -> Vec<&'a CustomHostname> {
    let mut sorted: Vec<&CustomHostname> = items.iter().collect();
    sorted.sort_by(|a, b| (&a.meta.created_on, &a.meta.id).cmp(&(&b.meta.created_on, &b.meta.id)));
    let mut names = HashSet::new();
    sorted
        .into_iter()
        .filter(|h| names.insert(h.hostname.as_str()))
        .filter(|h| zones.iter().any(|z| z.id == h.meta.zone_id) && !covered(zones, &h.hostname))
        .collect()
}

/// What the edge needs to know of the custom hostnames, by name.
#[derive(Default)]
pub struct Index {
    /// Active ones: the name of the zone (a key of `Snapshot::zones`) that serves each.
    routes: HashMap<String, String>,
    /// Created ones no visitor asked for yet: `(zone id, item id)`.
    waiting: HashMap<String, (String, String)>,
}

/// Build the index for a snapshot: routes and origins of the active custom
/// hostnames into their zones (`zones` by id), their certificates into
/// `certs` (below every uploaded or managed one).
pub fn index(data: &Data, zones: &mut HashMap<&str, ZoneSnap>, certs: &mut HashMap<String, Arc<CertifiedKey>>) -> Index {
    let mut out = Index::default();
    for h in counted(&data.custom_hostnames, &data.zones) {
        let Some(zs) = zones.get_mut(h.meta.zone_id.as_str()) else { continue };
        if h.status == ACTIVE {
            let origin = if h.custom_origin_server.is_empty() { zs.zone.name.clone() } else { h.custom_origin_server.clone() };
            zs.custom_origins.insert(h.hostname.clone(), origin);
            out.routes.insert(h.hostname.clone(), zs.zone.name.clone());
            if let Ok(key) = crate::edge::tls::parse_cert(&h.certificate, &h.private_key) {
                certs.entry(h.hostname.clone()).or_insert(key);
            }
        } else if h.seen_at.is_none() {
            out.waiting.insert(h.hostname.clone(), (h.meta.zone_id.clone(), h.meta.id.clone()));
        }
    }
    out
}

impl Snapshot {
    /// The zone that serves `host` at the edge: the zone it belongs to when a
    /// proxied record covers it, else the zone of the active custom hostname
    /// it is (when the host it is served from is proxied). The one place
    /// the edge maps a request's Host or server name to a zone.
    pub fn edge_zone(&self, host: &str) -> Option<&ZoneSnap> {
        let serves = |z: &&ZoneSnap| z.records_for(host).iter().any(|r| r.proxied);
        self.find_zone(host).filter(serves).or_else(|| self.custom_zone(host).filter(serves))
    }

    /// The zone whose settings apply to `host`, served or not: the zone it
    /// belongs to, or that of the active custom hostname it is.
    pub fn host_zone(&self, host: &str) -> Option<&ZoneSnap> {
        self.find_zone(host).or_else(|| self.custom_zone(host))
    }

    fn custom_zone(&self, host: &str) -> Option<&ZoneSnap> {
        self.zones.get(self.custom_hostnames.routes.get(host)?)
    }
}

// ---------------------------------------------------- the first visitor ----

/// When this node last noted a visitor of each waiting custom hostname.
static NOTED: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(Default::default);

/// Whether a visitor of `host` should be written down now: it is a created
/// custom hostname that waits for its first visitor, and this node did not
/// note one for it lately. Any other name (one that is no custom hostname
/// above all) gives `None`, whatever comes in.
fn to_note(snap: &Snapshot, host: &str, now: Instant) -> Option<(String, String)> {
    let found = snap.custom_hostnames.waiting.get(host)?.clone();
    let mut noted = NOTED.lock().unwrap();
    if noted.get(host).is_some_and(|at| now.duration_since(*at) < NOTE_EVERY) {
        return None;
    }
    if noted.len() >= NOTED_MAX {
        noted.retain(|_, at| now.duration_since(*at) < NOTE_EVERY);
    }
    noted.insert(host.to_string(), now);
    Some(found)
}

/// A visitor asked for `host` (TLS server name or Host header) and nothing
/// serves it: if it is a custom hostname waiting for its first visitor, note
/// that (in the background), which lets its certificate be ordered.
pub fn saw(store: &Arc<Store>, snap: &Snapshot, host: &str) {
    let Some((zone_id, id)) = to_note(snap, host, Instant::now()) else { return };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
    let store = store.clone();
    runtime.spawn(async move {
        let _ = mark_seen(&store, &zone_id, &id).await;
    });
}

/// Write down the first visitor of a custom hostname (unless one was, or it
/// is active by now).
pub async fn mark_seen(store: &Store, zone_id: &str, id: &str) -> Result<CustomHostname, StoreError> {
    let at = crate::store::rfc3339(crate::acme::unix_now());
    store
        .update_item_async::<CustomHostname, _>(zone_id, id, move |h| {
            if h.status == ACTIVE || h.seen_at.is_some() {
                return false;
            }
            h.seen_at = Some(at);
            true
        })
        .await
}

// --------------------------------------------------------- certificates ----

fn time(text: Option<&str>) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(text?).ok().map(|t| t.timestamp())
}

/// Does `h` want a certificate ordered (backoff and limits aside)? A
/// pending or failed one once a visitor asked for it; an active one in the
/// last third of its certificate's life.
fn wants_order(h: &CustomHostname, now: i64) -> bool {
    match h.status.as_str() {
        ACTIVE => crate::edge::tls::pem_validity(&h.certificate).is_none_or(|v| crate::site_acme::renewal_due(v, now)),
        _ => h.seen_at.is_some(),
    }
}

/// The custom hostnames to order a certificate for now, oldest first:
/// those that want one and whose backoff is over, within the limits per
/// zone and fleet (orders of the last hour count) and per look.
pub fn due(items: &[CustomHostname], zones: &[Zone], now: i64) -> Vec<CustomHostname> {
    let recent = |h: &&CustomHostname| time(h.last_attempt.as_deref()).is_some_and(|t| t > now - 3600);
    let mut fleet = items.iter().filter(recent).count();
    let mut per_zone: HashMap<&str, usize> = HashMap::new();
    for h in items.iter().filter(recent) {
        *per_zone.entry(h.meta.zone_id.as_str()).or_default() += 1;
    }
    let mut out = Vec::new();
    for h in counted(items, zones) {
        if out.len() >= ATTEMPTS_PER_LOOK || fleet >= FLEET_ATTEMPTS_PER_HOUR {
            break;
        }
        if h.verify_txt.is_empty() || !wants_order(h, now) || time(h.next_attempt.as_deref()).is_some_and(|t| t > now) {
            continue;
        }
        if !zones.iter().any(|z| z.id == h.meta.zone_id && z.kind != "cert") {
            continue;
        }
        let used = per_zone.entry(h.meta.zone_id.as_str()).or_default();
        if *used >= ZONE_ATTEMPTS_PER_HOUR {
            continue;
        }
        *used += 1;
        fleet += 1;
        out.push(h.clone());
    }
    out
}

/// Record how an order ended. A failure keeps a certificate still in use
/// (`active`, the reason in `error`) and waits longer after each one.
pub fn record(h: &mut CustomHostname, outcome: Result<(String, String), String>, now: i64) {
    match outcome {
        Ok((chain, key)) => {
            let until = crate::edge::tls::pem_validity(&chain).map_or(now, |(_, until)| until);
            (h.certificate, h.private_key) = (chain, key);
            (h.status, h.error, h.attempts) = (ACTIVE.into(), String::new(), 0);
            (h.issued_on, h.expires_on) = (Some(crate::store::rfc3339(now)), Some(crate::store::rfc3339(until)));
            // never ask again right away, whatever the certificate says
            h.next_attempt = Some(crate::store::rfc3339(now + 3600));
        }
        Err(reason) => {
            h.attempts += 1;
            h.next_attempt = Some(crate::store::rfc3339(now + crate::acme::backoff(h.attempts)));
            h.error = reason.chars().take(ERROR_MAX).collect();
            if h.certificate.is_empty() {
                h.status = FAILED.into();
            }
        }
    }
}

/// Order the certificates that are due, one after the other, on the node
/// that holds the fleet's ACME lease (called from crate::acme::Acme::tick).
pub async fn issue_due(acme: &Acme, me: &str, preferred: &str) {
    let store = acme.edge.store.clone();
    let zones = store.list_zones();
    for h in due(&store.all_items::<CustomHostname>(), &zones, crate::acme::unix_now()) {
        let Some(zone) = zones.iter().find(|z| z.id == h.meta.zone_id) else { continue };
        if !acme.claim(me, preferred, &h.meta.id).await {
            return;
        }
        // counted against the limits whatever happens next
        let started = crate::store::rfc3339(crate::acme::unix_now());
        if store.update_item_async::<CustomHostname, _>(&h.meta.zone_id, &h.meta.id, move |h| {
            h.last_attempt = Some(started);
            true
        })
        .await
        .is_err()
        {
            acme.release().await;
            continue; // deleted meanwhile
        }
        tracing::info!("ACME: requesting a certificate for the custom hostname {}", h.hostname);
        let at = format!("{}.{}", h.verify_txt, zone.name);
        let outcome = acme.issue_fleet(&h.meta.id, std::slice::from_ref(&h.hostname), true, move |_, _| ("dns-01", at.clone())).await;
        let _ = store.set_challenges_async(Some(&h.meta.id), Vec::new()).await;
        match &outcome {
            Ok(_) => tracing::info!("ACME: certificate for the custom hostname {} installed", h.hostname),
            Err(e) => tracing::warn!("ACME: no certificate for the custom hostname {}: {e}", h.hostname),
        }
        let now = crate::acme::unix_now();
        let _ = store
            .update_item_async::<CustomHostname, _>(&h.meta.zone_id, &h.meta.id, move |h| {
                record(h, outcome, now);
                true
            })
            .await;
        acme.release().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::temp_store;

    fn add(store: &Store, zone: &str, body: Value) -> Result<CustomHostname, StoreError> {
        store.save_item::<CustomHostname>(zone, None, body, true)
    }

    fn item(zone: &str, id: &str, host: &str, created: &str) -> CustomHostname {
        CustomHostname {
            meta: Meta { id: id.into(), zone_id: zone.into(), created_on: created.into(), ..Default::default() },
            hostname: host.into(),
            status: PENDING.into(),
            verify_txt: format!("tok{id}"),
            ..Default::default()
        }
    }

    fn zone(id: &str, name: &str, kind: &str) -> Zone {
        let mut z = temp_store().create_zone_as(name, kind).unwrap();
        z.id = id.into();
        z
    }

    #[test]
    fn hostnames_are_public_names_in_one_form() {
        assert_eq!(check_hostname(" Shop.Example.NET. ").unwrap(), "shop.example.net");
        assert_eq!(check_hostname("xn--bcher-kva.example.net").unwrap(), "xn--bcher-kva.example.net");
        for bad in [
            "", " ", ".", "192.0.2.1", "2001:db8::1", "[2001:db8::1]", "*.example.net", "a.*.example.net", "bücher.example.net",
            "shop.test", "intranet.local", "localhost", "net", "a_b.example.net", "-a.example.net", "a..example.net", "1.2.3.4.5",
            "shop.example.net/x", "shop example.net",
        ] {
            assert!(check_hostname(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}.example.net", ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(50)].join("."));
        assert!(long.len() > 253 && check_hostname(&long).is_err());
        assert!(check_hostname(&format!("{}.example.net", "a".repeat(64))).is_err(), "a label of 64");
    }

    #[test]
    fn a_custom_hostname_is_no_zone_of_the_fleet_nor_near_one_and_has_one_owner() {
        let store = temp_store();
        let saas = store.create_zone("example.com").unwrap().id;
        let other = store.create_zone("example.org").unwrap().id;
        store.create_zone("shop.example.net").unwrap();

        let h = add(&store, &saas, json!({ "hostname": "Www.Example.Info", "status": "active", "verify_txt": "mine", "certificate": "x", "seen_at": "2020-01-01T00:00:00Z" })).unwrap();
        assert_eq!((h.hostname.as_str(), h.status.as_str(), h.seen_at.as_ref(), h.certificate.as_str()), ("www.example.info", PENDING, None, ""), "the server's fields are the server's");
        assert_eq!(h.verify_txt.len(), 32);
        assert!(h.verify_txt.bytes().all(|b| b.is_ascii_hexdigit()));
        let again = add(&store, &saas, json!({ "hostname": "api.example.info" })).unwrap();
        assert_ne!(again.verify_txt, h.verify_txt, "a label of its own each");

        let conflict = |zone: &str, name: &str| matches!(add(&store, zone, json!({ "hostname": name })), Err(StoreError::Conflict(_)));
        assert!(conflict(&saas, "example.com"), "a zone");
        assert!(conflict(&saas, "www.example.com"), "below its own zone");
        assert!(conflict(&saas, "www.example.org"), "below another zone");
        assert!(conflict(&saas, "shop.example.net") && conflict(&saas, "a.shop.example.net"), "below a third one");
        assert!(conflict(&saas, "example.net"), "above a zone");
        assert!(conflict(&saas, "www.example.info") && conflict(&other, "WWW.example.info."), "taken, in any zone");

        let invalid = |zone: &str, body: Value| matches!(add(&store, zone, body), Err(StoreError::Invalid(_)));
        assert!(invalid(&saas, json!({ "hostname": "192.0.2.10" })));
        assert!(invalid(&saas, json!({ "hostname": "*.example.info" })));
        assert!(invalid(&saas, json!({})));
        assert!(invalid(&saas, json!({ "hostname": 7 })));
        assert!(invalid(&saas, json!({ "hostname": "a.example.info", "custom_origin_server": "www.example.org" })), "an origin outside the zone");
        assert!(invalid(&saas, json!({ "hostname": "a.example.info", "custom_origin_server": "*.example.com" })));
        assert!(matches!(add(&store, "no-such-zone", json!({ "hostname": "a.example.info" })), Err(StoreError::ZoneNotFound)));
        let cert_only = store.create_zone_as("certs.example", "cert").unwrap().id;
        assert!(invalid(&cert_only, json!({ "hostname": "a.example.info" })));
        assert_eq!(store.items::<CustomHostname>(&saas).unwrap().len(), 2);
    }

    #[test]
    fn only_the_origin_changes_after_creation() {
        let store = temp_store();
        let saas = store.create_zone("example.com").unwrap().id;
        let other = store.create_zone("example.org").unwrap().id;
        let h = add(&store, &saas, json!({ "hostname": "shop.example.info" })).unwrap();
        let id = h.meta.id.clone();
        let patch = |zone: &str, body: Value| store.save_item::<CustomHostname>(zone, Some(&id), body, false);
        let changed = patch(&saas, json!({ "custom_origin_server": "App.Example.com.", "status": "active", "verify_txt": "chosen", "attempts": 9 })).unwrap();
        assert_eq!((changed.custom_origin_server.as_str(), changed.status.as_str(), changed.verify_txt.as_str(), changed.attempts), ("app.example.com", PENDING, h.verify_txt.as_str(), 0));
        assert_eq!(patch(&saas, json!({ "hostname": "SHOP.example.info." })).unwrap().hostname, "shop.example.info", "the same name, written differently");
        assert!(matches!(patch(&saas, json!({ "hostname": "other.example.info" })), Err(StoreError::Invalid(_))));
        assert!(matches!(patch(&other, json!({ "custom_origin_server": "" })), Err(StoreError::NotFound)), "another zone's id");
        assert_eq!(patch(&saas, json!({ "custom_origin_server": "" })).unwrap().custom_origin_server, "");
        let replaced = store.save_item::<CustomHostname>(&saas, Some(&id), json!({ "hostname": "shop.example.info" }), true).unwrap();
        assert_eq!((replaced.verify_txt, replaced.meta.created_on), (h.verify_txt, h.meta.created_on));
    }

    #[test]
    fn the_api_shows_where_to_delegate_and_never_the_key() {
        let mut h = item("z1", "1", "shop.example.net", "2026-01-01T00:00:00Z");
        h.private_key = "-----BEGIN PRIVATE KEY-----".into();
        h.custom_origin_server = "app.example.com".into();
        let full = zone("z1", "example.com", "full");
        let v = view(&h, &full, None);
        assert!(v.get("private_key").is_none() && v.get("sync").is_none());
        assert_eq!(v["dcv_delegation"], json!({ "type": "CNAME", "name": "_acme-challenge.shop.example.net", "content": "_acme-challenge.tok1.example.com" }));
        assert_eq!(v["cname_target"], "app.example.com");
        let partial = zone("z1", "example.com", "partial");
        assert_eq!(view(&h, &partial, Some("cdn.example.org"))["dcv_delegation"]["content"], "_acme-challenge.tok1.example.com.cdn.example.org");
        assert_eq!(view(&h, &partial, None)["dcv_delegation"], Value::Null);
        h.custom_origin_server.clear();
        assert_eq!(view(&h, &full, None)["cname_target"], "example.com");
        assert!(may_create(&full, None).is_ok() && may_create(&partial, Some("cdn.example.org")).is_ok());
        assert!(may_create(&partial, None).is_err() && may_create(&zone("z", "c.example", "cert"), Some("cdn.example.org")).is_err());
    }

    #[test]
    fn only_a_created_custom_hostname_waits_for_a_visitor_and_is_noted_once_in_a_while() {
        let store = temp_store();
        let saas = store.create_zone("example.com").unwrap().id;
        let h = add(&store, &saas, json!({ "hostname": "noted.example.info" })).unwrap();
        let snap = store.snapshot();
        let t0 = Instant::now();
        for unknown in ["unknown.example.info", "example.com", "www.example.com", "", "NOTED.example.info"] {
            assert_eq!(to_note(&snap, unknown, t0), None, "{unknown:?}");
        }
        assert_eq!(to_note(&snap, "noted.example.info", t0), Some((saas.clone(), h.meta.id.clone())));
        assert_eq!(to_note(&snap, "noted.example.info", t0 + Duration::from_secs(5)), None, "not again right away");
        assert!(to_note(&snap, "noted.example.info", t0 + NOTE_EVERY + Duration::from_secs(1)).is_some());
    }

    #[tokio::test]
    async fn a_visitor_is_written_down_once_and_never_over_an_active_one() {
        let store = Arc::new(temp_store());
        let saas = store.create_zone("example.com").unwrap().id;
        let h = add(&store, &saas, json!({ "hostname": "seen.example.info" })).unwrap();
        assert!(store.snapshot().custom_hostnames.waiting.contains_key("seen.example.info"));
        let first = mark_seen(&store, &saas, &h.meta.id).await.unwrap();
        assert!(first.seen_at.is_some());
        assert!(!store.snapshot().custom_hostnames.waiting.contains_key("seen.example.info"), "it waits no more");
        assert!(matches!(mark_seen(&store, &saas, &h.meta.id).await, Err(StoreError::Conflict(_))), "nothing written twice");
        assert!(matches!(mark_seen(&store, &saas, "no-such-id").await, Err(StoreError::NotFound)));
        let other = store.create_zone("example.org").unwrap().id;
        assert!(matches!(mark_seen(&store, &other, &h.meta.id).await, Err(StoreError::NotFound)), "only in its own zone");

        // a name that is no custom hostname leaves the configuration as it was
        let version = store.version();
        saw(&store, &store.snapshot(), "unknown.example.info");
        saw(&store, &store.snapshot(), "seen.example.info");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(store.version(), version);
    }

    #[test]
    fn only_created_and_visited_custom_hostnames_are_ordered_within_the_limits() {
        let now = 1_800_000_000;
        let at = |t: i64| Some(crate::store::rfc3339(t));
        let zones = vec![zone("z1", "example.com", "full"), zone("z2", "example.org", "full"), zone("zc", "certs.example", "cert"), zone("zn", "example.net", "full")];
        let mut waiting = item("z1", "a", "a.example.info", "2026-01-01T00:00:01Z");
        let mut seen = item("z1", "b", "b.example.info", "2026-01-01T00:00:02Z");
        seen.seen_at = at(now - 10);
        assert!(due(&[waiting.clone(), seen.clone()], &zones, now).iter().map(|h| h.meta.id.as_str()).eq(["b"]), "not before a visitor asked");
        waiting.seen_at = at(now);
        assert_eq!(due(&[waiting.clone(), seen.clone()], &zones, now).len(), 2);

        // backoff: not before the next attempt is due
        let mut failed = seen.clone();
        record(&mut failed, Err("the CA said no".into()), now);
        assert_eq!((failed.status.as_str(), failed.attempts, failed.error.as_str()), (FAILED, 1, "the CA said no"));
        assert_eq!(time(failed.next_attempt.as_deref()), Some(now + 600));
        assert!(due(&[failed.clone()], &zones, now + 599).is_empty());
        assert_eq!(due(&[failed.clone()], &zones, now + 600).len(), 1);
        record(&mut failed, Err("x".repeat(5000)), now);
        assert_eq!((failed.attempts, failed.error.len()), (2, ERROR_MAX));
        assert_eq!(time(failed.next_attempt.as_deref()), Some(now + 1200), "longer each time");
        for _ in 0..20 {
            record(&mut failed, Err("again".into()), now);
        }
        assert_eq!(time(failed.next_attempt.as_deref()), Some(now + 86400), "a day at most");

        // the same name twice (two nodes at once): the older one only; none a zone covers, none of a cert-only or vanished zone
        let mut twin = item("z2", "c", "b.example.info", "2026-01-02T00:00:00Z");
        twin.seen_at = at(now);
        let mut covered_one = item("zn", "d", "shop.example.net", "2026-01-01T00:00:00Z");
        covered_one.seen_at = at(now);
        let mut cert_zone = item("zc", "e", "e.example.info", "2026-01-01T00:00:00Z");
        cert_zone.seen_at = at(now);
        let mut orphan = item("gone", "f", "f.example.info", "2026-01-01T00:00:00Z");
        orphan.seen_at = at(now);
        let mut unlabelled = item("z1", "g", "g.example.info", "2026-01-01T00:00:00Z");
        (unlabelled.seen_at, unlabelled.verify_txt) = (at(now), String::new());
        let got = due(&[twin, seen.clone(), covered_one, cert_zone, orphan, unlabelled], &zones, now);
        assert!(got.iter().map(|h| h.meta.id.as_str()).eq(["b"]), "{got:?}");

        // per look, per zone and per hour for the fleet
        let many = |zone: &str, n: usize, tried: Option<i64>| -> Vec<CustomHostname> {
            (0..n)
                .map(|i| {
                    let mut h = item(zone, &format!("{zone}-{i}"), &format!("h{i}.{zone}.example.info"), &format!("2026-01-01T00:00:{i:02}Z"));
                    (h.seen_at, h.last_attempt) = (at(now), tried.and_then(at));
                    h
                })
                .collect()
        };
        assert_eq!(due(&many("z1", 8, None), &zones, now).len(), ATTEMPTS_PER_LOOK);
        let mut zone_busy = many("z1", ZONE_ATTEMPTS_PER_HOUR, Some(now - 1800));
        for h in &mut zone_busy {
            h.next_attempt = at(now - 1);
        }
        assert!(due(&zone_busy, &zones, now).is_empty(), "the zone used its hour");
        let mut with_other = zone_busy.clone();
        with_other.extend(many("z2", 1, None));
        assert!(due(&with_other, &zones, now).iter().all(|h| h.meta.zone_id == "z2"), "another zone still gets its turn");
        assert_eq!(due(&zone_busy, &zones, now + 1801).len(), ATTEMPTS_PER_LOOK, "an hour later");
        let mut fleet_busy: Vec<CustomHostname> = (0..FLEET_ATTEMPTS_PER_HOUR).map(|i| {
            let mut h = item(&format!("x{i}"), &format!("x{i}"), &format!("x{i}.example.info"), "2026-01-01T00:00:00Z");
            h.last_attempt = at(now - 60);
            h
        }).collect();
        fleet_busy.extend(many("z2", 1, None));
        assert!(due(&fleet_busy, &zones, now).is_empty(), "the fleet used its hour");
    }

    #[test]
    fn an_active_one_renews_in_the_last_third_and_keeps_its_certificate_when_that_fails() {
        let now = crate::acme::unix_now();
        let zones = vec![zone("z1", "example.com", "full")];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert_for = |days: i64| {
            use chrono::Datelike;
            let mut p = rcgen::CertificateParams::new(vec!["renew.example.info".to_string()]).unwrap();
            let d = |o: i64| {
                let t = chrono::Utc::now() + chrono::Duration::days(o);
                rcgen::date_time_ymd(t.year(), t.month() as u8, t.day() as u8)
            };
            (p.not_before, p.not_after) = (d(days - 90), d(days));
            p.self_signed(&key).unwrap().pem()
        };
        let mut h = item("z1", "r", "renew.example.info", "2026-01-01T00:00:00Z");
        record(&mut h, Ok((cert_for(80), key.serialize_pem())), now);
        assert_eq!((h.status.as_str(), h.attempts, h.error.as_str()), (ACTIVE, 0, ""));
        assert!(h.expires_on.is_some() && h.issued_on.is_some());
        h.next_attempt = None;
        assert!(due(&[h.clone()], &zones, now).is_empty(), "two thirds of its life left; no visitor needed either");
        h.certificate = cert_for(20);
        assert_eq!(due(&[h.clone()], &zones, now).len(), 1);
        let before = h.certificate.clone();
        record(&mut h, Err("down".into()), now);
        assert_eq!((h.status.as_str(), h.certificate == before, h.attempts), (ACTIVE, true, 1));
    }

    #[test]
    fn active_ones_route_to_their_zone_and_a_zone_added_later_takes_the_name_over() {
        let store = temp_store();
        let saas = store.create_zone("example.com").unwrap().id;
        let mut www = crate::store::testutil::rec("www", "A", "192.0.2.10");
        www.proxied = true;
        store.create_record(&saas, www).unwrap();
        let h = add(&store, &saas, json!({ "hostname": "shop.example.info", "custom_origin_server": "www.example.com" })).unwrap();
        let other = add(&store, &saas, json!({ "hostname": "plain.example.info" })).unwrap();
        let snap = store.snapshot();
        assert!(snap.edge_zone("shop.example.info").is_none() && snap.host_zone("shop.example.info").is_none(), "pending: not served");

        // the server's own bookkeeping turns it active
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        for id in [&h.meta.id, &other.meta.id] {
            rt.block_on(store.update_item_async::<CustomHostname, _>(&saas, id, |x| {
                x.status = ACTIVE.into();
                true
            }))
            .unwrap();
        }
        let kept = store.save_item::<CustomHostname>(&saas, Some(&h.meta.id), json!({ "status": "pending" }), false).unwrap();
        assert_eq!(kept.status, ACTIVE, "a user's save keeps it active");
        let snap = store.snapshot();
        assert_eq!(snap.edge_zone("shop.example.info").map(|z| z.zone.id.as_str()), Some(saas.as_str()));
        assert_eq!(snap.edge_zone("shop.example.info").unwrap().records_for("shop.example.info")[0].content, "192.0.2.10");
        assert!(snap.edge_zone("plain.example.info").is_none(), "the apex has no proxied record: nothing serves it");
        assert_eq!(snap.host_zone("plain.example.info").map(|z| z.zone.name.as_str()), Some("example.com"), "the zone's settings still apply");
        assert!(snap.find_zone("shop.example.info").is_none(), "DNS knows nothing of it");
        assert!(snap.edge_zone("SHOP.example.info").is_none() && snap.edge_zone("x.shop.example.info").is_none());
        assert!(snap.edge_zone("www.example.com").is_some());

        // somebody adds the zone it lives in: that zone answers from then on
        store.create_zone("example.info").unwrap();
        let snap = store.snapshot();
        assert!(snap.host_zone("shop.example.info").is_some_and(|z| z.zone.name == "example.info"));
        assert!(snap.edge_zone("shop.example.info").is_none());
        assert!(due(&store.all_items::<CustomHostname>(), &store.list_zones(), crate::acme::unix_now() + 100 * 86400).is_empty(), "nor renewed");

        // they go with their zone
        store.delete_zone(&saas).unwrap();
        assert!(store.all_items::<CustomHostname>().is_empty());
        assert!(store.snapshot().custom_hostnames.routes.is_empty());
    }
}
