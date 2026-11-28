//! The automatic firewall: from the recent security events of a zone, the
//! addresses that keep attacking it go into one firewall rule of the zone's
//! own (`managed_by: auto_firewall`), each for a while, then out again.
//!
//! What counts: managed-rule hits (blocked or logged), firewall blocks and
//! rate limit hits. Each address that has `threshold` of them within
//! `window` seconds is banned for `ban` seconds (more attacks while banned
//! extend it). IPv6 addresses are taken by /64, the size one gets. The
//! fleet's own addresses and non-public ones are never banned.

use super::waf::{Event, Waf};
use crate::items::{FirewallRule, Settings};
use crate::store::Store;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

pub const MANAGED_BY: &str = "auto_firewall";
pub const MANAGED_BY_NETWORKS: &str = "auto_firewall_networks";
/// How long a surge keeps a zone in under attack mode after it was last seen.
const SURGE_SECS: u64 = 3600;
/// At most this many addresses in the rule (the latest bans are kept).
const MAX_BANS: usize = 1000;
const EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// The address (or /64) an event counts for, if it can be banned.
fn culprit(ip: &str, spared: &HashSet<IpAddr>) -> Option<String> {
    let ip: IpAddr = ip.parse().ok()?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    if spared.contains(&ip) {
        return None;
    }
    match ip {
        IpAddr::V4(a) => {
            let local = a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_broadcast() || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64);
            (!local).then(|| a.to_string())
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            let local = a.is_loopback() || a.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80;
            if local {
                return None;
            }
            let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            Some(format!("{net}/64"))
        }
    }
}

/// Does the event tell of an attack?
fn counts(e: &Event) -> bool {
    match e.source.as_str() {
        "managed" | "ratelimit" => true,
        "firewall" => e.action == "block",
        _ => false,
    }
}

fn secs(at: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(at).ok().map(|t| t.timestamp().max(0) as u64)
}

/// The bans from now on: those still running, extended or joined by the
/// addresses that attacked often enough lately.
pub fn bans(events: &[Event], now: u64, settings: &Settings, current: &BTreeMap<String, u64>, spared: &HashSet<IpAddr>) -> BTreeMap<String, u64> {
    let window = settings.auto_firewall_window.max(60) as u64;
    let ban = settings.auto_firewall_ban.max(60) as u64;
    let threshold = settings.auto_firewall_threshold.max(1) as usize;
    let mut tally: HashMap<String, (usize, u64)> = HashMap::new();
    for e in events.iter().filter(|e| counts(e)) {
        let Some(at) = secs(&e.occurred_at) else { continue };
        if at + window < now || at > now + 60 {
            continue;
        }
        let Some(who) = culprit(&e.client_ip, spared) else { continue };
        let slot = tally.entry(who).or_insert((0, 0));
        slot.0 += 1;
        slot.1 = slot.1.max(at);
    }
    let mut out: BTreeMap<String, u64> = current.iter().filter(|(_, until)| **until > now).map(|(k, v)| (k.clone(), *v)).collect();
    for (who, (n, last)) in tally {
        if n >= threshold {
            let until = last + ban;
            let slot = out.entry(who).or_insert(0);
            *slot = (*slot).max(until);
        }
    }
    if out.len() > MAX_BANS {
        let mut by_until: Vec<(String, u64)> = out.into_iter().collect();
        by_until.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        by_until.truncate(MAX_BANS);
        out = by_until.into_iter().collect();
    }
    out
}

pub fn expression(bans: &BTreeMap<String, u64>) -> String {
    format!("ip.src in {{{}}}", bans.keys().cloned().collect::<Vec<_>>().join(" "))
}

/// The networks (ASNs) to challenge: those from which at least
/// `auto_firewall_network_ips` different addresses attacked lately, counting
/// only addresses that score as data centre, VPN or worse (a home ISP is
/// never challenged as a whole).
pub fn networks(events: &[Event], now: u64, settings: &Settings, current: &BTreeMap<String, u64>, spared: &HashSet<IpAddr>) -> BTreeMap<String, u64> {
    let window = settings.auto_firewall_window.max(60) as u64;
    let ban = settings.auto_firewall_ban.max(60) as u64;
    let need = settings.auto_firewall_network_ips.max(2) as usize;
    let mut by_asn: HashMap<i64, (HashSet<String>, u64)> = HashMap::new();
    for e in events.iter().filter(|e| counts(e) && e.asn > 0 && e.threat >= 25) {
        let Some(at) = secs(&e.occurred_at) else { continue };
        if at + window < now || at > now + 60 {
            continue;
        }
        let Some(who) = culprit(&e.client_ip, spared) else { continue };
        let slot = by_asn.entry(e.asn).or_default();
        slot.0.insert(who);
        slot.1 = slot.1.max(at);
    }
    let mut out: BTreeMap<String, u64> = current.iter().filter(|(_, until)| **until > now).map(|(k, v)| (k.clone(), *v)).collect();
    for (asn, (ips, last)) in by_asn {
        if ips.len() >= need {
            let slot = out.entry(format!("AS{asn}")).or_insert(0);
            *slot = (*slot).max(last + ban);
        }
    }
    out
}

/// How many different addresses attacked within the window.
fn attackers(events: &[Event], now: u64, settings: &Settings, spared: &HashSet<IpAddr>) -> usize {
    let window = settings.auto_firewall_window.max(60) as u64;
    events
        .iter()
        .filter(|e| counts(e) && secs(&e.occurred_at).is_some_and(|at| at + window >= now))
        .filter_map(|e| culprit(&e.client_ip, spared))
        .collect::<HashSet<_>>()
        .len()
}

pub fn network_expression(nets: &BTreeMap<String, u64>, spared: &HashSet<IpAddr>) -> String {
    let asns: Vec<&str> = nets.keys().map(|k| k.trim_start_matches("AS")).collect();
    let mut e = format!("ip.geoip.asnum in {{{}}}", asns.join(" "));
    if !spared.is_empty() {
        // the fleet's own nodes live in such networks too
        let mut own: Vec<String> = spared.iter().map(IpAddr::to_string).collect();
        own.sort();
        e.push_str(&format!(" and not ip.src in {{{}}}", own.join(" ")));
    }
    e
}

/// Make the zone's rule kept by `managed_by` say what it should (or go, when there is nothing).
#[allow(clippy::too_many_arguments)]
async fn keep(
    store: &Store,
    zone_id: &str,
    mine: Option<&FirewallRule>,
    managed_by: &str,
    entries: &BTreeMap<String, u64>,
    expression: String,
    action: &str,
    description: String,
    priority: i32,
) -> Result<(), crate::store::StoreError> {
    match mine {
        None if entries.is_empty() => {}
        Some(r) if entries.is_empty() => store.delete_item_async::<FirewallRule>(zone_id, &r.meta.id).await?,
        Some(r) if r.auto_bans == *entries && r.action == action && r.expression == expression && r.enabled => {}
        _ => {
            let before = mine.map(|r| r.auto_bans.clone()).unwrap_or_default();
            let added: Vec<&String> = entries.keys().filter(|k| !before.contains_key(*k)).collect();
            if !added.is_empty() {
                tracing::info!(zone = zone_id, managed_by, added = ?added, total = entries.len(), "automatic firewall");
            }
            let body = json!({
                "expression": expression,
                "action": action,
                "description": description,
                "enabled": true,
                "priority": priority,
                "managed_by": managed_by,
                "auto_bans": entries,
            });
            store.save_item_async::<FirewallRule>(zone_id, mine.map(|r| r.meta.id.as_str()), body, true).await?;
        }
    }
    Ok(())
}

/// Bring one zone's automatic rules up to date: the addresses, the networks,
/// and the security level during a surge. Returns how many addresses are banned.
pub async fn update_zone(store: &Store, waf: &Waf, zone_id: &str, settings: &Settings, now: u64, spared: &HashSet<IpAddr>) -> Result<usize, crate::store::StoreError> {
    let rules = store.items::<FirewallRule>(zone_id)?;
    let events = if settings.auto_firewall { waf.events(zone_id, usize::MAX) } else { Vec::new() };
    let on = settings.auto_firewall;

    let ip_rule = rules.iter().find(|r| r.managed_by == MANAGED_BY);
    let ips = if on { bans(&events, now, settings, &ip_rule.map(|r| r.auto_bans.clone()).unwrap_or_default(), spared) } else { BTreeMap::new() };
    let what = format!("自动封禁 · Auto-banned from security events ({} addresses)", ips.len());
    keep(store, zone_id, ip_rule, MANAGED_BY, &ips, expression(&ips), &settings.auto_firewall_action, what, 1000).await?;

    let net_rule = rules.iter().find(|r| r.managed_by == MANAGED_BY_NETWORKS);
    let nets = if on && settings.auto_firewall_networks {
        networks(&events, now, settings, &net_rule.map(|r| r.auto_bans.clone()).unwrap_or_default(), spared)
    } else {
        BTreeMap::new()
    };
    let what = format!("自动人机验证 · Networks attacking from many addresses ({} networks)", nets.len());
    keep(store, zone_id, net_rule, MANAGED_BY_NETWORKS, &nets, network_expression(&nets, spared), "managed_challenge", what, 1001).await?;

    // a surge of attackers: under attack mode for an hour, then back to what it was
    let surge = on && settings.auto_firewall_surge > 0 && attackers(&events, now, settings, spared) >= settings.auto_firewall_surge as usize;
    if surge {
        // (an under attack mode switched on by hand is left alone)
        let ours = settings.auto_level_until > 0;
        if settings.security_level != "under_attack" {
            tracing::warn!(zone = zone_id, "automatic firewall: a surge of attackers, under attack mode for now");
            store.update_setting_async(zone_id, "auto_level_restore", json!(settings.security_level)).await?;
            store.update_setting_async(zone_id, "security_level", json!("under_attack")).await?;
            store.update_setting_async(zone_id, "auto_level_until", json!(now + SURGE_SECS)).await?;
        } else if ours && settings.auto_level_until < now + SURGE_SECS - 300 {
            store.update_setting_async(zone_id, "auto_level_until", json!(now + SURGE_SECS)).await?;
        }
    } else if settings.auto_level_until > 0 && (settings.auto_level_until <= now || !on) {
        if settings.security_level == "under_attack" && !settings.auto_level_restore.is_empty() {
            tracing::info!(zone = zone_id, "automatic firewall: the surge is over, back to {}", settings.auto_level_restore);
            store.update_setting_async(zone_id, "security_level", json!(settings.auto_level_restore)).await?;
        }
        store.update_setting_async(zone_id, "auto_level_until", json!(0)).await?;
        store.update_setting_async(zone_id, "auto_level_restore", json!("")).await?;
    }
    Ok(ips.len())
}

/// Keep the automatic rules of all zones up to date (writable nodes only:
/// they hold the events of the whole fleet).
pub fn spawn(store: Arc<Store>, waf: Arc<Waf>, reputation: Option<Arc<super::reputation::Reputation>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if store.is_read_only() {
                continue;
            }
            let snap = store.snapshot();
            let spared: HashSet<IpAddr> = snap
                .nodes
                .iter()
                .flat_map(|n| [n.ipv4.map(IpAddr::V4), n.ipv6.map(IpAddr::V6)])
                .flatten()
                .collect();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            for zone in store.list_zones() {
                let has_rule = || store.items::<FirewallRule>(&zone.id).is_ok_and(|r| r.iter().any(|r| r.managed_by.starts_with(MANAGED_BY)));
                if !zone.settings.auto_firewall && !has_rule() && zone.settings.auto_level_until == 0 {
                    continue;
                }
                if let Err(e) = update_zone(&store, &waf, &zone.id, &zone.settings, now, &spared).await {
                    tracing::warn!(zone = %zone.name, "automatic firewall: {e:?}");
                }
                // what is banned here counts against an address everywhere (its threat score)
                if let (Some(rep), Ok(rules)) = (&reputation, store.items::<FirewallRule>(&zone.id)) {
                    for r in rules.iter().filter(|r| r.managed_by == MANAGED_BY) {
                        rep.set_banned(r.auto_bans.clone());
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ip: &str, source: &str, action: &str, at: u64) -> Event {
        Event {
            ray_id: "r".into(),
            occurred_at: crate::store::rfc3339(at as i64),
            zone_id: "z".into(),
            source: source.into(),
            rule_id: "x".into(),
            description: String::new(),
            action: action.into(),
            client_ip: ip.into(),
            country: String::new(),
            node: String::new(),
            host: "example.com".into(),
            method: "GET".into(),
            uri: "/".into(),
            user_agent: String::new(),
            asn: 0,
            threat: 0,
        }
    }

    #[test]
    fn who_gets_banned_and_for_how_long() {
        let now = 1_800_000_000;
        let settings = Settings { auto_firewall: true, auto_firewall_threshold: 3, auto_firewall_window: 600, auto_firewall_ban: 3600, ..Settings::default() };
        let spared: HashSet<IpAddr> = ["9.9.9.9".parse().unwrap()].into();
        let mut events = Vec::new();
        for i in 0..3 {
            events.push(event("8.8.4.4", "managed", "block", now - 10 * i));
            events.push(event("2001:4860::1", "ratelimit", "block", now - 10 * i));
            events.push(event("2001:4860::2", "ratelimit", "block", now - 10 * i));
            events.push(event("9.9.9.9", "managed", "block", now));
            events.push(event("10.0.0.1", "managed", "block", now));
            events.push(event("1.1.1.1", "firewall", "js_challenge", now));
            events.push(event("1.0.0.1", "managed", "block", now - 7200));
        }
        events.push(event("8.8.8.8", "managed", "log", now));
        let current: BTreeMap<String, u64> = [("4.4.4.4".to_string(), now + 100), ("5.5.5.5".to_string(), now - 1)].into();
        let out = bans(&events, now, &settings, &current, &spared);
        let keys: Vec<&str> = out.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["2001:4860::/64", "4.4.4.4", "8.8.4.4"]);
        assert_eq!(out["8.8.4.4"], now + 3600);
        assert_eq!(out["4.4.4.4"], now + 100, "a ban runs out on its own");
        assert_eq!(expression(&out), "ip.src in {2001:4860::/64 4.4.4.4 8.8.4.4}");
        assert!(crate::expr::Expr::parse(&expression(&out)).is_ok());
        assert!(bans(&[], now + 4000, &settings, &out, &spared).is_empty(), "and then they are all gone");
    }

    #[tokio::test]
    async fn the_rule_comes_and_goes() {
        let dir = std::env::temp_dir().join(format!("fucf-autofw-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("store.json"), vec![]).unwrap();
        let zone = store.create_zone("example.com").unwrap();
        let waf = Waf::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let attacks: Vec<Event> = (0..10).map(|_| Event { zone_id: zone.id.clone(), ..event("8.8.4.4", "managed", "block", now) }).collect();
        waf.absorb("eu", attacks);
        let none = HashSet::new();

        // off: nothing happens
        let settings = store.get_zone(&zone.id).unwrap().settings;
        assert_eq!(update_zone(&store, &waf, &zone.id, &settings, now, &none).await.unwrap(), 0);
        assert!(store.items::<FirewallRule>(&zone.id).unwrap().is_empty());

        store.update_setting(&zone.id, "auto_firewall", json!(true)).unwrap();
        let settings = store.get_zone(&zone.id).unwrap().settings;
        assert_eq!(update_zone(&store, &waf, &zone.id, &settings, now, &none).await.unwrap(), 1);
        let rules = store.items::<FirewallRule>(&zone.id).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!((rules[0].managed_by.as_str(), rules[0].expression.as_str(), rules[0].action.as_str()), (MANAGED_BY, "ip.src in {8.8.4.4}", "block"));
        // again: no change, the same rule
        update_zone(&store, &waf, &zone.id, &settings, now + 30, &none).await.unwrap();
        assert_eq!(store.items::<FirewallRule>(&zone.id).unwrap()[0].meta.id, rules[0].meta.id);

        // the ban runs out: the rule goes
        assert_eq!(update_zone(&store, &waf, &zone.id, &settings, now + 86_400 + 700, &none).await.unwrap(), 0);
        assert!(store.items::<FirewallRule>(&zone.id).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn networks_attacking_from_many_addresses() {
        let now = 1_800_000_000;
        let settings = Settings { auto_firewall: true, auto_firewall_network_ips: 3, ..Settings::default() };
        let mut events = Vec::new();
        for i in 0..3 {
            // a hosting network: three addresses, each a data centre one
            events.push(Event { asn: 64500, threat: 30, ..event(&format!("8.8.8.{i}"), "managed", "block", now) });
            // a home ISP: as many attackers, but clean addresses
            events.push(Event { asn: 64501, threat: 0, ..event(&format!("9.9.9.{i}"), "managed", "block", now) });
        }
        events.push(Event { asn: 64502, threat: 80, ..event("7.7.7.7", "managed", "block", now) });
        let spared: HashSet<IpAddr> = ["1.2.3.4".parse().unwrap()].into();
        let nets = networks(&events, now, &settings, &BTreeMap::new(), &spared);
        assert_eq!(nets.keys().collect::<Vec<_>>(), vec!["AS64500"]);
        let e = network_expression(&nets, &spared);
        assert_eq!(e, "ip.geoip.asnum in {64500} and not ip.src in {1.2.3.4}");
        assert!(crate::expr::Expr::parse(&e).is_ok());
        assert_eq!(attackers(&events, now, &settings, &spared), 7);
    }

    #[tokio::test]
    async fn a_surge_means_under_attack_for_a_while() {
        let dir = std::env::temp_dir().join(format!("fucf-autofw-surge-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("store.json"), vec![]).unwrap();
        let zone = store.create_zone("example.com").unwrap();
        store.update_setting(&zone.id, "auto_firewall", json!(true)).unwrap();
        store.update_setting(&zone.id, "auto_firewall_surge", json!(5)).unwrap();
        let waf = Waf::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        waf.absorb("eu", (0..5).map(|i| Event { zone_id: zone.id.clone(), ..event(&format!("8.8.4.{i}"), "managed", "block", now) }).collect());
        let none = HashSet::new();
        let settings = store.get_zone(&zone.id).unwrap().settings;
        update_zone(&store, &waf, &zone.id, &settings, now, &none).await.unwrap();
        let s = store.get_zone(&zone.id).unwrap().settings;
        assert_eq!((s.security_level.as_str(), s.auto_level_restore.as_str()), ("under_attack", "medium"));
        assert!(s.auto_level_until > now);
        // an hour on, nobody attacking: back to what it was
        update_zone(&store, &waf, &zone.id, &s, now + SURGE_SECS + 700, &none).await.unwrap();
        let s = store.get_zone(&zone.id).unwrap().settings;
        assert_eq!((s.security_level.as_str(), s.auto_level_until), ("medium", 0));
        let _ = std::fs::remove_dir_all(dir);
    }
}
