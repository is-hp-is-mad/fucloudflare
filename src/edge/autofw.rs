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

/// Bring one zone's rule up to date. Returns how many addresses it holds.
pub async fn update_zone(store: &Store, waf: &Waf, zone_id: &str, settings: &Settings, now: u64, spared: &HashSet<IpAddr>) -> Result<usize, crate::store::StoreError> {
    let rules = store.items::<FirewallRule>(zone_id)?;
    let mine = rules.iter().find(|r| r.managed_by == MANAGED_BY);
    if !settings.auto_firewall {
        if let Some(r) = mine {
            store.delete_item_async::<FirewallRule>(zone_id, &r.meta.id).await?;
        }
        return Ok(0);
    }
    let current = mine.map(|r| r.auto_bans.clone()).unwrap_or_default();
    let next = bans(&waf.events(zone_id, usize::MAX), now, settings, &current, spared);
    let action = settings.auto_firewall_action.clone();
    match mine {
        None if next.is_empty() => {}
        Some(r) if next.is_empty() => store.delete_item_async::<FirewallRule>(zone_id, &r.meta.id).await?,
        Some(r) if r.auto_bans == next && r.action == action && r.enabled => {}
        _ => {
            let added: Vec<&String> = next.keys().filter(|k| !current.contains_key(*k)).collect();
            if !added.is_empty() {
                tracing::info!(zone = zone_id, added = ?added, total = next.len(), "automatic firewall: banning");
            }
            let body = json!({
                "expression": expression(&next),
                "action": action,
                "description": format!("自动封禁 · Auto-banned from security events ({} addresses)", next.len()),
                "enabled": true,
                "priority": 1000,
                "managed_by": MANAGED_BY,
                "auto_bans": next,
            });
            store.save_item_async::<FirewallRule>(zone_id, mine.map(|r| r.meta.id.as_str()), body, true).await?;
        }
    }
    Ok(next.len())
}

/// Keep the automatic rules of all zones up to date (writable nodes only:
/// they hold the events of the whole fleet).
pub fn spawn(store: Arc<Store>, waf: Arc<Waf>) {
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
                let has_rule = || store.items::<FirewallRule>(&zone.id).is_ok_and(|r| r.iter().any(|r| r.managed_by == MANAGED_BY));
                if !zone.settings.auto_firewall && !has_rule() {
                    continue;
                }
                if let Err(e) = update_zone(&store, &waf, &zone.id, &zone.settings, now, &spared).await {
                    tracing::warn!(zone = %zone.name, "automatic firewall: {e:?}");
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
}
