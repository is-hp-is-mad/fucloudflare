//! The addresses the automatic firewall bans, written as an nftables script
//! (`--ban-export FILE`), for whoever runs this host to load into the kernel:
//! what is dropped there costs this process nothing. Only bans that block
//! (not those that ask for a human check), and only a file: this process
//! runs without the rights to change the kernel's tables, and the host may
//! carry other services the bans should or should not cover.
//!
//! The automatic firewall bans IPv6 by /64 (one subscriber's share), so
//! those go into a set of their own, `banned6net`, declared with `flags
//! interval` as a set of prefixes must be. `banned6` keeps its old
//! declaration (single addresses, `flags timeout`) instead of gaining the
//! interval flag: re-adding an existing set with other flags is an error,
//! and as `nft -f` loads a script all or nothing, a host that had loaded an
//! older script would then lose its IPv4 bans as well.

use crate::store::{Snapshot, Store};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// One thing banned: an address, or an IPv6 network (its host bits zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Banned {
    Addr(IpAddr),
    Net6(Ipv6Addr, u8),
}

impl Banned {
    /// A key of a rule's `auto_bans`: `203.0.113.7`, `2001:db8::1` or
    /// `2001:db8:1:2::/64`. A prefix as long as the address (`/32`,
    /// `/128`) is that address. Not written: IPv4 networks (the automatic
    /// firewall makes none, and `banned4` holds single addresses), anything
    /// that does not parse, and IPv6 prefixes shorter than /16, which would
    /// drop a good part of the Internet on one bad entry.
    fn parse(key: &str) -> Option<Banned> {
        let Some((addr, len)) = key.split_once('/') else {
            return key.parse::<IpAddr>().ok().map(|ip| Banned::Addr(ip.to_canonical()));
        };
        let len: u8 = len.parse().ok()?;
        match addr.parse::<IpAddr>().ok()?.to_canonical() {
            IpAddr::V4(v4) if len == 32 => Some(Banned::Addr(IpAddr::V4(v4))),
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) if len == 128 => Some(Banned::Addr(IpAddr::V6(v6))),
            IpAddr::V6(v6) if (16..128).contains(&len) => {
                let mask = u128::MAX << (128 - u32::from(len));
                Some(Banned::Net6(Ipv6Addr::from(u128::from(v6) & mask), len))
            }
            IpAddr::V6(_) => None,
        }
    }

    /// The set it goes into.
    fn set(&self) -> &'static str {
        match self {
            Banned::Addr(IpAddr::V4(_)) => "banned4",
            Banned::Addr(IpAddr::V6(_)) => "banned6",
            Banned::Net6(..) => "banned6net",
        }
    }

    /// As an element of that set.
    fn element(&self) -> String {
        match self {
            Banned::Addr(ip) => ip.to_string(),
            Banned::Net6(net, len) => format!("{net}/{len}"),
        }
    }
}

/// What is banned right now, with the seconds each ban still lasts.
fn bans(snap: &Snapshot, now: u64) -> BTreeMap<Banned, u64> {
    let mut out = BTreeMap::new();
    for zone in snap.zones.values() {
        for (rule, _) in zone.firewall.iter().filter(|(r, _)| r.managed_by == super::autofw::MANAGED_BY && r.action == "block") {
            for (key, until) in rule.auto_bans.iter().filter(|(_, until)| **until > now) {
                if let Some(banned) = Banned::parse(key) {
                    let left = out.entry(banned).or_insert(0);
                    *left = (*left).max(until - now);
                }
            }
        }
    }
    out
}

/// The sets of the script: name, element type and flags.
const SETS: [(&str, &str, &str); 3] = [
    ("banned4", "ipv4_addr", "timeout"),
    ("banned6", "ipv6_addr", "timeout"),
    ("banned6net", "ipv6_addr", "interval, timeout"),
];

/// The script `nft -f` loads: three sets (made if missing), emptied and filled.
fn script(bans: &BTreeMap<Banned, u64>) -> String {
    let mut out = String::from("# written by fucf: the addresses its automatic firewall bans\nadd table inet fucf\n");
    for (set, kind, flags) in SETS {
        out += &format!("add set inet fucf {set} {{ type {kind}; flags {flags}; }}\nflush set inet fucf {set}\n");
        let list = bans.iter().filter(|(b, _)| b.set() == set).map(|(b, left)| format!("{} timeout {left}s", b.element())).collect::<Vec<_>>().join(", ");
        if !list.is_empty() {
            out += &format!("add element inet fucf {set} {{ {list} }}\n");
        }
    }
    out
}

/// Keep the file up to date: written when what is banned changes.
pub async fn run(store: Arc<Store>, path: PathBuf) {
    let mut written: Option<Vec<Banned>> = None;
    loop {
        let bans = bans(&store.snapshot(), super::stats::now_secs());
        let banned: Vec<Banned> = bans.keys().copied().collect();
        if written.as_ref() != Some(&banned) {
            let tmp = path.with_extension("tmp");
            match std::fs::write(&tmp, script(&bans)).and_then(|_| std::fs::rename(&tmp, &path)) {
                Ok(()) => written = Some(banned),
                Err(e) => tracing::warn!("cannot write the banned addresses to {}: {e}", path.display()),
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::waf::{Event, Waf};
    use crate::items::FirewallRule;
    use serde_json::json;
    use std::collections::HashSet;

    fn addr(s: &str) -> Banned {
        Banned::Addr(s.parse().unwrap())
    }

    fn net(s: &str, len: u8) -> Banned {
        Banned::Net6(s.parse().unwrap(), len)
    }

    #[test]
    fn the_script_fills_a_set_per_kind_of_ban() {
        let bans: BTreeMap<Banned, u64> = [
            (addr("192.0.2.1"), 60),
            (addr("192.0.2.9"), 7),
            (addr("2001:db8::1"), 3600),
            (net("2001:db8:1:2::", 64), 600),
            (net("2001:db8:5::", 64), 5),
        ]
        .into();
        let s = script(&bans);
        assert!(s.contains("add element inet fucf banned4 { 192.0.2.1 timeout 60s, 192.0.2.9 timeout 7s }\n"), "{s}");
        assert!(s.contains("add element inet fucf banned6 { 2001:db8::1 timeout 3600s }\n") && s.contains("flush set inet fucf banned6\n"), "{s}");
        assert!(s.contains("add element inet fucf banned6net { 2001:db8:1:2::/64 timeout 600s, 2001:db8:5::/64 timeout 5s }\n"), "{s}");
        let none = script(&BTreeMap::new());
        assert!(none.contains("flush set inet fucf banned4\n") && none.contains("flush set inet fucf banned6net\n") && !none.contains("add element"), "{none}");
    }

    #[test]
    fn only_the_set_of_prefixes_is_an_interval_set_and_the_old_ones_keep_their_flags() {
        let s = script(&BTreeMap::new());
        assert!(s.contains("add set inet fucf banned4 { type ipv4_addr; flags timeout; }\n"), "{s}");
        assert!(s.contains("add set inet fucf banned6 { type ipv6_addr; flags timeout; }\n"), "{s}");
        assert!(s.contains("add set inet fucf banned6net { type ipv6_addr; flags interval, timeout; }\n"), "{s}");
        // every set is declared before it is flushed, and flushed before it is filled
        for (set, _, _) in SETS {
            let declared = s.find(&format!("add set inet fucf {set} ")).unwrap();
            let flushed = s.find(&format!("flush set inet fucf {set}\n")).unwrap();
            assert!(declared < flushed, "{s}");
        }
    }

    #[test]
    fn keys_of_the_rule_are_read_as_addresses_or_ipv6_networks() {
        assert_eq!(Banned::parse("203.0.113.7"), Some(addr("203.0.113.7")));
        assert_eq!(Banned::parse("2001:db8::7"), Some(addr("2001:db8::7")));
        assert_eq!(Banned::parse("2001:db8:1:2::/64"), Some(net("2001:db8:1:2::", 64)));
        // host bits are dropped: what nft takes for a prefix
        assert_eq!(Banned::parse("2001:db8:1:2:3:4:5:6/64"), Some(net("2001:db8:1:2::", 64)));
        assert_eq!(Banned::parse("2001:db8:1:2ff::/56"), Some(net("2001:db8:1:200::", 56)));
        // a mapped IPv4 address is an IPv4 address, a full-length prefix is an address
        assert_eq!(Banned::parse("::ffff:198.51.100.4"), Some(addr("198.51.100.4")));
        assert_eq!(Banned::parse("198.51.100.4/32"), Some(addr("198.51.100.4")));
        assert_eq!(Banned::parse("2001:db8::9/128"), Some(addr("2001:db8::9")));
        // not written: IPv4 networks, very short or impossible prefixes, junk
        for key in ["198.51.100.0/24", "2001:db8::/8", "2001:db8::/0", "2001:db8::/129", "203.0.113.7/33", "2001:db8::/", "2001:db8::/x", "/64", "", "AS64500", "example.com", "2001:db8::/64/1"] {
            assert_eq!(Banned::parse(key), None, "{key}");
        }
    }

    #[test]
    fn the_same_network_banned_twice_is_written_once_with_the_longer_time() {
        let mut bans = BTreeMap::new();
        for (key, left) in [("2001:db8:1:2::/64", 60u64), ("2001:db8:1:2::1/64", 900), ("203.0.113.7", 30), ("::ffff:203.0.113.7", 40)] {
            let b = Banned::parse(key).unwrap();
            let e = bans.entry(b).or_insert(0);
            *e = (*e).max(left);
        }
        let s = script(&bans);
        assert!(s.contains("add element inet fucf banned6net { 2001:db8:1:2::/64 timeout 900s }\n"), "{s}");
        assert!(s.contains("add element inet fucf banned4 { 203.0.113.7 timeout 40s }\n"), "{s}");
    }

    fn attack(zone_id: &str, ip: &str, at: u64) -> Event {
        Event {
            ray_id: "r".into(),
            occurred_at: crate::store::rfc3339(at as i64),
            zone_id: zone_id.into(),
            source: "managed".into(),
            rule_id: "x".into(),
            description: String::new(),
            action: "block".into(),
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

    #[tokio::test]
    async fn ipv6_bans_of_the_automatic_firewall_are_exported_as_their_64() {
        let dir = std::env::temp_dir().join(format!("fucf-banset-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("store.json"), vec![]).unwrap();
        let zone = store.create_zone("example.com").unwrap();
        store.update_setting(&zone.id, "auto_firewall", json!(true)).unwrap();
        let waf = Waf::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut events = Vec::new();
        for _ in 0..10 {
            events.push(attack(&zone.id, "2001:db8:1:2::7", now));
            events.push(attack(&zone.id, "2001:db8:1:2::8", now));
            events.push(attack(&zone.id, "203.0.113.7", now));
        }
        waf.absorb("eu", events);
        let none = HashSet::new();
        let settings = store.get_zone(&zone.id).unwrap().settings;
        assert_eq!(crate::edge::autofw::update_zone(&store, &waf, &zone.id, &settings, now, &none).await.unwrap(), 2);

        let banned = bans(&store.snapshot(), now);
        assert_eq!(banned.keys().copied().collect::<Vec<_>>(), vec![addr("203.0.113.7"), net("2001:db8:1:2::", 64)]);
        let s = script(&banned);
        assert!(s.contains("add element inet fucf banned6net { 2001:db8:1:2::/64 timeout "), "{s}");
        assert!(!s.contains("add element inet fucf banned6 "), "{s}");
        // a ban that ran out is gone from the file too
        assert!(bans(&store.snapshot(), now + 10 * 86_400).is_empty());

        // the bans that only ask for a human check are not the kernel's to drop
        store.update_setting(&zone.id, "auto_firewall_action", json!("managed_challenge")).unwrap();
        let settings = store.get_zone(&zone.id).unwrap().settings;
        crate::edge::autofw::update_zone(&store, &waf, &zone.id, &settings, now, &none).await.unwrap();
        assert!(store.items::<FirewallRule>(&zone.id).unwrap().iter().all(|r| r.action != "block"));
        assert!(bans(&store.snapshot(), now).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
