//! The addresses the automatic firewall bans, written as an nftables script
//! (`--ban-export FILE`), for whoever runs this host to load into the kernel:
//! what is dropped there costs this process nothing. Only bans that block
//! (not those that ask for a human check), and only a file: this process
//! runs without the rights to change the kernel's tables, and the host may
//! carry other services the bans should or should not cover.

use crate::store::{Snapshot, Store};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// The addresses banned right now, with the seconds each ban still lasts.
fn bans(snap: &Snapshot, now: u64) -> BTreeMap<IpAddr, u64> {
    let mut out = BTreeMap::new();
    for zone in snap.zones.values() {
        for (rule, _) in zone.firewall.iter().filter(|(r, _)| r.managed_by == super::autofw::MANAGED_BY && r.action == "block") {
            for (addr, until) in rule.auto_bans.iter().filter(|(_, until)| **until > now) {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    let left = out.entry(ip.to_canonical()).or_insert(0);
                    *left = (*left).max(until - now);
                }
            }
        }
    }
    out
}

/// The script `nft -f` loads: two sets (made if missing), emptied and filled.
fn script(bans: &BTreeMap<IpAddr, u64>) -> String {
    let elements = |v6: bool| bans.iter().filter(|(ip, _)| ip.is_ipv6() == v6).map(|(ip, left)| format!("{ip} timeout {left}s")).collect::<Vec<_>>().join(", ");
    let mut out = String::from("# written by fucf: the addresses its automatic firewall bans\nadd table inet fucf\n");
    for (set, kind, v6) in [("banned4", "ipv4_addr", false), ("banned6", "ipv6_addr", true)] {
        out += &format!("add set inet fucf {set} {{ type {kind}; flags timeout; }}\nflush set inet fucf {set}\n");
        let list = elements(v6);
        if !list.is_empty() {
            out += &format!("add element inet fucf {set} {{ {list} }}\n");
        }
    }
    out
}

/// Keep the file up to date: written when the banned addresses change.
pub async fn run(store: Arc<Store>, path: PathBuf) {
    let mut written: Option<Vec<IpAddr>> = None;
    loop {
        let bans = bans(&store.snapshot(), super::stats::now_secs());
        let addrs: Vec<IpAddr> = bans.keys().copied().collect();
        if written.as_ref() != Some(&addrs) {
            let tmp = path.with_extension("tmp");
            match std::fs::write(&tmp, script(&bans)).and_then(|_| std::fs::rename(&tmp, &path)) {
                Ok(()) => written = Some(addrs),
                Err(e) => tracing::warn!("cannot write the banned addresses to {}: {e}", path.display()),
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_fills_a_set_per_address_family() {
        let bans: BTreeMap<IpAddr, u64> = [("192.0.2.1".parse().unwrap(), 60), ("192.0.2.9".parse().unwrap(), 7), ("2001:db8::1".parse().unwrap(), 3600)].into();
        let s = script(&bans);
        assert!(s.contains("add element inet fucf banned4 { 192.0.2.1 timeout 60s, 192.0.2.9 timeout 7s }\n"), "{s}");
        assert!(s.contains("add element inet fucf banned6 { 2001:db8::1 timeout 3600s }\n") && s.contains("flush set inet fucf banned6\n"), "{s}");
        let none = script(&BTreeMap::new());
        assert!(none.contains("flush set inet fucf banned4\n") && !none.contains("add element"), "{none}");
    }
}
