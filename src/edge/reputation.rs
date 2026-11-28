//! IP reputation ("purity"): how bad a visitor's address looks, as a threat
//! score from 0 (clean) to 100, like Cloudflare's `cf.threat_score`.
//!
//! Sources, each a list of addresses and networks with a score of its own;
//! an address scores the highest of the lists it is on:
//! - known abusers (FireHOL level 1: Spamhaus DROP/EDROP, DShield, ...) 80
//! - recent attackers (FireHOL level 2, the last two days)              60
//! - Tor exit nodes                                                     60
//! - commercial VPNs (X4BNet)                                           40
//! - data centres and hosting (X4BNet, and hosting networks by name)   30
//! - addresses this fleet itself banned lately (crate::edge::autofw)    70
//!
//! The lists are fetched by every node every 12 hours and kept under
//! `<data dir>/reputation`. Private addresses, the fleet's own and search
//! engine crawlers that are who they say they are score 0.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

pub struct Source {
    pub name: &'static str,
    pub url: &'static str,
    pub score: u8,
    pub label: &'static str,
}

pub const SOURCES: &[Source] = &[
    Source { name: "firehol_level1", url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", score: 80, label: "abuser" },
    Source { name: "firehol_level2", url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset", score: 60, label: "attacker" },
    Source { name: "tor_exits", url: "https://check.torproject.org/torbulkexitlist", score: 60, label: "tor" },
    Source { name: "vpn", url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt", score: 40, label: "vpn" },
    Source { name: "datacenter", url: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt", score: 30, label: "datacenter" },
];

/// Hosting networks by name, for what the lists do not know.
const HOSTING: &[&str] = &[
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure", "digitalocean", "linode", "akamai connected cloud", "vultr", "choopa",
    "ovh", "hetzner", "contabo", "leaseweb", "m247", "alibaba", "tencent cloud", "huawei cloud", "oracle", "scaleway", "online s.a.s",
    "ionos", "hostinger", "datacamp", "cdn77", "zenlayer", "psychz", "quadranet", "colocrossing", "buyvm", "frantech", "hostwinds",
    "racknerd", "dmit", "bandwagon", "it7", "kamatera", "upcloud", "cloudflare", "fastly", "datapacket", "g-core", "gcore", "servers.com",
];

/// Crawlers let through when they come from their own network: (user agent
/// word, ASNs).
const CRAWLERS: &[(&str, &[i64])] = &[
    ("googlebot", &[15169, 396982]),
    ("google-inspectiontool", &[15169]),
    ("bingbot", &[8075]),
    ("baiduspider", &[55967, 38365, 38627]),
    ("yandex", &[13238, 208722]),
    ("duckduckbot", &[8075, 14618, 16509]),
    ("applebot", &[714, 6185]),
    ("sogou", &[45090, 4837, 4808]),
    ("bytespider", &[396986, 138699, 137775]),
];

#[derive(Default)]
struct List {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl List {
    fn parse(text: &str) -> List {
        let mut list = List::default();
        for line in text.lines() {
            let word = line.split(['#', ';']).next().unwrap_or("").split_whitespace().next().unwrap_or("");
            if word.is_empty() {
                continue;
            }
            let (addr, prefix) = match word.split_once('/') {
                Some((a, p)) => (a, p.parse::<u32>().ok()),
                None => (word, None),
            };
            match addr.parse::<IpAddr>() {
                Ok(IpAddr::V4(a)) => {
                    let p = prefix.unwrap_or(32).min(32);
                    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                    let start = u32::from(a) & mask;
                    list.v4.push((start, start | !mask));
                }
                Ok(IpAddr::V6(a)) => {
                    let p = prefix.unwrap_or(128).min(128);
                    let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                    let start = u128::from(a) & mask;
                    list.v6.push((start, start | !mask));
                }
                Err(_) => {}
            }
        }
        fn merge<T: Ord + Copy>(v: &mut Vec<(T, T)>) {
            v.sort();
            let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
            for &(s, e) in v.iter() {
                match out.last_mut() {
                    Some(last) if s <= last.1 => last.1 = last.1.max(e),
                    _ => out.push((s, e)),
                }
            }
            *v = out;
        }
        merge(&mut list.v4);
        merge(&mut list.v6);
        list
    }

    fn contains(&self, ip: IpAddr) -> bool {
        fn find<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
            let i = v.partition_point(|r| r.0 <= x);
            i > 0 && v[i - 1].1 >= x
        }
        match ip {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => find(&self.v6, u128::from(a)),
        }
    }

    fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Assessment {
    pub score: u8,
    pub reasons: Vec<String>,
}

#[derive(Default)]
pub struct Reputation {
    lists: RwLock<HashMap<&'static str, Arc<List>>>,
    /// The fleet's own addresses: never suspect.
    fleet: RwLock<HashSet<IpAddr>>,
    /// What the automatic firewall banned lately, and until when.
    banned: RwLock<HashMap<String, u64>>,
    dir: Option<PathBuf>,
}

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified() || a.is_broadcast() || o[0] == 0 || (o[0] == 100 && (o[1] & 0xc0) == 64) || o[0] >= 224)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            !(a.is_loopback() || a.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xff00) == 0xff00)
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(a)),
        v4 => v4,
    }
}

impl Reputation {
    pub fn new(dir: Option<PathBuf>) -> Reputation {
        let rep = Reputation { dir, ..Default::default() };
        if let Some(dir) = &rep.dir {
            for s in SOURCES {
                if let Ok(text) = std::fs::read_to_string(dir.join(format!("{}.txt", s.name))) {
                    rep.set_list(s.name, &text);
                }
            }
        }
        rep
    }

    pub fn set_list(&self, name: &'static str, text: &str) {
        let list = List::parse(text);
        self.lists.write().unwrap().insert(name, Arc::new(list));
    }

    pub fn set_fleet(&self, ips: HashSet<IpAddr>) {
        *self.fleet.write().unwrap() = ips;
    }

    /// The automatic firewall's current bans (addresses or v6 /64s).
    pub fn set_banned(&self, bans: impl IntoIterator<Item = (String, u64)>) {
        let mut b = self.banned.write().unwrap();
        b.extend(bans);
        let now = unix_now();
        b.retain(|_, until| *until > now);
    }

    /// The lists loaded, and how many networks each holds.
    pub fn loaded(&self) -> Vec<(String, usize)> {
        let lists = self.lists.read().unwrap();
        SOURCES.iter().map(|s| (s.name.to_string(), lists.get(s.name).map(|l| l.len()).unwrap_or(0))).collect()
    }

    pub fn assess(&self, ip: IpAddr, asn: i64, as_org: &str, user_agent: &str) -> Assessment {
        let ip = canonical(ip);
        let mut out = Assessment::default();
        if !public(ip) || self.fleet.read().unwrap().contains(&ip) {
            return out;
        }
        let ua = user_agent.to_ascii_lowercase();
        if CRAWLERS.iter().any(|(word, asns)| ua.contains(word) && asns.contains(&asn)) {
            out.reasons.push("verified_crawler".into());
            return out;
        }
        let mut hit = |score: u8, why: &str| {
            out.score = out.score.max(score);
            out.reasons.push(why.to_string());
        };
        {
            let lists = self.lists.read().unwrap();
            for s in SOURCES {
                if lists.get(s.name).is_some_and(|l| l.contains(ip)) {
                    hit(s.score, s.label);
                }
            }
        }
        let org = as_org.to_ascii_lowercase();
        if !org.is_empty() && HOSTING.iter().any(|h| org.contains(h)) && !out.reasons.iter().any(|r| r == "datacenter") {
            hit(30, "datacenter");
        }
        let key = match ip {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => {
                let s = a.segments();
                format!("{}/64", std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        };
        if self.banned.read().unwrap().get(&key).is_some_and(|until| *until > unix_now()) {
            hit(70, "banned_here");
        }
        out
    }

    /// Fetch the lists now and then (into the directory, for the next start).
    pub fn spawn_refresh(self: Arc<Self>, edge: Arc<super::Edge>) {
        // the fleet's own addresses, as the configuration has them
        let (me, store) = (self.clone(), edge.store.clone());
        tokio::spawn(async move {
            loop {
                let snap = store.snapshot();
                let ips: HashSet<IpAddr> = snap.nodes.iter().flat_map(|n| [n.ipv4.map(IpAddr::V4), n.ipv6.map(IpAddr::V6)]).flatten().collect();
                me.set_fleet(ips);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
        tokio::spawn(async move {
            loop {
                for s in SOURCES {
                    match fetch(&edge, s.url).await {
                        Ok(text) if text.len() > 100 => {
                            self.set_list(s.name, &text);
                            if let Some(dir) = &self.dir {
                                let (dir, name, text) = (dir.clone(), s.name, text.clone());
                                let _ = tokio::task::spawn_blocking(move || {
                                    std::fs::create_dir_all(&dir)?;
                                    let tmp = dir.join(format!("{name}.tmp"));
                                    std::fs::write(&tmp, text)?;
                                    std::fs::rename(&tmp, dir.join(format!("{name}.txt")))
                                })
                                .await;
                            }
                        }
                        Ok(_) => tracing::warn!("ip reputation: {} came back empty", s.name),
                        Err(e) => tracing::warn!("ip reputation: {}: {e}", s.name),
                    }
                }
                tracing::info!("ip reputation lists: {:?}", self.loaded());
                tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;
            }
        });
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn fetch(edge: &super::Edge, url: &str) -> Result<String, String> {
    use http_body_util::BodyExt;
    let target = super::upstream::Target::from_url(url)?;
    let uri: hyper::Uri = url.parse().map_err(|e| format!("{e}"))?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let req = hyper::Request::builder()
        .uri(path)
        .header("user-agent", concat!("fucf/", env!("CARGO_PKG_VERSION")))
        .body(super::full(bytes::Bytes::new()))
        .map_err(|e| e.to_string())?;
    let exchange = async {
        let resp = edge.upstream.send(&target, req).await.map_err(|e| format!("{e:?}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let body = http_body_util::Limited::new(resp.into_body(), 64 << 20).collect().await.map_err(|e| e.to_string())?.to_bytes();
        Ok(String::from_utf8_lossy(&body).into_owned())
    };
    tokio::time::timeout(std::time::Duration::from_secs(120), exchange).await.map_err(|_| "timed out".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_from_the_lists_and_who_is_spared() {
        let rep = Reputation::new(None);
        rep.set_list("firehol_level1", "# comment\n203.0.113.0/24\n10.0.0.0/8\n2001:db8:bad::/48 ; x\n");
        rep.set_list("datacenter", "198.51.100.0/25\n198.51.100.128/25\n");
        rep.set_list("tor_exits", "192.0.2.77\n");
        let at = |ip: &str, asn: i64, org: &str, ua: &str| rep.assess(ip.parse().unwrap(), asn, org, ua);
        assert_eq!(at("203.0.113.9", 0, "", "").score, 80);
        assert_eq!(at("2001:db8:bad:1::5", 0, "", "").score, 80);
        assert_eq!(at("198.51.100.200", 0, "", "").score, 30, "merged networks");
        assert_eq!(at("192.0.2.77", 0, "", "").reasons, vec!["tor".to_string()]);
        assert_eq!(at("192.0.2.78", 0, "", "").score, 0);
        assert_eq!(at("10.1.2.3", 0, "", "").score, 0, "private addresses are never suspect");
        assert_eq!(at("8.8.8.8", 0, "Hetzner Online GmbH", "").score, 30, "hosting by name");
        assert_eq!(at("::ffff:203.0.113.9", 0, "", "").score, 80);
        assert_eq!(at("66.249.66.1", 15169, "Google LLC", "Mozilla/5.0 (compatible; Googlebot/2.1)").score, 0);
        assert_eq!(at("66.249.66.1", 15169, "Google LLC", "Mozilla/5.0").score, 30);
        assert_eq!(at("203.0.113.10", 4134, "", "Googlebot").score, 80, "a crawler only by its own network");
        rep.set_fleet(["203.0.113.9".parse().unwrap()].into());
        assert_eq!(at("203.0.113.9", 0, "", "").score, 0);
        rep.set_banned([("9.9.9.9".to_string(), unix_now() + 60), ("2001:db8:1:2::/64".to_string(), unix_now() + 60)]);
        assert_eq!(at("9.9.9.9", 0, "", "").score, 70);
        assert_eq!(at("2001:db8:1:2::99", 0, "", "").score, 70);
        assert_eq!(rep.loaded().iter().find(|(n, _)| n == "firehol_level1").unwrap().1, 3);
    }
}
