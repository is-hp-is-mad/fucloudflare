//! Automatic HTTPS for the hosts of proxy rules, the way Caddy does it: the
//! node that serves a site obtains its certificate by itself.
//!
//! A proxy rule that names this node explicitly (`nodes`) and keeps
//! `auto_https` gets one certificate per concrete host (no wildcards, no
//! private names) unless another one already covers it — a zone's managed or
//! uploaded certificate, or a valid one on disk that is not yet in the last
//! third of its life. The challenge (HTTP-01, or TLS-ALPN-01 every other
//! attempt) is answered from memory on this node only; nothing goes through
//! the fleet's configuration and the private key never leaves the node. IP
//! addresses use HTTP-01 and the CA's `shortlived` profile when it offers one
//! (Let's Encrypt certifies IP addresses only with it).
//!
//! Certificates land in `<data dir>/certs/<host>/<host>.{crt,key}`, which the
//! edge loads like any other certificate directory.

use crate::acme::Acme;
use crate::edge::certdir::DiskCerts;
use crate::items::LocalProxyRule;
use rustls::sign::CertifiedKey;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Duration;

static HTTP: LazyLock<RwLock<HashMap<String, String>>> = LazyLock::new(Default::default);
static TLS: LazyLock<RwLock<HashMap<String, Arc<CertifiedKey>>>> = LazyLock::new(Default::default);

/// The key authorization for an HTTP-01 `token` this node is answering.
pub fn http01(token: &str) -> Option<String> {
    HTTP.read().unwrap().get(token).cloned()
}

/// The TLS-ALPN-01 certificate for `host` this node is answering with.
pub fn tls_alpn(host: &str) -> Option<Arc<CertifiedKey>> {
    TLS.read().unwrap().get(host).cloned()
}

/// Challenge answers published while an order is under way; withdrawn when dropped.
#[derive(Default)]
pub struct Published {
    tokens: Vec<String>,
    hosts: Vec<String>,
}

impl Published {
    pub fn http(&mut self, token: &str, key_authorization: &str) {
        HTTP.write().unwrap().insert(token.to_string(), key_authorization.to_string());
        self.tokens.push(token.to_string());
    }
    pub fn tls(&mut self, host: &str, cert: Arc<CertifiedKey>) {
        TLS.write().unwrap().insert(host.to_string(), cert);
        self.hosts.push(host.to_string());
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        let mut http = HTTP.write().unwrap();
        for t in &self.tokens {
            http.remove(t);
        }
        let mut tls = TLS.write().unwrap();
        for h in &self.hosts {
            tls.remove(h);
        }
    }
}

/// Whether a public CA could certify `host` at all.
pub fn eligible(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(a) => {
                let o = a.octets();
                !(a.is_private()
                    || a.is_loopback()
                    || a.is_link_local()
                    || a.is_unspecified()
                    || a.is_broadcast()
                    || a.is_documentation()
                    || a.is_multicast()
                    || (o[0] == 100 && (64..128).contains(&o[1]))
                    || o[0] >= 240)
            }
            IpAddr::V6(a) => {
                let s = a.segments();
                !(a.is_loopback()
                    || a.is_unspecified()
                    || a.is_multicast()
                    || (s[0] & 0xfe00) == 0xfc00
                    || (s[0] & 0xffc0) == 0xfe80
                    || s[0] == 0x2001 && s[1] == 0x0db8
                    || a.to_ipv4_mapped().is_some())
            }
        };
    }
    let labels: Vec<&str> = host.split('.').collect();
    let private_tld = ["local", "localhost", "internal", "test", "invalid", "example", "lan", "home", "corp", "onion", "arpa"];
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && !private_tld.contains(labels.last().unwrap())
        && !labels.last().unwrap().bytes().all(|b| b.is_ascii_digit())
}

/// The hosts `rules` ask this node (`me`) to obtain certificates for.
pub fn wanted(rules: &[LocalProxyRule], me: &str) -> BTreeSet<String> {
    rules
        .iter()
        .filter(|r| r.enabled && r.auto_https && r.nodes.iter().any(|n| n.eq_ignore_ascii_case(me)))
        .flat_map(|r| r.hosts.iter())
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.contains('*') && eligible(h))
        .collect()
}

/// Whether a certificate valid `(from, until)` should be replaced at `now`:
/// in the last third of its life (Caddy's and Let's Encrypt's advice).
pub fn renewal_due((from, until): (i64, i64), now: i64) -> bool {
    now >= until - (until - from).max(0) / 3
}

/// Which challenge attempt number `n` uses for `host`.
fn challenge_for(host: &str, attempt: u32) -> &'static str {
    if host.parse::<IpAddr>().is_ok() || attempt % 2 == 0 {
        "http-01"
    } else {
        "tls-alpn-01"
    }
}

/// File-name form of a host (IPv6 colons are not welcome everywhere).
fn file_stem(host: &str) -> String {
    host.replace(':', "_")
}

struct Failure {
    attempts: u32,
    next: i64,
}

pub struct SiteAcme {
    pub acme: Arc<Acme>,
    /// Where issued certificates are written.
    pub dir: PathBuf,
    /// This node's name, when it is fixed (otherwise the edge's).
    pub node: Option<String>,
    /// How often to look for something to do.
    pub every: Duration,
    own: Arc<DiskCerts>,
    failures: Mutex<HashMap<String, Failure>>,
}

impl SiteAcme {
    pub fn new(acme: Arc<Acme>, dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        let own = DiskCerts::new(vec![dir.clone()]);
        SiteAcme { acme, dir, node: None, every: Duration::from_secs(600), own, failures: Mutex::default() }
    }

    fn me(&self) -> Option<String> {
        self.node.clone().or_else(|| self.acme.edge.node_name.get().cloned())
    }

    /// The hosts whose certificate should be obtained (or renewed) now.
    pub fn due(&self, now: i64) -> Vec<String> {
        let Some(me) = self.me() else { return Vec::new() };
        let snap = self.acme.edge.store.snapshot();
        let failures = self.failures.lock().unwrap();
        wanted(&snap.local_proxy_rules, &me)
            .into_iter()
            .filter(|host| {
                // a zone's certificate takes precedence on the edge anyway
                let wildcard = host.split_once('.').map(|(_, parent)| format!("*.{parent}"));
                let zone_cert = snap.certs.contains_key(host) || wildcard.is_some_and(|w| snap.certs.contains_key(&w));
                let best = [crate::edge::tls::disk_cert_validity(host), self.own.validity(host)].into_iter().flatten().max_by_key(|v| v.1);
                !zone_cert && best.is_none_or(|v| renewal_due(v, now))
            })
            .filter(|host| failures.get(host).is_none_or(|f| f.next <= now))
            .collect()
    }

    /// Obtain what is due, one host after the other.
    pub async fn tick(&self) {
        let now = crate::acme::unix_now();
        for host in self.due(now) {
            let attempts = self.failures.lock().unwrap().get(&host).map_or(0, |f| f.attempts);
            let kind = challenge_for(&host, attempts);
            let profile = host.parse::<IpAddr>().is_ok().then_some("shortlived");
            match self.acme.issue_site(std::slice::from_ref(&host), kind, profile).await {
                Ok((chain, key)) => match self.save(&host, &chain, &key).await {
                    Ok(()) => {
                        self.failures.lock().unwrap().remove(&host);
                        tracing::info!("automatic HTTPS: obtained a certificate for {host} ({kind})");
                    }
                    Err(e) => tracing::warn!("automatic HTTPS: cannot store the certificate for {host}: {e}"),
                },
                Err(e) => {
                    // 5 min, 10, 20 … at most 12 h; mind the CA's limit on failed validations
                    let wait = (300i64 << attempts.min(8)).min(12 * 3600);
                    self.failures.lock().unwrap().insert(host.clone(), Failure { attempts: attempts + 1, next: now + wait });
                    tracing::warn!("automatic HTTPS: no certificate for {host} yet ({kind}): {e}; next try in {} min", wait / 60);
                }
            }
        }
    }

    async fn save(&self, host: &str, chain: &str, key: &str) -> Result<(), String> {
        let (dir, stem) = (self.dir.join(file_stem(host)), file_stem(host));
        let (chain, key) = (chain.to_string(), key.to_string());
        let own = self.own.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            std::fs::create_dir_all(&dir)?;
            let (crt_tmp, key_tmp) = (dir.join(format!(".{stem}.crt.tmp")), dir.join(format!(".{stem}.key.tmp")));
            crate::auth::write_private(&key_tmp, key.as_bytes())?;
            std::fs::write(&crt_tmp, chain.as_bytes())?;
            std::fs::rename(&key_tmp, dir.join(format!("{stem}.key")))?;
            std::fs::rename(&crt_tmp, dir.join(format!("{stem}.crt")))?;
            own.rescan();
            crate::edge::tls::rescan_disk_certs();
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
    }

    pub async fn run(self: Arc<Self>) {
        // let the listeners come up and the configuration arrive
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            self.tick().await;
            tokio::time::sleep(self.every).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_public_concrete_hosts_of_this_node() {
        let rule = |nodes: &[&str], hosts: &[&str], auto: bool| LocalProxyRule {
            nodes: nodes.iter().map(|s| s.to_string()).collect(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            auto_https: auto,
            ..Default::default()
        };
        let rules = [
            rule(&["JP"], &["App.Example.org.", "*.example.org", "*", "intranet.local", "10.0.0.1", "1.1.1.1", "2001:db8::1"], true),
            rule(&["jp"], &["manual.example.org"], false),
            rule(&[], &["everywhere.example.org"], true),
            rule(&["eu"], &["eu.example.org"], true),
            rule(&["jp"], &["2606:4700::1111", "localhost", "1.2.3.4.5"], true),
        ];
        let got: Vec<_> = wanted(&rules, "jp").into_iter().collect();
        assert_eq!(got, ["1.1.1.1", "2606:4700::1111", "app.example.org"]);
    }

    #[test]
    fn renews_in_the_last_third() {
        let day = 86400;
        assert!(!renewal_due((0, 90 * day), 59 * day));
        assert!(renewal_due((0, 90 * day), 61 * day));
        assert!(!renewal_due((0, 6 * day), 3 * day));
        assert!(renewal_due((0, 6 * day), 4 * day + 1));
        assert_eq!((challenge_for("a.example.org", 0), challenge_for("a.example.org", 1)), ("http-01", "tls-alpn-01"));
        assert_eq!(challenge_for("1.1.1.1", 1), "http-01");
        assert_eq!(file_stem("2606:4700::1111"), "2606_4700__1111");
    }

    #[test]
    fn answers_are_withdrawn_with_the_order() {
        {
            let mut p = Published::default();
            p.http("tok-withdrawn", "tok-withdrawn.thumb");
            assert_eq!(http01("tok-withdrawn").as_deref(), Some("tok-withdrawn.thumb"));
        }
        assert_eq!(http01("tok-withdrawn"), None);
    }
}
