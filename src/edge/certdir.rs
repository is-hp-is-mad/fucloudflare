//! Certificates kept on disk, outside the configuration: what other tools
//! issue and renew (acme.sh, certbot, Caddy's storage, a hand-made pair).
//!
//! Each directory given with `--tls-cert-dir` is searched (four levels deep)
//! for certificate files (`.crt`, `.cer`, `.pem`) and the private key that goes
//! with each of them, whatever the tool's layout:
//!
//! - `name.crt` + `name.key` (Caddy: `certificates/<ca>/<host>/<host>.crt`)
//! - `fullchain.pem` + `privkey.pem` (certbot: `live/<host>/`)
//! - `fullchain.cer` + `<dir>.key` (acme.sh: `<host>/`, also `<host>_ecc/`)
//! - any certificate + the only key file in its directory
//!
//! A pair counts only when the key matches the certificate. The host names a
//! certificate is good for are the ones it says (SAN, wildcards and IP
//! addresses included); among several for one name, the one valid longest
//! wins. The directories are looked at again every minute, so renewals are
//! picked up without a restart.

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

const MAX_DEPTH: usize = 4;
const MAX_FILES: usize = 4096;
const MAX_FILE_SIZE: u64 = 1 << 20;

struct Entry {
    key: Arc<CertifiedKey>,
    /// Unix seconds.
    not_after: i64,
    not_before: i64,
    path: PathBuf,
}

pub struct DiskCerts {
    dirs: Vec<PathBuf>,
    entries: RwLock<Vec<Entry>>,
    /// What was on disk at the last scan: (path, modified, size).
    seen: RwLock<Vec<(PathBuf, Option<SystemTime>, u64)>>,
    /// host -> chosen certificate (cleared whenever the set changes).
    cache: RwLock<HashMap<String, Option<Arc<CertifiedKey>>>>,
}

fn now() -> i64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn is_cert_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".crt") || lower.ends_with(".cer") || lower.ends_with(".pem")) && !is_key_name(&lower)
}

fn is_key_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".key") || lower == "privkey.pem" || lower == "key.pem" || lower.ends_with("-key.pem") || lower.ends_with(".key.pem")
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else { return };
    for entry in read.flatten() {
        if out.len() >= MAX_FILES {
            return;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.is_dir() {
            if depth < MAX_DEPTH {
                walk(&path, depth + 1, out);
            }
        } else if meta.is_file() && meta.len() <= MAX_FILE_SIZE {
            out.push(path);
        }
    }
}

/// The key files that may belong to `cert`, most likely first.
fn key_candidates(cert: &Path, keys_in_dir: &[PathBuf]) -> Vec<PathBuf> {
    let dir = cert.parent().unwrap_or(Path::new("."));
    let stem = cert.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let dir_name = dir.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    let mut out = vec![dir.join(format!("{stem}.key")), dir.join("privkey.pem"), dir.join(format!("{dir_name}.key"))];
    // acme.sh names ECC directories `<host>_ecc` and the key `<host>.key`
    if let Some(host) = dir_name.strip_suffix("_ecc") {
        out.push(dir.join(format!("{host}.key")));
    }
    if keys_in_dir.len() == 1 {
        out.push(keys_in_dir[0].clone());
    }
    out.retain(|p| keys_in_dir.contains(p));
    out.dedup();
    out
}

fn load(files: &[PathBuf]) -> Vec<Entry> {
    let mut by_dir: HashMap<&Path, Vec<PathBuf>> = HashMap::new();
    for f in files {
        let name = f.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        if is_key_name(name) {
            by_dir.entry(f.parent().unwrap_or(Path::new("."))).or_default().push(f.clone());
        }
    }
    let mut entries: Vec<Entry> = Vec::new();
    for cert_path in files {
        let name = cert_path.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        if !is_cert_name(name) {
            continue;
        }
        let Ok(cert_pem) = std::fs::read_to_string(cert_path) else { continue };
        if !cert_pem.contains("BEGIN CERTIFICATE") {
            continue;
        }
        let keys = by_dir.get(cert_path.parent().unwrap_or(Path::new("."))).map(Vec::as_slice).unwrap_or_default();
        // a PEM that carries its own key works as well
        let mut candidates: Vec<Option<PathBuf>> = vec![None];
        candidates.extend(key_candidates(cert_path, keys).into_iter().map(Some));
        for key_path in candidates {
            let key_pem = match &key_path {
                None if cert_pem.contains("PRIVATE KEY") => cert_pem.clone(),
                None => continue,
                Some(p) => match std::fs::read_to_string(p) {
                    Ok(k) => k,
                    Err(_) => continue,
                },
            };
            let Ok(key) = super::tls::parse_cert(&cert_pem, &key_pem) else { continue };
            let Some((not_before, not_after)) = super::tls::cert_validity(&key.cert[0]) else { break };
            // the same certificate found twice (cert.pem and fullchain.pem): keep the longer chain
            if let Some(dup) = entries.iter_mut().find(|e| e.key.cert[0] == key.cert[0]) {
                if key.cert.len() > dup.key.cert.len() {
                    dup.key = key;
                    dup.path = cert_path.clone();
                }
            } else {
                entries.push(Entry { key, not_after, not_before, path: cert_path.clone() });
            }
            break;
        }
    }
    entries
}

fn covers(cert: &CertificateDer<'_>, host: &str) -> bool {
    let Ok(name) = ServerName::try_from(host) else { return false };
    rustls::server::ParsedCertificate::try_from(cert).is_ok_and(|parsed| rustls::client::verify_server_name(&parsed, &name).is_ok())
}

impl DiskCerts {
    pub fn new(dirs: Vec<PathBuf>) -> Arc<Self> {
        let me = Arc::new(DiskCerts { dirs, entries: RwLock::default(), seen: RwLock::default(), cache: RwLock::default() });
        me.rescan();
        me
    }

    /// Look at the directories again; reload when anything changed.
    pub fn rescan(&self) {
        let mut files = Vec::new();
        for dir in &self.dirs {
            walk(dir, 0, &mut files);
        }
        files.sort();
        let seen: Vec<_> = files
            .iter()
            .map(|p| {
                let meta = std::fs::metadata(p).ok();
                (p.clone(), meta.as_ref().and_then(|m| m.modified().ok()), meta.map_or(0, |m| m.len()))
            })
            .collect();
        if *self.seen.read().unwrap() == seen {
            return;
        }
        let entries = load(&files);
        let summary: Vec<String> = entries.iter().map(|e| e.path.display().to_string()).collect();
        tracing::info!("certificates on disk: {} loaded {:?}", entries.len(), summary);
        *self.entries.write().unwrap() = entries;
        *self.seen.write().unwrap() = seen;
        self.cache.write().unwrap().clear();
    }

    /// Follow what other tools renew.
    pub async fn watch(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let me = self.clone();
            let _ = tokio::task::spawn_blocking(move || me.rescan()).await;
        }
    }

    /// The certificate for `host` (a DNS name or an IP address), if any is on disk.
    pub fn get(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(hit) = self.cache.read().unwrap().get(&host) {
            return hit.clone();
        }
        let t = now();
        let found = self
            .entries
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.not_before <= t && t < e.not_after && covers(&e.key.cert[0], &host))
            .max_by_key(|e| e.not_after)
            .map(|e| e.key.clone());
        let mut cache = self.cache.write().unwrap();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(host, found.clone());
        found
    }

    /// Validity of the certificate [`Self::get`] picks for `host`.
    pub fn validity(&self, host: &str) -> Option<(i64, i64)> {
        let key = self.get(host)?;
        self.entries.read().unwrap().iter().find(|e| Arc::ptr_eq(&e.key, &key)).map(|e| (e.not_before, e.not_after))
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(names: &[&str]) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn finds_pairs_in_the_usual_layouts() {
        let root = std::env::temp_dir().join(format!("fucf-certdir-{}", uuid::Uuid::new_v4().simple()));
        let write = |rel: &str, text: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        // Caddy
        let (c, k) = pair(&["chat.example.org"]);
        write("caddy/certificates/acme/chat.example.org/chat.example.org.crt", &c);
        write("caddy/certificates/acme/chat.example.org/chat.example.org.key", &k);
        // certbot
        let (c, k) = pair(&["*.wild.example.org"]);
        write("letsencrypt/live/wild/fullchain.pem", &c);
        write("letsencrypt/live/wild/privkey.pem", &k);
        // acme.sh (ECC), with a stray CA file that matches no key
        let (c, k) = pair(&["sub.example.net"]);
        let (ca, _) = pair(&["ca.invalid"]);
        write("acme/sub.example.net_ecc/fullchain.cer", &c);
        write("acme/sub.example.net_ecc/ca.cer", &ca);
        write("acme/sub.example.net_ecc/sub.example.net.key", &k);
        // an IP address, key and certificate in one file
        let (c, k) = pair(&["192.0.2.7"]);
        write("ip/both.pem", &format!("{c}{k}"));
        // a key that belongs to nothing here
        let (c, _) = pair(&["lonely.example"]);
        let (_, other) = pair(&["x.invalid"]);
        write("bad/lonely.crt", &c);
        write("bad/lonely.key", &other);

        let certs = DiskCerts::new(vec![root.clone()]);
        assert_eq!(certs.len(), 4);
        for host in ["chat.example.org", "a.wild.example.org", "sub.example.net", "192.0.2.7"] {
            assert!(certs.get(host).is_some(), "{host}");
        }
        for host in ["wild.example.org", "lonely.example", "ca.invalid", "other.example"] {
            assert!(certs.get(host).is_none(), "{host}");
        }

        // a renewal shows up on the next look
        let (c, k) = pair(&["new.example.org"]);
        write("caddy/certificates/acme/new.example.org/new.example.org.crt", &c);
        write("caddy/certificates/acme/new.example.org/new.example.org.key", &k);
        assert!(certs.get("new.example.org").is_none());
        certs.rescan();
        assert!(certs.get("new.example.org").is_some());
        let _ = std::fs::remove_dir_all(root);
    }
}
