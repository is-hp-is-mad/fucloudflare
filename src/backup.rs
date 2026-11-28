//! Backups: everything the fleet replicates (configuration, accounts,
//! Workers KV, D1) as one gzipped JSON bundle -- the same full deltas that
//! peers send each other, so restoring is merging them into empty stores.
//!
//! Every node (accelerate nodes too: they hold the same replica in memory)
//! writes one every few hours into its backup directory and keeps the last
//! so many. `GET /client/v4/backup` hands out a fresh one; `--restore-from`
//! merges one in at start.

use crate::sync::{DomainDelta, HlcClock, SyncProvider};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const FORMAT: &str = "fucf-backup/1";
const PREFIX: &str = "fucf-backup-";

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub created: String,
    pub node: String,
    pub build: String,
    pub domains: Vec<DomainDelta>,
}

/// A fresh bundle, gzipped.
pub fn take(providers: &[Arc<dyn SyncProvider>], node: &str) -> Result<Vec<u8>, String> {
    let mut domains = Vec::new();
    for p in providers {
        domains.push(p.export_since(0, None)?);
    }
    let bundle = Bundle { format: FORMAT.into(), created: crate::store::now(), node: node.into(), build: env!("CARGO_PKG_VERSION").into(), domains };
    let json = serde_json::to_vec(&bundle).map_err(|e| e.to_string())?;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&json).map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())
}

pub fn read(bytes: &[u8]) -> Result<Bundle, String> {
    let mut json = Vec::new();
    let raw = if bytes.starts_with(&[0x1f, 0x8b]) {
        flate2::read::GzDecoder::new(bytes).take(1 << 30).read_to_end(&mut json).map_err(|e| format!("not a gzip file: {e}"))?;
        &json[..]
    } else {
        bytes
    };
    let bundle: Bundle = serde_json::from_slice(raw).map_err(|e| format!("not a backup: {e}"))?;
    if bundle.format != FORMAT {
        return Err(format!("unknown backup format '{}'", bundle.format));
    }
    Ok(bundle)
}

/// Merge a bundle into the stores (what is newer here stays). Returns the
/// domains it changed.
pub fn restore(bundle: &Bundle, providers: &[Arc<dyn SyncProvider>], clock: &HlcClock) -> Result<Vec<String>, String> {
    let mut changed = Vec::new();
    for delta in &bundle.domains {
        let Some(p) = providers.iter().find(|p| p.domain() == delta.domain) else {
            tracing::warn!("backup: nothing here takes the '{}' domain; skipped", delta.domain);
            continue;
        };
        // merged as an incremental delta: a full one would drop what is only here
        let mut d = delta.clone();
        d.full_resync = false;
        if p.merge_delta(&d, clock).map_err(|e| format!("{}: {e}", delta.domain))? {
            changed.push(delta.domain.clone());
        }
    }
    Ok(changed)
}

fn file_name(created_ms: u64) -> String {
    let t = chrono::DateTime::from_timestamp_millis(created_ms as i64).unwrap_or_default();
    format!("{PREFIX}{}.json.gz", t.format("%Y%m%dT%H%M%SZ"))
}

/// The backups in `dir`, oldest first.
pub fn list(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(".json.gz")))
        .collect();
    files.sort();
    files
}

/// Write a bundle into `dir` (owner-only) and keep the newest `keep`.
pub fn save(dir: &Path, bytes: &[u8], keep: usize) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = dir.join(file_name(crate::sync::unix_ms()));
    let tmp = path.with_extension("tmp");
    crate::auth::write_private(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    let files = list(dir);
    for old in files.iter().take(files.len().saturating_sub(keep.max(1))) {
        let _ = std::fs::remove_file(old);
    }
    Ok(path)
}

/// Every `every`, a backup into `dir`.
pub fn spawn(dir: PathBuf, every: std::time::Duration, keep: usize, providers: Vec<Arc<dyn SyncProvider>>, node: String) {
    tokio::spawn(async move {
        // the first one a few minutes after start: the replica has filled up by then
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
        loop {
            let (dir, providers, node) = (dir.clone(), providers.clone(), node.clone());
            let done = tokio::task::spawn_blocking(move || take(&providers, &node).and_then(|b| save(&dir, &b, keep).map_err(|e| e.to_string()).map(|p| (p, b.len())))).await;
            match done {
                Ok(Ok((path, size))) => tracing::info!("backup: {} ({size} bytes)", path.display()),
                Ok(Err(e)) => tracing::warn!("backup failed: {e}"),
                Err(e) => tracing::warn!("backup failed: {e}"),
            }
            tokio::time::sleep(every).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_brings_everything_back() {
        let dir = std::env::temp_dir().join(format!("fucf-backup-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(crate::store::Store::open(&dir.join("state.json"), vec![]).unwrap());
        let zone = store.create_zone("example.com").unwrap();
        store
            .create_record(&zone.id, crate::store::RecordInput { rtype: "A".into(), name: "www".into(), content: "192.0.2.1".into(), ttl: 1, priority: None, proxied: true, comment: None, origin: None })
            .unwrap();
        let accounts = Arc::new(crate::auth::Accounts::open(dir.join("accounts.json"), None));
        accounts.set_sync_identity(store.clock(), "au".into());
        accounts.create_user("owner@example.com", crate::auth::Role::Admin, Some("a good password"), "owner@example.com", &Default::default()).unwrap();
        let providers: Vec<Arc<dyn SyncProvider>> = vec![store.clone(), accounts.clone()];
        let bytes = take(&providers, "au").unwrap();

        // kept on disk, the newest so many
        let kept = dir.join("backups");
        for _ in 0..3 {
            save(&kept, &bytes, 2).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        assert_eq!(list(&kept).len(), 2);

        // into an empty node
        let fresh = Arc::new(crate::store::Store::open(&dir.join("fresh.json"), vec![]).unwrap());
        let fresh_accounts = Arc::new(crate::auth::Accounts::open(dir.join("fresh-accounts.json"), None));
        fresh_accounts.set_sync_identity(fresh.clock(), "jp".into());
        let targets: Vec<Arc<dyn SyncProvider>> = vec![fresh.clone(), fresh_accounts.clone()];
        let bundle = read(&std::fs::read(list(&kept).pop().unwrap()).unwrap()).unwrap();
        let changed = restore(&bundle, &targets, &fresh.clock()).unwrap();
        assert_eq!(changed, vec!["config".to_string(), "accounts".to_string()]);
        let (_, recs) = fresh.list_records(&zone.id).unwrap();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].proxied);
        assert!(matches!(fresh_accounts.login("owner@example.com", "a good password", &Default::default()), Ok(crate::auth::Login::Session(..))));
        assert!(read(b"{}").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
