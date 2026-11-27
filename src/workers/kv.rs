//! Workers KV (`env.<BINDING>`): disk-backed key-value namespaces with
//! TTL, metadata, prefix/cursor pagination, and HLC/LWW peer sync.

use crate::sync::clock::{unix_ms, HlcClock, SyncMeta};
use crate::sync::{DomainDelta, SyncProvider};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_KEY_BYTES: usize = 512;
pub const MAX_VALUE_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 1024;
pub const MIN_TTL_SECS: u64 = 60;
const DEFAULT_LIST_LIMIT: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvNamespace {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvEntryMeta {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct KvIndex {
    epoch: String,
    local_rev: u64,
    namespaces: BTreeMap<String, KvNamespace>,
    ns_tombstones: BTreeMap<String, SyncMeta>,
    /// `(namespace_id, key)` -> entry metadata
    entries: BTreeMap<String, BTreeMap<String, KvEntryMeta>>,
    entry_tombstones: BTreeMap<String, BTreeMap<String, SyncMeta>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KvSyncEntry {
    ns_id: String,
    key: String,
    expiration: Option<u64>,
    metadata: Option<Value>,
    value_b64: String,
    sync: SyncMeta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct KvDeltaPayload {
    namespaces: Vec<KvNamespace>,
    ns_tombstones: Vec<(String, SyncMeta)>,
    entries: Vec<KvSyncEntry>,
    entry_tombstones: Vec<(String, String, SyncMeta)>,
}

pub struct KvStore {
    dir: Option<PathBuf>,
    read_only: AtomicBool,
    clock: Arc<HlcClock>,
    sync_node: std::sync::RwLock<String>,
    index: Mutex<KvIndex>,
    write_lock: Mutex<()>,
    /// In-memory blob fallback for `open_ephemeral` (`--role accelerate`).
    mem_blobs: Mutex<HashMap<(String, String), Bytes>>,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn now_secs() -> u64 {
    unix_ms() / 1000
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn key_blob_name(key: &str) -> String {
    let d = digest(&SHA256, key.as_bytes());
    let mut s = String::with_capacity(68);
    for b in d.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s.push_str(".bin");
    s
}

pub(crate) fn is_valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(format!("KV key length must be 1..={MAX_KEY_BYTES} bytes"));
    }
    if key == "." || key == ".." {
        return Err("KV key cannot be '.' or '..'".into());
    }
    Ok(())
}

impl KvStore {
    pub fn open(dir: PathBuf, clock: Arc<HlcClock>, sync_node: String) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(&dir)?;
        let idx_path = dir.join("index.json");
        let mut idx: KvIndex = match std::fs::read(&idx_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("corrupt KV index {}: {e}", idx_path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => KvIndex::default(),
            Err(e) => return Err(e.into()),
        };
        if idx.epoch.is_empty() {
            idx.epoch = new_id();
        }
        Ok(Arc::new(KvStore {
            dir: Some(dir),
            read_only: AtomicBool::new(false),
            clock,
            sync_node: std::sync::RwLock::new(sync_node),
            index: Mutex::new(idx),
            write_lock: Mutex::new(()),
            mem_blobs: Mutex::new(HashMap::new()),
        }))
    }

    pub fn open_ephemeral(clock: Arc<HlcClock>, sync_node: String) -> Arc<Self> {
        let mut idx = KvIndex::default();
        idx.epoch = new_id();
        Arc::new(KvStore {
            dir: None,
            read_only: AtomicBool::new(true),
            clock,
            sync_node: std::sync::RwLock::new(sync_node),
            index: Mutex::new(idx),
            write_lock: Mutex::new(()),
            mem_blobs: Mutex::new(HashMap::new()),
        })
    }

    fn save_index_snapshot(&self, idx: &KvIndex) -> Result<(), String> {
        let Some(dir) = &self.dir else { return Ok(()) };
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let data = serde_json::to_vec(idx).map_err(|e| e.to_string())?;
        let tmp = dir.join(format!("index.{}.tmp", uuid::Uuid::new_v4().simple()));
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join("index.json")).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn write_blob(&self, ns_id: &str, key: &str, value: &[u8]) -> Result<(), String> {
        if !is_valid_id(ns_id) {
            return Err("invalid namespace id".into());
        }
        if let Some(dir) = &self.dir {
            let ns_dir = dir.join("blobs").join(ns_id);
            std::fs::create_dir_all(&ns_dir).map_err(|e| e.to_string())?;
            let path = ns_dir.join(key_blob_name(key));
            let tmp = ns_dir.join(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
            std::fs::write(&tmp, value).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        } else {
            self.mem_blobs.lock().unwrap().insert((ns_id.to_string(), key.to_string()), Bytes::copy_from_slice(value));
        }
        Ok(())
    }

    fn read_blob(&self, ns_id: &str, key: &str) -> Result<Option<Bytes>, String> {
        if !is_valid_id(ns_id) {
            return Err("invalid namespace id".into());
        }
        if let Some(dir) = &self.dir {
            let path = dir.join("blobs").join(ns_id).join(key_blob_name(key));
            match std::fs::read(&path) {
                Ok(b) => Ok(Some(Bytes::from(b))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        } else {
            Ok(self.mem_blobs.lock().unwrap().get(&(ns_id.to_string(), key.to_string())).cloned())
        }
    }

    fn remove_blob(&self, ns_id: &str, key: &str) {
        if !is_valid_id(ns_id) {
            return;
        }
        if let Some(dir) = &self.dir {
            let path = dir.join("blobs").join(ns_id).join(key_blob_name(key));
            let _ = std::fs::remove_file(path);
        } else {
            self.mem_blobs.lock().unwrap().remove(&(ns_id.to_string(), key.to_string()));
        }
    }

    fn stamp(&self, idx: &mut KvIndex, deleted: bool) -> SyncMeta {
        idx.local_rev = idx.local_rev.saturating_add(1);
        let node = self.sync_node.read().unwrap().clone();
        self.clock.stamp(&node, deleted, idx.local_rev)
    }

    // ---- Namespace management ----

    pub fn list_namespaces(&self) -> Vec<KvNamespace> {
        self.index.lock().unwrap().namespaces.values().cloned().collect()
    }

    pub fn get_namespace(&self, id: &str) -> Option<KvNamespace> {
        self.index.lock().unwrap().namespaces.get(id).cloned()
    }

    pub fn create_namespace(&self, title: &str) -> Result<KvNamespace, String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let title = title.trim();
        if title.is_empty() || title.len() > 64 {
            return Err("namespace title must be 1..=64 characters".into());
        }
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        if idx.namespaces.values().any(|n| n.title == title) {
            return Err(format!("KV namespace '{title}' already exists"));
        }
        let ts = now_iso();
        let sync = self.stamp(&mut idx, false);
        let ns = KvNamespace {
            id: new_id(),
            title: title.to_string(),
            created_on: ts.clone(),
            modified_on: ts,
            sync,
        };
        idx.ns_tombstones.remove(&ns.id);
        idx.namespaces.insert(ns.id.clone(), ns.clone());
        self.save_index_snapshot(&idx)?;
        *self.index.lock().unwrap() = idx;
        Ok(ns)
    }

    pub fn rename_namespace(&self, id: &str, title: &str) -> Result<KvNamespace, String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let title = title.trim();
        if title.is_empty() || title.len() > 64 {
            return Err("namespace title must be 1..=64 characters".into());
        }
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        if !idx.namespaces.contains_key(id) {
            return Err("namespace not found".into());
        }
        if idx.namespaces.values().any(|n| n.id != id && n.title == title) {
            return Err(format!("KV namespace '{title}' already exists"));
        }
        let sync = self.stamp(&mut idx, false);
        let ns = idx.namespaces.get_mut(id).unwrap();
        ns.title = title.to_string();
        ns.modified_on = now_iso();
        ns.sync = sync;
        let out = ns.clone();
        self.save_index_snapshot(&idx)?;
        *self.index.lock().unwrap() = idx;
        Ok(out)
    }

    pub fn delete_namespace(&self, id: &str) -> Result<(), String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        if idx.namespaces.remove(id).is_none() {
            return Err("namespace not found".into());
        }
        let tomb = self.stamp(&mut idx, true);
        idx.ns_tombstones.insert(id.to_string(), tomb);
        idx.entries.remove(id);
        idx.entry_tombstones.remove(id);
        self.save_index_snapshot(&idx)?;
        *self.index.lock().unwrap() = idx;
        if let Some(dir) = &self.dir {
            if is_valid_id(id) {
                let _ = std::fs::remove_dir_all(dir.join("blobs").join(id));
            }
        } else {
            self.mem_blobs.lock().unwrap().retain(|(ns, _), _| ns != id);
        }
        Ok(())
    }

    // ---- Key-Value Operations ----

    pub fn get_with_metadata(&self, ns_id: &str, key: &str) -> Result<Option<(Bytes, Option<Value>)>, String> {
        validate_key(key)?;
        let now = now_secs();
        let entry = {
            let idx = self.index.lock().unwrap();
            if !idx.namespaces.contains_key(ns_id) {
                return Err(format!("KV namespace '{ns_id}' not found"));
            }
            idx.entries.get(ns_id).and_then(|m| m.get(key)).cloned()
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        if entry.expiration.is_some_and(|exp| exp <= now) {
            return Ok(None);
        }
        let Some(bytes) = self.read_blob(ns_id, key)? else {
            return Ok(None);
        };
        Ok(Some((bytes, entry.metadata)))
    }

    pub fn put(
        &self,
        ns_id: &str,
        key: &str,
        value: &[u8],
        expiration: Option<u64>,
        expiration_ttl: Option<u64>,
        metadata: Option<Value>,
    ) -> Result<(), String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        validate_key(key)?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(format!("KV value exceeds {MAX_VALUE_BYTES} bytes"));
        }
        if let Some(m) = &metadata {
            let serialized = serde_json::to_vec(m).map_err(|e| e.to_string())?;
            if serialized.len() > MAX_METADATA_BYTES {
                return Err(format!("KV metadata exceeds {MAX_METADATA_BYTES} bytes"));
            }
        }
        let exp = match (expiration, expiration_ttl) {
            (Some(_), Some(_)) => return Err("cannot specify both expiration and expirationTtl".into()),
            (Some(e), None) => Some(e),
            (None, Some(ttl)) => {
                if ttl < MIN_TTL_SECS {
                    return Err(format!("expirationTtl must be >= {MIN_TTL_SECS} seconds"));
                }
                Some(now_secs().saturating_add(ttl))
            }
            (None, None) => None,
        };

        let _w = self.write_lock.lock().unwrap();
        {
            let idx = self.index.lock().unwrap();
            if !idx.namespaces.contains_key(ns_id) {
                return Err(format!("KV namespace '{ns_id}' not found"));
            }
        }
        self.write_blob(ns_id, key, value)?;
        let mut idx = self.index.lock().unwrap().clone();
        let sync = self.stamp(&mut idx, false);
        if let Some(tombs) = idx.entry_tombstones.get_mut(ns_id) {
            tombs.remove(key);
        }
        idx.entries.entry(ns_id.to_string()).or_default().insert(
            key.to_string(),
            KvEntryMeta {
                key: key.to_string(),
                expiration: exp,
                metadata,
                sync,
            },
        );
        self.save_index_snapshot(&idx)?;
        *self.index.lock().unwrap() = idx;
        Ok(())
    }

    pub fn delete(&self, ns_id: &str, key: &str) -> Result<(), String> {
        if self.read_only.load(Ordering::Relaxed) {
            return Err("read-only accelerate node".into());
        }
        validate_key(key)?;
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        if !idx.namespaces.contains_key(ns_id) {
            return Err(format!("KV namespace '{ns_id}' not found"));
        }
        idx.entries.get_mut(ns_id).and_then(|m| m.remove(key));
        let tomb = self.stamp(&mut idx, true);
        idx.entry_tombstones.entry(ns_id.to_string()).or_default().insert(key.to_string(), tomb);
        self.save_index_snapshot(&idx)?;
        *self.index.lock().unwrap() = idx;
        self.remove_blob(ns_id, key);
        Ok(())
    }

    pub fn list(
        &self,
        ns_id: &str,
        prefix: Option<&str>,
        limit: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<Value, String> {
        let now = now_secs();
        let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).clamp(1, DEFAULT_LIST_LIMIT);
        let idx = self.index.lock().unwrap();
        if !idx.namespaces.contains_key(ns_id) {
            return Err(format!("KV namespace '{ns_id}' not found"));
        }
        let mut keys: Vec<Value> = Vec::new();
        let mut next_cursor: Option<String> = None;
        if let Some(map) = idx.entries.get(ns_id) {
            let iter = match cursor {
                Some(c) if !c.is_empty() => map.range::<str, _>((std::ops::Bound::Excluded(c), std::ops::Bound::Unbounded)),
                _ => map.range::<str, _>(..),
            };
            for (k, entry) in iter {
                if let Some(pfx) = prefix {
                    if !k.starts_with(pfx) {
                        continue;
                    }
                }
                if entry.expiration.is_some_and(|e| e <= now) {
                    continue;
                }
                if keys.len() >= limit {
                    next_cursor = keys.last().and_then(|v| v["name"].as_str()).map(String::from);
                    break;
                }
                let mut item = json!({ "name": k });
                if let Some(exp) = entry.expiration {
                    item["expiration"] = json!(exp);
                }
                if let Some(meta) = &entry.metadata {
                    item["metadata"] = meta.clone();
                }
                keys.push(item);
            }
        }
        let list_complete = next_cursor.is_none();
        let mut out = json!({
            "keys": keys,
            "list_complete": list_complete,
        });
        if let Some(c) = next_cursor {
            out["cursor"] = json!(c);
        }
        Ok(out)
    }
}

impl SyncProvider for KvStore {
    fn domain(&self) -> &'static str {
        "kv"
    }

    fn current_rev(&self) -> u64 {
        self.index.lock().unwrap().local_rev
    }

    fn epoch(&self) -> String {
        self.index.lock().unwrap().epoch.clone()
    }

    fn export_since(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
        let idx = self.index.lock().unwrap().clone();
        let full_resync = peer_epoch != Some(idx.epoch.as_str()) || since_rev == 0 || since_rev > idx.local_rev;
        let threshold = if full_resync { 0 } else { since_rev };

        let mut payload = KvDeltaPayload::default();
        for ns in idx.namespaces.values() {
            if full_resync || ns.sync.local_rev > threshold {
                payload.namespaces.push(ns.clone());
            }
        }
        for (id, t) in &idx.ns_tombstones {
            if full_resync || t.local_rev > threshold {
                payload.ns_tombstones.push((id.clone(), t.clone()));
            }
        }
        for (ns_id, entries) in &idx.entries {
            for (k, entry) in entries {
                if full_resync || entry.sync.local_rev > threshold {
                    if let Ok(Some(bytes)) = self.read_blob(ns_id, k) {
                        payload.entries.push(KvSyncEntry {
                            ns_id: ns_id.clone(),
                            key: k.clone(),
                            expiration: entry.expiration,
                            metadata: entry.metadata.clone(),
                            value_b64: B64.encode(&bytes),
                            sync: entry.sync.clone(),
                        });
                    }
                }
            }
        }
        for (ns_id, tombs) in &idx.entry_tombstones {
            for (k, t) in tombs {
                if full_resync || t.local_rev > threshold {
                    payload.entry_tombstones.push((ns_id.clone(), k.clone(), t.clone()));
                }
            }
        }

        Ok(DomainDelta {
            domain: "kv".into(),
            epoch: idx.epoch,
            from_rev: if full_resync { 0 } else { since_rev },
            to_rev: idx.local_rev,
            full_resync,
            payload: serde_json::to_value(payload).map_err(|e| e.to_string())?,
        })
    }

    fn merge_delta(&self, delta: &DomainDelta, clock: &HlcClock) -> Result<bool, String> {
        if delta.domain != "kv" {
            return Err("wrong domain for KvStore".into());
        }
        let payload: KvDeltaPayload = serde_json::from_value(delta.payload.clone()).map_err(|e| e.to_string())?;
        let _w = self.write_lock.lock().unwrap();
        let mut idx = self.index.lock().unwrap().clone();
        let mut changed = false;

        let now_ms = unix_ms();
        let observe = |m: &mut SyncMeta| {
            m.clamp_skew(now_ms);
            clock.observe(m.updated_ms, m.seq);
        };

        for mut ns in payload.namespaces {
            if !is_valid_id(&ns.id) {
                continue;
            }
            observe(&mut ns.sync);
            let tomb = idx.ns_tombstones.get(&ns.id);
            if tomb.is_some_and(|t| !ns.sync.wins_over(t)) {
                continue;
            }
            let cur = idx.namespaces.get(&ns.id).map(|x| &x.sync);
            if cur.is_none_or(|c| ns.sync.wins_over(c)) {
                idx.local_rev = idx.local_rev.saturating_add(1);
                ns.sync.local_rev = idx.local_rev;
                idx.ns_tombstones.remove(&ns.id);
                idx.namespaces.insert(ns.id.clone(), ns);
                changed = true;
            }
        }

        for (id, mut tomb) in payload.ns_tombstones {
            if !is_valid_id(&id) {
                continue;
            }
            tomb.deleted = true;
            observe(&mut tomb);
            let cur_live = idx.namespaces.get(&id).map(|x| &x.sync);
            let cur_tomb = idx.ns_tombstones.get(&id);
            let wins_live = cur_live.is_none_or(|c| tomb.wins_over(c));
            let wins_tomb = cur_tomb.is_none_or(|c| tomb.wins_over(c));
            if wins_live && wins_tomb {
                idx.local_rev = idx.local_rev.saturating_add(1);
                tomb.local_rev = idx.local_rev;
                if idx.namespaces.remove(&id).is_some() {
                    changed = true;
                }
                idx.entries.remove(&id);
                idx.entry_tombstones.remove(&id);
                idx.ns_tombstones.insert(id.clone(), tomb);
                if let Some(dir) = &self.dir {
                    let _ = std::fs::remove_dir_all(dir.join("blobs").join(&id));
                } else {
                    self.mem_blobs.lock().unwrap().retain(|(ns, _), _| ns != &id);
                }
            }
        }

        for mut e in payload.entries {
            if !is_valid_id(&e.ns_id) {
                continue;
            }
            observe(&mut e.sync);
            if !idx.namespaces.contains_key(&e.ns_id) {
                continue;
            }
            let tomb = idx.entry_tombstones.get(&e.ns_id).and_then(|m| m.get(&e.key));
            if tomb.is_some_and(|t| !e.sync.wins_over(t)) {
                continue;
            }
            let cur = idx.entries.get(&e.ns_id).and_then(|m| m.get(&e.key)).map(|x| &x.sync);
            if cur.is_none_or(|c| e.sync.wins_over(c)) {
                let bytes = B64.decode(&e.value_b64).map_err(|err| err.to_string())?;
                self.write_blob(&e.ns_id, &e.key, &bytes)?;
                idx.local_rev = idx.local_rev.saturating_add(1);
                e.sync.local_rev = idx.local_rev;
                if let Some(tombs) = idx.entry_tombstones.get_mut(&e.ns_id) {
                    tombs.remove(&e.key);
                }
                idx.entries.entry(e.ns_id).or_default().insert(
                    e.key.clone(),
                    KvEntryMeta {
                        key: e.key,
                        expiration: e.expiration,
                        metadata: e.metadata,
                        sync: e.sync,
                    },
                );
                changed = true;
            }
        }

        for (ns_id, key, mut tomb) in payload.entry_tombstones {
            if !is_valid_id(&ns_id) {
                continue;
            }
            tomb.deleted = true;
            observe(&mut tomb);
            let cur_live = idx.entries.get(&ns_id).and_then(|m| m.get(&key)).map(|x| &x.sync);
            let cur_tomb = idx.entry_tombstones.get(&ns_id).and_then(|m| m.get(&key));
            if cur_live.is_none_or(|c| tomb.wins_over(c)) && cur_tomb.is_none_or(|c| tomb.wins_over(c)) {
                idx.local_rev = idx.local_rev.saturating_add(1);
                tomb.local_rev = idx.local_rev;
                if idx.entries.get_mut(&ns_id).and_then(|m| m.remove(&key)).is_some() {
                    changed = true;
                }
                idx.entry_tombstones.entry(ns_id.clone()).or_default().insert(key.clone(), tomb);
                self.remove_blob(&ns_id, &key);
            }
        }

        if changed {
            self.save_index_snapshot(&idx)?;
            *self.index.lock().unwrap() = idx;
        }
        Ok(changed)
    }
}

// ---- Worker Host Functions ----

#[derive(Deserialize)]
struct KvGetReq {
    ns_id: String,
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct KvPutReq {
    ns_id: String,
    key: String,
    value_b64: String,
    expiration: Option<u64>,
    #[serde(rename = "expirationTtl")]
    expiration_ttl: Option<u64>,
    metadata: Option<Value>,
}

#[derive(Deserialize)]
struct KvDelReq {
    ns_id: String,
    key: String,
}

#[derive(Deserialize)]
struct KvListReq {
    ns_id: String,
    prefix: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

pub fn host_kv_get(
    kv: &Arc<KvStore>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: KvGetReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let kv = kv.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let mut items = Vec::with_capacity(req.keys.len());
            for k in req.keys {
                match kv.get_with_metadata(&req.ns_id, &k)? {
                    Some((bytes, metadata)) => items.push(json!({
                        "key": k,
                        "value_b64": B64.encode(&bytes),
                        "metadata": metadata,
                    })),
                    None => items.push(json!({
                        "key": k,
                        "value_b64": Value::Null,
                        "metadata": Value::Null,
                    })),
                }
            }
            Ok(serde_json::to_string(&items).unwrap_or_else(|_| "[]".into()))
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

pub fn host_kv_put(
    kv: &Arc<KvStore>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: KvPutReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let bytes = B64.decode(&req.value_b64).map_err(|e| e.to_string())?;
    let kv = kv.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            kv.put(&req.ns_id, &req.key, &bytes, req.expiration, req.expiration_ttl, req.metadata)?;
            Ok("true".into())
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

pub fn host_kv_delete(
    kv: &Arc<KvStore>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: KvDelReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let kv = kv.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            kv.delete(&req.ns_id, &req.key)?;
            Ok("true".into())
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

pub fn host_kv_list(
    kv: &Arc<KvStore>,
    runtime: &tokio::runtime::Handle,
    arg_json: &str,
) -> Result<String, String> {
    let req: KvListReq = serde_json::from_str(arg_json).map_err(|e| e.to_string())?;
    let kv = kv.clone();
    runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let v = kv.list(&req.ns_id, req.prefix.as_deref(), req.limit, req.cursor.as_deref())?;
            Ok(v.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_crud_ttl_bounds_list_and_sync() {
        let dir_a = std::env::temp_dir().join(format!("fucf-kv-a-{}", uuid::Uuid::new_v4().simple()));
        let dir_b = std::env::temp_dir().join(format!("fucf-kv-b-{}", uuid::Uuid::new_v4().simple()));
        let clk_a = Arc::new(HlcClock::default());
        let clk_b = Arc::new(HlcClock::default());
        let a = KvStore::open(dir_a.clone(), clk_a.clone(), "au".into()).unwrap();
        let b = KvStore::open(dir_b.clone(), clk_b.clone(), "eu".into()).unwrap();

        let ns = a.create_namespace("sessions").unwrap();
        assert_eq!(a.list_namespaces().len(), 1);

        // Bounds checks
        assert!(a.put(&ns.id, &"x".repeat(513), b"v", None, None, None).is_err());
        assert!(a.put(&ns.id, "k1", b"v", None, Some(30), None).is_err()); // TTL < 60
        let big_meta = json!({ "pad": "x".repeat(1100) });
        assert!(a.put(&ns.id, "k1", b"v", None, None, Some(big_meta)).is_err());

        // Put with metadata & future TTL
        a.put(&ns.id, "user:1", b"alice", None, Some(120), Some(json!({"role": "admin"}))).unwrap();
        a.put(&ns.id, "user:2", b"bob", None, None, None).unwrap();
        a.put(&ns.id, "other:1", b"carol", None, None, None).unwrap();
        // Expired entry
        a.put(&ns.id, "user:expired", b"old", Some(1), None, None).unwrap();

        let got = a.get_with_metadata(&ns.id, "user:1").unwrap().unwrap();
        assert_eq!(got.0.as_ref(), b"alice");
        assert_eq!(got.1, Some(json!({"role": "admin"})));
        assert!(a.get_with_metadata(&ns.id, "user:expired").unwrap().is_none());

        // Prefix + cursor pagination
        let page1 = a.list(&ns.id, Some("user:"), Some(1), None).unwrap();
        assert_eq!(page1["keys"].as_array().unwrap().len(), 1);
        assert_eq!(page1["list_complete"], false);
        let cur = page1["cursor"].as_str().unwrap();
        let page2 = a.list(&ns.id, Some("user:"), Some(10), Some(cur)).unwrap();
        assert_eq!(page2["keys"].as_array().unwrap().len(), 1);
        assert_eq!(page2["list_complete"], true);

        // Sync A -> B
        let d0 = a.export_since(0, None).unwrap();
        assert!(b.merge_delta(&d0, &clk_b).unwrap());
        assert_eq!(b.get_with_metadata(&ns.id, "user:1").unwrap().unwrap().0.as_ref(), b"alice");

        // Delete on A & incremental sync to B
        let rev_b = d0.to_rev;
        let ep_a = d0.epoch;
        a.delete(&ns.id, "user:1").unwrap();
        let d1 = a.export_since(rev_b, Some(&ep_a)).unwrap();
        assert!(!d1.full_resync);
        assert!(b.merge_delta(&d1, &clk_b).unwrap());
        assert!(b.get_with_metadata(&ns.id, "user:1").unwrap().is_none());

        // Ephemeral accelerate node rejects writes
        let accel = KvStore::open_ephemeral(Arc::new(HlcClock::default()), "jp".into());
        assert!(accel.create_namespace("ro").is_err());
        assert!(accel.merge_delta(&a.export_since(0, None).unwrap(), &clk_b).unwrap());
        assert_eq!(accel.get_with_metadata(&ns.id, "user:2").unwrap().unwrap().0.as_ref(), b"bob");

        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }
}
