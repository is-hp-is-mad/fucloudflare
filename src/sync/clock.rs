//! Hybrid Logical Clock (HLC) and total-order Last-Write-Wins (LWW) metadata.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum forward clock skew (5 minutes) accepted from a remote peer so a
/// broken system clock cannot permanently poison LWW ordering.
pub const MAX_SKEW_MS: u64 = 300_000;

pub fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Replication metadata attached to every mutable entity and tombstone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncMeta {
    pub updated_ms: u64,
    pub seq: u64,
    pub node: String,
    #[serde(default)]
    pub deleted: bool,
    /// Local monotonic commit sequence on this node (used for `?since=` cursors;
    /// not transmitted across peers).
    #[serde(skip_serializing, default)]
    pub local_rev: u64,
}

impl SyncMeta {
    pub fn is_unset(&self) -> bool {
        self.updated_ms == 0 && self.seq == 0 && self.node.is_empty() && !self.deleted
    }

    pub fn version_key(&self) -> (u64, u64, &str) {
        (self.updated_ms, self.seq, self.node.as_str())
    }

    /// Strict total-order comparison: `(updated_ms, seq, node)`.
    pub fn wins_over(&self, other: &SyncMeta) -> bool {
        self.version_key() > other.version_key()
    }

    /// Clamp incoming remote timestamps that exceed `now_ms + MAX_SKEW_MS` so
    /// a rogue or skewed peer cannot permanently win LWW comparisons.
    pub fn clamp_skew(&mut self, now_ms: u64) {
        let max_allowed = now_ms.saturating_add(MAX_SKEW_MS);
        if self.updated_ms > max_allowed {
            tracing::warn!(
                "sync: clamping incoming SyncMeta.updated_ms ({} ms ahead of local clock)",
                self.updated_ms - now_ms
            );
            self.updated_ms = max_allowed;
        }
    }
}

/// Thread-safe Hybrid Logical Clock generating strictly monotonic `(ms, seq)`
/// timestamps within a node and advancing on observed peer timestamps.
pub struct HlcClock {
    inner: Mutex<(u64, u64)>,
}

impl Default for HlcClock {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl HlcClock {
    pub fn new(initial_ms: u64, initial_seq: u64) -> Self {
        HlcClock { inner: Mutex::new((initial_ms, initial_seq)) }
    }

    /// Advance the clock floor when loading persisted state from disk.
    pub fn advance_floor(&self, ms: u64, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        if (ms, seq) > *inner {
            *inner = (ms, seq);
        }
    }

    pub fn current(&self) -> (u64, u64) {
        *self.inner.lock().unwrap()
    }

    /// Generate a fresh local `(updated_ms, seq)` strictly greater than all
    /// previously issued or observed timestamps on this node.
    pub fn tick(&self) -> (u64, u64) {
        let phys = unix_ms();
        let mut inner = self.inner.lock().unwrap();
        let (last_ms, last_seq) = *inner;
        let next = if phys > last_ms { (phys, 0) } else { (last_ms, last_seq.saturating_add(1)) };
        *inner = next;
        next
    }

    /// Advance the clock upon receiving a remote `(remote_ms, remote_seq)`
    /// timestamp from a peer.
    pub fn observe(&self, remote_ms: u64, remote_seq: u64) -> (u64, u64) {
        let phys = unix_ms();
        let bounded_remote = if remote_ms > phys.saturating_add(MAX_SKEW_MS) {
            tracing::warn!("sync: clamping peer HLC timestamp skew ({} ms ahead)", remote_ms - phys);
            phys.saturating_add(MAX_SKEW_MS)
        } else {
            remote_ms
        };
        let mut inner = self.inner.lock().unwrap();
        let (last_ms, last_seq) = *inner;
        let max_ms = phys.max(last_ms).max(bounded_remote);
        let next_seq = if max_ms == last_ms && max_ms == bounded_remote {
            last_seq.max(remote_seq).saturating_add(1)
        } else if max_ms == last_ms {
            last_seq.saturating_add(1)
        } else if max_ms == bounded_remote {
            remote_seq.saturating_add(1)
        } else {
            0
        };
        let next = (max_ms, next_seq);
        *inner = next;
        next
    }

    /// Create a fresh `SyncMeta` stamped for a local mutation or tombstone.
    pub fn stamp(&self, node: &str, deleted: bool, local_rev: u64) -> SyncMeta {
        let (updated_ms, seq) = self.tick();
        SyncMeta { updated_ms, seq, node: node.to_string(), deleted, local_rev }
    }
}

/// Resolve a stable sync node identifier so two nodes without `--node-name`
/// never collide on `"local"`.
pub fn resolve_sync_node_id(data_dir: Option<&Path>, fleet_name: &str) -> String {
    let trimmed = fleet_name.trim().to_ascii_lowercase();
    if !trimmed.is_empty() && trimmed != "local" {
        return trimmed;
    }
    if let Some(dir) = data_dir {
        let path = dir.join("sync_node_id");
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let id = existing.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
        let generated = format!("local-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let _ = std::fs::create_dir_all(dir);
        let _ = crate::auth::write_private(&path, generated.as_bytes());
        return generated;
    }
    format!("local-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_monotonic_and_total_order() {
        let c1 = HlcClock::new(0, 0);
        let c2 = HlcClock::new(0, 0);

        // Monotonic ticks even within the same millisecond.
        let mut prev = c1.tick();
        for _ in 0..10 {
            let next = c1.tick();
            assert!(next > prev, "{next:?} <= {prev:?}");
            prev = next;
        }

        // Forward skew observation advances clock cleanly.
        let future_ms = unix_ms() + 5_000;
        let obs = c2.observe(future_ms, 7);
        assert_eq!(obs, (future_ms, 8));
        assert!(c2.tick() > obs);

        // Backward skew observation stays monotonic.
        let before = c2.current();
        let obs_old = c2.observe(1_000, 99);
        assert!(obs_old > before);

        // Total-order tie-breaking on (updated_ms, seq, node).
        let a = SyncMeta { updated_ms: 1000, seq: 2, node: "au".into(), deleted: false, local_rev: 1 };
        let b = SyncMeta { updated_ms: 1000, seq: 2, node: "eu".into(), deleted: false, local_rev: 2 };
        let c = SyncMeta { updated_ms: 1000, seq: 3, node: "au".into(), deleted: false, local_rev: 3 };
        let d = SyncMeta { updated_ms: 1001, seq: 0, node: "au".into(), deleted: true, local_rev: 4 };
        assert!(b.wins_over(&a) && !a.wins_over(&b));
        assert!(c.wins_over(&b));
        assert!(d.wins_over(&c));

        // Remote SyncMeta with excessive future timestamp is clamped to now_ms + MAX_SKEW_MS.
        let now_ms = 1_700_000_000_000;
        let mut rogue = SyncMeta { updated_ms: u64::MAX, seq: 0, node: "rogue".into(), deleted: false, local_rev: 0 };
        rogue.clamp_skew(now_ms);
        assert_eq!(rogue.updated_ms, now_ms + MAX_SKEW_MS);
    }
}
