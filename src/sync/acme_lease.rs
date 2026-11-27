//! Distributed ACME leader election and lease coordination across `peer` nodes.
//!
//! Only the peer holding an active `AcmeLease` (or elected as the lowest-named
//! healthy peer when no lease is active) performs ACME orders/renewals so peers
//! do not collide on CA rate limits or overwrite each other's challenge records.

use super::clock::SyncMeta;
use serde::{Deserialize, Serialize};

/// Default lease lifetime during an ACME tick/order (2 minutes).
pub const LEASE_TTL_MS: u64 = 120_000;
/// Failover grace past `expires_ms` before a non-preferred peer takes over.
pub const FAILOVER_GRACE_MS: u64 = 30_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeLease {
    pub holder: String,
    pub acquired_ms: u64,
    pub expires_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(default)]
    pub sync: SyncMeta,
}

impl AcmeLease {
    /// True if another peer currently holds an unexpired lease.
    pub fn held_by_other(&self, self_name: &str, now_ms: u64) -> bool {
        !self.holder.is_empty() && self.holder != self_name && self.expires_ms > now_ms
    }

    /// True if this node is allowed to attempt claiming the lease now.
    pub fn can_claim(&self, self_name: &str, preferred: &str, now_ms: u64) -> bool {
        if self.holder == self_name && self.expires_ms > now_ms {
            return true;
        }
        if self.held_by_other(self_name, now_ms) {
            return false;
        }
        if self_name == preferred {
            return true;
        }
        self.expires_ms > 0 && now_ms > self.expires_ms.saturating_add(FAILOVER_GRACE_MS)
    }
}

/// Deterministic preferred ACME leader: lexicographically smallest name among
/// `self_name` and currently online `peer` nodes.
pub fn preferred_leader(self_name: &str, online_peers: &[String]) -> String {
    let mut candidates: Vec<&str> = online_peers.iter().map(String::as_str).filter(|s| !s.is_empty()).collect();
    if !self_name.is_empty() {
        candidates.push(self_name);
    }
    candidates.sort();
    candidates.dedup();
    candidates.first().copied().unwrap_or(self_name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_election_and_lease_rules() {
        assert_eq!(preferred_leader("eu", &["sgp".into(), "au".into(), "my".into()]), "au");
        assert_eq!(preferred_leader("eu", &["sgp".into(), "my".into()]), "eu");

        let empty = AcmeLease::default();
        assert!(empty.can_claim("au", "au", 10_000));
        assert!(!empty.can_claim("eu", "au", 10_000));

        let active_au = AcmeLease {
            holder: "au".into(),
            acquired_ms: 10_000,
            expires_ms: 130_000,
            pack_id: Some("p1".into()),
            sync: SyncMeta::default(),
        };
        assert!(active_au.held_by_other("eu", 50_000));
        assert!(!active_au.can_claim("eu", "au", 50_000));
        assert!(!active_au.can_claim("eu", "au", 140_000), "within 30s failover grace");
        assert!(active_au.can_claim("eu", "au", 165_000), "past failover grace");
        assert!(active_au.can_claim("eu", "eu", 135_000), "au went offline so eu became preferred");
    }
}
