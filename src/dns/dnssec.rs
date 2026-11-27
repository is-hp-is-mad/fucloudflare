//! Online DNSSEC signing (RFC 4034 / RFC 6605 ECDSAP256SHA256, Algorithm 13)
//! with Cloudflare-style minimal NSEC ("Black Lies", RFC 4470).

use super::wire::{canonical_name, canonical_rdata, rtype, RData, RR};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ALGO_ECDSAP256SHA256: u8 = 13;
pub const FLAGS_CSK: u16 = 257;
pub const PROTOCOL_DNSSEC: u8 = 3;
pub const DIGEST_SHA256: u8 = 2;
pub const DNSKEY_TTL: u32 = 3600;

/// Persistent DNSSEC configuration stored on a [`crate::store::Zone`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    pub enabled: bool,
    pub algorithm: u8,
    pub flags: u16,
    pub key_tag: u16,
    pub public_key_b64: String,
    pub private_key_pkcs8_b64: String,
    pub digest: String,
    pub ds_record: String,
}

impl DnssecConfig {
    /// Generate a fresh ECDSA P-256 (Algorithm 13) CSK for `zone`.
    pub fn generate(zone: &str) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| "failed to generate ECDSA P-256 key".to_string())?;
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| "failed to parse generated ECDSA P-256 key".to_string())?;
        let raw_pub = kp.public_key().as_ref();
        // Uncompressed SEC1 point: 0x04 || X(32) || Y(32); RFC 6605 uses X || Y (64 bytes).
        if raw_pub.len() != 65 || raw_pub[0] != 0x04 {
            return Err("unexpected P-256 public key format".into());
        }
        let pub64 = &raw_pub[1..];
        let mut dnskey_rdata = Vec::with_capacity(68);
        dnskey_rdata.extend_from_slice(&FLAGS_CSK.to_be_bytes());
        dnskey_rdata.push(PROTOCOL_DNSSEC);
        dnskey_rdata.push(ALGO_ECDSAP256SHA256);
        dnskey_rdata.extend_from_slice(pub64);

        let tag = compute_key_tag(&dnskey_rdata);
        let mut ds_input = canonical_name(zone);
        ds_input.extend_from_slice(&dnskey_rdata);
        let ds_hash = digest(&SHA256, &ds_input);
        let digest_hex: String = ds_hash.as_ref().iter().map(|b| format!("{b:02X}")).collect();
        let ds_record = format!("{zone}. {DNSKEY_TTL} IN DS {tag} {ALGO_ECDSAP256SHA256} {DIGEST_SHA256} {digest_hex}");

        Ok(DnssecConfig {
            enabled: true,
            algorithm: ALGO_ECDSAP256SHA256,
            flags: FLAGS_CSK,
            key_tag: tag,
            public_key_b64: b64_encode(pub64),
            private_key_pkcs8_b64: b64_encode(pkcs8.as_ref()),
            digest: digest_hex,
            ds_record,
        })
    }

    pub fn api_view(&self) -> serde_json::Value {
        serde_json::json!({
            "status": if self.enabled { "active" } else { "disabled" },
            "algorithm": self.algorithm.to_string(),
            "algorithm_name": "ECDSAP256SHA256",
            "flags": self.flags,
            "key_tag": self.key_tag,
            "digest_type": DIGEST_SHA256.to_string(),
            "digest_algorithm": "SHA256",
            "digest": self.digest,
            "ds": self.ds_record,
            "public_key": self.public_key_b64,
        })
    }
}

/// Ready-to-sign key held in a compiled [`crate::store::ZoneSnap`].
pub struct DnssecSigner {
    pub zone: String,
    pub key_tag: u16,
    pub public_key: Vec<u8>,
    keypair: EcdsaKeyPair,
}

impl DnssecSigner {
    pub fn from_config(zone: &str, cfg: &DnssecConfig) -> Option<Arc<Self>> {
        if !cfg.enabled {
            return None;
        }
        let pkcs8 = b64_decode(&cfg.private_key_pkcs8_b64)?;
        let public_key = b64_decode(&cfg.public_key_b64)?;
        let rng = SystemRandom::new();
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).ok()?;
        Some(Arc::new(DnssecSigner {
            zone: zone.to_string(),
            key_tag: cfg.key_tag,
            public_key,
            keypair,
        }))
    }

    pub fn dnskey_rr(&self) -> RR {
        RR {
            name: self.zone.clone(),
            ttl: DNSKEY_TTL,
            data: RData::Dnskey {
                flags: FLAGS_CSK,
                protocol: PROTOCOL_DNSSEC,
                algorithm: ALGO_ECDSAP256SHA256,
                public_key: self.public_key.clone(),
            },
        }
    }

    /// Sign a non-empty RRset sharing the same `(owner, rtype)`.
    pub fn sign_rrset(&self, rrs: &[RR], now: u32) -> Option<RR> {
        let first = rrs.first()?;
        let owner = first.name.to_ascii_lowercase();
        let type_covered = first.data.rtype();
        let orig_ttl = first.ttl;
        let labels = label_count(&owner);
        let sig_inc = now.saturating_sub(3600);
        let sig_exp = now.saturating_add(7 * 86400);

        let mut tbs = Vec::with_capacity(256);
        tbs.extend_from_slice(&type_covered.to_be_bytes());
        tbs.push(ALGO_ECDSAP256SHA256);
        tbs.push(labels);
        tbs.extend_from_slice(&orig_ttl.to_be_bytes());
        tbs.extend_from_slice(&sig_exp.to_be_bytes());
        tbs.extend_from_slice(&sig_inc.to_be_bytes());
        tbs.extend_from_slice(&self.key_tag.to_be_bytes());
        tbs.extend_from_slice(&canonical_name(&self.zone));

        let owner_wire = canonical_name(&owner);
        let mut rdatas: Vec<Vec<u8>> = rrs.iter().map(|rr| canonical_rdata(&rr.data)).collect();
        rdatas.sort();
        for rd in rdatas {
            tbs.extend_from_slice(&owner_wire);
            tbs.extend_from_slice(&type_covered.to_be_bytes());
            tbs.extend_from_slice(&1u16.to_be_bytes()); // IN
            tbs.extend_from_slice(&orig_ttl.to_be_bytes());
            tbs.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            tbs.extend_from_slice(&rd);
        }

        let sig = self.keypair.sign(&SystemRandom::new(), &tbs).ok()?;
        Some(RR {
            name: first.name.clone(),
            ttl: orig_ttl,
            data: RData::Rrsig {
                type_covered,
                algorithm: ALGO_ECDSAP256SHA256,
                labels,
                orig_ttl,
                sig_exp,
                sig_inc,
                key_tag: self.key_tag,
                signer: self.zone.clone(),
                signature: sig.as_ref().to_vec(),
            },
        })
    }

    /// Sign every distinct `(owner, rtype)` RRset in `section` (skipping existing RRSIGs).
    pub fn sign_section(&self, section: &mut Vec<RR>, now: u32) {
        let mut groups: BTreeMap<(String, u16), Vec<RR>> = BTreeMap::new();
        for rr in section.iter() {
            let rt = rr.data.rtype();
            if rt == rtype::RRSIG {
                continue;
            }
            groups.entry((rr.name.to_ascii_lowercase(), rt)).or_default().push(rr.clone());
        }
        for (_, rrs) in groups {
            if let Some(sig) = self.sign_rrset(&rrs, now) {
                section.push(sig);
            }
        }
    }

    /// Minimal covering NSEC ("Black Lies", RFC 4470) at `owner` with next name `\000.<owner>`.
    pub fn minimal_nsec(owner: &str, types: &[u16], ttl: u32) -> RR {
        let mut t = types.to_vec();
        t.push(rtype::RRSIG);
        t.push(rtype::NSEC);
        let next_domain = if owner.is_empty() || owner == "." {
            "\0".to_string()
        } else {
            format!("\0.{owner}")
        };
        RR {
            name: owner.to_string(),
            ttl,
            data: RData::Nsec { next_domain, types: t },
        }
    }
}

/// RFC 4034 Appendix B key tag calculation.
pub fn compute_key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        ac += if i & 1 == 1 { b as u32 } else { (b as u32) << 8 };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

fn label_count(name: &str) -> u8 {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return 0;
    }
    let mut count = 0u8;
    for (i, label) in trimmed.split('.').enumerate() {
        if i == 0 && label == "*" {
            continue;
        }
        count = count.saturating_add(1);
    }
    count
}

fn b64_encode(input: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |b: u8| -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for c in bytes.chunks(4) {
        let a = val(c[0])?;
        let b = val(c[1])?;
        out.push(((a << 2) | (b >> 4)) as u8);
        if c[2] != b'=' {
            let d = val(c[2])?;
            out.push((((b & 0xf) << 4) | (d >> 2)) as u8);
            if c[3] != b'=' {
                let e = val(c[3])?;
                out.push((((d & 0x3) << 6) | e) as u8);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    #[test]
    fn generates_and_verifies_ecdsa_p256_rrsig() {
        let cfg = DnssecConfig::generate("example.com").unwrap();
        assert_eq!(cfg.algorithm, 13);
        assert_eq!(cfg.flags, 257);
        assert_eq!(cfg.digest.len(), 64);
        assert!(cfg.ds_record.contains(" IN DS "));

        let signer = DnssecSigner::from_config("example.com", &cfg).unwrap();
        let a_rr = RR { name: "sub.example.com".into(), ttl: 60, data: RData::A("192.0.2.1".parse().unwrap()) };
        let sig_rr = signer.sign_rrset(&[a_rr.clone()], 1_700_000_000).unwrap();
        let RData::Rrsig { type_covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, signer: sname, signature } = sig_rr.data else {
            panic!("expected RRSIG");
        };
        assert_eq!((type_covered, algorithm, labels, orig_ttl, key_tag, sname.as_str()), (rtype::A, 13, 3, 60, cfg.key_tag, "example.com"));
        assert_eq!(signature.len(), 64);

        // Reconstruct TBS and cryptographically verify using uncompressed SEC1 public key
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&type_covered.to_be_bytes());
        tbs.push(algorithm);
        tbs.push(labels);
        tbs.extend_from_slice(&orig_ttl.to_be_bytes());
        tbs.extend_from_slice(&sig_exp.to_be_bytes());
        tbs.extend_from_slice(&sig_inc.to_be_bytes());
        tbs.extend_from_slice(&key_tag.to_be_bytes());
        tbs.extend_from_slice(&canonical_name(&sname));
        let rd = canonical_rdata(&a_rr.data);
        tbs.extend_from_slice(&canonical_name(&a_rr.name));
        tbs.extend_from_slice(&rtype::A.to_be_bytes());
        tbs.extend_from_slice(&1u16.to_be_bytes());
        tbs.extend_from_slice(&orig_ttl.to_be_bytes());
        tbs.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        tbs.extend_from_slice(&rd);

        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&signer.public_key);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &sec1).verify(&tbs, &signature).expect("valid ECDSA-P256 RRSIG");
    }
}
