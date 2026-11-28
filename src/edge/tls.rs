//! TLS for the edge: SNI-based certificate selection (uploaded and managed
//! certificates, falling back to self-signed ones), ACME TLS-ALPN-01
//! challenge answers and client configs for origin pulls.

use crate::store::Store;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as provider, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

/// Certificates other tools keep on disk (`--tls-cert-dir`), see [`super::certdir`].
static DISK_CERTS: OnceLock<Arc<super::certdir::DiskCerts>> = OnceLock::new();
/// The name to answer for when a client sends no server name (`--tls-default-sni`),
/// e.g. the node's IP address for clients that connect by address.
static DEFAULT_SNI: OnceLock<String> = OnceLock::new();

pub fn set_disk_certs(certs: Arc<super::certdir::DiskCerts>) {
    let _ = DISK_CERTS.set(certs);
}

pub fn set_default_sni(name: &str) {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if !name.is_empty() {
        let _ = DEFAULT_SNI.set(name);
    }
}

/// A certificate for `host` from the disk, if there is one.
pub fn disk_cert(host: &str) -> Option<Arc<CertifiedKey>> {
    DISK_CERTS.get()?.get(host)
}

/// `(not before, not after)` of the certificate on disk that would be used for `host`.
pub fn disk_cert_validity(host: &str) -> Option<(i64, i64)> {
    DISK_CERTS.get()?.validity(host)
}

/// Load the certificate directories again now (after writing one).
pub fn rescan_disk_certs() {
    if let Some(certs) = DISK_CERTS.get() {
        certs.rescan();
    }
}

/// Parse and sanity-check a PEM certificate chain and its private key.
pub fn parse_cert(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("invalid certificate PEM: {e}"))?;
    if chain.is_empty() {
        return Err("certificate PEM contains no certificate".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| format!("invalid private key PEM: {e}"))?;
    let key = provider::sign::any_supported_type(&key).map_err(|e| format!("unsupported private key: {e}"))?;
    let ck = CertifiedKey::new(chain, key);
    ck.keys_match().map_err(|e| format!("private key does not match the certificate: {e}"))?;
    Ok(Arc::new(ck))
}

/// ALPN protocol of a CA validating a TLS-ALPN-01 challenge (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// The self-signed certificate that answers a TLS-ALPN-01 challenge for
/// `host`: it carries the digest of the key authorization.
pub fn acme_challenge_cert(host: &str, digest: &[u8; 32]) -> Option<Arc<CertifiedKey>> {
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).ok()?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let key = rcgen::KeyPair::generate().ok()?;
    let cert = params.self_signed(&key).ok()?;
    // Assembled by hand: the usual sanity check refuses the certificate over
    // its (critical, and unknown to it) acmeIdentifier extension.
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()));
    let key = provider::sign::any_supported_type(&key).ok()?;
    Some(Arc::new(CertifiedKey::new(vec![cert.der().clone()], key)))
}

/// One DER element: `(tag, content, what follows it)`.
pub fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |acc, b| acc << 8 | *b as usize), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// A DER `UTCTime` / `GeneralizedTime` as Unix seconds.
fn der_time(tag: u8, value: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(value).ok()?;
    let full = match tag {
        0x17 => {
            let year: u32 = text.get(..2)?.parse().ok()?;
            format!("{}{text}", if year >= 50 { 19 } else { 20 })
        }
        0x18 => text.to_string(),
        _ => return None,
    };
    chrono::NaiveDateTime::parse_from_str(&full, "%Y%m%d%H%M%SZ").ok().map(|t| t.and_utc().timestamp())
}

/// `(not before, not after)` of a DER certificate, in Unix seconds.
pub fn cert_validity(cert: &[u8]) -> Option<(i64, i64)> {
    let (_, cert, _) = der(cert)?;
    let (_, tbs, _) = der(cert)?;
    let mut rest = tbs;
    let (tag, _, after) = der(rest)?;
    if tag == 0xA0 {
        rest = after; // the optional version
    }
    for _ in 0..3 {
        rest = der(rest)?.2; // serial number, signature algorithm, issuer
    }
    let (_, validity, _) = der(rest)?;
    let (tag_from, from, more) = der(validity)?;
    let (tag_until, until, _) = der(more)?;
    Some((der_time(tag_from, from)?, der_time(tag_until, until)?))
}

/// Validity of the first (leaf) certificate of a PEM chain.
pub fn pem_validity(cert_pem: &str) -> Option<(i64, i64)> {
    let leaf = CertificateDer::pem_slice_iter(cert_pem.as_bytes()).next()?.ok()?;
    cert_validity(&leaf)
}

fn self_signed(name: &str) -> Option<Arc<CertifiedKey>> {
    let names = if name.starts_with("*.") || !name.contains('.') {
        vec![name.to_string()]
    } else {
        vec![name.to_string(), format!("*.{name}")]
    };
    let generated = rcgen::generate_simple_self_signed(names).ok()?;
    parse_cert(&generated.cert.pem(), &generated.signing_key.serialize_pem()).ok()
}

/// Picks the certificate for each TLS handshake.
pub struct CertResolver {
    store: Arc<Store>,
    /// Self-signed certificates per hosted zone, pre-warmed off Tokio workers.
    generated: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    default: Arc<CertifiedKey>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertResolver")
    }
}

impl CertResolver {
    /// Pre-warm a self-signed zone fallback certificate on a blocking thread
    /// before `into_stream` so `ResolvesServerCert::resolve` never runs `rcgen`
    /// on a Tokio worker thread.
    pub async fn warm_sni(self: &Arc<Self>, sni: &str) {
        let sni = sni.to_ascii_lowercase();
        let snap = self.store.snapshot();
        let wildcard = sni.split_once('.').map(|(_, parent)| format!("*.{parent}"));
        if snap.certs.contains_key(&sni) || wildcard.as_deref().is_some_and(|w| snap.certs.contains_key(w)) {
            return;
        }
        let Some(zone) = snap.find_zone(&sni) else { return };
        let zone_name = zone.zone.name.clone();
        if self.generated.read().unwrap().contains_key(&zone_name) {
            return;
        }
        let this = self.clone();
        let _ = tokio::task::spawn_blocking(move || this.ensure_zone_cert_blocking(&zone_name)).await;
    }

    pub fn ensure_zone_cert_blocking(&self, zone_name: &str) {
        if self.generated.read().unwrap().contains_key(zone_name) {
            return;
        }
        if let Some(cert) = self_signed(zone_name) {
            self.generated.write().unwrap().entry(zone_name.to_string()).or_insert(cert);
        }
    }

    pub fn warm_all_zones_blocking(&self) {
        let snap = self.store.snapshot();
        let missing: Vec<String> = {
            let guard = self.generated.read().unwrap();
            snap.zones.keys().filter(|name| !guard.contains_key(*name)).cloned().collect()
        };
        for name in missing {
            self.ensure_zone_cert_blocking(&name);
        }
    }

    /// Background watcher that pre-warms zone fallback certs whenever `Store` updates.
    pub async fn watch(self: Arc<Self>) {
        let mut changes = self.store.subscribe();
        loop {
            let this = self.clone();
            let _ = tokio::task::spawn_blocking(move || this.warm_all_zones_blocking()).await;
            if changes.changed().await.is_err() {
                return;
            }
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name().map(str::to_ascii_lowercase);
        if hello.alpn().is_some_and(|mut offered| offered.any(|p| p == ACME_TLS_ALPN)) {
            // A CA validating a challenge: only the challenge certificate will do.
            let sni = sni?;
            return self.store.snapshot().acme_tls.get(&sni).cloned().or_else(|| crate::site_acme::tls_alpn(&sni));
        }
        let Some(sni) = sni.or_else(|| DEFAULT_SNI.get().cloned()) else { return Some(self.default.clone()) };
        let snap = self.store.snapshot();
        let wildcard = sni.split_once('.').map(|(_, parent)| format!("*.{parent}"));
        if let Some(c) = snap.certs.get(&sni).or_else(|| snap.certs.get(wildcard.as_deref()?)) {
            return Some(c.clone());
        }
        // what other tools issued, on disk
        if let Some(c) = disk_cert(&sni) {
            return Some(c);
        }
        // Only mint certificates for zones we host (bounded by configuration).
        let Some(zone) = snap.find_zone(&sni) else { return Some(self.default.clone()) };
        if let Some(c) = self.generated.read().unwrap().get(&zone.zone.name) {
            return Some(c.clone());
        }
        // Fallback only if resolve() was called before warm_sni (e.g., direct HTTP/3 test).
        let cert = self_signed(&zone.zone.name)?;
        let stored = self.generated.write().unwrap().entry(zone.zone.name.clone()).or_insert(cert).clone();
        Some(stored)
    }
}

fn crypto() -> Arc<CryptoProvider> {
    Arc::new(provider::default_provider())
}

fn base_server_config(store: Arc<Store>) -> anyhow::Result<(ServerConfig, Arc<CertResolver>)> {
    let default = self_signed("fucf.invalid").ok_or_else(|| anyhow::anyhow!("cannot generate default certificate"))?;
    let resolver = Arc::new(CertResolver { store, generated: RwLock::default(), default });
    let cfg = ServerConfig::builder_with_provider(crypto())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    Ok((cfg, resolver))
}

/// TLS config and resolver for the TCP listener (HTTP/2 and HTTP/1.1).
pub fn server_config_with_resolver(store: Arc<Store>) -> anyhow::Result<(Arc<ServerConfig>, Arc<CertResolver>)> {
    let (mut cfg, resolver) = base_server_config(store)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((Arc::new(cfg), resolver))
}

/// TLS config for the TCP listener (HTTP/2 and HTTP/1.1).
pub fn server_config(store: Arc<Store>) -> anyhow::Result<Arc<ServerConfig>> {
    Ok(server_config_with_resolver(store)?.0)
}

/// TLS config for the QUIC listener (HTTP/3).
pub fn quic_server_config(store: Arc<Store>) -> anyhow::Result<Arc<ServerConfig>> {
    let (mut cfg, resolver) = base_server_config(store)?;
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(resolver.watch());
    }
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(cfg))
}

/// Accepts any origin certificate (Cloudflare's "Full" mode): the link is
/// encrypted but the origin is not authenticated.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Client config for origin connections; `verify` selects strict mode.
pub fn client_config(verify: bool) -> anyhow::Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(crypto()).with_safe_default_protocol_versions()?;
    let cfg = if verify {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(crypto()))).with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_parsing() {
        let a = rcgen::generate_simple_self_signed(vec!["a.test".to_string()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["b.test".to_string()]).unwrap();
        assert!(parse_cert(&a.cert.pem(), &a.signing_key.serialize_pem()).is_ok());
        assert!(parse_cert(&a.cert.pem(), &b.signing_key.serialize_pem()).is_err());
        assert!(parse_cert("garbage", &a.signing_key.serialize_pem()).is_err());
        assert!(self_signed("example.com").is_some());
    }

    #[test]
    fn reads_certificate_validity() {
        let mut params = rcgen::CertificateParams::new(vec!["a.test".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 3, 1);
        params.not_after = rcgen::date_time_ymd(2051, 6, 30);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let day = |y, m, d| chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp();
        // 2026 is written as UTCTime, 2051 as GeneralizedTime
        assert_eq!(pem_validity(&cert.pem()), Some((day(2026, 3, 1), day(2051, 6, 30))));
        assert_eq!(pem_validity("garbage"), None);
        assert_eq!(cert_validity(&[0x30, 0x03, 0x02, 0x01]), None);

        // the challenge certificate carries the digest in the acmeIdentifier extension
        let ck = acme_challenge_cert("a.test", &[7u8; 32]).unwrap();
        let der = ck.cert[0].as_ref();
        assert!(der.windows(8).any(|w| w == [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f]));
        assert!(der.windows(32).any(|w| w == [7u8; 32]));
    }
}
