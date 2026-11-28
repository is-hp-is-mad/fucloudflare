//! A zone's private origin CA: a certificate authority of the zone's own
//! that signs certificates for its origin servers (like Cloudflare's Origin
//! CA), so that an origin can serve TLS without a public CA.
//!
//! `POST /zones/{id}/origin_ca` makes the CA (one per zone: a second POST is
//! refused; rotating it is a DELETE and a new POST, after which certificates
//! signed by the old one no longer chain to it), `GET` answers its
//! certificate, `POST /zones/{id}/origin_ca/sign` signs a certificate for
//! names of the zone and answers it with its new private key. Nothing of a
//! signed certificate is kept: its key is shown once.
//!
//! The CA's private key is kept with the zone (like the DKIM key,
//! crate::dkim), so every node of the fleet can sign; the API never answers
//! it. The CA certificate is name-constrained to the zone, so even its key
//! cannot vouch for names of anybody else to a client that checks name
//! constraints (rustls / webpki do), and it signs server certificates only.

use crate::store::{Store, StoreError, Zone};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

/// How long the CA is valid. Longer than the longest certificate it signs,
/// so that one signed in its first years does not outlive it.
const CA_DAYS: u64 = 20 * 365;
/// The validity a signed certificate may ask for, in days (Cloudflare's
/// Origin CA goes up to 15 years too).
pub const MAX_DAYS: u32 = 5475;
/// At most so many names in one certificate.
pub const MAX_NAMES: usize = 50;
/// Certificates start this much before they are made, for clocks running late.
const BACKDATE_SECS: u64 = 3600;

/// What a zone keeps of its origin CA.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct OriginCa {
    /// The CA certificate (PEM).
    pub certificate: String,
    /// Its key (PKCS#8 PEM); never answered by the API.
    pub private_key: String,
    /// The subject's common name, from which the issuer of what it signs is
    /// written again (rcgen here is built without a certificate parser).
    pub common_name: String,
    pub created_on: String,
}

/// Written out by hand so that the key never lands in a log line.
impl std::fmt::Debug for OriginCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginCa")
            .field("common_name", &self.common_name)
            .field("created_on", &self.created_on)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

fn invalid(m: impl Into<String>) -> StoreError {
    StoreError::Invalid(m.into())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Valid from `from` until `until` (unix seconds). rcgen takes a time type
/// of its own, reached from a date it makes rather than named here.
fn set_validity(params: &mut CertificateParams, from: u64, until: u64) {
    params.not_before = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(from);
    params.not_after = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(until);
}

/// What the CA certificate says of its subject and its powers. The same
/// parameters name the issuer of what it signs (of them only the subject,
/// the key identifier method and the key usages matter there).
fn ca_params(common_name: &str, zone: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "fucf");
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    // it signs end entities only, never a CA below it
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params.name_constraints = Some(NameConstraints { permitted_subtrees: vec![GeneralSubtree::DnsName(zone.to_string())], excluded_subtrees: Vec::new() });
    params
}

impl OriginCa {
    /// A new CA for `zone`, with a new key.
    pub fn generate(zone: &str) -> Result<OriginCa, String> {
        let common_name = format!("fucf origin CA for {zone}");
        let key = KeyPair::generate().map_err(|e| format!("cannot make a key: {e}"))?;
        let mut params = ca_params(&common_name, zone);
        let now = now_secs();
        set_validity(&mut params, now.saturating_sub(BACKDATE_SECS), now + CA_DAYS * 86_400);
        let cert = params.self_signed(&key).map_err(|e| format!("cannot make the CA certificate: {e}"))?;
        Ok(OriginCa { certificate: cert.pem(), private_key: key.serialize_pem(), common_name, created_on: crate::store::now() })
    }

    /// Until when the CA certificate is valid (unix seconds).
    pub fn not_after(&self) -> Option<i64> {
        crate::edge::tls::pem_validity(&self.certificate).map(|(_, until)| until)
    }

    /// Sign a server certificate for `names` (already checked by
    /// [`check_names`]), valid for `days` from now, with a new key.
    pub fn sign(&self, zone: &str, names: &[String], days: u32) -> Result<Signed, StoreError> {
        let first = names.first().ok_or_else(|| invalid("a certificate needs a name"))?;
        let now = now_secs();
        let until = now + u64::from(days) * 86_400;
        let outlives = match (self.not_after(), i64::try_from(until)) {
            (Some(ca_until), Ok(until)) => until > ca_until,
            _ => true,
        };
        if outlives {
            return Err(invalid("the certificate would outlive the origin CA: ask for fewer days, or make a new CA"));
        }
        let ca_key = KeyPair::from_pem(&self.private_key).map_err(|_| invalid("the stored origin CA key cannot be read: make a new CA"))?;
        let issuer = Issuer::new(ca_params(&self.common_name, zone), ca_key);
        let mut params = CertificateParams::new(names.to_vec()).map_err(|e| invalid(format!("invalid name: {e}")))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, first.as_str());
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // for the origin's server side only: never a client certificate (crate::edge::mtls)
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params, now.saturating_sub(BACKDATE_SECS), until);
        let key = KeyPair::generate().map_err(|e| invalid(format!("cannot make a key: {e}")))?;
        let cert = params.signed_by(&key, &issuer).map_err(|e| invalid(format!("cannot sign: {e}")))?;
        Ok(Signed { certificate: cert.pem(), private_key: key.serialize_pem(), names: names.to_vec(), not_after: until as i64 })
    }
}

/// A certificate just signed, and its key (kept nowhere).
pub struct Signed {
    pub certificate: String,
    pub private_key: String,
    pub names: Vec<String>,
    pub not_after: i64,
}

fn rfc3339(secs: i64) -> Value {
    chrono::DateTime::from_timestamp(secs, 0).map_or(Value::Null, |t| json!(t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)))
}

/// The names a certificate of `zone` may carry: the zone, or names below
/// it, each at most once, and a wildcard only as the whole first label
/// (`*.example.com`). Answers them lowercase, in the order given.
pub fn check_names(zone: &str, names: &[String]) -> Result<Vec<String>, StoreError> {
    if names.is_empty() || names.len() > MAX_NAMES {
        return Err(invalid(format!("hostnames holds 1 to {MAX_NAMES} names")));
    }
    let mut out: Vec<String> = Vec::new();
    for raw in names {
        let name = crate::dns::wire::normalize_name(raw).map_err(|e| invalid(format!("hostnames: {e}")))?;
        let base = name.strip_prefix("*.").unwrap_or(&name);
        if base.contains(['*', '_']) || name.parse::<std::net::IpAddr>().is_ok() {
            return Err(invalid(format!("hostnames: '{name}' is not a host name (a wildcard is only '*.' in front)")));
        }
        if !(base == zone || base.ends_with(&format!(".{zone}"))) {
            return Err(invalid(format!("hostnames: '{name}' is not {zone} or a name below it")));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

/// The body of `POST /zones/{id}/origin_ca/sign` (Cloudflare's Origin CA
/// names for the same things are taken too).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    #[serde(alias = "names")]
    pub hostnames: Vec<String>,
    #[serde(alias = "requested_validity")]
    pub days: u32,
}

/// What the API shows of a zone's origin CA: never its key.
pub fn view(zone: &Zone) -> Value {
    match &zone.origin_ca {
        None => json!({ "present": false }),
        Some(ca) => json!({
            "present": true,
            "certificate": ca.certificate,
            "common_name": ca.common_name,
            "created_on": ca.created_on,
            "expires_on": ca.not_after().map_or(Value::Null, rfc3339),
        }),
    }
}

/// Make the zone's origin CA; there may be only one.
pub async fn create(store: &Store, zone_id: &str) -> Result<Zone, StoreError> {
    store
        .set_origin_ca_async(zone_id, |zone| {
            if zone.origin_ca.is_some() {
                return Err(StoreError::Conflict("the zone already has an origin CA: delete it first to make a new one".into()));
            }
            OriginCa::generate(&zone.name).map(Some).map_err(StoreError::Invalid)
        })
        .await
}

/// Remove the zone's origin CA (not found if it has none).
pub async fn remove(store: &Store, zone_id: &str) -> Result<Zone, StoreError> {
    store
        .set_origin_ca_async(zone_id, |zone| if zone.origin_ca.is_none() { Err(StoreError::NotFound) } else { Ok(None) })
        .await
}

/// Sign a certificate with the zone's origin CA, as the API answers it.
pub fn sign(zone: &Zone, request: &SignRequest) -> Result<Value, StoreError> {
    let ca = zone.origin_ca.as_ref().ok_or_else(|| invalid("the zone has no origin CA yet: make one first"))?;
    if !(1..=MAX_DAYS).contains(&request.days) {
        return Err(invalid(format!("days is 1 to {MAX_DAYS}")));
    }
    let names = check_names(&zone.name, &request.hostnames)?;
    let signed = ca.sign(&zone.name, &names, request.days)?;
    Ok(json!({
        "certificate": signed.certificate,
        "private_key": signed.private_key,
        "ca_certificate": ca.certificate,
        "hostnames": signed.names,
        "requested_validity": request.days,
        "expires_on": rfc3339(signed.not_after),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn names(of: &[&str]) -> Vec<String> {
        of.iter().map(|n| n.to_string()).collect()
    }

    /// Does `cert` chain to `ca` for `name`, as rustls checks a server?
    fn verifies(ca: &str, cert: &str, name: &str) -> Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(ca.as_bytes()).unwrap()).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(std::sync::Arc::new(roots), provider).build().unwrap();
        let leaf = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        verifier.verify_server_cert(&leaf, &[], &ServerName::try_from(name.to_string()).unwrap(), &[], UnixTime::now()).map(|_| ())
    }

    #[test]
    fn a_new_ca_is_a_ca_certificate_with_its_key_and_lasts_longer_than_what_it_signs() {
        let ca = OriginCa::generate("example.com").unwrap();
        assert!(ca.certificate.contains("BEGIN CERTIFICATE") && ca.private_key.contains("PRIVATE KEY"));
        assert_eq!(ca.common_name, "fucf origin CA for example.com");
        let until = ca.not_after().unwrap();
        assert!(until > now_secs() as i64 + i64::from(MAX_DAYS) * 86_400, "{until}");
        // the key is the certificate's, and parses as rustls takes keys
        assert!(crate::edge::tls::parse_cert(&ca.certificate, &ca.private_key).is_ok());
        // a second CA has a key of its own
        assert_ne!(OriginCa::generate("example.com").unwrap().private_key, ca.private_key);
        assert!(!format!("{ca:?}").contains("PRIVATE"), "the key stays out of logs");
    }

    #[test]
    fn a_signed_certificate_chains_to_its_ca_for_its_names_only() {
        let ca = OriginCa::generate("example.com").unwrap();
        let signed = ca.sign("example.com", &names(&["example.com", "*.example.com", "origin.example.com"]), 30).unwrap();
        assert!(signed.private_key.contains("PRIVATE KEY") && signed.private_key != ca.private_key);
        for name in ["example.com", "www.example.com", "origin.example.com"] {
            verifies(&ca.certificate, &signed.certificate, name).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        for name in ["example.net", "a.b.example.com", "example.com.example.net"] {
            assert!(verifies(&ca.certificate, &signed.certificate, name).is_err(), "{name}");
        }
        // the key goes with the certificate
        assert!(crate::edge::tls::parse_cert(&signed.certificate, &signed.private_key).is_ok());
        let (from, until) = crate::edge::tls::pem_validity(&signed.certificate).unwrap();
        let now = now_secs() as i64;
        assert!(from <= now && (until - now - 30 * 86_400).abs() < 60, "{from} {until}");
        // a CA made afresh for the same zone does not vouch for it
        let other = OriginCa::generate("example.com").unwrap();
        assert!(verifies(&other.certificate, &signed.certificate, "example.com").is_err());
    }

    #[test]
    fn the_ca_cannot_vouch_for_names_outside_its_zone_even_if_asked_to_sign_them() {
        // check_names keeps such names out; the name constraints hold should one get through
        let ca = OriginCa::generate("example.com").unwrap();
        let signed = ca.sign("example.com", &names(&["example.net"]), 30).unwrap();
        assert!(verifies(&ca.certificate, &signed.certificate, "example.net").is_err());
    }

    #[test]
    fn names_must_be_the_zone_or_below_it() {
        assert_eq!(
            check_names("example.com", &names(&["Example.COM.", "www.example.com", "*.example.com", "www.example.com"])).unwrap(),
            names(&["example.com", "www.example.com", "*.example.com"])
        );
        assert_eq!(check_names("example.com", &names(&["*.a.example.com"])).unwrap(), names(&["*.a.example.com"]));
        for bad in [
            vec![],
            names(&["example.net"]),
            names(&["notexample.com"]),
            names(&["example.com.example.net"]),
            names(&["com"]),
            names(&["*"]),
            names(&["*.com"]),
            names(&["a.*.example.com"]),
            names(&["**.example.com"]),
            names(&["_dmarc.example.com"]),
            names(&["192.0.2.1"]),
            names(&[""]),
            names(&["exa mple.example.com"]),
            names(&["www.example.com", "example.org"]),
            (0..=MAX_NAMES).map(|i| format!("n{i}.example.com")).collect(),
        ] {
            assert!(check_names("example.com", &bad).is_err(), "{bad:?}");
        }
        assert_eq!(check_names("example.com", &(0..MAX_NAMES).map(|i| format!("n{i}.example.com")).collect::<Vec<_>>()).unwrap().len(), MAX_NAMES);
    }

    #[test]
    fn days_are_bounded_and_a_zone_without_a_ca_cannot_sign() {
        let store = crate::store::testutil::temp_store();
        let mut zone = store.create_zone("example.com").unwrap();
        let ask = |days: u32| SignRequest { hostnames: names(&["example.com"]), days };
        assert!(matches!(sign(&zone, &ask(30)), Err(StoreError::Invalid(_))), "no CA yet");
        zone.origin_ca = Some(OriginCa::generate("example.com").unwrap());
        for days in [0, MAX_DAYS + 1, u32::MAX] {
            assert!(sign(&zone, &ask(days)).is_err(), "{days}");
        }
        for days in [1, MAX_DAYS] {
            let v = sign(&zone, &ask(days)).unwrap_or_else(|e| panic!("{days}: {e:?}"));
            assert_eq!((v["hostnames"].clone(), v["requested_validity"].clone()), (json!(["example.com"]), json!(days)));
            assert_eq!(v["ca_certificate"], json!(zone.origin_ca.as_ref().unwrap().certificate));
            assert!(v["expires_on"].as_str().is_some_and(|t| t.ends_with('Z')), "{v}");
        }
        // a CA near its end signs nothing that would outlive it
        let mut old = OriginCa::generate("example.com").unwrap();
        let key = KeyPair::from_pem(&old.private_key).unwrap();
        let mut params = ca_params(&old.common_name, "example.com");
        set_validity(&mut params, now_secs() - 86_400, now_secs() + 10 * 86_400);
        old.certificate = params.self_signed(&key).unwrap().pem();
        assert!(old.sign("example.com", &names(&["example.com"]), 9).is_ok());
        assert!(old.sign("example.com", &names(&["example.com"]), 11).is_err());
        assert!(old.sign("example.com", &[], 1).is_err());
    }

    #[test]
    fn a_sign_request_takes_either_name_for_each_field_and_nothing_else() {
        let a: SignRequest = serde_json::from_value(json!({ "hostnames": ["example.com"], "days": 7 })).unwrap();
        let b: SignRequest = serde_json::from_value(json!({ "names": ["example.com"], "requested_validity": 7 })).unwrap();
        assert_eq!((a.hostnames, a.days), (b.hostnames, b.days));
        for bad in [
            json!({ "hostnames": ["example.com"] }),
            json!({ "days": 7 }),
            json!({ "hostnames": ["example.com"], "days": -1 }),
            json!({ "hostnames": "example.com", "days": 7 }),
            json!({ "hostnames": ["example.com"], "days": 7, "private_key": "x" }),
        ] {
            assert!(serde_json::from_value::<SignRequest>(bad.clone()).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_zone_has_one_ca_whose_key_its_view_never_shows() {
        let store = crate::store::testutil::temp_store();
        let zone = store.create_zone("example.com").unwrap();
        assert_eq!(view(&zone), json!({ "present": false }));
        let made = create(&store, &zone.id).await.unwrap();
        let ca = made.origin_ca.clone().unwrap();
        assert!(matches!(create(&store, &zone.id).await, Err(StoreError::Conflict(_))), "one CA per zone");
        assert_eq!(store.get_zone(&zone.id).unwrap().origin_ca, Some(ca.clone()), "the refused second one changed nothing");
        let shown = view(&store.get_zone(&zone.id).unwrap());
        assert_eq!((shown["present"].clone(), shown["certificate"].clone()), (json!(true), json!(ca.certificate)));
        assert!(!shown.to_string().contains("PRIVATE KEY"), "{shown}");
        remove(&store, &zone.id).await.unwrap();
        assert!(store.get_zone(&zone.id).unwrap().origin_ca.is_none());
        assert!(matches!(remove(&store, &zone.id).await, Err(StoreError::NotFound)));
        assert!(matches!(create(&store, "0123456789abcdef0123456789abcdef").await, Err(StoreError::ZoneNotFound)));
        let again = create(&store, &zone.id).await.unwrap().origin_ca.unwrap();
        assert_ne!(again.private_key, ca.private_key, "a new CA after the old one is gone");
    }
}
