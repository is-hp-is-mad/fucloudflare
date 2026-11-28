//! Visitors' client certificates (mutual TLS, Cloudflare's "mTLS" for
//! visitors).
//!
//! With `--mtls-ca` the visitor listeners (HTTPS over TCP and HTTP/3) ask
//! every visitor for a client certificate issued by that CA, and let in the
//! ones that bring none (see crate::edge::tls::visitor_verifier): rustls
//! picks the certificate verifier for the whole listener, before it knows
//! which zone the visitor wants, so whether a certificate is needed is
//! decided here, per request, by the zone's `mtls` setting. Rules see the
//! outcome as `cf.tls_client_auth.cert_verified`.
//!
//! What "verified" means here is narrow on purpose: the TLS session the
//! request came on carries a certificate the verifier accepted. Plain HTTP,
//! the HTTP/3 front (it hands over the request, not the certificate) and
//! anything else that cannot tell count as not verified, so a zone with
//! `mtls: on` is refused on every such path rather than let through.

use super::{Edge, EdgeError, TlsInfo};

/// The value of the zone setting `mtls` that asks for a verified certificate.
pub const ON: &str = "on";

/// Did the request come over a TLS session whose client certificate the
/// edge verified?
pub fn verified(extensions: &hyper::http::Extensions) -> bool {
    extensions.get::<TlsInfo>().is_some_and(|tls| tls.client_cert_verified)
}

/// Is a request for a host of a zone with this `mtls` setting refused?
/// `panel`: the host is the management panel's, which is the fleet's and
/// not the zone's (it has a sign-in of its own), so it is never refused here:
/// a zone owner turning `mtls` on cannot lock the administrators out of it.
fn refused(mtls: Option<&str>, panel: bool, verified: bool) -> bool {
    mtls == Some(ON) && !panel && !verified
}

/// Refuse (403) a request for a host of a zone that takes only visitors with
/// a verified client certificate, when this one came without.
pub fn check(edge: &Edge, host: &str, extensions: &hyper::http::Extensions) -> Result<(), EdgeError> {
    let snap = edge.store.snapshot();
    // any name of the zone, served or not: the zone's setting covers all of them
    let mtls = snap.find_zone(host).map(|zone| zone.zone.settings.mtls.as_str());
    let panel = edge.panel.get().is_some_and(|(panel_host, _)| panel_host == host);
    if refused(mtls, panel, verified(extensions)) {
        return Err(EdgeError::new(403, "Forbidden", "this site takes only visitors with a valid client certificate"));
    }
    Ok(())
}

/// Certificates for tests, made when the test runs (nothing to leak):
/// a CA, and client certificates it issues.
#[cfg(test)]
pub mod test_certs {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// A CA that issues client certificates: its PEM certificate and what signs with it.
    pub struct Ca {
        pub pem: String,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    pub fn ca(name: &str) -> Ca {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Ca { pem, issuer: rcgen::Issuer::new(params, key) }
    }

    /// A certificate `ca` issues, for `usage`, with its key, as rustls takes them.
    pub fn issue(ca: &Ca, usage: rcgen::ExtendedKeyUsagePurpose) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let mut params = rcgen::CertificateParams::new(vec!["visitor.example.com".to_string()]).unwrap();
        params.extended_key_usages = vec![usage];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca.issuer).unwrap();
        (vec![cert.der().clone()], PrivatePkcs8KeyDer::from(key.serialize_der()).into())
    }

    /// A client certificate `ca` issues.
    pub fn client(ca: &Ca) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        issue(ca, rcgen::ExtendedKeyUsagePurpose::ClientAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, UnixTime};

    fn tls(client_cert_verified: bool) -> TlsInfo {
        TlsInfo { version: "TLSv1.3", sni: true, kex: String::new(), ja4: String::new(), client_cert_verified }
    }

    #[test]
    fn only_a_session_with_a_verified_certificate_counts_as_verified() {
        let mut ext = hyper::http::Extensions::new();
        assert!(!verified(&ext), "plain HTTP");
        ext.insert(tls(false));
        assert!(!verified(&ext), "TLS without a certificate");
        ext.insert(tls(true));
        assert!(verified(&ext));
    }

    #[test]
    fn a_zone_with_mtls_on_refuses_whoever_brings_no_verified_certificate() {
        assert!(refused(Some("on"), false, false));
        assert!(!refused(Some("on"), false, true));
        for setting in [Some("off"), None, Some(""), Some("ON")] {
            assert!(!refused(setting, false, false), "{setting:?}");
        }
        // the panel is the fleet's, not the zone's
        assert!(!refused(Some("on"), true, false));
    }

    #[test]
    fn the_verifier_lets_in_no_certificate_and_a_valid_one_and_refuses_any_other() {
        let ca = test_certs::ca("fucf test client CA");
        let verifier = crate::edge::tls::visitor_verifier(&ca.pem).unwrap();
        assert!(verifier.offer_client_auth() && !verifier.client_auth_mandatory(), "asked for, not required");
        let check = |chain: &[CertificateDer<'static>]| verifier.verify_client_cert(&chain[0], &chain[1..], UnixTime::now()).is_ok();
        assert!(check(&test_certs::client(&ca).0));
        // issued by another CA, or self-signed
        assert!(!check(&test_certs::client(&test_certs::ca("another CA")).0));
        let alone = rcgen::generate_simple_self_signed(vec!["visitor.example.com".to_string()]).unwrap();
        assert!(!check(&[alone.cert.der().clone()]));
        // the CA's, but made for servers (as the origin CA's certificates are)
        assert!(!check(&test_certs::issue(&ca, rcgen::ExtendedKeyUsagePurpose::ServerAuth).0));
        // a CA certificate is not a visitor's either
        assert!(!check(&[CertificateDer::from_pem_slice(ca.pem.as_bytes()).unwrap()]));
    }

    #[test]
    fn the_ca_file_must_hold_usable_certificates() {
        let ca = test_certs::ca("fucf test client CA");
        assert!(crate::edge::tls::visitor_verifier(&format!("{}{}", ca.pem, test_certs::ca("second").pem)).is_ok(), "several CAs");
        // armour around something that is not a certificate (put together here, not kept in the source)
        let armoured = format!("{dashes}BEGIN {kind}{dashes}\nAAAA\n{dashes}END {kind}{dashes}\n", dashes = "-----", kind = "CERTIFICATE");
        for bad in ["", "garbage", armoured.as_str()] {
            assert!(crate::edge::tls::visitor_verifier(bad).is_err(), "{bad}");
        }
    }
}
