//! A front for HTTP/3.
//!
//! Where UDP 443 belongs to another QUIC server -- a Hysteria 2 proxy, say,
//! which answers ordinary HTTP/3 clients with a "masquerade" -- that server
//! can pass those clients on to this edge: it terminates QUIC and TLS and
//! forwards each request over plain HTTP to a listener here (for Hysteria:
//! a masquerade of type "proxy", with rewriteHost off and xForwarded on).
//! Such a request is treated as what it was for the visitor: HTTPS over
//! HTTP/3, from the address the front names last in X-Forwarded-For.
//!
//! The certificate visitors get to see is the front's, not ours. HTTP/3 is
//! therefore only advertised (Alt-Svc, HTTPS records) for host names that
//! certificate covers: for all others the attempt would just fail.

use super::{respond, streaming, Body, Edge, TlsInfo};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;

/// On a request that reached the edge through the front: the visitor spoke HTTP/3.
#[derive(Clone, Copy)]
pub struct ViaFront;

pub struct Front {
    /// UDP port the front listens on.
    pub port: u16,
    alt_svc: HeaderValue,
    cert_path: Option<PathBuf>,
    /// The front's (leaf) certificate, and when its file was last changed.
    cert: RwLock<Option<(SystemTime, CertificateDer<'static>)>>,
}

impl Front {
    pub fn new(port: u16, cert_path: Option<PathBuf>) -> Front {
        let alt_svc = format!("h3=\":{port}\"; ma=86400").parse().expect("a valid header value");
        let front = Front { port, alt_svc, cert_path, cert: RwLock::default() };
        match &front.cert_path {
            Some(path) if !front.reload() => tracing::warn!("cannot read the certificate of the HTTP/3 front ({}): HTTP/3 is not advertised", path.display()),
            Some(_) => {}
            None => tracing::warn!("the certificate of the HTTP/3 front is not known (--h3-front-cert): HTTP/3 is not advertised"),
        }
        front
    }

    /// Read the front's certificate again if its file changed. Returns
    /// whether there is one.
    pub fn reload(&self) -> bool {
        let Some(path) = &self.cert_path else { return false };
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let known = self.cert.read().unwrap().as_ref().map(|(at, _)| *at);
        if modified.is_some() && modified == known {
            return true;
        }
        let leaf = std::fs::read(path).ok().and_then(|pem| CertificateDer::pem_slice_iter(&pem).next()?.ok());
        let cert = modified.zip(leaf);
        if cert.is_some() != known.is_some() || cert.is_some() {
            tracing::info!("certificate of the HTTP/3 front: {}", if cert.is_some() { "loaded" } else { "gone" });
        }
        let found = cert.is_some();
        *self.cert.write().unwrap() = cert;
        found
    }

    /// Non-blocking reload executed inside `spawn_blocking` for background watchers.
    pub async fn reload_async(&self) -> bool {
        let Some(path) = self.cert_path.clone() else { return false };
        let known = self.cert.read().unwrap().as_ref().map(|(at, _)| *at);
        let res = tokio::task::spawn_blocking(move || {
            let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
            if modified.is_some() && modified == known {
                return Ok::<_, ()>(None);
            }
            let leaf = std::fs::read(&path).ok().and_then(|pem| CertificateDer::pem_slice_iter(&pem).next()?.ok());
            Ok(Some(modified.zip(leaf)))
        })
        .await;
        match res {
            Ok(Ok(None)) => true,
            Ok(Ok(Some(cert))) => {
                if cert.is_some() != known.is_some() || cert.is_some() {
                    tracing::info!("certificate of the HTTP/3 front: {}", if cert.is_some() { "loaded" } else { "gone" });
                }
                let found = cert.is_some();
                *self.cert.write().unwrap() = cert;
                found
            }
            _ => false,
        }
    }

    /// Does the certificate the front presents (now) cover this host name?
    pub fn covers(&self, host: &str) -> bool {
        let cert = self.cert.read().unwrap();
        let Some((_, der)) = cert.as_ref() else { return false };
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        if !super::tls::cert_validity(der).is_some_and(|(from, until)| from <= now && now < until) {
            return false;
        }
        let Ok(name) = ServerName::try_from(host) else { return false };
        rustls::server::ParsedCertificate::try_from(der).is_ok_and(|parsed| rustls::client::verify_server_name(&parsed, &name).is_ok())
    }

    /// When the certificate the front presents runs out (Unix seconds).
    pub fn expires(&self) -> Option<i64> {
        let cert = self.cert.read().unwrap();
        super::tls::cert_validity(&cert.as_ref()?.1).map(|(_, until)| until)
    }

    /// What Alt-Svc says on responses for this host, if HTTP/3 works for it.
    pub fn alt_svc(&self, host: &str) -> Option<HeaderValue> {
        self.covers(host).then(|| self.alt_svc.clone())
    }

    /// Follow renewals of the front's certificate.
    pub async fn watch(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            self.reload_async().await;
        }
    }
}

/// Take what the front says about the visitor out of the headers: the
/// address (the last entry of X-Forwarded-For -- the one the front added;
/// what precedes it is the visitor's own claim and stays), the host name
/// that was asked for, and whether TLS was used (it was, unless the front
/// says otherwise).
fn unwrap_forwarded_with_trust(
    headers: &mut HeaderMap,
    trusted_front: bool,
    front_cert: Option<&Front>,
) -> (Option<IpAddr>, bool) {
    let chain: Vec<String> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect();
    headers.remove("x-forwarded-for");
    let visitor = chain.last().and_then(|last| last.parse::<IpAddr>().ok());
    if let Some(claimed) = chain.len().checked_sub(1).filter(|n| *n > 0 && visitor.is_some()) {
        if let Ok(v) = HeaderValue::from_str(&chain[..claimed].join(", ")) {
            headers.insert("x-forwarded-for", v);
        }
    }
    if let Some(host) = headers.get_all("x-forwarded-host").iter().last().cloned() {
        headers.remove("x-forwarded-host");
        let xfh_host = host
            .to_str()
            .ok()
            .and_then(|s| s.parse::<hyper::Uri>().ok().and_then(|u| u.host().map(|h| h.to_string())).or_else(|| {
                let s = s.trim();
                Some(s.split(':').next().unwrap_or(s).to_ascii_lowercase())
            }))
            .unwrap_or_default();
        let trusted = trusted_front
            || (!xfh_host.is_empty() && front_cert.is_some_and(|f| f.covers(&xfh_host)));
        if trusted {
            headers.insert(header::HOST, host);
        }
    }
    let tls = headers.get_all("x-forwarded-proto").iter().last().is_none_or(|proto| !proto.as_bytes().eq_ignore_ascii_case(b"http"));
    headers.remove("x-forwarded-proto");
    (visitor, tls)
}

#[cfg(test)]
fn unwrap_forwarded(headers: &mut HeaderMap) -> (Option<IpAddr>, bool) {
    unwrap_forwarded_with_trust(headers, true, None)
}

async fn handle(edge: Arc<Edge>, front: SocketAddr, port: u16, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    static WARNED: AtomicBool = AtomicBool::new(false);
    let mut req = req.map(streaming);
    let (visitor, tls) = unwrap_forwarded_with_trust(
        req.headers_mut(),
        edge.trust_forwarded_host.load(Ordering::Relaxed),
        edge.front.get().map(|f| f.as_ref()),
    );
    if visitor.is_none() && !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!("the HTTP/3 front does not say who its visitors are (X-Forwarded-For): they all count as {}", front.ip());
    }
    if tls {
        // QUIC is always TLS 1.3, and has no handshake without a server name to speak of;
        // the front passes on no client certificate, so none counts as verified (crate::edge::mtls)
        req.extensions_mut().insert(TlsInfo { version: "TLSv1.3", sni: true, kex: String::new(), ja4: String::new(), client_cert_verified: false });
        req.extensions_mut().insert(ViaFront);
    }
    req.extensions_mut().insert(super::proxy::ListenerInfo { port, is_proxy: false, is_front: true });
    let peer = visitor.map_or(front, |ip| SocketAddr::new(ip, 0));
    Ok(respond(edge, peer, tls, req).await)
}

const MAX_FRONT_CONNECTIONS: usize = 4096;

/// Accept loop of the front's listener: plain HTTP/1.1 from the QUIC server
/// next door. Whoever can connect is believed about the visitor's address,
/// so this belongs on loopback.
pub async fn serve(listener: TcpListener, edge: Arc<Edge>) {
    serve_with_limit(listener, edge, MAX_FRONT_CONNECTIONS).await;
}

pub async fn serve_with_limit(listener: TcpListener, edge: Arc<Edge>, max_connections: usize) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let limit = Arc::new(tokio::sync::Semaphore::new(max_connections.max(1)));
    loop {
        let Ok(permit) = limit.clone().acquire_owned().await else { return };
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!("HTTP/3 front accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let edge = edge.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper::service::service_fn(move |req| handle(edge.clone(), peer, port, req));
            let mut http = hyper::server::conn::http1::Builder::new();
            // idle connections are the front's to close: it keeps them for reuse
            http.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(120));
            let _ = http.serve_connection(TokioIo::new(stream), service).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_visitor_from_the_last_forwarded_entry() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.append(*name, HeaderValue::from_static(value));
            }
            map
        };
        fn value<'a>(map: &'a HeaderMap, name: &str) -> Option<&'a str> {
            map.get(name).and_then(|v| v.to_str().ok())
        }
        // what the front added, after what the visitor claimed
        let mut h = headers(&[("x-forwarded-for", "10.0.0.1, 198.51.100.7"), ("x-forwarded-proto", "https"), ("host", "example.com")]);
        assert_eq!(unwrap_forwarded(&mut h), (Some("198.51.100.7".parse().unwrap()), true));
        assert_eq!((value(&h, "x-forwarded-for"), value(&h, "host"), value(&h, "x-forwarded-proto")), (Some("10.0.0.1"), Some("example.com"), None));
        // several header lines count as one list; IPv6
        let mut h = headers(&[("x-forwarded-for", "10.0.0.1"), ("x-forwarded-for", "10.0.0.2 ,2001:db8::7")]);
        assert_eq!(unwrap_forwarded(&mut h).0, Some("2001:db8::7".parse().unwrap()));
        assert_eq!(value(&h, "x-forwarded-for"), Some("10.0.0.1, 10.0.0.2"));
        // only the front's entry: nothing is left
        let mut h = headers(&[("x-forwarded-for", "198.51.100.7"), ("x-forwarded-host", "site.example"), ("host", "127.0.0.1:18480")]);
        assert_eq!(unwrap_forwarded(&mut h), (Some("198.51.100.7".parse().unwrap()), true));
        assert_eq!((value(&h, "x-forwarded-for"), value(&h, "host"), value(&h, "x-forwarded-host")), (None, Some("site.example"), None));
        // a front that does not say, or says nonsense; plain HTTP
        assert_eq!(unwrap_forwarded(&mut headers(&[("x-forwarded-proto", "http")])), (None, false));
        let mut h = headers(&[("x-forwarded-for", "10.0.0.1, unknown")]);
        assert_eq!((unwrap_forwarded(&mut h), value(&h, "x-forwarded-for")), ((None, true), None));
        // untrusted front: x-forwarded-host is stripped and Host is preserved
        let mut h = headers(&[("x-forwarded-host", "evil.example"), ("host", "victim.example")]);
        unwrap_forwarded_with_trust(&mut h, false, None);
        assert_eq!((value(&h, "host"), value(&h, "x-forwarded-host")), (Some("victim.example"), None));
    }

    #[test]
    fn advertises_http3_only_for_names_its_certificate_covers() {
        let path = std::env::temp_dir().join(format!("fucf-front-{}.crt", uuid::Uuid::new_v4().simple()));
        let issue = |names: &[&str], until: i32| {
            let mut params = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(until, 1, 1);
            params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap().pem()
        };
        // no certificate named, or none there: nothing is advertised
        assert!(!Front::new(443, None).covers("example.com"));
        let front = Front::new(443, Some(path.clone()));
        assert!(!front.covers("example.com") && !front.reload());

        std::fs::write(&path, issue(&["example.com", "*.example.com", "203.0.113.9"], 2090)).unwrap();
        assert!(front.reload());
        for covered in ["example.com", "www.example.com", "WWW.Example.com", "203.0.113.9"] {
            assert!(front.covers(covered), "{covered}");
        }
        for other in ["a.b.example.com", "example.org", "203.0.113.10", "not a name", ""] {
            assert!(!front.covers(other), "{other}");
        }
        assert_eq!(front.alt_svc("www.example.com").unwrap(), "h3=\":443\"; ma=86400");
        assert_eq!((front.alt_svc("example.org"), Front::new(8443, None).alt_svc.to_str().unwrap()), (None, "h3=\":8443\"; ma=86400"));

        // an expired certificate covers nothing; neither does one that went away
        let expired = Front::new(443, Some(path.clone()));
        std::fs::write(&path, issue(&["example.com"], 2021)).unwrap();
        // (a new object: reloading is by the file's modification time, which may not have moved)
        let expired = { drop(expired); Front::new(443, Some(path.clone())) };
        assert!(!expired.covers("example.com"));
        std::fs::remove_file(&path).unwrap();
        assert!(!front.reload() && !front.covers("example.com"));
    }

    #[tokio::test]
    async fn front_serve_semaphore_bounds_concurrency() {
        let store = Arc::new(crate::store::Store::open_ephemeral(vec![]));
        let edge = Arc::new(crate::edge::Edge::new(store, Arc::new(crate::edge::cache::Cache::new(1 << 20)), Arc::new(crate::edge::waf::Waf::new()), vec![]).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_with_limit(listener, edge, 2));

        // Hold 2 idle connections; a 3rd request only completes after one closes.
        let c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut c3 = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        c3.write_all(b"GET /cdn-cgi/fucf-trace HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        let timed = tokio::time::timeout(Duration::from_millis(120), c3.read_to_end(&mut buf)).await;
        assert!(timed.is_err(), "3rd connection should wait while 2 permits are held");

        drop(c1);
        let n = tokio::time::timeout(Duration::from_secs(2), c3.read_to_end(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0 && String::from_utf8_lossy(&buf).contains("200 OK"));
        drop(c2);
    }
}
