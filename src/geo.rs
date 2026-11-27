//! Client geolocation for DNS steering (MaxMind GeoLite2 Country + ASN
//! databases) and the health view of the edge nodes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

pub const CONTINENTS: &[&str] = &["AF", "AN", "AS", "EU", "NA", "OC", "SA"];

/// What is known about where a client is and which network it is on.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Location {
    pub continent: Option<String>,
    /// ISO 3166-1 alpha-2, upper case.
    pub country: Option<String>,
    /// ISO 3166-2 first-level subdivision (province/state), upper case (e.g. `JS`, `ZJ`, `SH`).
    pub region: Option<String>,
    pub asn: Option<u32>,
    /// Network operator name, lower case.
    pub as_org: Option<String>,
}

#[derive(Default)]
pub struct Geo {
    country: Option<maxminddb::Reader<maxminddb::Mmap>>,
    asn: Option<maxminddb::Reader<maxminddb::Mmap>>,
    #[cfg(test)]
    pub fixed: HashMap<IpAddr, Location>,
}

fn open(path: &std::path::Path) -> anyhow::Result<maxminddb::Reader<maxminddb::Mmap>> {
    // SAFETY: the GeoIP database files are replaced atomically via rename, never mutated in place.
    unsafe { maxminddb::Reader::open_mmap(path) }
        .map_err(|e| anyhow::anyhow!("cannot open GeoIP database {}: {e}", path.display()))
}

impl Geo {
    pub fn open(country: Option<&std::path::Path>, asn: Option<&std::path::Path>) -> anyhow::Result<Self> {
        Ok(Geo { country: country.map(open).transpose()?, asn: asn.map(open).transpose()?, ..Default::default() })
    }

    /// Whether a Country/City GeoIP database is loaded.
    pub fn has_country_db(&self) -> bool {
        #[cfg(test)]
        if !self.fixed.is_empty() {
            return true;
        }
        self.country.is_some()
    }

    pub fn locate(&self, ip: IpAddr) -> Location {
        #[cfg(test)]
        if let Some(l) = self.fixed.get(&ip) {
            return l.clone();
        }
        let mut loc = Location::default();
        // `geoip2::City` decodes both GeoLite2-City (with subdivisions) and GeoLite2-Country (subdivisions empty).
        let city = self.country.as_ref().and_then(|r| r.lookup(ip).ok()?.decode::<maxminddb::geoip2::City>().ok()?);
        if let Some(c) = city {
            loc.continent = c.continent.code.map(String::from);
            loc.country = c.country.iso_code.map(|s| s.to_ascii_uppercase());
            loc.region = c
                .subdivisions
                .first()
                .and_then(|s| s.iso_code)
                .map(|s| s.to_ascii_uppercase());
        }
        let asn = self.asn.as_ref().and_then(|r| r.lookup(ip).ok()?.decode::<maxminddb::geoip2::Asn>().ok()?);
        if let Some(a) = asn {
            loc.asn = a.autonomous_system_number;
            loc.as_org = a.autonomous_system_organization.map(|s| s.to_ascii_lowercase());
        }
        loc
    }
}

/// Which edge nodes currently accept connections, as seen from this node.
#[derive(Default)]
pub struct Health(RwLock<HashMap<String, bool>>);

impl Health {
    /// Unknown nodes count as up.
    pub fn is_up(&self, node: &str) -> bool {
        self.0.read().unwrap().get(node).copied().unwrap_or(true)
    }
    pub fn set(&self, node: &str, up: bool) {
        self.0.write().unwrap().insert(node.to_string(), up);
    }
}

/// One health probe of a node's HTTPS port. With `sni`, a TLS handshake for
/// that name must complete (the certificate is not checked): this reaches the
/// edge itself even when a layer-4 proxy in front of it routes by SNI, where a
/// bare connection would only prove that the proxy is alive and would be
/// handed to whatever serves unknown names. Without `sni`, connecting is enough.
pub async fn probe(addr: std::net::SocketAddr, sni: Option<&str>, tls: &tokio_rustls::TlsConnector) -> bool {
    let attempt = async {
        let stream = tokio::net::TcpStream::connect(addr).await.ok()?;
        let Some(sni) = sni else { return Some(()) };
        let name = rustls::pki_types::ServerName::try_from(sni.to_string()).ok()?;
        tls.connect(name, stream).await.ok().map(|_| ())
    };
    matches!(tokio::time::timeout(std::time::Duration::from_secs(4), attempt).await, Ok(Some(())))
}

/// Probe every enabled node's HTTPS port (see [`probe`]); a node is marked
/// down after three consecutive failures and up again after two successes.
pub async fn health_checker(store: std::sync::Arc<crate::store::Store>, health: std::sync::Arc<Health>, sni: Option<String>) {
    use std::time::Duration;
    let tls = match crate::edge::tls::client_config(false) {
        Ok(cfg) => tokio_rustls::TlsConnector::from(cfg),
        Err(e) => {
            tracing::error!("node health checks disabled: {e}");
            return;
        }
    };
    let mut streak: HashMap<String, i32> = HashMap::new();
    loop {
        let nodes = store.snapshot().nodes.clone();
        let probes = nodes.into_iter().map(|n| {
            let (tls, sni) = (tls.clone(), sni.clone());
            async move {
                let addr: Option<IpAddr> = n.ipv4.map(Into::into).or(n.ipv6.map(Into::into));
                let Some(addr) = addr else { return (n.name.clone(), false) };
                (n.name.clone(), probe((addr, 443).into(), sni.as_deref(), &tls).await)
            }
        });
        let mut pending = Vec::new();
        for p in probes {
            pending.push(tokio::spawn(p));
        }
        for task in pending {
            let Ok((name, ok)) = task.await else { continue };
            let s = streak.entry(name.clone()).or_insert(0);
            *s = if ok { (*s).max(0) + 1 } else { (*s).min(0) - 1 };
            if *s <= -3 && health.is_up(&name) {
                tracing::warn!("edge node {name} is DOWN (3 failed probes): leaving DNS answers");
                health.set(&name, false);
            } else if *s >= 2 && !health.is_up(&name) {
                tracing::info!("edge node {name} is back up");
                health.set(&name, true);
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn probe_needs_a_tls_handshake_when_given_a_name() {
        let tls = tokio_rustls::TlsConnector::from(crate::edge::tls::client_config(false).unwrap());

        // an edge: completes the handshake
        let store = Arc::new(crate::store::testutil::temp_store());
        let acceptor = tokio_rustls::TlsAcceptor::from(crate::edge::tls::server_config(store).unwrap());
        let edge = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = edge.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = edge.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move { acceptor.accept(s).await.map(drop) });
            }
        });
        // something else on the port: accepts, then hangs up without speaking TLS
        let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other_addr = other.local_addr().unwrap();
        tokio::spawn(async move { while let Ok((s, _)) = other.accept().await { drop(s) } });
        // nothing listening
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);

        assert!(probe(edge_addr, Some("cdn.example.net"), &tls).await);
        assert!(probe(edge_addr, None, &tls).await);
        assert!(!probe(other_addr, Some("cdn.example.net"), &tls).await, "an open port is not a healthy edge");
        assert!(probe(other_addr, None, &tls).await);
        assert!(!probe(closed_addr, Some("cdn.example.net"), &tls).await);
        assert!(!probe(closed_addr, None, &tls).await);
    }
}
