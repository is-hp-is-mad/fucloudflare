//! Mainland China (GFW) reachability probe per edge node.
//!
//! Periodically (every 15 minutes) probes two mainland-China websites that serve
//! HTTP/1.1, HTTP/2 and HTTP/3 (`www.xiaohongshu.com` and `www.zhihu.com`)
//! using Tencent DNSPod DoH (`doh.pub`) with a mainland-China EDNS Client
//! Subnet, verifies via the local GeoIP database that the resolved IPv4/IPv6
//! address is actually inside mainland China (`CN`), and sends up to 5 probes
//! per site for each `(ip_version, protocol)` pair (stopping early on the
//! first reply; `www.xiaohongshu.com` is skipped for IPv6 QUIC/UDP because it
//! does not serve HTTP/3 over IPv6).
//!
//! All bytes spent by the probe are counted into the node's CDN traffic
//! allowance (`Limits::add`).

use crate::geo::Geo;
use crate::limits::Limits;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Probe targets: `(host, supports_v6_quic)`.
const TARGETS: &[(&str, bool)] = &[
    ("www.xiaohongshu.com", false),
    ("www.zhihu.com", true),
];
const MAX_ATTEMPTS: usize = 5;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
const PROBE_INTERVAL: Duration = Duration::from_secs(900);
const INITIAL_DELAY: Duration = Duration::from_secs(20);

const CN_ECS_V4: &[&str] = &["114.114.114.0/24", "223.5.5.0/24", "119.29.29.0/24"];
const CN_ECS_V6: &[&str] = &["240e:1f:1::/48", "2400:3200::/32", "114.114.114.0/24"];

/// Mainland China reachability of one edge node across IP version and transport.
///
/// `None` means unknown / not probed (or the node has no address of that IP
/// family). `Some(true)` means reachable from mainland China; `Some(false)`
/// means blocked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GfwStatus {
    pub v4_tcp: Option<bool>,
    pub v4_udp: Option<bool>,
    pub v6_tcp: Option<bool>,
    pub v6_udp: Option<bool>,
    pub checked_at: String,
}

impl GfwStatus {
    /// True only when the corresponding `(v6, udp)` channel was actively
    /// probed and confirmed blocked (`Some(false)`).
    pub fn is_blocked(&self, v6: bool, udp: bool) -> bool {
        match (v6, udp) {
            (false, false) => self.v4_tcp == Some(false),
            (false, true) => self.v4_udp == Some(false),
            (true, false) => self.v6_tcp == Some(false),
            (true, true) => self.v6_udp == Some(false),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4_tcp.is_none() && self.v4_udp.is_none() && self.v6_tcp.is_none() && self.v6_udp.is_none()
    }
}

/// Shared holder for this node's latest [`GfwStatus`].
#[derive(Default)]
pub struct GfwMonitor(RwLock<GfwStatus>);

impl GfwMonitor {
    pub fn get(&self) -> GfwStatus {
        self.0.read().unwrap().clone()
    }

    pub fn set(&self, status: GfwStatus) {
        *self.0.write().unwrap() = status;
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_multicast()
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && (v6.segments()[0] & 0xfe00) != 0xfc00 // not ULA fc00::/7
                && (v6.segments()[0] & 0xffc0) != 0xfe80 // not link-local
        }
    }
}

fn tls_client_config(alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder_with_provider(crate::edge::tls::crypto())
        .with_safe_default_protocol_versions()
        .expect("rustls default versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

/// Extract A or AAAA IP addresses from a Tencent DoH JSON response (`doh.pub/resolve`).
fn parse_doh_ips(body: &[u8], want_v6: bool) -> Vec<IpAddr> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else { return Vec::new() };
    let want_type = if want_v6 { 28 } else { 1 };
    let mut out = Vec::new();
    if let Some(arr) = v.get("Answer").and_then(|a| a.as_array()) {
        for item in arr {
            if item.get("type").and_then(|t| t.as_u64()) != Some(want_type) {
                continue;
            }
            if let Some(data) = item.get("data").and_then(|d| d.as_str()) {
                if let Ok(ip) = data.parse::<IpAddr>() {
                    if ip.is_ipv6() == want_v6 {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

/// Query Tencent DoH (`doh.pub`) with a mainland-China ECS and return the first
/// IP address verified by the local GeoIP database to be inside mainland China.
async fn resolve_cn_ip(host: &str, want_v6: bool, geo: &Geo, limits: &Limits) -> Option<IpAddr> {
    let rtype = if want_v6 { "AAAA" } else { "A" };
    let ecs_list = if want_v6 { CN_ECS_V6 } else { CN_ECS_V4 };
    let cfg = Arc::new(tls_client_config(&[b"http/1.1"]));
    let connector = tokio_rustls::TlsConnector::from(cfg);

    for ecs in ecs_list {
        let path = format!("/resolve?name={host}&type={rtype}&edns_client_subnet={ecs}");
        let res = timeout(Duration::from_secs(10), async {
            let tcp = TcpStream::connect("doh.pub:443").await.ok()?;
            let sni = rustls::pki_types::ServerName::try_from("doh.pub".to_string()).ok()?;
            let tls = connector.connect(sni, tcp).await.ok()?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .method("GET")
                .uri(&path)
                .header("host", "doh.pub")
                .header("accept", "application/dns-json")
                .header("user-agent", "fucf-probe/1.0")
                .body(Empty::<Bytes>::new())
                .ok()?;
            let resp = sender.send_request(req).await.ok()?;
            let bytes = resp.into_body().collect().await.ok()?.to_bytes();
            limits.add((path.len() as u64) + (bytes.len() as u64) + 512);
            Some(bytes)
        })
        .await
        .ok()
        .flatten();

        if let Some(body) = res {
            for ip in parse_doh_ips(&body, want_v6) {
                if geo.locate(ip).country.as_deref() == Some("CN") {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Probe `host` at `ip:443` over TCP (TLS + HTTP/2 or HTTP/1.1 fallback).
async fn probe_tcp(ip: IpAddr, host: &str, limits: &Limits) -> bool {
    let cfg = Arc::new(tls_client_config(&[b"h2", b"http/1.1"]));
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let addr = SocketAddr::new(ip, 443);

    timeout(ATTEMPT_TIMEOUT, async move {
        let tcp = TcpStream::connect(addr).await.ok()?;
        let sni = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
        let tls = connector.connect(sni, tcp).await.ok()?;
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let uri: Uri = format!("https://{host}/").parse().ok()?;
        let req = Request::builder()
            .method("HEAD")
            .uri(if is_h2 { uri } else { Uri::from_static("/") })
            .header("host", host)
            .header("user-agent", "Mozilla/5.0")
            .body(Empty::<Bytes>::new())
            .ok()?;
        if is_h2 {
            let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await.ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let _resp = sender.send_request(req).await.ok()?;
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let _resp = sender.send_request(req).await.ok()?;
        }
        // Account for TLS handshake + HEAD request/response headers in CDN traffic.
        limits.add(2048);
        Some(())
    })
    .await
    .ok()
    .flatten()
    .is_some()
}

/// Probe `host` at `ip:443` over UDP (QUIC + HTTP/3).
async fn probe_udp(ip: IpAddr, host: &str, limits: &Limits) -> bool {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let tls_cfg = tls_client_config(&[b"h3"]);
    let Ok(quic_crypto) = quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg) else { return false };
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let Ok(mut endpoint) = quinn::Endpoint::client(bind) else { return false };
    endpoint.set_default_client_config(client_cfg);
    let addr = SocketAddr::new(ip, 443);

    let ok = timeout(ATTEMPT_TIMEOUT, async {
        let conn = endpoint.connect(addr, host).ok()?.await.ok()?;
        let (mut driver, mut send_req) = h3::client::new(h3_quinn::Connection::new(conn)).await.ok()?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let uri: Uri = format!("https://{host}/").parse().ok()?;
        let req = Request::builder()
            .method("HEAD")
            .uri(uri)
            .header("user-agent", "Mozilla/5.0")
            .body(())
            .ok()?;
        let mut stream = send_req.send_request(req).await.ok()?;
        stream.finish().await.ok()?;
        let _resp = stream.recv_response().await.ok()?;
        limits.add(2048);
        Some(())
    })
    .await
    .ok()
    .flatten()
    .is_some();

    endpoint.close(0u32.into(), b"done");
    ok
}

/// Probe one `(want_v6, udp)` channel across all applicable targets.
/// Each target is tried up to `MAX_ATTEMPTS` times and short-circuits on the
/// first reply. Resolved CN IPs are cached across TCP/UDP within one round.
async fn probe_channel(
    want_v6: bool,
    udp: bool,
    geo: &Geo,
    limits: &Limits,
    resolved: &mut std::collections::HashMap<(&'static str, bool), Option<IpAddr>>,
) -> Option<bool> {
    let mut resolved_any = false;
    for &(host, supports_v6_quic) in TARGETS {
        if want_v6 && udp && !supports_v6_quic {
            continue;
        }
        let ip = match resolved.get(&(host, want_v6)) {
            Some(cached) => *cached,
            None => {
                let ip = resolve_cn_ip(host, want_v6, geo, limits).await;
                resolved.insert((host, want_v6), ip);
                ip
            }
        };
        let Some(ip) = ip else {
            continue;
        };
        resolved_any = true;
        for _ in 0..MAX_ATTEMPTS {
            let ok = if udp { probe_udp(ip, host, limits).await } else { probe_tcp(ip, host, limits).await };
            if ok {
                return Some(true);
            }
        }
    }
    if resolved_any {
        Some(false)
    } else {
        None
    }
}

/// Run one full 4-channel GFW reachability check.
pub async fn probe_once(geo: &Geo, limits: &Limits, has_v4: bool, has_v6: bool) -> GfwStatus {
    let mut resolved = std::collections::HashMap::new();
    let v4_tcp = if has_v4 { probe_channel(false, false, geo, limits, &mut resolved).await } else { None };
    let v4_udp = if has_v4 { probe_channel(false, true, geo, limits, &mut resolved).await } else { None };
    let v6_tcp = if has_v6 { probe_channel(true, false, geo, limits, &mut resolved).await } else { None };
    let v6_udp = if has_v6 { probe_channel(true, true, geo, limits, &mut resolved).await } else { None };
    GfwStatus {
        v4_tcp,
        v4_udp,
        v6_tcp,
        v6_udp,
        checked_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// Background task: probes mainland-China reachability every 15 minutes.
pub async fn run(monitor: Arc<GfwMonitor>, geo: Arc<Geo>, limits: Arc<Limits>, edge_ips: Vec<IpAddr>) {
    if !geo.has_country_db() {
        return;
    }
    let has_v4 = edge_ips.iter().any(|ip| ip.is_ipv4() && is_public_ip(*ip));
    let has_v6 = edge_ips.iter().any(|ip| ip.is_ipv6() && is_public_ip(*ip));
    if !has_v4 && !has_v6 {
        return;
    }
    tokio::time::sleep(INITIAL_DELAY).await;
    loop {
        let status = probe_once(&geo, &limits, has_v4, has_v6).await;
        tracing::info!(
            v4_tcp = ?status.v4_tcp,
            v4_udp = ?status.v4_udp,
            v6_tcp = ?status.v6_tcp,
            v6_udp = ?status.v6_udp,
            "CN reachability probe completed"
        );
        monitor.set(status);
        tokio::time::sleep(PROBE_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_doh_parsing() {
        let st = GfwStatus {
            v4_tcp: Some(true),
            v4_udp: Some(false),
            v6_tcp: Some(true),
            v6_udp: None,
            checked_at: String::new(),
        };
        assert!(!st.is_blocked(false, false));
        assert!(st.is_blocked(false, true));
        assert!(!st.is_blocked(true, false));
        assert!(!st.is_blocked(true, true)); // unknown is never treated as blocked

        let sample = br#"{"Status":0,"Answer":[{"type":5,"data":"cname.example."},{"type":1,"data":"192.0.2.1"},{"type":28,"data":"2001:db8::1"}]}"#;
        assert_eq!(parse_doh_ips(sample, false), vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(parse_doh_ips(sample, true), vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }
}
