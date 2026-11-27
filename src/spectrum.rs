//! Spectrum: raw TCP/UDP port forwarding from the edge to origins.
//!
//! A supervisor keeps one listener task per configured app and reconciles
//! them whenever the configuration changes.

use crate::items::SpectrumApp;
use crate::store::Store;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(60);
const MAX_TCP_CONNS: usize = 10_000;
const MAX_UDP_SESSIONS: usize = 1_024;

/// Everything that requires restarting a listener when it changes.
fn fingerprint(app: &SpectrumApp) -> String {
    format!("{}|{:?}|{}", app.protocol, app.origin_direct, app.proxy_protocol)
}

pub async fn run(store: Arc<Store>, bind: IpAddr) {
    let mut changes = store.subscribe();
    let mut running: HashMap<String, (String, JoinHandle<()>)> = HashMap::new();
    loop {
        let snap = store.snapshot();
        let wanted: HashMap<&str, &SpectrumApp> = snap.spectrum_apps.iter().map(|a| (a.meta.id.as_str(), a)).collect();

        let stale: Vec<String> = running
            .iter()
            .filter(|(id, (fp, task))| {
                task.is_finished() || wanted.get(id.as_str()).map(|a| fingerprint(a)) != Some(fp.clone())
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some((_, task)) = running.remove(&id) {
                task.abort();
                let _ = task.await; // the port is free once the task is gone
            }
        }

        let mut failed = false;
        for (id, app) in wanted {
            if running.contains_key(id) {
                continue;
            }
            let Some((udp, port)) = app.listener() else { continue };
            let addr = SocketAddr::new(bind, port);
            let started = if udp {
                UdpSocket::bind(addr).await.map(|s| tokio::spawn(serve_udp(Arc::new(s), app.clone())))
            } else {
                TcpListener::bind(addr).await.map(|l| tokio::spawn(serve_tcp(l, app.clone())))
            };
            match started {
                Ok(task) => {
                    tracing::info!("spectrum {} ({}) listening on {addr}", app.dns.name, app.protocol);
                    running.insert(id.to_string(), (fingerprint(app), task));
                }
                Err(e) => {
                    failed = true;
                    tracing::error!("spectrum {} cannot bind {} on {addr}: {e}", app.dns.name, app.protocol);
                }
            }
        }

        // Wake on configuration changes; retry failed binds periodically.
        let retry = async {
            if failed {
                tokio::time::sleep(Duration::from_secs(30)).await
            } else {
                std::future::pending().await
            }
        };
        tokio::select! {
            r = changes.changed() => if r.is_err() { return },
            _ = retry => {}
        }
    }
}

// ---------------------------------------------------------------- tcp ----

/// Connect to one of the origins, starting at a rotating offset.
async fn connect_origin(origins: &[String], start: usize) -> Option<TcpStream> {
    for i in 0..origins.len() {
        let addr = &origins[(start + i) % origins.len()];
        let Ok(Ok(resolved)) = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host(addr.as_str())).await else {
            continue;
        };
        let addrs: Vec<SocketAddr> = resolved.collect();
        if addrs.is_empty() || addrs.iter().any(|a| crate::edge::upstream::is_blocked_metadata_ip(a.ip())) {
            continue;
        }
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addrs.as_slice())).await {
            let _ = s.set_nodelay(true);
            return Some(s);
        }
    }
    None
}

/// PROXY protocol v1 header describing the client connection.
pub fn proxy_v1(client: SocketAddr, local: SocketAddr) -> String {
    let (c, l) = (client.ip().to_canonical(), local.ip().to_canonical());
    match (c, l) {
        (IpAddr::V4(_), IpAddr::V4(_)) => format!("PROXY TCP4 {c} {l} {} {}\r\n", client.port(), local.port()),
        (IpAddr::V6(_), IpAddr::V6(_)) => format!("PROXY TCP6 {c} {l} {} {}\r\n", client.port(), local.port()),
        _ => "PROXY UNKNOWN\r\n".to_string(),
    }
}

async fn serve_tcp(listener: TcpListener, app: SpectrumApp) {
    let origins = Arc::new(app.origins());
    let send_proxy = app.proxy_protocol == "v1";
    let limit = Arc::new(Semaphore::new(MAX_TCP_CONNS));
    let next = Arc::new(AtomicUsize::new(0));
    loop {
        let Ok(permit) = limit.clone().acquire_owned().await else { return };
        let (mut client, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let (origins, next) = (origins.clone(), next.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = client.set_nodelay(true);
            let Some(mut origin) = connect_origin(&origins, next.fetch_add(1, Ordering::Relaxed)).await else {
                return;
            };
            if send_proxy {
                let Ok(local) = client.local_addr() else { return };
                if origin.write_all(proxy_v1(peer, local).as_bytes()).await.is_err() {
                    return;
                }
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
        });
    }
}

// ---------------------------------------------------------------- udp ----

struct Session {
    upstream: Arc<UdpSocket>,
    last_seen: Mutex<Instant>,
}

type Sessions = Arc<Mutex<HashMap<SocketAddr, Arc<Session>>>>;

async fn open_session(origins: &[String], start: usize) -> Option<UdpSocket> {
    let origin = &origins[start % origins.len()];
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(origin.as_str()).await.ok()?.collect();
    if addrs.is_empty() || addrs.iter().any(|a| crate::edge::upstream::is_blocked_metadata_ip(a.ip())) {
        return None;
    }
    let addr = addrs[0];
    let local: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };
    let sock = UdpSocket::bind(local).await.ok()?;
    sock.connect(addr).await.ok()?;
    Some(sock)
}

/// Each client address gets its own upstream socket, so replies from the
/// origin can be routed back; sessions end after `UDP_IDLE` of silence.
async fn serve_udp(sock: Arc<UdpSocket>, app: SpectrumApp) {
    let origins = app.origins();
    let sessions: Sessions = Arc::default();
    let mut next = 0usize;
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let existing = sessions.lock().unwrap().get(&client).cloned();
        let session = match existing {
            Some(s) => s,
            None => {
                if sessions.lock().unwrap().len() >= MAX_UDP_SESSIONS {
                    continue;
                }
                next = next.wrapping_add(1);
                let Some(upstream) = open_session(&origins, next).await else { continue };
                let session = Arc::new(Session { upstream: Arc::new(upstream), last_seen: Mutex::new(Instant::now()) });
                sessions.lock().unwrap().insert(client, session.clone());
                tokio::spawn(relay_replies(sock.clone(), client, session.clone(), sessions.clone()));
                session
            }
        };
        *session.last_seen.lock().unwrap() = Instant::now();
        let _ = session.upstream.send(&buf[..n]).await;
    }
}

async fn relay_replies(sock: Arc<UdpSocket>, client: SocketAddr, session: Arc<Session>, sessions: Sessions) {
    let mut buf = vec![0u8; 65535];
    loop {
        match tokio::time::timeout(UDP_IDLE / 4, session.upstream.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                *session.last_seen.lock().unwrap() = Instant::now();
                let _ = sock.send_to(&buf[..n], client).await;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(Err(_)) => break,
            Err(_) => {
                if session.last_seen.lock().unwrap().elapsed() >= UDP_IDLE {
                    break;
                }
            }
        }
    }
    sessions.lock().unwrap().remove(&client);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::temp_store;
    use serde_json::json;
    use tokio::io::AsyncReadExt;

    #[test]
    fn proxy_header() {
        let h = proxy_v1("198.51.100.7:5555".parse().unwrap(), "203.0.113.10:22".parse().unwrap());
        assert_eq!(h, "PROXY TCP4 198.51.100.7 203.0.113.10 5555 22\r\n");
        let h = proxy_v1("[2001:db8::1]:5555".parse().unwrap(), "203.0.113.10:22".parse().unwrap());
        assert_eq!(h, "PROXY UNKNOWN\r\n");
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn forwards_tcp_and_udp_and_follows_config() {
        // origins: a TCP server that echoes with a prefix, and a UDP echo
        let tcp_origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_origin.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = tcp_origin.accept().await.unwrap();
                tokio::spawn(async move {
                    // the PROXY header and the payload may arrive separately
                    let (mut buf, mut seen) = ([0u8; 256], Vec::new());
                    while !seen.ends_with(b"hello") {
                        match s.read(&mut buf).await.unwrap() {
                            0 => break,
                            n => seen.extend_from_slice(&buf[..n]),
                        }
                    }
                    s.write_all(b"origin:").await.unwrap();
                    s.write_all(&seen).await.unwrap();
                });
            }
        });
        let udp_origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_origin.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            loop {
                let (n, peer) = udp_origin.recv_from(&mut buf).await.unwrap();
                udp_origin.send_to(&buf[..n], peer).await.unwrap();
            }
        });

        let store = Arc::new(temp_store());
        let zone = store.create_zone("example.com").unwrap().id;
        tokio::spawn(run(store.clone(), "127.0.0.1".parse().unwrap()));

        let (tcp_port, udp_port) = (free_port(), free_port());
        let app: SpectrumApp = store
            .save_item(
                &zone,
                None,
                json!({ "protocol": format!("tcp/{tcp_port}"), "dns": { "name": "ssh" },
                        "origin_direct": [format!("tcp://{tcp_addr}")], "proxy_protocol": "v1" }),
                true,
            )
            .unwrap();
        assert_eq!(app.dns.name, "ssh.example.com");
        store
            .save_item::<SpectrumApp>(
                &zone,
                None,
                json!({ "protocol": format!("udp/{udp_port}"), "dns": { "name": "game" },
                        "origin_direct": [format!("udp://{udp_addr}")] }),
                true,
            )
            .unwrap();
        // the same edge port cannot be claimed twice
        let dup = store.save_item::<SpectrumApp>(
            &zone,
            None,
            json!({ "protocol": format!("tcp/{tcp_port}"), "dns": { "name": "x" }, "origin_direct": ["tcp://127.0.0.1:1"] }),
            true,
        );
        assert!(dup.is_err());
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut c = TcpStream::connect(("127.0.0.1", tcp_port)).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8(got).unwrap();
        assert!(got.starts_with("origin:PROXY TCP4 127.0.0.1 127.0.0.1 "), "{got}");
        assert!(got.ends_with("\r\nhello"), "{got}");

        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        u.connect(("127.0.0.1", udp_port)).await.unwrap();
        for msg in [&b"ping-1"[..], b"ping-2"] {
            u.send(msg).await.unwrap();
            let mut buf = [0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(3), u.recv(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n], msg);
        }

        // deleting the app closes its listener
        store.delete_item::<SpectrumApp>(&zone, &app.meta.id).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(TcpStream::connect(("127.0.0.1", tcp_port)).await.is_err());
    }
}
