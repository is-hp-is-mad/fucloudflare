//! UDP QUIC Initial SNI demultiplexer.
//!
//! Allows `fucf`'s native multi-domain HTTP/3 (QUIC) server to share UDP 443
//! with another QUIC server on the same host (such as Hysteria 2 moved to
//! `127.0.0.1:14443`).
//!
//! On every QUIC Initial packet (v1 RFC 9001 or v2 RFC 9369), the Initial
//! decryption keys depend solely on the plaintext Destination Connection ID,
//! so we can decrypt the Initial payload without any private key and inspect
//! the TLS 1.3 ClientHello SNI:
//! - If the SNI belongs to a zone hosted by `fucf` (or the panel / CNAME base),
//!   the datagram is delivered to `fucf`'s own `quinn::Endpoint` with the real
//!   client `SocketAddr` preserved.
//! - Otherwise (e.g. Hysteria 2 proxy SNI, IP literal, or obfuscated UDP), the
//!   datagram is transparently forwarded to the configured fallback UDP server
//!   and its replies are relayed back to the client.

use crate::store::Store;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use ring::aead::{quic as ring_quic, Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf;
use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

const SESSION_IDLE: Duration = Duration::from_secs(90);
const MAX_FALLBACK_SESSIONS: usize = 4096;
const LOCAL_QUEUE: usize = 1024;

// ---------------------------------------------- QUIC Initial SNI parser ----

fn read_varint(buf: &[u8], off: &mut usize) -> Option<u64> {
    let first = *buf.get(*off)?;
    let len = 1usize << (first >> 6);
    if *off + len > buf.len() {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for b in &buf[*off + 1..*off + len] {
        val = (val << 8) | (*b as u64);
    }
    *off += len;
    Some(val)
}

struct OutLen(usize);
impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let full_label_len = 6 + label.len(); // "tls13 " + label
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0); // empty context
    let info_slices = [info.as_slice()];
    let okm = prk.expand(&info_slices, OutLen(out_len)).ok()?;
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

/// Extract the TLS 1.3 ClientHello SNI from a QUIC v1/v2 Initial packet.
pub fn extract_quic_initial_sni(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 16 || (pkt[0] & 0x80) == 0 {
        return None; // short header or too short
    }
    let version = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
    let (salt, initial_type, key_label, iv_label, hp_label): (&[u8], u8, &[u8], &[u8], &[u8]) = match version {
        QUIC_V1 => (&V1_SALT, 0, b"quic key", b"quic iv", b"quic hp"),
        QUIC_V2 => (&V2_SALT, 1, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
        _ => return None,
    };
    if ((pkt[0] & 0x30) >> 4) != initial_type {
        return None; // not an Initial packet
    }

    let mut off = 5usize;
    let dcid_len = *pkt.get(off)? as usize;
    off += 1;
    let dcid = pkt.get(off..off + dcid_len)?;
    off += dcid_len;

    let scid_len = *pkt.get(off)? as usize;
    off += 1;
    if off + scid_len > pkt.len() {
        return None;
    }
    off += scid_len;

    let token_len = read_varint(pkt, &mut off)? as usize;
    if off + token_len > pkt.len() {
        return None;
    }
    off += token_len;

    let payload_len = read_varint(pkt, &mut off)? as usize;
    let pn_off = off;
    if pn_off + payload_len > pkt.len() || payload_len < 20 {
        return None;
    }

    // Derive client Initial keys per RFC 9001 §5.2.
    let initial_secret = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;
    let client_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);
    let key_bytes = hkdf_expand_label(&client_prk, key_label, 16)?;
    let iv_bytes = hkdf_expand_label(&client_prk, iv_label, 12)?;
    let hp_bytes = hkdf_expand_label(&client_prk, hp_label, 16)?;

    // Remove header protection (RFC 9001 §5.4).
    let sample = pkt.get(pn_off + 4..pn_off + 20)?;
    let hp_key = ring_quic::HeaderProtectionKey::new(&ring_quic::AES_128, &hp_bytes).ok()?;
    let mask = hp_key.new_mask(sample).ok()?;

    let first_byte = pkt[0] ^ (mask[0] & 0x0f);
    let pn_len = ((first_byte & 0x03) + 1) as usize;
    if pn_off + pn_len + 16 > pn_off + payload_len {
        return None;
    }

    let mut header = pkt[..pn_off + pn_len].to_vec();
    header[0] = first_byte;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let b = pkt[pn_off + i] ^ mask[1 + i];
        header[pn_off + i] = b;
        pn = (pn << 8) | (b as u64);
    }

    // Decrypt Initial payload with AES-128-GCM.
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&iv_bytes);
    let pn_be = pn.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_be[i];
    }
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key_bytes).ok()?);
    let mut ciphertext = pkt[pn_off + pn_len..pn_off + payload_len].to_vec();
    let plain = key.open_in_place(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(&header), &mut ciphertext).ok()?;

    // Reassemble CRYPTO frame(s) from the decrypted Initial payload.
    let mut crypto = Vec::new();
    let mut foff = 0usize;
    while foff < plain.len() {
        let frame_type = read_varint(plain, &mut foff)?;
        match frame_type {
            0x00 | 0x01 => {} // PADDING / PING
            0x06 => {
                // CRYPTO frame: offset + length + data
                let c_off = read_varint(plain, &mut foff)? as usize;
                let c_len = read_varint(plain, &mut foff)? as usize;
                let data = plain.get(foff..foff + c_len)?;
                foff += c_len;
                let end = c_off.checked_add(c_len)?;
                if end > 16384 {
                    return None;
                }
                if end > crypto.len() {
                    crypto.resize(end, 0);
                }
                crypto[c_off..end].copy_from_slice(data);
            }
            _ => break,
        }
    }

    extract_client_hello_sni(&crypto)
}

/// Extract SNI (extension 0x0000) from a TLS handshake ClientHello message.
fn extract_client_hello_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 || buf[0] != 0x01 {
        return None; // not ClientHello
    }
    let msg_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    let ch = buf.get(4..4 + msg_len.min(buf.len() - 4))?;
    let mut off = 2 + 32; // legacy_version + random
    if off >= ch.len() {
        return None;
    }
    let sid_len = *ch.get(off)? as usize;
    off += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*ch.get(off)?, *ch.get(off + 1)?]) as usize;
    off += 2 + cs_len;
    let comp_len = *ch.get(off)? as usize;
    off += 1 + comp_len;
    let ext_total = u16::from_be_bytes([*ch.get(off)?, *ch.get(off + 1)?]) as usize;
    off += 2;
    let ext_end = (off + ext_total).min(ch.len());
    while off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[off], ch[off + 1]]);
        let ext_len = u16::from_be_bytes([ch[off + 2], ch[off + 3]]) as usize;
        off += 4;
        let ext = ch.get(off..off + ext_len)?;
        off += ext_len;
        if ext_type == 0x0000 && ext.len() >= 5 {
            // server_name_list: 2-byte list length, 1-byte name_type (0=host_name), 2-byte name_len
            if ext[2] == 0x00 {
                let nlen = u16::from_be_bytes([ext[3], ext[4]]) as usize;
                let name = ext.get(5..5 + nlen)?;
                let s = std::str::from_utf8(name).ok()?;
                return Some(s.trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    None
}

// -------------------------------------------------- quinn AsyncUdpSocket ----

#[derive(Debug)]
struct MuxUdpSocket {
    pub_sock: Arc<UdpSocket>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

#[derive(Debug)]
struct MuxPoller(Arc<UdpSocket>);

impl UdpPoller for MuxPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for MuxUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(MuxPoller(self.pub_sock.clone()))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.pub_sock.try_send_to(transmit.contents, transmit.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((pkt, addr))) => {
                let len = pkt.len().min(bufs[0].len());
                bufs[0][..len].copy_from_slice(&pkt[..len]);
                meta[0] = RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "quic mux closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.pub_sock.local_addr()
    }
}

// ----------------------------------------------------------- demultiplexer ----

enum Route {
    LocalH3,
    Fallback(Arc<UdpSocket>),
}

struct Session {
    route: Route,
    last: Instant,
}

fn matches_fallback_sni(sni: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        if let Some(suffix) = p.strip_prefix("*.") {
            sni.ends_with(&format!(".{suffix}"))
        } else {
            sni == p
        }
    })
}

fn is_cdn_sni(sni: &str, store: &Store, panel_host: Option<&str>, cname_base: Option<&str>, fallback_snis: &[String]) -> bool {
    if matches_fallback_sni(sni, fallback_snis) {
        return false;
    }
    if panel_host.is_some_and(|p| p == sni) {
        return true;
    }
    if let Some(base) = cname_base {
        if sni == base || sni.ends_with(&format!(".{base}")) {
            return true;
        }
    }
    store.snapshot().find_zone(sni).is_some()
}

/// Bind a public UDP socket shared between `fucf`'s native multi-domain HTTP/3
/// endpoint and a local fallback QUIC server (e.g. Hysteria 2).
pub async fn bind(
    addr: SocketAddr,
    fallback: SocketAddr,
    store: Arc<Store>,
    panel_host: Option<String>,
    cname_base: Option<String>,
    fallback_snis: Vec<String>,
) -> anyhow::Result<quinn::Endpoint> {
    let pub_sock = Arc::new(UdpSocket::bind(addr).await?);
    let (h3_tx, h3_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(LOCAL_QUEUE);

    let tls = super::tls::quic_server_config(store.clone())?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(200u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.send_window(16 * 1024 * 1024);
    transport.receive_window((16u32 * 1024 * 1024).into());
    transport.stream_receive_window((4u32 * 1024 * 1024).into());
    config.transport_config(Arc::new(transport));

    let mux_sock = Arc::new(MuxUdpSocket { pub_sock: pub_sock.clone(), rx: Mutex::new(h3_rx) });
    let ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(config),
        mux_sock,
        Arc::new(quinn::TokioRuntime),
    )?;

    tokio::spawn(run_mux(pub_sock, fallback, h3_tx, store, panel_host, cname_base, fallback_snis));
    Ok(ep)
}

async fn run_mux(
    pub_sock: Arc<UdpSocket>,
    fallback: SocketAddr,
    h3_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    store: Arc<Store>,
    panel_host: Option<String>,
    cname_base: Option<String>,
    fallback_snis: Vec<String>,
) {
    let sessions: Arc<Mutex<HashMap<SocketAddr, Session>>> = Arc::default();
    let mut buf = [0u8; 65535];
    let mut last_gc = Instant::now();

    loop {
        let (n, peer) = match pub_sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                tracing::warn!("quic mux recv error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let pkt = &buf[..n];
        let now = Instant::now();

        if last_gc.elapsed() >= Duration::from_secs(30) {
            last_gc = now;
            sessions.lock().unwrap().retain(|_, s| now.duration_since(s.last) < SESSION_IDLE);
        }

        // Classify on QUIC Initial packets (so a client port can even switch SNI),
        // and fall back to the existing session route for Handshake / 0-RTT / Short Header packets.
        let mut target_h3 = false;
        let mut fb_sock: Option<Arc<UdpSocket>> = None;

        let initial_sni = if n >= 16 && (pkt[0] & 0x80) != 0 { extract_quic_initial_sni(pkt) } else { None };
        if let Some(sni) = initial_sni {
            if is_cdn_sni(&sni, &store, panel_host.as_deref(), cname_base.as_deref(), &fallback_snis) {
                sessions.lock().unwrap().insert(peer, Session { route: Route::LocalH3, last: now });
                target_h3 = true;
            } else {
                // Explicit non-CDN SNI on a new Initial: drop any stale LocalH3 route for this peer.
                let mut map = sessions.lock().unwrap();
                if matches!(map.get(&peer), Some(Session { route: Route::LocalH3, .. })) {
                    map.remove(&peer);
                }
            }
        } else {
            let mut map = sessions.lock().unwrap();
            if let Some(s) = map.get_mut(&peer) {
                s.last = now;
                match &s.route {
                    Route::LocalH3 => target_h3 = true,
                    Route::Fallback(sock) => fb_sock = Some(sock.clone()),
                }
            }
        }

        if target_h3 {
            let _ = h3_tx.try_send((pkt.to_vec(), peer));
            continue;
        }

        if fb_sock.is_none() {
            // Look up existing fallback session or create a new one.
            let existing = {
                let mut map = sessions.lock().unwrap();
                map.get_mut(&peer).and_then(|s| match &s.route {
                    Route::Fallback(sock) => {
                        s.last = now;
                        Some(sock.clone())
                    }
                    Route::LocalH3 => None,
                })
            };
            if let Some(sock) = existing {
                fb_sock = Some(sock);
            } else {
                let count = sessions.lock().unwrap().len();
                if count >= MAX_FALLBACK_SESSIONS {
                    continue;
                }
                let bind_addr: SocketAddr = if fallback.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
                if let Ok(sock) = UdpSocket::bind(bind_addr).await {
                    if sock.connect(fallback).await.is_ok() {
                        let sock = Arc::new(sock);
                        sessions.lock().unwrap().insert(peer, Session { route: Route::Fallback(sock.clone()), last: now });
                        let pub_reply = pub_sock.clone();
                        let sock_read = sock.clone();
                        let sessions_gc = sessions.clone();
                        tokio::spawn(async move {
                            let mut rbuf = [0u8; 65535];
                            while let Ok(Ok(rn)) = tokio::time::timeout(SESSION_IDLE, sock_read.recv(&mut rbuf)).await {
                                let _ = pub_reply.send_to(&rbuf[..rn], peer).await;
                            }
                            sessions_gc.lock().unwrap().remove(&peer);
                        });
                        fb_sock = Some(sock);
                    }
                }
            }
        }

        if let Some(sock) = fb_sock {
            let _ = sock.send(pkt).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::temp_store;

    #[tokio::test]
    async fn demuxes_cdn_sni_and_fallback_on_same_udp_port() {
        let store = Arc::new(temp_store());
        let z = store.create_zone("alpha.test").unwrap().id;
        let cert = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
        store
            .save_item::<crate::items::Certificate>(
                &z,
                None,
                serde_json::json!({
                    "hosts": ["alpha.test"],
                    "certificate": cert.cert.pem(),
                    "private_key": cert.signing_key.serialize_pem()
                }),
                true,
            )
            .unwrap();

        // Fallback UDP echo server (stands in for Hysteria 2).
        let fb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb.local_addr().unwrap();
        let fb_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fb_hits_bg = fb_hits.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 4096];
            while let Ok((n, from)) = fb.recv_from(&mut b).await {
                fb_hits_bg.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = fb.send_to(b"FALLBACK-OK", from).await;
                let _ = n;
            }
        });

        let ep = bind("127.0.0.1:0".parse().unwrap(), fb_addr, store.clone(), Some("dash.test".into()), None, vec!["hy2.alpha.test".into()])
            .await
            .unwrap();
        let mux_addr = ep.local_addr().unwrap();

        // 1. Plain non-QUIC / unknown packet goes to fallback and gets reply back.
        let raw_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        raw_client.send_to(b"hello-hy2", mux_addr).await.unwrap();
        let mut rbuf = [0u8; 64];
        let (rn, _) = tokio::time::timeout(Duration::from_secs(2), raw_client.recv_from(&mut rbuf)).await.unwrap().unwrap();
        assert_eq!(&rbuf[..rn], b"FALLBACK-OK");
        assert!(fb_hits.load(std::sync::atomic::Ordering::Relaxed) >= 1);

        // 2. Real QUIC v1 ClientHello for hosted zone "alpha.test" reaches `ep` (native quinn)!
        let accept = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(3), ep.accept()).await.unwrap().unwrap();
            let conn = incoming.await.unwrap();
            conn.remote_address()
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut c_tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        c_tls.alpn_protocols = vec![b"h3".to_vec()];
        let c_cfg = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(c_tls).unwrap()));
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(c_cfg);
        let client_addr = client.local_addr().unwrap();
        let _conn = client.connect(mux_addr, "alpha.test").unwrap().await.unwrap();
        let seen_peer = accept.await.unwrap();
        assert_eq!(seen_peer, client_addr, "native quinn sees the real client address");
    }
}
