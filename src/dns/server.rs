//! UDP and TCP listeners for the authoritative DNS server.

use super::resolver::Resolver;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

const TCP_IDLE: Duration = Duration::from_secs(10);
const MAX_TCP_CONNS: usize = 1024;

/// Bind both transports; fails fast if the address is unavailable.
pub async fn bind(addr: SocketAddr) -> anyhow::Result<(UdpSocket, TcpListener)> {
    let ctx = |e| anyhow::anyhow!("cannot bind DNS listener on {addr}: {e}");
    let udp = UdpSocket::from_std(crate::handoff::udp(addr).map_err(ctx)?).map_err(ctx)?;
    // Use the port UDP actually got, so `:0` yields matching UDP/TCP ports.
    let tcp = crate::handoff::tcp(&udp.local_addr()?.to_string()).await.map_err(ctx)?;
    Ok((udp, tcp))
}

pub async fn serve_udp(sock: UdpSocket, resolver: Arc<Resolver>) {
    let mut buf = [0u8; 4096];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                // Lookups are in-memory and non-blocking: answer inline.
                if let Some(reply) = resolver.handle(&buf[..n], true, peer.ip()) {
                    let _ = sock.send_to(&reply, peer).await;
                }
            }
            // Windows reports ICMP port-unreachable from earlier sends here.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) => {
                tracing::warn!("dns udp recv error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

pub async fn serve_tcp(listener: TcpListener, resolver: Arc<Resolver>) {
    let limit = Arc::new(Semaphore::new(MAX_TCP_CONNS));
    loop {
        let Ok(permit) = limit.clone().acquire_owned().await else { return };
        match listener.accept().await {
            Ok((stream, _)) => {
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    let _ = tcp_conn(stream, resolver).await;
                    drop(permit);
                });
            }
            Err(e) => {
                tracing::warn!("dns tcp accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn tcp_conn(mut stream: TcpStream, resolver: Arc<Resolver>) -> std::io::Result<()> {
    const MAX_TCP_QUERY: usize = 16384;
    let peer = stream.peer_addr()?.ip();
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut len)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()), // idle
        };
        let len = u16::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_TCP_QUERY {
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()),
        };
        let Some(reply) = resolver.handle(&buf, false, peer) else { return Ok(()) };
        let mut out = Vec::with_capacity(reply.len() + 2);
        out.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        out.extend_from_slice(&reply);
        match tokio::time::timeout(TCP_IDLE, stream.write_all(&out)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()),
        }
    }
}
