//! Where a process cannot turn into another binary (everywhere but Unix, see
//! `handoff.rs`), no socket is handed over: each one is simply bound.

use std::net::SocketAddr;

/// A TCP listener on `spec` (`ip:port`).
pub async fn tcp(spec: &str) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(spec).await
}

/// A UDP socket on `addr` (non-blocking).
pub fn udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let sock = std::net::UdpSocket::bind(addr)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Nothing was handed over, so nothing is left unclaimed.
pub fn close_unclaimed() {}
