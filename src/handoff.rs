//! Listening sockets outlive the process when it turns into another binary
//! (a release taking over, or SIGUSR2 after the binary was replaced): the
//! kernel keeps queueing connections and datagrams while the next process
//! starts, so visitors wait a moment instead of being refused.
//!
//! Right before `exec`, every socket bound through here loses its
//! close-on-exec flag and is listed in `FUCF_LISTEN_FDS`
//! (`tcp 0.0.0.0:443=7,udp 0.0.0.0:443=8,…`). The next process takes those
//! it binds again (same kind, same address) and closes the others.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::{LazyLock, Mutex};

const ENV: &str = "FUCF_LISTEN_FDS";

#[derive(Default)]
struct Table {
    /// Handed over by the process before, not yet taken.
    inherited: HashMap<String, RawFd>,
    /// Bound or taken by this process.
    ours: Vec<(String, RawFd)>,
}

static TABLE: LazyLock<Mutex<Table>> = LazyLock::new(|| {
    let inherited = std::env::var(ENV).map(|v| parse(&v)).unwrap_or_default();
    std::env::remove_var(ENV); // not for the processes this one starts
    Mutex::new(Table { inherited, ours: Vec::new() })
});

fn parse(list: &str) -> HashMap<String, RawFd> {
    list.split(',')
        .filter_map(|item| {
            let (key, fd) = item.rsplit_once('=')?;
            Some((key.to_string(), fd.trim().parse::<RawFd>().ok().filter(|fd| *fd > 2)?))
        })
        .collect()
}

fn set_cloexec(fd: RawFd, on: bool) -> bool {
    // SAFETY: plain fcntl calls on a descriptor number; a closed one fails with EBADF.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return false;
        }
        let flags = if on { flags | libc::FD_CLOEXEC } else { flags & !libc::FD_CLOEXEC };
        libc::fcntl(fd, libc::F_SETFD, flags) == 0
    }
}

fn sockopt(fd: RawFd, name: libc::c_int) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `value`.
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, &mut value as *mut libc::c_int as *mut libc::c_void, &mut len) };
    (r == 0).then_some(value)
}

/// Whether `fd` is a socket of `kind` bound to `want` (when that is known).
fn fits(fd: RawFd, kind: &str, want: Option<SocketAddr>) -> bool {
    let ok_type = match kind {
        "tcp" => sockopt(fd, libc::SO_TYPE) == Some(libc::SOCK_STREAM) && sockopt(fd, libc::SO_ACCEPTCONN) == Some(1),
        _ => sockopt(fd, libc::SO_TYPE) == Some(libc::SOCK_DGRAM),
    };
    if !ok_type {
        return false;
    }
    // SAFETY: the descriptor is a socket (checked above); ManuallyDrop keeps it open whatever the answer.
    let probe = std::mem::ManuallyDrop::new(unsafe { std::net::UdpSocket::from_raw_fd(fd) });
    let local = probe.local_addr().ok();
    match want {
        Some(want) => local == Some(want),
        None => local.is_some(),
    }
}

fn take(key: &str, kind: &str, want: Option<SocketAddr>) -> Option<RawFd> {
    let mut table = TABLE.lock().unwrap();
    let fd = *table.inherited.get(key)?;
    if !fits(fd, kind, want) {
        // not what it says it is: leave that descriptor alone
        table.inherited.remove(key);
        return None;
    }
    table.inherited.remove(key);
    set_cloexec(fd, true);
    table.ours.push((key.to_string(), fd));
    Some(fd)
}

fn keep(key: String, fd: RawFd) {
    TABLE.lock().unwrap().ours.push((key, fd));
}

/// A TCP listener on `spec` (`ip:port`): the one the process before handed
/// over, or a new one.
pub async fn tcp(spec: &str) -> std::io::Result<tokio::net::TcpListener> {
    let key = format!("tcp {spec}");
    if let Some(fd) = take(&key, "tcp", spec.parse().ok()) {
        // SAFETY: a listening TCP socket that nothing else owns (handed over, checked by `fits`).
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        listener.set_nonblocking(true)?;
        tracing::info!("took over the listener on tcp {spec}");
        return tokio::net::TcpListener::from_std(listener);
    }
    let listener = tokio::net::TcpListener::bind(spec).await?;
    keep(key, listener.as_raw_fd());
    Ok(listener)
}

/// A UDP socket on `addr`, handed over or new (non-blocking).
pub fn udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let key = format!("udp {addr}");
    if let Some(fd) = take(&key, "udp", Some(addr)) {
        // SAFETY: a bound UDP socket that nothing else owns (handed over, checked by `fits`).
        let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        sock.set_nonblocking(true)?;
        tracing::info!("took over the socket on udp {addr}");
        return Ok(sock);
    }
    let sock = std::net::UdpSocket::bind(addr)?;
    sock.set_nonblocking(true)?;
    keep(key, sock.as_raw_fd());
    Ok(sock)
}

/// Close what the process before handed over and this one does not use.
pub fn close_unclaimed() {
    let mut table = TABLE.lock().unwrap();
    for (key, fd) in table.inherited.drain() {
        if fits(fd, if key.starts_with("tcp ") { "tcp" } else { "udp" }, None) {
            // SAFETY: an inherited socket nobody took; this process owns it.
            unsafe { libc::close(fd) };
            tracing::info!("closed the {key} listener handed over: no longer configured");
        }
    }
}

/// Hand this process's sockets to the binary `command` is about to exec.
pub fn prepare_exec(command: &mut std::process::Command) {
    let table = TABLE.lock().unwrap();
    let mut list = Vec::new();
    // what was handed over and not taken yet goes on as well (still open, still inheritable)
    let all = table.ours.iter().cloned().chain(table.inherited.iter().map(|(k, fd)| (k.clone(), *fd)));
    for (key, fd) in all {
        if set_cloexec(fd, false) {
            list.push(format!("{key}={fd}"));
        }
    }
    if list.is_empty() {
        command.env_remove(ENV);
    } else {
        command.env(ENV, list.join(","));
    }
}

/// The exec did not happen: the sockets are this process's again only.
pub fn exec_failed() {
    let table = TABLE.lock().unwrap();
    for (_, fd) in &table.ours {
        set_cloexec(*fd, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_list() {
        let got = parse("tcp 0.0.0.0:443=7,udp [::]:443=8,tcp 127.0.0.1:8787=x,tcp bad=1");
        assert_eq!(got.get("tcp 0.0.0.0:443"), Some(&7));
        assert_eq!(got.get("udp [::]:443"), Some(&8));
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[tokio::test]
    async fn checks_what_it_is_handed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let fd = listener.as_raw_fd();
        assert!(fits(fd, "tcp", Some(addr)));
        assert!(!fits(fd, "udp", Some(addr)));
        assert!(!fits(fd, "tcp", Some("127.0.0.1:1".parse().unwrap())));
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(fits(udp.as_raw_fd(), "udp", udp.local_addr().ok()));
        assert!(!fits(udp.as_raw_fd(), "tcp", None));
        // close-on-exec goes and comes back
        assert!(set_cloexec(fd, false));
        // SAFETY: test-only flag read on an open descriptor
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        assert!(set_cloexec(fd, true));
        assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    }
}
