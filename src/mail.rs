//! E-mail routing: mail for addresses of a zone is taken over SMTP and
//! passed on to mailboxes elsewhere, as the zone's rules say.
//!
//! Nothing is stored. A message is handed to its destinations while the
//! sender still waits for the answer to its DATA: it hears "250" only once
//! every destination has taken the message, a temporary error when one of
//! them could not right now (it will try again; destinations that already
//! have the message are not given it twice), and a permanent one when none
//! of them wants it. A sender is never told "accepted" for a message that
//! then gets lost, and no bounces are made up here.
//!
//! The envelope sender is rewritten (SRS) to an address of the zone, so
//! that the destination's SPF check sees a sender we may speak for; a
//! bounce to such an address finds its way back to the original sender.
//!
//! Outgoing mail goes straight to the destination's mail exchangers, or --
//! where the network does not let port 25 out -- through a relay.

use crate::auth::base32;
use crate::store::{Snapshot, Store};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Largest message taken, in bytes.
const MAX_MESSAGE: usize = 25 << 20;
/// Concurrent SMTP sessions (keeps memory bounded on small nodes).
const MAX_SESSIONS: usize = 64;
/// Concurrent DATA transfers in flight at once (avoids OOM under large-message floods).
const MAX_INFLIGHT_DATA: usize = 4;
const MAX_DELIVERED: usize = 10_000;
const MAX_REPLY_LINES: usize = 100;
const MAX_RECIPIENTS: usize = 50;
const MAX_LINE: usize = 4096;
/// A message that passed through this many servers is going in circles.
const MAX_HOPS: usize = 30;
const IDLE: Duration = Duration::from_secs(120);
const ACTIVITY_KEPT: usize = 200;
/// How long a rewritten sender address takes bounces.
const SRS_DAYS: i64 = 21;

/// What becomes of mail for an address.
#[derive(Debug, Clone, PartialEq)]
pub enum Route {
    /// Pass it on to these mailboxes; the sender is rewritten to an address of this zone.
    Forward { to: Vec<String>, zone: String },
    /// Hand the message to a Worker script's `email(message, env, ctx)` handler.
    Worker { script: String, zone: String },
    /// A bounce for a sender we rewrote: back to the original sender, as it is.
    Bounce { to: String },
    /// Take it and throw it away.
    Drop,
    /// Not ours, or nobody there: the SMTP reply to give.
    Reject(&'static str),
}

/// Where mail for this recipient goes, by the rules of its zone.
pub fn route(snap: &Snapshot, secret: &[u8], recipient: &str, today: i64) -> Route {
    let Some((local, domain)) = recipient.rsplit_once('@') else { return Route::Reject("501 5.1.3 that is not an address") };
    // (the real sender inside a rewritten address keeps its spelling)
    let as_written = local;
    let (local, domain) = (local.to_ascii_lowercase(), domain.trim_end_matches('.').to_ascii_lowercase());
    let Some(zone) = snap.find_zone(&domain).filter(|z| z.zone.settings.email_routing && !z.zone.paused) else {
        return Route::Reject("550 5.7.1 mail for that domain is not handled here");
    };
    if local.starts_with("srs0=") {
        return match srs_reverse(secret, as_written, today) {
            Some(original) => Route::Bounce { to: original },
            None => Route::Reject("550 5.1.1 that return address is not valid (any more)"),
        };
    }
    let address = format!("{local}@{domain}");
    // "name+tag@" is "name@" unless there is a rule for the tagged address itself
    let plain = local.split_once('+').map(|(name, _)| format!("{name}@{domain}"));
    let rule = zone
        .email_rules
        .iter()
        .find(|r| r.address == address)
        .or_else(|| zone.email_rules.iter().find(|r| Some(&r.address) == plain.as_ref()))
        .or_else(|| zone.email_rules.iter().find(|r| r.address == "*"));
    match rule {
        Some(rule) if rule.action == "drop" => Route::Drop,
        Some(rule) if rule.action == "worker" => match &rule.worker {
            Some(script) => Route::Worker { script: script.clone(), zone: zone.zone.name.clone() },
            None => Route::Reject("550 5.1.1 email worker not configured"),
        },
        Some(rule) => Route::Forward { to: rule.destinations.clone(), zone: zone.zone.name.clone() },
        None => Route::Reject("550 5.1.1 no such address here"),
    }
}

// ------------------------------------------------------------------ SRS ----

fn srs_hash(secret: &[u8], stamp: &str, domain: &str, local: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let text = format!("srs {stamp} {domain} {local}").to_ascii_lowercase();
    base32(&ring::hmac::sign(&key, text.as_bytes()).as_ref()[..5])[..6].to_ascii_lowercase()
}

/// The day as two base32 characters (it wraps after 1024 days).
fn srs_stamp(day: i64) -> String {
    let day = day.rem_euclid(1024) as u16;
    base32(&[(day >> 2) as u8, ((day & 3) << 6) as u8])[..2].to_ascii_lowercase()
}

/// The sender to pass a forwarded message on with: an address of ours that
/// leads back to the real one. The empty sender (a bounce) stays empty.
pub fn srs_forward(secret: &[u8], sender: &str, zone: &str, today: i64) -> String {
    let Some((local, domain)) = sender.rsplit_once('@') else { return String::new() };
    let stamp = srs_stamp(today);
    format!("srs0={}={stamp}={}={local}@{zone}", srs_hash(secret, &stamp, domain, local), domain.to_ascii_lowercase())
}

/// The real sender behind a rewritten address (its local part), if we made
/// it and not too long ago.
fn srs_reverse(secret: &[u8], local: &str, today: i64) -> Option<String> {
    let mut parts = local.splitn(5, '=');
    let (_, hash, stamp, domain, original) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let (hash, stamp, domain) = (hash.to_ascii_lowercase(), stamp.to_ascii_lowercase(), domain.to_ascii_lowercase());
    if !crate::auth::ct_eq(hash.as_bytes(), srs_hash(secret, &stamp, &domain, original).as_bytes()) {
        return None;
    }
    let fresh = (0..=SRS_DAYS).any(|age| srs_stamp(today - age) == stamp);
    (fresh && !domain.is_empty() && !original.is_empty()).then(|| format!("{original}@{domain}"))
}

// ------------------------------------------------- mail exchangers (DNS) ----

/// Skip a (possibly compressed) name; returns the offset after it.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)? as usize;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        if len == 0 {
            return Some(at + 1);
        }
        at += 1 + len;
    }
}

/// Read a (possibly compressed) name.
fn read_name(msg: &[u8], mut at: usize) -> Option<String> {
    let (mut labels, mut jumps) = (Vec::new(), 0);
    loop {
        let len = *msg.get(at)? as usize;
        if len & 0xc0 == 0xc0 {
            at = (len & 0x3f) << 8 | *msg.get(at + 1)? as usize;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
        } else if len == 0 {
            return Some(labels.join("."));
        } else {
            labels.push(String::from_utf8_lossy(msg.get(at + 1..at + 1 + len)?).to_ascii_lowercase());
            at += 1 + len;
        }
    }
}

fn mx_query(id: u16, domain: &str) -> Vec<u8> {
    let mut q = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in domain.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.extend_from_slice(&[0, 0, 15, 0, 1]);
    q
}

/// The mail exchangers in an answer, best first. Ok(empty): the domain has
/// none (mail then goes to the domain itself). Err: it takes no mail at
/// all, or does not exist (permanent), or the answer is no good (temporary).
fn mx_answer(msg: &[u8], id: u16) -> Result<Vec<String>, Failure> {
    let short = || Failure::temporary("the DNS answer about the mail exchangers is malformed");
    if msg.len() < 12 || msg[0] != (id >> 8) as u8 || msg[1] != id as u8 {
        return Err(short());
    }
    match msg[3] & 0x0f {
        0 => {}
        3 => return Err(Failure::permanent("the destination's domain does not exist")),
        _ => return Err(Failure::temporary("the DNS lookup of the mail exchangers failed")),
    }
    let (questions, answers) = (u16::from_be_bytes([msg[4], msg[5]]), u16::from_be_bytes([msg[6], msg[7]]));
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(msg, at).ok_or_else(short)? + 4;
    }
    let mut found: Vec<(u16, String)> = Vec::new();
    for _ in 0..answers {
        at = skip_name(msg, at).ok_or_else(short)?;
        let head = msg.get(at..at + 10).ok_or_else(short)?;
        let (rtype, len) = (u16::from_be_bytes([head[0], head[1]]), u16::from_be_bytes([head[8], head[9]]) as usize);
        at += 10;
        if at + len > msg.len() {
            return Err(short());
        }
        if rtype == 15 {
            if len < 2 {
                return Err(short());
            }
            let preference = u16::from_be_bytes([*msg.get(at).ok_or_else(short)?, *msg.get(at + 1).ok_or_else(short)?]);
            found.push((preference, read_name(msg, at + 2).ok_or_else(short)?));
        }
        at += len;
    }
    if found.iter().any(|(_, host)| host.is_empty()) {
        return Err(Failure::permanent("the destination's domain says that it takes no mail"));
    }
    found.sort();
    Ok(found.into_iter().map(|(_, host)| host).collect())
}

/// The DNS server this host asks (the first one in /etc/resolv.conf).
async fn system_resolver() -> SocketAddr {
    tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .ok()
        .and_then(|text| text.lines().find_map(|l| l.strip_prefix("nameserver")?.trim().parse::<IpAddr>().ok()))
        .map_or_else(|| SocketAddr::from(([1, 1, 1, 1], 53)), |ip| SocketAddr::new(ip, 53))
}

/// The hosts to hand mail for a domain to, best first.
async fn mail_exchangers(resolver: SocketAddr, domain: &str) -> Result<Vec<String>, Failure> {
    let down = || Failure::temporary("the DNS server could not be asked about the mail exchangers");
    let id = u16::from_be_bytes([ring_random()[0], ring_random()[1]]);
    let query = mx_query(id, domain);
    let asked = async {
        let bind: SocketAddr = if resolver.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
        let socket = UdpSocket::bind(bind).await?;
        socket.send_to(&query, resolver).await?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        if n > 2 && buf[2] & 0x02 != 0 {
            // cut short: the same question over TCP
            let mut tcp = TcpStream::connect(resolver).await?;
            tcp.write_all(&(query.len() as u16).to_be_bytes()).await?;
            tcp.write_all(&query).await?;
            let mut len = [0u8; 2];
            tcp.read_exact(&mut len).await?;
            buf = vec![0u8; u16::from_be_bytes(len) as usize];
            tcp.read_exact(&mut buf).await?;
        }
        std::io::Result::Ok(buf)
    };
    let answer = tokio::time::timeout(Duration::from_secs(8), asked).await.map_err(|_| down())?.map_err(|_| down())?;
    let hosts = mx_answer(&answer, id)?;
    Ok(if hosts.is_empty() { vec![domain.to_string()] } else { hosts })
}

fn ring_random() -> [u8; 2] {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 2];
    let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
    bytes
}

/// Why a message could not be handed on.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// Trying again will not help.
    pub permanent: bool,
    pub message: String,
}

impl Failure {
    fn temporary(message: impl Into<String>) -> Failure {
        Failure { permanent: false, message: message.into() }
    }
    fn permanent(message: impl Into<String>) -> Failure {
        Failure { permanent: true, message: message.into() }
    }
}

// ------------------------------------------------------------ SMTP out ----

/// A server that takes our outgoing mail for everybody (a "smarthost"),
/// for networks that do not let port 25 out.
#[derive(Debug, Clone, PartialEq)]
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// TLS from the first byte (smtps://) instead of STARTTLS.
    pub implicit_tls: bool,
    pub login: Option<(String, String)>,
}

impl Relay {
    /// smtp://[user:password@]host[:587] (STARTTLS, which is then required)
    /// or smtps://[user:password@]host[:465].
    pub fn parse(url: &str) -> Result<Relay, String> {
        let decode = |s: &str| percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned();
        let (implicit_tls, rest) = match url.trim().split_once("://") {
            Some(("smtp", rest)) => (false, rest),
            Some(("smtps", rest)) => (true, rest),
            _ => return Err(format!("'{url}' is not an smtp:// or smtps:// URL")),
        };
        let rest = rest.trim_end_matches('/');
        let (login, server) = match rest.rsplit_once('@') {
            Some((login, server)) => {
                let (user, password) = login.split_once(':').unwrap_or((login, ""));
                (Some((decode(user), decode(password))), server)
            }
            None => (None, rest),
        };
        let (host, port) = match server.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(']') || port.bytes().all(|b| b.is_ascii_digit()) => {
                (host, port.parse::<u16>().map_err(|_| format!("'{port}' is not a port"))?)
            }
            _ => (server, if implicit_tls { 465 } else { 587 }),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        if host.is_empty() {
            return Err(format!("'{url}' names no server"));
        }
        Ok(Relay { host, port, implicit_tls, login })
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One SMTP connection, either way round: lines in, lines out.
struct Conn {
    io: Option<Box<dyn Io>>,
    buf: Vec<u8>,
}

impl Conn {
    fn new(io: impl Io + 'static) -> Conn {
        Conn { io: Some(Box::new(io)), buf: Vec::new() }
    }

    fn io(&mut self) -> std::io::Result<&mut Box<dyn Io>> {
        self.io.as_mut().ok_or_else(|| std::io::Error::other("the connection is gone"))
    }

    async fn fill(&mut self) -> std::io::Result<()> {
        let mut chunk = [0u8; 8192];
        let n = tokio::time::timeout(IDLE, self.io()?.read(&mut chunk)).await.map_err(|_| std::io::Error::other("timed out"))??;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    /// The next line, without its line end. Ok(None): it is longer than a line may be.
    async fn line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = self.buf.iter().position(|b| *b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=end).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            if self.buf.len() > MAX_LINE {
                self.buf.clear();
                return Ok(None);
            }
            self.fill().await?;
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let io = self.io()?;
        tokio::time::timeout(IDLE, async {
            io.write_all(bytes).await?;
            io.flush().await
        })
        .await
        .map_err(|_| std::io::Error::other("timed out"))?
    }

    /// A server's reply: its code and its (last) line of text.
    async fn reply(&mut self) -> Result<(u16, String), Failure> {
        let lost = |e: std::io::Error| Failure::temporary(format!("the connection to the next server broke: {e}"));
        for _ in 0..MAX_REPLY_LINES {
            let line = self.line().await.map_err(lost)?.unwrap_or_default();
            let text = String::from_utf8_lossy(&line).into_owned();
            let code = text.get(..3).and_then(|c| c.parse::<u16>().ok()).ok_or_else(|| Failure::temporary("the next server does not speak SMTP"))?;
            if text.as_bytes().get(3) != Some(&b'-') {
                return Ok((code, text.get(4..).unwrap_or_default().to_string()));
            }
        }
        Err(Failure::temporary("the next server sent too many reply lines"))
    }

    /// Say something and expect a reply of a class (2 for 2xx ...); a
    /// refusal is the failure the server makes it: 4xx for now, 5xx for good.
    async fn command(&mut self, line: &str, class: u16) -> Result<String, Failure> {
        let lost = |e: std::io::Error| Failure::temporary(format!("the connection to the next server broke: {e}"));
        self.send(format!("{line}\r\n").as_bytes()).await.map_err(lost)?;
        self.expect(class).await
    }

    async fn expect(&mut self, class: u16) -> Result<String, Failure> {
        let (code, text) = self.reply().await?;
        if code / 100 == class {
            return Ok(text);
        }
        Err(Failure { permanent: code / 100 == 5, message: format!("the next server said: {code} {text}") })
    }

    /// EHLO, and what the server offers (upper case, one keyword per line).
    async fn ehlo(&mut self, name: &str) -> Result<Vec<String>, Failure> {
        let lost = |e: std::io::Error| Failure::temporary(format!("the connection to the next server broke: {e}"));
        self.send(format!("EHLO {name}\r\n").as_bytes()).await.map_err(lost)?;
        let mut offers = Vec::new();
        for _ in 0..MAX_REPLY_LINES {
            let line = self.line().await.map_err(lost)?.unwrap_or_default();
            let text = String::from_utf8_lossy(&line).into_owned();
            if !text.starts_with("250") {
                return Err(Failure { permanent: text.starts_with('5'), message: format!("the next server said: {text}") });
            }
            offers.push(text.get(4..).unwrap_or_default().to_ascii_uppercase());
            if text.as_bytes().get(3) != Some(&b'-') {
                return Ok(offers);
            }
        }
        Err(Failure::temporary("the next server sent too many EHLO lines"))
    }

    async fn start_tls(&mut self, config: Arc<rustls::ClientConfig>, name: &str) -> Result<(), Failure> {
        let io = self.io.take().ok_or_else(|| Failure::temporary("the connection is gone"))?;
        let name = rustls::pki_types::ServerName::try_from(name.to_string()).map_err(|_| Failure::temporary("the next server has no usable name for TLS"))?;
        let tls = tokio::time::timeout(Duration::from_secs(20), tokio_rustls::TlsConnector::from(config).connect(name, io)).await;
        match tls {
            Ok(Ok(stream)) => {
                let stream: Box<dyn Io> = Box::new(stream);
                (self.io, self.buf) = (Some(stream), Vec::new());
                Ok(())
            }
            Ok(Err(e)) => Err(Failure::temporary(format!("TLS with the next server failed: {e}"))),
            Err(_) => Err(Failure::temporary("TLS with the next server timed out")),
        }
    }
}

/// A message as it goes over the wire after DATA: lines that start with a
/// dot get another one, and a line with a single dot ends it.
fn wire_form(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut at_line_start = true;
    for b in data {
        if at_line_start && *b == b'.' {
            out.push(b'.');
        }
        out.push(*b);
        at_line_start = *b == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// How to talk to the server a message is handed to.
struct Hop<'a> {
    /// Name to verify (or just to name) in TLS.
    name: &'a str,
    /// The TLS configuration to use for STARTTLS, if any.
    tls: Option<Arc<rustls::ClientConfig>>,
    /// Without TLS nothing is sent (relays: the password would go in the clear).
    require_tls: bool,
    login: Option<&'a (String, String)>,
}

/// One SMTP transaction: this message, from this sender, to these mailboxes.
async fn submit(conn: &mut Conn, helo: &str, hop: Hop<'_>, from: &str, to: &[String], data: &[u8]) -> Result<(), Failure> {
    let lost = |e: std::io::Error| Failure::temporary(format!("the connection to the next server broke: {e}"));
    conn.expect(2).await?;
    let mut offers = conn.ehlo(helo).await?;
    let secured = match &hop.tls {
        Some(config) if offers.iter().any(|o| o == "STARTTLS") => {
            conn.command("STARTTLS", 2).await?;
            conn.start_tls(config.clone(), hop.name).await?;
            offers = conn.ehlo(helo).await?;
            true
        }
        _ => false,
    };
    if hop.require_tls && !secured {
        return Err(Failure::temporary("the relay does not offer TLS: not sending the password or the mail in the clear"));
    }
    if let Some((user, password)) = hop.login {
        if !offers.iter().any(|o| o.starts_with("AUTH") && o.contains("PLAIN")) {
            return Err(Failure::temporary("the relay does not take a login the way we give it (AUTH PLAIN)"));
        }
        let token = base64_std(format!("\0{user}\0{password}").as_bytes());
        conn.command(&format!("AUTH PLAIN {token}"), 2).await.map_err(|e| Failure::temporary(format!("the relay does not accept our login: {}", e.message)))?;
    }
    conn.command(&format!("MAIL FROM:<{from}>"), 2).await?;
    for recipient in to {
        conn.command(&format!("RCPT TO:<{recipient}>"), 2).await?;
    }
    conn.command("DATA", 3).await?;
    conn.send(&wire_form(data)).await.map_err(lost)?;
    conn.expect(2).await?;
    let _ = conn.send(b"QUIT\r\n").await;
    Ok(())
}

/// Base64 with padding (what AUTH wants).
fn base64_std(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

// ------------------------------------------------------------- the node ----

fn today() -> i64 {
    chrono::Utc::now().timestamp().div_euclid(86400)
}

/// E-mail routing on this node: the SMTP listener's state.
pub struct Mail {
    store: Arc<Store>,
    /// Signs rewritten sender addresses; the same on every node of a fleet.
    secret: Vec<u8>,
    /// The names this server is known by (MX targets); the first one is how it greets.
    pub hosts: Vec<String>,
    pub relay: Option<Relay>,
    tls: Option<Arc<rustls::ServerConfig>>,
    verified: Arc<rustls::ClientConfig>,
    unverified: Arc<rustls::ClientConfig>,
    resolver: tokio::sync::OnceCell<SocketAddr>,
    /// Tests: where all outgoing mail goes instead of the destinations' exchangers.
    exchanger: Option<SocketAddr>,
    /// The last messages: who, to whom, what came of it.
    activity: Mutex<VecDeque<Value>>,
    /// Message and destination of what was handed on lately, so that a
    /// sender's retry (after another destination failed) is not a duplicate.
    delivered: Mutex<HashMap<String, Instant>>,
    /// Caps concurrent DATA payloads buffered in memory.
    data_slots: Arc<tokio::sync::Semaphore>,
    /// Edge handle so Email Routing Workers can execute `fetch()` subrequests.
    pub edge: std::sync::OnceLock<Arc<crate::edge::Edge>>,
    pub listening: Mutex<Option<SocketAddr>>,
}

impl Mail {
    pub fn new(store: Arc<Store>, secret: &[u8], hosts: Vec<String>, relay: Option<Relay>) -> anyhow::Result<Mail> {
        Ok(Mail {
            tls: crate::edge::tls::server_config(store.clone()).ok(),
            store,
            secret: secret.to_vec(),
            hosts,
            relay,
            verified: crate::edge::tls::client_config(true)?,
            unverified: crate::edge::tls::client_config(false)?,
            resolver: tokio::sync::OnceCell::new(),
            exchanger: None,
            activity: Mutex::default(),
            delivered: Mutex::default(),
            data_slots: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_DATA)),
            edge: std::sync::OnceLock::new(),
            listening: Mutex::default(),
        })
    }

    fn name(&self) -> &str {
        self.hosts.first().map_or("localhost", String::as_str)
    }

    /// How this node handles mail, for the API.
    pub fn status(&self) -> Value {
        json!({
            "listening": self.listening.lock().unwrap().map(|a| a.to_string()),
            "hosts": self.hosts,
            "relay": self.relay.as_ref().map(|r| format!("{}:{}", r.host, r.port)),
        })
    }

    /// The last messages, newest first.
    pub fn activity(&self) -> Vec<Value> {
        self.activity.lock().unwrap().iter().rev().cloned().collect()
    }

    fn note(&self, from: &str, to: &str, result: &str, detail: &str) {
        let mut log = self.activity.lock().unwrap();
        log.push_back(json!({ "at": crate::store::now(), "from": from, "to": to, "result": result, "detail": detail }));
        while log.len() > ACTIVITY_KEPT {
            log.pop_front();
        }
    }

    async fn connect(addr: (&str, u16)) -> Result<TcpStream, Failure> {
        match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(Failure::temporary(format!("cannot connect to {}:{}: {e}", addr.0, addr.1))),
            Err(_) => Err(Failure::temporary(format!("cannot connect to {}:{}: timed out", addr.0, addr.1))),
        }
    }

    async fn connect_public(host: &str, port: u16) -> Result<TcpStream, Failure> {
        let lookup = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| Failure::temporary(format!("cannot resolve {host}: timed out")))?
            .map_err(|e| Failure::temporary(format!("cannot resolve {host}: {e}")))?;
        let addrs: Vec<SocketAddr> = lookup.filter(|a| is_public_ip(a.ip())).collect();
        if addrs.is_empty() {
            return Err(Failure::permanent(format!("mail exchanger {host} has no public address")));
        }
        let mut last = Failure::temporary(format!("cannot connect to {host}:{port}"));
        for addr in addrs.into_iter().take(3) {
            match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last = Failure::temporary(format!("cannot connect to {host}:{port}: {e}")),
                Err(_) => last = Failure::temporary(format!("cannot connect to {host}:{port}: timed out")),
            }
        }
        Err(last)
    }

    /// Hand a message to the mailboxes of one domain (or, through a relay, of any).
    async fn send(&self, domain: &str, from: &str, to: &[String], data: &[u8]) -> Result<(), Failure> {
        if let Some(relay) = &self.relay {
            let stream = Self::connect((&relay.host, relay.port)).await?;
            let local = relay.host == "localhost" || relay.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            let mut conn = Conn::new(stream);
            if relay.implicit_tls {
                conn.start_tls(self.verified.clone(), &relay.host).await?;
            }
            let hop = Hop {
                name: &relay.host,
                tls: (!relay.implicit_tls).then(|| self.verified.clone()),
                require_tls: !relay.implicit_tls && !local,
                login: relay.login.as_ref(),
            };
            return tokio::time::timeout(IDLE, submit(&mut conn, self.name(), hop, from, to, data))
                .await
                .unwrap_or_else(|_| Err(Failure::temporary("the relay timed out")));
        }
        if let Some(addr) = self.exchanger {
            let mut conn = Conn::new(Self::connect((&addr.ip().to_string(), addr.port())).await?);
            return submit(&mut conn, self.name(), Hop { name: domain, tls: None, require_tls: false, login: None }, from, to, data).await;
        }
        let mut last = Failure::temporary("the destination has no mail exchanger");
        let resolver = *self.resolver.get_or_init(|| system_resolver()).await;
        for host in mail_exchangers(resolver, domain).await?.into_iter().take(3) {
            let attempt = async {
                let mut conn = Conn::new(Self::connect_public(&host, 25).await?);
                // encrypted if the other side can, whatever its certificate: better than in the clear
                let hop = Hop { name: &host, tls: Some(self.unverified.clone()), require_tls: false, login: None };
                submit(&mut conn, self.name(), hop, from, to, data).await
            };
            match tokio::time::timeout(IDLE, attempt).await.unwrap_or_else(|_| Err(Failure::temporary("the next server timed out"))) {
                Ok(()) => return Ok(()),
                Err(e) if e.permanent => return Err(e),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Pass a message on along its routes. The SMTP reply for the sender.
    async fn hand_on(&self, sender: &str, routes: &[(String, Route)], data: &[u8]) -> String {
        let digest = crate::release::sha256_hex(data);
        // (envelope sender, destination domain) -> destinations, each with the address it was sent to
        let mut batches: Vec<(String, String, Vec<String>, String)> = Vec::new();
        let (mut delivered, mut temporary, mut permanent) = (0, None, None);
        for (recipient, route) in routes {
            let (from, to) = match route {
                Route::Forward { to, zone } => (srs_forward(&self.secret, sender, zone, today()), to.clone()),
                Route::Worker { script, zone } => {
                    let snap = self.store.snapshot();
                    let Some(worker) = snap.workers.get(script).cloned() else {
                        self.note(sender, recipient, "deferred", &format!("worker '{script}' missing"));
                        temporary = Some(format!("worker '{script}' not found"));
                        continue;
                    };
                    let Some(edge) = self.edge.get().cloned() else {
                        self.note(sender, recipient, "deferred", "worker runtime unavailable");
                        temporary = Some("worker runtime unavailable".into());
                        continue;
                    };
                    match crate::workers::run_email(edge, snap, worker, sender, recipient, bytes::Bytes::copy_from_slice(data)).await {
                        Ok(outcome) => {
                            if let Some(reason) = outcome.reject {
                                self.note(sender, recipient, "rejected", &format!("{script}: {reason}"));
                                permanent = Some(reason);
                                continue;
                            }
                            if outcome.forwards.is_empty() {
                                self.note(sender, recipient, "worker", script);
                                delivered += 1;
                                continue;
                            }
                            let mut dests = Vec::new();
                            for f in outcome.forwards {
                                if let Ok(mb) = crate::items::check_mailbox("forward", &f) {
                                    dests.push(mb);
                                }
                            }
                            if dests.is_empty() {
                                self.note(sender, recipient, "worker", script);
                                delivered += 1;
                                continue;
                            }
                            (srs_forward(&self.secret, sender, zone, today()), dests)
                        }
                        Err(why) => {
                            self.note(sender, recipient, "deferred", &format!("{script}: {why}"));
                            tracing::warn!("email worker {script} for {recipient} failed: {why}");
                            temporary = Some(why);
                            continue;
                        }
                    }
                }
                Route::Bounce { to } => (String::new(), vec![to.clone()]),
                Route::Drop => {
                    self.note(sender, recipient, "dropped", "");
                    continue;
                }
                Route::Reject(_) => continue,
            };
            for destination in to {
                let domain = destination.rsplit_once('@').map(|(_, d)| d.to_string()).unwrap_or_default();
                let key = if self.relay.is_some() { String::new() } else { domain };
                match batches.iter_mut().find(|b| b.0 == from && b.1 == key) {
                    Some(batch) if !batch.2.contains(&destination) => batch.2.push(destination),
                    Some(_) => {}
                    None => batches.push((from.clone(), key, vec![destination], recipient.clone())),
                }
            }
        }
        for (from, domain, to, recipient) in batches {
            let fresh: Vec<String> = {
                let mut seen = self.delivered.lock().unwrap();
                seen.retain(|_, at| at.elapsed() < Duration::from_secs(5 * 86400));
                to.into_iter().filter(|d| !seen.contains_key(&format!("{digest} {d}"))).collect()
            };
            if fresh.is_empty() {
                delivered += 1; // handed on at an earlier attempt
                continue;
            }
            let domain = if domain.is_empty() { "relay".to_string() } else { domain };
            match self.send(&domain, &from, &fresh, data).await {
                Ok(()) => {
                    delivered += 1;
                    let mut seen = self.delivered.lock().unwrap();
                    if seen.len() >= MAX_DELIVERED {
                        seen.clear();
                    }
                    for destination in &fresh {
                        seen.insert(format!("{digest} {destination}"), Instant::now());
                    }
                    self.note(sender, &recipient, "forwarded", &fresh.join(", "));
                }
                Err(e) => {
                    self.note(sender, &recipient, if e.permanent { "refused" } else { "deferred" }, &format!("{}: {}", fresh.join(", "), e.message));
                    tracing::warn!("mail for {recipient} not handed on to {}: {}", fresh.join(", "), e.message);
                    if e.permanent {
                        permanent = Some(e.message);
                    } else {
                        temporary = Some(e.message);
                    }
                }
            }
        }
        match (temporary, permanent, delivered) {
            (Some(_), _, _) => "451 4.4.1 the message could not be passed on right now: try again later".into(),
            (None, Some(why), 0) => format!("550 5.7.1 the message was refused where it was to be passed on: {}", why.chars().filter(|c| !c.is_control()).take(200).collect::<String>()),
            _ => "250 2.0.0 passed on".into(),
        }
    }

    /// Accept SMTP connections.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        *self.listening.lock().unwrap() = listener.local_addr().ok();
        let limit = Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS));
        loop {
            let Ok(permit) = limit.clone().acquire_owned().await else { return };
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = this.session(stream, peer).await;
                    });
                }
                Err(e) => {
                    tracing::warn!("smtp accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// One SMTP session with a sender.
    async fn session(&self, stream: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        let mut conn = Conn::new(stream);
        let (mut helo, mut secured, mut errors) = (String::new(), false, 0);
        let mut sender: Option<String> = None;
        let mut routes: Vec<(String, Route)> = Vec::new();
        conn.send(format!("220 {} ESMTP fucf\r\n", self.name()).as_bytes()).await?;
        loop {
            let Some(line) = conn.line().await? else {
                conn.send(b"500 5.5.2 line too long\r\n").await?;
                return Ok(());
            };
            let line = String::from_utf8_lossy(&line).into_owned();
            let (verb, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let reply: String = match verb.to_ascii_uppercase().as_str() {
                "EHLO" | "HELO" => {
                    helo = rest.trim().chars().filter(|c| c.is_ascii_graphic()).take(255).collect();
                    (sender, routes) = (None, Vec::new());
                    if verb.eq_ignore_ascii_case("HELO") {
                        format!("250 {}", self.name())
                    } else {
                        let tls = if self.tls.is_some() && !secured { "250-STARTTLS\r\n" } else { "" };
                        format!("250-{}\r\n250-SIZE {MAX_MESSAGE}\r\n250-8BITMIME\r\n{tls}250 ENHANCEDSTATUSCODES", self.name())
                    }
                }
                "STARTTLS" if !secured => {
                    if !conn.buf.is_empty() {
                        conn.send(b"500 5.5.1 pipelining before STARTTLS is not allowed\r\n").await?;
                        return Ok(());
                    }
                    match (&self.tls, conn.io.take()) {
                        (Some(config), Some(io)) => {
                            let mut plain = Conn { io: Some(io), buf: Vec::new() };
                            plain.send(b"220 2.0.0 go ahead\r\n").await?;
                            let io = plain.io.take().expect("just put there");
                            let accepted = tokio::time::timeout(Duration::from_secs(20), tokio_rustls::TlsAcceptor::from(config.clone()).accept(io)).await;
                            let Ok(Ok(tls)) = accepted else { return Ok(()) };
                            conn = Conn::new(tls);
                            (secured, helo, sender, routes) = (true, String::new(), None, Vec::new());
                            continue;
                        }
                        _ => "454 4.7.0 TLS is not available".into(),
                    }
                }
                "MAIL" => match address_of(rest, "FROM:") {
                    _ if helo.is_empty() => "503 5.5.1 say EHLO first".into(),
                    _ if sender.is_some() => "503 5.5.1 one message at a time".into(),
                    Some((_, params)) if declared_size(params) > MAX_MESSAGE => "552 5.3.4 the message is too big".into(),
                    Some((address, _)) => {
                        sender = Some(address);
                        "250 2.1.0 ok".into()
                    }
                    None => "501 5.5.4 MAIL FROM:<address>".into(),
                },
                "RCPT" => match address_of(rest, "TO:") {
                    _ if sender.is_none() => "503 5.5.1 MAIL first".into(),
                    _ if routes.len() >= MAX_RECIPIENTS => "452 4.5.3 too many recipients".into(),
                    Some((address, _)) => match route(&self.store.snapshot(), &self.secret, &address, today()) {
                        Route::Bounce { .. } if sender.as_deref() != Some("") => {
                            errors += 1;
                            let reply = "550 5.7.1 SRS addresses only accept bounces";
                            self.note(sender.as_deref().unwrap_or_default(), &address, "rejected", &reply[4..]);
                            reply.into()
                        }
                        Route::Reject(reply) => {
                            errors += 1;
                            self.note(sender.as_deref().unwrap_or_default(), &address, "rejected", &reply[4..]);
                            reply.into()
                        }
                        found => {
                            routes.push((address, found));
                            "250 2.1.5 ok".into()
                        }
                    },
                    None => "501 5.5.4 RCPT TO:<address>".into(),
                },
                "DATA" if routes.is_empty() => "503 5.5.1 no recipients".into(),
                "DATA" => {
                    let Ok(_data_permit) = tokio::time::timeout(Duration::from_secs(10), self.data_slots.acquire()).await else {
                        conn.send(b"451 4.3.2 busy: try again later\r\n").await?;
                        continue;
                    };
                    conn.send(b"354 end with a line that has only a dot\r\n").await?;
                    let from = sender.take().unwrap_or_default();
                    let taken = std::mem::take(&mut routes);
                    match conn.data(MAX_MESSAGE).await? {
                        None => "552 5.3.4 the message is too big".into(),
                        Some(body) if body.split(|b| *b == b'\n').take_while(|l| !l.is_empty() && *l != b"\r").filter(|l| l.len() >= 9 && l[..9].eq_ignore_ascii_case(b"received:")).count() > MAX_HOPS => {
                            "554 5.4.6 the message goes in circles".into()
                        }
                        Some(body) => {
                            let with = if secured { "ESMTPS" } else { "ESMTP" };
                            let mut message = format!(
                                "Received: from {helo} ([{}])\r\n\tby {} (fucf) with {with};\r\n\t{}\r\n",
                                peer.ip().to_canonical(),
                                self.name(),
                                chrono::Utc::now().to_rfc2822()
                            )
                            .into_bytes();
                            message.extend_from_slice(&body);
                            self.hand_on(&from, &taken, &message).await
                        }
                    }
                }
                "RSET" => {
                    (sender, routes) = (None, Vec::new());
                    "250 2.0.0 ok".into()
                }
                "NOOP" => "250 2.0.0 ok".into(),
                "VRFY" => "252 2.1.5 send some mail and see".into(),
                "QUIT" => {
                    conn.send(format!("221 2.0.0 {} closing\r\n", self.name()).as_bytes()).await?;
                    return Ok(());
                }
                _ => {
                    errors += 1;
                    "502 5.5.1 command not recognized".into()
                }
            };
            if errors > 10 {
                conn.send(b"421 4.7.0 too many errors\r\n").await?;
                return Ok(());
            }
            conn.send(format!("{reply}\r\n").as_bytes()).await?;
        }
    }
}

/// The address in "FROM:<a@b> PARAMS" / "TO:<a@b>", and what follows it.
fn address_of<'a>(rest: &'a str, keyword: &str) -> Option<(String, &'a str)> {
    let rest = rest.trim_start();
    let after = rest.get(..keyword.len()).filter(|k| k.eq_ignore_ascii_case(keyword)).map(|_| rest[keyword.len()..].trim_start())?;
    let (address, params) = after.strip_prefix('<')?.split_once('>')?;
    // a source route ("@a,@b:user@c") is ignored, as the standard says
    let address = address.rsplit_once(':').map_or(address, |(_, a)| a);
    let sane = address.len() <= 320 && address.bytes().all(|b| b.is_ascii_graphic()) && !address.contains(['<', '>']) && (address.is_empty() || address.contains('@'));
    sane.then(|| (address.to_string(), params))
}

/// The SIZE a sender declares with MAIL FROM, if any.
fn declared_size(params: &str) -> usize {
    params.split_whitespace().find_map(|p| p.get(..5).filter(|k| k.eq_ignore_ascii_case("SIZE=")).and_then(|_| p[5..].parse().ok())).unwrap_or(0)
}

/// Is `ip` a globally routable address (refuses loopback, private, link-local,
/// multicast and unspecified addresses when connecting to external mail exchangers)?
fn is_public_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !(a == 100 && (64..=127).contains(&b)) // RFC 6598 CGNAT
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unspecified()
                && (seg & 0xfe00) != 0xfc00 // fc00::/7 ULA (includes AWS fd00:ec2::254)
                && (seg & 0xffc0) != 0xfe80 // fe80::/10 link-local
        }
    }
}

impl Conn {
    /// What follows DATA, up to the line with only a dot (`<CRLF>.<CRLF>`),
    /// with dot-stuffing removed. Bare LF lines do not end DATA (prevents
    /// SMTP smuggling across relays). None: more than the limit.
    async fn data(&mut self, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
        let (mut body, mut over) = (Vec::new(), false);
        loop {
            let Some(end) = self.buf.iter().position(|b| *b == b'\n') else {
                if self.buf.len() > limit {
                    (over, self.buf) = (true, Vec::new());
                } else if over && self.buf.len() > MAX_LINE {
                    // keep only the last two bytes so a split ".\r\n" is not missed
                    let drain = self.buf.len() - 2;
                    self.buf.drain(..drain);
                }
                self.fill().await?;
                continue;
            };
            let line: Vec<u8> = self.buf.drain(..=end).collect();
            if line == b".\r\n" {
                return Ok((!over).then_some(body));
            }
            if !over {
                let slice = if line.starts_with(b".") { &line[1..] } else { &line };
                // normalize bare LF to CRLF so downstream relays see consistent line endings
                if slice.ends_with(b"\n") && !slice.ends_with(b"\r\n") {
                    body.extend_from_slice(&slice[..slice.len() - 1]);
                    body.extend_from_slice(b"\r\n");
                } else {
                    body.extend_from_slice(slice);
                }
                over = body.len() > limit;
                if over {
                    body = Vec::new();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::EmailRule;
    use crate::store::testutil::temp_store;

    const SECRET: &[u8] = b"fleet token";

    fn routed() -> (Arc<Store>, String) {
        let store = Arc::new(temp_store());
        let zone = store.create_zone("example.com").unwrap().id;
        store.update_setting(&zone, "email_routing", json!(true)).unwrap();
        let rule = |v| store.save_item::<EmailRule>(&zone, None, v, true).unwrap();
        rule(json!({ "address": "Hello", "destinations": ["Owner@Mailbox.example"] }));
        rule(json!({ "address": "team@example.com", "destinations": ["a@one.example", "b@two.example", "full@two.example"] }));
        rule(json!({ "address": "spam", "action": "drop", "destinations": ["x@y.example"] }));
        rule(json!({ "address": "old@example.com", "destinations": ["gone@two.example"] }));
        rule(json!({ "address": "off", "destinations": ["a@one.example"], "enabled": false }));
        (store, zone)
    }

    #[test]
    fn rules_decide_where_mail_goes() {
        let (store, zone) = routed();
        let to = |address: &str| route(&store.snapshot(), SECRET, address, 100);
        let forward = |list: &[&str]| Route::Forward { to: list.iter().map(|s| s.to_string()).collect(), zone: "example.com".into() };
        assert_eq!(to("hello@example.com"), forward(&["Owner@mailbox.example"]));
        assert_eq!(to("HELLO@Example.COM."), forward(&["Owner@mailbox.example"]));
        assert_eq!(to("hello+shop@example.com"), forward(&["Owner@mailbox.example"]), "a tag after + is the same mailbox");
        assert_eq!(to("spam@example.com"), Route::Drop);
        for nobody in ["nobody@example.com", "off@example.com", "hello@sub.example.com", "hello@other.org", "hello"] {
            assert!(matches!(to(nobody), Route::Reject(_)), "{nobody}");
        }
        // what a rule may be
        let bad = |v| store.save_item::<EmailRule>(&zone, None, v, true).is_err();
        assert!(bad(json!({ "address": "hello", "destinations": ["x@y.example"] })), "one rule per address");
        assert!(bad(json!({ "address": "a@other.org", "destinations": ["x@y.example"] })), "an address of another domain");
        assert!(bad(json!({ "address": "b", "destinations": [] })) && bad(json!({ "address": "b", "destinations": ["not an address"] })));
        assert!(bad(json!({ "address": "b", "destinations": ["someone@example.com"] })), "forwarding into the zone itself goes in circles");
        assert!(bad(json!({ "address": "b", "action": "bounce", "destinations": ["x@y.example"] })));
        // a catch-all takes what no other rule is for; addresses below the zone can have rules too
        store.save_item::<EmailRule>(&zone, None, json!({ "address": "*", "destinations": ["all@mailbox.example"] }), true).unwrap();
        store.save_item::<EmailRule>(&zone, None, json!({ "address": "info@shop.example.com", "destinations": ["shop@mailbox.example"] }), true).unwrap();
        assert_eq!(to("nobody@example.com"), forward(&["all@mailbox.example"]));
        assert_eq!(to("info@shop.example.com"), forward(&["shop@mailbox.example"]));
        assert_eq!(to("spam@example.com"), Route::Drop);
        // switched off for the zone, nothing is taken
        store.update_setting(&zone, "email_routing", json!(false)).unwrap();
        assert!(matches!(to("hello@example.com"), Route::Reject(_)));
    }

    #[test]
    fn rewritten_senders_lead_back() {
        let (store, _) = routed();
        let rewritten = srs_forward(SECRET, "Alice@Sender.example", "example.com", 100);
        assert!(rewritten.starts_with("srs0=") && rewritten.ends_with("=sender.example=Alice@example.com"), "{rewritten}");
        assert_eq!(srs_forward(SECRET, "", "example.com", 100), "", "a bounce stays a bounce");
        let back = |address: &str, day: i64| route(&store.snapshot(), SECRET, address, day);
        assert_eq!(back(&rewritten, 100), Route::Bounce { to: "Alice@sender.example".into() });
        assert_eq!(back(&rewritten.to_ascii_uppercase().replace("ALICE", "Alice"), 100 + SRS_DAYS), Route::Bounce { to: "Alice@sender.example".into() });
        assert!(matches!(back(&rewritten, 100 + SRS_DAYS + 1), Route::Reject(_)), "too old");
        assert!(matches!(back(&rewritten.replace("Alice", "Mallory"), 100), Route::Reject(_)), "not what we signed");
        assert!(matches!(back(&srs_forward(b"another secret", "alice@sender.example", "example.com", 100), 100), Route::Reject(_)));
        assert_ne!(srs_stamp(1023), srs_stamp(1024));
        assert_eq!(srs_stamp(0), srs_stamp(1024));
    }

    #[test]
    fn finds_mail_exchangers_and_reads_relay_addresses() {
        let query = mx_query(0x1234, "example.com");
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x0f\x00\x01");
        // an answer with two exchangers (names compressed against the question), the worse one first
        let mut answer = query.clone();
        (answer[2], answer[3], answer[7]) = (0x81, 0x80, 2);
        answer.extend_from_slice(b"\xc0\x0c\x00\x0f\x00\x01\x00\x00\x01\x2c\x00\x09\x00\x14\x04mx20\xc0\x0c");
        answer.extend_from_slice(b"\xc0\x0c\x00\x0f\x00\x01\x00\x00\x01\x2c\x00\x09\x00\x0a\x04MX10\xc0\x0c");
        assert_eq!(mx_answer(&answer, 0x1234).unwrap(), ["mx10.example.com", "mx20.example.com"]);
        assert!(mx_answer(&answer, 0x9999).is_err() && mx_answer(&answer[..20], 0x1234).is_err());
        // none at all: mail goes to the domain itself; a "null MX" or no such domain: no mail, for good
        let mut none = query.clone();
        (none[2], none[3]) = (0x81, 0x80);
        assert_eq!(mx_answer(&none, 0x1234).unwrap(), Vec::<String>::new());
        let mut null = none.clone();
        null[7] = 1;
        null.extend_from_slice(b"\xc0\x0c\x00\x0f\x00\x01\x00\x00\x01\x2c\x00\x03\x00\x00\x00");
        assert!(mx_answer(&null, 0x1234).unwrap_err().permanent);
        none[3] = 0x83;
        assert!(mx_answer(&none, 0x1234).unwrap_err().permanent);
        none[3] = 0x82;
        assert!(!mx_answer(&none, 0x1234).unwrap_err().permanent);

        let relay = Relay::parse("smtp://user%40example.com:p%3Ass@Smtp.Example.com").unwrap();
        assert_eq!(relay, Relay { host: "smtp.example.com".into(), port: 587, implicit_tls: false, login: Some(("user@example.com".into(), "p:ss".into())) });
        assert_eq!(Relay::parse("smtps://relay.example:2465/").unwrap(), Relay { host: "relay.example".into(), port: 2465, implicit_tls: true, login: None });
        assert_eq!(Relay::parse("smtps://u:p@relay.example").unwrap().port, 465);
        assert!(Relay::parse("relay.example:587").is_err() && Relay::parse("http://relay.example").is_err() && Relay::parse("smtp://").is_err());
        assert_eq!(base64_std(b"\0user\0pass"), "AHVzZXIAcGFzcw==");
        assert_eq!(wire_form(b"a\r\n.b\r\n..\r\nc"), b"a\r\n..b\r\n...\r\nc\r\n.\r\n");
        assert_eq!(address_of(" from:<a@b.example> SIZE=12", "FROM:"), Some(("a@b.example".into(), " SIZE=12")));
        assert_eq!((address_of("FROM:<>", "FROM:"), declared_size(" BODY=8BITMIME size=99")), (Some((String::new(), "")), 99));
        assert_eq!((address_of("TO:<@relay.example:a@b.example>", "TO:").unwrap().0.as_str(), address_of("TO:a@b.example", "TO:"), address_of("TO:<nobody>", "TO:")), ("a@b.example", None, None));
    }

    type Taken = Arc<Mutex<Vec<(String, Vec<String>, String)>>>;

    /// A mail exchanger that takes everything -- except for "full@" (not
    /// now) and "gone@" (never) -- and remembers what it got.
    async fn exchanger() -> (SocketAddr, Taken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (addr, taken) = (listener.local_addr().unwrap(), Taken::default());
        let seen = taken.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut conn = Conn::new(stream);
                    let (mut from, mut to) = (String::new(), Vec::new());
                    conn.send(b"220 mx.test ESMTP\r\n").await.ok()?;
                    loop {
                        let line = String::from_utf8(conn.line().await.ok()??).ok()?;
                        let reply = match line.split(':').next().unwrap_or_default().to_ascii_uppercase().as_str() {
                            "MAIL FROM" => {
                                from = address_of(&line[5..], "FROM:")?.0;
                                "250 ok"
                            }
                            "RCPT TO" if line.contains("full@") => "452 4.2.2 the mailbox is full",
                            "RCPT TO" if line.contains("gone@") => "550 5.1.1 no such user",
                            "RCPT TO" => {
                                to.push(address_of(&line[5..], "TO:")?.0);
                                "250 ok"
                            }
                            "DATA" => {
                                conn.send(b"354 go on\r\n").await.ok()?;
                                let body = conn.data(1 << 20).await.ok()??;
                                seen.lock().unwrap().push((std::mem::take(&mut from), std::mem::take(&mut to), String::from_utf8_lossy(&body).into_owned()));
                                "250 taken"
                            }
                            "QUIT" => return Some(()),
                            _ => "250-mx.test\r\n250 8BITMIME",
                        };
                        conn.send(format!("{reply}\r\n").as_bytes()).await.ok()?;
                    }
                });
            }
        });
        (addr, taken)
    }

    /// Say these lines to the server one after the other; its replies.
    async fn talk(server: SocketAddr, lines: &[&str]) -> Vec<String> {
        let mut conn = Conn::new(TcpStream::connect(server).await.unwrap());
        let mut replies = vec![conn.reply().await.map(|(code, text)| format!("{code} {text}")).unwrap()];
        for line in lines {
            conn.send(format!("{line}\r\n").as_bytes()).await.unwrap();
            if !line.ends_with("\r\n.") && replies.last().is_some_and(|r| r.starts_with("354")) {
                continue;
            }
            replies.push(conn.reply().await.map(|(code, text)| format!("{code} {text}")).unwrap_or_else(|e| e.message));
        }
        replies
    }

    #[tokio::test]
    async fn takes_mail_and_passes_it_on() {
        let (store, _) = routed();
        let (mx, taken) = exchanger().await;
        let mut mail = Mail::new(store, SECRET, vec!["mx.cdn.example".into()], None).unwrap();
        mail.exchanger = Some(mx);
        let mail = Arc::new(mail);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        tokio::spawn(mail.clone().serve(listener));
        let message = "Subject: hi\r\n\r\nhello\r\n..a line that starts with a dot\r\n.";

        // one mailbox: the destination gets the message as it was, from an address of ours
        let said = talk(server, &["EHLO sender.example", "MAIL FROM:<alice@sender.example> SIZE=100", "RCPT TO:<Hello@Example.com>", "DATA", message, "QUIT"]).await;
        assert!(said[0].starts_with("220 mx.cdn.example") && said[1].starts_with("250") && said[4].starts_with("354"), "{said:?}");
        assert_eq!((said[5].as_str(), &said[6][..3]), ("250 2.0.0 passed on", "221"), "{said:?}");
        let (from, to, body) = taken.lock().unwrap().pop().unwrap();
        assert!(from.starts_with("srs0=") && from.ends_with("=sender.example=alice@example.com"), "{from}");
        assert_eq!(to, ["Owner@mailbox.example"]);
        assert!(body.starts_with("Received: from sender.example ([127.0.0.1])\r\n\tby mx.cdn.example (fucf) with ESMTP;"), "{body}");
        assert!(body.ends_with("Subject: hi\r\n\r\nhello\r\n.a line that starts with a dot\r\n"), "{body}");
        assert_eq!(mail.activity()[0]["result"], "forwarded");

        // a bounce for that address goes back to the real sender, as a bounce
        let said = talk(server, &["EHLO mailbox.example", "MAIL FROM:<>", &format!("RCPT TO:<{from}>"), "DATA", "Subject: could not deliver\r\n\r\n.\r\n."]).await;
        assert_eq!(said[5], "250 2.0.0 passed on", "{said:?}");
        assert_eq!(taken.lock().unwrap().pop().map(|(from, to, _)| (from, to)), Some((String::new(), vec!["alice@sender.example".to_string()])));
        // a non-bounce sender must not abuse an SRS return address as an open relay
        let said = talk(server, &["EHLO evil.example", "MAIL FROM:<spam@evil.example>", &format!("RCPT TO:<{from}>"), "QUIT"]).await;
        assert!(said[3].starts_with("550"), "{said:?}");
        assert!(taken.lock().unwrap().is_empty());

        // what is not ours, nobody's, or out of order is refused before any data
        let said = talk(server, &["MAIL FROM:<a@b.example>", "EHLO x", "RCPT TO:<hello@example.com>", "MAIL FROM:<a@b.example>", "RCPT TO:<nobody@example.com>", "RCPT TO:<someone@elsewhere.example>", "DATA", "RSET", "MAIL FROM:<a@b.example> SIZE=99999999999", "BOGUS"]).await;
        let codes: Vec<&str> = said.iter().map(|r| &r[..3]).collect();
        assert_eq!(codes, ["220", "503", "250", "503", "250", "550", "550", "503", "250", "552", "502"], "{said:?}");
        assert!(taken.lock().unwrap().is_empty());

        // thrown away: taken, and nobody gets it
        let said = talk(server, &["EHLO x", "MAIL FROM:<a@b.example>", "RCPT TO:<spam@example.com>", "DATA", message]).await;
        assert!(said[5].starts_with("250") && taken.lock().unwrap().is_empty() && mail.activity()[0]["result"] == "dropped", "{said:?}");

        // several destinations, one of which cannot take it now: the sender is to try again ...
        let team = ["EHLO x", "MAIL FROM:<a@b.example>", "RCPT TO:<team@example.com>", "DATA", message];
        let said = talk(server, &team).await;
        assert!(said[5].starts_with("451"), "{said:?}");
        // (two.example refused the whole transaction because of full@; one.example got its copy)
        assert_eq!(taken.lock().unwrap().iter().map(|(_, to, _)| to.join(",")).collect::<Vec<_>>(), ["a@one.example"]);
        // ... and when it does, who already has the message is not given it again
        let said = talk(server, &team).await;
        assert!(said[5].starts_with("451") && taken.lock().unwrap().len() == 1, "{said:?}");
        // a destination that never takes it: the sender is told so, for good
        let said = talk(server, &["EHLO x", "MAIL FROM:<a@b.example>", "RCPT TO:<old@example.com>", "DATA", message]).await;
        assert!(said[5].starts_with("550") && said[5].contains("no such user"), "{said:?}");
        assert_eq!(mail.activity()[0]["result"], "refused");
        // a message that has been around too long is going in circles
        let looping = format!("{}Subject: x\r\n\r\n.\r\n.", "Received: by somewhere\r\n".repeat(MAX_HOPS + 1));
        let said = talk(server, &["EHLO x", "MAIL FROM:<a@b.example>", "RCPT TO:<hello@example.com>", "DATA", &looping]).await;
        assert!(said[5].starts_with("554"), "{said:?}");
        assert_eq!(mail.status()["hosts"][0], "mx.cdn.example");
    }
}
