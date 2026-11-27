//! Connections from the edge to origins: pooled HTTP/1.1 clients (and
//! HTTP/2 ones for gRPC) with optional TLS, where connect address, SNI and
//! Host are independent.

use super::Body;
use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tls {
    Off,
    /// Encrypt, but accept any certificate.
    NoVerify,
    Verify,
}

/// Where and how to reach an origin.
#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    /// Host name or IP literal to connect to.
    pub host: String,
    /// Other addresses of the same origin, tried when `host` is down.
    pub alternates: Vec<String>,
    pub port: u16,
    pub tls: Tls,
    pub sni: String,
    pub host_header: String,
    /// Speak HTTP/2 to the origin (what gRPC needs) instead of HTTP/1.1.
    pub h2: bool,
    /// Block loopback, unspecified, link-local/metadata, RFC 1918, CGNAT, and
    /// IPv6 ULA addresses after DNS resolution (enabled for Worker subrequests).
    pub block_private_ips: bool,
}

impl Target {
    /// The server an absolute `http(s)://host[:port]/...` URL points at.
    /// HTTPS servers must present a publicly trusted certificate.
    pub fn from_url(url: &str) -> Result<Target, String> {
        let (target, _) = Self::from_proxy_url(url, false)?;
        if target.h2 || url.starts_with("ws://") || url.starts_with("wss://") {
            return Err(format!("'{url}' is not an http(s) URL"));
        }
        Ok(target)
    }

    /// Parse a reverse-proxy upstream URL (`http://`, `https://`, `h2c://`, `ws://`, `wss://`)
    /// along with its optional base path (empty if `/` or omitted).
    pub fn from_proxy_url(url: &str, tls_insecure: bool) -> Result<(Target, String), String> {
        let uri: Uri = url.parse().map_err(|e| format!("invalid URL '{url}': {e}"))?;
        let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
        let (https, h2) = match scheme.as_str() {
            "https" | "wss" => (true, false),
            "http" | "ws" => (false, false),
            "h2c" => (false, true),
            _ => return Err(format!("'{url}' must use http://, https://, h2c://, ws://, or wss://")),
        };
        let authority = uri.authority().ok_or_else(|| format!("'{url}' names no host"))?;
        let host = authority.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        let raw_path = uri.path();
        let base_path = if raw_path == "/" || raw_path.is_empty() {
            String::new()
        } else {
            raw_path.trim_end_matches('/').to_string()
        };
        Ok((
            Target {
                host: host.clone(),
                alternates: Vec::new(),
                port: authority.port_u16().unwrap_or(if https { 443 } else { 80 }),
                tls: if https {
                    if tls_insecure { Tls::NoVerify } else { Tls::Verify }
                } else {
                    Tls::Off
                },
                sni: host,
                host_header: authority.as_str().to_ascii_lowercase(),
                h2,
                block_private_ips: false,
            },
            base_path,
        ))
    }
}

#[derive(Debug)]
pub enum UpstreamError {
    /// Nothing is listening (Cloudflare 521).
    Down(String),
    /// Connect or response timed out (522 / 524).
    Timeout,
    /// TLS handshake or certificate failure (525 / 526).
    Tls(String),
    Other(String),
}

pub enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Connection for Stream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Link-local and cloud instance metadata addresses (e.g. AWS IMDS
/// 169.254.169.254 / fd00:ec2::254): never a legitimate origin.
pub fn is_blocked_metadata_ip(ip: std::net::IpAddr) -> bool {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xffc0) == 0xfe80 || (s == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254])
        }
    }
}

/// Returns true for loopback, unspecified, link-local/metadata, RFC 1918,
/// CGNAT (100.64.0.0/10), and IPv6 ULA (fc00::/7) addresses.
pub fn is_private_or_reserved_ip(ip: std::net::IpAddr) -> bool {
    if is_blocked_metadata_ip(ip) {
        return true;
    }
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Connects to the URI's host:port and optionally wraps the socket in TLS
/// using a fixed server name (one connector per distinct SNI).
#[derive(Clone)]
struct Connector {
    tls: Option<(TlsConnector, ServerName<'static>)>,
    /// Set for HTTP/2: the address to connect to whatever the URI says.
    /// (There the URI names the origin as the origin knows itself, since it
    /// becomes the request's `:authority`.)
    h2_to: Option<(String, u16)>,
    block_private_ips: bool,
}

impl tower_service::Service<Uri> for Connector {
    type Response = TokioIo<Stream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let (tls, h2_to, block_private_ips) = (self.tls.clone(), self.h2_to.clone(), self.block_private_ips);
        Box::pin(async move {
            let h2 = h2_to.is_some();
            let (host, port) = h2_to.unwrap_or_else(|| {
                let host = uri.host().unwrap_or_default().trim_start_matches('[').trim_end_matches(']').to_string();
                (host, uri.port_u16().unwrap_or(80))
            });
            let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host.as_str(), port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolve timed out"))??
                .collect();
            if addrs.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}")));
            }
            if addrs.iter().any(|a| is_blocked_metadata_ip(a.ip())) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "refusing to connect to link-local or metadata address"));
            }
            if block_private_ips && addrs.iter().any(|a| is_private_or_reserved_ip(a.ip())) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to connect to private, loopback, or reserved address",
                ));
            }
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addrs.as_slice()))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
            let _ = tcp.set_nodelay(true);
            let stream = match tls {
                None => Stream::Plain(tcp),
                Some((connector, name)) => {
                    let s = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS: {e}")))?;
                    if h2 && s.get_ref().1.alpn_protocol() != Some(b"h2") {
                        return Err(io::Error::other("the origin does not offer HTTP/2, which gRPC needs"));
                    }
                    Stream::Tls(Box::new(s))
                }
            };
            Ok(TokioIo::new(stream))
        })
    }
}

type HttpClient = Client<Connector, Body>;

pub struct Upstream {
    /// One client per TLS mode, server name, h2 target, and SSRF guard mode.
    clients: Mutex<HashMap<(Tls, String, Option<(String, u16)>, bool), HttpClient>>,
    verify: Arc<ClientConfig>,
    no_verify: Arc<ClientConfig>,
    /// The same, offering only HTTP/2.
    verify_h2: Arc<ClientConfig>,
    no_verify_h2: Arc<ClientConfig>,
}

fn only_h2(config: &Arc<ClientConfig>) -> Arc<ClientConfig> {
    let mut config = (**config).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn classify(e: &(dyn std::error::Error + 'static)) -> UpstreamError {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<io::Error>() {
            return match io.kind() {
                io::ErrorKind::TimedOut => UpstreamError::Timeout,
                io::ErrorKind::InvalidData => UpstreamError::Tls(io.to_string()),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset | io::ErrorKind::NotFound => {
                    UpstreamError::Down(io.to_string())
                }
                _ => UpstreamError::Other(io.to_string()),
            };
        }
        cur = err.source();
    }
    UpstreamError::Other(e.to_string())
}

impl Upstream {
    pub fn new() -> anyhow::Result<Self> {
        let (verify, no_verify) = (super::tls::client_config(true)?, super::tls::client_config(false)?);
        Ok(Upstream {
            clients: Mutex::default(),
            verify_h2: only_h2(&verify),
            no_verify_h2: only_h2(&no_verify),
            verify,
            no_verify,
        })
    }

    fn client(&self, t: &Target) -> Result<HttpClient, UpstreamError> {
        let h2_to = t.h2.then(|| (t.host.clone(), t.port));
        let key = (
            t.tls,
            if t.tls == Tls::Off { String::new() } else { t.sni.clone() },
            h2_to.clone(),
            t.block_private_ips,
        );
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.get(&key) {
            return Ok(c.clone());
        }
        let tls = match t.tls {
            Tls::Off => None,
            mode => {
                let cfg = match (mode == Tls::Verify, t.h2) {
                    (true, false) => &self.verify,
                    (false, false) => &self.no_verify,
                    (true, true) => &self.verify_h2,
                    (false, true) => &self.no_verify_h2,
                };
                let name = ServerName::try_from(t.sni.clone())
                    .map_err(|_| UpstreamError::Tls(format!("invalid server name '{}'", t.sni)))?;
                Some((TlsConnector::from(cfg.clone()), name))
            }
        };
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_idle_timeout(Duration::from_secs(60)).pool_max_idle_per_host(64);
        if t.h2 {
            // Calls may stay open for long: pings tell a dead connection from a quiet one.
            builder
                .http2_only(true)
                .timer(TokioTimer::new())
                .http2_adaptive_window(true)
                .http2_keep_alive_interval(Duration::from_secs(30))
                .http2_keep_alive_timeout(Duration::from_secs(20));
        }
        let client = builder.build(Connector {
            tls,
            h2_to,
            block_private_ips: t.block_private_ips,
        });
        if clients.len() > 512 {
            clients.clear(); // unbounded SNI variety: drop the pools and start over
        }
        clients.insert(key, client.clone());
        Ok(client)
    }

    /// Send `req` (its URI must be origin-form, e.g. `/a?b`) to `target`.
    pub async fn send(&self, target: &Target, mut req: Request<Body>) -> Result<Response<Incoming>, UpstreamError> {
        let client = self.client(target)?;
        let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        if target.h2 {
            let scheme = if target.tls == Tls::Off { "http" } else { "https" };
            *req.uri_mut() = format!("{scheme}://{}{path}", target.host_header)
                .parse()
                .map_err(|e| UpstreamError::Other(format!("bad origin name: {e}")))?;
            *req.version_mut() = hyper::Version::HTTP_2;
            req.headers_mut().remove(hyper::header::HOST);
            // No limit on the wait for the answer: a stream may be silent for
            // as long as both ends like (the pings watch over the connection).
            return client.request(req).await.map_err(|e| classify(&e));
        }
        let host = if target.host.contains(':') { format!("[{}]", target.host) } else { target.host.clone() };
        *req.uri_mut() = format!("http://{host}:{}{path}", target.port)
            .parse()
            .map_err(|e| UpstreamError::Other(format!("bad origin address: {e}")))?;
        *req.version_mut() = hyper::Version::HTTP_11;
        let host_value = hyper::header::HeaderValue::from_str(&target.host_header)
            .map_err(|_| UpstreamError::Other("invalid host header".into()))?;
        req.headers_mut().insert(hyper::header::HOST, host_value);
        match tokio::time::timeout(RESPONSE_TIMEOUT, client.request(req)).await {
            Err(_) => Err(UpstreamError::Timeout),
            Ok(Err(e)) => Err(classify(&e)),
            Ok(Ok(resp)) => Ok(resp),
        }
    }
}
