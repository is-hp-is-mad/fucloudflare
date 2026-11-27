mod acme;
mod api;
mod auth;
mod dns;
mod edge;
mod expr;
mod fleet;
mod geo;
mod gfw;
mod items;
mod limits;
mod log;
mod mail;
mod node;
mod release;
mod spectrum;
mod store;
mod sync;
mod workers;

use anyhow::Context;
use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// fucloudflare: a self-hosted Cloudflare-style edge platform.
#[derive(Parser)]
#[command(name = "fucf", version)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Public key that releases must be signed with (see release-keygen).
    /// With it, this node takes the releases its fleet rolls out, and goes
    /// back to what it ran before when one does not work. Without it, the
    /// binary is only ever replaced by hand.
    #[arg(long, env = "FUCF_RELEASE_KEY")]
    release_key: Option<String>,

    /// Address for the authoritative DNS server (UDP + TCP).
    #[arg(long, env = "FUCF_DNS_LISTEN", value_delimiter = ',', default_value = "0.0.0.0:53")]
    dns_listen: Vec<SocketAddr>,

    /// MaxMind GeoLite2-Country database; enables steering visitors to the
    /// edge node assigned to their continent.
    #[arg(long, env = "FUCF_GEOIP_DB")]
    geoip_db: Option<PathBuf>,

    /// MaxMind GeoLite2-ASN database; enables steering rules by network operator.
    #[arg(long, env = "FUCF_GEOIP_ASN_DB")]
    geoip_asn_db: Option<PathBuf>,

    /// Domain whose every sub-name resolves to the edge (e.g. cdn.example.com,
    /// delegated to this server). Zones in "partial" mode CNAME their hosts to it.
    #[arg(long, env = "FUCF_CNAME_BASE")]
    cname_base: Option<String>,

    /// Publish the management panel and API on the edge under this host name.
    #[arg(long, env = "FUCF_PANEL_HOST")]
    panel_host: Option<String>,

    /// Node role in the fleet: `peer` (read/write control plane + bidirectional
    /// sync + persistent state) or `accelerate` (read-only ephemeral data plane
    /// with zero persistent control-plane files and suppressed public NS).
    #[arg(long, env = "FUCF_ROLE", value_enum, default_value_t = sync::NodeRole::Peer)]
    role: sync::NodeRole,

    /// Comma-separated peer hosts (`host` reached over HTTPS, or `http(s)://host:port`)
    /// to sync configuration, accounts, and telemetry with.
    #[arg(long, env = "FUCF_PEERS", value_delimiter = ',')]
    peers: Vec<String>,

    /// Deprecated compatibility flag; use `--peers` and `--role` instead.
    #[arg(long, env = "FUCF_PRIMARY", hide = true)]
    primary: Option<String>,

    /// Name of this node in the fleet. Defaults to the configured edge node
    /// that owns one of the `--edge-ip` addresses.
    #[arg(long, env = "FUCF_NODE_NAME")]
    node_name: Option<String>,

    /// ACME directory of the certificate authority that issues the managed
    /// certificates (certificate packs); "off" disables them. Using a CA
    /// means agreeing to its terms of service.
    #[arg(long, env = "FUCF_ACME_DIRECTORY", default_value = acme::LETS_ENCRYPT)]
    acme_directory: String,

    /// E-mail address given to the certificate authority (expiry warnings).
    #[arg(long, env = "FUCF_ACME_EMAIL")]
    acme_email: Option<String>,

    /// Address for the management API. Keep it on loopback or behind TLS.
    #[arg(long, env = "FUCF_API_LISTEN", default_value = "127.0.0.1:8787")]
    api_listen: SocketAddr,

    /// Directory holding persistent state.
    #[arg(long, env = "FUCF_DATA_DIR", default_value = "data")]
    data_dir: PathBuf,

    /// API bearer token. If unset, one is generated and stored in <data-dir>/api_token.
    #[arg(long, env = "FUCF_API_TOKEN", hide_env_values = true)]
    api_token: Option<String>,

    /// Address for the edge HTTP listener (CDN / WAF); "off" disables it.
    #[arg(long, env = "FUCF_HTTP_LISTEN", default_value = "0.0.0.0:80")]
    http_listen: String,

    /// Address for the edge HTTPS listener; "off" disables it.
    #[arg(long, env = "FUCF_HTTPS_LISTEN", default_value = "0.0.0.0:443")]
    https_listen: String,

    /// UDP address for HTTP/3 (QUIC). Defaults to the HTTPS address; "off" disables it.
    #[arg(long, env = "FUCF_HTTP3_LISTEN")]
    http3_listen: Option<String>,

    /// Optional local UDP fallback address for non-CDN QUIC/UDP traffic sharing
    /// `--http3-listen` (e.g. Hysteria 2 on `127.0.0.1:14443`). When set, fucf
    /// decrypts QUIC Initial SNI on UDP 443 and handles all hosted zones with
    /// native multi-domain HTTP/3 while forwarding everything else here.
    #[arg(long, env = "FUCF_QUIC_FALLBACK")]
    quic_fallback: Option<SocketAddr>,

    /// Comma-separated SNI names (exact or `*.domain`) that are always routed
    /// to `--quic-fallback` even if they fall inside a hosted zone (e.g. a
    /// Hysteria 2 SNI that overlaps a zone).
    #[arg(long, env = "FUCF_QUIC_FALLBACK_SNI", value_delimiter = ',')]
    quic_fallback_sni: Vec<String>,

    /// Plain HTTP listener for an HTTP/3 front: another QUIC server that
    /// owns UDP 443 on this node (Hysteria 2 with a "proxy" masquerade, say)
    /// and passes ordinary HTTP/3 visitors on to this address, naming them
    /// in X-Forwarded-For. Whoever can connect is believed: keep it on loopback.
    #[arg(long, env = "FUCF_H3_FRONT_LISTEN")]
    h3_front_listen: Option<SocketAddr>,

    /// Certificate (PEM) that the HTTP/3 front presents to visitors. HTTP/3
    /// is advertised only for the host names it covers.
    #[arg(long, env = "FUCF_H3_FRONT_CERT")]
    h3_front_cert: Option<PathBuf>,

    /// UDP port of the HTTP/3 front, as visitors see it.
    #[arg(long, env = "FUCF_H3_FRONT_PORT", default_value_t = 443)]
    h3_front_port: u16,

    /// TTL in seconds of DNS answers under the CNAME base. A node that goes
    /// down or over its traffic allowance keeps getting visitors for this long.
    #[arg(long, env = "FUCF_EDGE_TTL", default_value_t = 300)]
    edge_ttl: u32,

    /// SMTP listener for inbound e-mail routing (e.g. `0.0.0.0:25`). Off unless set.
    #[arg(long, env = "FUCF_SMTP_LISTEN")]
    smtp_listen: Option<SocketAddr>,

    /// Where forwarded mail is handed instead of each destination's exchangers:
    /// `smtp://[user[:pass]@]host[:port]` (submission, STARTTLS when offered) or `smtps://` (implicit TLS).
    #[arg(long, env = "FUCF_MAIL_RELAY", hide_env_values = true)]
    mail_relay: Option<String>,

    /// The names MX records point at on this node; the first is how the server greets.
    #[arg(long = "mail-host", env = "FUCF_MAIL_HOSTS", value_delimiter = ',')]
    mail_hosts: Vec<String>,

    /// Optional webroot directory for external ACME HTTP-01 challenges
    /// (`<dir>/.well-known/acme-challenge/<token>`), letting fucf serve port 80
    /// without Caddy/nginx.
    #[arg(long, env = "FUCF_ACME_WEBROOT")]
    acme_webroot: Option<PathBuf>,

    /// Write all hosted zone names (plus panel host and CNAME base) to this file
    /// whenever the domain list changes, one domain per line (for HAProxy `-m dom -f`).
    #[arg(long, env = "FUCF_EXPORT_DOMAINS")]
    export_domains: Option<PathBuf>,

    /// Optional local streaming backend for `/cdn-cgi/fucf-warp` (e.g. Xray xhttp:
    /// `h2c://127.0.0.1:10002/ray`, `https://127.0.0.1:10002/ray`, or `h2c://127.0.0.1:2443/`).
    #[arg(long, env = "FUCF_WARP_UPSTREAM")]
    warp_upstream: Option<String>,

    /// Native reverse-proxy HTTP/1.1 + h2c listener(s) (`<ip:port[=tag]>`),
    /// e.g. `127.0.0.1:3443` replacing Caddy behind HAProxy.
    #[arg(long = "proxy-listen", env = "FUCF_PROXY_LISTEN", value_delimiter = ',')]
    proxy_listen: Vec<String>,

    /// Native reverse-proxy HTTPS (TLS + HTTP/2 + HTTP/1.1) listener(s) (`<ip:port>`).
    #[arg(long = "proxy-tls-listen", env = "FUCF_PROXY_TLS_LISTEN", value_delimiter = ',')]
    proxy_tls_listen: Vec<String>,

    /// Native reverse-proxy HTTP/3 (QUIC) listener(s) (`<ip:port>`).
    #[arg(long = "proxy-h3-listen", env = "FUCF_PROXY_H3_LISTEN", value_delimiter = ',')]
    proxy_h3_listen: Vec<String>,

    /// Expect a PROXY protocol v1 header on every edge TCP connection. Only
    /// for listeners that are reachable solely through a trusted TCP proxy.
    #[arg(long, env = "FUCF_PROXY_PROTOCOL")]
    proxy_protocol: bool,

    /// Local IP that Spectrum (TCP/UDP proxy) listeners bind to.
    #[arg(long, env = "FUCF_SPECTRUM_BIND", default_value = "0.0.0.0")]
    spectrum_bind: IpAddr,

    /// Edge cache size in MiB.
    #[arg(long, env = "FUCF_CACHE_MB", default_value_t = 512)]
    cache_mb: usize,

    /// Host names of this deployment's nameservers, assigned to new zones.
    #[arg(long = "ns", env = "FUCF_NS", value_delimiter = ',', default_value = "ns1.fucf.local,ns2.fucf.local")]
    name_servers: Vec<String>,

    /// Public IPs of the edge proxy nodes; proxied records resolve to these
    /// instead of their origin. Without any, proxied records resolve to the origin.
    #[arg(long = "edge-ip", env = "FUCF_EDGE_IPS", value_delimiter = ',')]
    edge_ips: Vec<IpAddr>,
}

/// Tools that go with the server.
#[derive(clap::Subcommand)]
enum Command {
    /// Create a key pair for signing releases. Prints the private key (keep
    /// it where releases are built) and the public key (for every node).
    ReleaseKeygen,
    /// Print the public key that belongs to the private key in KEY_FILE.
    ReleasePubkey { key_file: PathBuf },
    /// Sign BINARY with the private key in KEY_FILE. Prints its digest and
    /// the signature: what the release API of the primary asks for.
    ReleaseSign { key_file: PathBuf, binary: PathBuf },
    /// Fetch URL over HTTP/3 and print the response: is HTTP/3 really
    /// served there, by whom, and under which certificate name?
    H3Get {
        url: String,
        /// Connect to this address (IP or IP:port) instead of resolving the host name.
        #[arg(long)]
        connect: Option<String>,
        /// Accept any certificate.
        #[arg(long)]
        insecure: bool,
    },
}

/// One request over HTTP/3, the way a browser would make it.
async fn h3_get(url: &str, connect: Option<&str>, insecure: bool) -> anyhow::Result<()> {
    use bytes::Buf;
    let uri: hyper::Uri = url.parse().with_context(|| format!("'{url}' is not a URL"))?;
    anyhow::ensure!(uri.scheme_str() == Some("https"), "HTTP/3 needs an https:// URL");
    let host = uri.host().context("the URL names no host")?.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = uri.port_u16().unwrap_or(443);
    let addr: SocketAddr = match connect {
        Some(to) => match to.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, port),
            Err(_) => to.parse().with_context(|| format!("--connect: '{to}' is not an address"))?,
        },
        None => tokio::net::lookup_host((host.as_str(), port)).await?.next().with_context(|| format!("{host} does not resolve"))?,
    };
    let mut tls = (*edge::tls::client_config(!insecure)?).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let bind: SocketAddr = if addr.is_ipv4() {
        if addr.ip().is_loopback() { "127.0.0.1:0" } else { "0.0.0.0:0" }.parse()?
    } else {
        if addr.ip().is_loopback() { "[::1]:0" } else { "[::]:0" }.parse()?
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?)));
    let started = std::time::Instant::now();
    let exchange = async {
        let conn = endpoint.connect(addr, &host)?.await.context("QUIC handshake")?;
        let handshake = started.elapsed();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
        tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = hyper::Request::builder().uri(url).header("user-agent", concat!("fucf-h3-get/", env!("CARGO_PKG_VERSION"))).body(())?;
        let mut stream = sender.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        anyhow::Ok((handshake, response, body))
    };
    let (handshake, response, body) = tokio::time::timeout(Duration::from_secs(20), exchange).await.map_err(|_| anyhow::anyhow!("no HTTP/3 answer from {addr} within 20 s"))??;
    println!("{:?} {} from {addr} (handshake {} ms, total {} ms)", response.version(), response.status(), handshake.as_millis(), started.elapsed().as_millis());
    for (name, value) in response.headers() {
        println!("{name}: {}", String::from_utf8_lossy(value.as_bytes()));
    }
    println!("\n{}", String::from_utf8_lossy(&body[..body.len().min(4096)]));
    Ok(())
}

fn run_command(command: &Command) -> anyhow::Result<()> {
    let read_key = |path: &PathBuf| std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()));
    match command {
        Command::ReleaseKeygen => {
            let (private, public) = release::keygen().map_err(anyhow::Error::msg)?;
            println!("private={private}\npublic={public}");
        }
        Command::ReleasePubkey { key_file } => {
            println!("{}", release::public_key(&read_key(key_file)?).map_err(anyhow::Error::msg)?);
        }
        Command::ReleaseSign { key_file, binary } => {
            let bytes = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
            let sha256 = release::sha256_hex(&bytes);
            let signature = release::sign(&read_key(key_file)?, &sha256).map_err(anyhow::Error::msg)?;
            println!("sha256={sha256}\nsignature={signature}");
        }
        Command::H3Get { .. } => unreachable!("handled by main"),
    }
    Ok(())
}

fn load_token(args: &Args, accel: bool) -> anyhow::Result<String> {
    if let Some(t) = args.api_token.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        return Ok(t.to_string());
    }
    if accel {
        // Accelerate nodes keep zero control-plane files on disk unless explicitly given a token.
        return Ok(format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()));
    }
    let path = args.data_dir.join("api_token");
    if let Ok(t) = std::fs::read_to_string(&path) {
        if !t.trim().is_empty() {
            return Ok(t.trim().to_string());
        }
    }
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    auth::write_private(&path, token.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
    tracing::info!("generated a new API token, stored in {}", path.display());
    Ok(token)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _log_guard = log::init_stdout();
    let args = Args::parse();
    match &args.command {
        Some(Command::H3Get { url, connect, insecure }) => return h3_get(url, connect.as_deref(), *insecure).await,
        Some(command) => return run_command(command),
        None => {}
    }

    let role = args.role;
    let accel = role.is_accelerate();
    if !accel || args.release_key.is_some() {
        std::fs::create_dir_all(&args.data_dir).context("creating data dir")?;
    }
    // If a release was rolled out to this node, this binary is only its
    // launcher: it becomes that release here and now.
    let updater = Arc::new(release::Updater::new(&args.data_dir, args.release_key.clone()));
    if let Some(note) = updater.launch() {
        tracing::warn!("{note}");
    }
    let name_servers = args
        .name_servers
        .iter()
        .map(|n| dns::wire::normalize_name(n).map_err(|e| anyhow::anyhow!("--ns: {e}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let cname_base = match &args.cname_base {
        Some(b) => Some(dns::wire::normalize_name(b).map_err(|e| anyhow::anyhow!("--cname-base: {e}"))?),
        None => None,
    };
    let panel_host = args.panel_host.as_ref().map(|h| h.trim().to_ascii_lowercase());
    let store = if accel {
        Arc::new(store::Store::open_ephemeral(name_servers.clone()))
    } else {
        Arc::new(store::Store::open(&args.data_dir.join("state.json"), name_servers.clone())?)
    };
    let token = load_token(&args, accel)?;
    let mut peer_specs = args.peers.clone();
    if let Some(primary) = &args.primary {
        tracing::warn!("--primary is deprecated; use --peers <url,...> and --role <peer|accelerate>");
        let p = primary.trim();
        if !p.is_empty() && !peer_specs.iter().any(|x| x.trim() == p) {
            peer_specs.push(p.to_string());
        }
    }
    let peer_targets: Vec<edge::upstream::Target> = peer_specs
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(sync::peer_target)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let fleet_self = fleet::self_name(&store, &args.edge_ips, args.node_name.as_deref());
    let sync_node_id = sync::resolve_sync_node_id(if accel { None } else { Some(args.data_dir.as_path()) }, &fleet_self);
    store.set_sync_node_id(sync_node_id.clone());

    let accounts = if accel {
        Arc::new(auth::Accounts::open_ephemeral(panel_host.clone()))
    } else {
        Arc::new(auth::Accounts::open(args.data_dir.join("accounts.json"), panel_host.clone()))
    };
    accounts.set_sync_identity(store.clock(), sync_node_id.clone());
    accounts.set_api_token_secret(&token);
    if !accel {
        accounts.spawn_writer();
    }

    let cache = Arc::new(edge::cache::Cache::new(args.cache_mb * 1024 * 1024));
    // Challenge clearances are derived from the token: the nodes of a fleet
    // share it, so they accept each other's, and restarts do not void them.
    let waf = Arc::new(edge::waf::Waf::with_secret(token.as_bytes()));
    let telemetry = if accel {
        waf.set_outbox_only();
        Arc::new(Telemetry {
            store: store.clone(),
            stats: Arc::new(edge::stats::Stats::new_ephemeral_reporting()),
            waf: waf.clone(),
            stats_path: args.data_dir.join("analytics.json"),
            events_path: args.data_dir.join("events.json"),
            limits: Arc::new(limits::Limits::open_ephemeral()),
        })
    } else {
        let t = Arc::new(Telemetry {
            store: store.clone(),
            stats: Arc::new(edge::stats::Stats::load(&args.data_dir.join("analytics.json"))),
            waf: waf.clone(),
            stats_path: args.data_dir.join("analytics.json"),
            events_path: args.data_dir.join("events.json"),
            limits: Arc::new(limits::Limits::load(&args.data_dir.join("usage.json"))),
        });
        waf.load(&t.events_path);
        let t_exec = t.clone();
        updater.on_exec(move || t_exec.save());
        t
    };
    let node_limits = telemetry.limits.clone();
    node_limits.refresh(&store, &args.edge_ips, args.node_name.as_deref());
    tokio::spawn(node_limits.clone().run(store.clone(), args.edge_ips.clone(), args.node_name.clone()));
    let gfw = Arc::new(gfw::GfwMonitor::default());
    let mut edge = edge::Edge::new(store.clone(), cache.clone(), waf.clone(), args.edge_ips.clone())?;
    edge.accelerate.store(accel, std::sync::atomic::Ordering::Relaxed);
    let kv_store = if accel {
        workers::kv::KvStore::open_ephemeral(store.clock(), sync_node_id.clone())
    } else {
        workers::kv::KvStore::open(args.data_dir.join("kv"), store.clock(), sync_node_id.clone())?
    };
    let d1_store = if accel {
        workers::db::D1Store::open_ephemeral(store.clock(), sync_node_id.clone())
    } else {
        workers::db::D1Store::open(args.data_dir.join("d1"), store.clock(), sync_node_id.clone())?
    };
    let _ = edge.kv.set(kv_store.clone());
    let _ = edge.d1.set(d1_store.clone());
    edge.stats = telemetry.stats.clone();
    edge.limits = node_limits.clone();
    edge.gfw = gfw.clone();
    let _ = edge.node_name.set(fleet::self_name(&store, &args.edge_ips, args.node_name.as_deref()));
    if let Some(base) = &cname_base {
        // what the over-limit notice shows is loaded from here: a name that
        // only resolves to nodes with allowance left
        let _ = edge.assets_host.set(format!("{}.{base}", limits::ASSET_LABEL));
    }
    if let Some(root) = &args.acme_webroot {
        let _ = edge.acme_webroot.set(root.clone());
    }
    if let Some(url) = &args.warp_upstream {
        let up = edge::warp::WarpUpstream::parse(url).map_err(anyhow::Error::msg)?;
        let _ = edge.warp_upstream.set(up);
    }
    if let Some(path) = args.export_domains.clone() {
        let extra: Vec<String> = [panel_host.clone(), cname_base.clone()].into_iter().flatten().collect();
        let initial = {
            let (p, s, e) = (path.clone(), store.clone(), extra.clone());
            tokio::task::spawn_blocking(move || export_domains_file(&p, &s, &e, None)).await.ok().flatten()
        };
        let store_bg = store.clone();
        tokio::spawn(async move {
            let mut changes = store_bg.subscribe();
            let mut last = initial;
            while changes.changed().await.is_ok() {
                let (p, s, e, prev) = (path.clone(), store_bg.clone(), extra.clone(), last.clone());
                if let Ok(next) = tokio::task::spawn_blocking(move || export_domains_file(&p, &s, &e, prev.as_deref())).await {
                    last = next;
                }
            }
        });
    }
    let edge = Arc::new(edge);
    let mut edge_listeners = Vec::new();
    for (what, addr, tls) in [("HTTP", &args.http_listen, false), ("HTTPS", &args.https_listen, true)] {
        if addr == "off" {
            continue;
        }
        let listener = tokio::net::TcpListener::bind(addr.as_str())
            .await
            .with_context(|| format!("cannot bind edge {what} listener on {addr}"))?;
        tracing::info!("edge {what} listening on {}", listener.local_addr()?);
        edge_listeners.push(listener.local_addr()?);
        let tls_pair = if tls {
            let (cfg, resolver) = edge::tls::server_config_with_resolver(store.clone())?;
            tokio::spawn(resolver.clone().watch());
            Some((cfg, Some(resolver)))
        } else {
            None
        };
        if tls_pair.is_some() && args.http3_listen.as_deref() != Some("off") {
            // HTTP/3 shares the HTTPS port number (over UDP) unless told otherwise.
            let addr = match &args.http3_listen {
                Some(a) => a.parse().with_context(|| format!("invalid --http3-listen address '{a}'"))?,
                None => listener.local_addr()?,
            };
            let quic = match args.quic_fallback {
                Some(fb) => {
                    let fb_snis: Vec<String> = args
                        .quic_fallback_sni
                        .iter()
                        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let ep = edge::quic_mux::bind(addr, fb, store.clone(), panel_host.clone(), cname_base.clone(), fb_snis)
                        .await
                        .with_context(|| format!("cannot bind QUIC SNI mux on udp {addr} (fallback {fb})"))?;
                    tracing::info!("edge HTTP/3 QUIC SNI mux listening on {addr} (udp, fallback -> {fb})");
                    ep
                }
                None => {
                    let ep = edge::h3::endpoint(addr, store.clone())
                        .with_context(|| format!("cannot bind HTTP/3 (QUIC) listener on udp {addr}"))?;
                    tracing::info!("edge HTTP/3 listening on {addr} (udp)");
                    ep
                }
            };
            let alt = format!("h3=\":{}\"; ma=86400", addr.port());
            let _ = edge.alt_svc.set(alt.parse()?);
            tokio::spawn(edge::h3::serve(quic, edge.clone()));
        }
        tokio::spawn(edge::serve_with_resolver(listener, edge.clone(), tls_pair, args.proxy_protocol));
    }
    for spec in &args.proxy_listen {
        let spec = spec.trim();
        if spec.is_empty() || spec == "off" {
            continue;
        }
        let (addr_str, tag) = spec.split_once('=').map(|(a, t)| (a.trim(), Some(t.trim()))).unwrap_or((spec, None));
        let listener = tokio::net::TcpListener::bind(addr_str)
            .await
            .with_context(|| format!("cannot bind --proxy-listen on {addr_str}"))?;
        let local = listener.local_addr()?;
        match tag {
            Some(t) if !t.is_empty() => tracing::info!("native reverse proxy listening on {local} (tag={t})"),
            _ => tracing::info!("native reverse proxy listening on {local}"),
        }
        edge_listeners.push(local);
        tokio::spawn(edge::serve_proxy_with_resolver(listener, edge.clone(), None, args.proxy_protocol));
    }
    for spec in &args.proxy_tls_listen {
        let spec = spec.trim();
        if spec.is_empty() || spec == "off" {
            continue;
        }
        let addr_str = spec.split_once('=').map(|(a, _)| a.trim()).unwrap_or(spec);
        let listener = tokio::net::TcpListener::bind(addr_str)
            .await
            .with_context(|| format!("cannot bind --proxy-tls-listen on {addr_str}"))?;
        let local = listener.local_addr()?;
        tracing::info!("native reverse proxy (TLS) listening on {local}");
        edge_listeners.push(local);
        let (cfg, resolver) = edge::tls::server_config_with_resolver(store.clone())?;
        tokio::spawn(resolver.clone().watch());
        tokio::spawn(edge::serve_proxy_with_resolver(
            listener,
            edge.clone(),
            Some((cfg, Some(resolver))),
            args.proxy_protocol,
        ));
    }
    for spec in &args.proxy_h3_listen {
        let spec = spec.trim();
        if spec.is_empty() || spec == "off" {
            continue;
        }
        let addr_str = spec.split_once('=').map(|(a, _)| a.trim()).unwrap_or(spec);
        let addr: SocketAddr = addr_str
            .parse()
            .with_context(|| format!("invalid --proxy-h3-listen address '{addr_str}'"))?;
        let quic = edge::h3::endpoint(addr, store.clone())
            .with_context(|| format!("cannot bind --proxy-h3-listen on {addr}"))?;
        let local = quic.local_addr()?;
        tracing::info!("native reverse proxy (HTTP/3) listening on udp://{local}");
        tokio::spawn(edge::h3::serve_with_proxy(quic, edge.clone(), true));
    }
    let front = match args.h3_front_listen {
        Some(addr) => {
            let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("cannot bind the HTTP/3 front's listener on {addr}"))?;
            if !addr.ip().is_loopback() {
                tracing::warn!("the HTTP/3 front's listener on {addr} believes whoever connects about the visitor's address: it belongs on loopback");
            }
            tracing::info!("HTTP/3 front (udp {}) hands its visitors to http://{}", args.h3_front_port, listener.local_addr()?);
            edge_listeners.push(listener.local_addr()?);
            let front = Arc::new(edge::front::Front::new(args.h3_front_port, args.h3_front_cert.clone()));
            let _ = edge.front.set(front.clone());
            tokio::spawn(front.clone().watch());
            tokio::spawn(edge::front::serve_with_limit(listener, edge.clone(), 4096));
            Some(front)
        }
        None => None,
    };
    let geo = Arc::new(geo::Geo::open(args.geoip_db.as_deref(), args.geoip_asn_db.as_deref())?);
    let _ = edge.geo.set(geo.clone());
    tokio::spawn(gfw::run(gfw.clone(), geo.clone(), node_limits.clone(), args.edge_ips.clone()));
    let health = Arc::new(geo::Health::default());
    // Probing with a name of ours gets the check through an SNI-routing proxy.
    tokio::spawn(geo::health_checker(store.clone(), health.clone(), cname_base.clone()));
    let flat = Arc::new(dns::resolver::Flattener::default());
    tokio::spawn(flat.clone().run(store.clone()));
    let resolver = Arc::new(dns::resolver::Resolver {
        flat,
        limits: node_limits.clone(),
        store: store.clone(),
        edge_v4: args.edge_ips.iter().filter_map(|ip| if let IpAddr::V4(a) = ip { Some(*a) } else { None }).collect(),
        edge_v6: args.edge_ips.iter().filter_map(|ip| if let IpAddr::V6(a) = ip { Some(*a) } else { None }).collect(),
        geo: geo.clone(),
        health: health.clone(),
        cname_base: cname_base.clone(),
        name_servers: name_servers.clone(),
        h3_port: edge.alt_svc.get().and_then(|v| v.to_str().ok()?.split('"').nth(1)?.trim_start_matches(':').parse().ok()),
        h3_front: front,
        edge_ttl: args.edge_ttl.max(1),
        accelerate: accel,
    });

    let mut dns_listeners = Vec::new();
    for addr in &args.dns_listen {
        if accel && !addr.ip().is_loopback() {
            tracing::info!("accelerate mode: skipping public DNS listener on {addr}");
            continue;
        }
        let (udp, tcp) = dns::server::bind(*addr).await?;
        tracing::info!("DNS listening on {} (udp+tcp)", udp.local_addr()?);
        dns_listeners.push(udp.local_addr()?);
        tokio::spawn(dns::server::serve_udp(udp, resolver.clone()));
        tokio::spawn(dns::server::serve_tcp(tcp, resolver.clone()));
    }

    tokio::spawn(spectrum::run(store.clone(), args.spectrum_bind));
    let mail = match args.smtp_listen {
        Some(addr) => {
            let relay = args
                .mail_relay
                .as_deref()
                .map(mail::Relay::parse)
                .transpose()
                .map_err(|e| anyhow::anyhow!("--mail-relay: {e}"))?;
            let hosts = args
                .mail_hosts
                .iter()
                .map(|h| dns::wire::normalize_name(h).map_err(|e| anyhow::anyhow!("--mail-host '{h}': {e}")))
                .collect::<anyhow::Result<Vec<_>>>()?;
            // SRS sender rewriting is signed with the API token: every node
            // of a fleet shares it, so a bounce for what one node forwarded
            // can come back to any of them.
            let mail = Arc::new(mail::Mail::new(store.clone(), token.as_bytes(), hosts, relay)?);
            let _ = mail.edge.set(edge.clone());
            let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("cannot bind the SMTP listener on {addr}"))?;
            tracing::info!("SMTP listening on {}", listener.local_addr()?);
            tokio::spawn(mail.clone().serve(listener));
            Some(mail)
        }
        None => None,
    };
    tokio::spawn(apply_purges(store.clone(), cache.clone()));
    let mut internal_listeners = vec![args.api_listen];
    if let Some(addr) = args.h3_front_listen {
        internal_listeners.push(addr);
    }
    let _ = edge.internal_listeners.set(internal_listeners);
    if let Some(host) = &panel_host {
        let _ = edge.panel.set((host.clone(), args.api_listen));
    }
    let fleet = Arc::new(fleet::Fleet::default());
    let releases = Arc::new(release::Releases::new(updater.clone(), !accel));
    let listeners = dns_listeners.iter().map(|a| format!("dns {a} (udp+tcp)")).chain(edge_listeners.iter().map(|a| format!("edge {a} (tcp)"))).collect();
    let info = Arc::new(node::NodeInfo {
        started: std::time::Instant::now(),
        started_at: store::now(),
        listeners,
        cache: cache.clone(),
        limits: node_limits.clone(),
        gfw: gfw.clone(),
        updater: updater.clone(),
        front: edge.front.get().cloned(),
    });
    if !accel {
        tokio::spawn(fleet::publish_limits(store.clone(), fleet.clone(), node_limits.clone(), gfw.clone()));
        tokio::spawn(releases.clone().drive(store.clone(), fleet.clone()));
    }
    let polled = if !peer_targets.is_empty() && (accel || args.primary.is_some()) {
        Some(Arc::new(AtomicBool::new(false)))
    } else {
        None
    };
    let sync = if !peer_targets.is_empty() {
        edge.stats.set_reporting();
        waf.set_reporting();
        let sync_polled = polled.clone().unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let s = sync::PeerSync::new(
            role,
            peer_targets,
            edge.clone(),
            store.clone(),
            accounts.clone(),
            fleet.clone(),
            store.clock(),
            token.clone(),
            args.edge_ips.clone(),
            args.node_name.clone(),
            updater.clone(),
            info.clone(),
            sync_polled,
        );
        s.register_provider(kv_store.clone());
        s.register_provider(d1_store.clone());
        tokio::spawn(s.clone().run());
        Some(s)
    } else {
        None
    };
    if !accel {
        workers::cron::spawn_scheduler(edge.clone(), store.clone(), fleet.clone(), fleet_self.clone());
    }
    if !accel && args.acme_directory != "off" {
        let account = args.data_dir.join("acme_account.json");
        let mut acme = acme::Acme::new(edge.clone(), fleet.clone(), args.acme_directory.clone(), args.acme_email.clone(), account);
        acme.sync = sync.clone();
        acme.node_name = Some(fleet_self);
        tokio::spawn(Arc::new(acme).run());
    }
    if !accel {
        tokio::spawn(telemetry.clone().keep_saving());
    }

    let listener = tokio::net::TcpListener::bind(args.api_listen)
        .await
        .with_context(|| format!("cannot bind API listener on {}", args.api_listen))?;
    tracing::info!("API listening on http://{}/client/v4", listener.local_addr()?);
    // A release on trial has to show that it works here before it may stay.
    let self_test = SelfTest { api: listener.local_addr()?, token: token.clone(), edge: edge_listeners, dns: dns_listeners, polled };
    updater.watchdog();
    tokio::spawn(updater.clone().settle(move || self_test.run()));
    let app = api::router(Arc::new(api::ApiState {
        store,
        token,
        cache,
        waf,
        stats: edge.stats.clone(),
        cname_base,
        name_servers,
        panel_host,
        health,
        fleet,
        limits: node_limits,
        edge_ips: args.edge_ips.clone(),
        node_name: args.node_name.clone(),
        started_at: store::now(),
        releases,
        accounts: accounts.clone(),
        info,
        password_checks: tokio::sync::Semaphore::new(2),
        mail,
        role,
        sync,
        edge,
    }));
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    if !accel {
        telemetry.save_async().await;
        let acc = accounts.clone();
        let _ = tokio::task::spawn_blocking(move || acc.flush_blocking()).await;
    }
    Ok(())
}

/// Completes when the process is asked to stop: Ctrl-C, or SIGTERM from a
/// service manager.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// What a release on trial is asked before it may stay on this node: do
/// the listeners answer, does the API, and (a replica) was the primary heard?
struct SelfTest {
    api: SocketAddr,
    token: String,
    edge: Vec<SocketAddr>,
    dns: Vec<SocketAddr>,
    polled: Option<Arc<AtomicBool>>,
}

impl SelfTest {
    /// A node that is busy right now gets a few attempts.
    async fn run(self) -> Result<(), String> {
        let mut last = String::new();
        for attempt in 0..6 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            match self.once().await {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn once(&self) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // a listener on every address is asked on the loopback one
        let local = |addr: &SocketAddr| match addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), addr.port()),
            IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), addr.port()),
            _ => *addr,
        };
        let limit = Duration::from_secs(3);
        for addr in self.edge.iter().map(local) {
            let connected = tokio::time::timeout(limit, tokio::net::TcpStream::connect(addr)).await;
            connected.ok().and_then(Result::ok).ok_or_else(|| format!("the edge listener on {addr} does not accept connections"))?;
        }
        for addr in self.dns.iter().map(local) {
            // any question will do ("." NS): what counts is that an answer comes back
            let query = [0x5f, 0xcf, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
            let asked = async {
                let any: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
                let socket = tokio::net::UdpSocket::bind(any).await.ok()?;
                socket.send_to(&query, addr).await.ok()?;
                let mut reply = [0u8; 512];
                let (n, _) = socket.recv_from(&mut reply).await.ok()?;
                Some(n >= 12 && reply[..2] == query[..2] && reply[2] & 0x80 != 0)
            };
            if tokio::time::timeout(limit, asked).await.ok().flatten() != Some(true) {
                return Err(format!("the DNS server on {addr} does not answer"));
            }
        }
        let api = local(&self.api);
        let asked = async {
            let mut stream = tokio::net::TcpStream::connect(api).await.ok()?;
            let request = format!("GET /client/v4/system HTTP/1.1\r\nHost: {api}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", self.token);
            stream.write_all(request.as_bytes()).await.ok()?;
            let mut head = [0u8; 12];
            stream.read_exact(&mut head).await.ok()?;
            Some(head.ends_with(b" 200"))
        };
        if tokio::time::timeout(limit, asked).await.ok().flatten() != Some(true) {
            return Err(format!("the management API on {api} does not answer"));
        }
        if self.polled.as_ref().is_some_and(|polled| !polled.load(Ordering::Relaxed)) {
            return Err("the primary could not be reached once since this release started".into());
        }
        Ok(())
    }
}

/// Analytics and security events: kept in memory, written to the data
/// directory every so often and on shutdown.
struct Telemetry {
    store: Arc<store::Store>,
    stats: Arc<edge::stats::Stats>,
    waf: Arc<edge::waf::Waf>,
    stats_path: PathBuf,
    events_path: PathBuf,
    limits: Arc<limits::Limits>,
}

impl Telemetry {
    fn save(&self) {
        let zones = self.store.list_zones().into_iter().map(|z| z.id).collect();
        if let Err(e) = self.stats.save(&self.stats_path, &zones) {
            tracing::warn!("cannot save analytics to {}: {e}", self.stats_path.display());
        }
        if let Err(e) = self.waf.save(&self.events_path) {
            tracing::warn!("cannot save security events to {}: {e}", self.events_path.display());
        }
        self.limits.save();
    }

    async fn save_async(self: &Arc<Self>) {
        let this = self.clone();
        let _ = tokio::task::spawn_blocking(move || this.save()).await;
    }

    async fn keep_saving(self: Arc<Self>) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            self.save_async().await;
        }
    }
}

/// Apply cache purges recorded in the configuration (on every node).
async fn apply_purges(store: Arc<store::Store>, cache: Arc<edge::cache::Cache>) {
    let mut changes = store.subscribe();
    let mut seen: std::collections::HashSet<String> = store.snapshot().purges.iter().map(|p| p.id.clone()).collect();
    while changes.changed().await.is_ok() {
        for op in &store.snapshot().purges {
            if !seen.insert(op.id.clone()) {
                continue;
            }
            if op.everything {
                cache.purge_zone(&op.zone_id);
            } else {
                cache.purge_urls(&op.zone_id, &op.files, false);
                cache.purge_urls(&op.zone_id, &op.prefixes, true);
            }
        }
    }
}

/// Atomically write all hosted zone names (plus extra hosts like panel/cname_base)
/// to `path`, one per line, only when the rendered content actually changed.
fn export_domains_file(path: &std::path::Path, store: &store::Store, extra: &[String], last: Option<&str>) -> Option<String> {
    let mut set: std::collections::BTreeSet<String> = store.list_zones().into_iter().map(|z| z.name).collect();
    for rule in &store.snapshot().local_proxy_rules {
        for h in &rule.hosts {
            let h = h.trim().trim_end_matches('.').trim_start_matches("*.").to_ascii_lowercase();
            if !h.is_empty() && h != "*" {
                set.insert(h);
            }
        }
    }
    for h in extra {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if !h.is_empty() {
            set.insert(h);
        }
    }
    let mut content = set.into_iter().collect::<Vec<_>>().join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    if last == Some(content.as_str()) {
        return Some(content);
    }
    let tmp = path.with_extension("lst.tmp");
    if let Err(e) = std::fs::write(&tmp, &content).and_then(|_| std::fs::rename(&tmp, path)) {
        tracing::warn!("cannot export domains list to {}: {e}", path.display());
        return last.map(str::to_string);
    }
    tracing::info!("exported {} domain(s) to {}", content.lines().count(), path.display());
    Some(content)
}

#[cfg(test)]
mod tests {
    use super::export_domains_file;
    use serde_json::json;

    #[test]
    fn export_domains_file_includes_enabled_proxy_rule_hosts() {
        let dir = std::env::temp_dir().join(format!("fucf-domains-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = crate::store::Store::open(&dir.join("state.json"), vec![]).unwrap();
        store.create_zone("zone.example").unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "enabled-proxy",
                    "hosts": ["app.proxy.example", "*.sub.example", "*"],
                    "upstreams": [{"url": "http://127.0.0.1:9001"}],
                    "enabled": true
                }),
            )
            .unwrap();
        store
            .save_proxy_rule(
                None,
                json!({
                    "name": "disabled-proxy",
                    "hosts": ["disabled.proxy.example"],
                    "upstreams": [{"url": "http://127.0.0.1:9002"}],
                    "enabled": false
                }),
            )
            .unwrap();

        let out = dir.join("domains.lst");
        let content = export_domains_file(&out, &store, &["dashboard.example".into()], None).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines,
            vec!["app.proxy.example", "dashboard.example", "sub.example", "zone.example"]
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), content);
        let _ = std::fs::remove_dir_all(dir);
    }
}
