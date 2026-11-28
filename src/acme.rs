//! Automatic certificates: an ACME (RFC 8555) client that obtains and renews
//! the certificate packs of the configuration from a CA such as Let's Encrypt.
//!
//! Only the primary runs it. Challenges are answered by the data plane
//! itself: TXT records from the authoritative DNS (`dns-01`), a special
//! certificate on the HTTPS listener (`tls-alpn-01`) or a well-known path on
//! the HTTP listener (`http-01`). They are published through the replicated
//! configuration and the CA is only told to look once the replicas have them,
//! since its validators may reach any node.

use crate::edge::upstream::Target;
use crate::edge::Edge;
use crate::fleet::Fleet;
use crate::items::{AcmeChallenge, CertificatePack};
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::header::HeaderMap;
use hyper::{Method, Request, StatusCode};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// After a restart the primary does not know its replicas until they have
/// polled it; no challenge is started before they had the time to.
const STARTUP_GRACE: Duration = Duration::from_secs(15);
/// How long the CA gets to validate a challenge or to issue.
const PATIENCE: Duration = Duration::from_secs(180);

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding, as ACME writes everything binary.
pub fn b64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes() {
        acc = acc << 6 | B64.iter().position(|b| *b == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
    out
}

pub fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn parse_time(text: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(text).ok().map(|t| t.timestamp())
}

/// Seconds to wait after the `attempts`-th failure in a row: 10 minutes,
/// doubling up to a day (CAs limit failed validations per name and hour).
fn backoff(attempts: u32) -> i64 {
    (600i64 << attempts.saturating_sub(1).min(8)).min(86400)
}

/// Should a certificate be requested for this pack now? Yes when it has none,
/// or when less than a third of its certificate's lifetime is left.
fn due(pack: &CertificatePack, now: i64) -> bool {
    if pack.next_attempt.as_deref().and_then(parse_time).is_some_and(|t| t > now) {
        return false;
    }
    if pack.certificate.is_empty() {
        return true;
    }
    crate::edge::tls::pem_validity(&pack.certificate).is_some_and(|(from, until)| now >= until - (until - from) / 3)
}

/// Which ACME challenge proves control of a name.
fn challenge_kind(method: &str, wildcard: bool, zone_kind: &str) -> &'static str {
    match method {
        "dns" => "dns-01",
        "tls-alpn" => "tls-alpn-01",
        "http" => "http-01",
        // We answer DNS for zones delegated to us (and for the `_acme-challenge`
        // CNAMEs of certificate-only zones); for the others the CA can only
        // reach the edge itself. Wildcards always need DNS.
        _ if wildcard || zone_kind == "full" || zone_kind == "cert" => "dns-01",
        _ => "tls-alpn-01",
    }
}

#[derive(Serialize, Deserialize)]
struct SavedAccount {
    directory: String,
    kid: String,
    /// PKCS#8, base64url.
    key: String,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.headers.get(name).and_then(|v| v.to_str().ok()).map(String::from)
    }
    fn json(&self) -> Result<Value, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("the CA sent something that is not JSON: {e}"))
    }
}

pub struct Acme {
    pub edge: Arc<Edge>,
    pub fleet: Arc<Fleet>,
    /// URL of the CA's ACME directory.
    pub directory: String,
    /// E-mail address the CA may send expiry warnings to.
    pub contact: Option<String>,
    /// Where the account key is kept (never replicated).
    pub account_path: PathBuf,
    /// Pause between two looks at something the CA is working on.
    pub poll: Duration,
    /// How long replicas get to pick up a challenge before the CA is told to look.
    pub sync_timeout: Duration,
    pub startup_grace: Duration,
    /// Optional peer sync handle for pushing ACME challenges & leases.
    pub sync: Option<Arc<crate::sync::PeerSync>>,
    /// Explicit node name used for ACME leader election.
    pub node_name: Option<String>,
    started: Instant,
}

/// One conversation with the CA: its URLs, our account and the anti-replay nonce.
struct Session<'a> {
    acme: &'a Acme,
    urls: Value,
    key: EcdsaKeyPair,
    kid: Option<String>,
    nonce: Option<String>,
}

impl Session<'_> {
    fn url(&self, name: &str) -> Result<String, String> {
        self.urls[name].as_str().map(String::from).ok_or_else(|| format!("the CA's directory lacks {name}"))
    }

    fn coordinates(&self) -> (String, String) {
        let point = self.key.public_key().as_ref(); // 0x04 || x || y
        (b64(&point[1..33]), b64(&point[33..65]))
    }

    /// RFC 7638 thumbprint of the account key; part of every key authorization.
    fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        b64(&sha256(format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#).as_bytes()))
    }

    /// A signed request (`payload` None: POST-as-GET); returns the reply of
    /// a successful one.
    async fn post(&mut self, url: &str, payload: Option<Value>) -> Result<Reply, String> {
        for attempt in 0.. {
            let nonce = match self.nonce.take() {
                Some(n) => n,
                None => {
                    let reply = self.acme.http(Method::HEAD, &self.url("newNonce")?, None).await?;
                    reply.header("replay-nonce").ok_or("the CA handed out no nonce")?
                }
            };
            let mut protected = json!({ "alg": "ES256", "nonce": nonce, "url": url });
            match &self.kid {
                Some(kid) => protected["kid"] = json!(kid),
                None => {
                    let (x, y) = self.coordinates();
                    protected["jwk"] = json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });
                }
            }
            let protected = b64(protected.to_string().as_bytes());
            let payload = payload.as_ref().map(|p| b64(p.to_string().as_bytes())).unwrap_or_default();
            let signature = self
                .key
                .sign(&SystemRandom::new(), format!("{protected}.{payload}").as_bytes())
                .map_err(|_| "cannot sign with the account key")?;
            let body = json!({ "protected": protected, "payload": payload, "signature": b64(signature.as_ref()) });
            let reply = self.acme.http(Method::POST, url, Some(body.to_string())).await?;
            self.nonce = reply.header("replay-nonce");
            if reply.status.is_success() {
                return Ok(reply);
            }
            let problem = reply.json().unwrap_or_default();
            let kind = problem["type"].as_str().unwrap_or_default().rsplit(':').next().unwrap_or_default().to_string();
            if kind == "badNonce" && attempt < 3 {
                continue; // the reply carried a fresh one
            }
            let detail = problem["detail"].as_str().unwrap_or("no details given");
            return Err(format!("the CA refused ({} {kind}): {detail}", reply.status.as_u16()));
        }
        unreachable!()
    }

    /// Fetch `url` until the CA is done with it (its status is no longer
    /// `pending` or `processing`).
    async fn settled(&mut self, url: &str, what: &str) -> Result<Value, String> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let reply = self.post(url, None).await?;
            let state = reply.json()?;
            if !matches!(state["status"].as_str(), Some("pending" | "processing")) {
                return Ok(state);
            }
            if Instant::now() > deadline {
                return Err(format!("the CA did not finish {what} within {} s", PATIENCE.as_secs()));
            }
            let hinted = reply.header("retry-after").and_then(|v| v.parse().ok()).map(Duration::from_secs);
            tokio::time::sleep(hinted.unwrap_or(self.acme.poll).min(Duration::from_secs(15))).await;
        }
    }
}

impl Acme {
    pub fn new(edge: Arc<Edge>, fleet: Arc<Fleet>, directory: String, contact: Option<String>, account_path: PathBuf) -> Self {
        Acme {
            edge,
            fleet,
            directory,
            contact: contact.map(|c| c.trim().trim_start_matches("mailto:").to_string()).filter(|c| !c.is_empty()),
            account_path,
            poll: Duration::from_secs(2),
            sync_timeout: Duration::from_secs(30),
            startup_grace: STARTUP_GRACE,
            sync: None,
            node_name: None,
            started: Instant::now(),
        }
    }

    fn self_node(&self) -> String {
        self.node_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| "local".into())
    }

    async fn http(&self, method: Method, url: &str, body: Option<String>) -> Result<Reply, String> {
        let target = Target::from_url(url)?;
        let uri: hyper::Uri = url.parse().map_err(|e| format!("invalid URL '{url}': {e}"))?;
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let mut req = Request::builder().method(method).uri(path).header("user-agent", concat!("fucf/", env!("CARGO_PKG_VERSION")));
        if body.is_some() {
            req = req.header("content-type", "application/jose+json");
        }
        let req = req.body(crate::edge::full(body.unwrap_or_default())).map_err(|e| e.to_string())?;
        let exchange = async {
            let resp = self.edge.upstream.send(&target, req).await.map_err(|e| format!("cannot reach {url}: {e:?}"))?;
            let (parts, body) = resp.into_parts();
            let body = Limited::new(body, 1 << 20).collect().await.map_err(|e| format!("reading {url}: {e}"))?.to_bytes();
            Ok(Reply { status: parts.status, headers: parts.headers, body })
        };
        match tokio::time::timeout(Duration::from_secs(30), exchange).await {
            Ok(result) => result,
            Err(_) => Err(format!("{url} timed out")),
        }
    }

    /// Open a session: read the CA's directory and load our account,
    /// registering one first if this is the first time with this CA.
    async fn session(&self) -> Result<Session<'_>, String> {
        let directory = self.http(Method::GET, &self.directory, None).await?;
        if !directory.status.is_success() {
            return Err(format!("{} answered {}", self.directory, directory.status));
        }
        enum SessionLoad {
            Existing(EcdsaKeyPair, String),
            NewKey(ring::pkcs8::Document),
        }
        let account_path = self.account_path.clone();
        let expected_dir = self.directory.clone();
        let loaded = tokio::task::spawn_blocking(move || -> Result<SessionLoad, String> {
            let rng = SystemRandom::new();
            let saved = std::fs::read(&account_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<SavedAccount>(&bytes).ok())
                .filter(|a| a.directory == expected_dir);
            if let Some(a) = saved {
                if let Some(bytes) = unb64(&a.key) {
                    if let Ok(key) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes, &rng) {
                        return Ok(SessionLoad::Existing(key, a.kid));
                    }
                }
            }
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| "cannot generate an account key".to_string())?;
            Ok(SessionLoad::NewKey(pkcs8))
        })
        .await
        .map_err(|e| format!("acme session task failed: {e}"))??;

        let pkcs8 = match loaded {
            SessionLoad::Existing(key, kid) => {
                return Ok(Session { acme: self, urls: directory.json()?, key, kid: Some(kid), nonce: None });
            }
            SessionLoad::NewKey(pkcs8) => pkcs8,
        };

        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).map_err(|_| "cannot use the account key")?;
        let mut session = Session { acme: self, urls: directory.json()?, key, kid: None, nonce: None };
        let mut registration = json!({ "termsOfServiceAgreed": true });
        if let Some(contact) = &self.contact {
            registration["contact"] = json!([format!("mailto:{contact}")]);
        }
        let reply = session.post(&session.url("newAccount")?, Some(registration)).await?;
        let kid = reply.header("location").ok_or("the CA did not name the new account")?;
        let saved = SavedAccount { directory: self.directory.clone(), kid: kid.clone(), key: b64(pkcs8.as_ref()) };
        let account_path = self.account_path.clone();
        tokio::task::spawn_blocking(move || {
            let tmp = account_path.with_extension("json.tmp");
            crate::auth::write_private(&tmp, &serde_json::to_vec(&saved).unwrap_or_default())
                .and_then(|_| std::fs::rename(&tmp, &account_path))
                .map_err(|e| format!("cannot save the ACME account to {}: {e}", account_path.display()))
        })
        .await
        .map_err(|e| format!("acme save task failed: {e}"))??;
        tracing::info!("registered ACME account {kid}");
        session.kid = Some(kid);
        Ok(session)
    }

    /// Wait until the replicas that are around run the current configuration.
    async fn wait_for_fleet(&self) {
        if let Some(left) = (self.started + self.startup_grace).checked_duration_since(Instant::now()) {
            tokio::time::sleep(left).await;
        }
        if let Some(sync) = &self.sync {
            sync.push_now_bounded(Duration::from_millis(500)).await;
        }
        let version = self.edge.store.version();
        let deadline = Instant::now() + self.sync_timeout;
        loop {
            let lagging = self.fleet.lagging(&version);
            if lagging.is_empty() {
                return;
            }
            if Instant::now() > deadline {
                tracing::warn!("ACME: validating although {} did not confirm the challenge", lagging.join(", "));
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Obtain a certificate for the names of `pack`: `(chain PEM, key PEM)`.
    async fn issue(&self, pack: &CertificatePack) -> Result<(String, String), String> {
        let store = &self.edge.store;
        let zone = store.get_zone(&pack.meta.zone_id).map_err(|_| "its zone no longer exists")?;
        let mut session = self.session().await?;
        let thumbprint = session.thumbprint();

        let identifiers: Vec<Value> = pack.hosts.iter().map(|h| json!({ "type": "dns", "value": h })).collect();
        let reply = session.post(&session.url("newOrder")?, Some(json!({ "identifiers": identifiers }))).await?;
        let order_url = reply.header("location").ok_or("the CA did not name the order")?;
        let order = reply.json()?;
        let text = |v: &Value, what: &str| v.as_str().map(String::from).ok_or_else(|| format!("the CA's reply lacks {what}"));

        // One authorization per name: pick a challenge for each.
        let (mut challenges, mut pending) = (Vec::new(), Vec::new());
        for authz_url in order["authorizations"].as_array().ok_or("the order lists no authorizations")? {
            let authz_url = text(authz_url, "an authorization URL")?;
            let authz = session.post(&authz_url, None).await?.json()?;
            if authz["status"] == "valid" {
                continue; // proven recently, the CA remembers
            }
            let host = text(&authz["identifier"]["value"], "the name to validate")?.to_ascii_lowercase();
            let kind = challenge_kind(&pack.validation_method, authz["wildcard"] == true, &zone.kind);
            let offered = authz["challenges"].as_array().and_then(|list| list.iter().find(|c| c["type"] == kind));
            let challenge = offered.ok_or_else(|| format!("the CA offers no {kind} challenge for {host}"))?;
            let token = text(&challenge["token"], "a challenge token")?;
            if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err("the CA sent a malformed challenge token".into());
            }
            pending.push((authz_url, text(&challenge["url"], "a challenge URL")?, host.clone()));
            challenges.push(AcmeChallenge {
                pack_id: pack.meta.id.clone(),
                host,
                kind: kind.to_string(),
                key_authorization: format!("{token}.{thumbprint}"),
                token,
                sync: Default::default(),
            });
        }

        if !challenges.is_empty() {
            store.set_challenges_async(Some(&pack.meta.id), challenges).await.map_err(|e| format!("cannot publish the challenges: {e:?}"))?;
            self.wait_for_fleet().await;
            for (_, challenge_url, _) in &pending {
                session.post(challenge_url, Some(json!({}))).await?;
            }
            for (authz_url, _, host) in &pending {
                let authz = session.settled(authz_url, "the validation").await?;
                if authz["status"] != "valid" {
                    let reason = authz["challenges"].as_array().and_then(|list| list.iter().find_map(|c| c["error"]["detail"].as_str()));
                    return Err(format!("validation of {host} failed: {}", reason.unwrap_or("the CA gave no reason")));
                }
            }
        }

        // Every name is proven: send the key to certify and collect the result.
        let hosts = pack.hosts.clone();
        let (key_pem, csr_der) = tokio::task::spawn_blocking(move || -> Result<(String, Vec<u8>), String> {
            let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
            let mut params = rcgen::CertificateParams::new(hosts).map_err(|e| e.to_string())?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
            Ok((key.serialize_pem(), csr.der().to_vec()))
        })
        .await
        .map_err(|e| e.to_string())??;
        session.post(&text(&order["finalize"], "the finalize URL")?, Some(json!({ "csr": b64(&csr_der) }))).await?;
        let order = session.settled(&order_url, "the certificate").await?;
        if order["status"] != "valid" {
            return Err(format!("the CA did not issue: the order is {}", order["status"].as_str().unwrap_or("in an unknown state")));
        }
        let chain = session.post(&text(&order["certificate"], "the certificate URL")?, None).await?;
        let chain = String::from_utf8(chain.body.to_vec()).map_err(|_| "the certificate is not PEM")?;
        crate::edge::tls::parse_cert(&chain, &key_pem).map_err(|e| format!("the CA sent an unusable certificate: {e}"))?;
        crate::edge::tls::pem_validity(&chain).ok_or("the CA sent a certificate whose validity cannot be read")?;
        Ok((chain, key_pem))
    }

    /// Obtain a certificate for `hosts` that this node proves by itself (the
    /// challenges are answered locally, see [`crate::site_acme`]), not through
    /// the fleet's configuration. `kind`: `http-01` or `tls-alpn-01`;
    /// `profile`: an ACME profile to ask for when the CA offers it (e.g.
    /// `shortlived`, which Let's Encrypt requires for IP addresses).
    pub async fn issue_site(&self, hosts: &[String], kind: &'static str, profile: Option<&str>) -> Result<(String, String), String> {
        let mut session = self.session().await?;
        let thumbprint = session.thumbprint();
        let identifiers: Vec<Value> = hosts
            .iter()
            .map(|h| match h.parse::<std::net::IpAddr>() {
                Ok(_) => json!({ "type": "ip", "value": h }),
                Err(_) => json!({ "type": "dns", "value": h }),
            })
            .collect();
        let mut new_order = json!({ "identifiers": identifiers });
        if let Some(p) = profile.filter(|p| session.urls["meta"]["profiles"].get(*p).is_some()) {
            new_order["profile"] = json!(p);
        }
        let reply = session.post(&session.url("newOrder")?, Some(new_order)).await?;
        let order_url = reply.header("location").ok_or("the CA did not name the order")?;
        let order = reply.json()?;
        let text = |v: &Value, what: &str| v.as_str().map(String::from).ok_or_else(|| format!("the CA's reply lacks {what}"));

        // answered here until this function returns, whatever happens
        let mut published = crate::site_acme::Published::default();
        let mut pending = Vec::new();
        for authz_url in order["authorizations"].as_array().ok_or("the order lists no authorizations")? {
            let authz_url = text(authz_url, "an authorization URL")?;
            let authz = session.post(&authz_url, None).await?.json()?;
            if authz["status"] == "valid" {
                continue;
            }
            let host = text(&authz["identifier"]["value"], "the name to validate")?.to_ascii_lowercase();
            let offered = authz["challenges"].as_array().and_then(|list| list.iter().find(|c| c["type"] == kind));
            let challenge = offered.ok_or_else(|| format!("the CA offers no {kind} challenge for {host}"))?;
            let token = text(&challenge["token"], "a challenge token")?;
            if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err("the CA sent a malformed challenge token".into());
            }
            let key_authorization = format!("{token}.{thumbprint}");
            match kind {
                "tls-alpn-01" => {
                    let digest = sha256(key_authorization.as_bytes());
                    let cert = crate::edge::tls::acme_challenge_cert(&host, &digest).ok_or("cannot make the challenge certificate")?;
                    published.tls(&host, cert);
                }
                _ => published.http(&token, &key_authorization),
            }
            pending.push((authz_url, text(&challenge["url"], "a challenge URL")?, host));
        }
        for (_, challenge_url, _) in &pending {
            session.post(challenge_url, Some(json!({}))).await?;
        }
        for (authz_url, _, host) in &pending {
            let authz = session.settled(authz_url, "the validation").await?;
            if authz["status"] != "valid" {
                let reason = authz["challenges"].as_array().and_then(|list| list.iter().find_map(|c| c["error"]["detail"].as_str()));
                return Err(format!("validation of {host} ({kind}) failed: {}", reason.unwrap_or("the CA gave no reason")));
            }
        }
        drop(published);

        let names = hosts.to_vec();
        let (key_pem, csr_der) = tokio::task::spawn_blocking(move || -> Result<(String, Vec<u8>), String> {
            let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
            let mut params = rcgen::CertificateParams::new(names).map_err(|e| e.to_string())?;
            params.distinguished_name = rcgen::DistinguishedName::new();
            let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
            Ok((key.serialize_pem(), csr.der().to_vec()))
        })
        .await
        .map_err(|e| e.to_string())??;
        session.post(&text(&order["finalize"], "the finalize URL")?, Some(json!({ "csr": b64(&csr_der) }))).await?;
        let order = session.settled(&order_url, "the certificate").await?;
        if order["status"] != "valid" {
            return Err(format!("the CA did not issue: the order is {}", order["status"].as_str().unwrap_or("in an unknown state")));
        }
        let chain = session.post(&text(&order["certificate"], "the certificate URL")?, None).await?;
        let chain = String::from_utf8(chain.body.to_vec()).map_err(|_| "the certificate is not PEM")?;
        crate::edge::tls::parse_cert(&chain, &key_pem).map_err(|e| format!("the CA sent an unusable certificate: {e}"))?;
        Ok((chain, key_pem))
    }

    /// Request the certificates that are due, one pack after the other.
    pub async fn tick(&self) {
        let store = &self.edge.store;
        if store.is_read_only() {
            return;
        }
        let now_ms = crate::sync::clock::unix_ms();
        let me = self.self_node();
        let online = self.fleet.online_peers();
        let preferred = crate::sync::acme_lease::preferred_leader(&me, &online);
        let cur_lease = store.acme_lease().unwrap_or_default();
        if !cur_lease.can_claim(&me, &preferred, now_ms) {
            return;
        }
        if store.pending_challenges() > 0 {
            // left behind by a run that was interrupted
            let _ = store.set_challenges_async(None, Vec::new()).await;
        }
        for pack in store.all_packs() {
            if !due(&pack, unix_now()) {
                continue;
            }
            let claim_ms = crate::sync::clock::unix_ms();
            let cur_lease = store.acme_lease().unwrap_or_default();
            if !cur_lease.can_claim(&me, &preferred, claim_ms) {
                return;
            }
            let lease = crate::sync::acme_lease::AcmeLease {
                holder: me.clone(),
                acquired_ms: claim_ms,
                expires_ms: claim_ms + crate::sync::acme_lease::LEASE_TTL_MS,
                pack_id: Some(pack.meta.id.clone()),
                sync: Default::default(),
            };
            let _ = store.set_acme_lease_async(lease).await;
            if let Some(sync) = &self.sync {
                sync.push_now_bounded(Duration::from_millis(300)).await;
            }
            let names = pack.hosts.join(", ");
            let names_log = names.clone();
            tracing::info!("ACME: requesting a certificate for {names}");
            let outcome = self.issue(&pack).await;
            let _ = store.set_challenges_async(Some(&pack.meta.id), Vec::new()).await;
            let now = unix_now();
            let updated = store
                .update_pack_async(&pack.meta.id, move |p| match outcome {
                    Ok((chain, key)) => {
                        let until = crate::edge::tls::pem_validity(&chain).map_or(now, |(_, until)| until);
                        tracing::info!("ACME: certificate for {names_log} installed, valid until {}", crate::store::rfc3339(until));
                        (p.certificate, p.private_key) = (chain, key);
                        (p.status, p.error, p.attempts) = ("active".into(), String::new(), 0);
                        (p.issued_on, p.expires_on) = (Some(crate::store::rfc3339(now)), Some(crate::store::rfc3339(until)));
                        // never ask again right away, whatever the certificate says
                        p.next_attempt = Some(crate::store::rfc3339(now + 3600));
                    }
                    Err(reason) => {
                        p.attempts += 1;
                        let wait = backoff(p.attempts);
                        tracing::warn!("ACME: no certificate for {names_log} (next attempt in {} min): {reason}", wait / 60);
                        p.error = reason;
                        p.next_attempt = Some(crate::store::rfc3339(now + wait));
                        if p.certificate.is_empty() {
                            p.status = "failed".into();
                        }
                    }
                })
                .await;
            if let Err(e) = updated {
                tracing::warn!("ACME: cannot record the outcome for {names}: {e:?}");
            }
            let _ = store.set_acme_lease_async(crate::sync::acme_lease::AcmeLease::default()).await;
            if let Some(sync) = &self.sync {
                sync.push_now_bounded(Duration::from_millis(300)).await;
            }
        }
    }

    /// Keep the certificate packs current: look whenever the configuration
    /// changes, and once a minute.
    pub async fn run(self: Arc<Self>) {
        let mut changes = self.edge.store.subscribe();
        loop {
            self.tick().await;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::Resolver;
    use crate::dns::wire::{rtype, testutil::query};
    use crate::edge::cache::Cache;
    use crate::edge::tls;
    use crate::edge::waf::Waf;
    use crate::items::Item;
    use crate::store::testutil::{rec, temp_store};
    use crate::store::Store;
    use axum::extract::State;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering::SeqCst};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn base64url_and_schedules() {
        assert_eq!((b64(b""), b64(b"f"), b64(b"fo"), b64(b"foo"), b64(b"foob")), ("".into(), "Zg".into(), "Zm8".into(), "Zm9v".into(), "Zm9vYg".into()));
        assert_eq!(b64(&[0xfb, 0xff, 0xfe]), "-__-");
        for n in 0..70usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + n) as u8).collect();
            assert_eq!(unb64(&b64(&bytes)).unwrap(), bytes);
        }
        assert_eq!(unb64("a+b"), None);

        assert_eq!((backoff(1), backoff(2), backoff(4), backoff(30)), (600, 1200, 4800, 86400));
        assert_eq!(challenge_kind("auto", false, "full"), "dns-01");
        assert_eq!(challenge_kind("auto", false, "partial"), "tls-alpn-01");
        assert_eq!(challenge_kind("auto", true, "partial"), "dns-01");
        assert_eq!(challenge_kind("http", false, "full"), "http-01");

        // a pack is due without a certificate, and unless told to wait
        let mut pack = CertificatePack::default();
        assert!(due(&pack, 1000));
        pack.next_attempt = Some(crate::store::rfc3339(2000));
        assert!(!due(&pack, 1000) && due(&pack, 2000));
    }

    // ---- a small ACME CA that really validates against the edge ----

    /// Trusts whatever it is shown: the tests look at the certificate themselves.
    #[derive(Debug)]
    struct Blind;

    impl ServerCertVerifier for Blind {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            crate::edge::tls::crypto().signature_verification_algorithms.supported_schemes()
        }
    }

    /// The certificate the edge presents for `host` (and the protocol agreed on).
    async fn presented(port: u16, host: &str, alpn: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        let mut config = rustls::ClientConfig::builder_with_provider(crate::edge::tls::crypto())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Blind))
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
        let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let conn = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.map_err(|e| format!("TLS handshake: {e}"))?;
        let (_, session) = conn.get_ref();
        let cert = session.peer_certificates().and_then(|c| c.first()).ok_or("no certificate presented")?;
        Ok((cert.to_vec(), session.alpn_protocol().map(<[u8]>::to_vec)))
    }

    struct CsrKey(Vec<u8>);

    impl rcgen::PublicKeyData for CsrKey {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
    }

    struct Authz {
        host: String,
        wildcard: bool,
        token: String,
        status: &'static str,
        error: String,
    }

    struct Order {
        hosts: Vec<String>,
        authz: Vec<Authz>,
        certificate: Option<String>,
    }

    #[derive(Default)]
    struct CaState {
        nonces: HashSet<String>,
        /// Public key (uncompressed point) and thumbprint of the account.
        account: Option<(Vec<u8>, String)>,
        contact: Value,
        orders: Vec<Order>,
        /// `"<challenge type> <name>"` of every successful validation.
        validated: Vec<String>,
    }

    struct Ca {
        base: String,
        resolver: Arc<Resolver>,
        http_port: u16,
        https_port: u16,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        ca_pem: String,
        state: Mutex<CaState>,
        /// Names whose `_acme-challenge` is a CNAME into the edge's base domain.
        delegated: Vec<&'static str>,
        reject: AtomicBool,
        bad_nonce_once: AtomicBool,
        /// Days until the certificates issued next expire (of 90).
        days_left: AtomicI64,
        accounts: AtomicUsize,
    }

    type Fail = (u16, &'static str, String);

    impl Ca {
        fn nonce(&self) -> String {
            let nonce = uuid::Uuid::new_v4().simple().to_string();
            self.state.lock().unwrap().nonces.insert(nonce.clone());
            nonce
        }

        fn order_json(&self, o: &Order, i: usize) -> String {
            let status = if o.certificate.is_some() {
                "valid"
            } else if o.authz.iter().any(|a| a.status == "invalid") {
                "invalid"
            } else if o.authz.iter().all(|a| a.status == "valid") {
                "ready"
            } else {
                "pending"
            };
            let mut v = json!({
                "status": status,
                "identifiers": o.hosts.iter().map(|h| json!({ "type": "dns", "value": h })).collect::<Vec<_>>(),
                "authorizations": (0..o.authz.len()).map(|j| format!("{}/authz/{i}/{j}", self.base)).collect::<Vec<_>>(),
                "finalize": format!("{}/finalize/{i}", self.base),
            });
            if o.certificate.is_some() {
                v["certificate"] = json!(format!("{}/cert/{i}", self.base));
            }
            v.to_string()
        }

        fn authz_json(&self, a: &Authz, i: usize, j: usize) -> String {
            let kinds: &[&str] = if a.wildcard { &["dns-01"] } else { &["http-01", "dns-01", "tls-alpn-01"] };
            let challenges: Vec<Value> = kinds
                .iter()
                .map(|k| {
                    let mut c = json!({ "type": k, "url": format!("{}/chall/{i}/{j}/{k}", self.base), "token": a.token, "status": a.status });
                    if !a.error.is_empty() {
                        c["error"] = json!({ "type": "urn:ietf:params:acme:error:unauthorized", "detail": a.error });
                    }
                    c
                })
                .collect();
            json!({ "identifier": { "type": "dns", "value": a.host }, "status": a.status, "wildcard": a.wildcard, "challenges": challenges }).to_string()
        }

        /// Look for the answer to a challenge the way a CA does: from outside.
        async fn validate(&self, kind: &str, host: &str, key_authorization: &str) -> Result<(), String> {
            if self.reject.load(SeqCst) {
                return Err("the CA was told to refuse".into());
            }
            let digest = sha256(key_authorization.as_bytes());
            match kind {
                "dns-01" => {
                    let name = match self.delegated.contains(&host) {
                        true => format!("_acme-challenge.{host}.cdn.test"),
                        false => format!("_acme-challenge.{host}"),
                    };
                    let peer = "127.0.0.1".parse().unwrap();
                    let reply = self.resolver.handle(&query(1, &name, rtype::TXT, false), false, peer).ok_or("no DNS reply")?;
                    let expected = b64(&digest);
                    let found = reply[3] & 0xF == 0 && reply.windows(expected.len()).any(|w| w == expected.as_bytes());
                    found.then_some(()).ok_or_else(|| format!("no TXT record with the digest at {name}"))
                }
                "tls-alpn-01" => {
                    let (cert, alpn) = presented(self.https_port, host, tls::ACME_TLS_ALPN).await?;
                    let ok = alpn.as_deref() == Some(tls::ACME_TLS_ALPN) && cert.windows(32).any(|w| w == digest);
                    ok.then_some(()).ok_or_else(|| "the certificate does not carry the digest".to_string())
                }
                "http-01" => {
                    let token = key_authorization.split('.').next().unwrap_or_default();
                    let mut s = TcpStream::connect(("127.0.0.1", self.http_port)).await.map_err(|e| e.to_string())?;
                    let request = format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                    s.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
                    let mut reply = String::new();
                    s.read_to_string(&mut reply).await.map_err(|e| e.to_string())?;
                    let ok = reply.starts_with("HTTP/1.1 200") && reply.ends_with(key_authorization);
                    ok.then_some(()).ok_or_else(|| format!("unexpected reply: {reply}"))
                }
                other => Err(format!("unknown challenge type {other}")),
            }
        }

        /// Certify the key of a signing request for `hosts`.
        fn sign(&self, hosts: &[String], csr: &[u8]) -> Option<String> {
            if !hosts.iter().all(|h| csr.windows(h.len()).any(|w| w == h.as_bytes())) {
                return None; // the request must name what was ordered
            }
            let (_, request, _) = tls::der(csr)?;
            let (_, info, _) = tls::der(request)?;
            let (_, _, rest) = tls::der(info)?; // version
            let (_, _, rest) = tls::der(rest)?; // subject
            let (_, spki, _) = tls::der(rest)?;
            let (_, _, rest) = tls::der(spki)?; // algorithm
            let (tag, bits, _) = tls::der(rest)?;
            let key = CsrKey(bits.get(1..).filter(|_| tag == 0x03)?.to_vec());
            let day = |offset: i64| {
                use chrono::Datelike;
                let d = chrono::Utc::now() + chrono::Duration::days(offset);
                rcgen::date_time_ymd(d.year(), d.month() as u8, d.day() as u8)
            };
            let left = self.days_left.load(SeqCst);
            let mut params = rcgen::CertificateParams::new(hosts.to_vec()).ok()?;
            (params.not_before, params.not_after) = (day(left - 90), day(left));
            let leaf = params.signed_by(&key, &self.issuer).ok()?;
            Some(format!("{}{}", leaf.pem(), self.ca_pem))
        }

        async fn dispatch(&self, path: &str, body: &str) -> Result<(u16, Option<String>, String), Fail> {
            let bad = |detail: &str| -> Fail { (400, "malformed", detail.to_string()) };
            let text = |v: &Value| v.as_str().map(String::from).ok_or(bad("missing member"));
            let jws: Value = serde_json::from_str(body).map_err(|_| bad("not JSON"))?;
            let (protected_b64, payload_b64, signature) = (text(&jws["protected"])?, text(&jws["payload"])?, text(&jws["signature"])?);
            let protected: Value =
                unb64(&protected_b64).and_then(|b| serde_json::from_slice(&b).ok()).ok_or(bad("unreadable protected header"))?;
            let nonce = protected["nonce"].as_str().unwrap_or_default();
            if self.bad_nonce_once.swap(false, SeqCst) || !self.state.lock().unwrap().nonces.remove(nonce) {
                return Err((400, "badNonce", "that nonce is not good".into()));
            }
            if protected["alg"] != "ES256" || protected["url"] != format!("{}{path}", self.base) {
                return Err(bad("wrong alg or url"));
            }
            let (key, thumbprint) = if path == "/acct" {
                let (x, y) = (text(&protected["jwk"]["x"])?, text(&protected["jwk"]["y"])?);
                let mut point = vec![4u8];
                point.extend(unb64(&x).ok_or(bad("x"))?);
                point.extend(unb64(&y).ok_or(bad("y"))?);
                (point, b64(&sha256(format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#).as_bytes())))
            } else {
                let known = self.state.lock().unwrap().account.clone();
                match known.filter(|_| protected["kid"] == format!("{}/acct/1", self.base)) {
                    Some(account) => account,
                    None => return Err((401, "accountDoesNotExist", "unknown account".into())),
                }
            };
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &key)
                .verify(format!("{protected_b64}.{payload_b64}").as_bytes(), &unb64(&signature).ok_or(bad("signature"))?)
                .map_err(|_| -> Fail { (401, "unauthorized", "the signature does not verify".into()) })?;
            let payload: Option<Value> = match payload_b64.is_empty() {
                true => None,
                false => Some(unb64(&payload_b64).and_then(|b| serde_json::from_slice(&b).ok()).ok_or(bad("unreadable payload"))?),
            };

            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let index = |i: usize| parts.get(i).and_then(|p| p.parse::<usize>().ok()).ok_or(bad("bad path"));
            match parts[0] {
                "acct" => {
                    let payload = payload.ok_or(bad("payload required"))?;
                    if payload["termsOfServiceAgreed"] != true {
                        return Err(bad("the terms of service must be agreed to"));
                    }
                    let mut state = self.state.lock().unwrap();
                    state.account = Some((key, thumbprint));
                    state.contact = payload["contact"].clone();
                    self.accounts.fetch_add(1, SeqCst);
                    Ok((201, Some(format!("{}/acct/1", self.base)), json!({ "status": "valid" }).to_string()))
                }
                "order" if parts.len() == 1 => {
                    let payload = payload.ok_or(bad("payload required"))?;
                    let identifiers = payload["identifiers"].as_array().ok_or(bad("identifiers"))?;
                    let hosts: Vec<String> = identifiers.iter().filter_map(|i| i["value"].as_str().map(String::from)).collect();
                    let authz = hosts
                        .iter()
                        .map(|h| Authz {
                            host: h.trim_start_matches("*.").to_string(),
                            wildcard: h.starts_with("*."),
                            token: format!("tok-{}", uuid::Uuid::new_v4().simple()),
                            status: "pending",
                            error: String::new(),
                        })
                        .collect();
                    let mut state = self.state.lock().unwrap();
                    state.orders.push(Order { hosts, authz, certificate: None });
                    let i = state.orders.len() - 1;
                    Ok((201, Some(format!("{}/order/{i}", self.base)), self.order_json(&state.orders[i], i)))
                }
                "order" => {
                    let i = index(1)?;
                    let state = self.state.lock().unwrap();
                    let order = state.orders.get(i).ok_or(bad("no such order"))?;
                    Ok((200, None, self.order_json(order, i)))
                }
                "authz" => {
                    let (i, j) = (index(1)?, index(2)?);
                    let state = self.state.lock().unwrap();
                    let authz = state.orders.get(i).and_then(|o| o.authz.get(j)).ok_or(bad("no such authorization"))?;
                    Ok((200, None, self.authz_json(authz, i, j)))
                }
                "chall" => {
                    if payload != Some(json!({})) {
                        return Err(bad("a challenge is answered with {}"));
                    }
                    let (i, j, kind) = (index(1)?, index(2)?, parts.get(3).copied().unwrap_or_default());
                    let found = {
                        let state = self.state.lock().unwrap();
                        state.orders.get(i).and_then(|o| o.authz.get(j)).map(|a| (a.host.clone(), a.wildcard, a.token.clone()))
                    };
                    let (host, wildcard, token) = found.ok_or(bad("no such challenge"))?;
                    let outcome = match wildcard && kind != "dns-01" {
                        true => Err("wildcards need dns-01".to_string()),
                        false => self.validate(kind, &host, &format!("{token}.{thumbprint}")).await,
                    };
                    let mut state = self.state.lock().unwrap();
                    match outcome {
                        Ok(()) => {
                            state.orders[i].authz[j].status = "valid";
                            state.validated.push(format!("{kind} {host}"));
                        }
                        Err(e) => {
                            state.orders[i].authz[j].status = "invalid";
                            state.orders[i].authz[j].error = e;
                        }
                    }
                    Ok((200, None, json!({ "type": kind, "status": "processing", "token": token }).to_string()))
                }
                "finalize" => {
                    let i = index(1)?;
                    let csr = payload.as_ref().and_then(|p| p["csr"].as_str()).and_then(unb64).ok_or(bad("csr"))?;
                    let mut state = self.state.lock().unwrap();
                    let order = state.orders.get_mut(i).ok_or(bad("no such order"))?;
                    if order.authz.iter().any(|a| a.status != "valid") {
                        return Err((403, "orderNotReady", "not every name is validated".into()));
                    }
                    order.certificate = Some(self.sign(&order.hosts, &csr).ok_or(bad("unusable CSR"))?);
                    Ok((200, None, self.order_json(order, i)))
                }
                "cert" => {
                    let i = index(1)?;
                    let state = self.state.lock().unwrap();
                    let chain = state.orders.get(i).and_then(|o| o.certificate.clone()).ok_or(bad("no certificate"))?;
                    Ok((200, None, chain))
                }
                _ => Err((404, "malformed", "no such resource".into())),
            }
        }
    }

    async fn ca_post(State(ca): State<Arc<Ca>>, uri: axum::http::Uri, body: String) -> axum::response::Response {
        let (status, location, body) = match ca.dispatch(uri.path(), &body).await {
            Ok(reply) => reply,
            Err((status, kind, detail)) => {
                (status, None, json!({ "type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail }).to_string())
            }
        };
        let mut resp = axum::response::Response::new(axum::body::Body::from(body));
        *resp.status_mut() = StatusCode::from_u16(status).unwrap();
        resp.headers_mut().insert("replay-nonce", ca.nonce().parse().unwrap());
        if let Some(location) = location {
            resp.headers_mut().insert("location", location.parse().unwrap());
        }
        resp
    }

    struct Env {
        store: Arc<Store>,
        acme: Acme,
        ca: Arc<Ca>,
        /// A zone delegated to us, and one that is hosted elsewhere.
        full: String,
        partial: String,
        https_port: u16,
    }

    impl Env {
        fn order(&self, zone: &str, body: Value) -> CertificatePack {
            self.store.save_item::<CertificatePack>(zone, None, body, true).unwrap()
        }
        fn pack(&self, pack: &CertificatePack) -> CertificatePack {
            self.store.item::<CertificatePack>(&pack.meta.zone_id, &pack.meta.id).unwrap()
        }
        fn orders(&self) -> usize {
            self.ca.state.lock().unwrap().orders.len()
        }
        fn retry_now(&self, pack: &CertificatePack) {
            self.store.update_pack(&pack.meta.id, |p| p.next_attempt = None).unwrap();
        }
    }

    async fn setup() -> Env {
        let store = Arc::new(temp_store());
        let full = store.create_zone("example.com").unwrap().id;
        let partial = store.create_zone_as("partial.net", "partial").unwrap().id;
        let mut www = rec("www", "A", "127.0.0.1");
        www.proxied = true;
        store.create_record(&partial, www).unwrap();
        store.create_record(&full, rec("_acme-challenge", "TXT", "left over from something else")).unwrap();

        let edge = Arc::new(Edge::new(store.clone(), Arc::new(Cache::new(1 << 20)), Arc::new(Waf::new()), vec![]).unwrap());
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (http_port, https_port) = (http.local_addr().unwrap().port(), https.local_addr().unwrap().port());
        tokio::spawn(crate::edge::serve(http, edge.clone(), None, false));
        tokio::spawn(crate::edge::serve(https, edge.clone(), Some(tls::server_config(store.clone()).unwrap()), false));
        let resolver = Arc::new(Resolver {
            store: store.clone(),
            edge_v4: vec!["203.0.113.10".parse().unwrap()],
            edge_v6: vec![],
            geo: Arc::default(),
            health: Arc::default(),
            cname_base: Some("cdn.test".into()),
            name_servers: vec![],
            h3_port: None, h3_front: None, edge_ttl: 60,
            flat: Arc::default(),
            limits: Arc::default(),
            accelerate: false,
            rtt: Arc::default(),
        });

        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "fucf test CA");
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ca = Arc::new(Ca {
            base: format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port()),
            resolver,
            http_port,
            https_port,
            issuer: rcgen::Issuer::new(ca_params, ca_key),
            ca_pem,
            state: Mutex::default(),
            delegated: vec!["partial.net"],
            reject: AtomicBool::new(false),
            bad_nonce_once: AtomicBool::new(false),
            days_left: AtomicI64::new(90),
            accounts: AtomicUsize::new(0),
        });
        let app = axum::Router::new()
            .route(
                "/dir",
                axum::routing::get(|State(ca): State<Arc<Ca>>| async move {
                    let url = |name: &str| format!("{}/{name}", ca.base);
                    axum::Json(json!({ "newNonce": url("nonce"), "newAccount": url("acct"), "newOrder": url("order") }))
                }),
            )
            .route("/nonce", axum::routing::get(|State(ca): State<Arc<Ca>>| async move { ([("replay-nonce", ca.nonce())], "") }))
            .fallback(ca_post)
            .with_state(ca.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let account = std::env::temp_dir().join(format!("fucf-acme-{}.json", uuid::Uuid::new_v4().simple()));
        let mut acme = Acme::new(edge, Arc::default(), format!("{}/dir", ca.base), Some("ops@example.com".into()), account);
        (acme.poll, acme.startup_grace, acme.sync_timeout) = (Duration::from_millis(20), Duration::ZERO, Duration::from_secs(5));
        Env { store, acme, ca, full, partial, https_port }
    }

    fn leaf(pack: &CertificatePack) -> Vec<u8> {
        CertificateDer::pem_slice_iter(pack.certificate.as_bytes()).next().unwrap().unwrap().to_vec()
    }

    #[tokio::test]
    async fn proxy_rule_hosts_get_their_own_certificates() {
        let Env { store, acme, ca, https_port, .. } = setup().await;
        store
            .save_proxy_rule(None, json!({
                "name": "site", "nodes": ["n1"], "hosts": ["App.example.org", "*.example.org", "intranet.local"],
                "respond": { "body": "hi" }
            }))
            .unwrap();
        store.save_proxy_rule(None, json!({ "name": "manual", "nodes": ["n1"], "hosts": ["manual.example.org"], "auto_https": false, "respond": {} })).unwrap();
        store.save_proxy_rule(None, json!({ "name": "elsewhere", "nodes": ["n2"], "hosts": ["other.example.org"], "respond": {} })).unwrap();
        let dir = std::env::temp_dir().join(format!("fucf-site-{}", uuid::Uuid::new_v4().simple()));
        let mut site = crate::site_acme::SiteAcme::new(Arc::new(acme), dir.clone());
        site.node = Some("n1".into());
        let now = unix_now();
        assert_eq!(site.due(now), ["app.example.org"]);

        site.tick().await;
        assert_eq!(ca.state.lock().unwrap().validated, ["http-01 app.example.org"]);
        let crt = std::fs::read_to_string(dir.join("app.example.org/app.example.org.crt")).unwrap();
        let key = dir.join("app.example.org/app.example.org.key");
        assert!(crt.contains("BEGIN CERTIFICATE") && std::fs::read_to_string(&key).unwrap().contains("PRIVATE KEY"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o077, 0, "the key is private");
        }
        assert!(site.due(now).is_empty(), "nothing more to do while the certificate is fresh");
        assert!(site.due(now + 61 * 86400).contains(&"app.example.org".to_string()), "renewed in the last third");
        site.tick().await;
        assert_eq!(ca.state.lock().unwrap().orders.len(), 1, "no second order");
        assert_eq!(crate::site_acme::http01("anything"), None, "answers are withdrawn");

        // TLS-ALPN-01 is answered by the edge's TLS listener, for a name it has no zone for
        let (chain, _) = site.acme.issue_site(&["b.example.org".into()], "tls-alpn-01", None).await.unwrap();
        assert!(chain.contains("BEGIN CERTIFICATE"));
        assert_eq!(ca.state.lock().unwrap().validated.last().unwrap(), "tls-alpn-01 b.example.org");
        assert!(!presented(https_port, "b.example.org", tls::ACME_TLS_ALPN).await.is_ok_and(|(_, alpn)| alpn.is_some()), "withdrawn");

        // a CA that refuses: back off instead of hammering it
        ca.reject.store(true, SeqCst);
        let stale = unix_now() + 70 * 86400;
        let before = ca.state.lock().unwrap().orders.len();
        site.acme.edge.store.save_proxy_rule(None, json!({ "name": "new", "nodes": ["n1"], "hosts": ["new.example.org"], "respond": {} })).unwrap();
        site.tick().await;
        assert_eq!(ca.state.lock().unwrap().orders.len(), before + 1);
        assert!(!site.due(unix_now()).contains(&"new.example.org".to_string()), "waits before trying again");
        assert!(site.due(stale).contains(&"new.example.org".to_string()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn obtains_certificates_through_every_challenge() {
        let env = setup().await;
        // apex + wildcard of a zone we are authoritative for: two DNS challenges at one name
        let wildcard = env.order(&env.full, json!({}));
        assert_eq!((wildcard.hosts.join(" "), wildcard.status.as_str()), ("example.com *.example.com".into(), "pending"));
        // a host of a zone kept elsewhere: only the edge can prove anything
        let host = env.order(&env.partial, json!({ "hosts": ["WWW.partial.net"] }));
        // its wildcard: DNS, through a CNAME into our base domain
        let delegated = env.order(&env.partial, json!({ "hosts": ["*.partial.net"] }));
        let over_http = env.order(&env.full, json!({ "hosts": ["h.example.com"], "validation_method": "http" }));
        // before anything is issued the edge has only its self-signed certificate
        let before = presented(env.https_port, "www.example.com", b"http/1.1").await.unwrap().0;

        env.ca.bad_nonce_once.store(true, SeqCst); // a stale nonce is not an error
        env.acme.tick().await;

        for pack in [&wildcard, &host, &delegated, &over_http] {
            let p = env.pack(pack);
            assert_eq!((p.status.as_str(), p.error.as_str(), p.attempts), ("active", "", 0), "{:?}", p.hosts);
            assert!(p.issued_on.is_some() && parse_time(p.expires_on.as_deref().unwrap()).unwrap() > unix_now() + 80 * 86400);
            assert!(p.public().get("private_key").is_none() && p.public()["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
        }
        let mut validated = env.ca.state.lock().unwrap().validated.clone();
        validated.sort();
        assert_eq!(
            validated,
            ["dns-01 example.com", "dns-01 example.com", "dns-01 partial.net", "http-01 h.example.com", "tls-alpn-01 www.partial.net"]
        );
        assert_eq!(env.ca.state.lock().unwrap().contact, json!(["mailto:ops@example.com"]));
        assert_eq!(env.store.pending_challenges(), 0, "challenges are withdrawn once answered");

        // the edge serves what was issued: apex, wildcard and single hosts
        let issued = leaf(&env.pack(&wildcard));
        assert_ne!(before, issued);
        for name in ["example.com", "www.example.com"] {
            assert_eq!(presented(env.https_port, name, b"http/1.1").await.unwrap().0, issued, "{name}");
        }
        assert_eq!(presented(env.https_port, "www.partial.net", b"h2").await.unwrap().0, leaf(&env.pack(&host)));
        assert_eq!(presented(env.https_port, "x.partial.net", b"h2").await.unwrap().0, leaf(&env.pack(&delegated)));
        assert_eq!(presented(env.https_port, "h.example.com", b"h2").await.unwrap().0, leaf(&env.pack(&over_http)), "an exact name beats the wildcard");
        // nobody is answered as a CA any more
        assert!(presented(env.https_port, "www.partial.net", tls::ACME_TLS_ALPN).await.is_err());
        // an uploaded certificate takes precedence over a managed one
        let own = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        let upload = json!({ "hosts": ["example.com"], "certificate": own.cert.pem(), "private_key": own.signing_key.serialize_pem() });
        let uploaded = env.store.save_item::<crate::items::Certificate>(&env.full, None, upload, true).unwrap();
        assert_eq!(presented(env.https_port, "example.com", b"h2").await.unwrap().0, own.cert.der().to_vec());
        assert!(uploaded.public()["expires_on"].as_str().is_some_and(|t| t.starts_with("4096-")));

        // nothing is due: the CA is left alone, and the account is kept
        let orders = env.orders();
        env.acme.tick().await;
        assert_eq!((env.orders(), env.ca.accounts.load(SeqCst)), (orders, 1));
        // deleting a zone takes its packs along
        env.store.delete_zone(&env.partial).unwrap();
        assert_eq!(env.store.all_packs().len(), 2);
    }

    #[tokio::test]
    async fn failures_back_off_and_renewals_keep_the_old_certificate() {
        let env = setup().await;
        let pack = env.order(&env.full, json!({ "hosts": ["a.example.com"] }));
        assert!(env.store.save_item::<CertificatePack>(&env.full, None, json!({ "hosts": ["a.example.org"] }), true).is_err());
        let wildcard_over_tls = json!({ "hosts": ["*.example.com"], "validation_method": "tls-alpn" });
        assert!(env.store.save_item::<CertificatePack>(&env.full, None, wildcard_over_tls, true).is_err());

        env.ca.reject.store(true, SeqCst);
        env.acme.tick().await;
        let p = env.pack(&pack);
        assert_eq!((p.status.as_str(), p.attempts), ("failed", 1));
        assert!(p.error.contains("validation of a.example.com failed: the CA was told to refuse"), "{}", p.error);
        let wait = parse_time(p.next_attempt.as_deref().unwrap()).unwrap() - unix_now();
        assert!((590..=600).contains(&wait), "{wait}");
        assert_eq!(env.store.pending_challenges(), 0);
        // not before the wait is over
        env.acme.tick().await;
        assert_eq!((env.orders(), env.pack(&pack).attempts), (1, 1));

        // second try: the CA issues a certificate with 10 of its 90 days left
        env.ca.reject.store(false, SeqCst);
        env.ca.days_left.store(10, SeqCst);
        env.retry_now(&pack);
        env.acme.tick().await;
        let first = env.pack(&pack);
        assert_eq!((first.status.as_str(), first.error.as_str(), first.attempts), ("active", "", 0));
        assert!(first.next_attempt.is_some(), "even a certificate about to expire is not renewed in a loop");
        env.acme.tick().await;
        assert_eq!(env.orders(), 2);

        // renewal is due but fails: the certificate in use stays
        env.ca.reject.store(true, SeqCst);
        env.retry_now(&pack);
        env.acme.tick().await;
        let p = env.pack(&pack);
        assert_eq!((p.status.as_str(), p.attempts, p.certificate == first.certificate), ("active", 1, true));
        assert!(!p.error.is_empty());
        assert_eq!(presented(env.https_port, "a.example.com", b"h2").await.unwrap().0, leaf(&first));

        // and then succeeds, with a full lifetime: nothing more to do
        env.ca.reject.store(false, SeqCst);
        env.ca.days_left.store(90, SeqCst);
        env.retry_now(&pack);
        env.acme.tick().await;
        let renewed = env.pack(&pack);
        assert!(renewed.certificate != first.certificate && renewed.error.is_empty());
        assert_eq!(presented(env.https_port, "a.example.com", b"h2").await.unwrap().0, leaf(&renewed));
        env.retry_now(&pack);
        let orders = env.orders();
        env.acme.tick().await;
        assert_eq!(env.orders(), orders);
        assert_eq!(env.ca.accounts.load(SeqCst), 1);

        // an unreachable CA is an error like any other
        let other = env.order(&env.full, json!({ "hosts": ["b.example.com"] }));
        let mut offline = Acme::new(env.acme.edge.clone(), Arc::default(), "http://127.0.0.1:9/dir".into(), None, env.acme.account_path.clone());
        offline.startup_grace = Duration::ZERO;
        offline.tick().await;
        let p = env.pack(&other);
        assert!(p.status == "failed" && p.error.contains("cannot reach http://127.0.0.1:9/dir"), "{}", p.error);
    }

    #[tokio::test]
    async fn waits_for_replicas_and_cleans_up() {
        let mut env = setup().await;
        let fleet = Arc::new(Fleet::default());
        env.acme.fleet = fleet.clone();
        fleet.seen("eu", "an older version", "0.1.0");
        let version = env.store.version();
        let late = fleet.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            late.seen("eu", &version, "0.1.0");
        });
        let started = Instant::now();
        env.acme.wait_for_fleet().await;
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(300) && waited < Duration::from_secs(3), "{waited:?}");

        // a replica that never catches up does not block issuance for ever
        fleet.seen("us", "stuck", "0.1.0");
        env.acme.sync_timeout = Duration::from_millis(400);
        let started = Instant::now();
        env.acme.wait_for_fleet().await;
        assert!(started.elapsed() >= Duration::from_millis(400));

        // challenges of an interrupted run are withdrawn
        env.acme.node_name = Some("aa".into());
        let stale = AcmeChallenge { pack_id: "gone".into(), host: "example.com".into(), kind: "dns-01".into(), token: "t".into(), key_authorization: "t.x".into(), sync: Default::default() };
        env.store.set_challenges(Some("gone"), vec![stale]).unwrap();
        assert_eq!(env.store.snapshot().acme_dns["example.com"].len(), 1);
        env.acme.tick().await;
        assert_eq!(env.store.pending_challenges(), 0);
    }

    #[tokio::test]
    async fn acme_leader_lease_prevents_double_order() {
        let mut env = setup().await;
        let fleet = Arc::new(Fleet::default());
        fleet.seen("au", &env.store.version(), "0.1.0");
        fleet.seen("us", &env.store.version(), "0.1.0");
        env.acme.fleet = fleet;
        env.acme.node_name = Some("us".into());
        let pack = env.order(&env.full, json!({}));

        // Since "au" < "us" and both are online peers, "us" defers to leader "au" and does NOT order.
        env.acme.tick().await;
        assert_eq!(env.pack(&pack).status, "pending");
        assert_eq!(env.ca.state.lock().unwrap().orders.len(), 0);

        // Even if node_name is "au", an active lease held by "us" blocks "au" from double-ordering.
        env.acme.node_name = Some("au".into());
        let now_ms = crate::sync::clock::unix_ms();
        env.store
            .set_acme_lease_async(crate::sync::acme_lease::AcmeLease {
                holder: "us".into(),
                acquired_ms: now_ms,
                pack_id: Some(pack.meta.id.clone()),
                expires_ms: now_ms + 60_000,
                sync: Default::default(),
            })
            .await
            .unwrap();
        env.acme.tick().await;
        assert_eq!(env.ca.state.lock().unwrap().orders.len(), 0);

        // Once the lease clears, "au" (the lowest online peer) orders exactly once.
        env.store.set_acme_lease_async(crate::sync::acme_lease::AcmeLease::default()).await.unwrap();
        env.acme.tick().await;
        assert_eq!(env.pack(&pack).status, "active");
        assert_eq!(env.ca.state.lock().unwrap().orders.len(), 1);
    }
}
