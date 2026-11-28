//! The human check for any page, in the manner of Cloudflare Turnstile: a
//! site puts a box into its own forms, the box runs the edge's challenge
//! (the same detection and proof of work as [`super::challenge`]), and the
//! site's backend asks the edge whether what came back with the form is real.
//!
//! 1. A [`ChallengeWidget`] (a global object: its id is the public sitekey)
//!    names the host names it may be used on and has a secret that only its
//!    backend knows. The secret is shown once; the store keeps its SHA-256.
//! 2. `/cdn-cgi/challenge-platform/widget.js` renders into every element with
//!    a `data-sitekey`. It fetches a puzzle from
//!    `/cdn-cgi/challenge-platform/widget/ticket` on the page's own host,
//!    which is only handed out for a proxied host that is one of the widget's
//!    domains, and answers it at `/cdn-cgi/challenge-platform/widget/verify`.
//!    A browser that passes gets a token, which the script writes into a
//!    hidden `fcf-challenge-response` field inside the container (so inside
//!    the form around it).
//! 3. The backend posts `secret` and `response` (and optionally `remoteip`)
//!    to `/cdn-cgi/challenge-platform/siteverify` and gets Turnstile's answer
//!    shape. A token is signed with the fleet's key, under a prefix of its
//!    own, lives five minutes, is bound to the sitekey, the host name and the
//!    visitor's address, and is accepted once per node.
//!
//! Nothing here hands out the zone's clearance cookie, and nothing the zone's
//! challenge signs is accepted here: every value this module signs starts
//! with a prefix that no other signer in the code base uses.

use super::challenge::{self, Level, Outcome};
use super::waf::Waf;
use super::{full, Body, Edge};
use crate::store::{Store, StoreError};
use crate::sync::SyncMeta;
use base64::Engine;
use http_body_util::BodyExt;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

/// The script a site loads.
pub const SCRIPT_PATH: &str = "/cdn-cgi/challenge-platform/widget.js";
/// Where the script gets its puzzle (on the page's own host).
pub const TICKET_PATH: &str = "/cdn-cgi/challenge-platform/widget/ticket";
/// Where the script sends its answer (on the page's own host).
pub const ANSWER_PATH: &str = "/cdn-cgi/challenge-platform/widget/verify";
/// Where a site's backend checks a token. (The form field the script fills
/// in, `fcf-challenge-response`, is named in the script alone.)
pub const SITEVERIFY_PATH: &str = "/cdn-cgi/challenge-platform/siteverify";

/// How long a token may be checked (Turnstile's five minutes).
pub const TOKEN_SECS: u64 = 300;
/// How long a puzzle may be answered.
const TICKET_SECS: u64 = 300;
/// How far ahead of this node's clock another node's stamp may be.
const SKEW_SECS: u64 = 5;
/// Widgets in the whole account (each is looked through on every siteverify).
pub const MAX_WIDGETS: usize = 50;
/// Host names per widget.
pub const MAX_DOMAINS: usize = 10;
/// Characters in a widget's name (Cloudflare's limit).
const MAX_NAME: usize = 254;
/// A browser's answer is small; anything larger is not ours.
const MAX_ANSWER: usize = 32 * 1024;
/// A siteverify request is three short fields.
const MAX_SITEVERIFY: usize = 16 * 1024;
/// Longer than any secret this module makes.
const MAX_SECRET: usize = 128;
/// Longer than any token this module makes (Turnstile's limit).
const MAX_RESPONSE: usize = 2048;
/// Tokens (and puzzles) remembered per node to refuse a second use. When it
/// is full of ones that have not expired, answers are refused rather than an
/// entry forgotten: a forgotten entry could be used again.
const REPLAY_CAP: usize = 100_000;

/// What a secret starts with (tells it apart from other credentials).
const SECRET_PREFIX: &str = "fcfws_";
/// Domain separation for [`Waf::mac`]: a token's MAC covers this and its
/// payload. Other signers use `challenge|` (the zone's puzzle) or a zone id
/// (the clearance cookie), so neither can ever produce or accept one of these.
const TOKEN_MAC: &str = "fcf-challenge-widget-token|";
/// The same for the widget's puzzle.
const TICKET_MAC: &str = "fcf-challenge-widget-ticket|";
/// The visible start of a token: no other signed value of the edge has it,
/// and it is neither a number (a clearance cookie starts with its expiry)
/// nor valid base64 (the zone's puzzle starts with its payload).
const TOKEN_TAG: &str = "fcfw1";
const TICKET_TAG: &str = "fcfwt1";

/// What the page runs: what the challenge page and the injected script share, then the widget's own part.
const SCRIPT: &str = concat!(include_str!("challenge-core.js"), include_str!("challenge-widget.js"));

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

fn managed() -> String {
    "managed".to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn b64(text: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text.as_bytes())
}

fn unb64(text: &str) -> Option<String> {
    String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text).ok()?).ok()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A random value nobody can guess, for what must be told apart once.
fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// How a secret is kept: SHA-256, hex. The secret is 256 random bits, so a
/// plain digest cannot be searched backwards, and checking needs no more.
fn digest(secret: &str) -> String {
    crate::release::sha256_hex(secret.as_bytes())
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Is this the shape of a sitekey (the store's ids: 32 lowercase hex digits)?
pub fn is_sitekey(text: &str) -> bool {
    is_hex(text, 32)
}

/// A new secret and the digest to keep, or `None` if the system has no randomness.
pub fn new_secret() -> Option<(String, String)> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
    let secret = format!("{SECRET_PREFIX}{}", hex(&bytes));
    let kept = digest(&secret);
    Some((secret, kept))
}

// ------------------------------------------------------------ widgets ----

/// A site's human check. A global object, replicated with the configuration;
/// its `id` is the sitekey that goes into the site's pages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeWidget {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Exact host names (lowercase) whose pages may use the widget and whose
    /// tokens its backend accepts.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Cloudflare's widget mode; only `managed` (a click when in doubt) is done here.
    #[serde(default = "managed")]
    pub mode: String,
    /// SHA-256 of the secret. Never shown, never logged.
    #[serde(default)]
    pub secret_sha256: String,
    #[serde(default)]
    pub created_on: String,
    #[serde(default)]
    pub modified_on: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

impl ChallengeWidget {
    /// The widget as the API shows it: no secret (not even its digest), no
    /// replication data. The id is also given as Cloudflare's `sitekey`.
    pub fn public(&self) -> Value {
        json!({
            "id": self.id,
            "sitekey": self.id,
            "name": self.name,
            "domains": self.domains,
            "mode": self.mode,
            "created_on": self.created_on,
            "modified_on": self.modified_on,
        })
    }

    /// [`ChallengeWidget::public`] with the secret: only the answer to a
    /// creation or a rotation, the one time the secret exists outside the
    /// backend that keeps it.
    pub fn with_secret(&self, secret: &str) -> Value {
        let mut v = self.public();
        v["secret"] = json!(secret);
        v
    }

    /// May pages of `host` use this widget (and its backend accept their tokens)?
    pub fn allows(&self, host: &str) -> bool {
        self.domains.iter().any(|d| d == host)
    }

    /// The widget to save: `old` (or a new one) with the fields of `body`.
    /// `secret_sha256` is the digest of a new secret: required for a new
    /// widget, given on a rotation, otherwise the old one stays. Fields the
    /// server sets cannot be set, and Cloudflare's options other than their
    /// defaults are refused rather than left out, since they would not do here
    /// what a client expects. `count`: how many widgets there are now.
    pub fn build(old: Option<&ChallengeWidget>, body: Value, secret_sha256: Option<String>, count: usize) -> Result<ChallengeWidget, StoreError> {
        let Value::Object(body) = body else { return invalid("request body must be a JSON object") };
        let mut w = match old {
            Some(old) => old.clone(),
            None if count >= MAX_WIDGETS => return invalid(format!("at most {MAX_WIDGETS} widgets")),
            None => ChallengeWidget { mode: managed(), ..Default::default() },
        };
        let text = |key: &str, v: &Value| v.as_str().map(str::to_string).ok_or_else(|| StoreError::Invalid(format!("{key} must be a string")));
        for (key, value) in body {
            match key.as_str() {
                "name" => w.name = text("name", &value)?.trim().to_string(),
                "domains" => w.domains = domains(&value)?,
                "mode" => w.mode = text("mode", &value)?.trim().to_string(),
                // the server's own fields, sent back as they were shown
                "id" | "sitekey" => match old {
                    Some(old) if value.as_str() == Some(old.id.as_str()) => {}
                    Some(_) => return invalid(format!("{key} cannot be changed")),
                    None => return invalid(format!("{key} is made by the server")),
                },
                "created_on" | "modified_on" => {}
                "secret" | "secret_sha256" => return invalid("the secret is made by the server: rotate it with POST …/rotate_secret"),
                // Cloudflare's options: their defaults are what this edge does
                "bot_fight_mode" | "offlabel" | "ephemeral_id" if value == json!(false) => {}
                "clearance_level" if value == json!("no_clearance") => {}
                "region" if value == json!("world") => {}
                "bot_fight_mode" | "offlabel" | "ephemeral_id" => return invalid(format!("{key}: only false is supported")),
                "clearance_level" => return invalid("clearance_level: only no_clearance is supported (a widget never clears a zone's challenge)"),
                "region" => return invalid("region: only world is supported"),
                other => return invalid(format!("unknown field '{other}'")),
            }
        }
        if w.name.is_empty() || w.name.chars().count() > MAX_NAME || w.name.chars().any(char::is_control) {
            return invalid(format!("a widget needs a name (at most {MAX_NAME} characters, no control characters)"));
        }
        if w.domains.is_empty() {
            return invalid("domains must name at least one host name");
        }
        if w.mode != "managed" {
            return invalid(format!("mode '{}': only managed is supported (a click is asked for when the browser looks doubtful)", w.mode));
        }
        match secret_sha256 {
            Some(kept) if is_hex(&kept, 64) => w.secret_sha256 = kept,
            Some(_) => return invalid("a secret's digest is 64 hex digits"),
            None if old.is_some() => {}
            None => return invalid("a new widget needs a secret"),
        }
        Ok(w)
    }
}

/// The `domains` of a request: exact host names, lowercase, each once.
fn domains(value: &Value) -> Result<Vec<String>, StoreError> {
    let Some(list) = value.as_array() else { return invalid("domains must be a list of host names") };
    if list.is_empty() || list.len() > MAX_DOMAINS {
        return invalid(format!("domains must name 1 to {MAX_DOMAINS} host names"));
    }
    let mut out: Vec<String> = Vec::new();
    for d in list {
        let Some(d) = d.as_str() else { return invalid("domains must be a list of host names") };
        let host = d.trim().to_ascii_lowercase();
        check_host(&host).map_err(|why| StoreError::Invalid(format!("domain '{d}': {why}")))?;
        if out.contains(&host) {
            return invalid(format!("domain '{host}' is listed twice"));
        }
        out.push(host);
    }
    Ok(out)
}

/// A host name as a widget's domain: a DNS name of at least two labels,
/// letters, digits and hyphens only, no scheme, port, path, trailing dot or
/// wildcard (a token is bound to one exact name), and not an address.
pub fn check_host(host: &str) -> Result<(), &'static str> {
    if host.is_empty() || host.len() > 253 {
        return Err("a host name has 1 to 253 characters");
    }
    if host.starts_with("*.") || host.contains('*') {
        return Err("wildcards are not supported: list each host name");
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err("an address is not a host name");
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err("a host name has at least two labels (like example.com)");
    }
    for label in &labels {
        let ok = (1..=63).contains(&label.len())
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err("only letters, digits and hyphens, in labels of 1 to 63 characters (no scheme, port or path)");
        }
    }
    if labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) {
        return Err("the last label of a host name is not a number");
    }
    Ok(())
}

// --------------------------------------------------- tokens and puzzles ----

/// What a browser that passed gets, and its backend checks: signed, bound
/// to the widget, the page's host name and the visitor's address.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub sitekey: String,
    pub host: String,
    pub ip: IpAddr,
    pub issued: u64,
    pub nonce: String,
}

impl Token {
    fn payload(&self) -> String {
        format!("1|{}|{}|{}|{}|{}", self.sitekey, self.host, self.ip, self.issued, self.nonce)
    }

    pub fn seal(&self, waf: &Waf) -> String {
        let payload = self.payload();
        format!("{TOKEN_TAG}.{}.{}", b64(&payload), waf.mac(&format!("{TOKEN_MAC}{payload}")))
    }

    /// The token in `sealed`, if this fleet signed it as a widget token.
    pub fn open(waf: &Waf, sealed: &str) -> Option<Token> {
        if sealed.len() > MAX_RESPONSE {
            return None;
        }
        let (b64, mac) = sealed.strip_prefix(TOKEN_TAG)?.strip_prefix('.')?.split_once('.')?;
        let payload = unb64(b64)?;
        if !waf.mac_ok(&format!("{TOKEN_MAC}{payload}"), mac) {
            return None;
        }
        let f: Vec<&str> = payload.split('|').collect();
        let ["1", sitekey, host, ip, issued, nonce] = f.as_slice() else { return None };
        Some(Token { sitekey: sitekey.to_string(), host: host.to_string(), ip: ip.parse().ok()?, issued: issued.parse().ok()?, nonce: nonce.to_string() })
    }

    /// What tells this token apart in the replay set: from the signed
    /// payload, not from the string (the same payload can be written in more
    /// than one way, for one the MAC's hex in upper case).
    fn key(&self) -> String {
        format!("{}|{}", self.sitekey, self.nonce)
    }
}

/// The widget's puzzle: the zone challenge's ticket with the widget and the
/// host name in it, under a signature of its own.
#[derive(Debug, Clone, PartialEq)]
pub struct WidgetTicket {
    pub sitekey: String,
    pub host: String,
    pub ip: IpAddr,
    /// Digest of the User-Agent (as the zone's challenge keeps it).
    pub ua: String,
    pub issued: u64,
    pub bits: u8,
    pub click: bool,
    pub nonce: String,
    pub level: Level,
}

impl WidgetTicket {
    pub fn at(sitekey: &str, host: &str, ip: IpAddr, ua: &str, click: bool, level: Level, issued: u64) -> WidgetTicket {
        WidgetTicket {
            sitekey: sitekey.to_string(),
            host: host.to_string(),
            ip,
            ua: challenge::ua_digest(ua),
            issued,
            bits: level.bits(),
            click,
            nonce: nonce(),
            level,
        }
    }

    fn payload(&self) -> String {
        format!(
            "1|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.sitekey,
            self.host,
            self.ip,
            self.ua,
            self.issued,
            self.bits,
            self.click as u8,
            self.nonce,
            self.level.code()
        )
    }

    pub fn seal(&self, waf: &Waf) -> String {
        let payload = self.payload();
        format!("{TICKET_TAG}.{}.{}", b64(&payload), waf.mac(&format!("{TICKET_MAC}{payload}")))
    }

    pub fn open(waf: &Waf, sealed: &str) -> Option<WidgetTicket> {
        if sealed.len() > MAX_RESPONSE {
            return None;
        }
        let (b64, mac) = sealed.strip_prefix(TICKET_TAG)?.strip_prefix('.')?.split_once('.')?;
        let payload = unb64(b64)?;
        if !waf.mac_ok(&format!("{TICKET_MAC}{payload}"), mac) {
            return None;
        }
        let f: Vec<&str> = payload.split('|').collect();
        let ["1", sitekey, host, ip, ua, issued, bits, click, nonce, level] = f.as_slice() else { return None };
        Some(WidgetTicket {
            sitekey: sitekey.to_string(),
            host: host.to_string(),
            ip: ip.parse().ok()?,
            ua: ua.to_string(),
            issued: issued.parse().ok()?,
            bits: bits.parse().ok()?,
            click: *click == "1",
            nonce: nonce.to_string(),
            level: Level::from_code(level)?,
        })
    }
}

/// How hard a widget's puzzle is and how much doubt it forgives: the zone's
/// security level, but never below medium. A site that puts a widget into a
/// form wants the check, whatever it asks of visitors elsewhere ("off" or
/// "low" there must not make the widget easier).
pub fn widget_level(zone_level: Level) -> Level {
    match zone_level {
        Level::High | Level::UnderAttack => zone_level,
        _ => Level::Medium,
    }
}

/// What a node remembers of the tokens (or puzzles) it accepted, to accept
/// each one once. Bounded: entries are dropped only once expired.
pub struct Replay {
    cap: usize,
    seen: Mutex<HashMap<String, u64>>,
}

/// The answer of [`Replay::first_use`].
#[derive(Debug, PartialEq, Eq)]
pub enum Use {
    First,
    Again,
    /// Too many unexpired entries to remember one more.
    Full,
}

impl Replay {
    pub fn new(cap: usize) -> Replay {
        Replay { cap, seen: Mutex::new(HashMap::new()) }
    }

    /// Record `key` (valid until `until`) unless it was seen before.
    pub fn first_use(&self, key: &str, until: u64, now: u64) -> Use {
        let mut seen = self.seen.lock().unwrap();
        if seen.contains_key(key) {
            return Use::Again;
        }
        if seen.len() >= self.cap {
            seen.retain(|_, expires| *expires > now);
            if seen.len() >= self.cap {
                return Use::Full;
            }
        }
        seen.insert(key.to_string(), until);
        Use::First
    }

    pub fn contains(&self, key: &str) -> bool {
        self.seen.lock().unwrap().contains_key(key)
    }

    /// (For the tests of the bound.)
    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// This node's memory of accepted tokens.
fn used_tokens() -> &'static Replay {
    static R: OnceLock<Replay> = OnceLock::new();
    R.get_or_init(|| Replay::new(REPLAY_CAP))
}

/// This node's memory of answered puzzles.
fn used_tickets() -> &'static Replay {
    static R: OnceLock<Replay> = OnceLock::new();
    R.get_or_init(|| Replay::new(REPLAY_CAP))
}

// ---------------------------------------------------------- endpoints ----

/// Is `endpoint` (what follows `/cdn-cgi/`) one of the widget's?
pub fn handles(endpoint: &str) -> bool {
    [SCRIPT_PATH, TICKET_PATH, ANSWER_PATH, SITEVERIFY_PATH].iter().any(|p| p.strip_prefix("/cdn-cgi/") == Some(endpoint))
}

fn answer(status: StatusCode, body: Value) -> Response<Body> {
    let mut resp = Response::new(full(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut().insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    resp
}

fn refuse(status: StatusCode, code: &'static str) -> Response<Body> {
    answer(status, json!({ "ok": false, "code": code }))
}

/// Answer one of the widget's endpoints (see [`handles`]). Everything it
/// needs is owned: nothing borrowed may live across its awaits.
pub fn serve(
    edge: Arc<Edge>,
    endpoint: String,
    ip: IpAddr,
    ssl: bool,
    req: Request<Body>,
    host: String,
    ray: String,
) -> impl std::future::Future<Output = Response<Body>> + Send + 'static {
    async move {
        if Some(endpoint.as_str()) == SCRIPT_PATH.strip_prefix("/cdn-cgi/") {
            script()
        } else if Some(endpoint.as_str()) == TICKET_PATH.strip_prefix("/cdn-cgi/") {
            ticket(&edge, ip, &req, &host)
        } else if Some(endpoint.as_str()) == ANSWER_PATH.strip_prefix("/cdn-cgi/") {
            answer_puzzle(edge, ip, ssl, req, host, ray).await
        } else {
            siteverify(edge, ip, ssl, req, host, ray).await
        }
    }
}

/// `/cdn-cgi/challenge-platform/widget.js`.
fn script() -> Response<Body> {
    let mut resp = Response::new(full(SCRIPT));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    resp
}

/// Does the browser say this comes from a page of another origin? The
/// puzzle and its answer belong to the page's own host only: no CORS is
/// offered, and a browser's own word that it is cross-site is believed.
/// (A request without these headers is not a browser's, and is judged by
/// the challenge like any other.)
fn cross_site(headers: &HeaderMap, host: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        if site.as_bytes() != b"same-origin" {
            return true;
        }
    }
    match headers.get(header::ORIGIN) {
        None => false,
        Some(origin) => match origin.to_str().ok().and_then(|o| o.parse::<hyper::Uri>().ok()) {
            Some(uri) => uri.host().map(super::request_host).as_deref() != Some(host),
            // `null`, or not an origin at all
            None => true,
        },
    }
}

fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

/// How bad the visitor's address looks (as the zone's checks see it).
fn threat(edge: &Edge, ip: IpAddr, ua: &str) -> i64 {
    let Some(rep) = edge.reputation.get() else { return 0 };
    let location = edge.geo.get().map(|geo| geo.locate(ip)).unwrap_or_default();
    rep.assess(ip, location.asn.unwrap_or(0) as i64, location.as_org.as_deref().unwrap_or(""), ua).score as i64
}

/// `GET /cdn-cgi/challenge-platform/widget/ticket?sitekey=…`.
fn ticket(edge: &Edge, ip: IpAddr, req: &Request<Body>, host: &str) -> Response<Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return refuse(StatusCode::METHOD_NOT_ALLOWED, "get_only");
    }
    if cross_site(req.headers(), host) {
        return refuse(StatusCode::FORBIDDEN, "cross_origin");
    }
    let Some(sitekey) = query_param(req.uri().query(), "sitekey") else { return refuse(StatusCode::BAD_REQUEST, "missing_sitekey") };
    let ua = req.headers().get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let visitor = Visitor { ip, ssl: false, host, headers: req.headers(), threat: threat(edge, ip, ua) };
    match ticket_config(&edge.store, &edge.waf, sitekey, &visitor, unix_now()) {
        Ok(cfg) => answer(StatusCode::OK, cfg),
        Err(code) => refuse(StatusCode::FORBIDDEN, code),
    }
}

/// Who asks, as the widget's endpoints see them.
pub struct Visitor<'a> {
    pub ip: IpAddr,
    pub ssl: bool,
    /// The request's host name (lowercase, no port).
    pub host: &'a str,
    pub headers: &'a HeaderMap,
    /// How bad the address looks (see [`super::reputation`]).
    pub threat: i64,
}

impl Visitor<'_> {
    fn user_agent(&self) -> &str {
        self.headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default()
    }
}

/// The puzzle for a page of the visitor's host using widget `sitekey`: only
/// for a host this edge proxies that is one of the widget's domains. An
/// unknown sitekey and a host the widget does not list get the same answer.
pub fn ticket_config(store: &Store, waf: &Waf, sitekey: &str, visitor: &Visitor, now: u64) -> Result<Value, &'static str> {
    let host = visitor.host;
    if !is_sitekey(sitekey) {
        return Err("not_allowed");
    }
    let snap = store.snapshot();
    let Some(zone) = snap.find_zone(host).filter(|z| Edge::serves(z, host)) else { return Err("not_allowed") };
    if !store.get_challenge_widget(sitekey).is_some_and(|w| w.allows(host)) {
        return Err("not_allowed");
    }
    let level = widget_level(Level::of(&zone.zone.settings.security_level));
    // an address that looks bad is asked to click, as the zone's own challenge would ask it
    let click = level.challenge(visitor.threat) == Some(true);
    let t = WidgetTicket::at(sitekey, host, visitor.ip, visitor.user_agent(), click, level, now);
    Ok(json!({ "t": t.seal(waf), "b": t.bits, "c": click, "v": ANSWER_PATH }))
}

enum ReadError {
    Unreadable,
    TooLarge,
}

/// A request body of at most `max` bytes, frame by frame (as the zone's
/// challenge reads its answer: http_body_util::Limited trips a
/// higher-ranked lifetime bug of rustc here).
async fn read_body(mut body: Body, max: usize) -> Result<Vec<u8>, ReadError> {
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ReadError::Unreadable)?;
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
        if bytes.len() > max {
            return Err(ReadError::TooLarge);
        }
    }
    Ok(bytes)
}

fn media_type(headers: &HeaderMap) -> String {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default();
    ct.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
}

/// `POST /cdn-cgi/challenge-platform/widget/verify`: the page's answer to its puzzle.
async fn answer_puzzle(edge: Arc<Edge>, ip: IpAddr, ssl: bool, req: Request<Body>, host: String, ray: String) -> Response<Body> {
    if req.method() != Method::POST {
        return refuse(StatusCode::METHOD_NOT_ALLOWED, "post_only");
    }
    let (parts, body) = req.into_parts();
    if cross_site(&parts.headers, &host) {
        return refuse(StatusCode::FORBIDDEN, "cross_origin");
    }
    // JSON only: a page of another origin cannot send it without asking first
    if media_type(&parts.headers) != "application/json" {
        return refuse(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_only");
    }
    let bytes = match read_body(body, MAX_ANSWER).await {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge) => return refuse(StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
        Err(ReadError::Unreadable) => return refuse(StatusCode::BAD_REQUEST, "unreadable"),
    };
    let Ok(report) = serde_json::from_slice::<Value>(&bytes) else { return refuse(StatusCode::BAD_REQUEST, "unreadable") };
    let visitor = Visitor { ip, ssl, host: &host, headers: &parts.headers, threat: 0 };
    judge(&edge.waf, &edge.store, used_tickets(), &visitor, &report, &ray, unix_now())
}

/// The verdict on a page's answer: the zone challenge's checks, in its
/// order, and a token instead of a cookie. A puzzle is answered once: after
/// a pass or a failure it is spent (asking for a click does not spend it).
pub fn judge(waf: &Waf, store: &Store, tickets: &Replay, visitor: &Visitor, report: &Value, ray: &str, now: u64) -> Response<Body> {
    let (ip, host) = (visitor.ip, visitor.host);
    let sealed = report["t"].as_str().unwrap_or_default();
    let ua = visitor.user_agent();
    let Some(ticket) = WidgetTicket::open(waf, sealed) else { return refuse(StatusCode::FORBIDDEN, "bad_ticket") };
    if ticket.issued > now + SKEW_SECS || now.saturating_sub(ticket.issued) > TICKET_SECS {
        return refuse(StatusCode::FORBIDDEN, "expired");
    }
    if ticket.ip != ip || ticket.ua != challenge::ua_digest(ua) {
        return refuse(StatusCode::FORBIDDEN, "other_visitor");
    }
    if ticket.host != host {
        return refuse(StatusCode::FORBIDDEN, "other_host");
    }
    // the widget may have been deleted, or the host taken off it, since
    if !store.get_challenge_widget(&ticket.sitekey).is_some_and(|w| w.allows(host)) {
        return refuse(StatusCode::FORBIDDEN, "not_allowed");
    }
    if tickets.contains(&ticket.nonce) {
        return refuse(StatusCode::FORBIDDEN, "used");
    }
    if !report["n"].as_u64().is_some_and(|n| challenge::work_done(sealed, n, ticket.bits)) {
        return refuse(StatusCode::FORBIDDEN, "bad_work");
    }
    let clicked = report["m"] == "click";
    if ticket.click && !clicked {
        return answer(StatusCode::OK, json!({ "ok": false, "need": "click" }));
    }
    let (outcome, score, why) = challenge::assess_at(report, visitor.headers, visitor.ssl, clicked, ticket.level);
    tracing::info!(%ray, client = %ip, sitekey = %ticket.sitekey, score, clicked, signals = ?why, "widget answer: {outcome:?}");
    if outcome == Outcome::NeedClick {
        return answer(StatusCode::OK, json!({ "ok": false, "need": "click" }));
    }
    match tickets.first_use(&ticket.nonce, ticket.issued + TICKET_SECS + SKEW_SECS, now) {
        Use::First => {}
        Use::Again => return refuse(StatusCode::FORBIDDEN, "used"),
        Use::Full => return refuse(StatusCode::SERVICE_UNAVAILABLE, "busy"),
    }
    match outcome {
        Outcome::Pass => {
            let token = Token { sitekey: ticket.sitekey, host: ticket.host, ip, issued: now, nonce: nonce() };
            answer(StatusCode::OK, json!({ "ok": true, "token": token.seal(waf) }))
        }
        Outcome::Fail(code) => refuse(StatusCode::FORBIDDEN, code),
        Outcome::NeedClick => answer(StatusCode::OK, json!({ "ok": false, "need": "click" })),
    }
}

/// What a siteverify request carries.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct VerifyInput {
    pub secret: Option<String>,
    pub response: Option<String>,
    pub remoteip: Option<String>,
}

/// The fields of a siteverify body (`application/json` or
/// `application/x-www-form-urlencoded`), or `None` when it is neither, is
/// not text, gives a field twice or gives one as anything but a string.
/// Other fields (Turnstile's `idempotency_key`, for one) are not used.
pub fn parse_verify(media_type: &str, body: &[u8]) -> Option<VerifyInput> {
    let mut fields: HashMap<String, String> = HashMap::new();
    match media_type {
        "application/json" => {
            let Value::Object(map) = serde_json::from_slice::<Value>(body).ok()? else { return None };
            for (k, v) in map {
                match v {
                    Value::String(s) => {
                        fields.insert(k, s);
                    }
                    Value::Null => {}
                    _ if ["secret", "response", "remoteip"].contains(&k.as_str()) => return None,
                    _ => {}
                }
            }
        }
        "application/x-www-form-urlencoded" => {
            let text = std::str::from_utf8(body).ok()?;
            let decode = |s: &str| percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8().ok().map(|c| c.into_owned());
            for pair in text.split('&').filter(|p| !p.is_empty()) {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                // a field given twice: which one counts would be a guess
                if fields.insert(decode(k)?, decode(v)?).is_some() {
                    return None;
                }
            }
        }
        _ => return None,
    }
    let mut take = |k: &str| fields.remove(k).filter(|v| !v.is_empty());
    Some(VerifyInput { secret: take("secret"), response: take("response"), remoteip: take("remoteip") })
}

/// The answer to a siteverify, Turnstile's shape.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub success: bool,
    pub errors: Vec<&'static str>,
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    /// The widget the secret named (for the log), once it is known.
    pub sitekey: Option<String>,
}

impl Verdict {
    fn fail(errors: Vec<&'static str>, sitekey: Option<&str>) -> Verdict {
        Verdict { success: false, errors, challenge_ts: None, hostname: None, sitekey: sitekey.map(str::to_string) }
    }

    pub fn json(&self) -> Value {
        let mut v = json!({ "success": self.success, "error-codes": self.errors });
        if let (Some(ts), Some(host)) = (&self.challenge_ts, &self.hostname) {
            v["challenge_ts"] = json!(ts);
            v["hostname"] = json!(host);
        }
        v
    }
}

/// Check a token for a site's backend. Nothing about the token is looked
/// at before the secret has named a widget, so without the secret nothing
/// is learnt (not whether a sitekey or a token exists). A token is spent
/// only when everything else about it holds.
pub fn check(store: &Store, waf: &Waf, tokens: &Replay, input: &VerifyInput, now: u64) -> Verdict {
    let mut missing = Vec::new();
    if input.secret.is_none() {
        missing.push("missing-input-secret");
    }
    if input.response.is_none() {
        missing.push("missing-input-response");
    }
    let (Some(secret), Some(response)) = (&input.secret, &input.response) else { return Verdict::fail(missing, None) };
    let remote = match &input.remoteip {
        None => None,
        Some(text) => match text.trim().parse::<IpAddr>() {
            Ok(ip) => Some(ip.to_canonical()),
            Err(_) => return Verdict::fail(vec!["bad-request"], None),
        },
    };
    if secret.len() > MAX_SECRET {
        return Verdict::fail(vec!["invalid-input-secret"], None);
    }
    let presented = digest(secret);
    let widgets = store.list_challenge_widgets();
    // every widget is compared, in constant time each, whichever matches
    let mut found: Option<&ChallengeWidget> = None;
    for w in &widgets {
        if crate::auth::ct_eq(w.secret_sha256.as_bytes(), presented.as_bytes()) && found.is_none() {
            found = Some(w);
        }
    }
    let Some(widget) = found else { return Verdict::fail(vec!["invalid-input-secret"], None) };
    let bad = |code: &'static str| Verdict::fail(vec![code], Some(&widget.id));
    let Some(token) = Token::open(waf, response) else { return bad("invalid-input-response") };
    if token.sitekey != widget.id || !widget.allows(&token.host) {
        return bad("invalid-input-response");
    }
    if remote.is_some_and(|r| r != token.ip.to_canonical()) {
        return bad("invalid-input-response");
    }
    if token.issued > now + SKEW_SECS || now.saturating_sub(token.issued) > TOKEN_SECS {
        return bad("timeout-or-duplicate");
    }
    match tokens.first_use(&token.key(), token.issued + TOKEN_SECS + SKEW_SECS, now) {
        Use::First => {}
        Use::Again => return bad("timeout-or-duplicate"),
        Use::Full => return bad("internal-error"),
    }
    let ts = chrono::DateTime::from_timestamp(token.issued as i64, 0).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)).unwrap_or_default();
    Verdict { success: true, errors: Vec::new(), challenge_ts: Some(ts), hostname: Some(token.host), sitekey: Some(widget.id.clone()) }
}

/// Is `host` one this node answers siteverify on: the panel's host, or a
/// proxied name of a zone (a site calls it on its own host)?
fn verify_host(edge: &Edge, host: &str) -> bool {
    edge.panel.get().is_some_and(|(panel, _)| panel == host) || edge.store.snapshot().find_zone(host).is_some_and(|z| Edge::serves(z, host))
}

fn verdict(status: StatusCode, errors: Vec<&'static str>) -> Response<Body> {
    answer(status, Verdict::fail(errors, None).json())
}

/// `POST /cdn-cgi/challenge-platform/siteverify`: a site's backend asks about a token.
async fn siteverify(edge: Arc<Edge>, ip: IpAddr, ssl: bool, req: Request<Body>, host: String, ray: String) -> Response<Body> {
    if !verify_host(&edge, &host) {
        return verdict(StatusCode::NOT_FOUND, vec!["bad-request"]);
    }
    // the secret travels in the request: never in the clear (a backend on the node itself aside)
    if !ssl && !ip.is_loopback() {
        return verdict(StatusCode::FORBIDDEN, vec!["bad-request"]);
    }
    if req.method() != Method::POST {
        return verdict(StatusCode::METHOD_NOT_ALLOWED, vec!["bad-request"]);
    }
    let (parts, body) = req.into_parts();
    let media = media_type(&parts.headers);
    let bytes = match read_body(body, MAX_SITEVERIFY).await {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge) => return verdict(StatusCode::PAYLOAD_TOO_LARGE, vec!["bad-request"]),
        Err(ReadError::Unreadable) => return verdict(StatusCode::BAD_REQUEST, vec!["bad-request"]),
    };
    let Some(input) = parse_verify(&media, &bytes) else { return verdict(StatusCode::BAD_REQUEST, vec!["bad-request"]) };
    let v = check(&edge.store, &edge.waf, used_tokens(), &input, unix_now());
    if let Some(sitekey) = &v.sitekey {
        // (the sitekey is public; neither the secret nor the token is logged)
        tracing::info!(%ray, %sitekey, success = v.success, errors = ?v.errors, "widget siteverify");
    }
    answer(StatusCode::OK, v.json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{rec, temp_store};

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    const SHOP: &str = "shop.example.com";

    fn visitor() -> IpAddr {
        "198.51.100.7".parse().unwrap()
    }

    fn chrome_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::USER_AGENT, HeaderValue::from_static(CHROME));
        h.insert("sec-ch-ua", HeaderValue::from_static("\"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\""));
        h.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h
    }

    /// What a desktop Chrome that a person uses reports (the zone challenge's fixture).
    fn person(sealed: &str, n: u64, mode: &str) -> Value {
        json!({
            "t": sealed, "n": n, "m": mode, "ms": 900,
            "s": {
                "wd": false, "auto": [], "ua": CHROME, "uad": { "m": false, "p": "Windows", "b": ["Chromium", "Google Chrome"] },
                "langs": 3, "plug": 5, "hc": 8, "scr": [1920, 1080, 1920, 1040, 24], "win": [1536, 760, 1550, 870],
                "tz": "Europe/Berlin", "touch": 0, "chrome": true, "own": 0, "wdp": true, "nat": 0,
                "gl": "Google Inc. (NVIDIA) / ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "cdp": false, "notif": "default", "perm": "prompt"
            },
            "c": if mode == "click" { json!({ "trusted": true, "dt": 900, "detail": 1, "pt": "mouse" }) } else { Value::Null },
            "ev": { "moves": 23, "dist": 640, "first": 300, "keys": 0, "touch": 0, "scroll": 0, "age": 900 }
        })
    }

    fn solve(sealed: &str, bits: u8) -> u64 {
        (0u64..).find(|n| challenge::work_done(sealed, *n, bits)).unwrap()
    }

    /// A store with a zone whose `shop` and `www` are proxied (`direct` is not), and a widget for `shop`.
    async fn site() -> (Store, ChallengeWidget, String) {
        let store = temp_store();
        let zone = store.create_zone("example.com").unwrap().id;
        for (name, proxied) in [("shop", true), ("www", true), ("direct", false)] {
            let mut r = rec(name, "A", "192.0.2.10");
            r.proxied = proxied;
            store.create_record(&zone, r).unwrap();
        }
        let (secret, kept) = new_secret().unwrap();
        let w = store.save_challenge_widget_async(None, json!({ "name": "signup", "domains": [SHOP, "direct.example.com"] }), Some(kept)).await.unwrap();
        (store, w, secret)
    }

    async fn body_json(resp: Response<Body>) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// The test visitor, over HTTPS, at `host`.
    fn at<'a>(host: &'a str, headers: &'a HeaderMap, threat: i64) -> Visitor<'a> {
        Visitor { ip: visitor(), ssl: true, host, headers, threat }
    }

    fn token(waf: &Waf, sitekey: &str, host: &str, issued: u64) -> String {
        Token { sitekey: sitekey.into(), host: host.into(), ip: visitor(), issued, nonce: nonce() }.seal(waf)
    }

    fn input(secret: &str, response: &str) -> VerifyInput {
        VerifyInput { secret: Some(secret.into()), response: Some(response.into()), remoteip: None }
    }

    #[test]
    fn host_names_are_exact_lowercase_dns_names() {
        for good in ["example.com", "shop.example.com", "a-b.example.test", "xn--bcher-kva.example", "1.example.com"] {
            assert_eq!(check_host(good), Ok(()), "{good}");
        }
        for bad in [
            "", "com", "*.example.com", "shop.*.example.com", "https://example.com", "example.com:443", "example.com/path", "example.com.",
            ".example.com", "-a.example.com", "a-.example.com", "a..example.com", "exa_mple.com", "Example.com", "192.0.2.1", "2001:db8::1",
            "example.123", "shop example.com",
        ] {
            assert!(check_host(bad).is_err(), "{bad}");
        }
        assert!(check_host(&format!("{}.example.com", "a".repeat(64))).is_err());
        assert!(check_host(&format!("{}example.com", "a.".repeat(125))).is_err(), "longer than 253");
        // what a request gives is tidied first: case and surrounding spaces
        assert_eq!(domains(&json!([" Shop.Example.COM "])).unwrap(), vec![SHOP]);
        assert!(domains(&json!([])).is_err());
        assert!(domains(&json!([SHOP, "SHOP.example.com"])).is_err(), "twice");
        assert!(domains(&json!((0..=MAX_DOMAINS).map(|i| format!("h{i}.example.com")).collect::<Vec<_>>())).is_err());
        assert!(domains(&json!((0..MAX_DOMAINS).map(|i| format!("h{i}.example.com")).collect::<Vec<_>>())).is_ok());
        assert!(domains(&json!("example.com")).is_err());
        assert!(domains(&json!([42])).is_err());
    }

    #[test]
    fn a_widget_is_checked_and_its_secret_cannot_be_set_from_outside() {
        let kept = digest("test-secret");
        let new = |body: Value| ChallengeWidget::build(None, body, Some(kept.clone()), 0);
        let w = new(json!({ "name": " signup ", "domains": [SHOP] })).unwrap();
        assert_eq!((w.name.as_str(), w.mode.as_str(), w.secret_sha256.as_str()), ("signup", "managed", kept.as_str()));
        // Cloudflare's defaults are fine, anything else is refused, never left out
        assert!(new(json!({ "name": "x", "domains": [SHOP], "mode": "managed", "region": "world", "bot_fight_mode": false, "clearance_level": "no_clearance", "offlabel": false, "ephemeral_id": false })).is_ok());
        for body in [
            json!({ "domains": [SHOP] }),
            json!({ "name": "", "domains": [SHOP] }),
            json!({ "name": "a\u{7}b", "domains": [SHOP] }),
            json!({ "name": "x".repeat(255), "domains": [SHOP] }),
            json!({ "name": "x" }),
            json!({ "name": "x", "domains": [] }),
            json!({ "name": "x", "domains": [SHOP], "mode": "invisible" }),
            json!({ "name": "x", "domains": [SHOP], "mode": "non-interactive" }),
            json!({ "name": "x", "domains": [SHOP], "region": "china" }),
            json!({ "name": "x", "domains": [SHOP], "clearance_level": "interactive" }),
            json!({ "name": "x", "domains": [SHOP], "bot_fight_mode": true }),
            json!({ "name": "x", "domains": [SHOP], "secret": "test-secret" }),
            json!({ "name": "x", "domains": [SHOP], "secret_sha256": kept }),
            json!({ "name": "x", "domains": [SHOP], "id": "0".repeat(32) }),
            json!({ "name": "x", "domains": [SHOP], "sitekey": "0".repeat(32) }),
            json!({ "name": "x", "domains": [SHOP], "unknown": 1 }),
            json!({ "name": 7, "domains": [SHOP] }),
            json!(["not", "an", "object"]),
        ] {
            assert!(new(body.clone()).is_err(), "{body}");
        }
        assert!(ChallengeWidget::build(None, json!({ "name": "x", "domains": [SHOP] }), None, 0).is_err(), "a new widget has a secret");
        assert!(ChallengeWidget::build(None, json!({ "name": "x", "domains": [SHOP] }), Some("short".into()), 0).is_err());
        assert!(ChallengeWidget::build(None, json!({ "name": "x", "domains": [SHOP] }), Some(kept.clone()), MAX_WIDGETS).is_err());

        // a change keeps the secret unless it is rotated; what was shown, sent back, is fine
        let mut w = w;
        w.id = "a".repeat(32);
        let shown = w.public();
        let changed = ChallengeWidget::build(Some(&w), json!({ "name": "renamed", "id": shown["id"], "sitekey": shown["sitekey"], "created_on": "x", "modified_on": "y" }), None, MAX_WIDGETS).unwrap();
        assert_eq!((changed.name.as_str(), changed.secret_sha256.as_str(), changed.domains.clone()), ("renamed", kept.as_str(), vec![SHOP.to_string()]));
        assert!(ChallengeWidget::build(Some(&w), json!({ "id": "b".repeat(32) }), None, 1).is_err());
        let rotated = ChallengeWidget::build(Some(&w), json!({}), Some(digest("test-secret-2")), 1).unwrap();
        assert_eq!(rotated.secret_sha256, digest("test-secret-2"));
    }

    #[test]
    fn the_secret_shows_once_and_never_in_what_is_listed_or_read() {
        let (secret, kept) = new_secret().unwrap();
        assert!(secret.starts_with(SECRET_PREFIX) && secret.len() == SECRET_PREFIX.len() + 64);
        assert_eq!(kept, digest(&secret));
        assert_ne!(new_secret().unwrap().0, secret, "random each time");
        let mut w = ChallengeWidget::build(None, json!({ "name": "x", "domains": [SHOP] }), Some(kept.clone()), 0).unwrap();
        w.id = "a".repeat(32);
        let public = w.public().to_string();
        assert!(!public.contains(&secret) && !public.contains(&kept) && !public.contains("secret"), "{public}");
        let once = w.with_secret(&secret);
        assert_eq!(once["secret"], json!(secret));
        assert!(!once.to_string().contains(&kept));
        // the stored form has the digest only
        let stored = serde_json::to_string(&w).unwrap();
        assert!(stored.contains(&kept) && !stored.contains(&secret));
    }

    #[test]
    fn tokens_are_sealed_and_cannot_be_changed_or_made_elsewhere() {
        let waf = Waf::new();
        let t = Token { sitekey: "a".repeat(32), host: SHOP.into(), ip: visitor(), issued: 1_700_000_000, nonce: nonce() };
        let sealed = t.seal(&waf);
        assert!(sealed.starts_with("fcfw1."));
        assert_eq!(Token::open(&waf, &sealed), Some(t.clone()));
        assert_eq!(Token::open(&Waf::new(), &sealed), None, "another fleet's key");
        let (_, rest) = sealed.split_once('.').unwrap();
        let (_, mac) = rest.split_once('.').unwrap();
        for forged in [
            format!("fcfw1.{}.{mac}", b64(&t.payload().replace(SHOP, "evil.example.net"))),
            format!("fcfw1.{}.{mac}", b64(&t.payload().replace("198.51.100.7", "203.0.113.9"))),
            format!("fcfw1.{}.{mac}", b64(&t.payload().replace("1700000000", "1900000000"))),
            format!("fcfw2.{rest}"),
            rest.to_string(),
            format!("fcfw1.{rest}.x"),
            format!("fcfw1.{rest}").replace(mac, &"0".repeat(64)),
            format!("fcfw1.{}", &rest[..rest.len() - 2]),
            "fcfw1".to_string(),
            "fcfw1..".to_string(),
            String::new(),
            "fcfw1.!!!.zz".to_string(),
            format!("fcfw1.{}.{}", b64("1|a|b"), waf.mac(&format!("{TOKEN_MAC}1|a|b"))),
            format!("fcfw1.{}.{}", b64("1|s|h|not-an-ip|1|n"), waf.mac(&format!("{TOKEN_MAC}1|s|h|not-an-ip|1|n"))),
            format!("fcfw1.{}.{}", b64("2|s|h|192.0.2.1|1|n"), waf.mac(&format!("{TOKEN_MAC}2|s|h|192.0.2.1|1|n"))),
            format!("fcfw1.{}.{}", b64("1|s|h|192.0.2.1|1|n|extra"), waf.mac(&format!("{TOKEN_MAC}1|s|h|192.0.2.1|1|n|extra"))),
            format!("{sealed}{}", "A".repeat(MAX_RESPONSE)),
        ] {
            assert_eq!(Token::open(&waf, &forged), None, "{forged}");
        }
    }

    #[test]
    fn nothing_else_signed_with_the_fleet_key_passes_for_a_token_and_back() {
        let waf = Waf::new();
        let ip = visitor();
        let zone_ticket = challenge::Ticket::at("zone1", ip, CHROME, false, Level::Medium).seal(&waf);
        let widget_ticket = WidgetTicket::at(&"a".repeat(32), SHOP, ip, CHROME, false, Level::Medium, 1_700_000_000).seal(&waf);
        let clearance = waf.clearance_token("zone1", ip);
        let tok = token(&waf, &"a".repeat(32), SHOP, 1_700_000_000);
        // as a widget token: the zone's puzzle, the widget's puzzle, a clearance cookie, and the same MACs rewrapped
        for other in [zone_ticket.clone(), widget_ticket.clone(), clearance.clone(), format!("fcfw1.{zone_ticket}"), format!("fcfw1.{}", widget_ticket.trim_start_matches("fcfwt1."))] {
            assert_eq!(Token::open(&waf, &other), None, "{other}");
        }
        let (_, clear_mac) = clearance.split_once('.').unwrap();
        let clearance_payload = format!("zone1|{ip}|{}", clearance.split_once('.').unwrap().0);
        assert_eq!(Token::open(&waf, &format!("fcfw1.{}.{clear_mac}", b64(&clearance_payload))), None);
        // and the other way: a token is neither puzzle, nor a clearance (whose MAC covers zone|ip|expiry)
        assert_eq!(challenge::Ticket::open(&waf, &tok), None);
        assert_eq!(challenge::Ticket::open(&waf, tok.trim_start_matches("fcfw1.")), None);
        assert_eq!(WidgetTicket::open(&waf, &tok), None);
        assert_eq!(WidgetTicket::open(&waf, &format!("fcfwt1.{}", tok.trim_start_matches("fcfw1."))), None);
        assert_eq!(Token::open(&waf, &format!("fcfw1.{}", tok.trim_start_matches("fcfw1."))).is_some(), true);
        let tok_mac = tok.rsplit_once('.').unwrap().1;
        let expiry = unix_now() + 600;
        assert!(!waf.mac_ok(&format!("zone1|{ip}|{expiry}"), tok_mac));
        // the widget's puzzle is no zone puzzle either (it would earn a clearance cookie at the zone's verify)
        assert_eq!(challenge::Ticket::open(&waf, &widget_ticket), None);
        assert_eq!(challenge::Ticket::open(&waf, widget_ticket.trim_start_matches("fcfwt1.")), None);
        assert_eq!(WidgetTicket::open(&waf, &format!("fcfwt1.{zone_ticket}")), None);
    }

    #[tokio::test]
    async fn a_token_as_a_clearance_cookie_does_not_pass_the_zones_challenge() {
        let store = temp_store();
        let zone = store.create_zone("example.com").unwrap().id;
        store.update_setting(&zone, "security_level", json!("under_attack")).unwrap();
        let waf = Waf::new();
        let ip = visitor();
        let snap = store.snapshot();
        let zs = snap.find_zone("example.com").unwrap();
        let tok = token(&waf, &"a".repeat(32), "example.com", unix_now());
        let tok_mac = tok.rsplit_once('.').unwrap().1.to_string();
        let with_cookie = |value: &str| crate::expr::ReqInfo {
            ip: Some(ip),
            host: "example.com".into(),
            path: "/".into(),
            method: "GET".into(),
            headers: vec![("cookie".into(), format!("{}={value}", super::super::waf::CLEARANCE_COOKIE))],
            ..Default::default()
        };
        let challenged = |value: &str| matches!(waf.check(zs, &with_cookie(value), None, "ray"), super::super::waf::Verdict::Challenge { .. });
        assert!(!challenged(&waf.clearance_token(&zone, ip)), "a real clearance passes");
        assert!(challenged(&tok));
        assert!(challenged(&format!("{}.{tok_mac}", unix_now() + 600)));
        assert!(challenged(tok.trim_start_matches("fcfw1.")));
    }

    #[tokio::test]
    async fn a_token_is_checked_once_for_its_widget_its_host_and_its_time() {
        let (store, w, secret) = site().await;
        let waf = Waf::new();
        let tokens = Replay::new(100);
        let now = 1_700_000_000;
        let tok = token(&waf, &w.id, SHOP, now);
        let v = check(&store, &waf, &tokens, &input(&secret, &tok), now + 10);
        assert!(v.success, "{v:?}");
        assert_eq!(v.json(), json!({ "success": true, "error-codes": [], "challenge_ts": "2023-11-14T22:13:20.000Z", "hostname": SHOP }));
        // the same token again: refused, as a duplicate
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &tok), now + 11).errors, vec!["timeout-or-duplicate"]);
        // the same payload written another way (the MAC in upper case) is the same token
        let (head, mac) = tok.rsplit_once('.').unwrap();
        let upper = format!("{head}.{}", mac.to_ascii_uppercase());
        assert!(Token::open(&waf, &upper).is_some());
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &upper), now + 12).errors, vec!["timeout-or-duplicate"]);

        // five minutes, no more; and not from the future
        let old = token(&waf, &w.id, SHOP, now);
        assert!(check(&store, &waf, &tokens, &input(&secret, &old), now + TOKEN_SECS).success);
        let older = token(&waf, &w.id, SHOP, now);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &older), now + TOKEN_SECS + 1).errors, vec!["timeout-or-duplicate"]);
        let ahead = token(&waf, &w.id, SHOP, now + 60);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &ahead), now).errors, vec!["timeout-or-duplicate"]);

        // a host the widget does not list (or no longer lists)
        let elsewhere = token(&waf, &w.id, "www.example.com", now);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &elsewhere), now).errors, vec!["invalid-input-response"]);
        let fresh = token(&waf, &w.id, SHOP, now);
        store.save_challenge_widget_async(Some(&w.id), json!({ "domains": ["www.example.com"] }), None).await.unwrap();
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &fresh), now).errors, vec!["invalid-input-response"]);
        let www = token(&waf, &w.id, "www.example.com", now);
        assert!(check(&store, &waf, &tokens, &input(&secret, &www), now).success, "the stored secret still works after the change");

        // a token of another widget, checked with this widget's secret, and the other way
        let (other_secret, other_kept) = new_secret().unwrap();
        let other = store.save_challenge_widget_async(None, json!({ "name": "other", "domains": ["www.example.com"] }), Some(other_kept)).await.unwrap();
        let theirs = token(&waf, &other.id, "www.example.com", now);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &theirs), now).errors, vec!["invalid-input-response"]);
        assert!(check(&store, &waf, &tokens, &input(&other_secret, &theirs), now).success, "not spent by the wrong secret");
        let ours = token(&waf, &w.id, "www.example.com", now);
        assert_eq!(check(&store, &waf, &tokens, &input(&other_secret, &ours), now).errors, vec!["invalid-input-response"]);
        assert!(check(&store, &waf, &tokens, &input(&secret, &ours), now).success);

        // signed by another fleet
        let foreign = token(&Waf::new(), &w.id, "www.example.com", now);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &foreign), now).errors, vec!["invalid-input-response"]);

        // a deleted widget's secret names nothing
        store.delete_challenge_widget_async(&w.id).await.unwrap();
        let after = token(&waf, &w.id, "www.example.com", now);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &after), now).errors, vec!["invalid-input-secret"]);
    }

    #[tokio::test]
    async fn without_the_secret_nothing_about_a_token_or_a_sitekey_is_told() {
        let (store, w, secret) = site().await;
        let waf = Waf::new();
        let tokens = Replay::new(100);
        let now = 1_700_000_000;
        let tok = token(&waf, &w.id, SHOP, now);
        for wrong in ["test-secret", "", &secret[..secret.len() - 1], &format!("{secret}0"), &secret.to_ascii_uppercase(), &format!(" {secret}"), &"x".repeat(MAX_SECRET + 1)] {
            for response in [tok.as_str(), "garbage", "fcfw1.x.y"] {
                let v = check(&store, &waf, &tokens, &VerifyInput { secret: Some(wrong.to_string()).filter(|s| !s.is_empty()), response: Some(response.into()), remoteip: None }, now);
                let expected = if wrong.is_empty() { vec!["missing-input-secret"] } else { vec!["invalid-input-secret"] };
                assert_eq!((v.success, v.errors.clone(), v.sitekey.clone()), (false, expected, None), "{wrong} {response}");
                assert_eq!(v.json().as_object().unwrap().len(), 2, "no time or host name on a failure");
            }
        }
        // the token was not spent by any of that
        assert!(check(&store, &waf, &tokens, &input(&secret, &tok), now).success);
        // what is missing
        let none = VerifyInput::default();
        assert_eq!(check(&store, &waf, &tokens, &none, now).errors, vec!["missing-input-secret", "missing-input-response"]);
        let no_response = VerifyInput { secret: Some(secret.clone()), ..Default::default() };
        assert_eq!(check(&store, &waf, &tokens, &no_response, now).errors, vec!["missing-input-response"]);
    }

    #[tokio::test]
    async fn malformed_tokens_of_every_sort_are_refused() {
        let (store, w, secret) = site().await;
        let waf = Waf::new();
        let tokens = Replay::new(100);
        let now = 1_700_000_000;
        let good = token(&waf, &w.id, SHOP, now);
        let zone_ticket = challenge::Ticket::at("zone1", visitor(), CHROME, false, Level::Medium).seal(&waf);
        let widget_ticket = WidgetTicket::at(&w.id, SHOP, visitor(), CHROME, false, Level::Medium, now).seal(&waf);
        for bad in [
            "x".to_string(),
            "fcfw1".to_string(),
            "fcfw1.".to_string(),
            "fcfw1..".to_string(),
            good.replace("fcfw1.", "fcfw1.A"),
            good[..good.len() - 1].to_string(),
            format!("{good}0"),
            format!("{good}.0"),
            good.replace('.', "_"),
            format!(" {good}"),
            "\u{0}".repeat(64),
            "é".repeat(500),
            "A".repeat(MAX_RESPONSE + 1),
            zone_ticket,
            widget_ticket,
            waf.clearance_token("zone1", visitor()),
        ] {
            assert_eq!(check(&store, &waf, &tokens, &input(&secret, &bad), now).errors, vec!["invalid-input-response"], "{bad}");
        }
        assert!(check(&store, &waf, &tokens, &input(&secret, &good), now).success);
    }

    #[tokio::test]
    async fn the_address_is_checked_when_the_backend_gives_one() {
        let (store, w, secret) = site().await;
        let waf = Waf::new();
        let tokens = Replay::new(100);
        let now = 1_700_000_000;
        let with_ip = |tok: &str, ip: &str| VerifyInput { remoteip: Some(ip.into()), ..input(&secret, tok) };
        let a = token(&waf, &w.id, SHOP, now);
        assert_eq!(check(&store, &waf, &tokens, &with_ip(&a, "203.0.113.9"), now).errors, vec!["invalid-input-response"]);
        assert!(check(&store, &waf, &tokens, &with_ip(&a, "198.51.100.7"), now).success, "not spent by the mismatch");
        let b = token(&waf, &w.id, SHOP, now);
        assert!(check(&store, &waf, &tokens, &with_ip(&b, "::ffff:198.51.100.7"), now).success, "the same address in IPv6 form");
        let c = token(&waf, &w.id, SHOP, now);
        assert_eq!(check(&store, &waf, &tokens, &with_ip(&c, "not-an-address"), now).errors, vec!["bad-request"]);
        assert!(check(&store, &waf, &tokens, &input(&secret, &c), now).success, "without remoteip the address is not asked about");
    }

    #[test]
    fn the_replay_memory_is_bounded_and_refuses_rather_than_forgets() {
        let r = Replay::new(3);
        assert_eq!(r.first_use("a", 100, 0), Use::First);
        assert_eq!(r.first_use("a", 100, 0), Use::Again);
        assert_eq!(r.first_use("b", 10, 0), Use::First);
        assert_eq!(r.first_use("c", 100, 0), Use::First);
        // full of unexpired entries: nothing is forgotten to make room
        assert_eq!(r.first_use("d", 100, 5), Use::Full);
        assert_eq!(r.len(), 3);
        assert_eq!(r.first_use("a", 100, 5), Use::Again);
        // once one has expired, it makes room
        assert_eq!(r.first_use("d", 100, 11), Use::First);
        assert_eq!(r.len(), 3);
        assert!(!r.contains("b") && r.contains("d") && r.contains("a"));
        for i in 0..1000 {
            let _ = r.first_use(&format!("k{i}"), 50, 200);
        }
        assert!(r.len() <= 3);
    }

    #[tokio::test]
    async fn a_full_replay_memory_fails_closed() {
        let (store, w, secret) = site().await;
        let waf = Waf::new();
        let tokens = Replay::new(1);
        let now = 1_700_000_000;
        assert!(check(&store, &waf, &tokens, &input(&secret, &token(&waf, &w.id, SHOP, now)), now).success);
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &token(&waf, &w.id, SHOP, now)), now).errors, vec!["internal-error"]);
        // after the first one's time, there is room again
        assert!(check(&store, &waf, &tokens, &input(&secret, &token(&waf, &w.id, SHOP, now + 400)), now + 400).success);
    }

    #[test]
    fn siteverify_takes_json_or_a_form_and_nothing_ambiguous() {
        let want = VerifyInput { secret: Some("test-secret".into()), response: Some("fcfw1.a.b".into()), remoteip: Some("192.0.2.1".into()) };
        let json_body = br#"{"secret":"test-secret","response":"fcfw1.a.b","remoteip":"192.0.2.1","idempotency_key":"x"}"#;
        assert_eq!(parse_verify("application/json", json_body), Some(want.clone()));
        assert_eq!(parse_verify("application/x-www-form-urlencoded", b"secret=test-secret&response=fcfw1.a.b&remoteip=192.0.2.1"), Some(want.clone()));
        assert_eq!(parse_verify("application/x-www-form-urlencoded", b"secret=test%2Dsecret&response=fcfw1.a.b&remoteip=192.0.2.1&"), Some(want));
        assert_eq!(parse_verify("application/x-www-form-urlencoded", b"secret=&response="), Some(VerifyInput::default()), "empty is missing");
        assert_eq!(parse_verify("application/json", br#"{"secret":null}"#), Some(VerifyInput::default()));
        for (media, body) in [
            ("application/x-www-form-urlencoded", &b"secret=a&secret=b"[..]),
            ("application/x-www-form-urlencoded", &b"secret=%ff"[..]),
            ("application/x-www-form-urlencoded", &b"\xff"[..]),
            ("application/json", &br#"{"secret":1}"#[..]),
            ("application/json", &br#"{"response":["x"]}"#[..]),
            ("application/json", &br#"["x"]"#[..]),
            ("application/json", &b"not json"[..]),
            ("multipart/form-data", &b"--x"[..]),
            ("text/plain", &b"secret=a"[..]),
            ("", &b"secret=a"[..]),
        ] {
            assert_eq!(parse_verify(media, body), None, "{media} {}", String::from_utf8_lossy(body));
        }
    }

    #[tokio::test]
    async fn the_puzzle_is_for_a_proxied_host_of_the_widget_only() {
        let (store, w, _) = site().await;
        let waf = Waf::new();
        let now = 1_700_000_000;
        let h = chrome_headers();
        let cfg = ticket_config(&store, &waf, &w.id, &at(SHOP, &h, 0), now).unwrap();
        let t = WidgetTicket::open(&waf, cfg["t"].as_str().unwrap()).unwrap();
        assert_eq!((t.sitekey.as_str(), t.host.as_str(), t.ip, t.bits, t.click, t.level), (w.id.as_str(), SHOP, visitor(), 17, false, Level::Medium));
        assert_eq!(t.ua, challenge::ua_digest(CHROME));
        assert_eq!(cfg["v"], ANSWER_PATH);
        // an unknown sitekey, a host the widget does not list, a host that is not proxied, a name of no zone: all alike
        for (key, host) in [("b".repeat(32), SHOP), (w.id.clone(), "www.example.com"), (w.id.clone(), "direct.example.com"), (w.id.clone(), "shop.example.net"), ("short".into(), SHOP), (w.id.to_ascii_uppercase(), SHOP)] {
            assert_eq!(ticket_config(&store, &waf, &key, &at(host, &h, 0), now), Err("not_allowed"), "{key} {host}");
        }
        // a doubtful address clicks; the zone's level counts, but never below medium
        assert_eq!(ticket_config(&store, &waf, &w.id, &at(SHOP, &h, 90), now).unwrap()["c"], json!(true));
        let zone = store.snapshot().find_zone(SHOP).unwrap().zone.id.clone();
        store.update_setting(&zone, "security_level", json!("off")).unwrap();
        let off = ticket_config(&store, &waf, &w.id, &at(SHOP, &h, 90), now).unwrap();
        assert_eq!((off["b"].clone(), off["c"].clone()), (json!(17), json!(true)));
        store.update_setting(&zone, "security_level", json!("under_attack")).unwrap();
        let hard = ticket_config(&store, &waf, &w.id, &at(SHOP, &h, 0), now).unwrap();
        assert_eq!(WidgetTicket::open(&waf, hard["t"].as_str().unwrap()).unwrap().level, Level::UnderAttack);
        assert_eq!(widget_level(Level::Off), Level::Medium);
        assert_eq!(widget_level(Level::Low), Level::Medium);
        assert_eq!(widget_level(Level::High), Level::High);
    }

    #[tokio::test]
    async fn a_browser_that_passes_gets_a_token_its_backend_accepts_once() {
        let (store, w, secret) = site().await;
        let waf = Waf::new();
        let (tickets, tokens) = (Replay::new(100), Replay::new(100));
        let now = unix_now();
        let h = chrome_headers();
        let cfg = ticket_config(&store, &waf, &w.id, &at(SHOP, &h, 0), now).unwrap();
        let sealed = cfg["t"].as_str().unwrap().to_string();
        let n = solve(&sealed, 17);
        let (status, r) = body_json(judge(&waf, &store, &tickets, &at(SHOP, &h, 0), &person(&sealed, n, "auto"), "ray", now + 1)).await;
        assert_eq!((status, r["ok"].clone()), (StatusCode::OK, json!(true)), "{r}");
        let tok = r["token"].as_str().unwrap().to_string();
        let v = check(&store, &waf, &tokens, &VerifyInput { remoteip: Some("198.51.100.7".into()), ..input(&secret, &tok) }, now + 2);
        assert_eq!((v.success, v.hostname.as_deref()), (true, Some(SHOP)), "{v:?}");
        assert_eq!(check(&store, &waf, &tokens, &input(&secret, &tok), now + 3).errors, vec!["timeout-or-duplicate"]);
        // the puzzle is spent: answering it again gets no second token
        let (status, r) = body_json(judge(&waf, &store, &tickets, &at(SHOP, &h, 0), &person(&sealed, n, "auto"), "ray", now + 4)).await;
        assert_eq!((status, r["code"].clone()), (StatusCode::FORBIDDEN, json!("used")));
    }

    #[tokio::test]
    async fn a_puzzle_answered_wrongly_or_elsewhere_gets_no_token() {
        let (store, w, _) = site().await;
        let waf = Waf::new();
        let tickets = Replay::new(100);
        let now = unix_now();
        let h = chrome_headers();
        let fresh = |threat: i64| {
            let cfg = ticket_config(&store, &waf, &w.id, &at(SHOP, &h, threat), now).unwrap();
            let sealed = cfg["t"].as_str().unwrap().to_string();
            let n = solve(&sealed, 17);
            (sealed, n)
        };
        let judge_at = |headers: &HeaderMap, ip: IpAddr, host: &str, report: &Value, when: u64| {
            judge(&waf, &store, &tickets, &Visitor { ip, ssl: true, host, headers, threat: 0 }, report, "ray", when)
        };
        let code = |r: (StatusCode, Value)| r.1["code"].as_str().unwrap_or_default().to_string();

        let (sealed, n) = fresh(0);
        let wrong = (0u64..).find(|m| !challenge::work_done(&sealed, *m, 17)).unwrap();
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, wrong, "auto"), now)).await), "bad_work");
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "auto"), now + TICKET_SECS + 1)).await), "expired");
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "auto"), now - 60)).await), "expired", "from the future");
        assert_eq!(code(body_json(judge_at(&h, "203.0.113.9".parse().unwrap(), SHOP, &person(&sealed, n, "auto"), now)).await), "other_visitor");
        let mut other_ua = h.clone();
        other_ua.insert(header::USER_AGENT, HeaderValue::from_static("curl/8"));
        assert_eq!(code(body_json(judge_at(&other_ua, visitor(), SHOP, &person(&sealed, n, "auto"), now)).await), "other_visitor");
        assert_eq!(code(body_json(judge_at(&h, visitor(), "direct.example.com", &person(&sealed, n, "auto"), now)).await), "other_host");
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person("fcfwt1.x.y", n, "auto"), now)).await), "bad_ticket");
        let zone_ticket = challenge::Ticket::at("zone1", visitor(), CHROME, false, Level::Medium).seal(&waf);
        let zone_n = solve(&zone_ticket, 17);
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&zone_ticket, zone_n, "auto"), now)).await), "bad_ticket");
        // none of that spent the puzzle; automation does
        let mut bot = person(&sealed, n, "auto");
        bot["s"]["wd"] = json!(true);
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &bot, now)).await), "webdriver");
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "auto"), now)).await), "used");

        // doubt asks for a click, which does not spend the puzzle; a real click then passes
        let (sealed, n) = fresh(0);
        let mut doubtful = person(&sealed, n, "auto");
        doubtful["s"]["cdp"] = json!(true);
        let (status, r) = body_json(judge_at(&h, visitor(), SHOP, &doubtful, now)).await;
        assert_eq!((status, r["need"].clone()), (StatusCode::OK, json!("click")));
        let mut clicked = person(&sealed, n, "click");
        clicked["s"]["cdp"] = json!(true);
        let (_, r) = body_json(judge_at(&h, visitor(), SHOP, &clicked, now)).await;
        assert_eq!(r["ok"], json!(true), "{r}");
        // an untrusted click fails, and spends the puzzle
        let (sealed, n) = fresh(0);
        let mut untrusted = person(&sealed, n, "click");
        untrusted["c"]["trusted"] = json!(false);
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &untrusted, now)).await), "untrusted_click");
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "click"), now)).await), "used");

        // a puzzle that asks for a click is not passed without one
        let (sealed, n) = fresh(90);
        assert_eq!(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "auto"), now)).await.1["need"], json!("click"));
        assert_eq!(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "click"), now)).await.1["ok"], json!(true));

        // a widget taken off the host since the puzzle was handed out
        let (sealed, n) = fresh(0);
        store.save_challenge_widget_async(Some(&w.id), json!({ "domains": ["www.example.com"] }), None).await.unwrap();
        assert_eq!(code(body_json(judge_at(&h, visitor(), SHOP, &person(&sealed, n, "auto"), now)).await), "not_allowed");
    }

    #[test]
    fn the_browser_says_when_it_comes_from_another_page() {
        let mut h = HeaderMap::new();
        assert!(!cross_site(&h, SHOP), "not a browser: judged by the challenge");
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(!cross_site(&h, SHOP));
        for site in ["cross-site", "same-site", "none"] {
            h.insert("sec-fetch-site", HeaderValue::from_static(site));
            assert!(cross_site(&h, SHOP), "{site}");
        }
        h.remove("sec-fetch-site");
        h.insert(header::ORIGIN, HeaderValue::from_static("https://shop.example.com"));
        assert!(!cross_site(&h, SHOP));
        h.insert(header::ORIGIN, HeaderValue::from_static("https://shop.example.com:8443"));
        assert!(!cross_site(&h, SHOP));
        for origin in ["https://evil.example.net", "null", "https://shop.example.com.example.net", "not an origin"] {
            h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert!(cross_site(&h, SHOP), "{origin}");
        }
    }

    #[test]
    fn the_endpoints_are_known_by_their_exact_paths() {
        for e in ["challenge-platform/widget.js", "challenge-platform/widget/ticket", "challenge-platform/widget/verify", "challenge-platform/siteverify"] {
            assert!(handles(e), "{e}");
        }
        for e in ["challenge-platform/verify", "challenge-platform/fcf.js", "challenge-platform/ticket", "challenge-platform/widget", "challenge-platform/siteverify/", "challenge-platform/widget.js.map"] {
            assert!(!handles(e), "{e}");
        }
        assert_eq!(query_param(Some("a=1&sitekey=abc"), "sitekey"), Some("abc"));
        assert_eq!(query_param(Some("xsitekey=abc"), "sitekey"), None);
        assert_eq!(query_param(None, "sitekey"), None);
        assert!(SCRIPT.contains("fcf-challenge-response") && SCRIPT.contains("data-sitekey") && SCRIPT.contains(TICKET_PATH) && SCRIPT.contains(ANSWER_PATH));
    }

    /// The whole way, through the edge's `/cdn-cgi/` dispatch.
    #[tokio::test]
    async fn the_edge_serves_the_script_the_puzzle_and_siteverify() {
        let (store, w, secret) = site().await;
        let store = Arc::new(store);
        let cache = Arc::new(crate::edge::cache::Cache::new(1 << 20));
        let edge = Arc::new(Edge::new(store.clone(), cache, Arc::new(Waf::new()), vec![]).unwrap());
        let req = |method: &str, uri: &str, headers: &[(&str, &str)], body: &str| {
            let mut b = Request::builder().method(method).uri(uri);
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            b.body(full(body.to_string())).unwrap()
        };
        let call = |endpoint: &str, ssl: bool, ip: IpAddr, r: Request<Body>, host: &str| {
            let edge = edge.clone();
            let (endpoint, host) = (endpoint.to_string(), host.to_string());
            async move {
                let resp = edge.cdn_cgi(&endpoint, ip, ssl, r, &host, "ray").await.unwrap_or_else(|e| {
                    let mut resp = Response::new(full(String::new()));
                    *resp.status_mut() = StatusCode::from_u16(e.status).unwrap();
                    resp
                });
                let status = resp.status();
                let ct = resp.headers().get(header::CONTENT_TYPE).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                (status, ct, String::from_utf8_lossy(&bytes).to_string())
            }
        };
        let (status, ct, js) = call("challenge-platform/widget.js", true, visitor(), req("GET", "/cdn-cgi/challenge-platform/widget.js", &[], ""), SHOP).await;
        assert_eq!((status, ct.as_str()), (StatusCode::OK, "text/javascript; charset=utf-8"));
        assert!(js.contains("\"fcf-challenge-response\""));

        let ticket_uri = format!("{TICKET_PATH}?sitekey={}", w.id);
        let (status, _, body) = call("challenge-platform/widget/ticket", true, visitor(), req("GET", &ticket_uri, &[("user-agent", CHROME), ("sec-fetch-site", "same-origin")], ""), SHOP).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let cfg: Value = serde_json::from_str(&body).unwrap();
        assert!(cfg["t"].as_str().unwrap().starts_with("fcfwt1."));
        let (status, _, body) = call("challenge-platform/widget/ticket", true, visitor(), req("GET", &ticket_uri, &[("user-agent", CHROME), ("sec-fetch-site", "cross-site")], ""), SHOP).await;
        assert!(status == StatusCode::FORBIDDEN && body.contains("cross_origin"), "{body}");
        let (status, _, _) = call("challenge-platform/widget/ticket", true, visitor(), req("GET", &ticket_uri, &[], ""), "www.example.com").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call("challenge-platform/widget/ticket", true, visitor(), req("POST", &ticket_uri, &[], ""), SHOP).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

        // the answer: JSON only, same origin only, bounded
        let sealed = cfg["t"].as_str().unwrap().to_string();
        let n = solve(&sealed, 17);
        let report = person(&sealed, n, "auto").to_string();
        let browser = [("user-agent", CHROME), ("content-type", "application/json"), ("accept-language", "en-US,en;q=0.9"), ("sec-ch-ua", "\"Chromium\";v=\"131\""), ("sec-fetch-site", "same-origin"), ("sec-fetch-mode", "cors"), ("origin", "https://shop.example.com")];
        let as_text: Vec<(&str, &str)> = browser.iter().map(|(k, v)| if *k == "content-type" { (*k, "text/plain") } else { (*k, *v) }).collect();
        let (status, _, _) = call("challenge-platform/widget/verify", true, visitor(), req("POST", ANSWER_PATH, &as_text, &report), SHOP).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let foreign: Vec<(&str, &str)> = browser.iter().map(|(k, v)| if *k == "origin" { (*k, "https://evil.example.net") } else { (*k, *v) }).collect();
        let (status, _, _) = call("challenge-platform/widget/verify", true, visitor(), req("POST", ANSWER_PATH, &foreign, &report), SHOP).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = call("challenge-platform/widget/verify", true, visitor(), req("POST", ANSWER_PATH, &browser, &"x".repeat(MAX_ANSWER + 1)), SHOP).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _, body) = call("challenge-platform/widget/verify", true, visitor(), req("POST", ANSWER_PATH, &browser, &report), SHOP).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let tok = serde_json::from_str::<Value>(&body).unwrap()["token"].as_str().unwrap().to_string();

        // siteverify: over HTTPS (or from the node itself), on a proxied host or the panel's, POST, bounded
        let form = format!("secret={secret}&response={tok}&remoteip=198.51.100.7");
        let backend: IpAddr = "203.0.113.20".parse().unwrap();
        let form_ct = [("content-type", "application/x-www-form-urlencoded")];
        let sv = "challenge-platform/siteverify";
        let (status, _, body) = call(sv, false, backend, req("POST", SITEVERIFY_PATH, &form_ct, &form), SHOP).await;
        assert!(status == StatusCode::FORBIDDEN && body.contains("bad-request"), "{body}");
        let (status, _, _) = call(sv, true, backend, req("POST", SITEVERIFY_PATH, &form_ct, &form), "unknown.example.net").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = call(sv, true, backend, req("GET", SITEVERIFY_PATH, &form_ct, ""), SHOP).await;
        assert!(status == StatusCode::METHOD_NOT_ALLOWED && body.contains("bad-request"), "{body}");
        let (status, _, _) = call(sv, true, backend, req("POST", SITEVERIFY_PATH, &form_ct, &"a".repeat(MAX_SITEVERIFY + 1)), SHOP).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, _, body) = call(sv, true, backend, req("POST", SITEVERIFY_PATH, &[("content-type", "text/plain")], &form), SHOP).await;
        assert!(status == StatusCode::BAD_REQUEST && body.contains("bad-request"), "{body}");
        let (status, ct, body) = call(sv, true, backend, req("POST", SITEVERIFY_PATH, &form_ct, &form), SHOP).await;
        assert_eq!((status, ct.as_str()), (StatusCode::OK, "application/json"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!((v["success"].clone(), v["hostname"].clone()), (json!(true), json!(SHOP)), "{body}");
        let again = json!({ "secret": secret, "response": tok }).to_string();
        let (_, _, body) = call(sv, false, "127.0.0.1".parse().unwrap(), req("POST", SITEVERIFY_PATH, &[("content-type", "application/json")], &again), "www.example.com").await;
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), json!({ "success": false, "error-codes": ["timeout-or-duplicate"] }));
    }
}
