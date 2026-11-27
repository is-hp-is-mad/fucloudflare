//! Accounts of the management panel: users with passwords, two-step
//! verification (TOTP, with single-use backup codes), passkeys (WebAuthn),
//! sessions and an audit trail.
//!
//! All of it lives in one file in the data directory of the node that
//! serves the panel (accounts.json). It is not part of the configuration
//! and is never handed to replicas. The API token keeps working next to it:
//! it is what the fleet's tooling and the replicas use, and it has every
//! right.
//!
//! Passwords are stored as PBKDF2-HMAC-SHA256 hashes, backup codes and
//! session tokens as SHA-256 digests (both are long random strings); TOTP
//! secrets have to be kept as they are.

use crate::acme::{b64, sha256, unb64};
use crate::sync::{unix_ms, DomainDelta, HlcClock, SyncMeta, SyncProvider};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

#[cfg(not(test))]
const KDF_ROUNDS: u32 = 600_000;
#[cfg(test)]
const KDF_ROUNDS: u32 = 1_000;
const SESSION_DAYS: i64 = 30;
const SESSION_PREFIX: &str = "fucf_s_";
/// Wrong passwords in a row before an account is locked for a while.
const FREE_ATTEMPTS: u32 = 5;
const BACKUP_CODES: usize = 10;
/// How long a login waits for its second step, and a passkey ceremony for its answer.
const PENDING_SECS: i64 = 300;
const AUDIT_KEPT: usize = 300;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn random(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    ring::rand::SystemRandom::new().fill(&mut bytes).expect("the system has randomness");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Write a file holding secrets so that only its owner can read it on Unix.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    file.write_all(bytes)
}

// ------------------------------------------------------------ passwords ----

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordHash {
    salt: String,
    rounds: u32,
    hash: String,
}

impl PasswordHash {
    fn of(password: &str) -> PasswordHash {
        let salt = random(16);
        let mut out = [0u8; 32];
        let rounds = NonZeroU32::new(KDF_ROUNDS).expect("not zero");
        ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, rounds, &salt, password.as_bytes(), &mut out);
        PasswordHash { salt: b64(&salt), rounds: KDF_ROUNDS, hash: b64(&out) }
    }

    fn matches(&self, password: &str) -> bool {
        let (Some(salt), Some(hash), Some(rounds)) = (unb64(&self.salt), unb64(&self.hash), NonZeroU32::new(self.rounds)) else { return false };
        ring::pbkdf2::verify(ring::pbkdf2::PBKDF2_HMAC_SHA256, rounds, &salt, password.as_bytes(), &hash).is_ok()
    }
}

fn check_password(password: &str, email: &str) -> Result<(), AuthError> {
    if password.chars().count() < 8 {
        return Err(AuthError::weak("a password has at least 8 characters"));
    }
    if password.len() > 256 {
        return Err(AuthError::weak("a password has at most 256 bytes"));
    }
    if password.eq_ignore_ascii_case(email) {
        return Err(AuthError::weak("the password must not be the e-mail address"));
    }
    Ok(())
}

/// Characters picked evenly from an alphabet.
fn random_text(alphabet: &[u8], len: usize) -> String {
    // bytes that would favour the start of the alphabet are dropped
    let fair = 256 - 256 % alphabet.len();
    random(len * 4 + 32).into_iter().filter(|b| (*b as usize) < fair).take(len).map(|b| alphabet[b as usize % alphabet.len()] as char).collect()
}

/// A password nobody chose: 20 characters without look-alikes.
pub fn random_password() -> String {
    random_text(b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", 20)
}

fn normalize_email(email: &str) -> Result<String, AuthError> {
    let email = email.trim().to_ascii_lowercase();
    let valid = email.len() <= 254
        && !email.contains(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') && !domain.contains('@')
        });
    if valid {
        Ok(email)
    } else {
        Err(AuthError::invalid("that is not an e-mail address"))
    }
}

// ----------------------------------------------------------------- TOTP ----

const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32(bytes: &[u8]) -> String {
    let (mut out, mut acc, mut bits) = (String::new(), 0u32, 0);
    for b in bytes {
        acc = acc << 8 | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[(acc >> bits & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[(acc << (5 - bits) & 31) as usize] as char);
    }
    out
}

fn unbase32(text: &str) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.bytes().filter(|c| *c != b'=' && *c != b' ') {
        acc = acc << 5 | BASE32.iter().position(|b| *b == c.to_ascii_uppercase())? as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// The six digits of RFC 6238 (HMAC-SHA1, 30 second steps) for a step.
fn totp_code(secret: &[u8], step: u64) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = ring::hmac::sign(&key, &step.to_be_bytes());
    let mac = mac.as_ref();
    let at = (mac[mac.len() - 1] & 0x0f) as usize;
    let number = u32::from_be_bytes([mac[at] & 0x7f, mac[at + 1], mac[at + 2], mac[at + 3]]);
    format!("{:06}", number % 1_000_000)
}

/// The step a code belongs to, if it is one of now, just before or just
/// after (clocks differ a little).
fn totp_step(secret: &[u8], code: &str, at: i64) -> Option<u64> {
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    let current = (at.max(0) as u64) / 30;
    [current, current.saturating_sub(1), current + 1].into_iter().find(|step| code.len() == 6 && ct_eq(totp_code(secret, *step).as_bytes(), code.as_bytes()))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Totp {
    /// Base32, as authenticator apps take it.
    secret: String,
    /// Confirmed with a code: from then on the second step is asked for.
    enabled: bool,
    /// The last step a code was accepted for: a code works once.
    last_step: u64,
}

fn backup_code() -> String {
    let text = random_text(b"abcdefghjkmnpqrstuvwxyz23456789", 10);
    format!("{}-{}", &text[..5], &text[5..])
}

fn backup_digest(code: &str) -> String {
    let plain: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    hex(&sha256(plain.as_bytes()))
}

// ------------------------------------------------------------- passkeys ----

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Passkey {
    /// Credential id (base64url).
    id: String,
    name: String,
    /// COSE algorithm: -7 ES256, -8 EdDSA, -257 RS256.
    alg: i64,
    /// Public key as the browser hands it out (SubjectPublicKeyInfo, base64url).
    key: String,
    sign_count: u32,
    created_on: String,
    #[serde(default)]
    last_used_on: Option<String>,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    sync: SyncMeta,
}

/// What a browser returns from navigator.credentials.create().
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub id: String,
    pub public_key: String,
    pub alg: i64,
    pub client_data: String,
    pub authenticator_data: String,
    #[serde(default)]
    pub name: String,
}

/// What a browser returns from navigator.credentials.get().
#[derive(Debug, Clone, Deserialize)]
pub struct Assertion {
    pub id: String,
    pub client_data: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// The relying party of a ceremony: taken from the origin the browser
/// reports, which must be the panel's own (or localhost, for a panel
/// reached on the node itself).
fn relying_party(origin: &str, panel_host: Option<&str>) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let authority = rest.split('/').next()?;
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    let host = host.to_ascii_lowercase();
    let allowed = (host == "localhost" && (scheme == "http" || scheme == "https")) || (scheme == "https" && panel_host == Some(host.as_str()));
    allowed.then_some(host)
}

/// Check what the browser says it signed: the kind of ceremony, an origin
/// of ours. Returns the challenge it answered and the relying party.
fn client_data(raw: &[u8], kind: &str, panel_host: Option<&str>) -> Result<(String, String), AuthError> {
    let data: Value = serde_json::from_slice(raw).map_err(|_| AuthError::passkey("the client data is not JSON"))?;
    if data["type"] != kind {
        return Err(AuthError::passkey("the client data is for another kind of ceremony"));
    }
    if data.get("crossOrigin").and_then(Value::as_bool) == Some(true) {
        return Err(AuthError::passkey("passkeys cannot be used from another frame"));
    }
    let origin = data["origin"].as_str().unwrap_or_default();
    let rp = relying_party(origin, panel_host).ok_or_else(|| AuthError::passkey(format!("passkeys do not work from {origin}: open the panel under its own host name")))?;
    Ok((data["challenge"].as_str().unwrap_or_default().to_string(), rp))
}

/// Check the authenticator data: made for this relying party, with the
/// user present (and verified, where that is asked for). Returns the counter.
fn authenticator_data(raw: &[u8], rp: &str, verified: bool) -> Result<u32, AuthError> {
    if raw.len() < 37 || raw[..32] != sha256(rp.as_bytes()) {
        return Err(AuthError::passkey("the passkey answered for another site"));
    }
    if raw[32] & 0x01 == 0 {
        return Err(AuthError::passkey("the passkey did not confirm that its user is present"));
    }
    if verified && raw[32] & 0x04 == 0 {
        return Err(AuthError::passkey("the passkey did not verify its user (PIN, fingerprint, face)"));
    }
    Ok(u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]))
}

/// Verify a passkey's signature over the authenticator data and the client data.
fn verify_signature(alg: i64, spki: &[u8], authenticator_data: &[u8], client_data: &[u8], signature: &[u8]) -> Result<(), AuthError> {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256};
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&sha256(client_data));
    let tail = |n: usize| spki.len().checked_sub(n).map(|at| &spki[at..]);
    let verified = match alg {
        -7 => tail(65).filter(|point| point[0] == 4).is_some_and(|point| UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).verify(&signed, signature).is_ok()),
        -8 => tail(32).is_some_and(|key| UnparsedPublicKey::new(&ED25519, key).verify(&signed, signature).is_ok()),
        -257 => {
            // SubjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING { RSAPublicKey } }
            let key = crate::edge::tls::der(spki)
                .and_then(|(_, body, _)| crate::edge::tls::der(body))
                .and_then(|(_, _, rest)| crate::edge::tls::der(rest))
                .and_then(|(tag, bits, _)| bits.get(1..).filter(|_| tag == 3));
            key.is_some_and(|key| UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key).verify(&signed, signature).is_ok())
        }
        _ => return Err(AuthError::passkey("this kind of passkey is not supported (ES256, EdDSA and RS256 are)")),
    };
    verified.then_some(()).ok_or_else(|| AuthError::passkey("the passkey's signature does not verify"))
}

// --------------------------------------------------------------- errors ----

#[derive(Debug, Clone, PartialEq)]
pub struct AuthError {
    /// 400, 401, 403, 404, 409 or 429.
    pub status: u16,
    /// Stable across wordings; the panel has its own texts for them.
    pub code: u32,
    pub message: String,
}

impl AuthError {
    fn new(status: u16, code: u32, message: impl Into<String>) -> AuthError {
        AuthError { status, code, message: message.into() }
    }
    fn credentials() -> AuthError {
        AuthError::new(401, 2001, "wrong e-mail address or password")
    }
    fn locked(secs: i64) -> AuthError {
        AuthError::new(429, 2002, format!("too many wrong attempts: try again in {secs} s"))
    }
    fn second_step(message: &str) -> AuthError {
        AuthError::new(401, 2003, message)
    }
    fn expired() -> AuthError {
        AuthError::new(401, 2004, "that took too long: sign in again")
    }
    fn disabled() -> AuthError {
        AuthError::new(403, 2005, "this account is disabled")
    }
    pub fn passkey(message: impl Into<String>) -> AuthError {
        AuthError::new(400, 2008, message)
    }
    fn weak(message: &str) -> AuthError {
        AuthError::new(400, 2009, message)
    }
    pub fn invalid(message: impl Into<String>) -> AuthError {
        AuthError::new(400, 2011, message)
    }
    fn not_found() -> AuthError {
        AuthError::new(404, 2012, "no such user")
    }
    fn conflict(message: &str) -> AuthError {
        AuthError::new(409, 2013, message)
    }
}

// ---------------------------------------------------------------- users ----

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything, users and nodes included.
    Admin,
    /// The configuration: zones, records, rules, workers.
    Editor,
    /// Looks, and changes nothing but its own account.
    #[default]
    Viewer,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    email: String,
    role: Role,
    #[serde(default)]
    disabled: bool,
    password: PasswordHash,
    /// Set for passwords somebody else chose (or generated).
    #[serde(default)]
    must_change_password: bool,
    #[serde(default)]
    totp: Option<Totp>,
    /// Digests of the backup codes that are left.
    #[serde(default)]
    backup_codes: Vec<String>,
    #[serde(default)]
    passkeys: Vec<Passkey>,
    created_on: String,
    #[serde(default)]
    last_login_on: Option<String>,
    #[serde(default)]
    failed: u32,
    #[serde(default)]
    locked_until: i64,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    sync: SyncMeta,
}

impl User {
    fn two_factor(&self) -> bool {
        self.totp.as_ref().is_some_and(|t| t.enabled)
    }

    fn view(&self) -> Value {
        json!({
            "id": self.id, "email": self.email, "role": self.role, "disabled": self.disabled,
            "two_factor": self.two_factor(), "passkeys": self.passkeys.len(), "must_change_password": self.must_change_password,
            "created_on": self.created_on, "last_login_on": self.last_login_on, "locked": self.locked_until > now(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    /// What the session is called in lists (not the secret).
    id: String,
    /// Digest of the token.
    digest: String,
    user_id: String,
    created: i64,
    last_seen: i64,
    expires: i64,
    ip: String,
    agent: String,
    /// How it was opened: password, password+totp, password+backup_code, password+passkey, passkey.
    #[serde(default)]
    method: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    sync: SyncMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditEntry {
    #[serde(default)]
    id: String,
    at: String,
    actor: String,
    action: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    ip: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    sync: SyncMeta,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterSecret {
    pub key_b64: String,
    pub created_ms: u64,
    pub node: String,
}

impl ClusterSecret {
    /// Lowest `(created_ms, node)` wins so all peers converge deterministically
    /// onto one cluster secret.
    fn preferred_over(&self, other: &Self) -> bool {
        (self.created_ms, self.node.as_str()) < (other.created_ms, other.node.as_str())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
    pub auto_provision: bool,
    pub default_role: Role,
    pub redirect_base_url: String,
    #[serde(default, skip_serializing_if = "SyncMeta::is_unset")]
    pub sync: SyncMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OAuthStateClaims {
    state: String,
    nonce: String,
    code_verifier: String,
    exp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Data {
    users: Vec<User>,
    sessions: Vec<Session>,
    audit: Vec<AuditEntry>,
    #[serde(default)]
    oauth_config: OAuthConfig,
    #[serde(default)]
    epoch: String,
    #[serde(default)]
    local_rev: u64,
    #[serde(default)]
    gc_floor_rev: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cluster_secret: Option<ClusterSecret>,
    #[serde(default)]
    deleted_users: BTreeMap<String, SyncMeta>,
    #[serde(default)]
    deleted_passkeys: BTreeMap<String, SyncMeta>,
    #[serde(default)]
    deleted_sessions: BTreeMap<String, SyncMeta>,
    #[serde(default)]
    spent_jti: BTreeMap<String, i64>,
    #[serde(default)]
    spent_jti_rev: BTreeMap<String, u64>,
    #[serde(default)]
    ticket_wrong: BTreeMap<String, (u32, i64)>,
    #[serde(default)]
    ticket_wrong_rev: BTreeMap<String, u64>,
}

/// Who a request comes from.
#[derive(Debug, Clone)]
pub struct Principal {
    /// None for the API token.
    pub user_id: Option<String>,
    pub email: String,
    pub role: Role,
    pub session_id: Option<String>,
    pub must_change_password: bool,
}

impl Principal {
    /// The API token: the fleet's own tooling.
    pub fn system() -> Principal {
        Principal { user_id: None, email: "api-token".into(), role: Role::Admin, session_id: None, must_change_password: false }
    }
}

/// Where a request comes from, for the records.
#[derive(Debug, Clone, Default)]
pub struct Client {
    pub ip: String,
    pub agent: String,
}

#[derive(Debug)]
pub enum Login {
    /// Signed in: the session token and the user.
    Session(String, Value),
    /// The password was right; now the second step, within a few minutes.
    SecondStep { ticket: String, methods: Vec<&'static str> },
}

/// Proof for the second step.
pub enum Proof {
    Totp(String),
    BackupCode(String),
    Passkey(Assertion),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingClaims {
    jti: String,
    k: char,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uid: Option<String>,
    exp: i64,
}

const PENDING_PREFIX: &str = "fucf_p1.";
const DURABLE_TOMBSTONE_TTL_MS: u64 = 30 * 86_400_000;
const SESSION_TOMBSTONE_TTL_MS: u64 = 3_600_000;

fn pending_key(cluster_secret: &[u8]) -> ring::hmac::Key {
    let derived = sha256(&[b"fucf-pending-v1:", cluster_secret].concat());
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &derived)
}

fn seal_pending(secret: &[u8], kind: char, uid: Option<&str>, exp: i64) -> String {
    let claims = PendingClaims {
        jti: b64(&random(16)),
        k: kind,
        uid: uid.map(str::to_string),
        exp,
    };
    let payload = b64(&serde_json::to_vec(&claims).unwrap_or_default());
    let tag = ring::hmac::sign(&pending_key(secret), payload.as_bytes());
    format!("{PENDING_PREFIX}{payload}.{}", b64(tag.as_ref()))
}

fn verify_pending_token(secret: &[u8], token: &str, expected_kind: char) -> Option<PendingClaims> {
    let rest = token.strip_prefix(PENDING_PREFIX)?;
    let (payload, sig_b64) = rest.split_once('.')?;
    let sig = unb64(sig_b64)?;
    ring::hmac::verify(&pending_key(secret), payload.as_bytes(), &sig).ok()?;
    let bytes = unb64(payload)?;
    let claims: PendingClaims = serde_json::from_slice(&bytes).ok()?;
    (claims.k == expected_kind && claims.exp > now()).then_some(claims)
}

struct PersistState {
    path: Option<PathBuf>,
    data: Arc<Mutex<Data>>,
    persist_lock: Mutex<()>,
    dirty_gen: AtomicU64,
    persisted_gen: AtomicU64,
    notify: tokio::sync::Notify,
    started: AtomicBool,
}

impl PersistState {
    fn write_bytes_if_newer(&self, bytes: &[u8], target_gen: u64) {
        let Some(path) = &self.path else {
            self.persisted_gen.fetch_max(target_gen, Ordering::AcqRel);
            return;
        };
        let _guard = self.persist_lock.lock().unwrap();
        if self.persisted_gen.load(Ordering::Acquire) >= target_gen {
            return;
        }
        let tmp = path.with_extension("json.tmp");
        let written = (|| -> std::io::Result<()> {
            write_private(&tmp, bytes)?;
            std::fs::rename(&tmp, path)
        })();
        if let Err(e) = written {
            tracing::error!("cannot save {}: {e}", path.display());
        } else {
            self.persisted_gen.fetch_max(target_gen, Ordering::AcqRel);
        }
    }

    fn save_snapshot(&self, snapshot: &Data, target_gen: u64) {
        if self.path.is_none() {
            self.persisted_gen.fetch_max(target_gen, Ordering::AcqRel);
            return;
        }
        let bytes = serde_json::to_vec(snapshot).unwrap_or_default();
        self.write_bytes_if_newer(&bytes, target_gen);
    }

    fn kick_async(self: &Arc<Self>) {
        self.dirty_gen.fetch_add(1, Ordering::AcqRel);
        if self.path.is_none() {
            return;
        }
        if !self.started.load(Ordering::Acquire) {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                if !self.started.swap(true, Ordering::AcqRel) {
                    let st = self.clone();
                    handle.spawn(async move { st.run_writer().await });
                }
            }
        }
        self.notify.notify_one();
    }

    async fn run_writer(self: Arc<Self>) {
        loop {
            self.notify.notified().await;
            loop {
                let target_gen = self.dirty_gen.load(Ordering::Acquire);
                if self.persisted_gen.load(Ordering::Acquire) >= target_gen {
                    break;
                }
                let snapshot = self.data.lock().unwrap().clone();
                let st = self.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    st.save_snapshot(&snapshot, target_gen);
                })
                .await;
            }
        }
    }
}

pub struct Accounts {
    #[cfg_attr(not(test), allow(dead_code))]
    path: Option<PathBuf>,
    /// Host name the panel is published under: the only origin passkeys work from.
    panel_host: Option<String>,
    read_only: AtomicBool,
    data: Arc<Mutex<Data>>,
    writer: Arc<PersistState>,
    changed: tokio::sync::watch::Sender<()>,
    clock: Arc<HlcClock>,
    sync_node_id: RwLock<String>,
}

fn stamp_acc(d: &mut Data, clock: &HlcClock, node: &str, deleted: bool) -> SyncMeta {
    d.local_rev = d.local_rev.saturating_add(1);
    clock.stamp(node, deleted, d.local_rev)
}

fn normalize_loaded_accounts(d: &mut Data, clock: &HlcClock) {
    if d.epoch.is_empty() {
        d.epoch = uuid::Uuid::new_v4().simple().to_string();
    }
    let mut max_ver = (0u64, 0u64);
    let mut bump = |m: &mut SyncMeta| {
        if m.is_unset() {
            m.updated_ms = 1;
            m.node = "legacy".into();
        }
        if (m.updated_ms, m.seq) > max_ver {
            max_ver = (m.updated_ms, m.seq);
        }
        if m.local_rev == 0 {
            d.local_rev = d.local_rev.saturating_add(1);
            m.local_rev = d.local_rev;
        } else if m.local_rev > d.local_rev {
            d.local_rev = m.local_rev;
        }
    };
    for u in &mut d.users {
        bump(&mut u.sync);
        for p in &mut u.passkeys {
            bump(&mut p.sync);
        }
    }
    for s in &mut d.sessions {
        bump(&mut s.sync);
    }
    for e in &mut d.audit {
        if e.id.is_empty() {
            let sig = sha256(format!("{}|{}|{}|{}|{}", e.at, e.actor, e.action, e.detail, e.ip).as_bytes());
            e.id = hex(&sig[..16]);
        }
        bump(&mut e.sync);
    }
    for m in d.deleted_users.values_mut() {
        m.deleted = true;
        bump(m);
    }
    for m in d.deleted_passkeys.values_mut() {
        m.deleted = true;
        bump(m);
    }
    for m in d.deleted_sessions.values_mut() {
        m.deleted = true;
        bump(m);
    }
    for jti in d.spent_jti.keys() {
        d.spent_jti_rev.entry(jti.clone()).or_insert_with(|| {
            d.local_rev = d.local_rev.saturating_add(1);
            d.local_rev
        });
    }
    for jti in d.ticket_wrong.keys() {
        d.ticket_wrong_rev.entry(jti.clone()).or_insert_with(|| {
            d.local_rev = d.local_rev.saturating_add(1);
            d.local_rev
        });
    }
    clock.advance_floor(max_ver.0, max_ver.1);
}

fn gc_account_state(d: &mut Data, now_secs: i64, now_ms: u64) {
    d.spent_jti.retain(|jti, exp| {
        let keep = *exp > now_secs;
        if !keep {
            d.spent_jti_rev.remove(jti);
        }
        keep
    });
    d.ticket_wrong.retain(|jti, (_, exp)| {
        let keep = *exp > now_secs;
        if !keep {
            d.ticket_wrong_rev.remove(jti);
        }
        keep
    });
    d.deleted_users.retain(|_, m| {
        let keep = now_ms.saturating_sub(m.updated_ms) <= DURABLE_TOMBSTONE_TTL_MS;
        if !keep {
            d.gc_floor_rev = d.gc_floor_rev.max(m.local_rev);
        }
        keep
    });
    d.deleted_passkeys.retain(|_, m| {
        let keep = now_ms.saturating_sub(m.updated_ms) <= DURABLE_TOMBSTONE_TTL_MS;
        if !keep {
            d.gc_floor_rev = d.gc_floor_rev.max(m.local_rev);
        }
        keep
    });
    d.deleted_sessions.retain(|_, m| {
        let keep = now_ms.saturating_sub(m.updated_ms) <= SESSION_TOMBSTONE_TTL_MS;
        if !keep {
            d.gc_floor_rev = d.gc_floor_rev.max(m.local_rev);
        }
        keep
    });
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct AccountsDeltaPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_secret: Option<ClusterSecret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth_config: Option<OAuthConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    users: Vec<User>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sessions: Vec<Session>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audit: Vec<AuditEntry>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    deleted_users: BTreeMap<String, SyncMeta>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    deleted_passkeys: BTreeMap<String, SyncMeta>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    deleted_sessions: BTreeMap<String, SyncMeta>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    spent_jti: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    ticket_wrong: BTreeMap<String, (u32, i64)>,
}

impl Accounts {
    pub fn open(path: PathBuf, panel_host: Option<String>) -> Accounts {
        let clock = Arc::new(HlcClock::default());
        let mut data = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                tracing::error!("cannot read {}: {e}; starting without accounts (the file is left as it is until something is saved)", path.display());
                Data::default()
            }),
            Err(_) => Data::default(),
        };
        normalize_loaded_accounts(&mut data, &clock);
        let sync_node_id = crate::sync::resolve_sync_node_id(path.parent(), "local");
        let data = Arc::new(Mutex::new(data));
        let writer = Arc::new(PersistState {
            path: Some(path.clone()),
            data: data.clone(),
            persist_lock: Mutex::default(),
            dirty_gen: AtomicU64::new(0),
            persisted_gen: AtomicU64::new(0),
            notify: tokio::sync::Notify::new(),
            started: AtomicBool::new(false),
        });
        Accounts {
            path: Some(path),
            panel_host,
            read_only: AtomicBool::new(false),
            data,
            writer,
            changed: tokio::sync::watch::channel(()).0,
            clock,
            sync_node_id: RwLock::new(sync_node_id),
        }
    }

    /// Ephemeral in-memory accounts (`--role accelerate`). Never reads or writes
    /// `accounts.json` and rejects local mutations with `ReadOnly` (`409`).
    pub fn open_ephemeral(panel_host: Option<String>) -> Accounts {
        let clock = Arc::new(HlcClock::default());
        let mut data = Data::default();
        normalize_loaded_accounts(&mut data, &clock);
        let sync_node_id = crate::sync::resolve_sync_node_id(None, "local");
        let data = Arc::new(Mutex::new(data));
        let writer = Arc::new(PersistState {
            path: None,
            data: data.clone(),
            persist_lock: Mutex::default(),
            dirty_gen: AtomicU64::new(0),
            persisted_gen: AtomicU64::new(0),
            notify: tokio::sync::Notify::new(),
            started: AtomicBool::new(false),
        });
        Accounts {
            path: None,
            panel_host,
            read_only: AtomicBool::new(true),
            data,
            writer,
            changed: tokio::sync::watch::channel(()).0,
            clock,
            sync_node_id: RwLock::new(sync_node_id),
        }
    }

    pub fn set_sync_identity(&self, clock: Arc<HlcClock>, node_id: String) {
        let (ms, seq) = self.clock.current();
        clock.advance_floor(ms, seq);
        *self.sync_node_id.write().unwrap() = node_id;
        // Keep internal clock synchronized to shared floor; updates use `self.clock`.
        let (cms, cseq) = clock.current();
        self.clock.advance_floor(cms, cseq);
    }

    /// Initialize a deterministic cluster secret from the shared fleet API token
    /// if no cluster secret has been persisted or synced yet.
    pub fn set_api_token_secret(&self, api_token: &str) {
        let mut d = self.data.lock().unwrap();
        if d.cluster_secret.is_none() {
            let key = sha256(&[b"fucf-cluster:", api_token.as_bytes()].concat());
            d.cluster_secret = Some(ClusterSecret { key_b64: b64(&key), created_ms: 1, node: "token".into() });
        }
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.changed.subscribe()
    }

    pub fn spawn_writer(&self) {
        if self.writer.path.is_none() {
            return;
        }
        if !self.writer.started.swap(true, Ordering::AcqRel) {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let w = self.writer.clone();
                handle.spawn(async move { w.run_writer().await });
            }
        }
    }

    pub fn flush_blocking(&self) {
        let target_gen = self.writer.dirty_gen.load(Ordering::Acquire);
        if self.writer.persisted_gen.load(Ordering::Acquire) >= target_gen {
            return;
        }
        let snapshot = self.data.lock().unwrap().clone();
        self.writer.save_snapshot(&snapshot, target_gen);
    }

    fn sync_node(&self) -> String {
        self.sync_node_id.read().unwrap().clone()
    }

    fn cluster_secret_bytes(&self) -> Vec<u8> {
        let mut d = self.data.lock().unwrap();
        if let Some(cs) = &d.cluster_secret {
            if let Some(bytes) = unb64(&cs.key_b64) {
                return bytes;
            }
        }
        let raw = random(32);
        let cs = ClusterSecret {
            key_b64: b64(&raw),
            created_ms: unix_ms().max(2),
            node: self.sync_node(),
        };
        d.cluster_secret = Some(cs);
        raw
    }

    fn check_writable(&self) -> Result<(), AuthError> {
        if self.read_only.load(Ordering::Relaxed) {
            Err(AuthError::new(409, 1003, "this node is in accelerate mode; make changes on a peer node"))
        } else {
            Ok(())
        }
    }

    fn commit_snapshot(&self, snapshot: Data) {
        let gen = self.writer.dirty_gen.fetch_add(1, Ordering::AcqRel) + 1;
        self.writer.save_snapshot(&snapshot, gen);
        self.changed.send_replace(());
    }

    fn record(data: &mut Data, clock: &HlcClock, node: &str, actor: &str, action: &str, detail: impl Into<String>, ip: &str) {
        let sync = stamp_acc(data, clock, node, false);
        data.audit.push(AuditEntry {
            id: uuid::Uuid::new_v4().simple().to_string(),
            at: crate::store::now(),
            actor: actor.to_string(),
            action: action.to_string(),
            detail: detail.into(),
            ip: ip.to_string(),
            sync,
        });
        let excess = data.audit.len().saturating_sub(AUDIT_KEPT);
        data.audit.drain(..excess);
    }

    fn hold_pending(&self, kind: char, uid: Option<&str>) -> String {
        let secret = self.cluster_secret_bytes();
        seal_pending(&secret, kind, uid, now() + PENDING_SECS)
    }

    fn verify_pending(&self, token: &str, expected_kind: char) -> Option<PendingClaims> {
        let secret = self.cluster_secret_bytes();
        verify_pending_token(&secret, token, expected_kind)
    }

    /// Is there anybody who can sign in? Until then the panel only offers
    /// to set up the first account.
    pub fn initialized(&self) -> bool {
        !self.data.lock().unwrap().users.is_empty()
    }

    /// Add a user. Without a password one is made up and returned -- once;
    /// the user is asked to change it after signing in.
    pub fn create_user(&self, email: &str, role: Role, password: Option<&str>, actor: &str, client: &Client) -> Result<(Value, Option<String>), AuthError> {
        self.check_writable()?;
        let email = normalize_email(email)?;
        let generated = password.is_none().then(random_password);
        let password = password.map(String::from).or(generated.clone()).unwrap_or_default();
        check_password(&password, &email)?;
        let hash = PasswordHash::of(&password);
        let node = self.sync_node();
        let snapshot = {
            let mut data = self.data.lock().unwrap();
            if data.users.iter().any(|u| u.email == email) {
                return Err(AuthError::conflict("there is a user with this e-mail address already"));
            }
            let uid = uuid::Uuid::new_v4().simple().to_string();
            let sync = stamp_acc(&mut data, &self.clock, &node, false);
            data.deleted_users.remove(&uid);
            let user = User {
                id: uid,
                email: email.clone(),
                role,
                disabled: false,
                password: hash,
                must_change_password: actor != email,
                totp: None,
                backup_codes: Vec::new(),
                passkeys: Vec::new(),
                created_on: crate::store::now(),
                last_login_on: None,
                failed: 0,
                locked_until: 0,
                sync,
            };
            let view = user.view();
            data.users.push(user);
            Self::record(&mut data, &self.clock, &node, actor, "user.create", format!("{email} ({})", role.name()), &client.ip);
            (view, data.clone())
        };
        let (view, snap) = snapshot;
        self.commit_snapshot(snap);
        Ok((view, generated))
    }

    pub fn users(&self) -> Vec<Value> {
        self.data.lock().unwrap().users.iter().map(User::view).collect()
    }

    /// Change a user: role, disabled; a new generated password (returned
    /// once); two-step verification and passkeys taken off (for somebody
    /// who lost them).
    #[allow(clippy::too_many_arguments)]
    pub fn update_user(
        &self,
        id: &str,
        role: Option<Role>,
        disabled: Option<bool>,
        reset_password: bool,
        reset_two_factor: bool,
        actor: &Principal,
        client: &Client,
    ) -> Result<(Value, Option<String>), AuthError> {
        self.check_writable()?;
        let generated = reset_password.then(random_password);
        let hash = generated.as_deref().map(PasswordHash::of);
        let node = self.sync_node();
        let (view, snap_opt) = {
            let mut data = self.data.lock().unwrap();
            let admins = data.users.iter().filter(|u| u.role == Role::Admin && !u.disabled).count();
            let idx = data.users.iter().position(|u| u.id == id).ok_or_else(AuthError::not_found)?;
            let own = actor.user_id.as_deref() == Some(id);
            let loses_admin = data.users[idx].role == Role::Admin
                && !data.users[idx].disabled
                && (role.is_some_and(|r| r != Role::Admin) || disabled == Some(true));
            if loses_admin && (own || admins <= 1) {
                return Err(AuthError::conflict(if own { "you cannot take the administrator role from yourself" } else { "this is the only administrator" }));
            }
            let mut changes = Vec::new();
            let mut removed_passkeys = Vec::new();
            {
                let user = &mut data.users[idx];
                if let Some(role) = role.filter(|r| *r != user.role) {
                    user.role = role;
                    changes.push(format!("role {}", role.name()));
                }
                if let Some(disabled) = disabled.filter(|d| *d != user.disabled) {
                    user.disabled = disabled;
                    changes.push(if disabled { "disabled" } else { "enabled" }.to_string());
                }
                if let Some(hash) = hash {
                    (user.password, user.must_change_password, user.failed, user.locked_until) = (hash, true, 0, 0);
                    changes.push("password reset".into());
                }
                if reset_two_factor {
                    (user.totp, user.backup_codes) = (None, Vec::new());
                    removed_passkeys = user.passkeys.drain(..).map(|p| p.id).collect();
                    changes.push("two-step verification and passkeys removed".into());
                }
            }
            for pk_id in removed_passkeys {
                let t = stamp_acc(&mut data, &self.clock, &node, true);
                data.deleted_passkeys.insert(pk_id, t);
            }
            let signed_out = data.users[idx].disabled || reset_password || reset_two_factor;
            let (view, email) = (data.users[idx].view(), data.users[idx].email.clone());
            if !changes.is_empty() {
                data.users[idx].sync = stamp_acc(&mut data, &self.clock, &node, false);
            }
            if signed_out {
                let keep = if own { actor.session_id.clone() } else { None };
                let mut dropped = Vec::new();
                data.sessions.retain(|s| {
                    let keep_s = s.user_id != id || Some(&s.id) == keep.as_ref();
                    if !keep_s {
                        dropped.push(s.id.clone());
                    }
                    keep_s
                });
                for sid in dropped {
                    let t = stamp_acc(&mut data, &self.clock, &node, true);
                    data.deleted_sessions.insert(sid, t);
                }
            }
            let snap_opt = if !changes.is_empty() {
                Self::record(&mut data, &self.clock, &node, &actor.email, "user.update", format!("{email}: {}", changes.join(", ")), &client.ip);
                Some(data.clone())
            } else {
                None
            };
            (view, snap_opt)
        };
        if let Some(snap) = snap_opt {
            self.commit_snapshot(snap);
        }
        Ok((view, generated))
    }

    pub fn delete_user(&self, id: &str, actor: &Principal, client: &Client) -> Result<(), AuthError> {
        self.check_writable()?;
        let node = self.sync_node();
        let snap = {
            let mut data = self.data.lock().unwrap();
            let user = data.users.iter().find(|u| u.id == id).ok_or_else(AuthError::not_found)?;
            if actor.user_id.as_deref() == Some(id) {
                return Err(AuthError::conflict("you cannot delete your own account"));
            }
            let admins = data.users.iter().filter(|u| u.role == Role::Admin && !u.disabled).count();
            if user.role == Role::Admin && !user.disabled && admins <= 1 {
                return Err(AuthError::conflict("this is the only administrator"));
            }
            let email = user.email.clone();
            let pk_ids: Vec<String> = user.passkeys.iter().map(|p| p.id.clone()).collect();
            data.users.retain(|u| u.id != id);
            let mut rm_sessions = Vec::new();
            data.sessions.retain(|s| {
                if s.user_id == id {
                    rm_sessions.push(s.id.clone());
                    false
                } else {
                    true
                }
            });
            let t_user = stamp_acc(&mut data, &self.clock, &node, true);
            data.deleted_users.insert(id.to_string(), t_user);
            for pk in pk_ids {
                let t = stamp_acc(&mut data, &self.clock, &node, true);
                data.deleted_passkeys.insert(pk, t);
            }
            for sid in rm_sessions {
                let t = stamp_acc(&mut data, &self.clock, &node, true);
                data.deleted_sessions.insert(sid, t);
            }
            Self::record(&mut data, &self.clock, &node, &actor.email, "user.delete", email, &client.ip);
            data.clone()
        };
        self.commit_snapshot(snap);
        Ok(())
    }

    fn open_session(data: &mut Data, clock: &HlcClock, node: &str, user_id: &str, method: &str, client: &Client) -> (String, Value) {
        let token = format!("{SESSION_PREFIX}{}", b64(&random(32)));
        let at = now();
        let mut expired = Vec::new();
        data.sessions.retain(|s| {
            if s.expires > at {
                true
            } else {
                expired.push(s.id.clone());
                false
            }
        });
        for sid in expired {
            let t = stamp_acc(data, clock, node, true);
            data.deleted_sessions.insert(sid, t);
        }
        let s_sync = stamp_acc(data, clock, node, false);
        let sid = hex(&random(6));
        data.deleted_sessions.remove(&sid);
        data.sessions.push(Session {
            id: sid,
            digest: hex(&sha256(token.as_bytes())),
            user_id: user_id.to_string(),
            created: at,
            last_seen: at,
            expires: at + SESSION_DAYS * 86400,
            ip: client.ip.clone(),
            agent: client.agent.chars().take(200).collect(),
            method: method.to_string(),
            sync: s_sync,
        });
        let u_sync = stamp_acc(data, clock, node, false);
        let user = data.users.iter_mut().find(|u| u.id == user_id).expect("the user signing in exists");
        (user.failed, user.locked_until, user.last_login_on) = (0, 0, Some(crate::store::now()));
        user.sync = u_sync;
        let (view, email) = (user.view(), user.email.clone());
        Self::record(data, clock, node, &email, "login", method, &client.ip);
        (token, view)
    }

    /// First step: e-mail address and password. (Slow on purpose: call it
    /// off the async threads.)
    pub fn login(&self, email: &str, password: &str, client: &Client) -> Result<Login, AuthError> {
        self.check_writable()?;
        let email = email.trim().to_ascii_lowercase();
        let found = {
            let data = self.data.lock().unwrap();
            data.users.iter().find(|u| u.email == email).map(|u| (u.id.clone(), u.password.clone(), u.locked_until))
        };
        let Some((id, hash, locked_until)) = found else {
            // the same work as for a user that exists, so that the time taken says nothing
            PasswordHash { salt: b64(&[0u8; 16]), rounds: KDF_ROUNDS, hash: b64(&[0u8; 32]) }.matches(password);
            return Err(AuthError::credentials());
        };
        if locked_until > now() {
            return Err(AuthError::locked(locked_until - now()));
        }
        let right = hash.matches(password);
        let node = self.sync_node();
        let outcome = {
            let mut data = self.data.lock().unwrap();
            let idx = data.users.iter().position(|u| u.id == id).ok_or_else(AuthError::credentials)?;
            if !right {
                let u_sync = stamp_acc(&mut data, &self.clock, &node, false);
                let failed = {
                    let user = &mut data.users[idx];
                    user.failed += 1;
                    if user.failed >= FREE_ATTEMPTS {
                        user.locked_until = now() + (60i64 << (user.failed - FREE_ATTEMPTS).min(4)).min(900);
                    }
                    user.sync = u_sync;
                    user.failed
                };
                Self::record(&mut data, &self.clock, &node, &email, "login.failed", format!("wrong password ({failed} in a row)"), &client.ip);
                Err((AuthError::credentials(), Some(data.clone())))
            } else if data.users[idx].disabled {
                Err((AuthError::disabled(), None))
            } else if data.users[idx].two_factor() {
                let mut methods = vec!["totp", "backup_code"];
                if !data.users[idx].passkeys.is_empty() {
                    methods.push("passkey");
                }
                Ok(Err(methods))
            } else {
                let (token, view) = Self::open_session(&mut data, &self.clock, &node, &id, "password", client);
                Ok(Ok((token, view, data.clone())))
            }
        };
        match outcome {
            Ok(Ok((token, view, snap))) => {
                self.commit_snapshot(snap);
                Ok(Login::Session(token, view))
            }
            Ok(Err(methods)) => {
                let ticket = self.hold_pending('t', Some(&id));
                Ok(Login::SecondStep { ticket, methods })
            }
            Err((err, snap_opt)) => {
                if let Some(snap) = snap_opt {
                    self.commit_snapshot(snap);
                }
                Err(err)
            }
        }
    }

    /// Second step: a code from the authenticator app, a backup code (which
    /// is used up by it), or a passkey.
    pub fn second_step(&self, ticket: &str, proof: Proof, client: &Client) -> Result<(String, Value), AuthError> {
        self.check_writable()?;
        let Some(claims) = self.verify_pending(ticket, 't') else { return Err(AuthError::expired()) };
        let Some(user_id) = claims.uid else { return Err(AuthError::expired()) };
        let node = self.sync_node();
        let panel_host = self.panel_host.as_deref();
        let (res, snap_opt) = {
            let mut data = self.data.lock().unwrap();
            gc_account_state(&mut data, now(), unix_ms());
            if data.spent_jti.contains_key(&claims.jti) {
                return Err(AuthError::expired());
            }
            let wrong = data.ticket_wrong.get(&claims.jti).map(|(w, _)| *w).unwrap_or(0);
            let idx = data
                .users
                .iter()
                .position(|u| u.id == user_id && !u.disabled && u.two_factor())
                .ok_or_else(AuthError::expired)?;
            let passed: Result<&str, AuthError> = match proof {
                Proof::Totp(code) => {
                    let totp = data.users[idx].totp.as_mut().expect("two-step verification is on");
                    match unbase32(&totp.secret).and_then(|secret| totp_step(&secret, &code, now())) {
                        Some(step) if step > totp.last_step => {
                            totp.last_step = step;
                            Ok("password+totp")
                        }
                        Some(_) => Err(AuthError::second_step("this code was used already: wait for the next one")),
                        None => Err(AuthError::second_step("wrong code")),
                    }
                }
                Proof::BackupCode(code) => {
                    let digest = backup_digest(&code);
                    match data.users[idx].backup_codes.iter().position(|c| ct_eq(c.as_bytes(), digest.as_bytes())) {
                        Some(at) => {
                            data.users[idx].backup_codes.remove(at);
                            Ok("password+backup_code")
                        }
                        None => Err(AuthError::second_step("wrong backup code (each works once)")),
                    }
                }
                Proof::Passkey(assertion) => {
                    let answered = unb64(&assertion.client_data)
                        .ok_or_else(|| AuthError::passkey("malformed passkey data"))
                        .and_then(|raw| client_data(&raw, "webauthn.get", panel_host))
                        .map(|(challenge, _)| challenge);
                    match answered {
                        Ok(challenge) if challenge == ticket => {
                            assert_passkey(&mut data.users[idx], &assertion, panel_host, false).map(|_| "password+passkey")
                        }
                        Ok(_) => Err(AuthError::passkey("the passkey answered another challenge")),
                        Err(e) => Err(e),
                    }
                }
            };
            match passed {
                Ok(method) => {
                    if method == "password+passkey" {
                        let pk_sync = stamp_acc(&mut data, &self.clock, &node, false);
                        if let Some(pk) = data.users[idx].passkeys.iter_mut().max_by_key(|p| p.last_used_on.clone()) {
                            pk.sync = pk_sync;
                        }
                    }
                    data.local_rev = data.local_rev.saturating_add(1);
                    let rev = data.local_rev;
                    data.spent_jti.insert(claims.jti.clone(), claims.exp);
                    data.spent_jti_rev.insert(claims.jti.clone(), rev);
                    data.ticket_wrong.remove(&claims.jti);
                    data.ticket_wrong_rev.remove(&claims.jti);
                    let (token, view) = Self::open_session(&mut data, &self.clock, &node, &user_id, method, client);
                    (Ok((token, view)), Some(data.clone()))
                }
                Err(e) => {
                    let u_sync = stamp_acc(&mut data, &self.clock, &node, false);
                    let (locked, email) = {
                        let user = &mut data.users[idx];
                        user.failed += 1;
                        user.sync = u_sync;
                        let locked = if user.failed >= FREE_ATTEMPTS {
                            let wait = (60i64 << (user.failed - FREE_ATTEMPTS).min(4)).min(900);
                            user.locked_until = now() + wait;
                            Some(wait)
                        } else {
                            None
                        };
                        (locked, user.email.clone())
                    };
                    if wrong + 1 < FREE_ATTEMPTS {
                        data.local_rev = data.local_rev.saturating_add(1);
                        let rev = data.local_rev;
                        data.ticket_wrong.insert(claims.jti.clone(), (wrong + 1, claims.exp));
                        data.ticket_wrong_rev.insert(claims.jti.clone(), rev);
                    } else {
                        data.local_rev = data.local_rev.saturating_add(1);
                        let rev = data.local_rev;
                        data.ticket_wrong.remove(&claims.jti);
                        data.ticket_wrong_rev.remove(&claims.jti);
                        data.spent_jti.insert(claims.jti.clone(), claims.exp);
                        data.spent_jti_rev.insert(claims.jti.clone(), rev);
                    }
                    Self::record(&mut data, &self.clock, &node, &email, "login.failed", format!("second step: {}", e.message), &client.ip);
                    let err = if let Some(secs) = locked {
                        AuthError::locked(secs)
                    } else if wrong + 1 < FREE_ATTEMPTS {
                        e
                    } else {
                        AuthError::expired()
                    };
                    (Err(err), Some(data.clone()))
                }
            }
        };
        if let Some(snap) = snap_opt {
            self.commit_snapshot(snap);
        }
        res
    }

    /// Who does this session token belong to? Also notes that it is in use
    /// in memory (never performs disk I/O on the auth middleware path).
    pub fn session(&self, token: &str) -> Option<Principal> {
        if !token.starts_with(SESSION_PREFIX) {
            return None;
        }
        let digest = hex(&sha256(token.as_bytes()));
        let (principal, stale) = {
            let mut data = self.data.lock().unwrap();
            let at = now();
            let session = data.sessions.iter_mut().find(|s| s.expires > at && ct_eq(s.digest.as_bytes(), digest.as_bytes()))?;
            let stale = at - session.last_seen > 300;
            if stale {
                session.last_seen = at;
            }
            let (user_id, session_id) = (session.user_id.clone(), session.id.clone());
            let user = data.users.iter().find(|u| u.id == user_id && !u.disabled)?;
            let principal = Principal {
                user_id: Some(user.id.clone()),
                email: user.email.clone(),
                role: user.role,
                session_id: Some(session_id),
                must_change_password: user.must_change_password,
            };
            (principal, stale)
        };
        if stale && !self.read_only.load(Ordering::Relaxed) {
            self.writer.kick_async();
        }
        Some(principal)
    }

    pub fn logout(&self, session_id: &str) {
        if self.read_only.load(Ordering::Relaxed) {
            return;
        }
        let node = self.sync_node();
        let snap = {
            let mut data = self.data.lock().unwrap();
            let before = data.sessions.len();
            data.sessions.retain(|s| s.id != session_id);
            if data.sessions.len() == before {
                return;
            }
            let tomb = stamp_acc(&mut data, &self.clock, &node, true);
            data.deleted_sessions.insert(session_id.to_string(), tomb);
            data.clone()
        };
        self.commit_snapshot(snap);
    }

    /// A user's own account: what protects it, and where it is signed in.
    pub fn me(&self, user_id: &str, session_id: Option<&str>) -> Option<Value> {
        let data = self.data.lock().unwrap();
        let user = data.users.iter().find(|u| u.id == user_id)?;
        let mut view = user.view();
        view["backup_codes_left"] = json!(user.backup_codes.len());
        view["passkey_list"] = user.passkeys.iter().map(|p| json!({ "id": p.id, "name": p.name, "alg": p.alg, "created_on": p.created_on, "last_used_on": p.last_used_on })).collect();
        view["sessions"] = data
            .sessions
            .iter()
            .filter(|s| s.user_id == user_id && s.expires > now())
            .map(|s| {
                json!({
                    "id": s.id, "current": Some(s.id.as_str()) == session_id, "ip": s.ip, "agent": s.agent, "method": s.method,
                    "created_on": crate::store::rfc3339(s.created), "last_seen_on": crate::store::rfc3339(s.last_seen),
                })
            })
            .collect();
        Some(view)
    }

    /// Do something to a user's account that takes the password again.
    fn with_password<T>(&self, user_id: &str, password: &str, then: impl FnOnce(&mut Data, usize, &HlcClock, &str) -> Result<T, AuthError>) -> Result<T, AuthError> {
        self.check_writable()?;
        let hash = self.data.lock().unwrap().users.iter().find(|u| u.id == user_id).map(|u| u.password.clone()).ok_or_else(AuthError::not_found)?;
        if !hash.matches(password) {
            return Err(AuthError::new(403, 2014, "the current password is wrong"));
        }
        let node = self.sync_node();
        let (result, snap) = {
            let mut data = self.data.lock().unwrap();
            let at = data.users.iter().position(|u| u.id == user_id).ok_or_else(AuthError::not_found)?;
            let result = then(&mut data, at, &self.clock, &node)?;
            data.users[at].sync = stamp_acc(&mut data, &self.clock, &node, false);
            (result, data.clone())
        };
        self.commit_snapshot(snap);
        Ok(result)
    }

    fn own_id(actor: &Principal) -> Result<&str, AuthError> {
        actor.user_id.as_deref().ok_or_else(|| AuthError::invalid("the API token is not a user: sign in to the panel for this"))
    }

    /// Change one's own password. Every other session of the user ends.
    pub fn change_password(&self, actor: &Principal, current: &str, new: &str, client: &Client) -> Result<(), AuthError> {
        let user_id = Self::own_id(actor)?;
        check_password(new, &actor.email)?;
        if current == new {
            return Err(AuthError::weak("the new password is the old one"));
        }
        let hash = PasswordHash::of(new);
        self.with_password(user_id, current, |data, at, clock, node| {
            (data.users[at].password, data.users[at].must_change_password) = (hash, false);
            let mut dropped = Vec::new();
            data.sessions.retain(|s| {
                let keep = s.user_id != user_id || Some(&s.id) == actor.session_id.as_ref();
                if !keep {
                    dropped.push(s.id.clone());
                }
                keep
            });
            for sid in dropped {
                let t = stamp_acc(data, clock, node, true);
                data.deleted_sessions.insert(sid, t);
            }
            Self::record(data, clock, node, &actor.email, "password.change", "", &client.ip);
            Ok(())
        })
    }

    /// Start setting up the authenticator app: a new secret, not in force
    /// until a code made with it is shown. Returns the secret and the
    /// otpauth:// address that apps scan.
    pub fn totp_begin(&self, actor: &Principal) -> Result<(String, String), AuthError> {
        self.check_writable()?;
        let user_id = Self::own_id(actor)?;
        let node = self.sync_node();
        let (secret, uri, snap) = {
            let mut data = self.data.lock().unwrap();
            let idx = data.users.iter().position(|u| u.id == user_id).ok_or_else(AuthError::not_found)?;
            if data.users[idx].two_factor() {
                return Err(AuthError::conflict("two-step verification is on already: switch it off first to use another app"));
            }
            let secret = base32(&random(20));
            let email = data.users[idx].email.clone();
            data.users[idx].totp = Some(Totp { secret: secret.clone(), enabled: false, last_step: 0 });
            data.users[idx].sync = stamp_acc(&mut data, &self.clock, &node, false);
            let label = format!("fucloudflare:{email}").replace(' ', "%20").replace('@', "%40");
            let uri = format!("otpauth://totp/{label}?secret={secret}&issuer=fucloudflare&algorithm=SHA1&digits=6&period=30");
            (secret, uri, data.clone())
        };
        self.commit_snapshot(snap);
        Ok((secret, uri))
    }

    /// Finish it with a code from the app. From now on signing in takes two
    /// steps. Returns the backup codes -- this once.
    pub fn totp_enable(&self, actor: &Principal, code: &str, client: &Client) -> Result<Vec<String>, AuthError> {
        self.check_writable()?;
        let user_id = Self::own_id(actor)?;
        let node = self.sync_node();
        let (codes, snap) = {
            let mut data = self.data.lock().unwrap();
            let idx = data.users.iter().position(|u| u.id == user_id).ok_or_else(AuthError::not_found)?;
            let codes = {
                let user = &mut data.users[idx];
                let totp = user.totp.as_mut().filter(|t| !t.enabled).ok_or_else(|| AuthError::conflict("there is no authenticator app being set up"))?;
                let step = unbase32(&totp.secret).and_then(|secret| totp_step(&secret, code, now())).ok_or_else(|| AuthError::second_step("wrong code"))?;
                (totp.enabled, totp.last_step) = (true, step);
                let codes: Vec<String> = (0..BACKUP_CODES).map(|_| backup_code()).collect();
                user.backup_codes = codes.iter().map(|c| backup_digest(c)).collect();
                codes
            };
            data.users[idx].sync = stamp_acc(&mut data, &self.clock, &node, false);
            Self::record(&mut data, &self.clock, &node, &actor.email, "two_factor.enable", "authenticator app", &client.ip);
            (codes, data.clone())
        };
        self.commit_snapshot(snap);
        Ok(codes)
    }

    /// Switch two-step verification off (the backup codes go with it).
    pub fn two_factor_disable(&self, actor: &Principal, password: &str, client: &Client) -> Result<(), AuthError> {
        self.with_password(Self::own_id(actor)?, password, |data, at, clock, node| {
            (data.users[at].totp, data.users[at].backup_codes) = (None, Vec::new());
            Self::record(data, clock, node, &actor.email, "two_factor.disable", "", &client.ip);
            Ok(())
        })
    }

    /// New backup codes; the old ones stop working. They are only ever a
    /// stand-in for the second step, so there are none without it.
    pub fn backup_codes_regenerate(&self, actor: &Principal, password: &str, client: &Client) -> Result<Vec<String>, AuthError> {
        self.with_password(Self::own_id(actor)?, password, |data, at, clock, node| {
            if !data.users[at].two_factor() {
                return Err(AuthError::conflict("backup codes stand in for the second step: switch two-step verification on first"));
            }
            let codes: Vec<String> = (0..BACKUP_CODES).map(|_| backup_code()).collect();
            data.users[at].backup_codes = codes.iter().map(|c| backup_digest(c)).collect();
            Self::record(data, clock, node, &actor.email, "backup_codes.regenerate", "", &client.ip);
            Ok(codes)
        })
    }

    /// A challenge for registering a passkey, with what the browser needs
    /// to know about the user and the passkeys there are already.
    pub fn passkey_register_begin(&self, actor: &Principal) -> Result<Value, AuthError> {
        self.check_writable()?;
        let user_id = Self::own_id(actor)?.to_string();
        let exclude: Vec<String> =
            self.data.lock().unwrap().users.iter().find(|u| u.id == user_id).map(|u| u.passkeys.iter().map(|p| p.id.clone()).collect()).unwrap_or_default();
        let challenge = self.hold_pending('r', Some(&user_id));
        Ok(json!({ "challenge": challenge, "user": { "id": b64(user_id.as_bytes()), "name": actor.email }, "exclude": exclude, "algorithms": [-7, -257, -8] }))
    }

    pub fn passkey_register(&self, actor: &Principal, registration: &Registration, client: &Client) -> Result<Value, AuthError> {
        self.check_writable()?;
        let malformed = || AuthError::passkey("malformed passkey data");
        let raw_client = unb64(&registration.client_data).ok_or_else(malformed)?;
        let raw_auth = unb64(&registration.authenticator_data).ok_or_else(malformed)?;
        let key = unb64(&registration.public_key).ok_or_else(malformed)?;
        let (challenge, rp) = client_data(&raw_client, "webauthn.create", self.panel_host.as_deref())?;
        let Some(claims) = self.verify_pending(&challenge, 'r') else { return Err(AuthError::expired()) };
        if claims.uid.as_ref() != actor.user_id.as_ref() {
            return Err(AuthError::expired());
        }
        let node = self.sync_node();
        let (res, snap_opt) = {
            let mut data = self.data.lock().unwrap();
            gc_account_state(&mut data, now(), unix_ms());
            if data.spent_jti.contains_key(&claims.jti) {
                return Err(AuthError::expired());
            }
            data.local_rev = data.local_rev.saturating_add(1);
            let rev = data.local_rev;
            data.spent_jti.insert(claims.jti.clone(), claims.exp);
            data.spent_jti_rev.insert(claims.jti.clone(), rev);

            let validate_and_insert = |data: &mut Data| -> Result<Value, AuthError> {
                let _sign_count = authenticator_data(&raw_auth, &rp, false)?;
                if ![-7, -8, -257].contains(&registration.alg) || key.len() < 32 || key.len() > 2048 || unb64(&registration.id).is_none_or(|id| id.is_empty() || id.len() > 1023) {
                    return Err(AuthError::passkey("this kind of passkey is not supported (ES256, EdDSA and RS256 are)"));
                }
                if data.users.iter().any(|u| u.passkeys.iter().any(|p| p.id == registration.id)) {
                    return Err(AuthError::conflict("this passkey is registered already"));
                }
                let user_id = actor.user_id.clone().unwrap_or_default();
                let idx = data.users.iter().position(|u| u.id == user_id).ok_or_else(AuthError::not_found)?;
                let name: String = registration.name.trim().chars().take(60).collect();
                let pk_sync = stamp_acc(data, &self.clock, &node, false);
                let u_sync = stamp_acc(data, &self.clock, &node, false);
                data.deleted_passkeys.remove(&registration.id);
                let passkey = Passkey {
                    id: registration.id.clone(),
                    name: if name.is_empty() { format!("passkey {}", data.users[idx].passkeys.len() + 1) } else { name },
                    alg: registration.alg,
                    key: registration.public_key.clone(),
                    sign_count: _sign_count,
                    created_on: crate::store::now(),
                    last_used_on: None,
                    sync: pk_sync,
                };
                let view = json!({ "id": passkey.id, "name": passkey.name, "created_on": passkey.created_on });
                data.users[idx].passkeys.push(passkey);
                data.users[idx].sync = u_sync;
                Self::record(data, &self.clock, &node, &actor.email, "passkey.add", view["name"].as_str().unwrap_or_default(), &client.ip);
                Ok(view)
            };
            let res = validate_and_insert(&mut data);
            (res, Some(data.clone()))
        };
        if let Some(snap) = snap_opt {
            self.commit_snapshot(snap);
        }
        res
    }

    pub fn passkey_delete(&self, actor: &Principal, id: &str, client: &Client) -> Result<(), AuthError> {
        self.check_writable()?;
        let user_id = Self::own_id(actor)?.to_string();
        let node = self.sync_node();
        let snap = {
            let mut data = self.data.lock().unwrap();
            let idx = data.users.iter().position(|u| u.id == user_id).ok_or_else(AuthError::not_found)?;
            let at = data.users[idx].passkeys.iter().position(|p| p.id == id).ok_or_else(|| AuthError::new(404, 2012, "no such passkey"))?;
            let name = data.users[idx].passkeys.remove(at).name;
            let pk_tomb = stamp_acc(&mut data, &self.clock, &node, true);
            data.deleted_passkeys.insert(id.to_string(), pk_tomb);
            data.users[idx].sync = stamp_acc(&mut data, &self.clock, &node, false);
            Self::record(&mut data, &self.clock, &node, &actor.email, "passkey.remove", name, &client.ip);
            data.clone()
        };
        self.commit_snapshot(snap);
        Ok(())
    }

    /// A challenge for signing in with a passkey (no e-mail address needed:
    /// the passkey says whose it is).
    pub fn passkey_login_begin(&self) -> String {
        self.hold_pending('s', None)
    }

    /// Sign in with a passkey alone. It has to verify its user itself (PIN,
    /// fingerprint, face): that is the second factor.
    pub fn passkey_login(&self, assertion: &Assertion, client: &Client) -> Result<(String, Value), AuthError> {
        self.check_writable()?;
        let raw_client = unb64(&assertion.client_data).ok_or_else(|| AuthError::passkey("malformed passkey data"))?;
        let (challenge, _) = client_data(&raw_client, "webauthn.get", self.panel_host.as_deref())?;
        let Some(claims) = self.verify_pending(&challenge, 's') else { return Err(AuthError::expired()) };
        let node = self.sync_node();
        let (res, snap_opt) = {
            let mut data = self.data.lock().unwrap();
            gc_account_state(&mut data, now(), unix_ms());
            if data.spent_jti.contains_key(&claims.jti) {
                return Err(AuthError::expired());
            }
            data.local_rev = data.local_rev.saturating_add(1);
            let rev = data.local_rev;
            data.spent_jti.insert(claims.jti.clone(), claims.exp);
            data.spent_jti_rev.insert(claims.jti.clone(), rev);

            let panel_host = self.panel_host.as_deref();
            let attempt = (|| -> Result<(String, Value), AuthError> {
                let idx = data
                    .users
                    .iter()
                    .position(|u| u.passkeys.iter().any(|p| p.id == assertion.id))
                    .ok_or_else(|| AuthError::passkey("this passkey is not registered here"))?;
                if data.users[idx].disabled {
                    return Err(AuthError::disabled());
                }
                assert_passkey(&mut data.users[idx], assertion, panel_host, true)?;
                let user_id = data.users[idx].id.clone();
                let pk_sync = stamp_acc(&mut data, &self.clock, &node, false);
                if let Some(pk) = data.users[idx].passkeys.iter_mut().find(|p| p.id == assertion.id) {
                    pk.sync = pk_sync;
                }
                Ok(Self::open_session(&mut data, &self.clock, &node, &user_id, "passkey", client))
            })();
            (attempt, Some(data.clone()))
        };
        if let Some(snap) = snap_opt {
            self.commit_snapshot(snap);
        }
        res
    }

    /// End one of the user's own sessions.
    pub fn revoke_session(&self, actor: &Principal, session_id: &str) -> Result<(), AuthError> {
        self.check_writable()?;
        let node = self.sync_node();
        let snap = {
            let mut data = self.data.lock().unwrap();
            let before = data.sessions.len();
            data.sessions.retain(|s| !(s.id == session_id && Some(&s.user_id) == actor.user_id.as_ref()));
            if data.sessions.len() == before {
                return Err(AuthError::new(404, 2012, "no such session"));
            }
            let tomb = stamp_acc(&mut data, &self.clock, &node, true);
            data.deleted_sessions.insert(session_id.to_string(), tomb);
            data.clone()
        };
        self.commit_snapshot(snap);
        Ok(())
    }

    /// Note something an administrator did that is not about accounts.
    pub fn note(&self, actor: &Principal, action: &str, detail: impl Into<String>, client: &Client) {
        if self.read_only.load(Ordering::Relaxed) {
            return;
        }
        let node = self.sync_node();
        let snap = {
            let mut data = self.data.lock().unwrap();
            Self::record(&mut data, &self.clock, &node, &actor.email, action, detail, &client.ip);
            data.clone()
        };
        self.commit_snapshot(snap);
    }

    /// Current OAuth SSO configuration.
    pub fn oauth_config(&self) -> OAuthConfig {
        self.data.lock().unwrap().oauth_config.clone()
    }

    /// Update OAuth SSO configuration (replicated across peers via HLC LWW).
    pub fn set_oauth_config(&self, mut cfg: OAuthConfig, actor: &str, client: &Client) -> Result<OAuthConfig, AuthError> {
        self.check_writable()?;
        cfg.issuer_url = cfg.issuer_url.trim().trim_end_matches('/').to_string();
        cfg.client_id = cfg.client_id.trim().to_string();
        cfg.client_secret = cfg.client_secret.trim().to_string();
        cfg.scopes = cfg.scopes.trim().to_string();
        if cfg.scopes.is_empty() {
            cfg.scopes = "openid profile email".into();
        }
        cfg.redirect_base_url = cfg.redirect_base_url.trim().trim_end_matches('/').to_string();
        if cfg.enabled {
            if cfg.issuer_url.is_empty() || (!cfg.issuer_url.starts_with("https://") && !cfg.issuer_url.starts_with("http://")) {
                return Err(AuthError::invalid("issuer_url must start with https:// or http://"));
            }
            if cfg.client_id.is_empty() {
                return Err(AuthError::invalid("client_id is required when OAuth is enabled"));
            }
        }
        let node = self.sync_node();
        let (out, snap) = {
            let mut d = self.data.lock().unwrap();
            if cfg.client_secret.is_empty() || cfg.client_secret == "***" {
                cfg.client_secret = d.oauth_config.client_secret.clone();
            }
            cfg.sync = stamp_acc(&mut d, &self.clock, &node, false);
            d.oauth_config = cfg.clone();
            Self::record(&mut d, &self.clock, &node, actor, "oauth.config", &cfg.issuer_url, &client.ip);
            (cfg, d.clone())
        };
        self.commit_snapshot(snap);
        Ok(out)
    }

    fn oauth_hmac_key(secret: &[u8]) -> ring::hmac::Key {
        let derived = sha256(&[b"fucf-oauth-state-v1:", secret].concat());
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &derived)
    }

    /// Seal stateless PKCE `code_verifier` + `state` + `nonce` into an HMAC-SHA256
    /// cookie value using the replicated `ClusterSecret`.
    pub fn seal_oauth_state(&self, code_verifier: &str, state: &str, nonce: &str) -> Result<String, AuthError> {
        let secret = self.cluster_secret_bytes();
        let claims = OAuthStateClaims {
            state: state.to_string(),
            nonce: nonce.to_string(),
            code_verifier: code_verifier.to_string(),
            exp: now() + 600,
        };
        let payload = b64(&serde_json::to_vec(&claims).unwrap_or_default());
        let tag = ring::hmac::sign(&Self::oauth_hmac_key(&secret), payload.as_bytes());
        Ok(format!("{payload}.{}", b64(tag.as_ref())))
    }

    /// Verify the stateless HMAC-SHA256 OAuth cookie and return `(code_verifier, nonce)`.
    pub fn verify_oauth_state(&self, cookie_val: &str, expected_state: &str) -> Result<(String, String), AuthError> {
        let secret = self.cluster_secret_bytes();
        let (payload, sig_b64) = cookie_val.split_once('.').ok_or_else(AuthError::expired)?;
        let sig = unb64(sig_b64).ok_or_else(AuthError::expired)?;
        ring::hmac::verify(&Self::oauth_hmac_key(&secret), payload.as_bytes(), &sig)
            .map_err(|_| AuthError::expired())?;
        let bytes = unb64(payload).ok_or_else(AuthError::expired)?;
        let claims: OAuthStateClaims = serde_json::from_slice(&bytes).map_err(|_| AuthError::expired())?;
        if claims.exp <= now() || !ct_eq(claims.state.as_bytes(), expected_state.as_bytes()) {
            return Err(AuthError::expired());
        }
        Ok((claims.code_verifier, claims.nonce))
    }

    /// Authenticate or auto-provision a user from an OAuth `/userinfo` email,
    /// issuing a replicated panel session.
    pub fn login_or_provision_oauth(&self, raw_email: &str, client: &Client) -> Result<(String, Value), AuthError> {
        self.check_writable()?;
        let email = normalize_email(raw_email)?;
        let node = self.sync_node();
        let mut d = self.data.lock().unwrap();
        let auto_provision = d.oauth_config.auto_provision;
        let default_role = d.oauth_config.default_role;
        let user_id = if let Some(u) = d.users.iter().find(|u| u.email == email) {
            if u.disabled {
                return Err(AuthError::disabled());
            }
            u.id.clone()
        } else {
            if !auto_provision {
                return Err(AuthError::new(403, 2005, "no panel account exists for this OAuth email"));
            }
            let id = hex(&random(8));
            let sync = stamp_acc(&mut d, &self.clock, &node, false);
            let random_pw = b64(&random(32));
            let user = User {
                id: id.clone(),
                email: email.clone(),
                role: default_role,
                disabled: false,
                password: PasswordHash::of(&random_pw),
                must_change_password: false,
                totp: None,
                backup_codes: Vec::new(),
                passkeys: Vec::new(),
                created_on: crate::store::rfc3339(now()),
                last_login_on: None,
                failed: 0,
                locked_until: 0,
                sync,
            };
            d.users.push(user);
            Self::record(&mut d, &self.clock, &node, &email, "user.create", format!("oauth ({})", default_role.name()), &client.ip);
            id
        };
        let (token, user_view) = Self::open_session(&mut d, &self.clock, &node, &user_id, "oauth", client);
        Self::record(&mut d, &self.clock, &node, &email, "login", "oauth", &client.ip);
        let snap = d.clone();
        drop(d);
        self.commit_snapshot(snap);
        Ok((token, user_view))
    }

    /// What happened lately, newest first.
    pub fn audit(&self) -> Vec<Value> {
        self.data.lock().unwrap().audit.iter().rev().map(|e| serde_json::to_value(e).unwrap_or_default()).collect()
    }
}

impl SyncProvider for Accounts {
    fn domain(&self) -> &'static str {
        "accounts"
    }

    fn current_rev(&self) -> u64 {
        self.data.lock().unwrap().local_rev
    }

    fn epoch(&self) -> String {
        self.data.lock().unwrap().epoch.clone()
    }

    fn export_since(&self, since_rev: u64, peer_epoch: Option<&str>) -> Result<DomainDelta, String> {
        let mut d = self.data.lock().unwrap().clone();
        gc_account_state(&mut d, now(), unix_ms());
        let full_resync = since_rev == 0 || peer_epoch != Some(d.epoch.as_str()) || since_rev < d.gc_floor_rev;
        let since = if full_resync { 0 } else { since_rev };
        let payload = AccountsDeltaPayload {
            cluster_secret: d.cluster_secret.clone(),
            oauth_config: (!d.oauth_config.sync.is_unset() && (full_resync || d.oauth_config.sync.local_rev > since))
                .then(|| d.oauth_config.clone()),
            users: d
                .users
                .iter()
                .filter(|u| full_resync || u.sync.local_rev > since || u.passkeys.iter().any(|p| p.sync.local_rev > since))
                .cloned()
                .collect(),
            sessions: d.sessions.iter().filter(|s| full_resync || s.sync.local_rev > since).cloned().collect(),
            audit: d.audit.iter().filter(|e| full_resync || e.sync.local_rev > since).cloned().collect(),
            deleted_users: d.deleted_users.iter().filter(|(_, m)| full_resync || m.local_rev > since).map(|(k, v)| (k.clone(), v.clone())).collect(),
            deleted_passkeys: d.deleted_passkeys.iter().filter(|(_, m)| full_resync || m.local_rev > since).map(|(k, v)| (k.clone(), v.clone())).collect(),
            deleted_sessions: d.deleted_sessions.iter().filter(|(_, m)| full_resync || m.local_rev > since).map(|(k, v)| (k.clone(), v.clone())).collect(),
            spent_jti: d
                .spent_jti
                .iter()
                .filter(|(jti, _)| full_resync || d.spent_jti_rev.get(*jti).copied().unwrap_or(0) > since)
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            ticket_wrong: d
                .ticket_wrong
                .iter()
                .filter(|(jti, _)| full_resync || d.ticket_wrong_rev.get(*jti).copied().unwrap_or(0) > since)
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        };
        Ok(DomainDelta {
            domain: "accounts".into(),
            epoch: d.epoch,
            from_rev: since,
            to_rev: d.local_rev,
            full_resync,
            payload: serde_json::to_value(&payload).map_err(|e| e.to_string())?,
        })
    }

    fn merge_delta(&self, delta: &DomainDelta, clock: &HlcClock) -> Result<bool, String> {
        let payload: AccountsDeltaPayload = serde_json::from_value(delta.payload.clone()).map_err(|e| e.to_string())?;
        let mut changed = false;
        let snap_opt = {
            let mut d = self.data.lock().unwrap();
            gc_account_state(&mut d, now(), unix_ms());

            if delta.full_resync && self.read_only.load(Ordering::Relaxed) {
                let u_ids: HashSet<String> = payload.users.iter().map(|u| u.id.clone()).collect();
                let s_ids: HashSet<String> = payload.sessions.iter().map(|s| s.id.clone()).collect();
                if d.users.len() != u_ids.len() || d.sessions.len() != s_ids.len() {
                    d.users.retain(|u| u_ids.contains(&u.id));
                    d.sessions.retain(|s| s_ids.contains(&s.id));
                    changed = true;
                }
            }

            if let Some(cs) = payload.cluster_secret {
                let take = match &d.cluster_secret {
                    None => true,
                    Some(cur) if cur.created_ms == 0 && cs.created_ms > 0 => true,
                    Some(cur) if cs.created_ms > 0 => cs.preferred_over(cur),
                    _ => false,
                };
                if take && d.cluster_secret.as_ref() != Some(&cs) {
                    d.cluster_secret = Some(cs);
                    changed = true;
                }
            }

            let mut rev = d.local_rev;
            let now_ms = crate::sync::clock::unix_ms();

            if let Some(mut oc) = payload.oauth_config {
                if oc.sync.updated_ms > 0 {
                    oc.sync.clamp_skew(now_ms);
                    clock.observe(oc.sync.updated_ms, oc.sync.seq);
                }
                if oc.sync.wins_over(&d.oauth_config.sync) {
                    rev = rev.saturating_add(1);
                    oc.sync.local_rev = rev;
                    d.oauth_config = oc;
                    changed = true;
                }
            }

            // Merge passkey tombstones first.
            for (pk_id, mut tomb) in payload.deleted_passkeys {
                tomb.deleted = true;
                if tomb.updated_ms > 0 {
                    tomb.clamp_skew(now_ms);
                    clock.observe(tomb.updated_ms, tomb.seq);
                }
                let cur = d.deleted_passkeys.get(&pk_id);
                if cur.is_none_or(|c| tomb.wins_over(c)) {
                    rev = rev.saturating_add(1);
                    tomb.local_rev = rev;
                    d.deleted_passkeys.insert(pk_id.clone(), tomb.clone());
                    for u in &mut d.users {
                        u.passkeys.retain(|p| !(p.id == pk_id && !p.sync.wins_over(&tomb)));
                    }
                    changed = true;
                }
            }

            // Merge users + per-passkey LWW + monotonic totp.last_step.
            for mut incoming in payload.users {
                if incoming.sync.updated_ms > 0 {
                    incoming.sync.clamp_skew(now_ms);
                    clock.observe(incoming.sync.updated_ms, incoming.sync.seq);
                }
                for p in &mut incoming.passkeys {
                    if p.sync.updated_ms > 0 {
                        p.sync.clamp_skew(now_ms);
                        clock.observe(p.sync.updated_ms, p.sync.seq);
                    }
                }
                if let Some(tomb) = d.deleted_users.get(&incoming.id) {
                    if !incoming.sync.wins_over(tomb) {
                        continue;
                    }
                    d.deleted_users.remove(&incoming.id);
                }
                if let Some(pos) = d.users.iter().position(|u| u.id == incoming.id) {
                    let local = &d.users[pos];
                    let incoming_wins = incoming.sync.wins_over(&local.sync);
                    let mut merged = if incoming_wins { incoming.clone() } else { local.clone() };
                    // Monotonic TOTP replay protection when same secret is active.
                    if let (Some(lt), Some(rt)) = (&local.totp, &incoming.totp) {
                        if lt.secret == rt.secret {
                            if let Some(mt) = &mut merged.totp {
                                mt.last_step = lt.last_step.max(rt.last_step);
                            }
                        }
                    }
                    // Per-passkey LWW merge (respecting deleted_passkeys tombstones & max sign_count).
                    let mut pk_map: BTreeMap<String, Passkey> = BTreeMap::new();
                    for p in local.passkeys.iter().chain(incoming.passkeys.iter()) {
                        if let Some(pk_tomb) = d.deleted_passkeys.get(&p.id) {
                            if !p.sync.wins_over(pk_tomb) {
                                continue;
                            }
                        }
                        match pk_map.get_mut(&p.id) {
                            Some(cur) => {
                                let max_sc = cur.sign_count.max(p.sign_count);
                                if p.sync.wins_over(&cur.sync) {
                                    *cur = p.clone();
                                    rev = rev.saturating_add(1);
                                    cur.sync.local_rev = rev;
                                }
                                cur.sign_count = max_sc;
                            }
                            None => {
                                let mut cp = p.clone();
                                if cp.sync.local_rev == 0 {
                                    rev = rev.saturating_add(1);
                                    cp.sync.local_rev = rev;
                                }
                                pk_map.insert(cp.id.clone(), cp);
                            }
                        }
                    }
                    let new_pks: Vec<Passkey> = pk_map.into_values().collect();
                    let pk_changed = new_pks.len() != local.passkeys.len()
                        || new_pks.iter().zip(local.passkeys.iter()).any(|(a, b)| a.id != b.id || a.sign_count != b.sign_count || a.sync != b.sync);
                    let totp_step_changed = merged.totp.as_ref().map(|t| t.last_step) != local.totp.as_ref().map(|t| t.last_step);
                    if incoming_wins || pk_changed || totp_step_changed {
                        merged.passkeys = new_pks;
                        if incoming_wins {
                            rev = rev.saturating_add(1);
                            merged.sync.local_rev = rev;
                        }
                        d.users[pos] = merged;
                        changed = true;
                    }
                } else {
                    incoming.passkeys.retain(|p| d.deleted_passkeys.get(&p.id).is_none_or(|t| p.sync.wins_over(t)));
                    rev = rev.saturating_add(1);
                    incoming.sync.local_rev = rev;
                    for p in &mut incoming.passkeys {
                        rev = rev.saturating_add(1);
                        p.sync.local_rev = rev;
                    }
                    d.users.push(incoming);
                    changed = true;
                }
            }

            // Deleted users
            for (uid, mut tomb) in payload.deleted_users {
                tomb.deleted = true;
                if tomb.updated_ms > 0 {
                    tomb.clamp_skew(now_ms);
                    clock.observe(tomb.updated_ms, tomb.seq);
                }
                let local_sync = d.users.iter().find(|u| u.id == uid).map(|u| &u.sync);
                let cur_best = local_sync.into_iter().chain(d.deleted_users.get(&uid)).max_by(|a, b| a.version_key().cmp(&b.version_key()));
                if cur_best.is_none_or(|b| tomb.wins_over(b)) {
                    rev = rev.saturating_add(1);
                    tomb.local_rev = rev;
                    d.users.retain(|u| u.id != uid);
                    d.sessions.retain(|s| s.user_id != uid);
                    d.deleted_users.insert(uid, tomb);
                    changed = true;
                }
            }

            // Natural-key collision resolution on User.email
            if d.users.len() > 1 {
                d.users.sort_by(|a, b| {
                    (b.sync.updated_ms, b.sync.seq, b.sync.node.as_str(), b.id.as_str())
                        .cmp(&(a.sync.updated_ms, a.sync.seq, a.sync.node.as_str(), a.id.as_str()))
                });
                let mut seen_emails = HashSet::new();
                let mut kept = Vec::with_capacity(d.users.len());
                let users_all = std::mem::take(&mut d.users);
                for u in users_all {
                    if seen_emails.insert(u.email.clone()) {
                        kept.push(u);
                    } else {
                        let mut tomb = u.sync.clone();
                        tomb.deleted = true;
                        rev = rev.saturating_add(1);
                        tomb.local_rev = rev;
                        d.deleted_users.insert(u.id, tomb);
                        changed = true;
                    }
                }
                d.users = kept;
            }

            // Merge sessions
            for mut s in payload.sessions {
                if s.sync.updated_ms > 0 {
                    s.sync.clamp_skew(now_ms);
                    clock.observe(s.sync.updated_ms, s.sync.seq);
                }
                if s.expires <= now() {
                    continue;
                }
                if d.deleted_sessions.get(&s.id).is_some_and(|t| !s.sync.wins_over(t)) {
                    continue;
                }
                if d.deleted_users.get(&s.user_id).is_some_and(|t| !s.sync.wins_over(t)) {
                    continue;
                }
                d.deleted_sessions.remove(&s.id);
                if let Some(pos) = d.sessions.iter().position(|cur| cur.id == s.id) {
                    let max_seen = d.sessions[pos].last_seen.max(s.last_seen);
                    if s.sync.wins_over(&d.sessions[pos].sync) {
                        rev = rev.saturating_add(1);
                        s.sync.local_rev = rev;
                        s.last_seen = max_seen;
                        d.sessions[pos] = s;
                        changed = true;
                    } else if max_seen > d.sessions[pos].last_seen {
                        d.sessions[pos].last_seen = max_seen;
                        changed = true;
                    }
                } else {
                    rev = rev.saturating_add(1);
                    s.sync.local_rev = rev;
                    d.sessions.push(s);
                    changed = true;
                }
            }
            for (sid, mut tomb) in payload.deleted_sessions {
                tomb.deleted = true;
                if tomb.updated_ms > 0 {
                    tomb.clamp_skew(now_ms);
                    clock.observe(tomb.updated_ms, tomb.seq);
                }
                let local_sync = d.sessions.iter().find(|s| s.id == sid).map(|s| &s.sync);
                let cur_best = local_sync.into_iter().chain(d.deleted_sessions.get(&sid)).max_by(|a, b| a.version_key().cmp(&b.version_key()));
                if cur_best.is_none_or(|b| tomb.wins_over(b)) {
                    rev = rev.saturating_add(1);
                    tomb.local_rev = rev;
                    d.sessions.retain(|s| s.id != sid);
                    d.deleted_sessions.insert(sid, tomb);
                    changed = true;
                }
            }

            // Merge audit log (union by id, sorted chronologically, capped at AUDIT_KEPT)
            let mut audit_added = false;
            let existing_ids: HashSet<String> = d.audit.iter().map(|e| e.id.clone()).collect();
            for mut e in payload.audit {
                if e.id.is_empty() {
                    let sig = sha256(format!("{}|{}|{}|{}|{}", e.at, e.actor, e.action, e.detail, e.ip).as_bytes());
                    e.id = hex(&sig[..16]);
                }
                if e.sync.updated_ms > 0 {
                    e.sync.clamp_skew(now_ms);
                    clock.observe(e.sync.updated_ms, e.sync.seq);
                }
                if !existing_ids.contains(&e.id) && !d.audit.iter().any(|cur| cur.id == e.id) {
                    rev = rev.saturating_add(1);
                    e.sync.local_rev = rev;
                    d.audit.push(e);
                    audit_added = true;
                    changed = true;
                }
            }
            if audit_added {
                d.audit.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.id.cmp(&b.id)));
                let excess = d.audit.len().saturating_sub(AUDIT_KEPT);
                d.audit.drain(..excess);
            }

            // Merge spent_jti & ticket_wrong
            let at = now();
            for (jti, exp) in payload.spent_jti {
                if exp > at && !d.spent_jti.contains_key(&jti) {
                    rev = rev.saturating_add(1);
                    d.spent_jti.insert(jti.clone(), exp);
                    d.spent_jti_rev.insert(jti.clone(), rev);
                    d.ticket_wrong.remove(&jti);
                    d.ticket_wrong_rev.remove(&jti);
                    changed = true;
                }
            }
            for (jti, (w, exp)) in payload.ticket_wrong {
                if exp > at && !d.spent_jti.contains_key(&jti) {
                    let cur = d.ticket_wrong.get(&jti).map(|(cw, _)| *cw).unwrap_or(0);
                    if w > cur {
                        rev = rev.saturating_add(1);
                        d.ticket_wrong.insert(jti.clone(), (w, exp));
                        d.ticket_wrong_rev.insert(jti, rev);
                        changed = true;
                    }
                }
            }

            d.local_rev = rev;
            if changed {
                Some(d.clone())
            } else {
                None
            }
        };
        if let Some(snap) = snap_opt {
            self.commit_snapshot(snap);
        }
        Ok(changed)
    }
}

/// Check a passkey's answer against the user's registered key, and note its use.
fn assert_passkey(user: &mut User, assertion: &Assertion, panel_host: Option<&str>, verified: bool) -> Result<(), AuthError> {
    let malformed = || AuthError::passkey("malformed passkey data");
    let raw_client = unb64(&assertion.client_data).ok_or_else(malformed)?;
    let raw_auth = unb64(&assertion.authenticator_data).ok_or_else(malformed)?;
    let signature = unb64(&assertion.signature).ok_or_else(malformed)?;
    let (_, rp) = client_data(&raw_client, "webauthn.get", panel_host)?;
    let passkey = user.passkeys.iter_mut().find(|p| p.id == assertion.id).ok_or_else(|| AuthError::passkey("this passkey does not belong to this account"))?;
    let count = authenticator_data(&raw_auth, &rp, verified)?;
    verify_signature(passkey.alg, &unb64(&passkey.key).ok_or_else(malformed)?, &raw_auth, &raw_client, &signature)?;
    // a counter that runs backwards means the passkey was copied
    if (count != 0 || passkey.sign_count != 0) && count <= passkey.sign_count {
        return Err(AuthError::passkey("the passkey's counter went backwards: it may have been copied"));
    }
    (passkey.sign_count, passkey.last_used_on) = (count, Some(crate::store::now()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn accounts() -> Accounts {
        let path = std::env::temp_dir().join(format!("fucf-accounts-{}.json", uuid::Uuid::new_v4().simple()));
        Accounts::open(path, Some("panel.example.net".into()))
    }

    fn client() -> Client {
        Client { ip: "198.51.100.7".into(), agent: "tests".into() }
    }

    fn principal(accounts: &Accounts, token: &str) -> Principal {
        accounts.session(token).unwrap()
    }

    fn sign_in(accounts: &Accounts, email: &str, password: &str) -> String {
        match accounts.login(email, password, &client()).unwrap() {
            Login::Session(token, _) => token,
            Login::SecondStep { .. } => panic!("a second step was asked for"),
        }
    }

    #[test]
    fn codes_and_encodings() {
        // RFC 6238, appendix B (SHA-1, the 8-digit values cut to 6)
        let secret = b"12345678901234567890";
        assert_eq!((totp_code(secret, 59 / 30), totp_code(secret, 1111111109 / 30), totp_code(secret, 2000000000 / 30)), ("287082".into(), "081804".into(), "279037".into()));
        assert_eq!(totp_step(secret, "287 082", 59), Some(1));
        assert_eq!(totp_step(secret, "287082", 59 + 30), Some(1), "the code of the step before is still taken");
        assert_eq!((totp_step(secret, "287082", 59 + 90), totp_step(secret, "28708", 59), totp_step(secret, "abcdef", 59)), (None, None, None));
        // RFC 4648
        assert_eq!((base32(b"foobar"), base32(b"fo"), base32(b"")), ("MZXW6YTBOI".into(), "MZXQ".into(), "".into()));
        assert_eq!(unbase32("mzxw6ytboi").as_deref(), Some(&b"foobar"[..]));
        assert_eq!((unbase32("MZXQ====").as_deref(), unbase32("M1")), (Some(&b"fo"[..]), None));
        let secret = random(20);
        assert_eq!(unbase32(&base32(&secret)), Some(secret));

        let code = backup_code();
        assert!(code.len() == 11 && code.as_bytes()[5] == b'-' && code != backup_code());
        assert_eq!(backup_digest(&code), backup_digest(&code.to_uppercase().replace('-', " ")));
        let password = random_password();
        assert!(password.len() == 20 && password != random_password() && check_password(&password, "a@b.c").is_ok());

        let hash = PasswordHash::of("correct horse");
        assert!(hash.matches("correct horse") && !hash.matches("correct horse ") && !hash.matches(""));
        assert_ne!(hash.hash, PasswordHash::of("correct horse").hash, "salted");
        assert!(check_password("short", "a@b.c").is_err() && check_password("A@B.c-long", "a@b.c-long").is_err());
        assert_eq!(normalize_email(" Admin@Example.COM ").unwrap(), "admin@example.com");
        for bad in ["", "admin", "admin@", "@example.com", "admin@localhost", "a b@example.com", "a@b@example.com", "a@.com"] {
            assert!(normalize_email(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn users_passwords_and_sessions() {
        let accounts = accounts();
        assert!(!accounts.initialized());
        // the first account, with a password of its owner's choosing
        let (first, generated) = accounts.create_user("Owner@Example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        assert!(accounts.initialized() && generated.is_none() && first["email"] == "owner@example.com" && first["must_change_password"] == false);
        assert_eq!(accounts.create_user("owner@example.com", Role::Viewer, None, "x", &client()).unwrap_err().code, 2013);
        assert!(accounts.create_user("not an address", Role::Viewer, None, "x", &client()).is_err());
        assert!(accounts.create_user("weak@example.com", Role::Viewer, Some("1234"), "x", &client()).is_err());

        let token = sign_in(&accounts, " owner@example.COM", "a good password");
        let owner = principal(&accounts, &token);
        assert!(owner.role == Role::Admin && owner.email == "owner@example.com" && owner.session_id.is_some());
        assert!(accounts.session("fucf_s_something-else").is_none() && accounts.session(&token[7..]).is_none());
        assert_eq!(accounts.login("owner@example.com", "wrong", &client()).unwrap_err(), AuthError::credentials());
        assert_eq!(accounts.login("nobody@example.com", "a good password", &client()).unwrap_err(), AuthError::credentials(), "nothing tells an unknown address from a wrong password");

        // a second user gets a made-up password, to be changed
        let (editor, generated) = accounts.create_user("editor@example.com", Role::Editor, None, &owner.email, &client()).unwrap();
        let generated = generated.unwrap();
        assert!(editor["must_change_password"] == true && generated.len() == 20);
        let editor_token = sign_in(&accounts, "editor@example.com", &generated);
        let editor_user = principal(&accounts, &editor_token);
        assert_eq!(accounts.change_password(&editor_user, "wrong", "another password", &client()).unwrap_err().code, 2014);
        assert!(accounts.change_password(&editor_user, &generated, "short", &client()).is_err());
        let second_session = sign_in(&accounts, "editor@example.com", &generated);
        accounts.change_password(&editor_user, &generated, "another password", &client()).unwrap();
        assert!(accounts.session(&editor_token).is_some() && accounts.session(&second_session).is_none(), "the other sessions end");
        assert!(accounts.login("editor@example.com", &generated, &client()).is_err());
        let me = accounts.me(editor_user.user_id.as_deref().unwrap(), editor_user.session_id.as_deref()).unwrap();
        assert!(me["must_change_password"] == false && me["sessions"].as_array().unwrap().len() == 1 && me["sessions"][0]["current"] == true && me["sessions"][0]["ip"] == "198.51.100.7");

        // wrong passwords lock the account for a while
        for _ in 0..FREE_ATTEMPTS - 1 {
            assert_eq!(accounts.login("editor@example.com", "guess", &client()).unwrap_err().code, 2001);
        }
        assert_eq!(accounts.login("editor@example.com", "another password", &client()).unwrap_err().code, 2002, "even the right password has to wait");
        // an administrator's reset lifts it, with a new made-up password
        let editor_id = editor["id"].as_str().unwrap();
        let (_, reset) = accounts.update_user(editor_id, None, None, true, false, &owner, &client()).unwrap();
        assert!(accounts.session(&editor_token).is_none(), "signed out by the reset");
        let editor_token = sign_in(&accounts, "editor@example.com", &reset.unwrap());

        // roles, disabling, deleting -- and the last administrator stays
        let owner_id = first["id"].as_str().unwrap();
        assert_eq!(accounts.update_user(owner_id, Some(Role::Viewer), None, false, false, &owner, &client()).unwrap_err().code, 2013);
        assert_eq!(accounts.delete_user(owner_id, &owner, &client()).unwrap_err().code, 2013);
        assert!(accounts.delete_user(owner_id, &principal(&accounts, &editor_token), &client()).is_err(), "the only administrator");
        let (changed, _) = accounts.update_user(editor_id, Some(Role::Viewer), Some(true), false, false, &owner, &client()).unwrap();
        assert!(changed["role"] == "viewer" && changed["disabled"] == true && accounts.session(&editor_token).is_none());
        assert_eq!(accounts.login("editor@example.com", "whatever it is", &client()).unwrap_err().code, 2001);
        accounts.delete_user(editor_id, &owner, &client()).unwrap();
        assert_eq!((accounts.users().len(), accounts.delete_user(editor_id, &owner, &client()).unwrap_err().code), (1, 2012));

        // sessions end by hand, and everything is still there after a restart
        let other = sign_in(&accounts, "owner@example.com", "a good password");
        let other_id = principal(&accounts, &other).session_id.unwrap();
        accounts.revoke_session(&owner, &other_id).unwrap();
        assert!(accounts.session(&other).is_none() && accounts.revoke_session(&owner, &other_id).is_err());
        let path = accounts.path.clone().unwrap();
        let reopened = Accounts::open(path.clone(), None);
        assert!(reopened.session(&token).is_some() && reopened.users().len() == 1);
        let actions: Vec<String> = reopened.audit().iter().map(|e| e["action"].as_str().unwrap().to_string()).collect();
        for expected in ["user.create", "login", "login.failed", "password.change", "user.update", "user.delete"] {
            assert!(actions.iter().any(|a| a == expected), "{expected} in {actions:?}");
        }
        let stored = std::fs::read_to_string(&path).unwrap();
        assert!(!stored.contains("a good password") && !stored.contains(&token), "neither passwords nor session tokens are stored");
        reopened.logout(owner.session_id.as_deref().unwrap());
        assert!(reopened.session(&token).is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn two_step_verification_and_backup_codes() {
        let accounts = accounts();
        accounts.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let owner = principal(&accounts, &sign_in(&accounts, "owner@example.com", "a good password"));
        let code_at = |secret: &str, offset: i64| totp_code(&unbase32(secret).unwrap(), ((now() + offset) / 30) as u64);

        // backup codes are a stand-in for the second step: none without it
        assert_eq!(accounts.backup_codes_regenerate(&owner, "a good password", &client()).unwrap_err().code, 2013);
        let (secret, uri) = accounts.totp_begin(&owner).unwrap();
        assert!(uri.starts_with("otpauth://totp/fucloudflare:owner%40example.com?secret=") && uri.contains(&secret) && uri.contains("issuer=fucloudflare"));
        // not in force until a code is shown
        assert!(matches!(accounts.login("owner@example.com", "a good password", &client()).unwrap(), Login::Session(..)));
        assert_eq!(accounts.totp_enable(&owner, "000000", &client()).unwrap_err().code, 2003);
        let codes = accounts.totp_enable(&owner, &code_at(&secret, 0), &client()).unwrap();
        assert!(codes.len() == 10 && codes.iter().collect::<std::collections::HashSet<_>>().len() == 10);
        assert!(accounts.totp_begin(&owner).is_err() && accounts.totp_enable(&owner, &code_at(&secret, 0), &client()).is_err());
        let me = accounts.me(owner.user_id.as_deref().unwrap(), None).unwrap();
        assert!(me["two_factor"] == true && me["backup_codes_left"] == 10);

        // now the password alone is not enough
        let ticket = || match accounts.login("owner@example.com", "a good password", &client()).unwrap() {
            Login::SecondStep { ticket, methods } => {
                assert_eq!(methods, ["totp", "backup_code"]);
                ticket
            }
            Login::Session(..) => panic!("signed in without the second step"),
        };
        let first = ticket();
        assert_eq!(accounts.second_step(&first, Proof::Totp("123456".into()), &client()).unwrap_err().code, 2003);
        // the code that switched it on was used; the next one works -- once
        assert!(accounts.second_step(&first, Proof::Totp(code_at(&secret, 0)), &client()).unwrap_err().message.contains("used already"));
        let (token, _) = accounts.second_step(&first, Proof::Totp(code_at(&secret, 30)), &client()).unwrap();
        assert!(accounts.session(&token).is_some());
        assert_eq!(accounts.second_step(&first, Proof::Totp(code_at(&secret, 30)), &client()).unwrap_err().code, 2004, "a ticket is for one login");
        assert!(accounts.second_step(&ticket(), Proof::Totp(code_at(&secret, 30)), &client()).is_err(), "and a code for one, too");

        // a backup code works instead, once, in any spelling
        let (token, _) = accounts.second_step(&ticket(), Proof::BackupCode(codes[3].to_uppercase().replace('-', "")), &client()).unwrap();
        assert!(accounts.session(&token).is_some());
        assert_eq!(accounts.second_step(&ticket(), Proof::BackupCode(codes[3].clone()), &client()).unwrap_err().code, 2003);
        assert_eq!(accounts.me(owner.user_id.as_deref().unwrap(), None).unwrap()["backup_codes_left"], 9);

        // new codes at any time: the old ones are void
        assert_eq!(accounts.backup_codes_regenerate(&owner, "wrong", &client()).unwrap_err().code, 2014);
        let fresh = accounts.backup_codes_regenerate(&owner, "a good password", &client()).unwrap();
        assert!(fresh.len() == 10 && !fresh.contains(&codes[0]));
        assert!(accounts.second_step(&ticket(), Proof::BackupCode(codes[0].clone()), &client()).is_err());
        assert!(accounts.second_step(&ticket(), Proof::BackupCode(fresh[9].clone()), &client()).is_ok());
        let stored = std::fs::read_to_string(accounts.path.as_ref().unwrap()).unwrap();
        assert!(fresh.iter().all(|code| !stored.contains(code.as_str())), "backup codes are stored as digests");

        // too many wrong codes on one ticket: the ticket dies and the account is locked
        let stubborn = ticket();
        for attempt in 0..FREE_ATTEMPTS {
            let code = accounts.second_step(&stubborn, Proof::BackupCode("aaaaa-aaaaa".into()), &client()).unwrap_err().code;
            assert_eq!(code, if attempt + 1 < FREE_ATTEMPTS { 2003 } else { 2002 });
        }
        assert_eq!(accounts.second_step(&stubborn, Proof::BackupCode(fresh[0].clone()), &client()).unwrap_err().code, 2004);
        assert_eq!(accounts.login("owner@example.com", "a good password", &client()).unwrap_err().code, 2002);

        // switched off (and unlocked after reset), the password is enough again and the codes are gone
        assert!(accounts.two_factor_disable(&owner, "wrong", &client()).is_err());
        accounts.two_factor_disable(&owner, "a good password", &client()).unwrap();
        assert_eq!(accounts.me(owner.user_id.as_deref().unwrap(), None).unwrap()["two_factor"], false);
        std::fs::remove_file(accounts.path.as_ref().unwrap()).ok();
    }

    /// A passkey as an authenticator holds it: a P-256 key and a counter.
    struct Authenticator {
        key: EcdsaKeyPair,
        id: String,
        count: u32,
    }

    impl Authenticator {
        fn new() -> Authenticator {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            Authenticator { key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap(), id: b64(&random(16)), count: 0 }
        }

        fn spki(&self) -> String {
            let mut der = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
            der.extend_from_slice(self.key.public_key().as_ref());
            b64(&der)
        }

        fn data(&mut self, rp: &str, flags: u8) -> Vec<u8> {
            self.count += 1;
            let mut data = sha256(rp.as_bytes()).to_vec();
            data.push(flags);
            data.extend_from_slice(&self.count.to_be_bytes());
            data
        }

        fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
            json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false }).to_string().into_bytes()
        }

        fn rp(origin: &str) -> String {
            origin.split("://").nth(1).unwrap().split(':').next().unwrap().to_string()
        }

        fn register(&mut self, challenge: &str, origin: &str) -> Registration {
            Registration {
                id: self.id.clone(),
                public_key: self.spki(),
                alg: -7,
                client_data: b64(&Self::client_data("webauthn.create", challenge, origin)),
                authenticator_data: b64(&self.data(&Self::rp(origin), 0x45)),
                name: "laptop".into(),
            }
        }

        fn assert(&mut self, challenge: &str, origin: &str, flags: u8) -> Assertion {
            let (client, auth) = (Self::client_data("webauthn.get", challenge, origin), self.data(&Self::rp(origin), flags));
            let mut signed = auth.clone();
            signed.extend_from_slice(&sha256(&client));
            let signature = self.key.sign(&ring::rand::SystemRandom::new(), &signed).unwrap();
            Assertion { id: self.id.clone(), client_data: b64(&client), authenticator_data: b64(&auth), signature: b64(signature.as_ref()) }
        }
    }

    #[test]
    fn passkeys() {
        const ORIGIN: &str = "https://panel.example.net";
        let accounts = accounts();
        accounts.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let owner = principal(&accounts, &sign_in(&accounts, "owner@example.com", "a good password"));
        let mut key = Authenticator::new();

        assert_eq!(relying_party(ORIGIN, Some("panel.example.net")).as_deref(), Some("panel.example.net"));
        assert_eq!(relying_party("http://localhost:8787", None).as_deref(), Some("localhost"));
        for elsewhere in ["https://evil.example", "http://panel.example.net", "https://panel.example.net.evil.example", "http://127.0.0.1:8787", "panel.example.net"] {
            assert_eq!(relying_party(elsewhere, Some("panel.example.net")), None, "{elsewhere}");
        }

        // registering: our challenge, our origin, once
        let options = accounts.passkey_register_begin(&owner).unwrap();
        let challenge = options["challenge"].as_str().unwrap().to_string();
        assert!(options["user"]["name"] == "owner@example.com" && options["exclude"].as_array().unwrap().is_empty());
        assert_eq!(accounts.passkey_register(&owner, &key.register(&challenge, "https://evil.example"), &client()).unwrap_err().code, 2008);
        assert_eq!(accounts.passkey_register(&owner, &key.register("made-up", ORIGIN), &client()).unwrap_err().code, 2004);
        let added = accounts.passkey_register(&owner, &key.register(&challenge, ORIGIN), &client()).unwrap();
        assert_eq!(added["name"], "laptop");
        assert_eq!(accounts.passkey_register(&owner, &key.register(&challenge, ORIGIN), &client()).unwrap_err().code, 2004, "a challenge is for one ceremony");
        let again = accounts.passkey_register_begin(&owner).unwrap();
        assert_eq!(again["exclude"], json!([key.id]));
        assert_eq!(accounts.passkey_register(&owner, &key.register(again["challenge"].as_str().unwrap(), ORIGIN), &client()).unwrap_err().code, 2013);

        // signing in with it alone: it has to have verified its user
        let challenge = accounts.passkey_login_begin();
        assert!(accounts.passkey_login(&key.assert(&challenge, ORIGIN, 0x01), &client()).unwrap_err().message.contains("verify its user"));
        let challenge = accounts.passkey_login_begin();
        let (token, user) = accounts.passkey_login(&key.assert(&challenge, ORIGIN, 0x05), &client()).unwrap();
        assert!(user["email"] == "owner@example.com" && accounts.session(&token).is_some());
        let me = accounts.me(owner.user_id.as_deref().unwrap(), None).unwrap();
        assert!(me["passkey_list"][0]["last_used_on"].is_string() && me["sessions"].as_array().unwrap().iter().any(|s| s["method"] == "passkey"));
        // a signature cannot be moved to other data, an answer cannot be replayed, a stranger's passkey is nobody's
        let challenge = accounts.passkey_login_begin();
        let good = key.assert(&challenge, ORIGIN, 0x05);
        let mut tampered = good.clone();
        tampered.authenticator_data = b64(&key.data("panel.example.net", 0x05));
        assert!(accounts.passkey_login(&tampered, &client()).unwrap_err().message.contains("signature"));
        assert_eq!(accounts.passkey_login(&good, &client()).unwrap_err().code, 2004, "the challenge went with the failed attempt");
        let challenge = accounts.passkey_login_begin();
        assert!(accounts.passkey_login(&Authenticator::new().assert(&challenge, ORIGIN, 0x05), &client()).unwrap_err().message.contains("not registered"));
        // a counter that runs backwards
        let challenge = accounts.passkey_login_begin();
        key.count = 0;
        assert!(accounts.passkey_login(&key.assert(&challenge, ORIGIN, 0x05), &client()).unwrap_err().message.contains("backwards"));
        key.count = 50;

        // as the second step after the password
        let (secret, _) = accounts.totp_begin(&owner).unwrap();
        accounts.totp_enable(&owner, &totp_code(&unbase32(&secret).unwrap(), (now() / 30) as u64), &client()).unwrap();
        let Login::SecondStep { ticket, methods } = accounts.login("owner@example.com", "a good password", &client()).unwrap() else { panic!() };
        assert_eq!(methods, ["totp", "backup_code", "passkey"]);
        assert!(accounts.second_step(&ticket, Proof::Passkey(key.assert("another-challenge", ORIGIN, 0x01)), &client()).is_err());
        let (token, _) = accounts.second_step(&ticket, Proof::Passkey(key.assert(&ticket, ORIGIN, 0x01)), &client()).unwrap();
        assert!(accounts.session(&token).is_some());

        // removed, it opens nothing
        accounts.passkey_delete(&owner, &key.id, &client()).unwrap();
        assert!(accounts.passkey_delete(&owner, &key.id, &client()).is_err());
        let challenge = accounts.passkey_login_begin();
        assert!(accounts.passkey_login(&key.assert(&challenge, ORIGIN, 0x05), &client()).is_err());
        std::fs::remove_file(accounts.path.as_ref().unwrap()).ok();
    }

    #[test]
    fn second_step_failures_lock_the_account() {
        let accounts = accounts();
        accounts.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let owner = principal(&accounts, &sign_in(&accounts, "owner@example.com", "a good password"));
        let (secret, _) = accounts.totp_begin(&owner).unwrap();
        accounts.totp_enable(&owner, &totp_code(&unbase32(&secret).unwrap(), (now() / 30) as u64), &client()).unwrap();
        // even fetching a fresh ticket each time must not bypass lockout
        for attempt in 0..FREE_ATTEMPTS {
            let Login::SecondStep { ticket, .. } = accounts.login("owner@example.com", "a good password", &client()).unwrap() else { panic!() };
            let err = accounts.second_step(&ticket, Proof::Totp("000000".into()), &client()).unwrap_err();
            if attempt + 1 < FREE_ATTEMPTS {
                assert_eq!(err.code, 2003);
            } else {
                assert_eq!(err.code, 2002);
            }
        }
        assert_eq!(accounts.login("owner@example.com", "a good password", &client()).unwrap_err().code, 2002);
        std::fs::remove_file(accounts.path.as_ref().unwrap()).ok();
    }

    #[test]
    fn accounts_sync_users_passkeys_sessions_audit() {
        const ORIGIN: &str = "https://panel.example.net";
        let a = accounts();
        a.set_sync_identity(Arc::new(HlcClock::default()), "au".into());
        a.set_api_token_secret("shared-token");
        let b = accounts();
        b.set_sync_identity(Arc::new(HlcClock::default()), "eu".into());
        b.set_api_token_secret("shared-token");

        a.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let tok_a = sign_in(&a, "owner@example.com", "a good password");
        let owner_a = principal(&a, &tok_a);
        let mut key = Authenticator::new();
        let reg_opts = a.passkey_register_begin(&owner_a).unwrap();
        let reg_chal = reg_opts["challenge"].as_str().unwrap();
        a.passkey_register(&owner_a, &key.register(reg_chal, ORIGIN), &client()).unwrap();

        let (totp_secret, _) = a.totp_begin(&owner_a).unwrap();
        let step0 = totp_code(&unbase32(&totp_secret).unwrap(), (now() / 30) as u64);
        a.totp_enable(&owner_a, &step0, &client()).unwrap();

        // Sync A -> B
        let delta = a.export_since(0, None).unwrap();
        assert!(b.merge_delta(&delta, &b.clock).unwrap());
        assert!(b.session(&tok_a).is_some(), "session opened on A works on B");

        // Passkey login works on B
        let ch_b = b.passkey_login_begin();
        let (tok_b, _) = b.passkey_login(&key.assert(&ch_b, ORIGIN, 0x05), &client()).unwrap();
        assert!(b.session(&tok_b).is_some());

        // TOTP step used on A is rejected on B
        let Login::SecondStep { ticket, .. } = b.login("owner@example.com", "a good password", &client()).unwrap() else { panic!() };
        assert!(b.second_step(&ticket, Proof::Totp(step0), &client()).unwrap_err().message.contains("used already"));

        // Logout & passkey delete on B sync back to A
        b.logout(owner_a.session_id.as_deref().unwrap());
        b.passkey_delete(&owner_a, &key.id, &client()).unwrap();
        let delta_b = b.export_since(0, None).unwrap();
        assert!(a.merge_delta(&delta_b, &a.clock).unwrap());
        assert!(a.session(&tok_a).is_none());
        assert!(a.session(&tok_b).is_some());
        assert_eq!(a.users()[0]["passkeys"], 0);

        // Audit merged cleanly without duplicates
        let len_a = a.audit().len();
        assert!(!a.merge_delta(&delta_b, &a.clock).unwrap());
        assert_eq!(a.audit().len(), len_a);

        std::fs::remove_file(a.path.as_ref().unwrap()).ok();
        std::fs::remove_file(b.path.as_ref().unwrap()).ok();
    }

    #[test]
    fn stateless_cross_node_2fa_and_passkey_ceremonies() {
        const ORIGIN: &str = "https://panel.example.net";
        let a = accounts();
        a.set_sync_identity(Arc::new(HlcClock::default()), "au".into());
        a.set_api_token_secret("cluster-secret-shared");
        let b = accounts();
        b.set_sync_identity(Arc::new(HlcClock::default()), "eu".into());
        b.set_api_token_secret("cluster-secret-shared");

        a.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let tok = sign_in(&a, "owner@example.com", "a good password");
        let owner = principal(&a, &tok);
        let (totp_secret, _) = a.totp_begin(&owner).unwrap();
        let step0 = totp_code(&unbase32(&totp_secret).unwrap(), (now() / 30) as u64);
        a.totp_enable(&owner, &step0, &client()).unwrap();

        // Sync initial user+totp+session to B BEFORE starting ceremonies
        b.merge_delta(&a.export_since(0, None).unwrap(), &b.clock).unwrap();

        // 1. Cross-node passkey registration: begin on A -> finish on B (zero pending sync!)
        let opts = a.passkey_register_begin(&owner).unwrap();
        let ch = opts["challenge"].as_str().unwrap().to_string();
        assert!(ch.starts_with(PENDING_PREFIX));
        let mut key = Authenticator::new();
        b.passkey_register(&owner, &key.register(&ch, ORIGIN), &client()).unwrap();
        // Sync spent_jti to A and verify replay on A fails
        a.merge_delta(&b.export_since(0, None).unwrap(), &a.clock).unwrap();
        assert_eq!(a.passkey_register(&owner, &key.register(&ch, ORIGIN), &client()).unwrap_err().code, 2004);

        // 2. Cross-node 2FA login: login on A -> second_step on B
        let Login::SecondStep { ticket, .. } = a.login("owner@example.com", "a good password", &client()).unwrap() else { panic!() };
        let next_step = totp_code(&unbase32(&totp_secret).unwrap(), (now() / 30) as u64 + 1);
        let (sess_from_b, _) = b.second_step(&ticket, Proof::Totp(next_step.clone()), &client()).unwrap();
        assert!(b.session(&sess_from_b).is_some());
        a.merge_delta(&b.export_since(0, None).unwrap(), &a.clock).unwrap();
        assert_eq!(a.second_step(&ticket, Proof::Totp(next_step), &client()).unwrap_err().code, 2004);

        // 3. Cross-node passkey sign-in: begin on A -> failed signature on B -> replay fails
        let login_ch = a.passkey_login_begin();
        let good = key.assert(&login_ch, ORIGIN, 0x05);
        let mut bad = good.clone();
        bad.authenticator_data = b64(&key.data("panel.example.net", 0x05));
        assert!(b.passkey_login(&bad, &client()).unwrap_err().message.contains("signature"));
        assert_eq!(b.passkey_login(&good, &client()).unwrap_err().code, 2004);

        std::fs::remove_file(a.path.as_ref().unwrap()).ok();
        std::fs::remove_file(b.path.as_ref().unwrap()).ok();
    }

    #[tokio::test]
    async fn coalesced_session_persistence_nonblocking() {
        let acc = Arc::new(accounts());
        acc.spawn_writer();
        acc.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let tok = sign_in(&acc, "owner@example.com", "a good password");

        // Trigger 100 rapid stale last_seen updates via session()
        for i in 0..100i64 {
            {
                let mut d = acc.data.lock().unwrap();
                d.sessions[0].last_seen = now() - 400 - i;
            }
            assert!(acc.session(&tok).is_some());
        }
        // Wait briefly for coalesced background writer to catch up
        for _ in 0..40 {
            if acc.writer.persisted_gen.load(Ordering::Acquire) >= acc.writer.dirty_gen.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        acc.flush_blocking();
        let path = acc.path.clone().unwrap();
        let reopened = Accounts::open(path.clone(), None);
        assert!(reopened.session(&tok).is_some());
        let expected_last_seen = acc.data.lock().unwrap().sessions[0].last_seen;
        assert_eq!(reopened.data.lock().unwrap().sessions[0].last_seen, expected_last_seen);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn ephemeral_accounts_writes_no_files() {
        let peer = accounts();
        peer.set_api_token_secret("tok");
        peer.create_user("owner@example.com", Role::Admin, Some("a good password"), "owner@example.com", &client()).unwrap();
        let tok = sign_in(&peer, "owner@example.com", "a good password");

        let accel = Accounts::open_ephemeral(None);
        assert_eq!(accel.create_user("x@example.com", Role::Viewer, Some("a good password"), "x", &client()).unwrap_err().status, 409);
        accel.merge_delta(&peer.export_since(0, None).unwrap(), &accel.clock).unwrap();
        assert!(accel.session(&tok).is_some());
        assert!(accel.path.is_none());
        std::fs::remove_file(peer.path.as_ref().unwrap()).ok();
    }
}
