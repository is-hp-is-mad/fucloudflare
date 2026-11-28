//! Leaked credential checks: the rule field
//! `cf.waf.credential_check.password_leaked`.
//!
//! The password of a login request is hashed with SHA-1 and looked up in a
//! table of hashes of leaked passwords that the operator keeps in a local
//! file (`--leaked-passwords`). Nothing is asked of any other server while a
//! request waits. The edge does nothing with the answer by itself: the
//! zone's own rules decide, a firewall rule blocking or challenging, a
//! transform rule adding a request header for the origin to act on.
//!
//! # The table file
//!
//! One SHA-1 hash per line, in hexadecimal (either case):
//!
//! ```text
//! # comments and empty lines are skipped
//! 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
//! 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493
//! 5baa61e4c9b93f3f
//! ```
//!
//! A line is either the whole hash (40 digits), as in the downloadable
//! Pwned Passwords files of Have I Been Pwned (`HASH:COUNT`, the count is
//! read past), or the first [`PREFIX_HEX`] digits of it. Only those first 64
//! bits are kept and compared: eight bytes an entry in memory, in one sorted
//! array searched by halving. With the table's [`MAX_ENTRIES`] the chance
//! that an unrelated password matches is about one in a trillion. Shorter
//! prefixes (such as the five digits of the k-anonymity range queries) are
//! refused: each would mark a millionth of all passwords as leaked. So are
//! other lengths, so that a file of NTLM hashes (32 digits) is not mistaken
//! for one of SHA-1 hashes.
//!
//! A file of more than [`MAX_FILE_BYTES`] bytes or [`MAX_ENTRIES`] entries,
//! or with one line that is not as above (or longer than 128 bytes, comments
//! included), is refused whole: at start the
//! process does not start, later the table loaded before stays. A partial
//! table would miss leaked passwords without anybody noticing. The full
//! Pwned Passwords list is far larger than the cap; use a part of it, such
//! as the most common passwords (the lines with the highest counts).
//!
//! The file is looked at again every minute and loaded anew when its
//! modification time or size changed (the way crate::edge::certdir follows
//! certificate files).
//!
//! # Which requests are checked
//!
//! Zones opt in with the setting `leaked_credential_checks`
//! ([`CredentialCheckSettings`]). A request is checked when it is a POST,
//! PUT or PATCH, its path is one of the zone's `paths` (any path when there
//! are none), and its body, which the edge already holds whole (at most
//! crate::edge::INSPECT_LIMIT bytes; a body still streaming is never read
//! for this), carries a password field and, unless the zone lists no
//! username fields, a username field:
//!
//! - `application/x-www-form-urlencoded`: the fields by name;
//! - JSON: the keys of the top-level object, or else of one object nested
//!   in it (`{"user": {"email": ..., "password": ...}}`); the username and
//!   the password come from the same object and are strings.
//!
//! Field names are compared without regard to case. Encoded bodies
//! (`Content-Encoding`) and other types (multipart forms) are not checked.
//! Paths are compared percent-decoded and without regard to case, with
//! `\` read as `/`, empty and `.` segments dropped, `..` taking away the one
//! before and `;params` cut from each segment, so that the ways origins read
//! a path the same do not let a request walk past the check.
//!
//! # What is never kept
//!
//! The password, its hash and the hash's prefix are not logged, traced,
//! written to the request log or security events, or kept on the request
//! (crate::expr::ReqInfo holds one boolean). The decoded password lives in a
//! buffer only while it is hashed, and the parsed body only while it is
//! looked at.

use super::ReqBody;
use crate::expr::ReqInfo;
use crate::store::StoreError;
use hyper::header::{self, HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

/// Hex digits of a hash that are kept and compared.
pub const PREFIX_HEX: usize = 16;
const PREFIX_BYTES: usize = PREFIX_HEX / 2;
/// Hex digits of a whole SHA-1 hash.
const FULL_HEX: usize = 40;
/// Largest table file.
pub const MAX_FILE_BYTES: u64 = 1 << 30;
/// Most entries of a table (80 MB in memory; twice that while a new table
/// replaces the old one).
pub const MAX_ENTRIES: usize = 10_000_000;
/// Longest line of a table file: a hash, a count and a few spaces.
const MAX_LINE: usize = 128;
/// Longer passwords are not looked up (leaked lists hold no such thing).
pub const MAX_PASSWORD: usize = 1024;
/// Passwords looked up for one request (`password=a&password=b&pass=c`...).
const MAX_CANDIDATES: usize = 8;
/// Limits of a zone's settings.
pub const MAX_PATHS: usize = 32;
const MAX_PATH_LEN: usize = 256;
pub const MAX_FIELDS: usize = 16;
const MAX_FIELD_LEN: usize = 64;
/// What a login form calls its fields, unless the zone says otherwise.
pub const DEFAULT_USERNAME_FIELDS: [&str; 4] = ["username", "email", "user", "login"];
pub const DEFAULT_PASSWORD_FIELDS: [&str; 3] = ["password", "pass", "passwd"];

type Prefix = [u8; PREFIX_BYTES];

fn invalid<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::Invalid(msg.into()))
}

// ----------------------------------------------------------- the table ----

/// The leaked password hashes, as their first [`PREFIX_BYTES`] bytes,
/// sorted and without duplicates.
#[derive(Default)]
pub struct Table {
    prefixes: Vec<Prefix>,
}

/// Only the size: the entries themselves are not for logs.
impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Table({} entries)", self.prefixes.len())
    }
}

/// Why a table file was refused. Line numbers only, never a line's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Io(String),
    TooLarge,
    TooManyEntries,
    BadLine(usize),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "cannot read the file: {e}"),
            LoadError::TooLarge => write!(f, "the file is larger than {MAX_FILE_BYTES} bytes"),
            LoadError::TooManyEntries => write!(f, "the file has more than {MAX_ENTRIES} entries"),
            LoadError::BadLine(n) => write!(
                f,
                "line {n} is not a SHA-1 hash in hexadecimal ({FULL_HEX} digits, optionally followed by :count) or its first {PREFIX_HEX} digits"
            ),
        }
    }
}

/// The value of one hex digit.
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The entry a line gives: `Ok(None)` for a comment or an empty line.
fn parse_line(line: &[u8]) -> Result<Option<Prefix>, ()> {
    let line = line.trim_ascii();
    if line.is_empty() || line[0] == b'#' {
        return Ok(None);
    }
    let (hash, count) = match line.iter().position(|&b| b == b':') {
        Some(at) => (line[..at].trim_ascii(), Some(line[at + 1..].trim_ascii())),
        None => (line, None),
    };
    if count.is_some_and(|c| c.is_empty() || !c.iter().all(u8::is_ascii_digit)) {
        return Err(());
    }
    // a count goes with a whole hash, as in the Pwned Passwords files
    let whole = hash.len() == FULL_HEX;
    if !(whole || (hash.len() == PREFIX_HEX && count.is_none())) {
        return Err(());
    }
    let mut digits = hash.iter().map(|&b| hex_value(b));
    if digits.clone().any(|d| d.is_none()) {
        return Err(());
    }
    let mut out = [0u8; PREFIX_BYTES];
    for byte in &mut out {
        let (hi, lo) = (digits.next().flatten().ok_or(())?, digits.next().flatten().ok_or(())?);
        *byte = hi << 4 | lo;
    }
    Ok(Some(out))
}

/// The first bytes of a password's SHA-1 hash.
fn prefix_of(password: &[u8]) -> Prefix {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, password);
    let mut out = [0u8; PREFIX_BYTES];
    out.copy_from_slice(&digest.as_ref()[..PREFIX_BYTES]);
    out
}

impl Table {
    /// Read a table file's lines. More than [`MAX_FILE_BYTES`] bytes or
    /// [`MAX_ENTRIES`] entries, or one line of the wrong form, refuses it all.
    pub fn read(reader: impl BufRead) -> Result<Table, LoadError> {
        Table::read_capped(reader, MAX_ENTRIES)
    }

    fn read_capped(mut reader: impl BufRead, max_entries: usize) -> Result<Table, LoadError> {
        let mut prefixes = Vec::new();
        let mut line = Vec::with_capacity(MAX_LINE + 1);
        let (mut number, mut total) = (0usize, 0u64);
        loop {
            line.clear();
            // a line is read at most MAX_LINE + 1 bytes at a time, so a file
            // without line breaks cannot take more memory than that
            let n = (&mut reader).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line).map_err(|e| LoadError::Io(e.kind().to_string()))?;
            if n == 0 {
                break;
            }
            number += 1;
            total += n as u64;
            if total > MAX_FILE_BYTES {
                return Err(LoadError::TooLarge);
            }
            if line.len() > MAX_LINE && line.last() != Some(&b'\n') {
                return Err(LoadError::BadLine(number));
            }
            match parse_line(&line) {
                Ok(None) => {}
                Ok(Some(p)) if prefixes.len() < max_entries => prefixes.push(p),
                Ok(Some(_)) => return Err(LoadError::TooManyEntries),
                Err(()) => return Err(LoadError::BadLine(number)),
            }
        }
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes.shrink_to_fit();
        Ok(Table { prefixes })
    }

    /// Read a table file from disk.
    pub fn load(path: &Path) -> Result<Table, LoadError> {
        let file = std::fs::File::open(path).map_err(|e| LoadError::Io(e.kind().to_string()))?;
        let size = file.metadata().map_err(|e| LoadError::Io(e.kind().to_string()))?.len();
        if size > MAX_FILE_BYTES {
            return Err(LoadError::TooLarge);
        }
        Table::read(BufReader::with_capacity(1 << 16, file))
    }

    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    /// Whether the password's hash is in the table.
    pub fn holds(&self, password: &[u8]) -> bool {
        !self.prefixes.is_empty() && self.prefixes.binary_search(&prefix_of(password)).is_ok()
    }
}

/// What the file was like when it was last looked at.
type Stamp = Option<(Option<SystemTime>, u64)>;

fn stamp(path: &Path) -> Stamp {
    std::fs::metadata(path).ok().map(|m| (m.modified().ok(), m.len()))
}

/// The table of this node, following its file (`--leaked-passwords`).
pub struct LeakedPasswords {
    path: PathBuf,
    table: RwLock<Arc<Table>>,
    seen: Mutex<Stamp>,
}

impl std::fmt::Debug for LeakedPasswords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LeakedPasswords({}, {} entries)", self.path.display(), self.entries())
    }
}

impl LeakedPasswords {
    /// Load the file; a file that cannot be used is an error (the process
    /// should not start with a check that silently finds nothing).
    pub fn open(path: &Path) -> Result<Arc<Self>, LoadError> {
        let seen = stamp(path);
        let table = Table::load(path)?;
        Ok(Arc::new(LeakedPasswords { path: path.to_path_buf(), table: RwLock::new(Arc::new(table)), seen: Mutex::new(seen) }))
    }

    pub fn entries(&self) -> usize {
        self.table.read().unwrap().len()
    }

    /// Whether the password's hash is in the table.
    pub fn holds(&self, password: &[u8]) -> bool {
        let table = self.table.read().unwrap().clone();
        table.holds(password)
    }

    /// Load the file again if its modification time or size changed:
    /// `None` when it did not, else the entries of the new table or why the
    /// old one stays. A file that cannot be used is reported once, not every
    /// minute until it changes again.
    pub fn reload_if_changed(&self) -> Option<Result<usize, LoadError>> {
        let now = stamp(&self.path);
        {
            let mut seen = self.seen.lock().unwrap();
            if *seen == now {
                return None;
            }
            *seen = now;
        }
        if now.is_none() {
            return Some(Err(LoadError::Io("the file is gone".into())));
        }
        Some(Table::load(&self.path).map(|table| {
            let n = table.len();
            *self.table.write().unwrap() = Arc::new(table);
            n
        }))
    }

    /// Follow the file: look at it every minute.
    pub async fn watch(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let me = self.clone();
            match tokio::task::spawn_blocking(move || me.reload_if_changed()).await {
                Ok(Some(Ok(n))) => tracing::info!("leaked password table {}: {n} entries", self.path.display()),
                Ok(Some(Err(e))) => tracing::warn!("leaked password table {}: {e}; the table loaded before stays", self.path.display()),
                _ => {}
            }
        }
    }
}

// ------------------------------------------------------- zone settings ----

/// The zone setting `leaked_credential_checks`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialCheckSettings {
    /// Look up the passwords of the zone's login requests.
    pub enabled: bool,
    /// The login paths (`/login`), or path prefixes ending in `*`
    /// (`/api/auth/*`); none: every path.
    pub paths: Vec<String>,
    /// A request is a login when it has one of these fields too; none: a
    /// password field alone will do.
    pub username_fields: Vec<String>,
    /// The fields whose values are looked up.
    pub password_fields: Vec<String>,
}

impl Default for CredentialCheckSettings {
    fn default() -> Self {
        CredentialCheckSettings {
            enabled: false,
            paths: Vec::new(),
            username_fields: DEFAULT_USERNAME_FIELDS.iter().map(|s| s.to_string()).collect(),
            password_fields: DEFAULT_PASSWORD_FIELDS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl CredentialCheckSettings {
    /// Checked as part of the zone's settings, whichever way they are written.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.paths.len() > MAX_PATHS {
            return invalid(format!("leaked_credential_checks.paths holds at most {MAX_PATHS} paths"));
        }
        for p in &self.paths {
            let star = p.find('*');
            if !p.starts_with('/')
                || p.len() > MAX_PATH_LEN
                || !p.bytes().all(|b| (0x21..0x7f).contains(&b))
                || p.contains(['?', '#'])
                || star.is_some_and(|at| at != p.len() - 1)
            {
                return invalid(format!(
                    "leaked_credential_checks.paths: '{}' is not a path like /login, or a prefix like /api/auth/* (at most {MAX_PATH_LEN} bytes, no spaces, ? or #, * only at the end)",
                    p.escape_debug()
                ));
            }
        }
        for (what, fields) in [("username_fields", &self.username_fields), ("password_fields", &self.password_fields)] {
            if fields.len() > MAX_FIELDS {
                return invalid(format!("leaked_credential_checks.{what} holds at most {MAX_FIELDS} names"));
            }
            if let Some(bad) = fields.iter().find(|f| f.is_empty() || f.len() > MAX_FIELD_LEN || !f.bytes().all(|b| (0x21..0x7f).contains(&b))) {
                return invalid(format!("leaked_credential_checks.{what}: '{}' is not a field name (1 to {MAX_FIELD_LEN} printable characters, no spaces)", bad.escape_debug()));
            }
        }
        if self.password_fields.is_empty() {
            return invalid("leaked_credential_checks.password_fields names at least one field");
        }
        Ok(())
    }
}

/// `GET /zones/{id}/leaked-credential-checks`: the settings, and how many
/// entries this node's table has (`null` without one).
pub fn view(s: &CredentialCheckSettings, table: Option<&LeakedPasswords>) -> Value {
    json!({
        "enabled": s.enabled,
        "paths": s.paths,
        "username_fields": s.username_fields,
        "password_fields": s.password_fields,
        "table_entries": table.map(|t| t.entries()),
    })
}

/// The settings after a `POST` / `PATCH` (Cloudflare's body is
/// `{"enabled": bool}`; the other fields are fucf's). A field set to null
/// goes back to its default.
pub fn patch(current: &CredentialCheckSettings, body: &Value) -> Result<CredentialCheckSettings, StoreError> {
    let Some(fields) = body.as_object() else { return invalid("the body is a JSON object") };
    let mut next = current.clone();
    let defaults = CredentialCheckSettings::default();
    for (key, value) in fields {
        let list = |default: &Vec<String>| -> Result<Vec<String>, StoreError> {
            match value {
                Value::Null => Ok(default.clone()),
                Value::Array(items) => items
                    .iter()
                    .map(|v| v.as_str().map(|s| s.trim().to_string()).ok_or_else(|| StoreError::Invalid(format!("{key} is a list of strings"))))
                    .collect(),
                _ => invalid(format!("{key} is a list of strings, or null for the default")),
            }
        };
        match key.as_str() {
            "enabled" => next.enabled = value.as_bool().ok_or_else(|| StoreError::Invalid("enabled is true or false".into()))?,
            "paths" => next.paths = list(&defaults.paths)?,
            "username_fields" => next.username_fields = list(&defaults.username_fields)?,
            "password_fields" => next.password_fields = list(&defaults.password_fields)?,
            other => return invalid(format!("unknown field '{other}' (known: enabled, paths, username_fields, password_fields)")),
        }
    }
    next.validate()?;
    Ok(next)
}

// ---------------------------------------------------------- the check ----

/// A path the way it is compared (see the module notes).
fn plain_path(path: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy().to_lowercase().replace('\\', "/");
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg.split(';').next().unwrap_or("") {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("/{}", segments.join("/"))
}

/// Whether the zone's `paths` cover a request path.
fn covers(paths: &[String], path: &str) -> bool {
    if paths.is_empty() {
        return true;
    }
    let path = plain_path(path);
    paths.iter().any(|p| match p.strip_suffix('*') {
        // `/api/*`: what is under /api (and /api itself); `/log*`: whatever starts so
        Some(prefix) if prefix.ends_with('/') => {
            let base = plain_path(prefix);
            base == "/" || path == base || path.strip_prefix(&base).is_some_and(|rest| rest.starts_with('/'))
        }
        Some(prefix) => path.starts_with(&plain_path(prefix)),
        None => path == plain_path(p),
    })
}

fn named(fields: &[String], key: &[u8]) -> bool {
    fields.iter().any(|f| f.as_bytes().eq_ignore_ascii_case(key))
}

/// One part of a form, `+` and percent escapes decoded.
fn form_decode(raw: &[u8]) -> Vec<u8> {
    let plus: Vec<u8> = raw.iter().map(|&b| if b == b'+' { b' ' } else { b }).collect();
    percent_encoding::percent_decode(&plus).collect()
}

/// The passwords of a form body (`a=1&b=2`), handed to `look` one at a
/// time; true as soon as `look` says so.
fn form_passwords(s: &CredentialCheckSettings, body: &[u8], look: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    let pairs = || body.split(|&b| b == b'&').map(|pair| match pair.iter().position(|&b| b == b'=') {
        Some(at) => (&pair[..at], &pair[at + 1..]),
        None => (pair, &pair[pair.len()..]),
    });
    let has_user = s.username_fields.is_empty() || pairs().any(|(k, v)| !v.is_empty() && named(&s.username_fields, &form_decode(k)));
    if !has_user {
        return false;
    }
    let mut tried = 0;
    for (k, v) in pairs() {
        if v.is_empty() || !named(&s.password_fields, &form_decode(k)) {
            continue;
        }
        let password = form_decode(v);
        if password.is_empty() || password.len() > MAX_PASSWORD {
            continue;
        }
        let found = look(&password);
        tried += 1;
        if found {
            return true;
        }
        if tried == MAX_CANDIDATES {
            break;
        }
    }
    false
}

/// The passwords of one JSON object, as for a form.
fn object_passwords(s: &CredentialCheckSettings, obj: &Map<String, Value>, look: &mut dyn FnMut(&[u8]) -> bool) -> Option<bool> {
    fn text(v: &Value) -> Option<&str> {
        v.as_str().filter(|t| !t.is_empty())
    }
    let has_user = s.username_fields.is_empty() || obj.iter().any(|(k, v)| text(v).is_some() && named(&s.username_fields, k.as_bytes()));
    let mut candidates = obj.iter().filter(|(k, _)| named(&s.password_fields, k.as_bytes())).filter_map(|(_, v)| text(v)).peekable();
    if !has_user || candidates.peek().is_none() {
        return None;
    }
    Some(candidates.filter(|p| p.len() <= MAX_PASSWORD).take(MAX_CANDIDATES).any(|p| look(p.as_bytes())))
}

/// The passwords of a JSON body: the top-level object's, or else the first
/// nested object's that has credentials.
fn json_passwords(s: &CredentialCheckSettings, body: &[u8], look: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    let Ok(Value::Object(top)) = serde_json::from_slice::<Value>(body) else { return false };
    if let Some(found) = object_passwords(s, &top, look) {
        return found;
    }
    top.values().filter_map(Value::as_object).find_map(|inner| object_passwords(s, inner, look)).unwrap_or(false)
}

/// The kind of body a request says it has.
#[derive(Debug, PartialEq)]
enum Kind {
    Form,
    Json,
}

fn kind(headers: &HeaderMap) -> Option<Kind> {
    let encoded = headers.get(header::CONTENT_ENCODING).is_some_and(|v| !v.as_bytes().trim_ascii().eq_ignore_ascii_case(b"identity"));
    if encoded {
        return None;
    }
    let content_type = String::from_utf8_lossy(headers.get(header::CONTENT_TYPE)?.as_bytes()).into_owned();
    let media = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if media == "application/x-www-form-urlencoded" {
        Some(Kind::Form)
    } else if super::apishield::is_json(&media) {
        Some(Kind::Json)
    } else {
        None
    }
}

/// Hand the credentials of a login request to `look`, one password at a
/// time (what the check and the tests share).
fn passwords(s: &CredentialCheckSettings, method: &str, path: &str, headers: &HeaderMap, body: &[u8], look: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    if !s.enabled || body.is_empty() || !matches!(method, "POST" | "PUT" | "PATCH") || !covers(&s.paths, path) {
        return false;
    }
    match kind(headers) {
        Some(Kind::Form) => form_passwords(s, body, look),
        Some(Kind::Json) => json_passwords(s, body, look),
        None => false,
    }
}

/// `cf.waf.credential_check.password_leaked` for a request, before the
/// zone's rules run. False without a table, for zones that did not opt in,
/// and for bodies the edge does not hold whole.
pub fn assess(table: Option<&LeakedPasswords>, s: &CredentialCheckSettings, info: &ReqInfo, headers: &HeaderMap, body: &ReqBody) -> bool {
    let (Some(table), ReqBody::Buffered(bytes)) = (table, body) else { return false };
    if !s.enabled || table.entries() == 0 {
        return false;
    }
    passwords(s, &info.method, &info.path, headers, bytes, &mut |password| table.holds(password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn sha1_hex(password: &str) -> String {
        ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes()).as_ref().iter().map(|b| format!("{b:02X}")).collect()
    }

    fn table(lines: &str) -> Result<Table, LoadError> {
        Table::read(lines.as_bytes())
    }

    fn on() -> CredentialCheckSettings {
        CredentialCheckSettings { enabled: true, ..Default::default() }
    }

    fn typed(content_type: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
        h
    }

    /// The passwords a request hands over, in order.
    fn found(s: &CredentialCheckSettings, method: &str, path: &str, headers: &HeaderMap, body: &str) -> Vec<String> {
        let mut out = Vec::new();
        passwords(s, method, path, headers, body.as_bytes(), &mut |p| {
            out.push(String::from_utf8_lossy(p).into_owned());
            false
        });
        out
    }

    const FORM: &str = "application/x-www-form-urlencoded";

    #[test]
    fn the_sha1_of_a_known_password_is_the_published_one() {
        // the hash of "password" that every leaked list starts with
        assert_eq!(sha1_hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(prefix_of(b"password"), [0x5b, 0xaa, 0x61, 0xe4, 0xc9, 0xb9, 0x3f, 0x3f]);
    }

    #[test]
    fn a_table_takes_whole_hashes_counts_prefixes_comments_and_either_case() {
        let t = table(&format!(
            "# leaked\n\n{}\r\n{}:42\n  {}  \n{}\n",
            sha1_hex("password"),
            sha1_hex("letmein-example"),
            &sha1_hex("hunter2-example")[..PREFIX_HEX].to_ascii_lowercase(),
            sha1_hex("password").to_ascii_lowercase(),
        ))
        .unwrap();
        assert_eq!(t.len(), 3, "the same hash twice is one entry");
        for leaked in ["password", "letmein-example", "hunter2-example"] {
            assert!(t.holds(leaked.as_bytes()), "{leaked}");
        }
        for fresh in ["Password", "password ", "", "correct horse battery staple example"] {
            assert!(!t.holds(fresh.as_bytes()), "{fresh:?}");
        }
        assert_eq!(table("").unwrap().len(), 0);
        assert!(!Table::default().holds(b"password"), "an empty table holds nothing");
        assert_eq!(table("# only a comment\n\n   \n").unwrap().len(), 0);
    }

    #[test]
    fn a_table_with_one_wrong_line_is_refused_with_its_number_and_not_its_text() {
        let good = sha1_hex("password");
        for (bad, line) in [
            (format!("{good}\n5BAA6\n"), 2),                              // a k-anonymity range prefix
            (format!("{good}\n{}\n", &good[..32]), 2),                    // NTLM length
            (format!("{}\n", &good[..39]), 1),                            // one digit short
            (format!("{good}0\n"), 1),                                    // one digit too many
            (format!("{}:12\n", &good[..PREFIX_HEX]), 1),                 // a count goes with whole hashes
            (format!("{good}:\n"), 1),                                    // no count after the colon
            (format!("{good}:12x\n"), 1),                                 // not a count
            (format!("{}G\n", &good[..39]), 1),                           // not hex
            (format!("{good}\n\n# c\n{} {}\n", &good[..20], &good[20..]), 4), // a space inside
            ("password\n".to_string(), 1),                                // a password, not a hash
        ] {
            let err = table(&bad).unwrap_err();
            assert_eq!(err, LoadError::BadLine(line), "{bad:?}");
            assert!(!err.to_string().contains(&good[..PREFIX_HEX]) && !err.to_string().contains("password"), "{err}");
        }
        // a line without a break that goes on and on is cut short
        let long = "0".repeat(10_000);
        assert_eq!(table(&long).unwrap_err(), LoadError::BadLine(1));
    }

    #[test]
    fn a_table_past_its_entries_is_refused_whole() {
        let lines: String = (0..5u64).map(|i| format!("{i:016x}\n")).collect();
        assert_eq!(Table::read_capped(lines.as_bytes(), 5).unwrap().len(), 5);
        assert_eq!(Table::read_capped(lines.as_bytes(), 4).unwrap_err(), LoadError::TooManyEntries);
        // duplicates count against the cap as they are read (it bounds the work, not the result)
        let twice = format!("{lines}{lines}");
        assert_eq!(Table::read_capped(twice.as_bytes(), 9).unwrap_err(), LoadError::TooManyEntries);
        assert_eq!(Table::read_capped(twice.as_bytes(), 10).unwrap().len(), 5);
    }

    #[test]
    fn a_file_on_disk_is_loaded_followed_and_a_bad_new_one_keeps_the_old_table() {
        let path = std::env::temp_dir().join(format!("fucf-leaked-{}.txt", uuid::Uuid::new_v4().simple()));
        assert!(matches!(LeakedPasswords::open(&path), Err(LoadError::Io(_))), "no file, no start");
        std::fs::write(&path, format!("{}\n", sha1_hex("password"))).unwrap();
        let leaked = LeakedPasswords::open(&path).unwrap();
        assert_eq!(leaked.entries(), 1);
        assert!(leaked.holds(b"password") && !leaked.holds(b"letmein-example"));
        assert_eq!(leaked.reload_if_changed(), None, "unchanged: not read again");
        assert!(format!("{leaked:?}").ends_with("1 entries)"), "Debug shows the size only");

        std::fs::write(&path, format!("{}\n{}\n", sha1_hex("password"), sha1_hex("letmein-example"))).unwrap();
        assert_eq!(leaked.reload_if_changed(), Some(Ok(2)));
        assert!(leaked.holds(b"letmein-example"));

        std::fs::write(&path, "not a hash at all, and longer than before\n").unwrap();
        assert_eq!(leaked.reload_if_changed(), Some(Err(LoadError::BadLine(1))));
        assert_eq!(leaked.reload_if_changed(), None, "reported once");
        assert!(leaked.holds(b"letmein-example"), "the table loaded before stays");

        std::fs::remove_file(&path).unwrap();
        assert!(matches!(leaked.reload_if_changed(), Some(Err(LoadError::Io(_)))));
        assert!(leaked.holds(b"password"), "a file taken away keeps the table too");
    }

    #[test]
    fn form_fields_are_found_by_name_decoded_and_without_regard_to_case() {
        let s = on();
        let h = typed(FORM);
        assert_eq!(found(&s, "POST", "/login", &h, "username=ann&password=hunter2"), ["hunter2"]);
        assert_eq!(found(&s, "POST", "/login", &h, "Email=ann%40example.com&PassWD=p%40ss+word%21"), ["p@ss word!"]);
        // the field names themselves may be escaped
        assert_eq!(found(&s, "POST", "/login", &h, "us%65r=ann&p%61ss=x%00y"), ["x\0y"]);
        // every password field counts: origins differ in which of two they read
        assert_eq!(found(&s, "POST", "/login", &h, "login=ann&password=a&pass=b&password=c"), ["a", "b", "c"]);
        assert_eq!(found(&s, "PUT", "/login", &typed("Application/X-WWW-Form-Urlencoded; charset=UTF-8"), "user=a&password=b"), ["b"]);
        // no username, an empty username or password, no password field: not a login
        for body in ["password=hunter2", "username=&password=hunter2", "username=ann&password=", "username=ann&secret=hunter2", "username=ann&password", "", "&&=&"] {
            assert!(found(&s, "POST", "/login", &h, body).is_empty(), "{body}");
        }
        // at most MAX_CANDIDATES lookups, and none of an overlong value
        let many = (0..20).map(|i| format!("password=p{i}")).collect::<Vec<_>>().join("&");
        assert_eq!(found(&s, "POST", "/login", &h, &format!("user=a&{many}")).len(), MAX_CANDIDATES);
        let long = "x".repeat(MAX_PASSWORD + 1);
        assert_eq!(found(&s, "POST", "/login", &h, &format!("user=a&password={long}&pass=ok")), ["ok"]);
    }

    #[test]
    fn json_keys_are_found_at_the_top_or_one_object_down() {
        let s = on();
        let h = typed("application/json");
        assert_eq!(found(&s, "POST", "/login", &h, r#"{"email": "ann@example.com", "password": "hunter2"}"#), ["hunter2"]);
        assert_eq!(found(&s, "POST", "/login", &h, r#"{"remember": true, "user": {"Login": "ann", "Passwd": "hunter2"}}"#), ["hunter2"]);
        assert_eq!(found(&s, "POST", "/login", &typed("application/vnd.api+json"), r#"{"username": "ann", "pass": "päss"}"#), ["p\u{e4}ss"]);
        for body in [
            r#"{"password": "hunter2"}"#,                                     // no username
            r#"{"username": "ann", "auth": {"password": "hunter2"}}"#,         // not in the same object
            r#"{"username": 7, "password": "hunter2"}"#,                       // a username is a string
            r#"{"username": "ann", "password": 1234}"#,                        // so is a password
            r#"{"username": "ann", "password": ""}"#,
            r#"{"a": {"b": {"username": "ann", "password": "hunter2"}}}"#,    // two levels down
            r#"[{"username": "ann", "password": "hunter2"}]"#,                 // not an object
            r#"{"username": "ann", "password": "hunter2""#,                    // not JSON
            "",
        ] {
            assert!(found(&s, "POST", "/login", &h, body).is_empty(), "{body}");
        }
    }

    #[test]
    fn field_names_paths_methods_and_types_come_from_the_settings_and_the_request() {
        let h = typed(FORM);
        let s = CredentialCheckSettings { username_fields: vec!["account".into()], password_fields: vec!["pin_code".into()], ..on() };
        assert_eq!(found(&s, "POST", "/x", &h, "account=a&pin_code=1234"), ["1234"]);
        assert!(found(&s, "POST", "/x", &h, "username=a&password=1234").is_empty(), "the defaults no longer count");
        let alone = CredentialCheckSettings { username_fields: vec![], ..on() };
        assert_eq!(found(&alone, "POST", "/x", &h, "password=1234"), ["1234"], "no username fields: a password alone will do");

        assert!(found(&CredentialCheckSettings::default(), "POST", "/login", &h, "user=a&password=b").is_empty(), "off by default");
        for method in ["GET", "HEAD", "DELETE", "OPTIONS", "post"] {
            assert!(found(&on(), method, "/login", &h, "user=a&password=b").is_empty(), "{method}");
        }
        for content_type in ["multipart/form-data; boundary=x", "text/plain", "application/jsonx", ""] {
            let h = typed(content_type);
            assert!(found(&on(), "POST", "/login", &h, "user=a&password=b").is_empty(), "{content_type}");
        }
        assert!(found(&on(), "POST", "/login", &HeaderMap::new(), "user=a&password=b").is_empty(), "no Content-Type");
        let mut gz = typed(FORM);
        gz.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(found(&on(), "POST", "/login", &gz, "user=a&password=b").is_empty(), "an encoded body is not read");
        gz.insert(header::CONTENT_ENCODING, HeaderValue::from_static("identity"));
        assert_eq!(found(&on(), "POST", "/login", &gz, "user=a&password=b"), ["b"]);
    }

    #[test]
    fn paths_match_however_an_origin_would_read_them() {
        let paths: Vec<String> = ["/login", "/api/auth/*", "/sign*", "/account/"].iter().map(|s| s.to_string()).collect();
        for yes in [
            "/login", "/login/", "/LOGIN", "/%6Cogin", "//login", "/./login", "/x/../login", "/login;jsessionid=1", "\\login",
            "/api/auth", "/api/auth/", "/api/auth/token", "/API/Auth/a/b", "/signin", "/signup/now", "/account",
        ] {
            assert!(covers(&paths, yes), "{yes}");
        }
        for no in ["/", "/login/x", "/loginx", "/x/login", "/api/authx", "/api", "/sig", "/accounts", "/login/.."] {
            assert!(!covers(&paths, no), "{no}");
        }
        assert!(covers(&[], "/anything"), "no paths: every path");
        assert!(covers(&["/*".to_string()], "/anything/at/all"));
    }

    #[test]
    fn settings_are_checked_patched_and_default_to_the_common_field_names() {
        let d = CredentialCheckSettings::default();
        assert!(!d.enabled && d.paths.is_empty());
        assert_eq!(d.username_fields, DEFAULT_USERNAME_FIELDS);
        assert_eq!(d.password_fields, DEFAULT_PASSWORD_FIELDS);
        assert!(d.validate().is_ok());
        let read: CredentialCheckSettings = serde_json::from_value(json!({ "enabled": true })).unwrap();
        assert_eq!(read, CredentialCheckSettings { enabled: true, ..d.clone() }, "missing fields read as the defaults");

        let next = patch(&d, &json!({ "enabled": true, "paths": [" /login ", "/api/*"], "username_fields": ["account"] })).unwrap();
        assert!(next.enabled);
        assert_eq!(next.paths, ["/login", "/api/*"]);
        assert_eq!(next.username_fields, ["account"]);
        assert_eq!(next.password_fields, DEFAULT_PASSWORD_FIELDS, "untouched");
        let back = patch(&next, &json!({ "paths": null, "username_fields": null })).unwrap();
        assert_eq!(back, CredentialCheckSettings { enabled: true, ..d.clone() }, "null puts the default back");
        assert!(patch(&next, &json!({ "username_fields": [] })).unwrap().username_fields.is_empty());

        for bad in [
            json!([]),
            json!({ "enabled": "yes" }),
            json!({ "enable": true }),
            json!({ "paths": "/login" }),
            json!({ "paths": [1] }),
            json!({ "paths": ["login"] }),
            json!({ "paths": ["/log in"] }),
            json!({ "paths": ["/login?x=1"] }),
            json!({ "paths": ["/a*b"] }),
            json!({ "paths": [format!("/{}", "a".repeat(MAX_PATH_LEN))] }),
            json!({ "paths": (0..=MAX_PATHS).map(|i| format!("/p{i}")).collect::<Vec<_>>() }),
            json!({ "password_fields": [] }),
            json!({ "password_fields": [""] }),
            json!({ "password_fields": ["pass word"] }),
            json!({ "username_fields": ["a".repeat(MAX_FIELD_LEN + 1)] }),
            json!({ "username_fields": (0..=MAX_FIELDS).map(|i| format!("u{i}")).collect::<Vec<_>>() }),
        ] {
            assert!(patch(&next, &bad).is_err(), "{bad}");
        }
        let v = view(&next, None);
        assert_eq!(v["enabled"], true);
        assert_eq!(v["table_entries"], Value::Null, "no table on this node");
    }

    #[test]
    fn the_check_needs_a_table_a_zone_that_opted_in_and_a_body_held_whole() {
        let path = std::env::temp_dir().join(format!("fucf-leaked-{}.txt", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, format!("{}\n", sha1_hex("hunter2-example"))).unwrap();
        let leaked = LeakedPasswords::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let info = ReqInfo { method: "POST".into(), path: "/login".into(), ..Default::default() };
        let h = typed(FORM);
        let body = |s: &str| ReqBody::Buffered(bytes::Bytes::from(s.to_string()));
        let s = on();
        assert!(assess(Some(&leaked), &s, &info, &h, &body("user=ann&password=hunter2-example")));
        assert!(!assess(Some(&leaked), &s, &info, &h, &body("user=ann&password=hunter3-example")));
        assert!(!assess(None, &s, &info, &h, &body("user=ann&password=hunter2-example")), "no table");
        assert!(!assess(Some(&leaked), &CredentialCheckSettings::default(), &info, &h, &body("user=ann&password=hunter2-example")), "zone off");
        let streamed = ReqBody::Stream(super::super::full(bytes::Bytes::from_static(b"user=ann&password=hunter2-example")));
        assert!(!assess(Some(&leaked), &s, &info, &h, &streamed), "a streamed body is not read");
        let json_info = ReqInfo { path: "/api/session".into(), ..info.clone() };
        let jh = typed("application/json");
        assert!(assess(Some(&leaked), &s, &json_info, &jh, &body(r#"{"session": {"email": "ann@example.com", "password": "hunter2-example"}}"#)));
        // what the request keeps of it is one boolean, and its Debug shows no password
        let marked = ReqInfo { password_leaked: true, ..info };
        assert!(!format!("{marked:?}").contains("hunter2"));
    }
}
