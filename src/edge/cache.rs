//! Edge cache with Cloudflare-like default eligibility rules: a memory tier
//! for what is hot, and optionally a disk tier that holds more and survives
//! restarts. Both evict what was used least recently.

use bytes::Bytes;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Largest single response we will buffer and store.
pub const MAX_OBJECT: u64 = 32 * 1024 * 1024;
/// The same for responses that do not announce their length: they are read
/// before the first byte is passed on, so the limit is lower.
pub const MAX_UNSIZED: usize = 8 * 1024 * 1024;
/// How long past its expiry an object may still be served when the origin
/// is down or answers with a server error.
pub const STALE_IF_ERROR: Duration = Duration::from_secs(24 * 3600);

/// File extensions cached by default (everything else needs explicit
/// `Cache-Control: public` / `s-maxage` from the origin).
const STATIC_EXT: &[&str] = &[
    "7z", "avi", "avif", "apk", "bin", "bmp", "bz2", "class", "css", "csv", "doc", "docx", "dmg", "ejs", "eot",
    "eps", "exe", "flac", "gif", "gz", "ico", "iso", "jar", "jpg", "jpeg", "js", "mid", "midi", "mkv", "mp3",
    "mp4", "ogg", "otf", "pdf", "pict", "pls", "png", "ppt", "pptx", "ps", "rar", "svg", "svgz", "swf", "tar",
    "tif", "tiff", "ttf", "webm", "webp", "woff", "woff2", "xls", "xlsx", "zip", "zst",
];

pub struct Entry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub stored: Instant,
    pub ttl: Duration,
    pub zone_id: String,
    /// `host/path?query`, used for purge-by-URL.
    pub url: String,
    /// Set on the entries of an object kept in chunks (see
    /// crate::edge::chunked); `None` for every other entry.
    pub piece: Option<Piece>,
}

/// What an entry of an object kept in chunks holds. Every fill of such an
/// object gets a new `fill` id, carried by its entry and each of its
/// chunks: a chunk is only used with the entry of its own fill, so chunks
/// of two versions of an object can never be served together.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Piece {
    /// The object's status, headers and freshness, under the object's key;
    /// its body is empty and `total` bytes long in chunks.
    Meta { fill: String, total: u64 },
    /// Chunk `n` of the fill (see crate::edge::chunked::chunk_key).
    Chunk { fill: String, n: u64 },
}

impl Entry {
    fn size(&self) -> usize {
        self.body.len() + self.url.len() + 512
    }
    /// Can the origin be asked "has this changed?" instead of refetching?
    pub fn has_validator(&self) -> bool {
        self.headers.contains_key(header::ETAG) || self.headers.contains_key(header::LAST_MODIFIED)
    }
    pub fn fresh(&self) -> bool {
        self.stored.elapsed() < self.ttl
    }
}

/// What to do with an origin response.
#[derive(Debug, PartialEq)]
pub enum Decision {
    Store(Duration),
    /// Eligible content, but the origin's headers forbid caching.
    Bypass,
    /// Not eligible for caching at all.
    Dynamic,
}

fn directives(headers: &HeaderMap) -> Vec<(String, Option<String>)> {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|d| match d.trim().split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim().trim_matches('"').to_string())),
            None => (d.trim().to_ascii_lowercase(), None),
        })
        .collect()
}

/// The `max-age` a response declares, if any.
pub fn max_age(headers: &HeaderMap) -> Option<u64> {
    directives(headers).into_iter().find(|(k, _)| k == "max-age").and_then(|(_, v)| v?.parse().ok())
}

/// For how long past its freshness an answer may still be served while a new
/// copy is fetched in the background (`stale-while-revalidate=N`, at most a day).
pub fn stale_while_revalidate(headers: &HeaderMap) -> Duration {
    let secs = directives(headers).into_iter().find(|(k, _)| k == "stale-while-revalidate").and_then(|(_, v)| v?.parse::<u64>().ok());
    Duration::from_secs(secs.unwrap_or(0).min(86400))
}

fn split_tags<'a>(values: impl Iterator<Item = &'a str>) -> Vec<String> {
    values.flat_map(|v| v.split(',')).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
}

/// The tags the origin put on an answer (`Cache-Tag: a, b`): what is kept can be purged by them.
pub fn tags_of(headers: &HeaderMap) -> Vec<String> {
    split_tags(headers.get_all("cache-tag").iter().filter_map(|v| v.to_str().ok()))
}

/// May this request be answered from / stored into the cache?
pub fn request_cacheable(method: &Method, headers: &HeaderMap) -> bool {
    (method == Method::GET || method == Method::HEAD)
        && !headers.contains_key(header::AUTHORIZATION)
        && !headers.contains_key(header::UPGRADE)
}

/// What a `Range` header asks for, of an object of `len` bytes.
#[derive(Debug, PartialEq)]
pub enum Range {
    /// Nothing we act on (no byte range, or several): the whole object.
    Whole,
    /// First and last byte, inclusive.
    Part(u64, u64),
    Unsatisfiable,
}

pub fn parse_range(value: &str, len: u64) -> Range {
    let Some((first, last)) = value.trim().strip_prefix("bytes=").and_then(|spec| spec.split_once('-')) else {
        return Range::Whole;
    };
    let (first, last) = (first.trim(), last.trim());
    match (first.parse::<u64>(), last.parse::<u64>()) {
        (Ok(a), _) if a >= len && (last.is_empty() || last.parse::<u64>().is_ok_and(|b| a <= b)) => Range::Unsatisfiable,
        (Ok(a), Ok(b)) if a <= b => Range::Part(a, b.min(len - 1)),
        (Ok(a), Err(_)) if last.is_empty() => Range::Part(a, len - 1),
        // `-n`: the last n bytes
        (Err(_), Ok(n)) if first.is_empty() && (n == 0 || len == 0) => Range::Unsatisfiable,
        (Err(_), Ok(n)) if first.is_empty() => Range::Part(len - n.min(len), len - 1),
        _ => Range::Whole,
    }
}

/// An HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`) as Unix seconds.
pub fn http_date(value: &header::HeaderValue) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(value.to_str().ok()?.trim()).ok().map(|t| t.timestamp())
}

/// The compressions a visitor's answer may come in, as the last part of
/// its key: those of br, gzip and zstd it accepts (by q-value, as
/// [`super::compress::accepts`] reads it), in that order, comma separated.
/// An origin answers compressed in one of what the visitor asked for, so
/// a copy kept under a bucket only goes to visitors that take every coding
/// of it ([`Cache::put`] refuses the rest).
fn accept_encoding_bucket(headers: &HeaderMap) -> String {
    let ae = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    let taken: Vec<&str> = BUCKET_CODINGS.into_iter().filter(|c| super::compress::accepts(ae, c)).collect();
    taken.join(",")
}

/// The codings a key tells apart; any other one is never stored (see
/// [`Cache::put`]).
const BUCKET_CODINGS: [&str; 3] = ["br", "gzip", "zstd"];

/// Whether an answer in `coding` (lower case) may be kept under `key`:
/// the coding is one of the key's compression part. Keys without one
/// (not from [`cache_key`]) take anything.
fn bucket_allows(key: &str, coding: &str) -> bool {
    match key.rsplit_once(&format!("|{ENC}")) {
        Some((_, bucket)) => bucket.split(',').any(|b| b == coding),
        None => true,
    }
}

/// Query parameters that only tell where a visitor came from: never part of the key.
fn tracking(param: &str) -> bool {
    let name = param.split('=').next().unwrap_or("").to_ascii_lowercase();
    name.starts_with("utm_") || matches!(name.as_str(), "fbclid" | "gclid" | "dclid" | "msclkid" | "yclid" | "mc_eid" | "_ga" | "igshid" | "spm")
}

/// The key of a request: scheme, host, path and query (without tracking
/// parameters), what a cache rule adds (`custom`, from
/// crate::edge::cachekey; empty for most), and which compressions the
/// client takes. `custom` goes before the compression part so that
/// [`identity_key`] still finds the copy every compression shares.
pub fn cache_key(ssl: bool, host: &str, uri: &str, custom: &str, req_headers: &HeaderMap) -> String {
    let uri = match uri.split_once('?') {
        Some((path, query)) if query.split('&').any(tracking) => {
            let kept: Vec<&str> = query.split('&').filter(|p| !p.is_empty() && !tracking(p)).collect();
            if kept.is_empty() { path.to_string() } else { format!("{path}?{}", kept.join("&")) }
        }
        _ => uri.to_string(),
    };
    format!("{}|{host}{uri}{custom}|{ENC}{}", if ssl { "https" } else { "http" }, accept_encoding_bucket(req_headers))
}

/// Marks the compression part of a key from [`cache_key`].
const ENC: &str = "ae=";

/// The key under which an uncompressed answer is kept: one copy serves
/// every client, whatever it accepts (the edge compresses on the way out).
fn identity_key(key: &str) -> Option<String> {
    let (head, bucket) = key.rsplit_once(&format!("|{ENC}"))?;
    (!bucket.is_empty()).then(|| format!("{head}|{ENC}"))
}

/// `force` makes any content type eligible ("cache everything"); `ttl`
/// overrides the origin's freshness directives. `keyed`: the request
/// headers a cache rule made part of the key (lower case), which the
/// origin's `Vary` may name too.
pub fn decide(path: &str, status: StatusCode, headers: &HeaderMap, force: bool, ttl: Option<u64>, keyed: &[String]) -> Decision {
    let cc = directives(headers);
    let has = |name: &str| cc.iter().any(|(k, _)| k == name);
    let secs = |name: &str| cc.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.as_ref()?.parse::<u64>().ok());

    let ext = path.rsplit('/').next().and_then(|f| f.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase());
    let is_static = ext.is_some_and(|e| STATIC_EXT.contains(&e.as_str()));
    let explicit = has("public") || secs("s-maxage").is_some();
    if !is_static && !explicit && !force {
        return Decision::Dynamic;
    }
    let default_ttl = match status.as_u16() {
        200 | 206 => 7200,
        301 | 308 => 1200,
        404 | 410 => 180,
        _ => return Decision::Dynamic,
    };
    if status == StatusCode::PARTIAL_CONTENT {
        return Decision::Bypass;
    }
    let forbidden = ttl.is_none() && (has("no-store") || has("private") || has("no-cache"));
    if forbidden || headers.contains_key(header::SET_COOKIE) {
        return Decision::Bypass;
    }
    // Only `Vary` on what is part of the key is supported: `Accept-Encoding`,
    // and the headers a cache rule added to it.
    let vary_ok = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .all(|v| v.eq_ignore_ascii_case("accept-encoding") || keyed.iter().any(|k| v.eq_ignore_ascii_case(k)));
    if !vary_ok {
        return Decision::Bypass;
    }
    match ttl.or(secs("s-maxage")).or(secs("max-age")).unwrap_or(default_ttl) {
        0 => Decision::Bypass,
        ttl => Decision::Store(Duration::from_secs(ttl.min(31_536_000))),
    }
}

/// Does an entry count as an object of its own (what a purge reports)?
/// The chunks of an object kept in chunks do not: they go with it.
fn is_object(piece: &Option<Piece>) -> bool {
    !matches!(piece, Some(Piece::Chunk { .. }))
}

#[derive(Default)]
struct Inner {
    /// Entry and when it was last used (a tick of `clock`).
    map: HashMap<String, (Arc<Entry>, u64)>,
    bytes: usize,
    clock: u64,
}

pub struct Cache {
    inner: Mutex<Inner>,
    max_bytes: usize,
    disk: Option<Disk>,
}

fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

impl Cache {
    pub fn new(max_bytes: usize) -> Self {
        Cache { inner: Mutex::default(), max_bytes, disk: None }
    }

    /// With a disk tier of `disk_bytes` in `dir`: what is already there is
    /// loaded (its index; bodies are read when asked for).
    pub fn with_disk(max_bytes: usize, dir: PathBuf, disk_bytes: usize) -> std::io::Result<Self> {
        Ok(Cache { inner: Mutex::default(), max_bytes, disk: Some(Disk::open(dir, disk_bytes)?) })
    }

    /// Bytes and objects held, and the size it may grow to (the disk tier's
    /// when there is one: it holds everything the memory tier does).
    pub fn usage(&self) -> (usize, usize, usize) {
        if let Some(disk) = &self.disk {
            let index = disk.index.lock().unwrap();
            return (index.bytes, index.map.len(), disk.max_bytes);
        }
        let inner = self.inner.lock().unwrap();
        (inner.bytes, inner.map.len(), self.max_bytes)
    }

    /// Forget everything.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.map.clear();
        inner.bytes = 0;
        drop(inner);
        if let Some(disk) = &self.disk {
            disk.clear();
        }
    }

    fn memory_get(&self, key: &str) -> Option<Arc<Entry>> {
        let mut inner = self.inner.lock().unwrap();
        inner.clock += 1;
        let now = inner.clock;
        let slot = inner.map.get_mut(key)?;
        slot.1 = now;
        Some(slot.0.clone())
    }

    /// From memory only; returns the entry even when stale (check [`Entry::fresh`]).
    pub fn get(&self, key: &str) -> Option<Arc<Entry>> {
        self.memory_get(key).or_else(|| self.memory_get(&identity_key(key)?))
    }

    /// From memory, else from disk (then kept in memory again).
    pub async fn lookup(&self, key: &str) -> Option<Arc<Entry>> {
        if let Some(hit) = self.get(key) {
            return Some(hit);
        }
        self.disk.as_ref()?;
        let candidates: Vec<String> = [Some(key.to_string()), identity_key(key)].into_iter().flatten().collect();
        for k in candidates {
            if let Some(entry) = self.from_disk(k).await {
                return Some(entry);
            }
        }
        None
    }

    /// Exactly the entry under `key` (no shared uncompressed copy is looked
    /// for), from memory, else from disk: the chunks of an object, whose
    /// keys must never lead to another entry.
    pub async fn lookup_exact(&self, key: &str) -> Option<Arc<Entry>> {
        match self.memory_get(key) {
            Some(hit) => Some(hit),
            None => self.from_disk(key.to_string()).await,
        }
    }

    /// The entry under `key` on disk, read back into memory. An index entry
    /// whose file cannot be read is forgotten.
    async fn from_disk(&self, key: String) -> Option<Arc<Entry>> {
        let disk = self.disk.as_ref()?;
        let file = disk.file_of(&key)?;
        let read = tokio::task::spawn_blocking(move || Disk::read(&file)).await.ok().flatten();
        match read {
            Some(entry) => {
                let entry = Arc::new(entry);
                self.memory_put(key, entry.clone());
                Some(entry)
            }
            None => {
                disk.forget(&key);
                None
            }
        }
    }

    /// The key under which [`Cache::put`] keeps an uncompressed answer to a
    /// request with this key (one copy for every compression). An object
    /// kept in chunks is always uncompressed: its entry is kept there, and
    /// its chunk keys start with it.
    pub fn shared_key(key: &str) -> String {
        identity_key(key).unwrap_or_else(|| key.to_string())
    }

    /// Keep an answer to a request with this key. An uncompressed one goes
    /// under the shared key; a compressed one only under a key whose
    /// compression part names its coding, else it is not kept at all: an
    /// origin that sends zstd, deflate or several codings to a visitor that
    /// did not ask for them (or gzip to one that sent no Accept-Encoding)
    /// must not have that body served to the next visitor from the cache.
    pub fn put(&self, key: String, entry: Entry) {
        let coding = entry.headers.get(header::CONTENT_ENCODING).map(|v| v.to_str().unwrap_or("?").trim().to_ascii_lowercase());
        let key = match (identity_key(&key), &coding) {
            // an uncompressed answer serves every client
            (Some(shared), None) => shared,
            _ => key,
        };
        if let Some(coding) = coding.filter(|c| c != "identity") {
            if !bucket_allows(&key, &coding) {
                return;
            }
        }
        self.put_exact(key, entry);
    }

    /// Keep `entry` under exactly `key`: unlike [`Cache::put`], an
    /// uncompressed one is not moved to the shared key.
    pub fn put_exact(&self, key: String, entry: Entry) {
        let entry = Arc::new(entry);
        if let Some(disk) = &self.disk {
            if entry.ttl >= Duration::from_secs(30) && entry.size() <= disk.max_bytes / 8 {
                disk.write(key.clone(), entry.clone());
            }
        }
        self.memory_put(key, entry);
    }

    fn memory_put(&self, key: String, entry: Arc<Entry>) {
        let size = entry.size();
        if size > self.max_bytes {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.clock += 1;
        let now = inner.clock;
        if let Some((old, _)) = inner.map.insert(key, (entry, now)) {
            inner.bytes -= old.size();
        }
        inner.bytes += size;
        if inner.bytes > self.max_bytes {
            // Drop expired entries first, then the least recently used until 10% is free.
            let mut all: Vec<(String, bool, u64, usize)> =
                inner.map.iter().map(|(k, (e, used))| (k.clone(), e.fresh(), *used, e.size())).collect();
            all.sort_by_key(|(_, fresh, used, _)| (*fresh, *used));
            let goal = self.max_bytes / 10 * 9;
            for (k, _, _, sz) in all {
                if inner.bytes <= goal {
                    break;
                }
                inner.map.remove(&k);
                inner.bytes -= sz;
            }
        }
    }

    /// Forget the entry under exactly `key`, in memory and on disk.
    pub fn remove(&self, key: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some((old, _)) = inner.map.remove(key) {
            inner.bytes -= old.size();
        }
        drop(inner);
        if let Some(disk) = &self.disk {
            disk.forget(key);
        }
    }

    fn remove_where(&self, pred: impl Fn(&str, &str) -> bool) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let mut gone = 0;
        inner.map.retain(|_, (e, _)| {
            let doomed = pred(&e.zone_id, &e.url);
            gone += usize::from(doomed && is_object(&e.piece));
            !doomed
        });
        inner.bytes = inner.map.values().map(|(e, _)| e.size()).sum();
        drop(inner);
        if let Some(disk) = &self.disk {
            gone = gone.max(disk.remove_where(&|m| pred(&m.zone_id, &m.url)));
        }
        gone
    }

    /// Purge what the origin tagged (its `Cache-Tag` header) with one of `tags`.
    pub fn purge_tags(&self, zone_id: &str, tags: &[String]) -> usize {
        if tags.is_empty() {
            return 0;
        }
        let hit = |have: &[String]| have.iter().any(|t| tags.contains(t));
        let mut inner = self.inner.lock().unwrap();
        let mut gone = 0;
        inner.map.retain(|_, (e, _)| {
            let doomed = e.zone_id == zone_id && hit(&tags_of(&e.headers));
            gone += usize::from(doomed && is_object(&e.piece));
            !doomed
        });
        inner.bytes = inner.map.values().map(|(e, _)| e.size()).sum();
        drop(inner);
        if let Some(disk) = &self.disk {
            gone = gone.max(disk.remove_where(&|m| m.zone_id == zone_id && hit(&m.tags)));
        }
        gone
    }

    pub fn purge_zone(&self, zone_id: &str) -> usize {
        self.remove_where(|zone, _| zone == zone_id)
    }

    /// Purge by full URL (`https://host/path?query`) or URL prefix.
    pub fn purge_urls(&self, zone_id: &str, urls: &[String], prefix: bool) -> usize {
        let wanted: Vec<&str> = urls
            .iter()
            .map(|u| u.strip_prefix("https://").or(u.strip_prefix("http://")).unwrap_or(u))
            .collect();
        self.remove_where(|zone, url| zone == zone_id && wanted.iter().any(|w| if prefix { url.starts_with(w) } else { url == *w }))
    }

    /// Wait until what was handed to the disk tier is written (tests, shutdown).
    pub fn flush(&self) {
        if let Some(disk) = &self.disk {
            let (tx, rx) = mpsc::channel();
            if disk.jobs.lock().unwrap().send(Job::Flush(tx)).is_ok() {
                let _ = rx.recv_timeout(Duration::from_secs(10));
            }
        }
    }
}

// ------------------------------------------------------------- disk tier ----

/// What a cache file starts with (after a 4-byte length).
#[derive(Serialize, Deserialize)]
struct FileHead {
    key: String,
    status: u16,
    headers: Vec<(String, String)>,
    /// When it was stored, and for how long it is fresh (ms).
    stored_ms: u64,
    ttl_ms: u64,
    zone_id: String,
    url: String,
    /// Left out for an entry that is not part of an object kept in chunks,
    /// so such files are written exactly as before chunks existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    piece: Option<Piece>,
}

struct Meta {
    file: PathBuf,
    size: usize,
    zone_id: String,
    url: String,
    /// The origin's `Cache-Tag`s.
    tags: Vec<String>,
    used: u64,
    /// A chunk of an object kept in chunks: not counted as an object of its own.
    chunk: bool,
}

#[derive(Default)]
struct Index {
    map: HashMap<String, Meta>,
    bytes: usize,
    clock: u64,
}

enum Job {
    Write(String, Arc<Entry>),
    Remove(Vec<PathBuf>),
    Flush(mpsc::Sender<()>),
}

struct Disk {
    dir: PathBuf,
    max_bytes: usize,
    index: Arc<Mutex<Index>>,
    jobs: Mutex<mpsc::Sender<Job>>,
}

/// Kept on disk this long past expiry, to be served when the origin fails.
fn keep_until(stored_ms: u64, ttl_ms: u64) -> u64 {
    stored_ms + ttl_ms + STALE_IF_ERROR.as_millis() as u64
}

impl Disk {
    fn open(dir: PathBuf, max_bytes: usize) -> std::io::Result<Disk> {
        std::fs::create_dir_all(&dir)?;
        let now = unix_ms(SystemTime::now());
        let mut index = Index::default();
        let mut found: Vec<(u64, String, Meta)> = Vec::new();
        for item in std::fs::read_dir(&dir)?.flatten() {
            let path = item.path();
            let name = item.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            // `.k`: the entry of an object kept in chunks (see [`Disk::file_name`])
            if !name.ends_with(".c") && !name.ends_with(".k") {
                continue;
            }
            match Disk::head(&path) {
                Some((head, size)) if keep_until(head.stored_ms, head.ttl_ms) > now => {
                    found.push((head.stored_ms, head.key, Meta { file: path, size, tags: split_tags(head.headers.iter().filter(|(n, _)| n == "cache-tag").map(|(_, v)| v.as_str())), zone_id: head.zone_id, url: head.url, used: 0, chunk: !is_object(&head.piece) }));
                }
                _ => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        // the most recently stored count as the most recently used
        found.sort_by_key(|(stored, _, _)| *stored);
        for (_, key, mut meta) in found {
            index.clock += 1;
            meta.used = index.clock;
            index.bytes += meta.size;
            let file = meta.file.clone();
            if let Some(old) = index.map.insert(key, meta) {
                index.bytes -= old.size;
                // one key in a `.c` and a `.k` file: the older one goes
                if old.file != file {
                    let _ = std::fs::remove_file(&old.file);
                }
            }
        }
        let index = Arc::new(Mutex::new(index));
        let (tx, rx) = mpsc::channel::<Job>();
        let (writer_index, writer_dir) = (index.clone(), dir.clone());
        std::thread::Builder::new().name("fucf-cache-disk".into()).spawn(move || Disk::writer(rx, writer_index, writer_dir, max_bytes))?;
        let disk = Disk { dir, max_bytes, index, jobs: Mutex::new(tx) };
        disk.evict();
        let (bytes, objects) = {
            let i = disk.index.lock().unwrap();
            (i.bytes, i.map.len())
        };
        tracing::info!("edge cache on disk: {} ({} objects, {} KiB of {} MiB)", disk.dir.display(), objects, bytes / 1024, max_bytes >> 20);
        Ok(disk)
    }

    /// The entry of an object kept in chunks goes to a `.k` file, every
    /// other one to a `.c` file: a binary from before chunks only reads
    /// `.c` files, so after a downgrade it never serves such an entry's
    /// empty body as the object (it ignores those files; chunks it reads are
    /// never asked for and age out).
    fn file_name(key: &str, piece: Option<&Piece>) -> String {
        let ext = if matches!(piece, Some(Piece::Meta { .. })) { "k" } else { "c" };
        format!("{}.{ext}", crate::acme::b64(&crate::acme::sha256(key.as_bytes())))
    }

    fn head(path: &std::path::Path) -> Option<(FileHead, usize)> {
        let mut f = std::fs::File::open(path).ok()?;
        let size = f.metadata().ok()?.len() as usize;
        let mut len = [0u8; 4];
        f.read_exact(&mut len).ok()?;
        let len = u32::from_le_bytes(len) as usize;
        if len > 1 << 20 || len + 4 > size {
            return None;
        }
        let mut head = vec![0u8; len];
        f.read_exact(&mut head).ok()?;
        Some((serde_json::from_slice(&head).ok()?, size))
    }

    fn read(path: &std::path::Path) -> Option<Entry> {
        let data = std::fs::read(path).ok()?;
        let len = u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as usize;
        let head: FileHead = serde_json::from_slice(data.get(4..4 + len)?).ok()?;
        let mut headers = HeaderMap::new();
        for (name, value) in &head.headers {
            if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
                headers.append(n, v);
            }
        }
        // its age, as an instant of this process (old ones become "long expired")
        let age = Duration::from_millis(unix_ms(SystemTime::now()).saturating_sub(head.stored_ms));
        let stored = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        let ttl = if Instant::now().checked_sub(age).is_some() { Duration::from_millis(head.ttl_ms) } else { Duration::ZERO };
        Some(Entry {
            status: StatusCode::from_u16(head.status).ok()?,
            headers,
            body: Bytes::copy_from_slice(data.get(4 + len..)?),
            stored,
            ttl,
            zone_id: head.zone_id,
            url: head.url,
            piece: head.piece,
        })
    }

    fn file_of(&self, key: &str) -> Option<PathBuf> {
        let mut index = self.index.lock().unwrap();
        index.clock += 1;
        let now = index.clock;
        let meta = index.map.get_mut(key)?;
        meta.used = now;
        Some(meta.file.clone())
    }

    fn forget(&self, key: &str) {
        let mut index = self.index.lock().unwrap();
        if let Some(meta) = index.map.remove(key) {
            index.bytes -= meta.size;
            let _ = self.jobs.lock().unwrap().send(Job::Remove(vec![meta.file]));
        }
    }

    fn write(&self, key: String, entry: Arc<Entry>) {
        let _ = self.jobs.lock().unwrap().send(Job::Write(key, entry));
    }

    fn remove_where(&self, pred: &dyn Fn(&Meta) -> bool) -> usize {
        let mut index = self.index.lock().unwrap();
        let doomed: Vec<String> = index.map.iter().filter(|(_, m)| pred(m)).map(|(k, _)| k.clone()).collect();
        let (mut files, mut objects) = (Vec::new(), 0);
        for k in &doomed {
            if let Some(m) = index.map.remove(k) {
                index.bytes -= m.size;
                objects += usize::from(!m.chunk);
                files.push(m.file);
            }
        }
        drop(index);
        if !files.is_empty() {
            let _ = self.jobs.lock().unwrap().send(Job::Remove(files));
        }
        objects
    }

    fn clear(&self) {
        self.remove_where(&|_| true);
    }

    /// Drop the least recently used until the tier fits again (10% to spare).
    fn evict(&self) {
        Disk::evict_index(&self.index, self.max_bytes, &self.jobs.lock().unwrap());
    }

    fn evict_index(index: &Mutex<Index>, max_bytes: usize, jobs: &mpsc::Sender<Job>) {
        let mut index = index.lock().unwrap();
        if index.bytes <= max_bytes {
            return;
        }
        let mut all: Vec<(u64, String)> = index.map.iter().map(|(k, m)| (m.used, k.clone())).collect();
        all.sort();
        let goal = max_bytes / 10 * 9;
        let mut files = Vec::new();
        for (_, k) in all {
            if index.bytes <= goal {
                break;
            }
            if let Some(m) = index.map.remove(&k) {
                index.bytes -= m.size;
                files.push(m.file);
            }
        }
        let _ = jobs.send(Job::Remove(files));
    }

    fn writer(rx: mpsc::Receiver<Job>, index: Arc<Mutex<Index>>, dir: PathBuf, max_bytes: usize) {
        // removals go back through the same queue, so they keep their order with writes
        let (again, more) = mpsc::channel::<Job>();
        loop {
            let job = match more.try_recv() {
                Ok(job) => job,
                Err(_) => match rx.recv() {
                    Ok(job) => job,
                    Err(_) => return,
                },
            };
            match job {
                Job::Flush(done) => {
                    while let Ok(job) = more.try_recv() {
                        Disk::run_removal(job);
                    }
                    let _ = done.send(());
                }
                Job::Remove(_) => Disk::run_removal(job),
                Job::Write(key, entry) => {
                    let path = dir.join(Disk::file_name(&key, entry.piece.as_ref()));
                    let head = FileHead {
                        key: key.clone(),
                        status: entry.status.as_u16(),
                        headers: entry.headers.iter().filter_map(|(n, v)| Some((n.as_str().to_string(), v.to_str().ok()?.to_string()))).collect(),
                        stored_ms: unix_ms(SystemTime::now()).saturating_sub(entry.stored.elapsed().as_millis() as u64),
                        ttl_ms: entry.ttl.as_millis() as u64,
                        zone_id: entry.zone_id.clone(),
                        url: entry.url.clone(),
                        piece: entry.piece.clone(),
                    };
                    let Ok(head_json) = serde_json::to_vec(&head) else { continue };
                    let tmp = path.with_extension("tmp");
                    let written = std::fs::File::create(&tmp).and_then(|mut f| {
                        f.write_all(&(head_json.len() as u32).to_le_bytes())?;
                        f.write_all(&head_json)?;
                        f.write_all(&entry.body)?;
                        f.flush()
                    });
                    if written.is_err() || std::fs::rename(&tmp, &path).is_err() {
                        let _ = std::fs::remove_file(&tmp);
                        continue;
                    }
                    let size = 4 + head_json.len() + entry.body.len();
                    {
                        let mut index = index.lock().unwrap();
                        index.clock += 1;
                        let used = index.clock;
                        let meta = Meta { file: path.clone(), size, zone_id: entry.zone_id.clone(), url: entry.url.clone(), tags: tags_of(&entry.headers), used, chunk: !is_object(&entry.piece) };
                        if let Some(old) = index.map.insert(key, meta) {
                            index.bytes -= old.size;
                            // the key went from a `.c` to a `.k` file or back
                            if old.file != path {
                                let _ = std::fs::remove_file(&old.file);
                            }
                        }
                        index.bytes += size;
                    }
                    Disk::evict_index(&index, max_bytes, &again);
                }
            }
        }
    }

    fn run_removal(job: Job) {
        if let Job::Remove(files) = job {
            for f in files {
                let _ = std::fs::remove_file(f);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs.iter().map(|(k, v)| (header::HeaderName::from_static(k), v.parse().unwrap())).collect()
    }

    #[test]
    fn decisions() {
        let ok = StatusCode::OK;
        let decide = |p, s, h: &HeaderMap| super::decide(p, s, h, false, None, &[]);
        let html = h(&[("cache-control", "private")]);
        assert_eq!(super::decide("/index.html", ok, &h(&[]), true, None, &[]), Decision::Store(Duration::from_secs(7200)));
        assert_eq!(super::decide("/index.html", ok, &html, true, None, &[]), Decision::Bypass);
        assert_eq!(super::decide("/index.html", ok, &html, true, Some(30), &[]), Decision::Store(Duration::from_secs(30)));
        assert_eq!(decide("/a/app.js", ok, &h(&[])), Decision::Store(Duration::from_secs(7200)));
        assert_eq!(decide("/index.html", ok, &h(&[])), Decision::Dynamic);
        assert_eq!(decide("/api", ok, &h(&[("cache-control", "max-age=60")])), Decision::Dynamic);
        assert_eq!(
            decide("/api", ok, &h(&[("cache-control", "public, max-age=60")])),
            Decision::Store(Duration::from_secs(60))
        );
        assert_eq!(
            decide("/a.css", ok, &h(&[("cache-control", "max-age=60, s-maxage=600")])),
            Decision::Store(Duration::from_secs(600))
        );
        assert_eq!(decide("/a.css", ok, &h(&[("cache-control", "private")])), Decision::Bypass);
        assert_eq!(decide("/a.css", ok, &h(&[("set-cookie", "a=b")])), Decision::Bypass);
        assert_eq!(decide("/a.css", ok, &h(&[("vary", "Cookie")])), Decision::Bypass);
        assert!(matches!(decide("/a.css", ok, &h(&[("vary", "Accept-Encoding")])), Decision::Store(_)));
        // a Vary on headers a cache rule keys by is covered by the key; any other is not
        let keyed = ["accept-language".to_string()];
        let vary = h(&[("vary", "Accept-Encoding, Accept-Language")]);
        assert_eq!(decide("/a.css", ok, &vary), Decision::Bypass);
        assert!(matches!(super::decide("/a.css", ok, &vary, false, None, &keyed), Decision::Store(_)));
        for other in ["Accept-Language, Cookie", "*", "Accept-Language-X"] {
            assert_eq!(super::decide("/a.css", ok, &h(&[("vary", other)]), false, None, &keyed), Decision::Bypass, "{other}");
        }
        assert_eq!(decide("/a.css", StatusCode::NOT_FOUND, &h(&[])), Decision::Store(Duration::from_secs(180)));
        assert_eq!(decide("/a.css", StatusCode::INTERNAL_SERVER_ERROR, &h(&[])), Decision::Dynamic);
    }

    #[test]
    fn ranges_and_dates() {
        use Range::*;
        assert_eq!(parse_range("bytes=0-99", 1000), Part(0, 99));
        assert_eq!(parse_range("bytes=500-", 1000), Part(500, 999));
        assert_eq!(parse_range("bytes=990-2000", 1000), Part(990, 999));
        assert_eq!(parse_range("bytes=-100", 1000), Part(900, 999));
        assert_eq!(parse_range("bytes=-5000", 1000), Part(0, 999));
        assert_eq!(parse_range(" bytes = 1-2", 1000), Whole);
        assert_eq!(parse_range("bytes=1000-", 1000), Unsatisfiable);
        assert_eq!(parse_range("bytes=1000-1001", 1000), Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 1000), Unsatisfiable);
        assert_eq!(parse_range("bytes=0-", 0), Unsatisfiable);
        // not acted on: other units, several ranges, nonsense
        for ignored in ["items=0-1", "bytes=0-1,5-6", "bytes=9-1", "bytes=a-b", "bytes=-", "bytes=5"] {
            assert_eq!(parse_range(ignored, 1000), Whole, "{ignored}");
        }

        let date = |s: &'static str| http_date(&header::HeaderValue::from_static(s));
        assert_eq!(date("Thu, 01 Jan 1970 00:01:00 GMT"), Some(60));
        assert!(date("Wed, 21 Oct 2015 07:28:00 GMT") < date("Wed, 21 Oct 2015 07:28:01 GMT"));
        assert_eq!(date("yesterday"), None);
    }

    #[test]
    fn what_the_origin_tagged_is_purged_by_tag() {
        let cache = Cache::new(1 << 20);
        let entry = |zone: &str, tags: &str| {
            let mut headers = HeaderMap::new();
            if !tags.is_empty() {
                headers.insert("cache-tag", tags.parse().unwrap());
            }
            Entry { status: StatusCode::OK, headers, body: Bytes::from_static(b"x"), stored: Instant::now(), ttl: Duration::from_secs(60), zone_id: zone.into(), url: "u".into(), piece: None }
        };
        cache.put("a".into(), entry("z", "product-1, listing"));
        cache.put("b".into(), entry("z", "listing"));
        cache.put("c".into(), entry("z", ""));
        cache.put("d".into(), entry("other", "listing"));
        assert_eq!(cache.purge_tags("z", &["product-1".into()]), 1);
        assert_eq!(cache.purge_tags("z", &["listing".into(), "nothing".into()]), 1);
        assert!(cache.get("c").is_some() && cache.get("d").is_some() && cache.get("a").is_none() && cache.get("b").is_none());
    }

    #[test]
    fn store_purge_evict() {
        let cache = Cache::new(4000);
        let entry = |zone: &str, url: &str, n: usize| Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from(vec![0u8; n]),
            stored: Instant::now(),
            ttl: Duration::from_secs(60),
            zone_id: zone.into(),
            url: url.into(),
            piece: None,
        };
        cache.put("k1".into(), entry("z1", "a.test/x.js", 100));
        cache.put("k2".into(), entry("z1", "a.test/img/y.png", 100));
        cache.put("k3".into(), entry("z2", "b.test/x.js", 100));
        assert!(cache.get("k1").unwrap().fresh());
        assert_eq!(cache.purge_urls("z1", &["https://a.test/x.js".into()], false), 1);
        assert_eq!(cache.purge_urls("z1", &["a.test/img/".into()], true), 1);
        assert_eq!(cache.purge_zone("z2"), 1);
        assert!(cache.get("k3").is_none());

        for i in 0..10 {
            cache.put(format!("big{i}"), entry("z", "u", 1000));
        }
        let inner = cache.inner.lock().unwrap();
        assert!(inner.bytes <= 4000 && !inner.map.is_empty());
        assert!(inner.map.contains_key("big9"));
    }

    #[test]
    fn keys_leave_out_tracking_and_share_uncompressed_copies() {
        let ae = |v: &str| {
            let mut h = HeaderMap::new();
            if !v.is_empty() {
                h.insert(header::ACCEPT_ENCODING, v.parse().unwrap());
            }
            h
        };
        let k = cache_key(true, "a.test", "/x.js?v=2&utm_source=tw&fbclid=1", "", &ae("gzip, br"));
        assert_eq!(k, "https|a.test/x.js?v=2|ae=br,gzip");
        assert_eq!(cache_key(true, "a.test", "/x.js?utm_medium=a", "", &ae("")), "https|a.test/x.js|ae=");
        assert_eq!(identity_key(&k).as_deref(), Some("https|a.test/x.js?v=2|ae="));
        assert_eq!(identity_key("https|a.test/x.js|ae="), None);
        assert_eq!(identity_key("warp|some|key"), None, "other keys are left alone");

        let cache = Cache::new(1 << 20);
        let entry = |encoded: bool| {
            let mut headers = HeaderMap::new();
            if encoded {
                headers.insert(header::CONTENT_ENCODING, "br".parse().unwrap());
            }
            Entry { status: StatusCode::OK, headers, body: Bytes::from_static(b"body"), stored: Instant::now(), ttl: Duration::from_secs(60), zone_id: "z".into(), url: "u".into(), piece: None }
        };
        cache.put(k.clone(), entry(false));
        for bucket in ["", "gzip", "br", "gzip, br"] {
            assert!(cache.get(&cache_key(true, "a.test", "/x.js?v=2", "", &ae(bucket))).is_some(), "{bucket}");
        }
        let br = cache_key(true, "a.test", "/y.js", "", &ae("br"));
        cache.put(br.clone(), entry(true));
        assert!(cache.get(&br).is_some() && cache.get(&cache_key(true, "a.test", "/y.js", "", &ae("gzip"))).is_none(), "compressed copies stay apart");
    }

    #[test]
    fn the_compression_part_of_a_key_follows_the_q_values_and_names_zstd() {
        let bucket = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT_ENCODING, v.parse().unwrap());
            accept_encoding_bucket(&h)
        };
        assert_eq!(bucket("gzip, deflate, br, zstd"), "br,gzip,zstd");
        assert_eq!(bucket("gzip, deflate, br"), "br,gzip", "keys of clients without zstd are as before");
        assert_eq!(bucket("zstd"), "zstd");
        assert_eq!(bucket("br;q=0, gzip"), "gzip", "a refused coding is not in the bucket");
        assert_eq!(bucket("zstd;q=0"), "");
        assert_eq!(bucket("deflate, identity, *"), "", "only br, gzip and zstd are told apart");
        assert_eq!(bucket("xbr, gzipped"), "", "whole tokens only");
        assert_eq!(accept_encoding_bucket(&HeaderMap::new()), "");
    }

    #[test]
    fn a_compressed_answer_is_kept_only_where_every_visitor_takes_its_coding() {
        let ae = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT_ENCODING, v.parse().unwrap());
            h
        };
        let entry = |coding: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_ENCODING, coding.parse().unwrap());
            Entry { status: StatusCode::OK, headers, body: Bytes::from_static(b"packed"), stored: Instant::now(), ttl: Duration::from_secs(60), zone_id: "z".into(), url: "u".into(), piece: None }
        };
        let key = |path: &str, accept: &str| cache_key(true, "a.test", path, "", &ae(accept));
        let cache = Cache::new(1 << 20);

        cache.put(key("/a.css", "gzip, br, zstd"), entry("zstd"));
        assert!(cache.get(&key("/a.css", "zstd, br, gzip")).is_some());
        for other in ["gzip, br", "gzip", "br", "zstd;q=0, gzip, br", "identity"] {
            assert!(cache.get(&key("/a.css", other)).is_none(), "{other}");
        }
        assert!(cache.get("https|a.test/a.css|ae=").is_none(), "nothing went to the shared key");

        // an origin that answered in a coding the visitor did not ask for: not kept
        cache.put(key("/b.css", "gzip, br"), entry("zstd"));
        cache.put(key("/c.css", "gzip"), entry("deflate"));
        cache.put(key("/d.css", "gzip, br"), entry("gzip, br"));
        cache.put("https|a.test/e.css|ae=".into(), entry("gzip"));
        for path in ["/b.css", "/c.css", "/d.css", "/e.css"] {
            for accept in ["gzip, br, zstd", "gzip", "identity"] {
                assert!(cache.get(&key(path, accept)).is_none(), "{path} {accept}");
            }
        }
        // a coding written in capitals is still the coding, and keys not made by cache_key take anything
        cache.put(key("/f.css", "gzip"), entry(" GZIP "));
        assert!(cache.get(&key("/f.css", "gzip, br")).is_none() && cache.get(&key("/f.css", "gzip")).is_some());
        cache.put("warp|x".into(), entry("zstd"));
        assert!(cache.get("warp|x").is_some());
    }

    #[test]
    fn a_custom_key_part_keeps_variants_apart_and_purges_still_find_them() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let (en, de) = ("\u{1f}hx-lang=en", "\u{1f}hx-lang=de");
        let k_en = cache_key(true, "a.test", "/p?v=1&utm_source=x", en, &h);
        assert_eq!(k_en, "https|a.test/p?v=1\u{1f}hx-lang=en|ae=gzip");
        assert_eq!(identity_key(&k_en).as_deref(), Some("https|a.test/p?v=1\u{1f}hx-lang=en|ae="), "the part stays in the shared key");

        let cache = Cache::new(1 << 20);
        let entry = |body: &'static [u8]| Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(body),
            stored: Instant::now(),
            ttl: Duration::from_secs(60),
            zone_id: "z".into(),
            url: "a.test/p?v=1".into(),
            piece: None,
        };
        cache.put(k_en.clone(), entry(b"en"));
        cache.put(cache_key(true, "a.test", "/p?v=1", de, &h), entry(b"de"));
        cache.put(cache_key(true, "a.test", "/other", de, &h), Entry { url: "a.test/other".into(), ..entry(b"o") });
        assert_eq!(&cache.get(&k_en).unwrap().body[..], b"en");
        assert_eq!(&cache.get(&cache_key(true, "a.test", "/p?v=1", de, &HeaderMap::new())).unwrap().body[..], b"de");
        assert!(cache.get(&cache_key(true, "a.test", "/p?v=1", "", &h)).is_none(), "no part, no variant");

        // purges match the stored URL, so every variant of it goes
        assert_eq!(cache.purge_urls("z", &["https://a.test/p?v=1".into()], false), 2);
        assert!(cache.get(&k_en).is_none());
        assert_eq!(cache.purge_urls("z", &["a.test/oth".into()], true), 1, "by prefix too");
    }

    #[test]
    fn evicts_the_least_recently_used() {
        let cache = Cache::new(3 * 1600);
        let entry = || Entry { status: StatusCode::OK, headers: HeaderMap::new(), body: Bytes::from(vec![0u8; 1000]), stored: Instant::now(), ttl: Duration::from_secs(60), zone_id: "z".into(), url: "u".into(), piece: None };
        cache.put("old-but-busy".into(), entry());
        cache.put("b".into(), entry());
        cache.put("c".into(), entry());
        assert!(cache.get("old-but-busy").is_some());
        cache.put("d".into(), entry());
        assert!(cache.get("old-but-busy").is_some() && cache.get("b").is_none(), "the one nobody asked for goes");
    }

    #[tokio::test]
    async fn the_disk_tier_survives_a_restart_and_purges() {
        let dir = std::env::temp_dir().join(format!("fucf-cache-{}", uuid::Uuid::new_v4().simple()));
        let entry = |url: &str, n: usize| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, "text/css".parse().unwrap());
            Entry { status: StatusCode::OK, headers, body: Bytes::from(vec![b'x'; n]), stored: Instant::now(), ttl: Duration::from_secs(600), zone_id: "z".into(), url: url.into(), piece: None }
        };
        {
            let cache = Cache::with_disk(2000, dir.clone(), 1 << 20).unwrap();
            cache.put("https|a.test/a.css|ae=gzip".into(), entry("a.test/a.css", 1500));
            cache.put("https|a.test/b.css|ae=".into(), entry("a.test/b.css", 1500)); // pushes a.css out of memory
            cache.put("short".into(), Entry { ttl: Duration::from_secs(5), ..entry("a.test/short", 10) });
            cache.flush();
            assert!(cache.get("https|a.test/a.css|ae=").is_none(), "no longer in memory");
            let back = cache.lookup("https|a.test/a.css|ae=br").await.expect("read back from disk");
            assert!(back.fresh() && back.body.len() == 1500 && back.headers[header::CONTENT_TYPE] == "text/css");
            assert_eq!(cache.usage().1, 2, "what is fresh only briefly stays in memory");
        }
        // a new process: the index is rebuilt from the files
        let cache = Cache::with_disk(2000, dir.clone(), 1 << 20).unwrap();
        assert_eq!(cache.usage().1, 2);
        assert!(cache.lookup("https|a.test/b.css|ae=gzip").await.is_some_and(|e| e.fresh()));
        assert_eq!(cache.purge_urls("z", &["https://a.test/a.css".into()], false), 1);
        cache.flush();
        assert!(cache.lookup("https|a.test/a.css|ae=").await.is_none());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        cache.clear();
        cache.flush();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_disk_tier_keeps_to_its_size() {
        let dir = std::env::temp_dir().join(format!("fucf-cache-{}", uuid::Uuid::new_v4().simple()));
        let cache = Cache::with_disk(1 << 20, dir.clone(), 64 * 1024).unwrap();
        for i in 0..40 {
            let e = Entry { status: StatusCode::OK, headers: HeaderMap::new(), body: Bytes::from(vec![0u8; 4000]), stored: Instant::now(), ttl: Duration::from_secs(600), zone_id: "z".into(), url: format!("u{i}"), piece: None };
            cache.put(format!("k{i}"), e);
        }
        cache.flush();
        let (bytes, objects, max) = cache.usage();
        assert!(bytes <= max && objects < 40 && objects > 5, "{bytes} {objects}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), objects);
        let _ = std::fs::remove_dir_all(dir);
    }
}
