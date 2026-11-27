//! In-memory edge cache with Cloudflare-like default eligibility rules.

use bytes::Bytes;
use hyper::header::{self, HeaderMap};
use hyper::{Method, StatusCode};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

#[derive(Default)]
struct Inner {
    map: HashMap<String, Arc<Entry>>,
    bytes: usize,
}

pub struct Cache {
    inner: Mutex<Inner>,
    max_bytes: usize,
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

fn accept_encoding_bucket(headers: &HeaderMap) -> &'static str {
    let ae = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    match (ae.contains("br"), ae.contains("gzip")) {
        (true, true) => "br,gzip",
        (true, false) => "br",
        (false, true) => "gzip",
        _ => "",
    }
}

pub fn cache_key(ssl: bool, host: &str, uri: &str, req_headers: &HeaderMap) -> String {
    format!("{}|{host}{uri}|{}", if ssl { "https" } else { "http" }, accept_encoding_bucket(req_headers))
}

/// `force` makes any content type eligible ("cache everything"); `ttl`
/// overrides the origin's freshness directives.
pub fn decide(path: &str, status: StatusCode, headers: &HeaderMap, force: bool, ttl: Option<u64>) -> Decision {
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
    // Only `Vary: Accept-Encoding` is supported (it is part of the key).
    let vary_ok = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .all(|v| v.trim().eq_ignore_ascii_case("accept-encoding"));
    if !vary_ok {
        return Decision::Bypass;
    }
    match ttl.or(secs("s-maxage")).or(secs("max-age")).unwrap_or(default_ttl) {
        0 => Decision::Bypass,
        ttl => Decision::Store(Duration::from_secs(ttl.min(31_536_000))),
    }
}

impl Cache {
    pub fn new(max_bytes: usize) -> Self {
        Cache { inner: Mutex::default(), max_bytes }
    }

    /// Bytes and objects held, and the size it may grow to.
    pub fn usage(&self) -> (usize, usize, usize) {
        let inner = self.inner.lock().unwrap();
        (inner.bytes, inner.map.len(), self.max_bytes)
    }

    /// Forget everything.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.map.clear();
        inner.bytes = 0;
    }

    /// Returns the entry even when stale; check [`Entry::fresh`].
    pub fn get(&self, key: &str) -> Option<Arc<Entry>> {
        self.inner.lock().unwrap().map.get(key).cloned()
    }

    pub fn put(&self, key: String, entry: Entry) {
        let size = entry.size();
        if size > self.max_bytes {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if let Some(old) = inner.map.insert(key, Arc::new(entry)) {
            inner.bytes -= old.size();
        }
        inner.bytes += size;
        if inner.bytes > self.max_bytes {
            // Drop expired entries first, then the oldest until 10% is free.
            let mut all: Vec<(String, bool, Instant, usize)> =
                inner.map.iter().map(|(k, e)| (k.clone(), e.fresh(), e.stored, e.size())).collect();
            all.sort_by_key(|(_, fresh, stored, _)| (*fresh, *stored));
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

    fn remove_where(&self, pred: impl Fn(&Entry) -> bool) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let before = inner.map.len();
        inner.map.retain(|_, e| !pred(e));
        inner.bytes = inner.map.values().map(|e| e.size()).sum();
        before - inner.map.len()
    }

    pub fn purge_zone(&self, zone_id: &str) -> usize {
        self.remove_where(|e| e.zone_id == zone_id)
    }

    /// Purge by full URL (`https://host/path?query`) or URL prefix.
    pub fn purge_urls(&self, zone_id: &str, urls: &[String], prefix: bool) -> usize {
        let wanted: Vec<&str> = urls
            .iter()
            .map(|u| u.strip_prefix("https://").or(u.strip_prefix("http://")).unwrap_or(u))
            .collect();
        self.remove_where(|e| {
            e.zone_id == zone_id
                && wanted.iter().any(|w| if prefix { e.url.starts_with(w) } else { e.url == *w })
        })
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
        let decide = |p, s, h: &HeaderMap| super::decide(p, s, h, false, None);
        let html = h(&[("cache-control", "private")]);
        assert_eq!(super::decide("/index.html", ok, &h(&[]), true, None), Decision::Store(Duration::from_secs(7200)));
        assert_eq!(super::decide("/index.html", ok, &html, true, None), Decision::Bypass);
        assert_eq!(super::decide("/index.html", ok, &html, true, Some(30)), Decision::Store(Duration::from_secs(30)));
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
}
