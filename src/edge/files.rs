//! A static file server for `LocalProxyRule`s with a `file_root` (what
//! Caddy's `file_server` does): GET and HEAD, index files, conditional
//! requests (ETag / Last-Modified), single byte ranges, streaming bodies.
//!
//! Only directories this node allows (`--file-root-allow`) are ever served,
//! whatever the (fleet-wide) configuration says. Paths cannot leave the root
//! (`..`, symbolic links pointing elsewhere), and dot files stay hidden.

use super::{full, Body, BoxError};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Frame;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::RwLock;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;

/// Bodies up to this size are read at once; larger ones stream.
const SMALL: u64 = 256 * 1024;
const CHUNK: usize = 64 * 1024;

static ALLOWED: RwLock<Vec<PathBuf>> = RwLock::new(Vec::new());

/// Allow serving files from these directories (and everything below them).
pub fn set_allowed_roots(roots: Vec<PathBuf>) {
    let roots: Vec<PathBuf> = roots.into_iter().filter_map(|r| std::fs::canonicalize(&r).ok()).collect();
    ALLOWED.write().unwrap().extend(roots);
}

fn allowed(root: &Path) -> bool {
    ALLOWED.read().unwrap().iter().any(|a| root.starts_with(a))
}

struct FileBody(mpsc::Receiver<Result<Bytes, BoxError>>);

impl hyper::body::Body for FileBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx).map(|item| item.map(|r| r.map(Frame::data)))
    }
}

pub fn content_type(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        "txt" | "md" | "log" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

fn status(code: StatusCode) -> Response<Body> {
    let mut resp = Response::new(full(format!("{} {}\n", code.as_u16(), code.canonical_reason().unwrap_or(""))));
    *resp.status_mut() = code;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    resp
}

fn http_date(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn parse_http_date(s: &str) -> Option<SystemTime> {
    let dt = chrono::NaiveDateTime::parse_from_str(s.trim(), "%a, %d %b %Y %H:%M:%S GMT").ok()?;
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(dt.and_utc().timestamp().max(0) as u64))
}

/// The path below the root a request path names, or `None` when it tries to
/// leave the root or names a hidden file.
pub fn relative_path(request_path: &str) -> Option<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(request_path).decode_utf8().ok()?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return None;
    }
    let mut out = PathBuf::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return None,
            s if s.starts_with('.') && s != ".well-known" => return None,
            s => out.push(s),
        }
    }
    Some(out)
}

/// `bytes=a-b`, `bytes=a-`, `bytes=-n` against a file of `len` bytes: the
/// inclusive range to send, `Err` when it cannot be satisfied, `Ok(None)`
/// when the header is absent or not understood (send the whole file).
fn byte_range(value: Option<&str>, len: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = value.and_then(|v| v.trim().strip_prefix("bytes=")) else { return Ok(None) };
    if spec.contains(',') {
        return Ok(None); // several ranges: the whole file will do
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    let (a, b) = (a.trim(), b.trim());
    let range = if a.is_empty() {
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 || len == 0 {
            return Err(());
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let start: u64 = a.parse().map_err(|_| ())?;
        let end = if b.is_empty() { len.saturating_sub(1) } else { b.parse::<u64>().map_err(|_| ())?.min(len.saturating_sub(1)) };
        if start >= len || end < start {
            return Err(());
        }
        (start, end)
    };
    Ok(Some(range))
}

/// Answer `request_path` from `root`.
pub async fn serve(root: &str, index_files: &[String], request_path: &str, method: &Method, headers: &HeaderMap) -> Response<Body> {
    if method != Method::GET && method != Method::HEAD {
        let mut resp = status(StatusCode::METHOD_NOT_ALLOWED);
        resp.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return resp;
    }
    let Ok(root) = tokio::fs::canonicalize(root).await else { return status(StatusCode::NOT_FOUND) };
    if !allowed(&root) {
        tracing::warn!("file_root {} is not below a directory this node allows (--file-root-allow): not served", root.display());
        return status(StatusCode::FORBIDDEN);
    }
    let Some(rel) = relative_path(request_path) else { return status(StatusCode::NOT_FOUND) };
    let Ok(mut path) = tokio::fs::canonicalize(root.join(&rel)).await else { return status(StatusCode::NOT_FOUND) };
    if !path.starts_with(&root) {
        return status(StatusCode::NOT_FOUND);
    }
    let Ok(mut meta) = tokio::fs::metadata(&path).await else { return status(StatusCode::NOT_FOUND) };
    if meta.is_dir() {
        if !request_path.ends_with('/') {
            // relative links in the index file need the trailing slash
            let mut resp = status(StatusCode::PERMANENT_REDIRECT);
            if let Ok(v) = HeaderValue::from_str(&format!("{request_path}/")) {
                resp.headers_mut().insert(header::LOCATION, v);
            }
            return resp;
        }
        let defaults = ["index.html".to_string()];
        let names = if index_files.is_empty() { &defaults[..] } else { index_files };
        let mut found = None;
        for name in names {
            let candidate = path.join(name);
            if let Ok(m) = tokio::fs::metadata(&candidate).await {
                if m.is_file() {
                    found = Some((candidate, m));
                    break;
                }
            }
        }
        let Some((p, m)) = found else { return status(StatusCode::NOT_FOUND) };
        (path, meta) = (p, m);
    }
    if !meta.is_file() {
        return status(StatusCode::NOT_FOUND);
    }

    let len = meta.len();
    let modified = meta.modified().ok();
    let mtime = modified.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    let etag = format!("\"{mtime:x}-{len:x}\"");
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type(&path)));
    resp_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        resp_headers.insert(header::ETAG, v);
    }
    if let Some(t) = modified {
        if let Ok(v) = HeaderValue::from_str(&http_date(t)) {
            resp_headers.insert(header::LAST_MODIFIED, v);
        }
    }

    // conditional requests: If-None-Match wins over If-Modified-Since
    let fresh = match headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        Some(inm) => inm.split(',').any(|t| {
            let t = t.trim();
            t == "*" || t.trim_start_matches("W/") == etag
        }),
        None => headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date)
            .is_some_and(|since| mtime <= since.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())),
    };
    if fresh {
        let mut resp = Response::new(full(Bytes::new()));
        *resp.status_mut() = StatusCode::NOT_MODIFIED;
        *resp.headers_mut() = resp_headers;
        resp.headers_mut().remove(header::CONTENT_TYPE);
        return resp;
    }

    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    // If-Range: a range only while the file is still the one the client has
    let range_header = match headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
        Some(ir) if ir.trim() != etag => None,
        _ => range_header,
    };
    let (code, start, end) = match byte_range(range_header, len) {
        Ok(Some((a, b))) => (StatusCode::PARTIAL_CONTENT, a, b),
        Ok(None) => (StatusCode::OK, 0, len.saturating_sub(1)),
        Err(()) => {
            let mut resp = status(StatusCode::RANGE_NOT_SATISFIABLE);
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{len}")) {
                resp.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            return resp;
        }
    };
    let count = if len == 0 { 0 } else { end - start + 1 };
    if code == StatusCode::PARTIAL_CONTENT {
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end}/{len}")) {
            resp_headers.insert(header::CONTENT_RANGE, v);
        }
    }
    resp_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(count));

    let body: Body = if *method == Method::HEAD || count == 0 {
        full(Bytes::new())
    } else if count <= SMALL {
        let read = async {
            let mut f = tokio::fs::File::open(&path).await?;
            f.seek(std::io::SeekFrom::Start(start)).await?;
            let mut buf = vec![0u8; count as usize];
            f.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(buf)
        };
        match read.await {
            Ok(buf) => full(buf),
            Err(_) => return status(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        let Ok(mut f) = tokio::fs::File::open(&path).await else { return status(StatusCode::NOT_FOUND) };
        if f.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return status(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let (tx, rx) = mpsc::channel::<Result<Bytes, BoxError>>(4);
        tokio::spawn(async move {
            let mut left = count;
            while left > 0 {
                let mut buf = vec![0u8; CHUNK.min(left as usize)];
                match f.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.truncate(n);
                        left -= n as u64;
                        if tx.send(Ok(Bytes::from(buf))).await.is_err() {
                            return; // the client went away
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Box::new(e))).await;
                        return;
                    }
                }
            }
        });
        FileBody(rx).boxed()
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = code;
    *resp.headers_mut() = resp_headers;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside_the_root() {
        assert_eq!(relative_path("/a/b.txt"), Some(PathBuf::from("a/b.txt")));
        assert_eq!(relative_path("/a/./b/"), Some(PathBuf::from("a/b")));
        assert_eq!(relative_path("/%E4%BD%A0%E5%A5%BD.html"), Some(PathBuf::from("你好.html")));
        assert_eq!(relative_path("/.well-known/acme-challenge/x"), Some(PathBuf::from(".well-known/acme-challenge/x")));
        for bad in ["/../etc/passwd", "/a/%2e%2e/b", "/.git/config", "/a/.env", "/a%00b", "/a\\..\\b", "/x/%5c..%5cy"] {
            assert_eq!(relative_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn ranges() {
        assert_eq!(byte_range(None, 100), Ok(None));
        assert_eq!(byte_range(Some("bytes=0-9"), 100), Ok(Some((0, 9))));
        assert_eq!(byte_range(Some("bytes=90-"), 100), Ok(Some((90, 99))));
        assert_eq!(byte_range(Some("bytes=-10"), 100), Ok(Some((90, 99))));
        assert_eq!(byte_range(Some("bytes=50-500"), 100), Ok(Some((50, 99))));
        assert_eq!(byte_range(Some("bytes=0-1,5-6"), 100), Ok(None));
        assert_eq!(byte_range(Some("bytes=100-"), 100), Err(()));
        assert_eq!(byte_range(Some("bytes=9-3"), 100), Err(()));
        assert_eq!(byte_range(Some("items=0-1"), 100), Ok(None));
    }

    #[tokio::test]
    async fn serves_files_conditionally_and_in_ranges() {
        let base = std::env::temp_dir().join(format!("fucf-files-{}", uuid::Uuid::new_v4().simple()));
        let root = base.join("site");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(root.join("sub/data.json"), "{\"a\":1}").unwrap();
        std::fs::write(root.join(".secret"), "no").unwrap();
        let big: Vec<u8> = (0..(SMALL as usize * 3)).map(|i| (i % 251) as u8).collect();
        std::fs::write(root.join("big.bin"), &big).unwrap();
        std::fs::write(base.join("outside.txt"), "outside").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(base.join("outside.txt"), root.join("link.txt")).unwrap();
        set_allowed_roots(vec![base.clone()]);
        let root_s = root.to_str().unwrap();
        let get = |path: &'static str, hdrs: Vec<(&'static str, String)>| {
            let mut h = HeaderMap::new();
            for (k, v) in hdrs {
                h.insert(k, HeaderValue::from_str(&v).unwrap());
            }
            async move { serve(root_s, &[], path, &Method::GET, &h).await }
        };
        let text = |r: Response<Body>| async move { String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap() };

        let r = get("/", vec![]).await;
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        let etag = r.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(text(r).await, "<h1>home</h1>");
        assert_eq!(get("/", vec![("if-none-match", etag)]).await.status(), 304);
        assert_eq!(get("/sub", vec![]).await.status(), 308);
        assert_eq!(get("/sub/data.json", vec![]).await.headers()[header::CONTENT_TYPE], "application/json");
        for hidden in ["/.secret", "/../outside.txt", "/link.txt", "/missing"] {
            assert_eq!(get(hidden, vec![]).await.status(), 404, "{hidden}");
        }
        let r = get("/big.bin", vec![("range", "bytes=10-19".into())]).await;
        assert_eq!(r.status(), 206);
        assert_eq!(r.headers()[header::CONTENT_RANGE], format!("bytes 10-19/{}", big.len()));
        assert_eq!(r.into_body().collect().await.unwrap().to_bytes().as_ref(), &big[10..20]);
        let r = get("/big.bin", vec![]).await;
        assert_eq!(r.into_body().collect().await.unwrap().to_bytes().as_ref(), &big[..], "streamed whole");
        assert_eq!(get("/big.bin", vec![("range", format!("bytes={}-", big.len()))]).await.status(), 416);
        let r = serve(root_s, &[], "/", &Method::POST, &HeaderMap::new()).await;
        assert_eq!(r.status(), 405);
        // a root outside what this node allows is never served
        let elsewhere = std::env::temp_dir();
        let r = serve(elsewhere.to_str().unwrap(), &[], "/", &Method::GET, &HeaderMap::new()).await;
        assert!(r.status() == 403 || r.status() == 404);
        let _ = std::fs::remove_dir_all(base);
    }
}
