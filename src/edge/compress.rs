//! Edge response compression (brotli / gzip), negotiated per client.

use super::{collect_limited, full, Body};
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use std::io::Write;

const MIN_SIZE: u64 = 1024;
const MAX_SIZE: u64 = 8 * 1024 * 1024;

const COMPRESSIBLE: &[&str] = &[
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/manifest+json",
    "application/ld+json",
    "application/wasm",
    "application/x-www-form-urlencoded",
    "image/svg+xml",
    "image/x-icon",
    "font/ttf",
    "font/otf",
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Encoding {
    Brotli,
    Gzip,
}

/// Best encoding the client accepts (`q=0` means "not acceptable").
pub fn negotiate(accept_encoding: &str) -> Option<Encoding> {
    let accepts = |name: &str| {
        accept_encoding.split(',').any(|item| {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim();
            let q = parts.find_map(|p| p.trim().strip_prefix("q=")).and_then(|q| q.trim().parse::<f32>().ok());
            coding.eq_ignore_ascii_case(name) && q != Some(0.0)
        })
    };
    if accepts("br") {
        Some(Encoding::Brotli)
    } else if accepts("gzip") {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

pub fn encode(encoding: Encoding, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 + 64);
    match encoding {
        Encoding::Brotli => {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 4, 22);
            let _ = w.write_all(data);
            drop(w);
        }
        Encoding::Gzip => {
            let mut w = flate2::write::GzEncoder::new(&mut out, flate2::Compression::new(5));
            let _ = w.write_all(data);
            let _ = w.finish();
        }
    }
    out
}

fn compressible(resp: &Response<Body>) -> bool {
    let h = resp.headers();
    let text = |name| h.get(name).and_then(|v: &HeaderValue| v.to_str().ok()).unwrap_or("");
    let ctype = text(header::CONTENT_TYPE).split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    resp.status() == StatusCode::OK
        && !h.contains_key(header::CONTENT_ENCODING)
        && !h.contains_key(header::CONTENT_RANGE)
        && !text(header::CACHE_CONTROL).contains("no-transform")
        && (ctype.starts_with("text/") || COMPRESSIBLE.contains(&ctype.as_str()))
}

/// Compress the response body when the client supports it and it is worth
/// it: a compressible type of known, moderate size that shrinks.
pub async fn apply(accept_encoding: Option<String>, head: bool, resp: Response<Body>) -> Response<Body> {
    let Some(encoding) = accept_encoding.as_deref().and_then(negotiate) else { return resp };
    let size = hyper::body::Body::size_hint(resp.body()).exact();
    if head || !compressible(&resp) || !size.is_some_and(|s| (MIN_SIZE..=MAX_SIZE).contains(&s)) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(data) = collect_limited(body, MAX_SIZE as usize).await else {
        return super::page(502, super::ORIGIN_ERROR, &super::ORIGIN_BAD_RESPONSE.to_string(), "-");
    };
    let packed = if data.len() > 64 * 1024 {
        let input = data.clone();
        tokio::task::spawn_blocking(move || encode(encoding, &input)).await.unwrap_or_default()
    } else {
        encode(encoding, &data)
    };
    parts.headers.append(header::VARY, HeaderValue::from_static("accept-encoding"));
    if packed.is_empty() || packed.len() >= data.len() {
        return Response::from_parts(parts, full(data));
    }
    let name = if encoding == Encoding::Brotli { "br" } else { "gzip" };
    parts.headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(name));
    parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(packed.len()));
    // the bytes changed, so a strong validator no longer holds
    let etag = parts.headers.get(header::ETAG).and_then(|v| v.to_str().ok()).filter(|e| !e.starts_with("W/"));
    if let Some(weak) = etag.and_then(|e| HeaderValue::from_str(&format!("W/{e}")).ok()) {
        parts.headers.insert(header::ETAG, weak);
    }
    Response::from_parts(parts, full(packed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        assert_eq!(negotiate("gzip, deflate, br"), Some(Encoding::Brotli));
        assert_eq!(negotiate("gzip;q=0.8, br;q=0"), Some(Encoding::Gzip));
        assert_eq!(negotiate("deflate"), None);
        assert_eq!(negotiate("GZIP"), Some(Encoding::Gzip));
        assert_eq!(negotiate(""), None);
    }

    #[test]
    fn round_trips() {
        let data = "hello fucf ".repeat(500);
        let gz = encode(Encoding::Gzip, data.as_bytes());
        let mut out = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&gz[..]), &mut out).unwrap();
        assert!(out == data && gz.len() < data.len() / 5);
        let br = encode(Encoding::Brotli, data.as_bytes());
        let mut out = Vec::new();
        brotli::BrotliDecompress(&mut &br[..], &mut out).unwrap();
        assert!(out == data.as_bytes() && br.len() < data.len() / 5);
    }
}
