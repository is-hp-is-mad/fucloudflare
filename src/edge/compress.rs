//! Edge response compression (brotli / zstd / gzip), negotiated per client.

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

/// zstd level for answers compressed on the way out: fast, close to
/// brotli 4 in size. Kept low so a burst of large answers does not eat
/// the CPU; at this level and with bodies capped at [`MAX_SIZE`] the window
/// stays far below the 8 MiB browsers accept (RFC 9659).
const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Encoding {
    Brotli,
    Zstd,
    Gzip,
}

impl Encoding {
    /// The `Content-Encoding` token.
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Zstd => "zstd",
            Encoding::Gzip => "gzip",
        }
    }
}

/// Whether `accept_encoding` names the coding `name` with a non-zero
/// q-value (`q=0` means "not acceptable"). The cache keys answers by the
/// same test, so what one visitor got is only served to another that
/// accepts it too.
pub fn accepts(accept_encoding: &str, name: &str) -> bool {
    accept_encoding.split(',').any(|item| {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or("").trim();
        let q = parts.find_map(|p| p.trim().strip_prefix("q=")).and_then(|q| q.trim().parse::<f32>().ok());
        coding.eq_ignore_ascii_case(name) && q != Some(0.0)
    })
}

/// Best encoding the client accepts. The order is fixed, whatever the
/// q-values above zero say: brotli first (as before zstd was added, so
/// browsers that take both keep getting what they got), then zstd, then
/// gzip.
pub fn negotiate(accept_encoding: &str) -> Option<Encoding> {
    [Encoding::Brotli, Encoding::Zstd, Encoding::Gzip].into_iter().find(|e| accepts(accept_encoding, e.name()))
}

pub fn encode(encoding: Encoding, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 3 + 64);
    match encoding {
        Encoding::Brotli => {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 4, 22);
            let _ = w.write_all(data);
            drop(w);
        }
        // a failure leaves the output empty, which `apply` takes as "send it as it is"
        Encoding::Zstd => out = zstd::bulk::compress(data, ZSTD_LEVEL).unwrap_or_default(),
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
pub async fn apply(accept_encoding: Option<String>, head: bool, resp: Response<Body>, ctx: impl FnOnce() -> super::PageCtx) -> Response<Body> {
    let Some(encoding) = accept_encoding.as_deref().and_then(negotiate) else { return resp };
    let size = hyper::body::Body::size_hint(resp.body()).exact();
    if head || !compressible(&resp) || !size.is_some_and(|s| (MIN_SIZE..=MAX_SIZE).contains(&s)) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(data) = collect_limited(body, MAX_SIZE as usize).await else {
        return super::page(502, super::ORIGIN_ERROR, "", "-", &ctx());
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
    parts.headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding.name()));
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
    fn zstd_comes_after_brotli_and_before_gzip() {
        assert_eq!(negotiate("gzip, deflate, br, zstd"), Some(Encoding::Brotli), "browsers that take both keep getting brotli");
        assert_eq!(negotiate("gzip, zstd"), Some(Encoding::Zstd));
        assert_eq!(negotiate("ZSTD;q=0.5"), Some(Encoding::Zstd));
        assert_eq!(negotiate("br;q=0, zstd;q=0.1, gzip"), Some(Encoding::Zstd));
        assert_eq!(negotiate("zstd;q=0, gzip"), Some(Encoding::Gzip));
        assert_eq!(negotiate("zstd;q=0"), None);
        assert_eq!(negotiate("zstdx, xzstd"), None, "only the whole token counts");
    }

    #[test]
    fn acceptance_reads_the_q_value_of_each_coding() {
        assert!(accepts("gzip;q=0.001", "gzip"));
        assert!(!accepts("gzip;q=0", "gzip"));
        assert!(!accepts("gzip; q=0.0", "gzip"));
        assert!(accepts("gzip;q=0, gzip", "gzip"), "any acceptable mention is enough");
        assert!(!accepts("br", "gzip") && !accepts("", "gzip"));
        assert!(accepts(" Br ", "br"));
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
        let zs = encode(Encoding::Zstd, data.as_bytes());
        assert!(zs.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]), "a zstd frame");
        assert!(zstd::stream::decode_all(&zs[..]).unwrap() == data.as_bytes() && zs.len() < data.len() / 5);
    }

    #[tokio::test]
    async fn a_zstd_client_gets_a_zstd_body_and_a_weak_etag() {
        let text = "fucf zstd body ".repeat(400);
        let resp = Response::builder()
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::ETAG, "\"v1\"")
            .body(full(bytes::Bytes::from(text.clone())))
            .unwrap();
        let out = apply(Some("gzip;q=0, zstd".into()), false, resp, || unreachable!("the body is read in full")).await;
        assert_eq!(out.headers()[header::CONTENT_ENCODING], "zstd");
        assert_eq!(out.headers()[header::ETAG], "W/\"v1\"");
        let body = http_body_util::BodyExt::collect(out.into_body()).await.unwrap().to_bytes();
        assert_eq!(zstd::stream::decode_all(&body[..]).unwrap(), text.as_bytes());
    }
}
