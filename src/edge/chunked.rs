//! Large objects kept in the edge cache in chunks (the zone setting
//! `cache_chunking`: objects of at least that many bytes).
//!
//! An object kept in chunks is one entry under the object's key, which holds
//! its status, headers, freshness and tags but no body (its piece is
//! [`Piece::Meta`]), and one entry per [`CHUNK`] bytes under
//! [`chunk_key`]. Memory and disk keep and drop chunks one by one, like any
//! other entry, so a large object no longer has to fit in a tier as a whole,
//! and a range request reads only the chunks it covers.
//!
//! What keeps this correct:
//! - Every fill gets a new id, carried by the entry and by each chunk; a
//!   chunk is only used with the entry of its own fill and only at its exact
//!   length, so two versions of an object are never served together.
//! - Chunks are stored before their entry, so the entry is never seen
//!   without the chunks it was cut with (they may still go later).
//! - A chunk the cache let go is fetched again with a range request for
//!   exactly the missing chunks and `If-Range` with the entry's validator;
//!   the answer is used only when it is a `206` for exactly those bytes of
//!   an object of the same length, entity tag and date (see [`answer_fits`]).
//!   Anything else is answered as if chunks did not exist (see [`Refill`]).
//! - Only whole `200` answers of announced length, without a
//!   `Content-Encoding`, are kept in chunks, at most
//!   crate::edge::cache::MAX_OBJECT bytes like every cached object.
//!
//! The body is still read from the origin in full before the visitor gets
//! its first byte, as for every object the cache stores; it is cut into
//! chunks as it is read (each chunk its own allocation, so that one can be
//! let go without the others), and the visitor is answered from those same
//! chunks. Passing it on while it is read is left for later.

use super::cache::{self, Cache, Entry, Piece};
use super::upstream::Target;
use super::{etag_matches, full, unchanged_since, Body, BoxError, Conditional, Edge};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bytes per chunk (the last chunk of an object holds what is left).
pub const CHUNK: u64 = 512 * 1024;

/// First and last byte (inclusive) of chunk `n` of an object of `total`
/// bytes; `None` for a chunk past its end.
pub fn bounds(n: u64, total: u64) -> Option<(u64, u64)> {
    let first = n.checked_mul(CHUNK)?;
    (first < total).then(|| (first, first.saturating_add(CHUNK).min(total) - 1))
}

/// The first and last chunk that hold bytes `first..=last`.
pub fn chunks_for(first: u64, last: u64) -> (u64, u64) {
    (first / CHUNK, last / CHUNK)
}

/// Where chunk `n` of the object whose entry is under `base` is kept.
/// `base` is the key the entry is under ([`Cache::shared_key`]); the
/// suffix makes it a key no request has (those end in their compression
/// part), and chunks are only ever read with [`Cache::lookup_exact`].
pub fn chunk_key(base: &str, n: u64) -> String {
    format!("{base}|chunk:{n}")
}

/// Is an answer kept in chunks (as it comes in) when the setting is
/// `threshold`? A whole `200` of announced length from `threshold` bytes up
/// to the largest object the cache keeps, sent as it is (a range of a
/// compressed body is a range of the compressed bytes: not worth it).
pub fn applies(threshold: u64, len: u64, status: StatusCode, headers: &HeaderMap) -> bool {
    threshold > 0
        && len >= threshold
        && len <= cache::MAX_OBJECT
        && status == StatusCode::OK
        && !headers.contains_key(header::CONTENT_ENCODING)
}

/// The fill id and length of an entry of an object kept in chunks, if it is
/// one and a sound one (a `200` with an empty body and a length).
fn meta_of(entry: &Entry) -> Option<(&str, u64)> {
    match &entry.piece {
        Some(Piece::Meta { fill, total }) if entry.status == StatusCode::OK && entry.body.is_empty() && *total > 0 => Some((fill, *total)),
        _ => None,
    }
}

/// Take apart what a lookup found: an ordinary entry (first), or the entry
/// of an object kept in chunks (second; only while the zone keeps objects
/// in chunks, `on`). Either way nothing else of chunks reaches the ordinary
/// cache path: a chunked entry served as an ordinary one would be an empty
/// body. With `on` false a chunked entry counts as a miss, and the answer
/// fetched then replaces it.
pub(super) fn split(found: Option<Arc<Entry>>, on: bool) -> (Option<Arc<Entry>>, Option<Arc<Entry>>) {
    match found {
        Some(entry) if entry.piece.is_some() => (None, Some(entry).filter(|e| on && meta_of(e).is_some())),
        other => (other, None),
    }
}

/// What a request asks of an object of `total` bytes, decided exactly as
/// crate::edge::cached_response decides it for a whole entry.
#[derive(Debug, PartialEq)]
enum Want {
    NotModified,
    Whole,
    /// First and last byte, inclusive.
    Part(u64, u64),
    Unsatisfiable,
}

fn want(meta: &Entry, total: u64, cond: &Conditional) -> Want {
    let validator_hit = match (&cond.none_match, &cond.modified_since) {
        (Some(inm), _) => meta.headers.get(header::ETAG).is_some_and(|etag| etag_matches(inm, etag)),
        (None, Some(since)) => meta.headers.get(header::LAST_MODIFIED).is_some_and(|modified| unchanged_since(modified, since)),
        _ => false,
    };
    if validator_hit {
        return Want::NotModified;
    }
    // A range only applies to the version the client has a part of.
    let same_version = cond.if_range.as_ref().is_none_or(|v| {
        meta.headers.get(header::ETAG) == Some(v) || meta.headers.get(header::LAST_MODIFIED) == Some(v)
    });
    let range = cond.range.as_ref().filter(|_| same_version).and_then(|v| v.to_str().ok());
    match range.map(|r| cache::parse_range(r, total)) {
        Some(cache::Range::Part(first, last)) => Want::Part(first, last),
        Some(cache::Range::Unsatisfiable) => Want::Unsatisfiable,
        _ => Want::Whole,
    }
}

/// The bytes a request needs from the chunks, if any.
fn span(want: &Want, total: u64, method: &Method) -> Option<(u64, u64)> {
    match want {
        _ if method == Method::HEAD => None,
        Want::Whole => Some((0, total - 1)),
        Want::Part(first, last) => Some((*first, *last)),
        Want::NotModified | Want::Unsatisfiable => None,
    }
}

/// Does a cached chunk belong to this fill, at this place, at its full length?
fn chunk_ok(entry: &Entry, fill: &str, n: u64, total: u64) -> bool {
    let at = matches!(&entry.piece, Some(Piece::Chunk { fill: f, n: m }) if f == fill && *m == n);
    at && bounds(n, total).is_some_and(|(first, last)| entry.body.len() as u64 == last - first + 1)
}

/// Chunks `first..=last` of a fill as the cache has them (`None`: missing,
/// or not of this fill).
async fn gather(cache: &Cache, base: &str, fill: &str, total: u64, first: u64, last: u64) -> Vec<Option<Bytes>> {
    let mut out = Vec::new();
    for n in first..=last {
        let found = cache.lookup_exact(&chunk_key(base, n)).await;
        out.push(found.filter(|e| chunk_ok(e, fill, n, total)).map(|e| e.body.clone()));
    }
    out
}

/// Bytes `first..=last` of the object, out of its chunks `chunks_for(first, last)` in order.
fn cut(chunks: Vec<Bytes>, first: u64, last: u64) -> Vec<Bytes> {
    let (from, _) = chunks_for(first, last);
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let start = (from + i as u64) * CHUNK;
            let end = start + chunk.len() as u64 - 1;
            chunk.slice((first.max(start) - start) as usize..=(last.min(end) - start) as usize)
        })
        .collect()
}

/// The answer to a request, from the entry and the pieces of body it needs:
/// the same status and headers crate::edge::cached_response gives for the
/// object as one entry.
fn answer(meta: &Entry, total: u64, want: &Want, method: &Method, pieces: Vec<Bytes>, label: &'static str) -> Response<Body> {
    let mut headers = meta.headers.clone();
    let status = match want {
        Want::NotModified => {
            headers.remove(header::CONTENT_LENGTH);
            StatusCode::NOT_MODIFIED
        }
        Want::Whole => StatusCode::OK,
        Want::Part(..) => StatusCode::PARTIAL_CONTENT,
        Want::Unsatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
    };
    if *want != Want::NotModified {
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }
    let content_range = match want {
        Want::Part(first, last) => Some((format!("bytes {first}-{last}/{total}"), last - first + 1)),
        Want::Unsatisfiable => Some((format!("bytes */{total}"), 0)),
        _ => None,
    };
    if let Some((value, len)) = content_range {
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(header::CONTENT_RANGE, value);
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        }
    }
    let body = if method == Method::HEAD || pieces.is_empty() { full(Bytes::new()) } else { Pieces::new(pieces).boxed() };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = headers;
    resp.headers_mut().insert(header::AGE, HeaderValue::from(meta.stored.elapsed().as_secs()));
    resp.headers_mut().insert("fcf-cache-status", HeaderValue::from_static(label));
    resp
}

/// Answer from an object kept in chunks, if the cache has every chunk the
/// request needs (a `HEAD`, a `304` or a `416` needs none).
pub(super) async fn serve(cache: &Cache, key: &str, meta: &Entry, method: &Method, cond: &Conditional, label: &'static str) -> Option<Response<Body>> {
    let (fill, total) = meta_of(meta)?;
    let want = want(meta, total, cond);
    let Some((first, last)) = span(&want, total, method) else {
        return Some(answer(meta, total, &want, method, Vec::new(), label));
    };
    let (from, to) = chunks_for(first, last);
    let chunks: Option<Vec<Bytes>> = gather(cache, &Cache::shared_key(key), fill, total, from, to).await.into_iter().collect();
    Some(answer(meta, total, &want, method, cut(chunks?, first, last), label))
}

/// Read a body of `len` bytes, cut into chunks: [`CHUNK`] bytes each, the
/// last one what is left. A body longer or shorter than `len` is an error.
pub(super) async fn read_chunks<B>(mut body: B, len: u64) -> Result<Vec<Bytes>, BoxError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let room = |read: u64| (len - read).min(CHUNK) as usize;
    let (mut out, mut read) = (Vec::new(), 0u64);
    let mut current: Vec<u8> = Vec::with_capacity(room(0));
    while let Some(frame) = body.frame().await {
        let Ok(mut data) = frame.map_err(Into::into)?.into_data() else { continue };
        if data.len() as u64 > len - read {
            return Err("the body is longer than announced".into());
        }
        while !data.is_empty() {
            let take = (CHUNK as usize - current.len()).min(data.len());
            current.extend_from_slice(&data.split_to(take));
            read += take as u64;
            if current.len() as u64 == CHUNK {
                out.push(Bytes::from(std::mem::replace(&mut current, Vec::with_capacity(room(read)))));
            }
        }
    }
    if read != len {
        return Err("the body is shorter than announced".into());
    }
    if !current.is_empty() {
        out.push(Bytes::from(current));
    }
    Ok(out)
}

/// The headers a chunk carries: the object's `Cache-Tag`s, so that a purge
/// by tag finds its chunks too (purges by URL, host and zone find them by
/// the URL and zone every chunk has).
fn chunk_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for value in headers.get_all("cache-tag") {
        out.append("cache-tag", value.clone());
    }
    out
}

/// What the entry and the chunks of one fill have in common.
struct Fill<'a> {
    cache: &'a Cache,
    base: String,
    fill: String,
    tags: HeaderMap,
    stored: Instant,
    ttl: Duration,
    zone_id: String,
    url: String,
}

impl Fill<'_> {
    fn put(&self, n: u64, body: Bytes) {
        let piece = Some(Piece::Chunk { fill: self.fill.clone(), n });
        let entry = Entry { status: StatusCode::OK, headers: self.tags.clone(), body, stored: self.stored, ttl: self.ttl, zone_id: self.zone_id.clone(), url: self.url.clone(), piece };
        self.cache.put_exact(chunk_key(&self.base, n), entry);
    }
}

/// What an object kept in chunks is stored with.
pub(super) struct Object<'a> {
    pub key: &'a str,
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
    pub ttl: Duration,
    pub zone_id: &'a str,
    pub url: String,
}

/// Read an origin's answer of `len` bytes into chunks, keep them and then
/// the object's entry, and give the body to pass on to the visitor (made of
/// the same chunks).
pub(super) async fn fill<B>(cache: &Cache, object: Object<'_>, body: B, len: u64) -> Result<Body, BoxError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let chunks = read_chunks(body, len).await?;
    let fill = uuid::Uuid::new_v4().simple().to_string();
    let base = Cache::shared_key(object.key);
    let stored = Instant::now();
    let f = Fill { cache, base: base.clone(), fill: fill.clone(), tags: chunk_headers(object.headers), stored, ttl: object.ttl, zone_id: object.zone_id.to_string(), url: object.url.clone() };
    for (n, chunk) in chunks.iter().enumerate() {
        f.put(n as u64, chunk.clone());
    }
    let mut headers = object.headers.clone();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    let meta = Entry { status: object.status, headers, body: Bytes::new(), stored, ttl: object.ttl, zone_id: object.zone_id.to_string(), url: object.url, piece: Some(Piece::Meta { fill, total: len }) };
    cache.put_exact(base, meta);
    Ok(Pieces::new(chunks).boxed())
}

/// `bytes first-last/total` of a `Content-Range` header (no other unit, no
/// unknown length, nothing out of order).
pub fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (span, total) = value.trim().strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = span.split_once('-')?;
    let digits = |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u64>().ok()).flatten();
    let (first, last, total) = (digits(first)?, digits(last)?, digits(total)?);
    (first <= last && last < total).then_some((first, last, total))
}

/// The validator the missing chunks of an object are asked for by
/// (`If-Range`): a strong entity tag, else the date of the last change. A
/// weak entity tag alone cannot be used (`If-Range` takes only strong ones).
fn validator(headers: &HeaderMap) -> Option<HeaderValue> {
    let strong = headers.get(header::ETAG).filter(|v| v.to_str().is_ok_and(|t| !t.trim_start().starts_with("W/")));
    strong.or_else(|| headers.get(header::LAST_MODIFIED)).cloned()
}

/// Is an origin's answer to the range request for bytes `first..=last`
/// those very bytes of the version the entry was cut from? A `206` for
/// exactly that span of an object of the same length, sent as it is, with
/// the same entity tag and date as the entry, as far as the entry has them.
pub fn answer_fits(meta: &HeaderMap, total: u64, first: u64, last: u64, status: StatusCode, headers: &HeaderMap) -> bool {
    let range = headers.get(header::CONTENT_RANGE).and_then(|v| v.to_str().ok()).and_then(parse_content_range);
    let same = |name: header::HeaderName| meta.get(&name).is_none_or(|ours| headers.get(&name) == Some(ours));
    let length_ok = headers.get(header::CONTENT_LENGTH).is_none_or(|v| v.to_str().ok().and_then(|v| v.parse::<u64>().ok()) == Some(last - first + 1));
    status == StatusCode::PARTIAL_CONTENT
        && range == Some((first, last, total))
        && !headers.contains_key(header::CONTENT_ENCODING)
        && length_ok
        && same(header::ETAG)
        && same(header::LAST_MODIFIED)
}

/// How a request for an object whose cached chunks are not all there went.
pub(super) enum Refill {
    /// The missing chunks came from the origin; this is the answer.
    Served(Response<Body>),
    /// The entry has no validator to ask for the missing chunks by: it was
    /// dropped, and the request goes on as a miss.
    Refetch,
    /// The origin did not give those chunks of that version (it ignored the
    /// range, the object changed, or it failed): the request goes on as if
    /// chunks did not exist, this once, with the origin's whole answer when
    /// it gave one. The entry was dropped unless the origin just failed.
    Unchunked(Option<Response<Incoming>>),
}

impl Edge {
    /// Fetch the chunks a request needs that the cache let go, with one
    /// range request to the origin (`target`, with the origin request's
    /// `headers` as they were built for it), and answer it.
    pub(super) async fn refill(&self, key: &str, meta: &Entry, method: &Method, cond: &Conditional, target: &Target, headers: &HeaderMap, uri: &hyper::Uri) -> Refill {
        let base = Cache::shared_key(key);
        let Some((fill, total)) = meta_of(meta) else { return Refill::Refetch };
        let want = want(meta, total, cond);
        let Some((first, last)) = span(&want, total, method) else {
            return Refill::Served(answer(meta, total, &want, method, Vec::new(), "HIT"));
        };
        let (from, to) = chunks_for(first, last);
        let mut chunks = gather(&self.cache, &base, fill, total, from, to).await;
        let missing: Vec<u64> = (from..=to).filter(|n| chunks[(n - from) as usize].is_none()).collect();
        let (Some(&lo), Some(&hi)) = (missing.first(), missing.last()) else {
            // they came back meanwhile
            let all = chunks.into_iter().flatten().collect();
            return Refill::Served(answer(meta, total, &want, method, cut(all, first, last), "HIT"));
        };
        let Some(validator) = validator(&meta.headers) else {
            self.cache.remove(&base);
            return Refill::Refetch;
        };
        let (Some((start, _)), Some((_, end))) = (bounds(lo, total), bounds(hi, total)) else { return Refill::Refetch };

        let mut ask = headers.clone();
        for name in [header::RANGE, header::IF_RANGE, header::IF_NONE_MATCH, header::IF_MODIFIED_SINCE, header::IF_MATCH, header::IF_UNMODIFIED_SINCE] {
            ask.remove(name);
        }
        let Ok(range) = HeaderValue::from_str(&format!("bytes={start}-{end}")) else { return Refill::Unchunked(None) };
        ask.insert(header::RANGE, range);
        ask.insert(header::IF_RANGE, validator);
        // ranges are of the bytes as stored, which are not compressed
        ask.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        let mut req = Request::new(full(Bytes::new()));
        *req.method_mut() = Method::GET;
        *req.uri_mut() = uri.clone();
        *req.headers_mut() = ask;
        let resp = match self.upstream.send(target, req).await {
            Ok(resp) => resp,
            Err(_) => return Refill::Unchunked(None),
        };
        if resp.status() == StatusCode::OK {
            // the range was ignored, or the object changed: take it whole, without chunks
            self.cache.remove(&base);
            return Refill::Unchunked(Some(resp));
        }
        if !answer_fits(&meta.headers, total, start, end, resp.status(), resp.headers()) {
            if !resp.status().is_server_error() {
                self.cache.remove(&base);
            }
            return Refill::Unchunked(None);
        }
        let Ok(fetched) = read_chunks(resp.into_body(), end - start + 1).await else { return Refill::Unchunked(None) };
        let f = Fill { cache: &self.cache, base, fill: fill.to_string(), tags: chunk_headers(&meta.headers), stored: meta.stored, ttl: meta.ttl, zone_id: meta.zone_id.clone(), url: meta.url.clone() };
        for (i, chunk) in fetched.into_iter().enumerate() {
            let n = lo + i as u64;
            f.put(n, chunk.clone());
            chunks[(n - from) as usize] = Some(chunk);
        }
        match chunks.into_iter().collect::<Option<Vec<Bytes>>>() {
            Some(all) => Refill::Served(answer(meta, total, &want, method, cut(all, first, last), "MISS")),
            None => Refill::Unchunked(None),
        }
    }
}

/// A body made of pieces already in memory, of exactly known size (as the
/// body of a whole entry is).
pub(super) struct Pieces {
    left: VecDeque<Bytes>,
    size: u64,
}

impl Pieces {
    fn new(pieces: Vec<Bytes>) -> Self {
        let left: VecDeque<Bytes> = pieces.into_iter().filter(|p| !p.is_empty()).collect();
        let size = left.iter().map(|p| p.len() as u64).sum();
        Pieces { left, size }
    }
}

impl hyper::body::Body for Pieces {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        let piece = self.left.pop_front();
        if let Some(p) = &piece {
            self.size -= p.len() as u64;
        }
        std::task::Poll::Ready(piece.map(|p| Ok(hyper::body::Frame::data(p))))
    }
    fn is_end_stream(&self) -> bool {
        self.left.is_empty()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::cached_response;
    use std::convert::Infallible;

    const C: u64 = CHUNK;

    fn headers(pairs: &[(&str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append(header::HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
        }
        h
    }

    /// An object whose bytes differ from chunk to chunk and from version to version.
    fn object(len: u64, version: u64) -> Vec<u8> {
        (0..len).map(|i| b'a' + ((i * 31 + version * 7 + i / C) % 26) as u8).collect()
    }

    /// A body arriving in the given frames.
    struct Frames(VecDeque<Bytes>);

    impl hyper::body::Body for Frames {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
            std::task::Poll::Ready(self.0.pop_front().map(|f| Ok(hyper::body::Frame::data(f))))
        }
    }

    fn frames(data: &[u8], size: usize) -> Frames {
        Frames(data.chunks(size.max(1)).map(Bytes::copy_from_slice).collect())
    }

    fn origin_headers() -> HeaderMap {
        headers(&[
            ("content-type", "video/mp4".into()),
            ("etag", "\"v1\"".into()),
            ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT".into()),
            ("cache-control", "public, max-age=600".into()),
            ("cache-tag", "video, big".into()),
        ])
    }

    const KEY: &str = "https|a.test/v.mp4|ae=gzip";

    async fn store(cache: &Cache, data: &[u8], h: &HeaderMap) {
        let object = Object { key: KEY, status: StatusCode::OK, headers: h, ttl: Duration::from_secs(600), zone_id: "z", url: "a.test/v.mp4".into() };
        let body = fill(cache, object, frames(data, 100_000), data.len() as u64).await.unwrap();
        assert_eq!(body.collect().await.unwrap().to_bytes(), data, "the visitor gets the body it was cut from");
    }

    async fn meta(cache: &Cache) -> Arc<Entry> {
        let (plain, meta) = split(cache.lookup(KEY).await, true);
        assert!(plain.is_none());
        meta.expect("the object's entry")
    }

    async fn parts(resp: Response<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let (p, body) = resp.into_parts();
        let mut h = p.headers;
        h.remove(header::AGE);
        (p.status, h, body.collect().await.unwrap().to_bytes())
    }

    fn entry(body: Bytes, piece: Option<Piece>) -> Entry {
        Entry { status: StatusCode::OK, headers: HeaderMap::new(), body, stored: Instant::now(), ttl: Duration::from_secs(600), zone_id: "z".into(), url: "a.test/v.mp4".into(), piece }
    }

    #[test]
    fn chunk_bounds_and_the_last_partial_chunk() {
        assert_eq!(bounds(0, 0), None, "an empty object has no chunks");
        assert_eq!(bounds(0, 1), Some((0, 0)));
        assert_eq!(bounds(0, C), Some((0, C - 1)), "exactly one chunk");
        assert_eq!(bounds(1, C), None);
        assert_eq!((bounds(1, C + 1), bounds(2, C + 1)), (Some((C, C)), None), "one byte over makes a second chunk");
        assert_eq!((bounds(2, 3 * C), bounds(3, 3 * C)), (Some((2 * C, 3 * C - 1)), None), "exactly three chunks");
        assert_eq!(bounds(3, 3 * C + 5), Some((3 * C, 3 * C + 4)), "the last holds what is left");
        assert_eq!(bounds(u64::MAX, u64::MAX), None, "no overflow");
        assert_eq!(chunks_for(0, 0), (0, 0));
        assert_eq!(chunks_for(C - 1, C), (0, 1), "a range across a boundary takes both");
        assert_eq!(chunks_for(C, 2 * C - 1), (1, 1));
        assert_eq!(chunk_key("https|a.test/x|ae=", 3), "https|a.test/x|ae=|chunk:3");
    }

    #[test]
    fn ranges_map_to_the_chunks_they_cover() {
        let total = 3 * C + 777;
        let m = Entry { headers: origin_headers(), ..entry(Bytes::new(), None) };
        let chunks = |range: &str| {
            let c = Conditional::of(&headers(&[("range", range.to_string())]));
            span(&want(&m, total, &c), total, &Method::GET).map(|(a, b)| chunks_for(a, b))
        };
        assert_eq!(chunks("bytes=0-99"), Some((0, 0)));
        assert_eq!(chunks(&format!("bytes={}-{}", C - 1, C)), Some((0, 1)));
        assert_eq!(chunks("bytes=-100"), Some((3, 3)), "a suffix is at the end");
        assert_eq!(chunks(&format!("bytes=-{}", C + 700)), Some((2, 3)));
        assert_eq!(chunks(&format!("bytes=-{}", C + 800)), Some((1, 3)), "a suffix reaching back past a boundary");
        assert_eq!(chunks(&format!("bytes=-{}", 10 * C)), Some((0, 3)), "a suffix longer than the object is all of it");
        assert_eq!(chunks(&format!("bytes={}-", 2 * C)), Some((2, 3)));
        assert_eq!(chunks(&format!("bytes=10-{}", 99 * C)), Some((0, 3)), "a range past the end stops at it");
        assert_eq!(chunks(&format!("bytes={total}-")), None, "past the end: nothing to read (416)");
        assert_eq!(chunks("bytes=-0"), None);
        assert_eq!(chunks("bytes=0-1,5-6"), Some((0, 3)), "several ranges: the whole object");
        let c = Conditional::of(&headers(&[("range", "bytes=0-9".into())]));
        assert_eq!(span(&want(&m, total, &c), total, &Method::HEAD), None, "a HEAD needs no chunk");
    }

    #[tokio::test]
    async fn bodies_are_cut_at_chunk_boundaries_whatever_the_frames() {
        let data = object(2 * C + 5, 0);
        for size in [1000, C as usize, C as usize + 1, 3 * C as usize] {
            let out = read_chunks(frames(&data, size), data.len() as u64).await.unwrap();
            assert_eq!(out.iter().map(Bytes::len).collect::<Vec<_>>(), [C as usize, C as usize, 5], "frames of {size}");
            assert_eq!(out.concat(), data);
        }
        let small = object(C + 3, 0);
        let out = read_chunks(frames(&small, 7), small.len() as u64).await.unwrap();
        assert_eq!((out.iter().map(Bytes::len).collect::<Vec<_>>(), out.concat()), (vec![C as usize, 3], small), "tiny frames");
        let one = object(C, 1);
        assert_eq!(read_chunks(frames(&one, 4096), C).await.unwrap().len(), 1, "exactly one chunk");
        let three = object(3 * C, 1);
        let out = read_chunks(frames(&three, 4096), 3 * C).await.unwrap();
        assert_eq!(out.iter().map(Bytes::len).collect::<Vec<_>>(), [C as usize; 3], "exactly three chunks");
        assert!(read_chunks(Frames(VecDeque::new()), 0).await.unwrap().is_empty(), "an empty body has no chunks");
        assert!(read_chunks(frames(&data, 1000), data.len() as u64 - 1).await.is_err(), "longer than announced");
        assert!(read_chunks(frames(&data, 1000), data.len() as u64 + 1).await.is_err(), "shorter than announced");
        assert!(read_chunks(frames(b"x", 1), 0).await.is_err());
    }

    #[test]
    fn only_whole_uncompressed_answers_of_their_size_are_kept_in_chunks() {
        let h = HeaderMap::new();
        assert!(applies(C, C, StatusCode::OK, &h));
        assert!(applies(C, cache::MAX_OBJECT, StatusCode::OK, &h));
        assert!(!applies(0, 10 * C, StatusCode::OK, &h), "0 is off");
        assert!(!applies(2 * C, 2 * C - 1, StatusCode::OK, &h), "smaller than the threshold");
        assert!(!applies(C, cache::MAX_OBJECT + 1, StatusCode::OK, &h), "larger than any cached object");
        assert!(!applies(C, 2 * C, StatusCode::NOT_FOUND, &h));
        assert!(!applies(C, 2 * C, StatusCode::PARTIAL_CONTENT, &h));
        assert!(!applies(C, 2 * C, StatusCode::OK, &headers(&[("content-encoding", "gzip".into())])));
    }

    #[test]
    fn content_ranges_are_read_strictly() {
        assert_eq!(parse_content_range("bytes 0-99/1000"), Some((0, 99, 1000)));
        assert_eq!(parse_content_range(" bytes 999-999/1000 "), Some((999, 999, 1000)));
        for bad in ["bytes */1000", "bytes 5-4/1000", "bytes 0-1000/1000", "items 0-1/2", "bytes 0-1/*", "bytes +1-2/3", "bytes 0-1", "bytes -1-2/3", "", "bytes 0 - 1/3"] {
            assert_eq!(parse_content_range(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_range_answer_is_taken_only_for_the_same_version_and_span() {
        let ours = origin_headers();
        let theirs = |extra: &[(&str, String)]| {
            let mut h = headers(&[("content-range", format!("bytes {}-{}/{}", C, 2 * C - 1, 3 * C)), ("etag", "\"v1\"".into()), ("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT".into())]);
            for (name, value) in extra {
                h.insert(header::HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
            }
            h
        };
        let fits = |status: u16, h: &HeaderMap| answer_fits(&ours, 3 * C, C, 2 * C - 1, StatusCode::from_u16(status).unwrap(), h);
        assert!(fits(206, &theirs(&[])));
        assert!(fits(206, &theirs(&[("content-length", C.to_string())])));
        assert!(!fits(200, &theirs(&[])), "a whole answer is not a range");
        assert!(!fits(206, &theirs(&[("etag", "\"v2\"".into())])), "another version");
        assert!(!fits(206, &theirs(&[("last-modified", "Thu, 22 Oct 2015 07:28:00 GMT".into())])), "another date");
        assert!(!fits(206, &theirs(&[("content-range", format!("bytes {}-{}/{}", C, 2 * C - 1, 3 * C + 1))])), "another length");
        assert!(!fits(206, &theirs(&[("content-range", format!("bytes 0-{}/{}", C - 1, 3 * C))])), "another span");
        assert!(!fits(206, &theirs(&[("content-encoding", "gzip".into())])));
        assert!(!fits(206, &theirs(&[("content-length", "5".into())])));
        let mut no_etag = theirs(&[]);
        no_etag.remove(header::ETAG);
        assert!(!fits(206, &no_etag), "the entry's entity tag must come back");
        let mut no_range = theirs(&[]);
        no_range.remove(header::CONTENT_RANGE);
        assert!(!fits(206, &no_range));
        // what the entry does not have is not asked of the answer
        assert!(answer_fits(&HeaderMap::new(), 3 * C, C, 2 * C - 1, StatusCode::PARTIAL_CONTENT, &no_etag));
    }

    #[test]
    fn missing_chunks_are_asked_for_by_a_strong_validator_only() {
        let lm = "Wed, 21 Oct 2015 07:28:00 GMT".to_string();
        assert_eq!(validator(&origin_headers()).unwrap(), "\"v1\"");
        assert_eq!(validator(&headers(&[("etag", "W/\"v1\"".into()), ("last-modified", lm.clone())])).unwrap(), lm.as_str());
        assert_eq!(validator(&headers(&[("last-modified", lm.clone())])).unwrap(), lm.as_str());
        assert_eq!(validator(&headers(&[("etag", "W/\"v1\"".into())])), None);
        assert_eq!(validator(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn a_chunked_object_answers_exactly_as_the_same_object_whole() {
        for total in [C, 2 * C, 3 * C + 777] {
            let data = object(total, 0);
            let cache = Cache::new(64 << 20);
            store(&cache, &data, &origin_headers()).await;
            let meta = meta(&cache).await;
            let mut h = origin_headers();
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(total));
            let plain = Entry { headers: h, stored: meta.stored, ..entry(Bytes::from(data.clone()), None) };
            let mut asks: Vec<Vec<(&str, String)>> = vec![vec![]];
            for range in ["bytes=0-0", "bytes=0-99", "bytes=100-", "bytes=-100", "bytes=0-1,5-6", "bytes=5-1", "bytes=-0", "items=0-1"] {
                asks.push(vec![("range", range.into())]);
            }
            for range in [format!("bytes={}-{}", C - 1, C), format!("bytes={}-", total - 1), format!("bytes={total}-"), format!("bytes=-{}", total + 5), format!("bytes=7-{}", total * 2)] {
                asks.push(vec![("range", range)]);
            }
            asks.push(vec![("range", "bytes=0-9".into()), ("if-range", "\"v1\"".into())]);
            asks.push(vec![("range", "bytes=0-9".into()), ("if-range", "\"v0\"".into())]);
            asks.push(vec![("if-none-match", "\"v1\"".into())]);
            asks.push(vec![("if-none-match", "W/\"v1\", \"x\"".into())]);
            asks.push(vec![("if-none-match", "\"other\"".into()), ("range", "bytes=3-4".into())]);
            asks.push(vec![("if-modified-since", "Thu, 22 Oct 2015 00:00:00 GMT".into())]);
            asks.push(vec![("if-modified-since", "Tue, 20 Oct 2015 00:00:00 GMT".into())]);
            for ask in &asks {
                let c = Conditional::of(&headers(ask));
                for method in [Method::GET, Method::HEAD] {
                    let want = parts(cached_response(&plain, &method, &c, "HIT")).await;
                    let got = parts(serve(&cache, KEY, &meta, &method, &c, "HIT").await.expect("all chunks are there")).await;
                    assert_eq!(got, want, "{total} {method} {ask:?}");
                }
            }
        }
    }

    #[tokio::test]
    async fn chunks_that_are_gone_or_of_another_fill_are_never_served() {
        let data = object(3 * C + 10, 0);
        let cache = Cache::new(64 << 20);
        store(&cache, &data, &origin_headers()).await;
        let meta = meta(&cache).await;
        let base = Cache::shared_key(KEY);
        assert_eq!(base, "https|a.test/v.mp4|ae=", "kept uncompressed, for every compression");
        let none = Conditional::of(&HeaderMap::new());
        let range = |r: &str| Conditional::of(&headers(&[("range", r.to_string())]));

        cache.remove(&chunk_key(&base, 1));
        assert!(serve(&cache, KEY, &meta, &Method::GET, &none, "HIT").await.is_none(), "the whole object needs chunk 1");
        let r = serve(&cache, KEY, &meta, &Method::GET, &range("bytes=0-99"), "HIT").await.expect("chunk 0 is enough");
        assert_eq!(parts(r).await.2, &data[..100]);
        let r = serve(&cache, KEY, &meta, &Method::HEAD, &none, "HIT").await.expect("a HEAD needs no chunk");
        assert_eq!(parts(r).await.1[header::CONTENT_LENGTH], (3 * C + 10).to_string().as_str());
        let c = Conditional::of(&headers(&[("if-none-match", "\"v1\"".into())]));
        assert_eq!(parts(serve(&cache, KEY, &meta, &Method::GET, &c, "HIT").await.unwrap()).await.0, StatusCode::NOT_MODIFIED);

        // a chunk of another fill under the same key: as good as gone
        let Some(Piece::Meta { fill: ours, .. }) = &meta.piece else { panic!("not an entry of chunks") };
        let other = entry(Bytes::from(vec![b'z'; C as usize]), Some(Piece::Chunk { fill: format!("{ours}x"), n: 1 }));
        cache.put_exact(chunk_key(&base, 1), other);
        assert!(serve(&cache, KEY, &meta, &Method::GET, &none, "HIT").await.is_none());
        // ... and so is one of the right fill but the wrong place or length
        let wrong = |n: u64, len: usize| entry(Bytes::from(vec![b'z'; len]), Some(Piece::Chunk { fill: ours.clone(), n }));
        cache.put_exact(chunk_key(&base, 1), wrong(2, C as usize));
        assert!(serve(&cache, KEY, &meta, &Method::GET, &range(&format!("bytes={C}-{C}")), "HIT").await.is_none());
        cache.put_exact(chunk_key(&base, 3), wrong(3, 9));
        assert!(serve(&cache, KEY, &meta, &Method::GET, &range("bytes=-1"), "HIT").await.is_none(), "a short last chunk");

        // a new fill replaces every chunk: all of them are of the new version
        let newer = object(3 * C + 10, 1);
        let mut h = origin_headers();
        h.insert(header::ETAG, HeaderValue::from_static("\"v2\""));
        store(&cache, &newer, &h).await;
        let meta = self::meta(&cache).await;
        assert_eq!(parts(serve(&cache, KEY, &meta, &Method::GET, &none, "HIT").await.unwrap()).await.2, newer);
    }

    #[tokio::test]
    async fn the_entry_of_a_chunked_object_never_passes_for_an_ordinary_one() {
        let cache = Cache::new(64 << 20);
        store(&cache, &object(C, 0), &origin_headers()).await;
        let found = cache.lookup(KEY).await;
        assert!(found.as_ref().is_some_and(|e| e.body.is_empty()));
        assert!(matches!(split(found.clone(), false), (None, None)), "off: a miss");
        assert!(matches!(split(found, true), (None, Some(_))));
        assert!(matches!(split(Some(Arc::new(entry(Bytes::from_static(b"x"), None))), true), (Some(_), None)), "an ordinary entry goes the ordinary way");
        let odd = |status: StatusCode, body: &'static [u8], piece| Some(Arc::new(Entry { status, ..entry(Bytes::from_static(body), Some(piece)) }));
        let meta = |total| Piece::Meta { fill: "f".into(), total };
        assert!(matches!(split(odd(StatusCode::OK, b"", Piece::Chunk { fill: "f".into(), n: 0 }), true), (None, None)), "a chunk is no entry");
        assert!(matches!(split(odd(StatusCode::NOT_FOUND, b"", meta(5)), true), (None, None)));
        assert!(matches!(split(odd(StatusCode::OK, b"body", meta(5)), true), (None, None)));
        assert!(matches!(split(odd(StatusCode::OK, b"", meta(0)), true), (None, None)));
        assert!(matches!(split(None, true), (None, None)));
    }

    /// Is the object's entry gone, and which of its first three chunks are left?
    async fn left(cache: &Cache) -> (bool, Vec<bool>) {
        let base = Cache::shared_key(KEY);
        let mut chunks = Vec::new();
        for n in 0..3 {
            chunks.push(cache.lookup_exact(&chunk_key(&base, n)).await.is_some());
        }
        (cache.lookup(KEY).await.is_none(), chunks)
    }

    #[tokio::test]
    async fn purges_take_the_chunks_with_the_object() {
        let cache = Cache::new(64 << 20);
        let data = object(2 * C + 1, 0);
        store(&cache, &data, &origin_headers()).await;
        assert_eq!(cache.usage().1, 4, "the entry and three chunks");
        assert_eq!(left(&cache).await, (false, vec![true; 3]));
        assert_eq!(cache.purge_tags("z", &["big".into()]), 1, "one object, chunks and all");
        assert_eq!(left(&cache).await, (true, vec![false; 3]));
        store(&cache, &data, &origin_headers()).await;
        assert_eq!(cache.purge_urls("z", &["https://a.test/v.mp4".into()], false), 1);
        assert_eq!(left(&cache).await, (true, vec![false; 3]));
        store(&cache, &data, &origin_headers()).await;
        assert_eq!(cache.purge_urls("z", &["a.test/".into()], true), 1, "by host (a prefix)");
        assert_eq!(left(&cache).await, (true, vec![false; 3]));
        store(&cache, &data, &origin_headers()).await;
        assert_eq!(cache.purge_zone("other"), 0);
        assert_eq!(cache.purge_zone("z"), 1);
        assert_eq!((left(&cache).await, cache.usage().1), ((true, vec![false; 3]), 0));
    }

    #[tokio::test]
    async fn a_chunked_object_survives_a_restart_on_disk_and_goes_with_a_purge() {
        let dir = std::env::temp_dir().join(format!("fucf-chunks-{}", uuid::Uuid::new_v4().simple()));
        let data = object(2 * C + 99, 0);
        let files = |ext: &str| std::fs::read_dir(&dir).unwrap().flatten().filter(|f| f.file_name().to_string_lossy().ends_with(ext)).count();
        {
            // memory smaller than the object: it is whole only on disk
            let cache = Cache::with_disk(C as usize + 4096, dir.clone(), 64 << 20).unwrap();
            store(&cache, &data, &origin_headers()).await;
            cache.flush();
            assert_eq!((files(".k"), files(".c")), (1, 3), "the entry in a .k file, the chunks in .c files");
            let meta = meta(&cache).await;
            let r = serve(&cache, KEY, &meta, &Method::GET, &Conditional::of(&HeaderMap::new()), "HIT").await.expect("read back from disk");
            assert_eq!(parts(r).await.2, data);
        }
        let cache = Cache::with_disk(64 << 20, dir.clone(), 64 << 20).unwrap();
        assert_eq!(cache.usage().1, 4, "a new process finds them all");
        let meta = meta(&cache).await;
        let r = serve(&cache, KEY, &meta, &Method::GET, &Conditional::of(&HeaderMap::new()), "HIT").await.expect("all chunks on disk");
        assert_eq!(parts(r).await.2, data);
        // the same key kept whole again: its .k file goes
        cache.put(KEY.into(), entry(Bytes::from_static(b"whole"), None));
        cache.flush();
        assert_eq!((files(".k"), files(".c")), (0, 4));
        assert_eq!(cache.purge_urls("z", &["https://a.test/v.mp4".into()], false), 1, "the whole copy; its old chunks go with it");
        cache.flush();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_body_of_pieces_tells_its_exact_size() {
        let body = Pieces::new(vec![Bytes::from_static(b"ab"), Bytes::new(), Bytes::from_static(b"cde")]);
        assert_eq!(hyper::body::Body::size_hint(&body).exact(), Some(5));
        assert_eq!(body.boxed().collect().await.unwrap().to_bytes(), "abcde");
    }
}
