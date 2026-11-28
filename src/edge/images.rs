//! Image resizing: `/cdn-cgi/image/<options>/<path>` (zone setting
//! `image_resizing`), in the manner of Cloudflare's image transformations.
//!
//! The original is the zone's own `<path>` (with the request's query): the
//! request is turned into a GET for it before the pipeline runs, so it goes
//! through everything a visitor asking for it directly would meet (the
//! firewall, rate limits, waiting rooms, rules, Workers, the cache, the
//! origin), and nothing else can be fetched this way: an absolute URL is only
//! taken for the request's own host, so the endpoint is no open proxy. The
//! pipeline's answer is then transformed: a `200` JPEG, PNG or WebP is
//! decoded, resized and encoded again on a blocking thread; anything else
//! (errors, redirects, other types, animated images, what is over a limit)
//! goes to the visitor as it came.
//!
//! Options, comma separated, unknown ones and unusable values ignored:
//! `width` / `w`, `height` / `h` (pixels, at most [`MAX_SIDE`]), `fit`
//! (`scale-down`, the default, `contain`, `cover`, `crop`, `pad`),
//! `quality` / `q` (1 to 100, JPEG only; 85 by default) and `format` / `f`
//! (`jpeg`, `png`, `webp`; `auto` and anything else keep the original's).
//! WebP is written lossless (the pure-Rust encoder has no lossy mode).
//!
//! Limits, so that one request cannot take the node's memory: originals of
//! at most [`MAX_INPUT`] bytes and [`MAX_PIXELS`] pixels (read from the
//! header before anything is decoded, against decompression bombs), at most
//! [`MAX_DECODE_BYTES`] for the decoded image, at most [`MAX_SIDE`] pixels
//! a side out, and [`CONCURRENT`] transformations at a time per node.
//!
//! A result is cached under the original's bytes and the options, for as
//! long as the original may be cached; an original the cache may not keep
//! (`DYNAMIC`, `BYPASS`) is transformed every time.

use super::cache::{self, Decision};
use super::{cached_response, full, read_up_to, Body, Conditional, Edge, EdgeError, Prefixed};
use bytes::Bytes;
use hyper::header::{self, HeaderMap, HeaderValue};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageReader, Limits};
use std::io::Cursor;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// The endpoint's path prefix.
pub const PREFIX: &str = "/cdn-cgi/image/";
/// Largest original that is transformed (bytes).
pub const MAX_INPUT: usize = 16 * 1024 * 1024;
/// Largest original that is transformed (pixels, width times height).
pub const MAX_PIXELS: u64 = 50_000_000;
/// The most memory the decoded original may take.
pub const MAX_DECODE_BYTES: u64 = 256 * 1024 * 1024;
/// No side of a result is longer than this.
pub const MAX_SIDE: u32 = 4096;
/// Transformations running at once on a node; more wait for their turn.
pub const CONCURRENT: usize = 2;
/// How long a transformation waits for its turn before the original is sent instead.
const QUEUE_WAIT: Duration = Duration::from_secs(10);
/// JPEG quality when none is asked for.
const DEFAULT_QUALITY: u8 = 85;

static PERMITS: Semaphore = Semaphore::const_new(CONCURRENT);

/// How a result fills the box `width` x `height`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
enum Fit {
    /// Within the box, never enlarged.
    #[default]
    ScaleDown,
    /// Within the box, enlarged if need be.
    Contain,
    /// Fills the box, the rest cut off evenly on both sides.
    Cover,
    /// As `cover` without enlarging: a smaller original is cut to the box, not scaled.
    Crop,
    /// `contain`, then padded to exactly the box (white for JPEG, transparent else).
    Pad,
}

impl Fit {
    fn name(self) -> &'static str {
        match self {
            Fit::ScaleDown => "scale-down",
            Fit::Contain => "contain",
            Fit::Cover => "cover",
            Fit::Crop => "crop",
            Fit::Pad => "pad",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Format {
    Jpeg,
    Png,
    Webp,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::Jpeg => "jpeg",
            Format::Png => "png",
            Format::Webp => "webp",
        }
    }

    fn mime(self) -> &'static str {
        match self {
            Format::Jpeg => "image/jpeg",
            Format::Png => "image/png",
            Format::Webp => "image/webp",
        }
    }

    fn of_image(self) -> image::ImageFormat {
        match self {
            Format::Jpeg => image::ImageFormat::Jpeg,
            Format::Png => image::ImageFormat::Png,
            Format::Webp => image::ImageFormat::WebP,
        }
    }

    /// The format of an image by its first bytes (not by what the origin says).
    fn sniff(data: &[u8]) -> Option<Format> {
        if data.starts_with(&[0xff, 0xd8, 0xff]) {
            Some(Format::Jpeg)
        } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Format::Png)
        } else if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
            Some(Format::Webp)
        } else {
            None
        }
    }
}

/// What a request asks of the original.
#[derive(Debug, Clone, Default, PartialEq)]
struct Options {
    width: Option<u32>,
    height: Option<u32>,
    fit: Fit,
    quality: Option<u8>,
    format: Option<Format>,
}

impl Options {
    /// Read `width=200,fit=cover,...`. Unknown names, values that cannot be
    /// used (`width=abc`, `quality=0`, `format=avif`) and empty parts are
    /// ignored, as the effects the edge does not have are; a size over
    /// [`MAX_SIDE`] is taken as [`MAX_SIDE`].
    fn parse(text: &str) -> Options {
        let mut opts = Options::default();
        for part in text.split(',') {
            let Some((name, value)) = part.split_once('=') else { continue };
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_ascii_lowercase());
            let side = || value.parse::<u32>().ok().filter(|&v| v > 0).map(|v| v.min(MAX_SIDE));
            match name.as_str() {
                "width" | "w" => opts.width = side().or(opts.width),
                "height" | "h" => opts.height = side().or(opts.height),
                "fit" => {
                    opts.fit = match value.as_str() {
                        "scale-down" => Fit::ScaleDown,
                        "contain" => Fit::Contain,
                        "cover" => Fit::Cover,
                        "crop" => Fit::Crop,
                        "pad" => Fit::Pad,
                        _ => opts.fit,
                    }
                }
                "quality" | "q" => opts.quality = value.parse::<u8>().ok().filter(|q| (1..=100).contains(q)).or(opts.quality),
                "format" | "f" => {
                    opts.format = match value.as_str() {
                        "jpeg" | "jpg" => Some(Format::Jpeg),
                        "png" => Some(Format::Png),
                        "webp" => Some(Format::Webp),
                        "auto" => None,
                        _ => opts.format,
                    }
                }
                _ => {}
            }
        }
        opts
    }

    /// The options written one way, for the cache key.
    fn canonical(&self) -> String {
        let num = |v: Option<u32>| v.map_or("-".to_string(), |v| v.to_string());
        format!(
            "w={},h={},fit={},q={},f={}",
            num(self.width),
            num(self.height),
            self.fit.name(),
            self.quality.map_or("-".to_string(), |q| q.to_string()),
            self.format.map_or("auto", Format::name)
        )
    }
}

/// Where in `rest` (the path after [`PREFIX`]) the options end and which
/// path of `host` the original is. Refused: no path, a path on another host
/// (or one written `//...`, which would be read as a host), and the edge's
/// own `/cdn-cgi/` paths.
fn split(rest: &str, host: &str) -> Result<(Options, String), &'static str> {
    let (opts, source) = rest.split_once('/').ok_or("no image path after the options")?;
    let path = match source.strip_prefix("https://").or_else(|| source.strip_prefix("http://")) {
        Some(url) => {
            let (authority, path) = url.split_once('/').unwrap_or((url, ""));
            if authority.contains('@') || super::request_host(authority) != host {
                return Err("only images of this host can be resized");
            }
            format!("/{path}")
        }
        None if source.starts_with('/') => return Err("only images of this host can be resized"),
        None => format!("/{source}"),
    };
    if path == "/" {
        return Err("no image path after the options");
    }
    if super::cgi::endpoint(&path).is_some() {
        return Err("the image cannot be one of the edge's own paths");
    }
    Ok((Options::parse(opts), path))
}

/// A resizing request on its way: what is needed to transform the answer
/// for its original.
pub struct Job {
    opts: Options,
    zone_id: String,
    host: String,
    /// The original's path and query.
    uri: String,
    /// The visitor's method (GET or HEAD).
    method: Method,
    /// The visitor's conditional and range headers, applied to the result.
    cond: Conditional,
}

/// Take a resizing request off its way into the pipeline: a request for
/// [`PREFIX`] on a proxied name of a zone with `image_resizing` on is turned
/// into a GET for the original (without the visitor's conditional and range
/// headers, which apply to the result, and asking for an uncompressed
/// answer), and the job to finish it with [`finish`] comes back. Any other
/// request is given back untouched with `None`.
pub fn take(edge: &Edge, req: Request<Body>) -> (Request<Body>, Option<Result<Job, EdgeError>>) {
    let Some(rest) = req.uri().path().strip_prefix(PREFIX) else { return (req, None) };
    let raw_host = req.uri().host().map(str::to_string).or_else(|| req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(str::to_string));
    let Some(host) = raw_host.map(|h| super::request_host(&h)) else { return (req, None) };
    let snap = edge.store.snapshot();
    let Some(zone) = snap.find_zone(&host).filter(|z| Edge::serves(z, &host) && z.zone.settings.image_resizing) else { return (req, None) };
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return (req, Some(Err(EdgeError::new(405, "Method not allowed", "images are fetched with GET or HEAD"))));
    }
    let (opts, path) = match split(rest, &host) {
        Ok(found) => found,
        Err(why) => return (req, Some(Err(EdgeError::new(400, "Bad request", why)))),
    };
    let uri = match req.uri().query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    let mut target = hyper::Uri::builder();
    if let (Some(scheme), Some(authority)) = (req.uri().scheme(), req.uri().authority()) {
        target = target.scheme(scheme.clone()).authority(authority.clone());
    }
    let Ok(target) = target.path_and_query(uri.as_str()).build() else {
        return (req, Some(Err(EdgeError::new(400, "Bad request", "invalid image path"))));
    };
    let (mut parts, body) = req.into_parts();
    let job = Job { opts, zone_id: zone.zone.id.clone(), host, uri, method: parts.method.clone(), cond: Conditional::of(&parts.headers) };
    parts.uri = target;
    parts.method = Method::GET;
    for name in [header::IF_NONE_MATCH, header::IF_MODIFIED_SINCE, header::IF_MATCH, header::IF_UNMODIFIED_SINCE, header::IF_RANGE, header::RANGE] {
        parts.headers.remove(name);
    }
    parts.headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    (Request::from_parts(parts, body), Some(Ok(job)))
}

/// Why an original went out as it came.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Skip {
    /// Not a JPEG, PNG or WebP.
    Unsupported,
    Animated,
    /// Nothing to do: no size, the same format, no quality.
    Unchanged,
    /// Over [`MAX_INPUT`], [`MAX_PIXELS`] or [`MAX_DECODE_BYTES`].
    TooLarge,
    /// The decoder refused it.
    Broken,
    /// No turn within [`QUEUE_WAIT`].
    Busy,
}

impl Skip {
    fn header(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Skip::Unsupported => "original; unsupported",
            Skip::Animated => "original; animated",
            Skip::Unchanged => "original; unchanged",
            Skip::TooLarge => "original; too-large",
            Skip::Broken => "original; undecodable",
            Skip::Busy => "original; busy",
        })
    }
}

/// A transformed image.
#[derive(Debug)]
struct Output {
    body: Vec<u8>,
    format: Format,
    width: u32,
    height: u32,
}

/// The answer to a resizing request, from the pipeline's answer for the
/// original. Errors and answers other than `200` go out as they are.
pub async fn finish(edge: &Edge, job: Job, answer: Result<Response<Body>, EdgeError>) -> Result<Response<Body>, EdgeError> {
    let resp = answer?;
    let encoded = resp.headers().get(header::CONTENT_ENCODING).is_some_and(|v| v.as_bytes() != b"identity");
    if resp.status() != StatusCode::OK || encoded {
        return Ok(resp);
    }
    let (mut parts, body) = resp.into_parts();
    if hyper::body::Body::size_hint(&body).lower() > MAX_INPUT as u64 {
        parts.headers.insert("fcf-resized", Skip::TooLarge.header());
        return Ok(Response::from_parts(parts, body));
    }
    let data = match read_up_to(body, MAX_INPUT).await {
        Ok((chunks, None)) => Bytes::from(chunks.concat()),
        Ok((chunks, Some(rest))) => {
            parts.headers.insert("fcf-resized", Skip::TooLarge.header());
            return Ok(Response::from_parts(parts, Prefixed { head: chunks.into(), rest }.boxed()));
        }
        Err(e) => return Err(EdgeError::origin(502, super::ORIGIN_BAD_RESPONSE, format!("reading the original image: {e}"))),
    };
    let original = |mut parts: hyper::http::response::Parts, why: Skip, data: Bytes| {
        parts.headers.insert("fcf-resized", why.header());
        Response::from_parts(parts, full(data))
    };
    if Format::sniff(&data).is_none() {
        return Ok(original(parts, Skip::Unsupported, data));
    }
    let key = variant_key(&job, &data);
    let ttl = cache_ttl(&job.uri, &parts.headers);
    if ttl.is_some() {
        if let Some(entry) = edge.cache.lookup_exact(&key).await.filter(|e| e.fresh()) {
            return Ok(cached_response(&entry, &job.method, &job.cond, "HIT"));
        }
    }
    let output = match tokio::time::timeout(QUEUE_WAIT, PERMITS.acquire()).await {
        Ok(Ok(permit)) => {
            let (input, opts) = (data.clone(), job.opts.clone());
            tokio::task::spawn_blocking(move || {
                let _turn = permit;
                transform(&input, &opts)
            })
            .await
            .unwrap_or(Err(Skip::Broken))
        }
        _ => Err(Skip::Busy),
    };
    let output = match output {
        Ok(output) => output,
        Err(why) => return Ok(original(parts, why, data)),
    };
    let entry = cache::Entry {
        status: StatusCode::OK,
        headers: result_headers(&parts.headers, &output, &key),
        body: Bytes::from(output.body),
        stored: Instant::now(),
        ttl: ttl.unwrap_or_default(),
        zone_id: job.zone_id.clone(),
        url: format!("{}{}", job.host, job.uri),
        piece: None,
    };
    let resp = cached_response(&entry, &job.method, &job.cond, "MISS");
    if ttl.is_some() {
        edge.cache.put_exact(key, entry);
    }
    Ok(resp)
}

/// The cache key of a result: the original's name and bytes and the
/// options, hashed (a changed original gets a new key by itself; the key
/// holds nothing a URL could inject).
fn variant_key(job: &Job, data: &[u8]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for part in [job.host.as_bytes(), b"\0", job.uri.as_bytes(), b"\0", job.opts.canonical().as_bytes(), b"\0", data] {
        ctx.update(part);
    }
    let hex: String = ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("img|{hex}")
}

/// How long a result may be cached: as long as the original could be,
/// `None` when the cache does not keep the original (`DYNAMIC`, `BYPASS`,
/// or what the origin's headers forbid).
fn cache_ttl(uri: &str, headers: &HeaderMap) -> Option<Duration> {
    let label = headers.get("fcf-cache-status").and_then(|v| v.to_str().ok())?;
    if matches!(label, "DYNAMIC" | "BYPASS") {
        return None;
    }
    let path = uri.split('?').next().unwrap_or(uri);
    match cache::decide(path, StatusCode::OK, headers, true, None, &[]) {
        Decision::Store(ttl) => Some(ttl),
        _ => None,
    }
}

/// The original's headers, made true of the result: its type, length and
/// an entity tag of its own (from the key, so equal results match); what
/// described the original's bytes goes.
fn result_headers(original: &HeaderMap, output: &Output, key: &str) -> HeaderMap {
    let mut headers = original.clone();
    for name in [header::CONTENT_LENGTH, header::CONTENT_ENCODING, header::CONTENT_RANGE, header::ACCEPT_RANGES, header::ETAG, header::AGE, header::VARY] {
        headers.remove(name);
    }
    headers.remove("fcf-cache-status");
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(output.format.mime()));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(output.body.len()));
    if let Ok(tag) = HeaderValue::from_str(&format!("\"{}\"", &key[4..36])) {
        headers.insert(header::ETAG, tag);
    }
    if let Ok(size) = HeaderValue::from_str(&format!("{}x{}", output.width, output.height)) {
        headers.insert("fcf-resized", size);
    }
    headers
}

/// Whether an image has more than one frame: a PNG with an `acTL` chunk
/// before its image data (APNG), a WebP whose `VP8X` header has the
/// animation flag. Only the first frame would be kept, so these are sent as
/// they are.
fn animated(format: Format, data: &[u8]) -> bool {
    match format {
        Format::Png => {
            let mut at = 8;
            while at + 8 <= data.len() {
                let len = u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) as usize;
                match &data[at + 4..at + 8] {
                    b"acTL" => return true,
                    b"IDAT" | b"IEND" => return false,
                    _ => {}
                }
                at = match at.checked_add(12).and_then(|a| a.checked_add(len)) {
                    Some(next) => next,
                    None => return false,
                };
            }
            false
        }
        Format::Webp => data.len() >= 21 && &data[12..16] == b"VP8X" && data[20] & 0x02 != 0,
        Format::Jpeg => false,
    }
}

/// What to do with an image of `w0` x `h0`: cut out `crop` (x, y, width,
/// height, centred), scale that to `size`, and put it in the middle of a
/// `canvas` (padding) if there is one.
#[derive(Debug, PartialEq)]
struct Plan {
    crop: (u32, u32, u32, u32),
    size: (u32, u32),
    canvas: Option<(u32, u32)>,
}

fn plan(w0: u32, h0: u32, opts: &Options) -> Plan {
    let (fw, fh) = (f64::from(w0), f64::from(h0));
    // never past MAX_SIDE, whatever was asked
    let cap = (f64::from(MAX_SIDE) / fw).min(f64::from(MAX_SIDE) / fh);
    let scaled = |r: f64| (((fw * r).round() as u32).clamp(1, MAX_SIDE), ((fh * r).round() as u32).clamp(1, MAX_SIDE));
    let whole = (0, 0, w0, h0);
    let enlarge = matches!(opts.fit, Fit::Contain | Fit::Cover | Fit::Pad);
    let one_side = |r: f64| Plan { crop: whole, size: scaled(if enlarge { r } else { r.min(1.0) }.min(cap)), canvas: None };
    let (w, h) = match (opts.width, opts.height) {
        (None, None) => return Plan { crop: whole, size: scaled(cap.min(1.0)), canvas: None },
        (Some(w), None) => return one_side(f64::from(w) / fw),
        (None, Some(h)) => return one_side(f64::from(h) / fh),
        (Some(w), Some(h)) => (w, h),
    };
    let (bw, bh) = (f64::from(w), f64::from(h));
    let inside = (bw / fw).min(bh / fh);
    match opts.fit {
        Fit::ScaleDown => Plan { crop: whole, size: scaled(inside.min(1.0)), canvas: None },
        Fit::Contain => Plan { crop: whole, size: scaled(inside), canvas: None },
        Fit::Pad => Plan { crop: whole, size: scaled(inside), canvas: Some((w, h)) },
        Fit::Cover | Fit::Crop => {
            let r = (bw / fw).max(bh / fh);
            if opts.fit == Fit::Crop && r > 1.0 {
                // smaller than the box: cut, do not enlarge
                let (cw, ch) = (w.min(w0), h.min(h0));
                return Plan { crop: ((w0 - cw) / 2, (h0 - ch) / 2, cw, ch), size: (cw, ch), canvas: None };
            }
            // the part of the original that becomes the box
            let cw = ((bw / r).round() as u32).clamp(1, w0);
            let ch = ((bh / r).round() as u32).clamp(1, h0);
            Plan { crop: ((w0 - cw) / 2, (h0 - ch) / 2, cw, ch), size: (w, h), canvas: None }
        }
    }
}

/// Decode, resize and encode again. Runs on a blocking thread.
fn transform(input: &[u8], opts: &Options) -> Result<Output, Skip> {
    let format = Format::sniff(input).ok_or(Skip::Unsupported)?;
    if animated(format, input) {
        return Err(Skip::Animated);
    }
    let out = opts.format.unwrap_or(format);
    if opts.width.is_none() && opts.height.is_none() && out == format && !(out == Format::Jpeg && opts.quality.is_some()) {
        return Err(Skip::Unchanged);
    }
    let mut reader = ImageReader::with_format(Cursor::new(input), format.of_image());
    let mut limits = Limits::default();
    limits.max_alloc = Some(MAX_DECODE_BYTES);
    reader.limits(limits);
    // a decoder that refuses the size for the allocation limit says so here
    let mut decoder = reader.into_decoder().map_err(|e| if matches!(e, image::ImageError::Limits(_)) { Skip::TooLarge } else { Skip::Broken })?;
    let (w0, h0) = decoder.dimensions();
    if w0 == 0 || h0 == 0 {
        return Err(Skip::Broken);
    }
    // from the header, before a single pixel is decoded
    if u64::from(w0) * u64::from(h0) > MAX_PIXELS || decoder.total_bytes() > MAX_DECODE_BYTES {
        return Err(Skip::TooLarge);
    }
    let orientation = decoder.orientation().unwrap_or(image::metadata::Orientation::NoTransforms);
    let icc = decoder.icc_profile().ok().flatten();
    let mut img = DynamicImage::from_decoder(decoder).map_err(|_| Skip::Broken)?;
    // EXIF rotation is applied: it would be lost with the rest of the metadata
    img.apply_orientation(orientation);

    let p = plan(img.width(), img.height(), opts);
    if p.crop != (0, 0, img.width(), img.height()) {
        let (x, y, w, h) = p.crop;
        img = img.crop_imm(x, y, w, h);
    }
    if p.size != (img.width(), img.height()) {
        img = img.resize_exact(p.size.0, p.size.1, image::imageops::FilterType::CatmullRom);
    }
    if let Some((cw, ch)) = p.canvas {
        let background = if out == Format::Jpeg { image::Rgba([255, 255, 255, 255]) } else { image::Rgba([0, 0, 0, 0]) };
        let mut canvas = image::RgbaImage::from_pixel(cw, ch, background);
        let (x, y) = (i64::from(cw.saturating_sub(img.width()) / 2), i64::from(ch.saturating_sub(img.height()) / 2));
        image::imageops::overlay(&mut canvas, &img.to_rgba8(), x, y);
        img = DynamicImage::ImageRgba8(canvas);
    }
    let (width, height) = (img.width(), img.height());
    let body = encode(&img, out, opts.quality.unwrap_or(DEFAULT_QUALITY), icc).ok_or(Skip::Broken)?;
    Ok(Output { body, format: out, width, height })
}

fn encode(img: &DynamicImage, format: Format, quality: u8, icc: Option<Vec<u8>>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let done = match format {
        Format::Jpeg => {
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality);
            if let Some(icc) = icc {
                let _ = encoder.set_icc_profile(icc);
            }
            DynamicImage::ImageRgb8(flatten(img)).write_with_encoder(encoder)
        }
        Format::Png => {
            let mut encoder = image::codecs::png::PngEncoder::new_with_quality(&mut out, image::codecs::png::CompressionType::Default, image::codecs::png::FilterType::Adaptive);
            if let Some(icc) = icc {
                let _ = encoder.set_icc_profile(icc);
            }
            img.write_with_encoder(encoder)
        }
        Format::Webp => {
            let mut encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut out);
            if let Some(icc) = icc {
                let _ = encoder.set_icc_profile(icc);
            }
            let img = if img.has_alpha() { DynamicImage::ImageRgba8(img.to_rgba8()) } else { DynamicImage::ImageRgb8(img.to_rgb8()) };
            img.write_with_encoder(encoder)
        }
    };
    done.ok().map(|_| out)
}

/// RGB for JPEG: what is transparent shows white, as a browser would show
/// the original on a white page (dropping alpha would make it black).
fn flatten(img: &DynamicImage) -> image::RgbImage {
    if !img.has_alpha() {
        return img.to_rgb8();
    }
    let rgba = img.to_rgba8();
    image::RgbImage::from_fn(rgba.width(), rgba.height(), |x, y| {
        let image::Rgba([r, g, b, a]) = *rgba.get_pixel(x, y);
        let over = |c: u8| ((u16::from(c) * u16::from(a) + 255 * (255 - u16::from(a)) + 127) / 255) as u8;
        image::Rgb([over(r), over(g), over(b)])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test picture: the left half red, the right half blue, half transparent at the bottom.
    fn picture(w: u32, h: u32, format: Format) -> Vec<u8> {
        let img = image::RgbaImage::from_fn(w, h, |x, y| image::Rgba([if x < w / 2 { 255 } else { 0 }, 0, if x < w / 2 { 0 } else { 255 }, if y < h / 2 { 255 } else { 128 }]));
        let img = DynamicImage::ImageRgba8(img);
        let img = if format == Format::Jpeg { DynamicImage::ImageRgb8(img.to_rgb8()) } else { img };
        let mut out = Cursor::new(Vec::new());
        img.write_to(&mut out, format.of_image()).unwrap();
        out.into_inner()
    }

    fn decoded(data: &[u8]) -> DynamicImage {
        image::load_from_memory(data).unwrap()
    }

    #[test]
    fn options_take_aliases_and_ignore_what_they_cannot_use() {
        let o = Options::parse("width=200,h=100,fit=cover,q=70,format=webp");
        assert_eq!(o, Options { width: Some(200), height: Some(100), fit: Fit::Cover, quality: Some(70), format: Some(Format::Webp) });
        assert_eq!(Options::parse(" W = 50 , F=JPG ").width, Some(50));
        assert_eq!(Options::parse("f=jpg").format, Some(Format::Jpeg));
        assert_eq!(Options::parse("width=99999").width, Some(MAX_SIDE), "capped, not refused");
        for ignored in ["", ",,,", "width=abc", "width=0", "width=-5", "quality=0", "quality=101", "fit=fill", "format=avif", "format=auto", "blur=10", "rotate=90", "width"] {
            assert_eq!(Options::parse(ignored), Options::default(), "{ignored}");
        }
        assert_eq!(Options::parse("width=10,width=abc").width, Some(10), "a bad repeat keeps the good value");
        assert_eq!(Options::parse("w=1,h=2,fit=pad,q=9,f=png").canonical(), "w=1,h=2,fit=pad,q=9,f=png");
        assert_eq!(Options::default().canonical(), "w=-,h=-,fit=scale-down,q=-,f=auto");
    }

    #[test]
    fn only_paths_of_the_same_host_are_originals() {
        let ok = |rest: &str| split(rest, "img.example.com").map(|(_, path)| path);
        assert_eq!(ok("width=100/photos/a.jpg"), Ok("/photos/a.jpg".into()));
        assert_eq!(ok("/a.jpg"), Ok("/a.jpg".into()), "no options at all");
        assert_eq!(ok("w=1/https://img.example.com/a.jpg"), Ok("/a.jpg".into()));
        assert_eq!(ok("w=1/https://IMG.example.com:443/b/c.png"), Ok("/b/c.png".into()));
        assert_eq!(ok("w=1/http://img.example.com./a.jpg"), Ok("/a.jpg".into()));
        for refused in [
            "width=100",
            "width=100/",
            "w=1/https://other.example.net/a.jpg",
            "w=1/https://img.example.com.evil.example/a.jpg",
            "w=1/https://user@img.example.com/a.jpg",
            "w=1/https://img.example.com",
            "w=1//other.example.net/a.jpg",
            "w=1/cdn-cgi/fucf-trace",
            "w=1/cdn-cgi/image/w=2/a.jpg",
            "w=1/https://img.example.com/cdn-cgi/fucf-trace",
        ] {
            assert!(ok(refused).is_err(), "{refused}");
        }
    }

    fn opts(w: Option<u32>, h: Option<u32>, fit: Fit) -> Options {
        Options { width: w, height: h, fit, ..Options::default() }
    }

    #[test]
    fn each_fit_plans_the_cut_and_the_size() {
        use Fit::*;
        let whole = (0, 0, 800, 400);
        // one side: the other follows; only contain, cover and pad enlarge
        assert_eq!(plan(800, 400, &opts(Some(200), None, ScaleDown)), Plan { crop: whole, size: (200, 100), canvas: None });
        assert_eq!(plan(800, 400, &opts(None, Some(100), ScaleDown)).size, (200, 100));
        assert_eq!(plan(800, 400, &opts(Some(1600), None, ScaleDown)).size, (800, 400));
        assert_eq!(plan(800, 400, &opts(Some(1600), None, Contain)).size, (1600, 800));
        assert_eq!(plan(800, 400, &opts(Some(1600), None, Crop)).size, (800, 400));
        // a box
        assert_eq!(plan(800, 400, &opts(Some(200), Some(200), ScaleDown)).size, (200, 100));
        assert_eq!(plan(800, 400, &opts(Some(2000), Some(2000), ScaleDown)).size, (800, 400));
        assert_eq!(plan(800, 400, &opts(Some(2000), Some(2000), Contain)).size, (2000, 1000));
        assert_eq!(plan(800, 400, &opts(Some(200), Some(200), Pad)), Plan { crop: whole, size: (200, 100), canvas: Some((200, 200)) });
        assert_eq!(plan(800, 400, &opts(Some(200), Some(200), Cover)), Plan { crop: (200, 0, 400, 400), size: (200, 200), canvas: None });
        assert_eq!(plan(800, 400, &opts(Some(200), Some(200), Crop)), Plan { crop: (200, 0, 400, 400), size: (200, 200), canvas: None });
        assert_eq!(plan(100, 100, &opts(Some(400), Some(200), Cover)), Plan { crop: (0, 25, 100, 50), size: (400, 200), canvas: None }, "cover enlarges");
        assert_eq!(plan(100, 100, &opts(Some(400), Some(50), Crop)), Plan { crop: (0, 25, 100, 50), size: (100, 50), canvas: None }, "crop does not");
        // never past MAX_SIDE, nor below one pixel
        assert_eq!(plan(8000, 2000, &opts(None, None, ScaleDown)).size, (4096, 1024));
        assert_eq!(plan(100, 10, &opts(None, Some(4096), Contain)).size, (4096, 410));
        assert_eq!(plan(10_000, 1, &opts(Some(10), None, ScaleDown)).size, (10, 1));
        assert_eq!(plan(1, 10_000, &opts(Some(4096), Some(4096), Cover)), Plan { crop: (0, 4999, 1, 1), size: (4096, 4096), canvas: None }, "a thin cut, never a huge middle step");
    }

    #[test]
    fn animated_images_are_told_by_their_headers() {
        let png = picture(4, 4, Format::Png);
        assert!(!animated(Format::Png, &png));
        // an acTL chunk right after IHDR (8 + 25 bytes), as APNG has it
        let mut apng = png[..33].to_vec();
        apng.extend_from_slice(&[0, 0, 0, 8]);
        apng.extend_from_slice(b"acTL\0\0\0\x02\0\0\0\0");
        apng.extend_from_slice(&[0; 4]);
        apng.extend_from_slice(&png[33..]);
        assert!(animated(Format::Png, &apng));
        assert!(!animated(Format::Png, &png[..20]), "a cut file is not");
        let mut huge = png[..8].to_vec();
        huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        huge.extend_from_slice(b"tEXt");
        assert!(!animated(Format::Png, &huge), "a chunk length past the end stops the walk");

        let mut webp = b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0".to_vec();
        webp.extend_from_slice(&[0x02, 0, 0, 0]);
        assert!(animated(Format::Webp, &webp));
        webp[20] = 0x10;
        assert!(!animated(Format::Webp, &webp));
        assert!(!animated(Format::Webp, &picture(4, 4, Format::Webp)));
    }

    #[test]
    fn images_are_resized_and_converted() {
        let png = picture(400, 200, Format::Png);
        let out = transform(&png, &opts(Some(100), None, Fit::ScaleDown)).unwrap();
        assert_eq!((out.format, out.width, out.height), (Format::Png, 100, 50));
        let img = decoded(&out.body);
        assert_eq!((img.width(), img.height()), (100, 50));
        assert_eq!(img.to_rgba8().get_pixel(10, 10).0, [255, 0, 0, 255], "the left stays red");
        assert_eq!(img.to_rgba8().get_pixel(90, 40).0[2], 255, "the right stays blue");

        let jpeg = transform(&png, &Options { format: Some(Format::Jpeg), quality: Some(90), ..opts(Some(40), Some(40), Fit::Pad) }).unwrap();
        assert!(jpeg.body.starts_with(&[0xff, 0xd8, 0xff]) && (jpeg.width, jpeg.height) == (40, 40));
        let px = decoded(&jpeg.body).to_rgb8();
        assert!(px.get_pixel(20, 2).0.iter().all(|&c| c > 240), "padding is white in JPEG: {:?}", px.get_pixel(20, 2));

        let webp = transform(&png, &Options { format: Some(Format::Webp), ..opts(Some(50), Some(50), Fit::Cover) }).unwrap();
        assert_eq!(Format::sniff(&webp.body), Some(Format::Webp));
        assert_eq!((decoded(&webp.body).width(), decoded(&webp.body).height()), (50, 50));

        let from_jpeg = transform(&picture(300, 300, Format::Jpeg), &opts(Some(30), None, Fit::ScaleDown)).unwrap();
        assert_eq!((from_jpeg.format, from_jpeg.width), (Format::Jpeg, 30));
        let reencoded = transform(&picture(300, 300, Format::Jpeg), &Options { quality: Some(20), ..Options::default() }).unwrap();
        assert_eq!(reencoded.width, 300, "quality alone re-encodes a JPEG");
    }

    #[test]
    fn what_cannot_or_need_not_be_transformed_is_left_alone() {
        let png = picture(64, 64, Format::Png);
        assert_eq!(transform(&png, &Options::default()).unwrap_err(), Skip::Unchanged);
        assert_eq!(transform(&png, &Options { quality: Some(50), ..Options::default() }).unwrap_err(), Skip::Unchanged, "quality means nothing to PNG");
        assert_eq!(transform(&png, &Options { format: Some(Format::Png), ..Options::default() }).unwrap_err(), Skip::Unchanged);
        assert_eq!(transform(b"GIF89a\x01\0\x01\0", &opts(Some(1), None, Fit::ScaleDown)).unwrap_err(), Skip::Unsupported);
        assert_eq!(transform(b"<html></html>", &opts(Some(1), None, Fit::ScaleDown)).unwrap_err(), Skip::Unsupported);
        assert_eq!(transform(&png[..40], &opts(Some(1), None, Fit::ScaleDown)).unwrap_err(), Skip::Broken);
        let mut jpeg = picture(64, 64, Format::Jpeg);
        jpeg.truncate(30);
        assert_eq!(transform(&jpeg, &opts(Some(1), None, Fit::ScaleDown)).unwrap_err(), Skip::Broken);
    }

    /// A PNG header for an image of `w` x `h` and no pixels at all: a
    /// decompression bomb is refused before anything is decoded.
    fn png_header(w: u32, h: u32) -> Vec<u8> {
        let mut ihdr = b"IHDR".to_vec();
        ihdr.extend_from_slice(&w.to_be_bytes());
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        let crc = crc(&ihdr);
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0d".to_vec();
        png.extend_from_slice(&ihdr);
        png.extend_from_slice(&crc.to_be_bytes());
        // the start of an IDAT chunk, where a decoder stops reading the header
        png.extend_from_slice(b"\0\0\0\x0bIDAT\x78\x9c");
        png
    }

    fn crc(data: &[u8]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }

    #[test]
    fn too_many_pixels_are_refused_from_the_header_alone() {
        assert_eq!(transform(&png_header(10_000, 10_000), &opts(Some(10), None, Fit::ScaleDown)).unwrap_err(), Skip::TooLarge);
        assert_eq!(transform(&png_header(50_001, 1000), &opts(Some(10), None, Fit::ScaleDown)).unwrap_err(), Skip::TooLarge);
        // within the limit, the missing pixels are what fails
        assert_eq!(transform(&png_header(100, 100), &opts(Some(10), None, Fit::ScaleDown)).unwrap_err(), Skip::Broken);
    }
}
