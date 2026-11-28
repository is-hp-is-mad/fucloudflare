//! Script uploads in the shape `wrangler deploy` sends them.
//!
//! wrangler 4 puts `PUT /accounts/{id}/workers/scripts/{name}` as
//! `multipart/form-data`: a `metadata` part (JSON naming the entry file in
//! `main_module`, or `body_part` for a service-worker script) and one part per
//! module, named after the file. `wrangler deploy` bundles with esbuild into a
//! single file by default (and `--no-bundle` uploads the one `main` file), so
//! one module is what a Worker here can be: the runtime has no module loader.
//! Anything that would need more (several modules, wasm, text or data blobs,
//! source maps, bindings or static assets in the metadata) is refused with a
//! message rather than half-deployed.

use serde_json::Value;

/// More parts than this is not a single-file Worker, whatever they are.
const MAX_PARTS: usize = 16;

/// Whether a `Content-Type` value announces a multipart form.
pub fn is_multipart(content_type: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case("multipart/form-data")
}

/// The media type of a header value, without its parameters.
fn media_type(value: &str) -> &str {
    value.split(';').next().unwrap_or("").trim()
}

/// The value of parameter `name` in a header value such as
/// `form-data; name="metadata"`, unquoted. Parameter names are
/// case-insensitive (RFC 2045); a quoted value may hold `;` and `\"`.
fn param(value: &str, name: &str) -> Option<String> {
    let mut rest = value.split_once(';')?.1;
    loop {
        rest = rest.trim_start_matches([' ', '\t', ';']);
        if rest.is_empty() {
            return None;
        }
        let (key, after) = rest.split_once('=')?;
        let after = after.trim_start();
        let (val, next) = if let Some(quoted) = after.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = quoted.char_indices();
            let mut end = None;
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, escaped)) = chars.next() {
                            out.push(escaped);
                        }
                    }
                    '"' => {
                        end = Some(i + 1);
                        break;
                    }
                    c => out.push(c),
                }
            }
            (out, &quoted[end?..])
        } else {
            let (v, n) = after.split_once(';').unwrap_or((after, ""));
            (v.trim().to_string(), n)
        };
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(val);
        }
        rest = next;
    }
}

/// One part of a multipart body.
#[derive(Debug)]
struct Part<'a> {
    name: String,
    content_type: Option<String>,
    data: &'a [u8],
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split a `multipart/form-data` body (RFC 7578 / RFC 2046) into its parts.
fn parse_form<'a>(content_type: &str, body: &'a [u8]) -> Result<Vec<Part<'a>>, String> {
    let boundary = param(content_type, "boundary").ok_or("the multipart upload has no boundary")?;
    if boundary.is_empty() || boundary.len() > 70 {
        return Err("the multipart boundary must be 1 to 70 characters".into());
    }
    let delimiter = format!("--{boundary}");
    let next_delimiter = format!("\r\n--{boundary}");
    // The first delimiter starts the body or follows a preamble line.
    let mut pos = if body.starts_with(delimiter.as_bytes()) {
        delimiter.len()
    } else {
        find(body, next_delimiter.as_bytes()).ok_or("the multipart body has no parts")? + next_delimiter.len()
    };
    let mut parts = Vec::new();
    loop {
        let rest = &body[pos..];
        if rest.starts_with(b"--") {
            return Ok(parts);
        }
        // transport padding, then the line break that ends the delimiter line
        let padding = rest.iter().take_while(|b| matches!(b, b' ' | b'\t')).count();
        let rest = rest[padding..].strip_prefix(b"\r\n").ok_or("malformed multipart delimiter line")?;
        let head_len = find(rest, b"\r\n\r\n").ok_or("a multipart part has no end of headers")?;
        let head = std::str::from_utf8(&rest[..head_len]).map_err(|_| "multipart part headers must be UTF-8")?;
        let content = &rest[head_len + 4..];
        let len = find(content, next_delimiter.as_bytes()).ok_or("the multipart body is not terminated")?;
        if parts.len() == MAX_PARTS {
            return Err(format!("the upload has more than {MAX_PARTS} parts"));
        }
        let mut name = None;
        let mut part_type = None;
        for line in head.split("\r\n") {
            let Some((key, value)) = line.split_once(':') else {
                return Err("malformed multipart part header".into());
            };
            if key.trim().eq_ignore_ascii_case("content-disposition") {
                if !media_type(value).eq_ignore_ascii_case("form-data") {
                    return Err("multipart parts must be form-data".into());
                }
                name = param(value, "name");
            } else if key.trim().eq_ignore_ascii_case("content-type") {
                part_type = Some(value.trim().to_string());
            }
        }
        let name = name.filter(|n| !n.is_empty()).ok_or("a multipart part has no name")?;
        parts.push(Part { name, content_type: part_type, data: &content[..len] });
        pos = body.len() - content.len() + len + next_delimiter.len();
    }
}

/// Whether a part's type is JavaScript the runtime can run: an ES module
/// (`application/javascript+module`, as wrangler labels one) or a classic
/// script (`application/javascript`, a service-worker Worker).
fn is_javascript(content_type: &str) -> bool {
    matches!(
        media_type(content_type).to_ascii_lowercase().as_str(),
        "application/javascript+module" | "text/javascript+module" | "application/javascript" | "text/javascript"
    )
}

/// The script source in a wrangler-style multipart upload, or why it cannot
/// be deployed here. The caller still checks the syntax and stores it.
pub fn module_from_form(content_type: &str, body: &[u8]) -> Result<String, String> {
    let parts = parse_form(content_type, body)?;
    let mut metadata = None;
    let mut modules = Vec::new();
    for part in parts {
        if part.name == "metadata" {
            if metadata.is_some() {
                return Err("the upload has more than one metadata part".into());
            }
            metadata = Some(part);
        } else {
            modules.push(part);
        }
    }
    let metadata = metadata.ok_or("the upload has no metadata part")?;
    let meta: Value = serde_json::from_slice(metadata.data).map_err(|e| format!("the metadata part is not JSON: {e}"))?;
    let meta = meta.as_object().ok_or("the metadata part must be a JSON object")?;
    let main = match (meta.get("main_module"), meta.get("body_part")) {
        (Some(Value::String(m)), None) | (None, Some(Value::String(m))) if !m.is_empty() => m.clone(),
        (Some(_), Some(_)) => return Err("metadata must name either main_module or body_part, not both".into()),
        _ => return Err("metadata must name the script in main_module (or body_part)".into()),
    };
    match meta.get("bindings") {
        None | Some(Value::Null) => {}
        Some(Value::Array(b)) if b.is_empty() => {}
        Some(Value::Array(_)) => {
            return Err(
                "bindings in the upload metadata are not supported: upload without them and set vars, KV and D1 bindings with PATCH /workers/scripts/{name}/settings"
                    .into(),
            )
        }
        Some(_) => return Err("metadata bindings must be an array".into()),
    }
    if meta.get("assets").is_some_and(|a| !a.is_null()) {
        return Err("static assets are not supported".into());
    }
    let module = match modules.as_slice() {
        [] => return Err(format!("the upload has no part named {main:?}")),
        [one] => one,
        _ => {
            return Err(format!(
                "the upload has {} parts besides metadata: only a single-file Worker can run here, so bundle it into one file first (wrangler deploy does by default) and do not upload source maps or wasm, text or data modules",
                modules.len()
            ))
        }
    };
    if module.name != main {
        return Err(format!("the upload names {main:?} as the script but its part is {:?}", module.name));
    }
    let ty = module.content_type.as_deref().unwrap_or("");
    if !is_javascript(ty) {
        let shown = if ty.is_empty() { "no content type" } else { ty };
        return Err(format!("the script part must be JavaScript (application/javascript+module), not {shown}"));
    }
    String::from_utf8(module.data.to_vec()).map_err(|_| "script must be UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CT: &str = "multipart/form-data; boundary=----formdata-undici-0123456789";
    const WORKER: &str = "export default {\r\n  async fetch() { return new Response(\"ok\"); }\r\n};\r\n";

    /// A body as undici (wrangler's HTTP client) writes one: each part with
    /// its disposition and, for files, a type, the content and a CRLF.
    fn form(parts: &[(&str, Option<&str>, Option<&str>, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, filename, ty, data) in parts {
            out.extend_from_slice(b"------formdata-undici-0123456789\r\n");
            let file = filename.map(|f| format!("; filename=\"{f}\"")).unwrap_or_default();
            out.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"{file}\r\n").as_bytes());
            if let Some(ty) = ty {
                out.extend_from_slice(format!("Content-Type: {ty}\r\n").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(data.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"------formdata-undici-0123456789--\r\n");
        out
    }

    fn meta(main: &str) -> String {
        format!(r#"{{"main_module":"{main}","bindings":[],"compatibility_date":"2025-01-01"}}"#)
    }

    #[test]
    fn a_wrangler_upload_with_one_module_yields_that_module_byte_for_byte() {
        let m = meta("worker.js");
        let body = form(&[("metadata", None, None, &m), ("worker.js", Some("worker.js"), Some("application/javascript+module"), WORKER)]);
        assert_eq!(module_from_form(CT, &body).unwrap(), WORKER);
    }

    #[test]
    fn a_service_worker_upload_names_its_script_in_body_part() {
        let m = r#"{"body_part":"script","bindings":[]}"#;
        let src = "addEventListener('fetch', e => e.respondWith(new Response('x')));";
        let body = form(&[("metadata", None, None, m), ("script", Some("script.js"), Some("application/javascript"), src)]);
        assert_eq!(module_from_form(CT, &body).unwrap(), src);
    }

    #[test]
    fn the_part_order_and_a_quoted_boundary_do_not_matter() {
        let m = meta("worker.js");
        let body = form(&[("worker.js", Some("worker.js"), Some("application/javascript+module"), WORKER), ("metadata", None, Some("application/json"), &m)]);
        let ct = "Multipart/Form-Data; charset=utf-8; BOUNDARY=\"----formdata-undici-0123456789\"";
        assert!(is_multipart(ct));
        assert_eq!(module_from_form(ct, &body).unwrap(), WORKER);
    }

    #[test]
    fn a_module_containing_text_that_looks_like_the_boundary_is_kept_whole() {
        let m = meta("worker.js");
        let src = "// ------formdata-undici-0123456789 is only text here\nexport default {};";
        let body = form(&[("metadata", None, None, &m), ("worker.js", Some("worker.js"), Some("application/javascript+module"), src)]);
        assert_eq!(module_from_form(CT, &body).unwrap(), src);
    }

    #[test]
    fn several_modules_wasm_and_source_maps_are_refused() {
        let m = meta("worker.js");
        let js = ("worker.js", Some("worker.js"), Some("application/javascript+module"), WORKER);
        let two = form(&[("metadata", None, None, &m), js, ("util.js", Some("util.js"), Some("application/javascript+module"), "export const a = 1;")]);
        assert!(module_from_form(CT, &two).unwrap_err().contains("bundle it into one file"));
        let map = form(&[("metadata", None, None, &m), js, ("worker.js.map", Some("worker.js.map"), Some("application/source-map"), "{}")]);
        assert!(module_from_form(CT, &map).is_err());
        let wasm = form(&[("metadata", None, None, &meta("a.wasm")), ("a.wasm", Some("a.wasm"), Some("application/wasm"), "\0asm")]);
        assert!(module_from_form(CT, &wasm).unwrap_err().contains("application/wasm"));
        let untyped = form(&[("metadata", None, None, &m), ("worker.js", Some("worker.js"), None, WORKER)]);
        assert!(module_from_form(CT, &untyped).unwrap_err().contains("no content type"));
    }

    #[test]
    fn metadata_that_asks_for_more_than_a_script_is_refused() {
        let js = ("worker.js", Some("worker.js"), Some("application/javascript+module"), WORKER);
        for (m, why) in [
            (r#"{"main_module":"worker.js","bindings":[{"type":"plain_text","name":"A","text":"b"}]}"#, "bindings"),
            (r#"{"main_module":"worker.js","bindings":{}}"#, "array"),
            (r#"{"main_module":"worker.js","assets":{"jwt":"x"}}"#, "assets"),
            (r#"{"main_module":"worker.js","body_part":"worker.js"}"#, "not both"),
            (r#"{"bindings":[]}"#, "main_module"),
            (r#"{"main_module":""}"#, "main_module"),
            (r#"{"main_module":7}"#, "main_module"),
            (r#"["worker.js"]"#, "JSON object"),
            ("not json", "not JSON"),
            (r#"{"main_module":"other.js"}"#, "other.js"),
        ] {
            let body = form(&[("metadata", None, None, m), js]);
            let err = module_from_form(CT, &body).unwrap_err();
            assert!(err.contains(why), "{m}: {err}");
        }
    }

    #[test]
    fn a_missing_or_doubled_metadata_part_is_refused() {
        let js = ("worker.js", Some("worker.js"), Some("application/javascript+module"), WORKER);
        assert!(module_from_form(CT, &form(&[js])).unwrap_err().contains("no metadata"));
        let m = meta("worker.js");
        let twice = form(&[("metadata", None, None, &m), ("metadata", None, None, &m), js]);
        assert!(module_from_form(CT, &twice).unwrap_err().contains("more than one metadata"));
        assert!(module_from_form(CT, &form(&[("metadata", None, None, &m)])).unwrap_err().contains("no part named"));
    }

    #[test]
    fn malformed_multipart_bodies_are_refused_without_panicking() {
        let m = meta("worker.js");
        let good = form(&[("metadata", None, None, &m), ("worker.js", Some("worker.js"), Some("application/javascript+module"), WORKER)]);
        assert!(module_from_form("multipart/form-data", &good).unwrap_err().contains("no boundary"));
        assert!(module_from_form("multipart/form-data; boundary=", &good).is_err());
        let long = format!("multipart/form-data; boundary={}", "a".repeat(71));
        assert!(module_from_form(&long, &good).is_err());
        assert!(module_from_form(CT, b"").is_err());
        assert!(module_from_form(CT, WORKER.as_bytes()).is_err());
        // every prefix of a good body: cut anywhere, it never parses as complete
        for cut in 0..good.len() - "--\r\n".len() {
            assert!(module_from_form(CT, &good[..cut]).is_err(), "cut at {cut}");
        }
        let no_name = good.clone();
        let no_name = String::from_utf8(no_name).unwrap().replace("name=\"worker.js\"", "filename=\"worker.js\"");
        assert!(module_from_form(CT, no_name.as_bytes()).unwrap_err().contains("no name"));
        let attachment = String::from_utf8(good.clone()).unwrap().replacen("form-data; name=\"metadata\"", "attachment; name=\"metadata\"", 1);
        assert!(module_from_form(CT, attachment.as_bytes()).unwrap_err().contains("form-data"));
        let bad_utf8 = [&good[..good.len() - 60], &[0xff, 0xfe][..], &good[good.len() - 60..]].concat();
        assert!(module_from_form(CT, &bad_utf8).is_err());
    }

    #[test]
    fn more_parts_than_the_limit_are_refused() {
        let m = meta("worker.js");
        let mut parts = vec![("metadata", None, None, m.as_str())];
        for _ in 0..MAX_PARTS {
            parts.push(("x.js", Some("x.js"), Some("application/javascript+module"), "1"));
        }
        assert!(module_from_form(CT, &form(&parts)).unwrap_err().contains("more than"));
    }

    #[test]
    fn parameters_are_read_with_quotes_escapes_and_any_case() {
        assert_eq!(param(r#"form-data; name="a;b"; filename="c\"d""#, "filename").as_deref(), Some("c\"d"));
        assert_eq!(param(r#"form-data; name="a;b"; filename="x""#, "name").as_deref(), Some("a;b"));
        assert_eq!(param("form-data; NAME=plain ; x=y", "name").as_deref(), Some("plain"));
        assert_eq!(param("form-data", "name"), None);
        assert_eq!(param(r#"form-data; name="unterminated"#, "name"), None);
        assert!(!is_multipart("application/javascript"));
        assert!(!is_multipart("multipart/mixed; boundary=x"));
    }
}
