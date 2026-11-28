//! Preload hints (zone setting `early_hints_links`): `Link` headers the edge
//! adds to a zone's HTML pages, so a browser starts fetching a page's
//! stylesheet, script or font, or opens the connection to another origin,
//! as soon as it reads the headers.
//!
//! This stands in for Early Hints (`103`): hyper 1.x cannot send an
//! informational answer before the final one on the server side (its HTTP/1
//! encoder turns a 1xx into a 500, and a service returns exactly one
//! response), so no `103` is ever sent. The hints arrive with the page's own
//! headers instead: they help while the body is still on its way, not while
//! the origin is still thinking.
//!
//! Only a narrow form is taken, so that what the zone writes cannot add other
//! headers, other link relations or a second link hidden in one entry:
//!
//! ```text
//! <URL>; rel=preload; as=TYPE [; crossorigin[=anonymous|use-credentials]]
//! <URL>; rel=preconnect [; crossorigin[=anonymous|use-credentials]]
//! ```
//!
//! `URL` is a path of the site (`/app.css`) or an `https://` URL; parameters
//! are unquoted, in any order and case.

use super::Body;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};

/// At most this many hints per zone.
pub const MAX_LINKS: usize = 16;
/// At most this many bytes in one hint as written.
pub const MAX_LINK_LEN: usize = 512;
/// The `Link` header the hints make together stays under this.
pub const MAX_HEADER_LEN: usize = 4096;

/// What a preload may fetch (the `as` values browsers act on).
const DESTINATIONS: &[&str] = &["audio", "document", "embed", "fetch", "font", "image", "object", "script", "style", "track", "video", "worker"];

/// One hint, read from its text.
#[derive(Debug, Clone, PartialEq)]
struct Hint {
    url: String,
    preload: bool,
    /// The `as` value, lower case (preloads only).
    dest: Option<String>,
    /// `crossorigin`, with its value if it has one (lower case).
    crossorigin: Option<Option<String>>,
}

impl Hint {
    fn parse(text: &str) -> Result<Hint, String> {
        if text.len() > MAX_LINK_LEN {
            return Err(format!("a hint is at most {MAX_LINK_LEN} bytes"));
        }
        let rest = text.trim().strip_prefix('<').ok_or("a hint starts with <URL>")?;
        let (url, params) = rest.split_once('>').ok_or("a hint starts with <URL>")?;
        if !url_ok(url) {
            return Err(format!("'{url}' is not a path of the site (/app.css) or an https:// URL without spaces, quotes, commas, semicolons or angle brackets"));
        }
        let mut params = params.trim();
        let mut hint = Hint { url: url.to_string(), preload: false, dest: None, crossorigin: None };
        let mut rel = None;
        while !params.is_empty() {
            params = params.strip_prefix(';').ok_or("parameters are separated by ;")?.trim_start();
            let end = params.find(';').unwrap_or(params.len());
            let (param, more) = params.split_at(end);
            params = more;
            let (name, value) = match param.split_once('=') {
                Some((n, v)) => (n.trim().to_ascii_lowercase(), Some(v.trim().to_ascii_lowercase())),
                None => (param.trim().to_ascii_lowercase(), None),
            };
            let repeated = match (name.as_str(), value) {
                ("rel", Some(v)) if v == "preload" || v == "preconnect" => rel.replace(v).is_some(),
                ("rel", _) => return Err("rel is preload or preconnect".into()),
                ("as", Some(v)) if DESTINATIONS.contains(&v.as_str()) => hint.dest.replace(v).is_some(),
                ("as", _) => return Err(format!("as is one of {}", DESTINATIONS.join(", "))),
                ("crossorigin", v) if v.as_deref().is_none_or(|v| v == "anonymous" || v == "use-credentials") => hint.crossorigin.replace(v).is_some(),
                ("crossorigin", _) => return Err("crossorigin takes no value, anonymous or use-credentials".into()),
                (other, _) => return Err(format!("unknown parameter '{other}': rel, as and crossorigin are taken")),
            };
            if repeated {
                return Err(format!("{name} is given twice"));
            }
        }
        match rel.as_deref() {
            Some("preload") if hint.dest.is_none() => Err("a preload needs as=TYPE (style, script, font, image, ...)".into()),
            Some("preload") => Ok(Hint { preload: true, ..hint }),
            Some(_) if hint.dest.is_some() => Err("as is for preloads only".into()),
            Some(_) => Ok(hint),
            None => Err("a hint needs rel=preload or rel=preconnect".into()),
        }
    }

    /// The hint as it goes into the header, written the same way whatever
    /// spacing and case it was saved with.
    fn render(&self) -> String {
        let mut out = format!("<{}>; rel={}", self.url, if self.preload { "preload" } else { "preconnect" });
        if let Some(dest) = &self.dest {
            out.push_str("; as=");
            out.push_str(dest);
        }
        match &self.crossorigin {
            Some(Some(v)) => out.push_str(&format!("; crossorigin={v}")),
            Some(None) => out.push_str("; crossorigin"),
            None => {}
        }
        out
    }
}

/// A path of the site (not `//`, which would be another host) or an
/// `https://` URL with a host, made only of printable ASCII that cannot end
/// the `<...>` or split the header into more links.
fn url_ok(url: &str) -> bool {
    let shape = match url.strip_prefix("https://") {
        Some(rest) => rest.split(['/', '?', '#']).next().is_some_and(|host| !host.is_empty() && !host.contains('@')),
        None => url.starts_with('/') && !url.starts_with("//"),
    };
    shape && url.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>' | b'"' | b'\\' | b',' | b';' | b'`'))
}

/// Check the setting as saved: the error says which hint is wrong.
pub fn validate(links: &[String]) -> Result<(), String> {
    if links.len() > MAX_LINKS {
        return Err(format!("early_hints_links holds at most {MAX_LINKS} hints"));
    }
    for (i, link) in links.iter().enumerate() {
        Hint::parse(link).map_err(|e| format!("early_hints_links[{i}]: {e}"))?;
    }
    if header_text(links).len() > MAX_HEADER_LEN {
        return Err(format!("early_hints_links make a Link header of more than {MAX_HEADER_LEN} bytes"));
    }
    Ok(())
}

/// The `Link` header value of the hints that read (all of them, once saved).
fn header_text(links: &[String]) -> String {
    links.iter().filter_map(|l| Hint::parse(l).ok()).map(|h| h.render()).collect::<Vec<_>>().join(", ")
}

/// Add the zone's hints to a page: a `200` whose type is HTML. Other
/// answers (assets, redirects, errors, the edge's own pages) are left alone,
/// and a `Link` header the origin sent is kept next to them.
pub fn apply(resp: &mut Response<Body>, links: &[String]) {
    if links.is_empty() || resp.status() != StatusCode::OK {
        return;
    }
    let html = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|t| t.trim_start().to_ascii_lowercase().starts_with("text/html"));
    if !html {
        return;
    }
    let text = header_text(links);
    if text.is_empty() || text.len() > MAX_HEADER_LEN {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(&text) {
        resp.headers_mut().append(header::LINK, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_narrow_forms_are_taken_and_written_one_way() {
        let ok = links(&[
            "</app.css>; rel=preload; as=style",
            "  </fonts/a.woff2> ;REL=Preload; As=FONT ;crossorigin ",
            "<https://cdn.example.com>; rel=preconnect",
            "<https://cdn.example.com/x.js?v=2>; rel=preload; as=script; crossorigin=use-credentials",
        ]);
        assert_eq!(validate(&ok), Ok(()));
        assert_eq!(
            header_text(&ok),
            "</app.css>; rel=preload; as=style, </fonts/a.woff2>; rel=preload; as=font; crossorigin, <https://cdn.example.com>; rel=preconnect, <https://cdn.example.com/x.js?v=2>; rel=preload; as=script; crossorigin=use-credentials"
        );
        assert_eq!(validate(&[]), Ok(()));
    }

    #[test]
    fn anything_else_is_refused_with_the_hint_it_is_about() {
        for bad in [
            "",
            "/app.css; rel=preload; as=style",
            "<app.css>; rel=preload; as=style",
            "<//evil.example/x.js>; rel=preload; as=script",
            "<http://example.com/x.js>; rel=preload; as=script",
            "<https://>; rel=preconnect",
            "<https://user@example.com/>; rel=preconnect",
            "<javascript:alert(1)>; rel=preload; as=script",
            "</a b.css>; rel=preload; as=style",
            "</a.css>, </b.css>; rel=preload; as=style",
            "</a.css;x>; rel=preload; as=style",
            "</a\"b.css>; rel=preload; as=style",
            "</é.css>; rel=preload; as=style",
            "</a.css>; rel=stylesheet",
            "</a.css>; rel=prefetch; as=style",
            "</a.css>; rel=\"preload\"; as=style",
            "</a.css>; rel=preload",
            "</a.css>; rel=preload; as=css",
            "</a.css>; as=style",
            "</a.css>; rel=preload; rel=preload; as=style",
            "</a.css>; rel=preload; as=style; as=style",
            "</a.css>; rel=preload; as=style; crossorigin; crossorigin",
            "</a.css>; rel=preload; as=style; crossorigin=yes",
            "</a.css>; rel=preload; as=style; nopush",
            "</a.css>; rel=preload; as=style\r\nSet-Cookie: a=b",
            "</a.css> rel=preload; as=style",
            "<https://cdn.example.com>; rel=preconnect; as=font",
        ] {
            let err = validate(&links(&["</ok.css>; rel=preload; as=style", bad])).unwrap_err();
            assert!(err.starts_with("early_hints_links[1]: "), "{bad:?}: {err}");
        }
        let long = format!("</{}>; rel=preload; as=style", "a".repeat(MAX_LINK_LEN));
        assert!(validate(&[long]).is_err(), "one hint is bounded");
        let many: Vec<String> = (0..=MAX_LINKS).map(|i| format!("</{i}.css>; rel=preload; as=style")).collect();
        assert!(validate(&many).is_err(), "so is their number");
        let wide: Vec<String> = (0..MAX_LINKS).map(|i| format!("</{i}{}>; rel=preload; as=style", "b".repeat(300))).collect();
        assert!(validate(&wide).unwrap_err().contains("Link header"), "and the header they make");
    }

    fn page(ctype: &str, status: u16) -> Response<Body> {
        let mut resp = Response::new(super::super::full(bytes::Bytes::from_static(b"<html></html>")));
        *resp.status_mut() = StatusCode::from_u16(status).unwrap();
        if !ctype.is_empty() {
            resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_str(ctype).unwrap());
        }
        resp
    }

    #[test]
    fn only_html_pages_get_the_hints_next_to_the_origins_own() {
        let hints = links(&["</app.css>; rel=preload; as=style"]);
        let mut resp = page("Text/HTML; charset=utf-8", 200);
        resp.headers_mut().insert(header::LINK, HeaderValue::from_static("</origin.js>; rel=preload; as=script"));
        apply(&mut resp, &hints);
        let all: Vec<_> = resp.headers().get_all(header::LINK).iter().map(|v| v.to_str().unwrap().to_string()).collect();
        assert_eq!(all, ["</origin.js>; rel=preload; as=script", "</app.css>; rel=preload; as=style"]);

        for (ctype, status) in [("text/css", 200), ("application/json", 200), ("", 200), ("text/html", 404), ("text/html", 301), ("text/html", 206)] {
            let mut resp = page(ctype, status);
            apply(&mut resp, &hints);
            assert!(resp.headers().get(header::LINK).is_none(), "{ctype} {status}");
        }
        let mut resp = page("text/html", 200);
        apply(&mut resp, &[]);
        assert!(resp.headers().get(header::LINK).is_none(), "nothing set, nothing added");
    }
}
