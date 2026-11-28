//! Custom cache keys: a cache rule may keep one copy per value of some
//! request headers and cookies (`cache_key_headers`, `cache_key_cookies`),
//! for origins that answer differently by language, device class or a
//! cookie-held variant. What is added goes into the key made by
//! [`super::cache::cache_key`], before its compression part, so the
//! uncompressed copy is still shared between compressions and purges (which
//! match the stored URL, not the key) still find every variant.
//!
//! The added part is written so that two different sets of values can never
//! give the same key: each name/value pair starts with a control character
//! (`SEP`), names come from a restricted character set without `=` or
//! control characters, and values lose their control characters and have
//! `%` and every non-ASCII byte percent-encoded.

use hyper::header::{self, HeaderMap};

/// How many headers, and how many cookies, one rule may add to the key:
/// each one multiplies the copies kept of every matching URL.
pub const MAX_NAMES: usize = 8;
/// Longest header or cookie name accepted.
pub const MAX_NAME_LEN: usize = 64;
/// Longest key (in bytes) that is looked up and stored when a rule adds to
/// it. Values come from the visitor, so without a bound a client could
/// make every key as large as its headers and fill the index with them; a
/// request whose key is longer is served from the origin, uncached.
pub const MAX_KEY: usize = 2048;

/// Starts each added name/value pair. A control character: values have
/// those removed and names cannot hold them, so it marks pairs unambiguously.
const SEP: char = '\u{1f}';

/// Check the header names of a rule and write them in lower case (header
/// names are case-insensitive; one spelling keeps one key).
pub fn check_headers(names: &mut [String]) -> Result<(), String> {
    check_count(names.len(), "cache_key_headers")?;
    for name in names.iter_mut() {
        *name = name.to_ascii_lowercase();
        let ok = name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        check_name(name, ok, "cache_key_headers", "letters, digits, '-' and '_'")?;
    }
    check_unique(names, "cache_key_headers")
}

/// Check the cookie names of a rule. Cookie names are case-sensitive, so
/// they are kept as written.
pub fn check_cookies(names: &[String]) -> Result<(), String> {
    check_count(names.len(), "cache_key_cookies")?;
    for name in names {
        // the token characters of RFC 6265 (no separators, no '=')
        let ok = name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
        check_name(name, ok, "cache_key_cookies", "letters, digits and !#$%&'*+-.^_`|~")?;
    }
    check_unique(names, "cache_key_cookies")
}

fn check_count(n: usize, field: &str) -> Result<(), String> {
    if n > MAX_NAMES {
        return Err(format!("{field} takes at most {MAX_NAMES} names"));
    }
    Ok(())
}

fn check_name(name: &str, charset_ok: bool, field: &str, allowed: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{field}: a name cannot be empty"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("{field}: '{name}' is longer than {MAX_NAME_LEN} characters"));
    }
    if !charset_ok {
        return Err(format!("{field}: '{name}' may only hold {allowed}"));
    }
    Ok(())
}

fn check_unique(names: &[String], field: &str) -> Result<(), String> {
    for (i, name) in names.iter().enumerate() {
        if names[..i].contains(name) {
            return Err(format!("{field}: '{name}' is listed twice"));
        }
    }
    Ok(())
}

/// What a rule adds to the key for this request: empty when it names no
/// header and no cookie, so such rules keep exactly the key they had. A
/// header or cookie that is not sent counts as an empty value. A header
/// sent more than once counts as its values joined by commas, as HTTP reads
/// it; a cookie sent more than once counts by its first value, as most
/// servers read it.
pub fn part(headers: &[String], cookies: &[String], req: &HeaderMap) -> String {
    let mut out = String::new();
    for name in headers {
        out.push(SEP);
        out.push('h');
        out.push_str(name);
        out.push('=');
        for (i, value) in req.get_all(name.as_str()).iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            clean(value.as_bytes(), &mut out);
        }
    }
    for name in cookies {
        out.push(SEP);
        out.push('c');
        out.push_str(name);
        out.push('=');
        if let Some(value) = cookie(req, name) {
            clean(value, &mut out);
        }
    }
    out
}

/// May a key that a rule added to be looked up and stored?
pub fn fits(key: &str) -> bool {
    key.len() <= MAX_KEY
}

/// The first value of cookie `name` in the request's `Cookie` headers
/// (HTTP/2 clients may send several). Pairs are split at `;`, spaces and
/// tabs around names and values are ignored, and a pair without `=` names
/// no cookie.
fn cookie<'a>(req: &'a HeaderMap, name: &str) -> Option<&'a [u8]> {
    req.get_all(header::COOKIE)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b';'))
        .filter_map(|pair| {
            let at = pair.iter().position(|b| *b == b'=')?;
            Some((trim(&pair[..at]), trim(&pair[at + 1..])))
        })
        .find(|(n, _)| *n == name.as_bytes())
        .map(|(_, v)| v)
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| *c != b' ' && *c != b'\t').unwrap_or(b.len());
    let end = b.iter().rposition(|c| *c != b' ' && *c != b'\t').map_or(start, |i| i + 1);
    &b[start..end]
}

/// Append a value: control characters dropped, `%` and non-ASCII bytes
/// percent-encoded (so distinct byte strings stay distinct and the key
/// stays valid text whatever the client sent).
fn clean(value: &[u8], out: &mut String) {
    for &b in value {
        match b {
            0..=0x1f | 0x7f => {}
            b'%' | 0x80..=0xff => out.push_str(&format!("%{b:02X}")),
            _ => out.push(char::from(b)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn req(pairs: &[(&str, &[u8])]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append(header::HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_bytes(value).unwrap());
        }
        h
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_rule_without_names_adds_nothing_to_the_key() {
        assert_eq!(part(&[], &[], &req(&[("accept-language", b"en"), ("cookie", b"a=1")])), "");
    }

    #[test]
    fn different_header_values_give_different_parts() {
        let h = names(&["accept-language"]);
        let en = part(&h, &[], &req(&[("accept-language", b"en")]));
        let de = part(&h, &[], &req(&[("accept-language", b"de")]));
        assert_ne!(en, de);
        assert_eq!(en, "\u{1f}haccept-language=en");
        assert_eq!(part(&h, &[], &req(&[("accept-language", b"en")])), en, "the same value, the same part");
        assert_eq!(part(&h, &[], &req(&[])), "\u{1f}haccept-language=", "a missing header is an empty value");
    }

    #[test]
    fn a_header_sent_twice_counts_as_its_values_joined() {
        let h = names(&["x-variant"]);
        assert_eq!(part(&h, &[], &req(&[("x-variant", b"a"), ("x-variant", b"b")])), "\u{1f}hx-variant=a,b");
    }

    #[test]
    fn values_lose_control_characters_and_cannot_forge_another_pair() {
        let h = names(&["x-a", "x-b"]);
        // a tab is the one control character hyper lets a header value carry
        let tabbed = part(&h, &[], &req(&[("x-a", b"1\t2")]));
        assert_eq!(tabbed, "\u{1f}hx-a=12\u{1f}hx-b=");
        // whatever bytes reach it, no value can hold the separator
        let mut out = String::new();
        clean(b"1\x1fhx-b=2\x00\x7f\r\n", &mut out);
        assert_eq!(out, "1hx-b=2");
        let sneaky = part(&h, &[], &req(&[("x-a", b"1hx-b=2")]));
        let honest = part(&h, &[], &req(&[("x-a", b"1"), ("x-b", b"2")]));
        assert_ne!(sneaky, honest);
        assert_eq!(sneaky.matches(SEP).count(), 2, "only the separators the rule asked for");
    }

    #[test]
    fn percent_and_non_ascii_bytes_are_encoded_so_values_stay_apart() {
        let h = names(&["x-a"]);
        let raw = part(&h, &[], &req(&[("x-a", b"\xe9")]));
        let typed = part(&h, &[], &req(&[("x-a", b"%E9")]));
        assert_eq!(raw, "\u{1f}hx-a=%E9");
        assert_eq!(typed, "\u{1f}hx-a=%25E9");
        assert_ne!(raw, typed);
    }

    #[test]
    fn cookies_are_found_through_spaces_repeats_and_several_headers() {
        let c = names(&["sess"]);
        let of = |pairs: &[(&str, &[u8])]| part(&[], &c, &req(pairs));
        assert_eq!(of(&[("cookie", b"a=1;  sess = abc ; b=2")]), "\u{1f}csess=abc");
        assert_eq!(of(&[("cookie", b"sess=first; sess=second")]), "\u{1f}csess=first", "the first of repeated names");
        assert_eq!(of(&[("cookie", b"a=1"), ("cookie", b"sess=two")]), "\u{1f}csess=two", "a second Cookie header");
        assert_eq!(of(&[]), "\u{1f}csess=", "no Cookie header");
        assert_eq!(of(&[("cookie", b"")]), "\u{1f}csess=", "an empty Cookie header");
        assert_eq!(of(&[("cookie", b"sess; other=1")]), "\u{1f}csess=", "a pair without '=' names no cookie");
        assert_eq!(of(&[("cookie", b"sess=")]), "\u{1f}csess=");
        assert_eq!(of(&[("cookie", b"Sess=x; session=y; xsess=z")]), "\u{1f}csess=", "names match exactly, case included");
        assert_eq!(of(&[("cookie", b"sess=a=b")]), "\u{1f}csess=a=b", "the value runs to the next ';'");
    }

    #[test]
    fn headers_come_before_cookies_in_the_order_the_rule_names_them() {
        let r = req(&[("x-b", b"2"), ("x-a", b"1"), ("cookie", b"k=v")]);
        assert_eq!(part(&names(&["x-a", "x-b"]), &names(&["k"]), &r), "\u{1f}hx-a=1\u{1f}hx-b=2\u{1f}ck=v");
    }

    #[test]
    fn header_names_are_lower_cased_and_checked() {
        let mut ok = names(&["Accept-Language", "X_Variant", "dnt"]);
        check_headers(&mut ok).unwrap();
        assert_eq!(ok, names(&["accept-language", "x_variant", "dnt"]));
        assert!(check_headers(&mut []).is_ok());
        for bad in [vec![""], vec!["x a"], vec!["x:y"], vec!["x\u{1f}"], vec!["é"], vec!["x-a", "X-A"]] {
            assert!(check_headers(&mut names(&bad)).is_err(), "{bad:?}");
        }
        assert!(check_headers(&mut names(&[&"a".repeat(MAX_NAME_LEN)])).is_ok());
        assert!(check_headers(&mut names(&[&"a".repeat(MAX_NAME_LEN + 1)])).is_err());
        let eight: Vec<String> = (0..MAX_NAMES).map(|i| format!("x-{i}")).collect();
        assert!(check_headers(&mut eight.clone()).is_ok());
        let nine: Vec<String> = (0..=MAX_NAMES).map(|i| format!("x-{i}")).collect();
        assert!(check_headers(&mut nine.clone()).is_err());
    }

    #[test]
    fn cookie_names_keep_their_case_and_are_checked() {
        assert!(check_cookies(&names(&["Sess", "sess", "__Host-id", "a.b|c~"])).is_ok(), "case tells cookies apart");
        for bad in [vec![""], vec!["a=b"], vec!["a b"], vec!["a;b"], vec!["a,b"], vec!["a\u{1f}"], vec!["x", "x"]] {
            assert!(check_cookies(&names(&bad)).is_err(), "{bad:?}");
        }
        let nine: Vec<String> = (0..=MAX_NAMES).map(|i| format!("c{i}")).collect();
        assert!(check_cookies(&nine).is_err());
        assert!(check_cookies(&names(&[&"c".repeat(MAX_NAME_LEN + 1)])).is_err());
    }

    #[test]
    fn keys_past_the_limit_do_not_fit() {
        assert!(fits(&"k".repeat(MAX_KEY)));
        assert!(!fits(&"k".repeat(MAX_KEY + 1)));
    }
}
