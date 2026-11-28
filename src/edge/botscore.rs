//! The bot score: one number from 1 to 99 saying how much a request looks
//! like it was sent by a person with a browser, in the direction Cloudflare
//! uses for `cf.bot_management.score` (1: almost certainly automated, 99:
//! almost certainly a human). Rules match it as `fcf.bot_score` (or
//! `cf.bot_management.score`); `/cdn-cgi/fucf-trace` shows it as `bot=`.
//!
//! It is a sum of small, independent signals around a neutral start, each
//! computed by a function of its own so that more (a JA3 hash, an HTTP/2
//! fingerprint) can be added the same way. No signal is decisive alone: a
//! browser behind a VPN keeps a human score, a script that copies a browser's
//! User-Agent still loses on the headers it forgets and on its TLS library.
//! The score is a pure function of what is known of the request, so the
//! same request gets the same score on every node that rates its address
//! the same (the reputation lists are fetched by each node on its own).
//!
//! ```text
//! factor            signal                                               points
//! ----------------  ---------------------------------------------------  ------
//! start             neutral                                                 50
//! fingerprint       TCP TLS whose ClientHello gave no JA4                  -25
//!                   JA4 of a modern client: TLS 1.3, a server name, ALPN   +10
//!                   any other JA4 (TLS 1.2 or older, no SNI, no ALPN)      -10
//!                   no TLS, HTTP/3, the HTTP/3 front (no JA4 to expect)      0
//! reputation        threat score 0 (crate::edge::reputation)                +5
//!                   threat score n > 0                                  -n / 3
//! http_version      HTTP/2 or HTTP/3                                       +10
//!                   HTTP/1.1 over TLS (browsers there speak HTTP/2)         -5
//!                   HTTP/1.1 without TLS                                     0
//!                   HTTP/1.0 or older                                      -20
//! user_agent        missing                                                -30
//!                   names a tool, library or crawler                       -30
//!                   a browser's (starts with "Mozilla/")                    +5
//! browser_headers   no Accept                                              -10
//!                   no Accept-Language                                     -15
//!                   no Accept-Encoding                                      -5
//! fetch_metadata    Sec-Fetch-Mode present (only browsers send it)         +10
//! ----------------  ---------------------------------------------------  ------
//! clamped to 1..=99
//! verified crawler  a search engine crawler from its own network:
//!                   always VERIFIED_CRAWLER, whatever the other signals
//! ```
//!
//! Verified crawlers get a fixed middle score rather than a low one: they
//! are automated, but wanted, and a rule such as `fcf.bot_score lt 30` must
//! not shut search engines out. A crawler that only says so in its
//! User-Agent (not from its own network) scores as the script it is.
//!
//! 0 is never a score: it is what requests the edge makes itself (worker
//! subrequests, health checks) carry, where no visitor was scored.

use crate::expr::ReqInfo;
use hyper::{Request, Version};

/// The score of every verified search engine crawler.
pub const VERIFIED_CRAWLER: i64 = 50;

/// Where the score starts before any signal.
const NEUTRAL: i64 = 50;

/// Words in a User-Agent that only tools, libraries and crawlers use.
/// Matched against the lowercased value. `bot` alone is not on it (phone
/// models such as "CUBOT" contain it); crawlers write `...bot/2.1` or
/// `...bot;` and put a contact URL as `+http...`.
const TOOLS: &[&str] = &[
    "curl/", "wget/", "python", "go-http-client", "java/", "okhttp", "libwww", "httpclient", "axios/", "node-fetch", "undici",
    "aiohttp", "httpx", "scrapy", "headless", "phantomjs", "postman", "insomnia", "bot/", "bot;", "bot)", "+http", "spider", "crawler",
];

/// What the score is computed from: the request as the rules see it, and
/// what is known of its transport.
pub struct Signals<'a> {
    pub info: &'a ReqInfo,
    pub version: Version,
    /// Did the request come over TCP TLS, where a JA4 fingerprint is taken?
    /// (Not over HTTP/3 or the HTTP/3 front: those never have one.)
    pub fingerprint_expected: bool,
    /// The reputation check found a search engine crawler on its own network.
    pub verified_crawler: bool,
}

impl<'a> Signals<'a> {
    /// The signals of a request on its way through the edge. `info` must
    /// already carry the JA4 fingerprint and the threat score.
    pub fn of<B>(req: &Request<B>, info: &'a ReqInfo, verified_crawler: bool) -> Signals<'a> {
        let tls = req.extensions().get::<super::TlsInfo>().is_some();
        let via_front = req.extensions().get::<super::front::ViaFront>().is_some();
        Signals {
            info,
            version: req.version(),
            fingerprint_expected: tls && !via_front && req.version() != Version::HTTP_3,
            verified_crawler,
        }
    }
}

/// The bot score of a request, 1 (a bot) to 99 (a human).
pub fn score(s: &Signals) -> i64 {
    if s.verified_crawler {
        return VERIFIED_CRAWLER;
    }
    let info = s.info;
    let sum = NEUTRAL
        + fingerprint(&info.ja4, s.fingerprint_expected)
        + reputation(info.threat)
        + http_version(s.version, info.ssl)
        + user_agent(info.header("user-agent"))
        + browser_headers(info)
        + fetch_metadata(info);
    sum.clamp(1, 99)
}

/// The TLS library a client uses shows in its ClientHello whatever it
/// claims to be. Without a fingerprint where one should be, the hello did
/// not come whole and at once, which is how hand-rolled clients and slow
/// scanners send it.
fn fingerprint(ja4: &str, expected: bool) -> i64 {
    if !expected {
        return 0;
    }
    if ja4.is_empty() {
        return -25;
    }
    // t13d1516h2_...: protocol, TLS version, SNI (d) or not (i), two
    // counts, then the first and last character of the first ALPN ("00": none)
    let head = ja4.as_bytes();
    let modern = head.len() >= 10 && head[..10].iter().all(u8::is_ascii_alphanumeric) && head.starts_with(b"t13d") && &head[8..10] != b"00";
    if modern { 10 } else { -10 }
}

/// Addresses on abuse lists, data centres and VPNs send more automated
/// traffic; a clean address is a small point in favour.
fn reputation(threat: i64) -> i64 {
    if threat <= 0 { 5 } else { -(threat.min(100) / 3) }
}

/// Browsers speak HTTP/2 or HTTP/3 wherever TLS lets them; many scripts and
/// libraries stay on HTTP/1.1, and HTTP/1.0 is nearly only tools.
fn http_version(version: Version, ssl: bool) -> i64 {
    match version {
        Version::HTTP_2 | Version::HTTP_3 => 10,
        Version::HTTP_11 => if ssl { -5 } else { 0 },
        _ => -20,
    }
}

/// Every browser sends a User-Agent starting "Mozilla/"; tools usually name
/// themselves, and sending none at all is a script's habit.
fn user_agent(ua: &str) -> i64 {
    if ua.trim().is_empty() {
        return -30;
    }
    let ua = ua.to_ascii_lowercase();
    if TOOLS.iter().any(|word| ua.contains(word)) {
        return -30;
    }
    if ua.starts_with("mozilla/") { 5 } else { 0 }
}

/// Headers every browser sends on every request, and that scripts which
/// copy only the User-Agent forget.
fn browser_headers(info: &ReqInfo) -> i64 {
    let missing = |name: &str, points: i64| if info.header(name).is_empty() { points } else { 0 };
    missing("accept", -10) + missing("accept-language", -15) + missing("accept-encoding", -5)
}

/// Fetch Metadata (`Sec-Fetch-*`) is set by the browser itself, not by page
/// scripts; its absence says little (older browsers, plain HTTP), so it
/// only counts in favour.
fn fetch_metadata(info: &ReqInfo) -> i64 {
    if info.header("sec-fetch-mode").is_empty() { 0 } else { 10 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

    fn info(ssl: bool, ja4: &str, threat: i64, headers: &[(&str, &str)]) -> ReqInfo {
        ReqInfo {
            ssl,
            ja4: ja4.into(),
            threat,
            headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
            ..Default::default()
        }
    }

    fn browser_headers_of(ua: &str) -> Vec<(&str, &str)> {
        vec![
            ("user-agent", ua),
            ("accept", "text/html,application/xhtml+xml"),
            ("accept-language", "en-US,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("sec-fetch-mode", "navigate"),
        ]
    }

    fn at(info: &ReqInfo, version: Version, fingerprint_expected: bool, verified_crawler: bool) -> i64 {
        score(&Signals { info, version, fingerprint_expected, verified_crawler })
    }

    #[test]
    fn a_full_browser_over_tls_scores_as_a_human() {
        let chrome = info(true, CHROME_JA4, 0, &browser_headers_of(CHROME_UA));
        let s = at(&chrome, Version::HTTP_2, true, false);
        assert!(s >= 80, "{s}");
        // over HTTP/3 there is no fingerprint to expect, and none is held against it
        assert!(at(&info(true, "", 0, &browser_headers_of(CHROME_UA)), Version::HTTP_3, false, false) >= 80);
        // a browser behind a VPN or in a data centre stays on the human side
        assert!(at(&info(true, CHROME_JA4, 40, &browser_headers_of(CHROME_UA)), Version::HTTP_2, true, false) > 50);
    }

    #[test]
    fn a_bare_tls_client_without_a_fingerprint_scores_lower_than_a_full_browser() {
        let chrome = at(&info(true, CHROME_JA4, 0, &browser_headers_of(CHROME_UA)), Version::HTTP_2, true, false);
        let bare = at(&info(true, "", 0, &[]), Version::HTTP_11, true, false);
        assert!(bare < chrome, "{bare} < {chrome}");
        assert!(bare < 30, "{bare}");
        // the missing fingerprint alone already costs: the same browser headers, no JA4
        let unprinted = at(&info(true, "", 0, &browser_headers_of(CHROME_UA)), Version::HTTP_2, true, false);
        assert!(unprinted < chrome, "{unprinted} < {chrome}");
    }

    #[test]
    fn command_line_tools_and_scripts_score_as_bots() {
        let curl = info(true, "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6", 0, &[("user-agent", "curl/8.5.0"), ("accept", "*/*")]);
        assert!(at(&curl, Version::HTTP_2, true, false) < 30);
        let python = info(true, "t13d4907h1_0d8feac7bc37_7395dae3b2f3", 0, &[("user-agent", "python-requests/2.32.3"), ("accept", "*/*"), ("accept-encoding", "gzip, deflate")]);
        assert!(at(&python, Version::HTTP_11, true, false) < 30);
        // copying a browser's User-Agent is not enough without its headers and its TLS
        let copied = info(true, "t12i0505h1_aaaaaaaaaaaa_bbbbbbbbbbbb", 0, &[("user-agent", CHROME_UA)]);
        assert!(at(&copied, Version::HTTP_11, true, false) < 30);
        // HTTP/1.0 with nothing at all, from a listed abuser
        assert_eq!(at(&info(false, "", 80, &[]), Version::HTTP_10, false, false), 1);
    }

    #[test]
    fn verified_crawlers_get_the_same_middle_score_whatever_they_send() {
        let googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        let requests = [
            (info(true, CHROME_JA4, 0, &[("user-agent", googlebot), ("accept", "*/*")]), Version::HTTP_11, true),
            (info(true, "", 0, &[("user-agent", googlebot)]), Version::HTTP_2, true),
            (info(false, "", 0, &[]), Version::HTTP_10, false),
        ];
        for (req, version, expected) in &requests {
            assert_eq!(at(req, *version, *expected, true), VERIFIED_CRAWLER);
        }
        // the same User-Agent from anywhere else is just a script that says it is Googlebot
        let (spoofed, version, expected) = &requests[0];
        assert!(at(spoofed, *version, *expected, false) < 30);
    }

    #[test]
    fn the_score_always_stays_within_one_and_ninety_nine() {
        let uas = ["", "curl/8.0", CHROME_UA, "Mozilla/5.0 (compatible; bingbot/2.0)", "x"];
        let ja4s = ["", CHROME_JA4, "t12i0000_000000000000_000000000000", "short", "t13d1516"];
        let versions = [Version::HTTP_09, Version::HTTP_10, Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];
        for ua in uas {
            for ja4 in ja4s {
                for threat in [-5, 0, 1, 30, 100, 1000] {
                    for version in versions {
                        for (ssl, expected, crawler) in [(false, false, false), (true, true, false), (true, false, false), (true, true, true)] {
                            for headers in [vec![("user-agent", ua)], browser_headers_of(ua)] {
                                let s = at(&info(ssl, ja4, threat, &headers), version, expected, crawler);
                                assert!((1..=99).contains(&s), "{s} for {ua:?} {ja4:?} {threat} {version:?}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_fingerprint_counts_only_where_one_is_taken_and_tells_modern_clients_from_old() {
        assert_eq!(fingerprint("", false), 0, "plain HTTP and HTTP/3 have none");
        assert_eq!(fingerprint(CHROME_JA4, false), 0);
        assert_eq!(fingerprint("", true), -25);
        assert_eq!(fingerprint(CHROME_JA4, true), 10);
        assert_eq!(fingerprint("t13d1516h2", true), 10, "the head alone is enough");
        for odd in ["t12d1516h2_x_y", "t13i1516h2_x_y", "t13d151600_x_y", "t13d15", "q13d1516h2_x_y"] {
            assert_eq!(fingerprint(odd, true), -10, "{odd}");
        }
        // something that is not ASCII at all does not trip the slicing
        assert_eq!(fingerprint("t13d\u{e9}\u{e9}\u{e9}", true), -10);
    }

    #[test]
    fn each_factor_points_the_way_its_table_says() {
        assert_eq!((reputation(0), reputation(30), reputation(80), reputation(500)), (5, -10, -26, -33));
        assert_eq!(http_version(Version::HTTP_11, false), 0);
        assert_eq!(http_version(Version::HTTP_11, true), -5);
        assert_eq!(http_version(Version::HTTP_09, false), -20);
        assert_eq!((user_agent(""), user_agent("   "), user_agent("Wget/1.21"), user_agent(CHROME_UA), user_agent("SomeApp/1.0")), (-30, -30, -30, 5, 0));
        assert_eq!(user_agent("Mozilla/5.0 (Linux; Android 10; CUBOT X30) AppleWebKit/537.36"), 5, "a phone model is not a bot");
        assert_eq!(user_agent("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"), -30);
        assert_eq!(browser_headers(&info(false, "", 0, &[])), -30);
        assert_eq!(browser_headers(&info(false, "", 0, &browser_headers_of(CHROME_UA))), 0);
        assert_eq!(browser_headers(&info(false, "", 0, &[("accept", "")])), -30, "an empty header is as good as none");
        assert_eq!(fetch_metadata(&info(false, "", 0, &[("sec-fetch-mode", "cors")])), 10);
    }

    #[test]
    fn signals_follow_the_transport_of_the_request() {
        let info = ReqInfo::default();
        let tls = super::super::TlsInfo { version: "TLSv1.3", sni: true, kex: String::new(), ja4: String::new(), client_cert_verified: false };
        let mut req = Request::builder().version(Version::HTTP_2).body(()).unwrap();
        assert!(!Signals::of(&req, &info, false).fingerprint_expected, "no TLS, no fingerprint");
        req.extensions_mut().insert(tls.clone());
        let s = Signals::of(&req, &info, true);
        assert!(s.fingerprint_expected && s.verified_crawler && s.version == Version::HTTP_2);
        req.extensions_mut().insert(super::super::front::ViaFront);
        assert!(!Signals::of(&req, &info, false).fingerprint_expected, "the HTTP/3 front takes none");
        let mut h3 = Request::builder().version(Version::HTTP_3).body(()).unwrap();
        h3.extensions_mut().insert(tls);
        assert!(!Signals::of(&h3, &info, false).fingerprint_expected, "neither does HTTP/3");
    }
}
