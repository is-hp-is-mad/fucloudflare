//! The edge's own human check, in the manner of Cloudflare's challenge
//! platform: a page that proves work, looks at the browser, and (for a
//! managed challenge, or when the browser looks doubtful) asks for one click.
//!
//! 1. The page carries a signed ticket: zone, visitor address, a digest of
//!    the User-Agent, when it was issued, the work to do, whether a click is
//!    required. It is signed with the fleet's secret (any node checks it,
//!    nothing is stored).
//! 2. In the browser, a script finds `n` such that
//!    `sha256(ticket ":" n)` starts with `bits` zero bits, and collects what
//!    automation tends to give away: `navigator.webdriver`, the globals that
//!    Selenium, Playwright, Puppeteer, PhantomJS and others leave, a debugger
//!    protocol client asking for the stack of what is logged, patched native
//!    functions, empty plugin and language lists, a window without an outer
//!    frame, software WebGL, notification permissions that contradict each
//!    other, a User-Agent that differs from the one sent. For a click: was it
//!    a real (trusted) event, how soon after the box appeared, did a mouse
//!    move before it.
//! 3. `POST /cdn-cgi/challenge-platform/verify` checks the ticket and the
//!    work, adds the request headers' story (client hints a Chromium browser
//!    sends, `Accept-Language`) and scores it all. A clean browser passes at
//!    once; a doubtful one is asked to click; an automated one fails. Passing
//!    sets the clearance cookie (HttpOnly, for this zone and address).

use super::waf::{Waf, CLEARANCE_COOKIE};
use super::{bi, escape, full, Body, EdgeError, Lang, LANG_SCRIPT, PAGE_CSS, PAGE_MARK};
use base64::Engine;
use http_body_util::BodyExt;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{json, Value};
use std::net::IpAddr;

/// Where the page sends its answer.
pub const VERIFY_PATH: &str = "/cdn-cgi/challenge-platform/verify";
/// How long a ticket may be answered.
const TICKET_SECS: u64 = 600;

/// The zone's security level (Cloudflare's names): who is challenged at all
/// (by the threat score of their address, see super::reputation), how much
/// work the browser does, and how much doubt it may leave before it has to
/// click or fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Off,
    Low,
    Medium,
    High,
    UnderAttack,
}

impl Level {
    pub fn of(setting: &str) -> Level {
        match setting {
            "off" | "essentially_off" => Level::Off,
            "low" => Level::Low,
            "high" => Level::High,
            "under_attack" => Level::UnderAttack,
            _ => Level::Medium,
        }
    }

    /// One letter for the level, as tickets carry it.
    pub(super) fn code(self) -> char {
        match self {
            Level::Off => 'o',
            Level::Low => 'l',
            Level::Medium => 'm',
            Level::High => 'h',
            Level::UnderAttack => 'u',
        }
    }

    pub(super) fn from_code(c: &str) -> Option<Level> {
        Some(match c {
            "o" => Level::Off,
            "l" => Level::Low,
            "m" => Level::Medium,
            "h" => Level::High,
            "u" => Level::UnderAttack,
            _ => return None,
        })
    }

    /// Work for a browser: 2^17 hashes on average is a fraction of a second.
    pub fn bits(self) -> u8 {
        match self {
            Level::High => 18,
            Level::UnderAttack => 19,
            _ => 17,
        }
    }

    /// Doubt at or above which a browser is taken for automation.
    fn fail_score(self) -> u32 {
        match self {
            Level::Off | Level::Low => 8,
            Level::Medium => 5,
            Level::High | Level::UnderAttack => 4,
        }
    }

    /// Doubt above which a click is asked for.
    fn click_above(self) -> u32 {
        match self {
            Level::Off | Level::Low => 2,
            _ => 0,
        }
    }

    /// Is a visitor with this threat score challenged, and must they click?
    /// (`None`: let through.)
    pub fn challenge(self, threat: i64) -> Option<bool> {
        match self {
            Level::Off => None,
            Level::Low => (threat >= 80).then_some(false),
            Level::Medium => (threat >= 50).then_some(threat >= 80),
            Level::High => (threat >= 25).then_some(threat >= 50),
            Level::UnderAttack => Some(threat >= 50),
        }
    }
}
/// The answer is small; anything larger is not ours.
const MAX_ANSWER: usize = 32 * 1024;

/// The challenge page's script: what the page and the injected script share, then the page's own part.
const SCRIPT: &str = concat!(include_str!("challenge-core.js"), include_str!("challenge-page.js"));
/// What is put into a site's pages (`/cdn-cgi/challenge-platform/fcf.js`).
const INJECTED: &str = concat!(include_str!("challenge-core.js"), include_str!("challenge-inject.js"));

/// `/cdn-cgi/challenge-platform/fcf.js`.
pub fn injected_script() -> Response<Body> {
    let mut resp = Response::new(full(INJECTED));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    resp
}

/// `/cdn-cgi/challenge-platform/ticket`: a ticket for passing quietly (no click asked).
pub fn ticket_answer(waf: &Waf, zone_id: &str, ip: IpAddr, ua: &str, level: Level) -> Response<Body> {
    answer(StatusCode::OK, config(waf, zone_id, ip, ua, false, level))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What a ticket keeps of the User-Agent it was issued to.
pub(super) fn ua_digest(ua: &str) -> String {
    crate::release::sha256_hex(ua.as_bytes())[..16].to_string()
}

/// What the page is asked to do, signed.
#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    pub zone: String,
    pub ip: IpAddr,
    pub ua: String,
    pub issued: u64,
    pub bits: u8,
    pub click: bool,
    pub nonce: String,
    pub level: Level,
}

impl Ticket {
    #[cfg(test)]
    pub fn new(zone: &str, ip: IpAddr, ua: &str, click: bool) -> Ticket {
        Ticket::at(zone, ip, ua, click, Level::Medium)
    }

    pub fn at(zone: &str, ip: IpAddr, ua: &str, click: bool, level: Level) -> Ticket {
        let nonce = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
        Ticket { zone: zone.to_string(), ip, ua: ua_digest(ua), issued: now(), bits: level.bits(), click, nonce, level }
    }

    fn payload(&self) -> String {
        format!("2|{}|{}|{}|{}|{}|{}|{}|{}", self.zone, self.ip, self.ua, self.issued, self.bits, self.click as u8, self.nonce, self.level.code())
    }

    pub fn seal(&self, waf: &Waf) -> String {
        let payload = self.payload();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("{b64}.{}", waf.mac(&format!("challenge|{payload}")))
    }

    pub fn open(waf: &Waf, sealed: &str) -> Option<Ticket> {
        let (b64, mac) = sealed.split_once('.')?;
        let payload = String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).ok()?).ok()?;
        if !waf.mac_ok(&format!("challenge|{payload}"), mac) {
            return None;
        }
        let f: Vec<&str> = payload.split('|').collect();
        let level = match (f.len(), f.first().copied()) {
            (8, Some("1")) => Level::Medium,
            (9, Some("2")) => Level::from_code(f[8])?,
            _ => return None,
        };
        Some(Ticket {
            zone: f[1].to_string(),
            ip: f[2].parse().ok()?,
            ua: f[3].to_string(),
            issued: f[4].parse().ok()?,
            bits: f[5].parse().ok()?,
            click: f[6] == "1",
            nonce: f[7].to_string(),
            level,
        })
    }
}

/// Does `n` do the work the ticket asks for?
pub fn work_done(sealed: &str, n: u64, bits: u8) -> bool {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("{sealed}:{n}").as_bytes());
    let mut zeros = 0u32;
    for b in digest.as_ref() {
        zeros += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    zeros >= bits as u32
}

/// What the page (or the script injected into a site's pages) is told: the
/// sealed ticket, the work, whether to ask for a click, where to answer.
pub fn config(waf: &Waf, zone_id: &str, ip: IpAddr, ua: &str, click: bool, level: Level) -> Value {
    let ticket = Ticket::at(zone_id, ip, ua, click, level);
    json!({ "t": ticket.seal(waf), "b": ticket.bits, "c": click, "v": VERIFY_PATH })
}

/// The answer to a request that is not a page load (fetch, XHR, an API
/// client): JSON instead of a page, with `fcf-mitigated: challenge` and what
/// the injected script needs to settle it without leaving the page.
pub fn for_script(waf: &Waf, zone_id: &str, ip: IpAddr, ua: &str, click: bool, level: Level, ray: &str) -> Response<Body> {
    let body = json!({
        "success": false,
        "errors": [{ "code": 1020, "message": "a human check is needed: load the page in a browser, or pass the challenge" }],
        "challenge": config(waf, zone_id, ip, ua, click, level),
        "ray": ray,
    });
    let mut resp = answer(StatusCode::FORBIDDEN, body);
    resp.headers_mut().insert("fcf-mitigated", HeaderValue::from_static("challenge"));
    resp.headers_mut().insert("fcf-challenge", HeaderValue::from_static(VERIFY_PATH));
    resp
}

/// Is this request a page load (rather than fetch / XHR / an API client)?
pub fn is_navigation(headers: &HeaderMap) -> bool {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or_default();
    if !h("x-requested-with").is_empty() {
        return false;
    }
    match h("sec-fetch-mode") {
        // older browsers and plain clients: by what they accept
        "" => h("accept").is_empty() || h("accept").contains("text/html"),
        mode => mode == "navigate",
    }
}

/// The challenge page for a visitor of `zone_id`.
#[cfg(test)]
pub fn page(waf: &Waf, zone_id: &str, ip: IpAddr, ua: &str, click: bool, ray: &str, lang: Lang, colo: &str) -> Response<Body> {
    page_at(waf, zone_id, ip, ua, click, ray, lang, colo, Level::Medium)
}

/// The challenge page, at a security level.
#[allow(clippy::too_many_arguments)]
pub fn page_at(waf: &Waf, zone_id: &str, ip: IpAddr, ua: &str, click: bool, ray: &str, lang: Lang, colo: &str, level: Level) -> Response<Body> {
    let config = config(waf, zone_id, ip, ua, click, level).to_string();
    let (html_lang, lang) = match lang {
        Lang::En => ("en", "en"),
        Lang::Zh => ("zh-CN", "zh"),
    };
    let heading = if click { bi("请确认你是真人", "Verify you are human") } else { bi("正在检查你的浏览器", "Checking your browser") };
    let lead = if click {
        bi("在继续访问之前，请点一下下面的方框。", "Click the box below to continue.")
    } else {
        bi("这通常只需要一两秒，完成后会自动继续。", "This usually takes a second or two, and continues by itself.")
    };
    let html = format!(
        "<!doctype html><html lang=\"{html_lang}\" data-lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\">\
         <title>{title}</title><style>{PAGE_CSS}{CSS}</style></head><body><main>\
         <button type=\"button\" id=\"lang\" class=\"lang\" aria-label=\"Language / 语言\"><span data-l=\"zh\">English</span><span data-l=\"en\">中文</span></button>\
         {PAGE_MARK}<h1>{heading}</h1><p>{lead}</p>\
         <div class=\"fc\" id=\"box\" data-state=\"working\">\
           <label class=\"fc-cb\"><input type=\"checkbox\" id=\"cb\" disabled><i aria-hidden=\"true\"></i>\
             <span class=\"fc-text\"><span class=\"s-working\">{working}</span><span class=\"s-ready\">{ready}</span>\
             <span class=\"s-verifying\">{verifying}</span><span class=\"s-done\">{done}</span><span class=\"s-fail\">{fail}</span></span></label>\
           <span class=\"fc-brand\">fucf<small>{privacy}</small></span>\
         </div>\
         <p class=\"fc-msg\"><code id=\"msg\"></code></p>\
         <div class=\"acts fc-retry\"><button type=\"button\" id=\"retry\">{again}</button></div>\
         <noscript><p>{noscript}</p></noscript>\
         <footer><span>Ray ID <code>{ray}</code></span><span>{node} <code>{colo}</code></span><span>fucf</span></footer>\
         </main><script type=\"application/json\" id=\"fc\">{config}</script><script>{SCRIPT}</script>{LANG_SCRIPT}</body></html>",
        title = if click { "请稍候… · Just a moment..." } else { "请稍候… · Just a moment..." },
        working = bi("正在验证…", "Verifying…"),
        ready = bi("确认您是真人", "Verify you are human"),
        verifying = bi("正在验证…", "Verifying…"),
        done = bi("成功！", "Success!"),
        fail = bi("验证失败", "Verification failed"),
        privacy = bi("人机验证", "human check"),
        again = bi("重试", "Try again"),
        noscript = bi("请启用 JavaScript 后继续。", "Enable JavaScript to continue."),
        node = bi("节点", "Node"),
        colo = escape(colo),
        ray = escape(ray),
    );
    let mut resp = Response::new(full(html));
    *resp.status_mut() = StatusCode::FORBIDDEN;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store, max-age=0"));
    h.insert(header::VARY, HeaderValue::from_static("Accept-Language"));
    // what Cloudflare sends with a challenge: clients that cannot run it can tell
    h.insert("fcf-mitigated", HeaderValue::from_static("challenge"));
    resp
}

const CSS: &str = "\
.fc{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:1.75rem 0 .5rem;padding:14px 16px;min-height:66px;\
border:1px solid var(--line);border-radius:.75rem;background:var(--chip);max-width:22rem}\
.fc-cb{display:flex;align-items:center;gap:12px;cursor:pointer;font-size:15px;color:var(--fg)}\
.fc-cb input{position:absolute;opacity:0;width:1px;height:1px}\
.fc-cb i{position:relative;flex:none;width:26px;height:26px;border:2px solid var(--sub);border-radius:6px;background:var(--bg);transition:border-color .15s}\
.fc-cb:hover i{border-color:var(--clay)}\
.fc-cb input:focus-visible+i{outline:2px solid #c46849;outline-offset:2px}\
.fc[data-state=working] .fc-cb i,.fc[data-state=verifying] .fc-cb i{border:2.5px solid var(--line);border-top-color:var(--clay);border-radius:50%;animation:r .9s linear infinite}\
.fc[data-state=done] .fc-cb i{border-color:#2f7a52;background:#2f7a52}\
.fc[data-state=done] .fc-cb i::after{content:'';position:absolute;left:7px;top:2px;width:7px;height:13px;border:solid #fff;border-width:0 3px 3px 0;transform:rotate(45deg)}\
.fc[data-state=fail] .fc-cb i{border-color:#b5462a}\
.fc-text>span{display:none}\
.fc[data-state=working] .s-working,.fc[data-state=ready] .s-ready,.fc[data-state=verifying] .s-verifying,.fc[data-state=done] .s-done,.fc[data-state=fail] .s-fail{display:inline}\
.fc[data-state=working] .fc-cb,.fc[data-state=verifying] .fc-cb,.fc[data-state=done] .fc-cb{cursor:default}\
.fc-brand{display:flex;flex-direction:column;align-items:flex-end;font:600 13px/1.2 ui-monospace,'SF Mono',Consolas,monospace;color:var(--clay)}\
.fc-brand small{font:11px/1.3 inherit;font-family:inherit;color:var(--faint);font-weight:400}\
.fc-msg{min-height:1.5em;font-size:13px}.fc-msg code{font:12.5px ui-monospace,'SF Mono',Consolas,monospace;color:var(--faint)}\
.fc-retry{display:none}.fc[data-state=fail]~.fc-retry{display:flex}";

/// How a browser's answer is judged.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Pass,
    /// Doubtful: one click (a trusted, human-paced one) settles it.
    NeedClick,
    Fail(&'static str),
}

/// Judge what a browser sent (`answer`: the page's report) together with the
/// headers of its request. `clicked`: the report comes with a click.
/// Returns the outcome, the doubt score and what added to it.
#[cfg(test)]
pub fn assess(answer: &Value, headers: &HeaderMap, ssl: bool, clicked: bool) -> (Outcome, u32, Vec<&'static str>) {
    assess_at(answer, headers, ssl, clicked, Level::Medium)
}

/// The JavaScript engine a User-Agent claims: `v8`, `sm` (Firefox) or `jsc` (Safari, and everything on iOS).
fn claimed_engine(ua: &str) -> Option<&'static str> {
    if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        return Some("jsc");
    }
    if ua.contains("Firefox/") {
        Some("sm")
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") || ua.contains("Edg/") {
        Some("v8")
    } else if ua.contains("Safari/") && ua.contains("Version/") {
        Some("jsc")
    } else {
        None
    }
}

/// The platform `navigator.platform` should name for a User-Agent, as a test.
fn platform_fits(ua: &str, platform: &str) -> bool {
    let p = platform.to_ascii_lowercase();
    if ua.contains("Windows") {
        p.starts_with("win")
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        p.starts_with("iphone") || p.starts_with("ipad") || p.starts_with("macintel")
    } else if ua.contains("Macintosh") {
        p.starts_with("mac")
    } else if ua.contains("Android") || ua.contains("Linux") || ua.contains("CrOS") {
        p.contains("linux") || p.contains("android") || p.starts_with("arm") || p.contains("cros")
    } else {
        true
    }
}

pub fn assess_at(answer: &Value, headers: &HeaderMap, ssl: bool, clicked: bool, level: Level) -> (Outcome, u32, Vec<&'static str>) {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let ua = header("user-agent");
    let s = &answer["s"];
    let mut why: Vec<&'static str> = Vec::new();
    let fail = |code: &'static str, why: Vec<&'static str>| (Outcome::Fail(code), 0, why);

    if !s.is_object() {
        return fail("no_signals", why);
    }
    let lower = ua.to_ascii_lowercase();
    if ["headlesschrome", "phantomjs", "headless", "electron/", "puppeteer", "playwright", "selenium"].iter().any(|m| lower.contains(m)) {
        return fail("headless", why);
    }
    if s["wd"] == true {
        return fail("webdriver", why);
    }
    if s["auto"].as_array().is_some_and(|a| !a.is_empty()) {
        return fail("automation", why);
    }
    if s["ua"].as_str() != Some(ua) {
        return fail("user_agent_mismatch", why);
    }
    // what a page's frames and workers say must be what the page says (spoofing only the top is common)
    if s["ifr"].as_str().is_some_and(|f| f != ua) || s["wk"].as_str().is_some_and(|w| w != ua) {
        return fail("user_agent_spoofed", why);
    }
    if s["ifwd"] == true {
        return fail("webdriver", why);
    }
    if clicked {
        let c = &answer["c"];
        if c["trusted"] != true {
            return fail("untrusted_click", why);
        }
        if c["dt"].as_u64().unwrap_or(0) < 150 {
            return fail("too_fast", why);
        }
    }

    let mut score = 0u32;
    let mut doubt = |points: u32, reason: &'static str| {
        score += points;
        why.push(reason);
    };
    let desktop_chromium = ua.contains("Chrome/") && !ua.contains("Mobile") && !ua.contains("Android");
    if desktop_chromium {
        if s["plug"].as_i64() == Some(0) {
            doubt(2, "no_plugins");
        }
        if s["chrome"] == false {
            doubt(1, "no_window_chrome");
        }
        // Chromium sends client hints on secure pages, and has navigator.userAgentData there
        if ssl && headers.get("sec-ch-ua").is_none() {
            doubt(2, "no_client_hints");
        }
        if ssl && s["uad"].is_null() {
            doubt(1, "no_user_agent_data");
        }
    }
    if s["langs"].as_i64() == Some(0) {
        doubt(3, "no_languages");
    }
    let win = |i: usize| s["win"].get(i).and_then(Value::as_i64);
    if win(2) == Some(0) || win(3) == Some(0) {
        doubt(3, "no_outer_window");
    }
    if s["scr"].get(0).and_then(Value::as_i64) == Some(0) {
        doubt(3, "no_screen");
    }
    if s["notif"] == "denied" && s["perm"] == "prompt" {
        doubt(3, "permissions_contradict");
    }
    if s["nat"].as_i64().unwrap_or(0) > 0 {
        doubt(3, "patched_natives");
    }
    if s["wdp"] == false {
        doubt(3, "patched_webdriver");
    }
    if s["own"].as_i64().unwrap_or(0) > 0 {
        doubt(2, "navigator_own_properties");
    }
    let gl = s["gl"].as_str().unwrap_or_default().to_ascii_lowercase();
    if ["swiftshader", "llvmpipe", "softpipe", "mesa offscreen"].iter().any(|m| gl.contains(m)) {
        doubt(2, "software_webgl");
    }
    if s["cdp"] == true {
        doubt(2, "debugger_attached");
    }
    if s["hc"].as_i64() == Some(0) {
        doubt(1, "no_cpu_count");
    }
    if s["tz"].as_str() == Some("") {
        doubt(1, "no_time_zone");
    }
    if header("accept-language").is_empty() {
        doubt(2, "no_accept_language");
    }
    if clicked && answer["c"]["pt"] == "mouse" && answer["ev"]["moves"].as_u64() == Some(0) {
        doubt(2, "click_without_moving");
    }
    // the engine behind the page, from how it words errors and prints functions
    if let (Some(claimed), Some(seen)) = (claimed_engine(ua), s["eng"].as_str()) {
        if claimed != seen {
            doubt(4, "engine_mismatch");
        }
    }
    if let Some(len) = s["evl"].as_i64() {
        let expected = match claimed_engine(ua) {
            Some("sm") => Some(37),
            Some("v8") | Some("jsc") => Some(33),
            _ => None,
        };
        if expected.is_some_and(|e| e != len) {
            doubt(2, "native_code_mismatch");
        }
    }
    if s["plat"].as_str().is_some_and(|p| !platform_fits(ua, p)) {
        doubt(3, "platform_mismatch");
    }
    let mobile = ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone");
    if mobile && s["touch"].as_i64() == Some(0) {
        doubt(2, "mobile_without_touch");
    }
    if s["cnv"] == false {
        // the same drawing twice, two different pictures: canvas noise of an anti-detect browser
        doubt(2, "canvas_noise");
    }
    if !mobile && desktop_chromium && win(0).is_some() && win(0) == win(2) && win(1) == win(3) && win(1).unwrap_or(0) > 0 {
        // a desktop browser window has toolbars: outer taller than inner
        doubt(1, "window_without_toolbars");
    }
    if desktop_chromium && ssl && headers.get("sec-fetch-site").is_none() && headers.get("sec-fetch-mode").is_none() {
        doubt(2, "no_fetch_metadata");
    }
    if s["dev"].as_i64() == Some(0) && desktop_chromium {
        doubt(1, "no_media_devices");
    }
    if let (Some(n), Some(ms)) = (answer["n"].as_u64(), answer["ms"].as_u64()) {
        // a page's script does well under a few million hashes a second: faster work was done elsewhere
        if n > 20_000 && ms * 5_000 < n {
            doubt(3, "work_off_page");
        }
    }
    if answer["ev"]["lin"] == true {
        doubt(2, "linear_pointer");
    }
    let first_lang = header("accept-language").split([',', ';']).next().unwrap_or("").trim().to_ascii_lowercase();
    if let Some(l0) = s["l0"].as_str() {
        let l0 = l0.to_ascii_lowercase();
        if !first_lang.is_empty() && !l0.is_empty() && first_lang.split('-').next() != l0.split('-').next() {
            doubt(1, "language_mismatch");
        }
    }

    let outcome = if score >= level.fail_score() {
        Outcome::Fail("automated")
    } else if score > level.click_above() && !clicked {
        Outcome::NeedClick
    } else {
        Outcome::Pass
    };
    (outcome, score, why)
}

fn answer(status: StatusCode, body: Value) -> Response<Body> {
    let mut resp = Response::new(full(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `POST /cdn-cgi/challenge-platform/verify`: the page's answer.
pub fn verify(
    waf: std::sync::Arc<Waf>,
    ip: IpAddr,
    ssl: bool,
    req: Request<Body>,
    ray: String,
) -> impl std::future::Future<Output = Result<Response<Body>, EdgeError>> + Send + 'static {
    async move { Ok(answer_of(waf, ip, ssl, req, ray).await) }
}

async fn answer_of(waf: std::sync::Arc<Waf>, ip: IpAddr, ssl: bool, req: Request<Body>, ray: String) -> Response<Body> {
    if req.method() != Method::POST {
        return answer(StatusCode::METHOD_NOT_ALLOWED, json!({ "ok": false, "code": "post_only" }));
    }
    let (parts, mut body) = req.into_parts();
    // frame by frame (http_body_util::Limited trips a higher-ranked lifetime bug of rustc here)
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { return answer(StatusCode::BAD_REQUEST, json!({ "ok": false, "code": "unreadable" })) };
        if let Some(data) = frame.data_ref() {
            bytes.extend_from_slice(data);
        }
        if bytes.len() > MAX_ANSWER {
            return answer(StatusCode::PAYLOAD_TOO_LARGE, json!({ "ok": false, "code": "too_large" }));
        }
    }
    let Ok(report) = serde_json::from_slice::<Value>(&bytes) else {
        return answer(StatusCode::BAD_REQUEST, json!({ "ok": false, "code": "unreadable" }));
    };
    judge(&waf, ip, ssl, &parts.headers, &report, &ray)
}

/// The verdict on a page's answer (no awaiting from here on).
fn judge(waf: &Waf, ip: IpAddr, ssl: bool, headers: &HeaderMap, report: &Value, ray: &str) -> Response<Body> {
    let sealed = report["t"].as_str().unwrap_or_default();
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default();
    fn refuse(code: &'static str) -> Response<Body> {
        answer(StatusCode::FORBIDDEN, json!({ "ok": false, "code": code }))
    }
    let Some(ticket) = Ticket::open(waf, sealed) else { return refuse("bad_ticket") };
    let age = now().saturating_sub(ticket.issued);
    if ticket.issued > now() + 5 || age > TICKET_SECS {
        return refuse("expired");
    }
    if ticket.ip != ip || ticket.ua != ua_digest(ua) {
        return refuse("other_visitor");
    }
    if !report["n"].as_u64().is_some_and(|n| work_done(sealed, n, ticket.bits)) {
        return refuse("bad_work");
    }
    let clicked = report["m"] == "click";
    if ticket.click && !clicked {
        return answer(StatusCode::OK, json!({ "ok": false, "need": "click" }));
    }
    let (outcome, score, why) = assess_at(report, headers, ssl, clicked, ticket.level);
    tracing::info!(%ray, client = %ip, score, clicked, signals = ?why, "challenge answer: {outcome:?}");
    match outcome {
        Outcome::Pass => {
            let mut resp = answer(StatusCode::OK, json!({ "ok": true }));
            let cookie = format!(
                "{CLEARANCE_COOKIE}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
                waf.clearance_token(&ticket.zone, ip),
                super::waf::CLEARANCE_SECS,
                if ssl { "; Secure" } else { "" }
            );
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(header::SET_COOKIE, v);
            }
            resp
        }
        Outcome::NeedClick => answer(StatusCode::OK, json!({ "ok": false, "need": "click" })),
        Outcome::Fail(code) => refuse(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

    fn chrome_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::USER_AGENT, HeaderValue::from_static(CHROME));
        h.insert("sec-ch-ua", HeaderValue::from_static("\"Chromium\";v=\"131\", \"Google Chrome\";v=\"131\""));
        h.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN,zh;q=0.9,en;q=0.8"));
        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        h
    }

    /// What a desktop Chrome that a person uses reports.
    fn person() -> Value {
        json!({
            "m": "auto",
            "s": {
                "wd": false, "auto": [], "ua": CHROME, "uad": { "m": false, "p": "Windows", "b": ["Chromium", "Google Chrome"] },
                "langs": 3, "plug": 5, "hc": 8, "scr": [1920, 1080, 1920, 1040, 24], "win": [1536, 760, 1550, 870],
                "tz": "Asia/Shanghai", "touch": 0, "chrome": true, "own": 0, "wdp": true, "nat": 0,
                "gl": "Google Inc. (NVIDIA) / ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "cdp": false, "notif": "default", "perm": "prompt"
            },
            "ev": { "moves": 23, "dist": 640, "first": 300, "keys": 0, "touch": 0, "scroll": 0, "age": 900 }
        })
    }

    #[test]
    fn a_person_passes_at_once_and_automation_does_not() {
        let h = chrome_headers();
        assert_eq!(assess(&person(), &h, true, false).0, Outcome::Pass);

        let with = |path: &str, value: Value| {
            let mut a = person();
            a["s"][path] = value;
            a
        };
        assert_eq!(assess(&with("wd", json!(true)), &h, true, false).0, Outcome::Fail("webdriver"));
        assert_eq!(assess(&with("auto", json!(["__playwright__binding__"])), &h, true, false).0, Outcome::Fail("automation"));
        assert_eq!(assess(&with("ua", json!("Mozilla/5.0 something else")), &h, true, false).0, Outcome::Fail("user_agent_mismatch"));
        let mut headless = h.clone();
        headless.insert(header::USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/131.0.0.0 Safari/537.36"));
        assert_eq!(assess(&person(), &headless, true, false).0, Outcome::Fail("headless"));

        // doubtful: asked to click
        let (outcome, score, why) = assess(&with("cdp", json!(true)), &h, true, false);
        assert_eq!((outcome, score, why), (Outcome::NeedClick, 2, vec!["debugger_attached"]));
        // what a headless browser in disguise looks like: no plugins, software WebGL, contradicting permissions
        let mut stealth = person();
        stealth["s"]["plug"] = json!(0);
        stealth["s"]["gl"] = json!("Google Inc. (Google) / ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)");
        stealth["s"]["notif"] = json!("denied");
        let (outcome, score, _) = assess(&stealth, &h, true, false);
        assert_eq!((outcome, score), (Outcome::Fail("automated"), 7));
        let mut no_hints = h.clone();
        no_hints.remove("sec-ch-ua");
        no_hints.remove(header::ACCEPT_LANGUAGE);
        assert_eq!(assess(&person(), &no_hints, true, false).1, 4, "no client hints, no Accept-Language");
        assert_eq!(assess(&with("plug", json!(0)), &no_hints, true, false).0, Outcome::Fail("automated"));
        assert_eq!(assess(&json!({}), &h, true, false).0, Outcome::Fail("no_signals"));
    }

    #[test]
    fn spoofed_browsers_give_themselves_away() {
        let h = chrome_headers();
        let with = |k: &str, v: Value| {
            let mut a = person();
            a["s"][k] = v;
            a
        };
        assert_eq!(assess(&with("eng", json!("v8")), &h, true, false).0, Outcome::Pass);
        assert_eq!(assess(&with("eng", json!("sm")), &h, true, false), (Outcome::NeedClick, 4, vec!["engine_mismatch"]));
        assert_eq!(assess(&with("plat", json!("Linux x86_64")), &h, true, false).2, vec!["platform_mismatch"]);
        assert_eq!(assess(&with("plat", json!("Win32")), &h, true, false).0, Outcome::Pass);
        assert_eq!(assess(&with("ifr", json!("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/131")), &h, true, false).0, Outcome::Fail("user_agent_spoofed"));
        assert_eq!(assess(&with("cnv", json!(false)), &h, true, false).2, vec!["canvas_noise"]);
        let mut fast = person();
        fast["n"] = json!(400_000);
        fast["ms"] = json!(3);
        assert_eq!(assess(&fast, &h, true, false).2, vec!["work_off_page"]);
        // the level decides how much doubt is too much
        let doubtful = with("eng", json!("sm"));
        assert_eq!(assess_at(&doubtful, &h, true, false, Level::High).0, Outcome::Fail("automated"));
        assert_eq!(assess_at(&with("plat", json!("Linux x86_64")), &h, true, false, Level::Low).0, Outcome::NeedClick);
        assert_eq!(assess_at(&with("cnv", json!(false)), &h, true, false, Level::Low).0, Outcome::Pass);
        assert_eq!(Level::Medium.challenge(30), None);
        assert_eq!(Level::High.challenge(30), Some(false));
        assert_eq!(Level::Medium.challenge(85), Some(true));
        assert_eq!(Level::UnderAttack.challenge(0), Some(false));
        assert_eq!(Level::Off.challenge(100), None);
        let waf = Waf::new();
        let t = Ticket::at("z", "198.51.100.7".parse().unwrap(), CHROME, false, Level::High);
        let opened = Ticket::open(&waf, &t.seal(&waf)).unwrap();
        assert_eq!((opened.level, opened.bits), (Level::High, 18));
        let mut nav = HeaderMap::new();
        nav.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        assert!(is_navigation(&nav));
        nav.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        assert!(!is_navigation(&nav));
        let mut old = HeaderMap::new();
        old.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(!is_navigation(&old));
        let r = for_script(&waf, "z", "198.51.100.7".parse().unwrap(), CHROME, true, Level::Medium, "ray");
        assert_eq!((r.status(), r.headers().get("fcf-mitigated").unwrap().to_str().unwrap()), (StatusCode::FORBIDDEN, "challenge"));
    }

    #[test]
    fn a_click_settles_doubt_when_it_is_a_real_one() {
        let h = chrome_headers();
        let mut a = person();
        a["m"] = json!("click");
        a["s"]["cdp"] = json!(true); // DevTools open
        a["c"] = json!({ "trusted": true, "dt": 900, "detail": 1, "pt": "mouse" });
        assert_eq!(assess(&a, &h, true, true).0, Outcome::Pass);
        a["c"]["trusted"] = json!(false);
        assert_eq!(assess(&a, &h, true, true).0, Outcome::Fail("untrusted_click"));
        a["c"] = json!({ "trusted": true, "dt": 40, "pt": "mouse" });
        assert_eq!(assess(&a, &h, true, true).0, Outcome::Fail("too_fast"));
        // a keyboard or touch: no pointer movement needed
        a["c"] = json!({ "trusted": true, "dt": 900, "detail": 0, "pt": "" });
        a["ev"]["moves"] = json!(0);
        assert_eq!(assess(&a, &h, true, true).0, Outcome::Pass);
    }

    #[test]
    fn tickets_are_sealed_and_bound() {
        let waf = Waf::new();
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let t = Ticket::new("zone1", ip, CHROME, true);
        let sealed = t.seal(&waf);
        assert_eq!(Ticket::open(&waf, &sealed), Some(t.clone()));
        let (b64, mac) = sealed.split_once('.').unwrap();
        let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t.payload().replace("|1|", "|0|"));
        assert_eq!(Ticket::open(&waf, &format!("{forged}.{mac}")), None, "a changed ticket");
        assert_eq!(Ticket::open(&Waf::new(), &sealed), None, "another fleet's secret");
        assert!(Ticket::open(&waf, b64).is_none());
        // the work: found by searching, checked in one hash
        let easy = 8;
        let n = (0u64..).find(|n| work_done(&sealed, *n, easy)).unwrap();
        assert!(work_done(&sealed, n, easy));
        assert!(!(0..n).any(|m| work_done(&sealed, m, easy)));
    }

    #[test]
    fn the_page_carries_its_ticket_and_script() {
        let waf = Waf::new();
        let r = page(&waf, "z", "198.51.100.7".parse().unwrap(), CHROME, true, "ray1", Lang::Zh, "SIN");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(r.headers().get("fcf-mitigated").unwrap(), "challenge");
    }
}
