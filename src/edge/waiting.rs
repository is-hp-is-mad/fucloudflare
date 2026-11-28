//! Waiting rooms: when the origin cannot take everybody, page loads over a
//! room's limits get a queue page instead, and visitors are let in first
//! come, first served.
//!
//! A [`WaitingRoom`] covers one host and a path prefix of a zone. It lets in
//! at most `new_users_per_minute` new visitors a minute while fewer than
//! `total_active_users` admitted sessions are active. An admitted visitor
//! carries a signed cookie (`Waf::mac`, the fleet's key) naming the room, a
//! random visitor id and an expiry, and passes directly until it expires;
//! page loads in the second half of a session renew it, so a session ends
//! `session_minutes` after the visitor's last page load.
//!
//! A queued visitor gets a signed ticket cookie with its arrival time. The
//! queue page reloads itself; each reload shows the ticket again and gets a
//! fresh one (same arrival time), and a ticket that was not shown for a while
//! is void, so leaving the line means losing the place. Tickets that arrived
//! earlier are let in first.
//!
//! Counting is per node: every node keeps its own sessions, admissions and
//! line in memory (bounded, pruned as sessions expire and tickets go stale)
//! and applies the limits to what it sees itself. Cookies are signed with
//! the fleet's key, so a visitor admitted by one node passes every node.
//!
//! The decisions are pure functions of a room's state, the time and what the
//! request carries ([`decide`]), so the tests need no clock or network.

use super::{bi, escape, full, Body, Edge, Lang, LANG_SCRIPT, PAGE_CSS, PAGE_MARK};
use crate::expr::ReqInfo;
use crate::items::{in_zone, Item, Meta};
use crate::store::{Data, StoreError, Zone, ZoneSnap};
use crate::sync::SyncMeta;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;

/// The cookie of an admitted visitor.
pub const COOKIE: &str = "fucf_waiting_room";
/// The cookie of a queued visitor: its place in line.
pub const TICKET_COOKIE: &str = "fucf_waiting_ticket";
/// How often the queue page reloads itself (and its `Retry-After`).
pub const REFRESH_SECS: u64 = 20;
/// A ticket not shown for this long is void: the visitor left the line.
/// Well above the refresh, as browsers slow down timers in background tabs.
pub const TICKET_STALE_SECS: u64 = 120;
/// How far nodes' clocks may disagree.
const SKEW_SECS: u64 = 60;
/// The window of `new_users_per_minute`.
const RATE_WINDOW_SECS: u64 = 60;
/// Upper bound of both limits; also bounds what a node keeps per room.
pub const MAX_USERS: u32 = 100_000;
pub const SESSION_MIN: u32 = 1;
pub const SESSION_MAX: u32 = 30;
const SESSION_DEFAULT: u32 = 5;
/// Rooms per zone.
pub const MAX_ROOMS_PER_ZONE: usize = 20;
/// Tickets a node keeps in line per room; more still get a ticket and are
/// counted once there is room.
const MAX_WAITING: usize = 100_000;
pub const PATH_MAX: usize = 256;
/// A room's state that nobody asked about for this long is dropped (the
/// room is gone, disabled, or quiet: every session in it has expired).
const IDLE_SECS: u64 = SESSION_MAX as u64 * 60 + TICKET_STALE_SECS;
/// How often idle rooms' states are looked for.
const SWEEP_SECS: u64 = 60;

// --------------------------------------------------------------- the item ----

fn yes() -> bool {
    true
}

fn root() -> String {
    "/".into()
}

fn session_default() -> u32 {
    SESSION_DEFAULT
}

/// A queue in front of one host and path prefix of a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitingRoom {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// One host name of the zone (no wildcard).
    #[serde(default)]
    pub host: String,
    /// The room covers this path and everything below it (`/shop` covers
    /// `/shop` and `/shop/cart`, not `/shopping`), the same paths its cookie
    /// is sent for.
    #[serde(default = "root")]
    pub path_prefix: String,
    /// Admitted sessions that may be active at once (per node).
    #[serde(default)]
    pub total_active_users: u32,
    /// New visitors let in per minute at most (per node).
    #[serde(default)]
    pub new_users_per_minute: u32,
    /// How long a session lasts after the visitor's last page load.
    #[serde(default = "session_default")]
    pub session_minutes: u32,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// Characters a path prefix may hold: those of a URI path that need no
/// quoting in a `Set-Cookie` `Path` (no `;`, `,`, quotes or spaces).
fn path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "/-._~!$&'()*+=:@%".contains(c)
}

/// The path prefix as stored: starts with `/`, no trailing `/` but the root.
pub fn check_path(p: &str) -> Result<String, String> {
    if !p.starts_with('/') || p.len() > PATH_MAX || !p.chars().all(path_char) {
        return Err(format!(
            "path_prefix must start with / and hold at most {PATH_MAX} of the characters a-z A-Z 0-9 / - . _ ~ ! $ & ' ( ) * + = : @ % (no query string)"
        ));
    }
    let trimmed = p.trim_end_matches('/');
    Ok(if trimmed.is_empty() { "/".into() } else { trimmed.to_string() })
}

impl Item for WaitingRoom {
    fn vec(d: &Data) -> &Vec<Self> {
        &d.waiting_rooms
    }
    fn vec_mut(d: &mut Data) -> &mut Vec<Self> {
        &mut d.waiting_rooms
    }
    fn tombstones(d: &Data) -> &BTreeMap<String, SyncMeta> {
        &d.tombstones.waiting_rooms
    }
    fn tombstones_mut(d: &mut Data) -> &mut BTreeMap<String, SyncMeta> {
        &mut d.tombstones.waiting_rooms
    }
    fn meta(&self) -> &Meta {
        &self.meta
    }
    fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
    fn validate(&mut self, zone: &Zone, d: &Data) -> Result<(), StoreError> {
        let invalid = |m: String| Err(StoreError::Invalid(m));
        let id = self.meta.id.clone();
        if zone.kind == "cert" {
            return invalid("a certificate-only zone is not proxied: it cannot have a waiting room".into());
        }
        if !d.waiting_rooms.iter().any(|r| r.meta.id == id)
            && d.waiting_rooms.iter().filter(|r| r.meta.zone_id == zone.id).count() >= MAX_ROOMS_PER_ZONE
        {
            return invalid(format!("a zone has at most {MAX_ROOMS_PER_ZONE} waiting rooms"));
        }
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.chars().count() > 64 || self.name.chars().any(char::is_control) {
            return invalid("a waiting room needs a name (max 64 characters)".into());
        }
        self.description = self.description.trim().to_string();
        if self.description.chars().count() > 256 || self.description.chars().any(char::is_control) {
            return invalid("description: at most 256 characters on one line".into());
        }

        let host = crate::dns::wire::normalize_name(&self.host).map_err(|e| StoreError::Invalid(format!("host: {e}")))?;
        if host.contains(['*', '_']) {
            return invalid(format!("host: '{host}' must be one host name, not a pattern"));
        }
        if !in_zone(zone, &host) {
            return invalid(format!("host '{host}' is not part of zone {}", zone.name));
        }
        // requests for a name inside a more specific zone go to that zone
        if let Some(inner) = d.zones.iter().find(|z| z.id != zone.id && z.kind != "cert" && z.name.len() > zone.name.len() && in_zone(z, &host)) {
            return invalid(format!("host '{host}' is served by zone {}, not by {}", inner.name, zone.name));
        }
        self.host = host;
        self.path_prefix = check_path(&self.path_prefix).map_err(StoreError::Invalid)?;

        if !(1..=MAX_USERS).contains(&self.total_active_users) {
            return invalid(format!("total_active_users must be between 1 and {MAX_USERS}"));
        }
        if !(1..=self.total_active_users).contains(&self.new_users_per_minute) {
            return invalid("new_users_per_minute must be between 1 and total_active_users".into());
        }
        if !(SESSION_MIN..=SESSION_MAX).contains(&self.session_minutes) {
            return invalid(format!("session_minutes must be between {SESSION_MIN} and {SESSION_MAX}"));
        }
        if self.enabled {
            if let Some(other) = d
                .waiting_rooms
                .iter()
                .find(|r| r.enabled && r.meta.id != id && r.host == self.host && r.path_prefix == self.path_prefix)
            {
                return Err(StoreError::Conflict(format!(
                    "waiting room '{}' already covers {}{}: disable it first",
                    other.name, self.host, self.path_prefix
                )));
            }
        }
        Ok(())
    }
}

/// Whether a room covers this request path (`prefix` as [`check_path`] leaves it).
pub fn covers(prefix: &str, path: &str) -> bool {
    prefix == "/" || path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// A path with its percent escapes decoded and runs of `/` made one, the
/// way most origins read it.
fn plain(path: &str) -> String {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    let mut out = String::with_capacity(decoded.len());
    for c in decoded.chars() {
        if !(c == '/' && out.ends_with('/')) {
            out.push(c);
        }
    }
    out
}

/// The room a request falls in: the longest path prefix of its host wins
/// (two rooms that cover the same paths, which only a race between nodes
/// can make, are told apart by id so every node picks the same one).
/// Paths are compared as [`plain`] leaves them, so `/%73hop` or `//shop`
/// cannot walk past a `/shop` room.
pub fn pick<'a>(rooms: &'a [WaitingRoom], host: &str, path: &str) -> Option<&'a WaitingRoom> {
    let path = plain(path);
    rooms
        .iter()
        .filter(|r| r.enabled && r.host == host && covers(&plain(&r.path_prefix), &path))
        .max_by(|a, b| a.path_prefix.len().cmp(&b.path_prefix.len()).then_with(|| b.meta.id.cmp(&a.meta.id)))
}

// ------------------------------------------------------------ cookies ----

/// What an admission cookie says, once its signature checked out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    pub visitor: u128,
    /// Unix seconds.
    pub expiry: u64,
}

/// What a ticket cookie says, once its signature checked out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    /// When the visitor got in line (unix seconds): the order of the line.
    pub issued: u64,
    /// Tells tickets of the same second apart.
    pub nonce: u64,
    /// When the ticket was last handed out (unix seconds).
    pub seen: u64,
}

impl Ticket {
    fn key(&self) -> (u64, u64) {
        (self.issued, self.nonce)
    }
}

fn admission_data(room: &str, visitor: u128, expiry: u64) -> String {
    format!("waiting-admit|{room}|{visitor:032x}|{expiry}")
}

fn ticket_data(room: &str, t: &Ticket) -> String {
    format!("waiting-ticket|{room}|{}|{:016x}|{}", t.issued, t.nonce, t.seen)
}

/// The admission cookie's value: `<room>.<visitor>.<expiry>.<mac>`.
pub fn admission_value(waf: &super::Waf, room: &str, a: &Admission) -> String {
    format!("{room}.{:032x}.{}.{}", a.visitor, a.expiry, waf.mac(&admission_data(room, a.visitor, a.expiry)))
}

/// The ticket cookie's value: `<room>.<issued>.<nonce>.<seen>.<mac>`.
pub fn ticket_value(waf: &super::Waf, room: &str, t: &Ticket) -> String {
    format!("{room}.{}.{:016x}.{}.{}", t.issued, t.nonce, t.seen, waf.mac(&ticket_data(room, t)))
}

/// The values of every cookie called `name` (HTTP/2 may split the header).
fn cookie_values<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(move |c| c.trim().strip_prefix(name)?.strip_prefix('='))
}

/// Lower-case hex of exactly `len` digits: the one spelling cookies are
/// written in, so that no other spelling of a value is taken for it.
fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex_u128(s: &str) -> Option<u128> {
    lower_hex(s, 32).then(|| u128::from_str_radix(s, 16).ok()).flatten()
}

fn hex_u64(s: &str) -> Option<u64> {
    lower_hex(s, 16).then(|| u64::from_str_radix(s, 16).ok()).flatten()
}

/// Decimal seconds without sign or leading zeros.
fn secs(s: &str) -> Option<u64> {
    let canonical = !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    canonical.then(|| s.parse().ok()).flatten()
}

/// The visitor's admission to `room`, if one of its cookies holds a valid
/// one: signed by the fleet, for this room, not expired, and not running
/// longer than the room's sessions do now. Anything else counts as no cookie,
/// another spelling of the same numbers (upper-case hex, leading zeros) too.
pub fn read_admission(waf: &super::Waf, headers: &HeaderMap, room: &WaitingRoom, now: u64) -> Option<Admission> {
    let longest = u64::from(room.session_minutes) * 60 + SKEW_SECS;
    cookie_values(headers, COOKIE).find_map(|v| {
        let mut parts = v.split('.');
        let (r, visitor, expiry, mac) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || r != room.meta.id {
            return None;
        }
        let (visitor, expiry) = (hex_u128(visitor)?, secs(expiry)?);
        let fresh = expiry > now && expiry <= now.saturating_add(longest);
        (fresh && waf.mac_ok(&admission_data(r, visitor, expiry), mac)).then_some(Admission { visitor, expiry })
    })
}

/// The visitor's place in the line of `room`, if one of its cookies holds a
/// valid ticket: signed, for this room, and shown again recently enough.
pub fn read_ticket(waf: &super::Waf, headers: &HeaderMap, room: &WaitingRoom, now: u64) -> Option<Ticket> {
    cookie_values(headers, TICKET_COOKIE).find_map(|v| {
        let mut parts = v.split('.');
        let (r, issued, nonce, seen, mac) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || r != room.meta.id {
            return None;
        }
        let t = Ticket { issued: secs(issued)?, nonce: hex_u64(nonce)?, seen: secs(seen)? };
        let fresh = t.issued <= t.seen && t.seen <= now.saturating_add(SKEW_SECS) && now.saturating_sub(t.seen) <= TICKET_STALE_SECS;
        (fresh && waf.mac_ok(&ticket_data(r, &t), mac)).then_some(t)
    })
}

/// A `Set-Cookie` value. `Secure` when the visitor came over TLS (a plain
/// HTTP site would never get it back otherwise); the path is the room's, so
/// the cookie goes where the room applies and nowhere else.
fn set_cookie(name: &str, value: &str, path: &str, max_age: u64, ssl: bool) -> Option<HeaderValue> {
    let secure = if ssl { "; Secure" } else { "" };
    HeaderValue::from_str(&format!("{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")).ok()
}

// ----------------------------------------------------------- deciding ----

/// What one node keeps about one room.
#[derive(Debug, Default)]
pub struct RoomState {
    /// Admitted sessions not yet expired: visitor id to expiry.
    active: HashMap<u128, u64>,
    /// When visitors were let in, over the last minute (oldest first).
    admits: VecDeque<u64>,
    /// The line: ticket to when it was last shown.
    waiting: HashMap<(u64, u64), u64>,
    /// Tickets already turned into an admission (and when): shown again
    /// (a copied cookie, a second tab) they count as no ticket.
    spent: HashMap<(u64, u64), u64>,
    /// Arrival seconds of the line with how many tickets arrived up to
    /// then, sorted: places in line by binary search, rebuilt on each tick.
    index: Vec<(u64, usize)>,
    /// The second of the last [`RoomState::tick`].
    ticked: Option<u64>,
    /// When anybody last asked about this room.
    touched: u64,
}

impl RoomState {
    /// Drops what is over: the admissions of more than a minute ago on every
    /// call, expired sessions and stale tickets once a second.
    fn tick(&mut self, now: u64) {
        while self.admits.front().is_some_and(|&t| t + RATE_WINDOW_SECS <= now) {
            self.admits.pop_front();
        }
        if self.ticked == Some(now) {
            return;
        }
        self.ticked = Some(now);
        self.active.retain(|_, expiry| *expiry > now);
        self.waiting.retain(|_, seen| now.saturating_sub(*seen) <= TICKET_STALE_SECS);
        self.spent.retain(|_, at| now.saturating_sub(*at) <= TICKET_STALE_SECS);
        let mut per_second: BTreeMap<u64, usize> = BTreeMap::new();
        for (issued, _) in self.waiting.keys() {
            *per_second.entry(*issued).or_default() += 1;
        }
        let mut total = 0;
        self.index = per_second
            .into_iter()
            .map(|(second, n)| {
                total += n;
                (second, total)
            })
            .collect();
    }

    /// Tickets in line that arrived in an earlier second (as of the last tick).
    fn ahead_of(&self, issued: u64) -> usize {
        match self.index.partition_point(|&(second, _)| second < issued) {
            0 => 0,
            i => self.index[i - 1].1,
        }
    }

    /// Admitted sessions this node counts.
    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.active.len()
    }

    /// Tickets in this node's line.
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

/// A room's limits, in the units [`decide`] counts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub total: usize,
    pub per_minute: usize,
    /// Seconds.
    pub session: u64,
}

impl Limits {
    pub fn of(room: &WaitingRoom) -> Self {
        Limits {
            total: room.total_active_users as usize,
            per_minute: room.new_users_per_minute as usize,
            session: u64::from(room.session_minutes) * 60,
        }
    }
}

/// What to do with a page load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An admitted visitor: on to the origin as it is.
    Pass,
    /// On to the origin with this admission (new, or renewed); `spent`: the
    /// visitor's ticket is used up, its cookie can go.
    Admit { admission: Admission, spent: bool },
    /// The queue page, with this ticket and roughly this many ahead.
    Queue { ticket: Ticket, ahead: usize },
}

/// The waiting room's decision for one page load at `now` (unix seconds),
/// given what the visitor's cookies validly hold (see [`read_admission`],
/// [`read_ticket`]) and a random number for a new visitor id or ticket.
///
/// An admitted visitor passes; one whose session is in its second half gets
/// it renewed. Anybody else is let in only if both the free sessions and
/// what is left of this minute's admissions exceed the tickets ahead of it
/// (all of them, for a visitor without a ticket), so that earlier tickets get
/// the places first; otherwise it is queued, keeping its ticket's arrival.
pub fn decide(st: &mut RoomState, lim: &Limits, now: u64, admission: Option<Admission>, ticket: Option<Ticket>, fresh: u128) -> Outcome {
    st.touched = now;
    st.tick(now);
    if let Some(a) = admission {
        // sessions another node admitted count here too, within bounds
        let room_for_more = st.active.len() < lim.total.saturating_mul(2);
        match st.active.get_mut(&a.visitor) {
            Some(expiry) => *expiry = (*expiry).max(a.expiry),
            None if room_for_more => {
                st.active.insert(a.visitor, a.expiry);
            }
            None => {}
        }
        if a.expiry.saturating_sub(now).saturating_mul(2) < lim.session {
            let renewed = Admission { visitor: a.visitor, expiry: now + lim.session };
            if let Some(expiry) = st.active.get_mut(&a.visitor) {
                *expiry = renewed.expiry;
            }
            return Outcome::Admit { admission: renewed, spent: ticket.is_some() };
        }
        return Outcome::Pass;
    }

    let ticket = ticket.filter(|t| !st.spent.contains_key(&t.key()));
    let free = lim.total.saturating_sub(st.active.len());
    let rate_left = lim.per_minute.saturating_sub(st.admits.len());
    let ahead = match &ticket {
        Some(t) => st.ahead_of(t.issued),
        None => st.waiting.len(),
    };
    if ahead < free.min(rate_left) {
        if let Some(t) = &ticket {
            st.waiting.remove(&t.key());
            st.spent.insert(t.key(), now);
        }
        let admission = Admission { visitor: fresh, expiry: now + lim.session };
        st.active.insert(admission.visitor, admission.expiry);
        st.admits.push_back(now);
        return Outcome::Admit { admission, spent: ticket.is_some() };
    }
    let ticket = match ticket {
        Some(t) => Ticket { seen: now, ..t },
        // the low half of the random number; the high half is a visitor id elsewhere
        None => Ticket { issued: now, nonce: fresh as u64, seen: now },
    };
    if st.waiting.contains_key(&ticket.key()) || st.waiting.len() < MAX_WAITING {
        st.waiting.insert(ticket.key(), now);
    }
    Outcome::Queue { ticket, ahead }
}

/// Every room's state on this node.
#[derive(Default)]
pub struct WaitingRooms {
    rooms: Mutex<(HashMap<String, RoomState>, u64)>,
}

impl WaitingRooms {
    /// [`decide`] for a room, on this node's state of it.
    pub fn decide(&self, room: &WaitingRoom, now: u64, admission: Option<Admission>, ticket: Option<Ticket>, fresh: u128) -> Outcome {
        let mut guard = self.rooms.lock().unwrap();
        let (rooms, swept) = &mut *guard;
        if now.saturating_sub(*swept) >= SWEEP_SECS {
            *swept = now;
            rooms.retain(|_, st| now.saturating_sub(st.touched) <= IDLE_SECS);
        }
        let st = rooms.entry(room.meta.id.clone()).or_default();
        decide(st, &Limits::of(room), now, admission, ticket, fresh)
    }

    /// `(active sessions, tickets in line)` of a room on this node.
    #[cfg(test)]
    pub fn counts(&self, room_id: &str) -> (usize, usize) {
        let guard = self.rooms.lock().unwrap();
        guard.0.get(room_id).map(|st| (st.active(), st.waiting())).unwrap_or((0, 0))
    }

    /// How many rooms this node keeps a state for.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.rooms.lock().unwrap().0.len()
    }
}

// --------------------------------------------------- in the request flow ----

/// What `process` knows about a request when it asks the waiting room.
pub(super) struct Visit<'a> {
    pub info: &'a ReqInfo,
    pub headers: &'a HeaderMap,
    pub ssl: bool,
    /// A firewall `skip` rule let it through: it skips the room too.
    pub skipped: bool,
    pub ray: &'a str,
    pub lang: Lang,
}

/// The waiting room's answer to a request.
pub(super) enum Gate {
    /// On to the origin, with these `Set-Cookie` values on the answer.
    Pass(Vec<HeaderValue>),
    /// The queue page instead.
    Queue(Response<Body>),
}

/// Only page loads wait: assets, API calls and form posts without a cookie
/// pass, as queueing them would break the pages admitted visitors already
/// have (or lose what was posted) without protecting much.
fn is_page(info: &ReqInfo, headers: &HeaderMap) -> bool {
    (info.method == Method::GET.as_str() || info.method == Method::HEAD.as_str()) && super::challenge::is_navigation(headers)
}

/// Checks a request against the zone's waiting rooms, before it goes to a
/// Worker or the origin. `/cdn-cgi/` and requests a firewall `skip` passed
/// never wait.
pub(super) fn gate(edge: &Edge, zone: &ZoneSnap, v: &Visit) -> Gate {
    if zone.waiting_rooms.is_empty() || v.skipped || v.info.path.starts_with("/cdn-cgi/") || !is_page(v.info, v.headers) {
        return Gate::Pass(Vec::new());
    }
    let Some(room) = pick(&zone.waiting_rooms, &v.info.host, &v.info.path) else { return Gate::Pass(Vec::new()) };
    let now = crate::sync::clock::unix_ms() / 1000;
    let admission = read_admission(&edge.waf, v.headers, room, now);
    let ticket = if admission.is_none() { read_ticket(&edge.waf, v.headers, room, now) } else { None };
    let id = room.meta.id.as_str();
    match edge.waiting.decide(room, now, admission, ticket, uuid::Uuid::new_v4().as_u128()) {
        Outcome::Pass => Gate::Pass(Vec::new()),
        Outcome::Admit { admission, spent } => {
            let mut cookies = Vec::new();
            cookies.extend(set_cookie(COOKIE, &admission_value(&edge.waf, id, &admission), &room.path_prefix, admission.expiry - now, v.ssl));
            if spent {
                cookies.extend(set_cookie(TICKET_COOKIE, "", &room.path_prefix, 0, v.ssl));
            }
            Gate::Pass(cookies)
        }
        Outcome::Queue { ticket, ahead } => {
            let mut resp = queue_page(ahead, room.new_users_per_minute, v.ray, &edge.here().colo, v.lang);
            if let Some(c) = set_cookie(TICKET_COOKIE, &ticket_value(&edge.waf, id, &ticket), &room.path_prefix, TICKET_STALE_SECS, v.ssl) {
                resp.headers_mut().append(header::SET_COOKIE, c);
            }
            Gate::Queue(resp)
        }
    }
}

/// Puts the waiting room's cookies on the answer. Called after the cache
/// had its look at the origin's answer, so they are never cached.
pub(super) fn stamp(resp: &mut Response<Body>, cookies: Vec<HeaderValue>) {
    for c in cookies {
        resp.headers_mut().append(header::SET_COOKIE, c);
    }
}

/// Roughly how many minutes the line ahead takes at the room's pace.
pub fn wait_minutes(ahead: usize, per_minute: u32) -> u64 {
    (ahead as u64 / u64::from(per_minute.max(1))) + 1
}

/// The queue page: reloads itself every [`REFRESH_SECS`]. Status 200, as
/// Cloudflare answers, so that it is not mistaken for an error (nor
/// replaced by an error page); `no-store` so that nobody keeps it, and
/// `Retry-After` for clients that read it.
pub fn queue_page(ahead: usize, per_minute: u32, ray: &str, colo: &str, lang: Lang) -> Response<Body> {
    let minutes = wait_minutes(ahead, per_minute);
    let (html_lang, lang) = match lang {
        Lang::Zh => ("zh-CN", "zh"),
        Lang::En => ("en", "en"),
    };
    let place = if ahead == 0 {
        bi("你在队伍的最前面，马上就轮到你。", "You are at the front of the line: it is your turn any moment now.")
    } else {
        bi(&format!("你前面大约还有 {ahead} 人，预计等待约 {minutes} 分钟。"), &format!("Visitors ahead of you: about {ahead}. Roughly {minutes} min to wait."))
    };
    let html = format!(
        "<!doctype html><html lang=\"{html_lang}\" data-lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\">\
         <meta http-equiv=\"refresh\" content=\"{REFRESH_SECS}\"><title>{}</title><style>{PAGE_CSS}</style></head><body><main>\
         <button type=\"button\" id=\"lang\" class=\"lang\" aria-label=\"Language / 语言\"><span data-l=\"zh\">English</span><span data-l=\"en\">中文</span></button>\
         {PAGE_MARK}<div class=\"spin\" aria-hidden=\"true\"></div><h1>{}</h1><p>{}</p><p>{place}</p>\
         <div class=\"what\"><h2>{}</h2><p>{}</p></div>\
         <footer><span>Ray ID <code>{}</code></span><span>{} <code>{}</code></span><span>fucf</span></footer>\
         </main>{LANG_SCRIPT}</body></html>",
        if lang == "en" { "Waiting room" } else { "排队中" },
        bi("你正在排队", "You are in line"),
        bi(
            "这个网站现在访问的人太多，按到达的先后顺序放行。保持这个页面打开，轮到你时会自动进入。",
            "This site is busy right now, so visitors are let in in the order they arrived. Keep this page open: it takes you in when it is your turn."
        ),
        bi("请不要反复刷新", "No need to reload"),
        bi(
            &format!("页面每 {REFRESH_SECS} 秒自动刷新一次；离开超过 {} 分钟会失去排队位置。", TICKET_STALE_SECS / 60),
            &format!("This page reloads itself every {REFRESH_SECS} s. Leaving it for more than {} min loses your place.", TICKET_STALE_SECS / 60)
        ),
        escape(ray),
        bi("节点", "Node"),
        escape(colo),
    );
    let mut resp = Response::new(full(html));
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::RETRY_AFTER, HeaderValue::from(REFRESH_SECS));
    h.insert(header::VARY, HeaderValue::from_static("Accept-Language"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    h.insert("fcf-waiting-room", HeaderValue::from_static("queued"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::waf::Waf;
    use crate::store::testutil::temp_store;
    use serde_json::{json, Value};

    const ROOM: &str = "0123456789abcdef0123456789abcdef";

    fn room(total: u32, per_minute: u32, session_minutes: u32) -> WaitingRoom {
        WaitingRoom {
            meta: Meta { id: ROOM.into(), zone_id: "z".into(), created_on: String::new(), modified_on: String::new(), sync: SyncMeta::default() },
            name: "shop".into(),
            description: String::new(),
            host: "www.example.com".into(),
            path_prefix: "/shop".into(),
            total_active_users: total,
            new_users_per_minute: per_minute,
            session_minutes,
            enabled: true,
        }
    }

    fn lim(total: usize, per_minute: usize) -> Limits {
        Limits { total, per_minute, session: 300 }
    }

    fn admitted(o: Outcome) -> Admission {
        match o {
            Outcome::Admit { admission, .. } => admission,
            other => panic!("expected an admission, got {other:?}"),
        }
    }

    fn queued(o: Outcome) -> (Ticket, usize) {
        match o {
            Outcome::Queue { ticket, ahead } => (ticket, ahead),
            other => panic!("expected the queue, got {other:?}"),
        }
    }

    fn cookies(pairs: &[(&str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        let line = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        h.insert(header::COOKIE, HeaderValue::from_str(&line).unwrap());
        h
    }

    #[test]
    fn visitors_are_let_in_until_the_room_is_full_and_then_queued() {
        let (mut st, l) = (RoomState::default(), lim(3, 100));
        for i in 0..3 {
            let a = admitted(decide(&mut st, &l, 1000, None, None, i));
            assert_eq!((a.visitor, a.expiry), (i, 1300));
        }
        assert_eq!(st.active(), 3);
        let (t, ahead) = queued(decide(&mut st, &l, 1000, None, None, 7));
        assert_eq!((t.issued, t.nonce, t.seen, ahead), (1000, 7, 1000, 0));
        let (_, ahead) = queued(decide(&mut st, &l, 1000, None, None, 8));
        assert_eq!(ahead, 1, "the second one in line has one ahead");
        assert_eq!(st.waiting(), 2);
    }

    #[test]
    fn the_per_minute_rate_holds_back_new_visitors_even_with_free_places() {
        let (mut st, l) = (RoomState::default(), lim(100, 2));
        admitted(decide(&mut st, &l, 1000, None, None, 1));
        admitted(decide(&mut st, &l, 1030, None, None, 2));
        let (t, ahead) = queued(decide(&mut st, &l, 1059, None, None, 3));
        assert_eq!(ahead, 0, "nobody ahead, but two admissions this minute already");
        // a minute after the first admission, one admission is free again
        let a = admitted(decide(&mut st, &l, 1060, None, Some(t), 4));
        assert_eq!(a.visitor, 4);
        let (t, _) = queued(decide(&mut st, &l, 1061, None, None, 5));
        let (_, ahead) = queued(decide(&mut st, &l, 1090, None, None, 6));
        assert_eq!(ahead, 1, "the free admission belongs to the ticket ahead");
        admitted(decide(&mut st, &l, 1091, None, Some(t), 7));
        assert_eq!(st.admits.len(), 2);
    }

    #[test]
    fn places_free_up_as_sessions_expire_and_the_expired_are_pruned() {
        let (mut st, l) = (RoomState::default(), Limits { total: 2, per_minute: 10, session: 60 });
        admitted(decide(&mut st, &l, 1000, None, None, 1));
        admitted(decide(&mut st, &l, 1010, None, None, 2));
        let (t, _) = queued(decide(&mut st, &l, 1059, None, None, 3));
        // the first session ends at 1060: a newcomer still queues behind the ticket
        let (_, ahead) = queued(decide(&mut st, &l, 1060, None, None, 4));
        assert_eq!(ahead, 1);
        assert_eq!(st.active(), 1, "the expired session was pruned");
        assert!(!st.active.contains_key(&1));
        admitted(decide(&mut st, &l, 1061, None, Some(t), 5));
        assert_eq!((st.active(), st.waiting()), (2, 1));
    }

    #[test]
    fn earlier_tickets_are_let_in_first() {
        let (mut st, l) = (RoomState::default(), Limits { total: 1, per_minute: 10, session: 60 });
        admitted(decide(&mut st, &l, 1000, None, None, 1));
        let (early, _) = queued(decide(&mut st, &l, 1001, None, None, 2));
        let (late, ahead) = queued(decide(&mut st, &l, 1002, None, None, 3));
        assert_eq!(ahead, 1);
        // the session ends at 1060: the later ticket asks first, but the earlier one is ahead of it
        let (late, ahead) = queued(decide(&mut st, &l, 1060, None, Some(Ticket { seen: 1059, ..late }), 4));
        assert_eq!(ahead, 1);
        // and a newcomer queues behind both, even with a free place
        let (_, ahead) = queued(decide(&mut st, &l, 1060, None, None, 5));
        assert_eq!(ahead, 2);
        admitted(decide(&mut st, &l, 1061, None, Some(Ticket { seen: 1060, ..early }), 6));
        // the place is taken; the next one waits for the next free place, now first in line
        let (_, ahead) = queued(decide(&mut st, &l, 1062, None, Some(late), 7));
        assert_eq!(ahead, 0, "the earlier ticket left the line");
    }

    #[test]
    fn a_used_ticket_counts_as_none_when_it_comes_back() {
        let (mut st, l) = (RoomState::default(), lim(1, 10));
        admitted(decide(&mut st, &l, 1000, None, None, 1));
        let (t, _) = queued(decide(&mut st, &l, 1000, None, None, 2));
        st.active.clear();
        let o = decide(&mut st, &l, 1001, None, Some(t), 3);
        assert!(matches!(o, Outcome::Admit { spent: true, .. }), "{o:?}");
        // a copy of the same ticket from another browser goes to the back as a newcomer
        let (again, _) = queued(decide(&mut st, &l, 1002, None, Some(t), 4));
        assert_eq!((again.issued, again.nonce), (1002, 4));
    }

    #[test]
    fn admitted_visitors_pass_and_have_their_session_renewed_in_its_second_half() {
        let (mut st, l) = (RoomState::default(), lim(1, 1));
        let a = admitted(decide(&mut st, &l, 1000, None, None, 1));
        // full and over the rate, yet the admitted visitor passes
        assert_eq!(decide(&mut st, &l, 1100, Some(a), None, 2), Outcome::Pass);
        queued(decide(&mut st, &l, 1100, None, None, 3));
        let renewed = admitted(decide(&mut st, &l, 1200, Some(a), None, 4));
        assert_eq!(renewed, Admission { visitor: 1, expiry: 1500 }, "same visitor, later expiry");
        assert_eq!(st.active.get(&1), Some(&1500));
    }

    #[test]
    fn sessions_admitted_by_another_node_are_counted_here_within_bounds() {
        let (mut st, l) = (RoomState::default(), lim(2, 10));
        for v in 0..10u128 {
            assert_eq!(decide(&mut st, &l, 1000, Some(Admission { visitor: v, expiry: 1250 }), None, 99), Outcome::Pass);
        }
        assert_eq!(st.active(), 4, "at most twice the room's size");
        queued(decide(&mut st, &l, 1000, None, None, 1));
    }

    #[test]
    fn stale_tickets_leave_the_line_and_memory_stays_bounded() {
        let (mut st, l) = (RoomState::default(), lim(1, 1));
        admitted(decide(&mut st, &l, 1000, None, None, 1));
        for n in 0..50u128 {
            queued(decide(&mut st, &l, 1000, None, None, n + 10));
        }
        assert_eq!(st.waiting(), 50);
        // nobody came back for longer than a ticket lasts: the line is empty, the session gone
        let (_, ahead) = queued(decide(&mut st, &l, 1000 + TICKET_STALE_SECS + 1, None, None, 5));
        assert_eq!(ahead, 0);
        assert_eq!((st.waiting(), st.active()), (1, 1), "the line emptied; the session is still on");

        let rooms = WaitingRooms::default();
        let r = room(1, 1, 1);
        rooms.decide(&r, 1000, None, None, 1);
        assert_eq!(rooms.counts(ROOM), (1, 0));
        assert_eq!(rooms.tracked(), 1);
        let mut other = room(1, 1, 1);
        other.meta.id = "fedcba9876543210fedcba9876543210".into();
        rooms.decide(&other, 1000 + IDLE_SECS + 1, None, None, 2);
        assert_eq!(rooms.tracked(), 1, "the idle room's state was dropped");
        assert_eq!(rooms.counts(ROOM), (0, 0));
    }

    #[test]
    fn the_line_stops_growing_at_its_cap() {
        let (mut st, l) = (RoomState::default(), lim(1, 1));
        admitted(decide(&mut st, &l, 1000, None, None, 1));
        for n in 0..MAX_WAITING as u128 + 5 {
            st.waiting.insert((1000, n as u64 + 1_000_000), 1000);
        }
        let before = st.waiting();
        queued(decide(&mut st, &l, 1000, None, None, 3));
        assert_eq!(st.waiting(), before, "no new entry past the cap");
    }

    #[test]
    fn admission_cookies_verify_only_for_their_room_and_their_time() {
        let waf = Waf::new();
        let r = room(10, 10, 5);
        let a = Admission { visitor: 0xabc, expiry: 1300 };
        let good = admission_value(&waf, ROOM, &a);
        assert_eq!(read_admission(&waf, &cookies(&[("a", "b".into()), (COOKIE, good.clone())]), &r, 1000), Some(a));
        assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, good.clone())]), &r, 1300), None, "expired");
        let mut short = r.clone();
        short.session_minutes = 1;
        assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, good.clone())]), &short, 1000), None, "longer than the room's sessions now are");

        let mut other = r.clone();
        other.meta.id = "fedcba9876543210fedcba9876543210".into();
        assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, good.clone())]), &other, 1000), None, "another room's cookie");
        let moved = good.replacen(ROOM, &other.meta.id, 1);
        assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, moved)]), &other, 1000), None, "the room is signed");
        assert_eq!(read_admission(&Waf::new(), &cookies(&[(COOKIE, good.clone())]), &r, 1000), None, "another fleet's key");

        let mac = good.rsplit('.').next().unwrap().to_string();
        for forged in [
            format!("{ROOM}.{:032x}.1300.{mac}", 0xabd),
            format!("{ROOM}.{:032x}.1301.{mac}", 0xabc),
            format!("{ROOM}.{:032X}.1300.{mac}", 0xabc),
            format!("{ROOM}.{:032x}.01300.{mac}", 0xabc),
            format!("{ROOM}.{:032x}.1300.{}", 0xabc, "0".repeat(64)),
            format!("{ROOM}.{:032x}.1300", 0xabc),
            format!("{good}.x"),
            format!("{ROOM}.+{:031x}.1300.{mac}", 0xabc),
            format!("{ROOM}.{:032x}.+1300.{mac}", 0xabc),
            String::new(),
            "garbage".into(),
        ] {
            assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, forged.clone())]), &r, 1000), None, "{forged:?}");
        }
        // a forged cookie next to a good one does not spoil it
        assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, "junk".into()), (COOKIE, good.clone())]), &r, 1000), Some(a));
        // cookies split over several headers (HTTP/2) are all read
        let mut split = HeaderMap::new();
        split.append(header::COOKIE, HeaderValue::from_static("x=1"));
        split.append(header::COOKIE, HeaderValue::from_str(&format!("{COOKIE}={good}")).unwrap());
        assert_eq!(read_admission(&waf, &split, &r, 1000), Some(a));
        assert_eq!(read_admission(&waf, &HeaderMap::new(), &r, 1000), None);
        // a name that only starts like the cookie's is another cookie
        assert_eq!(read_admission(&waf, &cookies(&[(&format!("{COOKIE}x"), good)]), &r, 1000), None);
    }

    #[test]
    fn tickets_verify_only_while_they_are_shown_again_in_time() {
        let waf = Waf::new();
        let r = room(10, 10, 5);
        let t = Ticket { issued: 900, nonce: 0x1234, seen: 1000 };
        let v = ticket_value(&waf, ROOM, &t);
        let read = |value: &str, now: u64| read_ticket(&waf, &cookies(&[(TICKET_COOKIE, value.to_string())]), &r, now);
        assert_eq!(read(&v, 1000), Some(t));
        assert_eq!(read(&v, 1000 + TICKET_STALE_SECS), Some(t));
        assert_eq!(read(&v, 1001 + TICKET_STALE_SECS), None, "the visitor left the line");
        assert_eq!(read(&v, 1000 - SKEW_SECS), Some(t), "another node's clock may run a little ahead");
        assert_eq!(read(&v, 999 - SKEW_SECS), None, "but not far");
        let mac = v.rsplit('.').next().unwrap();
        for forged in [
            format!("{ROOM}.800.{:016x}.1000.{mac}", 0x1234),
            format!("{ROOM}.900.{:016x}.1000.{mac}", 0x1235),
            format!("{ROOM}.900.{:016x}.1050.{mac}", 0x1234),
            format!("{ROOM}.900.{:x}.1000.{mac}", 0x1234),
            format!("fedcba9876543210fedcba9876543210.900.{:016x}.1000.{mac}", 0x1234),
            "x.y.z.w.v".into(),
        ] {
            assert_eq!(read(&forged, 1000), None, "{forged:?}");
        }
        let backwards = Ticket { issued: 1001, nonce: 1, seen: 1000 };
        assert_eq!(read(&ticket_value(&waf, ROOM, &backwards), 1000), None, "issued after it was last seen");
        // an admission cookie is no ticket, and the other way round
        assert_eq!(read_admission(&waf, &cookies(&[(COOKIE, v.clone())]), &r, 1000), None);
        let a = admission_value(&waf, ROOM, &Admission { visitor: 1, expiry: 1100 });
        assert_eq!(read(&a, 1000), None);
    }

    #[test]
    fn rooms_cover_their_prefix_on_path_segments_and_the_longest_wins() {
        assert!(covers("/", "/anything"));
        assert!(covers("/shop", "/shop"));
        assert!(covers("/shop", "/shop/cart"));
        assert!(!covers("/shop", "/shopping"));
        assert!(!covers("/shop", "/"));
        assert!(!covers("/shop", "/Shop"));

        let mut all = room(1, 1, 1);
        all.meta.id = "a".repeat(32);
        all.path_prefix = "/".into();
        let shop = room(1, 1, 1);
        let mut twin = room(1, 1, 1);
        twin.meta.id = "0".repeat(32);
        let mut off = room(1, 1, 1);
        off.path_prefix = "/shop/cart".into();
        off.enabled = false;
        let rooms = vec![all, shop.clone(), off];
        assert_eq!(pick(&rooms, "www.example.com", "/shop/cart").map(|r| r.meta.id.as_str()), Some(ROOM), "the disabled one is skipped");
        assert_eq!(pick(&rooms, "www.example.com", "/blog").map(|r| r.path_prefix.as_str()), Some("/"));
        assert!(pick(&rooms, "example.com", "/shop").is_none(), "another host");
        let raced = vec![shop.clone(), twin.clone()];
        let raced_back = vec![twin, shop];
        assert_eq!(pick(&raced, "www.example.com", "/shop").map(|r| &r.meta.id), pick(&raced_back, "www.example.com", "/shop").map(|r| &r.meta.id));
        assert_eq!(pick(&raced, "www.example.com", "/shop").map(|r| r.meta.id.as_str()), Some("00000000000000000000000000000000"));
    }

    #[test]
    fn encoded_or_doubled_slashes_do_not_walk_past_a_room() {
        let rooms = vec![room(1, 1, 1)];
        for path in ["/%73hop", "//shop", "/shop//cart", "/%73%68%6F%70/cart", "///shop"] {
            assert_eq!(pick(&rooms, "www.example.com", path).map(|r| r.meta.id.as_str()), Some(ROOM), "{path}");
        }
        assert!(pick(&rooms, "www.example.com", "/%73hopping").is_none());
        let mut escaped = room(1, 1, 1);
        escaped.path_prefix = "/caf%C3%A9".into();
        let rooms = vec![escaped];
        assert!(pick(&rooms, "www.example.com", "/caf%c3%a9/menu").is_some(), "an escaped prefix matches either spelling");
        assert!(pick(&rooms, "www.example.com", "/caf\u{e9}").is_some());
    }

    #[test]
    fn path_prefixes_are_checked_and_normalized() {
        assert_eq!(check_path("/"), Ok("/".into()));
        assert_eq!(check_path("///"), Ok("/".into()));
        assert_eq!(check_path("/shop/"), Ok("/shop".into()));
        assert_eq!(check_path("/a-b_c.d~e/%20"), Ok("/a-b_c.d~e/%20".into()));
        for bad in ["", "shop", " /shop", "/shop?x=1", "/shop#a", "/a;b", "/a,b", "/a b", "/a\"b", "/中", "/a\\b"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert!(check_path(&format!("/{}", "a".repeat(PATH_MAX - 1))).is_ok());
        assert!(check_path(&format!("/{}", "a".repeat(PATH_MAX))).is_err());
    }

    #[test]
    fn waiting_rooms_are_checked_belong_to_their_zone_and_go_with_it() {
        let store = temp_store();
        let z = store.create_zone("example.com").unwrap().id;
        let other = store.create_zone("example.net").unwrap().id;
        let base = json!({ "name": "shop", "host": "WWW.example.com.", "path_prefix": "/shop/", "total_active_users": 100, "new_users_per_minute": 20 });
        let r: WaitingRoom = store.save_item(&z, None, base.clone(), true).unwrap();
        assert_eq!((r.host.as_str(), r.path_prefix.as_str(), r.session_minutes, r.enabled), ("www.example.com", "/shop", SESSION_DEFAULT, true));
        assert_eq!(r.meta.zone_id, z);
        let snap = store.snapshot();
        assert_eq!(snap.zones["example.com"].waiting_rooms.len(), 1, "enabled rooms are in the snapshot");

        let with = |k: &str, v: Value| {
            let mut b = base.clone();
            b["path_prefix"] = json!("/other");
            b[k] = v;
            b
        };
        for bad in [
            with("host", json!("www.example.net")),
            with("host", json!("*.example.com")),
            with("host", json!("_dmarc.example.com")),
            with("host", json!("")),
            with("host", json!("192.0.2.1")),
            with("host", json!("a..example.com")),
            with("path_prefix", json!("shop")),
            with("path_prefix", json!("/a;b")),
            with("path_prefix", json!("")),
            with("name", json!("")),
            with("name", json!(" ")),
            with("name", json!("n".repeat(65))),
            with("description", json!("line\nbreak")),
            with("total_active_users", json!(0)),
            with("total_active_users", json!(MAX_USERS + 1)),
            with("total_active_users", json!(-1)),
            with("total_active_users", json!("100")),
            with("new_users_per_minute", json!(0)),
            with("new_users_per_minute", json!(101)),
            with("session_minutes", json!(0)),
            with("session_minutes", json!(SESSION_MAX + 1)),
            with("enabled", json!("yes")),
            json!({ "name": "no limits", "host": "www.example.com" }),
            json!("not an object"),
        ] {
            let res = store.save_item::<WaitingRoom>(&z, None, bad.clone(), true);
            assert!(matches!(res, Err(StoreError::Invalid(_))), "{bad} must be refused (saved: {})", res.is_ok());
        }
        // without a path prefix a room covers the whole host
        let whole: WaitingRoom = store
            .save_item(&z, None, json!({ "name": "all", "host": "example.com", "total_active_users": MAX_USERS, "new_users_per_minute": MAX_USERS, "session_minutes": SESSION_MAX }), true)
            .unwrap();
        assert_eq!(whole.path_prefix, "/");

        // one enabled room per host and path; a disabled twin is fine, enabling it is not
        let dup = store.save_item::<WaitingRoom>(&z, None, base.clone(), true);
        assert!(matches!(dup, Err(StoreError::Conflict(_))), "same host and path");
        let mut off = base.clone();
        off["enabled"] = json!(false);
        off["path_prefix"] = json!("/shop");
        let twin: WaitingRoom = store.save_item(&z, None, off, true).unwrap();
        assert!(matches!(store.save_item::<WaitingRoom>(&z, Some(&twin.meta.id), json!({ "enabled": true }), false), Err(StoreError::Conflict(_))));
        assert_eq!(store.snapshot().zones["example.com"].waiting_rooms.len(), 2, "the disabled twin is not in the snapshot");
        // saving a room again does not conflict with itself
        let again: WaitingRoom = store.save_item(&z, Some(&r.meta.id), json!({ "total_active_users": 50 }), false).unwrap();
        assert_eq!((again.total_active_users, again.path_prefix.as_str()), (50, "/shop"), "a patch keeps the rest");
        assert!(matches!(store.save_item::<WaitingRoom>(&z, Some(&r.meta.id), json!({ "total_active_users": 10 }), false), Err(StoreError::Invalid(_))), "below the rate");

        // a host of a more specific zone belongs to that zone
        store.create_zone("shop.example.com").unwrap();
        let inner = store.save_item::<WaitingRoom>(&z, None, with("host", json!("a.shop.example.com")), true);
        assert!(matches!(inner, Err(StoreError::Invalid(_))));

        // another zone's room cannot be read, changed or deleted through this one
        assert!(matches!(store.item::<WaitingRoom>(&other, &r.meta.id), Err(StoreError::NotFound)));
        assert!(matches!(store.save_item::<WaitingRoom>(&other, Some(&r.meta.id), json!({ "enabled": false }), false), Err(StoreError::NotFound)));
        assert!(matches!(store.delete_item::<WaitingRoom>(&other, &r.meta.id), Err(StoreError::NotFound)));
        assert!(matches!(store.save_item::<WaitingRoom>("no-such-zone", None, base.clone(), true), Err(StoreError::ZoneNotFound)));
        assert!(matches!(store.item::<WaitingRoom>(&z, "no-such-room"), Err(StoreError::NotFound)));
        let forged: WaitingRoom = store.save_item(&z, None, json!({ "name": "x", "host": "example.com", "path_prefix": "/x", "total_active_users": 1, "new_users_per_minute": 1, "zone_id": other }), true).unwrap();
        assert_eq!(forged.meta.zone_id, z, "the zone is the one in the path, not in the body");

        // at most so many rooms per zone
        let have = store.items::<WaitingRoom>(&z).unwrap().len();
        for i in have..MAX_ROOMS_PER_ZONE {
            store.save_item::<WaitingRoom>(&z, None, json!({ "name": "r", "host": "example.com", "path_prefix": format!("/r{i}"), "total_active_users": 1, "new_users_per_minute": 1 }), true).unwrap();
        }
        let over = store.save_item::<WaitingRoom>(&z, None, json!({ "name": "r", "host": "example.com", "path_prefix": "/over", "total_active_users": 1, "new_users_per_minute": 1 }), true);
        assert!(matches!(over, Err(StoreError::Invalid(_))));
        assert!(store.save_item::<WaitingRoom>(&z, Some(&r.meta.id), json!({ "session_minutes": 2 }), false).is_ok(), "a full zone's rooms can still change");

        store.delete_zone(&z).unwrap();
        assert!(store.all_items::<WaitingRoom>().is_empty(), "a zone's rooms go with it");
    }

    #[test]
    fn waiting_rooms_reach_other_nodes_and_their_deletion_too() {
        use crate::sync::SyncProvider;
        let (a, b) = (temp_store(), temp_store());
        a.set_sync_node_id("au".into());
        b.set_sync_node_id("eu".into());
        let z = a.create_zone("example.com").unwrap().id;
        b.merge_delta(&a.export_since(0, None).unwrap(), &b.clock()).unwrap();
        let version = a.version();
        let r: WaitingRoom = a
            .save_item(&z, None, json!({ "name": "shop", "host": "example.com", "total_active_users": 3, "new_users_per_minute": 2 }), true)
            .unwrap();
        assert_ne!(a.version(), version);
        assert!(b.merge_delta(&a.export_since(0, None).unwrap(), &b.clock()).unwrap());
        let got = b.item::<WaitingRoom>(&z, &r.meta.id).unwrap();
        assert_eq!((got.total_active_users, got.new_users_per_minute, got.host.as_str()), (3, 2, "example.com"));
        assert_eq!(b.snapshot().zones["example.com"].waiting_rooms.len(), 1);
        a.delete_item::<WaitingRoom>(&z, &r.meta.id).unwrap();
        b.merge_delta(&a.export_since(0, None).unwrap(), &b.clock()).unwrap();
        assert!(b.items::<WaitingRoom>(&z).unwrap().is_empty());
        assert!(b.snapshot().zones["example.com"].waiting_rooms.is_empty());
    }

    #[test]
    fn a_configuration_without_waiting_rooms_says_nothing_about_them() {
        let store = temp_store();
        store.create_zone("example.com").unwrap();
        let state = store.export();
        assert!(state.get("waiting_rooms").is_none());
        assert!(state["tombstones"].get("waiting_rooms").is_none(), "nodes without rooms compute the same version");
    }

    #[test]
    fn a_certificate_only_zone_has_no_waiting_room() {
        let store = temp_store();
        let z = store.create_zone_as("example.com", "cert").unwrap().id;
        let res = store.save_item::<WaitingRoom>(&z, None, json!({ "name": "x", "host": "example.com", "total_active_users": 1, "new_users_per_minute": 1 }), true);
        assert!(matches!(res, Err(StoreError::Invalid(_))));
    }

    #[test]
    fn the_queue_page_escapes_what_it_shows_and_is_never_kept() {
        let resp = queue_page(41, 20, "<ray>&\"", "<colo>", Lang::En);
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(h.get(header::RETRY_AFTER).unwrap(), &REFRESH_SECS.to_string());
        assert_eq!(h.get(header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");
        let body = body_text(resp);
        assert!(body.contains("&lt;ray&gt;&amp;&quot;") && !body.contains("<ray>"), "{body}");
        assert!(body.contains("&lt;colo&gt;") && !body.contains("<colo>"));
        assert!(body.contains(&format!("<meta http-equiv=\"refresh\" content=\"{REFRESH_SECS}\">")));
        assert!(body.contains("Visitors ahead of you: about 41. Roughly 3 min to wait."), "{body}");
        assert!(body.contains("data-lang=\"en\""));
        assert!(body_text(queue_page(0, 20, "r", "c", Lang::Zh)).contains("你在队伍的最前面"));
        assert_eq!((wait_minutes(0, 10), wait_minutes(9, 10), wait_minutes(10, 10), wait_minutes(5, 0)), (1, 1, 2, 6));
    }

    fn body_text(resp: Response<Body>) -> String {
        use http_body_util::BodyExt;
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let bytes = rt.block_on(resp.into_body().collect()).unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn cookies_carry_the_flags_and_the_rooms_path() {
        let c = set_cookie(COOKIE, "v", "/shop", 300, true).unwrap();
        assert_eq!(c, "fucf_waiting_room=v; Path=/shop; Max-Age=300; HttpOnly; SameSite=Lax; Secure");
        let c = set_cookie(TICKET_COOKIE, "", "/", 0, false).unwrap();
        assert_eq!(c, "fucf_waiting_ticket=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    }
}
