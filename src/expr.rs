//! Rule expression language (a subset of Cloudflare's wirefilter syntax),
//! shared by firewall rules, rate limits and origin rules.
//!
//! ```text
//! (http.request.uri.path contains "/admin" and not ip.src in {10.0.0.0/8 192.0.2.1})
//!   or lower(http.user_agent) matches "curl|wget"
//! ip.src in $office
//! ```
//!
//! `$office` names an IP list (crate::lists). The name is looked up when the
//! expression is compiled for a snapshot ([`Expr::parse_with`]), so a rule
//! follows its list as the list changes; a name with no list behind it
//! matches no address.

use crate::lists::{IpSet, ListSets};
use regex::Regex;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

/// Request attributes an expression is evaluated against.
#[derive(Debug, Clone, Default)]
pub struct ReqInfo {
    pub ip: Option<IpAddr>,
    pub ssl: bool,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    /// Header names are lowercase.
    pub headers: Vec<(String, String)>,
    /// Visitor location and network (empty / 0 when unknown).
    pub country: String,
    pub continent: String,
    pub asn: i64,
    pub as_org: String,
    /// How bad the visitor's address looks, 0 (clean) to 100 (see crate::edge::reputation).
    pub threat: i64,
    /// The JA4 fingerprint of the visitor's TLS ClientHello (see crate::edge::ja4); empty when not known.
    pub ja4: String,
    /// How human the request looks, 1 (a bot) to 99 (a human); 0 where it
    /// was not scored, on requests the edge makes itself (see crate::edge::botscore).
    pub bot_score: i64,
}

impl ReqInfo {
    pub fn header(&self, name: &str) -> &str {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str()).unwrap_or("")
    }
    pub fn uri(&self) -> String {
        if self.query.is_empty() { self.path.clone() } else { format!("{}?{}", self.path, self.query) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Ty {
    Str,
    Int,
    Ip,
    Bool,
}

#[derive(Debug, Clone)]
enum Val {
    Host,
    Uri,
    FullUri,
    Path,
    Query,
    Method,
    Header(String),
    IpSrc,
    Ssl,
    Country,
    Continent,
    Asn,
    AsOrg,
    Ja4,
    Threat,
    BotScore,
    Lower(Box<Val>),
    Upper(Box<Val>),
    UrlDecode(Box<Val>),
    Len(Box<Val>),
    StartsWith(Box<Val>, String),
    EndsWith(Box<Val>, String),
}

#[derive(Debug, Clone)]
enum Lit {
    Str(String),
    Int(i64),
    Net(IpAddr, u8),
}

#[derive(Debug, Clone)]
enum Op {
    Eq(Lit),
    Ne(Lit),
    Contains(String),
    Matches(Regex),
    In(Vec<Lit>),
    /// `ip.src in $name`: the list's addresses as they were when the
    /// expression was compiled; `None` when no list had that name.
    InList(String, Option<Arc<IpSet>>),
    Lt(i64),
    Le(i64),
    Gt(i64),
    Ge(i64),
}

#[derive(Debug, Clone)]
enum Node {
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Cmp(Val, Op),
    Truthy(Val),
}

/// A compiled expression. The empty expression matches every request.
#[derive(Debug, Clone)]
pub struct Expr(Option<Node>);

// ------------------------------------------------------------- lexing ----

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Sym(&'static str),
    /// `$name`, a reference to an IP list.
    List(String),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    const SYMS: &[&str] = &["==", "!=", "<=", ">=", "&&", "||", "(", ")", "{", "}", "[", "]", ",", "~", "<", ">", "!"];
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    'outer: while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'"' {
            let mut s = Vec::new();
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err("unterminated string".into()),
                    Some(b'"') => break,
                    Some(b'\\') if i + 1 < b.len() => {
                        if !matches!(b[i + 1], b'"' | b'\\') {
                            s.push(b'\\'); // keep regex escapes like \d intact
                        }
                        s.push(b[i + 1]);
                        i += 2;
                    }
                    Some(&ch) => {
                        s.push(ch);
                        i += 1;
                    }
                }
            }
            i += 1;
            out.push(Tok::Str(String::from_utf8(s).map_err(|_| "invalid utf-8 in string")?));
            continue;
        }
        if c == b'$' {
            // the name is checked here, so that `$Office` is an error rather
            // than a reference that can never match
            let start = i + 1;
            i = start;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let name = &src[start..i];
            if !crate::lists::valid_name(name) {
                return Err(format!(
                    "'${name}' is not a list name: lowercase letters, digits and underscores, at most {} characters",
                    crate::lists::MAX_NAME
                ));
            }
            out.push(Tok::List(name.to_string()));
            continue;
        }
        for s in SYMS {
            if src[i..].starts_with(s) {
                out.push(Tok::Sym(s));
                i += s.len();
                continue 'outer;
            }
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'.' | b':' | b'/' | b'-')) {
            i += 1;
        }
        if start == i {
            return Err(format!("unexpected character '{}'", &src[i..].chars().next().unwrap()));
        }
        out.push(Tok::Word(src[start..i].to_string()));
    }
    Ok(out)
}

// ------------------------------------------------------------ parsing ----

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    /// What `$name` stands for.
    lists: &'a ListSets,
}

fn parse_net(s: &str) -> Option<Lit> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    (prefix <= max).then_some(Lit::Net(ip, prefix))
}

impl Val {
    fn ty(&self) -> Ty {
        match self {
            Val::IpSrc => Ty::Ip,
            Val::Ssl | Val::StartsWith(..) | Val::EndsWith(..) => Ty::Bool,
            Val::Len(_) | Val::Asn | Val::Threat | Val::BotScore => Ty::Int,
            _ => Ty::Str,
        }
    }
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        self.pos += 1;
        self.toks.get(self.pos - 1).cloned()
    }
    fn eat_sym(&mut self, s: &str) -> bool {
        let hit = matches!(self.peek(), Some(Tok::Sym(x)) if *x == s);
        self.pos += hit as usize;
        hit
    }
    fn eat_word(&mut self, w: &str) -> bool {
        let hit = matches!(self.peek(), Some(Tok::Word(x)) if x == w);
        self.pos += hit as usize;
        hit
    }
    fn expect(&mut self, s: &str) -> Result<(), String> {
        if self.eat_sym(s) { Ok(()) } else { Err(format!("expected '{s}'")) }
    }
    fn string(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(s),
            _ => Err("expected a quoted string".into()),
        }
    }

    fn or(&mut self) -> Result<Node, String> {
        let mut left = self.and()?;
        while self.eat_word("or") || self.eat_sym("||") {
            left = Node::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Node, String> {
        let mut left = self.unary()?;
        while self.eat_word("and") || self.eat_sym("&&") {
            left = Node::And(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Node, String> {
        if self.eat_word("not") || self.eat_sym("!") {
            return Ok(Node::Not(Box::new(self.unary()?)));
        }
        if self.eat_sym("(") {
            let e = self.or()?;
            self.expect(")")?;
            return Ok(e);
        }
        let val = self.value()?;
        let ty = val.ty();
        let op = match self.peek() {
            Some(Tok::Word(w)) => match w.as_str() {
                "eq" | "ne" | "contains" | "matches" | "in" | "lt" | "le" | "gt" | "ge" => w.clone(),
                _ => String::new(),
            },
            Some(Tok::Sym(s @ ("==" | "!=" | "~" | "<" | "<=" | ">" | ">="))) => s.to_string(),
            _ => String::new(),
        };
        if op.is_empty() {
            return if ty == Ty::Bool { Ok(Node::Truthy(val)) } else { Err("expected a comparison operator".into()) };
        }
        self.pos += 1;
        let op = match op.as_str() {
            "eq" | "==" => Op::Eq(self.literal(ty)?),
            "ne" | "!=" => Op::Ne(self.literal(ty)?),
            "contains" if ty == Ty::Str => Op::Contains(self.string()?),
            "matches" | "~" if ty == Ty::Str => {
                let pattern = self.string()?;
                let re = regex::RegexBuilder::new(&pattern).size_limit(1 << 20).build();
                Op::Matches(re.map_err(|e| format!("invalid regex: {e}"))?)
            }
            "in" if matches!(self.peek(), Some(Tok::List(_))) => {
                let Some(Tok::List(name)) = self.next() else { unreachable!() };
                if ty != Ty::Ip {
                    return Err(format!("${name} is an IP list: it can only follow ip.src in"));
                }
                let set = self.lists.get(&name).cloned();
                Op::InList(name, set)
            }
            "in" => {
                self.expect("{")?;
                let mut items = Vec::new();
                while !self.eat_sym("}") {
                    items.push(self.literal(ty)?);
                    self.eat_sym(",");
                }
                Op::In(items)
            }
            "lt" | "<" | "le" | "<=" | "gt" | ">" | "ge" | ">=" if ty == Ty::Int => {
                let Lit::Int(n) = self.literal(Ty::Int)? else { unreachable!() };
                match op.as_str() {
                    "lt" | "<" => Op::Lt(n),
                    "le" | "<=" => Op::Le(n),
                    "gt" | ">" => Op::Gt(n),
                    _ => Op::Ge(n),
                }
            }
            other => return Err(format!("operator '{other}' cannot be applied to this field")),
        };
        Ok(Node::Cmp(val, op))
    }

    fn literal(&mut self, ty: Ty) -> Result<Lit, String> {
        match (ty, self.next()) {
            (Ty::Str, Some(Tok::Str(s))) => Ok(Lit::Str(s)),
            (Ty::Int, Some(Tok::Word(w))) => w.parse().map(Lit::Int).map_err(|_| format!("'{w}' is not an integer")),
            (Ty::Ip, Some(Tok::Word(w))) => parse_net(&w).ok_or(format!("'{w}' is not an IP address or CIDR")),
            (Ty::Bool, _) => Err("boolean fields cannot be compared; use them directly".into()),
            (Ty::Str, _) => Err("expected a quoted string".into()),
            _ => Err("expected a value".into()),
        }
    }

    fn value(&mut self) -> Result<Val, String> {
        let word = match self.next() {
            Some(Tok::Word(w)) => w,
            other => return Err(format!("expected a field name, found {other:?}")),
        };
        if self.eat_sym("(") {
            let arg = Box::new(self.value()?);
            let need_str = |v: &Val| if v.ty() == Ty::Str { Ok(()) } else { Err(format!("{word}() needs a string")) };
            need_str(&arg)?;
            let v = match word.as_str() {
                "lower" => Val::Lower(arg),
                "upper" => Val::Upper(arg),
                "url_decode" => Val::UrlDecode(arg),
                "len" => Val::Len(arg),
                "starts_with" | "ends_with" => {
                    self.expect(",")?;
                    let s = self.string()?;
                    if word == "starts_with" { Val::StartsWith(arg, s) } else { Val::EndsWith(arg, s) }
                }
                _ => return Err(format!("unknown function '{word}'")),
            };
            self.expect(")")?;
            return Ok(v);
        }
        Ok(match word.as_str() {
            "http.host" => Val::Host,
            "http.request.uri" => Val::Uri,
            "http.request.full_uri" => Val::FullUri,
            "http.request.uri.path" => Val::Path,
            "http.request.uri.query" => Val::Query,
            "http.request.method" => Val::Method,
            "http.user_agent" => Val::Header("user-agent".into()),
            "http.referer" => Val::Header("referer".into()),
            "http.cookie" => Val::Header("cookie".into()),
            "http.x_forwarded_for" => Val::Header("x-forwarded-for".into()),
            "http.request.headers" => {
                self.expect("[")?;
                let name = self.string()?.to_ascii_lowercase();
                self.expect("]")?;
                Val::Header(name)
            }
            "ip.src" => Val::IpSrc,
            "ip.geoip.country" | "ip.src.country" => Val::Country,
            "ip.geoip.continent" | "ip.src.continent" => Val::Continent,
            "ip.geoip.asnum" | "ip.src.asnum" => Val::Asn,
            "ip.geoip.as_org" => Val::AsOrg,
            "fcf.ja4" | "cf.bot_management.ja4" => Val::Ja4,
            "fcf.threat_score" | "cf.threat_score" | "ip.threat_score" => Val::Threat,
            "fcf.bot_score" | "cf.bot_management.score" => Val::BotScore,
            "ssl" => Val::Ssl,
            _ => return Err(format!("unknown field '{word}'")),
        })
    }
}

// --------------------------------------------------------- evaluation ----

enum V<'a> {
    S(Cow<'a, str>),
    I(i64),
    Ip(Option<IpAddr>),
    B(bool),
}

pub fn url_decode(s: &str) -> String {
    let plus = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus).decode_utf8_lossy().into_owned()
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    fn bits(ip: IpAddr) -> (u128, bool) {
        match ip {
            IpAddr::V4(a) => (u32::from(a) as u128, true),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(m) => (u32::from(m) as u128, true),
                None => (u128::from(a), false),
            },
        }
    }
    let ((a, a4), (b, b4)) = (bits(ip), bits(net));
    if a4 != b4 {
        return false;
    }
    let width: u32 = if a4 { 32 } else { 128 };
    let shift = width - (prefix as u32).min(width);
    if shift >= 128 { true } else { (a >> shift) == (b >> shift) }
}

fn lit_eq(v: &V, lit: &Lit) -> bool {
    match (v, lit) {
        (V::S(s), Lit::Str(l)) => s == l,
        (V::I(i), Lit::Int(l)) => i == l,
        (V::Ip(Some(ip)), Lit::Net(net, prefix)) => in_net(*ip, *net, *prefix),
        _ => false,
    }
}

impl Val {
    fn eval<'a>(&self, r: &'a ReqInfo) -> V<'a> {
        let s = |v: &Val| match v.eval(r) {
            V::S(s) => s,
            _ => Cow::Borrowed(""),
        };
        match self {
            Val::Host => V::S(Cow::Borrowed(&r.host)),
            Val::Path => V::S(Cow::Borrowed(&r.path)),
            Val::Query => V::S(Cow::Borrowed(&r.query)),
            Val::Method => V::S(Cow::Borrowed(&r.method)),
            Val::Uri => V::S(Cow::Owned(r.uri())),
            Val::FullUri => {
                V::S(Cow::Owned(format!("{}://{}{}", if r.ssl { "https" } else { "http" }, r.host, r.uri())))
            }
            Val::Header(name) => {
                let mut it = r.headers.iter().filter(|(n, _)| n == name).map(|(_, v)| v.as_str());
                match (it.next(), it.next()) {
                    (None, _) => V::S(Cow::Borrowed("")),
                    (Some(a), None) => V::S(Cow::Borrowed(a)),
                    (Some(a), Some(b)) => V::S(Cow::Owned(
                        [a, b].into_iter().chain(it).collect::<Vec<_>>().join(", "),
                    )),
                }
            }
            Val::IpSrc => V::Ip(r.ip),
            Val::Country => V::S(Cow::Borrowed(&r.country)),
            Val::Continent => V::S(Cow::Borrowed(&r.continent)),
            Val::Asn => V::I(r.asn),
            Val::Threat => V::I(r.threat),
            Val::BotScore => V::I(r.bot_score),
            Val::AsOrg => V::S(Cow::Borrowed(&r.as_org)),
            Val::Ja4 => V::S(Cow::Borrowed(&r.ja4)),
            Val::Ssl => V::B(r.ssl),
            Val::Lower(v) => V::S(Cow::Owned(s(v).to_lowercase())),
            Val::Upper(v) => V::S(Cow::Owned(s(v).to_uppercase())),
            Val::UrlDecode(v) => V::S(Cow::Owned(url_decode(&s(v)))),
            Val::Len(v) => V::I(s(v).len() as i64),
            Val::StartsWith(v, p) => V::B(s(v).starts_with(p.as_str())),
            Val::EndsWith(v, p) => V::B(s(v).ends_with(p.as_str())),
        }
    }
}

impl Node {
    fn eval(&self, r: &ReqInfo) -> bool {
        match self {
            Node::And(a, b) => a.eval(r) && b.eval(r),
            Node::Or(a, b) => a.eval(r) || b.eval(r),
            Node::Not(a) => !a.eval(r),
            Node::Truthy(v) => matches!(v.eval(r), V::B(true)),
            Node::Cmp(v, op) => {
                let v = v.eval(r);
                match (op, &v) {
                    (Op::Eq(l), _) => lit_eq(&v, l),
                    (Op::Ne(l), _) => !lit_eq(&v, l),
                    (Op::In(ls), _) => ls.iter().any(|l| lit_eq(&v, l)),
                    (Op::InList(_, set), V::Ip(Some(ip))) => set.as_ref().is_some_and(|s| s.contains(*ip)),
                    (Op::Contains(n), V::S(s)) => s.contains(n.as_str()),
                    (Op::Matches(re), V::S(s)) => re.is_match(s),
                    (Op::Lt(n), V::I(i)) => i < n,
                    (Op::Le(n), V::I(i)) => i <= n,
                    (Op::Gt(n), V::I(i)) => i > n,
                    (Op::Ge(n), V::I(i)) => i >= n,
                    _ => false,
                }
            }
        }
    }
}

impl Node {
    /// The IP lists this node names, in order, possibly more than once.
    fn lists<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Node::And(a, b) | Node::Or(a, b) => {
                a.lists(out);
                b.lists(out);
            }
            Node::Not(a) => a.lists(out),
            Node::Cmp(_, Op::InList(name, _)) => out.push(name),
            Node::Cmp(..) | Node::Truthy(_) => {}
        }
    }
}

impl Expr {
    /// Parse without IP lists: every `$name` is taken as naming no list, so
    /// it matches no address. Good for checking what was written; the edge
    /// compiles with [`Expr::parse_with`].
    pub fn parse(src: &str) -> Result<Expr, String> {
        Expr::parse_with(src, &ListSets::new())
    }

    /// Parse, resolving `$name` against `lists` as they are now. A list that
    /// changes later is not seen by this expression: the snapshot is built,
    /// and its rules compiled, again then.
    pub fn parse_with(src: &str, lists: &ListSets) -> Result<Expr, String> {
        if src.len() > 4096 {
            return Err("expression exceeds 4096 characters".into());
        }
        let toks = lex(src)?;
        if toks.is_empty() {
            return Ok(Expr(None));
        }
        let mut p = Parser { toks, pos: 0, lists };
        let node = p.or()?;
        if p.pos != p.toks.len() {
            return Err(format!("unexpected token {:?}", p.toks[p.pos]));
        }
        Ok(Expr(Some(node)))
    }

    pub fn matches(&self, r: &ReqInfo) -> bool {
        self.0.as_ref().is_none_or(|n| n.eval(r))
    }

    /// The names of the IP lists the expression uses, sorted, each once.
    pub fn lists(&self) -> Vec<&str> {
        let mut out = Vec::new();
        if let Some(n) = &self.0 {
            n.lists(&mut out);
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ReqInfo {
        ReqInfo {
            ip: Some("10.1.2.3".parse().unwrap()),
            ssl: true,
            method: "POST".into(),
            host: "www.example.com".into(),
            path: "/Admin/login.php".into(),
            query: "q=a%20b&x=1".into(),
            headers: vec![("user-agent".into(), "curl/8.0".into()), ("x-api-key".into(), "secret".into())],
            country: "CN".into(),
            continent: "AS".into(),
            asn: 4134,
            as_org: "chinanet".into(),
            ..Default::default()
        }
    }

    fn m(src: &str) -> bool {
        Expr::parse(src).unwrap_or_else(|e| panic!("{src}: {e}")).matches(&req())
    }

    #[test]
    fn evaluates() {
        assert!(m(""));
        assert!(m(r#"http.host eq "www.example.com""#));
        assert!(m(r#"(http.request.uri.path contains "/Admin" and http.request.method == "POST")"#));
        assert!(!m(r#"http.request.uri.path contains "/admin""#));
        assert!(m(r#"lower(http.request.uri.path) contains "/admin""#));
        assert!(m(r#"ip.src in {192.0.2.1 10.0.0.0/8}"#));
        assert!(m(r#"ip.src eq 10.1.2.3 and ip.src ne 10.1.2.4"#));
        assert!(!m(r#"ip.src in {2001:db8::/32, 192.168.0.0/16}"#));
        assert!(m(r#"http.user_agent matches "^curl/\d+" or http.host eq "x""#));
        assert!(m(r#"not http.request.method in {"GET" "HEAD"}"#));
        assert!(m(r#"ssl && ends_with(http.request.uri.path, ".php")"#));
        assert!(m(r#"!starts_with(http.host, "api.")"#));
        assert!(m(r#"http.request.headers["X-Api-Key"] eq "secret""#));
        assert!(m(r#"url_decode(http.request.uri.query) contains "a b""#));
        assert!(m(r#"len(http.request.uri.query) gt 5 and len(http.referer) == 0"#));
        assert!(m(r#"http.request.full_uri eq "https://www.example.com/Admin/login.php?q=a%20b&x=1""#));
        assert!(m(r#"ip.geoip.country in {"CN" "HK"} and ip.geoip.asnum eq 4134 and ip.geoip.as_org contains "chinanet""#));
        assert!(!m(r#"ip.geoip.continent ne "AS" or ip.geoip.asnum in {9808 4837}"#));
        // precedence: and binds tighter than or
        assert!(m(r#"http.host eq "nope" and ssl or http.request.method eq "POST""#));
    }

    #[test]
    fn rejects_invalid() {
        for bad in [
            "http.host",
            "http.host eq 5",
            "ip.src eq \"1.2.3.4\"",
            "ip.src contains \"1\"",
            "ip.geoip.city eq \"x\"",
            "http.host matches \"(\"",
            "(ssl",
            "ssl eq true",
            "http.host eq \"a\" garbage",
            "len(http.host) contains \"a\"",
        ] {
            assert!(Expr::parse(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn the_bot_score_is_a_number_under_either_name() {
        let at = |src: &str, score: i64| {
            let e = Expr::parse(src).unwrap_or_else(|e| panic!("{src}: {e}"));
            e.matches(&ReqInfo { bot_score: score, ..req() })
        };
        assert!(at("fcf.bot_score lt 30", 12));
        assert!(!at("fcf.bot_score lt 30", 30));
        assert!(at("cf.bot_management.score lt 30", 1));
        assert!(!at("cf.bot_management.score lt 30", 99));
        assert!(at("fcf.bot_score ge 30 and fcf.bot_score le 70", 50));
        assert!(at("cf.bot_management.score in {1 2 3}", 2));
        assert!(at(r#"fcf.bot_score lt 30 and not http.request.uri.path contains "/robots.txt""#, 5));
        for bad in ["fcf.bot_score eq \"1\"", "fcf.bot_score contains \"1\"", "fcf.bot_score", "cf.bot_management.scores lt 30", "fcf.bot_score lt"] {
            assert!(Expr::parse(bad).is_err(), "{bad} should fail");
        }
    }

    /// Lists by name, each holding the given (normalized) items.
    fn lists(of: &[(&str, &[&str])]) -> ListSets {
        let list = |(name, items): &(&str, &[&str])| crate::lists::IpList {
            id: name.to_string(),
            name: name.to_string(),
            description: String::new(),
            items: items
                .iter()
                .map(|ip| crate::lists::ListItem { id: ip.to_string(), ip: ip.to_string(), comment: String::new(), created_on: String::new(), modified_on: String::new() })
                .collect(),
            created_on: String::new(),
            modified_on: String::new(),
            sync: Default::default(),
        };
        crate::lists::sets(&of.iter().map(list).collect::<Vec<_>>())
    }

    #[test]
    fn ip_lists_are_named_with_a_dollar_and_resolved_when_compiled() {
        let sets = lists(&[("office", &["203.0.113.0/24", "2001:db8::/48"]), ("empty", &[]), ("one", &["192.0.2.1"])]);
        let at = |src: &str, ip: &str| {
            let e = Expr::parse_with(src, &sets).unwrap_or_else(|e| panic!("{src}: {e}"));
            e.matches(&ReqInfo { ip: Some(ip.parse().unwrap()), ..req() })
        };
        assert!(at("ip.src in $office", "203.0.113.23"));
        assert!(at("ip.src in $office", "2001:db8::ffff:1"));
        assert!(at("ip.src in $office", "::ffff:203.0.113.99"));
        assert!(!at("ip.src in $office", "192.0.2.1"));
        assert!(!at("ip.src in $office", "2001:db8:1::1"));
        assert!(at("ip.src in $one", "192.0.2.1") && !at("ip.src in $one", "192.0.2.2"));
        assert!(!at("ip.src in $empty", "192.0.2.1"));
        assert!(!at("ip.src in $nowhere", "192.0.2.1"), "a name with no list matches no address");
        assert!(at("not ip.src in $nowhere", "192.0.2.1"));
        assert!(at(r#"(ip.src in $one or ip.src in $office) and http.host eq "www.example.com""#, "203.0.113.1"));
        assert!(at("!(ip.src in $office)", "198.51.100.1"));
        assert!(at("ip.src in $office && ip.src in {203.0.113.0/25}", "203.0.113.9"), "sets written out still work beside lists");
        let no_ip = ReqInfo { ip: None, ..req() };
        assert!(!Expr::parse_with("ip.src in $office", &sets).unwrap().matches(&no_ip), "no address, no match");

        // parsed without lists, the same expression names the list and matches nothing
        let bare = Expr::parse("ip.src in $office or ip.src in $one and ip.src in $office").unwrap();
        assert_eq!(bare.lists(), ["office", "one"]);
        assert!(!bare.matches(&ReqInfo { ip: Some("203.0.113.23".parse().unwrap()), ..req() }));
        assert!(Expr::parse(r#"http.request.uri.path contains "$office""#).unwrap().lists().is_empty(), "a string is not a list");
        assert!(Expr::parse("").unwrap().lists().is_empty());
    }

    #[test]
    fn ip_lists_go_with_ip_src_in_only() {
        for bad in [
            "ip.src in $Office",
            "ip.src in $",
            "ip.src in $office-2",
            "ip.src in $office.x",
            "ip.src in {$office}",
            "ip.src eq $office",
            "ip.src ne $office",
            r#"http.host in $office"#,
            "ip.geoip.asnum in $office",
            "$office",
            "ip.src in $office $one",
            &format!("ip.src in ${}", "x".repeat(crate::lists::MAX_NAME + 1)),
        ] {
            assert!(Expr::parse(bad).is_err(), "{bad} should fail");
        }
        let e = Expr::parse("ip.src in $Office").unwrap_err();
        assert!(e.contains("lowercase"), "{e}");
        let e = Expr::parse("http.host in $office").unwrap_err();
        assert!(e.contains("ip.src"), "{e}");
        assert!(Expr::parse(&format!("ip.src in ${}", "x".repeat(crate::lists::MAX_NAME))).is_ok());
    }
}
