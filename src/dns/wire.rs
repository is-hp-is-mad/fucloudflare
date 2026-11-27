//! DNS wire format (RFC 1035 / 6891): query parsing, response encoding with
//! name compression, and presentation-format <-> RDATA conversion.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const HINFO: u16 = 13;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const OPT: u16 = 41;
    pub const DS: u16 = 43;
    pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47;
    pub const DNSKEY: u16 = 48;
    pub const HTTPS: u16 = 65;
    pub const ANY: u16 = 255;
    pub const CAA: u16 = 257;
}

pub mod rcode {
    pub const FORMERR: u16 = 1;
    pub const SERVFAIL: u16 = 2;
    pub const NXDOMAIN: u16 = 3;
    pub const NOTIMP: u16 = 4;
    pub const REFUSED: u16 = 5;
    pub const BADVERS: u16 = 16;
}

/// Record types users may create through the API.
pub const SUPPORTED_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR"];

pub fn type_from_str(s: &str) -> Option<u16> {
    Some(match s {
        "A" => rtype::A,
        "NS" => rtype::NS,
        "CNAME" => rtype::CNAME,
        "SOA" => rtype::SOA,
        "PTR" => rtype::PTR,
        "MX" => rtype::MX,
        "TXT" => rtype::TXT,
        "AAAA" => rtype::AAAA,
        "SRV" => rtype::SRV,
        "CAA" => rtype::CAA,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx { preference: u16, exchange: String },
    Txt(Vec<Vec<u8>>),
    Soa { mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Srv { priority: u16, weight: u16, port: u16, target: String },
    Caa { flags: u8, tag: String, value: Vec<u8> },
    Hinfo { cpu: String, os: String },
    /// HTTPS service binding (RFC 9460) for the owner name itself.
    Https { priority: u16, alpn: Vec<&'static str>, port: Option<u16> },
    /// DNSKEY (RFC 4034 §2).
    Dnskey { flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8> },
    /// RRSIG (RFC 4034 §3).
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        orig_ttl: u32,
        sig_exp: u32,
        sig_inc: u32,
        key_tag: u16,
        signer: String,
        signature: Vec<u8>,
    },
    /// NSEC (RFC 4034 §4).
    Nsec { next_domain: String, types: Vec<u16> },
    /// DS (RFC 4034 §5).
    #[allow(dead_code)]
    Ds { key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8> },
}

impl RData {
    pub fn rtype(&self) -> u16 {
        match self {
            RData::A(_) => rtype::A,
            RData::Aaaa(_) => rtype::AAAA,
            RData::Cname(_) => rtype::CNAME,
            RData::Ns(_) => rtype::NS,
            RData::Ptr(_) => rtype::PTR,
            RData::Mx { .. } => rtype::MX,
            RData::Txt(_) => rtype::TXT,
            RData::Soa { .. } => rtype::SOA,
            RData::Srv { .. } => rtype::SRV,
            RData::Caa { .. } => rtype::CAA,
            RData::Hinfo { .. } => rtype::HINFO,
            RData::Https { .. } => rtype::HTTPS,
            RData::Dnskey { .. } => rtype::DNSKEY,
            RData::Rrsig { .. } => rtype::RRSIG,
            RData::Nsec { .. } => rtype::NSEC,
            RData::Ds { .. } => rtype::DS,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RR {
    pub name: String,
    pub ttl: u32,
    pub data: RData,
}

// ---------------------------------------------------------------- names ----

/// Lowercase, strip the trailing dot and validate a host name.
/// `*` is allowed as a whole label (wildcards), `_` for service labels.
pub fn normalize_name(s: &str) -> Result<String, String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err("name must not be empty".into());
    }
    if s.len() > 253 {
        return Err("name exceeds 253 characters".into());
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid label length in '{s}'"));
        }
        if label == "*" {
            continue;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(format!("invalid character in name '{s}'"));
        }
    }
    Ok(s)
}

// ------------------------------------------------- presentation format ----

fn chunk_txt(bytes: &[u8], out: &mut Vec<Vec<u8>>) {
    if bytes.is_empty() {
        out.push(Vec::new());
    }
    for c in bytes.chunks(255) {
        out.push(c.to_vec());
    }
}

/// Parse `"quoted" "strings"` (with backslash escapes) or a bare string.
fn parse_txt(content: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let t = content.trim();
    if !t.starts_with('"') {
        chunk_txt(content.as_bytes(), &mut out);
        return Ok(out);
    }
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i] != b'"' {
            return Err("TXT content: expected '\"'".into());
        }
        i += 1;
        let mut cur = Vec::new();
        loop {
            match b.get(i) {
                None => return Err("TXT content: unterminated quote".into()),
                Some(b'"') => break,
                Some(b'\\') if i + 1 < b.len() => {
                    cur.push(b[i + 1]);
                    i += 2;
                }
                Some(&c) => {
                    cur.push(c);
                    i += 1;
                }
            }
        }
        i += 1;
        chunk_txt(&cur, &mut out);
    }
    Ok(out)
}

fn num<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, String> {
    s.parse().map_err(|_| format!("invalid {what}: '{s}'"))
}

/// Convert API-level `(type, content, priority)` into wire RDATA.
pub fn parse_rdata(rtype: &str, content: &str, priority: Option<u16>) -> Result<RData, String> {
    let c = content.trim();
    Ok(match rtype {
        "A" => RData::A(c.parse().map_err(|_| format!("'{c}' is not a valid IPv4 address"))?),
        "AAAA" => RData::Aaaa(c.parse().map_err(|_| format!("'{c}' is not a valid IPv6 address"))?),
        "CNAME" => RData::Cname(normalize_name(c)?),
        "NS" => RData::Ns(normalize_name(c)?),
        "PTR" => RData::Ptr(normalize_name(c)?),
        "MX" => RData::Mx {
            preference: priority.ok_or("MX records require a priority")?,
            exchange: normalize_name(c)?,
        },
        "TXT" => RData::Txt(parse_txt(content)?),
        "SRV" => {
            let f: Vec<&str> = c.split_whitespace().collect();
            let (prio, rest) = match (f.len(), priority) {
                (4, _) => (num(f[0], "SRV priority")?, &f[1..]),
                (3, Some(p)) => (p, &f[..]),
                _ => return Err("SRV content must be 'priority weight port target'".into()),
            };
            RData::Srv {
                priority: prio,
                weight: num(rest[0], "SRV weight")?,
                port: num(rest[1], "SRV port")?,
                target: if rest[2] == "." { String::new() } else { normalize_name(rest[2])? },
            }
        }
        "CAA" => {
            let mut it = c.splitn(3, char::is_whitespace);
            let flags = num(it.next().unwrap_or(""), "CAA flags")?;
            let tag = it.next().ok_or("CAA content must be 'flags tag value'")?.to_string();
            let value = it.next().ok_or("CAA content must be 'flags tag value'")?.trim();
            if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err("invalid CAA tag".into());
            }
            let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
            RData::Caa { flags, tag, value: value.as_bytes().to_vec() }
        }
        other => return Err(format!("unsupported record type '{other}'")),
    })
}

/// Canonical form of record content as stored and returned by the API.
pub fn normalize_content(rtype: &str, content: &str, priority: Option<u16>) -> Result<String, String> {
    Ok(match parse_rdata(rtype, content, priority)? {
        RData::A(ip) => ip.to_string(),
        RData::Aaaa(ip) => ip.to_string(),
        RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => n,
        RData::Mx { exchange, .. } => exchange,
        _ => content.trim().to_string(),
    })
}

// --------------------------------------------------------------- parse ----

#[derive(Debug, Clone, Copy)]
pub struct Edns {
    pub udp_size: u16,
    pub version: u8,
    pub do_bit: bool,
}

/// EDNS Client Subnet (RFC 7871): the network the end user is in, as
/// reported by the recursive resolver.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ecs {
    pub family: u16,
    pub source_prefix: u8,
    pub addr: std::net::IpAddr,
}

fn parse_ecs(mut options: &[u8]) -> Option<Ecs> {
    while options.len() >= 4 {
        let code = u16::from_be_bytes([options[0], options[1]]);
        let len = u16::from_be_bytes([options[2], options[3]]) as usize;
        let data = options.get(4..4 + len)?;
        if code == 8 && len >= 4 {
            let family = u16::from_be_bytes([data[0], data[1]]);
            let mut bytes = [0u8; 16];
            let given = &data[4..];
            let addr: std::net::IpAddr = match family {
                1 if given.len() <= 4 => {
                    bytes[..given.len()].copy_from_slice(given);
                    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into()
                }
                2 if given.len() <= 16 => {
                    bytes[..given.len()].copy_from_slice(given);
                    Ipv6Addr::from(bytes).into()
                }
                _ => return None,
            };
            return Some(Ecs { family, source_prefix: data[2], addr });
        }
        options = &options[4 + len..];
    }
    None
}

#[derive(Debug)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    /// Name exactly as sent (case preserved, echoed back for 0x20).
    pub qname_raw: String,
    /// Lowercased name used for lookups.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub edns: Option<Edns>,
    pub ecs: Option<Ecs>,
}

#[derive(Debug)]
pub enum ParseError {
    /// Not even a header: drop silently.
    TooShort,
    /// Header readable but the rest is malformed: answer FORMERR.
    FormErr { id: u16, flags: u16 },
}

fn be16(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]))
}

fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let target = (be16(buf, pos)? & 0x3FFF) as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 10 {
                return None;
            }
            pos = target;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = buf.get(pos + 1..pos + 1 + len)?;
        if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        if name.len() > 253 {
            return None;
        }
        pos += 1 + len;
    }
    Some((name, end.unwrap_or(pos)))
}

pub fn parse_query(buf: &[u8]) -> Result<Query, ParseError> {
    if buf.len() < 12 {
        return Err(ParseError::TooShort);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let inner = || -> Option<Query> {
        let (qd, an, ns, ar) = (be16(buf, 4)?, be16(buf, 6)?, be16(buf, 8)?, be16(buf, 10)?);
        if qd != 1 {
            return None;
        }
        let (qname_raw, mut pos) = read_name(buf, 12)?;
        let qtype = be16(buf, pos)?;
        let qclass = be16(buf, pos + 2)?;
        pos += 4;
        let mut edns = None;
        let mut ecs = None;
        let total = an as usize + ns as usize + ar as usize;
        for i in 0..total {
            let (_, p) = read_name(buf, pos)?;
            let t = be16(buf, p)?;
            let class = be16(buf, p + 2)?;
            let version = *buf.get(p + 5)?;
            let flags_z = be16(buf, p + 6)?;
            let rdlen = be16(buf, p + 8)? as usize;
            pos = p + 10 + rdlen;
            if pos > buf.len() {
                return None;
            }
            if t == rtype::OPT && i >= an as usize + ns as usize {
                edns = Some(Edns { udp_size: class, version, do_bit: (flags_z & 0x8000) != 0 });
                ecs = parse_ecs(&buf[p + 10..pos]);
            }
        }
        Some(Query { id, flags, qname: qname_raw.to_ascii_lowercase(), qname_raw, qtype, qclass, edns, ecs })
    };
    inner().ok_or(ParseError::FormErr { id, flags })
}

// -------------------------------------------------------------- encode ----

struct Writer {
    buf: Vec<u8>,
    names: HashMap<String, u16>,
}

impl Writer {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn chars(&mut self, s: &[u8]) {
        let s = &s[..s.len().min(255)];
        self.u8(s.len() as u8);
        self.buf.extend_from_slice(s);
    }

    fn name(&mut self, name: &str, compress: bool) {
        let mut rest = name.trim_end_matches('.');
        while !rest.is_empty() {
            let key = rest.to_ascii_lowercase();
            if compress {
                if let Some(&off) = self.names.get(&key) {
                    self.u16(0xC000 | off);
                    return;
                }
            }
            let off = self.buf.len();
            if off < 0x3FFF {
                self.names.entry(key).or_insert(off as u16);
            }
            let (label, tail) = rest.split_once('.').unwrap_or((rest, ""));
            let label = &label.as_bytes()[..label.len().min(63)];
            self.u8(label.len() as u8);
            self.buf.extend_from_slice(label);
            rest = tail;
        }
        self.u8(0);
    }

    fn rr(&mut self, rr: &RR) {
        self.name(&rr.name, true);
        self.u16(rr.data.rtype());
        self.u16(1);
        self.u32(rr.ttl);
        let len_pos = self.buf.len();
        self.u16(0);
        match &rr.data {
            RData::A(ip) => self.buf.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => self.buf.extend_from_slice(&ip.octets()),
            RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => self.name(n, true),
            RData::Mx { preference, exchange } => {
                self.u16(*preference);
                self.name(exchange, true);
            }
            RData::Txt(parts) => {
                for p in parts {
                    self.chars(p);
                }
            }
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                self.name(mname, true);
                self.name(rname, true);
                for v in [serial, refresh, retry, expire, minimum] {
                    self.u32(*v);
                }
            }
            RData::Srv { priority, weight, port, target } => {
                self.u16(*priority);
                self.u16(*weight);
                self.u16(*port);
                self.name(target, false);
            }
            RData::Caa { flags, tag, value } => {
                self.u8(*flags);
                self.chars(tag.as_bytes());
                self.buf.extend_from_slice(value);
            }
            RData::Hinfo { cpu, os } => {
                self.chars(cpu.as_bytes());
                self.chars(os.as_bytes());
            }
            RData::Https { priority, alpn, port } => {
                self.u16(*priority);
                self.u8(0); // target ".": the owner name
                let ids: Vec<u8> = alpn.iter().flat_map(|a| std::iter::once(a.len() as u8).chain(a.bytes())).collect();
                self.u16(1); // alpn
                self.u16(ids.len() as u16);
                self.buf.extend_from_slice(&ids);
                if let Some(port) = port {
                    self.u16(3); // port
                    self.u16(2);
                    self.u16(*port);
                }
            }
            RData::Dnskey { flags, protocol, algorithm, public_key } => {
                self.u16(*flags);
                self.u8(*protocol);
                self.u8(*algorithm);
                self.buf.extend_from_slice(public_key);
            }
            RData::Rrsig { type_covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, signer, signature } => {
                self.u16(*type_covered);
                self.u8(*algorithm);
                self.u8(*labels);
                self.u32(*orig_ttl);
                self.u32(*sig_exp);
                self.u32(*sig_inc);
                self.u16(*key_tag);
                self.name(signer, false);
                self.buf.extend_from_slice(signature);
            }
            RData::Nsec { next_domain, types } => {
                self.name(next_domain, false);
                encode_nsec_bitmap(types, &mut self.buf);
            }
            RData::Ds { key_tag, algorithm, digest_type, digest } => {
                self.u16(*key_tag);
                self.u8(*algorithm);
                self.u8(*digest_type);
                self.buf.extend_from_slice(digest);
            }
        }
        let rdlen = (self.buf.len() - len_pos - 2) as u16;
        self.buf[len_pos..len_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
}

/// Encode an RFC 4034 §4.1.2 NSEC Type Bit Maps field.
pub fn encode_nsec_bitmap(types: &[u16], out: &mut Vec<u8>) {
    let mut sorted = types.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut i = 0;
    while i < sorted.len() {
        let win = (sorted[i] >> 8) as u8;
        let mut map = [0u8; 32];
        let mut max_byte = 0usize;
        while i < sorted.len() && (sorted[i] >> 8) as u8 == win {
            let low = (sorted[i] & 0xFF) as usize;
            let byte_idx = low / 8;
            let bit_idx = 7 - (low % 8);
            map[byte_idx] |= 1u8 << bit_idx;
            if byte_idx + 1 > max_byte {
                max_byte = byte_idx + 1;
            }
            i += 1;
        }
        out.push(win);
        out.push(max_byte as u8);
        out.extend_from_slice(&map[..max_byte]);
    }
}

/// Canonical uncompressed, lowercased DNS wire name (RFC 4034 §6.2).
pub fn canonical_name(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 2);
    if !name.is_empty() && name != "." {
        for label in name.trim_end_matches('.').split('.') {
            out.push(label.len() as u8);
            for b in label.as_bytes() {
                out.push(b.to_ascii_lowercase());
            }
        }
    }
    out.push(0);
    out
}

/// Canonical uncompressed, lowercased RDATA wire bytes (RFC 4034 §6.2).
pub fn canonical_rdata(data: &RData) -> Vec<u8> {
    let mut w = Writer { buf: Vec::with_capacity(128), names: HashMap::new() };
    let cname = |w: &mut Writer, n: &str| w.buf.extend_from_slice(&canonical_name(n));
    match data {
        RData::A(ip) => w.buf.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => w.buf.extend_from_slice(&ip.octets()),
        RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => cname(&mut w, n),
        RData::Mx { preference, exchange } => {
            w.u16(*preference);
            cname(&mut w, exchange);
        }
        RData::Txt(parts) => {
            for p in parts {
                w.chars(p);
            }
        }
        RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            cname(&mut w, mname);
            cname(&mut w, rname);
            for v in [serial, refresh, retry, expire, minimum] {
                w.u32(*v);
            }
        }
        RData::Srv { priority, weight, port, target } => {
            w.u16(*priority);
            w.u16(*weight);
            w.u16(*port);
            cname(&mut w, target);
        }
        RData::Caa { flags, tag, value } => {
            w.u8(*flags);
            w.chars(tag.as_bytes());
            w.buf.extend_from_slice(value);
        }
        RData::Hinfo { cpu, os } => {
            w.chars(cpu.as_bytes());
            w.chars(os.as_bytes());
        }
        RData::Https { priority, alpn, port } => {
            w.u16(*priority);
            w.u8(0);
            let ids: Vec<u8> = alpn.iter().flat_map(|a| std::iter::once(a.len() as u8).chain(a.bytes())).collect();
            w.u16(1);
            w.u16(ids.len() as u16);
            w.buf.extend_from_slice(&ids);
            if let Some(port) = port {
                w.u16(3);
                w.u16(2);
                w.u16(*port);
            }
        }
        RData::Dnskey { flags, protocol, algorithm, public_key } => {
            w.u16(*flags);
            w.u8(*protocol);
            w.u8(*algorithm);
            w.buf.extend_from_slice(public_key);
        }
        RData::Rrsig { type_covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, signer, signature } => {
            w.u16(*type_covered);
            w.u8(*algorithm);
            w.u8(*labels);
            w.u32(*orig_ttl);
            w.u32(*sig_exp);
            w.u32(*sig_inc);
            w.u16(*key_tag);
            cname(&mut w, signer);
            w.buf.extend_from_slice(signature);
        }
        RData::Nsec { next_domain, types } => {
            cname(&mut w, next_domain);
            encode_nsec_bitmap(types, &mut w.buf);
        }
        RData::Ds { key_tag, algorithm, digest_type, digest } => {
            w.u16(*key_tag);
            w.u8(*algorithm);
            w.u8(*digest_type);
            w.buf.extend_from_slice(digest);
        }
    }
    w.buf
}

/// UDP payload size we advertise (DNS Flag Day 2020 recommendation).
pub const EDNS_UDP_SIZE: u16 = 1232;

#[derive(Debug, Default)]
pub struct Response {
    pub id: u16,
    /// Flags of the query (opcode and RD are echoed).
    pub query_flags: u16,
    /// Full rcode; values above 15 need EDNS (upper bits go into the OPT TTL).
    pub rcode: u16,
    pub aa: bool,
    pub question: Option<(String, u16, u16)>,
    pub answers: Vec<RR>,
    pub authority: Vec<RR>,
    pub additional: Vec<RR>,
    pub edns: bool,
    pub do_bit: bool,
    /// Client subnet to echo, with the scope prefix our answer is valid for.
    pub ecs: Option<(Ecs, u8)>,
}

impl Response {
    /// Encode; if the message does not fit in `max` bytes, send an empty
    /// truncated (TC) reply so the client retries over TCP.
    pub fn encode(&self, max: usize) -> Vec<u8> {
        let full = self.encode_inner(false);
        if full.len() <= max {
            full
        } else {
            self.encode_inner(true)
        }
    }

    fn encode_inner(&self, truncated: bool) -> Vec<u8> {
        let mut w = Writer { buf: Vec::with_capacity(512), names: HashMap::new() };
        let mut flags = 0x8000 | (self.query_flags & 0x7900) | (self.rcode & 0xF);
        if self.aa {
            flags |= 0x0400;
        }
        if truncated {
            flags |= 0x0200;
        }
        let empty: &[RR] = &[];
        let (an, ns, ar) = if truncated {
            (empty, empty, empty)
        } else {
            (&self.answers[..], &self.authority[..], &self.additional[..])
        };
        w.u16(self.id);
        w.u16(flags);
        w.u16(self.question.is_some() as u16);
        w.u16(an.len() as u16);
        w.u16(ns.len() as u16);
        w.u16(ar.len() as u16 + self.edns as u16);
        if let Some((name, qtype, qclass)) = &self.question {
            w.name(name, false);
            w.u16(*qtype);
            w.u16(*qclass);
        }
        for rr in an.iter().chain(ns).chain(ar) {
            w.rr(rr);
        }
        if self.edns {
            w.u8(0);
            w.u16(rtype::OPT);
            w.u16(EDNS_UDP_SIZE);
            w.u32((((self.rcode >> 4) as u32) << 24) | if self.do_bit { 0x8000 } else { 0 });
            match &self.ecs {
                None => w.u16(0),
                Some((ecs, scope)) => {
                    let octets = match ecs.addr {
                        std::net::IpAddr::V4(a) => a.octets().to_vec(),
                        std::net::IpAddr::V6(a) => a.octets().to_vec(),
                    };
                    let n = (ecs.source_prefix as usize).div_ceil(8).min(octets.len());
                    w.u16(8 + n as u16);
                    w.u16(8);
                    w.u16(4 + n as u16);
                    w.u16(ecs.family);
                    w.u8(ecs.source_prefix);
                    w.u8(*scope);
                    w.buf.extend_from_slice(&octets[..n]);
                }
            }
        }
        w.buf
    }
}

#[cfg(test)]
pub mod testutil {
    /// Build a minimal query packet.
    pub fn query(id: u16, name: &str, qtype: u16, edns: bool) -> Vec<u8> {
        let mut b = vec![];
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, edns as u8]);
        for l in name.split('.').filter(|l| !l.is_empty()) {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&[0, 1]);
        if edns {
            b.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_encode_roundtrip() {
        let q = parse_query(&testutil::query(0xBEEF, "WwW.Example.COM", rtype::A, true)).unwrap();
        assert_eq!(q.qname, "www.example.com");
        assert_eq!(q.qname_raw, "WwW.Example.COM");
        assert_eq!(q.edns.unwrap().udp_size, 4096);

        let resp = Response {
            id: q.id,
            query_flags: q.flags,
            aa: true,
            question: Some((q.qname_raw.clone(), q.qtype, q.qclass)),
            answers: vec![RR { name: q.qname.clone(), ttl: 300, data: RData::A("1.2.3.4".parse().unwrap()) }],
            edns: true,
            ..Default::default()
        };
        let b = resp.encode(1232);
        assert_eq!(&b[..2], &[0xBE, 0xEF]);
        assert_eq!(u16::from_be_bytes([b[2], b[3]]), 0x8500); // QR AA RD
        assert_eq!(&b[6..8], &[0, 1]);
        // answer owner is a compression pointer to the question name at offset 12
        let q_end = 12 + 17 + 4;
        assert_eq!(&b[q_end..q_end + 2], &[0xC0, 12]);
        assert_eq!(&b[q_end + 12..q_end + 16], &[1, 2, 3, 4]);
    }

    #[test]
    fn truncates_when_too_large() {
        let rr = RR { name: "t.example.com".into(), ttl: 1, data: RData::Txt(vec![vec![b'x'; 255]; 4]) };
        let resp = Response { answers: vec![rr], ..Default::default() };
        let b = resp.encode(512);
        assert_eq!(b.len(), 12);
        assert_ne!(b[2] & 0x02, 0);
    }

    #[test]
    fn rdata_parsing() {
        assert!(parse_rdata("A", "999.1.1.1", None).is_err());
        assert_eq!(normalize_content("AAAA", "2001:DB8:0::1", None).unwrap(), "2001:db8::1");
        assert_eq!(normalize_content("CNAME", "Foo.Example.com.", None).unwrap(), "foo.example.com");
        assert!(parse_rdata("MX", "mail.example.com", None).is_err());
        assert_eq!(
            parse_rdata("TXT", "\"a b\" \"c\"", None).unwrap(),
            RData::Txt(vec![b"a b".to_vec(), b"c".to_vec()])
        );
        assert_eq!(
            parse_rdata("CAA", "0 issue \"letsencrypt.org\"", None).unwrap(),
            RData::Caa { flags: 0, tag: "issue".into(), value: b"letsencrypt.org".to_vec() }
        );
        assert!(matches!(parse_rdata("SRV", "10 5 5060 sip.example.com", None).unwrap(), RData::Srv { port: 5060, .. }));
    }

    #[test]
    fn malformed_is_formerr() {
        let mut q = testutil::query(7, "example.com", 1, false);
        q.truncate(q.len() - 3);
        assert!(matches!(parse_query(&q), Err(ParseError::FormErr { id: 7, .. })));
        assert!(matches!(parse_query(&[0; 5]), Err(ParseError::TooShort)));
    }
}
