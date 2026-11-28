//! DKIM signatures (RFC 6376) on the mail that e-mail routing passes on.
//!
//! A forwarded message keeps its original From, and the sender's own DKIM
//! signature often does not survive the trip (or never was there). A
//! signature by the zone the mail was sent to tells the destination that a
//! server speaking for that zone passed the message on, and that nothing
//! changed since: mailbox providers count that in the forwarder's favour.
//! ARC (RFC 8617), which also carries the authentication results seen on
//! arrival, is a later step and not done here.
//!
//! The zone's owner brings the key: an unencrypted RSA key of 2048 to 4096
//! bits in PKCS#8 PEM form, with a selector. The API and the panel show the
//! TXT record to publish (`{selector}._domainkey.{zone}`), never the key.
//! Messages are signed with rsa-sha256 and relaxed/relaxed
//! canonicalization. A message that cannot be signed goes on unsigned: mail
//! that arrives without a signature costs less than mail that does not
//! arrive.

use crate::store::{Record, Snapshot, Store, StoreError, Zone};
use base64::Engine;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::borrow::Cow;

/// The longest PEM text taken; a 4096-bit key is about 3.3 KB of it.
const MAX_PEM: usize = 16 * 1024;
/// Shorter RSA keys are breakable, and mailbox providers ignore them.
const MIN_BITS: usize = 2048;
/// A selector is one name in DNS; this keeps it (and the record name) short.
const MAX_SELECTOR: usize = 63;
/// Longest line of the DKIM-Signature header field (RFC 5322 recommends 78).
const LINE: usize = 78;
/// The PEM label of a PKCS#8 private key (kept apart from the armour dashes
/// so that secret scanners do not take this source for a key).
const PEM_LABEL: &str = "PRIVATE KEY";
/// Header fields signed when present: those RFC 6376 section 5.4.1 says
/// should be, as far as a forwarded message has them. Each instance is
/// signed; From once more (see `Signer::signature`).
const SIGNED: &[&str] = &[
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "reply-to",
    "in-reply-to",
    "references",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
];
/// rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters: the
/// AlgorithmIdentifier of an RSA SubjectPublicKeyInfo (RFC 8017 A.1).
const RSA_ALGORITHM: &[u8] = &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

// ---------------------------------------------------------------- the key ----

/// What a zone keeps to sign the mail it passes on. It is stored with the
/// zone, so every node that takes mail for the zone has it; the API never
/// answers the private key.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DkimKey {
    pub selector: String,
    /// PKCS#8 PEM, armoured afresh from the key alone: whatever else was
    /// pasted with it (certificates, comments) is not kept.
    pub private_key: String,
}

/// Written out by hand so that the key never lands in a log line.
impl std::fmt::Debug for DkimKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimKey").field("selector", &self.selector).field("private_key", &"<redacted>").finish()
    }
}

impl DkimKey {
    /// A checked key for `zone`: the selector is a DNS name, the key an RSA
    /// key of a size that is signed with. Errors say what is wrong without
    /// repeating any of the key.
    pub fn new(zone: &str, selector: &str, pem: &str) -> Result<DkimKey, String> {
        let selector = check_selector(zone, selector)?;
        let der = pkcs8_der(pem)?;
        rsa_key(&der)?;
        Ok(DkimKey { selector, private_key: armour(&der) })
    }

    fn key_pair(&self) -> Result<RsaKeyPair, String> {
        rsa_key(&pkcs8_der(&self.private_key)?)
    }

    /// The TXT record the zone publishes for this key -- its name and its
    /// content -- and the key's size in bits.
    pub fn record(&self, zone: &str) -> Result<(String, String, usize), String> {
        let key = self.key_pair()?;
        let p = b64(&subject_public_key_info(key.public().as_ref()));
        Ok((record_name(&self.selector, zone), format!("v=DKIM1; k=rsa; p={p}"), key.public().modulus_len() * 8))
    }

    /// Something that signs for `zone` with this key.
    pub fn signer(&self, zone: &str) -> Result<Signer, String> {
        Ok(Signer { key: self.key_pair()?, domain: zone.to_ascii_lowercase(), selector: self.selector.clone() })
    }
}

/// A selector as it is stored: lowercase dot-separated DNS labels of
/// letters, digits and hyphens (RFC 6376 3.1 says a selector is a
/// sub-domain; no underscores, which DNS tools treat as special).
pub fn check_selector(zone: &str, selector: &str) -> Result<String, String> {
    let s = selector.trim().to_ascii_lowercase();
    let label = |l: &str| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if s.is_empty() || s.len() > MAX_SELECTOR || !s.split('.').all(label) {
        return Err(format!(
            "dkim_selector is a DNS name of at most {MAX_SELECTOR} characters: letters, digits and hyphens in dot-separated labels (e.g. \"fucf\")"
        ));
    }
    if record_name(&s, zone).len() > 253 {
        return Err("dkim_selector is too long for this zone: the record name would be longer than 253 characters".into());
    }
    Ok(s)
}

/// Where the zone publishes the public key of `selector`.
fn record_name(selector: &str, zone: &str) -> String {
    format!("{selector}._domainkey.{zone}")
}

/// The DER of the first PKCS#8 private key in `pem`. The messages name the
/// usual mistakes and how to fix them.
fn pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    if pem.len() > MAX_PEM {
        return Err("dkim_private_key is too long for an RSA key of at most 4096 bits".into());
    }
    // (lines pasted with indentation would not be read as armour)
    let text: String = pem.lines().map(str::trim).collect::<Vec<_>>().join("\n");
    match PrivatePkcs8KeyDer::from_pem_slice(text.as_bytes()) {
        Ok(der) => Ok(der.secret_pkcs8_der().to_vec()),
        Err(_) if text.contains("ENCRYPTED PRIVATE KEY") => {
            Err("dkim_private_key is encrypted: give it without a passphrase (openssl pkcs8 -topk8 -nocrypt)".into())
        }
        Err(_) if text.contains("RSA PRIVATE KEY") => Err(
            "dkim_private_key is a PKCS#1 key (BEGIN RSA PRIVATE KEY): convert it to PKCS#8 with openssl pkcs8 -topk8 -nocrypt".into(),
        ),
        Err(_) => Err("dkim_private_key is not a PEM private key: give an unencrypted RSA key in PKCS#8 form (BEGIN PRIVATE KEY)".into()),
    }
}

/// The RSA key in a PKCS#8 DER, if it is one that we sign with.
fn rsa_key(der: &[u8]) -> Result<RsaKeyPair, String> {
    let key = RsaKeyPair::from_pkcs8(der).map_err(|e| match e.to_string().as_str() {
        "TooSmall" => format!("dkim_private_key is too short: an RSA key of at least {MIN_BITS} bits is needed"),
        "TooLarge" => "dkim_private_key is too long: RSA keys of at most 4096 bits are taken".to_string(),
        "WrongAlgorithm" => "dkim_private_key is not an RSA key".to_string(),
        _ => "dkim_private_key is not a valid RSA private key".to_string(),
    })?;
    // (ring refuses these already; the policy should not hang on that)
    if key.public().modulus_len() * 8 < MIN_BITS {
        return Err(format!("dkim_private_key is too short: an RSA key of at least {MIN_BITS} bits is needed"));
    }
    Ok(key)
}

/// PKCS#8 DER as PEM, 64 characters to a line.
fn armour(der: &[u8]) -> String {
    let text = b64(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect();
    let dashes = "-----";
    format!("{dashes}BEGIN {PEM_LABEL}{dashes}\n{}\n{dashes}END {PEM_LABEL}{dashes}\n", lines.join("\n"))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A DER length: short form below 128, long form above.
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// The SubjectPublicKeyInfo (RFC 5280 4.1) around a PKCS#1 RSAPublicKey,
/// which is what ring gives: DKIM's `p=` holds the former (RFC 6376 3.6.1).
fn subject_public_key_info(rsa_public_key: &[u8]) -> Vec<u8> {
    let mut bits = vec![0]; // a BIT STRING of whole bytes: no unused bits
    bits.extend_from_slice(rsa_public_key);
    let mut inner = RSA_ALGORITHM.to_vec();
    inner.extend(der(0x03, &bits));
    der(0x30, &inner)
}

// ------------------------------------------------------- canonicalization ----

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Each run of spaces and tabs as one space; none at the end.
fn squeeze(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut gap = false;
    for &b in bytes {
        if is_wsp(b) {
            gap = true;
        } else {
            if gap {
                out.push(b' ');
            }
            gap = false;
            out.push(b);
        }
    }
    out
}

/// Without line ends: CRLF, and a bare LF the way a receiver that turns it
/// into CRLF would see it.
fn unfold(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' || (b == b'\r' && bytes.get(i + 1) == Some(&b'\n')) {
            continue;
        }
        out.push(b);
    }
    out
}

/// The "relaxed" form of one header field, folds and line end included
/// (RFC 6376 3.4.2): lowercase name, unfolded, whitespace squeezed and
/// trimmed around the value, ending in CRLF. None: not a field (no colon).
pub fn relaxed_header(field: &[u8]) -> Option<Vec<u8>> {
    let colon = field.iter().position(|&b| b == b':')?;
    let name = &field[..colon];
    let name_end = name.iter().rposition(|&b| !is_wsp(b)).map_or(0, |i| i + 1);
    let mut out = name[..name_end].to_ascii_lowercase();
    out.push(b':');
    let value = squeeze(&unfold(&field[colon + 1..]));
    out.extend_from_slice(value.strip_prefix(b" ").unwrap_or(&value));
    out.extend_from_slice(b"\r\n");
    Some(out)
}

/// The "relaxed" form of a body (RFC 6376 3.4.4): whitespace squeezed and
/// gone at line ends, empty lines at the end gone, every line ending in
/// CRLF. An empty body stays empty (unlike "simple", which makes it CRLF).
pub fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = body.split(|&b| b == b'\n').map(|l| squeeze(l.strip_suffix(b"\r").unwrap_or(l))).collect();
    // (what follows the last line end is a line only if something is in it)
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    for line in lines {
        out.extend_from_slice(&line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// A message's header fields -- each with its folds and line ends -- and
/// its body (what follows the first empty line). Lines may end in CRLF or
/// a bare LF.
fn split(message: &[u8]) -> (Vec<&[u8]>, &[u8]) {
    let mut fields = Vec::new();
    let (mut start, mut at) = (None::<usize>, 0);
    while at < message.len() {
        let end = message[at..].iter().position(|&b| b == b'\n').map_or(message.len(), |i| at + i + 1);
        let line = &message[at..end];
        let text = line.strip_suffix(b"\n").unwrap_or(line);
        if text.strip_suffix(b"\r").unwrap_or(text).is_empty() {
            fields.extend(start.map(|s| &message[s..at]));
            return (fields, &message[end..]);
        }
        // a line that starts with whitespace continues the field before it
        if !is_wsp(line[0]) || start.is_none() {
            fields.extend(start.map(|s| &message[s..at]));
            start = Some(at);
        }
        at = end;
    }
    fields.extend(start.map(|s| &message[s..at]));
    (fields, &message[message.len()..])
}

/// A field's name as DKIM compares it: lowercase, without the whitespace
/// before the colon.
fn field_name(field: &[u8]) -> Option<String> {
    let colon = field.iter().position(|&b| b == b':')?;
    Some(String::from_utf8_lossy(&field[..colon]).trim_end_matches([' ', '\t']).to_ascii_lowercase())
}

// ---------------------------------------------------------------- signing ----

/// Signs messages for one zone with its key.
pub struct Signer {
    key: RsaKeyPair,
    domain: String,
    selector: String,
}

impl Signer {
    /// The message with a DKIM-Signature header field in front of it,
    /// signed at `now` (unix seconds). The message itself is not changed.
    pub fn sign(&self, message: &[u8], now: u64) -> Result<Vec<u8>, String> {
        let header = self.signature(message, now)?;
        let mut out = Vec::with_capacity(header.len() + message.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(message);
        Ok(out)
    }

    /// The DKIM-Signature header field for `message`, folded, with its CRLF.
    fn signature(&self, message: &[u8], now: u64) -> Result<String, String> {
        let (fields, body) = split(message);
        let names: Vec<Option<String>> = fields.iter().map(|f| field_name(f)).collect();
        let count = |name: &str| names.iter().filter(|n| n.as_deref() == Some(name)).count();
        // DMARC judges the message by its one From: without one, or with
        // several, a signature would vouch for something unclear
        match count("from") {
            1 => {}
            0 => return Err("the message has no From header field".into()),
            _ => return Err("the message has more than one From header field".into()),
        }
        // every instance of each field present, and From once more: an empty
        // place that keeps another From from being added (RFC 6376 8.15)
        let mut signed: Vec<&str> = SIGNED.iter().flat_map(|name| std::iter::repeat_n(*name, count(name))).collect();
        signed.push("from");

        let mut data = Vec::new();
        let mut used = vec![false; fields.len()];
        for name in &signed {
            // instances are taken from the bottom up (RFC 6376 5.4.2)
            if let Some(i) = (0..fields.len()).rev().find(|&i| !used[i] && names[i].as_deref() == Some(*name)) {
                used[i] = true;
                data.extend(relaxed_header(fields[i]).unwrap_or_default());
            }
        }
        let body_hash = b64(ring::digest::digest(&ring::digest::SHA256, &relaxed_body(body)).as_ref());
        let mut h: Vec<String> = signed.iter().map(|n| format!("{n}:")).collect();
        if let Some(last) = h.last_mut() {
            last.pop();
        }
        h[0].insert_str(0, "h=");
        let one = |tag: String| vec![tag];
        let tags = vec![
            one("v=1".into()),
            one("a=rsa-sha256".into()),
            one("c=relaxed/relaxed".into()),
            one(format!("d={}", self.domain)),
            one(format!("s={}", self.selector)),
            one(format!("t={now}")),
            h,
            one(format!("bh={body_hash}")),
            one("b=".into()),
        ];
        // signed as it stands with b= empty, which is how a verifier sees it
        // once it takes the signature out (RFC 6376 3.7)
        let mut header = fold(&tags);
        let canonical = relaxed_header(format!("{header}\r\n").as_bytes()).unwrap_or_default();
        data.extend_from_slice(canonical.strip_suffix(b"\r\n").unwrap_or(&canonical));

        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), &data, &mut signature)
            .map_err(|_| "the message could not be signed".to_string())?;
        let mut col = header.len() - header.rfind('\n').map_or(0, |i| i + 1);
        for chunk in b64(&signature).as_bytes().chunks(64) {
            if col + chunk.len() > LINE {
                header.push_str("\r\n\t");
                col = 1;
            }
            header.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            col += chunk.len();
        }
        header.push_str("\r\n");
        Ok(header)
    }
}

/// The DKIM-Signature field with these tags, each a list of pieces that
/// whitespace may separate (`h=` by field name). Folded so that no line is
/// longer than LINE: a piece that does not fit goes on the next line.
fn fold(tags: &[Vec<String>]) -> String {
    let mut out = String::from("DKIM-Signature:");
    let mut col = out.len();
    for (t, pieces) in tags.iter().enumerate() {
        for (p, piece) in pieces.iter().enumerate() {
            let piece = if p + 1 == pieces.len() && t + 1 < tags.len() { format!("{piece};") } else { piece.clone() };
            let space = usize::from(p == 0);
            if col + space + piece.len() > LINE {
                out.push_str("\r\n\t");
                col = 1;
            } else if p == 0 {
                out.push(' ');
                col += 1;
            }
            out.push_str(&piece);
            col += piece.len();
        }
    }
    out
}

/// The message as it is passed on for `zone`: signed when the zone has a
/// DKIM key, as it came otherwise. A message that cannot be signed (no
/// From, a key that no longer reads) goes on unsigned, with a warning that
/// says why but nothing of the key.
pub fn sign_forwarded<'a>(snap: &Snapshot, zone: &str, message: &'a [u8], now: u64) -> Cow<'a, [u8]> {
    let Some(key) = snap.zones.get(zone).and_then(|z| z.zone.email_dkim.as_ref()) else { return Cow::Borrowed(message) };
    match key.signer(zone).and_then(|signer| signer.sign(message, now)) {
        Ok(signed) => Cow::Owned(signed),
        Err(why) => {
            tracing::warn!("mail for {zone} goes on without a DKIM signature: {why}");
            Cow::Borrowed(message)
        }
    }
}

// -------------------------------------------------------------------- API ----

/// What the API shows of a zone's DKIM key, as fields of its e-mail
/// settings: the selector, whether a key is set, the TXT record it needs
/// and whether the zone's DNS has it -- never the private key. Also the
/// record to add, when the zone's DNS does not have it yet.
pub fn view(zone: &Zone, records: &[Record]) -> (Map<String, Value>, Option<Value>) {
    let key = zone.email_dkim.as_ref();
    let mut v = Map::new();
    v.insert("dkim_selector".into(), json!(key.map(|k| &k.selector)));
    v.insert("has_dkim_private_key".into(), json!(key.is_some()));
    let mut needed = None;
    let (record, bits, published, error) = match key.map(|k| k.record(&zone.name)) {
        None => (Value::Null, Value::Null, false, Value::Null),
        Some(Err(why)) => (Value::Null, Value::Null, false, json!(why)),
        Some(Ok((name, content, bits))) => {
            let published = is_published(records, &name, &content);
            let record = json!({ "type": "TXT", "name": name, "content": content });
            if !published {
                needed = Some(record.clone());
            }
            (record, json!(bits), published, Value::Null)
        }
    };
    v.insert("dkim_record".into(), record);
    v.insert("dkim_key_bits".into(), bits);
    v.insert("dkim_published".into(), json!(published));
    v.insert("dkim_error".into(), error);
    (v, needed)
}

/// Does the zone have a TXT record at `name` with the public key of `content`?
fn is_published(records: &[Record], name: &str, content: &str) -> bool {
    let want = p_tag(content);
    want.is_some() && records.iter().filter(|r| r.rtype == "TXT" && r.name.eq_ignore_ascii_case(name)).any(|r| p_tag(&txt_text(&r.content)) == want)
}

/// The text of a TXT record: its quoted strings joined, or the bare text.
fn txt_text(content: &str) -> String {
    let t = content.trim();
    if !t.starts_with('"') {
        return t.to_string();
    }
    t.split('"').skip(1).step_by(2).collect()
}

/// The `p=` tag of a DKIM key record, without whitespace.
fn p_tag(text: &str) -> Option<String> {
    text.split(';').find_map(|tag| {
        let (name, value) = tag.split_once('=')?;
        (name.trim() == "p").then(|| value.split_whitespace().collect())
    })
}

/// Change a zone's DKIM key from a PATCH of its e-mail settings. Only two
/// fields are read: `dkim_selector` (null or "" removes the key) and
/// `dkim_private_key` (left out, null or "": the stored key stays, so that
/// what the API answers -- which never has the key -- can be sent back as
/// it is without losing it). Neither field: nothing changes.
pub async fn patch(store: &Store, zone_id: &str, body: &Value) -> Result<(), StoreError> {
    let invalid = |m: &str| StoreError::Invalid(m.to_string());
    let Some(body) = body.as_object() else { return Err(invalid("the body is a JSON object")) };
    // None: not given; Some(None): null or empty; Some(Some(text))
    let text = |name: &str| match body.get(name) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(Some(None)),
        Some(Value::String(s)) => Ok(Some(Some(s.clone()))),
        Some(_) => Err(StoreError::Invalid(format!("{name} is a string"))),
    };
    let selector = text("dkim_selector")?;
    let pem = text("dkim_private_key")?.flatten();
    let zone = store.get_zone(zone_id)?;
    match (&selector, &pem) {
        (None, None) => return Ok(()),
        (Some(None), Some(_)) => return Err(invalid("dkim_private_key needs a dkim_selector")),
        (Some(None), None) if zone.email_dkim.is_none() => return Ok(()),
        _ => {}
    }
    store
        .set_email_dkim_async(zone_id, move |zone| {
            let stored = zone.email_dkim.as_ref();
            let selector = match selector {
                Some(None) => return Ok(None),
                Some(Some(s)) => s,
                None => stored.map(|k| k.selector.clone()).ok_or_else(|| invalid("dkim_selector is required"))?,
            };
            let pem = match pem {
                Some(pem) => pem,
                None => stored
                    .map(|k| k.private_key.clone())
                    .ok_or_else(|| invalid("dkim_private_key is required: an unencrypted RSA key of at least 2048 bits in PKCS#8 PEM form"))?,
            };
            DkimKey::new(&zone.name, &selector, &pem).map(Some).map_err(StoreError::Invalid)
        })
        .await?;
    Ok(())
}

// ------------------------------------------------------------------ tests ----

/// Test-only RSA keys, made with openssl for these tests and nothing else.
/// Never use them for anything: they are public. Kept as base64 DER without
/// the PEM armour, which is put on at test time, so that secret scanners do
/// not take this file for a leaked key.
#[cfg(test)]
pub mod test_keys {
    /// PKCS#8 DER of a 2048-bit test-only key.
    const RSA_2048: &str = "
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQClwi+PDBTjjHvz
aJg6HaAINRkuOTBavnSUSHcwM3RptZJUaSQcWuec5g6RdKi9HTydbIxDHlyPFr/M
1iVRn79m9uF02s6GZYj6bg7EMqDYqCYcHJEely54bXqb9TNAjTCKVtqeToX7vDHC
JyDZSwNUro1JndAOn1O4+/adyU21A2CdTQxlP/5xvKMZil8JAZGB4M2xWV6VNkBA
MFyPq0JpSkkYNt6aW0V5a7SvpD3z4UJPqDITpT34zPR360cH7SG5vh6PcTL4gHmk
UR+dfX88lNUqJgQu73Cewce+QEcgK0Y06UQwcwDj3WoOp6Fu8ZZrIVltxakuG84R
4CUZ5M3FAgMBAAECggEAFme9mvXUmv9hv8CLFwvrFkDrIurbBOEKjAKRjcPev+0p
ltxRY73L4dLc9D9TEaDykQrbmLTxaOv3x/3INJTFv+quBegPk24FCmi2+UEoqbBs
2k7oNLzVrLSLpqoJn/eVsJVV3qEZjjHdffNhBs4TaK5hbap1tYxGulHgf2p25PkU
m+qs2PqENzAxt/17mayaQ5DsDd9g8L3Ys65plsQ+YqVQDfKLysDslJWhUj5vXmBf
pGN4mwKt7QbqNTq8M4AWqse7RcZiuRr9D9VK9QcgoY3PONiXA2jBsi3nxPGWMgwm
3X/P5MK0tDFLZ60nuctPV5PPB4xKS8JkXIiSshcIXwKBgQDap3d+3vygTMFSwa40
w4sduB8SrYb7Hk7CAExaWb13pwTfkyGog1OdFtckWM5at7zoJ+2QNEZgP/8sgR32
0qf5kQjW5D4RRKQfcOcMABe/j5niCQXlYcVqeXJmbHnRoBqhzdfz6ylYsGMNwhkI
BvK6tf1btTtSuyHrpCxgqC4DSwKBgQDCEeL/YZvkw3rRahMr3uUfPWPSBjjtR4Qy
0qoSvFAova9ZcdGjlC8yNASt72nrITc8q7xHm5DVfoUB1GoBLXHUXukm2p47DA3D
s3gZPac+Rq4kqE4WgesYBYEHnza2XBclnoTw1Iz2nvPgjiQf2/6JUgNrR8Sd20ub
VvJBH5O5LwKBgQCvYbo4enWZwlcioRWxXtN8QA40dhmZ3QKBG6oiom6VxdLj3ekW
eFgd3Y8tqUnDfDM656PmkfeNBmgP83TsYKW5STsU2rhqM2uNiIralkx2K6Hbqy8e
gSDPOaCoRQQlP019UVWRYaOlbr3U8EYRqTkSyBzzbVerEUyw7NtnoB5gJwKBgQCM
WOkjrVBTUTcp6R9yM6DZRclBovRaTMUDCCysnfkObZc5BUIJnWnAUbQsoZ6kx4Gt
47imxI8qhnPkDdyXe2j9n6HXUnTp2N6/b7Pj9R1UwULBCeJnDo+Y8KoOfArSOKkY
sJoNnHlRBUTzWXgwfiWG44PLerxrOKNl9Kv/grmPSwKBgQC5dcH1uSjqjIEfvH3y
bUV73+wHlMBMU4LbfPbLZv32cGYSQpkQPX3KcAh48VFZT6YV+awbydoAaMTtMICg
V9jgHHnI99NQPhtzz7EKyjDEWp01DZwxGAPt0UPHWBv2Vf6i85YKYWJlh0Bm2gZM
sddYvhsoDdQ7IOCz4hUr2pbGXA==
";
    /// The SubjectPublicKeyInfo of that key, as openssl writes it.
    pub const RSA_2048_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApcIvjwwU44x782iYOh2gCDUZLjkwWr50lEh3MDN0abWSVGkkHFrnnOYOkXSovR08nWyMQx5cjxa/zNYlUZ+/ZvbhdNrOhmWI+m4OxDKg2KgmHByRHpcueG16m/UzQI0wilbank6F+7wxwicg2UsDVK6NSZ3QDp9TuPv2nclNtQNgnU0MZT/+cbyjGYpfCQGRgeDNsVlelTZAQDBcj6tCaUpJGDbemltFeWu0r6Q98+FCT6gyE6U9+Mz0d+tHB+0hub4ej3Ey+IB5pFEfnX1/PJTVKiYELu9wnsHHvkBHICtGNOlEMHMA491qDqehbvGWayFZbcWpLhvOEeAlGeTNxQIDAQAB";
    /// PKCS#8 DER of a 1024-bit test-only key: too short to be taken.
    const RSA_1024: &str = "
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAN0NIdqcdTpSRXQt
eCuKeKEQTTGnwSy/tbGXe53bUD4+ARQjjd9PjUiCyVdVRuq9wSvB8CXupnapy3hp
3JQUuuhoMaoMebULfwcMYZyXgjD6ijSVTz29pn6qGuXhuK8cdvObgsDbzoiDV1yh
/uZWL99oFY4O5VJMnLuit8R/Bc9bAgMBAAECgYEAwv+zrpq4mxM6a6s0yAwmL8cm
obgfo+8WRCyigvWWCuI9p1tZ6vXNZ3rgTGdQ4QE1p/k0dPHa7PEKKhYQ3JyQ55GH
Z/macAm0xpNA8vn069cj0erTL1KllEULViPco3cVGIW7V1rVk9DVReNMV95O6RNE
YQGMnvwteim8JLs3iXECQQD9IbAA34AmIBs1SATR1eCPgY4dSA9rl3YwL1uFagI2
hwhPJ8skRRtfZzqcjbsT6OGfN9L3YFesei3rzeC/VQcZAkEA345h8y8ldqk39Whk
zjTZooX/8+8QpPUBWmhBmP/asu6kI9NnJ4psmAqnYiJCkd5Qg3Mfs84udh6RGd3J
IUwckwJBAJ/scaMLkY4EyMvP1WOxCXAA/QVY6o0iIwRsVxkiEYXbqA9CZ+BhXNrY
gDo6fRAmGK2b+khZ8OpCQtLwvmaDVLkCQB5+4cW2rLmfI88KSpYGh5mwBdZUykR2
V5Tpm+kvHbpC64knkW7HZ0DmUycD3WjglsMXtT9l5NigGtMYehNcupkCQFwDJCAF
UMrQ+y9LDqrpuWrQ38emiDtIr3epyJJARdnJd49fbuFEnX/aHbrRdPDsgnOO1YpP
BbLBwvPZrZe6sNE=
";

    /// `der` (base64, any whitespace) armoured as PEM under `label`.
    pub fn pem(label: &str, der: &str) -> String {
        let body: String = der.split_whitespace().collect();
        let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        let dashes = "-----";
        format!("{dashes}BEGIN {label}{dashes}\n{}\n{dashes}END {label}{dashes}\n", lines.join("\n"))
    }

    /// The 2048-bit test-only key as PKCS#8 PEM.
    pub fn rsa_2048() -> String {
        pem(super::PEM_LABEL, RSA_2048)
    }

    /// The 1024-bit test-only key as PKCS#8 PEM.
    pub fn rsa_1024() -> String {
        pem(super::PEM_LABEL, RSA_1024)
    }

    /// The 2048-bit key's public half, PKCS#1 (what ring verifies with).
    pub fn rsa_2048_public() -> Vec<u8> {
        let key = super::DkimKey::new("example.com", "fucf", &rsa_2048()).unwrap();
        key.key_pair().unwrap().public().as_ref().to_vec()
    }

    /// The 2048-bit key's DER, base64 on one line (to look for it in output).
    pub fn rsa_2048_b64() -> String {
        RSA_2048.split_whitespace().collect()
    }
}

/// A verifier for these tests, apart from the signing code where it can be:
/// it reads the DKIM-Signature field of `message` as a receiver would and
/// checks it with the PKCS#1 public key `public_key`.
#[cfg(test)]
pub fn verify(message: &[u8], public_key: &[u8]) -> Result<(), String> {
    let (fields, body) = split(message);
    let at = fields.iter().position(|f| field_name(f).as_deref() == Some("dkim-signature")).ok_or("no DKIM-Signature")?;
    let raw = fields[at];
    let value = String::from_utf8(unfold(&raw[raw.iter().position(|&b| b == b':').unwrap() + 1..])).map_err(|e| e.to_string())?;
    let tags: std::collections::HashMap<String, String> = value
        .split(';')
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.chars().filter(|c| !c.is_whitespace()).collect()))
        .collect();
    let tag = |k: &str| tags.get(k).cloned().ok_or(format!("no {k}= tag"));
    if (tag("v")?, tag("a")?, tag("c")?) != ("1".into(), "rsa-sha256".into(), "relaxed/relaxed".into()) {
        return Err(format!("unexpected v/a/c tags: {tags:?}"));
    }
    let body_hash = b64(ring::digest::digest(&ring::digest::SHA256, &relaxed_body(body)).as_ref());
    if body_hash != tag("bh")? {
        return Err("body hash mismatch".into());
    }
    let mut data = Vec::new();
    let mut used = vec![false; fields.len()];
    used[at] = true;
    for name in tag("h")?.split(':') {
        let name = name.to_ascii_lowercase();
        if let Some(i) = (0..fields.len()).rev().find(|&i| !used[i] && field_name(fields[i]).as_deref() == Some(name.as_str())) {
            used[i] = true;
            data.extend(relaxed_header(fields[i]).unwrap());
        }
    }
    // the signature field itself, with the value of b= taken out
    let without_b = regex::bytes::Regex::new(r";(\s*)b(\s*)=[^;]*").unwrap().replace(raw, &b";${1}b${2}="[..]);
    let canonical = relaxed_header(&without_b).unwrap();
    data.extend_from_slice(canonical.strip_suffix(b"\r\n").unwrap());
    let signature = base64::engine::general_purpose::STANDARD.decode(tag("b")?).map_err(|e| e.to_string())?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, public_key)
        .verify(&data, &signature)
        .map_err(|_| "bad signature".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{rec, temp_store};

    const NOW: u64 = 1_790_000_000;

    fn key() -> DkimKey {
        DkimKey::new("example.com", "fucf", &test_keys::rsa_2048()).unwrap()
    }

    fn public_key() -> Vec<u8> {
        test_keys::rsa_2048_public()
    }

    fn sign(message: &[u8]) -> Vec<u8> {
        key().signer("example.com").unwrap().sign(message, NOW).unwrap()
    }

    /// The signature header field at the top of a signed message, unfolded.
    fn signature_of(signed: &[u8]) -> String {
        let (fields, _) = split(signed);
        String::from_utf8(unfold(fields[0])).unwrap()
    }

    const MESSAGE: &str = "Received: from sender.example by mx.example.com; Mon, 1 Dec 2026 10:00:00 +0000\r\n\
        From: Alice <alice@sender.example>\r\n\
        To: hello@example.com\r\n\
        Subject: Quarterly\r\n  numbers\r\n\
        Date: Mon, 1 Dec 2026 10:00:00 +0000\r\n\
        Message-ID: <1@sender.example>\r\n\
        \r\n\
        Hello,\r\n\r\nthe numbers are in.  \r\n\r\n\r\n";

    #[test]
    fn relaxed_header_canonicalization_gives_the_rfc_6376_example() {
        // RFC 6376 3.4.5: "A: X", "B : Y<HTAB>" folded onto "<HTAB>Z<SP><SP>"
        let (fields, _) = split(b"A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n");
        let canonical: Vec<u8> = fields.iter().flat_map(|f| relaxed_header(f).unwrap()).collect();
        assert_eq!(canonical, b"a:X\r\nb:Y Z\r\n");
        assert_eq!(relaxed_header(b"no colon here\r\n"), None);
        assert_eq!(relaxed_header(b"Empty:\r\n").unwrap(), b"empty:\r\n");
        assert_eq!(relaxed_header(b"X-Many: \t a \t\t b \t \r\n").unwrap(), b"x-many:a b\r\n");
        assert_eq!(relaxed_header(b"Subject: a\r\n b\r\n\tc").unwrap(), b"subject:a b c\r\n", "folds become single spaces, with or without a final CRLF");
        assert_eq!(relaxed_header(b"Subject: a\n b\n").unwrap(), b"subject:a b\r\n", "bare LF folds too");
        assert_eq!(relaxed_header(b"Subject: a\rb\r\n").unwrap(), b"subject:a\rb\r\n", "a lone CR is not a line end");
    }

    #[test]
    fn relaxed_body_canonicalization_gives_the_rfc_6376_example() {
        let (_, body) = split(b"A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n");
        assert_eq!(body, b" C \r\nD \t E\r\n\r\n\r\n");
        assert_eq!(relaxed_body(body), b" C\r\nD E\r\n");
    }

    #[test]
    fn an_empty_body_hashes_as_the_empty_string() {
        // RFC 6376 3.4.4: an empty body stays empty under relaxed (the
        // SHA-256 of nothing), as do bodies of only blank or white lines
        let empty_hash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        for body in [&b""[..], b"\r\n", b"\r\n\r\n\r\n", b" \t \r\n\t\r\n", b"\n\n"] {
            assert_eq!(relaxed_body(body), b"", "{body:?}");
            assert_eq!(b64(ring::digest::digest(&ring::digest::SHA256, &relaxed_body(body)).as_ref()), empty_hash);
        }
        // a message with no body at all, and one with no empty line after its header
        for message in [&b"From: a@sender.example\r\n\r\n"[..], b"From: a@sender.example\r\n", b"From: a@sender.example"] {
            let signed = sign(message);
            assert!(signature_of(&signed).contains(&format!("bh={empty_hash}")), "{message:?}");
            verify(&signed, &public_key()).unwrap();
        }
    }

    #[test]
    fn trailing_blank_lines_and_whitespace_do_not_change_the_body() {
        assert_eq!(relaxed_body(b"text\r\n"), b"text\r\n");
        assert_eq!(relaxed_body(b"text\r\n\r\n\r\n \r\n"), b"text\r\n");
        assert_eq!(relaxed_body(b"text   \t\r\n"), b"text\r\n");
        assert_eq!(relaxed_body(b"text"), b"text\r\n", "a body without a final line end gets one");
        assert_eq!(relaxed_body(b"a\r\n\r\n\r\nb\r\n"), b"a\r\n\r\n\r\nb\r\n", "blank lines inside stay");
        assert_eq!(relaxed_body(b"\tindented  twice\r\n"), b" indented twice\r\n", "leading whitespace becomes one space");
        let signed = sign(b"From: a@sender.example\r\n\r\nbody\r\n");
        let padded = [&signed[..], b"\r\n\r\n  \r\n"].concat();
        verify(&padded, &public_key()).unwrap();
    }

    #[test]
    fn lf_and_crlf_line_ends_canonicalize_alike() {
        let crlf = MESSAGE.as_bytes();
        let lf = MESSAGE.replace("\r\n", "\n");
        let (crlf_fields, crlf_body) = split(crlf);
        let (lf_fields, lf_body) = split(lf.as_bytes());
        assert_eq!(crlf_fields.len(), 6);
        assert_eq!(lf_fields.len(), 6);
        for (a, b) in crlf_fields.iter().zip(&lf_fields) {
            assert_eq!(relaxed_header(a), relaxed_header(b));
        }
        assert_eq!(relaxed_body(crlf_body), relaxed_body(lf_body));
        // signed with bare LFs, it verifies once a receiver turned them into CRLF
        let signed = sign(lf.as_bytes());
        let received = String::from_utf8(signed).unwrap().replace("\r\n", "\n").replace('\n', "\r\n");
        verify(received.as_bytes(), &public_key()).unwrap();
        assert_eq!(sign(crlf), sign(crlf), "the same message at the same time signs the same (PKCS#1 v1.5 is deterministic)");
    }

    #[test]
    fn a_signed_message_verifies_with_ring() {
        let signed = sign(MESSAGE.as_bytes());
        verify(&signed, &public_key()).unwrap();
        let header = signature_of(&signed);
        assert!(header.starts_with("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=fucf;"), "{header}");
        assert!(header.contains(&format!("t={NOW};")), "{header}");
        let h: String = header.split("h=").nth(1).unwrap().split(';').next().unwrap().split_whitespace().collect();
        assert_eq!(h, "from:to:subject:date:message-id:from", "the fields present, From once more; Received is not signed");
        // the message after the new field is the one given, byte for byte
        assert!(signed.ends_with(MESSAGE.as_bytes()));
        assert_eq!(signed.len() - MESSAGE.len(), split(&signed).0[0].len());
        // and verification is not a formality: a changed signature does not do
        let text = String::from_utf8(signed.clone()).unwrap();
        let mut b = text.find(" b=").or_else(|| text.find("\tb=")).unwrap() + 3;
        while text[b..].starts_with(char::is_whitespace) {
            b += 1;
        }
        let flipped = format!("{}{}{}", &text[..b], if &text[b..b + 1] == "A" { "B" } else { "A" }, &text[b + 1..]);
        assert_eq!(verify(flipped.as_bytes(), &public_key()).unwrap_err(), "bad signature");
    }

    #[test]
    fn changes_after_signing_break_the_signature_and_others_do_not() {
        let signed = String::from_utf8(sign(MESSAGE.as_bytes())).unwrap();
        let ok = |m: &str| verify(m.as_bytes(), &public_key());
        assert!(ok(&signed.replace("the numbers are in.", "the numbers are out.")).is_err(), "body");
        assert!(ok(&signed.replace("Subject: Quarterly", "Subject: Urgent")).is_err(), "a signed field");
        assert!(ok(&signed.replace("Message-ID: <1@", "Message-ID: <2@")).is_err());
        let added = |field: &str| signed.replacen("\r\n\r\n", &format!("\r\n{field}\r\n\r\n"), 1);
        assert!(ok(&added("From: mallory@evil.example")).is_err(), "From is signed once more than it is there");
        assert!(ok(&added("Subject: another")).is_err(), "a second Subject at the bottom is the one a verifier takes");
        ok(&added("X-Added-Later: by a list")).unwrap();
        // the relaxed forms do not mind refolding or another spelling of whitespace or case
        ok(&signed.replace("Subject: Quarterly\r\n  numbers", "SUBJECT:Quarterly\r\n\tnumbers   ")).unwrap();
        ok(&signed.replace("the numbers are in.  ", "the  numbers\tare in.")).unwrap();
        // a received field above the signature does not matter either
        ok(&format!("Received: by mx.example.net\r\n{signed}")).unwrap();
    }

    #[test]
    fn repeated_and_folded_fields_are_signed_bottom_up() {
        let message = "From: a@sender.example\r\nTo: one@example.com\r\nX-Note: x\r\nTo: two@example.com,\r\n\tthree@example.com\r\n\r\nhi\r\n";
        let signed = String::from_utf8(sign(message.as_bytes())).unwrap();
        verify(signed.as_bytes(), &public_key()).unwrap();
        let h: String = signature_of(signed.as_bytes()).split("h=").nth(1).unwrap().split(';').next().unwrap().split_whitespace().collect();
        assert_eq!(h, "from:to:to:from");
        // swapping the two To fields changes which one is signed where
        let swapped = signed.replace("To: one@example.com", "To: tmp").replace("To: two@example.com,\r\n\tthree@example.com", "To: one@example.com").replace("To: tmp", "To: two@example.com,\r\n\tthree@example.com");
        assert!(verify(swapped.as_bytes(), &public_key()).is_err());
    }

    #[test]
    fn fields_that_are_missing_are_left_out_of_the_signature() {
        let signed = sign(b"From: a@sender.example\r\n\r\nhi\r\n");
        verify(&signed, &public_key()).unwrap();
        let h: String = signature_of(&signed).split("h=").nth(1).unwrap().split(';').next().unwrap().split_whitespace().collect();
        assert_eq!(h, "from:from");
        // every field it knows, when all are there: h= folds and still verifies
        let all: String = SIGNED.iter().map(|n| format!("{n}: value of {n}\r\n")).collect();
        let signed = sign(format!("{all}\r\nbody\r\n").as_bytes());
        verify(&signed, &public_key()).unwrap();
        let h: String = signature_of(&signed).split("h=").nth(1).unwrap().split(';').next().unwrap().split_whitespace().collect();
        assert_eq!(h, format!("{}:from", SIGNED.join(":")));
    }

    #[test]
    fn mail_without_exactly_one_from_is_not_signed() {
        let signer = key().signer("example.com").unwrap();
        assert_eq!(signer.sign(b"To: b@example.com\r\n\r\nhi\r\n", NOW).unwrap_err(), "the message has no From header field");
        assert_eq!(signer.sign(b"", NOW).unwrap_err(), "the message has no From header field");
        assert_eq!(signer.sign(b"\r\nFrom: a@sender.example\r\n", NOW).unwrap_err(), "the message has no From header field", "a From in the body is not one");
        assert_eq!(signer.sign(b"From: a@sender.example\r\nfrom : b@sender.example\r\n\r\n", NOW).unwrap_err(), "the message has more than one From header field");
        signer.sign(b"X-From: a@sender.example\r\nFrom: a@sender.example\r\n\r\n", NOW).unwrap();
    }

    #[test]
    fn the_signature_field_keeps_its_lines_short() {
        let all: String = SIGNED.iter().map(|n| format!("{n}: v\r\n")).collect();
        for message in [MESSAGE.to_string(), format!("{all}\r\n")] {
            let signed = sign(message.as_bytes());
            let (fields, _) = split(&signed);
            let header = std::str::from_utf8(fields[0]).unwrap();
            assert!(header.starts_with("DKIM-Signature: ") && header.ends_with("\r\n"), "{header}");
            let lines: Vec<&str> = header.trim_end_matches("\r\n").split("\r\n").collect();
            assert!(lines.len() > 2, "{header}");
            for (i, line) in lines.iter().enumerate() {
                assert!(line.len() <= LINE, "line {i} is {} long: {line}", line.len());
                assert!(!line.contains('\n') && !line.contains('\r'));
                assert_eq!(i > 0, line.starts_with('\t'), "{line}");
                assert!(!line.ends_with([' ', '\t']), "no whitespace before a line end: {line:?}");
            }
            assert!(signed.ends_with(message.as_bytes()));
        }
    }

    #[test]
    fn the_public_key_is_published_as_subject_public_key_info() {
        assert_eq!(der_length(0), [0]);
        assert_eq!(der_length(127), [127]);
        assert_eq!(der_length(128), [0x81, 128]);
        assert_eq!(der_length(255), [0x81, 255]);
        assert_eq!(der_length(256), [0x82, 1, 0]);
        assert_eq!(der_length(0x1_0000), [0x83, 1, 0, 0]);
        let (name, content, bits) = key().record("example.com").unwrap();
        assert_eq!(name, "fucf._domainkey.example.com");
        assert_eq!(content, format!("v=DKIM1; k=rsa; p={}", test_keys::RSA_2048_SPKI), "the same bytes openssl writes");
        assert_eq!(bits, 2048);
        // and the key inside is the one that verifies
        let spki = base64::engine::general_purpose::STANDARD.decode(test_keys::RSA_2048_SPKI).unwrap();
        assert!(spki.ends_with(&public_key()));
        assert_eq!(subject_public_key_info(&public_key()), spki);
        let short = subject_public_key_info(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(short, [&[0x30, 0x17][..], RSA_ALGORITHM, &[0x03, 0x06, 0x00, 0x30, 0x03, 0x02, 0x01, 0x05]].concat());
    }

    #[test]
    fn selectors_are_dns_names() {
        for (given, stored) in [("fucf", "fucf"), ("Mail2026", "mail2026"), (" s1 ", "s1"), ("a-b.c-d", "a-b.c-d"), ("0", "0")] {
            assert_eq!(check_selector("example.com", given).as_deref(), Ok(stored));
        }
        let long_label = "a".repeat(64);
        for bad in ["", " ", "-a", "a-", "a_b", "a..b", ".a", "a.", "a b", "a;b", "a=b", "sél", "a/b", long_label.as_str()] {
            assert!(check_selector("example.com", bad).is_err(), "{bad:?}");
        }
        assert!(check_selector("example.com", &"a".repeat(63)).is_ok());
        let zone = format!("{}.example.com", ["b".repeat(63), "c".repeat(63), "d".repeat(50)].join("."));
        assert!(check_selector(&zone, &"a".repeat(63)).unwrap_err().contains("253"));
        assert!(DkimKey::new("example.com", "bad_selector", &test_keys::rsa_2048()).is_err());
    }

    #[test]
    fn private_keys_are_unencrypted_rsa_pkcs8_of_at_least_2048_bits() {
        let new = |pem: &str| DkimKey::new("example.com", "fucf", pem);
        let rng = ring::rand::SystemRandom::new();
        let ec = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let ed = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let der = test_keys::rsa_2048_b64();
        let cases = [
            (String::new(), "not a PEM private key"),
            ("garbage".to_string(), "not a PEM private key"),
            ("***".to_string(), "not a PEM private key"),
            (der.clone(), "not a PEM private key"),
            (test_keys::pem("RSA PRIVATE KEY", &der), "PKCS#1"),
            (test_keys::pem("ENCRYPTED PRIVATE KEY", &der), "encrypted"),
            (test_keys::pem("CERTIFICATE", &der), "not a PEM private key"),
            (test_keys::pem(PEM_LABEL, &der[..der.len() - 40]), "not a"),
            (test_keys::pem(PEM_LABEL, &der.replace('A', "*")), "not a PEM private key"),
            (test_keys::pem(PEM_LABEL, "AAAA"), "not a valid RSA private key"),
            (test_keys::rsa_1024(), "at least 2048 bits"),
            (test_keys::pem(PEM_LABEL, &b64(ec.as_ref())), "not an RSA key"),
            (test_keys::pem(PEM_LABEL, &b64(ed.as_ref())), "not an RSA key"),
            (format!("{}\n{}", "x".repeat(MAX_PEM), test_keys::rsa_2048()), "too long"),
        ];
        for (pem, says) in cases {
            let err = new(&pem).unwrap_err();
            assert!(err.contains(says), "{says}: {err}");
            assert!(!err.contains(&der[100..120]), "an error never repeats the key: {err}");
        }
        // pasted with other things around it, indented, or with CRLF: the key alone is kept
        let messy = format!("a comment\r\n{}{}", test_keys::pem("CERTIFICATE", "AAAA").replace('\n', "\r\n"), test_keys::rsa_2048().lines().map(|l| format!("    {l}\r\n")).collect::<String>());
        assert_eq!(new(&messy).unwrap(), key());
        assert_eq!(key().private_key, test_keys::rsa_2048(), "stored armoured afresh, 64 characters to a line");
    }

    #[test]
    fn the_key_never_shows_in_debug_output() {
        let key = key();
        let shown = format!("{key:?}");
        assert!(shown.contains("fucf") && shown.contains("redacted"), "{shown}");
        assert!(!shown.contains(&test_keys::rsa_2048_b64()[60..90]) && !shown.contains(PEM_LABEL), "{shown}");
    }

    fn zone_with_key(store: &Store) -> Zone {
        let zone = store.create_zone("example.com").unwrap();
        let body = json!({ "dkim_selector": "fucf", "dkim_private_key": test_keys::rsa_2048() });
        tokio::runtime::Runtime::new().unwrap().block_on(patch(store, &zone.id, &body)).unwrap();
        store.get_zone(&zone.id).unwrap()
    }

    #[test]
    fn an_unconfigured_zone_passes_mail_on_byte_for_byte() {
        let store = temp_store();
        let plain = store.create_zone("example.net").unwrap();
        assert!(plain.email_dkim.is_none());
        let messages: [&[u8]; 4] = [MESSAGE.as_bytes(), b"", b"From: a@sender.example\n\nbare LF\n", &[0xff, 0x00, b'\r', b'\n', 0x80]];
        for message in messages {
            for zone in ["example.net", "not-a-zone.example", ""] {
                let out = sign_forwarded(&store.snapshot(), zone, message, NOW);
                assert!(matches!(out, Cow::Borrowed(_)), "{zone}");
                assert_eq!(&out[..], message);
            }
        }
        // a configured zone signs, and only the new field is in front
        zone_with_key(&store);
        let out = sign_forwarded(&store.snapshot(), "example.com", MESSAGE.as_bytes(), NOW);
        assert!(matches!(out, Cow::Owned(_)) && out.starts_with(b"DKIM-Signature: ") && out.ends_with(MESSAGE.as_bytes()));
        verify(&out, &public_key()).unwrap();
        // what it cannot sign goes on as it came
        for message in [&b"To: b@example.com\r\n\r\nno From\r\n"[..], b"From: a@sender.example\r\nFrom: b@sender.example\r\n\r\n"] {
            let out = sign_forwarded(&store.snapshot(), "example.com", message, NOW);
            assert!(matches!(out, Cow::Borrowed(_)));
            assert_eq!(&out[..], message);
        }
    }

    #[test]
    fn a_key_that_no_longer_reads_lets_mail_through_unsigned() {
        let store = temp_store();
        let zone = zone_with_key(&store);
        let broken = DkimKey { selector: "fucf".into(), private_key: "garbage".into() };
        tokio::runtime::Runtime::new().unwrap().block_on(store.set_email_dkim_async(&zone.id, move |_| Ok(Some(broken)))).unwrap();
        let out = sign_forwarded(&store.snapshot(), "example.com", MESSAGE.as_bytes(), NOW);
        assert_eq!(&out[..], MESSAGE.as_bytes());
        let (v, needed) = view(&store.get_zone(&zone.id).unwrap(), &[]);
        assert_eq!((v["dkim_selector"].clone(), v["has_dkim_private_key"].clone(), v["dkim_record"].clone()), (json!("fucf"), json!(true), Value::Null));
        assert!(v["dkim_error"].as_str().unwrap().contains("not a PEM private key") && needed.is_none());
    }

    #[tokio::test]
    async fn a_patch_sets_keeps_and_removes_the_key() {
        let store = temp_store();
        let zone = store.create_zone("example.com").unwrap();
        let other = store.create_zone("example.net").unwrap();
        let z = zone.id.as_str();
        let dkim = |id: &str| store.get_zone(id).unwrap().email_dkim;
        let refused = |r: Result<(), StoreError>| match r {
            Err(StoreError::Invalid(m)) => m,
            other => panic!("expected invalid, got {other:?}"),
        };

        // nothing to change, nothing set: no key appears
        patch(&store, z, &json!({})).await.unwrap();
        patch(&store, z, &json!({ "dkim_selector": null, "enabled": true })).await.unwrap();
        assert!(dkim(z).is_none());
        assert!(refused(patch(&store, z, &json!({ "dkim_selector": "fucf" })).await).contains("dkim_private_key is required"));
        assert!(refused(patch(&store, z, &json!({ "dkim_private_key": test_keys::rsa_2048() })).await).contains("dkim_selector is required"));
        assert!(refused(patch(&store, z, &json!({ "dkim_selector": "", "dkim_private_key": test_keys::rsa_2048() })).await).contains("needs a dkim_selector"));
        assert!(refused(patch(&store, z, &json!({ "dkim_selector": 7 })).await).contains("is a string"));
        assert!(refused(patch(&store, z, &json!({ "dkim_selector": "fucf", "dkim_private_key": ["x"] })).await).contains("is a string"));
        assert!(refused(patch(&store, z, &json!("fucf")).await).contains("JSON object"));
        assert!(matches!(patch(&store, "no-such-zone", &json!({ "dkim_selector": "fucf" })).await, Err(StoreError::ZoneNotFound)));
        assert!(matches!(patch(&store, "no-such-zone", &json!({})).await, Err(StoreError::ZoneNotFound)));
        assert!(dkim(z).is_none());

        // set
        patch(&store, z, &json!({ "dkim_selector": "FUCF", "dkim_private_key": test_keys::rsa_2048() })).await.unwrap();
        assert_eq!(dkim(z), Some(key()));
        assert!(dkim(&other.id).is_none(), "the other zone is untouched");
        // what the API answers, sent back as it is, keeps the key
        let records = store.list_records(z).unwrap().1;
        let (answered, _) = view(&store.get_zone(z).unwrap(), &records);
        patch(&store, z, &Value::Object(answered)).await.unwrap();
        assert_eq!(dkim(z), Some(key()));
        for kept in [json!({ "dkim_selector": "fucf", "dkim_private_key": "" }), json!({ "dkim_selector": "fucf", "dkim_private_key": null }), json!({ "dkim_private_key": " " })] {
            patch(&store, z, &kept).await.unwrap();
            assert_eq!(dkim(z), Some(key()), "{kept}");
        }
        // a new selector keeps the key; a bad one changes nothing
        patch(&store, z, &json!({ "dkim_selector": "s2" })).await.unwrap();
        assert_eq!(dkim(z).unwrap().selector, "s2");
        assert_eq!(dkim(z).unwrap().private_key, key().private_key);
        assert!(refused(patch(&store, z, &json!({ "dkim_selector": "not ok" })).await).contains("DNS name"));
        // a mask or garbage in place of the key is refused, and the stored key stays
        let short = test_keys::rsa_1024();
        for bad in ["***", "garbage", short.as_str()] {
            refused(patch(&store, z, &json!({ "dkim_selector": "s2", "dkim_private_key": bad })).await);
            assert_eq!(dkim(z).unwrap().private_key, key().private_key);
        }
        // removed
        patch(&store, z, &json!({ "dkim_selector": "" })).await.unwrap();
        assert!(dkim(z).is_none());
        patch(&store, z, &json!({ "dkim_selector": "fucf", "dkim_private_key": test_keys::rsa_2048() })).await.unwrap();
        patch(&store, z, &json!({ "dkim_selector": null })).await.unwrap();
        assert!(dkim(z).is_none());
        assert!(refused(patch(&store, z, &json!({ "dkim_selector": "fucf" })).await).contains("dkim_private_key is required"), "a removed key is gone");
    }

    #[test]
    fn the_view_shows_the_record_to_publish_but_never_the_key() {
        let store = temp_store();
        let zone = store.create_zone("example.net").unwrap();
        let (v, needed) = view(&zone, &[]);
        assert_eq!(Value::Object(v), json!({ "dkim_selector": null, "has_dkim_private_key": false, "dkim_record": null, "dkim_key_bits": null, "dkim_published": false, "dkim_error": null }));
        assert!(needed.is_none());

        let zone = zone_with_key(&store);
        let (v, needed) = view(&zone, &store.list_records(&zone.id).unwrap().1);
        let text = Value::Object(v.clone()).to_string();
        assert!(!text.contains(&test_keys::rsa_2048_b64()[200..240]) && !text.contains(PEM_LABEL) && !text.contains("private_key\":\""), "{text}");
        let record = json!({ "type": "TXT", "name": "fucf._domainkey.example.com", "content": format!("v=DKIM1; k=rsa; p={}", test_keys::RSA_2048_SPKI) });
        assert_eq!((v["dkim_selector"].clone(), v["has_dkim_private_key"].clone(), v["dkim_key_bits"].clone()), (json!("fucf"), json!(true), json!(2048)));
        assert_eq!((v["dkim_record"].clone(), v["dkim_published"].clone(), needed.clone()), (record.clone(), json!(false), Some(record.clone())));

        // published as it is shown, or as quoted strings of at most 255: found
        let p = test_keys::RSA_2048_SPKI;
        for content in [format!("v=DKIM1; k=rsa; p={p}"), format!("\"v=DKIM1; k=rsa; p={}\" \"{}\"", &p[..200], &p[200..]), format!("v=DKIM1;p={} {}", &p[..10], &p[10..])] {
            let s = temp_store();
            let z = zone_with_key(&s);
            s.create_record(&z.id, rec("fucf._domainkey", "TXT", &content)).unwrap();
            let (v, needed) = view(&z, &s.list_records(&z.id).unwrap().1);
            assert_eq!((v["dkim_published"].clone(), needed), (json!(true), None), "{content}");
        }
        // another key, another name or another type: not found
        for (name, rtype, content) in [("fucf._domainkey", "TXT", "v=DKIM1; k=rsa; p=AAAA"), ("other._domainkey", "TXT", record["content"].as_str().unwrap()), ("fucf._domainkey", "TXT", "v=DKIM1; k=rsa"), ("fucf._domainkey", "CNAME", "fucf.dkim.example.net")] {
            let s = temp_store();
            let z = zone_with_key(&s);
            s.create_record(&z.id, rec(name, rtype, content)).unwrap();
            let (v, needed) = view(&z, &s.list_records(&z.id).unwrap().1);
            assert_eq!((v["dkim_published"].clone(), needed.is_some()), (json!(false), true), "{name} {rtype} {content}");
        }
    }
}
