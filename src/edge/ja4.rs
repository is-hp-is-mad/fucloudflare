//! The JA4 fingerprint of a visitor's TLS ClientHello: which protocol version,
//! cipher suites, extensions and signature algorithms its TLS library offers.
//! Browsers, command line tools and attack tools differ in it whatever
//! User-Agent they send; rules can match it (`fcf.ja4`).
//!
//! Read from the first bytes of the connection without taking them (the TLS
//! library that then does the handshake does not show the extensions).

use std::time::Duration;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Values clients put in at random to keep servers tolerant (RFC 8701).
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn hash12(text: &str) -> String {
    if text.is_empty() {
        return "000000000000".into();
    }
    ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_list(values: &[u16]) -> String {
    values.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",")
}

/// The fingerprint of a ClientHello as it starts a connection (a TLS record).
pub fn of(raw: &[u8]) -> Option<String> {
    let mut r = Reader(raw);
    if r.u8()? != 22 {
        return None;
    }
    r.take(4)?;
    if r.u8()? != 1 {
        return None;
    }
    r.take(3)?;
    let mut version = r.u16()?;
    r.take(32)?;
    let session = r.u8()? as usize;
    r.take(session)?;
    let len = r.u16()? as usize;
    let mut ciphers: Vec<u16> = r.take(len)?.chunks_exact(2).map(|b| u16::from_be_bytes([b[0], b[1]])).filter(|v| !grease(*v)).collect();
    let compression = r.u8()? as usize;
    r.take(compression)?;
    let len = r.u16()? as usize;
    let mut ext = Reader(r.take(len)?);
    let (mut ids, mut sigs, mut sni, mut alpn) = (Vec::new(), Vec::new(), false, *b"00");
    while !ext.0.is_empty() {
        let (id, len) = (ext.u16()?, ext.u16()? as usize);
        let mut body = Reader(ext.take(len)?);
        if grease(id) {
            continue;
        }
        ids.push(id);
        match id {
            0x0000 => sni = true,
            0x0010 => {
                body.u16()?;
                let len = body.u8()? as usize;
                let first = body.take(len)?;
                if let (Some(a), Some(z)) = (first.first(), first.last()) {
                    alpn = if a.is_ascii_alphanumeric() && z.is_ascii_alphanumeric() { [*a, *z] } else { [b"0123456789abcdef"[usize::from(a >> 4)], b"0123456789abcdef"[usize::from(z & 0xf)]] };
                }
            }
            0x000d => {
                let len = body.u16()? as usize;
                sigs = body.take(len)?.chunks_exact(2).map(|b| u16::from_be_bytes([b[0], b[1]])).collect();
            }
            0x002b => {
                let len = body.u8()? as usize;
                let offered = body.take(len)?.chunks_exact(2).map(|b| u16::from_be_bytes([b[0], b[1]])).filter(|v| !grease(*v)).max();
                version = offered.unwrap_or(version);
            }
            _ => {}
        }
    }
    let version = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let head = format!("t{version}{}{:02}{:02}{}", if sni { 'd' } else { 'i' }, ciphers.len().min(99), ids.len().min(99), String::from_utf8_lossy(&alpn));
    ciphers.sort_unstable();
    // the extensions in order of their numbers, without the two that name the site and the protocol
    ids.retain(|id| !matches!(id, 0x0000 | 0x0010));
    ids.sort_unstable();
    let extensions = if sigs.is_empty() { hex_list(&ids) } else { format!("{}_{}", hex_list(&ids), hex_list(&sigs)) };
    Some(format!("{head}_{}_{}", hash12(&hex_list(&ciphers)), hash12(&extensions)))
}

/// The fingerprint of the ClientHello a connection starts with, left where it
/// is for the handshake; empty when it does not come whole and soon.
pub async fn peek(stream: &tokio::net::TcpStream) -> String {
    let mut buf = vec![0u8; 4096];
    for _ in 0..4 {
        let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), stream.peek(&mut buf)).await else { break };
        if n == 0 || buf[0] != 22 {
            break;
        }
        if n >= 5 && n >= (5 + usize::from(u16::from_be_bytes([buf[3], buf[4]]))).min(buf.len()) {
            return of(&buf[..n]).unwrap_or_default();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(ciphers: &[u16], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let list = |v: &[u16]| v.iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<u8>>();
        let ext: Vec<u8> = extensions.iter().flat_map(|(id, body)| [&id.to_be_bytes()[..], &(body.len() as u16).to_be_bytes(), body].concat()).collect();
        let c = list(ciphers);
        let body = [&[3, 3][..], &[7; 32], &[0], &(c.len() as u16).to_be_bytes(), &c, &[1, 0], &(ext.len() as u16).to_be_bytes(), &ext].concat();
        let handshake = [&[1, 0][..], &(body.len() as u16).to_be_bytes(), &body].concat();
        [&[22, 3, 1][..], &(handshake.len() as u16).to_be_bytes(), &handshake].concat()
    }

    #[test]
    fn tells_what_a_client_offers_whatever_the_order_and_the_grease() {
        let extensions = vec![
            (0x0a0a, vec![]),
            (0x0000, vec![0, 5, 0, 0, 2, b'a', b'b']),
            (0x002b, vec![4, 0x1a, 0x1a, 3, 4]),
            (0x0010, vec![0, 6, 2, b'h', b'2', 2, b'h', b'3']),
            (0x000d, vec![0, 4, 4, 3, 8, 4]),
            (0x000a, vec![0, 2, 0, 0x1d]),
        ];
        let got = of(&hello(&[0x1302, 0x2a2a, 0x1301], &extensions)).unwrap();
        assert_eq!(got, format!("t13d0205h2_{}_{}", hash12("1301,1302"), hash12("000a,000d,002b_0403,0804")));
        // without a server name, a protocol or TLS 1.3: by address, "00", the version of the hello itself
        let bare = of(&hello(&[0x002f], &[(0x000a, vec![0, 2, 0, 0x17])])).unwrap();
        assert_eq!(bare, format!("t12i010100_{}_{}", hash12("002f"), hash12("000a")));
        // not a ClientHello, or cut short
        let whole = hello(&[0x1301], &extensions);
        assert_eq!((of(b"GET / HTTP/1.1\r\n"), of(&whole[..whole.len() - 3]), of(&[])), (None, None, None));
    }
}
