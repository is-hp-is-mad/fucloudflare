//! Response rate limiting over UDP: a source address there is whatever the
//! sender wrote, so an authoritative server that answers everything is a
//! tool for flooding others. Per network (/24, /56) and name asked for, only
//! so many answers go out per second; beyond that every second one goes out
//! truncated (a real resolver then asks again over TCP, where the address is
//! its own) and the rest is dropped.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};

/// Answers per second for one network and name; 0: no limit.
static PER_SECOND: AtomicU32 = AtomicU32::new(0);
static SENT: LazyLock<Mutex<HashMap<(u128, u64), (u64, u32)>>> = LazyLock::new(Default::default);

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Send,
    Truncate,
    Drop,
}

pub fn configure(per_second: u32) {
    PER_SECOND.store(per_second, Ordering::Relaxed);
}

/// What to do with `reply`, about to go to `peer` over UDP.
pub fn check(peer: IpAddr, reply: &[u8]) -> Verdict {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    check_at(now, PER_SECOND.load(Ordering::Relaxed), peer, reply)
}

fn check_at(now: u64, per_second: u32, peer: IpAddr, reply: &[u8]) -> Verdict {
    let peer = peer.to_canonical();
    if per_second == 0 || peer.is_loopback() {
        return Verdict::Send;
    }
    let network = match peer {
        IpAddr::V4(ip) => u128::from(u32::from(ip) >> 8),
        IpAddr::V6(ip) => (u128::from(ip) >> 72) | 1 << 127,
    };
    let name = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        question_end(reply).map(|end| reply[12..end - 4].to_ascii_lowercase()).hash(&mut hasher);
        hasher.finish()
    };
    let mut sent = SENT.lock().unwrap();
    if sent.len() > 200_000 {
        sent.retain(|_, (second, _)| *second == now);
    }
    let entry = sent.entry((network, name)).or_insert((now, 0));
    if entry.0 != now {
        *entry = (now, 0);
    }
    entry.1 = entry.1.saturating_add(1);
    match entry.1.checked_sub(per_second) {
        None | Some(0) => Verdict::Send,
        Some(over) if over % 2 == 1 => Verdict::Truncate,
        Some(_) => Verdict::Drop,
    }
}

/// Where the question of a message ends (it has one, uncompressed, after the header).
fn question_end(m: &[u8]) -> Option<usize> {
    if m.len() < 12 || m[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12;
    loop {
        let len = *m.get(at)? as usize;
        if len & 0xc0 != 0 {
            return None;
        }
        at += 1 + len;
        if len == 0 {
            break;
        }
    }
    (at + 4 <= m.len()).then_some(at + 4)
}

/// `reply` cut down to its header and question, marked as truncated.
pub fn truncated(reply: &[u8]) -> Option<Vec<u8>> {
    let mut short = reply[..question_end(reply)?].to_vec();
    short[2] |= 0x02;
    short[6..12].fill(0);
    Some(short)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::testutil::query;

    #[test]
    fn beyond_the_limit_half_the_answers_go_out_truncated_and_the_rest_not_at_all() {
        let reply = |name: &str| {
            let mut m = query(9, name, 1, false);
            m[2] |= 0x80;
            m[7] = 1;
            m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
            m
        };
        let (a, b) = (reply("limited.example.com"), reply("other.example.com"));
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        let verdicts: Vec<Verdict> = (0..7).map(|_| check_at(50, 3, peer, &a)).collect();
        assert_eq!(verdicts, [Verdict::Send, Verdict::Send, Verdict::Send, Verdict::Truncate, Verdict::Drop, Verdict::Truncate, Verdict::Drop]);
        // the same network counts as one, another name or network or second does not, nor this host
        assert_eq!(check_at(50, 3, "198.51.100.200".parse().unwrap(), &a), Verdict::Truncate);
        assert_eq!((check_at(50, 3, peer, &b), check_at(50, 3, "198.51.101.7".parse().unwrap(), &a), check_at(51, 3, peer, &a)), (Verdict::Send, Verdict::Send, Verdict::Send));
        assert_eq!((check_at(50, 0, peer, &a), check_at(50, 3, "127.0.0.1".parse().unwrap(), &a)), (Verdict::Send, Verdict::Send));
        // truncated: the header and the question, no records, TC set
        let short = truncated(&a).unwrap();
        assert_eq!((short.len(), short[2] & 0x02, &short[6..12], &short[..2]), (a.len() - 16, 0x02, &[0u8; 6][..], &a[..2]));
        assert_eq!(truncated(&[0; 5]), None);
    }
}
