//! Zone transfers to secondary name servers: AXFR over TCP (RFC 5936) for the
//! addresses a zone lists in `dns_transfer_to`, and a NOTIFY (RFC 1996) to
//! them when the zone changes. With a secondary at another provider the zone
//! keeps resolving when this whole fleet is gone.
//!
//! What a secondary gets hides the origins like our own answers do: a proxied
//! name is transferred with the addresses of every edge node (no steering
//! there). A zone signed here (online, per query) is not transferred.

use super::resolver::{soa, to_rr, Resolver};
use super::wire::{self, rcode, rtype, RData, Response, RR};
use crate::store::Store;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// An address, or a network as `address/prefix`.
fn network(entry: &str) -> Option<(IpAddr, u32)> {
    let (addr, prefix) = match entry.split_once('/') {
        Some((addr, prefix)) => (addr.parse::<IpAddr>().ok()?, Some(prefix.parse::<u32>().ok()?)),
        None => (entry.parse::<IpAddr>().ok()?, None),
    };
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(bits);
    (prefix <= bits).then_some((addr, prefix))
}

/// Is this an entry `dns_transfer_to` may hold?
pub fn valid(entry: &str) -> bool {
    network(entry).is_some()
}

/// Is `peer` one of the addresses or within one of the networks listed?
pub fn allowed(list: &[String], peer: IpAddr) -> bool {
    let peer = peer.to_canonical();
    list.iter().filter_map(|entry| network(entry)).any(|(net, prefix)| match (net, peer) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => prefix == 0 || (u32::from(net) ^ u32::from(ip)) >> (32 - prefix) == 0,
        (IpAddr::V6(net), IpAddr::V6(ip)) => prefix == 0 || (u128::from(net) ^ u128::from(ip)) >> (128 - prefix) == 0,
        _ => false,
    })
}

/// The answer to an AXFR query (None for any other message): the messages of
/// the transfer, or one that refuses it.
pub fn axfr(resolver: &Resolver, buf: &[u8], peer: IpAddr) -> Option<Vec<Vec<u8>>> {
    let q = wire::parse_query(buf).ok()?;
    if q.qtype != rtype::AXFR || q.flags & 0x8000 != 0 || (q.flags >> 11) & 0xF != 0 {
        return None;
    }
    let message = |answers: Vec<RR>, rcode: u16| {
        Response { id: q.id, query_flags: q.flags, rcode, aa: rcode == 0, question: Some((q.qname_raw.clone(), q.qtype, q.qclass)), answers, ..Default::default() }.encode(u16::MAX as usize)
    };
    let snap = resolver.store.snapshot();
    let zone = snap.zones.values().find(|z| z.zone.name == q.qname);
    let Some(z) = zone.filter(|z| q.qclass == 1 && z.dnssec.is_none() && allowed(&z.zone.settings.dns_transfer_to, peer)) else {
        return Some(vec![message(Vec::new(), rcode::REFUSED)]);
    };
    // the edge as a secondary can give it: every node (the nodes of this process's flags when none is configured)
    let nodes: Vec<_> = snap.nodes.iter().filter(|n| !n.role.eq_ignore_ascii_case("accelerate")).collect();
    let (v4, v6) = match nodes.is_empty() {
        true => (resolver.edge_v4.clone(), resolver.edge_v6.clone()),
        false => (nodes.iter().filter_map(|n| n.ipv4).collect(), nodes.iter().filter_map(|n| n.ipv6).collect()),
    };
    let mut rrs = vec![soa(z)];
    rrs.extend(z.zone.name_servers.iter().map(|ns| RR { name: z.zone.name.clone(), ttl: 86400, data: RData::Ns(ns.clone()) }));
    let mut owners: Vec<&String> = z.names.keys().collect();
    owners.sort();
    for owner in owners {
        let records = &z.names[owner];
        let proxied = !z.zone.paused && records.iter().any(|r| r.proxied);
        if proxied {
            rrs.extend(v4.iter().map(|ip| RR { name: owner.clone(), ttl: 300, data: RData::A(*ip) }));
            rrs.extend(v6.iter().map(|ip| RR { name: owner.clone(), ttl: 300, data: RData::Aaaa(*ip) }));
        }
        let shown = records.iter().filter(|r| !(proxied && matches!(r.rtype.as_str(), "A" | "AAAA" | "CNAME")));
        rrs.extend(shown.filter_map(|r| to_rr(r, owner)));
    }
    rrs.push(soa(z));
    let mut out = Vec::new();
    for chunk in rrs.chunks(40) {
        let together = message(chunk.to_vec(), 0);
        // (truncated: too much for one message; then one record each)
        if together[2] & 0x02 == 0 {
            out.push(together);
        } else {
            out.extend(chunk.iter().map(|rr| message(vec![rr.clone()], 0)));
        }
    }
    Some(out)
}

/// A NOTIFY for `zone` (opcode 4, authoritative, the question `zone SOA IN`).
fn notify_message(id: u16, zone: &str) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&[0x24, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    m.extend_from_slice(&wire::canonical_name(zone));
    m.extend_from_slice(&[0, 6, 0, 1]);
    m
}

/// Tell the secondaries of a zone (the single addresses of its
/// `dns_transfer_to`) when its serial changed, so they fetch it at once
/// instead of at their next refresh. Sent once, not waited for.
pub async fn notify(store: Arc<Store>) {
    let mut changed = store.subscribe();
    let mut serials: HashMap<String, u32> = store.snapshot().zones.values().map(|z| (z.zone.id.clone(), z.zone.serial)).collect();
    while changed.changed().await.is_ok() {
        // changes come in bursts
        tokio::time::sleep(Duration::from_secs(2)).await;
        let snap = store.snapshot();
        for z in snap.zones.values() {
            if serials.insert(z.zone.id.clone(), z.zone.serial) == Some(z.zone.serial) {
                continue;
            }
            for to in z.zone.settings.dns_transfer_to.iter().filter_map(|entry| entry.parse::<IpAddr>().ok()) {
                let Ok(sock) = tokio::net::UdpSocket::bind(if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await else { continue };
                let _ = sock.send_to(&notify_message(z.zone.serial as u16, &z.zone.name), (to, 53)).await;
            }
        }
        let live: HashSet<&String> = snap.zones.values().map(|z| &z.zone.id).collect();
        serials.retain(|id, _| live.contains(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::testutil::query;
    use crate::store::testutil::{rec, temp_store};
    use serde_json::json;

    #[test]
    fn a_listed_secondary_gets_the_zone_with_the_origins_hidden() {
        let store = temp_store();
        let zone = store.create_zone("example.com").unwrap();
        let (z, ns) = (zone.id, zone.name_servers.len() as u16);
        let mut app = rec("app", "A", "198.51.100.9");
        app.proxied = true;
        store.create_record(&z, app).unwrap();
        store.create_record(&z, rec("txt", "TXT", "hello")).unwrap();
        assert!(store.update_setting(&z, "dns_transfer_to", json!(["not an address"])).is_err());
        store.update_setting(&z, "dns_transfer_to", json!(["192.0.2.53", "2001:db8:53::/48"])).unwrap();
        let r = Resolver { store: Arc::new(store), edge_v4: vec!["203.0.113.10".parse().unwrap()], edge_v6: vec![], geo: Arc::default(), health: Arc::default(), cname_base: None, name_servers: vec![], h3_port: None, h3_front: None, edge_ttl: 60, flat: Arc::default(), limits: Arc::default(), accelerate: false, rtt: Arc::default() };
        let ask = query(7, "example.com", rtype::AXFR, false);
        let has = |m: &[u8], bytes: &[u8]| m.windows(bytes.len()).any(|w| w == bytes);
        // anybody else is refused, and so is a query that is no transfer left to the resolver
        let refused = axfr(&r, &ask, "192.0.2.99".parse().unwrap()).unwrap();
        assert_eq!((refused.len(), refused[0][3] & 0x0f), (1, rcode::REFUSED as u8));
        assert!(axfr(&r, &query(7, "example.com", rtype::A, false), "192.0.2.53".parse().unwrap()).is_none());
        for secondary in ["192.0.2.53", "2001:db8:53::1"] {
            let got = axfr(&r, &ask, secondary.parse().unwrap()).unwrap();
            assert_eq!(got.len(), 1, "{secondary}");
            let m = &got[0];
            // not truncated, authoritative; SOA, the zone's NS records, the proxied name as the edge, the text record, SOA
            assert_eq!((m[2] & 0x86, m[3] & 0x0f, u16::from_be_bytes([m[6], m[7]])), (0x84, 0, 4 + ns));
            assert!(has(m, &[203, 0, 113, 10]) && has(m, b"hello") && !has(m, &[198, 51, 100, 9]), "the origin's address stays here");
        }
        assert!(allowed(&["192.0.2.0/24".into()], "::ffff:192.0.2.7".parse().unwrap()) && !allowed(&["192.0.2.0/24".into()], "192.0.3.7".parse().unwrap()));
        assert!(valid("2001:db8::/32") && !valid("192.0.2.1/33") && !valid("example.com"));
    }

    #[test]
    fn a_notify_names_the_zone() {
        assert_eq!(notify_message(0x1234, "example.com"), [&[0x12, 0x34, 0x24, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7][..], b"example", &[3], b"com", &[0, 0, 6, 0, 1]].concat());
    }
}
