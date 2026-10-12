//! Names on the overlay, answered by each node from what it already holds.
//!
//! A member is reachable at `<label>.<site>.internal` — `.internal` being the
//! top-level name set aside for private use, so nothing here can collide with a
//! public name. There is no DNS server for the site. Each node answers for the
//! zone from its own peer set: the members it decided to carry, with the
//! addresses it carries them on. A node cut off from everything else still
//! resolves every peer it holds, and a peer it does not hold does not resolve
//! on it, which is the same answer its tunnel would give.
//!
//! Two labels per member, for two different reasons:
//!
//! - **the id label**, derived from the node id. It is covered by the anchor's
//!   signature, so no member can claim another's. Always present.
//! - **the name it gives itself**, such as its host name. What people type,
//!   and self-asserted — so a name two members claim resolves under neither,
//!   and the clash is reported. Resolving it to either would let one machine
//!   take traffic meant for another by choosing a host name.
//!
//! An entry stops resolving when the authorization it was admitted on runs
//! out, even while the tunnel is retained as last known good: keeping a
//! session alive through a coordinator outage is a different decision from
//! continuing to vouch for a name past the date somebody signed.
//!
//! The answering side is deliberately small: one question, A and AAAA, the
//! site's zone only. A query for anything else is refused rather than
//! forwarded — the system resolver routes only this zone here, and a resolver
//! that forwarded would be one more thing on the node that talks to the world.

use crate::overlay::Peer;
use crate::roster::{dns_label, id_label};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Top-level name reserved for private use.
pub const TLD: &str = "internal";

/// Upper bound on what a resolver may cache an answer for. Short, because the
/// answer is "what this node holds now" and lapses on a signed date.
pub const MAX_TTL: u32 = 30;

/// One name's addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
    /// When this stops resolving. `None`: held on an unlocked overlay, which
    /// has no signed expiry to honour — and says so wherever it is shown.
    pub valid_until: Option<u64>,
}

/// The site zone as this node sees it.
#[derive(Clone, Debug, Default)]
pub struct Zone {
    site: String,
    records: BTreeMap<String, Record>,
    /// Names that were not published, and why.
    pub withheld: Vec<(String, String)>,
}

/// What a lookup found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Found(&'a Record),
    /// Never held, or held and lapsed. The two are not told apart on the wire.
    Absent,
}

/// A member as the zone needs it.
pub struct Member<'a> {
    pub node_id: &'a str,
    pub name: Option<&'a str>,
    pub overlay_addr: &'a str,
    pub valid_until: Option<u64>,
}

impl<'a> From<&'a Peer> for Member<'a> {
    fn from(p: &'a Peer) -> Self {
        Member {
            node_id: &p.node_id,
            name: p.name.as_deref(),
            overlay_addr: &p.overlay_addr,
            valid_until: p.valid_until,
        }
    }
}

fn parse_addr(a: &str) -> Option<IpAddr> {
    a.split('/').next()?.parse().ok()
}

impl Zone {
    /// Build the zone for `site` from members — this node first, then the
    /// peers it carries.
    pub fn build<'a, I>(site: &str, members: I) -> Result<Zone, String>
    where
        I: IntoIterator<Item = Member<'a>>,
    {
        let site = site.to_ascii_lowercase();
        if dns_label(&site).is_none() {
            return Err(format!(
                "site name `{site}` is not a DNS label (lower-case letters, digits, inner hyphens, at most 63)"
            ));
        }
        let mut zone = Zone { site, ..Default::default() };
        let mut by_name: BTreeMap<String, Vec<(String, Record)>> = BTreeMap::new();
        let mut ids: BTreeMap<String, Record> = BTreeMap::new();

        for m in members {
            let Some(ip) = parse_addr(m.overlay_addr) else {
                zone.withheld.push((m.node_id.to_string(), format!("overlay address `{}` is not an address", m.overlay_addr)));
                continue;
            };
            let mut rec = Record { valid_until: m.valid_until, ..Default::default() };
            match ip {
                IpAddr::V4(a) => rec.v4 = Some(a),
                IpAddr::V6(a) => rec.v6 = Some(a),
            }
            match id_label(m.node_id) {
                Some(l) => {
                    ids.insert(l.to_string(), rec.clone());
                }
                // This node's own entry may carry no id when none was
                // configured; its name still resolves.
                None if m.node_id.is_empty() => {}
                None => zone.withheld.push((m.node_id.to_string(), "node id is not a DNS label".into())),
            }
            if let Some(n) = m.name {
                match dns_label(n) {
                    Some(l) => by_name.entry(l.to_string()).or_default().push((m.node_id.to_string(), rec)),
                    None => zone.withheld.push((n.to_string(), "not a DNS label".into())),
                }
            }
        }

        for (name, claims) in by_name {
            let distinct: std::collections::BTreeSet<&String> = claims.iter().map(|(id, _)| id).collect();
            if distinct.len() > 1 {
                let who: Vec<&str> = distinct.iter().map(|s| s.as_str()).collect();
                zone.withheld.push((name, format!("claimed by {} members ({}); resolves under neither", who.len(), who.join(", "))));
                continue;
            }
            if ids.contains_key(&name) {
                zone.withheld.push((name, "is another member's id label".into()));
                continue;
            }
            zone.records.insert(name, claims.into_iter().next().map(|(_, r)| r).unwrap_or_default());
        }
        zone.records.extend(ids);
        Ok(zone)
    }

    /// `<site>.internal`
    pub fn origin(&self) -> String {
        format!("{}.{TLD}", self.site)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Look up one label as of `now`.
    pub fn lookup(&self, label: &str, now: u64) -> Lookup<'_> {
        match self.records.get(&label.to_ascii_lowercase()) {
            Some(r) if r.valid_until.is_none_or(|t| t > now) => Lookup::Found(r),
            _ => Lookup::Absent,
        }
    }
}

// ---- this node's own name -------------------------------------------------

/// Check a name a node proposes to call itself.
///
/// Case is folded, because DNS folds it and an operator who wrote `Node-a`
/// means `node-a`. Anything else that is not a label is refused with the
/// reason, never repaired: a name nobody typed is not one anybody looks up.
/// A name shaped like a node id label is refused too, because that label space
/// belongs to the signed ids and a name in it could only ever shadow one.
pub fn node_name(raw: &str) -> Result<String, String> {
    let n = raw.trim().to_ascii_lowercase();
    if dns_label(&n).is_none() {
        return Err(format!(
            "`{}` is not a DNS label (lower-case letters, digits, inner hyphens, at most 63)",
            raw.trim()
        ));
    }
    if n.len() == 52 && n.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)) {
        return Err(format!("`{n}` has the shape of a node id label, which only a node id may take"));
    }
    Ok(n)
}

/// What this node publishes about itself, kept beside the peer set.
///
/// The agent writes it each time it publishes its hint, so the names service
/// answers for this node under exactly the name its peers were given — one
/// source for both, rather than two settings that can disagree.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Own {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Where [`Own`] is kept for a given peer file: `<plan>-self.json` beside
/// `<plan>-peers.json`.
pub fn own_path_for(peers_path: &str) -> String {
    match peers_path.strip_suffix("-peers.json") {
        Some(plan) => format!("{plan}-self.json"),
        None => format!("{peers_path}.self.json"),
    }
}

// ---- the wire -------------------------------------------------------------

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

const NOERROR: u8 = 0;
const FORMERR: u8 = 1;
const NXDOMAIN: u8 = 3;
const NOTIMP: u8 = 4;
const REFUSED: u8 = 5;

/// Answer one DNS query from the zone.
///
/// `None` means drop: too short to carry an id, or already a response. Every
/// other packet gets an answer, including a refusal — a resolver left waiting
/// on a timeout is slower and less informative than one told no.
pub fn answer(zone: &Zone, query: &[u8], now: u64) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None;
    }
    let id = [query[0], query[1]];
    let rd = query[2] & 0x01;
    let opcode = (query[2] >> 3) & 0x0F;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    let header = |rcode: u8, aa: bool, qd: u16, an: u16| {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&id);
        h.push(0x80 | if aa { 0x04 } else { 0 } | rd);
        h.push(rcode);
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&an.to_be_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]);
        h
    };

    if opcode != 0 {
        return Some(header(NOTIMP, false, 0, 0));
    }
    if qdcount != 1 {
        return Some(header(FORMERR, false, 0, 0));
    }

    // The question: labels without compression (a query has nothing to point
    // back to), then type and class.
    let mut at = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let Some(&len) = query.get(at) else { return Some(header(FORMERR, false, 0, 0)) };
        at += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 || at + len as usize > query.len() || at > 12 + 255 {
            return Some(header(FORMERR, false, 0, 0));
        }
        let raw = &query[at..at + len as usize];
        labels.push(String::from_utf8_lossy(raw).to_ascii_lowercase());
        at += len as usize;
    }
    let Some(tail) = query.get(at..at + 4) else { return Some(header(FORMERR, false, 0, 0)) };
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    let question = &query[12..at + 4];

    let respond = |rcode: u8, aa: bool, answers: &[(u16, Vec<u8>, u32)]| {
        let mut out = header(rcode, aa, 1, answers.len() as u16);
        out.extend_from_slice(question);
        for (t, data, ttl) in answers {
            out.extend_from_slice(&[0xC0, 0x0C]); // the name in the question
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        Some(out)
    };

    // Only this zone. Everything else is somebody else's question.
    let n = labels.len();
    let in_zone = n >= 2 && labels[n - 1] == TLD && labels[n - 2] == zone.site;
    if !in_zone || (qclass != CLASS_IN && qclass != TYPE_ANY) {
        return respond(REFUSED, false, &[]);
    }
    // The apex has no addresses of its own, and anything deeper than one label
    // under it is not a member.
    if n == 2 {
        return respond(NOERROR, true, &[]);
    }
    if n != 3 {
        return respond(NXDOMAIN, true, &[]);
    }
    let rec = match zone.lookup(&labels[0], now) {
        Lookup::Found(r) => r,
        Lookup::Absent => return respond(NXDOMAIN, true, &[]),
    };
    let ttl = rec
        .valid_until
        .map(|t| t.saturating_sub(now).min(MAX_TTL as u64) as u32)
        .unwrap_or(MAX_TTL);
    let mut answers = Vec::new();
    if matches!(qtype, TYPE_A | TYPE_ANY) {
        if let Some(a) = rec.v4 {
            answers.push((TYPE_A, a.octets().to_vec(), ttl));
        }
    }
    if matches!(qtype, TYPE_AAAA | TYPE_ANY) {
        if let Some(a) = rec.v6 {
            answers.push((TYPE_AAAA, a.octets().to_vec(), ttl));
        }
    }
    // A name that exists with no address of the asked type is NOERROR with no
    // answers, not NXDOMAIN: saying the name does not exist would make a
    // resolver stop asking for the type it does have.
    respond(NOERROR, true, &answers)
}

/// A query for `name` and `qtype`, for tests and for `furcate-overlay names
/// --ask`.
pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.trim_end_matches('.').split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

/// The response code and the addresses in a response. Enough for a test and
/// for an operator's spot check; not a general parser.
pub fn read_answer(resp: &[u8]) -> Option<(u8, Vec<IpAddr>)> {
    if resp.len() < 12 {
        return None;
    }
    let rcode = resp[3] & 0x0F;
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    let mut at = 12;
    while *resp.get(at)? != 0 {
        at += 1 + resp[at] as usize;
    }
    at += 5;
    let mut out = Vec::new();
    for _ in 0..an {
        at += 2; // compressed name
        let t = u16::from_be_bytes([*resp.get(at)?, *resp.get(at + 1)?]);
        let len = u16::from_be_bytes([*resp.get(at + 8)?, *resp.get(at + 9)?]) as usize;
        let data = resp.get(at + 10..at + 10 + len)?;
        match (t, len) {
            (TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (TYPE_AAAA, 16) => out.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
            _ => {}
        }
        at += 10 + len;
    }
    Some((rcode, out))
}

pub const QTYPE_A: u16 = TYPE_A;
pub const QTYPE_AAAA: u16 = TYPE_AAAA;

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;
    const ID_A: &str = "furcate:node:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "furcate:node:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ID_C: &str = "furcate:node:cccccccccccccccccccccccccccccccccccccccccccccccccccc";

    /// A fixture roster as a node holds it: itself, a current peer, a peer
    /// whose authorization has lapsed, and one on IPv6.
    fn fixture() -> Zone {
        Zone::build(
            "lab",
            [
                Member { node_id: ID_A, name: Some("node-a"), overlay_addr: "10.90.0.10/32", valid_until: None },
                Member { node_id: ID_B, name: Some("node-b"), overlay_addr: "10.90.0.20/32", valid_until: Some(NOW + 3600) },
                Member { node_id: ID_C, name: Some("old"), overlay_addr: "10.90.0.30/32", valid_until: Some(NOW - 1) },
                Member { node_id: "furcate:node:dddd", name: Some("v6"), overlay_addr: "fd90::4/128", valid_until: None },
            ],
        )
        .unwrap()
    }

    fn ask(z: &Zone, name: &str, t: u16) -> (u8, Vec<IpAddr>) {
        read_answer(&answer(z, &query(0x1234, name, t), NOW).unwrap()).unwrap()
    }

    #[test]
    fn members_resolve_by_name_and_by_id_label() {
        let z = fixture();
        assert_eq!(ask(&z, "node-b.lab.internal", QTYPE_A), (NOERROR, vec!["10.90.0.20".parse().unwrap()]));
        assert_eq!(ask(&z, "NODE-A.Lab.Internal.", QTYPE_A), (NOERROR, vec!["10.90.0.10".parse().unwrap()]));
        let by_id = format!("{}.lab.internal", &ID_B[13..]);
        assert_eq!(ask(&z, &by_id, QTYPE_A).1, vec!["10.90.0.20".parse::<IpAddr>().unwrap()]);
        assert_eq!(ask(&z, "v6.lab.internal", QTYPE_AAAA).1, vec!["fd90::4".parse::<IpAddr>().unwrap()]);
        // The name exists; it has no IPv4 address. NOERROR, no answers.
        assert_eq!(ask(&z, "v6.lab.internal", QTYPE_A), (NOERROR, vec![]));
    }

    #[test]
    fn a_lapsed_entry_stops_resolving() {
        let z = fixture();
        assert_eq!(ask(&z, "old.lab.internal", QTYPE_A), (NXDOMAIN, vec![]));
        assert_eq!(ask(&z, "nobody.lab.internal", QTYPE_A), (NXDOMAIN, vec![]));
        // And one that is current now lapses on its date without a rebuild.
        let later = answer(&z, &query(1, "node-b.lab.internal", QTYPE_A), NOW + 3600).unwrap();
        assert_eq!(read_answer(&later).unwrap(), (NXDOMAIN, vec![]));
    }

    #[test]
    fn the_ttl_never_outlives_the_authorization() {
        let z = fixture();
        let r = answer(&z, &query(1, "node-b.lab.internal", QTYPE_A), NOW + 3590).unwrap();
        let ttl_at = r.len() - 4 - 2 - 4;
        assert_eq!(u32::from_be_bytes(r[ttl_at..ttl_at + 4].try_into().unwrap()), 10);
    }

    #[test]
    fn queries_outside_the_zone_are_refused_not_forwarded() {
        let z = fixture();
        assert_eq!(ask(&z, "example.com", QTYPE_A).0, REFUSED);
        assert_eq!(ask(&z, "node-a.othersite.internal", QTYPE_A).0, REFUSED);
        assert_eq!(ask(&z, "internal", QTYPE_A).0, REFUSED);
        assert_eq!(ask(&z, "a.node-a.lab.internal", QTYPE_A).0, NXDOMAIN);
    }

    #[test]
    fn a_node_name_is_folded_checked_and_never_repaired() {
        assert_eq!(node_name(" Node-a\n").unwrap(), "node-a");
        assert_eq!(node_name("node-e").unwrap(), "node-e");
        assert!(node_name("server_1").unwrap_err().contains("not a DNS label"));
        assert!(node_name("-x").is_err());
        assert!(node_name("").is_err());
        assert!(node_name(&"a".repeat(64)).is_err());
        assert!(node_name(&ID_A[13..]).unwrap_err().contains("node id"));
    }

    #[test]
    fn the_own_entry_sits_beside_the_peer_set() {
        assert_eq!(own_path_for("/var/lib/furcate/wg-plan-peers.json"), "/var/lib/furcate/wg-plan-self.json");
        assert_eq!(own_path_for("/tmp/p.json"), "/tmp/p.json.self.json");
    }

    #[test]
    fn every_member_resolves_by_the_name_it_published() {
        // Three nodes, each having published its node name: whichever of them
        // builds the zone, every one resolves by name.
        let all = [(ID_A, "node-a", "10.90.0.10"), (ID_B, "node-b", "10.90.0.20"), (ID_C, "node-e", "10.90.0.30")];
        for me in 0..all.len() {
            let mut members = vec![Member { node_id: all[me].0, name: Some(all[me].1), overlay_addr: all[me].2, valid_until: None }];
            let peers: Vec<Peer> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != me)
                .map(|(_, (id, name, addr))| Peer {
                    node_id: id.to_string(),
                    public_key: String::new(),
                    endpoint: None,
                    overlay_addr: format!("{addr}/16"),
                    tier: crate::overlay::Tier::Platform,
                    source: crate::overlay::Source::Hint,
                    resolved_at: 0,
                    name: Some(name.to_string()),
                    valid_until: None,
                    lease_until: None,
                    candidates: vec![],
                })
                .collect();
            members.extend(peers.iter().map(Member::from));
            let z = Zone::build("site-a", members).unwrap();
            assert!(z.withheld.is_empty(), "{:?}", z.withheld);
            for (_, name, addr) in all {
                let q = format!("{name}.site-a.internal");
                assert_eq!(ask(&z, &q, QTYPE_A), (NOERROR, vec![addr.parse().unwrap()]), "{q} on member {me}");
            }
        }
    }

    #[test]
    fn a_name_that_is_another_members_id_label_is_withheld_and_the_id_still_resolves() {
        let z = Zone::build(
            "lab",
            [
                Member { node_id: ID_A, name: Some(&ID_B[13..]), overlay_addr: "10.90.0.10/32", valid_until: None },
                Member { node_id: ID_B, name: Some("node-b"), overlay_addr: "10.90.0.20/32", valid_until: None },
            ],
        )
        .unwrap();
        assert!(z.withheld.iter().any(|(n, why)| n == &ID_B[13..] && why.contains("id label")));
        // The id label answers with its own member's address, not the claimant's.
        assert_eq!(ask(&z, &format!("{}.lab.internal", &ID_B[13..]), QTYPE_A).1, vec!["10.90.0.20".parse::<IpAddr>().unwrap()]);
        assert_eq!(ask(&z, &format!("{}.lab.internal", &ID_A[13..]), QTYPE_A).1, vec!["10.90.0.10".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn a_name_two_members_claim_resolves_under_neither() {
        let z = Zone::build(
            "lab",
            [
                Member { node_id: ID_A, name: Some("box"), overlay_addr: "10.90.0.10/32", valid_until: None },
                Member { node_id: ID_B, name: Some("box"), overlay_addr: "10.90.0.20/32", valid_until: None },
            ],
        )
        .unwrap();
        assert_eq!(ask(&z, "box.lab.internal", QTYPE_A).0, NXDOMAIN);
        assert!(z.withheld.iter().any(|(n, why)| n == "box" && why.contains("neither")));
        // Each is still reachable by the label nobody can claim.
        assert_eq!(ask(&z, &format!("{}.lab.internal", &ID_A[13..]), QTYPE_A).0, NOERROR);
    }

    #[test]
    fn a_malformed_or_unsupported_query_is_answered_with_why() {
        let z = fixture();
        assert!(answer(&z, &[0; 5], NOW).is_none());
        let mut resp = query(1, "node-a.lab.internal", QTYPE_A);
        resp[2] |= 0x80;
        assert!(answer(&z, &resp, NOW).is_none(), "a response is not answered");
        let mut notify = query(1, "node-a.lab.internal", QTYPE_A);
        notify[2] |= 4 << 3;
        assert_eq!(answer(&z, &notify, NOW).unwrap()[3] & 0x0F, NOTIMP);
        let mut truncated = query(1, "node-a.lab.internal", QTYPE_A);
        truncated.truncate(20);
        assert_eq!(answer(&z, &truncated, NOW).unwrap()[3] & 0x0F, FORMERR);
    }

    #[test]
    fn a_site_name_that_is_not_a_label_is_refused() {
        assert!(Zone::build("my site", std::iter::empty()).is_err());
    }
}
