//! Reaching a peer that sits behind a NAT, without a vendor in the path.
//!
//! Two machines behind two home routers cannot dial each other: each router
//! drops an inbound packet it has no record of asking for. What opens the path
//! is both sides sending at once. Each outbound packet makes its own router
//! expect a reply from that address, so whichever packet arrives second finds
//! the door already open. That needs each side to know the address the other's
//! router presents to the world, and nothing on the machine knows that — only
//! something outside it can see it.
//!
//! So this module has three parts, each small:
//!
//! - **Reflection.** Any node with a public address answers "what address did
//!   this packet come from" — a STUN Binding (RFC 8489), nothing else from that
//!   protocol. The answer goes into the node's own hint as `observed`, and
//!   travels with the rest of the hint through the coordinator and gossip.
//! - **Punching.** A peer's listening and observed addresses are tried in turn,
//!   on a schedule both sides derive from the clock, so both send toward each
//!   other in the same window. On a kernel WireGuard interface the "send" is
//!   the handshake WireGuard already makes to whatever endpoint is configured,
//!   and once one is answered WireGuard roams to the address the answer came
//!   from — which is the mapping the remote router actually made.
//! - **Relaying.** When no candidate answers — one side behind a router that
//!   picks a fresh port per destination, which no amount of simultaneous
//!   sending gets through — the peer is reached through a blind relay. Which
//!   relay is this node's choice, from its own measurements of each, not a
//!   coordinator's assignment.
//!
//! ## The port is a stated assumption
//!
//! Kernel WireGuard owns its UDP socket, so a reflection query cannot be sent
//! from it. The reflected address is therefore the router's public address
//! paired with WireGuard's listening port — correct for the common router that
//! preserves source ports, and wrong for one that does not. That is not hidden:
//! a wrong candidate simply never answers, the rotation moves on, and the relay
//! is the path for exactly that router.

use crate::reach::Probe;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// RFC 8489 magic cookie. Its presence is how a STUN packet is told apart from
/// anything else arriving on the same port.
const COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// The port reflectors answer on, the registered STUN port.
pub const REFLECT_PORT: u16 = 3478;

/// A Binding request with the given transaction id.
pub fn request(txid: [u8; 12]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Length 0: no attributes. A reflector needs nothing but the packet.
    out[4..8].copy_from_slice(&COOKIE.to_be_bytes());
    out[8..20].copy_from_slice(&txid);
    out
}

/// The transaction id of a well-formed Binding request, or `None`.
///
/// Strict on purpose: a reflector on a public address will be sent everything,
/// and the only thing it should ever answer is a request it can parse exactly.
pub fn parse_request(buf: &[u8]) -> Option<[u8; 12]> {
    if buf.len() < 20 || buf[0] & 0xC0 != 0 {
        return None;
    }
    let kind = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if kind != BINDING_REQUEST || cookie != COOKIE || len % 4 != 0 || len != buf.len() - 20 {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    Some(txid)
}

/// A Binding success response carrying the address the request came from.
pub fn response(txid: [u8; 12], observed: SocketAddr) -> Vec<u8> {
    let mut attr: Vec<u8> = Vec::with_capacity(20);
    attr.push(0);
    let xport = observed.port() ^ (COOKIE >> 16) as u16;
    match observed.ip() {
        IpAddr::V4(a) => {
            attr.push(0x01);
            attr.extend_from_slice(&xport.to_be_bytes());
            attr.extend_from_slice(&(u32::from(a) ^ COOKIE).to_be_bytes());
        }
        IpAddr::V6(a) => {
            attr.push(0x02);
            attr.extend_from_slice(&xport.to_be_bytes());
            let key = xor_key(&txid);
            let mut b = a.octets();
            for (x, k) in b.iter_mut().zip(key.iter()) {
                *x ^= k;
            }
            attr.extend_from_slice(&b);
        }
    }
    let mut out = Vec::with_capacity(24 + attr.len());
    out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&((4 + attr.len()) as u16).to_be_bytes());
    out.extend_from_slice(&COOKIE.to_be_bytes());
    out.extend_from_slice(&txid);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    out.extend_from_slice(&attr);
    out
}

fn xor_key(txid: &[u8; 12]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&COOKIE.to_be_bytes());
    key[4..16].copy_from_slice(txid);
    key
}

/// The observed address in a Binding success response to `txid`.
///
/// A response to some other transaction is ignored rather than believed: on a
/// public port anyone can send a well-formed response, and the address in it
/// is the thing a peer will be told to send to.
pub fn parse_response(buf: &[u8], txid: [u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    let kind = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if kind != BINDING_SUCCESS || cookie != COOKIE || buf[8..20] != txid || buf.len() < 20 + len {
        return None;
    }
    let mut at = 20;
    while at + 4 <= 20 + len {
        let t = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let l = u16::from_be_bytes([buf[at + 2], buf[at + 3]]) as usize;
        let v = buf.get(at + 4..at + 4 + l)?;
        if t == XOR_MAPPED_ADDRESS && l >= 8 {
            let port = u16::from_be_bytes([v[2], v[3]]) ^ (COOKIE >> 16) as u16;
            return match v[1] {
                0x01 => {
                    let raw = u32::from_be_bytes([v[4], v[5], v[6], v[7]]) ^ COOKIE;
                    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
                }
                0x02 if l >= 20 => {
                    let key = xor_key(&txid);
                    let mut b = [0u8; 16];
                    for i in 0..16 {
                        b[i] = v[4 + i] ^ key[i];
                    }
                    Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port))
                }
                _ => None,
            };
        }
        // Attributes are padded to a four-byte boundary.
        at += 4 + l.div_ceil(4) * 4;
    }
    None
}

/// Answer one packet on a reflector socket. Returns the address answered, or
/// `None` if the packet was not a Binding request and was dropped.
pub fn reflect_once(sock: &UdpSocket) -> std::io::Result<Option<SocketAddr>> {
    let mut buf = [0u8; 576];
    let (n, from) = sock.recv_from(&mut buf)?;
    match parse_request(&buf[..n]) {
        Some(txid) => {
            sock.send_to(&response(txid, from), from)?;
            Ok(Some(from))
        }
        None => Ok(None),
    }
}

/// A transaction id nobody else will reuse: the clock and the process, hashed.
fn txid() -> [u8; 12] {
    use sha2::{Digest, Sha256};
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut h = Sha256::new();
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(t.to_be_bytes());
    h.update(std::process::id().to_be_bytes());
    h.update(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_be_bytes());
    let d = h.finalize();
    let mut out = [0u8; 12];
    out.copy_from_slice(&d[..12]);
    out
}

/// Ask a reflector what address this socket's packets arrive from.
///
/// Three sends inside the timeout, because the request is one UDP packet and a
/// single loss should not read as "this node has no public address".
pub fn observe(sock: &UdpSocket, reflector: SocketAddr, timeout: Duration) -> std::io::Result<SocketAddr> {
    let id = txid();
    let deadline = Instant::now() + timeout;
    let step = timeout / 3;
    let mut buf = [0u8; 576];
    while Instant::now() < deadline {
        sock.send_to(&request(id), reflector)?;
        let until = (Instant::now() + step).min(deadline);
        while let Some(left) = until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
            sock.set_read_timeout(Some(left))?;
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from == reflector => {
                    if let Some(a) = parse_response(&buf[..n], id) {
                        return Ok(a);
                    }
                }
                Ok(_) => continue,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                Err(e) => return Err(e),
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{reflector} did not answer a binding request within {timeout:?}"),
    ))
}

/// The address to publish as this node's observed endpoint: the reflected
/// public address with WireGuard's listening port. See the module notes for
/// why the port is an assumption, and what happens when it is wrong.
pub fn observed_endpoint(reflected: SocketAddr, wg_port: u16) -> String {
    SocketAddr::new(reflected.ip(), wg_port).to_string()
}

/// How long each candidate is tried before the next.
///
/// WireGuard retries a handshake every five seconds; three tries per candidate
/// is enough for one lost packet each way not to skip a working address.
pub const ROUND_SECS: u64 = 15;

/// A handshake younger than this means the path in use works. WireGuard
/// itself rekeys every two minutes on a live session, so three minutes without
/// one is a session that has stopped.
pub const ALIVE_SECS: u64 = 180;

/// Where to send for one peer, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The path in use answered recently. Keep it — including when it is an
    /// address no candidate named, because that is the mapping the far router
    /// actually made.
    Keep(String),
    /// Nothing answered recently: try this candidate in this window.
    Try(String),
    /// Every candidate has had its window and none answered: use the relay.
    Relay(String),
    /// Nothing to try and no relay chosen. Said, not papered over.
    NoPath(String),
}

impl Decision {
    pub fn endpoint(&self) -> Option<&str> {
        match self {
            Decision::Keep(e) | Decision::Try(e) | Decision::Relay(e) => Some(e),
            Decision::NoPath(_) => None,
        }
    }
}

/// Decide where to send for one peer.
///
/// Stateless, so that it survives the agent restarting and so that both ends
/// compute the same schedule: the window is derived from the wall clock, which
/// a fleet keeps in step, and both sides therefore try their candidate for each
/// other at the same time — the simultaneous send that opens two routers.
///
/// One cycle is every candidate for one round, then the relay for as long again
/// before direct paths are retried, so a peer that moves to a better network
/// stops being relayed without anyone noticing it moved.
pub fn decide(
    candidates: &[String],
    relay: Option<&str>,
    handshake_age: Option<u64>,
    current: Option<&str>,
    now: u64,
) -> Decision {
    if let (Some(age), Some(cur)) = (handshake_age, current) {
        if age < ALIVE_SECS {
            return Decision::Keep(cur.to_string());
        }
    }
    if candidates.is_empty() {
        return match relay {
            Some(r) => Decision::Relay(r.to_string()),
            None => Decision::NoPath("no address is known for this peer and no relay is chosen".into()),
        };
    }
    let direct = candidates.len() as u64 * ROUND_SECS;
    let cycle = if relay.is_some() { direct * 2 } else { direct };
    let phase = now % cycle;
    if phase < direct {
        return Decision::Try(candidates[(phase / ROUND_SECS) as usize].clone());
    }
    Decision::Relay(relay.unwrap_or_default().to_string())
}

/// Pick a relay by this node's own measurements of each.
///
/// Failing relays are out; among the rest, least loss, then lowest round trip,
/// then least jitter. A relay with no round trip measured sorts after every one
/// that has one: unknown is not fast.
pub fn choose_relay<'a>(measured: &'a [(String, Probe)]) -> Option<&'a str> {
    let mut ok: Vec<&(String, Probe)> = measured.iter().filter(|(_, p)| !p.is_failing()).collect();
    let key = |p: &Probe| {
        (
            (p.loss() * 1000.0) as u64,
            p.rtt_ms.map(|r| (r * 1000.0) as u64).unwrap_or(u64::MAX),
            p.jitter_ms.map(|j| (j * 1000.0) as u64).unwrap_or(u64::MAX),
        )
    };
    ok.sort_by(|a, b| key(&a.1).cmp(&key(&b.1)).then(a.0.cmp(&b.0)));
    ok.first().map(|(r, _)| r.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reach::Layer;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn a_reflected_address_round_trips_for_both_families() {
        let id = [7u8; 12];
        for a in ["203.0.113.9:40001", "[2001:db8::5]:51820"] {
            let a: SocketAddr = a.parse().unwrap();
            let req = request(id);
            assert_eq!(parse_request(&req), Some(id));
            assert_eq!(parse_response(&response(id, a), id), Some(a));
        }
    }

    #[test]
    fn a_response_to_someone_elses_question_is_not_believed() {
        let a: SocketAddr = "203.0.113.9:40001".parse().unwrap();
        assert_eq!(parse_response(&response([1; 12], a), [2; 12]), None);
    }

    #[test]
    fn the_reflector_answers_only_what_it_can_parse() {
        assert_eq!(parse_request(b"GET / HTTP/1.1\r\n\r\n.."), None);
        let mut bad = request([3; 12]);
        bad[4] ^= 0xff; // not the cookie
        assert_eq!(parse_request(&bad), None);
        let mut resp = response([3; 12], "198.51.100.1:1".parse().unwrap());
        resp.truncate(20);
        assert_eq!(parse_request(&resp), None, "a response is not a request");
    }

    #[test]
    fn a_reflector_on_a_real_socket_reports_the_source_address() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let t = std::thread::spawn(move || reflect_once(&server).unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seen = observe(&client, addr, Duration::from_secs(3)).unwrap();
        assert_eq!(seen, client.local_addr().unwrap());
        assert_eq!(t.join().unwrap(), Some(seen));
        assert_eq!(observed_endpoint(seen, 51820), "127.0.0.1:51820");
    }

    // ---- a simulated internet with two routers in it -------------------

    /// How a router maps and filters, in the terms RFC 4787 uses.
    #[derive(Clone, Copy, PartialEq)]
    enum Router {
        /// Same public port whatever the destination; inbound only from an
        /// address and port this side has sent to.
        PortRestricted,
        /// A new public port for every destination.
        Symmetric,
    }

    struct Nat {
        kind: Router,
        public_ip: &'static str,
        /// destination -> public port used toward it
        mapping: BTreeMap<String, u16>,
        /// (public port, remote) pairs inbound is allowed for
        allowed: BTreeSet<(u16, String)>,
        next_port: u16,
    }

    impl Nat {
        fn new(kind: Router, public_ip: &'static str) -> Self {
            Nat { kind, public_ip, mapping: BTreeMap::new(), allowed: BTreeSet::new(), next_port: 51820 }
        }
        /// Send out; returns the public source address the far side sees.
        fn out(&mut self, to: &str) -> String {
            let port = match self.kind {
                Router::PortRestricted => 51820,
                Router::Symmetric => {
                    let next = &mut self.next_port;
                    *self.mapping.entry(to.to_string()).or_insert_with(|| {
                        *next += 1;
                        *next
                    })
                }
            };
            self.allowed.insert((port, to.to_string()));
            format!("{}:{port}", self.public_ip)
        }
        /// Whether a packet from `from` to public `port` is let in.
        fn admits(&self, port: u16, from: &str) -> bool {
            self.allowed.contains(&(port, from.to_string()))
        }
        /// What a reflector would report for this side.
        fn reflected(&mut self) -> String {
            self.out("192.0.2.200:3478")
        }
    }

    fn port_of(a: &str) -> u16 {
        a.rsplit(':').next().unwrap().parse().unwrap()
    }

    /// Both sides follow `decide` once a second, sending a
    /// handshake to wherever it says. Returns the endpoint each settled on.
    fn simulate(mut a: Nat, mut b: Nat, relay: Option<&str>) -> (Decision, Decision) {
        let a_cands = vec![a.reflected()];
        let b_cands = vec![b.reflected()];
        let (mut a_heard, mut b_heard): (Option<(u64, String)>, Option<(u64, String)>) = (None, None);
        let mut last = (Decision::NoPath(String::new()), Decision::NoPath(String::new()));
        // Two minutes, ending inside a relay window of the 30 s cycle (one
        // candidate each side: 15 s direct, then 15 s relayed).
        for now in 1_000_000u64..1_000_131 {
            let age = |h: &Option<(u64, String)>| h.as_ref().map(|(t, _)| now - t);
            let cur = |h: &Option<(u64, String)>| h.as_ref().map(|(_, e)| e.clone());
            let da = decide(&b_cands, relay, age(&a_heard), cur(&a_heard).as_deref(), now);
            let db = decide(&a_cands, relay, age(&b_heard), cur(&b_heard).as_deref(), now);
            // A sends first; a packet is delivered if the far router lets it in,
            // and the receiver learns the address it came from — which is the
            // roaming WireGuard does on an authenticated packet.
            if let Decision::Try(to) | Decision::Keep(to) = &da {
                let src = a.out(to);
                if to.starts_with(b.public_ip) && b.admits(port_of(to), &src) {
                    b_heard = Some((now, src));
                }
            }
            if let Decision::Try(to) | Decision::Keep(to) = &db {
                let src = b.out(to);
                if to.starts_with(a.public_ip) && a.admits(port_of(to), &src) {
                    a_heard = Some((now, src));
                }
            }
            last = (da, db);
        }
        last
    }

    #[test]
    fn two_ordinary_routers_open_a_direct_path_by_sending_at_once() {
        let (a, b) = simulate(
            Nat::new(Router::PortRestricted, "198.51.100.1"),
            Nat::new(Router::PortRestricted, "203.0.113.1"),
            Some("192.0.2.50:40000"),
        );
        assert_eq!(a, Decision::Keep("203.0.113.1:51820".into()));
        assert_eq!(b, Decision::Keep("198.51.100.1:51820".into()));
    }

    #[test]
    fn a_router_that_changes_port_per_destination_falls_back_to_the_relay() {
        let (a, b) = simulate(
            Nat::new(Router::PortRestricted, "198.51.100.1"),
            Nat::new(Router::Symmetric, "203.0.113.1"),
            Some("192.0.2.50:40000"),
        );
        // Neither direct attempt is let in, so after the direct window both
        // sides are on the relay.
        assert_eq!(a, Decision::Relay("192.0.2.50:40000".into()));
        assert_eq!(b, Decision::Relay("192.0.2.50:40000".into()));
    }

    #[test]
    fn with_no_relay_chosen_the_rotation_continues_rather_than_inventing_one() {
        let d = decide(&["a:1".into(), "b:2".into()], None, None, None, ROUND_SECS * 3);
        assert_eq!(d, Decision::Try("b:2".into()));
        let d = decide(&[], None, None, None, 0);
        assert!(matches!(d, Decision::NoPath(_)));
        assert!(d.endpoint().is_none());
    }

    #[test]
    fn a_stale_handshake_does_not_keep_a_dead_path() {
        let d = decide(&["a:1".into()], None, Some(ALIVE_SECS), Some("old:9"), 0);
        assert_eq!(d, Decision::Try("a:1".into()));
    }

    fn probe(sent: u32, received: u32, rtt: Option<f64>) -> Probe {
        Probe { layer: Layer::Internet, target: String::new(), received, sent, rtt_ms: rtt, jitter_ms: Some(1.0) }
    }

    #[test]
    fn the_relay_is_the_one_this_node_measured_best() {
        let m = vec![
            ("far:3479".to_string(), probe(10, 10, Some(80.0))),
            ("near:3479".to_string(), probe(10, 10, Some(9.0))),
            ("lossy:3479".to_string(), probe(10, 8, Some(2.0))),
            ("down:3479".to_string(), probe(10, 0, None)),
        ];
        assert_eq!(choose_relay(&m), Some("near:3479"));
        assert_eq!(choose_relay(&m[3..]), None, "a failing relay is not chosen");
    }
}
