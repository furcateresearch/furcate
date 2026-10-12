//! A leased node's new key, announced to its peers over the underlay.
//!
//! A node whose WireGuard key lives for one lease comes back from a restart
//! with a key no peer holds. Every other way it has of saying so (its report
//! to the coordinator, its membership pings, which carry leases on gossip)
//! travels inside the overlay, and the overlay needs the new key first. A
//! node configured with overlay addresses alone would wait forever.
//!
//! This is the one path that does not need the overlay: a single UDP
//! datagram, sent to the host address of each peer the node already knows
//! (the endpoints its own WireGuard peer set holds) on a port of its own. It
//! carries one thing, the node's current leased hint, and nothing else is
//! accepted on that port. No answer is ever sent, so the port cannot be used
//! to reflect traffic at anyone.
//!
//! ## What a receiver checks
//!
//! - The hint inside is checked exactly as a gossiped one is
//!   ([`crate::lease::verify_carried`]): a lease binding by the node's
//!   hardware key over its WireGuard key, tier and expiry, and on a locked
//!   overlay an anchor's authorization of that hardware key at that tier,
//!   still in force. A tier the key may not hold is refused there.
//! - The announcement itself is signed by the same hardware key, over the
//!   exact bytes of the hint and the time it was sent, so the endpoints in it
//!   are the node's own and the message cannot be replayed: a receiver takes
//!   an origin's announcements in strictly increasing order of their send
//!   time, and none older than [`FRESHNESS`].
//!
//! A WireGuard key changes nothing a receiver trusts; the hardware key and the
//! operator's authorization of it do, and both are checked on every message.

use crate::lease;
use crate::lock::Anchors;
use crate::overlay::Hint;
use furcate_identity::MessageSigner;
use furcate_policy::delegation::CellKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Domain separation from the lease binding, which the same key signs.
const CONTEXT: &[u8] = b"furcate-overlay-announce-v1";

/// The port announcements are sent to and received on, unless configured
/// otherwise. Next to WireGuard's, because it is reached the same way.
pub const DEFAULT_PORT: u16 = 51821;

/// The largest datagram read. A hint with its lease and authorization is
/// under two kilobytes; anything near this is not an announcement.
pub const MAX_DATAGRAM: usize = 8192;

/// How far a send time may be from the receiver's clock, either way.
pub const FRESHNESS: u64 = 300;

/// A peer with no handshake for this long may be holding an old key.
pub const STALE_AFTER: u64 = 300;

/// The format version this code writes and reads.
pub const VERSION: u32 = 1;

/// What goes on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Announcement {
    pub v: u32,
    /// The hint as JSON text, exactly as signed. Carried as text so the
    /// receiver verifies the bytes the sender signed, not a re-encoding.
    pub hint: String,
    /// Seconds since the epoch at which the sender signed this.
    pub sent_at: u64,
    /// Hex, by the key named in the hint's lease binding.
    pub signature: String,
}

fn signed_bytes(node_id: &str, hint: &str, sent_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTEXT.len() + hint.len() + 64);
    out.extend_from_slice(CONTEXT);
    for field in [node_id, hint] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out.extend_from_slice(&sent_at.to_be_bytes());
    out
}

/// Sign this node's leased hint for sending.
///
/// Only a leased hint is announced, and only by the key that bound its lease:
/// a receiver checks the announcement against that key, so anything else
/// would be refused by every peer.
pub fn seal(signer: &dyn MessageSigner, hint: &Hint, sent_at: u64) -> Result<Vec<u8>, String> {
    let Some(b) = &hint.lease else {
        return Err("this node's key is not leased, so there is nothing to announce".into());
    };
    let key = CellKey::of(signer)?;
    if key.id() != b.node_key {
        return Err(format!(
            "the lease was bound by {} and this signer holds {}; peers would refuse the announcement",
            b.node_key,
            key.id()
        ));
    }
    let text = serde_json::to_string(hint).map_err(|e| e.to_string())?;
    let bytes = signed_bytes(&hint.node_id, &text, sent_at);
    let raw = signer
        .sign(&bytes)
        .map_err(|e| format!("the hardware did not sign the announcement: {e:#}"))?;
    let a = Announcement { v: VERSION, hint: text, sent_at, signature: key.seal(&bytes, &raw)? };
    let out = serde_json::to_vec(&a).map_err(|e| e.to_string())?;
    if out.len() > MAX_DATAGRAM {
        return Err(format!("the announcement is {} bytes; receivers read at most {MAX_DATAGRAM}", out.len()));
    }
    Ok(out)
}

/// Why an announcement was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    TooLarge(usize),
    Malformed(String),
    UnknownVersion(u32),
    /// From this node itself, reflected back.
    Own,
    /// Sent further from this node's clock than [`FRESHNESS`] allows.
    OutOfWindow { node: String, sent_at: u64, now: u64 },
    /// Not later than an announcement already taken from the same origin.
    Replay { node: String, sent_at: u64, last: u64 },
    /// The hint's lease or authorization did not check.
    Lease(String),
    /// The announcement is not signed by the key that bound the lease.
    BadSignature(String),
}

impl Refusal {
    /// A short name for the kind of refusal, for counting without repeating
    /// a peer's text.
    pub fn kind(&self) -> &'static str {
        match self {
            Refusal::TooLarge(_) => "too large",
            Refusal::Malformed(_) => "malformed",
            Refusal::UnknownVersion(_) => "unknown version",
            Refusal::Own => "own",
            Refusal::OutOfWindow { .. } => "out of window",
            Refusal::Replay { .. } => "replay",
            Refusal::Lease(_) => "lease",
            Refusal::BadSignature(_) => "bad signature",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::TooLarge(n) => write!(f, "a {n}-byte datagram is not an announcement"),
            Refusal::Malformed(why) => write!(f, "not an announcement: {why}"),
            Refusal::UnknownVersion(v) => write!(f, "announcement version {v} is not one this node reads"),
            Refusal::Own => write!(f, "this node's own announcement came back"),
            Refusal::OutOfWindow { node, sent_at, now } => write!(
                f,
                "`{node}` announced at {sent_at}, and it is {now} here; more than {FRESHNESS} seconds apart, so one clock is wrong"
            ),
            Refusal::Replay { node, sent_at, last } => write!(
                f,
                "`{node}`'s announcement sent at {sent_at} is not later than the one taken at {last}; a replay"
            ),
            Refusal::Lease(why) => write!(f, "{why}"),
            Refusal::BadSignature(node) => write!(
                f,
                "`{node}`'s announcement is not signed by the hardware key that bound its lease"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The latest send time taken from each origin.
///
/// An entry older than [`FRESHNESS`] proves nothing the window does not, so
/// it is dropped; the guard stays as large as the set of nodes that
/// announced recently.
#[derive(Debug, Default)]
pub struct Replay {
    last: BTreeMap<String, u64>,
}

impl Replay {
    /// The most origins held at once. Past it, the oldest are dropped first,
    /// and those are the ones the window already covers.
    pub const LIMIT: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    fn check(&self, node: &str, sent_at: u64) -> Result<(), Refusal> {
        match self.last.get(node) {
            Some(&last) if sent_at <= last => Err(Refusal::Replay { node: node.to_string(), sent_at, last }),
            _ => Ok(()),
        }
    }

    fn record(&mut self, node: &str, sent_at: u64, now: u64) {
        if self.last.len() >= Self::LIMIT {
            self.last.retain(|_, t| t.saturating_add(FRESHNESS) >= now);
            while self.last.len() >= Self::LIMIT {
                let oldest = self.last.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => self.last.remove(&k),
                    None => break,
                };
            }
        }
        self.last.insert(node.to_string(), sent_at);
    }
}

/// Check one datagram and return the hint it carries.
///
/// Cheap checks come first and the signatures last, and the replay guard
/// records a send time only after both signatures verified, so a forged
/// datagram cannot advance it and lock the real node out.
pub fn open(
    datagram: &[u8],
    me: &str,
    anchors: &Anchors,
    trusted_key: &dyn Fn(&str) -> Option<String>,
    replay: &mut Replay,
    now: u64,
    ceiling: u64,
) -> Result<Hint, Refusal> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(Refusal::TooLarge(datagram.len()));
    }
    let a: Announcement = serde_json::from_slice(datagram).map_err(|e| Refusal::Malformed(e.to_string()))?;
    if a.v != VERSION {
        return Err(Refusal::UnknownVersion(a.v));
    }
    let h: Hint = serde_json::from_str(&a.hint).map_err(|e| Refusal::Malformed(e.to_string()))?;
    if h.node_id == me {
        return Err(Refusal::Own);
    }
    if a.sent_at.abs_diff(now) > FRESHNESS {
        return Err(Refusal::OutOfWindow { node: h.node_id, sent_at: a.sent_at, now });
    }
    replay.check(&h.node_id, a.sent_at)?;
    lease::verify_carried(anchors, trusted_key(&h.node_id).as_deref(), &h, now, ceiling).map_err(Refusal::Lease)?;
    let Some(b) = &h.lease else {
        return Err(Refusal::Lease(format!("`{}` announced a key that is not leased", h.node_id)));
    };
    let key = CellKey::parse(&b.node_key).map_err(Refusal::Lease)?;
    key.verify_hex(&signed_bytes(&h.node_id, &a.hint, a.sent_at), &a.signature)
        .map_err(|_| Refusal::BadSignature(h.node_id.clone()))?;
    replay.record(&h.node_id, a.sent_at, now);
    Ok(h)
}

/// Where to announce: the host of every endpoint this node's WireGuard peer
/// set holds, on the announcement port, for each peer with no recent
/// handshake.
///
/// `peers` is each peer's public key and endpoint, as the kernel or the held
/// peer set has them; `handshakes` is the kernel's latest handshake per
/// public key. A peer handshaking now already holds this node's key, so it is
/// left alone, but only a handshake made since `key_born` counts: the kernel
/// keeps a peer's last handshake time when the key under it is replaced, and
/// a handshake under the previous key says nothing about the new one. The
/// addresses come from the peer set this node already has,
/// which came from the coordinator's signed plan or a peer's own lease: none
/// is configured by hand.
pub fn targets<'a>(
    peers: impl IntoIterator<Item = (&'a str, &'a str)>,
    handshakes: &BTreeMap<String, u64>,
    key_born: u64,
    port: u16,
    now: u64,
) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for (key, endpoint) in peers {
        let fresh = handshakes
            .get(key)
            .is_some_and(|&t| t > 0 && t >= key_born && now.saturating_sub(t) < STALE_AFTER);
        if fresh {
            continue;
        }
        let Some(ip) = host_of(endpoint) else { continue };
        if ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        let to = SocketAddr::new(ip, port);
        if !out.contains(&to) {
            out.push(to);
        }
    }
    out
}

fn host_of(endpoint: &str) -> Option<IpAddr> {
    if let Ok(sa) = endpoint.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    endpoint.parse::<IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::{bind, Terms, DEFAULT_CEILING, DEFAULT_LEASE};
    use crate::lock::{self, Anchor, Claim};
    use crate::overlay::Tier;
    use furcate_identity::{Ed25519Signer, SignerKey};
    use std::sync::Arc;

    const NOW: u64 = 1_786_838_400;
    const OLD_WG: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const NEW_WG: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    struct FirmwareP256(p256::ecdsa::SigningKey);

    impl MessageSigner for FirmwareP256 {
        fn public_key(&self) -> anyhow::Result<SignerKey> {
            Ok(SignerKey::P256(self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()))
        }
        fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
            use p256::ecdsa::signature::Signer as _;
            let s: p256::ecdsa::Signature = self.0.sign(message);
            Ok(s.to_der().as_bytes().to_vec())
        }
    }

    fn pi() -> FirmwareP256 {
        FirmwareP256(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("a valid scalar"))
    }

    fn other_board() -> FirmwareP256 {
        FirmwareP256(p256::ecdsa::SigningKey::from_slice(&[8u8; 32]).expect("a valid scalar"))
    }

    fn server() -> Ed25519Signer {
        Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])))
    }

    fn operator() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
    }

    fn locked() -> Anchors {
        let mut a = Anchors::new();
        a.trust(&Anchor { key_id: "op".into(), public_key: hex::encode(operator().verifying_key().to_bytes()) })
            .expect("a well-formed anchor");
        a
    }

    /// A leased hint as a node publishes it, the operator having authorized
    /// its hardware key at `authorized` until `auth_until`.
    fn hint(
        signer: &dyn MessageSigner,
        node: &str,
        wg: &str,
        tier: Tier,
        authorized: Tier,
        lease_end: u64,
        auth_until: u64,
    ) -> Hint {
        let b = bind(signer, &Terms { node_id: node, wg_pub: wg, tier: tier.as_str(), not_after: lease_end, quote_digest: None })
            .expect("the hardware signs");
        let auth = lock::authorize(
            "op",
            &operator(),
            &Claim { node_id: node, public_key: &b.node_key, tier: authorized.as_str(), not_after: auth_until },
        );
        Hint {
            node_id: node.into(),
            public_key: wg.into(),
            endpoints: vec!["192.0.2.9:51820".into()],
            overlay_addr: "10.90.0.40/32".into(),
            tier,
            seen_at: NOW,
            lease: Some(b),
            authorization: Some(auth),
            name: None,
            observed: vec![],
        }
    }

    fn pi_hint(wg: &str, lease_end: u64) -> Hint {
        hint(&pi(), "pi-gw", wg, Tier::Device, Tier::Device, lease_end, NOW + 30 * 86_400)
    }

    fn nobody(_: &str) -> Option<String> {
        None
    }

    fn open_at(d: &[u8], r: &mut Replay, now: u64) -> Result<Hint, Refusal> {
        open(d, "node-b", &locked(), &nobody, r, now, DEFAULT_CEILING)
    }

    #[test]
    fn a_signed_announcement_carries_the_new_key() {
        let h = pi_hint(NEW_WG, NOW + DEFAULT_LEASE);
        let d = seal(&pi(), &h, NOW).expect("sealed");
        let got = open_at(&d, &mut Replay::new(), NOW + 1).expect("accepted");
        assert_eq!(got, h);
        assert_eq!(got.public_key, NEW_WG);
    }

    #[test]
    fn an_ed25519_node_announces_too() {
        let h = hint(&server(), "node-c", NEW_WG, Tier::Platform, Tier::Platform, NOW + DEFAULT_LEASE, NOW + 86_400);
        let d = seal(&server(), &h, NOW).expect("sealed");
        assert_eq!(open_at(&d, &mut Replay::new(), NOW).expect("accepted").node_id, "node-c");
    }

    #[test]
    fn an_unleased_hint_is_never_announced_or_taken() {
        let mut h = pi_hint(NEW_WG, NOW + DEFAULT_LEASE);
        h.lease = None;
        assert!(seal(&pi(), &h, NOW).is_err());
        // Built by hand, with a signature that cannot be anyone's.
        let a = Announcement {
            v: VERSION,
            hint: serde_json::to_string(&h).unwrap(),
            sent_at: NOW,
            signature: "00".repeat(64),
        };
        let d = serde_json::to_vec(&a).unwrap();
        assert!(matches!(open_at(&d, &mut Replay::new(), NOW), Err(Refusal::Lease(_))));
    }

    #[test]
    fn an_unsigned_or_forged_announcement_is_refused() {
        let h = pi_hint(NEW_WG, NOW + DEFAULT_LEASE);
        let good = seal(&pi(), &h, NOW).expect("sealed");
        let mut a: Announcement = serde_json::from_slice(&good).unwrap();

        // No signature at all.
        let mut unsigned = a.clone();
        unsigned.signature = String::new();
        assert!(matches!(
            open_at(&serde_json::to_vec(&unsigned).unwrap(), &mut Replay::new(), NOW),
            Err(Refusal::BadSignature(_))
        ));

        // Signed by another board's key over the real node's lease.
        let forged = seal(&other_board(), &h, NOW);
        assert!(forged.is_err(), "a signer that did not bind the lease cannot seal it");
        let k = CellKey::of(&other_board()).unwrap();
        let bytes = signed_bytes(&h.node_id, &a.hint, NOW);
        let raw = other_board().sign(&bytes).unwrap();
        a.signature = k.seal(&bytes, &raw).unwrap();
        assert!(matches!(
            open_at(&serde_json::to_vec(&a).unwrap(), &mut Replay::new(), NOW),
            Err(Refusal::BadSignature(_))
        ));

        // The endpoints changed after signing: the hint text is what is signed.
        let mut moved: Announcement = serde_json::from_slice(&good).unwrap();
        moved.hint = moved.hint.replace("192.0.2.9", "203.0.113.66");
        assert!(matches!(
            open_at(&serde_json::to_vec(&moved).unwrap(), &mut Replay::new(), NOW),
            Err(Refusal::BadSignature(_))
        ));

        // A lease the other board bound and announced itself, for this node,
        // with no authorization of its key.
        let mut rogue = hint(&other_board(), "pi-gw", NEW_WG, Tier::Device, Tier::Device, NOW + 60, NOW + 86_400);
        rogue.authorization = pi_hint(NEW_WG, NOW + 60).authorization;
        let d = seal(&other_board(), &rogue, NOW).expect("sealed by its own key");
        assert!(matches!(open_at(&d, &mut Replay::new(), NOW), Err(Refusal::Lease(_))));

        assert!(matches!(open_at(b"hello", &mut Replay::new(), NOW), Err(Refusal::Malformed(_))));
        assert!(matches!(open_at(&vec![b' '; MAX_DATAGRAM + 1], &mut Replay::new(), NOW), Err(Refusal::TooLarge(_))));
    }

    #[test]
    fn a_replay_is_refused() {
        let mut r = Replay::new();
        let first = seal(&pi(), &pi_hint(OLD_WG, NOW + DEFAULT_LEASE), NOW).unwrap();
        assert!(open_at(&first, &mut r, NOW).is_ok());
        // The same datagram again.
        assert!(matches!(open_at(&first, &mut r, NOW + 5), Err(Refusal::Replay { .. })));
        // A later one is taken; the earlier one is still refused after it.
        let second = seal(&pi(), &pi_hint(NEW_WG, NOW + DEFAULT_LEASE + 10), NOW + 10).unwrap();
        assert!(open_at(&second, &mut r, NOW + 10).is_ok());
        assert!(matches!(open_at(&first, &mut r, NOW + 11), Err(Refusal::Replay { .. })));
        // Outside the window, refused whatever the guard holds.
        assert!(matches!(
            open_at(&first, &mut Replay::new(), NOW + FRESHNESS + 1),
            Err(Refusal::OutOfWindow { .. })
        ));
    }

    #[test]
    fn a_forged_announcement_does_not_advance_the_replay_guard() {
        let mut r = Replay::new();
        let h = pi_hint(NEW_WG, NOW + DEFAULT_LEASE);
        let mut a: Announcement = serde_json::from_slice(&seal(&pi(), &h, NOW + 100).unwrap()).unwrap();
        a.signature = "11".repeat(64);
        assert!(open_at(&serde_json::to_vec(&a).unwrap(), &mut r, NOW + 100).is_err());
        // The real node's earlier send time is still taken.
        let real = seal(&pi(), &h, NOW + 50).unwrap();
        assert!(open_at(&real, &mut r, NOW + 100).is_ok());
    }

    #[test]
    fn an_expired_authorization_or_lease_is_refused() {
        let lapsed = hint(&pi(), "pi-gw", NEW_WG, Tier::Device, Tier::Device, NOW + DEFAULT_LEASE, NOW - 1);
        let d = seal(&pi(), &lapsed, NOW).unwrap();
        assert!(matches!(open_at(&d, &mut Replay::new(), NOW), Err(Refusal::Lease(_))));

        let over = pi_hint(NEW_WG, NOW - 1);
        let d = seal(&pi(), &over, NOW).unwrap();
        assert!(matches!(open_at(&d, &mut Replay::new(), NOW), Err(Refusal::Lease(_))));
    }

    #[test]
    fn a_device_tier_node_cannot_announce_itself_higher() {
        // The board binds its lease at `platform`, which its key may not hold.
        let up = hint(&pi(), "pi-gw", NEW_WG, Tier::Platform, Tier::Device, NOW + 60, NOW + 86_400);
        let d = seal(&pi(), &up, NOW).unwrap();
        let e = open_at(&d, &mut Replay::new(), NOW).unwrap_err();
        assert!(matches!(e, Refusal::Lease(_)), "{e}");

        // Even with the operator's authorization at that tier, the key class
        // caps it: a Device-class key without a boot quote stays `device`.
        let up = hint(&pi(), "pi-gw", NEW_WG, Tier::Platform, Tier::Platform, NOW + 60, NOW + 86_400);
        let d = seal(&pi(), &up, NOW).unwrap();
        assert!(matches!(open_at(&d, &mut Replay::new(), NOW), Err(Refusal::Lease(_))));

        // A server key the operator admitted at `device` claims `platform`:
        // the authorization covers the tier, so it does not cover this.
        let up = hint(&server(), "node-z", NEW_WG, Tier::Platform, Tier::Device, NOW + 60, NOW + 86_400);
        let d = seal(&server(), &up, NOW).unwrap();
        assert!(matches!(open_at(&d, &mut Replay::new(), NOW), Err(Refusal::Lease(_))));
    }

    #[test]
    fn its_own_announcement_is_ignored() {
        let h = pi_hint(NEW_WG, NOW + 60);
        let d = seal(&pi(), &h, NOW).unwrap();
        let r = open(&d, "pi-gw", &locked(), &nobody, &mut Replay::new(), NOW, DEFAULT_CEILING);
        assert_eq!(r, Err(Refusal::Own));
    }

    #[test]
    fn a_handshake_under_the_previous_key_does_not_count() {
        // The key was replaced 20 seconds ago; the kernel still shows the
        // handshake made 40 seconds ago, under the key before it.
        let mut hs = BTreeMap::new();
        hs.insert("peer".to_string(), NOW - 40);
        let peers = [("peer", "192.0.2.2:51820")];
        assert_eq!(
            targets(peers.iter().copied(), &hs, NOW - 20, DEFAULT_PORT, NOW),
            vec!["192.0.2.2:51821".parse::<SocketAddr>().unwrap()]
        );
        hs.insert("peer".to_string(), NOW - 5);
        assert!(targets(peers.iter().copied(), &hs, NOW - 20, DEFAULT_PORT, NOW).is_empty());
    }

    #[test]
    fn targets_are_the_peers_without_a_recent_handshake() {
        let mut hs = BTreeMap::new();
        hs.insert("fresh".to_string(), NOW - 30);
        hs.insert("stale".to_string(), NOW - STALE_AFTER - 1);
        hs.insert("never".to_string(), 0);
        let peers = [
            ("fresh", "192.168.1.10:51820"),
            ("stale", "192.0.2.2:51820"),
            ("never", "[2001:db8::7]:51820"),
            ("unknown", "192.0.2.2:40000"),
            ("nowhere", "-"),
            ("zero", "0.0.0.0:51820"),
        ];
        let t = targets(peers.iter().copied(), &hs, 0, DEFAULT_PORT, NOW);
        assert_eq!(
            t,
            vec![
                "192.0.2.2:51821".parse::<SocketAddr>().unwrap(),
                "[2001:db8::7]:51821".parse::<SocketAddr>().unwrap(),
            ]
        );
    }
}
