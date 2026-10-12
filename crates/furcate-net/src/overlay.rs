//! An overlay whose coordinator cannot cut anyone off.
//!
//! Mesh products merge two questions that are not the same question. *Where is
//! this peer, what key does it use, which path reaches it* is a fact about the
//! world: it changes constantly, it is expensive for each node to discover
//! alone, and a coordinator is the right thing to answer it. *May this peer
//! talk to me, and about what* is a decision about this machine: its operator
//! already made it, it changes rarely, and no remote party should be able to
//! revise it.
//!
//! Every self-hostable mesh — Tailscale's coordination server, Headscale,
//! NetBird — distributes both together, so removing a node from the map removes
//! its access. That is the correct design for a corporate VPN, where cutting off
//! a lost laptop is the entire point. It is also precisely `isolate`, which
//! [`crate::…`] — specifically `furcate_policy::invariant` — refuses to every
//! principal, rule and delegation on this site.
//!
//! So the two are separated here, and the separation is the whole module:
//!
//! - The coordinator supplies **hints**: endpoints, public keys, observed
//!   paths. Information, and nothing else.
//! - Each node computes its own **peer set** by evaluating hints against policy
//!   it already holds.
//!
//! The property that falls out is the one worth having: losing the coordinator
//! degrades *discovery*, never *connectivity*. A node dropped from the map stops
//! being advertised to peers that have never met it; peers already holding its
//! key carry on. Cutting a machine off still requires what it always required —
//! an operator physically present with a key sealed in hardware.
//!
//! ## Last known good, kept on purpose
//!
//! A node that cannot reach the coordinator keeps the peers it already resolved.
//! This is not a cache for performance. It is the mechanism by which a
//! coordinator outage is not an outage, and it is why [`resolve`] takes the
//! previous peer set as an input rather than building from nothing each time.

use serde::{Deserialize, Serialize};

/// How much a member's identity is actually worth.
///
/// Graded rather than boolean, from evidence Furcate already computes: the
/// class of root of trust behind a node, and whether its boot chain was
/// measured. A mesh that admitted everything at one tier would have to decide
/// between refusing boards that cannot hold a secret and pretending a chip
/// serial is a key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Identified, not trusted. A fingerprint is an identifier anyone who can
    /// read the device can repeat, so this tier is reachable and may not
    /// originate anything privileged.
    #[default]
    Soft,
    /// Holds a key the hardware will use and not surrender, such as a Pi's
    /// firmware-held key, on a class of root that cannot say what the board
    /// booted. Carried for readings, roll-ups, cell traffic and ordinary
    /// requests; never the origin of a privileged call.
    Device,
    /// Holds a secret it can prove — a TPM, a secure element, a read-protected
    /// fuse — but its kernel is unverified.
    Platform,
    /// Holds a secret *and* its boot chain was measured, so the software making
    /// the claims is the software that was measured.
    Attested,
}

impl Tier {
    /// Every tier, lowest first.
    pub const ALL: [Tier; 4] = [Tier::Soft, Tier::Device, Tier::Platform, Tier::Attested];

    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Soft => "soft",
            Tier::Device => "device",
            Tier::Platform => "platform",
            Tier::Attested => "attested",
        }
    }

    /// The tier a name spells, if it spells one.
    pub fn parse(name: &str) -> Option<Tier> {
        Tier::ALL.into_iter().find(|t| t.as_str() == name)
    }

    /// Whether a member at this tier may originate privileged calls.
    ///
    /// The distinction the grading exists for. A node admitted on a chip serial
    /// or on a key whose boot nobody measured is reachable and is not trusted
    /// to act, and that is enforced rather than left as a convention somebody
    /// has to remember.
    pub fn may_originate_privileged(&self) -> bool {
        *self >= Tier::Platform
    }

    /// Derive the tier from evidence already collected elsewhere.
    ///
    /// One function so the ordering cannot drift between callers: a node must
    /// never reach `Attested` because two places each assumed the other checked
    /// the boot chain. A Device-class root proves possession of its key and
    /// nothing about the software using it, so without a measured boot it is
    /// held at `Device` rather than `Platform`.
    pub fn from_evidence(class: furcate_identity::AssuranceClass, boot_measured: bool) -> Tier {
        use furcate_identity::AssuranceClass;
        match (class, boot_measured) {
            (AssuranceClass::Soft, _) => Tier::Soft,
            (_, true) => Tier::Attested,
            (AssuranceClass::Device, false) => Tier::Device,
            (_, false) => Tier::Platform,
        }
    }
}

/// Why a request from this origin may not be privileged, if it may not.
///
/// The origin is the overlay address a connection came from, the machine a
/// credential proved, or both. Either one naming a peer this node carries
/// below [`Tier::Platform`] refuses: a device-tier member is reachable and
/// carries readings, and the call it makes is not one it may originate. An
/// origin that names no carried peer is not judged here.
pub fn refuse_privileged(
    peers: &[Peer],
    from: Option<std::net::IpAddr>,
    machine: Option<&str>,
) -> Option<String> {
    let addr_of = |p: &Peer| p.overlay_addr.split('/').next().and_then(|a| a.parse::<std::net::IpAddr>().ok());
    peers
        .iter()
        .find(|p| {
            !p.tier.may_originate_privileged()
                && ((from.is_some() && addr_of(p) == from) || machine == Some(p.node_id.as_str()))
        })
        .map(|p| {
            format!(
                "{} is a {}-tier member: it may carry readings and ordinary requests, and may not originate a privileged call",
                p.node_id,
                p.tier.as_str()
            )
        })
}

/// What the coordinator says about a peer. Information only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    pub node_id: String,
    /// The peer's overlay public key, base64 as WireGuard spells it.
    pub public_key: String,
    /// Addresses it has been seen on, best first.
    pub endpoints: Vec<String>,
    /// Address it holds inside the overlay.
    pub overlay_addr: String,
    /// What the coordinator believes about its identity. Advisory: the local
    /// policy decides what to do with it.
    pub tier: Tier,
    /// When the coordinator last had evidence for this. Used to prefer fresher
    /// information, never to expire a peer.
    pub seen_at: u64,
    /// Proof that somebody other than the coordinator said this machine
    /// belongs here.
    ///
    /// Optional in the type and not in the behaviour: a locked overlay refuses
    /// a hint that arrives without one. It is optional so that a node running
    /// this code can still read what an older coordinator publishes, and be
    /// the thing that refuses it rather than failing to parse it.
    #[serde(default)]
    pub authorization: Option<crate::lock::Authorization>,
    /// The hardware's binding of this lease's WireGuard key, on a node whose
    /// key lives for one lease and is never written down (see
    /// [`crate::lease`]). Absent on a node that keeps its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<crate::lease::Binding>,
    /// The name the machine calls itself, for overlay DNS.
    ///
    /// Self-asserted and not part of what an anchor signs, so it is never the
    /// only name a peer has: every member also resolves under a label derived
    /// from its node id, which is. Two members claiming one name resolve under
    /// neither (see [`crate::names`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Addresses a reflector saw this machine's packets arrive from — its
    /// side of a NAT, as the outside world sees it. A peer behind another NAT
    /// sends to these at the same time as this machine sends to it, which is
    /// what opens the path (see [`crate::punch`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed: Vec<String>,
}

/// A peer this node has decided to carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub overlay_addr: String,
    pub tier: Tier,
    /// Whether this entry came from a live hint or from what was already held.
    pub source: Source,
    pub resolved_at: u64,
    /// The name the peer gave itself, if any. See [`Hint::name`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When the authorization this peer was admitted on runs out, if it was
    /// admitted on one. Carried so that what this node *says* about a peer —
    /// its overlay name — stops on the signed date even while the tunnel is
    /// retained as last known good.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
    /// When this peer's leased key stops being its key. Unlike an
    /// authorization's expiry this ends the tunnel too, retained or not: the
    /// node holding the key replaced it, so whoever still presents it is not
    /// that node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_until: Option<u64>,
    /// Every address worth trying for this peer, best first: where it listens,
    /// then where reflectors saw it. `endpoint` is the first of these; the rest
    /// are what hole punching works through before a relay is used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The coordinator supplied it this round.
    Hint,
    /// Retained from a previous resolution. Not a cache — the mechanism by
    /// which a coordinator outage is not an outage.
    Retained,
}

/// Why a hint did not become a peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub node_id: String,
    pub why: String,
}

/// The outcome of one resolution pass.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub peers: Vec<Peer>,
    /// Hints local policy declined. Kept and reported, because a coordinator
    /// offering peers this node will not carry is worth seeing.
    pub refused: Vec<Refused>,
    /// Peers retained because no hint arrived for them this round.
    pub retained: usize,
}

impl Resolution {
    pub fn peer(&self, node_id: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.node_id == node_id)
    }

    /// Peers that may originate privileged calls.
    pub fn privileged(&self) -> Vec<&Peer> {
        self.peers.iter().filter(|p| p.tier.may_originate_privileged()).collect()
    }
}

/// How far this overlay's traffic actually travels.
///
/// Post-quantum key exchange — Rosenpass feeding WireGuard's pre-shared-key
/// input — defends against an attacker recording ciphertext today and
/// decrypting it once the arithmetic gets cheaper. That is a real threat and it
/// requires sustained capture of the traffic.
///
/// On a mesh whose peers all sit on one switch, sustained capture means already
/// being inside the rack, at which point the recording is the least of it. So
/// the honest answer at this topology is that it is not yet warranted — and the
/// honest thing to do with that answer is to make it expire on its own rather
/// than depend on somebody remembering to revisit it.
///
/// This computes the condition. When any peer's endpoint stops being on the
/// local segment, the traffic starts crossing something the operator does not
/// own, and the calculation changes without anybody having to notice.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// Every peer is on the local segment. Traffic never leaves the switch.
    OnSegment,
    /// At least one peer is reached across something else.
    OffSegment { peers: Vec<String> },
    /// No peer has a known endpoint, so nothing can be said. The default,
    /// because a mesh nobody can locate must not report itself as contained.
    #[default]
    Unknown,
}

impl Exposure {
    /// Whether a post-quantum key exchange is worth its daemon here.
    ///
    /// `false` on a single segment is a judgement about topology, not about
    /// cryptography: the same mesh spanning two buildings would answer
    /// differently, and that is the point of computing it rather than deciding
    /// it once.
    pub fn warrants_post_quantum(&self) -> bool {
        matches!(self, Exposure::OffSegment { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Exposure::OnSegment => "on_segment",
            Exposure::OffSegment { .. } => "off_segment",
            Exposure::Unknown => "unknown",
        }
    }
}

/// Judge exposure from the peer set and this node's own segment.
///
/// `segment` is the local address with its prefix, e.g. `192.168.1.30/24`. Only
/// IPv4 prefixes on byte boundaries are compared, because anything finer would
/// be a subnet calculator and the question here is coarse: same wire, or not.
/// A prefix that is not on a byte boundary answers `Unknown` rather than
/// guessing, since guessing wrong in the safe direction costs a daemon and
/// guessing wrong in the other direction is worse.
pub fn exposure(peers: &[Peer], segment: &str) -> Exposure {
    let Some((addr, prefix)) = segment.split_once('/') else {
        return Exposure::Unknown;
    };
    let Ok(bits) = prefix.parse::<u32>() else {
        return Exposure::Unknown;
    };
    if bits % 8 != 0 || bits == 0 || addr.contains(':') {
        return Exposure::Unknown;
    }
    let octets = (bits / 8) as usize;
    let local: Vec<&str> = addr.split('.').take(octets).collect();
    if local.len() != octets {
        return Exposure::Unknown;
    }

    let mut off = Vec::new();
    let mut known = 0;
    for p in peers {
        let Some(endpoint) = &p.endpoint else { continue };
        let host = endpoint.rsplit_once(':').map(|(h, _)| h).unwrap_or(endpoint);
        if host.contains(':') {
            continue;
        }
        known += 1;
        let theirs: Vec<&str> = host.split('.').take(octets).collect();
        if theirs != local {
            off.push(p.node_id.clone());
        }
    }

    match (known, off.is_empty()) {
        (0, _) => Exposure::Unknown,
        (_, true) => Exposure::OnSegment,
        (_, false) => Exposure::OffSegment { peers: off },
    }
}

/// Resolve a peer set from hints, what was already held, and local policy.
///
/// `admits` is the local decision — in practice the policy engine, asked
/// whether this node will carry that one. It is a closure rather than a policy
/// handle so this module stays free of a dependency on the engine and so the
/// separation being argued for is visible in the signature: hints go in as
/// data, and the only thing that can *authorise* is supplied by the caller.
///
/// A peer already held is never dropped for want of a hint. That is the whole
/// design: the coordinator going quiet must not take the network with it.
pub fn resolve<F>(
    hints: &[Hint],
    held: &[Peer],
    now: u64,
    mut admits: F,
) -> Resolution
where
    F: FnMut(&Hint) -> Result<(), String>,
{
    let mut peers: Vec<Peer> = Vec::new();
    let mut refused: Vec<Refused> = Vec::new();

    for h in hints {
        if let Err(why) = admits(h) {
            refused.push(Refused { node_id: h.node_id.clone(), why });
            continue;
        }
        peers.push(Peer {
            node_id: h.node_id.clone(),
            public_key: h.public_key.clone(),
            // Best endpoint first, and `None` rather than an empty string when
            // the coordinator knows the peer exists but not where it is — a
            // peer with no endpoint can still be reached by one that dials in.
            endpoint: h.endpoints.first().cloned(),
            overlay_addr: h.overlay_addr.clone(),
            tier: h.tier,
            source: Source::Hint,
            resolved_at: now,
            name: h.name.clone(),
            valid_until: crate::lease::valid_until(h),
            lease_until: h.lease.as_ref().map(|b| b.not_after),
            candidates: candidates(h),
        });
    }

    // Everything held for which no hint arrived. Kept, not expired.
    let mut retained = 0;
    for p in held {
        if peers.iter().any(|x| x.node_id == p.node_id) {
            continue;
        }
        // A peer the coordinator explicitly offered and policy refused is not
        // retained: that is a local decision and it wins over history.
        if refused.iter().any(|r| r.node_id == p.node_id) {
            continue;
        }
        // A leased key past its lease is not retained. Retention covers a
        // coordinator going quiet; it cannot outlive the key, because the node
        // has already replaced it and its new key arrives with a new binding.
        if let Some(until) = p.lease_until.filter(|t| *t <= now) {
            refused.push(Refused {
                node_id: p.node_id.clone(),
                why: format!("its overlay key was leased until {until}; it is now {now}, and no newer lease has arrived"),
            });
            continue;
        }
        retained += 1;
        peers.push(Peer { source: Source::Retained, ..p.clone() });
    }

    peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    Resolution { peers, refused, retained }
}

/// Combine what the coordinator said with what gossip carried.
///
/// A gossiped hint replaces the coordinator's for the same node only when it
/// carries a later lease, which is the case this exists for: a node that
/// rebooted with a new key while the coordinator was down, or before the
/// coordinator caught up. Gossip without a lease adds nothing; the caller
/// has already refused it.
pub fn merge(coordinator: &[Hint], gossip: &[Hint]) -> Vec<Hint> {
    let mut out: Vec<Hint> = coordinator.to_vec();
    for g in gossip {
        let Some(gl) = &g.lease else { continue };
        match out.iter_mut().find(|h| h.node_id == g.node_id) {
            Some(h) => {
                if h.lease.as_ref().is_none_or(|l| l.not_after < gl.not_after) {
                    *h = g.clone();
                }
            }
            None => out.push(g.clone()),
        }
    }
    out
}

/// Listening endpoints first, then reflected ones, each once.
///
/// Listening addresses lead because on a shared segment they are the path that
/// does not leave the building; a reflected address is what the far side of a
/// NAT looks like and is only better when the two are on different networks,
/// which the punching attempt finds out by trying.
fn candidates(h: &Hint) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in h.endpoints.iter().chain(h.observed.iter()) {
        if !e.is_empty() && !out.contains(e) {
            out.push(e.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_786_838_400;

    fn leased(id: &str, key: &str, until: u64) -> Hint {
        Hint {
            public_key: key.into(),
            lease: Some(crate::lease::Binding {
                node_key: "p256:02".into(),
                not_after: until,
                quote_digest: None,
                signature: String::new(),
            }),
            ..hint(id, Tier::Platform)
        }
    }

    #[test]
    fn a_retained_peer_is_dropped_when_its_lease_ends() {
        let first = resolve(&[leased("pi", "old", NOW + 60)], &[], NOW, |_| Ok(()));
        assert_eq!(first.peers[0].lease_until, Some(NOW + 60));
        // Coordinator silent, lease still running: kept.
        let quiet = resolve(&[], &first.peers, NOW + 30, |_| Ok(()));
        assert_eq!(quiet.retained, 1);
        // Coordinator silent, lease over: not carried, and said why.
        let over = resolve(&[], &first.peers, NOW + 60, |_| Ok(()));
        assert!(over.peers.is_empty());
        assert!(over.refused[0].why.contains("leased until"));
    }

    #[test]
    fn an_unleased_peer_is_still_retained_indefinitely() {
        let first = resolve(&[hint("node-b", Tier::Platform)], &[], NOW, |_| Ok(()));
        let later = resolve(&[], &first.peers, NOW + 10 * 365 * 86_400, |_| Ok(()));
        assert_eq!(later.retained, 1);
    }

    #[test]
    fn gossip_with_a_later_lease_replaces_the_coordinators_key() {
        let coord = [leased("pi", "old", NOW + 60), hint("node-b", Tier::Platform)];
        let gossip = [leased("pi", "new", NOW + 3600)];
        let m = merge(&coord, &gossip);
        assert_eq!(m.len(), 2);
        assert_eq!(m.iter().find(|h| h.node_id == "pi").unwrap().public_key, "new");
        // An older lease does not roll a key back.
        let m = merge(&[leased("pi", "new", NOW + 3600)], &[leased("pi", "old", NOW + 60)]);
        assert_eq!(m[0].public_key, "new");
    }

    #[test]
    fn gossip_reaches_a_peer_when_the_coordinator_says_nothing() {
        let m = merge(&[], &[leased("pi", "new", NOW + 3600), hint("node-b", Tier::Platform)]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].node_id, "pi");
    }

    fn hint(id: &str, tier: Tier) -> Hint {
        Hint {
            node_id: id.into(),
            public_key: format!("{id}-pubkey"),
            endpoints: vec!["192.168.1.10:51820".into()],
            overlay_addr: "10.90.0.20/32".into(),
            tier,
            seen_at: NOW, lease: None,
            authorization: None,
            name: None,
            observed: vec![],
        }
    }

    fn yes(_: &Hint) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn reflected_addresses_follow_listening_ones_and_are_not_repeated() {
        let mut h = hint("a", Tier::Platform);
        h.observed = vec!["203.0.113.7:51820".into(), "192.168.1.10:51820".into()];
        let r = resolve(&[h], &[], NOW, yes);
        assert_eq!(
            r.peers[0].candidates,
            vec!["192.168.1.10:51820".to_string(), "203.0.113.7:51820".to_string()]
        );
        // The configured endpoint is unchanged by reflection: the first
        // listening address, as before.
        assert_eq!(r.peers[0].endpoint.as_deref(), Some("192.168.1.10:51820"));
    }

    #[test]
    fn a_hint_that_local_policy_admits_becomes_a_peer() {
        let r = resolve(&[hint("node-a", Tier::Platform)], &[], NOW, yes);
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].source, Source::Hint);
        assert_eq!(r.peers[0].endpoint.as_deref(), Some("192.168.1.10:51820"));
    }

    #[test]
    fn the_coordinator_cannot_add_a_peer_this_node_refuses() {
        // Hints are information. The only thing that authorises is supplied by
        // the caller, which is the entire argument of this module made
        // mechanical.
        let r = resolve(&[hint("stranger", Tier::Soft)], &[], NOW, |_| {
            Err("no rule permits it".into())
        });
        assert!(r.peers.is_empty());
        assert_eq!(r.refused.len(), 1);
        assert_eq!(r.refused[0].why, "no rule permits it");
    }

    #[test]
    fn losing_the_coordinator_does_not_lose_the_network() {
        // The property the whole design exists for. No hints at all, and every
        // peer already held carries on.
        let first = resolve(&[hint("node-a", Tier::Platform)], &[], NOW, yes);
        let after = resolve(&[], &first.peers, NOW + 3600, yes);
        assert_eq!(after.peers.len(), 1);
        assert_eq!(after.peers[0].source, Source::Retained);
        assert_eq!(after.retained, 1);
    }

    #[test]
    fn a_peer_dropped_from_the_map_is_not_cut_off() {
        // It stops being advertised to nodes that have never met it. Nodes
        // already holding its key keep talking to it — which is the difference
        // between de-advertising and isolating.
        let held = resolve(&[hint("node-a", Tier::Platform), hint("node-b", Tier::Platform)], &[], NOW, yes);
        assert_eq!(held.peers.len(), 2);

        // The coordinator now offers only one of them.
        let after = resolve(&[hint("node-b", Tier::Platform)], &held.peers, NOW + 60, yes);
        assert_eq!(after.peers.len(), 2, "the dropped peer is retained");
        assert_eq!(after.peer("node-a").unwrap().source, Source::Retained);
        assert_eq!(after.peer("node-b").unwrap().source, Source::Hint);
    }

    #[test]
    fn a_local_refusal_beats_history() {
        // Retention protects against the coordinator going quiet, not against
        // this node's own operator changing their mind. A peer explicitly
        // refused by local policy is dropped even though it was held.
        let held = resolve(&[hint("node-a", Tier::Platform)], &[], NOW, yes);
        let after = resolve(&[hint("node-a", Tier::Platform)], &held.peers, NOW + 60, |_| {
            Err("operator removed it".into())
        });
        assert!(after.peers.is_empty());
        assert_eq!(after.refused.len(), 1);
    }

    #[test]
    fn a_fresh_hint_replaces_a_retained_entry_rather_than_duplicating_it() {
        let held = resolve(&[hint("node-a", Tier::Platform)], &[], NOW, yes);
        let mut moved = hint("node-a", Tier::Platform);
        moved.endpoints = vec!["192.168.1.99:51820".into()];
        let after = resolve(&[moved], &held.peers, NOW + 60, yes);
        assert_eq!(after.peers.len(), 1);
        assert_eq!(after.peers[0].endpoint.as_deref(), Some("192.168.1.99:51820"));
        assert_eq!(after.retained, 0);
    }

    #[test]
    fn a_peer_whose_location_is_unknown_is_still_a_peer() {
        // It cannot be dialled and it can still dial in. An empty endpoint
        // string would be written into a configuration and fail to parse.
        let mut h = hint("roaming", Tier::Platform);
        h.endpoints.clear();
        let r = resolve(&[h], &[], NOW, yes);
        assert_eq!(r.peers.len(), 1);
        assert!(r.peers[0].endpoint.is_none());
    }

    fn at(id: &str, endpoint: Option<&str>) -> Peer {
        Peer {
            node_id: id.into(),
            public_key: "k".into(),
            endpoint: endpoint.map(String::from),
            overlay_addr: "10.90.0.40/32".into(),
            tier: Tier::Platform,
            source: Source::Hint,
            resolved_at: 0,
            name: None,
            valid_until: None,
            lease_until: None,
            candidates: vec![],
        }
    }

    #[test]
    fn a_mesh_on_one_switch_does_not_yet_warrant_a_post_quantum_daemon() {
        // A judgement about topology rather than about cryptography: sustained
        // capture of this traffic means already being inside the rack.
        let e = exposure(&[at("node-b", Some("192.168.1.31:51820"))], "192.168.1.30/24");
        assert_eq!(e, Exposure::OnSegment);
        assert!(!e.warrants_post_quantum());
    }

    #[test]
    fn one_peer_off_the_segment_changes_the_answer_on_its_own() {
        // The reason this is computed rather than decided once. Nobody has to
        // remember to revisit it when a second site appears.
        let e = exposure(
            &[
                at("node-b", Some("192.168.1.31:51820")),
                at("faraway", Some("203.0.113.9:51820")),
            ],
            "192.168.1.30/24",
        );
        assert_eq!(e, Exposure::OffSegment { peers: vec!["faraway".into()] });
        assert!(e.warrants_post_quantum());
    }

    #[test]
    fn no_known_endpoint_says_nothing_rather_than_saying_safe() {
        // Reporting `on_segment` for a mesh nobody can locate would be the one
        // answer that is certainly unjustified.
        assert_eq!(exposure(&[at("a", None)], "192.168.1.30/24"), Exposure::Unknown);
        assert_eq!(exposure(&[], "192.168.1.30/24"), Exposure::Unknown);
    }

    #[test]
    fn a_prefix_this_cannot_compare_exactly_is_unknown_not_guessed() {
        // Guessing wrong toward safety costs a daemon; guessing wrong the other
        // way costs the thing the daemon was for.
        let p = [at("b", Some("192.168.1.31:51820"))];
        assert_eq!(exposure(&p, "192.168.1.30/22"), Exposure::Unknown);
        assert_eq!(exposure(&p, "192.168.1.30"), Exposure::Unknown);
        assert_eq!(exposure(&p, "fd00::1/64"), Exposure::Unknown);
    }

    #[test]
    fn tiers_are_ordered_and_only_the_upper_two_may_originate_anything() {
        assert!(Tier::Soft < Tier::Device);
        assert!(Tier::Device < Tier::Platform);
        assert!(Tier::Platform < Tier::Attested);
        assert!(!Tier::Soft.may_originate_privileged());
        assert!(!Tier::Device.may_originate_privileged());
        assert!(Tier::Platform.may_originate_privileged());
        assert!(Tier::Attested.may_originate_privileged());
    }

    #[test]
    fn a_measured_boot_without_a_secret_is_not_attested() {
        // Measuring a boot chain says the kernel is what was measured. It says
        // nothing about the node being able to prove it is itself.
        use furcate_identity::AssuranceClass as C;
        assert_eq!(Tier::from_evidence(C::Tpm, true), Tier::Attested);
        assert_eq!(Tier::from_evidence(C::Tpm, false), Tier::Platform);
        assert_eq!(Tier::from_evidence(C::Soft, true), Tier::Soft);
        assert_eq!(Tier::from_evidence(C::Soft, false), Tier::Soft);
    }

    #[test]
    fn a_device_class_key_without_a_measured_boot_is_device_and_never_platform() {
        use furcate_identity::AssuranceClass as C;
        assert_eq!(Tier::from_evidence(C::Device, false), Tier::Device);
        // The classes existing nodes run on keep the tier they had.
        for c in [C::SecureElement, C::Tee, C::Dice, C::Tpm] {
            assert_eq!(Tier::from_evidence(c, false), Tier::Platform, "{c:?}");
        }
    }

    #[test]
    fn a_tier_round_trips_through_its_name_and_through_json() {
        for t in Tier::ALL {
            assert_eq!(Tier::parse(t.as_str()), Some(t));
            let j = serde_json::to_string(&t).unwrap();
            assert_eq!(j, format!("\"{}\"", t.as_str()));
            assert_eq!(serde_json::from_str::<Tier>(&j).unwrap(), t);
        }
        assert_eq!(Tier::parse("hard"), None);
    }

    #[test]
    fn a_device_tier_peer_is_refused_as_the_origin_of_a_privileged_call() {
        let mut pi = hint("pi-gw", Tier::Device);
        pi.overlay_addr = "10.90.0.40/32".into();
        let mut server = hint("node-a", Tier::Platform);
        server.overlay_addr = "10.90.0.10/32".into();
        let r = resolve(&[pi, server], &[], NOW, yes);
        let from = |a: &str| Some(a.parse::<std::net::IpAddr>().unwrap());

        let why = refuse_privileged(&r.peers, from("10.90.0.40"), None).expect("refused by address");
        assert!(why.contains("pi-gw") && why.contains("device-tier"), "{why}");
        assert!(refuse_privileged(&r.peers, None, Some("pi-gw")).is_some(), "refused by credential");
        // Its credential arriving from another address is still its call.
        assert!(refuse_privileged(&r.peers, from("10.90.0.10"), Some("pi-gw")).is_some());

        assert_eq!(refuse_privileged(&r.peers, from("10.90.0.10"), Some("node-a")), None);
        assert_eq!(refuse_privileged(&r.peers, from("127.0.0.1"), None), None);
        assert_eq!(refuse_privileged(&r.peers, None, None), None);
        // Not privileged, and still carried.
        assert!(r.peer("pi-gw").is_some());
        assert_eq!(r.privileged().len(), 1);
    }

    #[test]
    fn the_peer_set_is_ordered_so_a_rendered_config_is_stable() {
        // An unstable order rewrites the interface configuration every pass and
        // makes a diff meaningless.
        let r = resolve(
            &[hint("zulu", Tier::Soft), hint("alpha", Tier::Soft)],
            &[],
            NOW,
            yes,
        );
        let ids: Vec<&str> = r.peers.iter().map(|p| p.node_id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "zulu"]);
    }

    #[test]
    fn privileged_peers_are_the_ones_that_earned_it() {
        let r = resolve(
            &[hint("pi", Tier::Soft), hint("node-a", Tier::Attested)],
            &[],
            NOW,
            yes,
        );
        let p = r.privileged();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].node_id, "node-a");
    }
}
