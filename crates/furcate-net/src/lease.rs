//! A WireGuard key that lives for one lease, vouched for by the hardware.
//!
//! Kernel WireGuard holds its static key in kernel memory and cannot hand each
//! handshake to a TPM or a secure element, so the key cannot live in hardware.
//! What can be avoided is the key living anywhere *else*: on a node that opts
//! in, the privileged half generates the X25519 key in memory at boot and at
//! every renewal, gives it to the kernel on standard input, and writes it
//! nowhere. Nothing durable exists to copy.
//!
//! A key that changes needs something peers already believe to vouch for each
//! new one. That is the binding: the node's hardware key — a Pi's
//! firmware-held P-256 key, or the node's Ed25519 key elsewhere — signs the
//! node id, the WireGuard key, the tier and an expiry, plus the digest of a
//! boot quote where the platform produces one. It is the field set an anchor's
//! authorization covers in [`crate::lock`], signed by the machine rather than
//! the operator, because the key now changes too often for a person to sign
//! each one.
//!
//! ## Two signatures, two jobs
//!
//! - An anchor's authorization admits the node's **hardware key**, for a named
//!   node at a named tier, for as long as the operator chose. That is the
//!   operator's approval, and it is the same file and the same command as
//!   today; it names the hardware key where it used to name the WireGuard key.
//! - The hardware key's binding admits **one WireGuard key** for one lease.
//!
//! On a locked overlay a peer needs both, and the authorization must name the
//! key that signed the binding. A binding alone, from hardware nobody
//! admitted, is a machine introducing itself, and it is refused.
//!
//! ## Expiry is the revocation
//!
//! A copied WireGuard key is good until its lease ends; the next lease needs
//! the hardware again. A verifier refuses a lease that runs further ahead than
//! its ceiling, so a host that has been taken over cannot have its own
//! hardware sign one key for a year and keep it.

use crate::lock::{self, Anchors, Claim, State};
use crate::overlay::Hint;
use furcate_identity::MessageSigner;
use furcate_policy::delegation::CellKey;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Domain separation from every other signature in this tree, including an
/// anchor's authorization, which covers similar fields for a different
/// purpose.
const CONTEXT: &[u8] = b"furcate-overlay-lease-v1";

/// How long one key lives unless the node is configured otherwise.
pub const DEFAULT_LEASE: u64 = 12 * 60 * 60;

/// The furthest ahead a verifier accepts a lease's expiry, unless configured
/// otherwise. Four default leases: room for a node configured with longer
/// ones, and short enough that a binding is never a standing credential.
pub const DEFAULT_CEILING: u64 = 48 * 60 * 60;

/// The hardware's statement about one lease's key.
///
/// It carries no node id, WireGuard key or tier of its own: those are read
/// from the hint it arrives on, so the values a peer acts on are the values
/// that were signed, and there is no second copy to disagree with the first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The key that signed: `p256:<hex>` (compressed point) or
    /// `ed25519:<hex>`, written the way cell links write keys.
    pub node_key: String,
    /// Seconds since the epoch at which this key stops being this node's.
    pub not_after: u64,
    /// SHA-256 of the boot quote taken for this lease, hex, where the
    /// platform produces one. Signed when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_digest: Option<String>,
    /// Hex. Ed25519's 64 bytes, or P-256's low-S `r || s`.
    pub signature: String,
}

/// What a binding is about, in the exact terms that get signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms<'a> {
    pub node_id: &'a str,
    /// The WireGuard public key, base64 as WireGuard spells it.
    pub wg_pub: &'a str,
    pub tier: &'a str,
    pub not_after: u64,
    pub quote_digest: Option<&'a str>,
}

impl Terms<'_> {
    /// The bytes that are signed. Length-delimited, as in [`crate::lock`],
    /// because `node_id` comes from a machine that may not be friendly. The
    /// signing key is inside the signature, so a binding cannot be presented
    /// as having been made by a different key that happens to verify.
    pub fn bytes(&self, node_key: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(224);
        out.extend_from_slice(CONTEXT);
        for field in [self.node_id, node_key, self.wg_pub, self.tier, self.quote_digest.unwrap_or("")] {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out
    }
}

/// Why a binding was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The named key is not a key, or not written the one way keys are.
    BadKey { node: String, why: String },
    /// The quote digest is not 32 bytes of hex.
    BadQuote(String),
    /// The signature does not cover this node, key, tier and expiry.
    BadSignature(String),
    /// Correctly signed, and over.
    Expired { node: String, not_after: u64, now: u64 },
    /// Runs further ahead than this verifier accepts.
    TooLong { node: String, not_after: u64, now: u64, ceiling: u64 },
    /// Claims a tier its key may not be admitted at.
    OverTiered { node: String, why: String },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::BadKey { node, why } => write!(f, "`{node}` names a lease key that cannot be read: {why}"),
            Refusal::BadQuote(n) => write!(f, "`{n}` carries a quote digest that is not 32 bytes of hex"),
            Refusal::BadSignature(n) => write!(
                f,
                "`{n}` carries a lease signature that does not cover this node, key, tier and expiry"
            ),
            Refusal::Expired { node, not_after, now } => write!(
                f,
                "`{node}`'s overlay key was leased until {not_after}; it is now {now}. Its next key arrives with its next lease"
            ),
            Refusal::OverTiered { node, why } => write!(f, "`{node}`'s lease is refused: {why}"),
            Refusal::TooLong { node, not_after, now, ceiling } => write!(
                f,
                "`{node}`'s lease runs to {not_after}, {} seconds from now ({now}); this node accepts at most {ceiling}, \
                 because a lease that long is a standing credential",
                not_after.saturating_sub(*now)
            ),
        }
    }
}

impl std::error::Error for Refusal {}

fn check_quote(node: &str, q: &str) -> Result<(), Refusal> {
    let ok = q.len() == 64 && q.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(Refusal::BadQuote(node.to_string()))
    }
}

/// Sign one lease's key with the node's hardware key.
///
/// The signature is checked against the signer's own public key before it is
/// returned, and written in its one spelling, so a device that signed
/// something else is caught here rather than refused by every peer.
pub fn bind(signer: &dyn MessageSigner, terms: &Terms<'_>) -> Result<Binding, String> {
    if !crate::wg::is_key(terms.wg_pub) {
        return Err("that is not a wireguard public key, so there is nothing to bind".into());
    }
    if let Some(q) = terms.quote_digest {
        check_quote(terms.node_id, q).map_err(|e| e.to_string())?;
    }
    let key = CellKey::of(signer)?;
    let node_key = key.id();
    let bytes = terms.bytes(&node_key);
    let raw = signer
        .sign(&bytes)
        .map_err(|e| format!("the hardware did not sign the lease: {e:#}"))?;
    Ok(Binding {
        node_key,
        not_after: terms.not_after,
        quote_digest: terms.quote_digest.map(str::to_string),
        signature: key.seal(&bytes, &raw)?,
    })
}

/// Check a binding against the node, key and tier it arrived with.
///
/// Says nothing about whether the signing key belongs on this overlay; that is
/// [`verify_hint`]'s second half.
pub fn check(
    b: &Binding,
    node_id: &str,
    wg_pub: &str,
    tier: &str,
    now: u64,
    ceiling: u64,
) -> Result<(), Refusal> {
    let key = CellKey::parse(&b.node_key)
        .map_err(|why| Refusal::BadKey { node: node_id.to_string(), why })?;
    if let Some(q) = &b.quote_digest {
        check_quote(node_id, q)?;
    }
    crate::lock::admissible_tier(&b.node_key, tier, b.quote_digest.as_deref())
        .map_err(|why| Refusal::OverTiered { node: node_id.to_string(), why })?;
    let terms = Terms {
        node_id,
        wg_pub,
        tier,
        not_after: b.not_after,
        quote_digest: b.quote_digest.as_deref(),
    };
    key.verify_hex(&terms.bytes(&b.node_key), &b.signature)
        .map_err(|_| Refusal::BadSignature(node_id.to_string()))?;
    if b.not_after <= now {
        return Err(Refusal::Expired { node: node_id.to_string(), not_after: b.not_after, now });
    }
    if b.not_after - now > ceiling {
        return Err(Refusal::TooLong { node: node_id.to_string(), not_after: b.not_after, now, ceiling });
    }
    Ok(())
}

/// Check a hint before anything acts on its tier.
///
/// A hint without a lease is checked exactly as before: the anchor's
/// authorization must cover its WireGuard key. A hint with one must carry a
/// binding over its WireGuard key and tier by the hardware key, and on a
/// locked overlay an authorization by an anchor over that hardware key at that
/// tier. The authorization names the key, the binding is checked against it,
/// and neither is read from the other.
pub fn verify_hint(anchors: &Anchors, h: &Hint, now: u64, ceiling: u64) -> Result<State, String> {
    let tier = h.tier.as_str();
    let auth_not_after = h.authorization.as_ref().map(|a| a.not_after).unwrap_or_default();
    let admitted_key = match &h.lease {
        None => h.public_key.as_str(),
        Some(b) => {
            check(b, &h.node_id, &h.public_key, tier, now, ceiling).map_err(|e| e.to_string())?;
            b.node_key.as_str()
        }
    };
    lock::verify(
        anchors,
        &Claim { node_id: &h.node_id, public_key: admitted_key, tier, not_after: auth_not_after },
        h.authorization.as_ref(),
        now,
    )
    .map_err(|e| e.to_string())
}

/// Whether a hint heard on gossip may be passed on and used.
///
/// Gossip is carried by any member, so it is held to more than a coordinator
/// hint: it must have a lease, the lease must check, and its hardware key
/// must be one this node can show was admitted — by an anchor on a locked
/// overlay, or, on an unlocked one, by this node's own trust store naming that
/// key for that node. An unlocked overlay that took whatever key a neighbour
/// repeated would let any member replace any other's key.
pub fn verify_carried(
    anchors: &Anchors,
    trusted_key: Option<&str>,
    h: &Hint,
    now: u64,
    ceiling: u64,
) -> Result<(), String> {
    let Some(b) = &h.lease else {
        return Err(format!("`{}` arrived on gossip without a lease; only leased keys travel that way", h.node_id));
    };
    if anchors.state().is_locked() {
        return verify_hint(anchors, h, now, ceiling).map(|_| ());
    }
    check(b, &h.node_id, &h.public_key, h.tier.as_str(), now, ceiling).map_err(|e| e.to_string())?;
    let known = trusted_key.and_then(|k| CellKey::normalise(k).ok());
    if known.as_deref() == Some(b.node_key.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "`{}` arrived on gossip signed by {}, and this overlay has no anchors and no trust-store entry naming that key for it",
            h.node_id, b.node_key
        ))
    }
}

/// When a hint stops meaning anything: the earlier of its authorization and
/// its lease.
pub fn valid_until(h: &Hint) -> Option<u64> {
    let a = h.authorization.as_ref().map(|a| a.not_after);
    let l = h.lease.as_ref().map(|b| b.not_after);
    match (a, l) {
        (Some(a), Some(l)) => Some(a.min(l)),
        (a, l) => a.or(l),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::Anchor;
    use crate::overlay::Tier;
    use furcate_identity::{Ed25519Signer, SignerKey};
    use std::sync::Arc;

    const NOW: u64 = 1_786_838_400;
    const WG: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const WG2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    /// A P-256 key the way the Pi's firmware presents one: it reports a
    /// public key and returns DER signatures over SHA-256 of the message.
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

    fn terms<'a>(node: &'a str, wg: &'a str, not_after: u64) -> Terms<'a> {
        Terms { node_id: node, wg_pub: wg, tier: "platform", not_after, quote_digest: None }
    }

    /// Terms as a Device-class board signs them: at the tier its key may hold.
    fn device_terms<'a>(node: &'a str, wg: &'a str, not_after: u64) -> Terms<'a> {
        Terms { tier: "device", ..terms(node, wg, not_after) }
    }

    /// A hint as a leased node publishes it: its lease binding, and the
    /// operator's authorization of its hardware key.
    fn leased_hint(signer: &dyn MessageSigner, node: &str, wg: &str, lease_end: u64) -> Hint {
        let tier = match signer.public_key() {
            Ok(SignerKey::P256(_)) => Tier::Device,
            _ => Tier::Platform,
        };
        let b = bind(signer, &Terms { tier: tier.as_str(), ..terms(node, wg, lease_end) }).expect("the hardware signs");
        let auth = lock::authorize(
            "op",
            &operator(),
            &Claim { node_id: node, public_key: &b.node_key, tier: tier.as_str(), not_after: NOW + 30 * 86_400 },
        );
        Hint {
            node_id: node.into(),
            public_key: wg.into(),
            endpoints: vec![],
            overlay_addr: "192.0.2.9".into(),
            tier,
            seen_at: NOW,
            lease: Some(b),
            authorization: Some(auth),
            name: None,
            observed: vec![],
        }
    }

    #[test]
    fn a_p256_binding_round_trips() {
        let b = bind(&pi(), &device_terms("pi-gw", WG, NOW + DEFAULT_LEASE)).expect("signed");
        assert!(b.node_key.starts_with("p256:02") || b.node_key.starts_with("p256:03"));
        // DER from the firmware, kept in its one 64-byte spelling.
        assert_eq!(b.signature.len(), 128);
        assert_eq!(check(&b, "pi-gw", WG, "device", NOW, DEFAULT_CEILING), Ok(()));
    }

    #[test]
    fn an_ed25519_binding_round_trips() {
        let b = bind(&server(), &terms("node-b", WG, NOW + DEFAULT_LEASE)).expect("signed");
        assert!(b.node_key.starts_with("ed25519:"));
        assert_eq!(check(&b, "node-b", WG, "platform", NOW, DEFAULT_CEILING), Ok(()));
    }

    #[test]
    fn a_quote_digest_is_covered_by_the_signature() {
        let q = "ab".repeat(32);
        let mut t = terms("node-b", WG, NOW + 60);
        t.quote_digest = Some(&q);
        let mut b = bind(&server(), &t).expect("signed");
        assert_eq!(check(&b, "node-b", WG, "platform", NOW, DEFAULT_CEILING), Ok(()));
        b.quote_digest = Some("cd".repeat(32));
        assert_eq!(
            check(&b, "node-b", WG, "platform", NOW, DEFAULT_CEILING),
            Err(Refusal::BadSignature("node-b".into()))
        );
        b.quote_digest = Some("not hex".into());
        assert_eq!(
            check(&b, "node-b", WG, "platform", NOW, DEFAULT_CEILING),
            Err(Refusal::BadQuote("node-b".into()))
        );
    }

    #[test]
    fn a_binding_is_refused_for_any_other_key_node_or_tier() {
        let b = bind(&pi(), &device_terms("pi-gw", WG, NOW + 60)).expect("signed");
        let bad = |n: &str, k: &str, t: &str| check(&b, n, k, t, NOW, DEFAULT_CEILING);
        assert_eq!(bad("pi-gw", WG2, "device"), Err(Refusal::BadSignature("pi-gw".into())));
        assert_eq!(bad("other", WG, "device"), Err(Refusal::BadSignature("other".into())));
        assert_eq!(bad("pi-gw", WG, "soft"), Err(Refusal::BadSignature("pi-gw".into())));
        assert!(matches!(bad("pi-gw", WG, "attested"), Err(Refusal::OverTiered { .. })));
    }

    #[test]
    fn a_tampered_expiry_or_signature_is_refused() {
        let mut b = bind(&pi(), &device_terms("pi-gw", WG, NOW + 60)).expect("signed");
        b.not_after += 3600;
        assert_eq!(
            check(&b, "pi-gw", WG, "device", NOW, DEFAULT_CEILING),
            Err(Refusal::BadSignature("pi-gw".into()))
        );
        let mut b = bind(&server(), &terms("node-b", WG, NOW + 60)).expect("signed");
        let flipped = if b.signature.starts_with('0') { "1" } else { "0" };
        b.signature.replace_range(0..1, flipped);
        assert_eq!(
            check(&b, "node-b", WG, "platform", NOW, DEFAULT_CEILING),
            Err(Refusal::BadSignature("node-b".into()))
        );
        // A key swapped in for the one that signed.
        let mut b = bind(&pi(), &device_terms("pi-gw", WG, NOW + 60)).expect("signed");
        b.node_key = bind(&server(), &terms("pi-gw", WG, NOW + 60)).expect("signed").node_key;
        assert_eq!(
            check(&b, "pi-gw", WG, "device", NOW, DEFAULT_CEILING),
            Err(Refusal::BadSignature("pi-gw".into()))
        );
    }

    #[test]
    fn an_expired_lease_is_refused() {
        let b = bind(&pi(), &device_terms("pi-gw", WG, NOW)).expect("signed");
        assert_eq!(
            check(&b, "pi-gw", WG, "device", NOW, DEFAULT_CEILING),
            Err(Refusal::Expired { node: "pi-gw".into(), not_after: NOW, now: NOW })
        );
    }

    #[test]
    fn a_lease_longer_than_the_ceiling_is_refused() {
        let b = bind(&pi(), &device_terms("pi-gw", WG, NOW + 365 * 86_400)).expect("signed");
        assert!(matches!(
            check(&b, "pi-gw", WG, "device", NOW, DEFAULT_CEILING),
            Err(Refusal::TooLong { .. })
        ));
    }

    #[test]
    fn a_locked_overlay_admits_a_leased_pi_through_its_hardware_key() {
        let h = leased_hint(&pi(), "pi-gw", WG, NOW + DEFAULT_LEASE);
        assert_eq!(verify_hint(&locked(), &h, NOW, DEFAULT_CEILING), Ok(State::Locked { anchors: 1 }));
    }

    #[test]
    fn a_lease_from_hardware_nobody_admitted_is_refused() {
        // Signed correctly by real hardware, with no operator approval: the
        // machine is introducing itself.
        let mut h = leased_hint(&pi(), "pi-gw", WG, NOW + DEFAULT_LEASE);
        h.authorization = None;
        assert!(verify_hint(&locked(), &h, NOW, DEFAULT_CEILING).is_err());
        // Approved, but for a different hardware key than the one that signed.
        let other = leased_hint(&server(), "pi-gw", WG, NOW + DEFAULT_LEASE);
        h.authorization = other.authorization.clone();
        assert!(verify_hint(&locked(), &h, NOW, DEFAULT_CEILING).is_err());
    }

    #[test]
    fn the_tier_a_peer_acts_on_is_the_tier_that_was_signed() {
        let mut h = leased_hint(&pi(), "pi-gw", WG, NOW + DEFAULT_LEASE);
        h.tier = Tier::Attested;
        assert!(verify_hint(&locked(), &h, NOW, DEFAULT_CEILING).is_err());
    }

    #[test]
    fn a_device_tier_lease_round_trips_through_admission_and_gossip() {
        let h = leased_hint(&pi(), "pi-gw", WG, NOW + DEFAULT_LEASE);
        assert_eq!(h.tier, Tier::Device);
        assert_eq!(verify_hint(&locked(), &h, NOW, DEFAULT_CEILING), Ok(State::Locked { anchors: 1 }));
        assert_eq!(verify_carried(&locked(), None, &h, NOW, DEFAULT_CEILING), Ok(()));
        let key = h.lease.as_ref().unwrap().node_key.clone();
        assert_eq!(verify_carried(&Anchors::new(), Some(&key), &h, NOW, DEFAULT_CEILING), Ok(()));
        // As it travels: serialised, parsed, and checked again.
        let back: Hint = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(back.tier, Tier::Device);
        assert_eq!(verify_hint(&locked(), &back, NOW, DEFAULT_CEILING), Ok(State::Locked { anchors: 1 }));
        assert_eq!(valid_until(&back), Some(NOW + DEFAULT_LEASE));
    }

    #[test]
    fn a_device_class_key_signed_and_approved_at_platform_is_still_refused() {
        // Both halves say platform: the board signed it and an approval names
        // it. The key cannot hold that tier without a boot quote, so no node
        // carries it as one.
        let b = bind(&pi(), &terms("pi-gw", WG, NOW + DEFAULT_LEASE)).expect("the hardware signs");
        let auth = lock::authorize(
            "op",
            &operator(),
            &Claim { node_id: "pi-gw", public_key: &b.node_key, tier: "platform", not_after: NOW + 86_400 },
        );
        let h = Hint {
            tier: Tier::Platform,
            lease: Some(b),
            authorization: Some(auth),
            ..leased_hint(&pi(), "pi-gw", WG, NOW + DEFAULT_LEASE)
        };
        let why = verify_hint(&locked(), &h, NOW, DEFAULT_CEILING).expect_err("over-tiered");
        assert!(why.contains("`device` at most"), "{why}");
        assert!(verify_carried(&locked(), None, &h, NOW, DEFAULT_CEILING).is_err());
    }

    #[test]
    fn a_hint_without_a_lease_is_checked_as_it_always_was() {
        let auth = lock::authorize(
            "op",
            &operator(),
            &Claim { node_id: "node-b", public_key: WG, tier: "platform", not_after: NOW + 60 },
        );
        let h = Hint {
            node_id: "node-b".into(),
            public_key: WG.into(),
            endpoints: vec![],
            overlay_addr: "192.0.2.2".into(),
            tier: Tier::Platform,
            seen_at: NOW,
            lease: None,
            authorization: Some(auth),
            name: None,
            observed: vec![],
        };
        assert_eq!(verify_hint(&locked(), &h, NOW, DEFAULT_CEILING), Ok(State::Locked { anchors: 1 }));
        assert_eq!(verify_hint(&Anchors::new(), &h, NOW, DEFAULT_CEILING), Ok(State::Unlocked));
    }

    #[test]
    fn gossip_needs_a_key_this_node_can_show_was_admitted() {
        let h = leased_hint(&server(), "node-b", WG, NOW + DEFAULT_LEASE);
        let key = h.lease.as_ref().unwrap().node_key.clone();
        assert_eq!(verify_carried(&locked(), None, &h, NOW, DEFAULT_CEILING), Ok(()));
        // Unlocked: only a key the trust store names for that node.
        let open = Anchors::new();
        assert_eq!(verify_carried(&open, Some(&key), &h, NOW, DEFAULT_CEILING), Ok(()));
        assert!(verify_carried(&open, None, &h, NOW, DEFAULT_CEILING).is_err());
        let stranger = leased_hint(&pi(), "node-b", WG, NOW + DEFAULT_LEASE);
        assert!(verify_carried(&open, Some(&key), &stranger, NOW, DEFAULT_CEILING).is_err());
        // Nothing unleased travels on gossip.
        let mut bare = h.clone();
        bare.lease = None;
        assert!(verify_carried(&locked(), None, &bare, NOW, DEFAULT_CEILING).is_err());
    }

    #[test]
    fn a_p256_anchor_signs_and_verifies_an_authorization() {
        let op = pi();
        let key = CellKey::of(&op).expect("a key").id();
        let mut anchors = Anchors::new();
        anchors.trust(&Anchor { key_id: "op-se".into(), public_key: key.clone() }).expect("p256 anchor");
        let c = Claim { node_id: "pi-gw", public_key: "p256:00", tier: "platform", not_after: NOW + 60 };
        let auth = lock::authorize_with("op-se", &op, &c).expect("signed");
        assert_eq!(lock::verify(&anchors, &c, Some(&auth), NOW), Ok(State::Locked { anchors: 1 }));
        let tampered = Claim { tier: "attested", ..c.clone() };
        assert!(lock::verify(&anchors, &tampered, Some(&auth), NOW).is_err());
        // The uncompressed form an operator may paste is read as the same key.
        let long = match op.public_key().unwrap() {
            SignerKey::P256(b) => format!("p256:{}", hex::encode(b)),
            _ => unreachable!(),
        };
        let mut again = Anchors::new();
        again.trust(&Anchor { key_id: "op-se".into(), public_key: long }).expect("p256 anchor, uncompressed");
        assert!(lock::verify(&again, &c, Some(&auth), NOW).is_ok());
        assert!(again.trust(&Anchor { key_id: "x".into(), public_key: "p256:zz".into() }).is_err());
    }

    #[test]
    fn valid_until_is_the_earlier_of_the_two() {
        let h = leased_hint(&pi(), "pi-gw", WG, NOW + 60);
        assert_eq!(valid_until(&h), Some(NOW + 60));
    }
}
