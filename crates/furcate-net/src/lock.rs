//! Who is allowed to say that a machine belongs here.
//!
//! The coordinator hands each node a list of hints, and every hint carries a
//! `tier` describing what the coordinator believes about that peer's identity.
//! The node's policy then decides on the strength of that belief. Which means
//! the coordinator's claim about a peer *is* the identity check: whatever can
//! answer on the site address can assert a tier, and a WireGuard peer appears
//! on every machine that asked.
//!
//! That is the thing this module removes. A hint only becomes a peer if it
//! carries an authorization signed by a key the node already trusts, held
//! somewhere other than the coordinator. A coordinator that is taken over can
//! then still withhold peers, delay them, or lie about endpoints — denial, and
//! recoverable — but it cannot introduce a machine, because it cannot produce
//! the signature and the node checks rather than believes.
//!
//! ## What is signed, and why each field is in there
//!
//! The signature covers the node's identity, its overlay key, its tier and an
//! expiry, because leaving any one of them out leaves a way to reuse a genuine
//! signature for something it was not issued for:
//!
//! - **without the public key**, an authorization for a machine is an
//!   authorization for anyone who claims that machine's name, with their own
//!   key;
//! - **without the tier**, a signature issued for a peer the policy barely
//!   admits is a signature for one it trusts completely;
//! - **without an expiry**, a machine that is decommissioned, sold or stolen
//!   carries a valid authorization forever.
//!
//! Fields are length-delimited rather than joined by a separator. A separator
//! is forgeable whenever a field can contain it, and `node_id` comes from a
//! machine that may not be friendly.
//!
//! ## Being unlocked is a state, not an absence
//!
//! A site with no anchors configured cannot verify anything. Refusing every
//! peer there would break every existing site on upgrade; accepting quietly
//! would leave an operator believing in a check that is not running. So it is
//! neither: `State::Unlocked` is carried explicitly, reported wherever the
//! overlay is shown, and there is deliberately no way to hold anchors and not
//! check them — the only two states are "no anchors, and it says so" and
//! "anchors, and every peer is verified".

use furcate_policy::delegation::CellKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use crate::overlay::Tier;

/// Domain separation. A signature made for one purpose must not verify for
/// another, and every other signer in this tree signs different bytes.
const CONTEXT: &[u8] = b"furcate-overlay-authorization-v1";

/// One key that may authorize a machine onto this overlay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Which key this is, so an authorization can name the one it used and a
    /// key can be retired without retiring the rest.
    pub key_id: String,
    /// The public key: bare hex or `ed25519:<hex>` for Ed25519, as anchors
    /// have always been written, or `p256:<hex>` for an ECDSA P-256 key such
    /// as a Secure Enclave, TPM or firmware-held key. Read by the same code
    /// that reads cell link keys, so the two cannot disagree about a key.
    pub public_key: String,
}

/// What a node will accept an authorization from.
///
/// Distributed out of band — by the installer, by an operator, by anything
/// that is not the coordinator. A coordinator that could add to this set could
/// authorize itself, and the whole arrangement would be decorative.
#[derive(Clone, Debug, Default)]
pub struct Anchors {
    keys: BTreeMap<String, CellKey>,
}

impl Anchors {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an anchor, refusing anything that is not a usable key.
    ///
    /// Malformed here rather than at verification time: an anchor nobody can
    /// verify with is a hole that only shows up the day it is needed.
    pub fn trust(&mut self, a: &Anchor) -> Result<(), Refusal> {
        let key = CellKey::normalise(&a.public_key)
            .and_then(|id| CellKey::parse(&id))
            .map_err(|_| Refusal::MalformedAnchor(a.key_id.clone()))?;
        self.keys.insert(a.key_id.clone(), key);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether this overlay is checking authorizations at all.
    pub fn state(&self) -> State {
        if self.keys.is_empty() {
            State::Unlocked
        } else {
            State::Locked { anchors: self.keys.len() }
        }
    }

    /// Read anchors from the JSON a site publishes or an operator writes.
    ///
    /// Every anchor must parse. A file with one bad entry is a file somebody
    /// edited by hand and got wrong, and silently trusting the rest of it is
    /// how a set ends up smaller than the operator believes.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, Refusal> {
        let list: Vec<Anchor> = serde_json::from_value(v.clone())
            .map_err(|e| Refusal::MalformedAnchor(e.to_string()))?;
        let mut out = Self::new();
        for a in &list {
            out.trust(a)?;
        }
        Ok(out)
    }
}

/// Whether authorizations are being checked, and against how many keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// No anchors. Nothing is verified, and this is said out loud.
    Unlocked,
    Locked { anchors: usize },
}

impl State {
    pub fn is_locked(&self) -> bool {
        matches!(self, State::Locked { .. })
    }

    /// How this reads on a screen. An operator should be able to tell at a
    /// glance whether the check is running.
    pub fn describe(&self) -> String {
        match self {
            State::Unlocked => {
                "unlocked — the coordinator's word is taken for who belongs here".into()
            }
            State::Locked { anchors } => {
                format!("locked — every peer is verified against {anchors} key(s) held off the coordinator")
            }
        }
    }
}

/// A signed statement that a machine may join, and on what terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// Which anchor signed. Named, not searched for: trying every key in turn
    /// hides the case where the expected signer is gone.
    pub key_id: String,
    /// Seconds since the epoch after which this means nothing.
    pub not_after: u64,
    /// Ed25519 signature, hex.
    pub signature: String,
}

/// What an authorization is about, in the exact terms that get signed.
///
/// `public_key` is the machine's WireGuard key for a node that keeps one, or
/// its hardware key (`p256:<hex>` or `ed25519:<hex>`) for a node whose
/// WireGuard key lives for one lease (see [`crate::lease`]). The second
/// admits the hardware, which then vouches for each lease's key itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim<'a> {
    pub node_id: &'a str,
    pub public_key: &'a str,
    pub tier: &'a str,
    pub not_after: u64,
}

impl Claim<'_> {
    /// The bytes that are signed.
    ///
    /// Length-delimited so no field can be made to look like the end of
    /// another. `a|b` and `ab|` are the same string once a separator is
    /// allowed to appear inside a field, and `node_id` is attacker-supplied.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(CONTEXT);
        for field in [self.node_id, self.public_key, self.tier] {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.not_after.to_be_bytes());
        out
    }
}

/// Why a hint was not accepted as authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No authorization at all, on an overlay that requires one.
    Unauthorized(String),
    /// Signed by a key this node does not trust.
    UnknownAnchor { node: String, key_id: String },
    /// The signature does not match what it claims to cover.
    BadSignature(String),
    /// Correctly signed, and stale.
    Expired { node: String, not_after: u64, now: u64 },
    MalformedAnchor(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Unauthorized(n) => write!(
                f,
                "`{n}` arrived with no authorization and this overlay is locked"
            ),
            Refusal::UnknownAnchor { node, key_id } => write!(
                f,
                "`{node}` was authorized by `{key_id}`, which this node does not trust"
            ),
            Refusal::BadSignature(n) => write!(
                f,
                "`{n}` carries a signature that does not cover what it claims"
            ),
            Refusal::Expired { node, not_after, now } => write!(
                f,
                "`{node}` was authorized until {not_after}; it is now {now}. Re-authorization readmits it"
            ),
            Refusal::MalformedAnchor(k) => write!(f, "`{k}` is not a usable anchor key"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Check that this machine was authorized onto this overlay.
///
/// The tier is passed in by the caller from the hint, so the value the policy
/// is about to act on is the value that was signed. Reading it from anywhere
/// else would leave a gap between what was verified and what is used.
pub fn verify(
    anchors: &Anchors,
    claim: &Claim<'_>,
    auth: Option<&Authorization>,
    now: u64,
) -> Result<State, Refusal> {
    let state = anchors.state();
    // An unlocked overlay cannot check anything, and says so rather than
    // pretending. The caller carries this state to the screen.
    if !state.is_locked() {
        return Ok(state);
    }

    let Some(auth) = auth else {
        return Err(Refusal::Unauthorized(claim.node_id.to_string()));
    };

    // The key comes from the trust set, never from the message. A verifier
    // that reads its key out of the thing being verified checks nothing.
    let key = anchors.keys.get(&auth.key_id).ok_or_else(|| Refusal::UnknownAnchor {
        node: claim.node_id.to_string(),
        key_id: auth.key_id.clone(),
    })?;

    // Ed25519 takes its 64 bytes; P-256 takes `r || s` or DER, as hardware
    // returns either.
    let sig = hex::decode(&auth.signature)
        .map_err(|_| Refusal::BadSignature(claim.node_id.to_string()))?;

    // The expiry is verified as part of the claim before it is enforced —
    // otherwise the deadline is a number the sender chose.
    let signed = Claim { not_after: auth.not_after, ..claim.clone() };
    key.verify(&signed.bytes(), &sig)
        .map_err(|_| Refusal::BadSignature(claim.node_id.to_string()))?;

    if auth.not_after <= now {
        return Err(Refusal::Expired {
            node: claim.node_id.to_string(),
            not_after: auth.not_after,
            now,
        });
    }

    Ok(state)
}

/// The highest tier a key may be admitted at.
///
/// A `p256:` hardware key is the firmware-held key of a Device-class board:
/// it proves possession and nothing about what the board booted, so without
/// a boot quote it is capped at [`Tier::Device`]. WireGuard keys and Ed25519
/// node keys take the tier the operator approves, as before.
pub fn tier_ceiling(public_key: &str, quote_digest: Option<&str>) -> Tier {
    if public_key.starts_with("p256:") && quote_digest.is_none() {
        Tier::Device
    } else {
        Tier::Attested
    }
}

/// Whether `tier` names a tier and is one `public_key` may be admitted at.
///
/// Checked by the operator's tool before it signs, so an over-tiered approval
/// is refused rather than issued, and again by every node before it carries a
/// lease, so one issued elsewhere promotes nobody.
pub fn admissible_tier(public_key: &str, tier: &str, quote_digest: Option<&str>) -> Result<Tier, String> {
    let Some(t) = Tier::parse(tier) else {
        return Err(format!(
            "`{tier}` is not a tier; expected {}",
            Tier::ALL.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ")
        ));
    };
    let ceiling = tier_ceiling(public_key, quote_digest);
    if t > ceiling {
        return Err(format!(
            "{public_key} is a Device-class hardware key with no boot quote, so it may be admitted at `{}` at most, not `{tier}`: \
             a node without a measured boot never originates a privileged call",
            ceiling.as_str()
        ));
    }
    Ok(t)
}

/// Sign an authorization. Used by whatever holds an anchor's private half.
///
/// Not by the coordinator, which is the entire point — this exists so the
/// signing side has one implementation of the signed bytes rather than a
/// second one that drifts.
pub fn authorize(
    key_id: &str,
    signing: &ed25519_dalek::SigningKey,
    claim: &Claim<'_>,
) -> Authorization {
    use ed25519_dalek::Signer;
    Authorization {
        key_id: key_id.to_string(),
        not_after: claim.not_after,
        signature: hex::encode(signing.sign(&claim.bytes()).to_bytes()),
    }
}

/// Sign an authorization with a key held in hardware.
///
/// The same signed bytes as [`authorize`], for an anchor whose private half
/// never leaves its device: a P-256 Secure Enclave or TPM key, or an Ed25519
/// key behind a signer. The signature is checked against the signer's own
/// public key before it is returned, so a device that signed something else
/// is reported here rather than refused everywhere later.
pub fn authorize_with(
    key_id: &str,
    signer: &dyn furcate_identity::MessageSigner,
    claim: &Claim<'_>,
) -> Result<Authorization, String> {
    let key = CellKey::of(signer)?;
    let bytes = claim.bytes();
    let raw = signer.sign(&bytes).map_err(|e| format!("the anchor did not sign: {e:#}"))?;
    Ok(Authorization {
        key_id: key_id.to_string(),
        not_after: claim.not_after,
        signature: key.seal(&bytes, &raw)?,
    })
}

/// How long before an expiry an operator should be told about it.
///
/// Re-signing needs an anchor's private half, which is deliberately somewhere
/// the fleet is not. Notice therefore has to be long enough for a person to
/// physically reach that key, not merely long enough for a daemon to notice.
pub const NOTICE: u64 = 14 * 24 * 60 * 60;

/// How much life is left in an authorization.
///
/// `verify` answers one question — may this machine be admitted *now* — and it
/// answers at the moment somebody asks. That is the worst moment to discover
/// the answer changes on Tuesday. Expiry is the one refusal that arrives
/// without anybody doing anything, so it is the one worth saying in advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// Valid, with more than the notice period left.
    Good { seconds_left: u64 },
    /// Valid, and close enough that somebody should already be acting.
    Ending { seconds_left: u64 },
    /// Past its expiry. `verify` refuses this independently; it is named here
    /// so a screen can say *why* a machine stopped being a peer, rather than
    /// showing an overlay that quietly got smaller.
    Lapsed { seconds_ago: u64 },
}

impl Standing {
    /// Whether this is worth an operator's attention.
    ///
    /// One predicate, so the daemon and the console cannot disagree about what
    /// counts as urgent — the bug this codebase keeps producing is one fact
    /// written twice.
    pub fn needs_attention(&self) -> bool {
        !matches!(self, Standing::Good { .. })
    }

    /// How this reads on a screen.
    ///
    /// Days rather than seconds, because the decision it prompts — find the
    /// operator key, re-sign — is measured in days, and a five-digit number of
    /// seconds is something a reader has to convert before they can act.
    pub fn describe(&self) -> String {
        match self {
            Standing::Good { seconds_left } => {
                format!("authorized for another {} day(s)", seconds_left / 86_400)
            }
            Standing::Ending { seconds_left } => format!(
                "authorization ends in {} day(s) — re-sign with `furcatectl overlay authorize`, \
                 or this machine stops being admitted",
                seconds_left / 86_400
            ),
            Standing::Lapsed { seconds_ago } => format!(
                "authorization lapsed {} day(s) ago — this machine is refused everywhere until \
                 it is re-signed",
                seconds_ago / 86_400
            ),
        }
    }
}

/// Read an expiry against the clock.
///
/// `notice` is a parameter rather than baked in so a test can state its own
/// window instead of arranging a date fourteen days out.
pub fn standing(not_after: u64, now: u64, notice: u64) -> Standing {
    // `verify` refuses on `not_after <= now`, and this has to agree with it
    // exactly: a boundary that said "ending" while verification already said
    // "expired" would show an operator a machine that is fine and refused.
    if not_after <= now {
        return Standing::Lapsed { seconds_ago: now - not_after };
    }
    let seconds_left = not_after - now;
    if seconds_left <= notice {
        Standing::Ending { seconds_left }
    } else {
        Standing::Good { seconds_left }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_class_key_is_refused_above_the_device_tier() {
        let pi = "p256:02aa";
        assert_eq!(admissible_tier(pi, "device", None), Ok(Tier::Device));
        assert_eq!(admissible_tier(pi, "soft", None), Ok(Tier::Soft));
        for over in ["platform", "attested"] {
            let why = admissible_tier(pi, over, None).expect_err(over);
            assert!(why.contains("Device-class") && why.contains("`device` at most"), "{why}");
        }
        // Keys that were admitted at platform before still are.
        assert_eq!(admissible_tier("ed25519:ab", "platform", None), Ok(Tier::Platform));
        assert_eq!(admissible_tier("AQEB", "attested", None), Ok(Tier::Attested));
        assert!(admissible_tier(pi, "hard", None).unwrap_err().contains("not a tier"));
    }
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn anchors_with(seed: u8, id: &str) -> Anchors {
        let mut a = Anchors::new();
        a.trust(&Anchor {
            key_id: id.into(),
            public_key: hex::encode(key(seed).verifying_key().to_bytes()),
        })
        .expect("a well-formed anchor");
        a
    }

    fn claim<'a>(node: &'a str, pk: &'a str, tier: &'a str) -> Claim<'a> {
        Claim { node_id: node, public_key: pk, tier, not_after: 2_000 }
    }

    #[test]
    fn a_properly_authorized_machine_is_accepted() {
        let anchors = anchors_with(1, "operator");
        let c = claim("node-b", "AAAA", "hard");
        let auth = authorize("operator", &key(1), &c);
        assert_eq!(verify(&anchors, &c, Some(&auth), 1_000), Ok(State::Locked { anchors: 1 }));
    }

    #[test]
    fn a_locked_overlay_refuses_a_machine_nobody_authorized() {
        // The whole point: a coordinator that has been taken over can hand out
        // whatever it likes and none of it becomes a peer.
        let anchors = anchors_with(1, "operator");
        let c = claim("attacker", "AAAA", "hard");
        assert_eq!(verify(&anchors, &c, None, 1_000), Err(Refusal::Unauthorized("attacker".into())));
    }

    #[test]
    fn a_signature_from_a_key_this_node_does_not_trust_is_refused() {
        let anchors = anchors_with(1, "operator");
        let c = claim("attacker", "AAAA", "hard");
        // Correctly signed — by the wrong key, under a name it made up.
        let auth = authorize("operator", &key(9), &c);
        assert_eq!(verify(&anchors, &c, Some(&auth), 1_000), Err(Refusal::BadSignature("attacker".into())));

        let named = authorize("some-other-key", &key(9), &c);
        assert_eq!(
            verify(&anchors, &c, Some(&named), 1_000),
            Err(Refusal::UnknownAnchor { node: "attacker".into(), key_id: "some-other-key".into() })
        );
    }

    #[test]
    fn an_authorization_cannot_be_moved_to_another_key() {
        // Otherwise an authorization for a machine is an authorization for
        // anyone who takes its name and brings their own key.
        let anchors = anchors_with(1, "operator");
        let genuine = claim("node-b", "GENUINE", "hard");
        let auth = authorize("operator", &key(1), &genuine);
        let swapped = claim("node-b", "ATTACKER", "hard");
        assert_eq!(
            verify(&anchors, &swapped, Some(&auth), 1_000),
            Err(Refusal::BadSignature("node-b".into()))
        );
    }

    #[test]
    fn an_authorization_cannot_be_promoted_to_a_higher_tier() {
        // A signature issued for a peer the policy barely admits must not
        // become one for a peer it trusts completely.
        let anchors = anchors_with(1, "operator");
        let issued = claim("node-b", "AAAA", "soft");
        let auth = authorize("operator", &key(1), &issued);
        let promoted = claim("node-b", "AAAA", "hard");
        assert_eq!(
            verify(&anchors, &promoted, Some(&auth), 1_000),
            Err(Refusal::BadSignature("node-b".into()))
        );
    }

    #[test]
    fn the_deadline_is_signed_rather_than_chosen_by_the_sender() {
        // Moving `not_after` forward has to break the signature, or the expiry
        // is a number whoever is replaying it gets to pick.
        let anchors = anchors_with(1, "operator");
        let c = claim("node-b", "AAAA", "hard");
        let mut auth = authorize("operator", &key(1), &c);
        auth.not_after = 9_999_999;
        assert_eq!(
            verify(&anchors, &c, Some(&auth), 1_000),
            Err(Refusal::BadSignature("node-b".into()))
        );
    }

    #[test]
    fn a_stolen_machine_stops_being_authorized() {
        let anchors = anchors_with(1, "operator");
        let c = claim("node-b", "AAAA", "hard");
        let auth = authorize("operator", &key(1), &c);
        assert_eq!(
            verify(&anchors, &c, Some(&auth), 3_000),
            Err(Refusal::Expired { node: "node-b".into(), not_after: 2_000, now: 3_000 })
        );
    }

    #[test]
    fn field_boundaries_cannot_be_moved_between_fields() {
        // With a separator instead of lengths, a node called `a` on tier
        // `b|hard` and one called `a|b` on tier `hard` would sign the same
        // bytes, and one authorization would verify for the other.
        let a = Claim { node_id: "a", public_key: "k", tier: "b\u{1}hard", not_after: 1 };
        let b = Claim { node_id: "a\u{1}b", public_key: "k", tier: "hard", not_after: 1 };
        assert_ne!(a.bytes(), b.bytes());
    }

    #[test]
    fn signatures_do_not_carry_across_purposes() {
        // Domain separation: every other signer in this tree signs different
        // bytes, so none of their signatures can be replayed as an admission.
        assert!(claim("n", "k", "hard").bytes().starts_with(CONTEXT));
    }

    #[test]
    fn an_unlocked_overlay_accepts_and_says_so() {
        // The upgrade path. Refusing everything would break every existing
        // site; accepting quietly would leave an operator believing in a check
        // that is not running.
        let none = Anchors::new();
        let c = claim("node-b", "AAAA", "hard");
        assert_eq!(verify(&none, &c, None, 1_000), Ok(State::Unlocked));
        assert!(State::Unlocked.describe().contains("coordinator's word is taken"));
        assert!(!State::Unlocked.is_locked());
    }

    #[test]
    fn there_is_no_state_where_anchors_are_held_and_not_checked() {
        // The failure this design exists to make unreachable.
        let anchors = anchors_with(1, "operator");
        assert!(anchors.state().is_locked());
        let c = claim("anyone", "AAAA", "hard");
        assert!(verify(&anchors, &c, None, 1_000).is_err());
    }

    #[test]
    fn a_malformed_anchor_is_refused_when_it_is_added() {
        // Not at verification time, when it would be a hole that shows up on
        // the day it is needed.
        let mut a = Anchors::new();
        for bad in ["", "zz", "00"] {
            assert!(a.trust(&Anchor { key_id: "k".into(), public_key: bad.into() }).is_err());
        }
        assert!(a.is_empty());
    }

    #[test]
    fn one_bad_entry_refuses_the_whole_file() {
        // A file somebody edited by hand and got wrong, rather than a trust
        // set quietly smaller than the operator believes.
        let good = hex::encode(key(1).verifying_key().to_bytes());
        let v = serde_json::json!([
            {"key_id": "operator", "public_key": good},
            {"key_id": "broken", "public_key": "nonsense"},
        ]);
        assert!(Anchors::from_json(&v).is_err());
    }

    #[test]
    fn a_retired_key_stops_authorizing_without_touching_the_others() {
        let mut anchors = anchors_with(1, "operator");
        anchors
            .trust(&Anchor {
                key_id: "second".into(),
                public_key: hex::encode(key(2).verifying_key().to_bytes()),
            })
            .unwrap();
        let c = claim("node-b", "AAAA", "hard");
        let by_second = authorize("second", &key(2), &c);
        assert!(verify(&anchors, &c, Some(&by_second), 1_000).is_ok());
        assert_eq!(anchors.len(), 2);
    }

    #[test]
    fn an_expiry_far_out_is_not_worth_saying_anything_about() {
        let s = standing(100_000, 1_000, 1_000);
        assert_eq!(s, Standing::Good { seconds_left: 99_000 });
        assert!(!s.needs_attention());
    }

    #[test]
    fn an_expiry_inside_the_notice_window_asks_for_action() {
        let s = standing(1_500, 1_000, 1_000);
        assert_eq!(s, Standing::Ending { seconds_left: 500 });
        assert!(s.needs_attention());
        assert!(s.describe().contains("furcatectl overlay authorize"));
    }

    #[test]
    fn standing_and_verify_agree_on_the_boundary() {
        // The one that matters: if `standing` called the exact expiry second
        // "ending" while `verify` already refused it, a screen would show a
        // machine as authorized at the moment it stopped being admitted.
        let anchors = anchors_with(1, "operator");
        let c = claim("node-b", "AAAA", "hard");
        let auth = authorize("operator", &key(1), &c);
        let at = c.not_after;

        assert!(verify(&anchors, &c, Some(&auth), at).is_err());
        assert!(matches!(standing(at, at, 1_000), Standing::Lapsed { .. }));

        assert!(verify(&anchors, &c, Some(&auth), at - 1).is_ok());
        assert!(matches!(standing(at, at - 1, 1_000), Standing::Ending { .. }));
    }

    #[test]
    fn a_lapsed_authorization_says_it_is_refused_everywhere() {
        let s = standing(1_000, 1_000 + 3 * 86_400, 1_000);
        assert_eq!(s, Standing::Lapsed { seconds_ago: 3 * 86_400 });
        assert!(s.needs_attention());
        assert!(s.describe().contains("3 day(s) ago"));
    }

    #[test]
    fn the_notice_window_is_long_enough_to_reach_an_offline_key() {
        // The anchor's private half is deliberately not on the fleet, so this
        // is a number about how long it takes a person to get to it. A day
        // would technically be advance notice and would not be enough.
        //
        // Checked at compile time rather than at run time: a notice window
        // shortened to something useless should not produce a binary that has
        // to be run before anybody finds out.
        const { assert!(NOTICE >= 7 * 24 * 60 * 60) };
    }
}
