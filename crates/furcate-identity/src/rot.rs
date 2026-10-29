//! The root-of-trust abstraction.
//!
//! Furcate runs on hardware ranging from rack servers to microcontrollers, and
//! the strength of the identity binding varies with the silicon. The design
//! position is that weaker hardware is *recorded* as weaker rather than
//! excluded or quietly treated as equivalent, so [`AssuranceClass`] travels
//! with every identity and becomes an input to placement and policy.

use crate::node_id::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// How strongly a node's identity is bound to its hardware.
///
/// Ordering is meaningful: a higher class is strictly stronger, so policies can
/// be expressed as a minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceClass {
    /// File-backed key with no hardware binding. VMs, containers, development.
    Soft,
    /// A key held in a read-protected fuse block or key peripheral on
    /// microcontroller-class silicon. Secure boot alone does not earn it: a
    /// leaf earns it from its key custody, never by stating it; see
    /// [`crate::leaf`].
    Device,
    /// Discrete secure element.
    SecureElement,
    /// TEE-held key, typically ARM TrustZone with OP-TEE.
    Tee,
    /// Layered silicon identity via DICE.
    Dice,
    /// TPM 2.0 with endorsement and attestation keys.
    Tpm,
}

impl AssuranceClass {
    /// Whether this class binds the private key to hardware at all.
    ///
    /// The distinction that matters operationally: a `Soft` identity can be
    /// copied to another machine, so it holds custody only where the operator
    /// has explicitly allowed it (see [`crate::custody`]).
    /// Whether a machine with this root of trust may hold the controlling role
    /// for a cluster.
    ///
    /// The controller admits members, signs intents and holds the roster. A
    /// machine that cannot prove possession of a key cannot hold that job
    /// honestly: everything it asserts about itself is an assertion anyone with
    /// access to the device could repeat.
    ///
    /// The bar is a key the hardware will use but never surrender —
    /// [`Tpm`](Self::Tpm), [`Dice`](Self::Dice), [`Tee`](Self::Tee) or
    /// [`SecureElement`](Self::SecureElement). Explicitly excluded:
    ///
    /// * [`Soft`](Self::Soft) — a file-backed key, or a fingerprint built from
    ///   serials and MACs. Those give continuity, not unforgeability, which is
    ///   the whole argument in `backends::fingerprint`.
    /// * [`Device`](Self::Device) — fuse-backed keys do prove possession, and
    ///   that is enough to be a trusted *member*. It is not enough to be the
    ///   party that decides who else is one, because that class has no
    ///   attestation of what the machine is running.
    ///
    /// This is deliberately a property of the class rather than a check written
    /// at each call site, so that adding a root of trust forces the question to
    /// be answered once, here, where it is reviewable.
    pub fn may_control(&self) -> bool {
        matches!(
            self,
            AssuranceClass::Tpm
                | AssuranceClass::Dice
                | AssuranceClass::Tee
                | AssuranceClass::SecureElement
        )
    }

    pub fn is_hardware_bound(&self) -> bool {
        !matches!(self, AssuranceClass::Soft)
    }

    /// Whether this class can produce a signed quote over platform state.
    pub fn can_quote(&self) -> bool {
        matches!(self, AssuranceClass::Tpm | AssuranceClass::Dice)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AssuranceClass::Soft => "soft",
            AssuranceClass::Device => "device",
            AssuranceClass::SecureElement => "se",
            AssuranceClass::Tee => "tee",
            AssuranceClass::Dice => "dice",
            AssuranceClass::Tpm => "tpm",
        }
    }

    /// The exact inverse of [`as_str`](Self::as_str).
    ///
    /// Kept adjacent to it, and pinned by a round-trip test over every variant,
    /// because these two are one fact written twice and the failure mode when
    /// they disagree is silent. A class that does not parse is `None` rather
    /// than a default: a reader that cannot tell what a node is must decide
    /// that for itself, and every caller here fails closed to
    /// [`Soft`](Self::Soft).
    ///
    /// ⚠ `as_str` is NOT the `serde` encoding. The derive on this type is
    /// `rename_all = "lowercase"`, which renders `SecureElement` as
    /// `"secureelement"` where this renders it `"se"`. Both are already on the
    /// wire — `as_str` in `/attest`, `/identity` and the attestation-result
    /// hash (`verifier.rs`), serde in `Evidence` and `AttestationResult` — and
    /// they agree for every variant EXCEPT `SecureElement`, which is precisely
    /// the class Apple nodes report. Parse with this function anywhere the
    /// value came from an `as_str` producer, and do not mix the two.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "soft" => Some(AssuranceClass::Soft),
            "device" => Some(AssuranceClass::Device),
            "se" => Some(AssuranceClass::SecureElement),
            "tee" => Some(AssuranceClass::Tee),
            "dice" => Some(AssuranceClass::Dice),
            "tpm" => Some(AssuranceClass::Tpm),
            _ => None,
        }
    }
}

impl fmt::Display for AssuranceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of platform measurement registers and their current values.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PcrSet {
    /// Hash algorithm bank the values were read from, e.g. `sha256`.
    pub bank: String,
    /// Register index to raw digest.
    pub values: BTreeMap<u32, Vec<u8>>,
}

impl PcrSet {
    /// Render as index/hex pairs for display and logging.
    pub fn to_hex(&self) -> BTreeMap<u32, String> {
        self.values
            .iter()
            .map(|(k, v)| (*k, hex::encode(v)))
            .collect()
    }
}

/// A signed statement over platform state, bound to a caller-supplied nonce.
///
/// The nonce is what makes a quote *fresh*. Without it a quote is a replayable
/// artifact — which is exactly the failure mode a restored VM snapshot
/// reintroduces, and why restore has to terminate identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Quote {
    /// The attested message as produced by the hardware.
    pub message: Vec<u8>,
    /// Signature over `message` by the attestation key.
    pub signature: Vec<u8>,
    /// The nonce the caller supplied, echoed back for checking.
    pub nonce: Vec<u8>,
    /// Register values covered by this quote.
    pub pcrs: PcrSet,
}

impl Quote {
    /// Whether anything actually signed this.
    ///
    /// Hardware without an attestation key can still describe itself, and that
    /// self-description travels in the same shape as a quote so the rest of the
    /// system does not need two paths. What it must never do is pass for one.
    /// A verifier that treats an unsigned statement as evidence has verified
    /// nothing.
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

/// Everything a node can say about itself, for a verifier to appraise.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub node_id: NodeId,
    pub assurance: AssuranceClass,
    /// Marshalled public endorsement key.
    pub ek_public: Vec<u8>,
    /// Vendor endorsement certificate, when the platform ships one. Many
    /// consumer and embedded TPMs do not, which weakens but does not void the
    /// binding — it means the manufacturer has not vouched for the chip.
    pub ek_certificate: Option<Vec<u8>>,
    /// Marshalled public attestation key.
    pub ak_public: Vec<u8>,
    pub quote: Quote,
}

/// A hardware root of trust that can identify and attest to its node.
pub trait RootOfTrust {
    /// How strongly this backend binds identity to hardware.
    fn assurance(&self) -> AssuranceClass;

    /// Marshalled public endorsement key. Stable across reboots.
    fn ek_public(&self) -> anyhow::Result<Vec<u8>>;

    /// Vendor endorsement certificate, if the platform provides one.
    fn ek_certificate(&self) -> anyhow::Result<Option<Vec<u8>>>;

    /// Marshalled public attestation key.
    fn ak_public(&self) -> anyhow::Result<Vec<u8>>;

    /// Read the platform measurement registers.
    fn pcrs(&self) -> anyhow::Result<PcrSet>;

    /// Produce a quote bound to `nonce`.
    fn quote(&self, nonce: &[u8]) -> anyhow::Result<Quote>;

    /// The key this backend signs arbitrary messages with, when it has one
    /// that never leaves the hardware: a Pi's firmware-held OTP key.
    fn message_signer(&self) -> Option<&dyn crate::signer::MessageSigner> {
        None
    }

    /// Derive this node's identifier from its endorsement key.
    fn node_id(&self) -> anyhow::Result<NodeId> {
        Ok(NodeId::from_ek_public(&self.ek_public()?))
    }

    /// Collect a full evidence bundle for a verifier.
    fn evidence(&self, nonce: &[u8]) -> anyhow::Result<Evidence> {
        Ok(Evidence {
            node_id: self.node_id()?,
            assurance: self.assurance(),
            ek_public: self.ek_public()?,
            ek_certificate: self.ek_certificate()?,
            ak_public: self.ak_public()?,
            quote: self.quote(nonce)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_ordering_allows_minimum_policies() {
        assert!(AssuranceClass::Tpm > AssuranceClass::Soft);
    }

    /// Every variant, so adding one without teaching `from_tag` about it fails
    /// here rather than in the field as a node that silently appraises as
    /// `Soft`.
    #[test]
    fn every_assurance_tag_round_trips() {
        for c in [
            AssuranceClass::Soft,
            AssuranceClass::Device,
            AssuranceClass::SecureElement,
            AssuranceClass::Tee,
            AssuranceClass::Dice,
            AssuranceClass::Tpm,
        ] {
            assert_eq!(AssuranceClass::from_tag(c.as_str()), Some(c), "{c} did not round-trip");
        }
    }

    #[test]
    fn an_unknown_assurance_tag_is_none_not_a_guess() {
        assert_eq!(AssuranceClass::from_tag("secureelement"), None);
        assert_eq!(AssuranceClass::from_tag("TPM"), None);
        assert_eq!(AssuranceClass::from_tag(""), None);
    }

    #[test]
    fn controllers_need_a_key_the_hardware_will_not_surrender() {
        // A fingerprinted board and a file-backed key are the same class, and
        // neither may decide who joins a cluster.
        assert!(!AssuranceClass::Soft.may_control());
        // Fuse-backed possession is enough to be a member, not to admit members.
        assert!(!AssuranceClass::Device.may_control());
        for c in [
            AssuranceClass::SecureElement,
            AssuranceClass::Tee,
            AssuranceClass::Dice,
            AssuranceClass::Tpm,
        ] {
            assert!(c.may_control(), "{c:?} should be able to control");
        }
        assert!(AssuranceClass::Dice > AssuranceClass::Tee);
        assert!(AssuranceClass::Device > AssuranceClass::Soft);
    }

    #[test]
    fn only_soft_is_unbound() {
        assert!(!AssuranceClass::Soft.is_hardware_bound());
        assert!(AssuranceClass::Device.is_hardware_bound());
        assert!(AssuranceClass::Tpm.is_hardware_bound());
    }

    #[test]
    fn quoting_requires_measurement_registers() {
        assert!(AssuranceClass::Tpm.can_quote());
        assert!(!AssuranceClass::SecureElement.can_quote());
        assert!(!AssuranceClass::Soft.can_quote());
    }
}
