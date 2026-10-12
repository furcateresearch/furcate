//! The refusals.
//!
//! These are the points where the build arm declines rather than producing
//! something plausible. They are the part of this crate that is Furcate rather
//! than a re-implementation of a hosted build service, so they are a named type
//! and not scattered `bail!`s. Each variant is one of the six refusals in the
//! design note (§6), and each says enough to act on: which grade was required,
//! which digest was expected, what was offered.

use crate::digest::Digest;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// §6.1 — a source that cannot be named by digest is not an input.
    UnnamedSource { detail: String },

    /// §6.2 — no unsigned artifact leaves. Provenance that cannot be signed is
    /// not emitted.
    UnsignableProvenance { detail: String },

    /// §6.3 — a cache hit whose stored action digest does not match the
    /// requested one. The cache is an index of proofs, not of filenames.
    CacheDigestMismatch { requested: Digest, stored: Digest },

    /// A stored object whose bytes do not hash to the digest it was filed
    /// under. Corruption or tampering, caught on read rather than trusted.
    CorruptObject { expected: Digest, actual: Digest },

    /// §6.4 — the network was used inside a build the policy did not grant it
    /// to.
    UngrantedNetwork { detail: String },

    /// §6.5 — the node is below the policy's attestation floor. Both grades are
    /// named so the caller can see the gap rather than silently landing on
    /// another machine.
    BelowAttestationFloor { required: String, offered: String },

    /// A target no attested capability on the node can satisfy — e.g. a
    /// `cuda:sm_120` test placed on a machine that is not `sm_120`. Refused, not
    /// run and reported as passing (§9).
    UnsatisfiableTarget { target: String, detail: String },

    /// §6.6 — reproducibility is a claim about repetition; one build is one
    /// build. Reported reproducible only on two or more matching observations.
    ReproducibilityUnproven { observations: usize },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::UnnamedSource { detail } => {
                write!(f, "refused: source not named by digest — {detail}")
            }
            Refusal::UnsignableProvenance { detail } => {
                write!(f, "refused: provenance cannot be signed — {detail}")
            }
            Refusal::CacheDigestMismatch { requested, stored } => write!(
                f,
                "refused: cache hit for action {requested} is filed under {stored}"
            ),
            Refusal::CorruptObject { expected, actual } => write!(
                f,
                "refused: object filed under {expected} hashes to {actual}"
            ),
            Refusal::UngrantedNetwork { detail } => {
                write!(f, "refused: network without a policy grant — {detail}")
            }
            Refusal::BelowAttestationFloor { required, offered } => write!(
                f,
                "refused: attestation floor {required} required, node offers {offered}"
            ),
            Refusal::UnsatisfiableTarget { target, detail } => {
                write!(f, "refused: target {target} not satisfiable here — {detail}")
            }
            Refusal::ReproducibilityUnproven { observations } => write!(
                f,
                "refused: reproducibility needs \u{2265}2 matching builds, have {observations}"
            ),
        }
    }
}

impl std::error::Error for Refusal {}
