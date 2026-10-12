//! Anchoring a chain head in hardware.
//!
//! A hashchain alone only detects tampering by someone who does not hold the
//! chain; the operator holds it and could rewrite the whole thing. What closes
//! that is the TPM, because a platform register extend *is* a hashchain step
//! performed inside the chip and not resettable from software:
//!
//! ```text
//! PCR ← H(PCR ‖ measurement)
//! ```
//!
//! Extending the chain head into a register and quoting it produces a
//! checkpoint whose divergent history would require a quote over a value the
//! chip never held. A monotonic counter defeats replay of an older, more
//! flattering checkpoint.

use crate::chain::Digest32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A register reserved for application use, outside the firmware-owned range.
pub const DEFAULT_CHECKPOINT_PCR: u32 = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Chain head committed by this checkpoint.
    pub head: String,
    /// Register the head was extended into.
    pub pcr: u32,
    /// Register value after the extend, as quoted.
    pub pcr_after: String,
    /// Monotonic counter value at checkpoint time. Strictly increasing, so an
    /// older checkpoint cannot be presented as current.
    pub counter: u64,
    /// The nonce the verifier supplied.
    pub nonce: String,
    /// Quote message and signature from the attestation key.
    pub quote_message: String,
    pub quote_signature: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointError {
    /// The register value does not follow from the previous one and the head.
    ExtendMismatch,
    /// The counter did not advance, so this may be a replay.
    CounterNotAdvanced { previous: u64, found: u64 },
    /// Malformed hex in a checkpoint field.
    Malformed(&'static str),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckpointError::ExtendMismatch => write!(
                f,
                "register value does not follow from the previous value and this head"
            ),
            CheckpointError::CounterNotAdvanced { previous, found } => write!(
                f,
                "counter did not advance: previous {previous}, found {found} — possible replay"
            ),
            CheckpointError::Malformed(field) => write!(f, "malformed hex in `{field}`"),
        }
    }
}

impl std::error::Error for CheckpointError {}

/// Compute the register value that results from extending `before` with `head`.
///
/// This mirrors what the chip does, so a verifier can predict the expected
/// value and compare rather than taking the reported one on faith.
pub fn predict_extend(before: &Digest32, head: &Digest32) -> Digest32 {
    let mut h = Sha256::new();
    h.update(before);
    h.update(head);
    h.finalize().into()
}

impl Checkpoint {
    /// Check a checkpoint against the register value that preceded it and the
    /// last counter seen.
    ///
    /// Signature verification is the verifier's job and happens separately,
    /// against the node's attestation key; this covers the parts that are pure
    /// arithmetic over the reported values.
    pub fn verify_continuity(
        &self,
        pcr_before: &str,
        previous_counter: Option<u64>,
    ) -> Result<(), CheckpointError> {
        let before = decode32(pcr_before).ok_or(CheckpointError::Malformed("pcr_before"))?;
        let head = decode32(&self.head).ok_or(CheckpointError::Malformed("head"))?;
        let after = decode32(&self.pcr_after).ok_or(CheckpointError::Malformed("pcr_after"))?;

        if predict_extend(&before, &head) != after {
            return Err(CheckpointError::ExtendMismatch);
        }
        if let Some(prev) = previous_counter {
            if self.counter <= prev {
                return Err(CheckpointError::CounterNotAdvanced {
                    previous: prev,
                    found: self.counter,
                });
            }
        }
        Ok(())
    }
}

fn decode32(s: &str) -> Option<Digest32> {
    hex::decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(before: &Digest32, head: Digest32, counter: u64) -> Checkpoint {
        Checkpoint {
            head: hex::encode(head),
            pcr: DEFAULT_CHECKPOINT_PCR,
            pcr_after: hex::encode(predict_extend(before, &head)),
            counter,
            nonce: "00".into(),
            quote_message: String::new(),
            quote_signature: String::new(),
        }
    }

    #[test]
    fn a_well_formed_checkpoint_verifies() {
        let before = [0u8; 32];
        let c = checkpoint(&before, [7u8; 32], 1);
        assert_eq!(c.verify_continuity(&hex::encode(before), None), Ok(()));
    }

    #[test]
    fn a_forged_register_value_is_caught() {
        let before = [0u8; 32];
        let mut c = checkpoint(&before, [7u8; 32], 1);
        c.pcr_after = hex::encode([9u8; 32]);
        assert_eq!(
            c.verify_continuity(&hex::encode(before), None),
            Err(CheckpointError::ExtendMismatch)
        );
    }

    #[test]
    fn substituting_a_different_head_is_caught() {
        // The operator rewrites history and presents a different head while
        // keeping the register value the chip actually produced.
        let before = [0u8; 32];
        let honest = checkpoint(&before, [7u8; 32], 1);
        let mut forged = honest.clone();
        forged.head = hex::encode([8u8; 32]);
        assert_eq!(
            forged.verify_continuity(&hex::encode(before), None),
            Err(CheckpointError::ExtendMismatch)
        );
    }

    #[test]
    fn replaying_an_older_checkpoint_is_caught() {
        let before = [0u8; 32];
        let c = checkpoint(&before, [7u8; 32], 5);
        assert_eq!(
            c.verify_continuity(&hex::encode(before), Some(5)),
            Err(CheckpointError::CounterNotAdvanced {
                previous: 5,
                found: 5
            })
        );
        assert!(c.verify_continuity(&hex::encode(before), Some(4)).is_ok());
    }

    #[test]
    fn extends_chain_so_order_matters() {
        let zero = [0u8; 32];
        let a = predict_extend(&zero, &[1u8; 32]);
        let ab = predict_extend(&a, &[2u8; 32]);
        let b = predict_extend(&zero, &[2u8; 32]);
        let ba = predict_extend(&b, &[1u8; 32]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn malformed_hex_is_reported() {
        let c = checkpoint(&[0u8; 32], [1u8; 32], 1);
        assert_eq!(
            c.verify_continuity("nothex", None),
            Err(CheckpointError::Malformed("pcr_before"))
        );
    }
}
