//! Inference receipts.
//!
//! Inference is just another chip-level operation, so it lands in the same
//! ledger as everything else. A receipt ties an answer to a specific model, a
//! specific attested node, and specific inputs.
//!
//! What a receipt proves is **binding**, not correctness. Floating-point and
//! batching nondeterminism mean a GPU result generally cannot be reproduced
//! bit-exactly even by an honest party, so "recompute and compare" is not a
//! general check. Anyone claiming otherwise about attested inference is
//! overselling it. Stronger guarantees need a confidential runtime or
//! redundant execution, and those are recorded explicitly in
//! [`VerificationLevel`] so a consumer is never left guessing.

use ed25519_dalek::{SigningKey, VerifyingKey};
use furcate_identity::MessageSigner;
use furcate_policy::delegation::CellKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// How much a receipt actually establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLevel {
    /// Model, runtime, node and inputs are bound together and signed. The
    /// computation itself is not verified.
    Bound,
    /// The same request was executed on independent nodes and the outputs
    /// agreed. Catches a lying node without special silicon.
    Redundant { agreeing_nodes: u8 },
    /// The runtime executed inside a trusted execution environment, so the
    /// evidence covers the computation.
    Confidential,
}

impl VerificationLevel {
    /// Whether this level says anything about the computation being correct.
    pub fn covers_computation(&self) -> bool {
        !matches!(self, VerificationLevel::Bound)
    }
}

impl fmt::Display for VerificationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationLevel::Bound => write!(f, "bound (provenance only, computation unverified)"),
            VerificationLevel::Redundant { agreeing_nodes } => {
                write!(f, "redundant ({agreeing_nodes} independent nodes agreed)")
            }
            VerificationLevel::Confidential => write!(f, "confidential (executed in a TEE)"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InferenceReceipt {
    pub model_digest: String,
    pub runtime_digest: String,
    pub node_id: String,
    /// Inputs and outputs are committed by digest, so a receipt carries no
    /// payload and stays cheap enough to emit on every call.
    pub input_digest: String,
    pub output_digest: String,
    pub params: String,
    /// Ledger head at the time of the call, placing it in the node's history.
    pub chain_head: String,
    pub level: VerificationLevel,
    pub signature: Option<String>,
    /// The key that signed, as cell links name keys: `ed25519:<hex>` for a
    /// node key, `p256:<hex>` for a key the hardware holds, such as a Pi's
    /// firmware-held OTP key. A verifier still checks it is the key it
    /// expects for `node_id`; this says which one to check against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiptError {
    BadSignature,
    /// The receipt does not describe the payloads presented.
    PayloadMismatch,
    /// The claimed level requires evidence that was not supplied.
    UnsupportedClaim(&'static str),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::BadSignature => write!(f, "receipt signature does not verify"),
            ReceiptError::PayloadMismatch => {
                write!(f, "receipt does not commit to the payloads presented")
            }
            ReceiptError::UnsupportedClaim(why) => write!(f, "unsupported claim: {why}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl InferenceReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        model_digest: impl Into<String>,
        runtime_digest: impl Into<String>,
        node_id: impl Into<String>,
        input: &[u8],
        output: &[u8],
        params: impl Into<String>,
        chain_head: impl Into<String>,
        level: VerificationLevel,
    ) -> Self {
        Self {
            model_digest: model_digest.into(),
            runtime_digest: runtime_digest.into(),
            node_id: node_id.into(),
            input_digest: digest(input),
            output_digest: digest(output),
            params: params.into(),
            chain_head: chain_head.into(),
            level,
            signature: None,
            signer: None,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        for field in [
            self.model_digest.as_str(),
            self.runtime_digest.as_str(),
            self.node_id.as_str(),
            self.input_digest.as_str(),
            self.output_digest.as_str(),
            self.params.as_str(),
            self.chain_head.as_str(),
        ] {
            h.update((field.len() as u64).to_be_bytes());
            h.update(field.as_bytes());
        }
        h.update(format!("{:?}", self.level).as_bytes());
        h.finalize().to_vec()
    }

    /// Sign with a node's Ed25519 key.
    pub fn sign(self, key: &SigningKey) -> Self {
        let signer = furcate_identity::Ed25519Signer(std::sync::Arc::new(key.clone()));
        self.sign_with(&signer).expect("an Ed25519 key always signs")
    }

    /// Sign with whatever holds the node's key: the node key, or a key the
    /// hardware holds and signs with itself. The signature is checked against
    /// the signer's own key before it is attached, so a receipt never carries
    /// a signature that does not verify.
    pub fn sign_with(mut self, signer: &dyn MessageSigner) -> Result<Self, String> {
        let key = CellKey::of(signer)?;
        let payload = self.payload();
        let raw = signer.sign(&payload).map_err(|e| format!("signing the receipt: {e:#}"))?;
        self.signature = Some(key.seal(&payload, &raw)?);
        self.signer = Some(key.id());
        Ok(self)
    }

    /// Verify under a node's Ed25519 key.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ReceiptError> {
        self.verify_by(&CellKey::Ed25519(*key))
    }

    /// Verify under the key the caller trusts for this node, whichever kind
    /// it is.
    pub fn verify_by(&self, key: &CellKey) -> Result<(), ReceiptError> {
        let Some(hexsig) = &self.signature else {
            return Err(ReceiptError::BadSignature);
        };
        key.verify_hex(&self.payload(), hexsig).map_err(|_| ReceiptError::BadSignature)?;

        if let VerificationLevel::Redundant { agreeing_nodes } = self.level {
            if agreeing_nodes < 2 {
                return Err(ReceiptError::UnsupportedClaim(
                    "redundant execution requires at least two independent nodes",
                ));
            }
        }
        Ok(())
    }

    /// Check the receipt describes the payloads a caller actually holds.
    pub fn matches(&self, input: &[u8], output: &[u8]) -> Result<(), ReceiptError> {
        if self.input_digest != digest(input) || self.output_digest != digest(output) {
            return Err(ReceiptError::PayloadMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[4u8; 32])
    }

    fn receipt(level: VerificationLevel) -> InferenceReceipt {
        InferenceReceipt::new(
            "modeldigest",
            "runtimedigest",
            "furcate:node:a",
            b"what is the temperature",
            b"22.5C",
            "temp=0",
            "chainhead",
            level,
        )
        .sign(&key())
    }

    #[test]
    fn a_signed_receipt_verifies() {
        let r = receipt(VerificationLevel::Bound);
        assert_eq!(r.verify(&key().verifying_key()), Ok(()));
    }

    #[test]
    fn swapping_the_model_invalidates_the_receipt() {
        let mut r = receipt(VerificationLevel::Bound);
        r.model_digest = "someothermodel".into();
        assert_eq!(
            r.verify(&key().verifying_key()),
            Err(ReceiptError::BadSignature)
        );
    }

    #[test]
    fn a_receipt_commits_to_its_inputs_and_outputs() {
        let r = receipt(VerificationLevel::Bound);
        assert_eq!(r.matches(b"what is the temperature", b"22.5C"), Ok(()));
        assert_eq!(
            r.matches(b"a different question", b"22.5C"),
            Err(ReceiptError::PayloadMismatch)
        );
    }

    #[test]
    fn a_substituted_answer_is_detected() {
        let r = receipt(VerificationLevel::Bound);
        assert_eq!(
            r.matches(b"what is the temperature", b"99.9C"),
            Err(ReceiptError::PayloadMismatch)
        );
    }

    #[test]
    fn binding_does_not_claim_correctness() {
        assert!(!VerificationLevel::Bound.covers_computation());
        assert!(VerificationLevel::Confidential.covers_computation());
        assert!(VerificationLevel::Redundant { agreeing_nodes: 3 }.covers_computation());
    }

    #[test]
    fn a_redundancy_claim_needs_more_than_one_node() {
        let r = receipt(VerificationLevel::Redundant { agreeing_nodes: 1 });
        assert_eq!(
            r.verify(&key().verifying_key()),
            Err(ReceiptError::UnsupportedClaim(
                "redundant execution requires at least two independent nodes"
            ))
        );
    }

    #[test]
    fn a_genuine_redundancy_claim_verifies() {
        let r = receipt(VerificationLevel::Redundant { agreeing_nodes: 3 });
        assert_eq!(r.verify(&key().verifying_key()), Ok(()));
    }

    #[test]
    fn escalating_the_claimed_level_after_signing_is_caught() {
        let mut r = receipt(VerificationLevel::Bound);
        r.level = VerificationLevel::Confidential;
        assert_eq!(
            r.verify(&key().verifying_key()),
            Err(ReceiptError::BadSignature)
        );
    }

    #[test]
    fn a_hardware_held_p256_key_signs_a_receipt_that_verifies() {
        struct Firmware(p256::ecdsa::SigningKey);
        impl MessageSigner for Firmware {
            fn public_key(&self) -> anyhow::Result<furcate_identity::SignerKey> {
                Ok(furcate_identity::SignerKey::P256(
                    self.0.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                ))
            }
            fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = self.0.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
        let fw = Firmware(p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap());
        let r = InferenceReceipt::new("m", "r", "furcate:node:pi", b"in", b"out", "p", "h", VerificationLevel::Bound)
            .sign_with(&fw)
            .unwrap();
        let fw_key = CellKey::of(&fw).unwrap();
        assert_eq!(r.signer.as_deref(), Some(fw_key.id().as_str()));
        assert_eq!(r.verify_by(&fw_key), Ok(()));
        // Not anyone else's, and not after the answer changes.
        assert_eq!(r.verify(&key().verifying_key()), Err(ReceiptError::BadSignature));
        let mut changed = r.clone();
        changed.output_digest = digest(b"other");
        assert_eq!(changed.verify_by(&fw_key), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn a_signer_that_signs_with_another_key_is_refused() {
        struct Liar(p256::ecdsa::SigningKey, p256::ecdsa::SigningKey);
        impl MessageSigner for Liar {
            fn public_key(&self) -> anyhow::Result<furcate_identity::SignerKey> {
                Ok(furcate_identity::SignerKey::P256(
                    self.0.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                ))
            }
            fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = self.1.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
        }
        let liar = Liar(
            p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap(),
            p256::ecdsa::SigningKey::from_slice(&[2; 32]).unwrap(),
        );
        let r = InferenceReceipt::new("m", "r", "n", b"i", b"o", "p", "h", VerificationLevel::Bound);
        assert!(r.sign_with(&liar).is_err());
    }

    #[test]
    fn the_level_is_reported_honestly_in_text() {
        assert!(VerificationLevel::Bound.to_string().contains("unverified"));
    }
}
