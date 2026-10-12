//! Appraisal and attestation results.

use crate::freshness::FreshnessProof;
use crate::policy::{classify_coverage, AppraisalPolicy, Coverage, PolicyViolation};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Which RATS topology a result is being produced for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    /// The attester carries a signed result and presents it to many relying
    /// parties. Cheap and reusable.
    Passport,
    /// Raw evidence is forwarded so the relying party can appraise it with a
    /// verifier of its own choosing.
    BackgroundCheck,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Satisfies the policy.
    Admit,
    /// Fails the policy. The violations say why.
    Refuse,
}

/// A verifier's signed statement about an attester.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationResult {
    pub node_id: String,
    pub verdict: Verdict,
    pub assurance: AssuranceClass,
    /// What the underlying measurements genuinely cover. Carried explicitly so
    /// a relying party is never left to assume the OS was measured when it was
    /// not.
    pub coverage: Coverage,
    pub violations: Vec<PolicyViolation>,
    /// Validity window, in the site's logical clock.
    pub issued_at: u64,
    pub expires_at: u64,
    /// Verifier that produced this result.
    pub verifier_id: String,
    /// Signature over the canonical encoding of the fields above.
    pub signature: Option<String>,
}

impl AttestationResult {
    /// Bytes a signature covers. Excludes the signature itself.
    fn signing_payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.node_id.as_bytes());
        h.update(format!("{:?}", self.verdict).as_bytes());
        h.update(self.assurance.as_str().as_bytes());
        h.update(format!("{:?}", self.coverage).as_bytes());
        h.update(self.issued_at.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        h.update(self.verifier_id.as_bytes());
        for v in &self.violations {
            h.update(format!("{v:?}").as_bytes());
        }
        h.finalize().to_vec()
    }

    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Check the verifier's signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let Some(sig_hex) = &self.signature else {
            return false;
        };
        let Ok(bytes) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            return false;
        };
        key.verify(&self.signing_payload(), &Signature::from_bytes(&arr))
            .is_ok()
    }
}

/// The site verifier.
pub struct Verifier {
    id: String,
    key: SigningKey,
    policy: AppraisalPolicy,
    /// How long a result stays valid.
    validity: u64,
}

impl Verifier {
    pub fn new(id: impl Into<String>, key: SigningKey, policy: AppraisalPolicy, validity: u64) -> Self {
        Self {
            id: id.into(),
            key,
            policy,
            validity,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn policy(&self) -> &AppraisalPolicy {
        &self.policy
    }

    /// Appraise evidence and issue a signed result.
    ///
    /// A result is issued whether or not the node passes: a refusal is just as
    /// useful to a relying party as an admission, and signing it stops a node
    /// from suppressing an inconvenient verdict.
    pub fn appraise(
        &self,
        node_id: &str,
        assurance: AssuranceClass,
        endorsed: bool,
        registers: &BTreeMap<u32, String>,
        now: u64,
    ) -> AttestationResult {
        let violations = self.policy.appraise(assurance, endorsed, registers);
        let mut result = AttestationResult {
            node_id: node_id.to_string(),
            verdict: if violations.is_empty() {
                Verdict::Admit
            } else {
                Verdict::Refuse
            },
            assurance,
            coverage: classify_coverage(registers),
            violations,
            issued_at: now,
            expires_at: now + self.validity,
            verifier_id: self.id.clone(),
            signature: None,
        };
        let sig: Signature = self.key.sign(&result.signing_payload());
        result.signature = Some(hex::encode(sig.to_bytes()));
        result
    }

    /// Whether a freshness proof is acceptable for the given topology.
    ///
    /// A self-chosen nonce is never acceptable as proof to a third party. It
    /// is allowed only where the attester and the relying party are the same
    /// entity inspecting itself.
    pub fn accepts_freshness(&self, proof: &FreshnessProof, topology: Topology) -> bool {
        match (proof, topology) {
            (FreshnessProof::SelfChosen(_), _) => false,
            (FreshnessProof::Nonce(n), _) => !n.is_empty(),
            (FreshnessProof::Epoch(_), Topology::Passport) => true,
            (FreshnessProof::Epoch(_), Topology::BackgroundCheck) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SEPARATOR_ONLY;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn good_registers() -> BTreeMap<u32, String> {
        let mut m = BTreeMap::new();
        m.insert(0, "b4".repeat(32));
        m.insert(2, "49".repeat(32));
        m.insert(7, "b3".repeat(32));
        m
    }

    fn verifier() -> Verifier {
        Verifier::new("site:home-1", key(), AppraisalPolicy::default(), 300)
    }

    #[test]
    fn a_conforming_node_is_admitted_and_signed() {
        let v = verifier();
        let r = v.appraise("furcate:node:a", AssuranceClass::Tpm, true, &good_registers(), 100);
        assert_eq!(r.verdict, Verdict::Admit);
        assert!(r.verify_signature(&v.verifying_key()));
    }

    #[test]
    fn a_refusal_is_signed_too() {
        let v = verifier();
        let r = v.appraise("furcate:node:b", AssuranceClass::Soft, false, &good_registers(), 100);
        assert_eq!(r.verdict, Verdict::Refuse);
        assert!(!r.violations.is_empty());
        assert!(r.verify_signature(&v.verifying_key()), "a node must not be able to suppress a refusal");
    }

    #[test]
    fn tampering_with_a_result_invalidates_it() {
        let v = verifier();
        let mut r = v.appraise("furcate:node:b", AssuranceClass::Soft, false, &good_registers(), 100);
        r.verdict = Verdict::Admit;
        r.violations.clear();
        assert!(!r.verify_signature(&v.verifying_key()));
    }

    #[test]
    fn another_verifiers_key_does_not_validate() {
        let v = verifier();
        let r = v.appraise("n", AssuranceClass::Tpm, true, &good_registers(), 0);
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(!r.verify_signature(&other));
    }

    #[test]
    fn results_expire() {
        let v = verifier();
        let r = v.appraise("n", AssuranceClass::Tpm, true, &good_registers(), 100);
        assert!(r.is_valid_at(100));
        assert!(r.is_valid_at(399));
        assert!(!r.is_valid_at(400));
        assert!(!r.is_valid_at(99));
    }

    #[test]
    fn coverage_travels_with_the_result() {
        let v = verifier();
        let mut regs = good_registers();
        regs.insert(11, SEPARATOR_ONLY.into());
        let r = v.appraise("n", AssuranceClass::Tpm, true, &regs, 0);
        assert_eq!(r.coverage, Coverage::PlatformOnly);
        assert_eq!(r.verdict, Verdict::Admit, "admitted, but honest about what it proves");
    }

    #[test]
    fn a_self_chosen_nonce_is_never_proof() {
        let v = verifier();
        assert!(!v.accepts_freshness(&FreshnessProof::SelfChosen(vec![1, 2]), Topology::Passport));
        assert!(!v.accepts_freshness(
            &FreshnessProof::SelfChosen(vec![1, 2]),
            Topology::BackgroundCheck
        ));
    }

    #[test]
    fn issued_nonces_and_epochs_are_both_acceptable() {
        let v = verifier();
        assert!(v.accepts_freshness(&FreshnessProof::Nonce(vec![1]), Topology::Passport));
        assert!(v.accepts_freshness(&FreshnessProof::Epoch(3), Topology::BackgroundCheck));
        assert!(!v.accepts_freshness(&FreshnessProof::Nonce(vec![]), Topology::Passport));
    }
}
