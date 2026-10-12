//! Enrollment records.
//!
//! Enrollment is the one moment a node is trusted on an operator's say-so.
//! Everything afterwards is derived from the identity established here, which
//! is why the record is explicit, reviewable, and becomes the first entry in
//! the node's operation chain.

use crate::node_id::NodeId;
use crate::rot::{AssuranceClass, Evidence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A node's request to join a site, and the evidence supporting it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enrollment {
    pub node_id: NodeId,
    pub assurance: AssuranceClass,
    /// Operator-facing name. Advisory only — never used for identity.
    pub hostname: String,
    /// Whether the manufacturer vouched for this chip.
    pub endorsed: bool,
    /// Digest over the evidence bundle, so the record commits to exactly what
    /// was appraised at enrollment time.
    pub evidence_digest: String,
    /// Register values observed at enrollment. These are the starting point for
    /// drift detection, not a permanent reference value — a signed image
    /// produces reference values that can be computed in advance instead.
    pub pcrs: std::collections::BTreeMap<u32, String>,
}

impl Enrollment {
    pub fn from_evidence(evidence: &Evidence, hostname: impl Into<String>) -> Self {
        // Digest the canonical serialization so the commitment is reproducible
        // by anyone holding the same bundle.
        let encoded = serde_json::to_vec(evidence).unwrap_or_default();
        Enrollment {
            node_id: evidence.node_id.clone(),
            assurance: evidence.assurance,
            hostname: hostname.into(),
            // Holding an EK certificate is not an endorsement: an emulator
            // writes one too. Set by `with_endorsement` once the certificate
            // has been checked against the manufacturers' CAs.
            endorsed: false,
            evidence_digest: hex::encode(Sha256::digest(&encoded)),
            pcrs: evidence.quote.pcrs.to_hex(),
        }
    }

    /// Record whether a manufacturer CA vouches for the endorsement key, as
    /// decided by [`crate::backends::endorsement`].
    pub fn with_endorsement(mut self, endorsement: &crate::backends::Endorsement) -> Self {
        self.endorsed = endorsement.endorsed;
        self
    }

    /// Whether this node may hold custody of sealed data under the site's
    /// custody settings, and if not, why.
    ///
    /// Quote-capable classes (TPM, DICE) qualify by default. TEE, secure
    /// element and fuse-key classes qualify only when the operator has enabled
    /// TPM-less custody, and a readable one only when they have also allowed
    /// it; see [`crate::custody`].
    pub fn may_hold_custody(
        &self,
        settings: &crate::custody::CustodySettings,
    ) -> Result<(), crate::custody::CustodyRefusal> {
        settings.admits(self.assurance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rot::{PcrSet, Quote};
    use std::collections::BTreeMap;

    fn evidence(assurance: AssuranceClass, cert: Option<Vec<u8>>) -> Evidence {
        let mut values = BTreeMap::new();
        values.insert(0u32, vec![0xab, 0xcd]);
        Evidence {
            node_id: NodeId::from_ek_public(b"ek"),
            assurance,
            ek_public: b"ek".to_vec(),
            ek_certificate: cert,
            ak_public: b"ak".to_vec(),
            quote: Quote {
                message: b"msg".to_vec(),
                signature: b"sig".to_vec(),
                nonce: b"nonce".to_vec(),
                pcrs: PcrSet {
                    bank: "sha256".into(),
                    values,
                },
            },
        }
    }

    #[test]
    fn a_certificate_alone_is_not_recorded_as_endorsed() {
        let with = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, Some(vec![1])), "a");
        let without = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, None), "a");
        assert!(!with.endorsed);
        assert!(!without.endorsed);
        let checked = crate::backends::Endorsement { endorsed: true, detail: "vendor-endorsed".into() };
        assert!(with.with_endorsement(&checked).endorsed);
    }

    #[test]
    fn digest_commits_to_the_bundle() {
        let a = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, None), "a");
        let b = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, Some(vec![1])), "a");
        assert_ne!(a.evidence_digest, b.evidence_digest);
    }

    #[test]
    fn software_identities_cannot_hold_custody_by_default() {
        let soft = Enrollment::from_evidence(&evidence(AssuranceClass::Soft, None), "vm");
        let tpm = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, None), "server");
        let default = crate::custody::CustodySettings::default();
        assert!(soft.may_hold_custody(&default).is_err());
        assert!(tpm.may_hold_custody(&default).is_ok());
    }

    #[test]
    fn an_enclave_holds_custody_only_with_the_tpm_less_opt_in() {
        let se = Enrollment::from_evidence(&evidence(AssuranceClass::SecureElement, None), "mac");
        let tee = Enrollment::from_evidence(&evidence(AssuranceClass::Tee, None), "arm");
        let default = crate::custody::CustodySettings::default();
        let opted = crate::custody::CustodySettings { tpm_less: true, ..Default::default() };
        for e in [&se, &tee] {
            let why = e.may_hold_custody(&default).unwrap_err();
            assert!(why.0.contains("custody.tpm_less"), "{why}");
            assert!(e.may_hold_custody(&opted).is_ok());
        }
    }

    #[test]
    fn hostname_does_not_affect_identity() {
        let a = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, None), "one");
        let b = Enrollment::from_evidence(&evidence(AssuranceClass::Tpm, None), "two");
        assert_eq!(a.node_id, b.node_id);
    }
}
