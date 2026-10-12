//! Provenance: what was built, from what, by whom, at what assurance.
//!
//! Every hosted build service's provenance terminates in *trust our service
//! key*. Here it terminates in *this specific machine, at a stated assurance
//! grade* -- the attestation the build ran under is named in the statement, and
//! the statement is signed by the node's own key. The shape follows in-toto: a
//! statement with subjects (the outputs), a predicate type, and a predicate
//! carrying the action digest, the builder's identity and grade, the materials
//! (inputs by digest), the network posture, and the reproducibility standing.
//!
//! There is no way to obtain a `SignedProvenance` without a signing key. That
//! is refusal 6.2 enforced by type: no unsigned artifact leaves.

use crate::action::{BuildAction, Network};
use crate::cache::ActionResult;
use crate::digest::Digest;
use crate::refusal::Refusal;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://furcate.org/BuildProvenance/v1";

/// One output, named and digested -- an in-toto subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: Digest,
}

/// Who produced the artifact, and under what attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Builder {
    /// The node id whose key signs this.
    pub id: String,
    /// The assurance class of that node's identity, as a label
    /// (`furcate_identity::AssuranceClass`, e.g. "Tpm").
    pub assurance_grade: String,
    /// The attestation coverage at build time (`furcate_attest::Coverage`,
    /// e.g. "PlatformAndOs").
    pub attestation_coverage: String,
}

/// The predicate: the claim the statement makes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    /// The digest of the action that produced the subjects.
    pub action: Digest,
    pub builder: Builder,
    /// Inputs by name -> digest. What the artifact was built from.
    pub materials: BTreeMap<String, Digest>,
    /// Whether the network was granted, and why. A grant is recorded here so it
    /// is auditable rather than lost (6.4).
    pub network: Network,
    /// How many matching observations stand behind this, and whether that is
    /// enough to call the build reproducible (6.6).
    pub observations: u32,
    pub reproducible: bool,
}

/// The unsigned statement. Signing consumes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate,
}

impl Statement {
    /// Build a statement from an action, its result, and the builder's identity.
    pub fn new(
        action: &BuildAction,
        result: &ActionResult,
        builder: Builder,
    ) -> Result<Self, Refusal> {
        if result.outputs.is_empty() {
            return Err(Refusal::UnsignableProvenance {
                detail: "no outputs to attest".to_string(),
            });
        }
        let subject = result
            .outputs
            .iter()
            .map(|(name, digest)| Subject {
                name: name.clone(),
                digest: *digest,
            })
            .collect();
        Ok(Statement {
            statement_type: STATEMENT_TYPE.to_string(),
            subject,
            predicate_type: PREDICATE_TYPE.to_string(),
            predicate: Predicate {
                action: action.digest(),
                builder,
                materials: action.inputs.clone(),
                network: action.network.clone(),
                observations: result.observations,
                reproducible: result.is_reproducible(),
            },
        })
    }

    /// The exact bytes that get signed. Deterministic: our types are structs
    /// (declaration-ordered) over `BTreeMap`s (sorted), so `to_vec` is stable.
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("statement serialises")
    }

    /// Sign the statement with the node key. This is the only way to produce a
    /// `SignedProvenance` -- an unsigned artifact is unrepresentable.
    pub fn sign(self, key: &SigningKey) -> SignedProvenance {
        let sig = key.sign(&self.signing_bytes());
        SignedProvenance {
            verifying_key: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(sig.to_bytes()),
            statement: self,
        }
    }
}

/// A statement with its signature and the key that made it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedProvenance {
    pub statement: Statement,
    /// Ed25519 signature over the statement bytes, hex.
    pub signature: String,
    /// The verifying key, hex -- so a reader can check without a directory.
    pub verifying_key: String,
}

impl SignedProvenance {
    /// Verify the signature. A tampered statement, a wrong key, or a malformed
    /// signature all fail here.
    pub fn verify(&self) -> Result<(), Refusal> {
        let key_bytes: [u8; 32] = hex::decode(&self.verifying_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Refusal::UnsignableProvenance {
                detail: "verifying key is not 32 bytes of hex".to_string(),
            })?;
        let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            Refusal::UnsignableProvenance {
                detail: format!("bad verifying key: {e}"),
            }
        })?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Refusal::UnsignableProvenance {
                detail: "signature is not 64 bytes of hex".to_string(),
            })?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&self.statement.signing_bytes(), &sig).map_err(|_| {
            Refusal::UnsignableProvenance {
                detail: "signature does not verify".to_string(),
            }
        })
    }

    /// The signing node's id, for the ledger record.
    pub fn builder_id(&self) -> &str {
        &self.statement.predicate.builder.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn result() -> ActionResult {
        let mut outputs = BTreeMap::new();
        outputs.insert("furcated".to_string(), Digest::of(b"the binary"));
        ActionResult {
            action: Digest::of(b"act"),
            outputs,
            observations: 1,
        }
    }

    fn action() -> BuildAction {
        let mut inputs = BTreeMap::new();
        inputs.insert("src".to_string(), Digest::of(b"src"));
        BuildAction {
            target: "x86_64-linux".into(),
            inputs,
            command: vec!["cargo".into(), "build".into()],
            env: BTreeMap::new(),
            outputs: vec!["furcated".into()],
            network: Network::Denied,
        }
    }

    fn builder() -> Builder {
        Builder {
            id: "node-c".into(),
            assurance_grade: "Tpm".into(),
            attestation_coverage: "PlatformAndOs".into(),
        }
    }

    #[test]
    fn signed_provenance_verifies() {
        let stmt = Statement::new(&action(), &result(), builder()).unwrap();
        assert!(stmt.sign(&key()).verify().is_ok());
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let stmt = Statement::new(&action(), &result(), builder()).unwrap();
        let mut prov = stmt.sign(&key());
        prov.statement.predicate.reproducible = true; // lie after signing
        assert!(prov.verify().is_err());
    }

    #[test]
    fn no_outputs_cannot_be_attested() {
        let mut r = result();
        r.outputs.clear();
        assert!(matches!(
            Statement::new(&action(), &r, builder()),
            Err(Refusal::UnsignableProvenance { .. })
        ));
    }

    #[test]
    fn a_network_grant_is_recorded_in_provenance() {
        let mut a = action();
        a.network = Network::Granted {
            reason: "fetch crates".into(),
        };
        let stmt = Statement::new(&a, &result(), builder()).unwrap();
        assert!(matches!(stmt.predicate.network, Network::Granted { .. }));
    }
}
