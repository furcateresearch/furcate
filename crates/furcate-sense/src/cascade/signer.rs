//! How a rung signs.
//!
//! A processing node signs with a key its hardware holds and never hands over:
//! on a Raspberry Pi the firmware-held key through the signing broker, on a
//! node with a TPM the node key. [`HardwareSigner`] wraps any
//! [`MessageSigner`]. The in-memory [`Leaf`] implements the same trait for the
//! host-side simulator and tests; nothing in a service path constructs one.

use crate::leaf::{domain_digest, Leaf};
use furcate_identity::MessageSigner;
use furcate_policy::delegation::CellKey;
use std::sync::Arc;

/// A rung's signing identity: its node id and a way to sign under a domain.
pub trait CascadeSigner: Send + Sync {
    fn node_id(&self) -> &str;
    /// The key as a cell link names it: `ed25519:<hex>` or `p256:<hex>`.
    fn public_key(&self) -> String;
    /// Sign `msg` under `domain`, the same digest [`Leaf::sign_message`] signs.
    fn sign_message(&self, domain: &str, msg: &[u8]) -> Result<String, String>;
}

impl CascadeSigner for Leaf {
    fn node_id(&self) -> &str {
        &self.id
    }

    fn public_key(&self) -> String {
        Leaf::public_key(self)
    }

    fn sign_message(&self, domain: &str, msg: &[u8]) -> Result<String, String> {
        Ok(Leaf::sign_message(self, domain, msg))
    }
}

/// A signer whose private key stays in the hardware that holds it.
pub struct HardwareSigner {
    id: String,
    signer: Arc<dyn MessageSigner>,
    key: CellKey,
}

impl HardwareSigner {
    pub fn new(id: impl Into<String>, signer: Arc<dyn MessageSigner>) -> Result<Self, String> {
        let key = CellKey::of(&*signer)?;
        Ok(Self { id: id.into(), signer, key })
    }
}

impl CascadeSigner for HardwareSigner {
    fn node_id(&self) -> &str {
        &self.id
    }

    fn public_key(&self) -> String {
        self.key.id()
    }

    fn sign_message(&self, domain: &str, msg: &[u8]) -> Result<String, String> {
        let digest = domain_digest(domain, msg);
        let raw = self.signer.sign(&digest).map_err(|e| format!("{e:#}"))?;
        // `seal` checks the signature against the key before it is returned, so
        // a signer that signed with some other key is caught here.
        self.key.seal(&digest, &raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::verify_with_key;
    use furcate_identity::signer::Ed25519Signer;

    #[test]
    fn a_hardware_signature_verifies_like_a_leaf_signature() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let hw = HardwareSigner::new("furcate:node:small1", Arc::new(Ed25519Signer(Arc::new(sk)))).unwrap();
        let sig = hw.sign_message("d", b"m").unwrap();
        assert_eq!(verify_with_key(&hw.public_key(), "d", b"m", &sig), Ok(()));
        assert!(verify_with_key(&hw.public_key(), "other", b"m", &sig).is_err());
        let leaf = Leaf::new("x", [8u8; 32]);
        assert_eq!(leaf.public_key(), hw.public_key());
        assert_eq!(CascadeSigner::sign_message(&leaf, "d", b"m").unwrap(), sig);
    }
}
