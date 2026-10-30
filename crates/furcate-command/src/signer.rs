//! The site signer: whatever signs the site's receipts. The gate never holds more than this interface, so the key can
//! live in a hardware module or a key service and stay there.

use ed25519_dalek::{Signer, SigningKey};

/// Why a signer could not sign. The reason is for logs and the service's error answer; it carries no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignError {
    pub reason: String,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "site signer unavailable: {}", self.reason)
    }
}
impl std::error::Error for SignError {}

/// Signs the 32-byte domain digest (see [`crate::domain_digest`]) with the site's Ed25519 key.
pub trait SiteSigner {
    /// The public half as `ed25519:<64 lower-case hex>`. Fixed for the life of the signer.
    fn key_id(&self) -> String;
    /// Sign `domain_digest`. An error means nothing was signed; the gate then releases nothing.
    fn sign(&self, domain_digest: &[u8]) -> Result<[u8; 64], SignError>;
}

impl SiteSigner for SigningKey {
    fn key_id(&self) -> String {
        format!("ed25519:{}", hex::encode(self.verifying_key().to_bytes()))
    }
    fn sign(&self, domain_digest: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(Signer::sign(self, domain_digest).to_bytes())
    }
}
