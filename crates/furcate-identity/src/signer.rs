//! Signing with a key the hardware holds.
//!
//! A [`MessageSigner`] is handed bytes and returns a signature; the private
//! key never passes through the caller. A Pi signs through its firmware
//! ([`crate::backends::RpiFwCrypto`]); a node whose key is sealed to its TPM
//! signs with the unsealed node key, as it always has.

/// The public half of a signer's key, in the form the signer reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerKey {
    /// A 32-byte Ed25519 key.
    Ed25519([u8; 32]),
    /// An ECDSA P-256 key, signing SHA-256 of the message: a SEC1 point,
    /// compressed or not, or a DER SubjectPublicKeyInfo.
    P256(Vec<u8>),
}

/// A key that signs without surrendering itself.
pub trait MessageSigner: Send + Sync {
    /// The public half of the key.
    fn public_key(&self) -> anyhow::Result<SignerKey>;

    /// Sign `message`. Ed25519 returns its 64 bytes; P-256 signs the SHA-256
    /// of `message` and returns either a DER `Ecdsa-Sig-Value` or the 64-byte
    /// `r || s`, whichever the hardware gives.
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The node's Ed25519 key, as cell links have always been signed: the key
/// a node unseals from its own hardware at start.
#[derive(Clone)]
pub struct Ed25519Signer(pub std::sync::Arc<ed25519_dalek::SigningKey>);

impl MessageSigner for Ed25519Signer {
    fn public_key(&self) -> anyhow::Result<SignerKey> {
        Ok(SignerKey::Ed25519(self.0.verifying_key().to_bytes()))
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

/// The message signer of a node's root of trust, owned so it can be shared.
#[derive(Clone)]
pub struct RootOfTrustSigner(pub std::sync::Arc<dyn crate::rot::RootOfTrust + Send + Sync>);

impl RootOfTrustSigner {
    /// The root of trust's signer, when it has one.
    pub fn of(rot: std::sync::Arc<dyn crate::rot::RootOfTrust + Send + Sync>) -> Option<RootOfTrustSigner> {
        rot.message_signer().is_some().then(|| RootOfTrustSigner(rot))
    }

    fn inner(&self) -> anyhow::Result<&dyn MessageSigner> {
        self.0
            .message_signer()
            .ok_or_else(|| anyhow::anyhow!("this root of trust signs only its own quotes"))
    }
}

impl MessageSigner for RootOfTrustSigner {
    fn public_key(&self) -> anyhow::Result<SignerKey> {
        self.inner()?.public_key()
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.inner()?.sign(message)
    }
}
