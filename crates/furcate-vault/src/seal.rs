//! Encryption at rest under a vault key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use crate::envelope::nonce_of;
use chacha20poly1305::ChaCha20Poly1305;
use furcate_identity::custody::{CustodyGrant, CustodyRecord};
use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Decryption failed: wrong key, wrong context, or altered ciphertext.
    Undecryptable,
    /// The nonce was not the expected length.
    BadNonce,
    /// A nonce would have been reused, which would be catastrophic for the
    /// cipher's guarantees.
    NonceReuse,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Undecryptable => write!(
                f,
                "object could not be decrypted: wrong key, altered ciphertext, or wrong context"
            ),
            VaultError::BadNonce => write!(f, "nonce must be 12 bytes"),
            VaultError::NonceReuse => write!(
                f,
                "refusing to reuse a nonce with the same key: doing so would leak plaintext"
            ),
        }
    }
}

impl std::error::Error for VaultError {}

/// An encrypted object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub id: String,
    pub nonce: String,
    pub ciphertext: String,
    /// Context bound into the encryption, so an object cannot be replayed
    /// under a different identity or purpose.
    pub context: String,
    /// The custody mode and class this object was sealed under. Bound into
    /// the authenticated data with the context, so it cannot be edited.
    pub custody: CustodyRecord,
}

/// Authenticated data for an object: its custody record, then its context.
fn aad(custody: &CustodyRecord, context: &str) -> Vec<u8> {
    let mut a = custody.bound_bytes();
    a.push(0);
    a.extend_from_slice(context.as_bytes());
    a
}

/// A node's sealed store.
///
/// The vault key stands in for one sealed to the TPM against a policy over
/// boot measurements. Key custody lives behind this boundary so the backend
/// can become a real sealed blob without changing callers.
pub struct Vault {
    key: [u8; 32],
    custody: CustodyRecord,
    used_nonces: std::collections::BTreeSet<String>,
}

/// Debug is implemented by hand rather than derived: deriving it would print
/// the vault key into any log line that formatted a `Vault`.
impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("key", &"<redacted>")
            .field("custody", &self.custody)
            .field("sealed_objects", &self.used_nonces.len())
            .finish()
    }
}

impl Vault {
    /// Open a vault with a key that has been unsealed from the root of trust.
    ///
    /// Takes a custody grant rather than a class: whether this machine may
    /// hold sealed data is decided once, by the site's custody settings, and
    /// a grant is the only proof of that decision.
    pub fn open(key: [u8; 32], grant: &CustodyGrant) -> Result<Self, VaultError> {
        Ok(Self {
            key,
            custody: grant.record(),
            used_nonces: Default::default(),
        })
    }

    pub fn assurance(&self) -> AssuranceClass {
        self.custody.class
    }

    /// The mode and class every object sealed here records.
    pub fn custody(&self) -> CustodyRecord {
        self.custody
    }

    /// Derive a per-object key from the vault key and the object identity.
    ///
    /// Per-object keys are what make sharing possible without handing over
    /// everything: one object's key can be re-wrapped to a peer while the rest
    /// of the vault stays closed.
    pub fn object_key(&self, id: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"furcate/vault/object-key/v1");
        h.update(self.key);
        h.update((id.len() as u64).to_be_bytes());
        h.update(id.as_bytes());
        h.finalize().into()
    }

    /// Encrypt an object.
    pub fn seal(
        &mut self,
        id: &str,
        plaintext: &[u8],
        nonce: &[u8],
        context: &str,
    ) -> Result<Sealed, VaultError> {
        if nonce.len() != 12 {
            return Err(VaultError::BadNonce);
        }
        let marker = format!("{id}:{}", hex::encode(nonce));
        if !self.used_nonces.insert(marker) {
            return Err(VaultError::NonceReuse);
        }

        let key = self.object_key(id);
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::Undecryptable)?;
        let ct = cipher
            .encrypt(
                &nonce_of(nonce).ok_or(VaultError::BadNonce)?,
                Payload {
                    msg: plaintext,
                    aad: &aad(&self.custody, context),
                },
            )
            .map_err(|_| VaultError::Undecryptable)?;

        Ok(Sealed {
            id: id.to_string(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ct),
            context: context.to_string(),
            custody: self.custody,
        })
    }

    /// Decrypt an object held in this vault.
    pub fn unseal(&self, sealed: &Sealed) -> Result<Vec<u8>, VaultError> {
        let key = self.object_key(&sealed.id);
        Self::open_with_key(&key, sealed)
    }

    /// Decrypt using an object key obtained some other way — for instance one
    /// re-wrapped to this node by a peer.
    pub fn open_with_key(key: &[u8; 32], sealed: &Sealed) -> Result<Vec<u8>, VaultError> {
        let nonce = hex::decode(&sealed.nonce).map_err(|_| VaultError::BadNonce)?;
        if nonce.len() != 12 {
            return Err(VaultError::BadNonce);
        }
        let ct = hex::decode(&sealed.ciphertext).map_err(|_| VaultError::Undecryptable)?;
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Undecryptable)?;
        cipher
            .decrypt(
                &nonce_of(&nonce).ok_or(VaultError::BadNonce)?,
                Payload {
                    msg: &ct,
                    aad: &aad(&sealed.custody, &sealed.context),
                },
            )
            .map_err(|_| VaultError::Undecryptable)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use furcate_identity::custody::{elect, Candidate, CustodyMode, CustodySettings};

    pub(crate) fn grant(class: AssuranceClass, settings: &CustodySettings) -> CustodyGrant {
        let member = Candidate { id: "node".into(), class: Some(class), reachable: true };
        elect(settings, &[member]).unwrap().grant("node").unwrap()
    }

    pub(crate) fn tpm_grant() -> CustodyGrant {
        grant(AssuranceClass::Tpm, &CustodySettings::default())
    }

    fn vault() -> Vault {
        Vault::open([1u8; 32], &tpm_grant()).unwrap()
    }

    #[test]
    fn a_sealed_object_round_trips() {
        let mut v = vault();
        let s = v.seal("obj1", b"secret data", &[9u8; 12], "node:a").unwrap();
        assert_eq!(v.unseal(&s).unwrap(), b"secret data");
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let mut v = vault();
        let s = v.seal("obj1", b"secret data", &[9u8; 12], "ctx").unwrap();
        assert!(!s.ciphertext.contains(&hex::encode(b"secret data")));
    }

    #[test]
    fn altering_the_ciphertext_is_detected() {
        let mut v = vault();
        let mut s = v.seal("obj1", b"data", &[9u8; 12], "ctx").unwrap();
        // Flip a byte.
        let mut raw = hex::decode(&s.ciphertext).unwrap();
        raw[0] ^= 0xff;
        s.ciphertext = hex::encode(raw);
        assert_eq!(v.unseal(&s), Err(VaultError::Undecryptable));
    }

    #[test]
    fn changing_the_context_is_detected() {
        // Context is authenticated, so an object cannot be replayed under a
        // different identity or purpose.
        let mut v = vault();
        let mut s = v.seal("obj1", b"data", &[9u8; 12], "node:a").unwrap();
        s.context = "node:b".into();
        assert_eq!(v.unseal(&s), Err(VaultError::Undecryptable));
    }

    #[test]
    fn another_vault_cannot_read_it() {
        let mut v = vault();
        let s = v.seal("obj1", b"data", &[9u8; 12], "ctx").unwrap();
        let other = Vault::open([2u8; 32], &tpm_grant()).unwrap();
        assert_eq!(other.unseal(&s), Err(VaultError::Undecryptable));
    }

    #[test]
    fn objects_have_independent_keys() {
        let v = vault();
        assert_ne!(v.object_key("a"), v.object_key("b"));
    }

    #[test]
    fn object_key_boundaries_cannot_be_shifted() {
        let v = vault();
        assert_ne!(v.object_key("ab"), v.object_key("a\0b"));
    }

    #[test]
    fn nonce_reuse_is_refused() {
        let mut v = vault();
        v.seal("obj1", b"one", &[9u8; 12], "ctx").unwrap();
        assert_eq!(
            v.seal("obj1", b"two", &[9u8; 12], "ctx"),
            Err(VaultError::NonceReuse)
        );
    }

    #[test]
    fn a_sealed_object_records_mode_and_class() {
        let mut v = vault();
        let s = v.seal("obj1", b"data", &[9u8; 12], "ctx").unwrap();
        assert_eq!(s.custody.mode, CustodyMode::Elected);
        assert_eq!(s.custody.class, AssuranceClass::Tpm);

        let tpm_less = CustodySettings { tpm_less: true, ..Default::default() };
        let mut pi = Vault::open([3u8; 32], &grant(AssuranceClass::Device, &tpm_less)).unwrap();
        let s = pi.seal("obj1", b"data", &[9u8; 12], "ctx").unwrap();
        assert_eq!(s.custody.class, AssuranceClass::Device);
        assert!(s.custody.meets(AssuranceClass::Tpm).is_err());
    }

    #[test]
    fn editing_the_recorded_custody_is_detected() {
        // Claiming a stronger class than the object was sealed under must not
        // survive: the record is authenticated with the ciphertext.
        let tpm_less = CustodySettings { tpm_less: true, ..Default::default() };
        let mut pi = Vault::open([3u8; 32], &grant(AssuranceClass::Device, &tpm_less)).unwrap();
        let mut s = pi.seal("obj1", b"data", &[9u8; 12], "ctx").unwrap();
        s.custody.class = AssuranceClass::Tpm;
        assert_eq!(pi.unseal(&s), Err(VaultError::Undecryptable));
    }

    #[test]
    fn a_short_nonce_is_refused() {
        let mut v = vault();
        assert_eq!(
            v.seal("obj1", b"x", &[1u8; 8], "ctx"),
            Err(VaultError::BadNonce)
        );
    }
}
