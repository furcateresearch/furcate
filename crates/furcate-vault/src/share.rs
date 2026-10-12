//! Re-wrapping object keys to attested peers.
//!
//! Hybrid public-key encryption: an ephemeral X25519 key agreement with the
//! recipient's static public key, a key derivation binding both public keys
//! and the grant context, then an AEAD over the object key. The recipient's
//! public key is the one carried in its attestation, so a grant names a
//! specific node in a specific attested state rather than a bearer.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use crate::envelope::nonce_of;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// A peer's static key pair, bound to its attested identity.
pub struct PeerKey {
    secret: StaticSecret,
    pub node_id: String,
}

impl PeerKey {
    pub fn from_bytes(node_id: impl Into<String>, bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
            node_id: node_id.into(),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public().as_bytes())
    }
}

/// An object key wrapped for one recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedKey {
    pub object_id: String,
    /// Node the grant was issued to.
    pub recipient: String,
    /// Ephemeral public key for this wrap.
    pub ephemeral_public: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn derive(shared: &[u8], eph_pub: &[u8], recipient_pub: &[u8], context: &str) -> [u8; 32] {
    // Binding both public keys into the derivation stops a wrap intended for
    // one recipient being replayed toward another.
    let mut info = Vec::new();
    info.extend_from_slice(b"furcate/vault/share/v1");
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recipient_pub);
    info.extend_from_slice(context.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 bytes is a valid length");
    okm
}

/// Wrap an object key for a recipient.
///
/// `ephemeral_secret` and `nonce` are supplied by the caller so this stays
/// deterministic and testable; production callers draw both from the system
/// entropy source.
pub fn wrap_for(
    object_id: &str,
    object_key: &[u8; 32],
    recipient: &str,
    recipient_public: &PublicKey,
    ephemeral_secret: [u8; 32],
    nonce: &[u8; 12],
    context: &str,
) -> Option<WrappedKey> {
    let eph = StaticSecret::from(ephemeral_secret);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(recipient_public);

    let kek = derive(
        shared.as_bytes(),
        eph_pub.as_bytes(),
        recipient_public.as_bytes(),
        context,
    );
    let cipher = ChaCha20Poly1305::new_from_slice(&kek).ok()?;
    let ct = cipher
        .encrypt(
            &nonce_of(nonce)?,
            Payload {
                msg: object_key,
                aad: recipient.as_bytes(),
            },
        )
        .ok()?;

    Some(WrappedKey {
        object_id: object_id.to_string(),
        recipient: recipient.to_string(),
        ephemeral_public: hex::encode(eph_pub.as_bytes()),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
    })
}

/// Unwrap an object key granted to this node.
pub fn unwrap_with(peer: &PeerKey, wrapped: &WrappedKey, context: &str) -> Option<[u8; 32]> {
    // A grant addressed to someone else must not open here even if the bytes
    // happen to be available.
    if wrapped.recipient != peer.node_id {
        return None;
    }
    let eph_bytes: [u8; 32] = hex::decode(&wrapped.ephemeral_public).ok()?.try_into().ok()?;
    let eph_pub = PublicKey::from(eph_bytes);
    let shared = peer.secret.diffie_hellman(&eph_pub);

    let kek = derive(
        shared.as_bytes(),
        eph_pub.as_bytes(),
        peer.public().as_bytes(),
        context,
    );
    let cipher = ChaCha20Poly1305::new_from_slice(&kek).ok()?;
    let nonce = hex::decode(&wrapped.nonce).ok()?;
    let ct = hex::decode(&wrapped.ciphertext).ok()?;
    let pt = cipher
        .decrypt(
            &nonce_of(&nonce)?,
            Payload {
                msg: &ct,
                aad: wrapped.recipient.as_bytes(),
            },
        )
        .ok()?;
    pt.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::Vault;

    fn peers() -> (PeerKey, PeerKey) {
        (
            PeerKey::from_bytes("furcate:node:node-a", [11u8; 32]),
            PeerKey::from_bytes("furcate:node:node-b", [22u8; 32]),
        )
    }

    #[test]
    fn a_grant_opens_for_its_recipient() {
        let (_a, b) = peers();
        let key = [7u8; 32];
        let w = wrap_for(
            "obj1",
            &key,
            &b.node_id,
            &b.public(),
            [33u8; 32],
            &[1u8; 12],
            "epoch:5",
        )
        .unwrap();
        assert_eq!(unwrap_with(&b, &w, "epoch:5"), Some(key));
    }

    #[test]
    fn a_grant_does_not_open_for_anyone_else() {
        let (a, b) = peers();
        let w = wrap_for(
            "obj1",
            &[7u8; 32],
            &b.node_id,
            &b.public(),
            [33u8; 32],
            &[1u8; 12],
            "ctx",
        )
        .unwrap();
        assert_eq!(unwrap_with(&a, &w, "ctx"), None);
    }

    #[test]
    fn a_grant_is_bound_to_its_context() {
        // Changing the context is how revocation-by-epoch works: last epoch's
        // grant does not open this epoch.
        let (_a, b) = peers();
        let w = wrap_for(
            "obj1",
            &[7u8; 32],
            &b.node_id,
            &b.public(),
            [33u8; 32],
            &[1u8; 12],
            "epoch:5",
        )
        .unwrap();
        assert_eq!(unwrap_with(&b, &w, "epoch:6"), None);
    }

    #[test]
    fn redirecting_a_grant_to_another_node_fails() {
        let (a, b) = peers();
        let mut w = wrap_for(
            "obj1",
            &[7u8; 32],
            &b.node_id,
            &b.public(),
            [33u8; 32],
            &[1u8; 12],
            "ctx",
        )
        .unwrap();
        w.recipient = a.node_id.clone();
        assert_eq!(unwrap_with(&a, &w, "ctx"), None);
    }

    #[test]
    fn sharing_one_object_does_not_expose_the_vault() {
        let (_a, b) = peers();
        let mut vault = Vault::open([1u8; 32], &crate::seal::tests::tpm_grant()).unwrap();
        let shared = vault.seal("shared", b"you may read this", &[5u8; 12], "ctx").unwrap();
        let private = vault.seal("private", b"you may not", &[6u8; 12], "ctx").unwrap();

        let w = wrap_for(
            "shared",
            &vault.object_key("shared"),
            &b.node_id,
            &b.public(),
            [44u8; 32],
            &[2u8; 12],
            "ctx",
        )
        .unwrap();
        let obj_key = unwrap_with(&b, &w, "ctx").unwrap();

        assert_eq!(
            Vault::open_with_key(&obj_key, &shared).unwrap(),
            b"you may read this"
        );
        // The same granted key must not open the object it was not granted for.
        assert!(Vault::open_with_key(&obj_key, &private).is_err());
    }

    #[test]
    fn each_wrap_uses_a_distinct_ephemeral_key() {
        let (_a, b) = peers();
        let w1 = wrap_for("o", &[7u8; 32], &b.node_id, &b.public(), [1u8; 32], &[1u8; 12], "c").unwrap();
        let w2 = wrap_for("o", &[7u8; 32], &b.node_id, &b.public(), [2u8; 32], &[1u8; 12], "c").unwrap();
        assert_ne!(w1.ephemeral_public, w2.ephemeral_public);
        assert_ne!(w1.ciphertext, w2.ciphertext);
    }

    #[test]
    fn a_tampered_wrap_does_not_open() {
        let (_a, b) = peers();
        let mut w = wrap_for("o", &[7u8; 32], &b.node_id, &b.public(), [1u8; 32], &[1u8; 12], "c").unwrap();
        let mut raw = hex::decode(&w.ciphertext).unwrap();
        raw[0] ^= 0xff;
        w.ciphertext = hex::encode(raw);
        assert_eq!(unwrap_with(&b, &w, "c"), None);
    }
}
