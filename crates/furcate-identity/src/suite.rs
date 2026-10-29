//! The signature suite of a key, taken from the key and from nothing else.
//!
//! Hardware-held identity keys sign ECDSA P-256 with SHA-256
//! (`p256`), and Ed25519 stays for software, sealed and operator keys. The
//! suite is part of the key's name (`ed25519:<hex>` or `p256:<hex>`), and the
//! verifier reads it from the **enrolled key**. It is never read from a
//! signature: both suites sign with 64 bytes, so the bytes cannot say which
//! they are, and a verifier that guessed would let a signature made under one
//! suite be presented under the other. A record that carries its own `suite`
//! member must agree with the key's; a record that carries none is refused,
//! because the member is what makes a disagreement visible.
//!
//! The signing input is the existing framing,
//! `M = len(domain) || domain || len(msg) || msg` with 8-byte big-endian
//! lengths, and the digest is `e = SHA-256(M)`. `ed25519` signs the 32 bytes of
//! `e` as its message. `p256` signs ECDSA over `e`: a part that takes a message
//! is given `M` and hashes it itself, a part that takes a digest is given `e`
//! by the host, and the two are the same signature input. Signatures are the
//! raw 64 bytes (`r || s` for P-256); DER from hardware is converted by the
//! host before it gets here.

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::{Digest, Sha256};
use std::fmt;

/// A signature scheme a key can be enrolled under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeySuite {
    Ed25519,
    P256,
}

impl KeySuite {
    /// The word a `suite` member and a key prefix use.
    pub const fn tag(self) -> &'static str {
        match self {
            KeySuite::Ed25519 => "ed25519",
            KeySuite::P256 => "p256",
        }
    }

    /// The suite a `suite` member names. Anything else is refused.
    pub fn from_tag(tag: &str) -> Result<KeySuite, String> {
        match tag {
            "ed25519" => Ok(KeySuite::Ed25519),
            "p256" => Ok(KeySuite::P256),
            other => Err(format!("`{other}` is not a signature suite Furcate knows (`ed25519` or `p256`)")),
        }
    }
}

impl fmt::Display for KeySuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// An enrolled public key with its suite. Equal keys are equal however they
/// were written: a P-256 key is held as its compressed point, and the
/// uncompressed form of the same key parses to the same value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SuiteKey {
    suite: KeySuite,
    bytes: Vec<u8>,
}

impl SuiteKey {
    /// Parse a key as it is written with its suite: `ed25519:<64 hex>` or
    /// `p256:<66 hex compressed or 130 hex uncompressed SEC1 point>`. A key
    /// with no prefix, an unknown prefix, the wrong length, or a point that is
    /// not on the curve is refused.
    pub fn parse(s: &str) -> Result<SuiteKey, String> {
        let (tag, hexpart) = s.split_once(':').ok_or_else(|| {
            format!("`{s}` has no suite; write the key as `ed25519:<64 hex>` or `p256:<hex SEC1 point>`")
        })?;
        let suite = KeySuite::from_tag(tag)?;
        let raw = hex::decode(hexpart).map_err(|e| format!("the {suite} key is not hex: {e}"))?;
        match suite {
            KeySuite::Ed25519 => {
                let b: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| format!("an ed25519 key is 32 bytes, got {}", raw.len()))?;
                ed25519_dalek::VerifyingKey::from_bytes(&b).map_err(|_| "not a valid Ed25519 key".to_string())?;
                Ok(SuiteKey { suite, bytes: b.to_vec() })
            }
            KeySuite::P256 => {
                if raw.len() != 33 && raw.len() != 65 {
                    return Err(format!("a p256 key is a 33- or 65-byte SEC1 point, got {} bytes", raw.len()));
                }
                let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|_| "not a point on P-256".to_string())?;
                Ok(SuiteKey { suite, bytes: k.to_sec1_point(true).as_bytes().to_vec() })
            }
        }
    }

    /// [`SuiteKey::parse`] for a key written before keys carried their suite:
    /// a bare 64-hex string is an Ed25519 key, as it always was. Nothing else
    /// is read without its prefix.
    pub fn parse_stored(s: &str) -> Result<SuiteKey, String> {
        if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return SuiteKey::parse(&format!("ed25519:{s}"));
        }
        SuiteKey::parse(s)
    }

    pub fn suite(&self) -> KeySuite {
        self.suite
    }

    /// The key's bytes: the 32-byte Ed25519 key, or the 33-byte compressed point.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The one way this key is written: lower-case hex, P-256 compressed.
    pub fn id(&self) -> String {
        format!("{}:{}", self.suite, hex::encode(&self.bytes))
    }

    /// Check the `suite` a record declares against this key. The key decides;
    /// the declaration can only agree with it. A record with no declaration is
    /// refused, and so is one that names the other suite or an unknown one.
    pub fn check_declared(&self, declared: Option<&str>) -> Result<(), String> {
        let Some(tag) = declared else {
            return Err(format!("the record names no `suite`; the enrolled key is {}", self.suite));
        };
        let said = KeySuite::from_tag(tag)?;
        if said != self.suite {
            return Err(format!("the record says `{said}` but the enrolled key is {}", self.suite));
        }
        Ok(())
    }

    /// Verify `signature` over the framed message under this key's suite.
    pub fn verify(&self, domain: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), String> {
        let sig: &[u8; 64] = signature
            .try_into()
            .map_err(|_| format!("a signature is 64 bytes, got {}", signature.len()))?;
        let digest = signing_digest(domain, msg);
        match self.suite {
            KeySuite::Ed25519 => {
                let k = ed25519_dalek::VerifyingKey::from_bytes(self.bytes.as_slice().try_into().expect("32 bytes"))
                    .map_err(|_| "not a valid Ed25519 key".to_string())?;
                k.verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(sig))
                    .map_err(|_| "the signature is not this key's under ed25519".to_string())
            }
            KeySuite::P256 => {
                let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes)
                    .map_err(|_| "not a point on P-256".to_string())?;
                let s = p256::ecdsa::Signature::from_slice(sig).map_err(|_| "r || s is out of range".to_string())?;
                k.verify_prehash(&digest, &s).map_err(|_| "the signature is not this key's under p256".to_string())
            }
        }
    }

    /// [`SuiteKey::verify`] for a record that declares its suite: the
    /// declaration is checked against the key first.
    pub fn verify_declared(
        &self,
        declared: Option<&str>,
        domain: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        self.check_declared(declared)?;
        self.verify(domain, msg, signature)
    }
}

/// `len(domain) || domain || len(msg) || msg`, lengths 8-byte big-endian.
pub fn signing_frame(domain: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + domain.len() + msg.len());
    m.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    m.extend_from_slice(domain);
    m.extend_from_slice(&(msg.len() as u64).to_be_bytes());
    m.extend_from_slice(msg);
    m
}

/// `SHA-256` of [`signing_frame`]: what both suites sign.
pub fn signing_digest(domain: &[u8], msg: &[u8]) -> [u8; 32] {
    Sha256::digest(signing_frame(domain, msg)).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;

    const DOMAIN: &[u8] = b"furcate/test/suite/v1";
    const MSG: &[u8] = b"golden message";

    fn ed_secret() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }
    fn p_secret() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
    }
    fn ed_sign(domain: &[u8], msg: &[u8]) -> Vec<u8> {
        ed_secret().sign(&signing_digest(domain, msg)).to_bytes().to_vec()
    }
    fn p_sign(domain: &[u8], msg: &[u8]) -> Vec<u8> {
        let s: p256::ecdsa::Signature = p_secret().sign_prehash(&signing_digest(domain, msg)).unwrap();
        s.to_bytes().to_vec()
    }
    fn ed_key() -> SuiteKey {
        SuiteKey::parse(&format!("ed25519:{}", hex::encode(ed_secret().verifying_key().to_bytes()))).unwrap()
    }
    fn p_key() -> SuiteKey {
        let k = p_secret().verifying_key().clone();
        SuiteKey::parse(&format!("p256:{}", hex::encode(k.to_sec1_point(false).as_bytes())))
            .unwrap()
    }

    // Golden vectors. The Ed25519 signature is byte-identical on every run. The
    // P-256 one is too here (RFC 6979), but only its verification is relied on.
    const ED_KEY: &str = "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const FRAME: &str = "0000000000000015667572636174652f746573742f73756974652f7631000000000000000e676f6c64656e206d657373616765";
    const DIGEST: &str = "bdab781567903a74457aa811e834602d6d2156113da14dba99a770f3fcfc8fb0";
    const ED_SIG: &str = "7712e99f00f44267257ee4249716829cc23e9771c694256bf86d0426442910889ca4b1de681642cf3b5ac84cf303fdce29b966efa3fc729b1147ed339e33150e";
    const P_KEY_UNCOMPRESSED: &str = "p256:041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3";
    const P_KEY: &str = "p256:031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e";
    const P_SIG: &str = "27d3642cc37a181b2cb569f78de044bb8ea466db4e4752a038e039aab54866778536f3cbb1b4d6b801ce4f8c3024b2fd8584f66e58dd828fe3f3798545a55092";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn the_signing_input_is_the_length_prefixed_frame_and_its_sha256() {
        assert_eq!(hex::encode(signing_frame(DOMAIN, MSG)), FRAME);
        assert_eq!(hex::encode(signing_digest(DOMAIN, MSG)), DIGEST);
        // Moving a byte across the boundary changes the digest.
        assert_ne!(signing_digest(b"ab", b"c"), signing_digest(b"a", b"bc"));
    }

    #[test]
    fn golden_ed25519_vector_verifies_and_regenerates_byte_for_byte() {
        let k = SuiteKey::parse(ED_KEY).unwrap();
        assert_eq!(k, ed_key());
        assert_eq!(k.suite(), KeySuite::Ed25519);
        k.verify_declared(Some("ed25519"), DOMAIN, MSG, &h(ED_SIG)).unwrap();
        assert_eq!(hex::encode(ed_sign(DOMAIN, MSG)), ED_SIG);
    }

    #[test]
    fn golden_p256_vector_verifies_under_either_spelling_of_the_key() {
        let compressed = SuiteKey::parse(P_KEY).unwrap();
        let uncompressed = SuiteKey::parse(P_KEY_UNCOMPRESSED).unwrap();
        assert_eq!(compressed, uncompressed);
        assert_eq!(uncompressed.id(), P_KEY, "one key, one spelling");
        assert_eq!(compressed.suite(), KeySuite::P256);
        compressed.verify_declared(Some("p256"), DOMAIN, MSG, &h(P_SIG)).unwrap();
        uncompressed.verify_declared(Some("p256"), DOMAIN, MSG, &h(P_SIG)).unwrap();
        assert_eq!(p_key(), compressed);
    }

    #[test]
    fn both_p256_signing_modes_coincide() {
        // A part that takes a message hashes the frame itself; a part that
        // takes a digest is given SHA-256 of the frame. Same signature input.
        use p256::ecdsa::signature::Signer as _;
        let by_message: p256::ecdsa::Signature = p_secret().sign(&signing_frame(DOMAIN, MSG));
        assert_eq!(hex::encode(by_message.to_bytes()), hex::encode(p_sign(DOMAIN, MSG)));
        assert_eq!(hex::encode(by_message.to_bytes()), P_SIG);
        p_key().verify(DOMAIN, MSG, &by_message.to_bytes()).unwrap();
    }

    #[test]
    fn a_signature_of_one_suite_is_refused_under_a_key_of_the_other() {
        // Both are 64 bytes, so the bytes cannot say which suite they are.
        assert_eq!(h(ED_SIG).len(), h(P_SIG).len());
        let e = p_key().verify(DOMAIN, MSG, &h(ED_SIG)).unwrap_err();
        assert!(e.contains("p256"), "{e}");
        let e = ed_key().verify(DOMAIN, MSG, &h(P_SIG)).unwrap_err();
        assert!(e.contains("ed25519"), "{e}");
        // Even with a tag that matches the key and the signature's real suite is the other one.
        assert!(ed_key().verify_declared(Some("ed25519"), DOMAIN, MSG, &h(P_SIG)).is_err());
        assert!(p_key().verify_declared(Some("p256"), DOMAIN, MSG, &h(ED_SIG)).is_err());
    }

    #[test]
    fn a_record_with_no_suite_is_refused() {
        for k in [ed_key(), p_key()] {
            let e = k.check_declared(None).unwrap_err();
            assert!(e.contains("no `suite`"), "{e}");
        }
        assert!(ed_key().verify_declared(None, DOMAIN, MSG, &h(ED_SIG)).is_err());
        assert!(p_key().verify_declared(None, DOMAIN, MSG, &h(P_SIG)).is_err());
    }

    #[test]
    fn the_suite_is_taken_from_the_enrolled_key_never_from_the_signature_or_the_record() {
        // A valid P-256 signature, and a record that says `p256`, presented for
        // an enrolled Ed25519 key: the record follows the signature's real
        // suite, and the key refuses it.
        let e = ed_key().verify_declared(Some("p256"), DOMAIN, MSG, &h(P_SIG)).unwrap_err();
        assert!(e.contains("says `p256`") && e.contains("enrolled key is ed25519"), "{e}");
        // And the reverse.
        let e = p_key().verify_declared(Some("ed25519"), DOMAIN, MSG, &h(ED_SIG)).unwrap_err();
        assert!(e.contains("says `ed25519`") && e.contains("enrolled key is p256"), "{e}");
        // An unknown suite is refused, whatever the key.
        for t in ["", "ES256", "Ed25519", "rsa", "ed25519 "] {
            assert!(ed_key().check_declared(Some(t)).is_err(), "{t:?}");
            assert!(p_key().check_declared(Some(t)).is_err(), "{t:?}");
        }
        // The matching tag is the only one that passes.
        ed_key().check_declared(Some("ed25519")).unwrap();
        p_key().check_declared(Some("p256")).unwrap();
    }

    #[test]
    fn a_signature_is_bound_to_its_domain_and_message() {
        assert!(ed_key().verify(DOMAIN, b"other message", &h(ED_SIG)).is_err());
        assert!(ed_key().verify(b"furcate/test/other/v1", MSG, &h(ED_SIG)).is_err());
        assert!(p_key().verify(DOMAIN, b"other message", &h(P_SIG)).is_err());
        assert!(p_key().verify(b"furcate/test/other/v1", MSG, &h(P_SIG)).is_err());
        assert!(p_key().verify(DOMAIN, MSG, &h(P_SIG)[..63]).is_err(), "DER and short forms are converted by the host first");
    }

    #[test]
    fn keys_are_read_only_with_a_suite_and_the_right_shape() {
        // Never without a prefix, except the stored Ed25519 form.
        let bare = ED_KEY.trim_start_matches("ed25519:");
        assert!(SuiteKey::parse(bare).is_err());
        assert_eq!(SuiteKey::parse_stored(bare).unwrap(), ed_key());
        assert_eq!(SuiteKey::parse_stored(&bare.to_uppercase()).unwrap().id(), ED_KEY);
        assert_eq!(SuiteKey::parse_stored(P_KEY).unwrap(), p_key());
        assert!(SuiteKey::parse_stored(&format!("{bare}00")).is_err(), "a bare key of any other length is not read");
        // Unknown prefix, wrong lengths, bad hex.
        for bad in [
            "rsa:00".to_string(),
            "ed25519:00".to_string(),
            format!("ed25519:{bare}00"),
            "p256:00".to_string(),
            format!("p256:{}", "02".repeat(34)),
            format!("p256:{}", hex::encode(&h(P_KEY.trim_start_matches("p256:"))[..32])),
            "p256:zz".to_string(),
            "ed25519:".to_string(),
        ] {
            assert!(SuiteKey::parse(&bad).is_err(), "{bad}");
        }
        // A well-formed length that is not a point on the curve.
        assert!(SuiteKey::parse(&format!("p256:04{}", "ab".repeat(64))).is_err());
        assert!(SuiteKey::parse(&format!("p256:02{}", "ff".repeat(32))).is_err());
        // Case does not make a different key.
        assert_eq!(SuiteKey::parse(&P_KEY.to_uppercase().replacen("P256", "p256", 1)).unwrap(), p_key());
    }
}
