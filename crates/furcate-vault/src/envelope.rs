//! Envelope encryption for payloads larger than a TPM can hold.
//!
//! A TPM seals *secrets*, not files: a sealed data object is capped at a few
//! hundred bytes. So anything larger is encrypted under a randomly generated
//! data key, and only that key is sealed to the chip. The ciphertext can then
//! sit anywhere — it is inert without the chip that holds the key.
//!
//! This is the same shape as the vault's per-object keys, applied to a single
//! file rather than a store.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use furcate_identity::custody::CustodyRecord;
use serde::{Deserialize, Serialize};

/// A sealed data key is small enough for a TPM; the payload is not.
pub const DATA_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Build a cipher nonce from bytes, or nothing if the length is wrong.
///
/// `Nonce::from_slice` panicked on a wrong length and is now deprecated in
/// favour of `TryFrom`. Every caller here already checks the length, so this
/// returns an option rather than asserting — a length check that exists in two
/// places and disagrees is worse than one that returns a value.
pub(crate) fn nonce_of(bytes: &[u8]) -> Option<Nonce> {
    Nonce::try_from(bytes).ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The data key was not the expected length.
    BadKey,
    /// The nonce was not the expected length.
    BadNonce,
    /// Decryption failed: wrong key, altered ciphertext, or wrong context.
    Undecryptable,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::BadKey => write!(f, "data key must be {DATA_KEY_LEN} bytes"),
            EnvelopeError::BadNonce => write!(f, "nonce must be {NONCE_LEN} bytes"),
            EnvelopeError::Undecryptable => write!(
                f,
                "payload could not be decrypted: wrong data key, altered ciphertext, or wrong context"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// An encrypted payload and the context it is bound to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub nonce: String,
    pub ciphertext: String,
    /// Authenticated but not encrypted. Binding a purpose here stops a
    /// payload sealed for one use being replayed as another.
    pub context: String,
    /// The custody mode and class the data key was sealed under, authenticated
    /// with the context. Every envelope sealed now carries it; one written
    /// before custody was recorded has none, opens as it always did, and says
    /// so through [`Envelope::custody_stated`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<CustodyRecord>,
}

impl Envelope {
    /// The recorded custody, or why there is none.
    pub fn custody_stated(&self) -> Result<CustodyRecord, String> {
        self.custody
            .ok_or_else(|| "sealed before custody mode and class were recorded".to_string())
    }
}

fn aad(custody: Option<&CustodyRecord>, context: &str) -> Vec<u8> {
    match custody {
        None => context.as_bytes().to_vec(),
        Some(c) => {
            let mut a = c.bound_bytes();
            a.push(0);
            a.extend_from_slice(context.as_bytes());
            a
        }
    }
}

/// Encrypt a payload under a data key.
pub fn seal(
    data: &[u8],
    key: &[u8],
    nonce: &[u8],
    context: &str,
    custody: &CustodyRecord,
) -> Result<Envelope, EnvelopeError> {
    if key.len() != DATA_KEY_LEN {
        return Err(EnvelopeError::BadKey);
    }
    if nonce.len() != NONCE_LEN {
        return Err(EnvelopeError::BadNonce);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| EnvelopeError::BadKey)?;
    let ct = cipher
        .encrypt(
            &nonce_of(nonce).ok_or(EnvelopeError::BadNonce)?,
            Payload {
                msg: data,
                aad: &aad(Some(custody), context),
            },
        )
        .map_err(|_| EnvelopeError::Undecryptable)?;
    Ok(Envelope {
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
        context: context.to_string(),
        custody: Some(*custody),
    })
}

/// Decrypt a payload with its data key.
pub fn open(envelope: &Envelope, key: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if key.len() != DATA_KEY_LEN {
        return Err(EnvelopeError::BadKey);
    }
    let nonce = hex::decode(&envelope.nonce).map_err(|_| EnvelopeError::BadNonce)?;
    if nonce.len() != NONCE_LEN {
        return Err(EnvelopeError::BadNonce);
    }
    let ct = hex::decode(&envelope.ciphertext).map_err(|_| EnvelopeError::Undecryptable)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| EnvelopeError::BadKey)?;
    cipher
        .decrypt(
            &nonce_of(&nonce).ok_or(EnvelopeError::BadNonce)?,
            Payload {
                msg: &ct,
                aad: &aad(envelope.custody.as_ref(), &envelope.context),
            },
        )
        .map_err(|_| EnvelopeError::Undecryptable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_identity::custody::CustodyMode;
    use furcate_identity::AssuranceClass;

    const REC: CustodyRecord = CustodyRecord { mode: CustodyMode::SelfCustody, class: AssuranceClass::Tpm };

    const KEY: [u8; 32] = [7u8; 32];
    const NONCE: [u8; 12] = [3u8; 12];

    #[test]
    fn a_payload_round_trips() {
        let e = seal(b"a backup archive", &KEY, &NONCE, "backup", &REC).unwrap();
        assert_eq!(open(&e, &KEY).unwrap(), b"a backup archive");
    }

    #[test]
    fn a_large_payload_round_trips() {
        // The whole point: payloads far larger than a TPM can hold.
        let big = vec![0xABu8; 64 * 1024];
        let e = seal(&big, &KEY, &NONCE, "backup", &REC).unwrap();
        assert_eq!(open(&e, &KEY).unwrap(), big);
    }

    #[test]
    fn ciphertext_does_not_reveal_the_payload() {
        let e = seal(b"secret archive", &KEY, &NONCE, "backup", &REC).unwrap();
        assert!(!e.ciphertext.contains(&hex::encode(b"secret archive")));
    }

    #[test]
    fn the_wrong_data_key_does_not_open_it() {
        let e = seal(b"data", &KEY, &NONCE, "backup", &REC).unwrap();
        assert_eq!(open(&e, &[9u8; 32]), Err(EnvelopeError::Undecryptable));
    }

    #[test]
    fn altering_the_ciphertext_is_detected() {
        let mut e = seal(b"data", &KEY, &NONCE, "backup", &REC).unwrap();
        let mut raw = hex::decode(&e.ciphertext).unwrap();
        raw[0] ^= 0xff;
        e.ciphertext = hex::encode(raw);
        assert_eq!(open(&e, &KEY), Err(EnvelopeError::Undecryptable));
    }

    #[test]
    fn changing_the_context_is_detected() {
        let mut e = seal(b"data", &KEY, &NONCE, "backup", &REC).unwrap();
        e.context = "something-else".into();
        assert_eq!(open(&e, &KEY), Err(EnvelopeError::Undecryptable));
    }

    #[test]
    fn an_envelope_records_custody_and_it_cannot_be_edited() {
        let mut e = seal(b"data", &KEY, &NONCE, "backup", &REC).unwrap();
        assert_eq!(e.custody_stated().unwrap(), REC);
        e.custody = Some(CustodyRecord { mode: CustodyMode::Elected, class: AssuranceClass::Tpm });
        assert_eq!(open(&e, &KEY), Err(EnvelopeError::Undecryptable));
        e.custody = None;
        assert_eq!(open(&e, &KEY), Err(EnvelopeError::Undecryptable));
    }

    #[test]
    fn an_envelope_from_before_custody_was_recorded_still_opens() {
        let cipher = ChaCha20Poly1305::new_from_slice(&KEY).unwrap();
        let ct = cipher
            .encrypt(&nonce_of(&NONCE).unwrap(), Payload { msg: b"old".as_slice(), aad: b"backup" })
            .unwrap();
        let old = format!(
            r#"{{"nonce":"{}","ciphertext":"{}","context":"backup"}}"#,
            hex::encode(NONCE),
            hex::encode(ct)
        );
        let e: Envelope = serde_json::from_str(&old).unwrap();
        assert_eq!(open(&e, &KEY).unwrap(), b"old");
        assert!(e.custody_stated().unwrap_err().contains("before custody"));
    }

    #[test]
    fn key_and_nonce_lengths_are_enforced() {
        assert_eq!(seal(b"d", &[1u8; 16], &NONCE, "c", &REC), Err(EnvelopeError::BadKey));
        assert_eq!(seal(b"d", &KEY, &[1u8; 8], "c", &REC), Err(EnvelopeError::BadNonce));
    }
}
