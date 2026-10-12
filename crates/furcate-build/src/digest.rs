//! Content addressing.
//!
//! Everything the build arm stores or names is named by the SHA-256 of its
//! bytes. A name is therefore a claim about content that anyone can check by
//! rehashing — not a label someone assigned. This is the same 32-byte digest
//! the ledger chains with (`furcate_ledger::Digest32`), so a build result and
//! the ledger entry that records it speak in one currency.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// A SHA-256 content digest. Displayed and serialised as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The digest of a byte slice.
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Digest(h.finalize().into())
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex; the length and alphabet are both checked.
    pub fn from_hex(s: &str) -> Result<Self, DigestError> {
        let bytes = hex::decode(s).map_err(|_| DigestError::NotHex)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| DigestError::WrongLength)?;
        Ok(Digest(arr))
    }

    /// The raw bytes, for handing to the ledger, which speaks `[u8; 32]`.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A streaming hasher, so a large file need not be held in memory to be named.
#[derive(Default)]
pub struct Hasher(Sha256);

impl Hasher {
    pub fn new() -> Self {
        Hasher(Sha256::new())
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub fn finish(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DigestError {
    NotHex,
    WrongLength,
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestError::NotHex => write!(f, "digest is not valid hex"),
            DigestError::WrongLength => write!(f, "digest is not 32 bytes"),
        }
    }
}

impl std::error::Error for DigestError {}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Short form keeps test output and logs readable.
        write!(f, "sha256:{}", &self.to_hex()[..16])
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // SHA-256 of the empty input.
        assert_eq!(
            Digest::of(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let d = Digest::of(b"furcate");
        assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
    }

    #[test]
    fn rejects_short_hex() {
        assert_eq!(Digest::from_hex("abcd"), Err(DigestError::WrongLength));
    }

    #[test]
    fn streaming_equals_oneshot() {
        let mut h = Hasher::new();
        h.update(b"fur");
        h.update(b"cate");
        assert_eq!(h.finish(), Digest::of(b"furcate"));
    }
}
