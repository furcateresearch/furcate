//! Node identifier derivation.
//!
//! A node ID commits to the public half of the node's endorsement key, so it
//! names a specific piece of silicon. It is stable across reboots and
//! reinstalls because the EK is derived deterministically from the TPM's
//! endorsement seed, and it cannot be moved to another machine because the
//! private half is not extractable.

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// The scheme prefix carried by every node identifier.
pub const PREFIX: &str = "furcate:node:";

/// A hardware-derived node identifier.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Derive an identifier from the marshalled public endorsement key.
    ///
    /// The digest is base32-encoded rather than hex so the identifier stays
    /// case-insensitive and shorter, which matters where it appears in
    /// hostnames, filenames and log lines.
    pub fn from_ek_public(ek_public: &[u8]) -> Self {
        let digest = Sha256::digest(ek_public);
        NodeId(format!(
            "{PREFIX}{}",
            BASE32_NOPAD.encode(&digest).to_lowercase()
        ))
    }

    /// The full identifier, including the scheme prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The derived portion, without the scheme prefix.
    pub fn suffix(&self) -> &str {
        self.0.strip_prefix(PREFIX).unwrap_or(&self.0)
    }

    /// A shortened form for display. Never use this for comparison or lookup —
    /// it is deliberately lossy.
    pub fn short(&self) -> String {
        self.suffix().chars().take(12).collect()
    }

    /// Parse an identifier that was previously serialized.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let suffix = s
            .strip_prefix(PREFIX)
            .ok_or_else(|| anyhow::anyhow!("node id must start with `{PREFIX}`"))?;
        if suffix.len() != 52 {
            anyhow::bail!(
                "node id body must be 52 base32 characters, got {}",
                suffix.len()
            );
        }
        if !suffix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            anyhow::bail!("node id body must be lowercase base32");
        }
        Ok(NodeId(s.to_string()))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_stable() {
        let a = NodeId::from_ek_public(b"some marshalled public key");
        let b = NodeId::from_ek_public(b"some marshalled public key");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_keys_give_distinct_ids() {
        let a = NodeId::from_ek_public(b"key one");
        let b = NodeId::from_ek_public(b"key two");
        assert_ne!(a, b);
    }

    #[test]
    fn round_trips_through_parse() {
        let id = NodeId::from_ek_public(b"key");
        assert_eq!(NodeId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn rejects_malformed() {
        assert!(NodeId::parse("furcate:node:TOOSHORT").is_err());
        assert!(NodeId::parse("not-a-node-id").is_err());
        // Correct length but uppercase, which would break case-insensitive lookup.
        let upper = format!("{PREFIX}{}", "A".repeat(52));
        assert!(NodeId::parse(&upper).is_err());
    }

    #[test]
    fn short_form_is_not_the_identifier() {
        let id = NodeId::from_ek_public(b"key");
        assert_eq!(id.short().len(), 12);
        assert_ne!(id.short(), id.suffix());
    }
}
