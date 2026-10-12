//! Sealed custody of keys, proofs and data.
//!
//! Everything is encrypted at rest under a key sealed to the local root of
//! trust, so a disk pulled out of a machine is inert and a machine that booted
//! the wrong way cannot unseal its own data.
//!
//! Sharing does not hand over the vault key. The holder re-wraps one object's
//! key to the requesting node's attested public key, so access is granted per
//! object, to a specific node, in a specific attested state. Revocation is
//! declining to re-wrap next time. Because the recipient's key is bound to its
//! attestation, sharing and verification are one decision rather than two
//! systems that can disagree.

pub mod envelope;
pub mod seal;
pub mod share;

pub use envelope::{Envelope, EnvelopeError};
pub use seal::{Sealed, Vault, VaultError};
pub use share::{PeerKey, WrappedKey};
