//! Hardware-rooted node identity for Furcate.
//!
//! A node's identity is *derived* from its root of trust, never distributed to
//! it as a secret. The private half never leaves the hardware; what the rest of
//! the system handles is a public identifier and signed evidence.
//!
//! Roots of trust differ enormously across the hardware Furcate targets — a
//! rack server has TPM 2.0, a Jetson has TrustZone, an ESP32 has fuses. Rather
//! than require the strongest everywhere, [`RootOfTrust`] abstracts over them
//! and [`AssuranceClass`] records honestly how strong the binding actually is.
//!
//! ## Which backend a node gets
//!
//! [`backends::select`] tries a TPM, then a TEE, then a device key, and
//! reports the class each earned with the reason. A discrete or platform TPM
//! is `Tpm`. A Jetson's OP-TEE firmware TPM is `Tpm` only when secure boot is
//! fused and its EK certificate chains to a CA the operator lists, and `Tee`
//! otherwise ([`backends::firmware_tpm`]). An OP-TEE device with no recognised
//! trusted application answering is reported and not claimed. A Raspberry Pi
//! 5 signs with its OTP key through the firmware, which root can read, so it
//! is `Device` ([`backends::rpi_fw_crypto`]); with a TPM HAT it is `Tpm`.
//! `Soft` is never selected automatically.

pub mod backends;
pub mod custody;
pub mod enroll;
pub mod expected;
pub mod node_id;
pub mod pin;
pub mod recovery;
pub mod seal;
pub mod signer;
pub mod rot;
pub mod leaf;
pub mod unit_roster;
pub mod unit_rollover;
pub mod suite;

pub use custody::{Custody, CustodyGrant, CustodyMode, CustodyRecord, CustodySettings};
pub use enroll::Enrollment;
pub use leaf::{admits_leaf, LeafKeyCustody, Lockdown};
pub use suite::{signing_digest, signing_frame, KeySuite, SuiteKey};
pub use unit_roster::{EnrolledUnit, UnitRoster, Verdict};
pub use node_id::NodeId;
pub use pin::EnrolledIdentity;
pub use signer::{Ed25519Signer, MessageSigner, RootOfTrustSigner, SignerKey};
pub use recovery::{Fault, RecoveryAction, RecoveryPolicy};
pub use seal::Sealer;
pub use rot::{AssuranceClass, Evidence, PcrSet, Quote, RootOfTrust};
