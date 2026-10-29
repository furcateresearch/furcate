//! Root-of-trust backends.
//!
//! Each backend implements [`crate::RootOfTrust`] against one class of
//! hardware. They are deliberately independent: a platform that gains a
//! stronger root of trust changes which backend is selected, not how the rest
//! of Furcate treats identity.

pub mod ek_bind;
pub mod fingerprint;
pub mod firmware_tpm;
pub mod host;
pub mod optee;
pub mod rpi_fw_broker;
pub mod rpi_fw_crypto;
pub mod select;
pub mod tpm2_tools;

/// Apple Secure Enclave. macOS has no TPM; this is the strongest root of trust
/// the platform offers a daemon.
#[cfg(target_os = "macos")]
pub mod secure_enclave;

#[cfg(feature = "tss")]
pub mod tss_native;

pub use fingerprint::{Characteristic, Continuity, Fingerprint, FingerprintRot, SealedKey};
pub use host::SoftIdentity;
pub use rpi_fw_broker::RpiFwBroker;
pub use rpi_fw_crypto::RpiFwCrypto;
pub use select::{
    emulated_tpm_allowed, endorsement, open_backend, select, Endorsement, NoHardwareRoot, Policy, Selection,
    ALLOW_EMULATED_TPM, FWCRYPTO_DIRECT,
};
pub use tpm2_tools::{Tpm2Tools, TpmVendor};

#[cfg(target_os = "macos")]
pub use secure_enclave::SecureEnclave;

#[cfg(feature = "tss")]
pub use tss_native::TssNative;
