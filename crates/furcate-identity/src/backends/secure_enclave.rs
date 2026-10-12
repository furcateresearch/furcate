//! Identity from an Apple Secure Enclave.
//!
//! A Mac has no TPM and never will, but it has a coprocessor that generates a
//! P-256 key inside itself and will sign with it while refusing to hand it
//! over. That is the property `fingerprint`'s module doc names as the line
//! between asserting an identifier and proving possession of one: a key the
//! hardware will use but never surrender.
//!
//! ## Why this is `Device` and not `SecureElement`
//!
//! The tempting classification is [`SecureElement`], which would let a Mac hold
//! the controlling role for a cluster. It is wrong, and the reason is written
//! in [`AssuranceClass::may_control`]: the controller decides who else is a
//! member, so it must attest *what it is running*, not merely prove it holds a
//! key.
//!
//! macOS will not do the second part. The Secure Enclave exposes no
//! measurement registers, and App Attest -- the one API that produces an
//! Apple-signed statement about the running binary -- reports `isSupported ==
//! false` outside an App Store application, which a system daemon is not.
//! Measured on an M2 with Full Security secure boot and SIP enabled:
//! `DCAppAttestService.shared.isSupported` is false and `generateKey` fails
//! with `com.apple.devicecheck error 1`.
//!
//! So a Mac proves possession and says nothing about its software, which is
//! exactly [`Device`]: enough to be a trusted member, not enough to be the
//! party that decides who else is one.
//!
//! ## Why a helper, and why not the keychain
//!
//! The agent is Rust and does not link the Security framework; the helper is
//! Swift and small enough to read in full.
//!
//! The helper deliberately avoids the keychain. A persistent Secure Enclave
//! key stored as a keychain item fails with `-34018`
//! (`errSecMissingEntitlement`), and the entitlement it wants must be backed
//! by an Apple provisioning profile -- an Apple licence underneath the node's
//! identity, which this project's trust root may not depend on. CryptoKit
//! instead returns a *wrapped* key blob that only this machine's enclave can
//! unwrap, stored as an ordinary file. The private key still never exists
//! outside the enclave, and the file is inert on any other Mac.
//!
//! [`SecureElement`]: AssuranceClass::SecureElement
//! [`Device`]: AssuranceClass::Device

use crate::node_id::NodeId;
use crate::rot::{AssuranceClass, PcrSet, Quote, RootOfTrust};
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

/// The helper that speaks to the enclave. Looked up on PATH so a development
/// build and an installed one differ in PATH rather than in code.
const HELPER: &str = "furcate-sep";

/// The file name a caller should use, so the two binaries agree without this
/// crate learning where config lives.
pub const KEY_FILE: &str = "secure-enclave.key";

pub struct SecureEnclave {
    /// Where the wrapped key lives. Not a secret in the usual sense -- it
    /// cannot be unwrapped on another machine -- but a machine's identity
    /// should not be world-readable even when a copy is useless.
    path: PathBuf,
    /// Public key, raw X9.62 (64 bytes for P-256: X || Y).
    public: Vec<u8>,
}

impl SecureEnclave {
    /// Open the enclave-held identity, creating the key on first use.
    ///
    /// Fails rather than falling back when there is no usable enclave. A
    /// silent fallback is what leaves a fleet believing it is hardware-bound
    /// when part of it is not.
    pub fn open(path: PathBuf) -> Result<Self> {
        if !cfg!(target_os = "macos") {
            anyhow::bail!("the Secure Enclave backend is macOS only");
        }
        if !path.exists() {
            Self::run(&["create", &path.to_string_lossy()])
                .context("creating a key in the Secure Enclave")?;
        }
        let public = Self::run(&["public", &path.to_string_lossy()])
            .context("reading the public key from the Secure Enclave")?;
        let public = hex::decode(public.trim())
            .context("the helper returned a public key that is not hex")?;
        if public.len() != 64 {
            anyhow::bail!("expected a 64-byte P-256 public key, got {}", public.len());
        }
        Ok(Self { path, public })
    }

    fn run(args: &[&str]) -> Result<String> {
        let out = Command::new(HELPER)
            .args(args)
            .output()
            .with_context(|| format!("running {HELPER} {}", args[0]))?;
        if !out.status.success() {
            return Err(anyhow!(
                "{HELPER} {}: {}",
                args[0],
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8(out.stdout)?)
    }

    /// What macOS will state about how this machine booted.
    ///
    /// Not a measurement chain: there is nothing to replay and no register to
    /// compare against a reference. It is the platform's own answer to "is
    /// secure boot at full security, and is SIP on", digested so it travels in
    /// the same shape as a register bank. A verifier reading `Device` already
    /// knows not to treat this as measured boot.
    fn boot_state() -> PcrSet {
        let ask = |cmd: &str, args: &[&str]| -> String {
            Command::new(cmd)
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        };

        let sip = ask("csrutil", &["status"]);
        let policy = ask("system_profiler", &["SPiBridgeDataType"])
            .lines()
            .filter(|l| l.contains("Secure Boot") || l.contains("System Integrity"))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("; ");

        let mut values = BTreeMap::new();
        values.insert(0, Sha256::digest(policy.as_bytes()).to_vec());
        values.insert(1, Sha256::digest(sip.as_bytes()).to_vec());
        PcrSet { bank: "sha256".to_string(), values }
    }
}

impl RootOfTrust for SecureEnclave {
    fn assurance(&self) -> AssuranceClass {
        // See the module doc. Not SecureElement: no attestation of software.
        AssuranceClass::Device
    }

    fn ek_public(&self) -> Result<Vec<u8>> {
        Ok(self.public.clone())
    }

    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        // Apple issues no per-device certificate a daemon can reach. App
        // Attest is the nearest equivalent and is App Store only, so nothing
        // vouches for this key but the machine itself. Saying so is the point.
        Ok(None)
    }

    fn ak_public(&self) -> Result<Vec<u8>> {
        // One enclave key serves as both. A TPM separates endorsement from
        // attestation so the endorsement key can stay privacy-sensitive and
        // unused; the enclave offers no such split, and minting a second key
        // would imply a separation that does not exist.
        Ok(self.public.clone())
    }

    fn pcrs(&self) -> Result<PcrSet> {
        Ok(Self::boot_state())
    }

    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        if nonce.is_empty() {
            anyhow::bail!("a quote without a nonce is replayable; supply one");
        }
        let pcrs = Self::boot_state();

        // Bind the nonce to the boot state, so a signature cannot be lifted
        // from one context and presented in another.
        let mut message = Vec::new();
        message.extend_from_slice(b"furcate-sep-quote\0");
        message.extend_from_slice(nonce);
        for (idx, digest) in &pcrs.values {
            message.extend_from_slice(&idx.to_be_bytes());
            message.extend_from_slice(digest);
        }

        let signature = hex::decode(
            Self::run(&["sign", &self.path.to_string_lossy(), &hex::encode(&message)])?.trim(),
        )
        .context("the helper returned a signature that is not hex")?;
        if signature.is_empty() {
            anyhow::bail!("the Secure Enclave returned an empty signature");
        }

        Ok(Quote { message, signature, nonce: nonce.to_vec(), pcrs })
    }

    fn node_id(&self) -> Result<NodeId> {
        Ok(NodeId::from_ek_public(&self.public))
    }
}
