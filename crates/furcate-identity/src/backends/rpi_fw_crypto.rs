//! Identity from the Raspberry Pi firmware cryptography service.
//!
//! A Pi 5 or CM5 holds a device-unique ECDSA P-256 private key in OTP. The
//! VideoCore firmware will sign with it, HMAC with it and return its public
//! half through a mailbox API, which `rpi-fw-crypto` (raspberrypi/utils,
//! packaged on Bookworm and Trixie) drives. This backend shells out to that
//! tool the way [`super::tpm2_tools`] drives `tpm2-tools`.
//!
//! ## Why this is `Device`
//!
//! The firmware signs without handing the key to the ARM side, which is the
//! possession property. But it is not a secure element: the same firmware
//! also offers a raw read of the key (`privkey`) to root, blocked only by a
//! lock flag that lasts until the next reboot and that boot configuration
//! (`lock_device_private_key=1`) or a running process must set. Anything that
//! ran as root before that lock could have copied the key. And the Pi records
//! no measurements of what it booted, so nothing here attests software
//! state. That is [`AssuranceClass::Device`]: a trusted member, not a
//! controller. A Pi with a TPM HAT is identified by the TPM instead.
//!
//! Whether the raw read was locked when this backend opened is recorded in
//! [`RpiFwCrypto::status`] so an operator can see it, but it does not raise the
//! class, because it says nothing about the boots before this one.

use crate::rot::{AssuranceClass, PcrSet, Quote, RootOfTrust};
use anyhow::{anyhow, bail, Context as _, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

const TOOL: &str = "rpi-fw-crypto";

/// The device-unique key slot.
pub const DEVICE_KEY_ID: u32 = 1;

/// Key status flags, as `rpifwcrypto.h` defines them.
pub const STATUS_DEVICE: u32 = 1 << 0;
pub const STATUS_READ_LOCKED: u32 = 1 << 8;
pub const STATUS_SIGN_LOCKED: u32 = 1 << 10;

pub struct RpiFwCrypto {
    key_id: u32,
    /// DER SubjectPublicKeyInfo for the slot's key.
    public: Vec<u8>,
    status: u32,
    work: PathBuf,
}

impl RpiFwCrypto {
    /// Open the device-unique key. Fails when the tool is absent, the
    /// firmware does not offer the service, or signing is locked.
    pub fn open() -> Result<Self> {
        Self::with_key(DEVICE_KEY_ID)
    }

    pub fn with_key(key_id: u32) -> Result<Self> {
        let id = key_id.to_string();
        let status_text = run(&["get-key-status", &id])?;
        let status = parse_key_status(&status_text)
            .ok_or_else(|| anyhow!("unrecognised get-key-status output: {}", status_text.trim()))?;
        if status & STATUS_SIGN_LOCKED != 0 {
            bail!("signing with OTP key {key_id} is locked until reboot");
        }
        let public = hex::decode(run(&["pubkey", "--key-id", &id, "--outform", "hex"])?.trim())
            .context("rpi-fw-crypto returned a public key that is not hex")?;
        if public.is_empty() {
            bail!("rpi-fw-crypto returned an empty public key for slot {key_id}");
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let work = std::env::temp_dir().join(format!("furcate-rpifw-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
        Ok(Self { key_id, public, status, work })
    }

    /// The key status bit-field as the firmware reported it at open.
    pub fn status(&self) -> u32 {
        self.status
    }

    /// Whether the raw OTP read of this key was locked at open.
    pub fn read_locked(&self) -> bool {
        self.status & STATUS_READ_LOCKED != 0
    }

    /// The bootloader's secure boot bit-field, digested into register 0 so it
    /// travels in the same shape as a register bank. Not a measurement:
    /// nothing extends it, and a verifier reading `Device` knows that.
    fn boot_state() -> PcrSet {
        let signed = std::fs::read("/proc/device-tree/chosen/bootloader/signed").unwrap_or_default();
        let mut values = BTreeMap::new();
        values.insert(0, Sha256::digest(&signed).to_vec());
        PcrSet { bank: "sha256".to_string(), values }
    }
}

impl Drop for RpiFwCrypto {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

fn run(args: &[&str]) -> Result<String> {
    let out = Command::new(TOOL)
        .args(args)
        .output()
        .with_context(|| format!("running {TOOL} {}; install the rpi-fw-crypto package", args[0]))?;
    if !out.status.success() {
        bail!("{TOOL} {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse `Key 1 status: 0x00000101 (DEVICE READ_LOCKED)`.
pub fn parse_key_status(text: &str) -> Option<u32> {
    let after = text.split_once("status:")?.1.trim();
    let hex = after.split_whitespace().next()?.strip_prefix("0x")?;
    u32::from_str_radix(hex, 16).ok()
}

impl RootOfTrust for RpiFwCrypto {
    fn assurance(&self) -> AssuranceClass {
        // See the module doc: possession without attestation.
        AssuranceClass::Device
    }

    fn message_signer(&self) -> Option<&dyn crate::signer::MessageSigner> {
        Some(self)
    }

    fn ek_public(&self) -> Result<Vec<u8>> {
        Ok(self.public.clone())
    }

    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        // Raspberry Pi issues no per-device certificate for this key.
        Ok(None)
    }

    fn ak_public(&self) -> Result<Vec<u8>> {
        // One key serves as both; there is no second slot the firmware
        // generates and guards differently.
        Ok(self.public.clone())
    }

    fn pcrs(&self) -> Result<PcrSet> {
        Ok(Self::boot_state())
    }

    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        if nonce.is_empty() {
            bail!("a quote without a nonce is replayable; supply one");
        }
        let pcrs = Self::boot_state();
        let mut message = Vec::new();
        message.extend_from_slice(b"furcate-rpifw-quote\0");
        message.extend_from_slice(nonce);
        for (idx, digest) in &pcrs.values {
            message.extend_from_slice(&idx.to_be_bytes());
            message.extend_from_slice(digest);
        }

        let signature = self.sign_message(&message)?;
        Ok(Quote { message, signature, nonce: nonce.to_vec(), pcrs })
    }
}

impl RpiFwCrypto {
    /// Have the firmware sign `message` with the OTP key: ECDSA P-256 over
    /// the SHA-256 of `message`, returned as the tool prints it.
    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // The tool hashes the file with SHA-256 and signs the digest. Each
        // call writes its own file, so concurrent signatures do not race.
        let input = self.work.join(format!("sign-{}.msg", NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&input, message).context("writing the message to sign")?;
        let id = self.key_id.to_string();
        let sig = run(&["sign", "--in", &input.to_string_lossy(), "--key-id", &id, "--alg", "ec", "--outform", "hex"]);
        let _ = std::fs::remove_file(&input);
        let signature = hex::decode(sig?.trim()).context("rpi-fw-crypto returned a signature that is not hex")?;
        if signature.is_empty() {
            bail!("the firmware returned an empty signature");
        }
        Ok(signature)
    }
}

/// The OTP key signs cell links and roll-ups on a Pi that heads a cell.
impl crate::signer::MessageSigner for RpiFwCrypto {
    fn public_key(&self) -> Result<crate::signer::SignerKey> {
        Ok(crate::signer::SignerKey::P256(self.public.clone()))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_message(message)
    }
}

/// Custody keys on a Pi are an HMAC under the OTP key, computed by the
/// firmware, so the same board re-derives the same key on every boot without
/// the key ever reaching the ARM side.
impl crate::custody::SiliconKey for RpiFwCrypto {
    fn class(&self) -> AssuranceClass {
        AssuranceClass::Device
    }

    fn keyed_digest(&self, message: &[u8]) -> Result<[u8; 32]> {
        let input = self.work.join("custody.msg");
        std::fs::write(&input, message).context("writing the message to key")?;
        let id = self.key_id.to_string();
        let out = run(&["hmac", "--in", &input.to_string_lossy(), "--key-id", &id, "--outform", "hex"]);
        let _ = std::fs::remove_file(&input);
        let mac = hex::decode(out?.trim()).context("rpi-fw-crypto returned an HMAC that is not hex")?;
        mac.as_slice()
            .try_into()
            .map_err(|_| anyhow!("rpi-fw-crypto returned a {}-byte HMAC, expected 32", mac.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_status_parses() {
        let s = parse_key_status("Key 1 status: 0x00000101 (DEVICE READ_LOCKED)\n").unwrap();
        assert_eq!(s & STATUS_DEVICE, STATUS_DEVICE);
        assert_eq!(s & STATUS_READ_LOCKED, STATUS_READ_LOCKED);
        assert_eq!(s & STATUS_SIGN_LOCKED, 0);
        assert_eq!(parse_key_status("Key 2 status: 0x00000000 ()"), Some(0));
        assert_eq!(parse_key_status("Failed to get key status"), None);
    }
}
