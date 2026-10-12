//! Sealing secrets to the local root of trust.
//!
//! A sealed secret is encrypted by the TPM under a key that never leaves the
//! chip, against a policy over platform measurements. It cannot be copied to
//! another machine, and it will not unseal on a machine that booted
//! differently.
//!
//! What this does and does not buy is worth stating plainly. It removes the
//! "someone copied the file" failure entirely: the ciphertext is useless off
//! this chip. It does **not** stop a process already running as the owning
//! user on this machine, in the expected boot state, from asking the TPM to
//! unseal. For a secret that must also resist that, seal it with an
//! authorization value the operator supplies — then the machine and the
//! operator are both required.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Registers the seal policy binds to.
///
/// Firmware, option ROMs and secure-boot state: the measurements that change
/// when the platform is tampered with or reconfigured, and that stay stable
/// across ordinary reboots. Deliberately excludes registers that move with
/// disk layout, which would make a seal break on unrelated changes.
pub const SEAL_PCRS: &str = "sha256:0,2,7";

pub struct Sealer {
    work: PathBuf,
    tcti: String,
}

impl Sealer {
    /// Open the machine's TPM for sealing.
    ///
    /// An emulated TPM is refused: its seed is a file held by another
    /// process, so a seal to it binds the data to that process's state, not to
    /// this machine, and the data is lost when the emulator goes away.
    pub fn open() -> Result<Self> {
        use crate::backends::tpm2_tools::{unusable_device, TPM_DEVICE, TPM_SYSFS_CLASS};
        if let Some(why) = unusable_device(Path::new(TPM_DEVICE), Path::new(TPM_SYSFS_CLASS)) {
            bail!("not sealing to {TPM_DEVICE}: it is not a usable TPM: {why}");
        }
        if let furcate_host::board::TpmKind::Emulated { reason } = furcate_host::board::tpm_kind() {
            bail!("not sealing to {TPM_DEVICE}: {reason}");
        }
        Self::with_device(TPM_DEVICE)
    }

    pub fn with_device(device: &str) -> Result<Self> {
        if !Path::new(device).exists() {
            bail!("no TPM device at {device}");
        }
        let work = std::env::temp_dir().join(format!("furcate-seal-{}", std::process::id()));
        std::fs::create_dir_all(&work)?;
        Ok(Self {
            work,
            tcti: format!("device:{device}"),
        })
    }

    fn run(&self, tool: &str, args: &[&str]) -> Result<Vec<u8>> {
        let out = Command::new(tool)
            .args(args)
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .current_dir(&self.work)
            .output()
            .with_context(|| format!("spawning {tool}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!(
                "{tool} failed: {}",
                err.lines()
                    .find(|l| l.contains("ERROR") || !l.trim().is_empty())
                    .unwrap_or("no output")
                    .trim()
            );
        }
        Ok(out.stdout)
    }

    /// The primary key the sealed object hangs under.
    ///
    /// Derived from the owner hierarchy seed, so it is reproducible on this
    /// chip and never stored.
    fn ensure_primary(&self) -> Result<()> {
        if self.work.join("primary.ctx").exists() {
            return Ok(());
        }
        self.run(
            "tpm2_createprimary",
            &["-C", "o", "-g", "sha256", "-G", "rsa", "-c", "primary.ctx"],
        )?;
        Ok(())
    }

    /// Seal `secret`, writing the sealed object to `out_dir`.
    ///
    /// The plaintext is passed through a file in the work directory because
    /// tpm2-tools reads it that way; the directory is removed on drop.
    pub fn seal(&self, secret: &[u8], out_dir: &Path) -> Result<()> {
        self.ensure_primary()?;

        // Bind to platform state, so the secret does not unseal on a machine
        // that booted differently.
        self.run(
            "tpm2_createpolicy",
            &["--policy-pcr", "-l", SEAL_PCRS, "-L", "policy.dat"],
        )?;

        let plain = self.work.join("plain.bin");
        std::fs::write(&plain, secret).context("staging the secret")?;

        let result = self.run(
            "tpm2_create",
            &[
                "-C", "primary.ctx", "-L", "policy.dat", "-i", "plain.bin", "-u", "seal.pub",
                "-r", "seal.priv",
            ],
        );

        // Remove the plaintext before doing anything else, whether or not the
        // seal succeeded.
        let _ = std::fs::write(&plain, vec![0u8; secret.len()]);
        let _ = std::fs::remove_file(&plain);
        result?;

        std::fs::create_dir_all(out_dir)?;
        for name in ["seal.pub", "seal.priv"] {
            std::fs::copy(self.work.join(name), out_dir.join(name))
                .with_context(|| format!("writing {name}"))?;
        }
        Ok(())
    }

    /// Unseal a previously sealed object.
    pub fn unseal(&self, sealed_dir: &Path) -> Result<Vec<u8>> {
        self.ensure_primary()?;
        for name in ["seal.pub", "seal.priv"] {
            let src = sealed_dir.join(name);
            if !src.exists() {
                bail!("{} is missing from {}", name, sealed_dir.display());
            }
            std::fs::copy(&src, self.work.join(name))?;
        }
        self.run(
            "tpm2_load",
            &["-C", "primary.ctx", "-u", "seal.pub", "-r", "seal.priv", "-c", "seal.ctx"],
        )?;
        let out = self.run("tpm2_unseal", &["-c", "seal.ctx", "-p", &format!("pcr:{SEAL_PCRS}")])?;
        if out.is_empty() {
            bail!("unsealed an empty secret");
        }
        Ok(out)
    }
}

impl Drop for Sealer {
    fn drop(&mut self) {
        // The work directory holds key contexts and may have held plaintext.
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The register list, without the bank name. Parsed rather than string
    /// matched: `sha256` itself contains digits, so searching the whole
    /// constant finds registers that are not selected.
    fn selected_registers() -> Vec<u32> {
        SEAL_PCRS
            .split_once(':')
            .map(|(_, list)| list.split(',').filter_map(|p| p.trim().parse().ok()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn the_policy_excludes_registers_that_move_with_disk_layout() {
        // Register 5 tracks the partition table and would break a seal on an
        // unrelated change.
        let regs = selected_registers();
        assert!(!regs.contains(&5), "selected: {regs:?}");
        assert!(regs.contains(&0));
        assert!(regs.contains(&7), "secure-boot state must be bound");
    }

    #[test]
    fn the_policy_binds_at_least_firmware_and_secure_boot() {
        let regs = selected_registers();
        assert!(regs.len() >= 2);
        assert!(regs.iter().all(|r| *r <= 7), "platform registers only");
    }

    #[test]
    fn a_missing_device_is_refused_rather_than_silently_degraded() {
        assert!(Sealer::with_device("/dev/definitely-not-a-tpm").is_err());
    }

    // Sealing itself is exercised against hardware by `furcatectl operator
    // seal`, and against a software TPM in the selftest. A unit test would
    // need a chip, which most machines running the suite do not have.
}
