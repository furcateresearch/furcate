//! Guest lifecycle and VMM selection.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Available hypervisor backends.
///
/// The choice follows from what the guest must *prove*, not from taste.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vmm {
    /// QEMU with OVMF firmware and swtpm. Full UEFI secure boot and measured
    /// boot: the reference for what a machine-class boot cycle means.
    QemuOvmf,
    /// rust-vmm based, lighter device model, virtual TPM available. The
    /// practical middle for attested workloads.
    CloudHypervisor,
    /// Fastest boot and smallest attack surface, but no virtual TPM upstream —
    /// a virtio-TPM device has been demonstrated in research and is not
    /// shipped. For workloads that do not need measured boot.
    Firecracker,
}

impl Vmm {
    /// Whether this backend can give a guest a virtual TPM.
    pub fn supports_vtpm(&self) -> bool {
        matches!(self, Vmm::QemuOvmf | Vmm::CloudHypervisor)
    }

    /// Whether this backend measures firmware and boot chain.
    pub fn supports_measured_boot(&self) -> bool {
        matches!(self, Vmm::QemuOvmf)
    }

    /// Pick a backend for a guest's requirements.
    pub fn for_requirements(needs_measured_boot: bool, needs_vtpm: bool) -> Vmm {
        if needs_measured_boot {
            Vmm::QemuOvmf
        } else if needs_vtpm {
            Vmm::CloudHypervisor
        } else {
            Vmm::Firecracker
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestState {
    Defined,
    Booting,
    /// Running but not yet appraised.
    Running,
    /// Running and appraised.
    Attested,
    Stopped,
    /// Restored from a snapshot and awaiting re-enrollment.
    RestoredPendingEnrollment,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GuestError {
    /// The chosen backend cannot satisfy what the guest requires.
    BackendCannotAttest { vmm: Vmm },
    /// The guest has not booted far enough to attest.
    NotRunning { state: GuestState },
    /// A restored guest must re-enrol first.
    AwaitingReenrollment,
}

impl fmt::Display for GuestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestError::BackendCannotAttest { vmm } => write!(
                f,
                "{vmm:?} cannot provide a virtual TPM, so this guest cannot attest. \
                 Use QemuOvmf for measured boot"
            ),
            GuestError::NotRunning { state } => {
                write!(f, "guest is {state:?} and cannot produce evidence yet")
            }
            GuestError::AwaitingReenrollment => write!(
                f,
                "guest was restored from a snapshot and must re-enrol before attesting"
            ),
        }
    }
}

impl std::error::Error for GuestError {}

/// A machine-class guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Guest {
    pub id: String,
    pub host: String,
    pub vmm: Vmm,
    pub state: GuestState,
    /// Expected PCR 11, computed from the image the guest boots.
    pub expected_pcr11: Option<String>,
}

impl Guest {
    pub fn define(id: impl Into<String>, host: impl Into<String>, vmm: Vmm) -> Self {
        Self {
            id: id.into(),
            host: host.into(),
            vmm,
            state: GuestState::Defined,
            expected_pcr11: None,
        }
    }

    pub fn with_expected_pcr11(mut self, hex: impl Into<String>) -> Self {
        self.expected_pcr11 = Some(hex.into());
        self
    }

    pub fn boot(&mut self) -> &mut Self {
        self.state = GuestState::Booting;
        self
    }

    pub fn running(&mut self) -> &mut Self {
        self.state = GuestState::Running;
        self
    }

    pub fn restore_from_snapshot(&mut self) -> &mut Self {
        self.state = GuestState::RestoredPendingEnrollment;
        self
    }

    /// Attempt to attest, comparing against the pre-computed reference.
    pub fn attest(&mut self, reported_pcr11: &str) -> Result<bool, GuestError> {
        if !self.vmm.supports_vtpm() {
            return Err(GuestError::BackendCannotAttest { vmm: self.vmm });
        }
        match self.state {
            GuestState::RestoredPendingEnrollment => return Err(GuestError::AwaitingReenrollment),
            GuestState::Running | GuestState::Attested => {}
            other => return Err(GuestError::NotRunning { state: other }),
        }

        let matches = match &self.expected_pcr11 {
            Some(expected) => expected.eq_ignore_ascii_case(reported_pcr11),
            // With no reference value there is nothing to compare against, so
            // this is not an attestation — say so rather than passing.
            None => false,
        };
        if matches {
            self.state = GuestState::Attested;
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{expected_pcr11_hex, UkiSections};

    fn image() -> UkiSections {
        UkiSections::new()
            .with(".linux", b"kernel".to_vec())
            .with(".cmdline", b"ro quiet".to_vec())
    }

    fn guest() -> Guest {
        Guest::define("guest-1", "node-a", Vmm::QemuOvmf)
            .with_expected_pcr11(expected_pcr11_hex(&image()))
    }

    #[test]
    fn backend_selection_follows_requirements() {
        assert_eq!(Vmm::for_requirements(true, true), Vmm::QemuOvmf);
        assert_eq!(Vmm::for_requirements(false, true), Vmm::CloudHypervisor);
        assert_eq!(Vmm::for_requirements(false, false), Vmm::Firecracker);
    }

    #[test]
    fn firecracker_cannot_attest() {
        let mut g = Guest::define("g", "node-a", Vmm::Firecracker);
        g.running();
        assert_eq!(
            g.attest("whatever").unwrap_err(),
            GuestError::BackendCannotAttest {
                vmm: Vmm::Firecracker
            }
        );
    }

    #[test]
    fn a_guest_booting_the_expected_image_attests() {
        let mut g = guest();
        g.boot().running();
        assert!(g.attest(&expected_pcr11_hex(&image())).unwrap());
        assert_eq!(g.state, GuestState::Attested);
    }

    #[test]
    fn a_guest_booting_a_tampered_image_fails() {
        let tampered = UkiSections::new()
            .with(".linux", b"kernel".to_vec())
            .with(".cmdline", b"ro quiet init=/bin/sh".to_vec());
        let mut g = guest();
        g.boot().running();
        assert!(!g.attest(&expected_pcr11_hex(&tampered)).unwrap());
        assert_ne!(g.state, GuestState::Attested);
    }

    #[test]
    fn a_guest_with_no_reference_value_does_not_pass_by_default() {
        let mut g = Guest::define("g", "node-a", Vmm::QemuOvmf);
        g.running();
        assert!(!g.attest("anything").unwrap());
    }

    #[test]
    fn a_guest_that_has_not_booted_cannot_attest() {
        let mut g = guest();
        assert_eq!(
            g.attest("x").unwrap_err(),
            GuestError::NotRunning {
                state: GuestState::Defined
            }
        );
    }

    #[test]
    fn a_restored_guest_must_reenrol_before_attesting() {
        let mut g = guest();
        g.boot().running();
        g.attest(&expected_pcr11_hex(&image())).unwrap();
        g.restore_from_snapshot();
        assert_eq!(
            g.attest(&expected_pcr11_hex(&image())).unwrap_err(),
            GuestError::AwaitingReenrollment
        );
    }

    #[test]
    fn only_qemu_claims_full_measured_boot() {
        assert!(Vmm::QemuOvmf.supports_measured_boot());
        assert!(!Vmm::CloudHypervisor.supports_measured_boot());
        assert!(!Vmm::Firecracker.supports_vtpm());
    }
}
