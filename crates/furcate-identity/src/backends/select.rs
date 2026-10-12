//! Choosing this node's root of trust.
//!
//! Backends are tried strongest first: a TPM, then a TEE, then a device key.
//! The first that opens is used, with the class it earned and the reason,
//! and every backend that was tried and failed is kept so an operator can see
//! why a stronger one was not chosen.
//!
//! `Soft` is deliberately not in this list. A fingerprint identity is an
//! operator's recorded decision, not something a machine falls into because
//! nothing better answered; when [`select`] finds no hardware root it returns
//! the attempts and the caller decides.
//!
//! An emulated TPM (swtpm behind the kernel's vtpm proxy) is not a hardware
//! root either, however completely it answers. It is ignored unless the
//! operator has written [`ALLOW_EMULATED_TPM`], and even then it is `Soft`
//! and never endorsed.

use super::firmware_tpm::{self, Classified, EkChain};
use super::optee::{self, KnownTa};
use super::rpi_fw_crypto::RpiFwCrypto;
use super::tpm2_tools::{self, Tpm2Tools};
use crate::rot::{AssuranceClass, RootOfTrust};
use furcate_host::board::{self, Board, TpmKind};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File name, under the node's configuration directory, whose presence lets
/// an emulated TPM be used at all. Its contents are the operator's reason.
/// Meant for private test networks; a node using one is `Soft`.
pub const ALLOW_EMULATED_TPM: &str = "allow-emulated-tpm";

/// Operator configuration that affects classification.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// PEM bundle of the TPM manufacturers' CAs. An endorsement certificate
    /// counts only when it chains to one of these: for a firmware TPM this
    /// decides its class, and for any TPM whether it is reported endorsed.
    pub ek_ca_bundle: Option<PathBuf>,
    /// Where the Secure Enclave's wrapped key lives (macOS only).
    pub secure_enclave_key: Option<PathBuf>,
    /// The operator's reason for accepting an emulated TPM, when they have
    /// recorded one. `None` means an emulated TPM is ignored.
    pub allow_emulated_tpm: Option<String>,
}

impl Policy {
    /// The standard file names under a node's configuration directory.
    pub fn in_config_dir(dir: &Path) -> Self {
        Policy {
            ek_ca_bundle: Some(dir.join(firmware_tpm::EK_CA_BUNDLE)),
            secure_enclave_key: Some(dir.join("secure-enclave.key")),
            allow_emulated_tpm: emulated_tpm_allowed(dir),
        }
    }
}

/// The operator's recorded reason for accepting an emulated TPM, if any.
///
/// An empty file still counts as the decision; the reason is shown where it
/// exists.
pub fn emulated_tpm_allowed(config_dir: &Path) -> Option<String> {
    std::fs::read_to_string(config_dir.join(ALLOW_EMULATED_TPM)).ok().map(|s| {
        let s = s.trim();
        if s.is_empty() { "no reason recorded".to_string() } else { s.to_string() }
    })
}

/// A backend that was tried and what happened.
#[derive(Clone, Debug)]
pub struct Attempt {
    pub backend: &'static str,
    pub outcome: String,
}

pub struct Selection {
    pub rot: Arc<dyn RootOfTrust + Send + Sync>,
    pub class: AssuranceClass,
    pub backend: &'static str,
    pub reason: String,
    /// Stronger backends that were tried first and did not open.
    pub attempts: Vec<Attempt>,
}

/// No hardware root of trust opened.
#[derive(Debug)]
pub struct NoHardwareRoot {
    pub attempts: Vec<Attempt>,
}

impl fmt::Display for NoHardwareRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no hardware root of trust opened")?;
        for a in &self.attempts {
            write!(f, "; {}: {}", a.backend, a.outcome)?;
        }
        Ok(())
    }
}

impl std::error::Error for NoHardwareRoot {}

/// What one backend's probe found.
enum Probe {
    Opened(Selection),
    Failed(Attempt),
    /// Not applicable on this machine; nothing to report.
    Absent,
}

/// Every name a [`Selection`] can carry, strongest first.
pub const BACKENDS: &[&str] = &["tpm", "firmware-tpm", "emulated-tpm", "rpi-fw-crypto", "secure-enclave"];

/// Open the strongest root of trust this machine has: TPM, then TEE, then a
/// device key.
pub fn select(policy: &Policy) -> Result<Selection, NoHardwareRoot> {
    let mut attempts = Vec::new();
    let board = board::read();

    match probe_tpm(policy, &board) {
        Probe::Opened(s) => return Ok(Selection { attempts, ..s }),
        Probe::Failed(a) => attempts.push(a),
        Probe::Absent => {}
    }

    let tee = optee::probe();
    if tee.device {
        let outcome = match tee.known() {
            Some(KnownTa::FirmwareTpm) => {
                "the firmware TPM TA answered but no TPM device opened; is tpm_ftpm_tee loaded?".to_string()
            }
            None => tee.describe(),
        };
        attempts.push(Attempt { backend: "tee", outcome });
    }

    for probe in [probe_rpi(&board), probe_secure_enclave(policy)] {
        match probe {
            Probe::Opened(s) => return Ok(Selection { attempts, ..s }),
            Probe::Failed(a) => attempts.push(a),
            Probe::Absent => {}
        }
    }

    Err(NoHardwareRoot { attempts })
}

/// Open one named backend, and only that one.
///
/// Used to keep a node on the backend it enrolled with when a stronger one
/// has appeared: [`select`] would choose the newcomer, and that would be a
/// different node.
pub fn open_backend(policy: &Policy, name: &str) -> Result<Selection, String> {
    let board = board::read();
    let probe = match name {
        "tpm" | "firmware-tpm" | "emulated-tpm" => probe_tpm(policy, &board),
        "rpi-fw-crypto" => probe_rpi(&board),
        "secure-enclave" => probe_secure_enclave(policy),
        other => return Err(format!("{other:?} is not a hardware backend this build knows")),
    };
    match probe {
        Probe::Opened(s) if s.backend == name => Ok(s),
        Probe::Opened(s) => Err(format!("{name} is not available: the device now opens as {} ({})", s.backend, s.reason)),
        Probe::Failed(a) => Err(format!("{name} is not available: {}", a.outcome)),
        Probe::Absent => Err(format!("{name} is not available on this machine")),
    }
}

/// What becomes of a TPM found to be emulated: refused with the reason
/// unless the operator has allowed it, and then only as `Soft`.
fn admit_emulated(reason: &str, policy: &Policy) -> Result<String, Attempt> {
    match &policy.allow_emulated_tpm {
        Some(why) => Ok(format!("{reason}; accepted as soft because {ALLOW_EMULATED_TPM} is set: {why}")),
        None => Err(Attempt {
            backend: "tpm",
            outcome: format!(
                "ignored: {reason}. An emulated TPM is not a hardware root; it is used, as Soft, \
                 only when {ALLOW_EMULATED_TPM} is present in the configuration directory, \
                 which is for private test networks"
            ),
        }),
    }
}

fn probe_tpm(policy: &Policy, board: &Board) -> Probe {
    if let Some(a) = unusable_tpm(Path::new(tpm2_tools::TPM_DEVICE), Path::new(tpm2_tools::TPM_SYSFS_CLASS)) {
        return Probe::Failed(a);
    }
    let tpm_kind = board::tpm_kind();
    // Decided before the device is opened: the kernel already says what it is.
    if let TpmKind::Emulated { reason } = &tpm_kind {
        if let Err(a) = admit_emulated(reason, policy) {
            return Probe::Failed(a);
        }
    }

    let tpm = match Tpm2Tools::open() {
        Ok(t) => t,
        Err(e) => return Probe::Failed(Attempt { backend: "tpm", outcome: e.to_string() }),
    };

    // The kernel's view can miss an emulator that reaches the machine some
    // other way, so the chip's own answers are checked as well.
    let emulated = match &tpm_kind {
        TpmKind::Emulated { reason } => Some(reason.clone()),
        _ => emulated_by_answers(&tpm).map(|why| format!("emulated TPM (vtpm proxy / swtpm): {why}")),
    };
    if let Some(reason) = emulated {
        let accepted = match admit_emulated(&reason, policy) {
            Ok(r) => r,
            Err(a) => return Probe::Failed(a),
        };
        let rot = Classified::new(tpm, AssuranceClass::Soft, reason);
        return Probe::Opened(Selection {
            class: rot.assurance(),
            rot: Arc::new(rot),
            backend: "emulated-tpm",
            reason: accepted,
            attempts: Vec::new(),
        });
    }

    if tpm_kind.is_firmware() {
        let secure_boot = board::boot_integrity(board).secure_boot;
        let chain = ek_chain(&tpm, policy.ek_ca_bundle.as_deref());
        let (class, reason) = firmware_tpm::classify(&secure_boot, &chain);
        let rot = Classified::new(tpm, class, reason.clone());
        return Probe::Opened(Selection {
            class: rot.assurance(),
            rot: Arc::new(rot),
            backend: "firmware-tpm",
            reason,
            attempts: Vec::new(),
        });
    }
    let driver = match &tpm_kind {
        TpmKind::Platform { driver: Some(d) } => d.clone(),
        _ => "driver unknown".to_string(),
    };
    Probe::Opened(Selection {
        class: tpm.assurance(),
        rot: Arc::new(tpm),
        backend: "tpm",
        reason: format!("TPM 2.0 ({driver})"),
        attempts: Vec::new(),
    })
}

/// A TPM device path that cannot be used, as the attempt that passes it over.
fn unusable_tpm(device: &Path, sysfs_class: &Path) -> Option<Attempt> {
    tpm2_tools::unusable_device(device, sysfs_class).map(|why| Attempt {
        backend: "tpm",
        outcome: format!("{} is not a usable TPM: {why}", device.display()),
    })
}

/// Why the TPM's own answers mark it as software, if they do: its vendor
/// properties, then who issued its endorsement certificate.
fn emulated_by_answers(tpm: &Tpm2Tools) -> Option<String> {
    if let Some(why) = tpm.vendor().ok().and_then(|v| v.emulated()) {
        return Some(why);
    }
    let cert = match tpm.ek_certificate() {
        Ok(Some(c)) => Some(c),
        _ => tpm.ek_certificate_ecc().ok().flatten(),
    }?;
    let work = std::env::temp_dir().join(format!("furcate-ekissuer-{}", std::process::id()));
    std::fs::create_dir_all(&work).ok()?;
    let issuer = firmware_tpm::ek_issuer(&cert, &work);
    let _ = std::fs::remove_dir_all(&work);
    issuer.and_then(|i| firmware_tpm::emulator_issuer(&i))
}

fn probe_rpi(board: &Board) -> Probe {
    if !matches!(board, Board::RaspberryPi(_)) {
        return Probe::Absent;
    }
    match RpiFwCrypto::open() {
        Ok(fw) => {
            let reason = format!(
                "Raspberry Pi OTP device key via the firmware; raw OTP read {} at open, \
                 no measured boot",
                if fw.read_locked() { "locked" } else { "NOT locked" }
            );
            Probe::Opened(Selection {
                class: fw.assurance(),
                rot: Arc::new(fw),
                backend: "rpi-fw-crypto",
                reason,
                attempts: Vec::new(),
            })
        }
        Err(e) => Probe::Failed(Attempt { backend: "rpi-fw-crypto", outcome: e.to_string() }),
    }
}

#[cfg(target_os = "macos")]
fn probe_secure_enclave(policy: &Policy) -> Probe {
    let Some(path) = &policy.secure_enclave_key else {
        return Probe::Absent;
    };
    match super::secure_enclave::SecureEnclave::open(path.clone()) {
        Ok(se) => Probe::Opened(Selection {
            class: se.assurance(),
            rot: Arc::new(se),
            backend: "secure-enclave",
            reason: "Secure Enclave key; macOS attests no software state to a daemon".to_string(),
            attempts: Vec::new(),
        }),
        Err(e) => Probe::Failed(Attempt { backend: "secure-enclave", outcome: e.to_string() }),
    }
}

#[cfg(not(target_os = "macos"))]
fn probe_secure_enclave(_policy: &Policy) -> Probe {
    Probe::Absent
}

/// Check the fTPM's EK certificate, RSA index first, then ECC.
fn ek_chain(tpm: &Tpm2Tools, bundle: Option<&Path>) -> EkChain {
    let cert = match tpm.ek_certificate() {
        Ok(Some(c)) => Some(c),
        _ => tpm.ek_certificate_ecc().ok().flatten(),
    };
    verify_in_scratch(cert.as_deref(), bundle)
}

fn verify_in_scratch(cert: Option<&[u8]>, bundle: Option<&Path>) -> EkChain {
    let work = std::env::temp_dir().join(format!("furcate-ekchain-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&work) {
        return EkChain::Rejected { why: format!("creating {}: {e}", work.display()) };
    }
    let chain = firmware_tpm::verify_ek_chain(cert, bundle, &work);
    let _ = std::fs::remove_dir_all(&work);
    chain
}

/// Whether a manufacturer vouches for this root of trust's endorsement key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    pub endorsed: bool,
    pub detail: String,
}

/// Decide whether a root of trust is endorsed.
///
/// Holding an EK certificate is not enough: swtpm writes one too, signed by
/// a CA it generated on the spot. Endorsed means the certificate chains to a
/// manufacturer CA in the operator's bundle, and a `Soft` root is never
/// endorsed whatever it holds.
pub fn endorsement<R: RootOfTrust + ?Sized>(rot: &R, policy: &Policy) -> Endorsement {
    let cert = rot.ek_certificate().ok().flatten();
    endorsement_of(rot.assurance(), cert.as_deref(), |c| verify_in_scratch(Some(c), policy.ek_ca_bundle.as_deref()))
}

fn endorsement_of(class: AssuranceClass, cert: Option<&[u8]>, verify: impl FnOnce(&[u8]) -> EkChain) -> Endorsement {
    if class == AssuranceClass::Soft {
        return Endorsement { endorsed: false, detail: "not endorsed: a soft root of trust".to_string() };
    }
    let Some(cert) = cert else {
        return Endorsement { endorsed: false, detail: "no endorsement certificate".to_string() };
    };
    match verify(cert) {
        chain @ EkChain::Verified { .. } => Endorsement { endorsed: true, detail: format!("vendor-endorsed: {}", chain.describe()) },
        chain => Endorsement {
            endorsed: false,
            detail: format!("not endorsed: an EK certificate is present but {}", chain.describe()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_regular_file_at_the_tpm_path_is_passed_over() {
        let dir = std::env::temp_dir().join(format!("furcate-select-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("class/tpm0")).unwrap();
        let dev = dir.join("tpmrm0");
        std::fs::write(&dev, b"").unwrap();
        let a = unusable_tpm(&dev, &dir.join("class")).expect("a regular file is not a TPM");
        assert_eq!(a.backend, "tpm");
        assert!(a.outcome.contains("is not a usable TPM") && a.outcome.contains("not a character device"), "{}", a.outcome);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_certificate_alone_is_not_an_endorsement() {
        let e = endorsement_of(AssuranceClass::Tpm, Some(b"cert"), |_| EkChain::NoTrustedCa);
        assert!(!e.endorsed, "{e:?}");
        let e = endorsement_of(AssuranceClass::Tpm, Some(b"cert"), |_| EkChain::Rejected {
            why: "unable to get local issuer certificate".into(),
        });
        assert!(!e.endorsed, "{e:?}");
    }

    #[test]
    fn a_chain_to_a_manufacturer_root_is_an_endorsement() {
        let e = endorsement_of(AssuranceClass::Tpm, Some(b"cert"), |_| EkChain::Verified { bundle: "b.pem".into() });
        assert!(e.endorsed);
        assert!(e.detail.starts_with("vendor-endorsed"));
        let e = endorsement_of(AssuranceClass::Tpm, None, |_| unreachable!());
        assert!(!e.endorsed);
    }

    #[test]
    fn soft_is_never_endorsed_even_with_a_verifying_chain() {
        let e = endorsement_of(AssuranceClass::Soft, Some(b"cert"), |_| EkChain::Verified { bundle: "b.pem".into() });
        assert!(!e.endorsed);
    }

    #[test]
    fn the_flag_is_a_file_with_a_reason() {
        let dir = std::env::temp_dir().join(format!("furcate-allow-emu-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(Policy::in_config_dir(&dir).allow_emulated_tpm, None);
        std::fs::write(dir.join(ALLOW_EMULATED_TPM), "private IBC test net\n").unwrap();
        assert_eq!(Policy::in_config_dir(&dir).allow_emulated_tpm.as_deref(), Some("private IBC test net"));
        std::fs::write(dir.join(ALLOW_EMULATED_TPM), "").unwrap();
        assert_eq!(emulated_tpm_allowed(&dir).as_deref(), Some("no reason recorded"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_emulated_tpm_is_ignored_by_default_and_says_why() {
        let a = admit_emulated("emulated TPM (vtpm proxy / swtpm): bound to the tpm_vtpm_proxy driver", &Policy::default())
            .err()
            .unwrap();
        assert_eq!(a.backend, "tpm");
        assert!(a.outcome.starts_with("ignored: emulated TPM (vtpm proxy / swtpm)"), "{}", a.outcome);
        assert!(a.outcome.contains(ALLOW_EMULATED_TPM), "{}", a.outcome);
        // And it reaches the operator through the refusal text.
        let none = NoHardwareRoot { attempts: vec![a] };
        assert!(none.to_string().contains("tpm: ignored: emulated TPM"), "{none}");
    }

    #[test]
    fn the_flag_admits_an_emulated_tpm_as_soft_only() {
        let policy = Policy { allow_emulated_tpm: Some("private test net".into()), ..Policy::default() };
        let reason = admit_emulated("emulated TPM (vtpm proxy / swtpm): x", &policy).unwrap();
        assert!(reason.contains("accepted as soft") && reason.contains("private test net"), "{reason}");
    }

    #[test]
    fn open_backend_refuses_names_it_does_not_know() {
        let e = open_backend(&Policy::default(), "soft").err().unwrap();
        assert!(e.contains("not a hardware backend"), "{e}");
    }
}
