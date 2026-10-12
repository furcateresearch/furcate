//! What an OP-TEE trusted execution environment offers this node.
//!
//! Rockchip, i.MX, Jetson and other TrustZone boards run OP-TEE and expose it
//! as `/dev/tee0`. A TEE device on its own proves nothing: it is an interface
//! to a secure world that may hold no key at all. What matters is whether a
//! trusted application Furcate knows how to use is loaded and answering.
//!
//! The kernel enumerates trusted applications that registered for it on the
//! TEE bus, as `optee-ta-<uuid>` under `/sys/bus/tee/devices`. A TA appears
//! there only after OP-TEE has opened it and reported it, so presence on that
//! bus is the TA answering, not a file on disk.
//!
//! The one TA recognised today is the firmware TPM (`ftpm`), which the kernel
//! then exposes as an ordinary TPM device; it is driven through
//! [`super::tpm2_tools`] and classified by [`super::firmware_tpm`]. A TEE
//! with no recognised TA is reported and not claimed.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// The firmware TPM trusted application, as `tpm_ftpm_tee` names it.
pub const FTPM_TA_UUID: &str = "bc50d971-d4c9-42c4-82cb-343fb7f37896";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownTa {
    FirmwareTpm,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeProbe {
    /// Whether a TEE device node exists.
    pub device: bool,
    /// UUIDs of every TA enumerated on the TEE bus.
    pub tas: Vec<String>,
}

impl TeeProbe {
    /// The recognised TA, if one answered.
    pub fn known(&self) -> Option<KnownTa> {
        self.tas.iter().any(|t| t == FTPM_TA_UUID).then_some(KnownTa::FirmwareTpm)
    }

    /// One line for an operator.
    pub fn describe(&self) -> String {
        match (self.device, self.known()) {
            (false, _) => "no TEE device".to_string(),
            (true, Some(KnownTa::FirmwareTpm)) => "OP-TEE with the firmware TPM TA answering".to_string(),
            (true, None) if self.tas.is_empty() => {
                "OP-TEE present, no trusted application enumerated; not claimed".to_string()
            }
            (true, None) => format!(
                "OP-TEE present with {} unrecognised trusted application(s); not claimed",
                self.tas.len()
            ),
        }
    }
}

pub fn probe() -> TeeProbe {
    probe_at(Path::new("/dev"), Path::new("/sys/bus/tee/devices"))
}

pub fn probe_at(dev: &Path, bus: &Path) -> TeeProbe {
    let device = dev.join("tee0").exists() || dev.join("teepriv0").exists();
    let mut tas: Vec<String> = std::fs::read_dir(bus)
        .map(|r| {
            r.flatten()
                .filter_map(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .strip_prefix("optee-ta-")
                        .map(str::to_ascii_lowercase)
                })
                .collect()
        })
        .unwrap_or_default();
    tas.sort();
    TeeProbe { device, tas }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ftpm_ta_is_recognised_and_others_are_not_claimed() {
        let d = std::env::temp_dir().join(format!("furcate-optee-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("dev")).unwrap();
        std::fs::create_dir_all(d.join("bus")).unwrap();

        assert_eq!(probe_at(&d.join("dev"), &d.join("bus")).describe(), "no TEE device");

        std::fs::write(d.join("dev/tee0"), "").unwrap();
        std::fs::create_dir_all(d.join("bus/optee-ta-7011a688-ddde-4053-a5a9-7b3c4ddf13b8")).unwrap();
        let p = probe_at(&d.join("dev"), &d.join("bus"));
        assert_eq!(p.known(), None);
        assert!(p.describe().contains("not claimed"));

        std::fs::create_dir_all(d.join(format!("bus/optee-ta-{FTPM_TA_UUID}"))).unwrap();
        assert_eq!(probe_at(&d.join("dev"), &d.join("bus")).known(), Some(KnownTa::FirmwareTpm));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
