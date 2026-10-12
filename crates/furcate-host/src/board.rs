//! Which single-board computer this is, and how far its boot can be trusted.
//!
//! Rack servers describe themselves through SMBIOS ([`crate::firmware`]).
//! ARM boards mostly do not: a Raspberry Pi or a Jetson has no DMI tables, and
//! what it is lives in the device tree the firmware hands the kernel. That
//! tree is world-readable under `/proc/device-tree`, so recognising the board
//! needs no tool and no privilege.
//!
//! ## Recognition
//!
//! The root `compatible` property lists the board from most to least specific.
//! The strings matched here are the ones in the kernel's own bindings:
//!
//! * `brcm,bcm2712` is the Raspberry Pi 5 family (`raspberrypi,5-model-b`,
//!   `raspberrypi,5-compute-module`, `raspberrypi,500`), `brcm,bcm2711` the
//!   Pi 4 family, and so on down.
//! * `nvidia,tegra234` is Orin and `nvidia,tegra264` is Thor. The module is
//!   the part number without a carrier: `p3701` is AGX Orin, `p3767` is the
//!   Orin NX and Orin Nano family (SKUs 0000/0001 are NX, 0003/0004/0005 are
//!   Nano, per NVIDIA's module tables), `p3834` is AGX Thor.
//!
//! `/etc/nv_tegra_release` carries the L4T release; it is a file the BSP
//! installs, so its absence on a Tegra board means a non-NVIDIA userland
//! rather than a different board.
//!
//! ## Boot integrity is two separate facts
//!
//! *Secure boot* means the firmware refuses to run an unsigned next stage.
//! *Measured boot* means each stage is hashed into a register that something
//! can later quote. A Raspberry Pi can have the first and never the second
//! unless a TPM is fitted, because it has nowhere to record measurements. A
//! development Jetson typically has the second (its firmware TPM records the
//! boot chain) without the first (the secure boot fuses are not burned). The
//! two are reported separately so neither stands in for the other, and a fact
//! that cannot be read without root-only interfaces is reported as unknown
//! rather than guessed.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// What the device tree says this board is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum Board {
    RaspberryPi(RaspberryPi),
    Jetson(Jetson),
    /// A device tree is present but names a board not recognised here.
    Other { compatible: Vec<String>, model: Option<String> },
    /// No device tree: an x86 machine, or an ARM server booted through ACPI.
    NoDeviceTree,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaspberryPi {
    /// The model string from the device tree, e.g. `Raspberry Pi 5 Model B Rev 1.0`.
    pub model: Option<String>,
    /// The SoC compatible string, e.g. `brcm,bcm2712`.
    pub soc: String,
    /// Board generation as Raspberry Pi numbers it, from the SoC.
    pub generation: Option<u8>,
    pub compute_module: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TegraSoc {
    /// `nvidia,tegra234`.
    Orin,
    /// `nvidia,tegra264`.
    Thor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JetsonModule {
    AgxOrin,
    OrinNx,
    OrinNano,
    AgxThor,
    /// A Tegra module whose part number is not in the table above.
    Unrecognised,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jetson {
    pub soc: TegraSoc,
    pub module: JetsonModule,
    /// Module part number as the device tree gives it, e.g. `p3767-0003`.
    pub part: Option<String>,
    pub model: Option<String>,
    /// The L4T release from `/etc/nv_tegra_release`, if the BSP is installed.
    pub l4t: Option<L4tRelease>,
}

/// An L4T (Jetson Linux) release, e.g. 36.4.3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L4tRelease {
    pub major: u32,
    /// Everything after the major number, as the file states it: `4.3`.
    pub revision: String,
}

impl L4tRelease {
    pub fn version(&self) -> String {
        format!("{}.{}", self.major, self.revision)
    }
}

/// Split the NUL-separated `compatible` property into its strings.
pub fn parse_compatible(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Parse the first line of `/etc/nv_tegra_release`:
/// `# R36 (release), REVISION: 4.3, GCID: ..., BOARD: generic, ...`
pub fn parse_nv_tegra_release(text: &str) -> Option<L4tRelease> {
    let line = text.lines().find(|l| l.contains("REVISION"))?;
    let major = line
        .split_whitespace()
        .find_map(|w| w.strip_prefix('R').and_then(|n| n.parse::<u32>().ok()))?;
    let revision = line
        .split(',')
        .find_map(|f| f.trim().strip_prefix("REVISION:"))
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())?;
    Some(L4tRelease { major, revision })
}

/// Recognise the board from its device tree and, for Tegra, its L4T release.
pub fn identify(compatible: &[String], model: Option<&str>, nv_tegra_release: Option<&str>) -> Board {
    let model = model.map(|m| m.trim_end_matches('\0').trim().to_string()).filter(|m| !m.is_empty());
    if compatible.is_empty() {
        return Board::NoDeviceTree;
    }
    let has = |s: &str| compatible.iter().any(|c| c == s);

    if let Some(soc) = compatible.iter().find(|c| c.starts_with("brcm,bcm27") || c.as_str() == "brcm,bcm2835")
    {
        let generation = match soc.as_str() {
            "brcm,bcm2712" => Some(5),
            "brcm,bcm2711" => Some(4),
            "brcm,bcm2837" => Some(3),
            "brcm,bcm2836" => Some(2),
            "brcm,bcm2835" => Some(1),
            _ => None,
        };
        let compute_module = compatible
            .iter()
            .any(|c| c.starts_with("raspberrypi,") && c.contains("compute-module"));
        return Board::RaspberryPi(RaspberryPi { model, soc: soc.clone(), generation, compute_module });
    }

    let soc = if has("nvidia,tegra264") {
        Some(TegraSoc::Thor)
    } else if has("nvidia,tegra234") {
        Some(TegraSoc::Orin)
    } else {
        None
    };
    if let Some(soc) = soc {
        // The module is the bare part number; carrier-plus-module entries
        // carry a '+' and the SoC entry has no part number at all.
        let part = compatible
            .iter()
            .filter(|c| !c.contains('+'))
            .find_map(|c| c.strip_prefix("nvidia,p"))
            .map(|p| format!("p{p}"));
        let module = match part.as_deref().and_then(|p| p.split_once('-')) {
            Some(("p3701", _)) => JetsonModule::AgxOrin,
            Some(("p3767", "0000" | "0001")) => JetsonModule::OrinNx,
            Some(("p3767", "0003" | "0004" | "0005")) => JetsonModule::OrinNano,
            Some(("p3834", _)) => JetsonModule::AgxThor,
            _ => JetsonModule::Unrecognised,
        };
        return Board::Jetson(Jetson {
            soc,
            module,
            part,
            model,
            l4t: nv_tegra_release.and_then(parse_nv_tegra_release),
        });
    }

    Board::Other { compatible: compatible.to_vec(), model }
}

/// Read and recognise this machine's board.
pub fn read() -> Board {
    read_from(Path::new("/proc/device-tree"), Path::new("/etc/nv_tegra_release"))
}

pub fn read_from(device_tree: &Path, nv_tegra_release: &Path) -> Board {
    let compatible = std::fs::read(device_tree.join("compatible"))
        .map(|b| parse_compatible(&b))
        .unwrap_or_default();
    let model = std::fs::read(device_tree.join("model"))
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    let release = std::fs::read_to_string(nv_tegra_release).ok();
    identify(&compatible, model.as_deref(), release.as_deref())
}

/// Whether the board can encode video in hardware.
///
/// Stated only where the silicon is known: the Pi 5 dropped the hardware
/// H.264 encoder its predecessors had, and the Orin Nano is the one Orin
/// module without NVENC. Anywhere else the answer is unknown rather than
/// assumed either way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoder", rename_all = "snake_case")]
pub enum Encoder {
    Hardware { engine: String },
    Software { why: String },
    Unknown,
}

pub fn encoder(board: &Board) -> Encoder {
    match board {
        Board::RaspberryPi(pi) if pi.generation == Some(5) => Encoder::Software {
            why: "the BCM2712 has no hardware H.264 encoder".to_string(),
        },
        Board::Jetson(j) => match j.module {
            JetsonModule::AgxOrin | JetsonModule::OrinNx | JetsonModule::AgxThor => {
                Encoder::Hardware { engine: "nvenc".to_string() }
            }
            JetsonModule::OrinNano => Encoder::Software {
                why: "the Orin Nano module has no NVENC".to_string(),
            },
            JetsonModule::Unrecognised => Encoder::Unknown,
        },
        _ => Encoder::Unknown,
    }
}

/// Whether the firmware refuses unsigned boot stages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SecureBoot {
    /// Signature checking is fused or locked on; the ROM will not run
    /// unsigned firmware.
    Enforced { detail: String },
    /// Signed boot is requested by configuration but not locked into the
    /// silicon, so it can be switched off by rewriting that configuration.
    Configured { detail: String },
    Off { detail: String },
    Unknown { why: String },
}

/// The Raspberry Pi bootloader's `chosen/bootloader/signed` bit-field.
///
/// Bit 0: `SIGNED_BOOT` set in the EEPROM config. Bit 2: the ROM development
/// key is revoked. Bit 3: the customer public key digest is in OTP. Without
/// bit 3 nothing in the silicon checks the bootloader, so the configuration
/// alone is `Configured`, not `Enforced`.
pub fn pi_secure_boot(signed: Option<&[u8]>) -> SecureBoot {
    let Some(raw) = signed else {
        return SecureBoot::Unknown {
            why: "the bootloader does not publish chosen/bootloader/signed".to_string(),
        };
    };
    let Ok(bytes) = <[u8; 4]>::try_from(raw) else {
        return SecureBoot::Unknown { why: format!("signed property is {} bytes, expected 4", raw.len()) };
    };
    let bits = u32::from_be_bytes(bytes);
    let signed_boot = bits & 1 != 0;
    let devkey_revoked = bits & (1 << 2) != 0;
    let key_in_otp = bits & (1 << 3) != 0;
    let detail = format!(
        "signed=0x{bits:x}: SIGNED_BOOT {}, customer key {} OTP, development key {}",
        if signed_boot { "set" } else { "not set" },
        if key_in_otp { "in" } else { "not in" },
        if devkey_revoked { "revoked" } else { "not revoked" },
    );
    match (signed_boot, key_in_otp) {
        (true, true) => SecureBoot::Enforced { detail },
        (true, false) | (false, true) => SecureBoot::Configured { detail },
        (false, false) => SecureBoot::Off { detail },
    }
}

/// Paths at which some L4T releases expose the `security_mode` fuse to
/// userspace. Orin releases do not publish it in a world-readable place;
/// there the answer is `Unknown`, which callers must treat as not fused.
pub const TEGRA_SECURITY_MODE_PATHS: &[&str] = &[
    "/sys/devices/platform/tegra-fuse/security_mode",
    "/sys/devices/platform/efuse-burn/security_mode",
];

/// Interpret a Tegra `security_mode` fuse value: non-zero once secure boot
/// (PKC) has been burned.
pub fn tegra_secure_boot(security_mode: Option<&str>) -> SecureBoot {
    let Some(raw) = security_mode.map(str::trim) else {
        return SecureBoot::Unknown {
            why: "the security_mode fuse is not readable from userspace on this release".to_string(),
        };
    };
    let value = raw
        .strip_prefix("0x")
        .map(|h| u64::from_str_radix(h, 16))
        .unwrap_or_else(|| raw.parse::<u64>());
    match value {
        Ok(0) => SecureBoot::Off { detail: "security_mode fuse is 0: development part, not fused".to_string() },
        Ok(v) => SecureBoot::Enforced { detail: format!("security_mode fuse is {v:#x}") },
        Err(_) => SecureBoot::Unknown { why: format!("unparseable security_mode value {raw:?}") },
    }
}

/// How the TPM, if any, is provided.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TpmKind {
    /// No TPM device.
    Absent,
    /// The OP-TEE firmware TPM (`ftpm-tee` / `optee-ftpm`): a TPM implemented
    /// as a trusted application, as on Jetson Orin and Thor.
    OpteeFirmware { driver: String },
    /// Anything else: a discrete chip on SPI/I2C/LPC, or a platform TPM
    /// behind CRB.
    Platform { driver: Option<String> },
    /// A TPM implemented in software and handed to the kernel through the
    /// vtpm proxy, as swtpm does. It answers every TPM command, so nothing in
    /// the protocol tells it apart from a chip; the kernel's view of where the
    /// device came from does. Its endorsement seed is a file some process
    /// holds, which is not hardware of any kind.
    Emulated { reason: String },
}

impl TpmKind {
    pub fn is_firmware(&self) -> bool {
        matches!(self, TpmKind::OpteeFirmware { .. })
    }

    pub fn is_emulated(&self) -> bool {
        matches!(self, TpmKind::Emulated { .. })
    }
}

/// The kernel driver the vtpm proxy binds its chips to.
pub const VTPM_PROXY_DRIVER: &str = "tpm_vtpm_proxy";

/// Why the kernel's view of a TPM shows it is not hardware, if it does.
///
/// `canonical` is the resolved `/sys/class/tpm/tpmN` directory. A chip on a
/// bus resolves under that bus (`/sys/devices/pnp0/...`, `/sys/devices/
/// platform/...`); a vtpm proxy chip has no parent device, so the kernel puts
/// it under `/sys/devices/virtual/tpm/`, and it has no `device` link or
/// driver at all. Either signal is enough on its own.
pub fn emulated_by_sysfs(canonical: Option<&Path>, driver: Option<&str>) -> Option<String> {
    if driver == Some(VTPM_PROXY_DRIVER) {
        return Some(format!("bound to the {VTPM_PROXY_DRIVER} driver"));
    }
    let virtual_device = canonical.is_some_and(|p| {
        let parts: Vec<_> = p.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        parts.windows(2).any(|w| w[0] == "devices" && w[1] == "virtual")
    });
    if virtual_device {
        return Some(format!(
            "{} has no parent device, which is how the kernel places a vtpm proxy chip",
            canonical.map(|p| p.display().to_string()).unwrap_or_default()
        ));
    }
    None
}

/// Classify a TPM by the name of the kernel driver bound to it.
pub fn tpm_kind_from_driver(present: bool, driver: Option<&str>) -> TpmKind {
    if !present {
        return TpmKind::Absent;
    }
    match driver {
        Some(d @ ("ftpm-tee" | "optee-ftpm")) => TpmKind::OpteeFirmware { driver: d.to_string() },
        other => TpmKind::Platform { driver: other.map(str::to_string) },
    }
}

/// Read how this machine's first TPM is provided.
pub fn tpm_kind() -> TpmKind {
    tpm_kind_at(Path::new("/sys/class/tpm/tpm0"))
}

pub fn tpm_kind_at(class_dir: &Path) -> TpmKind {
    let present = class_dir.exists();
    let driver = std::fs::read_link(class_dir.join("device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
    if present {
        let canonical = std::fs::canonicalize(class_dir).ok();
        if let Some(why) = emulated_by_sysfs(canonical.as_deref(), driver.as_deref()) {
            return TpmKind::Emulated { reason: format!("emulated TPM (vtpm proxy / swtpm): {why}") };
        }
    }
    tpm_kind_from_driver(present, driver.as_deref())
}

/// Whether boot stages are recorded anywhere a verifier could quote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Measurement {
    /// A TPM is present. `event_log` is whether the kernel exposes the boot
    /// event log, `None` when that could not be checked without privilege.
    Tpm { kind: TpmKind, event_log: Option<bool> },
    /// No TPM and no other register the boot chain extends.
    None,
}

/// Secure boot and measured boot, reported side by side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootIntegrity {
    pub secure_boot: SecureBoot,
    pub measurement: Measurement,
}

impl BootIntegrity {
    /// One phrase for an operator: `measured`, `secure-boot-only, unmeasured`,
    /// `unmeasured`, or `secure boot unknown, unmeasured`.
    pub fn summary(&self) -> &'static str {
        match (&self.secure_boot, &self.measurement) {
            (_, Measurement::Tpm { .. }) => "measured",
            (SecureBoot::Enforced { .. }, Measurement::None) => "secure-boot-only, unmeasured",
            (SecureBoot::Unknown { .. }, Measurement::None) => "secure boot unknown, unmeasured",
            _ => "unmeasured",
        }
    }
}

/// Assess boot integrity for `board` on this machine.
pub fn boot_integrity(board: &Board) -> BootIntegrity {
    let kind = tpm_kind();
    let measurement = match kind {
        // An emulated TPM's registers are extended by whatever process holds
        // it, not by the boot chain, so it measures nothing about this boot.
        TpmKind::Absent | TpmKind::Emulated { .. } => Measurement::None,
        kind => {
            let log = std::fs::metadata("/sys/kernel/security/tpm0/binary_bios_measurements");
            let event_log = match log {
                Ok(_) => Some(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
                Err(_) => None,
            };
            Measurement::Tpm { kind, event_log }
        }
    };
    let secure_boot = match board {
        Board::RaspberryPi(_) => {
            pi_secure_boot(std::fs::read("/proc/device-tree/chosen/bootloader/signed").ok().as_deref())
        }
        Board::Jetson(_) => {
            let fuse = TEGRA_SECURITY_MODE_PATHS
                .iter()
                .find_map(|p| std::fs::read_to_string(p).ok());
            tegra_secure_boot(fuse.as_deref())
        }
        _ => SecureBoot::Unknown {
            why: "secure boot state is only read for Raspberry Pi and Jetson boards here".to_string(),
        },
    };
    BootIntegrity { secure_boot, measurement }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compat(raw: &[u8]) -> Vec<String> {
        parse_compatible(raw)
    }

    #[test]
    fn recognises_orin_nano_devkit() {
        let c = compat(include_bytes!("testdata/compatible-orin-nano"));
        assert_eq!(c[0], "nvidia,p3768-0000+p3767-0005");
        let b = identify(&c, Some("NVIDIA Jetson Orin Nano Developer Kit\0"), Some(include_str!("testdata/nv_tegra_release")));
        let Board::Jetson(j) = &b else { panic!("{b:?}") };
        assert_eq!(j.soc, TegraSoc::Orin);
        assert_eq!(j.module, JetsonModule::OrinNano);
        assert_eq!(j.part.as_deref(), Some("p3767-0005"));
        assert_eq!(j.model.as_deref(), Some("NVIDIA Jetson Orin Nano Developer Kit"));
        assert_eq!(j.l4t.as_ref().unwrap().version(), "36.4.3");
        assert!(matches!(encoder(&b), Encoder::Software { .. }));
    }

    #[test]
    fn recognises_thor_and_agx_orin_with_nvenc() {
        let thor = ["nvidia,p4071-0000+p3834-0008", "nvidia,p3834-0008", "nvidia,tegra264"].map(String::from);
        let Board::Jetson(j) = identify(&thor, None, None) else { panic!() };
        assert_eq!((j.soc, j.module.clone(), j.l4t.clone()), (TegraSoc::Thor, JetsonModule::AgxThor, None));
        assert_eq!(encoder(&Board::Jetson(j.clone())), Encoder::Hardware { engine: "nvenc".into() });

        let agx = ["nvidia,p3737-0000+p3701-0000", "nvidia,p3701-0000", "nvidia,tegra234"].map(String::from);
        let b = identify(&agx, None, None);
        assert!(matches!(&b, Board::Jetson(j) if j.module == JetsonModule::AgxOrin));
        assert!(matches!(encoder(&b), Encoder::Hardware { .. }));
    }

    #[test]
    fn unknown_tegra_sku_is_not_guessed() {
        let c = ["nvidia,p3767-0099", "nvidia,tegra234"].map(String::from);
        let b = identify(&c, None, None);
        assert!(matches!(&b, Board::Jetson(j) if j.module == JetsonModule::Unrecognised));
        assert_eq!(encoder(&b), Encoder::Unknown);
    }

    #[test]
    fn recognises_pi5_and_cm5() {
        let c = compat(include_bytes!("testdata/compatible-pi5"));
        let b = identify(&c, Some("Raspberry Pi 5 Model B Rev 1.0\0"), None);
        let Board::RaspberryPi(pi) = &b else { panic!("{b:?}") };
        assert_eq!((pi.generation, pi.compute_module), (Some(5), false));
        assert!(matches!(encoder(&b), Encoder::Software { .. }));

        let cm5 = ["raspberrypi,5-compute-module", "brcm,bcm2712"].map(String::from);
        assert!(matches!(identify(&cm5, None, None), Board::RaspberryPi(p) if p.compute_module));
        let pi4 = ["raspberrypi,4-model-b", "brcm,bcm2711"].map(String::from);
        let b4 = identify(&pi4, None, None);
        assert!(matches!(&b4, Board::RaspberryPi(p) if p.generation == Some(4)));
        assert_eq!(encoder(&b4), Encoder::Unknown);
    }

    #[test]
    fn no_device_tree_and_unrecognised_boards() {
        assert_eq!(identify(&[], None, None), Board::NoDeviceTree);
        let rk = ["radxa,rock-5b", "rockchip,rk3588"].map(String::from);
        assert!(matches!(identify(&rk, None, None), Board::Other { .. }));
    }

    #[test]
    fn nv_tegra_release_without_revision_is_none() {
        assert_eq!(parse_nv_tegra_release("# R36 (release)"), None);
        let r = parse_nv_tegra_release("# R39 (release), REVISION: 2.1, GCID: 1, BOARD: generic").unwrap();
        assert_eq!(r.version(), "39.2.1");
    }

    #[test]
    fn pi_signed_bits() {
        assert!(matches!(pi_secure_boot(None), SecureBoot::Unknown { .. }));
        assert!(matches!(pi_secure_boot(Some(&[0, 0, 0, 0])), SecureBoot::Off { .. }));
        assert!(matches!(pi_secure_boot(Some(&[0, 0, 0, 1])), SecureBoot::Configured { .. }));
        assert!(matches!(pi_secure_boot(Some(&[0, 0, 0, 0x0d])), SecureBoot::Enforced { .. }));
        assert!(matches!(pi_secure_boot(Some(&[1, 2])), SecureBoot::Unknown { .. }));
    }

    #[test]
    fn pi_without_tpm_is_secure_boot_only() {
        let b = BootIntegrity {
            secure_boot: pi_secure_boot(Some(&[0, 0, 0, 9])),
            measurement: Measurement::None,
        };
        assert_eq!(b.summary(), "secure-boot-only, unmeasured");
    }

    #[test]
    fn tegra_fuse_values() {
        assert!(matches!(tegra_secure_boot(None), SecureBoot::Unknown { .. }));
        assert!(matches!(tegra_secure_boot(Some("0x00000000\n")), SecureBoot::Off { .. }));
        assert!(matches!(tegra_secure_boot(Some("0x1")), SecureBoot::Enforced { .. }));
        assert!(matches!(tegra_secure_boot(Some("yes")), SecureBoot::Unknown { .. }));
    }

    /// A fake `/sys` with `class/tpm/tpm0` linked to `target`, relative to the
    /// root, and an optional driver link.
    fn fake_sys(name: &str, target: &str, driver: Option<&str>) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("furcate-sysfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dev = root.join(target);
        std::fs::create_dir_all(&dev).unwrap();
        if let Some(d) = driver {
            let drv = root.join("bus/platform/drivers").join(d);
            std::fs::create_dir_all(&drv).unwrap();
            std::fs::create_dir_all(dev.join("device")).unwrap();
            std::os::unix::fs::symlink(&drv, dev.join("device/driver")).unwrap();
        }
        std::fs::create_dir_all(root.join("class/tpm")).unwrap();
        std::os::unix::fs::symlink(&dev, root.join("class/tpm/tpm0")).unwrap();
        root
    }

    #[test]
    fn vtpm_proxy_chip_under_devices_virtual_is_emulated() {
        // What a swtpm chip looks like through the vtpm proxy: no parent, no
        // driver link, resolved under devices/virtual.
        let root = fake_sys("virtual", "devices/virtual/tpm/tpm0", None);
        let kind = tpm_kind_at(&root.join("class/tpm/tpm0"));
        assert!(kind.is_emulated(), "{kind:?}");
        assert!(!kind.is_firmware());
        let TpmKind::Emulated { reason } = kind else { unreachable!() };
        assert!(reason.contains("emulated TPM (vtpm proxy / swtpm)"), "{reason}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vtpm_proxy_driver_is_emulated_wherever_it_sits() {
        let root = fake_sys("driver", "devices/platform/vtpm/tpm/tpm0", Some(VTPM_PROXY_DRIVER));
        assert!(tpm_kind_at(&root.join("class/tpm/tpm0")).is_emulated());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_chip_on_a_bus_is_platform() {
        let root = fake_sys("crb", "devices/LNXSYSTM:00/MSFT0101:00/tpm/tpm0", Some("tpm_crb"));
        assert_eq!(
            tpm_kind_at(&root.join("class/tpm/tpm0")),
            TpmKind::Platform { driver: Some("tpm_crb".to_string()) }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sysfs_signals() {
        assert!(emulated_by_sysfs(None, Some("tpm_vtpm_proxy")).is_some());
        assert!(emulated_by_sysfs(Some(Path::new("/sys/devices/virtual/tpm/tpm9")), None).is_some());
        assert!(emulated_by_sysfs(Some(Path::new("/sys/devices/pnp0/00:05/tpm/tpm0")), Some("tpm_tis")).is_none());
        assert!(emulated_by_sysfs(None, None).is_none());
    }

    #[test]
    fn tpm_kind_by_driver() {
        assert_eq!(tpm_kind_from_driver(false, Some("ftpm-tee")), TpmKind::Absent);
        assert!(tpm_kind_from_driver(true, Some("optee-ftpm")).is_firmware());
        assert!(tpm_kind_from_driver(true, Some("ftpm-tee")).is_firmware());
        assert!(!tpm_kind_from_driver(true, Some("tpm_tis_spi")).is_firmware());
        assert!(!tpm_kind_from_driver(true, None).is_firmware());
    }
}
