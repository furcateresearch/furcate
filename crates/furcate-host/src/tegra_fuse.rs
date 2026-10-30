//! Read-only view of a Jetson's secure-boot fuses.
//!
//! Source of the fuse model: NVIDIA Jetson Linux Developer Guide r39.2,
//! "Secure Boot", "Fuse Configuration" and "Fuse Operations"
//! (docs.nvidia.com/jetson/archives/r39.2/DeveloperGuide/SD/Security/).
//!
//! * `SecurityMode` (a 4-byte fuse of which one bit is used, also called
//!   `odm_production_mode`) is the lock: once 1, further fuse writes are
//!   blocked (Secure Boot overview; Fuse Configuration).
//! * `PublicKeyHash` is 64 bytes in the fuse configuration of both chips. On
//!   Orin it is the hash of the PKC public key; on Thor it is a digest of the 16
//!   key hashes (Secure Boot overview, Fuse Configuration).
//! * `BootSecurityInfo` is 4 bytes. The overview page gives the bit meanings:
//!   Orin bits [2:0] the authentication scheme, [3] secure boot encryption, [9]
//!   OEM key valid; Thor [3] secure boot encryption, [5] revocation policy, [9]
//!   OEM key valid, [13] firmware TPM enable. The authentication scheme values
//!   are documented only through examples: the Fuse Configuration page gives
//!   Orin 0x1 RSA-3K, 0x2 ECDSA P-256, 0x5 XMSS, 0x20b ECDSA P-521 with SBK and
//!   OemK1 (low bits 0b011); the Orin Quick Start gives 0x2be1
//!   ("Bits[2:0]=001:RSA3K") and 0x2be9 (the same with bit 3, SBK encryption),
//!   and says newer Orin releases burn bits [8:5] in advance. On Thor the scheme
//!   is not in this fuse; it is chosen at signing time, and the Thor Quick Start
//!   gives 0x2220 and 0x2228 (bit 13 fTPM, bit 9 OEM key valid, bit 5
//!   revocation, bit 3 SBK encryption).
//! * `OdmId` is 8 bytes. `OdmInfo` is 4 bytes of which only the last two are
//!   programmable. `OptInEnable` is a 4-byte, 1-bit fuse.
//!
//! Secure boot is therefore enforced only when the lock is set **and** a key
//! hash is present. `SecurityMode` alone, or a key hash alone, is not it.
//!
//! The documented way to read these on a running device is
//! `nv_fuse_read.sh <name>` as root, with `-l` to list the supported fuses and
//! `boot_security_info` as the example name (Fuse Operations). Its output format is not documented, so the
//! parser accepts one value per call, bare or as `name: value` / `name = value`,
//! and anything else reads as "not read". The sysfs nodes some JetPack 5
//! releases exposed (`efuse-burn`, `tegra-fuse`) are tried first; whether
//! JetPack 6 and 7 publish them is unverified. Neither route is run on a real
//! device. Key fuses (SBK, KDK, OEM_K, FEK, KEK) are never read: the allow-list
//! below is the whole of what this module asks for.

use crate::board::{SecureBoot, TegraSoc};
use std::path::{Path, PathBuf};
use std::process::Command;

/// `PublicKeyHash` is 64 bytes (`size="64"` in every Fuse Configuration example).
pub const PUBLIC_KEY_HASH_HEX_DIGITS: usize = 128;

/// The only fuses this module reads. None of them is secret.
pub const READABLE: &[&str] = &[
    "security_mode",
    "boot_security_info",
    "public_key",
    "odmid",
    "odm_lock",
    "arm_jtag_disable",
    "ecid",
];

/// Names `nv_fuse_read.sh` or sysfs may use for the same fuse, tried in order.
/// Unverified: NVIDIA's pages give the fuse names (`SecurityMode`,
/// `PublicKeyHash`), the forum shows the sysfs spellings.
pub fn aliases(name: &str) -> &'static [&'static str] {
    match name {
        "security_mode" => &["security_mode", "odm_production_mode"],
        "public_key" => &["public_key", "public_key_hash"],
        "arm_jtag_disable" => &["arm_jtag_disable", "jtag_disable"],
        "boot_security_info" => &["boot_security_info"],
        "odmid" => &["odmid", "odm_id"],
        "odm_lock" => &["odm_lock"],
        "ecid" => &["ecid"],
        _ => &[],
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fuses {
    pub security_mode: Option<u64>,
    pub boot_security_info: Option<u64>,
    /// Lower-case hex, no prefix, as read.
    pub public_key_hash: Option<String>,
    pub odm_id: Option<u64>,
    pub odm_lock: Option<u64>,
    pub arm_jtag_disable: Option<u64>,
    pub ecid: Option<String>,
}

/// Pull the value out of one reading. `name` is any alias.
pub fn parse_reading(text: &str, name: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let mut value = line;
    for sep in [':', '='] {
        if let Some((k, v)) = line.split_once(sep) {
            let k = k.trim().to_ascii_lowercase().replace(['-', ' '], "_");
            if !k.is_empty() && !aliases_contains(name, &k) {
                return None; // a different fuse answered
            }
            value = v;
            break;
        }
    }
    let v = value.trim().trim_start_matches("0x").trim_start_matches("0X").to_ascii_lowercase();
    (!v.is_empty() && v.len() <= 256 && v.bytes().all(|b| b.is_ascii_hexdigit())).then_some(v)
}

fn aliases_contains(name: &str, key: &str) -> bool {
    aliases(name).contains(&key) || key == name
}

fn as_u64(h: &str) -> Option<u64> {
    (h.len() <= 16).then(|| u64::from_str_radix(h, 16).ok()).flatten()
}

impl Fuses {
    /// Build from `(canonical name, raw text)` readings.
    pub fn from_readings<'a>(readings: impl IntoIterator<Item = (&'a str, &'a str)>) -> Fuses {
        let mut f = Fuses::default();
        for (name, text) in readings {
            let Some(v) = parse_reading(text, name) else { continue };
            match name {
                "security_mode" => f.security_mode = as_u64(&v),
                "boot_security_info" => f.boot_security_info = as_u64(&v),
                "public_key" => f.public_key_hash = Some(v),
                "odmid" => f.odm_id = as_u64(&v),
                "odm_lock" => f.odm_lock = as_u64(&v),
                "arm_jtag_disable" => f.arm_jtag_disable = as_u64(&v),
                "ecid" => f.ecid = Some(v),
                _ => {}
            }
        }
        f
    }

    /// Whether a key hash is burned. `None` when it was not read, or was read in
    /// a width other than the documented 64 bytes (128 hex digits): a value of
    /// another width is not shown to be the fuse, so it is not judged.
    fn key_hash_present(&self) -> Option<bool> {
        self.public_key_hash
            .as_ref()
            .filter(|h| h.len() == PUBLIC_KEY_HASH_HEX_DIGITS)
            .map(|h| h.bytes().any(|b| b != b'0'))
    }

    /// Whether the firmware TPM is enabled by fuse, where the fuses say so.
    /// Thor: `BootSecurityInfo` bit 13. Orin: not carried by that register.
    pub fn ftpm_enable_bit(&self, soc: TegraSoc) -> Option<bool> {
        match soc {
            TegraSoc::Thor => self.boot_security_info.map(|b| b & (1 << 13) != 0),
            TegraSoc::Orin => None,
        }
    }
}

/// Where the fuses are read from.
pub struct Source {
    pub sysfs: Vec<PathBuf>,
    pub script: Option<PathBuf>,
}

impl Source {
    pub fn system() -> Source {
        Source {
            sysfs: vec![
                PathBuf::from("/sys/devices/platform/efuse-burn"),
                PathBuf::from("/sys/devices/platform/tegra-fuse"),
            ],
            script: ["/usr/sbin/nv_fuse_read.sh", "/usr/bin/nv_fuse_read.sh", "/opt/nvidia/jetson-io/nv_fuse_read.sh"]
                .iter()
                .map(PathBuf::from)
                .find(|p| p.exists()),
        }
    }

    /// Read every allowed fuse. Each call is read-only.
    pub fn read(&self) -> Fuses {
        let mut owned: Vec<(&str, String)> = Vec::new();
        for name in READABLE {
            if let Some(t) = self.read_one(name) {
                owned.push((name, t));
            }
        }
        Fuses::from_readings(owned.iter().map(|(n, t)| (*n, t.as_str())))
    }

    fn read_one(&self, name: &str) -> Option<String> {
        for alias in aliases(name) {
            for dir in &self.sysfs {
                if let Ok(t) = std::fs::read_to_string(dir.join(alias)) {
                    return Some(t);
                }
            }
        }
        let script = self.script.as_deref().filter(|s| Path::new(s).exists())?;
        for alias in aliases(name) {
            if let Ok(o) = Command::new(script).arg(alias).output() {
                if o.status.success() {
                    return Some(String::from_utf8_lossy(&o.stdout).into_owned());
                }
            }
        }
        None
    }
}

/// The Orin authentication scheme a `BootSecurityInfo` value names, for the
/// values the examples show: 0x1 and 0x2be1 RSA-3K, 0x2 ECDSA P-256, 0x5 XMSS,
/// 0x20b ECDSA P-521 (bits [2:0] = 0b011). Nothing else is named.
pub fn orin_scheme(boot_security_info: u64) -> Option<&'static str> {
    match boot_security_info & 0b111 {
        0b001 => Some("RSA-3K"),
        0b010 => Some("ECDSA P-256"),
        0b011 => Some("ECDSA P-521"),
        0b101 => Some("XMSS"),
        _ => None,
    }
}

/// Is secure boot fused? Anything not established reads as not enforced.
pub fn secure_boot(soc: TegraSoc, f: &Fuses) -> SecureBoot {
    let (Some(mode), Some(hash)) = (f.security_mode, f.key_hash_present()) else {
        let mut missing = Vec::new();
        if f.security_mode.is_none() {
            missing.push("SecurityMode");
        }
        match &f.public_key_hash {
            None => missing.push("PublicKeyHash"),
            Some(h) if h.len() != PUBLIC_KEY_HASH_HEX_DIGITS => missing.push("PublicKeyHash (read as a different width than 64 bytes)"),
            Some(_) => {}
        }
        return SecureBoot::Unknown { why: format!("fuse(s) not readable here: {}", missing.join(", ")) };
    };
    match (mode, hash) {
        (0, false) => SecureBoot::Off { detail: "SecurityMode is 0 and PublicKeyHash is zero: development part, not fused".into() },
        (0, true) => SecureBoot::Configured {
            detail: "PublicKeyHash is burned but SecurityMode is 0: not locked, further fuse writes are still possible".into(),
        },
        (1, false) => SecureBoot::Configured {
            detail: "SecurityMode is 1 but PublicKeyHash is zero: locked with no key to check against".into(),
        },
        (1, true) => match soc {
            TegraSoc::Orin => match f.boot_security_info {
                None => SecureBoot::Unknown { why: "BootSecurityInfo not readable, authentication scheme unknown".into() },
                Some(b) => match orin_scheme(b) {
                    Some(name) => SecureBoot::Enforced {
                        detail: format!("SecurityMode 1, PublicKeyHash burned, BootSecurityInfo {b:#x} ({name})"),
                    },
                    None if b & 0b111 == 0 => SecureBoot::Configured {
                        detail: format!("BootSecurityInfo {b:#x}: authentication scheme bits are 000, no scheme is selected"),
                    },
                    None => SecureBoot::Unknown {
                        why: format!(
                            "BootSecurityInfo {b:#x}: scheme bits {:03b} are not among the values the Fuse Configuration examples show (001, 010, 011, 101)",
                            b & 0b111
                        ),
                    },
                },
            },
            TegraSoc::Thor => SecureBoot::Enforced {
                detail: format!(
                    "SecurityMode 1, PublicKeyHash burned{}",
                    f.boot_security_info.map(|b| format!(", BootSecurityInfo {b:#x}")).unwrap_or_default()
                ),
            },
        },
        (other, _) => SecureBoot::Unknown { why: format!("SecurityMode {other:#x} is not 0 or 1") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic values in the documented shapes. Not captured from a device.
    const KEY: &str = "5d1b0f0c9e3a4b7c8d2e1f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829304";

    fn fuses(mode: &str, hash: &str, bsi: Option<&str>) -> Fuses {
        let mut r = vec![("security_mode", mode), ("public_key", hash)];
        if let Some(b) = bsi {
            r.push(("boot_security_info", b));
        }
        Fuses::from_readings(r)
    }

    fn zero() -> String {
        "0".repeat(128)
    }

    #[test]
    fn orin_fused_with_rsa3k_is_enforced() {
        // 0x2be1 is the Orin Quick Start's "Bits[2:0]=001:RSA3K"; 0x1 the Fuse Configuration example.
        for v in ["0x1", "0x2be1", "0x2be9"] {
            let f = fuses("0x1", KEY, Some(v));
            assert!(matches!(secure_boot(TegraSoc::Orin, &f), SecureBoot::Enforced { .. }), "{v}");
        }
    }

    #[test]
    fn wrong_levels_are_not_enforced() {
        let z = zero();
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("0", &z, Some("0x1"))), SecureBoot::Off { .. }));
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("0", KEY, Some("0x1"))), SecureBoot::Configured { .. }));
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("1", &z, Some("0x1"))), SecureBoot::Configured { .. }));
        // scheme bits 000: no scheme selected
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("1", KEY, Some("0x200"))), SecureBoot::Configured { .. }));
        // no BootSecurityInfo on Orin
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("1", KEY, None)), SecureBoot::Unknown { .. }));
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("2", KEY, Some("0x1"))), SecureBoot::Unknown { .. }));
    }

    #[test]
    fn every_documented_orin_scheme_is_enforced_and_nothing_else_is_named() {
        // The Fuse Configuration examples: 0x1 RSA-3K, 0x2 ECDSA P-256, 0x5 XMSS, 0x20b ECDSA P-521.
        for (bsi, name) in [("0x1", "RSA-3K"), ("0x2", "ECDSA P-256"), ("0x5", "XMSS"), ("0x20b", "ECDSA P-521")] {
            match secure_boot(TegraSoc::Orin, &fuses("1", KEY, Some(bsi))) {
                SecureBoot::Enforced { detail } => assert!(detail.contains(name), "{bsi}: {detail}"),
                other => panic!("{bsi}: {other:?}"),
            }
        }
        // 0b100, 0b110, 0b111 are not in any example: not established, not refused as wrong
        for bsi in ["0x4", "0x6", "0x7"] {
            assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("1", KEY, Some(bsi))), SecureBoot::Unknown { .. }), "{bsi}");
        }
    }

    #[test]
    fn a_key_hash_of_the_wrong_width_is_not_taken_for_the_fuse() {
        let short = &KEY[..64]; // 32 bytes
        assert!(matches!(secure_boot(TegraSoc::Orin, &fuses("1", short, Some("0x1"))), SecureBoot::Unknown { .. }));
        let long = format!("{KEY}00");
        assert!(matches!(secure_boot(TegraSoc::Thor, &fuses("1", &long, Some("0x2228"))), SecureBoot::Unknown { .. }));
        assert_eq!(KEY.len(), PUBLIC_KEY_HASH_HEX_DIGITS);
    }

    #[test]
    fn missing_fuses_are_unknown() {
        assert!(matches!(secure_boot(TegraSoc::Orin, &Fuses::default()), SecureBoot::Unknown { .. }));
        let only_mode = Fuses::from_readings([("security_mode", "0x1")]);
        assert!(matches!(secure_boot(TegraSoc::Thor, &only_mode), SecureBoot::Unknown { .. }));
    }

    #[test]
    fn thor_needs_lock_and_key_hash() {
        let f = fuses("1", KEY, Some("0x2228"));
        assert!(matches!(secure_boot(TegraSoc::Thor, &f), SecureBoot::Enforced { .. }));
        assert_eq!(f.ftpm_enable_bit(TegraSoc::Thor), Some(true)); // 0x2228: bit 13 (0x2000) set
        assert_eq!(fuses("1", KEY, Some("0x0228")).ftpm_enable_bit(TegraSoc::Thor), Some(false));
        assert_eq!(f.ftpm_enable_bit(TegraSoc::Orin), None);
    }

    #[test]
    fn readings_parse_strictly() {
        assert_eq!(parse_reading("0x1\n", "security_mode").as_deref(), Some("1"));
        assert_eq!(parse_reading("security_mode: 0x1", "security_mode").as_deref(), Some("1"));
        assert_eq!(parse_reading("odm_production_mode = 1", "security_mode").as_deref(), Some("1"));
        // another fuse answered
        assert_eq!(parse_reading("odmid: 0x1", "security_mode"), None);
        assert_eq!(parse_reading("permission denied", "security_mode"), None);
        assert_eq!(parse_reading("", "security_mode"), None);
        assert_eq!(parse_reading("0xzz", "security_mode"), None);
    }

    #[test]
    fn source_reads_sysfs_files_and_never_secret_names() {
        let d = std::env::temp_dir().join(format!("furcate-fuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("security_mode"), "0x1\n").unwrap();
        std::fs::write(d.join("public_key"), format!("{KEY}\n")).unwrap();
        std::fs::write(d.join("boot_security_info"), "0x1\n").unwrap();
        std::fs::write(d.join("secure_boot_key"), "deadbeef").unwrap();
        let f = Source { sysfs: vec![d.clone()], script: None }.read();
        assert!(matches!(secure_boot(TegraSoc::Orin, &f), SecureBoot::Enforced { .. }));
        for secret in ["secure_boot_key", "sbk", "kdk0", "oem_k1", "oem_k2", "fek", "kek0"] {
            assert!(!READABLE.contains(&secret));
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
