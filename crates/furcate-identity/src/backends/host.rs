//! What a Linux host can say about itself when it has no TPM.
//!
//! [`backends::fingerprint`] describes an identity built from immutable
//! hardware characteristics and is complete, but nothing gathered those
//! characteristics on a server. So a machine without a TPM could not start
//! `furcated` at all — not by policy, but because the code to ask the hardware
//! its name had never been written. This module is that code.
//!
//! Two things about the shape of it are deliberate.
//!
//! **The anchors are readable only by root, and `furcated` does not run as
//! root.** `/sys/class/dmi/id/board_serial` and its neighbours are mode 0400.
//! That is not an obstacle to work around; it is the right moment to involve a
//! person. The serials are read once, by an operator, through
//! `furcatectl identity soft-enroll`, and written to a root-owned file that the
//! daemon can read but not rewrite. Enrolling a machine on continuity alone is
//! a decision for the site, taken once, and this makes it one — rather than
//! something a node grants itself by starting up.
//!
//! **What the daemon re-reads on every start is the part it can.** Board name,
//! vendor and MACs are world-readable, so a machine that has been swapped under
//! a recorded identity is caught at the next start. The serials it cannot read
//! are carried from the record. That is a weaker check than a TPM quote and
//! says so: this whole path classifies [`AssuranceClass::Soft`], which may not
//! hold custody of anything and may not lead a cluster.
//!
//! [`backends::fingerprint`]: crate::backends::fingerprint
//! [`AssuranceClass::Soft`]: crate::rot::AssuranceClass::Soft

use crate::backends::fingerprint::{Characteristic, Continuity, Fingerprint, FingerprintRot};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const DMI: &str = "/sys/class/dmi/id";

/// Firmware fields that are present but say nothing.
///
/// Board vendors ship these strings rather than leave the field empty, so a
/// naive read produces a fingerprint that every machine of that model shares.
/// They have to be rejected by value, because they are indistinguishable from
/// a real serial by type.
fn is_placeholder(v: &str) -> bool {
    let t = v.trim();
    if t.is_empty() || t.len() < 4 {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    [
        "to be filled by o.e.m.",
        "to be filled by oem",
        "not specified",
        "not applicable",
        "system serial number",
        "default string",
        "none",
        "n/a",
        "unknown",
        "0123456789",
        "invalid",
    ]
    .iter()
    .any(|junk| lower == *junk)
        || lower.chars().all(|c| c == '0' || c == '.' || c == '-')
}

fn dmi(field: &str) -> Option<String> {
    let raw = std::fs::read_to_string(format!("{DMI}/{field}")).ok()?;
    let v = raw.trim().to_string();
    if is_placeholder(&v) {
        None
    } else {
        Some(v)
    }
}

/// MAC addresses of interfaces backed by real hardware.
///
/// The `device` symlink is what separates a network card from a bridge, a
/// veth or a WireGuard interface — and those come and go with whatever the
/// machine is running, which would make the fingerprint a description of the
/// workload rather than of the hardware.
fn hardware_macs() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for e in entries.flatten() {
        if !e.path().join("device").exists() {
            continue;
        }
        let Ok(addr) = std::fs::read_to_string(e.path().join("address")) else {
            continue;
        };
        let addr = addr.trim().to_ascii_lowercase();
        // A card that reports all zeros is reporting that it does not know.
        if addr.len() == 17 && addr != "00:00:00:00:00:00" {
            out.push(addr);
        }
    }
    out.sort();
    out
}

/// Where the firmware publishes the device tree it booted with.
const DEVICE_TREE: &str = "/sys/firmware/devicetree/base";

/// One device-tree property as text.
///
/// String properties end in a NUL and some carry several NUL-separated
/// strings; both are folded into one value. A property that is not printable
/// text, such as the 32-bit `linux,revision`, is returned as hex so that the
/// value recorded is the value the firmware reported, byte for byte.
fn devicetree_value(base: &Path, rel: &str) -> Option<String> {
    let raw = std::fs::read(base.join(rel)).ok()?;
    let trimmed: &[u8] = match raw.iter().rposition(|b| *b != 0) {
        Some(end) => &raw[..=end],
        None => return None,
    };
    let text = trimmed.iter().all(|b| *b == 0 || (0x20..0x7f).contains(b));
    let v = if text {
        trimmed.split(|b| *b == 0).map(|p| String::from_utf8_lossy(p).trim().to_string()).collect::<Vec<_>>().join(",")
    } else {
        hex::encode(trimmed)
    };
    if is_placeholder(&v) {
        None
    } else {
        Some(v)
    }
}

/// What a board without DMI, such as a Raspberry Pi, says about itself.
///
/// A Raspberry Pi 5 has no SMBIOS tables. Its firmware reads the board serial
/// and revision code from OTP and publishes them in the device tree, and newer
/// firmware adds a device-unique identifier (`chosen/rpi-duid`). All are
/// world-readable and none is secret: they give continuity, not possession.
/// The OTP device key, when provisioned, is the Pi's possession proof and is
/// opened by [`super::rpi_fw_crypto`], not here.
fn observe_devicetree(base: &Path, mut f: Fingerprint) -> Fingerprint {
    if let Some(v) = devicetree_value(base, "serial-number") {
        f = f.with(Characteristic::CpuSerial, v);
    }
    if let Some(v) = devicetree_value(base, "chosen/rpi-duid") {
        f = f.with(Characteristic::SocSerial, v);
    }
    let model = [devicetree_value(base, "model"), devicetree_value(base, "system/linux,revision")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" rev ");
    if !model.is_empty() && !f.parts.contains_key(&Characteristic::BoardRevision) {
        f = f.with(Characteristic::BoardRevision, model);
    }
    f
}

/// Everything this process can currently read about the machine.
///
/// Fields it cannot read are absent rather than empty, so a fingerprint taken
/// as `furcate` and one taken as root differ in size but never contradict each
/// other. [`SoftIdentity::continuity`] relies on that.
pub fn observe() -> Fingerprint {
    let mut f = Fingerprint::default();

    // Root only, and the two that actually anchor the identity.
    if let Some(v) = dmi("board_serial") {
        f = f.with(Characteristic::BoardSerial, v);
    }
    if let Some(v) = dmi("chassis_serial").or_else(|| dmi("product_serial")) {
        f = f.with(Characteristic::ChassisSerial, v);
    }
    if let Some(v) = dmi("product_uuid") {
        f = f.with(Characteristic::DmiUuid, v);
    }

    // World-readable, so the daemon can re-check these on every start.
    let model = [dmi("board_vendor"), dmi("board_name"), dmi("board_version")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if !model.is_empty() {
        f = f.with(Characteristic::BoardRevision, model);
    }
    let macs = hardware_macs();
    if !macs.is_empty() {
        f = f.with(Characteristic::MacAddress, macs.join(","));
    }

    observe_devicetree(Path::new(DEVICE_TREE), f)
}

/// A machine admitted on hardware continuity rather than on a held key.
///
/// Written by `furcatectl identity soft-enroll`, read by `furcated`. It is a
/// record of a decision, which is why it carries the reason it was taken and
/// when: a file that only says "allowed" cannot be reviewed afterwards.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SoftIdentity {
    /// Always true in a file that was written deliberately. Present so that a
    /// half-written or copied file does not read as consent.
    pub acknowledged: bool,
    /// Why this machine is enrolled without a root of trust.
    pub reason: String,
    /// Unix seconds at which an operator took the decision.
    pub recorded_at: u64,
    /// What the hardware said at that moment, read as root.
    pub observed: Fingerprint,
}

impl SoftIdentity {
    /// Capture the current machine. Requires the privilege to read DMI serials.
    pub fn capture(reason: impl Into<String>, now_s: u64) -> Result<Self> {
        let observed = observe();
        if !observed.is_usable() {
            return Err(anyhow!(
                "this machine offers {} hardware anchors and {} are needed. \
                 Reading {DMI}/board_serial needs root, so run this as root; \
                 if it still fails the firmware is not reporting serials.",
                observed.anchors().len(),
                Fingerprint::MIN_ANCHORS
            ));
        }
        Ok(Self {
            acknowledged: true,
            reason: reason.into(),
            recorded_at: now_s,
            observed,
        })
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, format!("{json}\n"))
            .with_context(|| format!("writing {}", path.display()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let me: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        if !me.acknowledged {
            return Err(anyhow!(
                "{} does not acknowledge the decision, so it is not consent",
                path.display()
            ));
        }
        if !me.observed.is_usable() {
            return Err(anyhow!(
                "{} records {} hardware anchors and {} are needed",
                path.display(),
                me.observed.anchors().len(),
                Fingerprint::MIN_ANCHORS
            ));
        }
        Ok(me)
    }

    /// Whether the machine still looks like the one that was enrolled.
    ///
    /// Only characteristics this process can read now are compared. A serial
    /// that needs root is carried from the record and not re-checked, so an
    /// unprivileged daemon reports `Same` for a field it never saw rather than
    /// an alarm it cannot substantiate.
    pub fn continuity(&self) -> Continuity {
        let now = observe();
        let visible = Fingerprint {
            parts: self
                .observed
                .parts
                .iter()
                .filter(|(c, _)| now.parts.contains_key(c))
                .map(|(c, v)| (*c, v.clone()))
                .collect(),
        };
        now.compare(&visible)
    }

    /// The root of trust this record stands for.
    ///
    /// The identity is the fingerprint as enrolled, not as re-read, so the node
    /// keeps one id across restarts and across the fields a given process
    /// happens to be able to read.
    pub fn rot(&self) -> FingerprintRot {
        FingerprintRot::new(self.observed.clone()).enrolled_as(self.observed.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_tree(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-dt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("chosen")).unwrap();
        std::fs::create_dir_all(d.join("system")).unwrap();
        d
    }

    #[test]
    fn a_pi_device_tree_gives_two_anchors() {
        let d = scratch_tree("pi5");
        std::fs::write(d.join("serial-number"), b"7f3a91c2d04e5b16\0").unwrap();
        std::fs::write(d.join("model"), b"Raspberry Pi 5 Model B Rev 1.0\0").unwrap();
        std::fs::write(d.join("system/linux,revision"), [0x00u8, 0xd0, 0x41, 0x70]).unwrap();
        let f = observe_devicetree(&d, Fingerprint::default());
        assert_eq!(f.parts.get(&Characteristic::CpuSerial).map(String::as_str), Some("7f3a91c2d04e5b16"));
        assert_eq!(
            f.parts.get(&Characteristic::BoardRevision).map(String::as_str),
            Some("Raspberry Pi 5 Model B Rev 1.0 rev 00d04170")
        );
        assert!(f.is_usable(), "serial and revision are two anchors");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_device_unique_id_is_recorded_when_the_firmware_offers_one() {
        let d = scratch_tree("duid");
        std::fs::write(d.join("serial-number"), b"7f3a91c2d04e5b16\0").unwrap();
        std::fs::write(d.join("chosen/rpi-duid"), b"5JQS3D1A0B\0").unwrap();
        let f = observe_devicetree(&d, Fingerprint::default());
        assert_eq!(f.parts.get(&Characteristic::SocSerial).map(String::as_str), Some("5JQS3D1A0B"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_empty_or_zero_serial_is_not_an_anchor() {
        let d = scratch_tree("zero");
        std::fs::write(d.join("serial-number"), b"0000000000000000\0").unwrap();
        let f = observe_devicetree(&d, Fingerprint::default());
        assert!(!f.parts.contains_key(&Characteristic::CpuSerial));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dmi_board_model_is_not_overwritten_by_the_device_tree() {
        let d = scratch_tree("dmi");
        std::fs::write(d.join("model"), b"QEMU arm64 virt\0").unwrap();
        let f = observe_devicetree(&d, Fingerprint::default().with(Characteristic::BoardRevision, "Vendor Board 1"));
        assert_eq!(f.parts.get(&Characteristic::BoardRevision).map(String::as_str), Some("Vendor Board 1"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn firmware_placeholders_are_not_serials() {
        for junk in [
            "To Be Filled By O.E.M.",
            "Default string",
            "None",
            "0000000000",
            "   ",
            "N/A",
        ] {
            assert!(is_placeholder(junk), "{junk} should be rejected");
        }
        assert!(!is_placeholder("QXB20000001"));
        assert!(!is_placeholder("ec113869-e362-9646-9ddc-6b841a8a1376"));
    }

    fn enrolled() -> SoftIdentity {
        SoftIdentity {
            acknowledged: true,
            reason: "build machine, no TPM header populated".into(),
            recorded_at: 1_700_000_000,
            observed: Fingerprint::default()
                .with(Characteristic::BoardSerial, "QXB20000001")
                .with(Characteristic::ChassisSerial, "QXC2000V1AB")
                .with(Characteristic::BoardRevision, "Cisco Systems Inc UCSC-C220-M4S")
                .with(Characteristic::MacAddress, "00:00:5e:00:53:20"),
        }
    }

    #[test]
    fn a_server_fingerprint_rests_on_its_serials() {
        let s = enrolled();
        assert!(s.observed.is_usable());
        // The MAC contributes to the digest but is not an anchor: it is
        // overridable with one command, so it cannot carry an identity.
        assert!(!s.observed.anchors().contains(&Characteristic::MacAddress));
        assert!(s
            .observed
            .anchors()
            .contains(&Characteristic::BoardSerial));

        // Model and MAC alone — what an unprivileged read yields — leave one
        // anchor, which is below the bar. Two identical machines out of the
        // same box would otherwise share an identity.
        let unprivileged = Fingerprint::default()
            .with(Characteristic::BoardRevision, "Cisco Systems Inc UCSC-C220-M4S")
            .with(Characteristic::MacAddress, "00:00:5e:00:53:20");
        assert!(!unprivileged.is_usable());
    }

    #[test]
    fn an_unreadable_serial_is_not_a_changed_serial() {
        // What an unprivileged daemon sees: the model and MAC, no serials.
        let visible = Fingerprint::default()
            .with(Characteristic::BoardRevision, "Cisco Systems Inc UCSC-C220-M4S")
            .with(Characteristic::MacAddress, "00:00:5e:00:53:20");
        let recorded = enrolled().observed;
        let narrowed = Fingerprint {
            parts: recorded
                .parts
                .iter()
                .filter(|(c, _)| visible.parts.contains_key(c))
                .map(|(c, v)| (*c, v.clone()))
                .collect(),
        };
        assert_eq!(visible.compare(&narrowed), Continuity::Same);
        // Compared against the whole record it would look like a swapped board,
        // which is the mistake this narrowing exists to prevent.
        assert!(visible.compare(&recorded).needs_operator());
    }

    #[test]
    fn a_swapped_board_is_an_alarm() {
        let recorded = enrolled().observed;
        let other = Fingerprint::default()
            .with(Characteristic::BoardSerial, "FCH9999999")
            .with(Characteristic::ChassisSerial, "QXC2000V1AB")
            .with(Characteristic::BoardRevision, "Cisco Systems Inc UCSC-C220-M4S")
            .with(Characteristic::MacAddress, "00:00:5e:00:53:20");
        assert!(other.compare(&recorded).needs_operator());
    }

    #[test]
    fn the_rot_keeps_one_id_and_stays_soft() {
        use crate::rot::{AssuranceClass, RootOfTrust};
        let s = enrolled();
        let rot = s.rot();
        assert_eq!(rot.assurance(), AssuranceClass::Soft);
        assert_eq!(rot.node_id().unwrap(), s.rot().node_id().unwrap());
        assert_eq!(rot.continuity(), Some(Continuity::Same));
        // A quote from here carries no signature, so a verifier rejects it.
        assert!(rot.quote(b"nonce").unwrap().signature.is_empty());
    }
}
