//! Identity for hardware with no trusted key store.
//!
//! Microcontrollers and single-board computers are full members of a site's
//! sensing surface and most of them have nothing to hold a private key with.
//! A Raspberry Pi has a CPU serial and one-time-programmable memory, an ESP32
//! has eFuses and a factory MAC — all readable, none secret. What the silicon
//! offers is a set of immutable characteristics, and this backend builds an
//! identity out of them.
//!
//! The property that gives is **continuity**, not unforgeability, and the
//! difference is the whole point of the module. A fingerprint proves that the
//! board answering today has the same characteristics as the board enrolled
//! last month. It does not prove that nobody copied those characteristics onto
//! a different board, because every one of them can be read by anything with
//! access to the device. So a fingerprinted node classifies [`Soft`] — the same
//! class as a file-backed key — and inherits every restriction that carries:
//! no custody of sealed data, no quotes, no attested placement.
//!
//! One thing does lift it. If the silicon has a fuse-held secret it will use
//! but never read back — an ESP32 eFuse HMAC key with read protection, or an
//! attached secure element — then the device can prove possession rather than
//! merely assert an identifier, and that is [`Device`] class. The distinction
//! is not the presence of a serial number; it is whether anything is secret.
//!
//! [`Soft`]: AssuranceClass::Soft
//! [`Device`]: AssuranceClass::Device

use crate::node_id::NodeId;
use crate::rot::{AssuranceClass, Evidence, PcrSet, Quote, RootOfTrust};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// An immutable property of a piece of hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Characteristic {
    /// Processor serial, from `/proc/cpuinfo` on a Pi.
    CpuSerial,
    /// System-on-chip identifier burned at manufacture.
    SocSerial,
    /// One-time-programmable memory contents.
    Otp,
    /// Factory MAC address, from eFuse on an ESP32.
    MacAddress,
    /// Board model and revision.
    BoardRevision,
    /// Flash chip JEDEC identifier and capacity.
    FlashId,
    /// Storage device world-wide name.
    DiskWwn,
    /// Firmware-reported system UUID.
    DmiUuid,
    /// Mainboard serial, burned at manufacture.
    ///
    /// On a Linux server this is `/sys/class/dmi/id/board_serial`, mode 0400.
    /// Readable by root and by nothing else, which is what makes it worth
    /// reading once with a person present rather than on every start.
    BoardSerial,
    /// Chassis or system serial — the number on the asset tag.
    ///
    /// Independent of the board serial in practice: a board swapped under
    /// warranty changes one and not the other, and that difference is the whole
    /// value of recording both.
    ChassisSerial,
}

impl Characteristic {
    /// Whether this survives ordinary maintenance.
    ///
    /// A serial burned into the die does; a disk identifier does not, because
    /// swapping a failed SD card is routine and would read as a compromised
    /// node. Volatile characteristics are still worth recording — they narrow
    /// the match — but a change in one alone must not raise an alarm.
    pub fn is_immutable(&self) -> bool {
        matches!(
            self,
            Characteristic::CpuSerial
                | Characteristic::SocSerial
                | Characteristic::Otp
                | Characteristic::MacAddress
                | Characteristic::BoardRevision
                | Characteristic::BoardSerial
                | Characteristic::ChassisSerial
        )
    }

    /// Whether this can be changed in software without touching the hardware.
    ///
    /// A MAC address is the classic example: burned at the factory, and
    /// overridable with one command on every operating system worth using. It
    /// contributes to a fingerprint and cannot carry one.
    pub fn is_softly_spoofable(&self) -> bool {
        matches!(self, Characteristic::MacAddress | Characteristic::DmiUuid)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Characteristic::CpuSerial => "cpu_serial",
            Characteristic::SocSerial => "soc_serial",
            Characteristic::Otp => "otp",
            Characteristic::MacAddress => "mac",
            Characteristic::BoardRevision => "board_revision",
            Characteristic::FlashId => "flash_id",
            Characteristic::DiskWwn => "disk_wwn",
            Characteristic::DmiUuid => "dmi_uuid",
            Characteristic::BoardSerial => "board_serial",
            Characteristic::ChassisSerial => "chassis_serial",
        }
    }
}

/// The set of characteristics captured from one device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub parts: BTreeMap<Characteristic, String>,
}

impl Fingerprint {
    /// Minimum number of hardware-anchored characteristics for a fingerprint to
    /// be usable as an identity.
    ///
    /// One serial is a claim anyone who has read the device can repeat. Several
    /// independent ones raise the cost of impersonation from "read one file" to
    /// "read the whole device", which is not a security boundary but is a
    /// meaningful difference in practice.
    pub const MIN_ANCHORS: usize = 2;

    pub fn with(mut self, c: Characteristic, value: impl Into<String>) -> Self {
        self.parts.insert(c, value.into());
        self
    }

    /// Characteristics that survive maintenance and are not trivially forged.
    pub fn anchors(&self) -> Vec<Characteristic> {
        self.parts
            .keys()
            .copied()
            .filter(|c| c.is_immutable() && !c.is_softly_spoofable())
            .collect()
    }

    /// Whether this fingerprint rests on enough to identify a device at all.
    pub fn is_usable(&self) -> bool {
        self.anchors().len() >= Self::MIN_ANCHORS
    }

    /// Stable digest over the immutable characteristics only.
    ///
    /// Volatile ones are deliberately excluded from the identifier: including a
    /// disk serial would give the node a new identity every time an SD card is
    /// replaced, and a node whose identity changes under maintenance is a node
    /// nobody can write a policy about.
    pub fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"furcate-fingerprint-v1");
        for (c, v) in self.parts.iter().filter(|(c, _)| c.is_immutable()) {
            h.update((c.as_str().len() as u32).to_be_bytes());
            h.update(c.as_str().as_bytes());
            h.update((v.len() as u32).to_be_bytes());
            h.update(v.as_bytes());
        }
        h.finalize().to_vec()
    }

    /// Compare against a previously enrolled fingerprint.
    pub fn compare(&self, previous: &Fingerprint) -> Continuity {
        let mut changed = Vec::new();
        for (c, v) in &previous.parts {
            match self.parts.get(c) {
                Some(now) if now == v => {}
                _ => changed.push(*c),
            }
        }
        if changed.is_empty() {
            Continuity::Same
        } else if changed.iter().any(|c| c.is_immutable()) {
            Continuity::HardwareChanged { fields: changed }
        } else {
            Continuity::PeripheralChanged { fields: changed }
        }
    }
}

/// What a comparison against an enrolled fingerprint means.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Continuity {
    /// Everything matches.
    Same,
    /// A characteristic that should never change did.
    ///
    /// This is the alarm the whole backend exists to raise. It means either the
    /// board was replaced or something is answering in its place, and a
    /// fingerprint cannot tell those apart — which is exactly why it must be
    /// escalated to an operator rather than resolved automatically.
    HardwareChanged { fields: Vec<Characteristic> },
    /// Something replaceable changed — a disk, a firmware UUID.
    PeripheralChanged { fields: Vec<Characteristic> },
}

impl Continuity {
    /// Whether the node may keep operating on its enrolled identity.
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Continuity::Same | Continuity::PeripheralChanged { .. })
    }

    /// Whether an operator has to be told.
    pub fn needs_operator(&self) -> bool {
        matches!(self, Continuity::HardwareChanged { .. })
    }
}

/// A fuse-held or secure-element-held secret the device uses but cannot read
/// back.
///
/// Its presence is what separates asserting an identifier from proving
/// possession of one, and it is the only thing that lifts a fingerprinted
/// device above `Soft`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedKey {
    /// Where it lives, for the record — `efuse:block4`, `atecc608:slot0`.
    pub slot: String,
    /// Public half, where the scheme has one. An HMAC fuse does not.
    pub public: Option<Vec<u8>>,
    /// Whether readback is actually blocked. A fuse that *could* be read
    /// protected but was not is not a secret, and enrolment must not treat the
    /// intention as the fact.
    pub readback_blocked: bool,
}

impl SealedKey {
    pub fn is_effective(&self) -> bool {
        self.readback_blocked
    }
}

/// Root of trust for devices identified by their hardware characteristics.
pub struct FingerprintRot {
    pub fingerprint: Fingerprint,
    /// A device-held secret, if the silicon has one.
    pub sealed_key: Option<SealedKey>,
    /// The fingerprint recorded when this node was admitted, if it has been.
    pub enrolled: Option<Fingerprint>,
}

impl FingerprintRot {
    pub fn new(fingerprint: Fingerprint) -> Self {
        Self {
            fingerprint,
            sealed_key: None,
            enrolled: None,
        }
    }

    pub fn with_sealed_key(mut self, k: SealedKey) -> Self {
        self.sealed_key = Some(k);
        self
    }

    pub fn enrolled_as(mut self, f: Fingerprint) -> Self {
        self.enrolled = Some(f);
        self
    }

    /// Whether the device still looks like the one that was enrolled.
    ///
    /// A node that has never been enrolled returns `None` rather than passing:
    /// trust on first use is a decision for the site, taken once, by an
    /// operator — not something a node grants itself by starting up.
    pub fn continuity(&self) -> Option<Continuity> {
        self.enrolled.as_ref().map(|e| self.fingerprint.compare(e))
    }
}

impl RootOfTrust for FingerprintRot {
    fn assurance(&self) -> AssuranceClass {
        match &self.sealed_key {
            Some(k) if k.is_effective() && self.fingerprint.is_usable() => AssuranceClass::Device,
            _ => AssuranceClass::Soft,
        }
    }

    fn ek_public(&self) -> Result<Vec<u8>> {
        if !self.fingerprint.is_usable() {
            return Err(anyhow!(
                "fingerprint rests on {} hardware anchors, need {}",
                self.fingerprint.anchors().len(),
                Fingerprint::MIN_ANCHORS
            ));
        }
        // The digest stands in for an endorsement key. It is public by nature,
        // which is precisely why this backend cannot rise above `Device`.
        Ok(self.fingerprint.digest())
    }

    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        // No manufacturer vouches for a serial number.
        Ok(None)
    }

    fn ak_public(&self) -> Result<Vec<u8>> {
        match &self.sealed_key {
            Some(k) if k.is_effective() => k
                .public
                .clone()
                .ok_or_else(|| anyhow!("sealed key in {} has no public half", k.slot)),
            _ => Err(anyhow!("no attestation key: this device holds no secret")),
        }
    }

    fn pcrs(&self) -> Result<PcrSet> {
        // Nothing measures the boot on this class of hardware, and an empty
        // register set says so rather than implying a clean measurement.
        Ok(PcrSet::default())
    }

    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        // A self-description in the shape of a quote, with no signature — so a
        // verifier calling `Quote::is_signed` rejects it, which is the correct
        // outcome. Returning an error instead would push every caller into a
        // special case and invite somebody to skip the check entirely.
        Ok(Quote {
            message: self.fingerprint.digest(),
            signature: Vec::new(),
            nonce: nonce.to_vec(),
            pcrs: PcrSet::default(),
        })
    }

    fn node_id(&self) -> Result<NodeId> {
        Ok(NodeId::from_ek_public(&self.ek_public()?))
    }

    fn evidence(&self, nonce: &[u8]) -> Result<Evidence> {
        Ok(Evidence {
            node_id: self.node_id()?,
            assurance: self.assurance(),
            ek_public: self.ek_public()?,
            ek_certificate: None,
            // Absent unless the device holds a secret.
            ak_public: self.ak_public().unwrap_or_default(),
            quote: self.quote(nonce)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Raspberry Pi: serial, board revision, OTP, MAC. All readable.
    fn pi() -> Fingerprint {
        Fingerprint::default()
            .with(Characteristic::CpuSerial, "100000003f8a1b2c")
            .with(Characteristic::BoardRevision, "d03115")
            .with(Characteristic::Otp, "0x00000000ffffffff")
            .with(Characteristic::MacAddress, "dc:a6:32:11:22:33")
            .with(Characteristic::DiskWwn, "mmc-SC32G_0x1234abcd")
    }

    /// An ESP32: factory MAC and flash identifier, plus a fuse block.
    fn esp32() -> Fingerprint {
        Fingerprint::default()
            .with(Characteristic::SocSerial, "esp32c6-7c0a12")
            .with(Characteristic::MacAddress, "7c:df:a1:00:11:22")
            .with(Characteristic::FlashId, "c84016")
            .with(Characteristic::Otp, "blk3:9f2c")
    }

    #[test]
    fn a_pi_fingerprint_is_usable_as_an_identifier() {
        assert!(pi().is_usable());
        assert!(esp32().is_usable());
    }

    #[test]
    fn a_mac_address_alone_cannot_carry_an_identity() {
        // Burned at the factory and overridable with one command.
        let weak = Fingerprint::default().with(Characteristic::MacAddress, "7c:df:a1:00:11:22");
        assert!(!weak.is_usable());
        assert!(FingerprintRot::new(weak).ek_public().is_err());
    }

    #[test]
    fn a_readable_fingerprint_is_soft_however_many_serials_it_has() {
        // The heart of it: a serial is an identifier, not a secret, so this
        // sits in the same class as a file-backed key and inherits every
        // restriction that carries.
        let rot = FingerprintRot::new(pi());
        assert_eq!(rot.assurance(), AssuranceClass::Soft);
        assert!(!rot.assurance().is_hardware_bound());
    }

    #[test]
    fn a_read_protected_fuse_lifts_it_to_device_class() {
        // Because the device can now prove possession rather than repeat a
        // number anybody can read off it.
        let rot = FingerprintRot::new(esp32()).with_sealed_key(SealedKey {
            slot: "efuse:block4".into(),
            public: Some(vec![1, 2, 3]),
            readback_blocked: true,
        });
        assert_eq!(rot.assurance(), AssuranceClass::Device);
        assert!(rot.assurance().is_hardware_bound());
    }

    #[test]
    fn a_fuse_that_was_never_read_protected_is_not_a_secret() {
        // Enrolment must not mistake the intention for the fact.
        let rot = FingerprintRot::new(esp32()).with_sealed_key(SealedKey {
            slot: "efuse:block4".into(),
            public: Some(vec![1, 2, 3]),
            readback_blocked: false,
        });
        assert_eq!(rot.assurance(), AssuranceClass::Soft);
        assert!(rot.ak_public().is_err());
    }

    #[test]
    fn a_fingerprinted_node_can_never_quote() {
        // And the unsigned statement it produces is rejected by the same check
        // a real quote passes, rather than needing a special case that somebody
        // will eventually skip.
        let rot = FingerprintRot::new(pi());
        let q = rot.quote(b"nonce").unwrap();
        assert!(!q.is_signed());
        assert!(!rot.assurance().can_quote());
        assert!(q.pcrs.values.is_empty(), "nothing measured this boot");
    }

    #[test]
    fn the_identifier_survives_replacing_an_sd_card() {
        // A node whose identity changes under routine maintenance is a node
        // nobody can write a policy about.
        let before = pi();
        let after = pi().with(Characteristic::DiskWwn, "mmc-SC32G_0xdeadbeef");
        assert_eq!(before.digest(), after.digest());
        assert!(matches!(
            after.compare(&before),
            Continuity::PeripheralChanged { .. }
        ));
        assert!(after.compare(&before).is_acceptable());
    }

    #[test]
    fn a_changed_cpu_serial_is_escalated_rather_than_resolved() {
        // The board was replaced, or something is answering in its place, and a
        // fingerprint cannot tell those apart.
        let before = pi();
        let after = pi().with(Characteristic::CpuSerial, "1000000099999999");
        let c = after.compare(&before);
        assert!(matches!(c, Continuity::HardwareChanged { .. }));
        assert!(!c.is_acceptable());
        assert!(c.needs_operator());
        assert_ne!(before.digest(), after.digest());
    }

    #[test]
    fn a_node_that_was_never_enrolled_does_not_grant_itself_continuity() {
        // Trust on first use is a decision for the site, taken once, by an
        // operator.
        assert!(FingerprintRot::new(pi()).continuity().is_none());
        let enrolled = FingerprintRot::new(pi()).enrolled_as(pi());
        assert_eq!(enrolled.continuity(), Some(Continuity::Same));
    }

    #[test]
    fn evidence_from_a_fingerprint_carries_no_certificate_and_no_signature() {
        let e = FingerprintRot::new(pi()).evidence(b"nonce").unwrap();
        assert_eq!(e.assurance, AssuranceClass::Soft);
        assert!(e.ek_certificate.is_none(), "no manufacturer vouches for a serial");
        assert!(e.ak_public.is_empty());
        assert!(!e.quote.is_signed());
    }

    #[test]
    fn the_node_id_is_stable_across_reboots() {
        let a = FingerprintRot::new(pi()).node_id().unwrap();
        let b = FingerprintRot::new(pi()).node_id().unwrap();
        assert_eq!(a.as_str(), b.as_str());
        assert!(a.as_str().starts_with("furcate:node:"));
    }
}
