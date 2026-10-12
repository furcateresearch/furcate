//! How a leaf holds its key, and the class that earns.
//!
//! A leaf is a microcontroller that attaches to a cell's head rather than
//! joining the cluster. It cannot quote and it has no TPM, so what it can say
//! about its identity is how its one signing key is held. That statement is
//! [`LeafKeyCustody`], and [`LeafKeyCustody::class`] is the only place a
//! leaf's [`AssuranceClass`] comes from. A leaf never states its class; the
//! parent grades the evidence.
//!
//! The evidence is the leaf's own description of its silicon, recorded when
//! the operator attaches it. Like a node's enrollment, that is the one moment
//! the operator vouches for what is in front of them. A microcontroller with
//! no attestation key cannot prove the statement later, so the grading is
//! deliberately conservative: anything not described, or described in a way
//! this module does not know, grades [`AssuranceClass::Soft`].
//!
//! ## The rule
//!
//! The question is the one [`crate::backends::fingerprint`] asks of a node:
//! is anything secret? A key anyone with the device in hand can recover proves
//! continuity, not possession, and is `Soft`. A key the silicon will use but
//! never surrender to code the operator did not sign proves possession, and is
//! `Device`, the class the identity layer already gives a fuse-backed key.
//!
//! - [`LeafKeyCustody::Stored`]: a key kept in flash. `Soft`.
//! - [`LeafKeyCustody::ReadableIdentifiers`]: a key derived from values any
//!   code on the part can read (factory MAC, chip ID, flash ID). Every input
//!   can be copied onto another board. `Soft`.
//! - [`LeafKeyCustody::SramFingerprint`]: a key reconstructed on every boot
//!   from the start-up pattern of a region of SRAM, which manufacturing
//!   variation makes specific to the piece of silicon, using helper data
//!   that is not secret on its own. Whoever can run code on the part at
//!   power-up can read the pattern, and with the helper data rebuild the key.
//!   On a part with secure boot, flash encryption, the serial download mode
//!   disabled and JTAG disabled, only firmware the operator signed ever runs
//!   there, so the pattern is the silicon's own secret: `Device`. Missing any
//!   one of the four, anyone with a USB cable can flash a reader: `Soft`.
//! - [`LeafKeyCustody::FuseKey`]: a key held in a read-protected eFuse block,
//!   or in the chip's key manager or ECDSA peripheral, that firmware can use
//!   but not read. Nothing on the part can surrender it: `Device`.
//!
//! ## Which leaves a cell takes
//!
//! Each cell has a leaf floor, the lowest class a leaf may hold to attach
//! there ([`admits_leaf`]). It is `device` unless the operator sets it lower
//! for that cell, in the head's signed link. It has nothing to do with who
//! holds the site's keys: a leaf holds no custody, and admitting a `soft`
//! leaf to a cell changes nothing about [`crate::custody`].
//!
//! No class sits between `Soft` and `Device` for a fingerprint on an open
//! part. Its binding to the silicon is real, but it protects nothing against
//! the person holding the board, and that person is the one the class has to
//! answer for.

use crate::rot::AssuranceClass;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The fuses that decide whether firmware the operator did not sign can run
/// on a microcontroller, or read its flash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockdown {
    /// Only signed images boot.
    #[serde(default)]
    pub secure_boot: bool,
    /// Flash contents are encrypted with a key held in eFuse.
    #[serde(default)]
    pub flash_encryption: bool,
    /// The ROM's serial download mode is disabled, so the part cannot be
    /// reflashed or read over its USB serial bridge.
    #[serde(default)]
    pub download_disabled: bool,
    /// The JTAG debug port is disabled.
    #[serde(default)]
    pub jtag_disabled: bool,
}

impl Lockdown {
    /// Every route by which code the operator did not sign could run on the
    /// part, or read what it stores, is closed.
    pub fn complete(&self) -> bool {
        self.secure_boot && self.flash_encryption && self.download_disabled && self.jtag_disabled
    }

    /// The routes still open, in words an operator can act on.
    pub fn open(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.secure_boot {
            v.push("secure boot is off");
        }
        if !self.flash_encryption {
            v.push("flash encryption is off");
        }
        if !self.download_disabled {
            v.push("serial download is enabled");
        }
        if !self.jtag_disabled {
            v.push("JTAG is enabled");
        }
        v
    }
}

/// How a leaf's signing key is held, as its attachment record describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LeafKeyCustody {
    /// A key kept in flash.
    Stored,
    /// A key derived only from identifiers any code on the part can read.
    ReadableIdentifiers,
    /// A key reconstructed from the SRAM start-up pattern.
    SramFingerprint {
        #[serde(default)]
        lockdown: Lockdown,
    },
    /// A key held in read-protected eFuse or a key peripheral, used but never
    /// read back.
    FuseKey {
        #[serde(default)]
        lockdown: Lockdown,
    },
}

impl LeafKeyCustody {
    /// The class this evidence earns. The one mapping from leaf evidence to a
    /// class; see the module documentation for why each lands where it does.
    pub fn class(&self) -> AssuranceClass {
        match self {
            LeafKeyCustody::Stored | LeafKeyCustody::ReadableIdentifiers => AssuranceClass::Soft,
            LeafKeyCustody::SramFingerprint { lockdown } if lockdown.complete() => AssuranceClass::Device,
            LeafKeyCustody::SramFingerprint { .. } => AssuranceClass::Soft,
            LeafKeyCustody::FuseKey { .. } => AssuranceClass::Device,
        }
    }

    /// Why the evidence earns the class it does, for refusals and views.
    pub fn reason(&self) -> String {
        match self {
            LeafKeyCustody::Stored => "the key is stored in flash, so it can be copied".into(),
            LeafKeyCustody::ReadableIdentifiers => {
                "the key is derived from identifiers anything on the part can read, so it can be copied".into()
            }
            LeafKeyCustody::SramFingerprint { lockdown } if lockdown.complete() => {
                "the key is rebuilt from the SRAM start-up pattern on a part that runs only signed firmware".into()
            }
            LeafKeyCustody::SramFingerprint { lockdown } => format!(
                "the key is rebuilt from the SRAM start-up pattern, but {}, so anyone holding the part can read it",
                lockdown.open().join(", ")
            ),
            LeafKeyCustody::FuseKey { .. } => {
                "the key is held in read-protected eFuse or a key peripheral and never read back".into()
            }
        }
    }
}

impl fmt::Display for LeafKeyCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LeafKeyCustody::Stored => "stored",
            LeafKeyCustody::ReadableIdentifiers => "readable-identifiers",
            LeafKeyCustody::SramFingerprint { .. } => "sram-fingerprint",
            LeafKeyCustody::FuseKey { .. } => "fuse-key",
        })
    }
}

/// The leaf floor a cell has when its operator has set none.
pub const DEFAULT_LEAF_FLOOR: AssuranceClass = AssuranceClass::Device;

/// Whether a leaf of `class` may attach to a cell whose floor is `floor`
/// (`None` is [`DEFAULT_LEAF_FLOOR`]). The class is recorded as it is; this
/// admits it, it never raises it. The refusal says what was missing; the
/// caller adds which cell and how its operator changes the floor.
pub fn admits_leaf(floor: Option<AssuranceClass>, class: AssuranceClass) -> Result<(), String> {
    let floor = floor.unwrap_or(DEFAULT_LEAF_FLOOR);
    if class >= floor {
        return Ok(());
    }
    Err(format!("leaf class `{class}` is below the cell's leaf floor `{floor}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: Lockdown =
        Lockdown { secure_boot: false, flash_encryption: false, download_disabled: false, jtag_disabled: false };
    const LOCKED: Lockdown =
        Lockdown { secure_boot: true, flash_encryption: true, download_disabled: true, jtag_disabled: true };

    #[test]
    fn every_kind_of_evidence_maps_to_one_class() {
        assert_eq!(LeafKeyCustody::Stored.class(), AssuranceClass::Soft);
        assert_eq!(LeafKeyCustody::ReadableIdentifiers.class(), AssuranceClass::Soft);
        assert_eq!(LeafKeyCustody::SramFingerprint { lockdown: OPEN }.class(), AssuranceClass::Soft);
        assert_eq!(LeafKeyCustody::SramFingerprint { lockdown: LOCKED }.class(), AssuranceClass::Device);
        assert_eq!(LeafKeyCustody::FuseKey { lockdown: OPEN }.class(), AssuranceClass::Device);
        assert_eq!(LeafKeyCustody::FuseKey { lockdown: LOCKED }.class(), AssuranceClass::Device);
    }

    #[test]
    fn a_fingerprint_with_any_route_left_open_stays_soft() {
        for i in 0..4 {
            let mut l = LOCKED;
            match i {
                0 => l.secure_boot = false,
                1 => l.flash_encryption = false,
                2 => l.download_disabled = false,
                _ => l.jtag_disabled = false,
            }
            let e = LeafKeyCustody::SramFingerprint { lockdown: l };
            assert_eq!(e.class(), AssuranceClass::Soft, "{l:?}");
            assert_eq!(l.open().len(), 1);
            assert!(e.reason().contains(l.open()[0]), "{}", e.reason());
        }
    }

    #[test]
    fn no_leaf_evidence_reaches_a_class_that_may_control() {
        for e in [
            LeafKeyCustody::Stored,
            LeafKeyCustody::ReadableIdentifiers,
            LeafKeyCustody::SramFingerprint { lockdown: LOCKED },
            LeafKeyCustody::FuseKey { lockdown: LOCKED },
        ] {
            assert!(!e.class().may_control(), "{e}");
        }
    }

    #[test]
    fn a_cell_takes_a_soft_leaf_only_when_its_floor_is_soft() {
        assert!(admits_leaf(None, AssuranceClass::Device).is_ok());
        let e = admits_leaf(None, AssuranceClass::Soft).unwrap_err();
        assert!(e.contains("`soft`") && e.contains("floor `device`"), "{e}");
        assert!(admits_leaf(Some(AssuranceClass::Soft), AssuranceClass::Soft).is_ok());
        assert!(admits_leaf(Some(AssuranceClass::Tpm), AssuranceClass::Device).is_err());
    }

    #[test]
    fn the_wire_form_is_tagged_and_strict() {
        let e: LeafKeyCustody = serde_json::from_str(
            r#"{"kind":"sram-fingerprint","lockdown":{"secure_boot":true,"flash_encryption":true,"download_disabled":true,"jtag_disabled":true}}"#,
        )
        .unwrap();
        assert_eq!(e, LeafKeyCustody::SramFingerprint { lockdown: LOCKED });
        let e: LeafKeyCustody = serde_json::from_str(r#"{"kind":"sram-fingerprint"}"#).unwrap();
        assert_eq!(e.class(), AssuranceClass::Soft, "an unstated fuse is an open one");
        assert!(serde_json::from_str::<LeafKeyCustody>(r#"{"kind":"tpm"}"#).is_err());
        assert!(
            serde_json::from_str::<LeafKeyCustody>(r#"{"kind":"fuse-key","lockdown":{"secureboot":true}}"#).is_err(),
            "a misspelt fuse is refused, not read as off"
        );
        let back = serde_json::to_string(&LeafKeyCustody::FuseKey { lockdown: OPEN }).unwrap();
        assert_eq!(serde_json::from_str::<LeafKeyCustody>(&back).unwrap(), LeafKeyCustody::FuseKey { lockdown: OPEN });
    }
}
