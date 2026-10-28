//! Machine identity for a sensing node, through the same machinery as any member.
//!
//! A sensing node that holds no secret is still a member of the site: it is
//! enrolled through `furcate-identity` like every other piece of hardware, with
//! an identity derived from its silicon fingerprint, an enrolment record, and
//! a continuity check on every start. What it cannot be is authenticated. The
//! characteristics a fingerprint rests on are readable by any code on the
//! device and by anyone holding it, so a fingerprint shows that the unit
//! answering has the characteristics of the unit enrolled, and not that it is
//! that unit. The class the identity crates give that situation is
//! [`AssuranceClass::Soft`], and nothing here raises it.
//!
//! No new assurance class is added. The existing description of `Soft`, an
//! identity not bound to a secret the hardware keeps, is exactly this case, and
//! the finer fact (fingerprint-identified, which anchors) travels as data in
//! [`IdentityBasis`] instead of as a second ladder.
//!
//! ## What feeds the fingerprint
//!
//! | characteristic | source on a board with an nRF52832 | anchor |
//! |---|---|---|
//! | `soc_serial` | the chip's 64-bit device id, if the firmware reports it | yes |
//! | `mac` | the chip's device address, if reported | no (spoofable) |
//! | `board_serial` | the serial string the USB bridge reports to the host | yes |
//! | `board_revision` | the board model, a constant | counted by the crate, shared by every unit |
//!
//! Per-unit analogue offsets and noise of the motion, magnetic and gas sensors
//! are not used. They drift with temperature and age and are bounded only by
//! datasheet limits, so they cannot serve as an immutable characteristic, and
//! there is no extraction method in the identity design to build on.

use crate::nicla::MODEL;
use furcate_identity::backends::{Characteristic, Continuity, Fingerprint, FingerprintRot};
use furcate_identity::enroll::Enrollment;
use furcate_identity::rot::{AssuranceClass, RootOfTrust};
use furcate_identity::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// The USB serial or a chip id is not a plain identifier.
    BadIdentifier(&'static str),
    /// Fewer unit-specific anchors than an identity needs.
    NotEnoughToIdentify,
    Rot(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::BadIdentifier(w) => write!(f, "identifier refused: {w}"),
            IdentityError::NotEnoughToIdentify => {
                write!(f, "the board reports too little to tell one unit from another")
            }
            IdentityError::Rot(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// What the chip reports about itself, when the firmware on it says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipIds {
    pub device_id: [u8; 8],
    pub device_addr: [u8; 6],
}

fn plain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Build the fingerprint of one unit. The USB serial is mandatory because it is
/// the one identifier every transport can read; the chip ids add anchors where
/// the firmware reports them.
pub fn fingerprint_of(usb_serial: &str, chip: Option<ChipIds>) -> Result<Fingerprint, IdentityError> {
    if !plain(usb_serial) {
        return Err(IdentityError::BadIdentifier("USB serial must be 1 to 64 of A-Z a-z 0-9 _ - ."));
    }
    let mut fp = Fingerprint::default()
        .with(Characteristic::BoardRevision, MODEL)
        .with(Characteristic::BoardSerial, usb_serial);
    if let Some(c) = chip {
        fp = fp
            .with(Characteristic::SocSerial, hex::encode(c.device_id))
            .with(
                Characteristic::MacAddress,
                c.device_addr.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"),
            );
    }
    Ok(fp)
}

/// How the identity is founded, recorded so the next tier does not infer it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBasis {
    /// Derived from readable characteristics. Names the unit-specific ones.
    Fingerprint { anchors: Vec<String> },
}

/// An enrolled sensing node.
#[derive(Clone, Debug)]
pub struct SensingNodeIdentity {
    pub node_id: NodeId,
    pub fingerprint: Fingerprint,
    pub enrollment: Enrollment,
    pub basis: IdentityBasis,
}

/// The result of comparing a unit against its enrolment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Same characteristics as enrolled. This is continuity, not proof.
    Continuous,
    /// A replaceable characteristic changed; operation may continue.
    PeripheralChanged(Vec<String>),
    /// An immutable characteristic changed: another unit, or something
    /// answering in its place. Needs an operator.
    HardwareChanged(Vec<String>),
}

impl Standing {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Standing::Continuous | Standing::PeripheralChanged(_))
    }
}

fn names(fields: &[Characteristic]) -> Vec<String> {
    fields.iter().map(|c| c.as_str().to_string()).collect()
}

/// Enrol a unit. Enrolment is the one step taken on an operator's say-so, so
/// this is called by the operator's tooling and never by the unit itself.
pub fn enrol(fingerprint: Fingerprint, name: &str, nonce: &[u8]) -> Result<SensingNodeIdentity, IdentityError> {
    let unit_anchors: Vec<String> = fingerprint
        .anchors()
        .into_iter()
        .filter(|c| !matches!(c, Characteristic::BoardRevision))
        .map(|c| c.as_str().to_string())
        .collect();
    if unit_anchors.is_empty() || !fingerprint.is_usable() {
        return Err(IdentityError::NotEnoughToIdentify);
    }
    let rot = FingerprintRot::new(fingerprint.clone());
    debug_assert_eq!(rot.assurance(), AssuranceClass::Soft);
    let evidence = rot.evidence(nonce).map_err(|e| IdentityError::Rot(e.to_string()))?;
    let enrollment = Enrollment::from_evidence(&evidence, name);
    Ok(SensingNodeIdentity {
        node_id: evidence.node_id,
        fingerprint,
        enrollment,
        basis: IdentityBasis::Fingerprint { anchors: unit_anchors },
    })
}

impl SensingNodeIdentity {
    /// The class this identity supports. Always `Soft`: see the module docs.
    pub fn assurance(&self) -> AssuranceClass {
        self.enrollment.assurance
    }

    /// Compare what a unit reports now with what was enrolled.
    pub fn check(&self, observed: &Fingerprint) -> Standing {
        let rot = FingerprintRot::new(observed.clone()).enrolled_as(self.fingerprint.clone());
        match rot.continuity() {
            Some(Continuity::Same) | None => Standing::Continuous,
            Some(Continuity::PeripheralChanged { fields }) => Standing::PeripheralChanged(names(&fields)),
            Some(Continuity::HardwareChanged { fields }) => Standing::HardwareChanged(names(&fields)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHIP: ChipIds = ChipIds { device_id: [1, 2, 3, 4, 5, 6, 7, 8], device_addr: [0xC0, 1, 2, 3, 4, 5] };

    fn enrolled() -> SensingNodeIdentity {
        enrol(fingerprint_of("SYNTH-0001", Some(CHIP)).unwrap(), "nicla-bench", b"n").unwrap()
    }

    #[test]
    fn enrolment_goes_through_the_identity_crates_and_lands_on_soft() {
        let id = enrolled();
        assert_eq!(id.assurance(), AssuranceClass::Soft);
        assert!(id.node_id.as_str().starts_with("furcate:node:"));
        assert!(!id.enrollment.endorsed);
        assert_eq!(
            id.basis,
            IdentityBasis::Fingerprint { anchors: vec!["soc_serial".into(), "board_serial".into()] }
        );
        // The same unit always derives the same identity.
        assert_eq!(id.node_id, enrolled().node_id);
    }

    #[test]
    fn a_usb_serial_alone_still_enrols_but_names_its_single_anchor() {
        let id = enrol(fingerprint_of("SYNTH-0001", None).unwrap(), "n", b"n").unwrap();
        assert_eq!(id.basis, IdentityBasis::Fingerprint { anchors: vec!["board_serial".into()] });
        assert_eq!(id.assurance(), AssuranceClass::Soft);
    }

    #[test]
    fn the_model_name_alone_identifies_nothing() {
        let fp = Fingerprint::default().with(Characteristic::BoardRevision, MODEL);
        assert_eq!(enrol(fp, "n", b"n").unwrap_err(), IdentityError::NotEnoughToIdentify);
    }

    #[test]
    fn identifiers_that_could_inject_into_an_id_are_refused() {
        for bad in ["", "a/b", "a b", "a,b"] {
            assert!(fingerprint_of(bad, None).is_err());
        }
    }

    #[test]
    fn the_same_unit_is_continuous() {
        let id = enrolled();
        assert_eq!(id.check(&fingerprint_of("SYNTH-0001", Some(CHIP)).unwrap()), Standing::Continuous);
    }

    #[test]
    fn a_swapped_unit_is_a_hardware_change() {
        let id = enrolled();
        let other = ChipIds { device_id: [9; 8], ..CHIP };
        let s = id.check(&fingerprint_of("OTHERSERIAL", Some(other)).unwrap());
        let Standing::HardwareChanged(f) = s else { panic!("{s:?}") };
        assert!(f.contains(&"soc_serial".to_string()) && f.contains(&"board_serial".to_string()));
        assert!(!Standing::HardwareChanged(f).is_acceptable());
    }

    #[test]
    fn a_new_usb_bridge_on_the_same_chip_is_still_flagged() {
        let id = enrolled();
        let s = id.check(&fingerprint_of("NEWBRIDGE", Some(CHIP)).unwrap());
        assert_eq!(s, Standing::HardwareChanged(vec!["board_serial".into()]));
    }

    #[test]
    fn a_unit_that_stops_reporting_its_chip_id_is_not_continuous() {
        let id = enrolled();
        let s = id.check(&fingerprint_of("SYNTH-0001", None).unwrap());
        assert!(matches!(s, Standing::HardwareChanged(f) if f.contains(&"soc_serial".to_string())));
    }

    /// The stated limit. Identifiers are readable, so a device that repeats
    /// them is indistinguishable from the original. The check passes and the
    /// class stays Soft, which is why nothing may rely on this identity for
    /// authentication.
    #[test]
    fn a_clone_that_repeats_the_identifiers_passes_and_that_is_the_limit() {
        let id = enrolled();
        let clone = fingerprint_of("SYNTH-0001", Some(CHIP)).unwrap();
        assert_eq!(id.check(&clone), Standing::Continuous);
        assert_eq!(id.assurance(), AssuranceClass::Soft);
    }
}
