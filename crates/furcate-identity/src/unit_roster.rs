//! Units behind a leaf: enrolling them and checking them on every session.
//!
//! A leaf can have a unit behind it that it processes and signs for: a sensing
//! module on a bus, a second board on a cable. The cascade is not fixed at
//! any number of rungs, so this module knows nothing about which rung a unit
//! sits on. It records what the operator saw when the unit was enrolled, and
//! on each later session compares what the unit presents against that.
//!
//! The comparison is the one [`crate::backends::fingerprint`] already makes
//! for a node ([`Fingerprint::compare`], [`Continuity`]); nothing here is a
//! second scheme. What this module adds is the roster, the key check for
//! units that hold a key, and refusing two live sessions for one identity.
//!
//! What a pass means depends on the unit. A unit identified only by values
//! burned into its silicon (a factory device ID, a part number) is identified
//! and not authenticated: anything that can repeat those values passes, so it
//! grades [`AssuranceClass::Soft`] however well it matches. A unit that holds
//! a key it will use but not surrender ([`LeafKeyCustody::FuseKey`]) is
//! authenticated by that key, and grades [`AssuranceClass::Device`].

use crate::backends::fingerprint::{Characteristic, Continuity, Fingerprint};
use crate::leaf::LeafKeyCustody;
use crate::rot::AssuranceClass;
use std::collections::{BTreeMap, BTreeSet};

/// What the operator recorded when the unit was enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledUnit {
    /// The unit's identifier as its parent sees it: a leaf's key hash, or the
    /// name the operator gave a unit that has no key.
    pub unit_id: String,
    pub fingerprint: Fingerprint,
    /// The unit's public key (`p256:<hex>`), when it holds one.
    pub key: Option<String>,
    /// How that key is held, when there is one.
    pub custody: Option<LeafKeyCustody>,
}

/// The result of checking a unit against its enrolment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Never enrolled. Trust on first use is the operator's decision, taken
    /// once; a session does not make it.
    NotEnrolled,
    /// The unit matches its enrolment. `class` is what the match proves.
    Verified { class: AssuranceClass },
    /// A replaceable part changed. The unit may keep working.
    PeripheralChanged { fields: Vec<Characteristic>, class: AssuranceClass },
    /// A value that never changes did: the unit was swapped or something is
    /// answering for it. Escalate to the operator; never resolve silently.
    Replaced { fields: Vec<Characteristic> },
    /// Same silicon values but a different key, or a key where there was none.
    KeyMismatch,
    /// The identity already has a live session. One of the two is a copy.
    DuplicateSession,
}

impl Verdict {
    /// Whether the session may go ahead.
    pub fn admits(&self) -> bool {
        matches!(self, Verdict::Verified { .. } | Verdict::PeripheralChanged { .. })
    }
}

#[derive(Default)]
pub struct UnitRoster {
    units: BTreeMap<String, EnrolledUnit>,
    live: BTreeSet<String>,
}

impl UnitRoster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a unit. Refuses a fingerprint that rests on too few hardware
    /// anchors to identify anything, and an id that is already enrolled
    /// (replacing one is a re-enrolment the operator does on purpose, with
    /// [`UnitRoster::forget`] first).
    pub fn enrol(&mut self, unit: EnrolledUnit) -> Result<(), String> {
        if !unit.fingerprint.is_usable() {
            return Err(format!(
                "unit `{}` rests on {} hardware anchors, need {}",
                unit.unit_id,
                unit.fingerprint.anchors().len(),
                Fingerprint::MIN_ANCHORS
            ));
        }
        if unit.key.is_some() != unit.custody.is_some() {
            return Err(format!("unit `{}`: a key and how it is held go together", unit.unit_id));
        }
        if self.units.contains_key(&unit.unit_id) {
            return Err(format!("unit `{}` is already enrolled; forget it first to enrol it again", unit.unit_id));
        }
        self.units.insert(unit.unit_id.clone(), unit);
        Ok(())
    }

    pub fn forget(&mut self, unit_id: &str) -> bool {
        self.live.remove(unit_id);
        self.units.remove(unit_id).is_some()
    }

    /// Check what a unit presents at the start of a session. A passing unit
    /// is marked live until [`UnitRoster::end_session`].
    pub fn verify(&mut self, unit_id: &str, presented: &Fingerprint, key: Option<&str>) -> Verdict {
        let Some(enrolled) = self.units.get(unit_id) else {
            return Verdict::NotEnrolled;
        };
        if self.live.contains(unit_id) {
            return Verdict::DuplicateSession;
        }
        let class = match (&enrolled.key, &enrolled.custody) {
            (Some(_), Some(c)) => c.class(),
            _ => AssuranceClass::Soft,
        };
        let continuity = presented.compare(&enrolled.fingerprint);
        if let Continuity::HardwareChanged { fields } = continuity {
            return Verdict::Replaced { fields };
        }
        if enrolled.key.as_deref() != key {
            return Verdict::KeyMismatch;
        }
        self.live.insert(unit_id.to_string());
        match continuity {
            Continuity::PeripheralChanged { fields } => Verdict::PeripheralChanged { fields, class },
            _ => Verdict::Verified { class },
        }
    }

    pub fn end_session(&mut self, unit_id: &str) {
        self.live.remove(unit_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::Lockdown;

    /// What the S3 reports in its evidence: unique ID, MAC, flash ID, part.
    fn s3(uid: &str) -> Fingerprint {
        Fingerprint::default()
            .with(Characteristic::SocSerial, format!("esp32s3-{uid}"))
            .with(Characteristic::MacAddress, "00:00:5e:00:53:01")
            .with(Characteristic::FlashId, "c84017")
            .with(Characteristic::BoardRevision, "esp32s3-v0.2")
    }

    /// A sensing module known only by values burned into its silicon.
    fn module(device_id: &str) -> Fingerprint {
        Fingerprint::default()
            .with(Characteristic::SocSerial, format!("nrf52832-{device_id}"))
            .with(Characteristic::BoardRevision, "nrf52832-QFAA-E1")
    }

    fn micro(uid: &str, custody: LeafKeyCustody) -> EnrolledUnit {
        EnrolledUnit {
            unit_id: "6f01a05cb51e53f79e31b55d89fa2f2e".into(),
            fingerprint: s3(uid),
            key: Some("p256:02aa".into()),
            custody: Some(custody),
        }
    }

    fn sensing(id: &str) -> EnrolledUnit {
        EnrolledUnit { unit_id: "nicla-1".into(), fingerprint: module(id), key: None, custody: None }
    }

    #[test]
    fn an_unenrolled_unit_is_left_to_the_operator() {
        let mut r = UnitRoster::new();
        let v = r.verify("nicla-1", &module("a1b2"), None);
        assert_eq!(v, Verdict::NotEnrolled);
        assert!(!v.admits());
    }

    #[test]
    fn an_enrolled_unit_verifies_and_a_readable_one_is_only_soft() {
        let mut r = UnitRoster::new();
        r.enrol(sensing("a1b2")).unwrap();
        assert_eq!(
            r.verify("nicla-1", &module("a1b2"), None),
            Verdict::Verified { class: AssuranceClass::Soft }
        );
    }

    #[test]
    fn the_micro_node_on_readable_identifiers_is_soft_and_with_a_fuse_key_is_device() {
        let mut r = UnitRoster::new();
        let mut open = micro("b58651c2", LeafKeyCustody::ReadableIdentifiers);
        open.unit_id = "open".into();
        r.enrol(open).unwrap();
        r.enrol(micro("b58651c2", LeafKeyCustody::FuseKey { lockdown: Lockdown::default() })).unwrap();
        assert_eq!(
            r.verify("open", &s3("b58651c2"), Some("p256:02aa")),
            Verdict::Verified { class: AssuranceClass::Soft }
        );
        assert_eq!(
            r.verify("6f01a05cb51e53f79e31b55d89fa2f2e", &s3("b58651c2"), Some("p256:02aa")),
            Verdict::Verified { class: AssuranceClass::Device }
        );
    }

    #[test]
    fn a_swapped_unit_is_replaced_and_needs_the_operator() {
        let mut r = UnitRoster::new();
        r.enrol(sensing("a1b2")).unwrap();
        match r.verify("nicla-1", &module("ffff"), None) {
            Verdict::Replaced { fields } => assert!(fields.contains(&Characteristic::SocSerial)),
            other => panic!("expected Replaced, got {other:?}"),
        }
        // A swapped unit does not become live.
        assert!(r.live.is_empty());
    }

    #[test]
    fn a_cloned_id_with_another_key_is_refused() {
        let mut r = UnitRoster::new();
        r.enrol(micro("b58651c2", LeafKeyCustody::ReadableIdentifiers)).unwrap();
        // Same silicon values replayed, but the key is not the enrolled one.
        let v = r.verify("6f01a05cb51e53f79e31b55d89fa2f2e", &s3("b58651c2"), Some("p256:02bb"));
        assert_eq!(v, Verdict::KeyMismatch);
        // And no key at all where one was enrolled.
        assert_eq!(r.verify("6f01a05cb51e53f79e31b55d89fa2f2e", &s3("b58651c2"), None), Verdict::KeyMismatch);
    }

    #[test]
    fn a_second_live_session_for_one_identity_is_a_duplicate() {
        let mut r = UnitRoster::new();
        r.enrol(sensing("a1b2")).unwrap();
        assert!(r.verify("nicla-1", &module("a1b2"), None).admits());
        // The same identity again while the first is up: one of them is a copy.
        assert_eq!(r.verify("nicla-1", &module("a1b2"), None), Verdict::DuplicateSession);
        r.end_session("nicla-1");
        assert!(r.verify("nicla-1", &module("a1b2"), None).admits());
    }

    #[test]
    fn a_replaceable_part_changing_does_not_stop_the_unit() {
        let mut r = UnitRoster::new();
        let mut u = sensing("a1b2");
        u.fingerprint = u.fingerprint.with(Characteristic::DiskWwn, "card-1");
        r.enrol(u).unwrap();
        let now = module("a1b2").with(Characteristic::DiskWwn, "card-2");
        let v = r.verify("nicla-1", &now, None);
        assert!(matches!(v, Verdict::PeripheralChanged { .. }));
        assert!(v.admits());
    }

    #[test]
    fn enrolment_refuses_what_identifies_nothing() {
        let mut r = UnitRoster::new();
        let weak = Fingerprint::default().with(Characteristic::MacAddress, "00:00:5e:00:53:01");
        let e = r
            .enrol(EnrolledUnit { unit_id: "x".into(), fingerprint: weak, key: None, custody: None })
            .unwrap_err();
        assert!(e.contains("hardware anchors"));
        // A key with no statement of how it is held is not enrolled either.
        let mut u = sensing("a1b2");
        u.key = Some("p256:02aa".into());
        assert!(r.enrol(u).is_err());
        // Enrolling twice needs a deliberate forget.
        r.enrol(sensing("a1b2")).unwrap();
        assert!(r.enrol(sensing("a1b2")).is_err());
        assert!(r.forget("nicla-1"));
        r.enrol(sensing("c3d4")).unwrap();
    }
}
