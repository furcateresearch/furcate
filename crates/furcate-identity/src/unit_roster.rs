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
use crate::suite::{KeySuite, SuiteKey};
use std::collections::{BTreeMap, BTreeSet};

/// What the operator recorded when the unit was enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledUnit {
    /// The unit's identifier as its parent sees it: a leaf's key hash, or the
    /// name the operator gave a unit that has no key.
    pub unit_id: String,
    pub fingerprint: Fingerprint,
    /// The unit's public key with its suite (`p256:<hex>` or `ed25519:<hex>`),
    /// when it holds one. The suite is the key's prefix and nothing else
    /// decides it ([`SuiteKey`]); a key written without one is refused.
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
    /// Identities that rolled over to a successor: old unit id -> (last
    /// accepted sequence, successor unit id). An old id stays retired.
    rolled: BTreeMap<String, (u32, String)>,
}

impl UnitRoster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a unit. Refuses a fingerprint that rests on too few hardware
    /// anchors to identify anything, and an id that is already enrolled
    /// (replacing one is a re-enrolment the operator does on purpose, with
    /// [`UnitRoster::forget`] first).
    pub fn enrol(&mut self, mut unit: EnrolledUnit) -> Result<(), String> {
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
        // The key is kept in the one spelling a key has, so a later session
        // that presents the same key written another way still matches it.
        if let Some(k) = unit.key.as_mut() {
            *k = SuiteKey::parse(k).map_err(|e| format!("unit `{}`: key: {e}", unit.unit_id))?.id();
        }
        if self.units.contains_key(&unit.unit_id) {
            return Err(format!("unit `{}` is already enrolled; forget it first to enrol it again", unit.unit_id));
        }
        self.units.insert(unit.unit_id.clone(), unit);
        Ok(())
    }

    /// Accept an identity rollover record (see [`crate::unit_rollover`]): the
    /// old identity, the new key and the operator all signed, so the unit moves
    /// to its new id without being orphaned. Returns the successor unit id.
    ///
    /// The old unit must be enrolled and have no live session. The level the
    /// roster holds for it comes from how its key is held. `proven_new_level`
    /// is what the successor proved in live, verified evidence (the level of
    /// its reported assurance); the caller takes it from that evidence, never
    /// from the record. On success the old id is retired for good, the
    /// successor is enrolled with the same silicon fingerprint and a fuse-held
    /// key, and the old id maps to it.
    pub fn accept_rollover(
        &mut self,
        record: &[u8],
        now: u64,
        proven_new_level: u8,
        operator_pubs: &[Vec<u8>],
        require_operator: bool,
    ) -> Result<String, String> {
        if record.len() < 134 {
            return Err("malformed record".into());
        }
        let old_hex = hex::encode(crate::unit_rollover::leaf_id(&record[4..69]));
        // A unit id may be the full key hash or its 16-byte prefix.
        let old_key = [old_hex.clone(), old_hex[..32].to_string()]
            .into_iter()
            .find(|k| self.units.contains_key(k))
            .ok_or_else(|| {
                if self.rolled.contains_key(&old_hex[..32]) || self.rolled.contains_key(&old_hex) {
                    "already rolled over: the old identity is retired".to_string()
                } else {
                    "old key is not the roster leaf".to_string()
                }
            })?;
        if self.live.contains(&old_key) {
            return Err("the old identity has a live session; end it first".into());
        }
        let old = self.units[&old_key].clone();
        let roster_old_level = match &old.custody {
            Some(LeafKeyCustody::Stored) | Some(LeafKeyCustody::ReadableIdentifiers) | None => 1,
            Some(LeafKeyCustody::SramFingerprint { .. }) => 2,
            Some(LeafKeyCustody::FuseKey { .. }) => 3,
        };
        let mut known: Vec<[u8; 32]> = Vec::new();
        let new_hex = hex::encode(crate::unit_rollover::leaf_id(&record[69..134]));
        for id in self.units.keys().filter(|k| **k != old_key) {
            if let Ok(b) = hex::decode(id) {
                if let Ok(a) = <[u8; 32]>::try_from(b.as_slice()) {
                    known.push(a);
                } else if b.len() == 16 && new_hex.starts_with(id.as_str()) {
                    return Err("successor is another leaf".into());
                }
            }
        }
        let old_id: [u8; 32] = hex::decode(&old_hex).expect("hex").try_into().expect("32 bytes");
        let policy = crate::unit_rollover::Policy {
            now,
            old_id,
            roster_old_level,
            proven_new_level,
            last_seq: self.rolled.get(&old_key).map(|r| r.0).unwrap_or(0),
            old_retired: false,
            retired_successor_id: [0; 32],
            known_ids: &known,
            operator_pubs,
            require_operator,
        };
        let ok = crate::unit_rollover::verify(record, &policy).map_err(|e| e.to_string())?;
        let new_full = hex::encode(ok.new_id());
        let new_id = if old_key.len() == 32 { new_full[..32].to_string() } else { new_full };
        let key = SuiteKey::parse(&format!("p256:{}", hex::encode(&ok.new_pub))).map_err(|e| e.to_string())?.id();
        let successor = EnrolledUnit {
            unit_id: new_id.clone(),
            fingerprint: old.fingerprint.clone(),
            key: Some(key),
            custody: Some(LeafKeyCustody::FuseKey { lockdown: Default::default() }),
        };
        self.units.remove(&old_key);
        self.units.insert(new_id.clone(), successor);
        self.rolled.insert(old_key, (ok.seq, new_id.clone()));
        Ok(new_id)
    }

    /// Record that `old_unit_id` rolled over to `successor` at `seq`, as a roster loaded from the operator's file
    /// is told what earlier rollovers happened. The old identity stays retired and the highest accepted sequence is
    /// kept, so an old record cannot be played again.
    pub fn retire(&mut self, old_unit_id: &str, seq: u32, successor: &str) -> Result<(), String> {
        if self.units.contains_key(old_unit_id) {
            return Err(format!("unit `{old_unit_id}` is retired in the same file that enrols it"));
        }
        if !self.units.contains_key(successor) {
            return Err(format!("the successor `{successor}` of `{old_unit_id}` is not enrolled"));
        }
        self.rolled.insert(old_unit_id.to_string(), (seq, successor.to_string()));
        Ok(())
    }

    /// The unit id a retired identity rolled over to, if it did.
    pub fn successor_of(&self, old_unit_id: &str) -> Option<&str> {
        self.rolled.get(old_unit_id).map(|r| r.1.as_str())
    }

    /// The suite a unit's enrolled key signs under, when it has a key.
    pub fn suite_of(&self, unit_id: &str) -> Option<KeySuite> {
        let k = self.units.get(unit_id)?.key.as_deref()?;
        SuiteKey::parse(k).ok().map(|k| k.suite())
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
        // The enrolled key decides; the presented one must be the same key in
        // the same suite. A key that does not parse, or has no suite, is not it.
        let presented_key = key.map(|k| SuiteKey::parse(k).map(|k| k.id()));
        match (&enrolled.key, presented_key) {
            (None, None) => {}
            (Some(want), Some(Ok(got))) if *want == got => {}
            _ => return Verdict::KeyMismatch,
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

    /// Two P-256 keys (private scalars 7 and 8) and an Ed25519 key.
    const KEY_A: &str = "p256:031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e";
    const KEY_A_UNCOMPRESSED: &str = "p256:041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3";
    const KEY_ED: &str = "ed25519:ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    /// Another valid P-256 key: the generator point.
    fn key_b() -> &'static str {
        "p256:036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    }

    fn micro(uid: &str, custody: LeafKeyCustody) -> EnrolledUnit {
        EnrolledUnit {
            unit_id: "6f01a05cb51e53f79e31b55d89fa2f2e".into(),
            fingerprint: s3(uid),
            key: Some(KEY_A.into()),
            custody: Some(custody),
        }
    }

    fn sensing(id: &str) -> EnrolledUnit {
        EnrolledUnit { unit_id: "nicla-1".into(), fingerprint: module(id), key: None, custody: None }
    }

    #[test]
    fn a_rollover_moves_the_leaf_to_its_new_id_and_retires_the_old_one() {
        // The first accepted vector of the leaf firmware repository.
        let line = include_str!("../tests/identity-vectors.txt")
            .lines()
            .find(|l| l.starts_with("rollover ok-basic "))
            .unwrap();
        let f: std::collections::HashMap<&str, &str> = line.split_whitespace().filter_map(|x| x.split_once('=')).collect();
        let rec = hex::decode(f["rec"]).unwrap();
        let ops = vec![hex::decode(f["ops"]).unwrap()];
        let now: u64 = f["now"].parse().unwrap();
        let old_hex = f["old_id"];
        let mut r = UnitRoster::new();
        let mut u = micro("b58651c2", LeafKeyCustody::ReadableIdentifiers);
        u.unit_id = old_hex.into();
        u.key = Some(format!("p256:{}", hex::encode(&rec[4..69])));
        r.enrol(u).unwrap();
        // A wrong operator key is refused and changes nothing.
        let bad = vec![ops[0].iter().map(|b| b ^ 1).collect::<Vec<u8>>()];
        assert!(r.accept_rollover(&rec, now, 3, &bad, true).is_err());
        assert!(r.units.contains_key(old_hex));
        // Overclaiming the successor level is refused.
        assert_eq!(r.accept_rollover(&rec, now, 1, &ops, true).unwrap_err(), "successor level exceeds proven");
        let new_id = r.accept_rollover(&rec, now, 3, &ops, true).unwrap();
        assert!(!r.units.contains_key(old_hex));
        assert_eq!(r.successor_of(old_hex), Some(new_id.as_str()));
        assert_eq!(r.suite_of(&new_id), Some(KeySuite::P256));
        // The same record again: the old identity is retired for good.
        assert!(r.accept_rollover(&rec, now, 3, &ops, true).unwrap_err().contains("retired"));
        // The successor verifies as a device-class unit with its own key.
        let key = format!("p256:{}", hex::encode(&rec[69..134]));
        assert_eq!(
            r.verify(&new_id, &s3("b58651c2"), Some(&key)),
            Verdict::Verified { class: AssuranceClass::Device }
        );
    }

    /// The record the real ESP32-S3 leaf produced on 2026-10-30 after the HMAC
    /// burn (old id 6f01a05c..., new id a0e12851...), operator-signed in the
    /// operator's Secure Enclave key. Public data only.
    #[test]
    fn the_real_s3_rollover_record_is_accepted_for_the_enrolled_s3_leaf() {
        let rec = hex::decode(include_str!("../tests/s3-rollover-6f01a05c-to-a0e12851.hex").trim()).unwrap();
        let op = hex::decode(include_str!("../tests/s3-operator-pub.hex").trim()).unwrap();
        let not_before = u64::from_be_bytes(rec[138..146].try_into().unwrap());
        let mut r = UnitRoster::new();
        let mut u = micro("b58651c2", LeafKeyCustody::ReadableIdentifiers);
        u.key = Some(format!("p256:{}", hex::encode(&rec[4..69])));
        r.enrol(u).unwrap(); // unit id 6f01a05cb51e53f79e31b55d89fa2f2e, the 16-byte form
        let new_id = r.accept_rollover(&rec, not_before + 60, 3, &[op], true).unwrap();
        assert_eq!(new_id, "a0e1285173b50bd77c78c9c41f15889c");
        assert_eq!(r.successor_of("6f01a05cb51e53f79e31b55d89fa2f2e"), Some(new_id.as_str()));
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
            r.verify("open", &s3("b58651c2"), Some(KEY_A)),
            Verdict::Verified { class: AssuranceClass::Soft }
        );
        assert_eq!(
            r.verify("6f01a05cb51e53f79e31b55d89fa2f2e", &s3("b58651c2"), Some(KEY_A)),
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
        let v = r.verify("6f01a05cb51e53f79e31b55d89fa2f2e", &s3("b58651c2"), Some(key_b()));
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
        u.key = Some(KEY_A.into());
        assert!(r.enrol(u).is_err());
        // Enrolling twice needs a deliberate forget.
        r.enrol(sensing("a1b2")).unwrap();
        assert!(r.enrol(sensing("a1b2")).is_err());
        assert!(r.forget("nicla-1"));
        r.enrol(sensing("c3d4")).unwrap();
    }

    #[test]
    fn a_unit_key_is_enrolled_only_with_a_suite_and_a_real_key() {
        for bad in ["p256:02aa", "02aa", "ed25519:00", "rsa:00", KEY_ED.trim_start_matches("ed25519:")] {
            let mut u = micro("b58651c2", LeafKeyCustody::ReadableIdentifiers);
            u.key = Some(bad.into());
            let e = UnitRoster::new().enrol(u).unwrap_err();
            assert!(e.contains("key:"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_unit_may_hold_a_key_of_either_suite_and_the_suite_is_the_enrolled_keys() {
        let mut r = UnitRoster::new();
        let mut p = micro("b58651c2", LeafKeyCustody::FuseKey { lockdown: Lockdown::default() });
        p.unit_id = "p".into();
        r.enrol(p).unwrap();
        let mut e = micro("b58651c2", LeafKeyCustody::FuseKey { lockdown: Lockdown::default() });
        e.unit_id = "e".into();
        e.key = Some(KEY_ED.into());
        r.enrol(e).unwrap();
        assert_eq!(r.suite_of("p"), Some(KeySuite::P256));
        assert_eq!(r.suite_of("e"), Some(KeySuite::Ed25519));
        assert_eq!(r.suite_of("nobody"), None);
        assert!(r.verify("p", &s3("b58651c2"), Some(KEY_A)).admits());
        assert!(r.verify("e", &s3("b58651c2"), Some(KEY_ED)).admits());
    }

    #[test]
    fn the_same_key_written_another_way_matches_and_another_suite_does_not() {
        let mut r = UnitRoster::new();
        r.enrol(micro("b58651c2", LeafKeyCustody::ReadableIdentifiers)).unwrap();
        let id = "6f01a05cb51e53f79e31b55d89fa2f2e";
        // The uncompressed spelling of the enrolled key is that key.
        assert!(r.verify(id, &s3("b58651c2"), Some(KEY_A_UNCOMPRESSED)).admits());
        r.end_session(id);
        // A key of the other suite, a key with no suite, and a key that is not
        // a key are all mismatches, never an error and never a pass.
        for presented in [KEY_ED, KEY_A.trim_start_matches("p256:"), "p256:02aa", "", "ed25519:"] {
            assert_eq!(r.verify(id, &s3("b58651c2"), Some(presented)), Verdict::KeyMismatch, "{presented:?}");
        }
    }
}
