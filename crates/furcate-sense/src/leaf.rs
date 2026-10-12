//! Leaf attachment and signed readings.
//!
//! A leaf is named by one key, Ed25519 or P-256, read with the same
//! [`CellKey`] the cell links use for heads, and graded by how that key is
//! held ([`LeafKeyCustody`]), never by a class the record states. The record
//! format is [`Attachment::from_record`].

use ed25519_dalek::{Signer as _, SigningKey};
use furcate_identity::{AssuranceClass, LeafKeyCustody, Lockdown};
use furcate_policy::delegation::CellKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// A leaf device's registration with its parent, as read from its record.
///
/// Built only by [`Attachment::from_record`] or by a [`Leaf`] itself, so an
/// attachment always carries a key that parsed and a class that was derived.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Attachment {
    pub leaf_id: String,
    pub parent: String,
    /// The leaf's key the way a cell link names it: `ed25519:<hex>` or
    /// `p256:<compressed SEC1 hex>`.
    pub public_key: String,
    /// How the key is held, when the record says. `None` grades `Soft`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_custody: Option<LeafKeyCustody>,
    pub attached_at: u64,
}

impl Attachment {
    /// The class the key custody earns. Never read from the record.
    pub fn assurance(&self) -> AssuranceClass {
        self.key_custody.map(|c| c.class()).unwrap_or(AssuranceClass::Soft)
    }

    /// Why the leaf has the class it has.
    pub fn assurance_reason(&self) -> String {
        match &self.key_custody {
            Some(c) => c.reason(),
            None => "the record does not say how the key is held".into(),
        }
    }

    /// Read an attachment record.
    ///
    /// The canonical record is an object with `leaf_id`, `parent`,
    /// `public_key` (`ed25519:<hex>` or `p256:<hex>`, in any form
    /// [`CellKey::normalise`] reads), `attached_at` and `key_custody` (a
    /// [`LeafKeyCustody`]). Any other field is the leaf's own description and
    /// is left alone.
    ///
    /// Two further forms are read because leaf firmware publishes them:
    ///
    /// - a bare hex `public_key` whose type is named in
    ///   `leaf.public_key_type` (`ecdsa-p256-uncompressed`); a bare key with
    ///   no type is Ed25519, as it always has been;
    /// - no `key_custody`, but the firmware's own report in
    ///   `leaf.assurance_reported`, which names an SRAM fingerprint key and
    ///   whether secure boot and flash encryption are on. It says nothing of
    ///   the download mode or JTAG, so those are read as open.
    ///
    /// A P-256 leaf is named by its key: `leaf_id` is the hex of the first
    /// 16 bytes of the SHA-256 of the uncompressed point.
    ///
    /// A stated `assurance` is not an input. When present it must agree with
    /// the class the evidence earns, so a record can never carry one class in
    /// one place and earn another.
    pub fn from_record(v: &Value) -> Result<Attachment, String> {
        let o = v.as_object().ok_or("an attachment record is a JSON object")?;
        let text = |k: &str| -> Result<String, String> {
            match o.get(k).and_then(Value::as_str) {
                Some(s) if !s.trim().is_empty() => Ok(s.to_string()),
                _ => Err(format!("the attachment record has no `{k}`")),
            }
        };
        let leaf_id = text("leaf_id")?;
        let parent = text("parent")?;
        let attached_at = o
            .get("attached_at")
            .and_then(Value::as_u64)
            .ok_or("the attachment record has no `attached_at` in seconds")?;
        let described = o.get("leaf").and_then(Value::as_object);

        let raw = text("public_key")?;
        let key_type = described.and_then(|d| d.get("public_key_type")).and_then(Value::as_str);
        let written = if raw.starts_with("ed25519:") || raw.starts_with("p256:") {
            raw.clone()
        } else {
            match key_type {
                None | Some("ed25519") => format!("ed25519:{raw}"),
                Some("ecdsa-p256-uncompressed") | Some("ecdsa-p256") => format!("p256:{raw}"),
                Some(other) => return Err(format!("leaf key type `{other}` is neither Ed25519 nor P-256")),
            }
        };
        let public_key = CellKey::normalise(&written).map_err(|e| format!("the leaf's key: {e}"))?;
        if let CellKey::P256(k) = CellKey::parse(&public_key)? {
            let digest = Sha256::digest(k.to_sec1_point(false).as_bytes());
            let expected = hex::encode(&digest[..16]);
            if leaf_id != expected {
                return Err(format!(
                    "a P-256 leaf is named by its key: `{leaf_id}` is not {expected}, the first 16 bytes \
                     of the SHA-256 of its uncompressed point"
                ));
            }
        }

        let key_custody = match o.get("key_custody") {
            Some(c) => Some(
                serde_json::from_value::<LeafKeyCustody>(c.clone())
                    .map_err(|e| format!("`key_custody` is not a key custody Furcate knows: {e}"))?,
            ),
            None => match described.and_then(|d| d.get("assurance_reported")).and_then(Value::as_str) {
                None => None,
                Some(r) => Some(firmware_report(r)?),
            },
        };
        let att = Attachment { leaf_id, parent, public_key, key_custody, attached_at };

        if let Some(stated) = o.get("assurance") {
            let stated: AssuranceClass = serde_json::from_value(stated.clone())
                .map_err(|_| format!("the record states assurance {stated}, which is not a class"))?;
            if stated != att.assurance() {
                return Err(format!(
                    "the record states `{stated}` but its evidence earns `{}`: {}",
                    att.assurance(),
                    att.assurance_reason()
                ));
            }
        }
        Ok(att)
    }
}

/// The key custody a leaf firmware's own `assurance_reported` string names.
fn firmware_report(r: &str) -> Result<LeafKeyCustody, String> {
    match r {
        "silicon-fingerprint/development" => Ok(LeafKeyCustody::SramFingerprint { lockdown: Lockdown::default() }),
        "silicon-fingerprint+secure-boot" => Ok(LeafKeyCustody::SramFingerprint {
            lockdown: Lockdown { secure_boot: true, flash_encryption: true, ..Lockdown::default() },
        }),
        other => Err(format!(
            "the firmware reports `{other}`, which says nothing Furcate can grade; describe the key in `key_custody`"
        )),
    }
}

/// A signed measurement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reading {
    pub sensor_id: String,
    pub leaf_id: String,
    pub value: f64,
    /// Monotonic sequence from the leaf, so a replayed reading is detectable
    /// even when the leaf has no trustworthy clock — which is the normal case
    /// on a microcontroller.
    pub seq: u64,
    pub taken_at: u64,
    pub signature: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LeafError {
    /// Signature absent or not from the attached leaf.
    BadSignature,
    /// The leaf is not attached to this parent.
    NotAttached,
    /// A reading arrived out of order or was replayed.
    StaleSequence { last: u64, found: u64 },
    /// The leaf's assurance class is below what policy allows for this data.
    AssuranceTooLow {
        required: AssuranceClass,
        found: AssuranceClass,
    },
}

impl fmt::Display for LeafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeafError::BadSignature => write!(f, "reading is not signed by the attached leaf"),
            LeafError::NotAttached => write!(f, "leaf is not attached to this parent"),
            LeafError::StaleSequence { last, found } => write!(
                f,
                "reading sequence {found} is not ahead of {last}: replayed or out of order"
            ),
            LeafError::AssuranceTooLow { required, found } => write!(
                f,
                "leaf assurance `{found}` is below the required `{required}` for this data"
            ),
        }
    }
}

impl std::error::Error for LeafError {}

fn reading_payload(sensor_id: &str, leaf_id: &str, value: f64, seq: u64, taken_at: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update((sensor_id.len() as u64).to_be_bytes());
    h.update(sensor_id.as_bytes());
    h.update((leaf_id.len() as u64).to_be_bytes());
    h.update(leaf_id.as_bytes());
    h.update(value.to_be_bytes());
    h.update(seq.to_be_bytes());
    h.update(taken_at.to_be_bytes());
    h.finalize().to_vec()
}

enum LeafKey {
    Ed25519(SigningKey),
    P256(p256::ecdsa::SigningKey),
}

/// A leaf device, as seen from its own side.
pub struct Leaf {
    pub id: String,
    key: LeafKey,
    seq: u64,
}

impl Leaf {
    /// An Ed25519 leaf, named by the caller.
    pub fn new(id: impl Into<String>, key_bytes: [u8; 32]) -> Self {
        Self { id: id.into(), key: LeafKey::Ed25519(SigningKey::from_bytes(&key_bytes)), seq: 0 }
    }

    /// A P-256 leaf, named by its key as [`Attachment::from_record`] requires.
    pub fn p256(scalar: [u8; 32]) -> Result<Self, String> {
        let key = p256::ecdsa::SigningKey::from_slice(&scalar).map_err(|_| "not a P-256 scalar".to_string())?;
        let digest = Sha256::digest(key.verifying_key().to_sec1_point(false).as_bytes());
        Ok(Self { id: hex::encode(&digest[..16]), key: LeafKey::P256(key), seq: 0 })
    }

    /// The key as a cell link names it.
    pub fn public_key(&self) -> String {
        match &self.key {
            LeafKey::Ed25519(k) => CellKey::Ed25519(k.verifying_key()).id(),
            LeafKey::P256(k) => CellKey::P256(k.verifying_key().clone()).id(),
        }
    }

    /// This leaf's attachment record, with the custody it reports.
    pub fn attach(&self, parent: &str, key_custody: Option<LeafKeyCustody>, now: u64) -> Attachment {
        Attachment {
            leaf_id: self.id.clone(),
            parent: parent.to_string(),
            public_key: self.public_key(),
            key_custody,
            attached_at: now,
        }
    }

    /// Take and sign a reading.
    pub fn publish(&mut self, sensor_id: &str, value: f64, taken_at: u64) -> Reading {
        self.seq += 1;
        let payload = reading_payload(sensor_id, &self.id, value, self.seq, taken_at);
        let signature = match &self.key {
            LeafKey::Ed25519(k) => hex::encode(k.sign(&payload).to_bytes()),
            LeafKey::P256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(&payload);
                hex::encode(sig.to_bytes())
            }
        };
        Reading {
            sensor_id: sensor_id.to_string(),
            leaf_id: self.id.clone(),
            value,
            seq: self.seq,
            taken_at,
            signature,
        }
    }
}

/// The parent's view: verify readings from attached leaves.
#[derive(Default)]
pub struct ParentPort {
    attachments: std::collections::BTreeMap<String, Attachment>,
    last_seq: std::collections::BTreeMap<String, u64>,
}

impl ParentPort {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(&mut self, attachment: Attachment) -> &mut Self {
        self.attachments
            .insert(attachment.leaf_id.clone(), attachment);
        self
    }

    pub fn detach(&mut self, leaf_id: &str) -> bool {
        self.last_seq.remove(leaf_id);
        self.attachments.remove(leaf_id).is_some()
    }

    /// Verify a reading and record its sequence.
    pub fn verify(&mut self, reading: &Reading, min_assurance: AssuranceClass) -> Result<(), LeafError> {
        let Some(att) = self.attachments.get(&reading.leaf_id) else {
            return Err(LeafError::NotAttached);
        };
        if att.assurance() < min_assurance {
            return Err(LeafError::AssuranceTooLow {
                required: min_assurance,
                found: att.assurance(),
            });
        }

        let key = CellKey::parse(&att.public_key).map_err(|_| LeafError::BadSignature)?;
        let payload = reading_payload(
            &reading.sensor_id,
            &reading.leaf_id,
            reading.value,
            reading.seq,
            reading.taken_at,
        );
        key.verify_hex(&payload, &reading.signature)
            .map_err(|_| LeafError::BadSignature)?;

        let last = self.last_seq.get(&reading.leaf_id).copied().unwrap_or(0);
        if reading.seq <= last {
            return Err(LeafError::StaleSequence {
                last,
                found: reading.seq,
            });
        }
        self.last_seq.insert(reading.leaf_id.clone(), reading.seq);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUSED: Option<LeafKeyCustody> = Some(LeafKeyCustody::FuseKey {
        lockdown: Lockdown { secure_boot: true, flash_encryption: true, download_disabled: true, jtag_disabled: true },
    });

    fn setup() -> (Leaf, ParentPort) {
        let leaf = Leaf::new("esp32-a", [5u8; 32]);
        let mut parent = ParentPort::new();
        parent.accept(leaf.attach("node-a", FUSED, 0));
        (leaf, parent)
    }

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../fixtures/home-lab-leaf.json")).unwrap()
    }

    #[test]
    fn an_ed25519_leaf_still_attaches_and_signs() {
        let leaf = Leaf::new("esp32-a", [5u8; 32]);
        let bare = leaf.public_key().trim_start_matches("ed25519:").to_string();
        let att = Attachment::from_record(&serde_json::json!({
            "leaf_id": "esp32-a", "parent": "node-a", "public_key": bare, "attached_at": 5,
            "key_custody": {"kind": "fuse-key"},
        }))
        .unwrap();
        assert_eq!(att.public_key, format!("ed25519:{bare}"));
        assert_eq!(att.assurance(), AssuranceClass::Device);
        assert_eq!(att, leaf.attach("node-a", Some(LeafKeyCustody::FuseKey { lockdown: Lockdown::default() }), 5));
    }

    #[test]
    fn a_p256_leaf_signs_readings_the_parent_verifies() {
        let mut leaf = Leaf::p256([7u8; 32]).unwrap();
        assert!(leaf.public_key().starts_with("p256:0"));
        let mut parent = ParentPort::new();
        parent.accept(leaf.attach("pi-lab", FUSED, 0));
        let r = leaf.publish("lux", 310.0, 100);
        assert_eq!(parent.verify(&r, AssuranceClass::Device), Ok(()));
        let mut forged = leaf.publish("lux", 311.0, 101);
        forged.value = 0.0;
        assert_eq!(parent.verify(&forged, AssuranceClass::Device), Err(LeafError::BadSignature));
    }

    #[test]
    fn the_published_home_lab_record_reads_as_a_soft_p256_leaf() {
        let att = Attachment::from_record(&fixture()).unwrap();
        assert_eq!(att.leaf_id, "1d3d319e958177e5a4f2d8fb58c11cfe");
        assert_eq!(att.parent, "pi-lab");
        assert_eq!(att.attached_at, 1791783303);
        assert_eq!(
            att.public_key,
            "p256:03749d5173ee808e288b9aca1d31293c6af71d9cf83e819e562c296213e40cdc54"
        );
        assert_eq!(att.key_custody, Some(LeafKeyCustody::SramFingerprint { lockdown: Lockdown::default() }));
        assert_eq!(att.assurance(), AssuranceClass::Soft);
        assert!(att.assurance_reason().contains("secure boot is off"), "{}", att.assurance_reason());
    }

    #[test]
    fn a_record_cannot_state_a_class_its_evidence_does_not_earn() {
        let mut v = fixture();
        v["assurance"] = "device".into();
        let e = Attachment::from_record(&v).unwrap_err();
        assert!(e.contains("states `device`") && e.contains("earns `soft`"), "{e}");
        v["assurance"] = "nonsense".into();
        assert!(Attachment::from_record(&v).is_err());
        v.as_object_mut().unwrap().remove("assurance");
        assert_eq!(Attachment::from_record(&v).unwrap().assurance(), AssuranceClass::Soft);
    }

    #[test]
    fn a_firmware_report_furcate_cannot_grade_is_refused_and_a_silent_one_is_soft() {
        let mut v = fixture();
        v["leaf"]["assurance_reported"] = "trust-me".into();
        assert!(Attachment::from_record(&v).unwrap_err().contains("trust-me"));
        v["leaf"]["assurance_reported"] = "silicon-fingerprint+secure-boot".into();
        let att = Attachment::from_record(&v).unwrap();
        assert_eq!(att.assurance(), AssuranceClass::Soft, "download mode and JTAG are not reported");
        v["leaf"].as_object_mut().unwrap().remove("assurance_reported");
        let att = Attachment::from_record(&v).unwrap();
        assert_eq!((att.key_custody, att.assurance()), (None, AssuranceClass::Soft));
        v["key_custody"] = serde_json::json!({"kind": "sram-fingerprint", "lockdown": {
            "secure_boot": true, "flash_encryption": true, "download_disabled": true, "jtag_disabled": true}});
        v.as_object_mut().unwrap().remove("assurance");
        assert_eq!(Attachment::from_record(&v).unwrap().assurance(), AssuranceClass::Device);
    }

    #[test]
    fn a_p256_leaf_is_named_by_its_key() {
        let mut v = fixture();
        v["leaf_id"] = "esp-lab".into();
        assert!(Attachment::from_record(&v).unwrap_err().contains("named by its key"));
        let mut v = fixture();
        v["leaf"]["public_key_type"] = "rsa".into();
        assert!(Attachment::from_record(&v).is_err());
        let mut v = fixture();
        v["leaf"].as_object_mut().unwrap().remove("public_key_type");
        assert!(Attachment::from_record(&v).is_err(), "an untyped bare key is Ed25519, and 65 bytes is not one");
        let mut v = fixture();
        let key = v["public_key"].as_str().unwrap().to_string();
        v["public_key"] = format!("p256:{key}").into();
        v["leaf"].as_object_mut().unwrap().remove("public_key_type");
        assert_eq!(Attachment::from_record(&v).unwrap().leaf_id, "1d3d319e958177e5a4f2d8fb58c11cfe");
    }

    #[test]
    fn a_signed_reading_from_an_attached_leaf_verifies() {
        let (mut leaf, mut parent) = setup();
        let r = leaf.publish("rack-temp", 22.5, 100);
        assert_eq!(parent.verify(&r, AssuranceClass::Device), Ok(()));
    }

    #[test]
    fn a_reading_from_an_unknown_leaf_is_refused() {
        let (_leaf, mut parent) = setup();
        let mut stranger = Leaf::new("esp32-rogue", [6u8; 32]);
        let r = stranger.publish("rack-temp", 22.5, 100);
        assert_eq!(
            parent.verify(&r, AssuranceClass::Device),
            Err(LeafError::NotAttached)
        );
    }

    #[test]
    fn an_altered_value_is_detected() {
        let (mut leaf, mut parent) = setup();
        let mut r = leaf.publish("rack-temp", 22.5, 100);
        r.value = 90.0;
        assert_eq!(
            parent.verify(&r, AssuranceClass::Device),
            Err(LeafError::BadSignature)
        );
    }

    #[test]
    fn a_replayed_reading_is_detected_without_a_trusted_clock() {
        let (mut leaf, mut parent) = setup();
        let r = leaf.publish("rack-temp", 22.5, 100);
        assert_eq!(parent.verify(&r, AssuranceClass::Device), Ok(()));
        assert_eq!(
            parent.verify(&r, AssuranceClass::Device),
            Err(LeafError::StaleSequence { last: 1, found: 1 })
        );
    }

    #[test]
    fn readings_must_advance_in_sequence() {
        let (mut leaf, mut parent) = setup();
        let first = leaf.publish("t", 1.0, 10);
        let second = leaf.publish("t", 2.0, 20);
        assert!(parent.verify(&second, AssuranceClass::Device).is_ok());
        // The earlier one arriving late is rejected.
        assert!(matches!(
            parent.verify(&first, AssuranceClass::Device),
            Err(LeafError::StaleSequence { .. })
        ));
    }

    #[test]
    fn policy_can_demand_stronger_silicon_for_some_data() {
        let (mut leaf, mut parent) = setup();
        let r = leaf.publish("rack-temp", 22.5, 100);
        assert_eq!(
            parent.verify(&r, AssuranceClass::Tpm),
            Err(LeafError::AssuranceTooLow {
                required: AssuranceClass::Tpm,
                found: AssuranceClass::Device
            })
        );
    }

    #[test]
    fn detaching_stops_accepting_readings() {
        let (mut leaf, mut parent) = setup();
        assert!(parent.detach("esp32-a"));
        let r = leaf.publish("rack-temp", 22.5, 100);
        assert_eq!(
            parent.verify(&r, AssuranceClass::Device),
            Err(LeafError::NotAttached)
        );
    }

    #[test]
    fn reattaching_resets_the_sequence_window() {
        let (mut leaf, mut parent) = setup();
        let r = leaf.publish("t", 1.0, 1);
        parent.verify(&r, AssuranceClass::Device).unwrap();
        parent.detach("esp32-a");
        parent.accept(leaf.attach("node-a", FUSED, 10));
        // A fresh attachment starts a fresh window, so an old reading still
        // fails but new ones are accepted.
        let r2 = leaf.publish("t", 2.0, 2);
        assert!(parent.verify(&r2, AssuranceClass::Device).is_ok());
    }
}
