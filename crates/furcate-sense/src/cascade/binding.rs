//! Binding a signed reading to the model and calibration that produced it.
//!
//! A reading signature says who signed. It does not say which model weights
//! were running, which calibration artefact was applied, or whether the node's
//! own check of both passed. A [`ModelBinding`] carries those four facts inside
//! the provenance the processing node signs, 17 bytes in the compact form
//! ([`BINDING_WIRE_LEN`]), and a [`BindingRegistry`] held by the verifying rung
//! says which combinations it accepts.
//!
//! | field | bytes | meaning |
//! |---|---|---|
//! | model | 8 | prefix of the SHA-256 of the model artefact as the node hashed it |
//! | epoch | 4 | model release epoch, never decreasing for one node |
//! | calibration | 4 | prefix of the SHA-256 of the applied calibration artefact |
//! | self test | 1 | the node's own boot or rolling check of model and calibration passed |
//!
//! A verifier refuses a binding that is absent (when a registry is in use),
//! names a model it has not registered, names a revoked model, is older than
//! the minimum epoch, goes backwards for that node, names an unregistered
//! calibration, reports a failed self test, or disagrees with the model named
//! inside an embedding window. Every refusal is recorded by the ingest log like
//! any other, and the item stays in the witnessed log, which is the quarantine:
//! what the node emitted is kept, and nothing acts on it.
//!
//! Limit: the binding is what the node states it ran. A node that hashes its
//! own weights honestly shows a flipped weight byte as an unregistered model; a
//! node whose software is replaced can state a registered hash while running
//! something else. Closing that needs a challenge that exercises the running
//! model, see [`super::attest`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MODEL_PREFIX: usize = 8;
pub const CALIBRATION_PREFIX: usize = 4;
/// Bytes of the compact form: 8 model, 4 epoch, 4 calibration, 1 self test.
pub const BINDING_WIRE_LEN: usize = MODEL_PREFIX + 4 + CALIBRATION_PREFIX + 1;

/// The calibration prefix of a node that applies no calibration artefact.
pub const NO_CALIBRATION: [u8; CALIBRATION_PREFIX] = [0; CALIBRATION_PREFIX];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelBinding {
    /// Hex of the first 8 bytes of the model artefact's SHA-256.
    pub model: String,
    pub epoch: u32,
    /// Hex of the first 4 bytes of the calibration artefact's SHA-256.
    pub calibration: String,
    pub self_test: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingError {
    BadLength(usize),
    BadHex(&'static str),
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::BadLength(n) => write!(f, "a binding is {BINDING_WIRE_LEN} bytes, got {n}"),
            BindingError::BadHex(w) => write!(f, "{w} is not the right length of hex"),
        }
    }
}

impl std::error::Error for BindingError {}

fn prefix_of<const N: usize>(digest: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

/// The calibration prefix of an artefact's bytes.
pub fn calibration_prefix(artefact: &[u8]) -> [u8; CALIBRATION_PREFIX] {
    prefix_of(&Sha256::digest(artefact))
}

impl ModelBinding {
    /// From the model's full SHA-256 (hex) and the calibration artefact bytes.
    pub fn new(model_sha256_hex: &str, epoch: u32, calibration_artefact: Option<&[u8]>, self_test: bool) -> Result<Self, BindingError> {
        let full = hex::decode(model_sha256_hex).map_err(|_| BindingError::BadHex("model hash"))?;
        if full.len() != 32 {
            return Err(BindingError::BadHex("model hash"));
        }
        let cal = calibration_artefact.map(calibration_prefix).unwrap_or(NO_CALIBRATION);
        Ok(Self { model: hex::encode(&full[..MODEL_PREFIX]), epoch, calibration: hex::encode(cal), self_test })
    }

    pub fn model_bytes(&self) -> Result<[u8; MODEL_PREFIX], BindingError> {
        let b = hex::decode(&self.model).map_err(|_| BindingError::BadHex("model prefix"))?;
        <[u8; MODEL_PREFIX]>::try_from(b.as_slice()).map_err(|_| BindingError::BadHex("model prefix"))
    }

    pub fn calibration_bytes(&self) -> Result<[u8; CALIBRATION_PREFIX], BindingError> {
        let b = hex::decode(&self.calibration).map_err(|_| BindingError::BadHex("calibration prefix"))?;
        <[u8; CALIBRATION_PREFIX]>::try_from(b.as_slice()).map_err(|_| BindingError::BadHex("calibration prefix"))
    }

    /// The compact form a firmware node carries.
    pub fn to_wire(&self) -> Result<[u8; BINDING_WIRE_LEN], BindingError> {
        let mut out = [0u8; BINDING_WIRE_LEN];
        out[..8].copy_from_slice(&self.model_bytes()?);
        out[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        out[12..16].copy_from_slice(&self.calibration_bytes()?);
        out[16] = u8::from(self.self_test);
        Ok(out)
    }

    pub fn from_wire(b: &[u8]) -> Result<Self, BindingError> {
        if b.len() != BINDING_WIRE_LEN {
            return Err(BindingError::BadLength(b.len()));
        }
        if b[16] > 1 {
            return Err(BindingError::BadHex("self test flag"));
        }
        Ok(Self {
            model: hex::encode(&b[..8]),
            epoch: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            calibration: hex::encode(&b[12..16]),
            self_test: b[16] == 1,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingRefusal {
    /// A registry is in use and the item carries no binding.
    Missing,
    /// The binding is not well formed.
    Malformed,
    UnknownModel(String),
    Revoked(String),
    /// Below the minimum epoch for the registry or for that model.
    EpochTooOld { minimum: u32, found: u32 },
    /// Lower than an epoch already seen from the same node.
    EpochRegressed { seen: u32, found: u32 },
    UnknownCalibration(String),
    SelfTestFailed,
    /// The embedding window names a different model than the binding.
    ModelDisagrees,
}

impl BindingRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            BindingRefusal::Missing => "binding_missing",
            BindingRefusal::Malformed => "binding_malformed",
            BindingRefusal::UnknownModel(_) => "binding_unknown_model",
            BindingRefusal::Revoked(_) => "binding_revoked_model",
            BindingRefusal::EpochTooOld { .. } => "binding_epoch_too_old",
            BindingRefusal::EpochRegressed { .. } => "binding_epoch_regressed",
            BindingRefusal::UnknownCalibration(_) => "binding_unknown_calibration",
            BindingRefusal::SelfTestFailed => "binding_self_test_failed",
            BindingRefusal::ModelDisagrees => "binding_model_disagrees",
        }
    }
}

impl std::fmt::Display for BindingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BindingRefusal::*;
        match self {
            Missing => write!(f, "the item carries no model binding"),
            Malformed => write!(f, "the model binding is not well formed"),
            UnknownModel(m) => write!(f, "model {m} is not registered"),
            Revoked(m) => write!(f, "model {m} is revoked"),
            EpochTooOld { minimum, found } => write!(f, "model epoch {found} is below the minimum {minimum}"),
            EpochRegressed { seen, found } => write!(f, "model epoch {found} is below {seen}, already seen from this node"),
            UnknownCalibration(c) => write!(f, "calibration {c} is not registered for this node"),
            SelfTestFailed => write!(f, "the node reports its own self test failed"),
            ModelDisagrees => write!(f, "the window names a different model than the binding"),
        }
    }
}

impl std::error::Error for BindingRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ModelEntry {
    id: String,
    min_epoch: u32,
    revoked: bool,
}

/// What a verifying rung accepts. Held by the verifier, never read from a sender.
#[derive(Clone, Debug, Default)]
pub struct BindingRegistry {
    models: BTreeMap<[u8; MODEL_PREFIX], ModelEntry>,
    calibrations: BTreeMap<String, BTreeSet<[u8; CALIBRATION_PREFIX]>>,
    min_epoch: u32,
}

impl BindingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The lowest epoch accepted from any node.
    pub fn with_min_epoch(mut self, epoch: u32) -> Self {
        self.min_epoch = epoch;
        self
    }

    /// Register a model by the SHA-256 of its artefact. Two registered models
    /// that share an 8-byte prefix are refused, so a prefix names one model.
    pub fn register_model(&mut self, id: &str, sha256_hex: &str, min_epoch: u32) -> Result<(), BindingError> {
        let b = ModelBinding::new(sha256_hex, 0, None, true)?;
        let key = b.model_bytes()?;
        if self.models.get(&key).is_some_and(|e| e.id != id) {
            return Err(BindingError::BadHex("model prefix already names another model"));
        }
        self.models.insert(key, ModelEntry { id: id.to_string(), min_epoch, revoked: false });
        Ok(())
    }

    pub fn revoke_model(&mut self, sha256_hex: &str) -> Result<bool, BindingError> {
        let key = ModelBinding::new(sha256_hex, 0, None, true)?.model_bytes()?;
        Ok(match self.models.get_mut(&key) {
            Some(e) => {
                e.revoked = true;
                true
            }
            None => false,
        })
    }

    /// Register the calibration artefact prefix a sensing node may apply.
    pub fn register_calibration(&mut self, sensing_node: &str, prefix: [u8; CALIBRATION_PREFIX]) {
        self.calibrations.entry(sensing_node.to_string()).or_default().insert(prefix);
    }

    /// Read the operator's registry file:
    /// `{"min_epoch": 2, "models": [{"id": "...", "sha256": "<hex>", "min_epoch": 0, "revoked": false}],
    ///   "calibrations": [{"sensing_node": "...", "prefix": "<8 hex>"}]}`
    /// `min_epoch`, the model's `min_epoch` and `revoked` may be left out.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Model {
            id: String,
            sha256: String,
            #[serde(default)]
            min_epoch: u32,
            #[serde(default)]
            revoked: bool,
        }
        #[derive(Deserialize)]
        struct Cal {
            sensing_node: String,
            prefix: String,
        }
        #[derive(Deserialize)]
        struct File {
            #[serde(default)]
            min_epoch: u32,
            models: Vec<Model>,
            #[serde(default)]
            calibrations: Vec<Cal>,
        }
        let f: File = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
        let mut r = BindingRegistry::new().with_min_epoch(f.min_epoch);
        for m in &f.models {
            r.register_model(&m.id, &m.sha256, m.min_epoch).map_err(|e| format!("model `{}`: {e}", m.id))?;
            if m.revoked {
                r.revoke_model(&m.sha256).map_err(|e| e.to_string())?;
            }
        }
        for c in &f.calibrations {
            let b = hex::decode(&c.prefix).map_err(|_| format!("calibration prefix for `{}` is not hex", c.sensing_node))?;
            let p = <[u8; CALIBRATION_PREFIX]>::try_from(b.as_slice())
                .map_err(|_| format!("calibration prefix for `{}` is not {CALIBRATION_PREFIX} bytes", c.sensing_node))?;
            r.register_calibration(&c.sensing_node, p);
        }
        Ok(r)
    }

    pub fn model_id(&self, binding: &ModelBinding) -> Option<&str> {
        binding.model_bytes().ok().and_then(|k| self.models.get(&k)).map(|e| e.id.as_str())
    }

    /// The stateless checks. `seen_epoch` is the highest epoch already accepted
    /// from this node, kept by the caller.
    pub fn check(&self, sensing_node: &str, b: &ModelBinding, seen_epoch: Option<u32>) -> Result<(), BindingRefusal> {
        let (Ok(model), Ok(cal)) = (b.model_bytes(), b.calibration_bytes()) else {
            return Err(BindingRefusal::Malformed);
        };
        let entry = self.models.get(&model).ok_or_else(|| BindingRefusal::UnknownModel(b.model.clone()))?;
        if entry.revoked {
            return Err(BindingRefusal::Revoked(b.model.clone()));
        }
        let minimum = self.min_epoch.max(entry.min_epoch);
        if b.epoch < minimum {
            return Err(BindingRefusal::EpochTooOld { minimum, found: b.epoch });
        }
        if let Some(seen) = seen_epoch {
            if b.epoch < seen {
                return Err(BindingRefusal::EpochRegressed { seen, found: b.epoch });
            }
        }
        if !self.calibrations.get(sensing_node).is_some_and(|s| s.contains(&cal)) {
            return Err(BindingRefusal::UnknownCalibration(b.calibration.clone()));
        }
        if !b.self_test {
            return Err(BindingRefusal::SelfTestFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn registry() -> BindingRegistry {
        let mut r = BindingRegistry::new().with_min_epoch(2);
        r.register_model("m", &sha(b"weights-v3"), 0).unwrap();
        r.register_calibration("n", calibration_prefix(b"cal-a"));
        r
    }

    fn good() -> ModelBinding {
        ModelBinding::new(&sha(b"weights-v3"), 3, Some(b"cal-a"), true).unwrap()
    }

    #[test]
    fn the_compact_form_is_17_bytes_and_round_trips() {
        let w = good().to_wire().unwrap();
        assert_eq!(w.len(), 17);
        assert_eq!(BINDING_WIRE_LEN, 17);
        assert_eq!(ModelBinding::from_wire(&w).unwrap(), good());
        assert!(ModelBinding::from_wire(&w[..16]).is_err());
        let mut bad = w;
        bad[16] = 2;
        assert!(ModelBinding::from_wire(&bad).is_err());
    }

    #[test]
    fn a_registered_binding_passes_and_each_deviation_has_its_own_refusal() {
        let r = registry();
        assert_eq!(r.check("n", &good(), None), Ok(()));
        let flipped = ModelBinding::new(&sha(b"weights-v3x"), 3, Some(b"cal-a"), true).unwrap();
        assert_eq!(r.check("n", &flipped, None).unwrap_err().code(), "binding_unknown_model");
        let old = ModelBinding { epoch: 1, ..good() };
        assert_eq!(r.check("n", &old, None), Err(BindingRefusal::EpochTooOld { minimum: 2, found: 1 }));
        assert_eq!(r.check("n", &good(), Some(5)), Err(BindingRefusal::EpochRegressed { seen: 5, found: 3 }));
        let cal = ModelBinding::new(&sha(b"weights-v3"), 3, Some(b"cal-b"), true).unwrap();
        assert_eq!(r.check("n", &cal, None).unwrap_err().code(), "binding_unknown_calibration");
        assert_eq!(r.check("other", &good(), None).unwrap_err().code(), "binding_unknown_calibration");
        let st = ModelBinding { self_test: false, ..good() };
        assert_eq!(r.check("n", &st, None), Err(BindingRefusal::SelfTestFailed));
        let junk = ModelBinding { model: "zz".into(), ..good() };
        assert_eq!(r.check("n", &junk, None), Err(BindingRefusal::Malformed));
    }

    #[test]
    fn a_revoked_model_is_refused_and_an_unknown_revocation_reports_false() {
        let mut r = registry();
        assert_eq!(r.revoke_model(&sha(b"weights-v3")), Ok(true));
        assert_eq!(r.check("n", &good(), None).unwrap_err().code(), "binding_revoked_model");
        assert_eq!(r.revoke_model(&sha(b"nothing")), Ok(false));
    }

    #[test]
    fn a_registry_file_reads_and_a_bad_one_is_an_error() {
        let v = serde_json::json!({
            "min_epoch": 2,
            "models": [
                {"id": "m", "sha256": sha(b"weights-v3")},
                {"id": "old", "sha256": sha(b"weights-v1"), "revoked": true}
            ],
            "calibrations": [{"sensing_node": "n", "prefix": hex::encode(calibration_prefix(b"cal-a"))}]
        });
        let r = BindingRegistry::from_json(&v).unwrap();
        assert_eq!(r.check("n", &good(), None), Ok(()));
        let old = ModelBinding::new(&sha(b"weights-v1"), 3, Some(b"cal-a"), true).unwrap();
        assert_eq!(r.check("n", &old, None).unwrap_err().code(), "binding_revoked_model");
        assert!(BindingRegistry::from_json(&serde_json::json!({"models": [{"id": "m", "sha256": "zz"}]})).is_err());
        assert!(BindingRegistry::from_json(&serde_json::json!({"models": [], "calibrations": [{"sensing_node": "n", "prefix": "00"}]})).is_err());
        assert!(BindingRegistry::from_json(&serde_json::json!({"nothing": 1})).is_err());
    }

    #[test]
    fn a_model_with_a_higher_floor_than_the_registry_uses_it() {
        let mut r = BindingRegistry::new();
        r.register_model("m", &sha(b"w"), 7).unwrap();
        r.register_calibration("n", NO_CALIBRATION);
        let b = ModelBinding::new(&sha(b"w"), 6, None, true).unwrap();
        assert_eq!(r.check("n", &b, None), Err(BindingRefusal::EpochTooOld { minimum: 7, found: 6 }));
        assert_eq!(r.check("n", &ModelBinding { epoch: 7, ..b }, None), Ok(()));
    }
}
