//! The operator's file: which leaves are enrolled and what their sensors are.
//!
//! ```json
//! {
//!   "bridge_id": "furcate:node:...",
//!   "ceiling": "device",
//!   "bridge_custody": {"kind": "fuse-key"},
//!   "leaves": [{
//!     "name": "micro-01",
//!     "key": "p256:04...",
//!     "custody": {"kind": "readable-identifiers"},
//!     "mac": "44b176b05724", "otp": "0102030405060708", "revision": "0002",
//!     "channels": {"0": "chip.tmp"},
//!     "module": {"name": "nicla-1", "serial": "NSM-0042", "device_id": "0908070605040302",
//!                "device_addr": "c00102030405", "unit_fingerprint": "6b8b373a92128b23de4ac344cdcd5f03",
//!                "channels": {"16": "tmp"}}
//!   }]
//! }
//! ```
//!
//! Enrolling is the operator's decision, taken once and written here; a leaf
//! that presents itself without an entry is refused, not enrolled by showing up.

use crate::bridge::{ModuleSource, Source};
use furcate_identity::backends::fingerprint::{Characteristic, Fingerprint};
use furcate_identity::{AssuranceClass, EnrolledUnit, LeafKeyCustody, UnitRoster};
use furcate_sense::identity::{enrol, fingerprint_of, ChipIds};
use furcate_sense::nicla::Transport;
use furcate_sense::relay::RelaySource;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct Loaded {
    pub bridge_id: String,
    pub ceiling: AssuranceClass,
    pub bridge_custody: Option<LeafKeyCustody>,
    pub roster: UnitRoster,
    pub sources: Vec<Source>,
}

pub fn class(s: &str) -> Result<AssuranceClass, String> {
    Ok(match s {
        "soft" => AssuranceClass::Soft,
        "device" => AssuranceClass::Device,
        "secure-element" | "secureelement" => AssuranceClass::SecureElement,
        "tee" => AssuranceClass::Tee,
        "dice" => AssuranceClass::Dice,
        "tpm" => AssuranceClass::Tpm,
        other => return Err(format!("unknown class `{other}`")),
    })
}

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("`{k}` is missing"))
}

fn hexn<const N: usize>(v: &Value, k: &str) -> Result<[u8; N], String> {
    let b = hex::decode(text(v, k)?).map_err(|e| format!("`{k}` is not hex: {e}"))?;
    b.try_into().map_err(|_| format!("`{k}` must be {N} bytes"))
}

fn channels(v: Option<&Value>) -> Result<BTreeMap<u8, String>, String> {
    let mut out = BTreeMap::new();
    for (k, c) in v.and_then(Value::as_object).ok_or("`channels` is missing")? {
        let idx: u8 = k.parse().map_err(|_| format!("sensor index `{k}` is not a number below 256"))?;
        out.insert(idx, c.as_str().ok_or("a channel is a name")?.to_string());
    }
    Ok(out)
}

pub fn load(v: &Value) -> Result<Loaded, String> {
    let mut roster = UnitRoster::new();
    let mut sources = Vec::new();
    for leaf in v.get("leaves").and_then(Value::as_array).ok_or("`leaves` is missing")? {
        let name = text(leaf, "name")?;
        let key = text(leaf, "key")?;
        let key_bytes = hex::decode(key.strip_prefix("p256:").ok_or("a leaf key is `p256:<hex>`")?).map_err(|e| format!("`key`: {e}"))?;
        let unit_id = hex::encode(Sha256::digest(&key_bytes));
        let custody: LeafKeyCustody = serde_json::from_value(leaf.get("custody").cloned().ok_or("`custody` is missing")?).map_err(|e| format!("`custody`: {e}"))?;
        // The same three silicon values the leaf reports in HELLO, written the same way.
        let fp = Fingerprint::default()
            .with(Characteristic::MacAddress, text(leaf, "mac")?)
            .with(Characteristic::Otp, text(leaf, "otp")?)
            .with(Characteristic::BoardRevision, text(leaf, "revision")?);
        let identity = enrol(fp.clone(), name, b"furcate-leaf-link").map_err(|e| format!("leaf `{name}`: {e}"))?;
        roster.enrol(EnrolledUnit { unit_id: unit_id.clone(), fingerprint: fp, key: Some(key.to_string()), custody: Some(custody) })?;
        let chip = RelaySource {
            identity,
            transport: Transport::UsbFrame,
            statement: format!(
                "Readings of the sensors on micro processing node `{name}`, signed by that node and verified at the link against the key it was enrolled with. The bridge signs the frame with its own hardware key and claims no class above the lower of the two."
            ),
        };
        let module = match leaf.get("module") {
            None => None,
            Some(m) => {
                let mname = text(m, "name")?;
                let fp = fingerprint_of(text(m, "serial")?, Some(ChipIds { device_id: hexn(m, "device_id")?, device_addr: hexn(m, "device_addr")? }))
                    .map_err(|e| format!("module `{mname}`: {e}"))?;
                let id = enrol(fp, mname, b"furcate-leaf-link").map_err(|e| format!("module `{mname}`: {e}"))?;
                Some(ModuleSource {
                    unit_fingerprint: hexn(m, "unit_fingerprint")?,
                    source: RelaySource {
                        identity: id,
                        transport: Transport::Bhy2Binary,
                        statement: format!(
                            "Sensing module `{mname}` behind micro processing node `{name}`. It is named by the leaf from identifiers the operator configured and is not authenticated: it holds no secret, so anything repeating them would match."
                        ),
                    },
                    channels: channels(m.get("channels"))?,
                })
            }
        };
        sources.push(Source { leaf_unit: unit_id, chip, chip_channels: channels(leaf.get("channels"))?, module });
    }
    Ok(Loaded {
        bridge_id: text(v, "bridge_id")?.to_string(),
        ceiling: class(text(v, "ceiling")?)?,
        bridge_custody: v.get("bridge_custody").map(|c| serde_json::from_value(c.clone())).transpose().map_err(|e| format!("`bridge_custody`: {e}"))?,
        roster,
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn leaf() -> Value {
        json!({
            "name": "micro-01",
            "key": "p256:041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3",
            "custody": {"kind": "readable-identifiers"},
            "mac": "44b176b05724", "otp": "0102030405060708", "revision": "0002",
            "channels": {"0": "chip.tmp"},
            "module": {"name": "nicla-1", "serial": "NSM-0042", "device_id": "0908070605040302", "device_addr": "c00102030405", "unit_fingerprint": "6b8b373a92128b23de4ac344cdcd5f03", "channels": {"16": "hum"}}
        })
    }

    #[test]
    fn a_file_loads_into_a_roster_and_sources() {
        let l = load(&json!({"bridge_id": "furcate:node:b", "ceiling": "device", "leaves": [leaf()]})).unwrap();
        assert_eq!(l.ceiling, AssuranceClass::Device);
        assert_eq!(l.sources.len(), 1);
        assert_eq!(l.sources[0].chip_channels.get(&0).map(String::as_str), Some("chip.tmp"));
        assert!(l.sources[0].module.is_some());
        assert_eq!(l.sources[0].leaf_unit.len(), 64);
    }

    #[test]
    fn a_file_with_a_gap_says_where() {
        let mut bad = leaf();
        bad.as_object_mut().unwrap().remove("otp");
        assert!(load(&json!({"bridge_id": "b", "ceiling": "soft", "leaves": [bad]})).err().unwrap().contains("otp"));
        assert!(load(&json!({"bridge_id": "b", "ceiling": "gold", "leaves": []})).err().unwrap().contains("gold"));
        let mut bad_key = leaf();
        bad_key["key"] = json!("ed25519:00");
        assert!(load(&json!({"bridge_id": "b", "ceiling": "soft", "leaves": [bad_key]})).is_err());
        // A key that is the right length but not a point on the curve is not enrolled.
        let mut off_curve = leaf();
        off_curve["key"] = json!(format!("p256:04{}", "ab".repeat(64)));
        let e = load(&json!({"bridge_id": "b", "ceiling": "soft", "leaves": [off_curve]})).err().unwrap();
        assert!(e.contains("not a point on P-256"), "{e}");
    }

    #[test]
    fn a_leaf_enrolled_twice_is_refused() {
        let e = load(&json!({"bridge_id": "b", "ceiling": "soft", "leaves": [leaf(), leaf()]}));
        assert!(e.is_err());
    }
}
