#![allow(dead_code)]
//! Fixtures for model-update records: three public test signers, a born agent, and a chain of updates.

use ed25519_dalek::SigningKey;
use furcate_command::canon::canonical;
use furcate_command::issue::key_id;
use furcate_command::update::{sign_update, UpdateRegister};
use furcate_ledger::Chain;
use serde_json::{json, Value};

pub const NOW: u64 = 1_800_000_000_000;
pub const AGENT: &str = "agent-1";
pub const BIRTH: &str = "3333333333333333333333333333333333333333333333333333333333333333";
pub const M0: &str = "2222222222222222222222222222222222222222222222222222222222222222";
pub const M1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const M2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const H0: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
pub const H1: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
pub const H2: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
pub const H3: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

pub fn k(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
/// Trainer (tee), evaluator (tpm), releaser (se): the lowest along the chain is se.
pub fn chain_keys() -> [(SigningKey, &'static str, &'static str); 3] {
    [(k(0x71), "tee", "trainer"), (k(0x72), "tpm", "evaluator"), (k(0x73), "se", "releaser")]
}

pub fn register(floor: &str) -> UpdateRegister {
    let enrolled = chain_keys().iter().map(|(s, c, _)| (key_id(s), c.to_string())).collect();
    let mut r = UpdateRegister::new("tenant-a", enrolled, floor, Chain::genesis("update-register", NOW - 10_000)).unwrap();
    r.born(AGENT, BIRTH, M0, H0);
    r
}

pub fn sha(b: &[u8]) -> String {
    furcate_command::sha256_hex(b)
}

/// An unsigned, valid update `old -> new` that links to `parent` (the previous update's hash) and `parent_head`.
pub fn update_value(n: u64, old: &str, new: &str, parent: Option<&str>, parent_head: &str, head: &str) -> Value {
    json!({
        "format": "model-update", "v": 1, "update_id": format!("upd-{n:04}"), "tenant": "tenant-a", "agent_id": AGENT, "reason": "learn",
        "old_model_sha256": old, "new_model_sha256": new, "birth_record_sha256": BIRTH,
        "parent_update_sha256": parent,
        "experience": {
            "ledger_head": head, "parent_ledger_head": parent_head, "ledger_entries": 1200 + n,
            "training_ref_sha256": format!("{:064x}", 0x7000 + n),
            "simulated_seconds_validated_delta": 86_400, "simulated_seconds_unvalidated_delta": 3_600
        },
        "evaluation": {
            "gate": "release-gate",
            "benchmarks": [
                {"name": "reach_success", "score_ppm": 962_000, "threshold_ppm": 950_000},
                {"name": "safety_envelope", "score_ppm": 1_000_000, "threshold_ppm": 999_000}
            ],
            "fidelity_ppm": 930_000, "fidelity_minimum_ppm": 800_000,
            "band_certificate_sha256": format!("{:064x}", 0x9000 + n), "release_point_inside_band": true, "result": "passed"
        },
        "signers": chain_keys().iter().map(|(s, c, r)| json!({"key": key_id(s), "attestation": c, "role": r})).collect::<Vec<_>>(),
        "attestation_min": "se",
        "issued_ms": NOW - 1000, "valid_until_ms": NOW + 86_400_000,
        "signatures": []
    })
}

pub fn sign_chain(mut v: Value) -> Vec<u8> {
    v["signatures"] = json!([]);
    for (s, _, _) in chain_keys() {
        sign_update(&mut v, &s).unwrap();
    }
    canonical(&v).unwrap().into_bytes()
}

/// Three accepted-shaped updates: M0 -> M1 -> M2, then a rollback to M1.
pub fn lineage_bytes() -> Vec<Vec<u8>> {
    let u1 = sign_chain(update_value(1, M0, M1, None, H0, H1));
    let u2 = sign_chain(update_value(2, M1, M2, Some(&sha(&u1)), H1, H2));
    let mut rb = update_value(3, M2, M1, Some(&sha(&u2)), H2, H3);
    rb["reason"] = json!("rollback");
    let u3 = sign_chain(rb);
    vec![u1, u2, u3]
}
