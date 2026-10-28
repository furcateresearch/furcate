#![allow(dead_code)]
//! Shared fixtures: public test keys (seeds are fixed bytes, never real keys), a valid command, the site policy it
//! satisfies, and the baseline verifier the fault suite compares against.

use ed25519_dalek::SigningKey;
use furcate_command::canon::{canonical, parse_canonical};
use furcate_command::issue::{bytes, key_id, sign_cert, sign_command};
use furcate_command::{verify_ed25519, Gate, NoKill, SiteLimit, SitePolicy, COMMAND_DOMAIN};
use furcate_ledger::Chain;
use serde_json::{json, Value};

pub const NOW: u64 = 1_800_000_000_000;
pub const LW_SEED: u8 = 0x4c;
pub const SITE_SEED: u8 = 0x53;
pub const ROGUE_SEED: u8 = 0x99;

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn lw() -> SigningKey {
    key(LW_SEED)
}
pub fn rogue() -> SigningKey {
    key(ROGUE_SEED)
}

pub const POLICY_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub const MODEL_HASH: &str = "2222222222222222222222222222222222222222222222222222222222222222";
pub const BIRTH_HASH: &str = "3333333333333333333333333333333333333333333333333333333333333333";

pub fn policy() -> SitePolicy {
    SitePolicy {
        site_id: "site-test-01".into(),
        tenant: "tenant-a".into(),
        policy_sha256: POLICY_HASH.into(),
        signers: vec![key_id(&lw())],
        approved_models: vec![MODEL_HASH.into()],
        require_birth_record: true,
        approved_birth_records: vec![BIRTH_HASH.into()],
        max_ttl_ms: 300_000,
        max_age_ms: 120_000,
        max_skew_ms: 5_000,
        min_fidelity: 0.8,
        limits: vec![SiteLimit {
            actuator_id: "valve-1".into(),
            quantity: "temperature".into(),
            unit: "celsius".into(),
            min: 12.0,
            max: 26.0,
            max_rate_per_s: 2.0,
        }],
    }
}

pub fn gate() -> Gate<NoKill> {
    Gate::new(policy(), NoKill, key(SITE_SEED), Chain::genesis("site-test-01", NOW - 10_000))
}

/// The unsigned certificate for the valid command.
pub fn cert_value() -> Value {
    json!({
        "format": "twin-band-certificate", "v": 1, "tenant": "tenant-a", "twin_id": "twin-plant-7", "version": 3,
        "ranges": [{"quantity": "temperature", "unit": "celsius", "min": 10, "max": 30}],
        "valid_from_ms": NOW - 86_400_000, "valid_until_ms": NOW + 3_600_000, "fidelity_score": 0.93,
        "signer": "", "signature": ""
    })
}

/// A valid, unsigned command with sequence `seq`.
pub fn command_value(seq: u64) -> Value {
    json!({
        "format": "physical-command", "v": 1, "command_id": format!("cmd-{seq:08}"), "tenant": "tenant-a", "site_id": "site-test-01",
        "target": {"actuator_id": "valve-1", "scope": "line-2"}, "kind": "setpoint",
        "body": {"quantity": "temperature", "unit": "celsius", "value": 21.5},
        "issued_at_ms": NOW - 1000, "not_before_ms": NOW - 1000, "expires_at_ms": NOW + 60_000,
        "nonce": format!("{:032x}", 0xabcdef0000u64 + seq as u64), "command_seq": seq, "mode": "shadow",
        "policy_sha256": POLICY_HASH, "model_sha256": MODEL_HASH, "birth_record_sha256": BIRTH_HASH,
        "envelope": {"min": 15, "max": 28, "max_rate_per_s": 3},
        "twin_cert": cert_value(), "signer": "", "signature": ""
    })
}

/// Sign the certificate then the command, both with `cert_key` / `cmd_key`.
pub fn finish(mut v: Value, cert_key: &SigningKey, cmd_key: &SigningKey) -> Vec<u8> {
    let mut cert = v["twin_cert"].take();
    sign_cert(&mut cert, cert_key).unwrap();
    v["twin_cert"] = cert;
    sign_command(&mut v, cmd_key).unwrap();
    bytes(&v)
}

pub fn valid(seq: u64) -> Vec<u8> {
    finish(command_value(seq), &lw(), &lw())
}

/// A verifier that checks only the signature and the expiry, the way a minimal implementation would: it parses
/// loosely, canonicalises what it parsed, and checks the signature of an enrolled key over that.
pub fn baseline_accepts(raw: &[u8], now: u64) -> bool {
    let Ok(v) = serde_json::from_slice::<Value>(raw) else { return false };
    let Some(o) = v.as_object() else { return false };
    let (Some(signer), Some(sig), Some(exp)) = (
        o.get("signer").and_then(|x| x.as_str()),
        o.get("signature").and_then(|x| x.as_str()),
        o.get("expires_at_ms").and_then(|x| x.as_u64()),
    ) else {
        return false;
    };
    if signer != key_id(&lw()) || now >= exp {
        return false;
    }
    let mut body = v.clone();
    body.as_object_mut().unwrap().remove("signature");
    let Ok(msg) = canonical(&body) else { return false };
    verify_ed25519(signer, COMMAND_DOMAIN, msg.as_bytes(), sig)
}

pub fn parse(b: &[u8]) -> Value {
    parse_canonical(b).unwrap()
}
