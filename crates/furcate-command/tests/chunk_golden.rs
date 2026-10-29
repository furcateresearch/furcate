//! Golden vector for trajectory commands: one accepted chunk, one vetoed chunk with its stop request and one
//! truncated chunk, built from public test seeds. Regenerate with UPDATE_GOLDEN=1; a drift fails this test.

mod common;
use common::*;
use furcate_command::issue::key_id;
use furcate_command::{sha256_hex, verify_receipt, verify_stop_request, ChunkOverrun};
use serde_json::{json, Value};

fn scenario(name: &str, mutate: impl FnOnce(&mut Value), o: ChunkOverrun) -> Value {
    let mut v = traj_value(1, 0);
    mutate(&mut v);
    let unsigned = v.clone();
    let raw = finish_traj(v);
    let mut g = traj_gate_with(o);
    let r = g.decide(&raw, NOW);
    let site = g.site_key_id();
    assert!(verify_receipt(&r.bytes, &site).is_ok());
    let sr = r.stop_request.as_ref().map(|b| {
        assert!(verify_stop_request(b, &site).is_ok());
        String::from_utf8(b.clone()).unwrap()
    });
    json!({
        "name": name,
        "command_unsigned": unsigned,
        "command_canonical": String::from_utf8(raw.clone()).unwrap(),
        "command_sha256": sha256_hex(&raw),
        "decision": r.decision.as_str(),
        "error_code": r.code.map(|c| c.as_str()),
        "verdict": r.verdict.as_ref().map(|v| v.to_json()),
        "receipt_canonical": String::from_utf8(r.bytes.clone()).unwrap(),
        "stop_request_canonical": sr,
    })
}

fn build() -> Value {
    let accepted = scenario("accepted", |_| {}, ChunkOverrun::Veto);
    let vetoed = scenario("vetoed_position_step_7", |v| v["body"]["steps"][7]["q"][3] = json!(2.85), ChunkOverrun::Veto);
    let truncated = scenario("truncated_velocity_step_12", |v| v["body"]["steps"][12]["q"][5] = json!(ref_q(5, 12) + 0.3), ChunkOverrun::Truncate { min_steps: 1 });
    assert_eq!(accepted["decision"], "shadowed");
    assert_eq!(vetoed["error_code"], "chunk_vetoed");
    assert_eq!(truncated["decision"], "truncated");
    json!({
        "about": "physical-command trajectory golden vector; public test seeds, never real keys",
        "keys": {"lw_seed_byte": LW_SEED, "site_seed_byte": SITE_SEED, "lw_key_id": key_id(&lw()), "site_key_id": traj_gate().site_key_id()},
        "now_ms": NOW,
        "domains": {"command": "lw-physical/command/v1", "twin_cert": "lw-physical/twin-cert/v1", "receipt": "furcate/physical-receipt/v1", "stop_request": "furcate/physical-stop-request/v1"},
        "scenarios": [accepted, vetoed, truncated],
    })
}

#[test]
fn the_trajectory_golden_vector_has_not_drifted() {
    let now = build();
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/physical-trajectory.golden.json");
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(&p, serde_json::to_string_pretty(&now).unwrap() + "\n").unwrap();
    }
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    assert_eq!(on_disk, now, "the vector changed: regenerate with UPDATE_GOLDEN=1");
}
