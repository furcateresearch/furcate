//! Model-update records: a born agent that learns stays verifiable.

mod update_common;
use furcate_command::update::*;
use furcate_ledger::OpKind;
use serde_json::{json, Value};
use update_common::*;

fn decide_one(mutate: impl FnOnce(&mut Value), now: u64) -> UpdateDecision {
    let mut v = update_value(1, M0, M1, None, H0, H1);
    mutate(&mut v);
    let mut r = register("se");
    r.decide(&sign_chain(v), now)
}
fn code(mutate: impl FnOnce(&mut Value)) -> Option<UpdateRefusal> {
    decide_one(mutate, NOW).code
}

#[test]
fn a_lineage_of_updates_and_a_rollback_is_accepted_and_chained() {
    let mut r = register("se");
    let n0 = r.chain().len();
    for (i, b) in lineage_bytes().iter().enumerate() {
        let d = r.decide(b, NOW);
        assert!(d.accepted, "update {i}: {:?}", d.code);
    }
    let l = r.lineage(AGENT).unwrap();
    assert_eq!((l.current_model.as_str(), l.updates, l.last_ledger_head.as_str()), (M1, 3, H3));
    assert_eq!(l.history, vec![M0, M1, M2]);
    assert_eq!(r.approved_models(AGENT), vec![M0, M1, M2]);
    assert_eq!(r.chain().len(), n0 + 3);
    assert!(r.chain().entries().iter().skip(n0).all(|e| e.kind == OpKind::ModelUpdate));
    assert!(r.chain().verify().is_ok());
    let last = r.chain().entries().last().unwrap();
    assert_eq!((last.subject.as_str(), last.actor.as_str()), ("upd-0003", "update-gate:agent-1"));
    assert!(last.result.starts_with("accepted:ok:"));
}

#[test]
fn every_refusal_is_a_ledger_entry_too() {
    let mut r = register("se");
    let n0 = r.chain().len();
    let b = lineage_bytes();
    assert!(!r.decide(&b[1], NOW).accepted); // out of order
    assert!(!r.decide(b"not json", NOW).accepted);
    assert!(r.decide(&b[0], NOW).accepted);
    assert!(!r.decide(&b[0], NOW).accepted); // replay
    assert_eq!(r.chain().len(), n0 + 4);
    assert!(r.chain().entries().last().unwrap().result.starts_with("refused:replayed_update:"));
    assert!(r.chain().verify().is_ok());
    // The refused record changed nothing.
    assert_eq!(r.lineage(AGENT).unwrap().current_model, M1);
}

#[test]
fn each_refusal_has_its_own_code() {
    use UpdateRefusal::*;
    let cases: Vec<(&str, Box<dyn FnOnce(&mut Value)>, UpdateRefusal)> = vec![
        ("wrong format", Box::new(|v| v["format"] = json!("birth-record")), WrongFormat),
        ("version", Box::new(|v| v["v"] = json!(2)), UnsupportedVersion),
        ("unknown member", Box::new(|v| v["extra"] = json!(1)), Malformed),
        ("tenant", Box::new(|v| v["tenant"] = json!("tenant-b")), WrongTenant),
        ("agent", Box::new(|v| v["agent_id"] = json!("agent-9")), AgentUnknown),
        ("birth record", Box::new(|v| v["birth_record_sha256"] = json!("4".repeat(64))), BirthRecordMismatch),
        ("same model", Box::new(|v| v["new_model_sha256"] = json!(M0)), SameModel),
        ("old not current", Box::new(|v| v["old_model_sha256"] = json!(M2)), OldModelNotCurrent),
        ("parent", Box::new(|v| v["parent_update_sha256"] = json!("5".repeat(64))), WrongParent),
        ("parent ledger", Box::new(|v| v["experience"]["parent_ledger_head"] = json!(H3)), WrongParentLedger),
        ("rollback to unknown", Box::new(|v| { v["reason"] = json!("rollback"); v["new_model_sha256"] = json!(M2); }), RollbackTargetUnknown),
        ("failed evaluation", Box::new(|v| { v["evaluation"]["benchmarks"][0]["score_ppm"] = json!(900_000); v["evaluation"]["result"] = json!("failed"); }), EvaluationFailed),
        ("claims passed on a failing score", Box::new(|v| v["evaluation"]["benchmarks"][0]["score_ppm"] = json!(900_000)), EvaluationInconsistent),
        ("claims passed outside the band", Box::new(|v| v["evaluation"]["release_point_inside_band"] = json!(false)), EvaluationInconsistent),
        ("fidelity below minimum, claims passed", Box::new(|v| v["evaluation"]["fidelity_ppm"] = json!(700_000)), EvaluationInconsistent),
        ("attestation_min overstated", Box::new(|v| v["attestation_min"] = json!("tee")), AttestationMismatch),
        ("attestation_min understated", Box::new(|v| v["attestation_min"] = json!("device")), AttestationMismatch),
        ("signer claims a higher class", Box::new(|v| v["signers"][2]["attestation"] = json!("tpm")), AttestationMismatch),
        ("window over 366 days", Box::new(|v| v["valid_until_ms"] = json!(NOW + 400 * 86_400_000u64)), WindowInvalid),
        ("window reversed", Box::new(|v| v["valid_until_ms"] = json!(NOW - 2000)), WindowInvalid),
        ("not yet valid", Box::new(|v| { v["issued_ms"] = json!(NOW + 5000); }), NotYetValid),
        ("last signer is not the releaser", Box::new(|v| v["signers"][2]["role"] = json!("trainer")), SignerChainInvalid),
        ("duplicate signer", Box::new(|v| v["signers"][1] = v["signers"][0].clone()), SignerChainInvalid),
        ("no signers", Box::new(|v| v["signers"] = json!([])), SignerChainInvalid),
    ];
    for (name, m, want) in cases {
        assert_eq!(code(m), Some(want), "{name}");
    }
    assert_eq!(decide_one(|_| {}, NOW + 86_400_000 + 5).code, Some(Expired));
}

#[test]
fn attestation_is_the_minimum_along_the_signer_chain_and_has_a_floor() {
    let ok = register("se").decide(&sign_chain(update_value(1, M0, M1, None, H0, H1)), NOW);
    assert!(ok.accepted);
    // The lowest signer is se; a register that wants tee or better refuses it.
    let d = register("tee").decide(&sign_chain(update_value(1, M0, M1, None, H0, H1)), NOW);
    assert_eq!(d.code, Some(UpdateRefusal::AttestationBelowFloor));
    assert_eq!(min_attestation(["tpm", "tee", "se"]), Some("se"));
    assert_eq!(min_attestation(["tpm", "soft"]), Some("soft"));
    assert_eq!(min_attestation([]), None);
    assert_eq!(min_attestation(["tpm", "bogus"]), None);
}

#[test]
fn signatures_are_checked_for_every_member_of_the_chain() {
    let mut r = register("se");
    let good = sign_chain(update_value(1, M0, M1, None, H0, H1));
    let mut v: Value = furcate_command::canon::parse_canonical(&good).unwrap();
    // Swap two signatures, or replace one with a signature from an unenrolled key.
    v["signatures"].as_array_mut().unwrap().swap(0, 1);
    assert_eq!(r.decide(&furcate_command::issue::bytes(&v), NOW).code, Some(UpdateRefusal::BadSignature));
    let mut w: Value = furcate_command::canon::parse_canonical(&good).unwrap();
    let mut rogue = update_value(1, M0, M1, None, H0, H1);
    rogue["signatures"] = json!([]);
    sign_update(&mut rogue, &k(0x99)).unwrap();
    w["signatures"][1] = rogue["signatures"][0].clone();
    assert_eq!(r.decide(&furcate_command::issue::bytes(&w), NOW).code, Some(UpdateRefusal::BadSignature));
    // One signature short.
    let mut x: Value = furcate_command::canon::parse_canonical(&good).unwrap();
    x["signatures"].as_array_mut().unwrap().pop();
    assert_eq!(r.decide(&furcate_command::issue::bytes(&x), NOW).code, Some(UpdateRefusal::SignerChainInvalid));
    // A signer that is not enrolled.
    let mut y = update_value(1, M0, M1, None, H0, H1);
    y["signers"][0]["key"] = json!(furcate_command::issue::key_id(&k(0x99)));
    assert_eq!(r.decide(&sign_chain(y), NOW).code, Some(UpdateRefusal::SignerNotEnrolled));
    assert_eq!(r.lineage(AGENT).unwrap().updates, 0);
}

#[test]
fn a_tampered_record_is_not_canonical_or_not_signed() {
    let mut r = register("se");
    let good = sign_chain(update_value(1, M0, M1, None, H0, H1));
    let mut pretty = serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&good).unwrap()).unwrap();
    assert_eq!(r.decide(&pretty, NOW).code, Some(UpdateRefusal::NotCanonical));
    pretty.clear();
    let mut t = good.clone();
    let i = t.windows(6).position(|w| w == b"upd-00").unwrap();
    t[i + 5] = b'9';
    assert_eq!(r.decide(&t, NOW).code, Some(UpdateRefusal::BadSignature));
    assert!(r.decide(&good, NOW).accepted);
}

#[test]
fn numbers_beyond_2_pow_53_are_refused() {
    let mut v = update_value(1, M0, M1, None, H0, H1);
    v["experience"]["ledger_entries"] = json!(9_007_199_254_740_993u64);
    let mut r = register("se");
    let bytes = serde_json::to_vec(&v).unwrap();
    assert_eq!(r.decide(&bytes, NOW).code, Some(UpdateRefusal::Malformed));
}

#[test]
fn the_ledger_kind_is_additive_and_distinct() {
    let mut r = register("se");
    r.decide(&lineage_bytes()[0], NOW);
    let e = r.chain().entries().last().unwrap();
    assert_eq!(e.kind, OpKind::ModelUpdate);
    assert_ne!(e.kind, OpKind::Command);
}

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/model-update.golden.json")
}

#[test]
fn the_golden_vector_has_not_drifted() {
    let mut r = register("se");
    let recs = lineage_bytes();
    let decisions: Vec<Value> = recs
        .iter()
        .map(|b| {
            let d = r.decide(b, NOW);
            json!({"accepted": d.accepted, "code": d.code.map(|c| c.code()), "update_sha256": d.update_sha256, "ledger_seq": d.ledger_seq, "ledger_entry_hash": d.ledger_entry_hash})
        })
        .collect();
    let now = json!({
        "about": "model-update golden vector; public test seeds (0x71 trainer, 0x72 evaluator, 0x73 releaser), never real keys",
        "now_ms": NOW,
        "domain": UPDATE_DOMAIN,
        "signers": chain_keys().iter().map(|(s, c, r)| json!({"key": furcate_command::issue::key_id(s), "attestation": c, "role": r})).collect::<Vec<_>>(),
        "born": {"agent_id": AGENT, "birth_record_sha256": BIRTH, "model_sha256": M0, "ledger_head": H0},
        "records_canonical": recs.iter().map(|b| String::from_utf8(b.clone()).unwrap()).collect::<Vec<_>>(),
        "decisions": decisions,
    });
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(path(), serde_json::to_string_pretty(&now).unwrap() + "\n").unwrap();
    }
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(on_disk, now, "the vector changed: regenerate with UPDATE_GOLDEN=1");
}
