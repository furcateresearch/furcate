//! Stages, approvals, release, write-ahead ordering, restore. Every refusal path leaves the executor uncalled.

mod common;
use common::*;
use furcate_command::issue::{bytes, key_id};
use furcate_command::{
    verify_receipt, ActuationConfig, ApprovalError, ChunkOverrun, Decision, ErrorCode, Gate, GateState, KillState, NoKill, Plan,
    RestoreError, SignError, SiteSigner, Stage,
};
use furcate_ledger::{Chain, OpKind};
use serde_json::{json, Value};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

fn approved(stage: Stage) -> Gate<NoKill> {
    let mut g = act_gate(stage, ChunkOverrun::Veto);
    g.install_approval(&valve_approval("ap-valve-1"), NOW).unwrap();
    g.install_approval(&arm_approval("ap-arm-1"), NOW).unwrap();
    g
}

#[test]
fn the_new_codes_exist_and_the_old_ones_are_unchanged() {
    assert_eq!(ErrorCode::ALL.len(), 34);
    assert_eq!(ErrorCode::ObserveOnly.as_str(), "observe_only");
    assert_eq!(ErrorCode::ExecutionFailed.as_str(), "execution_failed");
    assert_eq!(ErrorCode::ALL[31], ErrorCode::BandReferenceMismatch);
    assert_eq!(Decision::Failed.as_str(), "failed");
}

#[test]
fn observe_stage_refuses_every_command_and_never_calls_the_executor() {
    let mut g = approved(Stage::Observe);
    let mut x = Rec::default();
    for (i, raw) in [valid(1), actuate_setpoint(2), valid_chunk(3, 0), actuate_chunk(4, 0)].into_iter().enumerate() {
        let r = g.decide_exec(&raw, NOW, &mut x);
        assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::ObserveOnly)), "{i}");
    }
    assert!(x.calls.is_empty());
    assert_eq!(g.last_seq(), 0);
}

#[test]
fn shadow_stage_and_the_default_decide_but_never_release() {
    let mut x = Rec::default();
    let mut g = approved(Stage::Shadow);
    assert_eq!(g.decide_exec(&valid(1), NOW, &mut x).decision, Decision::Shadowed);
    let r = g.decide_exec(&actuate_setpoint(2), NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::ActuationNotApproved)));
    // No stage entry for the class is shadow too.
    let mut cfg = act_cfg(Stage::Actuate);
    cfg.stages.clear();
    let mut g = traj_gate().with_actuation(cfg);
    g.install_approval(&valve_approval("ap-valve-1"), NOW).unwrap();
    let r = g.decide_exec(&actuate_setpoint(1), NOW, &mut x);
    assert_eq!(r.code, Some(ErrorCode::ActuationNotApproved));
    // An actuator with no class is in no class: shadow only, never released.
    let mut cfg = act_cfg(Stage::Actuate);
    cfg.classes.clear();
    let mut g = traj_gate().with_actuation(cfg);
    assert_eq!(g.decide_exec(&valid(1), NOW, &mut x).decision, Decision::Shadowed);
    assert_eq!(g.decide_exec(&actuate_setpoint(2), NOW, &mut x).code, Some(ErrorCode::ActuationNotApproved));
    assert!(x.calls.is_empty());
}

#[test]
fn without_a_config_or_an_executor_actuate_is_refused_as_before() {
    let mut x = Rec::default();
    let mut g = gate();
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut x).code, Some(ErrorCode::ActuationNotApproved));
    assert_eq!(g.install_approval(&valve_approval("a"), NOW), Err(ApprovalError::NotConfigured));
    // Fully approved, but decide() has no executor.
    let mut g = approved(Stage::Actuate);
    let r = g.decide(&actuate_setpoint(1), NOW);
    assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::ActuationNotApproved)));
    assert!(x.calls.is_empty());
}

#[test]
fn an_approved_setpoint_is_released_write_ahead_and_receipted_with_an_execution_member() {
    let mut g = approved(Stage::Actuate);
    let mut x = Rec::default();
    let raw = actuate_setpoint(1);
    let r = g.decide_exec(&raw, NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Executed, None));
    assert_eq!(x.calls.len(), 1);
    assert_eq!(x.calls[0].2, "hvac_valve");
    assert_eq!(x.calls[0].3, Plan::Setpoint { quantity: "temperature".into(), unit: "celsius".into(), value: 21.5 });
    let v = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    let ex = &v["execution"];
    assert_eq!(ex["approval_id"], "ap-valve-1");
    assert_eq!(ex["system_class"], "hvac_valve");
    assert_eq!((ex["writes"].as_u64(), ex["acked"].as_bool()), (Some(1), Some(true)));
    // The release entry is in the chain, immediately before the receipt entry, with the command hash.
    let rs = ex["release_ledger_seq"].as_u64().unwrap() as usize;
    assert_eq!(rs + 1, r.ledger_seq as usize);
    let e = &g.chain().entries()[rs];
    assert_eq!(e.kind, OpKind::Command);
    assert_eq!(e.actor, "gate:site-test-01");
    assert_eq!(e.subject, "cmd-00000001");
    assert_eq!(e.result, format!("released:ok:{}", furcate_command::sha256_hex(&raw)));
    assert_eq!(ex["release_entry_hash"], hex::encode(e.hash));
    assert!(g.chain().verify().is_ok());
}

#[test]
fn shadow_receipts_have_no_execution_member_and_refused_actuate_receipts_carry_null() {
    let mut g = approved(Stage::Actuate);
    let r = g.decide(&valid(1), NOW);
    assert!(r.value.get("execution").is_none());
    let r = g.decide(&actuate_setpoint(2), NOW);
    assert_eq!(r.value["execution"], Value::Null);
    assert!(r.value.as_object().unwrap().contains_key("execution"));
    let mut x = Rec::default();
    let mut bad = command_value(3);
    bad["mode"] = json!("actuate");
    bad["policy_sha256"] = json!("9".repeat(64));
    let r = g.decide_exec(&finish(bad, &lw(), &lw()), NOW, &mut x);
    assert_eq!((r.code, &r.value["execution"]), (Some(ErrorCode::PolicyHashMismatch), &Value::Null));
    assert!(x.calls.is_empty());
}

#[test]
fn the_executor_is_never_called_for_a_refusal() {
    use ErrorCode::*;
    let mut x = Rec::default();
    let cases: Vec<(&str, Box<dyn FnOnce(&mut Value)>, u64, ErrorCode)> = vec![
        ("policy", Box::new(|v| v["policy_sha256"] = json!("4".repeat(64))), NOW, PolicyHashMismatch),
        ("model", Box::new(|v| v["model_sha256"] = json!("5".repeat(64))), NOW, ModelNotApproved),
        ("site", Box::new(|v| v["site_id"] = json!("site-other")), NOW, WrongSite),
        ("expired", Box::new(|_| {}), NOW + 60_000, Expired),
        ("outside site envelope", Box::new(|v| { v["body"]["value"] = json!(27.0); v["envelope"]["max"] = json!(29); }), NOW, OutsideSiteEnvelope),
        ("outside certified", Box::new(|v| { v["body"]["value"] = json!(31.0); v["envelope"]["max"] = json!(40); }), NOW, OutsideCertifiedRange),
        ("low fidelity", Box::new(|v| v["twin_cert"]["fidelity_score"] = json!(0.5)), NOW, TwinFidelityLow),
    ];
    for (name, m, now, code) in cases {
        let mut g = approved(Stage::Actuate);
        let mut v = command_value(1);
        v["mode"] = json!("actuate");
        m(&mut v);
        let r = g.decide_exec(&finish(v, &lw(), &lw()), now, &mut x);
        assert_eq!(r.code, Some(code), "{name}");
        assert_eq!(g.last_seq(), 0, "{name}");
    }
    // A rate violation and a replay.
    let mut g = approved(Stage::Actuate);
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut x).decision, Decision::Executed);
    let n = x.calls.len();
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut x).code, Some(ReplayedSequence));
    let mut v = command_value(2);
    v["mode"] = json!("actuate");
    v["body"]["value"] = json!(25.5);
    v["envelope"]["max"] = json!(28);
    v["issued_at_ms"] = json!(NOW);
    assert_eq!(g.decide_exec(&finish(v, &lw(), &lw()), NOW, &mut x).code, Some(RateExceeded));
    assert_eq!(x.calls.len(), n);
}

#[test]
fn approvals_must_cover_tenant_site_class_actuator_and_kind_and_be_in_their_window() {
    let mut x = Rec::default();
    let run = |ap: Vec<u8>, now_install: u64, now: u64, raw: Vec<u8>, x: &mut Rec| {
        let mut g = act_gate(Stage::Actuate, ChunkOverrun::Veto);
        let inst = g.install_approval(&ap, now_install);
        (inst, g.decide_exec(&raw, now, x).code)
    };
    let na = Some(ErrorCode::ActuationNotApproved);
    // wrong class (approval for robot_arm but the actuator is a valve)
    let ap = sign_approval(approval_value("a1", "robot_arm", &["valve-1"], &["setpoint"]), &approver());
    assert_eq!(run(ap, NOW, NOW, actuate_setpoint(1), &mut x), (Ok("a1".into()), na));
    // wrong actuator
    let ap = sign_approval(approval_value("a2", "hvac_valve", &["valve-2"], &["setpoint"]), &approver());
    assert_eq!(run(ap, NOW, NOW, actuate_setpoint(1), &mut x), (Ok("a2".into()), na));
    // wrong kind
    let ap = sign_approval(approval_value("a3", "hvac_valve", &["valve-1"], &["trajectory"]), &approver());
    assert_eq!(run(ap, NOW, NOW, actuate_setpoint(1), &mut x), (Ok("a3".into()), na));
    // not yet valid at use, expired at use
    let mut v = approval_value("a4", "hvac_valve", &["valve-1"], &["setpoint"]);
    v["valid_from_ms"] = json!(NOW + 5_000);
    assert_eq!(run(sign_approval(v, &approver()), NOW, NOW, actuate_setpoint(1), &mut x), (Ok("a4".into()), na));
    let mut v = approval_value("a5", "hvac_valve", &["valve-1"], &["setpoint"]);
    v["valid_until_ms"] = json!(NOW + 1);
    // The command is at NOW: valid. One tick later: not.
    let ap = sign_approval(v, &approver());
    assert_eq!(run(ap.clone(), NOW, NOW, actuate_setpoint(1), &mut x).1, None);
    let mut v = approval_value("a5", "hvac_valve", &["valve-1"], &["setpoint"]);
    v["valid_until_ms"] = json!(NOW);
    assert_eq!(run(sign_approval(v, &approver()), NOW - 1, NOW, actuate_setpoint(1), &mut x), (Ok("a5".into()), na));
    // The right one executes.
    assert_eq!(run(valve_approval("ok"), NOW, NOW, actuate_setpoint(1), &mut x).1, None);
    assert_eq!(x.calls.len(), 2);
}

#[test]
fn approval_records_are_checked_strictly_at_install() {
    let mut g = act_gate(Stage::Actuate, ChunkOverrun::Veto);
    let base = || approval_value("ap", "hvac_valve", &["valve-1"], &["setpoint"]);
    let sign = |v: Value| sign_approval(v, &approver());
    let mut ok_ids: Vec<String> = vec![];
    let mut e = |raw: Vec<u8>| g.install_approval(&raw, NOW).unwrap_err();
    // tenant, site
    let mut v = base();
    v["tenant"] = json!("tenant-b");
    assert_eq!(e(sign(v)), ApprovalError::WrongTenant);
    let mut v = base();
    v["site_id"] = json!("site-other");
    assert_eq!(e(sign(v)), ApprovalError::WrongSite);
    // approver not enrolled; signed by another key
    let mut v = base();
    v["approver"] = json!(key_id(&rogue()));
    assert_eq!(e(sign_approval(v, &rogue())), ApprovalError::ApproverNotEnrolled);
    let mut v = base();
    v["approver"] = json!(key_id(&approver()));
    assert_eq!(e(sign_approval(v, &rogue())), ApprovalError::BadSignature);
    // tampered after signing
    let mut t = valve_approval("ap");
    let i = t.windows(7).position(|w| w == b"valve-1").unwrap();
    t[i + 6] = b'2';
    assert_eq!(e(t), ApprovalError::BadSignature);
    // window: 31 days is fine, more is not; inverted; expired
    let mut v = base();
    v["valid_until_ms"] = json!(NOW - 1000 + 31 * 86_400_000u64);
    let mut at_limit = act_gate(Stage::Actuate, ChunkOverrun::Veto);
    ok_ids.push(at_limit.install_approval(&sign(v), NOW).unwrap());
    let mut v = base();
    v["approval_id"] = json!("ap2");
    v["valid_until_ms"] = json!(NOW - 1000 + 31 * 86_400_000u64 + 1);
    assert_eq!(e(sign(v)), ApprovalError::BadWindow);
    let mut v = base();
    v["approval_id"] = json!("ap3");
    v["valid_until_ms"] = json!(NOW - 2000);
    assert_eq!(e(sign(v)), ApprovalError::BadWindow);
    let mut v = base();
    v["approval_id"] = json!("ap4");
    v["valid_from_ms"] = json!(NOW - 20_000);
    v["valid_until_ms"] = json!(NOW);
    assert_eq!(e(sign(v)), ApprovalError::Expired);
    // shapes: unsorted or duplicate ids, empty lists, too many, unknown kind, unknown member, bad class, bad id
    for (name, f) in [
        ("unsorted", Box::new(|v: &mut Value| v["actuator_ids"] = json!(["valve-2", "valve-1"])) as Box<dyn Fn(&mut Value)>),
        ("duplicate", Box::new(|v| v["actuator_ids"] = json!(["valve-1", "valve-1"]))),
        ("no actuators", Box::new(|v| v["actuator_ids"] = json!([]))),
        ("too many", Box::new(|v| v["actuator_ids"] = json!((0..65).map(|i| format!("a-{i:03}")).collect::<Vec<_>>()))),
        ("no kinds", Box::new(|v| v["kinds"] = json!([]))),
        ("unknown kind", Box::new(|v| v["kinds"] = json!(["mode"]))),
        ("kinds unsorted", Box::new(|v| v["kinds"] = json!(["trajectory", "setpoint"]))),
        ("unknown member", Box::new(|v| v["extra"] = json!(1))),
        ("bad class", Box::new(|v| v["system_class"] = json!("Hvac Valve"))),
        ("bad id", Box::new(|v| v["approval_id"] = json!("a b"))),
        ("string time", Box::new(|v| v["valid_until_ms"] = json!("1"))),
        ("wrong format", Box::new(|v| v["format"] = json!("physical-command"))),
        ("wrong version", Box::new(|v| v["v"] = json!(2))),
    ] {
        let mut v = base();
        v["approval_id"] = json!("shape");
        f(&mut v);
        assert_eq!(e(sign(v)), ApprovalError::Malformed, "{name}");
    }
    // not canonical
    let pretty = serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&valve_approval("ap9")).unwrap()).unwrap();
    assert_eq!(e(pretty), ApprovalError::NotCanonical);
    assert_eq!(e(b"nope".to_vec()), ApprovalError::Malformed);
}

#[test]
fn install_duplicate_revoke_and_the_ledger_entries() {
    let mut g = act_gate(Stage::Actuate, ChunkOverrun::Veto);
    let raw = valve_approval("ap-1");
    let n0 = g.chain().len();
    assert_eq!(g.install_approval(&raw, NOW), Ok("ap-1".into()));
    let e = g.chain().entries().last().unwrap();
    assert_eq!((e.kind, e.actor.as_str(), e.subject.as_str()), (OpKind::Command, "gate:site-test-01", "ap-1"));
    assert_eq!(e.result, format!("approval_installed:ok:{}", furcate_command::sha256_hex(&raw)));
    assert_eq!(g.install_approval(&raw, NOW), Err(ApprovalError::Duplicate));
    assert_eq!(g.chain().len(), n0 + 1);
    // Revocation takes effect at once and is ledgered.
    let mut x = Rec::default();
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut x).decision, Decision::Executed);
    g.revoke_approval("ap-1", NOW + 5).unwrap();
    let e = g.chain().entries().last().unwrap();
    assert_eq!((e.subject.as_str(), e.result.as_str()), ("ap-1", "approval_revoked:ok:ap-1"));
    let mut v = command_value(2);
    v["mode"] = json!("actuate");
    v["issued_at_ms"] = json!(NOW + 4_000);
    let r = g.decide_exec(&finish(v, &lw(), &lw()), NOW + 5, &mut x);
    assert_eq!(r.code, Some(ErrorCode::ActuationNotApproved));
    assert_eq!(x.calls.len(), 1);
    // Unknown id, and a revoked id is never installable again.
    assert_eq!(g.revoke_approval("ap-1", NOW), Err(ApprovalError::Unknown));
    assert_eq!(g.install_approval(&raw, NOW), Err(ApprovalError::Revoked));
    assert!(g.chain().verify().is_ok());
}

#[test]
fn a_removed_approver_makes_its_approvals_inert() {
    let g = approved(Stage::Actuate);
    let st = g.export_state();
    let mut cfg = act_cfg(Stage::Actuate);
    cfg.approvers.clear();
    let mut g = Gate::restore(traj_policy(ChunkOverrun::Veto), NoKill, key(SITE_SEED), Some(cfg), st).unwrap();
    let mut x = Rec::default();
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut x).code, Some(ErrorCode::ActuationNotApproved));
    assert!(x.calls.is_empty());
}

#[test]
fn a_truncated_chunk_releases_only_the_accepted_prefix() {
    let mut g = act_gate(Stage::Actuate, ChunkOverrun::Truncate { min_steps: 1 });
    g.install_approval(&arm_approval("ap-arm-1"), NOW).unwrap();
    let mut x = Rec::default();
    let mut v = traj_value(1, 0);
    v["mode"] = json!("actuate");
    v["body"]["steps"][12]["q"][5] = json!(ref_q(5, 12) + 0.3);
    let r = g.decide_exec(&finish_traj(v), NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Truncated, Some(ErrorCode::ChunkTruncated)));
    let Plan::Trajectory { dof, step_ms, steps } = &x.calls[0].3 else { panic!() };
    assert_eq!((*dof, *step_ms, steps.len()), (DOF, STEP_MS, 12));
    for (k, s) in steps.iter().enumerate() {
        assert_eq!(s[5], ref_q(5, k as i64));
    }
    let rv = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    assert_eq!(rv["chunk"]["steps_accepted"], 12);
    assert_eq!(rv["execution"]["writes"], 12);
    assert!(r.stop_request.is_some(), "the advisory stop request is still emitted for a truncated chunk");
    // A whole chunk is executed.
    let mut g = act_gate(Stage::Actuate, ChunkOverrun::Truncate { min_steps: 1 });
    g.install_approval(&arm_approval("ap-arm-1"), NOW).unwrap();
    let r = g.decide_exec(&actuate_chunk(1, 0), NOW, &mut x);
    assert_eq!(r.decision, Decision::Executed);
    let Plan::Trajectory { steps, .. } = &x.calls[1].3 else { panic!() };
    assert_eq!(steps.len(), STEPS);
    // A vetoed chunk releases nothing.
    let mut v = traj_value(2, 1);
    v["mode"] = json!("actuate");
    v["body"]["steps"][0]["q"][0] = json!(2.95);
    let r = g.decide_exec(&finish_traj(v), NOW, &mut x);
    assert_eq!(r.code, Some(ErrorCode::ChunkVetoed));
    assert_eq!(x.calls.len(), 2);
}

#[test]
fn a_failed_write_is_a_failed_receipt_and_still_consumes_the_sequence_number() {
    let mut g = approved(Stage::Actuate);
    let mut x = Rec { fail_after: Some(3), ..Default::default() };
    let raw = actuate_chunk(1, 0);
    let r = g.decide_exec(&raw, NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Failed, Some(ErrorCode::ExecutionFailed)));
    let v = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    assert_eq!((v["decision"].as_str(), v["error_code"].as_str()), (Some("failed"), Some("execution_failed")));
    assert_eq!((v["execution"]["writes"].as_u64(), v["execution"]["acked"].as_bool()), (Some(3), Some(false)));
    assert_eq!(g.last_seq(), 1);
    // No replay of the same command.
    assert_eq!(g.decide_exec(&raw, NOW, &mut x).code, Some(ErrorCode::ReplayedSequence));
    assert_eq!(x.calls.len(), 1);
    // The next chunk follows from where the failed one was accepted to end.
    x.fail_after = None;
    assert_eq!(g.decide_exec(&actuate_chunk(2, 1), NOW, &mut x).decision, Decision::Executed);
}

struct Switch(Arc<AtomicBool>);
impl KillState for Switch {
    fn is_killed(&self, _: &str, _: &str) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[test]
fn the_write_ahead_entry_is_in_the_chain_and_the_state_before_the_executor_runs() {
    let hooked = Arc::new(Mutex::new(Vec::<GateState>::new()));
    let h2 = hooked.clone();
    let mut g = approved(Stage::Actuate).with_release_hook(Box::new(move |s| {
        h2.lock().unwrap().push(s.clone());
        Ok(())
    }));
    struct Probe(Arc<Mutex<Vec<GateState>>>, bool);
    impl furcate_command::Executor for Probe {
        fn execute(&mut self, r: &furcate_command::Release) -> Result<furcate_command::Execution, furcate_command::ExecError> {
            let snaps = self.0.lock().unwrap();
            let s = snaps.last().expect("the hook ran before the executor");
            let last = s.chain.entries().last().unwrap();
            assert_eq!(last.seq, r.release_ledger_seq());
            assert!(last.result.starts_with("released:ok:"));
            assert_eq!(s.last_seq, 1, "the sequence was already consumed");
            self.1 = true;
            Ok(furcate_command::Execution { writes: 1 })
        }
    }
    let mut p = Probe(hooked, false);
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut p).decision, Decision::Executed);
    assert!(p.1);
    // A hook that cannot persist stops the release before any write; the receipt says failed with no writes.
    let mut g = approved(Stage::Actuate).with_release_hook(Box::new(|_| Err("disk full".into())));
    let mut x = Rec::default();
    let r = g.decide_exec(&actuate_setpoint(1), NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Failed, Some(ErrorCode::ExecutionFailed)));
    assert_eq!((r.value["execution"]["writes"].as_u64(), r.value["execution"]["acked"].as_bool()), (Some(0), Some(false)));
    assert!(x.calls.is_empty());
}

#[test]
fn the_kill_state_is_checked_again_immediately_before_release() {
    // Not killed at the first look, killed at the second.
    struct Flip(Cell<u32>);
    impl KillState for Flip {
        fn is_killed(&self, _: &str, _: &str) -> bool {
            self.0.set(self.0.get() + 1);
            self.0.get() >= 2
        }
    }
    let mut g = Gate::new(traj_policy(ChunkOverrun::Veto), Flip(Cell::new(0)), key(SITE_SEED), Chain::genesis("site-test-01", NOW - 10_000)).with_actuation(act_cfg(Stage::Actuate));
    g.install_approval(&valve_approval("ap"), NOW).unwrap();
    let mut x = Rec::default();
    let r = g.decide_exec(&actuate_setpoint(1), NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Killed, Some(ErrorCode::KillSwitchActive)));
    assert!(x.calls.is_empty());
    assert_eq!(g.last_seq(), 0);
    // A trajectory under a kill order still gets its advisory stop request.
    let flag = Arc::new(AtomicBool::new(true));
    let mut g = Gate::new(traj_policy(ChunkOverrun::Veto), Switch(flag.clone()), key(SITE_SEED), Chain::genesis("site-test-01", NOW - 10_000)).with_actuation(act_cfg(Stage::Actuate));
    g.install_approval(&arm_approval("ap"), NOW).unwrap();
    let r = g.decide_exec(&actuate_chunk(1, 0), NOW, &mut x);
    assert_eq!(r.code, Some(ErrorCode::KillSwitchActive));
    assert!(r.stop_request.is_some());
    assert!(x.calls.is_empty());
}

/// A signer that can be made to fail or to answer garbage.
#[derive(Clone)]
struct Flaky {
    k: ed25519_dalek::SigningKey,
    down: Arc<AtomicBool>,
    garbage: Arc<AtomicBool>,
}
impl SiteSigner for Flaky {
    fn key_id(&self) -> String {
        key_id(&self.k)
    }
    fn sign(&self, d: &[u8]) -> Result<[u8; 64], SignError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(SignError { reason: "key service unreachable".into() });
        }
        if self.garbage.load(Ordering::SeqCst) {
            return Ok([7u8; 64]);
        }
        SiteSigner::sign(&self.k, d)
    }
}

#[test]
fn a_signer_that_cannot_sign_releases_nothing_and_consumes_nothing() {
    let s = Flaky { k: key(SITE_SEED), down: Arc::new(AtomicBool::new(true)), garbage: Arc::new(AtomicBool::new(false)) };
    let mut g = Gate::with_signer(traj_policy(ChunkOverrun::Veto), NoKill, s.clone(), Chain::genesis("site-test-01", NOW - 10_000)).with_actuation(act_cfg(Stage::Actuate));
    g.install_approval(&valve_approval("ap"), NOW).unwrap();
    let n = g.chain().len();
    let mut x = Rec::default();
    let raw = actuate_setpoint(1);
    let r = g.decide_exec(&raw, NOW, &mut x);
    assert_eq!((r.decision, r.code), (Decision::Failed, Some(ErrorCode::ExecutionFailed)));
    assert!(r.signer_error.is_some() && r.bytes.is_empty());
    assert!(x.calls.is_empty());
    assert_eq!((g.chain().len(), g.last_seq(), g.receipts()), (n, 0, 0));
    // A signer that answers with a signature that does not verify is as bad.
    s.down.store(false, Ordering::SeqCst);
    s.garbage.store(true, Ordering::SeqCst);
    let r = g.decide_exec(&raw, NOW, &mut x);
    assert!(r.signer_error.is_some() && x.calls.is_empty() && g.chain().len() == n);
    // When it recovers, the same command goes through: nothing was consumed.
    s.garbage.store(false, Ordering::SeqCst);
    let r = g.decide_exec(&raw, NOW, &mut x);
    assert_eq!(r.decision, Decision::Executed);
    assert!(r.signer_error.is_none());
    assert!(verify_receipt(&r.bytes, &g.site_key_id()).is_ok());
}

#[test]
fn restart_keeps_replay_protection_approvals_and_the_chain() {
    let mut g = approved(Stage::Actuate);
    let mut x = Rec::default();
    assert_eq!(g.decide_exec(&actuate_setpoint(1), NOW, &mut x).decision, Decision::Executed);
    assert_eq!(g.decide_exec(&actuate_chunk(2, 0), NOW, &mut x).decision, Decision::Executed);
    g.revoke_approval("ap-valve-1", NOW).unwrap();
    let state = g.export_state();
    // Through JSON, as the service saves it.
    let text = serde_json::to_string(&state).unwrap();
    let state: GateState = serde_json::from_str(&text).unwrap();
    let mut g2 = Gate::restore(traj_policy(ChunkOverrun::Veto), NoKill, key(SITE_SEED), Some(act_cfg(Stage::Actuate)), state).unwrap();
    assert_eq!((g2.last_seq(), g2.receipts(), g2.chain().len()), (g.last_seq(), g.receipts(), g.chain().len()));
    // Replay of either executed command is refused, the executor is not called.
    let n = x.calls.len();
    assert_eq!(g2.decide_exec(&actuate_setpoint(1), NOW, &mut x).code, Some(ErrorCode::ActuationNotApproved));
    assert_eq!(g2.decide_exec(&actuate_chunk(2, 0), NOW, &mut x).code, Some(ErrorCode::ReplayedSequence));
    // The arm approval survived, the revoked valve approval did not come back.
    assert_eq!(g2.decide_exec(&actuate_chunk(3, 1), NOW, &mut x).decision, Decision::Executed);
    assert_eq!(g2.install_approval(&valve_approval("ap-valve-1"), NOW), Err(ApprovalError::Revoked));
    assert_eq!(g2.decide_exec(&actuate_setpoint(4), NOW, &mut x).code, Some(ErrorCode::ActuationNotApproved));
    assert_eq!(x.calls.len(), n + 1);
    // Chunk continuity survived: the chunk after the one at index 1 must start where it ended.
    assert!(g2.chain().verify().is_ok());
}

#[test]
fn a_corrupt_or_foreign_state_is_refused() {
    let mut g = approved(Stage::Actuate);
    let mut x = Rec::default();
    g.decide_exec(&actuate_setpoint(1), NOW, &mut x);
    let ok = g.export_state();
    let restore = |s: GateState| Gate::restore(traj_policy(ChunkOverrun::Veto), NoKill, key(SITE_SEED), Some(act_cfg(Stage::Actuate)), s).err();
    assert!(restore(ok.clone()).is_none());
    // A tampered chain entry.
    let mut v = serde_json::to_value(&ok).unwrap();
    v["chain"]["entries"][3]["result"] = json!("approval_installed:ok:00");
    let s: GateState = serde_json::from_value(v).unwrap();
    assert!(matches!(restore(s), Some(RestoreError::Chain(_))));
    // A removed entry.
    let mut v = serde_json::to_value(&ok).unwrap();
    v["chain"]["entries"].as_array_mut().unwrap().remove(2);
    let s: GateState = serde_json::from_value(v).unwrap();
    assert!(matches!(restore(s), Some(RestoreError::Chain(_))));
    // An empty chain.
    let mut s = ok.clone();
    s.chain = Chain::new();
    assert!(matches!(restore(s), Some(RestoreError::Chain(_))));
    // Another site or tenant.
    let mut s = ok.clone();
    s.site_id = "site-other".into();
    assert_eq!(restore(s), Some(RestoreError::WrongSite));
    let mut s = ok.clone();
    s.tenant = "tenant-b".into();
    assert_eq!(restore(s), Some(RestoreError::WrongTenant));
    let mut s = ok.clone();
    s.v = 9;
    assert_eq!(restore(s), Some(RestoreError::Version));
    // An approval smuggled into the state with no matching ledger entry (signature valid).
    let mut s = ok.clone();
    s.approvals.push(String::from_utf8(sign_approval(approval_value("smuggled", "hvac_valve", &["valve-1"], &["setpoint"]), &approver())).unwrap());
    assert_eq!(restore(s), Some(RestoreError::ApprovalNotInChain("smuggled".into())));
    // An installed approval whose record was altered.
    let mut s = ok.clone();
    s.approvals[0] = s.approvals[0].replace("valve-1", "valve-2");
    assert!(matches!(restore(s), Some(RestoreError::Approval(_))));
    // A revoked id the chain never revoked.
    let mut s = ok.clone();
    s.revoked_approvals.push("never".into());
    assert_eq!(restore(s), Some(RestoreError::ApprovalNotInChain("never".into())));
    // An approval listed as installed that the chain revoked.
    let mut g3 = approved(Stage::Actuate);
    g3.revoke_approval("ap-valve-1", NOW).unwrap();
    let mut s = g3.export_state();
    s.revoked_approvals.clear();
    s.approvals.push(String::from_utf8(valve_approval("ap-valve-1")).unwrap());
    assert_eq!(restore(s), Some(RestoreError::ApprovalNotInChain("ap-valve-1".into())));
}

#[test]
fn a_mutated_pristine_actuate_command_never_reaches_the_executor() {
    // Bit flips of an approved actuate command: only the unchanged bytes may release, once.
    let raw = actuate_setpoint(1);
    let mut x = Rec::default();
    let mut released = 0;
    for i in (0..raw.len()).step_by(5) {
        let mut m = raw.clone();
        m[i] ^= 1 << (i % 8);
        let mut g = approved(Stage::Actuate);
        let r = g.decide_exec(&m, NOW, &mut x);
        if r.decision == Decision::Executed {
            released += 1;
        }
    }
    assert_eq!((released, x.calls.len()), (0, 0));
    let mut g = approved(Stage::Actuate);
    assert_eq!(g.decide_exec(&raw, NOW, &mut x).decision, Decision::Executed);
    let _ = bytes(&json!({}));
    let _: Option<ActuationConfig> = None;
}
