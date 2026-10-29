//! Trajectory commands: the chunk-level gate. Every verdict names the first violating step and the limit.

mod common;
use common::*;
use furcate_command::{verify_receipt, verify_stop_request, ChunkOutcome, ChunkOverrun, Decision, ErrorCode, KillState, LimitKind, Gate};
use furcate_ledger::{Chain, OpKind};
use serde_json::{json, Value};

fn decide_with(mutate: impl FnOnce(&mut Value), o: ChunkOverrun) -> (furcate_command::Receipt, Gate<furcate_command::NoKill>) {
    let mut v = traj_value(1, 0);
    mutate(&mut v);
    let mut g = traj_gate_with(o);
    let r = g.decide(&finish_traj(v), NOW);
    (r, g)
}
fn decide(mutate: impl FnOnce(&mut Value)) -> furcate_command::Receipt {
    decide_with(mutate, ChunkOverrun::Veto).0
}

#[test]
fn a_valid_chunk_is_shadowed_whole_and_receipted() {
    let mut g = traj_gate();
    let r = g.decide(&valid_chunk(1, 0), NOW);
    assert_eq!((r.decision, r.code), (Decision::Shadowed, None));
    let v = r.verdict.clone().unwrap();
    assert_eq!((v.outcome, v.steps_total, v.steps_accepted, v.first_violation), (ChunkOutcome::Accepted, STEPS, STEPS, None));
    assert!(r.stop_request.is_none());
    let rv = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    assert_eq!(rv["chunk"]["outcome"], "accepted");
    assert_eq!(rv["chunk"]["steps_accepted"], STEPS);
    assert_eq!(rv["stop_request_sha256"], Value::Null);
    assert_eq!(g.chain().entries().last().unwrap().kind, OpKind::Command);
    assert!(g.chain().verify().is_ok());
}

#[test]
fn setpoint_receipts_do_not_change() {
    let mut g = gate();
    let r = g.decide(&valid(1), NOW);
    assert!(r.value.get("chunk").is_none() && r.value.get("stop_request_sha256").is_none());
    assert!(r.verdict.is_none() && r.stop_request.is_none());
}

#[test]
fn consecutive_chunks_join_and_the_sequence_advances() {
    let mut g = traj_gate();
    for c in 0..3u64 {
        let r = g.decide(&valid_chunk(c + 1, c), NOW);
        assert_eq!((r.decision, r.code), (Decision::Shadowed, None), "chunk {c}");
    }
    assert_eq!(g.last_seq(), 3);
}

fn first(r: &furcate_command::Receipt) -> (Option<usize>, Option<usize>, LimitKind, &'static str) {
    let v = r.verdict.clone().unwrap().first_violation.unwrap();
    (v.step, v.joint, v.limit, v.source.as_str())
}

#[test]
fn each_limit_is_named_with_its_step_and_joint() {
    use LimitKind::*;
    // Position over the site maximum at step 7, joint 3 (the sender's own limit is looser).
    let r = decide(|v| v["body"]["steps"][7]["q"][3] = json!(2.85));
    assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::ChunkVetoed)));
    assert_eq!(first(&r), (Some(7), Some(3), Position, "site"));
    let r = decide(|v| v["body"]["steps"][7]["q"][3] = json!(-2.85));
    assert_eq!(first(&r), (Some(7), Some(3), Position, "site"));
    // Position past the sender's own, tighter limit.
    let r = decide(|v| v["body"]["limits"]["q_max"] = json!(vec![0.2; DOF]));
    assert_eq!(first(&r).2, Position);
    assert_eq!(first(&r).3, "sender");
    // A jump of 0.3 rad in one 20 ms step is 15 rad/s.
    let r = decide(|v| v["body"]["steps"][12]["q"][5] = json!(ref_q(5, 12) + 0.3));
    assert_eq!(first(&r), (Some(12), Some(5), Velocity, "site"));
    // Effort and workspace.
    let r = decide(|v| v["body"]["steps"][20]["tau"][2] = json!(-41.0));
    assert_eq!(first(&r), (Some(20), Some(2), Effort, "site"));
    let r = decide(|v| v["body"]["steps"][3]["xyz"][1] = json!(0.85));
    assert_eq!(first(&r), (Some(3), Some(1), Workspace, "site"));
    // Acceleration: a velocity of 0.9 rad/s (inside the 1.0 limit) reached from rest in one step is 45 rad/s^2.
    let r = decide(|v| {
        v["body"]["start"]["q"][0] = json!(0.0);
        v["body"]["start"]["dq"][0] = json!(0.0);
        v["body"]["start"]["ddq"][0] = json!(0.0);
        v["body"]["steps"][0]["q"][0] = json!(0.018);
    });
    assert_eq!(first(&r), (Some(0), Some(0), Acceleration, "site"));
    // Jerk: tighten the site jerk limit below what the reference motion needs.
    let mut p = traj_policy(ChunkOverrun::Veto);
    p.trajectory_limits[0].dddq_max = vec![1.0; DOF];
    let mut g = Gate::new(p, furcate_command::NoKill, key(SITE_SEED), Chain::genesis("site-test-01", NOW));
    let r = g.decide(&valid_chunk(1, 0), NOW);
    assert_eq!(r.verdict.unwrap().first_violation.unwrap().limit, Jerk);
}

#[test]
fn the_first_violating_step_wins() {
    let r = decide(|v| {
        v["body"]["steps"][30]["tau"][0] = json!(99.0);
        v["body"]["steps"][9]["xyz"][0] = json!(0.95);
        v["body"]["steps"][9]["q"][1] = json!(2.9);
    });
    // Step 9 is first; within it position comes before workspace.
    assert_eq!(first(&r), (Some(9), Some(1), LimitKind::Position, "site"));
}

#[test]
fn a_vetoed_chunk_gets_an_advisory_stop_request_to_the_named_safety_controller() {
    let (r, g) = decide_with(|v| v["body"]["steps"][7]["q"][3] = json!(2.85), ChunkOverrun::Veto);
    let sr = r.stop_request.clone().expect("stop request");
    let v = verify_stop_request(&sr, &g.site_key_id()).unwrap();
    assert_eq!(v["reason"], "chunk_vetoed");
    assert_eq!(v["safety_controller_id"], "safety-plc-1");
    assert_eq!(v["requested_stop"], "ss1");
    assert_eq!(v["advisory"], true);
    assert_eq!(v["emergency_stop"], false);
    assert_eq!(v["first_violation"]["step"], 7);
    assert_eq!(v["first_violation"]["limit"], "position");
    // The receipt commits to the exact stop request.
    let rv = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    assert_eq!(rv["stop_request_sha256"], furcate_command::sha256_hex(&sr));
    // Only the site key verifies it, and a changed byte does not.
    assert!(verify_stop_request(&sr, &furcate_command::issue::key_id(&lw())).is_err());
    let mut t = sr.clone();
    let i = t.windows(4).position(|w| w == b"true").unwrap();
    t[i..i + 4].copy_from_slice(b"fals");
    assert!(verify_stop_request(&t, &g.site_key_id()).is_err());
    // A receipt is not a stop request, nor the reverse.
    assert!(verify_stop_request(&r.bytes, &g.site_key_id()).is_err());
    assert!(verify_receipt(&sr, &g.site_key_id()).is_err());
}

#[test]
fn a_stop_request_cannot_claim_to_be_an_emergency_stop() {
    let (r, g) = decide_with(|v| v["body"]["steps"][7]["q"][3] = json!(2.85), ChunkOverrun::Veto);
    let mut v: Value = furcate_command::canon::parse_canonical(&r.stop_request.unwrap()).unwrap();
    v["emergency_stop"] = json!(true);
    v.as_object_mut().unwrap().remove("signature");
    // Even re-signed by the site key itself, the verifier refuses a record that claims to be an emergency stop.
    let site = key(SITE_SEED);
    furcate_command::issue::sign_value(&mut v, furcate_command::STOP_REQUEST_DOMAIN, &site).unwrap();
    assert!(verify_stop_request(&furcate_command::issue::bytes(&v), &g.site_key_id()).is_err());
}

#[test]
fn truncation_keeps_the_prefix_before_the_first_violation() {
    let (r, g) = decide_with(|v| v["body"]["steps"][12]["q"][5] = json!(ref_q(5, 12) + 0.3), ChunkOverrun::Truncate { min_steps: 1 });
    assert_eq!((r.decision, r.code), (Decision::Truncated, Some(ErrorCode::ChunkTruncated)));
    let v = r.verdict.clone().unwrap();
    assert_eq!((v.outcome, v.steps_accepted, v.steps_total), (ChunkOutcome::Truncated, 12, STEPS));
    assert_eq!(v.first_violation.unwrap().step, Some(12));
    // The rest is not authorised, so a stop request goes out.
    let sr = verify_stop_request(&r.stop_request.unwrap(), &g.site_key_id()).unwrap();
    assert_eq!(sr["reason"], "chunk_truncated");
    assert_eq!(g.last_seq(), 1);
    let rv = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    assert_eq!(rv["decision"], "truncated");
    assert_eq!(rv["chunk"]["steps_accepted"], 12);
}

#[test]
fn truncation_below_the_minimum_is_a_veto_and_whole_chunk_faults_always_veto() {
    // Violation at step 12 with a required prefix of 20.
    let (r, _) = decide_with(|v| v["body"]["steps"][12]["q"][5] = json!(ref_q(5, 12) + 0.3), ChunkOverrun::Truncate { min_steps: 20 });
    assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::ChunkVetoed)));
    assert_eq!(r.verdict.unwrap().steps_accepted, 0);
    // Violation at step 0.
    let (r, _) = decide_with(|v| v["body"]["steps"][0]["q"][0] = json!(2.9), ChunkOverrun::Truncate { min_steps: 1 });
    assert_eq!(r.code, Some(ErrorCode::ChunkVetoed));
    // Whole-chunk faults veto even when truncation is allowed.
    let t = ChunkOverrun::Truncate { min_steps: 1 };
    let (r, _) = decide_with(|v| v["body"]["step_ms"] = json!(150), t);
    assert_eq!((r.code, first(&r).2), (Some(ErrorCode::ChunkVetoed), LimitKind::StepRate));
    let (r, _) = decide_with(|v| v["body"]["step_ms"] = json!(2), t);
    assert_eq!(first(&r).2, LimitKind::StepRate);
    let (r, _) = decide_with(|v| {
        let s = v["body"]["steps"].as_array().unwrap().clone();
        let mut all = s.clone();
        all.extend(s.clone());
        all.extend(s);
        v["body"]["steps"] = json!(all);
    }, t);
    assert_eq!(first(&r).2, LimitKind::ChunkLength);
    let (r, _) = decide_with(|v| v["body"]["steps"].as_array_mut().unwrap().iter_mut().for_each(|s| { s.as_object_mut().unwrap().remove("tau"); }), t);
    assert_eq!(first(&r).2, LimitKind::MissingField);
    let (r, _) = decide_with(|v| v["target"]["actuator_id"] = json!("arm-9"), t);
    assert_eq!(r.code, Some(ErrorCode::NoSiteLimit));
}

#[test]
fn degrees_of_freedom_must_match_the_site() {
    // Six joints everywhere: a well-formed chunk for the wrong arm.
    let r = decide(|v| {
        v["body"]["dof"] = json!(6);
        for k in ["steps"] {
            for s in v["body"][k].as_array_mut().unwrap() {
                for m in ["q", "tau"] {
                    s[m].as_array_mut().unwrap().pop();
                }
            }
        }
        for m in ["q", "dq", "ddq"] {
            v["body"]["start"][m].as_array_mut().unwrap().pop();
        }
        for m in ["q_min", "q_max", "dq_max", "ddq_max", "dddq_max", "tau_max"] {
            v["body"]["limits"][m].as_array_mut().unwrap().pop();
        }
    });
    assert_eq!(first(&r).2, LimitKind::Dof);
}

#[test]
fn a_chunk_must_start_where_the_last_accepted_one_ended() {
    let mut g = traj_gate();
    assert_eq!(g.decide(&valid_chunk(1, 0), NOW).decision, Decision::Shadowed);
    let mut v = traj_value(2, 1);
    v["body"]["start"]["q"][4] = json!(ref_q(4, 49) + 0.01); // 0.01 rad away against a tolerance of 0.005
    let r = g.decide(&finish_traj(v), NOW);
    assert_eq!(r.code, Some(ErrorCode::ChunkVetoed));
    assert_eq!(first(&r), (None, Some(4), LimitKind::Continuity, "site"));
    // A refused chunk does not move the recorded end state or the sequence.
    assert_eq!(g.last_seq(), 1);
    assert_eq!(g.decide(&valid_chunk(2, 1), NOW).decision, Decision::Shadowed);
}

#[test]
fn chunks_may_not_arrive_faster_than_the_site_allows() {
    let mut g = traj_gate();
    assert_eq!(g.decide(&valid_chunk(1, 0), NOW).decision, Decision::Shadowed);
    let mut v = traj_value(2, 1);
    v["issued_at_ms"] = json!(NOW - 3_000 + 50); // 50 ms after chunk 0 against a minimum of 100
    v["not_before_ms"] = json!(NOW - 3_000 + 50);
    let r = g.decide(&finish_traj(v), NOW);
    assert_eq!(first(&r).2, LimitKind::ChunkInterval);
}

#[test]
fn the_chunk_names_the_band_certificate_it_was_planned_inside() {
    let r = decide(|v| v["body"]["twin_cert_sha256"] = json!("7".repeat(64)));
    let _ = r;
    let mut v = traj_value(1, 0);
    v["body"]["twin_cert_sha256"] = json!("7".repeat(64));
    let mut g = traj_gate();
    let r = g.decide(&finish_traj_with(v, &lw(), &lw(), true), NOW);
    assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::BandReferenceMismatch)));
}

#[test]
fn positions_outside_the_certified_band_are_named() {
    // The certificate certifies only +-0.01 rad: step 0 is already outside.
    let r = decide(|v| v["twin_cert"]["ranges"][0] = json!({"quantity": "joint_position", "unit": "radian", "min": -0.01, "max": 0.01}));
    assert_eq!(first(&r).2, LimitKind::CertifiedBand);
    assert_eq!(first(&r).0, Some(0));
    // No effort range at all while the chunk carries effort: default deny.
    let r = decide(|v| { v["twin_cert"]["ranges"].as_array_mut().unwrap().pop(); });
    assert_eq!(first(&r).2, LimitKind::CertifiedBand);
}

#[test]
fn the_start_state_is_inside_the_limits_too() {
    let r = decide(|v| v["body"]["start"]["dq"][2] = json!(1.2));
    assert_eq!(first(&r), (None, Some(2), LimitKind::Velocity, "site"));
}

#[test]
fn model_policy_and_birth_record_checks_apply_per_chunk() {
    assert_eq!(decide(|v| v["model_sha256"] = json!("5".repeat(64))).code, Some(ErrorCode::ModelNotApproved));
    assert_eq!(decide(|v| v["policy_sha256"] = json!("4".repeat(64))).code, Some(ErrorCode::PolicyHashMismatch));
    assert_eq!(decide(|v| v.as_object_mut().unwrap().remove("birth_record_sha256").map(|_| ()).unwrap()).code, Some(ErrorCode::BirthRecordRequired));
    // The model hash is signed with the chunk, so it cannot be swapped without the signature failing.
    let mut v: Value = furcate_command::canon::parse_canonical(&valid_chunk(1, 0)).unwrap();
    v["model_sha256"] = json!(MODEL_HASH.replace('2', "3"));
    let mut g = traj_gate();
    assert_eq!(g.decide(&furcate_command::issue::bytes(&v), NOW).code, Some(ErrorCode::BadSignature));
}

#[test]
fn actuation_is_refused_for_a_chunk_that_is_otherwise_perfect() {
    let r = decide(|v| v["mode"] = json!("actuate"));
    assert_eq!((r.decision, r.code), (Decision::Denied, Some(ErrorCode::ActuationNotApproved)));
    assert!(r.stop_request.is_none());
}

#[test]
fn a_trajectory_without_an_envelope_member_is_the_only_valid_shape() {
    let mut v = traj_value(1, 0);
    v["envelope"] = json!({"min": 0, "max": 1, "max_rate_per_s": 1});
    let mut g = traj_gate();
    assert_eq!(g.decide(&finish_traj(v), NOW).code, Some(ErrorCode::Malformed));
}

struct KillAll;
impl KillState for KillAll {
    fn is_killed(&self, _: &str, _: &str) -> bool {
        true
    }
}

#[test]
fn a_kill_order_yields_a_stop_request_and_no_acceptance() {
    let mut g = Gate::new(traj_policy(ChunkOverrun::Veto), KillAll, key(SITE_SEED), Chain::genesis("site-test-01", NOW));
    let r = g.decide(&valid_chunk(1, 0), NOW);
    assert_eq!((r.decision, r.code), (Decision::Killed, Some(ErrorCode::KillSwitchActive)));
    let v = verify_stop_request(&r.stop_request.unwrap(), &g.site_key_id()).unwrap();
    assert_eq!((v["reason"].as_str(), v["first_violation"].is_null()), (Some("kill_switch_active"), true));
    assert_eq!(g.last_seq(), 0);
}

#[test]
fn nothing_can_make_a_chunk_execute() {
    for o in [ChunkOverrun::Veto, ChunkOverrun::Truncate { min_steps: 1 }] {
        let mut g = traj_gate_with(o);
        for (i, m) in [0usize, 5, 11].iter().enumerate() {
            let mut v = traj_value(i as u64 + 1, i as u64);
            if *m > 0 {
                v["body"]["steps"][*m]["q"][0] = json!(ref_q(0, *m as i64 + (i * STEPS) as i64) + 0.4);
            }
            let r = g.decide(&finish_traj(v), NOW);
            assert_ne!(r.decision, Decision::Executed);
        }
    }
}

#[test]
fn decision_time_for_one_chunk() {
    // Informational: a 50-step, 7-joint chunk is one chunk period (1,000 ms at 50 Hz) of motion. The gate must act
    // inside a small fraction of it.
    let raw = valid_chunk(1, 0);
    let n = 200;
    let t = std::time::Instant::now();
    for _ in 0..n {
        let mut g = traj_gate();
        assert_eq!(g.decide(&raw, NOW).decision, Decision::Shadowed);
    }
    let per = t.elapsed() / n;
    println!("CHUNK-DECISION bytes={} steps={} dof={} per_decision={:?} profile={}", raw.len(), STEPS, DOF, per, if cfg!(debug_assertions) { "debug" } else { "release" });
    assert!(per.as_millis() < CHUNK_MS as u128, "slower than one chunk period");
}
