//! Fault injection for trajectory chunks (20 steps by 7 joints per chunk). A seeded generator mutates valid chunks in the ways a faulty or hostile
//! policy host could, and the gate must never accept one: zero false accepts. Case count: 20,000 in a debug-profile
//! run and 1,000,000 in a release run; FAULT_CASES overrides either.
//!
//! Three kinds of case. Byte-level mutations of the signed bytes. Structural mutations that are re-signed, so the
//! signature is good and only the content is wrong. Designed violations, where the generator knows the step, the
//! joint and the limit the gate must name; for those the verdict is compared with the expectation, and under a
//! truncating policy the accepted prefix must be exactly the steps before the violation. Controls must be accepted
//! whole. Every mutant that is vetoed or truncated must come with a stop request that verifies.

mod common;
use common::*;
use furcate_command::canon::canonical;
use furcate_command::issue::{key_id, sign_value};
use furcate_command::{verify_stop_request, ChunkOutcome, ChunkOverrun, Decision, Gate, KillState, LimitKind, NoKill, Receipt, COMMAND_DOMAIN};
use furcate_ledger::Chain;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SEED: u64 = 0x5eed_1029_c4a2_0001;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct KillAll;
impl KillState for KillAll {
    fn is_killed(&self, _: &str, _: &str) -> bool {
        true
    }
}

/// What the gate must say about a designed violation.
#[derive(Clone, Copy)]
struct Expect {
    step: Option<usize>,
    limit: LimitKind,
}

struct Case {
    cat: &'static str,
    prior: Option<Vec<u8>>,
    input: Vec<u8>,
    now: u64,
    kill: bool,
    control: bool,
    truncate: bool,
    expect: Option<Expect>,
}

fn resign(mut v: Value, cert_changed: bool, fix_hash: bool) -> Vec<u8> {
    if cert_changed && v.get("twin_cert").is_some_and(|c| c.is_object()) {
        let mut c = v["twin_cert"].take();
        c["signer"] = json!(key_id(&lw()));
        if sign_value(&mut c, furcate_command::CERT_DOMAIN, &lw()).is_err() {
            return b"{}".to_vec();
        }
        if fix_hash {
            if let Some(b) = v.get_mut("body").and_then(|b| b.as_object_mut()) {
                if b.contains_key("twin_cert_sha256") {
                    b.insert("twin_cert_sha256".into(), json!(furcate_command::sha256_hex(canonical(&c).unwrap().as_bytes())));
                }
            }
        }
        v["twin_cert"] = c;
    }
    v["signer"] = json!(key_id(&lw()));
    if sign_value(&mut v, COMMAND_DOMAIN, &lw()).is_err() {
        return b"{}".to_vec();
    }
    match canonical(&v) {
        Ok(s) => s.into_bytes(),
        Err(_) => b"{}".to_vec(),
    }
}

const CATS: usize = 38;
/// Steps per chunk in this suite: shorter than a production chunk (50) so a debug run stays short.
const N: usize = 20;

fn gen(index: u64, base: &Value, base_bytes: &[u8]) -> Case {
    let mut r = Rng(SEED ^ index.wrapping_mul(0xd1b5_4a32_d192_ed03));
    let cat = r.below(CATS);
    let truncate = r.below(2) == 0;
    let mut case = Case { cat: "", prior: None, input: base_bytes.to_vec(), now: NOW, kill: false, control: false, truncate, expect: None };
    let b = base_bytes.to_vec();
    let step = r.below(N);
    let joint = r.below(DOF);
    let mut v = base.clone();
    let designed = |case: &mut Case, name: &'static str, i: Option<usize>, limit: LimitKind| {
        case.cat = name;
        case.expect = Some(Expect { step: i, limit });
    };
    match cat {
        0 => {
            case.cat = "control";
            case.control = true;
        }
        1 => {
            case.cat = "bit_flip";
            let i = r.below(b.len());
            case.input[i] ^= 1 << r.below(8);
        }
        2 => {
            case.cat = "truncate_bytes";
            case.input.truncate(r.below(b.len()));
        }
        3 => {
            case.cat = "duplicate_bytes";
            let a = r.below(b.len());
            let l = 1 + r.below(60.min(b.len() - a));
            let chunk = b[a..a + l].to_vec();
            case.input.splice(a..a, chunk);
        }
        4 => {
            case.cat = "delete_byte";
            case.input.remove(r.below(b.len()));
        }
        5 => {
            case.cat = "insert_byte";
            let x = r.next() as u8;
            case.input.insert(r.below(b.len() + 1), x);
        }
        6 => {
            case.cat = "whitespace_or_pretty";
            if r.below(2) == 0 {
                case.input.insert(r.below(b.len() + 1), b' ');
            } else {
                case.input = serde_json::to_vec_pretty(base).unwrap();
            }
        }
        7 => {
            case.cat = "swap_bytes";
            let (i, j) = (r.below(b.len()), r.below(b.len()));
            case.input.swap(i, j);
            if case.input == b {
                case.control = true;
            }
        }
        // ---- designed violations, re-signed ----
        8 => {
            designed(&mut case, "position_over_max", Some(step), LimitKind::Position);
            v["body"]["steps"][step]["q"][joint] = json!(2.8 + 0.001 + r.unit() * 0.09); // sender limit is 2.9
            case.input = resign(v, false, false);
        }
        9 => {
            designed(&mut case, "position_under_min", Some(step), LimitKind::Position);
            v["body"]["steps"][step]["q"][joint] = json!(-2.8 - 0.001 - r.unit() * 0.09);
            case.input = resign(v, false, false);
        }
        10 => {
            designed(&mut case, "velocity_jump", Some(step), LimitKind::Velocity);
            let d = 0.03 + r.unit() * 0.4;
            let q = ref_q(joint, step as i64) + if r.below(2) == 0 { d } else { -d };
            v["body"]["steps"][step]["q"][joint] = json!(q);
            case.input = resign(v, false, false);
        }
        11 => {
            designed(&mut case, "effort_over", Some(step), LimitKind::Effort);
            let x = 40.001 + r.unit() * 4.0; // sender limit is 45
            v["body"]["steps"][step]["tau"][joint] = json!(if r.below(2) == 0 { x } else { -x });
            case.input = resign(v, false, false);
        }
        12 => {
            designed(&mut case, "workspace_out", Some(step), LimitKind::Workspace);
            let k = r.below(3);
            let hi = [0.8, 0.8, 1.2][k];
            v["body"]["steps"][step]["xyz"][k] = json!(hi + 0.001 + r.unit() * 0.09);
            case.input = resign(v, false, false);
        }
        13 => {
            designed(&mut case, "step_period_out_of_range", None, LimitKind::StepRate);
            v["body"]["step_ms"] = json!([1, 2, 3, 4, 101, 150, 500, 1000][r.below(8)]);
            case.input = resign(v, false, false);
        }
        14 => {
            designed(&mut case, "chunk_too_long", None, LimitKind::ChunkLength);
            let s = v["body"]["steps"].as_array().unwrap().clone();
            let extra = 81 + r.below(100);
            let mut all = s.clone();
            while all.len() < N + extra {
                all.push(s[r.below(N)].clone());
            }
            v["body"]["steps"] = json!(all);
            case.input = resign(v, false, false);
        }
        15 => {
            designed(&mut case, "tau_missing", None, LimitKind::MissingField);
            for s in v["body"]["steps"].as_array_mut().unwrap() {
                s.as_object_mut().unwrap().remove("tau");
            }
            case.input = resign(v, false, false);
        }
        16 => {
            designed(&mut case, "xyz_missing", None, LimitKind::MissingField);
            for s in v["body"]["steps"].as_array_mut().unwrap() {
                s.as_object_mut().unwrap().remove("xyz");
            }
            case.input = resign(v, false, false);
        }
        17 => {
            designed(&mut case, "start_velocity_over", None, LimitKind::Velocity);
            v["body"]["start"]["dq"][joint] = json!(1.001 + r.unit());
            case.input = resign(v, false, false);
        }
        18 => {
            designed(&mut case, "start_acceleration_over", None, LimitKind::Acceleration);
            v["body"]["start"]["ddq"][joint] = json!(4.001 + r.unit() * 3.0);
            case.input = resign(v, false, false);
        }
        19 => {
            designed(&mut case, "sender_limit_tighter", Some(0), LimitKind::Position);
            // The sender's own position limit is below the first step of one joint.
            let q0 = ref_q(joint, 0);
            v["body"]["limits"]["q_max"][joint] = json!(q0 - 0.001 - r.unit() * 0.02);
            case.input = resign(v, false, false);
        }
        20 => {
            designed(&mut case, "band_narrowed", Some(0), LimitKind::CertifiedBand);
            v["twin_cert"]["ranges"][0] = json!({"quantity": "joint_position", "unit": "radian", "min": -0.01 - r.unit() * 0.01, "max": 0.0});
            case.input = resign(v, true, true);
        }
        21 => {
            designed(&mut case, "band_reference_wrong", None, LimitKind::Dof);
            case.expect = None; // refused with its own code, no verdict
            v["body"]["twin_cert_sha256"] = json!(format!("{:064x}", r.next()));
            case.input = resign(v, false, false);
        }
        22 => {
            designed(&mut case, "continuity_gap", None, LimitKind::Continuity);
            case.prior = Some(valid_chunk_n(1, 0, N));
            let mut w = traj_value_n(2, 1, N);
            let d = 0.0051 + r.unit() * 0.5;
            let cur = w["body"]["start"]["q"][joint].as_f64().unwrap();
            w["body"]["start"]["q"][joint] = json!(cur + d);
            case.input = resign_hash(w);
        }
        23 => {
            designed(&mut case, "chunks_too_close", None, LimitKind::ChunkInterval);
            case.prior = Some(valid_chunk_n(1, 0, N));
            let mut w = traj_value_n(2, 1, N);
            let at = NOW - 3_000 + r.below(99) as u64;
            w["issued_at_ms"] = json!(at);
            w["not_before_ms"] = json!(at);
            case.input = resign_hash(w);
        }
        24 => {
            designed(&mut case, "dof_mismatch", None, LimitKind::Dof);
            v["body"]["dof"] = json!(DOF - 1);
            for s in v["body"]["steps"].as_array_mut().unwrap() {
                s["q"].as_array_mut().unwrap().pop();
                s["tau"].as_array_mut().unwrap().pop();
            }
            for m in ["q", "dq", "ddq"] {
                v["body"]["start"][m].as_array_mut().unwrap().pop();
            }
            for m in ["q_min", "q_max", "dq_max", "ddq_max", "dddq_max", "tau_max"] {
                v["body"]["limits"][m].as_array_mut().unwrap().pop();
            }
            case.input = resign(v, false, false);
        }
        25 => {
            case.cat = "malformed_body";
            match r.below(8) {
                0 => v["body"]["steps"] = json!([]),
                1 => v["body"]["steps"][step]["q"] = json!(1.0),
                2 => v["body"]["steps"][step]["q"][joint] = json!("0.1"),
                3 => v["body"]["steps"][step]["q"][joint] = json!(1e10),
                4 => v["body"]["extra"] = json!(1),
                5 => v["body"]["step_ms"] = json!(0),
                6 => v["body"]["dof"] = json!(0),
                _ => {
                    v["body"]["steps"][step].as_object_mut().unwrap().remove("q");
                }
            }
            case.input = resign(v, false, false);
        }
        26 => {
            case.cat = "mixed_optional_members";
            v["body"]["steps"][step].as_object_mut().unwrap().remove(["tau", "xyz"][r.below(2)]);
            case.input = resign(v, false, false);
        }
        27 => {
            case.cat = "actuate";
            v["mode"] = json!("actuate");
            case.input = resign(v, false, false);
        }
        28 => {
            case.cat = "model_or_policy";
            if r.below(2) == 0 {
                v["model_sha256"] = json!(format!("{:064x}", r.next()));
            } else {
                v["policy_sha256"] = json!(format!("{:064x}", r.next()));
            }
            case.input = resign(v, false, false);
        }
        29 => {
            case.cat = "birth_record";
            if r.below(2) == 0 {
                v.as_object_mut().unwrap().remove("birth_record_sha256");
            } else {
                v["birth_record_sha256"] = json!(format!("{:064x}", r.next()));
            }
            case.input = resign(v, false, false);
        }
        30 => {
            case.cat = "wrong_site_tenant";
            match r.below(3) {
                0 => v["site_id"] = json!("site-other"),
                1 => v["tenant"] = json!("tenant-b"),
                _ => v["twin_cert"]["tenant"] = json!("tenant-b"),
            }
            case.input = resign(v, true, true);
        }
        31 => {
            case.cat = "time";
            match r.below(4) {
                0 => case.now = NOW + 60_000 + r.below(1000) as u64,
                1 => case.now = NOW - 10_000_000,
                2 => v["expires_at_ms"] = json!(NOW + 400_000),
                _ => v["twin_cert"]["valid_until_ms"] = json!(NOW + 30_000),
            }
            case.input = resign(v, true, true);
        }
        32 => {
            case.cat = "cert_fidelity";
            v["twin_cert"]["fidelity_score"] = json!(r.below(80) as f64 / 100.0);
            case.input = resign(v, true, true);
        }
        33 => {
            case.cat = "unknown_signer";
            case.input = finish_traj_with(base.clone(), &lw(), &rogue(), false);
            if r.below(2) == 0 {
                case.input = finish_traj_with(base.clone(), &rogue(), &lw(), false);
            }
        }
        34 => {
            case.cat = "kill_switch";
            case.kill = true;
        }
        35 => {
            case.cat = "command_seq";
            v["command_seq"] = [json!(0), json!(-1), json!(1.5), json!("1"), json!(9007199254740993u64)][r.below(5)].clone();
            case.input = resign(v, false, false);
            if r.below(2) == 0 {
                case.prior = Some(valid_chunk_n(5, 0, N));
                let mut w = base.clone();
                w["command_seq"] = json!(r.below(6) as u64);
                case.input = resign(w, false, false);
            }
        }
        36 => {
            case.cat = "kind_or_envelope";
            match r.below(3) {
                0 => v["kind"] = json!(["setpoint", "model_update", "Trajectory", "mode"][r.below(4)]),
                1 => v["envelope"] = json!({"min": 0, "max": 1, "max_rate_per_s": 1}),
                _ => {
                    v["body"] = json!({"quantity": "temperature", "unit": "celsius", "value": 21.5});
                }
            }
            case.input = resign(v, false, false);
        }
        _ => {
            case.cat = "oversize_or_deep";
            let mut s = String::from_utf8(b.clone()).unwrap();
            match r.below(3) {
                0 => {
                    let n = 100 + r.below(400);
                    s = s.replacen("\"cell-3\"", &format!("{}1{}", "[".repeat(n), "]".repeat(n)), 1);
                }
                1 => s = s.replacen("\"cell-3\"", &format!("\"{}\"", "a".repeat(20_000)), 1),
                _ => s = s.replacen("\"chunk-", &format!("\"{}", "9".repeat(10_000)), 1),
            }
            case.input = s.into_bytes();
        }
    }
    if !case.control && case.prior.is_none() && !case.kill && case.now == NOW && case.input == base_bytes {
        case.control = true;
        case.expect = None;
    }
    case
}

fn resign_hash(v: Value) -> Vec<u8> {
    // The band reference must match for the case to reach the continuity and interval checks.
    resign(v, true, true)
}

#[derive(Default)]
struct Tally {
    cases: u64,
    controls: u64,
    control_accepts: u64,
    false_accepts: u64,
    wrong_verdicts: u64,
    missing_stop_requests: u64,
    truncated_ok: u64,
    baseline_accepts: u64,
    by_cat: BTreeMap<&'static str, (u64, u64)>,
    examples: Vec<String>,
}

fn decide_case(c: &Case) -> (Receipt, Vec<u8>) {
    let site = key(SITE_SEED);
    let key_id = key_id(&site);
    let _ = key_id;
    let policy = traj_policy(if c.truncate { ChunkOverrun::Truncate { min_steps: 1 } } else { ChunkOverrun::Veto });
    if c.kill {
        let mut g = Gate::new(policy, KillAll, key(SITE_SEED), Chain::genesis("site-test-01", NOW));
        let r = g.decide(&c.input, c.now);
        return (r, vec![]);
    }
    let mut g: Gate<NoKill> = Gate::new(policy, NoKill, key(SITE_SEED), Chain::genesis("site-test-01", NOW));
    if let Some(p) = &c.prior {
        g.decide(p, NOW);
    }
    let r = g.decide(&c.input, c.now);
    let site_key = g.site_key_id();
    (r, site_key.into_bytes())
}

fn run_range(lo: u64, hi: u64, base: &Value, base_bytes: &[u8]) -> Tally {
    let mut t = Tally::default();
    for i in lo..hi {
        let c = gen(i, base, base_bytes);
        let (r, site_key) = decide_case(&c);
        assert_ne!(r.decision, Decision::Executed);
        let accepted = matches!(r.decision, Decision::Shadowed | Decision::Truncated);
        let site_key = String::from_utf8(site_key).unwrap_or_default();
        // Every veto and truncation carries a stop request that verifies; every other refusal and acceptance of a
        // well-formed chunk does not.
        let verdict = r.verdict.clone();
        let needs_stop = matches!(verdict.as_ref().map(|v| v.outcome), Some(ChunkOutcome::Vetoed) | Some(ChunkOutcome::Truncated));
        if needs_stop {
            let ok = r.stop_request.as_ref().is_some_and(|b| verify_stop_request(b, &site_key).is_ok());
            if !ok {
                t.missing_stop_requests += 1;
            }
        }
        if i % 16 == 0 && !site_key.is_empty() {
            assert!(furcate_command::verify_receipt(&r.bytes, &site_key).is_ok());
        }
        let base_acc = baseline_accepts(&c.input, c.now);
        t.cases += 1;
        if c.control {
            t.controls += 1;
            let whole = r.decision == Decision::Shadowed && verdict.as_ref().is_some_and(|v| v.steps_accepted == N);
            if whole {
                t.control_accepts += 1;
            }
            continue;
        }
        let e = t.by_cat.entry(c.cat).or_insert((0, 0));
        e.0 += 1;
        if base_acc {
            e.1 += 1;
            t.baseline_accepts += 1;
        }
        // The only acceptance a mutant may get is a truncated prefix of a designed step-level violation, with the
        // exact prefix length the expectation predicts.
        let mut allowed = false;
        if let (Some(exp), Some(v)) = (c.expect, verdict.as_ref()) {
            let got = v.first_violation;
            let named = got.is_some_and(|g| g.step == exp.step && g.limit == exp.limit);
            let step_level = exp.step.is_some_and(|s| s >= 1);
            let want = if c.truncate && step_level { ChunkOutcome::Truncated } else { ChunkOutcome::Vetoed };
            let want_accepted = if want == ChunkOutcome::Truncated { exp.step.unwrap() } else { 0 };
            if !(named && v.outcome == want && v.steps_accepted == want_accepted) {
                t.wrong_verdicts += 1;
                if t.examples.len() < 5 {
                    t.examples.push(format!("case {i} {}: expected {:?}/{:?} got {:?}", c.cat, exp.step, exp.limit.as_str(), v));
                }
            }
            allowed = want == ChunkOutcome::Truncated && v.outcome == ChunkOutcome::Truncated;
            if allowed {
                t.truncated_ok += 1;
            }
        }
        if accepted && !allowed {
            t.false_accepts += 1;
            if t.examples.len() < 5 {
                t.examples.push(format!("case {i} {}: {}", c.cat, String::from_utf8_lossy(&c.input[..c.input.len().min(200)])));
            }
        }
    }
    t
}

#[test]
fn mutated_chunks_get_no_false_accept() {
    let default_cases: u64 = if cfg!(debug_assertions) { 20_000 } else { 1_000_000 };
    let n: u64 = std::env::var("FAULT_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(default_cases);
    let base_bytes = valid_chunk_n(1, 0, N);
    let base = parse(&base_bytes);
    // The generator's designed violations are only valid if the independent oracle agrees the base chunk is clean.
    assert_eq!(oracle(&base["body"], &traj_limit(), None), None);
    let threads = 8u64;
    let started = std::time::Instant::now();
    let tallies: Vec<Tally> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|k| {
                let (base, bb) = (&base, &base_bytes);
                s.spawn(move || run_range(n * k / threads, n * (k + 1) / threads, base, bb))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Tally::default();
    for t in tallies {
        all.cases += t.cases;
        all.controls += t.controls;
        all.control_accepts += t.control_accepts;
        all.false_accepts += t.false_accepts;
        all.wrong_verdicts += t.wrong_verdicts;
        all.missing_stop_requests += t.missing_stop_requests;
        all.truncated_ok += t.truncated_ok;
        all.baseline_accepts += t.baseline_accepts;
        all.examples.extend(t.examples);
        for (k, (a, b)) in t.by_cat {
            let e = all.by_cat.entry(k).or_insert((0, 0));
            e.0 += a;
            e.1 += b;
        }
    }
    let mutants = all.cases - all.controls;
    println!("CHUNK-FAULT-INJECTION cases={} mutants={} controls={} elapsed={:?}", all.cases, mutants, all.controls, started.elapsed());
    println!("CHUNK-FAULT-INJECTION gate false_accepts={} control_accepts={}/{} wrong_verdicts={} missing_stop_requests={} truncated_prefixes_as_predicted={}", all.false_accepts, all.control_accepts, all.controls, all.wrong_verdicts, all.missing_stop_requests, all.truncated_ok);
    println!("CHUNK-FAULT-INJECTION baseline(signature+expiry) accepts_of_mutants={}", all.baseline_accepts);
    for (k, (m, b)) in &all.by_cat {
        println!("  {k:30} mutants={m:7} baseline_accepts={b}");
    }
    assert_eq!(all.cases, n);
    assert_eq!(all.false_accepts, 0, "{:?}", all.examples);
    assert_eq!(all.wrong_verdicts, 0, "{:?}", all.examples);
    assert_eq!(all.missing_stop_requests, 0);
    assert_eq!(all.control_accepts, all.controls, "a valid chunk was refused or cut");
    assert!(all.baseline_accepts > 0, "the baseline should accept some of the mutants");
}

/// The differential check: random small perturbations of a valid chunk, decided by the gate and by the independent
/// oracle. The gate accepts the whole chunk exactly when the oracle finds no violation.
#[test]
fn the_gate_agrees_with_an_independent_oracle_on_random_perturbations() {
    let n: u64 = std::env::var("FAULT_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(if cfg!(debug_assertions) { 2_000 } else { 20_000 }).min(20_000);
    let lim = traj_limit();
    let (mut ok_cnt, mut bad_cnt) = (0u64, 0u64);
    for i in 0..n {
        let mut r = Rng(SEED ^ 0xabcd ^ i.wrapping_mul(0x9e37_79b9));
        let mut v = traj_value_n(1, 0, N);
        for _ in 0..1 + r.below(3) {
            let (s, j) = (r.below(N), r.below(DOF));
            match r.below(3) {
                0 => {
                    let cur = v["body"]["steps"][s]["q"][j].as_f64().unwrap();
                    v["body"]["steps"][s]["q"][j] = json!(cur + (r.unit() - 0.5) * 0.02);
                }
                1 => {
                    let cur = v["body"]["steps"][s]["tau"][j].as_f64().unwrap();
                    v["body"]["steps"][s]["tau"][j] = json!(cur + (r.unit() - 0.5) * 80.0);
                }
                _ => {
                    let k = r.below(3);
                    let cur = v["body"]["steps"][s]["xyz"][k].as_f64().unwrap();
                    v["body"]["steps"][s]["xyz"][k] = json!(cur + (r.unit() - 0.5) * 1.0);
                }
            }
        }
        let expect = oracle(&v["body"], &lim, None);
        let mut g = traj_gate();
        let rc = g.decide(&finish_traj(v), NOW);
        match expect {
            None => {
                ok_cnt += 1;
                assert_eq!(rc.decision, Decision::Shadowed, "case {i}: oracle found no violation");
            }
            Some((step, name)) => {
                bad_cnt += 1;
                assert_eq!(rc.decision, Decision::Denied, "case {i}: oracle says {name} at {step}");
                let got = rc.verdict.unwrap().first_violation.unwrap();
                assert_eq!((got.step, got.limit.as_str()), (Some(step), name), "case {i}");
            }
        }
    }
    println!("CHUNK-ORACLE cases={n} clean={ok_cnt} violating={bad_cnt}");
    assert!(ok_cnt > 0 && bad_cnt > 0);
}
