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
        trajectory_limits: vec![],
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

// ---- trajectory (action chunk) fixtures -------------------------------------------------------------------------

use furcate_command::{ChunkOverrun, RequestedStop, TrajectoryLimit};

pub const DOF: usize = 7;
pub const STEP_MS: u64 = 20;
pub const STEPS: usize = 50;
pub const CHUNK_MS: u64 = STEP_MS * STEPS as u64;

pub fn traj_limit() -> TrajectoryLimit {
    TrajectoryLimit {
        actuator_id: "arm-1".into(),
        dof: DOF,
        q_min: vec![-2.8; DOF],
        q_max: vec![2.8; DOF],
        dq_max: vec![1.0; DOF],
        ddq_max: vec![4.0; DOF],
        dddq_max: vec![100.0; DOF],
        tau_max: Some(vec![40.0; DOF]),
        xyz: Some(([-0.8, -0.8, 0.0], [0.8, 0.8, 1.2])),
        min_step_ms: 5,
        max_step_ms: 100,
        max_steps: 100,
        min_chunk_interval_ms: 100,
        join_tolerance: 0.005,
        overrun: ChunkOverrun::Veto,
        safety_controller_id: "safety-plc-1".into(),
        requested_stop: RequestedStop::Ss1,
    }
}

pub fn traj_policy(overrun: ChunkOverrun) -> SitePolicy {
    let mut p = policy();
    let mut l = traj_limit();
    l.overrun = overrun;
    p.trajectory_limits = vec![l];
    p
}

pub fn traj_gate() -> Gate<NoKill> {
    traj_gate_with(ChunkOverrun::Veto)
}
pub fn traj_gate_with(o: ChunkOverrun) -> Gate<NoKill> {
    Gate::new(traj_policy(o), NoKill, key(SITE_SEED), Chain::genesis("site-test-01", NOW - 10_000))
}

/// The smooth reference motion of joint `j` at global step `k` (k may be negative: the steps before the chunk).
pub fn ref_q(j: usize, k: i64) -> f64 {
    let t = k as f64 * STEP_MS as f64 / 1000.0;
    0.1 * (std::f64::consts::PI * t + 0.1 * j as f64).sin() + 0.05 * j as f64
}
fn ref_tau(j: usize, k: i64) -> f64 {
    let t = k as f64 * STEP_MS as f64 / 1000.0;
    10.0 * (0.5 * t + j as f64).sin()
}
fn ref_xyz(k: i64) -> [f64; 3] {
    let t = k as f64 * STEP_MS as f64 / 1000.0;
    [0.4 + 0.1 * (0.7 * t).sin(), 0.1 * (0.7 * t).cos(), 0.6 + 0.05 * (0.7 * t).sin()]
}

/// The unsigned certificate for trajectory commands: certified joint position and joint effort ranges.
pub fn traj_cert_value() -> Value {
    json!({
        "format": "twin-band-certificate", "v": 1, "tenant": "tenant-a", "twin_id": "twin-arm-1", "version": 4,
        "ranges": [
            {"quantity": "joint_position", "unit": "radian", "min": -3, "max": 3},
            {"quantity": "joint_effort", "unit": "newton_metre", "min": -50, "max": 50}
        ],
        "valid_from_ms": NOW - 86_400_000, "valid_until_ms": NOW + 3_600_000, "fidelity_score": 0.93,
        "signer": "", "signature": ""
    })
}

/// A valid unsigned trajectory command for chunk number `chunk` (chunk 0 starts at global step 0). Chunks are issued
/// one chunk period apart. `twin_cert_sha256` is left blank for [`finish_traj`] to fill.
pub fn traj_value(seq: u64, chunk: u64) -> Value {
    traj_value_n(seq, chunk, STEPS)
}

/// As [`traj_value`] with `n` steps per chunk (the fault suites use a shorter chunk to keep a debug run short).
pub fn traj_value_n(seq: u64, chunk: u64, n: usize) -> Value {
    let k0 = (chunk as usize * n) as i64;
    let steps: Vec<Value> = (0..n as i64)
        .map(|i| {
            let k = k0 + i;
            json!({
                "q": (0..DOF).map(|j| ref_q(j, k)).collect::<Vec<_>>(),
                "tau": (0..DOF).map(|j| ref_tau(j, k)).collect::<Vec<_>>(),
                "xyz": ref_xyz(k),
            })
        })
        .collect();
    let dt = STEP_MS as f64 / 1000.0;
    let q = |j: usize, k: i64| ref_q(j, k);
    let v = |j: usize, k: i64| (q(j, k) - q(j, k - 1)) / dt;
    let a = |j: usize, k: i64| (v(j, k) - v(j, k - 1)) / dt;
    let km1 = k0 - 1;
    let issued = NOW - 3_000 + chunk * STEP_MS * n as u64;
    json!({
        "format": "physical-command", "v": 1, "command_id": format!("chunk-{seq:08}"), "tenant": "tenant-a", "site_id": "site-test-01",
        "target": {"actuator_id": "arm-1", "scope": "cell-3"}, "kind": "trajectory",
        "body": {
            "chunk_index": chunk, "dof": DOF, "step_ms": STEP_MS, "steps": steps,
            "start": {
                "q": (0..DOF).map(|j| q(j, km1)).collect::<Vec<_>>(),
                "dq": (0..DOF).map(|j| v(j, km1)).collect::<Vec<_>>(),
                "ddq": (0..DOF).map(|j| a(j, km1)).collect::<Vec<_>>(),
            },
            "limits": {
                "q_min": vec![-2.9; DOF], "q_max": vec![2.9; DOF], "dq_max": vec![1.5; DOF], "ddq_max": vec![6.0; DOF],
                "dddq_max": vec![150.0; DOF], "tau_max": vec![45.0; DOF], "xyz_min": [-0.9, -0.9, 0.0], "xyz_max": [0.9, 0.9, 1.3]
            },
            "twin_cert_sha256": ""
        },
        "issued_at_ms": issued, "not_before_ms": issued, "expires_at_ms": NOW + 60_000,
        "nonce": format!("{:032x}", 0xfeed000000u64 + seq), "command_seq": seq, "mode": "shadow",
        "policy_sha256": POLICY_HASH, "model_sha256": MODEL_HASH, "birth_record_sha256": BIRTH_HASH,
        "twin_cert": traj_cert_value(), "signer": "", "signature": ""
    })
}

/// Sign the certificate, set the band reference to its hash (unless `keep_hash`), then sign the command.
pub fn finish_traj_with(mut v: Value, cert_key: &SigningKey, cmd_key: &SigningKey, keep_hash: bool) -> Vec<u8> {
    let mut cert = v["twin_cert"].take();
    sign_cert(&mut cert, cert_key).unwrap();
    if !keep_hash {
        v["body"]["twin_cert_sha256"] = json!(furcate_command::sha256_hex(canonical(&cert).unwrap().as_bytes()));
    }
    v["twin_cert"] = cert;
    sign_command(&mut v, cmd_key).unwrap();
    bytes(&v)
}
pub fn finish_traj(v: Value) -> Vec<u8> {
    finish_traj_with(v, &lw(), &lw(), false)
}
pub fn valid_chunk(seq: u64, chunk: u64) -> Vec<u8> {
    finish_traj(traj_value(seq, chunk))
}
pub fn valid_chunk_n(seq: u64, chunk: u64, n: usize) -> Vec<u8> {
    finish_traj(traj_value_n(seq, chunk, n))
}

/// An independent check of a chunk against the site limits, written separately from the gate: the first violating
/// step, joint and limit name, or None.
pub fn oracle(body: &Value, lim: &TrajectoryLimit, prev_end: Option<(&[f64], &[f64], &[f64])>) -> Option<(usize, &'static str)> {
    let dt = body["step_ms"].as_u64().unwrap() as f64 / 1000.0;
    let steps = body["steps"].as_array().unwrap();
    let get = |v: &Value| -> Vec<f64> { v.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect() };
    let (mut pq, mut pv, mut pa) = match prev_end {
        Some((q, v, a)) => (q.to_vec(), v.to_vec(), a.to_vec()),
        None => (get(&body["start"]["q"]), get(&body["start"]["dq"]), get(&body["start"]["ddq"])),
    };
    for (i, st) in steps.iter().enumerate() {
        let q = get(&st["q"]);
        for j in 0..lim.dof {
            if q[j] < lim.q_min[j] || q[j] > lim.q_max[j] {
                return Some((i, "position"));
            }
        }
        if let (Some(p), Some((lo, hi))) = (st.get("xyz"), lim.xyz) {
            let p = get(p);
            for k in 0..3 {
                if p[k] < lo[k] || p[k] > hi[k] {
                    return Some((i, "workspace"));
                }
            }
        }
        if let Some(t) = st.get("tau") {
            let t = get(t);
            for j in 0..lim.dof {
                if t[j].abs() > lim.tau_max.as_ref().unwrap()[j] {
                    return Some((i, "effort"));
                }
            }
        }
        let v: Vec<f64> = (0..lim.dof).map(|j| (q[j] - pq[j]) / dt).collect();
        if (0..lim.dof).any(|j| v[j].abs() > lim.dq_max[j]) {
            return Some((i, "velocity"));
        }
        let a: Vec<f64> = (0..lim.dof).map(|j| (v[j] - pv[j]) / dt).collect();
        if (0..lim.dof).any(|j| a[j].abs() > lim.ddq_max[j]) {
            return Some((i, "acceleration"));
        }
        if (0..lim.dof).any(|j| ((a[j] - pa[j]) / dt).abs() > lim.dddq_max[j]) {
            return Some((i, "jerk"));
        }
        pq = q;
        pv = v;
        pa = a;
    }
    None
}

// ---- actuation (stages, approvals, executor) fixtures -----------------------------------------------------------

use furcate_command::{ActuationConfig, ExecError, Execution, Executor, Plan, Release, Stage, APPROVAL_DOMAIN};
use furcate_command::issue::sign_value as sign_any;

pub const APPROVER_SEED: u8 = 0x41;
pub fn approver() -> SigningKey {
    key(APPROVER_SEED)
}

/// valve-1 is in class hvac_valve and arm-1 in robot_arm; both classes at `stage`; one enrolled approver.
pub fn act_cfg(stage: Stage) -> ActuationConfig {
    ActuationConfig {
        classes: vec![("valve-1".into(), "hvac_valve".into()), ("arm-1".into(), "robot_arm".into())],
        stages: vec![("hvac_valve".into(), stage), ("robot_arm".into(), stage)],
        approvers: vec![key_id(&approver())],
    }
}

/// An unsigned approval for one class, valid from NOW-1000 for one day.
pub fn approval_value(id: &str, class: &str, actuators: &[&str], kinds: &[&str]) -> Value {
    json!({
        "format": "actuation-approval", "v": 1, "approval_id": id, "tenant": "tenant-a", "site_id": "site-test-01",
        "system_class": class, "actuator_ids": actuators, "kinds": kinds,
        "valid_from_ms": NOW - 1000, "valid_until_ms": NOW + 86_400_000,
        "approver": key_id(&approver()), "signature": ""
    })
}

pub fn sign_approval(mut v: Value, k: &SigningKey) -> Vec<u8> {
    sign_any(&mut v, APPROVAL_DOMAIN, k).unwrap();
    bytes(&v)
}

/// The approval most tests install: both actuators of both classes need their own, so this is the valve one.
pub fn valve_approval(id: &str) -> Vec<u8> {
    sign_approval(approval_value(id, "hvac_valve", &["valve-1"], &["setpoint"]), &approver())
}
pub fn arm_approval(id: &str) -> Vec<u8> {
    sign_approval(approval_value(id, "robot_arm", &["arm-1"], &["trajectory"]), &approver())
}

/// A gate at stage `stage` with trajectory limits (overrun policy `o`) and no approvals installed.
pub fn act_gate(stage: Stage, o: furcate_command::ChunkOverrun) -> Gate<NoKill> {
    traj_gate_with(o).with_actuation(act_cfg(stage))
}

pub fn actuate_setpoint(seq: u64) -> Vec<u8> {
    let mut v = command_value(seq);
    v["mode"] = json!("actuate");
    finish(v, &lw(), &lw())
}
pub fn actuate_chunk(seq: u64, chunk: u64) -> Vec<u8> {
    let mut v = traj_value(seq, chunk);
    v["mode"] = json!("actuate");
    finish_traj(v)
}

/// An executor that records every release and can be told to fail after a number of writes.
#[derive(Default)]
pub struct Rec {
    pub calls: Vec<(String, String, String, Plan)>,
    pub fail_after: Option<u64>,
}
impl Executor for Rec {
    fn execute(&mut self, r: &Release) -> Result<Execution, ExecError> {
        self.calls.push((r.command_id().into(), r.actuator_id().into(), r.system_class().into(), r.plan().clone()));
        let n = match r.plan() {
            Plan::Setpoint { .. } => 1,
            Plan::Trajectory { steps, .. } => steps.len() as u64,
        };
        match self.fail_after {
            Some(k) if k < n => Err(ExecError { writes_done: k, reason: "sink rejected".into() }),
            _ => Ok(Execution { writes: n }),
        }
    }
}
