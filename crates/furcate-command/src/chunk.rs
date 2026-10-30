//! Trajectory commands: one action chunk from a learned policy, decided as a whole.
//!
//! Vision-language-action, diffusion and flow-matching policies emit a chunk of N future steps per inference, not one
//! command. The gate therefore checks a chunk step by step against per-step limits (position, workspace, effort,
//! velocity, acceleration, jerk), against the chunk's own shape (step period, length, interval between chunks,
//! continuity with the last accepted chunk) and against the solved band of the twin certificate, and then either
//! accepts it, truncates it to the longest prefix that is inside every limit, or vetoes it whole.
//!
//! The verdict names the first violating step and the limit. Derived quantities are finite differences at the step
//! period `dt = step_ms / 1000`: `v[i] = (q[i] - q[i-1]) / dt`, `a[i] = (v[i] - v[i-1]) / dt`,
//! `jerk[i] = (a[i] - a[i-1]) / dt`. A bound is violated when the magnitude is strictly greater than it.
//!
//! A stop request is an advisory output record addressed to a safety controller. It is never an emergency stop and
//! never replaces one (see docs/physical-command.md); nothing here clears or resets a stop.

use crate::command::{exact, s, u};
use crate::command::ErrorCode;
use crate::is_lower_hex;
use crate::policy::{ChunkOverrun, TrajectoryLimit};
use serde_json::{json, Value};

pub const MAX_DOF: usize = 32;
pub const MAX_STEPS: usize = 1024;
pub const MAX_STEP_MS: u64 = 1000;
/// Largest magnitude accepted for any number in a chunk. Keeps every finite difference finite and every figure a
/// receipt reports below 2^53.
pub const MAX_MAGNITUDE: f64 = 1e9;
pub const STOP_REQUEST_DOMAIN: &str = "furcate/physical-stop-request/v1";

#[derive(Clone, Debug)]
pub struct Step {
    pub q: Vec<f64>,
    pub tau: Option<Vec<f64>>,
    pub xyz: Option<[f64; 3]>,
}

#[derive(Clone, Debug)]
pub struct Start {
    pub q: Vec<f64>,
    pub dq: Vec<f64>,
    pub ddq: Vec<f64>,
}

/// The limits the sender states. The site's own limits are independent; both apply and the stricter wins.
#[derive(Clone, Debug)]
pub struct SenderLimits {
    pub q_min: Vec<f64>,
    pub q_max: Vec<f64>,
    pub dq_max: Vec<f64>,
    pub ddq_max: Vec<f64>,
    pub dddq_max: Vec<f64>,
    pub tau_max: Option<Vec<f64>>,
    pub xyz: Option<([f64; 3], [f64; 3])>,
}

#[derive(Clone, Debug)]
pub struct Trajectory {
    pub chunk_index: u64,
    pub dof: usize,
    pub step_ms: u64,
    pub steps: Vec<Step>,
    pub start: Start,
    pub limits: SenderLimits,
    /// SHA-256 of the canonical twin certificate (signature included) the chunk was planned inside.
    pub twin_cert_sha256: String,
}

fn num(v: &Value) -> Option<f64> {
    let x = v.as_f64()?;
    (x.is_finite() && x.abs() <= MAX_MAGNITUDE).then_some(x)
}
fn vecn(v: &Value, n: usize) -> Option<Vec<f64>> {
    let a = v.as_array()?;
    if a.len() != n {
        return None;
    }
    a.iter().map(num).collect()
}
fn vec3(v: &Value) -> Option<[f64; 3]> {
    let x = vecn(v, 3)?;
    Some([x[0], x[1], x[2]])
}

/// Parse the body of a `trajectory` command. Strict: exact members, exact lengths, bounded magnitudes.
pub fn parse_body(v: &Value) -> Result<Trajectory, ErrorCode> {
    use ErrorCode::Malformed;
    let m = exact(v, &["chunk_index", "dof", "step_ms", "steps", "start", "limits", "twin_cert_sha256"], &[]).ok_or(Malformed)?;
    let dof = u(m, "dof").ok_or(Malformed)? as usize;
    let step_ms = u(m, "step_ms").ok_or(Malformed)?;
    if !(1..=MAX_DOF).contains(&dof) || !(1..=MAX_STEP_MS).contains(&step_ms) {
        return Err(Malformed);
    }
    let arr = m["steps"].as_array().ok_or(Malformed)?;
    if arr.is_empty() || arr.len() > MAX_STEPS {
        return Err(Malformed);
    }
    let mut steps = Vec::with_capacity(arr.len());
    for st in arr {
        let sm = exact(st, &["q"], &["tau", "xyz"]).ok_or(Malformed)?;
        steps.push(Step {
            q: vecn(&sm["q"], dof).ok_or(Malformed)?,
            tau: match sm.get("tau") {
                None => None,
                Some(t) => Some(vecn(t, dof).ok_or(Malformed)?),
            },
            xyz: match sm.get("xyz") {
                None => None,
                Some(t) => Some(vec3(t).ok_or(Malformed)?),
            },
        });
    }
    // Every step has the same optional members, or none has them.
    let (has_tau, has_xyz) = (steps[0].tau.is_some(), steps[0].xyz.is_some());
    if steps.iter().any(|x| x.tau.is_some() != has_tau || x.xyz.is_some() != has_xyz) {
        return Err(Malformed);
    }
    let st = exact(&m["start"], &["q", "dq", "ddq"], &[]).ok_or(Malformed)?;
    let start = Start {
        q: vecn(&st["q"], dof).ok_or(Malformed)?,
        dq: vecn(&st["dq"], dof).ok_or(Malformed)?,
        ddq: vecn(&st["ddq"], dof).ok_or(Malformed)?,
    };
    let lm = exact(
        &m["limits"],
        &["q_min", "q_max", "dq_max", "ddq_max", "dddq_max"],
        &["tau_max", "xyz_min", "xyz_max"],
    )
    .ok_or(Malformed)?;
    let limits = SenderLimits {
        q_min: vecn(&lm["q_min"], dof).ok_or(Malformed)?,
        q_max: vecn(&lm["q_max"], dof).ok_or(Malformed)?,
        dq_max: vecn(&lm["dq_max"], dof).ok_or(Malformed)?,
        ddq_max: vecn(&lm["ddq_max"], dof).ok_or(Malformed)?,
        dddq_max: vecn(&lm["dddq_max"], dof).ok_or(Malformed)?,
        tau_max: match lm.get("tau_max") {
            None => None,
            Some(t) => Some(vecn(t, dof).ok_or(Malformed)?),
        },
        xyz: match (lm.get("xyz_min"), lm.get("xyz_max")) {
            (None, None) => None,
            (Some(a), Some(b)) => Some((vec3(a).ok_or(Malformed)?, vec3(b).ok_or(Malformed)?)),
            _ => return Err(Malformed),
        },
    };
    let ok = (0..dof).all(|j| limits.q_min[j] <= limits.q_max[j] && limits.dq_max[j] >= 0.0 && limits.ddq_max[j] >= 0.0 && limits.dddq_max[j] >= 0.0)
        && limits.tau_max.as_ref().is_none_or(|t| t.iter().all(|x| *x >= 0.0))
        && limits.xyz.is_none_or(|(a, b)| (0..3).all(|k| a[k] <= b[k]));
    let hash = s(m, "twin_cert_sha256").ok_or(Malformed)?;
    if !ok || hash.len() != 64 || !is_lower_hex(hash) {
        return Err(Malformed);
    }
    Ok(Trajectory { chunk_index: u(m, "chunk_index").ok_or(Malformed)?, dof, step_ms, steps, start, limits, twin_cert_sha256: hash.to_string() })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    Dof,
    StepRate,
    ChunkLength,
    ChunkInterval,
    Continuity,
    MissingField,
    Position,
    CertifiedBand,
    Workspace,
    Effort,
    Velocity,
    Acceleration,
    Jerk,
}

impl LimitKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitKind::Dof => "dof",
            LimitKind::StepRate => "step_rate",
            LimitKind::ChunkLength => "chunk_length",
            LimitKind::ChunkInterval => "chunk_interval",
            LimitKind::Continuity => "continuity",
            LimitKind::MissingField => "missing_field",
            LimitKind::Position => "position",
            LimitKind::CertifiedBand => "certified_band",
            LimitKind::Workspace => "workspace",
            LimitKind::Effort => "effort",
            LimitKind::Velocity => "velocity",
            LimitKind::Acceleration => "acceleration",
            LimitKind::Jerk => "jerk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitSource {
    Site,
    Sender,
    Band,
}

impl LimitSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitSource::Site => "site",
            LimitSource::Sender => "sender",
            LimitSource::Band => "band",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Violation {
    /// The step index (from 0), or `None` for a violation of the chunk as a whole or of its start state.
    pub step: Option<usize>,
    pub joint: Option<usize>,
    pub limit: LimitKind,
    pub source: LimitSource,
    pub value: f64,
    pub bound: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    Accepted,
    Truncated,
    Vetoed,
}

impl ChunkOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChunkOutcome::Accepted => "accepted",
            ChunkOutcome::Truncated => "truncated",
            ChunkOutcome::Vetoed => "vetoed",
        }
    }
}

/// The structured verdict on one chunk.
#[derive(Clone, Debug, PartialEq)]
pub struct ChunkVerdict {
    pub outcome: ChunkOutcome,
    pub steps_total: usize,
    /// The length of the prefix that is inside every limit and that the site would pass on in shadow: all of the
    /// chunk when accepted, the part before the first violating step when truncated, 0 when vetoed.
    pub steps_accepted: usize,
    pub first_violation: Option<Violation>,
}

fn report(x: f64) -> f64 {
    if x.is_nan() {
        0.0
    } else {
        x.clamp(-1e15, 1e15)
    }
}

impl Violation {
    pub fn to_json(&self) -> Value {
        json!({
            "step": self.step, "joint": self.joint, "limit": self.limit.as_str(), "source": self.source.as_str(),
            "value": report(self.value), "bound": report(self.bound),
        })
    }
}

impl ChunkVerdict {
    pub fn to_json(&self) -> Value {
        json!({
            "outcome": self.outcome.as_str(), "steps_total": self.steps_total, "steps_accepted": self.steps_accepted,
            "first_violation": self.first_violation.map(|v| v.to_json()),
        })
    }
}

/// Where the last accepted chunk for an actuator ended. The next chunk must start there.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EndState {
    pub q: Vec<f64>,
    pub dq: Vec<f64>,
    pub ddq: Vec<f64>,
    pub issued_at_ms: u64,
}

pub struct Evaluation {
    pub verdict: ChunkVerdict,
    /// Set when at least one step was accepted.
    pub end: Option<EndState>,
}

fn veto(total: usize, v: Violation) -> Evaluation {
    Evaluation { verdict: ChunkVerdict { outcome: ChunkOutcome::Vetoed, steps_total: total, steps_accepted: 0, first_violation: Some(v) }, end: None }
}

fn whole(limit: LimitKind, source: LimitSource, value: f64, bound: f64) -> Violation {
    Violation { step: None, joint: None, limit, source, value, bound }
}

/// Decide one chunk. `prev` is where the last accepted chunk for this actuator ended, `interval_ms` the time since it
/// was issued. The first violation in a fixed order (chunk-level checks, then step by step; within a step position,
/// certified band, workspace, effort, velocity, acceleration, jerk; within a check lowest joint first; site bound
/// before the sender's) is the one reported.
pub fn evaluate(
    t: &Trajectory,
    lim: &TrajectoryLimit,
    position_band: &[(f64, f64)],
    effort_band: &[(f64, f64)],
    prev: Option<&EndState>,
    interval_ms: Option<u64>,
    issued_at_ms: u64,
) -> Evaluation {
    use LimitKind::*;
    use LimitSource::*;
    let n = t.steps.len();
    let dof = t.dof;
    if dof != lim.dof {
        return veto(n, whole(Dof, Site, dof as f64, lim.dof as f64));
    }
    if t.step_ms < lim.min_step_ms {
        return veto(n, whole(StepRate, Site, t.step_ms as f64, lim.min_step_ms as f64));
    }
    if t.step_ms > lim.max_step_ms {
        return veto(n, whole(StepRate, Site, t.step_ms as f64, lim.max_step_ms as f64));
    }
    if n > lim.max_steps {
        return veto(n, whole(ChunkLength, Site, n as f64, lim.max_steps as f64));
    }
    if let Some(iv) = interval_ms {
        if iv < lim.min_chunk_interval_ms {
            return veto(n, whole(ChunkInterval, Site, iv as f64, lim.min_chunk_interval_ms as f64));
        }
    }
    if (lim.tau_max.is_some() && t.steps[0].tau.is_none()) || (lim.xyz.is_some() && t.steps[0].xyz.is_none()) {
        return veto(n, whole(MissingField, Site, 0.0, 1.0));
    }
    // Derivative state at the start: the gate's own record of the last accepted chunk when there is one, the
    // sender's claim otherwise. The sender's start state must itself be inside the limits.
    let (q0, dq0, ddq0): (&[f64], &[f64], &[f64]) = match prev {
        Some(p) => {
            for j in 0..dof {
                let d = (t.start.q[j] - p.q[j]).abs();
                if d > lim.join_tolerance {
                    return veto(n, Violation { step: None, joint: Some(j), limit: Continuity, source: Site, value: d, bound: lim.join_tolerance });
                }
            }
            (&p.q, &p.dq, &p.ddq)
        }
        None => (&t.start.q, &t.start.dq, &t.start.ddq),
    };
    for j in 0..dof {
        let vb = lim.dq_max[j].min(t.limits.dq_max[j]);
        if dq0[j].abs() > vb {
            let src = if lim.dq_max[j] <= t.limits.dq_max[j] { Site } else { Sender };
            return veto(n, Violation { step: None, joint: Some(j), limit: Velocity, source: src, value: dq0[j].abs(), bound: vb });
        }
        let ab = lim.ddq_max[j].min(t.limits.ddq_max[j]);
        if ddq0[j].abs() > ab {
            let src = if lim.ddq_max[j] <= t.limits.ddq_max[j] { Site } else { Sender };
            return veto(n, Violation { step: None, joint: Some(j), limit: Acceleration, source: src, value: ddq0[j].abs(), bound: ab });
        }
    }
    let dt = t.step_ms as f64 / 1000.0;
    let mut pq = q0.to_vec();
    let mut pv = dq0.to_vec();
    let mut pa = ddq0.to_vec();
    let mut last: Option<(Vec<f64>, Vec<f64>, Vec<f64>)> = None;
    let mut bad: Option<Violation> = None;
    'steps: for (i, st) in t.steps.iter().enumerate() {
        let mk = |j: Option<usize>, limit, source, value: f64, bound: f64| Violation { step: Some(i), joint: j, limit, source, value, bound };
        for j in 0..dof {
            let x = st.q[j];
            if x < lim.q_min[j] || x > lim.q_max[j] {
                let b = if x < lim.q_min[j] { lim.q_min[j] } else { lim.q_max[j] };
                bad = Some(mk(Some(j), Position, Site, x, b));
                break 'steps;
            }
            if x < t.limits.q_min[j] || x > t.limits.q_max[j] {
                let b = if x < t.limits.q_min[j] { t.limits.q_min[j] } else { t.limits.q_max[j] };
                bad = Some(mk(Some(j), Position, Sender, x, b));
                break 'steps;
            }
        }
        for j in 0..dof {
            let x = st.q[j];
            if !position_band.iter().any(|(lo, hi)| *lo <= x && x <= *hi) {
                bad = Some(mk(Some(j), CertifiedBand, Band, x, position_band.first().map_or(0.0, |r| r.0)));
                break 'steps;
            }
        }
        if let Some(p) = st.xyz {
            if let Some((lo, hi)) = lim.xyz {
                for k in 0..3 {
                    if p[k] < lo[k] || p[k] > hi[k] {
                        bad = Some(mk(Some(k), Workspace, Site, p[k], if p[k] < lo[k] { lo[k] } else { hi[k] }));
                        break 'steps;
                    }
                }
            }
            if let Some((lo, hi)) = t.limits.xyz {
                for k in 0..3 {
                    if p[k] < lo[k] || p[k] > hi[k] {
                        bad = Some(mk(Some(k), Workspace, Sender, p[k], if p[k] < lo[k] { lo[k] } else { hi[k] }));
                        break 'steps;
                    }
                }
            }
        }
        if let Some(tau) = &st.tau {
            for j in 0..dof {
                let x = tau[j].abs();
                if let Some(tm) = &lim.tau_max {
                    if x > tm[j] {
                        bad = Some(mk(Some(j), Effort, Site, x, tm[j]));
                        break 'steps;
                    }
                }
                if let Some(tm) = &t.limits.tau_max {
                    if x > tm[j] {
                        bad = Some(mk(Some(j), Effort, Sender, x, tm[j]));
                        break 'steps;
                    }
                }
                if !effort_band.iter().any(|(lo, hi)| *lo <= tau[j] && tau[j] <= *hi) {
                    bad = Some(mk(Some(j), CertifiedBand, Band, tau[j], effort_band.first().map_or(0.0, |r| r.0)));
                    break 'steps;
                }
            }
        }
        let mut v = vec![0.0; dof];
        let mut a = vec![0.0; dof];
        for j in 0..dof {
            v[j] = (st.q[j] - pq[j]) / dt;
            if v[j].abs() > lim.dq_max[j] {
                bad = Some(mk(Some(j), Velocity, Site, v[j].abs(), lim.dq_max[j]));
                break 'steps;
            }
            if v[j].abs() > t.limits.dq_max[j] {
                bad = Some(mk(Some(j), Velocity, Sender, v[j].abs(), t.limits.dq_max[j]));
                break 'steps;
            }
        }
        for j in 0..dof {
            a[j] = (v[j] - pv[j]) / dt;
            if a[j].abs() > lim.ddq_max[j] {
                bad = Some(mk(Some(j), Acceleration, Site, a[j].abs(), lim.ddq_max[j]));
                break 'steps;
            }
            if a[j].abs() > t.limits.ddq_max[j] {
                bad = Some(mk(Some(j), Acceleration, Sender, a[j].abs(), t.limits.ddq_max[j]));
                break 'steps;
            }
        }
        for j in 0..dof {
            let jerk = (a[j] - pa[j]) / dt;
            if jerk.abs() > lim.dddq_max[j] {
                bad = Some(mk(Some(j), Jerk, Site, jerk.abs(), lim.dddq_max[j]));
                break 'steps;
            }
            if jerk.abs() > t.limits.dddq_max[j] {
                bad = Some(mk(Some(j), Jerk, Sender, jerk.abs(), t.limits.dddq_max[j]));
                break 'steps;
            }
        }
        pq = st.q.clone();
        pv = v.clone();
        pa = a.clone();
        last = Some((pq.clone(), v, a));
    }
    let end = |last: Option<(Vec<f64>, Vec<f64>, Vec<f64>)>| last.map(|(q, dq, ddq)| EndState { q, dq, ddq, issued_at_ms });
    match bad {
        None => Evaluation {
            verdict: ChunkVerdict { outcome: ChunkOutcome::Accepted, steps_total: n, steps_accepted: n, first_violation: None },
            end: end(last),
        },
        Some(v) => {
            let at = v.step.unwrap_or(0);
            match lim.overrun {
                ChunkOverrun::Truncate { min_steps } if at >= min_steps.max(1) => Evaluation {
                    verdict: ChunkVerdict { outcome: ChunkOutcome::Truncated, steps_total: n, steps_accepted: at, first_violation: Some(v) },
                    end: end(last),
                },
                _ => veto(n, v),
            }
        }
    }
}

/// Check a stop request as received: canonical bytes, the named site key, its signature over
/// [`STOP_REQUEST_DOMAIN`], and the two fields that say what it is not: advisory, and not an emergency stop.
pub fn verify_stop_request(bytes: &[u8], site_key: &str) -> Result<Value, crate::receipt::ReceiptError> {
    use crate::canon::{canonical, parse_canonical};
    use crate::receipt::ReceiptError::*;
    let v = parse_canonical(bytes).map_err(|_| Malformed)?;
    let o = v.as_object().ok_or(Malformed)?;
    if o.get("format").and_then(|x| x.as_str()) != Some("physical-stop-request")
        || o.get("advisory") != Some(&Value::Bool(true))
        || o.get("emergency_stop") != Some(&Value::Bool(false))
    {
        return Err(Malformed);
    }
    if o.get("site_key").and_then(|x| x.as_str()) != Some(site_key) {
        return Err(WrongKey);
    }
    let sig = o.get("signature").and_then(|x| x.as_str()).ok_or(Malformed)?.to_string();
    let mut c = v.clone();
    c.as_object_mut().unwrap().remove("signature");
    let msg = canonical(&c).map_err(|_| Malformed)?;
    if !crate::verify_ed25519(site_key, STOP_REQUEST_DOMAIN, msg.as_bytes(), &sig) {
        return Err(BadSignature);
    }
    Ok(v)
}
