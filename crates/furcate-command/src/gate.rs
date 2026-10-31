//! The gate: one command in, one signed and chained receipt out. Checks run in a fixed order and the first failure is
//! the answer, so one bad command has one code.

use crate::actuation::{parse_approval, Approval, ApprovalError, ApprovalId, ActuationConfig, Stage};
use crate::canon::{canonical, parse_canonical, CanonError};
use crate::chunk::{evaluate, ChunkOutcome, ChunkVerdict, EndState, STOP_REQUEST_DOMAIN};
use crate::command::{parse_command, Command, ErrorCode, Mode};
use crate::exec::{Executor, ExecError, Execution, Plan, Release};
use crate::policy::SitePolicy;
use crate::receipt::{core_digest, Decision, Receipt};
use crate::signer::{SignError, SiteSigner};
use crate::state::{AppliedEntry, GateState, RestoreError, STATE_VERSION};
use crate::{domain_digest, sha256_hex, verify_ed25519, CERT_DOMAIN, COMMAND_DOMAIN, RECEIPT_DOMAIN};
use ed25519_dalek::SigningKey;
use furcate_ledger::{Chain, OpKind};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Domain of the probe signature taken before a release. The signature is discarded; a distinct domain means it can
/// never be mistaken for a receipt.
const PROBE_DOMAIN: &str = "furcate/physical-release-probe/v1";

/// Whether a kill order is in force for a site or one actuator. The signed order itself is verified elsewhere (the
/// kill switch crate); the gate only asks. Unknown state must be reported as killed.
pub trait KillState {
    fn is_killed(&self, site_id: &str, actuator_id: &str) -> bool;
}

pub struct NoKill;
impl KillState for NoKill {
    fn is_killed(&self, _: &str, _: &str) -> bool {
        false
    }
}

/// Called after the write-ahead entry and the state advance, before the executor runs. It receives the state to
/// persist; an error stops the release before anything is written.
pub type ReleaseHook = Box<dyn FnMut(&GateState) -> Result<(), String> + Send>;

/// The gate for one site. `S` is the site signer; the default is an in-memory Ed25519 key, which is what tests use.
/// A deployed site passes a signer whose key stays in a key service or hardware module ([`SiteSigner`]).
pub struct Gate<K: KillState, S: SiteSigner = SigningKey> {
    policy: SitePolicy,
    kill: K,
    signer: S,
    chain: Chain,
    last_seq: u64,
    last_applied: HashMap<(String, String), (f64, u64)>,
    /// Where the last accepted chunk ended, per actuator.
    last_chunk: HashMap<String, EndState>,
    receipts: u64,
    actuation: Option<ActuationConfig>,
    approvals: Vec<Approval>,
    revoked: Vec<String>,
    hook: Option<ReleaseHook>,
}

/// What an accepted command was accepted as.
enum Accepted {
    Setpoint((f64, f64)),
    Chunk(ChunkVerdict),
}

/// The state an accepted command advances. Applied once the command is final: at once in shadow, and for a release
/// after the write-ahead entry and before the executor runs, so a failed write still consumes the sequence number.
struct Update {
    seq: u64,
    chunk: Option<(String, EndState)>,
    applied: Option<((String, String), (f64, u64))>,
}

struct Checked {
    cmd: Command,
    accepted: Accepted,
    update: Update,
    /// (system class, approval id) when the command asks to actuate and everything allows it.
    release: Option<(String, String)>,
}

type Refusal = (ErrorCode, Option<Command>, Option<ChunkVerdict>);

fn canon_code(e: CanonError) -> ErrorCode {
    match e {
        CanonError::NotCanonical => ErrorCode::NotCanonical,
        _ => ErrorCode::Malformed,
    }
}

impl<K: KillState> Gate<K, SigningKey> {
    /// A gate whose site key is an in-memory Ed25519 key. With no actuation configuration every command that asks to
    /// actuate is refused with `actuation_not_approved`, as before.
    pub fn new(policy: SitePolicy, kill: K, site_key: SigningKey, chain: Chain) -> Self {
        Gate::with_signer(policy, kill, site_key, chain)
    }
}

impl<K: KillState, S: SiteSigner> Gate<K, S> {
    /// A gate with any [`SiteSigner`].
    pub fn with_signer(policy: SitePolicy, kill: K, signer: S, chain: Chain) -> Self {
        Gate {
            policy,
            kill,
            signer,
            chain,
            last_seq: 0,
            last_applied: HashMap::new(),
            last_chunk: HashMap::new(),
            receipts: 0,
            actuation: None,
            approvals: Vec::new(),
            revoked: Vec::new(),
            hook: None,
        }
    }

    /// Set the site-local stages, system classes and enrolled approvers. Without this the gate never releases.
    pub fn with_actuation(mut self, cfg: ActuationConfig) -> Self {
        self.actuation = Some(cfg);
        self
    }

    /// Set a hook that persists state between the write-ahead entry and the executor (see [`ReleaseHook`]).
    pub fn with_release_hook(mut self, hook: ReleaseHook) -> Self {
        self.hook = Some(hook);
        self
    }

    pub fn site_key_id(&self) -> String {
        self.signer.key_id()
    }
    /// The stop-request source this gate asks, for a service that reports on it.
    pub fn kill_state(&self) -> &K {
        &self.kill
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }
    /// How many receipts have been made.
    pub fn receipts(&self) -> u64 {
        self.receipts
    }
    /// The site-local actuation configuration, if one was set.
    pub fn actuation(&self) -> Option<&ActuationConfig> {
        self.actuation.as_ref()
    }
    /// The installed approvals.
    pub fn approvals(&self) -> &[Approval] {
        &self.approvals
    }

    /// The approval record, checked and installed. Needs an actuation configuration (the enrolled approvers); the
    /// record's tenant and site must be this gate's, the approver enrolled, the signature valid, the window at most
    /// 31 days and not over. A ledger entry records it. The id of a revoked approval is never installable again.
    pub fn install_approval(&mut self, raw: &[u8], now_ms: u64) -> Result<ApprovalId, ApprovalError> {
        let cfg = self.actuation.as_ref().ok_or(ApprovalError::NotConfigured)?;
        let a = parse_approval(raw, &self.policy.tenant, &self.policy.site_id, &cfg.approvers, now_ms, false)?;
        if self.revoked.contains(&a.approval_id) {
            return Err(ApprovalError::Revoked);
        }
        if self.approvals.iter().any(|x| x.approval_id == a.approval_id) {
            return Err(ApprovalError::Duplicate);
        }
        let actor = format!("gate:{}", self.policy.site_id);
        self.chain.append(now_ms, OpKind::Command, actor, a.approval_id.clone(), format!("approval_installed:ok:{}", a.sha256));
        let id = a.approval_id.clone();
        self.approvals.push(a);
        Ok(id)
    }

    /// Remove an installed approval at once. A ledger entry records it, and the id cannot be installed again.
    pub fn revoke_approval(&mut self, id: &str, now_ms: u64) -> Result<(), ApprovalError> {
        let i = self.approvals.iter().position(|a| a.approval_id == id).ok_or(ApprovalError::Unknown)?;
        let a = self.approvals.remove(i);
        let actor = format!("gate:{}", self.policy.site_id);
        self.chain.append(now_ms, OpKind::Command, actor, a.approval_id.clone(), format!("approval_revoked:ok:{}", a.approval_id));
        self.revoked.push(a.approval_id);
        Ok(())
    }

    /// Everything a restart needs to keep replay protection, rate and chunk continuity, the installed approvals and
    /// the ledger chain. The service writes it atomically (temp file, fsync, rename) after every decision.
    pub fn export_state(&self) -> GateState {
        GateState {
            v: STATE_VERSION,
            site_id: self.policy.site_id.clone(),
            tenant: self.policy.tenant.clone(),
            last_seq: self.last_seq,
            last_applied: self
                .last_applied
                .iter()
                .map(|((a, q), (v, t))| AppliedEntry { actuator_id: a.clone(), quantity: q.clone(), value: *v, at_ms: *t })
                .collect(),
            last_chunk: self.last_chunk.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            receipts: self.receipts,
            approvals: self.approvals.iter().map(|a| a.raw.clone()).collect(),
            revoked_approvals: self.revoked.clone(),
            chain: self.chain.clone(),
        }
    }

    /// Rebuild a gate from saved state. Refuses (fail closed) a state for another site or tenant, whose chain does
    /// not verify, whose approvals do not verify or are not in the chain as installed and not revoked, or whose
    /// revoked ids are not in the chain as revoked. Stages, classes and enrolled approvers come from `actuation`,
    /// not from the state; an approval whose approver is no longer enrolled stays inert.
    pub fn restore(policy: SitePolicy, kill: K, signer: S, actuation: Option<ActuationConfig>, state: GateState) -> Result<Self, RestoreError> {
        if state.v != STATE_VERSION {
            return Err(RestoreError::Version);
        }
        if state.site_id != policy.site_id {
            return Err(RestoreError::WrongSite);
        }
        if state.tenant != policy.tenant {
            return Err(RestoreError::WrongTenant);
        }
        state.chain.verify().map_err(|e| RestoreError::Chain(e.to_string()))?;
        let actor = format!("gate:{}", policy.site_id);
        let has = |subject: &str, result: &str| {
            state.chain.entries().iter().any(|e| e.kind == OpKind::Command && e.actor == actor && e.subject == subject && e.result == result)
        };
        let mut approvals = Vec::new();
        for raw in &state.approvals {
            let a = parse_approval(raw.as_bytes(), &policy.tenant, &policy.site_id, &[], 0, true).map_err(RestoreError::Approval)?;
            if !has(&a.approval_id, &format!("approval_installed:ok:{}", a.sha256)) || has(&a.approval_id, &format!("approval_revoked:ok:{}", a.approval_id)) {
                return Err(RestoreError::ApprovalNotInChain(a.approval_id));
            }
            if approvals.iter().any(|x: &Approval| x.approval_id == a.approval_id) {
                return Err(RestoreError::Approval(ApprovalError::Duplicate));
            }
            approvals.push(a);
        }
        for id in &state.revoked_approvals {
            if !has(id, &format!("approval_revoked:ok:{id}")) || approvals.iter().any(|a| &a.approval_id == id) {
                return Err(RestoreError::ApprovalNotInChain(id.clone()));
            }
        }
        let mut last_applied = HashMap::new();
        for e in &state.last_applied {
            last_applied.insert((e.actuator_id.clone(), e.quantity.clone()), (e.value, e.at_ms));
        }
        Ok(Gate {
            policy,
            kill,
            signer,
            chain: state.chain,
            last_seq: state.last_seq,
            last_applied,
            last_chunk: state.last_chunk.into_iter().collect(),
            receipts: state.receipts,
            actuation,
            approvals,
            revoked: state.revoked_approvals,
            hook: None,
        })
    }

    /// Decide one command given as the bytes received, with no executor: a command that asks to actuate is refused
    /// with `actuation_not_approved`. Always returns a receipt, and has appended it to the chain.
    pub fn decide(&mut self, raw: &[u8], now_ms: u64) -> Receipt {
        self.decide_inner(raw, now_ms, None)
    }

    /// As [`Gate::decide`], and an accepted command that asks to actuate, whose system class is at stage `actuate`
    /// and which an installed approval covers, is released to `exec`. In order: every check; the kill state again;
    /// a probe signature (if the signer cannot sign, nothing is released); a write-ahead ledger entry; the state
    /// advance (a failed write still consumes the sequence number); the release hook; `exec`; the receipt, decision
    /// `executed`, `truncated` or `failed`. `exec` is never called for a refused command.
    pub fn decide_exec(&mut self, raw: &[u8], now_ms: u64, exec: &mut dyn Executor) -> Receipt {
        self.decide_inner(raw, now_ms, Some(exec))
    }

    fn decide_inner(&mut self, raw: &[u8], now_ms: u64, exec: Option<&mut dyn Executor>) -> Receipt {
        let ck = match self.check(raw, now_ms, exec.is_some()) {
            Ok(ck) => ck,
            Err((code, cmd, verdict)) => {
                let d = match code {
                    ErrorCode::Expired => Decision::Expired,
                    ErrorCode::KillSwitchActive => Decision::Killed,
                    _ => Decision::Denied,
                };
                return self.receipt(raw, now_ms, d, Some(code), cmd.as_ref(), None, verdict, None);
            }
        };
        if let (Some((class, approval_id)), Some(exec)) = (ck.release.clone(), exec) {
            return self.release(raw, now_ms, ck, class, approval_id, exec);
        }
        self.apply(ck.update);
        let (decision, code, applied, verdict) = match ck.accepted {
            Accepted::Setpoint(a) => (Decision::Shadowed, None, Some(a), None),
            Accepted::Chunk(v) => {
                let (d, c) = if v.outcome == ChunkOutcome::Truncated {
                    (Decision::Truncated, Some(ErrorCode::ChunkTruncated))
                } else {
                    (Decision::Shadowed, None)
                };
                (d, c, None, Some(v))
            }
        };
        self.receipt(raw, now_ms, decision, code, Some(&ck.cmd), applied, verdict, None)
    }

    fn apply(&mut self, u: Update) {
        self.last_seq = u.seq;
        if let Some((k, e)) = u.chunk {
            self.last_chunk.insert(k, e);
        }
        if let Some((k, v)) = u.applied {
            self.last_applied.insert(k, v);
        }
    }

    /// The installed approval that covers this actuator, class and kind now, from an approver still enrolled.
    fn covering_approval(&self, class: &str, actuator_id: &str, kind: &str, now: u64) -> Option<&Approval> {
        let cfg = self.actuation.as_ref()?;
        self.approvals.iter().find(|a| cfg.approvers.contains(&a.approver) && a.covers(class, actuator_id, kind, now))
    }

    /// Sign a throwaway digest and verify it. A signer that errors or answers with a signature that does not verify
    /// under its own key must not be released on.
    fn probe(&self, raw: &[u8]) -> Result<(), SignError> {
        let msg = sha256_hex(raw);
        let sig = self.signer.sign(&domain_digest(PROBE_DOMAIN, msg.as_bytes()))?;
        if verify_ed25519(&self.signer.key_id(), PROBE_DOMAIN, msg.as_bytes(), &hex::encode(sig)) {
            Ok(())
        } else {
            Err(SignError { reason: "probe signature did not verify".into() })
        }
    }

    fn release(&mut self, raw: &[u8], now: u64, ck: Checked, class: String, approval_id: String, exec: &mut dyn Executor) -> Receipt {
        let Checked { cmd, accepted, update, .. } = ck;
        let verdict = match &accepted {
            Accepted::Chunk(v) => Some(v.clone()),
            Accepted::Setpoint(_) => None,
        };
        let applied = match &accepted {
            Accepted::Setpoint(a) => Some(*a),
            Accepted::Chunk(_) => None,
        };
        // The kill state again, immediately before release; unknown is killed.
        if self.kill.is_killed(&cmd.site_id, &cmd.actuator_id) {
            return self.receipt(raw, now, Decision::Killed, Some(ErrorCode::KillSwitchActive), Some(&cmd), None, None, None);
        }
        if self.covering_approval(&class, &cmd.actuator_id, &cmd.kind, now).is_none() {
            return self.receipt(raw, now, Decision::Denied, Some(ErrorCode::ActuationNotApproved), Some(&cmd), None, None, None);
        }
        // A signer that cannot sign cannot receipt the outcome: release nothing.
        if let Err(e) = self.probe(raw) {
            return self.unsigned(&cmd, e.reason);
        }
        let plan = match (&accepted, &cmd.traj) {
            (Accepted::Chunk(v), Some(t)) => Plan::Trajectory {
                dof: t.dof,
                step_ms: t.step_ms,
                steps: t.steps[..v.steps_accepted].iter().map(|st| st.q.clone()).collect(),
            },
            _ => Plan::Setpoint { quantity: cmd.quantity.clone(), unit: cmd.unit.clone(), value: cmd.value },
        };
        // Write ahead: the release is in the chain before anything is written.
        let actor = format!("gate:{}", self.policy.site_id);
        let eh = self.chain.append(now, OpKind::Command, actor, cmd.command_id.clone(), format!("released:ok:{}", sha256_hex(raw)));
        let rseq = (self.chain.len() - 1) as u64;
        let rhash = hex::encode(eh);
        self.apply(update);
        let release = Release::new(&cmd.command_id, &cmd.actuator_id, &class, &approval_id, rseq, plan);
        let hooked = match self.hook.take() {
            Some(mut h) => {
                let r = h(&self.export_state());
                self.hook = Some(h);
                r
            }
            None => Ok(()),
        };
        let outcome: Result<Execution, ExecError> = match hooked {
            Ok(()) => exec.execute(&release),
            Err(reason) => Err(ExecError { writes_done: 0, reason }),
        };
        let (decision, code, writes, acked) = match outcome {
            Ok(e) => match &verdict {
                Some(v) if v.outcome == ChunkOutcome::Truncated => (Decision::Truncated, Some(ErrorCode::ChunkTruncated), e.writes, true),
                _ => (Decision::Executed, None, e.writes, true),
            },
            Err(e) => (Decision::Failed, Some(ErrorCode::ExecutionFailed), e.writes_done, false),
        };
        let info = json!({
            "approval_id": approval_id, "system_class": class, "release_ledger_seq": rseq, "release_entry_hash": rhash,
            "writes": writes, "acked": acked,
        });
        self.receipt(raw, now, decision, code, Some(&cmd), applied, verdict, Some(info))
    }

    /// The answer when the signer could not sign before a release: nothing was released, nothing is receipted, no
    /// state moved. Not signed, so `bytes` is empty and `signer_error` is set.
    fn unsigned(&self, cmd: &Command, reason: String) -> Receipt {
        let head = self.chain.len().saturating_sub(1);
        Receipt {
            value: json!({
                "format": "physical-receipt", "v": 1, "command_id": cmd.command_id, "decision": "failed",
                "error_code": "execution_failed", "execution": Value::Null,
            }),
            bytes: Vec::new(),
            decision: Decision::Failed,
            code: Some(ErrorCode::ExecutionFailed),
            ledger_seq: head as u64,
            ledger_entry_hash: self.chain.head().map(hex::encode).unwrap_or_default(),
            verdict: None,
            stop_request: None,
            signer_error: Some(reason),
        }
    }

    fn check(&self, raw: &[u8], now: u64, has_exec: bool) -> Result<Checked, Refusal> {
        use ErrorCode::*;
        let v = parse_canonical(raw).map_err(|e| (canon_code(e), None, None))?;
        let cmd = parse_command(&v).map_err(|e| (e, None, None))?;
        let fail = |c: ErrorCode, cmd: &Command| -> Refusal { (c, Some(cmd.clone()), None) };
        let p = &self.policy;

        if cmd.site_id != p.site_id {
            return Err(fail(WrongSite, &cmd));
        }
        if cmd.tenant != p.tenant {
            return Err(fail(WrongTenant, &cmd));
        }
        if self.kill.is_killed(&cmd.site_id, &cmd.actuator_id) {
            return Err(fail(KillSwitchActive, &cmd));
        }
        // Signature over the canonical command without its signature member.
        if !p.signers.contains(&cmd.signer) {
            return Err(fail(SignerNotEnrolled, &cmd));
        }
        let mut body = v.clone();
        body.as_object_mut().unwrap().remove("signature");
        let msg = canonical(&body).map_err(|_| fail(Malformed, &cmd))?;
        if !verify_ed25519(&cmd.signer, COMMAND_DOMAIN, msg.as_bytes(), &cmd.signature) {
            return Err(fail(BadSignature, &cmd));
        }
        // Stage and approval. A command never raises a stage or stands in for an approval.
        let Some(mode) = Mode::parse(&cmd.mode_text) else { return Err(fail(Malformed, &cmd)) };
        let mut release = None;
        let class = self.actuation.as_ref().and_then(|c| c.class_of(&cmd.actuator_id));
        if let (Some(cfg), Some(class)) = (&self.actuation, class) {
            let stage = cfg.stage_of(class);
            if stage == Stage::Observe {
                return Err(fail(ObserveOnly, &cmd));
            }
            if mode == Mode::Actuate {
                if stage != Stage::Actuate || !has_exec {
                    return Err(fail(ActuationNotApproved, &cmd));
                }
                match self.covering_approval(class, &cmd.actuator_id, &cmd.kind, now) {
                    Some(a) => release = Some((class.to_string(), a.approval_id.clone())),
                    None => return Err(fail(ActuationNotApproved, &cmd)),
                }
            }
        } else if mode == Mode::Actuate {
            return Err(fail(ActuationNotApproved, &cmd));
        }
        // Freshness.
        if cmd.issued_at_ms > now.saturating_add(p.max_skew_ms) || now < cmd.not_before_ms {
            return Err(fail(NotYetValid, &cmd));
        }
        if now >= cmd.expires_at_ms || now.saturating_sub(cmd.issued_at_ms) > p.max_age_ms {
            return Err(fail(Expired, &cmd));
        }
        if cmd.expires_at_ms < cmd.not_before_ms || cmd.expires_at_ms.saturating_sub(cmd.issued_at_ms) > p.max_ttl_ms {
            return Err(fail(TtlTooLong, &cmd));
        }
        // Replay.
        if cmd.command_seq <= self.last_seq {
            return Err(fail(ReplayedSequence, &cmd));
        }
        // Policy, model, birth record.
        if cmd.policy_sha256 != p.policy_sha256 {
            return Err(fail(PolicyHashMismatch, &cmd));
        }
        if !p.approved_models.contains(&cmd.model_sha256) {
            return Err(fail(ModelNotApproved, &cmd));
        }
        match &cmd.birth_record_sha256 {
            None if p.require_birth_record => return Err(fail(BirthRecordRequired, &cmd)),
            Some(b) if p.require_birth_record && !p.approved_birth_records.contains(b) => {
                return Err(fail(BirthRecordNotApproved, &cmd))
            }
            _ => {}
        }
        // Twin certificate.
        let cert = &cmd.cert;
        if !p.signers.contains(&cert.signer) {
            return Err(fail(TwinCertSignerNotEnrolled, &cmd));
        }
        let mut cbody = cert.raw.clone();
        cbody.as_object_mut().unwrap().remove("signature");
        let cmsg = canonical(&cbody).map_err(|_| fail(Malformed, &cmd))?;
        if !verify_ed25519(&cert.signer, CERT_DOMAIN, cmsg.as_bytes(), &cert.signature) {
            return Err(fail(TwinCertBadSignature, &cmd));
        }
        if cert.tenant != p.tenant {
            return Err(fail(TwinCertWrongTenant, &cmd));
        }
        if now < cert.valid_from_ms {
            return Err(fail(TwinCertNotYetValid, &cmd));
        }
        if now >= cert.valid_until_ms || cert.valid_until_ms < cmd.expires_at_ms {
            return Err(fail(TwinCertExpired, &cmd));
        }
        if cert.fidelity_score < p.min_fidelity {
            return Err(fail(TwinFidelityLow, &cmd));
        }
        if let Some(t) = &cmd.traj {
            // The chunk names the exact certificate it was planned inside.
            let cert_hash = sha256_hex(canonical(&cert.raw).map_err(|_| fail(Malformed, &cmd))?.as_bytes());
            if cert_hash != t.twin_cert_sha256 {
                return Err(fail(BandReferenceMismatch, &cmd));
            }
            let Some(lim) = p.trajectory_limits.iter().find(|l| l.actuator_id == cmd.actuator_id) else {
                return Err(fail(NoSiteLimit, &cmd));
            };
            let band = |quantity: &str, unit: &str| -> Vec<(f64, f64)> {
                cert.ranges.iter().filter(|r| r.quantity == quantity && r.unit == unit).map(|r| (r.min, r.max)).collect()
            };
            let prev = self.last_chunk.get(&cmd.actuator_id);
            let interval = prev.map(|e| cmd.issued_at_ms.saturating_sub(e.issued_at_ms));
            let ev = evaluate(t, lim, &band("joint_position", "radian"), &band("joint_effort", "newton_metre"), prev, interval, cmd.issued_at_ms);
            if ev.verdict.outcome == ChunkOutcome::Vetoed {
                let verdict = ev.verdict;
                return Err((ChunkVetoed, Some(cmd), Some(verdict)));
            }
            let update = Update { seq: cmd.command_seq, chunk: ev.end.map(|end| (cmd.actuator_id.clone(), end)), applied: None };
            return Ok(Checked { cmd, accepted: Accepted::Chunk(ev.verdict), update, release });
        }
        let certified = cert
            .ranges
            .iter()
            .any(|r| r.quantity == cmd.quantity && r.unit == cmd.unit && r.min <= cmd.value && cmd.value <= r.max);
        if !certified {
            return Err(fail(OutsideCertifiedRange, &cmd));
        }
        // Envelopes: the sender's, then the site's own, which is independent and decides.
        if !(cmd.env_min <= cmd.value && cmd.value <= cmd.env_max) {
            return Err(fail(OutsideLwEnvelope, &cmd));
        }
        let Some(lim) = p
            .limits
            .iter()
            .find(|l| l.actuator_id == cmd.actuator_id && l.quantity == cmd.quantity && l.unit == cmd.unit)
        else {
            return Err(fail(NoSiteLimit, &cmd));
        };
        if !(lim.min <= cmd.value && cmd.value <= lim.max) {
            return Err(fail(OutsideSiteEnvelope, &cmd));
        }
        let key = (cmd.actuator_id.clone(), cmd.quantity.clone());
        if let Some((last_v, last_t)) = self.last_applied.get(&key) {
            let dt_s = (cmd.issued_at_ms.saturating_sub(*last_t)).max(1) as f64 / 1000.0;
            let rate = (cmd.value - last_v).abs() / dt_s;
            if rate > lim.max_rate_per_s || rate > cmd.env_max_rate_per_s {
                return Err(fail(RateExceeded, &cmd));
            }
        }
        let applied = (cmd.env_min.max(lim.min), cmd.env_max.min(lim.max));
        // Accepted: the caller applies this once the command is final.
        let update = Update { seq: cmd.command_seq, chunk: None, applied: Some((key, (cmd.value, cmd.issued_at_ms))) };
        Ok(Checked { accepted: Accepted::Setpoint(applied), update, release, cmd })
    }

    /// The advisory stop request for a trajectory command, if one is due: a chunk that was vetoed or truncated for a
    /// limit violation, or any trajectory command that arrives while a kill order is in force. It is an output record
    /// addressed to the safety controller the site names. It is not an emergency stop and does not replace one: a
    /// network message is never the emergency stop device (Machinery Regulation (EU) 2023/1230, Annex III 1.2.4.3),
    /// and the safety controller decides what to do with it. Nothing here clears or resets a stop.
    fn stop_request(&self, raw: &[u8], now: u64, code: Option<ErrorCode>, cmd: &Command, verdict: Option<&ChunkVerdict>) -> Result<Option<Vec<u8>>, SignError> {
        let Some(lim) = self.policy.trajectory_limits.iter().find(|l| l.actuator_id == cmd.actuator_id) else { return Ok(None) };
        let Some(code) = code else { return Ok(None) };
        let reason = match (code, verdict) {
            (ErrorCode::ChunkVetoed, Some(_)) => "chunk_vetoed",
            (ErrorCode::ChunkTruncated, Some(_)) => "chunk_truncated",
            (ErrorCode::KillSwitchActive, _) => "kill_switch_active",
            _ => return Ok(None),
        };
        let mut v = json!({
            "format": "physical-stop-request",
            "v": 1,
            "request_id": format!("stop-{}", cmd.command_id),
            "tenant": self.policy.tenant,
            "site_id": self.policy.site_id,
            "actuator_id": cmd.actuator_id,
            "command_id": cmd.command_id,
            "command_sha256": sha256_hex(raw),
            "reason": reason,
            "first_violation": verdict.and_then(|x| x.first_violation).map(|x| x.to_json()),
            "safety_controller_id": lim.safety_controller_id,
            "requested_stop": lim.requested_stop.as_str(),
            "advisory": true,
            "emergency_stop": false,
            "receipt_seq": self.receipts,
            "issued_at_ms": now,
            "site_key": self.site_key_id(),
        });
        let msg = canonical(&v).unwrap();
        let sig = self.signer.sign(&domain_digest(STOP_REQUEST_DOMAIN, msg.as_bytes()))?;
        v["signature"] = Value::String(hex::encode(sig));
        Ok(Some(canonical(&v).unwrap().into_bytes()))
    }

    /// `execution` is the member for a command whose mode is `actuate`: `None` when it never reached release.
    #[allow(clippy::too_many_arguments)]
    fn receipt(&mut self, raw: &[u8], now: u64, decision: Decision, code: Option<ErrorCode>, cmd: Option<&Command>, applied: Option<(f64, f64)>, verdict: Option<ChunkVerdict>, execution: Option<Value>) -> Receipt {
        self.receipts += 1;
        let id = cmd.map(|c| c.command_id.clone()).unwrap_or_else(|| "unparsed".into());
        let mut v = json!({
            "format": "physical-receipt",
            "v": 1,
            "command_id": id,
            "tenant": self.policy.tenant,
            "site_id": self.policy.site_id,
            "decision": decision.as_str(),
            "error_code": code.map(|c| c.as_str()),
            "mode": cmd.map(|c| c.mode_text.clone()),
            "command_sha256": sha256_hex(raw),
            "policy_sha256": self.policy.policy_sha256,
            "model_sha256": cmd.map(|c| c.model_sha256.clone()),
            "birth_record_sha256": cmd.and_then(|c| c.birth_record_sha256.clone()),
            "envelope_applied": applied.map(|(a, b)| json!({"min": a, "max": b})),
            "decided_at_ms": now,
            "receipt_seq": self.receipts,
            "site_key": self.site_key_id(),
        });
        if cmd.is_some_and(|c| c.mode_text == "actuate") {
            v["execution"] = execution.unwrap_or(Value::Null);
        }
        let mut stop_request = None;
        let mut signer_error = None;
        if cmd.is_some_and(|c| c.kind == "trajectory") {
            stop_request = match self.stop_request(raw, now, code, cmd.unwrap(), verdict.as_ref()) {
                Ok(x) => x,
                Err(e) => {
                    signer_error = Some(e.reason);
                    None
                }
            };
            v["chunk"] = verdict.as_ref().map_or(Value::Null, |x| x.to_json());
            v["stop_request_sha256"] = stop_request.as_ref().map_or(Value::Null, |b| Value::String(sha256_hex(b)));
        }
        let digest = core_digest(&v);
        let result = format!("{}:{}:{}", decision.as_str(), code.map_or("ok", |c| c.as_str()), digest);
        let actor = format!("gate:{}", self.policy.site_id);
        let entry_hash = self.chain.append(now, OpKind::Command, actor, id, result);
        let seq = (self.chain.len() - 1) as u64;
        let eh = hex::encode(entry_hash);
        v["ledger"] = json!({"seq": seq, "entry_hash": eh});
        let msg = canonical(&v).unwrap();
        let bytes = match self.signer.sign(&domain_digest(RECEIPT_DOMAIN, msg.as_bytes())) {
            Ok(sig) if signer_error.is_none() => {
                v["signature"] = Value::String(hex::encode(sig));
                canonical(&v).unwrap().into_bytes()
            }
            Ok(_) => Vec::new(),
            Err(e) => {
                signer_error = Some(e.reason);
                Vec::new()
            }
        };
        Receipt { value: v, bytes, decision, code, ledger_seq: seq, ledger_entry_hash: eh, verdict, stop_request, signer_error }
    }
}
