//! The gate: one command in, one signed and chained receipt out. Checks run in a fixed order and the first failure is
//! the answer, so one bad command has one code.

use crate::canon::{canonical, parse_canonical, CanonError};
use crate::chunk::{evaluate, ChunkOutcome, ChunkVerdict, EndState, STOP_REQUEST_DOMAIN};
use crate::command::{parse_command, Command, ErrorCode, Mode};
use crate::policy::SitePolicy;
use crate::receipt::{core_digest, Decision, Receipt};
use crate::{domain_digest, sha256_hex, verify_ed25519, CERT_DOMAIN, COMMAND_DOMAIN, RECEIPT_DOMAIN};
use ed25519_dalek::{Signer, SigningKey};
use furcate_ledger::{Chain, OpKind};
use serde_json::{json, Value};
use std::collections::HashMap;

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

pub struct Gate<K: KillState> {
    policy: SitePolicy,
    kill: K,
    site_key: SigningKey,
    chain: Chain,
    last_seq: u64,
    last_applied: HashMap<(String, String), (f64, u64)>,
    /// Where the last accepted chunk ended, per actuator.
    last_chunk: HashMap<String, EndState>,
    receipts: u64,
}

/// What an accepted command was accepted as.
enum Accepted {
    Setpoint((f64, f64)),
    Chunk(ChunkVerdict),
}

type Refusal = (ErrorCode, Option<Command>, Option<ChunkVerdict>);

fn canon_code(e: CanonError) -> ErrorCode {
    match e {
        CanonError::NotCanonical => ErrorCode::NotCanonical,
        _ => ErrorCode::Malformed,
    }
}

impl<K: KillState> Gate<K> {
    pub fn new(policy: SitePolicy, kill: K, site_key: SigningKey, chain: Chain) -> Self {
        Gate { policy, kill, site_key, chain, last_seq: 0, last_applied: HashMap::new(), last_chunk: HashMap::new(), receipts: 0 }
    }

    pub fn site_key_id(&self) -> String {
        format!("ed25519:{}", hex::encode(self.site_key.verifying_key().to_bytes()))
    }
    pub fn chain(&self) -> &Chain {
        &self.chain
    }
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Decide one command given as the bytes received. Always returns a receipt, and has appended it to the chain.
    pub fn decide(&mut self, raw: &[u8], now_ms: u64) -> Receipt {
        let (decision, code, cmd, applied, verdict) = match self.check(raw, now_ms) {
            Ok((cmd, Accepted::Setpoint(a))) => (Decision::Shadowed, None, Some(cmd), Some(a), None),
            Ok((cmd, Accepted::Chunk(v))) => {
                let (d, c) = if v.outcome == ChunkOutcome::Truncated {
                    (Decision::Truncated, Some(ErrorCode::ChunkTruncated))
                } else {
                    (Decision::Shadowed, None)
                };
                (d, c, Some(cmd), None, Some(v))
            }
            Err((code, cmd, verdict)) => {
                let d = match code {
                    ErrorCode::Expired => Decision::Expired,
                    ErrorCode::KillSwitchActive => Decision::Killed,
                    _ => Decision::Denied,
                };
                (d, Some(code), cmd, None, verdict)
            }
        };
        self.receipt(raw, now_ms, decision, code, cmd.as_ref(), applied, verdict)
    }

    fn check(&mut self, raw: &[u8], now: u64) -> Result<(Command, Accepted), Refusal> {
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
        // Mode: shadow only.
        match Mode::parse(&cmd.mode_text) {
            Ok(Mode::Shadow) => {}
            Err(Some(_)) => return Err(fail(ActuationNotApproved, &cmd)),
            Err(None) => return Err(fail(Malformed, &cmd)),
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
            self.last_seq = cmd.command_seq;
            if let Some(end) = ev.end {
                self.last_chunk.insert(cmd.actuator_id.clone(), end);
            }
            return Ok((cmd, Accepted::Chunk(ev.verdict)));
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
        // Accepted in shadow: remember it, do nothing else.
        self.last_seq = cmd.command_seq;
        self.last_applied.insert(key, (cmd.value, cmd.issued_at_ms));
        Ok((cmd, Accepted::Setpoint(applied)))
    }

    /// The advisory stop request for a trajectory command, if one is due: a chunk that was vetoed or truncated for a
    /// limit violation, or any trajectory command that arrives while a kill order is in force. It is an output record
    /// addressed to the safety controller the site names. It is not an emergency stop and does not replace one: a
    /// network message is never the emergency stop device (Machinery Regulation (EU) 2023/1230, Annex III 1.2.4.3),
    /// and the safety controller decides what to do with it. Nothing here clears or resets a stop.
    fn stop_request(&self, raw: &[u8], now: u64, code: Option<ErrorCode>, cmd: &Command, verdict: Option<&ChunkVerdict>) -> Option<Vec<u8>> {
        let lim = self.policy.trajectory_limits.iter().find(|l| l.actuator_id == cmd.actuator_id)?;
        let reason = match (code?, verdict) {
            (ErrorCode::ChunkVetoed, Some(_)) => "chunk_vetoed",
            (ErrorCode::ChunkTruncated, Some(_)) => "chunk_truncated",
            (ErrorCode::KillSwitchActive, _) => "kill_switch_active",
            _ => return None,
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
        let sig = self.site_key.sign(&domain_digest(STOP_REQUEST_DOMAIN, msg.as_bytes()));
        v["signature"] = Value::String(hex::encode(sig.to_bytes()));
        Some(canonical(&v).unwrap().into_bytes())
    }

    fn receipt(&mut self, raw: &[u8], now: u64, decision: Decision, code: Option<ErrorCode>, cmd: Option<&Command>, applied: Option<(f64, f64)>, verdict: Option<ChunkVerdict>) -> Receipt {
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
        let mut stop_request = None;
        if cmd.is_some_and(|c| c.kind == "trajectory") {
            stop_request = self.stop_request(raw, now, code, cmd.unwrap(), verdict.as_ref());
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
        let sig = self.site_key.sign(&domain_digest(RECEIPT_DOMAIN, msg.as_bytes()));
        v["signature"] = Value::String(hex::encode(sig.to_bytes()));
        let bytes = canonical(&v).unwrap().into_bytes();
        Receipt { value: v, bytes, decision, code, ledger_seq: seq, ledger_entry_hash: eh, verdict, stop_request }
    }
}
