//! The model-update record: how a born agent that keeps learning stays verifiable.
//!
//! A birth record is a one-time release. An agent that improves in place has a new model after every update, and a
//! new model without a record is an unreleased model. A `model-update` record binds the step from the old model hash
//! to the new one: the birth record of the lineage, the previous update, the experience that produced the new model
//! (a reference to its own experience ledger, chained to the one before), the evaluation against the release gate,
//! and the chain of signers with the attestation level of each and the minimum along the chain. The register
//! ([`UpdateRegister`]) decides every record, refusals included, and appends one `ModelUpdate` entry per decision to
//! a ledger chain. Contract, codes and the golden vector are in docs/model-update.md.
//!
//! Shadow only, like the rest of this crate: accepting an update changes what the register considers the current
//! model of an agent and writes a ledger entry. It loads nothing and moves nothing. The site's own approved model
//! list stays the site's decision.

use crate::canon::{canonical, parse_canonical};
use crate::command::{exact, s, u};
use crate::{domain_digest, is_lower_hex, sha256_hex, verify_ed25519};
use ed25519_dalek::{Signer, SigningKey};
use furcate_ledger::{Chain, OpKind};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const UPDATE_FORMAT: &str = "model-update";
pub const UPDATE_VERSION: u64 = 1;
pub const UPDATE_DOMAIN: &str = "lw-physical/model-update/v1";
/// A record is valid for at most 366 days from issue.
pub const MAX_VALIDITY_MS: u64 = 366 * 86_400_000;
const MAX_SAFE: u64 = (1 << 53) - 1;
/// Attestation classes, lowest first. The same order as the birth record's `min_attestation`.
pub const CLASSES: [&str; 6] = ["soft", "device", "se", "tee", "dice", "tpm"];
const ROLES: [&str; 3] = ["trainer", "evaluator", "releaser"];
const MAX_SIGNERS: usize = 8;

pub fn class_rank(c: &str) -> Option<usize> {
    CLASSES.iter().position(|x| *x == c)
}

macro_rules! refusals {
    ($($v:ident = $s:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum UpdateRefusal { $($v),* }
        impl UpdateRefusal {
            pub fn code(&self) -> &'static str { match self { $(UpdateRefusal::$v => $s),* } }
            pub const ALL: &'static [UpdateRefusal] = &[$(UpdateRefusal::$v),*];
        }
    };
}

refusals! {
    Malformed = "malformed",
    NotCanonical = "not_canonical",
    WrongFormat = "wrong_format",
    UnsupportedVersion = "unsupported_version",
    WrongTenant = "wrong_tenant",
    AgentUnknown = "agent_unknown",
    SignerChainInvalid = "signer_chain_invalid",
    SignerNotEnrolled = "signer_not_enrolled",
    AttestationMismatch = "attestation_mismatch",
    BadSignature = "bad_signature",
    AttestationBelowFloor = "attestation_below_floor",
    NotYetValid = "not_yet_valid",
    Expired = "expired",
    WindowInvalid = "window_invalid",
    BirthRecordMismatch = "birth_record_mismatch",
    ReplayedUpdate = "replayed_update",
    EvaluationInconsistent = "evaluation_inconsistent",
    EvaluationFailed = "evaluation_failed",
    SameModel = "same_model",
    OldModelNotCurrent = "old_model_not_current",
    WrongParent = "wrong_parent",
    WrongParentLedger = "wrong_parent_ledger",
    RollbackTargetUnknown = "rollback_target_unknown",
}

#[derive(Clone, Debug)]
pub struct SignerEntry {
    pub key: String,
    pub attestation: String,
    pub role: String,
}

#[derive(Clone, Debug)]
pub struct ModelUpdate {
    pub raw: Value,
    pub update_id: String,
    pub tenant: String,
    pub agent_id: String,
    pub rollback: bool,
    pub old_model_sha256: String,
    pub new_model_sha256: String,
    pub birth_record_sha256: String,
    pub parent_update_sha256: Option<String>,
    pub ledger_head: String,
    pub parent_ledger_head: String,
    pub ledger_entries: u64,
    pub training_ref_sha256: String,
    pub validated_delta: u64,
    pub unvalidated_delta: u64,
    pub passed: bool,
    pub signers: Vec<SignerEntry>,
    pub attestation_min: String,
    pub issued_ms: u64,
    pub valid_until_ms: u64,
    pub signatures: Vec<String>,
}

fn hex64(x: &str) -> bool {
    x.len() == 64 && is_lower_hex(x)
}
fn idok(x: &str) -> bool {
    !x.is_empty() && x.len() <= 64 && x.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn int(m: &serde_json::Map<String, Value>, k: &str) -> Option<u64> {
    u(m, k).filter(|x| *x <= MAX_SAFE)
}
fn hexf(m: &serde_json::Map<String, Value>, k: &str) -> Result<String, UpdateRefusal> {
    let x = s(m, k).ok_or(UpdateRefusal::Malformed)?;
    if hex64(x) {
        Ok(x.to_string())
    } else {
        Err(UpdateRefusal::Malformed)
    }
}

/// What the evaluation must say, recomputed from its own figures: every benchmark with a threshold at or above it,
/// the fidelity at or above its minimum, and the release point inside the freshly solved band.
fn recompute_passed(benchmarks: &[Value], fidelity: u64, minimum: u64, inside_band: bool) -> Result<bool, UpdateRefusal> {
    let mut ok = fidelity >= minimum && inside_band && !benchmarks.is_empty();
    for b in benchmarks {
        let m = exact(b, &["name", "score_ppm"], &["threshold_ppm"]).ok_or(UpdateRefusal::Malformed)?;
        let score = int(m, "score_ppm").ok_or(UpdateRefusal::Malformed)?;
        if s(m, "name").is_none_or(|n| !idok(n)) {
            return Err(UpdateRefusal::Malformed);
        }
        if let Some(t) = m.get("threshold_ppm") {
            if score < t.as_u64().filter(|x| *x <= MAX_SAFE).ok_or(UpdateRefusal::Malformed)? {
                ok = false;
            }
        }
    }
    Ok(ok)
}

pub fn parse_update(v: &Value) -> Result<ModelUpdate, UpdateRefusal> {
    use UpdateRefusal::*;
    let m = exact(
        v,
        &[
            "format", "v", "update_id", "tenant", "agent_id", "reason", "old_model_sha256", "new_model_sha256", "birth_record_sha256",
            "parent_update_sha256", "experience", "evaluation", "signers", "attestation_min", "issued_ms", "valid_until_ms", "signatures",
        ],
        &[],
    )
    .ok_or(Malformed)?;
    if s(m, "format") != Some(UPDATE_FORMAT) {
        return Err(WrongFormat);
    }
    if u(m, "v") != Some(UPDATE_VERSION) {
        return Err(UnsupportedVersion);
    }
    let ex = exact(
        &m["experience"],
        &["ledger_head", "parent_ledger_head", "ledger_entries", "training_ref_sha256", "simulated_seconds_validated_delta", "simulated_seconds_unvalidated_delta"],
        &[],
    )
    .ok_or(Malformed)?;
    let ev = exact(
        &m["evaluation"],
        &["gate", "benchmarks", "fidelity_ppm", "fidelity_minimum_ppm", "band_certificate_sha256", "release_point_inside_band", "result"],
        &[],
    )
    .ok_or(Malformed)?;
    if s(ev, "gate") != Some("release-gate") {
        return Err(Malformed);
    }
    let bench = ev["benchmarks"].as_array().ok_or(Malformed)?;
    let names: Vec<&str> = bench.iter().filter_map(|b| b.get("name").and_then(|n| n.as_str())).collect();
    if bench.len() > 64 || names.len() != bench.len() || names.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Malformed); // sorted by name, unique
    }
    let inside = ev["release_point_inside_band"].as_bool().ok_or(Malformed)?;
    let claimed = match s(ev, "result").ok_or(Malformed)? {
        "passed" => true,
        "failed" => false,
        _ => return Err(Malformed),
    };
    let fid = int(ev, "fidelity_ppm").ok_or(Malformed)?;
    let fmin = int(ev, "fidelity_minimum_ppm").ok_or(Malformed)?;
    hexf(ev, "band_certificate_sha256")?;
    let passed = recompute_passed(bench, fid, fmin, inside)?;
    if passed != claimed {
        return Err(EvaluationInconsistent);
    }
    let sg = m["signers"].as_array().ok_or(Malformed)?;
    let sigs = m["signatures"].as_array().ok_or(Malformed)?;
    if sg.is_empty() || sg.len() > MAX_SIGNERS || sigs.len() != sg.len() {
        return Err(SignerChainInvalid);
    }
    let mut signers = vec![];
    for x in sg {
        let sm = exact(x, &["key", "attestation", "role"], &[]).ok_or(Malformed)?;
        let key = s(sm, "key").ok_or(Malformed)?;
        let att = s(sm, "attestation").ok_or(Malformed)?;
        let role = s(sm, "role").ok_or(Malformed)?;
        if !key.strip_prefix("ed25519:").is_some_and(hex64) || class_rank(att).is_none() || !ROLES.contains(&role) {
            return Err(Malformed);
        }
        signers.push(SignerEntry { key: key.into(), attestation: att.into(), role: role.into() });
    }
    let mut signatures = vec![];
    for x in sigs {
        let sig = x.as_str().ok_or(Malformed)?;
        if sig.len() != 128 || !is_lower_hex(sig) {
            return Err(Malformed);
        }
        signatures.push(sig.to_string());
    }
    let keys: HashSet<&str> = signers.iter().map(|x| x.key.as_str()).collect();
    if keys.len() != signers.len() || signers.last().is_none_or(|x| x.role != "releaser") {
        return Err(SignerChainInvalid);
    }
    let reason = s(m, "reason").ok_or(Malformed)?;
    if reason != "learn" && reason != "rollback" {
        return Err(Malformed);
    }
    let parent = match &m["parent_update_sha256"] {
        Value::Null => None,
        Value::String(x) if hex64(x) => Some(x.clone()),
        _ => return Err(Malformed),
    };
    let up = ModelUpdate {
        raw: v.clone(),
        update_id: s(m, "update_id").ok_or(Malformed)?.into(),
        tenant: s(m, "tenant").ok_or(Malformed)?.into(),
        agent_id: s(m, "agent_id").ok_or(Malformed)?.into(),
        rollback: reason == "rollback",
        old_model_sha256: hexf(m, "old_model_sha256")?,
        new_model_sha256: hexf(m, "new_model_sha256")?,
        birth_record_sha256: hexf(m, "birth_record_sha256")?,
        parent_update_sha256: parent,
        ledger_head: hexf(ex, "ledger_head")?,
        parent_ledger_head: hexf(ex, "parent_ledger_head")?,
        ledger_entries: int(ex, "ledger_entries").filter(|x| *x >= 1).ok_or(Malformed)?,
        training_ref_sha256: hexf(ex, "training_ref_sha256")?,
        validated_delta: int(ex, "simulated_seconds_validated_delta").ok_or(Malformed)?,
        unvalidated_delta: int(ex, "simulated_seconds_unvalidated_delta").ok_or(Malformed)?,
        passed,
        signers,
        attestation_min: s(m, "attestation_min").ok_or(Malformed)?.into(),
        issued_ms: int(m, "issued_ms").ok_or(Malformed)?,
        valid_until_ms: int(m, "valid_until_ms").ok_or(Malformed)?,
        signatures,
    };
    if !idok(&up.update_id) || !idok(&up.tenant) || !idok(&up.agent_id) || class_rank(&up.attestation_min).is_none() {
        return Err(Malformed);
    }
    Ok(up)
}

/// The bytes every signer signs: the canonical record without its `signatures` member.
pub fn signing_bytes(v: &Value) -> Result<Vec<u8>, UpdateRefusal> {
    let mut c = v.clone();
    c.as_object_mut().ok_or(UpdateRefusal::Malformed)?.remove("signatures");
    Ok(canonical(&c).map_err(|_| UpdateRefusal::Malformed)?.into_bytes())
}

/// Sign a record on behalf of one chain member (tests and the golden vector; the production signers are
/// hardware-backed keys held outside this repository). Appends the signature at the member's position.
pub fn sign_update(v: &mut Value, key: &SigningKey) -> Result<(), UpdateRefusal> {
    let msg = signing_bytes(v)?;
    let sig = key.sign(&domain_digest(UPDATE_DOMAIN, &msg));
    v["signatures"].as_array_mut().ok_or(UpdateRefusal::Malformed)?.push(Value::String(hex::encode(sig.to_bytes())));
    Ok(())
}

/// The lowest attestation class along a chain given as class names. `None` for an empty chain or an unknown class.
pub fn min_attestation<'a>(classes: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    let mut lo: Option<usize> = None;
    for c in classes {
        let r = class_rank(c)?;
        lo = Some(lo.map_or(r, |l| l.min(r)));
    }
    lo.map(|r| CLASSES[r])
}

#[derive(Clone, Debug)]
pub struct Lineage {
    pub birth_record_sha256: String,
    pub current_model: String,
    /// Every model hash this lineage has approved, oldest first. A rollback may return only to one of these.
    pub history: Vec<String>,
    pub last_update_sha256: Option<String>,
    /// Head of the experience ledger the current model came from: the birth ledger's, then each update's.
    pub last_ledger_head: String,
    pub updates: u64,
}

/// The decision on one record. A ledger entry exists for every decision.
#[derive(Clone, Debug)]
pub struct UpdateDecision {
    pub accepted: bool,
    pub code: Option<UpdateRefusal>,
    pub update_sha256: String,
    pub ledger_seq: u64,
    pub ledger_entry_hash: String,
}

pub struct UpdateRegister {
    tenant: String,
    /// Enrolled signer keys and the attestation class each was enrolled at.
    enrolled: HashMap<String, String>,
    floor: &'static str,
    lineages: HashMap<String, Lineage>,
    seen: HashSet<String>,
    chain: Chain,
}

impl UpdateRegister {
    /// `floor` is the lowest `attestation_min` accepted. `enrolled` maps `ed25519:<hex>` to the class it was enrolled at.
    pub fn new(tenant: &str, enrolled: Vec<(String, String)>, floor: &str, chain: Chain) -> Option<Self> {
        let floor = CLASSES[class_rank(floor)?];
        if enrolled.iter().any(|(_, c)| class_rank(c).is_none()) {
            return None;
        }
        Some(UpdateRegister { tenant: tenant.into(), enrolled: enrolled.into_iter().collect(), floor, lineages: HashMap::new(), seen: HashSet::new(), chain })
    }

    /// Register a born agent: its birth record hash, the model it was born with and the head of the experience ledger
    /// that birth record committed to. The birth record itself is verified elsewhere (`docs/birth-record.md`).
    pub fn born(&mut self, agent_id: &str, birth_record_sha256: &str, model_sha256: &str, ledger_head: &str) {
        self.lineages.insert(
            agent_id.into(),
            Lineage {
                birth_record_sha256: birth_record_sha256.into(),
                current_model: model_sha256.into(),
                history: vec![model_sha256.into()],
                last_update_sha256: None,
                last_ledger_head: ledger_head.into(),
                updates: 0,
            },
        );
    }

    pub fn lineage(&self, agent_id: &str) -> Option<&Lineage> {
        self.lineages.get(agent_id)
    }
    pub fn chain(&self) -> &Chain {
        &self.chain
    }
    /// Model hashes approved for an agent so far, for the site to consider adding to its own approved list.
    pub fn approved_models(&self, agent_id: &str) -> Vec<String> {
        self.lineages.get(agent_id).map(|l| l.history.clone()).unwrap_or_default()
    }

    /// Decide one record given as the bytes received; always appends one `ModelUpdate` ledger entry.
    pub fn decide(&mut self, raw: &[u8], now_ms: u64) -> UpdateDecision {
        let update_sha = sha256_hex(raw);
        let (code, up) = match self.check(raw, now_ms) {
            Ok(up) => (None, Some(up)),
            Err((c, up)) => (Some(c), up),
        };
        let subject = up.as_ref().map(|u| u.update_id.clone()).unwrap_or_else(|| "unparsed".into());
        let agent = up.as_ref().map(|u| u.agent_id.clone()).unwrap_or_else(|| "unknown".into());
        let verdict = if code.is_none() { "accepted" } else { "refused" };
        let result = format!("{}:{}:{}", verdict, code.map_or("ok", |c| c.code()), update_sha);
        let seq = self.chain.len() as u64;
        let eh = self.chain.append(now_ms, OpKind::ModelUpdate, format!("update-gate:{agent}"), subject, result);
        UpdateDecision { accepted: code.is_none(), code, update_sha256: update_sha, ledger_seq: seq, ledger_entry_hash: hex::encode(eh) }
    }

    fn check(&mut self, raw: &[u8], now: u64) -> Result<ModelUpdate, (UpdateRefusal, Option<ModelUpdate>)> {
        use UpdateRefusal::*;
        let v = parse_canonical(raw).map_err(|e| (if e == crate::canon::CanonError::NotCanonical { NotCanonical } else { Malformed }, None))?;
        let up = parse_update(&v).map_err(|e| (e, None))?;
        let fail = |c: UpdateRefusal, up: &ModelUpdate| (c, Some(up.clone()));
        if up.tenant != self.tenant {
            return Err(fail(WrongTenant, &up));
        }
        // Signers: enrolled, at the attestation they claim, then the signatures over the record.
        for sg in &up.signers {
            match self.enrolled.get(&sg.key) {
                None => return Err(fail(SignerNotEnrolled, &up)),
                Some(c) if *c != sg.attestation => return Err(fail(AttestationMismatch, &up)),
                _ => {}
            }
        }
        let msg = signing_bytes(&v).map_err(|e| (e, Some(up.clone())))?;
        for (sg, sig) in up.signers.iter().zip(&up.signatures) {
            if !verify_ed25519(&sg.key, UPDATE_DOMAIN, &msg, sig) {
                return Err(fail(BadSignature, &up));
            }
        }
        let lowest = min_attestation(up.signers.iter().map(|x| x.attestation.as_str())).unwrap();
        if up.attestation_min != lowest {
            return Err(fail(AttestationMismatch, &up));
        }
        if class_rank(lowest) < class_rank(self.floor) {
            return Err(fail(AttestationBelowFloor, &up));
        }
        if up.valid_until_ms <= up.issued_ms || up.valid_until_ms - up.issued_ms > MAX_VALIDITY_MS {
            return Err(fail(WindowInvalid, &up));
        }
        if now < up.issued_ms {
            return Err(fail(NotYetValid, &up));
        }
        if now >= up.valid_until_ms {
            return Err(fail(Expired, &up));
        }
        let Some(l) = self.lineages.get(&up.agent_id) else { return Err(fail(AgentUnknown, &up)) };
        if up.birth_record_sha256 != l.birth_record_sha256 {
            return Err(fail(BirthRecordMismatch, &up));
        }
        let key = sha256_hex(raw);
        if self.seen.contains(&up.update_id) || self.seen.contains(&key) {
            return Err(fail(ReplayedUpdate, &up));
        }
        if !up.passed {
            return Err(fail(EvaluationFailed, &up));
        }
        if up.old_model_sha256 == up.new_model_sha256 {
            return Err(fail(SameModel, &up));
        }
        if up.old_model_sha256 != l.current_model {
            return Err(fail(OldModelNotCurrent, &up));
        }
        if up.parent_update_sha256 != l.last_update_sha256 {
            return Err(fail(WrongParent, &up));
        }
        if up.parent_ledger_head != l.last_ledger_head {
            return Err(fail(WrongParentLedger, &up));
        }
        if up.rollback && !l.history.contains(&up.new_model_sha256) {
            return Err(fail(RollbackTargetUnknown, &up));
        }
        // Accepted: this is now the agent's model.
        let l = self.lineages.get_mut(&up.agent_id).unwrap();
        l.current_model = up.new_model_sha256.clone();
        if !l.history.contains(&up.new_model_sha256) {
            l.history.push(up.new_model_sha256.clone());
        }
        l.last_update_sha256 = Some(key.clone());
        l.last_ledger_head = up.ledger_head.clone();
        l.updates += 1;
        self.seen.insert(up.update_id.clone());
        self.seen.insert(key);
        Ok(up)
    }
}
