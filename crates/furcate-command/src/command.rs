//! The `physical-command` record: strict parsing into typed fields, nothing guessed.

use crate::chunk::{parse_body, Trajectory};
use crate::is_lower_hex;
use serde_json::{Map, Value};

/// What a command asks of the site. `Actuate` is honoured only for an actuator whose system class is at stage
/// `actuate` and which an installed actuation approval covers; every other case is a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Shadow,
    Actuate,
}

impl Mode {
    /// The mode named by a command's `mode` member, or `None` for any other text.
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "shadow" => Some(Mode::Shadow),
            "actuate" => Some(Mode::Actuate),
            _ => None,
        }
    }
}

macro_rules! codes {
    ($($v:ident = $s:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum ErrorCode { $($v),* }
        impl ErrorCode {
            pub fn as_str(&self) -> &'static str { match self { $(ErrorCode::$v => $s),* } }
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$v),*];
        }
    };
}

codes! {
    Malformed = "malformed",
    NotCanonical = "not_canonical",
    UnsupportedFormat = "unsupported_format",
    UnsupportedKind = "unsupported_kind",
    WrongSite = "wrong_site",
    WrongTenant = "wrong_tenant",
    KillSwitchActive = "kill_switch_active",
    SignerNotEnrolled = "signer_not_enrolled",
    BadSignature = "bad_signature",
    ActuationNotApproved = "actuation_not_approved",
    Expired = "expired",
    NotYetValid = "not_yet_valid",
    TtlTooLong = "ttl_too_long",
    ReplayedSequence = "replayed_sequence",
    PolicyHashMismatch = "policy_hash_mismatch",
    ModelNotApproved = "model_not_approved",
    BirthRecordRequired = "birth_record_required",
    BirthRecordNotApproved = "birth_record_not_approved",
    TwinCertSignerNotEnrolled = "twin_cert_signer_not_enrolled",
    TwinCertBadSignature = "twin_cert_bad_signature",
    TwinCertWrongTenant = "twin_cert_wrong_tenant",
    TwinCertExpired = "twin_cert_expired",
    TwinCertNotYetValid = "twin_cert_not_yet_valid",
    TwinFidelityLow = "twin_fidelity_low",
    OutsideCertifiedRange = "outside_certified_range",
    OutsideLwEnvelope = "outside_lw_envelope",
    NoSiteLimit = "no_site_limit",
    OutsideSiteEnvelope = "outside_site_envelope",
    RateExceeded = "rate_exceeded",
    ChunkVetoed = "chunk_vetoed",
    ChunkTruncated = "chunk_truncated",
    BandReferenceMismatch = "band_reference_mismatch",
    ObserveOnly = "observe_only",
    ExecutionFailed = "execution_failed",
}

#[derive(Clone, Debug)]
pub struct CertRange {
    pub quantity: String,
    pub unit: String,
    pub min: f64,
    pub max: f64,
}

#[derive(Clone, Debug)]
pub struct Cert {
    pub raw: Value,
    pub tenant: String,
    pub twin_id: String,
    pub version: u64,
    pub ranges: Vec<CertRange>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub fidelity_score: f64,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct Command {
    pub raw: Value,
    /// `setpoint` or `trajectory`. For a trajectory the setpoint fields below (`quantity`, `unit`, `value`, the
    /// envelope) are empty or zero and `traj` carries the chunk.
    pub kind: String,
    pub traj: Option<Trajectory>,
    pub command_id: String,
    pub tenant: String,
    pub site_id: String,
    pub actuator_id: String,
    pub scope: String,
    pub quantity: String,
    pub unit: String,
    pub value: f64,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
    pub command_seq: u64,
    pub mode_text: String,
    pub policy_sha256: String,
    pub model_sha256: String,
    pub birth_record_sha256: Option<String>,
    pub env_min: f64,
    pub env_max: f64,
    pub env_max_rate_per_s: f64,
    pub cert: Cert,
    pub signer: String,
    pub signature: String,
}

pub const MAX_ID: usize = 64;

pub(crate) fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
pub(crate) fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}
pub(crate) fn hex_ok(s: &str, n: usize) -> bool {
    s.len() == n && is_lower_hex(s)
}
pub(crate) fn key_ok(s: &str) -> bool {
    s.strip_prefix("ed25519:").is_some_and(|h| hex_ok(h, 64))
}

/// The object must have exactly these keys (and `optional` ones if present).
pub(crate) fn exact<'a>(v: &'a Value, req: &[&str], opt: &[&str]) -> Option<&'a Map<String, Value>> {
    let m = v.as_object()?;
    if !req.iter().all(|k| m.contains_key(*k)) {
        return None;
    }
    if !m.keys().all(|k| req.contains(&k.as_str()) || opt.contains(&k.as_str())) {
        return None;
    }
    Some(m)
}
pub(crate) fn s<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k)?.as_str()
}
pub(crate) fn u(m: &Map<String, Value>, k: &str) -> Option<u64> {
    m.get(k)?.as_u64()
}
pub(crate) fn f(m: &Map<String, Value>, k: &str) -> Option<f64> {
    let x = m.get(k)?.as_f64()?;
    x.is_finite().then_some(x)
}

/// Why a parsed document is not a command of the kinds this gate knows.
pub fn parse_command(v: &Value) -> Result<Command, ErrorCode> {
    use ErrorCode::*;
    let is_traj = v.get("kind").and_then(|k| k.as_str()) == Some("trajectory");
    let mut req = vec![
        "format", "v", "command_id", "tenant", "site_id", "target", "kind", "body", "issued_at_ms", "not_before_ms",
        "expires_at_ms", "nonce", "command_seq", "mode", "policy_sha256", "model_sha256", "twin_cert", "signer", "signature",
    ];
    if !is_traj {
        req.push("envelope");
    }
    let m = exact(v, &req, &["birth_record_sha256"]).ok_or(Malformed)?;
    if s(m, "format") != Some("physical-command") || u(m, "v") != Some(1) {
        return Err(UnsupportedFormat);
    }
    let kind = s(m, "kind").ok_or(Malformed)?;
    if kind != "setpoint" && kind != "trajectory" {
        return Err(UnsupportedKind);
    }
    let target = exact(&m["target"], &["actuator_id", "scope"], &[]).ok_or(Malformed)?;
    let empty = Map::new();
    let (body, env, traj) = if is_traj {
        (&empty, &empty, Some(parse_body(&m["body"])?))
    } else {
        (
            exact(&m["body"], &["quantity", "unit", "value"], &[]).ok_or(Malformed)?,
            exact(&m["envelope"], &["min", "max", "max_rate_per_s"], &[]).ok_or(Malformed)?,
            None,
        )
    };
    let cert = parse_cert(&m["twin_cert"])?;

    let c = Command {
        raw: v.clone(),
        kind: kind.to_string(),
        traj,
        command_id: s(m, "command_id").ok_or(Malformed)?.into(),
        tenant: s(m, "tenant").ok_or(Malformed)?.into(),
        site_id: s(m, "site_id").ok_or(Malformed)?.into(),
        actuator_id: s(target, "actuator_id").ok_or(Malformed)?.into(),
        scope: s(target, "scope").ok_or(Malformed)?.into(),
        quantity: if is_traj { String::new() } else { s(body, "quantity").ok_or(Malformed)?.into() },
        unit: if is_traj { String::new() } else { s(body, "unit").ok_or(Malformed)?.into() },
        value: if is_traj { 0.0 } else { f(body, "value").ok_or(Malformed)? },
        issued_at_ms: u(m, "issued_at_ms").ok_or(Malformed)?,
        not_before_ms: u(m, "not_before_ms").ok_or(Malformed)?,
        expires_at_ms: u(m, "expires_at_ms").ok_or(Malformed)?,
        nonce: s(m, "nonce").ok_or(Malformed)?.into(),
        command_seq: u(m, "command_seq").ok_or(Malformed)?,
        mode_text: s(m, "mode").ok_or(Malformed)?.into(),
        policy_sha256: s(m, "policy_sha256").ok_or(Malformed)?.into(),
        model_sha256: s(m, "model_sha256").ok_or(Malformed)?.into(),
        birth_record_sha256: match m.get("birth_record_sha256") {
            None => None,
            Some(x) => Some(x.as_str().ok_or(Malformed)?.to_string()),
        },
        env_min: if is_traj { 0.0 } else { f(env, "min").ok_or(Malformed)? },
        env_max: if is_traj { 0.0 } else { f(env, "max").ok_or(Malformed)? },
        env_max_rate_per_s: if is_traj { 0.0 } else { f(env, "max_rate_per_s").ok_or(Malformed)? },
        cert,
        signer: s(m, "signer").ok_or(Malformed)?.into(),
        signature: s(m, "signature").ok_or(Malformed)?.into(),
    };
    let ok = id_ok(&c.command_id)
        && id_ok(&c.tenant)
        && id_ok(&c.site_id)
        && id_ok(&c.actuator_id)
        && id_ok(&c.scope)
        && (is_traj || (name_ok(&c.quantity) && name_ok(&c.unit)))
        && hex_ok(&c.nonce, 32)
        && c.command_seq >= 1
        && matches!(c.mode_text.as_str(), "shadow" | "actuate")
        && hex_ok(&c.policy_sha256, 64)
        && hex_ok(&c.model_sha256, 64)
        && c.birth_record_sha256.as_deref().is_none_or(|b| hex_ok(b, 64))
        && c.env_min <= c.env_max
        && c.env_max_rate_per_s >= 0.0
        && key_ok(&c.signer)
        && c.signature.len() == 128;
    if !ok {
        return Err(Malformed);
    }
    Ok(c)
}

fn parse_cert(v: &Value) -> Result<Cert, ErrorCode> {
    use ErrorCode::*;
    let m = exact(
        v,
        &["format", "v", "tenant", "twin_id", "version", "ranges", "valid_from_ms", "valid_until_ms", "fidelity_score", "signer", "signature"],
        &[],
    )
    .ok_or(Malformed)?;
    if s(m, "format") != Some("twin-band-certificate") || u(m, "v") != Some(1) {
        return Err(UnsupportedFormat);
    }
    let arr = m["ranges"].as_array().ok_or(Malformed)?;
    if arr.is_empty() || arr.len() > 64 {
        return Err(Malformed);
    }
    let mut ranges = Vec::new();
    for r in arr {
        let rm = exact(r, &["quantity", "unit", "min", "max"], &[]).ok_or(Malformed)?;
        let cr = CertRange {
            quantity: s(rm, "quantity").ok_or(Malformed)?.into(),
            unit: s(rm, "unit").ok_or(Malformed)?.into(),
            min: f(rm, "min").ok_or(Malformed)?,
            max: f(rm, "max").ok_or(Malformed)?,
        };
        if !name_ok(&cr.quantity) || !name_ok(&cr.unit) || cr.min > cr.max {
            return Err(Malformed);
        }
        ranges.push(cr);
    }
    let c = Cert {
        raw: v.clone(),
        tenant: s(m, "tenant").ok_or(Malformed)?.into(),
        twin_id: s(m, "twin_id").ok_or(Malformed)?.into(),
        version: u(m, "version").ok_or(Malformed)?,
        ranges,
        valid_from_ms: u(m, "valid_from_ms").ok_or(Malformed)?,
        valid_until_ms: u(m, "valid_until_ms").ok_or(Malformed)?,
        fidelity_score: f(m, "fidelity_score").ok_or(Malformed)?,
        signer: s(m, "signer").ok_or(Malformed)?.into(),
        signature: s(m, "signature").ok_or(Malformed)?.into(),
    };
    if !id_ok(&c.tenant) || !id_ok(&c.twin_id) || !(0.0..=1.0).contains(&c.fidelity_score) || !key_ok(&c.signer) || c.signature.len() != 128 {
        return Err(Malformed);
    }
    Ok(c)
}
