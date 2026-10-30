//! Stages per system class and the actuation-approval record.
//!
//! Each actuator belongs to a system class the site names. Per class the site sets a stage: `observe` (every command
//! refused), `shadow` (decided and recorded, nothing written; the default) or `actuate` (an accepted command may be
//! released). Actuating also needs an installed approval signed by an approver the site enrolled. Nothing in a
//! command can raise a stage or stand in for an approval.

use crate::canon::{canonical, parse_canonical};
use crate::command::{exact, hex_ok, id_ok, key_ok, name_ok, s, u};
use crate::{sha256_hex, verify_ed25519};
use serde_json::Value;

/// Domain every actuation approval is signed under.
pub const APPROVAL_DOMAIN: &str = "lw-physical/actuation-approval/v1";
/// Longest validity an approval may state: 31 days.
pub const MAX_APPROVAL_MS: u64 = 31 * 24 * 3600 * 1000;
/// Most actuators one approval may name.
pub const MAX_APPROVAL_ACTUATORS: usize = 64;

/// What a site does with commands for one system class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Readings flow up; every command for the class is refused with `observe_only`.
    Observe,
    /// The gate decides and records what it would do; nothing is written. The default.
    Shadow,
    /// An accepted command with a covering approval is released to the executor.
    Actuate,
}

impl Stage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Stage::Observe => "observe",
            Stage::Shadow => "shadow",
            Stage::Actuate => "actuate",
        }
    }
}

/// What the site sets locally. A class with no stage entry is at `shadow`; an actuator with no class entry is in no
/// class and can never be released.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActuationConfig {
    /// (actuator id, system class).
    pub classes: Vec<(String, String)>,
    /// (system class, stage).
    pub stages: Vec<(String, Stage)>,
    /// Enrolled approver keys, `ed25519:<hex>`.
    pub approvers: Vec<String>,
}

impl ActuationConfig {
    /// The system class the site assigned to `actuator_id`.
    pub fn class_of(&self, actuator_id: &str) -> Option<&str> {
        self.classes.iter().find(|(a, _)| a == actuator_id).map(|(_, c)| c.as_str())
    }
    /// The stage of `class`: the entry if there is one, `shadow` otherwise.
    pub fn stage_of(&self, class: &str) -> Stage {
        self.stages.iter().find(|(c, _)| c == class).map_or(Stage::Shadow, |(_, st)| *st)
    }
}

/// The identifier of an installed approval.
pub type ApprovalId = String;

/// Why an approval was not installed or removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    /// The gate has no actuation configuration, so there are no approvers.
    NotConfigured,
    /// Not canonical JSON.
    NotCanonical,
    /// Wrong members, types, ids, ordering or sizes.
    Malformed,
    /// Names another tenant.
    WrongTenant,
    /// Names another site.
    WrongSite,
    /// The approver key is not enrolled at this site.
    ApproverNotEnrolled,
    /// The signature does not verify under the approver key.
    BadSignature,
    /// `valid_until_ms` is not after `valid_from_ms`, or the window is longer than 31 days.
    BadWindow,
    /// `valid_until_ms` has passed.
    Expired,
    /// An approval with this id is installed.
    Duplicate,
    /// An approval with this id was revoked here; the id is never installable again.
    Revoked,
    /// No installed approval has this id.
    Unknown,
}

impl ApprovalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalError::NotConfigured => "not_configured",
            ApprovalError::NotCanonical => "not_canonical",
            ApprovalError::Malformed => "malformed",
            ApprovalError::WrongTenant => "wrong_tenant",
            ApprovalError::WrongSite => "wrong_site",
            ApprovalError::ApproverNotEnrolled => "approver_not_enrolled",
            ApprovalError::BadSignature => "bad_signature",
            ApprovalError::BadWindow => "bad_window",
            ApprovalError::Expired => "expired",
            ApprovalError::Duplicate => "duplicate",
            ApprovalError::Revoked => "revoked",
            ApprovalError::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for ApprovalError {}

/// A parsed, verified actuation approval.
#[derive(Clone, Debug)]
pub struct Approval {
    pub raw: String,
    pub sha256: String,
    pub approval_id: String,
    pub tenant: String,
    pub site_id: String,
    pub system_class: String,
    pub actuator_ids: Vec<String>,
    pub kinds: Vec<String>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub approver: String,
}

impl Approval {
    /// Whether this approval covers the actuator, class and command kind at `now`.
    pub fn covers(&self, class: &str, actuator_id: &str, kind: &str, now: u64) -> bool {
        self.system_class == class
            && self.actuator_ids.iter().any(|a| a == actuator_id)
            && self.kinds.iter().any(|k| k == kind)
            && self.valid_from_ms <= now
            && now < self.valid_until_ms
    }
}

fn sorted_unique(v: &[String]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

fn str_list(v: &Value, max: usize) -> Option<Vec<String>> {
    let a = v.as_array()?;
    if a.is_empty() || a.len() > max {
        return None;
    }
    a.iter().map(|x| x.as_str().map(str::to_string)).collect()
}

/// Parse and check an approval record. When installing (`restoring` false) the approver must be enrolled and the
/// record must not be expired at `now_ms`. When restoring saved state both are skipped: an expired approval is
/// inert, and an approval whose approver is no longer enrolled is refused at use (see `Gate`), neither is corrupt.
pub(crate) fn parse_approval(
    raw: &[u8],
    tenant: &str,
    site_id: &str,
    approvers: &[String],
    now_ms: u64,
    restoring: bool,
) -> Result<Approval, ApprovalError> {
    use ApprovalError::*;
    let v = parse_canonical(raw).map_err(|e| match e {
        crate::canon::CanonError::NotCanonical => NotCanonical,
        _ => Malformed,
    })?;
    let m = exact(
        &v,
        &["format", "v", "approval_id", "tenant", "site_id", "system_class", "actuator_ids", "kinds", "valid_from_ms", "valid_until_ms", "approver", "signature"],
        &[],
    )
    .ok_or(Malformed)?;
    if s(m, "format") != Some("actuation-approval") || u(m, "v") != Some(1) {
        return Err(Malformed);
    }
    let a = Approval {
        raw: String::from_utf8(raw.to_vec()).map_err(|_| Malformed)?,
        sha256: sha256_hex(raw),
        approval_id: s(m, "approval_id").ok_or(Malformed)?.into(),
        tenant: s(m, "tenant").ok_or(Malformed)?.into(),
        site_id: s(m, "site_id").ok_or(Malformed)?.into(),
        system_class: s(m, "system_class").ok_or(Malformed)?.into(),
        actuator_ids: str_list(&m["actuator_ids"], MAX_APPROVAL_ACTUATORS).ok_or(Malformed)?,
        kinds: str_list(&m["kinds"], 2).ok_or(Malformed)?,
        valid_from_ms: u(m, "valid_from_ms").ok_or(Malformed)?,
        valid_until_ms: u(m, "valid_until_ms").ok_or(Malformed)?,
        approver: s(m, "approver").ok_or(Malformed)?.into(),
    };
    let sig = s(m, "signature").ok_or(Malformed)?;
    let ok = id_ok(&a.approval_id)
        && id_ok(&a.tenant)
        && id_ok(&a.site_id)
        && name_ok(&a.system_class)
        && a.actuator_ids.iter().all(|x| id_ok(x))
        && sorted_unique(&a.actuator_ids)
        && a.kinds.iter().all(|k| k == "setpoint" || k == "trajectory")
        && sorted_unique(&a.kinds)
        && key_ok(&a.approver)
        && hex_ok(sig, 128);
    if !ok {
        return Err(Malformed);
    }
    if a.tenant != tenant {
        return Err(WrongTenant);
    }
    if a.site_id != site_id {
        return Err(WrongSite);
    }
    if !restoring && !approvers.contains(&a.approver) {
        return Err(ApproverNotEnrolled);
    }
    let mut body = v.clone();
    body.as_object_mut().unwrap().remove("signature");
    let msg = canonical(&body).map_err(|_| Malformed)?;
    if !verify_ed25519(&a.approver, APPROVAL_DOMAIN, msg.as_bytes(), sig) {
        return Err(BadSignature);
    }
    if a.valid_until_ms <= a.valid_from_ms || a.valid_until_ms - a.valid_from_ms > MAX_APPROVAL_MS {
        return Err(BadWindow);
    }
    if !restoring && now_ms >= a.valid_until_ms {
        return Err(Expired);
    }
    Ok(a)
}
