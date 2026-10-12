//! Changing who holds a site's keys.
//!
//! The custody section of site policy — the mode, the designated holders, the
//! minimum class and the two TPM-less opt-ins — is read by
//! [`furcate_identity::custody`]. This module is how it changes: only through
//! a signed change, checked here, and recorded in the node's operation chain as
//! a policy change whether it was applied or refused.
//!
//! A change is signed, time-bounded and chained in the same shape as an
//! administrator appointment: `epoch` only increases and `predecessor` is the
//! digest of the change it replaces, so an older setting cannot be replayed to
//! switch TPM-less custody back on after an operator turned it off.
//!
//! Who may sign is a [`ChangeAuthority`]. One is the operator's Ed25519 key,
//! the one that already signs appointments. The other is a passkey order
//! ([`PasskeyOrder`]): a `set_custody` order naming this change's digest and
//! approved by the site's threshold of independent people. It implements the
//! same trait, so every check below applies to it unchanged, and the outcome
//! is recorded the same way.
//!
//! A node keeps the change it runs on as an [`AppliedCustody`] record and
//! checks it again on every [`load`]. A record that does not check out is
//! refused with its reason and the node runs on the strict default.

use furcate_authn::order::{Action, Order, Target};
use furcate_authn::webauthn::Approval;
use furcate_identity::custody::{
    elect, Candidate, CustodyGrant, CustodyMode, CustodyRefusal, CustodySettings,
};
use furcate_identity::{AssuranceClass, Enrollment};
use furcate_ledger::chain::{Chain, OpKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

/// Why a custody change was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyChangeError {
    /// The signature does not verify under the authority presented.
    BadSignature,
    /// The signature or key is not readable as the right size.
    Malformed(String),
    /// Names a different site.
    WrongSite { named: String },
    /// Not yet, or no longer.
    NotLive { not_before: u64, not_after: u64, now: u64 },
    /// An older change presented after a newer one.
    Stale { epoch: u64, current: u64 },
    /// Does not continue the change it claims to follow.
    BrokenChain { expected: Option<String>, found: Option<String> },
    /// The settings contradict themselves.
    Invalid(CustodyRefusal),
    /// A passkey order that does not approve this change.
    NotApproved(String),
}

impl fmt::Display for CustodyChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => write!(f, "the custody change is not signed by this site's operator"),
            Self::Malformed(w) => write!(f, "the custody change is malformed: {w}"),
            Self::WrongSite { named } => write!(f, "the custody change names site `{named}`, not this one"),
            Self::NotLive { not_before, not_after, now } => write!(
                f,
                "the custody change is not live: valid {not_before}..{not_after}, now {now}"
            ),
            Self::Stale { epoch, current } => write!(
                f,
                "the custody change is epoch {epoch} but this site has already applied {current}; \
                 refusing to roll back"
            ),
            Self::BrokenChain { expected, found } => write!(
                f,
                "the custody change claims to follow {found:?} but the current one is {expected:?}"
            ),
            Self::Invalid(r) => write!(f, "the custody settings are refused: {r}"),
            Self::NotApproved(w) => write!(f, "the custody change is not approved: {w}"),
        }
    }
}

impl std::error::Error for CustodyChangeError {}

/// Something that may sign a site policy change.
pub trait ChangeAuthority {
    /// Recorded as the actor in the operation chain.
    fn name(&self) -> String;
    fn verify(&self, message: &[u8], signature_hex: &str) -> Result<(), CustodyChangeError>;
}

/// The site operator's Ed25519 key.
pub struct OperatorKey {
    pub key: ed25519_dalek::VerifyingKey,
}

impl ChangeAuthority for OperatorKey {
    fn name(&self) -> String {
        format!("operator:{}", hex::encode(self.key.as_bytes()))
    }

    fn verify(&self, message: &[u8], signature_hex: &str) -> Result<(), CustodyChangeError> {
        use ed25519_dalek::{Signature, Verifier};
        let raw = hex::decode(signature_hex)
            .map_err(|e| CustodyChangeError::Malformed(format!("signature is not hex: {e}")))?;
        let bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            CustodyChangeError::Malformed(format!("signature is {} bytes, expected 64", raw.len()))
        })?;
        self.key
            .verify(message, &Signature::from_bytes(&bytes))
            .map_err(|_| CustodyChangeError::BadSignature)
    }
}

/// An operator setting a site's custody policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyChange {
    pub site: String,
    pub epoch: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// Digest of the change this replaces; `None` only for the first.
    pub predecessor: Option<String>,
    pub settings: CustodySettings,
    /// Kept because a custody change nobody can explain is one nobody dares
    /// undo.
    pub reason: String,
    /// Hex signature over [`CustodyChange::signed_bytes`].
    pub signature: String,
}

impl CustodyChange {
    /// The exact bytes the signature covers. Built by hand, field by field and
    /// length-prefixed, so the signature does not depend on a serialiser.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let s = &self.settings;
        let mut m = b"furcate:custody-change:v1\0".to_vec();
        let mut fields = vec![
            self.site.clone(),
            self.epoch.to_string(),
            self.not_before.to_string(),
            self.not_after.to_string(),
            self.predecessor.clone().unwrap_or_default(),
            s.mode.as_str().to_string(),
            s.minimum.map(|c| c.as_str().to_string()).unwrap_or_default(),
            s.tpm_less.to_string(),
            s.allow_soft.to_string(),
            s.spread.to_string(),
            s.holders.len().to_string(),
        ];
        fields.extend(s.holders.iter().cloned());
        fields.push(self.reason.clone());
        for f in fields {
            m.extend_from_slice(&(f.len() as u64).to_be_bytes());
            m.extend_from_slice(f.as_bytes());
        }
        m
    }

    /// What a successor must name as its `predecessor`.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.signed_bytes()))
    }

    /// Check this change is one this site should apply. Every failure names
    /// itself: a custody change quietly ignored leaves an operator believing
    /// their keys are held somewhere they are not.
    pub fn verify(
        &self,
        authority: &dyn ChangeAuthority,
        site: &str,
        now: u64,
        current: Option<&CustodyChange>,
    ) -> Result<(), CustodyChangeError> {
        if self.site != site {
            return Err(CustodyChangeError::WrongSite { named: self.site.clone() });
        }
        if now < self.not_before || now >= self.not_after {
            return Err(CustodyChangeError::NotLive {
                not_before: self.not_before,
                not_after: self.not_after,
                now,
            });
        }
        if let Some(cur) = current {
            if self.epoch <= cur.epoch {
                return Err(CustodyChangeError::Stale { epoch: self.epoch, current: cur.epoch });
            }
            let want = Some(cur.digest());
            if self.predecessor != want {
                return Err(CustodyChangeError::BrokenChain {
                    expected: want,
                    found: self.predecessor.clone(),
                });
            }
        } else if self.predecessor.is_some() {
            return Err(CustodyChangeError::BrokenChain {
                expected: None,
                found: self.predecessor.clone(),
            });
        }
        self.settings.validate().map_err(CustodyChangeError::Invalid)?;
        authority.verify(&self.signed_bytes(), &self.signature)
    }

    /// Verify and record. The outcome is appended to `chain` as a policy
    /// change either way, so a refused attempt to lower custody is on the
    /// record beside the ones that were applied.
    pub fn apply(
        &self,
        authority: &dyn ChangeAuthority,
        site: &str,
        now: u64,
        current: Option<&CustodyChange>,
        chain: &mut Chain,
        ts_ms: u64,
    ) -> Result<CustodySettings, CustodyChangeError> {
        let outcome = self.verify(authority, site, now, current);
        let s = &self.settings;
        let result = serde_json::json!({
            "applied": outcome.is_ok(),
            "refused": outcome.as_ref().err().map(|e| e.to_string()),
            "epoch": self.epoch,
            "digest": self.digest(),
            "mode": s.mode.as_str(),
            "holders": s.holders,
            "floor": s.floor().as_str(),
            "tpm_less": s.tpm_less,
            "allow_soft": s.allow_soft,
            "reason": self.reason,
        });
        chain.append(
            ts_ms,
            OpKind::PolicyChange,
            authority.name(),
            format!("custody:{site}"),
            result.to_string(),
        );
        outcome.map(|()| self.settings.clone())
    }
}

/// A passkey order approved by the site's threshold of independent people.
///
/// The order names the digest of one change's signed bytes, so the approvers
/// approved exactly these settings, and the approval is over this exact order.
/// The change's `signature` field carries the order hash, which ties a stored
/// change to the order that applied it. The threshold is the site's
/// configuration for `set_custody` (two independent roots unless governance
/// sets otherwise); an [`Approval`] exists only once it is met.
pub struct PasskeyOrder<'a> {
    pub order: &'a Order,
    pub approval: &'a Approval,
}

impl ChangeAuthority for PasskeyOrder<'_> {
    fn name(&self) -> String {
        format!("passkeys:{}", self.approval.approvers().join(","))
    }

    fn verify(&self, message: &[u8], signature_hex: &str) -> Result<(), CustodyChangeError> {
        let hash = self
            .order
            .hash()
            .map_err(|e| CustodyChangeError::Malformed(e.to_string()))?;
        names_this_change(self.order, &hash, message, signature_hex)?;
        if self.approval.order_hash() != hash {
            return Err(CustodyChangeError::NotApproved(
                "the approval presented is for a different order".into(),
            ));
        }
        Ok(())
    }
}

/// Whether `order` is a `set_custody` order for the change whose signed bytes
/// are `message`, and the change carries that order's hash.
fn names_this_change(
    order: &Order,
    hash: &[u8; 32],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), CustodyChangeError> {
    if order.action != Action::SetCustody {
        return Err(CustodyChangeError::NotApproved(format!(
            "the order is `{}`, not `set_custody`",
            order.action.as_str()
        )));
    }
    let Target::Custody { change_sha256 } = &order.target else {
        return Err(CustodyChangeError::NotApproved(
            "the order does not name a custody change".into(),
        ));
    };
    let digest = hex::encode(Sha256::digest(message));
    if *change_sha256 != digest {
        return Err(CustodyChangeError::NotApproved(format!(
            "the order approves custody change {change_sha256}, not {digest}"
        )));
    }
    if signature_hex != hex::encode(hash) {
        return Err(CustodyChangeError::NotApproved(
            "the change does not carry the hash of the order that approved it".into(),
        ));
    }
    Ok(())
}

/// How an applied change was authorised, kept beside it so a node can check it
/// again every time it loads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum AppliedBy {
    /// The site operator's key; the change's `signature` is over its bytes.
    Operator,
    /// A passkey order. The approval was verified when the change was applied,
    /// and this node's operation chain records that it was.
    Passkeys { order: Order, approvers: Vec<String> },
}

/// The custody change a node runs on, as it keeps it in its state directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedCustody {
    pub change: CustodyChange,
    pub applied_by: AppliedBy,
}

impl AppliedCustody {
    /// Check a stored record before running on it.
    ///
    /// The validity window is not checked here: it bounds when a change may be
    /// applied, not how long it lasts once it has been.
    pub fn check(
        &self,
        operator: Option<&OperatorKey>,
        site: &str,
        chain: &Chain,
    ) -> Result<(), CustodyChangeError> {
        let c = &self.change;
        if c.site != site {
            return Err(CustodyChangeError::WrongSite { named: c.site.clone() });
        }
        c.settings.validate().map_err(CustodyChangeError::Invalid)?;
        match &self.applied_by {
            AppliedBy::Operator => match operator {
                Some(k) => k.verify(&c.signed_bytes(), &c.signature),
                None => Err(CustodyChangeError::NotApproved(
                    "the change is operator-signed but this node has no operator key to check \
                     it against"
                        .into(),
                )),
            },
            AppliedBy::Passkeys { order, .. } => {
                let hash = order
                    .hash()
                    .map_err(|e| CustodyChangeError::Malformed(e.to_string()))?;
                names_this_change(order, &hash, &c.signed_bytes(), &c.signature)?;
                chain.verify().map_err(|e| {
                    CustodyChangeError::NotApproved(format!(
                        "the operation chain does not verify, so it cannot vouch for the \
                         approval: {e}"
                    ))
                })?;
                let digest = c.digest();
                let subject = format!("custody:{site}");
                let recorded = chain.entries().iter().any(|op| {
                    op.kind == OpKind::PolicyChange
                        && op.subject == subject
                        && op.actor.starts_with("passkeys:")
                        && serde_json::from_str::<serde_json::Value>(&op.result).is_ok_and(|v| {
                            v["applied"] == true && v["digest"] == digest.as_str()
                        })
                });
                if !recorded {
                    return Err(CustodyChangeError::NotApproved(
                        "no passkey-approved application of this change is in this node's \
                         operation chain"
                            .into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Write the record so that a reader never sees half of it.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)
    }
}

/// The custody settings a node runs on, and where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub settings: CustodySettings,
    /// The change in force, which the next change must name as predecessor.
    /// Kept even when the stored record is refused, so that refusing a record
    /// can never reopen the chain to a replayed older change.
    pub current: Option<CustodyChange>,
    /// Why the stored record was not used. `settings` are then the strict
    /// default.
    pub refused: Option<String>,
}

/// The members custody is elected from: this machine at its own appraised
/// class, and each enrolment record the operator reviewed under `enrolled`.
///
/// `reachable` says whether a peer is up; this machine always is. A record
/// that does not parse is skipped and named, never guessed at.
pub fn members(
    node_id: &str,
    class: AssuranceClass,
    enrolled: &Path,
    reachable: &dyn Fn(&str) -> bool,
) -> (Vec<Candidate>, Vec<String>) {
    let mut out = vec![Candidate { id: node_id.to_string(), class: Some(class), reachable: true }];
    let mut skipped = Vec::new();
    let Ok(dir) = std::fs::read_dir(enrolled) else {
        return (out, skipped);
    };
    let mut files: Vec<_> = dir.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    files.sort();
    for p in files.into_iter().filter(|p| p.extension().is_some_and(|x| x == "json")) {
        let parsed = std::fs::read(&p)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Enrollment>(&b).map_err(|e| e.to_string()));
        match parsed {
            Ok(e) => {
                let id = e.node_id.to_string();
                if out.iter().any(|c| c.id == id) {
                    continue;
                }
                let up = reachable(&id);
                out.push(Candidate { id, class: Some(e.assurance), reachable: up });
            }
            Err(why) => skipped.push(format!("{}: {why}", p.display())),
        }
    }
    (out, skipped)
}

/// Read the applied custody record at `path`.
///
/// No record means the strict default. A record that cannot be read, does not
/// parse, names another site or does not check out also means the strict
/// default, never the settings it carries, and the reason is returned for the
/// caller to log and report.
pub fn load(path: &Path, operator: Option<&OperatorKey>, site: &str, chain: &Chain) -> Loaded {
    let strict = |current: Option<CustodyChange>, why: String| Loaded {
        settings: CustodySettings::default(),
        current,
        refused: Some(format!("{why}; running on the strict default")),
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Loaded { settings: CustodySettings::default(), current: None, refused: None }
        }
        Err(e) => return strict(None, format!("{} could not be read: {e}", path.display())),
    };
    let record: AppliedCustody = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(e) => {
            return strict(None, format!("{} is not a custody record: {e}", path.display()))
        }
    };
    match record.check(operator, site, chain) {
        Ok(()) => Loaded {
            settings: record.change.settings.clone(),
            current: Some(record.change),
            refused: None,
        },
        Err(e) => strict(Some(record.change), format!("{}: {e}", path.display())),
    }
}

impl Loaded {
    /// No custody record at all: none stored, so none applied or refused.
    pub fn absent(&self) -> bool {
        self.current.is_none() && self.refused.is_none()
    }

    /// What authorised the settings: `operator` or `passkeys` for a record in
    /// force, `none` when there is no record, `default` when one was refused.
    pub fn settings_from(&self, record: &Path) -> &'static str {
        if self.absent() {
            return "none";
        }
        if self.refused.is_some() {
            return "default";
        }
        match std::fs::read(record)
            .ok()
            .and_then(|b| serde_json::from_slice::<AppliedCustody>(&b).ok())
            .map(|r| r.applied_by)
        {
            Some(AppliedBy::Operator) => "operator",
            Some(AppliedBy::Passkeys { .. }) => "passkeys",
            None => "default",
        }
    }

    /// The settings material already sealed to this machine's own chip opens
    /// under.
    ///
    /// A site with no custody record predates custody: whatever a machine has
    /// sealed, it sealed to its own TPM, and nothing else can open it. That
    /// material is held in self-custody, at the default floor, so a node
    /// upgraded onto custody keeps opening what it already holds. Placing new
    /// material still follows [`Loaded::settings`], the strict elected
    /// default. A record that is present but refused gets no such allowance:
    /// existing material then opens only on the strict default too.
    pub fn for_existing_material(&self) -> CustodySettings {
        if self.absent() {
            CustodySettings { mode: CustodyMode::SelfCustody, ..CustodySettings::default() }
        } else {
            self.settings.clone()
        }
    }
}

/// Grant this machine to open material already sealed to its own chip, or the
/// reason it may not and the setting that would change that.
///
/// Every unseal of custody material goes through here before the chip is
/// asked for anything, so a machine opens only what the site's custody
/// settings say it holds.
pub fn existing_material_grant(
    loaded: &Loaded,
    node_id: &str,
    class: AssuranceClass,
    members: &[Candidate],
) -> Result<CustodyGrant, CustodyRefusal> {
    let settings = loaded.for_existing_material();
    let under = if loaded.absent() {
        "no custody record, so material already sealed here is self-custody".to_string()
    } else if let Some(why) = &loaded.refused {
        format!("the strict default ({why})")
    } else {
        format!("{} custody", settings.mode)
    };
    let custody = elect(&settings, members)
        .map_err(|r| CustodyRefusal(format!("no machine may hold custody under {under}: {r}")))?;
    custody.grant(node_id).map_err(|r| {
        let change = match settings.mode {
            CustodyMode::SelfCustody => {
                "custody.minimum, custody.tpm_less and custody.allow_soft set which classes may \
                 hold their own material"
            }
            CustodyMode::Elected => {
                "custody.mode `self` lets each admitted machine open its own sealed material; \
                 custody.spread or `designated` holders change who is elected"
            }
            CustodyMode::Designated => {
                "naming this machine in custody.holders, or custody.mode `self`, would let it \
                 open its own sealed material"
            }
        };
        CustodyRefusal(format!(
            "this machine ({node_id}, class `{class}`) does not hold custody under {under}: {r}; \
             {change}"
        ))
    })
}

/// An operator-signed record putting `site` in self-custody, ready to be
/// placed as the node's applied custody record.
///
/// For a site that has none yet: the change is the first in its chain
/// (epoch 1, no predecessor) and is checked against `key`'s public half
/// before it is returned, so a record that would be refused on load is never
/// written.
pub fn sign_self_custody(
    key: &ed25519_dalek::SigningKey,
    site: &str,
    now: u64,
    valid_for: u64,
    reason: &str,
) -> Result<AppliedCustody, CustodyChangeError> {
    use ed25519_dalek::Signer;
    let mut change = CustodyChange {
        site: site.to_string(),
        epoch: 1,
        not_before: now,
        not_after: now.saturating_add(valid_for),
        predecessor: None,
        settings: CustodySettings { mode: CustodyMode::SelfCustody, ..CustodySettings::default() },
        reason: reason.to_string(),
        signature: String::new(),
    };
    change.signature = hex::encode(key.sign(&change.signed_bytes()).to_bytes());
    let record = AppliedCustody { change, applied_by: AppliedBy::Operator };
    record.check(Some(&OperatorKey { key: key.verifying_key() }), site, &Chain::new())?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use furcate_identity::custody::CustodyMode;
    use furcate_identity::AssuranceClass;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn authority() -> OperatorKey {
        OperatorKey { key: operator().verifying_key() }
    }

    fn signed(mut c: CustodyChange, by: &SigningKey) -> CustodyChange {
        c.signature = hex::encode(by.sign(&c.signed_bytes()).to_bytes());
        c
    }

    fn change(epoch: u64, predecessor: Option<String>, settings: CustodySettings) -> CustodyChange {
        signed(
            CustodyChange {
                site: "site-a".into(),
                epoch,
                not_before: 100,
                not_after: 200,
                predecessor,
                settings,
                reason: "no TPM on this cluster".into(),
                signature: String::new(),
            },
            &operator(),
        )
    }

    fn tpm_less() -> CustodySettings {
        CustodySettings { tpm_less: true, ..Default::default() }
    }

    #[test]
    fn an_operator_signed_change_applies_and_is_recorded() {
        let mut chain = Chain::new();
        let c = change(1, None, tpm_less());
        let settings = c.apply(&authority(), "site-a", 150, None, &mut chain, 1).unwrap();
        assert!(settings.tpm_less);
        let op = &chain.entries()[0];
        assert_eq!(op.kind, OpKind::PolicyChange);
        assert_eq!(op.subject, "custody:site-a");
        assert!(op.result.contains("\"applied\":true"), "{}", op.result);
        assert!(op.result.contains("\"floor\":\"device\""), "{}", op.result);
        chain.verify().unwrap();
    }

    #[test]
    fn a_change_signed_by_anyone_else_is_refused_and_recorded() {
        let mut chain = Chain::new();
        let forged = signed(change(1, None, tpm_less()), &SigningKey::from_bytes(&[9u8; 32]));
        let e = forged.apply(&authority(), "site-a", 150, None, &mut chain, 1).unwrap_err();
        assert_eq!(e, CustodyChangeError::BadSignature);
        assert!(chain.entries()[0].result.contains("\"applied\":false"));
    }

    #[test]
    fn editing_any_setting_breaks_the_signature() {
        let mut c = change(1, None, CustodySettings::default());
        c.settings.allow_soft = true;
        c.settings.tpm_less = true;
        assert_eq!(c.verify(&authority(), "site-a", 150, None), Err(CustodyChangeError::BadSignature));

        let mut c = change(1, None, CustodySettings::default());
        c.settings.minimum = Some(AssuranceClass::Device);
        assert_eq!(c.verify(&authority(), "site-a", 150, None), Err(CustodyChangeError::BadSignature));
    }

    #[test]
    fn turning_the_opt_in_back_on_by_replay_is_refused() {
        let on = change(1, None, tpm_less());
        let off = change(2, Some(on.digest()), CustodySettings::default());
        off.verify(&authority(), "site-a", 150, Some(&on)).unwrap();
        assert_eq!(
            on.verify(&authority(), "site-a", 150, Some(&off)),
            Err(CustodyChangeError::Stale { epoch: 1, current: 2 })
        );
        let skipped = change(3, None, tpm_less());
        assert!(matches!(
            skipped.verify(&authority(), "site-a", 150, Some(&off)),
            Err(CustodyChangeError::BrokenChain { .. })
        ));
    }

    #[test]
    fn contradictory_settings_are_refused_with_the_reason() {
        let bad = change(1, None, CustodySettings { allow_soft: true, ..Default::default() });
        let e = bad.verify(&authority(), "site-a", 150, None).unwrap_err();
        assert!(e.to_string().contains("tpm_less"), "{e}");

        let designated = CustodySettings { mode: CustodyMode::Designated, ..Default::default() };
        let e = change(1, None, designated).verify(&authority(), "site-a", 150, None).unwrap_err();
        assert!(e.to_string().contains("no holders"), "{e}");
    }

    #[test]
    fn site_and_window_are_enforced() {
        let c = change(1, None, tpm_less());
        assert!(matches!(c.verify(&authority(), "site-b", 150, None), Err(CustodyChangeError::WrongSite { .. })));
        assert!(matches!(c.verify(&authority(), "site-a", 200, None), Err(CustodyChangeError::NotLive { .. })));
    }
    mod passkeys {
        use super::*;
        use furcate_authn::order::Bounds;
        use furcate_authn::webauthn::virtual_authenticator::Authenticator;
        use furcate_authn::webauthn::{verify_assertion, Challenge, Tally, Thresholds};

        const RP: &str = "site.example";

        fn order_for(c: &CustodyChange) -> Order {
            Order {
                site: RP.into(),
                action: Action::SetCustody,
                target: Target::Custody { change_sha256: c.digest() },
                bounds: Bounds { max_nodes: 1, duration_s: None },
                counter: 1,
                issued_at: 100,
                expires_at: 200,
                reason: "pi cluster".into(),
            }
        }

        fn approve(o: &Order, people: &[&str]) -> Option<Approval> {
            let mut t = Tally::new(o, &Thresholds::default()).unwrap();
            for i in 0..people.len() {
                let mut a = Authenticator::new(i as u8 + 1, RP);
                let cred = a.credential();
                let ch = Challenge { order_hash: o.hash().unwrap(), nonce: [0; 16], expires_at: 150 };
                t.add(verify_assertion(&cred, &a.get(&ch), &ch, 120).unwrap()).unwrap();
            }
            t.approval()
        }

        fn unsigned(epoch: u64, predecessor: Option<String>, settings: CustodySettings) -> CustodyChange {
            CustodyChange { signature: String::new(), ..change(epoch, predecessor, settings) }
        }

        #[test]
        fn one_passkey_is_not_enough_and_two_roots_apply_it() {
            let mut c = unsigned(1, None, tpm_less());
            let o = order_for(&c);
            assert!(approve(&o, &["alice"]).is_none(), "set_custody needs two roots by default");
            let approval = approve(&o, &["alice", "bob"]).unwrap();
            c.signature = hex::encode(o.hash().unwrap());
            let mut chain = Chain::new();
            let by = PasskeyOrder { order: &o, approval: &approval };
            let s = c.apply(&by, "site-a", 150, None, &mut chain, 1).unwrap();
            assert!(s.tpm_less);
            assert!(chain.entries()[0].actor.starts_with("passkeys:"));

            let rec = AppliedCustody {
                change: c.clone(),
                applied_by: AppliedBy::Passkeys { order: o.clone(), approvers: approval.approvers().to_vec() },
            };
            rec.check(None, "site-a", &chain).unwrap();
            let e = rec.check(None, "site-a", &Chain::new()).unwrap_err();
            assert!(e.to_string().contains("operation chain"), "{e}");
        }

        #[test]
        fn an_approval_for_other_settings_does_not_apply_these() {
            let approved = unsigned(1, None, CustodySettings::default());
            let o = order_for(&approved);
            let approval = approve(&o, &["alice", "bob"]).unwrap();
            let mut swapped = unsigned(1, None, CustodySettings { allow_soft: true, ..tpm_less() });
            swapped.signature = hex::encode(o.hash().unwrap());
            let by = PasskeyOrder { order: &o, approval: &approval };
            let mut chain = Chain::new();
            let e = swapped.apply(&by, "site-a", 150, None, &mut chain, 1).unwrap_err();
            assert!(matches!(e, CustodyChangeError::NotApproved(_)), "{e}");
            assert!(chain.entries()[0].result.contains("\"applied\":false"));
        }

        #[test]
        fn the_operator_path_still_works_beside_it() {
            let c = change(1, None, tpm_less());
            let rec = AppliedCustody { change: c, applied_by: AppliedBy::Operator };
            rec.check(Some(&authority()), "site-a", &Chain::new()).unwrap();
            assert!(rec.check(None, "site-a", &Chain::new()).is_err());
        }

        #[test]
        fn a_bad_record_loads_as_the_strict_default_with_a_reason() {
            let dir = std::env::temp_dir().join(format!("custody-load-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("custody.json");

            let none = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert_eq!(none.settings, CustodySettings::default());
            assert!(none.refused.is_none());

            std::fs::write(&path, b"{not json").unwrap();
            let bad = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert_eq!(bad.settings, CustodySettings::default());
            assert!(bad.refused.unwrap().contains("not a custody record"));

            let forged = signed(change(1, None, tpm_less()), &SigningKey::from_bytes(&[9u8; 32]));
            AppliedCustody { change: forged.clone(), applied_by: AppliedBy::Operator }.save(&path).unwrap();
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert!(!l.settings.tpm_less, "a forged record never loosens custody");
            assert!(l.refused.unwrap().contains("strict default"));
            assert_eq!(l.current, Some(forged), "the chain still continues from it");

            AppliedCustody { change: change(1, None, tpm_less()), applied_by: AppliedBy::Operator }
                .save(&path)
                .unwrap();
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert!(l.settings.tpm_less && l.refused.is_none());
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    mod existing_material {
        use super::*;

        /// Three quote-capable machines, where an election of two leaves `zz`
        /// out: the shape of a site whose nodes each sealed their own key
        /// before custody existed.
        fn cluster() -> Vec<Candidate> {
            ["zz", "aa", "bb"]
                .into_iter()
                .map(|id| Candidate { id: id.into(), class: Some(AssuranceClass::Tpm), reachable: true })
                .collect()
        }

        fn scratch(name: &str) -> std::path::PathBuf {
            let dir = std::env::temp_dir()
                .join(format!("custody-existing-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir.join("custody.json")
        }

        #[test]
        fn with_no_record_a_node_keeps_opening_what_it_sealed_to_its_own_tpm() {
            let path = scratch("absent");
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert!(l.absent());
            assert_eq!(l.settings_from(&path), "none");

            let g = existing_material_grant(&l, "zz", AssuranceClass::Tpm, &cluster()).unwrap();
            assert_eq!(g.mode(), CustodyMode::SelfCustody);
            assert_eq!(g.class(), AssuranceClass::Tpm);
            assert_eq!(g.holder(), "zz");

            // New placement still follows the strict elected default, which
            // this node does not win.
            let placed = elect(&l.settings, &cluster()).unwrap();
            assert_eq!(placed.mode, CustodyMode::Elected);
            assert!(placed.grant("zz").is_err());
            assert!(placed.grant("aa").is_ok());
        }

        #[test]
        fn with_no_record_the_default_floor_still_applies() {
            let path = scratch("floor");
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            let e = existing_material_grant(&l, "mac", AssuranceClass::SecureElement, &[Candidate {
                id: "mac".into(),
                class: Some(AssuranceClass::SecureElement),
                reachable: true,
            }])
            .unwrap_err()
            .0;
            assert!(e.contains("self-custody") && e.contains("custody.tpm_less"), "{e}");
        }

        #[test]
        fn a_refused_record_gets_no_allowance() {
            let path = scratch("refused");
            std::fs::write(&path, b"{not json").unwrap();
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert_eq!(l.settings_from(&path), "default");
            let e = existing_material_grant(&l, "zz", AssuranceClass::Tpm, &cluster()).unwrap_err().0;
            assert!(e.contains("strict default") && e.contains("custody.mode `self`"), "{e}");
        }

        #[test]
        fn an_elected_record_refuses_a_machine_it_did_not_elect_and_says_what_would_change_it() {
            let path = scratch("elected");
            AppliedCustody { change: change(1, None, CustodySettings::default()), applied_by: AppliedBy::Operator }
                .save(&path)
                .unwrap();
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert_eq!(l.settings_from(&path), "operator");
            let e = existing_material_grant(&l, "zz", AssuranceClass::Tpm, &cluster()).unwrap_err().0;
            assert!(e.contains("elected custody") && e.contains("spread is 2"), "{e}");
            assert!(e.contains("custody.mode `self`"), "{e}");
        }

        #[test]
        fn a_signed_self_record_loads_and_grants_each_machine_its_own_material() {
            let path = scratch("self");
            let record = sign_self_custody(&operator(), "site-a", 150, 86_400, "upgrade").unwrap();
            record.save(&path).unwrap();
            let l = load(&path, Some(&authority()), "site-a", &Chain::new());
            assert!(l.refused.is_none(), "{:?}", l.refused);
            assert_eq!(l.settings.mode, CustodyMode::SelfCustody);
            assert_eq!(l.settings_from(&path), "operator");
            for id in ["zz", "aa", "bb"] {
                let g = existing_material_grant(&l, id, AssuranceClass::Tpm, &cluster()).unwrap();
                assert_eq!((g.holder(), g.mode()), (id, CustodyMode::SelfCustody));
            }
            // And it is checked against the operator key: another site's
            // operator cannot produce it.
            let other = load(&path, Some(&OperatorKey { key: SigningKey::from_bytes(&[9u8; 32]).verifying_key() }), "site-a", &Chain::new());
            assert!(other.refused.is_some());
            // A record for another site is refused too.
            let elsewhere = load(&path, Some(&authority()), "site-b", &Chain::new());
            assert!(elsewhere.refused.unwrap().contains("site"));
        }
    }
}
