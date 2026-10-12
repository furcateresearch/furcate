//! Emergency access, and the accountability that is the only thing making it
//! safe.
//!
//! `furcate-policy` already covers the ordinary case well. A [`Grant`] is
//! short-lived, scoped to named actions, narrows at every hop and cannot reach
//! an invariant. What it assumes is that the machinery which issues grants is
//! reachable when somebody needs one, and the situations where emergency access
//! matters are very often the situations where it is not: the identity provider
//! is down, the site is partitioned, the approver is asleep in another
//! timezone, or the control plane is exactly what has failed.
//!
//! An emergency path that depends on the thing that is broken is not an
//! emergency path. So this is deliberately built like [`furcate_killswitch`]
//! rather than like the rest of the policy engine — a signed order, carried by
//! whoever needs it, verified locally against a key distributed in advance. No
//! service is consulted. It works on a node that can reach nothing at all.
//!
//! ## Why this is a separate crate
//!
//! The same reason the kill switch is one. This asserts that a particular
//! access was authorised by the operator and by nobody else, and an assertion
//! like that is worth precisely as much as the reader's ability to check it.
//! `furcate-policy` is a pure-data crate with no cryptography in it, and
//! neither the weight nor the claim belongs there.
//!
//! ## What actually keeps this honest
//!
//! Emergency access cannot be prevented — that is what makes it emergency
//! access. Every real control is therefore about what it costs and what it
//! leaves behind:
//!
//! - **It expires fast.** An hour, against a normal grant's day. An eight-hour
//!   emergency is a permission change wearing a costume.
//! - **It cannot reach an invariant.** Exactly the rule delegation follows. A
//!   halt or a crypto-erase stays with a physically present operator holding
//!   the key, which is the arrangement's whole point rather than a gap in it,
//!   and declaring an emergency is not a way around it.
//! - **It cannot be quiet.** [`Use::announcement`] is not optional and carries
//!   no suppression flag. Access nobody hears about has no control on it at
//!   all.
//! - **It must be reviewed, and an unreviewed one raises the price of the
//!   next.** This is the part that matters most in practice. Break-glass does
//!   not fail by being used once in a genuine emergency; it fails by becoming
//!   routine, one unremarkable use at a time, until it is simply how people
//!   work. [`Register`] escalates a second use to two signatures while the
//!   first is still unreviewed, so the cost of skipping the review lands on
//!   the next person to reach for it.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use furcate_policy::delegation::Grant;
use furcate_policy::invariant::forbidden_to_all;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A request for emergency access, signed by whoever authorised it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakGlass {
    /// Who receives the access. Their own identity — this grants authority, it
    /// does not lend an operator's.
    pub holder: String,
    /// Exactly what may be done. No wildcard, for the reason `Grant` gives:
    /// an unrestricted action list is impersonation with extra steps.
    pub actions: Vec<String>,
    /// What it may be done to.
    pub resources: Vec<String>,
    /// Why. Required and substantive, because in an emergency the record is
    /// the only control that survives.
    pub reason: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Single-use value defeating replay, as the kill switch uses.
    pub nonce: String,
    /// Operator signatures over the contents. More than one when the register
    /// says the bar has risen.
    pub signatures: Vec<String>,
}

/// Why an emergency access was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakGlassError {
    /// Not signed by enough keys the operator distributed in advance.
    NotAuthorized { valid: usize, required: usize },
    /// Two signatures were required and one key signed twice.
    ///
    /// Worth its own case: a duplicate signature satisfies a naive count while
    /// providing none of the second person the requirement exists to insist on.
    NotIndependent,
    Expired { expires_at: u64, now: u64 },
    /// This nonce has already been used.
    Replayed,
    /// Longer than emergency access is allowed to run.
    TooLong { seconds: u64, max: u64 },
    /// It names something no principal may ever do.
    ReachesInvariant { action: String },
    /// It grants nothing, or everything.
    BadScope(&'static str),
    /// No reason given, or none worth recording.
    NoReason,
}

impl fmt::Display for BreakGlassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BreakGlassError::NotAuthorized { valid, required } => write!(
                f,
                "emergency access carries {valid} valid signature(s) and needs {required}"
            ),
            BreakGlassError::NotIndependent => write!(
                f,
                "two signatures are required and one key signed twice; the second \
                 signature exists to be a second person"
            ),
            BreakGlassError::Expired { expires_at, now } => {
                write!(f, "expired at {expires_at}; it is now {now}")
            }
            BreakGlassError::Replayed => write!(f, "this emergency access has already been used"),
            BreakGlassError::TooLong { seconds, max } => write!(
                f,
                "emergency access may run for {max}s; this asks for {seconds}s. \
                 An emergency longer than that is a permission change"
            ),
            BreakGlassError::ReachesInvariant { action } => write!(
                f,
                "`{action}` is refused to every principal and declaring an emergency \
                 does not change that; it stays with an operator holding the key"
            ),
            BreakGlassError::BadScope(why) => write!(f, "{why}"),
            BreakGlassError::NoReason => write!(
                f,
                "emergency access must record why; the record is the only control \
                 that survives an emergency"
            ),
        }
    }
}

impl std::error::Error for BreakGlassError {}

/// How many independent signatures this use needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// The ordinary case: one operator key.
    One,
    /// Raised because an earlier use has not been reviewed.
    TwoIndependent,
}

impl Requirement {
    pub fn count(&self) -> usize {
        match self {
            Requirement::One => 1,
            Requirement::TwoIndependent => 2,
        }
    }
}

impl BreakGlass {
    /// Longest emergency access may run.
    ///
    /// An hour, against [`Grant::MAX_LIFETIME_SECS`]'s day. The asymmetry is
    /// the point: a normal grant is supervised work, and this is not.
    pub const MAX_LIFETIME_SECS: u64 = 3_600;

    /// Shortest reason worth recording.
    ///
    /// A crude bar, and it exists because the alternative is worse. "fix",
    /// "x", and "" are what a required-but-unenforced field collects, and a
    /// review of a hundred of those tells nobody anything.
    pub const MIN_REASON_LEN: usize = 12;

    pub fn new(
        holder: impl Into<String>,
        actions: Vec<String>,
        resources: Vec<String>,
        reason: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        nonce: impl Into<String>,
    ) -> Self {
        BreakGlass {
            holder: holder.into(),
            actions,
            resources,
            reason: reason.into(),
            issued_at,
            expires_at,
            nonce: nonce.into(),
            signatures: Vec::new(),
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.holder.as_bytes());
        for a in &self.actions {
            h.update(b"a");
            h.update(a.as_bytes());
        }
        for r in &self.resources {
            h.update(b"r");
            h.update(r.as_bytes());
        }
        h.update(self.reason.as_bytes());
        h.update(self.issued_at.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        h.update(self.nonce.as_bytes());
        h.finalize().to_vec()
    }

    /// Add an operator signature.
    pub fn sign(mut self, key: &SigningKey) -> Self {
        let sig: Signature = key.sign(&self.payload());
        self.signatures.push(hex::encode(sig.to_bytes()));
        self
    }

    /// Shape checks that need no keys and no clock beyond `now`.
    ///
    /// Separated from [`Self::authorize`] so a caller can reject a malformed
    /// request without holding the operator's public keys — a UI, for
    /// instance, which should say "give a real reason" before anything is
    /// signed rather than after.
    pub fn validate(&self, now: u64) -> Result<(), BreakGlassError> {
        if self.actions.is_empty() || self.resources.is_empty() {
            return Err(BreakGlassError::BadScope(
                "emergency access must name at least one action and one resource",
            ));
        }
        if self.actions.iter().any(|a| a == "*") {
            return Err(BreakGlassError::BadScope(
                "`*` is not an action; name what is actually needed",
            ));
        }
        if self.reason.trim().len() < Self::MIN_REASON_LEN {
            return Err(BreakGlassError::NoReason);
        }
        for a in &self.actions {
            if forbidden_to_all(a) {
                return Err(BreakGlassError::ReachesInvariant { action: a.clone() });
            }
        }
        if self.expires_at <= now {
            return Err(BreakGlassError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        let window = self.expires_at.saturating_sub(self.issued_at);
        if window > Self::MAX_LIFETIME_SECS {
            return Err(BreakGlassError::TooLong {
                seconds: window,
                max: Self::MAX_LIFETIME_SECS,
            });
        }
        Ok(())
    }

    /// How many of `keys` produced a valid signature, counting each key once.
    ///
    /// Counting distinct keys rather than signatures is the whole defence
    /// against a two-signature requirement being satisfied by one person
    /// signing twice.
    fn distinct_signers(&self, keys: &[VerifyingKey]) -> usize {
        let payload = self.payload();
        keys.iter()
            .filter(|k| {
                self.signatures.iter().any(|hexsig| {
                    let Ok(bytes) = hex::decode(hexsig) else {
                        return false;
                    };
                    let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else {
                        return false;
                    };
                    k.verify(&payload, &Signature::from_bytes(&arr)).is_ok()
                })
            })
            .count()
    }

    /// Authorise this emergency access against the operator keys and the
    /// register of earlier uses.
    ///
    /// Consults nothing over a network, by design: this has to work on a node
    /// that can reach nothing, which is when it is needed.
    pub fn authorize(
        &self,
        keys: &[VerifyingKey],
        register: &Register,
        now: u64,
    ) -> Result<Use, BreakGlassError> {
        self.validate(now)?;
        if register.was_used(&self.nonce) {
            return Err(BreakGlassError::Replayed);
        }

        let requirement = register.requirement();
        let valid = self.distinct_signers(keys);
        if valid < requirement.count() {
            // Distinguish "one person signed twice" from "not enough
            // signatures", because they call for different responses: find
            // another approver, versus this is not signed by anyone we know.
            if requirement == Requirement::TwoIndependent
                && self.signatures.len() >= 2
                && valid == 1
            {
                return Err(BreakGlassError::NotIndependent);
            }
            return Err(BreakGlassError::NotAuthorized {
                valid,
                required: requirement.count(),
            });
        }

        Ok(Use {
            nonce: self.nonce.clone(),
            holder: self.holder.clone(),
            actions: self.actions.clone(),
            resources: self.resources.clone(),
            reason: self.reason.clone(),
            at: now,
            expires_at: self.expires_at,
            requirement,
            reviewed: false,
        })
    }
}

/// An emergency access that was authorised, and now has to be answered for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Use {
    pub nonce: String,
    pub holder: String,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub reason: String,
    pub at: u64,
    pub expires_at: u64,
    /// What it took to authorise, kept so a review can see whether the bar had
    /// already been raised when this happened.
    pub requirement: Requirement,
    pub reviewed: bool,
}

impl Use {
    /// The authority this confers, in the form the rest of the system already
    /// understands.
    ///
    /// Deliberately an ordinary [`Grant`]. Everything downstream — the engine,
    /// the delegation chain, narrowing to a subagent — then treats emergency
    /// authority exactly as it treats any other, which means none of it needs
    /// a special case, and a special case is where the exemptions would
    /// eventually accumulate.
    ///
    /// It narrows like any grant and it cannot widen. What it does not do is
    /// carry its own privileges forward: a subagent handed part of this holds
    /// part of this, and nothing more.
    pub fn grant(&self) -> Grant {
        Grant {
            from: "break-glass".to_string(),
            to: self.holder.clone(),
            actions: self.actions.clone(),
            resources: self.resources.clone(),
            until: self.expires_at,
            reason: format!("break-glass: {}", self.reason),
        }
    }

    /// What has to be said out loud, immediately.
    ///
    /// Returned rather than logged here, because this crate does not get to
    /// decide where it goes — but there is no path through [`BreakGlass`] that
    /// produces a `Use` without one, and no flag anywhere that suppresses it.
    /// Emergency access nobody hears about has no control on it whatsoever.
    pub fn announcement(&self) -> String {
        format!(
            "break-glass: {} took emergency access to {} on {} at {} until {} — {}",
            self.holder,
            self.actions.join(", "),
            self.resources.join(", "),
            self.at,
            self.expires_at,
            self.reason,
        )
    }
}

/// Every emergency access this site has seen, and whether anyone looked at it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Register {
    uses: Vec<Use>,
}

impl Register {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, use_: Use) {
        self.uses.push(use_);
    }

    pub fn was_used(&self, nonce: &str) -> bool {
        self.uses.iter().any(|u| u.nonce == nonce)
    }

    /// Uses nobody has reviewed yet.
    pub fn unreviewed(&self) -> Vec<&Use> {
        self.uses.iter().filter(|u| !u.reviewed).collect()
    }

    /// Mark a use reviewed. Returns whether it was found.
    pub fn review(&mut self, nonce: &str) -> bool {
        match self.uses.iter_mut().find(|u| u.nonce == nonce) {
            Some(u) => {
                u.reviewed = true;
                true
            }
            None => false,
        }
    }

    pub fn all(&self) -> &[Use] {
        &self.uses
    }

    /// What the next emergency access will cost.
    ///
    /// The control that does the real work here. Break-glass does not fail by
    /// being used once in a genuine emergency — it fails by quietly becoming
    /// routine, and the review is the step that gets skipped first because
    /// skipping it has no consequences. This gives it one: while a use sits
    /// unreviewed, the next needs a second person.
    pub fn requirement(&self) -> Requirement {
        if self.unreviewed().is_empty() {
            Requirement::One
        } else {
            Requirement::TwoIndependent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn request(nonce: &str, now: u64) -> BreakGlass {
        BreakGlass::new(
            "oncall-alex",
            vec!["restart_service".to_string()],
            vec!["node-a".to_string()],
            "identity provider is down and the site cannot serve",
            now,
            now + 1800,
            nonce,
        )
    }

    #[test]
    fn a_signed_emergency_access_is_authorised_without_consulting_anything() {
        // The property the whole crate exists for: no service, no network, no
        // policy engine. Just a key distributed in advance.
        let k = key(1);
        let reg = Register::new();
        let bg = request("n1", 1000).sign(&k);
        let u = bg
            .authorize(&[k.verifying_key()], &reg, 1000)
            .expect("authorised");
        assert_eq!(u.holder, "oncall-alex");
        assert_eq!(u.requirement, Requirement::One);
        assert!(!u.reviewed);
    }

    #[test]
    fn an_unsigned_request_is_not_emergency_access() {
        let k = key(1);
        let reg = Register::new();
        let err = request("n1", 1000)
            .authorize(&[k.verifying_key()], &reg, 1000)
            .expect_err("unsigned");
        assert_eq!(
            err,
            BreakGlassError::NotAuthorized {
                valid: 0,
                required: 1
            }
        );
    }

    #[test]
    fn a_signature_from_a_key_we_do_not_hold_counts_for_nothing() {
        let ours = key(1);
        let theirs = key(9);
        let reg = Register::new();
        let bg = request("n1", 1000).sign(&theirs);
        assert!(bg.authorize(&[ours.verifying_key()], &reg, 1000).is_err());
    }

    #[test]
    fn declaring_an_emergency_does_not_reach_an_invariant() {
        // The rule delegation follows, and the one somebody will try hardest to
        // get around. A halt stays with an operator physically holding the key.
        let k = key(1);
        let reg = Register::new();
        for forbidden in ["halt", "power_off", "isolate", "crypto_erase"] {
            let bg = BreakGlass::new(
                "oncall",
                vec![forbidden.to_string()],
                vec!["node-a".to_string()],
                "the machine is on fire and must stop now",
                1000,
                1600,
                "n",
            )
            .sign(&k);
            assert_eq!(
                bg.authorize(&[k.verifying_key()], &reg, 1000),
                Err(BreakGlassError::ReachesInvariant {
                    action: forbidden.to_string()
                }),
                "{forbidden} must stay forbidden"
            );
        }
    }

    #[test]
    fn emergency_access_expires_far_sooner_than_an_ordinary_grant() {
        let k = key(1);
        let reg = Register::new();
        let long = BreakGlass::new(
            "oncall",
            vec!["restart_service".to_string()],
            vec!["node-a".to_string()],
            "this will take a while to sort out properly",
            1000,
            1000 + Grant::MAX_LIFETIME_SECS,
            "n",
        )
        .sign(&k);
        match long.authorize(&[k.verifying_key()], &reg, 1000) {
            Err(BreakGlassError::TooLong { max, .. }) => {
                assert_eq!(max, BreakGlass::MAX_LIFETIME_SECS);
                assert!(max < Grant::MAX_LIFETIME_SECS, "and it is much shorter");
            }
            other => panic!("a day-long emergency must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_reason_nobody_could_review_is_not_a_reason() {
        let k = key(1);
        let reg = Register::new();
        for reason in ["", "fix", "x", "   "] {
            let bg = BreakGlass::new(
                "oncall",
                vec!["restart_service".to_string()],
                vec!["node-a".to_string()],
                reason,
                1000,
                1600,
                "n",
            )
            .sign(&k);
            assert_eq!(
                bg.authorize(&[k.verifying_key()], &reg, 1000),
                Err(BreakGlassError::NoReason),
                "reason {reason:?}"
            );
        }
    }

    #[test]
    fn a_wildcard_is_not_a_scope() {
        let k = key(1);
        let reg = Register::new();
        let bg = BreakGlass::new(
            "oncall",
            vec!["*".to_string()],
            vec!["node-a".to_string()],
            "everything is broken and I need to look at all of it",
            1000,
            1600,
            "n",
        )
        .sign(&k);
        assert!(matches!(
            bg.authorize(&[k.verifying_key()], &reg, 1000),
            Err(BreakGlassError::BadScope(_))
        ));
    }

    #[test]
    fn the_same_order_cannot_be_used_twice() {
        let k = key(1);
        let mut reg = Register::new();
        let bg = request("n1", 1000).sign(&k);
        let u = bg
            .authorize(&[k.verifying_key()], &reg, 1000)
            .expect("first use");
        reg.record(u);
        reg.review("n1");
        assert_eq!(
            bg.authorize(&[k.verifying_key()], &reg, 1000),
            Err(BreakGlassError::Replayed)
        );
    }

    #[test]
    fn an_unreviewed_use_makes_the_next_one_cost_two_people() {
        // The control that matters. Break-glass fails by becoming routine, and
        // the review is what gets skipped first because skipping it is free.
        let k1 = key(1);
        let k2 = key(2);
        let keys = [k1.verifying_key(), k2.verifying_key()];
        let mut reg = Register::new();

        let first = request("n1", 1000).sign(&k1);
        reg.record(first.authorize(&keys, &reg, 1000).expect("first"));
        assert_eq!(reg.requirement(), Requirement::TwoIndependent);

        // One signature is no longer enough.
        let second = request("n2", 2000).sign(&k1);
        assert_eq!(
            second.authorize(&keys, &reg, 2000),
            Err(BreakGlassError::NotAuthorized {
                valid: 1,
                required: 2
            })
        );

        // Two people, and it proceeds.
        let second = request("n2", 2000).sign(&k1).sign(&k2);
        assert_eq!(
            second
                .authorize(&keys, &reg, 2000)
                .expect("two signatures")
                .requirement,
            Requirement::TwoIndependent
        );
    }

    #[test]
    fn reviewing_the_backlog_lowers_the_bar_again() {
        let k1 = key(1);
        let keys = [k1.verifying_key()];
        let mut reg = Register::new();
        reg.record(
            request("n1", 1000)
                .sign(&k1)
                .authorize(&keys, &reg, 1000)
                .expect("first"),
        );
        assert_eq!(reg.requirement(), Requirement::TwoIndependent);
        assert_eq!(reg.unreviewed().len(), 1);

        assert!(reg.review("n1"));
        assert_eq!(reg.requirement(), Requirement::One, "the debt is settled");
        assert!(reg.unreviewed().is_empty());
        assert!(!reg.review("nope"), "reviewing something absent finds nothing");
    }

    #[test]
    fn one_person_cannot_be_two_people_by_signing_twice() {
        // A duplicate satisfies a naive signature count while providing none of
        // the second person the requirement exists to insist on.
        let k1 = key(1);
        let k2 = key(2);
        let keys = [k1.verifying_key(), k2.verifying_key()];
        let mut reg = Register::new();
        reg.record(
            request("n1", 1000)
                .sign(&k1)
                .authorize(&keys, &reg, 1000)
                .expect("first"),
        );

        let twice = request("n2", 2000).sign(&k1).sign(&k1);
        assert_eq!(twice.signatures.len(), 2, "two signatures on the wire");
        assert_eq!(
            twice.authorize(&keys, &reg, 2000),
            Err(BreakGlassError::NotIndependent),
            "and one signer behind them"
        );
    }

    #[test]
    fn expiry_is_checked_against_the_clock_not_only_the_window() {
        let k = key(1);
        let reg = Register::new();
        let bg = request("n1", 1000).sign(&k);
        assert_eq!(
            bg.authorize(&[k.verifying_key()], &reg, 5000),
            Err(BreakGlassError::Expired {
                expires_at: 2800,
                now: 5000
            })
        );
    }

    #[test]
    fn the_authority_it_confers_is_an_ordinary_grant() {
        // So nothing downstream needs a special case — and a special case is
        // where exemptions would eventually accumulate.
        let k = key(1);
        let reg = Register::new();
        let u = request("n1", 1000)
            .sign(&k)
            .authorize(&[k.verifying_key()], &reg, 1000)
            .expect("authorised");
        let g = u.grant();
        assert_eq!(g.to, "oncall-alex");
        assert_eq!(g.until, 2800);
        assert!(g.reason.starts_with("break-glass:"), "it says what it is");
        assert!(g.validate(1000).is_ok(), "a well-formed ordinary grant");

        // And it narrows like any other, rather than carrying privilege
        // forward to whatever it is handed to.
        assert!(g
            .narrow("subagent", &["power_off".to_string()], 2000, "no")
            .is_err());
    }

    #[test]
    fn an_authorised_use_always_has_something_to_announce() {
        let k = key(1);
        let reg = Register::new();
        let u = request("n1", 1000)
            .sign(&k)
            .authorize(&[k.verifying_key()], &reg, 1000)
            .expect("authorised");
        let said = u.announcement();
        assert!(said.contains("oncall-alex"));
        assert!(said.contains("restart_service"));
        assert!(said.contains("identity provider is down"));
    }

    #[test]
    fn validation_needs_no_keys_so_a_ui_can_refuse_before_anyone_signs() {
        let bad = BreakGlass::new(
            "oncall",
            vec!["restart_service".to_string()],
            vec!["node-a".to_string()],
            "hm",
            1000,
            1600,
            "n",
        );
        assert_eq!(bad.validate(1000), Err(BreakGlassError::NoReason));
        assert!(request("n1", 1000).validate(1000).is_ok());
    }
}
