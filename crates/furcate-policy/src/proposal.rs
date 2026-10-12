//! What an agent hands a human instead of a paragraph.
//!
//! The MCP surface is observation only, and that is correct: dangerous
//! operations are absent rather than refused, so a confused model or an injected
//! instruction has nothing to reach for. The cost is that an agent which
//! correctly diagnoses a problem has no way to express the fix except in prose,
//! which is the least auditable artefact available. A sentence cannot be
//! evaluated by the policy engine, cannot expire, cannot be signed, and cannot
//! be compared against what was actually done afterwards.
//!
//! A proposal is the missing object. An agent constructs one, the engine rules
//! on it immediately, and what reaches a human is a typed thing with a decision
//! already attached — so the question they answer is "do I want this" rather
//! than "is this even allowed".
//!
//! ## It carries its refusal
//!
//! A proposal the engine already denied is still returned, still recorded, and
//! still shown. Silently dropping it would mean the agent's reasoning vanishes
//! at exactly the moment it is most worth reading: the case where an agent
//! believed something was necessary and the site's own rules disagreed is the
//! most interesting event this system can produce, and it is precisely the one a
//! filter would discard.
//!
//! ## What it is not
//!
//! It is not authority. Holding a proposal grants nothing; it is a request in a
//! shape that can be checked. The signature that makes it executable comes from
//! a key sealed in hardware that no agent can reach, and this module never
//! touches it — the entire contribution here is that by the time a human is
//! asked, everything checkable has been checked.
//!
//! It also cannot reach an invariant. The engine is consulted at construction
//! and refuses those structurally, so there is no sequence of proposals that
//! ends in a halt.

use crate::engine::{Decision, Request};
use serde::{Deserialize, Serialize};

/// How long a proposal stays answerable.
///
/// Short by design. A proposal is a judgement about the state of a machine at a
/// moment, and the state moves. Approving one from yesterday morning applies
/// yesterday's reasoning to today's fleet, which is the failure mode that makes
/// approval queues dangerous rather than merely slow.
pub const DEFAULT_TTL_SECS: u64 = 900;
pub const MAX_TTL_SECS: u64 = 3600;

/// Where a proposal has got to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Ruled on by the engine, waiting for a human.
    Open,
    /// The engine refused it. Kept and shown rather than dropped.
    Refused,
    /// A human declined it. Distinct from refused: the rules allowed this and
    /// a person still said no, which is a different signal entirely.
    Declined { by: String, reason: String },
    /// Approved and signed. Execution is somebody else's problem.
    Approved { by: String },
    /// Nobody answered in time.
    Expired,
}

/// A change an agent believes should happen.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    /// Which agent, in its own name. Never the operator's — the whole point of
    /// delegation over impersonation is that this stays traceable.
    pub proposer: String,
    /// The action, in the policy engine's vocabulary rather than prose. If it
    /// cannot be named as a capability and a resource, it cannot be proposed.
    pub request: Request,
    /// Why, in the agent's words. The one free-text field, and it is evidence
    /// for a human rather than an input to any decision.
    pub rationale: String,
    /// What the agent expects to observe if this works. Recorded before the
    /// fact so it can be checked after, rather than reconstructed favourably.
    pub expected_effect: String,
    /// How to undo it, or a statement that it cannot be undone.
    pub reversal: Reversal,
    /// The engine's ruling at construction time.
    pub decision: Decision,
    pub status: Status,
    pub created_at: u64,
    pub expires_at: u64,
}

/// How a change comes back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversal {
    /// Applying this named action restores the previous state.
    Action { capability: String, resource: String },
    /// It undoes itself when something expires or the next cycle runs.
    Automatic { how: String },
    /// It does not come back. Stated explicitly so nobody has to infer it from
    /// silence — an absent reversal plan and an irreversible action look
    /// identical until somebody needs the difference.
    Irreversible { why: String },
}

impl Reversal {
    pub fn is_reversible(&self) -> bool {
        !matches!(self, Reversal::Irreversible { .. })
    }
}

/// Why a proposal could not be constructed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalError {
    /// No rationale. A change nobody explained is one nobody can review.
    NoRationale,
    /// No statement of what should happen, so nothing can be checked after.
    NoExpectedEffect,
    /// The action was not named in the engine's vocabulary.
    NoAction,
}

impl Proposal {
    /// Build a proposal and rule on it in the same step.
    ///
    /// Ruling here rather than at approval time is deliberate. A proposal whose
    /// legality is only established when a human clicks is one where the human
    /// is the check, and people approve what is in front of them.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        id: impl Into<String>,
        proposer: impl Into<String>,
        request: Request,
        rationale: impl Into<String>,
        expected_effect: impl Into<String>,
        reversal: Reversal,
        decision: Decision,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Self, ProposalError> {
        let rationale = rationale.into();
        let expected_effect = expected_effect.into();
        if request.action.trim().is_empty() {
            return Err(ProposalError::NoAction);
        }
        if rationale.trim().is_empty() {
            return Err(ProposalError::NoRationale);
        }
        if expected_effect.trim().is_empty() {
            return Err(ProposalError::NoExpectedEffect);
        }
        let status = if decision.allowed { Status::Open } else { Status::Refused };
        Ok(Self {
            id: id.into(),
            proposer: proposer.into(),
            request,
            rationale,
            expected_effect,
            reversal,
            decision,
            status,
            created_at: now,
            expires_at: now + ttl_secs.clamp(1, MAX_TTL_SECS),
        })
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Whether a human could still act on this.
    pub fn is_actionable(&self, now: u64) -> bool {
        self.status == Status::Open && !self.is_expired(now)
    }

    /// Approve it.
    ///
    /// Refuses a refused proposal, an expired one, and one already answered.
    /// The first of those matters most: an approval path that could override
    /// the engine would make the engine advisory, and this whole object exists
    /// to keep it from being that.
    pub fn approve(&mut self, by: &str, now: u64) -> Result<(), Status> {
        if self.is_expired(now) {
            self.status = Status::Expired;
            return Err(self.status.clone());
        }
        if self.status != Status::Open {
            return Err(self.status.clone());
        }
        self.status = Status::Approved { by: by.to_string() };
        Ok(())
    }

    /// Decline it, with a reason.
    ///
    /// The reason is required. A declined proposal with no explanation teaches
    /// an agent nothing, and it will propose the same thing again tomorrow.
    pub fn decline(&mut self, by: &str, reason: &str, now: u64) -> Result<(), Status> {
        if self.is_expired(now) {
            self.status = Status::Expired;
            return Err(self.status.clone());
        }
        if self.status != Status::Open {
            return Err(self.status.clone());
        }
        self.status = Status::Declined { by: by.to_string(), reason: reason.to_string() };
        Ok(())
    }

    /// Mark it expired if its time has passed. Returns whether it changed.
    pub fn sweep(&mut self, now: u64) -> bool {
        if self.is_expired(now) && matches!(self.status, Status::Open) {
            self.status = Status::Expired;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_786_838_400;

    fn req(action: &str) -> Request {
        Request {
            principal: "agent:ops".into(),
            action: action.into(),
            resource: "node:node-a".into(),
            roles: Vec::new(),
        }
    }

    fn allowed() -> Decision {
        Decision { allowed: true, because: "rule 3".into(), structural: false }
    }
    fn denied() -> Decision {
        Decision { allowed: false, because: "no rule permits it".into(), structural: false }
    }

    fn open(d: Decision) -> Proposal {
        Proposal::open(
            "p1",
            "agent:ops",
            req("tune"),
            "psi memory-some at 34% for nine minutes",
            "contention below 20% within two cycles",
            Reversal::Action { capability: "tune".into(), resource: "node:node-a".into() },
            d,
            NOW,
            DEFAULT_TTL_SECS,
        )
        .unwrap()
    }

    #[test]
    fn a_proposal_carries_the_engines_ruling_from_the_moment_it_exists() {
        // Not at approval time. A proposal whose legality is established when a
        // human clicks is one where the human is the check, and people approve
        // what is in front of them.
        assert_eq!(open(allowed()).status, Status::Open);
        assert_eq!(open(denied()).status, Status::Refused);
    }

    #[test]
    fn a_refused_proposal_is_kept_rather_than_dropped() {
        // The case where an agent believed something was necessary and the
        // site's rules disagreed is the most interesting event this system can
        // produce, and it is exactly what a filter would discard.
        let p = open(denied());
        assert_eq!(p.status, Status::Refused);
        assert!(!p.rationale.is_empty(), "the reasoning survives the refusal");
        assert!(!p.decision.because.is_empty());
    }

    #[test]
    fn approval_cannot_override_a_refusal() {
        // Otherwise the engine is advisory, and this object exists to stop it
        // being that.
        let mut p = open(denied());
        assert!(p.approve("operator", NOW).is_err());
        assert_eq!(p.status, Status::Refused);
    }

    #[test]
    fn an_unexplained_change_cannot_be_proposed() {
        let e = Proposal::open(
            "p", "agent:ops", req("tune"), "   ", "something", Reversal::Automatic { how: "next cycle".into() },
            allowed(), NOW, DEFAULT_TTL_SECS,
        );
        assert_eq!(e, Err(ProposalError::NoRationale));
    }

    #[test]
    fn a_change_with_no_expected_effect_cannot_be_proposed() {
        // Recorded before the fact so it can be checked after, rather than
        // reconstructed favourably once the outcome is known.
        let e = Proposal::open(
            "p", "agent:ops", req("tune"), "because", "", Reversal::Automatic { how: "x".into() },
            allowed(), NOW, DEFAULT_TTL_SECS,
        );
        assert_eq!(e, Err(ProposalError::NoExpectedEffect));
    }

    #[test]
    fn an_action_that_cannot_be_named_cannot_be_proposed() {
        // If it does not fit a capability and a resource, the engine cannot
        // rule on it, and an unrulable proposal is prose with extra steps.
        let e = Proposal::open(
            "p", "agent:ops", req(""), "because", "effect", Reversal::Automatic { how: "x".into() },
            allowed(), NOW, DEFAULT_TTL_SECS,
        );
        assert_eq!(e, Err(ProposalError::NoAction));
    }

    #[test]
    fn a_proposal_goes_stale_because_the_fleet_moves() {
        // Approving yesterday's reasoning against today's machine is the
        // failure that makes approval queues dangerous rather than merely slow.
        let mut p = open(allowed());
        assert!(p.is_actionable(NOW + 60));
        assert!(!p.is_actionable(NOW + DEFAULT_TTL_SECS));
        assert!(p.approve("operator", NOW + DEFAULT_TTL_SECS).is_err());
        assert_eq!(p.status, Status::Expired);
    }

    #[test]
    fn a_long_ttl_is_capped_rather_than_honoured() {
        let p = Proposal::open(
            "p", "agent:ops", req("tune"), "because", "effect",
            Reversal::Automatic { how: "x".into() }, allowed(), NOW, 999_999,
        )
        .unwrap();
        assert_eq!(p.expires_at, NOW + MAX_TTL_SECS);
    }

    #[test]
    fn declining_is_not_the_same_event_as_refusing() {
        // The rules allowed it and a person still said no. That is a different
        // signal from the engine denying it, and collapsing the two loses the
        // only feedback an agent can learn from.
        let mut p = open(allowed());
        p.decline("operator", "we are mid-migration", NOW + 10).unwrap();
        assert_eq!(
            p.status,
            Status::Declined { by: "operator".into(), reason: "we are mid-migration".into() }
        );
    }

    #[test]
    fn a_proposal_is_answered_once() {
        let mut p = open(allowed());
        p.approve("operator", NOW + 10).unwrap();
        assert!(p.approve("someone-else", NOW + 20).is_err());
        assert!(p.decline("someone-else", "no", NOW + 20).is_err());
    }

    #[test]
    fn irreversibility_is_stated_rather_than_left_to_inference() {
        // An absent reversal plan and an irreversible action look identical
        // until somebody needs the difference.
        assert!(Reversal::Action { capability: "tune".into(), resource: "n".into() }.is_reversible());
        assert!(Reversal::Automatic { how: "expires".into() }.is_reversible());
        assert!(!Reversal::Irreversible { why: "destroys the key".into() }.is_reversible());
    }

    #[test]
    fn sweeping_expires_open_proposals_and_leaves_answered_ones_alone() {
        let mut open_one = open(allowed());
        let mut answered = open(allowed());
        answered.approve("operator", NOW).unwrap();

        assert!(open_one.sweep(NOW + MAX_TTL_SECS));
        assert_eq!(open_one.status, Status::Expired);
        assert!(!answered.sweep(NOW + MAX_TTL_SECS));
        assert_eq!(answered.status, Status::Approved { by: "operator".into() });
    }
}
