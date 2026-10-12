//! The things no policy may permit.
//!
//! Every other module in this crate is about making authority configurable.
//! This one is about the opposite, and it is checked first, so that nothing
//! below it can matter.
//!
//! The argument is not that these actions are dangerous — plenty of permitted
//! actions are dangerous. It is that a system whose value proposition includes
//! "the network can never stop your machine" cannot hold that property in a
//! file. A file can be edited, and the edit looks like configuration rather
//! than like removing a safety property. Compiled in, the same change is a code
//! change, a review, and a redeploy of every agent on the site.
//!
//! There are deliberately very few of these. An invariant that covers most of
//! what an operator wants to do is not an invariant, it is an argument waiting
//! to happen, and it will be lost by whoever needs the exception at three in
//! the morning.

use serde::{Deserialize, Serialize};

/// A capability that is refused to every principal, always.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Invariant {
    /// Stop a machine.
    Halt,
    /// Cut power to one.
    PowerOff,
    /// Cut a machine off from the site.
    Isolate,
    /// Destroy sealed key material.
    CryptoErase,
}

impl Invariant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Invariant::Halt => "halt",
            Invariant::PowerOff => "power_off",
            Invariant::Isolate => "isolate",
            Invariant::CryptoErase => "crypto_erase",
        }
    }
}

/// Everything no grant, policy or delegation may ever authorise.
///
/// These remain available to a **physically present operator** holding the
/// signing key — that is the whole point of the arrangement, not a gap in it.
/// What is refused here is any path that reaches them through configuration,
/// delegation, a network request, an agent, or a policy file.
pub const FORBIDDEN: &[Invariant] = &[
    Invariant::Halt,
    Invariant::PowerOff,
    Invariant::Isolate,
    Invariant::CryptoErase,
];

/// Whether a capability is refused to everything this engine can express.
///
/// Matching is on the exact string rather than a substring, and that is
/// deliberate in both directions. A substring check would refuse `halt_report`
/// and `isolate_test` for no reason; an over-loose one would let `do_halt`
/// through. Capability names are a closed vocabulary and are compared as such.
pub fn forbidden_to_all(capability: &str) -> bool {
    FORBIDDEN.iter().any(|i| i.as_str() == capability)
}

/// Actions no automatic process may take, whoever wrote the policy file.
///
/// This is narrower than [`forbidden_to_all`] and differently shaped: these are
/// things a *human* may do and a loop may not. Furcate observes workloads and
/// does not restart them — systemd and Docker already supervise what they own,
/// and a second supervisor fighting the first is how a flapping container
/// becomes a flapping machine. An operator asking for a restart from the screen
/// they were already reading is a different act, and that one is allowed.
///
/// Compiled in rather than expressed as a rule, because a rule that could be
/// written could be unwritten, and the distinction between "a human asked" and
/// "the loop decided" is the whole safety argument.
const AUTOMATION_MAY_NOT: &[&str] = &["restart"];

/// Whether this principal is an automatic process rather than a person.
///
/// Named for what it decides. The loop's principal is the one the MAPE reasoner
/// signs its proposals with; anything else is assumed to be a person or to be
/// acting on one's explicit instruction.
pub fn is_automation(principal: &str) -> bool {
    principal == "loop" || principal.starts_with("loop:")
}

/// Whether an automatic process is structurally barred from this action.
pub fn forbidden_to_automation(principal: &str, action: &str) -> bool {
    is_automation(principal) && AUTOMATION_MAY_NOT.contains(&action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forbidden_set_is_exactly_four_things() {
        // An invariant that covers most of what an operator wants to do is not
        // an invariant; it is an argument waiting to be lost at three in the
        // morning by whoever needs the exception.
        assert_eq!(FORBIDDEN.len(), 4);
    }

    #[test]
    fn each_of_them_is_refused() {
        for c in ["halt", "power_off", "isolate", "crypto_erase"] {
            assert!(forbidden_to_all(c), "{c} should be forbidden");
        }
    }

    #[test]
    fn ordinary_capabilities_are_not_caught_by_it() {
        // This module refuses four things and must not quietly refuse a fifth.
        for c in ["drain", "tune", "suspend", "resume", "attest", "report_capacity"] {
            assert!(!forbidden_to_all(c), "{c} should not be forbidden");
        }
    }

    #[test]
    fn matching_is_exact_in_both_directions() {
        // A substring check would refuse these for no reason —
        assert!(!forbidden_to_all("halt_report"));
        assert!(!forbidden_to_all("isolate_test"));
        assert!(!forbidden_to_all("power_off_dry_run"));
        // — and a loose one would let these through.
        assert!(!forbidden_to_all("do_halt"));
        assert!(!forbidden_to_all("HALT"), "case is part of the vocabulary");
    }

    #[test]
    fn an_unknown_capability_is_not_forbidden_here() {
        // Because it is denied by the engine's default instead. Two layers
        // saying no for different reasons is fine; this one is only for the
        // four that must never be reachable at all.
        assert!(!forbidden_to_all("something_nobody_defined"));
    }
}
