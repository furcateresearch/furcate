//! Recovering a faulted or compromised root of trust.
//!
//! A TPM can enter failure mode, and when it does no software path can bring
//! it back. Recovery runs through firmware setup, which a careful operator has
//! behind a password, so the only party who can restore a machine's root of
//! trust is someone physically at it holding that password.
//!
//! This is the kill switch's mirror image. Software can stop trusting a
//! machine but can never restore trust in one; that requires presence. It is
//! why none of these actions is exposed over any API, and why
//! [`RecoveryAction::software_invokable`] answers `false` for every variant.
//!
//! The distinction that matters operationally is between a **reset** and a
//! **clear**, because they cost very different things.

use crate::rot::AssuranceClass;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Ways an operator can recover a root of trust, cheapest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Power cycle the host. The chip runs its startup sequence again, which
    /// is what clears failure mode. Nothing is lost.
    PowerCycle,
    /// Clear the TPM from firmware setup. This resets the storage hierarchy,
    /// so everything sealed under it is unrecoverable — but the endorsement
    /// seed is untouched, so the machine keeps its identity.
    BiosClear,
    /// Change the endorsement primary seed. Rarely exposed, and destroys the
    /// endorsement key itself: the machine becomes a different node.
    ChangeEndorsementSeed,
}

impl RecoveryAction {
    /// Whether any software path can invoke this.
    ///
    /// Always false. The method exists so the answer is written down where
    /// someone would look for an exception, and finds none.
    pub fn software_invokable(&self) -> bool {
        false
    }

    /// Whether the operator must be physically at the machine.
    pub fn requires_physical_presence(&self) -> bool {
        !matches!(self, RecoveryAction::PowerCycle)
    }

    /// Whether the node keeps the identity it enrolled with.
    ///
    /// A node identifier commits to the *endorsement* key, and clearing a TPM
    /// resets the storage hierarchy rather than the endorsement seed. So a
    /// cleared machine is still the same node — which is exactly what an
    /// operator wants after a fault, and exactly what an attacker cannot use,
    /// since clearing requires presence.
    pub fn preserves_node_identity(&self) -> bool {
        !matches!(self, RecoveryAction::ChangeEndorsementSeed)
    }

    /// Whether data sealed to the storage hierarchy survives.
    pub fn preserves_sealed_data(&self) -> bool {
        matches!(self, RecoveryAction::PowerCycle)
    }

    /// What an operator must do afterwards.
    pub fn follow_up(&self) -> &'static str {
        match self {
            RecoveryAction::PowerCycle => "nothing; the node resumes with its identity and sealed data intact",
            RecoveryAction::BiosClear => "re-seal the vault: identity survives, but every key sealed under the storage hierarchy is gone",
            RecoveryAction::ChangeEndorsementSeed => "re-enrol from scratch: this is a different node now, with a different identifier",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RecoveryAction::PowerCycle => "power-cycle",
            RecoveryAction::BiosClear => "bios-clear",
            RecoveryAction::ChangeEndorsementSeed => "change-endorsement-seed",
        }
    }
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a root of trust needs recovering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// The chip reported `TPM_RC_FAILURE`. It answers `GetTestResult` and
    /// refuses almost everything else.
    FailureMode,
    /// Dictionary attack lockout after too many failed authorizations.
    LockedOut,
    /// Sealed data will not unseal because boot measurements changed.
    SealPolicyMismatch,
    /// The chip does not respond at all.
    Unresponsive,
}

impl Fault {
    /// The cheapest action likely to fix this, and why.
    ///
    /// Ordered deliberately: reaching for a clear when a power cycle would do
    /// destroys sealed data for no reason, and that mistake is not reversible.
    pub fn recommended(&self) -> RecoveryAction {
        match self {
            // Failure mode is cleared by the startup sequence, so try the
            // cheap thing first.
            Fault::FailureMode | Fault::Unresponsive => RecoveryAction::PowerCycle,
            // Lockout resets on its own timer, but a power cycle is faster and
            // costs nothing.
            Fault::LockedOut => RecoveryAction::PowerCycle,
            // A policy mismatch means the machine booted differently. Clearing
            // is the honest fix; the sealed data was bound to a state that no
            // longer exists.
            Fault::SealPolicyMismatch => RecoveryAction::BiosClear,
        }
    }

    /// The escalation if the recommended action does not work.
    pub fn escalation(&self) -> Option<RecoveryAction> {
        match self.recommended() {
            RecoveryAction::PowerCycle => Some(RecoveryAction::BiosClear),
            RecoveryAction::BiosClear => Some(RecoveryAction::ChangeEndorsementSeed),
            RecoveryAction::ChangeEndorsementSeed => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Fault::FailureMode => "failure mode (TPM_RC_FAILURE)",
            Fault::LockedOut => "dictionary attack lockout",
            Fault::SealPolicyMismatch => "seal policy mismatch",
            Fault::Unresponsive => "unresponsive",
        }
    }
}

/// Who may perform recovery on this site.
///
/// Recorded so an operator can see whether their recovery path is actually
/// protected. A machine whose firmware setup has no password can have its root
/// of trust cleared by anyone who reaches the keyboard, which silently reduces
/// every assurance claim the node makes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    /// Firmware setup is password protected.
    pub firmware_password_set: bool,
    /// The machine is in a physically controlled space.
    pub physically_secured: bool,
}

impl RecoveryPolicy {
    /// The effective assurance a node can claim, given who can reset it.
    ///
    /// An unprotected firmware setup caps assurance no matter how good the
    /// silicon is: a root of trust anyone can clear is a root of trust anyone
    /// can replace.
    pub fn effective_assurance(&self, hardware: AssuranceClass) -> AssuranceClass {
        if self.firmware_password_set || self.physically_secured {
            hardware
        } else {
            hardware.min(AssuranceClass::Soft)
        }
    }

    /// Whether recovery is genuinely operator-only.
    pub fn operator_only(&self) -> bool {
        self.firmware_password_set && self.physically_secured
    }

    /// What to fix, if anything.
    pub fn advice(&self) -> Option<&'static str> {
        match (self.firmware_password_set, self.physically_secured) {
            (true, true) => None,
            (false, true) => Some(
                "set a firmware setup password: without one, anyone with keyboard access can clear the TPM",
            ),
            (true, false) => Some(
                "the firmware password is the only barrier; physical access still allows a reset via jumper or battery",
            ),
            (false, false) => Some(
                "recovery is unprotected: anyone reaching this machine can clear its root of trust and re-enrol it as a node you would still trust",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_recovery_action_is_reachable_from_software() {
        // The invariant that makes recovery an operator power rather than an
        // API. If someone adds a software path, this fails.
        for action in [
            RecoveryAction::PowerCycle,
            RecoveryAction::BiosClear,
            RecoveryAction::ChangeEndorsementSeed,
        ] {
            assert!(!action.software_invokable(), "{action} must not be software-invokable");
        }
    }

    #[test]
    fn a_power_cycle_costs_nothing() {
        let a = RecoveryAction::PowerCycle;
        assert!(a.preserves_node_identity());
        assert!(a.preserves_sealed_data());
        assert!(!a.requires_physical_presence());
    }

    #[test]
    fn clearing_keeps_identity_but_destroys_sealed_data() {
        // Node identifiers commit to the endorsement key, and a clear resets
        // the storage hierarchy rather than the endorsement seed.
        let a = RecoveryAction::BiosClear;
        assert!(a.preserves_node_identity());
        assert!(!a.preserves_sealed_data());
        assert!(a.requires_physical_presence());
    }

    #[test]
    fn changing_the_endorsement_seed_makes_it_a_different_node() {
        let a = RecoveryAction::ChangeEndorsementSeed;
        assert!(!a.preserves_node_identity());
        assert!(!a.preserves_sealed_data());
    }

    #[test]
    fn failure_mode_recommends_the_cheap_fix_first() {
        // Reaching for a clear here would destroy sealed data for no reason,
        // and that is not reversible.
        assert_eq!(Fault::FailureMode.recommended(), RecoveryAction::PowerCycle);
        assert_eq!(
            Fault::FailureMode.escalation(),
            Some(RecoveryAction::BiosClear)
        );
    }

    #[test]
    fn a_seal_policy_mismatch_is_not_fixed_by_rebooting() {
        assert_eq!(
            Fault::SealPolicyMismatch.recommended(),
            RecoveryAction::BiosClear
        );
    }

    #[test]
    fn escalation_terminates() {
        let mut action = Fault::FailureMode.recommended();
        let mut steps = 0;
        while let Some(next) = Fault::FailureMode.escalation().filter(|n| *n > action) {
            action = next;
            steps += 1;
            assert!(steps < 5, "escalation must terminate");
            if action == RecoveryAction::ChangeEndorsementSeed {
                break;
            }
        }
        assert!(RecoveryAction::ChangeEndorsementSeed > RecoveryAction::PowerCycle);
    }

    #[test]
    fn an_unprotected_firmware_setup_caps_assurance() {
        // A root of trust anyone can clear is a root of trust anyone can
        // replace, however good the silicon.
        let open = RecoveryPolicy {
            firmware_password_set: false,
            physically_secured: false,
        };
        assert_eq!(
            open.effective_assurance(AssuranceClass::Tpm),
            AssuranceClass::Soft
        );
        assert!(!open.operator_only());
        assert!(open.advice().is_some());
    }

    #[test]
    fn a_protected_machine_keeps_its_hardware_assurance() {
        let locked = RecoveryPolicy {
            firmware_password_set: true,
            physically_secured: true,
        };
        assert_eq!(
            locked.effective_assurance(AssuranceClass::Tpm),
            AssuranceClass::Tpm
        );
        assert!(locked.operator_only());
        assert_eq!(locked.advice(), None);
    }

    #[test]
    fn physical_security_alone_still_names_the_remaining_gap() {
        let p = RecoveryPolicy {
            firmware_password_set: true,
            physically_secured: false,
        };
        assert!(!p.operator_only());
        assert!(p.advice().unwrap().contains("jumper"));
    }

    #[test]
    fn follow_up_advice_matches_what_was_lost() {
        assert!(RecoveryAction::BiosClear.follow_up().contains("re-seal"));
        assert!(RecoveryAction::ChangeEndorsementSeed
            .follow_up()
            .contains("re-enrol"));
    }
}
