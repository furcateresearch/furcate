//! The node lifecycle state machine.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Known to the site, identity established, not yet appraised.
    Enrolled,
    /// Evidence appraised and acceptable.
    Attested,
    /// Eligible to receive work.
    Admitted,
    /// Carrying work.
    Active,
    /// Removed from scheduling, existing work still running.
    Cordoned,
    /// Work migrated away.
    Drained,
    /// Under a remediation playbook.
    Repairing,
    /// Believed faulty but not yet proven so.
    Suspect,
    /// Forcibly stopped.
    Fenced,
    /// Permanently removed.
    Retired,
}

impl State {
    /// Whether the node may be given new work.
    pub fn accepts_work(&self) -> bool {
        matches!(self, State::Admitted | State::Active)
    }

    /// Whether the node may hold custody of sealed data.
    ///
    /// A fenced or retired node must not, because we can no longer make
    /// statements about what is running on it.
    pub fn may_hold_custody(&self) -> bool {
        !matches!(self, State::Fenced | State::Retired | State::Enrolled)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            State::Enrolled => "enrolled",
            State::Attested => "attested",
            State::Admitted => "admitted",
            State::Active => "active",
            State::Cordoned => "cordoned",
            State::Drained => "drained",
            State::Repairing => "repairing",
            State::Suspect => "suspect",
            State::Fenced => "fenced",
            State::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Attest,
    Admit,
    Schedule,
    Cordon,
    Drain,
    Repair,
    Suspect,
    Fence,
    Retire,
    /// Return a repaired or cordoned node to service.
    Restore,
    /// Attestation failed on re-check.
    AttestationLost,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LifecycleError {
    pub from: State,
    pub transition: Transition,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot {:?} a node in state `{}`",
            self.transition,
            self.from.as_str()
        )
    }
}

impl std::error::Error for LifecycleError {}

pub struct Lifecycle {
    state: State,
    history: Vec<(Transition, State)>,
}

impl Lifecycle {
    pub fn new() -> Self {
        Self {
            state: State::Enrolled,
            history: Vec::new(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn history(&self) -> &[(Transition, State)] {
        &self.history
    }

    /// Apply a transition, or explain why it is not legal.
    ///
    /// Illegal transitions are an error rather than a silent no-op: a caller
    /// trying to schedule work onto a fenced node has a bug worth surfacing.
    pub fn apply(&mut self, t: Transition) -> Result<State, LifecycleError> {
        // Both enums have a `Suspect` variant, so they are aliased rather than
        // glob-imported: `Suspect` alone would be ambiguous.
        use State as S;
        use Transition as T;

        let next = match (self.state, t) {
            (S::Enrolled, T::Attest) => S::Attested,
            (S::Attested, T::Admit) => S::Admitted,
            (S::Admitted, T::Schedule) => S::Active,

            // Cordoning is legal from anywhere the node is in service.
            (S::Admitted | S::Active | S::Suspect, T::Cordon) => S::Cordoned,
            (S::Cordoned, T::Drain) => S::Drained,
            (S::Cordoned | S::Drained, T::Repair) => S::Repairing,
            (S::Repairing, T::Restore) => S::Admitted,
            (S::Cordoned, T::Restore) => S::Admitted,

            // Health can raise a suspicion about a working node.
            (S::Admitted | S::Active, T::Suspect) => S::Suspect,

            // Fencing is reachable from any live state: it is the response to
            // a node that has stopped listening.
            (
                S::Attested
                | S::Admitted
                | S::Active
                | S::Cordoned
                | S::Drained
                | S::Repairing
                | S::Suspect,
                T::Fence,
            ) => S::Fenced,

            // Losing attestation drops the node out of service immediately.
            (S::Admitted | S::Active | S::Suspect, T::AttestationLost) => S::Cordoned,

            (S::Drained | S::Repairing | S::Fenced | S::Cordoned, T::Retire) => S::Retired,

            (from, transition) => return Err(LifecycleError { from, transition }),
        };

        self.state = next;
        self.history.push((t, next));
        Ok(next)
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Transition::*;

    fn active() -> Lifecycle {
        let mut l = Lifecycle::new();
        l.apply(Attest).unwrap();
        l.apply(Admit).unwrap();
        l.apply(Schedule).unwrap();
        l
    }

    #[test]
    fn the_happy_path_reaches_active() {
        assert_eq!(active().state(), State::Active);
    }

    #[test]
    fn work_cannot_skip_attestation() {
        let mut l = Lifecycle::new();
        assert_eq!(
            l.apply(Schedule).unwrap_err(),
            LifecycleError {
                from: State::Enrolled,
                transition: Schedule
            }
        );
    }

    #[test]
    fn a_cordoned_node_stops_taking_work() {
        let mut l = active();
        l.apply(Cordon).unwrap();
        assert!(!l.state().accepts_work());
    }

    #[test]
    fn losing_attestation_removes_a_node_from_service() {
        let mut l = active();
        assert_eq!(l.apply(AttestationLost).unwrap(), State::Cordoned);
        assert!(!l.state().accepts_work());
    }

    #[test]
    fn the_repair_cycle_returns_a_node_to_service() {
        let mut l = active();
        l.apply(Cordon).unwrap();
        l.apply(Drain).unwrap();
        l.apply(Repair).unwrap();
        assert_eq!(l.apply(Restore).unwrap(), State::Admitted);
        assert!(l.state().accepts_work());
    }

    #[test]
    fn fencing_is_reachable_from_any_live_state() {
        for setup in [State::Attested, State::Admitted, State::Active] {
            let mut l = Lifecycle::new();
            l.apply(Attest).unwrap();
            if setup != State::Attested {
                l.apply(Admit).unwrap();
            }
            if setup == State::Active {
                l.apply(Schedule).unwrap();
            }
            assert_eq!(l.apply(Fence).unwrap(), State::Fenced);
        }
    }

    #[test]
    fn a_fenced_node_cannot_be_restored_only_retired() {
        let mut l = active();
        l.apply(Fence).unwrap();
        assert!(l.apply(Restore).is_err());
        assert_eq!(l.apply(Retire).unwrap(), State::Retired);
    }

    #[test]
    fn a_fenced_node_may_not_hold_custody() {
        let mut l = active();
        assert!(l.state().may_hold_custody());
        l.apply(Fence).unwrap();
        assert!(!l.state().may_hold_custody());
    }

    #[test]
    fn history_records_every_transition() {
        let l = active();
        assert_eq!(l.history().len(), 3);
        assert_eq!(l.history()[0], (Attest, State::Attested));
    }
}
