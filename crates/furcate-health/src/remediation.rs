//! Bounded remediation playbooks.
//!
//! Automatic repair follows the pattern cluster managers settled on: cordon
//! the node out of scheduling, move what it was carrying, then run a
//! policy-driven playbook. The important constraint is that playbooks are
//! *bounded* — a node that fails remediation twice stays cordoned rather than
//! flapping, because an endless repair loop looks like availability while
//! delivering none.

use crate::signals::{Signal, SignalKind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Restart the affected service.
    RestartService,
    /// Reboot the operating system.
    Reboot,
    /// Power cycle out of band, for a wedged machine.
    PowerCycle,
    /// Re-run attestation.
    ReAttest,
    /// Nothing automatic can fix this.
    EscalateToHuman,
    /// Reset an accelerator, after its work has been moved off.
    ///
    /// Added once `furcatectl accelerator reset` existed to carry it out. A
    /// playbook is advice a person follows — `RestartService` has always been
    /// carried out by an operator running the command, not by this crate — so a
    /// step is honest exactly when somebody can act on it, and was not before.
    ResetDevice,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Playbook {
    pub steps: Vec<Step>,
    /// How many complete runs before giving up.
    pub max_attempts: u32,
}

impl Playbook {
    /// Choose a playbook for a signal.
    ///
    /// Physical faults escalate immediately: no amount of rebooting replaces a
    /// disk, and pretending otherwise wastes the window in which the operator
    /// could have acted.
    pub fn for_signal(kind: &SignalKind) -> Self {
        match kind {
            SignalKind::Unreachable => Playbook {
                steps: vec![Step::Reboot, Step::PowerCycle, Step::EscalateToHuman],
                max_attempts: 2,
            },
            SignalKind::AttestationDrift { .. } => Playbook {
                // Drift might be a legitimate firmware update, so re-check
                // once — but never silently re-admit.
                steps: vec![Step::ReAttest, Step::EscalateToHuman],
                max_attempts: 1,
            },
            SignalKind::Thermal { .. } => Playbook {
                steps: vec![Step::RestartService, Step::EscalateToHuman],
                max_attempts: 1,
            },
            SignalKind::DiskDegraded { .. } | SignalKind::MemoryErrors { .. } => Playbook {
                steps: vec![Step::EscalateToHuman],
                max_attempts: 1,
            },
            // Memory pressure has already been answered by the time this is
            // read: the power ladder descends to `Shed` on a stalled machine
            // and gives preemptible work back, which is the only remediation
            // that hands memory over. What is left here is the case where that
            // was not enough.
            //
            // The tempting step is `RestartService`, and it is wrong for the
            // reason the accelerator case above gives. A service restarted
            // re-allocates what it had; and every `furcate-app-*` unit is
            // already bounded, so a single runaway is being killed inside its
            // own cgroup without any of this. Pressure that survives both means
            // the legitimate work on this machine exceeds the machine, which is
            // a placement decision and belongs with a person.
            SignalKind::MemoryPressure { .. } => Playbook {
                steps: vec![Step::EscalateToHuman],
                max_attempts: 1,
            },
            SignalKind::PowerFault { .. } => Playbook {
                steps: vec![Step::EscalateToHuman],
                max_attempts: 1,
            },
            // Accelerators escalate, including the one case where an automatic
            // fix looks obvious and is not.
            //
            // A card that has condemned rows is a disk by another name: no
            // amount of restarting replaces it. The tempting one is headroom —
            // restarting the process holding the memory really would free it.
            // But a serving engine started with a static memory fraction
            // re-reserves exactly the same share the moment it comes back, so
            // the remediation would run, appear to succeed, and leave the card
            // in the state it started in, forever. The fix is a placement or
            // configuration decision and belongs with a person.
            SignalKind::AcceleratorDegraded { .. } => Playbook {
                steps: vec![Step::EscalateToHuman],
                max_attempts: 1,
            },
            // A card carrying a queued repair. The remap is recorded and only a
            // reset applies it, so the sequence is: move the work off, reset,
            // and if it comes back still complaining, a person.
            //
            // The drain is not a step here because this crate cannot decide
            // whose work to stop. `furcatectl accelerator reset` refuses a card
            // with processes on it, which turns the drain into a precondition
            // somebody has to satisfy rather than an action taken quietly.
            SignalKind::AcceleratorFault { remedy, .. } if remedy == "reset_device" => Playbook {
                steps: vec![Step::ResetDevice, Step::EscalateToHuman],
                max_attempts: 1,
            },
            // Every other named fault escalates, and the reason is worth
            // writing down because one automatic fix looks obvious and is not.
            //
            // Restarting the workload for a job that used an address it did not
            // own is genuinely the right repair — but it is the *job's* repair,
            // not the node's. An Xid 31 says nothing is wrong with this
            // machine, and a health remediator that restarts somebody's
            // training run because their program had a bug is acting well
            // outside what it was told about.
            SignalKind::AcceleratorFault { .. } => Playbook {
                steps: vec![Step::EscalateToHuman],
                max_attempts: 1,
            },
            // Workload faults escalate rather than being remediated here.
            // Systemd and Docker already restart what they own; a second
            // supervisor acting on the same process produces a state neither
            // intended, and a workload still down after its own supervisor
            // gave up is a case for a human, not another restart.
            SignalKind::WorkloadDown { .. } | SignalKind::WorkloadFlapping { .. } => Playbook {
                steps: vec![Step::EscalateToHuman],
                max_attempts: 1,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Run this step next.
    Run(Step),
    /// Remediation succeeded; the node may be restored.
    Recovered,
    /// Attempts exhausted. The node stays cordoned for a human.
    GaveUp { attempts: u32 },
}

pub struct Remediator {
    playbook: Playbook,
    step_index: usize,
    attempts: u32,
}

impl Remediator {
    pub fn new(playbook: Playbook) -> Self {
        Self {
            playbook,
            step_index: 0,
            attempts: 0,
        }
    }

    pub fn for_signal(signal: &Signal) -> Self {
        Self::new(Playbook::for_signal(&signal.kind))
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Ask for the next action.
    pub fn next_step(&mut self) -> Outcome {
        if self.attempts >= self.playbook.max_attempts {
            return Outcome::GaveUp {
                attempts: self.attempts,
            };
        }
        match self.playbook.steps.get(self.step_index) {
            Some(step) => {
                self.step_index += 1;
                Outcome::Run(*step)
            }
            None => {
                // Ran out of steps without recovering: count the attempt and
                // start again if any remain.
                self.attempts += 1;
                self.step_index = 0;
                if self.attempts >= self.playbook.max_attempts {
                    Outcome::GaveUp {
                        attempts: self.attempts,
                    }
                } else {
                    self.next_step()
                }
            }
        }
    }

    /// Report that the node came back.
    pub fn succeeded(&mut self) -> Outcome {
        Outcome::Recovered
    }

    /// The next step, bounded by what the service promised rather than by a
    /// count somebody guessed.
    ///
    /// `max_attempts` is a fixed number chosen once, with no idea whether the
    /// service it is restarting is inside its promise or far outside it. An
    /// exhausted error budget is the same decision made on evidence: the loop
    /// has had the whole window to work and the service is still outside its
    /// objective, so it is not fixing the problem, and every further attempt
    /// costs another outage while nobody who could fix it has been told.
    ///
    /// The count still applies. This only ever gives up *earlier*, never
    /// later — an intact budget cannot buy more attempts than the playbook
    /// allows, because a healthy month of history is not a reason to restart a
    /// machine twenty times tonight.
    pub fn next_step_within(&mut self, budget: &crate::slo::Status) -> Outcome {
        if !budget.permits_automatic_remediation() {
            return Outcome::GaveUp {
                attempts: self.attempts,
            };
        }
        self.next_step()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::Signal;

    #[test]
    fn an_unreachable_node_is_rebooted_then_power_cycled() {
        let s = Signal::new("n", SignalKind::Unreachable, 0);
        let mut r = Remediator::for_signal(&s);
        assert_eq!(r.next_step(), Outcome::Run(Step::Reboot));
        assert_eq!(r.next_step(), Outcome::Run(Step::PowerCycle));
        assert_eq!(r.next_step(), Outcome::Run(Step::EscalateToHuman));
    }

    #[test]
    fn a_failing_disk_goes_straight_to_a_human() {
        let s = Signal::new(
            "n",
            SignalKind::DiskDegraded {
                device: "nvme0".into(),
                reallocated: 9000,
            },
            0,
        );
        let mut r = Remediator::for_signal(&s);
        assert_eq!(r.next_step(), Outcome::Run(Step::EscalateToHuman));
    }

    #[test]
    fn remediation_gives_up_rather_than_flapping() {
        let s = Signal::new("n", SignalKind::Unreachable, 0);
        let mut r = Remediator::for_signal(&s);
        // Exhaust both attempts.
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 50, "must terminate");
            if let Outcome::GaveUp { attempts } = r.next_step() {
                assert_eq!(attempts, 2);
                break;
            }
        }
    }

    #[test]
    fn attestation_drift_is_rechecked_once_then_escalated() {
        let s = Signal::new("n", SignalKind::AttestationDrift { register: 11 }, 0);
        let mut r = Remediator::for_signal(&s);
        assert_eq!(r.next_step(), Outcome::Run(Step::ReAttest));
        assert_eq!(r.next_step(), Outcome::Run(Step::EscalateToHuman));
        assert_eq!(r.next_step(), Outcome::GaveUp { attempts: 1 });
    }

    #[test]
    fn recovery_ends_the_cycle() {
        let s = Signal::new("n", SignalKind::Unreachable, 0);
        let mut r = Remediator::for_signal(&s);
        r.next_step();
        assert_eq!(r.succeeded(), Outcome::Recovered);
    }
}

#[cfg(test)]
mod workload_tests {
    use super::*;

    #[test]
    fn a_failed_workload_escalates_rather_than_being_restarted_again() {
        // Systemd and Docker already restart what they own. A second
        // supervisor on the same process produces a state neither intended,
        // and a workload still down after its own supervisor gave up is a
        // case for a human.
        let p = Playbook::for_signal(&SignalKind::WorkloadDown {
            id: "mainnet-participant-1".into(),
            critical: true,
        });
        assert_eq!(p.steps, vec![Step::EscalateToHuman]);
    }

    #[test]
    fn so_does_a_flapping_one() {
        let p = Playbook::for_signal(&SignalKind::WorkloadFlapping {
            id: "x".into(),
            restarts: 12,
        });
        assert_eq!(p.steps, vec![Step::EscalateToHuman]);
        assert!(!p.steps.contains(&Step::RestartService));
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use crate::slo::{Objective, Observed, Status, assess};

    fn objective() -> Objective {
        Objective {
            name: "edge.availability".into(),
            target: 0.999,
            window_secs: 30 * 86_400,
        }
    }

    fn unreachable_node() -> Remediator {
        Remediator::new(Playbook::for_signal(&SignalKind::Unreachable))
    }

    #[test]
    fn an_exhausted_budget_gives_up_before_the_count_does() {
        // The loop has had the window and the service is still outside its
        // promise, so restarting again is not a fix — it is a second outage
        // with nobody told.
        let spent = assess(
            &objective(),
            &Observed { good: 9_970, total: 10_000, elapsed_secs: 20 * 86_400 },
        );
        assert!(spent.is_exhausted());

        let mut r = unreachable_node();
        assert_eq!(r.next_step_within(&spent), Outcome::GaveUp { attempts: 0 });
    }

    #[test]
    fn an_intact_budget_does_not_buy_extra_attempts() {
        // The bound only ever tightens. A healthy month of history is not a
        // reason to restart a machine past what the playbook allows.
        let healthy = assess(
            &objective(),
            &Observed { good: 10_000, total: 10_000, elapsed_secs: 20 * 86_400 },
        );
        assert!(healthy.permits_automatic_remediation());

        let mut r = unreachable_node();
        let mut steps = 0;
        loop {
            match r.next_step_within(&healthy) {
                Outcome::Run(_) => {
                    steps += 1;
                    assert!(steps < 50, "the count stopped bounding the loop");
                }
                Outcome::GaveUp { .. } => break,
                Outcome::Recovered => unreachable!(),
            }
        }
        // Same place the unbounded call would have stopped.
        let mut plain = unreachable_node();
        let mut plain_steps = 0;
        while let Outcome::Run(_) = plain.next_step() {
            plain_steps += 1;
        }
        assert_eq!(steps, plain_steps);
    }

    #[test]
    fn knowing_nothing_yet_does_not_block_a_fix() {
        // Early in a window there is no budget answer, and refusing to act on
        // that would make a service unrecoverable for the first hour of every
        // window.
        let early = assess(
            &objective(),
            &Observed { good: 3, total: 4, elapsed_secs: 30 },
        );
        assert!(matches!(early, Status::TooEarly { .. }));
        let mut r = unreachable_node();
        assert!(matches!(r.next_step_within(&early), Outcome::Run(_)));
    }

    #[test]
    fn a_queued_repair_asks_for_a_reset_before_a_person() {
        // The card has already decided the repair; only a reset applies it. A
        // step is honest here because `furcatectl accelerator reset` can carry
        // it out — it was not, before that existed.
        let p = Playbook::for_signal(&SignalKind::AcceleratorFault {
            index: Some(0),
            pci: None,
            code: 63,
            blame: "card".into(),
            remedy: "reset_device".into(),
            contained: Some(true),
            implicates_card: false,
            should_drain: false,
            actionable: true,
            summary: "row remap recorded".into(),
            seen: 1,
        });
        assert_eq!(p.steps, vec![Step::ResetDevice, Step::EscalateToHuman]);
        assert_eq!(p.max_attempts, 1, "once, then a person");
    }

    #[test]
    fn a_workloads_own_bug_does_not_ask_for_a_reset() {
        // Xid 31 is a job using an address it did not own. Resetting the card
        // over it would destroy every other context on the device to fix
        // somebody's pointer.
        let p = Playbook::for_signal(&SignalKind::AcceleratorFault {
            index: Some(0),
            pci: None,
            code: 31,
            blame: "workload".into(),
            remedy: "restart_workload".into(),
            contained: None,
            implicates_card: false,
            should_drain: false,
            actionable: true,
            summary: "memory page fault".into(),
            seen: 1,
        });
        assert_eq!(p.steps, vec![Step::EscalateToHuman]);
    }
}
