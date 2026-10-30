//! The release interface between the gate and whatever moves an actuator.
//!
//! A [`Release`] is the only thing an [`Executor`] receives, and only the gate can make one: its fields are private
//! and its constructor is crate-private. An executor therefore cannot be handed a command that did not pass every
//! check, and nothing outside this crate can call an executor with an invented release.
//!
//! Nothing here is a safety function. An executor writes setpoints; the machine's own safety system stays the safety
//! function (docs/physical-command.md).

/// What to write for one released command.
#[derive(Clone, Debug, PartialEq)]
pub enum Plan {
    /// One setpoint.
    Setpoint { quantity: String, unit: String, value: f64 },
    /// Joint positions in radian, `steps[i][j]` for step `i` and joint `j`, one step every `step_ms`. Only the
    /// accepted prefix of a chunk: a truncated chunk releases the steps before the first violation and nothing else.
    Trajectory { dof: usize, step_ms: u64, steps: Vec<Vec<f64>> },
}

/// One command the gate has accepted and written ahead to the ledger.
///
/// Only the gate makes a `Release`; the fields are private and the constructor is not public. This does not compile:
///
/// ```compile_fail,E0451
/// use furcate_command::{Plan, Release};
/// let _ = Release {
///     command_id: "c".into(),
///     actuator_id: "a".into(),
///     system_class: "test_bench".into(),
///     approval_id: "x".into(),
///     release_ledger_seq: 1,
///     plan: Plan::Setpoint { quantity: "q".into(), unit: "u".into(), value: 1.0 },
/// };
/// ```
///
/// Nor does calling the constructor:
///
/// ```compile_fail,E0624
/// use furcate_command::{Plan, Release};
/// let _ = Release::new("c", "a", "test_bench", "x", 1, Plan::Setpoint { quantity: "q".into(), unit: "u".into(), value: 1.0 });
/// ```
#[derive(Clone, Debug)]
pub struct Release {
    command_id: String,
    actuator_id: String,
    system_class: String,
    approval_id: String,
    release_ledger_seq: u64,
    plan: Plan,
}

impl Release {
    pub(crate) fn new(command_id: &str, actuator_id: &str, system_class: &str, approval_id: &str, release_ledger_seq: u64, plan: Plan) -> Release {
        Release {
            command_id: command_id.into(),
            actuator_id: actuator_id.into(),
            system_class: system_class.into(),
            approval_id: approval_id.into(),
            release_ledger_seq,
            plan,
        }
    }
    /// The command's id.
    pub fn command_id(&self) -> &str {
        &self.command_id
    }
    /// The actuator the command targets.
    pub fn actuator_id(&self) -> &str {
        &self.actuator_id
    }
    /// The system class the site assigned to that actuator.
    pub fn system_class(&self) -> &str {
        &self.system_class
    }
    /// The actuation approval that covers this release.
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }
    /// The ledger sequence number of the write-ahead entry. It is already in the chain when the executor runs.
    pub fn release_ledger_seq(&self) -> u64 {
        self.release_ledger_seq
    }
    /// What to write.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
}

/// A completed release: every write was done and acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Execution {
    /// How many writes were done.
    pub writes: u64,
}

/// A release that did not complete. The writes already done are not undone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecError {
    /// How many writes were done and acknowledged before the failure.
    pub writes_done: u64,
    /// A short reason for the log. It is not copied into the receipt.
    pub reason: String,
}

/// Writes a [`Release`] to the equipment. Called by [`crate::Gate::decide_exec`] after the write-ahead entry, and
/// never for a refused command.
pub trait Executor {
    /// Perform the release. Return the number of writes done, or the error with the number done before it.
    fn execute(&mut self, r: &Release) -> Result<Execution, ExecError>;
}
