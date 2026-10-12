//! Node lifecycle, health signals and bounded remediation.
//!
//! The lifecycle is explicit because every transition is worth recording, and
//! remediation is bounded because a node that flaps between repair attempts is
//! worse than a node that stays cordoned and waits for a human.

pub mod lifecycle;
pub mod remediation;
pub mod signals;
pub mod slo;
pub mod workload;

pub use lifecycle::{Lifecycle, LifecycleError, State, Transition};
pub use remediation::{Outcome, Playbook, Remediator, Step};
pub use signals::{Severity, Signal, SignalKind};
pub use workload::{Health, Inventory, RunState, Workload, WorkloadKind};
