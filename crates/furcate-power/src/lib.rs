//! Power as a first-class subsystem.
//!
//! Most cluster managers treat power as somebody else's problem. Hyperscalers
//! do not, and at site scale the numbers are smaller while the stakes are not:
//! one circuit, a supply with minutes of runtime, and no remote hands.
//!
//! Three concerns live here. The **ladder** descends through reversible rungs
//! as a supply drains, and is interruptible until the last one. The **bring-up
//! graph** is the harder half — shutdown is choreography, startup is
//! dependency resolution, and it is where this site has actually been burned.
//! The **kill switch** is the operator's authority over their own hardware,
//! and is deliberately the one thing no remote party can invoke. For a
//! machine it is an advisory stop request, never an emergency stop.
//!
//! Measurement comes first, and it differs by machine: [`rapl`] reads the
//! x86 package counters, [`rails`] the INA3221/INA238 rail monitors on Jetson
//! carriers and the Raspberry Pi 5 PMIC. Each figure names the interface it
//! came from, and a rail that did not read is not measured rather than zero.
//! [`supply`] reads what a board OS reports about its own supply.

pub mod actuator;
pub mod bringup;
pub mod confirm;
pub mod halt;
pub mod ladder;
pub mod rails;
pub mod rapl;
pub mod shutdown;
pub mod supply;
pub mod thermal;
pub mod wake;

pub use actuator::{Applied, Capabilities, Governor, Lever};
pub use bringup::{BringUp, Gate, GateState, Unit};
pub use ladder::{Ladder, PowerState, Rung, Triggers, UpsObservation};
pub use rails::{PowerMode, Rail};
pub use rapl::{Power, Sample, Scope};
pub use thermal::{rung_for, rung_from, Origin, Reading, Thresholds};
