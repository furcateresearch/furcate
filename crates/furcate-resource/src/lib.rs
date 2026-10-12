//! Machine resources: what is contended, what is allocated, what is wasted.
//!
//! Three ideas, all of them borrowed from how large fleets are actually run and
//! none of them needing a large fleet to be useful.
//!
//! **Pressure rather than utilisation.** A processor at a hundred percent with
//! nothing queued is fine; one at forty percent with tasks stalled on memory
//! reclaim is failing. Pressure Stall Information measures the second thing,
//! which is the one that predicts trouble, and the kernel has been keeping it
//! all along.
//!
//! **The kernel's accounting rather than the runtime's.** Everything on a
//! modern Linux box — Docker containers, systemd units, Kubernetes pods —
//! lands in the same cgroup v2 hierarchy, so reading it directly covers all of
//! them at once and reports what the kernel charged rather than what a runtime
//! chose to say about itself.
//!
//! **The gap between the limit and the peak.** Borg reclaims roughly a fifth
//! of everything allocated to it on exactly this observation. A site of two
//! machines has nowhere to put reclaimed capacity, but it does have an operator
//! who picked every one of those limits by hand and would like to know which
//! ones were wrong.
//!
//! One piece of advice this deliberately withholds. The obvious remedy for a
//! group with no throttling threshold is to add one — and on a group whose
//! memory is mostly heap, with swap still enabled, that is worse than doing
//! nothing. Reclaim pushes heap pages to swap, the garbage collector faults
//! them straight back in, and a fast clean kill becomes a slow spiral that also
//! drags the host's I/O down. So the recommendation names the prerequisite
//! rather than assuming it, which is the difference between advice an operator
//! can follow and advice that costs them an outage.

pub mod cgroup;
pub mod limits;
pub mod psi;
pub mod toolchain;
pub mod binding;
pub mod tenancy;

pub use cgroup::{Cpu, Group, Memory, Owner, CGROUP_ROOT};
pub use limits::{Bounds, IoMax, Step};
pub use psi::{Kind, Level, Pressure, Psi, Share, Thresholds};
pub use toolchain::{Bound, Machine as BuildMachine, Observed, Shape, Toolchain};
