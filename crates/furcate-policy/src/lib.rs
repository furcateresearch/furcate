//! Who may do what, as data — and the small set of things that must never be.
//!
//! Until now this system's authority rules were `matches!` arms in Rust:
//! `loop_may_ever`, `network_may_ever`, the MCP tool list. That is safe and
//! auditable and it has one bad property — changing a rule means rebuilding and
//! redeploying every agent on the site. An operator who wants to let one node
//! accept a drain from the network for one afternoon has no way to say so.
//!
//! Large fleets solved this by making policy data evaluated by an engine, and
//! the 2026 work on agent delegation has converged further: **delegation rather
//! than impersonation**. An agent does not become the operator; it receives a
//! narrowed grant, its identity stays its own, and every hop is traceable.
//!
//! ## The two tiers, and why the split is the whole design
//!
//! **Invariants are code.** A handful of things must be impossible regardless
//! of what any file says: the network may never halt a machine, cut its power,
//! isolate it or erase its keys. If those lived in a policy file they would be
//! one edit away from not holding, and the edit would look like configuration.
//! They are compiled in, they are checked before anything else, and no grant
//! can reach past them.
//!
//! **Everything else is data.** Which principal may ask for which action on
//! which resource, under what conditions, until when. Deny by default, so a
//! rule that was never written is a rule that refuses.
//!
//! The distinction is the point. Policy engines are usually presented as though
//! everything should be expressible, and that is exactly wrong for a system
//! whose value proposition is that some things cannot happen.

pub mod action;
pub mod agent;
pub mod change;
pub mod custody;
pub mod delegation;
pub mod engine;
pub mod file;
pub mod invariant;
pub mod proposal;

pub use delegation::{CellDelegation, Grant, GrantError, Role, Scale, Scope};
pub use engine::{Decision, Effect, Policy, PolicySet, Request};
pub use proposal::{Proposal, ProposalError, Reversal, Status};
pub use invariant::{forbidden_to_all, Invariant};
