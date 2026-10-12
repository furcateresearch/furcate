//! Cluster membership and failure detection.
//!
//! Membership is gossip, not consensus. SWIM gives scalable weakly-consistent
//! membership without a quorum, which matters here because a two-node site
//! cannot form one.
//!
//! The Lifeguard refinement is the part worth implementing carefully: a slow
//! node is not a dead node. A member that is itself starved of CPU or losing
//! packets is a poor judge of others, so it raises its own local health score
//! and becomes correspondingly more patient before accusing anyone. False
//! failure detection is expensive here — it triggers rebalancing, drains, and
//! in the worst case a fencing action against a healthy machine.
//!
//! Members also carry each other's signed statements about themselves
//! ([`rumour`]), so a fact such as a rebooted node's new overlay key spreads
//! member to member without a coordinator.

pub mod rumour;
pub mod swim;

pub use rumour::{Rumour, Rumours, Taken};
pub use swim::{Incarnation, Member, MemberState, Membership, Transition};
