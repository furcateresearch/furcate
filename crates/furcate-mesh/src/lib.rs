//! The local intelligence mesh.
//!
//! A real edge cluster is uneven: one machine has a GPU, some have decent
//! CPUs, a Jetson sits in the corner, and microcontrollers read sensors.
//! Unevenness is the resource, not the problem. Each tier hosts what it can
//! actually hold, and the whole cluster addresses all of it as one surface.
//!
//! Nodes do not self-declare capability — it comes from the attested hardware
//! inventory, so a node cannot claim a GPU it does not have and placement
//! inherits the trust properties of attestation for free.

pub mod administration;
pub mod agreement;
pub mod capability;
pub mod cascade;
pub mod catalog;
pub mod corruption;
pub mod handles;
pub mod ownership;
pub mod receipt;
pub mod roles;
pub mod router;

pub use capability::{Capability, Tier};
pub use cascade::{CascadePlan, CascadeStage};
pub use catalog::{Catalog, ModelManifest, RouteError, Route};
pub use receipt::{InferenceReceipt, ReceiptError, VerificationLevel};
pub use router::{route, Candidate, RouteFailure, Score, Weights};
