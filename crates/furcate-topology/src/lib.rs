//! The failure-domain tree and placement rules.
//!
//! Placement decisions that count hostnames are not placement decisions. Two
//! replicas on two machines fed by one UPS is replication factor one with
//! extra steps. Furcate publishes the physical hierarchy — site, feed, UPS,
//! rack, chassis, node — and evaluates placement as a rule over it, the way
//! CRUSH does: name the domain to spread across, and let the structure make
//! unsafe placements inexpressible rather than merely discouraged.

pub mod cabling;
pub mod cell;
pub mod capacity;
pub mod leaf_request;
pub mod lldp;
pub mod path;
pub mod placement;
pub mod read_token;
pub mod tree;

pub use cell::{Cell, CellTree, RollUp};
pub use capacity::{Capacity, Headroom, PowerModel};
pub use lldp::{discover, Neighbour};
pub use path::{LinkPath, PathPreference};
pub use placement::{place, PlacementError, PlacementRequest, PlacementResult};
pub use tree::{DomainKind, DomainTree, Node, Provenance};
