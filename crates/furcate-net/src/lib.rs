//! Authenticated transport between nodes.
//!
//! Until this existed every inter-node call was unauthenticated. Anything that
//! could reach a node's address could load a model onto it, read its ledger,
//! or — worst — post a forged chain head to the site controller, which then
//! folded it into the Merkle site root. A tamper-evident ledger whose
//! aggregate anyone can write is not tamper-evident.
//!
//! The shape follows what workload-identity systems settled on: a node proves
//! what it is by attestation, receives a short-lived credential, uses it to
//! authenticate every call, and the credential expires rather than being
//! revoked. What differs here is that the identity is already a public key
//! sealed to hardware, so there is nothing to distribute — a node signs with
//! the key it cannot export, and the roster of acceptable keys comes from the
//! verifier.
//!
//! The rest of the crate is about the network as a physical thing rather than
//! as a trust boundary: what the wire is doing, where the path stops working,
//! and whether the connection is good as opposed to merely fast. All of it
//! reads counters and small probes; nothing here saturates a link to measure
//! it, because the link in question is carrying production traffic.

pub mod announce;
pub mod firewall;
pub mod overlay;
pub mod wg;
pub mod link;
pub mod lease;
pub mod lock;
pub mod names;
pub mod punch;
pub mod quality;
pub mod reach;
pub mod roster;
pub mod sitepolicy;

pub use link::{diagnose, Counters, Delta, Fault, Link, LinkKind};
pub use quality::{Advice, Load, Quality, Responsiveness, Sample};
pub use reach::{Layer, Probe, Reachability};
pub use roster::{Roster, RosterError};
