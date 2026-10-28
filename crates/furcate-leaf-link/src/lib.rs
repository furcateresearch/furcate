//! The host end of a leaf link.
//!
//! A micro processing node (a leaf) dials out, says HELLO, and is answered by
//! a node that holds a grant from the operator. This crate is that node's
//! side: the frame format ([`wire`]), the session state machine and its keys
//! ([`session`]), the leaf's signed readings and how they are checked
//! ([`report`]), and the bridge that turns verified readings into the frames
//! the small processing node reads ([`bridge`]).
//!
//! The leaf's long-term key signs; the node's key never enters this crate. A
//! node signs through [`session::NodeSigner`], which the command wires to the
//! machine's hardware root of trust.

pub mod bridge;
pub mod config;
pub mod report;
pub mod serve;
pub mod session;
pub mod sim;
pub mod wire;

pub use bridge::{Action, Bridge, BridgeConfig, ModuleSource, Source};
pub use session::{Hello, LinkError, NodeGrant, NodeSigner, Session};
