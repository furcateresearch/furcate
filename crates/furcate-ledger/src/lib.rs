//! Hashchained proofs of chip-level operations.
//!
//! Every operation that touches the root of trust appends to a per-node chain
//! in which each entry commits to its predecessor, so history cannot be
//! rewritten without breaking the chain. Periodically the chain head is
//! extended into a platform register and quoted, producing a checkpoint the
//! operator cannot forge or roll back — reproducing a divergent history would
//! require a quote over a register value the chip never held.
//!
//! Site controllers aggregate node heads into a Merkle root, so one anchor
//! covers every node and any single operation can be proven against it with a
//! short inclusion path.

pub mod chain;
pub mod checkpoint;
pub mod merkle;
pub mod store;

pub use chain::{Chain, ChainError, Op, OpKind};
pub use checkpoint::{Checkpoint, CheckpointError};
pub use merkle::{InclusionProof, MerkleTree};
pub use store::{load, save, StoreError};
