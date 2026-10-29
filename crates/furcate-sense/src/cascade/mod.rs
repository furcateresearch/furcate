//! The processing rungs above a sensing node.
//!
//! A sensing node transduces; the micro processing node that reads it signs for
//! it; the small processing node implemented here (a Raspberry Pi running
//! Furcate) is the first rung that can afford to check everything the one below
//! it says. This module is that rung's logic, as a library with no I/O of its
//! own, so the same checks run in a test, in the `furcate-small` command and on
//! any further rung.
//!
//! | piece | does |
//! |---|---|
//! | [`signer`] | the one way a rung signs: a hardware-held key, never raw key bytes |
//! | [`directory`] | what this rung has enrolled: nodes, their keys and the classes their key custody earns |
//! | [`attest`] | a nonce challenge that has the running model compute, and the verifier that checks the answer |
//! | [`binding`] | the model, epoch and calibration a reading states it ran, and the registry that checks it |
//! | [`coherence`] | cross-checks between the accelerometer, gyroscope and rotation vector of one sensing node, as flags |
//! | [`commit`] | a signed Merkle commitment to a batch of embeddings, and the challenge that audits one window |
//! | [`birth`] | the signed birth record a model or policy must carry before a node accepts it |
//! | [`chain`] | validates the rungs a reading claims to have passed through |
//! | [`classes`] | what each position can host, its compute class and the attestation level it can reach |
//! | [`drift`] | per-node embedding-space drift and its cause, read across nodes |
//! | [`witness`] | per-leaf hash-chained reading log, checked and cosigned here |
//! | [`ingest`] | verifies a frame end to end and records every refusal |
//! | [`model`] | the hook for a model run on received embeddings, and a reference model |
//! | [`physical`] | the signed batch a large node sends to a consumer outside Furcate |
//! | [`escalate`] | when to pass an item to the next rung, and the extended chain it carries |
//! | [`gate`] | an escalation gate that holds the agreement of what it keeps to a target, from the larger model's answers |
//! | [`small`] | the small processing node: ingest, model, escalation policy and forwarding |
//! | [`micro`] | a host-side stand-in for the micro processing node, for tests and replay |
//!
//! Nothing here raises an attestation level. The level of anything that passes
//! through is the lowest class of any rung it passed, computed by the verifier
//! from its own records, and no rung can raise it by saying so.

pub mod attest;
pub mod binding;
pub mod birth;
pub mod chain;
pub mod classes;
pub mod coherence;
pub mod commit;
pub mod directory;
pub mod drift;
pub mod escalate;
pub mod gate;
pub mod ingest;
pub mod micro;
pub mod model;
pub mod physical;
pub mod signer;
pub mod small;
pub mod witness;
