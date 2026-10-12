//! The RATS verifier.
//!
//! Furcate occupies the Verifier role from RFC 9334: nodes are Attesters
//! producing Evidence, the TPM vendor is the Endorser, and the site controller
//! appraises Evidence against reference values and an appraisal policy to
//! produce an Attestation Result. Relying Parties — Furcate's own scheduler,
//! and optionally a remote verifier the operator chooses — act on the Result.
//!
//! Both topologies are supported deliberately. In the **passport** model the
//! node carries a signed Result and presents it wherever it goes, which is
//! cheap and lets a consumer avoid parsing TPM internals. In the
//! **background-check** model raw Evidence is passed through so a consumer can
//! appraise it with a verifier of its own choosing — which matters because a
//! site's own verifier is run by the same party that owns the hardware, and
//! therefore cannot certify that party's honesty.

pub mod freshness;
pub mod policy;
pub mod verifier;

pub use freshness::{EpochId, FreshnessError, FreshnessProof, NonceChallenge};
pub use policy::{AppraisalPolicy, Coverage, PolicyViolation, ReferenceValues};
pub use verifier::{AttestationResult, Topology, Verdict, Verifier};
