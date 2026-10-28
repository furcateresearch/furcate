//! What a sandboxed agent did, as the chain records it.
//!
//! A runtime's own logs are inputs, never authority: they are unsigned and a
//! busy runtime can drop events. So the node does not copy them into the chain.
//! It numbers the decisions it received itself, commits each batch to a count,
//! a sequence range and a Merkle root over the decisions, links the batch to
//! the one before it, and signs the result. A decision that was dropped before
//! it reached the node is declared in `source_gaps` when the runtime says so;
//! one dropped after is a hole in the sequence or the link, and
//! [`verify_continuity`] finds it.
//!
//! The entries use the free-form fields of [`crate::chain::Op`]: `actor` is
//! the agent id, `subject` names the runtime and sandbox, and `result` is the
//! JSON of [`DecisionBatch`] or [`AgentKilledRecord`].

use crate::merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What the runtime decided about one thing the agent tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allowed,
    Denied,
    /// The runtime reported something that is neither: audit-only, an error.
    Other,
}

/// One decision, numbered by the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Assigned by the node when the decision arrives, dense from zero for a
    /// sandbox. The runtime's own numbering, if it has any, is `source_seq`.
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_seq: Option<u64>,
    pub time_ms: u64,
    /// `network`, `process`, `filesystem`, `tool` or `other`.
    pub kind: String,
    pub action: Action,
    /// The destination, path, program or operation.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// SHA-256 of the runtime's own record, so the detail can be kept apart and
    /// still be checked against this entry.
    pub raw_sha256: String,
}

impl Decision {
    /// The bytes a Merkle leaf is made of.
    pub fn leaf_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A signed commitment to a run of consecutive decisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBatch {
    pub v: u32,
    pub agent: String,
    pub runtime: String,
    pub sandbox: String,
    pub policy_sha256: String,
    /// The batch covers decisions `first_seq .. first_seq + count`.
    pub first_seq: u64,
    pub count: u64,
    pub allowed: u64,
    pub denied: u64,
    /// Events the runtime or the channel it travelled is known to have lost
    /// before the node saw them. Zero means none was detected, not that none
    /// was lost.
    pub source_gaps: u64,
    /// Merkle root over the decisions, hex. Empty for a batch of none.
    pub root: String,
    /// Hash of the batch before this one for the same sandbox, or all zeros.
    pub prev: String,
    /// Why the batch is the last one: `exited`, `crashed`, `killed`,
    /// `torn_down`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// The node key that signed, as Furcate names keys.
    pub signer: String,
    /// Hex signature over [`DecisionBatch::signing_bytes`].
    pub signature: String,
}

fn put(m: &mut Vec<u8>, f: &str) {
    m.extend_from_slice(&(f.len() as u64).to_be_bytes());
    m.extend_from_slice(f.as_bytes());
}

impl DecisionBatch {
    /// An unsigned batch over `decisions`, which must be consecutive from
    /// `first_seq`.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        agent: &str,
        runtime: &str,
        sandbox: &str,
        policy_sha256: &str,
        first_seq: u64,
        decisions: &[Decision],
        source_gaps: u64,
        prev: Option<&str>,
        end: Option<&str>,
    ) -> DecisionBatch {
        let leaves: Vec<Vec<u8>> = decisions.iter().map(Decision::leaf_bytes).collect();
        DecisionBatch {
            v: 1,
            agent: agent.into(),
            runtime: runtime.into(),
            sandbox: sandbox.into(),
            policy_sha256: policy_sha256.into(),
            first_seq,
            count: decisions.len() as u64,
            allowed: decisions.iter().filter(|d| d.action == Action::Allowed).count() as u64,
            denied: decisions.iter().filter(|d| d.action == Action::Denied).count() as u64,
            source_gaps,
            root: MerkleTree::build(&leaves).map(|t| t.root_hex()).unwrap_or_default(),
            prev: prev.unwrap_or(ZERO).into(),
            end: end.map(str::to_string),
            signer: String::new(),
            signature: String::new(),
        }
    }

    /// What the signature covers: every field but the signature, length
    /// prefixed so the signature does not depend on a serialiser.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut m = b"furcate:agent-decision-batch:v1\0".to_vec();
        for f in [
            self.v.to_string(),
            self.agent.clone(),
            self.runtime.clone(),
            self.sandbox.clone(),
            self.policy_sha256.clone(),
            self.first_seq.to_string(),
            self.count.to_string(),
            self.allowed.to_string(),
            self.denied.to_string(),
            self.source_gaps.to_string(),
            self.root.clone(),
            self.prev.clone(),
            self.end.clone().unwrap_or_default(),
            self.signer.clone(),
        ] {
            put(&mut m, &f);
        }
        m
    }

    /// What the next batch names as its `prev`.
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.signing_bytes());
        h.update(self.signature.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn to_result(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_result(s: &str) -> Result<DecisionBatch, String> {
        serde_json::from_str(s).map_err(|e| format!("not a decision batch: {e}"))
    }
}

/// A hole or a break found in a sandbox's run of batches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Discontinuity {
    /// Decisions are missing between two batches.
    SequenceGap { at: usize, expected: u64, found: u64 },
    /// A batch does not name the one before it: one was removed or replaced.
    BrokenLink { at: usize },
    /// A batch names a different sandbox, agent or policy than the first.
    Mixed { at: usize },
}

/// What a walk over one sandbox's batches, in chain order, found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Continuity {
    pub batches: usize,
    pub decisions: u64,
    pub denied: u64,
    /// Sum of the `source_gaps` the batches declare.
    pub declared_source_gaps: u64,
    pub discontinuities: Vec<Discontinuity>,
}

impl Continuity {
    /// True when nothing is missing and nothing was declared lost.
    pub fn complete(&self) -> bool {
        self.discontinuities.is_empty() && self.declared_source_gaps == 0
    }
}

/// Check that `batches` (one sandbox, in chain order) cover a dense range and
/// link to each other. Signatures are checked by the caller, which holds the
/// key; this checks only the commitment structure.
pub fn verify_continuity(batches: &[DecisionBatch]) -> Continuity {
    let mut c = Continuity::default();
    let mut next = 0u64;
    let mut prev = ZERO.to_string();
    for (i, b) in batches.iter().enumerate() {
        c.batches += 1;
        c.decisions += b.count;
        c.denied += b.denied;
        c.declared_source_gaps += b.source_gaps;
        if let Some(f) = batches.first() {
            if b.sandbox != f.sandbox || b.agent != f.agent {
                c.discontinuities.push(Discontinuity::Mixed { at: i });
            }
        }
        if b.first_seq != next {
            c.discontinuities.push(Discontinuity::SequenceGap { at: i, expected: next, found: b.first_seq });
        }
        if b.prev != prev {
            c.discontinuities.push(Discontinuity::BrokenLink { at: i });
        }
        next = b.first_seq + b.count;
        prev = b.hash();
    }
    c
}

/// The record for a sandbox torn down by a verified kill order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKilledRecord {
    pub v: u32,
    pub agent: String,
    pub runtime: String,
    pub sandbox: String,
    pub policy_sha256: String,
    /// SHA-256 of the order as received.
    pub order_sha256: String,
    pub scope: String,
    pub mode: String,
    /// Milliseconds from the order being accepted to the sandbox confirmed gone.
    pub latency_ms: u64,
    /// `gone`, or `failed: <why>`.
    pub outcome: String,
}

impl AgentKilledRecord {
    pub fn to_result(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_result(s: &str) -> Result<AgentKilledRecord, String> {
        serde_json::from_str(s).map_err(|e| format!("not an agent-killed record: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(seq: u64, a: Action) -> Decision {
        Decision { seq, source_seq: None, time_ms: seq, kind: "network".into(), action: a, subject: "h:443".into(), rule: None, raw_sha256: "00".into() }
    }

    fn batch(first: u64, n: u64, prev: Option<&str>) -> DecisionBatch {
        let ds: Vec<Decision> = (first..first + n).map(|s| d(s, if s % 2 == 0 { Action::Allowed } else { Action::Denied })).collect();
        DecisionBatch::commit("a", "rt", "sb", "pol", first, &ds, 0, prev, None)
    }

    #[test]
    fn consecutive_linked_batches_are_complete() {
        let b1 = batch(0, 3, None);
        let b2 = batch(3, 2, Some(&b1.hash()));
        let c = verify_continuity(&[b1, b2]);
        assert!(c.complete(), "{c:?}");
        assert_eq!((c.decisions, c.denied), (5, 2));
    }

    #[test]
    fn a_removed_batch_is_a_gap_and_a_broken_link() {
        let b1 = batch(0, 3, None);
        let b2 = batch(3, 2, Some(&b1.hash()));
        let b3 = batch(5, 1, Some(&b2.hash()));
        let c = verify_continuity(&[b1, b3]);
        assert!(c.discontinuities.contains(&Discontinuity::SequenceGap { at: 1, expected: 3, found: 5 }));
        assert!(c.discontinuities.contains(&Discontinuity::BrokenLink { at: 1 }));
    }

    #[test]
    fn declared_source_gaps_make_a_run_incomplete() {
        let mut b = batch(0, 1, None);
        b.source_gaps = 4;
        assert!(!verify_continuity(&[b]).complete());
    }

    #[test]
    fn a_changed_field_changes_the_signed_bytes() {
        let b = batch(0, 2, None);
        let mut t = b.clone();
        t.count = 1;
        assert_ne!(b.signing_bytes(), t.signing_bytes());
    }

    #[test]
    fn results_round_trip() {
        let b = batch(0, 2, None);
        assert_eq!(DecisionBatch::from_result(&b.to_result()).unwrap(), b);
    }
}
