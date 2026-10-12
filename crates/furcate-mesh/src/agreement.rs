//! What a set of receipts for the same request actually establishes.
//!
//! [`VerificationLevel::Redundant`] is the one level in [`crate::receipt`] that
//! claims something about the *computation* without needing special silicon,
//! and until now nothing in this codebase produced it. It was a field anyone
//! constructing a receipt could fill in, which means a node could assert that
//! five independent nodes agreed with it without any comparison having taken
//! place — the strongest claim available and the easiest to forge.
//!
//! This module is where that level comes from instead: it is derived from
//! receipts that were actually compared, never asserted.
//!
//! ## What has to be true before outputs can be compared at all
//!
//! Three guards, and each closes a way of manufacturing agreement:
//!
//! - **Same question.** Receipts for different inputs, models, runtimes or
//!   parameters are not replicas of anything. Comparing them yields
//!   disagreement between honest nodes and agreement between dishonest ones.
//! - **Distinct nodes.** Two receipts from one node are one opinion. Counting
//!   them as two is how a single machine votes itself into a majority.
//! - **A real majority.** Half is not a majority. See
//!   [`crate::corruption`], which is careful about this because
//!   getting it wrong condemns healthy machines.
//!
//! ## Disagreement here is weaker evidence than it looks
//!
//! [`crate::receipt`] states the constraint this module has to respect: an
//! accelerator result generally cannot be reproduced bit-exactly even by an
//! honest node, because floating-point reduction order and batching are not
//! deterministic. So a disagreement between two honest nodes is entirely
//! ordinary, and "recompute and compare" is not a general correctness check.
//!
//! The consequence is that a failed comparison never lowers a node's standing
//! here. It withholds a claim — the receipt stays [`VerificationLevel::Bound`],
//! which is exactly what it was worth. Deciding a node is actually lying takes
//! a pattern across unrelated work, which is what
//! [`crate::corruption::Ledger`] accumulates and what this module
//! deliberately does not attempt from a single request.

use crate::receipt::{InferenceReceipt, VerificationLevel};
use crate::corruption::{compare, Finding, Replica};
use serde::{Deserialize, Serialize};

/// Why a set of receipts could not be compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotComparable {
    /// Fewer than two receipts.
    TooFew,
    /// The receipts do not answer the same question.
    DifferentRequests,
    /// The receipts came from fewer than two distinct nodes.
    OneOpinion,
}

/// What comparing a set of receipts established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agreement {
    /// The comparison happened and this is what it found.
    Compared {
        finding: Finding,
        /// Distinct nodes that took part.
        nodes: usize,
    },
    /// No comparison was possible, so nothing is claimed.
    Skipped(NotComparable),
}

impl Agreement {
    /// The verification level these receipts have earned.
    ///
    /// Only a real majority across distinct nodes earns
    /// [`VerificationLevel::Redundant`], and `agreeing_nodes` is the size of
    /// that majority rather than the number of receipts — a minority that
    /// disagreed is not evidence for the answer it disagreed with.
    ///
    /// Everything else is [`VerificationLevel::Bound`]: provenance, and no
    /// claim about the computation. That includes outright disagreement, for
    /// the reason in the module header — between honest accelerators it is
    /// ordinary, and treating it as an accusation would be wrong far more
    /// often than right.
    pub fn level(&self) -> VerificationLevel {
        match self {
            Agreement::Compared {
                finding: Finding::Agreed { replicas },
                ..
            } => VerificationLevel::Redundant {
                agreeing_nodes: (*replicas).min(u8::MAX as usize) as u8,
            },
            Agreement::Compared {
                finding: Finding::Outlier { majority, .. },
                ..
            } => VerificationLevel::Redundant {
                agreeing_nodes: (*majority).min(u8::MAX as usize) as u8,
            },
            _ => VerificationLevel::Bound,
        }
    }

    /// Nodes whose output was outside the majority, if there was one.
    ///
    /// Reported so a caller can feed a corruption ledger, and named as
    /// *disagreed* rather than *wrong*. One dissent from an accelerator is not
    /// evidence of a fault; a pattern of them across unrelated requests is, and
    /// that judgement belongs to the ledger.
    pub fn dissenters(&self) -> &[String] {
        match self {
            Agreement::Compared { finding, .. } => finding.suspects(),
            Agreement::Skipped(_) => &[],
        }
    }
}

/// Compare receipts that claim to answer the same request.
pub fn assess(receipts: &[InferenceReceipt]) -> Agreement {
    if receipts.len() < 2 {
        return Agreement::Skipped(NotComparable::TooFew);
    }

    // Same question. Comparing outputs computed from different inputs, models,
    // runtimes or parameters produces disagreement between honest nodes and
    // agreement between dishonest ones, so this is checked before anything else.
    let first = &receipts[0];
    let same_question = receipts.iter().all(|r| {
        r.input_digest == first.input_digest
            && r.model_digest == first.model_digest
            && r.runtime_digest == first.runtime_digest
            && r.params == first.params
    });
    if !same_question {
        return Agreement::Skipped(NotComparable::DifferentRequests);
    }

    // One opinion per node. Two receipts from one machine are not independent,
    // and counting them separately is how a single node votes itself into a
    // majority. The first receipt from each node is the one kept.
    let mut replicas: Vec<Replica> = Vec::new();
    for r in receipts {
        if replicas.iter().any(|e| e.participant == r.node_id) {
            continue;
        }
        replicas.push(Replica::new(&r.node_id, &r.output_digest));
    }
    if replicas.len() < 2 {
        return Agreement::Skipped(NotComparable::OneOpinion);
    }

    Agreement::Compared {
        finding: compare(&replicas),
        nodes: replicas.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(node: &str, output: &str) -> InferenceReceipt {
        InferenceReceipt {
            model_digest: "model".into(),
            runtime_digest: "runtime".into(),
            node_id: node.into(),
            input_digest: "input".into(),
            output_digest: output.into(),
            params: "t=0".into(),
            chain_head: "head".into(),
            level: VerificationLevel::Bound,
            signature: None,
        }
    }

    #[test]
    fn independent_nodes_that_agree_earn_the_redundant_level() {
        let a = assess(&[
            receipt("n1", "out"),
            receipt("n2", "out"),
            receipt("n3", "out"),
        ]);
        assert_eq!(
            a.level(),
            VerificationLevel::Redundant { agreeing_nodes: 3 }
        );
        assert!(a.level().covers_computation());
        assert!(a.dissenters().is_empty());
    }

    #[test]
    fn the_count_is_the_majority_not_the_number_of_receipts() {
        // A node that disagreed is not evidence for the answer it disagreed
        // with, and folding it into the count would overstate the guarantee.
        let a = assess(&[
            receipt("n1", "out"),
            receipt("n2", "out"),
            receipt("n3", "different"),
        ]);
        assert_eq!(
            a.level(),
            VerificationLevel::Redundant { agreeing_nodes: 2 }
        );
        assert_eq!(a.dissenters(), ["n3".to_string()]);
    }

    #[test]
    fn one_node_cannot_vote_itself_into_a_majority() {
        // Three receipts, one machine. Not three opinions.
        let a = assess(&[
            receipt("n1", "out"),
            receipt("n1", "out"),
            receipt("n1", "out"),
        ]);
        assert_eq!(a, Agreement::Skipped(NotComparable::OneOpinion));
        assert_eq!(a.level(), VerificationLevel::Bound);
        assert!(!a.level().covers_computation());
    }

    #[test]
    fn receipts_for_different_questions_are_not_replicas() {
        let mut other = receipt("n2", "out");
        other.input_digest = "a different input".into();
        let a = assess(&[receipt("n1", "out"), other]);
        assert_eq!(a, Agreement::Skipped(NotComparable::DifferentRequests));
        assert_eq!(a.level(), VerificationLevel::Bound);
    }

    #[test]
    fn the_same_input_to_a_different_model_is_a_different_question() {
        let mut other = receipt("n2", "out");
        other.model_digest = "another model".into();
        assert_eq!(
            assess(&[receipt("n1", "out"), other]),
            Agreement::Skipped(NotComparable::DifferentRequests)
        );

        // As are different parameters, which is the easy one to forget: the
        // same prompt at a different temperature is a different question and
        // two honest nodes would rightly disagree about it.
        let mut params = receipt("n2", "out");
        params.params = "t=0.7".into();
        assert_eq!(
            assess(&[receipt("n1", "out"), params]),
            Agreement::Skipped(NotComparable::DifferentRequests)
        );
    }

    #[test]
    fn two_nodes_disagreeing_claims_nothing_rather_than_accusing_either() {
        // An accelerator result is not bit-reproducible even between honest
        // nodes, so this is an ordinary event. It withholds the stronger claim
        // and leaves the receipt worth exactly what it was worth.
        let a = assess(&[receipt("n1", "out"), receipt("n2", "different")]);
        match &a {
            Agreement::Compared { finding, nodes } => {
                assert_eq!(*nodes, 2);
                assert!(!finding.accuses_anyone());
            }
            other => panic!("expected a comparison, got {other:?}"),
        }
        assert_eq!(a.level(), VerificationLevel::Bound);
        assert!(a.dissenters().is_empty(), "two nodes cannot attribute");
    }

    #[test]
    fn an_even_split_earns_nothing() {
        let a = assess(&[
            receipt("n1", "x"),
            receipt("n2", "x"),
            receipt("n3", "y"),
            receipt("n4", "y"),
        ]);
        assert_eq!(a.level(), VerificationLevel::Bound, "half is not a majority");
        assert!(a.dissenters().is_empty());
    }

    #[test]
    fn a_single_receipt_is_not_redundant_execution() {
        let a = assess(&[receipt("n1", "out")]);
        assert_eq!(a, Agreement::Skipped(NotComparable::TooFew));
        assert_eq!(a.level(), VerificationLevel::Bound);
        assert_eq!(assess(&[]).level(), VerificationLevel::Bound);
    }
}
