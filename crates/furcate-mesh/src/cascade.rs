//! Cross-tier cascades.
//!
//! The most natural use of an uneven cluster is not splitting one model, it is
//! chaining several. A small model answers easy requests; hard ones are
//! deferred to a stronger one. Mapped onto tiers that is a cluster-shaped
//! algorithm: the constrained node drafts, the accelerated node verifies, and
//! most requests never touch the GPU.
//!
//! The distinction that matters over a LAN is granularity. Token-level
//! speculation is latency-sensitive and belongs within a node or across a fast
//! link. Response-level cascades — draft a whole answer, then accept, improve
//! or skip — tolerate LAN latency comfortably and are the right default across
//! machines.

use crate::capability::Tier;
use furcate_topology::PathPreference;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    /// Draft tokens verified in parallel by the target model. Needs a fast
    /// link; degrades badly over an ordinary network.
    Token,
    /// Draft a whole response, then judge whether to accept it.
    Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CascadeStage {
    pub model: String,
    pub node: String,
    pub tier: Tier,
    /// Confidence at or above which this stage's answer is accepted without
    /// escalating.
    pub accept_threshold_pct: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CascadePlan {
    pub stages: Vec<CascadeStage>,
    pub granularity: Granularity,
}

impl CascadePlan {
    /// Build a plan from stages ordered weakest to strongest.
    ///
    /// Granularity is chosen from the worst link the plan has to cross: if any
    /// hop leaves the machine over anything but a fast local path, token-level
    /// speculation is not viable and the plan falls back to response level.
    pub fn build(stages: Vec<CascadeStage>, worst_path: PathPreference) -> Option<Self> {
        if stages.is_empty() {
            return None;
        }
        // Stages must ascend in capability, or the cascade is not a cascade.
        if stages.windows(2).any(|w| w[1].tier < w[0].tier) {
            return None;
        }
        let granularity = match worst_path {
            PathPreference::Loopback => Granularity::Token,
            _ => Granularity::Response,
        };
        Some(Self {
            stages,
            granularity,
        })
    }

    /// Which stage should answer, given the confidence each produced.
    ///
    /// Returns the first stage whose confidence met its threshold, or the last
    /// stage if none did — the strongest model is the fallback, not a failure.
    pub fn resolve(&self, confidences: &[u8]) -> &CascadeStage {
        for (stage, conf) in self.stages.iter().zip(confidences) {
            if *conf >= stage.accept_threshold_pct {
                return stage;
            }
        }
        self.stages.last().expect("non-empty by construction")
    }

    /// How many stages were consulted before one answered.
    pub fn stages_used(&self, confidences: &[u8]) -> usize {
        for (i, (stage, conf)) in self.stages.iter().zip(confidences).enumerate() {
            if *conf >= stage.accept_threshold_pct {
                return i + 1;
            }
        }
        self.stages.len()
    }

    /// Fraction of requests expected to stop before the strongest stage.
    pub fn escalation_avoided(&self, sample: &[Vec<u8>]) -> f64 {
        if sample.is_empty() {
            return 0.0;
        }
        let avoided = sample
            .iter()
            .filter(|c| self.stages_used(c) < self.stages.len())
            .count();
        avoided as f64 / sample.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(model: &str, node: &str, tier: Tier, threshold: u8) -> CascadeStage {
        CascadeStage {
            model: model.into(),
            node: node.into(),
            tier,
            accept_threshold_pct: threshold,
        }
    }

    fn plan(path: PathPreference) -> CascadePlan {
        CascadePlan::build(
            vec![
                stage("small", "pi", Tier::Constrained, 80),
                stage("large", "jetson", Tier::Accelerated, 0),
            ],
            path,
        )
        .unwrap()
    }

    #[test]
    fn a_confident_draft_is_accepted_without_the_gpu() {
        let p = plan(PathPreference::LocalLan);
        assert_eq!(p.resolve(&[95, 0]).node, "pi");
        assert_eq!(p.stages_used(&[95, 0]), 1);
    }

    #[test]
    fn an_unconfident_draft_escalates() {
        let p = plan(PathPreference::LocalLan);
        assert_eq!(p.resolve(&[40, 99]).node, "jetson");
        assert_eq!(p.stages_used(&[40, 99]), 2);
    }

    #[test]
    fn the_strongest_stage_is_the_fallback_not_a_failure() {
        let p = plan(PathPreference::LocalLan);
        // Nothing met its threshold; the final stage still answers.
        assert_eq!(p.resolve(&[10, 0]).model, "large");
    }

    #[test]
    fn crossing_a_network_forces_response_level_granularity() {
        assert_eq!(plan(PathPreference::LocalLan).granularity, Granularity::Response);
        assert_eq!(plan(PathPreference::Overlay).granularity, Granularity::Response);
    }

    #[test]
    fn staying_on_one_machine_allows_token_level() {
        assert_eq!(plan(PathPreference::Loopback).granularity, Granularity::Token);
    }

    #[test]
    fn stages_must_ascend_in_capability() {
        let backwards = CascadePlan::build(
            vec![
                stage("large", "jetson", Tier::Accelerated, 80),
                stage("small", "pi", Tier::Constrained, 0),
            ],
            PathPreference::LocalLan,
        );
        assert!(backwards.is_none());
    }

    #[test]
    fn an_empty_plan_is_rejected() {
        assert!(CascadePlan::build(vec![], PathPreference::Loopback).is_none());
    }

    #[test]
    fn most_requests_avoiding_the_gpu_is_measurable() {
        let p = plan(PathPreference::LocalLan);
        let sample = vec![vec![95, 0], vec![90, 0], vec![30, 0], vec![85, 0]];
        assert_eq!(p.escalation_avoided(&sample), 0.75);
    }

    #[test]
    fn an_empty_sample_reports_zero_rather_than_dividing_by_zero() {
        assert_eq!(plan(PathPreference::Loopback).escalation_avoided(&[]), 0.0);
    }
}
