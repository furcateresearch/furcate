//! Placement rules evaluated over the failure-domain tree.
//!
//! Consumers do not ask for hosts, they ask for isolation: *three replicas,
//! spread across `ups`*. On a single-rack site that request correctly fails,
//! and failing loudly is the point — it is a true statement about a site where
//! both machines die together.

use crate::tree::{DomainKind, DomainTree};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementRequest {
    /// How many distinct placements are needed.
    pub replicas: usize,
    /// The level replicas must not share.
    pub spread_across: DomainKind,
    /// Candidate nodes, normally the healthy admitted set.
    pub candidates: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementResult {
    pub selected: Vec<String>,
    /// Distinct domains the selection spans at the requested level.
    pub achieved_domains: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlacementError {
    /// Fewer candidates than replicas requested.
    NotEnoughCandidates { requested: usize, available: usize },
    /// Candidates exist but cannot be spread far enough apart.
    InsufficientIsolation {
        requested: usize,
        spread_across: DomainKind,
        available_domains: usize,
    },
    /// A replica count of zero is a caller bug rather than a placement.
    ZeroReplicas,
}

impl fmt::Display for PlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlacementError::ZeroReplicas => write!(f, "replica count must be at least one"),
            PlacementError::NotEnoughCandidates {
                requested,
                available,
            } => write!(
                f,
                "{requested} replicas requested but only {available} candidates offered"
            ),
            PlacementError::InsufficientIsolation {
                requested,
                spread_across,
                available_domains,
            } => write!(
                f,
                "cannot place {requested} replicas across distinct `{}` domains: \
                 the candidates span only {available_domains}. Placing them anyway would \
                 report redundancy this site does not physically have",
                spread_across.as_str()
            ),
        }
    }
}

impl std::error::Error for PlacementError {}

/// Select placements satisfying the isolation the caller asked for.
///
/// The algorithm is a deliberate round-robin over domains rather than a greedy
/// fill: taking candidates in order would happily put two replicas in one
/// domain while another sat empty.
pub fn place(tree: &DomainTree, req: &PlacementRequest) -> Result<PlacementResult, PlacementError> {
    if req.replicas == 0 {
        return Err(PlacementError::ZeroReplicas);
    }
    if req.candidates.len() < req.replicas {
        return Err(PlacementError::NotEnoughCandidates {
            requested: req.replicas,
            available: req.candidates.len(),
        });
    }

    // Bucket candidates by the domain they belong to at the requested level.
    let mut buckets: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for c in &req.candidates {
        let key = tree
            .domain_of(c, req.spread_across)
            .map(str::to_string)
            .unwrap_or_else(|| format!("__unplaced::{c}"));
        buckets.entry(key).or_default().push(c.clone());
    }

    if buckets.len() < req.replicas {
        return Err(PlacementError::InsufficientIsolation {
            requested: req.replicas,
            spread_across: req.spread_across,
            available_domains: buckets.len(),
        });
    }

    // One from each distinct domain, in stable order.
    let mut selected = Vec::with_capacity(req.replicas);
    for members in buckets.values() {
        if selected.len() == req.replicas {
            break;
        }
        if let Some(first) = members.first() {
            selected.push(first.clone());
        }
    }

    let refs: Vec<&str> = selected.iter().map(String::as_str).collect();
    let achieved = tree.distinct_domains(&refs, req.spread_across);
    Ok(PlacementResult {
        selected,
        achieved_domains: achieved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Provenance;

    fn two_node_one_ups() -> DomainTree {
        let mut t = DomainTree::new();
        t.insert("home-1", DomainKind::Site, None, Provenance::Declared)
            .insert("circuit-a", DomainKind::Feed, Some("home-1"), Provenance::Declared)
            .insert("ups-1", DomainKind::Ups, Some("circuit-a"), Provenance::Declared)
            .insert("rack-1", DomainKind::Rack, Some("ups-1"), Provenance::Declared)
            .insert("node-a", DomainKind::Node, Some("rack-1"), Provenance::Discovered)
            .insert("node-b", DomainKind::Node, Some("rack-1"), Provenance::Discovered);
        t
    }

    fn two_ups() -> DomainTree {
        let mut t = two_node_one_ups();
        t.insert("circuit-b", DomainKind::Feed, Some("home-1"), Provenance::Declared)
            .insert("ups-2", DomainKind::Ups, Some("circuit-b"), Provenance::Declared)
            .insert("rack-2", DomainKind::Rack, Some("ups-2"), Provenance::Declared)
            .insert("node-b", DomainKind::Node, Some("rack-2"), Provenance::Discovered);
        t
    }

    #[test]
    fn spreading_across_nodes_succeeds_on_the_first_site() {
        let t = two_node_one_ups();
        let r = place(
            &t,
            &PlacementRequest {
                replicas: 2,
                spread_across: DomainKind::Node,
                candidates: vec!["node-a".into(), "node-b".into()],
            },
        )
        .unwrap();
        assert_eq!(r.selected.len(), 2);
        assert_eq!(r.achieved_domains, 2);
    }

    #[test]
    fn spreading_across_power_correctly_fails_on_one_ups() {
        // This is the finding that matters: RF=2 across these two machines is
        // RF=1 as far as a power event is concerned.
        let t = two_node_one_ups();
        let err = place(
            &t,
            &PlacementRequest {
                replicas: 2,
                spread_across: DomainKind::Ups,
                candidates: vec!["node-a".into(), "node-b".into()],
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            PlacementError::InsufficientIsolation {
                requested: 2,
                spread_across: DomainKind::Ups,
                available_domains: 1
            }
        );
    }

    #[test]
    fn a_second_supply_makes_it_placeable() {
        let t = two_ups();
        let r = place(
            &t,
            &PlacementRequest {
                replicas: 2,
                spread_across: DomainKind::Ups,
                candidates: vec!["node-a".into(), "node-b".into()],
            },
        )
        .unwrap();
        assert_eq!(r.achieved_domains, 2);
    }

    #[test]
    fn selection_prefers_distinct_domains_over_candidate_order() {
        // node-a and node-a2 share a UPS; a greedy fill would take both.
        let mut t = two_ups();
        t.insert("node-a2", DomainKind::Node, Some("rack-1"), Provenance::Discovered);
        let r = place(
            &t,
            &PlacementRequest {
                replicas: 2,
                spread_across: DomainKind::Ups,
                candidates: vec!["node-a".into(), "node-a2".into(), "node-b".into()],
            },
        )
        .unwrap();
        assert_eq!(r.achieved_domains, 2);
        assert!(r.selected.contains(&"node-b".to_string()));
    }

    #[test]
    fn too_few_candidates_is_distinguished_from_too_little_isolation() {
        let t = two_node_one_ups();
        let err = place(
            &t,
            &PlacementRequest {
                replicas: 3,
                spread_across: DomainKind::Node,
                candidates: vec!["node-a".into(), "node-b".into()],
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            PlacementError::NotEnoughCandidates {
                requested: 3,
                available: 2
            }
        );
    }

    #[test]
    fn zero_replicas_is_a_caller_error() {
        let t = two_node_one_ups();
        assert_eq!(
            place(
                &t,
                &PlacementRequest {
                    replicas: 0,
                    spread_across: DomainKind::Node,
                    candidates: vec!["node-a".into()],
                }
            )
            .unwrap_err(),
            PlacementError::ZeroReplicas
        );
    }

    #[test]
    fn the_error_explains_the_physical_reality() {
        let t = two_node_one_ups();
        let err = place(
            &t,
            &PlacementRequest {
                replicas: 2,
                spread_across: DomainKind::Ups,
                candidates: vec!["node-a".into(), "node-b".into()],
            },
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ups"));
        assert!(msg.contains("does not physically have"));
    }
}
