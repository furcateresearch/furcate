//! The failure-domain hierarchy.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Levels of the hierarchy, ordered from broadest to narrowest.
///
/// Ordering matters: spreading across a broader domain implies spreading
/// across every narrower one, which lets a request for `Ups` isolation be
/// satisfied only by placements that are also on different chassis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainKind {
    Site,
    /// A distribution circuit, typically a breaker.
    Feed,
    /// An uninterruptible supply. Distinct from `Feed`: one circuit may carry
    /// several supplies, and a supply failure is far more likely.
    Ups,
    Rack,
    Chassis,
    Node,
    /// A device attached to a node — a disk, an accelerator, a sensor.
    Device,
}

impl DomainKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainKind::Site => "site",
            DomainKind::Feed => "feed",
            DomainKind::Ups => "ups",
            DomainKind::Rack => "rack",
            DomainKind::Chassis => "chassis",
            DomainKind::Node => "node",
            DomainKind::Device => "device",
        }
    }
}

/// How a fact entered the tree.
///
/// A placement engine should know when it is trusting a human. Declared facts
/// are accepted but marked, so an operator can see which parts of their blast
/// radius rest on someone having typed the truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    /// Learned from the hardware or the network, e.g. LLDP or a switched PDU.
    Discovered,
    /// Supplied by an operator and unverifiable by Furcate.
    Declared,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub kind: DomainKind,
    pub parent: Option<String>,
    pub provenance: Provenance,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// The site's failure-domain tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainTree {
    nodes: BTreeMap<String, Node>,
}

impl DomainTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a domain entry.
    pub fn insert(
        &mut self,
        id: impl Into<String>,
        kind: DomainKind,
        parent: Option<&str>,
        provenance: Provenance,
    ) -> &mut Self {
        let id = id.into();
        self.nodes.insert(
            id.clone(),
            Node {
                id,
                kind,
                parent: parent.map(str::to_string),
                provenance,
                labels: BTreeMap::new(),
            },
        );
        self
    }

    pub fn get(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every entry, in id order.
    ///
    /// Needed by anything that has to say something about each domain rather
    /// than about one kind of domain — capacity, for instance, which is a
    /// property of breakers, supplies and racks alike.
    pub fn every(&self) -> Vec<&Node> {
        self.nodes.values().collect()
    }

    /// All entries of a given kind.
    pub fn of_kind(&self, kind: DomainKind) -> Vec<&Node> {
        self.nodes.values().filter(|n| n.kind == kind).collect()
    }

    /// Every compute node in the tree.
    pub fn compute_nodes(&self) -> Vec<&Node> {
        self.of_kind(DomainKind::Node)
    }

    /// Walk from an entry up to the site root.
    pub fn ancestors(&self, id: &str) -> Vec<&Node> {
        let mut out = Vec::new();
        let mut cursor = self.nodes.get(id).and_then(|n| n.parent.as_deref());
        // Bounded by tree size so a cycle introduced by bad configuration
        // cannot hang the caller.
        let mut budget = self.nodes.len() + 1;
        while let Some(pid) = cursor {
            if budget == 0 {
                break;
            }
            budget -= 1;
            match self.nodes.get(pid) {
                Some(p) => {
                    out.push(p);
                    cursor = p.parent.as_deref();
                }
                None => break,
            }
        }
        out
    }

    /// Which domain of `kind` an entry belongs to, if any.
    ///
    /// This is the primitive placement rests on: two nodes are isolated at a
    /// level exactly when this returns different answers for them.
    pub fn domain_of(&self, id: &str, kind: DomainKind) -> Option<&str> {
        if let Some(n) = self.nodes.get(id) {
            if n.kind == kind {
                return Some(&n.id);
            }
        }
        self.ancestors(id)
            .into_iter()
            .find(|a| a.kind == kind)
            .map(|a| a.id.as_str())
    }

    /// Whether the tree contains any entry whose provenance is declared.
    pub fn has_declared_facts(&self) -> bool {
        self.nodes
            .values()
            .any(|n| n.provenance == Provenance::Declared)
    }

    /// How many distinct domains of `kind` the given members span.
    pub fn distinct_domains(&self, members: &[&str], kind: DomainKind) -> usize {
        let mut seen = std::collections::BTreeSet::new();
        for m in members {
            match self.domain_of(m, kind) {
                Some(d) => {
                    seen.insert(d.to_string());
                }
                // A member with no such ancestor is its own domain: unknown
                // placement must never be counted as shared isolation.
                None => {
                    seen.insert(format!("__unplaced::{m}"));
                }
            }
        }
        seen.len()
    }

    /// Render the tree for display, deepest-last within each parent.
    pub fn render(&self) -> String {
        fn walk(t: &DomainTree, parent: Option<&str>, depth: usize, out: &mut String) {
            let mut children: Vec<&Node> = t
                .nodes
                .values()
                .filter(|n| n.parent.as_deref() == parent)
                .collect();
            children.sort_by_key(|n| (n.kind, n.id.clone()));
            for c in children {
                let mark = match c.provenance {
                    Provenance::Discovered => "",
                    Provenance::Declared => "  (declared)",
                };
                out.push_str(&format!(
                    "{}{}: {}{}\n",
                    "  ".repeat(depth),
                    c.kind.as_str(),
                    c.id,
                    mark
                ));
                walk(t, Some(&c.id), depth + 1, out);
            }
        }
        let mut out = String::new();
        walk(self, None, 0, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first site: two machines, one rack, one UPS, one breaker.
    pub(crate) fn first_site() -> DomainTree {
        let mut t = DomainTree::new();
        t.insert("home-1", DomainKind::Site, None, Provenance::Declared)
            .insert("circuit-a", DomainKind::Feed, Some("home-1"), Provenance::Declared)
            .insert("ups-1", DomainKind::Ups, Some("circuit-a"), Provenance::Declared)
            .insert("rack-1", DomainKind::Rack, Some("ups-1"), Provenance::Declared)
            .insert("node-a", DomainKind::Node, Some("rack-1"), Provenance::Discovered)
            .insert("node-b", DomainKind::Node, Some("rack-1"), Provenance::Discovered);
        t
    }

    #[test]
    fn domains_are_ordered_broad_to_narrow() {
        assert!(DomainKind::Site < DomainKind::Ups);
        assert!(DomainKind::Ups < DomainKind::Node);
    }

    #[test]
    fn ancestors_reach_the_root() {
        let t = first_site();
        let ids: Vec<&str> = t.ancestors("node-a").iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["rack-1", "ups-1", "circuit-a", "home-1"]);
    }

    #[test]
    fn both_machines_share_every_power_domain() {
        let t = first_site();
        assert_eq!(t.domain_of("node-a", DomainKind::Ups), Some("ups-1"));
        assert_eq!(t.domain_of("node-b", DomainKind::Ups), Some("ups-1"));
        assert_eq!(t.distinct_domains(&["node-a", "node-b"], DomainKind::Ups), 1);
    }

    #[test]
    fn distinct_nodes_are_still_distinct_at_node_level() {
        let t = first_site();
        assert_eq!(t.distinct_domains(&["node-a", "node-b"], DomainKind::Node), 2);
    }

    #[test]
    fn an_unplaced_member_is_never_counted_as_shared() {
        let t = first_site();
        // A node with no UPS ancestor must not be treated as sharing one.
        let mut t2 = t.clone();
        t2.insert("orphan", DomainKind::Node, None, Provenance::Declared);
        assert_eq!(
            t2.distinct_domains(&["node-a", "orphan"], DomainKind::Ups),
            2
        );
    }

    #[test]
    fn declared_facts_are_visible() {
        assert!(first_site().has_declared_facts());
    }

    #[test]
    fn a_cycle_does_not_hang() {
        let mut t = DomainTree::new();
        t.insert("a", DomainKind::Rack, Some("b"), Provenance::Declared)
            .insert("b", DomainKind::Rack, Some("a"), Provenance::Declared);
        // Bounded walk: returns something finite rather than looping.
        assert!(t.ancestors("a").len() <= t.len() + 1);
    }

    #[test]
    fn render_shows_the_hierarchy() {
        let out = first_site().render();
        assert!(out.contains("site: home-1"));
        assert!(out.contains("node: node-a"));
        assert!(out.contains("(declared)"));
    }
}
