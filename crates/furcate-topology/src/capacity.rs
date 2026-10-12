//! How much more this circuit can take.
//!
//! The failure-domain tree has always known that a breaker feeds a supply which
//! feeds a rack which holds a node. It carried an id, a kind, a parent and a
//! provenance for each of those, and no watts anywhere — so it could answer
//! "what else dies when this dies" and not "can I plug another machine in".
//!
//! The second question is the one that decides operations. Every account of
//! running large fleets converges on the same structure: a capacity at each
//! level of the power delivery hierarchy, live draw aggregated up the same
//! tree, and headroom as the difference. The finding that makes it worth
//! building is that headroom is never evenly distributed — in a published
//! survey of a 100 MW cluster, over half the switchboards held comfortable
//! margin while an eighth ran with almost none. A site average would have
//! shown a fleet with room to spare.
//!
//! The arithmetic is trivial. What makes it possible at all is that node draw
//! is now *measured* at the chassis rather than scaled from package power by a
//! constant — a headroom figure built on a guessed multiplier would be a guess
//! about whether a breaker trips.
//!
//! ## Capacity is declared, and says so
//!
//! Nothing here discovers a breaker rating. It is stamped on the breaker, and
//! somebody has to type it in. That makes every headroom figure exactly as
//! trustworthy as the number an operator entered, which is why capacity carries
//! the tree's existing `Provenance` and why a domain with no declared capacity
//! reports `None` rather than assuming anything. An unknown limit is not a
//! large one.
//!
//! ## Why de-rating is applied here and not left to the operator
//!
//! Continuous load on a circuit is conventionally held below its rating, and
//! peaks do not coincide across machines. Both adjustments are applied to the
//! *usable* figure rather than asking an operator to pre-de-rate the number
//! they read off the panel — because a system that silently expects a
//! pre-adjusted input will eventually be given a raw one.

use crate::tree::{DomainKind, DomainTree, Provenance};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The rated capacity of one domain, as somebody declared it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Capacity {
    /// Nameplate rating in watts.
    pub rated_w: f64,
    /// How this figure entered the system. Always `Declared` in practice: a
    /// breaker does not announce itself over the network.
    pub provenance: Provenance,
}

impl Capacity {
    /// Fraction of nameplate treated as usable continuously.
    ///
    /// Protection devices are sized for continuous load below their rating,
    /// and a circuit run at its nameplate figure for hours is a circuit being
    /// operated at its trip point rather than below it.
    pub const CONTINUOUS_FRACTION: f64 = 0.8;

    pub fn declared(rated_w: f64) -> Self {
        Self { rated_w, provenance: Provenance::Declared }
    }

    /// What may actually be drawn continuously.
    pub fn usable_w(&self) -> f64 {
        self.rated_w * Self::CONTINUOUS_FRACTION
    }
}

/// What is known about one domain's electrical position.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Headroom {
    pub domain: String,
    pub kind: DomainKind,
    /// Measured draw of everything beneath this domain.
    pub draw_w: f64,
    /// How many nodes under this domain contributed a measurement.
    pub measured_nodes: usize,
    /// How many contributed nothing, so a reader can see whether the draw
    /// figure covers the domain or only part of it.
    pub unmeasured_nodes: usize,
    /// Declared rating, where one exists.
    pub rated_w: Option<f64>,
    /// Rating after continuous de-rating.
    pub usable_w: Option<f64>,
    /// Usable less draw. `None` when no capacity was declared — an unknown
    /// limit is not a large one, and reporting infinite headroom would be the
    /// most dangerous possible default.
    pub headroom_w: Option<f64>,
}

impl Headroom {
    /// Fraction of usable capacity in use.
    pub fn utilisation(&self) -> Option<f64> {
        let u = self.usable_w?;
        (u > 0.0).then(|| self.draw_w / u)
    }

    /// Whether the draw figure covers everything under this domain.
    ///
    /// A headroom figure computed from half the machines is not a headroom
    /// figure; it is an underestimate of load wearing the name of one.
    pub fn is_complete(&self) -> bool {
        self.unmeasured_nodes == 0
    }

    /// Whether this domain should be refused more load.
    ///
    /// Refuses on incomplete measurement as well as on genuine exhaustion.
    /// Adding a machine to a circuit whose current draw is partly unknown is
    /// the case where being wrong trips a breaker.
    pub fn would_refuse(&self, additional_w: f64) -> bool {
        if !self.is_complete() {
            return true;
        }
        match self.headroom_w {
            Some(h) => additional_w > h,
            // No declared capacity: refuse rather than assume. An operator who
            // wants the answer can type in the rating.
            None => true,
        }
    }
}

/// Live draw and declared capacity, resolved over the domain tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PowerModel {
    /// Declared rating per domain id.
    capacities: BTreeMap<String, Capacity>,
}

impl PowerModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn declare(&mut self, domain: &str, rated_w: f64) -> &mut Self {
        self.capacities.insert(domain.to_string(), Capacity::declared(rated_w));
        self
    }

    pub fn capacity_of(&self, domain: &str) -> Option<&Capacity> {
        self.capacities.get(domain)
    }

    pub fn is_empty(&self) -> bool {
        self.capacities.is_empty()
    }

    /// How many domains have a declared rating.
    pub fn assess_count(&self) -> usize {
        self.capacities.len()
    }

    /// Headroom for every domain in the tree.
    ///
    /// `node_draw_w` maps compute-node ids to measured chassis draw. A node
    /// absent from that map is counted as unmeasured rather than as zero —
    /// zero is a machine that is switched off, and a machine nobody measured
    /// is not switched off.
    pub fn assess(
        &self,
        tree: &DomainTree,
        node_draw_w: &BTreeMap<String, f64>,
    ) -> Vec<Headroom> {
        let mut out: Vec<Headroom> = Vec::new();

        for domain in tree.every() {
            let mut draw = 0.0;
            let mut measured = 0;
            let mut unmeasured = 0;

            for n in tree.compute_nodes() {
                // A domain contains itself, so a node's own entry is included
                // and a `Node`-kind domain reports its own draw.
                if n.id != domain.id && !tree.ancestors(&n.id).iter().any(|a| a.id == domain.id) {
                    continue;
                }
                match node_draw_w.get(&n.id) {
                    Some(w) => {
                        draw += w;
                        measured += 1;
                    }
                    None => unmeasured += 1,
                }
            }

            let cap = self.capacities.get(&domain.id);
            let usable = cap.map(|c| c.usable_w());
            out.push(Headroom {
                domain: domain.id.clone(),
                kind: domain.kind,
                draw_w: draw,
                measured_nodes: measured,
                unmeasured_nodes: unmeasured,
                rated_w: cap.map(|c| c.rated_w),
                usable_w: usable,
                headroom_w: usable.map(|u| u - draw),
            });
        }

        // Tightest first. The useful reading of this list is its head: a site
        // average hides the one circuit that is nearly full, which is the
        // observation that motivates the whole module.
        out.sort_by(|a, b| match (a.utilisation(), b.utilisation()) {
            (Some(x), Some(y)) => y.partial_cmp(&x).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.domain.cmp(&b.domain),
        });
        out
    }

    /// The tightest domain on the path from a node to the site root.
    ///
    /// What actually limits a machine is not its rack but the worst constraint
    /// anywhere above it, and that is rarely the nearest one.
    pub fn binding_constraint(
        &self,
        tree: &DomainTree,
        node: &str,
        node_draw_w: &BTreeMap<String, f64>,
    ) -> Option<Headroom> {
        let all = self.assess(tree, node_draw_w);
        let path: Vec<String> = tree.ancestors(node).iter().map(|d| d.id.clone()).collect();
        all.into_iter()
            .filter(|h| h.domain == node || path.contains(&h.domain))
            .filter(|h| h.headroom_w.is_some())
            .min_by(|a, b| {
                a.headroom_w
                    .unwrap_or(f64::MAX)
                    .partial_cmp(&b.headroom_w.unwrap_or(f64::MAX))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This site: one circuit, one supply, one rack, two machines.
    fn site() -> DomainTree {
        let mut t = DomainTree::new();
        t.insert("site", DomainKind::Site, None, Provenance::Declared)
            .insert("circuit-a", DomainKind::Feed, Some("site"), Provenance::Declared)
            .insert("ups-1", DomainKind::Ups, Some("circuit-a"), Provenance::Declared)
            .insert("rack-1", DomainKind::Rack, Some("ups-1"), Provenance::Declared)
            .insert("node-a", DomainKind::Node, Some("rack-1"), Provenance::Declared)
            .insert("node-b", DomainKind::Node, Some("rack-1"), Provenance::Declared);
        t
    }

    fn draw(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn find<'a>(h: &'a [Headroom], id: &str) -> &'a Headroom {
        h.iter().find(|x| x.domain == id).expect("domain present")
    }

    #[test]
    fn draw_aggregates_up_the_tree() {
        let mut m = PowerModel::new();
        m.declare("circuit-a", 3680.0); // 16 A at 230 V
        let h = m.assess(&site(), &draw(&[("node-a", 72.0), ("node-b", 69.0)]));

        assert_eq!(find(&h, "node-a").draw_w, 72.0);
        assert_eq!(find(&h, "rack-1").draw_w, 141.0);
        assert_eq!(find(&h, "circuit-a").draw_w, 141.0);
        assert_eq!(find(&h, "site").draw_w, 141.0);
    }

    #[test]
    fn headroom_is_derated_not_nameplate() {
        // A circuit run at its nameplate figure for hours is being operated at
        // its trip point rather than below it.
        let mut m = PowerModel::new();
        m.declare("circuit-a", 3680.0);
        let h = m.assess(&site(), &draw(&[("node-a", 72.0), ("node-b", 69.0)]));
        let c = find(&h, "circuit-a");
        assert_eq!(c.rated_w, Some(3680.0));
        assert_eq!(c.usable_w, Some(2944.0));
        assert_eq!(c.headroom_w, Some(2944.0 - 141.0));
    }

    #[test]
    fn an_undeclared_capacity_reports_nothing_rather_than_infinity() {
        // The most dangerous possible default: a domain nobody rated looking
        // like a domain with room for anything.
        let m = PowerModel::new();
        let h = m.assess(&site(), &draw(&[("node-a", 72.0), ("node-b", 69.0)]));
        let c = find(&h, "circuit-a");
        assert_eq!(c.headroom_w, None);
        assert!(c.would_refuse(10.0), "unknown limit is not a large one");
    }

    #[test]
    fn a_node_nobody_measured_is_not_a_node_drawing_zero() {
        // Zero is a machine switched off. Missing is a machine nobody asked.
        let mut m = PowerModel::new();
        m.declare("rack-1", 2000.0);
        let h = m.assess(&site(), &draw(&[("node-a", 72.0)]));
        let r = find(&h, "rack-1");
        assert_eq!(r.measured_nodes, 1);
        assert_eq!(r.unmeasured_nodes, 1);
        assert!(!r.is_complete());
    }

    #[test]
    fn incomplete_measurement_refuses_even_with_apparent_headroom() {
        // Over 1500 W of apparent headroom, and one machine of unknown draw.
        // This is the case where being wrong trips a breaker.
        let mut m = PowerModel::new();
        m.declare("rack-1", 2000.0);
        let h = m.assess(&site(), &draw(&[("node-a", 72.0)]));
        let r = find(&h, "rack-1");
        assert_eq!(r.headroom_w, Some(1600.0 - 72.0));
        assert!(r.would_refuse(100.0), "unknown load must refuse");
    }

    #[test]
    fn the_tightest_domain_sorts_first() {
        // A site average hides the one circuit that is nearly full. That
        // observation is the entire reason this module exists.
        let mut m = PowerModel::new();
        m.declare("site", 20_000.0);
        m.declare("circuit-a", 3680.0);
        m.declare("rack-1", 200.0);
        let h = m.assess(&site(), &draw(&[("node-a", 72.0), ("node-b", 69.0)]));
        assert_eq!(h[0].domain, "rack-1", "got {:?}", h.iter().map(|x| &x.domain).collect::<Vec<_>>());
    }

    #[test]
    fn the_binding_constraint_is_the_worst_above_a_node_not_the_nearest() {
        let mut m = PowerModel::new();
        m.declare("rack-1", 5000.0);
        m.declare("circuit-a", 300.0); // the real limit, two levels up
        let t = site();
        let d = draw(&[("node-a", 72.0), ("node-b", 69.0)]);
        let b = m.binding_constraint(&t, "node-a", &d).unwrap();
        assert_eq!(b.domain, "circuit-a");
        assert_eq!(b.headroom_w, Some(240.0 - 141.0));
    }

    #[test]
    fn a_full_circuit_refuses_another_machine() {
        let mut m = PowerModel::new();
        m.declare("circuit-a", 200.0); // 160 W usable
        let t = site();
        let d = draw(&[("node-a", 72.0), ("node-b", 69.0)]);
        let b = m.binding_constraint(&t, "node-a", &d).unwrap();
        assert!(b.headroom_w.unwrap() < 20.0);
        assert!(b.would_refuse(70.0), "a third machine must not fit");
        assert!(!b.would_refuse(10.0), "but a small load still does");
    }

    #[test]
    fn utilisation_is_against_usable_capacity_not_nameplate() {
        let mut m = PowerModel::new();
        m.declare("rack-1", 1000.0);
        let h = m.assess(&site(), &draw(&[("node-a", 400.0), ("node-b", 400.0)]));
        let r = find(&h, "rack-1");
        // 800 W of 800 W usable, not 800 of 1000.
        assert!((r.utilisation().unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_site_with_no_declared_capacities_still_reports_draw() {
        // Useful on day one, before anybody has read a breaker panel.
        let m = PowerModel::new();
        let h = m.assess(&site(), &draw(&[("node-a", 72.0), ("node-b", 69.0)]));
        assert!(m.is_empty());
        assert_eq!(find(&h, "site").draw_w, 141.0);
        assert!(find(&h, "site").rated_w.is_none());
    }
}
