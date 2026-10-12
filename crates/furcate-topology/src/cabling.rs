//! The fabric as intended, against the fabric as found.
//!
//! Furcate does not configure switches and this does not either — a leaf's
//! configuration belongs to whatever network OS owns it, and a platform that
//! reached in to rewrite it would be claiming an authority it has no business
//! holding. What Furcate does own is the consequence: [`crate::tree`] places
//! work by failure domain, and a failure domain is a claim about which
//! machines share a fate. Cabling is what makes that claim true or false, and
//! until now nothing checked it.
//!
//! ## The dangerous finding is not the missing cable
//!
//! An unplugged link announces itself. The machine has no path, the workload
//! does not start, and somebody goes and looks.
//!
//! A **miscabled** link is the one worth building this for, because it works.
//! Traffic flows, every health check passes, and the two legs of a redundant
//! pair that were meant to reach different switches both terminate on the same
//! one. The redundancy is imaginary and stays imaginary until the day that
//! switch fails, at which point a failure domain the placement engine was
//! relying on turns out never to have existed. Nothing else in this platform
//! can detect that, because from every other angle the machine is healthy.
//!
//! So findings are ordered by how quietly they fail, not by how loudly.

use crate::lldp::Neighbour;
use serde::{Deserialize, Serialize};

/// One link as the cabling plan says it should be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedLink {
    /// The node this port belongs to.
    pub node: String,
    /// The interface on that node.
    pub local_port: String,
    /// The switch it should reach.
    pub peer_system: String,
    /// The port on that switch.
    pub peer_port: String,
}

/// What one node actually saw on its interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub node: String,
    pub neighbours: Vec<Neighbour>,
}

/// A discrepancy between the plan and the wiring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// The port reaches something, and not what the plan said.
    ///
    /// First because it is silent. The link is up, the checks pass, and a
    /// failure domain the placement engine trusts does not exist.
    Miscabled {
        node: String,
        local_port: String,
        expected: String,
        found: String,
    },
    /// The plan expects a link here and the port sees nothing.
    Missing {
        node: String,
        local_port: String,
        expected: String,
    },
    /// A link exists that the plan does not mention.
    ///
    /// Not automatically wrong — a plan is a document and documents fall
    /// behind — but an undocumented path between failure domains is exactly
    /// how two racks quietly become one.
    Undocumented {
        node: String,
        local_port: String,
        found: String,
    },
}

impl Finding {
    /// Whether this finding means a failure domain is not what it claims.
    ///
    /// A missing cable costs capacity and is visible. The other two change the
    /// shape of the fabric without changing how it looks, which is what makes
    /// them worth waking somebody for.
    pub fn undermines_a_failure_domain(&self) -> bool {
        matches!(
            self,
            Finding::Miscabled { .. } | Finding::Undocumented { .. }
        )
    }

    pub fn node(&self) -> &str {
        match self {
            Finding::Miscabled { node, .. }
            | Finding::Missing { node, .. }
            | Finding::Undocumented { node, .. } => node,
        }
    }
}

/// How a peer is named when it is reported.
fn peer(system: &str, port: &str) -> String {
    format!("{system}:{port}")
}

/// Compare the plan against what the nodes saw.
///
/// Only nodes that actually reported are audited. A node that is down has not
/// told us its cabling is wrong; it has told us nothing, and reporting every
/// one of its planned links as missing would bury the real findings under an
/// outage that is already known about.
pub fn audit(plan: &[PlannedLink], observed: &[Observed]) -> Vec<Finding> {
    let mut miscabled = Vec::new();
    let mut missing = Vec::new();
    let mut undocumented = Vec::new();

    for obs in observed {
        let planned_here: Vec<&PlannedLink> =
            plan.iter().filter(|l| l.node == obs.node).collect();

        for link in &planned_here {
            match obs
                .neighbours
                .iter()
                .find(|n| n.local_port == link.local_port)
            {
                None => missing.push(Finding::Missing {
                    node: link.node.clone(),
                    local_port: link.local_port.clone(),
                    expected: peer(&link.peer_system, &link.peer_port),
                }),
                Some(seen) => {
                    if seen.system_name != link.peer_system || seen.remote_port != link.peer_port {
                        miscabled.push(Finding::Miscabled {
                            node: link.node.clone(),
                            local_port: link.local_port.clone(),
                            expected: peer(&link.peer_system, &link.peer_port),
                            found: peer(&seen.system_name, &seen.remote_port),
                        });
                    }
                }
            }
        }

        for seen in &obs.neighbours {
            if !planned_here
                .iter()
                .any(|l| l.local_port == seen.local_port)
            {
                undocumented.push(Finding::Undocumented {
                    node: obs.node.clone(),
                    local_port: seen.local_port.clone(),
                    found: peer(&seen.system_name, &seen.remote_port),
                });
            }
        }
    }

    // Quietest failures first.
    miscabled.extend(undocumented);
    miscabled.extend(missing);
    miscabled
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(local: &str, sys: &str, remote: &str) -> Neighbour {
        Neighbour {
            local_port: local.into(),
            system_name: sys.into(),
            remote_port: remote.into(),
        }
    }

    fn plan() -> Vec<PlannedLink> {
        vec![
            PlannedLink {
                node: "node-a".into(),
                local_port: "eth0".into(),
                peer_system: "leaf-a".into(),
                peer_port: "Ethernet1".into(),
            },
            PlannedLink {
                node: "node-a".into(),
                local_port: "eth1".into(),
                peer_system: "leaf-b".into(),
                peer_port: "Ethernet1".into(),
            },
        ]
    }

    #[test]
    fn a_correctly_wired_node_produces_nothing() {
        let obs = vec![Observed {
            node: "node-a".into(),
            neighbours: vec![
                n("eth0", "leaf-a", "Ethernet1"),
                n("eth1", "leaf-b", "Ethernet1"),
            ],
        }];
        assert!(audit(&plan(), &obs).is_empty());
    }

    #[test]
    fn the_redundant_pair_on_one_switch_is_caught() {
        // The case this module exists for. Both legs are up, every check
        // passes, and the second switch was never in the path — so a failure
        // domain the placement engine relies on does not exist.
        let obs = vec![Observed {
            node: "node-a".into(),
            neighbours: vec![
                n("eth0", "leaf-a", "Ethernet1"),
                n("eth1", "leaf-a", "Ethernet2"),
            ],
        }];
        let f = audit(&plan(), &obs);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0],
            Finding::Miscabled {
                node: "node-a".into(),
                local_port: "eth1".into(),
                expected: "leaf-b:Ethernet1".into(),
                found: "leaf-a:Ethernet2".into(),
            }
        );
        assert!(f[0].undermines_a_failure_domain());
    }

    #[test]
    fn the_quietest_failure_is_reported_first() {
        // A miscable and a missing cable on one node: the miscable leads,
        // because the missing one has already announced itself.
        let obs = vec![Observed {
            node: "node-a".into(),
            neighbours: vec![n("eth0", "leaf-c", "Ethernet9")],
        }];
        let f = audit(&plan(), &obs);
        assert!(matches!(f[0], Finding::Miscabled { .. }), "{f:?}");
        assert!(matches!(f[1], Finding::Missing { .. }), "{f:?}");
        assert!(!f[1].undermines_a_failure_domain());
    }

    #[test]
    fn an_undocumented_link_is_reported_without_being_called_wrong() {
        // A plan is a document and documents fall behind. But an unrecorded
        // path between racks is how two failure domains quietly become one.
        let obs = vec![Observed {
            node: "node-a".into(),
            neighbours: vec![
                n("eth0", "leaf-a", "Ethernet1"),
                n("eth1", "leaf-b", "Ethernet1"),
                n("eth9", "leaf-z", "Ethernet4"),
            ],
        }];
        let f = audit(&plan(), &obs);
        assert_eq!(
            f,
            vec![Finding::Undocumented {
                node: "node-a".into(),
                local_port: "eth9".into(),
                found: "leaf-z:Ethernet4".into(),
            }]
        );
        assert!(f[0].undermines_a_failure_domain());
    }

    #[test]
    fn a_node_that_did_not_report_is_not_audited() {
        // Silence is not evidence of miswiring. Reporting every planned link
        // on a downed machine as missing would bury the real findings under an
        // outage somebody already knows about.
        assert!(audit(&plan(), &[]).is_empty());

        let obs = vec![Observed {
            node: "node-b".into(),
            neighbours: vec![],
        }];
        assert!(
            audit(&plan(), &obs).is_empty(),
            "node-a's links must not be judged from node-b's report"
        );
    }

    #[test]
    fn the_same_switch_on_the_wrong_port_still_counts() {
        // Reaching leaf-b on the wrong port is a real finding: the plan is the
        // record of which port carries which domain, and a cable in the wrong
        // socket makes every later trace of that link wrong.
        let obs = vec![Observed {
            node: "node-a".into(),
            neighbours: vec![
                n("eth0", "leaf-a", "Ethernet1"),
                n("eth1", "leaf-b", "Ethernet7"),
            ],
        }];
        let f = audit(&plan(), &obs);
        assert_eq!(f.len(), 1);
        assert!(matches!(f[0], Finding::Miscabled { .. }));
    }
}
