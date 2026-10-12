//! Physical topology discovery over LLDP.
//!
//! LLDP is how automation learns which switch port a machine is actually
//! plugged into without anyone typing it into a spreadsheet. What it gives is
//! neighbour identity and port — enough to place machines relative to switches
//! and to detect two nodes sharing one uplink.
//!
//! What it cannot see is power: which outlet feeds which supply, which breaker
//! feeds which outlet. Those stay declared, and stay marked as declared.

use crate::tree::{DomainKind, DomainTree, Provenance};
use serde::{Deserialize, Serialize};

/// A neighbour seen on a local interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Neighbour {
    /// Local interface the neighbour was seen on.
    pub local_port: String,
    /// Neighbour's advertised system name.
    pub system_name: String,
    /// Neighbour's port identifier.
    pub remote_port: String,
}

/// Parse `lldpcli show neighbors -f keyvalue` output.
///
/// The key-value format is used rather than JSON because it is stable across
/// versions and needs no extra dependency to read.
pub fn parse_neighbours(text: &str) -> Vec<Neighbour> {
    let mut out: Vec<Neighbour> = Vec::new();
    let mut current: Option<(String, String, String)> = None;

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let parts: Vec<&str> = key.split('.').collect();
        // Keys look like: lldp.enp0s31f6.chassis.name
        let Some(iface) = parts.get(1) else { continue };

        match current.as_mut() {
            Some((existing, _, _)) if existing == iface => {}
            _ => {
                if let Some((i, n, p)) = current.take() {
                    if !n.is_empty() {
                        out.push(Neighbour {
                            local_port: i,
                            system_name: n,
                            remote_port: p,
                        });
                    }
                }
                current = Some((iface.to_string(), String::new(), String::new()));
            }
        }

        if let Some((_, name, port)) = current.as_mut() {
            if key.ends_with(".chassis.name") {
                *name = value.to_string();
            } else if key.contains(".port.") && key.ends_with("descr") && port.is_empty() {
                *port = value.to_string();
            }
        }
    }
    if let Some((i, n, p)) = current {
        if !n.is_empty() {
            out.push(Neighbour {
                local_port: i,
                system_name: n,
                remote_port: p,
            });
        }
    }
    out
}

/// Read neighbours from the local LLDP daemon.
pub fn discover() -> Vec<Neighbour> {
    std::process::Command::new("lldpcli")
        .args(["show", "neighbors", "-f", "keyvalue"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_neighbours(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

/// Fold discovered neighbours into a tree.
///
/// Switches enter as discovered facts. The machine is attached to the switch
/// it is cabled to, which is what lets a placement rule spread across network
/// domains rather than assuming one flat segment.
pub fn merge(tree: &mut DomainTree, node: &str, neighbours: &[Neighbour], parent_rack: &str) {
    for n in neighbours {
        let switch_id = format!("switch:{}", n.system_name);
        if tree.get(&switch_id).is_none() {
            tree.insert(
                switch_id.clone(),
                DomainKind::Chassis,
                Some(parent_rack),
                Provenance::Discovered,
            );
        }
        // The node's uplink is a discovered fact about where it sits.
        tree.insert(
            node,
            DomainKind::Node,
            Some(&switch_id),
            Provenance::Discovered,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
lldp.enp0s31f6.via=LLDP
lldp.enp0s31f6.chassis.name=switch-1
lldp.enp0s31f6.chassis.descr=Managed Switch
lldp.enp0s31f6.port.descr=Port 3
";

    #[test]
    fn a_neighbour_is_parsed() {
        let n = parse_neighbours(SAMPLE);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].system_name, "switch-1");
        assert_eq!(n[0].local_port, "enp0s31f6");
        assert_eq!(n[0].remote_port, "Port 3");
    }

    #[test]
    fn several_interfaces_yield_several_neighbours() {
        let text = format!("{SAMPLE}lldp.eth1.chassis.name=switch-2\nlldp.eth1.port.descr=Port 9\n");
        let n = parse_neighbours(&text);
        assert_eq!(n.len(), 2);
        assert_eq!(n[1].system_name, "switch-2");
    }

    #[test]
    fn empty_output_yields_nothing_rather_than_a_phantom() {
        assert!(parse_neighbours("").is_empty());
        assert!(parse_neighbours("lldp.eth0.via=LLDP\n").is_empty());
    }

    #[test]
    fn merging_places_the_node_under_its_switch() {
        let mut t = DomainTree::new();
        t.insert("rack-1", DomainKind::Rack, None, Provenance::Declared);
        merge(&mut t, "node-a", &parse_neighbours(SAMPLE), "rack-1");
        assert_eq!(
            t.domain_of("node-a", DomainKind::Chassis),
            Some("switch:switch-1")
        );
    }

    #[test]
    fn discovered_facts_are_marked_as_discovered() {
        let mut t = DomainTree::new();
        t.insert("rack-1", DomainKind::Rack, None, Provenance::Declared);
        merge(&mut t, "node-a", &parse_neighbours(SAMPLE), "rack-1");
        assert_eq!(
            t.get("switch:switch-1").unwrap().provenance,
            Provenance::Discovered
        );
    }

    #[test]
    fn two_nodes_on_one_switch_share_a_network_domain() {
        // The fact that matters for placement: one uplink is one failure.
        let mut t = DomainTree::new();
        t.insert("rack-1", DomainKind::Rack, None, Provenance::Declared);
        let n = parse_neighbours(SAMPLE);
        merge(&mut t, "node-a", &n, "rack-1");
        merge(&mut t, "node-b", &n, "rack-1");
        assert_eq!(
            t.distinct_domains(&["node-a", "node-b"], DomainKind::Chassis),
            1
        );
    }
}
