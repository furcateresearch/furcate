//! Ordered bring-up with readiness gates.
//!
//! Shutdown is choreography; startup is dependency resolution, and it is where
//! this site has actually been burned. A four-hour outage came from services
//! binding to an overlay address that did not exist yet at boot: the containers
//! exited immediately, and a restart policy does not rescue a start-time bind
//! failure.
//!
//! So nothing starts before its gate opens, and a gate that never opens is an
//! alert rather than a crash loop.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A precondition that must hold before a unit may start.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Gate {
    /// A network address exists and is assigned. The gate that would have
    /// prevented the outage.
    AddressReady(String),
    /// A filesystem is mounted.
    Mounted(String),
    /// Another unit reports healthy.
    UnitHealthy(String),
    /// Power is on line rather than on battery.
    OnLinePower,
    /// A node has passed attestation.
    Attested(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    Open,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unit {
    pub name: String,
    pub gates: Vec<Gate>,
    /// Seconds to wait before declaring the unit stuck.
    pub timeout: u64,
}

/// What happened on a bring-up tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Started {
    /// Units that started this tick.
    Units(Vec<String>),
    /// Units whose gates never opened within their timeout.
    Stuck(Vec<String>),
}

pub struct BringUp {
    units: Vec<Unit>,
    gates: BTreeMap<Gate, GateState>,
    started: BTreeSet<String>,
    began_at: u64,
}

impl BringUp {
    pub fn new(units: Vec<Unit>, began_at: u64) -> Self {
        Self {
            units,
            gates: BTreeMap::new(),
            started: BTreeSet::new(),
            began_at,
        }
    }

    /// Report a gate's current state.
    pub fn set_gate(&mut self, gate: Gate, state: GateState) -> &mut Self {
        self.gates.insert(gate, state);
        self
    }

    fn is_open(&self, gate: &Gate) -> bool {
        // A gate never reported is closed. Defaulting to open is how a
        // start-time race gets reintroduced.
        match gate {
            Gate::UnitHealthy(name) => self.started.contains(name),
            other => matches!(self.gates.get(other), Some(GateState::Open)),
        }
    }

    pub fn started(&self) -> &BTreeSet<String> {
        &self.started
    }

    /// Start everything whose gates are open, and report anything stuck.
    pub fn tick(&mut self, now: u64) -> Started {
        let ready: Vec<String> = self
            .units
            .iter()
            .filter(|u| !self.started.contains(&u.name))
            .filter(|u| u.gates.iter().all(|g| self.is_open(g)))
            .map(|u| u.name.clone())
            .collect();

        if !ready.is_empty() {
            for name in &ready {
                self.started.insert(name.clone());
            }
            return Started::Units(ready);
        }

        let elapsed = now.saturating_sub(self.began_at);
        let stuck: Vec<String> = self
            .units
            .iter()
            .filter(|u| !self.started.contains(&u.name))
            .filter(|u| elapsed >= u.timeout)
            .map(|u| u.name.clone())
            .collect();
        Started::Stuck(stuck)
    }

    /// Run until nothing more can start.
    pub fn settle(&mut self, now: u64) -> Vec<String> {
        let mut order = Vec::new();
        loop {
            match self.tick(now) {
                Started::Units(mut u) if !u.is_empty() => order.append(&mut u),
                _ => break,
            }
        }
        order
    }

    /// The order to stop the units, dependents before what they depend on:
    /// the reverse of the order they would start in with every gate open.
    /// Gates other than another unit being healthy are taken as open, because
    /// shutting down is not waiting for anything to be ready.
    pub fn halt_order(&self) -> Vec<String> {
        let mut order: Vec<String> = Vec::new();
        loop {
            let next: Vec<String> = self
                .units
                .iter()
                .filter(|u| !order.contains(&u.name))
                .filter(|u| {
                    u.gates.iter().all(|g| match g {
                        Gate::UnitHealthy(n) => order.contains(n),
                        _ => true,
                    })
                })
                .map(|u| u.name.clone())
                .collect();
            if next.is_empty() {
                break;
            }
            order.extend(next);
        }
        order.reverse();
        order
    }

    /// Units still waiting, with the gates they are waiting on.
    pub fn blocked(&self) -> Vec<(String, Vec<Gate>)> {
        self.units
            .iter()
            .filter(|u| !self.started.contains(&u.name))
            .map(|u| {
                let closed: Vec<Gate> = u
                    .gates
                    .iter()
                    .filter(|g| !self.is_open(g))
                    .cloned()
                    .collect();
                (u.name.clone(), closed)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str, gates: Vec<Gate>) -> Unit {
        Unit {
            name: name.into(),
            gates,
            timeout: 60,
        }
    }

    /// The stack that caused the outage: an app bound to an overlay address.
    fn outage_stack() -> Vec<Unit> {
        vec![
            unit("tailscale", vec![]),
            unit(
                "docker",
                vec![Gate::AddressReady("192.0.2.28".into()), Gate::UnitHealthy("tailscale".into())],
            ),
            unit("beacon", vec![Gate::UnitHealthy("docker".into())]),
        ]
    }

    #[test]
    fn nothing_starts_before_its_address_exists() {
        let mut b = BringUp::new(outage_stack(), 0);
        // Only the ungated unit may start.
        assert_eq!(b.tick(0), Started::Units(vec!["tailscale".into()]));
        assert_eq!(b.tick(0), Started::Stuck(vec![]));
        assert!(!b.started().contains("docker"));
    }

    #[test]
    fn the_stack_comes_up_in_order_once_the_address_appears() {
        let mut b = BringUp::new(outage_stack(), 0);
        b.tick(0);
        b.set_gate(Gate::AddressReady("192.0.2.28".into()), GateState::Open);
        let order = b.settle(1);
        assert_eq!(order, vec!["docker".to_string(), "beacon".to_string()]);
    }

    #[test]
    fn an_unreported_gate_is_closed_not_open() {
        let mut b = BringUp::new(vec![unit("x", vec![Gate::Mounted("/data".into())])], 0);
        assert_eq!(b.tick(0), Started::Stuck(vec![]));
        assert!(b.started().is_empty());
    }

    #[test]
    fn a_gate_that_never_opens_becomes_an_alert() {
        let mut b = BringUp::new(vec![unit("x", vec![Gate::Mounted("/data".into())])], 0);
        assert_eq!(b.tick(0), Started::Stuck(vec![]));
        // Past the timeout it is reported rather than retried forever.
        assert_eq!(b.tick(60), Started::Stuck(vec!["x".into()]));
    }

    #[test]
    fn blocked_units_name_the_gates_they_wait_on() {
        let mut b = BringUp::new(outage_stack(), 0);
        b.tick(0);
        let blocked = b.blocked();
        let docker = blocked.iter().find(|(n, _)| n == "docker").unwrap();
        assert!(docker.1.contains(&Gate::AddressReady("192.0.2.28".into())));
    }

    #[test]
    fn a_closed_gate_can_be_reported_explicitly() {
        let mut b = BringUp::new(vec![unit("x", vec![Gate::OnLinePower])], 0);
        b.set_gate(Gate::OnLinePower, GateState::Closed);
        assert_eq!(b.tick(0), Started::Stuck(vec![]));
        b.set_gate(Gate::OnLinePower, GateState::Open);
        assert_eq!(b.tick(0), Started::Units(vec!["x".into()]));
    }

    #[test]
    fn attestation_can_gate_a_workload() {
        let mut b = BringUp::new(
            vec![unit("model-server", vec![Gate::Attested("node-a".into())])],
            0,
        );
        assert_eq!(b.tick(0), Started::Stuck(vec![]));
        b.set_gate(Gate::Attested("node-a".into()), GateState::Open);
        assert_eq!(b.tick(0), Started::Units(vec!["model-server".into()]));
    }

    #[test]
    fn settle_is_idempotent_once_everything_has_started() {
        let mut b = BringUp::new(outage_stack(), 0);
        b.set_gate(Gate::AddressReady("192.0.2.28".into()), GateState::Open);
        b.settle(0);
        assert_eq!(b.settle(0), Vec::<String>::new());
        assert_eq!(b.started().len(), 3);
    }

    #[test]
    fn units_halt_in_the_reverse_of_the_order_they_start() {
        let b = BringUp::new(
            vec![
                Unit { name: "reporting".into(), gates: vec![Gate::UnitHealthy("api".into())], timeout: 1 },
                Unit { name: "api".into(), gates: vec![Gate::UnitHealthy("root".into())], timeout: 1 },
                Unit { name: "root".into(), gates: vec![], timeout: 1 },
            ],
            0,
        );
        assert_eq!(b.halt_order(), vec!["reporting", "api", "root"]);
    }
}
