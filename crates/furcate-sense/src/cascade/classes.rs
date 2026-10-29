//! What each position in the cascade is able to host, stated once.
//!
//! A position (a [`NodeRole`], the name already on every hop of a reading's
//! chain) is a different thing from a capability. The positions are sensing,
//! micro, small, medium and large processing nodes. The capabilities are what a
//! node does for a plan: it measures, plans, gates (checks a proposal against a
//! policy before anything leaves it) and actuates. This table says, for each
//! position, its compute class, the things it can host, the capabilities that
//! follow, and the attestation level it can reach.
//!
//! Nothing here enables anything. `actuation_enabled` is false for every class
//! and a test holds it there: an actuator interface can be hosted (a node has
//! somewhere to put one) while shadow mode keeps it off.
//!
//! The attestation levels come from [`furcate_identity::AssuranceClass`] and are
//! the highest a position can earn from its key custody with the right parts
//! fitted (`reachable`) and what it earns with none (`default`). A node never
//! states its own level; the verifier recomputes it from the chain. The
//! consumer keeps a copy of the table (`tests/fixtures/node-classes.json`) so
//! that a placement decision made outside Furcate names the same classes.

use crate::nicla::NodeRole;
use furcate_identity::AssuranceClass;
use serde_json::{json, Value};

pub const VERSION: u64 = 1;

/// Things a node can host. Names say what runs, not on what.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hosts {
    LocalModelInference,
    ShadowGate,
    ReplayValidation,
    ActuatorInterface,
    LocalPlanner,
}

impl Hosts {
    pub const ALL: [Hosts; 5] =
        [Hosts::LocalModelInference, Hosts::ShadowGate, Hosts::ReplayValidation, Hosts::ActuatorInterface, Hosts::LocalPlanner];

    pub fn as_str(self) -> &'static str {
        match self {
            Hosts::LocalModelInference => "local_model_inference",
            Hosts::ShadowGate => "shadow_gate",
            Hosts::ReplayValidation => "replay_validation",
            Hosts::ActuatorInterface => "actuator_interface",
            Hosts::LocalPlanner => "local_planner",
        }
    }
}

/// What a node does for a plan. Not a position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Measure,
    Plan,
    Gate,
    Actuate,
}

impl Capability {
    pub const ALL: [Capability; 4] = [Capability::Measure, Capability::Plan, Capability::Gate, Capability::Actuate];

    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Measure => "measure",
            Capability::Plan => "plan",
            Capability::Gate => "gate",
            Capability::Actuate => "actuate",
        }
    }
}

/// The largest model a position runs on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Inference {
    None,
    TinySignedModel,
    SmallModel,
    AcceleratedModel,
    AnyModel,
}

impl Inference {
    pub fn as_str(self) -> &'static str {
        match self {
            Inference::None => "none",
            Inference::TinySignedModel => "tiny_signed_model",
            Inference::SmallModel => "small_model",
            Inference::AcceleratedModel => "accelerated_model",
            Inference::AnyModel => "any_model",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeClass {
    pub role: NodeRole,
    /// The short name of the position: sensing, micro, small, medium, large.
    pub tier: &'static str,
    pub compute_class: &'static str,
    pub inference: Inference,
    pub hosts: Vec<Hosts>,
    pub capabilities: Vec<Capability>,
    /// What a node of this class earns with no secure part fitted.
    pub default_attestation: AssuranceClass,
    /// The highest class the position can earn with the right parts.
    pub reachable_attestation: AssuranceClass,
}

/// The wire name of a role, as it appears in every hop of a batch.
pub fn role_name(r: NodeRole) -> &'static str {
    match r {
        NodeRole::Sensing => "sensing",
        NodeRole::MicroProcessing => "micro_processing",
        NodeRole::SmallProcessing => "small_processing",
        NodeRole::MediumProcessing => "medium_processing",
        NodeRole::LargeProcessing => "large_processing",
    }
}

pub const ROLES: [NodeRole; 5] =
    [NodeRole::Sensing, NodeRole::MicroProcessing, NodeRole::SmallProcessing, NodeRole::MediumProcessing, NodeRole::LargeProcessing];

pub fn class_of(role: NodeRole) -> NodeClass {
    use AssuranceClass as A;
    use Capability as C;
    use Hosts as H;
    match role {
        // Measures and holds no key it can prove: identified by a fingerprint, never authenticated.
        NodeRole::Sensing => NodeClass {
            role, tier: "sensing", compute_class: "fixed_function", inference: Inference::None,
            hosts: vec![], capabilities: vec![C::Measure],
            default_attestation: A::Soft, reachable_attestation: A::Soft,
        },
        // Signs for the sensing node behind it, runs small signed models and a gate on its own readings,
        // and has pins for an actuator.
        NodeRole::MicroProcessing => NodeClass {
            role, tier: "micro", compute_class: "microcontroller", inference: Inference::TinySignedModel,
            hosts: vec![H::LocalModelInference, H::ShadowGate, H::ActuatorInterface],
            capabilities: vec![C::Measure, C::Gate, C::Actuate],
            default_attestation: A::Soft, reachable_attestation: A::SecureElement,
        },
        NodeRole::SmallProcessing => NodeClass {
            role, tier: "small", compute_class: "application_cpu", inference: Inference::SmallModel,
            hosts: vec![H::LocalModelInference, H::ShadowGate, H::ReplayValidation, H::ActuatorInterface, H::LocalPlanner],
            capabilities: vec![C::Measure, C::Plan, C::Gate, C::Actuate],
            default_attestation: A::Soft, reachable_attestation: A::Tpm,
        },
        NodeRole::MediumProcessing => NodeClass {
            role, tier: "medium", compute_class: "accelerated_edge", inference: Inference::AcceleratedModel,
            hosts: vec![H::LocalModelInference, H::ShadowGate, H::ReplayValidation, H::ActuatorInterface, H::LocalPlanner],
            capabilities: vec![C::Measure, C::Plan, C::Gate, C::Actuate],
            default_attestation: A::Soft, reachable_attestation: A::Tpm,
        },
        NodeRole::LargeProcessing => NodeClass {
            role, tier: "large", compute_class: "server", inference: Inference::AnyModel,
            hosts: vec![H::LocalModelInference, H::ShadowGate, H::ReplayValidation, H::ActuatorInterface, H::LocalPlanner],
            capabilities: vec![C::Measure, C::Plan, C::Gate, C::Actuate],
            default_attestation: A::Soft, reachable_attestation: A::Tpm,
        },
    }
}

/// The table as the consumer keeps it. Shadow mode is stated per class and is false for actuation everywhere.
pub fn catalogue() -> Value {
    let mut classes = serde_json::Map::new();
    for r in ROLES {
        let c = class_of(r);
        classes.insert(
            role_name(r).to_string(),
            json!({
                "tier": c.tier,
                "compute_class": c.compute_class,
                "inference": c.inference.as_str(),
                "hosts": c.hosts.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
                "capabilities": c.capabilities.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
                "attestation": {"default": c.default_attestation.as_str(), "reachable": c.reachable_attestation.as_str()},
                "actuation_enabled": false,
            }),
        );
    }
    json!({
        "note": "Generated by crates/open/furcate-sense/tests/node_classes.rs from cascade::classes. Do not edit; regenerate with UPDATE_GOLDEN=1.",
        "v": VERSION,
        "capabilities": Capability::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        "hosts": Hosts::ALL.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
        "classes": classes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_positions_host_what_lower_ones_do_and_reach_at_least_as_high() {
        for w in ROLES.windows(2) {
            let (lo, hi) = (class_of(w[0]), class_of(w[1]));
            assert!(hi.hosts.len() >= lo.hosts.len(), "{:?}", w);
            assert!(lo.hosts.iter().all(|h| hi.hosts.contains(h)));
            assert!(lo.capabilities.iter().all(|c| hi.capabilities.contains(c)));
            assert!(hi.inference >= lo.inference);
            assert!(hi.reachable_attestation >= lo.reachable_attestation);
        }
    }

    #[test]
    fn no_position_reaches_above_what_its_custody_can_earn_and_none_starts_above_soft() {
        for r in ROLES {
            let c = class_of(r);
            assert_eq!(c.default_attestation, AssuranceClass::Soft);
            assert!(c.reachable_attestation >= c.default_attestation);
        }
        // A sensing node holds no key, so it can never be graded above soft.
        assert_eq!(class_of(NodeRole::Sensing).reachable_attestation, AssuranceClass::Soft);
    }

    #[test]
    fn a_capability_follows_from_what_is_hosted() {
        for r in ROLES {
            let c = class_of(r);
            let has = |h: Hosts| c.hosts.contains(&h);
            assert_eq!(c.capabilities.contains(&Capability::Plan), has(Hosts::LocalPlanner), "{r:?}");
            assert_eq!(c.capabilities.contains(&Capability::Gate), has(Hosts::ShadowGate), "{r:?}");
            assert_eq!(c.capabilities.contains(&Capability::Actuate), has(Hosts::ActuatorInterface), "{r:?}");
            assert!(c.capabilities.contains(&Capability::Measure));
        }
    }
}
