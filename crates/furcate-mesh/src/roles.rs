//! What a machine is FOR, as the operator declares it.
//!
//! Furcate already derives some of this — `controller`, `accelerated`,
//! `administers` — from what a node observes about itself. That answers "what
//! can this machine do". It does not answer "what has the operator decided
//! this machine is for", and those differ constantly: node-c has 56 cores and
//! could serve anything, and is a build host because somebody decided so.
//!
//! ## Why declared and derived are kept apart
//!
//! A derived fact is a measurement and changes when the hardware does. A role
//! is a decision and changes when a person changes their mind. Storing a
//! decision in a field that a probe overwrites means the decision is lost the
//! next time anything reports, silently — which is how `tier` ends up
//! disagreeing with what everybody knows the machine is for.
//!
//! So roles never contradict hardware, they sit beside it. A machine with no
//! accelerator can be assigned `Ai` and the scheduler will simply find nothing
//! to place; that is an operator error worth seeing, not one to prevent by
//! refusing to record what they asked for.
//!
//! ## The vocabulary is what a datacentre actually separates
//!
//! Not a taxonomy of everything a computer can do. These are the divisions
//! that change where work goes: compute from storage, build from serving,
//! control from the things it controls. Anything finer is a label, and labels
//! belong in `Role::Other` rather than in a growing enum nobody can match on
//! exhaustively.
//!
//! Diverse hardware is the point. A Raspberry Pi is `Sensing` and `Edge`; a
//! UPS host is `Power`; an ESP32 with a thermometer is `Sensing` and nothing
//! else. A role vocabulary that assumed servers would have no way to say what
//! most of the estate is.

use serde::{Deserialize, Serialize};

/// What a machine is for. An operator's decision, not a measurement.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Runs the site controller: the roster, the authority engine, admission.
    /// One per cluster in practice, though nothing here enforces that — a
    /// cluster mid-migration legitimately has two.
    Control,
    /// Runs workloads. The default answer for a machine nobody has decided
    /// anything else about.
    Compute,
    /// Runs accelerated inference or training. Distinct from Compute because
    /// where a model runs is decided by capacity, not by convenience.
    Ai,
    /// Compiles. Separated because a build is a burst that will take every
    /// core it can reach, and a machine doing that is a bad neighbour to
    /// anything latency-sensitive.
    Build,
    /// Holds bulk data — object storage, backups, archives. The role that most
    /// often outlives the hardware, since the disks migrate and the duty does
    /// not.
    Storage,
    /// Databases and the durable state applications depend on. Separate from
    /// Storage: bulk is about capacity, this is about a working set and
    /// fsync latency.
    Data,
    /// Consensus, validation, signing — work whose value is that it is
    /// independent. A validator sharing a host with a noisy neighbour is a
    /// validator that misses its window.
    Validation,
    /// Public ingress: gateway, reverse proxy, TLS termination.
    Edge,
    /// Serves applications to users.
    Serving,
    /// Watches. Metrics, logs, alerting. Deliberately not `Compute`, because a
    /// monitor that dies with the thing it monitors has monitored nothing.
    Observability,
    /// Power delivery and environmental control — a UPS host, a PDU
    /// controller, a cooling manager. Small machines with outsized
    /// consequences.
    Power,
    /// Sensors and actuators. A Pi reading a thermometer, an ESP32 on a door
    /// contact. Usually the least capable hardware and the most numerous.
    Sensing,
    /// Network fabric: routing, VPN concentration, DNS.
    Network,
    /// Something this vocabulary does not name. Carried verbatim so an
    /// operator is never blocked from describing their estate by a list
    /// somebody else wrote.
    Other(String),
}

impl Role {
    /// Every named role, for a picker. `Other` is excluded deliberately: it is
    /// a free-text escape hatch, not a menu item.
    pub fn named() -> Vec<Role> {
        use Role::*;
        vec![
            Control, Compute, Ai, Build, Storage, Data, Validation, Edge, Serving,
            Observability, Power, Sensing, Network,
        ]
    }

    /// The word an operator types and reads.
    pub fn as_str(&self) -> &str {
        use Role::*;
        match self {
            Control => "control",
            Compute => "compute",
            Ai => "ai",
            Build => "build",
            Storage => "storage",
            Data => "data",
            Validation => "validation",
            Edge => "edge",
            Serving => "serving",
            Observability => "observability",
            Power => "power",
            Sensing => "sensing",
            Network => "network",
            Other(s) => s,
        }
    }

    /// One line saying what the role means, shown beside the name wherever an
    /// operator picks one. A vocabulary nobody can read the intent of gets
    /// used inconsistently within a week.
    pub fn means(&self) -> &str {
        use Role::*;
        match self {
            Control => "runs the site controller: roster, authority, admission",
            Compute => "runs workloads",
            Ai => "runs accelerated inference or training",
            Build => "compiles; takes every core it can reach",
            Storage => "holds bulk data: objects, backups, archives",
            Data => "databases and durable application state",
            Validation => "consensus and signing; needs to be a quiet neighbour",
            Edge => "public ingress: gateway, proxy, TLS",
            Serving => "serves applications to users",
            Observability => "metrics, logs and alerting",
            Power => "power delivery and environmental control",
            Sensing => "sensors and actuators",
            Network => "routing, VPN, DNS",
            Other(_) => "an operator's own label",
        }
    }

    pub fn parse(s: &str) -> Role {
        use Role::*;
        match s.trim().to_ascii_lowercase().as_str() {
            "control" | "controller" => Control,
            "compute" => Compute,
            "ai" | "inference" => Ai,
            "build" | "builder" => Build,
            "storage" => Storage,
            "data" | "database" | "db" => Data,
            "validation" | "validator" => Validation,
            "edge" | "gateway" => Edge,
            "serving" | "apps" | "app" => Serving,
            "observability" | "monitoring" => Observability,
            "power" | "ups" => Power,
            "sensing" | "sensor" => Sensing,
            "network" | "net" => Network,
            other => Other(other.to_string()),
        }
    }
}

/// What one machine is for. A set, because machines are rarely one thing:
/// node-a is `Serving` and `Data`, node-b is `Control` and `Validation`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub node_id: String,
    /// Sorted and deduplicated on the way in, so two writes of the same set in
    /// a different order do not read as a change.
    pub roles: Vec<Role>,
    /// Why, in the operator's words. Carried for the same reason the trust
    /// store carries one: a decision nobody can read the reasoning of is one
    /// nobody dares change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When it was last set, so a stale assignment is visible as stale.
    pub at: u64,
}

impl Assignment {
    pub fn new(node_id: &str, roles: Vec<Role>, note: Option<String>, at: u64) -> Self {
        let mut roles = roles;
        roles.sort();
        roles.dedup();
        Self { node_id: node_id.to_string(), roles, note, at }
    }

    pub fn has(&self, r: &Role) -> bool {
        self.roles.contains(r)
    }
}

/// Every machine's assignment.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roles {
    #[serde(default)]
    pub nodes: Vec<Assignment>,
}

impl Roles {
    pub fn get(&self, node_id: &str) -> Option<&Assignment> {
        self.nodes.iter().find(|a| a.node_id == node_id)
    }

    /// Replace rather than append: a machine appearing twice is two answers to
    /// one question, and the second is the one nobody looks at.
    pub fn set(&mut self, a: Assignment) {
        match self.nodes.iter().position(|n| n.node_id == a.node_id) {
            Some(i) => self.nodes[i] = a,
            None => self.nodes.push(a),
        }
    }

    pub fn clear(&mut self, node_id: &str) -> bool {
        let before = self.nodes.len();
        self.nodes.retain(|a| a.node_id != node_id);
        self.nodes.len() != before
    }

    /// Which machines carry a role. The question a scheduler asks.
    pub fn with(&self, r: &Role) -> Vec<&Assignment> {
        self.nodes.iter().filter(|a| a.has(r)).collect()
    }

    /// Roles no machine carries. Worth surfacing: a cluster with nothing
    /// assigned `Storage` is not necessarily wrong, but an operator who
    /// thought they had storage should be told they do not.
    pub fn unassigned(&self) -> Vec<Role> {
        Role::named().into_iter().filter(|r| self.with(r).is_empty()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_is_usually_several_things() {
        let a = Assignment::new("n1", vec![Role::Serving, Role::Data], None, 1);
        assert!(a.has(&Role::Serving) && a.has(&Role::Data));
    }

    #[test]
    fn order_is_not_a_change() {
        let a = Assignment::new("n1", vec![Role::Data, Role::Serving], None, 1);
        let b = Assignment::new("n1", vec![Role::Serving, Role::Data], None, 1);
        assert_eq!(a.roles, b.roles);
    }

    #[test]
    fn the_same_role_twice_is_once() {
        let a = Assignment::new("n1", vec![Role::Build, Role::Build], None, 1);
        assert_eq!(a.roles.len(), 1);
    }

    #[test]
    fn setting_replaces_rather_than_duplicates() {
        let mut r = Roles::default();
        r.set(Assignment::new("n1", vec![Role::Compute], None, 1));
        r.set(Assignment::new("n1", vec![Role::Build], None, 2));
        assert_eq!(r.nodes.len(), 1);
        assert_eq!(r.get("n1").unwrap().roles, vec![Role::Build]);
    }

    #[test]
    fn an_unknown_word_is_kept_not_dropped() {
        // An operator is never blocked by a list somebody else wrote.
        assert_eq!(Role::parse("seismograph"), Role::Other("seismograph".into()));
    }

    #[test]
    fn common_synonyms_land_on_the_same_role() {
        assert_eq!(Role::parse("validator"), Role::Validation);
        assert_eq!(Role::parse("ups"), Role::Power);
        assert_eq!(Role::parse("DB"), Role::Data);
    }

    #[test]
    fn unassigned_names_what_the_cluster_lacks() {
        let mut r = Roles::default();
        r.set(Assignment::new("n1", vec![Role::Compute], None, 1));
        let missing = r.unassigned();
        assert!(missing.contains(&Role::Storage));
        assert!(!missing.contains(&Role::Compute));
    }

    #[test]
    fn every_named_role_reads_as_something() {
        for r in Role::named() {
            assert!(!r.as_str().is_empty());
            assert!(!r.means().is_empty(), "{} has no description", r.as_str());
        }
    }
}
