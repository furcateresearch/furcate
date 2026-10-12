//! What an edition adds to the node agent.
//!
//! The open daemon is complete on its own. An edition that adds to it — more
//! routes, a policy for which work to give up when the supply fails, advice on
//! resource limits, a card advertising the node to agent frameworks —
//! implements [`Extension`] and passes it to [`register`] before calling
//! [`crate::main`]. Nothing here names what implements it: the open daemon
//! builds and runs with nothing registered, and every hook has an answer that
//! means "this build does not do that".
//!
//! One extension per process, registered once. A second registration is
//! refused rather than merged, because two editions in one binary would be two
//! answers to the same question with no rule for which one the operator gets.

use std::sync::{Arc, Mutex, OnceLock};

use furcate_api::Router;
use furcate_ledger::OpKind;
use furcate_mesh::Tier;
use furcate_power::Rung;
use furcate_resource::Group;

use furcate_health::workload::Inventory;

/// What an edition adds. Every method has a default that adds nothing.
pub trait Extension: Send + Sync + 'static {
    /// The edition's name as the release spells it, reported by `--version`
    /// and `/healthz` so a rollout can confirm the edition it installed is the
    /// one now running.
    fn edition(&self) -> &'static str {
        "open"
    }

    /// What this installation is, as served on `/features` before the
    /// machine's own facts are added. The open daemon reports its edition.
    fn features(&self) -> serde_json::Value {
        serde_json::json!({ "edition": self.edition() })
    }

    /// Routes added to the node's router after the open ones. A route here
    /// with the same method and path as an open one replaces it, which is how
    /// an edition answers paths the open daemon only explains.
    fn routes(&self, r: Router, _node: &Node) -> Router {
        r
    }

    /// The running workloads to stop at this rung, in the order to stop them.
    /// `None` means this edition does not choose, and the open daemon caps
    /// power at the rung without stopping anything.
    fn shed_order(&self, _rung: Rung, _inventory: &Inventory, _now_s: u64) -> Option<Vec<String>> {
        None
    }

    /// Limits worth changing for these control groups, as served under
    /// `recommendations` on `/resources`. `None` serves an empty list.
    fn recommendations(&self, _groups: &[Group]) -> Option<serde_json::Value> {
        None
    }

    /// This node as an agent card for other agent frameworks. `None` means the
    /// node does not advertise itself, and the card paths answer 404.
    fn agent_card(&self, _facts: &NodeFacts, _listen: &str) -> Option<serde_json::Value> {
        None
    }
}

/// The open daemon: adds nothing.
struct Open;

impl Extension for Open {}

static REGISTERED: OnceLock<Box<dyn Extension>> = OnceLock::new();

/// Register this process's extension. Returns false, and changes nothing, if
/// one is already registered.
pub fn register(extension: impl Extension) -> bool {
    REGISTERED.set(Box::new(extension)).is_ok()
}

/// The registered extension, or the open daemon's.
pub(crate) fn get() -> &'static dyn Extension {
    match REGISTERED.get() {
        Some(e) => e.as_ref(),
        None => &Open,
    }
}

/// What a node can do right now, measured rather than configured, for an
/// edition that describes the node to others.
#[derive(Clone, Debug)]
pub struct NodeFacts {
    pub node_id: String,
    pub tier: Tier,
    /// A model survived measurement at registration and can be served.
    pub serves_models: bool,
    /// The hardware exposes a lever the actuator can move.
    pub can_tune: bool,
    /// The node's lifecycle state accepts new work.
    pub accepts_work: bool,
    /// Sensor-tier devices are attached to this node.
    pub parents_leaves: bool,
}

/// The node, as an extension's routes reach it: its operation chain, and the
/// facts it reports about itself.
#[derive(Clone)]
pub struct Node {
    agent: Arc<Mutex<crate::Agent>>,
}

impl Node {
    pub(crate) fn new(agent: Arc<Mutex<crate::Agent>>) -> Self {
        Node { agent }
    }

    /// Append to the node's operation chain and persist it, as every open
    /// route that changes something does.
    pub fn record(&self, kind: OpKind, actor: impl Into<String>, subject: impl Into<String>, result: impl Into<String>) {
        let mut a = self.agent.lock().expect("agent lock");
        a.chain.append(crate::now_ms(), kind, actor, subject, result);
        a.persist_chain();
    }

    /// What the node can do right now.
    pub fn facts(&self) -> NodeFacts {
        self.agent.lock().expect("agent lock").facts()
    }
}
