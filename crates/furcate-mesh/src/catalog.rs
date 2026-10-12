//! The model catalogue and router.
//!
//! Every node runs a router but hosts only what it can. The catalogue is
//! gossiped alongside membership, so any node knows what exists on the cluster
//! and where. A request names a model or a capability; the router resolves it
//! to a host, preferring a local runtime, then the best LAN path, and never
//! the overlay when a direct link exists.

use crate::capability::{Capability, Tier};
use furcate_topology::PathPreference;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// What a model needs in order to run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelManifest {
    pub id: String,
    /// Digest of the weights, verified before load.
    pub digest: String,
    /// Memory the loaded model requires.
    pub memory_mb: u64,
    /// Runtime that can execute it.
    pub runtime: String,
    /// Lowest tier able to host it at all.
    pub min_tier: Tier,
    /// Whether the artifact carries a valid signature from a trusted signer.
    pub signed: bool,
}

/// Where a request should go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub model: String,
    pub node: String,
    pub path: PathPreference,
    /// True when the model is served by the node that asked.
    pub local: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RouteError {
    /// No node in the cluster hosts this model.
    NoHost { model: String },
    /// The model is not in the catalogue at all.
    UnknownModel { model: String },
    /// Hosts exist but none is currently reachable.
    Unreachable { model: String },
    /// The model is unsigned and policy requires signatures.
    Unsigned { model: String },
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::UnknownModel { model } => write!(f, "no model `{model}` in the catalogue"),
            RouteError::NoHost { model } => write!(
                f,
                "`{model}` is known but no node in this cluster can host it"
            ),
            RouteError::Unreachable { model } => {
                write!(f, "every node hosting `{model}` is currently unreachable")
            }
            RouteError::Unsigned { model } => write!(
                f,
                "`{model}` is unsigned and policy requires a verified signature"
            ),
        }
    }
}

impl std::error::Error for RouteError {}

/// Cluster-wide view of models and who serves them.
#[derive(Default)]
pub struct Catalog {
    models: BTreeMap<String, ModelManifest>,
    /// model id → nodes serving it.
    hosts: BTreeMap<String, Vec<String>>,
    capabilities: BTreeMap<String, Capability>,
    /// node → best path from the local node.
    paths: BTreeMap<String, PathPreference>,
    reachable: BTreeMap<String, bool>,
    me: String,
}

impl Catalog {
    pub fn new(me: impl Into<String>) -> Self {
        Self {
            me: me.into(),
            ..Default::default()
        }
    }

    pub fn add_model(&mut self, m: ModelManifest) -> &mut Self {
        self.models.insert(m.id.clone(), m);
        self
    }

    pub fn add_capability(&mut self, c: Capability) -> &mut Self {
        self.capabilities.insert(c.node.clone(), c);
        self
    }

    pub fn set_path(&mut self, node: &str, path: PathPreference) -> &mut Self {
        self.paths.insert(node.to_string(), path);
        self.reachable.entry(node.to_string()).or_insert(true);
        self
    }

    pub fn set_reachable(&mut self, node: &str, up: bool) -> &mut Self {
        self.reachable.insert(node.to_string(), up);
        self
    }

    /// Record that a node serves a model.
    pub fn announce(&mut self, model: &str, node: &str) -> &mut Self {
        let entry = self.hosts.entry(model.to_string()).or_default();
        if !entry.iter().any(|n| n == node) {
            entry.push(node.to_string());
        }
        self
    }

    pub fn models(&self) -> impl Iterator<Item = &ModelManifest> {
        self.models.values()
    }

    /// Whether a node could host a model at all.
    pub fn can_host(&self, node: &str, model: &str) -> bool {
        let (Some(cap), Some(m)) = (self.capabilities.get(node), self.models.get(model)) else {
            return false;
        };
        cap.tier() >= m.min_tier
            && cap.model_memory_mb() >= m.memory_mb
            && cap.has_runtime(&m.runtime)
    }

    /// Nodes that could host a model, whether or not they currently do.
    pub fn eligible_hosts(&self, model: &str) -> Vec<&str> {
        self.capabilities
            .keys()
            .filter(|n| self.can_host(n, model))
            .map(String::as_str)
            .collect()
    }

    /// Resolve a request to a host.
    pub fn route(&self, model: &str, require_signed: bool) -> Result<Route, RouteError> {
        let Some(manifest) = self.models.get(model) else {
            return Err(RouteError::UnknownModel {
                model: model.to_string(),
            });
        };
        if require_signed && !manifest.signed {
            return Err(RouteError::Unsigned {
                model: model.to_string(),
            });
        }

        let Some(hosts) = self.hosts.get(model).filter(|h| !h.is_empty()) else {
            return Err(RouteError::NoHost {
                model: model.to_string(),
            });
        };

        let up: Vec<&String> = hosts
            .iter()
            .filter(|n| *self.reachable.get(n.as_str()).unwrap_or(&true))
            .collect();
        if up.is_empty() {
            return Err(RouteError::Unreachable {
                model: model.to_string(),
            });
        }

        // A local runtime always wins: no serialization, no network, no
        // opportunity for a path preference to send it out of the building.
        if let Some(local) = up.iter().find(|n| ***n == self.me) {
            return Ok(Route {
                model: model.to_string(),
                node: (*local).clone(),
                path: PathPreference::Loopback,
                local: true,
            });
        }

        let best = up
            .iter()
            .min_by_key(|n| self.paths.get(n.as_str()).copied().unwrap_or(PathPreference::Relay))
            .unwrap();

        Ok(Route {
            model: model.to_string(),
            node: (*best).clone(),
            path: self
                .paths
                .get(best.as_str())
                .copied()
                .unwrap_or(PathPreference::Relay),
            local: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(node: &str, cores: u32, ram: u64, vram: u64) -> Capability {
        Capability {
            node: node.into(),
            cpu_cores: cores,
            ram_mb: ram,
            vram_mb: vram,
            runtimes: vec!["llama.cpp".into()],
            attested: true,
        }
    }

    fn model(id: &str, mem: u64, tier: Tier, signed: bool) -> ModelManifest {
        ModelManifest {
            id: id.into(),
            digest: "ab".repeat(32),
            memory_mb: mem,
            runtime: "llama.cpp".into(),
            min_tier: tier,
            signed,
        }
    }

    fn cluster() -> Catalog {
        let mut c = Catalog::new("node-a");
        c.add_capability(cap("node-a", 8, 32768, 0))
            .add_capability(cap("node-b", 8, 32768, 0))
            .add_capability(cap("jetson", 6, 8192, 8192))
            .add_capability(cap("pi", 4, 4096, 0));
        c.set_path("node-b", PathPreference::LocalLan);
        c.set_path("jetson", PathPreference::LocalLan);
        c.set_path("pi", PathPreference::Overlay);
        c.add_model(model("small", 800, Tier::Constrained, true))
            .add_model(model("mid", 8000, Tier::Compute, true))
            .add_model(model("large", 7000, Tier::Accelerated, true))
            .add_model(model("unsigned", 800, Tier::Constrained, false));
        c
    }

    #[test]
    fn a_gpu_model_only_fits_the_accelerated_node() {
        let c = cluster();
        assert_eq!(c.eligible_hosts("large"), vec!["jetson"]);
    }

    #[test]
    fn a_small_model_fits_almost_everything() {
        let c = cluster();
        let hosts = c.eligible_hosts("small");
        assert!(hosts.contains(&"pi"));
        assert!(hosts.contains(&"node-a"));
        assert!(hosts.contains(&"jetson"));
    }

    #[test]
    fn a_model_too_large_for_a_pi_excludes_it() {
        let c = cluster();
        assert!(!c.eligible_hosts("mid").contains(&"pi"));
    }

    #[test]
    fn a_local_runtime_always_wins() {
        let mut c = cluster();
        c.announce("mid", "node-a").announce("mid", "node-b");
        let r = c.route("mid", true).unwrap();
        assert_eq!(r.node, "node-a");
        assert!(r.local);
        assert_eq!(r.path, PathPreference::Loopback);
    }

    #[test]
    fn lan_is_preferred_over_overlay_for_remote_models() {
        let mut c = cluster();
        c.announce("small", "pi").announce("small", "node-b");
        let r = c.route("small", true).unwrap();
        assert_eq!(r.node, "node-b");
        assert_eq!(r.path, PathPreference::LocalLan);
    }

    #[test]
    fn an_unreachable_host_is_skipped() {
        let mut c = cluster();
        c.announce("small", "node-b").announce("small", "pi");
        c.set_reachable("node-b", false);
        let r = c.route("small", true).unwrap();
        assert_eq!(r.node, "pi");
    }

    #[test]
    fn all_hosts_down_is_distinguished_from_no_hosts() {
        let mut c = cluster();
        c.announce("small", "node-b");
        c.set_reachable("node-b", false);
        assert_eq!(
            c.route("small", true).unwrap_err(),
            RouteError::Unreachable {
                model: "small".into()
            }
        );
        assert_eq!(
            c.route("mid", true).unwrap_err(),
            RouteError::NoHost { model: "mid".into() }
        );
    }

    #[test]
    fn an_unknown_model_is_reported_clearly() {
        let c = cluster();
        assert_eq!(
            c.route("nope", true).unwrap_err(),
            RouteError::UnknownModel {
                model: "nope".into()
            }
        );
    }

    #[test]
    fn unsigned_models_are_refused_when_policy_requires_signing() {
        let mut c = cluster();
        c.announce("unsigned", "node-b");
        assert_eq!(
            c.route("unsigned", true).unwrap_err(),
            RouteError::Unsigned {
                model: "unsigned".into()
            }
        );
        assert!(c.route("unsigned", false).is_ok());
    }

    #[test]
    fn a_node_without_the_runtime_cannot_host() {
        let mut c = cluster();
        let mut odd = cap("odd", 8, 32768, 0);
        odd.runtimes = vec!["onnxruntime".into()];
        c.add_capability(odd);
        assert!(!c.can_host("odd", "mid"));
    }
}
