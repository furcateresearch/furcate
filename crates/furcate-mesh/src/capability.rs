//! Hardware capability and tiering.

use serde::{Deserialize, Serialize};

/// Hardware tiers, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Microcontroller class. Wake words, anomaly detection, on-sensor
    /// filtering.
    Leaf,
    /// Pi class single-board computers.
    Constrained,
    /// Server and desktop CPUs.
    Compute,
    /// Discrete GPU, Jetson, or unified-memory machines.
    Accelerated,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Leaf => "leaf",
            Tier::Constrained => "constrained",
            Tier::Compute => "compute",
            Tier::Accelerated => "accelerated",
        }
    }
}

/// What a node can actually do, derived from its attested inventory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    pub node: String,
    pub cpu_cores: u32,
    pub ram_mb: u64,
    /// Accelerator memory in megabytes, zero when there is none.
    pub vram_mb: u64,
    /// Runtimes installed and usable on this node.
    pub runtimes: Vec<String>,
    /// True when these figures came from appraised evidence rather than the
    /// node's own claim.
    pub attested: bool,
}

impl Capability {
    /// Classify into a tier.
    ///
    /// Thresholds are deliberately conservative: over-tiering a node means
    /// scheduling a model it will thrash on, which is worse than leaving
    /// capacity unused.
    pub fn tier(&self) -> Tier {
        if self.vram_mb >= 4096 {
            Tier::Accelerated
        } else if self.ram_mb >= 8192 && self.cpu_cores >= 4 {
            Tier::Compute
        } else if self.ram_mb >= 512 {
            Tier::Constrained
        } else {
            Tier::Leaf
        }
    }

    /// Memory available for holding a model, preferring accelerator memory.
    pub fn model_memory_mb(&self) -> u64 {
        if self.vram_mb > 0 {
            self.vram_mb
        } else {
            // Leave headroom for the OS and the runtime itself; loading a model
            // that exactly fills RAM is how a node starts swapping.
            self.ram_mb.saturating_mul(70) / 100
        }
    }

    pub fn has_runtime(&self, runtime: &str) -> bool {
        self.runtimes.iter().any(|r| r == runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(cores: u32, ram: u64, vram: u64) -> Capability {
        Capability {
            node: "n".into(),
            cpu_cores: cores,
            ram_mb: ram,
            vram_mb: vram,
            runtimes: vec!["llama.cpp".into()],
            attested: true,
        }
    }

    #[test]
    fn a_gpu_node_is_accelerated() {
        assert_eq!(cap(8, 32768, 24576).tier(), Tier::Accelerated);
    }

    #[test]
    fn a_server_without_a_gpu_is_compute() {
        // Both machines on the first site: no accelerator.
        assert_eq!(cap(8, 32768, 0).tier(), Tier::Compute);
    }

    #[test]
    fn a_pi_is_constrained() {
        assert_eq!(cap(4, 4096, 0).tier(), Tier::Constrained);
    }

    #[test]
    fn a_microcontroller_is_a_leaf() {
        assert_eq!(cap(1, 8, 0).tier(), Tier::Leaf);
    }

    #[test]
    fn accelerator_memory_is_preferred_when_present() {
        assert_eq!(cap(8, 32768, 24576).model_memory_mb(), 24576);
    }

    #[test]
    fn cpu_nodes_keep_headroom() {
        // Filling RAM exactly is how a node starts swapping.
        let c = cap(8, 10000, 0);
        assert!(c.model_memory_mb() < c.ram_mb);
        assert_eq!(c.model_memory_mb(), 7000);
    }

    #[test]
    fn tiers_are_ordered() {
        assert!(Tier::Accelerated > Tier::Compute);
        assert!(Tier::Compute > Tier::Constrained);
        assert!(Tier::Constrained > Tier::Leaf);
    }

    #[test]
    fn unattested_capability_is_visible_as_such() {
        let mut c = cap(8, 32768, 0);
        c.attested = false;
        assert!(!c.attested, "callers must be able to refuse unattested claims");
    }
}
