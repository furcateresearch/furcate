//! What a control group was given and what it is actually using.
//!
//! cgroup v2 is where every container and every service on a modern Linux box
//! actually lives, whatever put it there — Docker, systemd, Kubernetes. Reading
//! it directly means one collector covers all of them, and it means the figures
//! are the kernel's own accounting rather than something a runtime chose to
//! report about itself.
//!
//! The number worth having is the gap between the limit and the peak. Google's
//! Borg reclaims roughly a fifth of allocated resources this way — a job asks
//! for what it might need at worst, the scheduler reserves what it actually
//! uses plus a margin, and the difference goes to lower-priority work. At site
//! scale nobody is reclaiming anything automatically, but the same measurement
//! answers a question an operator does have: which of these limits was set by
//! guessing, and by how much.

use crate::psi::{Pressure, Psi};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where the unified hierarchy is mounted.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Memory limits and use for one group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    /// Bytes currently charged to the group.
    pub current: u64,
    /// Highest the group has ever reached. The kernel keeps this for us, which
    /// is why rightsizing does not need a sampling loop to be roughly right.
    pub peak: Option<u64>,
    /// Hard limit. Exceeding it invokes the OOM killer on the group.
    pub max: Option<u64>,
    /// Throttling threshold. Above it the kernel reclaims aggressively and
    /// slows the group down instead of killing it.
    pub high: Option<u64>,
    /// Anonymous bytes — heap, stacks, anything not backed by a file.
    ///
    /// The distinction decides whether throttling this group is safe.
    /// Reclaiming file-backed pages costs a soft fault; reclaiming anonymous
    /// pages means swapping them, and a garbage collector faults them straight
    /// back in.
    pub anon: u64,
    /// File-backed bytes, which reclaim cheaply.
    pub file: u64,
    /// Swap ceiling for this group. `Some(0)` means swap is disabled here.
    pub swap_max: Option<u64>,
}

impl Memory {
    /// Fraction of the hard limit in use.
    pub fn utilisation(&self) -> Option<f64> {
        self.max.filter(|m| *m > 0).map(|m| self.current as f64 / m as f64)
    }

    /// Whether most of this group's memory is anonymous.
    ///
    /// True of anything with a large heap — a JVM, a database buffer pool.
    /// Such a group cannot be throttled safely while it can still swap.
    pub fn is_anon_heavy(&self) -> bool {
        let total = self.anon + self.file;
        total > 0 && (self.anon as f64 / total as f64) > 0.6
    }

    /// Whether throttling this group would make the kernel swap its heap.
    ///
    /// The trap this exists to name: `memory.high` on an anonymous-heavy group
    /// that can still swap converts a fast, clean kill into a thrash spiral —
    /// reclaim pushes heap pages to swap, the collector faults them back, the
    /// process slows, so it stays under pressure longer and swaps more. Worse
    /// than the kill it replaces, and far harder to diagnose.
    pub fn throttling_would_thrash(&self) -> bool {
        self.is_anon_heavy() && !matches!(self.swap_max, Some(0))
    }

    /// Whether the group has a throttling threshold below its hard limit.
    ///
    /// Without one, a group goes from healthy to OOM-killed with nothing in
    /// between. With one, the kernel reclaims and slows it down first, which
    /// usually lets it recover — and when it does not, the slowdown is visible
    /// as memory pressure long before anything dies. Setting `high` ten to
    /// twenty percent below `max` is the standard advice and it is almost
    /// never done.
    pub fn has_throttle_margin(&self) -> bool {
        match (self.high, self.max) {
            (Some(h), Some(m)) => h < m,
            _ => false,
        }
    }
}

/// CPU accounting for one group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cpu {
    pub usage_usec: u64,
    /// Times the group was throttled by its quota, where one is set.
    pub throttled_usec: u64,
    pub nr_throttled: u64,
}

/// What put a control group there.
///
/// It decides how a limit is changed *persistently*, which is the only kind of
/// change worth recommending. A systemd unit takes `set-property`. A container
/// scope also takes it, and loses it the moment the container is recreated —
/// so the durable place for a container's limit is the file that creates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Unit,
    Container,
}

/// One control group: what it is, what it has, what it uses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Group {
    /// Path relative to the hierarchy root.
    pub path: String,
    /// A friendlier name — the unit or container it belongs to.
    pub name: String,
    pub owner: Owner,
    pub memory: Memory,
    pub cpu: Cpu,
    /// Pressure inside this group specifically. The figure that says *which*
    /// workload is causing a machine's stall rather than that one is.
    pub psi: Psi,
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_u64(base: &Path, file: &str) -> Option<u64> {
    read(&base.join(file))?.parse().ok()
}

/// Read a limit file, where the literal `max` means unlimited.
fn read_limit(base: &Path, file: &str) -> Option<u64> {
    match read(&base.join(file))?.as_str() {
        "max" => None,
        v => v.parse().ok(),
    }
}

/// One field out of `memory.stat`.
fn stat_field(base: &Path, key: &str) -> u64 {
    read(&base.join("memory.stat"))
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix(&format!("{key} "))?.parse().ok())
        })
        .unwrap_or(0)
}

fn read_pressure(base: &Path, file: &str) -> Pressure {
    read(&base.join(file))
        .and_then(|t| Pressure::parse(&t))
        .unwrap_or_default()
}

impl Group {
    /// Read one group from the hierarchy.
    pub fn read(root: &Path, rel: &str, name: &str, owner: Owner) -> Option<Self> {
        let base = root.join(rel.trim_start_matches('/'));
        if !base.is_dir() {
            return None;
        }
        let cpu_stat = read(&base.join("cpu.stat")).unwrap_or_default();
        let mut cpu = Cpu::default();
        for line in cpu_stat.lines() {
            let mut f = line.split_whitespace();
            match (f.next(), f.next().and_then(|v| v.parse::<u64>().ok())) {
                (Some("usage_usec"), Some(v)) => cpu.usage_usec = v,
                (Some("throttled_usec"), Some(v)) => cpu.throttled_usec = v,
                (Some("nr_throttled"), Some(v)) => cpu.nr_throttled = v,
                _ => {}
            }
        }

        Some(Group {
            path: rel.to_string(),
            name: name.to_string(),
            owner,
            memory: Memory {
                current: read_u64(&base, "memory.current").unwrap_or(0),
                peak: read_u64(&base, "memory.peak"),
                max: read_limit(&base, "memory.max"),
                high: read_limit(&base, "memory.high"),
                anon: stat_field(&base, "anon"),
                file: stat_field(&base, "file"),
                // `max` here means unlimited swap, which is the default and is
                // exactly the condition that makes throttling dangerous.
                swap_max: read_limit(&base, "memory.swap.max").or_else(|| {
                    read(&base.join("memory.swap.max")).and_then(|v| {
                        if v == "max" { None } else { v.parse().ok() }
                    })
                }),
            },
            cpu,
            psi: Psi {
                cpu: read_pressure(&base, "cpu.pressure"),
                memory: read_pressure(&base, "memory.pressure"),
                io: read_pressure(&base, "io.pressure"),
            },
        })
    }
}

/// Whether the unified hierarchy is in use here.
///
/// Returns false on a v1 or hybrid system, where none of this applies and the
/// honest response is to report nothing rather than to read v1 files that mean
/// something subtly different.
pub fn unified_hierarchy(root: &Path) -> bool {
    root.join("cgroup.controllers").exists()
}

/// Find the control group directory for a container or unit by name.
///
/// Searches the two places anything on this kind of host actually lives, which
/// is cheaper and more predictable than walking the whole tree.
pub fn find(root: &Path, needle: &str) -> Option<(String, PathBuf)> {
    for slice in ["system.slice", "user.slice", "kubepods.slice", ""] {
        let dir = if slice.is_empty() {
            root.to_path_buf()
        } else {
            root.join(slice)
        };
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.filter_map(|e| e.ok()) {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.contains(needle) && e.path().is_dir() {
                let rel = if slice.is_empty() {
                    n
                } else {
                    format!("{slice}/{n}")
                };
                return Some((rel.clone(), root.join(rel)));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(current: u64, peak: Option<u64>, max: Option<u64>, high: Option<u64>) -> Memory {
        Memory { current, peak, max, high, anon: 0, file: 0, swap_max: None }
    }

    #[test]
    fn a_limit_of_max_reads_as_unlimited_rather_than_zero() {
        // The kernel writes the literal string `max`. Parsing it as a number
        // fails, and defaulting that to zero would make every unlimited group
        // look permanently over its limit.
        let m = mem(1000, None, None, None);
        assert!(m.utilisation().is_none());
    }

    #[test]
    fn utilisation_is_against_the_hard_limit() {
        let m = mem(1_715_724_288, None, Some(8_589_934_592), None);
        assert!((m.utilisation().unwrap() - 0.2).abs() < 0.01);
    }

    #[test]
    fn a_group_with_no_throttle_margin_goes_straight_from_healthy_to_killed() {
        // The common case, and the one worth flagging: `memory.high` is unset
        // on almost everything, so there is nothing between running fine and
        // the OOM killer.
        let m = mem(1000, None, Some(8_589_934_592), None);
        assert!(!m.has_throttle_margin());
    }

    #[test]
    fn a_group_with_high_below_max_has_somewhere_to_slow_down() {
        let m = mem(1000, None, Some(8_589_934_592), Some(7_000_000_000));
        assert!(m.has_throttle_margin());
    }

    #[test]
    fn high_at_the_same_value_as_max_is_not_a_margin() {
        // It would be reclaimed and killed at the same threshold, which buys
        // nothing.
        let m = mem(1000, None, Some(8_000_000_000), Some(8_000_000_000));
        assert!(!m.has_throttle_margin());
    }

    #[test]
    fn this_machine_uses_the_unified_hierarchy() {
        // Everything in this module assumes v2. If a host is on v1 or hybrid
        // the collector must report nothing rather than read v1 files whose
        // semantics differ.
        let root = Path::new(CGROUP_ROOT);
        if root.exists() {
            assert!(unified_hierarchy(root), "expected cgroup v2 on this host");
        }
    }

    #[test]
    fn reading_a_group_that_does_not_exist_yields_nothing() {
        assert!(Group::read(Path::new(CGROUP_ROOT), "no/such/group", "x", Owner::Unit).is_none());
    }

    #[test]
    fn the_agents_own_group_can_be_read_on_this_machine() {
        // A weak check by design: it must not fail on a machine where the
        // agent is not running under systemd, such as a developer's laptop.
        let root = Path::new(CGROUP_ROOT);
        if !root.exists() || !unified_hierarchy(root) {
            return;
        }
        if let Some((rel, _)) = find(root, "furcated") {
            let g = Group::read(root, &rel, "furcated", Owner::Unit).expect("group readable");
            assert!(g.memory.current > 0, "a running process charges memory");
        }
    }
}

#[cfg(test)]
mod thrash_tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn jvm_like(swap_max: Option<u64>) -> Memory {
        Memory {
            current: 5 * GIB,
            peak: Some(6 * GIB),
            max: Some(8 * GIB),
            high: None,
            anon: 5 * GIB,
            file: 275 * 1024 * 1024,
            swap_max,
        }
    }

    #[test]
    fn a_heap_heavy_group_is_recognised_as_anonymous() {
        // Measured on this site's validators: about 1.2 GiB anonymous against
        // 275 MiB of page cache.
        assert!(jvm_like(None).is_anon_heavy());
    }

    #[test]
    fn a_cache_heavy_group_is_not() {
        let m = Memory {
            anon: 100 * 1024 * 1024,
            file: 4 * GIB,
            ..jvm_like(None)
        };
        assert!(!m.is_anon_heavy());
    }

    #[test]
    fn throttling_a_swappable_jvm_would_thrash() {
        // The lesson this encodes, learned the hard way: memory.high on an
        // anonymous-heavy group that can still swap converts a fast kill into
        // a slow spiral.
        assert!(jvm_like(None).throttling_would_thrash());
    }

    #[test]
    fn disabling_swap_for_the_group_makes_throttling_safe() {
        assert!(!jvm_like(Some(0)).throttling_would_thrash());
    }

    #[test]
    fn a_cache_heavy_group_can_be_throttled_even_with_swap_on() {
        // Reclaim drops page cache, which costs a soft fault rather than a
        // swap round trip.
        let m = Memory { anon: 100 * 1024 * 1024, file: 4 * GIB, ..jvm_like(None) };
        assert!(!m.throttling_would_thrash());
    }
}
