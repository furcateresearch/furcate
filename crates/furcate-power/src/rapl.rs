//! Reading energy from the processor.
//!
//! RAPL exposes cumulative energy counters through the powercap subsystem.
//! Two things about them shape this module. They are **cumulative and
//! wrapping**, so a reading on its own means nothing — only a difference over
//! a known interval is power. And since the Platypus disclosure the counters
//! are readable only by root, so an unprivileged agent needs a helper rather
//! than direct access.
//!
//! What RAPL measures is also worth stating plainly, because it is easy to
//! quote a number that is a fraction of the truth: the processor package, and
//! optionally DRAM. Not disks, not fans, not the loss in the power supply. A
//! package figure is a lower bound on system draw and should never be
//! presented as wall power.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where the kernel exposes powercap domains.
pub const POWERCAP_ROOT: &str = "/sys/class/powercap";

/// What a reading actually covers, carried alongside the number so a consumer
/// cannot mistake a package figure for the whole machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Processor package.
    Package,
    /// Memory controller.
    Dram,
    /// Measured at the inlet by a meter that sees everything.
    Wall,
}

impl Scope {
    /// Whether this scope accounts for the whole machine.
    pub fn is_complete(&self) -> bool {
        matches!(self, Scope::Wall)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Package => "package",
            Scope::Dram => "dram",
            Scope::Wall => "wall",
        }
    }
}

/// A cumulative energy counter reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub microjoules: u64,
    /// Milliseconds since an arbitrary epoch, from a monotonic source.
    pub at_ms: u64,
}

/// Average power over an interval.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Power {
    pub watts: f64,
    pub scope: Scope,
    pub interval_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RaplError {
    /// The domain does not exist on this platform.
    NoDomain(String),
    /// The counter exists but could not be read. Almost always permissions:
    /// the counters are root-only.
    Unreadable(String),
    /// Two samples were taken at the same instant, so no rate can be derived.
    ZeroInterval,
}

impl std::fmt::Display for RaplError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaplError::NoDomain(d) => write!(f, "no powercap domain at {d}"),
            RaplError::Unreadable(d) => write!(
                f,
                "cannot read {d}; energy counters are root-only since the Platypus mitigation"
            ),
            RaplError::ZeroInterval => {
                write!(f, "two samples at the same instant give no rate")
            }
        }
    }
}

impl std::error::Error for RaplError {}

/// Convert two counter readings into average power.
///
/// Handles the counter wrapping at `max_range`. A naive subtraction would
/// produce a wildly negative figure once per wrap, which on this hardware is
/// roughly every 262 seconds at full load — often enough that ignoring it
/// would corrupt any long-running average.
pub fn power_between(a: Sample, b: Sample, max_range_uj: u64, scope: Scope) -> Result<Power, RaplError> {
    let interval_ms = b.at_ms.saturating_sub(a.at_ms);
    if interval_ms == 0 {
        return Err(RaplError::ZeroInterval);
    }
    let delta_uj = if b.microjoules >= a.microjoules {
        b.microjoules - a.microjoules
    } else {
        // Wrapped.
        max_range_uj.saturating_sub(a.microjoules) + b.microjoules
    };
    Ok(Power {
        watts: (delta_uj as f64) / (interval_ms as f64 * 1000.0),
        scope,
        interval_ms,
    })
}

/// A powercap domain on this machine.
#[derive(Clone, Debug)]
pub struct Domain {
    pub path: PathBuf,
    pub name: String,
    pub scope: Scope,
    pub max_range_uj: u64,
}

/// Enumerate the domains this platform exposes.
///
/// Returns an empty list rather than an error when powercap is absent: a
/// machine with no RAPL is a normal member of a heterogeneous fleet, and it
/// should report that it cannot account for itself rather than fail to start.
pub fn discover(root: &Path) -> Vec<Domain> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        let Some(dir) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Sub-domains carry a second colon, e.g. intel-rapl:0:0. Only the
        // top-level package domains are enumerated here; a caller wanting core
        // or uncore detail can walk into them.
        if !dir.starts_with("intel-rapl:") || dir.matches(':').count() != 1 {
            continue;
        }
        let name = std::fs::read_to_string(p.join("name"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| dir.to_string());
        let scope = if name.contains("dram") {
            Scope::Dram
        } else {
            Scope::Package
        };
        let max_range_uj = std::fs::read_to_string(p.join("max_energy_range_uj"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(u64::MAX);
        out.push(Domain {
            path: p,
            name,
            scope,
            max_range_uj,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Attribute a share of package power to one process.
///
/// The approach Scaphandre uses: package energy is real, per-process energy is
/// not measurable, so the package figure is divided by the ratio of CPU time
/// the process consumed to the CPU time consumed by everything. It is an
/// estimate and should be described as one.
///
/// `process_jiffies` and `total_jiffies` are both deltas over the same
/// interval as the power figure.
pub fn attribute(power: Power, process_jiffies: u64, total_jiffies: u64) -> f64 {
    if total_jiffies == 0 {
        return 0.0;
    }
    let share = (process_jiffies as f64 / total_jiffies as f64).clamp(0.0, 1.0);
    power.watts * share
}

/// Energy for a unit of work, which is the figure worth optimising.
pub fn joules_per_unit(power: Power, duration_ms: u64, units: u64) -> Option<f64> {
    if units == 0 || duration_ms == 0 {
        return None;
    }
    Some(power.watts * (duration_ms as f64 / 1000.0) / units as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_is_a_rate_not_a_reading() {
        let a = Sample { microjoules: 1_000_000, at_ms: 0 };
        let b = Sample { microjoules: 3_000_000, at_ms: 1000 };
        let p = power_between(a, b, u64::MAX, Scope::Package).unwrap();
        assert_eq!(p.watts, 2.0);
    }

    #[test]
    fn a_wrapped_counter_does_not_produce_negative_power() {
        // The failure this exists to prevent: on this hardware the counter
        // wraps roughly every 262 s at load.
        let max = 262_143_328_850u64;
        let a = Sample { microjoules: max - 1_000_000, at_ms: 0 };
        let b = Sample { microjoules: 1_000_000, at_ms: 1000 };
        let p = power_between(a, b, max, Scope::Package).unwrap();
        assert_eq!(p.watts, 2.0);
        assert!(p.watts > 0.0);
    }

    #[test]
    fn two_samples_at_one_instant_are_refused() {
        let a = Sample { microjoules: 0, at_ms: 5 };
        let b = Sample { microjoules: 100, at_ms: 5 };
        assert_eq!(
            power_between(a, b, u64::MAX, Scope::Package),
            Err(RaplError::ZeroInterval)
        );
    }

    #[test]
    fn scope_says_whether_the_figure_is_the_whole_machine() {
        assert!(!Scope::Package.is_complete());
        assert!(!Scope::Dram.is_complete());
        assert!(Scope::Wall.is_complete());
    }

    #[test]
    fn attribution_splits_by_cpu_time() {
        let p = Power { watts: 20.0, scope: Scope::Package, interval_ms: 1000 };
        assert_eq!(attribute(p, 250, 1000), 5.0);
        assert_eq!(attribute(p, 1000, 1000), 20.0);
    }

    #[test]
    fn attribution_cannot_exceed_the_package() {
        // A process cannot consume more CPU time than the machine had.
        let p = Power { watts: 20.0, scope: Scope::Package, interval_ms: 1000 };
        assert_eq!(attribute(p, 5000, 1000), 20.0);
    }

    #[test]
    fn an_idle_machine_attributes_nothing_rather_than_dividing_by_zero() {
        let p = Power { watts: 13.0, scope: Scope::Package, interval_ms: 1000 };
        assert_eq!(attribute(p, 0, 0), 0.0);
    }

    #[test]
    fn energy_per_unit_matches_the_measured_figure() {
        // The real measurement from node-a: 29 W for 3,138 ms, 86 tokens.
        let p = Power { watts: 29.0, scope: Scope::Package, interval_ms: 3138 };
        let j = joules_per_unit(p, 3138, 86).unwrap();
        assert!((j - 1.058).abs() < 0.01, "got {j}");
    }

    #[test]
    fn zero_units_has_no_cost_per_unit() {
        let p = Power { watts: 29.0, scope: Scope::Package, interval_ms: 1000 };
        assert!(joules_per_unit(p, 1000, 0).is_none());
    }

    #[test]
    fn a_machine_without_powercap_reports_no_domains_rather_than_failing() {
        assert!(discover(Path::new("/nonexistent/powercap")).is_empty());
    }
}
