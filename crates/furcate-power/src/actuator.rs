//! The levers that change how much power a machine draws.
//!
//! Every action here is bounded by construction. A power manager that can set
//! an arbitrary value is a power manager that can set zero, and a node capped
//! to nothing is a node that has effectively been taken offline by a
//! subsystem that was only supposed to make it more efficient.
//!
//! So each lever declares its own floor, and a request below the floor is
//! clamped and reported rather than obeyed silently.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The lowest performance ceiling that may be requested.
///
/// `intel_pstate` accepts values down to a few percent, which would make a
/// machine technically alive and practically useless — and, worse, would take
/// far longer to finish the same work, quite possibly using *more* energy.
/// Race-to-idle is real on these parts.
pub const MIN_PERF_FLOOR_PCT: u8 = 40;

/// The lowest package cap that may be requested, as a fraction of the
/// platform maximum. Below this the processor spends its time throttling
/// rather than working.
pub const MIN_CAP_FRACTION: f64 = 0.35;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Governor {
    Performance,
    Powersave,
}

impl Governor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Governor::Performance => "performance",
            Governor::Powersave => "powersave",
        }
    }
}

/// A requested change to how a machine draws power.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lever {
    /// Ceiling on processor performance, as a percentage.
    MaxPerfPct(u8),
    /// Package power cap, in watts.
    PackageCapWatts(u32),
    /// Frequency governor.
    Governor(Governor),
    /// Whether turbo/boost may be used.
    Turbo(bool),
}

impl fmt::Display for Lever {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lever::MaxPerfPct(p) => write!(f, "max_perf_pct={p}"),
            Lever::PackageCapWatts(w) => write!(f, "package_cap={w}W"),
            Lever::Governor(g) => write!(f, "governor={}", g.as_str()),
            Lever::Turbo(on) => write!(f, "turbo={}", if *on { "on" } else { "off" }),
        }
    }
}

/// What happened to a requested lever setting.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum Applied {
    /// Applied as requested.
    Exact(Lever),
    /// Clamped to a safe bound. Carries both so the caller can see the gap.
    Clamped { requested: Lever, applied: Lever },
    /// The platform does not offer this lever.
    Unsupported(Lever),
}

impl Applied {
    pub fn lever(&self) -> Lever {
        match self {
            Applied::Exact(l) => *l,
            Applied::Clamped { applied, .. } => *applied,
            Applied::Unsupported(l) => *l,
        }
    }

    pub fn was_clamped(&self) -> bool {
        matches!(self, Applied::Clamped { .. })
    }
}

/// What a given machine can actually do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub has_pstate: bool,
    pub has_powercap: bool,
    pub governors: Vec<Governor>,
    /// Platform maximum package power, in watts.
    pub max_package_watts: u32,
    pub has_turbo: bool,
}

impl Capabilities {
    /// A machine that offers nothing. The honest default for hardware whose
    /// levers have not been probed.
    pub fn none() -> Self {
        Self {
            has_pstate: false,
            has_powercap: false,
            governors: Vec::new(),
            max_package_watts: 0,
            has_turbo: false,
        }
    }

    /// The Xeons on this site, as measured.
    pub fn xeon_e5_1660_v4() -> Self {
        Self {
            has_pstate: true,
            has_powercap: true,
            governors: vec![Governor::Performance, Governor::Powersave],
            max_package_watts: 140,
            has_turbo: true,
        }
    }
}

/// Decide what a lever request becomes on a given machine.
///
/// Pure: it computes the outcome without touching the system, so the policy
/// can be tested exhaustively and the same decision can be logged before it is
/// carried out.
pub fn resolve(caps: &Capabilities, requested: Lever) -> Applied {
    match requested {
        Lever::MaxPerfPct(pct) => {
            if !caps.has_pstate {
                return Applied::Unsupported(requested);
            }
            let clamped = pct.clamp(MIN_PERF_FLOOR_PCT, 100);
            if clamped == pct {
                Applied::Exact(requested)
            } else {
                Applied::Clamped {
                    requested,
                    applied: Lever::MaxPerfPct(clamped),
                }
            }
        }
        Lever::PackageCapWatts(w) => {
            if !caps.has_powercap || caps.max_package_watts == 0 {
                return Applied::Unsupported(requested);
            }
            let floor = (caps.max_package_watts as f64 * MIN_CAP_FRACTION).ceil() as u32;
            let clamped = w.clamp(floor, caps.max_package_watts);
            if clamped == w {
                Applied::Exact(requested)
            } else {
                Applied::Clamped {
                    requested,
                    applied: Lever::PackageCapWatts(clamped),
                }
            }
        }
        Lever::Governor(g) => {
            if caps.governors.contains(&g) {
                Applied::Exact(requested)
            } else {
                Applied::Unsupported(requested)
            }
        }
        Lever::Turbo(_) => {
            if caps.has_turbo {
                Applied::Exact(requested)
            } else {
                Applied::Unsupported(requested)
            }
        }
    }
}

/// Split a required reduction evenly across the machines carrying a job.
///
/// The ladder reduces one machine, which for anything synchronous is the worst
/// available choice: one slow worker sets the pace for all of them, so taking
/// the whole reduction from a single node costs the job far more throughput
/// than it saves in watts. Published analysis of large training fleets states
/// the rule plainly — to reclaim P watts from a job spanning N machines, take
/// P/N from each rather than P from one.
///
/// Returns the per-node share. An empty fleet yields `None` rather than
/// dividing by zero, and a negative request yields `None` rather than quietly
/// handing back extra power to machines that were never throttled.
pub fn spread_reduction(total_w: f64, nodes: usize) -> Option<f64> {
    if nodes == 0 || !total_w.is_finite() || total_w <= 0.0 {
        return None;
    }
    Some(total_w / nodes as f64)
}

/// Where each lever is written on Linux.
///
/// Returned rather than written so the privileged helper is the only thing that
/// touches sysfs, and so a caller can log exactly what would change.
///
/// Nothing in the running system calls this, and that is deliberate rather than
/// an oversight: the writes happen in `deploy/furcate-actuator.sh`, on the other
/// side of a privilege boundary, in a different language. What this is for is
/// keeping the two honest. The paths and the turbo inversion are encoded in both
/// places, and a test below reads the shell script and checks it still agrees —
/// so a change to one that forgets the other fails the build instead of shipping
/// a lever that silently writes the wrong file, or raises power while trying to
/// lower it.
pub fn sysfs_write(lever: Lever, max_package_watts: u32) -> Option<(String, String)> {
    let _ = max_package_watts;
    match lever {
        Lever::MaxPerfPct(p) => Some((
            "/sys/devices/system/cpu/intel_pstate/max_perf_pct".into(),
            p.to_string(),
        )),
        Lever::PackageCapWatts(w) => Some((
            "/sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw".into(),
            (w as u64 * 1_000_000).to_string(),
        )),
        Lever::Governor(g) => Some((
            "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor".into(),
            g.as_str().to_string(),
        )),
        // The kernel's flag is inverted: no_turbo=1 disables it.
        Lever::Turbo(on) => Some((
            "/sys/devices/system/cpu/intel_pstate/no_turbo".into(),
            if on { "0".into() } else { "1".into() },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xeon() -> Capabilities {
        Capabilities::xeon_e5_1660_v4()
    }

    #[test]
    fn a_reasonable_request_applies_exactly() {
        assert_eq!(
            resolve(&xeon(), Lever::MaxPerfPct(70)),
            Applied::Exact(Lever::MaxPerfPct(70))
        );
    }

    #[test]
    fn a_crushing_performance_request_is_clamped_not_obeyed() {
        // Below the floor a machine takes so much longer to finish that it can
        // use more energy, not less.
        let a = resolve(&xeon(), Lever::MaxPerfPct(5));
        assert!(a.was_clamped());
        assert_eq!(a.lever(), Lever::MaxPerfPct(MIN_PERF_FLOOR_PCT));
    }

    #[test]
    fn a_cap_of_zero_cannot_take_a_node_offline() {
        let a = resolve(&xeon(), Lever::PackageCapWatts(0));
        assert!(a.was_clamped());
        // 35% of 140 W.
        assert_eq!(a.lever(), Lever::PackageCapWatts(49));
    }

    #[test]
    fn a_cap_above_the_platform_maximum_is_clamped_down() {
        let a = resolve(&xeon(), Lever::PackageCapWatts(500));
        assert!(a.was_clamped());
        assert_eq!(a.lever(), Lever::PackageCapWatts(140));
    }

    #[test]
    fn a_governor_the_platform_lacks_is_unsupported_not_clamped() {
        let mut caps = xeon();
        caps.governors = vec![Governor::Powersave];
        assert_eq!(
            resolve(&caps, Lever::Governor(Governor::Performance)),
            Applied::Unsupported(Lever::Governor(Governor::Performance))
        );
    }

    #[test]
    fn a_machine_with_no_levers_reports_unsupported_for_everything() {
        let none = Capabilities::none();
        for l in [
            Lever::MaxPerfPct(50),
            Lever::PackageCapWatts(50),
            Lever::Governor(Governor::Powersave),
            Lever::Turbo(false),
        ] {
            assert!(matches!(resolve(&none, l), Applied::Unsupported(_)), "{l}");
        }
    }

    #[test]
    fn clamping_reports_both_numbers_so_the_gap_is_visible() {
        match resolve(&xeon(), Lever::MaxPerfPct(10)) {
            Applied::Clamped { requested, applied } => {
                assert_eq!(requested, Lever::MaxPerfPct(10));
                assert_eq!(applied, Lever::MaxPerfPct(40));
            }
            other => panic!("expected a clamp, got {other:?}"),
        }
    }

    #[test]
    fn a_reduction_is_spread_rather_than_taken_from_one_machine() {
        // One slow worker sets the pace for a synchronous job, so taking the
        // whole reduction from a single node costs more throughput than it
        // saves in watts.
        assert_eq!(spread_reduction(60.0, 3), Some(20.0));
        assert_eq!(spread_reduction(60.0, 1), Some(60.0));
    }

    #[test]
    fn an_empty_fleet_yields_nothing_rather_than_dividing_by_zero() {
        assert_eq!(spread_reduction(60.0, 0), None);
    }

    #[test]
    fn a_negative_reduction_does_not_hand_out_extra_power() {
        // Machines that were never throttled must not be given headroom by a
        // sign error somewhere upstream.
        assert_eq!(spread_reduction(-60.0, 3), None);
        assert_eq!(spread_reduction(0.0, 3), None);
        assert_eq!(spread_reduction(f64::NAN, 3), None);
    }

    #[test]
    fn the_turbo_flag_is_inverted_when_written() {
        // no_turbo=1 disables turbo. Getting this backwards would raise power
        // while trying to lower it.
        let (_, off) = sysfs_write(Lever::Turbo(false), 140).unwrap();
        let (_, on) = sysfs_write(Lever::Turbo(true), 140).unwrap();
        assert_eq!(off, "1");
        assert_eq!(on, "0");
    }

    #[test]
    fn the_cap_is_written_in_microwatts() {
        let (path, value) = sysfs_write(Lever::PackageCapWatts(90), 140).unwrap();
        assert!(path.contains("power_limit_uw"));
        assert_eq!(value, "90000000");
    }

    /// The privileged actuator is shell, on the other side of a privilege
    /// boundary, and neither half imports the other. This is the only thing
    /// holding them to the same kernel interface.
    fn actuator_script() -> Option<String> {
        // Relative to this crate, so it works from the workspace root or from
        // the crate directory. Absent in a package built without the deploy
        // directory, in which case there is nothing to check.
        // Found by walking up from the crate, so it works at either tree depth.
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|a| a.join("deploy/furcate-actuator.sh"))
            .find(|p| p.is_file())?;
        std::fs::read_to_string(p).ok()
    }

    #[test]
    fn the_shell_actuator_writes_the_same_paths_this_module_names() {
        let Some(sh) = actuator_script() else { return };
        for lever in [
            Lever::MaxPerfPct(60),
            Lever::PackageCapWatts(90),
            Lever::Governor(Governor::Powersave),
            Lever::Turbo(false),
        ] {
            let (path, _) = sysfs_write(lever, 140).unwrap();
            // The script builds some paths from a prefix variable, so the
            // final component is what is compared.
            let leaf = path.rsplit('/').next().unwrap();
            assert!(
                sh.contains(leaf),
                "the actuator script never mentions {leaf:?}, which {lever} writes"
            );
        }
    }

    #[test]
    fn both_halves_agree_that_no_turbo_is_inverted() {
        // The one place a disagreement would raise power while trying to lower
        // it, and it would look correct from either side alone.
        let Some(sh) = actuator_script() else { return };
        assert_eq!(sysfs_write(Lever::Turbo(true), 140).unwrap().1, "0");
        assert_eq!(sysfs_write(Lever::Turbo(false), 140).unwrap().1, "1");
        assert!(sh.contains(r#"on)  echo 0 > "$NT""#), "script must write 0 for on");
        assert!(sh.contains(r#"off) echo 1 > "$NT""#), "script must write 1 for off");
    }
}
