//! Reading contention and allocation on this machine.
//!
//! System pressure comes from `/proc/pressure`, per-workload pressure and
//! accounting from the cgroup v2 hierarchy. Both are files; neither costs
//! anything to read and neither perturbs what it measures, which matters
//! because the machines being measured are the machines doing the work.
//!
//! The groups examined are the ones already declared critical for workload
//! monitoring. Walking the whole hierarchy would produce hundreds of entries
//! every thirty seconds to say that nothing is wrong, and the interesting
//! groups are exactly the ones somebody already said they cannot do without.

use super::workloads;
use std::process::Command;
use furcate_resource::cgroup::{self, Group, Owner};
use furcate_resource::psi::{Kind, Pressure, Psi, Thresholds};
// Measuring the pressure is this module's job; advice on a different limit
// comes from the registered extension, if any.
use serde::{Deserialize, Serialize};
use std::path::Path;

const PROC_PRESSURE: &str = "/proc/pressure";

fn read_pressure(name: &str) -> Pressure {
    std::fs::read_to_string(format!("{PROC_PRESSURE}/{name}"))
        .ok()
        .and_then(|t| Pressure::parse(&t))
        .unwrap_or_default()
}

/// Pressure for the machine as a whole.
/// The rung sustained memory pressure justifies, if any.
///
/// Only `Stalled`, and only on memory. The distinction is the whole of the
/// judgement:
///
/// - `Stalled` means `full` pressure — *every* non-idle task blocked at once,
///   for a tenth of the last minute. On memory that is the signature of a
///   machine about to spend several minutes thrashing, and shedding is the
///   remedy rather than a precaution: it hands memory back.
/// - `Starved` is `some` pressure on a busy machine. Shedding there would kill
///   work on a machine that is loaded and fine, which is a worse outcome than
///   the problem.
///
/// Never past `Shed`. `Capture` and `Quiesce` flush state ahead of losing
/// power, and draining a database over a memory spike is a cure worse than the
/// disease — the machine is not going away, it is busy.
///
/// I/O and CPU are deliberately excluded. I/O stalling is real and shedding is
/// not obviously its remedy; CPU has no meaningful `full` on most kernels. A
/// ladder that descended on all three would descend constantly.
pub fn pressure_rung(psi: &Psi) -> Option<furcate_power::Rung> {
    let t = Thresholds::default();
    match t.judge(&psi.memory, Kind::Memory) {
        furcate_resource::psi::Level::Stalled => Some(furcate_power::Rung::Shed),
        _ => None,
    }
}

/// Memory pressure as a health signal, if it warrants one.
///
/// `is_actionable` is the vocabulary's own line for "worth doing something
/// about rather than noting", and this is the first thing to use it.
pub fn pressure_level(psi: &Psi) -> Option<&'static str> {
    let t = Thresholds::default();
    match t.judge(&psi.memory, Kind::Memory) {
        furcate_resource::psi::Level::Stalled => Some("stalled"),
        furcate_resource::psi::Level::Starved => Some("starved"),
        _ => None,
    }
}

pub fn system_psi() -> Option<Psi> {
    if !Path::new(PROC_PRESSURE).is_dir() {
        // A kernel built without PSI. Reporting zeros would say the machine is
        // calm when the truth is that nobody looked.
        return None;
    }
    Some(Psi {
        cpu: read_pressure("cpu"),
        memory: read_pressure("memory"),
        io: read_pressure("io"),
    })
}

/// Everything this machine can say about its own resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceReport {
    /// `None` when the kernel does not expose pressure at all.
    pub psi: Option<Psi>,
    /// The worst resource and how bad, when pressure is available.
    pub worst: Option<(String, String)>,
    /// Whether this node should be offered more work.
    pub can_take_more: Option<bool>,
    pub groups: Vec<Group>,
    /// True when the cgroup hierarchy could not be read, so an empty group
    /// list means "could not look" rather than "nothing is running".
    pub partial: bool,
}

/// Read pressure and control-group accounting.
pub fn collect() -> ResourceReport {
    let psi = system_psi();
    let t = Thresholds::default();
    let root = Path::new(cgroup::CGROUP_ROOT);
    let unified = cgroup::unified_hierarchy(root);

    let mut groups = Vec::new();
    if unified {
        // Containers first. Docker names their scope by container *id*, not by
        // container name, so searching the hierarchy for `mainnet-` finds
        // nothing — which is exactly what the first run of this collector did,
        // reporting two systemd units and none of the twelve containers that
        // matter most on this host.
        for (name, id) in container_ids() {
            if !workloads::is_critical_name(&name) {
                continue;
            }
            let rel = format!("system.slice/docker-{id}.scope");
            if let Some(g) = Group::read(root, &rel, &name, Owner::Container) {
                groups.push(g);
            }
        }
        for needle in workloads::critical_list() {
            if groups.iter().any(|g| g.name == needle) {
                continue;
            }
            if let Some((rel, _)) = cgroup::find(root, &needle) {
                if let Some(g) = Group::read(root, &rel, &needle, Owner::Unit) {
                    groups.push(g);
                }
            }
        }
    }
    groups.sort_by(|a, b| a.name.cmp(&b.name));

    ResourceReport {
        worst: psi.map(|p| {
            let (k, l) = p.worst(&t);
            (k.as_str().to_string(), format!("{l:?}").to_lowercase())
        }),
        can_take_more: psi.map(|p| p.can_take_more(&t)),
        psi,
        groups,
        partial: !unified,
    }
}

/// Container names paired with the ids their control groups are named after.
///
/// Empty when Docker is absent or unreadable, which the caller cannot
/// distinguish from "no containers" — and does not need to, because the
/// workload inventory already reports that gap as `partial`.
fn container_ids() -> Vec<(String, String)> {
    let Ok(out) = Command::new("docker")
        .args(["ps", "--format", "{{.Names}}\t{{.ID}}"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (name, short) = l.split_once('\t')?;
            // `docker ps` prints a truncated id; the scope carries the full
            // one, so the short form is resolved rather than guessed at.
            let full = Command::new("docker")
                .args(["inspect", "-f", "{{.Id}}", short.trim()])
                .output()
                .ok()
                .filter(|o| o.status.success())?;
            Some((
                name.trim().to_string(),
                String::from_utf8_lossy(&full.stdout).trim().to_string(),
            ))
        })
        .collect()
}

/// Contention expressed on the scale the control loop reasons in.
///
/// Not a utilisation figure and not pretending to be one. It is the share of
/// the last minute during which *something* could not proceed, taken across
/// the three resources — which is the quantity a scheduler should key on,
/// because a machine at full utilisation and zero stall has capacity to spare
/// while one at half utilisation and heavy stall does not.
pub fn contention(psi: &Psi) -> f64 {
    [Kind::Cpu, Kind::Memory, Kind::Io]
        .into_iter()
        .map(|k| psi.of(k).some.avg60)
        .fold(0.0f64, f64::max)
        / 100.0
}

/// Named scalar series for the forecaster.
pub fn series_points(r: &ResourceReport) -> Vec<(String, f64)> {
    let Some(psi) = &r.psi else { return Vec::new() };
    vec![
        ("psi_cpu_some".to_string(), psi.cpu.some.avg60),
        ("psi_memory_some".to_string(), psi.memory.some.avg60),
        ("psi_memory_full".to_string(), psi.memory.full.avg60),
        ("psi_io_some".to_string(), psi.io.some.avg60),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_without_pressure_reports_nothing_rather_than_calm() {
        // Zeros would say the machine is fine when the truth is that nobody
        // looked, which is the worst direction to be wrong in.
        let r = collect();
        if !Path::new(PROC_PRESSURE).is_dir() {
            assert!(r.psi.is_none());
            assert!(r.can_take_more.is_none());
        }
    }

    #[test]
    fn this_kernel_does_expose_pressure() {
        // Every kernel this fleet runs has it; if that stops being true the
        // collector degrades rather than lying, but it is worth noticing.
        if Path::new(PROC_PRESSURE).is_dir() {
            assert!(system_psi().is_some());
        }
    }

    #[test]
    fn contention_is_a_fraction_and_takes_the_worst_resource() {
        let mut psi = Psi::default();
        psi.cpu.some.avg60 = 4.0;
        psi.memory.some.avg60 = 37.0;
        psi.io.some.avg60 = 12.0;
        assert!((contention(&psi) - 0.37).abs() < 1e-9);
    }

    #[test]
    fn a_calm_machine_has_no_contention() {
        assert_eq!(contention(&Psi::default()), 0.0);
    }

    #[test]
    fn series_are_emitted_only_when_pressure_was_actually_read() {
        let empty = ResourceReport {
            psi: None,
            worst: None,
            can_take_more: None,
            groups: vec![],
            partial: true,
        };
        assert!(series_points(&empty).is_empty());
    }

    #[test]
    fn collecting_on_this_machine_produces_an_answer_rather_than_a_panic() {
        let r = collect();
        // Either the hierarchy was readable or the report says it was not.
        assert!(!r.partial || r.groups.is_empty());
    }
}


#[cfg(test)]
mod pressure_tests {
    use super::*;
    use furcate_resource::psi::{Pressure, Share};

    /// A reading with the given `some` and `full` sixty-second averages.
    fn mem(some60: f64, full60: f64) -> Psi {
        Psi {
            memory: Pressure {
                some: Share { avg10: 0.0, avg60: some60, avg300: 0.0, total_us: 0 },
                full: Share { avg10: 0.0, avg60: full60, avg300: 0.0, total_us: 0 },
            },
            ..Psi::default()
        }
    }

    /// **The case that wedges a machine.** Every non-idle task blocked for a
    /// tenth of the last minute is the death-spiral signature, and until now
    /// the daemon measured it, reported it on /resources, and did nothing --
    /// so the machine thrashed until something outside it intervened.
    #[test]
    fn a_stalled_machine_descends_to_shed() {
        assert_eq!(
            pressure_rung(&mem(40.0, 15.0)),
            Some(furcate_power::Rung::Shed)
        );
        assert_eq!(pressure_level(&mem(40.0, 15.0)), Some("stalled"));
    }

    /// **And a busy machine is left alone.** `some` pressure is what a loaded
    /// machine does: one task waiting while others run. Shedding there would
    /// destroy work on a machine that is fine, which is worse than the problem
    /// it would be solving.
    #[test]
    fn a_busy_machine_is_not_shed() {
        // Well past `some_starved` at 20%, with nothing fully stalled.
        assert_eq!(pressure_rung(&mem(55.0, 0.0)), None);
        assert_eq!(
            pressure_level(&mem(55.0, 0.0)),
            Some("starved"),
            "still worth seeing, just not worth shedding over"
        );
    }

    /// An idle machine says nothing at all. Without this the signal would be
    /// permanent and the list would carry a fact about every machine.
    #[test]
    fn a_quiet_machine_reports_nothing() {
        assert_eq!(pressure_rung(&mem(0.5, 0.0)), None);
        assert_eq!(pressure_level(&mem(0.5, 0.0)), None);
    }

    /// **Never past Shed.** `Capture` and `Quiesce` flush state ahead of losing
    /// power. A machine under memory pressure is not going away -- draining its
    /// databases would be a cure worse than the disease, and would take the
    /// site down over a spike.
    #[test]
    fn pressure_never_descends_past_shedding() {
        for full in [10.0, 50.0, 99.9, 100.0] {
            let r = pressure_rung(&mem(100.0, full));
            assert_eq!(
                r,
                Some(furcate_power::Rung::Shed),
                "{full}% full pressure must not reach Capture or Quiesce"
            );
        }
    }

    /// I/O and CPU are excluded deliberately. Shedding is not obviously the
    /// remedy for I/O stalling, CPU has no meaningful `full` on most kernels,
    /// and a ladder descending on all three would descend constantly.
    #[test]
    fn only_memory_descends_the_ladder() {
        let io_bound = Psi {
            io: Pressure {
                some: Share { avg10: 0.0, avg60: 90.0, avg300: 0.0, total_us: 0 },
                full: Share { avg10: 0.0, avg60: 80.0, avg300: 0.0, total_us: 0 },
            },
            cpu: Pressure {
                some: Share { avg10: 0.0, avg60: 95.0, avg300: 0.0, total_us: 0 },
                full: Share::default(),
            },
            ..Psi::default()
        };
        assert_eq!(pressure_rung(&io_bound), None);
        assert_eq!(pressure_level(&io_bound), None);
    }

    /// The threshold is the one the pressure vocabulary already defines, not a
    /// second number here. Two thresholds for one question would eventually
    /// disagree.
    #[test]
    fn the_threshold_is_the_shared_one() {
        let t = Thresholds::default();
        assert_eq!(pressure_rung(&mem(0.0, t.full_stalled - 0.1)), None);
        assert_eq!(
            pressure_rung(&mem(0.0, t.full_stalled)),
            Some(furcate_power::Rung::Shed),
            "at the threshold, not past it"
        );
    }
}
