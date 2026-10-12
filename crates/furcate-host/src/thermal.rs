//! Bounding what a machine is allowed to draw, and therefore how loud it gets.
//!
//! [`crate::cooling`] measures the cooling system and refuses to touch it. This
//! is the other half: the levers that *are* safe to pull, and the reasoning for
//! why these and not the fans.
//!
//! # The asymmetry that decides what may be actuated
//!
//! Driving fans from software is refused here for a reason the cooling module
//! states and this one depends on: if the software holding a fan speed dies,
//! the fans stay wherever it last left them, and a monitoring outage becomes a
//! thermal one.
//!
//! Bounding power fails the other way. If the process holding a power cap dies,
//! the cap stays in force and the machine runs slower and cooler than it could.
//! That is an availability cost, not a safety one, and it is recoverable by
//! anyone who notices. The failure directions are opposite, and that asymmetry
//! — not a preference about which is tidier — is why one is actuated and the
//! other is not.
//!
//! # Why power and not temperature
//!
//! The kernel offers two paths and they are complementary. The thermal
//! framework reacts to temperature: zone, trip point, cooling device, frequency
//! drop. It is correct and it is slow, because temperature is the *consequence*
//! of power and lags it by seconds to minutes.
//!
//! The power path — RAPL through the powercap framework — bounds draw directly
//! in hardware, without depending on a temperature sensor being read at all.
//!
//! For acoustics the power path is the only one that works, because management
//! controllers on server hardware lead their fan curves on package power rather
//! than waiting for temperature. That is correct of them: at two sockets of
//! 135 W the thermal ramp would outrun the fans if they waited. It is also why
//! a machine can be at 40 °C with its fans at maximum and nothing is wrong with
//! the controller — it is responding to draw, and the only way to quiet it is
//! to draw less.
//!
//! A temperature-driven governor cannot fix that. It would wait for heat that
//! never arrives, conclude everything is fine, and leave the fans at maximum.
//!
//! # Generality
//!
//! Machines differ and most of them will offer only some of this. Every lever
//! is probed, and one that is not present is recorded as an explicit absence
//! with the reason rather than silently skipped — see [`Absent`]. A machine
//! with no lever at all gets an honest empty plan, not a pretence.
//!
//! Preference order, most general first:
//!
//! 1. **powercap** (`/sys/class/powercap`) — the kernel's vendor-neutral
//!    framework. `intel-rapl` on Intel, RAPL on recent AMD, `idle-injection`
//!    where a hardware cap does not exist. Bounds watts, which is the quantity
//!    the fan controller is actually reading.
//! 2. **cpufreq** (`scaling_max_freq`) — present on Intel, AMD and Arm.
//!    Bounds frequency, which bounds power indirectly and less precisely.
//! 3. **intel_pstate** (`max_perf_pct`, `no_turbo`) — Intel only, and the
//!    turbo switch is the single largest step on a machine with headroom.
//!
//! Accelerators are deliberately not here. A GPU power limit is set through the
//! vendor's own control plane and belongs with [`crate::accelerator`], which
//! already owns that relationship.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The kernel's power capping framework.
const POWERCAP: &str = "/sys/class/powercap";
/// Per-CPU frequency policy.
const CPUFREQ: &str = "/sys/devices/system/cpu/cpufreq";
/// Intel's performance-percentage interface.
const PSTATE: &str = "/sys/devices/system/cpu/intel_pstate";

/// One way this machine can be told to draw less.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lever", rename_all = "snake_case")]
pub enum Lever {
    /// A powercap zone. The general case, and the only one that bounds the
    /// quantity a fan controller reads.
    PowerCap {
        /// Sysfs directory of the zone.
        path: PathBuf,
        /// The zone's own name: `package-0`, `dram`, `core`.
        name: String,
        /// Current long-term limit, microwatts.
        limit_uw: u64,
        /// The ceiling the hardware reports, microwatts. `None` where the zone
        /// does not publish one, which is common for `dram`.
        max_uw: Option<u64>,
    },
    /// A cpufreq policy's maximum frequency.
    CpuFreq {
        /// Sysfs directory of the policy.
        path: PathBuf,
        /// Current ceiling, kHz.
        max_khz: u64,
        /// What the hardware can do, kHz.
        hardware_max_khz: u64,
    },
    /// Intel's performance-percentage cap.
    PstatePercent {
        /// Current value, 1–100.
        max_perf_pct: u8,
    },
    /// Intel's turbo switch.
    ///
    /// Separate from the percentage because it is a different physical thing
    /// and by far the largest single step: turbo is where a part exceeds its
    /// nameplate, and it is exactly the excursion a controller ramps for.
    Turbo {
        /// Whether turbo is currently permitted.
        enabled: bool,
    },
}

/// A lever this machine does not offer, and why.
///
/// Recorded rather than skipped. "This machine cannot be quietened" and "nobody
/// looked" are different facts, and a caller that cannot tell them apart will
/// eventually report the second as the first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Absent {
    /// Which lever.
    pub what: String,
    /// What was looked for and not found.
    pub why: String,
}

/// What this machine actually offers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Levers {
    pub found: Vec<Lever>,
    pub absent: Vec<Absent>,
}

impl Levers {
    /// Whether anything here can bound power at all.
    pub fn any(&self) -> bool {
        !self.found.is_empty()
    }

    /// The package-power zones, which are the ones that matter for noise.
    ///
    /// `dram` and `core` sub-zones are excluded: a fan controller responds to
    /// package draw, and capping DRAM to quieten a machine would slow memory
    /// for no acoustic gain.
    pub fn packages(&self) -> Vec<&Lever> {
        self.found
            .iter()
            .filter(|l| matches!(l, Lever::PowerCap { name, .. } if name.starts_with("package")))
            .collect()
    }
}

/// How much of itself a machine may use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "envelope", rename_all = "snake_case")]
pub enum Envelope {
    /// No restriction. What a machine in a hall should be at.
    ///
    /// The default, and it has to be: a machine whose operator has declared
    /// nothing must run at full speed. Defaulting to a restriction would
    /// throttle every undeclared machine in a fleet on nobody's decision.
    #[default]
    Full,
    /// A fraction of each package's own maximum, 0.0–1.0.
    ///
    /// Relative rather than absolute so one policy is meaningful across a fleet
    /// of different machines — the same declaration on a 65 W part and a 270 W
    /// pair of sockets means the same thing about how hard each is working.
    Fraction {
        /// Of each package's reported ceiling.
        of_maximum: f64,
    },
    /// An absolute budget per package, watts.
    ///
    /// For the case where a site has a real electrical or acoustic number to
    /// hit rather than a proportion to hold.
    WattsPerPackage {
        /// Per package, not per machine: a two-socket box given 90 here may
        /// draw 180 across its packages. Per-package because that is the unit
        /// the hardware enforces, and converting silently would mean the
        /// number an operator wrote is not the number in force.
        watts: u32,
    },
}

impl Envelope {
    /// The budget this envelope implies for a zone whose ceiling is `max_uw`.
    fn limit_uw_for(&self, max_uw: u64) -> Option<u64> {
        match self {
            Envelope::Full => Some(max_uw),
            Envelope::Fraction { of_maximum } => {
                let f = of_maximum.clamp(0.0, 1.0);
                Some(((max_uw as f64) * f) as u64)
            }
            Envelope::WattsPerPackage { watts } => Some(u64::from(*watts) * 1_000_000),
        }
    }

    /// Whether this envelope restricts anything.
    pub fn is_restrictive(&self) -> bool {
        !matches!(self, Envelope::Full)
    }
}

/// What an operator has declared about this machine's thermal behaviour.
///
/// # Why this is a file and not a policy rule
///
/// [`furcate_policy`] is the one place authority is written, and this does not
/// belong in it. Its `Effect` is `Allow` or `Deny` and a rule carries no value,
/// deliberately — so "quiet hours are 22 to 07" has nowhere to live there, and
/// squeezing a number into an allow rule would make the authority file mean two
/// different kinds of thing.
///
/// The split that does hold: **whether** a caller may change any of this is
/// `tune` on `node:<id>`, ruled by the policy engine like every other mutation.
/// **What** it is set to is this, carried the way every other per-concern
/// setting on a node is carried.
///
/// Absent is ordinary and restricts nothing. A site that has declared nothing
/// is a machine room until somebody says otherwise, because the alternative —
/// throttling on a guess — is a decision taken on the operator's behalf.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Declared {
    /// Where this machine sits relative to people.
    #[serde(default)]
    pub acoustics: crate::acoustics::Acoustics,
    /// How far to bound the machine when it is disturbing somebody for no
    /// reason. Defaults to seven tenths of each package's own maximum.
    #[serde(default = "default_quiet")]
    pub quiet: Envelope,
}

fn default_quiet() -> Envelope {
    Envelope::Fraction { of_maximum: 0.6 }
}

impl Default for Declared {
    /// Written out rather than derived, because deriving it produced a
    /// different answer from the serde default and the two disagreed in a way
    /// nothing would have noticed: a machine with no file ran with
    /// `quiet: Full` and a machine with an empty file ran with `0.6`.
    ///
    /// `Full` is also the wrong value for this field specifically. It is the
    /// envelope to hold *when the machine needs bounding*, so `Full` there
    /// means "when disturbing somebody, restrict to nothing" — the feature
    /// doing nothing, quietly.
    ///
    /// The undeclared machine still runs unrestricted, and that property comes
    /// from the placement defaulting to a machine room rather than from this:
    /// nothing is ever disturbing anybody there, so the quiet envelope is
    /// never reached.
    fn default() -> Self {
        Self {
            acoustics: crate::acoustics::Acoustics::default(),
            quiet: default_quiet(),
        }
    }
}

impl Declared {
    /// The envelope in force, and why.
    ///
    /// The reason travels with the answer because an operator looking at a
    /// throttled machine needs to know which of several rules put it there,
    /// and a bare envelope makes them guess.
    pub fn in_force(
        &self,
        local_hour: Option<u8>,
        faults: &[crate::cooling::Fault],
    ) -> (Envelope, &'static str) {
        let Some(hour) = local_hour else {
            return (
                Envelope::Full,
                "no trustworthy local hour, so no acoustic judgement was made",
            );
        };
        if !self.acoustics.disturbing(hour) {
            return (Envelope::Full, "not within quiet hours at an occupied site");
        }
        if faults.iter().any(|f| f.is_thermal()) {
            return (
                Envelope::Full,
                "genuinely hot: heat needs the fans and the clocks, and quietening \
                 a hot machine trades a noise complaint for lost hardware",
            );
        }
        if faults
            .iter()
            .any(|f| matches!(f, crate::cooling::Fault::RunningHardWhileCold { .. }))
        {
            return (self.quiet, "fans working hard with no heat to justify them");
        }
        (Envelope::Full, "fans are not working harder than the heat warrants")
    }
}

/// One sysfs write, with the reason it is being made.
///
/// Returned rather than performed. This crate reads hardware and judges it; the
/// privileged side decides whether to carry a plan out, and a plan it can read
/// before acting is one it can refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Write {
    pub path: PathBuf,
    pub value: String,
    /// Why, in the operator's language. Ends up in the actuator's log, where
    /// somebody reading it months later needs to know what it was for.
    pub why: String,
}

/// Read the levers this machine offers.
pub fn probe() -> Levers {
    probe_in(Path::new(POWERCAP), Path::new(CPUFREQ), Path::new(PSTATE))
}

/// Probe given roots. Split out so a test can own the filesystem.
pub fn probe_in(powercap: &Path, cpufreq: &Path, pstate: &Path) -> Levers {
    let mut out = Levers::default();

    // ---- powercap, the general case ------------------------------------
    match std::fs::read_dir(powercap) {
        Ok(entries) => {
            let mut zones = 0usize;
            for e in entries.flatten() {
                let p = e.path();
                let Some(name) = read_trim(&p.join("name")) else {
                    continue;
                };
                let Some(limit_uw) = read_u64(&p.join("constraint_0_power_limit_uw")) else {
                    continue;
                };
                zones += 1;
                out.found.push(Lever::PowerCap {
                    path: p.clone(),
                    name,
                    limit_uw,
                    max_uw: read_u64(&p.join("constraint_0_max_power_uw")),
                });
            }
            if zones == 0 {
                out.absent.push(Absent {
                    what: "powercap".into(),
                    why: format!(
                        "{} exists but publishes no zone with a long-term limit",
                        powercap.display()
                    ),
                });
            }
        }
        Err(e) => out.absent.push(Absent {
            what: "powercap".into(),
            why: format!("{}: {e}", powercap.display()),
        }),
    }

    // ---- cpufreq ---------------------------------------------------------
    match std::fs::read_dir(cpufreq) {
        Ok(entries) => {
            let mut policies = 0usize;
            for e in entries.flatten() {
                let p = e.path();
                if !p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("policy"))
                {
                    continue;
                }
                let (Some(max_khz), Some(hardware_max_khz)) = (
                    read_u64(&p.join("scaling_max_freq")),
                    read_u64(&p.join("cpuinfo_max_freq")),
                ) else {
                    continue;
                };
                policies += 1;
                out.found.push(Lever::CpuFreq {
                    path: p,
                    max_khz,
                    hardware_max_khz,
                });
            }
            if policies == 0 {
                out.absent.push(Absent {
                    what: "cpufreq".into(),
                    why: format!("{} publishes no policy", cpufreq.display()),
                });
            }
        }
        Err(e) => out.absent.push(Absent {
            what: "cpufreq".into(),
            why: format!("{}: {e}", cpufreq.display()),
        }),
    }

    // ---- intel_pstate ----------------------------------------------------
    let pct = read_u64(&pstate.join("max_perf_pct"));
    let turbo = read_u64(&pstate.join("no_turbo"));
    match (pct, turbo) {
        (None, None) => out.absent.push(Absent {
            what: "intel_pstate".into(),
            why: format!("{} not present; not an Intel P-state machine", pstate.display()),
        }),
        _ => {
            if let Some(v) = pct {
                out.found.push(Lever::PstatePercent {
                    max_perf_pct: v.clamp(1, 100) as u8,
                });
            }
            if let Some(v) = turbo {
                out.found.push(Lever::Turbo { enabled: v == 0 });
            }
        }
    }

    out
}

/// The writes that put `envelope` in force, given what this machine offers.
///
/// Ordered so the largest effect comes first: turbo, then the package budget,
/// then frequency. A plan applied halfway therefore still helps, which matters
/// because the privileged side applies one write at a time and can be
/// interrupted.
///
/// Zones with no published ceiling are skipped rather than guessed at. A cap
/// derived from a ceiling nobody reported is a number with no meaning, and on
/// this interface it would be a number in microwatts.
pub fn plan(levers: &Levers, envelope: Envelope) -> Vec<Write> {
    let mut out = Vec::new();

    for lever in &levers.found {
        match lever {
            // Turbo is where a part exceeds its nameplate, which is precisely
            // the excursion a management controller ramps its fans for.
            Lever::Turbo { .. } => out.push(Write {
                path: Path::new(PSTATE).join("no_turbo"),
                value: if envelope.is_restrictive() { "1" } else { "0" }.to_string(),
                why: if envelope.is_restrictive() {
                    "turbo off: the excursion above nameplate is what ramps the fans".into()
                } else {
                    "turbo restored".into()
                },
            }),
            _ => {}
        }
    }

    for lever in levers.packages() {
        let Lever::PowerCap {
            path, name, max_uw, ..
        } = lever
        else {
            continue;
        };
        let Some(max) = max_uw else {
            continue;
        };
        let Some(target) = envelope.limit_uw_for(*max) else {
            continue;
        };
        // Never above what the hardware says it can do. A limit past the
        // ceiling is rejected by the kernel on some parts and silently ignored
        // on others, and the second is worse.
        let target = target.min(*max).max(1);
        out.push(Write {
            path: path.join("constraint_0_power_limit_uw"),
            value: target.to_string(),
            why: format!(
                "{name} budget {} W of {} W: package draw is what the controller reads",
                target / 1_000_000,
                max / 1_000_000
            ),
        });
    }

    for lever in &levers.found {
        if let Lever::CpuFreq {
            path,
            hardware_max_khz,
            ..
        } = lever
        {
            let target = match envelope {
                Envelope::Full => *hardware_max_khz,
                Envelope::Fraction { of_maximum } => {
                    ((*hardware_max_khz as f64) * of_maximum.clamp(0.0, 1.0)) as u64
                }
                // An absolute watt budget says nothing about frequency, and a
                // ratio invented here would be a guess dressed as a setting.
                // The package cap already carries it.
                Envelope::WattsPerPackage { .. } => continue,
            };
            out.push(Write {
                path: path.join("scaling_max_freq"),
                value: target.max(1).to_string(),
                why: format!("frequency ceiling {} kHz of {hardware_max_khz} kHz", target.max(1)),
            });
        }
    }

    out
}

/// The envelope a machine should hold, given where it is and what its cooling
/// is doing.
///
/// Thin wrapper over [`Declared::in_force`], kept because most callers want the
/// envelope and not the sentence explaining it. There is one implementation
/// rather than two: a second copy of this judgement would be a second answer to
/// "should this machine be throttled", and the one that loses is whichever the
/// reader did not open.
pub fn envelope_for(
    acoustics: &crate::acoustics::Acoustics,
    local_hour: u8,
    faults: &[crate::cooling::Fault],
    quiet: Envelope,
) -> Envelope {
    Declared {
        acoustics: *acoustics,
        quiet,
    }
    .in_force(Some(local_hour), faults)
    .0
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn read_u64(p: &Path) -> Option<u64> {
    read_trim(p).and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acoustics::Acoustics;
    use crate::cooling::Fault;

    fn scratch(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("furcate-thermal-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &Path, name: &str, v: &str) {
        std::fs::create_dir_all(p).unwrap();
        std::fs::write(p.join(name), v).unwrap();
    }

    /// A machine shaped like the one that prompted this: two sockets, each
    /// reporting a 135 W ceiling through `intel-rapl`.
    fn two_socket_powercap() -> PathBuf {
        let root = scratch("powercap");
        // Named without the colon a real zone carries (`intel-rapl:0`), because
        // a colon is illegal in a Windows filename and these tests run on every
        // developer machine. Nothing reads the directory name — `probe_in`
        // identifies a zone by its `name` file — so the fixture is faithful
        // where it matters.
        for i in [0, 1] {
            let z = root.join(format!("intel-rapl-{i}"));
            write(&z, "name", &format!("package-{i}\n"));
            write(&z, "constraint_0_power_limit_uw", "135000000\n");
            write(&z, "constraint_0_max_power_uw", "135000000\n");
            // A dram sub-zone, which must not be capped for noise.
            let d = root.join(format!("intel-rapl-{i}-0"));
            write(&d, "name", "dram\n");
            write(&d, "constraint_0_power_limit_uw", "0\n");
        }
        root
    }

    #[test]
    fn the_package_zones_are_found_and_the_dram_zones_are_not_confused_for_them() {
        let l = probe_in(&two_socket_powercap(), Path::new("/nonexistent"), Path::new("/nonexistent"));
        assert_eq!(l.found.len(), 4, "two packages and two dram zones");
        assert_eq!(l.packages().len(), 2, "only the packages are noise-relevant");
    }

    /// **Absence is reported, never silently skipped.** A machine that cannot
    /// be quietened and a machine nobody looked at must not read alike.
    #[test]
    fn a_machine_with_no_levers_says_so_rather_than_looking_healthy() {
        let l = probe_in(
            Path::new("/nonexistent/powercap"),
            Path::new("/nonexistent/cpufreq"),
            Path::new("/nonexistent/pstate"),
        );
        assert!(!l.any());
        assert_eq!(l.absent.len(), 3, "each lever accounts for itself");
        assert!(l.absent.iter().any(|a| a.what == "powercap"));
        assert!(l.absent.iter().any(|a| a.what == "intel_pstate"));
        assert!(plan(&l, Envelope::Fraction { of_maximum: 0.6 }).is_empty());
    }

    /// An Arm or AMD box with cpufreq but no RAPL and no P-state still gets a
    /// usable plan. This is the generality the module claims.
    #[test]
    fn a_machine_with_only_cpufreq_can_still_be_quietened() {
        let root = scratch("cpufreq-only");
        for i in [0, 1] {
            let p = root.join(format!("policy{i}"));
            write(&p, "scaling_max_freq", "2600000\n");
            write(&p, "cpuinfo_max_freq", "2600000\n");
        }
        let l = probe_in(Path::new("/nonexistent"), &root, Path::new("/nonexistent"));
        assert_eq!(l.found.len(), 2);

        let writes = plan(&l, Envelope::Fraction { of_maximum: 0.5 });
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|w| w.value == "1300000"));
        assert!(writes.iter().all(|w| w.path.ends_with("scaling_max_freq")));
    }

    /// The plan leads with turbo, because it is the largest single step and a
    /// plan applied halfway should still have helped.
    #[test]
    fn the_largest_effect_is_planned_first() {
        let pstate = scratch("pstate");
        write(&pstate, "max_perf_pct", "100\n");
        write(&pstate, "no_turbo", "0\n");

        let l = probe_in(&two_socket_powercap(), Path::new("/nonexistent"), &pstate);
        let writes = plan(&l, Envelope::Fraction { of_maximum: 0.6 });

        assert!(
            writes[0].path.ends_with("no_turbo") && writes[0].value == "1",
            "turbo must come first, got {:?}",
            writes[0]
        );
        assert!(writes.iter().any(|w| w.value == "81000000"), "135 W * 0.6");
        assert_eq!(
            writes.iter().filter(|w| w.value == "81000000").count(),
            2,
            "both packages, and neither dram zone"
        );
    }

    /// A cap above what the hardware reports is clamped. Some parts reject it
    /// and some ignore it silently, and the silent case is the dangerous one
    /// because the operator believes a limit is in force.
    #[test]
    fn a_budget_above_the_hardware_ceiling_is_clamped() {
        let l = probe_in(&two_socket_powercap(), Path::new("/nonexistent"), Path::new("/nonexistent"));
        let writes = plan(&l, Envelope::WattsPerPackage { watts: 500 });
        assert!(
            writes.iter().all(|w| w.value == "135000000"),
            "clamped to the reported 135 W ceiling"
        );
    }

    /// Restoring is a plan too, and it must put back the hardware maximum
    /// rather than whatever happened to be there.
    #[test]
    fn full_restores_the_hardware_maximum_and_turns_turbo_back_on() {
        let pstate = scratch("restore");
        write(&pstate, "max_perf_pct", "60\n");
        write(&pstate, "no_turbo", "1\n");
        let l = probe_in(&two_socket_powercap(), Path::new("/nonexistent"), &pstate);

        let writes = plan(&l, Envelope::Full);
        assert!(writes.iter().any(|w| w.path.ends_with("no_turbo") && w.value == "0"));
        assert!(writes.iter().any(|w| w.value == "135000000"));
    }

    /// A zone that publishes no ceiling is skipped rather than guessed at. The
    /// guess would be a number in microwatts with nothing behind it.
    #[test]
    fn a_zone_with_no_published_ceiling_is_left_alone() {
        let root = scratch("no-ceiling");
        let z = root.join("intel-rapl-0");
        write(&z, "name", "package-0\n");
        write(&z, "constraint_0_power_limit_uw", "95000000\n");
        // no constraint_0_max_power_uw

        let l = probe_in(&root, Path::new("/nonexistent"), Path::new("/nonexistent"));
        assert_eq!(l.packages().len(), 1);
        assert!(plan(&l, Envelope::Fraction { of_maximum: 0.5 }).is_empty());
    }

    // ---- the judgement ---------------------------------------------------

    fn loud_and_cold() -> Vec<Fault> {
        vec![Fault::RunningHardWhileCold {
            fastest_rpm: 9_200,
            hottest_c: 41,
        }]
    }

    /// **The shape that reaches an operator.** An internally tagged enum
    /// cannot wrap a bare number — serde has nowhere to put the tag — and the
    /// first version of this panicked on serialisation, which would have taken
    /// the route down on its first call rather than failing a test.
    #[test]
    fn every_envelope_survives_the_wire() {
        for e in [
            Envelope::Full,
            Envelope::Fraction { of_maximum: 0.6 },
            Envelope::WattsPerPackage { watts: 90 },
        ] {
            let j = serde_json::to_string(&e).expect("must serialise");
            assert!(j.contains("\"envelope\""), "self-describing: {j}");
            let back: Envelope = serde_json::from_str(&j).expect("must round-trip");
            assert_eq!(back, e);
        }
    }

    /// **The sentence an operator reads.** A throttled machine is a question
    /// ("why is this slow?") and a bare envelope makes them guess which of
    /// several rules put it there. Each branch names itself.
    #[test]
    fn the_reason_says_which_rule_decided() {
        let home = Declared {
            acoustics: Acoustics::living_space(),
            quiet: Envelope::Fraction { of_maximum: 0.6 },
        };

        let (e, why) = home.in_force(Some(1), &loud_and_cold());
        assert_eq!(e, Envelope::Fraction { of_maximum: 0.6 });
        assert!(why.contains("no heat to justify"), "{why}");

        let (e, why) = home.in_force(Some(14), &loud_and_cold());
        assert_eq!(e, Envelope::Full);
        assert!(why.contains("not within quiet hours"), "{why}");

        let (e, why) = home.in_force(None, &loud_and_cold());
        assert_eq!(e, Envelope::Full);
        assert!(why.contains("no trustworthy local hour"), "{why}");

        let hot = vec![Fault::Hot { name: "CPU".into(), celsius: 92 }];
        let (e, why) = home.in_force(Some(1), &hot);
        assert_eq!(e, Envelope::Full);
        assert!(why.contains("genuinely hot"), "{why}");

        let (e, why) = home.in_force(Some(1), &[]);
        assert_eq!(e, Envelope::Full);
        assert!(why.contains("not working harder"), "{why}");
    }

    /// An undeclared machine runs at full speed. Defaulting to a restriction
    /// would throttle every machine in a fleet on nobody's decision.
    #[test]
    fn an_undeclared_machine_is_unrestricted() {
        let d = Declared::default();
        assert_eq!(d.acoustics.placement, crate::acoustics::Placement::MachineRoom);
        for h in 0..24u8 {
            assert_eq!(d.in_force(Some(h), &loud_and_cold()).0, Envelope::Full);
        }
    }

    /// It has to survive the file it is written to, or an operator declares
    /// something once and the machine forgets at the next boot.
    #[test]
    fn a_declaration_survives_its_file() {
        let d = Declared {
            acoustics: Acoustics::living_space(),
            quiet: Envelope::WattsPerPackage { watts: 90 },
        };
        let j = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Declared>(&j).unwrap(), d);
        // And an empty document is the unrestricted default rather than an error.
        assert_eq!(serde_json::from_str::<Declared>("{}").unwrap(), Declared::default());
    }

    /// A machine in a hall is never restricted, however loud it is. Noise costs
    /// electricity there and nothing else, and slowing the fleet to save it
    /// would be a worse trade than the one it fixes.
    #[test]
    fn a_machine_room_is_never_restricted() {
        for h in [1u8, 14] {
            assert_eq!(
                envelope_for(&Acoustics::machine_room(), h, &loud_and_cold(), Envelope::Fraction { of_maximum: 0.6 }),
                Envelope::Full
            );
        }
    }

    /// **The case this exists for.** A machine in a home, at night, with its
    /// fans at the ceiling and nothing hot enough to justify them.
    #[test]
    fn a_home_at_night_with_loud_fans_and_no_heat_is_restricted() {
        assert_eq!(
            envelope_for(&Acoustics::living_space(), 1, &loud_and_cold(), Envelope::Fraction { of_maximum: 0.6 }),
            Envelope::Fraction { of_maximum: 0.6 }
        );
    }

    /// The same machine in the afternoon is left alone. Quiet hours are a
    /// window, not a permanent handicap on the hardware.
    #[test]
    fn the_same_machine_in_the_afternoon_runs_at_full_speed() {
        assert_eq!(
            envelope_for(&Acoustics::living_space(), 14, &loud_and_cold(), Envelope::Fraction { of_maximum: 0.6 }),
            Envelope::Full
        );
    }

    /// **Heat always wins.** A genuinely hot machine is never throttled to
    /// quieten it, at any hour, anywhere. It needs its fans and its clocks, and
    /// trading that for silence swaps a noise complaint for lost hardware.
    #[test]
    fn a_hot_machine_is_never_quietened() {
        let hot = vec![
            Fault::RunningHardWhileCold {
                fastest_rpm: 9_200,
                hottest_c: 41,
            },
            Fault::Hot {
                name: "CPU".into(),
                celsius: 92,
            },
        ];
        assert_eq!(
            envelope_for(&Acoustics::living_space(), 2, &hot, Envelope::Fraction { of_maximum: 0.6 }),
            Envelope::Full
        );
    }

    /// A quiet machine in a home at night is not restricted either. The
    /// trigger is fans working without cause, not the hour by itself —
    /// otherwise every machine in every home would be throttled all night for
    /// nothing.
    #[test]
    fn a_quiet_machine_at_night_is_left_alone() {
        assert_eq!(
            envelope_for(&Acoustics::living_space(), 2, &[], Envelope::Fraction { of_maximum: 0.6 }),
            Envelope::Full
        );
    }
}
