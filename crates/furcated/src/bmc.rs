//! Reading the management controller.
//!
//! Everything below was invisible until now. Linux exposed one temperature on
//! this hardware — the processor package — while the controller had twelve
//! sensors and seven tachometers, and six of those fans were running at
//! eighteen thousand RPM against a machine that was thirty-eight degrees.
//!
//! The controller is reached in-band, so no network path and no credentials
//! are involved. The agent does not touch `/dev/ipmi0` itself: that device is
//! root-only and should stay so, because IPMI can power off the chassis, and
//! handing this agent read access would hand it the ability to stop the
//! machine — precisely the capability the thermal design says software must
//! not hold. The privileged reader copies the sensor listing out to a file,
//! the same arrangement already used for the energy counters.
//!
//! Read-only, deliberately and permanently. Fan speed on this class of
//! controller is defined in firmware and the command to change it is refused;
//! more importantly, taking manual control of cooling means the fans stay
//! wherever software last left them if that software dies. The controller's
//! curve survives a kernel panic. A replacement for it would not.

use furcate_host::acoustics::{Acoustics, Placement, QuietHours};
use furcate_host::cooling::{assess, parse_sdr, Cooling, Fault, Limits};
use furcate_host::thermal::Envelope;
use furcate_host::wall::{self, Wall};
use furcate_power::thermal::{rung_from, Origin, Reading, Thresholds};
use furcate_power::Rung;
use serde::{Deserialize, Serialize};

/// Nominal draw of one server fan at full speed, in watts.
///
/// A stand-in, and marked as one wherever it surfaces. High-static-pressure
/// fans of this size sit somewhere between ten and twenty watts flat out; the
/// figure is not precise and does not need to be, because the finding it
/// supports is an order of magnitude rather than a number.
const FAN_WATTS_AT_MAX: f64 = 15.0;

/// Speed treated as full for the power estimate when the machine's own
/// ceiling is unknown and nothing has been observed.
///
/// Only a last resort. Used against a machine whose fans reach 9,200 RPM it
/// understates the fan draw by roughly an order of magnitude, because the
/// estimate is a cube law — the error is not proportional, it is cubed.
const FAN_MAX_RPM_FALLBACK: u32 = 20_000;

/// The fastest this machine's fans can run, best available answer.
///
/// Profile first, then the fastest speed actually seen in this reading, then
/// the fallback. The middle step matters: a machine with no profile that is
/// currently at full tilt yields its own true ceiling, which is exactly the
/// case the fixed constant could not judge.
fn fan_ceiling(cooling: &Cooling) -> u32 {
    if let Some(rpm) = furcate_host::hardware::recognise()
        .profile()
        .and_then(|p| p.fan_max_rpm())
    {
        return rpm;
    }
    match cooling.fastest_fan() {
        Some(f) if f.rpm > 0 => f.rpm,
        _ => FAN_MAX_RPM_FALLBACK,
    }
}

/// Where the privileged reader publishes the controller's sensor listing.
const COOLING_PATH: &str = "/run/furcate/cooling.txt";

fn published() -> Option<String> {
    std::fs::read_to_string(COOLING_PATH).ok().filter(|s| !s.trim().is_empty())
}

/// Whether this machine has a controller worth asking.
pub fn present() -> bool {
    std::path::Path::new("/dev/ipmi0").exists() || std::path::Path::new(COOLING_PATH).exists()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BmcReport {
    pub present: bool,
    /// False when the device exists but the tool is absent or refused, so an
    /// empty reading is distinguishable from a quiet machine.
    pub readable: bool,
    pub cooling: Cooling,
    pub faults: Vec<Fault>,
    /// Estimated fan power, and the fact that it is an estimate.
    pub fan_watts_estimated: f64,
    /// The rung heat alone justifies. Never `Halt` — see
    /// [`furcate_power::thermal`].
    pub thermal_rung: Option<String>,
    pub hottest: Option<Reading>,
    /// Chassis power as the supply measures it.
    ///
    /// The number every energy figure divides by, and until now the one number
    /// this system had no measurement of — it multiplied package draw by a
    /// factor somebody typed into a file. The same sensor dump that carries the
    /// fans carries this, so it cost no extra round trip and was simply never
    /// read.
    pub wall: Option<Wall>,
}

pub fn collect() -> BmcReport {
    if !present() {
        return BmcReport {
            present: false,
            readable: false,
            cooling: Cooling::default(),
            faults: Vec::new(),
            fan_watts_estimated: 0.0,
            thermal_rung: None,
            hottest: None,
            wall: None,
        };
    }

    let Some(text) = published() else {
        return BmcReport {
            present: true,
            readable: false,
            cooling: Cooling::default(),
            faults: Vec::new(),
            fan_watts_estimated: 0.0,
            thermal_rung: None,
            hottest: None,
            wall: None,
        };
    };

    let cooling = parse_sdr(&text);
    // Against this machine's own ceiling. With `Limits::default()` here, a
    // machine whose fans top out below 12,000 RPM could never report
    // `RunningHardWhileCold` — it ran at full speed, cold, for days, and this
    // path stayed silent the whole time.
    let ceiling = fan_ceiling(&cooling);
    let faults = assess(&cooling, &Limits::for_fan_max(ceiling));

    let readings: Vec<Reading> = cooling
        .temperatures
        .iter()
        .map(|t| Reading {
            name: t.name.clone(),
            celsius: t.celsius,
            origin: Origin::Controller,
        })
        .collect();

    // Positioned against this machine's own controller rather than against the
    // hardware the defaults were written for. A ladder whose steps sit above
    // the point where the controller takes over is not an early response; it is
    // a log line written after the fact.
    let thresholds = furcate_host::hardware::recognise()
        .profile()
        .and_then(|p| p.controller_critical_c())
        .map(Thresholds::below_critical)
        .unwrap_or_default();
    let decided = rung_from(&readings, &thresholds);

    BmcReport {
        present: true,
        readable: true,
        wall: wall::parse_sdr(&text),
        fan_watts_estimated: cooling.estimated_watts(ceiling, FAN_WATTS_AT_MAX),
        thermal_rung: decided.as_ref().map(|(r, _)| format!("{r:?}").to_lowercase()),
        hottest: decided.map(|(_, h)| h),
        cooling,
        faults,
    }
}

/// Where this machine sits relative to people, as the operator declared it.
///
/// Declared through the environment rather than inferred, because there is no
/// measurement a machine can take of itself that distinguishes a hall from a
/// hallway. The default is `machine_room`, which restricts nothing: a site that
/// has not said anything is not quietly throttled on a guess.
///
/// - `FURCATE_PLACEMENT` = `machine_room` | `shared_space` | `living_space`
/// - `FURCATE_QUIET_HOURS` = `22-7` (local, wraps midnight)
/// - `FURCATE_QUIET_BUILDS` = `narrow` | `refuse` (what the window does to builds)
pub fn declared() -> furcate_host::thermal::Declared {
    // File first, environment second, compiled default last. The same order
    // the authority file resolves in, for the same reason: an operator who has
    // written something down has said more than an environment variable
    // inherited from a unit file nobody has read in months.
    //
    // Absent is ordinary. Present-and-unparseable is NOT fatal here, unlike the
    // authority file, and the asymmetry is deliberate: falling back on an
    // unreadable authority file would restore permissions somebody removed,
    // whereas falling back here only means a machine runs at full speed, which
    // is what it did before anybody declared anything. Refusing to start over a
    // malformed comfort setting would be the worse failure.
    //
    // Two files, in order. The state directory holds what an operator set
    // through `/thermal` — the only place this process can write, see
    // `write_declared`. The configuration directory holds one an operator wrote
    // by hand. A declaration made through the policy-checked route is the more
    // recent decision, so it is read first.
    for path in [furcate_paths::state("thermal.json"), furcate_paths::config("thermal.json")] {
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(d) => return d,
                Err(e) => eprintln!(
                    "furcated: {} is not readable as a thermal declaration ({e}); \
                     ignoring it",
                    path.display()
                ),
            },
            Err(_) => {}
        }
    }
    furcate_host::thermal::Declared {
        acoustics: acoustics_of_this_site(),
        quiet: quiet_envelope(),
    }
}

/// Write the declaration an operator asked for.
///
/// Whether they may is decided before this is called, by the policy engine, on
/// `tune`. This only records the decision.
///
/// Into the state directory, not the configuration directory. The unit runs with
/// `ProtectSystem=strict`, which makes `/etc` read-only to this process whatever
/// owns the file, so every declaration made through `/thermal` was ruled on,
/// chained to the ledger, and then failed to record with EACCES — on every
/// machine, since the day the route existed. The reply said "cannot record it",
/// so nothing was silently lost, but nothing could ever be set either.
///
/// Temp-then-rename, because the power pass reads this every ten seconds and
/// must never see half a declaration.
pub fn write_declared(d: &furcate_host::thermal::Declared) -> std::io::Result<()> {
    let path = furcate_paths::state("thermal.json");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(d).map_err(std::io::Error::other)?)?;
    std::fs::rename(&tmp, &path)
}

pub fn acoustics_of_this_site() -> Acoustics {
    let placement = match std::env::var("FURCATE_PLACEMENT").unwrap_or_default().as_str() {
        "living_space" => Placement::LivingSpace,
        "shared_space" => Placement::SharedSpace,
        _ => Placement::MachineRoom,
    };
    let quiet_hours = std::env::var("FURCATE_QUIET_HOURS").ok().and_then(|v| {
        let (a, b) = v.split_once('-')?;
        Some(QuietHours {
            from: a.trim().parse().ok()?,
            to: b.trim().parse().ok()?,
        })
    });
    let builds = match std::env::var("FURCATE_QUIET_BUILDS").unwrap_or_default().as_str() {
        "refuse" => furcate_host::acoustics::Builds::Refuse,
        _ => furcate_host::acoustics::Builds::Narrow,
    };
    Acoustics {
        placement,
        quiet_hours,
        builds,
    }
}

/// Where the resolved quiet-hours declaration is published for the privileged
/// helper that enforces it.
///
/// Beside the actuator's intent, for the same reason that file is there: this
/// daemon runs unprivileged and may write to its own state directory, and the
/// root helper reads from it.
pub fn quiet_declaration_path() -> std::path::PathBuf {
    std::env::var_os("FURCATE_QUIET_DECLARATION")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/furcate/quiet-hours"))
}

/// The declaration as the helper reads it: resolved, flat, and safe to parse
/// with `sed` as root.
///
/// Resolved means `Acoustics::window` has already been applied (an occupied
/// site with no stated window gets the default one here), so the helper never
/// re-implements that rule and cannot disagree with this daemon about it. The
/// hour is not included: the helper reads its own clock, so enforcement does not
/// go stale if this process stops. A machine room publishes `occupied=0` even
/// with a window declared, because it is never disturbing anyone.
pub fn render_quiet(acoustics: &Acoustics) -> String {
    let mut s = String::from(concat!(
        "# Published by furcated from its thermal declaration. Read, never sourced, by\n",
        "# /usr/libexec/furcate/quiet-hours. Change it with `furcatectl thermal set`.\n",
    ));
    match acoustics.window().filter(|_| acoustics.placement.is_occupied()) {
        Some(w) => s.push_str(&format!(
            "occupied=1\nfrom={}\nto={}\nbuilds={}\n",
            w.from,
            w.to,
            acoustics.builds.as_str()
        )),
        None => s.push_str("occupied=0\n"),
    }
    s
}

/// Write [`render_quiet`] to [`quiet_declaration_path`], temp-then-rename so the
/// helper never reads half a file, and not at all when nothing changed.
pub fn publish_quiet(acoustics: &Acoustics) -> std::io::Result<()> {
    let path = quiet_declaration_path();
    let body = render_quiet(acoustics);
    if std::fs::read_to_string(&path).is_ok_and(|old| old == body) {
        return Ok(());
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, &path)
}

/// How far to bound this machine when it is disturbing somebody for no reason.
///
/// `FURCATE_QUIET_ENVELOPE` takes either a fraction of each package's own
/// maximum (`0.6`) or an absolute per-package budget (`90W`). A fraction is the
/// default because it means the same thing across a fleet of different
/// machines, where one watt figure would be a cap on some and a no-op on
/// others.
pub fn quiet_envelope() -> Envelope {
    match std::env::var("FURCATE_QUIET_ENVELOPE") {
        Ok(v) => {
            let v = v.trim();
            if let Some(w) = v.strip_suffix(['W', 'w']) {
                if let Ok(w) = w.trim().parse::<u32>() {
                    return Envelope::WattsPerPackage { watts: w };
                }
            }
            match v.parse::<f64>() {
                Ok(f) if (0.0..=1.0).contains(&f) => Envelope::Fraction { of_maximum: f },
                // An unreadable setting restricts nothing. Failing closed here
                // would mean a typo silently halves a machine's throughput,
                // and the operator would look for the cause in the workload.
                _ => Envelope::Fraction { of_maximum: 0.6 },
            }
        }
        Err(_) => Envelope::Fraction { of_maximum: 0.6 },
    }
}

/// The hour where this machine is, when the clock is worth believing.
///
/// Gated on [`furcate_host::platform::Clock::may_decide_on_time`], which is the
/// same gate every other wall-clock decision in this daemon passes through. An
/// unsynchronised clock yields `None` and no acoustic judgement is made — the
/// two ways of being wrong are throttling a machine in the middle of its
/// working day and leaving a bedroom loud all night, and declining beats both.
///
/// Takes the clock rather than reading it, so this module stays usable from
/// both binaries in this crate. `lite` includes `bmc` and not `host`, and a
/// call across that boundary would compile in one and not the other.
pub fn local_hour(clock: &furcate_host::platform::Clock) -> Option<u8> {
    if !clock.may_decide_on_time() {
        return None;
    }
    clock.local_hour
}

/// The rung heat justifies, for the ladder to combine with the supply state.
pub fn thermal_rung(r: &BmcReport) -> Option<Rung> {
    match r.thermal_rung.as_deref() {
        Some("nominal") => Some(Rung::Nominal),
        Some("shed") => Some(Rung::Shed),
        Some("capture") => Some(Rung::Capture),
        Some("quiesce") => Some(Rung::Quiesce),
        _ => None,
    }
}

/// Named scalars for the forecaster.
///
/// Inlet temperature is the interesting one: it tracks the room rather than the
/// workload, so it trends with the day and is the earliest warning that the
/// space itself is getting warmer.
pub fn series_points(r: &BmcReport) -> Vec<(String, f64)> {
    if !r.readable {
        return Vec::new();
    }
    let mut out = Vec::new();
    // Wall draw is the rail that matters most for cost and carbon, and it is
    // the one the forecaster could not have until now: package draw forecast
    // accurately still left the bill multiplied by a guess.
    if let Some(w) = r.wall {
        out.push(("wall_watts".to_string(), f64::from(w.input_watts)));
        if let Some(o) = w.output_watts {
            out.push(("psu_output_watts".to_string(), f64::from(o)));
        }
    }
    for t in &r.cooling.temperatures {
        let key = match t.name.as_str() {
            "Air-Inlet" => "temp_inlet_c",
            "Ambient" => "temp_ambient_c",
            "CPU" => "temp_cpu_c",
            _ => continue,
        };
        out.push((key.to_string(), t.celsius as f64));
    }
    if let Some(f) = r.cooling.fastest_fan() {
        out.push(("fan_max_rpm".to_string(), f.rpm as f64));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_without_a_controller_says_so_rather_than_reporting_nothing() {
        let r = collect();
        if !present() {
            assert!(!r.present);
            assert!(!r.readable);
            assert!(r.thermal_rung.is_none());
        }
    }

    #[test]
    fn an_unreadable_controller_is_distinguishable_from_a_quiet_one() {
        // Present but unreadable and present but calm are different problems.
        let r = BmcReport {
            present: true,
            readable: false,
            cooling: Cooling::default(),
            faults: vec![],
            fan_watts_estimated: 0.0,
            thermal_rung: None,
            hottest: None,
            wall: None,
        };
        assert!(r.present && !r.readable);
        assert!(series_points(&r).is_empty(), "nothing was read, so nothing is reported");
    }

    #[test]
    fn this_machine_is_read_if_it_has_a_controller() {
        let r = collect();
        if r.present && r.readable {
            assert!(!r.cooling.temperatures.is_empty(), "a controller with no temperatures");
            assert!(thermal_rung(&r).is_some());
        }
    }

    #[test]
    fn heat_never_asks_the_ladder_to_halt() {
        // Enforced at the boundary as well as in the policy, because this is
        // the function the ladder actually calls.
        let r = BmcReport {
            present: true,
            readable: true,
            cooling: Cooling::default(),
            faults: vec![],
            fan_watts_estimated: 0.0,
            thermal_rung: Some("halt".into()),
            hottest: None,
            wall: None,
        };
        assert_eq!(thermal_rung(&r), None, "halt must not round-trip");
    }
}
