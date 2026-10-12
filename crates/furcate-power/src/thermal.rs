//! Heat, and which layer is allowed to act on it.
//!
//! A machine has several thermal defences and they are not interchangeable.
//! Getting the division wrong is how software either duplicates a protection it
//! cannot match or, worse, replaces one it cannot uphold.
//!
//! **The silicon** throttles itself. PROCHOT asserts in microseconds, cannot be
//! disabled, and needs no operating system. Nothing above it can react at that
//! speed and nothing above it should try.
//!
//! **The management controller** watches its own sensors and will cut power at
//! its critical threshold — on this site, ninety-four degrees. It runs whether
//! or not Linux is running, which is exactly what a last resort has to do.
//!
//! **The kernel** can hold trip points that trigger an orderly shutdown. On
//! this hardware they are unset — the zone reports `-274°C`, a sentinel below
//! absolute zero — so this layer is absent here and worth knowing about.
//!
//! **This system** is the layer above all of that, and its job is the part none
//! of them do: act *early and gracefully* so the lower layers never have to.
//! Shed work, cap power, checkpoint, drain — all reversible, all well below any
//! threshold that would cut power.
//!
//! ## Why nothing here halts on temperature
//!
//! It is the obvious feature and it would be a mistake. A hardware shutdown at
//! the critical threshold already exists, it is faster, and it survives a
//! kernel panic and a hung agent. Adding a software halt does not make the
//! machine safer; it adds a way to shut down a *healthy* machine because one
//! sensor read badly. The ladder therefore descends as far as draining and
//! stops, and the last rung is left to firmware that cannot be talked out of
//! it.

use crate::ladder::Rung;
use serde::{Deserialize, Serialize};

/// Where a temperature reading came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The processor's own package sensor, via the kernel.
    Package,
    /// The management controller, which sees inlet, memory, chipset and more.
    Controller,
}

/// Thresholds for graduated response, in degrees Celsius.
///
/// Every one of these sits below the controller's own critical threshold, and
/// deliberately so: if this system is working, the controller never acts. If
/// this system is not working, the controller still does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Stop taking new work and reduce power draw.
    pub shed_c: i32,
    /// Checkpoint state while there is still time to do it calmly.
    pub capture_c: i32,
    /// Drain: move work elsewhere and quiesce what cannot move.
    pub quiesce_c: i32,
    /// The controller's own critical threshold, carried for context.
    ///
    /// Not acted on — recorded so a reader can see how much margin the
    /// software layer is leaving, and so a configuration that left none would
    /// be visible rather than implied.
    pub controller_critical_c: i32,
}

impl Thresholds {
    /// Thresholds derived from the machine's own critical point.
    ///
    /// The defaults below were written for hardware whose controller acts at
    /// 94 C. On a machine that acts at 100, keeping them wastes six degrees of
    /// perfectly good headroom; on one that acts at 85, they are above it, and
    /// every software rung would fire after the controller had already taken
    /// over — which is worse than not having them, because it looks like a
    /// layered response and is not one.
    ///
    /// So the steps are held as distances below whatever the hardware says,
    /// not as absolute temperatures. The shape is preserved and the position
    /// follows the machine.
    pub fn below_critical(critical_c: i32) -> Self {
        // The same gaps the defaults describe: nineteen, twelve and six
        // degrees of margin. Kept as differences so the relationship survives
        // being moved.
        Self {
            shed_c: critical_c - 19,
            capture_c: critical_c - 12,
            quiesce_c: critical_c - 6,
            controller_critical_c: critical_c,
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        // Measured on this site: the controller reports upper-critical at 94
        // and upper-non-critical at 92. Everything here is comfortably beneath
        // both, and the machine's ordinary operating point is 38.
        Self {
            shed_c: 75,
            capture_c: 82,
            quiesce_c: 88,
            controller_critical_c: 94,
        }
    }
}

impl Thresholds {
    /// Whether these leave the hardware room to be the last resort.
    ///
    /// A configuration whose software rungs reach the controller's critical
    /// point has quietly made software the safety net, which is the one thing
    /// this arrangement is trying to avoid.
    pub fn leave_hardware_the_last_word(&self) -> bool {
        self.quiesce_c < self.controller_critical_c
            && self.shed_c < self.capture_c
            && self.capture_c < self.quiesce_c
    }

    /// Degrees of margin between the deepest software action and the point at
    /// which firmware cuts power.
    pub fn margin_c(&self) -> i32 {
        self.controller_critical_c - self.quiesce_c
    }
}

/// The rung heat alone justifies.
///
/// Never returns `Halt`. That rung exists for a supply that is about to
/// disappear, where stopping cleanly is strictly better than stopping
/// abruptly. Heat is different: the hardware will stop the machine on its own,
/// sooner and more reliably than this can, so the software ladder stops one
/// step short and leaves the last word to firmware.
pub fn rung_for(celsius: i32, t: &Thresholds) -> Rung {
    if celsius >= t.quiesce_c {
        Rung::Quiesce
    } else if celsius >= t.capture_c {
        Rung::Capture
    } else if celsius >= t.shed_c {
        Rung::Shed
    } else {
        Rung::Nominal
    }
}

/// A temperature worth acting on, with where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reading {
    pub name: String,
    pub celsius: i32,
    pub origin: Origin,
}

/// Decide a rung from every sensor available.
///
/// Takes the hottest, because a machine is as hot as its hottest part and a
/// mean would hide a cooking memory bank behind a cold inlet.
///
/// Returns `None` when nothing was read. Absence of a reading is not a cold
/// machine, and defaulting it to `Nominal` would let a monitoring failure look
/// like good news — the same mistake this codebase avoids everywhere else.
pub fn rung_from(readings: &[Reading], t: &Thresholds) -> Option<(Rung, Reading)> {
    let hottest = readings.iter().max_by_key(|r| r.celsius)?;
    Some((rung_for(hottest.celsius, t), hottest.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(name: &str, c: i32) -> Reading {
        Reading {
            name: name.into(),
            celsius: c,
            origin: Origin::Controller,
        }
    }

    #[test]
    fn heat_never_produces_a_halt() {
        // The design decision this module rests on. The controller cuts power
        // at its critical threshold whether or not this software is running;
        // a software halt adds no safety and adds a way to shut down a healthy
        // machine on one bad sensor read.
        let t = Thresholds::default();
        for c in [0, 50, 75, 82, 88, 94, 120, 999] {
            assert_ne!(rung_for(c, &t), Rung::Halt, "halted at {c}C");
        }
    }

    #[test]
    fn an_ordinary_operating_temperature_does_nothing() {
        // This site idles at 38.
        assert_eq!(rung_for(38, &Thresholds::default()), Rung::Nominal);
    }

    #[test]
    fn the_response_is_graduated_rather_than_a_single_cliff() {
        let t = Thresholds::default();
        assert_eq!(rung_for(74, &t), Rung::Nominal);
        assert_eq!(rung_for(75, &t), Rung::Shed);
        assert_eq!(rung_for(83, &t), Rung::Capture);
        assert_eq!(rung_for(90, &t), Rung::Quiesce);
    }

    #[test]
    fn every_software_rung_sits_below_the_hardware_cutoff() {
        // If it did not, software would have quietly become the safety net.
        let t = Thresholds::default();
        assert!(t.leave_hardware_the_last_word());
        assert!(t.margin_c() >= 5, "margin was {}", t.margin_c());
    }

    #[test]
    fn a_configuration_that_leaves_no_margin_is_detectable() {
        let bad = Thresholds {
            shed_c: 90,
            capture_c: 92,
            quiesce_c: 96,
            controller_critical_c: 94,
        };
        assert!(!bad.leave_hardware_the_last_word());
    }

    #[test]
    fn the_hottest_sensor_decides_rather_than_an_average() {
        // A cooking memory bank behind a cold inlet is exactly what a mean
        // would hide.
        let readings = vec![r("Air-Inlet", 33), r("MEM C", 89), r("CPU", 40)];
        let (rung, hottest) = rung_from(&readings, &Thresholds::default()).unwrap();
        assert_eq!(rung, Rung::Quiesce);
        assert_eq!(hottest.name, "MEM C");
    }

    #[test]
    fn no_readings_yields_no_decision_rather_than_nominal() {
        // A monitoring failure must not look like good news.
        assert!(rung_from(&[], &Thresholds::default()).is_none());
    }

    #[test]
    fn this_sites_real_sensors_produce_no_action() {
        // Measured: ambient 32, inlet 33, CPU 38, memory 35-37, PCH 40,
        // PSU 41. Everything the fans are screaming about is cold.
        let readings = vec![
            r("Ambient", 32),
            r("Air-Inlet", 33),
            r("CPU", 38),
            r("MEM C", 37),
            r("PCH", 40),
            r("PSU", 41),
        ];
        let (rung, _) = rung_from(&readings, &Thresholds::default()).unwrap();
        assert_eq!(rung, Rung::Nominal);
    }

    #[test]
    fn a_package_reading_and_a_controller_reading_are_both_usable() {
        let readings = vec![
            Reading { name: "x86_pkg_temp".into(), celsius: 84, origin: Origin::Package },
            r("Ambient", 30),
        ];
        let (rung, hottest) = rung_from(&readings, &Thresholds::default()).unwrap();
        assert_eq!(rung, Rung::Capture);
        assert_eq!(hottest.origin, Origin::Package);
    }
}

#[cfg(test)]
mod derived_tests {
    use super::*;

    #[test]
    fn the_defaults_are_what_deriving_from_this_hardware_produces() {
        // The constants were written for a controller that acts at 94 C. If
        // deriving from 94 did not reproduce them, one of the two would be
        // wrong and nothing would say which.
        assert_eq!(Thresholds::below_critical(94), Thresholds::default());
    }

    #[test]
    fn every_rung_stays_below_the_hardware_that_acts_without_us() {
        // The whole argument for a software ladder is that its steps happen
        // before the controller takes over. A rung at or above the critical
        // point is not an early step; it is a log line written after the fact.
        for critical in [85, 90, 94, 100, 105] {
            let t = Thresholds::below_critical(critical);
            assert!(t.quiesce_c < critical, "quiesce at {critical}");
            assert!(t.capture_c < t.quiesce_c);
            assert!(t.shed_c < t.capture_c);
            assert!(t.margin_c() > 0, "no margin left at {critical}");
        }
    }

    #[test]
    fn a_cooler_machine_gets_cooler_thresholds_rather_than_the_old_ones() {
        // Keeping 94-degree thresholds on a controller that acts at 85 would
        // put every software rung above the point where the hardware has
        // already taken over.
        let t = Thresholds::below_critical(85);
        assert!(t.shed_c < Thresholds::default().shed_c);
        assert!(t.quiesce_c < 85);
    }

    #[test]
    fn a_hotter_machine_is_allowed_the_headroom_it_has() {
        let t = Thresholds::below_critical(100);
        assert!(t.shed_c > Thresholds::default().shed_c, "six degrees not thrown away");
    }
}
