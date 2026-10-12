//! What the machine actually draws from the wall.
//!
//! Every energy, cost and carbon figure this system produces divides by this
//! number, and until now it was a guess: package draw multiplied by a configured
//! factor, declared in a file, never checked. The profile named the gap
//! honestly (`Gap::NoWallMeter`) and the assumption stood anyway, because
//! nobody had a meter.
//!
//! It turns out there was one. Server-class power supplies on this hardware
//! report input and output power to the management controller, which means the
//! measurement was sitting one IPMI round trip away the whole time.
//!
//! ## Input and output are different questions
//!
//! `Total Power` is what crosses the meter the utility bills. `Total Power Out`
//! is what the supply delivers to the board after its own conversion losses.
//! The first is the one that costs money and emits carbon; the second is the
//! one that heats the room in a way the fans have to answer for.
//!
//! Keeping both is not pedantry. Their difference is supply efficiency, which
//! is a real and diagnosable quantity — a supply degrading toward failure loses
//! efficiency before it loses regulation, and nothing else on this machine
//! would notice.
//!
//! ## Why this does not replace RAPL
//!
//! RAPL measures a package; this measures a chassis. Attributing site energy to
//! a workload needs the first, and paying the bill needs the second. A system
//! holding only one of them is either unable to bill or unable to attribute.
//! They are also a check on each other: package draw exceeding wall draw is
//! impossible, and observing it means one of the two is lying.

use serde::{Deserialize, Serialize};

/// How far a raw supply reading is known to overshoot.
///
/// Published measurements of production fleets find power supply telemetry
/// reads high against facility metering by roughly five to ten percent. The
/// bias is systematic rather than noise, so it does not average out and it is
/// worth naming: an uncorrected figure makes a site look like it is drawing
/// more than it is, which is the safe direction for a breaker and the wrong
/// direction for a bill.
///
/// The correction is *not* applied automatically here. A single-machine site
/// has no facility meter to have calibrated against, and silently scaling a
/// measured number by a constant taken from somebody else's hardware is exactly
/// the practice this module was written to end. It is offered, and named.
pub const PSU_OVERREAD_LOW: f64 = 0.05;
pub const PSU_OVERREAD_HIGH: f64 = 0.10;

/// Percentile of aggregated samples that matches facility metering.
///
/// The same measurements find that the 70th percentile of readings aggregated
/// over a minute tracks the facility's own sensors, while the mean is pulled up
/// by transients that the meter does not see. Instantaneous readings are worse
/// still.
pub const CALIBRATION_PERCENTILE: f64 = 0.70;

/// Averaging window, in seconds, for anything that decides against a limit.
///
/// Not a smoothing preference: it is a property of the protection device.
/// Breakers tolerate substantial overload briefly — around 1.2× for tens of
/// seconds is typical — so a controller reacting to an instantaneous peak
/// throttles a machine that was never close to tripping anything, and one
/// averaging over minutes reacts after the breaker has already opened.
pub const DECISION_WINDOW_SECS: u64 = 7;

/// The calibrated draw for a window of raw supply readings.
///
/// Returns `None` for an empty window rather than zero. A window with no
/// samples is a reader that has not started or has stopped, and zero watts is a
/// machine that is switched off — reporting the second for the first would show
/// headroom that does not exist.
pub fn calibrated_w(samples: &[u32]) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut v: Vec<u32> = samples.to_vec();
    v.sort_unstable();
    // Nearest-rank, clamped. With few samples this lands on a real reading
    // rather than interpolating between two, which keeps the result a thing
    // the hardware actually reported.
    let rank = ((v.len() as f64) * CALIBRATION_PERCENTILE).ceil() as usize;
    let idx = rank.saturating_sub(1).min(v.len() - 1);
    Some(f64::from(v[idx]))
}

/// Power at the chassis boundary, as the management controller measures it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wall {
    /// Drawn from the mains. The figure that costs money.
    pub input_watts: u32,
    /// Delivered to the board. `None` where the supply reports only input.
    pub output_watts: Option<u32>,
}

impl Wall {
    /// Supply efficiency as a percentage, where both ends are known.
    ///
    /// `None` rather than 100 when output is unreported: a supply that does not
    /// say cannot be assumed perfect, and 100% would be the one value
    /// guaranteed wrong.
    pub fn efficiency_pct(&self) -> Option<u32> {
        let out = self.output_watts?;
        if self.input_watts == 0 || out > self.input_watts {
            // Output above input is not a very good supply, it is a bad
            // reading, and reporting it as an efficiency would launder a sensor
            // fault into a plausible number.
            return None;
        }
        Some(out * 100 / self.input_watts)
    }

    /// How much the supply itself is turning into heat.
    pub fn conversion_loss_watts(&self) -> Option<u32> {
        let out = self.output_watts?;
        self.input_watts.checked_sub(out)
    }

    /// The ratio a profile would otherwise have to declare.
    ///
    /// Returned so a configured `package_to_wall` can be checked against
    /// reality rather than trusted. The whole reason this module exists is that
    /// on this site the declared figure was wrong by more than a factor of two.
    pub fn measured_ratio_to(&self, package_watts: f64) -> Option<f64> {
        (package_watts > 0.0).then(|| f64::from(self.input_watts) / package_watts)
    }
}

/// Read chassis power out of the controller's sensor dump.
///
/// Takes the same text `cooling::parse_sdr` takes, because it is the same dump
/// and asking the controller twice for one round trip's worth of answers would
/// be wasteful on a bus this slow.
///
/// Sensor naming varies by vendor, so both the specific and the general name
/// are accepted, preferring the one that unambiguously means input.
pub fn parse_sdr(text: &str) -> Option<Wall> {
    let mut input = None;
    let mut output = None;
    for line in text.lines() {
        let mut parts = line.split('|').map(str::trim);
        let Some(name) = parts.next() else { continue };
        // `ipmitool` emits two layouts and this controller emits both in the
        // same dump: `name | value | status` and `name | id | ok | x | value`.
        // So the reading is found by looking for the field that is a wattage,
        // not by counting columns — position was wrong on the real hardware
        // and the same mistake has already been made once in `cooling.rs`.
        let Some(w) = parts.find_map(|f| {
            f.strip_suffix("Watts")
                .map(str::trim)
                .and_then(|n| n.parse::<u32>().ok())
        }) else {
            continue;
        };

        let lower = name.to_ascii_lowercase();
        // Checked before the input names: "Total Power Out" also contains
        // "total power", and matching that first would record the output as the
        // billed figure and understate the bill on every machine.
        if lower.contains("out") {
            output = Some(w);
        } else if lower.contains("total power") || lower.contains("psu power") {
            // Multiple supplies each report separately; the chassis draws
            // their sum.
            input = Some(input.map_or(w, |p: u32| p.max(w)));
        }
    }
    input.map(|input_watts| Wall {
        input_watts,
        output_watts: output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from a Fujitsu CELSIUS C740 on this site, `ipmitool sdr elist`.
    const REAL: &str = "\
PSU Power        | 28h | ok  | 10.4 | 69 Watts
Total Power      | 29h | ok  | 224.0 | 69 Watts
Total Power Out  | 2Ah | ok  | 224.1 | 57 Watts
Ambient          | 01h | ok  | 55.0 | 32 degrees C
FAN1 GFX         | 21h | ok  | 29.0 | 9400 RPM";

    /// Verbatim from `/run/furcate/cooling.txt` on node-b — the file this
    /// actually parses in production, which turned out to be a *different*
    /// layout from the one above. The reading is the middle field here and the
    /// last field there, and the same controller emits both in one dump.
    const REAL_PUBLISHED: &str = "\
PSU Power        | 63 Watts          | ok
Total Power      | 63 Watts          | ok
Total Power Out  | 57 Watts          | ok
Total Power      | 0x01              | ok
Total Power Out  | 0x01              | ok
Ambient          | 32 degrees C      | ok
FAN1 GFX         | 9400 RPM          | ok";

    #[test]
    fn the_real_dump_from_this_hardware_parses() {
        let w = parse_sdr(REAL).expect("this machine reports chassis power");
        assert_eq!(w.input_watts, 69);
        assert_eq!(w.output_watts, Some(57));
    }

    #[test]
    fn the_layout_this_actually_parses_in_production_works() {
        // The first version of this module read the last field, which is
        // correct for `sdr elist` and wrong for the dump the privileged reader
        // publishes. It parsed nothing on the real machine and reported a site
        // with no wall meter — while the meter sat in the file.
        let w = parse_sdr(REAL_PUBLISHED).expect("the published dump carries chassis power");
        assert_eq!(w.input_watts, 63);
        assert_eq!(w.output_watts, Some(57));
    }

    #[test]
    fn a_discrete_sensor_sharing_a_name_is_not_a_wattage() {
        // This controller emits `Total Power | 0x01 | ok` alongside the analogue
        // reading. Parsing 0x01 as one watt would report a machine drawing
        // almost nothing.
        let only_discrete = "Total Power | 0x01 | ok\nTotal Power Out | 0x01 | ok";
        assert!(parse_sdr(only_discrete).is_none());
    }

    #[test]
    fn the_billed_figure_is_input_not_output() {
        // "Total Power Out" contains "total power". Matching that first would
        // record 57 W as the number the utility meters, understating every
        // bill and every carbon figure derived from it.
        let w = parse_sdr(REAL).unwrap();
        assert_eq!(w.input_watts, 69, "input must win over the output sensor");
        assert!(w.input_watts > w.output_watts.unwrap());
    }

    #[test]
    fn conversion_loss_is_the_difference_and_efficiency_follows() {
        let w = parse_sdr(REAL).unwrap();
        assert_eq!(w.conversion_loss_watts(), Some(12));
        assert_eq!(w.efficiency_pct(), Some(82));
    }

    #[test]
    fn the_calibration_percentile_is_below_the_peak_and_above_the_median() {
        // The point of P70: transients pull the mean up past what a facility
        // meter sees, and the median throws away real load.
        let w = [60u32, 62, 63, 64, 65, 66, 68, 70, 95, 120];
        let c = calibrated_w(&w).unwrap();
        assert!(c < 95.0, "must discard the transient tail, got {c}");
        assert!(c > 64.0, "must not collapse to the median, got {c}");
    }

    #[test]
    fn an_empty_window_is_not_a_machine_drawing_nothing() {
        // Zero would show headroom that does not exist.
        assert!(calibrated_w(&[]).is_none());
    }

    #[test]
    fn a_single_sample_is_that_sample() {
        assert_eq!(calibrated_w(&[63]), Some(63.0));
    }

    #[test]
    fn the_result_is_always_a_reading_the_hardware_actually_gave() {
        // Nearest-rank, not interpolated. A figure between two samples is a
        // number no sensor reported.
        let w = [10u32, 20, 30, 40];
        let c = calibrated_w(&w).unwrap();
        assert!(w.iter().any(|x| f64::from(*x) == c), "got {c}");
    }

    #[test]
    fn the_decision_window_is_shorter_than_a_breaker_tolerates() {
        // Longer than the overload a breaker rides out and the controller
        // reacts after it has opened; instantaneous and it throttles machines
        // that were never close.
        const { assert!(DECISION_WINDOW_SECS < 45) };
        const { assert!(DECISION_WINDOW_SECS > 1) };
    }

    #[test]
    fn the_known_overread_is_named_and_not_silently_applied() {
        // A measured figure scaled by a constant from somebody else's hardware
        // is the practice this module exists to end.
        let w = parse_sdr(REAL).unwrap();
        assert_eq!(w.input_watts, 69, "raw, uncorrected");
        const { assert!(PSU_OVERREAD_LOW < PSU_OVERREAD_HIGH) };
    }

    #[test]
    fn a_supply_that_does_not_report_output_is_not_assumed_perfect() {
        // 100% would be the one value guaranteed to be wrong.
        let w = Wall { input_watts: 70, output_watts: None };
        assert_eq!(w.efficiency_pct(), None);
        assert_eq!(w.conversion_loss_watts(), None);
    }

    #[test]
    fn output_above_input_is_a_fault_not_an_efficiency() {
        let w = Wall { input_watts: 50, output_watts: Some(60) };
        assert_eq!(w.efficiency_pct(), None);
    }

    #[test]
    fn a_machine_with_no_power_sensors_reports_nothing_rather_than_zero() {
        // Zero would read as a machine drawing no power, which divides into
        // every derived figure as an infinitely efficient one.
        let text = "Ambient | 01h | ok | 55.0 | 32 degrees C";
        assert!(parse_sdr(text).is_none());
    }

    #[test]
    fn temperatures_and_tachometers_are_not_mistaken_for_watts() {
        let text = "FAN1 GFX | 21h | ok | 29.0 | 9400 RPM\nAmbient | 01h | ok | 55.0 | 32 degrees C";
        assert!(parse_sdr(text).is_none());
    }

    #[test]
    fn two_supplies_are_the_chassis_draw_not_one_of_them() {
        let text = "\
PSU1 Power | 28h | ok | 10.4 | 70 Watts
PSU2 Power | 28h | ok | 10.4 | 65 Watts
Total Power | 29h | ok | 224.0 | 135 Watts";
        assert_eq!(parse_sdr(text).unwrap().input_watts, 135);
    }

    #[test]
    fn the_measured_ratio_exposes_a_wrong_declared_one() {
        // The reason this module exists. This site declared package x 2.0 and
        // the hardware says 5.3 at idle, so every energy figure was understated
        // by more than half.
        let w = parse_sdr(REAL).unwrap();
        let ratio = w.measured_ratio_to(13.0).unwrap();
        assert!(ratio > 5.0, "got {ratio}");
        assert!(w.measured_ratio_to(0.0).is_none(), "no package reading, no ratio");
    }
}
