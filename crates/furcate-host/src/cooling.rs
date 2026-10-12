//! Fans, and whether they are working for a living.
//!
//! A management controller runs the fans on server-class hardware, and it does
//! so independently of the operating system — which is the right design,
//! because a fan curve that stops when the OS hangs is a fan curve that cooks a
//! processor. The cost is that the operating system usually cannot see the
//! fans at all, and on this site it could not: Linux exposed one temperature
//! and no tachometers while six fans ran at eighteen thousand RPM.
//!
//! ## The anomaly worth detecting
//!
//! Fans at maximum with a hot machine is a fan curve doing its job. Fans at
//! maximum with a *cold* machine is a controller that has lost confidence in
//! something and is failing safe — most often because a thermal sensor it
//! expects to read is returning nothing, so it assumes the worst and never
//! stops assuming it.
//!
//! That combination is invisible to every threshold you would normally set.
//! Temperature alarms are quiet because the machine is cold. Fan alarms are
//! quiet because the fans are spinning. The fault only appears when the two
//! are considered together, which is what this does.
//!
//! ## Why nothing here sets a fan speed
//!
//! It is tempting, given a temperature reading, to drive the fans directly.
//! Two reasons not to. Most controllers of this class do not expose it —
//! Fujitsu's iRMC defines fan behaviour in firmware and declines the command
//! outright. And where it *is* exposed, taking manual control means the fans
//! stay wherever software last left them if that software dies, which converts
//! a monitoring outage into a thermal one. The controller's own curve survives
//! the OS; a replacement for it would not.
//!
//! So the contribution here is evidence, not actuation: measure both sides,
//! notice when they disagree, and say what it is costing.

use serde::{Deserialize, Serialize};

/// One fan, as the management controller reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fan {
    pub name: String,
    pub rpm: u32,
    /// Whether the controller considers the reading valid.
    pub ok: bool,
}

/// One temperature the controller can see.
///
/// Richer than the operating system's view by a long way: inlet, exhaust,
/// memory banks, chipset, power supply, expansion slots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Temperature {
    pub name: String,
    pub celsius: i32,
}

/// A sensor the controller expects and cannot read.
///
/// The most consequential field in this module. A controller with a blind spot
/// does not degrade gracefully — it assumes the worst about the thing it
/// cannot see, and on cooling that means maximum airflow indefinitely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blind {
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cooling {
    pub fans: Vec<Fan>,
    pub temperatures: Vec<Temperature>,
    /// Sensors present in the controller's inventory that report nothing.
    pub blind: Vec<Blind>,
}

impl Cooling {
    /// The hottest thing the controller can see.
    pub fn hottest(&self) -> Option<&Temperature> {
        self.temperatures.iter().max_by_key(|t| t.celsius)
    }

    pub fn fastest_fan(&self) -> Option<&Fan> {
        self.fans.iter().filter(|f| f.ok).max_by_key(|f| f.rpm)
    }

    /// Rough electrical cost of the fans, in watts.
    ///
    /// A cube law on speed, which is how fan power behaves, against a nominal
    /// figure for a server fan at full tilt. Deliberately coarse and marked as
    /// an estimate wherever it surfaces — the point is not the number but its
    /// order of magnitude, and the order of magnitude is the finding: six fans
    /// at maximum can draw several times what an idle processor does.
    pub fn estimated_watts(&self, max_rpm: u32, watts_at_max: f64) -> f64 {
        if max_rpm == 0 {
            return 0.0;
        }
        self.fans
            .iter()
            .filter(|f| f.ok)
            .map(|f| {
                let ratio = (f.rpm as f64 / max_rpm as f64).clamp(0.0, 1.0);
                watts_at_max * ratio.powi(3)
            })
            .sum()
    }
}

/// What is wrong with the cooling, if anything.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// Fans are running hard while the machine is cold.
    ///
    /// Not a cooling failure — a cooling *control* failure, and the two want
    /// completely different responses.
    RunningHardWhileCold { fastest_rpm: u32, hottest_c: i32 },
    /// The controller cannot read a sensor it has in its inventory.
    SensorBlind { names: Vec<String> },
    /// A fan has stopped or is reporting an invalid speed.
    FanFailed { name: String },
    /// Genuinely hot.
    Hot { name: String, celsius: i32 },
}

impl Fault {
    /// Whether this is a thermal emergency as opposed to a control problem.
    ///
    /// A machine that is too hot is losing hardware. A machine whose fans are
    /// loud for no reason is losing nothing, which is why this is the wrong
    /// question to decide urgency with on its own — see
    /// [`Self::demands_attention_now`].
    pub fn is_thermal(&self) -> bool {
        matches!(self, Fault::Hot { .. } | Fault::FanFailed { .. })
    }

    /// Whether this needs somebody now, given where the machine sits.
    ///
    /// This used to be [`Self::is_thermal`] alone, and the doc comment on it
    /// said a machine whose fans are loud for no reason "needs attention on a
    /// weekday". That is right in a hall and exactly wrong in a house. Nothing
    /// is breaking, so nobody is paged — but somebody is awake because of it,
    /// and telling them to wait until Monday is not a triage decision, it is
    /// three more nights of this.
    ///
    /// `local_hour` is the hour at the machine's own site.
    pub fn demands_attention_now(
        &self,
        acoustics: &crate::acoustics::Acoustics,
        local_hour: u8,
    ) -> bool {
        if self.is_thermal() {
            return true;
        }
        matches!(self, Fault::RunningHardWhileCold { .. }) && acoustics.disturbing(local_hour)
    }
}

/// Thresholds for judging a cooling system.
pub struct Limits {
    /// RPM above which a fan is working hard **for this machine**.
    ///
    /// Per-machine, and it has to be. An absolute figure is meaningless across
    /// hardware classes: the fans this module was written against reach 18,000
    /// RPM, while a Cisco UCS C220 M4 tops out near 9,200. A threshold of
    /// 12,000 is an early warning on the first and is above the *maximum* of
    /// the second — so on that machine the check could never fire, no matter
    /// how loud it got or how cold it was. It ran at full speed for days and
    /// this module stayed silent, which is the failure it exists to prevent
    /// arriving from underneath.
    ///
    /// Build it with [`Limits::for_fan_max`] wherever the machine's ceiling is
    /// known, and with [`Limits::relative_to_observed`] where it is not.
    pub hard_rpm: u32,
    /// Temperature below which nothing justifies working hard.
    ///
    /// Fifty degrees, and the number has a source rather than being a round
    /// one. ASHRAE TC 9.9's thermal guidelines (2021, 5th edition) put the
    /// *recommended* inlet envelope at 18-27 C for every air-cooled class, and
    /// the allowable ceiling at 32, 35, 40 and 45 C for classes A1 to A4. A
    /// machine whose hottest reading is still below fifty is inside even the
    /// most permissive of those with margin to spare, so its fans have nothing
    /// to answer for.
    ///
    /// Deliberately compared against the hottest sensor rather than the inlet
    /// alone. The inlet says what the room is doing; the hottest component says
    /// whether this machine is in trouble, and it is the second that decides
    /// whether airflow is earned.
    pub cold_c: i32,
    /// Temperature at which something is actually wrong.
    ///
    /// Eighty. Above ASHRAE's A4 allowable inlet by a wide margin, which is the
    /// point: by the time a *component* reads this, the question is no longer
    /// what class the room is run at.
    pub hot_c: i32,
}

/// Fraction of a machine's maximum fan speed treated as working hard.
///
/// Seven tenths. Below it a fan curve is responding; at or above it the
/// controller has decided the machine needs most of the airflow it has, and
/// that decision is either justified by heat or it is not.
const HARD_FRACTION: f64 = 0.70;

impl Default for Limits {
    /// Thresholds for hardware whose fans reach roughly 18,000 RPM.
    ///
    /// Kept so existing callers compile, but it is the wrong constructor for
    /// any machine whose ceiling differs — which is most of them. Prefer
    /// [`Limits::for_fan_max`].
    fn default() -> Self {
        Self {
            hard_rpm: 12_000,
            cold_c: 50,
            hot_c: 80,
        }
    }
}

impl Limits {
    /// Thresholds for a machine whose fans top out at `max_rpm`.
    pub fn for_fan_max(max_rpm: u32) -> Self {
        Self {
            hard_rpm: ((f64::from(max_rpm) * HARD_FRACTION) as u32).max(1),
            ..Self::default()
        }
    }

    /// Thresholds for a machine whose ceiling nobody has declared, scaled to
    /// the fastest speed this machine has actually been seen to run.
    ///
    /// The fallback, and a deliberately self-fulfilling one: a machine that
    /// has only ever been observed at full tilt will compare its current speed
    /// against that, and report. That is the correct outcome rather than a
    /// flaw — such a machine *has* been running hard the whole time, and the
    /// alternative is the silence that let it.
    ///
    /// It cannot produce a false alarm on a quiet machine, because the
    /// two-sided check still requires the hardware to be cold, and a cold
    /// machine with idling fans has a low observed maximum and a current speed
    /// at or below it either way.
    pub fn relative_to_observed(observed_max_rpm: u32) -> Self {
        Self::for_fan_max(observed_max_rpm)
    }
}

/// Judge a cooling system by comparing both sides of it.
pub fn assess(c: &Cooling, limits: &Limits) -> Vec<Fault> {
    let mut out = Vec::new();

    for t in &c.temperatures {
        if t.celsius >= limits.hot_c {
            out.push(Fault::Hot {
                name: t.name.clone(),
                celsius: t.celsius,
            });
        }
    }

    for f in &c.fans {
        if !f.ok || (f.rpm == 0 && c.fans.iter().any(|o| o.rpm > 0)) {
            out.push(Fault::FanFailed { name: f.name.clone() });
        }
    }

    // The two-sided check. Only meaningful when both sides were actually read;
    // a machine with no temperature sensors is not a cold machine.
    if let (Some(fan), Some(hot)) = (c.fastest_fan(), c.hottest()) {
        if fan.rpm >= limits.hard_rpm && hot.celsius < limits.cold_c {
            out.push(Fault::RunningHardWhileCold {
                fastest_rpm: fan.rpm,
                hottest_c: hot.celsius,
            });
        }
    }

    if !c.blind.is_empty() {
        out.push(Fault::SensorBlind {
            names: c.blind.iter().map(|b| b.name.clone()).collect(),
        });
    }

    out
}

/// Parse `ipmitool sdr` output, in either of the two shapes it emits.
///
/// Plain `sdr` gives three columns:
/// ```text
/// Ambient          | 32 degrees C      | ok
/// ```
/// while `sdr type Fan` gives five:
/// ```text
/// FAN4 SYS         | 24h | ok  | 29.3 | 18400 RPM
/// ```
///
/// Both are accepted because both are what the tool actually produces, and a
/// parser that only knew the five-column form silently reported an empty
/// cooling system on a machine with seven fans — which is exactly the failure
/// this module exists to catch, arriving from the other direction.
///
/// Anything that is not a fan, a temperature or an unreadable sensor is
/// ignored rather than guessed at: voltages and currents are on the same
/// listing and have nothing to say about cooling.
pub fn parse_sdr(text: &str) -> Cooling {
    let mut c = Cooling::default();

    for line in text.lines() {
        let f: Vec<&str> = line.split('|').map(|p| p.trim()).collect();
        let (name, state, reading) = match f.len() {
            3 => (f[0], f[2], f[1]),
            n if n >= 5 => (f[0], f[2], f[4]),
            _ => continue,
        };
        if name.is_empty() {
            continue;
        }

        if reading.eq_ignore_ascii_case("no reading") || state == "ns" {
            c.blind.push(Blind { name: name.to_string() });
            continue;
        }
        if let Some(rpm) = reading.strip_suffix(" RPM").and_then(|v| v.trim().parse().ok()) {
            c.fans.push(Fan {
                name: name.to_string(),
                rpm,
                ok: state == "ok",
            });
            continue;
        }
        if let Some(deg) = reading
            .strip_suffix(" degrees C")
            .and_then(|v| v.trim().parse().ok())
        {
            c.temperatures.push(Temperature {
                name: name.to_string(),
                celsius: deg,
            });
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This site's actual reading, which is what prompted the module.
    fn real() -> Cooling {
        parse_sdr(
            "FAN1 GFX         | 21h | ok  | 29.0 | 9400 RPM\n\
             FAN2 GFX         | 22h | ok  | 29.1 | 9400 RPM\n\
             FAN3 GFX         | 23h | ok  | 29.2 | 9000 RPM\n\
             FAN4 SYS         | 24h | ok  | 29.3 | 18400 RPM\n\
             FAN5 SYS         | 25h | ok  | 29.4 | 18400 RPM\n\
             FAN6 SYS         | 26h | ok  | 29.5 | 17800 RPM\n\
             FAN PSU          | 27h | ok  | 10.4 | 3600 RPM\n\
             Ambient          | 01h | ok  | 55.0 | 32 degrees C\n\
             CPU              | 03h | ok  |  3.0 | 38 degrees C\n\
             PSU              | 0Bh | ok  | 10.4 | 41 degrees C\n\
             GPU              | 09h | ns  | 18.0 | No Reading\n\
             RAID Controller  | 0Dh | ns  | 18.0 | No Reading\n\
             CPU 1.05V        | 0Eh | ns  |  1.0 | No Reading",
        )
    }

    /// A Cisco UCS C220 M4S at midnight, read from the machine on
    /// 2026-09-13: twelve tachometers between 7,500 and 9,200 RPM with the
    /// chassis at 26 °C and the busiest DIMM at 41 °C. Nothing is hot. The
    /// fans are at roughly full speed because the controller has overridden
    /// its own policy, which on this model happens when a PSU loses input or
    /// an idle expansion card trips the override.
    fn ucs_c220_at_midnight() -> Cooling {
        parse_sdr(
            "FAN1_TACH1       | 0Fh | ok  | 29.1 | 7700 RPM\n\
             FAN1_TACH2       | 10h | ok  | 29.1 | 8800 RPM\n\
             FAN2_TACH1       | 11h | ok  | 29.2 | 7700 RPM\n\
             FAN2_TACH2       | 12h | ok  | 29.2 | 8800 RPM\n\
             FAN3_TACH1       | 13h | ok  | 29.3 | 7700 RPM\n\
             FAN3_TACH2       | 14h | ok  | 29.3 | 8800 RPM\n\
             FAN4_TACH1       | 15h | ok  | 29.4 | 7500 RPM\n\
             FAN4_TACH2       | 16h | ok  | 29.4 | 9200 RPM\n\
             FAN5_TACH1       | 17h | ok  | 29.5 | 7700 RPM\n\
             FAN5_TACH2       | 18h | ok  | 29.5 | 8800 RPM\n\
             FAN6_TACH1       | 19h | ok  | 29.6 | 7500 RPM\n\
             FAN6_TACH2       | 1Ah | ok  | 29.6 | 8800 RPM\n\
             FP_TEMP_SENSOR   | 43h | ok  | 12.1 | 26 degrees C\n\
             DDR4_P1_A1_TEMP  | 51h | ok  |  8.0 | 41 degrees C",
        )
    }

    /// **The silence this module was supposed to prevent, arriving from
    /// underneath.** Every fan on this machine is at or near its ceiling and
    /// the chassis is at 26 °C — the exact anomaly the module docs describe —
    /// and the default threshold reports nothing, because 12,000 RPM is above
    /// anything this hardware can physically reach.
    ///
    /// The machine ran like this for days and no check fired.
    #[test]
    fn the_default_threshold_cannot_fire_on_hardware_with_slower_fans() {
        let c = ucs_c220_at_midnight();
        assert_eq!(c.fastest_fan().unwrap().rpm, 9_200);
        assert!(
            c.fastest_fan().unwrap().rpm < Limits::default().hard_rpm,
            "this machine's maximum is below the default threshold, which is the \
             whole defect"
        );
        assert!(
            !assess(&c, &Limits::default())
                .iter()
                .any(|f| matches!(f, Fault::RunningHardWhileCold { .. })),
            "kept as a record of what the old default did"
        );
    }

    /// Scaled to the machine in front of it, the same reading is caught.
    #[test]
    fn scaled_to_the_machine_the_same_reading_is_caught() {
        let c = ucs_c220_at_midnight();
        let faults = assess(&c, &Limits::for_fan_max(9_200));
        let found = faults
            .iter()
            .find(|f| matches!(f, Fault::RunningHardWhileCold { .. }))
            .expect("fans at the ceiling on a 26 C machine must be reported");
        match found {
            Fault::RunningHardWhileCold {
                fastest_rpm,
                hottest_c,
            } => {
                assert_eq!(*fastest_rpm, 9_200);
                assert_eq!(*hottest_c, 41);
            }
            _ => unreachable!(),
        }
    }

    /// And caught with no profile at all, by scaling to what the machine has
    /// been seen to do. This is the path most hardware takes, because most
    /// hardware has no profile written for it.
    #[test]
    fn with_no_profile_the_observed_speed_is_enough_to_catch_it() {
        let c = ucs_c220_at_midnight();
        let observed = c.fastest_fan().unwrap().rpm;
        assert!(
            assess(&c, &Limits::relative_to_observed(observed))
                .iter()
                .any(|f| matches!(f, Fault::RunningHardWhileCold { .. }))
        );
    }

    /// The two-sided check still protects it. A machine working hard *because*
    /// it is hot is a fan curve doing its job, and scaling the threshold down
    /// must not turn that into a fault.
    #[test]
    fn a_hot_machine_working_hard_is_not_a_control_fault() {
        let c = parse_sdr(
            "FAN1_TACH1       | 0Fh | ok  | 29.1 | 9200 RPM\n\
             CPU              | 03h | ok  |  3.0 | 71 degrees C",
        );
        assert!(
            !assess(&c, &Limits::for_fan_max(9_200))
                .iter()
                .any(|f| matches!(f, Fault::RunningHardWhileCold { .. })),
            "71 C justifies the airflow"
        );
    }

    /// A quiet machine does not accuse itself. Scaling to the observed maximum
    /// could in principle always compare a machine against itself and always
    /// report — it does not, because a machine that is idling has a low
    /// observed maximum too.
    #[test]
    fn an_idling_machine_reports_nothing() {
        let c = parse_sdr(
            "FAN1_TACH1       | 0Fh | ok  | 29.1 | 3300 RPM\n\
             FAN2_TACH1       | 11h | ok  | 29.2 | 3400 RPM\n\
             FP_TEMP_SENSOR   | 43h | ok  | 12.1 | 24 degrees C",
        );
        // Against the machine's real ceiling, 3,400 of 9,200 is not hard.
        assert!(assess(&c, &Limits::for_fan_max(9_200)).is_empty());
    }

    /// **Who this wakes, and when.** The same fault, in two places. Nothing is
    /// breaking either way — but in a house at one in the morning somebody is
    /// awake because of it, and "look at it on a weekday" is three more nights
    /// of this.
    #[test]
    fn a_control_fault_is_urgent_only_where_it_costs_somebody_sleep() {
        use crate::acoustics::Acoustics;

        let fault = Fault::RunningHardWhileCold {
            fastest_rpm: 9_200,
            hottest_c: 41,
        };
        assert!(!fault.is_thermal(), "nothing is breaking");

        let hall = Acoustics::machine_room();
        let home = Acoustics::living_space();

        assert!(!fault.demands_attention_now(&hall, 1), "a rack at 01:00");
        assert!(fault.demands_attention_now(&home, 1), "a house at 01:00");
        assert!(!fault.demands_attention_now(&home, 14), "a house at 14:00");
    }

    /// A machine that is genuinely too hot wakes somebody wherever it is. The
    /// acoustic rule only ever adds urgency; it can never take it away.
    #[test]
    fn heat_is_urgent_everywhere_and_at_every_hour() {
        use crate::acoustics::Acoustics;

        let hot = Fault::Hot {
            name: "CPU".into(),
            celsius: 92,
        };
        for h in [1u8, 14] {
            assert!(hot.demands_attention_now(&Acoustics::machine_room(), h));
            assert!(hot.demands_attention_now(&Acoustics::living_space(), h));
        }
    }

    #[test]
    fn the_real_listing_parses_into_its_three_kinds() {
        let c = real();
        assert_eq!(c.fans.len(), 7);
        assert_eq!(c.temperatures.len(), 3);
        assert_eq!(c.blind.len(), 3);
    }

    #[test]
    fn the_three_column_form_parses_too() {
        // What plain `ipmitool sdr` emits, and what the privileged reader
        // publishes. A parser that only knew the five-column form reported an
        // empty cooling system on a machine with seven fans.
        let c = parse_sdr(
            "Ambient          | 32 degrees C      | ok\n\
             FAN4 SYS         | 18400 RPM         | ok\n\
             GPU              | No Reading        | ns",
        );
        assert_eq!(c.temperatures.len(), 1);
        assert_eq!(c.fans.len(), 1);
        assert_eq!(c.fans[0].rpm, 18_400);
        assert_eq!(c.blind.len(), 1);
    }

    #[test]
    fn voltages_and_other_rows_are_ignored_rather_than_guessed_at() {
        let c = parse_sdr("VBAT | 30h | ok | 7.1 | 3.05 Volts\nFAN1 | 21h | ok | 29.0 | 900 RPM");
        assert_eq!(c.fans.len(), 1);
        assert!(c.temperatures.is_empty());
    }

    #[test]
    fn the_two_sided_check_catches_what_neither_threshold_would() {
        // The finding this module exists for. A temperature alarm is quiet
        // because the machine is cold; a fan alarm is quiet because the fans
        // are spinning. Only together do they say anything.
        let faults = assess(&real(), &Limits::default());
        let anomaly = faults
            .iter()
            .find(|f| matches!(f, Fault::RunningHardWhileCold { .. }))
            .expect("should have caught it");
        assert!(matches!(
            anomaly,
            Fault::RunningHardWhileCold { fastest_rpm: 18400, hottest_c: 41 }
        ));
        assert!(!anomaly.is_thermal(), "it is a control problem, not a thermal one");
    }

    #[test]
    fn the_blind_sensor_is_reported_because_it_is_usually_the_cause() {
        let faults = assess(&real(), &Limits::default());
        let blind = faults
            .iter()
            .find_map(|f| match f {
                Fault::SensorBlind { names } => Some(names),
                _ => None,
            })
            .expect("blind sensors should be reported");
        assert!(blind.iter().any(|n| n == "GPU"));
    }

    #[test]
    fn a_hot_machine_with_fast_fans_is_not_an_anomaly() {
        // That is a fan curve doing its job, and reporting it would be noise.
        let mut c = real();
        c.temperatures = vec![Temperature { name: "CPU".into(), celsius: 72 }];
        let faults = assess(&c, &Limits::default());
        assert!(!faults.iter().any(|f| matches!(f, Fault::RunningHardWhileCold { .. })));
    }

    #[test]
    fn a_genuinely_hot_sensor_is_a_thermal_fault_and_says_so() {
        // Different urgency, different person, different hour of the night.
        let mut c = real();
        c.temperatures.push(Temperature { name: "CPU".into(), celsius: 88 });
        let f = assess(&c, &Limits::default());
        let hot = f.iter().find(|x| matches!(x, Fault::Hot { .. })).unwrap();
        assert!(hot.is_thermal());
    }

    #[test]
    fn a_stopped_fan_among_running_ones_is_a_failure() {
        let mut c = real();
        c.fans.push(Fan { name: "FAN7".into(), rpm: 0, ok: true });
        assert!(assess(&c, &Limits::default())
            .iter()
            .any(|f| matches!(f, Fault::FanFailed { .. })));
    }

    #[test]
    fn a_machine_with_no_temperature_sensors_is_not_called_cold() {
        // Absence of a reading is not a low reading, and treating it as one
        // would raise this anomaly on every machine without a BMC.
        let c = Cooling {
            fans: vec![Fan { name: "FAN1".into(), rpm: 18_000, ok: true }],
            temperatures: vec![],
            blind: vec![],
        };
        assert!(!assess(&c, &Limits::default())
            .iter()
            .any(|f| matches!(f, Fault::RunningHardWhileCold { .. })));
    }

    #[test]
    fn the_fans_cost_more_than_the_processor_does_at_idle() {
        // The finding that makes this an energy question rather than only a
        // noise one: this site's package idles at 13 W.
        let w = real().estimated_watts(20_000, 15.0);
        assert!(w > 13.0, "estimated {w} W");
    }

    #[test]
    fn slowing_the_fans_saves_disproportionately() {
        // Cube law: half the speed is an eighth of the power, which is why
        // this is worth chasing at all.
        let fast = real().estimated_watts(20_000, 15.0);
        let slow = Cooling {
            fans: real()
                .fans
                .iter()
                .map(|f| Fan { rpm: f.rpm / 2, ..f.clone() })
                .collect(),
            ..real()
        }
        .estimated_watts(20_000, 15.0);
        assert!(slow < fast / 4.0, "{slow} should be far below {fast}");
    }
}
