//! The graceful degradation ladder.
//!
//! NUT's own guidance is that dependents shut down before the machine holding
//! the supply connection, and that timers should absorb brief events rather
//! than reacting to the first one. A dumb supply signalling only on-line, on-
//! battery and low-battery through contact closure is enough to drive all of
//! this — which matters, because that is exactly what the first site has.

use serde::{Deserialize, Serialize};

/// What the supply is reporting. These map to the three contact-closure
/// signals a `genericups` driver exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    /// On line power.
    OnLine,
    /// Running from battery.
    OnBattery,
    /// Battery is nearly exhausted.
    LowBattery,
}

/// Rungs of the descent, in order. Every rung below `Halt` is reversible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    /// Nothing is happening, or the event is still within the dwell window.
    Nominal = 0,
    /// Cap power, shed preemptible work, stop accepting new work.
    Shed = 1,
    /// Capture session and workload state, flush and checkpoint.
    Capture = 2,
    /// Quiesce databases, drain, unmount cleanly.
    Quiesce = 3,
    /// Ordered halt: leaf domains first, controller last.
    Halt = 4,
}

impl Rung {
    /// Whether returning power can still undo this rung.
    pub fn is_reversible(&self) -> bool {
        *self < Rung::Halt
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Rung::Nominal => "nominal",
            Rung::Shed => "shed",
            Rung::Capture => "capture",
            Rung::Quiesce => "quiesce",
            Rung::Halt => "halt",
        }
    }
}


/// Thresholds for a supply that reports charge but not runtime.
///
/// The Green Cell publishes no runtime and its low-battery flag is unproven,
/// so the ladder descends on the charge left and on how long the site has been
/// on battery, whichever is worse. All of it is configuration: the figures
/// below are starting points for a small supply, not facts about any one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Triggers {
    /// Seconds on battery to absorb before acting at all.
    pub dwell_secs: u64,
    /// Capture at or below this charge, or after this long on battery.
    pub capture_charge_pct: f64,
    pub capture_after_secs: u64,
    /// Quiesce at or below this charge, or after this long on battery.
    pub quiesce_charge_pct: f64,
    pub quiesce_after_secs: u64,
    /// Halt at or below this charge, or after this long on battery. The charge
    /// line is the supply's own `battery.charge.low`.
    pub halt_charge_pct: f64,
    pub halt_after_secs: u64,
    /// Whether the driver's `LB` flag halts by itself. Off until it is proven
    /// on the supply in use; the flag is still reported either way.
    pub trust_lb: bool,
    /// An outage is confirmed only after this many consecutive on-battery
    /// reads from upsd, spread over at least `confirm_secs`. One read, a parse
    /// error or stale data never starts the ladder.
    pub confirm_reads: u32,
    pub confirm_secs: u64,
    /// Contact with upsd lost while the last confirmed state was on battery
    /// has to last this long before the ladder keeps counting time without it.
    /// Lost contact while on line never acts at all.
    pub commbad_secs: u64,
}

impl Default for Triggers {
    fn default() -> Self {
        Self {
            dwell_secs: 20,
            capture_charge_pct: 80.0,
            capture_after_secs: 180,
            quiesce_charge_pct: 65.0,
            quiesce_after_secs: 420,
            halt_charge_pct: 50.0,
            halt_after_secs: 900,
            trust_lb: false,
            confirm_reads: 3,
            confirm_secs: 20,
            commbad_secs: 60,
        }
    }
}

impl Triggers {
    pub fn validate(&self) -> Result<(), String> {
        let pct = [self.capture_charge_pct, self.quiesce_charge_pct, self.halt_charge_pct];
        if pct.iter().any(|p| !p.is_finite() || *p < 0.0 || *p > 100.0) {
            return Err("triggers: charge lines must be between 0 and 100".into());
        }
        if !(pct[0] >= pct[1] && pct[1] >= pct[2]) {
            return Err("triggers: capture, quiesce and halt charge lines must descend".into());
        }
        if !(self.capture_after_secs <= self.quiesce_after_secs && self.quiesce_after_secs <= self.halt_after_secs) {
            return Err("triggers: capture, quiesce and halt times must not decrease".into());
        }
        if self.confirm_reads < 2 || self.confirm_secs < 5 {
            return Err("triggers: an outage needs at least 2 reads over at least 5s to be confirmed".into());
        }
        Ok(())
    }
}

/// What the supply said, reduced to what the ladder needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UpsObservation {
    /// `None` when the supply's state is unknown: the ladder holds.
    pub state: Option<PowerState>,
    pub charge_pct: Option<f64>,
    pub runtime_left: Option<u64>,
}

/// Ladder configuration and current position.
pub struct Ladder {
    /// Seconds on battery to absorb before acting at all. Without this a
    /// two-second flicker triggers a full descent.
    dwell: u64,
    /// Seconds of estimated runtime below which state is captured.
    capture_at: u64,
    /// Seconds of estimated runtime below which services are quiesced.
    quiesce_at: u64,
    rung: Rung,
    /// When the current on-battery episode began.
    on_battery_since: Option<u64>,
}

impl Ladder {
    pub fn new(dwell: u64, capture_at: u64, quiesce_at: u64) -> Self {
        Self {
            dwell,
            capture_at,
            quiesce_at,
            rung: Rung::Nominal,
            on_battery_since: None,
        }
    }

    /// Sensible defaults for a small supply: absorb 20s, capture with 120s
    /// left, quiesce with 60s left.
    pub fn default_for_small_ups() -> Self {
        Self::new(20, 120, 60)
    }

    pub fn rung(&self) -> Rung {
        self.rung
    }

    /// Feed the ladder an observation.
    ///
    /// `runtime_left` is the supply's estimate in seconds, where available. A
    /// dumb supply cannot provide it, in which case the ladder still descends
    /// on the low-battery signal alone.
    pub fn observe(&mut self, state: PowerState, now: u64, runtime_left: Option<u64>) -> Rung {
        match state {
            PowerState::OnLine => {
                // Power returned. Anything short of a halt is undone.
                self.on_battery_since = None;
                if self.rung.is_reversible() {
                    self.rung = Rung::Nominal;
                }
            }
            PowerState::LowBattery => {
                self.on_battery_since.get_or_insert(now);
                self.rung = Rung::Halt;
            }
            PowerState::OnBattery => {
                let since = *self.on_battery_since.get_or_insert(now);
                if now.saturating_sub(since) < self.dwell {
                    // Still absorbing. Deliberately do not descend.
                    return self.rung;
                }
                let target = match runtime_left {
                    Some(left) if left <= self.quiesce_at => Rung::Quiesce,
                    Some(left) if left <= self.capture_at => Rung::Capture,
                    _ => Rung::Shed,
                };
                // Never climb back up while still on battery.
                self.rung = self.rung.max(target);
            }
        }
        self.rung
    }

    /// Feed the ladder what a charge-reporting supply said.
    ///
    /// Unknown state holds the rung: neither descending nor climbing on a
    /// status nobody could read. On battery the rung is the worst of the
    /// dwell, the runtime estimate (when there is one), the charge lines and
    /// the time spent on battery. Only the supply can take the ladder to
    /// `Halt`, through the charge and time lines or a trusted `LB`.
    pub fn observe_ups(&mut self, obs: UpsObservation, low_flag: bool, t: &Triggers, now: u64) -> Rung {
        let Some(state) = obs.state else {
            return self.rung;
        };
        match state {
            PowerState::OnLine => self.observe(PowerState::OnLine, now, None),
            PowerState::LowBattery => self.observe(PowerState::LowBattery, now, obs.runtime_left),
            PowerState::OnBattery => {
                if low_flag && t.trust_lb {
                    return self.observe(PowerState::LowBattery, now, obs.runtime_left);
                }
                let since = *self.on_battery_since.get_or_insert(now);
                let elapsed = now.saturating_sub(since);
                if elapsed < t.dwell_secs {
                    return self.rung;
                }
                self.observe(PowerState::OnBattery, now, obs.runtime_left);
                let charge = obs.charge_pct;
                let mut target = Rung::Shed;
                if charge.is_some_and(|c| c <= t.capture_charge_pct) || elapsed >= t.capture_after_secs {
                    target = Rung::Capture;
                }
                if charge.is_some_and(|c| c <= t.quiesce_charge_pct) || elapsed >= t.quiesce_after_secs {
                    target = Rung::Quiesce;
                }
                if charge.is_some_and(|c| c <= t.halt_charge_pct) || elapsed >= t.halt_after_secs {
                    target = Rung::Halt;
                }
                self.rung = self.rung.max(target);
                self.rung
            }
        }
    }

    /// Withdraw a halt that has not been carried out.
    ///
    /// `observe` latches `Halt` so that flapping power cannot resurrect or
    /// repeat it. The shutdown plan, which alone knows whether anything has
    /// actually stopped, calls this when mains returned before this node's
    /// turn. Refused if power is not on line as far as the ladder knows.
    pub fn stand_down(&mut self) -> Rung {
        if self.rung == Rung::Halt && self.on_battery_since.is_none() {
            self.rung = Rung::Nominal;
        }
        self.rung
    }

    /// Descend because of something other than the supply.
    ///
    /// Heat is the second cause, and it descends the same ladder: both are a
    /// reversible sequence of steps taken before something irreversible
    /// happens, and two mechanisms could disagree about which rung the machine
    /// is on.
    ///
    /// Only ever descends. A cooling machine does not climb back up here,
    /// because the rung it is on may have been set by a supply this call knows
    /// nothing about — `observe` owns recovery, and it owns it for both causes.
    ///
    /// `Halt` is refused outright. Nothing but a supply that is about to
    /// disappear justifies stopping the machine from software: for heat, the
    /// management controller cuts power at its own threshold, faster and
    /// without needing an operating system, and a software halt would only add
    /// a way to stop a healthy machine on one bad sensor reading.
    pub fn descend_to(&mut self, target: Rung) -> Rung {
        if target == Rung::Halt {
            return self.rung;
        }
        self.rung = self.rung.max(target);
        self.rung
    }

    /// Actions a rung implies, for an executor to carry out in order.
    pub fn actions(rung: Rung) -> &'static [&'static str] {
        match rung {
            Rung::Nominal => &[],
            Rung::Shed => &["cap power", "stop accepting new work", "shed preemptible work"],
            Rung::Capture => &["checkpoint sessions", "flush write buffers"],
            Rung::Quiesce => &["quiesce databases", "drain workloads", "unmount cleanly"],
            Rung::Halt => &["halt leaf domains", "halt workers", "halt controller last"],
        }
    }
}

#[cfg(test)]
mod ups_tests {
    use super::*;

    fn ob(charge: Option<f64>) -> UpsObservation {
        UpsObservation { state: Some(PowerState::OnBattery), charge_pct: charge, runtime_left: None }
    }
    fn ol() -> UpsObservation {
        UpsObservation { state: Some(PowerState::OnLine), charge_pct: Some(100.0), runtime_left: None }
    }

    #[test]
    fn a_simulated_drain_descends_by_charge_and_ends_at_halt() {
        let t = Triggers::default();
        let mut l = Ladder::default_for_small_ups();
        assert_eq!(l.observe_ups(ob(Some(99.0)), false, &t, 0), Rung::Nominal, "dwell");
        assert_eq!(l.observe_ups(ob(Some(98.0)), false, &t, 30), Rung::Shed);
        assert_eq!(l.observe_ups(ob(Some(78.0)), false, &t, 60), Rung::Capture);
        assert_eq!(l.observe_ups(ob(Some(64.0)), false, &t, 90), Rung::Quiesce);
        assert_eq!(l.observe_ups(ob(Some(50.0)), false, &t, 120), Rung::Halt);
    }

    #[test]
    fn with_no_charge_the_time_on_battery_still_descends() {
        let t = Triggers::default();
        let mut l = Ladder::default_for_small_ups();
        l.observe_ups(ob(None), false, &t, 0);
        assert_eq!(l.observe_ups(ob(None), false, &t, 25), Rung::Shed);
        assert_eq!(l.observe_ups(ob(None), false, &t, 200), Rung::Capture);
        assert_eq!(l.observe_ups(ob(None), false, &t, 500), Rung::Quiesce);
        assert_eq!(l.observe_ups(ob(None), false, &t, 901), Rung::Halt);
    }

    #[test]
    fn an_untrusted_low_battery_flag_does_not_halt_but_a_trusted_one_does() {
        let mut t = Triggers::default();
        let mut l = Ladder::default_for_small_ups();
        l.observe_ups(ob(Some(90.0)), true, &t, 0);
        assert_eq!(l.observe_ups(ob(Some(90.0)), true, &t, 30), Rung::Shed);
        t.trust_lb = true;
        assert_eq!(l.observe_ups(ob(Some(90.0)), true, &t, 31), Rung::Halt);
    }

    #[test]
    fn mains_returning_undoes_a_partial_descent() {
        let t = Triggers::default();
        let mut l = Ladder::default_for_small_ups();
        l.observe_ups(ob(Some(90.0)), false, &t, 0);
        l.observe_ups(ob(Some(70.0)), false, &t, 40);
        assert_eq!(l.rung(), Rung::Capture);
        assert_eq!(l.observe_ups(ol(), false, &t, 50), Rung::Nominal);
    }

    #[test]
    fn a_pending_halt_is_withdrawn_when_mains_returns_and_not_before() {
        let t = Triggers::default();
        let mut l = Ladder::default_for_small_ups();
        l.observe_ups(ob(Some(90.0)), false, &t, 0);
        l.observe_ups(ob(Some(40.0)), false, &t, 40);
        assert_eq!(l.rung(), Rung::Halt);
        assert_eq!(l.stand_down(), Rung::Halt, "still on battery");
        assert_eq!(l.observe_ups(ol(), false, &t, 50), Rung::Halt, "latched by observe");
        assert_eq!(l.stand_down(), Rung::Nominal);
    }

    #[test]
    fn an_unknown_state_holds_the_rung() {
        let t = Triggers::default();
        let mut l = Ladder::default_for_small_ups();
        l.observe_ups(ob(Some(90.0)), false, &t, 0);
        l.observe_ups(ob(Some(90.0)), false, &t, 40);
        let unknown = UpsObservation { state: None, charge_pct: None, runtime_left: None };
        assert_eq!(l.observe_ups(unknown, false, &t, 50), Rung::Shed);
    }

    #[test]
    fn bad_thresholds_are_refused() {
        let mut t = Triggers::default();
        t.halt_charge_pct = 90.0;
        assert!(t.validate().is_err());
        assert!(Triggers::default().validate().is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ladder() -> Ladder {
        Ladder::new(20, 120, 60)
    }

    #[test]
    fn a_brief_flicker_is_absorbed() {
        let mut l = ladder();
        assert_eq!(l.observe(PowerState::OnBattery, 0, Some(600)), Rung::Nominal);
        assert_eq!(l.observe(PowerState::OnBattery, 10, Some(590)), Rung::Nominal);
        assert_eq!(l.observe(PowerState::OnLine, 12, None), Rung::Nominal);
    }

    #[test]
    fn a_sustained_outage_descends() {
        let mut l = ladder();
        l.observe(PowerState::OnBattery, 0, Some(600));
        assert_eq!(l.observe(PowerState::OnBattery, 25, Some(600)), Rung::Shed);
        assert_eq!(l.observe(PowerState::OnBattery, 60, Some(110)), Rung::Capture);
        assert_eq!(l.observe(PowerState::OnBattery, 90, Some(50)), Rung::Quiesce);
    }

    #[test]
    fn power_returning_reverses_the_descent() {
        let mut l = ladder();
        l.observe(PowerState::OnBattery, 0, Some(600));
        l.observe(PowerState::OnBattery, 60, Some(110));
        assert_eq!(l.rung(), Rung::Capture);
        assert_eq!(l.observe(PowerState::OnLine, 70, None), Rung::Nominal);
    }

    #[test]
    fn a_halt_is_not_reversed_by_power_returning() {
        let mut l = ladder();
        l.observe(PowerState::LowBattery, 0, Some(5));
        assert_eq!(l.rung(), Rung::Halt);
        // Once the halt is committed, flapping power must not resurrect it.
        assert_eq!(l.observe(PowerState::OnLine, 1, None), Rung::Halt);
    }

    #[test]
    fn low_battery_halts_even_without_a_runtime_estimate() {
        // The dumb-supply case: contact closure only.
        let mut l = ladder();
        assert_eq!(l.observe(PowerState::LowBattery, 0, None), Rung::Halt);
    }

    #[test]
    fn a_dumb_supply_still_sheds_after_dwell() {
        let mut l = ladder();
        l.observe(PowerState::OnBattery, 0, None);
        assert_eq!(l.observe(PowerState::OnBattery, 30, None), Rung::Shed);
    }

    #[test]
    fn the_ladder_never_climbs_while_on_battery() {
        let mut l = ladder();
        l.observe(PowerState::OnBattery, 0, Some(600));
        l.observe(PowerState::OnBattery, 60, Some(50));
        assert_eq!(l.rung(), Rung::Quiesce);
        // A supply reporting an optimistic estimate must not un-quiesce us.
        assert_eq!(l.observe(PowerState::OnBattery, 70, Some(600)), Rung::Quiesce);
    }

    #[test]
    fn reversibility_is_explicit() {
        assert!(Rung::Shed.is_reversible());
        assert!(Rung::Quiesce.is_reversible());
        assert!(!Rung::Halt.is_reversible());
    }

    #[test]
    fn halt_order_puts_the_controller_last() {
        let actions = Ladder::actions(Rung::Halt);
        assert_eq!(*actions.last().unwrap(), "halt controller last");
    }
}

#[cfg(test)]
mod thermal_cause_tests {
    use super::*;

    #[test]
    fn heat_can_descend_the_ladder() {
        let mut l = Ladder::default_for_small_ups();
        assert_eq!(l.rung(), Rung::Nominal);
        assert_eq!(l.descend_to(Rung::Shed), Rung::Shed);
        assert_eq!(l.descend_to(Rung::Capture), Rung::Capture);
    }

    #[test]
    fn heat_cannot_halt_the_machine() {
        // The controller does that, faster and without an operating system. A
        // software halt would only add a way to stop a healthy machine on one
        // bad sensor reading.
        let mut l = Ladder::default_for_small_ups();
        assert_eq!(l.descend_to(Rung::Halt), Rung::Nominal);
        assert_ne!(l.rung(), Rung::Halt);
    }

    #[test]
    fn a_cooling_machine_does_not_climb_back_up_here() {
        // The rung may have been set by a supply this call knows nothing
        // about; `observe` owns recovery for both causes.
        let mut l = Ladder::default_for_small_ups();
        l.descend_to(Rung::Quiesce);
        assert_eq!(l.descend_to(Rung::Nominal), Rung::Quiesce);
    }

    #[test]
    fn a_supply_event_and_heat_do_not_fight_over_the_rung() {
        // Whichever is worse wins, and there is only one ladder to be on.
        let mut l = Ladder::default_for_small_ups();
        l.descend_to(Rung::Capture);
        // Power returns: recovery is `observe`'s job and it undoes both.
        l.observe(PowerState::OnLine, 1_000, None);
        assert_eq!(l.rung(), Rung::Nominal);
    }
}
