//! The ordered, self-administered shutdown at the bottom of the ladder.
//!
//! Nothing here can stop another machine. Every node runs its own copy of the
//! ladder against the same supply, and when the ladder reaches `Halt` each
//! node waits its own configured delay and then stops itself. Giving Pi-class
//! boards and the accelerator hosts small delays and the host that holds the
//! UPS connection the largest makes the dependents go first and the supply's
//! host last, with no node holding authority over another. The operator's kill
//! switch is a different thing and is untouched.
//!
//! The delay is the whole window in which mains can come back: a pending halt
//! is withdrawn the moment the supply reports mains on line, on every node
//! that has not yet stopped. Real shutdown is off until the node's operator
//! turns it on; until then the plan logs exactly what it would have done.

use crate::ladder::{Ladder, Rung};

/// Where the node's authority to act on a halt lives. Root-owned. The
/// privileged actuator reads the same file and enforces it independently.
pub const CONFIG_PATH: &str = "/etc/furcate/ups-shutdown";

/// The kill switch for actuation. While this file exists on a node nothing is
/// stopped and nothing is powered off there, whatever the mode says: the daemon
/// and the privileged actuator both look for it, every time, independently.
/// One command disables a node: `sudo touch /etc/furcate/ups-actuation-disabled`.
pub const KILL_SWITCH_PATH: &str = "/etc/furcate/ups-actuation-disabled";

/// The configuration the plan actually runs with: live only when the operator
/// wrote `mode=enforce` and the kill switch is absent. No other path is live.
pub fn effective(cfg: Config, kill_switch_present: bool) -> Config {
    if kill_switch_present {
        Config { mode: Mode::DryRun, ..cfg }
    } else {
        cfg
    }
}

/// The node that holds the UPS connection must wait at least this long.
pub const MIN_UPS_HOST_DELAY_SECS: u64 = 120;
/// And outlast every other node by at least this much.
pub const MIN_MARGIN_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Log what would happen; stop nothing. The default.
    DryRun,
    Enforce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    /// Seconds after the ladder reaches `Halt` before this node stops itself.
    pub delay_secs: u64,
    /// This node holds the UPS connection and so stops last.
    pub ups_host: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { mode: Mode::DryRun, delay_secs: 0, ups_host: false }
    }
}

impl Config {
    /// `key=value` lines; `#` comments. Unknown keys and bad values are errors,
    /// not defaults.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut c = Config::default();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or_else(|| format!("not key=value: {line}"))?;
            let (k, v) = (k.trim(), v.trim());
            match k {
                "mode" => {
                    c.mode = match v {
                        "dry-run" => Mode::DryRun,
                        "enforce" => Mode::Enforce,
                        _ => return Err(format!("mode is dry-run or enforce, not {v:?}")),
                    }
                }
                "delay_secs" => c.delay_secs = v.parse().map_err(|_| format!("delay_secs is a whole number, not {v:?}"))?,
                "ups_host" => {
                    c.ups_host = match v {
                        "yes" => true,
                        "no" => false,
                        _ => return Err(format!("ups_host is yes or no, not {v:?}")),
                    }
                }
                _ => return Err(format!("unknown key {k:?}")),
            }
        }
        if c.ups_host && c.delay_secs < MIN_UPS_HOST_DELAY_SECS {
            return Err(format!(
                "the node holding the UPS connection must wait at least {MIN_UPS_HOST_DELAY_SECS}s so its dependents stop first"
            ));
        }
        Ok(c)
    }
}

/// What reading the file found. No file is a node that never shuts itself
/// down, which is the default and not a fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loaded {
    Absent,
    Invalid(String),
    Some(Config),
}

pub fn load(path: &std::path::Path) -> Loaded {
    match std::fs::read_to_string(path) {
        Ok(t) => match Config::parse(&t) {
            Ok(c) => Loaded::Some(c),
            Err(e) => Loaded::Invalid(format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Absent,
        Err(e) => Loaded::Invalid(format!("{} cannot be read: {e}", path.display())),
    }
}

/// What the plan wants done this pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    /// The ladder reached `Halt`; this node will stop at `fire_at`.
    Armed { fire_at: u64 },
    /// Mains returned first; the pending halt is withdrawn.
    Cancelled,
    /// This node's turn. `enforce` false means log it and stop nothing.
    Fire { enforce: bool },
}

pub struct Plan {
    cfg: Config,
    armed_at: Option<u64>,
    fired: bool,
}

impl Plan {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, armed_at: None, fired: false }
    }

    pub fn config(&self) -> Config {
        self.cfg
    }

    /// Adopt a changed configuration without forgetting where the plan is.
    pub fn reconfigure(&mut self, cfg: Config) {
        self.cfg = cfg;
    }

    /// The turn came and the request to stop could not be made; try again on
    /// the next pass rather than treating the node as stopped.
    pub fn failed(&mut self) {
        self.fired = false;
    }

    pub fn pending(&self) -> Option<u64> {
        self.armed_at.filter(|_| !self.fired).map(|a| a + self.cfg.delay_secs)
    }

    /// One pass. `mains_on_line` is true only when the supply measured mains
    /// on line: an unreadable supply never withdraws a halt.
    pub fn observe(&mut self, ladder: &mut Ladder, mains_on_line: bool, now: u64) -> Action {
        if self.fired {
            // The sequence checks for cancellation before every step, so mains
            // returning ends it in either mode and the next outage is judged
            // anew. Past the power-off nothing is left to cancel.
            if mains_on_line {
                ladder.stand_down();
                self.fired = false;
                self.armed_at = None;
                return Action::Cancelled;
            }
            return Action::None;
        }
        if self.armed_at.is_some() && mains_on_line {
            ladder.stand_down();
            self.armed_at = None;
            return Action::Cancelled;
        }
        if ladder.rung() != Rung::Halt {
            return Action::None;
        }
        let armed = *self.armed_at.get_or_insert(now);
        let fire_at = armed + self.cfg.delay_secs;
        if now >= fire_at {
            self.fired = true;
            return Action::Fire { enforce: self.cfg.mode == Mode::Enforce };
        }
        if armed == now {
            Action::Armed { fire_at }
        } else {
            Action::None
        }
    }
}

/// Check a fleet's delays before trusting them: the node holding the UPS
/// connection is exactly one, and stops last with a margin.
pub fn check_order(nodes: &[(&str, Config)]) -> Result<(), String> {
    let hosts: Vec<_> = nodes.iter().filter(|(_, c)| c.ups_host).collect();
    if hosts.len() != 1 {
        return Err(format!("{} nodes claim the UPS connection; exactly one does", hosts.len()));
    }
    let (name, host) = hosts[0];
    for (n, c) in nodes {
        if n != name && c.delay_secs + MIN_MARGIN_SECS > host.delay_secs {
            return Err(format!("{n} (delay {}s) does not stop {MIN_MARGIN_SECS}s before {name}", c.delay_secs));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ladder::{PowerState, Triggers, UpsObservation};

    fn cfg(mode: Mode, delay: u64, host: bool) -> Config {
        Config { mode, delay_secs: delay, ups_host: host }
    }
    fn ob(c: f64) -> UpsObservation {
        UpsObservation { state: Some(PowerState::OnBattery), charge_pct: Some(c), runtime_left: None }
    }
    fn ol() -> UpsObservation {
        UpsObservation { state: Some(PowerState::OnLine), charge_pct: Some(100.0), runtime_left: None }
    }

    /// One simulated node: its own ladder and plan.
    struct Node {
        name: &'static str,
        ladder: Ladder,
        plan: Plan,
        fired_at: Option<u64>,
        cancelled: bool,
    }
    impl Node {
        fn new(name: &'static str, c: Config) -> Self {
            Self { name, ladder: Ladder::default_for_small_ups(), plan: Plan::new(c), fired_at: None, cancelled: false }
        }
        fn step(&mut self, obs: UpsObservation, now: u64) {
            let t = Triggers::default();
            self.ladder.observe_ups(obs, false, &t, now);
            let on_line = obs.state == Some(PowerState::OnLine);
            match self.plan.observe(&mut self.ladder, on_line, now) {
                Action::Fire { .. } => self.fired_at = Some(now),
                Action::Cancelled => self.cancelled = true,
                _ => {}
            }
        }
    }

    fn fleet(mode: Mode) -> Vec<Node> {
        vec![
            Node::new("pi", cfg(mode, 0, false)),
            Node::new("accelerator-host", cfg(mode, 60, false)),
            Node::new("ups-host", cfg(mode, 180, true)),
        ]
    }

    #[test]
    fn the_fleet_stops_dependents_first_and_the_ups_host_last_in_dry_run() {
        let mut nodes = fleet(Mode::DryRun);
        check_order(&nodes.iter().map(|n| (n.name, n.plan.config())).collect::<Vec<_>>()).unwrap();
        for now in 0..=400u64 {
            // Drain: 100% falling to 40% by t=100.
            let c = (100.0 - now as f64 * 0.6).max(40.0);
            for n in nodes.iter_mut() {
                n.step(ob(c), now);
            }
        }
        let t: Vec<u64> = nodes.iter().map(|n| n.fired_at.expect("every node reached its turn")).collect();
        assert!(t[0] < t[1] && t[1] < t[2], "order was {t:?}");
        assert_eq!(t[1] - t[0], 60);
        assert_eq!(t[2] - t[1], 120);
    }

    #[test]
    fn mains_returning_saves_every_node_that_has_not_yet_stopped() {
        let mut nodes = fleet(Mode::Enforce);
        let mut returned = false;
        for now in 0..=400u64 {
            let c = (100.0 - now as f64 * 0.6).max(40.0);
            // Mains is back at t=100: the pi (t=~84) and the accelerator host
            // (~144) are in different positions relative to it.
            let obs = if now >= 120 { ol() } else { ob(c) };
            returned |= now >= 120;
            for n in nodes.iter_mut() {
                n.step(obs, now);
            }
        }
        assert!(returned);
        assert!(nodes[0].fired_at.is_some(), "already stopped before mains came back");
        assert!(nodes[1].fired_at.is_none() && nodes[1].cancelled, "pending, withdrawn");
        assert!(nodes[2].fired_at.is_none() && nodes[2].cancelled);
        assert_eq!(nodes[2].ladder.rung(), Rung::Nominal);
    }

    #[test]
    fn a_dry_run_resets_when_mains_returns_so_the_next_outage_is_judged_anew() {
        let mut n = Node::new("pi", cfg(Mode::DryRun, 0, false));
        for now in 0..100u64 {
            n.step(ob((100.0 - now as f64).max(40.0)), now);
        }
        assert!(n.fired_at.is_some());
        n.step(ol(), 101);
        assert!(n.cancelled);
        assert_eq!(n.ladder.rung(), Rung::Nominal);
        n.fired_at = None;
        for now in 200..300u64 {
            n.step(ob((100.0 - (now - 200) as f64).max(40.0)), now);
        }
        assert!(n.fired_at.is_some(), "a second outage fires again");
    }

    #[test]
    fn an_unreadable_supply_never_withdraws_a_halt() {
        let mut l = Ladder::default_for_small_ups();
        let t = Triggers::default();
        let mut p = Plan::new(cfg(Mode::DryRun, 50, false));
        l.observe_ups(ob(90.0), false, &t, 0);
        l.observe_ups(ob(30.0), false, &t, 30);
        assert!(matches!(p.observe(&mut l, false, 30), Action::Armed { fire_at: 80 }));
        assert_eq!(p.observe(&mut l, false, 60), Action::None);
        assert_eq!(p.pending(), Some(80));
    }

    #[test]
    fn the_kill_switch_makes_an_enforcing_node_dry_run() {
        let c = cfg(Mode::Enforce, 10, false);
        assert_eq!(effective(c, true).mode, Mode::DryRun);
        assert_eq!(effective(c, false).mode, Mode::Enforce);
        assert_eq!(effective(Config::default(), false).mode, Mode::DryRun, "nothing is live without an explicit setting");
    }

    #[test]
    fn config_is_strict_and_defaults_to_dry_run() {
        assert_eq!(Config::default().mode, Mode::DryRun);
        let c = Config::parse("# x\nmode=enforce\ndelay_secs=60\n").unwrap();
        assert_eq!((c.mode, c.delay_secs), (Mode::Enforce, 60));
        assert!(Config::parse("mode=yes").is_err());
        assert!(Config::parse("shutdown=now").is_err());
        assert!(Config::parse("ups_host=yes\ndelay_secs=10").is_err());
        assert!(Config::parse("ups_host=yes\ndelay_secs=300").is_ok());
        assert_eq!(load(std::path::Path::new("/nonexistent/furcate-ups-shutdown")), Loaded::Absent);
    }

    #[test]
    fn a_fleet_where_the_ups_host_does_not_stop_last_is_refused() {
        let bad = [("a", cfg(Mode::DryRun, 160, false)), ("h", cfg(Mode::DryRun, 180, true))];
        assert!(check_order(&bad).is_err());
        let two = [("a", cfg(Mode::DryRun, 0, true)), ("h", cfg(Mode::DryRun, 180, true))];
        assert!(check_order(&two).is_err());
    }
}
