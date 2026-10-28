//! The graceful stop that precedes a UPS power-off.
//!
//! Nothing is lost because nothing is killed: every stateful service is asked
//! to stop in the reverse of its bring-up order, each with its own timeout and,
//! for long jobs, a grace window to checkpoint, and only then are the journal
//! flushed, the disks synced and the power cut. The sequence has no way to
//! send a signal itself: the [`Actuator`] it drives can only ask for a stop,
//! a start or the final power-off, and the privileged side behind it stops
//! units through systemd with timeouts and never by killing a process.
//!
//! The list of units is the operator's, root-owned, and both halves read it;
//! the daemon never names a unit the list does not.

use crate::bringup::{BringUp, Gate, Unit};
use crate::shutdown::Mode;

/// Where the operator declares what to stop and how long to wait.
pub const STOP_LIST_PATH: &str = "/etc/furcate/ups-stop";

/// Seconds allowed for the journal flush and the final sync.
pub const FINISH_SECS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopUnit {
    pub name: String,
    /// Units this one needs running. They are stopped after it.
    pub needs: Vec<String>,
    /// Seconds to wait for a stop before logging a timeout and moving on.
    pub timeout_secs: u64,
    /// Extra window for a job that checkpoints on SIGTERM. The unit is never
    /// escalated before `max(timeout, grace)`.
    pub grace_secs: u64,
    pub stateful: bool,
    /// An operator-set safe-stop command (absolute path, no arguments) run
    /// before the unit is stopped, for services that have their own.
    pub safe_stop: Option<String>,
}

impl StopUnit {
    pub fn window(&self) -> u64 {
        self.timeout_secs.max(self.grace_secs)
    }
}

fn unit_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && !n.starts_with('-')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

/// `key=value` fields on one line per unit; `#` comments:
///
/// `unit=postgres.service needs=furcate-kms.service timeout=120 stateful=yes`
pub fn parse(text: &str) -> Result<Vec<StopUnit>, String> {
    let mut out: Vec<StopUnit> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let at = |m: &str| format!("line {}: {m}", i + 1);
        let mut u = StopUnit { name: String::new(), needs: vec![], timeout_secs: 60, grace_secs: 0, stateful: false, safe_stop: None };
        for f in line.split_whitespace() {
            let (k, v) = f.split_once('=').ok_or_else(|| at(&format!("not key=value: {f}")))?;
            match k {
                "unit" => u.name = v.to_string(),
                "needs" => u.needs = v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
                "timeout" => u.timeout_secs = v.parse().map_err(|_| at("timeout is whole seconds"))?,
                "grace" => u.grace_secs = v.parse().map_err(|_| at("grace is whole seconds"))?,
                "stateful" => {
                    u.stateful = match v {
                        "yes" => true,
                        "no" => false,
                        _ => return Err(at("stateful is yes or no")),
                    }
                }
                "stop" => {
                    if !v.starts_with('/') || v.contains("..") || !v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-')) {
                        return Err(at("stop is an absolute path with no arguments"));
                    }
                    u.safe_stop = Some(v.to_string());
                }
                _ => return Err(at(&format!("unknown key {k}"))),
            }
        }
        if !unit_name_ok(&u.name) || u.needs.iter().any(|n| !unit_name_ok(n)) {
            return Err(at("a unit name is empty or has characters a unit cannot"));
        }
        if u.timeout_secs == 0 {
            return Err(at("timeout must be at least 1"));
        }
        if out.iter().any(|o| o.name == u.name) {
            return Err(at("unit listed twice"));
        }
        out.push(u);
    }
    for u in &out {
        for n in &u.needs {
            if !out.iter().any(|o| &o.name == n) {
                return Err(format!("{} needs {n}, which is not in the list", u.name));
            }
        }
    }
    // A cycle never settles; refuse it rather than stop in an arbitrary order.
    if order(&out).len() != out.len() {
        return Err("the units depend on each other in a cycle".into());
    }
    Ok(out)
}

/// What reading the list found. No list is a node that declares nothing
/// stateful, which the dry run states plainly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loaded {
    Absent,
    Invalid(String),
    Some(Vec<StopUnit>),
}

pub fn load(path: &std::path::Path) -> Loaded {
    match std::fs::read_to_string(path) {
        Ok(t) => match parse(&t) {
            Ok(u) => Loaded::Some(u),
            Err(e) => Loaded::Invalid(format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Absent,
        Err(e) => Loaded::Invalid(format!("{} cannot be read: {e}", path.display())),
    }
}

/// Stop order: the reverse of the order the bring-up graph starts them in, so
/// whatever needs a database stops before the database does.
pub fn order(units: &[StopUnit]) -> Vec<StopUnit> {
    let graph: Vec<Unit> = units
        .iter()
        .map(|u| Unit {
            name: u.name.clone(),
            gates: u.needs.iter().map(|n| Gate::UnitHealthy(n.clone())).collect(),
            timeout: u.window(),
        })
        .collect();
    let by = BringUp::new(graph, 0).halt_order();
    by.iter().filter_map(|n| units.iter().find(|u| &u.name == n).cloned()).collect()
}

/// The worst case of the whole sequence, for the dry run to print.
pub fn expected_secs(units: &[StopUnit]) -> u64 {
    units.iter().map(StopUnit::window).sum::<u64>() + FINISH_SECS
}

/// The plan as lines, in order, with timings.
pub fn describe(units: &[StopUnit]) -> Vec<String> {
    let mut at = 0;
    let mut out = Vec::new();
    for u in order(units) {
        out.push(format!(
            "stop {} (timeout {}s{}{}{}) at t+{at}s",
            u.name,
            u.timeout_secs,
            if u.grace_secs > 0 { format!(", grace {}s to checkpoint", u.grace_secs) } else { String::new() },
            if u.stateful { ", stateful" } else { "" },
            u.safe_stop.as_ref().map_or(String::new(), |p| format!(", safe-stop {p}")),
        ));
        at += u.window();
    }
    out.push(format!("flush the journal, sync the disks at t+{at}s"));
    out.push(format!("power off at t+{}s (worst case {}s in all)", at + FINISH_SECS, at + FINISH_SECS));
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepResult {
    Stopped { secs: u64 },
    /// The window ran out; systemd is still stopping it and nothing was killed
    /// by this sequence.
    TimedOut { secs: u64 },
    /// The privileged half stopped it, but with a kill after `after_secs`.
    Killed { after_secs: u64 },
    Failed(String),
}

/// What the sequence can ask for. There is no kill here, deliberately.
pub trait Actuator {
    fn stop(&mut self, unit: &StopUnit) -> StepResult;
    fn start(&mut self, unit: &StopUnit) -> StepResult;
    /// Flush the journal, sync the disks and power off. Last, once.
    fn finish(&mut self) -> Result<(), String>;
}

/// Where intents and results go: the ledger that survives the reboot.
pub trait Ledger {
    fn record(&mut self, line: String);
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Dry run: everything was logged, nothing was done.
    Rehearsed,
    PoweredOff,
    /// Mains returned: `stopped` units were started again in bring-up order.
    Cancelled { stopped: Vec<String> },
    /// The final step failed.
    FinishFailed(String),
}

/// Run the whole sequence. In dry run `real` is never touched.
pub fn run(
    units: &[StopUnit],
    mode: Mode,
    host: &str,
    real: &mut dyn Actuator,
    ledger: &mut dyn Ledger,
    cancelled: &dyn Fn() -> bool,
) -> Outcome {
    let ordered = order(units);
    if mode == Mode::DryRun {
        ledger.record(format!("DRY RUN on {host}: nothing is stopped and nothing is powered off"));
        if ordered.is_empty() {
            ledger.record("WOULD STOP nothing: no stateful unit is declared on this node".into());
        }
        for l in describe(units) {
            ledger.record(format!("WOULD {}", l.replacen("stop ", "STOP ", 1).replacen("power off", "POWEROFF", 1)));
        }
        return Outcome::Rehearsed;
    }
    ledger.record(format!(
        "INTENT on {host}: stop {} unit(s) in order [{}], then flush, sync and power off; worst case {}s",
        ordered.len(),
        ordered.iter().map(|u| u.name.as_str()).collect::<Vec<_>>().join(", "),
        expected_secs(units)
    ));
    let mut stopped: Vec<StopUnit> = Vec::new();
    for u in &ordered {
        if cancelled() {
            return cancel(&stopped, host, real, ledger);
        }
        ledger.record(format!("INTENT on {host}: stop {} (timeout {}s, grace {}s)", u.name, u.timeout_secs, u.grace_secs));
        let r = real.stop(u);
        match &r {
            StepResult::Stopped { secs } => ledger.record(format!("stopped {} in {secs}s", u.name)),
            StepResult::TimedOut { secs } => ledger.record(format!("TIMEOUT {} still stopping after {secs}s; not killed by the ladder", u.name)),
            StepResult::Killed { after_secs } if *after_secs < u.window() => {
                ledger.record(format!("VIOLATION {} was killed after {after_secs}s, before its {}s window", u.name, u.window()))
            }
            StepResult::Killed { after_secs } => ledger.record(format!("{} needed a kill after its full window ({after_secs}s)", u.name)),
            StepResult::Failed(why) => ledger.record(format!("FAILED to stop {}: {why}", u.name)),
        }
        stopped.push(u.clone());
    }
    if cancelled() {
        return cancel(&stopped, host, real, ledger);
    }
    ledger.record(format!("INTENT on {host}: flush the journal, sync the disks, power off"));
    match real.finish() {
        Ok(()) => Outcome::PoweredOff,
        Err(e) => {
            ledger.record(format!("FAILED the final step: {e}"));
            Outcome::FinishFailed(e)
        }
    }
}

fn cancel(stopped: &[StopUnit], host: &str, real: &mut dyn Actuator, ledger: &mut dyn Ledger) -> Outcome {
    ledger.record(format!("CANCELLED on {host}: mains returned; nothing further is stopped, {} unit(s) already stopped are started again", stopped.len()));
    for u in stopped.iter().rev() {
        match real.start(u) {
            StepResult::Failed(why) => ledger.record(format!("FAILED to start {} again: {why}", u.name)),
            _ => ledger.record(format!("started {} again", u.name)),
        }
    }
    Outcome::Cancelled { stopped: stopped.iter().map(|u| u.name.clone()).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const LIST: &str = "
# jobs need the database; the database needs the kms
unit=batch-job.service needs=postgres.service timeout=30 grace=300
unit=postgres.service needs=furcate-kms.service timeout=120 stateful=yes
unit=furcate-kms.service timeout=60 stateful=yes
unit=chain-node.service needs=furcate-kms.service timeout=90 stateful=yes stop=/usr/local/libexec/node-safe-stop
";

    #[derive(Default)]
    struct Mock {
        calls: Vec<String>,
        kill_early: bool,
    }
    impl Actuator for Mock {
        fn stop(&mut self, u: &StopUnit) -> StepResult {
            self.calls.push(format!("stop {}", u.name));
            if self.kill_early {
                StepResult::Killed { after_secs: 1 }
            } else {
                StepResult::Stopped { secs: 2 }
            }
        }
        fn start(&mut self, u: &StopUnit) -> StepResult {
            self.calls.push(format!("start {}", u.name));
            StepResult::Stopped { secs: 1 }
        }
        fn finish(&mut self) -> Result<(), String> {
            self.calls.push("finish".into());
            Ok(())
        }
    }
    #[derive(Default)]
    struct Led(Vec<String>);
    impl Ledger for Led {
        fn record(&mut self, l: String) {
            self.0.push(l);
        }
    }
    struct Panics;
    impl Actuator for Panics {
        fn stop(&mut self, _: &StopUnit) -> StepResult { panic!("a dry run called the real actuator") }
        fn start(&mut self, _: &StopUnit) -> StepResult { panic!("a dry run called the real actuator") }
        fn finish(&mut self) -> Result<(), String> { panic!("a dry run called the real actuator") }
    }

    fn names(v: &[StopUnit]) -> Vec<&str> {
        v.iter().map(|u| u.name.as_str()).collect()
    }

    #[test]
    fn the_stop_order_is_the_reverse_of_bring_up() {
        let u = parse(LIST).unwrap();
        let o = order(&u);
        let pos = |n: &str| o.iter().position(|x| x.name == n).unwrap();
        assert!(pos("batch-job.service") < pos("postgres.service"), "the job checkpoints before its database stops");
        assert!(pos("postgres.service") < pos("furcate-kms.service"), "the KMS seals last");
        assert!(pos("chain-node.service") < pos("furcate-kms.service"));
        assert_eq!(names(&o).len(), 4);
    }

    #[test]
    fn a_dry_run_never_touches_the_real_actuator_and_says_what_it_would_do() {
        let u = parse(LIST).unwrap();
        let mut led = Led::default();
        let out = run(&u, Mode::DryRun, "node-a", &mut Panics, &mut led, &|| false);
        assert_eq!(out, Outcome::Rehearsed);
        let all = led.0.join("\n");
        assert!(all.contains("WOULD STOP batch-job.service (timeout 30s, grace 300s to checkpoint"), "{all}");
        assert!(all.contains("WOULD POWEROFF"), "{all}");
        assert!(all.contains("safe-stop /usr/local/libexec/node-safe-stop"));
        assert!(!all.contains("INTENT"), "a dry run states WOULD, not intent");
    }

    #[test]
    fn every_stateful_service_stops_before_the_power_off_and_nothing_follows_it() {
        let u = parse(LIST).unwrap();
        let mut m = Mock::default();
        let mut led = Led::default();
        let out = run(&u, Mode::Enforce, "node-a", &mut m, &mut led, &|| false);
        assert_eq!(out, Outcome::PoweredOff);
        assert_eq!(m.calls.last().unwrap(), "finish", "the power-off is the last call");
        assert_eq!(m.calls.iter().filter(|c| *c == "finish").count(), 1);
        for s in u.iter().filter(|s| s.stateful) {
            let stop = m.calls.iter().position(|c| *c == format!("stop {}", s.name)).expect("stateful unit stopped");
            assert!(stop < m.calls.len() - 1, "{} must stop before the power-off", s.name);
        }
        assert!(m.calls.iter().all(|c| c.starts_with("stop ") || c == "finish"), "{:?}", m.calls);
        // Each stop was announced before it happened.
        let intents = led.0.iter().filter(|l| l.starts_with("INTENT on node-a: stop ") && l.contains("(timeout")).count();
        assert_eq!(intents, 4);
    }

    #[test]
    fn a_kill_before_the_graceful_window_is_flagged_as_a_violation() {
        let u = parse(LIST).unwrap();
        let mut m = Mock { kill_early: true, ..Default::default() };
        let mut led = Led::default();
        run(&u, Mode::Enforce, "node-a", &mut m, &mut led, &|| false);
        assert!(led.0.iter().any(|l| l.starts_with("VIOLATION batch-job.service was killed after 1s, before its 300s window")), "{:?}", led.0);
    }

    #[test]
    fn a_timeout_is_logged_and_the_sequence_moves_on_without_killing() {
        struct Slow(Vec<String>);
        impl Actuator for Slow {
            fn stop(&mut self, u: &StopUnit) -> StepResult { self.0.push(u.name.clone()); StepResult::TimedOut { secs: u.window() } }
            fn start(&mut self, _: &StopUnit) -> StepResult { StepResult::Stopped { secs: 0 } }
            fn finish(&mut self) -> Result<(), String> { self.0.push("finish".into()); Ok(()) }
        }
        let u = parse(LIST).unwrap();
        let mut s = Slow(vec![]);
        let mut led = Led::default();
        assert_eq!(run(&u, Mode::Enforce, "n", &mut s, &mut led, &|| false), Outcome::PoweredOff);
        assert_eq!(led.0.iter().filter(|l| l.starts_with("TIMEOUT ")).count(), 4);
    }

    #[test]
    fn mains_returning_mid_sequence_stops_nothing_further_and_starts_back_up() {
        let u = parse(LIST).unwrap();
        let mut m = Mock::default();
        let mut led = Led::default();
        let seen = Cell::new(0);
        // Cancelled after the first unit has been stopped.
        let out = run(&u, Mode::Enforce, "n", &mut m, &mut led, &|| {
            seen.set(seen.get() + 1);
            seen.get() > 1
        });
        assert!(matches!(out, Outcome::Cancelled { ref stopped } if stopped.len() == 1), "{out:?}");
        assert!(!m.calls.contains(&"finish".to_string()), "no power-off after a cancel");
        assert_eq!(m.calls.iter().filter(|c| c.starts_with("stop ")).count(), 1, "nothing further was stopped");
        assert!(m.calls.last().unwrap().starts_with("start "));
    }

    #[test]
    fn the_list_is_strict() {
        assert!(parse("unit=a.service needs=b.service").is_err(), "unknown dependency");
        assert!(parse("unit=a.service needs=b.service\nunit=b.service needs=a.service").is_err(), "cycle");
        assert!(parse("unit=a.service stop=relative/path").is_err());
        assert!(parse("unit=a.service stop=/bin/x;reboot").is_err());
        assert!(parse("unit=--now").is_err());
        assert!(parse("unit=a.service timeout=0").is_err());
        assert!(parse("unit=a.service\nunit=a.service").is_err());
        assert!(parse("unit=a.service kill=yes").is_err(), "there is no kill option");
        assert_eq!(load(std::path::Path::new("/nonexistent/furcate-ups-stop")), Loaded::Absent);
    }

    #[test]
    fn the_dry_run_prints_timings() {
        let u = parse(LIST).unwrap();
        let d = describe(&u);
        assert!(d[0].starts_with("stop ") && d[0].ends_with("at t+0s"));
        assert!(d.last().unwrap().contains("worst case"));
        assert_eq!(expected_secs(&u), 300 + 120 + 60 + 90 + FINISH_SECS);
    }
}
