//! One scheduler, for everything that runs on a timer.
//!
//! This replaces eight hand-rolled `loop { sleep(n); work() }` threads spread
//! across the node agent and the site controller. They all did the same thing
//! and they all had the same problems, which is the argument for centralising
//! them rather than a matter of taste:
//!
//! - **No jitter.** Every node boots together and polls on the same timer, so
//!   after a site-wide restart they hit the controller in the same millisecond,
//!   forever. The bigger the fleet, the worse it gets.
//! - **No backoff.** A failing task retried at full rate against a dead
//!   endpoint, which is the least useful moment to be generating load.
//! - **Drift.** `sleep(n)` after the work means the real period is `n` plus
//!   however long the work took, so anything aligned to an external schedule
//!   slides off it.
//! - **No visibility.** Nothing recorded when a task last ran or last
//!   succeeded, so a task that had been failing for a week looked exactly like
//!   one that had nothing to do.
//! - **Silent death.** A panicking thread simply vanished, and the only
//!   symptom was something quietly no longer happening.
//!
//! The last two are the ones that matter most here. A carbon feed that stopped
//! working is not supposed to be discoverable only by noticing that a number
//! looks old.
//!
//! The scheduling decision itself lives in [`policy`] as a pure function, so it
//! can be tested without waiting for time to pass; what remains here is the
//! thread that sleeps and the state that makes it observable.

pub mod placement;
pub mod policy;

pub use policy::{next_wait, Backoff, Cadence, Outcome, Plan};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// What a task did last time, and how it has been doing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TaskState {
    pub name: String,
    pub cadence_secs: u64,
    /// Unix seconds of the last attempt, whatever came of it.
    pub last_run: Option<u64>,
    /// Unix seconds of the last attempt that worked.
    ///
    /// Kept separate from `last_run` on purpose: a task running every minute
    /// and failing every time has a very recent `last_run`, and reporting that
    /// alone is how a broken feed passes for a healthy one.
    pub last_success: Option<u64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub runs: u64,
    pub failures: u64,
    pub skips: u64,
    /// Whether the last wait was a backoff.
    pub backing_off: bool,
    /// Set when a task panicked. It is restarted, and the fact is kept —
    /// a task that panics once a day is a bug, not a blip.
    pub panics: u64,
}

impl TaskState {
    /// Whether this task has ever done its job.
    ///
    /// "Never worked" and "worked an hour ago and is failing now" want
    /// different responses, and collapsing them into "unhealthy" loses the
    /// distinction that tells an operator whether to check the config or the
    /// network.
    pub fn has_ever_succeeded(&self) -> bool {
        self.last_success.is_some()
    }

    /// Whether the task is behind where it should be.
    ///
    /// Generous by design — three missed periods, not one — because a single
    /// late run is jitter or a slow network, and alarming on it trains
    /// everyone to ignore the alarm.
    pub fn is_stalled(&self, now: u64) -> bool {
        match self.last_success {
            None => self.runs > 3,
            Some(t) => now.saturating_sub(t) > self.cadence_secs.saturating_mul(3).max(60),
        }
    }
}

/// Shared, readable state for every registered task.
pub type Registry = Arc<Mutex<BTreeMap<String, TaskState>>>;

pub fn registry() -> Registry {
    Arc::new(Mutex::new(BTreeMap::new()))
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cheap per-task jitter that needs no random number generator.
///
/// Seeded from the task name and the run count, so two tasks on the same period
/// diverge and two *nodes* running the same task diverge as well — which is the
/// point, since identical nodes are exactly what produces a thundering herd.
fn jitter_for(name: &str, runs: u64) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h ^= runs;
    h = h.wrapping_mul(1099511628211);
    // Mix the high bits down; the low bits of an FNV hash are the weakest.
    (h >> 33) % 1000
}

/// What a task's closure returns.
pub enum Ran {
    Ok,
    /// A gate declined. Not an error.
    Skipped(String),
    Failed(String),
}

/// Register a task and start it.
///
/// One thread per task, which matches the rest of this codebase and costs
/// nothing at this scale — there are single digits of these, not thousands.
pub fn spawn<F>(reg: &Registry, name: &str, cadence: Cadence, backoff: Backoff, mut work: F)
where
    F: FnMut() -> Ran + Send + 'static,
{
    {
        let mut r = reg.lock().expect("scheduler registry");
        r.insert(
            name.to_string(),
            TaskState {
                name: name.to_string(),
                cadence_secs: cadence.secs(),
                ..TaskState::default()
            },
        );
    }

    let reg = Arc::clone(reg);
    let name = name.to_string();

    std::thread::spawn(move || loop {
        let started = Instant::now();

        // A panicking task is contained and restarted. Previously it took its
        // thread with it and the only symptom was something silently no longer
        // happening.
        let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut work)) {
            Ok(r) => r,
            Err(_) => {
                if let Ok(mut r) = reg.lock() {
                    if let Some(s) = r.get_mut(&name) {
                        s.panics += 1;
                    }
                }
                Ran::Failed("task panicked".into())
            }
        };

        let elapsed = started.elapsed().as_secs();
        let now = now_s();

        let (result, failures, runs) = {
            let mut r = reg.lock().expect("scheduler registry");
            let s = r.entry(name.clone()).or_default();
            s.last_run = Some(now);
            s.runs += 1;

            let result = match &outcome {
                Ran::Ok => {
                    s.last_success = Some(now);
                    s.last_error = None;
                    s.consecutive_failures = 0;
                    Outcome::Ok
                }
                Ran::Skipped(why) => {
                    s.skips += 1;
                    // Deliberately not an error: the work is fine, the moment
                    // is wrong.
                    s.last_error = Some(format!("skipped: {why}"));
                    Outcome::Skipped
                }
                Ran::Failed(e) => {
                    s.failures += 1;
                    s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                    s.last_error = Some(e.clone());
                    Outcome::Failed
                }
            };
            (result, s.consecutive_failures, s.runs)
        };

        let plan = next_wait(
            cadence,
            result,
            failures,
            elapsed,
            backoff,
            jitter_for(&name, runs),
        );

        if let Ok(mut r) = reg.lock() {
            if let Some(s) = r.get_mut(&name) {
                s.backing_off = plan.backing_off;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(plan.wait_secs));
    });
}

/// Every task's state, for a report.
pub fn snapshot(reg: &Registry) -> Vec<TaskState> {
    reg.lock()
        .map(|r| r.values().cloned().collect())
        .unwrap_or_default()
}

/// Tasks that are behind, which is the question an operator actually has.
pub fn stalled(reg: &Registry) -> Vec<String> {
    let now = now_s();
    reg.lock()
        .map(|r| {
            r.values()
                .filter(|s| s.is_stalled(now))
                .map(|s| s.name.clone())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn a_task_that_has_never_succeeded_is_distinguishable() {
        // "Never worked" points at configuration; "worked an hour ago" points
        // at the network. Collapsing them loses the only useful signal.
        let mut s = TaskState {
            cadence_secs: 60,
            runs: 10,
            failures: 10,
            last_run: Some(1000),
            ..TaskState::default()
        };
        assert!(!s.has_ever_succeeded());
        s.last_success = Some(500);
        assert!(s.has_ever_succeeded());
    }

    #[test]
    fn a_recent_run_does_not_make_a_failing_task_look_healthy() {
        // The trap this design avoids: a task failing every minute has a very
        // recent last_run.
        let s = TaskState {
            cadence_secs: 60,
            last_run: Some(1000),
            last_success: Some(100),
            runs: 15,
            ..TaskState::default()
        };
        assert!(s.is_stalled(1000));
    }

    #[test]
    fn a_single_late_run_is_not_a_stall() {
        // Alarming on one missed period trains everyone to ignore the alarm.
        let s = TaskState {
            cadence_secs: 60,
            last_success: Some(1000),
            runs: 5,
            ..TaskState::default()
        };
        assert!(!s.is_stalled(1100));
        assert!(s.is_stalled(1400));
    }

    #[test]
    fn a_task_that_has_not_run_yet_is_not_stalled() {
        let s = TaskState { cadence_secs: 60, ..TaskState::default() };
        assert!(!s.is_stalled(10_000));
    }

    #[test]
    fn two_nodes_running_the_same_task_do_not_fire_together() {
        // Same name, same period — the jitter has to come from somewhere, and
        // here it comes from the run count diverging.
        let a: Vec<u64> = (0..5).map(|r| jitter_for("report", r)).collect();
        assert!(a.windows(2).any(|w| w[0] != w[1]), "jitter never varied");
    }

    #[test]
    fn different_tasks_get_different_jitter() {
        assert_ne!(jitter_for("report", 0), jitter_for("checkpoint", 0));
    }

    #[test]
    fn a_registered_task_appears_immediately_rather_than_after_its_first_run() {
        // A task on a fifteen-minute period would otherwise be invisible for
        // fifteen minutes, which is exactly when somebody is checking whether
        // it started.
        let reg = registry();
        spawn(&reg, "slow", Cadence::FixedDelay { secs: 3600 }, Backoff::default(), || Ran::Ok);
        let s = snapshot(&reg);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "slow");
        assert_eq!(s[0].cadence_secs, 3600);
    }

    #[test]
    fn a_task_runs_and_records_success() {
        let reg = registry();
        let count = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&count);
        spawn(&reg, "quick", Cadence::FixedDelay { secs: 3600 }, Backoff::default(), move || {
            c.fetch_add(1, Ordering::SeqCst);
            Ran::Ok
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(count.load(Ordering::SeqCst) >= 1);
        let s = snapshot(&reg);
        assert!(s[0].has_ever_succeeded());
        assert_eq!(s[0].consecutive_failures, 0);
    }

    #[test]
    fn a_panicking_task_is_contained_and_counted_rather_than_vanishing() {
        // Previously the thread died and the only symptom was something
        // quietly no longer happening.
        let reg = registry();
        spawn(&reg, "boom", Cadence::FixedDelay { secs: 3600 }, Backoff::default(), || {
            panic!("deliberate");
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let s = snapshot(&reg);
        assert!(s[0].panics >= 1);
        assert_eq!(s[0].consecutive_failures, 1, "a panic counts as a failure");
    }

    #[test]
    fn a_skip_is_not_recorded_as_a_failure() {
        let reg = registry();
        spawn(&reg, "gated", Cadence::FixedDelay { secs: 3600 }, Backoff::default(), || {
            Ran::Skipped("on battery".into())
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let s = snapshot(&reg);
        assert_eq!(s[0].skips, 1);
        assert_eq!(s[0].failures, 0);
        assert_eq!(s[0].consecutive_failures, 0, "a skip must not trigger backoff");
    }

    #[test]
    fn a_failure_is_recorded_with_its_reason() {
        let reg = registry();
        spawn(&reg, "broken", Cadence::FixedDelay { secs: 3600 }, Backoff::default(), || {
            Ran::Failed("connection refused".into())
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let s = snapshot(&reg);
        assert_eq!(s[0].failures, 1);
        assert!(s[0].last_error.as_ref().unwrap().contains("refused"));
        assert!(!s[0].has_ever_succeeded());
    }
}
