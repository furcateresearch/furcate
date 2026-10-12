//! When a task should next run.
//!
//! Deliberately separated from anything that sleeps, so the interesting part is
//! a pure function of the last outcome and can be tested exhaustively without
//! waiting for wall-clock time to pass. The thread that actually sleeps is
//! twenty lines and has no decisions in it.
//!
//! Eight hand-rolled `loop { sleep(n); work() }` threads preceded this, and
//! between them they had every problem this module exists to fix.

use serde::{Deserialize, Serialize};

/// How a task's period is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cadence {
    /// Every `secs`, measured start to start.
    ///
    /// Work time is subtracted from the wait, so a task that takes ten seconds
    /// on a sixty-second period still runs at :00 rather than sliding a little
    /// later every hour. Anything aligned to something external — a settlement
    /// period, a tariff window — wants this.
    FixedRate { secs: u64 },
    /// `secs` after the previous run *finishes*.
    ///
    /// The right choice when the work's duration is unpredictable and
    /// overlapping runs would be worse than drifting.
    FixedDelay { secs: u64 },
}

impl Cadence {
    pub fn secs(&self) -> u64 {
        match self {
            Cadence::FixedRate { secs } | Cadence::FixedDelay { secs } => *secs,
        }
    }
}

/// What happened on the last attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Failed,
    /// A gate said not now. Not a failure: no backoff, no error recorded.
    ///
    /// Polling an external feed while the site runs on battery is the case
    /// this exists for — the work is fine, the moment is wrong, and treating
    /// that as an error would back the task off just as the situation cleared.
    Skipped,
}

/// Retry behaviour after failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backoff {
    /// Multiplier applied per consecutive failure.
    pub factor: u32,
    /// Ceiling, so a dead endpoint is not hammered and a recovered one is not
    /// stuck waiting an hour to notice.
    pub max_secs: u64,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            factor: 2,
            max_secs: 900,
        }
    }
}

/// Randomised spread applied to every wait.
///
/// On by default and not opt-in, which is the one decision here worth
/// defending. A fleet whose nodes all boot together and all poll on a
/// sixty-second timer will hit the controller in the same millisecond forever
/// after — and the bigger the fleet, the worse it gets. Ten percent is enough
/// to smear that out and small enough that nothing downstream notices.
pub const JITTER_PERCENT: u64 = 10;

/// The scheduling decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Seconds to wait before the next attempt.
    pub wait_secs: u64,
    /// Whether this wait is a backoff rather than the ordinary period.
    pub backing_off: bool,
}

/// Decide how long to wait before running again.
///
/// `elapsed_secs` is how long the run just finished took. `jitter` is a value
/// in `0..100` supplied by the caller rather than drawn here, so the whole
/// function stays deterministic and testable.
pub fn next_wait(
    cadence: Cadence,
    outcome: Outcome,
    consecutive_failures: u32,
    elapsed_secs: u64,
    backoff: Backoff,
    jitter: u64,
) -> Plan {
    let base = cadence.secs().max(1);

    let (wait, backing_off) = match outcome {
        Outcome::Failed if consecutive_failures > 0 => {
            let mult = backoff
                .factor
                .saturating_pow(consecutive_failures.min(16)) as u64;
            (base.saturating_mul(mult).min(backoff.max_secs).max(base), true)
        }
        // A skip waits the ordinary period. The gate will be consulted again,
        // and backing off would mean the task is slowest to resume at exactly
        // the moment the condition clears.
        _ => match cadence {
            // Subtract the work already done, so the period is start-to-start.
            // Work that overran its own period runs again immediately rather
            // than trying to catch up on a debt it cannot pay.
            Cadence::FixedRate { .. } => (base.saturating_sub(elapsed_secs).max(1), false),
            Cadence::FixedDelay { .. } => (base, false),
        },
    };

    // Jitter spreads a fleet; it never shortens a backoff below the base.
    let spread = (wait * JITTER_PERCENT) / 100;
    let offset = if spread == 0 { 0 } else { jitter % (spread * 2 + 1) };
    let jittered = wait.saturating_add(offset).saturating_sub(spread).max(1);

    Plan {
        wait_secs: jittered,
        backing_off,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_JITTER: u64 = 0;

    fn rate(secs: u64) -> Cadence {
        Cadence::FixedRate { secs }
    }
    fn delay(secs: u64) -> Cadence {
        Cadence::FixedDelay { secs }
    }

    /// The band a wait may land in once jitter is applied.
    fn within(wait: u64, base_after_work: u64) -> bool {
        let spread = (base_after_work * JITTER_PERCENT) / 100;
        wait >= base_after_work.saturating_sub(spread) && wait <= base_after_work + spread
    }

    #[test]
    fn a_fixed_rate_task_subtracts_its_own_work_time() {
        // Otherwise a sixty-second task that takes ten seconds runs every
        // seventy, and a schedule aligned to settlement periods slides off it.
        // Asserted as a band rather than a value, because jitter is deliberate
        // and pinning the exact number would just be pinning the jitter.
        for j in 0..40 {
            let p = next_wait(rate(60), Outcome::Ok, 0, 10, Backoff::default(), j);
            assert!(within(p.wait_secs, 50), "{} not near 50", p.wait_secs);
        }
    }

    #[test]
    fn a_fixed_delay_task_does_not() {
        // Its period is measured from completion on purpose, so how long the
        // work took makes no difference at all.
        for j in 0..40 {
            let with_work = next_wait(delay(60), Outcome::Ok, 0, 10, Backoff::default(), j);
            let without = next_wait(delay(60), Outcome::Ok, 0, 0, Backoff::default(), j);
            assert_eq!(with_work.wait_secs, without.wait_secs);
            assert!(within(with_work.wait_secs, 60));
        }
    }

    #[test]
    fn work_that_overran_its_period_runs_again_immediately() {
        // Rather than accumulating a debt of missed runs it cannot pay off.
        let p = next_wait(rate(60), Outcome::Ok, 0, 300, Backoff::default(), NO_JITTER);
        assert_eq!(p.wait_secs, 1);
    }

    #[test]
    fn failure_backs_off_and_success_resets_it() {
        let b = Backoff::default();
        let one = next_wait(rate(60), Outcome::Failed, 1, 0, b, NO_JITTER);
        let three = next_wait(rate(60), Outcome::Failed, 3, 0, b, NO_JITTER);
        assert!(three.wait_secs > one.wait_secs);
        assert!(one.backing_off && three.backing_off);

        let recovered = next_wait(rate(60), Outcome::Ok, 0, 0, b, NO_JITTER);
        assert!(!recovered.backing_off);
        assert!(recovered.wait_secs < one.wait_secs);
    }

    #[test]
    fn backoff_is_capped_so_a_recovered_endpoint_is_noticed() {
        // Unbounded doubling means a feed that comes back after an outage
        // waits hours to find out.
        let b = Backoff { factor: 2, max_secs: 900 };
        let p = next_wait(rate(60), Outcome::Failed, 20, 0, b, NO_JITTER);
        assert!(p.wait_secs <= 900 + 90, "capped, allowing for jitter");
    }

    #[test]
    fn an_enormous_failure_count_does_not_overflow() {
        let p = next_wait(rate(60), Outcome::Failed, u32::MAX, 0, Backoff::default(), NO_JITTER);
        assert!(p.wait_secs > 0 && p.wait_secs <= 990);
    }

    #[test]
    fn a_skip_waits_the_ordinary_period_rather_than_backing_off() {
        // A gated task would otherwise be slowest to resume at exactly the
        // moment the condition clears.
        let p = next_wait(rate(60), Outcome::Skipped, 5, 0, Backoff::default(), NO_JITTER);
        assert!(!p.backing_off);
        assert!(p.wait_secs < 70);
    }

    #[test]
    fn jitter_spreads_a_fleet_around_the_period() {
        // The failure it prevents: every node boots together, polls on the
        // same timer, and hits the controller in the same millisecond forever.
        let waits: Vec<u64> = (0..40)
            .map(|j| next_wait(rate(60), Outcome::Ok, 0, 0, Backoff::default(), j).wait_secs)
            .collect();
        let lo = *waits.iter().min().unwrap();
        let hi = *waits.iter().max().unwrap();
        assert!(hi > lo, "jitter produced no spread");
        assert!(lo >= 54 && hi <= 66, "spread was {lo}..{hi}, expected within 10% of 60");
    }

    #[test]
    fn jitter_never_produces_a_zero_wait() {
        // A zero wait is a busy loop, and on a one-second task the jitter
        // arithmetic is where that would come from.
        for j in 0..50 {
            for secs in [1, 2, 5] {
                let p = next_wait(rate(secs), Outcome::Ok, 0, 0, Backoff::default(), j);
                assert!(p.wait_secs >= 1, "{secs}s task with jitter {j} waited 0");
            }
        }
    }

    #[test]
    fn a_zero_period_is_treated_as_one_second() {
        let p = next_wait(rate(0), Outcome::Ok, 0, 0, Backoff::default(), NO_JITTER);
        assert!(p.wait_secs >= 1);
    }
}
