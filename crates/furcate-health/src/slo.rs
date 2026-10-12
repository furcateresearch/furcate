//! What "healthy" was promised to mean, as a number with a budget attached.
//!
//! Everything else in this crate answers *is something wrong*. This answers
//! *how much wrong is allowed*, which is the question that turns a signal into
//! a decision. Without it, [`crate::remediation`] can only be bounded by
//! `max_attempts` — a hard-coded count, invented once, that knows nothing
//! about whether the service it is restarting is actually in trouble.
//!
//! ## The budget is the point, not the percentage
//!
//! A target of 99.9% over thirty days is not a promise never to fail. It is a
//! statement that roughly forty-three minutes of failure are *acceptable*, and
//! the useful question is how much of that allowance is left and how fast it is
//! going. A service that has spent 5% of its budget is fine even while it is
//! failing right now; one that has spent 95% in the first two days is in
//! trouble even though it currently looks perfect.
//!
//! ## Nothing is claimed early
//!
//! The same discipline the rest of the platform applies to a measurement it
//! does not have. Three minutes into a thirty-day window, one failed request
//! reads as a catastrophic 100% burn and zero failures read as flawless, and
//! neither is information. [`Status::TooEarly`] is a real answer and is
//! returned rather than a number that would be acted on.

use serde::{Deserialize, Serialize};

/// A promise about a service, and the period it is measured over.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Objective {
    /// What this is a promise about, e.g. `edge.availability`.
    pub name: String,
    /// The fraction of events that must succeed, e.g. `0.999`.
    pub target: f64,
    /// The rolling period the target is measured over.
    pub window_secs: u64,
}

impl Objective {
    /// Events that may fail, out of `total`, before the promise is broken.
    ///
    /// Rounded down: a budget of "2.7 failures" allows two. Rounding the other
    /// way would let a service breach its own target and still report budget
    /// remaining, which is the one direction this must never err in.
    pub fn allowed_failures(&self, total: u64) -> u64 {
        if total == 0 {
            return 0;
        }
        let allowed = (1.0 - self.target.clamp(0.0, 1.0)) * total as f64;
        allowed.floor().max(0.0) as u64
    }
}

/// What was observed over the window so far.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Observed {
    pub good: u64,
    pub total: u64,
    /// How much of the window has actually elapsed.
    pub elapsed_secs: u64,
}

impl Observed {
    pub fn failures(&self) -> u64 {
        self.total.saturating_sub(self.good)
    }
}

/// Least of the window, and fewest events, before a figure is reported.
///
/// Both are needed and neither alone is enough: a busy service reaches a
/// thousand events in seconds and still has not seen a daily pattern, and a
/// quiet one can be a week in with nine requests. The numbers are deliberately
/// modest — this gate exists to refuse noise, not to withhold an answer until
/// it is too late to use.
pub const MIN_WINDOW_FRACTION: f64 = 0.05;
pub const MIN_EVENTS: u64 = 100;

/// Where a service stands against its promise.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Too little of the window, or too few events, to say anything.
    TooEarly { elapsed_secs: u64, total: u64 },
    /// Within budget.
    Meeting {
        /// Fraction of the allowance still unspent, 0.0 to 1.0.
        budget_remaining: f64,
        /// Failure rate over allowed failure rate. Above 1.0 the budget will
        /// not last the window at this pace, even though it has not run out.
        burn_rate: f64,
    },
    /// The allowance is gone. The promise is broken for this window.
    Exhausted { failures: u64, allowed: u64 },
}

impl Status {
    pub fn is_exhausted(&self) -> bool {
        matches!(self, Status::Exhausted { .. })
    }

    /// Whether the budget will survive the window at the current pace.
    ///
    /// Distinct from [`Status::is_exhausted`], and the more useful of the two
    /// while there is still time to act: a service can be comfortably inside
    /// its allowance and spending it four times too fast.
    pub fn is_burning_too_fast(&self) -> bool {
        matches!(self, Status::Meeting { burn_rate, .. } if *burn_rate > 1.0)
    }

    /// Whether automatic remediation should keep trying.
    ///
    /// False once the budget is gone, and the reasoning is worth stating
    /// because the opposite is at least as intuitive: surely the moment things
    /// are worst is the moment to keep trying? The answer is that automatic
    /// remediation has by then had the whole window to work and the service is
    /// still outside its promise, so the loop is not fixing it — and every
    /// further restart costs another outage of its own while a person who
    /// could fix it has not been told. Exhaustion is the principled version of
    /// the `max_attempts` count, which was a number somebody guessed once.
    ///
    /// `TooEarly` permits it. Refusing to act because nothing is known yet
    /// would make a service unrecoverable for the first hour of every window.
    pub fn permits_automatic_remediation(&self) -> bool {
        !self.is_exhausted()
    }
}

/// Judge a service against its objective.
pub fn assess(objective: &Objective, observed: &Observed) -> Status {
    let long_enough =
        observed.elapsed_secs as f64 >= objective.window_secs as f64 * MIN_WINDOW_FRACTION;
    if !long_enough || observed.total < MIN_EVENTS {
        return Status::TooEarly {
            elapsed_secs: observed.elapsed_secs,
            total: observed.total,
        };
    }

    let failures = observed.failures();
    let allowed = objective.allowed_failures(observed.total);
    if failures > allowed {
        return Status::Exhausted { failures, allowed };
    }

    let budget_remaining = if allowed == 0 {
        // A target so strict that the observed volume allows no failures at
        // all. Nothing has failed, or the branch above would have taken it, so
        // the budget is intact — but it is one event from gone, and reporting
        // it as full would be flattering.
        0.0
    } else {
        1.0 - (failures as f64 / allowed as f64)
    };

    // Burn rate compares the pace of spending against the pace the window can
    // afford. Elapsed time, not event count, is the denominator: a budget is
    // spent over a period, and a quiet hour does not bank allowance.
    let window_fraction =
        (observed.elapsed_secs as f64 / objective.window_secs.max(1) as f64).clamp(1e-9, 1.0);
    let spent_fraction = if allowed == 0 {
        0.0
    } else {
        failures as f64 / allowed as f64
    };
    let burn_rate = spent_fraction / window_fraction;

    Status::Meeting {
        budget_remaining,
        burn_rate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three_nines() -> Objective {
        Objective {
            name: "edge.availability".into(),
            target: 0.999,
            window_secs: 30 * 86_400,
        }
    }

    #[test]
    fn nothing_is_claimed_from_a_handful_of_events() {
        // Three minutes into thirty days, one failure would read as a total
        // burn and none as perfection. Neither is information.
        let s = assess(
            &three_nines(),
            &Observed {
                good: 8,
                total: 9,
                elapsed_secs: 180,
            },
        );
        assert_eq!(
            s,
            Status::TooEarly {
                elapsed_secs: 180,
                total: 9
            }
        );
        // And it does not block remediation while it knows nothing.
        assert!(s.permits_automatic_remediation());
    }

    #[test]
    fn a_busy_service_early_in_the_window_is_still_too_early() {
        // Volume alone is not enough: a million events in the first minute
        // have not seen a daily pattern.
        let s = assess(
            &three_nines(),
            &Observed {
                good: 999_000,
                total: 1_000_000,
                elapsed_secs: 60,
            },
        );
        assert!(matches!(s, Status::TooEarly { .. }));
    }

    #[test]
    fn a_service_inside_its_allowance_is_meeting_it() {
        // 10,000 events at 99.9% allows 10 failures; 4 have happened, half way
        // through the window.
        let s = assess(
            &three_nines(),
            &Observed {
                good: 9_996,
                total: 10_000,
                elapsed_secs: 15 * 86_400,
            },
        );
        match s {
            Status::Meeting {
                budget_remaining,
                burn_rate,
            } => {
                assert!((budget_remaining - 0.6).abs() < 1e-9, "{budget_remaining}");
                // 40% of the budget spent in 50% of the window: sustainable.
                assert!((burn_rate - 0.8).abs() < 1e-9, "{burn_rate}");
            }
            other => panic!("expected Meeting, got {other:?}"),
        }
        assert!(!s.is_burning_too_fast());
    }

    #[test]
    fn burning_too_fast_is_reported_before_the_budget_is_gone() {
        // The state worth acting on: comfortably inside the allowance, and
        // spending it four times faster than the window can afford.
        let s = assess(
            &three_nines(),
            &Observed {
                good: 9_992,
                total: 10_000,
                elapsed_secs: 6 * 86_400,
            },
        );
        assert!(s.is_burning_too_fast(), "{s:?}");
        assert!(!s.is_exhausted());
        // Still inside the promise, so automation keeps working.
        assert!(s.permits_automatic_remediation());
    }

    #[test]
    fn an_exhausted_budget_stops_the_restart_loop_and_calls_a_person() {
        let s = assess(
            &three_nines(),
            &Observed {
                good: 9_970,
                total: 10_000,
                elapsed_secs: 20 * 86_400,
            },
        );
        assert_eq!(
            s,
            Status::Exhausted {
                failures: 30,
                allowed: 10
            }
        );
        assert!(!s.permits_automatic_remediation());
    }

    #[test]
    fn the_allowance_rounds_against_the_service() {
        // 2.7 allowed failures means two. Rounding up would let a service
        // breach its own target and still report budget remaining.
        let o = three_nines();
        assert_eq!(o.allowed_failures(2_700), 2);
        assert_eq!(o.allowed_failures(1_000), 1);
        assert_eq!(o.allowed_failures(0), 0);
    }

    #[test]
    fn a_target_the_volume_cannot_express_is_not_reported_as_healthy() {
        // 100 events at 99.9% allows zero failures. Nothing has failed, so the
        // promise holds — but it is one event from broken, and a full budget
        // would be a flattering way to say that.
        let s = assess(
            &three_nines(),
            &Observed {
                good: 100,
                total: 100,
                elapsed_secs: 10 * 86_400,
            },
        );
        match s {
            Status::Meeting {
                budget_remaining, ..
            } => assert_eq!(budget_remaining, 0.0),
            other => panic!("expected Meeting, got {other:?}"),
        }
    }
}
