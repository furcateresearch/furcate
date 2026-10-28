//! Deciding that an outage is real before anything acts on it.
//!
//! The ladder is fed only what this has confirmed, so no single read, parse
//! error, stale answer or unreachable daemon can start a descent:
//!
//! * on battery is confirmed after N consecutive on-battery reads from upsd
//!   itself, spread over at least a minimum time;
//! * mains on line is confirmed by one read (cancelling is the safe direction);
//! * losing contact with upsd while the last confirmed state was on line is
//!   logged as COMMBAD and nothing else;
//! * losing contact while the last confirmed state was on battery lets the
//!   ladder keep counting, but only once the loss has lasted `commbad_secs`;
//! * a supply never read, or one whose flags are neither OL nor OB, is never
//!   acted on.

use crate::ladder::{PowerState, Triggers};

/// One attempt to read the supply, reduced to what matters here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sample {
    OnLine,
    OnBattery,
    /// upsd answered but the status is neither OL nor OB.
    Unknown,
    /// Unreachable, refused, stale, garbage, or a parse error.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirmed {
    Never,
    OnLine,
    OnBattery,
}

/// What changed this pass, for the log and the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    None,
    /// An on-battery read that is not yet an outage (`reads` so far).
    ObSeen { reads: u32 },
    OutageConfirmed,
    MainsConfirmed,
    /// Contact with upsd lost; `acting` is whether the ladder keeps going
    /// without it (false whenever the last confirmed state was not on battery).
    CommBad,
    CommRestored,
}

pub struct Debounce {
    t: Triggers,
    confirmed: Confirmed,
    ob_reads: u32,
    ob_first: Option<u64>,
    comm_bad_since: Option<u64>,
}

impl Debounce {
    pub fn new(t: Triggers) -> Self {
        Self { t, confirmed: Confirmed::Never, ob_reads: 0, ob_first: None, comm_bad_since: None }
    }

    pub fn retune(&mut self, t: Triggers) {
        self.t = t;
    }

    pub fn confirmed(&self) -> Confirmed {
        self.confirmed
    }

    pub fn comm_bad_since(&self) -> Option<u64> {
        self.comm_bad_since
    }

    pub fn feed(&mut self, s: Sample, now: u64) -> Event {
        let mut ev = Event::None;
        // Contact bookkeeping first: any answer from upsd, even an odd one,
        // is contact.
        if s == Sample::Failed {
            if self.comm_bad_since.is_none() {
                self.comm_bad_since = Some(now);
                ev = Event::CommBad;
            }
        } else if self.comm_bad_since.take().is_some() {
            ev = Event::CommRestored;
        }
        match s {
            Sample::OnBattery => {
                if self.confirmed == Confirmed::OnBattery {
                    return ev;
                }
                let first = *self.ob_first.get_or_insert(now);
                self.ob_reads += 1;
                if self.ob_reads >= self.t.confirm_reads && now.saturating_sub(first) >= self.t.confirm_secs {
                    self.confirmed = Confirmed::OnBattery;
                    return Event::OutageConfirmed;
                }
                return Event::ObSeen { reads: self.ob_reads };
            }
            Sample::OnLine => {
                self.ob_reads = 0;
                self.ob_first = None;
                if self.confirmed != Confirmed::OnLine {
                    self.confirmed = Confirmed::OnLine;
                    return Event::MainsConfirmed;
                }
            }
            Sample::Unknown | Sample::Failed => {
                // Before an outage is confirmed these break the run of
                // consecutive reads; after it they change nothing.
                if self.confirmed != Confirmed::OnBattery {
                    self.ob_reads = 0;
                    self.ob_first = None;
                }
            }
        }
        ev
    }

    /// What the ladder may be told. `None` holds the rung.
    pub fn ladder_state(&self, now: u64) -> Option<PowerState> {
        match self.confirmed {
            Confirmed::Never => None,
            Confirmed::OnLine => Some(PowerState::OnLine),
            Confirmed::OnBattery => match self.comm_bad_since {
                None => Some(PowerState::OnBattery),
                Some(since) if now.saturating_sub(since) >= self.t.commbad_secs => Some(PowerState::OnBattery),
                Some(_) => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> Debounce {
        Debounce::new(Triggers::default())
    }

    #[test]
    fn a_single_on_battery_read_confirms_nothing() {
        let mut d = d();
        assert_eq!(d.feed(Sample::OnBattery, 0), Event::ObSeen { reads: 1 });
        assert_eq!(d.ladder_state(0), None);
        assert_eq!(d.confirmed(), Confirmed::Never);
    }

    #[test]
    fn reads_must_be_consecutive_and_spread_over_time() {
        let mut d = d();
        d.feed(Sample::OnBattery, 0);
        d.feed(Sample::OnBattery, 2);
        // Three reads inside a few seconds is a burst, not an outage.
        assert_eq!(d.feed(Sample::OnBattery, 4), Event::ObSeen { reads: 3 });
        assert_eq!(d.ladder_state(4), None);
        assert_eq!(d.feed(Sample::OnBattery, 20), Event::OutageConfirmed);
        assert_eq!(d.ladder_state(20), Some(PowerState::OnBattery));
    }

    #[test]
    fn a_parse_error_unknown_status_or_stale_answer_breaks_the_run() {
        for bad in [Sample::Failed, Sample::Unknown] {
            let mut d = d();
            d.feed(Sample::OnBattery, 0);
            d.feed(Sample::OnBattery, 10);
            d.feed(bad, 15);
            assert_eq!(d.feed(Sample::OnBattery, 20), Event::ObSeen { reads: 1 }, "{bad:?}");
            assert_eq!(d.ladder_state(20), None);
        }
    }

    #[test]
    fn losing_contact_while_on_line_is_logged_and_never_acts() {
        let mut d = d();
        assert_eq!(d.feed(Sample::OnLine, 0), Event::MainsConfirmed);
        assert_eq!(d.feed(Sample::Failed, 10), Event::CommBad);
        assert_eq!(d.ladder_state(10_000), Some(PowerState::OnLine), "stays on line, never an outage");
        assert_eq!(d.confirmed(), Confirmed::OnLine);
        assert_eq!(d.feed(Sample::OnLine, 20), Event::CommRestored);
    }

    #[test]
    fn losing_contact_while_on_battery_continues_only_once_sustained() {
        let mut d = d();
        for t in [0, 10, 20] {
            d.feed(Sample::OnBattery, t);
        }
        assert_eq!(d.confirmed(), Confirmed::OnBattery);
        assert_eq!(d.feed(Sample::Failed, 30), Event::CommBad);
        assert_eq!(d.ladder_state(60), None, "a short loss holds the rung");
        assert_eq!(d.ladder_state(90), Some(PowerState::OnBattery), "a sustained loss keeps the ladder going");
    }

    #[test]
    fn a_never_read_supply_is_never_acted_on() {
        let mut d = d();
        for t in 0..100 {
            d.feed(Sample::Failed, t);
        }
        assert_eq!(d.ladder_state(100), None);
        assert_eq!(d.confirmed(), Confirmed::Never);
    }

    #[test]
    fn mains_on_line_cancels_at_once() {
        let mut d = d();
        for t in [0, 10, 20] {
            d.feed(Sample::OnBattery, t);
        }
        assert_eq!(d.feed(Sample::OnLine, 21), Event::MainsConfirmed);
        assert_eq!(d.ladder_state(21), Some(PowerState::OnLine));
    }
}
