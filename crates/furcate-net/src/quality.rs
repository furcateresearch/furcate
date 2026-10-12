//! How good the connection is, as opposed to how fast it is.
//!
//! A throughput number is the metric everybody asks for and the one that
//! describes experience worst. A link can pass hundreds of megabits and be
//! unusable for anything interactive, because the buffers between here and
//! there fill up under load and every round trip queues behind a megabyte of
//! somebody's backup. The IETF metric for this is **responsiveness**, in round
//! trips per minute: `60 / loaded_RTT_seconds`. Above about a thousand is
//! excellent; below about three hundred feels sluggish while the link is busy.
//!
//! The standard way to measure it is to saturate the link on purpose and watch
//! what latency does. **This does not do that.** A site's uplink carries the
//! workloads the site exists to run, and a measurement that deliberately fills
//! the queues is a self-inflicted outage on a schedule — worse on the sites
//! that need the measurement most, because those are the ones with something
//! important on the wire. Instead responsiveness is computed *opportunistically* — from
//! round trips that happened to be taken while the link was already busy with
//! real traffic — and the result is labelled as opportunistic wherever it
//! appears. It is a weaker measurement than a controlled test and it costs
//! nothing, which on a production link is the right trade.

use crate::link::Delta;
use serde::{Deserialize, Serialize};

/// How busy the link was when a sample was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Load {
    /// Effectively nothing on the wire.
    Idle,
    /// Traffic, but nowhere near capacity.
    Light,
    /// Enough to start queueing.
    Busy,
    /// At or near the link's capacity.
    Saturated,
}

impl Load {
    pub fn from_utilisation(u: f64) -> Self {
        if u < 0.05 {
            Load::Idle
        } else if u < 0.35 {
            Load::Light
        } else if u < 0.80 {
            Load::Busy
        } else {
            Load::Saturated
        }
    }

    /// Whether a latency sample taken under this load says anything about
    /// responsiveness.
    ///
    /// An unloaded round trip measures distance, not buffering, and reporting
    /// it as responsiveness would give every idle link a perfect score.
    pub fn is_working_condition(&self) -> bool {
        matches!(self, Load::Busy | Load::Saturated)
    }
}

/// A round trip and the load it was taken under.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub rtt_ms: f64,
    pub load: Load,
}

/// Responsiveness in round trips per minute.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Responsiveness {
    pub rpm: f64,
    /// How many loaded samples it rests on.
    pub samples: usize,
    /// Always true here. A controlled test saturates the link on purpose;
    /// this waits for real traffic to do it, which means the figure arrives
    /// when it arrives and is never available on demand.
    pub opportunistic: bool,
}

impl Responsiveness {
    /// Loaded samples required before a figure is published.
    ///
    /// A single round trip that happened to land during a burst is noise, and
    /// an RPM quoted from it would swing by a factor of ten between polls.
    pub const MIN_SAMPLES: usize = 5;

    /// Compute from samples, using only those taken under working conditions.
    ///
    /// Returns `None` when the link was never busy enough to say — which on a
    /// quiet site is most of the time, and is the honest answer rather than a
    /// flattering one.
    pub fn from_samples(samples: &[Sample]) -> Option<Self> {
        let mut loaded: Vec<f64> = samples
            .iter()
            .filter(|s| s.load.is_working_condition())
            .map(|s| s.rtt_ms)
            .collect();
        if loaded.len() < Self::MIN_SAMPLES {
            return None;
        }
        loaded.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = loaded[loaded.len() / 2];
        if median <= 0.0 {
            return None;
        }
        Some(Responsiveness {
            rpm: 60_000.0 / median,
            samples: loaded.len(),
            opportunistic: true,
        })
    }

    /// Plain-language grade, on the scale the metric was defined against.
    pub fn grade(&self) -> &'static str {
        if self.rpm >= 1000.0 {
            "excellent"
        } else if self.rpm >= 300.0 {
            "usable"
        } else {
            "sluggish under load"
        }
    }
}

/// Something the operator could actually do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advice {
    pub lever: String,
    pub reason: String,
    /// Whether the site can act on this without involving the provider.
    pub within_our_control: bool,
}

/// Everything known about the connection at one moment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quality {
    pub load: Load,
    pub rx_mbps: f64,
    pub tx_mbps: f64,
    /// Capacity the utilisation was measured against, and where that number
    /// came from — a negotiated link rate is not an uplink capacity.
    pub against_mbps: u32,
    pub capacity_is_declared: bool,
    pub responsiveness: Option<Responsiveness>,
    pub loss: f64,
    pub rtt_ms: Option<f64>,
}

impl Quality {
    pub fn from_delta(
        delta: &Delta,
        capacity_mbps: u32,
        capacity_is_declared: bool,
        rtt_ms: Option<f64>,
        loss: f64,
        samples: &[Sample],
    ) -> Self {
        let u = delta.utilisation_of(capacity_mbps).unwrap_or(0.0);
        Quality {
            load: Load::from_utilisation(u),
            rx_mbps: delta.rx_mbps(),
            tx_mbps: delta.tx_mbps(),
            against_mbps: capacity_mbps,
            capacity_is_declared,
            responsiveness: Responsiveness::from_samples(samples),
            loss,
            rtt_ms,
        }
    }

    /// What is worth doing about it.
    ///
    /// Deliberately short, and honest about the boundary: a site cannot make
    /// its provider faster. What it can do is stop competing with itself,
    /// which is where nearly all recoverable latency at this scale lives.
    pub fn advice(&self) -> Vec<Advice> {
        let mut out = Vec::new();

        if !self.capacity_is_declared {
            out.push(Advice {
                lever: "declare the uplink's real capacity".into(),
                reason: "utilisation is currently measured against the negotiated \
                         link rate, which is the switch port and not the service; \
                         every saturation figure is wrong until this is set"
                    .into(),
                within_our_control: true,
            });
        }

        if self.load >= Load::Saturated {
            out.push(Advice {
                lever: "move bulk transfers to an idle window".into(),
                reason: "the link is at capacity, so everything interactive is \
                         queueing behind whatever is filling it — and the thing \
                         filling it is almost always ours"
                    .into(),
                within_our_control: true,
            });
        }

        if let Some(r) = &self.responsiveness {
            if r.rpm < 300.0 {
                out.push(Advice {
                    lever: "enable a modern queue discipline on the uplink".into(),
                    reason: format!(
                        "{:.0} RPM under load is {}; that is buffering between \
                         here and the provider, and fq_codel or cake on the \
                         egress interface addresses it without more bandwidth",
                        r.rpm,
                        r.grade()
                    ),
                    within_our_control: true,
                });
            }
        }

        if self.loss > 0.0 && self.load < Load::Busy {
            out.push(Advice {
                lever: "raise loss on a quiet link with the provider".into(),
                reason: "packets are being lost while the link is not busy, so \
                         it is not our congestion — which makes it theirs"
                    .into(),
                within_our_control: false,
            });
        }

        out
    }

    /// Whether anything here should stop the site starting large transfers.
    pub fn should_defer_bulk(&self) -> bool {
        self.load >= Load::Busy
            || matches!(&self.responsiveness, Some(r) if r.rpm < 300.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::Delta;

    fn delta(rx_bytes: u64, tx_bytes: u64) -> Delta {
        Delta {
            name: "enp0s25".into(),
            interval_ms: 1000,
            rx_bytes,
            tx_bytes,
            crc_errors: 0,
            dropped: 0,
            carrier_changes: 0,
        }
    }

    fn loaded(n: usize, rtt: f64) -> Vec<Sample> {
        (0..n).map(|_| Sample { rtt_ms: rtt, load: Load::Busy }).collect()
    }

    #[test]
    fn an_idle_link_offers_no_responsiveness_figure() {
        // An unloaded round trip measures distance, not buffering, and
        // reporting it would give every quiet link a perfect score.
        let idle: Vec<Sample> = (0..50)
            .map(|_| Sample { rtt_ms: 8.0, load: Load::Idle })
            .collect();
        assert!(Responsiveness::from_samples(&idle).is_none());
    }

    #[test]
    fn one_lucky_sample_is_not_enough_to_publish() {
        assert!(Responsiveness::from_samples(&loaded(1, 40.0)).is_none());
        assert!(Responsiveness::from_samples(&loaded(5, 40.0)).is_some());
    }

    #[test]
    fn responsiveness_follows_the_defined_formula() {
        // 60 seconds divided by a 60 ms loaded round trip is 1000 RPM.
        let r = Responsiveness::from_samples(&loaded(9, 60.0)).unwrap();
        assert!((r.rpm - 1000.0).abs() < 1e-6);
        assert_eq!(r.grade(), "excellent");
    }

    #[test]
    fn a_bufferbloated_link_grades_as_sluggish() {
        // Half a second of queueing under load: passes any throughput test,
        // miserable to use.
        let r = Responsiveness::from_samples(&loaded(9, 500.0)).unwrap();
        assert!(r.rpm < 300.0);
        assert_eq!(r.grade(), "sluggish under load");
    }

    #[test]
    fn every_figure_this_produces_is_marked_opportunistic() {
        // Because nothing here saturates the link on purpose, and a reader
        // must be able to tell this from a controlled test.
        assert!(Responsiveness::from_samples(&loaded(9, 60.0)).unwrap().opportunistic);
    }

    #[test]
    fn utilisation_against_a_link_rate_is_flagged_as_not_the_service() {
        // 50 Mb/s on a gigabit port reads as light traffic and would saturate
        // a 50 Mb uplink completely.
        let q = Quality::from_delta(&delta(6_250_000, 0), 1000, false, Some(20.0), 0.0, &[]);
        assert_eq!(q.load, Load::Light);
        assert!(!q.should_defer_bulk(), "and nothing would stop a big transfer");
        let a = q.advice();
        assert!(a.iter().any(|x| x.lever.contains("real capacity")));
    }

    #[test]
    fn the_same_traffic_against_the_real_uplink_is_saturated() {
        let q = Quality::from_delta(&delta(6_250_000, 0), 50, true, Some(20.0), 0.0, &[]);
        assert_eq!(q.load, Load::Saturated);
        assert!(q.should_defer_bulk());
        assert!(q.advice().iter().any(|x| x.lever.contains("idle window")));
    }

    #[test]
    fn a_saturated_link_is_our_own_traffic_and_the_advice_says_so() {
        let q = Quality::from_delta(&delta(6_250_000, 0), 50, true, Some(20.0), 0.0, &[]);
        let a = q.advice();
        let bulk = a.iter().find(|x| x.lever.contains("idle window")).unwrap();
        assert!(bulk.within_our_control);
    }

    #[test]
    fn loss_on_a_quiet_link_is_attributed_outward() {
        // Not our congestion, so not our fix.
        let q = Quality::from_delta(&delta(1000, 0), 1000, true, Some(20.0), 0.04, &[]);
        let a = q.advice();
        let l = a.iter().find(|x| x.lever.contains("provider")).unwrap();
        assert!(!l.within_our_control);
    }

    #[test]
    fn loss_while_saturated_is_not_blamed_on_the_provider() {
        // A full link drops packets; that is what a full link does.
        let q = Quality::from_delta(&delta(6_250_000, 0), 50, true, Some(20.0), 0.04, &[]);
        assert!(!q.advice().iter().any(|x| x.lever.contains("provider")));
    }

    #[test]
    fn a_bloated_link_gets_a_queue_discipline_suggestion_not_more_bandwidth() {
        let q = Quality::from_delta(&delta(1000, 0), 1000, true, Some(20.0), 0.0, &loaded(9, 500.0));
        let a = q.advice();
        assert!(a.iter().any(|x| x.lever.contains("queue discipline")));
        assert!(q.should_defer_bulk(), "even though the link is idle right now");
    }

    #[test]
    fn a_healthy_idle_link_needs_no_advice_beyond_declaring_capacity() {
        let q = Quality::from_delta(&delta(1000, 0), 1000, true, Some(8.0), 0.0, &loaded(9, 30.0));
        assert!(q.advice().is_empty());
        assert!(!q.should_defer_bulk());
    }
}
