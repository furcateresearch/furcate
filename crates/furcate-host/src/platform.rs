//! The clock, the kernel, and what is waiting for a reboot.
//!
//! Three facts about a host that are dull individually and matter here more
//! than they would elsewhere.
//!
//! **The clock.** Most systems tolerate a drifting clock; this one does not.
//! Tariff windows are wall-clock local, so an hour of drift runs deferrable
//! work inside peak while believing it is saving money. Sun position comes from
//! the timestamp. Attestation freshness is a validity window. The operation
//! chain is ordered by time, and the scheduler measures its own periods against
//! it. A host whose clock is wrong makes this system confidently wrong in four
//! places at once, and none of them announce themselves.
//!
//! **A pending reboot.** Today's lesson on this site was that restarting a
//! machine is riskier than it looks — a database replica that restarts must
//! rebuild its entire sequencer set, and if any of it is unreachable it does
//! not come back. Knowing a reboot is already pending is the difference between
//! choosing a moment and discovering one.
//!
//! **What is actually running.** Binaries here have been deployed by copying
//! them over and restarting a unit, which leaves no record of what version is
//! where. A fleet where that is unknown is a fleet where "did the fix land"
//! cannot be answered.

use serde::{Deserialize, Serialize};

/// How the clock is being kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    /// systemd-timesyncd, chrony or ntpd reports the clock as synchronised.
    Synchronised,
    /// A daemon is running but has not converged.
    Converging,
    /// Nothing is disciplining the clock.
    Unsynchronised,
    /// Could not be determined.
    Unknown,
}

impl TimeSource {
    /// Whether decisions that depend on wall-clock time can be trusted.
    ///
    /// `Unknown` counts as untrusted. The alternative is a system that
    /// silently treats "nobody looked" as "fine", and the whole point of this
    /// field is the case where nobody looked.
    pub fn is_trustworthy(&self) -> bool {
        matches!(self, TimeSource::Synchronised)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Clock {
    pub source: TimeSource,
    /// Offset from the reference in milliseconds, where the daemon reports it.
    pub offset_ms: Option<i64>,
    /// Which daemon answered.
    pub daemon: Option<String>,
    /// The hour where this machine physically is, 0-23.
    ///
    /// Local rather than UTC, and that is the whole point of carrying it. A
    /// fleet spans time zones, and anything that reasons about what hour it is
    /// for the people near a machine — quiet hours, tariff windows, a
    /// maintenance window someone has to be awake for — must use the clock at
    /// the machine rather than the clock at whoever is asking. Judging a
    /// machine in one place by the hour in another is how a night-time
    /// decision arrives at lunchtime.
    ///
    /// `None` when the clock did not report it. Never defaulted: a guessed
    /// hour would throttle a machine mid-working-day or leave a bedroom loud
    /// all night, and either is worse than declining to judge.
    #[serde(default)]
    pub local_hour: Option<u8>,
}

impl Clock {
    /// Offset beyond which wall-clock decisions are affected.
    ///
    /// Two seconds is far tighter than a tariff window needs and far looser
    /// than a synchronised clock ever drifts, which makes it a good line: any
    /// host past it has something actually wrong rather than a slow NTP round.
    pub const MAX_OFFSET_MS: i64 = 2_000;

    /// Whether anything that reasons about wall-clock time should proceed.
    pub fn may_decide_on_time(&self) -> bool {
        if !self.source.is_trustworthy() {
            return false;
        }
        match self.offset_ms {
            Some(o) => o.abs() <= Self::MAX_OFFSET_MS,
            // Synchronised but not reporting an offset is the common case for
            // timesyncd, and is fine.
            None => true,
        }
    }
}

/// Whether the host is waiting to be restarted, and why.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reboot {
    pub required: bool,
    /// Packages that asked for it, where the system records them.
    pub because: Vec<String>,
    /// Security updates waiting to be installed.
    pub security_updates: Option<u32>,
}

impl Reboot {
    /// Whether this host should be restarted at the next opportunity rather
    /// than at the next convenient moment.
    ///
    /// Deliberately conservative about saying yes. On this site a restart is
    /// expensive — it can cost tens of minutes of reconnection — so "a reboot
    /// is pending" and "reboot now" are different statements and only the
    /// first is made automatically.
    pub fn is_urgent(&self) -> bool {
        self.required && self.security_updates.map(|n| n > 0).unwrap_or(false)
    }
}

/// What is running, so "did the fix land" is answerable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Build {
    /// Version of the agent reporting this.
    pub version: String,
    /// Kernel release.
    pub kernel: String,
    /// Seconds since boot.
    pub uptime_secs: u64,
}

impl Build {
    /// Whether the host has been up long enough for its own measurements to
    /// mean anything.
    ///
    /// Load averages, pressure and counter rates all need a few minutes of
    /// history; reading them a minute after boot produces figures that look
    /// like a crisis and are an artefact.
    pub fn measurements_are_settled(&self) -> bool {
        self.uptime_secs > 300
    }
}

/// Parse `timedatectl show` output.
///
/// Reads only the two fields that matter and ignores the rest, which is the
/// same discipline the external feeds use: a parser that understands one shape
/// cannot be surprised by another.
pub fn parse_timedatectl(text: &str) -> Clock {
    let mut synced = None;
    let mut ntp_active = None;
    let mut local_hour = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("NTPSynchronized", v)) => synced = Some(v.trim() == "yes"),
            Some(("NTP", v)) => ntp_active = Some(v.trim() == "yes"),
            // `TimeUSec=Sun 2026-09-13 09:41:13 CEST`. Already in the output
            // this function is handed, already local, and already carrying the
            // zone — so the hour costs nothing to read and needs neither a
            // time-zone database nor a second command.
            Some(("TimeUSec", v)) => local_hour = hour_of(v),
            _ => {}
        }
    }
    let source = match (synced, ntp_active) {
        (Some(true), _) => TimeSource::Synchronised,
        (Some(false), Some(true)) => TimeSource::Converging,
        (Some(false), Some(false)) => TimeSource::Unsynchronised,
        _ => TimeSource::Unknown,
    };
    Clock {
        source,
        offset_ms: None,
        daemon: Some("systemd-timesyncd".into()),
        local_hour,
    }
}

/// The hour out of a `Day YYYY-MM-DD HH:MM:SS ZONE` stamp.
///
/// Tolerant of the shape and strict about the value: anything that does not
/// yield an hour in 0-23 returns `None` rather than a number, because a
/// plausible-looking wrong hour is worse here than no hour at all.
fn hour_of(stamp: &str) -> Option<u8> {
    stamp
        .split_whitespace()
        .find(|f| f.len() >= 8 && f.as_bytes()[2] == b':' && f.as_bytes()[5] == b':')
        .and_then(|t| t.split(':').next())
        .and_then(|h| h.parse::<u8>().ok())
        .filter(|h| *h <= 23)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stamp `timedatectl show` already emits, which is where the hour
    /// comes from without a time-zone database or a second command.
    #[test]
    fn the_local_hour_is_read_from_the_stamp_the_clock_already_reports() {
        let c = parse_timedatectl(
            "Timezone=Europe/Tirane\nNTP=yes\nNTPSynchronized=yes\n\
             TimeUSec=Sun 2026-09-13 09:41:13 CEST",
        );
        assert_eq!(c.local_hour, Some(9));
    }

    /// Local, not UTC. The same instant was 07:41 UTC, and a fleet judged on
    /// the wrong one makes night-time decisions at lunchtime.
    #[test]
    fn the_hour_is_the_one_at_the_machine() {
        let c = parse_timedatectl("TimeUSec=Sun 2026-09-13 23:05:00 CEST");
        assert_eq!(c.local_hour, Some(23), "not 21, which is the UTC hour");
    }

    /// Midnight parses as zero rather than as absent, which a truthiness test
    /// on the string would get wrong.
    #[test]
    fn midnight_is_zero_and_not_missing() {
        let c = parse_timedatectl("TimeUSec=Sun 2026-09-13 00:12:00 CEST");
        assert_eq!(c.local_hour, Some(0));
    }

    /// A clock that did not report one yields `None`. Nothing downstream may
    /// invent an hour, because the two directions of a wrong guess are a
    /// machine throttled mid-working-day and a bedroom loud all night.
    #[test]
    fn an_unreported_or_malformed_stamp_yields_no_hour() {
        assert_eq!(parse_timedatectl("NTP=yes").local_hour, None);
        assert_eq!(parse_timedatectl("TimeUSec=n/a").local_hour, None);
        assert_eq!(
            parse_timedatectl("TimeUSec=Sun 2026-09-13 41:00:00 CEST").local_hour,
            None,
            "an impossible hour is refused rather than passed on"
        );
    }

    #[test]
    fn a_synchronised_clock_may_decide_on_time() {
        let c = parse_timedatectl("NTP=yes\nNTPSynchronized=yes\nTimezone=Europe/Tirane");
        assert_eq!(c.source, TimeSource::Synchronised);
        assert!(c.may_decide_on_time());
    }

    #[test]
    fn a_daemon_that_has_not_converged_is_not_synchronised() {
        let c = parse_timedatectl("NTP=yes\nNTPSynchronized=no");
        assert_eq!(c.source, TimeSource::Converging);
        assert!(!c.may_decide_on_time());
    }

    #[test]
    fn no_daemon_at_all_is_unsynchronised() {
        let c = parse_timedatectl("NTP=no\nNTPSynchronized=no");
        assert_eq!(c.source, TimeSource::Unsynchronised);
    }

    #[test]
    fn an_unreadable_clock_is_untrusted_rather_than_assumed_fine() {
        // "Nobody looked" must not read as "fine" — the entire point of the
        // field is the case where nobody looked.
        let c = parse_timedatectl("Timezone=Europe/Tirane");
        assert_eq!(c.source, TimeSource::Unknown);
        assert!(!c.may_decide_on_time());
    }

    #[test]
    fn a_large_offset_stops_time_based_decisions_even_when_synchronised() {
        // An hour of drift runs deferrable work inside peak while the system
        // believes it is saving money.
        let c = Clock {
            source: TimeSource::Synchronised,
            offset_ms: Some(3_600_000),
            daemon: None,
            local_hour: None,
        };
        assert!(!c.may_decide_on_time());
    }

    #[test]
    fn ordinary_jitter_does_not() {
        let c = Clock {
            source: TimeSource::Synchronised,
            offset_ms: Some(-40),
            daemon: None,
            local_hour: None,
        };
        assert!(c.may_decide_on_time());
    }

    #[test]
    fn extra_fields_in_the_output_are_ignored() {
        let c = parse_timedatectl(
            "Timezone=Europe/Tirane\nLocalRTC=no\nNTP=yes\nNTPSynchronized=yes\nTimeUSec=123",
        );
        assert_eq!(c.source, TimeSource::Synchronised);
    }

    #[test]
    fn a_pending_reboot_is_reported_without_being_called_urgent() {
        // "A reboot is pending" and "reboot now" are different statements, and
        // on this site only the first is made automatically.
        let r = Reboot {
            required: true,
            because: vec!["linux-image-generic".into()],
            security_updates: Some(0),
        };
        assert!(r.required);
        assert!(!r.is_urgent());
    }

    #[test]
    fn a_pending_reboot_with_security_updates_is_urgent() {
        let r = Reboot {
            required: true,
            because: vec![],
            security_updates: Some(3),
        };
        assert!(r.is_urgent());
    }

    #[test]
    fn security_updates_without_a_pending_reboot_are_not_urgent_on_their_own() {
        let r = Reboot {
            required: false,
            because: vec![],
            security_updates: Some(5),
        };
        assert!(!r.is_urgent());
    }

    #[test]
    fn a_freshly_booted_host_says_its_measurements_are_not_settled() {
        // Pressure and counter rates read a minute after boot look like a
        // crisis and are an artefact.
        let b = Build {
            version: "0.1.0".into(),
            kernel: "7.0.0".into(),
            uptime_secs: 30,
        };
        assert!(!b.measurements_are_settled());
        assert!(Build { uptime_secs: 40_000, ..b }.measurements_are_settled());
    }
}
