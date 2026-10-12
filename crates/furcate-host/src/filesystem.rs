//! Disks, and when they will fill.
//!
//! A percentage is the wrong number. Eighty-three percent full is not
//! actionable — it might be a database that has been at eighty-three percent
//! for a year, or one that was at fifty percent this morning. What an operator
//! needs is **how long until it fills**, and that requires two readings and a
//! rate rather than one reading and a threshold.
//!
//! The distinction is not academic. A filesystem crossing a fixed threshold
//! produces an alarm that is early on a stable mount and far too late on a
//! growing one; a filesystem with three days of headroom left produces an alarm
//! exactly when somebody can still do something about it.
//!
//! Inodes get the same treatment and are usually forgotten. A mount can be at
//! forty percent of its bytes and out of inodes, and the failure mode is
//! identical — writes stop — while every dashboard in the building says there
//! is plenty of room.

use serde::{Deserialize, Serialize};

/// One mounted filesystem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub path: String,
    pub device: String,
    pub fstype: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
}

impl Mount {
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.free_bytes)
    }

    pub fn used_fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        self.used_bytes() as f64 / self.total_bytes as f64
    }

    pub fn inode_used_fraction(&self) -> f64 {
        if self.total_inodes == 0 {
            // Not every filesystem has inodes to run out of.
            return 0.0;
        }
        (self.total_inodes - self.free_inodes) as f64 / self.total_inodes as f64
    }

    /// Whether this mount is worth watching at all.
    ///
    /// Overlay and tmpfs mounts come and go with containers, and a fleet
    /// report listing forty of them buries the two that matter under noise
    /// nobody can act on.
    pub fn is_durable(&self) -> bool {
        !matches!(
            self.fstype.as_str(),
            "tmpfs" | "devtmpfs" | "overlay" | "squashfs" | "ramfs" | "autofs" | "nsfs"
        )
    }
}

/// How fast a mount is filling, from two readings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Trend {
    pub path: String,
    /// Bytes consumed per second. Negative when space is being freed.
    pub bytes_per_sec: f64,
    /// Seconds until free space reaches zero at the current rate.
    ///
    /// `None` when the mount is stable or shrinking, which is the common case
    /// and must not be reported as an imminent failure.
    pub seconds_to_full: Option<u64>,
    /// How long the two readings were apart. A rate from a short window is
    /// noise, and the caller is told rather than left to assume.
    pub window_secs: u64,
}

impl Trend {
    /// Shortest window over which a growth rate means anything.
    ///
    /// Below this, a single log rotation or a container image pull dominates
    /// the measurement and produces a "fills in two hours" that is nonsense.
    pub const MIN_WINDOW_SECS: u64 = 900;

    /// Compute the trend between two readings of the same mount.
    pub fn between(before: &Mount, after: &Mount, window_secs: u64) -> Option<Self> {
        if before.path != after.path || window_secs == 0 {
            return None;
        }
        // A mount that was resized, or a device swapped underneath the path,
        // makes the two readings incomparable rather than dramatic.
        if before.total_bytes != after.total_bytes {
            return None;
        }

        let delta = after.used_bytes() as i64 - before.used_bytes() as i64;
        let rate = delta as f64 / window_secs as f64;

        let seconds_to_full = if rate > 0.0 && window_secs >= Self::MIN_WINDOW_SECS {
            Some((after.free_bytes as f64 / rate) as u64)
        } else {
            // Stable, shrinking, or measured over too short a window to say.
            None
        };

        Some(Trend {
            path: after.path.clone(),
            bytes_per_sec: rate,
            seconds_to_full,
            window_secs,
        })
    }

    pub fn days_to_full(&self) -> Option<f64> {
        self.seconds_to_full.map(|s| s as f64 / 86_400.0)
    }
}

/// What is wrong with a mount, if anything.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Concern {
    /// Filling fast enough that it needs attention before it stops writes.
    FillingSoon { days: f64 },
    /// Nearly full and not obviously growing — still worth saying, because a
    /// stable mount at ninety-eight percent has no room for anything unusual.
    NearlyFull { used_fraction: f64 },
    /// Out of inodes, or nearly. Bytes are irrelevant when this happens.
    InodesExhausted { used_fraction: f64 },
}

/// Days of headroom below which a filling mount is worth an operator's time.
///
/// A week, because that is long enough to plan and short enough to be real.
pub const URGENT_DAYS: f64 = 7.0;

/// Fraction above which a mount is nearly full regardless of trend.
pub const NEARLY_FULL: f64 = 0.90;

/// Judge one mount.
///
/// Trend first: a mount at sixty percent that fills in three days is a more
/// urgent problem than one that has sat at ninety-two percent for a year, and
/// reporting them the other way round is how threshold alerting trains people
/// to ignore disk alarms.
pub fn assess(m: &Mount, trend: Option<&Trend>) -> Vec<Concern> {
    let mut out = Vec::new();

    if let Some(days) = trend.and_then(|t| t.days_to_full()) {
        if days <= URGENT_DAYS {
            out.push(Concern::FillingSoon { days });
        }
    }
    if m.used_fraction() >= NEARLY_FULL {
        out.push(Concern::NearlyFull {
            used_fraction: m.used_fraction(),
        });
    }
    if m.inode_used_fraction() >= NEARLY_FULL {
        out.push(Concern::InodesExhausted {
            used_fraction: m.inode_used_fraction(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn mount(total_g: u64, free_g: u64) -> Mount {
        Mount {
            path: "/".into(),
            device: "/dev/nvme0n1p2".into(),
            fstype: "ext4".into(),
            total_bytes: total_g * GIB,
            free_bytes: free_g * GIB,
            total_inodes: 30_000_000,
            free_inodes: 29_000_000,
        }
    }

    #[test]
    fn container_and_memory_mounts_are_left_out_of_the_report() {
        // Forty overlay mounts would bury the two that matter.
        for fs in ["tmpfs", "overlay", "squashfs", "devtmpfs"] {
            let m = Mount { fstype: fs.into(), ..mount(100, 50) };
            assert!(!m.is_durable(), "{fs}");
        }
        assert!(mount(100, 50).is_durable());
    }

    #[test]
    fn a_stable_mount_has_no_time_to_full() {
        // The common case, and reporting it as imminent failure is how a
        // capacity alarm becomes background noise.
        let m = mount(469, 399);
        let t = Trend::between(&m, &m, 3600).unwrap();
        assert_eq!(t.bytes_per_sec, 0.0);
        assert!(t.seconds_to_full.is_none());
        assert!(assess(&m, Some(&t)).is_empty());
    }

    #[test]
    fn a_shrinking_mount_is_not_reported_as_filling() {
        let before = mount(469, 300);
        let after = mount(469, 350);
        let t = Trend::between(&before, &after, 3600).unwrap();
        assert!(t.bytes_per_sec < 0.0);
        assert!(t.seconds_to_full.is_none());
    }

    #[test]
    fn a_growing_mount_reports_days_rather_than_a_percentage() {
        // The number an operator can act on. A database growing 2 GiB a day
        // with 100 GiB free has fifty days — which is the useful answer, and
        // is invisible to any percentage-based check.
        let mib = 1024 * 1024;
        let before = Mount { free_bytes: 100 * GIB + 85 * mib, ..mount(469, 100) };
        let after = mount(469, 100);
        let t = Trend::between(&before, &after, 3600).unwrap();
        let days = t.days_to_full().unwrap();
        assert!((days - 50.0).abs() < 2.0, "days was {days}");
    }

    #[test]
    fn a_fast_filling_mount_reports_hours_not_days() {
        // 10 GiB an hour against 100 GiB free is ten hours, and the point of
        // the figure is that it is obviously urgent without a threshold.
        let before = mount(469, 110);
        let after = mount(469, 100);
        let t = Trend::between(&before, &after, 3600).unwrap();
        assert!((t.days_to_full().unwrap() - 0.42).abs() < 0.05);
        assert!(matches!(
            assess(&after, Some(&t)).first(),
            Some(Concern::FillingSoon { .. })
        ));
    }

    #[test]
    fn a_rate_from_too_short_a_window_is_refused() {
        // One log rotation over sixty seconds would otherwise read as filling
        // within the hour.
        let before = mount(469, 110);
        let after = mount(469, 100);
        let t = Trend::between(&before, &after, 60).unwrap();
        assert!(t.seconds_to_full.is_none(), "60s is not a trend");
        assert_eq!(t.window_secs, 60, "and the window is reported");
    }

    #[test]
    fn a_resized_mount_makes_the_readings_incomparable() {
        // Rather than producing a dramatic and meaningless rate.
        let before = mount(469, 100);
        let after = mount(940, 500);
        assert!(Trend::between(&before, &after, 3600).is_none());
    }

    #[test]
    fn a_mount_filling_within_the_week_is_urgent_even_at_sixty_percent() {
        // The inversion this module exists for: threshold alerting would say
        // nothing at all here.
        let before = mount(469, 60);
        let after = mount(469, 50);
        let t = Trend::between(&before, &after, 3600).unwrap();
        let c = assess(&after, Some(&t));
        assert!(matches!(c.first(), Some(Concern::FillingSoon { .. })));
        assert!(after.used_fraction() < 0.90, "and it is not nearly full");
    }

    #[test]
    fn a_mount_that_has_sat_nearly_full_forever_is_still_worth_saying() {
        // It has no room for anything unusual, which is a different problem
        // from filling and worth reporting differently.
        let m = mount(469, 20);
        let t = Trend::between(&m, &m, 3600).unwrap();
        let c = assess(&m, Some(&t));
        assert_eq!(c.len(), 1);
        assert!(matches!(c[0], Concern::NearlyFull { .. }));
    }

    #[test]
    fn inode_exhaustion_is_caught_while_the_bytes_look_fine() {
        // A mount at forty percent of its bytes and out of inodes fails in
        // exactly the same way, and every byte-based dashboard says it is fine.
        let m = Mount {
            free_inodes: 100_000,
            ..mount(469, 280)
        };
        assert!(m.used_fraction() < 0.5);
        let c = assess(&m, None);
        assert!(matches!(c[0], Concern::InodesExhausted { .. }));
    }

    #[test]
    fn a_filesystem_without_inodes_does_not_report_them_exhausted() {
        let m = Mount { total_inodes: 0, free_inodes: 0, ..mount(469, 280) };
        assert_eq!(m.inode_used_fraction(), 0.0);
        assert!(assess(&m, None).is_empty());
    }

    #[test]
    fn a_zero_sized_mount_does_not_divide_by_zero() {
        let m = Mount { total_bytes: 0, free_bytes: 0, ..mount(0, 0) };
        assert_eq!(m.used_fraction(), 0.0);
    }
}
