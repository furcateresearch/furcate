//! Backups, certificates, and configuration — three things with deadlines.
//!
//! They look unrelated and they fail the same way: something that was fine when
//! it was set up quietly stops being fine, and nobody finds out until it
//! matters. A backup that stopped running three weeks ago looks exactly like
//! one that ran last night, right up until a restore.
//!
//! ## What this refuses to claim
//!
//! **A backup that has never been restored is a hypothesis.** This can report
//! that a file exists, that it is recent, that it is not suspiciously small,
//! and that its contents still hash to what was recorded. It cannot report that
//! it would restore, because the only way to know is to restore it. That
//! distinction is carried in the type rather than left in a comment, because
//! "backup: ok" is one of the most expensive lies a monitoring system can tell.

use serde::{Deserialize, Serialize};

/// A backup artefact on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backup {
    pub path: String,
    pub bytes: u64,
    /// Unix seconds of last modification.
    pub modified: u64,
    /// Digest recorded when it was last checked, if it has been.
    pub digest: Option<String>,
}

/// What can be said about a backup, and what cannot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Recent, plausibly sized, and unchanged since it was last hashed.
    ///
    /// The name is the honest one. Nothing here has restored it, so this is a
    /// statement about a file rather than about recoverability.
    PresentAndIntact,
    /// Older than the interval it is supposed to be taken at.
    Stale { age_secs: u64 },
    /// Present but far smaller than its predecessors, which is what a backup
    /// looks like when the thing producing it failed partway through.
    Truncated { bytes: u64, expected_at_least: u64 },
    /// The digest no longer matches what was recorded.
    Altered,
    /// Nothing is there at all.
    Missing,
}

impl Verdict {
    /// Whether an operator needs to look.
    pub fn needs_attention(&self) -> bool {
        !matches!(self, Verdict::PresentAndIntact)
    }

    /// Always false, on purpose.
    ///
    /// Nothing in this module establishes that a backup can be restored. The
    /// method exists so that anything tempted to conclude otherwise has to
    /// call something that says no.
    pub fn proves_restorable(&self) -> bool {
        false
    }
}

/// What a backup is expected to look like.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Expectation {
    /// How often it should be taken.
    pub interval_secs: u64,
    /// Tolerance before staleness is reported, as a multiple of the interval.
    ///
    /// A backup taken nightly is not broken at 24 hours and one minute; it is
    /// broken when it has missed a cycle.
    pub grace_multiple: u64,
    /// Smallest size that is plausibly a whole backup. Below this it is
    /// assumed to have been interrupted.
    pub min_bytes: u64,
}

impl Default for Expectation {
    fn default() -> Self {
        Self {
            interval_secs: 86_400,
            grace_multiple: 2,
            min_bytes: 1024,
        }
    }
}

pub fn judge(backup: Option<&Backup>, expect: &Expectation, now: u64, digest_now: Option<&str>) -> Verdict {
    let Some(b) = backup else {
        return Verdict::Missing;
    };

    if b.bytes < expect.min_bytes {
        return Verdict::Truncated {
            bytes: b.bytes,
            expected_at_least: expect.min_bytes,
        };
    }

    // Alteration outranks staleness: a backup that changed under us is a
    // different and more alarming problem than one that is merely old.
    if let (Some(recorded), Some(now_digest)) = (&b.digest, digest_now) {
        if recorded != now_digest {
            return Verdict::Altered;
        }
    }

    let age = now.saturating_sub(b.modified);
    let allowed = expect.interval_secs.saturating_mul(expect.grace_multiple.max(1));
    if age > allowed {
        return Verdict::Stale { age_secs: age };
    }

    Verdict::PresentAndIntact
}

/// An X.509 certificate's expiry, however it was found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    pub path: String,
    pub subject: String,
    /// Unix seconds.
    pub not_after: u64,
}

impl Certificate {
    /// Days before expiry at which renewal stops being routine.
    ///
    /// Thirty is the convention and it earns its place: it is longer than any
    /// renewal process and short enough that nobody ignores it for a quarter.
    pub const WARN_DAYS: u64 = 30;

    pub fn days_remaining(&self, now: u64) -> i64 {
        (self.not_after as i64 - now as i64) / 86_400
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.not_after <= now
    }

    pub fn needs_renewal(&self, now: u64) -> bool {
        self.days_remaining(now) <= Self::WARN_DAYS as i64
    }
}

/// A file whose contents the site depends on.
///
/// The interesting property is not that a change is detected — plenty of tools
/// do that — but that the change is appended to the operation chain, so a
/// configuration edit becomes part of the same tamper-evident record as
/// everything else the machine did. A change nobody can deny is more useful
/// than one somebody noticed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watched {
    pub path: String,
    pub digest: String,
    pub modified: u64,
}

/// What changed between two observations of the watched set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Drift {
    Changed { path: String, from: String, to: String },
    Appeared { path: String },
    Vanished { path: String },
}

impl Drift {
    pub fn path(&self) -> &str {
        match self {
            Drift::Changed { path, .. } | Drift::Appeared { path } | Drift::Vanished { path } => path,
        }
    }
}

/// Compare two observations of the watched set.
pub fn drift(before: &[Watched], after: &[Watched]) -> Vec<Drift> {
    let mut out = Vec::new();

    for a in after {
        match before.iter().find(|b| b.path == a.path) {
            Some(b) if b.digest != a.digest => out.push(Drift::Changed {
                path: a.path.clone(),
                from: b.digest.clone(),
                to: a.digest.clone(),
            }),
            Some(_) => {}
            None => out.push(Drift::Appeared { path: a.path.clone() }),
        }
    }
    for b in before {
        if !after.iter().any(|a| a.path == b.path) {
            out.push(Drift::Vanished { path: b.path.clone() });
        }
    }
    out.sort_by(|x, y| x.path().cmp(y.path()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_786_838_400;
    const GIB: u64 = 1024 * 1024 * 1024;

    fn backup(modified: u64, bytes: u64) -> Backup {
        Backup {
            path: "/var/backups/orchid/mainnet.sql".into(),
            bytes,
            modified,
            digest: None,
        }
    }

    fn nightly() -> Expectation {
        Expectation {
            interval_secs: 86_400,
            grace_multiple: 2,
            min_bytes: 100 * 1024 * 1024,
        }
    }

    #[test]
    fn nothing_here_ever_claims_a_backup_would_restore() {
        // The most expensive lie a monitoring system can tell. Anything
        // tempted to conclude otherwise has to call something that says no.
        for v in [
            Verdict::PresentAndIntact,
            Verdict::Stale { age_secs: 1 },
            Verdict::Missing,
        ] {
            assert!(!v.proves_restorable());
        }
    }

    #[test]
    fn a_recent_full_sized_backup_is_present_and_intact() {
        let b = backup(NOW - 3600, GIB);
        assert_eq!(judge(Some(&b), &nightly(), NOW, None), Verdict::PresentAndIntact);
    }

    #[test]
    fn a_missing_backup_is_not_confused_with_a_stale_one() {
        assert_eq!(judge(None, &nightly(), NOW, None), Verdict::Missing);
    }

    #[test]
    fn a_nightly_backup_is_not_broken_a_minute_after_its_deadline() {
        // Alarming on the exact interval produces a daily false alarm and
        // trains everyone to ignore it.
        let b = backup(NOW - 86_460, GIB);
        assert_eq!(judge(Some(&b), &nightly(), NOW, None), Verdict::PresentAndIntact);
    }

    #[test]
    fn a_backup_that_missed_a_cycle_is_stale() {
        let b = backup(NOW - 3 * 86_400, GIB);
        assert!(matches!(judge(Some(&b), &nightly(), NOW, None), Verdict::Stale { .. }));
    }

    #[test]
    fn a_truncated_backup_is_caught_even_though_it_is_recent() {
        // What a backup looks like when the thing producing it died partway
        // through — and it passes every freshness check.
        let b = backup(NOW - 60, 4096);
        assert!(matches!(
            judge(Some(&b), &nightly(), NOW, None),
            Verdict::Truncated { .. }
        ));
    }

    #[test]
    fn an_altered_backup_outranks_a_stale_one() {
        // Changing under us is a different and more alarming problem than
        // being old, and reporting the milder one would bury it.
        let mut b = backup(NOW - 30 * 86_400, GIB);
        b.digest = Some("abc".into());
        assert_eq!(judge(Some(&b), &nightly(), NOW, Some("def")), Verdict::Altered);
    }

    #[test]
    fn a_certificate_with_months_left_needs_nothing() {
        let c = Certificate {
            path: "/etc/ssl/x.pem".into(),
            subject: "CN=example".into(),
            not_after: NOW + 120 * 86_400,
        };
        assert!(!c.needs_renewal(NOW));
        assert!(!c.is_expired(NOW));
        assert_eq!(c.days_remaining(NOW), 120);
    }

    #[test]
    fn a_certificate_inside_the_renewal_window_is_flagged_before_it_expires() {
        let c = Certificate {
            path: "/etc/ssl/x.pem".into(),
            subject: "CN=example".into(),
            not_after: NOW + 10 * 86_400,
        };
        assert!(c.needs_renewal(NOW));
        assert!(!c.is_expired(NOW), "and it has not expired yet");
    }

    #[test]
    fn an_expired_certificate_reports_negative_days_rather_than_wrapping() {
        // Unsigned arithmetic here would report an expired certificate as
        // having fifty thousand years left.
        let c = Certificate {
            path: "/etc/ssl/x.pem".into(),
            subject: "CN=example".into(),
            not_after: NOW - 5 * 86_400,
        };
        assert!(c.is_expired(NOW));
        assert_eq!(c.days_remaining(NOW), -5);
    }

    fn watched(path: &str, digest: &str) -> Watched {
        Watched {
            path: path.into(),
            digest: digest.into(),
            modified: NOW,
        }
    }

    #[test]
    fn an_unchanged_configuration_produces_no_drift() {
        let set = vec![watched("/etc/furcate/env", "aaa")];
        assert!(drift(&set, &set).is_empty());
    }

    #[test]
    fn an_edited_file_is_reported_with_both_digests() {
        // Both, so the change is provable rather than merely asserted.
        let before = vec![watched("/etc/furcate/env", "aaa")];
        let after = vec![watched("/etc/furcate/env", "bbb")];
        let d = drift(&before, &after);
        assert_eq!(
            d[0],
            Drift::Changed {
                path: "/etc/furcate/env".into(),
                from: "aaa".into(),
                to: "bbb".into()
            }
        );
    }

    #[test]
    fn a_deleted_file_is_as_important_as_a_changed_one() {
        // A unit override that vanished changes behaviour exactly as much as
        // one that was edited, and is easier to miss.
        let before = vec![watched("/etc/furcate/workloads.env", "aaa")];
        let d = drift(&before, &[]);
        assert_eq!(d[0], Drift::Vanished { path: "/etc/furcate/workloads.env".into() });
    }

    #[test]
    fn a_new_file_in_the_watched_set_is_reported() {
        let after = vec![watched("/etc/furcate/new.env", "aaa")];
        assert_eq!(drift(&[], &after)[0], Drift::Appeared { path: "/etc/furcate/new.env".into() });
    }
}
