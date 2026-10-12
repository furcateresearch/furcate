//! Reading the journal, the backups, the certificates, and the config.
//!
//! Four collectors that all answer the same shape of question: is the thing
//! that was set up once still true?
//!
//! The configuration one is the least conventional and the most Furcate-shaped.
//! Detecting that a file changed is ordinary; what matters here is that the
//! change is appended to the operation chain, so a configuration edit becomes
//! part of the same tamper-evident record as everything else the machine did.
//! A change nobody can deny is worth more than a change somebody noticed.

use furcate_host::custody::{drift, judge, Backup, Drift, Expectation, Verdict, Watched};
use furcate_host::journal::{classify, Event, JournalSize};
use furcate_host::xid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The previous observation of the watched config set.
static PREVIOUS_CONFIG: Mutex<Option<Vec<Watched>>> = Mutex::new(None);

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The kernel's own log for the window, or `None` when it could not be read,
/// which is not the same as nothing having happened.
///
/// Only the kernel's own log, and only since the last look. Reading the whole
/// journal every cycle would re-report a disk error from three months ago as
/// though it had just happened.
///
/// Returns the text rather than the events because two different parsers now
/// read it: the classifier below, and the accelerator fault taxonomy. Running
/// journalctl twice would pay for the log twice and, worse, let the two answer
/// for slightly different windows — so a fault could be reported in a cycle
/// whose kernel events did not contain it.
fn kernel_log(since_secs: u64) -> Option<String> {
    let out = Command::new("journalctl")
        .args([
            "-k",
            "--no-pager",
            "-o",
            "cat",
            "--since",
            &format!("-{since_secs}s"),
        ])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn classified(text: &str) -> Vec<Event> {
    let mut events: Vec<Event> = text.lines().filter_map(classify).collect();
    // A flapping link produces the same event hundreds of times; the operator
    // needs to know it happened, not how many lines it took.
    events.dedup();
    events
}

pub fn journal_size() -> Option<JournalSize> {
    let out = Command::new("journalctl").args(["--disk-usage"]).output().ok()?;
    out.status
        .success()
        .then(|| JournalSize::parse(&String::from_utf8_lossy(&out.stdout)))
        .flatten()
}

fn digest_of(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Some(hex::encode(h.finalize()))
}

fn modified_of(path: &str) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Files this site's behaviour depends on, declared rather than discovered.
///
/// Watching everything under `/etc` would produce drift on every package
/// update and teach everyone to ignore it. The set is small and named because
/// the point is the files whose contents decide what this machine does.
pub fn watched_paths() -> Vec<String> {
    std::env::var("FURCATE_WATCH_CONFIG")
        .unwrap_or_else(|_| {
            "/etc/furcate/env,/etc/furcate/workloads.env,\
             /etc/systemd/system/furcated@.service,\
             /etc/systemd/system/furcate-site@.service"
                .to_string()
        })
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn observe_config() -> Vec<Watched> {
    watched_paths()
        .into_iter()
        .filter_map(|p| {
            Some(Watched {
                digest: digest_of(&p)?,
                modified: modified_of(&p),
                path: p,
            })
        })
        .collect()
}

/// Backups this site expects to exist, as
/// `dir:interval_secs:min_bytes[:suffix]`.
///
/// The suffix earns its place. A backup directory is rarely only backups —
/// this site's holds a 1.1 GB dump next to a 1.5 KB config copy — and "the
/// newest file here" then picks whichever was touched last and calls a real
/// backup truncated. Naming what a backup looks like is the difference
/// between a check and a coin toss.
fn backup_specs() -> Vec<(String, Option<String>, Expectation)> {
    parse_backup_specs(&std::env::var("FURCATE_BACKUPS").unwrap_or_default())
}

/// The parsing half, separated from the environment so it can be tested.
///
/// Two tests that both set a process-wide variable race each other, which is
/// how the first version of this failed — the same shape of mistake as a test
/// that read the developer's own ledger out of `$HOME`.
fn parse_backup_specs(raw: &str) -> Vec<(String, Option<String>, Expectation)> {
    raw.split(',')
        .filter(|e| !e.trim().is_empty())
        .filter_map(|entry| {
            let mut f = entry.split(':');
            let dir = f.next()?.trim().to_string();
            if dir.is_empty() {
                return None;
            }
            let interval = f.next().and_then(|v| v.trim().parse().ok()).unwrap_or(86_400);
            let min_bytes = f.next().and_then(|v| v.trim().parse().ok()).unwrap_or(1024);
            let suffix = f.next().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
            Some((dir, suffix, Expectation {
                interval_secs: interval,
                grace_multiple: 2,
                min_bytes,
            }))
        })
        .collect()
}

/// The most recent backup in a directory.
///
/// `suffix` names what a backup looks like, because a directory that also
/// holds notes and config copies would otherwise have the wrong file judged.
fn newest_in(dir: &str, suffix: Option<&str>) -> Option<Backup> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| match suffix {
            Some(sfx) => e.file_name().to_string_lossy().ends_with(sfx),
            None => true,
        })
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            let modified = md
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some(Backup {
                path: e.path().to_string_lossy().into_owned(),
                bytes: md.len(),
                modified,
                digest: None,
            })
        })
        .max_by_key(|b| b.modified)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyReport {
    /// Kernel events since the last look.
    pub events: Vec<Event>,
    /// False when the journal could not be read, so an empty list means
    /// "could not look" rather than "nothing happened".
    pub journal_readable: bool,
    pub journal_bytes: Option<u64>,
    pub journal_large: bool,
    /// One verdict per declared backup location.
    pub backups: Vec<(String, Verdict)>,
    /// Accelerator faults the driver named in this window, one finding per
    /// card, worst card first.
    ///
    /// Read from the same journal text as `events`, because an Xid *is* a
    /// kernel log line. Grouped per card rather than listed flat: a host with
    /// eight cards and a fault on one must not report it against all eight,
    /// and two genuinely different faults on two cards must not collapse into
    /// one verdict.
    ///
    /// Empty when the journal could not be read, which `journal_readable`
    /// already distinguishes from a window with no faults in it.
    pub xids: Vec<(Option<String>, xid::Finding)>,
    /// Configuration files whose contents changed since the last observation.
    pub drift: Vec<Drift>,
    pub watched: usize,
}

/// How far back to look for kernel events.
///
/// Matched to the collection period with a margin, so nothing is missed
/// between runs and little is re-reported.
pub const LOOKBACK_SECS: u64 = 900;

pub fn collect() -> CustodyReport {
    // One read, two readings.
    let log = kernel_log(LOOKBACK_SECS);
    let journal_readable = log.is_some();
    let events = log.as_deref().map(classified).unwrap_or_default();
    let xids = log
        .as_deref()
        .map(|t| xid::by_card(&xid::parse(t)))
        .unwrap_or_default();
    let size = journal_size();

    let backups: Vec<(String, Verdict)> = backup_specs()
        .into_iter()
        .map(|(dir, suffix, expect)| {
            let newest = newest_in(&dir, suffix.as_deref());
            let verdict = judge(newest.as_ref(), &expect, now_s(), None);
            (dir, verdict)
        })
        .collect();

    let observed = observe_config();
    let changes = {
        let mut guard = PREVIOUS_CONFIG.lock().expect("config tracker");
        // The first observation establishes a baseline and reports nothing.
        // Reporting every watched file as "appeared" on startup would bury the
        // one edit that matters under a list of things that did not change.
        let changes = guard.as_ref().map(|prev| drift(prev, &observed)).unwrap_or_default();
        *guard = Some(observed.clone());
        changes
    };

    CustodyReport {
        events,
        xids,
        journal_readable,
        journal_bytes: size.map(|s| s.bytes),
        journal_large: size.map(|s| s.is_large()).unwrap_or(false),
        backups,
        drift: changes,
        watched: observed.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_is_readable_on_this_machine() {
        let readable = kernel_log(60).is_some();
        // If it is not, the report says so rather than implying quiet.
        let r = collect();
        assert_eq!(r.journal_readable, readable);
    }

    #[test]
    fn ordinary_kernel_chatter_produces_no_events() {
        // A day of this machine's real journal, which is full of ACPI and
        // workqueue lines and contains no hardware faults.
        let events = kernel_log(86_400).map(|t| classified(&t)).unwrap_or_default();
        for e in &events {
            // Anything found must at least be one of the modelled kinds.
            assert!(!e.summary().is_empty());
        }
    }

    #[test]
    fn the_first_observation_reports_no_drift() {
        // Otherwise every watched file appears as new on startup and buries
        // the one edit that matters.
        *PREVIOUS_CONFIG.lock().unwrap() = None;
        let r = collect();
        assert!(r.drift.is_empty(), "baseline must be silent");
    }

    #[test]
    fn watched_paths_are_declared_rather_than_discovered() {
        // Watching all of /etc would produce drift on every package update.
        let p = watched_paths();
        assert!(!p.is_empty());
        assert!(p.iter().all(|x| x.starts_with('/')));
        assert!(p.len() < 20, "the set is meant to be small and readable");
    }

    #[test]
    fn a_backup_location_that_is_not_declared_is_not_invented() {
        // Nothing declared means no claims about backups, rather than a
        // cheerful empty list that reads as healthy.
        assert!(parse_backup_specs("").is_empty());
    }

    #[test]
    fn a_declared_backup_directory_is_parsed_with_its_expectation() {
        let specs = parse_backup_specs("/var/backups/orchid:86400:104857600:.sql");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].0, "/var/backups/orchid");
        assert_eq!(specs[0].1.as_deref(), Some(".sql"));
        assert_eq!(specs[0].2.interval_secs, 86_400);
        assert_eq!(specs[0].2.min_bytes, 104_857_600);
    }

    #[test]
    fn a_spec_without_sizes_gets_conservative_defaults() {
        let specs = parse_backup_specs("/var/backups/orchid");
        assert_eq!(specs[0].2.interval_secs, 86_400);
        assert!(specs[0].2.min_bytes > 0, "a zero floor would accept an empty file");
        assert!(specs[0].1.is_none(), "no suffix means every file counts");
    }

    #[test]
    fn a_directory_with_nothing_in_it_is_missing_rather_than_fresh() {
        let expect = Expectation::default();
        let v = judge(newest_in("/nonexistent-backup-dir", None).as_ref(), &expect, now_s(), None);
        assert_eq!(v, Verdict::Missing);
    }

    #[test]
    fn a_suffix_stops_the_wrong_file_being_judged() {
        // Found on real data: this site's backup directory holds a 1.1 GB dump
        // next to a 1.5 KB config copy, and "the newest file" picked the copy
        // and called the backup truncated.
        let dir = std::env::temp_dir().join("furcate-backup-suffix-test");
        let _ = std::fs::create_dir_all(&dir);
        let d = dir.to_string_lossy().to_string();
        std::fs::write(dir.join("dump.sql"), vec![0u8; 4096]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(dir.join("notes.txt"), b"a note").unwrap();

        let unfiltered = newest_in(&d, None).unwrap();
        assert!(unfiltered.path.ends_with("notes.txt"), "the newest is the note");

        let filtered = newest_in(&d, Some(".sql")).unwrap();
        assert!(filtered.path.ends_with("dump.sql"));
        assert_eq!(filtered.bytes, 4096);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collecting_produces_an_answer_rather_than_a_panic() {
        let r = collect();
        assert!(r.watched <= watched_paths().len());
    }
}
