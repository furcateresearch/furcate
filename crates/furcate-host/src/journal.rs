//! Mining the journal for the faults this system already models.
//!
//! Deliberately not log shipping. Collecting and forwarding logs is a solved
//! problem with good tools, and duplicating them here would be work with no
//! return.
//!
//! What is *not* solved is that Furcate already has signal types for
//! degraded disks, memory errors, thermal events and power faults, and until
//! now it only learned about them from SMART attributes and a thermal zone.
//! The kernel has been reporting the rest into the journal the whole time —
//! I/O errors, machine-check exceptions, OOM kills, filesystem remounts,
//! link flaps, TPM failures — and nothing was reading it.
//!
//! So this closes a loop rather than opening a new one: journal lines become
//! the same signals the health pipeline already knows how to act on.
//!
//! ## What it refuses to do
//!
//! It does not interpret application logs. A pattern that matches an error in
//! one service is a routine debug line in another, and a system that guessed
//! would spend its life crying wolf about somebody else's software. Only
//! **kernel** messages are read, because the kernel has one vocabulary and it
//! is talking about the hardware this system is responsible for.

use serde::{Deserialize, Serialize};

/// A hardware-relevant event recovered from the kernel log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// The kernel killed something to reclaim memory.
    ///
    /// Distinct from a container hitting its own limit, which cgroup
    /// accounting already reports: this is the machine as a whole running out.
    OomKill { victim: String },
    /// A block device reported an I/O error. Almost always the beginning of a
    /// disk failure rather than a transient.
    IoError { device: String },
    /// A filesystem was remounted read-only, which is what ext4 does when it
    /// finds corruption. Writes have already stopped.
    FilesystemReadOnly { device: String },
    /// A machine-check exception: the CPU or memory controller reported a
    /// hardware fault.
    MachineCheck { detail: String },
    /// Correctable memory errors, which precede uncorrectable ones.
    MemoryError { count: u64 },
    /// The TPM returned an error. On this site that has happened, and it made
    /// every sealed secret temporarily unreachable.
    TpmError { code: String },
    /// A network link went up or down.
    LinkChange { interface: String, up: bool },
    /// Thermal throttling engaged.
    ThermalThrottle { detail: String },
}

impl Event {
    /// Whether this warrants taking the node out of scheduling.
    ///
    /// Deliberately narrow. A link flap and a throttle are worth recording and
    /// are not reasons to stop using a machine; a read-only filesystem or a
    /// machine check means the hardware has already failed at something.
    pub fn warrants_cordon(&self) -> bool {
        matches!(
            self,
            Event::FilesystemReadOnly { .. } | Event::MachineCheck { .. } | Event::IoError { .. }
        )
    }

    /// A short description for an operator.
    pub fn summary(&self) -> String {
        match self {
            Event::OomKill { victim } => format!("kernel killed {victim} to reclaim memory"),
            Event::IoError { device } => format!("I/O error on {device}"),
            Event::FilesystemReadOnly { device } => {
                format!("{device} was remounted read-only; writes have stopped")
            }
            Event::MachineCheck { detail } => format!("machine check: {detail}"),
            Event::MemoryError { count } => format!("{count} correctable memory errors"),
            Event::TpmError { code } => format!("TPM error {code}"),
            Event::LinkChange { interface, up } => {
                format!("{interface} link {}", if *up { "up" } else { "down" })
            }
            Event::ThermalThrottle { detail } => format!("thermal throttling: {detail}"),
        }
    }
}

fn word_after(line: &str, needle: &str) -> Option<String> {
    let rest = line.split(needle).nth(1)?;
    rest.split_whitespace()
        .next()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '-' && c != '_')
            .to_string())
        .filter(|w| !w.is_empty())
}

/// Recognise one kernel line.
///
/// Returns nothing for the overwhelming majority of lines, which is the point:
/// this is a narrow recogniser over a known vocabulary, not a classifier. A
/// line it does not recognise is left alone rather than guessed at.
pub fn classify(line: &str) -> Option<Event> {
    let l = line.to_lowercase();

    if l.contains("out of memory: killed process") || l.contains("oom-kill:") {
        let victim = word_after(&l, "(")
            .or_else(|| word_after(&l, "process "))
            .unwrap_or_else(|| "unknown".into());
        return Some(Event::OomKill { victim });
    }
    // ext4 says "Remounting filesystem read-only"; the device is on the line.
    if l.contains("remounting filesystem read-only") || l.contains("re-mounted read-only") {
        return Some(Event::FilesystemReadOnly {
            device: word_after(&l, "ext4-fs (").unwrap_or_else(|| "unknown".into()),
        });
    }
    if l.contains("i/o error") || l.contains("critical medium error") {
        return Some(Event::IoError {
            device: word_after(&l, "dev ")
                .or_else(|| word_after(&l, "on device "))
                .unwrap_or_else(|| "unknown".into()),
        });
    }
    if l.contains("machine check") || l.contains("mce:") || l.contains("hardware error") {
        return Some(Event::MachineCheck {
            detail: line.chars().take(120).collect(),
        });
    }
    if l.contains("corrected error") || l.contains("edac") && l.contains("ce ") {
        return Some(Event::MemoryError { count: 1 });
    }
    if l.contains("tpm") && (l.contains("error") || l.contains("tpm_try_transmit")) {
        return Some(Event::TpmError {
            code: word_after(&l, "error ").unwrap_or_else(|| "unspecified".into()),
        });
    }
    if l.contains("link is not ready") || l.contains("link down") {
        return Some(Event::LinkChange {
            interface: word_after(&l, ": ").unwrap_or_else(|| "unknown".into()),
            up: false,
        });
    }
    if l.contains("link becomes ready") || (l.contains("link up") && l.contains("mbps")) {
        return Some(Event::LinkChange {
            interface: word_after(&l, ": ").unwrap_or_else(|| "unknown".into()),
            up: true,
        });
    }
    // The kernel's own throttle message does not contain the word "thermal" —
    // it is "Core temperature above threshold, cpu clock throttled" — so
    // matching on that word alone misses the event this exists to catch.
    if l.contains("temperature above threshold")
        || l.contains("cpu clock throttled")
        || (l.contains("thermal") && l.contains("critical temperature"))
    {
        return Some(Event::ThermalThrottle {
            detail: line.chars().take(120).collect(),
        });
    }
    None
}

/// What the journal itself is costing.
///
/// Worth its own field because a journal that has grown to gigabytes is a
/// common cause of a full root filesystem, and it is invisible in a
/// per-service view — the space belongs to systemd, not to whatever produced
/// the lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalSize {
    pub bytes: u64,
}

impl JournalSize {
    /// Size above which the journal is worth an operator's attention on a
    /// site of this scale.
    pub const LARGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

    pub fn is_large(&self) -> bool {
        self.bytes >= Self::LARGE_BYTES
    }

    /// Parse `journalctl --disk-usage`.
    ///
    /// Format: "Archived and active journals take up 773.4M in the file system."
    pub fn parse(text: &str) -> Option<Self> {
        let token = text
            .split_whitespace()
            .find(|w| w.ends_with('M') || w.ends_with('G') || w.ends_with('K'))?;
        let (num, unit) = token.split_at(token.len() - 1);
        let n: f64 = num.parse().ok()?;
        let mult = match unit {
            "K" => 1024.0,
            "M" => 1024.0 * 1024.0,
            "G" => 1024.0 * 1024.0 * 1024.0,
            _ => return None,
        };
        Some(JournalSize {
            bytes: (n * mult) as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_line_is_not_classified_as_anything() {
        // The overwhelming majority, and guessing at them is how a monitor
        // spends its life crying wolf.
        for line in [
            "ENERGY_PERF_BIAS: Set to 'normal', was 'performance'",
            "kauditd_printk_skb: 199 callbacks suppressed",
            "workqueue: drm_fb_helper_damage_work hogged CPU for >10000us",
            "power_meter ACPI000D:01: Ignoring unsafe software power cap!",
        ] {
            assert_eq!(classify(line), None, "misread: {line}");
        }
    }

    #[test]
    fn an_oom_kill_is_recognised_and_names_the_victim() {
        let e = classify("Out of memory: Killed process 1234 (java) total-vm:8g").unwrap();
        assert!(matches!(e, Event::OomKill { .. }));
        assert!(e.summary().contains("java"));
    }

    #[test]
    fn a_read_only_remount_is_the_most_serious_thing_here() {
        // Writes have already stopped by the time this line appears.
        let e = classify("EXT4-fs (nvme0n1p2): Remounting filesystem read-only").unwrap();
        assert!(matches!(e, Event::FilesystemReadOnly { .. }));
        assert!(e.warrants_cordon());
        assert!(e.summary().contains("writes have stopped"));
    }

    #[test]
    fn an_io_error_cordons_because_it_is_rarely_transient() {
        let e = classify("blk_update_request: I/O error, dev sda, sector 12345").unwrap();
        assert!(matches!(e, Event::IoError { .. }));
        assert!(e.warrants_cordon());
    }

    #[test]
    fn a_machine_check_cordons() {
        let e = classify("mce: [Hardware Error]: CPU 3: Machine Check Exception").unwrap();
        assert!(matches!(e, Event::MachineCheck { .. }));
        assert!(e.warrants_cordon());
    }

    #[test]
    fn a_link_flap_is_recorded_without_taking_the_node_out_of_service() {
        // Worth knowing, not worth losing a machine over.
        let down = classify("enp0s25: Link is not ready").unwrap();
        assert!(matches!(down, Event::LinkChange { up: false, .. }));
        assert!(!down.warrants_cordon());
    }

    #[test]
    fn a_tpm_error_is_recognised_because_it_has_happened_here() {
        // It made every sealed secret temporarily unreachable.
        let e = classify("tpm tpm0: A TPM error (257) occurred attempting to read a pcr value")
            .unwrap();
        assert!(matches!(e, Event::TpmError { .. }));
    }

    #[test]
    fn thermal_throttling_is_recognised() {
        let e = classify("CPU2: Core temperature above threshold, cpu clock throttled").unwrap();
        assert!(matches!(e, Event::ThermalThrottle { .. }));
    }

    #[test]
    fn journal_size_parses_the_real_output() {
        let s = JournalSize::parse(
            "Archived and active journals take up 773.4M in the file system.",
        )
        .unwrap();
        assert!(s.bytes > 700 * 1024 * 1024 && s.bytes < 800 * 1024 * 1024);
        assert!(!s.is_large());
    }

    #[test]
    fn a_multi_gigabyte_journal_is_flagged() {
        // A common cause of a full root filesystem, and invisible per-service
        // because the space belongs to systemd.
        let s = JournalSize::parse("Archived and active journals take up 6.2G in the file system.")
            .unwrap();
        assert!(s.is_large());
    }

    #[test]
    fn unparseable_journal_output_yields_nothing_rather_than_zero() {
        // Zero would read as a healthy empty journal.
        assert!(JournalSize::parse("").is_none());
        assert!(JournalSize::parse("no numbers here").is_none());
    }
}
