//! What the card says went wrong, in its own words.
//!
//! [`crate::accelerator`] asks a card for its counters and watches them move.
//! That catches a card *becoming* unwell. It cannot catch the other half, which
//! is the driver announcing that something already went wrong a moment ago:
//!
//! ```text
//! NVRM: Xid (PCI:0000:81:00): 94, pid=31337, name=python3, Contained: ECC error
//! ```
//!
//! An Xid is the closest thing an accelerator has to a fault code. It is the
//! one place the hardware, the driver and the workload all get to name a
//! failure at the moment it happens, and it is thrown away by every layer above
//! unless something reads the kernel log for it.
//!
//! ## The whole value is in who is to blame
//!
//! Reporting "Xid 31" as an accelerator fault is worse than reporting nothing.
//! Xid 31 is a memory page fault: a process used an illegal address. The card
//! is fine, the driver is fine, and the person who gets sent to swap the card
//! will trust the next alert less — the same argument [`crate::accelerator`]
//! makes for separating "actionable" from "replace the card".
//!
//! So every code this module knows carries a [`Blame`] and a [`Remedy`], and
//! the codes it does not know are [`Blame::Unknown`] rather than a guess. The
//! distinction that matters most is *contained* versus *uncontained*: an Xid 94
//! killed one process and the node keeps working, while an Xid 95 did not, and
//! everything on that card is now suspect.
//!
//! ## Absence is not health
//!
//! A machine with no accelerator, no NVIDIA driver, or no readable kernel log
//! produces no events, and that is reported as no events — never as a clean
//! bill. Same discipline as the `Option` fields next door: `None` means the
//! question was not answered, and a fleet that cannot tell those apart will
//! eventually call an unmonitored node healthy.

use serde::{Deserialize, Serialize};

/// One Xid as the driver reported it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The Xid number itself.
    pub code: u16,
    /// PCI address the driver named, where the line carried one. This is how an
    /// event is tied to a card on a host with more than one.
    pub pci: Option<String>,
    /// The process the driver blamed, where it named one.
    pub pid: Option<u32>,
    /// The process name, where the line carried one. Worth keeping even though
    /// the pid is more precise: the pid is gone by the time anybody reads this.
    pub name: Option<String>,
    /// The rest of the line, so an operator can read what the driver actually
    /// said rather than only this module's opinion of it.
    pub detail: Option<String>,
}

/// Who the evidence implicates.
///
/// Deliberately not a severity. Severity collapses "this card is dying" and
/// "this program has a bug" onto one axis, and they lead to opposite actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blame {
    /// The silicon or its memory. Somebody may need to touch the machine.
    Card,
    /// What was running. The card did what it was told and the instruction was
    /// illegal.
    Workload,
    /// The link between cards, or between a card and the host.
    Fabric,
    /// The driver, its firmware, or the host around it.
    System,
    /// A code this module does not have a documented meaning for. Reported so
    /// an operator can look it up; never quietly folded into one of the above.
    Unknown,
}

/// What acting on this event actually looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Remedy {
    /// Nothing to do. The event is informational.
    Watch,
    /// The job that caused it should be restarted or fixed. The node is fine.
    RestartWorkload,
    /// The device needs a reset, which means draining it first. A scheduling
    /// decision, not an emergency.
    ResetDevice,
    /// Stop placing work on this node until somebody has looked at it.
    DrainNode,
    /// The card is the fault and swapping it is the likely fix.
    ReplaceCard,
}

impl Blame {
    /// The name this carries in a report, identical to its serialised form so
    /// a log line and a JSON field never disagree about what happened.
    pub fn as_str(&self) -> &'static str {
        match self {
            Blame::Card => "card",
            Blame::Workload => "workload",
            Blame::Fabric => "fabric",
            Blame::System => "system",
            Blame::Unknown => "unknown",
        }
    }
}

impl Remedy {
    /// As [`Blame::as_str`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Remedy::Watch => "watch",
            Remedy::RestartWorkload => "restart_workload",
            Remedy::ResetDevice => "reset_device",
            Remedy::DrainNode => "drain_node",
            Remedy::ReplaceCard => "replace_card",
        }
    }
}

/// What one Xid code means.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Class {
    pub code: u16,
    pub blame: Blame,
    pub remedy: Remedy,
    /// Whether the failure was contained to the process that caused it.
    ///
    /// `Some(true)` is the case that lets a fleet keep a node in service after
    /// a memory error; `Some(false)` is the case that must not. `None` means
    /// containment is not a meaningful question for this code.
    pub contained: Option<bool>,
    /// One line, in the operator's language rather than the driver's.
    ///
    /// Owned rather than borrowed so a `Class` survives serialisation intact:
    /// this line is the part a person actually reads, and it has to reach
    /// whoever is looking at the JSON rather than only whoever is holding the
    /// struct. Same reason [`crate::accelerator::Verdict`] owns its `reason`.
    pub summary: String,
}

/// The documented meaning of an Xid, where NVIDIA publishes one.
///
/// The table is deliberately short. Every entry here is a code whose meaning
/// changes what an operator should do; codes that only a driver engineer can
/// act on are better served by [`Blame::Unknown`] and the raw line than by a
/// paraphrase that reads as authoritative.
pub fn classify(code: u16) -> Class {
    let (blame, remedy, contained, summary) = match code {
        // --- the workload's fault. The card is well. ---
        13 => (Blame::Workload, Remedy::RestartWorkload, None,
               "graphics engine exception — usually an illegal instruction or address in the job"),
        31 => (Blame::Workload, Remedy::RestartWorkload, None,
               "memory page fault — the job used an address it does not own"),
        32 => (Blame::Workload, Remedy::RestartWorkload, None,
               "corrupted push buffer stream"),
        43 => (Blame::Workload, Remedy::RestartWorkload, None,
               "the job was stopped and its channel reset"),
        45 => (Blame::Workload, Remedy::RestartWorkload, None,
               "preemptive channel cleanup — usually the aftermath of another fault"),
        69 => (Blame::Workload, Remedy::RestartWorkload, None,
               "graphics engine class error"),

        // --- memory. The card is implicated. ---
        48 => (Blame::Card, Remedy::DrainNode, Some(false),
               "double-bit ECC error — a result has already been wrong"),
        63 => (Blame::Card, Remedy::ResetDevice, Some(true),
               "the card recorded a page retirement or row remap — a repair it must reset to apply"),
        64 => (Blame::Card, Remedy::ReplaceCard, Some(false),
               "the card tried to retire memory and failed"),
        92 => (Blame::Card, Remedy::Watch, Some(true),
               "high rate of corrected single-bit errors"),
        94 => (Blame::Card, Remedy::RestartWorkload, Some(true),
               "ECC error contained to one process — that process is lost, the card is not"),
        95 => (Blame::Card, Remedy::DrainNode, Some(false),
               "ECC error NOT contained — everything on this card is suspect"),

        // --- the link. A different repair from replacing the card. ---
        74 => (Blame::Fabric, Remedy::DrainNode, Some(false),
               "NVLink error — the link between cards, not the silicon"),
        79 => (Blame::Card, Remedy::DrainNode, Some(false),
               "the card fell off the bus — it stopped answering entirely"),

        // --- driver and firmware. ---
        61 | 62 => (Blame::System, Remedy::DrainNode, None,
               "the card's internal micro-controller halted"),
        109 => (Blame::System, Remedy::ResetDevice, None,
               "context switch timeout"),
        119 | 120 => (Blame::System, Remedy::ResetDevice, None,
               "GSP firmware stopped answering the driver"),

        _ => (Blame::Unknown, Remedy::Watch, None,
              "an Xid this build has no documented meaning for — read the driver's own line"),
    };
    Class { code, blame, remedy, contained, summary: summary.to_string() }
}

impl Class {
    /// Whether this should reach a human.
    pub fn is_actionable(&self) -> bool {
        !matches!(self.remedy, Remedy::Watch)
    }

    /// Whether work should stop being placed here.
    ///
    /// The same question [`crate::accelerator::Verdict::should_drain`] answers,
    /// so the two can be folded together by whatever is deciding placement.
    pub fn should_drain(&self) -> bool {
        matches!(self.remedy, Remedy::DrainNode | Remedy::ReplaceCard)
            || self.contained == Some(false)
    }

    /// Whether swapping the card is the likely remedy.
    pub fn implicates_the_card(&self) -> bool {
        matches!(self.blame, Blame::Card) && matches!(self.remedy, Remedy::ReplaceCard | Remedy::DrainNode)
    }
}

/// What a run of events adds up to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The event that decided the verdict.
    pub worst: Event,
    /// Its meaning.
    pub class: Class,
    /// How many events were seen in the window, all codes together. A single
    /// Xid 31 is a bug report; two hundred of them is a different conversation.
    pub total: usize,
    /// How many carried the same code as `worst`.
    pub repeats: usize,
}

/// The one thing worth saying about a set of events.
///
/// Returns `None` for an empty set — which is "nothing was reported", not
/// "nothing is wrong". The caller knows whether it managed to read a log.
pub fn assess(events: &[Event]) -> Option<Finding> {
    let worst = events.iter().max_by_key(|e| rank(classify(e.code).remedy))?;
    let class = classify(worst.code);
    let repeats = events.iter().filter(|e| e.code == worst.code).count();
    Some(Finding { worst: worst.clone(), class, total: events.len(), repeats })
}

/// Order remedies by how much they interrupt. Used only to pick the event that
/// speaks for the set.
fn rank(r: Remedy) -> u8 {
    match r {
        Remedy::Watch => 0,
        Remedy::RestartWorkload => 1,
        Remedy::ResetDevice => 2,
        Remedy::DrainNode => 3,
        Remedy::ReplaceCard => 4,
    }
}

/// Read Xids out of kernel log text (`dmesg`, `journalctl -k`).
///
/// Tolerant by construction: the line format has changed across driver
/// generations and carries different trailing fields on different cards, so
/// this locks onto `Xid` and the number after it and treats everything else as
/// optional. A parser that demanded the full shape would silently return
/// nothing on the next driver release, which is the worst possible failure for
/// something whose job is noticing faults.
pub fn parse(text: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(pos) = line.find("Xid") else { continue };
        let rest = &line[pos + 3..];

        // PCI address, where the line has one: "(PCI:0000:81:00)".
        let pci = rest
            .split_once("PCI:")
            .and_then(|(_, r)| r.split(')').next())
            .map(|s| s.trim().to_string());

        // The code is the first number after the closing paren, or after "Xid"
        // when there is no paren at all.
        let after = rest.split_once(')').map(|(_, r)| r).unwrap_or(rest);
        let Some(code) = first_number(after) else { continue };

        let pid = field(after, "pid=").and_then(|s| s.parse().ok());
        let name = field(after, "name=");
        let detail = {
            let d = after.trim_start_matches(|c: char| c.is_ascii_digit() || matches!(c, ',' | ' ' | ':'));
            (!d.trim().is_empty()).then(|| d.trim().to_string())
        };

        out.push(Event { code, pci, pid, name, detail });
    }
    out
}

/// Reduce a PCI address to a form both sides of this join agree on.
///
/// The driver and the vendor tool do not spell the same address the same way,
/// and nothing announces it — the strings simply never compare equal, so every
/// fault silently fails to attach to a card and the whole taxonomy reports
/// faults belonging to nobody:
///
/// ```text
/// nvidia-smi  pci.bus_id   00000000:81:00.0     8-digit domain, function suffix
/// driver      Xid (PCI:    0000:81:00           4-digit domain, no function
/// ```
///
/// So both are reduced to `domain:bus:device` with a four-digit domain and the
/// function dropped. The function is discarded rather than compared because an
/// accelerator is function 0 and the driver never prints one; keeping it would
/// only reintroduce the mismatch.
///
/// Anything that does not look like a PCI address at all is returned lowercased
/// and otherwise untouched, so an unrecognised format fails to match rather
/// than matching the wrong card.
pub fn pci_key(raw: &str) -> String {
    let raw = raw.trim().trim_start_matches("PCI:").to_ascii_lowercase();
    let parts: Vec<&str> = raw.split(':').collect();
    let (domain, bus, device) = match parts.as_slice() {
        [domain, bus, device] => (*domain, *bus, *device),
        // Some tools omit the domain entirely.
        [bus, device] => ("0000", *bus, *device),
        _ => return raw,
    };
    // The function suffix, where there is one.
    let device = device.split('.').next().unwrap_or(device);
    // Right-align the domain to four digits: 00000000 and 0000 are the same
    // domain written two ways.
    let domain = if domain.len() > 4 { &domain[domain.len() - 4..] } else { domain };
    format!("{domain}:{bus}:{device}")
}

/// Group events by the card the driver named, worst-first.
///
/// A host with eight cards and a fault on one must not report the fault
/// against all eight, and must not collapse two genuinely different faults on
/// two different cards into a single verdict. Events whose line carried no PCI
/// address are grouped under `None` — real, reported, and deliberately not
/// attributed to a card that happens to be the only one present.
pub fn by_card(events: &[Event]) -> Vec<(Option<String>, Finding)> {
    let mut keys: Vec<Option<String>> = Vec::new();
    for e in events {
        let k = e.pci.as_deref().map(pci_key);
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    let mut out: Vec<(Option<String>, Finding)> = keys
        .into_iter()
        .filter_map(|k| {
            let mine: Vec<Event> = events
                .iter()
                .filter(|e| e.pci.as_deref().map(pci_key) == k)
                .cloned()
                .collect();
            assess(&mine).map(|f| (k, f))
        })
        .collect();
    // Worst card first, so a consumer that only looks at the head sees the
    // fault that matters rather than the card that happened to log first.
    out.sort_by(|a, b| {
        rank(b.1.class.remedy)
            .cmp(&rank(a.1.class.remedy))
            .then(b.1.total.cmp(&a.1.total))
    });
    out
}

fn first_number(s: &str) -> Option<u16> {
    let t = s.trim_start_matches([' ', ':', ',']);
    let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn field(s: &str, key: &str) -> Option<String> {
    let (_, r) = s.split_once(key)?;
    let v: String = r
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "\
[12345.678901] NVRM: Xid (PCI:0000:81:00): 94, pid=31337, name=python3, Contained: ECC error
[12399.000000] NVRM: Xid (PCI:0000:81:00): 31, pid=404, name=train.py, Ch 00000008, MMU Fault
kernel: NVRM: Xid (PCI:0000:07:00): 63, Row Remapper: New row marked for remapping
some unrelated kernel line about usb
";

    #[test]
    fn reads_the_fields_the_driver_actually_prints() {
        let ev = parse(REAL);
        assert_eq!(ev.len(), 3, "three Xid lines, one unrelated: {ev:#?}");
        assert_eq!(ev[0].code, 94);
        assert_eq!(ev[0].pci.as_deref(), Some("0000:81:00"));
        assert_eq!(ev[0].pid, Some(31337));
        assert_eq!(ev[0].name.as_deref(), Some("python3"));
        assert_eq!(ev[2].code, 63);
        assert_eq!(ev[2].pid, None, "that line names no process");

        // `detail` is what an operator reads when this module has no opinion,
        // so it must start at the driver's words and not at the punctuation
        // left over from the code we already parsed out.
        assert_eq!(
            ev[2].detail.as_deref(),
            Some("Row Remapper: New row marked for remapping"),
        );
        assert_eq!(
            ev[0].detail.as_deref(),
            Some("pid=31337, name=python3, Contained: ECC error"),
        );
    }

    #[test]
    fn a_job_using_an_illegal_address_does_not_implicate_the_card() {
        // The whole reason this module classifies rather than counts. Sending
        // somebody to swap a card over an Xid 31 teaches them to ignore alerts.
        let c = classify(31);
        assert_eq!(c.blame, Blame::Workload);
        assert!(!c.implicates_the_card());
        assert!(!c.should_drain());
        assert_eq!(c.remedy, Remedy::RestartWorkload);
    }

    #[test]
    fn containment_is_the_distinction_that_decides_whether_a_node_keeps_working() {
        let contained = classify(94);
        let uncontained = classify(95);
        assert_eq!(contained.contained, Some(true));
        assert_eq!(uncontained.contained, Some(false));
        // 94 loses a process; 95 loses the card.
        assert!(!contained.should_drain(), "a contained error must not drain the node");
        assert!(uncontained.should_drain(), "an uncontained error must");
    }

    #[test]
    fn a_failed_remap_says_replace_and_a_recorded_one_says_reset() {
        assert_eq!(classify(64).remedy, Remedy::ReplaceCard);
        assert_eq!(classify(63).remedy, Remedy::ResetDevice);
        // Matches accelerator.rs, which already treats a failed remap as the
        // condition to replace on and a pending one as a scheduling decision.
    }

    #[test]
    fn an_unknown_code_says_so_rather_than_guessing() {
        let c = classify(60001);
        assert_eq!(c.blame, Blame::Unknown);
        assert!(!c.is_actionable(), "an unknown code must not page anyone");
        assert!(c.summary.contains("no documented meaning"));
    }

    #[test]
    fn nvlink_is_the_fabric_not_the_silicon() {
        // A different repair: cable, connector or switch, not the card.
        let c = classify(74);
        assert_eq!(c.blame, Blame::Fabric);
        assert!(c.should_drain());
        assert!(!c.implicates_the_card(), "do not send anyone to swap a card over a link fault");
    }

    #[test]
    fn the_worst_event_speaks_for_the_set() {
        let ev = parse(REAL);
        let f = assess(&ev).expect("three events");

        // Not the first event, not the highest code, not the loudest-sounding
        // one — the one whose remedy interrupts most. The set is 94
        // (restart the job), 31 (restart the job) and 63 (reset the card),
        // and a reset outranks a restart: an Xid 94 lost one process and the
        // card kept working, while an Xid 63 means the card is running on
        // memory it has already condemned.
        assert_eq!(f.worst.code, 63, "the remedy ladder decides, not order or code: {f:#?}");
        assert_eq!(f.class.remedy, Remedy::ResetDevice);
        assert_eq!(f.total, 3, "every event counted, not just the worst");
        assert_eq!(f.repeats, 1, "only one event carried code 63");
    }

    #[test]
    fn the_set_is_ranked_by_remedy_not_by_code_number() {
        // Guards the trap directly: a low code with a heavy remedy must beat a
        // high code with a light one, or `worst` degenerates into `max(code)`.
        let ev = vec![
            Event { code: 109, ..Default::default() }, // ResetDevice
            Event { code: 48, ..Default::default() },  // DrainNode — lower code, worse
        ];
        let f = assess(&ev).expect("two events");
        assert_eq!(f.worst.code, 48);
        assert_eq!(f.class.remedy, Remedy::DrainNode);
        assert!(f.class.should_drain());
    }

    #[test]
    fn the_two_tools_spell_the_same_address_differently_and_still_join() {
        // The silent failure this exists to prevent: without normalisation the
        // strings never compare equal, every fault fails to attach to a card,
        // and the taxonomy reports faults belonging to nobody.
        assert_eq!(pci_key("00000000:81:00.0"), "0000:81:00", "nvidia-smi form");
        assert_eq!(pci_key("PCI:0000:81:00"), "0000:81:00", "driver form");
        assert_eq!(pci_key("0000:81:00"), "0000:81:00");
        assert_eq!(pci_key("81:00.0"), "0000:81:00", "domain omitted");
        // Different cards must not collide.
        assert_ne!(pci_key("00000000:81:00.0"), pci_key("00000000:07:00.0"));
        // Something that is not an address at all does not match anything.
        assert_eq!(pci_key("not-an-address"), "not-an-address");
    }

    #[test]
    fn a_fault_on_one_card_is_not_reported_against_the_other_seven() {
        let ev = parse(REAL);
        let cards = by_card(&ev);
        assert_eq!(cards.len(), 2, "two distinct PCI addresses: {cards:#?}");

        // Worst first: 0000:07:00 logged an Xid 63 (reset the card), which
        // outranks the 94 and 31 on 0000:81:00 (restart the job).
        assert_eq!(cards[0].0.as_deref(), Some("0000:07:00"));
        assert_eq!(cards[0].1.class.remedy, Remedy::ResetDevice);
        assert_eq!(cards[0].1.total, 1, "only that card's own events");

        assert_eq!(cards[1].0.as_deref(), Some("0000:81:00"));
        assert_eq!(cards[1].1.total, 2);
    }

    #[test]
    fn an_unattributed_fault_is_not_pinned_on_the_only_card_present() {
        // The driver printed no address. The fault is real and must be
        // reported, but guessing it belongs to whichever card happens to be
        // installed would drain working hardware.
        let ev = parse("NVRM: Xid 79 the card fell off the bus");
        let cards = by_card(&ev);
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].0, None, "no address means no attribution");
        assert_eq!(cards[0].1.worst.code, 79);
    }

    #[test]
    fn the_names_in_a_log_line_match_the_names_in_the_json() {
        // Two spellings of the same verdict is how a fleet ends up filtering
        // on a string that never appears.
        for b in [Blame::Card, Blame::Workload, Blame::Fabric, Blame::System, Blame::Unknown] {
            let json = serde_json::to_string(&b).expect("serialise");
            assert_eq!(json, format!("\"{}\"", b.as_str()), "{b:?}");
        }
        for r in [
            Remedy::Watch,
            Remedy::RestartWorkload,
            Remedy::ResetDevice,
            Remedy::DrainNode,
            Remedy::ReplaceCard,
        ] {
            let json = serde_json::to_string(&r).expect("serialise");
            assert_eq!(json, format!("\"{}\"", r.as_str()), "{r:?}");
        }
    }

    #[test]
    fn no_events_is_not_a_clean_bill() {
        // A node with no driver, no card, or an unreadable log lands here, and
        // it must not be indistinguishable from a healthy one.
        assert_eq!(assess(&[]), None);
    }

    #[test]
    fn a_driver_line_in_a_shape_we_have_not_seen_still_yields_the_code() {
        // Format has moved across driver generations; locking onto the number
        // is what keeps this working on the next one.
        let ev = parse("NVRM: Xid 79 something entirely new here");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].code, 79);
        assert_eq!(ev[0].pci, None);
    }
}
