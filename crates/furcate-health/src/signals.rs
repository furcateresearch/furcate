//! Health signals from the platform.
//!
//! Signals come from the hardware rather than from guesswork: out-of-band
//! sensors, storage self-monitoring, memory error counters, and — a signal
//! peculiar to Furcate — attestation drift, which is a health event as much as
//! a security one.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    /// Degraded but serving.
    Warning,
    /// Should be taken out of service.
    Critical,
    /// Already failed.
    Fatal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Storage self-monitoring reported reallocated sectors or similar.
    DiskDegraded { device: String, reallocated: u64 },
    /// Correctable memory errors above threshold.
    MemoryErrors { count: u64 },
    /// An accelerator reported something an operator should act on.
    ///
    /// Carries the facts rather than `furcate_host::accelerator::Verdict`, for
    /// the same reason `DiskDegraded` carries a name and a count: this model
    /// has to describe a node reporting from somewhere else, where nobody here
    /// can read that machine's hardware. The two booleans are the distinctions
    /// that decide what happens next, and flattening them into the severity
    /// alone would lose the case that matters most — see `classify`.
    AcceleratorDegraded {
        /// Ordinal on its host, as the vendor tool numbered it.
        index: u32,
        /// The verdict's own name, for a human and for a log.
        verdict: String,
        /// Whether the card itself is implicated, as opposed to its cooling,
        /// its slot, or the work that was placed on it.
        implicates_card: bool,
        /// Whether work should stop being placed on this card.
        should_drain: bool,
    },
    /// The driver named a fault on a card, in the card's own words.
    ///
    /// Distinct from `AcceleratorDegraded`, which is inferred from counters
    /// moving over time. This one is an error code the driver emitted at the
    /// moment something went wrong, and the two catch different halves: a card
    /// becoming unwell versus a card that has already faulted once.
    ///
    /// It carries blame because the single most common code by far is the
    /// workload's fault — a job using an address it does not own — and
    /// reporting that as a hardware fault sends somebody to swap a healthy
    /// card and teaches them to trust the next alert less.
    AcceleratorFault {
        /// Ordinal on its host, where the fault could be matched to a card the
        /// vendor tool also enumerated. `None` when the driver named a PCI
        /// address this node has no reading for — the fault is still real and
        /// still reported, it just cannot be tied to an index.
        index: Option<u32>,
        /// The PCI address the driver named, where the line carried one.
        pci: Option<String>,
        /// The fault code itself.
        code: u16,
        /// Who the evidence implicates, in one word, for a human and a log.
        blame: String,
        /// What acting on it looks like, in one word.
        remedy: String,
        /// Whether the failure was contained to the process that caused it.
        ///
        /// `Some(false)` is the distinction that decides whether the node
        /// keeps working: an uncontained memory error means every result from
        /// that card is suspect, not just the job that hit it.
        contained: Option<bool>,
        /// Whether the card itself is implicated, as opposed to the fabric,
        /// the driver, or the work that was placed on it.
        implicates_card: bool,
        /// Whether work should stop being placed on this card.
        should_drain: bool,
        /// Whether this should reach a human at all.
        actionable: bool,
        /// One line, in the operator's language rather than the driver's.
        summary: String,
        /// How many events carried this code in the window. One Xid 31 is a
        /// bug report; two hundred is a different conversation.
        seen: usize,
    },
    /// The machine is stalling on memory reclaim.
    ///
    /// Emphatically not [`SignalKind::MemoryErrors`], which is ECC faults in
    /// the DIMMs — a hardware problem answered by replacing a part. This is a
    /// *workload* problem: the memory is fine and there is not enough of it,
    /// and the answer is to take work away rather than to send an engineer.
    /// Reporting one as the other sends somebody to swap healthy memory.
    ///
    /// Carries the level rather than the percentage. The numbers are on
    /// `/resources` in full, and a float here would mean a reading that drifts
    /// by a tenth is a different signal from the one before it — so the same
    /// machine in the same state would raise a new signal every pass and the
    /// list would fill with the same fact.
    MemoryPressure {
        /// `starved` or `stalled`, in the pressure vocabulary's own words.
        level: String,
    },
    /// A sensor exceeded its limit.
    Thermal { sensor: String, celsius: f32 },
    /// A power supply or feed failed.
    PowerFault { detail: String },
    /// Re-attestation no longer matches the reference values.
    AttestationDrift { register: u32 },
    /// The node stopped answering probes.
    Unreachable,
    /// A workload this node hosts has failed or is failing its own check.
    WorkloadDown { id: String, critical: bool },
    /// A workload is being restarted repeatedly without recovering.
    WorkloadFlapping { id: String, restarts: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signal {
    pub node: String,
    pub kind: SignalKind,
    pub severity: Severity,
    pub observed_at: u64,
}

impl Signal {
    pub fn new(node: impl Into<String>, kind: SignalKind, observed_at: u64) -> Self {
        let severity = Self::classify(&kind);
        Self {
            node: node.into(),
            kind,
            severity,
            observed_at,
        }
    }

    /// Default severity for a signal.
    ///
    /// Attestation drift is deliberately `Critical` rather than `Warning`: a
    /// register that no longer matches means the machine is not the one that
    /// was admitted, and continuing to schedule work onto it would extend
    /// trust that has already been withdrawn.
    fn classify(kind: &SignalKind) -> Severity {
        match kind {
            SignalKind::DiskDegraded { reallocated, .. } if *reallocated > 100 => Severity::Critical,
            SignalKind::DiskDegraded { .. } => Severity::Warning,
            SignalKind::MemoryErrors { count } if *count > 1000 => Severity::Critical,
            SignalKind::MemoryErrors { .. } => Severity::Warning,
            // A card that is condemning its own memory is `Critical`, and so
            // cordons the node — the same judgement `DiskDegraded` already
            // makes about a failing disk, for the same reason: results from it
            // cannot be trusted and somebody has to look.
            SignalKind::AcceleratorDegraded {
                implicates_card: true,
                ..
            } => Severity::Critical,
            // Everything else about an accelerator is a `Warning`, and this is
            // the important half. A card that is out of memory must stop
            // receiving work, but it is perfectly healthy and the node very
            // likely holds seven others that are fine. Promoting that to
            // `Critical` would cordon a whole machine over one full card,
            // which is a worse outcome than the problem. Draining a card and
            // cordoning a node are different acts, and `should_drain` is
            // carried separately so a scheduler can do the first without the
            // second.
            SignalKind::AcceleratorDegraded { .. } => Severity::Warning,
            // A fault the driver named follows the same split, decided by the
            // one question that separates "this card lost a process" from
            // "this card lost everything": containment. An uncontained error
            // means results already computed on that card cannot be trusted,
            // which is the disk-that-is-failing case and cordons the node.
            SignalKind::AcceleratorFault {
                contained: Some(false),
                ..
            } => Severity::Critical,
            SignalKind::AcceleratorFault {
                implicates_card: true,
                ..
            } => Severity::Critical,
            // A code with no action attached — a rate of *corrected* errors,
            // or one this build has no documented meaning for — is Info. It
            // belongs in the record, and paging on it would train the operator
            // to dismiss the codes that do matter.
            SignalKind::AcceleratorFault {
                actionable: false, ..
            } => Severity::Info,
            SignalKind::AcceleratorFault { .. } => Severity::Warning,
            // A machine where every non-idle task is stalled has stopped
            // making progress, and the reason this is `Critical` is the
            // cordon: no more work should be placed on it. That is the same
            // judgement `Psi::can_take_more` already makes for a scheduler,
            // reached through the health path so it also reaches a human.
            SignalKind::MemoryPressure { level } if level == "stalled" => Severity::Critical,
            // Starved is a busy machine, not a dying one. Worth seeing and not
            // worth cordoning over: memory reclaim under load is what a loaded
            // machine does.
            SignalKind::MemoryPressure { .. } => Severity::Warning,
            SignalKind::Thermal { celsius, .. } if *celsius >= 90.0 => Severity::Critical,
            SignalKind::Thermal { .. } => Severity::Warning,
            SignalKind::PowerFault { .. } => Severity::Critical,
            SignalKind::AttestationDrift { .. } => Severity::Critical,
            SignalKind::Unreachable => Severity::Fatal,
            // A failed workload is a fault on the node, not a fault *of* it.
            // Critical only when the operator declared the workload critical:
            // cordoning a machine because a scratch container exited would
            // take a healthy node out of service to no purpose.
            SignalKind::WorkloadDown { critical: true, .. } => Severity::Critical,
            SignalKind::WorkloadDown { .. } => Severity::Warning,
            // Flapping is a warning whatever it is. The restart loop means
            // something is already trying to fix it, and the value here is
            // that a human hears about it before the count climbs all day.
            SignalKind::WorkloadFlapping { .. } => Severity::Warning,
        }
    }

    /// Whether this signal should remove the node from scheduling.
    pub fn warrants_cordon(&self) -> bool {
        self.severity >= Severity::Critical
    }

    /// Whether this signal warrants forcibly stopping the node.
    pub fn warrants_fence(&self) -> bool {
        self.severity == Severity::Fatal
    }

    /// The accelerator this signal takes out of service, if it takes one.
    ///
    /// The unit of exclusion that did not exist before: every other signal
    /// here is about a whole machine, and the only lever was cordon. An
    /// accelerator that is full, throttling, or condemning rows should stop
    /// receiving work while the seven cards beside it keep going, and a
    /// scheduler needs to be told *which one* to skip rather than being handed
    /// a node-level verdict it can only obey or ignore.
    pub fn drains_accelerator(&self) -> Option<u32> {
        match &self.kind {
            SignalKind::AcceleratorDegraded {
                index,
                should_drain: true,
                ..
            } => Some(*index),
            // A named fault drains the same way, when the fault could be tied
            // to a card. An unmatched PCI address yields None here rather than
            // a guess: draining the wrong card is worse than draining none,
            // because the fault stays where it is and a healthy card stops
            // earning.
            SignalKind::AcceleratorFault {
                index: Some(index),
                should_drain: true,
                ..
            } => Some(*index),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_few_reallocated_sectors_are_a_warning_not_an_outage() {
        let s = Signal::new(
            "node-a",
            SignalKind::DiskDegraded {
                device: "nvme0".into(),
                reallocated: 12,
            },
            0,
        );
        assert_eq!(s.severity, Severity::Warning);
        assert!(!s.warrants_cordon());
    }

    #[test]
    fn many_reallocated_sectors_take_the_node_out() {
        let s = Signal::new(
            "node-a",
            SignalKind::DiskDegraded {
                device: "nvme0".into(),
                reallocated: 5000,
            },
            0,
        );
        assert!(s.warrants_cordon());
    }

    #[test]
    fn attestation_drift_is_critical() {
        let s = Signal::new("node-a", SignalKind::AttestationDrift { register: 11 }, 0);
        assert_eq!(s.severity, Severity::Critical);
        assert!(s.warrants_cordon());
    }

    #[test]
    fn an_unreachable_node_warrants_fencing() {
        let s = Signal::new("node-b", SignalKind::Unreachable, 0);
        assert!(s.warrants_fence());
        assert!(s.warrants_cordon());
    }

    #[test]
    fn thermal_thresholds_escalate() {
        let warm = Signal::new(
            "n",
            SignalKind::Thermal {
                sensor: "cpu".into(),
                celsius: 78.0,
            },
            0,
        );
        let hot = Signal::new(
            "n",
            SignalKind::Thermal {
                sensor: "cpu".into(),
                celsius: 95.0,
            },
            0,
        );
        assert!(!warm.warrants_cordon());
        assert!(hot.warrants_cordon());
    }

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Fatal > Severity::Critical);
        assert!(Severity::Critical > Severity::Warning);
    }

    fn accel(verdict: &str, implicates_card: bool, should_drain: bool) -> Signal {
        Signal::new(
            "n1",
            SignalKind::AcceleratorDegraded {
                index: 3,
                verdict: verdict.into(),
                implicates_card,
                should_drain,
            },
            0,
        )
    }

    #[test]
    fn a_full_card_does_not_cordon_the_node() {
        // The distinction the whole signal exists for. A card at 119 of 122 GB
        // is healthy and must stop receiving work; the node very likely holds
        // seven others that are fine, and cordoning it would cost far more
        // capacity than the problem does.
        let s = accel("headroom_exhausted", false, true);
        assert_eq!(s.severity, Severity::Warning);
        assert!(!s.warrants_cordon(), "a full card must not cordon a node");
        assert!(!s.warrants_fence());
        assert_eq!(s.drains_accelerator(), Some(3), "but it must drain the card");
    }

    #[test]
    fn a_card_condemning_its_own_memory_cordons_the_node() {
        // Same judgement DiskDegraded already makes: results cannot be trusted
        // and somebody has to look.
        for verdict in ["remap_failed", "uncorrectable_memory"] {
            let s = accel(verdict, true, true);
            assert_eq!(s.severity, Severity::Critical, "{verdict}");
            assert!(s.warrants_cordon(), "{verdict}");
            assert_eq!(s.drains_accelerator(), Some(3));
        }
    }

    #[test]
    fn a_throttling_card_is_reported_without_taking_anything_out_of_service() {
        // Real, worth an operator's attention, and not a reason to stop using
        // the card: it is a cooling or power problem, and the work is still
        // correct.
        let s = accel("throttled", false, false);
        assert_eq!(s.severity, Severity::Warning);
        assert!(!s.warrants_cordon());
        assert_eq!(s.drains_accelerator(), None);
    }

    #[test]
    fn only_accelerator_signals_drain_an_accelerator() {
        let s = Signal::new("n1", SignalKind::Unreachable, 0);
        assert_eq!(s.drains_accelerator(), None);
        assert!(s.warrants_fence());
    }

    /// A driver-named fault, with the four decisions the classifier reads.
    fn fault(
        code: u16,
        contained: Option<bool>,
        implicates_card: bool,
        should_drain: bool,
        actionable: bool,
    ) -> Signal {
        Signal::new(
            "node-a",
            SignalKind::AcceleratorFault {
                index: Some(3),
                pci: Some("0000:81:00".into()),
                code,
                blame: "card".into(),
                remedy: "drain_node".into(),
                contained,
                implicates_card,
                should_drain,
                actionable,
                summary: "test".into(),
                seen: 1,
            },
            0,
        )
    }

    #[test]
    fn a_contained_fault_loses_a_process_and_an_uncontained_one_loses_the_node() {
        // The distinction the whole variant exists to carry. Xid 94 killed one
        // process on a card that keeps working; Xid 95 did not, and every
        // result that card has produced is now suspect.
        let contained = fault(94, Some(true), false, false, true);
        assert_eq!(contained.severity, Severity::Warning);
        assert!(!contained.warrants_cordon(), "one lost process must not cordon a node");

        let uncontained = fault(95, Some(false), true, true, true);
        assert_eq!(uncontained.severity, Severity::Critical);
        assert!(uncontained.warrants_cordon());
    }

    #[test]
    fn a_job_using_an_illegal_address_does_not_take_the_card_out() {
        // Xid 31 is the most common code by a wide margin and it is the
        // workload's fault. Draining a card over it would take working
        // hardware out of service every time somebody shipped a bug.
        let s = fault(31, None, false, false, true);
        assert_eq!(s.severity, Severity::Warning);
        assert!(!s.warrants_cordon());
        assert_eq!(s.drains_accelerator(), None);
    }

    #[test]
    fn a_code_with_no_action_attached_is_recorded_without_paging_anyone() {
        // A rate of *corrected* errors, or a code this build has no documented
        // meaning for. It belongs in the record; paging on it would train the
        // operator to dismiss the codes that matter.
        let s = fault(92, Some(true), false, false, false);
        assert_eq!(s.severity, Severity::Info);
        assert!(!s.warrants_cordon());
        assert_eq!(s.drains_accelerator(), None);
    }

    #[test]
    fn a_fault_that_cannot_be_tied_to_a_card_drains_nothing() {
        // The driver named a PCI address this node has no reading for. The
        // fault is real and still reported, but draining the wrong card is
        // worse than draining none: the fault stays where it is and a healthy
        // card stops earning.
        let s = Signal::new(
            "node-a",
            SignalKind::AcceleratorFault {
                index: None,
                pci: Some("0000:99:00".into()),
                code: 95,
                blame: "card".into(),
                remedy: "drain_node".into(),
                contained: Some(false),
                implicates_card: true,
                should_drain: true,
                actionable: true,
                summary: "test".into(),
                seen: 1,
            },
            0,
        );
        assert_eq!(s.drains_accelerator(), None, "no index, no drain");
        // It must still cordon: an uncontained fault somewhere on this node is
        // reason enough to stop placing work, even unattributed.
        assert!(s.warrants_cordon());
    }

}
