//! Whether the accelerators are dying, as opposed to being busy.
//!
//! Accelerators were the largest hole in what this host can see. They appeared
//! in the tree exactly once, as the string `cuda:sm_120` in
//! [`furcate-build`]'s placement rules — a *target* a build may be sent to,
//! attested and matched exactly. Nothing anywhere asked whether the card was
//! well. On a fleet whose whole purpose is running models that is the one
//! device class that must not be invisible.
//!
//! This is [`crate::storage`] applied to a different device, and deliberately
//! so: the questions a disk answers about itself are the questions a GPU
//! answers about itself, under different names. A retired sector is a remapped
//! row. A pending sector is a pending remap. Reading the parallel across is
//! most of the design.
//!
//! ## Leading indicators only
//!
//! Same discipline as the disks: a count that climbs before anything stops
//! working. Utilisation and inlet temperature are not health — a card at 100%
//! and 70°C is a card doing its job, and [`crate::cooling`] already owns the
//! thermal picture. What is taken from the thermal domain here is narrower and
//! different in kind: whether the card *says it is throttling itself*, which is
//! the card's own statement that it could not sustain what it was asked to do.
//!
//! ## Thresholds are the manufacturer's own, where one exists
//!
//! Row remapping has no published budget the way NVMe endurance does, so the
//! signal taken is movement and the two states NVIDIA itself calls terminal:
//! a remap that is *pending* (the row is retired but the card needs a reset to
//! take it out of service) and a remap that *failed* (the card tried to retire
//! a row and could not, which is the documented RMA condition).
//!
//! ## Headroom is here, and capacity normally would not be
//!
//! [`crate::storage`] deliberately leaves capacity to [`crate::filesystem`].
//! There is no equivalent owner for accelerator memory, and the omission has
//! already cost us: a serving process was started against 90% of a 121 GB card
//! on 2026-09-04, the remaining few gigabytes were not enough for the
//! allocator's transient peaks, and the driver's out-of-memory took the whole
//! host off the network for eighteen minutes. Nothing in the fleet could have
//! reported beforehand that the machine was one allocation away from that,
//! because nothing was looking. So headroom is a health signal here, and it is
//! the one an operator most needs before placing work.

use serde::{Deserialize, Serialize};

/// One accelerator's health, in whatever terms it reports.
///
/// Every field is optional because support varies by generation far more than
/// it does across disks: row remapping is Ampere and later, retired pages are
/// what came before it, and a consumer card reports neither. A `None` means
/// "this card does not answer that question", never "zero".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Device {
    /// Ordinal on this host. Stable within a boot, not across one.
    pub index: u32,
    /// The card's own identifier, which is stable across boots and reseats.
    pub uuid: Option<String>,
    /// PCI address, as the vendor tool spells it.
    ///
    /// Carried because it is the only field the *driver* also names. An Xid
    /// line identifies its card by PCI address and by nothing else, so without
    /// this a fault the kernel reported cannot be attached to the card it came
    /// from — see [`crate::xid::pci_key`], which reconciles the two spellings.
    pub pci: Option<String>,
    /// Model string, where the device gives one.
    pub name: Option<String>,

    // --- memory errors ---
    /// Corrected single-bit errors since boot. Expected to be non-zero on a
    /// healthy card; only movement is interesting.
    pub ecc_corrected_volatile: Option<u64>,
    /// Uncorrected errors since boot. A computation has already been wrong.
    pub ecc_uncorrected_volatile: Option<u64>,
    /// Uncorrected errors across the card's life, held in its own inforom.
    /// Survives a reboot, which is what makes it the honest lifetime figure.
    pub ecc_uncorrected_aggregate: Option<u64>,

    // --- row remapping (Ampere and later) ---
    /// Rows retired after correctable errors. The analogue of a reallocated
    /// sector: normal in small numbers, meaningful when it moves.
    pub remapped_rows_correctable: Option<u64>,
    /// Rows retired after uncorrectable errors.
    pub remapped_rows_uncorrectable: Option<u64>,
    /// A remap is queued and needs a reset to take effect. Until then the card
    /// is running on memory it has already condemned.
    pub remapped_rows_pending: Option<bool>,
    /// The card tried to retire a row and could not. NVIDIA documents this as
    /// the condition to replace the card on.
    pub remapped_rows_failure: Option<bool>,
    /// Pre-Ampere equivalent of a pending remap.
    pub retired_pages_pending: Option<u64>,

    // --- link ---
    /// PCIe replays. Climbs on a marginal riser, cable or slot — which is a
    /// different repair from replacing the card.
    pub pcie_replay_counter: Option<u64>,
    /// Negotiated and maximum PCIe generation. A card that has fallen back a
    /// generation is a card whose bandwidth is quietly a fraction of what the
    /// placement assumed.
    pub pcie_link_gen_current: Option<u8>,
    pub pcie_link_gen_max: Option<u8>,

    // --- the card's own statement that it is being held back ---
    pub throttle_hw_thermal: Option<bool>,
    pub throttle_sw_thermal: Option<bool>,
    pub throttle_hw_power_brake: Option<bool>,

    // --- memory occupancy ---
    pub memory_total_mib: Option<u64>,
    pub memory_used_mib: Option<u64>,
}

impl Device {
    /// Fraction of the card's memory in use, where both figures are known.
    pub fn memory_fraction(&self) -> Option<f64> {
        let (used, total) = (self.memory_used_mib?, self.memory_total_mib?);
        (total > 0).then(|| used as f64 / total as f64)
    }

    /// Whether the card said anything at all worth assessing.
    fn reported_anything(&self) -> bool {
        self.ecc_uncorrected_aggregate.is_some()
            || self.ecc_corrected_volatile.is_some()
            || self.remapped_rows_correctable.is_some()
            || self.retired_pages_pending.is_some()
            || self.memory_total_mib.is_some()
    }
}

/// What the evidence says about one accelerator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing to report.
    Healthy,
    /// Counts exist and are not moving. Normal for a card with history.
    StableWithHistory { remapped: u64 },
    /// A count moved since the last observation. The signal that matters.
    Deteriorating { what: String, from: u64, to: u64 },
    /// The card tried to retire a row and failed. Replace it.
    RemapFailed,
    /// A remap is queued. The card is running on memory it has condemned and
    /// needs a reset — which is a scheduling decision, not an emergency.
    RemapPending,
    /// Uncorrectable errors over the card's lifetime. A result has been wrong.
    UncorrectableMemory { aggregate: u64 },
    /// Almost no memory left. Placing work here risks the driver's
    /// out-of-memory, which does not stop at the process.
    HeadroomExhausted { used_mib: u64, total_mib: u64 },
    /// The card says it is throttling itself.
    Throttled { reason: String },
    /// The link negotiated below what the card supports.
    LinkDegraded { current_gen: u8, max_gen: u8 },
    /// The device is present and said nothing useful.
    NotReported,
}

impl Verdict {
    /// Whether this should reach a human.
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            Verdict::Deteriorating { .. }
                | Verdict::RemapFailed
                | Verdict::RemapPending
                | Verdict::UncorrectableMemory { .. }
                | Verdict::HeadroomExhausted { .. }
                | Verdict::Throttled { .. }
                | Verdict::LinkDegraded { .. }
        )
    }

    /// Whether replacing the card is the likely remedy.
    ///
    /// Separated from actionable for the same reason the disks separate it: a
    /// throttling card is a cooling or power problem, a degraded link is a
    /// riser or a slot, and an exhausted card is a placement decision. Sending
    /// somebody to swap a healthy accelerator is worse than not telling them,
    /// because they will trust the next alert less.
    pub fn implicates_the_card(&self) -> bool {
        matches!(
            self,
            Verdict::Deteriorating { .. }
                | Verdict::RemapFailed
                | Verdict::RemapPending
                | Verdict::UncorrectableMemory { .. }
        )
    }

    /// Whether work should stop being placed here until somebody has looked.
    ///
    /// Narrower than actionable and wider than implicates: a card that is out
    /// of memory is perfectly healthy and still must not be given more, and a
    /// card whose remap failed must not be given anything at all.
    pub fn should_drain(&self) -> bool {
        matches!(
            self,
            Verdict::RemapFailed
                | Verdict::UncorrectableMemory { .. }
                | Verdict::HeadroomExhausted { .. }
        )
    }
}

/// Fraction of accelerator memory above which the card is called exhausted.
///
/// Ninety-five rather than a hundred, and the five points are not a safety
/// margin for the workload — they are room for the allocator itself. A serving
/// engine reserving 90% of a card leaves the rest to be fought over by CUDA
/// context, fragmentation and transient peaks, and losing that fight is not a
/// failed allocation in one process: on 2026-09-04 it took the host off the
/// network entirely.
pub const HEADROOM_FRACTION: f64 = 0.95;

/// Judge a device, optionally against how it looked before.
///
/// The previous observation is what turns a count into a trend, exactly as it
/// does for a disk. Without it this can only report absolute figures, and an
/// absolute remap count is close to meaningless — cards ship with spare rows
/// precisely so that a few can be retired without incident.
pub fn assess(now: &Device, before: Option<&Device>) -> Verdict {
    if !now.reported_anything() {
        return Verdict::NotReported;
    }

    // The card's own terminal states outrank inference from counters, in the
    // order that decides what an operator does next: a failed remap is a
    // replacement, a pending one is a scheduled reset.
    if now.remapped_rows_failure == Some(true) {
        return Verdict::RemapFailed;
    }
    if let Some(aggregate) = now.ecc_uncorrected_aggregate {
        if aggregate > 0 {
            return Verdict::UncorrectableMemory { aggregate };
        }
    }
    if now.remapped_rows_pending == Some(true) || now.retired_pages_pending.is_some_and(|p| p > 0) {
        return Verdict::RemapPending;
    }

    // Movement, against the previous observation.
    if let Some(prev) = before {
        for (what, from, to) in [
            (
                "remapped_rows_correctable",
                prev.remapped_rows_correctable,
                now.remapped_rows_correctable,
            ),
            (
                "remapped_rows_uncorrectable",
                prev.remapped_rows_uncorrectable,
                now.remapped_rows_uncorrectable,
            ),
            (
                "ecc_uncorrected_volatile",
                prev.ecc_uncorrected_volatile,
                now.ecc_uncorrected_volatile,
            ),
            (
                "pcie_replay_counter",
                prev.pcie_replay_counter,
                now.pcie_replay_counter,
            ),
        ] {
            if let (Some(from), Some(to)) = (from, to) {
                if to > from {
                    return Verdict::Deteriorating {
                        what: what.to_string(),
                        from,
                        to,
                    };
                }
            }
        }
    }

    // Headroom before throttling: a card with no memory left is the more
    // urgent of the two and the one that ends the host rather than the job.
    if let (Some(fraction), Some(used), Some(total)) = (
        now.memory_fraction(),
        now.memory_used_mib,
        now.memory_total_mib,
    ) {
        if fraction >= HEADROOM_FRACTION {
            return Verdict::HeadroomExhausted {
                used_mib: used,
                total_mib: total,
            };
        }
    }

    for (flag, reason) in [
        (now.remapped_rows_failure, "remap_failure"),
        (now.throttle_hw_thermal, "hw_thermal_slowdown"),
        (now.throttle_hw_power_brake, "hw_power_brake"),
        (now.throttle_sw_thermal, "sw_thermal_slowdown"),
    ] {
        if flag == Some(true) {
            return Verdict::Throttled {
                reason: reason.to_string(),
            };
        }
    }

    if let (Some(current), Some(max)) = (now.pcie_link_gen_current, now.pcie_link_gen_max) {
        if current < max {
            return Verdict::LinkDegraded {
                current_gen: current,
                max_gen: max,
            };
        }
    }

    match now.remapped_rows_correctable {
        Some(remapped) if remapped > 0 => Verdict::StableWithHistory { remapped },
        _ => Verdict::Healthy,
    }
}

/// Read one accelerator out of the published report.
///
/// The shape is a flat map of `nvidia-smi --query-gpu` field names to the
/// strings that tool prints, because that is what the privileged reader can
/// produce without a parser of its own. Every conversion here is total: a
/// field that is missing, empty, or the literal `[N/A]` that nvidia-smi prints
/// for an unsupported query becomes `None` rather than a zero, so a consumer
/// card and a healthy datacentre card are never confused for one another.
pub fn parse_nvidia_smi(index: u32, v: &serde_json::Value) -> Device {
    let s = |k: &str| -> Option<String> {
        let raw = v.get(k)?.as_str()?.trim();
        // nvidia-smi prints these for "the card cannot answer that".
        if raw.is_empty() || raw.eq_ignore_ascii_case("[N/A]") || raw.eq_ignore_ascii_case("N/A") {
            return None;
        }
        Some(raw.to_string())
    };
    let n = |k: &str| -> Option<u64> { s(k)?.parse().ok() };
    let g = |k: &str| -> Option<u8> {
        // Link generation is sometimes printed as "4" and sometimes "Gen4".
        let raw = s(k)?;
        raw.trim_start_matches(['G', 'e', 'n']).parse().ok()
    };
    // Booleans arrive in three dialects depending on the field and the driver.
    let b = |k: &str| -> Option<bool> {
        match s(k)?.to_ascii_lowercase().as_str() {
            "yes" | "active" | "enabled" | "true" => Some(true),
            "no" | "not active" | "disabled" | "false" => Some(false),
            _ => None,
        }
    };

    Device {
        index,
        uuid: s("uuid"),
        pci: s("pci.bus_id"),
        name: s("name"),
        ecc_corrected_volatile: n("ecc.errors.corrected.volatile.total"),
        ecc_uncorrected_volatile: n("ecc.errors.uncorrected.volatile.total"),
        ecc_uncorrected_aggregate: n("ecc.errors.uncorrected.aggregate.total"),
        remapped_rows_correctable: n("remapped_rows.correctable"),
        remapped_rows_uncorrectable: n("remapped_rows.uncorrectable"),
        remapped_rows_pending: b("remapped_rows.pending"),
        remapped_rows_failure: b("remapped_rows.failure"),
        retired_pages_pending: n("retired_pages.pending"),
        pcie_replay_counter: n("pcie.replay.counter"),
        pcie_link_gen_current: g("pcie.link.gen.current"),
        pcie_link_gen_max: g("pcie.link.gen.max"),
        throttle_hw_thermal: b("clocks_throttle_reasons.hw_thermal_slowdown"),
        throttle_sw_thermal: b("clocks_throttle_reasons.sw_thermal_slowdown"),
        throttle_hw_power_brake: b("clocks_throttle_reasons.hw_power_brake_slowdown"),
        memory_total_mib: n("memory.total"),
        memory_used_mib: n("memory.used"),
    }
}

/// Read a whole published accelerator report.
///
/// The privileged reader writes one file holding every card, for the same
/// reason it does for the disks: a consumer wants a fleet view, and reading one
/// file is atomic in a way that reading N files is not.
///
/// The boolean is whether the report could be read *at all*, and it carries the
/// distinction the rest of this module is built on. A host with no driver, a
/// host whose cards are healthy, and a host whose cards are failing are three
/// states. An empty list with `true` means a driver answered and had nothing to
/// report; an empty list with `false` means nobody asked or nobody answered.
///
/// This lives here rather than in the agent because it is pure parsing, and
/// because the agent cannot be built or tested on a developer's machine — a
/// contract that can only be exercised on the target is a contract nobody
/// exercises.
pub fn parse_published(text: &str) -> (Vec<Device>, bool) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return (Vec::new(), false);
    };
    let Some(list) = v.get("accelerators").and_then(|d| d.as_array()) else {
        return (Vec::new(), false);
    };
    let out = list
        .iter()
        .filter_map(|a| {
            let report = a.get("report")?;
            // The publisher's index is authoritative: it is the ordinal
            // nvidia-smi itself used, and renumbering by position here would
            // silently disagree with every other tool on the host.
            let index = a.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as u32;
            Some(parse_nvidia_smi(index, report))
        })
        .collect();
    (out, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The exact bytes `publish_accelerators` writes, for the three cases that
    /// matter: a healthy datacentre card, one condemning memory, and a consumer
    /// card that answers `[N/A]` to every health question.
    ///
    /// Captured from the shell publisher's own output rather than written by
    /// hand. The two halves of this seam are an awk program and a Rust module,
    /// and nothing but this stops them drifting apart silently — a renamed
    /// field would surface as a fleet of cards reporting no health, which looks
    /// exactly like a fleet of healthy cards unless somebody is checking.
    const PUBLISHED: &str = r#"{"accelerators":[
      {"index":0,"vendor":"nvidia","report":{"uuid":"GPU-aaa","name":"NVIDIA H100 80GB HBM3","ecc.errors.corrected.volatile.total":"12","ecc.errors.uncorrected.volatile.total":"0","ecc.errors.uncorrected.aggregate.total":"0","remapped_rows.correctable":"3","remapped_rows.uncorrectable":"0","remapped_rows.pending":"No","remapped_rows.failure":"No","pcie.replay.counter":"17","pcie.link.gen.current":"4","pcie.link.gen.max":"4","clocks_throttle_reasons.hw_thermal_slowdown":"Not Active","clocks_throttle_reasons.sw_thermal_slowdown":"Not Active","clocks_throttle_reasons.hw_power_brake_slowdown":"Not Active","memory.total":"81559","memory.used":"40000"}},
      {"index":1,"vendor":"nvidia","report":{"uuid":"GPU-bbb","name":"NVIDIA H100 80GB HBM3","ecc.errors.corrected.volatile.total":"0","ecc.errors.uncorrected.volatile.total":"0","ecc.errors.uncorrected.aggregate.total":"2","remapped_rows.correctable":"0","remapped_rows.uncorrectable":"1","remapped_rows.pending":"Yes","remapped_rows.failure":"No","pcie.replay.counter":"0","pcie.link.gen.current":"4","pcie.link.gen.max":"4","clocks_throttle_reasons.hw_thermal_slowdown":"Active","clocks_throttle_reasons.sw_thermal_slowdown":"Not Active","clocks_throttle_reasons.hw_power_brake_slowdown":"Not Active","memory.total":"81559","memory.used":"79000"}},
      {"index":2,"vendor":"nvidia","report":{"uuid":"GPU-ccc","name":"NVIDIA GeForce RTX 5090","ecc.errors.corrected.volatile.total":"[N/A]","ecc.errors.uncorrected.volatile.total":"[N/A]","ecc.errors.uncorrected.aggregate.total":"[N/A]","remapped_rows.correctable":"[N/A]","remapped_rows.uncorrectable":"[N/A]","remapped_rows.pending":"[N/A]","remapped_rows.failure":"[N/A]","pcie.replay.counter":"0","pcie.link.gen.current":"4","pcie.link.gen.max":"4","clocks_throttle_reasons.hw_thermal_slowdown":"Not Active","clocks_throttle_reasons.sw_thermal_slowdown":"Not Active","clocks_throttle_reasons.hw_power_brake_slowdown":"Not Active","memory.total":"32607","memory.used":"31500"}}
    ]}"#;

    #[test]
    fn the_published_report_survives_the_trip() {
        let (cards, readable) = parse_published(PUBLISHED);
        assert!(readable);
        assert_eq!(cards.len(), 3);

        // The publisher's index is kept, not re-derived from position.
        assert_eq!(cards[1].index, 1);
        assert_eq!(cards[0].pcie_replay_counter, Some(17));

        // Healthy card with history: three remapped rows and room to work.
        assert_eq!(
            assess(&cards[0], None),
            Verdict::StableWithHistory { remapped: 3 }
        );

        // Lifetime uncorrectable errors outrank the pending remap and the
        // thermal throttle that are also true of this card.
        assert_eq!(
            assess(&cards[1], None),
            Verdict::UncorrectableMemory { aggregate: 2 }
        );
        assert!(assess(&cards[1], None).should_drain());

        // The consumer card answers nothing about ECC, and that is not zero —
        // but it did answer about memory, and it is nearly full.
        assert_eq!(cards[2].ecc_uncorrected_aggregate, None);
        assert_eq!(cards[2].remapped_rows_pending, None);
        assert!(matches!(
            assess(&cards[2], None),
            Verdict::HeadroomExhausted { .. }
        ));
    }

    #[test]
    fn a_host_with_no_driver_is_unreadable_rather_than_healthy() {
        // The distinction the whole design turns on: nothing published is not
        // the same as a card reporting itself well.
        assert!(!parse_published("").1);
        assert!(!parse_published("{}").1);
        assert!(!parse_published("not json at all").1);
        let (cards, readable) = parse_published(r#"{"accelerators":[]}"#);
        assert!(
            readable,
            "a driver that reported no cards is still a reading"
        );
        assert!(cards.is_empty());
    }

    fn healthy() -> Device {
        Device {
            index: 0,
            name: Some("NVIDIA GB10".into()),
            ecc_uncorrected_aggregate: Some(0),
            remapped_rows_correctable: Some(0),
            memory_total_mib: Some(122_880),
            memory_used_mib: Some(1_024),
            ..Device::default()
        }
    }

    #[test]
    fn a_card_that_says_nothing_is_not_called_healthy() {
        let d = Device {
            index: 0,
            name: Some("some consumer card".into()),
            ..Device::default()
        };
        assert_eq!(assess(&d, None), Verdict::NotReported);
    }

    #[test]
    fn a_failed_remap_outranks_everything_else() {
        let mut d = healthy();
        d.remapped_rows_failure = Some(true);
        d.ecc_uncorrected_aggregate = Some(9);
        assert_eq!(assess(&d, None), Verdict::RemapFailed);
        assert!(assess(&d, None).implicates_the_card());
        assert!(assess(&d, None).should_drain());
    }

    #[test]
    fn a_pending_remap_is_a_scheduled_reset_not_a_replacement() {
        let mut d = healthy();
        d.remapped_rows_pending = Some(true);
        let v = assess(&d, None);
        assert_eq!(v, Verdict::RemapPending);
        assert!(v.is_actionable());
        // It needs a reset, but the card is not condemned and draining it now
        // would take capacity away for no gain.
        assert!(!v.should_drain());
    }

    #[test]
    fn movement_is_reported_over_a_standing_count() {
        let before = Device {
            remapped_rows_correctable: Some(4),
            ..healthy()
        };
        let now = Device {
            remapped_rows_correctable: Some(7),
            ..healthy()
        };
        // Standing still, the same count is history and not news.
        assert_eq!(
            assess(&before, Some(&before)),
            Verdict::StableWithHistory { remapped: 4 }
        );
        assert_eq!(
            assess(&now, Some(&before)),
            Verdict::Deteriorating {
                what: "remapped_rows_correctable".into(),
                from: 4,
                to: 7
            }
        );
    }

    #[test]
    fn the_headroom_that_took_a_host_off_the_network() {
        // The 2026-09-04 shape: a 121 GB card with a serving engine holding
        // ~90% of it and a benchmark asking for the rest.
        let mut d = healthy();
        d.memory_used_mib = Some(119_000);
        let v = assess(&d, None);
        assert_eq!(
            v,
            Verdict::HeadroomExhausted {
                used_mib: 119_000,
                total_mib: 122_880
            }
        );
        assert!(v.should_drain());
        // A healthy card is not blamed: this is a placement decision.
        assert!(!v.implicates_the_card());
    }

    #[test]
    fn a_busy_card_with_room_is_healthy() {
        let mut d = healthy();
        d.memory_used_mib = Some(80_000); // 65%, working hard, fine
        assert_eq!(assess(&d, None), Verdict::Healthy);
    }

    #[test]
    fn throttling_and_a_slow_link_are_not_the_cards_fault() {
        let mut d = healthy();
        d.throttle_hw_thermal = Some(true);
        let v = assess(&d, None);
        assert_eq!(
            v,
            Verdict::Throttled {
                reason: "hw_thermal_slowdown".into()
            }
        );
        assert!(v.is_actionable() && !v.implicates_the_card());

        let mut d = healthy();
        d.pcie_link_gen_current = Some(1);
        d.pcie_link_gen_max = Some(4);
        let v = assess(&d, None);
        assert_eq!(
            v,
            Verdict::LinkDegraded {
                current_gen: 1,
                max_gen: 4
            }
        );
        assert!(!v.implicates_the_card());
    }

    #[test]
    fn unsupported_queries_become_none_and_never_zero() {
        // The distinction the disks insisted on: a card that cannot answer is
        // not a card answering zero.
        let d = parse_nvidia_smi(
            3,
            &json!({
                "name": "NVIDIA GeForce RTX 5090",
                "uuid": "GPU-abc",
                "remapped_rows.correctable": "[N/A]",
                "ecc.errors.uncorrected.aggregate.total": "N/A",
                "memory.total": "32607",
                "memory.used": "  1024 ",
                "pcie.link.gen.current": "Gen4",
                "pcie.link.gen.max": "4",
                "remapped_rows.pending": "No",
                "clocks_throttle_reasons.hw_thermal_slowdown": "Not Active"
            }),
        );
        assert_eq!(d.index, 3);
        assert_eq!(d.remapped_rows_correctable, None);
        assert_eq!(d.ecc_uncorrected_aggregate, None);
        assert_eq!(d.memory_total_mib, Some(32_607));
        assert_eq!(d.memory_used_mib, Some(1_024), "whitespace is trimmed");
        assert_eq!(d.pcie_link_gen_current, Some(4), "Gen4 and 4 are one thing");
        assert_eq!(d.pcie_link_gen_max, Some(4));
        assert_eq!(d.remapped_rows_pending, Some(false));
        assert_eq!(d.throttle_hw_thermal, Some(false));
        // It answered about its memory, so it is assessable.
        assert_eq!(assess(&d, None), Verdict::Healthy);
    }

    #[test]
    fn a_datacentre_card_parses_the_whole_surface() {
        let d = parse_nvidia_smi(
            0,
            &json!({
                "name": "NVIDIA H100 80GB HBM3",
                "uuid": "GPU-1234",
                "ecc.errors.corrected.volatile.total": "12",
                "ecc.errors.uncorrected.volatile.total": "0",
                "ecc.errors.uncorrected.aggregate.total": "2",
                "remapped_rows.correctable": "3",
                "remapped_rows.uncorrectable": "1",
                "remapped_rows.pending": "Yes",
                "remapped_rows.failure": "No",
                "pcie.replay.counter": "17",
                "memory.total": "81559",
                "memory.used": "40000"
            }),
        );
        assert_eq!(d.ecc_corrected_volatile, Some(12));
        assert_eq!(d.remapped_rows_uncorrectable, Some(1));
        assert_eq!(d.remapped_rows_pending, Some(true));
        assert_eq!(d.remapped_rows_failure, Some(false));
        assert_eq!(d.pcie_replay_counter, Some(17));
        // Lifetime uncorrectable errors outrank the pending remap.
        assert_eq!(
            assess(&d, None),
            Verdict::UncorrectableMemory { aggregate: 2 }
        );
    }

    #[test]
    fn memory_fraction_is_none_rather_than_a_divide_by_zero() {
        let d = Device {
            memory_total_mib: Some(0),
            memory_used_mib: Some(0),
            ..Device::default()
        };
        assert_eq!(d.memory_fraction(), None);
    }
}
