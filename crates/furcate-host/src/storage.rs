//! Whether the disks are dying, as opposed to filling.
//!
//! [`crate::filesystem`] answers how long until a mount is full, which is the
//! right question and the wrong half of the problem. A disk can fill up or it
//! can fail, and only the first was covered — so a drive quietly reallocating
//! sectors for a month looked identical to a healthy one right up until the
//! journal reported an I/O error, at which point the answer had arrived too
//! late to be useful.
//!
//! Everything here is a *leading* indicator: a count that climbs before
//! anything stops working. That is the only reason to read them. Temperature
//! and capacity are already covered elsewhere and are deliberately not
//! duplicated.
//!
//! ## Thresholds are ratios of the manufacturer's own limit
//!
//! NVMe reports wear as a percentage against a lifetime the manufacturer
//! defined, and `available_spare` against a threshold the manufacturer also
//! defined. Both are compared against the device's own declared floor rather
//! than a number invented here, because drive endurance varies by an order of
//! magnitude across classes and any fixed figure would be wrong for most of
//! them.
//!
//! ## What a rising count means, and what it does not
//!
//! A reallocated sector is not a failure. Drives ship with spare sectors
//! precisely so that a handful can be retired without incident. What predicts
//! failure is the count **changing**, which is why the assessment takes a
//! previous observation and reports movement — a drive that has sat at 40
//! reallocations for two years is in a different position from one that reached
//! 12 last week.

use serde::{Deserialize, Serialize};

/// One storage device's health, in whatever terms it reports.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Device {
    /// Kernel name, e.g. `nvme0n1` or `sda`.
    pub name: String,
    /// Model string, where the device gives one.
    pub model: Option<String>,
    /// The device's own overall verdict, where it has one.
    pub self_assessment_passed: Option<bool>,

    // --- rotational and SATA SSD, from SMART ---
    /// Sectors retired because they could not be read reliably.
    pub reallocated_sectors: Option<u64>,
    /// Sectors waiting to be retired. Often the earlier signal of the two.
    pub pending_sectors: Option<u64>,
    /// Uncorrectable read errors.
    pub uncorrectable: Option<u64>,
    /// Interface errors. A cable fault rather than a disk fault, and worth
    /// distinguishing because replacing the drive would not fix it.
    pub crc_errors: Option<u64>,
    pub power_on_hours: Option<u64>,

    // --- NVMe ---
    /// Percentage of rated endurance consumed. Exceeds 100 on a worn drive.
    pub percentage_used: Option<u8>,
    /// Remaining spare capacity, as a percentage.
    pub available_spare: Option<u8>,
    /// The manufacturer's own floor for the above.
    pub available_spare_threshold: Option<u8>,
    /// Errors the device could not correct and reported.
    pub media_errors: Option<u64>,
    /// The device's own critical-warning bitfield, non-zero when it is
    /// complaining about something.
    pub critical_warning: Option<u8>,
}

/// What the evidence says about one device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing to report.
    Healthy,
    /// Counts exist and are not moving. Normal for a drive with history.
    StableWithHistory { reallocated: u64 },
    /// A count moved since the last observation. The signal that matters.
    Deteriorating { what: String, from: u64, to: u64 },
    /// Endurance is close to or past its rated life.
    Worn { percentage_used: u8 },
    /// Spare capacity has fallen to the manufacturer's own floor.
    SpareExhausted { available: u8, threshold: u8 },
    /// The device itself says it is failing.
    SelfReportedFailing,
    /// Errors that point at the cable rather than the drive.
    LinkErrors { crc: u64 },
    /// The device is present and said nothing useful.
    NotReported,
}

impl Verdict {
    /// Whether this should reach a human.
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            Verdict::Deteriorating { .. }
                | Verdict::Worn { .. }
                | Verdict::SpareExhausted { .. }
                | Verdict::SelfReportedFailing
                | Verdict::LinkErrors { .. }
        )
    }

    /// Whether replacing the drive is the likely remedy.
    ///
    /// Separated from actionable because one of these is a cable. Sending
    /// somebody to swap a healthy disk is a worse outcome than not telling
    /// them, since they will trust the next alert less.
    pub fn implicates_the_drive(&self) -> bool {
        self.is_actionable() && !matches!(self, Verdict::LinkErrors { .. })
    }
}

/// Endurance above which a drive is called worn.
///
/// Ninety rather than a hundred: a drive at its rated life is not a surprise to
/// plan around, it is one to have already planned around.
pub const WORN_PERCENTAGE: u8 = 90;

/// Judge a device, optionally against how it looked before.
///
/// The previous observation is what turns a count into a trend. Without it this
/// can only report the absolute figures, and an absolute reallocation count is
/// close to meaningless — drives ship with spares precisely so a few can be
/// retired without incident.
pub fn assess(now: &Device, before: Option<&Device>) -> Verdict {
    // The device's own verdict outranks inference from counters. It has
    // information that is not exposed as a counter.
    if now.self_assessment_passed == Some(false) {
        return Verdict::SelfReportedFailing;
    }
    if now.critical_warning.is_some_and(|w| w != 0) {
        return Verdict::SelfReportedFailing;
    }

    // Movement first: a count that changed outranks a count that is merely
    // large, because the large-and-static one has already been survived.
    if let Some(prev) = before {
        for (what, a, b) in [
            ("pending_sectors", prev.pending_sectors, now.pending_sectors),
            ("reallocated_sectors", prev.reallocated_sectors, now.reallocated_sectors),
            ("uncorrectable", prev.uncorrectable, now.uncorrectable),
            ("media_errors", prev.media_errors, now.media_errors),
        ] {
            if let (Some(from), Some(to)) = (a, b) {
                if to > from {
                    return Verdict::Deteriorating { what: what.into(), from, to };
                }
            }
        }
    }

    if let (Some(avail), Some(thresh)) = (now.available_spare, now.available_spare_threshold) {
        if avail <= thresh {
            return Verdict::SpareExhausted { available: avail, threshold: thresh };
        }
    }
    if now.percentage_used.is_some_and(|p| p >= WORN_PERCENTAGE) {
        return Verdict::Worn { percentage_used: now.percentage_used.unwrap() };
    }
    // Checked after the drive's own health so a failing disk on a bad cable is
    // reported as a failing disk.
    if now.crc_errors.is_some_and(|c| c > 0) {
        return Verdict::LinkErrors { crc: now.crc_errors.unwrap() };
    }
    if let Some(r) = now.reallocated_sectors {
        if r > 0 {
            return Verdict::StableWithHistory { reallocated: r };
        }
    }

    let said_anything = now.reallocated_sectors.is_some()
        || now.percentage_used.is_some()
        || now.media_errors.is_some()
        || now.self_assessment_passed.is_some();
    if said_anything {
        Verdict::Healthy
    } else {
        Verdict::NotReported
    }
}

/// Parse `smartctl --json` output for one device.
///
/// Both vocabularies are handled from one function because a machine commonly
/// has both kinds of drive, and the caller should not have to know which it is
/// looking at before it can ask.
pub fn parse_smartctl(name: &str, v: &serde_json::Value) -> Device {
    let attr = |id: u64| -> Option<u64> {
        v.get("ata_smart_attributes")?
            .get("table")?
            .as_array()?
            .iter()
            .find(|a| a.get("id").and_then(|x| x.as_u64()) == Some(id))?
            .get("raw")?
            .get("value")?
            .as_u64()
    };
    let nvme = v.get("nvme_smart_health_information_log");
    let n = |k: &str| nvme.and_then(|x| x.get(k)).and_then(|x| x.as_u64());

    Device {
        name: name.to_string(),
        model: v.get("model_name").and_then(|x| x.as_str()).map(String::from),
        self_assessment_passed: v
            .get("smart_status")
            .and_then(|s| s.get("passed"))
            .and_then(|x| x.as_bool()),

        reallocated_sectors: attr(5),
        pending_sectors: attr(197),
        uncorrectable: attr(198),
        crc_errors: attr(199),
        power_on_hours: attr(9).or_else(|| n("power_on_hours")),

        percentage_used: n("percentage_used").map(|x| x.min(255) as u8),
        available_spare: n("available_spare").map(|x| x.min(255) as u8),
        available_spare_threshold: n("available_spare_threshold").map(|x| x.min(255) as u8),
        media_errors: n("media_errors"),
        critical_warning: n("critical_warning").map(|x| x.min(255) as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spinning(realloc: u64, pending: u64) -> Device {
        Device {
            name: "sda".into(),
            self_assessment_passed: Some(true),
            reallocated_sectors: Some(realloc),
            pending_sectors: Some(pending),
            ..Device::default()
        }
    }

    #[test]
    fn a_healthy_drive_says_so() {
        assert_eq!(assess(&spinning(0, 0), None), Verdict::Healthy);
    }

    #[test]
    fn an_old_static_count_is_not_an_alert() {
        // Drives ship with spare sectors precisely so a handful can be retired
        // without incident. A drive that has sat at 40 for two years has
        // already survived whatever caused them.
        let d = spinning(40, 0);
        assert_eq!(assess(&d, Some(&d)), Verdict::StableWithHistory { reallocated: 40 });
        assert!(!assess(&d, Some(&d)).is_actionable());
    }

    #[test]
    fn a_count_that_moved_is_the_alert() {
        // Twelve is a smaller number than forty and a much worse sign.
        let before = spinning(8, 0);
        let now = spinning(12, 0);
        assert_eq!(
            assess(&now, Some(&before)),
            Verdict::Deteriorating { what: "reallocated_sectors".into(), from: 8, to: 12 }
        );
        assert!(assess(&now, Some(&before)).is_actionable());
    }

    #[test]
    fn pending_outranks_reallocated_when_both_moved() {
        // Pending sectors are the earlier signal: they are sectors the drive
        // has not yet been able to retire.
        let before = spinning(8, 0);
        let now = spinning(12, 3);
        assert_eq!(
            assess(&now, Some(&before)),
            Verdict::Deteriorating { what: "pending_sectors".into(), from: 0, to: 3 }
        );
    }

    #[test]
    fn a_drive_that_says_it_is_failing_outranks_every_counter() {
        let d = Device { self_assessment_passed: Some(false), ..spinning(0, 0) };
        assert_eq!(assess(&d, None), Verdict::SelfReportedFailing);
    }

    #[test]
    fn an_nvme_critical_warning_is_the_same_thing() {
        let d = Device { name: "nvme0n1".into(), critical_warning: Some(0x04), ..Device::default() };
        assert_eq!(assess(&d, None), Verdict::SelfReportedFailing);
    }

    #[test]
    fn spare_is_judged_against_the_manufacturers_own_floor() {
        // Endurance varies by an order of magnitude across drive classes, so a
        // fixed threshold invented here would be wrong for most of them.
        let d = Device {
            name: "nvme0n1".into(),
            available_spare: Some(9),
            available_spare_threshold: Some(10),
            ..Device::default()
        };
        assert_eq!(assess(&d, None), Verdict::SpareExhausted { available: 9, threshold: 10 });

        let ok = Device { available_spare: Some(11), ..d };
        assert!(!assess(&ok, None).is_actionable());
    }

    #[test]
    fn wear_is_flagged_before_the_rated_life_is_reached() {
        // A drive at its rated life is not a surprise to plan around; it is one
        // to have already planned around.
        let d = Device { name: "nvme0n1".into(), percentage_used: Some(92), ..Device::default() };
        assert_eq!(assess(&d, None), Verdict::Worn { percentage_used: 92 });
        let young = Device { percentage_used: Some(40), ..d };
        assert!(!assess(&young, None).is_actionable());
    }

    #[test]
    fn a_cable_fault_does_not_send_somebody_to_replace_a_healthy_disk() {
        // Actionable, but not the drive's fault. Swapping it would not fix
        // anything, and the next alert would be trusted less.
        let d = Device { crc_errors: Some(37), ..spinning(0, 0) };
        let v = assess(&d, None);
        assert_eq!(v, Verdict::LinkErrors { crc: 37 });
        assert!(v.is_actionable());
        assert!(!v.implicates_the_drive());
    }

    #[test]
    fn a_failing_disk_on_a_bad_cable_is_reported_as_a_failing_disk() {
        let d = Device {
            crc_errors: Some(37),
            self_assessment_passed: Some(false),
            ..spinning(0, 0)
        };
        assert_eq!(assess(&d, None), Verdict::SelfReportedFailing);
    }

    #[test]
    fn a_silent_device_is_distinguishable_from_a_healthy_one() {
        // "Said nothing" and "said it is fine" are different, and conflating
        // them means a drive with SMART disabled reads as healthy forever.
        let d = Device { name: "sdb".into(), ..Device::default() };
        assert_eq!(assess(&d, None), Verdict::NotReported);
        assert!(!assess(&d, None).is_actionable());
    }

    #[test]
    fn smartctl_output_parses_for_both_vocabularies() {
        let ata = json!({
            "model_name": "ST4000NM0035",
            "smart_status": { "passed": true },
            "ata_smart_attributes": { "table": [
                { "id": 5,   "raw": { "value": 8 } },
                { "id": 197, "raw": { "value": 0 } },
                { "id": 199, "raw": { "value": 2 } },
                { "id": 9,   "raw": { "value": 41231 } }
            ]}
        });
        let d = parse_smartctl("sda", &ata);
        assert_eq!(d.reallocated_sectors, Some(8));
        assert_eq!(d.crc_errors, Some(2));
        assert_eq!(d.power_on_hours, Some(41231));
        assert_eq!(d.model.as_deref(), Some("ST4000NM0035"));

        let nvme = json!({
            "model_name": "Samsung SSD 980",
            "smart_status": { "passed": true },
            "nvme_smart_health_information_log": {
                "critical_warning": 0,
                "percentage_used": 3,
                "available_spare": 100,
                "available_spare_threshold": 10,
                "media_errors": 0,
                "power_on_hours": 9001
            }
        });
        let d = parse_smartctl("nvme0n1", &nvme);
        assert_eq!(d.percentage_used, Some(3));
        assert_eq!(d.available_spare_threshold, Some(10));
        assert_eq!(d.power_on_hours, Some(9001));
        assert_eq!(assess(&d, None), Verdict::Healthy);
    }

    #[test]
    fn an_empty_response_yields_a_device_that_reported_nothing() {
        // Rather than a device that reported zeroes, which would read as a
        // perfectly healthy disk.
        let d = parse_smartctl("sdz", &json!({}));
        assert_eq!(assess(&d, None), Verdict::NotReported);
        assert!(d.reallocated_sectors.is_none());
    }
}
