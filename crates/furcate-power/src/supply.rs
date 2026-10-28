//! A board's own report of its power supply.
//!
//! A board OS that can see its supply publishes it as one JSON object,
//! rewritten atomically every few seconds: on a Raspberry Pi, what the
//! firmware says about undervoltage and throttling, the 5 V rail, the SoC
//! temperature, the supply's current limit and whether the board is shedding
//! load. This reads that file and nothing else; it does not ask the firmware
//! itself, because the board OS owns that conversation.
//!
//! A missing file, one that does not parse, or one older than
//! [`STALE_SECS`] is "not measured", never "healthy". Every field the report
//! leaves out stays out: nothing here fills a gap with a default.

use furcate_topology::cell::SupplyState;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod ups;

/// Where the board OS publishes the report.
pub const STATUS_PATH: &str = "/run/furcate-os/power.status";

/// The report is rewritten every 5 s; one older than this is not current.
pub const STALE_SECS: u64 = 15;

/// The report as the board writes it. Every field optional except the time it
/// was taken, so a board that measures less is read for what it does say.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupplyStatus {
    /// Unix seconds when the board took the reading.
    pub ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply_max_current_ma: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usb_high_current: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undervoltage_now: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undervoltage_since_boot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freq_capped_now: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttled_now: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_temp_limit_now: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttled_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext5v_v: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soc_temp_c: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_shed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shed_since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_max_khz: Option<u64>,
}

impl SupplyStatus {
    /// The supply in one state, worst first. `None` when the report does not
    /// say enough to call it healthy: `Ok` needs undervoltage and throttling
    /// both measured and both clear.
    pub fn state(&self) -> Option<SupplyState> {
        if self.load_shed == Some(true) {
            return Some(SupplyState::Shedding);
        }
        if self.undervoltage_now == Some(true) {
            return Some(SupplyState::Undervoltage);
        }
        if self.throttled_now == Some(true) || self.freq_capped_now == Some(true) {
            return Some(SupplyState::Throttled);
        }
        match (self.undervoltage_now, self.throttled_now) {
            (Some(false), Some(false)) => Some(SupplyState::Ok),
            _ => None,
        }
    }
}

/// What reading the report found.
#[derive(Clone, Debug, PartialEq)]
pub enum Supply {
    /// A current report.
    Measured(SupplyStatus),
    /// No current report, and why.
    NotMeasured(String),
}

impl Supply {
    /// The supply's state when measured and decided.
    pub fn state(&self) -> Option<SupplyState> {
        match self {
            Supply::Measured(s) => s.state(),
            Supply::NotMeasured(_) => None,
        }
    }

    /// As node facts give it: the report with its age and state, or why
    /// there is none.
    pub fn to_json(&self, now: u64) -> serde_json::Value {
        match self {
            Supply::Measured(s) => serde_json::json!({
                "measured": true,
                "state": s.state(),
                "age_secs": now.saturating_sub(s.ts),
                "status": s,
            }),
            Supply::NotMeasured(why) => serde_json::json!({ "measured": false, "why": why }),
        }
    }
}

/// Read the board's report at `path` as of `now` (Unix seconds).
pub fn read_at(path: &Path, now: u64) -> Supply {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Supply::NotMeasured(format!("{} does not exist; this board publishes no supply report", path.display()))
        }
        Err(e) => return Supply::NotMeasured(format!("{} cannot be read: {e}", path.display())),
    };
    let status: SupplyStatus = match serde_json::from_slice(&raw) {
        Ok(s) => s,
        Err(e) => return Supply::NotMeasured(format!("{} is not a supply report: {e}", path.display())),
    };
    if status.ts > now.saturating_add(STALE_SECS) {
        return Supply::NotMeasured(format!(
            "the supply report is dated {}s in the future; the clocks disagree",
            status.ts - now
        ));
    }
    let age = now.saturating_sub(status.ts);
    if age > STALE_SECS {
        return Supply::NotMeasured(format!("the supply report is {age}s old (stale after {STALE_SECS}s)"));
    }
    Supply::Measured(status)
}

/// Read the board's report from [`STATUS_PATH`].
pub fn read(now: u64) -> Supply {
    read_at(Path::new(STATUS_PATH), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{"ts":1000,"supply_max_current_ma":1500,"usb_high_current":false,
 "undervoltage_now":false,"undervoltage_since_boot":true,"freq_capped_now":false,
 "throttled_now":false,"soft_temp_limit_now":false,"throttled_raw":"0x50000",
 "ext5v_v":5.08,"soc_temp_c":52.1,"load_shed":false,"shed_since":null,
 "cpu_max_khz":2400000}"#;

    fn file(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("furcate-supply-{name}-{}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn a_fresh_report_is_read_as_written() {
        let p = file("fresh", REPORT);
        let Supply::Measured(s) = read_at(&p, 1005) else { panic!("fresh report not read") };
        assert_eq!(s.supply_max_current_ma, Some(1500));
        assert_eq!(s.ext5v_v, Some(5.08));
        assert_eq!(s.undervoltage_since_boot, Some(true));
        assert_eq!(s.shed_since, None);
        assert_eq!(s.state(), Some(SupplyState::Ok), "a past undervoltage is history, not the state now");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn stale_missing_future_and_garbled_reports_are_not_measured() {
        let p = file("stale", REPORT);
        assert!(matches!(read_at(&p, 1016), Supply::NotMeasured(w) if w.contains("16s old")));
        assert!(matches!(read_at(&p, 900), Supply::NotMeasured(w) if w.contains("future")));
        let _ = std::fs::remove_file(&p);
        assert!(matches!(read_at(&p, 1000), Supply::NotMeasured(w) if w.contains("does not exist")));
        let g = file("garbled", "{\"undervoltage_now\":true}");
        assert!(matches!(read_at(&g, 1000), Supply::NotMeasured(w) if w.contains("not a supply report")));
        let _ = std::fs::remove_file(g);
        assert_eq!(Supply::NotMeasured("x".into()).state(), None);
    }

    #[test]
    fn the_state_is_the_worst_thing_measured_and_never_invented() {
        let base: SupplyStatus = serde_json::from_str(REPORT).unwrap();
        let with = |f: &dyn Fn(&mut SupplyStatus)| {
            let mut s = base.clone();
            f(&mut s);
            s.state()
        };
        assert_eq!(with(&|s| s.throttled_now = Some(true)), Some(SupplyState::Throttled));
        assert_eq!(with(&|s| s.undervoltage_now = Some(true)), Some(SupplyState::Undervoltage));
        assert_eq!(
            with(&|s| {
                s.undervoltage_now = Some(true);
                s.load_shed = Some(true);
            }),
            Some(SupplyState::Shedding)
        );
        // A report that does not say whether it is throttled is not healthy.
        assert_eq!(with(&|s| s.throttled_now = None), None);
        let sparse: SupplyStatus = serde_json::from_str("{\"ts\":5}").unwrap();
        assert_eq!(sparse.state(), None);
        let j = serde_json::to_value(&sparse).unwrap();
        assert_eq!(j, serde_json::json!({"ts": 5}), "absent fields stay absent");
    }
}
