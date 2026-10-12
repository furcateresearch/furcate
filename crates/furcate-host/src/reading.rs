//! A value together with where it came from.
//!
//! Small boards report the same quantity through several interfaces, and they
//! do not agree on which ones exist. A Jetson Orin answers GPU load through
//! `tegrastats` and devfreq but not NVML; a Thor answers through NVML but
//! leaves clocks and power blank; a Raspberry Pi has no GPU counter at all.
//! A reading that does not say which interface produced it cannot be compared
//! across those machines, and a reading that defaults to zero when nothing
//! answered is worse than none: zero watts and zero load are real values that
//! a scheduler will act on.
//!
//! So every value here is either [`Reading::Measured`] with its [`Source`], or
//! [`Reading::NotMeasured`]. There is no third state and no default.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The interface a value was read through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// NVIDIA Management Library, as reported by `nvidia-smi`.
    #[serde(rename = "nvml")]
    Nvml,
    /// One line of Jetson `tegrastats` output.
    #[serde(rename = "tegrastats")]
    Tegrastats,
    /// The kernel's devfreq node for the device, and its `load` attribute.
    #[serde(rename = "sysfs-devfreq")]
    SysfsDevfreq,
    /// A TI INA3221 three-channel monitor through hwmon.
    #[serde(rename = "hwmon-ina3221")]
    HwmonIna3221,
    /// A TI INA228/INA237/INA238 monitor through hwmon.
    #[serde(rename = "hwmon-ina238")]
    HwmonIna238,
    /// A TI INA2xx (INA219/INA226 class) monitor through hwmon.
    #[serde(rename = "hwmon-ina2xx")]
    HwmonIna2xx,
    /// The Raspberry Pi 5 power management IC, via `vcgencmd pmic_read_adc`.
    #[serde(rename = "pi-pmic")]
    PiPmic,
    /// The VideoCore firmware, via `vcgencmd measure_temp`.
    #[serde(rename = "vcgencmd")]
    Vcgencmd,
    /// A kernel thermal zone.
    #[serde(rename = "thermal-zone")]
    ThermalZone,
    /// Intel/AMD RAPL energy counters through powercap.
    #[serde(rename = "rapl")]
    Rapl,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Nvml => "nvml",
            Source::Tegrastats => "tegrastats",
            Source::SysfsDevfreq => "sysfs-devfreq",
            Source::HwmonIna3221 => "hwmon-ina3221",
            Source::HwmonIna238 => "hwmon-ina238",
            Source::HwmonIna2xx => "hwmon-ina2xx",
            Source::PiPmic => "pi-pmic",
            Source::Vcgencmd => "vcgencmd",
            Source::ThermalZone => "thermal-zone",
            Source::Rapl => "rapl",
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value and its source, or the statement that nothing measured it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Reading<T> {
    Measured { value: T, source: Source },
    NotMeasured,
}

impl<T> Reading<T> {
    pub fn measured(value: T, source: Source) -> Self {
        Reading::Measured { value, source }
    }

    /// A reading from `source` when `value` is present, otherwise not measured.
    pub fn from_option(value: Option<T>, source: Source) -> Self {
        match value {
            Some(value) => Reading::Measured { value, source },
            None => Reading::NotMeasured,
        }
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Reading::Measured { value, .. } => Some(value),
            Reading::NotMeasured => None,
        }
    }

    pub fn source(&self) -> Option<Source> {
        match self {
            Reading::Measured { source, .. } => Some(*source),
            Reading::NotMeasured => None,
        }
    }

    pub fn is_measured(&self) -> bool {
        matches!(self, Reading::Measured { .. })
    }

    /// This reading if measured, otherwise `next`. Sources are tried in the
    /// caller's order and the first that answered is the one reported.
    pub fn or(self, next: Reading<T>) -> Reading<T> {
        match self {
            Reading::Measured { .. } => self,
            Reading::NotMeasured => next,
        }
    }
}

impl<T: fmt::Display> fmt::Display for Reading<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reading::Measured { value, source } => write!(f, "{value} ({source})"),
            Reading::NotMeasured => f.write_str("not measured"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_is_not_measured_rather_than_zero() {
        let r: Reading<f64> = Reading::from_option(None, Source::Tegrastats);
        assert_eq!(r, Reading::NotMeasured);
        assert_eq!(r.to_string(), "not measured");
        assert_eq!(serde_json::to_value(&r).unwrap(), serde_json::json!({"state": "not_measured"}));
    }

    #[test]
    fn first_measured_source_wins() {
        let r = Reading::NotMeasured
            .or(Reading::measured(41.0, Source::Tegrastats))
            .or(Reading::measured(40.0, Source::SysfsDevfreq));
        assert_eq!(r.source(), Some(Source::Tegrastats));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["source"], "tegrastats");
        assert_eq!(v["state"], "measured");
    }

    #[test]
    fn serde_names_match_as_str() {
        for s in [
            Source::Nvml,
            Source::Tegrastats,
            Source::SysfsDevfreq,
            Source::HwmonIna3221,
            Source::HwmonIna238,
            Source::HwmonIna2xx,
            Source::PiPmic,
            Source::Vcgencmd,
            Source::ThermalZone,
            Source::Rapl,
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
    }
}
