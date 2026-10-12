//! Reading power from board rail monitors.
//!
//! [`crate::rapl`] covers x86. ARM boards have no RAPL; what they have instead
//! is current-sense monitors on the supply rails, and on a Raspberry Pi 5 the
//! power management IC itself. Both are read here, alongside RAPL rather than
//! in place of it, and each rail carries the [`Source`] it was read from.
//!
//! ## What is read
//!
//! * **INA3221** (Jetson Orin carrier boards): three channels per chip through
//!   hwmon, `inN_label` naming the rail (`VDD_IN`, `VDD_CPU_GPU_CV`,
//!   `VDD_SOC`), `inN_input` the bus voltage in mV and `currN_input` the
//!   current in mA. Power is their product.
//! * **INA228/INA237/INA238** and the older **INA2xx** parts: one channel,
//!   bus voltage on `in1_input`, current on `curr1_input`, and power directly
//!   on `power1_input` in microwatts. The rail name is the hwmon `label` when
//!   the device tree sets one.
//! * **Raspberry Pi 5 PMIC**, via `vcgencmd pmic_read_adc`: a current and a
//!   voltage per rail, paired by name.
//!
//! ## What the numbers are not
//!
//! Rails nest. On a Jetson `VDD_IN` is the module input and the other channels
//! are parts of it, so the channels must never be summed. On a Pi the PMIC
//! rails are downstream of the 5 V input and exclude conversion loss, USB and
//! anything on the header, so their sum is a lower bound on board draw, the
//! same caveat RAPL carries. A rail whose voltage or current did not read is
//! [`Reading::NotMeasured`], and so is its power: never zero.

use furcate_host::reading::{Reading, Source};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const HWMON_ROOT: &str = "/sys/class/hwmon";

/// One supply rail.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rail {
    pub name: String,
    pub volts: Reading<f64>,
    pub amps: Reading<f64>,
    pub watts: Reading<f64>,
}

fn product(v: &Reading<f64>, a: &Reading<f64>, source: Source) -> Reading<f64> {
    match (v.value(), a.value()) {
        (Some(v), Some(a)) => Reading::measured(v * a, source),
        _ => Reading::NotMeasured,
    }
}

fn read_num(p: PathBuf) -> Option<f64> {
    std::fs::read_to_string(p).ok()?.trim().parse::<f64>().ok()
}

fn read_label(p: PathBuf) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Every rail exposed by a recognised current monitor under `root`
/// (normally [`HWMON_ROOT`]).
pub fn discover_hwmon(root: &Path) -> Vec<Rail> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    dirs.sort();

    let mut rails = Vec::new();
    for dir in dirs {
        let Some(chip) = read_label(dir.join("name")) else { continue };
        let hwmon = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        match chip.as_str() {
            "ina3221" => {
                for ch in 1..=3 {
                    let volts = Reading::from_option(
                        read_num(dir.join(format!("in{ch}_input"))).map(|mv| mv / 1000.0),
                        Source::HwmonIna3221,
                    );
                    let amps = Reading::from_option(
                        read_num(dir.join(format!("curr{ch}_input"))).map(|ma| ma / 1000.0),
                        Source::HwmonIna3221,
                    );
                    // A channel with neither reading is disabled in the
                    // device tree, not a rail at zero.
                    if !volts.is_measured() && !amps.is_measured() {
                        continue;
                    }
                    let name = read_label(dir.join(format!("in{ch}_label")))
                        .unwrap_or_else(|| format!("{chip}:{hwmon}:ch{ch}"));
                    let watts = product(&volts, &amps, Source::HwmonIna3221);
                    rails.push(Rail { name, volts, amps, watts });
                }
            }
            "ina228" | "ina237" | "ina238" | "ina219" | "ina220" | "ina226" | "ina230" | "ina231"
            | "ina260" => {
                let source = if matches!(chip.as_str(), "ina228" | "ina237" | "ina238") {
                    Source::HwmonIna238
                } else {
                    Source::HwmonIna2xx
                };
                let volts = Reading::from_option(read_num(dir.join("in1_input")).map(|mv| mv / 1000.0), source);
                let amps = Reading::from_option(read_num(dir.join("curr1_input")).map(|ma| ma / 1000.0), source);
                let direct = Reading::from_option(read_num(dir.join("power1_input")).map(|uw| uw / 1e6), source);
                if !volts.is_measured() && !amps.is_measured() && !direct.is_measured() {
                    continue;
                }
                let watts = direct.or(product(&volts, &amps, source));
                let name = read_label(dir.join("label")).unwrap_or_else(|| format!("{chip}:{hwmon}"));
                rails.push(Rail { name, volts, amps, watts });
            }
            _ => {}
        }
    }
    rails
}

/// Parse `vcgencmd pmic_read_adc`.
///
/// Lines look like `VDD_CORE_A current(7)=0.97818500A` and
/// `VDD_CORE_V volt(15)=0.72475400V`; the `_A`/`_V` suffix pairs them. Rails
/// with only a voltage (`EXT5V_V`, `BATT_V`) are reported with current and
/// power not measured.
pub fn parse_pmic_read_adc(text: &str) -> Vec<Rail> {
    let mut rails: Vec<Rail> = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some(label), Some(value)) = (words.next(), words.next()) else { continue };
        let Some((_, number)) = value.split_once('=') else { continue };
        let (name, is_current) = if let Some(n) = label.strip_suffix("_A") {
            (n, true)
        } else if let Some(n) = label.strip_suffix("_V") {
            (n, false)
        } else {
            continue;
        };
        let Ok(x) = number.trim_end_matches(['A', 'V']).parse::<f64>() else { continue };

        let idx = match rails.iter().position(|r| r.name == name) {
            Some(i) => i,
            None => {
                rails.push(Rail {
                    name: name.to_string(),
                    volts: Reading::NotMeasured,
                    amps: Reading::NotMeasured,
                    watts: Reading::NotMeasured,
                });
                rails.len() - 1
            }
        };
        let r = &mut rails[idx];
        if is_current {
            r.amps = Reading::measured(x, Source::PiPmic);
        } else {
            r.volts = Reading::measured(x, Source::PiPmic);
        }
        r.watts = product(&r.volts, &r.amps, Source::PiPmic);
    }
    rails
}

/// Read the Pi 5 PMIC rails. An error when `vcgencmd` is missing or the
/// firmware does not support the command (boards before the Pi 5).
pub fn read_pi_pmic() -> anyhow::Result<Vec<Rail>> {
    let out = std::process::Command::new("vcgencmd").arg("pmic_read_adc").output()?;
    if !out.status.success() {
        anyhow::bail!("vcgencmd pmic_read_adc failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let rails = parse_pmic_read_adc(&String::from_utf8_lossy(&out.stdout));
    if rails.is_empty() {
        anyhow::bail!("vcgencmd pmic_read_adc returned no rails");
    }
    Ok(rails)
}

/// Sum of PMIC rail power: a lower bound on what the board draws (see the
/// module doc). Not measured unless at least one rail has power.
pub fn pmic_lower_bound_watts(rails: &[Rail]) -> Reading<f64> {
    let measured: Vec<f64> = rails.iter().filter_map(|r| r.watts.value().copied()).collect();
    if measured.is_empty() {
        return Reading::NotMeasured;
    }
    Reading::measured(measured.iter().sum(), Source::PiPmic)
}

/// A Jetson power mode, from `nvpmodel -q`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerMode {
    pub name: String,
    pub id: Option<u32>,
}

/// Parse `nvpmodel -q`: `NV Power Mode: MAXN` followed by the mode number.
pub fn parse_nvpmodel(text: &str) -> Option<PowerMode> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let name = lines
        .find_map(|l| l.strip_prefix("NV Power Mode:"))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())?;
    let id = lines.next().and_then(|l| l.parse::<u32>().ok());
    Some(PowerMode { name, id })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-rails-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn files(dir: &Path, entries: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        for (n, v) in entries {
            std::fs::write(dir.join(n), v).unwrap();
        }
    }

    #[test]
    fn hwmon_ina3221_and_ina238() {
        let d = scratch("hwmon");
        files(
            &d.join("hwmon1"),
            &[
                ("name", "ina3221\n"),
                ("in1_label", "VDD_IN\n"),
                ("in1_input", "5072\n"),
                ("curr1_input", "960\n"),
                ("in2_label", "VDD_CPU_GPU_CV\n"),
                ("in2_input", "5064\n"),
                ("curr2_input", "96\n"),
                // Channel 3 disabled: no readings at all.
                ("in3_label", "VDD_SOC\n"),
            ],
        );
        files(
            &d.join("hwmon2"),
            &[("name", "ina238\n"), ("in1_input", "12000\n"), ("curr1_input", "2500\n"), ("power1_input", "30100000\n")],
        );
        files(&d.join("hwmon0"), &[("name", "cpu_thermal\n"), ("temp1_input", "45000\n")]);

        let rails = discover_hwmon(&d);
        assert_eq!(rails.len(), 3);
        assert_eq!(rails[0].name, "VDD_IN");
        assert_eq!(rails[0].watts.source(), Some(Source::HwmonIna3221));
        assert!((rails[0].watts.value().unwrap() - 4.869).abs() < 0.001);
        assert_eq!(rails[1].name, "VDD_CPU_GPU_CV");
        assert_eq!(rails[2].name, "ina238:hwmon2");
        assert_eq!(rails[2].watts, Reading::measured(30.1, Source::HwmonIna238));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn missing_current_means_power_not_measured() {
        let d = scratch("partial");
        files(&d.join("hwmon0"), &[("name", "ina3221\n"), ("in1_label", "VDD_IN\n"), ("in1_input", "5000\n")]);
        let rails = discover_hwmon(&d);
        assert_eq!(rails[0].amps, Reading::NotMeasured);
        assert_eq!(rails[0].watts, Reading::NotMeasured);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pi5_pmic() {
        let rails = parse_pmic_read_adc(include_str!("testdata/pmic_read_adc"));
        let core = rails.iter().find(|r| r.name == "VDD_CORE").unwrap();
        assert_eq!(core.amps, Reading::measured(0.978185, Source::PiPmic));
        assert!((core.watts.value().unwrap() - 0.978185 * 0.724754).abs() < 1e-9);
        let ext = rails.iter().find(|r| r.name == "EXT5V").unwrap();
        assert!(ext.volts.is_measured());
        assert_eq!(ext.watts, Reading::NotMeasured);
        let total = pmic_lower_bound_watts(&rails);
        assert_eq!(total.source(), Some(Source::PiPmic));
        assert!(*total.value().unwrap() > 0.7);
        assert_eq!(pmic_lower_bound_watts(&[]), Reading::NotMeasured);
    }

    #[test]
    fn nvpmodel() {
        let m = parse_nvpmodel("NV Power Mode: MAXN_SUPER\n2\n").unwrap();
        assert_eq!((m.name.as_str(), m.id), ("MAXN_SUPER", Some(2)));
        assert_eq!(parse_nvpmodel("nvpmodel: error\n"), None);
    }
}
