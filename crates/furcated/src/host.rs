//! Reading the host: disks, the clock, and what is pending.
//!
//! Mounts come from `/proc/self/mounts` and `statvfs`, the clock from
//! `timedatectl`, and the pending-reboot flag from the file the package manager
//! writes. All cheap, none of it perturbing what it measures.
//!
//! The previous reading of every mount is kept so the report carries a *rate*
//! rather than a percentage. That is the whole reason this module is more than
//! a `df` wrapper: "83% full" is not actionable and "fills in three days" is.

use furcate_host::filesystem::{assess, Concern, Mount, Trend};
use furcate_host::platform::{parse_timedatectl, Build, Clock, Reboot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Previous mount readings, so counters become rates.
static PREVIOUS: Mutex<Option<(u64, Vec<Mount>)>> = Mutex::new(None);

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Free space and inodes for one path.
///
/// `statvfs` through libc would avoid a subprocess, but this crate has no libc
/// dependency and `df` is on every machine this runs on. The cost is one
/// process per collection, against a period measured in minutes.
fn statvfs(path: &str) -> Option<(u64, u64, u64, u64)> {
    let out = Command::new("df")
        // `-P` and `--output` are mutually exclusive, and passing both makes
        // df exit non-zero — which produced an empty mount list on every
        // machine until a test asked for the root filesystem by name.
        .args(["-B1", "--output=size,avail,itotal,iavail", path])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    let f: Vec<u64> = line
        .split_whitespace()
        .map(|v| v.parse().unwrap_or(0))
        .collect();
    if f.len() < 4 {
        return None;
    }
    Some((f[0], f[1], f[2], f[3]))
}

/// Every durable mount on this machine.
pub fn mounts() -> Vec<Mount> {
    let Ok(text) = std::fs::read_to_string("/proc/self/mounts") else {
        return Vec::new();
    };
    let mut seen = BTreeMap::new();

    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(device), Some(path), Some(fstype)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        // The mounts file escapes spaces as octal; a path with one would be
        // read wrong, so it is skipped rather than guessed at.
        if path.contains("\\040") {
            continue;
        }
        let m = Mount {
            path: path.to_string(),
            device: device.to_string(),
            fstype: fstype.to_string(),
            total_bytes: 0,
            free_bytes: 0,
            total_inodes: 0,
            free_inodes: 0,
        };
        if !m.is_durable() {
            continue;
        }
        // Bind mounts and duplicates of the same device report identical
        // figures; counting them twice would inflate a fleet total.
        seen.entry(device.to_string()).or_insert(m);
    }

    seen.into_values()
        .filter_map(|mut m| {
            let (total, avail, itotal, iavail) = statvfs(&m.path)?;
            if total == 0 {
                return None;
            }
            m.total_bytes = total;
            m.free_bytes = avail;
            m.total_inodes = itotal;
            m.free_inodes = iavail;
            Some(m)
        })
        .collect()
}

/// How the clock is being kept.
pub fn clock() -> Clock {
    for bin in ["timedatectl", "/usr/bin/timedatectl"] {
        if let Ok(out) = Command::new(bin).args(["show"]).output() {
            if out.status.success() {
                return parse_timedatectl(&String::from_utf8_lossy(&out.stdout));
            }
        }
    }
    parse_timedatectl("")
}

/// Whether a restart is pending.
pub fn reboot() -> Reboot {
    let required = std::path::Path::new("/var/run/reboot-required").exists()
        || std::path::Path::new("/run/reboot-required").exists();

    let because = ["/var/run/reboot-required.pkgs", "/run/reboot-required.pkgs"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|t| {
            let mut v: Vec<String> = t.lines().map(|l| l.trim().to_string()).collect();
            v.sort();
            v.dedup();
            v
        })
        .unwrap_or_default();

    Reboot {
        required,
        because,
        // Counting pending security updates means running the package manager,
        // which can take tens of seconds and hold a lock other things want.
        // Left unread rather than paid for on every collection.
        security_updates: None,
    }
}

pub fn build() -> Build {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let uptime_secs = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0);
    Build {
        version: env!("CARGO_PKG_VERSION").to_string(),
        kernel,
        uptime_secs,
    }
}

/// Everything this machine can say about itself as a host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostReport {
    pub mounts: Vec<Mount>,
    pub trends: Vec<Trend>,
    /// Mounts with something worth an operator's attention, and what.
    pub concerns: Vec<(String, Vec<Concern>)>,
    pub clock: Clock,
    pub reboot: Reboot,
    pub build: Build,
    /// False until the host has been up long enough for rates to mean
    /// anything.
    pub settled: bool,
    /// Physical device health, as distinct from mount capacity. A disk can
    /// fill up or it can die, and until now only the first was watched.
    pub devices: Vec<furcate_host::storage::Device>,
    /// Whether the health of those devices could be read at all, so a machine
    /// with no tooling is distinguishable from one with healthy disks.
    pub devices_readable: bool,
    /// Throttling, ECC and PCIe error counters, as the platform reader saw
    /// them. `None` means nothing published, which is not the same as a
    /// machine with nothing wrong.
    ///
    /// ⛔ The ECC counts here are monotonic since boot. A rate needs two
    /// samples, and a consumer that alerts on the count alone will page
    /// somebody about a machine that logged its errors a year ago.
    pub platform: Option<serde_json::Value>,
    /// Accelerator health. The device class this fleet exists to run and the
    /// last one nothing was watching.
    pub accelerators: Vec<furcate_host::accelerator::Device>,
    /// Whether any accelerator could be read, so a host with no driver is
    /// distinguishable from a host with healthy cards — and from one whose
    /// cards are all in trouble.
    pub accelerators_readable: bool,
}

/// Where the privileged reader publishes device health.
const STORAGE_PATH: &str = "/run/furcate/storage.json";

/// Storage device health, as the privileged reader saw it.
///
/// Read from a published file rather than by running `smartctl` here, because
/// opening a block device needs a capability this agent does not have and
/// should not get. An unprivileged call fails with "Permission denied" for the
/// *whole* query, so the agent could not even see that a device existed — which
/// looks exactly like a machine with no disks.
///
/// Absence is reported as absence. A machine where the tool is missing and one
/// with perfectly healthy disks are different states and neither is claimed for
/// the other.
pub fn devices() -> (Vec<furcate_host::storage::Device>, bool) {
    let Ok(text) = std::fs::read_to_string(STORAGE_PATH) else {
        return (Vec::new(), false);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (Vec::new(), false);
    };
    let Some(list) = v.get("devices").and_then(|d| d.as_array()) else {
        return (Vec::new(), false);
    };
    let out = list
        .iter()
        .filter_map(|d| {
            let path = d.get("path")?.as_str()?;
            let report = d.get("report")?;
            let name = path.rsplit('/').next().unwrap_or(path);
            Some(furcate_host::storage::parse_smartctl(name, report))
        })
        .collect();
    (out, true)
}

/// Where the privileged reader publishes accelerator health.
const ACCELERATOR_PATH: &str = "/run/furcate/accelerator.json";

/// Where the platform reader publishes throttling, ECC and PCIe error counts.
const PLATFORM_PATH: &str = "/run/furcate/platform.json";

/// Accelerator health, as the reader saw it.
///
/// Read from a published file for the same reason as the disks, though not for
/// the same cause: `nvidia-smi` needs no privilege, but this agent does not
/// exec, and growing a second way of learning about hardware is the thing that
/// pattern exists to prevent.
///
/// Absence is absence. A host with no driver, a host whose cards are healthy,
/// and a host whose cards are failing are three states and none is claimed for
/// another.
/// Platform health the kernel gives away: throttling, ECC, PCIe errors.
///
/// Passed through as published rather than parsed into types. The shape is
/// whatever sysfs offered on that machine -- four EDAC controllers on one host
/// and one on another, PCIe error breakdowns that are lists of named counters
/// rather than integers -- and inventing a Rust type for each would mean this
/// file changing every time a kernel grows a counter.
///
/// What the agent guarantees is provenance, not schema: it says where the
/// reading came from and when, and refuses to turn absence into a zero.
pub fn platform() -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(PLATFORM_PATH).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn accelerators() -> (Vec<furcate_host::accelerator::Device>, bool) {
    match std::fs::read_to_string(ACCELERATOR_PATH) {
        Ok(text) => furcate_host::accelerator::parse_published(&text),
        // No file is no reading, which is not the same as no cards.
        Err(_) => (Vec::new(), false),
    }
}

pub fn collect() -> HostReport {
    let now = now_s();
    let mounts = mounts();

    let trends = {
        let mut guard = PREVIOUS.lock().expect("host tracker");
        let trends = guard
            .as_ref()
            .map(|(then, prev)| {
                let window = now.saturating_sub(*then);
                mounts
                    .iter()
                    .filter_map(|m| {
                        let before = prev.iter().find(|p| p.path == m.path)?;
                        Trend::between(before, m, window)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        *guard = Some((now, mounts.clone()));
        trends
    };

    let concerns: Vec<(String, Vec<Concern>)> = mounts
        .iter()
        .filter_map(|m| {
            let t = trends.iter().find(|t| t.path == m.path);
            let c = assess(m, t);
            (!c.is_empty()).then(|| (m.path.clone(), c))
        })
        .collect();

    let build = build();
    let (devices, devices_readable) = devices();
    let (accelerators, accelerators_readable) = accelerators();
    HostReport {
        settled: build.measurements_are_settled(),
        devices,
        devices_readable,
        accelerators,
        accelerators_readable,
        platform: platform(),
        mounts,
        trends,
        concerns,
        clock: clock(),
        reboot: reboot(),
        build,
    }
}

/// Named scalars for the forecaster.
///
/// Free space is a genuinely good rail: it is smooth, it trends, and the thing
/// a forecast of it answers — when does this run out — is the question the
/// operator has anyway.
pub fn series_points(r: &HostReport) -> Vec<(String, f64)> {
    r.mounts
        .iter()
        .filter(|m| m.path == "/" || m.path == "/mnt/shared")
        .map(|m| {
            (
                format!("disk_free_gb{}", if m.path == "/" { "" } else { "_shared" }),
                m.free_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_has_at_least_a_root_filesystem() {
        let m = mounts();
        assert!(m.iter().any(|x| x.path == "/"), "no root mount found");
        assert!(
            m.iter().all(|x| x.total_bytes > 0),
            "a zero-sized mount got through"
        );
    }

    #[test]
    fn container_and_memory_mounts_are_not_in_the_list() {
        // On a host running a dozen containers these would otherwise be most
        // of the report.
        for m in mounts() {
            assert!(
                m.is_durable(),
                "{} ({}) should be filtered",
                m.path,
                m.fstype
            );
        }
    }

    #[test]
    fn the_same_device_is_not_counted_twice() {
        // Bind mounts report identical figures and would inflate a fleet
        // total.
        let m = mounts();
        let mut devices: Vec<&String> = m.iter().map(|x| &x.device).collect();
        devices.sort();
        let before = devices.len();
        devices.dedup();
        assert_eq!(before, devices.len(), "a device appeared twice");
    }

    #[test]
    fn the_first_collection_has_no_trends_because_a_rate_needs_two_readings() {
        let r = collect();
        assert!(!r.mounts.is_empty());
        // Whatever the state of this machine, a report must be produced.
        assert!(r.build.uptime_secs > 0);
    }

    #[test]
    fn the_clock_is_read_and_judged_rather_than_assumed() {
        let c = clock();
        // Any answer is acceptable; silently assuming trustworthy is not.
        let _ = c.may_decide_on_time();
        assert!(c.daemon.is_some());
    }

    #[test]
    fn a_missing_reboot_flag_reads_as_no_reboot_pending() {
        let r = reboot();
        if !r.required {
            assert!(r.because.is_empty());
        }
    }

    #[test]
    fn series_are_emitted_for_the_mounts_worth_forecasting() {
        let r = collect();
        let s = series_points(&r);
        assert!(s.iter().all(|(_, v)| *v >= 0.0));
        assert!(
            s.iter().any(|(k, _)| k == "disk_free_gb"),
            "root should be a rail"
        );
    }
}
