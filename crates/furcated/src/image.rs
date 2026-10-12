//! Reading what this machine is, and remembering what it was.
//!
//! The baseline is recorded on disk beside the node's other state. That is what
//! moves a package-based machine from `Unmanaged` to `Pinned`: not a new
//! operating system, just something that wrote down what the current one looked
//! like so a change becomes visible.
//!
//! First observation is deliberately silent. Every machine differs from an
//! empty baseline, so recording one and immediately reporting drift against it
//! would produce an alert on every node the first time this ran, and teach
//! whoever saw it that the alert means nothing.

use furcate_host::firmware::{age, dmi_field, Age, Component, Firmware};
use furcate_host::image::{assurance_of, drift, parse_bootc, parse_os_release, parse_ostree, Drift, Image};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageReport {
    pub image: Image,
    /// What has moved since the baseline, where one exists.
    pub drift: Option<Drift>,
    /// What the boot chain does and does not cover. The honest version of a
    /// limitation that has lived in prose.
    pub boot_coverage: BootCoverage,
    pub firmware: Firmware,
    pub firmware_age: Age,
}

/// How far platform measurement actually extends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootCoverage {
    /// Whether anything past the firmware was measured.
    pub kernel_measured: bool,
    /// What a comparison would catch, in plain terms.
    pub detects: Vec<String>,
    /// What it would not.
    pub blind_to: Vec<String>,
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Whether the platform measured anything past the firmware.
///
/// Read from the published TPM state rather than by talking to the device: the
/// agent has no business holding a TPM handle, and the identity subsystem
/// already establishes what the platform registers contain.
///
/// A register of all zeroes has never been extended, which is exactly the state
/// on this hardware and the reason attestation here stops at the firmware.
fn kernel_measured() -> bool {
    let Some(text) = read("/run/furcate/pcr.txt") else { return false };
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(idx, _)| idx.trim() == "11")
        .any(|(_, v)| {
            let hex = v.trim().trim_start_matches("0x");
            !hex.is_empty() && hex.chars().any(|c| c != '0')
        })
}

pub fn collect(baseline: Option<&Image>, baseline_at: u64) -> ImageReport {
    let (os_id, os_version) = read("/etc/os-release")
        .map(|t| parse_os_release(&t))
        .unwrap_or((None, None));

    let kernel = read("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string());
    let cmdline = read("/proc/cmdline").map(|s| s.trim().to_string());

    // Image-based hosts, where either tool is installed. Neither is required:
    // a module that needed one would report nothing on the machines that most
    // need to be told they are unmanaged.
    let bootc = std::process::Command::new("bootc")
        .args(["status", "--json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .and_then(|v| parse_bootc(&v));

    let ostree = bootc.is_none().then(|| {
        std::process::Command::new("ostree")
            .args(["admin", "status"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| parse_ostree(&String::from_utf8_lossy(&o.stdout)))
    })
    .flatten();

    let (digest, reference, rollback_available) = match (bootc, ostree) {
        (Some((d, r, roll)), _) => (Some(d), r, roll),
        (None, Some((commit, roll))) => (Some(commit), None, roll),
        _ => (None, None, false),
    };

    let measured = kernel_measured();
    let image = Image {
        assurance: assurance_of(digest.as_deref(), measured, baseline.is_some()),
        os_id,
        os_version,
        kernel,
        cmdline,
        digest,
        reference,
        rollback_available,
        boot_measured: measured,
    };

    let firmware = firmware();
    let firmware_age = age(firmware.bios_date.as_deref(), current_year());

    ImageReport {
        drift: baseline.map(|b| drift(b, &image, baseline_at)),
        boot_coverage: coverage(measured),
        image,
        firmware,
        firmware_age,
    }
}

/// What measurement covers, said plainly.
fn coverage(kernel_measured: bool) -> BootCoverage {
    if kernel_measured {
        BootCoverage {
            kernel_measured: true,
            detects: vec![
                "a changed firmware image".into(),
                "a changed kernel or initramfs".into(),
                "a changed kernel command line".into(),
            ],
            blind_to: vec!["changes to the root filesystem after boot".into()],
        }
    } else {
        BootCoverage {
            kernel_measured: false,
            detects: vec!["a changed firmware image".into()],
            // Stated as a field rather than a footnote. A limitation that lives
            // in a document is one that stops being read.
            blind_to: vec![
                "a swapped kernel".into(),
                "a swapped initramfs".into(),
                "a changed kernel command line".into(),
            ],
        }
    }
}

/// The year, for judging firmware age.
///
/// Derived from the clock rather than compiled in, because a constant would
/// make every machine look newer as the binary aged.
fn current_year() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Good enough for a threshold measured in years.
    1970 + (secs / 31_556_952) as u32
}

fn dmi(field: &str) -> Option<String> {
    read(&format!("/sys/class/dmi/id/{field}")).and_then(|t| dmi_field(&t))
}

fn firmware() -> Firmware {
    // `fwupd` is richer where it exists and is not required. The SMBIOS tables
    // are decoded by the kernel and world-readable on every machine, which is
    // why they are the base rather than the enhancement.
    let components: Vec<Component> = std::process::Command::new("fwupdmgr")
        .args(["get-devices", "--json"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .map(|v| furcate_host::firmware::parse_fwupd(&v))
        .unwrap_or_default();

    Firmware {
        bios_vendor: dmi("bios_vendor"),
        bios_version: dmi("bios_version"),
        bios_date: dmi("bios_date"),
        board_name: dmi("board_name"),
        product_name: dmi("product_name"),
        system_vendor: dmi("sys_vendor"),
        inventory_available: !components.is_empty(),
        components,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_describes_itself_without_panicking() {
        let r = collect(None, 0);
        // Every Linux machine has these two.
        assert!(r.image.kernel.is_some());
        assert!(r.image.cmdline.is_some());
    }

    #[test]
    fn a_machine_with_no_baseline_reports_no_drift() {
        // First observation is silent. Otherwise every node alerts the first
        // time this runs, and whoever sees it learns the alert means nothing.
        assert!(collect(None, 0).drift.is_none());
    }

    #[test]
    fn coverage_states_the_blind_spot_rather_than_implying_it() {
        let c = coverage(false);
        assert!(!c.kernel_measured);
        assert!(c.blind_to.iter().any(|b| b.contains("kernel")));
        assert!(c.detects.iter().any(|d| d.contains("firmware")));
        // And the covered case does not silently keep the same warning.
        assert!(coverage(true).blind_to.iter().all(|b| !b.contains("swapped kernel")));
    }

    #[test]
    fn an_unmeasured_machine_never_reports_the_top_assurance_level() {
        // The site's actual state, and the thing that must not be overstated.
        let r = collect(None, 0);
        if !r.image.boot_measured {
            assert!(!r.image.assurance.detects_a_swapped_kernel());
        }
    }

    #[test]
    fn the_year_is_derived_rather_than_compiled_in() {
        // A constant would make every machine look newer as the binary aged.
        let y = current_year();
        assert!((2020..2100).contains(&y), "got {y}");
    }
}
