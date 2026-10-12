//! Accelerators that are not discrete NVIDIA cards.
//!
//! [`crate::accelerator`] reads health from `nvidia-smi`, which covers the
//! rack. Small boards carry their accelerators differently: a Jetson's GPU is
//! on the SoC and Orin's NVML does not report it; a Raspberry Pi's AI HAT is a
//! Hailo part on PCIe; Rockchip, Intel and AMD NPUs register with the kernel's
//! `accel` subsystem. This module finds them and says, for each, whether work
//! can actually be placed on it.
//!
//! ## Schedulable is a separate fact from present
//!
//! A device the kernel has bound is not a device anything can use. Each of
//! these needs a userspace runtime (CUDA, HailoRT, Teflon or RKNN, Level Zero,
//! XRT) and without it a job sent there fails, or worse, quietly runs on the
//! CPU. [`Accelerator::schedulable`] refuses in that case, naming what is
//! missing, so a placement decision can never route accelerator work to a node
//! that would fall back to software.
//!
//! ## Integrated GPU telemetry
//!
//! NVML is asked first, because on Thor it answers. Fields it leaves blank,
//! which on Orin is all of them, are taken from `tegrastats`, then from the
//! devfreq node. Each value records where it came from ([`Reading`]); a value
//! no source produced is `NotMeasured`, never zero.

use crate::reading::{Reading, Source};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One sample of an integrated GPU.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntegratedGpu {
    pub load_percent: Reading<f64>,
    pub frequency_mhz: Reading<u64>,
    pub temperature_c: Reading<f64>,
}

impl IntegratedGpu {
    pub fn not_measured() -> Self {
        IntegratedGpu {
            load_percent: Reading::NotMeasured,
            frequency_mhz: Reading::NotMeasured,
            temperature_c: Reading::NotMeasured,
        }
    }

    /// Fill each field from the first source that measured it.
    pub fn or(self, next: IntegratedGpu) -> IntegratedGpu {
        IntegratedGpu {
            load_percent: self.load_percent.or(next.load_percent),
            frequency_mhz: self.frequency_mhz.or(next.frequency_mhz),
            temperature_c: self.temperature_c.or(next.temperature_c),
        }
    }
}

/// Parse `nvidia-smi --query-gpu=utilization.gpu,clocks.gr,temperature.gpu
/// --format=csv,noheader,nounits` for the first GPU. `[N/A]` is not measured.
pub fn parse_nvml_igpu(text: &str) -> IntegratedGpu {
    let Some(line) = text.lines().find(|l| !l.trim().is_empty()) else {
        return IntegratedGpu::not_measured();
    };
    let f: Vec<&str> = line.split(',').map(str::trim).collect();
    let num = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok());
    IntegratedGpu {
        load_percent: Reading::from_option(num(0), Source::Nvml),
        frequency_mhz: Reading::from_option(num(1).map(|v| v as u64), Source::Nvml),
        temperature_c: Reading::from_option(num(2), Source::Nvml),
    }
}

/// Parse one `tegrastats` line.
///
/// The GPU field has changed shape across releases: `GR3D_FREQ 12%@1300`,
/// `GR3D_FREQ 12%@[1300]` and `GR3D_FREQ 12%@[305,305]` all occur, and
/// without a frequency at all on some. The GPU temperature is `gpu@46.4C` or
/// `GPU@46.4C`.
pub fn parse_tegrastats(line: &str) -> IntegratedGpu {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut load = None;
    let mut freq = None;
    if let Some(i) = words.iter().position(|w| *w == "GR3D_FREQ") {
        if let Some(field) = words.get(i + 1) {
            let (pct, at) = field.split_once('@').map_or((*field, None), |(p, a)| (p, Some(a)));
            load = pct.strip_suffix('%').and_then(|p| p.parse::<f64>().ok());
            freq = at.and_then(|a| {
                a.trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
            });
        }
    }
    let temp = words.iter().find_map(|w| {
        let (name, value) = w.split_once('@')?;
        if !name.eq_ignore_ascii_case("gpu") {
            return None;
        }
        value.strip_suffix('C')?.parse::<f64>().ok()
    });
    IntegratedGpu {
        load_percent: Reading::from_option(load, Source::Tegrastats),
        frequency_mhz: Reading::from_option(freq, Source::Tegrastats),
        temperature_c: Reading::from_option(temp, Source::Tegrastats),
    }
}

/// The devfreq directory for an integrated GPU under `class_devfreq`.
pub fn find_gpu_devfreq(class_devfreq: &Path) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(class_devfreq)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
            n.contains("gpu") || n.contains("ga10b") || n.contains("gb10b")
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

/// Read frequency (`cur_freq`, Hz) and load (`device/load`, per mille) from a
/// devfreq directory.
pub fn read_devfreq(dir: &Path) -> IntegratedGpu {
    let read_u64 = |p: PathBuf| {
        std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u64>().ok())
    };
    let freq = read_u64(dir.join("cur_freq")).map(|hz| hz / 1_000_000);
    let load = read_u64(dir.join("device/load")).map(|permille| permille as f64 / 10.0);
    IntegratedGpu {
        load_percent: Reading::from_option(load, Source::SysfsDevfreq),
        frequency_mhz: Reading::from_option(freq, Source::SysfsDevfreq),
        temperature_c: Reading::NotMeasured,
    }
}

/// Sample a Jetson's integrated GPU: NVML, then `tegrastats`, then devfreq.
pub fn sample_jetson_gpu() -> IntegratedGpu {
    let nvml = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=utilization.gpu,clocks.gr,temperature.gpu", "--format=csv,noheader,nounits"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_nvml_igpu(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_else(IntegratedGpu::not_measured);
    let tegra = tegrastats_once().map(|l| parse_tegrastats(&l)).unwrap_or_else(IntegratedGpu::not_measured);
    let devfreq = find_gpu_devfreq(Path::new("/sys/class/devfreq"))
        .map(|d| read_devfreq(&d))
        .unwrap_or_else(IntegratedGpu::not_measured);
    nvml.or(tegra).or(devfreq)
}

/// One line from `tegrastats`, which otherwise runs until stopped.
fn tegrastats_once() -> Option<String> {
    use std::io::BufRead;
    let mut child = std::process::Command::new("tegrastats")
        .args(["--interval", "100"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut line = String::new();
    let read = child
        .stdout
        .take()
        .map(|out| std::io::BufReader::new(out).read_line(&mut line));
    let _ = child.kill();
    let _ = child.wait();
    match read {
        Some(Ok(n)) if n > 0 => Some(line),
        _ => None,
    }
}

/// Parse `vcgencmd measure_temp`: `temp=52.1'C`.
pub fn parse_measure_temp(text: &str) -> Option<f64> {
    text.trim().strip_prefix("temp=")?.trim_end_matches("'C").parse().ok()
}

/// A Raspberry Pi's SoC temperature: the firmware's figure, then thermal zone 0.
pub fn pi_soc_temperature() -> Reading<f64> {
    let vc = std::process::Command::new("vcgencmd")
        .arg("measure_temp")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_measure_temp(&String::from_utf8_lossy(&o.stdout)));
    let zone = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .map(|milli| milli as f64 / 1000.0);
    Reading::from_option(vc, Source::Vcgencmd).or(Reading::from_option(zone, Source::ThermalZone))
}

/// PCI vendor ID for Hailo Technologies.
pub const HAILO_PCI_VENDOR: &str = "0x1e60";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The GPU on a Jetson SoC.
    JetsonIgpu,
    /// Hailo-8, Hailo-8L, Hailo-10H: the Raspberry Pi AI HAT+ and AI HAT+ 2.
    Hailo,
    /// Rockchip NPU: mainline `rocket` or the vendor `rknpu` driver.
    RockchipNpu,
    /// Intel NPU (`intel_vpu`).
    IntelNpu,
    /// AMD XDNA NPU (`amdxdna`).
    AmdNpu,
    /// An `accel` device whose driver is not recognised here.
    OtherAccel,
}

/// Whether the userspace runtime for an accelerator is installed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Runtime {
    Present { library: String },
    Missing { needs: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accelerator {
    pub kind: Kind,
    /// Kernel driver bound to the device, if any.
    pub driver: Option<String>,
    /// Device node work is submitted through.
    pub node: Option<String>,
    /// PCI address and device ID, for PCIe parts.
    pub pci: Option<String>,
    pub pci_device: Option<String>,
    pub runtime: Runtime,
}

/// Why work must not be placed on an accelerator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum Refusal {
    NoDriver,
    NoDeviceNode,
    RuntimeMissing { needs: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoDriver => f.write_str("no kernel driver is bound to the device"),
            Refusal::NoDeviceNode => f.write_str("the driver exposes no device node"),
            Refusal::RuntimeMissing { needs } => write!(f, "runtime missing: {needs}"),
        }
    }
}

impl Accelerator {
    /// Whether work may be placed here. There is no CPU fallback: a device
    /// without its runtime is refused rather than emulated.
    pub fn schedulable(&self) -> Result<(), Refusal> {
        if self.driver.is_none() {
            return Err(Refusal::NoDriver);
        }
        if self.node.is_none() {
            return Err(Refusal::NoDeviceNode);
        }
        match &self.runtime {
            Runtime::Present { .. } => Ok(()),
            Runtime::Missing { needs } => Err(Refusal::RuntimeMissing { needs: needs.clone() }),
        }
    }
}

/// Where to look. Real paths in production; a scratch tree in tests.
#[derive(Clone, Debug)]
pub struct Roots {
    pub sys: PathBuf,
    pub dev: PathBuf,
    pub lib_dirs: Vec<PathBuf>,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            sys: PathBuf::from("/sys"),
            dev: PathBuf::from("/dev"),
            lib_dirs: [
                "/usr/lib",
                "/usr/lib64",
                "/usr/local/lib",
                "/usr/lib/aarch64-linux-gnu",
                "/usr/lib/aarch64-linux-gnu/nvidia",
                "/usr/lib/aarch64-linux-gnu/tegra",
                "/usr/lib/x86_64-linux-gnu",
                "/opt/xilinx/xrt/lib",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
        }
    }
}

impl Roots {
    fn find_library(&self, prefixes: &[&str]) -> Option<String> {
        for dir in &self.lib_dirs {
            let Ok(entries) = std::fs::read_dir(dir) else { continue };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if prefixes.iter().any(|p| name.starts_with(p)) {
                    return Some(e.path().to_string_lossy().into_owned());
                }
            }
        }
        None
    }

    fn runtime(&self, prefixes: &[&str], needs: &str) -> Runtime {
        match self.find_library(prefixes) {
            Some(library) => Runtime::Present { library },
            None => Runtime::Missing { needs: needs.to_string() },
        }
    }

    fn first_node(&self, names: &[&str]) -> Option<String> {
        names
            .iter()
            .map(|n| self.dev.join(n))
            .find(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
    }
}

fn driver_of(device: &Path) -> Option<String> {
    std::fs::read_link(device.join("driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

fn read_trim(p: PathBuf) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn sorted_dir(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(p)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// Find the accelerators on this machine. `jetson` says whether the board is
/// a Jetson, from [`crate::board`]; its GPU is on the SoC and has no PCI or
/// `accel` entry to find.
pub fn discover(roots: &Roots, jetson: bool) -> Vec<Accelerator> {
    let mut out = Vec::new();

    if jetson {
        let devfreq = find_gpu_devfreq(&roots.sys.join("class/devfreq"));
        out.push(Accelerator {
            kind: Kind::JetsonIgpu,
            driver: devfreq.as_deref().and_then(|d| driver_of(&d.join("device"))),
            node: roots.first_node(&["nvgpu/igpu0", "nvidia0", "nvhost-ctrl-gpu"]),
            pci: None,
            pci_device: None,
            runtime: roots.runtime(&["libcuda.so"], "CUDA (libcuda.so from the L4T BSP)"),
        });
    }

    for dev in sorted_dir(&roots.sys.join("bus/pci/devices")) {
        if read_trim(dev.join("vendor")).as_deref() != Some(HAILO_PCI_VENDOR) {
            continue;
        }
        out.push(Accelerator {
            kind: Kind::Hailo,
            driver: driver_of(&dev),
            node: roots.first_node(&["hailo0"]),
            pci: dev.file_name().map(|n| n.to_string_lossy().into_owned()),
            pci_device: read_trim(dev.join("device")),
            runtime: roots.runtime(&["libhailort.so"], "HailoRT (libhailort.so)"),
        });
    }

    for accel in sorted_dir(&roots.sys.join("class/accel")) {
        let name = accel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let driver = driver_of(&accel.join("device"));
        let (kind, runtime) = match driver.as_deref() {
            Some("rocket") => (Kind::RockchipNpu, roots.runtime(&["libteflon.so"], "Mesa Teflon (libteflon.so)")),
            Some("intel_vpu") => (
                Kind::IntelNpu,
                roots.runtime(&["libze_intel_vpu.so", "libze_intel_npu.so"], "Intel NPU Level Zero driver"),
            ),
            Some("amdxdna") => (Kind::AmdNpu, roots.runtime(&["libxrt_driver_xdna.so"], "XRT with the XDNA plugin")),
            _ => (
                Kind::OtherAccel,
                Runtime::Missing { needs: "a runtime for an unrecognised accel driver".to_string() },
            ),
        };
        let node = roots.first_node(&[&format!("accel/{name}")]);
        out.push(Accelerator { kind, driver, node, pci: None, pci_device: None, runtime });
    }

    // The vendor Rockchip driver registers as DRM rather than accel.
    for render in sorted_dir(&roots.sys.join("class/drm")) {
        let name = render.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !name.starts_with("renderD") {
            continue;
        }
        let driver = driver_of(&render.join("device"));
        if !driver.as_deref().is_some_and(|d| d.eq_ignore_ascii_case("rknpu")) {
            continue;
        }
        out.push(Accelerator {
            kind: Kind::RockchipNpu,
            driver,
            node: roots.first_node(&[&format!("dri/{name}")]),
            pci: None,
            pci_device: None,
            runtime: roots.runtime(&["librknnrt.so"], "RKNN runtime (librknnrt.so)"),
        });
    }

    out
}

/// What `hailortcli fw-control identify` says about a Hailo device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HailoIdentity {
    pub architecture: Option<String>,
    pub firmware: Option<String>,
    pub product: Option<String>,
}

pub fn parse_hailo_identify(text: &str) -> HailoIdentity {
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).and_then(|r| r.strip_prefix(':')))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    HailoIdentity {
        architecture: field("Device Architecture"),
        firmware: field("Firmware Version"),
        product: field("Product Name"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-inventory-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    fn bind(device: &Path, driver: &str) {
        std::fs::create_dir_all(device).unwrap();
        std::os::unix::fs::symlink(format!("/bus/drivers/{driver}"), device.join("driver")).unwrap();
    }

    #[test]
    fn tegrastats_orin_nano() {
        let g = parse_tegrastats(include_str!("testdata/tegrastats-orin-nano"));
        assert_eq!(g.load_percent, Reading::measured(37.0, Source::Tegrastats));
        assert_eq!(g.frequency_mhz, Reading::measured(624, Source::Tegrastats));
        assert_eq!(g.temperature_c, Reading::measured(46.406, Source::Tegrastats));
    }

    #[test]
    fn tegrastats_older_shapes() {
        let g = parse_tegrastats("RAM 1/2MB GR3D_FREQ 5%@1300 GPU@40.5C");
        assert_eq!(g.frequency_mhz.value(), Some(&1300));
        assert_eq!(g.temperature_c.value(), Some(&40.5));
        let bare = parse_tegrastats("RAM 1/2MB GR3D_FREQ 0% cpu@40C");
        assert_eq!(bare.load_percent.value(), Some(&0.0));
        assert_eq!(bare.frequency_mhz, Reading::NotMeasured);
        assert_eq!(bare.temperature_c, Reading::NotMeasured);
    }

    #[test]
    fn nvml_gaps_are_filled_from_later_sources() {
        // Thor: NVML answers utilisation and temperature, not clocks.
        let nvml = parse_nvml_igpu("12, [N/A], 51\n");
        assert_eq!(nvml.frequency_mhz, Reading::NotMeasured);
        let tegra = parse_tegrastats(include_str!("testdata/tegrastats-orin-nano"));
        let g = nvml.or(tegra);
        assert_eq!(g.load_percent, Reading::measured(12.0, Source::Nvml));
        assert_eq!(g.frequency_mhz.source(), Some(Source::Tegrastats));
        assert_eq!(g.temperature_c.source(), Some(Source::Nvml));
        assert_eq!(parse_nvml_igpu(""), IntegratedGpu::not_measured());
    }

    #[test]
    fn devfreq_tree() {
        let d = scratch("devfreq");
        let gpu = d.join("class/devfreq/17000000.gpu");
        write(&gpu.join("cur_freq"), "624750000\n");
        write(&gpu.join("device/load"), "373\n");
        write(&d.join("class/devfreq/3d00000.mem/cur_freq"), "1\n");
        let found = find_gpu_devfreq(&d.join("class/devfreq")).unwrap();
        let g = read_devfreq(&found);
        assert_eq!(g.frequency_mhz, Reading::measured(624, Source::SysfsDevfreq));
        assert_eq!(g.load_percent, Reading::measured(37.3, Source::SysfsDevfreq));
        assert_eq!(g.temperature_c, Reading::NotMeasured);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn measure_temp() {
        assert_eq!(parse_measure_temp("temp=52.1'C\n"), Some(52.1));
        assert_eq!(parse_measure_temp("error=1"), None);
    }

    #[test]
    fn hailo_without_runtime_is_refused() {
        let d = scratch("hailo");
        let pci = d.join("sys/bus/pci/devices/0001:01:00.0");
        write(&pci.join("vendor"), "0x1e60\n");
        write(&pci.join("device"), "0x2864\n");
        bind(&pci, "hailo_pci");
        write(&d.join("dev/hailo0"), "");
        let roots = Roots { sys: d.join("sys"), dev: d.join("dev"), lib_dirs: vec![d.join("lib")] };

        let found = discover(&roots, false);
        assert_eq!(found.len(), 1);
        let h = &found[0];
        assert_eq!((h.kind.clone(), h.driver.as_deref(), h.pci_device.as_deref()), (Kind::Hailo, Some("hailo_pci"), Some("0x2864")));
        assert!(matches!(h.schedulable(), Err(Refusal::RuntimeMissing { .. })));

        write(&d.join("lib/libhailort.so.4.20.0"), "");
        assert_eq!(discover(&roots, false)[0].schedulable(), Ok(()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn accel_npus_and_jetson_igpu() {
        let d = scratch("accel");
        bind(&d.join("sys/class/accel/accel0/device"), "rocket");
        bind(&d.join("sys/class/accel/accel1/device"), "amdxdna");
        bind(&d.join("sys/class/drm/renderD129/device"), "RKNPU");
        bind(&d.join("sys/class/devfreq/17000000.gpu/device"), "nvgpu");
        write(&d.join("dev/accel/accel0"), "");
        write(&d.join("dev/nvgpu/igpu0/ctrl"), "");
        write(&d.join("lib/libcuda.so.1"), "");
        let roots = Roots { sys: d.join("sys"), dev: d.join("dev"), lib_dirs: vec![d.join("lib")] };

        let found = discover(&roots, true);
        let kinds: Vec<Kind> = found.iter().map(|a| a.kind.clone()).collect();
        assert_eq!(kinds, vec![Kind::JetsonIgpu, Kind::RockchipNpu, Kind::AmdNpu, Kind::RockchipNpu]);
        assert_eq!(found[0].driver.as_deref(), Some("nvgpu"));
        assert_eq!(found[0].schedulable(), Ok(()));
        assert!(matches!(found[1].schedulable(), Err(Refusal::RuntimeMissing { .. })));
        assert_eq!(found[2].schedulable(), Err(Refusal::NoDeviceNode));
        assert_eq!(found[3].runtime, Runtime::Missing { needs: "RKNN runtime (librknnrt.so)".into() });
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn hailo_identify() {
        let h = parse_hailo_identify(include_str!("testdata/hailortcli-identify"));
        assert_eq!(h.architecture.as_deref(), Some("HAILO8L"));
        assert_eq!(h.firmware.as_deref(), Some("4.20.0 (release,app,extended context switch buffer)"));
        assert!(h.product.unwrap().starts_with("HAILO-8L"));
    }
}
