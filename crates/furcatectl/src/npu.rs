//! Neural processing units on this node, as the kernel reports them.
//!
//! An NPU is not a GPU. The inference runtime offloads to what it can enumerate
//! (`llama-server --list-devices`), and an NPU never appears there: it runs
//! networks compiled for it by its vendor, through the vendor's runtime, in the
//! vendor's format. So whether an NPU can serve a model is a question about the
//! model's format and the runtimes on the node, and it is answered here, by
//! name, rather than left to look like a node with no accelerator at all.
//!
//! Detection reads PCI identity from sysfs, which needs no driver: a part whose
//! driver did not load is still reported, as unbound, because "the board has
//! an NPU and its driver is not running" and "the board has no NPU" call for
//! different fixes.

use std::path::Path;

/// One NPU on the PCI bus.
#[derive(Debug, Clone, PartialEq)]
pub struct Npu {
    /// The PCI address, e.g. `0001:01:00.0`.
    pub slot: String,
    /// `1e60:2864`.
    pub id: String,
    pub family: Family,
    /// The kernel driver bound to it, if any.
    pub driver: Option<String>,
    /// The driver's own version, from the module, if it reports one.
    pub driver_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Family {
    /// Hailo-8 and Hailo-8L, one PCI id. Runs compiled vision and audio
    /// networks (HEF) through HailoRT 4; no language-model runtime exists for
    /// it.
    Hailo8,
    /// Hailo-10H. Runs language models, but only ones Hailo compiled to HEF,
    /// through HailoRT 5 and its GenAI library.
    Hailo10,
    /// A Hailo part this code does not know.
    HailoOther,
}

const HAILO: &str = "1e60";

impl Npu {
    pub fn name(&self) -> String {
        match self.family {
            Family::Hailo8 => "Hailo-8/8L".to_string(),
            Family::Hailo10 => "Hailo-10H".to_string(),
            Family::HailoOther => format!("Hailo device {}", self.id),
        }
    }

    /// One line for an operator: what it is, where, and whether its driver runs.
    pub fn describe(&self) -> String {
        let drv = match (&self.driver, &self.driver_version) {
            (Some(d), Some(v)) => format!("driver {d} {v}"),
            (Some(d), None) => format!("driver {d}"),
            (None, _) => "NO DRIVER BOUND".to_string(),
        };
        format!("{} at {} ({drv})", self.name(), self.slot)
    }

    /// Why this NPU cannot serve `model` (a phrase: "`qwen3-0.6b`", "the
    /// gateway's models"), GGUF run by llama.cpp. Every
    /// model `furcatectl model` serves is one, so for now the answer is always a
    /// reason; it is stated per family because what would change it differs.
    pub fn cannot_serve(&self, model: &str) -> String {
        let what = match self.family {
            Family::Hailo8 => format!(
                "it runs networks compiled to Hailo's HEF format (vision and audio models) through\n\
                 HailoRT 4. No language-model runtime exists for this part, and llama.cpp, the\n\
                 runtime that serves {model}, has no backend for it."
            ),
            Family::Hailo10 => format!(
                "it can run language models, but only ones Hailo compiled to HEF, through HailoRT 5\n\
                 and its GenAI library. Furcate does not ship that runtime, and {model} is GGUF,\n\
                 which cannot be offloaded to it."
            ),
            Family::HailoOther => format!(
                "this part is not one Furcate knows, and llama.cpp, the runtime that serves\n\
                 {model}, has no Hailo backend."
            ),
        };
        format!("the NPU on this node, {}, cannot serve {model}:\n{what}", self.describe())
    }
}

/// NPUs on the PCI bus under `root` (`/` on a node; a fixture in tests).
pub fn scan(root: &Path) -> Vec<Npu> {
    let bus = root.join("sys/bus/pci/devices");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&bus) else { return out };
    let read = |p: &Path| -> Option<String> {
        std::fs::read_to_string(p).ok().map(|s| s.trim().trim_start_matches("0x").to_ascii_lowercase())
    };
    let mut slots: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    slots.sort();
    for dev in slots {
        let (Some(vendor), Some(device)) = (read(&dev.join("vendor")), read(&dev.join("device"))) else {
            continue;
        };
        if vendor != HAILO {
            continue;
        }
        let family = match device.as_str() {
            "2864" => Family::Hailo8,
            "45c4" => Family::Hailo10,
            _ => Family::HailoOther,
        };
        let driver = std::fs::read_link(dev.join("driver"))
            .ok()
            .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned()));
        let driver_version = driver
            .as_ref()
            .and_then(|d| std::fs::read_to_string(root.join("sys/module").join(d).join("version")).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        out.push(Npu {
            slot: dev.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            id: format!("{vendor}:{device}"),
            family,
            driver,
            driver_version,
        });
    }
    out
}

/// The NPUs on this node.
pub fn present() -> Vec<Npu> {
    scan(Path::new("/"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A sysfs fixture: `(slot, vendor, device, driver)`.
    pub(crate) fn fixture(tag: &str, devs: &[(&str, &str, &str, Option<&str>)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("furcatectl-npu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (slot, vendor, device, driver) in devs {
            let d = root.join("sys/bus/pci/devices").join(slot);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("vendor"), format!("0x{vendor}\n")).unwrap();
            std::fs::write(d.join("device"), format!("0x{device}\n")).unwrap();
            if let Some(drv) = driver {
                let target = root.join("sys/bus/pci/drivers").join(drv);
                std::fs::create_dir_all(&target).unwrap();
                std::os::unix::fs::symlink(&target, d.join("driver")).unwrap();
                let m = root.join("sys/module").join(drv);
                std::fs::create_dir_all(&m).unwrap();
                std::fs::write(m.join("version"), "4.24.0\n").unwrap();
            }
        }
        root
    }

    #[test]
    fn a_hailo_8_is_found_with_its_driver_and_other_devices_are_not() {
        let root = fixture(
            "found",
            &[("0001:01:00.0", "1e60", "2864", Some("hailo_pci")), ("0000:00:00.0", "14e4", "2712", None)],
        );
        let n = scan(&root);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].family, Family::Hailo8);
        assert_eq!(n[0].slot, "0001:01:00.0");
        assert_eq!(n[0].driver.as_deref(), Some("hailo_pci"));
        assert_eq!(n[0].driver_version.as_deref(), Some("4.24.0"));
        assert_eq!(n[0].describe(), "Hailo-8/8L at 0001:01:00.0 (driver hailo_pci 4.24.0)");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_npu_whose_driver_did_not_load_is_reported_as_such_not_hidden() {
        let root = fixture("unbound", &[("0001:01:00.0", "1e60", "2864", None)]);
        let n = scan(&root);
        assert_eq!(n.len(), 1);
        assert!(n[0].describe().contains("NO DRIVER BOUND"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_bus_means_no_npu_rather_than_an_error() {
        let root = std::env::temp_dir().join(format!("furcatectl-npu-empty-{}", std::process::id()));
        assert!(scan(&root).is_empty());
    }

    #[test]
    fn each_family_says_why_it_cannot_serve_a_gguf_model() {
        let mk = |family| Npu {
            slot: "s".into(),
            id: "1e60:0000".into(),
            family,
            driver: Some("hailo_pci".into()),
            driver_version: None,
        };
        assert!(mk(Family::Hailo8).cannot_serve("qwen3-0.6b").contains("HEF"));
        assert!(mk(Family::Hailo10).cannot_serve("qwen3-0.6b").contains("HailoRT 5"));
        assert!(mk(Family::HailoOther).cannot_serve("qwen3-0.6b").contains("no Hailo backend"));
    }
}
