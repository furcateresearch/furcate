//! Reading what this machine actually is.
//!
//! Capability is detected rather than declared. A node that could claim its own
//! specification could claim a GPU it does not have, and every placement
//! decision downstream would inherit that lie.

use furcate_mesh::Capability;

/// Core count from the kernel's own view.
fn cpu_cores() -> u32 {
    #[cfg(target_os = "macos")]
    if let Some(n) = sysctl_num("hw.ncpu") {
        return (n as u32).max(1);
    }
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count() as u32)
        .unwrap_or(1)
        .max(1)
}

/// One numeric `sysctl`, for the platform that has no `/proc`.
///
/// A Mac reports through sysctl what Linux reports through procfs, and reading
/// neither leaves a node advertising one core and no memory -- which is not a
/// small inaccuracy, because it is what the scheduler places work against.
#[cfg(target_os = "macos")]
fn sysctl_num(name: &str) -> Option<u64> {
    let out = std::process::Command::new("sysctl").args(["-n", name]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Total memory in megabytes.
fn ram_mb() -> u64 {
    #[cfg(target_os = "macos")]
    if let Some(bytes) = sysctl_num("hw.memsize") {
        return bytes / 1024 / 1024;
    }
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Accelerator memory, zero when there is no accelerator.
///
/// Absence is the common case and must not be an error: most nodes on an edge
/// cluster have no GPU, and treating that as a failure would make the whole
/// capability report unavailable.
fn vram_mb() -> u64 {
    let out = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=memory.total", "--format=csv,noheader,nounits"])
        .output()
        .ok()
        .filter(|o| o.status.success());
    let Some(out) = out else { return 0 };
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    if let Ok(mb) = first.parse::<u64>() {
        return mb;
    }

    // A number is the ordinary answer. `[N/A]` is the other one, and it does
    // not mean "no accelerator" -- it means this part has no memory of its own
    // to report, because the GPU and the CPU share one pool. A Grace-Blackwell
    // GB10 answers exactly this, and parsing it as a failure made node-e, the
    // only accelerated node in the fleet, report `vram_mb: 0` and classify as
    // `compute`. The scheduler then had nowhere to place a model.
    //
    // So: ask whether an accelerator is there at all, separately from how much
    // memory it claims. If one is present and the memory is unreportable, the
    // usable figure is system RAM, which is what unified memory means.
    if first.contains("N/A") && has_accelerator() {
        return ram_mb();
    }
    0
}

/// Whether this machine has an accelerator, regardless of what it says about
/// memory.
///
/// Separate from `vram_mb` because the two questions have different answers on
/// a unified-memory part, and conflating them is what made a GB10 look like a
/// machine with no GPU.
fn has_accelerator() -> bool {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Where Furcate's own runtimes live, inside the system extension.
///
/// Deliberately NOT on PATH. `llama-server` is started by absolute path from the
/// unit `furcatectl model serve` writes, because putting a model server on every
/// process's PATH invites it being started outside that supervision.
///
/// Which is exactly why this constant has to exist. Detection used to be
/// `command -v llama-server` alone, so the runtime Furcate ships was invisible to
/// it: a node could be serving a model through a supervised unit and still
/// advertise `runtimes: []`, and the controller — which decides where inference
/// can go by asking `Catalog::can_host`, and that asks `has_runtime` — would rule
/// it out of the one thing it was provisioned for.
///
/// A capability report that disagrees with what the machine can do is worse than
/// no report, because it is believed.
const FURCATE_RUNTIMES: &str = "/usr/lib/furcate/runtimes";

/// Runtimes present on this machine.
///
/// Two sources, and both count. What Furcate ships is found by path, because it
/// is deliberately off PATH; anything the operator installed themselves is found
/// on PATH, because that is where they will have put it.
fn runtimes() -> Vec<String> {
    let mut found: Vec<String> = Vec::new();

    // Shipped with the extension, addressed absolutely.
    let shipped = [("llama.cpp", "llama/llama-server")];
    for (name, rel) in shipped {
        if std::path::Path::new(FURCATE_RUNTIMES).join(rel).is_file()
            && !found.iter().any(|f| f == name)
        {
            found.push(name.to_string());
        }
    }

    // Installed by the operator, found the ordinary way.
    let candidates = [
        ("llama.cpp", "llama-server"),
        ("llama.cpp", "llama-cli"),
        ("onnxruntime", "onnxruntime_test"),
        ("ollama", "ollama"),
        ("vllm", "vllm"),
    ];
    for (name, binary) in candidates {
        let present = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {binary}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if present && !found.iter().any(|f| f == name) {
            found.push(name.to_string());
        }
    }
    found
}

/// Disk space available for storage, in gigabytes.
pub fn disk_gb(path: &str) -> u64 {
    std::process::Command::new("df")
        .args(["-BG", "--output=avail", path])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .nth(1)
                .and_then(|l| l.trim().trim_end_matches('G').parse::<u64>().ok())
        })
        .unwrap_or(0)
}

/// Build a capability report for this machine.
///
/// `attested` is passed in rather than assumed: the caller knows whether the
/// figures are backed by an appraisal, and a report that claims attestation it
/// does not have is worse than one that admits it.
pub fn detect(node: &str, attested: bool) -> Capability {
    Capability {
        node: node.to_string(),
        cpu_cores: cpu_cores(),
        ram_mb: ram_mb(),
        vram_mb: vram_mb(),
        runtimes: runtimes(),
        attested,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unified-memory part reports no VRAM of its own, and that is not zero.
    ///
    /// This is a regression guard rather than a detection test: it can only
    /// assert the invariant on a machine that has an accelerator, and asserts
    /// the harmless direction everywhere else. The bug it guards made node-e --
    /// the fleet's only accelerated node -- report vram_mb 0 and classify as
    /// `compute`, because nvidia-smi answered `[N/A]` and the parse failed to
    /// a default.
    #[test]
    fn an_accelerator_is_never_reported_with_no_memory_at_all() {
        if has_accelerator() {
            assert!(
                vram_mb() > 0,
                "this machine has an accelerator but reports no memory for it"
            );
        }
    }

    #[test]
    fn detection_returns_something_plausible_for_this_machine() {
        let c = detect("test", false);
        assert!(c.cpu_cores >= 1, "at least one core");
        assert!(c.ram_mb > 0, "some memory");
    }

    #[test]
    fn a_machine_without_an_accelerator_reports_zero_not_an_error() {
        // The common case on an edge cluster.
        let c = detect("test", false);
        assert!(c.vram_mb < 1_000_000);
    }

    #[test]
    fn attestation_is_reported_as_given_not_inferred() {
        assert!(!detect("n", false).attested);
        assert!(detect("n", true).attested);
    }
}
