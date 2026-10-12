//! Local model inference, served by Furcate itself.
//!
//! ## Why Furcate serves models itself
//!
//! A site that wants a small model on its own hardware should not have to adopt
//! a second product to get it. So Furcate serves models from a runtime it ships
//! itself: `furcatectl model serve` needs nothing but the extension.
//!
//! ## Why the endpoint is OpenAI-shaped
//!
//! Because that is what applications already speak. praecise ships no model ids
//! and no base URLs — an app declares its own endpoints, and the first one whose
//! credential is present is the one that runs. An OpenAI-compatible endpoint
//! therefore needs no praecise change at all: the app declares `speaks: "chat"`
//! against what `furcatectl model endpoint` prints, and a local model is
//! indistinguishable from a cloud one to everything above it.
//!
//! ## Nothing here is forced
//!
//! Device, context size and offload are chosen automatically and every one of
//! them can be overridden — on the command line for once, in
//! `/etc/furcate/model.conf` for always. A node with a GPU uses it by default
//! because that is what the operator installed it for, not because the software
//! insists.
//!
//! CPU serving is never the automatic answer. A node whose accelerator the
//! runtime cannot use refuses and says why (driver, NPU format), and the
//! operator chooses the CPU by name: `--cpu`, or `device = cpu`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The inference runtime, shipped inside the Furcate system extension.
///
/// Under /usr rather than /usr/local for the same reason node and uv are: /usr
/// is read-only and delivered whole by a cluster update, so every node gets the
/// runtime from the same artefact instead of each being wired up by hand.
///
/// `FURCATE_RUNTIMES_DIR` names another runtimes tree (holding `llama/`): a
/// runtime being verified before it ships, run by an unprivileged user.
fn runtime_dir() -> PathBuf {
    std::env::var_os("FURCATE_RUNTIMES_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/lib/furcate/runtimes"))
        .join("llama")
}

/// Weights live in /var. They are large, machine-local, and must survive the
/// extension being replaced — which is precisely what /usr does not do.
///
/// `FURCATE_MODELS_DIR` moves the store, for the same verification or a store
/// on another disk.
fn models_dir() -> PathBuf {
    std::env::var_os("FURCATE_MODELS_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/furcate/models"))
}

/// Where a served model's endpoint is published for applications to find.
fn registry() -> PathBuf {
    models_dir().join("endpoints.json")
}

/// Operator defaults. Absent is fine and means "use the built-in behaviour".
const CONF: &str = "/etc/furcate/model.conf";

/// Deliberately disjoint from the supervised site band (8600-8699), so a model
/// and a site can never be handed the same port.
const PORT_LOW: u16 = 8700;
const PORT_HIGH: u16 = 8749;

/// A model this node knows how to fetch.
///
/// Every entry was resolved against the source before being written down. A
/// catalog whose entries 404 is worse than no catalog, because it fails at the
/// point the operator has already committed to waiting for a download.
struct Entry {
    id: &'static str,
    repo: &'static str,
    file: &'static str,
    /// Measured, not estimated — for the operator deciding what this machine can
    /// hold, and what will fit in the VRAM it has.
    gib: f32,
    /// Whether this model needs an accelerator to be worth serving.
    ///
    /// **Measured on this hardware, not assumed from size.** Same prompt, same
    /// budget, thinking off, through the gateway, on a machine with no
    /// accelerator:
    ///
    /// | | CPU | GPU (RTX 5070 Ti) |
    /// |---|---|---|
    /// | 0.8B | 29.5 tok/s | 183.6 |
    /// | 1.7B | 19.3 | — |
    /// | 2B   | 17.2 | 193.3 |
    /// | 4B   | **7.6** | 133.8 |
    ///
    /// The line is between 2B and 4B and it is a cliff, not a slope: twice the
    /// model, a third of the throughput. At 7.6 tok/s a 300-token reply takes
    /// **39 seconds**, which is not a conversation.
    ///
    /// So a small model on a CPU node is a perfectly good deployment — most
    /// nodes have no accelerator and most agent work is small — and 4B upward is
    /// where the accelerator stops being an optimisation and becomes the
    /// requirement.
    needs_accelerator: bool,
}

impl Entry {
    /// The lowest tier that should be offered this model.
    ///
    /// This is what the site controller gates placement on: `Catalog::can_host`
    /// compares it against the node's tier, so a 4B model is never placed on a
    /// machine that would take 39 seconds to answer with it.
    fn min_tier(&self) -> &'static str {
        if self.needs_accelerator { "accelerated" } else { "compute" }
    }
}

const CATALOG: &[Entry] = &[
    Entry { id: "qwen3.5-0.8b", repo: "unsloth/Qwen3.5-0.8B-GGUF", file: "Qwen3.5-0.8B-Q4_K_M.gguf", gib: 0.50, needs_accelerator: false },
    Entry { id: "qwen3.5-2b",   repo: "unsloth/Qwen3.5-2B-GGUF",   file: "Qwen3.5-2B-Q4_K_M.gguf",   gib: 1.19, needs_accelerator: false },
    Entry { id: "qwen3.5-4b",   repo: "unsloth/Qwen3.5-4B-GGUF",   file: "Qwen3.5-4B-Q4_K_M.gguf",   gib: 2.55, needs_accelerator: true },
    Entry { id: "qwen3.5-9b",   repo: "unsloth/Qwen3.5-9B-GGUF",   file: "Qwen3.5-9B-Q4_K_M.gguf",   gib: 5.29, needs_accelerator: true },
    // The largest dense Qwen3.5. Verified against the Hugging Face API rather
    // than assumed: the series ships 0.8B, 2B, 4B, 9B and 27B, with no 12B or
    // 14B, so an operator asking for "about twelve billion" is choosing
    // between the 9B and this.
    Entry { id: "qwen3.5-27b",  repo: "unsloth/Qwen3.5-27B-GGUF",  file: "Qwen3.5-27B-Q4_K_M.gguf", gib: 15.59, needs_accelerator: true },
    // The previous generation, kept because a node that already pulled one
    // should not be told its weights are no longer a thing the catalog knows.
    Entry { id: "qwen3-0.6b",   repo: "unsloth/Qwen3-0.6B-GGUF",   file: "Qwen3-0.6B-Q4_K_M.gguf",   gib: 0.37, needs_accelerator: false },
    Entry { id: "qwen3-1.7b",   repo: "unsloth/Qwen3-1.7B-GGUF",   file: "Qwen3-1.7B-Q4_K_M.gguf",   gib: 1.03, needs_accelerator: false },
    Entry { id: "qwen3-4b",     repo: "unsloth/Qwen3-4B-GGUF",     file: "Qwen3-4B-Q4_K_M.gguf",     gib: 2.33, needs_accelerator: true },
    Entry { id: "qwen3-8b",     repo: "unsloth/Qwen3-8B-GGUF",     file: "Qwen3-8B-Q4_K_M.gguf",     gib: 4.68, needs_accelerator: true },
];


/// Models fit to be a node's orchestrator.
///
/// The orchestrator is the one model a machine always has: the agent an
/// operator talks to, and the thing that answers `/infer` for other machines.
/// It is a singleton per node, which is what separates it from anything else
/// the runtime happens to be serving.
///
/// Qwen3.5 only, deliberately, and only the dense sizes. A node's agent has to
/// behave the same on every machine in a fleet for a conversation across them
/// to make sense, and supporting one family properly is worth more than
/// supporting several approximately. Other families are a later decision, not
/// an omission.
///
/// The ceiling is the machine, not this list: `can_host` already refuses a
/// model a node would take half a minute to answer with. 0.8B is the default
/// because it answers an operational question in about a second on a busy
/// machine with two cores, which is the job.
pub const ORCHESTRATORS: &[&str] = &[
    // Measured on this fleet, six factual questions whose answers are checkable
    // against what the machines report:
    //
    //   0.8B  3/6 correct, 13.4s   invented a statistic to justify an answer
    //   2B    3/6 correct, 31.8s   no more accurate, 2.4x slower
    //   4B    6/6 correct, 40.5s   on the accelerated node
    //
    // A cliff, not a gradient. The 2B is not here because nothing recommends
    // it: it costs more than the 0.8B and answers no better. The 0.8B stays
    // because a busy machine with two cores can run it and a larger one cannot,
    // and a node that answers imperfectly is worth more than one that times out.
    "qwen3.5-0.8b",
    "qwen3.5-4b",
    "qwen3.5-9b",
    "qwen3.5-27b",
];

/// Whether this model may be a node's orchestrator.
pub fn is_orchestrator(id: &str) -> bool {
    ORCHESTRATORS.contains(&id)
}


/// Where a node records which model is its agent.
fn orchestrator_path() -> std::path::PathBuf {
    furcate_paths::state("orchestrator")
}

fn orchestrator_current() -> Option<String> {
    std::fs::read_to_string(orchestrator_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}


/// What this machine is, as the daemon on it reports.
///
/// Falls back to `compute` when the daemon cannot be reached, because the
/// consequence of guessing wrong in that direction is a note suggesting a
/// model might be slow, and in the other direction is silence about a model
/// that will be.
fn local_tier() -> &'static str {
    let addr = std::env::var("FURCATE_NODE_ADDR").unwrap_or_else(|_| {
        std::env::var("FURCATE_LISTEN").unwrap_or_else(|_| "127.0.0.1:7616".into())
    });
    match furcate_api::get_json(&addr, "/capability", 3_000) {
        Ok(v) if v.get("tier").and_then(|t| t.as_str()) == Some("accelerated") => "accelerated",
        _ => "compute",
    }
}

/// Models this machine may run as its agent.
pub fn orchestrator_list() -> Result<()> {
    let here = orchestrator_current();
    // Ask the machine, not the filesystem.
    //
    // This looked for a marker file that nothing writes, so every machine
    // reported itself as plain compute -- including the one with the GB10,
    // which was then told its own accelerator was missing. The daemon already
    // knows: it detects the hardware and publishes the tier at /capability.
    let tier = local_tier();
    println!("{:<14} {:>7}  {:<12} {}", "MODEL", "SIZE", "NEEDS", "");
    for id in ORCHESTRATORS {
        let e = match entry(id) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mark = if here.as_deref() == Some(*id) { "  <- running here" } else { "" };
        // Said rather than hidden: a machine with no accelerator can still be
        // told to run a 9B, and the honest answer is that it will be slow, not
        // that the model does not exist.
        let note = if e.needs_accelerator && tier != "accelerated" {
            "  (wants an accelerator)"
        } else {
            ""
        };
        println!("{:<14} {:>6.2}G  {:<12}{}{}", e.id, e.gib, e.min_tier(), mark, note);
    }
    println!();
    println!("one per machine. `furcatectl orchestrator set ID` to change it.");
    Ok(())
}

/// Which model is this node's agent, and where its weights came from.
pub fn orchestrator_show() -> Result<()> {
    match orchestrator_current() {
        Some(id) => {
            let path = weights(&id);
            println!("{id}");
            match std::fs::metadata(&path) {
                Ok(m) => println!("  weights  {} ({:.2} GiB)", path.display(), m.len() as f64 / 1_073_741_824.0),
                Err(_) => println!("  weights  MISSING at {}", path.display()),
            }
        }
        None => {
            println!("this machine has no orchestrator");
            println!("choose one with `furcatectl orchestrator set qwen3.5-0.8b`");
        }
    }
    Ok(())
}

/// Make a model this node's agent.
pub fn orchestrator_set(id: &str) -> Result<()> {
    if !is_orchestrator(id) {
        bail!(
            "`{id}` is not one of the orchestrator models\n\n{}",
            ORCHESTRATORS.join("\n")
        );
    }
    // Fetch only if it is not already here: an operator running this twice
    // should not re-download several gigabytes.
    if !weights(id).is_file() {
        println!("fetching {id}...");
        pull(id)?;
    }
    std::fs::create_dir_all(orchestrator_path().parent().unwrap_or(std::path::Path::new("/")))?;
    std::fs::write(orchestrator_path(), format!("{id}\n"))?;
    println!("{id} is this machine's orchestrator");
    println!();
    println!("serve and register it:");
    println!("  furcatectl model gateway");
    println!("  curl -sS -XPOST http://127.0.0.1:7616/models/load -H 'content-type: application/json' \\");
    println!("    -d '{{\"id\":\"{id}\",\"path\":\"{}\",\"endpoint\":\"http://127.0.0.1:8750\"}}'", weights(id).display());
    Ok(())
}

/// Install weights from a path rather than the internet.
///
/// The air-gapped case, and the ordinary one on a slow link: a fleet downloads
/// once and the file travels on a drive or over the LAN. The digest is printed
/// so the operator can compare it with the machine it came from -- this copies
/// bytes and does not vouch for them.
pub fn orchestrator_import(path: &str, id: &str) -> Result<()> {
    if !is_orchestrator(id) {
        bail!("`{id}` is not one of the orchestrator models");
    }
    let src = std::path::Path::new(path);
    if !src.is_file() {
        bail!("{path} is not a file");
    }
    let dest = weights(id);
    if dest.is_file() {
        bail!("{} already exists; remove it first if you mean to replace it", dest.display());
    }
    std::fs::create_dir_all(dest.parent().unwrap_or(std::path::Path::new("/")))?;
    std::fs::copy(src, &dest).with_context(|| format!("copying {path} to {}", dest.display()))?;
    let bytes = std::fs::metadata(&dest)?.len();
    println!("imported {id} — {:.2} GiB at {}", bytes as f64 / 1_073_741_824.0, dest.display());
    println!("  sha256 {}", sha256_file(&dest)?);
    println!();
    println!("make it this machine's agent:  furcatectl orchestrator set {id}");
    Ok(())
}

/// Copy this machine's weights out, to carry somewhere with no internet.
pub fn orchestrator_export(id: &str, path: &str) -> Result<()> {
    let src = weights(id);
    if !src.is_file() {
        bail!("{} is not here; nothing to export", src.display());
    }
    let dest = std::path::Path::new(path);
    if dest.exists() {
        bail!("{path} already exists; refusing to overwrite");
    }
    std::fs::copy(&src, dest).with_context(|| format!("copying to {path}"))?;
    println!("exported {id} to {path}");
    println!("  sha256 {}", sha256_file(&src)?);
    println!();
    println!("on the other machine:  furcatectl orchestrator import {path} {id}");
    Ok(())
}

/// Send weights to another machine on the LAN.
///
/// So a fleet downloads once. Over ssh rather than a new protocol: the
/// operator already has a way onto these machines, and a file transfer is not
/// a reason to open another port or invent an authenticated channel for it.
pub fn orchestrator_push(id: &str, node: &str) -> Result<()> {
    let src = weights(id);
    if !src.is_file() {
        bail!("{} is not here; fetch it first with `furcatectl orchestrator set {id}`", src.display());
    }
    let bytes = std::fs::metadata(&src)?.len();
    println!("sending {id} ({:.2} GiB) to {node}...", bytes as f64 / 1_073_741_824.0);
    let status = Command::new("scp")
        .args(["-q", &src.display().to_string(), &format!("{node}:{}", src.display())])
        .status()
        .context("running scp")?;
    if !status.success() {
        bail!("scp to {node} failed");
    }
    println!("sent. on {node}:  furcatectl orchestrator set {id}");
    Ok(())
}

/// The digest of a file, so two machines can agree they hold the same weights.
fn sha256_file(path: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    // Read in chunks rather than to a Vec: these files are gigabytes, and a
    // digest that needs the whole model resident to compute is a digest that
    // fails on the machine most in need of checking one.
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn entry(id: &str) -> Result<&'static Entry> {
    CATALOG.iter().find(|e| e.id == id).with_context(|| {
        let known = CATALOG.iter().map(|e| e.id).collect::<Vec<_>>().join(", ");
        format!(
            "no model `{id}` in the catalog.\nKnown: {known}\n\n\
             A model outside the catalog can still be served: put the .gguf at\n\
             {}/<id>.gguf and `furcatectl model serve <id>` will use it.",
            models_dir().display()
        )
    })
}

fn weights(id: &str) -> PathBuf {
    models_dir().join(format!("{id}.gguf"))
}

fn server() -> PathBuf {
    runtime_dir().join("llama-server")
}

fn require_runtime() -> Result<PathBuf> {
    let s = server();
    if !s.is_file() {
        bail!(
            "no inference runtime at {}\n\n\
             The runtime ships inside the Furcate system extension. A node that\n\
             does not have it is running an extension built before local\n\
             inference existed; take a cluster update and try again.",
            s.display()
        );
    }
    Ok(s)
}

fn unit_name(id: &str) -> String {
    format!("furcate-model-{id}.service")
}

fn unit_path(id: &str) -> PathBuf {
    Path::new("/etc/systemd/system").join(unit_name(id))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// operator defaults
// ---------------------------------------------------------------------------

/// Read `/etc/furcate/model.conf`, if the operator wrote one.
///
/// `key = value`, `#` comments, everything optional. A missing file, a missing
/// key and an unparseable value all mean the same thing — use the default —
/// because a node refusing to serve a model over a typo in an optional config
/// file is a worse failure than ignoring the line.
fn conf(key: &str) -> Option<String> {
    let text = std::fs::read_to_string(CONF).ok()?;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum Device {
    /// Use the accelerator the runtime reports. The default. With none, refuse:
    /// the CPU is a choice the operator makes, not one made for them.
    Auto,
    /// Use it, and fail loudly if there is none — so a node that was meant to be
    /// the cluster's GPU node says so instead of quietly running on CPU at a
    /// twentieth of the speed.
    Gpu,
    /// Stay on CPU even where an accelerator exists. An operator may be keeping
    /// the GPU for something else, and that is their call to make.
    Cpu,
    /// The node's NPU. Refused, with the reason, for every model the runtime
    /// serves today (see `npu::Npu::cannot_serve`); accepted as a value so
    /// that asking for it gets that answer rather than "unknown device".
    Npu,
}

impl Device {
    fn parse(s: &str) -> Result<Device> {
        match s {
            "auto" => Ok(Device::Auto),
            "gpu" => Ok(Device::Gpu),
            "cpu" => Ok(Device::Cpu),
            "npu" => Ok(Device::Npu),
            other => bail!("unknown device `{other}` — use auto, gpu, npu or cpu"),
        }
    }
}

/// Ask the runtime what it can offload to, rather than inferring it.
///
/// `nvidia-smi` answers "is there an NVIDIA card", which is a different question
/// from "can this build use it" — the runtime ships a Vulkan backend, so the
/// answer depends on the driver and the loader as much as the card. The binary
/// that will do the work is the only thing that knows.
fn devices() -> Vec<String> {
    let out = Command::new(server())
        .arg("--list-devices")
        .env("LD_LIBRARY_PATH", runtime_dir())
        .output();
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip_while(|l| !l.contains("Available devices"))
        .skip(1)
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && *l != "(none)")
        .map(String::from)
        .collect()
}

/// Where `what` runs: (layers offloaded, device name), or why it cannot run.
///
/// `gpus` is what the runtime reports, `npus` what the kernel reports. Pure, so
/// every path is tested without the hardware.
fn choose(device: Device, layers: Option<u32>, gpus: &[String], npus: &[crate::npu::Npu], what: &str) -> Result<(u32, String)> {
    let npu_notes = || -> String {
        npus.iter().map(|n| format!("\n\n{}", n.cannot_serve(what))).collect()
    };
    let explicit_cpu = format!(
        "\n\nTo serve on the CPU, choose it: add --cpu, or set `device = cpu` in {CONF}."
    );
    match device {
        Device::Cpu => Ok((0, "cpu".to_string())),
        // 99 means "as many as fit". An exact count is a tuning decision and
        // stays available; guessing one on the operator's behalf is not better
        // than letting the runtime place what it can.
        Device::Gpu | Device::Auto if !gpus.is_empty() => Ok((layers.unwrap_or(99), gpus[0].clone())),
        Device::Gpu => bail!(
            "--gpu was asked for and the runtime reports no device it can use here.\n\n\
             That is a driver or loader question as much as a hardware one: the build\n\
             offloads through Vulkan, so a GPU with no working Vulkan loader looks like no GPU.{}{explicit_cpu}",
            npu_notes()
        ),
        Device::Npu if npus.is_empty() => bail!(
            "--device npu was asked for and the kernel reports no NPU on this node.{explicit_cpu}"
        ),
        Device::Npu => bail!("{}{explicit_cpu}", npu_notes().trim_start()),
        Device::Auto => bail!(
            "not started: the runtime reports no accelerator it can use on this node, and\n\
             serving on the CPU is not chosen for you.{}{explicit_cpu}",
            npu_notes()
        ),
    }
}

// ---------------------------------------------------------------------------
// credential
// ---------------------------------------------------------------------------

pub(crate) fn token_path(id: &str) -> PathBuf {
    models_dir().join(format!("{id}.token"))
}

/// The credential the endpoint requires, minted once per model and kept.
///
/// ## Why a local endpoint is authenticated at all
///
/// It binds loopback, so nothing off the machine can reach it. But a node runs
/// deployed applications, and loopback is shared by every one of them: without a
/// credential, any process on the box can spend the model's time. The token is
/// what makes "this application may use the model" a decision rather than a
/// consequence of being on the same host.
///
/// It also makes the endpoint fit what applications already expect. praecise
/// runs the first declared endpoint *whose credential is present*, so an
/// endpoint with no credential is one it will never select. Issuing a real token
/// satisfies that contract honestly; setting a placeholder to get past the check
/// would satisfy the letter of it and leave the model open.
fn token(id: &str) -> Result<String> {
    let p = token_path(id);
    if let Ok(t) = std::fs::read_to_string(&p) {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    // read_exact, not read-to-end: /dev/urandom never reaches EOF, so reading it
    // as a file hangs forever at 100% CPU. That is not hypothetical — it is a
    // bug this codebase already shipped once.
    use std::io::Read as _;
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .context("reading /dev/urandom to mint a model credential")?;
    let t = hex::encode(buf);
    std::fs::create_dir_all(models_dir())?;
    std::fs::write(&p, format!("{t}\n"))?;
    // The registry is readable so applications can discover the endpoint. The
    // credential is not part of that and stays with its owner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(t)
}

pub fn credential(id: &str) -> Result<()> {
    let p = token_path(id);
    let t = std::fs::read_to_string(&p)
        .with_context(|| format!("no credential for `{id}` — it is minted by `furcatectl model serve {id}`"))?;
    println!("{}", t.trim());
    Ok(())
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

/// What is being served, so an application can find it without being told.
///
/// A file rather than a lookup service: the consumer is a config file being
/// written by a person or a deploy, and adding a discovery protocol to answer
/// "which port" would be a service to keep alive for no gain.
fn registry_read() -> serde_json::Value {
    std::fs::read_to_string(registry())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({ "models": [] }))
}

fn registry_write(v: &serde_json::Value) -> Result<()> {
    std::fs::create_dir_all(models_dir())?;
    let tmp = registry().with_extension("json.tmp");
    std::fs::write(&tmp, format!("{}\n", serde_json::to_string_pretty(v)?))?;
    std::fs::rename(&tmp, registry())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn registry_set(id: &str, port: u16, ctx: u32, dev: &str, ngl: u32, reasoning: &str) -> Result<()> {
    let mut v = registry_read();
    let list = v["models"].as_array_mut().context("registry is not a list")?;
    list.retain(|m| m["id"].as_str() != Some(id));
    list.push(serde_json::json!({
        "id": id,
        "port": port,
        "base_url": format!("http://127.0.0.1:{port}/v1"),
        // What an app needs in order to talk to it. `speaks` is praecise's word
        // for the wire format. `tools` is here because an agent that cannot call
        // a tool is a different product from one that can, and that is a
        // property of the model rather than of the server.
        "speaks": "chat",
        "tools": true,
        "context": ctx,
        "device": dev,
        "gpu_layers": ngl,
        "reasoning": reasoning,
        // The path, never the secret. This file is how applications discover the
        // endpoint, so it is readable, so it must not carry the credential.
        "credential_file": token_path(id).display().to_string(),
        "since": now(),
    }));
    registry_write(&v)
}

fn registry_clear(id: &str) -> Result<()> {
    let mut v = registry_read();
    if let Some(list) = v["models"].as_array_mut() {
        list.retain(|m| m["id"].as_str() != Some(id));
    }
    registry_write(&v)
}

fn allocate_port(id: &str) -> Result<u16> {
    // A model already in the registry keeps its port, so restarting one does not
    // move the endpoint out from under an application that wrote it into a
    // config file.
    let v = registry_read();
    if let Some(list) = v["models"].as_array() {
        for m in list {
            if m["id"].as_str() == Some(id) {
                if let Some(p) = m["port"].as_u64() {
                    return Ok(p as u16);
                }
            }
        }
    }
    let taken: Vec<u16> = v["models"]
        .as_array()
        .map(|l| l.iter().filter_map(|m| m["port"].as_u64().map(|p| p as u16)).collect())
        .unwrap_or_default();
    (PORT_LOW..=PORT_HIGH)
        .find(|p| !taken.contains(p))
        .context("no free port in the model band 8700-8749")
}

// ---------------------------------------------------------------------------
// pull
// ---------------------------------------------------------------------------

/// Fetch a model's weights.
///
/// Verification is against the digest the source advertises for the file
/// (`x-linked-etag`, which for a HuggingFace LFS object is its sha256), read at
/// download time rather than pinned here. Pinning would be stronger provenance
/// and weaker in practice: a repository legitimately requantises, and a
/// hard-coded digest turns that into a failure the operator cannot fix without a
/// new Furcate release.
///
/// Be clear about what this does and does not prove. It establishes that the
/// bytes on disk are the bytes the repository served. It is not a statement
/// about who produced the weights.
pub fn pull(id: &str) -> Result<()> {
    let e = entry(id)?;
    let dest = weights(id);
    let url = format!("https://huggingface.co/{}/resolve/main/{}", e.repo, e.file);

    if dest.is_file() {
        let have = std::fs::metadata(&dest)?.len();
        println!("{id} already present — {:.2} GiB at {}", have as f64 / 1_073_741_824.0, dest.display());
        return Ok(());
    }

    std::fs::create_dir_all(models_dir())?;

    let head = Command::new("curl")
        .args(["-sIL", "--max-time", "60", &url])
        .output()
        .context("running curl to read the model's headers")?;
    let headers = String::from_utf8_lossy(&head.stdout);
    // The LAST such header: -L follows redirects and each hop may carry one, so
    // the final hop is the one that served the bytes.
    let want = headers
        .lines()
        .rev()
        .find(|l| l.to_ascii_lowercase().starts_with("x-linked-etag:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        // A SHA-256, or nothing: a git blob id (what a non-LFS file carries
        // here) names the bytes but is not the digest checked below.
        .filter(|v| v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()));

    // Weights reach a node only with a digest to check them against. A source
    // that advertises none is refused before a byte is fetched.
    let Some(want) = want else {
        bail!(
            "refusing to pull {id}: {url} advertised no SHA-256 (x-linked-etag), so the\n\
             weights could not be verified. Nothing was downloaded."
        );
    };
    println!("pulling {id} — {:.2} GiB from {}", e.gib, e.repo);

    // Download beside the target and rename, so an interrupted pull never leaves
    // a half file that looks like a model. `--fail` matters: without it curl
    // writes an HTML error page to the output file and exits zero.
    let part = dest.with_extension("part");

    // Resume rather than restart.
    //
    // These are gigabytes over a link that may drop: the 9B failed at 51% with
    // curl 92 (an HTTP/2 stream the far end cancelled), and the old code then
    // deleted 2.7 GB of perfectly good bytes so the next attempt began at zero.
    // `-C -` continues from whatever is on disk and is harmless on a fresh
    // file; the digest check at the end is what decides whether the result is
    // the model, so resuming cannot quietly produce a wrong one.
    //
    // More retries and a longer delay for the same reason: the failure this is
    // built for is a transfer interrupted midway, not a server that is down.
    let mut attempt = 0;
    let st = loop {
        attempt += 1;
        let st = Command::new("curl")
            .args([
                "-fL", "-C", "-",
                "--retry", "5", "--retry-delay", "3", "--retry-all-errors",
                // A stall is a failure worth retrying rather than waiting out:
                // under 30 KB/s for a minute means the transfer has stopped
                // moving, whatever the socket believes.
                "--speed-limit", "30000", "--speed-time", "60",
                "-o",
            ])
            .arg(&part)
            .arg(&url)
            .status()
            .context("running curl to fetch the model")?;
        if st.success() || attempt >= 3 {
            break st;
        }
        let have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        println!(
            "  interrupted at {:.2} GiB — resuming (attempt {})",
            have as f64 / 1_073_741_824.0,
            attempt + 1
        );
    };
    if !st.success() {
        // The partial file is KEPT. It is most of a model, and the next run
        // continues from it; deleting it is how a flaky link turns into a
        // download that can never finish.
        let have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        bail!(
            "download failed for {id} — curl exited {}. {:.2} GiB is kept at {}; \
             run the same command again to continue from there",
            st.code().unwrap_or(-1),
            have as f64 / 1_073_741_824.0,
            part.display()
        );
    }

    {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        // Chunked rather than read-to-end: the largest catalog entry is over five
        // gigabytes and hashing it must not require holding it in memory.
        let mut f = std::fs::File::open(&part)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let got = hex::encode(h.finalize());
        if !got.eq_ignore_ascii_case(&want) {
            let _ = std::fs::remove_file(&part);
            bail!("digest mismatch for {id}\n  expected {want}\n  got      {got}\nThe file was removed.");
        }
        println!("  digest verified: {}", &got[..16]);
    }

    std::fs::rename(&part, &dest)?;
    let n = std::fs::metadata(&dest)?.len();
    println!("  {} — {:.2} GiB", dest.display(), n as f64 / 1_073_741_824.0);
    gateway_refresh();
    Ok(())
}

/// Make a running gateway notice a model that was not there when it started.
///
/// The router reads its directory **once**, at startup. So pulling a model while
/// the gateway is up leaves the weights on disk and the endpoint answering
/// `HTTP 400 model not found` — the two disagree, and nothing says so. That is
/// the kind of gap an operator debugs against the application instead of the
/// platform.
///
/// Restarting is the only way to re-read it. Done here rather than left to the
/// operator, because "pull then restart the gateway" is a rule nobody should
/// have to know, and forgetting it produces a failure that looks like a broken
/// app.
fn gateway_refresh() {
    let unit = unit_name(ROUTER);
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", &unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    // Only the gateway that reads this store. A pull into another store
    // (FURCATE_MODELS_DIR) has nothing to tell the running one.
    let reads_this_store = std::fs::read_to_string(unit_path(ROUTER))
        .map(|t| t.contains(&format!("--models-dir {} ", models_dir().display())))
        .unwrap_or(false);
    if !active || !reads_this_store {
        return;
    }
    println!("  gateway is running and reads its models at start — restarting it to pick this up");
    let before = main_pid(&unit);
    let _ = Command::new("systemctl").args(["restart", "--no-block", &unit]).status();
    if let Err(e) = await_new_process(&unit, before) {
        eprintln!("  WARNING the gateway did not come back: {e}");
        return;
    }
    // A new process is not a serving one. Reporting "restarted" while the
    // endpoint still 404s for the model just pulled would hand the operator a
    // failure that resolves itself a few seconds after they have stopped
    // looking -- and taught them not to trust the message.
    let tok = std::fs::read_to_string(token_path("gateway")).unwrap_or_default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::time::Instant::now() < deadline {
        if let Some((200, b)) = http(ROUTER_PORT, "/v1/models", None, Some(tok.trim()), 5) {
            if b.contains("\"id\"") {
                println!("  gateway restarted and listing models again");
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(600));
    }
    eprintln!("  WARNING the gateway restarted but is not listing models yet");
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}

/// Whether the model is allowed to think before answering.
///
/// ## Why this is surfaced rather than buried
///
/// The Qwen3 and Qwen3.5 families are reasoning models: they emit a thought
/// trace which the runtime, given `--jinja`, splits into `reasoning_content` and
/// leaves `content` empty until the thinking finishes. So a caller that sends a
/// modest `max_tokens` gets **an empty answer and no error** — the request
/// succeeded, the tokens were spent, and the content field is blank.
///
/// That is a silent failure, and the kind that gets blamed on the model. It is
/// not a broken model; it is a budget too small to reach the answer. `off` makes
/// the endpoint behave like an ordinary chat model, `on` forces thinking, and
/// `auto` leaves the decision to the template — which is the runtime's own
/// default, and so the one that imposes no opinion of ours.
fn reasoning_setting(flag: Option<&str>) -> Result<String> {
    let v = flag
        .map(String::from)
        .or_else(|| conf("reasoning"))
        .unwrap_or_else(|| "auto".to_string());
    match v.as_str() {
        "on" | "off" | "auto" => Ok(v),
        other => bail!("unknown reasoning setting `{other}` — use on, off or auto"),
    }
}

fn write_unit(id: &str, port: u16, ctx: u32, ngl: u32, reasoning: &str, tok: &str) -> Result<()> {
    let bin = server();
    let model = weights(id);
    // Leave one core. A model server that saturates every thread makes the node
    // unresponsive, and this is an operating layer before it is an inference
    // host. Irrelevant when the work is on a GPU, and harmless there.
    let t = threads().saturating_sub(1).max(1);

    let unit = format!(
        "# Generated by `furcatectl model serve`. Edits are overwritten.\n\
         [Unit]\n\
         Description=Furcate local model {id}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         OnFailure=notify-failure@%N.service\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         # The runtime's shared objects sit beside the binary in the extension.\n\
         # systemd resolves neither a bare program name nor a relative library\n\
         # path, so both are absolute.\n\
         Environment=LD_LIBRARY_PATH={runtime}\n\
         # --alias is why /v1/models reports `{id}` rather than the path of the\n\
         # file on disk. An application declares a model by name, and a name that\n\
         # changes when the weights move is not a name.\n\
         # --jinja is not optional: without it the model's chat template is not\n\
         # applied and tool calling silently does not work — the model emits a\n\
         # tool call as ordinary prose and the caller sees a plain answer that\n\
         # happens to be wrong.\n\
         # -ngl {ngl} is how many layers go to the accelerator. 0 is CPU.\n\
         ExecStart={bin} --model {model} --alias {id} \\\n\
             --host 127.0.0.1 --port {port} --ctx-size {ctx} --threads {t} \\\n\
             --n-gpu-layers {ngl} --reasoning {reasoning} --jinja --api-key-file {tokfile}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # Loading weights from cold cache is slow and is not a hang.\n\
         TimeoutStartSec=600\n\
         TimeoutStopSec=30\n\
         KillSignal=SIGTERM\n\
         \n\
         NoNewPrivileges=true\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ProtectKernelTunables=true\n\
         ProtectControlGroups=true\n\
         # Weights and the credential are read-only to the thing serving them. A\n\
         # model server has no reason to write to the file it loaded, and this is\n\
         # the cheapest way to be sure a bug cannot corrupt a large download.\n\
         ReadOnlyPaths={models}\n\
         # Binds one loopback socket and speaks to nothing else. No AF_NETLINK:\n\
         # this runtime does not enumerate interfaces, and the health gate below\n\
         # would catch it if that were ever wrong.\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
         # DeviceAllow rather than PrivateDevices=yes: an accelerator IS a device,\n\
         # and a sandbox that hides /dev/dri turns a GPU node into a slow CPU one\n\
         # with no error to explain it.\n\
         DeviceAllow=/dev/dri rw\n\
         DeviceAllow=char-nvidia rw\n\
         SupplementaryGroups=video render\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        id = id,
        runtime = runtime_dir().display(),
        bin = bin.display(),
        model = model.display(),
        models = models_dir().display(),
        tokfile = token_path(id).display(),
        port = port,
        ctx = ctx,
        ngl = ngl,
        reasoning = reasoning,
        t = t,
    );
    let _ = tok;
    std::fs::write(unit_path(id), unit)?;
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    Ok(())
}

/// The unit's current main PID, or 0 when it is not running.
fn main_pid(unit: &str) -> u32 {
    Command::new("systemctl")
        .args(["show", unit, "-p", "MainPID", "--value"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

/// Block until the unit is running under a process that is not the one we
/// replaced.
///
/// The old PID is what we are waiting to stop seeing. Waiting merely for a
/// non-zero PID would be satisfied instantly by the process still shutting down.
fn await_new_process(unit: &str, before: u32) -> Result<()> {
    // Comfortably longer than the unit's own TimeoutStopSec, so a server that
    // insists on finishing a long completion before exiting is waited out rather
    // than reported as a failure to start.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < deadline {
        let now = main_pid(unit);
        if now != 0 && now != before {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    bail!(
        "{unit} did not come up under a new process within 90s.\n\
         The previous one may still be finishing a request:\n  systemctl status {unit}"
    )
}

/// One HTTP request, returning the body. Enough for a health check and a single
/// completion; anything richer belongs to the application, not the operator CLI.
fn http(port: u16, path: &str, body: Option<&str>, tok: Option<&str>, secs: u64) -> Option<(u16, String)> {
    http_at("127.0.0.1", port, path, body, tok, secs)
}

/// The same, against a named address — for a gateway that is not on loopback.
fn http_at(host: &str, port: u16, path: &str, body: Option<&str>, tok: Option<&str>, secs: u64) -> Option<(u16, String)> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = format!("{host}:{port}").to_socket_addrs().ok()?.next()?;
    let mut c = TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(800)).ok()?;
    c.set_read_timeout(Some(std::time::Duration::from_secs(secs))).ok()?;
    c.set_write_timeout(Some(std::time::Duration::from_secs(10))).ok()?;
    let auth = tok.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = match body {
        Some(b) => format!(
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}Content-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
            b.len()
        ),
        None => format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Connection: close\r\n\r\n"),
    };
    c.write_all(req.as_bytes()).ok()?;
    let mut s = String::new();
    c.read_to_string(&mut s).ok()?;
    let code = s.split_whitespace().nth(1).and_then(|c| c.parse().ok())?;
    let body = s.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Some((code, body))
}

/// Wait for the model to load, then prove it can actually answer.
///
/// Two steps because they fail differently. `/health` returning 200 means the
/// weights finished loading — while loading it returns 503, so a socket check
/// alone would pass on a server that cannot yet do anything. And a loaded model
/// is still not a working one: the completion below is what distinguishes a
/// server that is up from a server that is *serving*.
///
/// This is the same lesson as a TCP-connect gate passing while every request
/// times out. The gate has to make the request the user will make.
fn health_gate(port: u16, tok: &str, secs: u64) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last = String::from("no response");
    while std::time::Instant::now() < deadline {
        match http(port, "/health", None, Some(tok), 5) {
            Some((200, _)) => {
                let probe = r#"{"messages":[{"role":"user","content":"ok"}],"max_tokens":1}"#;
                return match http(port, "/v1/chat/completions", Some(probe), Some(tok), 180) {
                    Some((200, b)) if b.contains("\"choices\"") => Ok(()),
                    Some((401, _)) => bail!("the model rejected its own credential — the token file and the unit disagree"),
                    Some((c, b)) => bail!(
                        "the model loaded but will not answer: HTTP {c}\n{}",
                        b.chars().take(300).collect::<String>()
                    ),
                    None => bail!("the model loaded but the completion request got no response"),
                };
            }
            Some((c, _)) => last = format!("HTTP {c} from /health"),
            None => last = "not listening yet".into(),
        }
        std::thread::sleep(std::time::Duration::from_millis(700));
    }
    bail!("model did not become ready within {secs}s — last saw: {last}")
}

/// `furcatectl model serve ID [--cpu|--gpu|--device D] [--context N] [--gpu-layers N]`
///
/// Precedence is flag, then `/etc/furcate/model.conf`, then the built-in default.
/// The operator can decide once in the file or per invocation on the line, and
/// deciding nothing at all is also a valid choice.
pub fn serve(id: &str, args: &[&str]) -> Result<()> {
    let mut device = match conf("device") {
        Some(d) => Device::parse(&d).context("reading `device` from /etc/furcate/model.conf")?,
        None => Device::Auto,
    };
    let mut ctx: u32 = conf("context").and_then(|c| c.parse().ok()).unwrap_or(8192);
    let mut layers: Option<u32> = conf("gpu_layers").and_then(|c| c.parse().ok());
    let mut reasoning_flag: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--cpu" => device = Device::Cpu,
            "--gpu" => device = Device::Gpu,
            "--device" => {
                i += 1;
                device = Device::parse(args.get(i).context("--device needs a value")?)?;
            }
            "--context" => {
                i += 1;
                ctx = args.get(i).context("--context needs a value")?.parse().context("--context must be a number of tokens")?;
            }
            "--gpu-layers" => {
                i += 1;
                layers = Some(args.get(i).context("--gpu-layers needs a value")?.parse().context("--gpu-layers must be a number")?);
            }
            "--reasoning" => {
                i += 1;
                reasoning_flag = Some((*args.get(i).context("--reasoning needs a value")?).to_string());
            }
            other => bail!(
                "unknown option `{other}`\n\nusage: furcatectl model serve ID \
                 [--cpu|--gpu|--device auto|gpu|npu|cpu] [--context N] [--gpu-layers N] \
                 [--reasoning on|off|auto]"
            ),
        }
        i += 1;
    }

    require_runtime()?;
    let model = weights(id);
    if !model.is_file() {
        bail!("no weights for `{id}` at {}\n\nRun `furcatectl model pull {id}` first.", model.display());
    }

    let (ngl, chosen) = choose(device, layers, &devices(), &crate::npu::present(), &format!("`{id}`"))?;

    // Say so before the operator waits for a load that will disappoint them.
    // Not a refusal: a slow model on a CPU is a legitimate choice for batch work,
    // and the point is that it should be a choice rather than a surprise.
    if ngl == 0 {
        if let Some(e) = CATALOG.iter().find(|e| e.id == id) {
            if e.needs_accelerator {
                println!(
                    "  note: `{id}` is measured at roughly 8 tok/s without an accelerator —\n\
                     \x20       about 40 seconds for a short reply. Models up to 2B are\n\
                     \x20       comfortable on a CPU; this one is not."
                );
            }
        }
    }
    let reasoning = reasoning_setting(reasoning_flag.as_deref())?;
    let port = allocate_port(id)?;
    let tok = token(id)?;
    write_unit(id, port, ctx, ngl, &reasoning, &tok)?;

    let unit = unit_name(id);
    let _ = Command::new("systemctl").args(["enable", &unit]).status();

    // Whose process is answering matters more than whether anything is.
    //
    // Restarting a model that is mid-request does not free the port promptly:
    // the outgoing server finishes its current completion, and llama.cpp can sit
    // in "cleaning up before exit" long enough to reach TimeoutStopSec and be
    // killed. For that whole window something IS listening on the port — the
    // process that is leaving. A health gate that starts immediately talks to it,
    // gets nothing, and reports the new instance as broken while it is in fact
    // loading perfectly well.
    //
    // So the gate does not begin until the unit's main PID has actually changed.
    let before = main_pid(&unit);
    let ok = Command::new("systemctl")
        .args(["restart", "--no-block", &unit])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        bail!("systemctl could not start {unit}");
    }
    await_new_process(&unit, before)?;

    println!("serving {id} on 127.0.0.1:{port}");
    println!("  device  {chosen}{}", if ngl > 0 { format!(" ({ngl} layers offloaded)") } else { String::new() });
    println!("  context {ctx} tokens");
    println!("  reasoning {reasoning}");
    if reasoning != "off" {
        // Said once, here, because the alternative is an application author
        // debugging an endpoint that returns success and nothing else.
        println!(
            "    note: a reasoning model leaves `content` empty until it has finished thinking,\n\
             \x20         so a caller with a small max_tokens gets a blank answer and no error.\n\
             \x20         Budget for it, send \"chat_template_kwargs\":{{\"enable_thinking\":false}},\n\
             \x20         or serve with --reasoning off."
        );
    }

    // Generous, and scaled by nothing: a large model off a cold disk on a machine
    // that is also doing something else takes minutes, and failing something that
    // was merely slow is worse than waiting.
    if let Err(e) = health_gate(port, &tok, 900) {
        // Leave it running. The operator needs the logs, and stopping the unit is
        // the fastest way to destroy the evidence of why it did not come up.
        eprintln!("\n{unit} did not pass its health gate.\n{e}\n");
        eprintln!("It has been left running so the failure can be read:");
        eprintln!("  journalctl -u {unit} -n 50 --no-pager");
        bail!("{id} is not serving");
    }

    registry_set(id, port, ctx, &chosen, ngl, &reasoning)?;
    println!("ready — http://127.0.0.1:{port}/v1");
    println!("  credential: furcatectl model credential {id}");
    Ok(())
}

/// The port the gateway holds. One, fixed, and outside the per-model band.
///
/// Fixed rather than allocated because this is the address applications are
/// configured with. A port that moved when a model was added would break every
/// app that had written it down.
const GATEWAY_PORT: u16 = 8750;

/// The model router behind the gateway, on loopback only. Applications on
/// this machine use it with the loopback credential; nothing else reaches it.
const ROUTER_PORT: u16 = 8751;

/// The unit id of the router, beside the gateway's.
const ROUTER: &str = "router";

fn gateway_unit() -> String {
    unit_name("gateway")
}

/// Serve every local model from one OpenAI-compatible endpoint.
///
/// ## Why this exists as well as `serve`
///
/// `serve` runs one model on one port, which is the right shape for a node
/// dedicated to a model. It is the wrong shape for an application, because an
/// application does not declare a port per model — it declares **one endpoint
/// and a ladder of model ids on it**: something cheap for easy work, something
/// stronger for hard work. praecise's `fast` / `balanced` / `best` are exactly
/// that, and they are model ids on a single `url`.
///
/// With only `serve`, those three ids live on three ports, so an app can reach
/// exactly one of them and the ladder cannot climb. The gateway is what makes a
/// ladder expressible: one address, one credential, every model the node has,
/// loaded on demand and unloaded when something else needs the room.
///
/// The runtime does the routing itself (llama.cpp's router mode), bound to
/// loopback. What the cell reaches is the door in `model_front`: it admits a
/// request signed by a leaf attached to the cell this node heads, or by the
/// operator, and hands it to the router. No shared secret is given to anything
/// off this machine.
pub fn gateway(args: &[&str]) -> Result<()> {
    let mut device = match conf("device") {
        Some(d) => Device::parse(&d).context("reading `device` from /etc/furcate/model.conf")?,
        None => Device::Auto,
    };
    let mut ctx: u32 = conf("context").and_then(|c| c.parse().ok()).unwrap_or(8192);
    let mut layers: Option<u32> = conf("gpu_layers").and_then(|c| c.parse().ok());
    let mut reasoning_flag: Option<String> = None;
    // How many may be resident at once. The runtime's own default is 4; on a
    // node with one accelerator that is a way to run out of memory, so it is
    // stated rather than inherited.
    let mut max: u32 = conf("models_max").and_then(|c| c.parse().ok()).unwrap_or(2);
    // Where the door listens. Loopback by default: a model endpoint is not
    // something to publish by accident. A cell's leaves need it on the cell's
    // network, and that is a decision the operator makes by naming an
    // address. The router itself is on loopback whatever this is.
    let mut bind: String = conf("bind").unwrap_or_else(|| "127.0.0.1".to_string());

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--cpu" => device = Device::Cpu,
            "--gpu" => device = Device::Gpu,
            "--device" => { i += 1; device = Device::parse(args.get(i).context("--device needs a value")?)?; }
            "--context" => { i += 1; ctx = args.get(i).context("--context needs a value")?.parse().context("--context must be a number")?; }
            "--gpu-layers" => { i += 1; layers = Some(args.get(i).context("--gpu-layers needs a value")?.parse().context("--gpu-layers must be a number")?); }
            "--reasoning" => { i += 1; reasoning_flag = Some((*args.get(i).context("--reasoning needs a value")?).to_string()); }
            "--max" => { i += 1; max = args.get(i).context("--max needs a value")?.parse().context("--max must be a number")?; }
            "--bind" => { i += 1; bind = (*args.get(i).context("--bind needs an address")?).to_string(); }
            other => bail!(
                "unknown option `{other}`\n\nusage: furcatectl model gateway \
                 [--cpu|--gpu|--device auto|gpu|npu|cpu] [--context N] [--gpu-layers N] \
                 [--reasoning on|off|auto] [--max N] [--bind ADDR]"
            ),
        }
        i += 1;
    }

    require_runtime()?;
    let present: Vec<String> = std::fs::read_dir(models_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("gguf") {
                p.file_stem().and_then(|x| x.to_str()).map(String::from)
            } else {
                None
            }
        })
        .collect();
    if present.is_empty() {
        bail!("no weights in {} — `furcatectl model pull <id>` first", models_dir().display());
    }

    let (ngl, chosen) = choose(device, layers, &devices(), &crate::npu::present(), "the gateway's models")?;
    let reasoning = reasoning_setting(reasoning_flag.as_deref())?;
    let tok = token("gateway")?;
    let t = threads().saturating_sub(1).max(1);

    let router = format!(
        "# Generated by `furcatectl model gateway`. Edits are overwritten.\n\
         [Unit]\n\
         Description=Furcate model router (every local model, loopback only)\n\
         OnFailure=notify-failure@%N.service\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         Environment=LD_LIBRARY_PATH={runtime}\n\
         # Router mode. The runtime starts a child per model on demand, so the\n\
         # binary must be able to execute itself, which is why this unit is not\n\
         # locked down as hard as a single-model one.\n\
         ExecStart={bin} --models-dir {models} --models-max {max} \\\n\
             --host 127.0.0.1 --port {port} --ctx-size {ctx} --threads {t} \\\n\
             --n-gpu-layers {ngl} --reasoning {reasoning} --jinja --api-key-file {tokfile}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         TimeoutStartSec=600\n\
         TimeoutStopSec=30\n\
         KillSignal=SIGTERM\n\
         \n\
         NoNewPrivileges=true\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ReadOnlyPaths={models}\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
         DeviceAllow=/dev/dri rw\n\
         DeviceAllow=char-nvidia rw\n\
         SupplementaryGroups=video render\n",
        runtime = runtime_dir().display(),
        bin = server().display(),
        models = models_dir().display(),
        tokfile = token_path("gateway").display(),
        port = ROUTER_PORT,
        ctx = ctx,
        ngl = ngl,
        max = max,
        reasoning = reasoning,
        t = t,
    );
    let me = std::env::current_exe().context("finding this furcatectl to run the gateway's door")?;
    // The door reads the cell's files where this command does, and the
    // router's credential from the store it was minted in.
    let door = format!(
        "# Generated by `furcatectl model gateway`. Edits are overwritten.\n\
         [Unit]\n\
         Description=Furcate model gateway (signed requests from the cell)\n\
         Requires={router_unit}\n\
         After={router_unit} network-online.target\n\
         Wants=network-online.target\n\
         OnFailure=notify-failure@%N.service\n\
         StartLimitIntervalSec=0\n\
         \n\
         [Service]\n\
         Type=simple\n\
         Environment=FURCATE_CONFIG_DIR={config}\n\
         Environment=FURCATE_STATE_DIR={state}\n\
         Environment=FURCATE_MODELS_DIR={models}\n\
         ExecStart={me} model front --bind {bind} --port {port} --upstream-port {router_port}\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         \n\
         NoNewPrivileges=true\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectControlGroups=yes\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
         MemoryMax=256M\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        router_unit = unit_name(ROUTER),
        config = furcate_paths::config_dir().display(),
        state = furcate_paths::state_dir().display(),
        models = models_dir().display(),
        me = me.display(),
        bind = bind,
        port = GATEWAY_PORT,
        router_port = ROUTER_PORT,
    );
    std::fs::write(unit_path(ROUTER), router)?;
    std::fs::write(unit_path("gateway"), door)?;
    let _ = Command::new("systemctl").arg("daemon-reload").status();

    // The router restarts first so the door's start finds it; the door
    // starts it anyway through Requires=.
    let r = unit_name(ROUTER);
    let before_router = main_pid(&r);
    if !Command::new("systemctl").args(["restart", "--no-block", &r]).status().map(|s| s.success()).unwrap_or(false) {
        bail!("systemctl could not start {r}");
    }
    await_new_process(&r, before_router)?;

    let u = gateway_unit();
    let _ = Command::new("systemctl").args(["enable", &u]).status();
    let before = main_pid(&u);
    if !Command::new("systemctl").args(["restart", "--no-block", &u]).status().map(|s| s.success()).unwrap_or(false) {
        bail!("systemctl could not start {u}");
    }
    await_new_process(&u, before)?;

    println!("gateway   {bind}:{GATEWAY_PORT} (signed requests)  router 127.0.0.1:{ROUTER_PORT}");
    println!("  device  {chosen}{}", if ngl > 0 { format!(" ({ngl} layers offloaded)") } else { String::new() });
    println!("  models  {} ({max} resident at once, loaded on demand)", present.join(", "));

    // The gate: the endpoint must list models, and one of them must answer.
    // Listing alone would pass on a router that can see files and load none.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut listed = false;
    while std::time::Instant::now() < deadline {
        if let Some((200, b)) = http(ROUTER_PORT, "/v1/models", None, Some(&tok), 5) {
            if b.contains("\"id\"") {
                listed = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(600));
    }
    if !listed {
        bail!("the router did not list any model within 120s\n  journalctl -u {r} -n 40 --no-pager");
    }

    let probe = format!(
        "{{\"model\":\"{}\",\"messages\":[{{\"role\":\"user\",\"content\":\"ok\"}}],\"max_tokens\":1}}",
        present[0]
    );
    match http(ROUTER_PORT, "/v1/chat/completions", Some(&probe), Some(&tok), 600) {
        Some((200, b)) if b.contains("\"choices\"") => {}
        Some((c, b)) => {
            eprintln!("\nthe gateway listed models but `{}` would not answer: HTTP {c}\n{}", present[0], b.chars().take(300).collect::<String>());
            bail!("gateway is not serving");
        }
        None => bail!("the gateway listed models but the completion got no response"),
    }

    // The door: up, and refusing what is not signed. A 401 to an unsigned
    // request is the answer that proves both; a 200 would mean the cell's
    // network reaches the models with no credential at all.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut door = None;
    while std::time::Instant::now() < deadline {
        door = http_at(&bind, GATEWAY_PORT, "/v1/models", None, None, 5).map(|(c, _)| c);
        if door.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    match door {
        Some(401) => {}
        Some(c) => bail!("the gateway answered an unsigned request with HTTP {c}; it must refuse it\n  journalctl -u {u} -n 40 --no-pager"),
        None => bail!("the gateway is not answering on {bind}:{GATEWAY_PORT}\n  journalctl -u {u} -n 40 --no-pager"),
    }

    let mut v = registry_read();
    let list = v["models"].as_array_mut().context("registry is not a list")?;
    list.retain(|m| m["id"].as_str() != Some("gateway"));
    list.push(serde_json::json!({
        "id": "gateway",
        // Applications on this machine: the router, with the loopback
        // credential in `credential_file`.
        "port": ROUTER_PORT,
        "base_url": format!("http://127.0.0.1:{ROUTER_PORT}/v1"),
        // The cell: the door, where a request is signed by an attached leaf
        // or by the operator, never by a shared token.
        "cell_url": format!("http://{bind}:{GATEWAY_PORT}/v1"),
        "cell_auth": "X-Furcate-Credential: leaf or operator signature",
        "speaks": "chat",
        "tools": true,
        "context": ctx,
        "device": chosen,
        "gpu_layers": ngl,
        "reasoning": reasoning,
        "bind": bind,
        "serves": present,
        "credential_file": token_path("gateway").display().to_string(),
        "since": now(),
    }));
    registry_write(&v)?;

    println!("ready — http://{bind}:{GATEWAY_PORT}/v1 for the cell (leaf- or operator-signed requests)");
    println!("  on this machine: http://127.0.0.1:{ROUTER_PORT}/v1 with `furcatectl model credential gateway`");
    if let Err(why) = crate::model_front::headed(now()) {
        println!("  NOTE no leaf is admitted until this node heads a cell: {why}");
    }
    println!("\nAn application declares one endpoint and names these ids for its rungs,");
    println!("which is what lets it ask for something cheap or something stronger.");
    Ok(())
}

pub fn stop(id: &str) -> Result<()> {
    // The gateway is its door and the router behind it.
    let ids: &[&str] = if id == "gateway" { &["gateway", ROUTER] } else { &[id] };
    for id in ids {
        let unit = unit_name(id);
        let _ = Command::new("systemctl").args(["disable", "--now", &unit]).status();
        let p = unit_path(id);
        if p.exists() {
            std::fs::remove_file(&p)?;
        }
    }
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    registry_clear(id)?;
    // The credential is kept. Stopping a model is not a decision to invalidate
    // every application config that names it, and serving it again should not
    // silently require re-issuing them all.
    println!("stopped {id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

pub fn list() -> Result<()> {
    let runtime = server().is_file();
    let v = registry_read();
    let serving: Vec<String> = v["models"]
        .as_array()
        .map(|l| l.iter().filter_map(|m| m["id"].as_str().map(String::from)).collect())
        .unwrap_or_default();

    if runtime {
        println!("runtime  {}", server().display());
        let d = devices();
        // What this node can actually do, stated plainly. An operator choosing
        // where a model should live is choosing between machines, and the answer
        // is not visible from the outside.
        if d.is_empty() {
            println!("device   none the runtime can use — serving here needs --cpu");
        } else {
            println!("device   {}", d.join(", "));
        }
        // An NPU is listed separately: the runtime cannot offload to one, and
        // leaving it out would make a board with one look like a board without.
        for n in crate::npu::present() {
            println!("npu      {} — serves none of the models below", n.describe());
        }
    } else {
        println!("runtime  not installed — take a cluster update");
    }
    println!("weights  {}", models_dir().display());
    if Path::new(CONF).exists() {
        println!("defaults {CONF}");
    }
    println!();

    println!("{:<15} {:>7}  {:<12} {:<10} ENDPOINT", "MODEL", "SIZE", "NEEDS", "STATE");
    for e in CATALOG {
        let have = weights(e.id).is_file();
        let up = serving.iter().any(|s| s == e.id);
        let state = if up { "serving" } else if have { "local" } else { "available" };
        let ep = if up {
            v["models"]
                .as_array()
                .and_then(|l| l.iter().find(|m| m["id"].as_str() == Some(e.id)))
                .and_then(|m| m["base_url"].as_str())
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };
        println!("{:<15} {:>6.2}G  {:<12} {:<10} {}", e.id, e.gib, e.min_tier(), state, ep);
    }

    // Anything served that the catalog does not know about — a model the operator
    // supplied themselves. Reporting only the catalog would make those invisible,
    // which is how a machine ends up serving something nobody can account for.
    for id in &serving {
        if !CATALOG.iter().any(|e| e.id == *id) {
            println!("{:<15} {:>7}  {:<12} {:<10} (supplied locally)", id, "-", "?", "serving");
        }
    }
    Ok(())
}

/// The base URL an application should be pointed at.
///
/// Prints one line and nothing else, because the caller is usually a shell
/// substitution writing a config file.
pub fn endpoint(id: Option<&str>) -> Result<()> {
    let v = registry_read();
    let list = v["models"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        bail!("no model is being served here.\nRun `furcatectl model serve <id>`.");
    }
    let m = match id {
        Some(want) => list
            .iter()
            .find(|m| m["id"].as_str() == Some(want))
            .with_context(|| format!("`{want}` is not being served on this node"))?,
        None => &list[0],
    };
    println!("{}", m["base_url"].as_str().unwrap_or_default());
    Ok(())
}

pub fn status() -> Result<()> {
    let v = registry_read();
    let list = v["models"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("no model is being served on this node");
        return Ok(());
    }
    for m in &list {
        let id = m["id"].as_str().unwrap_or("?");
        let port = m["port"].as_u64().unwrap_or(0) as u16;
        // Ask the server rather than trust the registry. The registry says what
        // was started; only the port says what is answering.
        let tok = std::fs::read_to_string(token_path(id)).unwrap_or_default();
        let live = matches!(http(port, "/health", None, Some(tok.trim()), 3), Some((200, _)));
        let ngl = m["gpu_layers"].as_u64().unwrap_or(0);
        println!(
            "{id}\n  endpoint  {}\n  device    {}{}\n  context   {} tokens\n  reasoning {}\n  tools     {}\n  state     {}",
            m["base_url"].as_str().unwrap_or_default(),
            m["device"].as_str().unwrap_or("?"),
            if ngl > 0 { format!(" ({ngl} layers offloaded)") } else { String::new() },
            m["context"].as_u64().unwrap_or(0),
            m["reasoning"].as_str().unwrap_or("auto"),
            if m["tools"].as_bool().unwrap_or(false) { "yes" } else { "no" },
            if live { "answering" } else { "REGISTERED BUT NOT ANSWERING" }
        );
        if let Some(cell) = m["cell_url"].as_str() {
            println!("  cell      {cell} (leaf- or operator-signed)");
        }
    }
    Ok(())
}

#[cfg(test)]
mod device_tests {
    use super::*;
    use crate::npu::{Family, Npu};

    fn hailo8() -> Npu {
        Npu {
            slot: "0001:01:00.0".into(),
            id: "1e60:2864".into(),
            family: Family::Hailo8,
            driver: Some("hailo_pci".into()),
            driver_version: Some("4.24.0".into()),
        }
    }

    #[test]
    fn auto_with_no_accelerator_refuses_and_names_the_explicit_cpu_choice() {
        let e = choose(Device::Auto, None, &[], &[], "`qwen3-0.6b`").unwrap_err().to_string();
        assert!(e.contains("not chosen for you"), "{e}");
        assert!(e.contains("--cpu"), "{e}");
    }

    #[test]
    fn auto_on_a_board_with_an_npu_says_why_the_npu_cannot_serve() {
        let e = choose(Device::Auto, None, &[], &[hailo8()], "`qwen3-0.6b`").unwrap_err().to_string();
        assert!(e.contains("Hailo-8/8L at 0001:01:00.0"), "{e}");
        assert!(e.contains("HEF"), "{e}");
        assert!(e.contains("--cpu"), "{e}");
    }

    #[test]
    fn asking_for_the_npu_is_refused_with_the_reason_never_run_elsewhere() {
        let e = choose(Device::Npu, None, &["Vulkan0".into()], &[hailo8()], "`qwen3-0.6b`").unwrap_err().to_string();
        assert!(e.starts_with("the NPU on this node"), "{e}");
        let e = choose(Device::Npu, None, &[], &[], "`qwen3-0.6b`").unwrap_err().to_string();
        assert!(e.contains("no NPU"), "{e}");
    }

    #[test]
    fn cpu_is_served_only_when_chosen() {
        assert_eq!(choose(Device::Cpu, None, &["Vulkan0".into()], &[hailo8()], "x").unwrap(), (0, "cpu".to_string()));
    }

    #[test]
    fn a_reported_gpu_is_used_by_auto_and_by_gpu() {
        let g = vec!["Vulkan0: NVIDIA GB10".to_string()];
        assert_eq!(choose(Device::Auto, None, &g, &[], "x").unwrap(), (99, g[0].clone()));
        assert_eq!(choose(Device::Gpu, Some(20), &g, &[], "x").unwrap(), (20, g[0].clone()));
        assert!(choose(Device::Gpu, None, &[], &[], "x").is_err());
    }

    #[test]
    fn npu_is_a_device_value() {
        assert_eq!(Device::parse("npu").unwrap(), Device::Npu);
        assert!(Device::parse("tpu").unwrap_err().to_string().contains("npu"));
    }
}
