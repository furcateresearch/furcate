//! `furcated` — the node agent.
//!
//! Runs on every machine. It holds the root of trust, keeps the operation
//! chain, watches health and power, tracks membership, publishes sensors and
//! capability, and serves the local API.
//!
//! The structural rule it exists to honour: **the node agent survives the
//! control plane**. A site controller crash must never cascade into a power
//! event, so this process holds its last known good intent, keeps enforcing
//! it, and degrades to safe autonomy rather than waiting for instructions.

mod actuate;
mod actuators;
mod bmc;
mod cells;
mod custody;
mod hardware;
mod host;
mod image;
mod keycustody;
pub mod extension;
mod network;
mod orders;
mod overlay;
pub mod policyfile;
mod resources;
mod power;
mod runtime;
mod wake;
mod ups;
pub mod workloads;

use furcate_api::{listen_also, serve_also, Request, Response, Router};
use furcate_health::{Lifecycle, Remediator, Signal, SignalKind, Transition};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use furcate_identity::{AssuranceClass, RootOfTrust, Sealer};
use furcate_ledger::{Chain, OpKind};
use furcate_membership::Membership;
use furcate_mesh::{Capability, InferenceReceipt, VerificationLevel};
use furcate_power::{BringUp, Gate, GateState, Ladder, Unit};
use furcate_sense::{Sensor, SensorKind, SensorRegistry};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared agent state.
///
/// One mutex around the whole thing is correct at this scale: contention is
/// nil, and a single lock removes any chance of two subsystems observing
/// inconsistent state during a power transition.
struct Agent {
    node_id: String,
    chain: Chain,
    ladder: Ladder,
    lifecycle: Lifecycle,
    membership: Membership,
    sensors: SensorRegistry,
    last_seen: BTreeMap<String, u64>,
    signals: Vec<Signal>,
    capability: Capability,
    bringup: BringUp,
    /// Models this node can actually serve, measured before load.
    models: BTreeMap<String, runtime::LoadedModel>,
    /// How many times the chain head has been committed to the chip.
    checkpoints: u64,
    /// An actuation asked for but not yet confirmed by the privileged half.
    pending_actuation: Option<String>,
    /// What the actuator last reported, verbatim.
    last_actuation: Option<serde_json::Value>,
    /// Last intent received from the site controller, retained so the agent
    /// can keep enforcing it when the controller is unreachable.
    last_intent: Option<String>,
    controller_seen_at: Option<u64>,
    ups: ups::Reading,
    /// Whether the current cordon was caused by a workload rather than by the
    /// machine itself.
    ///
    /// Kept so the node can come back on its own. A cordon that only a human
    /// can lift turns a container restarting into a machine out of service
    /// until somebody notices, which is worse than not cordoning at all.
    cordoned_by_workload: bool,
}

/// Where the operation chain is kept between restarts.
///
/// A hashchain that resets on restart is not an audit trail, and it breaks the
/// TPM checkpoint sequence and the Merkle site root along with it.
/// Fold the workload inventory into the node's own health.
///
/// Until this existed the inventory reached the controller's `/workloads` view
/// and nothing else: a node whose critical validator had died still reported
/// `signals: 0` and stayed eligible for new work. Cordoning is the right
/// response — it stops *new* placement and leaves running work alone — but only
/// with a way back, which is what the first branch does.
fn fold_workloads_into_health(a: &mut Agent, inv: &furcate_health::Inventory) {
    let now = now_s();

    // Every degraded workload is recorded, critical or not — an operator
    // should be able to see a scratch container failing. Only the critical
    // ones cordon, which the severity classification already decides, so a
    // machine is never taken out of service over something nobody depends on.
    //
    // Signals are deduplicated by kind: a container down for an hour would
    // otherwise append a chain entry every thirty seconds.
    for signal in inv.signals(&a.node_id, now) {
        if a.signals.iter().any(|s| s.kind == signal.kind) {
            continue;
        }
        if a.observe_signal(signal) == "cordoned" {
            a.cordoned_by_workload = true;
        }
    }

    // Nothing critical is broken any more. If the only reason this node was
    // cordoned was a workload, put it back in service — a cordon only a human
    // can lift turns a container restarting into a machine out of the fleet
    // until somebody notices.
    if inv.critical_degraded().is_empty() && a.cordoned_by_workload {
        let _ = a.lifecycle.apply(Transition::Restore);
        a.cordoned_by_workload = false;
        a.chain.append(
            now_ms(),
            OpKind::Lifecycle,
            "health",
            "workloads recovered".to_string(),
            "restored",
        );
        a.persist_chain();
    }
}

/// Fold kernel events and configuration changes into health and the chain.
///
/// Two loops closed here. The kernel has been reporting the faults this system
/// already models — I/O errors, machine checks, OOM kills — and nothing was
/// reading them. And a configuration edit is exactly the kind of thing that
/// belongs in a tamper-evident record: detecting drift is ordinary, chaining
/// it is the part worth having.
fn fold_custody_into_health(a: &mut Agent, r: &custody::CustodyReport) {
    let now = now_s();

    for e in &r.events {
        // Mapped onto the signal kinds that already exist rather than new
        // ones, so remediation and cordoning behave the way they always did.
        let kind = match e {
            furcate_host::journal::Event::IoError { device }
            | furcate_host::journal::Event::FilesystemReadOnly { device } => {
                SignalKind::DiskDegraded { device: device.clone(), reallocated: 0 }
            }
            furcate_host::journal::Event::MemoryError { count } => {
                SignalKind::MemoryErrors { count: *count }
            }
            furcate_host::journal::Event::MachineCheck { detail } => {
                SignalKind::PowerFault { detail: detail.clone() }
            }
            furcate_host::journal::Event::ThermalThrottle { .. } => {
                SignalKind::Thermal { sensor: "kernel".into(), celsius: 0.0 }
            }
            // An OOM kill, a link flap and a TPM error are recorded on the
            // chain below but do not map onto a hardware signal: the first is
            // a workload problem, the second is covered by the network
            // collector, and the third has its own recovery path.
            _ => continue,
        };
        let signal = Signal::new(&a.node_id, kind, now);
        if a.signals.iter().any(|s| s.kind == signal.kind) {
            continue;
        }
        a.observe_signal(signal);
    }

    // Faults the driver named, attached to the card that emitted them.
    //
    // The index comes from the published accelerator reading rather than from
    // the log line, because the log identifies a card by PCI address and every
    // scheduling decision downstream is expressed in indices. A fault whose
    // address matches no card this node can read keeps `index: None`, and
    // `Signal::drains_accelerator` then drains nothing rather than guessing —
    // stopping the wrong card leaves the fault where it is and takes working
    // hardware out of service.
    let (cards, _) = host::accelerators();
    for (pci, finding) in &r.xids {
        let class = &finding.class;
        let index = pci.as_deref().and_then(|key| {
            cards
                .iter()
                .find(|c| c.pci.as_deref().map(furcate_host::xid::pci_key).as_deref() == Some(key))
                .map(|c| c.index)
        });
        let signal = Signal::new(
            &a.node_id,
            SignalKind::AcceleratorFault {
                index,
                pci: pci.clone(),
                code: class.code,
                blame: class.blame.as_str().to_string(),
                remedy: class.remedy.as_str().to_string(),
                contained: class.contained,
                implicates_card: class.implicates_the_card(),
                should_drain: class.should_drain(),
                actionable: class.is_actionable(),
                summary: class.summary.clone(),
                seen: finding.repeats,
            },
            now,
        );
        if a.signals.iter().any(|s| s.kind == signal.kind) {
            continue;
        }
        a.observe_signal(signal);
    }

    for d in &r.drift {
        let (what, detail) = match d {
            furcate_host::custody::Drift::Changed { path, from, to } => (
                "config changed",
                format!("{path} {}->{}", &from[..8.min(from.len())], &to[..8.min(to.len())]),
            ),
            furcate_host::custody::Drift::Appeared { path } => ("config appeared", path.clone()),
            furcate_host::custody::Drift::Vanished { path } => ("config vanished", path.clone()),
        };
        a.chain.append(now_ms(), OpKind::Lifecycle, "config", detail, what);
        a.persist_chain();
    }
}

fn ledger_path() -> std::path::PathBuf {
    furcate_paths::state("ledger.json")
}

/// Where model registrations are kept between restarts.
fn model_registry_path() -> std::path::PathBuf {
    furcate_paths::state("models.json")
}

/// Where the recorded operating-system baseline lives.
fn baseline_path() -> std::path::PathBuf {
    furcate_paths::state("image-baseline.json")
}

/// The recorded baseline and when it was taken.
fn load_baseline() -> (Option<furcate_host::image::Image>, u64) {
    let Ok(text) = std::fs::read_to_string(baseline_path()) else {
        return (None, 0);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (None, 0);
    };
    let at = v.get("at").and_then(|a| a.as_u64()).unwrap_or(0);
    let image = v
        .get("image")
        .and_then(|i| serde_json::from_value(i.clone()).ok());
    (image, at)
}

fn save_baseline(image: &furcate_host::image::Image) -> std::io::Result<u64> {
    let at = now_s();
    let path = baseline_path();
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let body = serde_json::json!({ "at": at, "image": image });
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&body)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(at)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_s() -> u64 {
    now_ms() / 1000
}

const CONTROLLER_TIMEOUT_MS: u64 = 30_000;
/// Ticks a member may stay suspect before being confirmed dead.
const SUSPICION_BASE: u64 = 6;

impl Agent {
    /// What this node can do right now, for an edition that describes it to
    /// others.
    ///
    /// DERIVED from what the node can actually do, not declared in a config
    /// somebody has to remember to update: a description that advertises
    /// inference on a node with no model loaded is a router being told to send
    /// work that will be refused.
    fn facts(&self) -> extension::NodeFacts {
        let hw = furcate_host::hardware::recognise();
        extension::NodeFacts {
            node_id: self.node_id.clone(),
            tier: self.capability.tier(),
            // `models` is what survived measurement at registration, so this is
            // "can serve", not "was configured to serve".
            serves_models: !self.models.is_empty(),
            can_tune: hw.can("cpu_performance") == Some(true) || hw.can("power_cap") == Some(true),
            accepts_work: self.lifecycle.state().accepts_work(),
            parents_leaves: !self.sensors.is_empty(),
        }
    }

    /// Persist the chain. Called after anything that appends.
    ///
    /// Failure is logged rather than fatal: a node that cannot write its
    /// ledger should keep serving and say so, not stop.
    fn persist_chain(&self) {
        if let Err(e) = furcate_ledger::save(&self.chain, &ledger_path()) {
            eprintln!("furcated: WARNING ledger not persisted: {e}");
        }
    }

    /// Load the persisted chain and build an agent around it.
    fn new(node_id: String, capability: Capability) -> Self {
        // Continue the existing chain where there is one. Starting fresh over
        // a chain that failed verification would erase the evidence, so that
        // case is fatal rather than silently recovered.
        let chain = match furcate_ledger::load(&ledger_path()) {
            Ok(Some(existing)) => {
                eprintln!("furcated: ledger resumed at {} entries", existing.len());
                existing
            }
            Ok(None) => Chain::genesis(&node_id, now_ms()),
            Err(e) => {
                eprintln!("furcated: FATAL {e}");
                std::process::exit(1);
            }
        };
        Self::with_chain(node_id, capability, chain)
    }

    /// Build an agent around a chain the caller supplies.
    ///
    /// Split out from [`Agent::new`] so construction does not reach into the
    /// filesystem. A test that exercised the loading path would pass or fail
    /// depending on whether the machine running it happens to have a ledger,
    /// which is a property of the developer's home directory rather than of
    /// the code.
    fn with_chain(node_id: String, capability: Capability, chain: Chain) -> Self {
        // Units this agent expects to come up, with the gates that must open
        // first. The address gate is the one that would have prevented a
        // four-hour outage on this site.
        let units = vec![
            Unit {
                name: "root-of-trust".into(),
                gates: vec![],
                timeout: 30,
            },
            Unit {
                name: "api".into(),
                gates: vec![Gate::UnitHealthy("root-of-trust".into())],
                timeout: 30,
            },
            Unit {
                name: "reporting".into(),
                gates: vec![
                    Gate::UnitHealthy("api".into()),
                    Gate::AddressReady("site".into()),
                ],
                timeout: 120,
            },
        ];

        Self {
            chain,
            membership: Membership::new(node_id.clone(), SUSPICION_BASE),
            node_id,
            ladder: Ladder::default_for_small_ups(),
            lifecycle: Lifecycle::new(),
            sensors: SensorRegistry::new(),
            last_seen: BTreeMap::new(),
            signals: Vec::new(),
            capability,
            bringup: BringUp::new(units, now_s()),
            models: BTreeMap::new(),
            checkpoints: 0,
            pending_actuation: None,
            last_actuation: None,
            last_intent: None,
            controller_seen_at: None,
            ups: ups::Reading::Absent,
            cordoned_by_workload: false,
        }
    }

    /// Whether the agent is operating without a reachable controller.
    ///
    /// Reported rather than hidden: an operator should be able to see that a
    /// node is running on its last instruction.
    fn autonomous(&self, now: u64, timeout_ms: u64) -> bool {
        match self.controller_seen_at {
            Some(t) => now.saturating_sub(t) > timeout_ms,
            None => true,
        }
    }

    /// Record a health signal and act on it.
    ///
    /// Cordoning is driven by the signal's own severity rather than by a
    /// caller's opinion, so a critical fault always removes the node from
    /// scheduling even if whoever reported it did not ask for that.
    fn observe_signal(&mut self, signal: Signal) -> String {
        let outcome = if signal.warrants_fence() {
            let _ = self.lifecycle.apply(Transition::Fence);
            "fenced"
        } else if signal.warrants_cordon() {
            let _ = self.lifecycle.apply(Transition::Cordon);
            "cordoned"
        } else {
            "recorded"
        };
        self.chain.append(
            now_ms(),
            OpKind::Lifecycle,
            "health",
            format!("{:?}", signal.kind),
            outcome,
        );
        self.persist_chain();
        self.signals.push(signal);
        // Keep the buffer bounded; a node that runs for months should not
        // accumulate signals until it runs out of memory.
        if self.signals.len() > 256 {
            self.signals.remove(0);
        }
        outcome.to_string()
    }
}

fn grants_path() -> String {
    furcate_paths::state("grants.json").to_string_lossy().to_string()
}
fn grants_load() -> Vec<furcate_resource::tenancy::Grant> {
    std::fs::read_to_string(grants_path()).ok()
        .and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}
fn grants_save(v: &[furcate_resource::tenancy::Grant]) {
    write_atomically(&grants_path(), v)
}
fn bindings_path() -> String {
    furcate_paths::state("bindings.json").to_string_lossy().to_string()
}
fn bindings_load() -> Vec<furcate_resource::binding::Binding> {
    std::fs::read_to_string(bindings_path()).ok()
        .and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}
fn bindings_save(v: &[furcate_resource::binding::Binding]) {
    write_atomically(&bindings_path(), v)
}

/// Written beside and renamed, so a crash halfway leaves the previous list
/// rather than a truncated one. Losing which tenant holds which database is
/// worse than losing the write.
fn write_atomically<T: serde::Serialize + ?Sized>(path: &str, v: &T) {
    if let Ok(text) = serde_json::to_string_pretty(v) {
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// Where the record for a domain lives.
// Read by the deploy surface, which keeps the domain table.
fn domains_path() -> String {
    furcate_paths::state("domains.json").to_string_lossy().to_string()
}

fn domains_load() -> Vec<furcate_deploy::domain::Domain> {
    std::fs::read_to_string(domains_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn domains_save(list: &[furcate_deploy::domain::Domain]) {
    let path = domains_path();
    if let Ok(text) = serde_json::to_string_pretty(list) {
        // Written beside and renamed, so a crash halfway leaves the previous
        // list rather than a truncated one — losing which names were verified
        // means requesting certificates for them again.
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// The addresses the outside can reach this cluster on.
///
/// Declared rather than discovered. A machine behind a NAT cannot tell its own
/// address from the address anybody can use, and a record pointing at the
/// former is the most common way this goes wrong.
// Deploy-only; see the note on domains_path.
fn reachable_addresses() -> Vec<String> {
    std::env::var("FURCATE_REACHED_AT")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// What a name resolves to, using the resolver this machine already trusts.
///
/// Shelling out rather than speaking DNS: the agent needs one answer
/// occasionally, and a resolver implementation is a large thing to own for
/// that. If the tool is missing the name simply does not verify, which is the
/// safe direction.
// Deploy-only; see the note on domains_path.
fn resolve(name: &str) -> Vec<String> {
    let out = std::process::Command::new("getent")
        .args(["ahostsv4", name])
        .output();
    let Ok(out) = out else { return vec![] };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut seen: Vec<String> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .collect();
    seen.sort();
    seen.dedup();
    seen
}

/// The node's receipt-signing key, sealed to this machine's TPM where there is
/// one.
///
/// Generated once and sealed, so it cannot be lifted off the disk and used to
/// sign receipts claiming to come from this node. An unsigned receipt proves
/// nothing to anyone who did not watch it being produced.
///
/// A node with no TPM, admitted on hardware continuity, gets the same key in a
/// file instead. That is not a workaround: `AssuranceClass::Soft` is defined as
/// a file-backed key with no hardware binding, and the restrictions that go with
/// the class — no custody, no control of a cluster — are enforced on the class
/// and not on whether a key happens to exist. Refusing the key here only meant
/// such a node could never be admitted to anyone's trust store, which stopped
/// the soft path one step short of being usable while making nothing safer.
/// The node's Ed25519 receipt key, sealed to this machine's Secure Enclave.
///
/// macOS has no TPM and never will, so without this a Mac reaches
/// `node_signing_key` with no TPM and — because it classifies `Device` rather
/// than `Soft` — no file fallback either. It ended up with no key at all:
/// receipts unsigned, `signing_key` null, and nothing to present to
/// `roster admit`, so the machine could not join a cluster it was otherwise
/// entitled to join.
///
/// The helper writes the same two files the TPM sealer writes,
/// `node-key/{seal.pub, seal.priv}`, so this function's shape does not change
/// with the hardware underneath it. `seal.pub` is a Secure Enclave
/// key-agreement blob whose private half never leaves the enclave; `seal.priv`
/// is the seed encrypted to it. Both are inert on any other Mac.
#[cfg(target_os = "macos")]
fn enclave_signing_key(dir: &std::path::Path) -> anyhow::Result<SigningKey> {
    use std::process::Command;
    const HELPER: &str = "furcate-sep";

    let verb = if dir.join("seal.priv").exists() { "unseal" } else { "seal" };
    let out = Command::new(HELPER)
        .args([verb, &dir.to_string_lossy()])
        .output()
        .map_err(|e| anyhow::anyhow!("running {HELPER} {verb}: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("{HELPER} {verb}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    // `seal` prints the public key and `unseal` prints the seed, so a fresh
    // seal is read back rather than trusting what it printed. One path through
    // the helper means one thing to get right.
    let hexed = if verb == "seal" {
        let read = Command::new(HELPER)
            .args(["unseal", &dir.to_string_lossy()])
            .output()
            .map_err(|e| anyhow::anyhow!("running {HELPER} unseal: {e}"))?;
        if !read.status.success() {
            anyhow::bail!(
                "the node key sealed but would not read back: {}",
                String::from_utf8_lossy(&read.stderr).trim()
            );
        }
        String::from_utf8_lossy(&read.stdout).trim().to_string()
    } else {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    let bytes: [u8; 32] = hex::decode(&hexed)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the sealed node key is malformed"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn node_signing_key(dir: &std::path::Path, soft: bool) -> anyhow::Result<SigningKey> {
    // Tried before the TPM only because a Mac has no TPM to try. Where both
    // could exist the TPM is the stronger root and keeps its place.
    #[cfg(target_os = "macos")]
    {
        match enclave_signing_key(dir) {
            Ok(k) => {
                eprintln!("furcated: node key sealed to the Secure Enclave");
                return Ok(k);
            }
            // Not fatal on its own: a Mac without the helper installed can
            // still fall through to the message below, which names what is
            // missing rather than reporting a generic absence of a key.
            Err(e) => eprintln!("furcated: the Secure Enclave cannot hold the node key: {e}"),
        }
    }

    // A soft identity keeps its file-backed key even when a TPM is present:
    // the identity was pinned to hardware continuity, and a TPM that appeared
    // later (or an emulated one) would otherwise hand it a new receipt key.
    if soft {
        return soft_signing_key(dir).map_err(|inner| anyhow::anyhow!("the file-backed node key: {inner}"));
    }
    let sealer = Sealer::open().map_err(|e| anyhow::anyhow!("opening the TPM to seal the node key: {e}"))?;
    if dir.join("seal.priv").exists() {
        let hexed = sealer.unseal(dir)?;
        let bytes: [u8; 32] = hex::decode(String::from_utf8_lossy(&hexed).trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("the sealed node key is malformed"))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("drawing key material: {e}"))?;
    sealer.seal(hex::encode(seed).as_bytes(), dir)?;
    // Confirm it reads back before relying on it.
    let check = sealer.unseal(dir)?;
    if String::from_utf8_lossy(&check).trim() != hex::encode(seed) {
        anyhow::bail!("the node key did not read back after sealing");
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// The receipt key for a node whose identity is its hardware, not a chip.
///
/// Mode 0600 and never leaves this directory. It can still be copied by anyone
/// who can read it as this user, which is exactly the property that keeps the
/// node `Soft`.
fn soft_signing_key(dir: &std::path::Path) -> anyhow::Result<SigningKey> {
    let path = dir.join("node.key");
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        // Reported as itself: falling through to create the file only
        // produced "File exists", which hid that the key could not be read.
        Err(e) => anyhow::bail!("reading {}: {e}", path.display()),
    };
    if let Some(text) = existing {
        let bytes: [u8; 32] = hex::decode(text.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("{} is malformed", path.display()))?;
        return Ok(SigningKey::from_bytes(&bytes));
    }

    std::fs::create_dir_all(dir)?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("drawing key material: {e}"))?;

    // Written 0600 from the start rather than written and then chmodded: the
    // window between the two is short, and it is the whole of the exposure.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", path.display()))?;
    f.write_all(format!("{}\n", hex::encode(seed)).as_bytes())?;
    f.sync_all()?;
    eprintln!("furcated: receipt key in {} — file-backed, not sealed", path.display());
    Ok(SigningKey::from_bytes(&seed))
}

/// The overlay address this node should use.
///
/// ⚠ There is deliberately NO hardcoded fallback here any more. This used to
/// default to `10.90.0.1/16` — node-a's actual address — so any node that
/// started without `FURCATE_OVERLAY_ADDR` set quietly claimed its neighbour's
/// identity.
///
/// That failure is invisible from the node doing it. Traffic to the address it
/// took routes to its own loopback and is refused there, while the machine that
/// really owns it sits healthy and idle. What breaks is whatever happens to use
/// the overlay, and it breaks silently: object replication fell to a single
/// copy with nothing on a second machine, and database dumps reported success
/// for hours while never leaving the disk they were meant to be backed up from.
///
/// A default that names one specific machine is correct only on that machine.
/// So: take the environment when it is set; otherwise take what the interface
/// already holds, which is not a guess because an address the kernel has
/// configured on this node's own interface is this node's by definition; and
/// otherwise return empty rather than invent one.
fn overlay_addr() -> String {
    if let Ok(a) = std::env::var("FURCATE_OVERLAY_ADDR") {
        let a = a.trim().to_string();
        if !a.is_empty() {
            return a;
        }
    }
    let iface = std::env::var("FURCATE_WG_IFACE").unwrap_or_else(|_| "fur0".into());
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "dev", &iface])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // `ip -o` puts the CIDR in the fourth field.
            if let Some(cidr) = line.split_whitespace().nth(3) {
                if cidr.contains('/') {
                    return cidr.to_string();
                }
            }
        }
    }
    eprintln!(
        "furcated: FURCATE_OVERLAY_ADDR is unset and {iface} holds no address; this node \
will not claim one, because a guessed overlay address is another node's identity"
    );
    String::new()
}

/// The daemon's entry point: answers `--version` and `--help`, then runs.
pub fn main() -> anyhow::Result<()> {
    // Answer for itself and exit, before anything opens a socket or touches the
    // TPM.
    //
    // This is not a convenience. `furcate-update` runs the newly installed
    // binary to check it works on this machine — the part a checksum cannot
    // tell you — and without this, `furcated --version` fell through to the
    // agent, bound a port, and never returned. On node-a that left a second
    // agent serving on loopback beside the real one, and the update hung
    // forever with the image merged and nothing recorded.
    //
    // A daemon that cannot say what it is cannot be verified after an upgrade,
    // so saying so is part of being upgradable.
    //
    // The first argument decides everything, because there is no second one this
    // agent would accept. Written as a look rather than a loop: every branch
    // below returns or exits, so a loop here would examine exactly one argument
    // while appearing to consider them all.
    if let Some(arg) = std::env::args().nth(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!(
                    "furcated {} edition={}",
                    env!("CARGO_PKG_VERSION"),
                    extension::get().edition()
                );
                return Ok(());
            }
            "--help" | "-h" => {
                println!("furcated {} — Furcate node agent", env!("CARGO_PKG_VERSION"));
                println!();
                println!("Configured entirely by environment, because it is run by systemd:");
                println!("  FURCATE_LISTEN       address to serve on");
                println!("  FURCATE_LISTEN_ALSO  further addresses to serve on, comma-separated");
                println!("  FURCATE_SITE         the site controller to report to");
                println!("  FURCATE_NODE_NAME    what this machine calls itself");
                println!();
                println!("It takes no other arguments. `furcatectl` is the operator's tool,");
                println!("and `furcate` opens the console.");
                return Ok(());
            }
            other => {
                // Refused rather than ignored. Ignoring an unrecognised
                // argument is how the flag above ended up starting a server.
                eprintln!("furcated: unknown argument {other:?}");
                eprintln!("this agent is configured by environment; try --help");
                std::process::exit(2);
            }
        }
    }
    run()
}

/// Where this node keeps what decides its identity; `furcatectl` reads the
/// same places.
fn node_paths() -> furcate_identity::pin::NodePaths {
    furcate_identity::pin::NodePaths::new(&furcate_paths::config_dir(), &furcate_paths::state("node-key"))
}

/// This machine's root of trust.
///
/// The strongest hardware root the machine has: a TPM, then a TEE, then a
/// device key such as a Raspberry Pi's OTP key or a Mac's Secure Enclave. The
/// class each earns, and why, is decided in `furcate_identity::backends::select`
/// and printed here. If none opens, the machine can still join on its own
/// hardware serials -- but only when an operator has recorded that decision,
/// because the two are not equivalent and the difference has to be somebody's
/// choice rather than a default.
///
/// A fingerprint gives continuity, not unforgeability: it proves the machine
/// answering today has the characteristics of the one enrolled, and nothing
/// about whether those characteristics were copied. So such a node classifies
/// `Soft`, holds custody of nothing, produces no signed quote, and cannot lead
/// a cluster. Falling back silently would leave a fleet believing it is
/// attested when part of it is not, which is worse than refusing to start.
fn open_root_of_trust() -> anyhow::Result<Arc<dyn RootOfTrust + Send + Sync>> {
    use furcate_identity::pin;

    let paths = node_paths();
    let record_path = paths.record();
    let key_dir = &paths.key_dir;

    let (resolved, attempts) = pin::open_node(&paths, now_s());
    for a in &attempts {
        eprintln!("furcated: {} unavailable: {}", a.backend, a.outcome);
    }
    let resolved = resolved.map_err(anyhow::Error::msg)?;
    if let Some(note) = &resolved.note {
        eprintln!("furcated: {note}");
    }
    if let Some(record) = &resolved.record {
        let written = std::fs::create_dir_all(key_dir).and_then(|()| record.write(&record_path));
        match written {
            Ok(()) => eprintln!(
                "furcated: enrolled identity recorded in {}: {} on {} ({})",
                record_path.display(),
                record.node_id,
                record.backend,
                record.how
            ),
            // Loud rather than fatal: this start already matches the node-key
            // state, and refusing here would take a working node down over a
            // permission. Until the record exists each start re-derives it.
            Err(e) => eprintln!(
                "furcated: WARNING the enrolled identity ({} on {}) could not be recorded in {}: {e}. \
                 Later starts are held to it only once it is recorded; give this service write access \
                 to {}",
                record.node_id,
                record.backend,
                record_path.display(),
                key_dir.display()
            ),
        }
    }

    let chosen = resolved.opened;
    if chosen.backend == pin::SOFT_BACKEND {
        eprintln!("furcated: no TPM — identity from {}", chosen.reason);
    } else {
        eprintln!("furcated: identity from {} as {}: {}", chosen.backend, chosen.class, chosen.reason);
    }
    Ok(chosen.rot)
}

/// The agent proper, callable from both binary profiles so there is one code
/// path rather than two that can drift.
pub fn run() -> anyhow::Result<()> {
    let addr = std::env::var("FURCATE_LISTEN").unwrap_or_else(|_| "127.0.0.1:7616".to_string());

    let rot = open_root_of_trust()?;
    let node_id = rot.node_id()?.to_string();
    let assurance = rot.assurance();
    let capability = hardware::detect(&node_id, true);
    let disk_gb = hardware::disk_gb("/");
    eprintln!(
        "furcated: {node_id} ({assurance}) {} cores, {} MB ram, {} MB vram, tier {}",
        capability.cpu_cores,
        capability.ram_mb,
        capability.vram_mb,
        capability.tier().as_str()
    );

    // The single most important path in this program. It holds material sealed
    // to this machine's TPM, which no reinstall can regenerate — so it lives in
    // the state directory, which an upgrade never touches, rather than in a
    // person's home, where it depended on that account continuing to exist.
    let key_dir = furcate_paths::state("node-key");
    let signing = match node_signing_key(&key_dir, assurance == AssuranceClass::Soft) {
        Ok(k) => {
            eprintln!(
                "furcated: receipt signing key {}",
                &hex::encode(k.verifying_key().to_bytes())[..16]
            );
            Some(Arc::new(k))
        }
        Err(e) => {
            // Serving unsigned receipts is worse than not serving them, so
            // this is loud. Inference still works; receipts say they are
            // unsigned.
            eprintln!("furcated: WARNING receipts will be unsigned: {e}");
            None
        }
    };

    let agent = Arc::new(Mutex::new(Agent::new(node_id.clone(), capability)));

    // Bring-up: the root of trust answered, so the API may start.
    {
        let mut a = agent.lock().expect("agent lock");
        // Re-measure every saved registration. One whose artifact changed is
        // dropped rather than served under a digest it no longer has.
        for m in runtime::load(&model_registry_path()) {
            eprintln!("furcated: model {} restored ({})", m.id, &m.digest[..16]);
            a.models.insert(m.id.clone(), m);
        }
        a.bringup.settle(now_s());
        let _ = a.lifecycle.apply(Transition::Attest);
        let _ = a.lifecycle.apply(Transition::Admit);
        let _ = a.lifecycle.apply(Transition::Schedule);
    }

    // Whose word this machine takes. Loaded once here rather than inside
    // `build_router`, because the membership loop needs the same answer: a node
    // that served one trust store and joined peers by another would be two
    // policies wearing one file's name.
    let trust = load_trust_store();
    let peer_keys: BTreeMap<String, VerifyingKey> = trust
        .device_keys()
        .into_iter()
        .map(|(id, key, _boot_measured)| (id, key))
        .collect();

    // One scheduler for every timer in this process.
    let sched = furcate_sched::registry();
    let router = build_router(
        Arc::clone(&sched),
        Arc::clone(&agent),
        Arc::clone(&rot),
        node_id.clone(),
        signing.clone(),
        trust,
    );

    register_local_sensors(Arc::clone(&agent), &node_id);
    spawn_power_loop(&sched, Arc::clone(&agent));
    spawn_health_loop(&sched, Arc::clone(&agent));
    spawn_checkpoint_loop(&sched, Arc::clone(&agent), Arc::clone(&rot));
    spawn_membership_loop(&sched, Arc::clone(&agent), node_id.clone(), peer_keys.clone(), assurance);
    if let Ok(site) = std::env::var("FURCATE_SITE") {
        spawn_rejoin(&sched, Arc::clone(&agent), node_id.clone(), peer_keys, assurance);
        spawn_overlay_loop(&sched, Arc::clone(&agent), site.clone(), node_id.clone());
        spawn_reporting_loop(
            &sched,
            Arc::clone(&agent),
            Reporting {
                node_id: node_id.clone(),
                site,
                disk_gb,
                endpoint: addr.clone(),
                signing: signing.clone(),
                assurance,
            },
        );
    }

    // Further addresses serve the same routes, so the same checks guard them,
    // but they are only further ways in: the node reports and advertises
    // FURCATE_LISTEN alone.
    let also = listen_also(&std::env::var("FURCATE_LISTEN_ALSO").unwrap_or_default());
    eprintln!("furcated: listening on {addr}");
    serve_also(addr, &also, router)?;
    Ok(())
}

/// Register sensors this machine already has.
///
/// The kernel exposes thermal zones on every platform worth running on, so a
/// node has real sensors before any leaf attaches. Registering them means the
/// cluster-wide registry reflects hardware that exists rather than staying
/// empty until someone plugs in a microcontroller.
fn register_local_sensors(agent: Arc<Mutex<Agent>>, node_id: &str) {
    let Ok(entries) = std::fs::read_dir("/sys/class/thermal") else {
        return;
    };
    let mut a = agent.lock().expect("agent lock");
    let mut count = 0;
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
        if !name.starts_with("thermal_zone") || !p.join("temp").exists() {
            continue;
        }
        let kind = std::fs::read_to_string(p.join("type"))
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|_| name.to_string());
        a.sensors.register(Sensor {
            id: format!("{node_id}/{name}"),
            kind: SensorKind::Temperature,
            unit: furcate_sense::Unit::Celsius,
            host: node_id.to_string(),
            domain: None,
            interval_s: 60,
        });
        a.last_seen.insert(format!("{node_id}/{name}"), now_s());
        let _ = kind;
        count += 1;
    }
    if count > 0 {
        eprintln!("furcated: registered {count} local temperature sensors");
    }
}

/// The subset of hardware state the controller republishes under standard names.
///
/// OpenTelemetry defines semantic conventions for exactly this — `hw.host.power`,
/// `hw.temperature`, `hw.fan.speed`, `hw.status` — and Furcate held every one of
/// these values under names only Furcate understood. Data nothing else can read
/// is data a site cannot build on.
/// This node's overlay reachability, if the mesh is up.
///
/// The tier is derived from evidence already collected rather than declared:
/// the class of the root of trust, and whether the boot chain was measured. A
/// node cannot promote itself by asserting a higher one.
fn overlay_hint(node_id: &str, assurance: furcate_identity::AssuranceClass) -> serde_json::Value {
    let addr = overlay_addr();
    let port: u16 = std::env::var("FURCATE_WG_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(furcate_net::wg::DEFAULT_PORT);

    // The underlay address a peer should dial. Not the overlay address — an
    // endpoint inside the tunnel would be circular.
    let toward = std::env::var("FURCATE_OVERLAY_TOWARD").unwrap_or_else(|_| "192.0.2.1".into());
    let endpoints: Vec<String> = overlay::local_endpoint_addr(&toward)
        .map(|a| vec![format!("{a}:{port}")])
        .unwrap_or_default();

    let boot_measured = image::collect(None, 0).image.boot_measured;
    let tier = furcate_net::overlay::Tier::from_evidence(assurance, boot_measured);

    let observed = overlay::observed_endpoints(port, now_s());
    match overlay::self_hint(node_id, &addr, endpoints, observed, tier, now_s()) {
        Some(mut h) => {
            // A machine carries its own authorization. The coordinator relays
            // it and cannot mint it, which is what lets every other node check
            // rather than believe. Absent is normal on an unlocked overlay and
            // refused on a locked one — by the receiving node, not here.
            h.authorization = overlay::self_authorization();
            overlay::save_own(&h);
            serde_json::to_value(h).unwrap_or(serde_json::Value::Null)
        }
        None => serde_json::Value::Null,
    }
}

/// What this machine is, for the controller's fleet view of identity.
fn image_summary() -> serde_json::Value {
    let (b, at) = load_baseline();
    let r = image::collect(b.as_ref(), at);
    json!({
        "assurance": r.image.assurance.as_str(),
        "next_step": r.image.assurance.next_step(),
        "os_id": r.image.os_id,
        "os_version": r.image.os_version,
        "kernel": r.image.kernel,
        "digest": r.image.digest,
        "boot_measured": r.image.boot_measured,
        "rollback_available": r.image.rollback_available,
        "drift": r.drift,
        "bios_version": r.firmware.bios_version,
        "bios_date": r.firmware.bios_date,
        "firmware_age": r.firmware_age,
        "firmware_updates": r.firmware.updatable().len(),
        "firmware_security_updates": r.firmware.security_updates().len(),
        "firmware_inventory_available": r.firmware.inventory_available,
    })
}

/// A compact hardware summary.
///
/// Takes the custody report rather than collecting one, which is the whole
/// reason the card faults can appear here at all: the kernel log has already
/// been read once this cycle, and reading it again to decorate a summary would
/// pay for it twice and let the two readings answer for different windows.
fn hardware_summary(cust: &custody::CustodyReport) -> serde_json::Value {
    let b = bmc::collect();
    let h = host::collect();
    let devices: Vec<serde_json::Value> = h
        .devices
        .iter()
        .map(|d| {
            let v = furcate_host::storage::assess(d, None);
            json!({
                "id": d.name,
                "model": d.model,
                "verdict": v,
                // `hw.status` is a boolean per state, and "degraded" is the one
                // that matters here: a drive with a rising error count is
                // neither ok nor failed.
                "ok": !v.is_actionable(),
                "degraded": v.is_actionable() && v != furcate_host::storage::Verdict::SelfReportedFailing,
                "failed": v == furcate_host::storage::Verdict::SelfReportedFailing,
            })
        })
        .collect();

    // The same three-state shape asked of the accelerators, which are what
    // this fleet exists to run and were the last device class nothing watched.
    let accelerators: Vec<serde_json::Value> = h
        .accelerators
        .iter()
        .map(|a| {
            let v = furcate_host::accelerator::assess(a, None);
            json!({
                "id": a.uuid.clone().unwrap_or_else(|| format!("gpu{}", a.index)),
                "index": a.index,
                "model": a.name,
                "verdict": v,
                "memory_fraction": a.memory_fraction(),
                // `degraded` and `failed` split on whether the card itself is
                // implicated, for the same reason the drives split on it: a
                // throttling card is a cooling problem and a full one is a
                // placement decision, and sending somebody to swap either is
                // worse than not telling them.
                "ok": !v.is_actionable(),
                "degraded": v.is_actionable() && !v.implicates_the_card(),
                "failed": v.implicates_the_card(),
                // Carried separately from the verdict because it is a
                // different decision: a card out of memory is healthy and must
                // still stop receiving work.
                "should_drain": v.should_drain(),
                // What the driver itself said about this card, if anything.
                //
                // Beside the verdict rather than instead of it: the two catch
                // different halves. `verdict` is inferred from counters moving
                // over time and catches a card becoming unwell; this is an
                // error code emitted at the moment something went wrong. A
                // card can be healthy by every counter and have thrown an
                // uncontained memory fault a minute ago.
                //
                // Matched on the PCI address, which is the only field both the
                // vendor tool and the driver name — and only when it matches.
                // A fault the log could not attribute stays unattributed here
                // rather than being pinned on whichever card is being rendered.
                "fault": a.pci.as_deref().map(furcate_host::xid::pci_key).and_then(|key| {
                    cust.xids.iter().find(|(pci, _)| pci.as_deref() == Some(key.as_str())).map(|(_, f)| json!({
                        "code": f.class.code,
                        "blame": f.class.blame.as_str(),
                        "remedy": f.class.remedy.as_str(),
                        "contained": f.class.contained,
                        "summary": f.class.summary,
                        "seen": f.repeats,
                    }))
                }),
            })
        })
        .collect();

    json!({
        "host_power_w": b.wall.map(|w| w.input_watts),
        "psu_output_w": b.wall.and_then(|w| w.output_watts),
        "psu_efficiency_pct": b.wall.and_then(|w| w.efficiency_pct()),
        "fans": b.cooling.fans.iter().map(|f| json!({
            "id": f.name, "rpm": f.rpm, "ok": f.ok
        })).collect::<Vec<_>>(),
        "temperatures": b.cooling.temperatures.iter().map(|t| json!({
            "id": t.name, "celsius": t.celsius
        })).collect::<Vec<_>>(),
        "devices": devices,
        "devices_readable": h.devices_readable,
        "accelerators": accelerators,
        "accelerators_readable": h.accelerators_readable,
                    // Present only when something published it. Absent means
                    // nothing read the counters, which is not the same as a
                    // machine with no errors.
                    "platform": h.platform,
    })
}

/// Pull the coordinator's map and reconcile the overlay.
///
/// Pulled rather than pushed, and that is the whole point restated as a data
/// flow: the coordinator answers a question when asked and cannot reach into a
/// node to change its peer set. A node that stops asking keeps what it has.
///
/// The admission decision is made here, locally, from this node's own
/// configuration — never from anything in the response.
fn spawn_overlay_loop(sched: &furcate_sched::Registry, agent: Arc<Mutex<Agent>>, site: String, node_id: String) {
    if site.trim().is_empty() {
        // A node with no coordinator still runs an overlay; it just has nobody
        // to learn new peers from. Reconciling with an empty hint set keeps
        // whatever it already held, which is the correct behaviour and not a
        // degraded one.
        eprintln!("furcated: no site configured; the overlay keeps its held peers");
    }
    let addr = overlay_addr();
    // Loaded once, at start. A policy that could be swapped underneath a
    // running loop would be one an attacker could swap underneath a running
    // loop; changing it is a restart, which is visible.
    let policy = std::sync::Arc::new(overlay::load_policy());

    furcate_sched::spawn(
        sched,
        "overlay",
        furcate_sched::Cadence::FixedRate { secs: 30 },
        furcate_sched::Backoff::default(),
        move || {
            // A failed fetch is not a failed reconciliation. The node proceeds
            // with no hints, which retains every peer it already had — this is
            // the coordinator-outage path and it must run, not be skipped.
            let hints: Vec<furcate_net::overlay::Hint> = if site.trim().is_empty() {
                Vec::new()
            } else {
                furcate_api::get_json(&site, "/overlay", 4000)
                    .ok()
                    .and_then(|v| v.get("hints").cloned())
                    .and_then(|h| serde_json::from_value(h).ok())
                    .unwrap_or_default()
            };
            // Leased keys members gossiped, already checked on arrival. A
            // node that rebooted with a new key while the coordinator was down
            // reaches this one this way.
            let gossip = {
                let a = agent.lock().expect("agent lock");
                overlay::gossip_hints(&a.membership, &node_id, now_s())
            };
            let hints = furcate_net::overlay::merge(&hints, &gossip);

            // The admission decision, made by the same engine that governs
            // everything else here. It was two hardcoded conditions, which made
            // the claim that a node "evaluates hints against policy it already
            // holds" true of the design and not of the code.
            let me = node_id.clone();
            let now = now_s();
            let policy = std::sync::Arc::clone(&policy);
            // Read every pass rather than captured once, so adding an anchor
            // takes effect on the next cycle instead of at the next restart —
            // and so a file that becomes unreadable is noticed rather than
            // remembered as it was.
            let anchors = match overlay::anchors() {
                Ok(a) => a,
                Err(e) => return furcate_sched::Ran::Skipped(e),
            };
            if !anchors.state().is_locked() {
                // Said out loud every pass. An operator who never sees this
                // line is entitled to assume peers are being verified.
                eprintln!("furcated: overlay {}", anchors.state().describe());
            }
            // Only inside the notice window, so this is silent for most of an
            // authorization's life and then does not stop. An expiry is the
            // one refusal that arrives on its own, and the machine it removes
            // is this one — which is the machine least able to report it
            // afterwards.
            if let Some(s) = overlay::self_standing(now) {
                if s.needs_attention() {
                    eprintln!("furcated: {}", s.describe());
                }
            }
            let r = overlay::reconcile(&hints, &addr, now, move |h| {
                overlay::admits(&policy, &anchors, &me, h, now)
            });

            if !r.available {
                // Reported, not fatal: the plan is written either way, and the
                // privileged half applies it when it can.
                return furcate_sched::Ran::Skipped(
                    r.why_unavailable
                        .unwrap_or_else(|| "the privileged overlay helper is not reporting".into()),
                );
            }
            furcate_sched::Ran::Ok
        },
    );
}

/// Poll the supply and drive the ladder.
///
/// Runs whether or not a supply is present: a machine with no UPS reports that
/// honestly rather than claiming to be on line.
fn spawn_power_loop(sched: &furcate_sched::Registry, agent: Arc<Mutex<Agent>>) {
    let ups_name = std::env::var("FURCATE_UPS").unwrap_or_else(|_| "ups".to_string());
    // Recognised once. DMI does not change while a machine is running, and
    // re-reading the registry every ten seconds would be work done to reach the
    // same answer.
    let hw = std::sync::Arc::new(furcate_host::hardware::recognise());
    furcate_sched::spawn(sched, "power", furcate_sched::Cadence::FixedRate { secs: 10 }, furcate_sched::Backoff::default(), {
        let hw = std::sync::Arc::clone(&hw);
        move || {
        // Proof of life first, before anything that could fail. The privileged
        // actuator reverts to a safe power level when this stops arriving, so a
        // beat that only happened on successful passes would revert the fleet
        // every time a sensor read was slow.
        if let Err(e) = actuate::beat() {
            eprintln!("furcated: WARNING heartbeat not written ({e}); the actuator will revert");
        }
        // Published every pass and skipped when unchanged. This daemon owns the
        // declaration, behind the policy check on `tune`; the root helper that
        // enforces it reads this, and keeps enforcing the last one it read if
        // this process stops.
        if let Err(e) = bmc::publish_quiet(&bmc::declared().acoustics) {
            eprintln!("furcated: WARNING quiet-hours declaration not published ({e})");
        }
        let reading = ups::read(&ups_name);
        // Heat is read whether or not a supply is present. This used to sit
        // inside the `Reading::Present` arm, which meant a machine with no UPS
        // — the common case, and the one this loop's own doc comment promises
        // to handle honestly — had no thermal protection at all. Heat is not a
        // supply problem.
        let thermal = bmc::thermal_rung(&bmc::collect());
        // Read on the same pass and for the same reason heat is: a machine
        // thrashing on memory reclaim is not a supply problem either, and it
        // was the one input this loop measured accurately and never acted on.
        // `system_psi` has been collected since the resource work; it fed a
        // forecaster and a number on /resources and nothing else, so a machine
        // could spiral while the daemon watched and described it.
        let psi = resources::system_psi();
        let pressure = psi.as_ref().and_then(resources::pressure_rung);
        {
            let mut a = agent.lock().expect("agent lock");
            a.ups = reading.clone();
            let before = a.ladder.rung();

            // Supply and heat descend the same ladder and the machine sits at
            // whichever is worse. They are the same shape of problem — a
            // reversible sequence of steps taken before something irreversible
            // happens — so they get one mechanism rather than two that could
            // disagree.
            let mut rung = before;
            if let ups::Reading::Present { state, runtime_left, .. } = reading {
                rung = a.ladder.observe(state, now_s(), runtime_left);
            }
            if let Some(t) = thermal {
                if t > rung {
                    rung = a.ladder.descend_to(t);
                }
            }
            // Third input, same ladder, same rule: the machine sits at
            // whichever is worse. A separate mechanism for memory would be a
            // second thing able to shed work, and the two could disagree about
            // what state the machine is in.
            if let Some(m) = pressure {
                if m > rung {
                    rung = a.ladder.descend_to(m);
                }
            }

            // Reported as well as acted on. Shedding changes what the
            // machine does; the signal is what makes it visible to a person
            // and what cordons the node at `stalled`, so nothing new is placed
            // on a machine that has stopped making progress.
            if let Some(level) = psi.as_ref().and_then(resources::pressure_level) {
                let signal = Signal::new(
                    &a.node_id,
                    SignalKind::MemoryPressure { level: level.to_string() },
                    now_s(),
                );
                if !a.signals.iter().any(|s| s.kind == signal.kind) {
                    a.signals.push(signal);
                }
            } else {
                // Cleared when the pressure is gone, or a machine that
                // recovered would stay cordoned until something restarted it.
                a.signals.retain(|s| !matches!(s.kind, SignalKind::MemoryPressure { .. }));
            }

            if rung != before {
                // Which of the three put it here. A record saying only
                // "shed" leaves somebody guessing whether the building lost
                // power, the room got hot, or a workload ate the machine --
                // and those want completely different responses.
                let cause = if pressure.is_some_and(|m| m >= rung) {
                    "memory"
                } else if thermal.is_some_and(|t| t >= rung) {
                    "thermal"
                } else {
                    "ups"
                };
                a.chain.append(
                    now_ms(),
                    OpKind::Power,
                    cause,
                    rung.as_str(),
                    format!("from {}", before.as_str()),
                );
                eprintln!("furcated: power rung {} -> {}", before.as_str(), rung.as_str());

                // And now the part that was missing. Until this line the
                // ladder observed, chained, printed, and left the CPU at 100%.
                // A power ladder that only logs is a power ladder that does not
                // exist: the entire argument for descending early is that the
                // early steps buy time, and they buy nothing if nothing
                // happens.
                if let Some(lever) = actuate::lever_for(rung) {
                    // Ask the machine's own profile before reaching for the
                    // lever. Without this the loop tries whatever the rung
                    // names, is refused by hardware that does not implement it,
                    // and tries again on the next pass for as long as the
                    // machine runs — a refusal nobody reads, once a tick.
                    //
                    // Unknown hardware is attempted, deliberately. Most
                    // machines have no profile, and a control loop that stopped
                    // working on unfamiliar hardware because nobody had
                    // described it yet would be worse than one that tries and
                    // is told no.
                    let name = actuate::render(lever, "probe")
                        .lines()
                        .find_map(|l| l.strip_prefix("lever=").map(str::to_string))
                        .unwrap_or_default();
                    if let Err(why) = furcate_host::hardware::may_attempt(hw.as_ref(), &name) {
                        a.chain.append(
                            now_ms(),
                            OpKind::Power,
                            "actuate",
                            lever.to_string(),
                            format!("not attempted: {why}"),
                        );
                        eprintln!("furcated: {why}");
                        return furcate_sched::Ran::Ok;
                    }
                    let nonce = format!("{}-{}", rung.as_str(), now_ms());
                    match actuate::write(lever, &nonce) {
                        Ok(()) => {
                            a.chain.append(
                                now_ms(),
                                OpKind::Power,
                                "actuate",
                                lever.to_string(),
                                format!("requested at {}", rung.as_str()),
                            );
                            a.pending_actuation = Some(nonce);
                        }
                        // Logged, not fatal, and explicitly not a reason to
                        // stay at the old rung: the descent is still correct,
                        // it is only unenforced, and pretending otherwise would
                        // hide a broken actuator behind a nominal reading.
                        Err(e) => eprintln!("furcated: WARNING actuation not written: {e}"),
                    }
                }
            }

            // Read back separately from writing. The actuator polls, so the
            // result for this cycle's intent normally lands during the next
            // one, and blocking here to wait for it would put a sleep in the
            // path that handles power failures.
            // The ladder's other instruction, carried out.
            //
            // `Shed` has always named two actions — cap power, and shed
            // preemptible work — and only the first of them had a referent.
            // Nothing could say which work was preemptible, so half of every
            // descent was inert in exactly the way actuate.rs's own header
            // complains about.
            //
            // Outside the transition branch on purpose. A rung is entered once
            // and has to keep being true afterwards: work that arrives while
            // the site is already on battery must also be shed, and shedding
            // one workload may not have been enough.
            //
            // One per pass, and that is the actuator's shape rather than
            // caution. It reads a single intent every two seconds and compares
            // the whole body, so a burst of writes leaves only the last one
            // visible and the rest silently dropped. At a ten-second cadence
            // this clears a list in tens of seconds and re-reads the situation
            // between each — so a supply that recovers stops the shedding
            // rather than discovering it has already thrown everything away.
            //
            // Self-limiting: only running work is ever offered for shedding, so
            // a workload that stopped drops out of the list on the next pass.
            //
            // Which work, and in what order, is the registered extension's
            // choice. With none registered the open daemon still caps power at
            // this rung; it says once, plainly, that it is not shedding, rather
            // than appearing to and doing nothing.
            let inv = (rung >= furcate_power::Rung::Shed).then(workloads::collect);
            let order = inv
                .as_ref()
                .map(|inv| extension::get().shed_order(rung, inv, now_s()));
            if let (Some(inv), Some(Some(order))) = (inv.as_ref(), order.as_ref()) {
                if let Some(id) = order.first() {
                    // The privileged half refuses anything not on the
                    // operator's own list, so this cannot widen its reach by
                    // naming something new — but it should still be refused by
                    // something that can explain itself.
                    if actuate::id_is_safe(id) {
                        let kind = inv
                            .workloads
                            .iter()
                            .find(|w| &w.id == id)
                            .map(|w| w.kind.as_str())
                            .unwrap_or("unit");
                        let nonce = format!("shed-{}-{}", id, now_ms());
                        match actuate::write_shed(kind, id, &nonce) {
                            Ok(()) => {
                                a.chain.append(
                                    now_ms(),
                                    OpKind::Power,
                                    "shed",
                                    id.clone(),
                                    format!(
                                        "{kind}; {} preemptible workload(s) remaining, least costly first",
                                        order.len().saturating_sub(1)
                                    ),
                                );
                                eprintln!(
                                    "furcated: shedding {id} ({kind}); {} more preemptible",
                                    order.len().saturating_sub(1)
                                );
                            }
                            Err(e) => eprintln!("furcated: could not ask to shed {id}: {e}"),
                        }
                    }
                }
            } else if inv.is_some() {
                static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    eprintln!(
                        "furcated: the power ladder is at {rung:?}, which sheds preemptible work; \
                         this build has no policy for choosing what to shed, so nothing is being shed"
                    );
                }
            }

            if let Some(nonce) = a.pending_actuation.clone() {
                if let Some(res) = actuate::confirm(&nonce) {
                    let ok = res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    let applied = res.get("applied").and_then(|v| v.as_str()).unwrap_or("-");
                    let why = res.get("why").and_then(|v| v.as_str()).unwrap_or("");
                    a.chain.append(
                        now_ms(),
                        OpKind::Power,
                        "actuated",
                        if ok { applied } else { "refused" },
                        if ok {
                            format!("clamped={}", res.get("clamped").and_then(|v| v.as_bool()).unwrap_or(false))
                        } else {
                            why.to_string()
                        },
                    );
                    if !ok {
                        eprintln!("furcated: actuation refused: {why}");
                    }
                    a.last_actuation = Some(res);
                    a.pending_actuation = None;
                }
            }
        }
        furcate_sched::Ran::Ok
        }
    });
}

/// Exchange membership with peers.
///
/// Gossip over the existing API rather than a separate transport: with a
/// handful of nodes the saving from a purpose-built protocol is not worth a
/// second attack surface on a daemon that controls power.
/// Add the leases this node carries to a membership message, when it
/// carries any. A node with none sends exactly what it always sent.
fn with_leases(mut v: serde_json::Value, leases: serde_json::Value) -> serde_json::Value {
    if leases.as_array().is_some_and(|l| !l.is_empty()) {
        if let Some(o) = v.as_object_mut() {
            o.insert("leases".into(), leases);
        }
    }
    v
}

/// Rejoin over the underlay: listen for peers' leased-key announcements, and
/// announce this node's own to peers that have stopped handshaking with it.
///
/// A leased node that restarts holds a key no peer has, and everything else
/// it says travels inside the overlay. This is the path that does not, and the
/// only thing it carries is a signed lease; see [`furcate_net::announce`]. A
/// node whose key is not leased listens and never announces.
fn spawn_rejoin(
    sched: &furcate_sched::Registry,
    agent: Arc<Mutex<Agent>>,
    me: String,
    peer_keys: BTreeMap<String, VerifyingKey>,
    assurance: furcate_identity::AssuranceClass,
) {
    let port = match overlay::announce_port() {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("furcated: overlay rejoin announcements are off (FURCATE_OVERLAY_ANNOUNCE_PORT=0); a new leased key reaches peers through the coordinator or gossip only");
            return;
        }
        Err(e) => {
            eprintln!("furcated: WARNING overlay: {e}; rejoin announcements are off");
            return;
        }
    };
    spawn_announce_listener(Arc::clone(&agent), me.clone(), peer_keys, port);

    // The signed announcement is reused for a minute: a lost datagram is
    // resent as it was, and the hardware is asked at most once a minute, and
    // only while some peer is not handshaking.
    let mut sealed: Option<(u64, String, Vec<u8>)> = None;
    let mut last_targets: Vec<std::net::SocketAddr> = Vec::new();
    furcate_sched::spawn(sched, "overlay-rejoin", furcate_sched::Cadence::FixedRate { secs: 15 }, furcate_sched::Backoff::default(), move || {
        if !overlay::leased_here() {
            return furcate_sched::Ran::Ok;
        }
        let now = now_s();
        let targets = overlay::announce_targets(port, now);
        if targets.is_empty() {
            last_targets.clear();
            return furcate_sched::Ran::Ok;
        }
        let key = overlay::kernel_key().unwrap_or_default();
        let reuse = sealed.as_ref().is_some_and(|(at, k, _)| *k == key && now.saturating_sub(*at) < 60);
        if !reuse {
            let h = match serde_json::from_value::<furcate_net::overlay::Hint>(overlay_hint(&me, assurance)) {
                Ok(h) if h.lease.is_some() => h,
                Ok(_) => return furcate_sched::Ran::Skipped("this node's lease is not bound yet; nothing to announce".into()),
                Err(_) => return furcate_sched::Ran::Skipped("the overlay is not up yet; nothing to announce".into()),
            };
            match overlay::announcement(&h, now) {
                Ok(d) => sealed = Some((now, h.public_key.clone(), d)),
                Err(e) => return furcate_sched::Ran::Failed(e),
            }
        }
        let Some((_, _, datagram)) = sealed.as_ref() else { return furcate_sched::Ran::Ok };
        if targets != last_targets {
            let list: Vec<String> = targets.iter().map(|t| t.to_string()).collect();
            eprintln!(
                "furcated: overlay: announcing this node's leased key over the underlay to {} peer address(es) with no recent handshake: {}",
                targets.len(),
                list.join(", ")
            );
            last_targets = targets.clone();
        }
        let v4 = std::net::UdpSocket::bind("0.0.0.0:0");
        let v6 = std::net::UdpSocket::bind("[::]:0");
        let mut sent = 0;
        for t in &targets {
            let sock = if t.is_ipv4() { v4.as_ref() } else { v6.as_ref() };
            if let Ok(s) = sock {
                if s.send_to(datagram, t).is_ok() {
                    sent += 1;
                }
            }
        }
        if sent == 0 {
            return furcate_sched::Ran::Failed(format!("no announcement could be sent to {} peer address(es)", targets.len()));
        }
        furcate_sched::Ran::Ok
    });
}

/// The receiving half: one UDP socket that reads announcements and nothing
/// else, and never answers.
fn spawn_announce_listener(
    agent: Arc<Mutex<Agent>>,
    me: String,
    peer_keys: BTreeMap<String, VerifyingKey>,
    port: u16,
) {
    let sock = match std::net::UdpSocket::bind(("::", port)).or_else(|_| std::net::UdpSocket::bind(("0.0.0.0", port))) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("furcated: WARNING overlay: cannot listen for rejoin announcements on udp {port}: {e}; peers that restart with a new leased key reach this node through the coordinator or gossip only");
            return;
        }
    };
    eprintln!("furcated: overlay: listening for leased-key announcements on udp {port} (signed leases only; nothing is answered)");
    let spawned = std::thread::Builder::new().name("overlay-announce".into()).spawn(move || {
        let mut replay = furcate_net::announce::Replay::new();
        let mut buf = vec![0u8; furcate_net::announce::MAX_DATAGRAM + 1];
        // At most this many datagrams are checked per second; the rest are
        // dropped unread, so a flood costs a read, not a signature check.
        const PER_SECOND: u32 = 20;
        let mut window = (0u64, 0u32);
        let mut refused: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut dropped = 0u64;
        loop {
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("furcated: WARNING overlay: announcement socket: {e}");
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }
            };
            let now = now_s();
            if window.0 != now {
                if dropped > 0 {
                    eprintln!("furcated: overlay: {dropped} announcement datagram(s) dropped unread over the rate limit");
                    dropped = 0;
                }
                window = (now, 0);
            }
            if window.1 >= PER_SECOND {
                dropped += 1;
                continue;
            }
            window.1 += 1;
            let anchors = match overlay::anchors() {
                Ok(a) => a,
                Err(e) => {
                    if refused.insert(format!("anchors: {e}")) {
                        eprintln!("furcated: overlay: announcements cannot be checked: {e}");
                    }
                    continue;
                }
            };
            let trusted = |id: &str| peer_keys.get(id).map(|k| format!("ed25519:{}", hex::encode(k.to_bytes())));
            match furcate_net::announce::open(&buf[..n], &me, &anchors, &trusted, &mut replay, now, overlay::lease_ceiling()) {
                Ok(h) => {
                    let mut a = agent.lock().expect("agent lock");
                    if overlay::hold(&mut a.membership, &h, now) {
                        eprintln!(
                            "furcated: overlay: {} announced its leased key {} from {from}; carried from the next reconciliation",
                            h.node_id, h.public_key
                        );
                    }
                }
                // The same signed datagram resent: the sender repeats each one
                // in case it was lost, so this is expected and not worth a line.
                Err(furcate_net::announce::Refusal::Replay { sent_at, last, .. }) if sent_at == last => {}
                Err(e) => {
                    if refused.len() > 1024 {
                        refused.clear();
                    }
                    // Once per kind of refusal per sender: a peer repeats
                    // what it sends, and the reason does not change between.
                    if refused.insert(format!("{} {}", e.kind(), from.ip())) {
                        eprintln!("furcated: overlay: announcement from {} refused: {e}", from.ip());
                    }
                }
            }
        }
    });
    if let Err(e) = spawned {
        eprintln!("furcated: WARNING overlay: cannot start the announcement listener: {e}");
    }
}

/// The bytes a `/ping` signature covers.
///
/// Domain-separated and bound to the identity being claimed. The nonce alone
/// would already stop a replay, and looking the key up by the claimed id
/// already stops one node answering as another — this binds both anyway so the
/// signature cannot be lifted out of this exchange and presented as an answer
/// to some other question that also signs 16 random bytes.
fn ping_challenge(nonce: &[u8], node_id: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + nonce.len() + node_id.len());
    m.extend_from_slice(b"furcate:ping:v1\0");
    m.extend_from_slice(nonce);
    m.extend_from_slice(node_id.as_bytes());
    m
}

fn spawn_membership_loop(
    sched: &furcate_sched::Registry,
    agent: Arc<Mutex<Agent>>,
    me: String,
    // Whose claim to an identity this node will believe, from the trust store.
    // Empty means this node joins nobody, which is the correct failure: a
    // membership set assembled from unverified claims is worse than an empty
    // one, because everything downstream treats it as fact.
    peer_keys: BTreeMap<String, VerifyingKey>,
    assurance: furcate_identity::AssuranceClass,
) {
    let peers: Vec<String> = std::env::var("FURCATE_PEERS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    if peers.is_empty() {
        return;
    }
    // Address to identity, learned from the first successful ping. Without it
    // a failed ping has no identity to suspect, and suspecting every known
    // member instead would condemn healthy nodes for one peer's silence.
    //
    // Declared outside the closure so it survives between runs: the scheduler
    // calls this repeatedly rather than owning a loop, so anything that must
    // persist across ticks is captured rather than re-initialised.
    let mut identity_of: BTreeMap<String, String> = BTreeMap::new();
    let mut tick = 0u64;
    furcate_sched::spawn(sched, "membership", furcate_sched::Cadence::FixedRate { secs: 5 }, furcate_sched::Backoff::default(), move || {
            tick += 1;
            let now = now_s();
            // This node's own leased hint, when its key is leased, so the
            // next member pinged learns a new key without the coordinator.
            if tick % 6 == 1 && overlay::leased_here() {
                if let Ok(h) = serde_json::from_value::<furcate_net::overlay::Hint>(overlay_hint(&me, assurance)) {
                    let mut a = agent.lock().expect("agent lock");
                    overlay::hold(&mut a.membership, &h, now);
                }
            }
            // Taken once per tick and released before any exchange, so no
            // lock is held across the network call.
            let out_leases = {
                let a = agent.lock().expect("agent lock");
                overlay::gossip_out(&a.membership, now)
            };
            let anchors = overlay::anchors();
            let trusted = |id: &str| peer_keys.get(id).map(|k| format!("ed25519:{}", hex::encode(k.to_bytes())));
            for peer in &peers {
                // A nonce this node chose, so the answer cannot be a recording.
                let mut nonce = [0u8; 16];
                let seen = if getrandom::fill(&mut nonce).is_err() {
                    // No randomness means no challenge, and an unchallenged
                    // answer is not evidence. Say so and move on rather than
                    // falling back to trusting the claim.
                    eprintln!("furcated: WARNING membership: no randomness for a ping challenge; {peer} not joined this tick");
                    None
                } else {
                    furcate_api::post_json(
                        peer,
                        "/ping",
                        &with_leases(
                            json!({ "from": me, "nonce": hex::encode(nonce) }),
                            out_leases.clone(),
                        ),
                        4_000,
                    )
                    .ok()
                    .inspect(|v| {
                        // Checked on arrival whoever sent them; relaying adds
                        // no trust, so this does not wait on the identity check
                        // below.
                        if let Ok(anchors) = &anchors {
                            let mut a = agent.lock().expect("agent lock");
                            overlay::gossip_in(&mut a.membership, &me, v.get("leases"), anchors, &trusted, now);
                        }
                    })
                    .and_then(|v| {
                        // The identity being claimed, and the proof of it.
                        // Before this, `node_id` was taken at face value: any
                        // host in FURCATE_PEERS could answer with a peer's
                        // identity and be joined under it, and everything
                        // downstream — placement, suspicion, the ledger entries
                        // written on a membership change — treated that as
                        // established.
                        let claimed = v.get("node_id").and_then(|n| n.as_str())?;
                        let Some(sig_hex) = v.get("signature").and_then(|s| s.as_str()) else {
                            eprintln!("furcated: WARNING membership: {peer} claims {claimed} but sent no signature (an agent from before signed pings?); not joined");
                            return None;
                        };
                        let Some(key) = peer_keys.get(claimed) else {
                            eprintln!("furcated: WARNING membership: {peer} claims {claimed}, which is not a machine this node's trust store recognises; not joined");
                            return None;
                        };
                        let ok = hex::decode(sig_hex)
                            .ok()
                            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
                            .map(|b| Signature::from_bytes(&b))
                            .is_some_and(|sig| {
                                key.verify(&ping_challenge(&nonce, claimed), &sig).is_ok()
                            });
                        if !ok {
                            eprintln!("furcated: WARNING membership: {peer} claims {claimed} but the signature over this node's nonce did not verify; not joined");
                            return None;
                        }
                        Some(claimed.to_string())
                    })
                };

                let mut a = agent.lock().expect("agent lock");
                match seen {
                    Some(peer_id) => {
                        identity_of.insert(peer.clone(), peer_id.clone());
                        a.membership.join(peer_id.clone());
                        a.membership.alive_update(&peer_id, tick);
                        a.membership.health().reward();
                    }
                    None => {
                        // Suspect only the peer that failed to answer.
                        if let Some(id) = identity_of.get(peer) {
                            a.membership.suspect(id, tick, tick);
                        }
                        a.membership.health().punish();
                    }
                }
                for t in a.membership.tick(tick) {
                    a.chain.append(
                        now_ms(),
                        OpKind::Lifecycle,
                        "membership",
                        format!("{t:?}"),
                        "confirmed",
                    );
                }
            }
        furcate_sched::Ran::Ok
    });
}

/// Watch the platform for health signals.
///
/// Signals come from the hardware rather than from guesswork: storage
/// self-monitoring and thermal sensors. Nothing here invents a fault; a
/// machine with no readable sensors simply produces no signals.
fn spawn_health_loop(sched: &furcate_sched::Registry, agent: Arc<Mutex<Agent>>) {
    furcate_sched::spawn(sched, "health", furcate_sched::Cadence::FixedRate { secs: 60 }, furcate_sched::Backoff::default(), move || {
        let mut found: Vec<SignalKind> = Vec::new();

        // Storage: reallocated sectors, where smartctl can read them.
        if let Ok(out) = std::process::Command::new("lsblk")
            .args(["-dno", "NAME,TYPE"])
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let mut parts = line.split_whitespace();
                let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
                    continue;
                };
                if kind != "disk" {
                    continue;
                }
                let dev = format!("/dev/{name}");
                let Ok(smart) = std::process::Command::new("smartctl")
                    .args(["-A", &dev])
                    .output()
                else {
                    continue;
                };
                let text = String::from_utf8_lossy(&smart.stdout);
                let reallocated = text
                    .lines()
                    .find(|l| l.contains("Reallocated_Sector_Ct") || l.contains("Reallocated_Event_Count"))
                    .and_then(|l| l.split_whitespace().last())
                    .and_then(|v| v.parse::<u64>().ok());
                if let Some(count) = reallocated {
                    if count > 0 {
                        found.push(SignalKind::DiskDegraded { device: dev, reallocated: count });
                    }
                }
            }
        }

        // Accelerators, from the report the privileged reader publishes.
        //
        // Read rather than probed: this loop already shells out to smartctl
        // for the disks, but the cards are published as a file precisely so
        // this agent does not have to, and reading it here keeps the one path.
        //
        // Only cards with something to say raise a signal. A healthy card, and
        // a card with old remaps that are not moving, are both silent — the
        // chain is for things somebody has to act on.
        {
            let (cards, _readable) = host::accelerators();
            for card in &cards {
                let verdict = furcate_host::accelerator::assess(card, None);
                if !verdict.is_actionable() {
                    continue;
                }
                found.push(SignalKind::AcceleratorDegraded {
                    index: card.index,
                    // The verdict's serde name, which is the same string the
                    // /host route and the console already show.
                    verdict: serde_json::to_value(&verdict)
                        .ok()
                        .and_then(|v| match v {
                            serde_json::Value::String(s) => Some(s),
                            serde_json::Value::Object(o) => o.keys().next().cloned(),
                            _ => None,
                        })
                        .unwrap_or_else(|| "unknown".into()),
                    implicates_card: verdict.implicates_the_card(),
                    should_drain: verdict.should_drain(),
                });
            }
        }

        // Thermal, straight from the kernel.
        if let Ok(entries) = std::fs::read_dir("/sys/class/thermal") {
            for e in entries.flatten() {
                let p = e.path();
                if !p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("thermal_zone")).unwrap_or(false) {
                    continue;
                }
                let Ok(raw) = std::fs::read_to_string(p.join("temp")) else { continue };
                let Ok(milli) = raw.trim().parse::<i64>() else { continue };
                let celsius = milli as f32 / 1000.0;
                if celsius >= 80.0 {
                    found.push(SignalKind::Thermal {
                        sensor: p.file_name().unwrap_or_default().to_string_lossy().to_string(),
                        celsius,
                    });
                }
            }
        }

        if !found.is_empty() {
            let mut a = agent.lock().expect("agent lock");
            let node = a.node_id.clone();
            for kind in found {
                let signal = Signal::new(node.clone(), kind, now_s());
                // Only act on what is new; re-reporting the same warning every
                // minute would fill the chain with noise.
                let already = a.signals.iter().any(|s| s.kind == signal.kind);
                if !already {
                    a.observe_signal(signal);
                }
            }
        }
        furcate_sched::Ran::Ok
    });
}

/// Checkpoint the operation chain into the TPM.
///
/// A hashchain alone only detects tampering by someone who does not hold it.
/// Extending the head into a platform register puts the commitment inside the
/// chip, where reproducing a divergent history would need a quote over a value
/// the chip never held.
fn spawn_checkpoint_loop(
    sched: &furcate_sched::Registry,
    agent: Arc<Mutex<Agent>>,
    rot: Arc<dyn RootOfTrust + Send + Sync>,
) {
    furcate_sched::spawn(sched, "checkpoint", furcate_sched::Cadence::FixedDelay { secs: 300 }, furcate_sched::Backoff::default(), move || {
        let head = {
            let a = agent.lock().expect("agent lock");
            a.chain.head()
        };
        // Nothing to checkpoint yet. A skip rather than a failure: the chain
        // being empty is a fact about a fresh node, not a fault.
        let Some(head) = head else {
            return furcate_sched::Ran::Skipped("chain has no head yet".into());
        };

        let extended = std::process::Command::new("tpm2_pcrextend")
            .arg(format!(
                "{}:sha256={}",
                furcate_ledger::checkpoint::DEFAULT_CHECKPOINT_PCR,
                hex::encode(head)
            ))
            .env("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if extended {
            // Quote the register so the checkpoint is signed by the chip.
            // A quote that came back is not a quote that was signed: the
            // fingerprint backend returns a self-description with an empty
            // signature precisely so a verifier rejects it. Asking `is_ok`
            // would record "quoted" for a node that cannot quote.
            let signed = rot.quote(&head).map(|q| q.is_signed()).unwrap_or(false);
            let mut a = agent.lock().expect("agent lock");
            a.persist_chain();
            a.chain.append(
                now_ms(),
                OpKind::Quote,
                "checkpoint",
                format!("pcr{}", furcate_ledger::checkpoint::DEFAULT_CHECKPOINT_PCR),
                if signed { "extended and quoted" } else { "extended" },
            );
            a.checkpoints += 1;
            return furcate_sched::Ran::Ok;
        }
        // The register did not extend. Worth recording as a failure rather
        // than a skip: a chip that will not extend is a chip whose checkpoints
        // have stopped being evidence.
        furcate_sched::Ran::Failed("tpm2_pcrextend did not succeed".into())
    });
}

/// Report to the site controller on a timer.
///
/// Deliberately best-effort: a controller that is down, slow or absent must
/// never affect the node's own operation.
/// Everything the reporting loop needs to describe this machine.
///
/// A struct rather than eight positional parameters: the two booleans at the
/// end were one transposition away from a node reporting somebody else's
/// assurance, and a compiler cannot catch that when both are `bool`.
pub struct Reporting {
    pub node_id: String,
    pub site: String,
    pub disk_gb: u64,
    pub endpoint: String,
    pub signing: Option<Arc<SigningKey>>,
    /// The class of this node's root of trust. Carried rather than
    /// re-derived, so the overlay tier and the identity this node reports
    /// elsewhere cannot disagree about the same machine.
    pub assurance: furcate_identity::AssuranceClass,
}

fn spawn_reporting_loop(
    sched: &furcate_sched::Registry,
    agent: Arc<Mutex<Agent>>,
    r: Reporting,
) {
    let Reporting { node_id, site, disk_gb, endpoint, signing, assurance } = r;
    let topology_id = std::env::var("FURCATE_NODE_NAME").unwrap_or_else(|_| {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    });
    furcate_sched::spawn(sched, "report", furcate_sched::Cadence::FixedRate { secs: 15 }, furcate_sched::Backoff::default(), move || {
        let (head, capability, rung, on_battery) = {
            let a = agent.lock().expect("agent lock");
            (
                a.chain.head().map(hex::encode),
                a.capability.clone(),
                a.ladder.rung(),
                // Whether this machine is running on stored power. The
                // controller's loop has to know: on battery the ladder owns
                // the situation, and a loop that believed the fleet was always
                // on mains would keep optimising straight through an outage.
                matches!(
                    a.ups.state(),
                    Some(furcate_power::PowerState::OnBattery)
                        | Some(furcate_power::PowerState::LowBattery)
                ),
            )
        };
        // Collected once and used three times: reported to the controller,
        // folded into this node's own health, and left out of a second probe.
        let inventory = workloads::collect();
        {
            let mut a = agent.lock().expect("agent lock");
            fold_workloads_into_health(&mut a, &inventory);
        }

        // Collected once and used twice: reporting it and deriving series from
        // it separately would probe the network twice per cycle.
        let net = network::collect();
        let mut series = network::series_points(&net);
        let net_report = serde_json::to_value(&net).unwrap_or(json!(null));

        // Contention rather than utilisation. A processor at full load with
        // nothing queued is fine; one at half load with tasks stalled on
        // memory reclaim is failing, and only pressure tells them apart.
        let res = resources::collect();
        for (k, v) in resources::series_points(&res) {
            series.insert(k, v);
        }

        // The host underneath: disks and when they fill, the clock, and
        // whether a restart is pending. Free space is a good forecast rail —
        // smooth, trending, and the question a forecast of it answers is the
        // one the operator already has.
        // Journal, backups, certificates and configuration drift.
        let cust = custody::collect();
        {
            let mut a = agent.lock().expect("agent lock");
            fold_custody_into_health(&mut a, &cust);
        }
        let custody_report = serde_json::to_value(&cust).unwrap_or(json!(null));

        // The management controller: fans and temperatures Linux cannot see.
        let bmcinfo = bmc::collect();
        for (k, v) in bmc::series_points(&bmcinfo) {
            series.insert(k, v);
        }
        let bmc_report = serde_json::to_value(&bmcinfo).unwrap_or(json!(null));

        let hostinfo = host::collect();
        for (k, v) in host::series_points(&hostinfo) {
            series.insert(k, v);
        }
        let host_report = serde_json::to_value(&hostinfo).unwrap_or(json!(null));
        let contention = res.psi.map(|p| resources::contention(&p));
        let res_report = serde_json::to_value(&res).unwrap_or(json!(null));

        if let Some(head) = head {
            let models: Vec<serde_json::Value> = {
                let a = agent.lock().expect("agent lock");
                a.models
                    .values()
                    .map(|m| {
                        // Report enough for the site to build a manifest. The
                        // node knows its own runtime and the artifact size; it
                        // does not know whether anyone signed the model, so it
                        // does not claim that.
                        let bytes = m
                            .path
                            .as_ref()
                            .and_then(|p| std::fs::metadata(p).ok())
                            .map(|md| md.len())
                            .unwrap_or(0);
                        json!({
                            "id": m.id,
                            "digest": m.digest,
                            "runtime": "llama.cpp",
                            "bytes": bytes,
                        })
                    })
                    .collect()
            };
            let body = json!({
                "node_id": node_id,
                "models": models,
                // The name this machine answers to in the site file. Reported
                // rather than guessed: a controller matching node identifiers
                // against topology names by substring will map several
                // machines onto one entry and say so confidently.
                "topology_id": topology_id,
                "head": head,
                "capability": capability,
                "disk_gb": disk_gb,
                "power_w": power::read().watts,
                // Measured at the chassis boundary by the power supply, where
                // the hardware offers it. This is the figure the utility bills
                // and the one the controller previously had to estimate.
                "wall_w": bmc::collect().wall.map(|w| w.input_watts),
                // A compact hardware summary for the site's standard-schema
                // metric export. Sent in the report rather than scraped
                // per-node so a controller keeps one view of the fleet, and
                // kept small deliberately — the full detail is on /cooling and
                // /host, and duplicating it here would create a second copy
                // that could disagree with the first.
                "hw": hardware_summary(&cust),
                // What this machine is, so the controller can hold a fleet
                // view of identity rather than each node knowing only itself.
                "image": image_summary(),
                // Where this node can be reached on the overlay, for the
                // coordinator to pass on. Published rather than inferred from
                // the connection's source address, so the mesh does not depend
                // on the coordinator sitting on the same path as the peers.
                "overlay_hint": overlay_hint(&node_id, assurance),
                // Evidence about coming back, not a claim of being able to.
                "wake": wake::collect(),
                "on_battery": on_battery,
                // What this machine is actually running. A node that is
                // attested, cool and on mains can still be useless because the
                // thing it hosts has been crash-looping for an hour, and until
                // now nothing in the report would have said so.
                "workloads": inventory,
                // The network as a physical thing: what the wire is doing,
                // where the path stops working, and whether the connection is
                // good as opposed to merely fast.
                "network": net_report,
                "resources": res_report,
                "host": host_report,
                "custody": custody_report,
                "bmc": bmc_report,
                // What share of the last minute something could not proceed.
                // Absent on a kernel without pressure accounting, which is
                // different from zero.
                "contention": contention,
                // Named scalar series for the forecaster. Throughput and round
                // trip are series like any other, so the machinery that
                // predicts power predicts them without knowing what they are.
                "series": series,
                "endpoint": endpoint,
                "power_rung": rung.as_str(),
            });
            // The report is signed by the header credential the router checks,
            // and nothing else. The envelope that used to ride in the body said
            // the same thing in a second encoding, and two encodings of one
            // protocol is a thing to keep in step forever for no gain.
            // Signed as this machine, against the roster the controller
            // admitted it into.
            let machine = signing.as_ref().map(|k| {
                furcate_authn::local::MachineSigner::new(node_id.clone(), (**k).clone())
            });
            let sign = |m: &str, p: &str, b: &[u8]| {
                machine
                    .as_ref()
                    .map(|s| s.credential(m, p, b, now_s()))
                    .unwrap_or_default()
            };
            let credentialled: Option<furcate_api::Credentialler> =
                machine.as_ref().map(|_| &sign as furcate_api::Credentialler);
            if furcate_api::post_signed(&site, "/head", &body, 5_000, credentialled).is_ok() {
                let mut a = agent.lock().expect("agent lock");
                a.controller_seen_at = Some(now_ms());
                a.bringup.set_gate(Gate::AddressReady("site".into()), GateState::Open);
                a.bringup.settle(now_s());
            }
        }
        furcate_sched::Ran::Ok
    });
    eprintln!("furcated: reporting to site controller");
}

/// Read the site's trust store, or refuse to start on a broken one.
///
/// A file that is present and unreadable is fatal, never a fall-through to
/// defaults: falling back would restore authority an operator had written down
/// a decision to remove, and an unreadable file is not evidence they changed
/// their mind. The overlay policy already follows this rule, learned the same
/// way.
///
/// Absent is a different thing and is allowed. A site that has enrolled nobody
/// recognises nobody, which is deny-by-default working rather than failing.
fn load_trust_store() -> furcate_authn::TrustStore {
    let path = furcate_paths::config("trust.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("furcated: FATAL trust store {} exists and cannot be read: {e}", path.display());
            std::process::exit(1);
        }
    };
    match furcate_authn::TrustStore::load(text.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("furcated: FATAL trust store {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Register a model this node serves.
///
/// It reads a path on this machine, points inference at an endpoint and
/// writes the registry, so it is the operator's to call.
fn model_load_route(r: Router, agent: Arc<Mutex<Agent>>) -> Router {
    r.guarded("POST", "/models/load", {
        let agent = Arc::clone(&agent);
        move |req: &Request| {
            let (Some(id), Some(path), Some(endpoint)) = (
                req.body.get("id").and_then(|v| v.as_str()),
                req.body.get("path").and_then(|v| v.as_str()),
                req.body.get("endpoint").and_then(|v| v.as_str()),
            ) else {
                return Response::error(400, "`id`, `path` and `endpoint` are required");
            };
            // Measure the artifact before serving it. A node that serves
            // weights it never hashed cannot say which model it ran.
            let digest = match runtime::measure(std::path::Path::new(path)) {
                Ok(d) => d,
                Err(e) => return Response::error(400, format!("measuring {path}: {e}")),
            };
            if !runtime::reachable(endpoint) {
                return Response::error(
                    503,
                    format!("no runtime answering at {endpoint}; not registering a model this node cannot serve"),
                );
            }
            let mut a = agent.lock().expect("agent lock");
            a.models.insert(
                id.to_string(),
                runtime::LoadedModel {
                    id: id.to_string(),
                    digest: digest.clone(),
                    endpoint: endpoint.to_string(),
                    path: Some(path.to_string()),
                },
            );
            let all: Vec<_> = a.models.values().cloned().collect();
            let _ = runtime::save(&model_registry_path(), &all);
            a.chain.append(now_ms(), OpKind::ModelLoad, "api", id, &digest[..16]);
            a.persist_chain();
            Response::ok(json!({ "loaded": id, "digest": digest }))
        }
    })
}

/// A new directory that only this process's user can enter, under a name
/// nobody could have made first.
///
/// `create_dir_all` under a time-based name accepts a directory that is
/// already there, along with anything another user placed in it, such as a
/// link where a file is about to be written.
fn private_dir(base: &std::path::Path, prefix: &str) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut r = [0u8; 16];
    getrandom::fill(&mut r).map_err(|e| std::io::Error::other(e.to_string()))?;
    let dir = base.join(format!("{prefix}-{}", hex::encode(r)));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

fn build_router(
    sched: furcate_sched::Registry,
    agent: Arc<Mutex<Agent>>,
    rot: Arc<dyn RootOfTrust + Send + Sync>,
    node_id: String,
    signing: Option<Arc<SigningKey>>,
    // Loaded by the caller and shared with the membership loop, so the machines
    // this node serves and the machines it will join are the same list.
    trust: furcate_authn::TrustStore,
) -> Router {
    // What signs this node's cell links, read tokens and roll-ups: the key
    // the root of trust signs messages with when it has one, such as a Pi's
    // firmware-held OTP key, so a head's key never leaves its hardware; else
    // the node key, as before.
    let cell_signer: Option<Arc<dyn furcate_identity::MessageSigner>> =
        match furcate_identity::RootOfTrustSigner::of(Arc::clone(&rot)) {
            Some(s) => Some(Arc::new(s)),
            None => signing.clone().map(|k| {
                Arc::new(furcate_identity::Ed25519Signer(k)) as Arc<dyn furcate_identity::MessageSigner>
            }),
        };
    // The same key binds this node's overlay leases, so a Pi's leases are
    // signed by its firmware-held key and never by a key on disk.
    if let Some(s) = &cell_signer {
        overlay::set_lease_signer(Arc::clone(s));
    }
    // Whose gossiped lease this node accepts on an overlay with no anchors:
    // the machine keys its trust store names, as for membership.
    let lease_keys: Arc<BTreeMap<String, String>> = Arc::new(
        trust
            .device_keys()
            .into_iter()
            .map(|(id, key, _)| (id, format!("ed25519:{}", hex::encode(key.to_bytes()))))
            .collect(),
    );
    // Who this machine is willing to recognise.
    //
    // The site's own operator key, read from the same file and the same format
    // the kill switch already uses. There is deliberately no second operator
    // key: a machine that can be told to stop is a machine that can be told to
    // restart a container, and a separate authority for the smaller act would
    // be a second thing to protect.
    //
    // Absent means this machine recognises nobody and every guarded route
    // refuses. That is the correct failure — a node that invented its own
    // authority when the key was missing would defeat the guarantee.
    // Who this machine is willing to recognise, in the order it tries them.
    //
    // The site's own operator key first, because that is the path that works
    // when nothing else answers — a machine whose network is down still admits
    // the person standing in front of it.
    //
    // Then machines, then agents. A machine here proves itself with its TPM.
    // A person's passkey is not a request credential: it approves orders,
    // through the order routes mounted at the end, and never signs a request.
    let operator_key = furcate_paths::config("operator.pub");
    // The operator, plus anyone this site admits alongside them. The roster
    // is read here rather than per request: this path must answer with no
    // network and no directory to consult, which is the property it exists for.
    let local = furcate_authn::LocalVerifier::from_key_file(&operator_key)
        .with_people_file(&furcate_paths::config("people.json"), now_s());
    if !local.knows_its_operator() {
        eprintln!(
            "furcated: no operator key at {} — every guarded route will refuse",
            operator_key.display()
        );
    }

    let devices = furcate_authn::device::DeviceVerifier::new(trust.device_keys());
    let agents = furcate_authn::TokenVerifier::new(
        trust.issuer_keys(),
        node_id.clone(),
        trust.revoked.clone(),
        trust.revocations_checked_at,
    );
    eprintln!(
        "furcated: recognises the operator{}, {} admitted {}, {} machine(s), {} agent issuer(s)",
        if local.knows_its_operator() { "" } else { " (no key)" },
        local.admitted(),
        if local.admitted() == 1 { "person" } else { "people" },
        trust.device_keys().len(),
        trust.issuer_keys().len()
    );

    // What this node's root of trust actually is, read once.
    //
    // `/attest` used to report the quote and the registers but never the class
    // of the thing that produced them, so a verifier had nothing to appraise
    // against and the controller filled the gap with a literal `Tpm`. That is
    // only harmless while every node is a TPM node.
    //
    // Read here rather than per request because both answers are fixed for the
    // life of the process, and `ek_certificate()` is a TPM round-trip on the
    // tpm2-tools backend. `/dev/tpmrm0` serialises and is shared with other services,
    // so a round-trip per attestation is a cost paid by an unrelated service.
    let attest_assurance = rot.assurance();
    // Endorsed means the platform ships a vendor certificate over its
    // endorsement key — the difference between "this key lives in a TPM" and
    // "this key lives in a TPM that Infineon vouches for". A node that cannot
    // produce one says so; the verifier decides what that is worth.
    //
    // Holding a certificate is not enough: swtpm writes one as well, signed by
    // a CA it made on the spot. Endorsed means it chains to a manufacturer CA
    // in the operator's bundle, and a soft root is never endorsed.
    let attest_endorsement = furcate_identity::backends::endorsement(
        &*rot,
        &furcate_identity::backends::Policy::in_config_dir(&furcate_paths::config_dir()),
    );
    let attest_endorsed = attest_endorsement.endorsed;
    eprintln!("furcated: attesting as {attest_assurance}, {}", attest_endorsement.detail);

    // Where this node answers, for the agent card to point at. Read here rather
    // than threaded through build_router as a parameter: one route needing it
    // does not justify changing every caller's signature.
    let listen_addr =
        std::env::var("FURCATE_LISTEN").unwrap_or_else(|_| "127.0.0.1:7616".to_string());

    let r = Router::new()
        .verified_by(Arc::new(furcate_authn::AnyOf(vec![
            // First, since it claims only its own scheme: a passkey read
            // token for GET /cells, issued by this node.
            Box::new(furcate_topology::read_token::ReadTokenVerifier {
                node: cell_signer
                    .as_ref()
                    .and_then(|k| furcate_topology::cell::signer_id(k.as_ref()).ok())
                    .unwrap_or_default(),
            }),
            Box::new(local),
            Box::new(devices),
            Box::new(agents),
        ])))
        // A device-tier member carries readings and ordinary requests. A
        // privileged call from it, by its overlay address or its own
        // credential, is refused here, before any guarded handler or order.
        .originating(Arc::new(overlay::may_originate))
        .route("GET", "/healthz", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                Response::ok(json!({
                    "node_id": a.node_id,
                    "edition": extension::get().edition(),
                    "state": a.lifecycle.state().as_str(),
                    "chain_length": a.chain.len(),
                    "power_rung": a.ladder.rung().as_str(),
                    "ups": match &a.ups {
                        ups::Reading::Present { state, charge_pct, .. } =>
                            json!({ "present": true, "state": format!("{state:?}"), "charge_pct": charge_pct }),
                        ups::Reading::Absent => json!({ "present": false }),
                    },
                    "members": a.membership.alive().len(),
                    "sensors": a.sensors.len(),
                    "signals": a.signals.len(),
                    "checkpoints": a.checkpoints,
                    "autonomous": a.autonomous(now_ms(), CONTROLLER_TIMEOUT_MS),
                    "accepts_work": a.lifecycle.state().accepts_work(),
                }))
            }
        })
        // Prove this identity to a peer, rather than merely assert it.
        //
        // Answering with a bare `node_id` made membership a matter of what a
        // host was willing to type. The caller supplies a nonce and gets a
        // signature over it under this node's key, which is the same key the
        // trust store already names for this machine.
        //
        // Deliberately still unauthenticated *inbound*: a challenge is not a
        // secret, and requiring credentials to answer one would mean two nodes
        // could not establish membership until each already trusted the other.
        // What it discloses is this node's own id and a signature over the
        // caller's nonce, neither of which helps anyone who did not already
        // reach the port.
        .route("POST", "/ping", {
            let node_id = node_id.clone();
            let signing = signing.clone();
            let agent = Arc::clone(&agent);
            let lease_keys = Arc::clone(&lease_keys);
            move |req: &Request| {
                // Leases ride the challenge both ways: what the caller holds
                // is checked and kept, and what this node holds goes back.
                let now = now_s();
                let leases = {
                    let mut a = agent.lock().expect("agent lock");
                    if req.body.get("leases").is_some() {
                        match overlay::anchors() {
                            Ok(anchors) => {
                                overlay::gossip_in(
                                    &mut a.membership,
                                    &node_id,
                                    req.body.get("leases"),
                                    &anchors,
                                    &|id| lease_keys.get(id).cloned(),
                                    now,
                                );
                            }
                            Err(e) => eprintln!("furcated: overlay gossip not checked: {e}"),
                        }
                    }
                    overlay::gossip_out(&a.membership, now)
                };
                let body = with_leases(json!({ "node_id": node_id }), leases.clone());
                let (Some(nonce_hex), Some(key)) = (
                    req.body.get("nonce").and_then(|v| v.as_str()),
                    signing.as_ref(),
                ) else {
                    // No nonce (an older peer) or no key (the seal did not
                    // open, and `receipts will be unsigned` was already loud at
                    // startup). Answer honestly without a proof and let the
                    // caller decide; it will refuse to join us, which is right.
                    return Response::ok(body);
                };
                let Ok(nonce) = hex::decode(nonce_hex) else {
                    return Response::error(400, "`nonce` must be hex");
                };
                if nonce.is_empty() {
                    return Response::error(400, "`nonce` must not be empty");
                }
                let sig = key.sign(&ping_challenge(&nonce, &node_id));
                Response::ok(with_leases(
                    json!({
                        "node_id": node_id,
                        "nonce": nonce_hex,
                        "signature": hex::encode(sig.to_bytes()),
                    }),
                    leases,
                ))
            }
        })
        // What this machine is, and what it will refuse.
        //
        // Every other reading here is an instrument. This is the model
        // underneath them, so an agent asking whether it can move the fans gets
        // an answer rather than finding out by issuing a command the controller
        // does not implement.
        .route("GET", "/hardware", {
            move |_: &Request| {
                let r = furcate_host::hardware::recognise();
                let asked = ["cpu_performance", "cpu_turbo", "fan_speed", "power_cap",
                             "measured_boot"];
                Response::ok(json!({
                    "recognised": r,
                    // Answered as three states, never two: a capability nobody
                    // has described is not the same as one that is refused, and
                    // an agent told a lever does not exist stops looking for it.
                    "can": asked
                        .iter()
                        .map(|k| (k.to_string(), json!(r.can(k))))
                        .collect::<serde_json::Map<String, serde_json::Value>>(),
                }))
            }
        })
        .route("GET", "/identity", {
            let rot = Arc::clone(&rot);
            let signing = signing.clone();
            move |_: &Request| match (rot.node_id(), rot.ek_certificate()) {
                (Ok(id), Ok(cert)) => Response::ok(json!({
                    "node_id": id.to_string(),
                    "assurance": rot.assurance().as_str(),
                    "endorsed": cert.is_some(),
                    // The public half of what this machine signs with, so
                    // another machine can enrol it and check its requests.
                    //
                    // Public by design: it is a verifying key, and publishing
                    // it is the only way a peer can ever refuse a forgery. What
                    // it is NOT is the identity — `node_id` is derived from the
                    // endorsement key and survives anything, while this is
                    // generated once and sealed, so it changes if the seal is
                    // ever lost. Enrolling a machine binds the two together,
                    // and re-enrolling is how a rotated key is accepted.
                    "signing_key": signing.as_ref().map(|k| hex::encode(k.verifying_key().to_bytes())),
                })),
                _ => Response::error(500, "could not read identity from the root of trust"),
            }
        })
        .route("POST", "/attest", {
            let rot = Arc::clone(&rot);
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                // A verifier must supply the nonce. A nonce the attester chose
                // itself proves nothing about freshness, so it is refused
                // rather than silently accepted.
                let Some(nonce_hex) = req.body.get("nonce").and_then(|v| v.as_str()) else {
                    return Response::error(
                        400,
                        "a verifier-supplied `nonce` is required; a self-chosen nonce proves nothing",
                    );
                };
                let Ok(nonce) = hex::decode(nonce_hex) else {
                    return Response::error(400, "`nonce` must be hex");
                };
                if nonce.is_empty() {
                    return Response::error(400, "`nonce` must not be empty");
                }
                match rot.quote(&nonce) {
                    Ok(q) => {
                        let mut a = agent.lock().expect("agent lock");
                        a.controller_seen_at = Some(now_ms());
                        a.chain.append(
                            now_ms(),
                            OpKind::Quote,
                            "verifier",
                            "pcr",
                            format!("{} registers", q.pcrs.values.len()),
                        );
                        a.persist_chain();
                        Response::ok(json!({
                            "node_id": a.node_id,
                            "nonce": hex::encode(&q.nonce),
                            "quote": hex::encode(&q.message),
                            "signature": hex::encode(&q.signature),
                            "pcrs": q.pcrs.to_hex(),
                            "chain_head": a.chain.head().map(hex::encode),
                            // What produced the quote above. Without these the
                            // verifier has evidence it cannot grade, and the
                            // controller was assuming `tpm` for every node —
                            // which would have recorded a Secure Enclave node
                            // as a TPM attestation, permanently, in a hash
                            // chain. `as_str()`, matching `/identity` and the
                            // attestation-result hash; NOT the serde encoding.
                            "assurance": attest_assurance.as_str(),
                            "endorsed": attest_endorsed,
                        }))
                    }
                    Err(e) => Response::error(500, format!("quote failed: {e}")),
                }
            }
        })
        // What this machine publishes. `/tls/allow` answers whether a name may
        // have a certificate; this answers the operator's question instead —
        // what is being served here, and at which release.
        // The key material this machine holds, and what is about to lapse.
        //
        // Presence and dates only — never a private key, and never a path that
        // would help somebody find one. An operator needs to know that the
        // machine has an identity, whose signatures it trusts, and which
        // certificate expires first; none of those questions require the secret
        // to leave the disk it is sealed to.
;
    let r = r
        .route("GET", "/keys", {
            let node_id_for_keys = node_id.clone();
            move |_: &Request| {
                let held = |name: &str| std::path::Path::new(&furcate_paths::state(name)).exists();

                let anchors: Vec<serde_json::Value> =
                    std::fs::read_to_string(furcate_paths::config("overlay-anchors.json"))
                        .ok()
                        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default()
                        .into_iter()
                        .map(|a| json!({ "key_id": a.get("key_id") }))
                        .collect();

                // Certificates, and the one that lapses first. Read from the
                // certificate rather than the issuer's metadata beside it: after
                // a failed renewal those disagree, and the metadata is the more
                // optimistic of the two.
                let root = std::env::var("FURCATE_DEPLOY_ROOT")
                    .unwrap_or_else(|_| "/var/lib/furcate/deploy".into());
                let mut certs: Vec<serde_json::Value> = Vec::new();
                let mut stack = vec![std::path::PathBuf::from(&root).join("edge/certificates")];
                while let Some(dir) = stack.pop() {
                    let Ok(entries) = std::fs::read_dir(&dir) else { continue };
                    for e in entries.flatten() {
                        let p = e.path();
                        if p.is_dir() {
                            stack.push(p);
                        } else if p.extension().and_then(|x| x.to_str()) == Some("crt") {
                            let name = p
                                .file_stem()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let expires = std::fs::read_to_string(&p)
                                .ok()
                                .and_then(|pem| furcate_deploy::certs::not_after(&pem));
                            certs.push(json!({ "name": name, "expires": expires }));
                        }
                    }
                }
                certs.sort_by_key(|c| c.get("expires").and_then(|v| v.as_i64()).unwrap_or(i64::MAX));

                Response::ok(json!({
                    "node_id": node_id_for_keys.clone(),
                    "held": {
                        // Named for what each is for, not for its filename: an
                        // operator reading this is deciding what would be lost.
                        "receipt signing": held("node-key"),
                        "site verifier": held("verifier-key"),
                        "operator anchor": held("operator-key"),
                    },
                    "anchors": anchors,
                    "certificates": certs,
                }))
            }
        })
        // Encrypted links out of this machine.
        //
        // Read from what the privileged half recorded rather than by asking the
        // kernel: the agent does not hold CAP_NET_ADMIN and must not, because an
        // agent able to reconfigure the interface it reports on could lie about
        // the network it is describing.
;
    let r = r
        .route("GET", "/tunnels", {
            move |_: &Request| {
                let mut out: Vec<serde_json::Value> = Vec::new();
                if let Ok(entries) = std::fs::read_dir("/run/furcate") {
                    for e in entries.flatten() {
                        let p = e.path();
                        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                        if !name.starts_with("wg") || !name.ends_with(".json") {
                            continue;
                        }
                        if let Some(v) = std::fs::read_to_string(&p)
                            .ok()
                            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                        {
                            out.push(v);
                        }
                    }
                }
                // Interfaces the kernel has that nothing recorded. Named so a
                // tunnel somebody made by hand is visible rather than absent —
                // an unmanaged link is exactly the one worth noticing.
                let mut unmanaged: Vec<String> = Vec::new();
                if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
                    for e in entries.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        let uevent = e.path().join("uevent");
                        let is_wg = std::fs::read_to_string(&uevent)
                            .map(|t| t.contains("DEVTYPE=wireguard"))
                            .unwrap_or(false);
                        let recorded = out.iter().any(|v| {
                            v.get("iface").and_then(|i| i.as_str()) == Some(name.as_str())
                        });
                        if is_wg && !recorded {
                            unmanaged.push(name);
                        }
                    }
                }
                unmanaged.sort();
                Response::ok(json!({ "tunnels": out, "unmanaged": unmanaged }))
            }
        })
        // The network this machine is actually on.
        //
        // Addresses and neighbours are read from the kernel's own files, which
        // any user may read. The filter rules are the part worth being careful
        // about: only the table Furcate owns is reported, because a tool that
        // lists rules it did not create invites somebody to change one it does
        // not understand.
        .route("GET", "/lan", {
            move |_: &Request| {
                let mut links: Vec<serde_json::Value> = Vec::new();
                if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
                    for e in entries.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name == "lo" {
                            continue;
                        }
                        let read = |f: &str| {
                            std::fs::read_to_string(e.path().join(f))
                                .map(|t| t.trim().to_string())
                                .unwrap_or_default()
                        };
                        let carrier = read("carrier");
                        links.push(json!({
                            "name": name,
                            "state": read("operstate"),
                            // Carrier and operstate disagree on a link that is
                            // up with nothing plugged in, and that difference is
                            // the whole diagnosis.
                            "carrier": carrier == "1",
                            "mtu": read("mtu"),
                            "speed": read("speed"),
                        }));
                    }
                }
                links.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

                // Neighbours as the kernel sees them: who this machine has
                // actually spoken to on the wire, which is a different and more
                // truthful list than whatever a config file says should be here.
                let mut neighbours: Vec<serde_json::Value> = Vec::new();
                if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
                    for line in text.lines().skip(1) {
                        let f: Vec<&str> = line.split_whitespace().collect();
                        if f.len() >= 6 && f[3] != "00:00:00:00:00:00" {
                            neighbours.push(json!({
                                "address": f[0], "mac": f[3], "device": f[5],
                            }));
                        }
                    }
                }

                Response::ok(json!({
                    "links": links,
                    "neighbours": neighbours,
                    "seen": neighbours.len(),
                }))
            }
        })
        // Domains, from a name somebody typed to a name that serves.
        //
        // State lives in a file the agent owns rather than in the deploy: a name
        // that has been added and not yet verified is a real thing to remember,
        // and the deploy only ever knew about names that were already working.
;
    let r = r
        .route("GET", "/domains", {
            move |_: &Request| {
                let list = domains_load();
                Response::ok(json!({
                    "domains": list.iter().map(|d| json!({
                        "name": d.name,
                        "step": d.step.as_str(),
                        "next": d.step.next(),
                        "site": d.site,
                        "last_check": d.last_check,
                    })).collect::<Vec<_>>(),
                    "reached_at": reachable_addresses(),
                }))
            }
        })
        .guarded("POST", "/domains/add", {
            move |req: &Request| {
                let Some(name) = req.body.get("name").and_then(|v| v.as_str()) else {
                    return Response::error(400, "`name` is required");
                };
                let name = name.trim().to_lowercase();
                if name.is_empty() || !name.contains('.') {
                    return Response::error(400, "that is not a domain name");
                }
                let mut list = domains_load();
                if list.iter().any(|d| d.name == name) {
                    return Response::refused(format!("{name} has already been added"));
                }
                list.push(furcate_deploy::domain::Domain {
                    name: name.clone(),
                    step: furcate_deploy::domain::Step::Added,
                    site: None,
                    last_check: None,
                });
                domains_save(&list);
                Response::ok(json!({ "added": name, "next": "ask for its records" }))
            }
        })
        .guarded("POST", "/domains/records", {
            move |req: &Request| {
                let Some(name) = req.body.get("name").and_then(|v| v.as_str()) else {
                    return Response::error(400, "`name` is required");
                };
                let mut list = domains_load();
                let Some(i) = list.iter().position(|d| d.name == name) else {
                    return Response::refused(format!("{name} has not been added"));
                };
                let reachable = reachable_addresses();
                let Some(at) = reachable.first().cloned() else {
                    // Refusing rather than emitting a record pointing at an
                    // address nobody outside can use. A wrong record is worse
                    // than no record: it looks finished.
                    return Response::refused(
                        "this cluster does not know an address the outside can reach it on"
                            .to_string(),
                    );
                };
                let records = furcate_deploy::domain::records(name, &at);
                // Only advances when it was waiting to; asking twice is not an
                // error and must not move anything.
                if list[i].step == furcate_deploy::domain::Step::Added {
                    if let Ok(next) = furcate_deploy::domain::advance(
                        &list[i],
                        furcate_deploy::domain::Step::RecordsIssued,
                    ) {
                        list[i] = next;
                        domains_save(&list);
                    }
                }
                Response::ok(json!({
                    "name": name,
                    "records": records.iter().map(|r| json!({
                        "kind": r.kind, "name": r.name, "value": r.value, "why": r.why,
                    })).collect::<Vec<_>>(),
                }))
            }
        })
        .guarded("POST", "/domains/verify", {
            move |req: &Request| {
                let Some(name) = req.body.get("name").and_then(|v| v.as_str()) else {
                    return Response::error(400, "`name` is required");
                };
                let mut list = domains_load();
                let Some(i) = list.iter().position(|d| d.name == name) else {
                    return Response::refused(format!("{name} has not been added"));
                };
                let resolved = resolve(name);
                let expected = reachable_addresses();
                match furcate_deploy::domain::verdict(&resolved, &expected) {
                    Ok(()) => {
                        list[i].last_check = Some(format!("resolves to {}", resolved.join(", ")));
                        if list[i].step < furcate_deploy::domain::Step::Verified {
                            list[i].step = furcate_deploy::domain::Step::Verified;
                        }
                        domains_save(&list);
                        Response::ok(json!({ "verified": name, "resolved": resolved }))
                    }
                    Err(why) => {
                        // The failure is kept. A check nobody can read is a
                        // check somebody will run again unchanged.
                        list[i].last_check = Some(why.clone());
                        domains_save(&list);
                        Response::refused(why)
                    }
                }
            }
        })
        .guarded("POST", "/domains/map", {
            move |req: &Request| {
                let (Some(name), Some(site)) = (
                    req.body.get("name").and_then(|v| v.as_str()),
                    req.body.get("site").and_then(|v| v.as_str()),
                ) else {
                    return Response::error(400, "`name` and `site` are required");
                };
                let mut list = domains_load();
                let Some(i) = list.iter().position(|d| d.name == name) else {
                    return Response::refused(format!("{name} has not been added"));
                };
                let root = std::env::var("FURCATE_DEPLOY_ROOT")
                    .unwrap_or_else(|_| "/var/lib/furcate/deploy".into());
                if !furcate_deploy::placed::placed(&root).iter().any(|p| p.name == site) {
                    return Response::refused(format!(
                        "no site called `{site}` is placed on this machine"
                    ));
                }
                match furcate_deploy::domain::advance(
                    &list[i],
                    furcate_deploy::domain::Step::Mapped,
                ) {
                    Ok(next) => {
                        list[i] = furcate_deploy::domain::Domain {
                            site: Some(site.to_string()),
                            ..next
                        };
                        domains_save(&list);
                        Response::ok(json!({ "mapped": name, "to": site }))
                    }
                    Err(why) => Response::refused(why),
                }
            }
        })
        // What tenants have been given, and what workloads may reach.
        //
        // Declared here and served by workloads elsewhere: deciding that a
        // database may exist and running the engine that holds it are different
        // jobs, and the second one belongs to placement, which already knows
        // about failure domains.
;
    let r = r
        .route("GET", "/grants", {
            move |_: &Request| {
                let grants = grants_load();
                Response::ok(json!({
                    "grants": grants.iter().map(|g| json!({
                        "tenant": g.tenant,
                        "name": g.name,
                        "shape": g.shape.as_str(),
                        "engine": format!("{:?}", g.shape.engine()).to_lowercase(),
                        "extension": g.shape.extension(),
                        "isolation": g.isolation.as_str(),
                        "caveat": g.isolation.caveat(),
                        // The claim the isolation is in service of, stated per
                        // grant so an operator never has to work it out.
                        "leaving": furcate_resource::tenancy::how_to_leave(g),
                    })).collect::<Vec<_>>(),
                }))
            }
        })
        .guarded("POST", "/grants/add", {
            move |req: &Request| {
                let g = |k: &str| req.body.get(k).and_then(|v| v.as_str()).unwrap_or_default();
                let shape = match g("shape") {
                    "relational" => furcate_resource::tenancy::Shape::Relational,
                    "vector" => furcate_resource::tenancy::Shape::Vector,
                    "time-series" | "timeseries" => furcate_resource::tenancy::Shape::TimeSeries,
                    "graph" => furcate_resource::tenancy::Shape::Graph,
                    "geospatial" => furcate_resource::tenancy::Shape::Geospatial,
                    "key-value" | "keyvalue" => furcate_resource::tenancy::Shape::KeyValue,
                    "objects" | "bucket" => furcate_resource::tenancy::Shape::Objects,
                    other => {
                        return Response::error(
                            400,
                            format!("`{other}` is not a shape; expected relational, vector, time-series, graph, geospatial, key-value or objects"),
                        )
                    }
                };
                // The strongest isolation unless something weaker is asked for
                // by name, because the weaker ones cost something an operator
                // should have to acknowledge.
                let isolation = match g("isolation") {
                    "" | "database" => furcate_resource::tenancy::Isolation::Database,
                    "schema" => furcate_resource::tenancy::Isolation::Schema,
                    "rows" => furcate_resource::tenancy::Isolation::Rows,
                    other => return Response::error(400, format!("`{other}` is not an isolation")),
                };
                let want = furcate_resource::tenancy::Grant {
                    tenant: g("tenant").to_string(),
                    name: g("name").to_string(),
                    shape,
                    isolation,
                };
                let mut have = grants_load();
                if let Err(why) = furcate_resource::tenancy::admits(&have, &want) {
                    return Response::refused(why);
                }
                have.push(want.clone());
                grants_save(&have);
                Response::ok(json!({
                    "granted": want.name,
                    "to": want.tenant,
                    "leaving": furcate_resource::tenancy::how_to_leave(&want),
                }))
            }
        })
        .route("GET", "/bindings", {
            move |_: &Request| {
                let b = bindings_load();
                Response::ok(json!({
                    "bindings": b.iter().map(|x| json!({
                        "workload": x.workload,
                        "prefix": x.prefix,
                        "need": x.need,
                        // The names only. Values are filled in where the
                        // credentials live, and this endpoint holds none.
                        "variables": furcate_resource::binding::vars(x).iter().map(|v| json!({
                            "name": v.name, "means": v.means, "secret": v.secret,
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                }))
            }
        })
        .guarded("POST", "/bindings/add", {
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                let g = |k: &str| req.body.get(k).and_then(|v| v.as_str()).unwrap_or_default();
                let need = if !g("model").is_empty() {
                    furcate_resource::binding::Need::Model {
                        model: g("model").to_string(),
                        from: match g("from") {
                            "network" => furcate_resource::binding::Inference::Network,
                            _ => furcate_resource::binding::Inference::Local,
                        },
                    }
                } else {
                    let name = g("resource").to_string();
                    let shape = grants_load()
                        .into_iter()
                        .find(|x| x.name == name)
                        .map(|x| x.shape);
                    let Some(shape) = shape else {
                        return Response::refused(format!(
                            "`{name}` has not been granted to anyone yet, so nothing can be bound to it"
                        ));
                    };
                    furcate_resource::binding::Need::Resource { name, shape }
                };
                let want = furcate_resource::binding::Binding {
                    workload: g("workload").to_string(),
                    prefix: g("prefix").to_string(),
                    need,
                };
                // Whether this machine could answer a model locally is a fact
                // about its hardware, not a preference.
                let can_serve = {
                    let a = agent.lock().expect("agent lock");
                    !a.models.is_empty()
                };
                let granted: Vec<String> = grants_load().into_iter().map(|x| x.name).collect();
                if let Err(why) = furcate_resource::binding::admits(&want, &granted, can_serve) {
                    return Response::refused(why);
                }
                let mut have = bindings_load();
                have.push(want.clone());
                bindings_save(&have);
                Response::ok(json!({
                    "bound": want.workload,
                    "variables": furcate_resource::binding::vars(&want)
                        .iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
                }))
            }
        })
;
    let r = r
        .route("GET", "/published", {
            move |_: &Request| {
                let root = std::env::var("FURCATE_DEPLOY_ROOT")
                    .unwrap_or_else(|_| "/var/lib/furcate/deploy".into());
                let sites = furcate_deploy::placed::placed(&root);
                Response::ok(json!({
                    "sites": sites.len(),
                    "placed": sites,
                }))
            }
        })
;
    let r = r
        .route("GET", "/ledger", {
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                let a = agent.lock().expect("agent lock");
                let all = a.chain.entries();
                // `?tail=N` returns the most recent N rather than the whole
                // chain. The chain only grows — a node that has been up for a
                // fortnight answers this in megabytes — so anything polling it
                // on a timer has to be able to ask for the end of it. The
                // summary fields are computed over the whole chain either way,
                // because a truncated view must not be able to report a length
                // or a verification result that is only true of the excerpt.
                let entries = match req.query_param("tail").and_then(|t| t.parse::<usize>().ok()) {
                    Some(n) if n < all.len() => &all[all.len() - n..],
                    _ => all,
                };
                Response::ok(json!({
                    "length": a.chain.len(),
                    "head": a.chain.head().map(hex::encode),
                    "verified": a.chain.verify().is_ok(),
                    "returned": entries.len(),
                    "entries": entries,
                }))
            }
        })
        // Commit a service mutation to the chain.
        //
        // Provisioning a tenant database or a mail identity is an action on this
        // machine. Until now those went into a private journal that verified
        // against itself and nothing else — a local hash chain proves only that
        // its own file was not edited, and says nothing about the node it claims
        // to describe.
        //
        // Guarded, so the caller must present a credential this machine
        // recognises. The verifier accepts the operator key, then machines, then
        // agents; a local service signs as the machine, which is the honest
        // authority for "this machine created a database". Deliberately not the
        // operator key — that one arms the kill switch, and routine provisioning
        // must not need it.
        //
        // The kind is fixed to Provision and cannot be chosen by the caller. The
        // kinds this chain exists to protect — Quote, KeyUse, Seal, PolicyChange
        // — are precisely the ones worth forging, so a caller that may record "I
        // created a database" must not thereby be able to record "a quote was
        // produced over platform state".
        .guarded("POST", "/ledger", {
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                let actor = req.body.get("actor").and_then(|v| v.as_str()).unwrap_or("");
                let subject = req.body.get("subject").and_then(|v| v.as_str()).unwrap_or("");
                let result = req.body.get("result").and_then(|v| v.as_str()).unwrap_or("");
                if actor.is_empty() || subject.is_empty() || result.is_empty() {
                    return Response::error(
                        400,
                        "actor, subject and result are all required".to_string(),
                    );
                }
                if actor.len() > 128 || subject.len() > 256 || result.len() > 512 {
                    return Response::error(400, "field too long".to_string());
                }
                let mut a = agent.lock().expect("agent lock");
                let hash = a.chain.append(now_ms(), OpKind::Provision, actor, subject, result);
                let seq = a.chain.len() - 1;
                // Without this the entry lives only in memory and is gone at the
                // next restart, which is the one property a tamper-evident record
                // must not have.
                a.persist_chain();
                drop(a);
                Response::ok(json!({
                    "committed": true,
                    "kind": "provision",
                    "hash": hex::encode(hash),
                    "seq": seq,
                }))
            }
        })
        // Ask this site for an SSH certificate.
        //
        // The CA is sealed to this machine's TPM, so signing can only happen here.
        // Exposing it as a route means an operator or an agent elsewhere on the
        // overlay can obtain scoped, expiring access without the private key ever
        // leaving the box — and without anyone hand-editing authorized_keys, which
        // is the practice this replaces.
        //
        // Guarded: the caller presents a credential this machine recognises.
        // Unauthenticated certificate issuance would be a key-signing oracle.
        //
        // Delegates to furcate-ssh, which owns policy, serial allocation, the
        // revocation list and the ledger record. Duplicating any of that here would
        // mean two implementations of the same rules, and they would drift.
        .guarded("POST", "/ssh/cert", {
            move |req: &Request| {
                let user = req.body.get("user").and_then(|v| v.as_str()).unwrap_or("");
                let host = req.body.get("host").and_then(|v| v.as_str()).unwrap_or("");
                let ttl = req.body.get("ttl").and_then(|v| v.as_str()).unwrap_or("1h");
                let pubkey = req.body.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
                if user.is_empty() || host.is_empty() || pubkey.is_empty() {
                    return Response::error(
                        400,
                        "user, host and public_key are all required".to_string(),
                    );
                }
                // Reject anything that is not a plausible single-line SSH public key
                // before it reaches a file or a subprocess argument.
                if pubkey.len() > 1024 || pubkey.contains('\n') || !pubkey.starts_with("ssh-") {
                    return Response::error(400, "public_key must be one line of OpenSSH key text".to_string());
                }
                if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
                    || !ttl.chars().all(|c| c.is_ascii_alphanumeric())
                {
                    return Response::error(400, "user, host or ttl contains characters that are not allowed".to_string());
                }

                let Ok(dir) = private_dir(&std::env::temp_dir(), "furcate-ssh-req") else {
                    return Response::error(500, "could not stage the request".to_string());
                };
                let keypath = dir.join("k");
                if std::fs::write(keypath.with_extension("pub"), format!("{pubkey}\n")).is_err() {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Response::error(500, "could not stage the public key".to_string());
                }

                let out = std::process::Command::new("/opt/ops/bin/furcate-ssh")
                    .args(["issue", user, host, "--ttl", ttl, "--key"])
                    .arg(&keypath)
                    .output();
                let cert = std::fs::read_to_string(dir.join("k-cert.pub")).unwrap_or_default();
                let _ = std::fs::remove_dir_all(&dir);

                match out {
                    Ok(o) if o.status.success() && !cert.trim().is_empty() => Response::ok(json!({
                        "certificate": cert.trim(),
                        "detail": String::from_utf8_lossy(&o.stdout).trim(),
                    })),
                    Ok(o) => Response::error(
                        403,
                        format!(
                            "{}{}",
                            String::from_utf8_lossy(&o.stderr).trim(),
                            String::from_utf8_lossy(&o.stdout).trim()
                        ),
                    ),
                    Err(e) => Response::error(500, format!("could not run furcate-ssh: {e}")),
                }
            }
        })
        .route("GET", "/members", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                let members: Vec<_> = a
                    .membership
                    .members()
                    .map(|m| {
                        json!({
                            "id": m.id,
                            "state": format!("{:?}", m.state).to_lowercase(),
                            "incarnation": m.incarnation,
                        })
                    })
                    .collect();
                Response::ok(json!({ "members": members, "alive": a.membership.alive().len() }))
            }
        })
        .route("GET", "/lldp", {
            move |_: &Request| {
                // Discovered rather than declared: which switch port this
                // machine is actually plugged into.
                let neighbours = furcate_topology::lldp::discover();
                Response::ok(json!({
                    "neighbours": neighbours,
                    "count": neighbours.len(),
                    "note": if neighbours.is_empty() {
                        "no LLDP neighbours seen; the switch may not advertise, in which case network topology stays declared"
                    } else {
                        "physical uplink discovered"
                    },
                }))
            }
        })
        .route("GET", "/power", {
            move |_: &Request| {
                let reading = power::read();
                Response::ok(serde_json::to_value(&reading).unwrap_or(json!({})))
            }
        })
        // Every timer in this process, and how it is doing. The reason this
        // exists: a task that has been failing for a week used to look exactly
        // like one that had nothing to do.
        .route("GET", "/scheduler", {
            let sched = sched.clone();
            move |_: &Request| {
                let tasks = furcate_sched::snapshot(&sched);
                let stalled = furcate_sched::stalled(&sched);
                Response::ok(json!({
                    "tasks": tasks,
                    "stalled": stalled,
                    "note": "last_success is the field that matters — a task \
                             failing every minute has a very recent last_run.",
                }))
            }
        })
        .guarded("POST", "/thermal", {
            let agent = Arc::clone(&agent);
            // The same authority file the overlay and the restart route are
            // ruled against, loaded once at start. A site has one place where
            // authority is written rather than one per feature.
            //
            // The action is `tune`, which already exists and which
            // the agent surface already uses for exactly this — changing a power
            // lever. A new action name here would have meant two words for one
            // capability, and a grant written with one of them would silently
            // not cover the other.
            let policy = policyfile::load();
            move |req: &Request| {
                let Some(who) = req.principal.as_ref() else {
                    return Response::refused("this route requires a proved caller");
                };
                let principal = who.id.as_str();
                let node = std::env::var("FURCATE_NODE_NAME")
                    .unwrap_or_else(|_| "this".to_string());

                let request = furcate_policy::Request {
                    principal: principal.to_string(),
                    action: "tune".into(),
                    resource: format!("node:{node}"),
                    // From whoever proved the caller, never from the body — a
                    // caller that could name its own roles would be deciding
                    // what it is allowed to do.
                    roles: who.roles.clone(),
                };
                let decision = policy.evaluate(&request, now_s());

                let mut current = bmc::declared();
                let asked = req.body.clone();
                if let Some(p) = asked.get("placement").and_then(|v| v.as_str()) {
                    current.acoustics.placement = match p {
                        "living_space" => furcate_host::acoustics::Placement::LivingSpace,
                        "shared_space" => furcate_host::acoustics::Placement::SharedSpace,
                        "machine_room" => furcate_host::acoustics::Placement::MachineRoom,
                        other => {
                            return Response::error(
                                400,
                                format!(
                                    "`{other}` is not a placement; expected machine_room, \
                                     shared_space or living_space"
                                ),
                            )
                        }
                    };
                }
                if let Some(q) = asked.get("quiet_hours").and_then(|v| v.as_str()) {
                    if q.is_empty() {
                        current.acoustics.quiet_hours = None;
                    } else {
                        let Some((a, b)) = q.split_once('-') else {
                            return Response::error(400, "`quiet_hours` looks like `22-7`");
                        };
                        let (Ok(from), Ok(to)) =
                            (a.trim().parse::<u8>(), b.trim().parse::<u8>())
                        else {
                            return Response::error(400, "`quiet_hours` looks like `22-7`");
                        };
                        if from > 23 || to > 23 {
                            return Response::error(400, "hours are 0-23");
                        }
                        current.acoustics.quiet_hours =
                            Some(furcate_host::acoustics::QuietHours { from, to });
                    }
                }
                if let Some(b) = asked.get("builds").and_then(|v| v.as_str()) {
                    current.acoustics.builds = match b {
                        "narrow" => furcate_host::acoustics::Builds::Narrow,
                        "refuse" => furcate_host::acoustics::Builds::Refuse,
                        other => {
                            return Response::error(
                                400,
                                format!("`{other}` is not a build posture; expected narrow or refuse"),
                            )
                        }
                    };
                }
                if let Some(e) = asked.get("envelope").and_then(|v| v.as_str()) {
                    current.quiet = match e.trim() {
                        "full" => furcate_host::thermal::Envelope::Full,
                        v => {
                            if let Some(w) = v.strip_suffix(['W', 'w']) {
                                match w.trim().parse::<u32>() {
                                    Ok(watts) => {
                                        furcate_host::thermal::Envelope::WattsPerPackage { watts }
                                    }
                                    Err(_) => {
                                        return Response::error(
                                            400,
                                            "`envelope` is `full`, a fraction like `0.6`, or \
                                             watts per package like `90W`",
                                        )
                                    }
                                }
                            } else {
                                match v.parse::<f64>() {
                                    Ok(f) if (0.0..=1.0).contains(&f) => {
                                        furcate_host::thermal::Envelope::Fraction {
                                            of_maximum: f,
                                        }
                                    }
                                    _ => {
                                        return Response::error(
                                            400,
                                            "`envelope` is `full`, a fraction like `0.6`, or \
                                             watts per package like `90W`",
                                        )
                                    }
                                }
                            }
                        }
                    };
                }

                let mut a = agent.lock().expect("agent lock");
                // Chained with how the caller proved itself rather than only
                // what it was called: a record naming "operator" says nothing
                // about whether anyone checked.
                a.chain.append(
                    now_ms(),
                    OpKind::Power,
                    format!("{principal} via {}", who.evidence.as_str()),
                    format!("tune node:{node}"),
                    if decision.allowed { "permitted" } else { "refused" },
                );
                a.persist_chain();
                drop(a);

                if !decision.allowed {
                    return Response::refused(format!(
                        "policy refuses `tune` on node:{node} for {principal}: {}",
                        decision.because
                    ));
                }

                match bmc::write_declared(&current) {
                    Ok(()) => Response::ok(json!({
                        "declared": current,
                        "note": "recorded. It takes effect on the next pass; nothing is \
                                 throttled unless the machine is actually disturbing \
                                 somebody and its fans are working without heat to \
                                 justify them.",
                    })),
                    Err(e) => Response::error(500, format!("cannot record it: {e}")),
                }
            }
        })
        .route("GET", "/thermal", {
            move |_: &Request| {
                use furcate_host::thermal;
                let levers = thermal::probe();
                let b = bmc::collect();
                let declared = bmc::declared();
                let acoustics = declared.acoustics;
                let hour = bmc::local_hour(&host::clock());
                // One judgement, carrying the sentence that explains it. An
                // operator looking at a throttled machine needs to know which
                // rule put it there.
                let (envelope, because) = declared.in_force(hour, &b.faults);
                Response::ok(json!({
                    "levers": levers.found,
                    "absent": levers.absent,
                    "acoustics": acoustics,
                    "local_hour": hour,
                    "disturbing": hour.map(|h| acoustics.disturbing(h)),
                    // What the declaration says about starting a build now. An
                    // unknown hour reads as night here, deliberately; see
                    // `Acoustics::builds_at`.
                    "builds": acoustics.builds_at(hour),
                    "envelope": envelope,
                    "because": because,
                    "quiet_envelope": declared.quiet,
                    // The writes this envelope implies, shown before anything
                    // is asked for. An operator who can read the plan can
                    // refuse it, which is the whole reason planning and
                    // applying are separate.
                    "plan": thermal::plan(&levers, envelope),
                    "note": "Bounding draw, not driving fans. If the process \
                             holding a power cap dies the cap stays and the \
                             machine runs slower and cooler; if software \
                             holding a fan speed dies the fans stay where it \
                             left them and a monitoring outage becomes a \
                             thermal one. That asymmetry is why one is \
                             actuated here and the other is not.",
                }))
            }
        })
        .route("GET", "/cooling", {
            move |_: &Request| {
                let b = bmc::collect();
                Response::ok(json!({
                    "present": b.present,
                    "readable": b.readable,
                    "fans": b.cooling.fans,
                    "temperatures": b.cooling.temperatures,
                    "blind_sensors": b.cooling.blind,
                    "faults": b.faults,
                    "fan_watts_estimated": b.fan_watts_estimated,
                    // Measured at the chassis boundary by the power supply, so
                    // the fans' share of this machine's draw is a ratio of two
                    // measured figures rather than one measured and one
                    // declared. The declared multiplier was wrong here by
                    // between four and nine times, which is why absent is
                    // reported as absent and never filled in with a model.
                    "wall_w": b.wall.map(|w| w.input_watts),
                    "thermal_rung": b.thermal_rung,
                    "hottest": b.hottest,
                    "note": "Fan speed is read-only here. It is defined in \
                             firmware, and taking manual control would leave the \
                             fans wherever software last set them if that \
                             software died. Heat drives the ladder as far as \
                             draining and never to a halt — the controller cuts \
                             power at its own critical threshold, faster and \
                             without needing an operating system. \
                             A loud machine is not therefore untreatable: see \
                             /thermal, which bounds what the machine may draw. \
                             Controllers of this class lead their fans on \
                             package power, so drawing less is how a machine \
                             gets quieter without anyone overriding its fans.",
                }))
            }
        })
        .route("GET", "/custody", {
            move |_: &Request| {
                let c = custody::collect();
                Response::ok(json!({
                    "kernel_events": c.events,
                    // The same window, read for the codes the accelerator
                    // driver emits. One entry per card, worst card first.
                    "accelerator_faults": c.xids.iter().map(|(pci, f)| json!({
                        "pci": pci,
                        "code": f.class.code,
                        "blame": f.class.blame.as_str(),
                        "remedy": f.class.remedy.as_str(),
                        "contained": f.class.contained,
                        "summary": f.class.summary,
                        "seen": f.repeats,
                        "events_in_window": f.total,
                    })).collect::<Vec<_>>(),
                    "journal_readable": c.journal_readable,
                    "journal_bytes": c.journal_bytes,
                    "journal_large": c.journal_large,
                    "backups": c.backups,
                    "config_drift": c.drift,
                    "watched_files": c.watched,
                    "note": "kernel log only — application logs are somebody \
                             else's vocabulary. A backup verdict describes a \
                             file, never that it would restore.",
                }))
            }
        })
        .route("GET", "/host", {
            move |_: &Request| {
                let h = host::collect();
                Response::ok(json!({
                    // Device health, which is a different question from mount
                    // capacity: a disk can fill up or it can die, and only the
                    // first used to be watched. A count that moved matters more
                    // than a count that is merely large, so each device carries
                    // its verdict rather than only its numbers.
                    "devices": h.devices.iter().map(|d| json!({
                        "device": d,
                        "verdict": furcate_host::storage::assess(d, None),
                    })).collect::<Vec<_>>(),
                    "devices_readable": h.devices_readable,
                    // The same question asked of the accelerators. A card that
                    // is out of memory is the case this was built for: it is
                    // healthy, it is not failing, and it must stop receiving
                    // work before the driver's out-of-memory takes the host.
                    "accelerators": h.accelerators.iter().map(|a| {
                        let v = furcate_host::accelerator::assess(a, None);
                        json!({
                            "device": a,
                            "verdict": v,
                            "should_drain": v.should_drain(),
                            "implicates_the_card": v.implicates_the_card(),
                        })
                    }).collect::<Vec<_>>(),
                    "accelerators_readable": h.accelerators_readable,
                    // Present only when something published it. Absent means
                    // nothing read the counters, which is not the same as a
                    // machine with no errors.
                    "platform": h.platform,
                    "mounts": h.mounts,
                    "trends": h.trends,
                    "concerns": h.concerns,
                    "clock": h.clock,
                    "reboot": h.reboot,
                    "build": h.build,
                    "settled": h.settled,
                    "note": "capacity is reported as time-to-full rather than a \
                             percentage: a mount at 60% filling in three days \
                             matters more than one that has sat at 92% for a year.",
                }))
            }
        })
        .route("GET", "/resources", {
            move |_: &Request| {
                let r = resources::collect();
                // Right-sizing advice comes from the registered extension; the
                // key stays either way so a client sees "no advice" rather than
                // a field that vanished.
                let recs = extension::get().recommendations(&r.groups).unwrap_or_else(|| json!([]));
                Response::ok(json!({
                    "pressure": r.psi,
                    "worst": r.worst,
                    "can_take_more": r.can_take_more,
                    "contention": r.psi.map(|p| resources::contention(&p)),
                    "groups": r.groups,
                    "recommendations": recs,
                    "partial": r.partial,
                    "note": "pressure is stall time, not utilisation: a machine at \
                             full load with nothing queued is fine, one at half \
                             load with tasks stalled is not. Recommendations are \
                             printed, never applied.",
                }))
            }
        })
        .route("GET", "/network", {
            move |_: &Request| {
                let n = network::collect();
                Response::ok(json!({
                    "primary": n.primary,
                    "diagnosis": n.diagnosis,
                    "faults": n.faults,
                    "throughput": n.delta.as_ref().map(|d| json!({
                        "rx_mbps": d.rx_mbps(),
                        "tx_mbps": d.tx_mbps(),
                        "interval_ms": d.interval_ms,
                    })),
                    "quality": n.quality,
                    "reach": n.reach.probes,
                    "advice": n.quality.as_ref().map(|q| q.advice()),
                    "links": n.links.iter().filter(|l| l.kind != furcate_net::LinkKind::Virtual)
                        .collect::<Vec<_>>(),
                    "note": "counters and small probes only; nothing here saturates \
                             the link to measure it, because the link is carrying \
                             production traffic",
                }))
            }
        })
        .route("GET", "/workloads", {
            move |_: &Request| {
                let inv = workloads::collect();
                Response::ok(json!({
                    "workloads": inv.workloads,
                    "degraded": inv.degraded().len(),
                    "critical_degraded": inv.critical_degraded().len(),
                    "partial": inv.partial,
                    "note": "read-only; systemd and docker supervise what they own. \
                             A container's `healthy` is its own opinion of itself.",
                }))
            }
        })
        // What this installation is, so a console can offer what will work.
        //
        // Every other endpoint answers "what is this machine doing". This one
        // answers "what is this machine able to be asked", which a user
        // interface needs before it draws anything: a screen that offers fleet
        // policy against a node with no controller is offering a button that
        // returns 404, and the person pressing it learns the product is broken
        // rather than what this build is.
        //
        // Two separate facts, deliberately not merged: what this build is,
        // as the edition reports it, and what this hardware can do, which no
        // build changes. Collapsing them would make "this build cannot do
        // this" and "this machine has no GPU" indistinguishable, and those
        // have different remedies.
        //
        // Open, because a console has to ask this before it can sign anything,
        // and because none of it is a secret.
        .route("GET", "/features", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                let mut report = extension::get().features();
                if let Some(obj) = report.as_object_mut() {
                    // What this hardware adds or withholds regardless of any of
                    // the above. An accelerator panel on a machine with no
                    // accelerator is the same mistake as a fleet panel on a
                    // node with no fleet.
                    obj.insert(
                        "machine".to_string(),
                        json!({
                            "tier": a.capability.tier().as_str(),
                            "accelerated": a.capability.vram_mb > 0,
                            "attested": a.capability.attested,
                            "cpu_cores": a.capability.cpu_cores,
                            "ram_mb": a.capability.ram_mb,
                            "vram_mb": a.capability.vram_mb,
                        }),
                    );
                    // Where the fleet half lives, if this node was told. A
                    // console asks the node it can reach and is pointed at the
                    // controller, rather than being configured twice.
                    obj.insert(
                        "site".to_string(),
                        match std::env::var("FURCATE_SITE") {
                            Ok(v) if !v.trim().is_empty() => json!(v),
                            _ => serde_json::Value::Null,
                        },
                    );
                }
                Response::ok(report)
            }
        })
        .route("GET", "/capability", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                Response::ok(json!({
                    "capability": a.capability,
                    "tier": a.capability.tier().as_str(),
                    "model_memory_mb": a.capability.model_memory_mb(),
                }))
            }
        })
        .route("GET", "/sensors", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                let stale = a.sensors.stale(&a.last_seen, now_s(), 3);
                Response::ok(json!({
                    "count": a.sensors.len(),
                    "stale": stale.iter().map(|s| &s.id).collect::<Vec<_>>(),
                    "sensors": a.sensors.of_kind(SensorKind::Temperature)
                        .iter().map(|s| &s.id).collect::<Vec<_>>(),
                }))
            }
        })
        .route("GET", "/sensors/read", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let ids: Vec<String> = {
                    let a = agent.lock().expect("agent lock");
                    a.sensors.of_kind(SensorKind::Temperature).iter().map(|s| s.id.clone()).collect()
                };
                let readings: Vec<_> = ids
                    .iter()
                    .filter_map(|id| {
                        let zone = id.rsplit('/').next()?;
                        let raw = std::fs::read_to_string(format!("/sys/class/thermal/{zone}/temp")).ok()?;
                        let milli: i64 = raw.trim().parse().ok()?;
                        Some(json!({ "id": id, "celsius": milli as f64 / 1000.0 }))
                    })
                    .collect();
                Response::ok(json!({ "readings": readings }))
            }
        })
        .route("POST", "/sensors/register", {
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                let (Some(id), Some(host)) = (
                    req.body.get("id").and_then(|v| v.as_str()),
                    req.body.get("host").and_then(|v| v.as_str()),
                ) else {
                    return Response::error(400, "`id` and `host` are required");
                };
                let mut a = agent.lock().expect("agent lock");
                a.sensors.register(Sensor {
                    id: id.to_string(),
                    kind: SensorKind::Temperature,
                    unit: furcate_sense::Unit::Celsius,
                    host: host.to_string(),
                    domain: None,
                    interval_s: req.body.get("interval_s").and_then(|v| v.as_u64()).unwrap_or(10),
                });
                a.last_seen.insert(id.to_string(), now_s());
                Response::ok(json!({ "registered": id, "count": a.sensors.len() }))
            }
        })
        .route("POST", "/health/signal", {
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                let kind = match req.body.get("kind").and_then(|v| v.as_str()) {
                    Some("unreachable") => SignalKind::Unreachable,
                    Some("attestation_drift") => SignalKind::AttestationDrift {
                        register: req.body.get("register").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    },
                    Some("disk") => SignalKind::DiskDegraded {
                        device: req.body.get("device").and_then(|v| v.as_str()).unwrap_or("unknown").into(),
                        reallocated: req.body.get("reallocated").and_then(|v| v.as_u64()).unwrap_or(0),
                    },
                    Some("thermal") => SignalKind::Thermal {
                        sensor: req.body.get("sensor").and_then(|v| v.as_str()).unwrap_or("cpu").into(),
                        celsius: req.body.get("celsius").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32,
                    },
                    _ => return Response::error(400, "`kind` must be unreachable, attestation_drift, disk or thermal"),
                };
                let mut a = agent.lock().expect("agent lock");
                let node = a.node_id.clone();
                let signal = Signal::new(node, kind, now_s());
                let severity = signal.severity;
                let playbook = Remediator::for_signal(&signal);
                let outcome = a.observe_signal(signal);
                Response::ok(json!({
                    "severity": format!("{severity:?}").to_lowercase(),
                    "outcome": outcome,
                    "state": a.lifecycle.state().as_str(),
                    "remediation_attempts_allowed": playbook.attempts(),
                }))
            }
        })
        .route("GET", "/bringup", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                let blocked: Vec<_> = a
                    .bringup
                    .blocked()
                    .into_iter()
                    .map(|(unit, gates)| json!({ "unit": unit, "waiting_on": format!("{gates:?}") }))
                    .collect();
                Response::ok(json!({
                    "started": a.bringup.started().iter().collect::<Vec<_>>(),
                    "blocked": blocked,
                }))
            }
        })
        .route("GET", "/models", {
            let agent = Arc::clone(&agent);
            move |_: &Request| {
                let a = agent.lock().expect("agent lock");
                let models: Vec<_> = a
                    .models
                    .values()
                    .map(|m| json!({ "id": m.id, "digest": m.digest, "endpoint": m.endpoint,
                                      "reachable": runtime::reachable(&m.endpoint) }))
                    .collect();
                Response::ok(json!({ "models": models }))
            }
        })
        .route("GET", "/receipt-key", {
            let signing = signing.clone();
            move |_: &Request| match &signing {
                Some(k) => Response::ok(json!({
                    "public_key": hex::encode(k.verifying_key().to_bytes()),
                    "sealed_to_tpm": true,
                })),
                None => Response::ok(json!({ "public_key": null, "sealed_to_tpm": false })),
            }
        })
        .route("POST", "/infer", {
            let agent = Arc::clone(&agent);
            let signing = signing.clone();
            move |req: &Request| {
                let Some(model) = req.body.get("model").and_then(|v| v.as_str()) else {
                    return Response::error(400, "`model` is required");
                };
                let input = req.body.get("input").and_then(|v| v.as_str()).unwrap_or("");
                let max_tokens = req.body.get("max_tokens").and_then(|v| v.as_u64()).unwrap_or(64) as u32;

                let (loaded, node_id, head, accepts) = {
                    let a = agent.lock().expect("agent lock");
                    (
                        a.models.get(model).cloned(),
                        a.node_id.clone(),
                        a.chain.head().map(hex::encode).unwrap_or_default(),
                        a.lifecycle.state().accepts_work(),
                    )
                };
                if !accepts {
                    return Response::refused("this node is not accepting work");
                }
                let Some(loaded) = loaded else {
                    return Response::error(404, format!("no model `{model}` is loaded on this node"));
                };

                // Run outside the lock: a completion can take many seconds and
                // holding the agent lock would stall power observation.
                match runtime::complete_as(&loaded.endpoint, Some(model), input, max_tokens) {
                    Ok(output) => {
                        let mut a = agent.lock().expect("agent lock");
                        let receipt = InferenceReceipt::new(
                            loaded.digest.clone(),
                            "llama.cpp",
                            node_id,
                            input.as_bytes(),
                            output.as_bytes(),
                            format!("max_tokens={max_tokens};temperature=0"),
                            head,
                            VerificationLevel::Bound,
                        );
                        let receipt = match &signing {
                            Some(k) => receipt.sign(k),
                            None => receipt,
                        };
                        a.chain.append(now_ms(), OpKind::Inference, "api", model, &receipt.output_digest[..16]);
                        a.persist_chain();
                        Response::ok(json!({
                            "output": output,
                            "receipt": receipt,
                            "proves": "binding: this model, this runtime, this node, these inputs. Not that the computation was correct.",
                        }))
                    }
                    Err(e) => Response::error(502, format!("{e}")),
                }
            }
        })
        // What this machine is, and whether it still matches what was recorded.
        //
        // The baseline is the difference between a machine that is merely
        // observed and one that is defined. Recording it costs nothing and
        // turns a package-based host from `unmanaged` into `pinned` — not a new
        // operating system, just something that wrote down what the current one
        // looked like so a change becomes visible.
        // This node's place in the overlay.
        //
        // The peer set here is resolved locally: hints from the controller are
        // information, and what turns one into a peer is this node's own
        // policy. A coordinator that stops answering costs discovery and never
        // connectivity — `retained` is the count of peers that prove it.
        // May a certificate be obtained for this name?
        //
        // Asked by the edge during a TLS handshake, before it will request
        // anything from a certificate authority. It lives on the **node**
        // rather than the controller because the question is "does *this*
        // machine serve that name", and only this machine knows: the release,
        // the symlink and the edge are all local. Asking the controller
        // answers a different question and refuses names that are genuinely
        // served — a refusal indistinguishable from the one that stops abuse.
;
    // The agent card routes, answered by the registered extension.
    //
    // Unauthenticated on purpose, and safe because a card is DISCOVERY, NOT
    // AUTHORITY. It says asking is worthwhile; it grants nothing. Every request
    // it might lead to still arrives at a guarded route and is still checked
    // against the policy engine by a principal that had to prove itself. What
    // it discloses is this node's id, tier and the fixed set of things it does
    // -- the same facts /identity and /hardware already give anyone who can
    // reach the port.
    //
    // WARNING: OUTWARD ONLY. Nothing here parses an inbound agent request or
    // accepts a skill string.
    let r = model_load_route(r, Arc::clone(&agent));
    let r = ["/.well-known/agent-card.json", "/.well-known/agent.json"]
        .into_iter()
        .fold(r, |r, path| {
            let agent = Arc::clone(&agent);
            let listen = listen_addr.clone();
            r.route("GET", path, move |_: &Request| {
                let facts = agent.lock().expect("agent lock").facts();
                match extension::get().agent_card(&facts, &listen) {
                    Some(card) => Response::ok(card),
                    None => Response::error(404, "this node does not publish an agent card"),
                }
            })
        });

    let r = r
        .route("GET", "/tls/allow", {
            move |req: &Request| {
                let Some(domain) = req.query_param("domain") else {
                    return Response::error(400, "ask for one `domain`");
                };
                let root = std::env::var("FURCATE_DEPLOY_ROOT")
                    .unwrap_or_else(|_| "/var/lib/furcate/deploy".into());
                // Verification first. An unverified name refused here says so
                // with a reason; the same name refused by a certificate
                // authority arrives as a rate limit that also blocks the names
                // that were fine.
                let known = domains_load();
                if let Some(d) = known.iter().find(|d| d.name == domain) {
                    if let Err(why) = furcate_deploy::domain::may_have_certificate(d) {
                        return Response::refused(why);
                    }
                }
                if furcate_deploy::placed::serves(&root, &domain) {
                    Response::ok(serde_json::json!({ "domain": domain, "serve": true }))
                } else {
                    Response::refused(format!("no site placed on this machine answers on `{domain}`"))
                }
            }
        })
;
    let mut r = r
        .route("GET", "/overlay", {
            move |_: &Request| {
                // Observation only. Reconciling here would rewrite the plan and
                // the held peers, and would report every peer as retained
                // because a read supplies no hints — which is exactly the state
                // an operator checking this endpoint would be looking for.
                let state = overlay::status();
                Response::ok(json!({
                    "public_key": state.public_key,
                    "interface": state.interface,
                    "address": state.address,
                    "peers": state.peers,
                    "retained": state.retained,
                    "last_handshake_secs": state.last_handshake_secs,
                    "available": state.available,
                    "why_unavailable": state.why_unavailable,
                    "exposure": state.exposure,
                    "post_quantum_warranted": state.exposure.warrants_post_quantum(),
                    "note": "the coordinator supplies where peers are; this node decides \
                             whether they may speak. Peers already held are never dropped \
                             for want of a hint — losing the coordinator degrades discovery, \
                             not connectivity.",
                }))
            }
        })
        .route("POST", "/overlay/hints", {
            let agent_h = Arc::clone(&agent);
            let me_h = node_id.clone();
            move |req: &Request| {
                let hints: Vec<furcate_net::overlay::Hint> = req
                    .body
                    .get("hints")
                    .and_then(|h| serde_json::from_value(h.clone()).ok())
                    .unwrap_or_default();
                let gossip = {
                    let a = agent_h.lock().expect("agent lock");
                    overlay::gossip_hints(&a.membership, &me_h, now_s())
                };
                let hints = furcate_net::overlay::merge(&hints, &gossip);
                let addr = overlay_addr();

                // Local admission, by the same engine and the same rules the
                // scheduled loop uses. Deliberately not delegated to whoever
                // sent the hints: this is the line the whole design is drawn
                // along, and it would be an odd place to have two answers.
                let policy = overlay::load_policy();
                let now = now_s();
                let anchors = match overlay::anchors() {
                    Ok(a) => a,
                    Err(e) => return Response::ok(json!({"available": false, "why": e})),
                };
                let state = anchors.state();
                let r = overlay::reconcile(&hints, &addr, now, |h| {
                    overlay::admits(&policy, &anchors, "", h, now)
                });
                Response::ok(json!({
                    "peers": r.peers.len(),
                    "retained": r.retained,
                    "refused": r.refused,
                    "public_key": r.public_key,
                    "available": r.available,
                    // Reported alongside the peers, because "two peers" means
                    // something different depending on who was allowed to say
                    // they belong here.
                    "lock": state,
                    "lock_note": state.describe(),
                    // This machine's own standing, which is the half an
                    // operator cannot infer from the peer count: an expiry
                    // takes effect without anybody doing anything, and the
                    // symptom is an overlay that quietly got smaller.
                    "authorization": overlay::self_standing(now),
                    "authorization_note": overlay::self_standing(now).map(|s| s.describe()),
                }))
            }
        })
        .route("GET", "/image", {
            move |_: &Request| {
                let (baseline, at) = load_baseline();
                let r = image::collect(baseline.as_ref(), at);
                Response::ok(json!({
                    "image": r.image,
                    "assurance": r.image.assurance.as_str(),
                    "next_step": r.image.assurance.next_step(),
                    "drift": r.drift,
                    "boot_coverage": r.boot_coverage,
                    "firmware": r.firmware,
                    "firmware_age": r.firmware_age,
                    "note": "assurance is what a comparison would CATCH, not what the machine \
                             says about itself. Only a measured boot detects a swapped kernel; \
                             below that the identity is self-reported however precise it looks.",
                }))
            }
        })
        .guarded("POST", "/image/baseline", {
            move |_: &Request| {
                let r = image::collect(None, 0);
                match save_baseline(&r.image) {
                    Ok(at) => Response::ok(json!({
                        "recorded": r.image,
                        "at": at,
                        "assurance_now": "pinned",
                        "note": "drift is measured against this from now on. Re-record after a \
                                 deliberate change, or every subsequent upgrade reads as drift \
                                 and the signal stops meaning anything.",
                    })),
                    Err(e) => Response::error(500, format!("{e}")),
                }
            }
        })
        .guarded("POST", "/intent", {
            let agent = Arc::clone(&agent);
            move |req: &Request| {
                let Some(intent) = req.body.get("intent").and_then(|v| v.as_str()) else {
                    return Response::error(400, "`intent` is required");
                };
                let mut a = agent.lock().expect("agent lock");
                a.last_intent = Some(intent.to_string());
                a.controller_seen_at = Some(now_ms());

                // Apply the ones that name a lifecycle change.
                //
                // This route recorded an intent and did nothing with it: a
                // `drain` was accepted, written to the chain, and the node went
                // on taking work. An endpoint that answers "accepted" to a
                // request it does not carry out is worse than one that refuses,
                // because the caller has no way to tell.
                //
                // `cordon` is the honest name for what drain means here --
                // removed from scheduling, existing work untouched -- and the
                // lifecycle machine already refuses transitions that do not
                // make sense from where it is.
                let applied = match intent {
                    "drain" | "cordon" => Some(furcate_health::lifecycle::Transition::Cordon),
                    "undrain" | "restore" => Some(furcate_health::lifecycle::Transition::Restore),
                    _ => None,
                };
                let outcome = match applied {
                    Some(t) => match a.lifecycle.apply(t) {
                        Ok(state) => Some(Ok(state)),
                        Err(e) => Some(Err(e)),
                    },
                    None => None,
                };

                match outcome {
                    Some(Err(e)) => {
                        // Refused by the lifecycle machine, and said so. An
                        // intent that cannot be applied from this state is not
                        // an accepted one.
                        a.chain.append(now_ms(), OpKind::Lifecycle, "site", intent, "refused");
                        a.persist_chain();
                        Response::error(409, format!("{intent} cannot be applied here: {e:?}"))
                    }
                    Some(Ok(state)) => {
                        a.chain.append(now_ms(), OpKind::Lifecycle, "site", intent, state.as_str());
                        a.persist_chain();
                        Response::ok(json!({
                            "accepted": intent,
                            "state": state.as_str(),
                            "accepts_work": state.accepts_work(),
                        }))
                    }
                    None => {
                        // Recorded, as before: an intent this node has no
                        // transition for is a note for whoever reads the chain.
                        a.chain.append(now_ms(), OpKind::Lifecycle, "site", intent, "recorded");
                        a.persist_chain();
                        Response::ok(json!({
                            "accepted": intent,
                            "note": "recorded; this node has no lifecycle transition for that name",
                        }))
                    }
                }
            }
        })
        // Restart one workload, on an operator's explicit instruction.
        //
        // Every part of the safety argument is here in one place: the policy
        // engine rules first and a refusal ends it; an automatic principal is
        // barred structurally whatever the policy file says; the id is checked
        // before it becomes an argument on the privileged side; and the
        // decision is chained whether it was permitted or refused, because a
        // record of only the permitted ones is a record of what somebody
        // thought was worth keeping.
        //
        // Restart and nothing else. There is no stop and no remove: a lever
        // that can only put something back cannot be used to take a site apart.
        .guarded("POST", "/workloads/restart", {
            let agent = Arc::clone(&agent);
            // The same policy the overlay's admission is ruled against, loaded
            // once at start. A site has one place where authority is written
            // rather than one per feature, and a file that could be swapped
            // under a running agent is a file that decides nothing.
            //
            // The compiled default grants nothing for `restart`, so a site that
            // has said nothing refuses it. That is the difference between a
            // console that can act and one that acts because nobody stopped it.
            let policy = policyfile::load();
            move |req: &Request| {
                let (Some(id), Some(kind)) = (
                    req.body.get("id").and_then(|v| v.as_str()),
                    req.body.get("kind").and_then(|v| v.as_str()),
                ) else {
                    return Response::error(400, "`id` and `kind` are required");
                };
                // Proved by the router, never named in the body. The old
                // version read this field out of the request and the policy
                // engine ruled on whatever it said — a caller decided who it
                // was, and the socket is bound to the overlay address.
                //
                // A guarded route cannot reach a handler without one, so this
                // is unreachable rather than defensive; it is written as a
                // refusal anyway, because "cannot happen" is how the next
                // person removes the guard without noticing.
                let Some(who) = req.principal.as_ref() else {
                    return Response::refused("this route requires a proved caller");
                };
                let principal = who.id.as_str();

                // Purpose binding. A credential issued for one job may not be
                // spent on another, however wide its capability looks: the
                // capability says what kind of thing, the task says which one.
                if let Some(task) = &who.task {
                    if !task.contains(id) {
                        return Response::refused(format!(
                            "that credential was issued for `{task}`, not for {id}"
                        ));
                    }
                }
                // An action needing a person cannot be taken by a principal
                // that has none. Refusing is the only resolution: the
                // alternative is granting it to something that by construction
                // cannot be asked.
                if who.needs_approval("restart") && !who.can_stand_in_for_a_person() {
                    return Response::refused(
                        "that credential requires a human to approve a restart, and it \
                         has no human in its chain",
                    );
                }

                let request = furcate_policy::Request {
                    principal: principal.to_string(),
                    action: "restart".into(),
                    resource: format!("workload:{id}"),
                    // Roles come from whoever proved the caller — never from
                    // the body, for the same reason the principal does not.
                    roles: who.roles.clone(),
                };
                let decision = policy.evaluate(&request, now_s());

                let mut a = agent.lock().expect("agent lock");
                // Chained with how the caller proved itself, not just what it
                // was called. A record naming "operator" says nothing about
                // whether anyone checked.
                a.chain.append(
                    now_ms(),
                    OpKind::Lifecycle,
                    format!("{principal} via {}", who.evidence.as_str()),
                    format!("restart {kind} {id}"),
                    if decision.allowed { "permitted" } else { "refused" },
                );
                a.persist_chain();

                if !decision.allowed {
                    return Response::ok(json!({
                        "ok": false,
                        "refused": true,
                        "structural": decision.structural,
                        "because": decision.because,
                    }));
                }
                if !actuate::id_is_safe(id) {
                    return Response::ok(json!({
                        "ok": false,
                        "refused": true,
                        "because": "that id has characters that may not cross into a                                     privileged process",
                    }));
                }

                let nonce = format!("restart-{}", now_ms());
                if let Err(e) = actuate::write_restart(kind, id, &nonce) {
                    return Response::ok(json!({
                        "ok": false,
                        "because": format!("could not reach the privileged half: {e}"),
                    }));
                }
                // The actuator polls; the answer is not instant. The nonce is
                // returned so a caller can ask again rather than this blocking
                // a request thread on somebody else's loop.
                Response::ok(json!({
                    "ok": true,
                    "requested": {"action": "restart", "kind": kind, "id": id},
                    "nonce": nonce,
                    "because": decision.because,
                    "note": "asked for; confirm with /workloads/restart/result",
                }))
            }
        })
        // Reset one accelerator, on an operator's explicit instruction.
        //
        // The remedy furcate-health's playbook has always named and nothing
        // could carry out: a card that recorded a row remap is running on
        // memory it has already condemned, and only a reset applies the repair.
        //
        // Ruled the same way a restart is, and chained the same way, because it
        // is the same kind of act — a person reaching for a control through the
        // machine rather than beside it. The privileged half refuses a card
        // with processes on it, so the drain stays a precondition somebody has
        // to satisfy rather than something taken quietly here.
        .guarded("POST", "/accelerators/reset", {
            let agent = Arc::clone(&agent);
            let policy = policyfile::load();
            move |req: &Request| {
                let Some(index) = req.body.get("index").and_then(|v| v.as_u64()) else {
                    return Response::error(400, "`index` is required");
                };
                let Some(who) = req.principal.as_ref() else {
                    return Response::refused("this route requires a proved caller");
                };
                let principal = who.id.as_str();

                if let Some(task) = &who.task {
                    if !task.contains(&index.to_string()) {
                        return Response::refused(format!(
                            "that credential was issued for `{task}`, not for accelerator {index}"
                        ));
                    }
                }
                // A reset destroys every context on the card. If a credential
                // needs a person for a restart, it needs one at least as much
                // for this.
                if who.needs_approval("reset") && !who.can_stand_in_for_a_person() {
                    return Response::refused(
                        "that credential requires a human to approve a device reset, and                          it has no human in its chain",
                    );
                }

                let request = furcate_policy::Request {
                    principal: principal.to_string(),
                    action: "reset".into(),
                    resource: format!("accelerator:{index}"),
                    roles: who.roles.clone(),
                };
                let decision = policy.evaluate(&request, now_s());

                let mut a = agent.lock().expect("agent lock");
                a.chain.append(
                    now_ms(),
                    OpKind::Lifecycle,
                    format!("{principal} via {}", who.evidence.as_str()),
                    format!("reset accelerator {index}"),
                    if decision.allowed { "permitted" } else { "refused" },
                );
                a.persist_chain();

                if !decision.allowed {
                    return Response::ok(json!({
                        "ok": false,
                        "refused": true,
                        "structural": decision.structural,
                        "because": decision.because,
                    }));
                }

                let nonce = format!("reset-{}", now_ms());
                if let Err(e) = actuate::write_reset(index as u32, &nonce) {
                    return Response::ok(json!({
                        "ok": false,
                        "because": format!("could not reach the privileged half: {e}"),
                    }));
                }
                Response::ok(json!({
                    "ok": true,
                    "requested": {"action": "reset_accelerator", "index": index},
                    "nonce": nonce,
                    "because": decision.because,
                    // Said here as well as refused there, so an operator reads
                    // the precondition before the refusal rather than after.
                    "note": "asked for; a card with processes on it will be refused — drain it                              first. Confirm with /workloads/restart/result",
                }))
            }
        })
        .route("POST", "/workloads/restart/result", {
            move |req: &Request| {
                let Some(nonce) = req.body.get("nonce").and_then(|v| v.as_str()) else {
                    return Response::error(400, "`nonce` is required");
                };
                // Matched, not trusted-latest: a stale result from the previous
                // request would otherwise read as confirmation of this one.
                match actuate::confirm(nonce) {
                    Some(v) => Response::ok(v),
                    None => Response::ok(json!({
                        "pending": true,
                        "note": "the privileged half has not answered for this nonce yet",
                    })),
                }
            }
        });

    // Boxes are not part of the open daemon. It answers their paths with a
    // sentence rather than a 404 that reads like a typo; an edition that rents
    // boxes replaces these routes with its own below.
    {
        const NOT_HERE: &str = "boxes are not part of this build of furcated";
        r = r
            .route("GET", "/box", move |_: &Request| Response::error(501, NOT_HERE))
            .route("GET", "/box/observed", move |_: &Request| Response::error(501, NOT_HERE));
        for verb in ["", "start", "stop", "resize", "extend", "expose", "delete", "attach", "meter"] {
            let path = if verb.is_empty() { "/box".to_string() } else { format!("/box/{verb}") };
            r = r.guarded("POST", &path, move |_: &Request| Response::error(501, NOT_HERE));
        }
    }

    // The site view, in every build. A home lab with several machines needs
    // one answer to what is running across them, and that answer is a cache
    // of what each machine says about itself: it grants nothing, so any node
    // can serve it and the open edition does. The machines it lists are the
    // ones this node joins, so the view and the membership are one list.
    let listen = std::env::var("FURCATE_LISTEN").unwrap_or_else(|_| "127.0.0.1:7616".to_string());
    let peers: Vec<String> = std::env::var("FURCATE_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(str::to_string)
        .collect();
    let view = Arc::new(Mutex::new(furcate_siteview::SiteView::new(Some(listen), peers)));
    furcate_siteview::spawn_poller(&sched, Arc::clone(&view));
    r = site_view_routes(r, Arc::clone(&view), Arc::clone(&agent));

    // The site as its cells, read back from the signed chain and cut to
    // whoever asks. A node that heads a cell also reports its roll-up to the
    // node that enrolled it, and keeps running on what it last knew when that
    // node cannot be reached.
    let cells = Arc::new(cells::Cells::load(cell_signer.clone(), now_s()));
    let cell_readings: Arc<dyn Fn(u64) -> furcate_topology::cell::Readings + Send + Sync> = {
        let view = Arc::clone(&view);
        let agent = Arc::clone(&agent);
        Arc::new(move |now| furcate_topology::cell::Readings {
            machines: view.lock().expect("siteview lock").machine_readings(now),
            sensors: agent
                .lock()
                .expect("agent lock")
                .sensors
                .sensors()
                .into_iter()
                .cloned()
                .collect(),
            ..Default::default()
        })
    };
    {
        let cells = Arc::clone(&cells);
        let readings = Arc::clone(&cell_readings);
        furcate_sched::spawn(
            &sched,
            "cells-uplink",
            furcate_sched::Cadence::FixedRate { secs: furcate_siteview::POLL_SECS },
            furcate_sched::Backoff::default(),
            move || {
                let now = now_s();
                let mut r = readings(now);
                r.reported = cells.reported();
                cells.report_up(&r, now);
                furcate_sched::Ran::Ok
            },
        );
    }
    r = cells::routes(r, cells, cell_readings);

    // Who holds the site's keys: loaded and checked at start and again on
    // every pass, so a changed or tampered record takes effect, or is
    // refused, without a restart. Reported read-only; changed only by a
    // signed operator change or a passkey order.
    let key_custody = Arc::new(keycustody::KeyCustody::new(
        node_id.clone(),
        rot.assurance(),
        furcate_siteview::site_name(),
        keycustody::Paths::standard(),
    ));
    {
        let reload = {
            let custody = Arc::clone(&key_custody);
            let agent = Arc::clone(&agent);
            move || {
                let mut a = agent.lock().expect("agent lock");
                let alive = a.membership.alive().into_iter().map(|m| m.id.clone()).collect();
                let before = a.chain.len();
                custody.reload(&mut a.chain, &alive, now_s(), now_ms());
                if a.chain.len() != before {
                    a.persist_chain();
                }
            }
        };
        reload();
        furcate_sched::spawn(
            &sched,
            "key-custody",
            furcate_sched::Cadence::FixedRate { secs: 15 },
            furcate_sched::Backoff::default(),
            move || {
                reload();
                furcate_sched::Ran::Ok
            },
        );
    }
    r = furcate_api::custody::mount(r, Arc::clone(&key_custody) as Arc<dyn furcate_api::custody::CustodySource>);

    // Halting, powering off, isolating and erasing are reachable only as a
    // passkey-approved order, verified here by the node it names. There is
    // still no plain API call that does any of them.
    {
        let config = furcate_api::orders::OrdersConfig::load(&furcate_paths::config("orders.json"));
        if let Err(why) = &config {
            eprintln!("furcated: passkey orders are off, and the order routes will say so: {why}");
        }
        let actuator = Arc::new(actuators::IntentActuator::from_env());
        acknowledge_erase(&actuator.erase, &rot, &agent);
        let out_of_band = match furcate_killswitch::warden::OutOfBandPath::load(
            &furcate_paths::config("out-of-band.json"),
        ) {
            Ok(Some(path)) => Ok(path.open()),
            Ok(None) => Err("no out-of-band path is declared in out-of-band.json".to_string()),
            Err(why) => {
                eprintln!("furcated: WARNING the out-of-band path is unusable: {why}");
                Err(format!("the declared out-of-band path is unusable: {why}"))
            }
        };
        let executor = Arc::new(orders::NodeOrders::new(
            node_id.clone(),
            Arc::clone(&agent),
            actuator,
            out_of_band,
            Some(furcate_paths::state("killswitch.json")),
        )
        .with_custody(Arc::clone(&key_custody)));
        match furcate_api::orders::Desk::new(
            config,
            Some(furcate_paths::state("passkeys.json")),
            Some(furcate_paths::state("orders-desk.json")),
            executor,
        ) {
            Ok(desk) => r = furcate_api::orders::mount(r, Arc::new(desk)),
            Err(why) => eprintln!(
                "furcated: WARNING the passkey roster could not be read, so this node takes no \
                 orders: {why}"
            ),
        }
    }

    // What the registered edition adds, last, so a route it serves replaces
    // the open daemon's answer on the same path.
    extension::get().routes(r, &extension::Node::new(Arc::clone(&agent)))
}

/// Acknowledge an erase that early boot has completed, with a fresh quote,
/// and record it. Until this succeeds the node keeps reporting the erase as
/// pending.
fn acknowledge_erase(
    latch: &actuators::EraseLatch,
    rot: &Arc<dyn RootOfTrust + Send + Sync>,
    agent: &Arc<Mutex<Agent>>,
) {
    let quote = |nonce: &[u8]| -> Result<serde_json::Value, String> {
        let q = rot.quote(nonce).map_err(|e| e.to_string())?;
        Ok(json!({
            "nonce": hex::encode(&q.nonce),
            "quote": hex::encode(&q.message),
            "signature": hex::encode(&q.signature),
            "pcrs": q.pcrs.to_hex(),
        }))
    };
    match latch.acknowledge(&quote) {
        Ok(None) => {
            if let Some(p) = latch.pending() {
                eprintln!("furcated: an erase is pending and not yet acknowledged: {p}");
            }
        }
        Ok(Some(ack)) => {
            {
                let mut a = agent.lock().expect("agent lock");
                let subject = ack["order_hash"].as_str().unwrap_or_default().to_string();
                let entry = json!({ "event": "erase_acknowledged", "acknowledgment": ack });
                a.chain
                    .append(now_ms(), OpKind::KeyUse, "erase", subject, entry.to_string());
                a.persist_chain();
            }
            if let Err(e) = latch.clear() {
                eprintln!("furcated: WARNING the erase was acknowledged but the latch remains: {e}");
            }
        }
        Err(why) => eprintln!("furcated: WARNING the pending erase cannot be acknowledged: {why}"),
    }
}

/// Attach the site view, marking as members the nodes whose signed ping this
/// node has verified. A node that only claims an identity is still shown, as
/// a claim.
fn site_view_routes(
    r: Router,
    view: Arc<Mutex<furcate_siteview::SiteView>>,
    agent: Arc<Mutex<Agent>>,
) -> Router {
    furcate_siteview::routes(r, view, move || {
        let a = agent.lock().expect("agent lock");
        let mut ids: std::collections::BTreeSet<String> =
            a.membership.alive().into_iter().map(|m| m.id.clone()).collect();
        ids.insert(a.node_id.clone());
        ids
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the tests exercise the ladder directly; the agent reaches these
    // through `Ladder` and `ups::Reading`.
    use furcate_power::{PowerState, Rung};

    pub(super) fn capability() -> Capability {
        Capability {
            node: "n".into(),
            cpu_cores: 8,
            ram_mb: 32768,
            vram_mb: 0,
            runtimes: vec![],
            attested: true,
        }
    }

    /// An agent on a fresh chain, independent of whatever ledger happens to
    /// exist on the machine running the tests.
    #[test]
    fn registering_a_model_needs_the_operator() {
        // It hashes any path the caller names as this daemon's user, sends
        // every later /infer for that id to the endpoint the caller names, and
        // persists both. An unsigned caller must not get as far as any of it.
        let r = model_load_route(Router::new(), Arc::new(Mutex::new(agent())));
        let res = r.dispatch(&Request {
            method: "POST".into(),
            path: "/models/load".into(),
            body: json!({ "id": "m", "path": "/etc/hostname", "endpoint": "http://192.0.2.1:9" }),
            raw_body: br#"{"id":"m","path":"/etc/hostname","endpoint":"http://192.0.2.1:9"}"#.to_vec(),
            ..Default::default()
        });
        assert_eq!(res.status, 403, "{}", res.body);
        assert!(r.guarded_paths().contains(&"POST /models/load".to_string()));
    }

    #[test]
    fn an_ssh_request_is_staged_where_nobody_else_could_have_put_anything() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = std::env::temp_dir().join(format!("furcated-private-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let a = private_dir(&base, "furcate-ssh-req").unwrap();
        let b = private_dir(&base, "furcate-ssh-req").unwrap();
        assert_ne!(a, b, "two requests must never share a directory");
        let mode = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "only this user may enter it");
        let _ = std::fs::remove_dir_all(&base);
    }

    pub(super) fn agent() -> Agent {
        let id = "furcate:node:test".to_string();
        let chain = Chain::genesis(&id, 1_000_000);
        Agent::with_chain(id, capability(), chain)
    }

    /// The open build serves a multi-node site view: the route answers without
    /// a credential, lists every configured machine, and calls this node a
    /// member of its own site.
    #[test]
    fn the_open_build_serves_the_site_view() {
        let mut v = furcate_siteview::SiteView::new(
            Some("10.0.0.1:7616".into()),
            ["10.0.0.2:7616".to_string(), "10.0.0.3:7616".to_string()],
        );
        v.readings.insert(
            "10.0.0.1:7616".into(),
            furcate_siteview::Reading {
                at: now_s(),
                reachable: true,
                health: Some(json!({ "node_id": "furcate:node:test" })),
                workloads: None,
                custody: None,
            },
        );
        let r = site_view_routes(
            Router::new(),
            Arc::new(Mutex::new(v)),
            Arc::new(Mutex::new(agent())),
        );
        assert!(r.guarded_paths().iter().all(|p| !p.ends_with(" /site")));
        let got = r.dispatch(&Request {
            method: "GET".into(),
            path: "/site".into(),
            ..Default::default()
        });
        assert_eq!(got.status, 200);
        assert_eq!(got.body["of"], 3);
        assert_eq!(got.body["nodes"][0]["member"], true);
        assert_eq!(got.body["nodes"][0]["freshness"], "fresh");
        assert_eq!(got.body["nodes"][1]["freshness"], "silent");
        let page = r.dispatch(&Request {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        });
        assert_eq!(page.status, 200);
    }

    #[test]
    fn a_fresh_agent_starts_with_a_genesis_entry() {
        let a = agent();
        assert_eq!(a.chain.len(), 1);
        assert!(a.chain.verify().is_ok());
    }

    #[test]
    fn an_agent_that_has_never_heard_from_a_controller_is_autonomous() {
        assert!(agent().autonomous(1_000_000, CONTROLLER_TIMEOUT_MS));
    }

    #[test]
    fn losing_the_controller_does_not_change_the_power_rung() {
        // The rule the daemon exists to honour: a controller crash must not
        // cascade into a power event.
        let mut a = agent();
        a.ladder.observe(PowerState::OnLine, 0, None);
        let before = a.ladder.rung();
        a.controller_seen_at = None;
        assert!(a.autonomous(999_999, CONTROLLER_TIMEOUT_MS));
        assert_eq!(a.ladder.rung(), before);
        assert_eq!(before, Rung::Nominal);
    }

    #[test]
    fn a_critical_signal_cordons_the_node() {
        let mut a = agent();
        a.lifecycle.apply(Transition::Attest).unwrap();
        a.lifecycle.apply(Transition::Admit).unwrap();
        assert!(a.lifecycle.state().accepts_work());
        let s = Signal::new("n", SignalKind::AttestationDrift { register: 11 }, 0);
        assert_eq!(a.observe_signal(s), "cordoned");
        assert!(!a.lifecycle.state().accepts_work());
    }

    #[test]
    fn a_warning_signal_does_not_remove_the_node_from_service() {
        let mut a = agent();
        a.lifecycle.apply(Transition::Attest).unwrap();
        a.lifecycle.apply(Transition::Admit).unwrap();
        let s = Signal::new(
            "n",
            SignalKind::DiskDegraded {
                device: "nvme0".into(),
                reallocated: 3,
            },
            0,
        );
        assert_eq!(a.observe_signal(s), "recorded");
        assert!(a.lifecycle.state().accepts_work());
    }

    #[test]
    fn every_signal_lands_in_the_chain() {
        let mut a = agent();
        let before = a.chain.len();
        a.observe_signal(Signal::new("n", SignalKind::Unreachable, 0));
        assert!(a.chain.len() > before);
        assert!(a.chain.verify().is_ok());
    }

    #[test]
    fn the_signal_buffer_is_bounded() {
        let mut a = agent();
        for _ in 0..300 {
            a.observe_signal(Signal::new(
                "n",
                SignalKind::DiskDegraded {
                    device: "d".into(),
                    reallocated: 1,
                },
                0,
            ));
        }
        assert!(a.signals.len() <= 256);
    }

    #[test]
    fn membership_starts_with_only_this_node() {
        let a = agent();
        assert_eq!(a.membership.alive().len(), 1);
    }

    #[test]
    fn reporting_waits_for_the_site_address_gate() {
        // The gate that would have prevented the outage: nothing that talks to
        // the controller starts before its address exists.
        let mut a = agent();
        a.bringup.settle(now_s());
        assert!(a.bringup.started().contains("api"));
        assert!(!a.bringup.started().contains("reporting"));
        a.bringup
            .set_gate(Gate::AddressReady("site".into()), GateState::Open);
        a.bringup.settle(now_s());
        assert!(a.bringup.started().contains("reporting"));
    }
}

#[cfg(test)]
mod workload_health_tests {
    use super::*;
    use furcate_health::workload::{Inventory, RunState, Workload, WorkloadKind};

    fn agent_with(inv: &Inventory) -> Agent {
        let id = "furcate:node:test".to_string();
        let chain = Chain::genesis(&id, 1_000_000);
        let mut a = Agent::with_chain(id, capability_for_test(), chain);
        fold_workloads_into_health(&mut a, inv);
        a
    }

    fn capability_for_test() -> Capability {
        Capability {
            node: "n".into(),
            cpu_cores: 8,
            ram_mb: 32768,
            vram_mb: 0,
            runtimes: vec![],
            attested: true,
        }
    }

    fn healthy() -> Inventory {
        Inventory {
            workloads: vec![
                Workload::new("mainnet-validator-1", WorkloadKind::Container, RunState::Running)
                    .critical(),
            ],
            partial: false,
        }
    }

    fn broken() -> Inventory {
        Inventory {
            workloads: vec![
                Workload::new("mainnet-validator-1", WorkloadKind::Container, RunState::Failed)
                    .critical(),
            ],
            partial: false,
        }
    }

    #[test]
    fn a_healthy_fleet_produces_no_signals() {
        let a = agent_with(&healthy());
        assert!(a.signals.is_empty());
        assert!(!a.cordoned_by_workload);
    }

    #[test]
    fn a_failed_critical_workload_reaches_the_nodes_own_health() {
        // Before this the inventory reached the controller's view and nothing
        // else: the node reported no signals and stayed eligible for work
        // while the thing it exists to run was dead.
        let a = agent_with(&broken());
        assert_eq!(a.signals.len(), 1);
        assert!(a.cordoned_by_workload);
    }

    #[test]
    fn the_same_failure_is_not_signalled_again_every_cycle() {
        // A container down for an hour would otherwise append a chain entry
        // every thirty seconds.
        let mut a = agent_with(&broken());
        let before = a.chain.len();
        fold_workloads_into_health(&mut a, &broken());
        fold_workloads_into_health(&mut a, &broken());
        assert_eq!(a.signals.len(), 1);
        assert_eq!(a.chain.len(), before);
    }

    #[test]
    fn recovery_puts_the_node_back_without_a_human() {
        // A cordon only a human can lift turns a restarting container into a
        // machine out of service until somebody notices.
        let mut a = agent_with(&broken());
        assert!(a.cordoned_by_workload);
        fold_workloads_into_health(&mut a, &healthy());
        assert!(!a.cordoned_by_workload);
    }

    #[test]
    fn a_non_critical_failure_does_not_cordon_the_machine() {
        // Taking a node out of service over a scratch container would cost
        // more than it protects.
        let inv = Inventory {
            workloads: vec![Workload::new("scratch", WorkloadKind::Container, RunState::Failed)],
            partial: false,
        };
        let a = agent_with(&inv);
        assert_eq!(a.signals.len(), 1, "still recorded");
        assert!(!a.cordoned_by_workload, "but not cordoned");
    }
}
