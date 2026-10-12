//! Public ingress gateways, and durable operator access to them.
//!
//! A gateway is the one machine a NAT'd fleet is reachable *through*: it holds
//! the public address, terminates the tunnel every node dials out to, and
//! forwards traffic in by SNI. The nodes themselves have no public address, so
//! without a gateway nothing in the estate answers from the internet.
//!
//! Two things about a gateway were, until now, done by hand and off the record.
//! The first is simply *knowing* one exists — its address, its tunnel key, what
//! it forwards — which lived in a person's memory and a `wg show`. The second is
//! *getting onto it*: a hardened gateway accepts a locked, single-purpose SSH
//! command and nothing else, so adding a real management key meant opening the
//! provider's web console and typing a key in by hand. That is a workaround, and
//! a workaround that has to be repeated is a missing feature.
//!
//! This module makes both first-class. `gateway add` records the gateway in
//! `gateways.json` beside the site's other decisions; `gateway authorize`
//! installs an operator's public key into the gateway's `authorized_keys` over
//! the access it already has, so the next person — or the next machine — reaches
//! it directly. The key is the operator's to hold; this only places it.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The WireGuard hub a gateway runs, as seen from the fleet.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WgHub {
    /// The gateway's WireGuard public key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pubkey: String,
    /// Where nodes dial it: `ip:port`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// The gateway's own address inside the tunnel, e.g. 10.0.0.1.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fleet_addr: String,
}

/// One gateway the estate reaches the internet through.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Gateway {
    pub name: String,
    /// `main`, `backup`, or empty. Advisory: it records intent, and the first
    /// gateway added with role `main` is the one tools should prefer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_ip: String,
    /// How to reach it for management.
    #[serde(default = "default_user")]
    pub ssh_user: String,
    #[serde(default = "default_port")]
    pub ssh_port: u16,
    /// The private key on THIS node that already opens a shell on the gateway.
    /// Recorded, never its contents — so `gateway ssh`/`authorize` know how to
    /// connect without anyone retyping it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key: String,
    #[serde(default, skip_serializing_if = "is_default_wg")]
    pub wg: WgHub,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default)]
    pub added_at: u64,
}

fn default_user() -> String {
    "root".to_string()
}
fn default_port() -> u16 {
    22
}
fn is_default_wg(w: &WgHub) -> bool {
    w.pubkey.is_empty() && w.endpoint.is_empty() && w.fleet_addr.is_empty()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub gateways: Vec<Gateway>,
}

fn path() -> std::path::PathBuf {
    furcate_paths::config("gateways.json")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load() -> Result<Registry> {
    let p = path();
    match std::fs::read_to_string(&p) {
        Ok(t) => serde_json::from_str(&t)
            .with_context(|| format!("{} is not a readable gateway registry", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

fn save(r: &Registry) -> Result<()> {
    let p = path();
    let bytes = serde_json::to_vec_pretty(r).context("the registry serialises")?;
    // Temp-then-rename, like the people roster: a half-written registry must
    // read as the old one, never as an empty one that forgets every gateway.
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &p).with_context(|| format!("installing {}", p.display()))?;
    Ok(())
}

/// Split `key=value` pairs, so optional fields read the way `deploy env` does.
fn pairs(rest: &[&str]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut m = std::collections::BTreeMap::new();
    for kv in rest {
        let (k, v) = kv
            .split_once('=')
            .with_context(|| format!("`{kv}` is not key=value"))?;
        m.insert(k.to_string(), v.to_string());
    }
    Ok(m)
}

/// The ssh argument vector for reaching a gateway, shared by ssh/authorize so
/// they cannot drift in how they connect.
fn ssh_base(g: &Gateway) -> Vec<String> {
    let mut a = vec![
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "ConnectTimeout=12".into(),
        "-p".into(),
        g.ssh_port.to_string(),
    ];
    if !g.access_key.is_empty() {
        a.push("-i".into());
        a.push(g.access_key.clone());
    }
    let target = format!("{}@{}", g.ssh_user, host_for(g));
    a.push(target);
    a
}

/// Prefer the public IP for the actual connection when we have it — a gateway's
/// own hostname often resolves to itself and can be mid-migration.
fn host_for(g: &Gateway) -> String {
    if g.public_ip.is_empty() {
        g.hostname.clone()
    } else {
        g.public_ip.clone()
    }
}

fn find<'a>(r: &'a Registry, name: &str) -> Result<&'a Gateway> {
    r.gateways
        .iter()
        .find(|g| g.name == name)
        .with_context(|| format!("no gateway named `{name}` — see `furcatectl gateway list`"))
}

/* ── commands ───────────────────────────────────────────────────────────── */

pub fn add(name: &str, hostname: &str, rest: &[&str]) -> Result<()> {
    let opt = pairs(rest)?;
    let mut r = load()?;
    if r.gateways.iter().any(|g| g.name == name) {
        bail!("a gateway named `{name}` is already registered; `gateway remove {name}` first");
    }
    let role = opt.get("role").cloned().unwrap_or_default();
    if role == "main" {
        // One main at a time: an ambiguous "which is the main gateway" is worse
        // than making the operator demote the old one on purpose.
        if let Some(old) = r.gateways.iter().find(|g| g.role == "main") {
            bail!(
                "`{}` is already the main gateway; re-add it as role=backup first, \
                 or add this one as role=backup",
                old.name
            );
        }
    }
    let g = Gateway {
        name: name.to_string(),
        role,
        hostname: hostname.to_string(),
        public_ip: opt.get("ip").cloned().unwrap_or_default(),
        ssh_user: opt.get("user").cloned().unwrap_or_else(default_user),
        ssh_port: opt
            .get("port")
            .map(|p| p.parse())
            .transpose()
            .context("port must be a number")?
            .unwrap_or_else(default_port),
        access_key: opt.get("key").cloned().unwrap_or_default(),
        wg: WgHub {
            pubkey: opt.get("wg_pubkey").cloned().unwrap_or_default(),
            endpoint: opt.get("wg_endpoint").cloned().unwrap_or_default(),
            fleet_addr: opt.get("wg_addr").cloned().unwrap_or_default(),
        },
        provider: opt.get("provider").cloned().unwrap_or_default(),
        note: opt.get("note").cloned().unwrap_or_default(),
        added_at: now(),
    };
    r.gateways.push(g);
    save(&r)?;
    println!("registered gateway `{name}` ({hostname})");
    if !rest.iter().any(|kv| kv.starts_with("key=")) {
        println!(
            "no access key recorded — `gateway authorize {name} <pub>` needs one to reach it, \
             set it with `gateway add ... key=/path/to/private_key`"
        );
    }
    Ok(())
}

pub fn list() -> Result<()> {
    let r = load()?;
    if r.gateways.is_empty() {
        println!("no gateways registered — add one with `furcatectl gateway add NAME HOST ...`");
        return Ok(());
    }
    for g in &r.gateways {
        let role = if g.role.is_empty() {
            String::new()
        } else {
            format!("  [{}]", g.role)
        };
        println!("{:<12} {}{}", g.name, g.hostname, role);
        let addr = if g.public_ip.is_empty() {
            "—".into()
        } else {
            g.public_ip.clone()
        };
        println!(
            "             {addr}  ssh {}@{}:{}  key={}",
            g.ssh_user,
            host_for(g),
            g.ssh_port,
            if g.access_key.is_empty() {
                "none"
            } else {
                &g.access_key
            }
        );
        if !g.wg.endpoint.is_empty() {
            println!("             wg {} via {}", g.wg.fleet_addr, g.wg.endpoint);
        }
    }
    Ok(())
}

pub fn show(name: &str) -> Result<()> {
    let r = load()?;
    let g = find(&r, name)?;
    println!("{}", serde_json::to_string_pretty(g)?);
    Ok(())
}

pub fn remove(name: &str) -> Result<()> {
    let mut r = load()?;
    let before = r.gateways.len();
    r.gateways.retain(|g| g.name != name);
    if r.gateways.len() == before {
        bail!("no gateway named `{name}`");
    }
    save(&r)?;
    println!("removed gateway `{name}` (its access key on the gateway is untouched)");
    Ok(())
}

/// Run a command on a gateway, or open a shell, over its recorded access.
///
/// The replacement for `ssh -i <key> root@<ip>` typed from memory: the access is
/// looked up, not remembered.
pub fn ssh(name: &str, cmd: &[&str]) -> Result<()> {
    let r = load()?;
    let g = find(&r, name)?;
    let mut args = ssh_base(g);
    // A shell wants a tty; a command does not.
    if cmd.is_empty() {
        args.insert(0, "-t".into());
    } else {
        args.push("--".into());
        args.extend(cmd.iter().map(|s| s.to_string()));
    }
    let status = Command::new("ssh")
        .args(&args)
        .status()
        .context("running ssh")?;
    if !status.success() {
        bail!("ssh to `{name}` exited {}", status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Install an operator's public key into a gateway's authorized_keys.
///
/// This is the whole point of the module: persistent access, placed by the tool
/// rather than pasted into a provider console. It uses the access the gateway
/// already grants this node, and is idempotent — a key already present is left
/// exactly once, so running it twice does not stack duplicates.
pub fn authorize(name: &str, keyfile: &str) -> Result<()> {
    let r = load()?;
    let g = find(&r, name)?;
    if g.access_key.is_empty() {
        bail!(
            "`{name}` has no recorded access key, so there is no way in to place another. \
             Add the first key out of band (the provider console), then record it with \
             `gateway add ... key=<private key>` — after that this command carries the rest."
        );
    }
    let pubkey = std::fs::read_to_string(keyfile)
        .with_context(|| format!("reading {keyfile}"))?
        .trim()
        .to_string();
    if !pubkey.starts_with("ssh-") && !pubkey.starts_with("ecdsa-") && !pubkey.starts_with("sk-") {
        bail!("{keyfile} does not look like an SSH public key");
    }
    // Guard against a private key by mistake: those are the thing never to send.
    if pubkey.contains("PRIVATE KEY") {
        bail!("{keyfile} is a PRIVATE key — pass the .pub");
    }

    // The remote side, run under a shell on the gateway. Idempotent by grep, and
    // it creates ~/.ssh with the right mode if this is the first key placed
    // outside the provider console.
    let remote = format!(
        "set -e; mkdir -p ~/.ssh; chmod 700 ~/.ssh; touch ~/.ssh/authorized_keys; \
         chmod 600 ~/.ssh/authorized_keys; \
         if grep -qF '{key}' ~/.ssh/authorized_keys; then echo ALREADY; \
         else printf '\\n%s\\n' '{key}' >> ~/.ssh/authorized_keys; echo ADDED; fi",
        key = pubkey.replace('\'', "'\\''"),
    );

    let mut args = ssh_base(g);
    args.push("--".into());
    args.push(remote);

    let out = Command::new("ssh")
        .args(&args)
        .output()
        .context("running ssh to place the key")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "could not place the key on `{name}`: {}",
            err.trim().lines().last().unwrap_or("ssh failed")
        );
    }
    if stdout.contains("ALREADY") {
        println!("`{name}` already trusts that key — nothing to do");
    } else {
        println!("placed the key on `{name}`; it now grants persistent access");
    }
    Ok(())
}
