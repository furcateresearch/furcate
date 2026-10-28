//! `furcatectl firewall`: render the node's input firewall and apply it
//! without locking the node out.
//!
//! Applying is guarded three ways. A rollback is armed as a systemd timer
//! before anything changes, so it fires even if this process dies. The new
//! ruleset is checked by nft before it is loaded, and loaded in one
//! transaction. Then the overlay must complete a fresh WireGuard handshake
//! within the confirmation window; if it does not, the previous table is
//! restored at once. A ruleset that has passed that check is recorded, and
//! applying the same ruleset again (as at boot) does not wait for it.

use anyhow::{anyhow, bail, Context as _, Result};
use furcate_net::firewall::{self, FirewallConfig, HANDSHAKE_FRESH_SECS, TABLE};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a new ruleset has to prove the overlay still works.
pub const DEFAULT_CONFIRM_SECS: u64 = 180;
/// How long a new ruleset waits for the overlay to be up before it is refused.
pub const DEFAULT_OVERLAY_WAIT_SECS: u64 = 120;
const ROLLBACK_UNIT: &str = "furcate-firewall-rollback";

fn state_dir() -> PathBuf {
    furcate_paths::state("firewall")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn nft() -> Result<PathBuf> {
    ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .ok_or_else(|| anyhow!("nftables is not installed (no nft); the firewall is not enabled on this node"))
}

fn run(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {cmd:?}"))?;
    if !out.status.success() {
        bail!("{cmd:?}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn load(config: &Path) -> Result<FirewallConfig> {
    let text = std::fs::read_to_string(config).with_context(|| {
        format!("reading {}; a node's firewall is rendered only from its declared configuration", config.display())
    })?;
    FirewallConfig::parse(&text).map_err(|e| anyhow!("{}: {e}", config.display()))
}

/// Where the overlay's port came from.
#[derive(Clone, Copy, Debug, PartialEq)]
enum PortSource {
    Declared,
    Environment,
    EnvFile,
    Default,
}

impl PortSource {
    fn describe(self) -> &'static str {
        match self {
            PortSource::Declared => "overlay_port in the firewall configuration",
            PortSource::Environment => "FURCATE_WG_PORT in the environment",
            PortSource::EnvFile => "FURCATE_WG_PORT in /etc/furcate/env",
            PortSource::Default => "the WireGuard default",
        }
    }
}

const PORT_VAR: &str = "FURCATE_WG_PORT";

fn parse_port(text: &str, source: &str) -> Result<u16> {
    match text.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => bail!("{PORT_VAR} is {text:?} in {source}; it must be a port from 1 to 65535"),
    }
}

/// `FURCATE_WG_PORT` as `furcated` would see it from an EnvironmentFile: the
/// last `NAME=value` line, quotes around the value removed.
fn port_in_env_file(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with('#') || l.starts_with(';') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            (k.trim() == PORT_VAR).then(|| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        })
        .next_back()
}

/// The overlay's WireGuard port, from configuration alone. An explicit
/// `overlay_port` wins; otherwise the same variable the agent reads when it
/// plans the interface, in the process environment and then in
/// `/etc/furcate/env`; otherwise the WireGuard default the agent also falls
/// back to. The interface itself is never the source: at boot it does not
/// exist yet, and what it listens on is what the agent asked for.
fn derive_port(
    c: &FirewallConfig,
    env: &dyn Fn(&str) -> Option<String>,
    env_file: Option<&str>,
) -> Result<(u16, PortSource)> {
    if let Some(p) = c.overlay_port {
        return Ok((p, PortSource::Declared));
    }
    if let Some(v) = env(PORT_VAR) {
        return Ok((parse_port(&v, "the environment")?, PortSource::Environment));
    }
    if let Some(v) = env_file.and_then(port_in_env_file) {
        return Ok((parse_port(&v, "/etc/furcate/env")?, PortSource::EnvFile));
    }
    Ok((furcate_net::wg::DEFAULT_PORT, PortSource::Default))
}

/// What the interface listens on now, or `None` where it is not up.
fn live_port(c: &FirewallConfig) -> Option<u16> {
    let out = run(Command::new("wg").args(["show", &c.overlay_interface, "listen-port"])).ok()?;
    out.trim().parse::<u16>().ok().filter(|p| *p > 0)
}

/// The warning for a live interface that listens elsewhere than the rules
/// open, if it does.
fn mismatch(derived: u16, source: PortSource, live: Option<u16>, iface: &str) -> Option<String> {
    let live = live?;
    (live != derived).then(|| {
        format!(
            "warning: {iface} listens on {live} but the firewall opens {derived} ({}); \
             peers cannot reach the overlay until they agree",
            source.describe()
        )
    })
}

/// The overlay's WireGuard port: derived from configuration, cross-checked
/// against the live interface only to warn.
fn overlay_port(c: &FirewallConfig) -> Result<u16> {
    let env_file = std::fs::read_to_string(furcate_paths::config("env")).ok();
    let (port, source) = derive_port(c, &|k| std::env::var(k).ok(), env_file.as_deref())?;
    if let Some(w) = mismatch(port, source, live_port(c), &c.overlay_interface) {
        eprintln!("firewall: {w}");
    }
    Ok(port)
}

fn newest_handshake(c: &FirewallConfig) -> Option<u64> {
    let out = run(Command::new("wg").args(["show", &c.overlay_interface, "latest-handshakes"])).ok()?;
    firewall::latest_handshake(&out)
}

/// Whether the overlay is up at time `t`, given its newest handshake.
fn overlay_up(newest: Option<u64>, t: u64, iface: &str) -> Result<(), String> {
    match newest {
        Some(h) if t.saturating_sub(h) <= HANDSHAKE_FRESH_SECS => Ok(()),
        Some(h) => Err(format!(
            "refusing: the overlay's newest handshake is {}s old; a new firewall is applied only while the overlay is up",
            t.saturating_sub(h)
        )),
        None => Err(format!("refusing: {iface} has no completed handshake; a new firewall is applied only while the overlay is up")),
    }
}

/// Wait up to `window` seconds for the overlay to be up. Returns at once if it
/// already is; otherwise the reason it was not, once the window has passed.
fn await_overlay(
    probe: &mut dyn FnMut() -> Option<u64>,
    clock: &dyn Fn() -> u64,
    sleep: &mut dyn FnMut(),
    window: u64,
    iface: &str,
) -> Result<(), String> {
    let start = clock();
    loop {
        let t = clock();
        match overlay_up(probe(), t, iface) {
            Ok(()) => return Ok(()),
            Err(why) if t.saturating_sub(start) >= window => return Err(format!("{why} (waited {window}s)")),
            Err(_) => sleep(),
        }
    }
}

fn digest(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// `furcatectl firewall render [CONFIG]`.
pub fn render(config: Option<&str>) -> Result<()> {
    let c = load(Path::new(config.unwrap_or(firewall::CONFIG_PATH)))?;
    print!("{}", firewall::render(&c, overlay_port(&c)?));
    Ok(())
}

/// `furcatectl firewall status`.
pub fn status() -> Result<()> {
    let nft = nft()?;
    let confirmed = std::fs::read_to_string(state_dir().join("confirmed.sha256")).ok();
    match run(Command::new(&nft).args(["list", "table", "inet", TABLE])) {
        Ok(live) => {
            println!("table       inet {TABLE} loaded ({} rules)", live.lines().filter(|l| l.contains(" accept")).count());
        }
        Err(_) => println!("table       inet {TABLE} not loaded: input is not filtered by Furcate"),
    }
    match confirmed {
        Some(d) => println!("confirmed   {}", d.trim()),
        None => println!("confirmed   none: no ruleset has passed the overlay check here"),
    }
    Ok(())
}

/// `furcatectl firewall apply [CONFIG] [--confirm-secs N]`.
pub fn apply(config: Option<&str>, confirm_secs: u64) -> Result<()> {
    let wait_secs = DEFAULT_OVERLAY_WAIT_SECS;
    let nft = nft()?;
    let c = load(Path::new(config.unwrap_or(firewall::CONFIG_PATH)))?;
    let rules = firewall::render(&c, overlay_port(&c)?);
    let sum = digest(&rules);
    let dir = state_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let next = dir.join("next.nft");
    std::fs::write(&next, &rules).context("writing the rendered ruleset")?;
    run(Command::new(&nft).arg("-c").arg("-f").arg(&next)).context("nft refused the rendered ruleset")?;

    let confirmed = std::fs::read_to_string(dir.join("confirmed.sha256")).ok();
    if confirmed.as_deref().map(str::trim) == Some(sum.as_str()) {
        run(Command::new(&nft).arg("-f").arg(&next)).context("loading the confirmed ruleset")?;
        println!("firewall: applied the confirmed ruleset {}", &sum[..16]);
        return Ok(());
    }

    // A new ruleset goes only onto a node whose overlay is up, so its
    // survival can be judged. At boot the overlay is still coming up (the
    // interface does not exist until the agent has planned it), so wait for
    // it a bounded while before refusing; refusing changes nothing.
    await_overlay(
        &mut || newest_handshake(&c),
        &now,
        &mut || std::thread::sleep(Duration::from_secs(2)),
        wait_secs,
        &c.overlay_interface,
    )
    .map_err(|e| anyhow!(e))?;

    let previous = run(Command::new(&nft).args(["list", "table", "inet", TABLE])).ok();
    let restore = dir.join("previous.nft");
    std::fs::write(&restore, firewall::restore_script(previous.as_deref())).context("saving the previous table")?;

    // Armed before anything changes, and run by systemd, so it fires even if
    // this process is killed or the session that started it drops.
    let _ = Command::new("systemctl").args(["stop", &format!("{ROLLBACK_UNIT}.timer")]).output();
    let _ = Command::new("systemctl").args(["reset-failed", &format!("{ROLLBACK_UNIT}.service")]).output();
    run(Command::new("systemd-run")
        .arg(format!("--unit={ROLLBACK_UNIT}"))
        .arg(format!("--on-active={}", confirm_secs + 30))
        .arg("--timer-property=AccuracySec=1s")
        .arg(&nft)
        .arg("-f")
        .arg(&restore))
    .context("refusing: the rollback timer could not be armed, so nothing was changed")?;

    let applied_at = now();
    if let Err(e) = run(Command::new(&nft).arg("-f").arg(&next)) {
        disarm();
        bail!("nft did not load the ruleset, nothing changed: {e}");
    }
    println!(
        "firewall: ruleset {} loaded; waiting up to {confirm_secs}s for a fresh overlay handshake (rollback armed)",
        &sum[..16]
    );

    let deadline = applied_at + confirm_secs;
    loop {
        if newest_handshake(&c).is_some_and(|h| h > applied_at) {
            disarm();
            std::fs::write(dir.join("confirmed.sha256"), format!("{sum}\n")).context("recording the confirmed ruleset")?;
            std::fs::copy(&next, dir.join("confirmed.nft")).ok();
            println!("firewall: the overlay handshook through the new ruleset; confirmed {}", &sum[..16]);
            return Ok(());
        }
        if now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    let restored = run(Command::new(&nft).arg("-f").arg(&restore));
    match restored {
        Ok(_) => {
            disarm();
            bail!("no overlay handshake within {confirm_secs}s of applying; the previous table was restored")
        }
        Err(e) => bail!(
            "no overlay handshake within {confirm_secs}s and restoring failed ({e}); the rollback timer stays \
             armed and fires in 30s, or run `nft -f {}`",
            restore.display()
        ),
    }
}

fn disarm() {
    let _ = Command::new("systemctl").args(["stop", &format!("{ROLLBACK_UNIT}.timer")]).output();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn cfg(json: &str) -> FirewallConfig {
        FirewallConfig::parse(json).unwrap()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn the_port_is_derived_without_the_interface() {
        let c = cfg(r#"{"lan": ["end0"]}"#);
        assert_eq!(derive_port(&c, &no_env, None).unwrap(), (51820, PortSource::Default));
    }

    #[test]
    fn a_declared_port_overrides_everything() {
        let c = cfg(r#"{"lan": ["end0"], "overlay_port": 41000}"#);
        let env = |_: &str| Some("42000".to_string());
        assert_eq!(derive_port(&c, &env, Some("FURCATE_WG_PORT=43000\n")).unwrap(), (41000, PortSource::Declared));
    }

    #[test]
    fn the_agents_variable_is_read_from_the_environment_then_its_file() {
        let c = cfg(r#"{"lan": ["end0"]}"#);
        let env = |k: &str| (k == "FURCATE_WG_PORT").then(|| "42000".to_string());
        assert_eq!(derive_port(&c, &env, Some("FURCATE_WG_PORT=43000\n")).unwrap(), (42000, PortSource::Environment));
        let file = "# comment\nOTHER=1\nFURCATE_WG_PORT=\"43000\"\n";
        assert_eq!(derive_port(&c, &no_env, Some(file)).unwrap(), (43000, PortSource::EnvFile));
        assert_eq!(derive_port(&c, &no_env, Some("# FURCATE_WG_PORT=1\nFOO=2\n")).unwrap().1, PortSource::Default);
    }

    #[test]
    fn a_malformed_port_is_refused_not_replaced() {
        let c = cfg(r#"{"lan": ["end0"]}"#);
        for bad in ["abc", "0", "70000", ""] {
            let env = |_: &str| Some(bad.to_string());
            assert!(derive_port(&c, &env, None).is_err(), "{bad:?} must not fall back to the default");
        }
        assert!(derive_port(&c, &no_env, Some("FURCATE_WG_PORT=nope\n")).is_err());
    }

    #[test]
    fn rendering_works_with_no_overlay_interface_present() {
        // No such interface exists on any machine running the tests, and `wg`
        // may not be installed: the rules must still render, port included.
        let c = cfg(r#"{"lan": ["end0"], "overlay_interface": "furtest9"}"#);
        assert_eq!(live_port(&c), None);
        let port = overlay_port(&c).expect("a missing interface is not an error");
        let rules = firewall::render(&c, port);
        assert!(rules.contains(&format!("udp dport {port} accept")), "{rules}");
    }

    #[test]
    fn a_live_interface_that_disagrees_only_warns() {
        assert_eq!(mismatch(51820, PortSource::Default, None, "fur0"), None);
        assert_eq!(mismatch(51820, PortSource::Default, Some(51820), "fur0"), None);
        let w = mismatch(51820, PortSource::Declared, Some(41000), "fur0").unwrap();
        assert!(w.contains("41000") && w.contains("51820") && w.contains("overlay_port"), "{w}");
    }

    #[test]
    fn a_late_overlay_is_waited_for_and_then_accepted() {
        let t = Cell::new(1000u64);
        let mut polls = 0;
        let r = await_overlay(
            &mut || {
                polls += 1;
                (polls >= 4).then(|| t.get())
            },
            &|| t.get(),
            &mut || t.set(t.get() + 2),
            120,
            "fur0",
        );
        assert!(r.is_ok());
        assert_eq!(t.get(), 1006, "three waits of two seconds, not the whole window");
    }

    #[test]
    fn an_overlay_that_never_comes_up_is_refused_after_the_window() {
        let t = Cell::new(1000u64);
        let r = await_overlay(&mut || None, &|| t.get(), &mut || t.set(t.get() + 2), 120, "fur0");
        let why = r.unwrap_err();
        assert!(why.contains("no completed handshake") && why.contains("waited 120s"), "{why}");
        assert_eq!(t.get(), 1120);
    }

    #[test]
    fn a_stale_handshake_is_not_an_up_overlay() {
        let t = Cell::new(10_000u64);
        let r = await_overlay(&mut || Some(1), &|| t.get(), &mut || t.set(t.get() + 2), 4, "fur0");
        assert!(r.unwrap_err().contains("old"));
    }
}
