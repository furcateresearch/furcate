//! `furcatectl ssh trust`: this machine accepts the site's passkey logins.
//!
//! What `furcate-ssh trust NODE` does from the CA's machine, done by the
//! machine itself so a release can carry it: the fleet rollout runs this on
//! every host after the host is updated, with the CA's SHA-256 pinned in the
//! rollout's settings.
//!
//! 1. Fetch the CA public key and revocation list (`GET /ssh/ca`) from any of
//!    the addresses given, refusing one whose SHA-256 is not the pinned one.
//! 2. Write `/etc/ssh/furcate_ca.pub`, the revocation list, the principals
//!    command (the bare user name, as before, and `<user>@<this machine>`,
//!    which is all a passkey certificate carries) and the sshd drop-in, which
//!    also turns on `ExposeAuthInfo` so the session recorder can read which
//!    certificate a session logged in with.
//! 3. `sshd -t` before anything is reloaded; a failing configuration is put
//!    back as it was.
//! 4. Start the session recorder: a passkey certificate's force-command is the
//!    recorder's client, which refuses to run a session nothing records.
//!
//! Additive, like the rest of the CA's trust: authorized_keys and every other
//! way in are untouched, so this can never become the only path to a machine.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const DROPIN: &str = "sshd_config.d/70-furcate-ca.conf";

/// What `ssh trust` will write, by path relative to `/etc/ssh`.
#[derive(Debug, PartialEq, Eq)]
pub struct Files {
    pub files: Vec<(String, Vec<u8>, u32)>,
}

/// The files for a CA key, its revocation list and this machine's names.
pub fn render(ca_line: &str, krl: Option<&[u8]>, names: &[String]) -> Result<Files> {
    for n in names {
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) {
            bail!("machine name {n:?} is not lowercase letters, digits, . _ -");
        }
    }
    if names.is_empty() {
        bail!("this machine has no name to accept passkey logins for");
    }
    let mut principals = String::from(
        "#!/bin/sh\n# Written by furcatectl ssh trust. Usage: furcate-principals USER\n\
         case \"$1\" in ''|*[!A-Za-z0-9._-]*) exit 0;; esac\nprintf '%s\\n' \"$1\"\n",
    );
    for n in names {
        principals.push_str(&format!("printf '%s@{n}\\n' \"$1\"\n"));
    }
    let mut dropin = String::from(
        "# Written by furcatectl ssh trust. Additive: authorized_keys still works.\n\
         TrustedUserCAKeys /etc/ssh/furcate_ca.pub\n\
         AuthorizedPrincipalsCommand /etc/ssh/furcate-principals %u\n\
         AuthorizedPrincipalsCommandUser nobody\n\
         # The session recorder reads which certificate a session logged in with.\n\
         ExposeAuthInfo yes\n",
    );
    let mut files = vec![
        ("furcate_ca.pub".to_string(), format!("{}\n", ca_line.trim()).into_bytes(), 0o644),
        ("furcate-principals".to_string(), principals.into_bytes(), 0o755),
    ];
    if let Some(k) = krl {
        dropin.push_str("RevokedKeys /etc/ssh/furcate_ca.krl\n");
        files.push(("furcate_ca.krl".to_string(), k.to_vec(), 0o644));
    }
    files.push((DROPIN.to_string(), dropin.into_bytes(), 0o644));
    Ok(Files { files })
}

/// The CA answer from the first address that gives the pinned key.
fn fetch(from: &[String], pin: &str) -> Result<(String, Option<Vec<u8>>)> {
    let mut why = Vec::new();
    for addr in from {
        let v = match furcate_api::get_json(addr, "/ssh/ca", 5_000) {
            Ok(v) => v,
            Err(e) => {
                why.push(format!("{addr}: {e}"));
                continue;
            }
        };
        let Some(line) = v.get("public_key").and_then(|x| x.as_str()) else {
            why.push(format!("{addr}: no CA there ({v})"));
            continue;
        };
        let got = hex::encode(Sha256::digest(line.trim().as_bytes()));
        if got != pin {
            why.push(format!("{addr}: offered a CA with SHA-256 {got}, not the pinned one"));
            continue;
        }
        if !(line.starts_with("ssh-ed25519 ") || line.starts_with("ecdsa-sha2-nistp256 ")) {
            bail!("the pinned CA is not an ssh-ed25519 or ecdsa-sha2-nistp256 key");
        }
        let krl = match v.get("krl_b64").and_then(|x| x.as_str()) {
            Some(b) => Some(
                data_encoding::BASE64
                    .decode(b.as_bytes())
                    .context("the revocation list is not base64")?,
            ),
            None => None,
        };
        return Ok((line.trim().to_string(), krl));
    }
    bail!("no address gave the pinned CA: {}", why.join("; "))
}

fn machine_names(extra: &[String]) -> Vec<String> {
    let mut names: Vec<String> = extra.to_vec();
    let env = std::fs::read_to_string("/etc/furcate/env").unwrap_or_default();
    for line in env.lines() {
        if let Some(v) = line.trim().strip_prefix("FURCATE_NODE_NAME=") {
            names.push(v.trim().trim_matches('"').to_string());
        }
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        names.push(h.trim().split('.').next().unwrap_or("").to_string());
    }
    let mut names: Vec<String> = names
        .into_iter()
        .map(|n| n.to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Write `files` under `root`, check sshd accepts them, and put everything
/// back if it does not. Returns whether anything changed.
fn apply(root: &Path, files: &Files, check: &dyn Fn() -> Result<()>) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut previous: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
    let mut changed = false;
    for (rel, body, mode) in &files.files {
        let p = root.join(rel);
        let old = std::fs::read(&p).ok();
        if old.as_deref() == Some(body.as_slice()) {
            continue;
        }
        changed = true;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = p.with_extension("furcate-new");
        std::fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(*mode))?;
        std::fs::rename(&tmp, &p)?;
        previous.push((p, old));
    }
    if !changed {
        return Ok(false);
    }
    if let Err(e) = check() {
        for (p, old) in previous {
            match old {
                Some(b) => {
                    let _ = std::fs::write(&p, b);
                }
                None => {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        bail!("sshd refused the new configuration, so it was put back as it was: {e:#}");
    }
    Ok(true)
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let o = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if !o.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

/// `ssh trust --ca-from ADDR[,ADDR] --ca-sha256 HEX [--name NAME]...`
pub fn trust(args: &[&str]) -> Result<()> {
    let mut from = Vec::new();
    let mut pin = None;
    let mut extra = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().map(|s| s.to_string()).ok_or_else(|| anyhow::anyhow!("{a} needs a value"));
        match *a {
            "--ca-from" => from.extend(val()?.split(',').filter(|s| !s.is_empty()).map(String::from)),
            "--ca-sha256" => pin = Some(val()?.to_ascii_lowercase()),
            "--name" => extra.push(val()?),
            other => bail!("unknown argument {other}"),
        }
    }
    let pin = pin.ok_or_else(|| anyhow::anyhow!("--ca-sha256 is required: the CA is pinned, never taken on first use"))?;
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("--ca-sha256 is 64 hex characters");
    }
    if from.is_empty() {
        bail!("--ca-from names at least one machine that trusts the CA (host:port)");
    }
    let (line, krl) = fetch(&from, &pin)?;
    let names = machine_names(&extra);
    let files = render(&line, krl.as_deref(), &names)?;
    let changed = apply(Path::new("/etc/ssh"), &files, &|| run("sshd", &["-t"]))?;
    if changed {
        run("systemctl", &["reload", "ssh"]).or_else(|_| run("systemctl", &["reload", "sshd"]))?;
        println!("ssh trust      CA {} for {}", &pin[..16], names.join(", "));
    } else {
        println!("ssh trust      unchanged (CA {})", &pin[..16]);
    }
    run("systemctl", &["enable", "--now", "furcate-ssh-recorder.service"])
        .context("starting the session recorder; passkey sessions here are refused without it")?;
    println!("recorder       furcate-ssh-recorder running");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        vec!["node-a".into(), "node-a.example".into()]
    }

    #[test]
    fn the_dropin_trusts_the_ca_and_exposes_the_login_to_the_recorder() {
        let f = render("ssh-ed25519 AAAA", Some(b"krl"), &names()).unwrap();
        let get = |n: &str| {
            String::from_utf8(f.files.iter().find(|(p, _, _)| p == n).unwrap().1.clone()).unwrap()
        };
        let d = get(DROPIN);
        assert!(d.contains("TrustedUserCAKeys /etc/ssh/furcate_ca.pub"));
        assert!(d.contains("ExposeAuthInfo yes"));
        assert!(d.contains("RevokedKeys /etc/ssh/furcate_ca.krl"));
        let p = get("furcate-principals");
        assert!(p.contains("printf '%s@node-a\\n'") && p.contains("printf '%s\\n' \"$1\""));
        assert_eq!(get("furcate_ca.pub"), "ssh-ed25519 AAAA\n");
    }

    #[test]
    fn without_a_revocation_list_sshd_is_not_pointed_at_one() {
        let f = render("ssh-ed25519 AAAA", None, &names()).unwrap();
        assert!(!f.files.iter().any(|(p, b, _)| p == "furcate_ca.krl" || String::from_utf8_lossy(b).contains("RevokedKeys")));
    }

    #[test]
    fn a_name_that_could_break_the_script_is_refused() {
        assert!(render("ssh-ed25519 AAAA", None, &["a;rm -rf /".into()]).is_err());
        assert!(render("ssh-ed25519 AAAA", None, &[]).is_err());
    }

    #[test]
    fn a_configuration_sshd_refuses_is_put_back() {
        let root = std::env::temp_dir().join(format!("furcate-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sshd_config.d")).unwrap();
        std::fs::write(root.join("furcate_ca.pub"), "old\n").unwrap();
        let f = render("ssh-ed25519 AAAA", None, &names()).unwrap();
        let e = apply(&root, &f, &|| bail!("bad")).unwrap_err();
        assert!(format!("{e:#}").contains("put back"));
        assert_eq!(std::fs::read_to_string(root.join("furcate_ca.pub")).unwrap(), "old\n");
        assert!(!root.join(DROPIN).exists());
        assert!(apply(&root, &f, &|| Ok(())).unwrap());
        assert!(!apply(&root, &f, &|| Ok(())).unwrap(), "a second run changes nothing");
        let _ = std::fs::remove_dir_all(&root);
    }
}
