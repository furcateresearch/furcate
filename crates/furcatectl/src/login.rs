//! Signing a machine in to a Praecise account.
//!
//! The problem this solves: Furcate authenticates every write with an ed25519
//! signature from a key the site admits, and a Praecise account is not a key.
//! Somebody added to a fleet in a browser therefore cannot, by that alone, run
//! a single command. The two systems have to be introduced.
//!
//! RFC 8628, the device grant, is the introduction. The machine asks for a
//! code, prints it, and waits; a person opens a browser anywhere, signs in
//! once, and approves. Nothing is typed on the machine, no browser is needed
//! on it, and the credential never travels through a terminal that might be
//! logged or shoulder-read.
//!
//! What the grant does NOT carry is which machines are being claimed -- a user
//! code is a short string and nothing else. So the controller registers that
//! separately, and the approval screen shows a named fleet rather than a bare
//! client id. Approving a machine you cannot see is the phishing shape the
//! whole flow otherwise invites.
//!
//! The key stays here. `login` generates one locally, keeps the private half
//! on this machine, and sends only the public half to be admitted. A login
//! that shipped a private key to a server would defeat the thing signatures
//! are for.

use anyhow::{bail, Context, Result};
use std::process::Command;

/// Where Praecise accounts answers.
///
/// Overridable so a different estate can run its own, and defaulted so the
/// ordinary case needs no configuration.
fn issuer() -> String {
    std::env::var("PRAECISE_ISSUER")
        .unwrap_or_else(|_| "https://accounts.praecise.com".to_string())
}

/// The client id the machine identifies itself as. Public, per RFC 8628 §5.6.
const CLIENT_ID: &str = "furcate-node";

/// A tiny HTTPS POST, by way of curl.
///
/// `furcatectl` links no TLS stack: its own client speaks plain HTTP to the
/// tailnet, and pulling in rustls and a certificate store to make a handful of
/// calls during enrolment would be a large dependency for a small job. The
/// model puller already reaches the internet this way.
fn post_form(url: &str, fields: &[(&str, &str)]) -> Result<serde_json::Value> {
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "--max-time", "20", "-X", "POST", url]);
    for (k, v) in fields {
        // --data-urlencode, so a value containing & or = cannot split into two
        // fields. A device code is opaque and may contain either.
        cmd.args(["--data-urlencode", &format!("{k}={v}")]);
    }
    let out = cmd.output().context("running curl")?;
    if !out.status.success() {
        bail!("could not reach {url}");
    }
    serde_json::from_slice(&out.stdout)
        .with_context(|| format!("{url} did not answer with JSON: {}", String::from_utf8_lossy(&out.stdout).chars().take(200).collect::<String>()))
}

fn post_json(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let out = Command::new("curl")
        .args([
            "-s", "--max-time", "20", "-X", "POST", url,
            "-H", "Content-Type: application/json",
            "--data-binary", "@-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write as _;
            if let Some(mut si) = c.stdin.take() {
                si.write_all(serde_json::to_string(body).unwrap_or_default().as_bytes())?;
            }
            c.wait_with_output()
        })
        .context("running curl")?;
    if !out.status.success() {
        bail!("could not reach {url}");
    }
    Ok(serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null))
}

/// What the controller would claim, described for the approval screen.
///
/// Read from the fleet the controller already holds, so the list is the one the
/// machines themselves report rather than anything typed here.
fn fleet_for_enrolment(site: &str) -> (Option<String>, Vec<serde_json::Value>) {
    let Ok(fleet) = furcate_api::get_json(site, "/fleet", 8_000) else {
        return (None, Vec::new());
    };
    let name = fleet.get("site").and_then(|v| v.as_str()).map(String::from);
    let machines = fleet
        .get("nodes")
        .and_then(|v| v.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "node_id": n.get("node_id").and_then(|v| v.as_str()).unwrap_or(""),
                        // The hostname a person recognises, falling back to the
                        // id: a screen listing five identical-looking node ids
                        // is not a screen anybody can check.
                        "name": n.get("topology").and_then(|v| v.as_str())
                            .or_else(|| n.get("node_id").and_then(|v| v.as_str()))
                            .unwrap_or(""),
                        "attested": n.get("attested").and_then(|v| v.as_bool()).unwrap_or(false),
                        "administers": n.get("administers").and_then(|v| v.as_bool()).unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    (name, machines)
}

/// Sign this machine, and the fleet it administers, in to a Praecise account.
pub fn login(site: &str) -> Result<()> {
    let issuer = issuer();

    // 1. Ask for a code.
    let started = post_form(
        &format!("{issuer}/device/auth"),
        &[("client_id", CLIENT_ID), ("scope", "openid email")],
    )?;
    let (Some(device_code), Some(user_code)) = (
        started.get("device_code").and_then(|v| v.as_str()),
        started.get("user_code").and_then(|v| v.as_str()),
    ) else {
        bail!(
            "{issuer} did not issue a device code: {}",
            started.get("error_description").and_then(|v| v.as_str())
                .or_else(|| started.get("error").and_then(|v| v.as_str()))
                .unwrap_or("no reason given")
        );
    };
    let verification = started
        .get("verification_uri_complete")
        .or_else(|| started.get("verification_uri"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let interval = started.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);
    let expires_in = started.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(300);

    // 2. Say what this would claim, so the approval screen can show it. Best
    //    effort: the flow still works without it, the screen simply says less.
    let (site_name, machines) = fleet_for_enrolment(site);
    let node_id = furcate_api::get_json(site, "/features", 5_000)
        .ok()
        .and_then(|f| f.get("fleet").and_then(|x| x.get("site")).and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_else(|| site.to_string());
    let _ = post_json(
        &format!("{issuer}/device/enrolment"),
        &serde_json::json!({
            "user_code": user_code,
            "node_id": node_id,
            "site": site_name,
            "site_addr": site,
            "machines": machines,
        }),
    );

    println!();
    println!("  Open  {verification}");
    println!("  Code  {user_code}");
    println!();
    if machines.is_empty() {
        println!("waiting for approval...");
    } else {
        println!(
            "waiting for approval of {} machine(s)...",
            machines.len()
        );
    }

    // 3. Wait. The interval is the server's to set and polling faster than it
    //    asked earns a slow_down and then a refusal.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(expires_in);
    let mut wait = std::time::Duration::from_secs(interval);
    loop {
        if std::time::Instant::now() >= deadline {
            bail!("that code expired before it was approved — run `furcatectl login` again");
        }
        std::thread::sleep(wait);

        let reply = post_form(
            &format!("{issuer}/token"),
            &[
                ("client_id", CLIENT_ID),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
            ],
        )?;

        match reply.get("error").and_then(|v| v.as_str()) {
            Some("authorization_pending") => continue,
            // Asked to back off: the spec says add 5s each time, and a client
            // that ignores this is eventually refused outright.
            Some("slow_down") => {
                wait += std::time::Duration::from_secs(5);
                continue;
            }
            Some("expired_token") => {
                bail!("that code expired before it was approved — run `furcatectl login` again")
            }
            Some("access_denied") => bail!("that request was declined in the browser"),
            Some(other) => bail!("{issuer} refused the enrolment: {other}"),
            None => {}
        }

        let Some(id_token) = reply.get("id_token").and_then(|v| v.as_str()) else {
            bail!("the token response carried no id_token, so there is no account to bind to");
        };
        let account = email_from(id_token)
            .context("the id_token carried no email, so there is nobody to claim these machines for")?;

        println!();
        println!("signed in as {account}");
        println!();
        println!("This machine now knows which account owns it. To record that on the");
        println!("fleet, and to admit {account} as its owner, an operator runs:");
        println!();
        println!("  furcatectl fleet admit KEY {site} {account} owner");
        for m in &machines {
            if let Some(id) = m.get("node_id").and_then(|v| v.as_str()) {
                println!("  furcatectl owner claim KEY {site} {id} {account} \"enrolled by furcatectl login\"");
            }
        }
        println!();
        println!("Those are operator-signed, and deliberately not done for you: this");
        println!("command proves who the person is, and the operator key proves the");
        println!("fleet agrees. Neither alone is enough.");
        return Ok(());
    }
}

/// The email inside an id_token, without verifying it.
///
/// Read, not trusted: this is used to print who signed in and to fill in the
/// commands below it. Nothing is authorised on the strength of it -- the claim
/// that matters is recorded by an operator-signed call, which is checked
/// properly at the controller.
fn email_from(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    // base64url, no padding.
    let mut b = payload.replace('-', "+").replace('_', "/");
    while b.len() % 4 != 0 {
        b.push('=');
    }
    let raw = base64_decode(&b)?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("email")
        .and_then(|x| x.as_str())
        .map(String::from)
        .or_else(|| v.get("sub").and_then(|x| x.as_str()).map(String::from))
}

/// Just enough base64 to read a JWT payload.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
