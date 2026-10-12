//! furcate-overlay: the small network services a node runs for the overlay.
//!
//!   furcate-overlay names     answer `<member>.<site>.internal` from this
//!                             node's own peer set, on its overlay address
//!   furcate-overlay reflect   tell a sender the address its packet came from
//!                             (STUN Binding), on a node with a public address
//!   furcate-overlay observe   ask a reflector what this machine looks like
//!                             from outside
//!   furcate-overlay verify    check one member's signed binding against the
//!                             anchors, for programs that cannot verify Ed25519
//!                             themselves (the blind relay)
//!
//! One binary rather than four because each is a few dozen lines over code in
//! `furcate_net`, and they ship together or not at all. No subcommand changes
//! anything on the host: none configures an interface, a route or a resolver.
//! The units that run them ship disabled, and enabling one is the operator's
//! decision per host.

use furcate_net::lock::Anchors;
use furcate_net::names::{answer, Member, Zone};
use furcate_net::overlay::{Hint, Peer};
use furcate_net::punch;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage:
  furcate-overlay names   [--listen ADDR:PORT] [--site NAME] [--peers FILE]
                          [--self-id ID] [--self-name NAME] [--self-addr ADDR]
  furcate-overlay reflect [--listen ADDR:PORT]
  furcate-overlay observe --reflector HOST:PORT [--wg-port PORT]
  furcate-overlay verify  [--anchors FILE] < binding.json

Defaults come from the environment, which the units read from
/etc/furcate/overlay.env: FURCATE_OVERLAY_SITE, FURCATE_OVERLAY_ADDR,
FURCATE_OVERLAY_PEERS, FURCATE_OVERLAY_NODE_ID.";

const DEFAULT_PEERS: &str = "/var/lib/furcate/wg-plan-peers.json";
const DEFAULT_ANCHORS: &str = "/etc/furcate/overlay-anchors.json";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `--key value` from the arguments, else the environment variable, else none.
fn opt(args: &[String], key: &str, env: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == key)
        .map(|w| w[1].clone())
        .or_else(|| std::env::var(env).ok().filter(|v| !v.is_empty()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    let r = match args.first().map(String::as_str) {
        Some("names") => names(rest),
        Some("reflect") => reflect(rest),
        Some("observe") => observe(rest),
        Some("verify") => return verify(rest),
        _ => Err(USAGE.to_string()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("furcate-overlay: {e}");
            ExitCode::from(2)
        }
    }
}

// ---- names ----------------------------------------------------------------

fn short_hostname() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    Some(raw.trim().split('.').next()?.to_ascii_lowercase())
}

/// What the agent recorded about this node beside the peer set: the id and the
/// name it publishes to its peers. Absent before the agent has published.
fn own_entry(peers_path: &str) -> Option<furcate_net::names::Own> {
    let raw = std::fs::read(furcate_net::names::own_path_for(peers_path)).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// This node's own id and name, in order of who decides: an explicit flag or
/// overlay.env, then what the agent publishes to peers, then the host name.
fn own_id_and_name(args: &[String], peers_path: &str) -> (Option<String>, Option<String>) {
    let own = own_entry(peers_path);
    let id = opt(args, "--self-id", "FURCATE_OVERLAY_NODE_ID")
        .or_else(|| own.as_ref().map(|o| o.node_id.clone()).filter(|i| !i.is_empty()));
    let name = match opt(args, "--self-name", "FURCATE_OVERLAY_NAME") {
        Some(n) => Some(n),
        None => match own {
            Some(o) => o.name,
            None => short_hostname(),
        },
    };
    (id, name)
}

/// Build the zone from the peer file and this node's own entry.
///
/// A peer file that cannot be read is an error the caller reports, not an
/// empty zone: answering NXDOMAIN for every member because a file was
/// unreadable would look exactly like every member having lapsed.
fn load_zone(site: &str, peers_path: &str, me: &(Option<String>, Option<String>, Option<String>)) -> Result<Zone, String> {
    let peers: Vec<Peer> = match std::fs::read(peers_path) {
        Ok(raw) => serde_json::from_slice(&raw).map_err(|e| format!("{peers_path} is not a peer set: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{peers_path} cannot be read: {e}")),
    };
    let (id, name, addr) = me;
    // Read with the peer set on every reload, so the name this node answers
    // to follows the one it publishes without a restart.
    let (own_id, own_name) = own_id_and_name(&[], peers_path);
    let id = id.clone().or(own_id);
    let name = name.clone().or(own_name);
    let mut members: Vec<Member> = Vec::new();
    if let Some(addr) = addr {
        members.push(Member {
            node_id: id.as_deref().unwrap_or(""),
            name: name.as_deref(),
            overlay_addr: addr,
            valid_until: None,
        });
    }
    members.extend(peers.iter().map(Member::from));
    Zone::build(site, members)
}

fn names(args: &[String]) -> Result<(), String> {
    let site = opt(args, "--site", "FURCATE_OVERLAY_SITE")
        .ok_or("no site name: set FURCATE_OVERLAY_SITE in /etc/furcate/overlay.env or pass --site")?;
    let self_addr = opt(args, "--self-addr", "FURCATE_OVERLAY_ADDR");
    let listen = match opt(args, "--listen", "FURCATE_OVERLAY_NAMES_LISTEN") {
        Some(l) => l,
        // The overlay address, not a wildcard: this answers members of the
        // overlay and nothing on any other interface.
        None => format!(
            "{}:53",
            self_addr
                .as_deref()
                .and_then(|a| a.split('/').next())
                .ok_or("no listen address: set FURCATE_OVERLAY_ADDR (this node's fur0 address) or pass --listen")?
        ),
    };
    let peers_path = opt(args, "--peers", "FURCATE_OVERLAY_PEERS").unwrap_or_else(|| DEFAULT_PEERS.into());
    // Explicit settings only; the rest is read with the peer set (load_zone).
    let me = (
        opt(args, "--self-id", "FURCATE_OVERLAY_NODE_ID"),
        opt(args, "--self-name", "FURCATE_OVERLAY_NAME"),
        self_addr.map(|a| a.split('/').next().unwrap_or(&a).to_string()),
    );

    let sock = UdpSocket::bind(&listen).map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    let mut zone = load_zone(&site, &peers_path, &me)?;
    let mut stamp = std::fs::metadata(&peers_path).and_then(|m| m.modified()).ok();
    eprintln!("furcate-overlay names: {} on {listen}, {} name(s)", zone.origin(), zone.len());
    for (n, why) in &zone.withheld {
        eprintln!("  withheld {n}: {why}");
    }

    let mut buf = [0u8; 512];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("receive failed: {e}");
                continue;
            }
        };
        // Re-read the peer set when it changes. Checked per query because a
        // query is rare and a stat is cheap; a timer would be one more thing.
        let current = std::fs::metadata(&peers_path).and_then(|m| m.modified()).ok();
        if current != stamp {
            match load_zone(&site, &peers_path, &me) {
                Ok(z) => {
                    eprintln!("reloaded: {} name(s), {} withheld", z.len(), z.withheld.len());
                    for (n, why) in &z.withheld {
                        eprintln!("  withheld {n}: {why}");
                    }
                    zone = z;
                    stamp = current;
                }
                // Keep answering from the last good zone, and say so: the
                // same last-known-good rule the peer set itself follows.
                Err(e) => eprintln!("keeping the previous zone: {e}"),
            }
        }
        if let Some(resp) = answer(&zone, &buf[..n], now()) {
            let _ = sock.send_to(&resp, from);
        }
    }
}

// ---- reflect / observe ----------------------------------------------------

fn reflect(args: &[String]) -> Result<(), String> {
    let listen = opt(args, "--listen", "FURCATE_OVERLAY_REFLECT_LISTEN")
        .unwrap_or_else(|| format!("0.0.0.0:{}", punch::REFLECT_PORT));
    let sock = UdpSocket::bind(&listen).map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    eprintln!("furcate-overlay reflect on {listen}");
    // A count, logged occasionally, rather than a line per packet: on a public
    // address the log would otherwise be whatever strangers send it.
    let (mut answered, mut dropped) = (0u64, 0u64);
    loop {
        match punch::reflect_once(&sock) {
            Ok(Some(_)) => answered += 1,
            Ok(None) => dropped += 1,
            Err(e) => eprintln!("reflect: {e}"),
        }
        if (answered + dropped) % 10_000 == 0 {
            eprintln!("reflect: {answered} answered, {dropped} not binding requests");
        }
    }
}

fn observe(args: &[String]) -> Result<(), String> {
    let r = opt(args, "--reflector", "FURCATE_OVERLAY_REFLECTOR").ok_or("--reflector HOST:PORT is required")?;
    let target: SocketAddr = r
        .to_socket_addrs()
        .map_err(|e| format!("{r}: {e}"))?
        .next()
        .ok_or_else(|| format!("{r} resolves to nothing"))?;
    let sock = UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| e.to_string())?;
    let seen = punch::observe(&sock, target, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    match opt(args, "--wg-port", "FURCATE_WG_PORT").and_then(|p| p.parse().ok()) {
        Some(port) => println!("{}", punch::observed_endpoint(seen, port)),
        None => println!("{seen}"),
    }
    Ok(())
}

// ---- verify ---------------------------------------------------------------

/// Check a member's binding — its hint, as it publishes it — for a program
/// that is about to spend something on that member's behalf.
///
/// Stricter than peer admission in one way, on purpose: an unlocked overlay is
/// a refusal here, not a pass. Admission on an unlocked overlay is a stated,
/// visible choice; a relay allocating bandwidth to whoever asks, on the
/// strength of a check that is not running, is not a choice anyone made.
///
/// Prints one JSON line. Exit 0 verified, 1 refused, 2 could not check.
fn verify(args: &[String]) -> ExitCode {
    let path = opt(args, "--anchors", "FURCATE_OVERLAY_ANCHORS").unwrap_or_else(|| DEFAULT_ANCHORS.into());
    let say = |ok: bool, msg: &str, code: u8| {
        let mut m = serde_json::Map::new();
        m.insert("ok".into(), ok.into());
        m.insert(if ok { "state" } else { "why" }.into(), msg.into());
        println!("{}", serde_json::Value::Object(m));
        ExitCode::from(code)
    };
    let anchors = match std::fs::read_to_string(&path) {
        Err(e) => return say(false, &format!("{path} cannot be read ({e}); nothing can be verified"), 2),
        Ok(t) => match serde_json::from_str::<serde_json::Value>(&t)
            .map_err(|e| e.to_string())
            .and_then(|v| Anchors::from_json(&v).map_err(|e| e.to_string()))
        {
            Ok(a) => a,
            Err(e) => return say(false, &format!("{path}: {e}"), 2),
        },
    };
    let mut input = String::new();
    if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input) {
        return say(false, &format!("cannot read the binding: {e}"), 2);
    }
    let hint: Hint = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(e) => return say(false, &format!("not a binding: {e}"), 1),
    };
    match check(&anchors, &hint, now()) {
        Ok(state) => say(true, &state, 0),
        Err(why) => say(false, &why, 1),
    }
}

fn check(anchors: &Anchors, hint: &Hint, now: u64) -> Result<String, String> {
    if !anchors.state().is_locked() {
        return Err(format!(
            "this overlay is {}; with no anchors nothing can be verified, so nothing is allocated",
            anchors.state().describe()
        ));
    }
    // A leased node is checked through its hardware key, an unleased one
    // through its WireGuard key, by the same function peers use.
    furcate_net::lease::verify_hint(anchors, hint, now, furcate_net::lease::DEFAULT_CEILING)
        .map(|s| s.describe())
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_net::lock::{self, Claim};
    use furcate_net::lock::Anchor;
    use furcate_net::overlay::Tier;

    fn signed(not_after: u64) -> (Anchors, Hint) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut anchors = Anchors::new();
        anchors
            .trust(&Anchor { key_id: "site".into(), public_key: hex::encode(key.verifying_key().to_bytes()) })
            .unwrap();
        let mut h = Hint {
            node_id: "furcate:node:abc".into(),
            public_key: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=".into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.5/32".into(),
            tier: Tier::Platform,
            seen_at: 0, lease: None,
            authorization: None,
            name: None,
            observed: vec![],
        };
        h.authorization = Some(lock::authorize(
            "site",
            &key,
            &Claim { node_id: &h.node_id, public_key: &h.public_key, tier: h.tier.as_str(), not_after },
        ));
        (anchors, h)
    }

    #[test]
    fn a_signed_binding_verifies_and_a_doctored_one_does_not() {
        let (a, h) = signed(2_000);
        assert!(check(&a, &h, 1_000).is_ok());
        let mut other = h.clone();
        other.public_key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".into();
        assert!(check(&a, &other, 1_000).is_err(), "a binding is for one key");
        assert!(check(&a, &h, 2_000).unwrap_err().contains("authorized until"));
        let mut bare = h;
        bare.authorization = None;
        assert!(check(&a, &bare, 1_000).is_err());
    }

    #[test]
    fn an_unlocked_overlay_allocates_nothing() {
        let (_, h) = signed(2_000);
        assert!(check(&Anchors::new(), &h, 1_000).unwrap_err().contains("nothing is allocated"));
    }
}
