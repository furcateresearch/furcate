//! The data plane, and the smallest possible amount of it.
//!
//! WireGuard is the substrate for the reasons everybody else picks it: it is in
//! the kernel, it is small enough to have been audited properly, it negotiates
//! no ciphers, and it has no dial to set wrongly. None of that is reimplemented
//! here and none of it should be — a second WireGuard would be the least
//! defensible use of the effort available.
//!
//! What this module does is turn a resolved peer set into the exact
//! configuration that expresses it, and work out the difference between that and
//! what the interface currently holds.
//!
//! ## Why a plan rather than a command
//!
//! Nothing here touches an interface. Creating one is a net-admin operation, the
//! agent does not hold that capability, and giving it one to save a file write
//! would repeat a mistake this host has now avoided five times. So the agent
//! computes what should change and something privileged applies it — the same
//! split already used for the energy counters, the management controller, the
//! interface wake setting and the disks.
//!
//! Computing a *difference* rather than rewriting the configuration matters for
//! one specific reason: replacing a WireGuard interface tears down every
//! session on it. A node whose peer list gained one entry should not lose
//! connectivity to the others while that is applied.
//!
//! ## Allowed IPs are per-peer and narrow
//!
//! Each peer is allowed exactly its own overlay address and nothing else.
//! WireGuard treats `AllowedIPs` as both a routing table and an access control
//! list, so a peer allowed a wide range can source traffic claiming to be
//! anything inside it. A mesh of single addresses cannot express that mistake.

use crate::overlay::Peer;
use serde::{Deserialize, Serialize};

/// Default listening port. The WireGuard convention.
pub const DEFAULT_PORT: u16 = 51820;

/// How often to send keepalives to a peer behind NAT.
///
/// Twenty-five seconds is the WireGuard-documented figure: comfortably inside
/// the shortest NAT mapping timeouts seen in the wild, and infrequent enough to
/// be irrelevant to power.
pub const KEEPALIVE_SECS: u16 = 25;

/// Whether a string is a WireGuard key as the tooling spells one.
///
/// Base64 of 32 bytes: 44 characters ending in `=`. Checked because an invalid
/// key is accepted into a configuration file and rejected at load time, by
/// which point the interface is half-configured and the error is a long way
/// from its cause.
pub fn is_key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

/// One peer, in the terms the kernel wants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    /// Exactly this peer's overlay address. Never a range.
    pub allowed_ips: String,
    pub keepalive_secs: u16,
}

/// What one interface should look like.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    /// This node's own overlay address, with prefix.
    pub address: String,
    pub listen_port: u16,
    pub peers: Vec<WgPeer>,
}

/// A single change to apply.
///
/// Enumerated rather than rendered as a config file, because applying a whole
/// file replaces the interface and drops every session on it. A node that
/// gained one peer should not lose the others while that happens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// The interface does not exist yet.
    CreateInterface { name: String, address: String, listen_port: u16 },
    AddPeer(WgPeer),
    /// Same key, different endpoint. Applied in place; sessions survive.
    UpdateEndpoint { public_key: String, endpoint: Option<String> },
    RemovePeer { public_key: String },
}

impl Change {
    /// Whether applying this interrupts existing traffic.
    ///
    /// Reported so a caller can decide when to apply it rather than discovering
    /// afterwards that a routine reconciliation dropped the fleet.
    pub fn is_disruptive(&self) -> bool {
        matches!(self, Change::CreateInterface { .. } | Change::RemovePeer { .. })
    }
}

/// Build the interface a resolved peer set implies.
///
/// Peers with no key are dropped rather than rendered: an unparseable key
/// reaches the kernel as a load failure with no indication of which entry
/// caused it.
pub fn interface_for(name: &str, address: &str, port: u16, peers: &[Peer]) -> Interface {
    Interface {
        name: name.to_string(),
        address: address.to_string(),
        listen_port: port,
        peers: peers
            .iter()
            .filter(|p| is_key(&p.public_key))
            .map(|p| WgPeer {
                public_key: p.public_key.clone(),
                endpoint: p.endpoint.clone(),
                // Narrow by construction. WireGuard treats AllowedIPs as both a
                // route and an access control list, so a wide range lets a peer
                // source traffic claiming to be anything inside it.
                allowed_ips: single_host(&p.overlay_addr),
                keepalive_secs: KEEPALIVE_SECS,
            })
            .collect(),
    }
}

/// Reduce an address to exactly one host.
///
/// A peer declaring `10.90.0.0/16` would otherwise be permitted to speak as
/// every node in the overlay.
fn single_host(addr: &str) -> String {
    let host = addr.split('/').next().unwrap_or(addr);
    if host.contains(':') {
        format!("{host}/128")
    } else {
        format!("{host}/32")
    }
}

/// What has to change to get from `current` to `desired`.
///
/// `current` is `None` when the interface does not exist. Ordering is
/// deliberate: additions and updates first, removals last, so a reconciliation
/// never leaves the node with fewer peers than it needs partway through.
pub fn plan(desired: &Interface, current: Option<&Interface>) -> Vec<Change> {
    let mut out = Vec::new();

    let Some(cur) = current else {
        out.push(Change::CreateInterface {
            name: desired.name.clone(),
            address: desired.address.clone(),
            listen_port: desired.listen_port,
        });
        out.extend(desired.peers.iter().cloned().map(Change::AddPeer));
        return out;
    };

    for want in &desired.peers {
        match cur.peers.iter().find(|p| p.public_key == want.public_key) {
            None => out.push(Change::AddPeer(want.clone())),
            Some(have) if have.endpoint != want.endpoint => {
                out.push(Change::UpdateEndpoint {
                    public_key: want.public_key.clone(),
                    endpoint: want.endpoint.clone(),
                });
            }
            Some(_) => {}
        }
    }

    for have in &cur.peers {
        if !desired.peers.iter().any(|p| p.public_key == have.public_key) {
            out.push(Change::RemovePeer { public_key: have.public_key.clone() });
        }
    }

    out
}

/// Render an interface as `wg setconf` input.
///
/// Used for the initial creation only; incremental changes go through
/// `wg set`, which does not disturb sessions. The private key is deliberately
/// absent — it is added by the privileged half from sealed storage, so the
/// agent never holds it and it never appears in anything the agent writes.
pub fn render_setconf(iface: &Interface) -> String {
    let mut s = format!("[Interface]\nListenPort = {}\n", iface.listen_port);
    for p in &iface.peers {
        s.push_str("\n[Peer]\n");
        s.push_str(&format!("PublicKey = {}\n", p.public_key));
        s.push_str(&format!("AllowedIPs = {}\n", p.allowed_ips));
        if let Some(e) = &p.endpoint {
            s.push_str(&format!("Endpoint = {e}\n"));
        }
        s.push_str(&format!("PersistentKeepalive = {}\n", p.keepalive_secs));
    }
    s
}

/// Parse `wg showconf` output back into an interface.
pub fn parse_showconf(name: &str, text: &str) -> Interface {
    let mut iface = Interface {
        name: name.to_string(),
        address: String::new(),
        listen_port: DEFAULT_PORT,
        peers: Vec::new(),
    };
    let mut current: Option<WgPeer> = None;

    for line in text.lines() {
        let t = line.trim();
        if t.eq_ignore_ascii_case("[peer]") {
            if let Some(p) = current.take() {
                iface.peers.push(p);
            }
            current = Some(WgPeer {
                public_key: String::new(),
                endpoint: None,
                allowed_ips: String::new(),
                keepalive_secs: 0,
            });
            continue;
        }
        let Some((k, v)) = t.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match (&mut current, k) {
            (None, "ListenPort") => iface.listen_port = v.parse().unwrap_or(DEFAULT_PORT),
            (Some(p), "PublicKey") => p.public_key = v.to_string(),
            (Some(p), "AllowedIPs") => p.allowed_ips = v.to_string(),
            (Some(p), "Endpoint") => p.endpoint = Some(v.to_string()),
            (Some(p), "PersistentKeepalive") => p.keepalive_secs = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    if let Some(p) = current.take() {
        iface.peers.push(p);
    }
    // A key is base64 and contains `=`, so the split above truncates it.
    // Recovering it from the original line is less fragile than teaching the
    // parser about padding.
    recover_keys(text, &mut iface);
    iface
}

/// Restore full base64 keys, which contain the character used as the separator.
fn recover_keys(text: &str, iface: &mut Interface) {
    let keys: Vec<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("PublicKey"))
        .map(|v| v.trim_start().trim_start_matches('=').trim().to_string())
        .collect();
    for (p, k) in iface.peers.iter_mut().zip(keys) {
        p.public_key = k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::{Source, Tier};

    const KEY_A: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";
    const KEY_B: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

    fn peer(id: &str, key: &str, endpoint: Option<&str>, addr: &str) -> Peer {
        Peer {
            node_id: id.into(),
            public_key: key.into(),
            endpoint: endpoint.map(String::from),
            overlay_addr: addr.into(),
            tier: Tier::Platform,
            source: Source::Hint,
            resolved_at: 0,
            name: None,
            valid_until: None,
            lease_until: None,
            candidates: vec![],
        }
    }

    fn iface(peers: &[Peer]) -> Interface {
        interface_for("fur0", "10.90.0.10/16", DEFAULT_PORT, peers)
    }

    #[test]
    fn a_key_is_checked_before_it_reaches_the_kernel() {
        // An invalid key is accepted into a config file and rejected at load
        // time, by which point the interface is half-configured and the error
        // is a long way from its cause.
        assert!(is_key(KEY_A));
        assert!(!is_key("not-a-key"));
        assert!(!is_key(""));
        assert!(!is_key(&"A".repeat(44)), "must end in =");
        // Real base64 of 32 bytes always pads to a single `=`. A 44-character
        // string ending in anything else is not one, and this exact mistake
        // silently dropped every peer using it while the tests read as passing
        // the validator.
        assert!(!is_key("QmFzZTY0dGVzdGtleWZvcnRlc3Rpbmc5ODc2NTQzMjE9"));
        assert!(!is_key(&format!("{}=", "A".repeat(50))), "wrong length");
    }

    #[test]
    fn a_peer_with_a_bad_key_is_dropped_rather_than_rendered() {
        let i = iface(&[peer("bad", "nonsense", None, "10.90.0.20/32")]);
        assert!(i.peers.is_empty());
    }

    #[test]
    fn every_peer_is_allowed_exactly_one_address() {
        // WireGuard treats AllowedIPs as a route AND an access control list, so
        // a peer allowed a range can source traffic claiming to be anything in
        // it. A peer declaring a /16 gets a /32.
        let i = iface(&[peer("a", KEY_A, None, "10.90.0.0/16")]);
        assert_eq!(i.peers[0].allowed_ips, "10.90.0.0/32");

        let v6 = iface(&[peer("b", KEY_B, None, "fd00::2/64")]);
        assert_eq!(v6.peers[0].allowed_ips, "fd00::2/128");
    }

    #[test]
    fn a_missing_interface_is_created_before_peers_are_added() {
        let want = iface(&[peer("a", KEY_A, Some("1.2.3.4:51820"), "10.90.0.20/32")]);
        let p = plan(&want, None);
        assert!(matches!(p[0], Change::CreateInterface { .. }));
        assert!(matches!(p[1], Change::AddPeer(_)));
    }

    #[test]
    fn adding_one_peer_does_not_disturb_the_others() {
        // The reason this computes a difference rather than rewriting: applying
        // a whole configuration replaces the interface and drops every session
        // on it.
        let have = iface(&[peer("a", KEY_A, Some("1.2.3.4:51820"), "10.90.0.20/32")]);
        let want = iface(&[
            peer("a", KEY_A, Some("1.2.3.4:51820"), "10.90.0.20/32"),
            peer("b", KEY_B, Some("1.2.3.5:51820"), "10.90.0.30/32"),
        ]);
        let p = plan(&want, Some(&have));
        assert_eq!(p.len(), 1);
        assert!(matches!(&p[0], Change::AddPeer(x) if x.public_key == KEY_B));
        assert!(!p[0].is_disruptive());
    }

    #[test]
    fn a_moved_peer_is_updated_in_place_rather_than_replaced() {
        // Same key, new address. Removing and re-adding would drop the session
        // for a peer that never went anywhere logically.
        let have = iface(&[peer("a", KEY_A, Some("1.2.3.4:51820"), "10.90.0.20/32")]);
        let want = iface(&[peer("a", KEY_A, Some("9.9.9.9:51820"), "10.90.0.20/32")]);
        let p = plan(&want, Some(&have));
        assert_eq!(
            p,
            vec![Change::UpdateEndpoint {
                public_key: KEY_A.into(),
                endpoint: Some("9.9.9.9:51820".into())
            }]
        );
        assert!(!p[0].is_disruptive());
    }

    #[test]
    fn removals_come_last_so_the_node_is_never_short_partway_through() {
        let have = iface(&[peer("a", KEY_A, None, "10.90.0.20/32")]);
        let want = iface(&[peer("b", KEY_B, None, "10.90.0.30/32")]);
        let p = plan(&want, Some(&have));
        assert!(matches!(p[0], Change::AddPeer(_)));
        assert!(matches!(p[1], Change::RemovePeer { .. }));
        assert!(p[1].is_disruptive());
    }

    #[test]
    fn an_unchanged_peer_set_plans_nothing() {
        // A reconciliation that always has work to do is one nobody can read.
        let have = iface(&[peer("a", KEY_A, Some("1.2.3.4:51820"), "10.90.0.20/32")]);
        assert!(plan(&have.clone(), Some(&have)).is_empty());
    }

    #[test]
    fn the_rendered_config_never_contains_a_private_key() {
        // It is added by the privileged half from sealed storage, so the agent
        // never holds it and it never appears in anything the agent writes.
        let s = render_setconf(&iface(&[peer("a", KEY_A, Some("1.2.3.4:51820"), "10.90.0.20/32")]));
        assert!(!s.to_lowercase().contains("privatekey"));
        assert!(s.contains(KEY_A));
        assert!(s.contains("AllowedIPs = 10.90.0.20/32"));
        assert!(s.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn showconf_round_trips_including_the_padding_in_keys() {
        // Keys are base64 and contain `=`, which is also the separator. A naive
        // split truncates every key in the file.
        let text = format!(
            "[Interface]\nListenPort = 51820\nPrivateKey = {KEY_B}\n\n\
             [Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.90.0.20/32\n\
             Endpoint = 1.2.3.4:51820\nPersistentKeepalive = 25\n"
        );
        let i = parse_showconf("fur0", &text);
        assert_eq!(i.listen_port, 51820);
        assert_eq!(i.peers.len(), 1);
        assert_eq!(i.peers[0].public_key, KEY_A, "the key must survive the parse");
        assert_eq!(i.peers[0].endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(i.peers[0].allowed_ips, "10.90.0.20/32");
    }

    #[test]
    fn an_empty_interface_parses_to_no_peers_rather_than_failing() {
        let i = parse_showconf("fur0", "[Interface]\nListenPort = 51820\n");
        assert!(i.peers.is_empty());
    }

    #[test]
    fn a_peer_with_no_endpoint_is_rendered_without_one() {
        // It cannot be dialled and it can still dial in. An empty Endpoint line
        // fails to parse and takes the whole configuration with it.
        let s = render_setconf(&iface(&[peer("a", KEY_A, None, "10.90.0.20/32")]));
        assert!(!s.contains("Endpoint"));
    }
}
