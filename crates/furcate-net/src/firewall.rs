//! A node's input firewall, rendered from its configuration.
//!
//! A board OS that ships nftables with no ruleset leaves the policy to the
//! node: this renders it. Default deny on input; established and related
//! traffic back in; loopback; the ICMP a network needs to work; ssh; the
//! overlay's WireGuard port; the overlay announcement on LAN interfaces;
//! the agent on the overlay only; the model gateway where the node declares
//! it; the leaf link on the interfaces the node declares for leaves; and the
//! ports the node's configuration opens.
//!
//! Everything lives in one table of its own, `inet furcate`, replaced whole
//! in one `nft -f` transaction, so the rules are never half-applied and no
//! other table on the machine is touched. Forwarding and output are not
//! filtered here.
//!
//! Rendering is pure and tested here. Applying it, with a rollback timer
//! armed before the change and the overlay checked after it, is
//! `furcatectl firewall apply`.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// The table this module owns, in the `inet` family.
pub const TABLE: &str = "furcate";

/// Where a node declares its firewall.
pub const CONFIG_PATH: &str = "/etc/furcate/firewall.json";

pub const SSH_PORT: u16 = 22;
/// The node agent.
pub const AGENT_PORT: u16 = 7616;
/// The model gateway.
pub const MODEL_GATEWAY_PORT: u16 = 8750;
/// The leaf link, where leaves on the LAN reach their head.
pub const LEAF_LINK_PORT: u16 = 7781;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Where a port is open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    /// The overlay interface only.
    Overlay,
    /// The declared LAN interfaces only.
    Lan,
    /// The overlay and the LAN interfaces.
    Both,
}

/// A port the node's configuration opens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    pub port: u16,
    pub proto: Proto,
    pub on: Zone,
    /// What it is for, rendered as the rule's comment.
    pub why: String,
}

fn default_overlay_interface() -> String {
    "fur0".to_string()
}
fn default_announce_port() -> u16 {
    crate::announce::DEFAULT_PORT
}
fn default_true() -> bool {
    true
}
fn default_gateway() -> Option<Zone> {
    Some(Zone::Overlay)
}

/// `/etc/furcate/firewall.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// The LAN interfaces, by name.
    pub lan: Vec<String>,
    #[serde(default = "default_overlay_interface")]
    pub overlay_interface: String,
    /// The overlay's WireGuard listen port. Absent: derived from the same
    /// configuration the overlay manager plans the interface from
    /// (`FURCATE_WG_PORT`, else the WireGuard default), never from the live
    /// interface, which does not exist yet at boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_port: Option<u16>,
    /// The overlay announcement's UDP port, open on LAN interfaces.
    #[serde(default = "default_announce_port")]
    pub announce_port: u16,
    /// Where the model gateway is reachable; `null` closes it.
    #[serde(default = "default_gateway")]
    pub model_gateway: Option<Zone>,
    /// The interfaces leaves attach on; each must be a LAN interface. Empty:
    /// the leaf link is closed.
    #[serde(default)]
    pub leaf_link: Vec<String>,
    /// DHCP and mDNS replies on the LAN interfaces, which a LAN address and a
    /// `.local` name need.
    #[serde(default = "default_true")]
    pub lan_services: bool,
    #[serde(default)]
    pub open: Vec<Opening>,
}

impl FirewallConfig {
    pub fn parse(text: &str) -> Result<FirewallConfig, String> {
        let c: FirewallConfig = serde_json::from_str(text).map_err(|e| format!("not a firewall configuration: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<(), String> {
        for name in self.lan.iter().chain(std::iter::once(&self.overlay_interface)).chain(&self.leaf_link) {
            interface_name(name)?;
        }
        if self.lan.contains(&self.overlay_interface) {
            return Err(format!("{} is the overlay interface and cannot also be a LAN interface", self.overlay_interface));
        }
        for i in &self.leaf_link {
            if !self.lan.contains(i) {
                return Err(format!("the leaf link may open only on LAN interfaces, and {i} is not one"));
            }
        }
        if self.overlay_port == Some(0) || self.announce_port == 0 {
            return Err("port 0 is not a port".to_string());
        }
        for o in &self.open {
            if o.port == 0 {
                return Err(format!("opening {:?}: port 0 is not a port", o.why));
            }
            if o.why.trim().is_empty() || o.why.contains(['"', '\n', '\\']) {
                return Err(format!("opening port {}: `why` must be a plain non-empty line", o.port));
            }
        }
        Ok(())
    }
}

/// An interface name nft can take verbatim: what Linux allows, minus what
/// would need quoting.
fn interface_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(format!("{name:?} is not an interface name"))
    }
}

fn set_of(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
    format!("{{ {} }}", quoted.join(", "))
}

/// The ruleset for `config`, with the overlay listening on `overlay_port`.
///
/// One transaction that creates the table if absent, deletes it, and
/// declares it again, so applying it replaces the table whole whether or not
/// it existed.
pub fn render(config: &FirewallConfig, overlay_port: u16) -> String {
    let ov = &config.overlay_interface;
    let lan = set_of(&config.lan);
    let mut r = String::new();
    let _ = writeln!(r, "# Rendered by furcatectl firewall from {CONFIG_PATH}. Replaced whole on each apply.");
    let _ = writeln!(r, "table inet {TABLE} {{}}");
    let _ = writeln!(r, "delete table inet {TABLE}");
    let _ = writeln!(r, "table inet {TABLE} {{");
    let _ = writeln!(r, "\tchain input {{");
    let _ = writeln!(r, "\t\ttype filter hook input priority filter; policy drop;");
    let _ = writeln!(r, "\t\tiif \"lo\" accept");
    let _ = writeln!(r, "\t\tct state established,related accept");
    let _ = writeln!(r, "\t\tct state invalid drop");
    let _ = writeln!(
        r,
        "\t\ticmp type {{ echo-request, destination-unreachable, time-exceeded, parameter-problem }} accept"
    );
    let _ = writeln!(
        r,
        "\t\ticmpv6 type {{ echo-request, destination-unreachable, packet-too-big, time-exceeded, \
         parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept"
    );
    let _ = writeln!(r, "\t\ttcp dport {SSH_PORT} accept comment \"ssh\"");
    let _ = writeln!(r, "\t\tudp dport {overlay_port} accept comment \"overlay wireguard\"");
    if !config.lan.is_empty() {
        let _ = writeln!(r, "\t\tiifname {lan} udp dport {} accept comment \"overlay announce\"", config.announce_port);
        if config.lan_services {
            let _ = writeln!(r, "\t\tiifname {lan} udp dport {{ 68, 546 }} accept comment \"dhcp client\"");
            let _ = writeln!(r, "\t\tiifname {lan} udp dport 5353 accept comment \"mdns\"");
        }
    }
    let _ = writeln!(r, "\t\tiifname \"{ov}\" tcp dport {AGENT_PORT} accept comment \"furcated\"");
    if let Some(zone) = &config.model_gateway {
        for line in zone_rules(zone, ov, &config.lan, Proto::Tcp, MODEL_GATEWAY_PORT, "model gateway") {
            let _ = writeln!(r, "\t\t{line}");
        }
    }
    if !config.leaf_link.is_empty() {
        let _ = writeln!(
            r,
            "\t\tiifname {} tcp dport {LEAF_LINK_PORT} accept comment \"leaf link\"",
            set_of(&config.leaf_link)
        );
    }
    for o in &config.open {
        for line in zone_rules(&o.on, ov, &config.lan, o.proto, o.port, &o.why) {
            let _ = writeln!(r, "\t\t{line}");
        }
    }
    let _ = writeln!(r, "\t}}");
    let _ = writeln!(r, "}}");
    r
}

fn zone_rules(zone: &Zone, overlay: &str, lan: &[String], proto: Proto, port: u16, why: &str) -> Vec<String> {
    let p = proto.as_str();
    let on_overlay = format!("iifname \"{overlay}\" {p} dport {port} accept comment \"{why}\"");
    let on_lan = format!("iifname {} {p} dport {port} accept comment \"{why}\"", set_of(lan));
    match zone {
        Zone::Overlay => vec![on_overlay],
        Zone::Lan if lan.is_empty() => vec![],
        Zone::Lan => vec![on_lan],
        Zone::Both if lan.is_empty() => vec![on_overlay],
        Zone::Both => vec![on_overlay, on_lan],
    }
}

/// What restores the table as it was: the listing of the previous table, or
/// nothing when there was none, either way as one replacing transaction.
pub fn restore_script(previous_listing: Option<&str>) -> String {
    let mut r = format!("table inet {TABLE} {{}}\ndelete table inet {TABLE}\n");
    if let Some(prev) = previous_listing.filter(|p| !p.trim().is_empty()) {
        r.push_str(prev);
        if !prev.ends_with('\n') {
            r.push('\n');
        }
    }
    r
}

/// The newest handshake in `wg show <iface> latest-handshakes` output, in
/// Unix seconds; `None` when no peer has completed one.
pub fn latest_handshake(wg_output: &str) -> Option<u64> {
    wg_output
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|t| t.parse::<u64>().ok())
        .filter(|t| *t > 0)
        .max()
}

/// WireGuard rejects a session older than this; a newest handshake older
/// than it means the overlay is not up.
pub const HANDSHAKE_FRESH_SECS: u64 = 180;

#[cfg(test)]
mod tests {
    use super::*;

    fn pi() -> FirewallConfig {
        FirewallConfig::parse(
            r#"{"lan": ["end0", "wld0"], "leaf_link": ["end0", "wld0"], "model_gateway": "both",
                "open": [{"port": 53, "proto": "udp", "on": "overlay", "why": "overlay names"}]}"#,
        )
        .unwrap()
    }

    #[test]
    fn the_pi_policy_renders_every_agreed_rule_and_nothing_wider() {
        let r = render(&pi(), 51820);
        for want in [
            "table inet furcate {}\ndelete table inet furcate\ntable inet furcate {",
            "type filter hook input priority filter; policy drop;",
            "iif \"lo\" accept",
            "ct state established,related accept",
            "tcp dport 22 accept",
            "udp dport 51820 accept comment \"overlay wireguard\"",
            "iifname { \"end0\", \"wld0\" } udp dport 51821 accept comment \"overlay announce\"",
            "iifname \"fur0\" tcp dport 7616 accept comment \"furcated\"",
            "iifname \"fur0\" tcp dport 8750 accept comment \"model gateway\"",
            "iifname { \"end0\", \"wld0\" } tcp dport 8750 accept comment \"model gateway\"",
            "iifname { \"end0\", \"wld0\" } tcp dport 7781 accept comment \"leaf link\"",
            "iifname \"fur0\" udp dport 53 accept comment \"overlay names\"",
        ] {
            assert!(r.contains(want), "missing {want:?} in\n{r}");
        }
        // The agent never on the LAN, the leaf link never on the overlay.
        assert_eq!(r.matches("dport 7616").count(), 1);
        assert_eq!(r.matches("dport 7781").count(), 1);
        // Input only: nothing here filters forwarding or output.
        assert!(!r.contains("hook forward") && !r.contains("hook output"));
        assert!(!r.contains("flush ruleset"), "other tables are not this module's");
    }

    #[test]
    fn defaults_keep_the_gateway_on_the_overlay_and_the_leaf_link_closed() {
        let c = FirewallConfig::parse(r#"{"lan": ["eth0"]}"#).unwrap();
        let r = render(&c, 41000);
        assert!(r.contains("udp dport 41000 accept"));
        assert!(r.contains("iifname \"fur0\" tcp dport 8750"));
        assert!(!r.contains("{ \"eth0\" } tcp dport 8750"));
        assert!(!r.contains("7781"));
        assert!(r.contains("udp dport 5353"));
        let closed = FirewallConfig::parse(r#"{"lan": ["eth0"], "model_gateway": null, "lan_services": false}"#).unwrap();
        let r = render(&closed, 41000);
        assert!(!r.contains("8750") && !r.contains("5353") && !r.contains("dport { 68, 546 }"));
    }

    #[test]
    fn a_node_without_a_lan_opens_nothing_on_one() {
        let c = FirewallConfig::parse(r#"{"lan": [], "model_gateway": "both"}"#).unwrap();
        let r = render(&c, 51820);
        assert!(!r.contains("51821") && !r.contains("iifname { }"));
        assert_eq!(r.matches("dport 8750").count(), 1);
    }

    #[test]
    fn bad_configurations_are_refused() {
        for (bad, why) in [
            (r#"{"lan": ["end0"], "leaf_link": ["wld0"]}"#, "only on LAN interfaces"),
            (r#"{"lan": ["fur0"]}"#, "overlay interface"),
            (r#"{"lan": ["end0\"; flush ruleset"]}"#, "not an interface name"),
            (r#"{"lan": ["end0"], "open": [{"port": 9, "proto": "tcp", "on": "lan", "why": "a\"b"}]}"#, "plain"),
            (r#"{"lan": ["end0"], "open": [{"port": 0, "proto": "tcp", "on": "lan", "why": "x"}]}"#, "port 0"),
            (r#"{"lan": ["end0"], "surprise": true}"#, "unknown field"),
            (r#"{}"#, "missing field"),
        ] {
            let e = FirewallConfig::parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn the_restore_script_replaces_the_table_with_what_was_there() {
        assert_eq!(restore_script(None), "table inet furcate {}\ndelete table inet furcate\n");
        let prev = "table inet furcate {\n\tchain input {\n\t}\n}";
        let s = restore_script(Some(prev));
        assert!(s.starts_with("table inet furcate {}\ndelete table inet furcate\ntable inet furcate {"));
        assert!(s.ends_with("}\n"));
    }

    #[test]
    fn the_newest_handshake_is_read_from_wg_output() {
        let out = "AAAA=\t1791800000\nBBBB=\t0\nCCCC=\t1791800100\n";
        assert_eq!(latest_handshake(out), Some(1_791_800_100));
        assert_eq!(latest_handshake("AAAA=\t0\n"), None);
        assert_eq!(latest_handshake(""), None);
    }
}
