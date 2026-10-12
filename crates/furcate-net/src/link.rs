//! The wire, as the kernel sees it.
//!
//! Everything here comes from interface counters, which means it costs nothing
//! and disturbs nothing. That matters more than it sounds: the obvious way to
//! measure a link is to saturate it and see what happens, and on a site
//! carrying a validator that is a self-inflicted outage.
//!
//! Two distinctions do most of the work.
//!
//! **A link rate is not a connection speed.** `speed` is what the NIC
//! negotiated with the switch — 1000 Mb/s here — and says nothing about what
//! the ISP will carry. Reporting the first as the second is the most common
//! error in network dashboards and it makes a saturated 100 Mb uplink look
//! like a link running at 10 % utilisation.
//!
//! **Errors and drops are different faults.** CRC errors mean the bits arrived
//! corrupted: a cable, a connector, interference. Drops mean the bits arrived
//! fine and nobody picked them up: a queue overflowed, the host was too busy.
//! One is fixed by replacing a cable and the other by reducing load, so
//! collapsing them into "packet loss" throws away the diagnosis.

use serde::{Deserialize, Serialize};

/// What kind of interface this is.
///
/// Container bridges and veth pairs carry the same bytes twice and would
/// double every fleet total they were included in, so the kind is part of the
/// reading rather than a filter applied by whoever remembers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// A real NIC.
    Physical,
    /// Loopback.
    Loopback,
    /// A tunnel or mesh interface — WireGuard, VXLAN, an overlay.
    Overlay,
    /// A bridge or veth belonging to a container runtime.
    Virtual,
}

impl LinkKind {
    /// Classify from the interface name and what the kernel exposes.
    ///
    /// Name-based, which is a heuristic; the alternative is reading driver
    /// metadata that several of these interfaces do not publish. The names
    /// container runtimes use are stable enough that this holds, and a
    /// misclassified interface shows up as an obviously wrong kind rather than
    /// as a silently wrong number.
    pub fn classify(name: &str) -> Self {
        if name == "lo" {
            return LinkKind::Loopback;
        }
        for p in ["docker", "br-", "veth", "cni", "virbr", "kube"] {
            if name.starts_with(p) {
                return LinkKind::Virtual;
            }
        }
        for p in ["tailscale", "wg", "flannel", "tun", "tap", "vxlan", "gre"] {
            if name.starts_with(p) {
                return LinkKind::Overlay;
            }
        }
        LinkKind::Physical
    }

    /// Whether this interface's traffic belongs in a site total.
    pub fn counts_toward_site_traffic(&self) -> bool {
        matches!(self, LinkKind::Physical)
    }
}

/// Raw counters at a moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Corrupted on arrival: cable, connector, interference.
    pub rx_crc_errors: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    /// Arrived intact and nobody took them: a queue overflowed.
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub collisions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub name: String,
    pub kind: LinkKind,
    /// `up`, `down`, `unknown`. Overlay interfaces often report unknown, which
    /// is not the same as down.
    pub operstate: String,
    /// Negotiated rate in Mb/s, where the driver reports one. **Not** the
    /// capacity of anything beyond the switch port.
    pub speed_mbps: Option<u32>,
    /// How many times the carrier has come or gone since boot. A cable that is
    /// seated badly announces itself here long before anything else notices.
    pub carrier_changes: u64,
    pub counters: Counters,
}

impl Link {
    pub fn is_up(&self) -> bool {
        self.operstate == "up" || self.operstate == "unknown"
    }
}

/// What changed between two readings of the same interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub name: String,
    pub interval_ms: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub crc_errors: u64,
    pub dropped: u64,
    pub carrier_changes: u64,
}

impl Delta {
    /// Difference between two readings, or `None` if they are not comparable.
    ///
    /// A counter that went backwards means the interface was recreated or the
    /// machine rebooted. The honest answer there is no measurement, not a
    /// wrapped-around figure that would read as an enormous burst of traffic.
    pub fn between(before: &Link, after: &Link, interval_ms: u64) -> Option<Self> {
        if before.name != after.name || interval_ms == 0 {
            return None;
        }
        let a = &before.counters;
        let b = &after.counters;
        if b.rx_bytes < a.rx_bytes || b.tx_bytes < a.tx_bytes {
            return None;
        }
        Some(Delta {
            name: after.name.clone(),
            interval_ms,
            rx_bytes: b.rx_bytes - a.rx_bytes,
            tx_bytes: b.tx_bytes - a.tx_bytes,
            crc_errors: b.rx_crc_errors.saturating_sub(a.rx_crc_errors),
            dropped: (b.rx_dropped + b.tx_dropped)
                .saturating_sub(a.rx_dropped + a.tx_dropped),
            carrier_changes: after.carrier_changes.saturating_sub(before.carrier_changes),
        })
    }

    pub fn rx_mbps(&self) -> f64 {
        (self.rx_bytes as f64 * 8.0) / (self.interval_ms as f64 * 1000.0)
    }

    pub fn tx_mbps(&self) -> f64 {
        (self.tx_bytes as f64 * 8.0) / (self.interval_ms as f64 * 1000.0)
    }

    /// Utilisation of the negotiated link rate, if one is known.
    ///
    /// Deliberately takes the rate as an argument rather than reading it from
    /// the link, so a caller substituting the *uplink's* real capacity gets an
    /// answer about the uplink instead of about the switch port.
    pub fn utilisation_of(&self, rate_mbps: u32) -> Option<f64> {
        if rate_mbps == 0 {
            return None;
        }
        Some(((self.rx_mbps().max(self.tx_mbps())) / rate_mbps as f64).clamp(0.0, 1.0))
    }
}

/// What a link's counters say is wrong with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// Frames arriving corrupted. Physical layer: cable, connector,
    /// interference, a failing transceiver.
    Physical { crc_errors: u64 },
    /// Frames arriving intact and being discarded. A queue overflowed —
    /// either the host could not keep up or the link is oversubscribed.
    Congestion { dropped: u64 },
    /// The carrier came and went. A cable that is seated badly, a switch port
    /// renegotiating, a duplex mismatch.
    Flapping { changes: u64 },
    /// The interface is administratively or physically down.
    Down,
}

impl Fault {
    /// Whether the fix is at the physical layer.
    ///
    /// Worth separating because the two classes get opposite responses: a
    /// cable fault gets worse under more traffic and congestion gets better
    /// under less, so a remediation that shed load would mask one and fix the
    /// other.
    pub fn needs_hands(&self) -> bool {
        matches!(self, Fault::Physical { .. } | Fault::Flapping { .. })
    }
}

/// Diagnose a link from a reading and the change since the last one.
///
/// Order matters: a link that is down explains everything else about it, and a
/// physical fault explains drops that a congestion diagnosis would blame on
/// load.
pub fn diagnose(link: &Link, delta: Option<&Delta>) -> Vec<Fault> {
    let mut out = Vec::new();
    if !link.is_up() {
        out.push(Fault::Down);
        return out;
    }
    let Some(d) = delta else {
        // A single reading cannot separate errors accumulated over months of
        // uptime from errors happening now, and reporting lifetime counters as
        // a live fault would condemn every long-running machine.
        return out;
    };
    if d.crc_errors > 0 {
        out.push(Fault::Physical { crc_errors: d.crc_errors });
    }
    if d.carrier_changes > 0 {
        out.push(Fault::Flapping { changes: d.carrier_changes });
    }
    if d.dropped > 0 && d.crc_errors == 0 {
        out.push(Fault::Congestion { dropped: d.dropped });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str, rx: u64, tx: u64) -> Link {
        Link {
            name: name.into(),
            kind: LinkKind::classify(name),
            operstate: "up".into(),
            speed_mbps: Some(1000),
            carrier_changes: 2,
            counters: Counters {
                rx_bytes: rx,
                tx_bytes: tx,
                ..Counters::default()
            },
        }
    }

    #[test]
    fn container_interfaces_are_kept_out_of_site_totals() {
        // They carry the same bytes a second time and would double every
        // figure they were included in.
        for n in ["docker0", "br-29fa248ac246", "veth269d171b", "cni0"] {
            assert_eq!(LinkKind::classify(n), LinkKind::Virtual, "{n}");
            assert!(!LinkKind::classify(n).counts_toward_site_traffic());
        }
    }

    #[test]
    fn the_mesh_is_an_overlay_not_a_wire() {
        // Its traffic already crossed the physical NIC once.
        assert_eq!(LinkKind::classify("tailscale0"), LinkKind::Overlay);
        assert_eq!(LinkKind::classify("flannel.1"), LinkKind::Overlay);
        assert_eq!(LinkKind::classify("wg0"), LinkKind::Overlay);
        assert!(!LinkKind::classify("tailscale0").counts_toward_site_traffic());
    }

    #[test]
    fn a_real_nic_counts() {
        assert_eq!(LinkKind::classify("enp0s25"), LinkKind::Physical);
        assert!(LinkKind::classify("enp0s25").counts_toward_site_traffic());
    }

    #[test]
    fn throughput_comes_from_the_delta_not_the_counter() {
        let a = link("enp0s25", 1_000_000, 0);
        let b = link("enp0s25", 2_250_000, 0);
        let d = Delta::between(&a, &b, 1000).unwrap();
        // 1.25 MB in one second is 10 Mb/s.
        assert!((d.rx_mbps() - 10.0).abs() < 1e-6);
    }

    #[test]
    fn a_counter_that_went_backwards_yields_no_measurement() {
        // A reboot or a recreated interface, not an enormous burst of traffic.
        let a = link("enp0s25", 5_000_000, 0);
        let b = link("enp0s25", 1_000, 0);
        assert!(Delta::between(&a, &b, 1000).is_none());
    }

    #[test]
    fn utilisation_is_measured_against_a_rate_the_caller_chooses() {
        // The whole point: a 1 Gb NIC in front of a 100 Mb uplink is at 50 %
        // of the uplink and 5 % of the port, and only one of those is the
        // number anybody wants.
        let d = Delta::between(&link("enp0s25", 0, 0), &link("enp0s25", 6_250_000, 0), 1000).unwrap();
        assert!((d.utilisation_of(1000).unwrap() - 0.05).abs() < 1e-6);
        assert!((d.utilisation_of(100).unwrap() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn a_single_reading_never_reports_a_live_fault() {
        // Lifetime counters would condemn every long-running machine.
        let mut l = link("enp0s25", 0, 0);
        l.counters.rx_crc_errors = 4_000;
        l.counters.rx_dropped = 50_000;
        assert!(diagnose(&l, None).is_empty());
    }

    #[test]
    fn crc_errors_are_diagnosed_as_physical_and_need_hands() {
        let a = link("enp0s25", 0, 0);
        let mut b = link("enp0s25", 1000, 0);
        b.counters.rx_crc_errors = 12;
        let d = Delta::between(&a, &b, 1000).unwrap();
        let f = diagnose(&b, Some(&d));
        assert_eq!(f, vec![Fault::Physical { crc_errors: 12 }]);
        assert!(f[0].needs_hands(), "no amount of shedding load fixes a cable");
    }

    #[test]
    fn drops_without_errors_are_congestion_and_do_not() {
        let a = link("enp0s25", 0, 0);
        let mut b = link("enp0s25", 1000, 0);
        b.counters.rx_dropped = 900;
        let d = Delta::between(&a, &b, 1000).unwrap();
        let f = diagnose(&b, Some(&d));
        assert_eq!(f, vec![Fault::Congestion { dropped: 900 }]);
        assert!(!f[0].needs_hands());
    }

    #[test]
    fn a_physical_fault_is_not_reported_as_congestion_as_well() {
        // Corrupted frames get dropped too, and blaming load for a bad cable
        // sends somebody to look at the wrong thing.
        let a = link("enp0s25", 0, 0);
        let mut b = link("enp0s25", 1000, 0);
        b.counters.rx_crc_errors = 5;
        b.counters.rx_dropped = 5;
        let d = Delta::between(&a, &b, 1000).unwrap();
        let f = diagnose(&b, Some(&d));
        assert!(f.contains(&Fault::Physical { crc_errors: 5 }));
        assert!(!f.iter().any(|x| matches!(x, Fault::Congestion { .. })));
    }

    #[test]
    fn a_flapping_carrier_is_caught_before_anything_else_notices() {
        let a = link("enp0s25", 0, 0);
        let mut b = link("enp0s25", 1000, 0);
        b.carrier_changes = 9;
        let d = Delta::between(&a, &b, 1000).unwrap();
        assert!(diagnose(&b, Some(&d)).contains(&Fault::Flapping { changes: 7 }));
    }

    #[test]
    fn a_down_link_explains_itself_and_nothing_else_is_reported() {
        let mut l = link("enp0s25", 0, 0);
        l.operstate = "down".into();
        assert_eq!(diagnose(&l, None), vec![Fault::Down]);
    }

    #[test]
    fn an_overlay_reporting_unknown_is_not_down() {
        let mut l = link("tailscale0", 0, 0);
        l.operstate = "unknown".into();
        assert!(l.is_up());
        assert!(diagnose(&l, None).is_empty());
    }
}
