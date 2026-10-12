//! Getting a suspended machine back, and knowing whether you can before you try.
//!
//! Consolidation has been refused on this site since it was written, for one
//! reason: `wake_proven` was false and nothing could set it. That refusal is
//! correct — suspending a machine you cannot wake converts a power saving into
//! a site visit, and on a site in another country that is not a trade anyone
//! would make knowingly. But "correct and permanent" is not a design, it is a
//! feature that never ships.
//!
//! ## Why proof has four states rather than two
//!
//! The obvious model is a boolean: either wake works or it does not. The
//! problem is that the only way to move a boolean from false to true is to
//! suspend a production machine and find out, which is precisely the
//! irreversible experiment the refusal exists to prevent. So the boolean stays
//! false forever and consolidation is dead code.
//!
//! Splitting it lets the safe evidence accumulate. Three of the four states can
//! be established without suspending anything:
//!
//! - the interface is **armed** — the NIC will act on a magic packet at all,
//!   which is off by default on this hardware and does not survive a reboot
//!   unless something sets it;
//! - a packet was **delivered** — one was sent and observed arriving, so the
//!   switch forwards it, no VLAN eats it, and the address is right;
//! - and only **demonstrated** — a machine actually suspended and actually came
//!   back — unblocks suspension.
//!
//! The gap between the third and fourth is real and is not hand-waved here.
//! Delivery proves the network path. It does not prove the NIC will raise the
//! board out of S3 or S5, which depends on firmware settings this software
//! cannot read. What the split buys is that when somebody is finally standing
//! next to the machine, everything else has already been checked, and a failure
//! at that point means one thing rather than five.
//!
//! ## Why not IPMI
//!
//! The management controller can power a chassis on, and on paper that is a
//! better wake path than Wake-on-LAN. It needs the controller reachable over
//! the network to do it, and in-band access dies with the host — which is
//! exactly when it would be needed. On this site the controller's LAN interface
//! is unconfigured, so the better path is currently no path.

use serde::{Deserialize, Serialize};

/// How confident the site is that a given node can be brought back.
///
/// Ordered: each state implies the ones before it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakePath {
    /// Nothing established. The default, and the honest one.
    #[default]
    Unknown,
    /// The interface reports it will act on a magic packet.
    Armed,
    /// A packet was sent and observed arriving at the target.
    PacketDelivered,
    /// A machine was suspended and came back. The only state that permits
    /// suspending one.
    Demonstrated,
}

impl WakePath {
    /// Whether this is enough to risk suspending a machine.
    ///
    /// Only the last one. Everything below it is evidence that the *network*
    /// works, and a wake failure would be in the firmware, which is the part
    /// none of this can see.
    pub fn permits_suspend(&self) -> bool {
        matches!(self, WakePath::Demonstrated)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WakePath::Unknown => "unknown",
            WakePath::Armed => "armed",
            WakePath::PacketDelivered => "packet_delivered",
            WakePath::Demonstrated => "demonstrated",
        }
    }

    /// What still has to happen before a node may be suspended.
    pub fn what_is_missing(&self) -> Option<&'static str> {
        match self {
            WakePath::Unknown => Some(
                "the interface is not armed for wake-on-lan; it is off by default on this \
                 hardware and does not survive a reboot unless something sets it",
            ),
            WakePath::Armed => Some(
                "no magic packet has been observed arriving; send one to a running node and \
                 watch for it, which costs nothing and rules out the switch, the vlan and the \
                 address",
            ),
            WakePath::PacketDelivered => Some(
                "the network path works but no machine has actually been woken. This last step \
                 needs somebody who can reach the machine if it does not come back",
            ),
            WakePath::Demonstrated => None,
        }
    }
}

/// Parse `ethtool`'s wake setting.
///
/// The field is a set of single letters and `g` is the one that matters: magic
/// packet. `d` means disabled, which is this hardware's default and the reason
/// nothing worked.
///
/// `Supports Wake-on` is deliberately ignored — a NIC that *can* do it and is
/// not doing it will not wake, and reading the capability line instead of the
/// state line is the classic way to get a confident false positive.
pub fn armed_from_ethtool(text: &str) -> bool {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("Wake-on:"))
        .any(|v| v.trim().contains('g'))
}

/// Build a magic packet for a MAC address.
///
/// Six `0xFF` bytes followed by the address sixteen times. Returns `None` for
/// anything that is not a MAC, because sending a malformed packet would look
/// exactly like a working one from the sender's side — nothing reports an
/// error, and the machine simply never wakes.
pub fn magic_packet(mac: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = mac
        .split([':', '-'])
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    if bytes.len() != 6 {
        return None;
    }
    let mut p = vec![0xFF; 6];
    for _ in 0..16 {
        p.extend_from_slice(&bytes);
    }
    Some(p)
}

/// Send a magic packet on the local broadcast address.
///
/// Broadcast rather than unicast because a suspended machine has fallen out of
/// every switch's forwarding table and out of every ARP cache; a unicast frame
/// to an address nothing has seen recently is flooded anyway on a good switch
/// and dropped on a bad one.
///
/// Port 9 by convention. Nothing listens on it — the NIC matches the payload
/// pattern, not the port — so the number matters only for firewalls.
pub fn send(mac: &str, broadcast: &str) -> std::io::Result<usize> {
    let packet = magic_packet(mac).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("not a mac address: {mac}"))
    })?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    sock.send_to(&packet, format!("{broadcast}:9"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_demonstrated_wake_permits_suspending_a_machine() {
        // The whole point. Everything below Demonstrated is evidence about the
        // network, and a wake failure would be in firmware.
        assert!(!WakePath::Unknown.permits_suspend());
        assert!(!WakePath::Armed.permits_suspend());
        assert!(!WakePath::PacketDelivered.permits_suspend());
        assert!(WakePath::Demonstrated.permits_suspend());
    }

    #[test]
    fn every_state_short_of_proof_says_what_is_missing() {
        for s in [WakePath::Unknown, WakePath::Armed, WakePath::PacketDelivered] {
            assert!(s.what_is_missing().is_some(), "{s:?} should name its next step");
        }
        assert!(WakePath::Demonstrated.what_is_missing().is_none());
    }

    #[test]
    fn the_states_are_ordered_so_evidence_only_accumulates() {
        assert!(WakePath::Unknown < WakePath::Armed);
        assert!(WakePath::Armed < WakePath::PacketDelivered);
        assert!(WakePath::PacketDelivered < WakePath::Demonstrated);
    }

    #[test]
    fn the_state_line_is_read_and_the_capability_line_is_not() {
        // Verbatim from this site's NICs, where the two lines disagree. Reading
        // the capability would report every machine here as ready to wake.
        let real = "\tSupports Wake-on: pumbg\n\tWake-on: d";
        assert!(!armed_from_ethtool(real), "d means disabled");

        let armed = "\tSupports Wake-on: pumbg\n\tWake-on: g";
        assert!(armed_from_ethtool(armed));
    }

    #[test]
    fn an_interface_that_says_nothing_is_not_armed() {
        assert!(!armed_from_ethtool(""));
        assert!(!armed_from_ethtool("Settings for enp0s25:\n\tSpeed: 1000Mb/s"));
    }

    #[test]
    fn a_magic_packet_is_six_ff_then_the_address_sixteen_times() {
        let p = magic_packet("00:00:5e:00:53:fa").unwrap();
        assert_eq!(p.len(), 6 + 16 * 6);
        assert_eq!(&p[..6], &[0xFF; 6]);
        assert_eq!(&p[6..12], &[0x00, 0x00, 0x5e, 0x00, 0x53, 0xfa]);
        assert_eq!(&p[p.len() - 6..], &[0x00, 0x00, 0x5e, 0x00, 0x53, 0xfa]);
    }

    #[test]
    fn hyphens_are_a_mac_address_too() {
        assert_eq!(magic_packet("00-00-5e-00-53-fa"), magic_packet("00:00:5e:00:53:fa"));
    }

    #[test]
    fn a_malformed_address_is_refused_rather_than_sent() {
        // A malformed packet looks identical to a working one from the sending
        // side: nothing errors, and the machine simply never wakes. The failure
        // would surface as "wake-on-lan does not work on this hardware".
        assert!(magic_packet("00:00:5e:00:53").is_none(), "five octets");
        assert!(magic_packet("00:00:5e:00:53:fa:cc").is_none(), "seven");
        assert!(magic_packet("not-a-mac-at-all").is_none());
        assert!(magic_packet("").is_none());
        assert!(magic_packet("00:00:5e:00:53:zz").is_none(), "not hex");
    }

    #[test]
    fn send_refuses_a_bad_address_instead_of_emitting_noise() {
        let e = send("nonsense", "255.255.255.255").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }
}
