//! What this machine knows about its own ability to come back.
//!
//! Reported rather than asserted. A node claiming it can be woken is worth
//! nothing on its own — the claim only matters to the site controller, which is
//! the thing that would have to do the waking, and which is also the only place
//! that can hold the record of a wake having actually worked.
//!
//! So this collects evidence and stops. It reads whether the interface is armed
//! and what address to send to. It does not decide that the node is safe to
//! suspend, and it cannot: the last step of that proof involves this process
//! not running.

use furcate_power::wake::{armed_from_ethtool, WakePath};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WakeReport {
    /// The interface the address belongs to.
    pub interface: Option<String>,
    /// Hardware address, for the packet the controller would send.
    pub mac: Option<String>,
    /// Whether the NIC will act on a magic packet.
    pub armed: bool,
    /// Whether the NIC is capable of it at all, which is a different question
    /// and the one that produces false confidence when confused with the first.
    pub supported: bool,
    /// The furthest state this node can establish about itself. Never
    /// `Demonstrated` — proving that requires this process to have stopped.
    pub reached: WakePath,
    /// This boot of this machine.
    ///
    /// Carried so the controller can scope its own evidence to it. Wake
    /// settings do not survive a reboot and neither does anything learned about
    /// them; a boot id changing is the signal to start again, and a controller
    /// restart is not.
    pub boot_id: Option<String>,
}

/// The interface carrying the default route.
///
/// Read from `/proc/net/route` rather than by running `ip`, because the agent's
/// unit restricts address families and `ip` talks netlink — a lesson this
/// codebase has already paid for once.
fn primary_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let iface = f.next()?;
        let dest = f.next()?;
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

fn mac_of(iface: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Where the privileged reader publishes the interface's wake setting.
const WAKE_PATH: &str = "/run/furcate/wake.txt";

/// What the kernel says about magic-packet wake on this interface.
///
/// Read from a published file rather than by running `ethtool`, because
/// `ethtool` refuses an unprivileged caller — and refuses the *entire* query,
/// not just the wake field. The agent saw "Operation not permitted" and
/// reported both machines as not supporting wake-on-lan while both were armed.
/// A capability check that fails closed on a permission error looks exactly
/// like hardware that cannot do the thing.
///
/// This is the third instrument on this host that needed the same treatment,
/// after the energy counters and the management controller. The pattern is
/// settled: privilege reads, agent parses.
fn published() -> Option<String> {
    std::fs::read_to_string(WAKE_PATH).ok().filter(|s| !s.trim().is_empty())
}

pub fn collect() -> WakeReport {
    let text = published();
    // The reader names the interface it actually queried; falling back to the
    // route table only when it has not published yet. Trusting the local guess
    // over the reader's own statement would report one interface's address
    // beside another's wake setting.
    let interface = text
        .as_deref()
        .and_then(|t| {
            t.lines()
                .filter_map(|l| l.trim().strip_prefix("interface:"))
                .next()
                .map(|v| v.trim().to_string())
        })
        .or_else(primary_interface);
    let mac = interface.as_deref().and_then(mac_of);

    let armed = text.as_deref().map(armed_from_ethtool).unwrap_or(false);
    let supported = text
        .as_deref()
        .map(|t| {
            t.lines()
                .filter_map(|l| l.trim().strip_prefix("Supports Wake-on:"))
                .any(|v| v.contains('g'))
        })
        .unwrap_or(false);

    WakeReport {
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        // Armed is as far as a node can get about itself. Delivery is observed
        // by the receiver and proof is observed by the controller.
        reached: if armed && mac.is_some() { WakePath::Armed } else { WakePath::Unknown },
        interface,
        mac,
        armed,
        supported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_machine_answers_without_panicking() {
        let r = collect();
        // Whatever it finds, an address without an interface would mean the
        // two were read from different places.
        assert!(r.mac.is_none() || r.interface.is_some());
    }

    #[test]
    fn a_node_never_claims_to_have_proven_its_own_wake() {
        // The last step of that proof involves this process not running, so a
        // node asserting it would be asserting something it cannot observe.
        assert!(collect().reached < WakePath::Demonstrated);
        assert!(!collect().reached.permits_suspend());
    }

    #[test]
    fn a_boot_id_is_reported_so_evidence_can_be_scoped_to_one_boot() {
        // Without it the controller cannot tell a machine that rebooted from a
        // controller that restarted, and has to discard evidence on both.
        assert!(collect().boot_id.is_some(), "linux always has one");
    }

    #[test]
    fn an_armed_interface_still_needs_an_address_to_be_useful() {
        // Armed with no MAC is not a wake path: there is nothing to address the
        // packet to, and reporting Armed would put the fleet one step further
        // along than it is.
        let r = collect();
        if r.reached == WakePath::Armed {
            assert!(r.mac.is_some());
        }
    }
}
