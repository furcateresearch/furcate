//! Link paths and preference between peers.
//!
//! A site typically has more than one way for two machines to reach each
//! other — a direct LAN link and an overlay that also works from anywhere
//! else. Intra-site traffic should never take the overlay, and consumers
//! should not have to discover that by accident.

use serde::{Deserialize, Serialize};

/// How two peers are reaching each other, best first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPreference {
    /// Same machine.
    Loopback,
    /// Direct link on the local segment.
    LocalLan,
    /// Routed within the site.
    SiteRouted,
    /// Encrypted overlay, possibly hairpinning outside the building.
    Overlay,
    /// Relayed by a third party.
    Relay,
}

impl PathPreference {
    /// Whether this path stays inside the site.
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            PathPreference::Loopback | PathPreference::LocalLan | PathPreference::SiteRouted
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkPath {
    pub peer: String,
    pub address: String,
    pub preference: PathPreference,
    /// Observed round trip in microseconds, when measured.
    pub rtt_us: Option<u64>,
}

/// Choose the best path to a peer.
///
/// Preference class dominates measured latency: an overlay that currently
/// looks fast is still carrying traffic out of the building, and a transient
/// latency measurement should not be able to reroute it there.
pub fn best(paths: &[LinkPath]) -> Option<&LinkPath> {
    paths.iter().min_by(|a, b| {
        a.preference
            .cmp(&b.preference)
            .then(a.rtt_us.unwrap_or(u64::MAX).cmp(&b.rtt_us.unwrap_or(u64::MAX)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(pref: PathPreference, addr: &str, rtt: Option<u64>) -> LinkPath {
        LinkPath {
            peer: "node-b".into(),
            address: addr.into(),
            preference: pref,
            rtt_us: rtt,
        }
    }

    #[test]
    fn lan_beats_overlay_even_when_overlay_measures_faster() {
        let paths = vec![
            path(PathPreference::Overlay, "192.0.2.11", Some(100)),
            path(PathPreference::LocalLan, "192.168.1.30", Some(900)),
        ];
        assert_eq!(best(&paths).unwrap().address, "192.168.1.30");
    }

    #[test]
    fn latency_breaks_ties_within_a_class() {
        let paths = vec![
            path(PathPreference::LocalLan, "192.168.1.30", Some(900)),
            path(PathPreference::LocalLan, "192.168.1.31", Some(200)),
        ];
        assert_eq!(best(&paths).unwrap().address, "192.168.1.31");
    }

    #[test]
    fn unmeasured_paths_lose_to_measured_ones_in_the_same_class() {
        let paths = vec![
            path(PathPreference::LocalLan, "a", None),
            path(PathPreference::LocalLan, "b", Some(500)),
        ];
        assert_eq!(best(&paths).unwrap().address, "b");
    }

    #[test]
    fn locality_is_explicit() {
        assert!(PathPreference::LocalLan.is_local());
        assert!(!PathPreference::Overlay.is_local());
        assert!(!PathPreference::Relay.is_local());
    }

    #[test]
    fn no_paths_yields_nothing() {
        assert!(best(&[]).is_none());
    }
}
