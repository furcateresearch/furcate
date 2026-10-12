//! Where the path stops working.
//!
//! "The internet is down" is not an actionable statement. "Your NIC has
//! carrier, your gateway answers, and your ISP's next hop does not" is — it
//! says whose problem it is and who to call. So reachability is probed in
//! layers, from the closest hop outward, and the diagnosis is the **first**
//! layer that fails rather than a list of everything that timed out.
//!
//! Latency is collected alongside, because a link that is up and answering in
//! two seconds is a different failure from one that is down, and it is the one
//! a plain up/down check reports as healthy.

use serde::{Deserialize, Serialize};

/// How far out a probe reaches.
///
/// Ordered by distance so a diagnosis can be "the nearest layer that failed".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// Another node on this site.
    Local,
    /// The default gateway.
    Gateway,
    /// A name resolver.
    Resolver,
    /// Something on the public internet.
    Internet,
}

impl Layer {
    /// Whose problem a failure at this layer is.
    ///
    /// The point of the whole module: an operator seeing `Internet` failing
    /// while `Gateway` answers has an ISP problem and no amount of restarting
    /// their own equipment will help.
    pub fn owner(&self) -> &'static str {
        match self {
            Layer::Local => "this site",
            Layer::Gateway => "site network equipment",
            Layer::Resolver => "name resolution, ours or the ISP's",
            Layer::Internet => "the upstream provider",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Layer::Local => "local",
            Layer::Gateway => "gateway",
            Layer::Resolver => "resolver",
            Layer::Internet => "internet",
        }
    }
}

/// One probe's outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Probe {
    pub layer: Layer,
    pub target: String,
    /// Round trips that came back, out of `sent`.
    pub received: u32,
    pub sent: u32,
    /// Median round-trip in milliseconds, over the replies that arrived.
    pub rtt_ms: Option<f64>,
    /// Spread between the fastest and slowest reply. A stable link with high
    /// latency is usable; an unstable one at the same average is not, and the
    /// average alone cannot tell them apart.
    pub jitter_ms: Option<f64>,
}

impl Probe {
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        1.0 - (self.received as f64 / self.sent as f64)
    }

    pub fn reachable(&self) -> bool {
        self.received > 0
    }

    /// Loss above which a path is treated as failing rather than lossy.
    ///
    /// Some loss is normal — a probe is low priority and routers shed it
    /// first. Treating a single dropped packet as an outage produces an alarm
    /// every few minutes and trains everyone to ignore it.
    pub const LOSS_THRESHOLD: f64 = 0.5;

    pub fn is_degraded(&self) -> bool {
        self.reachable() && self.loss() > 0.0
    }

    pub fn is_failing(&self) -> bool {
        !self.reachable() || self.loss() > Self::LOSS_THRESHOLD
    }
}

/// What the whole set of probes says.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reachability {
    pub probes: Vec<Probe>,
}

impl Reachability {
    /// The nearest layer that is failing.
    ///
    /// Nearest rather than all of them: when the gateway is down, everything
    /// beyond it is down too, and reporting four failures invites four
    /// investigations of one fault.
    pub fn first_failure(&self) -> Option<&Probe> {
        self.probes
            .iter()
            .filter(|p| p.is_failing())
            .min_by_key(|p| p.layer)
    }

    /// A sentence naming the fault and whose it is.
    pub fn diagnosis(&self) -> String {
        match self.first_failure() {
            None => {
                let worst = self
                    .probes
                    .iter()
                    .filter(|p| p.is_degraded())
                    .max_by(|a, b| a.loss().partial_cmp(&b.loss()).unwrap_or(std::cmp::Ordering::Equal));
                match worst {
                    Some(p) => format!(
                        "reachable throughout; {:.0}% loss to {} ({})",
                        p.loss() * 100.0,
                        p.target,
                        p.layer.owner()
                    ),
                    None => "reachable throughout".into(),
                }
            }
            Some(p) if p.reachable() => format!(
                "{:.0}% loss to {} at the {} layer — {}",
                p.loss() * 100.0,
                p.target,
                p.layer.as_str(),
                p.layer.owner()
            ),
            Some(p) => format!(
                "no reply from {} at the {} layer — {}",
                p.target,
                p.layer.as_str(),
                p.layer.owner()
            ),
        }
    }

    pub fn probe_at(&self, layer: Layer) -> Option<&Probe> {
        self.probes.iter().find(|p| p.layer == layer)
    }

    /// Whether the site can reach anything outside itself.
    pub fn has_internet(&self) -> bool {
        self.probe_at(Layer::Internet).map(|p| p.reachable()).unwrap_or(false)
    }

    /// Round-trip to the internet, when there is one.
    pub fn internet_rtt_ms(&self) -> Option<f64> {
        self.probe_at(Layer::Internet).and_then(|p| p.rtt_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(layer: Layer, target: &str, received: u32, sent: u32, rtt: Option<f64>) -> Probe {
        Probe {
            layer,
            target: target.into(),
            received,
            sent,
            rtt_ms: rtt,
            jitter_ms: Some(1.0),
        }
    }

    fn healthy() -> Reachability {
        Reachability {
            probes: vec![
                probe(Layer::Gateway, "192.168.1.1", 5, 5, Some(0.4)),
                probe(Layer::Resolver, "1.1.1.1", 5, 5, Some(12.0)),
                probe(Layer::Internet, "8.8.8.8", 5, 5, Some(18.0)),
            ],
        }
    }

    #[test]
    fn a_working_path_reports_no_failure() {
        assert!(healthy().first_failure().is_none());
        assert_eq!(healthy().diagnosis(), "reachable throughout");
        assert!(healthy().has_internet());
    }

    #[test]
    fn a_gateway_failure_is_reported_once_not_three_times() {
        // When the gateway is down everything beyond it is too, and reporting
        // three failures invites three investigations of one fault.
        let r = Reachability {
            probes: vec![
                probe(Layer::Gateway, "192.168.1.1", 0, 5, None),
                probe(Layer::Resolver, "1.1.1.1", 0, 5, None),
                probe(Layer::Internet, "8.8.8.8", 0, 5, None),
            ],
        };
        let f = r.first_failure().unwrap();
        assert_eq!(f.layer, Layer::Gateway);
        assert!(r.diagnosis().contains("site network equipment"));
    }

    #[test]
    fn a_working_gateway_and_a_dead_internet_names_the_isp() {
        // The distinction that makes the whole module worth having.
        let r = Reachability {
            probes: vec![
                probe(Layer::Gateway, "192.168.1.1", 5, 5, Some(0.4)),
                probe(Layer::Internet, "8.8.8.8", 0, 5, None),
            ],
        };
        assert_eq!(r.first_failure().unwrap().layer, Layer::Internet);
        assert!(r.diagnosis().contains("upstream provider"));
        assert!(!r.has_internet());
    }

    #[test]
    fn a_single_dropped_packet_is_not_an_outage() {
        // Otherwise there is an alarm every few minutes and everyone learns to
        // ignore it.
        let p = probe(Layer::Internet, "8.8.8.8", 4, 5, Some(20.0));
        assert!(p.is_degraded());
        assert!(!p.is_failing());
    }

    #[test]
    fn majority_loss_is() {
        let p = probe(Layer::Internet, "8.8.8.8", 1, 5, Some(20.0));
        assert!(p.is_failing());
    }

    #[test]
    fn degradation_short_of_failure_still_reaches_the_summary() {
        // A path that is up and losing a fifth of its packets is not healthy,
        // and a bare "reachable" would hide it.
        let mut r = healthy();
        r.probes[2] = probe(Layer::Internet, "8.8.8.8", 4, 5, Some(20.0));
        assert!(r.first_failure().is_none());
        assert!(r.diagnosis().contains("20% loss"));
    }

    #[test]
    fn a_slow_but_reachable_path_is_visible_in_the_latency() {
        // The failure a plain up/down check reports as healthy.
        let mut r = healthy();
        r.probes[2] = probe(Layer::Internet, "8.8.8.8", 5, 5, Some(2100.0));
        assert!(r.has_internet());
        assert!(r.internet_rtt_ms().unwrap() > 2000.0);
    }

    #[test]
    fn each_layer_says_whose_problem_it_is() {
        assert!(Layer::Internet.owner().contains("upstream"));
        assert!(Layer::Gateway.owner().contains("site"));
        assert!(Layer::Local < Layer::Internet, "ordered by distance");
    }

    #[test]
    fn a_probe_that_was_never_sent_reports_no_loss_rather_than_total_loss() {
        let p = probe(Layer::Internet, "8.8.8.8", 0, 0, None);
        assert_eq!(p.loss(), 0.0);
    }
}
