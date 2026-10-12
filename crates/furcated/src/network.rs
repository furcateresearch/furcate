//! Reading the network on this machine.
//!
//! Interface state comes from `/sys/class/net`, which costs nothing. Reach
//! comes from a handful of ICMP probes per minute — small enough not to matter
//! on any link, and the only way to tell "our switch is fine and the provider
//! is not" from "everything is broken".
//!
//! The uplink's real capacity cannot be discovered without saturating it, and
//! this deliberately does not saturate it, so the capacity is **declared**
//! through `FURCATE_UPLINK_MBPS`. Until it is, utilisation is measured against
//! the negotiated link rate and every figure derived from it says so.

use furcate_net::link::{Counters, Delta, Fault, Link, LinkKind};
use furcate_net::quality::{Load, Quality, Sample};
use furcate_net::reach::{Layer, Probe, Reachability};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const SYS_NET: &str = "/sys/class/net";

/// Previous reading per interface, so counters become rates.
static PREVIOUS: Mutex<Option<(u64, Vec<Link>)>> = Mutex::new(None);

/// Round trips taken under load, kept so responsiveness has something to rest
/// on. Bounded — a fleet running for months must not accumulate samples until
/// it runs out of memory.
static SAMPLES: Mutex<Vec<Sample>> = Mutex::new(Vec::new());

const MAX_SAMPLES: usize = 240;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_u64(iface: &str, path: &str) -> u64 {
    std::fs::read_to_string(format!("{SYS_NET}/{iface}/{path}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn read_str(iface: &str, path: &str) -> String {
    std::fs::read_to_string(format!("{SYS_NET}/{iface}/{path}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Every interface the kernel knows about, classified.
pub fn links() -> Vec<Link> {
    let Ok(dir) = std::fs::read_dir(SYS_NET) else {
        return Vec::new();
    };
    let mut out: Vec<Link> = dir
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .map(|name| {
            let speed: i64 = std::fs::read_to_string(format!("{SYS_NET}/{name}/speed"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(-1);
            Link {
                kind: LinkKind::classify(&name),
                operstate: read_str(&name, "operstate"),
                // A driver reports -1 when the rate is not meaningful, which
                // is every virtual interface. Carrying that through as a
                // capacity would produce negative utilisation.
                speed_mbps: if speed > 0 { Some(speed as u32) } else { None },
                carrier_changes: read_u64(&name, "carrier_changes"),
                counters: Counters {
                    rx_bytes: read_u64(&name, "statistics/rx_bytes"),
                    tx_bytes: read_u64(&name, "statistics/tx_bytes"),
                    rx_packets: read_u64(&name, "statistics/rx_packets"),
                    tx_packets: read_u64(&name, "statistics/tx_packets"),
                    rx_crc_errors: read_u64(&name, "statistics/rx_crc_errors"),
                    rx_errors: read_u64(&name, "statistics/rx_errors"),
                    tx_errors: read_u64(&name, "statistics/tx_errors"),
                    rx_dropped: read_u64(&name, "statistics/rx_dropped"),
                    tx_dropped: read_u64(&name, "statistics/tx_dropped"),
                    collisions: read_u64(&name, "statistics/collisions"),
                },
                name,
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The physical interface carrying the site's traffic.
///
/// The one physical link that is up and has actually moved bytes. A machine
/// with two NICs where one is unplugged would otherwise be a coin toss.
pub fn primary(links: &[Link]) -> Option<&Link> {
    links
        .iter()
        .filter(|l| l.kind == LinkKind::Physical && l.is_up())
        .max_by_key(|l| l.counters.rx_bytes + l.counters.tx_bytes)
}

/// Declared capacity of the service, not of the switch port.
///
/// Returns whether it was declared alongside the figure, because a number
/// derived from the negotiated link rate is measuring the wrong thing and
/// anything quoting it should say so.
pub fn uplink_mbps(primary: Option<&Link>) -> (u32, bool) {
    match std::env::var("FURCATE_UPLINK_MBPS").ok().and_then(|s| s.trim().parse::<u32>().ok()) {
        Some(m) if m > 0 => (m, true),
        _ => (primary.and_then(|l| l.speed_mbps).unwrap_or(0), false),
    }
}

/// The default gateway, read from the kernel's route table.
///
/// Parsed out of `/proc/net/route` rather than shelled out to `ip`, and that
/// is not a style preference. The agent's unit sets
/// `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, and `ip` talks
/// **netlink** — so it fails inside the sandbox while working perfectly from a
/// shell. The first deployment reported a healthy network with the gateway
/// layer silently missing because of exactly that. Widening the sandbox to fix
/// a diagnostic would have been the wrong trade; reading the file needs no
/// socket at all.
///
/// The gateway column is a little-endian hex address, which is why it reads
/// backwards.
fn default_gateway() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[1] != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(f[2], 16).ok()?;
        if raw == 0 {
            continue;
        }
        let b = raw.to_le_bytes();
        return Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
    }
    None
}

fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1"
}

/// The resolver actually being queried.
///
/// `/etc/resolv.conf` on a systemd machine points at a loopback stub, and
/// probing that measures nothing — it answers in sixty microseconds whether or
/// not DNS works, so it would report a healthy layer that was never tested.
/// systemd-resolved writes the real upstreams to its own file, which is a
/// plain read and needs no D-Bus.
fn first_resolver() -> Option<String> {
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        if let Some(a) = text
            .lines()
            .filter(|l| l.starts_with("nameserver"))
            .filter_map(|l| l.split_whitespace().nth(1))
            .find(|a| !is_loopback(a))
        {
            return Some(a.to_string());
        }
    }
    None
}

fn internet_targets() -> Vec<String> {
    std::env::var("FURCATE_REACH_TARGETS")
        .unwrap_or_else(|_| "1.1.1.1".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Probe one target, returning what came back.
///
/// Three packets with a one-second deadline. Enough to distinguish loss from a
/// single unlucky drop, small enough that running it every thirty seconds is
/// invisible on any link.
fn ping(layer: Layer, target: &str) -> Probe {
    let sent = 3u32;
    let mut probe = Probe {
        layer,
        target: target.to_string(),
        received: 0,
        sent,
        rtt_ms: None,
        jitter_ms: None,
    };

    // `ping` exits non-zero when every packet is lost, which is a result and
    // not a failure to run — so this deliberately does not use `run`.
    let Ok(out) = Command::new("ping")
        .args(["-n", "-q", "-c", "3", "-W", "1", target])
        .output()
    else {
        return probe;
    };
    let text = String::from_utf8_lossy(&out.stdout);

    for line in text.lines() {
        if let Some(rest) = line.split(" received").next() {
            if let Some(n) = rest.rsplit(", ").next().and_then(|s| s.trim().parse::<u32>().ok()) {
                if line.contains("received") {
                    probe.received = n.min(sent);
                }
            }
        }
        // rtt min/avg/max/mdev = 0.293/0.351/0.408/0.041 ms
        if let Some(stats) = line.split('=').nth(1) {
            if line.contains("min/avg/max") {
                let parts: Vec<f64> = stats
                    .trim()
                    .trim_end_matches(" ms")
                    .split('/')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
                if parts.len() >= 4 {
                    probe.rtt_ms = Some(parts[1]);
                    probe.jitter_ms = Some(parts[3]);
                }
            }
        }
    }
    probe
}

/// Probe outward in layers.
pub fn reachability() -> Reachability {
    let mut probes = Vec::new();
    if let Some(gw) = default_gateway() {
        probes.push(ping(Layer::Gateway, &gw));
    }
    if let Some(r) = first_resolver() {
        // A resolver that happens to be the gateway is one probe, not two.
        if probes.first().map(|p| p.target != r).unwrap_or(true) {
            probes.push(ping(Layer::Resolver, &r));
        }
    }
    for t in internet_targets() {
        probes.push(ping(Layer::Internet, &t));
    }
    Reachability { probes }
}

/// Everything this machine knows about its network right now.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkReport {
    pub links: Vec<Link>,
    pub primary: Option<String>,
    pub delta: Option<Delta>,
    pub faults: Vec<Fault>,
    pub reach: Reachability,
    pub quality: Option<Quality>,
    pub diagnosis: String,
}

/// Read the network, using the previous reading to turn counters into rates.
pub fn collect() -> NetworkReport {
    let links = links();
    let now = now_ms();

    let primary_name = primary(&links).map(|l| l.name.clone());
    let (capacity, declared) = uplink_mbps(primary(&links));

    let delta = {
        let mut guard = PREVIOUS.lock().expect("network tracker");
        let d = guard.as_ref().and_then(|(then, prev)| {
            let interval = now.saturating_sub(*then);
            let name = primary_name.as_ref()?;
            let before = prev.iter().find(|l| l.name == *name)?;
            let after = links.iter().find(|l| l.name == *name)?;
            Delta::between(before, after, interval)
        });
        *guard = Some((now, links.clone()));
        d
    };

    let reach = reachability();
    let faults = match (primary(&links), delta.as_ref()) {
        (Some(l), d) => furcate_net::link::diagnose(l, d),
        (None, _) => Vec::new(),
    };

    let quality = delta.as_ref().map(|d| {
        let loss = reach
            .probe_at(Layer::Internet)
            .map(|p| p.loss())
            .unwrap_or(0.0);
        let rtt = reach.internet_rtt_ms();

        // Record this round trip against the load it was taken under, which is
        // what makes an opportunistic responsiveness figure possible at all.
        if let (Some(rtt), Some(u)) = (rtt, d.utilisation_of(capacity)) {
            let mut s = SAMPLES.lock().expect("samples");
            s.push(Sample { rtt_ms: rtt, load: Load::from_utilisation(u) });
            let len = s.len();
            if len > MAX_SAMPLES {
                s.drain(0..len - MAX_SAMPLES);
            }
        }
        let samples = SAMPLES.lock().expect("samples").clone();
        Quality::from_delta(d, capacity, declared, rtt, loss, &samples)
    });

    NetworkReport {
        diagnosis: reach.diagnosis(),
        primary: primary_name,
        links,
        delta,
        faults,
        reach,
        quality,
    }
}

/// Throughput series keys for the forecaster, so the network is predicted with
/// the same machinery as everything else.
pub fn series_points(report: &NetworkReport) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    if let Some(d) = &report.delta {
        out.insert("net_rx_mbps".to_string(), d.rx_mbps());
        out.insert("net_tx_mbps".to_string(), d.tx_mbps());
    }
    if let Some(r) = report.reach.internet_rtt_ms() {
        out.insert("net_rtt_ms".to_string(), r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phys(name: &str, rx: u64, up: bool) -> Link {
        Link {
            name: name.into(),
            kind: LinkKind::classify(name),
            operstate: if up { "up".into() } else { "down".into() },
            speed_mbps: Some(1000),
            carrier_changes: 2,
            counters: Counters { rx_bytes: rx, ..Counters::default() },
        }
    }

    #[test]
    fn the_primary_is_the_physical_link_that_has_actually_moved_bytes() {
        // A machine with a second NIC plugged into nothing would otherwise be
        // a coin toss.
        let links = vec![
            phys("enp0s25", 605_528_027, true),
            phys("enp0s26", 0, true),
            phys("docker0", 999_999_999, true),
        ];
        assert_eq!(primary(&links).unwrap().name, "enp0s25");
    }

    #[test]
    fn a_down_interface_is_never_the_primary() {
        let links = vec![phys("enp0s25", 900, false), phys("enp0s26", 100, true)];
        assert_eq!(primary(&links).unwrap().name, "enp0s26");
    }

    #[test]
    fn a_machine_with_no_physical_link_up_has_no_primary() {
        let links = vec![phys("enp0s25", 900, false)];
        assert!(primary(&links).is_none());
    }

    #[test]
    fn an_undeclared_uplink_falls_back_to_the_port_rate_and_says_so() {
        // The fallback is usable and it is measuring the switch port, which is
        // not the service anybody is paying for.
        let links = vec![phys("enp0s25", 900, true)];
        std::env::remove_var("FURCATE_UPLINK_MBPS");
        let (mbps, declared) = uplink_mbps(primary(&links));
        assert_eq!(mbps, 1000);
        assert!(!declared);
    }

    #[test]
    fn a_virtual_interface_never_reports_a_negative_rate() {
        // Drivers return -1 for interfaces where a link rate is meaningless,
        // and carrying that through would produce negative utilisation.
        let l = links();
        assert!(l.iter().all(|x| x.speed_mbps.map(|s| s > 0).unwrap_or(true)));
    }

    #[test]
    fn reading_this_machine_produces_an_answer_rather_than_a_panic() {
        let l = links();
        // Every machine has loopback.
        assert!(l.iter().any(|x| x.kind == LinkKind::Loopback) || l.is_empty());
    }

    #[test]
    fn a_loopback_resolver_is_not_a_resolver_worth_probing() {
        // It answers in microseconds whether or not DNS works, so a probe
        // against it reports a healthy layer that was never tested.
        assert!(is_loopback("127.0.0.53"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("::1"));
        assert!(!is_loopback("192.168.1.1"));
        assert!(!is_loopback("1.1.1.1"));
    }

    #[test]
    fn the_gateway_is_read_without_a_netlink_socket() {
        // The agent's sandbox permits AF_INET, AF_INET6 and AF_UNIX only, so
        // `ip` fails inside it while working from a shell — which is how the
        // first deployment shipped with the gateway layer silently missing.
        // Whatever this machine's routing looks like, the read must not panic.
        let _ = default_gateway();
        assert!(std::path::Path::new("/proc/net/route").exists());
    }

    #[test]
    fn the_resolver_probe_skips_the_local_stub() {
        // Otherwise it reports a healthy DNS layer that was never tested.
        if let Some(r) = first_resolver() {
            assert!(!is_loopback(&r), "picked the stub at {r}");
        }
    }

    #[test]
    fn series_are_only_emitted_once_there_is_a_rate_to_report() {
        // The first collection has no previous reading, so there is no
        // throughput — and a zero would be a measurement of nothing.
        let r = NetworkReport {
            links: vec![],
            primary: None,
            delta: None,
            faults: vec![],
            reach: Reachability { probes: vec![] },
            quality: None,
            diagnosis: String::new(),
        };
        assert!(series_points(&r).is_empty());
    }
}
