//! `furcate-siteview` — one view of a site, assembled from its nodes.
//!
//! Every node answers `/healthz` and `/workloads` about itself only. A person
//! with three machines in a cupboard wants one answer to "what is running here
//! and is it all up", not three. This crate is that answer: it lists the
//! site's nodes, asks each of them on a timer, keeps the last reading with its
//! age, and serves the result as JSON and as a read-only page.
//!
//! ## It holds no authority
//!
//! The view is a cache of what nodes said about themselves. Nothing here
//! signs, admits, places or orders anything, and nothing a node does depends
//! on it: an order still goes to the node it concerns and is verified there,
//! against that node's own trust store. Because of that, any node can serve
//! the view, two nodes serving it at once cannot disagree about anything that
//! matters, and losing the node that serves it loses a screen, not the site.
//!
//! The collecting and the showing live here, so a home lab with a few machines
//! sees its whole site.

pub mod cells;
pub mod web;

use furcate_api::{Request, Response, Router};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How old a reading is allowed to be before it stops meaning anything.
///
/// Three states, not two. "Fresh", "stale" and "never answered" are genuinely
/// different, and collapsing stale into fresh is how a console shows green for
/// a machine that died an hour ago. The poller runs every 30s, so a node is
/// stale after it has missed roughly four attempts — long enough that one slow
/// reply is not an alarm, short enough that a real failure surfaces fast.
pub const STALE_SECS: u64 = 120;

/// How often the poller asks every node.
pub const POLL_SECS: u64 = 30;

/// One node's own account of itself, with the age of that account.
#[derive(Clone, Debug)]
pub struct Reading {
    /// Unix seconds when this was collected. Compared against now to decide
    /// whether it is worth believing.
    pub at: u64,
    /// Whether the last attempt succeeded. A stale reading plus a failed
    /// attempt is a different thing from a stale reading nobody has retried.
    pub reachable: bool,
    /// Verbatim /healthz, as the node reported it.
    pub health: Option<serde_json::Value>,
    /// Verbatim /workloads: systemd units, docker containers and k3s pods,
    /// already unified per node by furcated.
    pub workloads: Option<serde_json::Value>,
    /// Verbatim key custody status: who holds the site's keys as that node
    /// sees it, and why it does or does not hold them itself.
    pub custody: Option<serde_json::Value>,
}

/// The latest reading per node, keyed however the caller names nodes.
pub type Readings = BTreeMap<String, Reading>;

/// `fresh`, `stale` or `silent`, for a reading of this age.
pub fn freshness(reading: Option<&Reading>, now: u64) -> &'static str {
    match reading {
        None => "silent",
        Some(r) if r.reachable && now.saturating_sub(r.at) <= STALE_SECS => "fresh",
        Some(_) => "stale",
    }
}

/// Ask every target for its health and workloads, all at once.
///
/// One thread per node, because this is judged on how fresh its answers are
/// and a sequential pass is as slow as the sum of every node's timeout. A
/// single machine that is switched off would otherwise spend the whole budget
/// on its own silence: five nodes at a 6s worst case is 50s sequentially,
/// which is longer than both the 30s cadence and the staleness threshold the
/// results are measured against — so the poller would report a stale fleet
/// because it was slow, not because the fleet was. Polled together, a pass
/// costs the slowest node rather than all of them.
pub fn poll(targets: Vec<(String, String)>, now: u64) -> Vec<(String, Reading)> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .into_iter()
            .map(|(node, endpoint)| {
                scope.spawn(move || {
                    // Short timeouts. This runs every 30s and its job is
                    // to notice silence, not to wait patiently through it.
                    let health = furcate_api::get_json(&endpoint, "/healthz", 4_000).ok();
                    let workloads = furcate_api::get_json(&endpoint, "/workloads", 6_000).ok();
                    let custody =
                        furcate_api::get_json(&endpoint, furcate_api::custody::PATH, 4_000).ok();
                    (
                        node,
                        Reading {
                            at: now,
                            reachable: health.is_some() || workloads.is_some(),
                            health,
                            workloads,
                            custody,
                        },
                    )
                })
            })
            .collect();
        // A panicking probe must not take the pass down with it: the
        // node it was reading simply has no reading this time, which is
        // the state `absorb` already knows how to represent.
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    })
}

/// Fold one pass of `poll` into the cache.
///
/// Keeps the last good reading and marks the node unreachable, rather than
/// replacing knowledge with a blank. "Last seen 40 minutes ago running these
/// things" is far more useful to somebody at 3am than "unknown".
pub fn absorb(readings: &mut Readings, collected: Vec<(String, Reading)>) {
    for (node, reading) in collected {
        if reading.reachable {
            readings.insert(node, reading);
        } else {
            match readings.get_mut(&node) {
                Some(prev) => prev.reachable = false,
                None => {
                    readings.insert(node, reading);
                }
            }
        }
    }
}

/// What this site calls itself.
pub fn site_name() -> String {
    std::env::var("FURCATE_SITE_NAME")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|h| h.trim().to_string()))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "this site".into())
}

/// Sites placed on this machine by `furcate deploy`.
///
/// Read from the deploy root rather than held in memory: the deploy command
/// owns that directory, and a second copy of the list here would be a second
/// answer to what is hosted.
pub fn hosted_sites() -> Vec<web::HostedSite> {
    let root = std::env::var("FURCATE_DEPLOY_ROOT")
        .unwrap_or_else(|_| "/var/lib/furcate/deploy".into());
    let dir = std::path::Path::new(&root).join("sites");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();
    paths
        .iter()
        .filter_map(|d| {
            let text = std::fs::read_to_string(d.join("site.json")).ok()?;
            let v: serde_json::Value = serde_json::from_str(&text).ok()?;
            Some(web::HostedSite {
                name: v.get("name")?.as_str()?.to_string(),
                domains: v
                    .get("domains")
                    .and_then(|d| d.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                // The release is whatever `current` points at, which is the
                // only statement about what is being served that cannot go
                // stale independently of the thing serving it.
                release: std::fs::read_link(d.join("current"))
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())),
                tier: v
                    .get("tier")
                    .and_then(|t| t.as_str())
                    .unwrap_or("static")
                    .to_string(),
            })
        })
        .collect()
}

/// Whether peers are verified, as the node next door reports it.
pub fn overlay_lock_state() -> Option<bool> {
    let text = std::fs::read_to_string(furcate_paths::config("overlay-anchors.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(v.as_array().is_some_and(|a| !a.is_empty()))
}

pub(crate) fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The site as seen from one node: who to ask, and what they last said.
///
/// Targets are addresses, because an address is what an operator configures
/// and what can be dialled. The identity a node reports at that address is
/// shown as the node's claim; whether it is a verified member is a separate
/// fact the caller supplies from its own membership, so the view never
/// upgrades a claim on its own.
#[derive(Debug, Default)]
pub struct SiteView {
    /// The address this node itself answers on, so it lists itself.
    pub own: Option<String>,
    /// Every address this view asks, this node's own included.
    pub targets: Vec<String>,
    /// Last reading per address.
    pub readings: Readings,
}

impl SiteView {
    /// A view over this node and the peers it was told about.
    ///
    /// Duplicates are dropped, so a peer list that names this node too does
    /// not show it twice.
    pub fn new(own: Option<String>, peers: impl IntoIterator<Item = String>) -> Self {
        let mut targets: Vec<String> = own.iter().cloned().collect();
        for p in peers {
            let p = p.trim().to_string();
            if !p.is_empty() && !targets.contains(&p) {
                targets.push(p);
            }
        }
        Self { own, targets, readings: Readings::new() }
    }

    /// From the environment the node agent already reads: `FURCATE_LISTEN`
    /// for itself and `FURCATE_PEERS` for the machines it joins, so the
    /// machines it shows and the machines it gossips with are one list.
    pub fn from_env() -> Self {
        let own = std::env::var("FURCATE_LISTEN").ok().filter(|v| !v.is_empty());
        let peers = std::env::var("FURCATE_PEERS").unwrap_or_default();
        Self::new(own, peers.split(',').map(str::to_string).collect::<Vec<_>>())
    }

    /// The JSON answer: every target, with its freshness and last reading.
    ///
    /// `members` is the set of node ids the caller has verified, typically its
    /// membership's alive set. A node whose reported id is in it is marked
    /// `member`; anything else is shown, but as what it says it is.
    pub fn fleet(&self, now: u64, members: &BTreeSet<String>) -> serde_json::Value {
        let nodes: Vec<_> = self
            .targets
            .iter()
            .map(|endpoint| {
                let reading = self.readings.get(endpoint);
                let node_id = reading
                    .and_then(|r| r.health.as_ref())
                    .and_then(|h| h.get("node_id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                json!({
                    "node_id": node_id,
                    "endpoint": endpoint,
                    "self": self.own.as_deref() == Some(endpoint.as_str()),
                    "member": node_id.as_ref().is_some_and(|id| members.contains(id)),
                    "freshness": freshness(reading, now),
                    "as_of_secs_ago": reading.map(|r| now.saturating_sub(r.at)),
                    "health": reading.and_then(|r| r.health.clone()),
                    "workloads": reading.and_then(|r| r.workloads.clone()),
                    "custody": reading.and_then(|r| r.custody.clone()),
                })
            })
            .collect();
        let fresh = nodes.iter().filter(|n| n["freshness"] == "fresh").count();
        json!({
            "site": site_name(),
            "nodes": nodes,
            "fresh": fresh,
            "of": nodes.len(),
            "stale_after_secs": STALE_SECS,
            "authority": "none: a cached view; every order is verified by the node it concerns",
            "note": if fresh == nodes.len() {
                "every node answered recently"
            } else {
                "some nodes are stale or silent; their workload lists are last known, not current"
            },
        })
    }

    /// Each node's figures for the cell view, by node id: up when its
    /// reading is fresh, and only what it reported, never a zero for a gap.
    pub fn machine_readings(&self, now: u64) -> BTreeMap<String, furcate_topology::cell::MachineReading> {
        let mut out = BTreeMap::new();
        for r in self.readings.values() {
            let Some(h) = r.health.as_ref() else { continue };
            let Some(id) = h.get("node_id").and_then(|v| v.as_str()) else { continue };
            let fresh = freshness(Some(r), now) == "fresh";
            out.insert(
                id.to_string(),
                furcate_topology::cell::MachineReading {
                    up: fresh,
                    cores: h
                        .get("capability")
                        .and_then(|c| c.get("cpu_cores"))
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u32),
                    power_w: h.get("power_w").and_then(|v| v.as_f64()),
                    workloads: r
                        .workloads
                        .as_ref()
                        .and_then(|w| w.get("workloads"))
                        .and_then(|w| w.as_array())
                        .map(|a| a.len() as u32),
                    // Only from a fresh reading: a supply last seen healthy
                    // two minutes ago is not known to be healthy now.
                    supply: if fresh { supply_state(h) } else { None },
                },
            );
        }
        out
    }

    /// The node id each machine answers to under the other names a cell record
    /// uses for it: the key it signs cell links with and its name, both as it
    /// reports them in its own `/healthz`. A key or name two machines claim
    /// is left out rather than given to either.
    pub fn machine_aliases(&self) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, Option<String>> = BTreeMap::new();
        for r in self.readings.values() {
            let Some(h) = r.health.as_ref() else { continue };
            let Some(id) = h.get("node_id").and_then(|v| v.as_str()) else { continue };
            for field in ["cell_key", "name"] {
                let Some(alias) = h.get(field).and_then(|v| v.as_str()).filter(|a| !a.is_empty() && *a != id) else {
                    continue;
                };
                match out.get(alias) {
                    Some(Some(other)) if other != id => {
                        out.insert(alias.to_string(), None);
                    }
                    Some(_) => {}
                    None => {
                        out.insert(alias.to_string(), Some(id.to_string()));
                    }
                }
            }
        }
        out.into_iter().filter_map(|(a, id)| id.map(|id| (a, id))).collect()
    }

    /// What the read-only page states, from the same readings.
    pub fn overview(&self) -> web::Overview {
        let nodes = self
            .targets
            .iter()
            .map(|endpoint| {
                let reading = self.readings.get(endpoint);
                let id = reading
                    .and_then(|r| r.health.as_ref())
                    .and_then(|h| h.get("node_id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| endpoint.clone());
                web::NodeRow {
                    id,
                    workloads: reading
                        .and_then(|r| r.workloads.as_ref())
                        .and_then(|w| w.get("workloads"))
                        .and_then(|w| w.as_array())
                        .map(Vec::len),
                    custody: reading.and_then(|r| r.custody.as_ref()).map(custody_cell),
                    supply: reading
                        .filter(|r| freshness(Some(r), now_s()) == "fresh")
                        .and_then(|r| r.health.as_ref())
                        .and_then(supply_cell),
                    // No node here is a controller: the view holds no
                    // authority, so the page must not name one.
                    controller: false,
                    ..Default::default()
                }
            })
            .collect();
        web::Overview {
            site: site_name(),
            nodes,
            sites: hosted_sites(),
            wall_total_w: None,
            overlay_locked: overlay_lock_state(),
            ledger_entries: 0,
        }
    }
}

/// A node's supply state from its `/healthz`, when it measured one.
pub fn supply_state(health: &serde_json::Value) -> Option<furcate_topology::cell::SupplyState> {
    let supply = health.get("supply")?;
    if supply.get("measured").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    serde_json::from_value(supply.get("state")?.clone()).ok()
}

/// One line for the page: the supply's state and the figures behind it, or
/// nothing when the node measured none.
fn supply_cell(health: &serde_json::Value) -> Option<String> {
    let state = supply_state(health)?;
    let status = &health["supply"]["status"];
    let mut line = state.as_str().to_string();
    if let Some(v) = status.get("ext5v_v").and_then(|v| v.as_f64()) {
        line.push_str(&format!(", 5V rail {v:.2} V"));
    }
    if let Some(c) = status.get("soc_temp_c").and_then(|v| v.as_f64()) {
        line.push_str(&format!(", SoC {c:.0} °C"));
    }
    if status.get("undervoltage_since_boot").and_then(|v| v.as_bool()) == Some(true) {
        line.push_str(", undervolted since boot");
    }
    Some(line)
}

/// One line for the page: whether the node holds custody and at what class,
/// or why not.
fn custody_cell(c: &serde_json::Value) -> String {
    let class = c.get("class").and_then(|v| v.as_str()).unwrap_or("unknown");
    let mode = c.get("mode").and_then(|v| v.as_str()).unwrap_or("unknown");
    if c.get("holds_custody").and_then(|v| v.as_bool()) == Some(true) {
        format!("holds ({mode}, {class})")
    } else {
        let why = c.get("refused").and_then(|v| v.as_str()).unwrap_or("not a holder");
        format!("none ({mode}, {class}): {why}")
    }
}

/// Keep `view` current, every `POLL_SECS`.
///
/// The address list is copied out before polling so the lock is never held
/// across a network call: one unreachable node must not stall every request
/// the view answers.
pub fn spawn_poller(sched: &furcate_sched::Registry, view: Arc<Mutex<SiteView>>) {
    furcate_sched::spawn(
        sched,
        "siteview",
        furcate_sched::Cadence::FixedRate { secs: POLL_SECS },
        furcate_sched::Backoff::default(),
        move || {
            let targets: Vec<(String, String)> = {
                let v = view.lock().expect("siteview lock");
                v.targets.iter().map(|t| (t.clone(), t.clone())).collect()
            };
            if targets.is_empty() {
                return furcate_sched::Ran::Ok;
            }
            let collected = poll(targets, now_s());
            let mut v = view.lock().expect("siteview lock");
            absorb(&mut v.readings, collected);
            furcate_sched::Ran::Ok
        },
    );
}

/// Serve the view: `GET /site` as JSON, and the read-only page at `GET /` with
/// its detail at `GET /dashboard`, the paths the page links between.
///
/// All open routes, because they change nothing and disclose only what each
/// node already answers to anyone who can reach its port. `members` yields the
/// verified node ids at request time.
pub fn routes(
    router: Router,
    view: Arc<Mutex<SiteView>>,
    members: impl Fn() -> BTreeSet<String> + Send + Sync + 'static,
) -> Router {
    router
        .route("GET", "/site", {
            let view = Arc::clone(&view);
            move |_: &Request| {
                let ids = members();
                let v = view.lock().expect("siteview lock");
                Response::ok(v.fleet(now_s(), &ids))
            }
        })
        .route("GET", "/", {
            let view = Arc::clone(&view);
            move |_: &Request| {
                let v = view.lock().expect("siteview lock");
                Response::html(web::homepage(&v.overview()))
            }
        })
        .route("GET", "/dashboard", {
            let view = Arc::clone(&view);
            move |_: &Request| {
                let v = view.lock().expect("siteview lock");
                Response::html(web::dashboard(&v.overview()))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(at: u64, reachable: bool, id: &str) -> Reading {
        Reading {
            at,
            reachable,
            health: Some(json!({ "node_id": id })),
            workloads: Some(json!({ "workloads": [{"name": "a"}, {"name": "b"}] })),
            custody: Some(json!({
                "mode": "elected",
                "class": "tee",
                "holds_custody": false,
                "refused": "custody.tpm_less is off",
                "holders": [],
            })),
        }
    }

    #[test]
    fn custody_is_part_of_the_view_with_its_reason() {
        let mut v = SiteView::new(Some("10.0.0.1:7616".into()), Vec::<String>::new());
        v.readings.insert("10.0.0.1:7616".into(), reading(100, true, "pi-1"));
        let f = v.fleet(100, &BTreeSet::new());
        assert_eq!(f["nodes"][0]["custody"]["holds_custody"], false);
        let row = &v.overview().nodes[0];
        let cell = row.custody.as_deref().unwrap();
        assert!(cell.starts_with("none (elected, tee)") && cell.contains("tpm_less"), "{cell}");
        assert!(web::dashboard(&v.overview()).contains("custody"));
    }

    #[test]
    fn a_supply_is_carried_only_when_measured_and_fresh() {
        use furcate_topology::cell::SupplyState;
        let mut v = SiteView::new(Some("10.0.0.1:7616".into()), Vec::<String>::new());
        let mut r = reading(1_000, true, "furcate:node:pi");
        r.health = Some(json!({
            "node_id": "furcate:node:pi",
            "supply": {"measured": true, "state": "undervoltage", "age_secs": 3,
                       "status": {"ts": 997, "ext5v_v": 4.71, "soc_temp_c": 61.0}},
        }));
        v.readings.insert("10.0.0.1:7616".into(), r.clone());
        assert_eq!(supply_state(r.health.as_ref().unwrap()), Some(SupplyState::Undervoltage));
        assert_eq!(supply_cell(r.health.as_ref().unwrap()).unwrap(), "undervoltage, 5V rail 4.71 V, SoC 61 °C");
        let m = v.machine_readings(1_010);
        assert_eq!(m["furcate:node:pi"].supply, Some(SupplyState::Undervoltage));
        // A stale reading says nothing about the supply now.
        let m = v.machine_readings(1_001 + STALE_SECS);
        assert_eq!(m["furcate:node:pi"].supply, None);
        // Not measured is not healthy.
        let unmeasured = json!({"supply": {"measured": false, "why": "no report"}});
        assert_eq!(supply_state(&unmeasured), None);
        assert_eq!(supply_state(&json!({"node_id": "x"})), None);
    }

    #[test]
    fn a_key_or_name_two_machines_claim_belongs_to_neither() {
        let mut v = SiteView::new(Some("10.0.0.1:7616".into()), Vec::<String>::new());
        for (ep, id, key, name) in [("10.0.0.1:7616", "furcate:node:a", "p256:aa", "a"), ("10.0.0.2:7616", "furcate:node:b", "p256:bb", "a")] {
            let mut r = reading(100, true, id);
            r.health = Some(json!({"node_id": id, "cell_key": key, "name": name}));
            v.readings.insert(ep.into(), r);
        }
        let a = v.machine_aliases();
        assert_eq!(a["p256:aa"], "furcate:node:a");
        assert_eq!(a["p256:bb"], "furcate:node:b");
        assert!(!a.contains_key("a"));
    }

    #[test]
    fn three_states_not_two() {
        assert_eq!(freshness(None, 1_000), "silent");
        assert_eq!(freshness(Some(&reading(1_000, true, "n")), 1_000 + STALE_SECS), "fresh");
        assert_eq!(freshness(Some(&reading(1_000, true, "n")), 1_001 + STALE_SECS), "stale");
        assert_eq!(freshness(Some(&reading(1_000, false, "n")), 1_000), "stale");
    }

    #[test]
    fn a_failed_pass_keeps_the_last_good_reading() {
        let mut r = Readings::new();
        absorb(&mut r, vec![("a".into(), reading(10, true, "na"))]);
        absorb(
            &mut r,
            vec![(
                "a".into(),
                Reading { at: 40, reachable: false, health: None, workloads: None, custody: None },
            )],
        );
        let kept = &r["a"];
        assert!(!kept.reachable);
        assert_eq!(kept.at, 10);
        assert!(kept.health.is_some());
    }

    #[test]
    fn a_node_that_never_answered_is_listed_as_silent() {
        let v = SiteView::new(Some("10.0.0.1:7616".into()), ["10.0.0.2:7616".to_string()]);
        let f = v.fleet(100, &BTreeSet::new());
        assert_eq!(f["of"], 2);
        assert_eq!(f["fresh"], 0);
        assert_eq!(f["nodes"][1]["freshness"], "silent");
        assert_eq!(f["nodes"][0]["self"], true);
    }

    #[test]
    fn this_node_is_not_listed_twice() {
        let v = SiteView::new(
            Some("10.0.0.1:7616".into()),
            ["10.0.0.1:7616".to_string(), " ".to_string(), "10.0.0.2:7616".to_string()],
        );
        assert_eq!(v.targets, vec!["10.0.0.1:7616", "10.0.0.2:7616"]);
    }

    #[test]
    fn a_claimed_identity_is_not_a_member_until_the_caller_says_so() {
        let mut v = SiteView::new(None, ["10.0.0.2:7616".to_string()]);
        v.readings.insert("10.0.0.2:7616".into(), reading(100, true, "node-b"));
        let none = v.fleet(100, &BTreeSet::new());
        assert_eq!(none["nodes"][0]["node_id"], "node-b");
        assert_eq!(none["nodes"][0]["member"], false);
        let verified: BTreeSet<String> = ["node-b".to_string()].into();
        assert_eq!(v.fleet(100, &verified)["nodes"][0]["member"], true);
    }

    #[test]
    fn the_page_counts_workloads_from_the_reading() {
        let mut v = SiteView::new(None, ["10.0.0.2:7616".to_string()]);
        v.readings.insert("10.0.0.2:7616".into(), reading(100, true, "node-b"));
        let o = v.overview();
        assert_eq!(o.nodes[0].id, "node-b");
        assert_eq!(o.nodes[0].workloads, Some(2));
    }

    #[test]
    fn the_routes_answer_and_change_nothing() {
        let view = Arc::new(Mutex::new(SiteView::new(None, ["10.0.0.2:7616".to_string()])));
        let r = routes(Router::new(), view, BTreeSet::new);
        let paths = r.paths();
        for p in ["GET /site", "GET /", "GET /dashboard"] {
            assert!(paths.iter().any(|have| have == p), "missing {p}: {paths:?}");
        }
        assert!(r.guarded_paths().is_empty(), "the view takes no credentials and grants nothing");
    }
}
