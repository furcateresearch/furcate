//! What the machines are actually running.
//!
//! Until now a node reported its own health — power, temperature, attestation,
//! chain — and said nothing about the work it exists to do. A machine can be
//! attested, cool, on mains and completely useless because the thing it hosts
//! has been crash-looping for an hour.
//!
//! Two positions shape this module.
//!
//! **A service's own health check is not evidence.** A container reporting
//! `healthy` is reporting that *it* believes it is fine, and on this site that
//! exact signal read green while a validator served a freshly-initialised empty
//! database. So a self-reported status is recorded as self-reported and is
//! never promoted to an independent observation.
//!
//! **Furcate observes; it does not restart.** Everything here is read-only.
//! A supervisor that fights another supervisor produces a state neither
//! intended, and the workloads on this site already have one — systemd and
//! Docker both restart what they own. What Furcate adds is a fleet-wide view
//! and the ability to refuse a decision, not another hand on the controls.

use crate::signals::{Severity, Signal, SignalKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadKind {
    /// A systemd unit.
    Unit,
    /// A container.
    Container,
    /// A Kubernetes pod, as this node's container runtime sees it.
    ///
    /// Read from the node's CRI socket rather than from a cluster API, so it
    /// is what is running *here* — which is the question a node agent is
    /// entitled to answer. Asking the control plane would need cluster
    /// credentials and would return somebody else's machines as well.
    Pod,
}

impl WorkloadKind {
    /// What supervises this, for a screen that has to say who to talk to.
    pub fn supervisor(&self) -> &'static str {
        match self {
            WorkloadKind::Unit => "systemd",
            WorkloadKind::Container => "docker",
            WorkloadKind::Pod => "kubelet",
        }
    }

    /// The kind's own name, identical to its serialised form.
    ///
    /// Distinct from [`Self::supervisor`], which names who to talk to rather
    /// than what this is — the two were the same field until something needed
    /// to say `unit` across a privilege boundary and had only `systemd` to
    /// hand. Pinned to the serde name by a test, because a name that differs
    /// between a log line and a JSON field is a filter that matches nothing.
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkloadKind::Unit => "unit",
            WorkloadKind::Container => "container",
            WorkloadKind::Pod => "pod",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Running,
    /// Deliberately not running.
    Stopped,
    /// Exited non-zero, or systemd calls it failed.
    Failed,
    /// Between attempts.
    Restarting,
    /// Present but not classifiable from what was read.
    Unknown,
}

impl RunState {
    pub fn is_broken(&self) -> bool {
        matches!(self, RunState::Failed | RunState::Restarting)
    }
}

/// What a workload says about itself, and how much that is worth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    /// The workload declares a health check and it passes.
    ///
    /// Deliberately named for what it is. This is the workload's opinion of
    /// itself: on this site a participant reported healthy while running
    /// against an empty database, because its check asked whether postgres
    /// answered, not whether it held anything.
    SelfReportedHealthy,
    /// It declares a check and the check fails.
    SelfReportedUnhealthy,
    /// It declares a check that has not settled yet.
    Starting,
    /// It declares no check at all, which is not the same as passing one.
    NoneDeclared,
}

impl Health {
    /// Whether this may be quoted as evidence that the workload works.
    ///
    /// Always false. Every variant here is either the workload's own opinion
    /// or the absence of one, and an independent check is a different thing
    /// that would be a different type.
    pub fn is_independent_evidence(&self) -> bool {
        false
    }

    pub fn is_failing(&self) -> bool {
        matches!(self, Health::SelfReportedUnhealthy)
    }
}

// No `Eq`: a CPU limit is a fraction of a core and floats do not have it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    pub id: String,
    pub kind: WorkloadKind,
    pub state: RunState,
    pub health: Health,
    /// Seconds in the current state, where it could be read.
    pub since_s: Option<u64>,
    /// How many times the supervisor has restarted it over its whole life.
    pub restarts: u32,
    /// Restarts since the previous observation, where there was one.
    ///
    /// Lifetime restarts do not distinguish a container that crash-looped last
    /// week from one crash-looping now — a healthy container that has survived
    /// six host reboots carries six restarts forever. `None` on first sight,
    /// and flapping is not claimed from a single observation.
    pub recent_restarts: Option<u32>,
    /// Whether the site would notice if this stopped. Declared by the
    /// operator, not inferred: nothing in a process table says which of these
    /// is load-bearing.
    pub critical: bool,
    /// Which project this belongs to, where the operator has said.
    ///
    /// Declared, for the same reason `critical` is: a name prefix is a
    /// convention, not a fact, and a machine that guessed would file a
    /// validator under the wrong service the first time somebody renamed
    /// something. `None` means nobody has said — reported as unfiled rather
    /// than swept into an "other" bucket, which would read as a decision.
    pub project: Option<String>,
    /// Ports this publishes, where the supervisor reports them without
    /// privilege. Empty means none were reported, which is not the same as
    /// none being open.
    pub ports: Vec<String>,
    /// Whether the thing supervising this intends it to be running.
    ///
    /// The supervisor already knows — a container's restart policy, a pod's
    /// owning kind — and asking it is the difference between a completed init
    /// job and a crashed database, which otherwise look identical. `None`
    /// where the source did not say, and then nothing is claimed either way.
    pub should_run: Option<bool>,
    /// The image tag this was started from, and the digest it is running.
    ///
    /// Two facts, not one: the tag is what somebody asked for, the digest is
    /// what they got. A tag that resolves elsewhere now is an update that looks
    /// applied and is not.
    pub image: Option<String>,
    pub image_digest: Option<String>,
    /// True when the tag this runs points at a different image on this machine
    /// than the one it is running — pulled, never restarted into.
    pub image_stale: bool,
    /// What the operator declared this may use. `None` means they declared
    /// nothing, which is not the same as declaring no limit.
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit: Option<f64>,
    /// The object an operator actually manages, where one owns this.
    ///
    /// A pod is one replica of a Deployment, a StatefulSet, a DaemonSet or a
    /// Job, with a random suffix. Listing pods is listing the consequences of
    /// something rather than the thing.
    pub owner: Option<Owner>,
    /// The service this is within its project, as the deployment names it.
    ///
    /// `mainnet-participant-1` is the service `participant` of the project
    /// `mainnet`. Two stacks of the same software have the same service names,
    /// which is what makes them comparable.
    pub service: Option<String>,
}

impl Workload {
    /// Restarts *within one observation window* above which a workload is
    /// flapping rather than recovering.
    ///
    /// Deliberately measured against a window rather than a lifetime. A
    /// container that has survived six host reboots carries six restarts
    /// forever and is perfectly healthy; one that restarted three times in the
    /// last thirty seconds is not. Reading the lifetime counter as a rate is
    /// how a stable service gets reported as broken for the rest of its life.
    pub const FLAP_THRESHOLD: u32 = 2;

    pub fn new(id: impl Into<String>, kind: WorkloadKind, state: RunState) -> Self {
        Self {
            id: id.into(),
            kind,
            state,
            health: Health::NoneDeclared,
            since_s: None,
            restarts: 0,
            recent_restarts: None,
            critical: false,
            project: None,
            ports: Vec::new(),
            should_run: None,
            service: None,
            image: None,
            image_digest: None,
            image_stale: false,
            memory_limit_bytes: None,
            cpu_limit: None,
            owner: None,
        }
    }

    /// File this under a project.
    pub fn in_project(mut self, p: Option<String>) -> Self {
        self.project = p;
        self
    }

    /// Record the image this runs, and whether the tag has moved past it.
    pub fn with_image(mut self, tag: Option<String>, digest: Option<String>) -> Self {
        self.image = tag;
        self.image_digest = digest;
        self
    }

    /// Record the limits the operator declared. Zero means undeclared, because
    /// that is how both Docker and cgroups spell it.
    pub fn with_limits(mut self, memory_bytes: u64, nano_cpus: u64) -> Self {
        self.memory_limit_bytes = (memory_bytes > 0).then_some(memory_bytes);
        self.cpu_limit = (nano_cpus > 0).then(|| nano_cpus as f64 / 1_000_000_000.0);
        self
    }

    /// Record the object that owns this.
    pub fn owned_by(mut self, o: Option<Owner>) -> Self {
        self.owner = o;
        self
    }

    /// Whether this is bounded at all — the question `furcate-resource` asks of
    /// every group, answered here per workload.
    pub fn is_unbounded(&self) -> bool {
        self.memory_limit_bytes.is_none()
    }

    /// Record what the supervisor says about whether this should be running.
    pub fn should_run(mut self, yes: Option<bool>) -> Self {
        self.should_run = yes;
        self
    }

    /// Record the service name the deployment gave this.
    pub fn with_service(mut self, s: Option<String>) -> Self {
        self.service = s;
        self
    }

    /// Record the ports the supervisor reported.
    pub fn with_ports(mut self, ports: Vec<String>) -> Self {
        self.ports = ports;
        self
    }

    pub fn critical(mut self) -> Self {
        self.critical = true;
        self
    }

    /// Mark critical only if the operator declared it so.
    pub fn critical_if(mut self, yes: bool) -> Self {
        self.critical = yes;
        self
    }

    pub fn with_health(mut self, h: Health) -> Self {
        self.health = h;
        self
    }

    pub fn with_restarts(mut self, n: u32) -> Self {
        self.restarts = n;
        self
    }

    /// Record how many restarts happened since the previous observation.
    pub fn with_recent_restarts(mut self, n: u32) -> Self {
        self.recent_restarts = Some(n);
        self
    }

    pub fn with_age(mut self, s: u64) -> Self {
        self.since_s = Some(s);
        self
    }

    /// Whether it is restarting faster than it is recovering.
    ///
    /// False on first sight: one observation of a lifetime counter says
    /// nothing about a rate, and claiming otherwise would flag every
    /// long-lived container the moment the agent restarted.
    pub fn is_flapping(&self) -> bool {
        matches!(self.recent_restarts, Some(n) if n > Self::FLAP_THRESHOLD)
    }

    /// Whether something is wrong with this workload.
    ///
    /// A stopped workload is not degraded on its own — plenty of units are
    /// deliberately inactive, and treating every one as a fault would bury the
    /// signal that matters under things nobody asked to be running.
    ///
    /// But a stopped workload *its supervisor intends to be running* is a
    /// different fact, and it was being missed. A container with
    /// `restart: always` that is not running has either crashed past its
    /// policy or been stopped by hand, and both are worth a human. The
    /// supervisor is asked rather than guessed at: without that, a completed
    /// init container and a crashed database are indistinguishable, and this
    /// fleet runs both.
    pub fn is_degraded(&self) -> bool {
        self.state.is_broken()
            || self.health.is_failing()
            || self.is_flapping()
            || self.stopped_but_wanted()
    }

    /// Not running, while whatever supervises it says it should be.
    ///
    /// `None` for `should_run` claims nothing: a source that did not say is not
    /// a source that said no.
    pub fn stopped_but_wanted(&self) -> bool {
        self.should_run == Some(true) && self.state == RunState::Stopped
    }

    /// Health signals for the fleet's own pipeline.
    pub fn signals(&self, node: &str, now: u64) -> Vec<Signal> {
        let mut out = Vec::new();
        if self.state.is_broken() || self.health.is_failing() {
            out.push(Signal::new(
                node,
                SignalKind::WorkloadDown {
                    id: self.id.clone(),
                    critical: self.critical,
                },
                now,
            ));
        }
        if self.is_flapping() {
            out.push(Signal::new(
                node,
                SignalKind::WorkloadFlapping {
                    id: self.id.clone(),
                    restarts: self.recent_restarts.unwrap_or(0),
                },
                now,
            ));
        }
        out
    }
}

/// The Kubernetes object an operator manages, of which a pod is one replica.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub kind: OwnerKind,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    Deployment,
    StatefulSet,
    DaemonSet,
    Job,
    /// Run directly, owned by nothing — a static pod or one somebody applied by
    /// hand. Named rather than guessed at.
    Standalone,
}

impl OwnerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwnerKind::Deployment => "deployment",
            OwnerKind::StatefulSet => "statefulset",
            OwnerKind::DaemonSet => "daemonset",
            OwnerKind::Job => "job",
            OwnerKind::Standalone => "standalone",
        }
    }

    /// Whether this kind is expected to keep running.
    ///
    /// A Job is not: it runs to completion and stops, and reporting a finished
    /// one as down is the same mistake as reporting a completed init container
    /// as a crash.
    pub fn should_keep_running(&self) -> bool {
        !matches!(self, OwnerKind::Job)
    }
}

/// One project's state on one node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRollup {
    /// `None` where the operator has not said which project this belongs to.
    pub project: Option<String>,
    pub total: usize,
    pub running: usize,
    pub degraded: usize,
    /// Degraded *and* declared load-bearing — the ones that need a human.
    pub critical_degraded: usize,
}

impl ProjectRollup {
    /// Whether this needs somebody, as opposed to being worth a look.
    pub fn needs_a_human(&self) -> bool {
        self.critical_degraded > 0
    }
}

/// Something a workload publishes, and whether it is actually being served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub workload: String,
    pub project: Option<String>,
    pub port: String,
    pub live: bool,
}

/// Everything one node is running.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub workloads: Vec<Workload>,
    /// True when the collector could not read one of its sources — no docker
    /// socket, no systemd. An inventory missing a source is not an empty one,
    /// and a controller must be able to tell the difference.
    pub partial: bool,
}

impl Inventory {
    pub fn degraded(&self) -> Vec<&Workload> {
        self.workloads.iter().filter(|w| w.is_degraded()).collect()
    }

    pub fn critical_degraded(&self) -> Vec<&Workload> {
        self.workloads
            .iter()
            .filter(|w| w.critical && w.is_degraded())
            .collect()
    }

    /// Whether this node is carrying work that must not be interrupted.
    ///
    /// Consumed by consolidation: a node hosting a healthy critical workload
    /// is not a candidate for suspension however idle its processor looks.
    pub fn has_unmovable_work(&self) -> bool {
        self.workloads.iter().any(|w| w.critical && w.state == RunState::Running)
    }

    /// Whether the picture is good enough to decide on.
    pub fn is_complete(&self) -> bool {
        !self.partial
    }

    pub fn signals(&self, node: &str, now: u64) -> Vec<Signal> {
        self.workloads.iter().flat_map(|w| w.signals(node, now)).collect()
    }

    /// Everything, filed under the project it was declared to belong to.
    ///
    /// Ordered with the unfiled last and named as such. A project nobody has
    /// declared is a gap in the site's own description of itself, and burying
    /// it under "other" alongside real projects hides that.
    pub fn by_project(&self) -> Vec<(Option<String>, Vec<&Workload>)> {
        let mut named: BTreeMap<String, Vec<&Workload>> = BTreeMap::new();
        let mut unfiled: Vec<&Workload> = Vec::new();
        for w in &self.workloads {
            match &w.project {
                Some(p) => named.entry(p.clone()).or_default().push(w),
                None => unfiled.push(w),
            }
        }
        let mut out: Vec<(Option<String>, Vec<&Workload>)> =
            named.into_iter().map(|(k, v)| (Some(k), v)).collect();
        if !unfiled.is_empty() {
            out.push((None, unfiled));
        }
        out
    }

    /// The projects this node carries, in order.
    pub fn projects(&self) -> Vec<String> {
        let mut v: Vec<String> =
            self.workloads.iter().filter_map(|w| w.project.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Whether any workload of a project is degraded.
    ///
    /// The question an operator asks is about the service, not the process:
    /// "is orchid all right" rather than "is orchid-participant-1 all right".
    pub fn project_is_degraded(&self, project: &str) -> bool {
        self.workloads
            .iter()
            .any(|w| w.project.as_deref() == Some(project) && w.is_degraded())
    }

    /// A per-project roll-up: running, degraded, and the total.
    ///
    /// The question an operator asks about a site is about the service, not the
    /// process — "is orchid-mainnet all right", not "is
    /// mainnet-participant-1 all right". A fleet view that lists processes
    /// makes them do that arithmetic in their head across every node.
    pub fn rollup(&self) -> Vec<ProjectRollup> {
        let mut by: BTreeMap<Option<String>, ProjectRollup> = BTreeMap::new();
        for w in &self.workloads {
            let e = by.entry(w.project.clone()).or_insert_with(|| ProjectRollup {
                project: w.project.clone(),
                ..Default::default()
            });
            e.total += 1;
            if w.state == RunState::Running {
                e.running += 1;
            }
            if w.is_degraded() {
                e.degraded += 1;
                if w.critical {
                    e.critical_degraded += 1;
                }
            }
        }
        by.into_values().collect()
    }

    /// Everything published, for a map of what listens where.
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.workloads
            .iter()
            .filter(|w| !w.ports.is_empty())
            .flat_map(|w| {
                w.ports.iter().map(move |p| Endpoint {
                    workload: w.id.clone(),
                    project: w.project.clone(),
                    port: p.clone(),
                    // A port published by something that is not running is not
                    // a service, and a map that showed it as one would send
                    // somebody to debug a connection that was never offered.
                    live: w.state == RunState::Running,
                })
            })
            .collect()
    }

    /// The worst severity present, for a one-line fleet summary.
    pub fn worst(&self) -> Option<Severity> {
        self.workloads
            .iter()
            .flat_map(|w| w.signals("", 0))
            .map(|s| s.severity)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kinds_name_matches_its_serialised_form() {
        for k in [WorkloadKind::Unit, WorkloadKind::Container, WorkloadKind::Pod] {
            assert_eq!(
                serde_json::to_string(&k).expect("serialise"),
                format!("\"{}\"", k.as_str()),
                "{k:?}"
            );
        }
        // And it is not the supervisor, which answers a different question.
        assert_ne!(WorkloadKind::Unit.as_str(), WorkloadKind::Unit.supervisor());
    }

    fn container(id: &str, state: RunState) -> Workload {
        Workload::new(id, WorkloadKind::Container, state)
    }

    #[test]
    fn a_container_reporting_healthy_is_not_independent_evidence() {
        // The failure this encodes: a participant reported healthy while
        // serving a freshly-initialised empty database, because its check
        // asked whether postgres answered rather than whether it held
        // anything.
        let w = container("mainnet-participant-1", RunState::Running)
            .with_health(Health::SelfReportedHealthy);
        assert!(!w.health.is_independent_evidence());
        assert!(!w.is_degraded(), "and it is still not a fault");
    }

    #[test]
    fn declaring_no_health_check_is_not_the_same_as_passing_one() {
        let w = container("shop-backend", RunState::Running);
        assert_eq!(w.health, Health::NoneDeclared);
        assert!(!w.health.is_independent_evidence());
    }

    #[test]
    fn a_deliberately_stopped_workload_is_not_degraded() {
        // Treating every inactive unit as a fault buries the signal that
        // matters under things nobody asked to be running.
        assert!(!container("some-oneshot", RunState::Stopped).is_degraded());
    }

    #[test]
    fn a_failed_workload_is() {
        assert!(container("api-node", RunState::Failed).is_degraded());
        assert!(container("api-node", RunState::Restarting).is_degraded());
    }

    #[test]
    fn a_long_lived_container_with_old_restarts_is_not_flapping() {
        // The bug this encodes, found on real data: mainnet-nginx-1 carried
        // six restarts accumulated over months of host reboots and was
        // reported degraded while running perfectly.
        let w = container("mainnet-nginx-1", RunState::Running)
            .with_restarts(6)
            .with_recent_restarts(0);
        assert!(!w.is_flapping());
        assert!(!w.is_degraded());
    }

    #[test]
    fn a_first_observation_never_claims_flapping() {
        // One reading of a lifetime counter says nothing about a rate, and
        // claiming otherwise flags every long-lived container the moment the
        // agent restarts.
        let w = container("x", RunState::Running).with_restarts(500);
        assert_eq!(w.recent_restarts, None);
        assert!(!w.is_flapping());
    }

    #[test]
    fn a_few_restarts_in_one_window_are_a_supervisor_doing_its_job() {
        let w = container("x", RunState::Running).with_recent_restarts(2);
        assert!(!w.is_flapping());
    }

    #[test]
    fn restarting_repeatedly_within_one_window_is_flapping() {
        let w = container("x", RunState::Running)
            .with_restarts(40)
            .with_recent_restarts(5);
        assert!(w.is_flapping());
        assert!(w.is_degraded(), "even though it is currently up");
    }

    #[test]
    fn a_flapping_workload_raises_a_signal_carrying_the_recent_count() {
        // The rate is what an operator needs, not the lifetime total.
        let w = container("x", RunState::Running)
            .with_restarts(40)
            .with_recent_restarts(5);
        let s = w.signals("node-a", 100);
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0].kind, SignalKind::WorkloadFlapping { restarts: 5, .. }));
    }

    #[test]
    fn a_failed_critical_workload_raises_a_signal_that_says_it_is_critical() {
        let w = container("mainnet-participant-1", RunState::Failed).critical();
        let s = w.signals("node-b", 100);
        assert!(matches!(
            s[0].kind,
            SignalKind::WorkloadDown { critical: true, .. }
        ));
    }

    #[test]
    fn criticality_is_declared_rather_than_inferred() {
        // Nothing in a process table says which of these is load-bearing.
        assert!(!container("x", RunState::Running).critical);
        assert!(container("x", RunState::Running).critical().critical);
    }

    #[test]
    fn an_unreadable_source_makes_the_inventory_partial_not_empty() {
        // A controller must be able to tell "nothing is running" from "I could
        // not look", because they justify opposite decisions.
        let inv = Inventory { workloads: vec![], partial: true };
        assert!(!inv.is_complete());
        assert!(inv.degraded().is_empty());
    }

    #[test]
    fn a_node_running_critical_work_is_not_a_consolidation_candidate() {
        let inv = Inventory {
            workloads: vec![
                container("mainnet-validator-1", RunState::Running).critical(),
                container("idle-thing", RunState::Running),
            ],
            partial: false,
        };
        assert!(inv.has_unmovable_work());
    }

    #[test]
    fn a_node_running_nothing_critical_is() {
        let inv = Inventory {
            workloads: vec![container("idle-thing", RunState::Running)],
            partial: false,
        };
        assert!(!inv.has_unmovable_work());
    }

    #[test]
    fn critical_failures_are_separable_from_ordinary_ones() {
        let inv = Inventory {
            workloads: vec![
                container("mainnet-participant-1", RunState::Failed).critical(),
                container("scratch", RunState::Failed),
            ],
            partial: false,
        };
        assert_eq!(inv.degraded().len(), 2);
        assert_eq!(inv.critical_degraded().len(), 1);
    }
}
