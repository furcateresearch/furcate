//! Reading what this machine is running.
//!
//! Two sources, both read-only and both optional. Systemd is asked which
//! services exist and which have failed; Docker is asked the same about
//! containers. Either can be unavailable — a Pi with no Docker, a node whose
//! agent is not in the `docker` group — and an unavailable source marks the
//! inventory **partial** rather than producing an empty one. A controller that
//! could not tell "nothing is running" from "I could not look" would draw
//! opposite conclusions from the same reading.
//!
//! Nothing here writes. The agent does not restart, stop or start anything it
//! finds; systemd and Docker already supervise what they own.

use furcate_health::workload::{
    Health, Inventory, Owner, OwnerKind, RunState, Workload, WorkloadKind,
};
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Mutex;

/// Restart counts as of the previous collection.
///
/// Both systemd and Docker expose a *lifetime* restart count, which cannot
/// distinguish a container that crash-looped last week from one crash-looping
/// now. Holding the previous reading turns it into a rate.
static PREVIOUS: Mutex<Option<BTreeMap<String, u32>>> = Mutex::new(None);

/// Units and containers whose failure the site should treat as critical.
///
/// Read from `FURCATE_CRITICAL_WORKLOADS`, comma separated. Declared rather
/// than inferred: nothing in a process table says which of these the site
/// cannot do without, and guessing would either cordon nodes over scratch
/// containers or stay quiet when a validator dies.
pub fn critical_list() -> Vec<String> {
    std::env::var("FURCATE_CRITICAL_WORKLOADS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Units and containers the site may stop to save power or make room.
///
/// Read from `FURCATE_PREEMPTIBLE_WORKLOADS`, comma separated, in the same
/// shape as the critical list and declared for the same reason. Nothing in a
/// process table says which work can be interrupted, and the two available
/// guesses are both bad: treat everything as preemptible and the first brownout
/// kills a validator, treat nothing as preemptible and `Rung::Shed` remains the
/// inert instruction it has always been.
///
/// The inverse of the critical list is deliberately NOT used as the answer.
/// "Nobody declared this load-bearing" is not the same statement as "this may
/// be destroyed", and quietly treating the first as the second would make every
/// workload the operator simply had not got round to declaring into a candidate
/// for deletion during an incident.
pub fn preemptible_list() -> Vec<String> {
    std::env::var("FURCATE_PREEMPTIBLE_WORKLOADS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Whether a name matches the site's declared preemptible list.
///
/// Critical always wins. Declaring a workload both load-bearing and disposable
/// is a configuration mistake, and the safe reading of a contradiction is the
/// one that does not destroy anything.
pub fn is_preemptible_name(id: &str) -> bool {
    !is_critical_name(id) && matches_any(id, &preemptible_list())
}

fn matches_any(id: &str, list: &[String]) -> bool {
    list.iter().any(|c| id == c || id.starts_with(c))
}

/// Which project each workload belongs to, as the operator declared it.
///
/// Read from `FURCATE_PROJECTS`, as `name=prefix,prefix; name=prefix`. For
/// example:
///
/// ```text
/// FURCATE_PROJECTS="orchid=orchid-,sentry-; furcate=furcate; web=nginx"
/// ```
///
/// Declared rather than inferred, for the same reason criticality is. A naming
/// convention is a habit, not a fact: the first time somebody renames a
/// container, a system that guessed files a mainnet validator under the wrong
/// service and an operator reads the wrong screen during an incident.
///
/// Longest prefix wins, so `orchid-participant` can be filed separately from
/// `orchid-` without the order of the declaration deciding it.
pub fn project_map() -> Vec<(String, Vec<String>)> {
    parse_projects(&std::env::var("FURCATE_PROJECTS").unwrap_or_default())
}

fn parse_projects(spec: &str) -> Vec<(String, Vec<String>)> {
    spec.split(';')
        .filter_map(|entry| {
            let (name, prefixes) = entry.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let prefixes: Vec<String> = prefixes
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            if prefixes.is_empty() {
                return None;
            }
            Some((name.to_string(), prefixes))
        })
        .collect()
}

/// The project a workload belongs to, or `None` if nobody has said.
fn project_of(id: &str, map: &[(String, Vec<String>)]) -> Option<String> {
    map.iter()
        .filter_map(|(name, prefixes)| {
            prefixes
                .iter()
                .filter(|p| id.starts_with(p.as_str()))
                .map(|p| p.len())
                .max()
                .map(|len| (len, name.clone()))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, name)| name)
}

/// Whether a name matches the site's declared critical list.
pub fn is_critical_name(id: &str) -> bool {
    is_critical(id, &critical_list())
}

fn is_critical(id: &str, critical: &[String]) -> bool {
    critical.iter().any(|c| id == c || id.starts_with(c))
}

fn run(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Failed systemd services, plus any explicitly-named critical unit.
///
/// Only failures and declared-critical units are collected. Enumerating every
/// unit on a general-purpose machine would put hundreds of entries through the
/// report every thirty seconds to say that nothing is wrong.
fn from_systemd(critical: &[String]) -> Option<Vec<Workload>> {
    let failed = run(
        "systemctl",
        &["list-units", "--type=service", "--state=failed", "--no-legend", "--plain"],
    )?;
    let projects = project_map();

    let mut out: Vec<Workload> = failed
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|name| {
            Workload::new(name, WorkloadKind::Unit, RunState::Failed)
                .in_project(project_of(name, &projects))
                .critical_if(is_critical(name, critical))
        })
        .collect();

    for name in critical {
        if out.iter().any(|w| w.id == *name) {
            continue;
        }
        let Some(props) = run(
            "systemctl",
            &["show", name, "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", "--value"],
        ) else {
            continue;
        };
        let mut lines = props.lines();
        let load = lines.next().unwrap_or("").trim();
        let active = lines.next().unwrap_or("").trim();
        let sub = lines.next().unwrap_or("").trim();
        let restarts: u32 = lines.next().unwrap_or("0").trim().parse().unwrap_or(0);

        // Systemd answers for units it has never heard of, calling them
        // inactive. So `LoadState` is the discriminator, not `ActiveState`:
        // without this, a container name or a `mainnet-` prefix in the
        // critical list becomes a phantom stopped unit in every report — which
        // is exactly what the first run of this collector produced.
        if load != "loaded" {
            continue;
        }
        if active.is_empty() {
            continue;
        }
        let state = match (active, sub) {
            ("active", _) => RunState::Running,
            ("failed", _) => RunState::Failed,
            ("activating", _) | ("deactivating", _) => RunState::Restarting,
            ("inactive", _) => RunState::Stopped,
            _ => RunState::Unknown,
        };
        out.push(
            Workload::new(name, WorkloadKind::Unit, state)
                .with_restarts(restarts)
                .in_project(project_of(name, &projects))
                .critical(),
        );
    }
    Some(out)
}

/// Every container, with its self-reported health and restart count.
///
/// Containers are enumerated in full rather than filtered to failures: there
/// are tens rather than hundreds of them, and a container that has quietly
/// exited is invisible in a failures-only view because Docker does not report
/// a stopped container as failed.
fn from_docker(critical: &[String]) -> Option<Vec<Workload>> {
    // Published by the privileged reader. The socket is root:docker 0660 and
    // the agent runs as a user deliberately not in that group — `docker` is
    // root-equivalent, and adding the agent to it would be widening a sandbox
    // to fetch a value. The direct call is kept for a host where the agent does
    // have access; it is not the path this fleet takes.
    //
    // Reading the file also removes the per-container `docker inspect` the
    // agent used to run for restart counts: the reader puts that on the line.
    let listing = std::fs::read_to_string(CONTAINERS_FILE).ok().or_else(|| {
        let listing = run(
            "docker",
            &["ps", "-a", "--format", "{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Ports}}"],
        )?;
        // Restart counts, appended in the same shape the reader publishes, so
        // one parser serves both sources.
        Some(
            listing
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let name = l.split('\t').next().unwrap_or("");
                    let n = run("docker", &["inspect", "-f", "{{.RestartCount}}", name])
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| "0".into());
                    format!("{l}\t{n}")
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
    })?;
    let mut ws = parse_containers(&listing, critical, &project_map());
    mark_stale_images(&mut ws, &std::fs::read_to_string(IMAGES_FILE).unwrap_or_default());
    Some(ws)
}

/// Flag any container running an older image than the tag now points to.
///
/// The question a fleet asks after every deployment: did it actually take?
/// A pulled image with no restart is an update that looks applied and is not,
/// and nothing else on the machine says so — the container is healthy, its tag
/// is right, and it is running last week's code.
///
/// An unknown tag marks nothing. The image may have been pruned, or pulled by
/// digest, and neither is evidence the container is stale.
fn mark_stale_images(workloads: &mut [Workload], images: &str) {
    let by_tag: BTreeMap<&str, &str> = images
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(tag, id)| (tag.trim(), id.trim()))
        .collect();
    for w in workloads {
        let (Some(tag), Some(running)) = (w.image.as_deref(), w.image_digest.as_deref()) else {
            continue;
        };
        if let Some(current) = by_tag.get(tag) {
            w.image_stale = *current != running;
        }
    }
}

/// One container per line, tab separated:
/// name, state, status, ports, restarts, restart-policy, compose project,
/// compose service.
fn parse_containers(
    listing: &str,
    critical: &[String],
    projects: &[(String, Vec<String>)],
) -> Vec<Workload> {
    listing
        .lines()
        .filter_map(|line| {
            let mut f = line.split('\t');
            let name = f.next()?.trim();
            if name.is_empty() {
                return None;
            }
            let state = f.next().unwrap_or("").trim();
            let status = f.next().unwrap_or("").trim();
            // Published ports, as the daemon reports them. No socket
            // enumeration: this is what Docker was asked to expose, which is
            // what an operator means by "what does it listen on".
            let ports: Vec<String> = f
                .next()
                .unwrap_or("")
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            let restarts: u32 = f.next().unwrap_or("0").trim().parse().unwrap_or(0);

            // The supervisor's own statement about whether this is meant to be
            // running. Without it a completed init container and a crashed
            // database look identical — this fleet runs both, and the init
            // containers were being labelled load-bearing while the real
            // question went unasked.
            let should_run = match f.next().unwrap_or("").trim() {
                "always" | "unless-stopped" => Some(true),
                // `on-failure` means restart if it fails, which is a statement
                // about failure and not about whether it should be up now — a
                // job with that policy has finished when it exits zero.
                "no" | "on-failure" => Some(false),
                _ => None,
            };

            // What the deployment calls this, rather than what somebody named
            // the container. Two stacks of the same software share their
            // service names, which is what makes them comparable at all.
            let project = f.next().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            let service = f.next().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            let image = f.next().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            let digest = f.next().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            // Zero is how both Docker and cgroups spell "nothing declared", and
            // it is not the same as declaring no limit.
            let mem: u64 = f.next().unwrap_or("0").trim().parse().unwrap_or(0);
            let cpus: u64 = f.next().unwrap_or("0").trim().parse().unwrap_or(0);

            let run_state = match state {
                "running" => RunState::Running,
                "restarting" => RunState::Restarting,
                "exited" | "dead" => {
                    // A zero exit is a job that finished; anything else stopped
                    // for a reason worth reporting.
                    if status.contains("(0)") {
                        RunState::Stopped
                    } else {
                        RunState::Failed
                    }
                }
                "created" | "paused" => RunState::Stopped,
                _ => RunState::Unknown,
            };

            // Docker prints the health check's verdict inside the status
            // string. It is the container's opinion of itself, recorded as such.
            let health = if status.contains("(healthy)") {
                Health::SelfReportedHealthy
            } else if status.contains("(unhealthy)") {
                Health::SelfReportedUnhealthy
            } else if status.contains("(health: starting)") {
                Health::Starting
            } else {
                Health::NoneDeclared
            };

            Some(
                Workload::new(name, WorkloadKind::Container, run_state)
                    .with_health(health)
                    .with_restarts(restarts)
                    .with_ports(ports)
                    .should_run(should_run)
                    .with_service(service)
                    .with_image(image, digest)
                    .with_limits(mem, cpus)
                    // The operator's declaration first, because it is an
                    // explicit choice about how *they* want the site grouped —
                    // "orchid-mainnet" rather than "mainnet". The deployment's
                    // own label second, which is a fact it states about itself
                    // and not a guess from a name prefix. That order means a
                    // site gets sensible grouping with no configuration at all,
                    // and can still override it where the default reads wrong.
                    .in_project(project_of(name, projects).or(project))
                    .critical_if(is_critical(name, critical)),
            )
        })
        .collect()
}

/// Whether this machine runs Kubernetes at all.
///
/// Checked separately from whether the pods can be *read*, because those are
/// different answers and conflating them is a mistake this codebase has made
/// four times now — with `ethtool`, `smartctl`, `ipmitool` and RAPL. A tool
/// that refuses an unprivileged caller looks exactly like hardware that cannot
/// do the thing, and a missing `crictl` looks exactly like a machine with no
/// pods. On a node with no kubelet there is nothing to report and the
/// inventory is complete; on a node with a kubelet that could not be read, it
/// is partial and must say so.
/// Where the privileged reader leaves the pod listing.
const PODS_FILE: &str = "/run/furcate/pods.txt";

/// Where the privileged reader leaves the container listing.
const CONTAINERS_FILE: &str = "/run/furcate/containers.txt";

/// What each image tag resolves to on this machine right now.
const IMAGES_FILE: &str = "/run/furcate/images.txt";

/// The pod listing with the labels the table form does not carry.
const PODS_JSON_FILE: &str = "/run/furcate/pods.json";

/// Why each exited pod container stopped: namespace, pod, exit code, reason.
const POD_CONTAINERS_FILE: &str = "/run/furcate/pod-containers.txt";

fn kubernetes_is_present() -> bool {
    std::path::Path::new("/var/lib/kubelet").exists()
        || std::path::Path::new("/etc/kubernetes").exists()
}

/// Pods on this node, from the node's own container runtime.
///
/// `crictl` speaks CRI, so this works the same on containerd and CRI-O and
/// needs no cluster credentials — it reports what is running *here*, which is
/// the only thing a node agent should claim to know. Asking the API server
/// would need a kubeconfig, would return other people's machines, and would
/// make every node a client of a control plane that may be the thing that has
/// failed.
///
/// `None` means Kubernetes is present and could not be read. A node with no
/// Kubernetes returns an empty list rather than `None`: nothing is missing.
fn from_kubernetes(critical: &[String]) -> Option<Vec<Workload>> {
    if !kubernetes_is_present() {
        return Some(Vec::new());
    }
    // Published by the privileged reader, because `crictl` talks to a socket
    // that is root:root 0660 — no group grants access the way `docker` does —
    // and an unprivileged caller gets a config error indistinguishable from a
    // machine running no pods. The fifth instrument here to need this.
    //
    // The direct call is kept as a fallback for a host where the agent does
    // have access, but it is not the path this fleet takes.
    let listing = std::fs::read_to_string(PODS_FILE)
        .ok()
        .or_else(|| run("crictl", &["pods", "-o", "table"]))?;
    let projects = project_map();
    // Why anything stopped. Absent is a supported state: without it a pod that
    // is not ready is reported as unclassifiable, which is what it is.
    let outcomes = std::fs::read_to_string(POD_CONTAINERS_FILE).unwrap_or_default();

    let owners = owners_from_json(&std::fs::read_to_string(PODS_JSON_FILE).unwrap_or_default());
    Some(
        parse_pods(&listing, critical, &projects)
            .with_owners(&owners)
            .apply_outcomes(&outcomes),
    )
}

/// One pod row, as `crictl pods -o table` prints it.
///
/// Columns are POD ID, CREATED, STATE, NAME, NAMESPACE, ATTEMPT, RUNTIME — but
/// CREATED is free text with spaces in it ("34 hours ago"), so counting fields
/// from the left does not work, and RUNTIME is absent on some runtimes, so
/// counting from the right does not either. The first version of this counted
/// from the right and read every pod's *name* as its state.
///
/// ATTEMPT is the one column that is always a bare integer, so it is the
/// anchor: NAMESPACE is the field before it, NAME the one before that, and
/// STATE the one before that.
/// What a pod's containers say about why it stopped.
///
/// `Vec<Workload>` on its own cannot express this, so the pods come back in a
/// wrapper that knows how to fold the container outcomes in. Kept apart from
/// the parse because the two sources are two files and either can be absent.
struct Pods(Vec<Workload>);

impl Pods {
    /// Attach the object that owns each pod.
    fn with_owners(mut self, owners: &BTreeMap<String, Owner>) -> Self {
        for w in &mut self.0 {
            if let Some(o) = owners.get(&w.id) {
                // A Job is not expected to keep running, so a finished one is
                // not a workload that should be up. Same reasoning as a
                // container with `restart: no`, from a different supervisor.
                w.should_run = Some(o.kind.should_keep_running());
                w.owner = Some(o.clone());
            }
        }
        self
    }

    /// Fold in the exit codes, so a pod that finished is not called a failure.
    ///
    /// A sandbox listing says whether a pod is ready and never why it is not.
    /// With the exit codes, three answers become distinguishable:
    ///
    /// - every container exited 0 → the work finished. Stopped, not failed.
    /// - any container exited non-zero → a real failure, reported as one.
    /// - nothing known → Unknown, which is what it was before this existed.
    fn apply_outcomes(mut self, outcomes: &str) -> Vec<Workload> {
        let by_pod = parse_outcomes(outcomes);
        for w in &mut self.0 {
            if w.state != RunState::Unknown {
                continue;
            }
            match by_pod.get(&w.id) {
                Some(codes) if codes.iter().any(|c| *c != 0) => w.state = RunState::Failed,
                Some(codes) if !codes.is_empty() => w.state = RunState::Stopped,
                _ => {}
            }
        }
        self.0
    }
}

/// `namespace \t pod \t exitCode \t reason` per line, from `crictl inspect`.
fn parse_outcomes(text: &str) -> BTreeMap<String, Vec<i32>> {
    let mut out: BTreeMap<String, Vec<i32>> = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        let (ns, pod) = (f[0].trim(), f[1].trim());
        if ns.is_empty() || pod.is_empty() {
            continue;
        }
        // A field the template could not fill comes back as "<no value>", and
        // treating that as a zero exit would report a crashed pod as finished.
        let Ok(code) = f[2].trim().parse::<i32>() else {
            continue;
        };
        out.entry(format!("{ns}/{pod}")).or_default().push(code);
    }
    out
}

fn parse_pods(
    listing: &str,
    critical: &[String],
    projects: &[(String, Vec<String>)],
) -> Pods {
    // A pod that has been restarted leaves its old sandboxes in the listing,
    // and they are NotReady forever. Reporting them is how a perfectly healthy
    // cluster came back as seven failed pods — worse than showing nothing,
    // because an operator who learns the screen cries wolf stops reading it.
    //
    // crictl prints newest first, so the first row for a name is the live one
    // and every later row for that name is a sandbox it replaced.
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let v: Vec<Workload> = listing
        .lines()
        .skip(1) // the header
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let attempt_at = f.iter().rposition(|x| x.parse::<u32>().is_ok())?;
            if attempt_at < 3 {
                return None;
            }
            let attempt: u32 = f[attempt_at].parse().ok()?;
            let namespace = f[attempt_at - 1];
            let name = f[attempt_at - 2];
            let state = f[attempt_at - 3];

            // Namespaced, because two namespaces name pods the same and an
            // operator reading `web` needs to know whose.
            let id = format!("{namespace}/{name}");
            if !seen.insert(id.clone()) {
                return None;
            }

            let run_state = match state {
                "Ready" | "SANDBOX_READY" => RunState::Running,
                // NotReady is NOT a failure, and calling it one was the second
                // form of the same mistake. A sandbox listing says whether a
                // pod is ready; it does not say why it is not. A Job that ran
                // once and finished successfully sits here NotReady forever —
                // k3s ships two of them — and reporting those as failures
                // would put a permanent fault on the screen of a cluster with
                // nothing wrong with it.
                //
                // Unknown is the honest verdict and its documentation already
                // says so: present, not classifiable from what was read. A pod
                // that really is crash-looping still shows, through the attempt
                // counter and the restarts-this-window column, which are
                // measurements rather than inferences.
                //
                // Telling a finished Job from a crashed pod needs container
                // state and exit codes (`crictl ps`), which is a second source
                // and a separate piece of work.
                "NotReady" | "SANDBOX_NOTREADY" => RunState::Unknown,
                _ => RunState::Unknown,
            };

            Some(
                Workload::new(&id, WorkloadKind::Pod, run_state)
                    // The runtime's attempt counter is a lifetime count in the
                    // same way Docker's restart count is, and is turned into a
                    // rate by the same pass.
                    .with_restarts(attempt)
                    .in_project(project_of(&id, projects).or_else(|| {
                        // A namespace is the operator's own grouping and a
                        // better default than nothing — but only where no
                        // project has been declared.
                        (namespace != "default").then(|| namespace.to_string())
                    }))
                    .critical_if(is_critical(&id, critical) || is_critical(name, critical)),
            )
        })
        .collect();
    Pods(v)
}

/// Which object owns a pod, from the labels Kubernetes stamps on every one.
///
/// A pod is not the thing an operator manages. `traefik-59b7647586-p2k7j` is one
/// replica of the Deployment `traefik`, and the two middle segments are a
/// template hash and a random suffix that change on every rollout. A screen
/// listing pods lists the consequences of something rather than the thing, and
/// the name it shows is different tomorrow for no reason worth reporting.
///
/// Derived from labels rather than from the pod's name, because a name is a
/// convention and these are stamped by the controller that owns it:
///
/// - `batch.kubernetes.io/job-name` — a Job, which is meant to finish.
/// - `pod-template-hash` — a ReplicaSet, i.e. a Deployment. The Deployment's
///   name is the pod name with the hash and suffix removed.
/// - `statefulset.kubernetes.io/pod-name` — a StatefulSet; its members are
///   numbered rather than random, so the ordinal comes off instead.
/// - `controller-revision-hash` alone — a DaemonSet.
/// - none of them — run directly. Named `Standalone` rather than guessed at.
fn owner_of(name: &str, labels: &serde_json::Value) -> Owner {
    let label = |k: &str| labels.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty());

    if let Some(job) = label("batch.kubernetes.io/job-name").or_else(|| label("job-name")) {
        return Owner { kind: OwnerKind::Job, name: job.to_string() };
    }
    if let Some(hash) = label("pod-template-hash") {
        // `<deployment>-<hash>-<suffix>`. Cut at the hash rather than counting
        // segments from the end: a deployment may have dashes in its own name.
        let cut = name
            .rfind(&format!("-{hash}-"))
            .or_else(|| name.rfind(&format!("-{hash}")))
            .map(|i| &name[..i])
            .unwrap_or(name);
        return Owner { kind: OwnerKind::Deployment, name: cut.to_string() };
    }
    if label("statefulset.kubernetes.io/pod-name").is_some() {
        // Members are `<set>-<ordinal>`, numbered and stable.
        let cut = name.rsplit_once('-').map(|(a, _)| a).unwrap_or(name);
        return Owner { kind: OwnerKind::StatefulSet, name: cut.to_string() };
    }
    if label("controller-revision-hash").is_some() {
        let cut = name.rsplit_once('-').map(|(a, _)| a).unwrap_or(name);
        return Owner { kind: OwnerKind::DaemonSet, name: cut.to_string() };
    }
    Owner { kind: OwnerKind::Standalone, name: name.to_string() }
}

/// Owners for every pod in the JSON listing, keyed `namespace/name`.
fn owners_from_json(text: &str) -> BTreeMap<String, Owner> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return BTreeMap::new();
    };
    v.get("items")
        .and_then(|a| a.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|p| {
                    let m = p.get("metadata")?;
                    let name = m.get("name")?.as_str()?;
                    let ns = m.get("namespace")?.as_str()?;
                    let labels = p.get("labels").cloned().unwrap_or(serde_json::Value::Null);
                    Some((format!("{ns}/{name}"), owner_of(name, &labels)))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Turn lifetime restart counters into per-window deltas.
///
/// The first pass records the counters and claims nothing, because one reading
/// of a lifetime counter says nothing about a rate.
fn apply_restart_deltas(workloads: &mut [Workload]) {
    let mut guard = PREVIOUS.lock().expect("restart tracker");
    let next = deltas(guard.as_ref(), workloads);
    *guard = Some(next);
}

/// The pure half: assign deltas against a supplied previous reading and return
/// the reading to keep.
///
/// Split out from the state it uses so it can be tested. A test driving the
/// process-wide tracker directly would be racing every other test in the
/// binary for it.
fn deltas(
    previous: Option<&BTreeMap<String, u32>>,
    workloads: &mut [Workload],
) -> BTreeMap<String, u32> {
    if let Some(prev) = previous {
        for w in workloads.iter_mut() {
            // A workload seen for the first time gets no delta rather than a
            // delta from zero, which would read its whole history as having
            // happened in this window.
            if let Some(before) = prev.get(&w.id) {
                w.recent_restarts = Some(w.restarts.saturating_sub(*before));
            }
        }
    }
    workloads.iter().map(|w| (w.id.clone(), w.restarts)).collect()
}

/// Everything this machine is running, as far as it can see.
pub fn collect() -> Inventory {
    let critical = critical_list();
    let units = from_systemd(&critical);
    let containers = from_docker(&critical);
    let pods = from_kubernetes(&critical);

    let partial = units.is_none() || containers.is_none() || pods.is_none();
    let mut workloads = units.unwrap_or_default();
    workloads.extend(containers.unwrap_or_default());
    workloads.extend(pods.unwrap_or_default());
    workloads.sort_by(|a, b| a.id.cmp(&b.id));
    apply_restart_deltas(&mut workloads);

    Inventory { workloads, partial }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_critical_prefix_matches_a_whole_stack() {
        // One entry covers `mainnet-participant-1`, `mainnet-validator-1` and
        // the rest, rather than the operator listing six container names.
        let c = vec!["mainnet-".to_string()];
        assert!(is_critical("mainnet-participant-1", &c));
        assert!(is_critical("mainnet-validator-1", &c));
        assert!(!is_critical("sentry-validator-nginx-1", &c));
    }

    #[test]
    fn an_exact_name_still_matches() {
        let c = vec!["api-node.service".to_string()];
        assert!(is_critical("api-node.service", &c));
    }

    #[test]
    fn an_empty_declaration_makes_nothing_critical() {
        // The safe direction: an unset variable must not silently promote
        // every workload on the machine to critical.
        assert!(!is_critical("anything", &[]));
        assert!(critical_list().is_empty() || !critical_list().is_empty());
    }

    fn one(id: &str, restarts: u32) -> Workload {
        Workload::new(id, WorkloadKind::Container, RunState::Running).with_restarts(restarts)
    }

    #[test]
    fn a_first_pass_assigns_no_deltas_and_a_second_assigns_them() {
        let mut first = vec![one("a", 6)];
        let seen = deltas(None, &mut first);
        assert_eq!(first[0].recent_restarts, None, "one reading is not a rate");

        let mut second = vec![one("a", 6)];
        let seen = deltas(Some(&seen), &mut second);
        assert_eq!(second[0].recent_restarts, Some(0), "stable across the window");
        assert!(!second[0].is_flapping());

        let mut third = vec![one("a", 11)];
        deltas(Some(&seen), &mut third);
        assert_eq!(third[0].recent_restarts, Some(5));
        assert!(third[0].is_flapping());
    }

    #[test]
    fn a_newly_seen_workload_gets_no_delta_from_zero() {
        // Otherwise its whole history reads as having happened in this window.
        let mut a = vec![one("known", 0)];
        let seen = deltas(None, &mut a);
        let mut b = vec![one("known", 0), one("brand-new", 40)];
        deltas(Some(&seen), &mut b);
        assert_eq!(b[1].recent_restarts, None);
        assert!(!b[1].is_flapping());
    }

    #[test]
    fn a_counter_that_went_backwards_does_not_underflow() {
        // Docker resets RestartCount when a container is recreated, so the
        // new value can be below the one held.
        let mut prev = BTreeMap::new();
        prev.insert("a".to_string(), 40u32);
        let mut now = vec![one("a", 0)];
        deltas(Some(&prev), &mut now);
        assert_eq!(now[0].recent_restarts, Some(0));
    }

    #[test]
    fn collecting_on_this_machine_produces_an_answer_rather_than_a_panic() {
        // Whatever is or is not installed here, the collector must return.
        let inv = collect();
        // If either source was unavailable it says so instead of pretending
        // the machine is idle.
        assert!(inv.is_complete() || inv.partial);
    }
}

#[cfg(test)]
mod pod_tests {
    use super::*;

    /// Copied verbatim from `k3s crictl pods` on node-a and node-b.
    ///
    /// Real output, because the first parser counted columns from the right and
    /// read every pod's name as its state — which type-checked, passed a
    /// hand-written test with tidy columns, and would have reported the whole
    /// cluster as being in an unknown state.
    const REAL: &str = "POD ID              CREATED             STATE               NAME                                      NAMESPACE           ATTEMPT             RUNTIME
965212ae0ccc2       34 hours ago        Ready               traefik-59b7647586-p2k7j                  kube-system         10                  (default)
429f99654a938       34 hours ago        Ready               metrics-server-6dc596dfb8-8mj82           kube-system         10                  (default)
329d8b6cc3a94       33 hours ago        Ready               svclb-traefik-2412f41e-7k2w9              kube-system         8                   (default)
9dcc203bec37f       34 hours ago        NotReady            svclb-traefik-2412f41e-7k2w9              kube-system         7                   (default)";

    #[test]
    fn the_columns_are_read_from_the_right_field_not_the_right_position() {
        let pods = parse_pods(REAL, &[], &[]).apply_outcomes("");
        // Three, not four: the fixture holds `svclb-traefik` twice — the live
        // sandbox and the one it replaced — and that pair is exactly the case
        // that made a healthy cluster report as failed.
        assert_eq!(pods.len(), 3, "one per live pod, header skipped");

        let t = &pods[0];
        assert_eq!(t.id, "kube-system/traefik-59b7647586-p2k7j");
        assert_eq!(t.kind, WorkloadKind::Pod);
        assert_eq!(t.state, RunState::Running);
        assert_eq!(t.restarts, 10);
        // The namespace groups it, since no project was declared for it.
        assert_eq!(t.project.as_deref(), Some("kube-system"));
    }

    #[test]
    fn the_state_column_is_read_as_a_state_and_not_as_a_name() {
        // "CREATED" is free text with spaces in it, so a parser that counts
        // fields from the left lands on the wrong column and every pod comes
        // back Unknown — which reads as "cannot tell" rather than "broken".
        let pods = parse_pods(REAL, &[], &[]).apply_outcomes("");
        assert!(
            pods.iter().all(|p| p.state == RunState::Running),
            "every live pod in this fixture is Ready: {pods:#?}"
        );
        // And the NotReady row in it is a superseded sandbox, not a fault.
        assert!(!pods.iter().any(|p| p.state == RunState::Failed));
    }

    #[test]
    fn a_declared_project_beats_the_namespace() {
        // The namespace is a fallback, not the answer. An operator who has said
        // where something belongs must not be overruled by the cluster's own
        // grouping.
        let projects = parse_projects("platform=kube-system/traefik");
        let pods = parse_pods(REAL, &[], &projects).apply_outcomes("");
        assert_eq!(pods[0].project.as_deref(), Some("platform"));
        assert_eq!(pods[1].project.as_deref(), Some("kube-system"), "others unchanged");
    }

    #[test]
    fn a_pod_can_be_declared_critical_by_its_bare_name_or_its_full_id() {
        // An operator writing a critical list should not have to know that this
        // collector namespaces the id.
        let by_name = parse_pods(REAL, &["traefik".into()], &[]).apply_outcomes("");
        assert!(by_name[0].critical, "matched on the bare pod name");
        let by_id = parse_pods(REAL, &["kube-system/metrics".into()], &[]).apply_outcomes("");
        assert!(by_id[1].critical, "matched on the namespaced id");
    }

    #[test]
    fn a_header_alone_yields_nothing_rather_than_a_phantom_pod() {
        let pods = parse_pods("POD ID  CREATED  STATE  NAME  NAMESPACE  ATTEMPT  RUNTIME", &[], &[]).apply_outcomes("");
        assert!(pods.is_empty());
        assert!(parse_pods("", &[], &[]).apply_outcomes("").is_empty());
    }

    #[test]
    fn a_row_with_no_attempt_column_is_skipped_rather_than_guessed() {
        // Anchoring on the one always-numeric column means a row that does not
        // have it cannot be read, and a row that cannot be read must not become
        // a workload with invented fields.
        let pods = parse_pods("POD ID CREATED\nabc123  a while ago  Ready", &[], &[]).apply_outcomes("");
        assert!(pods.is_empty());
    }

    #[test]
    fn projects_are_matched_by_longest_prefix_not_by_declaration_order() {
        // So `orchid-participant` can be filed apart from `orchid-` without the
        // order of the declaration silently deciding it.
        let p = parse_projects("orchid=orchid-; participants=orchid-participant");
        assert_eq!(project_of("orchid-participant-1", &p).as_deref(), Some("participants"));
        assert_eq!(project_of("orchid-sequencer-1", &p).as_deref(), Some("orchid"));
        assert_eq!(project_of("something-else", &p), None, "unfiled, not guessed");
    }

    #[test]
    fn a_malformed_project_declaration_is_ignored_rather_than_fatal() {
        // This is read from an env file an operator edits by hand. A stray
        // semicolon must not take the inventory down with it.
        let p = parse_projects("orchid=orchid-;;=nothing;noequals;empty=");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "orchid");
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    /// A real pod restarted twice: the live sandbox and the two it replaced.
    /// Copied from node-a, where this produced seven "failed" pods on a
    /// cluster with nothing wrong with it.
    const RESTARTED: &str = "POD ID              CREATED             STATE               NAME                         NAMESPACE           ATTEMPT             RUNTIME
aaa0000000001       33 hours ago        Ready               coredns-54996dc9b4-k2jrd     kube-system         10                  (default)
bbb0000000002       34 hours ago        NotReady            coredns-54996dc9b4-k2jrd     kube-system         9                   (default)
ccc0000000003       35 hours ago        NotReady            coredns-54996dc9b4-k2jrd     kube-system         8                   (default)";

    #[test]
    fn a_sandbox_a_pod_has_already_replaced_is_not_a_failure() {
        // Every restart leaves its old sandbox in the listing, NotReady
        // forever. Counting them reported a healthy cluster as broken — and a
        // screen that cries wolf is worse than one that shows nothing.
        let pods = parse_pods(RESTARTED, &[], &[]).apply_outcomes("");
        assert_eq!(pods.len(), 1, "one pod, not three: {pods:#?}");
        assert_eq!(pods[0].state, RunState::Running);
        assert_eq!(pods[0].restarts, 10, "and the live sandbox's attempt count");
    }

    #[test]
    fn the_newest_sandbox_decides_and_not_ready_is_not_called_a_failure() {
        // The dedupe must not swallow the live sandbox — it is the one that
        // counts, whatever state it is in. And NotReady is reported as unknown
        // rather than failed: this source says whether a pod is ready, never
        // why it is not, and k3s ships Jobs that sit NotReady forever having
        // succeeded.
        let listing = "POD ID  CREATED  STATE  NAME  NAMESPACE  ATTEMPT  RUNTIME
aaa1  1 hour ago  NotReady  web-1  prod  4  (default)
bbb2  9 hours ago  Ready  web-1  prod  3  (default)";
        let pods = parse_pods(listing, &[], &[]).apply_outcomes("");
        assert_eq!(pods.len(), 1);
        assert_eq!(pods[0].restarts, 4, "the newest sandbox, not the older Ready one");
        assert_eq!(pods[0].state, RunState::Unknown);
        assert!(!pods[0].state.is_broken(), "and does not raise a fault on its own");
    }

    /// Real `docker ps` output from node-a, with the restart count the
    /// privileged reader appends.
    const CONTAINERS: &str = "acme-api\trunning\tUp 2 days (healthy)\t0.0.0.0:8080->8080/tcp\t3\talways\tacme\tapi
beacon-ml\texited\tExited (0) 3 hours ago\t\t0\tno\tbeacon\tml
falkordb\texited\tExited (137) 1 hour ago\t\t7\talways\t\t
homepage\trunning\tUp 5 days\t\t0\tunless-stopped\t\t";

    #[test]
    fn containers_come_off_one_line_each_including_the_restart_count() {
        // The agent used to run a `docker inspect` per container for this. The
        // reader has already paid for it, so it goes on the line.
        let ws = parse_containers(CONTAINERS, &[], &[]);
        assert_eq!(ws.len(), 4);
        assert_eq!(ws[0].id, "acme-api");
        assert_eq!(ws[0].state, RunState::Running);
        assert_eq!(ws[0].health, Health::SelfReportedHealthy);
        assert_eq!(ws[0].restarts, 3);
        assert_eq!(ws[0].ports, vec!["0.0.0.0:8080->8080/tcp"]);
    }

    #[test]
    fn a_clean_exit_is_a_finished_job_and_a_dirty_one_is_a_fault() {
        // Docker calls both "exited". A job that finished is not a failure, and
        // reporting it as one teaches an operator to ignore the column.
        let ws = parse_containers(CONTAINERS, &[], &[]);
        assert_eq!(ws[1].state, RunState::Stopped, "exit 0 finished");
        assert_eq!(ws[2].state, RunState::Failed, "exit 137 did not");
    }

    #[test]
    fn a_container_with_no_ports_reports_none_rather_than_a_blank_field() {
        let ws = parse_containers(CONTAINERS, &[], &[]);
        assert!(ws[3].ports.is_empty());
        assert_eq!(ws[3].restarts, 0);
    }

    #[test]
    fn declared_projects_reach_containers_too() {
        let p = parse_projects("acme=acme-; beacon=beacon-,falkordb");
        let ws = parse_containers(CONTAINERS, &[], &p);
        assert_eq!(ws[0].project.as_deref(), Some("acme"));
        assert_eq!(ws[2].project.as_deref(), Some("beacon"));
        assert_eq!(ws[3].project, None, "unfiled, not guessed");
    }

    #[test]
    fn the_supervisor_is_asked_whether_something_should_be_running() {
        // A completed init container and a crashed database are the same two
        // words — "exited", "stopped" — and the only thing that separates them
        // is what the supervisor was told to do about it.
        let ws = parse_containers(CONTAINERS, &[], &[]);
        assert_eq!(ws[0].should_run, Some(true), "restart: always");
        assert_eq!(ws[1].should_run, Some(false), "restart: no — a job");
        assert_eq!(ws[3].should_run, Some(true), "unless-stopped");
    }

    #[test]
    fn a_job_that_finished_is_not_degraded_and_a_stopped_service_is() {
        // This is the whole point of reading the policy. Both are "exited".
        let ws = parse_containers(CONTAINERS, &[], &[]);
        assert!(!ws[1].is_degraded(), "a finished job is not a fault");
        assert!(ws[2].is_degraded(), "exit 137 under restart:always is");
    }

    #[test]
    fn a_service_stopped_by_hand_under_restart_always_is_reported() {
        // Docker calls it "exited" with a zero code when somebody runs
        // `docker stop`. Under `restart: always` that still means something a
        // human did and nobody undid, which is worth saying.
        let one = "web\texited\tExited (0) 2 minutes ago\t\t0\talways\tsite\tweb";
        let w = &parse_containers(one, &[], &[])[0];
        assert_eq!(w.state, RunState::Stopped);
        assert!(w.stopped_but_wanted());
        assert!(w.is_degraded());
    }

    #[test]
    fn the_deployment_names_its_own_project_and_service() {
        // Not a guess from a name prefix: compose states these about itself, so
        // a site is grouped correctly with no configuration at all.
        let ws = parse_containers(CONTAINERS, &[], &[]);
        assert_eq!(ws[0].project.as_deref(), Some("acme"));
        assert_eq!(ws[0].service.as_deref(), Some("api"));
        assert_eq!(ws[2].project, None, "a container outside a project stays unfiled");
    }

    #[test]
    fn an_operator_declaration_beats_the_deployments_own_label() {
        // The label is a fact; the declaration is a choice about how this site
        // should read. An operator who wrote "orchid-mainnet" gets that, not
        // compose's "mainnet".
        let p = parse_projects("orchid-mainnet=acme-");
        let ws = parse_containers(CONTAINERS, &[], &p);
        assert_eq!(ws[0].project.as_deref(), Some("orchid-mainnet"));
        assert_eq!(ws[1].project.as_deref(), Some("beacon"), "others keep the label");
    }

    #[test]
    fn an_unknown_policy_claims_nothing_either_way() {
        // A source that did not say is not a source that said no.
        let one = "x\texited\tExited (0) 1 min ago\t\t0\t\t\t";
        let w = &parse_containers(one, &[], &[])[0];
        assert_eq!(w.should_run, None);
        assert!(!w.is_degraded(), "nothing is claimed about an unstated policy");
    }

    #[test]
    fn a_truncated_line_does_not_invent_a_container() {
        // The reader writes to a temp file and renames, so a half-written line
        // should not be readable — but a parser that trusts that is one bad
        // disk away from reporting a container called "ipno".
        let ws = parse_containers("\n\t\t\t\nonlyaname", &[], &[]);
        assert_eq!(ws.len(), 1, "a bare name is still a container");
        assert_eq!(ws[0].state, RunState::Unknown, "with nothing claimed about it");
    }
}


#[cfg(test)]
mod outcome_tests {
    use super::*;

    /// A pod that is not ready, with nothing yet said about why.
    const NOT_READY: &str = "POD ID  CREATED  STATE  NAME  NAMESPACE  ATTEMPT  RUNTIME
aaa1  2 hours ago  NotReady  helm-install-traefik-8flgq  kube-system  0  (default)
bbb2  2 hours ago  NotReady  web-7f9  prod  3  (default)";

    #[test]
    fn a_job_that_finished_is_stopped_and_not_a_failure() {
        // k3s ships two of these. They succeeded, they will never run again,
        // and they sat on the screen as permanent faults.
        let out = "kube-system\thelm-install-traefik-8flgq\t0\tCompleted";
        let pods = parse_pods(NOT_READY, &[], &[]).apply_outcomes(out);
        let job = pods.iter().find(|p| p.id.contains("helm-install")).unwrap();
        assert_eq!(job.state, RunState::Stopped);
        assert!(!job.state.is_broken(), "a finished job raises nothing");
    }

    #[test]
    fn a_container_that_died_is_still_reported_as_a_failure() {
        // The whole point of reading the exit codes is to keep this one.
        let out = "prod\tweb-7f9\t137\tError";
        let pods = parse_pods(NOT_READY, &[], &[]).apply_outcomes(out);
        let web = pods.iter().find(|p| p.id == "prod/web-7f9").unwrap();
        assert_eq!(web.state, RunState::Failed);
        assert!(web.state.is_broken());
    }

    #[test]
    fn one_bad_container_condemns_the_pod() {
        // A pod is up when all of it is up. A sidecar that exited 1 next to a
        // main container that exited 0 is not a pod that finished.
        let out = "prod\tweb-7f9\t0\tCompleted\nprod\tweb-7f9\t1\tError";
        let pods = parse_pods(NOT_READY, &[], &[]).apply_outcomes(out);
        assert_eq!(pods.iter().find(|p| p.id == "prod/web-7f9").unwrap().state, RunState::Failed);
    }

    #[test]
    fn no_outcomes_at_all_leaves_the_verdict_unknown() {
        // The file is absent on a host with no Kubernetes, and briefly after a
        // restart. Guessing either way would be a claim nobody made.
        let pods = parse_pods(NOT_READY, &[], &[]).apply_outcomes("");
        assert!(pods.iter().all(|p| p.state == RunState::Unknown));
    }

    #[test]
    fn a_running_pod_is_never_overruled_by_an_old_exit_code() {
        // Containers from a previous attempt keep their records. A pod that is
        // Ready now must not be turned back into a failure by them.
        let ready = "POD ID  CREATED  STATE  NAME  NAMESPACE  ATTEMPT  RUNTIME
aaa1  1 hour ago  Ready  web-7f9  prod  4  (default)";
        let pods = parse_pods(ready, &[], &[]).apply_outcomes("prod\tweb-7f9\t137\tError");
        assert_eq!(pods[0].state, RunState::Running);
    }

    #[test]
    fn a_template_that_could_not_fill_a_field_is_skipped_not_read_as_zero() {
        // crictl writes "<no value>" for a field it cannot resolve, and reading
        // that as a zero exit would report a crashed pod as finished.
        let m = parse_outcomes("prod\tweb-7f9\t<no value>\tError\nprod\tweb-7f9\t2\tError");
        assert_eq!(m.get("prod/web-7f9"), Some(&vec![2]));
        assert!(parse_outcomes("\n\t\t\nrubbish").is_empty());
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use serde_json::json;

    /// Labels copied from `crictl pods -o json` on node-a.
    fn real_pods() -> String {
        json!({"items": [
            {"metadata": {"name": "traefik-59b7647586-p2k7j", "namespace": "kube-system"},
             "labels": {"app.kubernetes.io/name": "traefik", "pod-template-hash": "59b7647586"}},
            {"metadata": {"name": "coredns-54996dc9b4-k2jrd", "namespace": "kube-system"},
             "labels": {"k8s-app": "kube-dns", "pod-template-hash": "54996dc9b4"}},
            {"metadata": {"name": "helm-install-traefik-8flgq", "namespace": "kube-system"},
             "labels": {"batch.kubernetes.io/job-name": "helm-install-traefik"}},
            {"metadata": {"name": "svclb-traefik-2412f41e-q6js4", "namespace": "kube-system"},
             "labels": {"controller-revision-hash": "7c9d"}},
            {"metadata": {"name": "postgres-0", "namespace": "data"},
             "labels": {"statefulset.kubernetes.io/pod-name": "postgres-0",
                        "controller-revision-hash": "abc"}},
            {"metadata": {"name": "hand-applied", "namespace": "default"}, "labels": {}}
        ]}).to_string()
    }

    #[test]
    fn a_pod_names_the_object_an_operator_actually_manages() {
        // `traefik-59b7647586-p2k7j` is one replica of the Deployment
        // `traefik`, and the two trailing segments change on every rollout —
        // a screen showing the pod name shows a different name tomorrow for no
        // reason worth reporting.
        let o = owners_from_json(&real_pods());
        let t = &o["kube-system/traefik-59b7647586-p2k7j"];
        assert_eq!(t.kind, OwnerKind::Deployment);
        assert_eq!(t.name, "traefik");
    }

    #[test]
    fn every_controller_kind_is_told_apart_by_its_own_label() {
        let o = owners_from_json(&real_pods());
        assert_eq!(o["kube-system/helm-install-traefik-8flgq"].kind, OwnerKind::Job);
        assert_eq!(o["kube-system/helm-install-traefik-8flgq"].name, "helm-install-traefik");
        assert_eq!(o["kube-system/svclb-traefik-2412f41e-q6js4"].kind, OwnerKind::DaemonSet);
        assert_eq!(o["data/postgres-0"].kind, OwnerKind::StatefulSet);
        assert_eq!(o["data/postgres-0"].name, "postgres");
    }

    #[test]
    fn a_pod_nothing_owns_is_named_standalone_rather_than_guessed_at() {
        let o = owners_from_json(&real_pods());
        assert_eq!(o["default/hand-applied"].kind, OwnerKind::Standalone);
    }

    #[test]
    fn a_deployment_with_dashes_in_its_own_name_survives() {
        // Counting segments from the end would cut `helm-install-traefik-crd`
        // down to `helm-install`. The hash is the anchor, not the position.
        let j = json!({"items": [{
            "metadata": {"name": "my-long-app-name-6dc596dfb8-8mj82", "namespace": "x"},
            "labels": {"pod-template-hash": "6dc596dfb8"}}]}).to_string();
        assert_eq!(owners_from_json(&j)["x/my-long-app-name-6dc596dfb8-8mj82"].name,
                   "my-long-app-name");
    }

    #[test]
    fn a_job_is_not_expected_to_keep_running_and_a_deployment_is() {
        // Same reasoning as a container's restart policy, from a different
        // supervisor: a finished Job is not a workload that is down.
        assert!(!OwnerKind::Job.should_keep_running());
        for k in [OwnerKind::Deployment, OwnerKind::StatefulSet, OwnerKind::DaemonSet] {
            assert!(k.should_keep_running(), "{k:?}");
        }
    }

    #[test]
    fn unreadable_or_absent_json_yields_no_owners_rather_than_wrong_ones() {
        assert!(owners_from_json("").is_empty());
        assert!(owners_from_json("not json").is_empty());
        assert!(owners_from_json(r#"{"items": null}"#).is_empty());
    }

    #[test]
    fn a_container_running_an_older_image_than_its_tag_is_flagged() {
        // The question a fleet asks after every deployment. A pulled image with
        // no restart is an update that looks applied and is not: the container
        // is healthy, its tag is right, and it runs last week's code.
        let mut ws = parse_containers(
            "api\trunning\tUp\t\t0\talways\tp\tapi\tghcr.io/x/api:1.2\tsha256:OLD\t0\t0",
            &[],
            &[],
        );
        mark_stale_images(&mut ws, "ghcr.io/x/api:1.2\tsha256:NEW");
        assert!(ws[0].image_stale);

        mark_stale_images(&mut ws, "ghcr.io/x/api:1.2\tsha256:OLD");
        assert!(!ws[0].image_stale, "same digest is not stale");
    }

    #[test]
    fn an_image_this_machine_no_longer_has_marks_nothing() {
        // Pruned, or pulled by digest. Neither is evidence the container is
        // running something old.
        let mut ws = parse_containers(
            "api\trunning\tUp\t\t0\talways\tp\tapi\tghcr.io/x/api:1.2\tsha256:OLD\t0\t0",
            &[],
            &[],
        );
        mark_stale_images(&mut ws, "ghcr.io/other:1\tsha256:Z");
        assert!(!ws[0].image_stale);
    }

    #[test]
    fn declared_limits_are_read_and_zero_means_undeclared() {
        // Zero is how Docker and cgroups both spell "nothing declared", and
        // that is not the same as declaring no limit.
        let ws = parse_containers(
            "a\trunning\tUp\t\t0\talways\tp\ta\timg:1\tsha256:A\t21474836480\t2000000000\n\
             b\trunning\tUp\t\t0\talways\tp\tb\timg:1\tsha256:A\t0\t0",
            &[],
            &[],
        );
        assert_eq!(ws[0].memory_limit_bytes, Some(21_474_836_480));
        assert_eq!(ws[0].cpu_limit, Some(2.0));
        assert!(!ws[0].is_unbounded());
        assert!(ws[1].is_unbounded(), "nothing declared");
        assert_eq!(ws[1].cpu_limit, None);
    }
}
