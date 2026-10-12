//! Writing a control group, as a plan somebody else applies.
//!
//! [`cgroup`](crate::cgroup) reads. This says what it would take to *bound* a
//! group, and says it as a list of steps rather than performing any of them.
//!
//! The split is not decoration. Creating a cgroup subtree, delegating
//! controllers into it and moving a process between groups are all privileged,
//! and the daemon that decides these things runs as `User=furcate` with
//! `ProtectSystem=strict` and holds no capability at all. So it computes a plan
//! and writes it where a helper holding one capability reads it —
//! `furcate_host::thermal::plan` emits `Write`s the actuator carries out,
//! `furcated::overlay` renders a plan `deploy/furcate-wg.sh` applies, and this
//! is the same exchange for the same reason. A plan the privileged side can read
//! before acting is a plan it can refuse.
//!
//! It lives here rather than beside the boxes so that cgroup path construction
//! and the file formats stay in one crate. What rents boxes knows what a `standard`
//! box is worth; this knows that `cpu.max` is two numbers separated by a space
//! and that `memory.swap.max` takes the literal `max`, and nothing else in the
//! tree needs to learn either of those twice.
//!
//! ## Order is part of the plan
//!
//! The steps come back in the order they must be applied, and it is not
//! arbitrary:
//!
//! 1. The parent delegates controllers through `cgroup.subtree_control`, or the
//!    child's `cpu.max` does not exist to be written.
//! 2. The child is created.
//! 3. Its limits are written **before** anything is moved into it. A process
//!    attached to an unbounded group runs unbounded for however long the rest of
//!    the plan takes, and on a fork bomb that is long enough.
//! 4. Only then is the process moved in.
//!
//! A plan applied halfway therefore leaves a bounded empty group rather than an
//! unbounded populated one, which is the direction the failure has to fall.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The controllers a bounded group needs delegated into it.
///
/// Written to the *parent's* `cgroup.subtree_control`, with a `+` on each.
/// `memory` and `pids` are there for the limits below; `io` is there because
/// the volume is a distinct loop device and `io.max` is only meaningful when it
/// is.
pub const CONTROLLERS: &[&str] = &["cpu", "memory", "pids", "io"];

/// One step in bounding a group, with the reason it is being taken.
///
/// Returned rather than performed, exactly as `furcate_host::thermal::Write` is.
/// The extra shapes beside a write are the two things a cgroup needs that sysfs
/// tuning does not: a subtree has to exist before it can be written, and it has
/// to be removed afterwards or it is a leak nothing else prunes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    /// `mkdir` the subtree. The kernel populates its interface files.
    Create { path: PathBuf, why: String },
    /// Write `value` to `path`, with no trailing newline of our own — the
    /// kernel accepts either and the helper writes bytes verbatim.
    Write { path: PathBuf, value: String, why: String },
    /// `rmdir` the subtree. Fails with `EBUSY` while anything is still in it,
    /// which is the kernel refusing to lose the accounting rather than a
    /// problem to work around.
    Remove { path: PathBuf, why: String },
}

impl Step {
    pub fn path(&self) -> &Path {
        match self {
            Step::Create { path, .. } | Step::Write { path, .. } | Step::Remove { path, .. } => path,
        }
    }

    pub fn why(&self) -> &str {
        match self {
            Step::Create { why, .. } | Step::Write { why, .. } | Step::Remove { why, .. } => why,
        }
    }
}

/// Everything a bounded group is held to, in the units its files want.
///
/// Microseconds for CPU because `cpu.max` is a quota and a period in them;
/// bytes for memory because every `memory.*` file is in bytes; a bare count for
/// `pids.max`. Converting at the edge rather than here would put the same
/// arithmetic in two places, and the two places are in different languages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bounds {
    /// `cpu.max` numerator. `None` is the literal `max`, which is no limit.
    pub cpu_quota_us: Option<u64>,
    pub cpu_period_us: u64,
    /// `cpu.weight`, 1–10000, default 100. The ceiling is `cpu.max`; this only
    /// decides who wins when the machine is full.
    pub cpu_weight: u64,
    pub memory_max_bytes: Option<u64>,
    /// Throttling threshold below `memory.max`.
    ///
    /// `None` when it must not be set at all — see
    /// [`crate::cgroup::Memory::throttling_would_thrash`], which is exactly this
    /// check: on an anon-heavy group with swap available, reclaim pushes heap to
    /// swap, the collector faults it straight back, and a fast clean kill
    /// becomes a slow spiral that drags the host's I/O down with it.
    pub memory_high_bytes: Option<u64>,
    /// `memory.swap.max`. Zero denies swap outright, which is what makes
    /// `memory_high_bytes` safe to set on a group that would otherwise thrash.
    pub memory_swap_max_bytes: Option<u64>,
    /// The fork-bomb stop. Nothing in this tree read or wrote it before.
    pub pids_max: Option<u64>,
    /// `io.max` on one device, or nothing.
    pub io_max: Option<IoMax>,
    /// `memory.oom.group`: kill the whole group together rather than picking
    /// one process out of it and leaving a half-dead workload behind.
    pub oom_group: bool,
}

/// A per-device I/O ceiling.
///
/// Only meaningful because a box's volume is a distinct loop device. On a
/// shared filesystem there is no major:minor that means "this tenant's writes",
/// which is the second thing the volume design buys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoMax {
    pub major: u32,
    pub minor: u32,
    pub rbps: Option<u64>,
    pub wbps: Option<u64>,
    pub riops: Option<u64>,
    pub wiops: Option<u64>,
}

impl IoMax {
    /// `io.max`'s value: `MAJ:MIN` then the keys that are set.
    ///
    /// Keys that are `None` are omitted rather than written as `max`. Writing
    /// `max` explicitly is the same as omitting it on a fresh group and *clears
    /// an existing limit* on one that already has it, and a plan that silently
    /// lifts a ceiling somebody else set is the failure this avoids.
    pub fn value(&self) -> String {
        let mut s = format!("{}:{}", self.major, self.minor);
        for (key, v) in [
            ("rbps", self.rbps),
            ("wbps", self.wbps),
            ("riops", self.riops),
            ("wiops", self.wiops),
        ] {
            if let Some(v) = v {
                s.push_str(&format!(" {key}={v}"));
            }
        }
        s
    }

    pub fn any(&self) -> bool {
        self.rbps.is_some() || self.wbps.is_some() || self.riops.is_some() || self.wiops.is_some()
    }
}

impl Default for Bounds {
    /// Unbounded, which is what a group is before anybody says otherwise.
    ///
    /// Written out rather than derived, because `Default` on `cpu_period_us`
    /// would be zero and a zero period is a division the kernel rejects. A
    /// default that cannot be applied is worse than none.
    fn default() -> Self {
        Bounds {
            cpu_quota_us: None,
            cpu_period_us: 100_000,
            cpu_weight: 100,
            memory_max_bytes: None,
            memory_high_bytes: None,
            memory_swap_max_bytes: None,
            pids_max: None,
            io_max: None,
            oom_group: false,
        }
    }
}

/// A limit the file spells `max` when it is absent.
fn limit(v: Option<u64>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "max".to_string(),
    }
}

/// The steps that create `rel` under `root` and bound it to `bounds`.
///
/// `rel` is relative to the hierarchy root, the way
/// [`crate::cgroup::Group::read`] takes it, so one spelling of a group's path
/// serves both the reader and the writer.
///
/// Returns an empty plan for an empty `rel` rather than emitting steps against
/// the hierarchy root. Bounding the root is not a smaller version of bounding a
/// subtree; it is capping the machine.
pub fn create(root: &Path, rel: &str, bounds: &Bounds) -> Vec<Step> {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        return Vec::new();
    }
    let path = root.join(rel);
    let mut out = Vec::new();

    // 1. Delegate, at every level between the root and the parent. A controller
    //    that is not enabled in the parent has no interface file in the child,
    //    and the write below would fail with ENOENT for a reason that reads
    //    like a missing kernel feature.
    let mut walked = root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        out.push(Step::Write {
            path: walked.join("cgroup.subtree_control"),
            value: CONTROLLERS.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" "),
            why: format!(
                "delegate {} into {}: a controller not enabled in the parent has \
                 no interface file in the child",
                CONTROLLERS.join(", "),
                walked.display()
            ),
        });
        walked = walked.join(part);
    }
    out.push(Step::Write {
        path: walked.join("cgroup.subtree_control"),
        value: CONTROLLERS.iter().map(|c| format!("+{c}")).collect::<Vec<_>>().join(" "),
        why: format!("delegate {} into {}", CONTROLLERS.join(", "), walked.display()),
    });

    // 2. Create.
    out.push(Step::Create {
        path: path.clone(),
        why: format!("the subtree {rel} is where this workload is accounted and bounded"),
    });

    // 3. Bound, before anything is moved in.
    out.extend(bound(root, rel, bounds));
    out
}

/// The writes that put `bounds` in force on a group that already exists.
///
/// Split out from [`create`] so a resize is the same code as a create, rather
/// than a second spelling of the same file names that can drift from it.
pub fn bound(root: &Path, rel: &str, b: &Bounds) -> Vec<Step> {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        return Vec::new();
    }
    let path = root.join(rel);
    let mut out = Vec::new();

    out.push(Step::Write {
        path: path.join("cpu.max"),
        value: format!("{} {}", limit(b.cpu_quota_us), b.cpu_period_us),
        why: "the ceiling on processor time, as a quota over a period".into(),
    });
    out.push(Step::Write {
        path: path.join("cpu.weight"),
        value: b.cpu_weight.to_string(),
        why: format!(
            "weight {} against the default 100: this decides who wins when the \
             machine is full, and a tenant must not win it against serving",
            b.cpu_weight
        ),
    });

    // Swap first, and deliberately: `memory.high` is only safe on a group that
    // cannot swap, and writing the threshold before denying swap leaves a
    // window in which the spiral this crate's header warns about is live.
    if let Some(swap) = b.memory_swap_max_bytes {
        out.push(Step::Write {
            path: path.join("memory.swap.max"),
            value: swap.to_string(),
            why: if swap == 0 {
                "no swap: reclaim must kill this group cleanly rather than push \
                 its heap to disk and fault it straight back in"
                    .into()
            } else {
                format!("swap ceiling {swap} bytes")
            },
        });
    }
    if let Some(max) = b.memory_max_bytes {
        out.push(Step::Write {
            path: path.join("memory.max"),
            value: max.to_string(),
            why: "the hard ceiling; exceeding it invokes the OOM killer on the group".into(),
        });
    }
    if let Some(high) = b.memory_high_bytes {
        out.push(Step::Write {
            path: path.join("memory.high"),
            value: high.to_string(),
            why: "throttle before killing, which is only safe because swap is denied above".into(),
        });
    }
    if b.oom_group {
        out.push(Step::Write {
            path: path.join("memory.oom.group"),
            value: "1".into(),
            why: "kill the group together: one process picked out of a workload \
                  leaves something half-dead that nothing is watching"
                .into(),
        });
    }
    if let Some(pids) = b.pids_max {
        out.push(Step::Write {
            path: path.join("pids.max"),
            value: pids.to_string(),
            why: "the fork-bomb stop".into(),
        });
    }
    if let Some(io) = b.io_max.filter(IoMax::any) {
        out.push(Step::Write {
            path: path.join("io.max"),
            value: io.value(),
            why: format!(
                "an I/O ceiling on {}:{}, which is only expressible because this \
                 workload's disk is a device of its own",
                io.major, io.minor
            ),
        });
    }

    out
}

/// Move a process into a group.
///
/// Separate from [`create`] because the order matters and because the caller
/// usually does not have the pid until after the plan that created the group
/// has been applied. `cgroup.procs` takes one pid per write, and moving a
/// thread group leader moves the whole thread group.
pub fn attach(root: &Path, rel: &str, pid: u32) -> Vec<Step> {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        return Vec::new();
    }
    vec![Step::Write {
        path: root.join(rel).join("cgroup.procs"),
        value: pid.to_string(),
        why: format!("move {pid} into {rel}, now that {rel} is bounded"),
    }]
}

/// Remove a group.
///
/// Emitted as its own plan rather than as a flag on something else, because
/// this is the step that gets skipped when a start fails halfway and a skipped
/// cleanup is a cgroup that no other tool prunes. `rmdir` on a non-empty group
/// returns `EBUSY`, and that is the kernel declining to lose the accounting.
pub fn remove(root: &Path, rel: &str) -> Vec<Step> {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        return Vec::new();
    }
    vec![Step::Remove {
        path: root.join(rel),
        why: format!(
            "{rel} is finished with; a subtree left behind is a leak nothing \
             else prunes"
        ),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/sys/fs/cgroup")
    }

    fn bounded() -> Bounds {
        Bounds {
            cpu_quota_us: Some(200_000),
            cpu_period_us: 100_000,
            cpu_weight: 50,
            memory_max_bytes: Some(4 * 1_024 * 1_024 * 1_024),
            memory_high_bytes: Some(3 * 1_024 * 1_024 * 1_024),
            memory_swap_max_bytes: Some(0),
            pids_max: Some(1_024),
            io_max: None,
            oom_group: true,
        }
    }

    fn written(steps: &[Step], file: &str) -> Option<String> {
        steps.iter().find_map(|s| match s {
            Step::Write { path, value, .. } if path.ends_with(file) => Some(value.clone()),
            _ => None,
        })
    }

    #[test]
    fn nothing_is_written_before_the_group_exists() {
        let p = create(&root(), "system.slice/furcate-work.slice/w-9222", &bounded());
        let created = p.iter().position(|s| matches!(s, Step::Create { .. })).expect("a create");
        for (i, s) in p.iter().enumerate() {
            if let Step::Write { path, .. } = s {
                if path.to_string_lossy().contains("w-9222") {
                    assert!(i > created, "{} is written before the group exists", path.display());
                }
            }
        }
    }

    #[test]
    fn the_group_is_bounded_before_anything_is_moved_into_it() {
        // A process attached to an unbounded group runs unbounded for however
        // long the rest of the plan takes, and on a fork bomb that is enough.
        let rel = "system.slice/furcate-work.slice/w-9222";
        let mut plan = create(&root(), rel, &bounded());
        let bounds_end = plan.len();
        plan.extend(attach(&root(), rel, 4_242));
        let moved = plan
            .iter()
            .position(|s| s.path().ends_with("cgroup.procs"))
            .expect("an attach");
        assert!(moved >= bounds_end, "the move must come after every limit");
    }

    #[test]
    fn swap_is_denied_before_the_throttle_threshold_is_set() {
        // memory.high on a group that can still swap is the spiral this crate's
        // header warns about, and the window between the two writes is live.
        let p = bound(&root(), "g", &bounded());
        let swap = p.iter().position(|s| s.path().ends_with("memory.swap.max")).unwrap();
        let high = p.iter().position(|s| s.path().ends_with("memory.high")).unwrap();
        assert!(swap < high, "swap must be denied first");
    }

    #[test]
    fn a_group_that_would_thrash_gets_no_throttle_threshold_at_all() {
        // The check is crate::cgroup::Memory::throttling_would_thrash, and the
        // answer here is an absent write rather than a written `max`.
        let mut b = bounded();
        b.memory_high_bytes = None;
        let p = bound(&root(), "g", &b);
        assert!(
            !p.iter().any(|s| s.path().ends_with("memory.high")),
            "no write at all, not a permissive one"
        );
    }

    #[test]
    fn cpu_max_is_the_two_numbers_the_file_wants() {
        assert_eq!(written(&bound(&root(), "g", &bounded()), "cpu.max").as_deref(), Some("200000 100000"));
    }

    #[test]
    fn an_unlimited_dimension_is_the_literal_max_and_not_a_number() {
        let mut b = bounded();
        b.cpu_quota_us = None;
        assert_eq!(written(&bound(&root(), "g", &b), "cpu.max").as_deref(), Some("max 100000"));
    }

    #[test]
    fn a_controller_is_delegated_at_every_level_above_the_group() {
        // A controller not enabled in the parent has no interface file in the
        // child, and the write fails with an ENOENT that reads like a missing
        // kernel feature.
        let p = create(&root(), "system.slice/furcate-work.slice/w-9222", &bounded());
        let delegations: Vec<&Step> = p
            .iter()
            .filter(|s| s.path().ends_with("cgroup.subtree_control"))
            .collect();
        assert_eq!(delegations.len(), 3, "root, system.slice, furcate-work.slice");
        for d in &delegations {
            if let Step::Write { value, .. } = d {
                for c in CONTROLLERS {
                    assert!(value.contains(&format!("+{c}")), "{value} is missing {c}");
                }
            }
        }
    }

    #[test]
    fn an_io_ceiling_omits_the_keys_it_does_not_set() {
        // Writing `max` explicitly clears a limit somebody else set, and a plan
        // that silently lifts a ceiling is worse than one that sets none.
        let io = IoMax { major: 7, minor: 0, rbps: None, wbps: Some(10_000_000), riops: None, wiops: None };
        assert_eq!(io.value(), "7:0 wbps=10000000");
        let mut b = bounded();
        b.io_max = Some(io);
        assert_eq!(written(&bound(&root(), "g", &b), "io.max").as_deref(), Some("7:0 wbps=10000000"));
    }

    #[test]
    fn an_io_ceiling_with_nothing_set_is_no_write_rather_than_an_empty_one() {
        let mut b = bounded();
        b.io_max = Some(IoMax { major: 7, minor: 0, rbps: None, wbps: None, riops: None, wiops: None });
        assert!(!bound(&root(), "g", &b).iter().any(|s| s.path().ends_with("io.max")));
    }

    #[test]
    fn bounding_the_hierarchy_root_is_capping_the_machine_and_is_refused() {
        // Not a smaller version of bounding a subtree.
        for rel in ["", "/", "///"] {
            assert!(create(&root(), rel, &bounded()).is_empty(), "{rel:?}");
            assert!(bound(&root(), rel, &bounded()).is_empty(), "{rel:?}");
            assert!(remove(&root(), rel).is_empty(), "{rel:?}");
            assert!(attach(&root(), rel, 1).is_empty(), "{rel:?}");
        }
    }

    #[test]
    fn a_resize_is_the_same_writes_as_a_create() {
        // Two spellings of the same file names is how they drift.
        let rel = "system.slice/furcate-work.slice/w-9222";
        let created = create(&root(), rel, &bounded());
        let rebounded = bound(&root(), rel, &bounded());
        let tail = &created[created.len() - rebounded.len()..];
        assert_eq!(tail, rebounded.as_slice());
    }

    #[test]
    fn removing_names_a_directory_and_not_a_file() {
        let p = remove(&root(), "system.slice/furcate-work.slice/w-9222");
        assert!(matches!(p[0], Step::Remove { .. }));
        assert_eq!(p[0].path(), root().join("system.slice/furcate-work.slice/w-9222"));
    }

    #[test]
    fn the_default_is_unbounded_and_still_applicable() {
        // A default with a zero period is a division the kernel rejects, which
        // is worse than having no default at all.
        let b = Bounds::default();
        assert_ne!(b.cpu_period_us, 0);
        assert_eq!(written(&bound(&root(), "g", &b), "cpu.max").as_deref(), Some("max 100000"));
    }

    #[test]
    fn every_step_says_why_because_it_ends_up_in_the_helpers_log() {
        for s in create(&root(), "system.slice/furcate-work.slice/w-9222", &bounded()) {
            assert!(!s.why().is_empty(), "{:?} has no reason", s.path());
        }
    }

    #[test]
    fn a_plan_survives_the_file_the_helper_reads_it_from() {
        let p = create(&root(), "system.slice/furcate-work.slice/w-9222", &bounded());
        let json = serde_json::to_string(&p).expect("serialises");
        assert_eq!(serde_json::from_str::<Vec<Step>>(&json).unwrap(), p);
    }
}
