//! Placement: where a build is allowed to run, and whether it can run now.
//!
//! A node becomes a builder the way it becomes any other role — elected on
//! attested capability and named by policy, never by claiming a GPU it does not
//! have. This module answers two separate questions, and keeps them separate:
//!
//!  * *May this node run this build at all?* Decided from the attestation
//!    verdict, the node's assurance class against the policy floor, and whether
//!    the node actually satisfies the action's target. A no here is a
//!    `Refusal` — it names the gap rather than silently choosing another
//!    machine (§6.5).
//!  * *Can it run it right now?* Decided from the node's declared quiet hours
//!    and from live resource pressure. A no here is `Quiet` or `Deferred`, not
//!    a refusal: the node is allowed, it is just not now.
//!
//! It leans on the real fleet types: `furcate_identity::AssuranceClass` (which
//! is `Ord`, so the floor is a comparison), `furcate_attest::Verdict`,
//! `furcate_resource::Level` — pressure, not utilisation — and
//! `furcate_host::acoustics::BuildVerdict`, which is what the node's own
//! declaration says about starting work at its local hour.

use crate::refusal::Refusal;
use furcate_attest::Verdict;
use furcate_host::acoustics::BuildVerdict;
use furcate_identity::AssuranceClass;
use furcate_resource::Level;

/// What a candidate node offers.
#[derive(Clone, Debug)]
pub struct NodeCapability {
    /// A stable identifier, for the message when it is refused or chosen.
    pub node_id: String,
    /// Targets this node can build and run, from attested hardware — e.g.
    /// `x86_64-linux`, `cuda:sm_120`. Membership is exact: the Blackwell
    /// families do not interoperate, so `sm_120` does not satisfy `sm_100`.
    pub targets: Vec<String>,
    /// The node's most recent attestation verdict.
    pub verdict: Verdict,
    /// The assurance class of the node's identity.
    pub assurance: AssuranceClass,
    /// Current resource pressure (the worst axis).
    pub pressure: Level,
    /// Cores and memory this node will lend a build.
    ///
    /// `None` where the node has not reported it. A build still places; it just
    /// cannot be sized, and [`Placement::Placed`] says so rather than inventing
    /// a width.
    pub build_capacity: Option<furcate_resource::BuildMachine>,
    /// What this node's acoustic declaration says about starting work now.
    ///
    /// Computed by the node from its own declaration at its own local hour —
    /// `Acoustics::builds_at` — and never by this module, which knows neither
    /// where the machine sits nor what time it is there. This replaced a bare
    /// `must_stay_quiet: bool`, which could say "narrower" but had no way to
    /// say "not tonight", and which left whoever filled it in to decide.
    pub builds: BuildVerdict,
    /// What a compiler process has actually been seen to peak at on this node.
    ///
    /// Carried from observation rather than assumed. Cargo's own default is the
    /// core count, which is a statement about cores on a machine whose real
    /// constraint is usually memory — see `furcate_resource::toolchain`.
    pub observed: furcate_resource::Observed,
}

/// The operator's placement policy for a build.
#[derive(Clone, Debug)]
pub struct PlacementPolicy {
    /// The minimum assurance class a builder must present.
    pub floor: AssuranceClass,
}

/// The outcome of a placement decision.
#[derive(Debug)]
pub enum Placement {
    /// The node may run the build, and can take it now.
    ///
    /// Carries how wide it should run. This is the moment the system knows
    /// *which* machine, and therefore the only moment it can answer how large
    /// the work should have been — asking later means the default has already
    /// been taken.
    Placed {
        /// `None` when the toolchain is unknown or the node reported no
        /// capacity. The build proceeds on the toolchain's own default, which
        /// is what happened before this existed.
        shape: Option<furcate_resource::Shape>,
    },
    /// The node may run the build, but it is inside quiet hours that refuse
    /// work, and the build waits for the window to end.
    Quiet { why: String },
    /// The node may run the build but is under too much pressure right now.
    Deferred { level: Level, why: String },
    /// The node may not run this build. The reason names the gap.
    Refused(Refusal),
}

/// Decide placement of an action with `target` onto `node` under `policy`.
/// `toolchain` is how the work parallelises, not what it produces, so it is a
/// parameter here rather than a field on [`crate::BuildAction`]. Putting it on
/// the action would either change the action digest — invalidating every cached
/// result over a scheduling hint — or sit outside the digest while looking like
/// part of it. `-j` does not affect output; `codegen-units` would, and is
/// deliberately not set here for that reason.
pub fn decide(
    target: &str,
    toolchain: Option<furcate_resource::Toolchain>,
    node: &NodeCapability,
    policy: &PlacementPolicy,
) -> Placement {
    // 1. The node must have passed attestation at all.
    if node.verdict != Verdict::Admit {
        return Placement::Refused(Refusal::BelowAttestationFloor {
            required: format!("{:?}", policy.floor),
            offered: "attestation refused".to_string(),
        });
    }

    // 2. The node must meet the assurance floor. AssuranceClass is Ord, low to
    //    high, so this is a direct comparison rather than a hand-kept table.
    if node.assurance < policy.floor {
        return Placement::Refused(Refusal::BelowAttestationFloor {
            required: format!("{:?}", policy.floor),
            offered: format!("{:?}", node.assurance),
        });
    }

    // 3. The node must actually be the target. Exact match, on purpose (§9).
    if !node.targets.iter().any(|t| t == target) {
        return Placement::Refused(Refusal::UnsatisfiableTarget {
            target: target.to_string(),
            detail: format!("node {} satisfies {:?}", node.node_id, node.targets),
        });
    }

    // 4. It is allowed — but not while the machine is keeping quiet for the
    //    people near it. Checked before pressure because it does not depend on
    //    how busy the node is: a build deferred for load at 01:00 would
    //    otherwise start the moment load fell, still at 01:00.
    if !node.builds.permits_start() {
        return Placement::Quiet {
            why: format!(
                "node {} is inside quiet hours that refuse builds, and starts none until the \
                 window ends",
                node.node_id
            ),
        };
    }

    // 5. Can it take the work now? Pressure, not utilisation.
    match node.pressure {
        Level::Clear | Level::Contended => Placement::Placed {
            shape: match (toolchain, node.build_capacity.as_ref()) {
                (Some(t), Some(m)) => Some(furcate_resource::Shape::size(
                    t,
                    m,
                    &node.observed,
                    node.builds.requires_quiet_width(),
                )),
                _ => None,
            },
        },
        Level::Starved | Level::Stalled => Placement::Deferred {
            level: node.pressure,
            why: format!("node {} is under {:?} pressure", node.node_id, node.pressure),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> NodeCapability {
        NodeCapability {
            node_id: "node-c".into(),
            targets: vec!["x86_64-linux".into()],
            verdict: Verdict::Admit,
            assurance: AssuranceClass::Tpm,
            pressure: Level::Clear,
            // A machine with room to spare, so these tests keep testing
            // placement rather than accidentally testing sizing.
            build_capacity: Some(furcate_resource::BuildMachine {
                logical_cpus: 8,
                usable_bytes: 64 * 1024 * 1024 * 1024,
                quiet_jobs: None,
            }),
            builds: BuildVerdict::Unrestricted,
            observed: furcate_resource::Observed::default(),
        }
    }

    fn policy() -> PlacementPolicy {
        PlacementPolicy { floor: AssuranceClass::Device }
    }

    /// The machine this was written on: 56 threads, 121 GB, a measured 4 GB
    /// compiler peak, and fans that step to maximum above four jobs.
    fn the_build_machine() -> NodeCapability {
        let mut n = node();
        n.build_capacity = Some(furcate_resource::BuildMachine {
            logical_cpus: 56,
            usable_bytes: 121 * 1024 * 1024 * 1024,
            quiet_jobs: Some(4),
        });
        n.observed = furcate_resource::Observed {
            peak_job_bytes: Some(4 * 1024 * 1024 * 1024),
        };
        n
    }

    #[test]
    fn a_capable_admitted_clear_node_is_placed() {
        assert!(matches!(decide("x86_64-linux", None, &node(), &policy()), Placement::Placed { .. }));
    }

    #[test]
    fn below_the_floor_is_refused_with_both_grades() {
        let mut n = node();
        n.assurance = AssuranceClass::Soft;
        match decide("x86_64-linux", None, &n, &policy()) {
            Placement::Refused(Refusal::BelowAttestationFloor { required, offered }) => {
                assert_eq!(required, "Device");
                assert_eq!(offered, "Soft");
            }
            other => panic!("expected floor refusal, got {other:?}"),
        }
    }

    #[test]
    fn wrong_cuda_family_is_refused_not_run() {
        let mut n = node();
        n.targets = vec!["cuda:sm_121".into()];
        assert!(matches!(
            decide("cuda:sm_120", None, &n, &policy()),
            Placement::Refused(Refusal::UnsatisfiableTarget { .. })
        ));
    }

    #[test]
    fn a_refused_attestation_cannot_be_placed() {
        let mut n = node();
        n.verdict = Verdict::Refuse;
        assert!(matches!(
            decide("x86_64-linux", None, &n, &policy()),
            Placement::Refused(Refusal::BelowAttestationFloor { .. })
        ));
    }

    #[test]
    fn a_stalled_node_is_deferred_not_refused() {
        let mut n = node();
        n.pressure = Level::Stalled;
        assert!(matches!(
            decide("x86_64-linux", None, &n, &policy()),
            Placement::Deferred { .. }
        ));
    }

    /// **The sizing this exists for.** A Rust build on a machine whose measured
    /// compiler peak makes the core count impossible: cargo would start one job
    /// per core and ask for more memory than the machine has.
    #[test]
    fn a_rust_build_is_sized_to_the_machine_rather_than_to_its_cores() {
        match decide(
            "x86_64-linux",
            Some(furcate_resource::Toolchain::Rust),
            &the_build_machine(),
            &policy(),
        ) {
            Placement::Placed { shape: Some(s) } => {
                assert_eq!(s.jobs, 30, "121 GB / 4 GB, not the 56 cores");
                assert_eq!(s.bounded_by, furcate_resource::Bound::Memory);
            }
            other => panic!("expected a sized placement, got {other:?}"),
        }
    }

    /// An unknown toolchain places without a width rather than guessing one.
    /// The build then runs on its own default, which is what happened before
    /// any of this existed — no worse, and honest about it.
    #[test]
    fn an_unknown_toolchain_places_without_a_width() {
        match decide("x86_64-linux", None, &node(), &policy()) {
            Placement::Placed { shape: None } => {}
            other => panic!("expected an unsized placement, got {other:?}"),
        }
    }

    /// A node that has not reported its capacity is the same case. Sizing
    /// against a capacity nobody stated would be a number with nothing behind
    /// it.
    #[test]
    fn a_node_with_no_reported_capacity_places_without_a_width() {
        let mut n = node();
        n.build_capacity = None;
        match decide(
            "x86_64-linux",
            Some(furcate_resource::Toolchain::Rust),
            &n,
            &policy(),
        ) {
            Placement::Placed { shape: None } => {}
            other => panic!("expected an unsized placement, got {other:?}"),
        }
    }

    /// **The case this was changed for.** A machine in somebody's home, inside
    /// a window that refuses builds, does not take one — however idle it is.
    #[test]
    fn a_node_inside_refusing_quiet_hours_does_not_start_the_build() {
        let mut n = the_build_machine();
        n.builds = BuildVerdict::Refuse;
        assert!(matches!(
            decide("x86_64-linux", Some(furcate_resource::Toolchain::Rust), &n, &policy()),
            Placement::Quiet { .. }
        ));
    }

    /// Quiet hours are decided before pressure, so a build that was waiting
    /// for load to fall does not start the moment it does, at night.
    #[test]
    fn quiet_hours_outrank_pressure() {
        let mut n = node();
        n.builds = BuildVerdict::Refuse;
        n.pressure = Level::Stalled;
        assert!(matches!(decide("x86_64-linux", None, &n, &policy()), Placement::Quiet { .. }));
    }

    /// But quiet hours never let an ineligible node in: a refusal still names
    /// its gap rather than being reported as a wait that will never end.
    #[test]
    fn quiet_hours_do_not_hide_a_refusal() {
        let mut n = node();
        n.builds = BuildVerdict::Refuse;
        n.targets = vec!["aarch64-linux".into()];
        assert!(matches!(
            decide("x86_64-linux", None, &n, &policy()),
            Placement::Refused(Refusal::UnsatisfiableTarget { .. })
        ));
    }

    /// A narrowing window runs the build at the measured quiet width — four
    /// jobs where memory alone would have allowed thirty.
    #[test]
    fn a_narrowing_window_sizes_the_build_to_the_quiet_width() {
        let mut n = the_build_machine();
        n.builds = BuildVerdict::Narrow;
        match decide("x86_64-linux", Some(furcate_resource::Toolchain::Rust), &n, &policy()) {
            Placement::Placed { shape: Some(s) } => {
                assert_eq!(s.jobs, 4);
                assert_eq!(s.bounded_by, furcate_resource::Bound::Acoustic);
            }
            other => panic!("expected a quiet-width placement, got {other:?}"),
        }
    }
}
