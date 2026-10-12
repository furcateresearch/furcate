//! The build arm: attested, content-addressed builds placed on machines you own.
//!
//! A build here is an *action on a site*. It goes to the policy engine as a
//! request and comes back permitted or refused; it is placed on a node elected
//! from attested capability, not one that claimed a GPU; its inputs and outputs
//! are named by content; its result is cached against the digest of the action;
//! the artifact carries an in-toto attestation signed by the node's own key,
//! naming the assurance grade of the machine that produced it; and the decision
//! is chained into the ledger either way. Every hosted build service's
//! provenance ends in *trust our service key*. This one ends in *this machine,
//! at this grade* -- available only to someone who owns the metal.
//!
//! The pieces, each its own module and each with the refusals that make it
//! Furcate rather than a re-implementation of a hosted builder:
//!
//!  * [`digest`] -- content addressing, the currency the ledger already speaks.
//!  * [`action`] -- the build action and the digest that names it.
//!  * [`cas`] -- the content store; a read verifies rather than trusts.
//!  * [`cache`] -- the action cache; an index of proofs, not of filenames.
//!  * [`placement`] -- where a build may run, and whether it can run now.
//!  * [`isolation`] -- how it runs; a process backend now, a microVM seam next.
//!  * [`provenance`] -- the signed in-toto statement.
//!  * [`manifest`] -- the declarative form a person writes.
//!  * [`refusal`] -- the six refusals, as one named type.

pub mod action;
pub mod cache;
pub mod cas;
pub mod digest;
pub mod isolation;
pub mod manifest;
pub mod placement;
pub mod provenance;
pub mod refusal;

pub use action::{BuildAction, Network};

/// Which toolchain an action drives, read from the command it runs.
///
/// Read rather than declared, because the command is already in the action and
/// a second field saying the same thing is a second thing to get wrong. It is
/// a hint about how to run the work, never about what the work produces, so a
/// wrong answer costs a default width and nothing else — which is why inferring
/// it is acceptable here and would not be for anything the digest covers.
fn toolchain_of(action: &BuildAction) -> Option<furcate_resource::Toolchain> {
    let argv0 = action.command.first()?;
    let bin = argv0.rsplit(['/', '\\']).next()?;
    match bin {
        "cargo" | "cargo.exe" | "rustc" | "rustc.exe" => {
            Some(furcate_resource::Toolchain::Rust)
        }
        _ => None,
    }
}


pub use cache::{ActionCache, ActionResult};
pub use cas::Cas;
pub use digest::Digest;
pub use isolation::{Isolation, ProcessSandbox, RunReport};
pub use manifest::Manifest;
pub use placement::{decide as decide_placement, NodeCapability, Placement, PlacementPolicy};
pub use provenance::{Builder, SignedProvenance, Statement};
pub use refusal::Refusal;

use ed25519_dalek::SigningKey;
use furcate_ledger::chain::Digest32;
use furcate_ledger::{Chain, OpKind};
use std::path::Path;

/// The outcome of a successful build.
#[derive(Debug)]
pub struct Outcome {
    /// What the action produced, with its observation count.
    pub result: ActionResult,
    /// The signed attestation over those outputs.
    pub provenance: SignedProvenance,
    /// Whether this came from the cache rather than a fresh run.
    pub from_cache: bool,
    /// The ledger head after the build was chained in.
    pub ledger_head: Digest32,
}

/// Everything a build needs that comes from outside this crate: the policy
/// decision on the build action, the node it is placed on, the placement
/// policy, the stores, the isolation backend, the working tree, the node's
/// signing key, and the builder identity to stamp into provenance.
pub struct BuildContext<'a> {
    pub decision: &'a furcate_policy::Decision,
    pub node: &'a NodeCapability,
    pub placement_policy: &'a PlacementPolicy,
    pub cas: &'a Cas,
    pub cache: &'a ActionCache,
    pub isolation: &'a dyn Isolation,
    pub work_dir: &'a Path,
    pub signing_key: &'a SigningKey,
    pub builder: Builder,
    pub ts_ms: u64,
}

/// Run a build action through the whole arm, chaining the outcome -- built,
/// refused, or deferred -- into `chain`.
///
/// The order is the design note's supply chain: rule on it, place it, answer
/// from the cache if the proof matches, otherwise run it isolated, record it,
/// attest it, and chain it.
pub fn execute(
    action: &BuildAction,
    ctx: BuildContext<'_>,
    chain: &mut Chain,
) -> Result<Outcome, BuildError> {
    let subject = action.digest().to_hex();

    // 0. The action must name its sources by digest (6.1). A manifest enforces
    //    this on resolution, but an action arriving any other way is checked.
    if !action.inputs_are_named() {
        let refusal = Refusal::UnnamedSource {
            detail: "action declares no inputs".to_string(),
        };
        chain.append(ctx.ts_ms, OpKind::Deploy, ctx.builder.id.clone(), subject, "refused: unnamed source");
        return Err(BuildError::Refused(refusal));
    }

    // 1. A build is a ruled-on action. A deny is chained and returned.
    if !ctx.decision.allowed {
        chain.append(
            ctx.ts_ms,
            OpKind::Deploy,
            ctx.builder.id.clone(),
            subject,
            format!("refused by policy: {}", ctx.decision.because),
        );
        return Err(BuildError::PolicyDenied(ctx.decision.because.clone()));
    }

    // 2. Placement: may this node run it, and can it now?
    match placement::decide(
        &action.target,
        toolchain_of(action),
        ctx.node,
        ctx.placement_policy,
    ) {
        Placement::Placed { .. } => {}
        Placement::Quiet { why } => {
            return Err(BuildError::QuietHours { why });
        }
        Placement::Deferred { level, why } => {
            return Err(BuildError::Deferred { level, why });
        }
        Placement::Refused(refusal) => {
            chain.append(
                ctx.ts_ms,
                OpKind::Deploy,
                ctx.builder.id.clone(),
                subject,
                format!("refused: {refusal}"),
            );
            return Err(BuildError::Refused(refusal));
        }
    }

    // 3. The cache. A hit is only honoured if its proof matches (6.3, inside
    //    `cache.get`). A hit still gets fresh, signed provenance.
    let action_digest = action.digest();
    if let Some(result) = ctx.cache.get(&action_digest).map_err(BuildError::Cache)? {
        let provenance = Statement::new(action, &result, ctx.builder.clone())
            .map_err(BuildError::Refused)?
            .sign(ctx.signing_key);
        let ledger_head = chain.append(
            ctx.ts_ms,
            OpKind::Deploy,
            ctx.builder.id.clone(),
            subject,
            format!("cache hit: {} outputs, reproducible={}", result.outputs.len(), result.is_reproducible()),
        );
        return Ok(Outcome {
            result,
            provenance,
            from_cache: true,
            ledger_head,
        });
    }

    // 4. Miss: run it under isolation.
    let report = ctx
        .isolation
        .run(action, ctx.work_dir, ctx.cas)
        .map_err(BuildError::Isolation)?;
    if !report.ok {
        chain.append(
            ctx.ts_ms,
            OpKind::Deploy,
            ctx.builder.id.clone(),
            subject,
            "refused: build command failed",
        );
        return Err(BuildError::BuildFailed);
    }

    // 5. Record it, attest it, chain it.
    let result = ctx
        .cache
        .record(&action_digest, report.outputs)
        .map_err(BuildError::Cache)?;
    let provenance = Statement::new(action, &result, ctx.builder.clone())
        .map_err(BuildError::Refused)?
        .sign(ctx.signing_key);
    let ledger_head = chain.append(
        ctx.ts_ms,
        OpKind::Deploy,
        ctx.builder.id.clone(),
        subject,
        format!("built: {} outputs, reproducible={}", result.outputs.len(), result.is_reproducible()),
    );

    Ok(Outcome {
        result,
        provenance,
        from_cache: false,
        ledger_head,
    })
}

#[derive(Debug)]
pub enum BuildError {
    /// The policy declined the build.
    PolicyDenied(String),
    /// The build cannot run on this node; the refusal names the gap.
    Refused(Refusal),
    /// The node is allowed but too busy right now.
    Deferred {
        level: furcate_resource::Level,
        why: String,
    },
    /// The node is allowed, but inside quiet hours that refuse builds.
    QuietHours { why: String },
    /// The build command exited non-zero.
    BuildFailed,
    Cache(cache::CacheError),
    Isolation(isolation::IsolationError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::PolicyDenied(why) => write!(f, "policy denied: {why}"),
            BuildError::Refused(r) => write!(f, "{r}"),
            BuildError::Deferred { level, why } => write!(f, "deferred ({level:?}): {why}"),
            BuildError::QuietHours { why } => write!(f, "waiting for quiet hours to end: {why}"),
            BuildError::BuildFailed => write!(f, "the build command failed"),
            BuildError::Cache(e) => write!(f, "{e}"),
            BuildError::Isolation(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BuildError {}
