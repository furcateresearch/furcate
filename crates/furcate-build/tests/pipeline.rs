//! End-to-end: a manifest resolved to an action, run through the whole arm,
//! chained into a ledger, and attested. These tests exercise the seams between
//! the modules -- the unit tests inside each module cover the parts.

#![cfg(unix)]

use furcate_build::action::Network;
use furcate_build::isolation::ProcessSandbox;
use furcate_build::{
    ActionCache, BuildContext, Cas, Manifest, Refusal, Statement,
};
use furcate_build::placement::{NodeCapability, PlacementPolicy};
use furcate_build::provenance::Builder;
use furcate_build::execute;
use furcate_build::BuildError;

use ed25519_dalek::SigningKey;
use furcate_attest::Verdict;
use furcate_identity::AssuranceClass;
use furcate_ledger::Chain;
use furcate_resource::Level;
use std::fs;
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "fcbuild-it-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

fn node(assurance: AssuranceClass, pressure: Level) -> NodeCapability {
    NodeCapability {
        node_id: "node-c".into(),
        targets: vec!["x86_64-linux".into()],
        verdict: Verdict::Admit,
        assurance,
        pressure,
        build_capacity: Some(furcate_resource::BuildMachine {
            logical_cpus: 8,
            usable_bytes: 64 * 1024 * 1024 * 1024,
            quiet_jobs: None,
        }),
        builds: furcate_host::acoustics::BuildVerdict::Unrestricted,
        observed: furcate_resource::Observed::default(),
    }
}

fn builder() -> Builder {
    Builder {
        id: "node-c".into(),
        assurance_grade: "Tpm".into(),
        attestation_coverage: "PlatformAndOs".into(),
    }
}

fn allow() -> furcate_policy::Decision {
    furcate_policy::Decision {
        allowed: true,
        because: "operator policy permits builds on node-c".into(),
        structural: false,
    }
}

/// A manifest whose one action writes a deterministic file.
fn manifest_and_workdir() -> (Manifest, PathBuf) {
    let work = scratch("work");
    // A real input file, so resolution has bytes to name.
    fs::write(work.join("src.txt"), b"the source").unwrap();
    let yaml = r#"
target: x86_64-linux
actions:
  hello:
    command: [sh, -c, "printf built-from-source > out.bin"]
    inputs:
      src: src.txt
    outputs:
      - out.bin
    network: denied
"#;
    (Manifest::parse(yaml).unwrap(), work)
}

#[test]
fn full_pipeline_builds_attests_and_chains() {
    let cas = Cas::open(scratch("cas")).unwrap();
    let cache = ActionCache::open(scratch("cache")).unwrap();
    let (manifest, work) = manifest_and_workdir();
    // Resolve inputs relative to the work dir so `src.txt` is found.
    std::env::set_current_dir(&work).unwrap();
    let action = manifest.resolve("hello", &cas).unwrap();

    assert_eq!(action.network, Network::Denied);

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let mut chain = Chain::genesis("node-c", 1_000);
    let len_before = chain.len();

    let ctx = BuildContext {
        decision: &allow(),
        node: &node(AssuranceClass::Tpm, Level::Clear),
        placement_policy: &PlacementPolicy { floor: AssuranceClass::Device },
        cas: &cas,
        cache: &cache,
        isolation: &ProcessSandbox,
        work_dir: &work,
        signing_key: &key,
        builder: builder(),
        ts_ms: 2_000,
    };

    let outcome = execute(&action, ctx, &mut chain).expect("build succeeds");

    // Fresh build, one output, attested, chained.
    assert!(!outcome.from_cache);
    assert_eq!(outcome.result.outputs.len(), 1);
    assert!(!outcome.result.is_reproducible(), "one build is not reproducible");
    assert!(outcome.provenance.verify().is_ok(), "provenance must verify");
    assert_eq!(chain.len(), len_before + 1, "the build is chained");
    assert!(chain.verify().is_ok(), "ledger stays continuous");

    // The attested output digest is really in the store.
    let d = outcome.result.outputs.get("out.bin").unwrap();
    assert_eq!(cas.get(d).unwrap(), b"built-from-source");
}

#[test]
fn second_identical_build_is_a_cache_hit() {
    let cas = Cas::open(scratch("cas2")).unwrap();
    let cache = ActionCache::open(scratch("cache2")).unwrap();
    let (manifest, work) = manifest_and_workdir();
    std::env::set_current_dir(&work).unwrap();
    let action = manifest.resolve("hello", &cas).unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let mut chain = Chain::genesis("node-c", 1_000);

    // Owned values live in this scope so both contexts can borrow them.
    let decision = allow();
    let candidate = node(AssuranceClass::Tpm, Level::Clear);
    let pp = PlacementPolicy { floor: AssuranceClass::Device };
    let iso = ProcessSandbox;

    let first = execute(
        &action,
        BuildContext {
            decision: &decision,
            node: &candidate,
            placement_policy: &pp,
            cas: &cas,
            cache: &cache,
            isolation: &iso,
            work_dir: &work,
            signing_key: &key,
            builder: builder(),
            ts_ms: 2_000,
        },
        &mut chain,
    )
    .unwrap();
    assert!(!first.from_cache);

    let second = execute(
        &action,
        BuildContext {
            decision: &decision,
            node: &candidate,
            placement_policy: &pp,
            cas: &cas,
            cache: &cache,
            isolation: &iso,
            work_dir: &work,
            signing_key: &key,
            builder: builder(),
            ts_ms: 2_000,
        },
        &mut chain,
    )
    .unwrap();
    assert!(second.from_cache, "identical action must hit the cache");
    assert!(second.provenance.verify().is_ok());
}

#[test]
fn a_policy_denied_build_is_refused_and_chained() {
    let cas = Cas::open(scratch("cas3")).unwrap();
    let cache = ActionCache::open(scratch("cache3")).unwrap();
    let (manifest, work) = manifest_and_workdir();
    std::env::set_current_dir(&work).unwrap();
    let action = manifest.resolve("hello", &cas).unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let mut chain = Chain::genesis("node-c", 1_000);
    let len_before = chain.len();

    let deny = furcate_policy::Decision {
        allowed: false,
        because: "builds are cordoned during the freeze".into(),
        structural: false,
    };
    let ctx = BuildContext {
        decision: &deny,
        node: &node(AssuranceClass::Tpm, Level::Clear),
        placement_policy: &PlacementPolicy { floor: AssuranceClass::Device },
        cas: &cas,
        cache: &cache,
        isolation: &ProcessSandbox,
        work_dir: &work,
        signing_key: &key,
        builder: builder(),
        ts_ms: 2_000,
    };

    match execute(&action, ctx, &mut chain) {
        Err(BuildError::PolicyDenied(why)) => assert!(why.contains("freeze")),
        other => panic!("expected PolicyDenied, got {other:?}"),
    }
    // A refusal is chained too -- what was declined is as auditable as what ran.
    assert_eq!(chain.len(), len_before + 1);
}

#[test]
fn a_node_below_the_floor_is_refused() {
    let cas = Cas::open(scratch("cas4")).unwrap();
    let cache = ActionCache::open(scratch("cache4")).unwrap();
    let (manifest, work) = manifest_and_workdir();
    std::env::set_current_dir(&work).unwrap();
    let action = manifest.resolve("hello", &cas).unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let mut chain = Chain::genesis("node-c", 1_000);

    let ctx = BuildContext {
        decision: &allow(),
        node: &node(AssuranceClass::Soft, Level::Clear),
        placement_policy: &PlacementPolicy { floor: AssuranceClass::Tpm },
        cas: &cas,
        cache: &cache,
        isolation: &ProcessSandbox,
        work_dir: &work,
        signing_key: &key,
        builder: builder(),
        ts_ms: 2_000,
    };

    match execute(&action, ctx, &mut chain) {
        Err(BuildError::Refused(Refusal::BelowAttestationFloor { required, offered })) => {
            assert_eq!(required, "Tpm");
            assert_eq!(offered, "Soft");
        }
        other => panic!("expected BelowAttestationFloor, got {other:?}"),
    }
}

#[test]
fn provenance_from_a_manifest_names_the_materials() {
    let cas = Cas::open(scratch("cas5")).unwrap();
    let (manifest, work) = manifest_and_workdir();
    std::env::set_current_dir(&work).unwrap();
    let action = manifest.resolve("hello", &cas).unwrap();
    // The input digest is the digest of the source bytes we wrote.
    let src_digest = furcate_build::Digest::of(b"the source");
    assert_eq!(action.inputs.get("src"), Some(&src_digest));

    // And it travels into the provenance as a material.
    let mut outputs = std::collections::BTreeMap::new();
    outputs.insert("out.bin".to_string(), furcate_build::Digest::of(b"built-from-source"));
    let result = furcate_build::ActionResult { action: action.digest(), outputs, observations: 1 };
    let stmt = Statement::new(&action, &result, builder()).unwrap();
    assert_eq!(stmt.predicate.materials.get("src"), Some(&src_digest));
}
