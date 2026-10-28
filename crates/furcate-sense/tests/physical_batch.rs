//! The recorded Nicla capture, through the cascade and out as a signed physical
//! batch, compared byte for byte with the committed golden vector.
//!
//! The consumer of the batch keeps a copy of the same vector and verifies it
//! with no Furcate code, so this test is what stops the two sides drifting: if
//! the producer's output changes, this fails until the vector is regenerated
//! (`UPDATE_GOLDEN=1 cargo test -p furcate-sense --test physical_batch`) and the
//! new file is copied to the consumer.
//!
//! The site key is a test key made here from a fixed seed. It signs nothing
//! real and protects nothing.

use furcate_identity::{AssuranceClass, LeafKeyCustody, Lockdown};
use furcate_sense::cascade::directory::Directory;
use furcate_sense::cascade::escalate::MarginPolicy;
use furcate_sense::cascade::ingest::{Frame, Ingest, IngestPolicy};
use furcate_sense::cascade::micro::MicroSim;
use furcate_sense::cascade::physical::{
    canonical_sha256, signing_bytes, BatchBuilder, ExportRefusal, LogSegment, SiteClock, BATCH_DOMAIN,
};
use furcate_sense::cascade::signer::CascadeSigner;
use furcate_sense::cascade::small::{Forwarded, Forwarder, Outcome, SmallNode};
use furcate_sense::leaf::verify_with_key;
use furcate_sense::nicla::{NodeRole, Sample};
use furcate_sense::text::{LineSplitter, TextSession};
use furcate_sense::Leaf;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const CAPTURE: &[u8] = include_bytes!("fixtures/nicla-standalone-real-capture.bin");
const GOLDEN: &str = include_str!("fixtures/physical-batch.golden.json");
const GOLDEN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/physical-batch.golden.json");

/// The test site key: a fixed seed, public by construction.
const SITE_SEED: [u8; 32] = [0x5a; 32];
/// Samples taken from the start of the capture (after the line noise).
const SAMPLES: usize = 16;
/// The site's wall clock when the first frame arrives, in milliseconds.
const SITE_EPOCH_MS: u64 = 1_761_600_000_000;

const FIXED: Option<LeafKeyCustody> = Some(LeafKeyCustody::FuseKey {
    lockdown: Lockdown { secure_boot: true, flash_encryption: true, download_disabled: true, jtag_disabled: true },
});

struct Shared(Arc<Mutex<Vec<Forwarded>>>);

impl Forwarder for Shared {
    fn forward(&mut self, f: &Forwarded) -> Result<(), String> {
        self.0.lock().unwrap().push(f.clone());
        Ok(())
    }
}

struct Run {
    batch: Value,
    site: Leaf,
    next_dir: Directory,
    forwarded: Vec<Forwarded>,
    frames: Vec<Frame>,
}

/// The stated full-scale ranges of the capture's sketch: +/-2 g and +/-2000 dps, as the
/// existing capture tests state them (the sketch prints no range lines).
fn samples() -> Vec<Sample> {
    let mut session = TextSession::with_ranges(2.0, 2000.0).unwrap();
    LineSplitter::new()
        .push(CAPTURE)
        .into_iter()
        .filter_map(|l| session.feed_line(&l).ok().flatten())
        .take(SAMPLES)
        .collect()
}

fn run() -> Run {
    let mut micro = MicroSim::new("SYNTH-0001", [9u8; 32], "furcate:node:micro1");
    micro.set_binding(Some(MicroSim::feature_binding(1)));
    let small_leaf = Leaf::new("furcate:node:small1", [3u8; 32]);
    let site = Leaf::new("furcate:node:large1", SITE_SEED);

    let mut dir = Directory::new();
    dir.add_node(&micro.gateway_attachment(FIXED), NodeRole::MicroProcessing).unwrap();
    dir.bind_sensing(micro.sensing_id(), "furcate:node:micro1").unwrap();

    let sent = Arc::new(Mutex::new(Vec::new()));
    let signer: Arc<dyn CascadeSigner> = Arc::new(Leaf::new("furcate:node:small1", [3u8; 32]));
    let ingest = Ingest::new(dir, signer.clone(), IngestPolicy::default());
    let mut node = SmallNode::new(
        ingest,
        signer,
        AssuranceClass::Device,
        None,
        Box::new(MarginPolicy::new(0.2, 2)),
        Box::new(Shared(sent.clone())),
    )
    .forward_readings(true);

    let mut now = 1_000u64;
    let mut frames = Vec::new();
    for s in samples() {
        for f in micro.reading_frames(&s, now).unwrap() {
            assert!(matches!(node.handle(&f, now + 5), Outcome::Escalated { .. }));
            frames.push(f);
            now += 10;
        }
    }
    let cp = micro.checkpoint_frame(now);
    let Outcome::Cosigned(cosigned) = node.handle(&cp, now + 5) else { panic!("the checkpoint is cosigned") };
    let forwarded = sent.lock().unwrap().clone();

    let next_dir = next_dir_of(&small_leaf, &micro);
    let mut b = BatchBuilder::new(
        "site-test-01",
        "furcate:node:large1",
        AssuranceClass::Soft,
        "00000000-0000-4000-8000-000000000001",
        1,
        SITE_EPOCH_MS + now + 100,
        SiteClock { source: "ntp".into(), uncertainty_ms: Some(50) },
    );
    let mut entries = Vec::new();
    for (f, frame) in forwarded.iter().zip(&frames) {
        let Frame::Reading { entry, .. } = frame else { panic!() };
        entries.push(entry.clone());
        // The site reads its own clock when the frame arrives: 5 ms after the micro node stamped it.
        b.add_forwarded(f, &next_dir, entry, SITE_EPOCH_MS + entry.ts_ms + 5).unwrap();
    }
    b.add_log(
        LogSegment {
            leaf_id: micro.sensing_id().to_string(),
            leaf_key: micro.signer().public_key(),
            witness_key: small_leaf.public_key(),
            entries,
            cosigned,
        },
        now + 50,
    )
    .unwrap();
    let batch = b.build(&site).unwrap();
    Run { batch, site, next_dir, forwarded, frames }
}

fn next_dir_of(small_leaf: &Leaf, micro: &MicroSim) -> Directory {
    let mut d = Directory::new();
    d.add_node(&micro.gateway_attachment(FIXED), NodeRole::MicroProcessing).unwrap();
    d.bind_sensing(micro.sensing_id(), "furcate:node:micro1").unwrap();
    d.add_node(&small_leaf.attach("next", FIXED, 0), NodeRole::SmallProcessing).unwrap();
    d
}

fn document(r: &Run) -> String {
    let kinds: std::collections::BTreeSet<String> =
        r.batch["readings"].as_array().unwrap().iter().map(|x| x["kind"].as_str().unwrap().to_string()).collect();
    let doc = json!({
        "note": "Generated by crates/open/furcate-sense/tests/physical_batch.rs from the recorded Nicla capture with a test site key (seed 0x5a repeated 32 times). Do not edit; regenerate with UPDATE_GOLDEN=1.",
        "batch": r.batch,
        "expected": {
            "site_key_id": r.site.public_key(),
            "canonical_sha256": canonical_sha256(&r.batch).unwrap(),
            "effective": "soft",
            "limiting_hop": r.batch["readings"][0]["attestation"]["limiting_hop"],
            "readings": r.batch["readings"].as_array().unwrap().len(),
            "kinds": kinds,
        }
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap();
    s.push('\n');
    s
}

#[test]
fn the_golden_vector_is_what_the_producer_writes_now() {
    let r = run();
    let now = document(&r);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(GOLDEN_PATH, &now).unwrap();
        return;
    }
    assert!(now == GOLDEN, "the producer's batch differs from tests/fixtures/physical-batch.golden.json; regenerate with UPDATE_GOLDEN=1 and copy it to the consumer");
}

#[test]
fn the_batch_carries_the_capture_and_its_proofs() {
    let r = run();
    let b = &r.batch;
    let readings = b["readings"].as_array().unwrap();
    assert!(readings.len() >= 30, "{}", readings.len());
    // Every reading's chain is sensing, micro, small, large, and the level is the lowest of them.
    for x in readings {
        let roles: Vec<&str> = x["attestation"]["hops"].as_array().unwrap().iter().map(|h| h["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["sensing", "micro_processing", "small_processing", "large_processing"]);
        assert_eq!(x["attestation"]["effective"], "soft");
        assert_eq!(x["attestation"]["limiting_hop"], x["leaf_id"]);
        assert!(x["binding"]["self_test"].as_bool().unwrap());
    }
    // The signature is the site key's over the canonical bytes, under the batch domain.
    let bytes = signing_bytes(b).unwrap();
    assert_eq!(
        verify_with_key(b["site_key_id"].as_str().unwrap(), BATCH_DOMAIN, bytes.as_bytes(), b["signature"].as_str().unwrap()),
        Ok(())
    );
    assert!(verify_with_key(b["site_key_id"].as_str().unwrap(), "other/domain", bytes.as_bytes(), b["signature"].as_str().unwrap()).is_err());
    // Every forwarded reading is again verifiable by the rung that built the batch.
    assert_eq!(r.forwarded.len(), readings.len());
    assert!(r.frames.len() == readings.len());
}

#[test]
fn the_exporter_takes_only_what_it_verified() {
    let mut r = run();
    // A value altered after signing is refused before it is exported.
    if let furcate_sense::cascade::small::ForwardedItem::Reading(b) = &mut r.forwarded[0].item {
        b.reading.value += 1.0;
    }
    let mut b = BatchBuilder::new("s", "furcate:node:large1", AssuranceClass::Soft, "id", 1, 0, SiteClock { source: "none".into(), uncertainty_ms: None });
    let Frame::Reading { entry, .. } = &r.frames[0] else { panic!() };
    assert!(matches!(b.add_forwarded(&r.forwarded[0], &r.next_dir, entry, 0), Err(ExportRefusal::Unverified(_))));
    // A reading with no log covering it cannot be built.
    let mut b = BatchBuilder::new("s", "furcate:node:large1", AssuranceClass::Soft, "id", 1, 0, SiteClock { source: "none".into(), uncertainty_ms: None });
    b.add_forwarded(&r.forwarded[1], &r.next_dir, match &r.frames[1] { Frame::Reading { entry, .. } => entry, _ => panic!() }, 0).unwrap();
    assert!(matches!(b.build(&r.site), Err(ExportRefusal::NotInLog { .. })));
}

#[test]
fn the_vector_names_the_keys_that_signed_its_log() {
    let r = run();
    let l = &r.batch["logs"][0];
    assert_eq!(l["entries"].as_array().unwrap().len() as u64, l["checkpoint"]["size"].as_u64().unwrap());
    assert!(l["leaf_key_id"].as_str().unwrap().starts_with("ed25519:"));
}
