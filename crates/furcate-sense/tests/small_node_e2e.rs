//! The recorded sensing-node capture through every rung: decode, the micro
//! processing node's signing (simulated), the small processing node's
//! verification, log, model and escalation, and the next rung's check.

use furcate_identity::{AssuranceClass, LeafKeyCustody, Lockdown};
use furcate_sense::cascade::binding::{calibration_prefix, BindingRegistry, ModelBinding, BINDING_WIRE_LEN};
use furcate_sense::cascade::coherence::{CoherenceConfig, CoherenceMonitor, Flag};
use furcate_sense::cascade::commit::{audit, check_complete, verify_batch, wire_cost, AuditFailure, BatchBuilder};
use furcate_sense::cascade::directory::Directory;
use furcate_sense::cascade::drift::{Cause, DriftConfig, FleetDrift};
use furcate_sense::cascade::escalate::{EscalationReason, MarginPolicy};
use furcate_sense::cascade::ingest::{Frame, Ingest, IngestPolicy, RefusalReason};
use furcate_sense::cascade::micro::{window_features, MicroSim};
use furcate_sense::cascade::model::{NearestCentroid, WindowModel};
use furcate_sense::cascade::signer::CascadeSigner;
use furcate_sense::cascade::small::{
    verify_forwarded, ForwardRefusal, Forwarded, ForwardedItem, Forwarder, Outcome, SmallNode,
};
use furcate_sense::cascade::witness::{verify_cosigned, WitnessRefusal};
use furcate_sense::nicla::{NodeRole, Sample};
use furcate_sense::text::{LineSplitter, TextSession};
use furcate_sense::Leaf;
use std::sync::{Arc, Mutex};

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

struct Failing;

impl Forwarder for Failing {
    fn forward(&mut self, _: &Forwarded) -> Result<(), String> {
        Err("link down".into())
    }
}

struct World {
    micro: MicroSim,
    small_leaf: Leaf,
    next_dir: Directory,
    node: SmallNode,
    sent: Arc<Mutex<Vec<Forwarded>>>,
    samples: Vec<Sample>,
}

fn samples() -> Vec<Sample> {
    let capture = include_str!("fixtures/nicla-standalone-usb.txt");
    let mut session = TextSession::new();
    LineSplitter::new()
        .push(capture.as_bytes())
        .into_iter()
        .filter_map(|l| session.feed_line(&l).unwrap())
        .collect()
}

fn world_with(policy: IngestPolicy, margin: MarginPolicy, forwarder: Option<Box<dyn Forwarder>>) -> World {
    let micro = MicroSim::new("SYNTH-0001", [9u8; 32], "furcate:node:micro1");
    let small_leaf = Leaf::new("furcate:node:small1", [3u8; 32]);

    // The small node's records: its micro node and the binding.
    let mut dir = Directory::new();
    dir.add_node(&micro.gateway_attachment(FIXED), NodeRole::MicroProcessing).unwrap();
    dir.bind_sensing(micro.sensing_id(), "furcate:node:micro1").unwrap();
    // The next rung's records add the small node itself.
    let mut next_dir = dir.clone();
    next_dir.add_node(&small_leaf.attach("next", FIXED, 0), NodeRole::SmallProcessing).unwrap();

    let samples = samples();
    let near = window_features(&samples);
    let far: Vec<i8> = near.iter().map(|v| v.wrapping_neg().clamp(-100, 100)).collect();
    let model = NearestCentroid::fit(
        "reference-centroid",
        &[("capture".to_string(), near), ("elsewhere".to_string(), far)],
    )
    .unwrap();

    let sent = Arc::new(Mutex::new(Vec::new()));
    let forwarder = forwarder.unwrap_or_else(|| Box::new(Shared(sent.clone())));
    let signer: Arc<dyn CascadeSigner> = Arc::new(Leaf::new("furcate:node:small1", [3u8; 32]));
    let ingest = Ingest::new(dir, signer.clone(), policy);
    let node = SmallNode::new(ingest, signer, AssuranceClass::Device, Some(Box::new(model)), Box::new(margin), forwarder);
    World { micro, small_leaf, next_dir, node, sent, samples }
}

fn world() -> World {
    world_with(IngestPolicy::default(), MarginPolicy::new(0.2, 2), None)
}

#[test]
fn the_capture_flows_through_every_rung() {
    let mut w = world();
    let mut now = 1_000u64;

    // Readings: the sensing node's channels, signed by the micro node, verified here.
    let mut verified = 0;
    for s in w.samples.clone() {
        for f in w.micro.reading_frames(&s, now).unwrap() {
            match w.node.handle(&f, now + 5) {
                Outcome::Stored => verified += 1,
                other => panic!("{other:?}"),
            }
            now += 10;
        }
    }
    assert_eq!(verified, 12, "acceleration 3, gyroscope 3, temperature, gas, rotation 4");

    // Embeddings: the capture's window twice (one kept, one audited) and an ambiguous one.
    let near = window_features(&w.samples);
    let ambiguous: Vec<i8> = near.iter().map(|_| 0i8).collect();
    let mut outcomes = Vec::new();
    for v in [&near, &near, &ambiguous] {
        let f = w.micro.embedding_frame(v, now);
        outcomes.push(w.node.handle(&f, now + 5));
        now += 100;
    }
    let Outcome::Kept { inference: Some(i) } = &outcomes[0] else { panic!("{:?}", outcomes[0]) };
    assert_eq!(i.label, "capture");
    assert!(matches!(&outcomes[1], Outcome::Escalated { reason: EscalationReason::Audit, .. }));
    assert!(matches!(&outcomes[2], Outcome::Escalated { reason: EscalationReason::LowMargin, .. }));

    // The log checkpoint is cosigned by the small node and checks out for a consumer.
    let cp = w.micro.checkpoint_frame(now);
    let Outcome::Cosigned(c) = w.node.handle(&cp, now + 5) else { panic!() };
    assert_eq!(c.signed.checkpoint.size, 12 + 3);
    assert_eq!(
        verify_cosigned(&c, &w.micro.signer().public_key(), &w.small_leaf.public_key(), now + 50, 1_000),
        Ok(())
    );

    // The next rung verifies what was passed up, with this rung in the chain.
    let sent = w.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    for f in &sent {
        let report = verify_forwarded(f, &w.next_dir, AssuranceClass::Soft).unwrap();
        assert_eq!(report.hops.iter().map(|h| h.role).collect::<Vec<_>>(), [NodeRole::Sensing, NodeRole::MicroProcessing, NodeRole::SmallProcessing]);
        // The sensing node holds no secret, so nothing above it can raise this.
        assert_eq!(report.effective, AssuranceClass::Soft);
        assert_eq!(report.limiting, w.micro.sensing_id());
        assert_eq!(f.inference.as_ref().unwrap().model.id, "reference-centroid");
        assert_eq!(f.inference.as_ref().unwrap().model.sha256.len(), 64);
        assert_eq!(
            verify_forwarded(f, &w.next_dir, AssuranceClass::Device),
            Err(ForwardRefusal::BelowFloor { required: AssuranceClass::Device, found: AssuranceClass::Soft })
        );
    }
    let s = w.node.stats();
    assert_eq!((s.readings, s.embeddings, s.kept, s.escalated, s.refused, s.cosigned), (12, 3, 1, 2, 0, 1));
}

#[test]
fn tampering_is_refused_and_recorded() {
    let mut w = world();
    let now = 5_000;

    // A value altered after signing.
    let mut f = w.micro.reading_frames(&Sample::Temperature(21.0), now).unwrap().remove(0);
    if let Frame::Reading { item, .. } = &mut f {
        item.reading.value = 99.0;
    }
    let Outcome::Refused(r) = w.node.handle(&f, now) else { panic!() };
    assert_eq!(r.code, "bad_reading_signature");

    // An embedding altered after signing.
    let mut f = w.micro.embedding_frame(&[1, 2, 3, 4], now + 10);
    if let Frame::Embedding { item, .. } = &mut f {
        item.window.values[0] = 100;
    }
    let Outcome::Refused(r) = w.node.handle(&f, now + 10) else { panic!() };
    assert_eq!(r.code, "bad_envelope_signature");

    // Provenance edited after signing: a stronger sensing node.
    let mut f = w.micro.embedding_frame(&[1, 2, 3, 4], now + 20);
    if let Frame::Embedding { item, .. } = &mut f {
        item.provenance.chain[0].attestation_level = AssuranceClass::Tpm;
    }
    let Outcome::Refused(r) = w.node.handle(&f, now + 20) else { panic!() };
    assert_eq!(r.code, "bad_envelope_signature");

    // The tampered frames consumed nothing: the next honest ones are accepted
    // only after the log gap the tampering left is healed by the honest sender,
    // which here means the earlier entries never reached the witness.
    assert_eq!(w.node.stats().refused, 3);
    assert_eq!(w.node.ingest().refused_total(), 3);
    assert_eq!(w.node.ingest().recent_refusals().count(), 3);
}

#[test]
fn a_processing_node_that_claims_more_than_it_is_refused() {
    let mut w = world();
    let mut liar = MicroSim::claiming("SYNTH-0001", [9u8; 32], "furcate:node:micro1", AssuranceClass::Tpm);
    assert_eq!(liar.sensing_id(), w.micro.sensing_id());
    let f = liar.embedding_frame(&[1, 2, 3, 4], 100);
    let Outcome::Refused(r) = w.node.handle(&f, 100) else { panic!() };
    assert_eq!(r.code, "chain");
    assert!(r.detail.contains("claims `tpm`"), "{}", r.detail);
}

#[test]
fn a_swapped_unit_is_refused() {
    let mut w = world();
    // Another board, read by the same processing node and key: not the enrolled unit.
    let mut other = MicroSim::new("OTHERUNIT", [9u8; 32], "furcate:node:micro1");
    assert_ne!(other.sensing_id(), w.micro.sensing_id());
    let f = other.embedding_frame(&[1, 2, 3, 4], 100);
    let Outcome::Refused(r) = w.node.handle(&f, 100) else { panic!() };
    assert_eq!(r.code, "unknown_source");
    // Another processing node claiming the enrolled board: its key is not the enrolled one.
    let mut thief = MicroSim::new("SYNTH-0001", [8u8; 32], "furcate:node:micro1");
    assert_eq!(thief.sensing_id(), w.micro.sensing_id());
    let f = thief.embedding_frame(&[1, 2, 3, 4], 100);
    let Outcome::Refused(r) = w.node.handle(&f, 100) else { panic!() };
    assert_eq!(r.code, "bad_envelope_signature");
}

#[test]
fn drop_duplicate_reorder_and_delay_are_each_detected() {
    let mut w = world_with(
        IngestPolicy { max_delay_ms: 500, ..IngestPolicy::default() },
        MarginPolicy::new(0.0, 0),
        None,
    );
    let v = [1i8, 2, 3, 4];
    let f1 = w.micro.embedding_frame(&v, 1_000);
    let f2 = w.micro.embedding_frame(&v, 1_100);
    let f3 = w.micro.embedding_frame(&v, 1_200);
    let f4 = w.micro.embedding_frame(&v, 1_300);

    assert!(matches!(w.node.handle(&f1, 1_005), Outcome::Kept { .. }));
    // Drop: f2 never arrives, f3 skips ahead.
    let Outcome::Refused(r) = w.node.handle(&f3, 1_205) else { panic!() };
    assert_eq!(r.code, "log_gap");
    // The checkpoint over a log with a hole is not cosigned.
    let Outcome::Refused(r) = w.node.handle(&w.micro.checkpoint_frame(1_400), 1_405) else { panic!() };
    assert!(r.detail.contains("were witnessed"), "{}", r.detail);
    // Reorder healed: f2 then f3 in order are accepted.
    assert!(matches!(w.node.handle(&f2, 1_105), Outcome::Kept { .. }));
    assert!(matches!(w.node.handle(&f3, 1_205), Outcome::Kept { .. }));
    // Duplicate and replay.
    let Outcome::Refused(r) = w.node.handle(&f3, 1_210) else { panic!() };
    assert_eq!(r.code, "log_duplicate");
    let Outcome::Refused(r) = w.node.handle(&f1, 1_210) else { panic!() };
    assert_eq!(r.code, "log_duplicate");
    // Delay: f4 held back for two seconds beyond the usual 5 ms.
    let Outcome::Refused(r) = w.node.handle(&f4, 1_300 + 5 + 2_000) else { panic!() };
    assert_eq!(r.code, "late");
    // It is still in the log, so the checkpoint over it is cosigned.
    let cp = w.micro.checkpoint_frame(4_000);
    assert!(matches!(w.node.handle(&cp, 4_005), Outcome::Cosigned(_)));
}

#[test]
fn a_replayed_reading_and_a_replayed_window_are_refused() {
    let mut w = world();
    let f = w.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    assert!(matches!(w.node.handle(&f, 105), Outcome::Stored));
    let Outcome::Refused(r) = w.node.handle(&f, 106) else { panic!() };
    assert_eq!(r.code, "log_duplicate");
    // The same signed window under a fresh log entry is still a replayed window.
    let e = w.micro.embedding(&[1, 2, 3, 4], 200);
    let entry = w.micro.log_entry(&e.envelope_signature, 200);
    let ok = Frame::Embedding { item: e.clone(), entry };
    assert!(matches!(w.node.handle(&ok, 205), Outcome::Kept { .. } | Outcome::Escalated { .. }));
    let entry = w.micro.log_entry(&e.envelope_signature, 210);
    let again = Frame::Embedding { item: e, entry };
    let Outcome::Refused(r) = w.node.handle(&again, 215) else { panic!() };
    assert_eq!(r.code, "replayed_window");
}

#[test]
fn a_policy_refusal_is_recorded_and_does_not_block_the_log() {
    let policy = IngestPolicy { min_effective: AssuranceClass::Device, ..IngestPolicy::default() };
    let mut w = world_with(policy, MarginPolicy::new(0.0, 0), None);
    let f = w.micro.embedding_frame(&[1, 2, 3, 4], 100);
    let Outcome::Refused(r) = w.node.handle(&f, 105) else { panic!() };
    assert_eq!(r.code, "below_floor");
    // The log moved on, so the checkpoint over the refused item is cosigned.
    assert!(matches!(w.node.handle(&w.micro.checkpoint_frame(200), 205), Outcome::Cosigned(_)));
}

#[test]
fn the_next_rung_refuses_a_forwarded_message_that_was_altered() {
    let mut w = world_with(IngestPolicy::default(), MarginPolicy::new(2.0, 0), None); // margin never reaches 2: always up
    for t in 0..2 {
        let f = w.micro.embedding_frame(&[1, 2, 3, 4], 100 + t);
        assert!(matches!(w.node.handle(&f, 105 + t), Outcome::Escalated { .. }));
    }
    let good = w.sent.lock().unwrap()[0].clone();
    assert!(verify_forwarded(&good, &w.next_dir, AssuranceClass::Soft).is_ok());

    let mut t = good.clone();
    t.inference.as_mut().unwrap().label = "tampered".into();
    assert_eq!(verify_forwarded(&t, &w.next_dir, AssuranceClass::Soft), Err(ForwardRefusal::BadOutputSignature));

    let mut t = good.clone();
    if let ForwardedItem::Embedding(e) = &mut t.item {
        e.countersignatures.clear(); // the small node's rung removed
    }
    assert!(verify_forwarded(&t, &w.next_dir, AssuranceClass::Soft).is_err());

    let mut t = good.clone();
    t.inference = None; // the answer removed, hop still names a model
    assert!(verify_forwarded(&t, &w.next_dir, AssuranceClass::Soft).is_err());

    // The next rung does not know the small node: its rung is not trusted.
    let mut unaware = Directory::new();
    unaware.add_node(&w.micro.gateway_attachment(FIXED), NodeRole::MicroProcessing).unwrap();
    unaware.bind_sensing(w.micro.sensing_id(), "furcate:node:micro1").unwrap();
    assert!(matches!(verify_forwarded(&good, &unaware, AssuranceClass::Soft), Err(ForwardRefusal::Chain(_))));
}

#[test]
fn a_failed_forward_is_reported_not_swallowed() {
    let mut w = world_with(IngestPolicy::default(), MarginPolicy::new(2.0, 0), Some(Box::new(Failing)));
    let f = w.micro.embedding_frame(&[1, 2, 3, 4], 100);
    let Outcome::ForwardFailed { error, .. } = w.node.handle(&f, 105) else { panic!() };
    assert_eq!(error, "link down");
    assert_eq!(w.node.stats().forward_failed, 1);
}

#[test]
fn the_model_hash_in_the_chain_is_the_models() {
    let mut w = world_with(IngestPolicy::default(), MarginPolicy::new(2.0, 0), None);
    let f = w.micro.embedding_frame(&[1, 2, 3, 4], 100);
    w.node.handle(&f, 105);
    let sent = w.sent.lock().unwrap()[0].clone();
    let ForwardedItem::Embedding(e) = &sent.item else { panic!() };
    let near = window_features(&w.samples);
    let far: Vec<i8> = near.iter().map(|v| v.wrapping_neg().clamp(-100, 100)).collect();
    let m = NearestCentroid::fit("reference-centroid", &[("capture".into(), near), ("elsewhere".into(), far)]).unwrap();
    let furcate_sense::nicla::Derivation::Model(r) = &e.countersignatures[0].hop.derivation else { panic!() };
    assert_eq!(r, m.model_ref());
    // The micro node's own model is named in its hop as well.
    assert!(matches!(&e.provenance.chain[1].derivation, furcate_sense::nicla::Derivation::Model(r) if r.id.starts_with("furcate-sim-window-features")));
    let _ = (RefusalReason::UnknownSource, WitnessRefusal::UnknownLeaf);
}

// Provenance-bound readings: the model, epoch, calibration and self test a node
// states are checked against the verifier's registry. The injected faults are
// run once with no registry (what the cascade did before) and once with one.

const WEIGHTS: &[u8] = b"furcate-ref reference weights, release 7: 64 bytes of stand-in data!";
const CALIBRATION: &[u8] = b"calibration artefact A";
const EPOCH: u32 = 7;

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

fn registry(micro: &MicroSim) -> BindingRegistry {
    let mut r = BindingRegistry::new().with_min_epoch(EPOCH);
    r.register_model("window-features", &sha_hex(WEIGHTS), 0).unwrap();
    r.register_calibration(micro.sensing_id(), calibration_prefix(CALIBRATION));
    r
}

fn bound_world(with_registry: bool) -> World {
    let probe = MicroSim::new("SYNTH-0001", [9u8; 32], "furcate:node:micro1");
    let policy = IngestPolicy { bindings: with_registry.then(|| registry(&probe)), ..IngestPolicy::default() };
    let mut w = world_with(policy, MarginPolicy::new(0.0, 0), None);
    w.micro.set_binding(Some(good_binding()));
    w.micro.set_model(furcate_sense::nicla::ModelRef { id: "window-features".into(), sha256: sha_hex(WEIGHTS) });
    w
}

fn good_binding() -> ModelBinding {
    ModelBinding::new(&sha_hex(WEIGHTS), EPOCH, Some(CALIBRATION), true).unwrap()
}

fn accepted(o: &Outcome) -> bool {
    matches!(o, Outcome::Stored | Outcome::Kept { .. } | Outcome::Escalated { .. })
}

#[test]
fn the_capture_passes_with_a_registered_binding_and_adds_17_bytes() {
    let mut w = bound_world(true);
    let mut now = 1_000;
    let mut n = 0;
    for s in w.samples.clone() {
        for f in w.micro.reading_frames(&s, now).unwrap() {
            assert!(accepted(&w.node.handle(&f, now + 5)), "reading refused");
            n += 1;
            now += 10;
        }
    }
    assert_eq!(n, 12);
    let f = w.micro.embedding_frame(&window_features(&w.samples), now);
    assert!(accepted(&w.node.handle(&f, now + 5)));
    assert_eq!(w.node.stats().refused, 0);
    assert_eq!(good_binding().to_wire().unwrap().len(), BINDING_WIRE_LEN);
    // In the JSON frames this implementation exchanges, the binding is a field of the provenance.
    let with = serde_json::to_vec(&good_binding()).unwrap().len();
    println!("binding: {BINDING_WIRE_LEN} bytes compact, {with} bytes as JSON");
    assert!(with < 120);
    assert_eq!(BINDING_WIRE_LEN, 17);
}

#[test]
fn an_item_without_a_binding_is_refused_when_a_registry_is_in_use() {
    let mut w = bound_world(true);
    w.micro.set_binding(None);
    let f = w.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    let Outcome::Refused(r) = w.node.handle(&f, 105) else { panic!() };
    assert_eq!(r.code, "binding_missing");
}

#[test]
fn a_binding_edited_after_signing_breaks_the_signature() {
    let mut w = bound_world(true);
    let mut f = w.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    if let Frame::Reading { item, .. } = &mut f {
        item.provenance.binding.as_mut().unwrap().epoch += 1;
    }
    let Outcome::Refused(r) = w.node.handle(&f, 105) else { panic!() };
    assert_eq!(r.code, "bad_envelope_signature");
}

#[test]
fn the_window_must_name_the_model_the_binding_names() {
    let mut w = bound_world(true);
    w.micro.set_model(furcate_sense::nicla::ModelRef { id: "window-features".into(), sha256: sha_hex(b"other") });
    let f = w.micro.embedding_frame(&[1, 2, 3, 4], 100);
    let Outcome::Refused(r) = w.node.handle(&f, 105) else { panic!() };
    assert_eq!(r.code, "binding_model_disagrees");
}

/// One injected fault per call: every flipped bit of the weights, every epoch
/// below the minimum, a failed self test, a wrong calibration, a revoked model,
/// and a replay. Returns (injected, accepted by the verifier).
fn inject(with_registry: bool) -> (usize, usize, Vec<String>) {
    let mut w = bound_world(with_registry);
    let (mut injected, mut accepted_n) = (0, 0);
    let mut codes = Vec::new();
    let mut now = 1_000u64;
    let mut run = |w: &mut World, f: Frame, now: &mut u64| {
        let o = w.node.handle(&f, *now + 5);
        *now += 10;
        injected += 1;
        if accepted(&o) {
            accepted_n += 1;
        } else if let Outcome::Refused(r) = o {
            codes.push(r.code);
        }
    };

    // Flipped weight byte in flash: the node hashes the weights it holds.
    for byte in 0..WEIGHTS.len() {
        for bit in 0..8 {
            let mut weights = WEIGHTS.to_vec();
            weights[byte] ^= 1 << bit;
            let b = ModelBinding::new(&sha_hex(&weights), EPOCH, Some(CALIBRATION), true).unwrap();
            w.micro.set_binding(Some(b));
            let f = w.micro.reading_frames(&Sample::Temperature(21.0), now).unwrap().remove(0);
            run(&mut w, f, &mut now);
        }
    }
    // Older model: the registered weights at every epoch below the minimum.
    for epoch in 0..EPOCH {
        w.micro.set_binding(Some(ModelBinding::new(&sha_hex(WEIGHTS), epoch, Some(CALIBRATION), true).unwrap()));
        let f = w.micro.reading_frames(&Sample::Temperature(21.0), now).unwrap().remove(0);
        run(&mut w, f, &mut now);
    }
    // Other faults: failed self test and a calibration nobody registered.
    w.micro.set_binding(Some(ModelBinding::new(&sha_hex(WEIGHTS), EPOCH, Some(CALIBRATION), false).unwrap()));
    let f = w.micro.reading_frames(&Sample::Temperature(21.0), now).unwrap().remove(0);
    run(&mut w, f, &mut now);
    w.micro.set_binding(Some(ModelBinding::new(&sha_hex(WEIGHTS), EPOCH, Some(b"calibration artefact B"), true).unwrap()));
    let f = w.micro.reading_frames(&Sample::Temperature(21.0), now).unwrap().remove(0);
    run(&mut w, f, &mut now);

    // Replay: an honest reading is accepted once, then sent again.
    w.micro.set_binding(Some(good_binding()));
    let honest = w.micro.reading_frames(&Sample::Temperature(22.0), now).unwrap().remove(0);
    let o = w.node.handle(&honest, now + 5);
    assert!(accepted(&o), "{o:?}");
    now += 10;
    run(&mut w, honest.clone(), &mut now);
    (injected, accepted_n, codes)
}

#[test]
fn fault_injection_without_a_registry_is_accepted_and_with_one_is_detected_in_full() {
    let (n0, accepted0, _) = inject(false);
    // The baseline: weight flips, old epochs, failed self test and a wrong
    // calibration all pass, and only the exact replay is stopped by the log.
    assert_eq!(n0 - accepted0, 1, "only the replay was refused before bindings");

    let (n1, accepted1, codes) = inject(true);
    assert_eq!(n1, n0);
    assert_eq!(accepted1, 0, "an injected fault was accepted");
    let count = |c: &str| codes.iter().filter(|x| x.as_str() == c).count();
    assert_eq!(count("binding_unknown_model"), WEIGHTS.len() * 8);
    assert_eq!(count("binding_epoch_too_old"), EPOCH as usize);
    assert_eq!(count("binding_self_test_failed"), 1);
    assert_eq!(count("binding_unknown_calibration"), 1);
    assert_eq!(count("log_duplicate"), 1);
    assert_eq!(codes.len(), n1);
}

#[test]
fn an_old_epoch_is_refused_after_an_upgrade_and_a_registry_revocation_takes_effect() {
    // Upgrade seen at epoch 9, then a reading signed at 8 arrives (replayed from before).
    let mut w = bound_world(true);
    w.micro.set_binding(Some(ModelBinding::new(&sha_hex(WEIGHTS), 9, Some(CALIBRATION), true).unwrap()));
    let upgraded = w.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    assert!(accepted(&w.node.handle(&upgraded, 105)));
    w.micro.set_binding(Some(ModelBinding::new(&sha_hex(WEIGHTS), 8, Some(CALIBRATION), true).unwrap()));
    let older = w.micro.reading_frames(&Sample::Temperature(21.0), 200).unwrap().remove(0);
    let Outcome::Refused(r) = w.node.handle(&older, 205) else { panic!() };
    assert_eq!(r.code, "binding_epoch_regressed");

    // A model revoked in the registry is refused although it was accepted before.
    let probe = MicroSim::new("SYNTH-0001", [9u8; 32], "furcate:node:micro1");
    let mut reg = registry(&probe);
    assert_eq!(reg.revoke_model(&sha_hex(WEIGHTS)), Ok(true));
    let mut w2 = world_with(IngestPolicy { bindings: Some(reg), ..IngestPolicy::default() }, MarginPolicy::new(0.0, 0), None);
    w2.micro.set_binding(Some(good_binding()));
    let f = w2.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    let Outcome::Refused(r) = w2.node.handle(&f, 105) else { panic!() };
    assert_eq!(r.code, "binding_revoked_model");
}

#[test]
fn a_refused_binding_stays_in_the_log_and_the_checkpoint_is_still_cosigned() {
    let mut w = bound_world(true);
    w.micro.set_binding(Some(ModelBinding { self_test: false, ..good_binding() }));
    let f = w.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    assert!(matches!(w.node.handle(&f, 105), Outcome::Refused(_)));
    assert!(matches!(w.node.handle(&w.micro.checkpoint_frame(200), 205), Outcome::Cosigned(_)));
}

#[test]
fn a_reading_replayed_to_a_verifier_that_lost_its_state_is_refused_by_epoch() {
    // The reading was honest when signed, at epoch 5, under a registry whose floor was 5.
    let probe = MicroSim::new("SYNTH-0001", [9u8; 32], "furcate:node:micro1");
    let mut old_reg = BindingRegistry::new().with_min_epoch(5);
    old_reg.register_model("window-features", &sha_hex(WEIGHTS), 0).unwrap();
    old_reg.register_calibration(probe.sensing_id(), calibration_prefix(CALIBRATION));
    let mut then = world_with(IngestPolicy { bindings: Some(old_reg), ..IngestPolicy::default() }, MarginPolicy::new(0.0, 0), None);
    then.micro.set_binding(Some(ModelBinding::new(&sha_hex(WEIGHTS), 5, Some(CALIBRATION), true).unwrap()));
    let f = then.micro.reading_frames(&Sample::Temperature(21.0), 100).unwrap().remove(0);
    assert!(accepted(&then.node.handle(&f, 105)), "honest at the time");

    // A verifier with no memory of it and a floor of 7 is shown the same frame later.
    let mut now = bound_world(true);
    let Outcome::Refused(r) = now.node.handle(&f, 9_000) else { panic!() };
    assert_eq!(r.code, "binding_epoch_too_old");
}

// Commit-then-reveal over the recorded capture: each window's raw bytes are
// the capture lines up to a point, and the embedding is what the decoder and
// the feature formula make of them. The rung above gets embeddings through the
// normal path, the signed batch beside them, and challenges windows.

fn embed_capture(raw: &[u8]) -> Vec<i8> {
    let mut session = TextSession::new();
    let samples: Vec<Sample> = LineSplitter::new()
        .push(raw)
        .into_iter()
        .filter_map(|l| session.feed_line(&l).unwrap())
        .collect();
    window_features(&samples)
}

fn capture_windows() -> Vec<Vec<u8>> {
    let capture = include_str!("fixtures/nicla-standalone-usb.txt");
    let lines: Vec<&str> = capture.lines().collect();
    (1..=lines.len()).map(|n| format!("{}\n", lines[..n].join("\n")).into_bytes()).collect()
}

struct Committed {
    w: World,
    builder: BatchBuilder,
    windows: Vec<Vec<u8>>,
    sent: Vec<Vec<i8>>,
    batch: furcate_sense::cascade::commit::SignedBatch,
}

fn committed(hide: Option<usize>) -> Committed {
    let mut w = world_with(IngestPolicy::default(), MarginPolicy::new(2.0, 0), None);
    let windows = capture_windows();
    let model = furcate_sense::cascade::micro::feature_model();
    let mut builder = BatchBuilder::new(w.micro.sensing_id(), &model.sha256[..16], windows.len(), 1 << 20);
    let (mut sent, mut batch) = (Vec::new(), None);
    for (i, raw) in windows.iter().enumerate() {
        let mut e = embed_capture(raw);
        if Some(i) == hide {
            e = vec![0; e.len()]; // a hard window reported as an easy one
        }
        let f = w.micro.embedding_frame(&e, 1_000 + i as u64 * 100);
        assert!(!matches!(w.node.handle(&f, 1_005 + i as u64 * 100), Outcome::Refused(_)));
        batch = builder.push(w.micro.signer(), 1 + i as u64, &e, raw).unwrap().or(batch);
        sent.push(e);
    }
    Committed { w, builder, windows, sent, batch: batch.expect("the batch seals at its last window") }
}

#[test]
fn every_window_of_the_capture_audits_clean_and_the_commit_is_small_next_to_the_raw() {
    let c = committed(None);
    let key = c.w.micro.signer().public_key();
    assert_eq!(verify_batch(&c.batch, &key), Ok(()));
    let seqs: Vec<u64> = (1..=c.windows.len() as u64).collect();
    assert_eq!(check_complete(&c.batch, &seqs), Ok(()));
    for (i, e) in c.sent.iter().enumerate() {
        let r = c.builder.reveal(1 + i as u64).unwrap();
        assert_eq!(audit(&c.batch, e, &r, &embed_capture), Ok(()), "window {}", i + 1);
    }
    // Bytes: the mean raw window against the embedding plus a share of the signed commit.
    let raw_mean = c.windows.iter().map(|w| w.len()).sum::<usize>() / c.windows.len();
    let cost = wire_cost(c.windows.len(), c.sent[0].len(), raw_mean);
    println!("capture: raw {raw_mean} B/window, embedding {} B + commit {:.1} B = {:.1} B/window, {:.1}x less", c.sent[0].len(), cost.commit_per_window, cost.per_window, cost.reduction);
    assert!(cost.per_window < raw_mean as f64);
}

#[test]
fn a_hidden_hard_window_is_found_by_challenging_it_and_only_it() {
    let hidden = 5;
    let c = committed(Some(hidden));
    for (i, e) in c.sent.iter().enumerate() {
        let r = c.builder.reveal(1 + i as u64).unwrap();
        let verdict = audit(&c.batch, e, &r, &embed_capture);
        if i == hidden {
            assert_eq!(verdict, Err(AuditFailure::EmbeddingMismatch));
        } else {
            assert_eq!(verdict, Ok(()), "window {}", i + 1);
        }
    }
}

#[test]
fn a_window_swapped_after_the_commit_or_with_other_raw_is_refused() {
    let c = committed(None);
    // The rung received a different embedding than the one committed to.
    let mut other = c.sent[2].clone();
    other[0] = other[0].wrapping_add(1);
    assert_eq!(audit(&c.batch, &other, &c.builder.reveal(3).unwrap(), &embed_capture), Err(AuditFailure::NotCommitted));
    // The node reveals the raw of another window.
    let mut r = c.builder.reveal(3).unwrap();
    r.raw = c.windows[3].clone();
    assert_eq!(audit(&c.batch, &c.sent[2], &r, &embed_capture), Err(AuditFailure::NotCommitted));
    // A batch signed by a different key is not this node's.
    let thief = Leaf::new("furcate:node:micro1", [8u8; 32]);
    assert_eq!(verify_batch(&c.batch, &thief.public_key()), Err(AuditFailure::BadSignature));
}

// Drift across several sensing nodes behind one small processing node: three
// micro nodes send the capture's embedding with a little noise; the node
// attributes a change to the site, one sensing node, or a model change.

struct Fleet3 {
    micros: Vec<MicroSim>,
    node: SmallNode,
    base: Vec<i8>,
    seed: u64,
    now: u64,
}

fn fleet3() -> Fleet3 {
    let micros: Vec<MicroSim> =
        (0..3).map(|i| MicroSim::new(&format!("UNIT-{i}"), [20 + i as u8; 32], &format!("furcate:node:micro{i}"))).collect();
    let mut dir = Directory::new();
    for m in &micros {
        let gateway = m.gateway_attachment(FIXED);
        dir.add_node(&gateway, NodeRole::MicroProcessing).unwrap();
        dir.bind_sensing(m.sensing_id(), &gateway.leaf_id).unwrap();
    }
    let signer: Arc<dyn CascadeSigner> = Arc::new(Leaf::new("furcate:node:small1", [3u8; 32]));
    let ingest = Ingest::new(dir, signer.clone(), IngestPolicy::default());
    let drift = FleetDrift::new(DriftConfig { reference_windows: 60, ..DriftConfig::default() });
    let node = SmallNode::new(ingest, signer, AssuranceClass::Device, None, Box::new(MarginPolicy::new(0.0, 0)), Box::new(Shared(Default::default())))
        .with_drift(drift);
    Fleet3 { micros, node, base: window_features(&samples()), seed: 0x1234_5678_9ABC_DEF1, now: 1_000 }
}

impl Fleet3 {
    fn noise(&mut self) -> i8 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        (self.seed % 9) as i8 - 4
    }

    /// One window from every node; `shift(node, dim)` is added to the capture's values.
    fn round(&mut self, shift: &dyn Fn(usize, usize) -> i8, model: Option<&str>) {
        for i in 0..self.micros.len() {
            let v: Vec<i8> = (0..self.base.len()).map(|j| self.base[j].saturating_add(shift(i, j)).saturating_add(self.noise())).collect();
            if let Some(m) = model {
                self.micros[i].set_model(furcate_sense::nicla::ModelRef { id: "window-features".into(), sha256: m.repeat(64)[..64].to_string() });
            }
            let f = self.micros[i].embedding_frame(&v, self.now);
            assert!(!matches!(self.node.handle(&f, self.now + 5), Outcome::Refused(_)), "refused");
            self.now += 100;
        }
    }

    fn causes(&self) -> Vec<Cause> {
        self.micros.iter().map(|m| self.node.drift().unwrap().cause_of(m.sensing_id()).unwrap()).collect()
    }
}

#[test]
fn drift_on_one_sensing_node_is_read_as_that_node_alone() {
    let mut f = fleet3();
    for _ in 0..60 {
        f.round(&|_, _| 0, None);
    }
    assert_eq!(f.causes(), [Cause::Stable; 3]);
    for _ in 0..50 {
        f.round(&|i, j| if i == 1 && j < 2 { 25 } else { 0 }, None);
    }
    assert_eq!(f.causes(), [Cause::Stable, Cause::SensorDrift, Cause::Stable]);
}

#[test]
fn a_change_reaching_every_sensing_node_is_read_as_the_site() {
    let mut f = fleet3();
    for _ in 0..60 {
        f.round(&|_, _| 0, None);
    }
    for _ in 0..50 {
        f.round(&|_, j| if j < 2 { 25 } else { 0 }, None);
    }
    assert_eq!(f.causes(), [Cause::SiteWide; 3]);
}

#[test]
fn a_new_model_on_every_node_with_shifted_embeddings_is_a_model_change() {
    let mut f = fleet3();
    for _ in 0..60 {
        f.round(&|_, _| 0, None);
    }
    for _ in 0..50 {
        f.round(&|_, j| if j < 2 { 25 } else { 0 }, Some("e"));
    }
    assert_eq!(f.causes(), [Cause::ModelChange; 3]);
}

// Cross-sensor coherence over the recorded capture: the accelerometer, the
// gyroscope and the rotation vector are three outputs of one motion.

fn coherence_flags(capture: &str) -> Vec<Flag> {
    let mut session = TextSession::new();
    let mut monitor = CoherenceMonitor::new(CoherenceConfig::default());
    let mut flags = Vec::new();
    for (i, l) in LineSplitter::new().push(capture.as_bytes()).into_iter().enumerate() {
        if let Some(s) = session.feed_line(&l).unwrap() {
            flags.extend(monitor.observe(&s, i as f64 * 0.1));
        }
    }
    flags
}

#[test]
fn the_capture_decoded_at_its_printed_range_is_flagged_for_gravity_and_agrees_on_direction() {
    let flags = coherence_flags(include_str!("fixtures/nicla-standalone-usb.txt"));
    let [Flag::GravityMagnitude { measured_g, scale_to_one_g }] = flags.as_slice() else { panic!("{flags:?}") };
    // About four g at rest, which is what the fixture documents as an open point; the hint is the +/-2 g scale.
    assert!((measured_g - 4.12).abs() < 0.05, "{measured_g}");
    assert!((scale_to_one_g * 8.0 - 1.94).abs() < 0.1, "{scale_to_one_g}");
}

#[test]
fn the_same_capture_at_a_2g_range_raises_nothing() {
    let capture = include_str!("fixtures/nicla-standalone-usb.txt").replace("+/-8g", "+/-2g");
    assert_ne!(capture, include_str!("fixtures/nicla-standalone-usb.txt"));
    assert_eq!(coherence_flags(&capture), vec![]);
}
