//! The leaf link end to end against a simulated leaf: the session, the checks
//! on what the leaf signs, and the frames the small processing node reads.

use furcate_identity::signer::Ed25519Signer;
use furcate_identity::{AssuranceClass, EnrolledUnit, LeafKeyCustody, Lockdown, UnitRoster};
use furcate_leaf_link::report::i2c_unit_fingerprint;
use furcate_leaf_link::session::{HardwareNodeSigner, Hello, NodeGrant, NodeSigner};
use furcate_leaf_link::sim::{exchange, tick, SimLeaf, SimModule};
use furcate_leaf_link::{Action, Bridge, BridgeConfig, ModuleSource, Source};
use furcate_sense::cascade::directory::Directory;
use furcate_sense::cascade::ingest::{Accepted, Frame, Ingest, IngestPolicy, RefusalReason};
use furcate_sense::identity::{enrol, fingerprint_of, ChipIds};
use furcate_sense::leaf::Leaf;
use furcate_sense::nicla::{NodeRole, Transport};
use furcate_sense::relay::{Relay, RelaySource};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;

use std::collections::BTreeMap;
use std::sync::Arc;

const LEAF_SEED: [u8; 32] = [0x21; 32];

struct TestNode(SigningKey);

impl NodeSigner for TestNode {
    fn public_key(&self) -> Result<[u8; 65], String> {
        Ok(self.0.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap())
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn node_signer() -> Arc<TestNode> {
    Arc::new(TestNode(SigningKey::from_slice(&[0x31; 32]).unwrap()))
}

fn grant_for(node: &TestNode) -> NodeGrant {
    let mut g = b"FLG1".to_vec();
    g.extend(node.public_key().unwrap());
    g.push(1);
    g.extend(3u32.to_be_bytes());
    g.extend([0u8; 32]);
    NodeGrant { grant: g, sig: vec![0u8; 70] }
}

const MODULE_ID: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
const MODULE_ADDR: [u8; 6] = [0xc0, 1, 2, 3, 4, 5];

fn module() -> SimModule {
    SimModule { fingerprint: i2c_unit_fingerprint(0x55, "NSM-0042", &MODULE_ID, &MODULE_ADDR), values: vec![(16, 48.0)] }
}

struct Rig {
    bridge: Bridge,
    leaf: SimLeaf,
    ingest: Ingest,
}

struct Opts {
    custody: LeafKeyCustody,
    ceiling: AssuranceClass,
    with_module: bool,
    module_enrolled_serial: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { custody: LeafKeyCustody::ReadableIdentifiers, ceiling: AssuranceClass::Device, with_module: false, module_enrolled_serial: "NSM-0042" }
    }
}

fn rig(o: Opts) -> Rig {
    let mut leaf = SimLeaf::new(LEAF_SEED, 1);
    if o.with_module {
        leaf.module = Some(module());
    }
    // The operator enrols the leaf from what it presented once, and decides to.
    let first = Hello::parse(&leaf.say_hello(0)).unwrap();
    let fp = first.fingerprint();
    let chip_identity = enrol(fp.clone(), "micro-1", b"leaf-link").unwrap();
    let mut roster = UnitRoster::new();
    roster.enrol(EnrolledUnit { unit_id: first.unit_id(), fingerprint: fp, key: Some(first.key()), custody: Some(o.custody.clone()) }).unwrap();
    let chip = RelaySource { identity: chip_identity, transport: Transport::UsbFrame, statement: "Leaf-signed readings, verified at the link.".into() };
    let module_source = if o.with_module {
        let mfp = fingerprint_of(o.module_enrolled_serial, Some(ChipIds { device_id: MODULE_ID, device_addr: MODULE_ADDR })).unwrap();
        let id = enrol(mfp, "module-1", b"leaf-link").unwrap();
        Some(ModuleSource {
            unit_fingerprint: i2c_unit_fingerprint(0x55, o.module_enrolled_serial, &MODULE_ID, &MODULE_ADDR),
            source: RelaySource { identity: id, transport: Transport::Bhy2Binary, statement: "Module behind the leaf, identified not authenticated.".into() },
            channels: BTreeMap::from([(16u8, "hum".to_string()), (17u8, "tmp".to_string())]),
        })
    } else {
        None
    };
    let source = Source { leaf_unit: first.unit_id(), chip, chip_channels: BTreeMap::from([(0u8, "tmp".to_string())]), module: module_source };

    let relay_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let relay = Relay::new("furcate:node:bridge1", Arc::new(Ed25519Signer(Arc::new(relay_key)))).unwrap();
    let node = node_signer();
    let grant = grant_for(&node);

    // What the small processing node holds: the bridge enrolled as the
    // processing node of record for each sensing node behind it.
    let bridge_custody = if o.ceiling >= AssuranceClass::Device { LeafKeyCustody::FuseKey { lockdown: Lockdown::default() } } else { LeafKeyCustody::ReadableIdentifiers };
    let mut dir = Directory::new();
    dir.add_node(&relay.attachment("small", Some(bridge_custody)), NodeRole::MicroProcessing).unwrap();
    dir.bind_sensing(source.chip.identity.node_id.as_str(), relay.node_id()).unwrap();
    if let Some(m) = &source.module {
        dir.bind_sensing(m.source.identity.node_id.as_str(), relay.node_id()).unwrap();
    }
    let ingest = Ingest::new(dir, Arc::new(Leaf::new("furcate:node:small", [3u8; 32])), IngestPolicy::default());

    let bridge = Bridge::new(BridgeConfig {
        signer: node,
        grant,
        roster,
        sources: vec![source],
        relay,
        ceiling: o.ceiling,
        poll_ms: 1_000,
        auth_wait_ms: 20_000,
        reply_wait_ms: 10_000,
    });
    Rig { bridge, leaf, ingest }
}

fn frames(actions: &[Action]) -> Vec<&Frame> {
    actions.iter().filter_map(|a| if let Action::Frame(f) = a { Some(&**f) } else { None }).collect()
}

fn refusals(actions: &[Action]) -> Vec<&str> {
    actions.iter().filter_map(|a| if let Action::Refused(r) = a { Some(r.as_str()) } else { None }).collect()
}

fn connect(r: &mut Rig, n: u32, now: u64) -> Vec<Action> {
    let hello = r.leaf.say_hello(n);
    exchange(&mut r.leaf, &mut r.bridge, hello, now)
}

#[test]
fn a_simulated_leaf_reaches_the_small_node_and_keeps_going() {
    let mut r = rig(Opts::default());
    let a = connect(&mut r, 1, 1_000);
    assert!(a.iter().any(|x| matches!(x, Action::Up { class: AssuranceClass::Soft, .. })), "{a:?}");
    let fs = frames(&a);
    assert_eq!(fs.len(), 1);
    match r.ingest.accept(fs[0], 1_000).expect("the small node accepts the first frame") {
        Accepted::Reading(v) => {
            assert_eq!(v.item.reading.value, 21.5);
            assert!(v.item.reading.sensor_id.ends_with("/tmp"));
            assert_eq!(v.report.effective, AssuranceClass::Soft);
        }
        _ => panic!("expected a reading"),
    }
    // Three more rounds: sequences rise, the witnessed log continues with nothing dropped.
    for i in 1..=3u64 {
        r.leaf.temperature += 0.5;
        let a = tick(&mut r.leaf, &mut r.bridge, 1_000 + i * 1_100);
        let fs = frames(&a);
        assert_eq!(fs.len(), 1, "{a:?}");
        assert!(matches!(r.ingest.accept(fs[0], 1_000 + i * 1_100), Ok(Accepted::Reading(_))));
    }
}

#[test]
fn nothing_is_asked_before_the_poll_interval_and_a_silent_leaf_is_dropped() {
    let mut r = rig(Opts::default());
    connect(&mut r, 1, 1_000);
    assert!(r.bridge.poll(1_500).is_empty());
    // The reply came back at once in the harness, so the next request is due at 2_000.
    assert!(matches!(r.bridge.poll(2_000).as_slice(), [Action::Send(_)]));
    // Unanswered for longer than the reply wait: the session is over.
    let a = r.bridge.poll(2_000 + 10_001);
    assert!(matches!(a.as_slice(), [Action::Down(_)]), "{a:?}");
    assert!(!r.bridge.is_up());
}

#[test]
fn the_class_claimed_is_never_above_what_the_leafs_key_earns() {
    // A bridge on strong hardware, a leaf whose key is only readable identifiers.
    let mut r = rig(Opts { custody: LeafKeyCustody::ReadableIdentifiers, ceiling: AssuranceClass::Device, ..Opts::default() });
    let a = connect(&mut r, 1, 1_000);
    let Frame::Reading { item, .. } = frames(&a)[0] else { panic!() };
    assert_eq!(item.provenance.chain[1].attestation_level, AssuranceClass::Soft);
    // The same leaf with a fused key, behind a bridge whose own key is weak: the lower one.
    let mut r = rig(Opts { custody: LeafKeyCustody::FuseKey { lockdown: Lockdown::default() }, ceiling: AssuranceClass::Soft, ..Opts::default() });
    let a = connect(&mut r, 1, 1_000);
    let Frame::Reading { item, .. } = frames(&a)[0] else { panic!() };
    assert_eq!(item.provenance.chain[1].attestation_level, AssuranceClass::Soft);
    // Both strong: claims Device, and the small node still computes Soft overall because a sensing node holds no secret.
    let mut r = rig(Opts { custody: LeafKeyCustody::FuseKey { lockdown: Lockdown::default() }, ceiling: AssuranceClass::Device, ..Opts::default() });
    let a = connect(&mut r, 1, 1_000);
    let f = frames(&a)[0];
    let Frame::Reading { item, .. } = f else { panic!() };
    assert_eq!(item.provenance.chain[1].attestation_level, AssuranceClass::Device);
    let Ok(Accepted::Reading(v)) = r.ingest.accept(f, 1_000) else { panic!() };
    assert_eq!(v.report.effective, AssuranceClass::Soft);
}

#[test]
fn a_leaf_that_is_not_enrolled_is_not_answered() {
    let mut r = rig(Opts::default());
    let mut stranger = SimLeaf::new([0x55; 32], 1);
    let h = stranger.say_hello(1);
    let a = exchange(&mut stranger, &mut r.bridge, h, 1_000);
    assert!(frames(&a).is_empty());
    assert!(refusals(&a)[0].contains("not enrolled"), "{a:?}");
    assert!(!r.bridge.is_up());
}

#[test]
fn the_same_identifiers_with_another_key_are_refused() {
    let mut r = rig(Opts::default());
    // A copy that repeats the chip's readable values but cannot hold its key.
    let mut clone = SimLeaf::new([0x66; 32], 1);
    let h = clone.say_hello(1);
    let a = exchange(&mut clone, &mut r.bridge, h, 1_000);
    assert!(frames(&a).is_empty());
    assert!(refusals(&a).iter().any(|s| s.contains("not enrolled")), "{a:?}");
}

#[test]
fn a_swapped_chip_is_refused_by_its_enrolment() {
    let mut r = rig(Opts::default());
    r.leaf.mac = [0, 0, 0, 0, 0, 1];
    let a = connect(&mut r, 1, 1_000);
    assert!(frames(&a).is_empty());
    assert!(refusals(&a).iter().any(|s| s.contains("Replaced")), "{a:?}");
}

#[test]
fn a_changed_value_does_not_verify_and_uses_up_no_sequence() {
    let mut r = rig(Opts::default());
    r.leaf.tamper = Some(|plain| {
        // Flip a bit of the reported value (21.5 as f32 big endian).
        let at = plain.windows(4).position(|w| w == 21.5f32.to_bits().to_be_bytes()).expect("the value is in the reply");
        plain[at + 1] ^= 0x01;
    });
    let a = connect(&mut r, 1, 1_000);
    assert!(frames(&a).is_empty());
    assert!(refusals(&a).iter().any(|s| s.contains("not signed by the leaf")), "{a:?}");
    // The honest reading that follows is still accepted: the forged one took no sequence number.
    r.leaf.tamper = None;
    let a = tick(&mut r.leaf, &mut r.bridge, 2_200);
    assert_eq!(frames(&a).len(), 1, "{a:?}");
}

#[test]
fn a_replayed_sealed_record_ends_the_session() {
    let mut r = rig(Opts::default());
    let hello = r.leaf.say_hello(1);
    let start = r.bridge.handle(&hello, 1_000);
    // Pump by hand so the leaf's sealed reply can be kept.
    let Action::Send(auth) = &start[0] else { panic!() };
    let finish = r.leaf.on_message(auth).unwrap().remove(0);
    let up = r.bridge.handle(&finish, 1_000);
    let Action::Send(req) = &up[1] else { panic!() };
    let reply = r.leaf.on_message(req).unwrap().remove(0);
    assert_eq!(frames(&r.bridge.handle(&reply, 1_000)).len(), 1);
    // The same record again.
    let again = r.bridge.handle(&reply, 1_001);
    assert!(matches!(again.as_slice(), [Action::Down(_)]), "{again:?}");
    assert!(!r.bridge.is_up());
}

#[test]
fn a_restarted_leaf_is_a_new_generation_and_a_rolled_back_one_is_refused() {
    let mut r = rig(Opts::default());
    assert_eq!(frames(&connect(&mut r, 1, 1_000)).len(), 1);
    // Reboot: the leaf's counter restarts and its generation goes up.
    r.leaf = {
        let mut l = SimLeaf::new(LEAF_SEED, 2);
        l.temperature = 22.0;
        l
    };
    assert_eq!(frames(&connect(&mut r, 2, 5_000)).len(), 1);
    // The old attachment generation presented again is stale, however well it is signed.
    r.leaf = SimLeaf::new(LEAF_SEED, 1);
    let a = connect(&mut r, 3, 9_000);
    assert!(frames(&a).is_empty());
    assert!(refusals(&a).iter().any(|s| s.contains("older than")), "{a:?}");
}

#[test]
fn a_hello_that_crosses_our_auth_is_ignored_until_the_window_runs_out() {
    let mut r = rig(Opts::default());
    let h1 = r.leaf.say_hello(1);
    assert!(matches!(r.bridge.handle(&h1, 1_000).as_slice(), [Action::Send(_)]));
    let h2 = r.leaf.say_hello(2);
    assert!(r.bridge.handle(&h2, 5_000).is_empty());
    // The leaf has given up on the first AUTH by now: a new HELLO is a new attempt.
    let h3 = r.leaf.say_hello(3);
    assert!(matches!(r.bridge.handle(&h3, 25_000).as_slice(), [Action::Send(_)]));
    // And a handshake nobody finishes is dropped.
    let a = r.bridge.poll(25_000 + 20_001);
    assert!(matches!(a.as_slice(), [Action::Down(_)]));
}

#[test]
fn a_module_behind_the_leaf_is_identified_and_its_readings_flow() {
    let mut r = rig(Opts { with_module: true, ..Opts::default() });
    let a = connect(&mut r, 1, 1_000);
    let fs = frames(&a);
    assert_eq!(fs.len(), 2, "{a:?}");
    for f in &fs {
        assert!(matches!(r.ingest.accept(f, 1_000), Ok(Accepted::Reading(_))));
    }
    let Frame::Reading { item, .. } = fs[1] else { panic!() };
    assert!(item.reading.sensor_id.ends_with("/hum"));
    assert_eq!(item.reading.value, 48.0);
    // The two sensing nodes are different identities.
    let Frame::Reading { item: chip, .. } = fs[0] else { panic!() };
    assert_ne!(chip.reading.leaf_id, item.reading.leaf_id);
}

#[test]
fn a_module_that_is_not_the_one_enrolled_is_not_trusted_but_the_chip_still_reads() {
    let mut r = rig(Opts { with_module: true, module_enrolled_serial: "NSM-9999", ..Opts::default() });
    let a = connect(&mut r, 1, 1_000);
    assert_eq!(frames(&a).len(), 1, "{a:?}");
    assert!(refusals(&a).iter().any(|s| s.contains("not enrolled")), "{a:?}");
    assert!(refusals(&a).iter().any(|s| s.contains("no verified module record")), "{a:?}");
}

#[test]
fn a_module_reading_outside_the_signed_range_is_not_moved_onto_the_module() {
    let mut r = rig(Opts { with_module: true, ..Opts::default() });
    r.leaf.module.as_mut().unwrap().values = vec![(16, 48.0), (17, 21.0)];
    // The unit record covers only the first of the module's two readings.
    r.leaf.unit_last_override = Some(2);
    let a = connect(&mut r, 1, 1_000);
    // The chip's reading is sequence 1, the module's are 2 and 3.
    assert_eq!(frames(&a).len(), 2, "{a:?}");
    assert!(refusals(&a).iter().any(|s| s.contains("sensor 17") && s.contains("no verified module record")), "{a:?}");
}

#[test]
fn a_module_the_chain_does_not_list_is_not_trusted() {
    let mut r = rig(Opts { with_module: true, ..Opts::default() });
    r.leaf.omit_module_chain = true;
    let a = connect(&mut r, 1, 1_000);
    assert_eq!(frames(&a).len(), 1, "{a:?}");
    assert!(refusals(&a).iter().any(|s| s.contains("does not list the module")), "{a:?}");
}

#[test]
fn a_module_report_with_no_module_enrolled_behind_the_leaf_is_refused() {
    let mut r = rig(Opts::default());
    r.leaf.module = Some(module());
    let a = connect(&mut r, 1, 1_000);
    assert_eq!(frames(&a).len(), 1, "{a:?}");
    assert!(refusals(&a).iter().any(|s| s.contains("none is enrolled")), "{a:?}");
}

#[test]
fn a_grant_for_another_node_key_is_not_used() {
    let mut r = rig(Opts::default());
    // A bridge whose signer is not the key the grant names.
    let other = Arc::new(TestNode(SigningKey::from_slice(&[0x32; 32]).unwrap()));
    let g = grant_for(&node_signer());
    let cfg_roster = {
        let mut ro = UnitRoster::new();
        let first = Hello::parse(&r.leaf.say_hello(0)).unwrap();
        ro.enrol(EnrolledUnit { unit_id: first.unit_id(), fingerprint: first.fingerprint(), key: Some(first.key()), custody: Some(LeafKeyCustody::ReadableIdentifiers) }).unwrap();
        ro
    };
    let first = Hello::parse(&r.leaf.say_hello(0)).unwrap();
    let id = enrol(first.fingerprint(), "x", b"n").unwrap();
    let relay = Relay::new("furcate:node:b", Arc::new(Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]))))).unwrap();
    let mut b = Bridge::new(BridgeConfig {
        signer: other,
        grant: g,
        roster: cfg_roster,
        sources: vec![Source {
            leaf_unit: first.unit_id(),
            chip: RelaySource { identity: id, transport: Transport::UsbFrame, statement: String::new() },
            chip_channels: BTreeMap::new(),
            module: None,
        }],
        relay,
        ceiling: AssuranceClass::Soft,
        poll_ms: 1,
        auth_wait_ms: 1,
        reply_wait_ms: 1,
    });
    let h = r.leaf.say_hello(1);
    let a = b.handle(&h, 0);
    assert!(refusals(&a)[0].contains("grant is for another node key"), "{a:?}");
}

#[test]
fn a_frame_altered_after_the_bridge_signed_it_is_refused_by_the_small_node() {
    let mut r = rig(Opts::default());
    let a = connect(&mut r, 1, 1_000);
    let mut f = frames(&a)[0].clone();
    if let Frame::Reading { item, .. } = &mut f {
        item.reading.value = 99.0;
    }
    let err = r.ingest.accept(&f, 1_000).err().expect("refused");
    assert!(err.code == RefusalReason::BadEnvelopeSignature.code() || err.code == RefusalReason::BadReadingSignature.code(), "{}", err.code);
}

#[test]
fn the_hardware_signer_adapter_signs_der_the_leaf_can_check() {
    // The adapter over a MessageSigner is what runs on a host with a broker or
    // a TPM; here the signer is a P-256 key in memory behind the same trait.
    struct P256Msg(SigningKey);
    impl furcate_identity::MessageSigner for P256Msg {
        fn public_key(&self) -> anyhow::Result<furcate_identity::signer::SignerKey> {
            Ok(furcate_identity::signer::SignerKey::P256(self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()))
        }
        fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
            let sig: p256::ecdsa::Signature = self.0.sign(message);
            // A broker answers r || s.
            Ok(sig.to_bytes().to_vec())
        }
    }
    let hw = HardwareNodeSigner::new(Arc::new(P256Msg(SigningKey::from_slice(&[0x31; 32]).unwrap()))).unwrap();
    assert_eq!(hw.public_key().unwrap(), node_signer().public_key().unwrap());
    let der = hw.sign_der(b"FL1 node auth x").unwrap();
    assert_eq!(der[0], 0x30);
    let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
    use p256::ecdsa::signature::Verifier;
    assert!(SigningKey::from_slice(&[0x31; 32]).unwrap().verifying_key().verify(b"FL1 node auth x", &sig).is_ok());
    // A node whose key is not P-256 cannot be a leaf's node.
    let ed = Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])));
    assert!(HardwareNodeSigner::new(Arc::new(ed)).is_err());
}

#[test]
fn over_a_real_socket_the_leaf_dials_in_and_frames_come_out() {
    use furcate_leaf_link::serve::{run, TcpListen};
    use furcate_leaf_link::wire::{encode_line, Line, LineDecoder};
    use std::io::{Read, Write};

    let Rig { mut bridge, mut leaf, mut ingest } = rig(Opts::default());
    let mut link = TcpListen::bind("127.0.0.1:0").unwrap();
    let addr = link.local_addr().unwrap();
    let leaf_thread = std::thread::spawn(move || {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_millis(100))).unwrap();
        // The leaf prints its log on the same stream, then says HELLO.
        s.write_all(b"I (100) fl-link: waiting for a node\n").unwrap();
        s.write_all(&encode_line(&leaf.say_hello(1))).unwrap();
        let (mut dec, mut buf) = (LineDecoder::new(), [0u8; 4096]);
        let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < end {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    for l in dec.push(&buf[..n]) {
                        if let Line::Frame(m) = l {
                            for reply in leaf.on_message(&m).unwrap_or_default() {
                                s.write_all(&encode_line(&reply)).unwrap();
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });
    let started = std::time::Instant::now();
    let mut frames: Vec<Frame> = Vec::new();
    let mut log: Vec<String> = Vec::new();
    let tally = run(&mut bridge, &mut link, &mut |f| { frames.push(f.clone()); Ok(()) }, &mut |l| log.push(l.to_string()), &mut |t| {
        assert!(started.elapsed() < std::time::Duration::from_secs(30), "no frames within 30 s");
        t.frames >= 2
    })
    .unwrap();
    drop(link);
    leaf_thread.join().unwrap();
    assert!(tally.frames >= 2 && tally.sessions == 1, "{tally:?} {log:?}");
    assert!(log.iter().any(|l| l.contains("fl-link: waiting for a node")), "the leaf's own log passes through: {log:?}");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    for f in &frames {
        assert!(matches!(ingest.accept(f, now), Ok(Accepted::Reading(_))));
    }
}
