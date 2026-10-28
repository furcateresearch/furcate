//! A simulated leaf, for tests and for checking an installation without a
//! board.
//!
//! It speaks the leaf's half of the session exactly as the firmware does
//! (`fl_link.c`, `fl_sensors.c`) and signs with a key the caller gives it, so
//! it proves the host side against the format and says nothing about a real
//! board. A real board's key never leaves it.

use crate::bridge::{Action, Bridge};
use crate::report::{unit_digest, UnitRecord};
use crate::session::{PUB_LEN, SIG_LEN};
use crate::wire::{self, msg, tag, Builder};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use furcate_leaf_core::{LeafState, Sample};
use hkdf::Hkdf;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::SecretKey;
use sha2::{Digest, Sha256};

/// A sensing module the simulated leaf reads. It holds no key: the leaf names
/// it by `fingerprint` and signs for it.
#[derive(Clone)]
pub struct SimModule {
    pub fingerprint: [u8; 16],
    /// `(sensor index, value)` for each reading the module gives.
    pub values: Vec<(u8, f32)>,
}

pub struct SimLeaf {
    sk: SigningKey,
    eph: SecretKey,
    pub public: [u8; PUB_LEN],
    pub generation: u16,
    seq: u32,
    pub model: [u8; 32],
    /// Chip silicon values reported in the evidence.
    pub mac: [u8; 6],
    pub uid: [u8; 8],
    pub revision: u16,
    pub temperature: f32,
    pub module: Option<SimModule>,
    /// Sign a unit record that stops short of the module's last reading.
    pub unit_last_override: Option<u32>,
    /// Leave the module out of the chain.
    pub omit_module_chain: bool,
    /// Applied to the plain SENSE content before it is sealed.
    pub tamper: Option<fn(&mut Vec<u8>)>,
    hello: Vec<u8>,
    th: [u8; 32],
    k_tx: [u8; 32],
    k_rx: [u8; 32],
    c_tx: u64,
    c_rx: u64,
    up: bool,
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn derive(th: &[u8; 32], shared: &[u8], info: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    Hkdf::<Sha256>::new(Some(th), shared).expand(info, &mut o).expect("32 bytes");
    o
}

fn nonce(dir: u8, c: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = dir;
    n[4..].copy_from_slice(&c.to_be_bytes());
    n
}

impl SimLeaf {
    /// `seed` makes the identity key; the ephemeral key is derived from it and
    /// a counter, so a run is repeatable.
    pub fn new(seed: [u8; 32], generation: u16) -> Self {
        let sk = SigningKey::from_slice(&seed).expect("a seed that is a valid P-256 scalar");
        let public: [u8; PUB_LEN] = VerifyingKey::from(&sk).to_sec1_point(false).as_bytes().try_into().expect("65 bytes");
        let eph_seed = sha(&[b"sim eph", &seed]);
        Self {
            sk,
            eph: SecretKey::from_slice(&eph_seed).expect("valid scalar"),
            public,
            generation,
            seq: 0,
            model: [0; 32],
            mac: [0x44, 0xb1, 0x76, 0xb0, 0x57, 0x24],
            uid: [1, 2, 3, 4, 5, 6, 7, 8],
            revision: 2,
            temperature: 21.5,
            module: None,
            unit_last_override: None,
            omit_module_chain: false,
            tamper: None,
            hello: Vec::new(),
            th: [0; 32],
            k_tx: [0; 32],
            k_rx: [0; 32],
            c_tx: 0,
            c_rx: 0,
            up: false,
        }
    }

    pub fn leaf_id(&self) -> [u8; 32] {
        Sha256::digest(self.public).into()
    }

    /// A fresh HELLO. Each carries a new ephemeral key, as the firmware's do.
    pub fn say_hello(&mut self, n: u32) -> Vec<u8> {
        self.eph = SecretKey::from_slice(&sha(&[b"sim eph", &self.sk.to_bytes(), &n.to_be_bytes()])).expect("valid scalar");
        self.up = false;
        let evidence = Builder::new(0)
            .field(1, &self.mac)
            .field(2, &self.revision.to_be_bytes())
            .field(4, b"silicon-id/development")
            .field(20, &self.uid)
            .field(21, b"esp32s3")
            .field(22, &[0])
            .build()
            .expect("small");
        let eph_pub = self.eph.public_key().to_sec1_point(false);
        let m = Builder::new(msg::HELLO)
            .field(1, &[1])
            .field(tag::DEV_PUB, &self.public)
            .field(tag::EPH, eph_pub.as_bytes())
            .field(tag::NONCE, &sha(&[b"sim nonce", &n.to_be_bytes()]))
            .field(tag::EVIDENCE, &evidence[1..])
            .build()
            .expect("small");
        self.hello = m.clone();
        m
    }

    /// The leaf's answer to each message the node sends.
    pub fn on_message(&mut self, m: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        match m.first() {
            Some(&msg::AUTH) => self.on_auth(m).map(|f| vec![f]),
            Some(&msg::SEALED) => self.on_sealed(m).map(|r| r.into_iter().collect()),
            other => Err(format!("the leaf does not take {other:?}")),
        }
    }

    fn on_auth(&mut self, m: &[u8]) -> Result<Vec<u8>, String> {
        let (_, f) = wire::split(m).map_err(|e| e.to_string())?;
        let get = |t: u8| f.get(t).ok_or_else(|| format!("AUTH has no tag {t}"));
        let (node_pub, node_eph, grant, node_sig) = (get(tag::NODE_PUB)?, get(tag::EPH)?, get(tag::GRANT)?, get(tag::NODE_SIG)?);
        self.th = sha(&[b"FL1 transcript", &self.hello, node_pub, node_eph, grant]);
        let digest = sha(&[b"FL1 node auth ", &self.th]);
        let key = VerifyingKey::from_sec1_bytes(node_pub).map_err(|e| e.to_string())?;
        let sig = Signature::from_der(node_sig).map_err(|e| e.to_string())?;
        key.verify_prehash(&digest, &sig).map_err(|_| "node signature does not verify".to_string())?;
        let peer = p256::PublicKey::from_sec1_bytes(node_eph).map_err(|e| e.to_string())?;
        let shared = p256::ecdh::diffie_hellman(self.eph.to_nonzero_scalar(), peer.as_affine());
        self.k_tx = derive(&self.th, shared.raw_secret_bytes(), b"FL1 leaf to node");
        self.k_rx = derive(&self.th, shared.raw_secret_bytes(), b"FL1 node to leaf");
        let covered = &node_sig[..node_sig.len().min(72)];
        let lh = sha(&[b"FL1 leaf auth ", &self.th, covered]);
        let dev_sig: Signature = self.sk.sign_prehash(&lh).map_err(|e| e.to_string())?;
        self.c_tx = 0;
        self.c_rx = 0;
        self.up = true;
        Builder::new(msg::FINISH).field(tag::DEV_SIG, &dev_sig.to_bytes()).build().map_err(|e| e.to_string())
    }

    fn on_sealed(&mut self, m: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if !self.up {
            return Err("no session".into());
        }
        let (_, f) = wire::split(m).map_err(|e| e.to_string())?;
        let boxed = f.get(tag::BOX).ok_or("no box")?;
        let cipher = Aes256Gcm::new_from_slice(&self.k_rx).map_err(|e| e.to_string())?;
        let plain = cipher.decrypt(Nonce::from_slice(&nonce(b'N', self.c_rx)), boxed).map_err(|_| "does not open".to_string())?;
        self.c_rx += 1;
        if plain.first() != Some(&msg::SENSE_REQ) {
            return Ok(None);
        }
        let mut reply = self.sense();
        if let Some(t) = self.tamper {
            t(&mut reply);
        }
        let cipher = Aes256Gcm::new_from_slice(&self.k_tx).map_err(|e| e.to_string())?;
        let boxed = cipher.encrypt(Nonce::from_slice(&nonce(b'L', self.c_tx)), reply.as_slice()).map_err(|_| "seal".to_string())?;
        let out = Builder::new(msg::SEALED)
            .field(tag::COUNTER, &(self.c_tx as u32).to_be_bytes())
            .field(tag::BOX, &boxed)
            .build()
            .map_err(|e| e.to_string())?;
        self.c_tx += 1;
        Ok(Some(out))
    }

    fn reading(&mut self, sensor: u8, value: f32) -> Vec<u8> {
        self.seq += 1;
        let id = self.leaf_id();
        let device: [u8; 8] = id[..8].try_into().expect("8");
        let digest = LeafState::new(0, self.generation).bound_payload(&device, &Sample { sensor, value, seq: self.seq }, &self.model);
        let sig: Signature = self.sk.sign_prehash(&digest).expect("signs");
        let mut r = vec![sensor];
        r.extend(value.to_bits().to_be_bytes());
        r.extend(self.seq.to_be_bytes());
        r.extend(sig.to_bytes());
        debug_assert_eq!(r.len(), 1 + 4 + 4 + SIG_LEN);
        r
    }

    /// The plain content of a SENSE reply, laid out as `fl_sensors_read` does.
    pub fn sense(&mut self) -> Vec<u8> {
        let id = self.leaf_id();
        let mut chain = id[..16].to_vec();
        chain.extend(b"micro-processing");
        let mut b = Builder::new(msg::SENSE)
            .field(tag::GENERATION, &self.generation.to_be_bytes())
            .field(tag::MODEL_SHA, &self.model)
            .field(tag::SIGNER_ID, &id[..16])
            .field(tag::CHAIN, &chain);
        let t = self.temperature;
        b = b.field(tag::READING, &self.reading(0, t));
        if let Some(m) = self.module.clone() {
            // As fl_sensors.c does: the module's readings first, then its entry
            // in the chain as a sensing signer, then the signed unit record
            // over the sequence range just issued.
            let (mut first, mut last) = (0u32, 0u32);
            for (idx, v) in m.values {
                let r = self.reading(idx, v);
                if first == 0 {
                    first = self.seq;
                }
                last = self.seq;
                b = b.field(tag::READING, &r);
            }
            if !self.omit_module_chain {
                let mut entry = m.fingerprint.to_vec();
                entry.extend(b"sensing");
                b = b.field(tag::CHAIN, &entry);
            }
            let last = self.unit_last_override.unwrap_or(last);
            let mut rec = UnitRecord { fingerprint: m.fingerprint, first_seq: first, last_seq: last, signature: [0; SIG_LEN] };
            let sig: Signature = self.sk.sign_prehash(&unit_digest(&id, self.generation, &rec)).expect("signs");
            rec.signature.copy_from_slice(&sig.to_bytes());
            let mut raw = rec.fingerprint.to_vec();
            raw.extend(rec.first_seq.to_be_bytes());
            raw.extend(rec.last_seq.to_be_bytes());
            raw.extend(rec.signature);
            b = b.field(tag::UNIT, &raw);
        }
        b.build().expect("small")
    }
}

/// Carries the bridge's pending actions to the leaf and the leaf's replies back
/// until neither has anything more to say. Returns what the bridge did that is
/// not a message to the leaf.
pub fn pump(leaf: &mut SimLeaf, bridge: &mut Bridge, start: Vec<Action>, now_ms: u64) -> Vec<Action> {
    let (mut all, mut todo) = (Vec::new(), start);
    while !todo.is_empty() {
        let mut next = Vec::new();
        for a in todo {
            match a {
                Action::Send(out) => {
                    if let Ok(replies) = leaf.on_message(&out) {
                        for r in replies {
                            next.extend(bridge.handle(&r, now_ms));
                        }
                    }
                }
                other => all.push(other),
            }
        }
        todo = next;
    }
    all
}

/// Hands the bridge one message from the leaf and pumps the rest.
pub fn exchange(leaf: &mut SimLeaf, bridge: &mut Bridge, first: Vec<u8>, now_ms: u64) -> Vec<Action> {
    let start = bridge.handle(&first, now_ms);
    pump(leaf, bridge, start, now_ms)
}

/// Lets time pass for the bridge and pumps what it then sends.
pub fn tick(leaf: &mut SimLeaf, bridge: &mut Bridge, now_ms: u64) -> Vec<Action> {
    let start = bridge.poll(now_ms);
    pump(leaf, bridge, start, now_ms)
}
