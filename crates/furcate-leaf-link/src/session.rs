//! The node's half of a leaf session.
//!
//! The leaf always initiates. It sends HELLO (its public key, an ephemeral
//! key, a nonce and its evidence); the node answers with AUTH (its key, an
//! ephemeral key, the operator's grant for that key, and its signature over
//! the transcript); the leaf checks all of it and sends FINISH carrying its
//! own signature over the same transcript. From then on every message is a
//! SEALED record: AES-256-GCM, a key per direction from HKDF over the ECDH
//! secret with the transcript hash as salt, and a counter nonce.
//!
//! This follows the leaf firmware's `fl_link.c` and the reference host in
//! `host/fl_proto.py`; the vectors in the tests are the byte layouts both
//! read.

use crate::wire::{self, msg, tag, Builder, Fields, WireError};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use furcate_identity::backends::fingerprint::{Characteristic, Fingerprint};
use furcate_identity::MessageSigner;
use furcate_policy::delegation::CellKey;
use hkdf::Hkdf;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const PUB_LEN: usize = 65;
pub const SIG_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum LinkError {
    Wire(WireError),
    Missing(&'static str),
    BadKey(&'static str),
    /// The leaf refused, with its reason.
    Refused(String),
    /// The leaf's signature over the handshake does not verify.
    BadLeafSignature,
    Signer(String),
    /// A sealed record that does not open.
    Open,
    /// A sealed record out of order: replayed, dropped or reordered.
    Counter { expected: u64, found: u64 },
    Unexpected(u8),
    /// The grant is not for the key this node signs with.
    GrantNotForThisNode,
    Random,
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use LinkError::*;
        match self {
            Wire(e) => write!(f, "{e}"),
            Missing(w) => write!(f, "the message has no {w}"),
            BadKey(w) => write!(f, "{w} is not a valid P-256 public key"),
            Refused(r) => write!(f, "the leaf refused: {r}"),
            BadLeafSignature => write!(f, "the leaf's signature over the handshake does not verify"),
            Signer(e) => write!(f, "the node's signer failed: {e}"),
            Open => write!(f, "a sealed record did not open"),
            Counter { expected, found } => write!(f, "sealed record {found} where {expected} was due"),
            Unexpected(t) => write!(f, "unexpected message type 0x{t:02x}"),
            GrantNotForThisNode => write!(f, "the grant is for another node key than the signer's"),
            Random => write!(f, "no randomness for the ephemeral key"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<WireError> for LinkError {
    fn from(e: WireError) -> Self {
        LinkError::Wire(e)
    }
}

/// The node's signing key. P-256, signing SHA-256 of the message, answering in
/// DER, which is what the leaf checks.
pub trait NodeSigner {
    fn public_key(&self) -> Result<[u8; PUB_LEN], String>;
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

/// A [`MessageSigner`] (the machine's firmware-held key through its broker, a
/// TPM key) as the node's signer. The key never leaves the hardware; what
/// comes back is checked against the key before it is sent.
pub struct HardwareNodeSigner {
    signer: Arc<dyn MessageSigner>,
    key: CellKey,
    public: [u8; PUB_LEN],
}

impl HardwareNodeSigner {
    pub fn new(signer: Arc<dyn MessageSigner>) -> Result<Self, String> {
        let key = CellKey::of(&*signer)?;
        let id = key.id();
        let hex_key = id.strip_prefix("p256:").ok_or_else(|| format!("a leaf link needs an ECDSA P-256 node key; this one is {id}"))?;
        let bytes = hex::decode(hex_key).map_err(|e| format!("the node key is not hex: {e}"))?;
        let pk = PublicKey::from_sec1_bytes(&bytes).map_err(|_| "the node key is not a P-256 point".to_string())?;
        let point = pk.to_sec1_point(false);
        let public: [u8; PUB_LEN] = point.as_bytes().try_into().map_err(|_| "the node key does not encode in 65 bytes".to_string())?;
        Ok(Self { signer, key, public })
    }
}

impl NodeSigner for HardwareNodeSigner {
    fn public_key(&self) -> Result<[u8; PUB_LEN], String> {
        Ok(self.public)
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let raw = self.signer.sign(message).map_err(|e| format!("{e:#}"))?;
        self.key.verify(message, &raw).map_err(|e| format!("the signer did not sign as {}: {e}", self.key.id()))?;
        if raw.len() == SIG_LEN {
            let sig = Signature::from_slice(&raw).map_err(|e| e.to_string())?;
            Ok(sig.to_der().as_bytes().to_vec())
        } else {
            Ok(raw)
        }
    }
}

/// The operator's grant for a node key, and the operator's signature over it.
/// The leaf checks the signature against the operator keys it was provisioned
/// with; this side only carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeGrant {
    pub grant: Vec<u8>,
    pub sig: Vec<u8>,
}

impl NodeGrant {
    /// `"FLG1" | node key (65) | roles (1) | generation (4 BE) | leaf id (32)`.
    pub const LEN: usize = 4 + PUB_LEN + 1 + 4 + 32;

    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let field = |k: &str| -> Result<Vec<u8>, String> {
            hex::decode(v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("the grant file has no `{k}`"))?)
                .map_err(|e| format!("`{k}` is not hex: {e}"))
        };
        let g = Self { grant: field("grant")?, sig: field("sig")? };
        if g.grant.len() != Self::LEN || &g.grant[..4] != b"FLG1" {
            return Err("the grant is not a version 1 grant".into());
        }
        Ok(g)
    }

    pub fn node_key(&self) -> &[u8] {
        &self.grant[4..4 + PUB_LEN]
    }

    pub fn roles(&self) -> u8 {
        self.grant[4 + PUB_LEN]
    }
}

/// What a leaf says in HELLO.
#[derive(Clone, Debug)]
pub struct Hello {
    /// The whole message: the transcript covers it as sent.
    pub raw: Vec<u8>,
    pub dev_pub: [u8; PUB_LEN],
    pub eph: [u8; PUB_LEN],
    pub evidence: Fields,
}

fn point(b: Option<&[u8]>, what: &'static str) -> Result<[u8; PUB_LEN], LinkError> {
    let b = b.ok_or(LinkError::Missing(what))?;
    let arr: [u8; PUB_LEN] = b.try_into().map_err(|_| LinkError::BadKey(what))?;
    PublicKey::from_sec1_bytes(&arr).map_err(|_| LinkError::BadKey(what))?;
    Ok(arr)
}

impl Hello {
    pub fn parse(raw: &[u8]) -> Result<Hello, LinkError> {
        let (kind, f) = wire::split(raw)?;
        if kind != msg::HELLO {
            return Err(LinkError::Unexpected(kind));
        }
        let evidence = Fields::parse(f.get(tag::EVIDENCE).ok_or(LinkError::Missing("evidence"))?)?;
        Ok(Hello {
            raw: raw.to_vec(),
            dev_pub: point(f.get(tag::DEV_PUB), "the leaf key")?,
            eph: point(f.get(tag::EPH), "the leaf's ephemeral key")?,
            evidence,
        })
    }

    /// SHA-256 of the leaf's public key: the leaf's id.
    pub fn leaf_id(&self) -> [u8; 32] {
        Sha256::digest(self.dev_pub).into()
    }

    /// The id the roster knows the leaf by.
    pub fn unit_id(&self) -> String {
        hex::encode(self.leaf_id())
    }

    /// The key as the roster writes it.
    pub fn key(&self) -> String {
        format!("p256:{}", hex::encode(self.dev_pub))
    }

    /// The silicon values the leaf reports, as the characteristics the roster
    /// compares: the MAC (tag 1), the unique ID (tag 20) and the chip
    /// revision (tag 2). The assurance label the leaf prints (tag 4) is its own
    /// statement and is not read into the fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        let h = |t: u8| self.evidence.get(t).map(hex::encode).unwrap_or_default();
        Fingerprint::default()
            .with(Characteristic::MacAddress, h(1))
            .with(Characteristic::Otp, h(20))
            .with(Characteristic::BoardRevision, h(2))
    }
}

/// The ephemeral key for one handshake.
pub fn ephemeral() -> Result<SecretKey, LinkError> {
    for _ in 0..8 {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).map_err(|_| LinkError::Random)?;
        if let Ok(k) = SecretKey::from_slice(&b) {
            return Ok(k);
        }
    }
    Err(LinkError::Random)
}

fn lp(prefix: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn derive(salt: &[u8; 32], shared: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // 32 bytes is far below the HKDF-SHA256 limit, so expand cannot fail.
    Hkdf::<Sha256>::new(Some(salt), shared).expand(info, &mut out).expect("32 bytes is a valid HKDF length");
    out
}

/// A handshake waiting for the leaf's FINISH.
pub struct Pending {
    th: [u8; 32],
    node_sig: Vec<u8>,
    leaf_pub: [u8; PUB_LEN],
    k_tx: [u8; 32],
    k_rx: [u8; 32],
}

/// Answers a HELLO: returns the AUTH message and the state that waits for FINISH.
pub fn answer(hello: &Hello, signer: &dyn NodeSigner, grant: &NodeGrant, eph: &SecretKey) -> Result<(Pending, Vec<u8>), LinkError> {
    let node_pub = signer.public_key().map_err(LinkError::Signer)?;
    if grant.node_key() != node_pub {
        return Err(LinkError::GrantNotForThisNode);
    }
    let eph_pub_point = eph.public_key().to_sec1_point(false);
    let eph_pub = eph_pub_point.as_bytes();
    let th = lp(b"FL1 transcript", &[&hello.raw, &node_pub, eph_pub, &grant.grant]);
    let node_sig = signer.sign_der(&[b"FL1 node auth ".as_slice(), &th].concat()).map_err(LinkError::Signer)?;
    let leaf_eph = PublicKey::from_sec1_bytes(&hello.eph).map_err(|_| LinkError::BadKey("the leaf's ephemeral key"))?;
    let shared = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), leaf_eph.as_affine());
    let shared = shared.raw_secret_bytes();
    let auth = Builder::new(msg::AUTH)
        .field(tag::NODE_PUB, &node_pub)
        .field(tag::EPH, eph_pub)
        .field(tag::GRANT, &grant.grant)
        .field(tag::GRANT_SIG, &grant.sig)
        .field(tag::NODE_SIG, &node_sig)
        .build()?;
    let pending = Pending {
        th,
        node_sig,
        leaf_pub: hello.dev_pub,
        // The leaf's `k_tx` is "leaf to node": this side's receive key.
        k_rx: derive(&th, shared, b"FL1 leaf to node"),
        k_tx: derive(&th, shared, b"FL1 node to leaf"),
    };
    Ok((pending, auth))
}

impl Pending {
    /// Checks the leaf's FINISH. A REFUSE here carries the leaf's reason.
    pub fn finish(self, message: &[u8]) -> Result<Session, LinkError> {
        let (kind, f) = wire::split(message)?;
        match kind {
            msg::REFUSE => {
                return Err(LinkError::Refused(f.get(tag::REASON).map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default()))
            }
            msg::FINISH => {}
            other => return Err(LinkError::Unexpected(other)),
        }
        let sig = f.get(tag::DEV_SIG).ok_or(LinkError::Missing("the leaf signature"))?;
        let sig = Signature::from_slice(sig).map_err(|_| LinkError::BadLeafSignature)?;
        let covered = &self.node_sig[..self.node_sig.len().min(72)];
        let digest = lp(b"FL1 leaf auth ", &[&self.th, covered]);
        let key = VerifyingKey::from_sec1_bytes(&self.leaf_pub).map_err(|_| LinkError::BadKey("the leaf key"))?;
        key.verify_prehash(&digest, &sig).map_err(|_| LinkError::BadLeafSignature)?;
        Ok(Session { k_tx: self.k_tx, k_rx: self.k_rx, c_tx: 0, c_rx: 0, leaf_pub: self.leaf_pub })
    }
}

/// An authenticated session.
pub struct Session {
    k_tx: [u8; 32],
    k_rx: [u8; 32],
    c_tx: u64,
    c_rx: u64,
    pub leaf_pub: [u8; PUB_LEN],
}

fn nonce(direction: u8, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = direction;
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

impl Session {
    /// Seals `plain` (a whole message) as a SEALED record.
    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>, LinkError> {
        let cipher = Aes256Gcm::new_from_slice(&self.k_tx).map_err(|_| LinkError::Open)?;
        let boxed = cipher.encrypt(Nonce::from_slice(&nonce(b'N', self.c_tx)), plain).map_err(|_| LinkError::Open)?;
        let counter = u32::try_from(self.c_tx).map_err(|_| LinkError::Open)?.to_be_bytes();
        let m = Builder::new(msg::SEALED).field(tag::COUNTER, &counter).field(tag::BOX, &boxed).build()?;
        self.c_tx += 1;
        Ok(m)
    }

    /// Opens a SEALED record. Counters must arrive in order; a record that
    /// does not is refused and the session should be dropped.
    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>, LinkError> {
        let (kind, f) = wire::split(sealed)?;
        if kind != msg::SEALED {
            return Err(LinkError::Unexpected(kind));
        }
        let found = f.uint(tag::COUNTER).ok_or(LinkError::Missing("counter"))?;
        if found != self.c_rx {
            return Err(LinkError::Counter { expected: self.c_rx, found });
        }
        let boxed = f.get(tag::BOX).ok_or(LinkError::Missing("box"))?;
        let cipher = Aes256Gcm::new_from_slice(&self.k_rx).map_err(|_| LinkError::Open)?;
        let plain = cipher.decrypt(Nonce::from_slice(&nonce(b'L', self.c_rx)), boxed).map_err(|_| LinkError::Open)?;
        self.c_rx += 1;
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node signer with a fixed key and a fixed (not valid) signature, so
    /// the handshake's derived values can be compared with the reference host.
    struct Fixed(SecretKey);

    impl NodeSigner for Fixed {
        fn public_key(&self) -> Result<[u8; PUB_LEN], String> {
            Ok(self.0.public_key().to_sec1_point(false).as_bytes().try_into().unwrap())
        }

        fn sign_der(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Ok((0u8..71).collect())
        }
    }

    fn scalar(n: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = n;
        SecretKey::from_slice(&b).unwrap()
    }

    // Produced by running host/fl_proto.py (the reference host in the leaf
    // firmware repository) on fixed inputs: node key 7, node ephemeral 9, leaf
    // ephemeral 11.
    const HELLO: &str = "0168656c6c6f2d62797465732d666f722d766563746f72";
    const GRANT: &str = "464c4731048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b401000000030000000000000000000000000000000000000000000000000000000000000000";
    const TH: &str = "6356cbb22816e0c874d75447800621f10a6e8c83bd182691d31fe233ff9d28c2";
    const K_TX: &str = "fff4771759014a7b5e44fcf903f147d7327a6ed6358c40493cee0f90bb6b7790";
    const K_RX: &str = "ebca3852c46e3fc0353258fae908b7f599ac0382fe401d826823836f833f1c50";
    const LEAF_DIGEST: &str = "9c638504bbc5451cb44ee6d72b880cbb848c7b5beb0b6f839bf0243f864d3334";
    const SEALED: &str = "100d0004000000000e00116892824dbde13293dfacb678c656c35fc8";
    const BOX_LEAF_5: &str = "68b896cdffcb13377212bf4717ab0fae6e387cb3";

    fn pending() -> Pending {
        let leaf_eph = scalar(11).public_key().to_sec1_point(false).as_bytes().try_into().unwrap();
        let hello = Hello { raw: hex::decode(HELLO).unwrap(), dev_pub: [0; PUB_LEN], eph: leaf_eph, evidence: Fields::default() };
        let grant = NodeGrant { grant: hex::decode(GRANT).unwrap(), sig: vec![0; 70] };
        answer(&hello, &Fixed(scalar(7)), &grant, &scalar(9)).unwrap().0
    }

    #[test]
    fn the_transcript_and_keys_match_the_reference_host() {
        let p = pending();
        assert_eq!(hex::encode(p.th), TH);
        assert_eq!(hex::encode(p.k_tx), K_TX);
        assert_eq!(hex::encode(p.k_rx), K_RX);
        let covered = &p.node_sig[..p.node_sig.len().min(72)];
        assert_eq!(hex::encode(lp(b"FL1 leaf auth ", &[&p.th, covered])), LEAF_DIGEST);
    }

    #[test]
    fn a_sealed_record_is_byte_identical_to_the_reference_hosts() {
        let p = pending();
        let mut s = Session { k_tx: p.k_tx, k_rx: p.k_rx, c_tx: 0, c_rx: 0, leaf_pub: [0; PUB_LEN] };
        assert_eq!(hex::encode(s.seal(&[msg::SENSE_REQ]).unwrap()), SEALED);
        assert_eq!(s.c_tx, 1);
        // A record from the leaf, counter 5, sealed with the reference host's key for that direction.
        let m = Builder::new(msg::SEALED).field(tag::COUNTER, &5u32.to_be_bytes()).field(tag::BOX, &hex::decode(BOX_LEAF_5).unwrap()).build().unwrap();
        s.c_rx = 5;
        assert_eq!(s.open(&m).unwrap(), b"\x73abc");
        // The same record again is a replay, and a record that skips is refused too.
        assert_eq!(s.open(&m), Err(LinkError::Counter { expected: 6, found: 5 }));
    }

    #[test]
    fn a_grant_for_another_key_is_not_answered() {
        let leaf_eph = scalar(11).public_key().to_sec1_point(false).as_bytes().try_into().unwrap();
        let hello = Hello { raw: hex::decode(HELLO).unwrap(), dev_pub: [0; PUB_LEN], eph: leaf_eph, evidence: Fields::default() };
        let grant = NodeGrant { grant: hex::decode(GRANT).unwrap(), sig: vec![0; 70] };
        assert!(matches!(answer(&hello, &Fixed(scalar(8)), &grant, &scalar(9)), Err(LinkError::GrantNotForThisNode)));
    }

    #[test]
    fn a_tampered_box_does_not_open_and_does_not_advance_the_counter() {
        let p = pending();
        let mut s = Session { k_tx: p.k_tx, k_rx: p.k_rx, c_tx: 0, c_rx: 5, leaf_pub: [0; PUB_LEN] };
        let mut b = hex::decode(BOX_LEAF_5).unwrap();
        b[0] ^= 1;
        let m = Builder::new(msg::SEALED).field(tag::COUNTER, &5u32.to_be_bytes()).field(tag::BOX, &b).build().unwrap();
        assert_eq!(s.open(&m), Err(LinkError::Open));
        assert_eq!(s.c_rx, 5);
    }
}
