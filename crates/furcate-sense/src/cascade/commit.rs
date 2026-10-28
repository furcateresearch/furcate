//! A signed commitment to a batch of embeddings, and the audit that checks it.
//!
//! The micro processing node sends embeddings upward and keeps the raw windows.
//! Per window the wire carries the embedding only; per batch of `K` windows it
//! carries one signed [`BatchCommit`], the root of a Merkle tree whose leaves
//! commit to each window's sequence, its embedding and the digest of its raw
//! samples. The rung above may then ask for any window it has an embedding for:
//! the node reveals the raw samples and the tree path, and the rung
//!
//! 1. rebuilds the leaf from the embedding **it received**, the position, and
//!    the digest of the raw samples just revealed;
//! 2. checks the path from that leaf to the signed root, at the position the
//!    window must occupy;
//! 3. recomputes the embedding from the raw samples with the model and compares.
//!
//! Step 1 and 2 show the embedding sent is the one committed to, over the raw
//! the node still holds. Step 3 shows the embedding is what the model makes of
//! that raw. A node that sent an embedding it did not compute, or committed to
//! raw that is not what it measured but cannot reproduce, fails one of the
//! three. A node that changes a window it expects not to be challenged is
//! caught with the probability [`detection_probability`] gives, and cannot know
//! which windows will be asked for.
//!
//! What this does not do: it cannot show the raw samples are what the sensor
//! produced (the sensing node holds no secret), and a node that computes the
//! committed embedding honestly from fabricated raw passes every step. Raw
//! samples are kept in a bounded [`RawRing`]; a window older than the ring
//! cannot be challenged and is reported as expired, not as passed.
//!
//! Wire size: see [`wire_cost`]. The per-batch part is [`BATCH_WIRE_LEN`] bytes;
//! sequence numbers and framing are carried with or without a commitment and
//! are not counted.

use super::signer::CascadeSigner;
use crate::leaf::verify_with_key;
use furcate_ledger::merkle::{leaf_digest, InclusionProof, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

pub const BATCH_DOMAIN: &str = "furcate/embedding-batch/v1";
const LEAF_DOMAIN: &[u8] = b"furcate/embedding-batch/leaf/v1";
const RAW_DOMAIN: &[u8] = b"furcate/embedding-batch/raw/v1";

/// Compact size of a signed commit: batch 4, first window 4, count 2, model
/// prefix 8, root 32, Ed25519 or P-256 signature 64.
pub const BATCH_WIRE_LEN: usize = 4 + 4 + 2 + 8 + 32 + 64;

/// Digest of one window's raw samples.
pub fn raw_digest(raw: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RAW_DOMAIN);
    h.update((raw.len() as u64).to_be_bytes());
    h.update(raw);
    h.finalize().into()
}

/// What a tree leaf commits to for one window.
pub fn leaf_payload(window_seq: u64, embedding: &[i8], raw_hash: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(LEAF_DOMAIN.len() + 8 + 2 + embedding.len() + 32);
    p.extend(LEAF_DOMAIN);
    p.extend(window_seq.to_be_bytes());
    p.extend((embedding.len() as u16).to_be_bytes());
    p.extend(embedding.iter().map(|v| *v as u8));
    p.extend(raw_hash);
    p
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchCommit {
    pub leaf_id: String,
    pub batch_seq: u64,
    pub first_window_seq: u64,
    pub count: u32,
    /// Hex of the model hash prefix the embeddings were made with.
    pub model: String,
    /// Merkle root, hex.
    pub root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBatch {
    pub commit: BatchCommit,
    pub signature: String,
}

fn commit_message(c: &BatchCommit) -> Vec<u8> {
    serde_json::to_vec(c).unwrap_or_default()
}

pub fn sign_batch(signer: &dyn CascadeSigner, commit: BatchCommit) -> Result<SignedBatch, String> {
    let signature = signer.sign_message(BATCH_DOMAIN, &commit_message(&commit))?;
    Ok(SignedBatch { commit, signature })
}

/// What the node reveals for a challenged window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reveal {
    pub batch_seq: u64,
    pub window_seq: u64,
    pub raw: Vec<u8>,
    pub proof: InclusionProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeError {
    /// The window is in a batch that is not sealed yet.
    NotSealed,
    /// The raw samples have left the ring.
    Expired,
    Unknown,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeError::NotSealed => write!(f, "the window's batch is not sealed yet"),
            ChallengeError::Expired => write!(f, "the raw samples are no longer held"),
            ChallengeError::Unknown => write!(f, "no such window"),
        }
    }
}

impl std::error::Error for ChallengeError {}

struct Held {
    window_seq: u64,
    batch_seq: u64,
    raw: Vec<u8>,
}

/// The node side: builds batches and answers challenges.
pub struct BatchBuilder {
    leaf_id: String,
    model: String,
    k: usize,
    ring: RawRing,
    open: Vec<(u64, Vec<i8>, [u8; 32])>,
    next_batch: u64,
    trees: BTreeMap<u64, (u64, MerkleTree)>,
}

/// Raw windows held for challenge, oldest dropped first once the byte budget is full.
pub struct RawRing {
    budget: usize,
    used: usize,
    items: VecDeque<Held>,
}

impl RawRing {
    pub fn new(budget_bytes: usize) -> Self {
        Self { budget: budget_bytes, used: 0, items: VecDeque::new() }
    }

    fn push(&mut self, h: Held) {
        self.used += h.raw.len();
        self.items.push_back(h);
        while self.used > self.budget {
            match self.items.pop_front() {
                Some(old) => self.used -= old.raw.len(),
                None => break,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn get(&self, window_seq: u64) -> Option<&Held> {
        self.items.iter().find(|h| h.window_seq == window_seq)
    }

    fn oldest(&self) -> Option<u64> {
        self.items.front().map(|h| h.window_seq)
    }
}

impl BatchBuilder {
    /// `model_prefix` is the hex of the model hash prefix (8 bytes); `k` windows
    /// per batch; `ring_bytes` of raw samples held.
    pub fn new(leaf_id: &str, model_prefix: &str, k: usize, ring_bytes: usize) -> Self {
        Self {
            leaf_id: leaf_id.to_string(),
            model: model_prefix.to_string(),
            k: k.max(1),
            ring: RawRing::new(ring_bytes),
            open: Vec::new(),
            next_batch: 1,
            trees: BTreeMap::new(),
        }
    }

    /// Add a window. Returns the signed batch when this window completes one.
    /// Window sequence numbers must increase by one.
    pub fn push(
        &mut self,
        signer: &dyn CascadeSigner,
        window_seq: u64,
        embedding: &[i8],
        raw: &[u8],
    ) -> Result<Option<SignedBatch>, String> {
        if let Some((last, _, _)) = self.open.last() {
            if window_seq != last + 1 {
                return Err(format!("window {window_seq} does not follow {last}"));
            }
        }
        self.ring.push(Held { window_seq, batch_seq: self.next_batch, raw: raw.to_vec() });
        self.open.push((window_seq, embedding.to_vec(), raw_digest(raw)));
        if self.open.len() == self.k {
            return self.flush(signer);
        }
        Ok(None)
    }

    /// Seal the open batch even if it holds fewer than `k` windows.
    pub fn flush(&mut self, signer: &dyn CascadeSigner) -> Result<Option<SignedBatch>, String> {
        if self.open.is_empty() {
            return Ok(None);
        }
        let payloads: Vec<Vec<u8>> = self.open.iter().map(|(s, e, r)| leaf_payload(*s, e, r)).collect();
        let tree = MerkleTree::build(&payloads).ok_or("an empty batch")?;
        let first = self.open[0].0;
        let commit = BatchCommit {
            leaf_id: self.leaf_id.clone(),
            batch_seq: self.next_batch,
            first_window_seq: first,
            count: self.open.len() as u32,
            model: self.model.clone(),
            root: tree.root_hex(),
        };
        let signed = sign_batch(signer, commit)?;
        self.trees.insert(self.next_batch, (first, tree));
        self.next_batch += 1;
        self.open.clear();
        // A tree is useless once every raw window of its batch has left the ring.
        if let Some(oldest) = self.ring.oldest() {
            self.trees.retain(|_, (first, tree)| *first + tree.len() as u64 > oldest);
        }
        Ok(Some(signed))
    }

    /// Reveal the raw samples and path for a window.
    pub fn reveal(&self, window_seq: u64) -> Result<Reveal, ChallengeError> {
        if self.open.iter().any(|(s, _, _)| *s == window_seq) {
            return Err(ChallengeError::NotSealed);
        }
        let held = self.ring.get(window_seq);
        let Some(held) = held else {
            return Err(match self.ring.oldest() {
                Some(o) if window_seq < o => ChallengeError::Expired,
                None if self.next_batch > 1 => ChallengeError::Expired,
                _ => ChallengeError::Unknown,
            });
        };
        let (first, tree) = self.trees.get(&held.batch_seq).ok_or(ChallengeError::Expired)?;
        let proof = tree.prove((window_seq - first) as usize).ok_or(ChallengeError::Unknown)?;
        Ok(Reveal { batch_seq: held.batch_seq, window_seq, raw: held.raw.clone(), proof })
    }

    pub fn ring(&self) -> &RawRing {
        &self.ring
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditFailure {
    BadSignature,
    /// The rung did not receive exactly the windows the batch covers.
    Incomplete { missing: Vec<u64> },
    WrongBatch,
    NotInBatch,
    /// The path is for another position than the one the window occupies.
    WrongPosition,
    /// The embedding received or the raw revealed is not what was committed.
    NotCommitted,
    ProofInvalid,
    /// The committed embedding is not what the model makes of the committed raw.
    EmbeddingMismatch,
}

impl AuditFailure {
    pub fn code(&self) -> &'static str {
        match self {
            AuditFailure::BadSignature => "batch_bad_signature",
            AuditFailure::Incomplete { .. } => "batch_incomplete",
            AuditFailure::WrongBatch => "batch_wrong_batch",
            AuditFailure::NotInBatch => "batch_not_in_batch",
            AuditFailure::WrongPosition => "batch_wrong_position",
            AuditFailure::NotCommitted => "batch_not_committed",
            AuditFailure::ProofInvalid => "batch_proof_invalid",
            AuditFailure::EmbeddingMismatch => "batch_embedding_mismatch",
        }
    }
}

impl std::fmt::Display for AuditFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditFailure::BadSignature => write!(f, "the batch is not signed by the enrolled node"),
            AuditFailure::Incomplete { missing } => write!(f, "{} windows of the batch were not received", missing.len()),
            AuditFailure::WrongBatch => write!(f, "the reveal is for another batch"),
            AuditFailure::NotInBatch => write!(f, "the window is not in the batch"),
            AuditFailure::WrongPosition => write!(f, "the path is for another position"),
            AuditFailure::NotCommitted => write!(f, "the embedding or raw samples are not what the node committed to"),
            AuditFailure::ProofInvalid => write!(f, "the path does not reach the signed root"),
            AuditFailure::EmbeddingMismatch => write!(f, "the model does not make the committed embedding from the committed raw samples"),
        }
    }
}

impl std::error::Error for AuditFailure {}

/// Check the batch signature against the enrolled key of the node.
pub fn verify_batch(b: &SignedBatch, node_key: &str) -> Result<(), AuditFailure> {
    verify_with_key(node_key, BATCH_DOMAIN, &commit_message(&b.commit), &b.signature).map_err(|_| AuditFailure::BadSignature)
}

/// Check that the windows received are exactly the ones the batch covers.
pub fn check_complete(b: &SignedBatch, received: &[u64]) -> Result<(), AuditFailure> {
    let c = &b.commit;
    let missing: Vec<u64> =
        (c.first_window_seq..c.first_window_seq + c.count as u64).filter(|s| !received.contains(s)).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AuditFailure::Incomplete { missing })
    }
}

/// Audit one challenged window of a verified batch. `received` is the
/// embedding this rung received for `reveal.window_seq`; `embed` is the model.
pub fn audit(
    batch: &SignedBatch,
    received: &[i8],
    reveal: &Reveal,
    embed: &dyn Fn(&[u8]) -> Vec<i8>,
) -> Result<(), AuditFailure> {
    let c = &batch.commit;
    if reveal.batch_seq != c.batch_seq {
        return Err(AuditFailure::WrongBatch);
    }
    if reveal.window_seq < c.first_window_seq || reveal.window_seq >= c.first_window_seq + c.count as u64 {
        return Err(AuditFailure::NotInBatch);
    }
    if reveal.proof.index as u64 != reveal.window_seq - c.first_window_seq {
        return Err(AuditFailure::WrongPosition);
    }
    let leaf = leaf_digest(&leaf_payload(reveal.window_seq, received, &raw_digest(&reveal.raw)));
    if reveal.proof.leaf != hex::encode(leaf) {
        return Err(AuditFailure::NotCommitted);
    }
    if !MerkleTree::verify(&reveal.proof, &c.root) {
        return Err(AuditFailure::ProofInvalid);
    }
    if embed(&reveal.raw).as_slice() != received {
        return Err(AuditFailure::EmbeddingMismatch);
    }
    Ok(())
}

/// The chance that at least one of `altered` windows out of `k` is among
/// `challenges` windows drawn without replacement.
pub fn detection_probability(k: usize, altered: usize, challenges: usize) -> f64 {
    if altered == 0 {
        return 0.0;
    }
    if challenges + altered > k {
        return 1.0;
    }
    let mut miss = 1.0;
    for i in 0..challenges {
        miss *= (k - altered - i) as f64 / (k - i) as f64;
    }
    1.0 - miss
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WireCost {
    /// Bytes per window added to the embedding by the commitment.
    pub commit_per_window: f64,
    /// Embedding plus commitment, per window.
    pub per_window: f64,
    /// Raw bytes per window over `per_window`.
    pub reduction: f64,
}

/// Bytes on the wire per window for `k` windows per batch.
pub fn wire_cost(k: usize, embedding_dim: usize, raw_bytes_per_window: usize) -> WireCost {
    let commit_per_window = BATCH_WIRE_LEN as f64 / k as f64;
    let per_window = embedding_dim as f64 + commit_per_window;
    WireCost { commit_per_window, per_window, reduction: raw_bytes_per_window as f64 / per_window }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::Leaf;

    const DIM: usize = 4;

    /// A deterministic stand-in model over raw bytes.
    fn embed(raw: &[u8]) -> Vec<i8> {
        (0..DIM).map(|i| ((raw.iter().skip(i).step_by(DIM).map(|b| *b as u32).sum::<u32>() % 200) as i32 - 100) as i8).collect()
    }

    fn raw(seq: u64) -> Vec<u8> {
        (0..48u64).map(|i| ((seq * 31 + i * 7) % 251) as u8).collect()
    }

    struct Node {
        leaf: Leaf,
        b: BatchBuilder,
        sent: Vec<(u64, Vec<i8>)>,
        batches: Vec<SignedBatch>,
    }

    fn node(k: usize, ring: usize, windows: u64) -> Node {
        let leaf = Leaf::new("furcate:node:micro1", [5; 32]);
        let mut n = Node { b: BatchBuilder::new("furcate:node:micro1", "0011223344556677", k, ring), leaf, sent: vec![], batches: vec![] };
        for s in 1..=windows {
            let e = embed(&raw(s));
            n.sent.push((s, e.clone()));
            if let Some(sb) = n.b.push(&n.leaf, s, &e, &raw(s)).unwrap() {
                n.batches.push(sb);
            }
        }
        n
    }

    fn received(n: &Node, s: u64) -> Vec<i8> {
        n.sent.iter().find(|(x, _)| *x == s).unwrap().1.clone()
    }

    #[test]
    fn every_window_of_every_batch_audits_clean() {
        let n = node(5, 1 << 20, 20);
        assert_eq!(n.batches.len(), 4);
        for sb in &n.batches {
            assert_eq!(verify_batch(sb, &n.leaf.public_key()), Ok(()));
            for s in sb.commit.first_window_seq..sb.commit.first_window_seq + 5 {
                let r = n.b.reveal(s).unwrap();
                assert_eq!(audit(sb, &received(&n, s), &r, &embed), Ok(()), "window {s}");
            }
        }
    }

    #[test]
    fn a_batch_signed_by_another_key_or_altered_is_refused() {
        let n = node(5, 1 << 20, 5);
        let other = Leaf::new("x", [6; 32]);
        assert_eq!(verify_batch(&n.batches[0], &other.public_key()), Err(AuditFailure::BadSignature));
        let mut t = n.batches[0].clone();
        t.commit.count = 4;
        assert_eq!(verify_batch(&t, &n.leaf.public_key()), Err(AuditFailure::BadSignature));
    }

    #[test]
    fn an_embedding_that_differs_from_the_committed_one_is_not_committed() {
        let n = node(5, 1 << 20, 5);
        let sb = &n.batches[0];
        let r = n.b.reveal(3).unwrap();
        let mut e = received(&n, 3);
        e[0] = e[0].wrapping_add(1);
        assert_eq!(audit(sb, &e, &r, &embed), Err(AuditFailure::NotCommitted));
    }

    #[test]
    fn raw_samples_other_than_the_committed_ones_are_not_committed() {
        let n = node(5, 1 << 20, 5);
        let mut r = n.b.reveal(3).unwrap();
        r.raw[0] ^= 1;
        assert_eq!(audit(&n.batches[0], &received(&n, 3), &r, &embed), Err(AuditFailure::NotCommitted));
    }

    #[test]
    fn a_node_that_committed_an_embedding_its_model_does_not_make_is_caught() {
        // The node sends and commits a wrong embedding for window 3 and holds the true raw.
        let leaf = Leaf::new("furcate:node:micro1", [5; 32]);
        let mut b = BatchBuilder::new("furcate:node:micro1", "0011223344556677", 5, 1 << 20);
        let mut sent = Vec::new();
        let mut sb = None;
        for s in 1..=5u64 {
            let mut e = embed(&raw(s));
            if s == 3 {
                e = vec![0, 0, 0, 0]; // hides a hard window
            }
            sent.push(e.clone());
            sb = b.push(&leaf, s, &e, &raw(s)).unwrap().or(sb);
        }
        let sb = sb.unwrap();
        for s in [1u64, 2, 4, 5] {
            assert_eq!(audit(&sb, &sent[s as usize - 1], &b.reveal(s).unwrap(), &embed), Ok(()));
        }
        assert_eq!(audit(&sb, &sent[2], &b.reveal(3).unwrap(), &embed), Err(AuditFailure::EmbeddingMismatch));
    }

    #[test]
    fn a_path_for_another_position_or_batch_or_a_forged_path_is_refused() {
        let n = node(5, 1 << 20, 10);
        let (b1, b2) = (&n.batches[0], &n.batches[1]);
        let r = n.b.reveal(3).unwrap();
        assert_eq!(audit(b2, &received(&n, 3), &r, &embed), Err(AuditFailure::WrongBatch));
        let mut moved = n.b.reveal(3).unwrap();
        moved.window_seq = 4;
        assert_eq!(audit(b1, &received(&n, 4), &moved, &embed), Err(AuditFailure::WrongPosition));
        let mut outside = n.b.reveal(3).unwrap();
        outside.window_seq = 99;
        assert_eq!(audit(b1, &received(&n, 3), &outside, &embed), Err(AuditFailure::NotInBatch));
        let mut forged = n.b.reveal(3).unwrap();
        forged.proof.path[0].1 = "00".repeat(32);
        assert_eq!(audit(b1, &received(&n, 3), &forged, &embed), Err(AuditFailure::ProofInvalid));
    }

    #[test]
    fn completeness_names_the_windows_that_never_arrived() {
        let n = node(5, 1 << 20, 5);
        assert_eq!(check_complete(&n.batches[0], &[1, 2, 3, 4, 5]), Ok(()));
        assert_eq!(check_complete(&n.batches[0], &[1, 2, 4, 5]), Err(AuditFailure::Incomplete { missing: vec![3] }));
    }

    #[test]
    fn the_ring_expires_old_windows_and_an_open_batch_is_not_revealable() {
        // 48 bytes per window, room for 7: windows 1..=15 sealed in batches of 5, 16 open.
        let n = {
            let mut n = node(5, 48 * 7, 15);
            let e = embed(&raw(16));
            assert!(n.b.push(&n.leaf, 16, &e, &raw(16)).unwrap().is_none());
            n
        };
        assert_eq!(n.b.reveal(1).err(), Some(ChallengeError::Expired));
        assert_eq!(n.b.reveal(16).err(), Some(ChallengeError::NotSealed));
        assert_eq!(n.b.reveal(99).err(), Some(ChallengeError::Unknown));
        let r = n.b.reveal(12).unwrap();
        assert_eq!(audit(&n.batches[2], &received(&n, 12), &r, &embed), Ok(()));
        assert!(n.b.ring().len() <= 7);
    }

    #[test]
    fn a_partial_batch_can_be_sealed_and_audited() {
        let mut n = node(5, 1 << 20, 7);
        let sb = n.b.flush(&n.leaf).unwrap().unwrap();
        assert_eq!((sb.commit.first_window_seq, sb.commit.count), (6, 2));
        assert_eq!(audit(&sb, &received(&n, 7), &n.b.reveal(7).unwrap(), &embed), Ok(()));
        assert_eq!(n.b.flush(&n.leaf).unwrap(), None);
    }

    #[test]
    fn an_out_of_order_window_is_refused_by_the_builder() {
        let leaf = Leaf::new("x", [5; 32]);
        let mut b = BatchBuilder::new("x", "00", 5, 1000);
        b.push(&leaf, 1, &[1], &[1]).unwrap();
        assert!(b.push(&leaf, 3, &[1], &[1]).is_err());
    }

    #[test]
    fn the_wire_cost_is_the_embedding_plus_a_share_of_114_bytes() {
        assert_eq!(BATCH_WIRE_LEN, 114);
        // 6 axes of int16 at 100 Hz for one second.
        let c = wire_cost(10, 32, 1200);
        assert!((c.commit_per_window - 11.4).abs() < 1e-9);
        assert!((c.per_window - 43.4).abs() < 1e-9);
        assert!((c.reduction - 27.65).abs() < 0.01);
        // A signature on every window would be 96 bytes.
        assert!(wire_cost(1, 32, 1200).per_window > 140.0);
    }

    #[test]
    fn the_signature_on_the_wire_is_64_bytes() {
        let n = node(5, 1 << 20, 5);
        assert_eq!(hex::decode(&n.batches[0].signature).unwrap().len(), 64);
        assert_eq!(hex::decode(&n.batches[0].commit.root).unwrap().len(), 32);
    }

    #[test]
    fn detection_probability_matches_a_simulated_audit() {
        // A node alters `m` of K=20 committed embeddings; the rung challenges `c` at random.
        let n = {
            let leaf = Leaf::new("furcate:node:micro1", [5; 32]);
            let mut b = BatchBuilder::new("furcate:node:micro1", "00", 20, 1 << 20);
            let mut sent = Vec::new();
            let mut sb = None;
            for s in 1..=20u64 {
                sent.push(embed(&raw(s)));
                sb = b.push(&leaf, s, &sent[s as usize - 1], &raw(s)).unwrap().or(sb);
            }
            (b, sent, sb.unwrap())
        };
        let (b, honest, sb) = n;
        let mut rng = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for (m, c) in [(1usize, 1usize), (1, 4), (3, 2), (5, 3)] {
            let trials = 4000;
            let mut caught = 0;
            for _ in 0..trials {
                // The rung received altered embeddings for the first `m` windows (the commit is over the true ones).
                let mut recv = honest.clone();
                for e in recv.iter_mut().take(m) {
                    e[0] = e[0].wrapping_add(1);
                }
                let mut pool: Vec<u64> = (1..=20).collect();
                let mut hit = false;
                for _ in 0..c {
                    let i = (next() % pool.len() as u64) as usize;
                    let s = pool.swap_remove(i);
                    hit |= audit(&sb, &recv[s as usize - 1], &b.reveal(s).unwrap(), &embed).is_err();
                }
                caught += hit as usize;
            }
            let rate = caught as f64 / trials as f64;
            let theory = detection_probability(20, m, c);
            assert!((rate - theory).abs() < 0.03, "m={m} c={c} rate={rate} theory={theory}");
        }
        assert_eq!(detection_probability(20, 0, 5), 0.0);
        assert_eq!(detection_probability(20, 16, 5), 1.0);
    }
}
