//! A per-leaf, hash-chained reading log, witnessed by the rung above.
//!
//! The micro processing node appends one entry per item it signs. Each entry
//! commits to the one before it, to its position, to the node's own monotonic
//! time and to a digest of the item, so removing, repeating or reordering
//! entries breaks the chain. Every so often the node signs a checkpoint, the
//! size and head of its log. The small processing node holds the same chain,
//! built from what actually reached it, and cosigns a checkpoint only if it
//! has seen every entry up to it and its own head at that size is the same.
//! A consumer that demands a recent cosigned checkpoint therefore learns two
//! things: nothing up to that point was dropped, and the log was alive no
//! longer ago than the cosignature.
//!
//! What it does not do: it cannot show that an item was never produced and
//! never logged (the micro node is the trusted signer), and delay detection
//! compares arrival against the node's own clock after removing the smallest
//! offset seen, which bounds extra delay but is not synchronised time.
//!
//! The witness never advances over a gap. A frame that skips ahead is refused
//! and the leaf heals the gap by sending the missing entries in order.

use super::signer::CascadeSigner;
use crate::leaf::verify_with_key;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

pub const ENTRY_DOMAIN: &str = "furcate/leaf-log/entry/v1";
pub const CHECKPOINT_DOMAIN: &str = "furcate/leaf-log/checkpoint/v1";
pub const COSIGN_DOMAIN: &str = "furcate/leaf-log/cosignature/v1";
const GENESIS_DOMAIN: &[u8] = b"furcate/leaf-log/genesis/v1";

/// How many past heads a witness keeps, to cosign a checkpoint that is not the newest.
const HISTORY: usize = 4096;

fn lp(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_be_bytes());
    h.update(b);
}

/// The head of an empty log for `leaf_id`.
pub fn genesis(leaf_id: &str) -> String {
    let mut h = Sha256::new();
    lp(&mut h, GENESIS_DOMAIN);
    lp(&mut h, leaf_id.as_bytes());
    hex::encode(h.finalize())
}

/// The digest an entry carries for an item: SHA-256 of the item's envelope signature.
pub fn item_digest(envelope_signature: &str) -> String {
    hex::encode(Sha256::digest(envelope_signature.as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Position, from 1.
    pub seq: u64,
    /// The signing node's monotonic time in milliseconds. Advisory.
    pub ts_ms: u64,
    pub digest: String,
    pub prev: String,
    pub hash: String,
}

fn entry_hash(prev: &str, seq: u64, ts_ms: u64, digest: &str) -> String {
    let mut h = Sha256::new();
    lp(&mut h, ENTRY_DOMAIN.as_bytes());
    lp(&mut h, prev.as_bytes());
    h.update(seq.to_be_bytes());
    h.update(ts_ms.to_be_bytes());
    lp(&mut h, digest.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub leaf_id: String,
    /// Number of entries covered.
    pub size: u64,
    pub head: String,
    pub ts_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signature: String,
}

fn checkpoint_message(c: &Checkpoint) -> Vec<u8> {
    serde_json::to_vec(c).unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosigned {
    pub signed: SignedCheckpoint,
    pub witness: String,
    pub witnessed_at_ms: u64,
    pub cosignature: String,
}

fn cosign_message(s: &SignedCheckpoint, witness: &str, at: u64) -> Vec<u8> {
    let mut m = checkpoint_message(&s.checkpoint);
    m.extend(s.signature.as_bytes());
    m.extend((witness.len() as u64).to_be_bytes());
    m.extend(witness.as_bytes());
    m.extend(at.to_be_bytes());
    m
}

/// The producing side: what the micro processing node keeps.
#[derive(Clone, Debug)]
pub struct LeafLog {
    leaf_id: String,
    size: u64,
    head: String,
}

impl LeafLog {
    pub fn new(leaf_id: &str) -> Self {
        Self { leaf_id: leaf_id.to_string(), size: 0, head: genesis(leaf_id) }
    }

    pub fn append(&mut self, ts_ms: u64, digest: &str) -> LogEntry {
        self.size += 1;
        let hash = entry_hash(&self.head, self.size, ts_ms, digest);
        let e = LogEntry { seq: self.size, ts_ms, digest: digest.to_string(), prev: self.head.clone(), hash: hash.clone() };
        self.head = hash;
        e
    }

    pub fn checkpoint(&self, ts_ms: u64, signer: &dyn CascadeSigner) -> Result<SignedCheckpoint, String> {
        let checkpoint = Checkpoint { leaf_id: self.leaf_id.clone(), size: self.size, head: self.head.clone(), ts_ms };
        let signature = signer.sign_message(CHECKPOINT_DOMAIN, &checkpoint_message(&checkpoint))?;
        Ok(SignedCheckpoint { checkpoint, signature })
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// An entry that skips ahead: the entries between were not received.
    Gap { expected: u64, found: u64 },
    /// An entry already witnessed, repeated.
    Duplicate { seq: u64 },
    /// An entry for a position already witnessed, with different content.
    Equivocation { seq: u64 },
    /// The entry does not continue the witnessed head.
    BrokenLink { seq: u64 },
    /// The entry's hash is not the hash of its fields.
    BadHash { seq: u64 },
    UnknownLeaf,
    BadCheckpointSignature,
    /// The checkpoint covers entries this witness has not seen: something was dropped.
    MissingEntries { claimed: u64, witnessed: u64 },
    HeadMismatch { size: u64 },
    /// The checkpoint is older than the history the witness keeps.
    CheckpointTooOld { size: u64 },
    BadCosignature,
    StaleCosignature { age_ms: u64, max_ms: u64 },
}

impl std::fmt::Display for WitnessRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use WitnessRefusal::*;
        match self {
            Gap { expected, found } => write!(f, "log gap: expected entry {expected}, received {found}"),
            Duplicate { seq } => write!(f, "log entry {seq} was already witnessed"),
            Equivocation { seq } => write!(f, "log entry {seq} conflicts with the one already witnessed"),
            BrokenLink { seq } => write!(f, "log entry {seq} does not continue the witnessed head"),
            BadHash { seq } => write!(f, "log entry {seq} does not hash to its fields"),
            UnknownLeaf => write!(f, "no log witnessed for this leaf"),
            BadCheckpointSignature => write!(f, "the checkpoint is not signed by the leaf's processing node"),
            MissingEntries { claimed, witnessed } => {
                write!(f, "checkpoint covers {claimed} entries but {witnessed} were witnessed")
            }
            HeadMismatch { size } => write!(f, "checkpoint head at size {size} differs from the witnessed head"),
            CheckpointTooOld { size } => write!(f, "checkpoint size {size} is older than the witnessed history"),
            BadCosignature => write!(f, "the cosignature does not verify"),
            StaleCosignature { age_ms, max_ms } => write!(f, "cosigned {age_ms} ms ago, more than {max_ms} ms"),
        }
    }
}

impl std::error::Error for WitnessRefusal {}

/// Whether an entry arrived within the bound of extra delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timing {
    OnTime,
    /// Arrived this many milliseconds later than the fastest delivery seen.
    Late { by_ms: u64 },
}

struct LeafState {
    size: u64,
    head: String,
    history: VecDeque<(u64, String)>,
    /// The smallest `arrival - node time` seen, in milliseconds.
    min_offset: Option<i128>,
}

impl LeafState {
    fn new(leaf_id: &str) -> Self {
        Self { size: 0, head: genesis(leaf_id), history: VecDeque::new(), min_offset: None }
    }
}

pub struct Witness {
    leaves: BTreeMap<String, LeafState>,
    max_delay_ms: u64,
}

impl Witness {
    pub fn new(max_delay_ms: u64) -> Self {
        Self { leaves: BTreeMap::new(), max_delay_ms }
    }

    /// Entries witnessed and the head, for a leaf.
    pub fn state(&self, leaf_id: &str) -> Option<(u64, &str)> {
        self.leaves.get(leaf_id).map(|s| (s.size, s.head.as_str()))
    }

    fn structure(&self, leaf_id: &str, e: &LogEntry) -> Result<(), WitnessRefusal> {
        let (size, head) = match self.leaves.get(leaf_id) {
            Some(s) => (s.size, s.head.clone()),
            None => (0, genesis(leaf_id)),
        };
        if e.seq <= size {
            // A repeat only if the entry is internally consistent and is the one witnessed.
            let consistent = entry_hash(&e.prev, e.seq, e.ts_ms, &e.digest) == e.hash;
            let witnessed = self.leaves.get(leaf_id).and_then(|s| {
                if e.seq == s.size {
                    Some(s.head.clone())
                } else {
                    s.history.iter().find(|(q, _)| *q == e.seq).map(|(_, h)| h.clone())
                }
            });
            return Err(if consistent && witnessed.as_deref() == Some(e.hash.as_str()) {
                WitnessRefusal::Duplicate { seq: e.seq }
            } else {
                WitnessRefusal::Equivocation { seq: e.seq }
            });
        }
        if e.seq > size + 1 {
            return Err(WitnessRefusal::Gap { expected: size + 1, found: e.seq });
        }
        if e.prev != head {
            return Err(WitnessRefusal::BrokenLink { seq: e.seq });
        }
        if entry_hash(&e.prev, e.seq, e.ts_ms, &e.digest) != e.hash {
            return Err(WitnessRefusal::BadHash { seq: e.seq });
        }
        Ok(())
    }

    /// Check an entry without recording it. `arrival_ms` is this node's clock.
    pub fn check_entry(&self, leaf_id: &str, e: &LogEntry, arrival_ms: u64) -> Result<Timing, WitnessRefusal> {
        self.structure(leaf_id, e)?;
        let offset = arrival_ms as i128 - e.ts_ms as i128;
        let min = self.leaves.get(leaf_id).and_then(|s| s.min_offset).map_or(offset, |m| m.min(offset));
        let late = (offset - min) as u64;
        Ok(if late > self.max_delay_ms { Timing::Late { by_ms: late } } else { Timing::OnTime })
    }

    /// Record an entry that [`Witness::check_entry`] accepted.
    pub fn commit_entry(&mut self, leaf_id: &str, e: &LogEntry, arrival_ms: u64) -> Result<(), WitnessRefusal> {
        self.structure(leaf_id, e)?;
        let offset = arrival_ms as i128 - e.ts_ms as i128;
        self.advance(leaf_id, e, Some(offset));
        Ok(())
    }

    fn advance(&mut self, leaf_id: &str, e: &LogEntry, offset: Option<i128>) {
        let s = self.leaves.entry(leaf_id.to_string()).or_insert_with(|| LeafState::new(leaf_id));
        if s.history.len() == HISTORY {
            s.history.pop_front();
        }
        s.history.push_back((s.size, s.head.clone()));
        s.size = e.seq;
        s.head = e.hash.clone();
        if let Some(o) = offset {
            s.min_offset = Some(s.min_offset.map_or(o, |m| m.min(o)));
        }
    }

    /// Rebuild state from a journal: the chain is checked, timing is not.
    pub fn restore_entry(&mut self, leaf_id: &str, e: &LogEntry) -> Result<(), WitnessRefusal> {
        self.structure(leaf_id, e)?;
        self.advance(leaf_id, e, None);
        Ok(())
    }

    fn head_at(&self, leaf_id: &str, size: u64) -> Result<String, WitnessRefusal> {
        let Some(s) = self.leaves.get(leaf_id) else {
            return if size == 0 { Ok(genesis(leaf_id)) } else { Err(WitnessRefusal::UnknownLeaf) };
        };
        if size > s.size {
            return Err(WitnessRefusal::MissingEntries { claimed: size, witnessed: s.size });
        }
        if size == s.size {
            return Ok(s.head.clone());
        }
        if size == 0 {
            return Ok(genesis(leaf_id));
        }
        // `history` holds the head before each entry from the oldest kept.
        let Some((first, _)) = s.history.front() else { return Err(WitnessRefusal::CheckpointTooOld { size }) };
        if size < *first {
            return Err(WitnessRefusal::CheckpointTooOld { size });
        }
        // The head after entry `size` is the head before entry `size + 1`.
        s.history
            .iter()
            .find(|(q, _)| *q == size)
            .map(|(_, h)| h.clone())
            .ok_or(WitnessRefusal::CheckpointTooOld { size })
    }

    /// Cosign a leaf's checkpoint, if everything it covers was witnessed here.
    pub fn cosign(
        &self,
        sc: &SignedCheckpoint,
        leaf_key: &str,
        signer: &dyn CascadeSigner,
        now_ms: u64,
    ) -> Result<Cosigned, WitnessRefusal> {
        let c = &sc.checkpoint;
        verify_with_key(leaf_key, CHECKPOINT_DOMAIN, &checkpoint_message(c), &sc.signature)
            .map_err(|_| WitnessRefusal::BadCheckpointSignature)?;
        if self.head_at(&c.leaf_id, c.size)? != c.head {
            return Err(WitnessRefusal::HeadMismatch { size: c.size });
        }
        let cosignature = signer
            .sign_message(COSIGN_DOMAIN, &cosign_message(sc, signer.node_id(), now_ms))
            .map_err(|_| WitnessRefusal::BadCosignature)?;
        Ok(Cosigned { signed: sc.clone(), witness: signer.node_id().to_string(), witnessed_at_ms: now_ms, cosignature })
    }
}

/// What a consumer of a log checks: both signatures, and that the cosignature is recent.
pub fn verify_cosigned(
    c: &Cosigned,
    leaf_key: &str,
    witness_key: &str,
    now_ms: u64,
    max_age_ms: u64,
) -> Result<(), WitnessRefusal> {
    verify_with_key(leaf_key, CHECKPOINT_DOMAIN, &checkpoint_message(&c.signed.checkpoint), &c.signed.signature)
        .map_err(|_| WitnessRefusal::BadCheckpointSignature)?;
    verify_with_key(witness_key, COSIGN_DOMAIN, &cosign_message(&c.signed, &c.witness, c.witnessed_at_ms), &c.cosignature)
        .map_err(|_| WitnessRefusal::BadCosignature)?;
    let age_ms = now_ms.saturating_sub(c.witnessed_at_ms);
    if age_ms > max_age_ms {
        return Err(WitnessRefusal::StaleCosignature { age_ms, max_ms: max_age_ms });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::Leaf;

    fn setup() -> (LeafLog, Witness, Leaf, Leaf) {
        (LeafLog::new("s1"), Witness::new(500), Leaf::new("micro", [1; 32]), Leaf::new("small", [2; 32]))
    }

    fn feed(log: &mut LeafLog, w: &mut Witness, n: u64) -> Vec<LogEntry> {
        (1..=n)
            .map(|i| {
                let e = log.append(i * 100, &item_digest(&format!("item{i}")));
                w.check_entry("s1", &e, i * 100 + 5).unwrap();
                w.commit_entry("s1", &e, i * 100 + 5).unwrap();
                e
            })
            .collect()
    }

    #[test]
    fn an_in_order_log_is_witnessed_and_cosigned() {
        let (mut log, mut w, micro, small) = setup();
        feed(&mut log, &mut w, 5);
        let cp = log.checkpoint(600, &micro).unwrap();
        let c = w.cosign(&cp, &micro.public_key(), &small, 700).unwrap();
        assert_eq!(verify_cosigned(&c, &micro.public_key(), &small.public_key(), 800, 1000), Ok(()));
        assert_eq!(w.state("s1").unwrap().0, 5);
    }

    #[test]
    fn a_dropped_entry_is_a_gap_and_the_checkpoint_over_it_is_not_cosigned() {
        let (mut log, mut w, micro, small) = setup();
        feed(&mut log, &mut w, 2);
        let _lost = log.append(300, "d3");
        let e4 = log.append(400, "d4");
        assert_eq!(w.check_entry("s1", &e4, 405), Err(WitnessRefusal::Gap { expected: 3, found: 4 }));
        let cp = log.checkpoint(500, &micro).unwrap();
        assert_eq!(
            w.cosign(&cp, &micro.public_key(), &small, 600),
            Err(WitnessRefusal::MissingEntries { claimed: 4, witnessed: 2 })
        );
    }

    #[test]
    fn a_gap_heals_when_the_missing_entries_arrive_in_order() {
        let (mut log, mut w, micro, small) = setup();
        let e1 = log.append(100, "d1");
        let e2 = log.append(200, "d2");
        let e3 = log.append(300, "d3");
        w.commit_entry("s1", &e1, 105).unwrap();
        // 3 arrives before 2: refused, state unchanged. Then 2, 3 in order.
        assert!(matches!(w.check_entry("s1", &e3, 305), Err(WitnessRefusal::Gap { .. })));
        w.commit_entry("s1", &e2, 205).unwrap();
        w.commit_entry("s1", &e3, 305).unwrap();
        let cp = log.checkpoint(400, &micro).unwrap();
        assert!(w.cosign(&cp, &micro.public_key(), &small, 410).is_ok());
    }

    #[test]
    fn a_repeated_entry_is_a_duplicate_and_a_conflicting_one_is_equivocation() {
        let (mut log, mut w, ..) = setup();
        let es = feed(&mut log, &mut w, 3);
        assert_eq!(w.check_entry("s1", &es[2], 400), Err(WitnessRefusal::Duplicate { seq: 3 }));
        assert_eq!(w.check_entry("s1", &es[0], 400), Err(WitnessRefusal::Duplicate { seq: 1 }));
        let mut forged = es[1].clone();
        forged.digest = "other".into();
        assert_eq!(w.check_entry("s1", &forged, 400), Err(WitnessRefusal::Equivocation { seq: 2 }));
    }

    #[test]
    fn a_tampered_or_forked_entry_is_refused() {
        let (mut log, mut w, ..) = setup();
        feed(&mut log, &mut w, 2);
        let mut e = log.append(300, "d3");
        e.ts_ms = 301;
        assert_eq!(w.check_entry("s1", &e, 400), Err(WitnessRefusal::BadHash { seq: 3 }));
        let mut forked = LeafLog::new("s1");
        forked.append(100, "x");
        forked.append(200, "y");
        let f3 = forked.append(300, "d3");
        assert_eq!(w.check_entry("s1", &f3, 400), Err(WitnessRefusal::BrokenLink { seq: 3 }));
    }

    #[test]
    fn delay_is_measured_against_the_fastest_delivery() {
        let (mut log, mut w, ..) = setup();
        for i in 1..=3u64 {
            let e = log.append(i * 100, "d");
            assert_eq!(w.check_entry("s1", &e, i * 100 + 10), Ok(Timing::OnTime));
            w.commit_entry("s1", &e, i * 100 + 10).unwrap();
        }
        let e = log.append(400, "d");
        assert_eq!(w.check_entry("s1", &e, 400 + 10 + 499), Ok(Timing::OnTime));
        assert_eq!(w.check_entry("s1", &e, 400 + 10 + 501), Ok(Timing::Late { by_ms: 501 }));
    }

    #[test]
    fn checkpoints_must_be_the_leafs_and_the_heads_must_agree() {
        let (mut log, mut w, micro, small) = setup();
        feed(&mut log, &mut w, 3);
        let cp = log.checkpoint(400, &micro).unwrap();
        let other = Leaf::new("micro", [9; 32]);
        assert_eq!(w.cosign(&cp, &other.public_key(), &small, 1), Err(WitnessRefusal::BadCheckpointSignature));
        let mut bent = cp.clone();
        bent.checkpoint.head = "00".repeat(32);
        assert_eq!(w.cosign(&bent, &micro.public_key(), &small, 1), Err(WitnessRefusal::BadCheckpointSignature));
        // A properly signed checkpoint over a head the witness never saw.
        let mut other_log = LeafLog::new("s1");
        for i in 1..=3 {
            other_log.append(i * 100, "different");
        }
        let cp2 = other_log.checkpoint(400, &micro).unwrap();
        assert_eq!(w.cosign(&cp2, &micro.public_key(), &small, 1), Err(WitnessRefusal::HeadMismatch { size: 3 }));
    }

    #[test]
    fn an_older_checkpoint_is_cosigned_against_history() {
        let (mut log, mut w, micro, small) = setup();
        feed(&mut log, &mut w, 2);
        let early = log.checkpoint(300, &micro).unwrap();
        let mut es = Vec::new();
        for i in 3..=6u64 {
            let e = log.append(i * 100, "d");
            w.commit_entry("s1", &e, i * 100 + 5).unwrap();
            es.push(e);
        }
        assert!(w.cosign(&early, &micro.public_key(), &small, 900).is_ok());
        let empty = LeafLog::new("s1").checkpoint(0, &micro).unwrap();
        assert!(w.cosign(&empty, &micro.public_key(), &small, 900).is_ok());
    }

    #[test]
    fn a_stale_cosignature_is_refused_by_the_consumer() {
        let (mut log, mut w, micro, small) = setup();
        feed(&mut log, &mut w, 1);
        let c = w.cosign(&log.checkpoint(200, &micro).unwrap(), &micro.public_key(), &small, 1_000).unwrap();
        assert!(matches!(
            verify_cosigned(&c, &micro.public_key(), &small.public_key(), 50_000, 10_000),
            Err(WitnessRefusal::StaleCosignature { .. })
        ));
        let mut c2 = c.clone();
        c2.witnessed_at_ms = 49_000;
        assert_eq!(verify_cosigned(&c2, &micro.public_key(), &small.public_key(), 50_000, 10_000), Err(WitnessRefusal::BadCosignature));
    }

    #[test]
    fn a_journal_rebuilds_the_witness() {
        let (mut log, mut w, ..) = setup();
        let es = feed(&mut log, &mut w, 4);
        let mut r = Witness::new(500);
        for e in &es {
            r.restore_entry("s1", e).unwrap();
        }
        assert_eq!(r.state("s1"), w.state("s1"));
        let mut r2 = Witness::new(500);
        r2.restore_entry("s1", &es[0]).unwrap();
        assert!(r2.restore_entry("s1", &es[2]).is_err());
    }

    /// Randomly dropped, repeated and reordered frames: whatever the witness
    /// commits is exactly the in-order prefix of what the leaf produced, and a
    /// checkpoint is cosigned exactly when the whole prefix arrived.
    #[test]
    fn lossy_delivery_never_commits_anything_but_the_true_prefix() {
        let mut seed = 0x2545F4914F6CDD1Du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (micro, small) = (Leaf::new("micro", [1; 32]), Leaf::new("small", [2; 32]));
        for loss_pct in [0u64, 10, 30] {
            let mut log = LeafLog::new("s1");
            let mut w = Witness::new(1_000_000);
            let mut sent = Vec::new();
            for i in 1..=300u64 {
                sent.push(log.append(i * 10, &format!("d{i}")));
            }
            for (i, e) in sent.iter().enumerate() {
                let r = next() % 100;
                if r < loss_pct {
                    continue;
                }
                let _ = w.commit_entry("s1", e, e.ts_ms + 1);
                if r % 7 == 0 {
                    let _ = w.commit_entry("s1", e, e.ts_ms + 1); // repeated
                }
                if r % 11 == 0 && i > 3 {
                    let _ = w.commit_entry("s1", &sent[i - 3], 1); // replayed old
                }
            }
            let (size, head) = w.state("s1").map(|(s, h)| (s, h.to_string())).unwrap_or((0, genesis("s1")));
            // The committed state is a prefix of what was produced.
            let expect_head = if size == 0 { genesis("s1") } else { sent[size as usize - 1].hash.clone() };
            assert_eq!(head, expect_head);
            let cp = log.checkpoint(5_000, &micro).unwrap();
            let r = w.cosign(&cp, &micro.public_key(), &small, 6_000);
            if size < 300 {
                assert!(matches!(r, Err(WitnessRefusal::MissingEntries { .. })), "{r:?}");
            } else {
                assert!(r.is_ok());
            }
            if loss_pct == 0 {
                assert_eq!(size, 300);
            }
        }
    }
}
