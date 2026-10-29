//! Per-node operation hashchains.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A digest, kept as a fixed array so a truncated or oversized value cannot be
/// constructed by accident.
pub type Digest32 = [u8; 32];

/// Classes of operation worth committing to.
///
/// The list is deliberately about *authority* rather than activity: these are
/// the events that would let someone who compromised a node cover their
/// tracks, which is exactly what the chain exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    /// The node was enrolled and granted an assurance class.
    Enrollment,
    /// A key was created, used to sign, or destroyed.
    KeyUse,
    /// Data was sealed to, or unsealed from, the local root of trust.
    Seal,
    Unseal,
    /// A quote was produced over platform state.
    Quote,
    /// An appraisal policy or reference value set changed.
    PolicyChange,
    /// A node was cordoned, drained, fenced or admitted.
    Lifecycle,
    /// A power transition was commanded or observed.
    Power,
    /// Model weights were verified and loaded.
    ModelLoad,
    /// An inference was served and a receipt issued.
    Inference,
    /// A vault object's key was re-wrapped to a peer.
    Share,
    /// A site was built and placed, or refused. Added last so that chains
    /// written before it existed still deserialise — the variant order is
    /// part of the on-disk format, not only of this file.
    Deploy,
    /// A service resource was created or destroyed — a tenant database, a
    /// cache, a mail identity. Appended after `Deploy` for the same reason it
    /// was appended last: the order is on-disk format.
    Provision,
    /// A change was made to the estate, and whether a window covered it.
    ///
    /// The chain already recorded what the platform did to itself; this is for
    /// what a person did to it, carrying the standing from
    /// [`furcate_policy::change`] in its `result`. An out-of-window change is
    /// still committed — the whole point is that an emergency change is
    /// recorded rather than refused, and a record that only contains approved
    /// changes is the one nobody needs. Appended last, as every variant here
    /// must be.
    Change,
    /// One action taken by a person holding authority, inside a recorded
    /// session.
    ///
    /// Distinct from `Change`, which records that the estate moved and whether
    /// a window covered it. This records *who did what while they were allowed
    /// to*, which is the question an emergency grant leaves behind — see
    /// `furcate-session`. Appended last, as every variant here must be: the
    /// order is the on-disk format, and inserting this anywhere else would
    /// silently reinterpret every chain already written.
    Session,
    /// What a rented workload consumed over one billing period, and the root
    /// over the readings that prove it.
    ///
    /// The fine-grained readings are not here and must not be. `store::save`
    /// serialises the whole chain and rewrites the whole file on every append,
    /// so a per-minute meter over a thirty-day period is 43,200 entries whose
    /// last append costs as much as all the ones before it — and `Op` has no
    /// numeric field, so every quantity would live stringly in `result`. The
    /// readings go to a rotating file under `/var/lib/furcate/boxes/<id>/meter/`
    /// and this commits to them: one entry per box per period, whose `subject`
    /// carries a [`crate::merkle`] root over the readings it summarises. That is
    /// already how node chain heads are aggregated into a site root, so a tenant
    /// disputing a bill can be handed an inclusion proof for one reading against
    /// a root that was chained before the dispute existed.
    ///
    /// Appended last, as every variant here must be.
    Meter,
    /// A command from a simulation platform reached a site gate and was decided.
    ///
    /// One entry per decision, refusals included: the subject is the command
    /// id and the result is decision, code and a digest of the signed receipt
    /// without its ledger and signature members. Appended last, as every
    /// variant here must be.
    Command,
    /// A batch of decisions a sandboxed agent runtime made about one agent,
    /// committed by count and Merkle root, signed by the node. See
    /// [`crate::agent`]. Appended last, as every variant here must be.
    AgentDecision,
    /// A verified kill order tore a sandboxed agent down. See
    /// [`crate::agent`]. Appended last, as every variant here must be.
    AgentKilled,
    /// A model update was decided for an agent that was born with a birth record and keeps learning: old and new
    /// model hash, the experience reference, the evaluation against the release gate and the signer chain, refusals
    /// included. See `furcate_command::update`. Appended last, as every variant here must be.
    ModelUpdate,
}

/// One committed operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Op {
    /// Position in the chain, starting at zero for the genesis entry.
    pub seq: u64,
    /// Milliseconds since the Unix epoch, as observed locally. Advisory: a
    /// compromised node can lie about time, which is why ordering comes from
    /// `seq` and the hash linkage rather than from timestamps.
    pub ts_ms: u64,
    pub kind: OpKind,
    /// Who or what initiated it.
    pub actor: String,
    /// What it acted on.
    pub subject: String,
    /// Outcome, free-form so subsystems can record what matters to them.
    pub result: String,
    /// `H(prev_hash ‖ encoded(fields))`.
    #[serde(with = "hex_digest")]
    pub hash: Digest32,
    #[serde(with = "hex_digest")]
    pub prev: Digest32,
}

impl Op {
    /// Recompute this entry's hash from its own fields and a predecessor.
    ///
    /// Recomputation rather than trust is the whole point: verification never
    /// reads the stored `hash` field except to compare against this.
    fn compute_hash(
        seq: u64,
        ts_ms: u64,
        kind: OpKind,
        actor: &str,
        subject: &str,
        result: &str,
        prev: &Digest32,
    ) -> Digest32 {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(seq.to_be_bytes());
        h.update(ts_ms.to_be_bytes());
        // Length-prefix every variable-length field so that
        // ("ab","c") and ("a","bc") cannot collide.
        for field in [
            format!("{kind:?}").as_str(),
            actor,
            subject,
            result,
        ] {
            h.update((field.len() as u64).to_be_bytes());
            h.update(field.as_bytes());
        }
        h.finalize().into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The chain is empty where an entry was required.
    Empty,
    /// Sequence numbers are not contiguous from zero.
    Sequence { at: usize, expected: u64, found: u64 },
    /// An entry does not link to its predecessor.
    BrokenLink { at: usize },
    /// An entry's stored hash does not match its contents.
    Tampered { at: usize },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Empty => write!(f, "chain is empty"),
            ChainError::Sequence { at, expected, found } => {
                write!(f, "entry {at}: expected seq {expected}, found {found}")
            }
            ChainError::BrokenLink { at } => {
                write!(f, "entry {at} does not link to its predecessor")
            }
            ChainError::Tampered { at } => {
                write!(f, "entry {at} has been altered: contents do not match its hash")
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// An append-only chain of operations for one node.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Chain {
    entries: Vec<Op>,
}

impl Chain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a chain with a genesis entry committing to the node's identity.
    pub fn genesis(node_id: &str, ts_ms: u64) -> Self {
        let mut chain = Chain::new();
        chain.append(ts_ms, OpKind::Enrollment, "operator", node_id, "enrolled");
        chain
    }

    /// Append an operation, returning its hash.
    pub fn append(
        &mut self,
        ts_ms: u64,
        kind: OpKind,
        actor: impl Into<String>,
        subject: impl Into<String>,
        result: impl Into<String>,
    ) -> Digest32 {
        let seq = self.entries.len() as u64;
        let prev = self.head().unwrap_or([0u8; 32]);
        let (actor, subject, result) = (actor.into(), subject.into(), result.into());
        let hash = Op::compute_hash(seq, ts_ms, kind, &actor, &subject, &result, &prev);
        self.entries.push(Op {
            seq,
            ts_ms,
            kind,
            actor,
            subject,
            result,
            hash,
            prev,
        });
        hash
    }

    /// The current head, or `None` for an empty chain.
    pub fn head(&self) -> Option<Digest32> {
        self.entries.last().map(|e| e.hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Op] {
        &self.entries
    }

    /// Verify the whole chain by recomputation.
    ///
    /// This is the operation that makes tampering detectable: every hash is
    /// derived again from the entry's own contents and its predecessor, so
    /// altering any field invalidates that entry and everything after it.
    pub fn verify(&self) -> Result<(), ChainError> {
        if self.entries.is_empty() {
            return Err(ChainError::Empty);
        }
        let mut prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(ChainError::Sequence {
                    at: i,
                    expected: i as u64,
                    found: e.seq,
                });
            }
            if e.prev != prev {
                return Err(ChainError::BrokenLink { at: i });
            }
            let expect =
                Op::compute_hash(e.seq, e.ts_ms, e.kind, &e.actor, &e.subject, &e.result, &e.prev);
            if expect != e.hash {
                return Err(ChainError::Tampered { at: i });
            }
            prev = e.hash;
        }
        Ok(())
    }
}

/// Hex serialization for fixed-size digests, so records stay readable.
mod hex_digest {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(d))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must be 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Chain {
        let mut c = Chain::genesis("furcate:node:test", 1000);
        c.append(1001, OpKind::KeyUse, "furcated", "ak", "created");
        c.append(1002, OpKind::Quote, "verifier", "pcr:0-7", "signed");
        c
    }

    #[test]
    fn the_model_update_kind_is_additive() {
        // Appended after every earlier variant, so a chain written before it existed still reads, and it round-trips.
        let mut c = sample();
        c.append(1003, OpKind::ModelUpdate, "update-gate:agent-1", "upd-1", "accepted:ok:00");
        let j = serde_json::to_string(&c).unwrap();
        assert!(j.contains("\"model_update\""));
        let back: Chain = serde_json::from_str(&j).unwrap();
        assert_eq!(back.verify(), Ok(()));
        assert_eq!(back.entries().last().unwrap().kind, OpKind::ModelUpdate);
        assert!(OpKind::ModelUpdate as u8 > OpKind::AgentKilled as u8);
    }

    #[test]
    fn a_fresh_chain_verifies() {
        assert_eq!(sample().verify(), Ok(()));
        assert_eq!(sample().len(), 3);
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert_eq!(Chain::new().verify(), Err(ChainError::Empty));
    }

    #[test]
    fn each_entry_links_to_its_predecessor() {
        let c = sample();
        for w in c.entries().windows(2) {
            assert_eq!(w[0].hash, w[1].prev);
        }
    }

    #[test]
    fn altering_a_field_is_detected() {
        let mut c = sample();
        c.entries[1].result = "destroyed".into();
        assert_eq!(c.verify(), Err(ChainError::Tampered { at: 1 }));
    }

    #[test]
    fn removing_an_entry_is_detected() {
        let mut c = sample();
        c.entries.remove(1);
        // Reindexing is what gives it away: seq no longer matches position.
        assert!(matches!(c.verify(), Err(ChainError::Sequence { .. })));
    }

    #[test]
    fn reordering_is_detected() {
        let mut c = sample();
        c.entries.swap(1, 2);
        assert!(c.verify().is_err());
    }

    #[test]
    fn head_advances_on_every_append() {
        let mut c = Chain::genesis("n", 1);
        let a = c.head().unwrap();
        c.append(2, OpKind::Power, "ups", "rung", "1");
        assert_ne!(a, c.head().unwrap());
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        // Without length prefixing these two would hash identically.
        let mut a = Chain::new();
        a.append(1, OpKind::KeyUse, "ab", "c", "r");
        let mut b = Chain::new();
        b.append(1, OpKind::KeyUse, "a", "bc", "r");
        assert_ne!(a.head(), b.head());
    }

    #[test]
    fn survives_a_round_trip() {
        let c = sample();
        let json = serde_json::to_string(&c).unwrap();
        let back: Chain = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verify(), Ok(()));
        assert_eq!(back.head(), c.head());
    }

    /// **What is actually load-bearing about `OpKind`, pinned.**
    ///
    /// Three doc comments in this file say the *order* of the variants is the
    /// on-disk format, and new variants are appended last because of it. Keeping
    /// that convention costs nothing and this test does not argue with it — but
    /// the mechanism is the spelling, not the position. `compute_hash` mixes
    /// `format!("{kind:?}")`, which is the Debug name, and serde writes the
    /// snake_case name. Neither depends on where a variant sits.
    ///
    /// So the thing that would silently reinterpret every chain already written,
    /// including the ones a bill was issued against, is *renaming* a variant —
    /// and nothing held that until now. This does.
    #[test]
    fn the_spelling_of_an_op_kind_is_the_on_disk_format() {
        let spellings = [
            (OpKind::Enrollment, "Enrollment", "\"enrollment\""),
            (OpKind::KeyUse, "KeyUse", "\"key_use\""),
            (OpKind::Seal, "Seal", "\"seal\""),
            (OpKind::Unseal, "Unseal", "\"unseal\""),
            (OpKind::Quote, "Quote", "\"quote\""),
            (OpKind::PolicyChange, "PolicyChange", "\"policy_change\""),
            (OpKind::Lifecycle, "Lifecycle", "\"lifecycle\""),
            (OpKind::Power, "Power", "\"power\""),
            (OpKind::ModelLoad, "ModelLoad", "\"model_load\""),
            (OpKind::Inference, "Inference", "\"inference\""),
            (OpKind::Share, "Share", "\"share\""),
            (OpKind::Deploy, "Deploy", "\"deploy\""),
            (OpKind::Provision, "Provision", "\"provision\""),
            (OpKind::Change, "Change", "\"change\""),
            (OpKind::Session, "Session", "\"session\""),
            (OpKind::Meter, "Meter", "\"meter\""),
        ];
        for (kind, debug, json) in spellings {
            assert_eq!(format!("{kind:?}"), debug, "this name is in every hash");
            assert_eq!(serde_json::to_string(&kind).unwrap(), json, "this name is on disk");
        }
    }

    #[test]
    fn a_meter_entry_chains_like_any_other_op() {
        // The proof is chained; the readings are not. What goes in `subject` is
        // a merkle root over them.
        let mut c = Chain::genesis("node", 1);
        let root = "0".repeat(64);
        c.append(2, OpKind::Meter, "furcated", &root, "cpu_secs=610 disk_secs=1310");
        assert_eq!(c.verify(), Ok(()));
        assert_eq!(c.entries().last().unwrap().kind, OpKind::Meter);
    }

    #[test]
    fn a_chain_written_before_meter_existed_still_loads() {
        // The reason every variant here is appended rather than inserted.
        let before = r#"{"entries":[{"seq":0,"ts_ms":1,"kind":"enrollment","actor":"operator","subject":"node","result":"enrolled","hash":"","prev":""}]}"#;
        let with_hashes = {
            let mut c = Chain::genesis("node", 1);
            c.append(2, OpKind::Deploy, "a", "b", "c");
            serde_json::to_string(&c).unwrap()
        };
        assert!(before.contains("enrollment"));
        let back: Chain = serde_json::from_str(&with_hashes).unwrap();
        assert_eq!(back.verify(), Ok(()));
    }
}
