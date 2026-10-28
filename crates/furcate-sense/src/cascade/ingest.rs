//! Verifying what a micro processing node sends, and recording what is refused.
//!
//! A frame is one signed item from the node below, with its log entry: a
//! reading, an embedding window, or a log checkpoint. Everything the item
//! claims is checked against this rung's own records before it is used:
//!
//! 1. the envelope signature, against the key of the processing node enrolled
//!    for that sensing node;
//! 2. the rungs it claims to have passed ([`chain::validate`]), which also
//!    computes the class the item may be treated as;
//! 3. the signatures of any rungs added after the signing node;
//! 4. the log entry: the item is the one the entry commits to, and the entry
//!    continues the witnessed chain with nothing dropped, repeated or altered;
//! 5. replay: the reading's own signature and sequence, or the window sequence;
//! 6. the model binding, when the policy holds a [`BindingRegistry`]: the model,
//!    epoch and calibration the node states it ran, checked against the registry;
//! 7. the operator's policy: the lowest class accepted, and a delay bound.
//!
//! Nothing is accepted by default and nothing is dropped silently. A frame that
//! fails any step is refused with a [`Refusal`] that is counted, kept and handed
//! to the sink, including a frame that is authentic but below policy.
//!
//! Steps 1 to 5 change no state until all have passed, so a forged frame cannot
//! use up a sequence number or advance the log. A frame that passes them is
//! entered in the witnessed log even if step 6 or 7 then refuses it: the log records
//! what the node emitted, whether or not this rung acts on it, and a policy
//! refusal must not leave a gap that blocks every frame behind it.

use super::binding::{BindingRefusal, BindingRegistry};
use super::chain::{self, ChainRefusal, ChainReport};
use super::directory::Directory;
use super::signer::CascadeSigner;
use super::witness::{item_digest, Cosigned, LogEntry, SignedCheckpoint, Timing, Witness, WitnessRefusal};
use crate::leaf::{Attachment, LeafError, ParentPort};
use crate::nicla::{
    verify_countersignature_list, BridgedReading, Countersignature, ModelRef, NodeRole, Provenance, ENVELOPE_DOMAIN,
};
use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const EMBEDDING_DOMAIN: &str = "furcate/bridged-embedding/v1";

/// One window's embedding, as the micro processing node's model produced it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingWindow {
    /// The sensing node the window was read from.
    pub leaf_id: String,
    /// Increases by one per window from that node.
    pub window_seq: u64,
    pub taken_at: u64,
    /// The model on the micro processing node that produced the values.
    pub model: ModelRef,
    pub values: Vec<i8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgedEmbedding {
    pub window: EmbeddingWindow,
    pub provenance: Provenance,
    pub envelope_signature: String,
    pub countersignatures: Vec<Countersignature>,
}

pub fn embedding_message(w: &EmbeddingWindow, p: &Provenance) -> Vec<u8> {
    let (wj, pj) = (serde_json::to_vec(w).unwrap_or_default(), serde_json::to_vec(p).unwrap_or_default());
    let mut m = Vec::new();
    m.extend((wj.len() as u64).to_be_bytes());
    m.extend(wj);
    m.extend((pj.len() as u64).to_be_bytes());
    m.extend(pj);
    m
}

/// Sign an embedding as the processing node that read the sensing node.
pub fn sign_embedding(
    signer: &dyn CascadeSigner,
    window: EmbeddingWindow,
    provenance: Provenance,
) -> Result<BridgedEmbedding, String> {
    let envelope_signature = signer.sign_message(EMBEDDING_DOMAIN, &embedding_message(&window, &provenance))?;
    Ok(BridgedEmbedding { window, provenance, envelope_signature, countersignatures: Vec::new() })
}

/// What a micro processing node sends to the rung above.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case")]
pub enum Frame {
    Reading { item: BridgedReading, entry: LogEntry },
    Embedding { item: BridgedEmbedding, entry: LogEntry },
    Checkpoint { checkpoint: SignedCheckpoint },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    UnknownSource,
    BadEnvelopeSignature,
    BadReadingSignature,
    ReplayedReading { last: u64, found: u64 },
    ReplayedWindow { last: u64, found: u64 },
    Chain(ChainRefusal),
    BadCountersignature,
    LogDigestMismatch,
    Log(WitnessRefusal),
    BelowFloor { required: AssuranceClass, found: AssuranceClass },
    Late { by_ms: u64 },
    Binding(BindingRefusal),
}

impl RefusalReason {
    pub fn code(&self) -> &'static str {
        use RefusalReason::*;
        match self {
            UnknownSource => "unknown_source",
            BadEnvelopeSignature => "bad_envelope_signature",
            BadReadingSignature => "bad_reading_signature",
            ReplayedReading { .. } => "replayed_reading",
            ReplayedWindow { .. } => "replayed_window",
            Chain(_) => "chain",
            BadCountersignature => "bad_countersignature",
            LogDigestMismatch => "log_digest_mismatch",
            Log(WitnessRefusal::Gap { .. }) => "log_gap",
            Log(WitnessRefusal::Duplicate { .. }) => "log_duplicate",
            Log(_) => "log",
            BelowFloor { .. } => "below_floor",
            Late { .. } => "late",
            Binding(b) => b.code(),
        }
    }
}

impl std::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RefusalReason::*;
        match self {
            UnknownSource => write!(f, "no processing node is enrolled for this sensing node"),
            BadEnvelopeSignature => write!(f, "the envelope is not signed by the enrolled processing node"),
            BadReadingSignature => write!(f, "the reading is not signed by the enrolled processing node"),
            ReplayedReading { last, found } => write!(f, "reading sequence {found} is not ahead of {last}"),
            ReplayedWindow { last, found } => write!(f, "window sequence {found} is not ahead of {last}"),
            Chain(c) => write!(f, "{c}"),
            BadCountersignature => write!(f, "a rung added after the signing node does not verify"),
            LogDigestMismatch => write!(f, "the log entry does not commit to this item"),
            Log(w) => write!(f, "{w}"),
            BelowFloor { required, found } => write!(f, "item is `{found}`, the policy requires `{required}`"),
            Late { by_ms } => write!(f, "arrived {by_ms} ms later than the fastest delivery seen"),
            Binding(b) => write!(f, "{b}"),
        }
    }
}

/// A recorded refusal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Refusal {
    pub at_ms: u64,
    pub source: String,
    pub item: String,
    pub code: String,
    pub detail: String,
}

impl Refusal {
    fn new(at_ms: u64, source: &str, item: String, reason: &RefusalReason) -> Self {
        Self { at_ms, source: source.to_string(), item, code: reason.code().to_string(), detail: reason.to_string() }
    }
}

/// Where refusals go besides memory. A failing sink is not an excuse to accept.
pub trait RefusalSink: Send {
    fn record(&mut self, r: &Refusal);
}

#[derive(Clone, Debug)]
pub struct IngestPolicy {
    /// The lowest class an item may be treated as, after the whole chain.
    pub min_effective: AssuranceClass,
    /// A rung the chain must contain (for a next rung: the rung below it).
    pub required_rung: Option<NodeRole>,
    /// Extra delay beyond the fastest delivery seen, in milliseconds.
    pub max_delay_ms: u64,
    /// Whether a late item is refused. The log still records it.
    pub refuse_late: bool,
    /// What model, epoch and calibration bindings are accepted. With a registry
    /// every item must carry a binding; without one, bindings are not checked.
    pub bindings: Option<BindingRegistry>,
}

impl Default for IngestPolicy {
    fn default() -> Self {
        Self { min_effective: AssuranceClass::Soft, required_rung: None, max_delay_ms: 5_000, refuse_late: true, bindings: None }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedReading {
    pub item: BridgedReading,
    pub report: ChainReport,
    pub timing: Timing,
}

#[derive(Clone, Debug)]
pub struct VerifiedEmbedding {
    pub item: BridgedEmbedding,
    pub report: ChainReport,
    pub timing: Timing,
}

#[derive(Clone, Debug)]
pub enum Accepted {
    Reading(VerifiedReading),
    Embedding(VerifiedEmbedding),
    Checkpoint(Cosigned),
}

/// Recent refusals kept in memory; the total is counted separately.
const KEEP_REFUSALS: usize = 1000;

pub struct Ingest {
    dir: Directory,
    port: ParentPort,
    witness: Witness,
    signer: Arc<dyn CascadeSigner>,
    policy: IngestPolicy,
    last_window: BTreeMap<String, u64>,
    last_epoch: BTreeMap<String, u32>,
    refusals: std::collections::VecDeque<Refusal>,
    refused_total: u64,
    sink: Option<Box<dyn RefusalSink>>,
}

impl Ingest {
    pub fn new(dir: Directory, signer: Arc<dyn CascadeSigner>, policy: IngestPolicy) -> Self {
        let mut port = ParentPort::new();
        for (sensing, gateway) in dir.sensing_nodes() {
            // The sensing node holds no key; the processing node signs for it,
            // and the class of the sensing node is the lowest, so no custody.
            port.accept(Attachment {
                leaf_id: sensing.to_string(),
                parent: signer.node_id().to_string(),
                public_key: gateway.public_key.clone(),
                key_custody: None,
                attached_at: 0,
            });
        }
        let witness = Witness::new(policy.max_delay_ms);
        Self {
            dir,
            port,
            witness,
            signer,
            policy,
            last_window: BTreeMap::new(),
            last_epoch: BTreeMap::new(),
            refusals: Default::default(),
            refused_total: 0,
            sink: None,
        }
    }

    pub fn with_sink(mut self, sink: Box<dyn RefusalSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn directory(&self) -> &Directory {
        &self.dir
    }

    pub fn witness(&self) -> &Witness {
        &self.witness
    }

    pub fn refused_total(&self) -> u64 {
        self.refused_total
    }

    pub fn recent_refusals(&self) -> impl Iterator<Item = &Refusal> {
        self.refusals.iter()
    }

    /// Rebuild the witnessed log from a journal entry. The chain is checked.
    pub fn restore_entry(&mut self, leaf_id: &str, e: &LogEntry) -> Result<(), WitnessRefusal> {
        self.witness.restore_entry(leaf_id, e)
    }

    fn refuse(&mut self, now_ms: u64, source: &str, item: String, reason: RefusalReason) -> Refusal {
        let r = Refusal::new(now_ms, source, item, &reason);
        self.refused_total += 1;
        if self.refusals.len() == KEEP_REFUSALS {
            self.refusals.pop_front();
        }
        self.refusals.push_back(r.clone());
        if let Some(s) = self.sink.as_mut() {
            s.record(&r);
        }
        r
    }

    /// Steps 1 to 4 for any item, changing nothing.
    #[allow(clippy::too_many_arguments)]
    fn check_envelope(
        &self,
        source: &str,
        domain: &str,
        message: &[u8],
        envelope_signature: &str,
        provenance: &Provenance,
        counters: &[Countersignature],
        entry: &LogEntry,
        now_ms: u64,
    ) -> Result<(ChainReport, Timing), RefusalReason> {
        self.port.verify_message(source, domain, message, envelope_signature).map_err(|e| match e {
            LeafError::NotAttached => RefusalReason::UnknownSource,
            _ => RefusalReason::BadEnvelopeSignature,
        })?;
        let report = chain::validate(provenance, counters, &self.dir, source, self.policy.required_rung)
            .map_err(RefusalReason::Chain)?;
        verify_countersignature_list(envelope_signature, counters, &|id| self.dir.key_of(id))
            .map_err(|_| RefusalReason::BadCountersignature)?;
        if entry.digest != item_digest(envelope_signature) {
            return Err(RefusalReason::LogDigestMismatch);
        }
        let timing = self.witness.check_entry(source, entry, now_ms).map_err(RefusalReason::Log)?;
        Ok((report, timing))
    }

    /// Step 6, after the item is in the log. The epoch seen from a node moves
    /// only when every binding check passed.
    fn binding_check(
        &mut self,
        source: &str,
        provenance: &Provenance,
        window_model: Option<&ModelRef>,
    ) -> Result<(), RefusalReason> {
        let Some(registry) = self.policy.bindings.as_ref() else { return Ok(()) };
        let b = provenance.binding.as_ref().ok_or(RefusalReason::Binding(BindingRefusal::Missing))?;
        registry.check(source, b, self.last_epoch.get(source).copied()).map_err(RefusalReason::Binding)?;
        if window_model.is_some_and(|m| !m.sha256.starts_with(&b.model)) {
            return Err(RefusalReason::Binding(BindingRefusal::ModelDisagrees));
        }
        self.last_epoch.insert(source.to_string(), b.epoch);
        Ok(())
    }

    /// Step 7, after the item is in the log.
    fn policy_check(&self, report: &ChainReport, timing: Timing) -> Result<(), RefusalReason> {
        if report.effective < self.policy.min_effective {
            return Err(RefusalReason::BelowFloor { required: self.policy.min_effective, found: report.effective });
        }
        if let (Timing::Late { by_ms }, true) = (timing, self.policy.refuse_late) {
            return Err(RefusalReason::Late { by_ms });
        }
        Ok(())
    }

    /// Verify one frame. Every outcome that is not an acceptance is a recorded refusal.
    pub fn accept(&mut self, frame: &Frame, now_ms: u64) -> Result<Accepted, Refusal> {
        match frame {
            Frame::Reading { item, entry } => {
                let source = item.reading.leaf_id.clone();
                let id = item.reading.sensor_id.clone();
                let msg = crate::nicla::envelope_message(&item.reading, &item.provenance);
                let (report, timing) = self
                    .check_envelope(
                        &source,
                        ENVELOPE_DOMAIN,
                        &msg,
                        &item.envelope_signature,
                        &item.provenance,
                        &item.countersignatures,
                        entry,
                        now_ms,
                    )
                    .map_err(|r| self.refuse(now_ms, &source, id.clone(), r))?;
                // The reading's own signature and sequence. This is the one
                // step here that records state, and it is the last that can fail.
                self.port.verify(&item.reading, AssuranceClass::Soft).map_err(|e| {
                    let r = match e {
                        LeafError::StaleSequence { last, found } => RefusalReason::ReplayedReading { last, found },
                        _ => RefusalReason::BadReadingSignature,
                    };
                    self.refuse(now_ms, &source, id.clone(), r)
                })?;
                let _ = self.witness.commit_entry(&source, entry, now_ms);
                self.binding_check(&source, &item.provenance, None)
                    .and_then(|()| self.policy_check(&report, timing))
                    .map_err(|r| self.refuse(now_ms, &source, id, r))?;
                Ok(Accepted::Reading(VerifiedReading { item: item.clone(), report, timing }))
            }
            Frame::Embedding { item, entry } => {
                let source = item.window.leaf_id.clone();
                let id = format!("{source}/emb/{}", item.window.window_seq);
                let msg = embedding_message(&item.window, &item.provenance);
                let (report, timing) = self
                    .check_envelope(
                        &source,
                        EMBEDDING_DOMAIN,
                        &msg,
                        &item.envelope_signature,
                        &item.provenance,
                        &item.countersignatures,
                        entry,
                        now_ms,
                    )
                    .map_err(|r| self.refuse(now_ms, &source, id.clone(), r))?;
                let last = self.last_window.get(&source).copied().unwrap_or(0);
                if item.window.window_seq <= last {
                    let r = RefusalReason::ReplayedWindow { last, found: item.window.window_seq };
                    return Err(self.refuse(now_ms, &source, id, r));
                }
                self.last_window.insert(source.clone(), item.window.window_seq);
                let _ = self.witness.commit_entry(&source, entry, now_ms);
                self.binding_check(&source, &item.provenance, Some(&item.window.model))
                    .and_then(|()| self.policy_check(&report, timing))
                    .map_err(|r| self.refuse(now_ms, &source, id, r))?;
                Ok(Accepted::Embedding(VerifiedEmbedding { item: item.clone(), report, timing }))
            }
            Frame::Checkpoint { checkpoint } => {
                let source = checkpoint.checkpoint.leaf_id.clone();
                let id = format!("checkpoint@{}", checkpoint.checkpoint.size);
                let Some(gateway) = self.dir.gateway_of(&source) else {
                    return Err(self.refuse(now_ms, &source, id, RefusalReason::UnknownSource));
                };
                let key = gateway.public_key.clone();
                self.witness
                    .cosign(checkpoint, &key, self.signer.as_ref(), now_ms)
                    .map(Accepted::Checkpoint)
                    .map_err(|w| self.refuse(now_ms, &source, id, RefusalReason::Log(w)))
            }
        }
    }
}
