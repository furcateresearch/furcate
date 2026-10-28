//! The small processing node.
//!
//! In the cascade this is the first rung that checks everything the one below
//! it says: a Raspberry Pi running Furcate. In the older vocabulary it is a
//! `furcated-lite` worker that is the parent of the micro processing nodes
//! attached to it. It
//!
//! 1. verifies every frame ([`Ingest`]) and refuses and records what fails;
//! 2. cosigns the leaf log checkpoints it can vouch for;
//! 3. runs its model on embedding windows and records the model id and hash in
//!    the hop it adds to the chain;
//! 4. asks its [`EscalationPolicy`] whether the item goes up, and if so signs a
//!    [`Forwarded`] message carrying the extended chain and its answer;
//! 5. counts what it did.
//!
//! It has no I/O of its own. The `furcate-small` command feeds it frames and
//! journals its outcomes.

use super::chain::{self, ChainRefusal, ChainReport};
use super::directory::Directory;
use super::drift::FleetDrift;
use super::escalate::{Decision, EscalationContext, EscalationPolicy, EscalationReason};
use super::ingest::{
    embedding_message, Accepted, BridgedEmbedding, Frame, Ingest, Refusal, EMBEDDING_DOMAIN,
};
use super::model::{Inference, WindowModel};
use super::signer::CascadeSigner;
use super::witness::Cosigned;
use crate::leaf::{verify_with_key, Attachment, ParentPort};
use crate::nicla::{
    countersign_list, envelope_message, verify_countersignature_list, BridgedReading, Countersignature, Derivation,
    Hop, NodeRole, Provenance, ENVELOPE_DOMAIN,
};
use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;

pub const OUTPUT_DOMAIN: &str = "furcate/small-node-output/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ForwardedItem {
    Reading(BridgedReading),
    Embedding(BridgedEmbedding),
}

impl ForwardedItem {
    fn parts(&self) -> (&str, &str, &Provenance, &[Countersignature]) {
        match self {
            ForwardedItem::Reading(r) => (&r.reading.leaf_id, &r.envelope_signature, &r.provenance, &r.countersignatures),
            ForwardedItem::Embedding(e) => (&e.window.leaf_id, &e.envelope_signature, &e.provenance, &e.countersignatures),
        }
    }
}

/// What the small processing node sends to the next rung: the item as it
/// arrived, this rung's hop added to its chain, this rung's answer, and a
/// signature over all of it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Forwarded {
    pub item: ForwardedItem,
    pub inference: Option<Inference>,
    pub reason: EscalationReason,
    pub output_signature: String,
}

fn output_message(env: &str, counters: &[Countersignature], inf: &Option<Inference>, reason: EscalationReason) -> Vec<u8> {
    let mut m = env.as_bytes().to_vec();
    for c in counters {
        m.push(b'|');
        m.extend(c.signature.as_bytes());
    }
    m.push(b'#');
    m.extend(serde_json::to_vec(inf).unwrap_or_default());
    m.push(b'#');
    m.extend(serde_json::to_vec(&reason).unwrap_or_default());
    m
}

pub trait Forwarder: Send {
    fn forward(&mut self, f: &Forwarded) -> Result<(), String>;
}

/// One JSON object per line to any writer: a file, a socket, a pipe.
pub struct JsonLinesForwarder<W: Write + Send>(pub W);

impl<W: Write + Send> Forwarder for JsonLinesForwarder<W> {
    fn forward(&mut self, f: &Forwarded) -> Result<(), String> {
        let mut line = serde_json::to_vec(f).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.0.write_all(&line).and_then(|_| self.0.flush()).map_err(|e| e.to_string())
    }
}

#[derive(Default)]
pub struct MemoryForwarder(pub Vec<Forwarded>);

impl Forwarder for MemoryForwarder {
    fn forward(&mut self, f: &Forwarded) -> Result<(), String> {
        self.0.push(f.clone());
        Ok(())
    }
}

#[derive(Debug)]
pub enum Outcome {
    Refused(Refusal),
    /// Verified and kept at this rung.
    Kept { inference: Option<Inference> },
    /// Verified, extended with this rung, and passed up.
    Escalated { reason: EscalationReason, inference: Option<Inference> },
    /// Verified and meant to go up, but the forward failed. Never silent.
    ForwardFailed { reason: EscalationReason, error: String },
    Cosigned(Cosigned),
    /// A verified reading this node was not configured to pass on.
    Stored,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub readings: u64,
    pub embeddings: u64,
    pub refused: u64,
    pub kept: u64,
    pub escalated: u64,
    pub forward_failed: u64,
    pub cosigned: u64,
}

pub struct SmallNode {
    ingest: Ingest,
    signer: Arc<dyn CascadeSigner>,
    /// The class this node's own key earns, from its root of trust.
    own_level: AssuranceClass,
    model: Option<Box<dyn WindowModel>>,
    policy: Box<dyn EscalationPolicy>,
    forwarder: Box<dyn Forwarder>,
    forward_readings: bool,
    stats: Stats,
    drift: Option<FleetDrift>,
}

impl SmallNode {
    pub fn new(
        ingest: Ingest,
        signer: Arc<dyn CascadeSigner>,
        own_level: AssuranceClass,
        model: Option<Box<dyn WindowModel>>,
        policy: Box<dyn EscalationPolicy>,
        forwarder: Box<dyn Forwarder>,
    ) -> Self {
        Self { ingest, signer, own_level, model, policy, forwarder, forward_readings: false, stats: Stats::default(), drift: None }
    }

    /// Pass verified readings up unprocessed, with this rung added.
    pub fn forward_readings(mut self, yes: bool) -> Self {
        self.forward_readings = yes;
        self
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Watch the embeddings of each sensing node for drift and attribute its cause.
    pub fn with_drift(mut self, drift: FleetDrift) -> Self {
        self.drift = Some(drift);
        self
    }

    pub fn drift(&self) -> Option<&FleetDrift> {
        self.drift.as_ref()
    }

    pub fn drift_mut(&mut self) -> Option<&mut FleetDrift> {
        self.drift.as_mut()
    }

    pub fn ingest(&self) -> &Ingest {
        &self.ingest
    }

    pub fn ingest_mut(&mut self) -> &mut Ingest {
        &mut self.ingest
    }

    fn escalate(&mut self, item: ForwardedItem, inference: Option<Inference>, reason: EscalationReason) -> Outcome {
        let hop = Hop {
            role: NodeRole::SmallProcessing,
            node_id: self.signer.node_id().to_string(),
            attestation_level: self.own_level,
            derivation: match &inference {
                Some(i) => Derivation::Model(i.model.clone()),
                None => Derivation::Relayed,
            },
        };
        let mut item = item;
        let (env, counters) = match &mut item {
            ForwardedItem::Reading(r) => (r.envelope_signature.clone(), &mut r.countersignatures),
            ForwardedItem::Embedding(e) => (e.envelope_signature.clone(), &mut e.countersignatures),
        };
        let fail = |this: &mut Self, error: String| {
            this.stats.forward_failed += 1;
            Outcome::ForwardFailed { reason, error }
        };
        if let Err(e) = countersign_list(&env, counters, self.signer.as_ref(), hop) {
            return fail(self, e.to_string());
        }
        let msg = output_message(&env, counters, &inference, reason);
        let output_signature = match self.signer.sign_message(OUTPUT_DOMAIN, &msg) {
            Ok(s) => s,
            Err(e) => return fail(self, e),
        };
        let f = Forwarded { item, inference: inference.clone(), reason, output_signature };
        match self.forwarder.forward(&f) {
            Ok(()) => {
                self.stats.escalated += 1;
                Outcome::Escalated { reason, inference }
            }
            Err(e) => fail(self, e),
        }
    }

    /// Handle one frame from the rung below.
    pub fn handle(&mut self, frame: &Frame, now_ms: u64) -> Outcome {
        match self.ingest.accept(frame, now_ms) {
            Err(r) => {
                self.stats.refused += 1;
                Outcome::Refused(r)
            }
            Ok(Accepted::Checkpoint(c)) => {
                self.stats.cosigned += 1;
                Outcome::Cosigned(c)
            }
            Ok(Accepted::Reading(v)) => {
                self.stats.readings += 1;
                if self.forward_readings {
                    self.escalate(ForwardedItem::Reading(v.item), None, EscalationReason::Relay)
                } else {
                    Outcome::Stored
                }
            }
            Ok(Accepted::Embedding(v)) => {
                self.stats.embeddings += 1;
                if let Some(d) = self.drift.as_mut() {
                    let w = &v.item.window;
                    let _ = d.observe(&w.leaf_id, w.model.sha256.get(..16).unwrap_or(""), &w.values);
                }
                // A model that cannot answer is an escalation, not a guess.
                let inference = self.model.as_ref().and_then(|m| m.infer(&v.item.window.values).ok());
                let ctx = EscalationContext { inference: inference.as_ref(), effective: v.report.effective };
                match self.policy.decide(&ctx) {
                    Decision::Keep => {
                        self.stats.kept += 1;
                        Outcome::Kept { inference }
                    }
                    Decision::Escalate(reason) => self.escalate(ForwardedItem::Embedding(v.item), inference, reason),
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ForwardRefusal {
    UnknownSource,
    BadEnvelopeSignature,
    BadReadingSignature,
    Chain(ChainRefusal),
    BadCountersignature,
    /// The signature over the answer, the chain and the item is not the last rung's.
    BadOutputSignature,
    /// The answer does not match what the last rung's hop says it did.
    OutputDisagreesWithHop,
    BelowFloor { required: AssuranceClass, found: AssuranceClass },
}

impl std::fmt::Display for ForwardRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardRefusal::Chain(c) => write!(f, "{c}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for ForwardRefusal {}

/// What the next rung checks about a [`Forwarded`] message against its own
/// directory. The caller supplies the directory; the rung's own signing key
/// need not be the small node's.
pub fn verify_forwarded(
    f: &Forwarded,
    dir: &Directory,
    min_effective: AssuranceClass,
) -> Result<ChainReport, ForwardRefusal> {
    let (source, env, prov, counters) = f.item.parts();
    let gateway = dir.gateway_of(source).ok_or(ForwardRefusal::UnknownSource)?;
    match &f.item {
        ForwardedItem::Embedding(e) => {
            verify_with_key(&gateway.public_key, EMBEDDING_DOMAIN, &embedding_message(&e.window, &e.provenance), env)
        }
        ForwardedItem::Reading(r) => {
            verify_with_key(&gateway.public_key, ENVELOPE_DOMAIN, &envelope_message(&r.reading, &r.provenance), env)
        }
    }
    .map_err(|_| ForwardRefusal::BadEnvelopeSignature)?;
    if let ForwardedItem::Reading(r) = &f.item {
        let mut port = ParentPort::new();
        port.accept(Attachment {
            leaf_id: source.to_string(),
            parent: String::new(),
            public_key: gateway.public_key.clone(),
            key_custody: None,
            attached_at: 0,
        });
        port.verify(&r.reading, AssuranceClass::Soft).map_err(|_| ForwardRefusal::BadReadingSignature)?;
    }
    let report = chain::validate(prov, counters, dir, source, Some(NodeRole::SmallProcessing)).map_err(ForwardRefusal::Chain)?;
    verify_countersignature_list(env, counters, &|id| dir.key_of(id)).map_err(|_| ForwardRefusal::BadCountersignature)?;
    let last = counters.last().ok_or(ForwardRefusal::BadOutputSignature)?;
    let key = dir.key_of(&last.hop.node_id).ok_or(ForwardRefusal::BadOutputSignature)?;
    verify_with_key(&key, OUTPUT_DOMAIN, &output_message(env, counters, &f.inference, f.reason), &f.output_signature)
        .map_err(|_| ForwardRefusal::BadOutputSignature)?;
    let agrees = match (&f.inference, &last.hop.derivation) {
        (Some(i), Derivation::Model(m)) => &i.model == m,
        (None, Derivation::Relayed) => true,
        _ => false,
    };
    if !agrees {
        return Err(ForwardRefusal::OutputDisagreesWithHop);
    }
    if report.effective < min_effective {
        return Err(ForwardRefusal::BelowFloor { required: min_effective, found: report.effective });
    }
    Ok(report)
}
