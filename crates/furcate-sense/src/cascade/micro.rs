//! A host-side stand-in for the micro processing node.
//!
//! The real node is firmware and is built elsewhere. This is what a test, the
//! `furcate-small replay` command and a developer without the board use to
//! produce what that node would send: signed readings with log entries, signed
//! embedding windows, and signed checkpoints, in the formats [`super::ingest`]
//! reads. It signs with an in-memory key from the caller, so it is for
//! simulation only; a service path never builds one.

use super::binding::ModelBinding;
use super::ingest::{sign_embedding, EmbeddingWindow, Frame};
use super::signer::CascadeSigner;
use super::witness::{item_digest, LeafLog};
use crate::identity::{enrol, fingerprint_of, SensingNodeIdentity};
use crate::leaf::{Attachment, Leaf};
use crate::nicla::{
    Derivation, Hop, ModelRef, NiclaAdapter, NiclaError, NodeRole, Provenance, Sample, Transport,
};
use crate::registry::Modality;
use furcate_identity::{AssuranceClass, LeafKeyCustody};
use sha2::{Digest, Sha256};

/// The embedding the stand-in computes: four quantised window features. It is
/// a fixed formula, named by the hash of its description, and not a trained
/// model.
pub const FEATURE_SPEC: &str = "furcate-sim-window-features-v0: int8[4] = clamp(round(8*mean|acc| m/s2)), clamp(round(32*mean|gyr| rad/s)), clamp(round(mean temperature C)), clamp(round(10*ln(mean gas ohm)))";

pub fn feature_model() -> ModelRef {
    ModelRef { id: "furcate-sim-window-features-v0".into(), sha256: hex::encode(Sha256::digest(FEATURE_SPEC.as_bytes())) }
}

fn q(x: f64) -> i8 {
    x.round().clamp(-128.0, 127.0) as i8
}

/// The stand-in embedding of a window of samples.
pub fn window_features(samples: &[Sample]) -> Vec<i8> {
    let (mut acc, mut gyr, mut tmp, mut gas) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for s in samples {
        match s {
            Sample::Acceleration { x, y, z } => acc.push((x * x + y * y + z * z).sqrt()),
            Sample::AngularRate { x, y, z } => gyr.push((x * x + y * y + z * z).sqrt()),
            Sample::Temperature(c) => tmp.push(*c),
            Sample::GasResistance(o) => gas.push(*o),
            _ => {}
        }
    }
    let mean = |v: &[f64]| if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 };
    let g = mean(&gas);
    vec![q(8.0 * mean(&acc)), q(32.0 * mean(&gyr)), q(mean(&tmp)), q(if g > 0.0 { 10.0 * g.ln() } else { 0.0 })]
}

pub struct MicroSim {
    identity: SensingNodeIdentity,
    signer: Leaf,
    gateway: String,
    claim: AssuranceClass,
    adapter: NiclaAdapter,
    log: LeafLog,
    window_seq: u64,
    binding: Option<ModelBinding>,
    model: ModelRef,
}

impl MicroSim {
    /// A sensing node enrolled from `usb_serial`, read by the processing node
    /// `gateway_id`, which signs with `key` and says its class is `device`.
    pub fn new(usb_serial: &str, key: [u8; 32], gateway_id: &str) -> Self {
        Self::claiming(usb_serial, key, gateway_id, AssuranceClass::Device)
    }

    /// As [`MicroSim::new`] but the processing node claims `claim`, for tests
    /// of a rung that claims more than it is.
    pub fn claiming(usb_serial: &str, key: [u8; 32], gateway_id: &str, claim: AssuranceClass) -> Self {
        let fp = fingerprint_of(usb_serial, None).expect("a plain serial");
        let identity = enrol(fp, usb_serial, b"cascade-sim").expect("enrols");
        let signer = Leaf::new(identity.node_id.as_str(), key);
        let adapter = NiclaAdapter::new(
            Leaf::new(identity.node_id.as_str(), key),
            &identity,
            gateway_id,
            NodeRole::MicroProcessing,
            claim,
            Transport::UsbText,
            1,
        )
        .expect("the leaf carries the enrolled id");
        let log = LeafLog::new(identity.node_id.as_str());
        Self { identity, signer, gateway: gateway_id.to_string(), claim, adapter, log, window_seq: 0, binding: None, model: feature_model() }
    }

    /// State a model binding in every reading and embedding from now on.
    pub fn set_binding(&mut self, binding: Option<ModelBinding>) {
        self.adapter.set_binding(binding.clone());
        self.binding = binding;
    }

    /// Name a different model in the embeddings this stand-in signs, as a node
    /// running other weights would.
    pub fn set_model(&mut self, model: ModelRef) {
        self.model = model;
    }

    /// The binding for this stand-in's own feature model at `epoch`, with no
    /// calibration artefact and a passing self test.
    pub fn feature_binding(epoch: u32) -> ModelBinding {
        ModelBinding::new(&feature_model().sha256, epoch, None, true).expect("a SHA-256 is 32 bytes")
    }

    pub fn sensing_id(&self) -> &str {
        self.identity.node_id.as_str()
    }

    pub fn signer(&self) -> &Leaf {
        &self.signer
    }

    /// The processing node's enrolment record, as the rung above would hold it.
    pub fn gateway_attachment(&self, custody: Option<LeafKeyCustody>) -> Attachment {
        Attachment {
            leaf_id: self.gateway.clone(),
            parent: "small".into(),
            public_key: self.signer.public_key(),
            key_custody: custody,
            attached_at: 0,
        }
    }

    /// Signed readings for one sample, each with its log entry.
    pub fn reading_frames(&mut self, sample: &Sample, now_ms: u64) -> Result<Vec<Frame>, NiclaError> {
        let items = self.adapter.ingest(sample, now_ms / 1000)?;
        Ok(items
            .into_iter()
            .map(|item| {
                let entry = self.log.append(now_ms, &item_digest(&item.envelope_signature));
                Frame::Reading { item, entry }
            })
            .collect())
    }

    fn embedding_provenance(&self, model: &ModelRef) -> Provenance {
        let a = self.adapter.attestation().clone();
        Provenance {
            version: 1,
            attestation_level: a.sensor_assurance,
            attestation: a,
            source_module: self.sensing_id().to_string(),
            transport: Transport::UsbText,
            modality: Modality::Inferred,
            chain: vec![
                Hop {
                    role: NodeRole::Sensing,
                    node_id: self.sensing_id().to_string(),
                    attestation_level: self.identity.assurance(),
                    derivation: Derivation::Measured,
                },
                Hop {
                    role: NodeRole::MicroProcessing,
                    node_id: self.gateway.clone(),
                    attestation_level: self.claim,
                    derivation: Derivation::Model(model.clone()),
                },
            ],
            binding: self.binding.clone(),
        }
    }

    /// A signed embedding window, without its frame, so a test can alter it.
    pub fn embedding(&mut self, values: &[i8], now_ms: u64) -> super::ingest::BridgedEmbedding {
        self.window_seq += 1;
        let model = self.model.clone();
        let window = EmbeddingWindow {
            leaf_id: self.sensing_id().to_string(),
            window_seq: self.window_seq,
            taken_at: now_ms / 1000,
            model: model.clone(),
            values: values.to_vec(),
        };
        sign_embedding(&self.signer, window, self.embedding_provenance(&model)).expect("an in-memory key signs")
    }

    /// A signed embedding in its frame, with the next log entry.
    pub fn embedding_frame(&mut self, values: &[i8], now_ms: u64) -> Frame {
        let item = self.embedding(values, now_ms);
        let entry = self.log.append(now_ms, &item_digest(&item.envelope_signature));
        Frame::Embedding { item, entry }
    }

    /// The log entry for an item built by hand.
    pub fn log_entry(&mut self, envelope_signature: &str, now_ms: u64) -> super::witness::LogEntry {
        self.log.append(now_ms, &item_digest(envelope_signature))
    }

    pub fn checkpoint_frame(&self, now_ms: u64) -> Frame {
        let checkpoint = self.log.checkpoint(now_ms, &self.signer as &dyn CascadeSigner).expect("an in-memory key signs");
        Frame::Checkpoint { checkpoint }
    }
}
