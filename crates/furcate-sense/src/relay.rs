//! A processing node that signs, with hardware-held keys, for sensing nodes
//! whose readings reached it over a verified link.
//!
//! [`crate::nicla::NiclaAdapter`] signs with an in-memory key from the
//! caller, which is right for a simulator and wrong for a service. A relay is
//! the service path: the readings were already verified at the link (the
//! leaf's own signature checked against its enrolled identity), and what is
//! signed here is the frame the next rung reads, with the relay's
//! hardware-held key. The class it claims for itself is given by the caller
//! and is never above what the link verified.

use crate::cascade::ingest::Frame;
use crate::cascade::signer::{CascadeSigner, HardwareSigner};
use crate::cascade::witness::{item_digest, LeafLog};
use crate::identity::SensingNodeIdentity;
use crate::leaf::{reading_payload, Attachment, Reading};
use crate::nicla::{
    envelope_message, BridgeAttestation, BridgedReading, Derivation, DerivationKind, Hop, NodeRole, Provenance,
    SensorRootOfTrust, Transport, CHANNELS, ENVELOPE_DOMAIN,
};
use furcate_identity::{AssuranceClass, LeafKeyCustody, MessageSigner};
use furcate_policy::delegation::CellKey;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum RelayError {
    UnknownChannel(String),
    NonFinite,
    Sign(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::UnknownChannel(c) => write!(f, "`{c}` is not a channel the cascade publishes"),
            RelayError::NonFinite => write!(f, "the value is not a finite number"),
            RelayError::Sign(e) => write!(f, "signing failed: {e}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// A sensing node a relay signs for, and how its readings reached the relay.
#[derive(Clone, Debug)]
pub struct RelaySource {
    pub identity: SensingNodeIdentity,
    pub transport: Transport,
    /// Said once in every reading's attestation record: how the sensing node
    /// is identified and what the relay checked at the link.
    pub statement: String,
}

/// A channel a relay signs for, as its adapter declares it.
#[derive(Clone, Debug)]
pub struct RelayChannel<'a> {
    /// The channel id after `<sensing node>/`.
    pub suffix: &'a str,
    pub modality: crate::registry::Modality,
    /// How the value came to exist at the sensing node: measured, or computed
    /// by a named algorithm on the device.
    pub derivation: Derivation,
}

pub struct Relay {
    id: String,
    signer: Arc<dyn MessageSigner>,
    key: CellKey,
    hw: HardwareSigner,
    logs: BTreeMap<String, LeafLog>,
}

impl Relay {
    pub fn new(id: impl Into<String>, signer: Arc<dyn MessageSigner>) -> Result<Self, String> {
        let id = id.into();
        let key = CellKey::of(&*signer)?;
        let hw = HardwareSigner::new(id.clone(), signer.clone())?;
        Ok(Self { id, signer, key, hw, logs: BTreeMap::new() })
    }

    pub fn node_id(&self) -> &str {
        &self.id
    }

    /// The key as a cell link names it.
    pub fn public_key(&self) -> String {
        self.key.id()
    }

    /// The relay's enrolment record, as the rung above holds it. The custody is
    /// what the operator knows about the key, never something the relay says.
    pub fn attachment(&self, parent: &str, custody: Option<LeafKeyCustody>) -> Attachment {
        Attachment { leaf_id: self.id.clone(), parent: parent.to_string(), public_key: self.key.id(), key_custody: custody, attached_at: 0 }
    }

    /// One signed reading in its frame, with the next entry of that sensing
    /// node's log. `seq` must rise with every reading of the sensing node.
    #[allow(clippy::too_many_arguments)]
    pub fn frame(
        &mut self,
        src: &RelaySource,
        channel: &str,
        value: f64,
        seq: u64,
        taken_at: u64,
        claim: AssuranceClass,
        now_ms: u64,
    ) -> Result<Frame, RelayError> {
        let c = CHANNELS.iter().find(|c| c.suffix == channel).ok_or_else(|| RelayError::UnknownChannel(channel.to_string()))?;
        let derivation = match c.derivation {
            DerivationKind::Transducer => Derivation::Measured,
            DerivationKind::OnSensor(a) => Derivation::OnSensor { algorithm: a.to_string() },
        };
        let ch = RelayChannel { suffix: c.suffix, modality: c.kind.modality(), derivation };
        self.frame_channel(src, &ch, value, seq, taken_at, claim, None, now_ms)
    }

    /// [`Relay::frame`] for a channel the caller declares, and with the model
    /// binding the relay states for it. The Nicla channel table is not
    /// consulted: a bus adapter declares its own channels (quantity, unit and
    /// range live with the adapter), and the exporter learns them the same way
    /// ([`crate::cascade::physical::BatchBuilder::with_channels`]).
    #[allow(clippy::too_many_arguments)]
    pub fn frame_channel(
        &mut self,
        src: &RelaySource,
        ch: &RelayChannel,
        value: f64,
        seq: u64,
        taken_at: u64,
        claim: AssuranceClass,
        binding: Option<crate::cascade::binding::ModelBinding>,
        now_ms: u64,
    ) -> Result<Frame, RelayError> {
        if !value.is_finite() {
            return Err(RelayError::NonFinite);
        }
        let sensing = src.identity.node_id.as_str().to_string();
        let sensor_id = format!("{sensing}/{}", ch.suffix);
        let payload = reading_payload(&sensor_id, &sensing, value, seq, taken_at);
        let raw = self.signer.sign(&payload).map_err(|e| RelayError::Sign(format!("{e:#}")))?;
        let signature = self.key.seal(&payload, &raw).map_err(RelayError::Sign)?;
        let reading = Reading { sensor_id, leaf_id: sensing.clone(), value, seq, taken_at, signature };
        let attestation = BridgeAttestation {
            sensing_node: sensing.clone(),
            identity_basis: src.identity.basis.clone(),
            enrollment_digest: src.identity.enrollment.evidence_digest.clone(),
            gateway: self.id.clone(),
            gateway_assurance: claim,
            sensor_root_of_trust: SensorRootOfTrust::None,
            sensor_assurance: src.identity.assurance(),
            statement: src.statement.clone(),
        };
        let provenance = Provenance {
            version: 1,
            attestation_level: attestation.sensor_assurance,
            attestation,
            source_module: sensing.clone(),
            transport: src.transport,
            modality: ch.modality,
            chain: vec![
                Hop {
                    role: NodeRole::Sensing,
                    node_id: sensing.clone(),
                    attestation_level: src.identity.assurance(),
                    derivation: ch.derivation.clone(),
                },
                Hop { role: NodeRole::MicroProcessing, node_id: self.id.clone(), attestation_level: claim, derivation: Derivation::Relayed },
            ],
            binding,
        };
        let envelope_signature = self.hw.sign_message(ENVELOPE_DOMAIN, &envelope_message(&reading, &provenance)).map_err(RelayError::Sign)?;
        let item = BridgedReading { reading, provenance, envelope_signature, countersignatures: Vec::new() };
        let log = self.logs.entry(sensing.clone()).or_insert_with(|| LeafLog::new(&sensing));
        let entry = log.append(now_ms, &item_digest(&item.envelope_signature));
        Ok(Frame::Reading { item, entry })
    }

    /// A signed checkpoint of each sensing node's log, for the rung above to
    /// cosign.
    pub fn checkpoints(&self, now_ms: u64) -> Result<Vec<Frame>, RelayError> {
        self.logs
            .values()
            .map(|l| l.checkpoint(now_ms, &self.hw as &dyn CascadeSigner).map(|checkpoint| Frame::Checkpoint { checkpoint }).map_err(RelayError::Sign))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cascade::binding::ModelBinding;
    use crate::identity::{enrol, fingerprint_of};
    use crate::registry::Modality;
    use furcate_identity::signer::Ed25519Signer;

    fn relay() -> Relay {
        Relay::new("furcate:node:r", Arc::new(Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]))))).unwrap()
    }

    fn source() -> RelaySource {
        RelaySource {
            identity: enrol(fingerprint_of("SYNTH-0001", None).unwrap(), "n", b"n").unwrap(),
            transport: Transport::UsbFrame,
            statement: "test".into(),
        }
    }

    #[test]
    fn a_declared_channel_carries_its_modality_derivation_and_binding() {
        let (mut r, s) = (relay(), source());
        let b = ModelBinding::new(&"ab".repeat(32), 3, Some(b"cal"), true).unwrap();
        let ch = RelayChannel { suffix: "joint1.position", modality: Modality::Inferred, derivation: Derivation::OnSensor { algorithm: "ekf".into() } };
        let Frame::Reading { item, .. } = r.frame_channel(&s, &ch, 0.5, 1, 10, AssuranceClass::Device, Some(b.clone()), 1000).unwrap() else { panic!() };
        assert_eq!(item.provenance.modality, Modality::Inferred);
        assert_eq!(item.provenance.binding, Some(b));
        assert!(matches!(&item.provenance.chain[0].derivation, Derivation::OnSensor { algorithm } if algorithm == "ekf"));
        assert!(item.reading.sensor_id.ends_with("/joint1.position"));
        assert_eq!(item.provenance.attestation_level, AssuranceClass::Soft);
    }

    #[test]
    fn the_nicla_path_is_the_declared_path_with_the_nicla_table() {
        let s = source();
        let (mut a, mut b) = (relay(), relay());
        let Frame::Reading { item: x, .. } = a.frame(&s, "tmp", 21.0, 1, 10, AssuranceClass::Device, 1000).unwrap() else { panic!() };
        let ch = RelayChannel { suffix: "tmp", modality: Modality::Direct, derivation: Derivation::Measured };
        let Frame::Reading { item: y, .. } = b.frame_channel(&s, &ch, 21.0, 1, 10, AssuranceClass::Device, None, 1000).unwrap() else { panic!() };
        assert_eq!(x.envelope_signature, y.envelope_signature);
        assert_eq!(x.reading.signature, y.reading.signature);
    }

    #[test]
    fn a_non_finite_value_and_an_unknown_nicla_channel_are_refused() {
        let (mut r, s) = (relay(), source());
        assert_eq!(r.frame(&s, "tmp", f64::NAN, 1, 1, AssuranceClass::Soft, 1).unwrap_err(), RelayError::NonFinite);
        assert!(matches!(r.frame(&s, "no.such", 1.0, 1, 1, AssuranceClass::Soft, 1), Err(RelayError::UnknownChannel(_))));
    }
}
