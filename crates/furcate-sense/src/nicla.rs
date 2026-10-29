//! The Arduino Nicla Sense ME as a sensor behind a gateway.
//!
//! The board carries a Bosch BHI260AP sensor hub (accelerometer, gyroscope and
//! on-chip sensor fusion), a BMM150 magnetometer, a BME688 gas, humidity,
//! temperature and pressure sensor, and a BMP390 pressure sensor, all behind an
//! nRF52832 microcontroller. None of that is a root of trust. In the cascade it
//! is a **sensing node**: enrolled through the ordinary identity machinery
//! ([`crate::identity`]), identified by its silicon fingerprint, and never a
//! signer. The processing node that reads it signs on its behalf, and the
//! record says exactly what that does and does not establish. See
//! [`ATTESTATION_STATEMENT`].
//!
//! ## What is measured and what is derived
//!
//! Accelerometer, gyroscope, magnetometer, temperature, humidity, pressure and
//! gas resistance are transducer channels and are [`Modality::Direct`]. The
//! rotation vector, the step count, the activity class and the air-quality
//! figures are computed on the sensor by the vendor's algorithms from those
//! channels; the air-quality "CO2 equivalent" and "breath VOC equivalent" are
//! estimates from gas resistance, not a CO2 measurement. Those kinds are
//! [`Modality::Inferred`], which means they may inform and corroborate but may
//! not on their own justify a physical action. Their [`Derivation`] says which
//! kind of derivation produced them. No Furcate model is involved, so no model
//! hash is recorded for them.

use crate::bhy2::DecodeError;
use crate::cascade::signer::CascadeSigner;
use crate::frame::FrameError;
use crate::identity::{IdentityBasis, SensingNodeIdentity};
use crate::leaf::{Attachment, Leaf, LeafError, ParentPort, Reading};
use crate::registry::{Modality, Sensor, SensorKind, SensorRegistry, Unit};
use crate::text::TextError;
use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::bhy2::{self, Decoded, Record};

pub const MODEL: &str = "arduino-nicla-sense-me";

/// The wording recorded with every attachment and every reading.
pub const ATTESTATION_STATEMENT: &str = "Fingerprint-identified, not hardware-keyed: the Arduino Nicla Sense ME holds no secret and has no secure element, so it cannot authenticate itself. Its identity is derived from identifiers the board reports (chip and USB serial numbers), which any code on it or anyone holding it can repeat; a fingerprint shows continuity with the unit that was enrolled, not that this unit is the one answering. Readings are signed by the processing node that reads the board, on its behalf.";

/// Standard gravity, for converting the accelerometer's g.
const G: f64 = 9.80665;

#[derive(Debug)]
pub enum NiclaError {
    /// A scaled quantity arrived before the range that scales it.
    RangeUnknown(&'static str),
    BadRange(&'static str),
    NonFinite,
    /// A valid sample that is withheld on purpose, with the reason.
    Withheld(&'static str),
    Text(TextError),
    Frame(FrameError),
    Decode(DecodeError),
    Identity(crate::identity::IdentityError),
    LeafIdMismatch { expected: String, found: String },
    Leaf(LeafError),
    Io(std::io::Error),
    Sign(String),
}

impl fmt::Display for NiclaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NiclaError::RangeUnknown(w) => write!(f, "{w} counts arrived before its range was known"),
            NiclaError::BadRange(w) => write!(f, "bad range: {w}"),
            NiclaError::NonFinite => write!(f, "value is not finite"),
            NiclaError::Withheld(w) => write!(f, "sample withheld: {w}"),
            NiclaError::Text(e) => write!(f, "{e}"),
            NiclaError::Frame(e) => write!(f, "{e}"),
            NiclaError::Decode(e) => write!(f, "{e}"),
            NiclaError::Identity(e) => write!(f, "{e}"),
            NiclaError::LeafIdMismatch { expected, found } => {
                write!(f, "leaf id `{found}` is not the enrolled identity `{expected}`")
            }
            NiclaError::Leaf(e) => write!(f, "{e}"),
            NiclaError::Io(e) => write!(f, "{e}"),
            NiclaError::Sign(e) => write!(f, "signing failed: {e}"),
        }
    }
}

impl std::error::Error for NiclaError {}

impl From<DecodeError> for NiclaError {
    fn from(e: DecodeError) -> Self {
        NiclaError::Decode(e)
    }
}

impl From<crate::identity::IdentityError> for NiclaError {
    fn from(e: crate::identity::IdentityError) -> Self {
        NiclaError::Identity(e)
    }
}

impl From<LeafError> for NiclaError {
    fn from(e: LeafError) -> Self {
        NiclaError::Leaf(e)
    }
}

impl From<std::io::Error> for NiclaError {
    fn from(e: std::io::Error) -> Self {
        NiclaError::Io(e)
    }
}

/// The full-scale ranges that turn raw counts into physical units.
///
/// The wire carries counts only; the range is a setting on the sensor hub. An
/// unset range refuses conversion instead of assuming a default, because a
/// wrong assumption scales every reading by the same unnoticed factor.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ranges {
    accel_g: Option<f64>,
    gyro_dps: Option<f64>,
    mag_ut: Option<f64>,
}

fn sane_range(v: f64, what: &'static str) -> Result<f64, NiclaError> {
    if v.is_finite() && v > 0.0 && v <= 10_000.0 {
        Ok(v)
    } else {
        Err(NiclaError::BadRange(what))
    }
}

impl Ranges {
    pub fn set_accel(&mut self, g: f64) -> Result<(), NiclaError> {
        self.accel_g = Some(sane_range(g, "accelerometer range")?);
        Ok(())
    }

    pub fn set_gyro(&mut self, dps: f64) -> Result<(), NiclaError> {
        self.gyro_dps = Some(sane_range(dps, "gyroscope range")?);
        Ok(())
    }

    /// Full-scale of the magnetometer in microtesla. The wire does not carry it
    /// and no default is assumed.
    pub fn set_mag(&mut self, ut: f64) -> Result<(), NiclaError> {
        self.mag_ut = Some(sane_range(ut, "magnetometer range")?);
        Ok(())
    }

    pub fn accel_g(&self) -> Option<f64> {
        self.accel_g
    }

    pub fn gyro_dps(&self) -> Option<f64> {
        self.gyro_dps
    }

    /// Counts to metres per second squared. Full scale is 32768 counts.
    pub fn acceleration(&self, x: i16, y: i16, z: i16) -> Result<Sample, NiclaError> {
        let r = self.accel_g.ok_or(NiclaError::RangeUnknown("accelerometer"))?;
        let k = r / 32768.0 * G;
        Ok(Sample::Acceleration { x: x as f64 * k, y: y as f64 * k, z: z as f64 * k })
    }

    /// Counts to microtesla.
    pub fn magnetic_field(&self, x: i16, y: i16, z: i16) -> Result<Sample, NiclaError> {
        let r = self.mag_ut.ok_or(NiclaError::RangeUnknown("magnetometer"))?;
        let k = r / 32768.0;
        Ok(Sample::MagneticField { x: x as f64 * k, y: y as f64 * k, z: z as f64 * k })
    }

    /// Counts to radians per second.
    pub fn angular_rate(&self, x: i16, y: i16, z: i16) -> Result<Sample, NiclaError> {
        let r = self.gyro_dps.ok_or(NiclaError::RangeUnknown("gyroscope"))?;
        let k = r / 32768.0 * std::f64::consts::PI / 180.0;
        Ok(Sample::AngularRate { x: x as f64 * k, y: y as f64 * k, z: z as f64 * k })
    }
}

/// One observation in physical units, whatever carried it.
#[derive(Clone, Debug, PartialEq)]
pub enum Sample {
    /// Metres per second squared, gravity included.
    Acceleration { x: f64, y: f64, z: f64 },
    /// Radians per second.
    AngularRate { x: f64, y: f64, z: f64 },
    /// Microtesla.
    MagneticField { x: f64, y: f64, z: f64 },
    /// A unit quaternion from the sensor hub's fusion, with its accuracy
    /// estimate in radians where the transport carries one.
    Rotation { x: f64, y: f64, z: f64, w: f64, accuracy: Option<f64> },
    Temperature(f64),
    Humidity(f64),
    Pressure(f64),
    GasResistance(f64),
    /// The vendor's air-quality estimate. Accuracy 0 means still stabilising.
    AirQuality { index: f64, co2_eq_ppm: f64, b_voc_eq_ppm: f64, accuracy: u8 },
    Steps(u32),
    /// An activity code from the hub's classifier: the bit index of the
    /// activity word, 0 to 6 for ended, 8 to 14 for started.
    Activity(u8),
}

/// One published channel of the board.
pub struct Channel {
    /// Where the value comes from: the Nicla module, or the processing node that hosts it.
    pub origin: Origin,
    pub suffix: &'static str,
    pub kind: SensorKind,
    pub unit: Unit,
    pub derivation: DerivationKind,
}

/// Which device a channel is measured on. The chip of the micro processing node
/// that hosts the module is a different thing from the module's own sensors and
/// is never published under a module channel name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Module,
    HostChip,
}

/// How a channel's value comes to exist, without the algorithm's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationKind {
    Transducer,
    OnSensor(&'static str),
}

const FUSION: DerivationKind = DerivationKind::OnSensor("bhi260ap-sensor-fusion");
const BSEC: DerivationKind = DerivationKind::OnSensor("bsec-air-quality");
const PEDOMETER: DerivationKind = DerivationKind::OnSensor("bhi260ap-step-counter");
const CLASSIFIER: DerivationKind = DerivationKind::OnSensor("bhi260ap-activity-recognition");

macro_rules! ch {
    ($s:expr, $k:ident, $u:ident, $d:expr) => {
        Channel { origin: Origin::Module, suffix: $s, kind: SensorKind::$k, unit: Unit::$u, derivation: $d }
    };
}

/// Every sensor the board can publish, by id suffix.
pub const CHANNELS: &[Channel] = &[
    ch!("acc.x", Acceleration, MetresPerSecondSquared, DerivationKind::Transducer),
    ch!("acc.y", Acceleration, MetresPerSecondSquared, DerivationKind::Transducer),
    ch!("acc.z", Acceleration, MetresPerSecondSquared, DerivationKind::Transducer),
    ch!("gyr.x", AngularRate, RadiansPerSecond, DerivationKind::Transducer),
    ch!("gyr.y", AngularRate, RadiansPerSecond, DerivationKind::Transducer),
    ch!("gyr.z", AngularRate, RadiansPerSecond, DerivationKind::Transducer),
    ch!("mag.x", MagneticField, Microtesla, DerivationKind::Transducer),
    ch!("mag.y", MagneticField, Microtesla, DerivationKind::Transducer),
    ch!("mag.z", MagneticField, Microtesla, DerivationKind::Transducer),
    ch!("rot.x", Orientation, Unitless, FUSION),
    ch!("rot.y", Orientation, Unitless, FUSION),
    ch!("rot.z", Orientation, Unitless, FUSION),
    ch!("rot.w", Orientation, Unitless, FUSION),
    ch!("tmp", Temperature, Celsius, DerivationKind::Transducer),
    ch!("hum", Humidity, Percent, DerivationKind::Transducer),
    ch!("prs", Pressure, Pascals, DerivationKind::Transducer),
    ch!("gas", GasResistance, Ohms, DerivationKind::Transducer),
    ch!("iaq", AirQualityIndex, Unitless, BSEC),
    ch!("co2eq", GasEquivalent, Ppm, BSEC),
    ch!("bvoceq", GasEquivalent, Ppm, BSEC),
    ch!("steps", StepCount, Count, PEDOMETER),
    ch!("act", ActivityState, Count, CLASSIFIER),
    // The die temperature of the micro processing node that hosts the module. It is
    // not ambient air and not the module's `tmp`.
    Channel { origin: Origin::HostChip, suffix: "chip.tmp", kind: SensorKind::Temperature, unit: Unit::Celsius, derivation: DerivationKind::Transducer },
];

fn channel(suffix: &str) -> Option<&'static Channel> {
    CHANNELS.iter().find(|c| c.suffix == suffix)
}

/// The channel values a sample carries, by channel suffix. Air quality still
/// stabilising is withheld, and a value that is not finite is refused.
pub fn channel_values(s: &Sample) -> Result<Vec<(&'static str, f64)>, NiclaError> {
    values_of(s)
}

/// The channel values a sample carries.
fn values_of(s: &Sample) -> Result<Vec<(&'static str, f64)>, NiclaError> {
    let v = match s {
        Sample::Acceleration { x, y, z } => vec![("acc.x", *x), ("acc.y", *y), ("acc.z", *z)],
        Sample::AngularRate { x, y, z } => vec![("gyr.x", *x), ("gyr.y", *y), ("gyr.z", *z)],
        Sample::MagneticField { x, y, z } => vec![("mag.x", *x), ("mag.y", *y), ("mag.z", *z)],
        Sample::Rotation { x, y, z, w, .. } => vec![("rot.x", *x), ("rot.y", *y), ("rot.z", *z), ("rot.w", *w)],
        Sample::Temperature(c) => vec![("tmp", *c)],
        Sample::Humidity(p) => vec![("hum", *p)],
        Sample::Pressure(p) => vec![("prs", *p)],
        Sample::GasResistance(o) => vec![("gas", *o)],
        Sample::AirQuality { index, co2_eq_ppm, b_voc_eq_ppm, accuracy } => {
            if *accuracy == 0 {
                return Err(NiclaError::Withheld("air quality is still stabilising (accuracy 0)"));
            }
            vec![("iaq", *index), ("co2eq", *co2_eq_ppm), ("bvoceq", *b_voc_eq_ppm)]
        }
        Sample::Steps(n) => vec![("steps", *n as f64)],
        Sample::Activity(code) => vec![("act", *code as f64)],
    };
    if v.iter().any(|(_, x)| !x.is_finite()) {
        return Err(NiclaError::NonFinite);
    }
    Ok(v)
}

/// What the sensor itself contributes to trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorRootOfTrust {
    None,
}

/// A rung in the cascade, named by role. Board names never appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Transduces and holds no key it can prove: a leaf in the older vocabulary.
    Sensing,
    /// Processes and signs for the sensing node behind it (the gateway).
    MicroProcessing,
    /// A single-board computer running the full agent.
    SmallProcessing,
    /// A module with a hardware root of trust and an accelerator.
    MediumProcessing,
    /// Servers and cloud, for compute.
    LargeProcessing,
}

/// The recorded basis on which a processing node signs for a sensing node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeAttestation {
    /// The enrolled identity of the sensing node.
    pub sensing_node: String,
    pub identity_basis: IdentityBasis,
    /// Digest of the evidence the enrolment committed to.
    pub enrollment_digest: String,
    pub gateway: String,
    /// The signing node's own class: the strength of the signing key, which
    /// says nothing about the board.
    pub gateway_assurance: AssuranceClass,
    pub sensor_root_of_trust: SensorRootOfTrust,
    /// The strongest class the sensing node's own identity supports.
    pub sensor_assurance: AssuranceClass,
    pub statement: String,
}

/// An attachment plus the attestation record that explains its assurance.
#[derive(Clone, Debug, Serialize)]
pub struct BridgedAttachment {
    pub attachment: Attachment,
    pub attestation: BridgeAttestation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Text lines from the stock `Standalone` example (verified on hardware).
    UsbText,
    /// The framed line format.
    UsbFrame,
    /// The binary sensor-hub protocol over serial, ESLOV or BLE.
    Bhy2Binary,
    /// A ROS 2 topic, observed read-only.
    Ros2,
    /// An OPC UA server, browsed, read and subscribed to, never written.
    OpcUa,
    /// EtherCAT process data observed on the wire, never sent.
    EtherCat,
    /// An MQTT broker, subscribed to, never published to.
    Mqtt,
    /// A CAN bus through SocketCAN, received only.
    SocketCan,
    /// Modbus registers read by function codes 1 to 4 only.
    Modbus,
}

/// A model that produced a value, for the tier that has to trust it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub id: String,
    /// SHA-256 of the model artefact, hex.
    pub sha256: String,
}

/// What a hop did to the value it passes on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Derivation {
    Measured,
    /// Computed on the sensor by a vendor algorithm, named, with no hash.
    OnSensor { algorithm: String },
    /// Produced by a model whose hash is known.
    Model(ModelRef),
    /// Carried unchanged.
    Relayed,
}

/// One rung the reading has passed through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub role: NodeRole,
    pub node_id: String,
    /// The class of the key that vouches at this rung.
    pub attestation_level: AssuranceClass,
    pub derivation: Derivation,
}

/// Everything the next tier needs to judge a reading, covered by the signing
/// node's signature together with the reading itself.
///
/// `chain` lists the rungs from the sensing node outward and is open-ended:
/// each further rung appends itself with [`countersign`], so nothing here fixes
/// the number of tiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub version: u8,
    /// The class of the sensing node's own identity, repeated so a verifier
    /// does not have to look up the attachment to read it.
    pub attestation_level: AssuranceClass,
    pub attestation: BridgeAttestation,
    pub source_module: String,
    pub transport: Transport,
    pub modality: Modality,
    pub chain: Vec<Hop>,
    /// The model, epoch and calibration the signing node states it ran, covered
    /// by the same signature as everything else here. Absent from nodes that
    /// do not state one, which a verifier holding a registry refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<crate::cascade::binding::ModelBinding>,
}

/// A later rung's signature over the reading as it arrived plus its own hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Countersignature {
    pub hop: Hop,
    pub signature: String,
}

/// A reading with its provenance and the signing node's signature over both.
///
/// The next tier verifies this with [`verify_bridged`]. What it then does with
/// an `Inferred` or below-floor reading is that tier's own policy and is not
/// implemented here; this is the seam.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgedReading {
    pub reading: Reading,
    pub provenance: Provenance,
    pub envelope_signature: String,
    pub countersignatures: Vec<Countersignature>,
}

pub(crate) const ENVELOPE_DOMAIN: &str = "furcate/bridged-reading/v1";
const HOP_DOMAIN: &str = "furcate/bridged-hop/v1";

pub(crate) fn envelope_message(reading: &Reading, p: &Provenance) -> Vec<u8> {
    // Field order is fixed by the struct, so the encoding is deterministic.
    let json = serde_json::to_vec(p).unwrap_or_default();
    let mut m = Vec::new();
    m.extend((reading.signature.len() as u64).to_be_bytes());
    m.extend(reading.signature.as_bytes());
    m.extend((json.len() as u64).to_be_bytes());
    m.extend(json);
    m
}

fn hop_message_of(envelope_signature: &str, prior: &[Countersignature], hop: &Hop) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend(envelope_signature.as_bytes());
    for c in prior {
        m.push(b'|');
        m.extend(c.signature.as_bytes());
    }
    m.push(b'#');
    m.extend(serde_json::to_vec(hop).unwrap_or_default());
    m
}

/// Verify a bridged reading at the receiving parent: the envelope that binds
/// the provenance to the reading, then the reading's own signature and sequence.
pub fn verify_bridged(
    port: &mut ParentPort,
    b: &BridgedReading,
    min_assurance: AssuranceClass,
) -> Result<(), LeafError> {
    // The envelope is checked first so a forged provenance cannot consume a
    // sequence number.
    port.verify_message(
        &b.reading.leaf_id,
        ENVELOPE_DOMAIN,
        &envelope_message(&b.reading, &b.provenance),
        &b.envelope_signature,
    )?;
    port.verify(&b.reading, min_assurance)
}

/// Add a rung. The signer's id must be the hop's node id.
pub fn countersign(b: &mut BridgedReading, signer: &dyn CascadeSigner, hop: Hop) -> Result<(), NiclaError> {
    countersign_list(&b.envelope_signature, &mut b.countersignatures, signer, hop)
}

/// [`countersign`] for any envelope: the rung signs the envelope signature,
/// the rungs before it, and its own hop.
pub fn countersign_list(
    envelope_signature: &str,
    counters: &mut Vec<Countersignature>,
    signer: &dyn CascadeSigner,
    hop: Hop,
) -> Result<(), NiclaError> {
    if signer.node_id() != hop.node_id {
        return Err(NiclaError::LeafIdMismatch { expected: hop.node_id, found: signer.node_id().to_string() });
    }
    let signature = signer
        .sign_message(HOP_DOMAIN, &hop_message_of(envelope_signature, counters, &hop))
        .map_err(NiclaError::Sign)?;
    counters.push(Countersignature { hop, signature });
    Ok(())
}

/// Check every added rung. `key_of` is the receiving tier's record of each
/// node's public key (hex), which it holds from that node's enrolment; this
/// crate does not know how that tier stores them.
pub fn verify_countersignatures(
    b: &BridgedReading,
    key_of: &dyn Fn(&str) -> Option<String>,
) -> Result<(), LeafError> {
    verify_countersignature_list(&b.envelope_signature, &b.countersignatures, key_of)
}

/// [`verify_countersignatures`] for any envelope.
pub fn verify_countersignature_list(
    envelope_signature: &str,
    counters: &[Countersignature],
    key_of: &dyn Fn(&str) -> Option<String>,
) -> Result<(), LeafError> {
    for (i, c) in counters.iter().enumerate() {
        let key = key_of(&c.hop.node_id).ok_or(LeafError::NotAttached)?;
        let msg = hop_message_of(envelope_signature, &counters[..i], &c.hop);
        crate::leaf::verify_with_key(&key, HOP_DOMAIN, &msg, &c.signature)?;
    }
    Ok(())
}

/// Attaches a sensing node behind a processing node and turns its samples
/// into signed readings.
pub struct NiclaAdapter {
    leaf: Leaf,
    attestation: BridgeAttestation,
    gateway_role: NodeRole,
    transport: Transport,
    interval_s: u64,
    binding: Option<crate::cascade::binding::ModelBinding>,
}

impl NiclaAdapter {
    /// `leaf` carries the processing node's signing key, derived by that node
    /// from its own identity; this function does not make keys. Its id must be
    /// the sensing node's enrolled node id, which puts the enrolled identity
    /// inside every signed reading.
    pub fn new(
        leaf: Leaf,
        identity: &SensingNodeIdentity,
        gateway: &str,
        gateway_role: NodeRole,
        gateway_assurance: AssuranceClass,
        transport: Transport,
        interval_s: u64,
    ) -> Result<Self, NiclaError> {
        let expected = identity.node_id.as_str().to_string();
        if leaf.id != expected {
            return Err(NiclaError::LeafIdMismatch { expected, found: leaf.id.clone() });
        }
        Ok(Self {
            leaf,
            attestation: BridgeAttestation {
                sensing_node: expected,
                identity_basis: identity.basis.clone(),
                enrollment_digest: identity.enrollment.evidence_digest.clone(),
                gateway: gateway.to_string(),
                gateway_assurance,
                sensor_root_of_trust: SensorRootOfTrust::None,
                sensor_assurance: identity.assurance(),
                statement: ATTESTATION_STATEMENT.to_string(),
            },
            gateway_role,
            transport,
            interval_s: interval_s.max(1),
            binding: None,
        })
    }

    /// State the model, epoch and calibration every following reading carries.
    pub fn with_binding(mut self, binding: crate::cascade::binding::ModelBinding) -> Self {
        self.binding = Some(binding);
        self
    }

    pub fn set_binding(&mut self, binding: Option<crate::cascade::binding::ModelBinding>) {
        self.binding = binding;
    }

    pub fn binding(&self) -> Option<&crate::cascade::binding::ModelBinding> {
        self.binding.as_ref()
    }

    pub fn leaf_id(&self) -> &str {
        &self.leaf.id
    }

    pub fn attestation(&self) -> &BridgeAttestation {
        &self.attestation
    }

    /// Register the sensing node with its parent. No key custody is recorded,
    /// so the attachment grades `Soft`: the signing key is the processing
    /// node's, and its custody is recorded separately in the attestation.
    pub fn attach(&self, now: u64) -> BridgedAttachment {
        BridgedAttachment {
            attachment: self.leaf.attach(&self.attestation.gateway, None, now),
            attestation: self.attestation.clone(),
        }
    }

    /// Add the sensing node's channels to the cluster catalogue.
    pub fn register_sensors(&self, registry: &mut SensorRegistry) {
        for c in CHANNELS.iter().filter(|c| c.origin == Origin::Module) {
            registry.register(Sensor {
                id: format!("{}/{}", self.leaf.id, c.suffix),
                kind: c.kind,
                unit: c.unit,
                host: self.leaf.id.clone(),
                domain: None,
                interval_s: self.interval_s,
            });
        }
    }

    /// Sign a sample's channels. Each carries its own provenance.
    pub fn ingest(&mut self, sample: &Sample, taken_at: u64) -> Result<Vec<BridgedReading>, NiclaError> {
        let mut out = Vec::new();
        for (suffix, value) in values_of(sample)? {
            let Some(c) = channel(suffix) else { continue };
            let sensor_id = format!("{}/{}", self.leaf.id, suffix);
            let reading = self.leaf.publish(&sensor_id, value, taken_at);
            let provenance = Provenance {
                version: 1,
                attestation_level: self.attestation.sensor_assurance,
                attestation: self.attestation.clone(),
                source_module: self.leaf.id.clone(),
                transport: self.transport,
                modality: c.kind.modality(),
                chain: vec![
                    Hop {
                        role: NodeRole::Sensing,
                        node_id: self.leaf.id.clone(),
                        attestation_level: self.attestation.sensor_assurance,
                        derivation: match c.derivation {
                            DerivationKind::Transducer => Derivation::Measured,
                            DerivationKind::OnSensor(a) => Derivation::OnSensor { algorithm: a.to_string() },
                        },
                    },
                    Hop {
                        role: self.gateway_role,
                        node_id: self.attestation.gateway.clone(),
                        attestation_level: self.attestation.gateway_assurance,
                        derivation: Derivation::Relayed,
                    },
                ],
                binding: self.binding.clone(),
            };
            let envelope_signature = self.leaf.sign_message(ENVELOPE_DOMAIN, &envelope_message(&reading, &provenance));
            out.push(BridgedReading { reading, provenance, envelope_signature, countersignatures: Vec::new() });
        }
        Ok(out)
    }
}

/// The wake-up variant of a sensor carries the same payload, scaling and meaning
/// as the base id; the module's stock firmware sends humidity only under its
/// wake-up id (134), so every variant is accepted.
pub fn base_sensor_id(id: u8) -> u8 {
    match id {
        6 => 4,
        15 => 13,
        24 => 22,
        35 => 34,
        53 => 52,
        132 => 128,
        133 => 129,
        134 => 130,
        135 => 131,
        other => other,
    }
}

/// Turn one binary record into samples. Ids outside what the node publishes are
/// an error rather than a silent drop, so a mis-configured hub is visible.
pub fn samples_from_record(rec: &Record, ranges: &Ranges) -> Result<Vec<Sample>, NiclaError> {
    let d = bhy2::decode(rec)?;
    let id = base_sensor_id(rec.sensor_id);
    Ok(match (id, d) {
        (4, Decoded::Vector3 { x, y, z }) => vec![ranges.acceleration(x, y, z)?],
        (13, Decoded::Vector3 { x, y, z }) => vec![ranges.angular_rate(x, y, z)?],
        (22, Decoded::Vector3 { x, y, z }) => vec![ranges.magnetic_field(x, y, z)?],
        (34, Decoded::Quaternion { x, y, z, w, accuracy_raw }) => {
            vec![Sample::Rotation { x, y, z, w, accuracy: Some(accuracy_raw as f64 / 16384.0) }]
        }
        (128, Decoded::Scalar(v)) => vec![Sample::Temperature(v)],
        (129, Decoded::Scalar(v)) => vec![Sample::Pressure(v)],
        (130, Decoded::Scalar(v)) => vec![Sample::Humidity(v)],
        (131, Decoded::Scalar(v)) => vec![Sample::GasResistance(v)],
        (52, Decoded::Scalar(v)) => vec![Sample::Steps(v as u32)],
        (63, Decoded::Activity(bits)) => bits
            .changes()
            .iter()
            .map(|c| {
                let base = match c.activity {
                    bhy2::Activity::Still => 0,
                    bhy2::Activity::Walking => 1,
                    bhy2::Activity::Running => 2,
                    bhy2::Activity::OnBicycle => 3,
                    bhy2::Activity::InVehicle => 4,
                    bhy2::Activity::Tilting => 5,
                    bhy2::Activity::InVehicleStill => 6,
                };
                Sample::Activity(base + if c.started { 8 } else { 0 })
            })
            .collect(),
        (115, Decoded::Bsec(b)) => vec![Sample::AirQuality {
            index: b.iaq_static as f64,
            co2_eq_ppm: b.co2_ppm,
            b_voc_eq_ppm: b.b_voc_ppm,
            accuracy: b.accuracy,
        }],
        _ => return Err(NiclaError::Decode(bhy2::DecodeError::Unsupported(id))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{enrol, fingerprint_of, ChipIds};
    use crate::text::{LineSplitter, TextSession};

    fn identity(serial: &str) -> SensingNodeIdentity {
        let chip = ChipIds { device_id: [7; 8], device_addr: [1, 2, 3, 4, 5, 6] };
        enrol(fingerprint_of(serial, Some(chip)).unwrap(), "bench", b"n").unwrap()
    }

    fn adapter_for(id: &SensingNodeIdentity, transport: Transport) -> NiclaAdapter {
        NiclaAdapter::new(
            Leaf::new(id.node_id.as_str(), [9u8; 32]),
            id,
            "furcate:node:micro1",
            NodeRole::MicroProcessing,
            AssuranceClass::Device,
            transport,
            1,
        )
        .unwrap()
    }

    fn adapter(transport: Transport) -> NiclaAdapter {
        adapter_for(&identity("SYNTH-0001"), transport)
    }

    fn parent_for(a: &NiclaAdapter) -> ParentPort {
        let mut p = ParentPort::new();
        p.accept(a.attach(0).attachment);
        p
    }

    #[test]
    fn the_leaf_must_carry_the_enrolled_identity() {
        let id = identity("SYNTH-0001");
        let r = NiclaAdapter::new(
            Leaf::new("other", [1; 32]),
            &id,
            "g",
            NodeRole::MicroProcessing,
            AssuranceClass::Soft,
            Transport::UsbText,
            1,
        );
        assert!(matches!(r, Err(NiclaError::LeafIdMismatch { .. })));
        assert_eq!(adapter(Transport::UsbText).leaf_id(), id.node_id.as_str());
    }

    #[test]
    fn the_sensing_node_attaches_as_soft_fingerprint_identified() {
        let a = adapter(Transport::UsbText);
        let att = a.attach(5);
        assert_eq!(att.attachment.assurance(), AssuranceClass::Soft);
        assert_eq!(att.attestation.sensor_root_of_trust, SensorRootOfTrust::None);
        assert_eq!(att.attestation.gateway_assurance, AssuranceClass::Device);
        assert!(matches!(att.attestation.identity_basis, IdentityBasis::Fingerprint { .. }));
        assert!(att.attestation.statement.starts_with("Fingerprint-identified, not hardware-keyed"));
        assert!(!att.attestation.enrollment_digest.is_empty());
    }

    #[test]
    fn a_parent_that_requires_device_class_refuses_the_sensing_node() {
        let mut a = adapter(Transport::UsbText);
        let mut parent = parent_for(&a);
        let b = a.ingest(&Sample::Temperature(21.0), 1).unwrap().remove(0);
        assert_eq!(
            verify_bridged(&mut parent, &b, AssuranceClass::Device),
            Err(LeafError::AssuranceTooLow { required: AssuranceClass::Device, found: AssuranceClass::Soft })
        );
        assert!(verify_bridged(&mut parent, &b, AssuranceClass::Soft).is_ok());
    }

    #[test]
    fn provenance_is_covered_by_the_signature() {
        let mut a = adapter(Transport::UsbText);
        let mut parent = parent_for(&a);
        let mut b = a.ingest(&Sample::Temperature(21.0), 1).unwrap().remove(0);
        // Claiming a stronger board after the fact must fail.
        b.provenance.attestation_level = AssuranceClass::Tpm;
        assert_eq!(verify_bridged(&mut parent, &b, AssuranceClass::Soft), Err(LeafError::BadSignature));
        // A failed envelope does not burn the sequence number.
        let good = a.ingest(&Sample::Temperature(22.0), 2).unwrap().remove(0);
        assert!(verify_bridged(&mut parent, &good, AssuranceClass::Soft).is_ok());
    }

    #[test]
    fn a_replayed_bridged_reading_is_refused() {
        let mut a = adapter(Transport::UsbText);
        let mut parent = parent_for(&a);
        let b = a.ingest(&Sample::Temperature(21.0), 1).unwrap().remove(0);
        assert!(verify_bridged(&mut parent, &b, AssuranceClass::Soft).is_ok());
        assert!(matches!(
            verify_bridged(&mut parent, &b, AssuranceClass::Soft),
            Err(LeafError::StaleSequence { .. })
        ));
    }

    #[test]
    fn a_reading_from_a_swapped_unit_does_not_verify_against_the_enrolled_one() {
        let mut a = adapter(Transport::UsbText);
        let mut other = adapter_for(&identity("OTHERUNIT"), Transport::UsbText);
        let mut parent = parent_for(&a);
        let b = other.ingest(&Sample::Temperature(21.0), 1).unwrap().remove(0);
        assert_eq!(verify_bridged(&mut parent, &b, AssuranceClass::Soft), Err(LeafError::NotAttached));
        let _ = a.ingest(&Sample::Temperature(1.0), 1);
    }

    #[test]
    fn the_chain_is_open_ended_and_each_rung_signs() {
        let mut a = adapter(Transport::UsbFrame);
        let mut b = a.ingest(&Sample::Temperature(21.0), 1).unwrap().remove(0);
        assert_eq!(b.provenance.chain.len(), 2);
        assert_eq!(b.provenance.chain[0].role, NodeRole::Sensing);
        assert_eq!(b.provenance.chain[1].role, NodeRole::MicroProcessing);

        let small = Leaf::new("furcate:node:small1", [3u8; 32]);
        let large = Leaf::new("furcate:node:large1", [4u8; 32]);
        let hop = |l: &Leaf, role, level, derivation| Hop { role, node_id: l.id.clone(), attestation_level: level, derivation };
        countersign(&mut b, &small, hop(&small, NodeRole::SmallProcessing, AssuranceClass::Soft, Derivation::Relayed)).unwrap();
        let model = ModelRef { id: "anomaly-v3".into(), sha256: "ab".repeat(32) };
        countersign(&mut b, &large, hop(&large, NodeRole::LargeProcessing, AssuranceClass::Tpm, Derivation::Model(model.clone()))).unwrap();

        let keys = |id: &str| match id {
            "furcate:node:small1" => Some(small.public_key()),
            "furcate:node:large1" => Some(large.public_key()),
            _ => None,
        };
        assert_eq!(verify_countersignatures(&b, &keys), Ok(()));
        assert_eq!(b.countersignatures[1].hop.derivation, Derivation::Model(model));

        // Altering an earlier rung's hop, or the model, breaks the chain.
        let mut t = b.clone();
        t.countersignatures[0].hop.attestation_level = AssuranceClass::Tpm;
        assert!(verify_countersignatures(&t, &keys).is_err());
        let mut t = b.clone();
        t.countersignatures[1].hop.derivation = Derivation::Relayed;
        assert!(verify_countersignatures(&t, &keys).is_err());
        // Removing a rung from the middle breaks the later signature.
        let mut t = b.clone();
        t.countersignatures.remove(0);
        assert!(verify_countersignatures(&t, &keys).is_err());
        // A rung nobody enrolled is unknown, not trusted.
        assert_eq!(verify_countersignatures(&b, &|_| None), Err(LeafError::NotAttached));
    }

    #[test]
    fn a_rung_cannot_sign_as_another_node() {
        let mut a = adapter(Transport::UsbFrame);
        let mut b = a.ingest(&Sample::Temperature(21.0), 1).unwrap().remove(0);
        let small = Leaf::new("furcate:node:small1", [3u8; 32]);
        let hop = Hop { role: NodeRole::SmallProcessing, node_id: "furcate:node:someone-else".into(), attestation_level: AssuranceClass::Tpm, derivation: Derivation::Relayed };
        assert!(countersign(&mut b, &small, hop).is_err());
    }

    #[test]
    fn modality_follows_how_the_value_is_made() {
        let mut a = adapter(Transport::UsbFrame);
        let acc = a.ingest(&Sample::Acceleration { x: 0.0, y: 0.0, z: 9.8 }, 1).unwrap();
        assert!(acc.iter().all(|b| b.provenance.modality == Modality::Direct));
        assert!(acc.iter().all(|b| b.provenance.chain[0].derivation == Derivation::Measured));
        let rot = a.ingest(&Sample::Rotation { x: 0.0, y: 0.0, z: 0.0, w: 1.0, accuracy: None }, 1).unwrap();
        assert_eq!(rot.len(), 4);
        assert!(rot.iter().all(|b| b.provenance.modality == Modality::Inferred));
        assert!(matches!(&rot[0].provenance.chain[0].derivation, Derivation::OnSensor { algorithm } if algorithm == "bhi260ap-sensor-fusion"));
        assert!(!SensorKind::GasEquivalent.may_actuate_alone());
        assert!(!SensorKind::StepCount.may_actuate_alone());
        assert!(SensorKind::Acceleration.may_actuate_alone());
    }

    #[test]
    fn air_quality_is_withheld_until_the_sensor_is_stabilised() {
        let mut a = adapter(Transport::UsbFrame);
        let s = Sample::AirQuality { index: 50.0, co2_eq_ppm: 600.0, b_voc_eq_ppm: 1.0, accuracy: 0 };
        assert!(matches!(a.ingest(&s, 1), Err(NiclaError::Withheld(_))));
        let s = Sample::AirQuality { index: 50.0, co2_eq_ppm: 600.0, b_voc_eq_ppm: 1.0, accuracy: 2 };
        assert_eq!(a.ingest(&s, 1).unwrap().len(), 3);
    }

    #[test]
    fn non_finite_values_are_refused() {
        let mut a = adapter(Transport::UsbFrame);
        assert!(matches!(a.ingest(&Sample::Temperature(f64::NAN), 1), Err(NiclaError::NonFinite)));
        assert!(matches!(a.ingest(&Sample::Pressure(f64::INFINITY), 1), Err(NiclaError::NonFinite)));
    }

    #[test]
    fn the_sensing_node_registers_every_channel_under_its_identity() {
        let a = adapter(Transport::UsbText);
        let mut r = SensorRegistry::new();
        a.register_sensors(&mut r);
        assert_eq!(r.len(), CHANNELS.iter().filter(|c| c.origin == Origin::Module).count());
        assert_eq!(r.of_kind(SensorKind::Acceleration).len(), 3);
        assert_eq!(r.of_kind(SensorKind::Temperature).len(), 1);
        let n = CHANNELS.iter().filter(|c| c.origin == Origin::Module).count();
        assert_eq!(r.hosted_by(a.leaf_id()).len(), n);
        assert_eq!(r.forget_host(a.leaf_id()), n);
    }

    #[test]
    fn units_and_scales_are_physical() {
        let mut r = Ranges::default();
        r.set_accel(2.0).unwrap();
        r.set_gyro(1000.0).unwrap();
        let Sample::Acceleration { x, .. } = r.acceleration(-32768, 0, 0).unwrap() else { panic!() };
        assert!((x + 2.0 * G).abs() < 1e-9);
        let Sample::AngularRate { y, .. } = r.angular_rate(0, 16384, 0).unwrap() else { panic!() };
        assert!((y - 500.0_f64.to_radians()).abs() < 1e-9);
        assert!(r.set_accel(0.0).is_err() && r.set_gyro(f64::NAN).is_err());
        assert!(matches!(r.magnetic_field(1, 2, 3), Err(NiclaError::RangeUnknown(_))));
    }

    #[test]
    fn binary_records_become_the_same_samples() {
        let mut r = Ranges::default();
        r.set_accel(2.0).unwrap();
        let rec = Record::new(4, &[0, 0, 0, 0, 0, 0x40]); // z = 16384
        let s = samples_from_record(&rec, &r).unwrap();
        assert!(matches!(&s[0], Sample::Acceleration { z, .. } if (*z - G).abs() < 1e-9));
        assert_eq!(samples_from_record(&Record::new(128, &2829i16.to_le_bytes()), &r).unwrap(), vec![Sample::Temperature(28.29)]);
        let act = samples_from_record(&Record::new(63, &(1u16 << 9).to_le_bytes()), &r).unwrap();
        assert_eq!(act, vec![Sample::Activity(9)]);
        assert!(samples_from_record(&Record::new(1, &[0; 6]), &r).is_err());
        assert!(samples_from_record(&Record::new(4, &[0; 6]), &Ranges::default()).is_err());
    }

    /// Every channel the module publishes decodes from a constructed binary record, and
    /// the wake-up variant of each sensor means the same as its base id.
    #[test]
    fn every_module_channel_decodes_from_a_binary_record() {
        let mut r = Ranges::default();
        r.set_accel(8.0).unwrap();
        r.set_gyro(2000.0).unwrap();
        r.set_mag(1300.0).unwrap();
        let one = |id: u8, p: &[u8]| samples_from_record(&Record::new(id, p), &r).unwrap();
        // Magnetometer: 1000 counts at 1300 uT full scale.
        let mag = one(22, &[0xE8, 0x03, 0, 0, 0x18, 0xFC]);
        assert!(matches!(&mag[0], Sample::MagneticField { x, y, z }
            if (*x - 1000.0 * 1300.0 / 32768.0).abs() < 1e-9 && *y == 0.0 && (*z + 1000.0 * 1300.0 / 32768.0).abs() < 1e-9));
        assert_eq!(one(24, &[0xE8, 0x03, 0, 0, 0x18, 0xFC]), mag, "wake-up magnetometer");
        // Rotation vector: identity with accuracy field 0x4000 (1.0 rad).
        let rot = one(34, &[0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0x40]);
        assert_eq!(rot, vec![Sample::Rotation { x: 0.0, y: 0.0, z: 0.0, w: 1.0, accuracy: Some(1.0) }]);
        assert_eq!(one(35, &[0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0x40]), rot);
        // Pressure: the module sends 1/128 hPa, so 1013.25 hPa is 129696.
        let prs = one(129, &129_696u32.to_le_bytes()[..3]);
        assert_eq!(prs, vec![Sample::Pressure(101_325.0)]);
        assert_eq!(one(133, &129_696u32.to_le_bytes()[..3]), prs);
        // Humidity under both ids, temperature and gas under their wake-up ids.
        assert_eq!(one(130, &[47]), vec![Sample::Humidity(47.0)]);
        assert_eq!(one(134, &[47]), vec![Sample::Humidity(47.0)]);
        assert_eq!(one(132, &2829i16.to_le_bytes()), vec![Sample::Temperature(28.29)]);
        assert_eq!(one(135, &949u32.to_le_bytes()), vec![Sample::GasResistance(949.0)]);
        // Steps, including the wake-up id.
        assert_eq!(one(52, &1234u32.to_le_bytes()), vec![Sample::Steps(1234)]);
        assert_eq!(one(53, &1234u32.to_le_bytes()), vec![Sample::Steps(1234)]);
        // Air quality from the vendor's algorithm: static index, CO2 and breath VOC equivalents.
        let mut p = Vec::new();
        p.extend(85u16.to_le_bytes());
        p.extend(90u16.to_le_bytes());
        p.extend(123u16.to_le_bytes());
        p.extend(&650u32.to_le_bytes()[..3]);
        p.push(3);
        p.extend((25i16 * 256).to_le_bytes());
        p.extend((40u16 * 500).to_le_bytes());
        p.extend(52_000f32.to_le_bytes());
        let iaq = one(115, &p);
        assert!(matches!(&iaq[0], Sample::AirQuality { index, co2_eq_ppm, accuracy: 3, .. } if *index == 90.0 && *co2_eq_ppm == 650.0));
        // A magnetometer record with no range stated is refused, not guessed.
        assert!(matches!(
            samples_from_record(&Record::new(22, &[0; 6]), &Ranges::default()),
            Err(NiclaError::RangeUnknown("magnetometer"))
        ));
        // An id the node does not publish is an error, not a silent drop.
        assert!(samples_from_record(&Record::new(117, &[0; 5]), &r).is_err());
    }

    #[test]
    fn the_host_chip_is_a_channel_of_its_own() {
        let chip = channel("chip.tmp").unwrap();
        assert_eq!((chip.origin, chip.kind, chip.unit), (Origin::HostChip, SensorKind::Temperature, Unit::Celsius));
        assert_eq!(channel("tmp").unwrap().origin, Origin::Module);
        let mut registry = SensorRegistry::new();
        let a = adapter(Transport::UsbFrame);
        a.register_sensors(&mut registry);
        assert!(registry.get(&format!("{}/chip.tmp", a.leaf_id())).is_none(), "the module never publishes the host chip's temperature");
        assert!(registry.get(&format!("{}/tmp", a.leaf_id())).is_some());
    }

    /// The recorded fixture end to end: lines to samples to signed readings
    /// that a parent accepts and finds in the catalogue.
    #[test]
    fn the_captured_fixture_flows_end_to_end() {
        let capture = include_str!("../tests/fixtures/nicla-standalone-usb.txt");
        let mut a = adapter(Transport::UsbText);
        let mut parent = parent_for(&a);
        let mut registry = SensorRegistry::new();
        a.register_sensors(&mut registry);
        let mut session = TextSession::new();
        let mut accepted = 0;
        let mut seen = std::collections::BTreeSet::new();
        for (i, line) in LineSplitter::new().push(capture.as_bytes()).into_iter().enumerate() {
            let Some(sample) = session.feed_line(&line).unwrap() else { continue };
            for b in a.ingest(&sample, 100 + i as u64).unwrap() {
                verify_bridged(&mut parent, &b, AssuranceClass::Soft).unwrap();
                assert!(registry.get(&b.reading.sensor_id).is_some(), "{}", b.reading.sensor_id);
                seen.insert(b.reading.sensor_id.rsplit('/').next().unwrap().to_string());
                accepted += 1;
            }
        }
        // acceleration 3, gyroscope 3, temperature 1, gas 1, rotation 4.
        assert_eq!(accepted, 12);
        for want in ["acc.x", "gyr.z", "tmp", "gas", "rot.w"] {
            assert!(seen.contains(want), "{want}");
        }
    }
}
