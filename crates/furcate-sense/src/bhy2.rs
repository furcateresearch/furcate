//! The BHY2 sensor protocol: request encoding, reply framing and payload
//! decoding.
//!
//! Pure functions over byte slices. Nothing here opens a port, reads a clock
//! or allocates beyond the records a reply carries, so every rule can be
//! tested with constructed bytes and garbage cannot reach anything with side
//! effects.
//!
//! ## Provenance and status
//!
//! This is an independent implementation written from the documented protocol:
//! the frame layouts, sensor ids and fixed-point scalings that the vendor
//! publishes and that Bosch's sensor hub defines. It contains no code from the
//! Arduino host or device libraries, which are AGPL-3.0 and must not be copied
//! into this Apache-2.0 crate. **Nothing in this module has been checked
//! against a live board**: the stock `App` sketch answers only over ESLOV (I2C)
//! or BLE and keeps USB serial silent, so there is no binary stream on a bare
//! USB cable to record. The transport verified on hardware is the text path in
//! [`crate::text`]; the production serial path is the framed format in
//! [`crate::frame`].
//!
//! ## The protocol
//!
//! The host drives; the sensor hub never speaks unprompted.
//!
//! | Request | Bytes | Reply |
//! |---|---|---|
//! | read short | `02` | `n`, then `n` records of 12 bytes |
//! | read long | `04` | `n`, then `n` records of 23 bytes (20 in older libraries) |
//! | configure | `03`, id, rate (f32 LE), latency (u32 LE) | one byte, `0F` for acknowledged |
//!
//! A record is the sensor id, a size byte, then the payload zero-padded to the
//! channel width. The size byte counts the payload **plus one** (it mirrors the
//! Bosch FIFO `data_size`, which includes the id byte). The vendor tool treats
//! it as the payload length and over-reads by one; this module uses the
//! library's own definition.
//!
//! There is no sync marker and no checksum. A reply that is cut short cannot be
//! told from a slow one, and a desynchronised stream cannot be recovered by
//! scanning, so [`parse_read_reply`] reports exactly how many bytes it still
//! needs and the transport is expected to discard input and re-ask on timeout.

use std::fmt;

pub const OP_READ: u8 = 2;
pub const OP_CONFIG: u8 = 3;
pub const OP_LONG_READ: u8 = 4;
pub const ACK: u8 = 0x0F;
pub const NACK: u8 = 0x00;

/// Payload capacity of a short record.
pub const SHORT_DATA_LEN: usize = 10;
/// Payload capacity of a long record in the current library.
pub const LONG_DATA_LEN: usize = 21;
/// Payload capacity of a long record in libraries before the BSEC2 collector.
pub const LONG_DATA_LEN_LEGACY: usize = 18;
/// Largest latency the sensor hub accepts: the field is 24 bits.
pub const MAX_LATENCY_MS: u32 = 0x00FF_FFFF;

/// Which read a reply answers, which fixes the record width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadKind {
    Short,
    Long,
    /// Long records as the older library and the vendor tool size them.
    LongLegacy,
}

impl ReadKind {
    pub fn opcode(self) -> u8 {
        match self {
            ReadKind::Short => OP_READ,
            ReadKind::Long | ReadKind::LongLegacy => OP_LONG_READ,
        }
    }

    pub fn data_len(self) -> usize {
        match self {
            ReadKind::Short => SHORT_DATA_LEN,
            ReadKind::Long => LONG_DATA_LEN,
            ReadKind::LongLegacy => LONG_DATA_LEN_LEGACY,
        }
    }

    pub fn record_len(self) -> usize {
        2 + self.data_len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ends before the frame does; this many more bytes are needed.
    Incomplete { needed: usize },
    /// The sensor id is not in the library's table.
    UnknownSensor(u8),
    /// The id is known but this module does not decode its payload.
    Unsupported(u8),
    /// The record carries fewer payload bytes than the sensor's format needs.
    Short { sensor_id: u8, needed: usize, got: usize },
    /// The configuration is outside what the hub accepts.
    BadConfig(&'static str),
    /// The hub refused the configuration.
    Nack,
    /// The acknowledgement byte was neither `0F` nor `00`.
    BadAck(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Incomplete { needed } => write!(f, "frame incomplete: {needed} more bytes needed"),
            DecodeError::UnknownSensor(id) => write!(f, "sensor id {id} is not in the table"),
            DecodeError::Unsupported(id) => write!(f, "sensor id {id} has no decoder"),
            DecodeError::Short { sensor_id, needed, got } => {
                write!(f, "sensor {sensor_id} payload is {got} bytes, needs {needed}")
            }
            DecodeError::BadConfig(why) => write!(f, "sensor configuration refused: {why}"),
            DecodeError::Nack => write!(f, "sensor hub refused the configuration"),
            DecodeError::BadAck(b) => write!(f, "unexpected acknowledgement byte {b:#04x}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Payload formats, named after the library's `SensorPayload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload {
    Quaternion,
    Vector3,
    Euler,
    U8,
    I16,
    U16,
    U24,
    U32,
    Event,
    Activity,
    Debug,
    Timestamp,
    Bsec,
    BsecLegacy,
    Bsec2,
    Bsec2Collector,
    Klio,
}

/// Every sensor id of the protocol: id, payload format, scale for the scalar formats.
const SENSORS: &[(u8, Payload, f64)] = &[
    (1, Payload::Vector3, 1.0),
    (3, Payload::Vector3, 1.0),
    (4, Payload::Vector3, 1.0),
    (5, Payload::Vector3, 1.0),
    (6, Payload::Vector3, 1.0),
    (7, Payload::Vector3, 1.0),
    (10, Payload::Vector3, 1.0),
    (12, Payload::Vector3, 1.0),
    (13, Payload::Vector3, 1.0),
    (14, Payload::Vector3, 1.0),
    (15, Payload::Vector3, 1.0),
    (16, Payload::Vector3, 1.0),
    (19, Payload::Vector3, 1.0),
    (21, Payload::Vector3, 1.0),
    (22, Payload::Vector3, 1.0),
    (23, Payload::Vector3, 1.0),
    (24, Payload::Vector3, 1.0),
    (25, Payload::Vector3, 1.0),
    (28, Payload::Vector3, 1.0),
    (29, Payload::Vector3, 1.0),
    (31, Payload::Vector3, 1.0),
    (32, Payload::Vector3, 1.0),
    (34, Payload::Quaternion, 1.0),
    (35, Payload::Quaternion, 1.0),
    (37, Payload::Quaternion, 1.0),
    (38, Payload::Quaternion, 1.0),
    (40, Payload::Quaternion, 1.0),
    (41, Payload::Quaternion, 1.0),
    (43, Payload::Euler, 0.01098),
    (44, Payload::Euler, 0.01098),
    (48, Payload::Event, 1.0),
    (50, Payload::Event, 1.0),
    (52, Payload::U32, 1.0),
    (53, Payload::U32, 1.0),
    (55, Payload::Event, 1.0),
    (57, Payload::Event, 1.0),
    (59, Payload::Event, 1.0),
    (61, Payload::Event, 1.0),
    (63, Payload::Activity, 1.0),
    (67, Payload::Event, 1.0),
    (69, Payload::U8, 1.0),
    (70, Payload::U8, 1.0),
    (75, Payload::Event, 1.0),
    (77, Payload::Event, 1.0),
    (91, Payload::Vector3, 1.0),
    (92, Payload::Vector3, 1.0),
    (93, Payload::Vector3, 1.0),
    (94, Payload::Event, 1.0),
    (112, Payload::Klio, 1.0),
    (115, Payload::Bsec, 1.0),
    (116, Payload::Bsec2Collector, 1.0),
    (117, Payload::Bsec2, 1.0),
    (128, Payload::I16, 0.01),
    (129, Payload::U24, 0.0078125),
    (130, Payload::U8, 1.0),
    (131, Payload::U32, 1.0),
    (132, Payload::I16, 0.01),
    (133, Payload::U24, 0.0078125),
    (134, Payload::U8, 1.0),
    (135, Payload::U32, 1.0),
    (136, Payload::U32, 1.0),
    (137, Payload::Event, 1.0),
    (138, Payload::Event, 1.0),
    (139, Payload::U32, 1.0),
    (140, Payload::Event, 1.0),
    (141, Payload::Event, 1.0),
    (142, Payload::Event, 1.0),
    (143, Payload::Event, 1.0),
    (144, Payload::U8, 1.0),
    (145, Payload::Vector3, 1.0),
    (146, Payload::U16, 46.296),
    (147, Payload::U8, 1.0),
    (148, Payload::U16, 46.296),
    (149, Payload::U8, 1.0),
    (171, Payload::BsecLegacy, 1.0),
    (245, Payload::Timestamp, 0.000015625),
    (246, Payload::Timestamp, 0.000015625),
    (247, Payload::Timestamp, 0.000015625),
    (250, Payload::Debug, 1.0),
    (251, Payload::Timestamp, 0.000015625),
    (252, Payload::Timestamp, 0.000015625),
    (253, Payload::Timestamp, 0.000015625),
];

pub fn payload_of(id: u8) -> Option<Payload> {
    SENSORS.iter().find(|s| s.0 == id).map(|s| s.1)
}

fn scale_of(id: u8) -> f64 {
    SENSORS.iter().find(|s| s.0 == id).map(|s| s.2).unwrap_or(1.0)
}

/// One sensor sample as carried on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub sensor_id: u8,
    /// The size byte as sent: payload length plus one.
    pub size: u8,
    data: [u8; LONG_DATA_LEN],
    stored: u8,
}

impl Record {
    /// Read one record of the given width from exactly `kind.record_len()` bytes.
    pub fn from_wire(bytes: &[u8], kind: ReadKind) -> Result<Record, DecodeError> {
        let need = kind.record_len();
        if bytes.len() < need {
            return Err(DecodeError::Incomplete { needed: need - bytes.len() });
        }
        let size = bytes[1];
        let stored = (size.saturating_sub(1) as usize).min(kind.data_len());
        let mut data = [0u8; LONG_DATA_LEN];
        data[..stored].copy_from_slice(&bytes[2..2 + stored]);
        Ok(Record { sensor_id: bytes[0], size, data, stored: stored as u8 })
    }

    /// Build a record from a payload, for tests and for simulating a hub.
    pub fn new(sensor_id: u8, payload: &[u8]) -> Record {
        let stored = payload.len().min(LONG_DATA_LEN);
        let mut data = [0u8; LONG_DATA_LEN];
        data[..stored].copy_from_slice(&payload[..stored]);
        Record { sensor_id, size: (stored + 1) as u8, data, stored: stored as u8 }
    }

    /// The payload bytes that arrived.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.stored as usize]
    }

    /// Whether the hub sent more payload than the channel can carry.
    pub fn truncated(&self) -> bool {
        (self.size.saturating_sub(1)) > self.stored
    }

    /// Whether the id travels on the long channel.
    pub fn is_long_sensor(&self) -> bool {
        matches!(
            payload_of(self.sensor_id),
            Some(Payload::Bsec | Payload::BsecLegacy | Payload::Bsec2Collector | Payload::Klio)
        )
    }
}

/// A parsed reply to a read request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadReply {
    pub records: Vec<Record>,
    /// Bytes of the buffer the reply occupied.
    pub consumed: usize,
}

pub fn encode_read(kind: ReadKind) -> [u8; 1] {
    [kind.opcode()]
}

/// Parse the reply to a read: a count byte, then that many records.
pub fn parse_read_reply(buf: &[u8], kind: ReadKind) -> Result<ReadReply, DecodeError> {
    let Some(&count) = buf.first() else {
        return Err(DecodeError::Incomplete { needed: 1 });
    };
    let width = kind.record_len();
    let total = 1 + count as usize * width;
    if buf.len() < total {
        return Err(DecodeError::Incomplete { needed: total - buf.len() });
    }
    let mut records = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let at = 1 + i * width;
        records.push(Record::from_wire(&buf[at..at + width], kind)?);
    }
    Ok(ReadReply { records, consumed: total })
}

/// A request to start, change or stop a sensor.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SensorConfig {
    pub sensor_id: u8,
    /// Zero disables the sensor.
    pub sample_rate_hz: f32,
    /// How long the hub may hold a sample before notifying the host.
    pub latency_ms: u32,
}

impl SensorConfig {
    pub fn new(sensor_id: u8, sample_rate_hz: f32, latency_ms: u32) -> Result<Self, DecodeError> {
        if !sample_rate_hz.is_finite() || sample_rate_hz < 0.0 {
            return Err(DecodeError::BadConfig("sample rate must be finite and not negative"));
        }
        if latency_ms > MAX_LATENCY_MS {
            return Err(DecodeError::BadConfig("latency does not fit in 24 bits"));
        }
        Ok(Self { sensor_id, sample_rate_hz, latency_ms })
    }

    pub fn disable(sensor_id: u8) -> Self {
        Self { sensor_id, sample_rate_hz: 0.0, latency_ms: 0 }
    }

    /// The nine-byte packet, as written to the BLE configuration characteristic.
    pub fn encode_packet(&self) -> [u8; 9] {
        let mut out = [0u8; 9];
        out[0] = self.sensor_id;
        out[1..5].copy_from_slice(&self.sample_rate_hz.to_le_bytes());
        out[5..9].copy_from_slice(&self.latency_ms.to_le_bytes());
        out
    }

    /// The ten-byte request, opcode first, as written over a serial or ESLOV link.
    pub fn encode_request(&self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0] = OP_CONFIG;
        out[1..].copy_from_slice(&self.encode_packet());
        out
    }
}

pub fn parse_ack(byte: u8) -> Result<(), DecodeError> {
    match byte {
        ACK => Ok(()),
        NACK => Err(DecodeError::Nack),
        other => Err(DecodeError::BadAck(other)),
    }
}

/// Quaternion components are signed 16-bit fixed point with 14 fractional bits.
const QUAT_SCALE: f64 = 1.0 / 16384.0;
/// Euler angles are signed 16-bit over a full turn.
const EULER_DEG: f64 = 360.0 / 32768.0;

/// One activity the on-chip classifier reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    Still,
    Walking,
    Running,
    OnBicycle,
    InVehicle,
    Tilting,
    InVehicleStill,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityChange {
    pub activity: Activity,
    pub started: bool,
}

/// The activity word: bits 0 to 6 mark an activity ended, bits 8 to 14 one started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivityBits(pub u16);

impl ActivityBits {
    /// Every change in the word, ended before started. The vendor tool reports
    /// only the lowest set bit; a word can carry both an end and a start.
    pub fn changes(&self) -> Vec<ActivityChange> {
        const ALL: [Activity; 7] = [
            Activity::Still,
            Activity::Walking,
            Activity::Running,
            Activity::OnBicycle,
            Activity::InVehicle,
            Activity::Tilting,
            Activity::InVehicleStill,
        ];
        let mut out = Vec::new();
        for started in [false, true] {
            for (i, a) in ALL.iter().enumerate() {
                let bit = i + if started { 8 } else { 0 };
                if self.0 & (1 << bit) != 0 {
                    out.push(ActivityChange { activity: *a, started });
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bsec {
    pub iaq: u16,
    pub iaq_static: u16,
    pub b_voc_ppm: f64,
    pub co2_ppm: f64,
    /// 0 is stabilising, 3 is calibrated.
    pub accuracy: u8,
    pub temperature_c: f64,
    pub humidity_pct: f64,
    pub gas_resistance_ohm: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bsec2 {
    pub gas_estimates: [u8; 4],
    pub accuracy: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bsec2Collector {
    pub timestamp_ms: u64,
    pub temperature_c: f64,
    pub pressure_pa: f64,
    pub humidity_pct: f64,
    pub gas_resistance_ohm: f64,
    pub gas_index: u8,
}

/// A decoded payload. Vectors stay in raw counts because their scale is a
/// configuration of the hub that the wire does not carry.
#[derive(Clone, Debug, PartialEq)]
pub enum Decoded {
    Vector3 { x: i16, y: i16, z: i16 },
    /// Components are unit-quaternion values; accuracy is the raw field.
    Quaternion { x: f64, y: f64, z: f64, w: f64, accuracy_raw: u16 },
    Euler { heading_deg: f64, pitch_deg: f64, roll_deg: f64 },
    /// A single scaled number: temperature in degrees C, pressure in Pa,
    /// humidity in percent, a step count, and so on per sensor id.
    Scalar(f64),
    Event,
    Activity(ActivityBits),
    Bsec(Bsec),
    Bsec2(Bsec2),
    Bsec2Collector(Bsec2Collector),
}

fn need(r: &Record, n: usize) -> Result<&[u8], DecodeError> {
    let p = r.payload();
    if p.len() < n {
        Err(DecodeError::Short { sensor_id: r.sensor_id, needed: n, got: p.len() })
    } else {
        Ok(&p[..n])
    }
}

fn le_i16(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}
fn le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le_f32(b: &[u8], at: usize) -> f64 {
    f32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as f64
}

/// Decode one record. Never panics, whatever the bytes.
pub fn decode(r: &Record) -> Result<Decoded, DecodeError> {
    let payload = payload_of(r.sensor_id).ok_or(DecodeError::UnknownSensor(r.sensor_id))?;
    let scale = scale_of(r.sensor_id);
    Ok(match payload {
        Payload::Vector3 => {
            let b = need(r, 6)?;
            Decoded::Vector3 { x: le_i16(b, 0), y: le_i16(b, 2), z: le_i16(b, 4) }
        }
        Payload::Quaternion => {
            let b = need(r, 10)?;
            Decoded::Quaternion {
                x: le_i16(b, 0) as f64 * QUAT_SCALE,
                y: le_i16(b, 2) as f64 * QUAT_SCALE,
                z: le_i16(b, 4) as f64 * QUAT_SCALE,
                w: le_i16(b, 6) as f64 * QUAT_SCALE,
                accuracy_raw: le_u16(b, 8),
            }
        }
        Payload::Euler => {
            let b = need(r, 6)?;
            Decoded::Euler {
                heading_deg: le_i16(b, 0) as f64 * EULER_DEG,
                pitch_deg: le_i16(b, 2) as f64 * EULER_DEG,
                roll_deg: le_i16(b, 4) as f64 * EULER_DEG,
            }
        }
        Payload::U8 => Decoded::Scalar(need(r, 1)?[0] as f64 * scale),
        Payload::I16 => Decoded::Scalar(le_i16(need(r, 2)?, 0) as f64 * scale),
        Payload::U16 => Decoded::Scalar(le_u16(need(r, 2)?, 0) as f64 * scale),
        Payload::U24 => {
            let b = need(r, 3)?;
            Decoded::Scalar(u32::from_le_bytes([b[0], b[1], b[2], 0]) as f64 * scale)
        }
        Payload::U32 => {
            let b = need(r, 4)?;
            Decoded::Scalar(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64 * scale)
        }
        Payload::Event => Decoded::Event,
        Payload::Activity => Decoded::Activity(ActivityBits(le_u16(need(r, 2)?, 0))),
        Payload::Bsec => {
            let b = need(r, 18)?;
            Decoded::Bsec(Bsec {
                iaq: le_u16(b, 0),
                iaq_static: le_u16(b, 2),
                b_voc_ppm: le_u16(b, 4) as f64 * 0.01,
                co2_ppm: u32::from_le_bytes([b[6], b[7], b[8], 0]) as f64,
                accuracy: b[9],
                temperature_c: le_i16(b, 10) as f64 / 256.0,
                humidity_pct: le_u16(b, 12) as f64 / 500.0,
                gas_resistance_ohm: le_f32(b, 14),
            })
        }
        Payload::Bsec2 => {
            let b = need(r, 5)?;
            Decoded::Bsec2(Bsec2 { gas_estimates: [b[0], b[1], b[2], b[3]], accuracy: b[4] })
        }
        Payload::Bsec2Collector => {
            let b = need(r, 21)?;
            let mut ts = [0u8; 8];
            ts.copy_from_slice(&b[..8]);
            Decoded::Bsec2Collector(Bsec2Collector {
                timestamp_ms: u64::from_le_bytes(ts),
                temperature_c: le_i16(b, 8) as f64 / 256.0,
                pressure_pa: le_f32(b, 10),
                humidity_pct: le_u16(b, 14) as f64 / 500.0,
                gas_resistance_ohm: le_f32(b, 16),
                gas_index: b[20],
            })
        }
        Payload::BsecLegacy | Payload::Klio | Payload::Debug | Payload::Timestamp => {
            return Err(DecodeError::Unsupported(r.sensor_id))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(id: u8, payload: &[u8], kind: ReadKind) -> Vec<u8> {
        let mut v = vec![id, payload.len() as u8 + 1];
        v.extend_from_slice(payload);
        v.resize(kind.record_len(), 0);
        v
    }

    #[test]
    fn read_requests_are_one_opcode_byte() {
        assert_eq!(encode_read(ReadKind::Short), [2]);
        assert_eq!(encode_read(ReadKind::Long), [4]);
    }

    #[test]
    fn a_config_request_matches_the_vendor_tool_byte_for_byte() {
        // `bhy sensor config -sensor 10 -rate 1 -latency 0`: opcode 3, id 10,
        // 1.0f32 little endian, latency zero.
        let c = SensorConfig::new(10, 1.0, 0).unwrap();
        assert_eq!(c.encode_request(), [3, 10, 0x00, 0x00, 0x80, 0x3F, 0, 0, 0, 0]);
        assert_eq!(c.encode_packet().len(), 9);
        assert_eq!(&c.encode_request()[1..], &c.encode_packet()[..]);
    }

    #[test]
    fn disabling_is_rate_zero_latency_zero() {
        assert_eq!(SensorConfig::disable(10).encode_request(), [3, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn configuration_the_hub_cannot_hold_is_refused_before_sending() {
        assert!(SensorConfig::new(1, f32::NAN, 0).is_err());
        assert!(SensorConfig::new(1, -1.0, 0).is_err());
        assert!(SensorConfig::new(1, f32::INFINITY, 0).is_err());
        assert!(SensorConfig::new(1, 1.0, MAX_LATENCY_MS + 1).is_err());
        assert!(SensorConfig::new(1, 1.0, MAX_LATENCY_MS).is_ok());
    }

    #[test]
    fn acknowledgement_bytes() {
        assert_eq!(parse_ack(0x0F), Ok(()));
        assert_eq!(parse_ack(0x00), Err(DecodeError::Nack));
        assert_eq!(parse_ack(0x41), Err(DecodeError::BadAck(0x41)));
    }

    #[test]
    fn an_empty_reply_is_a_count_of_zero() {
        let r = parse_read_reply(&[0], ReadKind::Short).unwrap();
        assert!(r.records.is_empty());
        assert_eq!(r.consumed, 1);
    }

    #[test]
    fn a_reply_with_two_records_parses_and_reports_its_length() {
        let mut buf = vec![2];
        buf.extend(wire(4, &[1, 0, 2, 0, 3, 0], ReadKind::Short));
        buf.extend(wire(128, &[0x34, 0x08], ReadKind::Short));
        buf.extend([0xAA, 0xBB]); // the next reply, not ours
        let r = parse_read_reply(&buf, ReadKind::Short).unwrap();
        assert_eq!(r.records.len(), 2);
        assert_eq!(r.consumed, 25);
        assert_eq!(r.records[0].sensor_id, 4);
    }

    #[test]
    fn a_short_reply_says_how_much_is_missing() {
        let mut buf = vec![1];
        buf.extend(wire(4, &[0; 6], ReadKind::Short));
        buf.truncate(8);
        assert_eq!(
            parse_read_reply(&buf, ReadKind::Short),
            Err(DecodeError::Incomplete { needed: 5 })
        );
        assert_eq!(parse_read_reply(&[], ReadKind::Short), Err(DecodeError::Incomplete { needed: 1 }));
    }

    #[test]
    fn accelerometer_counts_decode_signed() {
        let r = Record::from_wire(&wire(4, &[0xAF, 0x16, 0x56, 0x06, 0x87, 0x3D], ReadKind::Short), ReadKind::Short).unwrap();
        // 5807, 1622, 15751
        assert_eq!(decode(&r), Ok(Decoded::Vector3 { x: 5807, y: 1622, z: 15751 }));
        let g = Record::new(13, &[0x07, 0x00, 0xFC, 0xFF, 0x02, 0x00]);
        assert_eq!(decode(&g), Ok(Decoded::Vector3 { x: 7, y: -4, z: 2 }));
    }

    #[test]
    fn rotation_vector_is_a_unit_quaternion() {
        // x 0.048, y -0.176, z 0.003, w 0.983 in 14-bit fixed point.
        let q = |v: f64| ((v * 16384.0).round() as i16).to_le_bytes();
        let mut p = Vec::new();
        for v in [0.048, -0.176, 0.003, 0.983] {
            p.extend(q(v));
        }
        p.extend(51471u16.to_le_bytes());
        let Decoded::Quaternion { x, y, z, w, accuracy_raw } = decode(&Record::new(34, &p)).unwrap() else {
            panic!("not a quaternion");
        };
        assert!((x - 0.048).abs() < 1e-4 && (y + 0.176).abs() < 1e-4);
        assert!((z - 0.003).abs() < 1e-4 && (w - 0.983).abs() < 1e-4);
        assert_eq!(accuracy_raw, 51471);
    }

    #[test]
    fn environmental_scalars_use_the_table_scales() {
        // 28.29 C: raw 2829 at 0.01.
        let t = decode(&Record::new(128, &2829i16.to_le_bytes())).unwrap();
        assert_eq!(t, Decoded::Scalar(2829.0 * 0.01));
        // 101325 Pa is 12969600 in 1/128 Pa units: 24 bits.
        let raw = 12_969_600u32.to_le_bytes();
        assert_eq!(decode(&Record::new(129, &raw[..3])), Ok(Decoded::Scalar(101_325.0)));
        assert_eq!(decode(&Record::new(130, &[47])), Ok(Decoded::Scalar(47.0)));
        assert_eq!(decode(&Record::new(131, &949u32.to_le_bytes())), Ok(Decoded::Scalar(949.0)));
        assert_eq!(decode(&Record::new(52, &1234u32.to_le_bytes())), Ok(Decoded::Scalar(1234.0)));
    }

    #[test]
    fn negative_temperature_is_signed() {
        let t = decode(&Record::new(128, &(-550i16).to_le_bytes())).unwrap();
        assert_eq!(t, Decoded::Scalar(-5.5));
    }

    #[test]
    fn activity_words_decode_every_change() {
        let walking_started = ActivityBits(1 << 9);
        assert_eq!(
            walking_started.changes(),
            vec![ActivityChange { activity: Activity::Walking, started: true }]
        );
        let swap = ActivityBits(1 | (1 << 10));
        let c = swap.changes();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], ActivityChange { activity: Activity::Still, started: false });
        assert_eq!(c[1], ActivityChange { activity: Activity::Running, started: true });
        // Bits 7 and 15 are unused.
        assert!(ActivityBits(0x8080).changes().is_empty());
    }

    #[test]
    fn bsec_output_decodes_from_the_long_channel() {
        let mut p = Vec::new();
        p.extend(85u16.to_le_bytes()); // iaq
        p.extend(90u16.to_le_bytes()); // iaq static
        p.extend(123u16.to_le_bytes()); // b-voc 1.23
        p.extend(&650u32.to_le_bytes()[..3]);
        p.push(3);
        p.extend((25i16 * 256).to_le_bytes());
        p.extend((40u16 * 500).to_le_bytes());
        p.extend(52_000f32.to_le_bytes());
        assert_eq!(p.len(), 18);
        let r = Record::from_wire(&wire(115, &p, ReadKind::LongLegacy), ReadKind::LongLegacy).unwrap();
        let Decoded::Bsec(b) = decode(&r).unwrap() else { panic!() };
        assert_eq!((b.iaq, b.iaq_static, b.accuracy), (85, 90, 3));
        assert!((b.b_voc_ppm - 1.23).abs() < 1e-9 && b.co2_ppm == 650.0);
        assert_eq!((b.temperature_c, b.humidity_pct, b.gas_resistance_ohm), (25.0, 40.0, 52_000.0));
        assert!(r.is_long_sensor());
    }

    #[test]
    fn the_collector_record_needs_the_wider_channel() {
        let mut p = Vec::new();
        p.extend(1_000u64.to_le_bytes());
        p.extend((20i16 * 256).to_le_bytes());
        p.extend(100_000f32.to_le_bytes());
        p.extend((50u16 * 500).to_le_bytes());
        p.extend(7_000f32.to_le_bytes());
        p.push(2);
        assert_eq!(p.len(), 21);
        let wide = Record::from_wire(&wire(116, &p, ReadKind::Long), ReadKind::Long).unwrap();
        let Decoded::Bsec2Collector(c) = decode(&wide).unwrap() else { panic!() };
        assert_eq!((c.timestamp_ms, c.gas_index, c.pressure_pa), (1_000, 2, 100_000.0));
        let narrow = Record::from_wire(&wire(116, &p, ReadKind::LongLegacy), ReadKind::LongLegacy).unwrap();
        assert!(narrow.truncated());
        assert_eq!(decode(&narrow), Err(DecodeError::Short { sensor_id: 116, needed: 21, got: 18 }));
    }

    #[test]
    fn a_payload_shorter_than_its_format_is_an_error_not_a_zero() {
        let r = Record::new(4, &[1, 2, 3]);
        assert_eq!(decode(&r), Err(DecodeError::Short { sensor_id: 4, needed: 6, got: 3 }));
    }

    #[test]
    fn unknown_and_unsupported_ids_are_named() {
        assert_eq!(decode(&Record::new(200, &[0])), Err(DecodeError::UnknownSensor(200)));
        assert_eq!(decode(&Record::new(253, &[0])), Err(DecodeError::Unsupported(253)));
        assert_eq!(decode(&Record::new(171, &[0; 18])), Err(DecodeError::Unsupported(171)));
    }

    #[test]
    fn the_size_byte_counts_the_id_byte() {
        let r = Record::from_wire(&wire(130, &[47], ReadKind::Short), ReadKind::Short).unwrap();
        assert_eq!(r.size, 2);
        assert_eq!(r.payload(), &[47]);
    }

    #[test]
    fn an_oversized_size_byte_is_clamped_and_flagged() {
        let mut b = vec![171, 0xFF];
        b.extend([7u8; 10]);
        let r = Record::from_wire(&b, ReadKind::Short).unwrap();
        assert_eq!(r.payload().len(), SHORT_DATA_LEN);
        assert!(r.truncated());
    }

    #[test]
    fn the_table_has_no_duplicate_ids() {
        let mut ids: Vec<u8> = SENSORS.iter().map(|s| s.0).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    // Deterministic noise so a failure reproduces.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn every_id_and_size_decodes_or_errors_without_panicking() {
        for id in 0..=255u8 {
            for size in 0..=255u8 {
                for fill in [0x00u8, 0xFF, 0x7F, 0x80, 0xA5] {
                    let mut b = vec![id, size];
                    b.resize(ReadKind::Long.record_len(), fill);
                    for kind in [ReadKind::Short, ReadKind::Long, ReadKind::LongLegacy] {
                        let r = Record::from_wire(&b[..kind.record_len()], kind).unwrap();
                        let _ = decode(&r);
                    }
                }
            }
        }
    }

    #[test]
    fn random_streams_never_panic_the_reply_parser() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..20_000 {
            let len = (xorshift(&mut s) % 400) as usize;
            let buf: Vec<u8> = (0..len).map(|_| xorshift(&mut s) as u8).collect();
            for kind in [ReadKind::Short, ReadKind::Long, ReadKind::LongLegacy] {
                match parse_read_reply(&buf, kind) {
                    Ok(reply) => {
                        assert!(reply.consumed <= buf.len());
                        for r in &reply.records {
                            let _ = decode(r);
                        }
                    }
                    Err(DecodeError::Incomplete { needed }) => assert!(needed > 0),
                    Err(e) => panic!("unexpected {e}"),
                }
            }
        }
    }

    #[test]
    fn every_truncation_of_a_valid_reply_is_incomplete() {
        let mut full = vec![3];
        for id in [4u8, 13, 128] {
            full.extend(wire(id, &[1, 0, 2, 0, 3, 0], ReadKind::Short));
        }
        for cut in 0..full.len() {
            assert!(matches!(
                parse_read_reply(&full[..cut], ReadKind::Short),
                Err(DecodeError::Incomplete { .. })
            ));
        }
        assert!(parse_read_reply(&full, ReadKind::Short).is_ok());
    }
}
