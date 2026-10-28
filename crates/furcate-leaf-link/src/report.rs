//! The leaf's signed readings, and how they are checked.
//!
//! A SENSE reply carries the attachment generation, the hash of the model
//! active on the leaf, the leaf's id and the chain of signers, then one
//! reading per sensor: `sensor u8 | value f32 BE | seq u32 BE | signature 64`.
//! The signature is the leaf's ECDSA P-256 over the 32-byte digest
//! [`furcate_leaf_core::LeafState::bound_payload`] defines, which names the
//! device, the generation, the sensor, the value, the sequence and the model.
//! A sensing module behind the leaf is named by a unit record the leaf signs as
//! well: the module's fingerprint and the range of sequence numbers the leaf
//! issued for its readings, so a reading cannot be moved to another module and
//! what the leaf says about the module cannot be changed on the wire. The
//! module holds no key; the chain lists it as a `sensing` signer.

use crate::session::{LinkError, PUB_LEN, SIG_LEN};
use crate::wire::{self, msg, tag};
use furcate_leaf_core::{LeafState, Sample, MODEL_HASH_LEN};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Sensors with an index below this are the leaf's own; from here up they are
/// on a module behind it.
pub const MODULE_BASE: u8 = 16;

const READING_LEN: usize = 1 + 4 + 4 + SIG_LEN;

#[derive(Clone, Debug, PartialEq)]
pub struct RawReading {
    pub sensor: u8,
    pub value: f32,
    pub seq: u32,
    pub signature: [u8; SIG_LEN],
}

/// The leaf's statement of which unit its module readings came from:
/// `fingerprint 16 | first seq u32 | last seq u32 | signature 64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitRecord {
    pub fingerprint: [u8; 16],
    pub first_seq: u32,
    pub last_seq: u32,
    pub signature: [u8; SIG_LEN],
}

#[derive(Clone, Debug, PartialEq)]
pub struct SenseReport {
    pub generation: u16,
    pub model_sha: [u8; MODEL_HASH_LEN],
    pub signer_id: [u8; 16],
    /// `(signer id, role)` for each signer the readings passed through.
    pub chain: Vec<([u8; 16], String)>,
    pub readings: Vec<RawReading>,
    pub unit: Option<UnitRecord>,
}

fn arr<const N: usize>(b: &[u8], what: &'static str) -> Result<[u8; N], LinkError> {
    b.try_into().map_err(|_| LinkError::Missing(what))
}

fn unit_record(b: &[u8]) -> Result<UnitRecord, LinkError> {
    if b.len() != 16 + 8 + SIG_LEN {
        return Err(LinkError::Missing("a whole unit record"));
    }
    Ok(UnitRecord {
        fingerprint: arr(&b[..16], "unit fingerprint")?,
        first_seq: u32::from_be_bytes([b[16], b[17], b[18], b[19]]),
        last_seq: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
        signature: arr(&b[24..], "unit signature")?,
    })
}

/// Reads the plain content of a SENSE reply. A RESULT in its place is the
/// leaf declining, with its reason.
pub fn parse_sense(plain: &[u8]) -> Result<SenseReport, LinkError> {
    let (kind, f) = wire::split(plain)?;
    if kind == msg::RESULT {
        return Err(LinkError::Refused(f.get(tag::REASON).map(|r| String::from_utf8_lossy(r).into_owned()).unwrap_or_default()));
    }
    if kind != msg::SENSE {
        return Err(LinkError::Unexpected(kind));
    }
    let mut readings = Vec::new();
    for r in f.all(tag::READING) {
        if r.len() != READING_LEN {
            return Err(LinkError::Missing("a whole reading"));
        }
        readings.push(RawReading {
            sensor: r[0],
            value: f32::from_be_bytes([r[1], r[2], r[3], r[4]]),
            seq: u32::from_be_bytes([r[5], r[6], r[7], r[8]]),
            signature: arr(&r[9..], "reading signature")?,
        });
    }
    let mut chain = Vec::new();
    for c in f.all(tag::CHAIN) {
        if c.len() < 16 {
            return Err(LinkError::Missing("a whole chain entry"));
        }
        chain.push((arr(&c[..16], "chain id")?, String::from_utf8_lossy(&c[16..]).into_owned()));
    }
    Ok(SenseReport {
        generation: u16::try_from(f.uint(tag::GENERATION).ok_or(LinkError::Missing("generation"))?).map_err(|_| LinkError::Missing("generation"))?,
        model_sha: arr(f.get(tag::MODEL_SHA).ok_or(LinkError::Missing("model hash"))?, "model hash")?,
        signer_id: arr(f.get(tag::SIGNER_ID).ok_or(LinkError::Missing("signer id"))?, "signer id")?,
        chain,
        readings,
        unit: f.get(tag::UNIT).map(unit_record).transpose()?,
    })
}

/// The digest the leaf signs for one reading.
pub fn reading_digest(leaf_id: &[u8; 32], generation: u16, r: &RawReading, model: &[u8; MODEL_HASH_LEN]) -> [u8; 32] {
    let device: [u8; 8] = leaf_id[..8].try_into().expect("a SHA-256 has eight leading bytes");
    LeafState::new(0, generation).bound_payload(&device, &Sample { sensor: r.sensor, value: r.value, seq: r.seq }, model)
}

/// The digest the leaf signs for the unit record: it names the leaf, the
/// attachment generation, the unit and the sequence range.
pub fn unit_digest(leaf_id: &[u8; 32], generation: u16, u: &UnitRecord) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"furcate/leaf/unit/v1");
    h.update(&leaf_id[..8]);
    h.update(generation.to_be_bytes());
    h.update(u.fingerprint);
    h.update(u.first_seq.to_be_bytes());
    h.update(u.last_seq.to_be_bytes());
    h.finalize().into()
}

/// The fingerprint a leaf gives a module on its I2C bus: the identifiers the
/// operator configured on the leaf, since the module cannot say them over the
/// port. The same bytes `fl_nicla_i2c_unit_fingerprint` hashes.
pub fn i2c_unit_fingerprint(i2c_addr: u8, serial: &str, device_id: &[u8; 8], device_addr: &[u8; 6]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"furcate/nicla/i2c-unit/v1");
    h.update([i2c_addr, serial.len().min(255) as u8]);
    h.update(&serial.as_bytes()[..serial.len().min(255)]);
    h.update(device_id);
    h.update(device_addr);
    let full: [u8; 32] = h.finalize().into();
    full[..16].try_into().expect("16 of 32")
}

fn verify(leaf_pub: &[u8; PUB_LEN], digest: &[u8; 32], sig: &[u8; SIG_LEN]) -> bool {
    let (Ok(key), Ok(sig)) = (VerifyingKey::from_sec1_bytes(leaf_pub), Signature::from_slice(sig)) else {
        return false;
    };
    key.verify_prehash(digest, &sig).is_ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadingRefusal {
    /// The report names a different leaf than the one in the session.
    WrongSigner,
    BadSignature,
    /// Not ahead of the last reading accepted from this leaf.
    Replayed { last: (u16, u32), found: (u16, u32) },
    /// A report from an attachment older than one already seen.
    StaleGeneration { last: u16, found: u16 },
    /// A reading carrying a value that is not a number.
    NotFinite,
}

impl std::fmt::Display for ReadingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadingRefusal::WrongSigner => write!(f, "the report names a different leaf than the session's"),
            ReadingRefusal::BadSignature => write!(f, "the reading is not signed by the leaf"),
            ReadingRefusal::Replayed { last, found } => write!(f, "reading {}.{} is not ahead of {}.{}", found.0, found.1, last.0, last.1),
            ReadingRefusal::StaleGeneration { last, found } => write!(f, "generation {found} is older than {last}"),
            ReadingRefusal::NotFinite => write!(f, "the value is not a finite number"),
        }
    }
}

/// A reading whose signature verified and whose sequence is ahead of every
/// one before it.
#[derive(Clone, Debug, PartialEq)]
pub struct Verified {
    pub sensor: u8,
    pub value: f32,
    pub seq: u32,
    pub generation: u16,
    pub model_sha: [u8; MODEL_HASH_LEN],
}

/// The sequence rule: within an attachment generation sequences only go up,
/// and a new generation starts again. An older generation never returns.
#[derive(Default)]
pub struct ReplayGuard {
    last: Option<(u16, u32)>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    fn admit(&mut self, generation: u16, seq: u32) -> Result<(), ReadingRefusal> {
        if let Some(last) = self.last {
            if generation < last.0 {
                return Err(ReadingRefusal::StaleGeneration { last: last.0, found: generation });
            }
            if (generation, seq) <= last {
                return Err(ReadingRefusal::Replayed { last, found: (generation, seq) });
            }
        }
        self.last = Some((generation, seq));
        Ok(())
    }
}

/// Checks every reading in a report against the leaf's key. The signature is
/// checked before the sequence is recorded, so a forged reading cannot use up
/// a sequence number.
pub fn verify_report(leaf_pub: &[u8; PUB_LEN], report: &SenseReport, guard: &mut ReplayGuard) -> Vec<Result<Verified, ReadingRefusal>> {
    let leaf_id: [u8; 32] = Sha256::digest(leaf_pub).into();
    report
        .readings
        .iter()
        .map(|r| {
            if report.signer_id != leaf_id[..16] {
                return Err(ReadingRefusal::WrongSigner);
            }
            if !r.value.is_finite() {
                return Err(ReadingRefusal::NotFinite);
            }
            if !verify(leaf_pub, &reading_digest(&leaf_id, report.generation, r, &report.model_sha), &r.signature) {
                return Err(ReadingRefusal::BadSignature);
            }
            guard.admit(report.generation, r.seq)?;
            Ok(Verified { sensor: r.sensor, value: r.value, seq: r.seq, generation: report.generation, model_sha: report.model_sha })
        })
        .collect()
}

/// Checks the unit record's signature.
pub fn verify_unit(leaf_pub: &[u8; PUB_LEN], generation: u16, u: &UnitRecord) -> bool {
    let leaf_id: [u8; 32] = Sha256::digest(leaf_pub).into();
    verify(leaf_pub, &unit_digest(&leaf_id, generation, u), &u.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values computed with Python's hashlib from the layouts in the
    /// leaf firmware (fl_sensors.c, fl_nicla_i2c_proto.c).
    #[test]
    fn the_unit_digest_and_i2c_fingerprint_match_independent_values() {
        let mut leaf_id = [0u8; 32];
        for (i, b) in leaf_id.iter_mut().enumerate() {
            *b = i as u8;
        }
        let fp = i2c_unit_fingerprint(0x55, "NSM-0042", &[9, 8, 7, 6, 5, 4, 3, 2], &[0xc0, 1, 2, 3, 4, 5]);
        assert_eq!(hex::encode(fp), "6b8b373a92128b23de4ac344cdcd5f03");
        assert_ne!(fp, i2c_unit_fingerprint(0x55, "NSM-0043", &[9, 8, 7, 6, 5, 4, 3, 2], &[0xc0, 1, 2, 3, 4, 5]));
        let u = UnitRecord { fingerprint: fp, first_seq: 7, last_seq: 9, signature: [0; SIG_LEN] };
        assert_eq!(hex::encode(unit_digest(&leaf_id, 3, &u)), "0b3443fc7f9ad69ca1dc71e9e47fc548ad58739fb24dbbef54ad8b34a95cccd4");
    }

    #[test]
    fn a_unit_record_of_the_wrong_length_is_refused() {
        assert!(unit_record(&[0u8; 87]).is_err());
        assert!(unit_record(&[0u8; 88]).is_ok());
    }
}
