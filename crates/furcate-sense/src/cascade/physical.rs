//! The producer side of the physical batch: what a large node sends to a
//! consumer that has no Furcate code.
//!
//! A large node holds readings that arrived through the rungs below it. This
//! module takes only readings it has itself verified ([`verify_forwarded`]),
//! adds its own rung to each chain, attaches the witnessed log segment that
//! proves nothing was dropped, and signs the whole batch under the site key.
//! The consumer re-checks the arithmetic (the hash chain, the minimum level)
//! with no shared code; the format is in `docs/physical-batch.md`.
//!
//! Canonical form: JSON with object keys sorted by UTF-16 code unit, no
//! whitespace, strings escaped minimally and numbers in the ECMAScript
//! shortest form, as RFC 8785 specifies. No number in a batch is larger than 2^53 - 1 in
//! magnitude (a double that large is an integer, which cannot be told from an unsafe one after parsing).

use super::chain::ChainReport;
use super::directory::Directory;
use super::signer::CascadeSigner;
use super::small::{verify_forwarded, ForwardRefusal, Forwarded, ForwardedItem};
use super::witness::{genesis, item_digest, verify_cosigned, Cosigned, LogEntry};
use crate::nicla::{Hop, CHANNELS};
use furcate_identity::AssuranceClass;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The domain the site key signs a batch under.
pub const BATCH_DOMAIN: &str = "lw-physical/batch/v1";
/// The wire format name and version carried inside every batch.
pub const FORMAT: &str = "physical-batch";
pub const FORMAT_VERSION: u64 = 1;

/// The largest integer a double holds exactly: 2^53 - 1.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, PartialEq, Eq)]
pub enum ExportRefusal {
    /// The reading failed the large node's own verification.
    Unverified(ForwardRefusal),
    /// Only readings are exported; an embedding is not a measurement.
    NotAReading,
    /// The sensor id names no channel this producer knows.
    UnknownChannel(String),
    /// The log entry does not commit to this reading.
    EntryMismatch,
    /// No log segment was added for this reading's leaf, or it does not cover it.
    NotInLog { leaf_id: String, seq: u64 },
    BadLog(String),
    Sign(String),
}

impl std::fmt::Display for ExportRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExportRefusal {}

/// How the site knows the time, stated by the site and never inferred.
#[derive(Clone, Debug)]
pub struct SiteClock {
    /// `gps`, `ntp`, `rtc` or `none`.
    pub source: String,
    pub uncertainty_ms: Option<u64>,
}

/// One leaf's witnessed log, from its first entry to a cosigned checkpoint.
pub struct LogSegment {
    pub leaf_id: String,
    pub leaf_key: String,
    pub witness_key: String,
    pub entries: Vec<LogEntry>,
    pub cosigned: Cosigned,
}

struct Pending {
    reading: Map<String, Value>,
    leaf_id: String,
    log_seq: u64,
    envelope_signature: String,
}

pub struct BatchBuilder {
    site_id: String,
    batch_id: String,
    batch_seq: u64,
    created_at_ms: u64,
    clock: SiteClock,
    site_node: String,
    site_assurance: AssuranceClass,
    readings: Vec<Pending>,
    logs: BTreeMap<String, LogSegment>,
    birth_record_hash: Option<String>,
}

impl BatchBuilder {
    /// `site_node` is the node id of the large node that signs, `site_assurance`
    /// the class its key custody earns: it becomes the last rung of every chain.
    pub fn new(
        site_id: &str,
        site_node: &str,
        site_assurance: AssuranceClass,
        batch_id: &str,
        batch_seq: u64,
        created_at_ms: u64,
        clock: SiteClock,
    ) -> Self {
        Self {
            site_id: site_id.into(),
            batch_id: batch_id.into(),
            batch_seq,
            created_at_ms,
            clock,
            site_node: site_node.into(),
            site_assurance,
            readings: Vec::new(),
            logs: BTreeMap::new(),
            birth_record_hash: None,
        }
    }

    /// Name the birth record of the model that produced these readings, by its hash
    /// ([`super::birth::record_hash`]). Optional: a batch without it is byte-identical to one built
    /// before the field existed. When present it is a top-level member and is covered by the signature.
    pub fn with_birth_record_hash(mut self, record_hash: &str) -> Result<Self, String> {
        if record_hash.len() != 64 || !record_hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("a birth record hash is 64 lower-case hex characters".into());
        }
        self.birth_record_hash = Some(record_hash.into());
        Ok(self)
    }

    /// Verify a forwarded reading against `dir` (the large node's own records)
    /// and add it, with the log entry the micro node made for it and the time
    /// the site read on its own clock when it arrived.
    pub fn add_forwarded(
        &mut self,
        f: &Forwarded,
        dir: &Directory,
        entry: &LogEntry,
        at_ms: u64,
    ) -> Result<(), ExportRefusal> {
        let report = verify_forwarded(f, dir, AssuranceClass::Soft).map_err(ExportRefusal::Unverified)?;
        let ForwardedItem::Reading(b) = &f.item else { return Err(ExportRefusal::NotAReading) };
        if entry.digest != item_digest(&b.envelope_signature) {
            return Err(ExportRefusal::EntryMismatch);
        }
        let r = &b.reading;
        let suffix = r
            .sensor_id
            .strip_prefix(&format!("{}/", r.leaf_id))
            .ok_or_else(|| ExportRefusal::UnknownChannel(r.sensor_id.clone()))?;
        let ch = CHANNELS.iter().find(|c| c.suffix == suffix).ok_or_else(|| ExportRefusal::UnknownChannel(r.sensor_id.clone()))?;

        let hops: Vec<&Hop> = b.provenance.chain.iter().chain(b.countersignatures.iter().map(|c| &c.hop)).collect();
        let mut wire_hops: Vec<Value> = report
            .hops
            .iter()
            .zip(hops.iter())
            .map(|(h, hop)| hop_json(hop, h.held))
            .collect();
        wire_hops.push(hop_json(
            &Hop {
                role: crate::nicla::NodeRole::LargeProcessing,
                node_id: self.site_node.clone(),
                attestation_level: self.site_assurance,
                derivation: crate::nicla::Derivation::Relayed,
            },
            self.site_assurance,
        ));
        let (effective, limiting) = effective_of(&report, &self.site_node, self.site_assurance);

        let binding = match &b.provenance.binding {
            Some(m) => json!({"model": m.model, "epoch": m.epoch, "calibration": m.calibration, "self_test": m.self_test}),
            None => Value::Null,
        };
        let mut o = Map::new();
        o.insert("sensor_id".into(), json!(r.sensor_id));
        o.insert("leaf_id".into(), json!(r.leaf_id));
        o.insert("kind".into(), serde_json::to_value(ch.kind).map_err(|e| ExportRefusal::BadLog(e.to_string()))?);
        o.insert("unit".into(), serde_json::to_value(ch.unit).map_err(|e| ExportRefusal::BadLog(e.to_string()))?);
        o.insert("modality".into(), serde_json::to_value(b.provenance.modality).map_err(|e| ExportRefusal::BadLog(e.to_string()))?);
        o.insert("value".into(), json!(r.value));
        o.insert("seq".into(), json!(r.seq));
        o.insert("taken_at_leaf_s".into(), json!(r.taken_at));
        o.insert("sensor_ts_ms".into(), Value::Null);
        o.insert("at_ms".into(), json!(at_ms));
        o.insert("reading_signature".into(), json!(r.signature));
        o.insert("envelope_signature".into(), json!(b.envelope_signature));
        o.insert("item_digest".into(), json!(item_digest(&b.envelope_signature)));
        o.insert("log_seq".into(), json!(entry.seq));
        o.insert("binding".into(), binding);
        o.insert(
            "attestation".into(),
            json!({"effective": effective.as_str(), "limiting_hop": limiting, "hops": wire_hops}),
        );
        self.readings.push(Pending {
            reading: o,
            leaf_id: r.leaf_id.clone(),
            log_seq: entry.seq,
            envelope_signature: b.envelope_signature.clone(),
        });
        Ok(())
    }

    /// Add the witnessed log of one leaf. It must start at the leaf's first
    /// entry, run unbroken, and end at the cosigned checkpoint.
    pub fn add_log(&mut self, seg: LogSegment, now_ms: u64) -> Result<(), ExportRefusal> {
        let bad = |s: &str| ExportRefusal::BadLog(s.to_string());
        let c = &seg.cosigned.signed.checkpoint;
        if c.leaf_id != seg.leaf_id {
            return Err(bad("checkpoint names another leaf"));
        }
        let mut prev = genesis(&seg.leaf_id);
        for (i, e) in seg.entries.iter().enumerate() {
            if e.seq != i as u64 + 1 || e.prev != prev {
                return Err(bad("entries are not an unbroken chain from the first entry"));
            }
            prev = e.hash.clone();
        }
        if c.size != seg.entries.len() as u64 || c.head != prev {
            return Err(bad("the checkpoint is not over exactly these entries"));
        }
        verify_cosigned(&seg.cosigned, &seg.leaf_key, &seg.witness_key, now_ms, u64::MAX)
            .map_err(|e| ExportRefusal::BadLog(format!("{e}")))?;
        self.logs.insert(seg.leaf_id.clone(), seg);
        Ok(())
    }

    /// Assemble and sign. Every reading must be covered by an added log.
    pub fn build(self, signer: &dyn CascadeSigner) -> Result<Value, ExportRefusal> {
        let mut readings = Vec::new();
        for p in &self.readings {
            let seg = self.logs.get(&p.leaf_id).ok_or(ExportRefusal::NotInLog { leaf_id: p.leaf_id.clone(), seq: p.log_seq })?;
            seg.entries
                .get(p.log_seq as usize - 1)
                .filter(|e| e.digest == item_digest(&p.envelope_signature))
                .ok_or(ExportRefusal::NotInLog { leaf_id: p.leaf_id.clone(), seq: p.log_seq })?;
            readings.push(Value::Object(p.reading.clone()));
        }
        let logs: Vec<Value> = self
            .logs
            .values()
            .map(|s| {
                let c = &s.cosigned;
                json!({
                    "leaf_id": s.leaf_id,
                    "leaf_key_id": s.leaf_key,
                    "anchor": genesis(&s.leaf_id),
                    "entries": s.entries.iter().map(|e| json!({"seq": e.seq, "ts_ms": e.ts_ms, "digest": e.digest, "prev": e.prev, "hash": e.hash})).collect::<Vec<_>>(),
                    "checkpoint": {"leaf_id": c.signed.checkpoint.leaf_id, "size": c.signed.checkpoint.size, "head": c.signed.checkpoint.head, "ts_ms": c.signed.checkpoint.ts_ms},
                    "checkpoint_signature": c.signed.signature,
                    "cosign": {"witness": c.witness, "witness_key_id": s.witness_key, "at_ms": c.witnessed_at_ms, "signature": c.cosignature},
                })
            })
            .collect();
        let mut batch = json!({
            "format": FORMAT,
            "v": FORMAT_VERSION,
            "site_id": self.site_id,
            "site_key_id": signer.public_key(),
            "batch_id": self.batch_id,
            "batch_seq": self.batch_seq,
            "created_at_ms": self.created_at_ms,
            "site_clock": {"source": self.clock.source, "uncertainty_ms": self.clock.uncertainty_ms},
            "readings": readings,
            "logs": logs,
        });
        if let Some(h) = &self.birth_record_hash {
            batch.as_object_mut().expect("an object").insert("birth_record_hash".into(), json!(h));
        }
        let bytes = signing_bytes(&batch).map_err(ExportRefusal::Sign)?;
        let sig = signer.sign_message(BATCH_DOMAIN, bytes.as_bytes()).map_err(ExportRefusal::Sign)?;
        batch.as_object_mut().expect("an object").insert("signature".into(), json!(sig));
        Ok(batch)
    }
}

fn hop_json(h: &Hop, level: AssuranceClass) -> Value {
    json!({
        "role": serde_json::to_value(h.role).unwrap_or(Value::Null),
        "node_id": h.node_id,
        "level": level.as_str(),
        "derivation": serde_json::to_value(&h.derivation).unwrap_or(Value::Null),
    })
}

/// The lowest class on the chain with the large node's own rung added, and the
/// first rung at that class.
fn effective_of(report: &ChainReport, site_node: &str, site: AssuranceClass) -> (AssuranceClass, String) {
    if site < report.effective {
        (site, site_node.to_string())
    } else {
        (report.effective, report.limiting.clone())
    }
}

/// The bytes the site key signs: the canonical form of the batch without its
/// `signature` member.
pub fn signing_bytes(batch: &Value) -> Result<String, String> {
    let mut v = batch.clone();
    v.as_object_mut().ok_or("a batch is an object")?.remove("signature");
    canonical_json(&v)
}

/// SHA-256 of the signing bytes, hex.
pub fn canonical_sha256(batch: &Value) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(signing_bytes(batch)?.as_bytes())))
}

/// RFC 8785 canonical JSON of a value.
pub fn canonical_json(v: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(format!("integer {u} is beyond 2^53 - 1"));
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(format!("integer {i} is beyond 2^53 - 1"));
                }
                out.push_str(&i.to_string());
            } else {
                let f = n.as_f64().ok_or("a number that is not finite")?;
                if f.abs() > MAX_SAFE_INTEGER as f64 {
                    return Err(format!("number {f} is beyond 2^53 - 1"));
                }
                out.push_str(&es6_number(f)?);
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_canonical(&m[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A double in the ECMAScript `Number::toString` form (RFC 8785 section 3.2.2.3).
pub fn es6_number(x: f64) -> Result<String, String> {
    if !x.is_finite() {
        return Err("a number that is not finite".into());
    }
    if x == 0.0 {
        return Ok("0".into());
    }
    let sign = if x < 0.0 { "-" } else { "" };
    // The shortest digits that read back as the same double, as d.ddde<exp>.
    let sci = format!("{:e}", x.abs());
    let (mant, exp) = sci.split_once('e').ok_or("unexpected float format")?;
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let exp: i32 = exp.parse().map_err(|_| "unexpected float exponent")?;
    let k = digits.len() as i32;
    let n = exp + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign_e = if e < 0 { "-" } else { "+" };
        if k == 1 {
            format!("{digits}e{sign_e}{}", e.abs())
        } else {
            format!("{}.{}e{sign_e}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    Ok(format!("{sign}{body}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_follow_the_ecmascript_form() {
        for (x, s) in [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (21.5, "21.5"),
            (-4.25, "-4.25"),
            (0.000001, "0.000001"),
            (1e-7, "1e-7"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e21, "1e+21"),
            (1.5e300, "1.5e+300"),
            (4.5e-10, "4.5e-10"),
            (9.80665, "9.80665"),
            (0.1 + 0.2, "0.30000000000000004"),
        ] {
            assert_eq!(es6_number(x).unwrap(), s, "{x}");
        }
        assert!(es6_number(f64::NAN).is_err());
    }

    #[test]
    fn keys_sort_by_utf16_and_strings_escape_minimally() {
        let v = json!({"b": 1, "a": [true, null, "x\u{1}\n\"\\é"], "\u{1F600}": 2, "\u{FF5E}": 3});
        // U+1F600 is a surrogate pair in UTF-16 (first unit 0xD83D), so it sorts before U+FF5E; in UTF-8 order it would not.
        assert_eq!(
            canonical_json(&v).unwrap(),
            "{\"a\":[true,null,\"x\\u0001\\n\\\"\\\\é\"],\"b\":1,\"\u{1F600}\":2,\"\u{FF5E}\":3}"
        );
    }

    #[test]
    fn integers_beyond_the_safe_range_are_refused() {
        assert!(canonical_json(&json!({"n": (1u64 << 53) - 1})).is_ok());
        assert!(canonical_json(&json!({"n": 1u64 << 53})).is_err());
        assert!(canonical_json(&json!({"n": 1e21})).is_err());
        assert!(canonical_json(&json!({"n": 1e-21})).is_ok());
    }
}
