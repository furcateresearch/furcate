//! The birth record: what a node demands before it runs a model or policy that
//! was made in a simulated world.
//!
//! A record binds the artefact hashes to their digital lineage and to the head
//! of a hash-chained experience ledger. It is signed by a Living Worlds signer
//! the node has enrolled. The contract, the codes and the golden vector are in
//! `docs/birth-record.md`; the producer is a separate implementation, and
//! `tests/fixtures/birth-record.golden.json` is the byte-identical vector both
//! sides verify.
//!
//! Simulated time counts for physical purposes only inside the band the twin was
//! validated against real measurements. The record keeps validated and
//! unvalidated seconds apart; experience outside the band never unlocks
//! actuation, and a record that moves seconds between the two is refused by
//! anyone holding the ledger ([`reconcile`]).
//!
//! The node holds the record and the ledger head, not the ledger: [`verify`]
//! checks everything that can be checked from the record alone. [`accept_model`]
//! is the gate: a model or policy offered without a valid record is refused.

use super::physical::canonical_json;
use crate::leaf::verify_with_key;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const RECORD_FORMAT: &str = "birth-record";
pub const RECORD_VERSION: u64 = 1;
pub const RECORD_DOMAIN: &str = "lw-physical/birth-record/v1";
pub const LEDGER_ENTRY_DOMAIN: &str = "lw-experience/entry/v1";
pub const LEDGER_GENESIS_DOMAIN: &str = "lw-experience/genesis/v1";
/// A validity window is at most 366 days.
pub const MAX_WINDOW_MS: u64 = 366 * 86_400_000;
const MAX_SAFE: u64 = (1 << 53) - 1;
const CLASSES: [&str; 6] = ["soft", "device", "se", "tee", "dice", "tpm"];
const TOP: [&str; 13] = [
    "format", "version", "signer", "issued_ms", "valid_from_ms", "valid_until_ms", "artefact", "lineage", "run", "results", "band_certificate", "experience",
    "signature",
];

/// Why a record, a ledger or an offer was refused. [`BirthRefusal::code`] is the code in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BirthRefusal {
    Absent,
    Malformed,
    WrongFormat,
    UnsupportedVersion,
    UnknownSigner,
    BadSignature,
    WindowInvalid,
    NotYetValid,
    Expired,
    ModelHashMismatch,
    LedgerHeadMissing,
    KnowledgeHashMissing,
    ExperienceInconsistent,
    BandMissing,
    ReleasePointOutsideBand,
    CoverageOutsideBand,
    FidelityBelowMinimum,
    LedgerMalformed,
    LedgerReordered,
    LedgerChainBroken,
    LedgerHeadMismatch,
    LedgerKindUnknown,
    LedgerNotStarted,
    LedgerNotFinished,
    LedgerAfterFinish,
    OutOfBandClaimedValidated,
    LedgerSummaryMismatch,
}

impl BirthRefusal {
    pub fn code(&self) -> &'static str {
        use BirthRefusal::*;
        match self {
            Absent => "birth_record_absent",
            Malformed => "malformed",
            WrongFormat => "wrong_format",
            UnsupportedVersion => "unsupported_version",
            UnknownSigner => "unknown_signer",
            BadSignature => "bad_signature",
            WindowInvalid => "window_invalid",
            NotYetValid => "not_yet_valid",
            Expired => "expired",
            ModelHashMismatch => "model_hash_mismatch",
            LedgerHeadMissing => "ledger_head_missing",
            KnowledgeHashMissing => "knowledge_hash_missing",
            ExperienceInconsistent => "experience_inconsistent",
            BandMissing => "band_missing",
            ReleasePointOutsideBand => "release_point_outside_band",
            CoverageOutsideBand => "coverage_outside_band",
            FidelityBelowMinimum => "fidelity_below_minimum",
            LedgerMalformed => "ledger_malformed",
            LedgerReordered => "ledger_reordered",
            LedgerChainBroken => "ledger_chain_broken",
            LedgerHeadMismatch => "ledger_head_mismatch",
            LedgerKindUnknown => "ledger_kind_unknown",
            LedgerNotStarted => "ledger_not_started",
            LedgerNotFinished => "ledger_not_finished",
            LedgerAfterFinish => "ledger_after_finish",
            OutOfBandClaimedValidated => "out_of_band_claimed_validated",
            LedgerSummaryMismatch => "ledger_summary_mismatch",
        }
    }
}

impl std::fmt::Display for BirthRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for BirthRefusal {}

/// What the verifying node holds. `signers` are the Living Worlds signer keys it has enrolled
/// (`ed25519:<hex>`); nothing in a record can add to them.
pub struct BirthContext<'a> {
    pub signers: &'a [String],
    pub now_ms: u64,
    /// The hash of the artefact being installed. When set it must be one the record names.
    pub model_hash: Option<&'a str>,
}

/// A record that passed [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub record_hash: String,
    pub model_hashes: Vec<String>,
    pub ledger_head: String,
    pub validated_seconds: u64,
    pub unvalidated_seconds: u64,
    pub valid_until_ms: u64,
}

fn int(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= MAX_SAFE)
}
fn hash(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
fn text(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty() && s.chars().count() <= 256)
}
fn range(v: &Value) -> Option<(f64, f64)> {
    let a = v.as_array().filter(|a| a.len() == 2)?;
    let (lo, hi) = (a[0].as_f64()?, a[1].as_f64()?);
    (lo.is_finite() && hi.is_finite() && lo <= hi).then_some((lo, hi))
}
fn ranges(v: &Value) -> Option<Vec<(String, (f64, f64))>> {
    v.as_object()?.iter().map(|(k, r)| range(r).map(|r| (k.clone(), r))).collect()
}
fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn lp(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_be_bytes());
    h.update(b);
}

/// The bytes the signer signs: the canonical record without its `signature`.
pub fn signing_bytes(record: &Value) -> Result<String, BirthRefusal> {
    let mut v = record.clone();
    v.as_object_mut().ok_or(BirthRefusal::Malformed)?.remove("signature");
    canonical_json(&v).map_err(|_| BirthRefusal::Malformed)
}

/// SHA-256 of the canonical record including its signature: what a reading or a receipt can carry to name its birth record.
pub fn record_hash(record: &Value) -> Result<String, BirthRefusal> {
    Ok(sha_hex(canonical_json(record).map_err(|_| BirthRefusal::Malformed)?.as_bytes()))
}

fn shape(r: &Map<String, Value>) -> Result<(), BirthRefusal> {
    use BirthRefusal::Malformed as M;
    let mut keys: Vec<&str> = r.keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    let mut top = TOP.to_vec();
    top.sort_unstable();
    if keys != top {
        return Err(M);
    }
    let signer = r["signer"].as_str().ok_or(M)?;
    if !(signer.len() == 72 && signer.starts_with("ed25519:") && hash(&Value::from(&signer[8..]))) {
        return Err(M);
    }
    if r["signature"].as_str().is_none_or(|s| s.len() != 128 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
        return Err(M);
    }
    for k in ["issued_ms", "valid_from_ms", "valid_until_ms"] {
        int(&r[k]).ok_or(M)?;
    }
    let a = r["artefact"].as_object().ok_or(M)?;
    if !a.get("kind").and_then(Value::as_str).is_some_and(|k| ["model", "policy", "plan"].contains(&k)) {
        return Err(M);
    }
    let hashes = a.get("hashes").and_then(Value::as_array).ok_or(M)?;
    if hashes.is_empty() || hashes.len() > 16 || !hashes.iter().all(hash) {
        return Err(M);
    }
    let names: Vec<&str> = hashes.iter().filter_map(Value::as_str).collect();
    if names.windows(2).any(|w| w[0] >= w[1]) {
        return Err(M);
    }
    let l = r["lineage"].as_object().ok_or(M)?;
    if !["world_id", "world_version", "twin_id", "twin_version"].iter().all(|k| l.get(*k).is_some_and(text)) {
        return Err(M);
    }
    let run = r["run"].as_object().ok_or(M)?;
    if !run.get("run_id").is_some_and(text) || ["seed", "started_ms", "finished_ms"].iter().any(|k| run.get(*k).and_then(int).is_none()) {
        return Err(M);
    }
    for d in run.get("data_sources").and_then(Value::as_array).ok_or(M)? {
        let d = d.as_object().ok_or(M)?;
        let ok = d.get("kind").and_then(Value::as_str) == Some("physical_batch")
            && d.get("batch_id").is_some_and(text)
            && d.get("batch_hash").is_some_and(hash)
            && d.get("min_attestation").and_then(Value::as_str).is_some_and(|c| CLASSES.contains(&c));
        if !ok {
            return Err(M);
        }
    }
    let res = r["results"].as_object().ok_or(M)?;
    if ["fidelity_ppm", "fidelity_minimum_ppm"].iter().any(|k| res.get(*k).and_then(int).is_none()) {
        return Err(M);
    }
    for b in res.get("benchmarks").and_then(Value::as_array).ok_or(M)? {
        let b = b.as_object().ok_or(M)?;
        if !b.get("name").is_some_and(text) || b.get("score_ppm").and_then(int).is_none() || b.get("threshold_ppm").is_some_and(|t| int(t).is_none()) {
            return Err(M);
        }
    }
    let bc = r["band_certificate"].as_object().ok_or(M)?;
    if !bc.get("calibration_id").is_some_and(text) || ranges(&bc["band"]).is_none() {
        return Err(M);
    }
    let rp = bc.get("release_point").and_then(Value::as_object).ok_or(M)?;
    if !rp.values().all(|v| v.as_f64().is_some_and(f64::is_finite)) {
        return Err(M);
    }
    let x = r["experience"].as_object().ok_or(M)?;
    for k in [
        "ledger_entries", "simulated_seconds_total", "simulated_seconds_validated", "simulated_seconds_unvalidated", "wall_clock_seconds", "cpu_core_seconds",
        "gpu_seconds", "episodes_total", "episodes_validated", "scenarios_total", "scenarios_validated",
    ] {
        x.get(k).and_then(int).ok_or(M)?;
    }
    if ranges(&x["coverage"]).is_none() || ranges(&x["coverage_validated"]).is_none() || x.get("validated_scope").and_then(Value::as_str) != Some("inside_band_only") {
        return Err(M);
    }
    Ok(())
}

fn n(x: &Map<String, Value>, k: &str) -> u64 {
    x.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// Everything a node can check from the record alone. The first failure wins, in the order of the contract.
pub fn verify(record: &Value, ctx: &BirthContext) -> Result<Accepted, BirthRefusal> {
    use BirthRefusal::*;
    let obj = record.as_object().ok_or(Malformed)?;
    canonical_json(record).map_err(|_| Malformed)?;
    if obj.get("format").and_then(Value::as_str) != Some(RECORD_FORMAT) {
        return Err(WrongFormat);
    }
    if obj.get("version").and_then(Value::as_u64) != Some(RECORD_VERSION) {
        return Err(UnsupportedVersion);
    }
    // ledger_head and knowledge_set_hash carry codes of their own, checked in order after the signature.
    let mut probe = obj.clone();
    if let Some(a) = probe.get_mut("artefact").and_then(Value::as_object_mut) {
        a.remove("knowledge_set_hash");
    }
    if let Some(x) = probe.get_mut("experience").and_then(Value::as_object_mut) {
        x.remove("ledger_head");
    }
    shape(&probe)?;
    let signer = obj["signer"].as_str().ok_or(Malformed)?;
    if !ctx.signers.iter().any(|s| s == signer) {
        return Err(UnknownSigner);
    }
    let bytes = signing_bytes(record)?;
    verify_with_key(signer, RECORD_DOMAIN, bytes.as_bytes(), obj["signature"].as_str().ok_or(Malformed)?).map_err(|_| BadSignature)?;

    let (from, until) = (n(obj, "valid_from_ms"), n(obj, "valid_until_ms"));
    if until <= from || until - from > MAX_WINDOW_MS {
        return Err(WindowInvalid);
    }
    if ctx.now_ms < from {
        return Err(NotYetValid);
    }
    if ctx.now_ms >= until {
        return Err(Expired);
    }
    let art = obj["artefact"].as_object().ok_or(Malformed)?;
    let hashes: Vec<String> = art["hashes"].as_array().ok_or(Malformed)?.iter().filter_map(|h| h.as_str().map(String::from)).collect();
    if ctx.model_hash.is_some_and(|m| !hashes.iter().any(|h| h == m)) {
        return Err(ModelHashMismatch);
    }
    let x = obj["experience"].as_object().ok_or(Malformed)?;
    let run_id = obj["run"]["run_id"].as_str().ok_or(Malformed)?;
    let head = x.get("ledger_head").filter(|h| hash(h)).and_then(Value::as_str).ok_or(LedgerHeadMissing)?;
    if head == genesis(run_id) || n(x, "ledger_entries") < 2 {
        return Err(LedgerHeadMissing);
    }
    if !art.get("knowledge_set_hash").is_some_and(hash) {
        return Err(KnowledgeHashMissing);
    }
    // internal consistency
    let (total, valid, unvalid) = (n(x, "simulated_seconds_total"), n(x, "simulated_seconds_validated"), n(x, "simulated_seconds_unvalidated"));
    if valid + unvalid != total || n(x, "episodes_validated") > n(x, "episodes_total") || n(x, "scenarios_validated") > n(x, "scenarios_total") || (valid > 0 && n(x, "episodes_validated") == 0) {
        return Err(ExperienceInconsistent);
    }
    let bc = obj["band_certificate"].as_object().ok_or(Malformed)?;
    let band = ranges(&bc["band"]).ok_or(Malformed)?;
    if band.is_empty() {
        return Err(BandMissing);
    }
    let rp = bc["release_point"].as_object().ok_or(Malformed)?;
    for (p, (lo, hi)) in &band {
        let v = rp.get(p).and_then(Value::as_f64).ok_or(ReleasePointOutsideBand)?;
        if v < *lo || v > *hi {
            return Err(ReleasePointOutsideBand);
        }
    }
    if rp.keys().any(|p| !band.iter().any(|(b, _)| b == p)) {
        return Err(ReleasePointOutsideBand);
    }
    let all = ranges(&x["coverage"]).ok_or(Malformed)?;
    for (p, (lo, hi)) in ranges(&x["coverage_validated"]).ok_or(Malformed)? {
        let in_band = band.iter().find(|(b, _)| *b == p).is_some_and(|(_, (blo, bhi))| lo >= *blo && hi <= *bhi);
        let in_all = all.iter().find(|(b, _)| *b == p).is_some_and(|(_, (alo, ahi))| lo >= *alo && hi <= *ahi);
        if !in_band || !in_all {
            return Err(CoverageOutsideBand);
        }
    }
    let res = obj["results"].as_object().ok_or(Malformed)?;
    if n(res, "fidelity_ppm") < n(res, "fidelity_minimum_ppm") {
        return Err(FidelityBelowMinimum);
    }
    Ok(Accepted { record_hash: record_hash(record)?, model_hashes: hashes, ledger_head: head.to_string(), validated_seconds: valid, unvalidated_seconds: unvalid, valid_until_ms: until })
}

/// The gate for installing a model or policy: no record, or an invalid one, and it is refused.
pub fn accept_model(model_hash: &str, record: Option<&Value>, signers: &[String], now_ms: u64) -> Result<Accepted, BirthRefusal> {
    let record = record.ok_or(BirthRefusal::Absent)?;
    verify(record, &BirthContext { signers, now_ms, model_hash: Some(model_hash) })
}

/// The head of a ledger with no entries.
pub fn genesis(run_id: &str) -> String {
    let mut h = Sha256::new();
    lp(&mut h, LEDGER_GENESIS_DOMAIN.as_bytes());
    lp(&mut h, run_id.as_bytes());
    hex::encode(h.finalize())
}

/// The hash a ledger entry commits to.
pub fn entry_hash(prev: &str, seq: u64, ts_ms: u64, kind: &str, body: &Value) -> Result<String, BirthRefusal> {
    let digest = sha_hex(canonical_json(body).map_err(|_| BirthRefusal::LedgerMalformed)?.as_bytes());
    let mut h = Sha256::new();
    lp(&mut h, LEDGER_ENTRY_DOMAIN.as_bytes());
    lp(&mut h, prev.as_bytes());
    h.update(seq.to_be_bytes());
    h.update(ts_ms.to_be_bytes());
    lp(&mut h, kind.as_bytes());
    lp(&mut h, digest.as_bytes());
    Ok(hex::encode(h.finalize()))
}

/// What a verified ledger adds up to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSummary {
    pub head: String,
    pub entries: u64,
    pub seconds_total: u64,
    pub seconds_validated: u64,
    pub episodes_total: u64,
    pub episodes_validated: u64,
}

const KINDS: [&str; 6] = ["run_started", "episode_batch", "calibration_update", "physical_batch_ingested", "benchmark_result", "run_finished"];

/// Checks the chain end to end and recomputes the validated split from the band, never from an entry's own claim.
pub fn verify_ledger(entries: &[Value]) -> Result<LedgerSummary, BirthRefusal> {
    use BirthRefusal::*;
    let first = entries.first().ok_or(LedgerMalformed)?;
    if first.get("kind").and_then(Value::as_str) != Some("run_started") {
        return Err(if first.get("kind").and_then(Value::as_str).is_some_and(|k| KINDS.contains(&k)) { LedgerNotStarted } else { LedgerMalformed });
    }
    let run_id = first["body"]["run_id"].as_str().ok_or(LedgerMalformed)?;
    let mut prev = genesis(run_id);
    let (mut last_ts, mut finished) = (0u64, false);
    let mut band: Option<Vec<(String, (f64, f64))>> = None;
    let mut s = LedgerSummary { head: String::new(), entries: 0, seconds_total: 0, seconds_validated: 0, episodes_total: 0, episodes_validated: 0 };
    for (i, e) in entries.iter().enumerate() {
        let e = e.as_object().ok_or(LedgerMalformed)?;
        let (seq, ts) = (e.get("seq").and_then(int).ok_or(LedgerMalformed)?, e.get("ts_ms").and_then(int).ok_or(LedgerMalformed)?);
        let kind = e.get("kind").and_then(Value::as_str).ok_or(LedgerMalformed)?;
        let (eprev, ehash) = (e.get("prev").filter(|h| hash(h)).and_then(Value::as_str), e.get("hash").filter(|h| hash(h)).and_then(Value::as_str));
        let (eprev, ehash) = eprev.zip(ehash).ok_or(LedgerMalformed)?;
        if !KINDS.contains(&kind) {
            return Err(LedgerKindUnknown);
        }
        if seq != i as u64 || ts < last_ts {
            return Err(LedgerReordered);
        }
        let body = e.get("body").ok_or(LedgerMalformed)?;
        if eprev != prev || entry_hash(&prev, seq, ts, kind, body).map_err(|_| LedgerChainBroken)? != ehash {
            return Err(LedgerChainBroken);
        }
        if finished {
            return Err(LedgerAfterFinish);
        }
        if i > 0 && kind == "run_started" {
            return Err(LedgerMalformed);
        }
        last_ts = ts;
        prev = ehash.to_string();
        match kind {
            "calibration_update" => band = Some(ranges(&body["band"]).filter(|b| !b.is_empty()).ok_or(LedgerMalformed)?),
            "episode_batch" => {
                let secs = body.get("simulated_seconds").and_then(int).ok_or(LedgerMalformed)?;
                let eps = body.get("episodes").and_then(int).ok_or(LedgerMalformed)?;
                let r = ranges(&body["ranges"]).ok_or(LedgerMalformed)?;
                let claimed = body.get("in_band").and_then(Value::as_bool).ok_or(LedgerMalformed)?;
                let inside = band.as_ref().is_some_and(|b| r.iter().all(|(p, (lo, hi))| b.iter().any(|(bp, (blo, bhi))| bp == p && lo >= blo && hi <= bhi)));
                if claimed != inside {
                    return Err(OutOfBandClaimedValidated);
                }
                s.seconds_total += secs;
                s.episodes_total += eps;
                if inside {
                    s.seconds_validated += secs;
                    s.episodes_validated += eps;
                }
            }
            "run_finished" => finished = true,
            _ => {}
        }
    }
    if !finished {
        return Err(LedgerNotFinished);
    }
    s.head = prev;
    s.entries = entries.len() as u64;
    Ok(s)
}

/// An auditor who holds the ledger: it verifies, ends at the record's head, and adds up to what the record states.
pub fn reconcile(record: &Value, ledger: &[Value]) -> Result<LedgerSummary, BirthRefusal> {
    use BirthRefusal::*;
    let s = verify_ledger(ledger)?;
    let x = record.get("experience").and_then(Value::as_object).ok_or(Malformed)?;
    if x.get("ledger_head").and_then(Value::as_str) != Some(s.head.as_str()) {
        return Err(LedgerHeadMismatch);
    }
    let same = n(x, "ledger_entries") == s.entries
        && n(x, "simulated_seconds_total") == s.seconds_total
        && n(x, "simulated_seconds_validated") == s.seconds_validated
        && n(x, "simulated_seconds_unvalidated") == s.seconds_total - s.seconds_validated
        && n(x, "episodes_total") == s.episodes_total
        && n(x, "episodes_validated") == s.episodes_validated;
    if same {
        Ok(s)
    } else {
        Err(LedgerSummaryMismatch)
    }
}
