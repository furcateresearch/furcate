//! The birth record, checked against the vector the Living Worlds side produced, byte for byte.
//!
//! `tests/fixtures/birth-record.golden.json` is made by the producer's test (livingworlds-core,
//! tests/birth-record.test.ts) and signed by a test key whose seed is public: 32 bytes of 0x42. This side
//! shares no code with it, so the vector is what stops the two drifting. The hash below is pinned in both
//! tests; changing one copy of the file without the other fails one of them.

use furcate_identity::AssuranceClass;
use furcate_sense::cascade::birth::{
    accept_model, entry_hash, genesis, reconcile, record_hash, signing_bytes, verify, verify_ledger, BirthContext, BirthRefusal, RECORD_DOMAIN, MAX_WINDOW_MS,
};
use furcate_sense::cascade::physical::{BatchBuilder, SiteClock, BATCH_DOMAIN};
use furcate_sense::cascade::physical::signing_bytes as batch_signing_bytes;
use furcate_sense::leaf::verify_with_key;
use furcate_sense::Leaf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const GOLDEN: &str = include_str!("fixtures/birth-record.golden.json");
const GOLDEN_SHA256: &str = "7738ec6110f73d1a70e31a3fc52c755dad7c3830fa71b96563148e67015146d9";
const SEED: u8 = 0x42;

struct Vector {
    record: Value,
    ledger: Vec<Value>,
    expected: Value,
}

fn vector() -> Vector {
    let v: Value = serde_json::from_str(GOLDEN).unwrap();
    Vector { record: v["record"].clone(), ledger: v["ledger"].as_array().unwrap().clone(), expected: v["expected"].clone() }
}

fn signer(byte: u8) -> Leaf {
    Leaf::new("lw-test-signer", [byte; 32])
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn ctx<'a>(signers: &'a [String], v: &'a Vector) -> BirthContext<'a> {
    BirthContext { signers, now_ms: v.expected["verify_now_ms"].as_u64().unwrap(), model_hash: v.expected["model_hash"].as_str() }
}

fn resign(r: &mut Value, byte: u8) {
    let sig = signer(byte).sign_message(RECORD_DOMAIN, signing_bytes(r).unwrap().as_bytes());
    r["signature"] = json!(sig);
}

fn refused(r: &Value, v: &Vector) -> &'static str {
    let signers = [v.expected["signer_key_id"].as_str().unwrap().to_string()];
    verify(r, &ctx(&signers, v)).expect_err("expected a refusal").code()
}

fn resigned(v: &Vector, change: impl Fn(&mut Value)) -> Value {
    let mut r = v.record.clone();
    change(&mut r);
    resign(&mut r, SEED);
    r
}

#[test]
fn the_vector_is_the_pinned_one_and_made_by_the_test_key() {
    assert_eq!(hex::encode(Sha256::digest(GOLDEN.as_bytes())), GOLDEN_SHA256, "the file changed: update the pin here and in the producer's test together");
    let v = vector();
    assert_eq!(signer(SEED).public_key(), v.expected["signer_key_id"].as_str().unwrap());
    assert_eq!(v.record["signer"], v.expected["signer_key_id"]);
}

#[test]
fn the_golden_record_verifies_with_the_producers_hash_and_split() {
    let v = vector();
    let signers = [v.expected["signer_key_id"].as_str().unwrap().to_string()];
    let a = verify(&v.record, &ctx(&signers, &v)).unwrap();
    assert_eq!(a.record_hash, v.expected["record_hash"].as_str().unwrap());
    assert_eq!(a.validated_seconds, v.expected["simulated_seconds_validated"].as_u64().unwrap());
    assert_eq!(a.unvalidated_seconds, v.expected["simulated_seconds_unvalidated"].as_u64().unwrap());
    assert_eq!(a.ledger_head, v.expected["ledger_head"].as_str().unwrap());
    assert_eq!(record_hash(&v.record).unwrap(), a.record_hash);
}

#[test]
fn the_ledger_verifies_here_and_adds_up_to_the_record() {
    let v = vector();
    let s = reconcile(&v.record, &v.ledger).unwrap();
    assert_eq!(s.head, v.expected["ledger_head"].as_str().unwrap());
    assert_eq!(s.seconds_total, 315_360_000 + 63_072_000);
    assert_eq!(s.seconds_validated, 315_360_000);
}

fn leaves(v: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match v {
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            path.push(k.clone());
            leaves(x, path, out);
            path.pop();
        }),
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| {
            path.push(i.to_string());
            leaves(x, path, out);
            path.pop();
        }),
        _ => out.push(path.clone()),
    }
}

fn at<'a>(v: &'a mut Value, path: &[String]) -> &'a mut Value {
    path.iter().fold(v, |v, k| if v.is_array() { &mut v[k.parse::<usize>().unwrap()] } else { &mut v[k.as_str()] })
}

#[test]
fn flipping_any_single_field_of_a_signed_record_is_refused() {
    let v = vector();
    let mut paths = Vec::new();
    leaves(&v.record, &mut Vec::new(), &mut paths);
    assert!(paths.len() > 50, "{}", paths.len());
    for p in &paths {
        let mut r = v.record.clone();
        let leaf = at(&mut r, p);
        *leaf = match leaf.clone() {
            Value::Number(n) if n.is_u64() => json!(n.as_u64().unwrap() + 1),
            Value::Number(n) => json!(n.as_f64().unwrap() + 1.0),
            Value::Bool(b) => json!(!b),
            Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {
                let mut s = s;
                let last = if s.ends_with('0') { '1' } else { '0' };
                s.pop();
                s.push(last);
                json!(s)
            }
            Value::String(s) => json!(format!("{s}x")),
            other => other,
        };
        let code = refused(&r, &v);
        let ok: &[&str] = match p[0].as_str() {
            "format" => &["wrong_format"],
            "version" => &["unsupported_version"],
            "signer" => &["unknown_signer", "malformed"],
            _ => &["bad_signature", "malformed"],
        };
        assert!(ok.contains(&code), "{} gave {code}", p.join("."));
    }
}

#[test]
fn a_member_added_or_removed_is_refused() {
    let v = vector();
    let mut added = v.record.clone();
    added["extra"] = json!(1);
    assert_eq!(refused(&added, &v), "malformed");
    for k in v.record.as_object().unwrap().keys() {
        let mut r = v.record.clone();
        r.as_object_mut().unwrap().remove(k);
        assert!(["malformed", "wrong_format", "unsupported_version"].contains(&refused(&r, &v)), "{k}");
    }
}

#[test]
fn re_signed_records_that_break_a_rule_are_each_refused_by_their_own_code() {
    let v = vector();
    let cases: Vec<(&str, &str, Box<dyn Fn(&mut Value)>)> = vec![
        ("window ends where it starts", "window_invalid", Box::new(|r| r["valid_until_ms"] = r["valid_from_ms"].clone())),
        ("window over 366 days", "window_invalid", Box::new(|r| r["valid_until_ms"] = json!(r["valid_from_ms"].as_u64().unwrap() + MAX_WINDOW_MS + 1))),
        ("no knowledge set hash", "knowledge_hash_missing", Box::new(|r| { r["artefact"].as_object_mut().unwrap().remove("knowledge_set_hash"); })),
        ("head of an empty ledger", "ledger_head_missing", Box::new(|r| r["experience"]["ledger_head"] = json!(genesis(r["run"]["run_id"].as_str().unwrap())))),
        ("no ledger head", "ledger_head_missing", Box::new(|r| { r["experience"].as_object_mut().unwrap().remove("ledger_head"); })),
        ("validated above the total", "experience_inconsistent", Box::new(|r| r["experience"]["simulated_seconds_validated"] = json!(r["experience"]["simulated_seconds_validated"].as_u64().unwrap() + 1))),
        ("out-of-band seconds moved into validated", "experience_inconsistent", Box::new(|r| r["experience"]["simulated_seconds_validated"] = json!(315_360_000u64 + 63_072_000))),
        ("empty band", "band_missing", Box::new(|r| r["band_certificate"]["band"] = json!({}))),
        ("release point outside the band", "release_point_outside_band", Box::new(|r| r["band_certificate"]["release_point"]["temp"] = json!(31))),
        ("validated coverage wider than the band", "coverage_outside_band", Box::new(|r| r["experience"]["coverage_validated"]["temp"] = json!([5, 35]))),
        ("fidelity under the stated minimum", "fidelity_below_minimum", Box::new(|r| r["results"]["fidelity_minimum_ppm"] = json!(950_000))),
    ];
    for (name, want, change) in cases {
        assert_eq!(refused(&resigned(&v, change), &v), want, "{name}");
    }
}

#[test]
fn wrong_signer_expired_not_yet_valid_wrong_model_and_a_number_beyond_2_pow_53() {
    let v = vector();
    let enrolled = [v.expected["signer_key_id"].as_str().unwrap().to_string()];
    let mut other = v.record.clone();
    other["signer"] = json!(signer(0x77).public_key());
    resign(&mut other, 0x77);
    assert_eq!(refused(&other, &v), "unknown_signer");
    let mut stolen_id = v.record.clone();
    resign(&mut stolen_id, 0x77);
    assert_eq!(refused(&stolen_id, &v), "bad_signature");
    let until = v.record["valid_until_ms"].as_u64().unwrap();
    let from = v.record["valid_from_ms"].as_u64().unwrap();
    let c = |now_ms, model: Option<&str>, signers: &[String]| verify(&v.record, &BirthContext { signers, now_ms, model_hash: model }).err().map(|e| e.code());
    let model = v.expected["model_hash"].as_str();
    assert_eq!(c(until, model, &enrolled), Some("expired"));
    assert_eq!(c(from - 1, model, &enrolled), Some("not_yet_valid"));
    assert_eq!(c(from, Some(&sha("another model")), &enrolled), Some("model_hash_mismatch"));
    assert_eq!(c(from, model, &[]), Some("unknown_signer"));
    let mut big = v.record.clone();
    big["experience"]["gpu_seconds"] = json!(1u64 << 53);
    assert_eq!(refused(&big, &v), "malformed");
    assert_eq!(refused(&json!([1]), &v), "malformed");
}

#[test]
fn a_model_offered_without_a_valid_record_is_refused() {
    let v = vector();
    let enrolled = [v.expected["signer_key_id"].as_str().unwrap().to_string()];
    let (now, model) = (v.expected["verify_now_ms"].as_u64().unwrap(), v.expected["model_hash"].as_str().unwrap());
    assert_eq!(accept_model(model, None, &enrolled, now), Err(BirthRefusal::Absent));
    assert_eq!(BirthRefusal::Absent.code(), "birth_record_absent");
    assert!(accept_model(model, Some(&v.record), &enrolled, now).is_ok());
    assert_eq!(accept_model(&sha("x"), Some(&v.record), &enrolled, now), Err(BirthRefusal::ModelHashMismatch));
    assert_eq!(accept_model(model, Some(&json!({})), &enrolled, now), Err(BirthRefusal::WrongFormat));
    assert_eq!(accept_model(model, Some(&v.record), &[], now), Err(BirthRefusal::UnknownSigner));
}

/// A producer that lies and still chains correctly: every entry from `from` on is rehashed.
fn rechain(ledger: &[Value], from: usize) -> Vec<Value> {
    let mut out = ledger.to_vec();
    let run_id = out[0]["body"]["run_id"].as_str().unwrap().to_string();
    for i in from..out.len() {
        let prev = if i == 0 { genesis(&run_id) } else { out[i - 1]["hash"].as_str().unwrap().to_string() };
        let h = entry_hash(&prev, out[i]["seq"].as_u64().unwrap(), out[i]["ts_ms"].as_u64().unwrap(), out[i]["kind"].as_str().unwrap(), &out[i]["body"]).unwrap();
        out[i]["prev"] = json!(prev);
        out[i]["hash"] = json!(h);
    }
    out
}

fn lcode(l: &[Value]) -> &'static str {
    verify_ledger(l).err().map(|e| e.code()).unwrap_or("ok")
}

#[test]
fn a_ledger_entry_deleted_reordered_edited_or_appended_after_the_end_is_refused() {
    let v = vector();
    let l = &v.ledger;
    assert_eq!(lcode(l), "ok");
    let mut gap = l.clone();
    gap.remove(3);
    assert_eq!(lcode(&gap), "ledger_reordered");
    let mut swapped = l.clone();
    swapped.swap(3, 4);
    for (i, e) in swapped.iter_mut().enumerate() {
        e["seq"] = json!(i);
    }
    assert_eq!(lcode(&swapped), "ledger_chain_broken");
    let mut moved = l.clone();
    moved.swap(1, 2);
    assert_eq!(lcode(&moved), "ledger_reordered");
    let mut edited = l.clone();
    edited[3]["body"]["simulated_seconds"] = json!(1);
    assert_eq!(lcode(&edited), "ledger_chain_broken");
    assert_eq!(lcode(&l[..l.len() - 1]), "ledger_not_finished");
    assert_eq!(lcode(&l[1..]), "ledger_not_started");
    let mut after = l.clone();
    let mut extra = l[5].clone();
    extra["seq"] = json!(l.len());
    extra["ts_ms"] = l[l.len() - 1]["ts_ms"].clone();
    extra["prev"] = l[l.len() - 1]["hash"].clone();
    extra["hash"] = json!(entry_hash(extra["prev"].as_str().unwrap(), l.len() as u64, extra["ts_ms"].as_u64().unwrap(), "benchmark_result", &extra["body"]).unwrap());
    after.push(extra);
    assert_eq!(lcode(&after), "ledger_after_finish");
    let mut back = l.clone();
    back[4]["ts_ms"] = json!(back[3]["ts_ms"].as_u64().unwrap() - 1);
    assert_eq!(lcode(&rechain(&back, 4)), "ledger_reordered");
    let mut unknown = l.clone();
    unknown[2]["kind"] = json!("mystery");
    assert_eq!(lcode(&unknown), "ledger_kind_unknown");
}

#[test]
fn head_mismatch_and_out_of_band_experience_claimed_as_validated() {
    let v = vector();
    let other_head = resigned(&v, |r| r["experience"]["ledger_head"] = json!(sha("some other head")));
    assert_eq!(reconcile(&other_head, &v.ledger).unwrap_err(), BirthRefusal::LedgerHeadMismatch);
    let moved = resigned(&v, |r| {
        r["experience"]["simulated_seconds_validated"] = json!(315_360_000u64 + 63_072_000);
        r["experience"]["simulated_seconds_unvalidated"] = json!(0);
        r["experience"]["episodes_validated"] = json!(1200);
    });
    let signers = [v.expected["signer_key_id"].as_str().unwrap().to_string()];
    assert!(verify(&moved, &ctx(&signers, &v)).is_ok(), "a node holding only the record cannot see this");
    assert_eq!(reconcile(&moved, &v.ledger).unwrap_err(), BirthRefusal::LedgerSummaryMismatch);
    let mut lie = v.ledger.clone();
    lie[4]["body"]["in_band"] = json!(true);
    assert_eq!(lcode(&rechain(&lie, 4)), "out_of_band_claimed_validated");
}

#[test]
fn a_batch_can_name_its_birth_record_and_without_the_field_it_is_unchanged() {
    let site = Leaf::new("furcate:node:large1", [0x5a; 32]);
    let clock = || SiteClock { source: "ntp".into(), uncertainty_ms: Some(50) };
    let plain = BatchBuilder::new("site-test-01", "furcate:node:large1", AssuranceClass::Soft, "b1", 1, 1_000, clock()).build(&site).unwrap();
    assert!(plain.get("birth_record_hash").is_none());
    let v = vector();
    let hash = v.expected["record_hash"].as_str().unwrap();
    let bound = BatchBuilder::new("site-test-01", "furcate:node:large1", AssuranceClass::Soft, "b1", 1, 1_000, clock())
        .with_birth_record_hash(hash)
        .unwrap()
        .build(&site)
        .unwrap();
    assert_eq!(bound["birth_record_hash"], json!(hash));
    let check = |b: &Value| verify_with_key(&site.public_key(), BATCH_DOMAIN, batch_signing_bytes(b).unwrap().as_bytes(), b["signature"].as_str().unwrap()).is_ok();
    assert!(check(&plain) && check(&bound));
    let mut swapped = bound.clone();
    swapped["birth_record_hash"] = json!(sha("another record"));
    assert!(!check(&swapped), "the field is covered by the site signature");
    assert!(BatchBuilder::new("s", "n", AssuranceClass::Soft, "b", 1, 1, clock()).with_birth_record_hash("not a hash").is_err());
}
