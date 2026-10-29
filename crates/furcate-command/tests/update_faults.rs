//! Fault injection for model-update records: no mutant may be accepted. Counts as for the other suites: 20,000 in a
//! debug run, 1,000,000 in a release run, FAULT_CASES overrides.
//!
//! Two families. Byte-level damage to a valid signed record (nothing re-signed), which must fail on canonical form or
//! signature. Re-signed records in which exactly one thing the register binds is wrong (the model chain, the birth
//! record, the parent links, the evaluation, the attestation, the signer chain, the window), which must fail on that
//! thing. Controls are the valid record and must be accepted.

mod update_common;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use update_common::*;

const SEED: u64 = 0x5eed_1029_0000_0010;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn hexrand(r: &mut Rng) -> String {
    format!("{:016x}{:016x}{:016x}{:016x}", r.next(), r.next(), r.next(), r.next())
}

struct Case {
    cat: &'static str,
    input: Vec<u8>,
    now: u64,
    control: bool,
}

fn gen(i: u64, base: &Value, bytes: &[u8]) -> Case {
    let mut r = Rng(SEED ^ i.wrapping_mul(0xd1b5_4a32_d192_ed03));
    let mut v = base.clone();
    let mut c = Case { cat: "", input: bytes.to_vec(), now: NOW, control: false };
    match r.below(30) {
        0 => {
            c.cat = "control";
            c.control = true;
        }
        1 => {
            c.cat = "bit_flip";
            let p = r.below(bytes.len());
            c.input[p] ^= 1 << r.below(8);
        }
        2 => {
            c.cat = "truncate";
            c.input.truncate(r.below(bytes.len()));
        }
        3 => {
            c.cat = "delete_byte";
            c.input.remove(r.below(bytes.len()));
        }
        4 => {
            c.cat = "insert_byte";
            let x = r.next() as u8;
            c.input.insert(r.below(bytes.len() + 1), x);
        }
        5 => {
            c.cat = "whitespace_or_pretty";
            if r.below(2) == 0 {
                c.input.insert(r.below(bytes.len() + 1), b'\n');
            } else {
                c.input = serde_json::to_vec_pretty(base).unwrap();
            }
        }
        6 => {
            c.cat = "swap_signatures";
            let n = v["signatures"].as_array().unwrap().len();
            let (a, b) = (r.below(n), r.below(n));
            v["signatures"].as_array_mut().unwrap().swap(a, b);
            c.input = furcate_command::issue::bytes(&v);
            if a == b {
                c.control = true;
            }
        }
        7 => {
            c.cat = "edit_unsigned_field";
            // Change one field and leave the old signatures in place.
            match r.below(4) {
                0 => v["new_model_sha256"] = json!(hexrand(&mut r)),
                1 => v["experience"]["ledger_head"] = json!(hexrand(&mut r)),
                2 => v["evaluation"]["fidelity_ppm"] = json!(1 + r.below(999_999) as u64),
                _ => v["update_id"] = json!(format!("upd-{:04}", 5000 + r.below(1000))),
            }
            c.input = furcate_command::issue::bytes(&v);
        }
        8 => {
            c.cat = "signature_dropped";
            v["signatures"].as_array_mut().unwrap().remove(r.below(3));
            c.input = furcate_command::issue::bytes(&v);
        }
        9 => {
            c.cat = "signature_from_other_record";
            let other = sign_chain(update_value(9, M0, M1, None, H0, H1));
            let o: Value = furcate_command::canon::parse_canonical(&other).unwrap();
            v["signatures"][r.below(3)] = o["signatures"][r.below(3)].clone();
            c.input = furcate_command::issue::bytes(&v);
            if v["signatures"] == base["signatures"] {
                c.control = true;
            }
        }
        // ---- re-signed, one bound thing wrong ----
        10 => {
            c.cat = "old_model_not_current";
            v["old_model_sha256"] = json!(hexrand(&mut r));
            c.input = sign_chain(v);
        }
        11 => {
            c.cat = "same_model";
            v["new_model_sha256"] = v["old_model_sha256"].clone();
            c.input = sign_chain(v);
        }
        12 => {
            c.cat = "birth_record";
            v["birth_record_sha256"] = json!(hexrand(&mut r));
            c.input = sign_chain(v);
        }
        13 => {
            c.cat = "parent_update";
            v["parent_update_sha256"] = if r.below(2) == 0 { json!(hexrand(&mut r)) } else { Value::Null };
            if v["parent_update_sha256"].is_null() {
                // null is the right parent for the first update; make it wrong by pointing at a prior update instead
                v["parent_update_sha256"] = json!(hexrand(&mut r));
            }
            c.input = sign_chain(v);
        }
        14 => {
            c.cat = "parent_ledger_head";
            v["experience"]["parent_ledger_head"] = json!(hexrand(&mut r));
            c.input = sign_chain(v);
        }
        15 => {
            c.cat = "score_below_threshold_claims_passed";
            let b = r.below(2);
            let th = v["evaluation"]["benchmarks"][b]["threshold_ppm"].as_u64().unwrap();
            v["evaluation"]["benchmarks"][b]["score_ppm"] = json!(r.below(th as usize) as u64);
            c.input = sign_chain(v);
        }
        16 => {
            c.cat = "fidelity_below_minimum_claims_passed";
            let m = v["evaluation"]["fidelity_minimum_ppm"].as_u64().unwrap();
            v["evaluation"]["fidelity_ppm"] = json!(r.below(m as usize) as u64);
            c.input = sign_chain(v);
        }
        17 => {
            c.cat = "outside_band_claims_passed";
            v["evaluation"]["release_point_inside_band"] = json!(false);
            c.input = sign_chain(v);
        }
        18 => {
            c.cat = "evaluation_failed";
            v["evaluation"]["release_point_inside_band"] = json!(false);
            v["evaluation"]["result"] = json!("failed");
            c.input = sign_chain(v);
        }
        19 => {
            c.cat = "attestation_min_wrong";
            let wrong = ["soft", "device", "tee", "dice", "tpm"][r.below(5)];
            v["attestation_min"] = json!(wrong);
            c.input = sign_chain(v);
        }
        20 => {
            c.cat = "signer_claims_other_class";
            let s = r.below(3);
            let cur = v["signers"][s]["attestation"].as_str().unwrap().to_string();
            let other = ["soft", "device", "se", "tee", "dice", "tpm"].iter().find(|x| **x != cur).unwrap();
            v["signers"][s]["attestation"] = json!(other);
            c.input = sign_chain(v);
        }
        21 => {
            c.cat = "unenrolled_signer";
            v["signers"][r.below(3)]["key"] = json!(furcate_command::issue::key_id(&k(0x80 + r.below(8) as u8)));
            c.input = sign_chain(v);
        }
        22 => {
            c.cat = "signer_chain_shape";
            match r.below(3) {
                0 => v["signers"][2]["role"] = json!(["trainer", "evaluator"][r.below(2)]),
                1 => v["signers"][r.below(3)] = v["signers"][r.below(3)].clone(),
                _ => v["signers"] = json!([]),
            }
            let unchanged = v["signers"] == base["signers"];
            c.input = sign_chain(v);
            if unchanged {
                c.control = true;
            }
        }
        23 => {
            c.cat = "window";
            match r.below(3) {
                0 => v["valid_until_ms"] = json!(NOW - 1000 - r.below(1000) as u64),
                1 => v["valid_until_ms"] = json!(NOW + 366 * 86_400_000u64 + 1 + r.below(1000) as u64),
                _ => v["issued_ms"] = json!(NOW + 1 + r.below(100_000) as u64),
            }
            c.input = sign_chain(v);
        }
        24 => {
            c.cat = "expired";
            c.input = sign_chain(v);
            c.now = NOW + 86_400_000 + r.below(100_000) as u64;
        }
        25 => {
            c.cat = "tenant_or_agent";
            if r.below(2) == 0 {
                v["tenant"] = json!("tenant-b");
            } else {
                v["agent_id"] = json!("agent-x");
            }
            c.input = sign_chain(v);
        }
        26 => {
            c.cat = "unknown_or_missing_member";
            match r.below(3) {
                0 => v["experience"]["extra"] = json!(1),
                1 => {
                    v.as_object_mut().unwrap().remove(["birth_record_sha256", "evaluation", "experience", "signers"][r.below(4)]);
                }
                _ => v["extra"] = json!("x"),
            }
            c.input = sign_chain(v);
        }
        27 => {
            c.cat = "big_numbers";
            v["experience"]["ledger_entries"] = json!(9_007_199_254_740_993u64 + r.below(1000) as u64);
            c.input = serde_json::to_vec(&v).unwrap();
        }
        28 => {
            c.cat = "format_or_version";
            if r.below(2) == 0 {
                v["format"] = json!(["birth-record", "model_update", "Model-Update"][r.below(3)]);
            } else {
                v["v"] = [json!(0), json!(2), json!(1.5)][r.below(3)].clone();
            }
            c.input = sign_chain(v);
        }
        _ => {
            c.cat = "duplicate_bytes";
            let a = r.below(bytes.len());
            let l = 1 + r.below(40.min(bytes.len() - a));
            let chunk = bytes[a..a + l].to_vec();
            c.input.splice(a..a, chunk);
        }
    }
    if !c.control && c.now == NOW && c.input == bytes {
        c.control = true;
    }
    c
}

#[derive(Default)]
struct Tally {
    cases: u64,
    controls: u64,
    control_accepts: u64,
    false_accepts: u64,
    by_cat: BTreeMap<&'static str, u64>,
    examples: Vec<String>,
}

#[test]
fn mutated_updates_get_no_false_accept() {
    let default_cases: u64 = if cfg!(debug_assertions) { 20_000 } else { 1_000_000 };
    let n: u64 = std::env::var("FAULT_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(default_cases);
    let bytes = sign_chain(update_value(1, M0, M1, None, H0, H1));
    let base: Value = furcate_command::canon::parse_canonical(&bytes).unwrap();
    let threads = 8u64;
    let started = std::time::Instant::now();
    let tallies: Vec<Tally> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let (base, bytes) = (&base, &bytes);
                s.spawn(move || {
                    let mut tl = Tally::default();
                    for i in n * t / threads..n * (t + 1) / threads {
                        let c = gen(i, base, bytes);
                        let mut reg = register("se");
                        let d = reg.decide(&c.input, c.now);
                        assert!(reg.chain().verify().is_ok());
                        tl.cases += 1;
                        if c.control {
                            tl.controls += 1;
                            tl.control_accepts += d.accepted as u64;
                        } else {
                            *tl.by_cat.entry(c.cat).or_insert(0) += 1;
                            if d.accepted {
                                tl.false_accepts += 1;
                                if tl.examples.len() < 5 {
                                    tl.examples.push(format!("case {i} {}", c.cat));
                                }
                            }
                        }
                    }
                    tl
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Tally::default();
    for t in tallies {
        all.cases += t.cases;
        all.controls += t.controls;
        all.control_accepts += t.control_accepts;
        all.false_accepts += t.false_accepts;
        all.examples.extend(t.examples);
        for (k, v) in t.by_cat {
            *all.by_cat.entry(k).or_insert(0) += v;
        }
    }
    println!("UPDATE-FAULT-INJECTION cases={} mutants={} controls={} elapsed={:?}", all.cases, all.cases - all.controls, all.controls, started.elapsed());
    println!("UPDATE-FAULT-INJECTION false_accepts={} control_accepts={}/{}", all.false_accepts, all.control_accepts, all.controls);
    for (k, v) in &all.by_cat {
        println!("  {k:40} mutants={v}");
    }
    assert_eq!(all.cases, n);
    assert_eq!(all.false_accepts, 0, "{:?}", all.examples);
    assert_eq!(all.control_accepts, all.controls, "a valid record was refused");
}
