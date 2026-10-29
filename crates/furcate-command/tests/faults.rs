//! Fault injection: a seeded generator mutates valid commands in every way the task names, and the gate must accept
//! none of them. The same cases go to a baseline that checks only the signature and the expiry, to show what that
//! would let through. Case count: 20,000 in a debug-profile run (the default for `cargo test`) and 1,000,000 in a
//! release run. FAULT_CASES overrides either, for example `FAULT_CASES=1000000 cargo test` for the full run in debug.

mod common;
use common::*;
use furcate_command::canon::canonical;
use furcate_command::issue::{bytes, key_id, sign_value};
use furcate_command::{Decision, Gate, KillState, COMMAND_DOMAIN};
use furcate_ledger::Chain;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SEED: u64 = 0x5eed_1028_c0de_0001;

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

struct KillAll;
impl KillState for KillAll {
    fn is_killed(&self, _: &str, _: &str) -> bool {
        true
    }
}

/// What a case does: optionally a prior command that is decided first, the bytes under test, the clock, kill state.
struct Case {
    cat: &'static str,
    prior: Option<Vec<u8>>,
    input: Vec<u8>,
    now: u64,
    kill: bool,
    /// Whether the input is meant to be accepted.
    control: bool,
}

const ORDER_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// signature bytes S + L (little endian), which a non-strict verifier may accept.
fn malleate(sig_hex: &str) -> String {
    let mut b = hex::decode(sig_hex).unwrap();
    let mut carry = 0u16;
    for i in 0..32 {
        let t = b[32 + i] as u16 + ORDER_L[i] as u16 + carry;
        b[32 + i] = t as u8;
        carry = t >> 8;
    }
    hex::encode(b)
}

fn pointers(v: &Value) -> Vec<String> {
    fn walk(v: &Value, p: String, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    let q = format!("{p}/{k}");
                    out.push(q.clone());
                    walk(x, q, out);
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    let q = format!("{p}/{i}");
                    out.push(q.clone());
                    walk(x, q, out);
                }
            }
            _ => {}
        }
    }
    let mut out = vec![];
    walk(v, String::new(), &mut out);
    out
}

fn set(v: &mut Value, ptr: &str, x: Value) {
    if let Some(t) = v.pointer_mut(ptr) {
        *t = x;
    }
}
fn remove(v: &mut Value, ptr: &str) {
    let (parent, last) = ptr.rsplit_once('/').unwrap();
    match v.pointer_mut(parent) {
        Some(Value::Object(m)) => {
            m.remove(last);
        }
        Some(Value::Array(a)) => {
            if let Ok(i) = last.parse::<usize>() {
                if i < a.len() {
                    a.remove(i);
                }
            }
        }
        _ => {}
    }
}

/// Re-sign after a structural mutation: the certificate if it was touched, then the command.
fn resign(mut v: Value, in_cert: bool) -> Vec<u8> {
    if in_cert && v.get("twin_cert").is_some_and(|c| c.is_object()) {
        let mut c = v["twin_cert"].take();
        c["signer"] = json!(key_id(&lw()));
        if sign_value(&mut c, furcate_command::CERT_DOMAIN, &lw()).is_err() {
            return b"{}".to_vec();
        }
        v["twin_cert"] = c;
    }
    v["signer"] = json!(key_id(&lw()));
    if sign_value(&mut v, COMMAND_DOMAIN, &lw()).is_err() {
        return b"{}".to_vec();
    }
    match canonical(&v) {
        Ok(s) => s.into_bytes(),
        Err(_) => b"{}".to_vec(),
    }
}

fn gen(index: u64, base: &Value, base_bytes: &[u8], ptrs: &[String]) -> Case {
    let mut r = Rng(SEED ^ index.wrapping_mul(0xd1b5_4a32_d192_ed03));
    let cat = r.below(34);
    let mut case = Case { cat: "", prior: None, input: base_bytes.to_vec(), now: NOW, kill: false, control: false };
    let b = base_bytes.to_vec();
    match cat {
        0 => {
            case.cat = "control";
            case.control = true;
        }
        1 => {
            case.cat = "bit_flip";
            let i = r.below(b.len());
            case.input[i] ^= 1 << r.below(8);
        }
        2 => {
            case.cat = "truncate";
            case.input.truncate(r.below(b.len()));
        }
        3 => {
            case.cat = "duplicate";
            let a = r.below(b.len());
            let l = 1 + r.below(40.min(b.len() - a));
            let chunk = b[a..a + l].to_vec();
            case.input.splice(a..a, chunk);
            if r.below(4) == 0 {
                case.input = [b.clone(), b.clone()].concat();
            }
        }
        4 => {
            case.cat = "swap_bytes";
            let (i, j) = (r.below(b.len()), r.below(b.len()));
            case.input.swap(i, j);
            if case.input == b {
                case.control = true;
            }
        }
        5 => {
            case.cat = "delete_byte";
            case.input.remove(r.below(b.len()));
        }
        6 => {
            case.cat = "insert_byte";
            let x = r.next() as u8;
            case.input.insert(r.below(b.len() + 1), x);
        }
        7 => {
            case.cat = "whitespace";
            let ws = [b' ', b'\n', b'\t', b'\r'][r.below(4)];
            case.input.insert(r.below(b.len() + 1), ws);
        }
        8 => {
            case.cat = "reordered_or_pretty";
            if r.below(2) == 0 {
                case.input = serde_json::to_vec_pretty(base).unwrap();
            } else {
                // reversed key order at the top level, values canonical
                let m = base.as_object().unwrap();
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort_by(|a, b| b.cmp(a));
                let parts: Vec<String> = keys.iter().map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(&m[*k]).unwrap())).collect();
                case.input = format!("{{{}}}", parts.join(",")).into_bytes();
            }
        }
        9 => {
            case.cat = "duplicate_key";
            let extra = ["\"mode\":\"actuate\"", "\"command_seq\":999", "\"body\":{\"quantity\":\"temperature\",\"unit\":\"celsius\",\"value\":99}", "\"policy_sha256\":\"00\"", "\"signer\":\"x\""][r.below(5)];
            let mut s = String::from_utf8(b.clone()).unwrap();
            if r.below(2) == 0 {
                s.insert_str(1, &format!("{extra},"));
            } else {
                s.insert_str(s.len() - 1, &format!(",{extra}"));
            }
            case.input = s.into_bytes();
        }
        10 => {
            case.cat = "unicode";
            let s = String::from_utf8(b.clone()).unwrap();
            let tricks: [&str; 8] = ["\u{0430}", "\u{200b}", "\u{ff11}", "\\u0061", "\u{feff}", "\\ud800", "\u{202e}", "\0"];
            let t = tricks[r.below(tricks.len())];
            let positions: Vec<usize> = s.char_indices().filter(|(_, c)| c.is_ascii_alphanumeric()).map(|(i, _)| i).collect();
            let at = positions[r.below(positions.len())];
            if r.below(2) == 0 {
                case.input = [&s[..at], t, &s[at + 1..]].concat().into_bytes();
            } else {
                case.input = [&s[..at], t, &s[at..]].concat().into_bytes();
            }
            if r.below(8) == 0 {
                case.input = [&[0xef, 0xbb, 0xbf][..], &b[..]].concat();
            }
        }
        11 => {
            case.cat = "number_forms";
            let forms = ["21.50", "2.15e1", "+21.5", "21.5E0", "0x15", "NaN", "Infinity", "-Infinity", "1e999", "-0", "9007199254740993", "1e400", "21.5.1", ".5", "1_0", "null", "\"21.5\"", "[21.5]", "true"];
            let s = String::from_utf8(b.clone()).unwrap();
            case.input = s.replacen("21.5", forms[r.below(forms.len())], 1).into_bytes();
        }
        12 => {
            case.cat = "wrong_key";
            let mut v = base.clone();
            let mut c = v["twin_cert"].take();
            c["signer"] = json!(key_id(&lw()));
            sign_value(&mut c, furcate_command::CERT_DOMAIN, &lw()).unwrap();
            v["twin_cert"] = c;
            match r.below(3) {
                0 => {
                    v["signer"] = json!(key_id(&rogue()));
                    sign_value(&mut v, COMMAND_DOMAIN, &rogue()).unwrap();
                }
                1 => {
                    v["signer"] = json!(key_id(&lw()));
                    sign_value(&mut v, COMMAND_DOMAIN, &rogue()).unwrap();
                }
                _ => {
                    let mut c = v["twin_cert"].take();
                    c["signer"] = json!(key_id(&rogue()));
                    sign_value(&mut c, furcate_command::CERT_DOMAIN, &rogue()).unwrap();
                    v["twin_cert"] = c;
                    v["signer"] = json!(key_id(&lw()));
                    sign_value(&mut v, COMMAND_DOMAIN, &lw()).unwrap();
                }
            }
            case.input = bytes(&v);
        }
        13 => {
            case.cat = "signature_malleability";
            let mut v = base.clone();
            let sig = v["signature"].as_str().unwrap().to_string();
            v["signature"] = json!(malleate(&sig));
            case.input = bytes(&v);
        }
        14 => {
            case.cat = "signature_forms";
            let mut v = base.clone();
            let sig = v["signature"].as_str().unwrap().to_string();
            v["signature"] = json!(match r.below(6) {
                0 => "0".repeat(128),
                1 => "f".repeat(128),
                2 => sig.to_uppercase(),
                3 => sig[..126].to_string(),
                4 => format!("{sig}00"),
                _ => String::new(),
            });
            case.input = bytes(&v);
        }
        15 => {
            case.cat = "delayed_past_window";
            case.now = NOW + 60_000 + r.next() % 10_000_000_000;
        }
        16 => {
            case.cat = "premature";
            let mut v = base.clone();
            let d = 6_000 + r.next() % 1_000_000_000;
            if r.below(2) == 0 {
                v["not_before_ms"] = json!(NOW + d);
            } else {
                v["issued_at_ms"] = json!(NOW + d);
            }
            case.input = resign(v, false);
        }
        17 => {
            case.cat = "ttl_too_long";
            let mut v = base.clone();
            v["expires_at_ms"] = json!(NOW + 300_000 + 1 + r.next() % 1_000_000);
            v["twin_cert"]["valid_until_ms"] = json!(NOW + 400_000_000);
            case.input = resign(v, true);
        }
        18 => {
            case.cat = "replay";
            match r.below(3) {
                0 => case.prior = Some(base_bytes.to_vec()),
                1 => case.prior = Some(valid(10 + r.below(1000) as u64 + 1000)),
                _ => case.prior = Some(valid(1)),
            }
        }
        19 => {
            case.cat = "stale_certificate";
            let mut v = base.clone();
            match r.below(3) {
                0 => v["twin_cert"]["valid_until_ms"] = json!(NOW - 1 - r.next() % 100_000_000),
                1 => v["twin_cert"]["valid_from_ms"] = json!(NOW + 1 + r.next() % 100_000_000),
                _ => v["twin_cert"]["valid_until_ms"] = json!(NOW + 60_000 - 1 - r.next() % 50_000),
            }
            case.input = resign(v, true);
        }
        20 => {
            case.cat = "out_of_range";
            let mut v = base.clone();
            let vals = [json!(9.999999999999998), json!(30.000000000000004), json!(-1e300), json!(1e300), json!(1.7976931348623157e308), json!(-5), json!(9007199254740991i64), json!(26.000000000000004), json!(11.999999999999998), json!(4.9e-324), json!(1e15)];
            v["body"]["value"] = vals[r.below(vals.len())].clone();
            v["envelope"] = json!({"min": -1e6, "max": 1e6, "max_rate_per_s": 1000});
            if r.below(2) == 0 {
                v["twin_cert"]["ranges"][0]["min"] = json!(-1e6);
                v["twin_cert"]["ranges"][0]["max"] = json!(1e6);
            }
            case.input = resign(v, true);
        }
        21 => {
            case.cat = "nonfinite_or_wrong_type_value";
            let mut v = base.clone();
            let vals = [json!(null), json!("NaN"), json!("Infinity"), json!("21.5"), json!([21.5]), json!({"v": 1}), json!(true)];
            v["body"]["value"] = vals[r.below(vals.len())].clone();
            case.input = resign(v, false);
        }
        22 => {
            case.cat = "policy_model_birth";
            let mut v = base.clone();
            let h = format!("{:064x}", r.next());
            match r.below(4) {
                0 => v["policy_sha256"] = json!(h),
                1 => v["model_sha256"] = json!(h),
                2 => v["birth_record_sha256"] = json!(h),
                _ => {
                    v.as_object_mut().unwrap().remove("birth_record_sha256");
                }
            }
            case.input = resign(v, false);
        }
        23 => {
            case.cat = "actuate_or_bad_mode";
            let mut v = base.clone();
            v["mode"] = json!(["actuate", "act", "approve", "ACTUATE", "Shadow", "", "shadow "][r.below(7)]);
            case.input = resign(v, false);
        }
        24 | 25 | 26 => {
            case.cat = "field_flip_resigned";
            let mut v = base.clone();
            let cands: Vec<&String> = ptrs.iter().filter(|p| *p != "/signer" && *p != "/signature").collect();
            let p = cands[r.below(cands.len())].clone();
            let in_cert = p.starts_with("/twin_cert");
            let is_str = base.pointer(&p).is_some_and(|x| x.is_string());
            let is_container = base.pointer(&p).is_some_and(|x| x.is_object() || x.is_array());
            match r.below(3) {
                0 => remove(&mut v, &p),
                1 => {
                    // a type that is never valid for the field
                    let x = if is_str || is_container {
                        [json!(null), json!(1), json!(true), json!([]), json!({})][r.below(5)].clone()
                    } else {
                        [json!(null), json!("x"), json!(true), json!([]), json!({})][r.below(5)].clone()
                    };
                    set(&mut v, &p, x);
                }
                _ => {
                    if is_str {
                        set(&mut v, &p, [json!(""), json!("a b"), json!("é"), json!("x".repeat(300))][r.below(4)].clone());
                    } else {
                        // an unknown member next to the field
                        let parent = p.rsplit_once('/').unwrap().0.to_string();
                        if let Some(Value::Object(m)) = v.pointer_mut(&parent) {
                            m.insert("extra".into(), json!(1));
                        } else {
                            v["extra"] = json!(1);
                        }
                    }
                }
            }
            case.input = resign(v, in_cert);
        }
        27 => {
            case.cat = "wrong_site_tenant_cert_tenant";
            let mut v = base.clone();
            match r.below(3) {
                0 => v["site_id"] = json!("site-other"),
                1 => v["tenant"] = json!("tenant-b"),
                _ => v["twin_cert"]["tenant"] = json!("tenant-b"),
            }
            case.input = resign(v, true);
        }
        28 => {
            case.cat = "kill_switch";
            case.kill = true;
        }
        29 => {
            case.cat = "rate";
            case.prior = Some(valid(1));
            let mut v = command_value(2);
            v["body"]["value"] = json!(25.9 - (r.below(20) as f64) / 100.0);
            v["envelope"]["max"] = json!(28);
            v["issued_at_ms"] = json!(NOW - 900 + r.below(500) as u64);
            case.input = resign(v, true);
        }
        30 => {
            case.cat = "low_fidelity";
            let mut v = base.clone();
            v["twin_cert"]["fidelity_score"] = json!(r.below(80) as f64 / 100.0);
            case.input = resign(v, true);
        }
        31 => {
            case.cat = "oversize_or_deep";
            let mut s = String::from_utf8(b.clone()).unwrap();
            match r.below(3) {
                0 => {
                    let n = 100 + r.below(400);
                    s = s.replacen("\"line-2\"", &format!("{}1{}", "[".repeat(n), "]".repeat(n)), 1);
                }
                1 => s = s.replacen("\"line-2\"", &format!("\"{}\"", "a".repeat(20_000)), 1),
                _ => s = s.replacen("\"cmd-", &format!("\"{}", "9".repeat(10_000)), 1),
            }
            case.input = s.into_bytes();
        }
        32 => {
            case.cat = "unknown_kind_or_format";
            let mut v = base.clone();
            match r.below(4) {
                0 => v["kind"] = json!(["trajectory", "model_update", "calibration_update", "mode", "Setpoint"][r.below(5)]),
                1 => v["format"] = json!("physical-batch"),
                2 => v["v"] = json!(2),
                _ => v["v"] = json!(1.5),
            }
            case.input = resign(v, false);
        }
        _ => {
            case.cat = "command_seq";
            let mut v = base.clone();
            v["command_seq"] = [json!(0), json!(-1), json!(1.5), json!("1"), json!(18446744073709551615u64), json!(9007199254740993u64)][r.below(6)].clone();
            case.input = resign(v, false);
            if r.below(2) == 0 {
                case.prior = Some(valid(5));
                case.input = resign({ let mut v = base.clone(); v["command_seq"] = json!(r.below(6) as u64); v }, false);
            }
        }
    }
    if !case.control && case.prior.is_none() && !case.kill && case.now == NOW && case.input == base_bytes {
        // A mutation that left the bytes as they were is the control, not a mutant.
        case.control = true;
    }
    case
}

#[derive(Default)]
struct Tally {
    cases: u64,
    controls: u64,
    control_accepts: u64,
    false_accepts: u64,
    baseline_accepts: u64,
    baseline_control_accepts: u64,
    by_cat: BTreeMap<&'static str, (u64, u64)>, // (mutants, baseline accepts)
    false_accept_examples: Vec<String>,
}

fn run_range(lo: u64, hi: u64, base: &Value, base_bytes: &[u8], ptrs: &[String]) -> Tally {
    let mut t = Tally::default();
    for i in lo..hi {
        let c = gen(i, base, base_bytes, ptrs);
        let accepted = if c.kill {
            let mut g = Gate::new(policy(), KillAll, key(SITE_SEED), Chain::genesis("site-test-01", NOW));
            g.decide(&c.input, c.now).decision == Decision::Shadowed
        } else {
            let mut g: Gate<furcate_command::NoKill> = gate();
            if let Some(p) = &c.prior {
                g.decide(p, NOW);
            }
            let r = g.decide(&c.input, c.now);
            assert_ne!(r.decision, Decision::Executed);
            if i % 16 == 0 {
                assert!(furcate_command::verify_receipt(&r.bytes, &g.site_key_id()).is_ok());
            }
            r.decision == Decision::Shadowed
        };
        let base_acc = baseline_accepts(&c.input, c.now);
        t.cases += 1;
        if c.control {
            t.controls += 1;
            if accepted {
                t.control_accepts += 1;
            }
            if base_acc {
                t.baseline_control_accepts += 1;
            }
        } else {
            let e = t.by_cat.entry(c.cat).or_insert((0, 0));
            e.0 += 1;
            if base_acc {
                e.1 += 1;
                t.baseline_accepts += 1;
            }
            if accepted {
                t.false_accepts += 1;
                if t.false_accept_examples.len() < 5 {
                    t.false_accept_examples.push(format!("case {i} {}: {}", c.cat, String::from_utf8_lossy(&c.input[..c.input.len().min(300)])));
                }
            }
        }
    }
    t
}

#[test]
fn mutated_commands_get_no_false_accept() {
    let default_cases: u64 = if cfg!(debug_assertions) { 20_000 } else { 1_000_000 };
    let n: u64 = std::env::var("FAULT_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(default_cases);
    let base = parse(&valid(1));
    let base_bytes = valid(1);
    let ptrs = pointers(&base);
    let threads = 8u64;
    let started = std::time::Instant::now();
    let tallies: Vec<Tally> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|k| {
                let (base, bb, ptrs) = (&base, &base_bytes, &ptrs);
                s.spawn(move || run_range(n * k / threads, n * (k + 1) / threads, base, bb, ptrs))
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
        all.baseline_accepts += t.baseline_accepts;
        all.baseline_control_accepts += t.baseline_control_accepts;
        all.false_accept_examples.extend(t.false_accept_examples);
        for (k, (a, b)) in t.by_cat {
            let e = all.by_cat.entry(k).or_insert((0, 0));
            e.0 += a;
            e.1 += b;
        }
    }
    let mutants = all.cases - all.controls;
    println!("FAULT-INJECTION cases={} mutants={} controls={} elapsed={:?}", all.cases, mutants, all.controls, started.elapsed());
    println!("FAULT-INJECTION gate false_accepts={} control_accepts={}/{}", all.false_accepts, all.control_accepts, all.controls);
    println!("FAULT-INJECTION baseline(signature+expiry) accepts_of_mutants={} control_accepts={}", all.baseline_accepts, all.baseline_control_accepts);
    for (k, (m, b)) in &all.by_cat {
        println!("  {k:34} mutants={m:7} baseline_accepts={b}");
    }
    assert_eq!(all.cases, n);
    assert_eq!(all.false_accepts, 0, "{:?}", all.false_accept_examples);
    assert_eq!(all.control_accepts, all.controls, "a valid command was refused");
    assert!(all.baseline_accepts > 0, "the baseline should accept some of the mutants");
}
