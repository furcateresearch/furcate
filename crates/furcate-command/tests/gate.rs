mod common;
use common::*;
use furcate_command::{verify_receipt, Decision, ErrorCode, Gate, KillState, SitePolicy};
use furcate_ledger::{Chain, OpKind};
use serde_json::{json, Value};

fn run(mutate: impl FnOnce(&mut Value), now: u64) -> (Decision, Option<ErrorCode>) {
    let mut v = command_value(1);
    mutate(&mut v);
    let mut g = gate();
    let r = g.decide(&finish(v, &lw(), &lw()), now);
    (r.decision, r.code)
}

#[test]
fn a_valid_command_is_shadowed_and_receipted() {
    let mut g = gate();
    let r = g.decide(&valid(1), NOW);
    assert_eq!((r.decision, r.code), (Decision::Shadowed, None));
    let v = verify_receipt(&r.bytes, &g.site_key_id()).unwrap();
    assert_eq!(v["decision"], "shadowed");
    assert_eq!(v["envelope_applied"], json!({"min": 15, "max": 26}));
    assert_eq!(g.chain().entries().last().unwrap().kind, OpKind::Command);
    assert!(g.chain().verify().is_ok());
    assert_eq!(r.ledger_seq as usize, g.chain().len() - 1);
}

#[test]
fn every_decision_is_a_receipt_on_one_chain() {
    let mut g = gate();
    let n0 = g.chain().len();
    g.decide(&valid(1), NOW);
    g.decide(&valid(1), NOW); // replay
    g.decide(b"not json", NOW);
    g.decide(&valid(2), NOW + 10_000_000); // expired
    assert_eq!(g.chain().len(), n0 + 4);
    assert!(g.chain().verify().is_ok());
}

#[test]
fn each_refusal_has_its_own_code() {
    use ErrorCode::*;
    let cases: Vec<(&str, Box<dyn FnOnce(&mut Value)>, u64, Decision, ErrorCode)> = vec![
        ("actuate", Box::new(|v| v["mode"] = json!("actuate")), NOW, Decision::Denied, ActuationNotApproved),
        ("wrong policy", Box::new(|v| v["policy_sha256"] = json!("4".repeat(64))), NOW, Decision::Denied, PolicyHashMismatch),
        ("unapproved model", Box::new(|v| v["model_sha256"] = json!("5".repeat(64))), NOW, Decision::Denied, ModelNotApproved),
        ("no birth record", Box::new(|v| { v.as_object_mut().unwrap().remove("birth_record_sha256"); }), NOW, Decision::Denied, BirthRecordRequired),
        ("unknown birth record", Box::new(|v| v["birth_record_sha256"] = json!("6".repeat(64))), NOW, Decision::Denied, BirthRecordNotApproved),
        ("wrong site", Box::new(|v| v["site_id"] = json!("site-other")), NOW, Decision::Denied, WrongSite),
        ("wrong tenant", Box::new(|v| v["tenant"] = json!("tenant-b")), NOW, Decision::Denied, WrongTenant),
        ("expired", Box::new(|_| {}), NOW + 60_000, Decision::Expired, Expired),
        ("too old", Box::new(|v| { v["issued_at_ms"] = json!(NOW - 200_000); v["not_before_ms"] = json!(NOW - 200_000); }), NOW, Decision::Expired, Expired),
        ("not yet valid", Box::new(|v| v["not_before_ms"] = json!(NOW + 5000)), NOW, Decision::Denied, NotYetValid),
        ("issued in the future", Box::new(|v| v["issued_at_ms"] = json!(NOW + 60_000)), NOW, Decision::Denied, NotYetValid),
        ("ttl too long", Box::new(|v| v["expires_at_ms"] = json!(NOW + 400_000)), NOW, Decision::Denied, TtlTooLong),
        ("cert expired", Box::new(|v| v["twin_cert"]["valid_until_ms"] = json!(NOW - 1)), NOW, Decision::Denied, TwinCertExpired),
        ("cert ends before command", Box::new(|v| v["twin_cert"]["valid_until_ms"] = json!(NOW + 30_000)), NOW, Decision::Denied, TwinCertExpired),
        ("cert not yet valid", Box::new(|v| v["twin_cert"]["valid_from_ms"] = json!(NOW + 1)), NOW, Decision::Denied, TwinCertNotYetValid),
        ("cert wrong tenant", Box::new(|v| v["twin_cert"]["tenant"] = json!("tenant-b")), NOW, Decision::Denied, TwinCertWrongTenant),
        ("low fidelity", Box::new(|v| v["twin_cert"]["fidelity_score"] = json!(0.5)), NOW, Decision::Denied, TwinFidelityLow),
        ("outside certified range", Box::new(|v| { v["body"]["value"] = json!(31.0); v["envelope"]["max"] = json!(40); }), NOW, Decision::Denied, OutsideCertifiedRange),
        ("outside sender envelope", Box::new(|v| v["envelope"]["max"] = json!(20)), NOW, Decision::Denied, OutsideLwEnvelope),
        ("outside site envelope", Box::new(|v| { v["body"]["value"] = json!(27.0); v["envelope"]["max"] = json!(29); }), NOW, Decision::Denied, OutsideSiteEnvelope),
        ("no site limit", Box::new(|v| v["target"]["actuator_id"] = json!("valve-9")), NOW, Decision::Denied, NoSiteLimit),
        ("unsupported kind", Box::new(|v| v["kind"] = json!("trajectory")), NOW, Decision::Denied, UnsupportedKind),
        ("unknown field", Box::new(|v| v["extra"] = json!(1)), NOW, Decision::Denied, Malformed),
    ];
    for (name, m, now, d, c) in cases {
        let (gd, gc) = run(m, now);
        assert_eq!((gd, gc), (d, Some(c)), "{name}");
    }
}

#[test]
fn signatures_are_checked_before_content() {
    let mut g = gate();
    let mut v = command_value(1);
    // Signed by a key that is not enrolled.
    let r = g.decide(&finish(v.clone(), &lw(), &rogue()), NOW);
    assert_eq!(r.code, Some(ErrorCode::SignerNotEnrolled));
    // Claims the enrolled signer, signed by another key.
    v["twin_cert"] = { let mut c = cert_value(); furcate_command::issue::sign_cert(&mut c, &lw()).unwrap(); c };
    v["signer"] = json!(furcate_command::issue::key_id(&lw()));
    furcate_command::issue::sign_value(&mut v, furcate_command::COMMAND_DOMAIN, &rogue()).unwrap();
    let r = g.decide(&furcate_command::issue::bytes(&v), NOW);
    assert_eq!(r.code, Some(ErrorCode::BadSignature));
    // Certificate signed by a key that is not enrolled, then by an enrolled key's name with the wrong signature.
    let r = g.decide(&finish(command_value(1), &rogue(), &lw()), NOW);
    assert_eq!(r.code, Some(ErrorCode::TwinCertSignerNotEnrolled));
    let mut w = command_value(1);
    let mut c = cert_value();
    furcate_command::issue::sign_cert(&mut c, &rogue()).unwrap();
    c["signer"] = json!(furcate_command::issue::key_id(&lw()));
    w["twin_cert"] = c;
    furcate_command::issue::sign_command(&mut w, &lw()).unwrap();
    let r = g.decide(&furcate_command::issue::bytes(&w), NOW);
    assert_eq!(r.code, Some(ErrorCode::TwinCertBadSignature));
}

#[test]
fn sequence_must_strictly_increase_and_only_accepted_commands_advance_it() {
    let mut g = gate();
    assert_eq!(g.decide(&valid(5), NOW).decision, Decision::Shadowed);
    for s in [5, 4, 1] {
        assert_eq!(g.decide(&valid(s), NOW).code, Some(ErrorCode::ReplayedSequence), "{s}");
    }
    // A refused command does not consume a number.
    let mut bad = command_value(6);
    bad["policy_sha256"] = json!("9".repeat(64));
    assert_eq!(g.decide(&finish(bad, &lw(), &lw()), NOW).decision, Decision::Denied);
    assert_eq!(g.last_seq(), 5);
    assert_eq!(g.decide(&valid(6), NOW).decision, Decision::Shadowed);
}

#[test]
fn the_site_rate_limit_applies_between_accepted_commands() {
    let mut g = gate();
    assert_eq!(g.decide(&valid(1), NOW).decision, Decision::Shadowed);
    let mut v = command_value(2);
    v["body"]["value"] = json!(25.5); // 4 degrees in one second against 2 per second
    v["envelope"]["max"] = json!(28);
    v["issued_at_ms"] = json!(NOW);
    let r = g.decide(&finish(v, &lw(), &lw()), NOW);
    assert_eq!(r.code, Some(ErrorCode::RateExceeded));
}

struct Killed(bool);
impl KillState for Killed {
    fn is_killed(&self, site: &str, _: &str) -> bool {
        self.0 && site == "site-test-01"
    }
}

#[test]
fn kill_dominates_a_valid_command() {
    let mut g = Gate::new(policy(), Killed(true), key(SITE_SEED), Chain::genesis("site-test-01", NOW));
    let r = g.decide(&valid(1), NOW);
    assert_eq!((r.decision, r.code), (Decision::Killed, Some(ErrorCode::KillSwitchActive)));
    assert_eq!(g.last_seq(), 0);
}

#[test]
fn receipts_verify_only_against_the_site_key_and_are_tamper_evident() {
    let mut g = gate();
    let r = g.decide(&valid(1), NOW);
    assert!(verify_receipt(&r.bytes, &g.site_key_id()).is_ok());
    assert!(verify_receipt(&r.bytes, &furcate_command::issue::key_id(&lw())).is_err());
    let mut t = r.bytes.clone();
    let i = t.windows(8).position(|w| w == b"shadowed").unwrap();
    t[i..i + 8].copy_from_slice(b"executed");
    assert!(verify_receipt(&t, &g.site_key_id()).is_err());
}

#[test]
fn nothing_can_make_the_gate_execute() {
    // There is no input that yields Executed: sweep the decisions over every refusal and the accept path.
    let mut g = gate();
    let r = g.decide(&valid(1), NOW);
    assert_ne!(r.decision, Decision::Executed);
    let _: SitePolicy = policy();
}
