//! The offline verifier: a clean history verifies, and deleting, reordering, altering, shortening or forking it is found.
mod common;
use common::*;
use furcate_command::history::*;
use furcate_command::receipt::ReceiptError;
use furcate_command::{Gate, NoKill, Receipt};
use furcate_ledger::{Chain, InclusionProof};
use serde_json::{json, Value};

fn run(extra_junk: &[u8]) -> (Gate<NoKill>, Vec<Receipt>) {
    let mut g = gate();
    let mut rs = vec![];
    rs.push(g.decide(&valid(1), NOW));
    rs.push(g.decide(&valid(1), NOW)); // replay, refused
    rs.push(g.decide(extra_junk, NOW)); // not a command
    rs.push(g.decide(&valid(2), NOW + 100));
    rs.push(g.decide(&valid(3), NOW + 200));
    (g, rs)
}

fn edited(chain: &Chain, f: impl FnOnce(&mut Vec<Value>)) -> Chain {
    let mut v = serde_json::to_value(chain).unwrap();
    f(v["entries"].as_array_mut().unwrap());
    serde_json::from_value(v).unwrap()
}

#[test]
fn a_clean_history_verifies_with_every_receipt() {
    let (g, rs) = run(b"junk");
    let cp = checkpoint_of(g.chain()).unwrap();
    assert!(verify_history(g.chain(), &cp).is_ok());
    for r in &rs {
        assert_eq!(verify_receipt_in_history(g.chain(), &cp, &r.bytes, &g.site_key_id()), Ok(()));
        let proof = prove_receipt(g.chain(), r.ledger_seq as usize).unwrap();
        assert_eq!(verify_receipt_with_proof(&r.bytes, &g.site_key_id(), &proof, &cp), Ok(()));
    }
    // a history that has grown since the checkpoint still verifies against it
    let mut g = g;
    g.decide(&valid(4), NOW + 300);
    assert!(verify_history(g.chain(), &cp).is_ok());
}

#[test]
fn deleting_reordering_altering_or_shortening_is_found() {
    let (g, _) = run(b"junk");
    let cp = checkpoint_of(g.chain()).unwrap();
    let c = g.chain();
    let deleted = edited(c, |e| { e.remove(2); });
    assert!(matches!(verify_history(&deleted, &cp), Err(HistoryError::Chain(_))), "{:?}", verify_history(&deleted, &cp));
    let reordered = edited(c, |e| e.swap(2, 3));
    assert!(matches!(verify_history(&reordered, &cp), Err(HistoryError::Chain(_))));
    let altered = edited(c, |e| e[3]["result"] = json!("shadowed:ok:00"));
    assert!(matches!(verify_history(&altered, &cp), Err(HistoryError::Chain(_))));
    // dropping the last entries leaves a consistent chain that is shorter than the quote
    let cut = edited(c, |e| { e.truncate(3); });
    assert!(cut.verify().is_ok());
    assert_eq!(verify_history(&cut, &cp), Err(HistoryError::TooShort { have: 3, quoted: cp.size }));
    // a quote with the wrong head or root
    let mut bad = cp.clone();
    bad.head = "0".repeat(64);
    assert_eq!(verify_history(c, &bad), Err(HistoryError::HeadMismatch));
    let mut bad = cp.clone();
    bad.merkle_root = "0".repeat(64);
    assert_eq!(verify_history(c, &bad), Err(HistoryError::RootMismatch));
}

#[test]
fn a_fork_is_found_between_two_valid_histories() {
    let (g1, _) = run(b"junk");
    let cp = checkpoint_of(g1.chain()).unwrap();
    // The same five decisions, except that entry 2 is a different refusal: a history rewritten from there on.
    let (g2, _) = run(b"different junk");
    assert!(g2.chain().verify().is_ok());
    assert_eq!(detect_fork(g1.chain(), g2.chain()), Err(HistoryError::Fork { at: 3 }), "entry 3 is the first that differs: the junk command has the same id, its receipt digest differs");
    // the rewritten history does not match what was quoted
    assert_eq!(verify_history(g2.chain(), &cp), Err(HistoryError::HeadMismatch));
    // a prefix is not a fork
    let prefix = edited(g1.chain(), |e| { e.truncate(4); });
    assert_eq!(detect_fork(g1.chain(), &prefix), Ok(()));
}

#[test]
fn a_receipt_that_is_not_what_the_ledger_committed_is_refused() {
    let (g, rs) = run(b"junk");
    let cp = checkpoint_of(g.chain()).unwrap();
    let key = g.site_key_id();
    // flipped decision: the signature no longer verifies
    let mut t = rs[0].bytes.clone();
    let i = t.windows(8).position(|w| w == b"shadowed").unwrap();
    t[i..i + 8].copy_from_slice(b"executed");
    assert_eq!(verify_receipt_in_history(g.chain(), &cp, &t, &key), Err(HistoryError::Receipt(ReceiptError::BadSignature)));
    // another site's key
    assert_eq!(verify_receipt_in_history(g.chain(), &cp, &rs[0].bytes, &format!("ed25519:{}", "ab".repeat(32))), Err(HistoryError::Receipt(ReceiptError::WrongKey)));
    // a receipt for an entry past the checkpoint
    let early = checkpoint_of(&edited(g.chain(), |e| { e.truncate(3); })).unwrap();
    assert_eq!(verify_receipt_in_history(g.chain(), &early, &rs[4].bytes, &key), Err(HistoryError::ReceiptNotInCheckpoint));
    // a genuine receipt whose entry was swapped for another: the ledger says something else was committed there
    let mut other = serde_json::to_value(g.chain()).unwrap();
    let a = other["entries"][1].clone();
    other["entries"][5]["subject"] = a["subject"].clone();
    let forged: Chain = serde_json::from_value(other).unwrap();
    assert!(verify_history(&forged, &cp).is_err());
    // a proof for a different leaf
    let proof = prove_receipt(g.chain(), 3).unwrap();
    assert_eq!(verify_receipt_with_proof(&rs[4].bytes, &key, &proof, &cp), Err(HistoryError::ReceiptNotInCheckpoint));
    let wrong = InclusionProof { index: rs[4].ledger_seq as usize, ..proof.clone() };
    assert_eq!(verify_receipt_with_proof(&rs[4].bytes, &key, &wrong, &cp), Err(HistoryError::ReceiptEntryMismatch));
    let mut tampered = prove_receipt(g.chain(), rs[4].ledger_seq as usize).unwrap();
    tampered.path[0].1 = "00".repeat(32);
    assert_eq!(verify_receipt_with_proof(&rs[4].bytes, &key, &tampered, &cp), Err(HistoryError::ProofInvalid));
}
