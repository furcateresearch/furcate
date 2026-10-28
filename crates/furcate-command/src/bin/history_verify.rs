//! furcate-history-verify: check a site's action history offline.
//!
//!   furcate-history-verify <chain.json> <checkpoint.json> [--site-key ed25519:<hex> <receipt.json>...]
//!
//! Exit status 0 when the chain is consistent and matches the checkpoint and every receipt given is in it; 1 otherwise, with
//! the first reason printed.

use furcate_command::history::{verify_history, verify_receipt_in_history, QuotedCheckpoint};
use furcate_ledger::Chain;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: furcate-history-verify <chain.json> <checkpoint.json> [--site-key <key> <receipt.json>...]");
        std::process::exit(2);
    }
    let read = |p: &str| std::fs::read(p).unwrap_or_else(|e| { eprintln!("{p}: {e}"); std::process::exit(2) });
    let chain: Chain = serde_json::from_slice(&read(&a[0])).unwrap_or_else(|e| { eprintln!("chain: {e}"); std::process::exit(2) });
    let cp: QuotedCheckpoint = serde_json::from_slice(&read(&a[1])).unwrap_or_else(|e| { eprintln!("checkpoint: {e}"); std::process::exit(2) });
    if let Err(e) = verify_history(&chain, &cp) {
        println!("FAIL history: {e:?}");
        std::process::exit(1);
    }
    println!("ok history: {} entries, head {}", cp.size, cp.head);
    if a.len() > 2 {
        if a[2] != "--site-key" || a.len() < 4 {
            eprintln!("expected --site-key <key> after the checkpoint");
            std::process::exit(2);
        }
        for p in &a[4..] {
            match verify_receipt_in_history(&chain, &cp, &read(p), &a[3]) {
                Ok(()) => println!("ok receipt {p}"),
                Err(e) => {
                    println!("FAIL receipt {p}: {e:?}");
                    std::process::exit(1);
                }
            }
        }
    }
}
