//! Offline checks of the action history: the site's ledger chain, a checkpoint the site quoted, and the receipts it signed.
//!
//! Nothing here talks to a site or trusts one beyond its signature. Given the chain (or just an inclusion proof), a quoted
//! checkpoint and a receipt, a third party can tell that the receipt is in the history in the place it claims, that the
//! history has not been edited, shortened or reordered since the checkpoint, and whether two presented histories fork.
//! What it cannot tell is whether the physical effect matched the command; that is what the measured response is for.

use crate::canon::parse_canonical;
use crate::receipt::{core_digest, verify_receipt, ReceiptError};
use furcate_ledger::merkle::leaf_digest;
use furcate_ledger::{Chain, ChainError, InclusionProof, MerkleTree, OpKind};

/// What a site publishes (and, with a platform quote, anchors): how many entries, the chain head after the last of them,
/// and the Merkle root over the entry hashes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuotedCheckpoint {
    pub size: u64,
    pub head: String,
    pub merkle_root: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HistoryError {
    Empty,
    /// The chain is not internally consistent: an entry was deleted, reordered or altered.
    Chain(ChainError),
    /// The chain is shorter than the checkpoint says it was.
    TooShort { have: u64, quoted: u64 },
    /// The entry the checkpoint ends at is not the quoted head: the history was rewritten or is a different one.
    HeadMismatch,
    RootMismatch,
    Receipt(ReceiptError),
    ReceiptNotInCheckpoint,
    ReceiptEntryMismatch,
    ReceiptNotBound,
    ProofInvalid,
    /// Two valid histories share a prefix and then differ.
    Fork { at: usize },
}

fn hashes(chain: &Chain, upto: usize) -> Vec<Vec<u8>> {
    chain.entries()[..upto].iter().map(|e| e.hash.to_vec()).collect()
}

/// The checkpoint a site would quote for its chain as it stands.
pub fn checkpoint_of(chain: &Chain) -> Option<QuotedCheckpoint> {
    let tree = MerkleTree::build(&hashes(chain, chain.len()))?;
    Some(QuotedCheckpoint { size: chain.len() as u64, head: hex::encode(chain.head()?), merkle_root: tree.root_hex() })
}

/// The chain is consistent and is the history the checkpoint quoted (it may have grown since).
pub fn verify_history(chain: &Chain, cp: &QuotedCheckpoint) -> Result<(), HistoryError> {
    if chain.is_empty() || cp.size == 0 {
        return Err(HistoryError::Empty);
    }
    chain.verify().map_err(HistoryError::Chain)?;
    let have = chain.len() as u64;
    if have < cp.size {
        return Err(HistoryError::TooShort { have, quoted: cp.size });
    }
    let n = cp.size as usize;
    if hex::encode(chain.entries()[n - 1].hash) != cp.head {
        return Err(HistoryError::HeadMismatch);
    }
    let tree = MerkleTree::build(&hashes(chain, n)).ok_or(HistoryError::Empty)?;
    if tree.root_hex() != cp.merkle_root {
        return Err(HistoryError::RootMismatch);
    }
    Ok(())
}

/// A receipt as received is signed by the site, sits where it says in a history that matches the checkpoint, and is the one
/// the ledger entry committed to (the entry's result carries the digest of the receipt without its ledger and signature).
pub fn verify_receipt_in_history(chain: &Chain, cp: &QuotedCheckpoint, receipt: &[u8], site_key: &str) -> Result<(), HistoryError> {
    verify_history(chain, cp)?;
    let v = verify_receipt(receipt, site_key).map_err(HistoryError::Receipt)?;
    let seq = v["ledger"]["seq"].as_u64().ok_or(HistoryError::ReceiptEntryMismatch)?;
    if seq >= cp.size {
        return Err(HistoryError::ReceiptNotInCheckpoint);
    }
    let e = &chain.entries()[seq as usize];
    if hex::encode(e.hash) != v["ledger"]["entry_hash"].as_str().unwrap_or("") {
        return Err(HistoryError::ReceiptEntryMismatch);
    }
    let decision = v["decision"].as_str().unwrap_or("");
    let code = v["error_code"].as_str().unwrap_or("ok");
    let want = format!("{decision}:{code}:{}", core_digest(&v));
    if e.kind != OpKind::Command || e.subject != v["command_id"].as_str().unwrap_or("") || e.result != want {
        return Err(HistoryError::ReceiptNotBound);
    }
    Ok(())
}

/// The proof a site hands out with a receipt so a verifier needs no chain.
pub fn prove_receipt(chain: &Chain, seq: usize) -> Option<InclusionProof> {
    MerkleTree::build(&hashes(chain, chain.len()))?.prove(seq)
}

/// With only the receipt, its proof and a checkpoint quoted for the tree the proof was made against: the receipt is signed,
/// and the entry hash it names is the leaf at its position in the tree the checkpoint commits to.
pub fn verify_receipt_with_proof(receipt: &[u8], site_key: &str, proof: &InclusionProof, cp: &QuotedCheckpoint) -> Result<(), HistoryError> {
    let v = verify_receipt(receipt, site_key).map_err(HistoryError::Receipt)?;
    let seq = v["ledger"]["seq"].as_u64().ok_or(HistoryError::ReceiptEntryMismatch)?;
    let entry_hash = hex::decode(v["ledger"]["entry_hash"].as_str().unwrap_or("")).map_err(|_| HistoryError::ReceiptEntryMismatch)?;
    if seq >= cp.size || proof.index as u64 != seq {
        return Err(HistoryError::ReceiptNotInCheckpoint);
    }
    if proof.leaf != hex::encode(leaf_digest(&entry_hash)) {
        return Err(HistoryError::ReceiptEntryMismatch);
    }
    if !MerkleTree::verify(proof, &cp.merkle_root) {
        return Err(HistoryError::ProofInvalid);
    }
    Ok(())
}

/// Two histories that are each consistent: one is a prefix of the other, or they fork at the first differing entry.
pub fn detect_fork(a: &Chain, b: &Chain) -> Result<(), HistoryError> {
    a.verify().map_err(HistoryError::Chain)?;
    b.verify().map_err(HistoryError::Chain)?;
    for (i, (x, y)) in a.entries().iter().zip(b.entries()).enumerate() {
        if x.hash != y.hash {
            return Err(HistoryError::Fork { at: i });
        }
    }
    Ok(())
}

/// Parse a canonical receipt's command id without verifying it (for listings).
pub fn receipt_command_id(receipt: &[u8]) -> Option<String> {
    parse_canonical(receipt).ok()?["command_id"].as_str().map(String::from)
}
