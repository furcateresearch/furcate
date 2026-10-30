//! The `physical-receipt` record: the site's signed account of one decision.

use crate::canon::{canonical, parse_canonical};
use crate::{sha256_hex, verify_ed25519, RECEIPT_DOMAIN};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// The whole command was written through an [`crate::Executor`] and acknowledged. Produced only by
    /// [`crate::Gate::decide_exec`].
    Executed,
    Shadowed,
    /// A trajectory chunk was accepted in part: the prefix before the first violating step. In shadow nothing is
    /// executed; with an executor only that prefix is released and written.
    Truncated,
    Denied,
    Expired,
    Killed,
    /// The command was released and the executor reported an error, or the release could not be completed after the
    /// write-ahead entry. Writes may be partial; the `execution` member says how many were done.
    Failed,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Executed => "executed",
            Decision::Shadowed => "shadowed",
            Decision::Truncated => "truncated",
            Decision::Denied => "denied",
            Decision::Expired => "expired",
            Decision::Killed => "killed",
            Decision::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Receipt {
    pub value: Value,
    /// Canonical bytes, signature included. What goes on the wire.
    pub bytes: Vec<u8>,
    pub decision: Decision,
    pub code: Option<crate::ErrorCode>,
    pub ledger_seq: u64,
    pub ledger_entry_hash: String,
    /// The verdict on the chunk, for a trajectory command that was well formed enough to be judged.
    pub verdict: Option<crate::chunk::ChunkVerdict>,
    /// Canonical bytes of the signed advisory stop request, when one is due. See `chunk::verify_stop_request`.
    pub stop_request: Option<Vec<u8>>,
    /// Set when the site signer could not sign. The receipt is then NOT signed: `bytes` is empty and `value` carries
    /// no signature, so nothing can mistake it for a receipt. A service answers "unavailable" and the command can be
    /// sent again when nothing was released (see `decision` and `value["execution"]`).
    pub signer_error: Option<String>,
}

/// The digest the ledger entry commits to: the receipt without its `ledger` and `signature` members.
pub fn core_digest(v: &Value) -> String {
    let mut c = v.clone();
    let o = c.as_object_mut().unwrap();
    o.remove("ledger");
    o.remove("signature");
    sha256_hex(canonical(&c).unwrap().as_bytes())
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiptError {
    Malformed,
    BadSignature,
    WrongKey,
}

/// Check a receipt as received: canonical bytes, the named site key, and that key's signature.
pub fn verify_receipt(bytes: &[u8], site_key: &str) -> Result<Value, ReceiptError> {
    let v = parse_canonical(bytes).map_err(|_| ReceiptError::Malformed)?;
    let o = v.as_object().ok_or(ReceiptError::Malformed)?;
    if o.get("format").and_then(|x| x.as_str()) != Some("physical-receipt") {
        return Err(ReceiptError::Malformed);
    }
    if o.get("site_key").and_then(|x| x.as_str()) != Some(site_key) {
        return Err(ReceiptError::WrongKey);
    }
    let sig = o.get("signature").and_then(|x| x.as_str()).ok_or(ReceiptError::Malformed)?.to_string();
    let mut c = v.clone();
    c.as_object_mut().unwrap().remove("signature");
    let msg = canonical(&c).map_err(|_| ReceiptError::Malformed)?;
    if !verify_ed25519(site_key, RECEIPT_DOMAIN, msg.as_bytes(), &sig) {
        return Err(ReceiptError::BadSignature);
    }
    Ok(v)
}
