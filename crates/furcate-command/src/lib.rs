//! The site-side gate for commands that a simulation platform proposes.
//!
//! A command is accepted only if every check passes, and every decision, refusals included, yields a signed receipt
//! that is appended to the site ledger chain. The only mode that exists is shadow: the site records what it would do
//! and does nothing. A request to actuate is refused with [`ErrorCode::ActuationNotApproved`], and there is no
//! executor other than [`ShadowExecutor`]. The wire format is in docs/physical-command.md.

pub mod canon;
pub mod command;
pub mod gate;
pub mod history;
pub mod issue;
pub mod policy;
pub mod receipt;

pub use command::{Command, ErrorCode, Mode};
pub use gate::{Gate, KillState, NoKill};
pub use policy::{SiteLimit, SitePolicy};
pub use receipt::{verify_receipt, Decision, Receipt};

pub const COMMAND_DOMAIN: &str = "lw-physical/command/v1";
pub const CERT_DOMAIN: &str = "lw-physical/twin-cert/v1";
pub const RECEIPT_DOMAIN: &str = "furcate/physical-receipt/v1";

use sha2::{Digest, Sha256};

/// SHA-256 of len(domain) || domain || len(msg) || msg, lengths as 8 bytes big-endian. What every key signs.
pub fn domain_digest(domain: &str, msg: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain.as_bytes());
    h.update((msg.len() as u64).to_be_bytes());
    h.update(msg);
    h.finalize().to_vec()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Verify an `ed25519:<hex>` key's signature over the domain digest of `msg`. Strict: small-order keys and
/// non-canonical signatures are refused.
pub fn verify_ed25519(key_id: &str, domain: &str, msg: &[u8], sig_hex: &str) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some(kh) = key_id.strip_prefix("ed25519:") else { return false };
    if kh.len() != 64 || sig_hex.len() != 128 || !is_lower_hex(kh) || !is_lower_hex(sig_hex) {
        return false;
    }
    let (Ok(kb), Ok(sb)) = (hex::decode(kh), hex::decode(sig_hex)) else { return false };
    let (Ok(kb), Ok(sb)) = (<[u8; 32]>::try_from(kb.as_slice()), <[u8; 64]>::try_from(sb.as_slice())) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&kb) else { return false };
    vk.verify_strict(&domain_digest(domain, msg), &Signature::from_bytes(&sb)).is_ok()
}

pub(crate) fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The only executor. It records nothing and moves nothing; a command that passed the gate is described, not run.
pub struct ShadowExecutor;
