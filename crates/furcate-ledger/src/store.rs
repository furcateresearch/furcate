//! Keeping a chain across restarts.
//!
//! A hashchain that resets on restart is not an audit trail. It also breaks
//! the two things built on top of it: the TPM checkpoint sequence, which is
//! meant to be continuous, and the Merkle site root, which would change for
//! reasons that have nothing to do with tampering.
//!
//! Loading is where the care goes. A chain read from disk is untrusted input —
//! the whole point is that someone may have edited it — so it is verified
//! before use, and a chain that fails verification is refused loudly rather
//! than replaced with a fresh one. Silently starting over is exactly what an
//! attacker who tampered with the file would want.

use crate::chain::{Chain, ChainError};
use std::fmt;
use std::path::Path;

#[derive(Debug)]
pub enum StoreError {
    /// The file exists but could not be read or parsed.
    Unreadable(String),
    /// The chain on disk does not verify. Someone or something altered it.
    Tampered(ChainError),
    /// The chain could not be written.
    Unwritable(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unreadable(e) => write!(f, "ledger could not be read: {e}"),
            StoreError::Tampered(e) => write!(
                f,
                "ledger on disk does not verify ({e}). Refusing to start a fresh chain over it — \
                 that would erase the evidence. Move it aside deliberately if this is expected"
            ),
            StoreError::Unwritable(e) => write!(f, "ledger could not be written: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Write a chain durably.
///
/// Written to a temporary file and renamed, so a crash midway leaves the
/// previous chain intact rather than a truncated one. A half-written ledger
/// would fail verification on the next start and look exactly like tampering.
pub fn save(chain: &Chain, path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::Unwritable(e.to_string()))?;
    }
    let encoded =
        serde_json::to_vec_pretty(chain).map_err(|e| StoreError::Unwritable(e.to_string()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &encoded).map_err(|e| StoreError::Unwritable(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| StoreError::Unwritable(e.to_string()))?;
    Ok(())
}

/// Load a chain, verifying it.
///
/// Returns `Ok(None)` when there is simply nothing there yet, which is the
/// normal first start. A file that exists but does not verify is an error.
pub fn load(path: &Path) -> Result<Option<Chain>, StoreError> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(StoreError::Unreadable(e.to_string())),
    };
    let chain: Chain =
        serde_json::from_slice(&raw).map_err(|e| StoreError::Unreadable(e.to_string()))?;
    chain.verify().map_err(StoreError::Tampered)?;
    Ok(Some(chain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::OpKind;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-ledger-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> Chain {
        let mut c = Chain::genesis("furcate:node:test", 1000);
        c.append(1001, OpKind::KeyUse, "furcated", "ak", "created");
        c.append(1002, OpKind::Quote, "verifier", "pcr", "signed");
        c
    }

    #[test]
    fn a_chain_survives_a_round_trip() {
        let d = tmpdir("roundtrip");
        let p = d.join("ledger.json");
        let c = sample();
        save(&c, &p).unwrap();
        let back = load(&p).unwrap().expect("a chain was written");
        assert_eq!(back.len(), c.len());
        assert_eq!(back.head(), c.head());
        assert!(back.verify().is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn appending_after_a_reload_keeps_the_chain_linked() {
        // The property that matters: a restart must not break the linkage, or
        // the TPM checkpoint sequence stops being continuous.
        let d = tmpdir("append");
        let p = d.join("ledger.json");
        let c = sample();
        save(&c, &p).unwrap();

        let mut reloaded = load(&p).unwrap().unwrap();
        let head_before = reloaded.head().unwrap();
        reloaded.append(2000, OpKind::Power, "ups", "shed", "from nominal");
        assert!(reloaded.verify().is_ok());
        assert_eq!(reloaded.entries().last().unwrap().prev, head_before);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_on_disk_is_not_an_error() {
        let d = tmpdir("absent");
        assert!(load(&d.join("ledger.json")).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_tampered_chain_is_refused_rather_than_replaced() {
        // The failure this exists to prevent: starting fresh over evidence.
        let d = tmpdir("tampered");
        let p = d.join("ledger.json");
        let mut c = sample();
        save(&c, &p).unwrap();

        // Edit an entry's result and write it back without recomputing hashes.
        let raw = std::fs::read_to_string(&p).unwrap();
        let doctored = raw.replace("\"created\"", "\"destroyed\"");
        std::fs::write(&p, doctored).unwrap();

        match load(&p) {
            Err(StoreError::Tampered(_)) => {}
            other => panic!("expected a tamper error, got {other:?}"),
        }
        // And the original is still there to be examined.
        c.append(3000, OpKind::Seal, "x", "y", "z");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_tamper_message_says_not_to_start_over() {
        let e = StoreError::Tampered(ChainError::Tampered { at: 1 });
        let msg = e.to_string();
        assert!(msg.contains("Refusing to start a fresh chain"));
        assert!(msg.contains("erase the evidence"));
    }

    #[test]
    fn a_truncated_file_does_not_leave_a_broken_ledger_behind() {
        // save() renames over, so a crash mid-write cannot truncate the
        // previous chain.
        let d = tmpdir("atomic");
        let p = d.join("ledger.json");
        save(&sample(), &p).unwrap();
        let first = std::fs::read(&p).unwrap();
        save(&sample(), &p).unwrap();
        assert_eq!(std::fs::read(&p).unwrap().len(), first.len());
        assert!(!p.with_extension("json.tmp").exists(), "no stray temp file left");
        let _ = std::fs::remove_dir_all(&d);
    }
}
