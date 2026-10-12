//! The action cache.
//!
//! Keyed by the digest of the action (`BuildAction::digest`), it answers a
//! single question: for this exact action, what outputs were produced, and how
//! often has that been observed? Two refusals live here:
//!
//!  * A hit whose stored action digest does not equal the requested one is
//!    refused (§6.3). Each entry re-states the digest it was filed under, and a
//!    lookup checks it. The cache is an index of proofs, not of filenames — a
//!    filename can be wrong; a proof that fails to check is thrown out.
//!  * Reproducibility is never claimed from a single build (§6.6). An entry
//!    counts matching observations, and `is_reproducible` is false until there
//!    are at least two.

use crate::action::BuildAction;
use crate::digest::Digest;
use crate::refusal::Refusal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// What an action produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    /// The action digest this result belongs to. Stored, not implied by the
    /// filename, so a mislabelled entry is detectable.
    pub action: Digest,
    /// Declared output path -> content digest.
    pub outputs: BTreeMap<String, Digest>,
    /// How many independent runs produced exactly this output set.
    pub observations: u32,
}

impl ActionResult {
    /// A claim about repetition needs repetition behind it (§6.6).
    pub fn is_reproducible(&self) -> bool {
        self.observations >= 2
    }
}

/// A disk-backed action cache.
pub struct ActionCache {
    root: PathBuf,
}

impl ActionCache {
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(ActionCache { root })
    }

    fn path_for(&self, action: &Digest) -> PathBuf {
        let hex = action.to_hex();
        self.root.join(&hex[..2]).join(format!("{hex}.json"))
    }

    /// Look up a result for `action`. Returns `Ok(None)` on a clean miss, and a
    /// `CacheDigestMismatch` refusal if the stored entry is filed against a
    /// different action than the one asked for.
    pub fn get(&self, action: &Digest) -> Result<Option<ActionResult>, CacheError> {
        let path = self.path_for(action);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(CacheError::Io(e)),
        };
        let result: ActionResult =
            serde_json::from_slice(&bytes).map_err(CacheError::Decode)?;
        if result.action != *action {
            return Err(CacheError::Refused(Refusal::CacheDigestMismatch {
                requested: *action,
                stored: result.action,
            }));
        }
        Ok(Some(result))
    }

    /// Record that `action` produced `outputs`. If an identical output set is
    /// already recorded, the observation count is incremented (evidence toward
    /// reproducibility). If a *different* output set is recorded for the same
    /// action, that is a non-determinism finding: the count resets to one and
    /// the newest result stands, because the old claim is no longer supported.
    pub fn record(
        &self,
        action: &Digest,
        outputs: BTreeMap<String, Digest>,
    ) -> Result<ActionResult, CacheError> {
        let observations = match self.get(action)? {
            Some(prev) if prev.outputs == outputs => prev.observations.saturating_add(1),
            _ => 1,
        };
        let result = ActionResult {
            action: *action,
            outputs,
            observations,
        };
        let path = self.path_for(action);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&result).map_err(CacheError::Decode)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(result)
    }

    /// Convenience: look up by the action itself.
    pub fn get_action(&self, action: &BuildAction) -> Result<Option<ActionResult>, CacheError> {
        self.get(&action.digest())
    }
}

#[derive(Debug)]
pub enum CacheError {
    Refused(Refusal),
    Decode(serde_json::Error),
    Io(io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Refused(r) => write!(f, "{r}"),
            CacheError::Decode(e) => write!(f, "cache decode: {e}"),
            CacheError::Io(e) => write!(f, "cache io: {e}"),
        }
    }
}

impl From<io::Error> for CacheError {
    fn from(e: io::Error) -> Self {
        CacheError::Io(e)
    }
}

impl std::error::Error for CacheError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fcbuild-cache-{}-{:?}", std::process::id(), std::time::SystemTime::now()));
        p
    }

    fn out(name: &str, bytes: &[u8]) -> BTreeMap<String, Digest> {
        let mut m = BTreeMap::new();
        m.insert(name.to_string(), Digest::of(bytes));
        m
    }

    #[test]
    fn miss_then_hit() {
        let c = ActionCache::open(temp()).unwrap();
        let a = Digest::of(b"action-1");
        assert!(c.get(&a).unwrap().is_none());
        c.record(&a, out("bin", b"artifact")).unwrap();
        assert!(c.get(&a).unwrap().is_some());
    }

    #[test]
    fn one_build_is_not_reproducible() {
        let c = ActionCache::open(temp()).unwrap();
        let a = Digest::of(b"action-2");
        let r = c.record(&a, out("bin", b"artifact")).unwrap();
        assert_eq!(r.observations, 1);
        assert!(!r.is_reproducible(), "one observation must not read as reproducible");
    }

    #[test]
    fn two_matching_builds_are_reproducible() {
        let c = ActionCache::open(temp()).unwrap();
        let a = Digest::of(b"action-3");
        c.record(&a, out("bin", b"artifact")).unwrap();
        let r = c.record(&a, out("bin", b"artifact")).unwrap();
        assert_eq!(r.observations, 2);
        assert!(r.is_reproducible());
    }

    #[test]
    fn nondeterministic_output_resets_the_claim() {
        let c = ActionCache::open(temp()).unwrap();
        let a = Digest::of(b"action-4");
        c.record(&a, out("bin", b"first")).unwrap();
        let r = c.record(&a, out("bin", b"second")).unwrap();
        assert_eq!(r.observations, 1, "a different output is not more evidence");
        assert!(!r.is_reproducible());
    }

    #[test]
    fn mislabelled_entry_is_refused() {
        let root = temp();
        let c = ActionCache::open(&root).unwrap();
        let asked = Digest::of(b"asked");
        let other = Digest::of(b"other");
        // Write an entry under `asked`'s filename but stamped with `other`.
        let entry = ActionResult { action: other, outputs: out("bin", b"x"), observations: 1 };
        let hex = asked.to_hex();
        let dir = root.join(&hex[..2]);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{hex}.json")), serde_json::to_vec(&entry).unwrap()).unwrap();
        match c.get(&asked) {
            Err(CacheError::Refused(Refusal::CacheDigestMismatch { requested, stored })) => {
                assert_eq!(requested, asked);
                assert_eq!(stored, other);
            }
            other => panic!("expected CacheDigestMismatch, got {other:?}"),
        }
    }
}
