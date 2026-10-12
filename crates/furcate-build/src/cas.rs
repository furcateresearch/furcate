//! The content-addressed store.
//!
//! Inputs and outputs live here, each filed under the digest of its own bytes.
//! Two properties matter and are enforced, not assumed:
//!
//!  * *Put is idempotent.* Writing the same bytes twice yields the same name
//!    and no second copy.
//!  * *Get verifies.* A read rehashes the bytes and refuses to return them if
//!    they do not match the name they were filed under (`Refusal::CorruptObject`).
//!    The store is trusted because it checks itself, not because the disk is
//!    assumed honest — the same reason Buildbarn separates the cache from the
//!    thing that writes into it.

use crate::digest::Digest;
use crate::refusal::Refusal;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A content-addressed store rooted at a directory.
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    /// Open (creating if needed) a store under `root`. Objects are sharded by
    /// the first byte of the digest so a single directory never holds the whole
    /// store.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Cas { root })
    }

    fn path_for(&self, d: &Digest) -> PathBuf {
        let hex = d.to_hex();
        self.root.join(&hex[..2]).join(&hex)
    }

    /// File bytes under their digest and return it. Idempotent: if the object
    /// already exists it is left untouched.
    pub fn put(&self, bytes: &[u8]) -> io::Result<Digest> {
        let d = Digest::of(bytes);
        let path = self.path_for(&d);
        if path.exists() {
            return Ok(d);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Write to a temp name in the same directory, then rename, so a reader
        // never sees a half-written object under a valid name.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(d)
    }

    /// File a file's contents, returning its digest.
    pub fn put_path(&self, src: impl AsRef<Path>) -> io::Result<Digest> {
        let bytes = fs::read(src)?;
        self.put(&bytes)
    }

    /// Whether an object is present. Presence is not integrity — `get` still
    /// verifies.
    pub fn has(&self, d: &Digest) -> bool {
        self.path_for(d).exists()
    }

    /// Read an object, verifying its bytes hash to `d`. A mismatch is a refusal,
    /// not a returned buffer.
    pub fn get(&self, d: &Digest) -> Result<Vec<u8>, CasError> {
        let path = self.path_for(d);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => CasError::Missing(*d),
            _ => CasError::Io(e),
        })?;
        let actual = Digest::of(&bytes);
        if actual != *d {
            return Err(CasError::Refused(Refusal::CorruptObject {
                expected: *d,
                actual,
            }));
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
pub enum CasError {
    Missing(Digest),
    Refused(Refusal),
    Io(io::Error),
}

impl std::fmt::Display for CasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CasError::Missing(d) => write!(f, "object {d} is not in the store"),
            CasError::Refused(r) => write!(f, "{r}"),
            CasError::Io(e) => write!(f, "store io: {e}"),
        }
    }
}

impl std::error::Error for CasError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fcbuild-cas-{}", std::process::id()));
        p.push(format!("{:?}", std::time::SystemTime::now()));
        p
    }

    #[test]
    fn put_get_roundtrip() {
        let cas = Cas::open(temp()).unwrap();
        let d = cas.put(b"hello").unwrap();
        assert_eq!(cas.get(&d).unwrap(), b"hello");
    }

    #[test]
    fn put_is_idempotent() {
        let cas = Cas::open(temp()).unwrap();
        let a = cas.put(b"same").unwrap();
        let b = cas.put(b"same").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn missing_is_reported() {
        let cas = Cas::open(temp()).unwrap();
        let d = Digest::of(b"never stored");
        assert!(matches!(cas.get(&d), Err(CasError::Missing(_))));
    }

    #[test]
    fn corruption_is_caught_on_read() {
        let root = temp();
        let cas = Cas::open(&root).unwrap();
        let d = cas.put(b"honest bytes").unwrap();
        // Tamper with the stored object behind the store's back.
        let hex = d.to_hex();
        let path = root.join(&hex[..2]).join(&hex);
        fs::write(&path, b"tampered bytes").unwrap();
        match cas.get(&d) {
            Err(CasError::Refused(Refusal::CorruptObject { expected, actual })) => {
                assert_eq!(expected, d);
                assert_ne!(actual, d);
            }
            other => panic!("expected CorruptObject refusal, got {other:?}"),
        }
    }
}
