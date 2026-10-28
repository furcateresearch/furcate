//! Signatures for runs on this machine, from local services.
//!
//! A service that runs work for somebody else, such as Silo, returns a receipt
//! for each run. A receipt its own process vouches for is a claim; one this
//! node signs with the key it signs inference receipts with is evidence a
//! verifier can check against a key it already holds. The service sends the
//! SHA-256 of what it wants signed; this daemon signs
//!
//! ```text
//! "furcate-run-receipt-v1" 0x00 <context> 0x00 <the 32 bytes>
//! ```
//!
//! so a signature made here can never be mistaken for a cell link, a read
//! token or an inference receipt, whatever bytes a caller sends. The context
//! is one of a fixed list. Like the session ledger, the socket answers only a
//! peer running as this daemon's own user.

use furcate_identity::MessageSigner;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The domain every signature here is made under.
pub const DOMAIN: &[u8] = b"furcate-run-receipt-v1";

/// What may be signed here, by context.
pub const CONTEXTS: &[&str] = &["silo-run"];

pub fn socket_path() -> PathBuf {
    std::env::var("FURCATE_RUN_RECEIPTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| furcate_paths::runtime("run-receipts.sock"))
}

/// The bytes signed for `context` and `digest`.
pub fn message(context: &str, digest: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + context.len() + 34);
    m.extend_from_slice(DOMAIN);
    m.push(0);
    m.extend_from_slice(context.as_bytes());
    m.push(0);
    m.extend_from_slice(digest);
    m
}

/// Listen for as long as the daemon runs. Without a signer there is nothing
/// to offer, and the socket is not opened: a service then sends its receipts
/// unsigned, and says so.
pub fn spawn(signer: Option<Arc<dyn MessageSigner>>) {
    let Some(signer) = signer else {
        eprintln!("furcated: no run-receipt socket: this node has no key to sign receipts with");
        return;
    };
    let key_id = match furcate_policy::delegation::CellKey::of(signer.as_ref()) {
        Ok(k) => k.id(),
        Err(e) => {
            eprintln!("furcated: no run-receipt socket: the signer cannot say its key ({e})");
            return;
        }
    };
    let path = socket_path();
    match listen(&path) {
        Ok(listener) => {
            std::thread::Builder::new()
                .name("run-receipts".into())
                .spawn(move || serve(listener, signer.as_ref(), &key_id))
                .expect("spawning the run-receipt thread");
        }
        Err(e) => eprintln!("furcated: WARNING no run-receipt socket at {}: {e}", path.display()),
    }
}

fn listen(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

fn serve(listener: UnixListener, signer: &dyn MessageSigner, key_id: &str) {
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { continue };
        if crate::sessionledger::peer_uid(&s) != Some(me) {
            let _ = writeln!(
                s,
                "{}",
                json!({"error": "only this node's own services may ask for a signature"})
            );
            continue;
        }
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let reader = BufReader::new(match s.try_clone() {
            Ok(r) => r,
            Err(_) => continue,
        });
        for line in reader.lines().take(64) {
            let Ok(line) = line else { break };
            let reply = answer(&line, &|m| signer.sign(m).map_err(|e| e.to_string()), key_id);
            if writeln!(s, "{reply}").is_err() {
                break;
            }
        }
    }
}

/// `{"context", "digest"}` (64 hex) in, `{"key_id", "domain", "signature"}` (hex) out.
pub fn answer(line: &str, sign: &dyn Fn(&[u8]) -> Result<Vec<u8>, String>, key_id: &str) -> Value {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return json!({"error": "not JSON"});
    };
    let context = v.get("context").and_then(|x| x.as_str()).unwrap_or("");
    if !CONTEXTS.contains(&context) {
        return json!({"error": format!("context must be one of {}", CONTEXTS.join(", "))});
    }
    let digest: [u8; 32] = match v.get("digest").and_then(|x| x.as_str()).map(hex::decode) {
        Some(Ok(b)) if b.len() == 32 => b.try_into().expect("32 bytes"),
        _ => return json!({"error": "digest is 64 hex characters"}),
    };
    match sign(&message(context, &digest)) {
        Ok(sig) => {
            json!({"key_id": key_id, "domain": "furcate-run-receipt-v1", "signature": hex::encode(sig)})
        }
        Err(e) => json!({"error": format!("signing failed: {e}")}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_signed_under_the_domain_and_verifies() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let signer = furcate_identity::Ed25519Signer(Arc::new(key));
        let id = furcate_policy::delegation::CellKey::of(&signer).unwrap().id();
        let d = "ab".repeat(32);
        let r = answer(
            &format!(r#"{{"context":"silo-run","digest":"{d}"}}"#),
            &|m| signer.sign(m).map_err(|e| e.to_string()),
            &id,
        );
        let sig = r["signature"].as_str().unwrap();
        let msg = message("silo-run", &[0xab; 32]);
        furcate_policy::delegation::CellKey::parse(&id)
            .unwrap()
            .verify_hex(&msg, sig)
            .unwrap();
        assert!(msg.starts_with(b"furcate-run-receipt-v1\0silo-run\0"));
    }

    #[test]
    fn other_contexts_and_bad_digests_are_refused() {
        let never = |_: &[u8]| -> Result<Vec<u8>, String> { panic!("must not sign") };
        assert!(answer(r#"{"context":"cell-link","digest":""}"#, &never, "k")["error"].is_string());
        assert!(answer(r#"{"context":"silo-run","digest":"abcd"}"#, &never, "k")["error"].is_string());
        assert!(answer("nope", &never, "k")["error"].is_string());
    }
}
