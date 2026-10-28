//! Session entries in this machine's chain, from the session recorder.
//!
//! The recorder (`furcatectl ssh-session serve`) watches every passkey SSH
//! session on this machine and keeps each one's commands in its own chain under
//! `sessions/`. What it commits here is the session's opening (who, which
//! machine, under which order) and its close (when, how many commands, and the
//! head of the session's chain). The head is what makes a session record
//! checkable: a session file with entries cut from its end no longer reaches
//! the head committed here.
//!
//! A Unix socket rather than a route, because the caller is a local service
//! with no credential of its own to sign with. The socket answers only a peer
//! running as this daemon's own user, which can already write the chain's file
//! directly; nothing gains a power it did not have. The kind is fixed to
//! `Session` and cannot be chosen by the caller.

use super::Agent;
use furcate_ledger::OpKind;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Where the socket lives. The directory is root:furcate 2775 (tmpfiles).
pub fn socket_path() -> PathBuf {
    std::env::var("FURCATE_SESSION_LEDGER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| furcate_paths::runtime("session-ledger.sock"))
}

/// Listen for session entries for as long as the daemon runs.
pub fn spawn(agent: Arc<Mutex<Agent>>) {
    let path = socket_path();
    let commit = move |actor: &str, subject: &str, result: &str| {
        let mut a = agent.lock().expect("agent lock");
        let hash = a.chain.append(super::now_ms(), OpKind::Session, actor, subject, result);
        let seq = a.chain.len() as u64 - 1;
        a.persist_chain();
        (hex::encode(hash), seq)
    };
    match listen(&path) {
        Ok(listener) => {
            std::thread::Builder::new()
                .name("session-ledger".into())
                .spawn(move || serve(listener, &commit))
                .expect("spawning the session ledger thread");
        }
        // Said, not hidden: without this socket the recorder refuses every
        // passkey session on this machine, and this line is why.
        Err(e) => eprintln!(
            "furcated: WARNING no session ledger socket at {}: {e}; passkey SSH sessions here \
             will be refused by the recorder",
            path.display()
        ),
    }
}

fn listen(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// The uid of the process on the other end of `s`.
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd as _;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`, which is a
    // ucred of exactly that size.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

fn serve(listener: UnixListener, commit: &dyn Fn(&str, &str, &str) -> (String, u64)) {
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { continue };
        if peer_uid(&s) != Some(me) {
            let _ = writeln!(s, "{}", json!({"error": "only the session recorder may write here"}));
            continue;
        }
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let reader = BufReader::new(match s.try_clone() {
            Ok(r) => r,
            Err(_) => continue,
        });
        for line in reader.lines().take(64) {
            let Ok(line) = line else { break };
            let reply = answer(&line, commit);
            if writeln!(s, "{reply}").is_err() {
                break;
            }
        }
    }
}

/// One entry: `{"actor", "subject", "result"}` in, `{"hash", "seq"}` out.
pub fn answer(line: &str, commit: &dyn Fn(&str, &str, &str) -> (String, u64)) -> Value {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return json!({"error": "not JSON"});
    };
    let f = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (actor, subject, result) = (f("actor"), f("subject"), f("result"));
    if actor.is_empty() || subject.is_empty() || result.is_empty() {
        return json!({"error": "actor, subject and result are all required"});
    }
    if !subject.starts_with("ssh-session:") {
        return json!({"error": "this socket records SSH sessions only"});
    }
    if actor.len() > 256 || subject.len() > 128 || result.len() > 1024 {
        return json!({"error": "field too long"});
    }
    let (hash, seq) = commit(&actor, &subject, &result);
    json!({"hash": hash, "seq": seq})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_committed_and_its_hash_returned() {
        let got = std::cell::RefCell::new(Vec::new());
        let commit = |a: &str, s: &str, r: &str| {
            got.borrow_mut().push((a.to_string(), s.to_string(), r.to_string()));
            ("ab".to_string(), 7)
        };
        let r = answer(
            r#"{"actor":"passkey:c1","subject":"ssh-session:x","result":"opened"}"#,
            &commit,
        );
        assert_eq!(r, json!({"hash": "ab", "seq": 7}));
        assert_eq!(got.borrow().len(), 1);
    }

    #[test]
    fn only_session_subjects_and_complete_entries_are_taken() {
        let commit = |_: &str, _: &str, _: &str| -> (String, u64) { panic!("must not commit") };
        assert!(answer(r#"{"actor":"a","subject":"quote","result":"r"}"#, &commit)["error"].is_string());
        assert!(answer(r#"{"actor":"a","subject":"ssh-session:x"}"#, &commit)["error"].is_string());
        assert!(answer("nope", &commit)["error"].is_string());
    }

    #[test]
    fn the_socket_answers_its_own_user() {
        let p = std::env::temp_dir().join(format!("furcate-sl-{}.sock", std::process::id()));
        let l = listen(&p).unwrap();
        std::thread::spawn(move || {
            serve(l, &|_: &str, _: &str, _: &str| ("cd".to_string(), 1));
        });
        let mut c = UnixStream::connect(&p).unwrap();
        writeln!(c, r#"{{"actor":"a","subject":"ssh-session:y","result":"closed"}}"#).unwrap();
        let mut line = String::new();
        BufReader::new(&c).read_line(&mut line).unwrap();
        assert!(line.contains("\"cd\""), "{line}");
        let _ = std::fs::remove_file(&p);
    }
}
