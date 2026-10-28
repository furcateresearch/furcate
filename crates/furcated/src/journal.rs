//! Events a person reads: one sentence when the agent's state changes, and
//! what to do about it, with fields a reader selects on.
//!
//! Written straight to the journal over its native socket, so the sentence
//! arrives with `FURCATE_EVENT`, `FURCATE_COMPONENT`, `FURCATE_SEVERITY` and
//! `FURCATE_HINT` beside it; `furcate-os log`, the console panel and the
//! controller that receives this node's journal read those. Where there is no
//! journal (a process outside systemd, a test), the sentence goes to stderr as
//! every other line of this agent does, so it is never lost and never written
//! twice.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

/// How much attention an event needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Info,
    Notice,
    Warning,
    Error,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }

    /// syslog priority. Info is written at notice, so a unit that keeps its
    /// own chatter out of the journal (LogLevelMax=notice) keeps its events.
    fn priority(self) -> u8 {
        match self {
            Severity::Info | Severity::Notice => 5,
            Severity::Warning => 4,
            Severity::Error => 3,
        }
    }
}

/// One event.
pub struct Event<'a> {
    pub component: &'a str,
    pub event: &'a str,
    pub severity: Severity,
    /// What happened, in one sentence; written as the journal's MESSAGE.
    pub message: &'a str,
    /// What to do about it, in one sentence; empty when nothing is to be done.
    pub hint: &'a str,
}

/// The journal socket to write to, or None to write to stderr: only when
/// stderr already goes to the journal (systemd says so in JOURNAL_STREAM), so
/// an agent run by hand in a terminal still prints its sentences there.
fn socket_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("FURCATE_JOURNAL_SOCKET") {
        return Some(PathBuf::from(p));
    }
    let stream = std::env::var("JOURNAL_STREAM").ok()?;
    let (dev, ino) = stream.split_once(':')?;
    let (dev, ino): (u64, u64) = (dev.parse().ok()?, ino.parse().ok()?);
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    let fd = std::io::stderr().as_fd().try_clone_to_owned().ok()?;
    let meta = std::fs::File::from(fd).metadata().ok()?;
    (meta.dev() == dev && meta.ino() == ino).then(|| PathBuf::from("/run/systemd/journal/socket"))
}

/// The datagram the journal's native protocol takes: `KEY=value` lines, and
/// for a value holding a newline the length-prefixed binary form.
pub fn encode(ev: &Event) -> Vec<u8> {
    let mut message = ev.message.to_string();
    if !ev.hint.is_empty() {
        message.push_str(" -- ");
        message.push_str(ev.hint);
    }
    let priority = ev.severity.priority().to_string();
    let fields: [(&str, &str); 7] = [
        ("MESSAGE", &message),
        ("PRIORITY", &priority),
        ("SYSLOG_IDENTIFIER", "furcated"),
        ("FURCATE_EVENT", ev.event),
        ("FURCATE_COMPONENT", ev.component),
        ("FURCATE_SEVERITY", ev.severity.as_str()),
        ("FURCATE_HINT", ev.hint),
    ];
    let mut out = Vec::new();
    for (k, v) in fields {
        if k == "FURCATE_HINT" && v.is_empty() {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        if v.contains('\n') {
            out.push(b'\n');
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
        } else {
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
        }
        out.push(b'\n');
    }
    out
}

/// Write the event to the journal, or to stderr when there is none.
pub fn emit(ev: &Event) {
    let sent = match socket_path() {
        Some(path) => UnixDatagram::unbound().and_then(|s| s.send_to(&encode(ev), path)).is_ok(),
        None => false,
    };
    if !sent {
        if ev.hint.is_empty() {
            eprintln!("{}", ev.message);
        } else {
            eprintln!("{} -- {}", ev.message, ev.hint);
        }
    }
}

/// An error's first sentence and, when the chain ends in one, its root cause
/// ("...: Permission denied"), on one line of at most 220 characters.
pub fn summarise(err: &str) -> String {
    let flat: Vec<&str> = err.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let Some(first_line) = flat.first() else {
        return String::new();
    };
    let first = match first_line.find(". ") {
        Some(i) if first_line[i + 2..].starts_with(|c: char| c.is_ascii_uppercase()) => &first_line[..i],
        _ => first_line,
    };
    let cause = flat
        .iter()
        .rev()
        .copied()
        .find(|l| {
            l.split_once(": ")
                .map(|(_, tail)| tail.starts_with(|c: char| c.is_ascii_uppercase()))
                .unwrap_or(false)
                && !l.starts_with("Last ")
        })
        .map(|l| match l.rfind(": ") {
            // The innermost "<what>: <why>" of a chained message.
            Some(i) => {
                let head = &l[..i];
                let what = head.rsplit(": ").next().unwrap_or(head);
                format!("{what}: {}", &l[i + 2..])
            }
            None => l.to_string(),
        });
    let mut out = first.to_string();
    if let Some(c) = cause {
        if !out.contains(&c) {
            out.push_str(&format!(" ({c})"));
        }
    }
    if out.chars().count() > 220 {
        out = out.chars().take(217).collect::<String>() + "...";
    }
    out
}

/// What to do about an agent that refused to start.
pub fn refusal_hint(reason: &str) -> &'static str {
    let denied = reason.contains("Permission denied");
    if reason.contains("different node") && denied || reason.contains("vcio") && denied {
        "the agent cannot reach the board's firmware key; check the fwcrypto line of 'furcate-os status' and \
that furcate-fwcrypto-broker.socket is active; the enrolled identity is kept, so nothing needs re-enrolling \
once the key is reachable"
    } else if reason.contains("different node") {
        "the identity this node enrolled with is not available now; the message names both; restore that \
identity source, and re-enrol (furcatectl identity re-enrol) only if the board really changed"
    } else if reason.contains("Address already in use") {
        "another process holds the agent's port; find it with 'ss -ltnp'"
    } else {
        "see 'journalctl -u furcated -b' for the full error"
    }
}

/// Emit `ev` only when `state` differs from the last state written under
/// `key`: a unit restarting the agent every few seconds would otherwise write
/// the same event at every start. Kept in the runtime directory, which is
/// cleared at boot; where it cannot be kept, the event is written every time.
pub fn on_change(key: &str, state: &str, ev: &Event) {
    let marker = furcate_paths::runtime(&format!("event-{key}"));
    if std::fs::read_to_string(&marker).ok().as_deref() == Some(state) {
        return;
    }
    let _ = std::fs::write(&marker, state);
    emit(ev);
}

/// Report that the agent refused to start, with what to do about it.
pub fn refused(err: &anyhow::Error) {
    let full = format!("{err:#}");
    let reason = summarise(&full);
    on_change(
        "agent",
        &format!("refused {reason}"),
        &Event {
            component: "furcated",
            event: "agent-refused",
            severity: Severity::Error,
            message: &format!("furcated: the node agent refused to start: {reason}"),
            hint: refusal_hint(&full),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const PI: &str = "refusing to start as a different node. This node enrolled as furcate:node:abc on \
rpi-fw-crypto (first start, recorded at 1791734581); backend selection now finds nothing usable: no \
hardware root of trust opened; rpi-fw-crypto: rpi-fw-crypto get-key-status: Failed to\n\
Failed to open /dev/vcio_crypto: Permission denied\n\
Last crypto error: -1 (Unrecognized error code); the enrolled backend rpi-fw-crypto is not available: \
rpi-fw-crypto is not available: rpi-fw-crypto get-key-status: Failed to open /dev/vcio_crypto: Permission denied";

    #[test]
    fn summarises_the_refusal_seen_on_a_board() {
        let s = summarise(PI);
        assert_eq!(s, "refusing to start as a different node (Failed to open /dev/vcio_crypto: Permission denied)");
        assert!(refusal_hint(PI).contains("firmware key"));
    }

    #[test]
    fn summary_is_one_bounded_line() {
        let long = format!("{}: Permission denied", "x".repeat(400));
        let s = summarise(&long);
        assert!(!s.contains('\n'));
        assert!(s.chars().count() <= 220);
        assert_eq!(summarise(""), "");
    }

    #[test]
    fn encodes_fields_and_multiline_values() {
        let ev = Event {
            component: "furcated",
            event: "agent-up",
            severity: Severity::Info,
            message: "furcated: listening on 127.0.0.1:7616",
            hint: "",
        };
        let b = String::from_utf8(encode(&ev)).unwrap();
        assert!(b.contains("MESSAGE=furcated: listening on 127.0.0.1:7616\n"));
        assert!(b.contains("PRIORITY=5\n"));
        assert!(b.contains("FURCATE_EVENT=agent-up\n"));
        assert!(b.contains("FURCATE_COMPONENT=furcated\n"));
        assert!(b.contains("FURCATE_SEVERITY=info\n"));
        assert!(!b.contains("FURCATE_HINT"));

        let ev = Event { message: "two\nlines", hint: "do this", severity: Severity::Error, ..ev };
        let b = encode(&ev);
        let m = b"MESSAGE\n";
        let at = b.windows(m.len()).position(|w| w == m).unwrap() + m.len();
        let n = u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize;
        assert_eq!(&b[at + 8..at + 8 + n], b"two\nlines -- do this");
        assert!(String::from_utf8_lossy(&b).contains("FURCATE_HINT=do this\n"));
        assert!(String::from_utf8_lossy(&b).contains("PRIORITY=3\n"));
    }

    #[test]
    fn emits_to_the_socket_it_is_given() {
        let dir = std::env::temp_dir().join(format!("furcated-journal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket");
        let _ = std::fs::remove_file(&path);
        let rx = UnixDatagram::bind(&path).unwrap();
        // Set for this test only; no other test reads it.
        std::env::set_var("FURCATE_JOURNAL_SOCKET", &path);
        emit(&Event {
            component: "furcated",
            event: "agent-refused",
            severity: Severity::Error,
            message: "furcated: the node agent refused to start: x",
            hint: "do y",
        });
        std::env::remove_var("FURCATE_JOURNAL_SOCKET");
        let mut buf = [0u8; 4096];
        let n = rx.recv(&mut buf).unwrap();
        let got = String::from_utf8_lossy(&buf[..n]);
        assert!(got.contains("FURCATE_EVENT=agent-refused\n"), "{got}");
        assert!(got.contains("FURCATE_HINT=do y\n"), "{got}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
