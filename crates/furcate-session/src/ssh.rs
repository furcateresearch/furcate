//! Recording passkey SSH sessions: who, which machine, when, and what ran.
//!
//! A passkey login certificate carries a force-command, so sshd runs
//! `furcatectl ssh-session --order H --by C --principal U@N` instead of the
//! user's shell. That program is the [`client`] half: it asks this machine's
//! recorder to open a session, and only then starts the shell or the command
//! the person asked for. The recorder is the [`serve`] half, a small service
//! running as the `furcate` user with `CAP_NET_ADMIN` and nothing else.
//!
//! ## What is recorded, and how
//!
//! Commands, as the kernel saw them executed, not keystrokes. The recorder
//! listens to the kernel's process events (the netlink proc connector) and,
//! for every `exec`, reads the new program's argument list and attributes it to
//! a session by the process's audit session id, which `pam_loginuid` sets for
//! the whole SSH login and which every descendant inherits: a program started
//! by `sudo`, by a script, or by a daemonised child is still attributed to the
//! session that started it, and nothing in the session can change the id.
//! Where a machine has no audit session ids (the login's id is unset), the
//! session is tracked by process ancestry instead, and the session's first
//! entry says which of the two applies, so the record never claims more than
//! it did.
//!
//! What this deliberately does not capture: what was typed into a program
//! (the password at a `sudo` prompt, an editor's contents) and shell builtins,
//! which run no program. A process that exits before its argument list can be
//! read is recorded as an exec without one, so the count stays right.
//!
//! ## Where it goes
//!
//! Each session is its own chain (`sessions/<id>.json`, [`crate::Session`]),
//! and this machine's ledger gets two entries per session: the opening, with
//! the approving passkey credentials, the machine, the user, the order and the
//! certificate serial; and the close, with the command count and the head of
//! the session's chain. The head in the ledger is what makes cutting entries
//! from the end of a session file detectable.
//!
//! ## Failing closed
//!
//! A session that cannot be recorded does not start: no recorder, a
//! certificate the CA did not sign, an order that disagrees with the
//! certificate, or a ledger that will not take the opening entry, and the
//! client exits before any shell runs. If the recorder goes away during a
//! session, the client ends it.

#![cfg(target_os = "linux")]

use crate::{Action, Session};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The recorder's socket, in the abstract namespace.
pub const SOCKET_NAME: &str = "furcate-ssh-session";

/// Commands itemised per session before the rest are only counted. A build
/// run inside a session can start tens of thousands of programs, and a record
/// nobody can read is not better than a count.
pub const MAX_ITEMISED: usize = 10_000;

/// The audit session id of a process that has none.
const NO_AUDIT_SESSION: u32 = u32::MAX;

/// Where the recorder looks for things. One value so tests can point it at a
/// temporary directory.
#[derive(Clone, Debug)]
pub struct Config {
    /// The abstract socket name.
    pub socket: String,
    /// The CA public key sshd trusts.
    pub ca_pub: PathBuf,
    /// Where session chains are written.
    pub sessions: PathBuf,
    /// furcated's session ledger socket.
    pub ledger: PathBuf,
    /// The uid the client accepts as the recorder.
    pub recorder_uid: Option<u32>,
}

impl Config {
    pub fn standard() -> Self {
        let env = |k: &str| std::env::var(k).ok();
        Config {
            socket: env("FURCATE_SSH_SESSION_SOCKET").unwrap_or_else(|| SOCKET_NAME.into()),
            ca_pub: env("FURCATE_SSH_CA_PUB")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/etc/ssh/furcate_ca.pub".into()),
            sessions: furcate_paths::state("sessions"),
            ledger: env("FURCATE_SESSION_LEDGER")
                .map(PathBuf::from)
                .unwrap_or_else(|| furcate_paths::runtime("session-ledger.sock")),
            recorder_uid: env("FURCATE_SSH_RECORDER_UID")
                .and_then(|u| u.parse().ok())
                .or_else(|| uid_of("furcate")),
        }
    }
}

/// What the certificate's force-command says this session is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub order: String,
    pub by: Vec<String>,
    pub principal: String,
}

impl Claim {
    /// From `--order H --by C1,C2 --principal U@N`, the arguments the CA
    /// writes into the force-command.
    pub fn from_args(args: &[&str]) -> Result<Claim, String> {
        let mut m = BTreeMap::new();
        let mut it = args.iter();
        while let Some(k) = it.next() {
            let v = it.next().ok_or_else(|| format!("{k} needs a value"))?;
            if m.insert(*k, *v).is_some() {
                return Err(format!("{k} given twice"));
            }
        }
        let get = |k: &str| m.get(k).map(|s| s.to_string()).ok_or_else(|| format!("{k} is required"));
        let claim = Claim {
            order: get("--order")?,
            by: get("--by")?.split(',').filter(|s| !s.is_empty()).map(String::from).collect(),
            principal: get("--principal")?,
        };
        if m.len() != 3 {
            return Err("only --order, --by and --principal are understood".into());
        }
        if claim.order.len() != 64 || !claim.order.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("--order is the 64-hex order hash".into());
        }
        if claim.by.is_empty()
            || !claim
                .by
                .iter()
                .all(|c| c.len() <= 512 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err("--by is the approving passkey credential ids".into());
        }
        let (user, node) = claim.principal.split_once('@').ok_or("--principal is <user>@<node>")?;
        if user.is_empty() || node.is_empty() {
            return Err("--principal is <user>@<node>".into());
        }
        Ok(claim)
    }

    /// From the certificate's force-command, which is `<program> ssh-session
    /// <arguments>`.
    pub fn from_force_command(fc: &str) -> Result<Claim, String> {
        let words: Vec<&str> = fc.split_whitespace().collect();
        let at = words
            .iter()
            .position(|w| *w == "ssh-session")
            .ok_or("the certificate's force-command is not the session recorder")?;
        Claim::from_args(&words[at + 1..])
    }

    pub fn user(&self) -> &str {
        self.principal.split_once('@').map(|(u, _)| u).unwrap_or("")
    }
}

/// How a session's commands are attributed to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tracking {
    /// By the audit session id every process of the login inherits.
    Audit(u32),
    /// By ancestry from the client process, where there is no audit id.
    Tree(i32),
}

impl Tracking {
    fn describe(&self) -> String {
        match self {
            Tracking::Audit(s) => format!("audit-session {s}"),
            Tracking::Tree(p) => format!("process-tree {p}"),
        }
    }
}

/// Check an opening request. Returns the certificate as read.
pub fn check_open(
    claim: &Claim,
    cert_line: &str,
    ca_line: &str,
    peer_user: &str,
    now_s: u64,
) -> Result<furcate_authn::sshcert::Certificate, String> {
    let cert = furcate_authn::sshcert::verify(cert_line, ca_line).map_err(|e| e.to_string())?;
    if now_s < cert.valid_after || now_s >= cert.valid_before {
        return Err("the certificate is not valid now".into());
    }
    let fc = cert
        .force_command
        .as_deref()
        .ok_or("the certificate has no force-command, so it is not a passkey login")?;
    let signed = Claim::from_force_command(fc)?;
    if &signed != claim {
        return Err("the session's arguments are not the ones the certificate carries".into());
    }
    if cert.principals != [claim.principal.clone()] {
        return Err("the certificate's principal is not the session's".into());
    }
    if claim.user() != peer_user {
        return Err(format!(
            "the certificate is for {}, and this session runs as {peer_user}",
            claim.user()
        ));
    }
    Ok(cert)
}

// ---------------------------------------------------------------------------
// The recorder

struct Live {
    session: Session,
    tracking: Tracking,
    path: PathBuf,
    itemised: usize,
    further: u64,
    last_save: Instant,
}

impl Live {
    fn record(&mut self, action: Action) {
        if self.itemised >= MAX_ITEMISED {
            self.further += 1;
            return;
        }
        self.itemised += 1;
        let _ = self.session.record(now_ms(), action);
        if self.last_save.elapsed() >= Duration::from_secs(1) {
            self.save();
        }
    }

    fn save(&mut self) {
        if let Err(e) = crate::save(&self.session, &self.path) {
            eprintln!("ssh-session: WARNING session {} not saved: {e}", self.session.id());
        }
        self.last_save = Instant::now();
    }
}

type Registry = Arc<Mutex<BTreeMap<String, Live>>>;

/// Run the recorder until it fails. Needs `CAP_NET_ADMIN` for the kernel's
/// process events; without them it refuses to start rather than run blind.
pub fn serve(cfg: Config) -> Result<(), String> {
    let events = ProcEvents::open().map_err(|e| {
        format!("cannot listen to the kernel's process events ({e}); the recorder needs CAP_NET_ADMIN")
    })?;
    let addr = SocketAddr::from_abstract_name(cfg.socket.as_bytes()).map_err(|e| e.to_string())?;
    let listener = UnixListener::bind_addr(&addr).map_err(|e| format!("binding @{}: {e}", cfg.socket))?;
    let live: Registry = Arc::default();
    {
        let live = Arc::clone(&live);
        std::thread::Builder::new()
            .name("exec-events".into())
            .spawn(move || watch(events, &live))
            .map_err(|e| e.to_string())?;
    }
    eprintln!("ssh-session: recording on @{}", cfg.socket);
    for conn in listener.incoming() {
        let Ok(s) = conn else { continue };
        let (live, cfg) = (Arc::clone(&live), cfg.clone());
        let _ = std::thread::Builder::new()
            .name("ssh-session".into())
            .spawn(move || connection(s, &cfg, &live));
    }
    Ok(())
}

fn connection(s: UnixStream, cfg: &Config, live: &Registry) {
    let Some(peer) = peer_cred(&s) else { return };
    let Ok(read_half) = s.try_clone() else { return };
    let mut w = s;
    let mut lines = BufReader::new(read_half).lines();
    let _ = w.set_read_timeout(Some(Duration::from_secs(10)));
    let first = match lines.next() {
        Some(Ok(l)) => l,
        _ => return,
    };
    let opened = open(&first, peer, cfg, live);
    let id = match opened {
        Ok(id) => {
            let _ = writeln!(w, "{}", json!({"ok": true, "session": id}));
            id
        }
        Err(why) => {
            let _ = writeln!(w, "{}", json!({"ok": false, "error": why}));
            return;
        }
    };
    // The session lasts as long as this connection. No timeout from here:
    // a session may sit idle for hours.
    let _ = w.set_read_timeout(None);
    let mut status: Option<i64> = None;
    for line in lines {
        let Ok(line) = line else { break };
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if let Some(c) = v.get("close") {
                status = Some(c.get("status").and_then(|x| x.as_i64()).unwrap_or(-1));
                break;
            }
        }
    }
    let reply = close(&id, status, cfg, live);
    let _ = writeln!(w, "{reply}");
}

fn open(line: &str, peer: libc::ucred, cfg: &Config, live: &Registry) -> Result<String, String> {
    let v: Value = serde_json::from_str(line).map_err(|_| "not JSON".to_string())?;
    // `open`: an SSH login, proved by the certificate it logged in with.
    // `web`: a browser terminal, whose passkey approval the terminal (root,
    // furcate-console web) checked with the site's order desk before starting
    // this; only root may say so.
    let (o, via) = match (v.get("open"), v.get("web")) {
        (Some(o), None) => (o, "ssh"),
        (None, Some(o)) => {
            if peer.uid != 0 {
                return Err("only the browser terminal, as root, opens web sessions".into());
            }
            (o, "browser")
        }
        _ => return Err("expected an open or a web request".into()),
    };
    let s = |k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let args: Vec<String> = o
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let claim = Claim::from_args(&arg_refs)?;
    let (serial, key) = if via == "ssh" {
        let ca_line = std::fs::read_to_string(&cfg.ca_pub)
            .map_err(|e| format!("this machine trusts no site CA ({}: {e})", cfg.ca_pub.display()))?;
        let peer_user = user_name(peer.uid).ok_or("the session's user has no name")?;
        let cert = check_open(&claim, &s("cert"), ca_line.trim(), &peer_user, now_ms() / 1000)?;
        (cert.serial.to_string(), cert.key_sha256)
    } else {
        if uid_of(claim.user()).is_none() {
            return Err(format!("there is no user {} on this machine", claim.user()));
        }
        ("none".to_string(), "none".to_string())
    };

    let sid = read_audit_session(peer.pid);
    let tracking = match sid {
        Some(sid) => Tracking::Audit(sid),
        None => Tracking::Tree(peer.pid),
    };
    let at = now_ms();
    let id = format!("{via}-{}-{at}-{}", if via == "ssh" { serial.as_str() } else { "term" }, peer.pid);
    let command = s("command");
    let what = if command.is_empty() { "a shell".to_string() } else { crate::redact(&command) };
    let actor = format!("passkey:{}", claim.by.join(","));
    let opening = format!(
        "opened via={via} user={} machine={} order={} serial={serial} key={key} tracking={} running {}",
        claim.user(),
        claim.principal.split_once('@').map(|(_, n)| n).unwrap_or(""),
        claim.order,
        tracking.describe(),
        what
    );
    let opening: String = opening.chars().take(1000).collect();

    // The ledger first: a session the machine's chain does not know about
    // does not start.
    commit(&cfg.ledger, &actor, &format!("ssh-session:{id}"), &opening)
        .map_err(|e| format!("the ledger refused the session: {e}"))?;

    let authority = format!("order {} via {via} cert {serial} key {key}", claim.order);
    let mut session = Session::open(&id, &actor, authority, at);
    let _ = session.record(at, Action::new(format!("login {}", claim.principal), opening));
    let path = cfg.sessions.join(format!("{id}.json"));
    crate::save(&session, &path).map_err(|e| format!("the session record cannot be written: {e}"))?;
    live.lock().expect("sessions lock").insert(
        id.clone(),
        Live { session, tracking, path, itemised: 0, further: 0, last_save: Instant::now() },
    );
    Ok(id)
}

fn close(id: &str, status: Option<i64>, cfg: &Config, live: &Registry) -> Value {
    let Some(mut l) = live.lock().expect("sessions lock").remove(id) else {
        return json!({"error": "no such session"});
    };
    let at = now_ms();
    let ending = match status {
        Some(s) => format!("ended, status {s}"),
        None => "ended without a close: the connection was lost".to_string(),
    };
    if l.further > 0 {
        let _ = l.session.record(at, Action::new("further commands not itemised", l.further.to_string()));
    }
    let _ = l.session.record(at, Action::new("logout", ending.clone()));
    let recording = l.session.close(at);
    if let Err(e) = crate::save_recording(&recording, &l.path) {
        eprintln!("ssh-session: WARNING session {id} not saved at close: {e}");
    }
    let anchor = recording.head().map(hex::encode).unwrap_or_default();
    let result = format!(
        "closed: {ending}; commands={} anchor={anchor}",
        l.itemised as u64 + l.further
    );
    match commit(&cfg.ledger, recording.actor.as_str(), &format!("ssh-session:{id}"), &result) {
        Ok(h) => json!({"ok": true, "anchor": anchor, "ledger": h}),
        Err(e) => {
            eprintln!("ssh-session: WARNING the close of {id} is not in the ledger: {e}");
            json!({"ok": false, "error": e})
        }
    }
}

/// Attribute one exec to the sessions it belongs to.
fn on_exec(pid: i32, live: &Registry) {
    let mut sessions = live.lock().expect("sessions lock");
    if sessions.is_empty() {
        return;
    }
    let sid = read_audit_session(pid);
    let ancestors = if sessions.values().any(|l| matches!(l.tracking, Tracking::Tree(_))) {
        ancestry(pid)
    } else {
        Vec::new()
    };
    let mine: Vec<String> = sessions
        .iter()
        .filter(|(_, l)| match l.tracking {
            Tracking::Audit(s) => sid == Some(s),
            Tracking::Tree(root) => ancestors.contains(&root),
        })
        .map(|(id, _)| id.clone())
        .collect();
    if mine.is_empty() {
        return;
    }
    let cmd = read_cmdline(pid).unwrap_or_else(|| "(exited before it could be read)".into());
    let uid = std::fs::metadata(format!("/proc/{pid}"))
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m).to_string())
        .unwrap_or_else(|_| "?".into());
    for id in mine {
        if let Some(l) = sessions.get_mut(&id) {
            l.record(Action::new(cmd.clone(), format!("exec uid={uid}")).on(format!("pid {pid}")));
        }
    }
}

fn watch(mut events: ProcEvents, live: &Registry) {
    loop {
        match events.next() {
            Ok(Some(pid)) => on_exec(pid, live),
            Ok(None) => {}
            Err(Lost) => {
                let mut s = live.lock().expect("sessions lock");
                for l in s.values_mut() {
                    l.record(Action::new(
                        "(kernel dropped process events)",
                        "commands may be missing from this point",
                    ));
                }
            }
        }
    }
}

/// Send one entry to furcated's session ledger socket.
pub fn commit(sock: &Path, actor: &str, subject: &str, result: &str) -> Result<String, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    writeln!(s, "{}", json!({"actor": actor, "subject": subject, "result": result}))
        .map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|_| "no answer".to_string())?;
    match v.get("hash").and_then(|h| h.as_str()) {
        Some(h) => Ok(h.to_string()),
        None => Err(v.get("error").and_then(|e| e.as_str()).unwrap_or("refused").to_string()),
    }
}

// ---------------------------------------------------------------------------
// The client: the certificate's force-command

/// Open the session, run what the person asked for, close it. Returns the
/// exit status for the process. Nothing runs unless the recorder accepted.
pub fn client(args: &[&str], cfg: &Config) -> i32 {
    match client_inner(args, cfg) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("furcate: this session cannot be recorded, so it does not start: {why}");
            1
        }
    }
}

fn client_inner(args: &[&str], cfg: &Config) -> Result<i32, String> {
    use std::os::unix::process::CommandExt as _;
    // Checked here as well as by the recorder, so a malformed force-command
    // is reported as such rather than as a refusal.
    Claim::from_args(args)?;
    let auth_file = std::env::var("SSH_USER_AUTH")
        .map_err(|_| "sshd did not expose the login (ExposeAuthInfo is off)".to_string())?;
    let auth = std::fs::read_to_string(&auth_file).map_err(|e| format!("{auth_file}: {e}"))?;
    let cert = furcate_authn::sshcert::from_user_auth(&auth).map_err(|e| e.to_string())?;
    let command = std::env::var("SSH_ORIGINAL_COMMAND").ok().filter(|c| !c.trim().is_empty());

    let addr = SocketAddr::from_abstract_name(cfg.socket.as_bytes()).map_err(|e| e.to_string())?;
    let mut s = UnixStream::connect_addr(&addr).map_err(|e| format!("no recorder on this machine ({e})"))?;
    // Anyone can bind an abstract name first. The recorder is the one running
    // as the recorder's user.
    let server = peer_cred(&s).ok_or("cannot identify the recorder")?;
    if Some(server.uid) != cfg.recorder_uid && server.uid != 0 {
        return Err(format!("the socket is held by uid {}, not the recorder", server.uid));
    }
    let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
    writeln!(
        s,
        "{}",
        json!({"open": {"args": args, "cert": cert, "command": command.clone().unwrap_or_default()}})
    )
    .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| format!("the recorder did not answer: {e}"))?;
    let v: Value = serde_json::from_str(&line).map_err(|_| "the recorder did not answer".to_string())?;
    if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        return Err(v.get("error").and_then(|e| e.as_str()).unwrap_or("refused").to_string());
    }
    let _ = s.set_read_timeout(None);

    let shell = login_shell().unwrap_or_else(|| "/bin/sh".into());
    let mut cmd = std::process::Command::new(&shell);
    match &command {
        Some(c) => {
            cmd.arg("-c").arg(c);
        }
        None => {
            let base = Path::new(&shell).file_name().and_then(|b| b.to_str()).unwrap_or("sh");
            cmd.arg0(format!("-{base}"));
        }
    }
    cmd.env_remove("SSH_ORIGINAL_COMMAND");
    let mut child = cmd.spawn().map_err(|e| format!("starting {shell}: {e}"))?;
    let child_pid = child.id() as i32;

    // If the recorder goes away, the session ends.
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        loop {
            match reader.get_mut().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        eprintln!("\r\nfurcate: the session recorder stopped, so this session ends.\r");
        // SAFETY: signalling a child we started.
        unsafe {
            libc::kill(child_pid, libc::SIGHUP);
        }
        std::thread::sleep(Duration::from_secs(2));
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
        }
        std::process::exit(1);
    });

    let status = child.wait().map_err(|e| e.to_string())?;
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt as _;
        128 + status.signal().unwrap_or(0)
    });
    let _ = writeln!(s, "{}", json!({"close": {"status": code}}));
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(code)
}

/// The browser terminal's side: run as root inside the terminal's PTY by
/// `furcate-console web`, after the order desk approved the login. Opens a
/// `web` session, then runs the user's login shell as that user.
pub fn client_web(args: &[&str], cfg: &Config) -> i32 {
    match client_web_inner(args, cfg) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("furcate: this session cannot be recorded, so it does not start: {why}");
            1
        }
    }
}

struct Account {
    uid: u32,
    gid: u32,
    name: std::ffi::CString,
    home: String,
    shell: String,
}

fn account(name: &str) -> Option<Account> {
    let c = std::ffi::CString::new(name).ok()?;
    passwd_field(
        |pw, buf| {
            let mut out = std::ptr::null_mut();
            // SAFETY: buffers sized and owned by passwd_field.
            let rc = unsafe { libc::getpwnam_r(c.as_ptr(), pw, buf.as_mut_ptr(), buf.len(), &mut out) };
            if out.is_null() { -1 } else { rc }
        },
        |pw| Account {
            uid: pw.pw_uid,
            gid: pw.pw_gid,
            name: c.clone(),
            home: cstr(pw.pw_dir).unwrap_or_else(|| "/".into()),
            shell: cstr(pw.pw_shell).filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into()),
        },
    )
}

fn client_web_inner(args: &[&str], cfg: &Config) -> Result<i32, String> {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        return Err("a browser terminal session is started by root".into());
    }
    let claim = Claim::from_args(args)?;
    let acct = account(claim.user()).ok_or_else(|| format!("no user {} here", claim.user()))?;
    // A fresh audit session for this login, as pam_loginuid gives an SSH
    // login, so everything it starts is attributed to it. Where the kernel
    // has no audit support this fails and the recorder tracks the process
    // tree instead, and says so.
    let _ = std::fs::write("/proc/self/loginuid", acct.uid.to_string());

    let addr = SocketAddr::from_abstract_name(cfg.socket.as_bytes()).map_err(|e| e.to_string())?;
    let mut s = UnixStream::connect_addr(&addr).map_err(|e| format!("no recorder on this machine ({e})"))?;
    let server = peer_cred(&s).ok_or("cannot identify the recorder")?;
    if Some(server.uid) != cfg.recorder_uid && server.uid != 0 {
        return Err(format!("the socket is held by uid {}, not the recorder", server.uid));
    }
    let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
    writeln!(s, "{}", json!({"web": {"args": args}})).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| format!("the recorder did not answer: {e}"))?;
    let v: Value = serde_json::from_str(&line).map_err(|_| "the recorder did not answer".to_string())?;
    if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        return Err(v.get("error").and_then(|e| e.as_str()).unwrap_or("refused").to_string());
    }
    let _ = s.set_read_timeout(None);

    let base = Path::new(&acct.shell).file_name().and_then(|b| b.to_str()).unwrap_or("sh").to_string();
    let mut cmd = std::process::Command::new(&acct.shell);
    cmd.arg0(format!("-{base}"))
        .current_dir(&acct.home)
        .env_clear()
        .env("HOME", &acct.home)
        .env("USER", claim.user())
        .env("LOGNAME", claim.user())
        .env("SHELL", &acct.shell)
        .env("TERM", std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()))
        .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    let (uid, gid, name) = (acct.uid, acct.gid, acct.name.clone());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::initgroups(name.as_ptr(), gid) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| format!("starting {}: {e}", acct.shell))?;
    let child_pid = child.id() as i32;
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        loop {
            match reader.get_mut().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        eprintln!("\r\nfurcate: the session recorder stopped, so this session ends.\r");
        // SAFETY: signalling a child we started.
        unsafe {
            libc::kill(child_pid, libc::SIGHUP);
        }
        std::thread::sleep(Duration::from_secs(2));
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
        }
        std::process::exit(1);
    });
    let status = child.wait().map_err(|e| e.to_string())?;
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt as _;
        128 + status.signal().unwrap_or(0)
    });
    let _ = writeln!(s, "{}", json!({"close": {"status": code}}));
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(code)
}

// ---------------------------------------------------------------------------
// The kernel's process events

struct ProcEvents {
    fd: i32,
}

struct Lost;

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDR: usize = 16;
const CN_MSG: usize = 20;

impl ProcEvents {
    fn open() -> std::io::Result<ProcEvents> {
        // SAFETY: plain socket calls on a descriptor this function owns; the
        // structures passed are sized as the kernel expects.
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let ev = ProcEvents { fd };
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            sa.nl_groups = CN_IDX_PROC;
            if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // A deep buffer: an exec storm should not cost records.
            let size: i32 = 8 << 20;
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &size as *const _ as *const libc::c_void, 4);
            let mut msg = Vec::with_capacity(NLMSG_HDR + CN_MSG + 4);
            msg.extend_from_slice(&((NLMSG_HDR + CN_MSG + 4) as u32).to_ne_bytes());
            msg.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
            msg.extend_from_slice(&0u16.to_ne_bytes());
            msg.extend_from_slice(&0u32.to_ne_bytes());
            msg.extend_from_slice(&(libc::getpid() as u32).to_ne_bytes());
            msg.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
            msg.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
            msg.extend_from_slice(&0u32.to_ne_bytes());
            msg.extend_from_slice(&0u32.to_ne_bytes());
            msg.extend_from_slice(&4u16.to_ne_bytes());
            msg.extend_from_slice(&0u16.to_ne_bytes());
            msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
            if libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(ev)
        }
    }

    /// The pid of the next exec, `None` for any other event.
    fn next(&mut self) -> Result<Option<i32>, Lost> {
        let mut buf = [0u8; 4096];
        // SAFETY: recv writes at most buf.len() bytes into buf.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOBUFS) {
                return Err(Lost);
            }
            return Ok(None);
        }
        Ok(parse_exec(&buf[..n as usize]))
    }
}

impl Drop for ProcEvents {
    fn drop(&mut self) {
        // SAFETY: closing the descriptor this value owns.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// The exec'd process from one proc connector message, if it is an exec.
fn parse_exec(m: &[u8]) -> Option<i32> {
    let u32_at = |o: usize| m.get(o..o + 4).map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
    let ev = NLMSG_HDR + CN_MSG;
    if u32_at(ev)? != PROC_EVENT_EXEC {
        return None;
    }
    // what(4) cpu(4) timestamp(8), then process_pid and process_tgid.
    let tgid = u32_at(ev + 20)? as i32;
    (tgid > 0).then_some(tgid)
}

// ---------------------------------------------------------------------------
// /proc and the user database

fn read_audit_session(pid: i32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/sessionid")).ok()?;
    let id: u32 = s.trim().parse().ok()?;
    (id != NO_AUDIT_SESSION).then_some(id)
}

fn read_cmdline(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let words: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|w| !w.is_empty())
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect();
    let mut s = words.join(" ");
    if s.len() > 400 {
        let mut cut = 400;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str(" ...");
    }
    Some(s)
}

/// Parent chain of `pid`, nearest first, at most 64 deep.
fn ancestry(pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let mut p = pid;
    for _ in 0..64 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{p}/stat")) else { break };
        // The command name is in parentheses and may itself contain them.
        let Some(rest) = stat.rfind(')').map(|i| &stat[i + 1..]) else { break };
        let Some(ppid) = rest.split_whitespace().nth(1).and_then(|x| x.parse::<i32>().ok()) else { break };
        if ppid <= 1 {
            break;
        }
        out.push(ppid);
        p = ppid;
    }
    out
}

fn peer_cred(s: &UnixStream) -> Option<libc::ucred> {
    use std::os::fd::AsRawFd as _;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into a ucred of that size.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred)
}

fn passwd_field<T>(f: impl FnOnce(*mut libc::passwd, &mut [libc::c_char]) -> i32, read: impl FnOnce(&libc::passwd) -> T) -> Option<T> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let rc = f(&mut pw, &mut buf);
    if rc != 0 || pw.pw_name.is_null() {
        return None;
    }
    Some(read(&pw))
}

fn cstr(p: *const libc::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-null pointer from getpw*_r into the caller's buffer.
    Some(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

fn user_name(uid: u32) -> Option<String> {
    passwd_field(
        |pw, buf| {
            let mut out = std::ptr::null_mut();
            // SAFETY: buffers sized and owned by passwd_field.
            let rc = unsafe { libc::getpwuid_r(uid, pw, buf.as_mut_ptr(), buf.len(), &mut out) };
            if out.is_null() { -1 } else { rc }
        },
        |pw| cstr(pw.pw_name),
    )
    .flatten()
}

fn uid_of(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    passwd_field(
        |pw, buf| {
            let mut out = std::ptr::null_mut();
            // SAFETY: buffers sized and owned by passwd_field.
            let rc = unsafe { libc::getpwnam_r(c.as_ptr(), pw, buf.as_mut_ptr(), buf.len(), &mut out) };
            if out.is_null() { -1 } else { rc }
        },
        |pw| pw.pw_uid,
    )
}

fn login_shell() -> Option<String> {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    passwd_field(
        |pw, buf| {
            let mut out = std::ptr::null_mut();
            // SAFETY: buffers sized and owned by passwd_field.
            let rc = unsafe { libc::getpwuid_r(uid, pw, buf.as_mut_ptr(), buf.len(), &mut out) };
            if out.is_null() { -1 } else { rc }
        },
        |pw| cstr(pw.pw_shell),
    )
    .flatten()
    .filter(|s| !s.is_empty())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDER: &str = "ab00000000000000000000000000000000000000000000000000000000000001";

    fn fc() -> String {
        format!("/usr/bin/furcatectl ssh-session --order {ORDER} --by c1,c2 --principal ops@node-a")
    }

    fn claim() -> Claim {
        Claim::from_force_command(&fc()).unwrap()
    }

    fn ca() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[9; 32])
    }

    fn cert(force: Option<&str>, principal: &str) -> String {
        let q = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
        let q = q.verifying_key().to_sec1_point(false);
        furcate_authn::sshcert::sign_for_test(&ca(), q.as_bytes(), "ssh:", 3, "furcate:passkey:x:3", &[principal], (100, 10_000), force)
    }

    #[test]
    fn the_claim_reads_the_arguments_the_ca_writes() {
        let c = claim();
        assert_eq!(c.order, ORDER);
        assert_eq!(c.by, vec!["c1", "c2"]);
        assert_eq!(c.user(), "ops");
        assert!(Claim::from_args(&["--order", "zz", "--by", "c", "--principal", "a@b"]).is_err());
        assert!(Claim::from_args(&["--order", ORDER, "--by", "c"]).is_err());
        assert!(Claim::from_args(&["--order", ORDER, "--by", "c;rm", "--principal", "a@b"]).is_err());
    }

    #[test]
    fn a_session_opens_only_with_the_certificate_that_carries_its_arguments() {
        let ca_line = furcate_authn::sshcert::ca_line_for_test(&ca());
        let good = cert(Some(&fc()), "ops@node-a");
        assert!(check_open(&claim(), &good, &ca_line, "ops", 500).is_ok());
        // Another user's session cannot use it.
        assert!(check_open(&claim(), &good, &ca_line, "root", 500).unwrap_err().contains("runs as root"));
        // Outside its validity.
        assert!(check_open(&claim(), &good, &ca_line, "ops", 20_000).is_err());
        // A certificate without the recorder is not a passkey login.
        let plain = cert(None, "ops@node-a");
        assert!(check_open(&claim(), &plain, &ca_line, "ops", 500).is_err());
        // Arguments that disagree with what the CA signed.
        let other = fc().replace("c1,c2", "c3");
        let signed_other = cert(Some(&other), "ops@node-a");
        assert!(check_open(&claim(), &signed_other, &ca_line, "ops", 500).unwrap_err().contains("not the ones"));
        // A principal that is not the session's.
        let wide = cert(Some(&fc()), "ops");
        assert!(check_open(&claim(), &wide, &ca_line, "ops", 500).is_err());
    }

    #[test]
    fn an_exec_event_is_read_from_the_connector_message() {
        let mut m = vec![0u8; NLMSG_HDR + CN_MSG + 32];
        let ev = NLMSG_HDR + CN_MSG;
        m[ev..ev + 4].copy_from_slice(&PROC_EVENT_EXEC.to_ne_bytes());
        m[ev + 20..ev + 24].copy_from_slice(&4242u32.to_ne_bytes());
        assert_eq!(parse_exec(&m), Some(4242));
        m[ev..ev + 4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(parse_exec(&m), None);
        assert_eq!(parse_exec(&m[..10]), None);
    }

    #[test]
    fn this_process_has_a_command_line_and_ancestors() {
        let me = std::process::id() as i32;
        assert!(read_cmdline(me).is_some());
        // A test runner always has a parent other than init.
        let _ = ancestry(me);
    }

    #[test]
    fn a_session_is_opened_recorded_and_closed_into_its_chain_and_the_ledger() {
        let dir = std::env::temp_dir().join(format!("furcate-ssh-rec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A stand-in for furcated's socket that keeps what it is sent.
        let ledger = dir.join("ledger.sock");
        let got: Arc<Mutex<Vec<Value>>> = Arc::default();
        {
            let l = UnixListener::bind(&ledger).unwrap();
            let got = Arc::clone(&got);
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let mut c = c.unwrap();
                    let mut line = String::new();
                    BufReader::new(&c).read_line(&mut line).unwrap();
                    got.lock().unwrap().push(serde_json::from_str(&line).unwrap());
                    writeln!(c, r#"{{"hash":"h","seq":1}}"#).unwrap();
                }
            });
        }
        let ca_pub = dir.join("ca.pub");
        std::fs::write(&ca_pub, furcate_authn::sshcert::ca_line_for_test(&ca())).unwrap();
        let me = user_name(unsafe { libc::getuid() }).unwrap();
        let force = format!("/usr/bin/furcatectl ssh-session --order {ORDER} --by c1 --principal {me}@node-a");
        let now = now_ms() / 1000;
        let q = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
        let q = q.verifying_key().to_sec1_point(false);
        let c = furcate_authn::sshcert::sign_for_test(
            &ca(), q.as_bytes(), "ssh:", 7, "k", &[&format!("{me}@node-a")], (now - 10, now + 600), Some(&force),
        );
        let cfg = Config {
            socket: format!("furcate-test-{}", std::process::id()),
            ca_pub,
            sessions: dir.join("sessions"),
            ledger,
            recorder_uid: None,
        };
        let live: Registry = Arc::default();
        let args: Vec<String> = force.split_whitespace().skip(2).map(String::from).collect();
        let peer = libc::ucred { pid: std::process::id() as i32, uid: unsafe { libc::getuid() }, gid: 0 };
        let line = json!({"open": {"args": args, "cert": c, "command": "uptime --token s3cret"}}).to_string();
        let id = open(&line, peer, &cfg, &live).unwrap();
        // Attribute an exec of this very process to the session.
        {
            let mut s = live.lock().unwrap();
            let l = s.get_mut(&id).unwrap();
            l.tracking = Tracking::Tree(-1);
        }
        live.lock().unwrap().get_mut(&id).unwrap().record(Action::new("systemctl restart x", "exec uid=0"));
        let reply = close(&id, Some(0), &cfg, &live);
        assert_eq!(reply["ok"], true, "{reply}");
        let sent = got.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0]["actor"], "passkey:c1");
        let opening = sent[0]["result"].as_str().unwrap();
        assert!(opening.contains(&format!("user={me} machine=node-a order={ORDER} serial=7")), "{opening}");
        assert!(opening.contains("[redacted]") && !opening.contains("s3cret"), "{opening}");
        let closing = sent[1]["result"].as_str().unwrap();
        assert!(closing.contains("status 0") && closing.contains("commands=1"), "{closing}");
        // The session's chain reaches the anchor committed to the ledger.
        let anchor = closing.rsplit("anchor=").next().unwrap();
        let s = crate::resume(&dir.join("sessions").join(format!("{id}.json"))).unwrap().unwrap();
        let r = s.close(now_ms());
        let a: [u8; 32] = hex::decode(anchor).unwrap().try_into().unwrap();
        assert!(r.verify_against(&a).is_ok());
        assert!(r.entries().iter().any(|e| e.subject.contains("systemctl restart x")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_root_opens_a_browser_terminal_session() {
        let cfg = Config {
            socket: "unused".into(),
            ca_pub: "/nonexistent".into(),
            sessions: std::env::temp_dir().join("furcate-web-none"),
            ledger: "/nonexistent.sock".into(),
            recorder_uid: None,
        };
        let line = json!({"web": {"args": ["--order", ORDER, "--by", "c1", "--principal", "root@node-a"]}}).to_string();
        let peer = libc::ucred { pid: std::process::id() as i32, uid: 1000, gid: 1000 };
        let e = open(&line, peer, &cfg, &Arc::default()).unwrap_err();
        assert!(e.contains("only the browser terminal"), "{e}");
        let both = json!({"web": {}, "open": {}}).to_string();
        assert!(open(&both, peer, &cfg, &Arc::default()).is_err());
    }

    #[test]
    fn a_browser_session_from_root_is_opened_without_a_certificate() {
        let dir = std::env::temp_dir().join(format!("furcate-web-rec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger = dir.join("ledger.sock");
        let got: Arc<Mutex<Vec<Value>>> = Arc::default();
        {
            let l = UnixListener::bind(&ledger).unwrap();
            let got = Arc::clone(&got);
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let mut c = c.unwrap();
                    let mut line = String::new();
                    BufReader::new(&c).read_line(&mut line).unwrap();
                    got.lock().unwrap().push(serde_json::from_str(&line).unwrap());
                    writeln!(c, r#"{{"hash":"h","seq":1}}"#).unwrap();
                }
            });
        }
        let me = user_name(unsafe { libc::getuid() }).unwrap();
        let cfg = Config {
            socket: "unused".into(),
            ca_pub: "/nonexistent".into(),
            sessions: dir.join("sessions"),
            ledger,
            recorder_uid: None,
        };
        let principal = format!("{me}@node-a");
        let line = json!({"web": {"args": ["--order", ORDER, "--by", "c9", "--principal", principal]}}).to_string();
        let peer = libc::ucred { pid: std::process::id() as i32, uid: 0, gid: 0 };
        let id = open(&line, peer, &cfg, &Arc::default()).unwrap();
        assert!(id.starts_with("browser-term-"), "{id}");
        let sent = got.lock().unwrap().clone();
        assert!(sent[0]["result"].as_str().unwrap().contains("via=browser"), "{}", sent[0]);
        assert_eq!(sent[0]["actor"], "passkey:c9");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_session_the_ledger_will_not_take_does_not_open() {
        let dir = std::env::temp_dir().join(format!("furcate-ssh-noledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_pub = dir.join("ca.pub");
        std::fs::write(&ca_pub, furcate_authn::sshcert::ca_line_for_test(&ca())).unwrap();
        let me = user_name(unsafe { libc::getuid() }).unwrap();
        let force = format!("/usr/bin/furcatectl ssh-session --order {ORDER} --by c1 --principal {me}@node-a");
        let now = now_ms() / 1000;
        let q = p256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
        let q = q.verifying_key().to_sec1_point(false);
        let c = furcate_authn::sshcert::sign_for_test(
            &ca(), q.as_bytes(), "ssh:", 8, "k", &[&format!("{me}@node-a")], (now - 10, now + 600), Some(&force),
        );
        let cfg = Config {
            socket: "unused".into(),
            ca_pub,
            sessions: dir.join("sessions"),
            ledger: dir.join("absent.sock"),
            recorder_uid: None,
        };
        let args: Vec<String> = force.split_whitespace().skip(2).map(String::from).collect();
        let peer = libc::ucred { pid: std::process::id() as i32, uid: unsafe { libc::getuid() }, gid: 0 };
        let line = json!({"open": {"args": args, "cert": c}}).to_string();
        let e = open(&line, peer, &cfg, &Arc::default()).unwrap_err();
        assert!(e.contains("ledger refused"), "{e}");
        assert!(!dir.join("sessions").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
