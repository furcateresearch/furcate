//! `furcate-console web`: a terminal in the browser, opened with a passkey.
//!
//! For the phone or the borrowed laptop that has no SSH client and no FIDO
//! key file: a shell on this machine, in a browser, over the overlay. There is
//! no password path. A session starts only after a passkey on the site's
//! roster approves a `login` order for `<user>@<this machine>`, through the
//! same order desk, thresholds, nonces and RP IDs as every other order, and it
//! is recorded by the same recorder, into the same ledger, as a passkey SSH
//! session.
//!
//! ## The flow
//!
//! 1. `POST /start {user}`: this server makes a random ticket and asks the
//!    desk (the node holding the SSH CA) to propose a login order naming the
//!    ticket's SHA-256 (`POST /term/login`), then fetches the order's challenge.
//!    The page gets the order and the challenge, never the ticket.
//! 2. The page shows the order, checks it hashes to what the challenge signs,
//!    and asks the passkey for an assertion (WebAuthn, `userVerification:
//!    required`).
//! 3. `POST /approve`: this server hands the assertion to the desk
//!    (`POST /orders`). When the desk answers that it carried out a terminal
//!    login for this user, this machine and this ticket's digest, the page gets
//!    the ticket, good once and for two minutes.
//! 4. `GET /ws?ticket=`: the WebSocket. The ticket is spent, a PTY is opened,
//!    and `furcatectl ssh-session web` runs in it as root: it opens the
//!    recorded session and then runs the user's login shell as that user.
//!
//! ## Where it listens
//!
//! On this machine's overlay address, as plain HTTP: WebAuthn needs a secure
//! context on the passkeys' RP ID, so the browser reaches this through the
//! site's edge, which terminates TLS on a name under the RP ID and proxies to
//! here (WebSocket included). Runs as root, because it starts a login shell as
//! another user; everything the browser sends is bounded and parsed here.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PAGE: &str = include_str!("web/terminal.html");

/// How long an approved ticket may wait for its WebSocket.
const TICKET_LIFETIME_S: u64 = 120;
/// Requests waiting for a passkey at once.
const MAX_PENDING: usize = 16;
/// The largest request body read.
const MAX_BODY: usize = 64 * 1024;
/// The request line and headers together. Lines are read to a line break, so
/// without a bound a caller who never sends one is held in memory in full.
const MAX_HEAD: usize = 16 * 1024;
/// Where the session starts.
const SESSION_PROGRAM: &str = "/usr/bin/furcatectl";

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    /// The order desks that take login orders (the node holding the CA), in
    /// the order to try them.
    pub desks: Vec<String>,
    /// This machine's name, as login orders name it.
    pub node: String,
    /// How long a session's order says it may last, in seconds.
    pub ttl_s: u64,
}

impl Config {
    pub fn from_args(args: &[String]) -> Result<Config, String> {
        let mut c = Config { listen: String::new(), desks: Vec::new(), node: String::new(), ttl_s: 3600 };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut v = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
            match a.as_str() {
                "--listen" => c.listen = v()?,
                "--desk" => c.desks.extend(v()?.split(',').filter(|s| !s.is_empty()).map(String::from)),
                "--node" => c.node = v()?,
                "--ttl" => c.ttl_s = v()?.parse().map_err(|_| "--ttl is seconds".to_string())?,
                other => return Err(format!("unknown argument {other}")),
            }
        }
        if c.node.is_empty() {
            c.node = node_name().ok_or("--node is required: this machine has no FURCATE_NODE_NAME")?;
        }
        if c.listen.is_empty() || c.desks.is_empty() {
            return Err("--listen ADDR:PORT and --desk ADDR:PORT[,..] are required".into());
        }
        if !(60..=86_400).contains(&c.ttl_s) {
            return Err("--ttl is between 60 and 86400 seconds".into());
        }
        Ok(c)
    }
}

fn node_name() -> Option<String> {
    std::env::var("FURCATE_NODE_NAME").ok().filter(|s| !s.is_empty()).or_else(|| {
        std::fs::read_to_string("/etc/furcate/env").ok()?.lines().find_map(|l| {
            l.trim().strip_prefix("FURCATE_NODE_NAME=").map(|v| v.trim().trim_matches('"').to_string())
        })
    })
}

/// A login waiting for its passkey, by order hash.
struct Pending {
    ticket: [u8; 32],
    user: String,
    desk: String,
    created: u64,
}

/// A login the desk approved, by ticket digest.
struct Approved {
    user: String,
    order: String,
    approvers: Vec<String>,
    until: u64,
}

#[derive(Default)]
struct State {
    pending: BTreeMap<String, Pending>,
    approved: BTreeMap<String, Approved>,
}

/// How this server reaches a desk. A trait so the tests can stand one in.
pub trait Desk: Send + Sync {
    fn post(&self, desk: &str, path: &str, body: &Value) -> Result<Value, String>;
    fn get(&self, desk: &str, path: &str) -> Result<Value, String>;
}

pub struct HttpDesk;

impl Desk for HttpDesk {
    fn post(&self, desk: &str, path: &str, body: &Value) -> Result<Value, String> {
        furcate_api::post_signed(desk, path, body, 15_000, None).map_err(|e| format!("{desk}: {e}"))
    }
    fn get(&self, desk: &str, path: &str) -> Result<Value, String> {
        furcate_api::get_json(desk, path, 15_000).map_err(|e| format!("{desk}: {e}"))
    }
}

pub struct Server {
    cfg: Config,
    desk: Box<dyn Desk>,
    state: Mutex<State>,
}

fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn valid_user(u: &str) -> bool {
    !u.is_empty() && u.len() <= 32 && u.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !u.starts_with('-')
}

impl Server {
    pub fn new(cfg: Config, desk: Box<dyn Desk>) -> Self {
        Server { cfg, desk, state: Mutex::new(State::default()) }
    }

    /// `POST /start {user}`: propose the login and fetch its challenge.
    pub fn start(&self, body: &Value) -> (u16, Value) {
        let user = body.get("user").and_then(|u| u.as_str()).unwrap_or("").to_string();
        if !valid_user(&user) {
            return (400, json!({"error": "a user name is letters, digits, . _ -"}));
        }
        let now = now_s();
        {
            let mut st = self.state.lock().expect("state lock");
            st.pending.retain(|_, p| p.created + TICKET_LIFETIME_S > now);
            if st.pending.len() >= MAX_PENDING {
                return (503, json!({"error": "too many logins are waiting; try again shortly"}));
            }
        }
        let mut ticket = [0u8; 32];
        if getrandom::fill(&mut ticket).is_err() {
            return (500, json!({"error": "no randomness"}));
        }
        let digest = hex::encode(Sha256::digest(ticket));
        let request = json!({
            "user": user,
            "node": self.cfg.node,
            "ttl_s": self.cfg.ttl_s,
            "ticket_sha256": digest,
            "reason": "browser terminal",
        });
        let mut why = Vec::new();
        for desk in &self.cfg.desks {
            let proposed = match self.desk.post(desk, "/term/login", &request) {
                Ok(v) => v,
                Err(e) => {
                    why.push(e);
                    continue;
                }
            };
            let Some(hash) = proposed.get("order_hash").and_then(|h| h.as_str()).map(String::from) else {
                why.push(format!("{desk}: {}", proposed.get("error").unwrap_or(&proposed)));
                continue;
            };
            let challenge = match self.desk.get(desk, &format!("/challenge?order={hash}")) {
                Ok(c) if c.get("challenge").is_some() => c,
                Ok(c) => return (502, json!({"error": format!("the desk gave no challenge: {c}")})),
                Err(e) => return (502, json!({"error": e})),
            };
            self.state.lock().expect("state lock").pending.insert(
                hash.clone(),
                Pending { ticket, user, desk: desk.clone(), created: now },
            );
            return (200, challenge);
        }
        (502, json!({"error": format!("no desk took the login: {}", why.join("; "))}))
    }

    /// `POST /approve {order_hash, nonce, assertion}`: the desk decides.
    pub fn approve(&self, body: &Value) -> (u16, Value) {
        let hash = body.get("order_hash").and_then(|h| h.as_str()).unwrap_or("").to_string();
        let (desk, user, ticket) = {
            let st = self.state.lock().expect("state lock");
            match st.pending.get(&hash) {
                Some(p) => (p.desk.clone(), p.user.clone(), p.ticket),
                None => return (404, json!({"error": "no login is waiting for that order here"})),
            }
        };
        let digest = hex::encode(Sha256::digest(ticket));
        let forward = json!({
            "order_hash": hash,
            "approvals": [{"nonce": body.get("nonce"), "assertion": body.get("assertion")}],
        });
        let answer = match self.desk.post(&desk, "/orders", &forward) {
            Ok(v) => v,
            Err(e) => return (502, json!({"error": e})),
        };
        let outcome = &answer["outcome"];
        if outcome["status"] != "actuated" {
            // Not carried out (yet): a threshold above one, or a refusal. The
            // page shows the desk's own words.
            return (202, json!({"waiting": true, "desk": answer}));
        }
        let d = &outcome["detail"];
        let principal = format!("{user}@{}", self.cfg.node);
        if d["terminal"] != principal.as_str() || d["ticket_sha256"] != digest.as_str() || d["order"] != hash.as_str() {
            return (502, json!({"error": "the desk approved something other than this login", "desk": answer}));
        }
        let approvers: Vec<String> = d["approvers"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if approvers.is_empty() {
            return (502, json!({"error": "the desk's approval names no passkey"}));
        }
        let mut st = self.state.lock().expect("state lock");
        st.pending.remove(&hash);
        let now = now_s();
        st.approved.retain(|_, a| a.until > now);
        st.approved.insert(digest, Approved { user, order: hash, approvers, until: now + TICKET_LIFETIME_S });
        (200, json!({"ticket": hex::encode(ticket)}))
    }

    /// Spend a ticket: the arguments for `ssh-session web`, once.
    pub fn spend(&self, ticket_hex: &str) -> Result<Vec<String>, String> {
        let ticket = hex::decode(ticket_hex).map_err(|_| "not a ticket".to_string())?;
        let digest = hex::encode(Sha256::digest(&ticket));
        let mut st = self.state.lock().expect("state lock");
        let a = st.approved.remove(&digest).ok_or("no approved login for that ticket")?;
        if a.until <= now_s() {
            return Err("that approval has expired; open the terminal again".into());
        }
        Ok(vec![
            "ssh-session".into(),
            "web".into(),
            "--order".into(),
            a.order,
            "--by".into(),
            a.approvers.join(","),
            "--principal".into(),
            format!("{}@{}", a.user, self.cfg.node),
        ])
    }
}

// ---------------------------------------------------------------------------
// HTTP and WebSocket

struct Request {
    method: String,
    path: String,
    query: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut impl Read) -> Option<Request> {
    let mut r = BufReader::new(stream.take((MAX_HEAD + MAX_BODY) as u64));
    let mut head = 0usize;
    let mut line = String::new();
    head += r.read_line(&mut line).ok()?;
    if head > MAX_HEAD || !line.ends_with('\n') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut headers = BTreeMap::new();
    for _ in 0..64 {
        let mut h = String::new();
        head += r.read_line(&mut h).ok()?;
        if head > MAX_HEAD {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    Some(Request { method, path, query, headers, body })
}

fn respond(s: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
         X-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
}

fn json_reply(s: &mut TcpStream, (status, v): (u16, Value)) {
    respond(s, status, "application/json", v.to_string().as_bytes());
}

fn query_param(q: &str, k: &str) -> Option<String> {
    q.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).map(|(_, v)| v.to_string()))
}

/// The `Sec-WebSocket-Accept` for a key (RFC 6455).
pub fn ws_accept(key: &str) -> String {
    let mut m = key.as_bytes().to_vec();
    m.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    data_encoding::BASE64.encode(&sha1(&m))
}

/// SHA-1, for the WebSocket handshake only, which is not a security use.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// One frame from the browser: (opcode, payload). Browsers always mask.
pub fn read_frame(r: &mut impl Read) -> std::io::Result<(u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h)?;
    let op = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7f) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b)?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        len = u64::from_be_bytes(b);
    }
    if len > MAX_BODY as u64 || !masked {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame refused"));
    }
    let mut mask = [0u8; 4];
    r.read_exact(&mut mask)?;
    let mut p = vec![0u8; len as usize];
    r.read_exact(&mut p)?;
    for (i, b) in p.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok((op, p))
}

/// One unmasked frame to the browser.
pub fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | op];
    match payload.len() {
        n if n < 126 => f.push(n as u8),
        n if n <= 0xffff => {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(payload);
    f
}

// ---------------------------------------------------------------------------
// The terminal

fn open_pty() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (mut m, mut s) = (-1, -1);
    let ws = libc::winsize { ws_row: 30, ws_col: 100, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: openpty writes two descriptors; the winsize outlives the call.
    let rc = unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), &ws) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just returned by openpty and are owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) })
}

fn resize(master: i32, cols: u16, rows: u16) {
    let ws = libc::winsize { ws_row: rows.clamp(2, 500), ws_col: cols.clamp(2, 1000), ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCSWINSZ reads one winsize.
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ, &ws);
    }
}

fn terminal(mut ws: TcpStream, args: Vec<String>) {
    use std::os::unix::process::CommandExt as _;
    let (master, slave) = match open_pty() {
        Ok(p) => p,
        Err(e) => {
            let _ = ws.write_all(&frame(2, format!("no terminal: {e}\r\n").as_bytes()));
            return;
        }
    };
    let mut cmd = std::process::Command::new(SESSION_PROGRAM);
    cmd.args(&args).env_clear().env("TERM", "xterm-256color");
    let (Ok(i), Ok(o), Ok(e)) = (slave.try_clone(), slave.try_clone(), slave.try_clone()) else { return };
    cmd.stdin(i).stdout(o).stderr(e);
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = ws.write_all(&frame(2, format!("cannot start the session: {e}\r\n").as_bytes()));
            return;
        }
    };
    drop(slave);
    let pid = child.id() as i32;
    let fd = master.as_raw_fd();
    let Ok(input_fd) = master.try_clone() else { return };
    let mut input = std::fs::File::from(input_fd);
    // Two threads write frames: the shell's output and the answers to pings.
    let Ok(out) = ws.try_clone() else { return };
    let out = Arc::new(Mutex::new(out));

    // The shell's output to the browser.
    let reader = {
        let out = Arc::clone(&out);
        std::thread::spawn(move || {
            let mut m = std::fs::File::from(master);
            let mut buf = [0u8; 8192];
            loop {
                match m.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.lock().expect("ws lock").write_all(&frame(2, &buf[..n])).is_err() {
                            break;
                        }
                    }
                }
            }
            let w = out.lock().expect("ws lock");
            let _ = (&*w).write_all(&frame(8, &[]));
            let _ = w.shutdown(std::net::Shutdown::Both);
        })
    };

    // The browser's keys to the shell. A text frame is a control message.
    loop {
        match read_frame(&mut ws) {
            Ok((2, data)) => {
                if input.write_all(&data).is_err() {
                    break;
                }
            }
            Ok((1, text)) => {
                if let Ok(v) = serde_json::from_slice::<Value>(&text) {
                    if let (Some(c), Some(r)) = (v["cols"].as_u64(), v["rows"].as_u64()) {
                        resize(fd, c as u16, r as u16);
                    }
                }
            }
            Ok((9, p)) => {
                let _ = out.lock().expect("ws lock").write_all(&frame(10, &p));
            }
            Ok((8, _)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    // The browser left: hang up the session, as a dropped SSH connection does.
    // SAFETY: signalling the process group of a child we started.
    unsafe {
        libc::kill(-pid, libc::SIGHUP);
    }
    let _ = child.wait();
    let _ = reader.join();
}

fn handle(server: &Server, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(mut read_half) = stream.try_clone() else { return };
    let Some(req) = read_request(&mut read_half) else { return };
    let mut s = stream;
    let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => respond(&mut s, 200, "text/html; charset=utf-8", PAGE.as_bytes()),
        ("POST", "/start") => json_reply(&mut s, server.start(&body)),
        ("POST", "/approve") => json_reply(&mut s, server.approve(&body)),
        ("GET", "/ws") => {
            let upgrade = req.headers.get("upgrade").map(|u| u.eq_ignore_ascii_case("websocket")).unwrap_or(false);
            let (Some(key), true) = (req.headers.get("sec-websocket-key"), upgrade) else {
                return respond(&mut s, 400, "text/plain", b"a WebSocket is expected here");
            };
            let args = match query_param(&req.query, "ticket").ok_or("no ticket".to_string()).and_then(|t| server.spend(&t)) {
                Ok(a) => a,
                Err(e) => return json_reply(&mut s, (400, json!({"error": e}))),
            };
            let head = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
                ws_accept(key)
            );
            if s.write_all(head.as_bytes()).is_err() {
                return;
            }
            let _ = s.set_read_timeout(None);
            // Anything the reader already buffered past the handshake would be
            // a frame sent before the 101, which a browser never does.
            terminal(s, args);
        }
        (_, "/" | "/start" | "/approve" | "/ws") => respond(&mut s, 405, "text/plain", b"method not allowed"),
        _ => respond(&mut s, 404, "text/plain", b"not found"),
    }
}

/// `furcate-console web --listen ADDR --desk ADDR[,..] [--node NAME] [--ttl S]`
pub fn main(args: &[String]) -> i32 {
    let cfg = match Config::from_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("furcate-console web: {e}");
            return 2;
        }
    };
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("furcate-console web: runs as root, to start a login shell as the user a passkey approved");
        return 2;
    }
    let listener = match TcpListener::bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("furcate-console web: cannot listen on {}: {e}", cfg.listen);
            return 1;
        }
    };
    eprintln!("furcate-console web: {} on {}, desks {}", cfg.node, cfg.listen, cfg.desks.join(","));
    let server = Arc::new(Server::new(cfg, Box::new(HttpDesk)));
    for conn in listener.incoming() {
        let Ok(c) = conn else { continue };
        let server = Arc::clone(&server);
        let _ = std::thread::Builder::new().name("web".into()).spawn(move || handle(&server, c));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counting<R> {
        inner: R,
        read: usize,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n;
            Ok(n)
        }
    }

    #[test]
    fn a_request_line_that_never_ends_is_not_read_without_bound() {
        let flood = std::io::Cursor::new(b"GET /".to_vec()).chain(std::io::repeat(b'a').take(16 * 1024 * 1024));
        let mut wire = Counting { inner: flood, read: 0 };
        assert!(read_request(&mut wire).is_none());
        assert!(wire.read <= 256 * 1024, "read {} bytes of an unterminated line", wire.read);
    }

    #[test]
    fn a_request_with_a_body_still_reads() {
        let mut wire = std::io::Cursor::new(b"POST /start HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}".to_vec());
        let req = read_request(&mut wire).expect("parses");
        assert_eq!(req.path, "/start");
        assert_eq!(req.body, b"{}");
    }

    struct FakeDesk {
        outcome: Mutex<Option<Value>>,
        seen: Mutex<Vec<(String, Value)>>,
    }

    impl Desk for Arc<FakeDesk> {
        fn post(&self, _: &str, path: &str, body: &Value) -> Result<Value, String> {
            self.seen.lock().unwrap().push((path.to_string(), body.clone()));
            match path {
                "/term/login" => Ok(json!({"order_hash": "ab".repeat(32)})),
                "/orders" => Ok(self.outcome.lock().unwrap().clone().unwrap_or(Value::Null)),
                _ => Err("no".into()),
            }
        }
        fn get(&self, _: &str, path: &str) -> Result<Value, String> {
            assert!(path.starts_with("/challenge?order="));
            Ok(json!({"challenge": "c", "nonce": "n", "order_hash": "ab".repeat(32)}))
        }
    }

    fn server() -> (Server, Arc<FakeDesk>) {
        let d = Arc::new(FakeDesk { outcome: Mutex::new(None), seen: Mutex::new(Vec::new()) });
        let cfg = Config { listen: "x".into(), desks: vec!["desk".into()], node: "node-a".into(), ttl_s: 600 };
        (Server::new(cfg, Box::new(Arc::clone(&d))), d)
    }

    fn ticket_digest(d: &FakeDesk) -> String {
        let seen = d.seen.lock().unwrap();
        seen[0].1["ticket_sha256"].as_str().unwrap().to_string()
    }

    #[test]
    fn a_login_is_proposed_for_this_machine_and_the_ticket_stays_here() {
        let (s, d) = server();
        let (st, v) = s.start(&json!({"user": "ops"}));
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["challenge"], "c");
        let seen = d.seen.lock().unwrap();
        assert_eq!(seen[0].0, "/term/login");
        assert_eq!(seen[0].1["node"], "node-a");
        assert_eq!(seen[0].1["ttl_s"], 600);
        assert!(v.get("ticket").is_none());
    }

    #[test]
    fn the_ticket_comes_back_only_when_the_desk_carried_out_this_login() {
        let (s, d) = server();
        s.start(&json!({"user": "ops"}));
        let digest = ticket_digest(&d);
        let hash = "ab".repeat(32);
        // Waiting for a second approval.
        *d.outcome.lock().unwrap() = Some(json!({"outcome": {"status": "approved"}}));
        assert_eq!(s.approve(&json!({"order_hash": hash})).0, 202);
        // Carried out for another ticket.
        *d.outcome.lock().unwrap() = Some(json!({"outcome": {"status": "actuated", "detail": {
            "terminal": "ops@node-a", "ticket_sha256": "00".repeat(32), "order": hash, "approvers": ["c1"]}}}));
        assert_eq!(s.approve(&json!({"order_hash": hash})).0, 502);
        // Carried out for this one.
        *d.outcome.lock().unwrap() = Some(json!({"outcome": {"status": "actuated", "detail": {
            "terminal": "ops@node-a", "ticket_sha256": digest, "order": hash, "approvers": ["c1", "c2"]}}}));
        let (st, v) = s.approve(&json!({"order_hash": hash}));
        assert_eq!(st, 200, "{v}");
        let ticket = v["ticket"].as_str().unwrap().to_string();
        let args = s.spend(&ticket).unwrap();
        assert_eq!(
            args,
            ["ssh-session", "web", "--order", hash.as_str(), "--by", "c1,c2", "--principal", "ops@node-a"]
        );
        assert!(s.spend(&ticket).is_err(), "a ticket is spent once");
    }

    #[test]
    fn a_user_name_that_could_be_an_option_is_refused() {
        let (s, _) = server();
        for bad in ["", "-oProxyCommand", "a b", "root;x", &"a".repeat(40)] {
            assert_eq!(s.start(&json!({"user": bad})).0, 400, "{bad}");
        }
    }

    #[test]
    fn the_websocket_handshake_matches_the_rfc_example() {
        assert_eq!(ws_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn frames_round_trip_and_unmasked_ones_are_refused() {
        let payload = b"ls -l\r";
        let mask = [1u8, 2, 3, 4];
        let mut f = vec![0x82, 0x80 | payload.len() as u8];
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let (op, p) = read_frame(&mut &f[..]).unwrap();
        assert_eq!((op, p.as_slice()), (2, &payload[..]));
        assert!(read_frame(&mut &frame(2, payload)[..]).is_err());
        assert_eq!(frame(2, &[0u8; 300])[1], 126);
    }

    #[test]
    fn the_page_asks_for_user_verification_and_checks_the_order() {
        assert!(PAGE.contains("userVerification: \"required\""));
        assert!(PAGE.contains("canonical("));
        assert!(!PAGE.contains("type=\"password\""), "no password path");
    }
}
