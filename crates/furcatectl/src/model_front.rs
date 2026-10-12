//! The model gateway's door to the cell.
//!
//! The model router listens on loopback only. This is what the cell reaches:
//! it takes a request, admits it only when it is signed by a leaf attached to
//! the cell this node heads or by the operator, and passes it to the router
//! with the router's loopback credential. That credential never leaves this
//! machine; nothing off it holds a shared secret.
//!
//! A leaf signs with the key derived from its hardware, and is checked against
//! the cell's chain read fresh on every request (`NodeFiles::headed_tree`):
//! a leaf the operator revoked, whose link ended, or whose class is below the
//! cell's leaf floor is refused the moment the files say so. The scheme is
//! `furcate_topology::leaf_request`; the operator's is the signed request
//! every other Furcate service takes (`furcate_authn::local`).
//!
//! The response is copied back as it arrives, so a streamed completion
//! streams.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use furcate_authn::{Presented, Verifier};
use furcate_topology::cell::NodeFiles;
use furcate_topology::leaf_request::{self, LeafRequests};

/// The largest request body taken. A chat request from a leaf is a few
/// hundred bytes; an operator's can carry a long prompt.
pub const MAX_BODY: usize = 1024 * 1024;
const MAX_HEAD: usize = 16 * 1024;
/// Requests handled at once. More are told to come back rather than queued,
/// so a flood cannot hold every thread.
const MAX_CONNECTIONS: usize = 64;
/// How long a completion may take before the router is given up on.
const UPSTREAM_SECS: u64 = 600;

/// Where to read the spec, named in every refusal of a missing credential.
const SPEC: &str = "docs/interfaces/leaf-gateway-request.md";

pub struct Front {
    pub files: NodeFiles,
    pub leaves: LeafRequests,
    pub operator: furcate_authn::LocalVerifier,
    pub upstream: SocketAddr,
    pub token: String,
}

struct Head {
    method: String,
    target: String,
    content_type: Option<String>,
    accept: Option<String>,
    credential: Option<String>,
    length: usize,
    expect_continue: bool,
}

/// Why a request was not forwarded: the status and the message.
type Refused = (u16, String);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Front {
    /// Accept until the listener fails.
    pub fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let busy = Arc::new(AtomicUsize::new(0));
        for conn in listener.incoming() {
            let mut client = match conn {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("model gateway: accept failed: {e}");
                    continue;
                }
            };
            if busy.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                busy.fetch_sub(1, Ordering::SeqCst);
                let _ = reply(&mut client, 503, "too many requests at once; try again shortly");
                continue;
            }
            let me = Arc::clone(&self);
            let busy = Arc::clone(&busy);
            std::thread::spawn(move || {
                me.handle(client, now());
                busy.fetch_sub(1, Ordering::SeqCst);
            });
        }
        bail!("the listener stopped")
    }

    fn handle(&self, mut client: TcpStream, now: u64) {
        let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = client.set_write_timeout(Some(Duration::from_secs(30)));
        let peer = client.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
        let Ok(read_half) = client.try_clone() else { return };
        let mut reader = BufReader::new(read_half);
        let head = match read_head(&mut reader) {
            Ok(h) => h,
            Err((code, why)) => {
                let _ = reply(&mut client, code, &why);
                return;
            }
        };
        if head.expect_continue && head.length > 0 {
            let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        let mut body = vec![0u8; head.length];
        if reader.read_exact(&mut body).is_err() {
            let _ = reply(&mut client, 400, "the body is shorter than its Content-Length");
            return;
        }
        let presented = Presented {
            method: head.method.clone(),
            path: head.target.clone(),
            body,
            credential: head.credential.clone(),
        };
        let who = match self.admit(&presented, now) {
            Ok(who) => who,
            Err((code, why)) => {
                eprintln!("model gateway: refused {} {} from {peer}: {why}", head.method, head.target);
                let _ = reply(&mut client, code, &why);
                return;
            }
        };
        eprintln!("model gateway: {who} {} {} from {peer}", head.method, head.target);
        if let Err(why) = self.forward(&head, &presented.body, &mut client) {
            eprintln!("model gateway: {why}");
            let _ = reply(&mut client, 502, &why);
        }
    }

    /// Who signed the request, or why it is refused.
    pub fn admit(&self, p: &Presented, now: u64) -> std::result::Result<String, Refused> {
        let Some(cred) = p.credential.as_deref() else {
            return Err((
                401,
                format!(
                    "this gateway admits requests signed by a leaf attached to its cell or by the \
                     operator, carried in X-Furcate-Credential ({SPEC})"
                ),
            ));
        };
        if cred.starts_with(leaf_request::SCHEME) {
            let (cell, tree) = self
                .files
                .headed_tree(now)
                .map_err(|why| (403, format!("leaves are admitted by the cell this node heads, and {why}")))?;
            let leaf = self.leaves.verify(&tree, &cell, p, now).map_err(|r| (401, r.because))?;
            return Ok(format!("leaf {} ({}, {}) of cell {}", leaf.name, leaf.holder, leaf.assurance, leaf.cell));
        }
        if cred.starts_with(furcate_authn::local::SCHEME) {
            let who = self.operator.verify(p, now).map_err(|r| (401, r.because))?;
            return Ok(who.id);
        }
        Err((401, format!("X-Furcate-Credential is a leaf signature (leaf:...) or an operator signature (op:...); see {SPEC}")))
    }

    /// Pass the request to the router with its loopback credential, and copy
    /// the answer back as it arrives.
    fn forward(&self, head: &Head, body: &[u8], client: &mut TcpStream) -> std::result::Result<(), String> {
        let mut up = TcpStream::connect_timeout(&self.upstream, Duration::from_secs(2))
            .map_err(|e| format!("the model router on {} is not answering: {e}", self.upstream))?;
        let _ = up.set_read_timeout(Some(Duration::from_secs(UPSTREAM_SECS)));
        let _ = up.set_write_timeout(Some(Duration::from_secs(30)));
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            head.method,
            head.target,
            self.upstream,
            self.token,
            body.len()
        );
        if let Some(ct) = &head.content_type {
            req.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        if let Some(a) = &head.accept {
            req.push_str(&format!("Accept: {a}\r\n"));
        }
        req.push_str("\r\n");
        up.write_all(req.as_bytes())
            .and_then(|_| up.write_all(body))
            .map_err(|e| format!("could not send the request to the model router: {e}"))?;
        let _ = client.set_write_timeout(Some(Duration::from_secs(UPSTREAM_SECS)));
        // The response is passed through untouched, headers included.
        std::io::copy(&mut up, client).map(|_| ()).map_err(|e| format!("the answer was cut off: {e}"))
    }
}

fn read_head(r: &mut impl BufRead) -> std::result::Result<Head, Refused> {
    let mut used = 0usize;
    let mut line = String::new();
    let mut next = |line: &mut String| -> std::result::Result<(), Refused> {
        line.clear();
        let n = r.read_line(line).map_err(|_| (400, "the request could not be read".to_string()))?;
        used += n;
        if n == 0 {
            return Err((400, "the request ended before its headers did".into()));
        }
        if used > MAX_HEAD {
            return Err((431, format!("request headers are limited to {MAX_HEAD} bytes")));
        }
        Ok(())
    };
    next(&mut line)?;
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err((400, "the request line is not METHOD TARGET HTTP/1.1".into()));
    };
    if !version.starts_with("HTTP/1.") {
        return Err((505, "HTTP/1.1 only".into()));
    }
    if method != "GET" && method != "POST" {
        return Err((405, format!("{method} is not taken here; GET and POST are")));
    }
    if !(target.starts_with("/v1/") || target == "/health") {
        return Err((404, format!("{target} is not served; the models are under /v1/")));
    }
    let mut head = Head {
        method: method.to_string(),
        target: target.to_string(),
        content_type: None,
        accept: None,
        credential: None,
        length: 0,
        expect_continue: false,
    };
    let mut length: Option<usize> = None;
    loop {
        next(&mut line)?;
        let h = line.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        let Some((name, value)) = h.split_once(':') else {
            return Err((400, format!("`{h}` is not a header")));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                let n: usize = value.parse().map_err(|_| (400, "Content-Length is not a number".to_string()))?;
                if length.is_some_and(|l| l != n) {
                    return Err((400, "two different Content-Length headers".into()));
                }
                length = Some(n);
            }
            "transfer-encoding" => {
                return Err((411, "send the body with a Content-Length; chunked requests are not taken".into()))
            }
            "x-furcate-credential" => {
                if head.credential.is_some() {
                    return Err((400, "one X-Furcate-Credential per request".into()));
                }
                head.credential = Some(value.to_string());
            }
            "content-type" => head.content_type = Some(value.to_string()),
            "accept" => head.accept = Some(value.to_string()),
            "expect" => head.expect_continue = value.eq_ignore_ascii_case("100-continue"),
            // Anything else, Authorization included, stays here. The router
            // is asked with this machine's credential, never the caller's.
            _ => {}
        }
    }
    head.length = length.unwrap_or(0);
    if head.length > MAX_BODY {
        return Err((413, format!("request bodies are limited to {MAX_BODY} bytes")));
    }
    Ok(head)
}

fn reply(client: &mut TcpStream, code: u16, message: &str) -> std::io::Result<()> {
    let reason = match code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    };
    let kind = if code == 401 || code == 403 { "authentication_error" } else { "invalid_request_error" };
    let body = serde_json::json!({ "error": { "message": message, "type": kind, "code": code } }).to_string();
    let mut extra = String::new();
    if code == 401 {
        extra.push_str("WWW-Authenticate: Furcate-Signature\r\n");
    }
    write!(
        client,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The files this node's cell is read from: the same ones `furcated` reads.
fn node_files() -> NodeFiles {
    NodeFiles {
        anchor: furcate_paths::config("cell-anchor.json"),
        links: vec![furcate_paths::config("cells.json"), furcate_paths::state("cells-issued.json")],
        operator_pub: furcate_paths::config("operator.pub"),
    }
}

/// The cell this node heads, as the gateway would read it now.
pub fn headed(now: u64) -> std::result::Result<String, String> {
    node_files().headed_tree(now).map(|(cell, _)| cell)
}

/// `furcatectl model front --bind ADDR --port N --upstream-port N`: run by the
/// gateway's unit, not by hand.
pub fn run(args: &[&str], token_file: &std::path::Path) -> Result<()> {
    let mut bind: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut upstream: Option<u16> = None;
    let mut i = 0;
    while i < args.len() {
        let v = || args.get(i + 1).copied().with_context(|| format!("{} needs a value", args[i]));
        match args[i] {
            "--bind" => bind = Some(v()?.to_string()),
            "--port" => port = Some(v()?.parse().context("--port must be a port")?),
            "--upstream-port" => upstream = Some(v()?.parse().context("--upstream-port must be a port")?),
            other => bail!("unknown option `{other}`\n\nusage: furcatectl model front --bind ADDR --port N --upstream-port N"),
        }
        i += 2;
    }
    let (Some(bind), Some(port), Some(upstream)) = (bind, port, upstream) else {
        bail!("usage: furcatectl model front --bind ADDR --port N --upstream-port N (written by `furcatectl model gateway`)");
    };
    let token = std::fs::read_to_string(token_file)
        .with_context(|| format!("reading the router's loopback credential at {}", token_file.display()))?
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("{} is empty", token_file.display());
    }
    let operator_pub = furcate_paths::config("operator.pub");
    let operator = furcate_authn::LocalVerifier::from_key_file(&operator_pub)
        .with_people_file(&furcate_paths::config("people.json"), now());
    if !operator.knows_its_operator() {
        eprintln!("model gateway: no operator key at {}; operator requests will be refused", operator_pub.display());
    }
    let files = node_files();
    match files.headed_tree(now()) {
        Ok((cell, _)) => eprintln!("model gateway: admitting the leaves of cell {cell}"),
        Err(why) => eprintln!("model gateway: no leaf will be admitted until this node heads a cell: {why}"),
    }
    let listener = TcpListener::bind((bind.as_str(), port)).with_context(|| format!("binding {bind}:{port}"))?;
    eprintln!("model gateway: {bind}:{port} -> 127.0.0.1:{upstream}");
    let front = Arc::new(Front {
        files,
        leaves: LeafRequests::new(),
        operator,
        upstream: SocketAddr::from(([127, 0, 0, 1], upstream)),
        token,
    });
    front.serve(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use furcate_identity::AssuranceClass;
    use furcate_topology::cell::{ed25519_id, p256_id, CellDelegation, CellFile, Role, Scale, Scope};

    const BODY: &str = r#"{"model":"m","messages":[{"role":"user","content":"ok"}],"max_tokens":4}"#;

    // Test-only keys; a leaf derives its key from its silicon and a node
    // keeps its own in the TPM.
    fn ed(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }

    fn link(by: &ed25519_dalek::SigningKey, above: Option<&CellDelegation>, holder: String, role: Role, name: &str, now: u64) -> CellDelegation {
        CellDelegation {
            site: "home".into(),
            issuer: ed25519_id(&by.verifying_key()),
            holder,
            role,
            scope: Scope::parse(if role == Role::Controller { "site" } else { "cell:lab" }).unwrap(),
            scale: (role == Role::Head).then_some(Scale::Other),
            assurance: Some(AssuranceClass::Device),
            leaf_min_class: None,
            endpoint: String::new(),
            name: name.into(),
            parent: above.map(|a| a.digest()),
            not_before: now - 100,
            not_after: above.map(|a| a.not_after).unwrap_or(now + 86_400),
            signature: String::new(),
        }
        .signed_by(|m| Ok(by.sign(m).to_bytes().to_vec()))
        .unwrap()
    }

    /// A router stand-in: answers every request with what it was sent, so
    /// the test sees exactly what crossed the loopback.
    fn echo_router() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut c = c;
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut seen = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    seen.push_str(&line);
                }
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                seen.push_str(&String::from_utf8_lossy(&body));
                let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{seen}", seen.len());
            }
        });
        addr
    }

    struct Rig {
        dir: std::path::PathBuf,
        addr: SocketAddr,
        leaf: p256::ecdsa::SigningKey,
        op: ed25519_dalek::SigningKey,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn rig(tag: &str) -> Rig {
        let now = now();
        let dir = std::env::temp_dir().join(format!("furcate-front-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let op = ed(1);
        let leaf = p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
        let ctl = link(&op, None, ed25519_id(&ed(2).verifying_key()), Role::Controller, "core", now);
        let h = link(&ed(2), Some(&ctl), ed25519_id(&ed(3).verifying_key()), Role::Head, "pi-lab", now);
        let l = link(&ed(3), Some(&h), p256_id(leaf.verifying_key()), Role::Leaf, "esp-8", now);
        std::fs::write(dir.join("operator.pub"), hex::encode(op.verifying_key().to_bytes())).unwrap();
        std::fs::write(dir.join("cell-anchor.json"), serde_json::json!({ "own": h, "parent_endpoint": "core:7616" }).to_string()).unwrap();
        let file = CellFile { site: "home".into(), links: vec![ctl, l], revoked: vec![] };
        std::fs::write(dir.join("cells-issued.json"), serde_json::to_string(&file).unwrap()).unwrap();
        let files = NodeFiles {
            anchor: dir.join("cell-anchor.json"),
            links: vec![dir.join("cells-issued.json")],
            operator_pub: dir.join("operator.pub"),
        };
        let front = Arc::new(Front {
            files,
            leaves: LeafRequests::new(),
            operator: furcate_authn::LocalVerifier::from_key_file(&dir.join("operator.pub")),
            upstream: echo_router(),
            token: "not-a-real-credential".into(),
        });
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || front.serve(l));
        Rig { dir, addr, leaf, op }
    }

    fn send(addr: SocketAddr, target: &str, body: &str, headers: &[String]) -> (u16, String) {
        let mut c = TcpStream::connect(addr).unwrap();
        let mut req = format!("POST {target} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len());
        for h in headers {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        req.push_str(body);
        c.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        let code = out.split_whitespace().nth(1).unwrap().parse().unwrap();
        (code, out)
    }

    fn leaf_cred(r: &Rig, target: &str, body: &str, nonce: &str) -> String {
        let cred = leaf_request::credential(&p256_id(r.leaf.verifying_key()), "POST", target, body.as_bytes(), nonce, now() + 60, |m| {
            let s: p256::ecdsa::Signature = r.leaf.sign(m);
            Ok(s.to_bytes().to_vec())
        })
        .unwrap();
        format!("X-Furcate-Credential: {cred}")
    }

    #[test]
    fn a_signed_leaf_request_reaches_the_router_with_the_loopback_credential_only() {
        let r = rig("leaf");
        let t = "/v1/chat/completions";
        let (code, out) = send(r.addr, t, BODY, &[leaf_cred(&r, t, BODY, "front-0001"), "Authorization: Bearer stolen".into()]);
        assert_eq!(code, 200, "{out}");
        assert!(out.contains("Authorization: Bearer not-a-real-credential"), "{out}");
        assert!(!out.contains("stolen"), "the caller's Authorization is never forwarded: {out}");
        assert!(!out.contains("leaf:"), "the credential is not forwarded: {out}");
        assert!(out.ends_with(BODY));
    }

    #[test]
    fn an_unsigned_or_bearer_only_request_is_refused() {
        let r = rig("unsigned");
        let (code, out) = send(r.addr, "/v1/chat/completions", BODY, &[]);
        assert_eq!(code, 401, "{out}");
        let (code, _) = send(r.addr, "/v1/chat/completions", BODY, &["Authorization: Bearer not-a-real-credential".into()]);
        assert_eq!(code, 401, "the router's own token is no credential at the door");
    }

    #[test]
    fn a_leaf_request_replayed_or_altered_is_refused() {
        let r = rig("replay");
        let t = "/v1/chat/completions";
        let h = leaf_cred(&r, t, BODY, "front-0002");
        assert_eq!(send(r.addr, t, BODY, std::slice::from_ref(&h)).0, 200);
        let (code, out) = send(r.addr, t, BODY, std::slice::from_ref(&h));
        assert_eq!(code, 401, "{out}");
        assert!(out.contains("already been made"));
        let h = leaf_cred(&r, t, BODY, "front-0003");
        let (code, _) = send(r.addr, t, &BODY.replace("ok", "ko"), &[h]);
        assert_eq!(code, 401);
    }

    #[test]
    fn the_operator_signs_as_everywhere_else() {
        let r = rig("operator");
        let t = "/v1/models";
        let cred = furcate_authn::local::sign(&r.op, "POST", t, BODY.as_bytes(), "op-0001", now() + 60);
        let (code, out) = send(r.addr, t, BODY, &[format!("X-Furcate-Credential: {cred}")]);
        assert_eq!(code, 200, "{out}");
        // Another key is not the operator.
        let cred = furcate_authn::local::sign(&ed(7), "POST", t, BODY.as_bytes(), "op-0002", now() + 60);
        assert_eq!(send(r.addr, t, BODY, &[format!("X-Furcate-Credential: {cred}")]).0, 401);
    }

    #[test]
    fn only_the_model_api_is_served_and_bodies_are_bounded() {
        let r = rig("bounds");
        assert_eq!(send(r.addr, "/admin", BODY, &[]).0, 404);
        assert_eq!(send(r.addr, "/v1/chat/completions", BODY, &["Transfer-Encoding: chunked".into()]).0, 411);
        let mut c = TcpStream::connect(r.addr).unwrap();
        write!(c, "POST /v1/chat/completions HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 413"), "{out}");
    }
}
