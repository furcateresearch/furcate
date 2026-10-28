//! Passkey logins: an SSH certificate for a FIDO-held key, issued only after
//! a passkey on the roster approved a `login` order for it.
//!
//! The flow, all of it on the node that holds the site's SSH CA:
//!
//! 1. `POST /ssh/login` with the user, the machine, how long, and the OpenSSH
//!    line of a FIDO public key (`sk-ecdsa` or `sk-ed25519`). The key is kept
//!    here, by its digest, and a `login` order naming that digest is proposed
//!    to the order desk. Nothing is authorised yet; the answer is the order
//!    and its hash.
//! 2. `GET /challenge?order=<hash>`, then `POST /orders` with the passkey's
//!    assertion: the desk's ordinary approval. When the threshold is met the
//!    desk hands the order to the executor, which calls [`issue`].
//! 3. [`issue`] finds the key the order names, checks its digest again, and
//!    has `furcate-ssh issue-login` sign it. The certificate is the
//!    execution's detail, so it comes back in the `POST /orders` answer and
//!    sits in the desk's record of the order.
//!
//! The key arrives without authentication on purpose: it is public, and it
//! does nothing until a passkey approves an order naming its exact digest.

use furcate_api::orders::Desk;
use furcate_api::{Request, Response, Router};
use furcate_authn::order::{ssh_key_sha256, Order, Target, FIDO_SSH_KEY_TYPES};
use furcate_authn::webauthn::Approval;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What a held browser terminal ticket is stored as, in place of a key line.
pub const TERMINAL_TICKET: &str = "furcate-terminal-ticket";

/// How long a login request waits for its approval.
pub const REQUEST_LIFETIME_S: u64 = 120;

/// The most keys held for requests at once.
const MAX_KEYS: usize = 64;

/// Public keys waiting for their order to be approved, by digest.
#[derive(Default)]
pub struct LoginKeys {
    keys: Mutex<BTreeMap<String, (String, u64)>>,
}

impl LoginKeys {
    /// Hold `line` until `expires_at`. Returns its digest, or why it is not a
    /// key a login may certify.
    pub fn hold(&self, line: &str, expires_at: u64, now: u64) -> Result<String, String> {
        let line = line.trim();
        if line.len() > 2048 || line.contains('\n') {
            return Err("public_key must be one line of OpenSSH key text".into());
        }
        let (kind, digest) = ssh_key_sha256(line).map_err(|e| e.to_string())?;
        if !FIDO_SSH_KEY_TYPES.contains(&kind.as_str()) {
            return Err(format!(
                "a passkey login certifies a FIDO key ({}), not `{kind}`",
                FIDO_SSH_KEY_TYPES.join(" or ")
            ));
        }
        let mut k = self.keys.lock().expect("login keys lock");
        k.retain(|_, (_, until)| *until > now);
        if k.len() >= MAX_KEYS && !k.contains_key(&digest) {
            return Err("too many login requests are waiting; try again shortly".into());
        }
        // Keep only the type and key fields: the comment is not certified and
        // is not passed to a signing command.
        let canonical = line.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let until = k.get(&digest).map(|(_, u)| *u).unwrap_or(0).max(expires_at);
        k.insert(digest.clone(), (canonical, until));
        Ok(digest)
    }

    /// Hold a browser terminal's ticket digest the way a key is held: the
    /// login order names it, and approving the order approves that one
    /// terminal session, once. The ticket itself never comes here.
    pub fn hold_ticket(&self, digest: &str, expires_at: u64, now: u64) -> Result<(), String> {
        if digest.len() != 64 || !digest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err("ticket_sha256 is 64 lowercase hex characters".into());
        }
        let mut k = self.keys.lock().expect("login keys lock");
        k.retain(|_, (_, until)| *until > now);
        if k.len() >= MAX_KEYS && !k.contains_key(digest) {
            return Err("too many login requests are waiting; try again shortly".into());
        }
        k.insert(digest.to_string(), (TERMINAL_TICKET.to_string(), expires_at));
        Ok(())
    }

    /// The key an approved order names, removed so it is certified once.
    pub fn take(&self, digest: &str) -> Option<String> {
        self.keys.lock().expect("login keys lock").remove(digest).map(|(l, _)| l)
    }
}

/// The CA's signer: `furcate-ssh issue-login --serve`, run as root by
/// `furcate-ssh-signer.socket` on the node that holds the CA. This daemon runs
/// unprivileged and cannot read the CA or unseal it; the socket is the one
/// place it asks, and only this daemon's user may connect (SocketUser, 0600),
/// the same trust a root actuator gives the intents this daemon writes.
pub fn signer_socket() -> PathBuf {
    std::env::var("FURCATE_SSH_SIGNER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| furcate_paths::runtime("ssh-signer.sock"))
}

/// Whether this node signs passkey logins: its CA signer is listening.
pub fn holds_ca() -> bool {
    use std::os::unix::fs::FileTypeExt as _;
    std::fs::metadata(signer_socket()).map(|m| m.file_type().is_socket()).unwrap_or(false)
}

/// Carry out an approved `login` order: sign the key it names.
pub fn issue(
    order: &Order,
    approval: &Approval,
    keys: &LoginKeys,
    signer: &dyn Fn(&[String]) -> Result<(String, Value), String>,
) -> Result<Value, String> {
    let Target::Login {
        user,
        node,
        key_sha256,
    } = &order.target
    else {
        return Err("a login order names a login".into());
    };
    if approval.order_hash() != order.hash().map_err(|e| e.to_string())? {
        return Err("the approval is for a different order".into());
    }
    let Some(line) = keys.take(key_sha256) else {
        return Err(format!(
            "no public key with digest {key_sha256} is waiting here; request the login again"
        ));
    };
    let ttl = order.bounds.duration_s.ok_or("a login order has a duration")?;
    // A browser terminal: nothing is signed. The approval is the outcome, and
    // the terminal on that machine starts the one session whose ticket hashes
    // to this digest.
    if line == TERMINAL_TICKET {
        return Ok(json!({
            "terminal": format!("{user}@{node}"),
            "ticket_sha256": key_sha256,
            "order": hex::encode(approval.order_hash()),
            "approvers": approval.approvers(),
            "valid_s": ttl,
        }));
    }
    let (_, digest) = ssh_key_sha256(&line).map_err(|e| e.to_string())?;
    if &digest != key_sha256 {
        return Err("the held key is not the one the order names".into());
    }
    let args = vec![
        "issue-login".to_string(),
        "--principal".into(),
        format!("{user}@{node}"),
        "--ttl".into(),
        ttl.to_string(),
        "--order".into(),
        hex::encode(approval.order_hash()),
        "--approvers".into(),
        approval.approvers().join(","),
        "--key".into(),
        line,
    ];
    let (cert, detail) = signer(&args)?;
    Ok(json!({
        "certificate": cert,
        "principal": format!("{user}@{node}"),
        "approvers": approval.approvers(),
        "issued": detail,
    }))
}

/// Have the CA's signer sign: the `issue-login` arguments [`issue`] built,
/// sent as one JSON request over the signer socket, the certificate back.
pub fn furcate_ssh_signer(args: &[String]) -> Result<(String, Value), String> {
    furcate_ssh_signer_at(&signer_socket(), args)
}

pub fn furcate_ssh_signer_at(sock: &Path, args: &[String]) -> Result<(String, Value), String> {
    use std::io::{Read as _, Write as _};
    let mut req = serde_json::Map::new();
    let mut it = args.iter().skip_while(|a| *a == "issue-login");
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("{k} has no value"))?;
        req.insert(k.trim_start_matches("--").to_string(), Value::String(v.clone()));
    }
    let mut s = std::os::unix::net::UnixStream::connect(sock)
        .map_err(|e| format!("the CA signer is not reachable at {}: {e}", sock.display()))?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(120)));
    writeln!(s, "{}", Value::Object(req)).map_err(|e| format!("asking the CA signer: {e}"))?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| format!("reading the CA signer: {e}"))?;
    let v: Value = out
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str(l).ok())
        .ok_or_else(|| "the CA signer gave no answer".to_string())?;
    if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
        return Err(format!("the CA signer refused: {e}"));
    }
    let cert = v
        .get("certificate")
        .and_then(|c| c.as_str())
        .ok_or("the CA signer returned no certificate")?
        .trim()
        .to_string();
    Ok((cert, v))
}

/// `GET /ssh/ca`: the public half of the site's SSH CA, as this machine's
/// sshd trusts it (`/etc/ssh/furcate_ca.pub`), with its revocation list.
///
/// Public by nature, and any machine that trusts the CA can answer, so no
/// single node is the only source. The answer is not the trust decision: a
/// machine adopting it pins the SHA-256 (`furcatectl ssh trust --ca-sha256`)
/// and refuses anything else, so a substitute is refused there.
pub fn mount_ca(router: Router, etc_ssh: PathBuf) -> Router {
    router.route("GET", "/ssh/ca", move |_: &Request| ca_answer(&etc_ssh))
}

fn ca_answer(etc_ssh: &Path) -> Response {
    use sha2::Digest as _;
    let line = match std::fs::read_to_string(etc_ssh.join("furcate_ca.pub")) {
        Ok(l) => l.trim().to_string(),
        Err(_) => {
            return Response::error(404, "this machine does not trust a site SSH CA".to_string())
        }
    };
    let krl = std::fs::read(etc_ssh.join("furcate_ca.krl")).ok();
    Response::ok(json!({
        "public_key": line,
        "sha256": hex::encode(sha2::Sha256::digest(line.as_bytes())),
        "krl_b64": krl.map(|k| data_encoding_b64(&k)),
    }))
}

fn data_encoding_b64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `POST /ssh/login`: hold the key and propose the order. `POST
/// /term/login`: the same for a browser terminal's ticket.
pub fn mount(router: Router, desk: Arc<Desk>, keys: Arc<LoginKeys>) -> Router {
    let (d, k) = (Arc::clone(&desk), Arc::clone(&keys));
    router
        .route("POST", "/ssh/login", move |req: &Request| request(&d, &k, req, super::now_s()))
        .route("POST", "/term/login", move |req: &Request| {
            terminal_request(&desk, &keys, req, super::now_s())
        })
}

fn terminal_request(desk: &Desk, keys: &LoginKeys, req: &Request, now: u64) -> Response {
    let s = |k: &str| req.body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (user, node, digest, reason) = (s("user"), s("node"), s("ticket_sha256"), s("reason"));
    let Some(ttl) = req.body.get("ttl_s").and_then(|v| v.as_u64()) else {
        return Response::error(400, "ttl_s (seconds) is required".to_string());
    };
    if user.is_empty() || node.is_empty() {
        return Response::error(400, "user and node are required".to_string());
    }
    if let Err(why) = keys.hold_ticket(&digest, now + REQUEST_LIFETIME_S, now) {
        return Response::error(400, why);
    }
    let target = Target::Login { user, node, key_sha256: digest };
    desk.propose_login(target, ttl, reason, REQUEST_LIFETIME_S, now)
}

fn request(desk: &Desk, keys: &LoginKeys, req: &Request, now: u64) -> Response {
    let s = |k: &str| req.body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (user, node, line, reason) = (s("user"), s("node"), s("public_key"), s("reason"));
    let Some(ttl) = req.body.get("ttl_s").and_then(|v| v.as_u64()) else {
        return Response::error(400, "ttl_s (seconds) is required".to_string());
    };
    if user.is_empty() || node.is_empty() || line.is_empty() {
        return Response::error(400, "user, node and public_key are all required".to_string());
    }
    let digest = match keys.hold(&line, now + REQUEST_LIFETIME_S, now) {
        Ok(d) => d,
        Err(why) => return Response::error(400, why),
    };
    let target = Target::Login {
        user,
        node,
        key_sha256: digest,
    };
    desk.propose_login(target, ttl, reason, REQUEST_LIFETIME_S, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_authn::order::Bounds;
    use furcate_authn::webauthn::virtual_authenticator::Authenticator;
    use furcate_authn::webauthn::{verify_assertion, Challenge, Credential, Tally, Thresholds};

    const SK: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBI05E5HOabGO4jichqpkg3Kem8Kfzcfga3U30iHnyuIMcsdXWdPzImdPvN6ZJibBMw4a99t1yQbXeC6GU71JvuIAAAAUY29uc29sZS5leGFtcGxlLnRlc3Q= laptop";

    fn order(key_sha256: String) -> Order {
        Order {
            site: "ops.example.org".into(),
            action: furcate_authn::order::Action::Login,
            target: Target::Login {
                user: "root".into(),
                node: "node-a".into(),
                key_sha256,
            },
            bounds: Bounds {
                max_nodes: 1,
                duration_s: Some(1800),
            },
            counter: 1,
            issued_at: 100,
            expires_at: 200,
            reason: "disks".into(),
        }
    }

    fn approved(o: &Order) -> Approval {
        let mut a = Authenticator::new(7, "ops.example.org");
        let c = Challenge {
            order_hash: o.hash().unwrap(),
            nonce: [3; 16],
            expires_at: 190,
        };
        let enrol = Challenge::enrolment([1; 16], 190);
        let e = furcate_authn::webauthn::verify_enrolment(&a.create(&enrol), "ops.example.org", &enrol, 120)
            .unwrap();
        let cred = Credential::from_enrolled(&e, "alice".into(), 100);
        let mut t = Tally::new(o, &Thresholds::default()).unwrap();
        t.add(verify_assertion(&cred, &a.get(&c), &c, 150).unwrap()).unwrap();
        t.approval().unwrap()
    }

    #[test]
    fn only_fido_keys_are_held_and_the_comment_is_dropped() {
        let k = LoginKeys::default();
        let d = k.hold(SK, 200, 100).unwrap();
        assert_eq!(k.take(&d).unwrap(), SK.rsplit_once(' ').unwrap().0);
        let plain = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x";
        assert!(k.hold(plain, 200, 100).unwrap_err().contains("FIDO"));
        assert!(k.hold("sk-ecdsa-sha2-nistp256@openssh.com AAAA\nx", 200, 100).is_err());
    }

    #[test]
    fn the_signer_gets_exactly_what_the_order_names() {
        let k = LoginKeys::default();
        let d = k.hold(SK, 200, 100).unwrap();
        let o = order(d.clone());
        let a = approved(&o);
        let seen = Mutex::new(Vec::new());
        let signer = |args: &[String]| -> Result<(String, Value), String> {
            seen.lock().unwrap().extend_from_slice(args);
            Ok(("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA".into(), json!({"serial": 31})))
        };
        let v = issue(&o, &a, &k, &signer).unwrap();
        assert_eq!(v["principal"], "root@node-a");
        assert_eq!(v["issued"]["serial"], 31);
        let args = seen.lock().unwrap().clone();
        let at = |f: &str| args[args.iter().position(|x| x == f).unwrap() + 1].clone();
        assert_eq!(at("--principal"), "root@node-a");
        assert_eq!(at("--ttl"), "1800");
        assert_eq!(at("--order"), hex::encode(o.hash().unwrap()));
        assert_eq!(at("--key"), SK.rsplit_once(' ').unwrap().0);
        // Certified once: the key is no longer held.
        assert!(issue(&o, &a, &k, &signer).is_err());
    }

    #[test]
    fn an_order_for_a_key_never_offered_is_refused() {
        let k = LoginKeys::default();
        let o = order("cd".repeat(32));
        let a = approved(&o);
        let signer = |_: &[String]| -> Result<(String, Value), String> { panic!("must not sign") };
        assert!(issue(&o, &a, &k, &signer).unwrap_err().contains("no public key"));
    }

    #[test]
    fn an_approval_for_another_order_is_refused() {
        let k = LoginKeys::default();
        let d = k.hold(SK, 200, 100).unwrap();
        let o = order(d);
        let mut other = o.clone();
        other.reason = "something else".into();
        let a = approved(&other);
        let signer = |_: &[String]| -> Result<(String, Value), String> { panic!("must not sign") };
        assert!(issue(&o, &a, &k, &signer).unwrap_err().contains("different order"));
    }

    #[test]
    fn an_approved_terminal_ticket_is_the_outcome_and_nothing_is_signed() {
        let k = LoginKeys::default();
        let d = "5e".repeat(32);
        k.hold_ticket(&d, 200, 100).unwrap();
        let o = order(d.clone());
        let a = approved(&o);
        let signer = |_: &[String]| -> Result<(String, Value), String> { panic!("must not sign") };
        let v = issue(&o, &a, &k, &signer).unwrap();
        assert_eq!(v["terminal"], "root@node-a");
        assert_eq!(v["ticket_sha256"], d);
        assert_eq!(v["order"], hex::encode(o.hash().unwrap()));
        assert_eq!(v["approvers"].as_array().unwrap().len(), 1);
        // Once.
        assert!(issue(&o, &a, &k, &signer).is_err());
        assert!(k.hold_ticket("not-hex", 200, 100).is_err());
    }
}

#[cfg(test)]
mod ca_tests {
    use super::*;

    #[test]
    fn the_ca_answer_carries_the_key_its_digest_and_the_krl() {
        let d = std::env::temp_dir().join(format!("furcate-ca-answer-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(ca_answer(&d).status, 404);
        std::fs::write(d.join("furcate_ca.pub"), "ssh-ed25519 AAAAC3Nza example\n").unwrap();
        std::fs::write(d.join("furcate_ca.krl"), b"krl").unwrap();
        let r = ca_answer(&d);
        assert_eq!(r.status, 200);
        assert_eq!(r.body["public_key"], "ssh-ed25519 AAAAC3Nza example");
        assert_eq!(r.body["krl_b64"], "a3Js");
        assert_eq!(r.body["sha256"].as_str().unwrap().len(), 64);
        std::fs::remove_dir_all(&d).unwrap();
    }
}

#[cfg(test)]
mod signer_tests {
    use super::*;

    #[test]
    fn the_signer_gets_one_json_request_and_its_certificate_comes_back() {
        use std::io::{BufRead as _, Write as _};
        let p = std::env::temp_dir().join(format!("furcate-signer-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        let t = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&c).read_line(&mut line).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            writeln!(c, "{}", json!({"certificate": "sk-cert AAAA\n", "serial": 9})).unwrap();
            v
        });
        let args: Vec<String> = ["issue-login", "--principal", "ops@node-a", "--ttl", "60", "--key", "sk-ecdsa x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (cert, detail) = furcate_ssh_signer_at(&p, &args).unwrap();
        assert_eq!(cert, "sk-cert AAAA");
        assert_eq!(detail["serial"], 9);
        let sent = t.join().unwrap();
        assert_eq!(sent, json!({"principal": "ops@node-a", "ttl": "60", "key": "sk-ecdsa x"}));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_refusal_carries_the_signers_reason() {
        use std::io::Write as _;
        let p = std::env::temp_dir().join(format!("furcate-signer-no-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            let (mut c, _) = l.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(&c).read_line(&mut line).unwrap();
            writeln!(c, "{}", json!({"error": "policy does not allow"})).unwrap();
        });
        let e = furcate_ssh_signer_at(&p, &["issue-login".to_string()]).unwrap_err();
        assert!(e.contains("policy does not allow"), "{e}");
        let _ = std::fs::remove_file(&p);
    }
}
