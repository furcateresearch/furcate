//! OpenSSH user certificates for FIDO keys: read one and check the CA signed it.
//!
//! sshd has already verified the certificate a session logged in with. This is
//! for the programs that run after it and need to know *which* certificate
//! that was: the session recorder takes the order hash and the approving
//! credentials from the certificate's force-command, and it accepts them only
//! from a certificate it has checked against the same CA key sshd trusts. A
//! claim passed in an environment variable or an argument is not evidence.
//!
//! Only what a passkey login certificate is: `sk-ecdsa-sha2-nistp256` or
//! `sk-ssh-ed25519` subject keys, signed by an `ssh-ed25519` or
//! `ecdsa-sha2-nistp256` CA. Anything else is refused by name.

use data_encoding::BASE64;
use sha2::{Digest, Sha256};

/// The certificate types a passkey login carries.
pub const FIDO_CERT_TYPES: [&str; 2] = [
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
];

/// What a certificate says, once its CA signature has been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The certificate type, one of [`FIDO_CERT_TYPES`].
    pub kind: String,
    /// SHA-256 of the subject key's plain wire encoding, lowercase hex: the
    /// digest a `login` order names.
    pub key_sha256: String,
    /// The FIDO application string the key was made for, usually `ssh:`.
    pub application: String,
    pub serial: u64,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    /// The force-command critical option, if the certificate carries one.
    pub force_command: Option<String>,
    /// SHA-256 of the CA public key blob that signed it, lowercase hex.
    pub ca_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

fn no(why: impl Into<String>) -> Refused {
    Refused(why.into())
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, at: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Refused> {
        let end = self.at.checked_add(n).ok_or_else(|| no("truncated certificate"))?;
        let out = self.buf.get(self.at..end).ok_or_else(|| no("truncated certificate"))?;
        self.at = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, Refused> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, Refused> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn string(&mut self) -> Result<&'a [u8], Refused> {
        let n = self.u32()? as usize;
        self.bytes(n)
    }

    fn text(&mut self) -> Result<String, Refused> {
        String::from_utf8(self.string()?.to_vec()).map_err(|_| no("a certificate field is not UTF-8"))
    }

    fn done(&self) -> bool {
        self.at == self.buf.len()
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// The certificate blob from an OpenSSH line, `<type> <base64> [comment]`.
pub fn blob_from_line(line: &str) -> Result<(String, Vec<u8>), Refused> {
    let mut parts = line.split_whitespace();
    let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
        return Err(no("not an OpenSSH certificate line"));
    };
    let blob = BASE64.decode(b64.as_bytes()).map_err(|_| no("the certificate is not base64"))?;
    Ok((kind.to_string(), blob))
}

/// The certificate a session authenticated with, from the file sshd writes
/// when `ExposeAuthInfo yes` is set (`$SSH_USER_AUTH`). Each line is one
/// method that succeeded; the passkey certificate is the `publickey` line
/// whose key is a FIDO certificate. More than one is refused: which of them
/// the session "is" would be a guess.
pub fn from_user_auth(contents: &str) -> Result<String, Refused> {
    let mut found = Vec::new();
    for line in contents.lines() {
        let mut w = line.split_whitespace();
        if w.next() != Some("publickey") {
            continue;
        }
        let rest: Vec<&str> = w.collect();
        if rest.first().is_some_and(|k| FIDO_CERT_TYPES.contains(k)) && rest.len() >= 2 {
            found.push(format!("{} {}", rest[0], rest[1]));
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(no("the session did not authenticate with a FIDO key certificate")),
        _ => Err(no("the session authenticated with more than one FIDO key certificate")),
    }
}

/// Parse a certificate line and check it was signed by `ca_line` (an OpenSSH
/// public key line, as in `/etc/ssh/furcate_ca.pub`).
///
/// Validity times are returned, not judged: the caller knows what "now" is.
pub fn verify(cert_line: &str, ca_line: &str) -> Result<Certificate, Refused> {
    let (kind, blob) = blob_from_line(cert_line)?;
    if !FIDO_CERT_TYPES.contains(&kind.as_str()) {
        return Err(no(format!("`{kind}` is not a FIDO key certificate")));
    }
    let (_, ca_blob) = blob_from_line(ca_line)?;

    let mut r = Reader::new(&blob);
    if r.text()? != kind {
        return Err(no("the certificate's type does not match its encoding"));
    }
    let _nonce = r.string()?;
    // The subject key, re-encoded as the plain key so its digest is the one a
    // login order names.
    let mut plain = Vec::new();
    let application;
    if kind.starts_with("sk-ecdsa") {
        let curve = r.string()?;
        if curve != b"nistp256" {
            return Err(no("an sk-ecdsa key must be on nistp256"));
        }
        let q = r.string()?;
        application = r.text()?;
        put_string(&mut plain, b"sk-ecdsa-sha2-nistp256@openssh.com");
        put_string(&mut plain, curve);
        put_string(&mut plain, q);
        put_string(&mut plain, application.as_bytes());
    } else {
        let pk = r.string()?;
        if pk.len() != 32 {
            return Err(no("an sk-ed25519 key is 32 bytes"));
        }
        application = r.text()?;
        put_string(&mut plain, b"sk-ssh-ed25519@openssh.com");
        put_string(&mut plain, pk);
        put_string(&mut plain, application.as_bytes());
    }
    let serial = r.u64()?;
    let cert_type = r.u32()?;
    if cert_type != 1 {
        return Err(no("this is a host certificate, not a user certificate"));
    }
    let key_id = r.text()?;
    let mut principals = Vec::new();
    {
        let packed = r.string()?;
        let mut p = Reader::new(packed);
        while !p.done() {
            principals.push(p.text()?);
        }
    }
    let valid_after = r.u64()?;
    let valid_before = r.u64()?;
    let mut force_command = None;
    {
        let packed = r.string()?;
        let mut c = Reader::new(packed);
        while !c.done() {
            let name = c.text()?;
            let data = c.string()?;
            if name == "force-command" {
                let mut d = Reader::new(data);
                force_command = Some(d.text()?);
            }
        }
    }
    let _extensions = r.string()?;
    let _reserved = r.string()?;
    let signature_key = r.string()?;
    let signed_len = r.at;
    let signature = r.string()?;
    if !r.done() {
        return Err(no("trailing bytes after the certificate's signature"));
    }
    if signature_key != ca_blob.as_slice() {
        return Err(no("the certificate was not signed by this site's CA"));
    }
    check_signature(&ca_blob, &blob[..signed_len], signature)?;

    Ok(Certificate {
        kind,
        key_sha256: hex::encode(Sha256::digest(&plain)),
        application,
        serial,
        key_id,
        principals,
        valid_after,
        valid_before,
        force_command,
        ca_sha256: hex::encode(Sha256::digest(&ca_blob)),
    })
}

fn check_signature(ca_blob: &[u8], signed: &[u8], signature: &[u8]) -> Result<(), Refused> {
    let mut k = Reader::new(ca_blob);
    let ca_kind = k.text()?;
    let mut s = Reader::new(signature);
    let sig_kind = s.text()?;
    let sig = s.string()?;
    match ca_kind.as_str() {
        "ssh-ed25519" => {
            if sig_kind != "ssh-ed25519" {
                return Err(no("the CA signature is not ssh-ed25519"));
            }
            let pk: [u8; 32] = k.string()?.try_into().map_err(|_| no("bad ed25519 CA key"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| no("bad ed25519 CA key"))?;
            let sig: [u8; 64] = sig.try_into().map_err(|_| no("bad ed25519 signature"))?;
            vk.verify_strict(signed, &ed25519_dalek::Signature::from_bytes(&sig))
                .map_err(|_| no("the CA signature does not verify"))
        }
        "ecdsa-sha2-nistp256" => {
            use p256::ecdsa::signature::Verifier;
            if sig_kind != "ecdsa-sha2-nistp256" {
                return Err(no("the CA signature is not ecdsa-sha2-nistp256"));
            }
            let _curve = k.string()?;
            let q = k.string()?;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(q).map_err(|_| no("bad P-256 CA key"))?;
            let mut rs = Reader::new(sig);
            let mut rs64 = [0u8; 64];
            rs64[..32].copy_from_slice(&mpint32(rs.string()?)?);
            rs64[32..].copy_from_slice(&mpint32(rs.string()?)?);
            let sig = p256::ecdsa::Signature::from_slice(&rs64).map_err(|_| no("bad P-256 signature"))?;
            vk.verify(signed, &sig).map_err(|_| no("the CA signature does not verify"))
        }
        other => Err(no(format!("a `{other}` CA is not supported"))),
    }
}

/// An SSH mpint as a 32-byte big-endian scalar.
fn mpint32(m: &[u8]) -> Result<[u8; 32], Refused> {
    let m = match m {
        [0, rest @ ..] => rest,
        _ => m,
    };
    if m.len() > 32 {
        return Err(no("an ECDSA scalar is longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - m.len()..].copy_from_slice(m);
    Ok(out)
}

/// Encode a user certificate and sign it with an Ed25519 CA. For tests of the
/// programs that read certificates; the CA in production is `ssh-keygen`.
#[cfg(any(test, feature = "test-authenticator"))]
#[allow(clippy::too_many_arguments)]
pub fn sign_for_test(
    ca: &ed25519_dalek::SigningKey,
    subject_q: &[u8],
    application: &str,
    serial: u64,
    key_id: &str,
    principals: &[&str],
    valid: (u64, u64),
    force_command: Option<&str>,
) -> String {
    use ed25519_dalek::Signer;
    let kind = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com";
    let mut b = Vec::new();
    put_string(&mut b, kind.as_bytes());
    put_string(&mut b, &[7u8; 32]);
    put_string(&mut b, b"nistp256");
    put_string(&mut b, subject_q);
    put_string(&mut b, application.as_bytes());
    b.extend_from_slice(&serial.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut b, key_id.as_bytes());
    let mut p = Vec::new();
    for x in principals {
        put_string(&mut p, x.as_bytes());
    }
    put_string(&mut b, &p);
    b.extend_from_slice(&valid.0.to_be_bytes());
    b.extend_from_slice(&valid.1.to_be_bytes());
    let mut c = Vec::new();
    if let Some(fc) = force_command {
        put_string(&mut c, b"force-command");
        let mut d = Vec::new();
        put_string(&mut d, fc.as_bytes());
        put_string(&mut c, &d);
    }
    put_string(&mut b, &c);
    put_string(&mut b, b"");
    put_string(&mut b, b"");
    put_string(&mut b, &ca_blob_for_test(ca));
    let sig = ca.sign(&b);
    let mut s = Vec::new();
    put_string(&mut s, b"ssh-ed25519");
    put_string(&mut s, &sig.to_bytes());
    put_string(&mut b, &s);
    format!("{kind} {}", BASE64.encode(&b))
}

#[cfg(any(test, feature = "test-authenticator"))]
fn ca_blob_for_test(ca: &ed25519_dalek::SigningKey) -> Vec<u8> {
    let mut k = Vec::new();
    put_string(&mut k, b"ssh-ed25519");
    put_string(&mut k, ca.verifying_key().as_bytes());
    k
}

/// The OpenSSH public key line of a test CA.
#[cfg(any(test, feature = "test-authenticator"))]
pub fn ca_line_for_test(ca: &ed25519_dalek::SigningKey) -> String {
    format!("ssh-ed25519 {}", BASE64.encode(&ca_blob_for_test(ca)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn q() -> Vec<u8> {
        let sk = p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap();
        sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn cert(ca: &ed25519_dalek::SigningKey) -> String {
        sign_for_test(
            ca,
            &q(),
            "ssh:",
            42,
            "furcate:passkey:ab:42",
            &["ops@node-a"],
            (100, 200),
            Some("/usr/bin/furcatectl ssh-session --order ab --by c1 --principal ops@node-a"),
        )
    }

    #[test]
    fn a_certificate_from_the_ca_reads_back_every_field() {
        let c = verify(&cert(&ca(1)), &ca_line_for_test(&ca(1))).unwrap();
        assert_eq!(c.serial, 42);
        assert_eq!(c.principals, vec!["ops@node-a".to_string()]);
        assert_eq!((c.valid_after, c.valid_before), (100, 200));
        assert_eq!(c.key_id, "furcate:passkey:ab:42");
        assert!(c.force_command.unwrap().contains("--order ab"));
        assert_eq!(c.application, "ssh:");
    }

    #[test]
    fn the_key_digest_is_the_one_a_login_order_names() {
        let c = verify(&cert(&ca(1)), &ca_line_for_test(&ca(1))).unwrap();
        let mut plain = Vec::new();
        put_string(&mut plain, b"sk-ecdsa-sha2-nistp256@openssh.com");
        put_string(&mut plain, b"nistp256");
        put_string(&mut plain, &q());
        put_string(&mut plain, b"ssh:");
        let line = format!("sk-ecdsa-sha2-nistp256@openssh.com {}", BASE64.encode(&plain));
        let (_, d) = crate::order::ssh_key_sha256(&line).unwrap();
        assert_eq!(c.key_sha256, d);
    }

    #[test]
    fn another_ca_is_refused() {
        let e = verify(&cert(&ca(1)), &ca_line_for_test(&ca(2))).unwrap_err();
        assert!(e.0.contains("not signed by this site's CA"), "{e}");
    }

    #[test]
    fn a_changed_byte_breaks_the_signature() {
        let (kind, mut blob) = blob_from_line(&cert(&ca(1))).unwrap();
        // The serial sits after type, nonce, curve, key and application.
        let at = blob.len() / 3;
        blob[at] ^= 1;
        let line = format!("{kind} {}", BASE64.encode(&blob));
        assert!(verify(&line, &ca_line_for_test(&ca(1))).is_err());
    }

    #[test]
    fn a_plain_key_certificate_is_not_a_passkey_login() {
        let line = cert(&ca(1)).replacen("sk-ecdsa-sha2-nistp256-cert", "ecdsa-sha2-nistp256-cert", 1);
        assert!(verify(&line, &ca_line_for_test(&ca(1))).unwrap_err().0.contains("not a FIDO"));
    }

    #[test]
    fn the_user_auth_file_yields_exactly_one_fido_certificate() {
        let c = cert(&ca(1));
        let f = format!("keyboard-interactive\npublickey {c}\n");
        assert_eq!(from_user_auth(&f).unwrap(), c);
        assert!(from_user_auth("publickey ssh-ed25519 AAAA\n").is_err());
        assert!(from_user_auth(&format!("publickey {c}\npublickey {c}\n")).is_err());
    }
}
