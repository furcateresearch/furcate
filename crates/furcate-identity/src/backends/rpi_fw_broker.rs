//! The Raspberry Pi OTP device key, through the board's signing broker.
//!
//! The same key as [`super::rpi_fw_crypto`], reached a different way. A board
//! OS that keeps the firmware mailbox to root runs a small broker on a unix
//! socket instead, and a member of its group asks it to sign:
//!
//! ```text
//! {"op":"sign","key_id":1,"alg":"ecdsa-p256-sha256","msg_b64":"..."}
//!   -> {"ok":true,"key_id":1,"sig_der_b64":"...","sig_raw_b64":"..."}
//! {"op":"pubkey","key_id":1}
//!   -> {"ok":true,"key_id":1,"spki_der_b64":"..."}
//! ```
//!
//! One JSON object per line, one request per connection. The broker hashes
//! the message with SHA-256 and the firmware signs the digest, exactly as the
//! direct path does, so the public key, the node ID derived from it and every
//! signature verify the same whichever path produced them.
//!
//! The broker offers `sign` and `pubkey` and nothing else: no HMAC, so a board
//! reached this way derives no custody key from its silicon, and no raw read
//! of the key, which is the point of having a broker. The class is `Device`
//! for the reasons the direct backend gives.

use crate::rot::{AssuranceClass, PcrSet, Quote, RootOfTrust};
use anyhow::{anyhow, bail, Context as _, Result};
use data_encoding::BASE64;
use serde_json::{json, Value};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::rpi_fw_crypto::DEVICE_KEY_ID;

/// Where the board OS puts the broker's socket.
pub const BROKER_SOCKET: &str = "/run/furcate-os/fwcrypto.sock";

/// The broker refuses messages larger than this.
pub const MAX_MESSAGE: usize = 1 << 20;

/// How long one request may take. The firmware signs in milliseconds; a
/// broker that has not answered in this long is not going to.
const TIMEOUT: Duration = Duration::from_secs(10);

pub struct RpiFwBroker {
    socket: PathBuf,
    key_id: u32,
    /// DER SubjectPublicKeyInfo of the slot's key, read at open.
    public: Vec<u8>,
}

impl RpiFwBroker {
    /// Open the device-unique key through the broker at `socket`. Fails when
    /// the broker does not answer or returns no key.
    pub fn open(socket: &Path) -> Result<Self> {
        let key_id = DEVICE_KEY_ID;
        let reply = request(socket, &json!({ "op": "pubkey", "key_id": key_id }))?;
        let public = field_b64(&reply, "spki_der_b64")?;
        if public.is_empty() {
            bail!("the signing broker returned an empty public key for slot {key_id}");
        }
        Ok(Self { socket: socket.to_path_buf(), key_id, public })
    }

    /// The socket this key is reached through.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() > MAX_MESSAGE {
            bail!("a {}-byte message is larger than the broker signs ({MAX_MESSAGE} bytes)", message.len());
        }
        let reply = request(
            &self.socket,
            &json!({
                "op": "sign",
                "key_id": self.key_id,
                "alg": "ecdsa-p256-sha256",
                "msg_b64": BASE64.encode(message),
            }),
        )?;
        let signature = field_b64(&reply, "sig_der_b64")?;
        if signature.is_empty() {
            bail!("the signing broker returned an empty signature");
        }
        Ok(signature)
    }

    fn boot_state() -> PcrSet {
        use sha2::{Digest, Sha256};
        let signed = std::fs::read("/proc/device-tree/chosen/bootloader/signed").unwrap_or_default();
        let mut values = std::collections::BTreeMap::new();
        values.insert(0, Sha256::digest(&signed).to_vec());
        PcrSet { bank: "sha256".to_string(), values }
    }
}

/// One request, one reply line.
fn request(socket: &Path, body: &Value) -> Result<Value> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to the signing broker at {}", socket.display()))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    let mut line = serde_json::to_vec(body).context("encoding the broker request")?;
    line.push(b'\n');
    stream.write_all(&line).context("writing to the signing broker")?;
    stream.flush().ok();
    let mut reply = String::new();
    BufReader::new(&stream)
        .read_line(&mut reply)
        .context("reading the signing broker's reply")?;
    parse_reply(&reply)
}

/// A reply line as a JSON object with `"ok": true`, or the broker's error.
pub fn parse_reply(line: &str) -> Result<Value> {
    let line = line.trim();
    if line.is_empty() {
        bail!("the signing broker closed the connection without a reply");
    }
    let v: Value = serde_json::from_str(line).map_err(|e| anyhow!("the signing broker's reply is not JSON: {e}"))?;
    match v.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(v),
        Some(false) => bail!(
            "the signing broker refused: {}",
            v.get("error").and_then(Value::as_str).unwrap_or("no reason given")
        ),
        None => bail!("the signing broker's reply has no `ok`"),
    }
}

fn field_b64(v: &Value, name: &str) -> Result<Vec<u8>> {
    let s = v
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the signing broker's reply has no `{name}`"))?;
    BASE64
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("the signing broker's `{name}` is not base64: {e}"))
}

impl RootOfTrust for RpiFwBroker {
    fn assurance(&self) -> AssuranceClass {
        AssuranceClass::Device
    }

    fn message_signer(&self) -> Option<&dyn crate::signer::MessageSigner> {
        Some(self)
    }

    fn ek_public(&self) -> Result<Vec<u8>> {
        Ok(self.public.clone())
    }

    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn ak_public(&self) -> Result<Vec<u8>> {
        Ok(self.public.clone())
    }

    fn pcrs(&self) -> Result<PcrSet> {
        Ok(Self::boot_state())
    }

    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        if nonce.is_empty() {
            bail!("a quote without a nonce is replayable; supply one");
        }
        let pcrs = Self::boot_state();
        // The same message the direct backend signs, so a verifier needs no
        // second rule for the same key.
        let mut message = Vec::new();
        message.extend_from_slice(b"furcate-rpifw-quote\0");
        message.extend_from_slice(nonce);
        for (idx, digest) in &pcrs.values {
            message.extend_from_slice(&idx.to_be_bytes());
            message.extend_from_slice(digest);
        }
        let signature = self.sign_message(&message)?;
        Ok(Quote { message, signature, nonce: nonce.to_vec(), pcrs })
    }
}

impl crate::signer::MessageSigner for RpiFwBroker {
    fn public_key(&self) -> Result<crate::signer::SignerKey> {
        Ok(crate::signer::SignerKey::P256(self.public.clone()))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_message(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn replies_parse_and_refusals_carry_the_reason() {
        assert!(parse_reply("{\"ok\":true,\"key_id\":1}\n").is_ok());
        let e = parse_reply("{\"ok\":false,\"error\":\"key 1 sign-locked\"}").unwrap_err();
        assert!(e.to_string().contains("key 1 sign-locked"), "{e}");
        assert!(parse_reply("").is_err());
        assert!(parse_reply("{\"key_id\":1}").is_err());
        assert!(parse_reply("not json").is_err());
    }

    /// A broker on a socket in a scratch directory that answers the way the
    /// board's does, signing with a key it holds.
    fn fake_broker(dir: &Path, key: p256::ecdsa::SigningKey, answers: usize) -> PathBuf {
        use p256::ecdsa::signature::Signer as _;
        let path = dir.join("fwcrypto.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(answers) {
                let stream = stream.unwrap();
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                let reply = match req["op"].as_str() {
                    Some("pubkey") => {
                        // id-ecPublicKey, prime256v1, then the uncompressed point.
                        let mut spki = vec![
                            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
                        ];
                        spki.extend_from_slice(key.verifying_key().to_sec1_point(false).as_bytes());
                        json!({"ok": true, "key_id": 1, "spki_der_b64": BASE64.encode(&spki)})
                    }
                    Some("sign") => {
                        assert_eq!(req["alg"], "ecdsa-p256-sha256");
                        let msg = BASE64.decode(req["msg_b64"].as_str().unwrap().as_bytes()).unwrap();
                        let sig: p256::ecdsa::Signature = key.sign(&msg);
                        json!({"ok": true, "key_id": 1,
                               "sig_der_b64": BASE64.encode(sig.to_der().as_bytes()),
                               "sig_raw_b64": BASE64.encode(&sig.to_bytes())})
                    }
                    _ => json!({"ok": false, "error": "unknown op"}),
                };
                let mut out = serde_json::to_vec(&reply).unwrap();
                out.push(b'\n');
                (&stream).write_all(&out).unwrap();
            }
        });
        path
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-broker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn signs_through_the_broker_and_the_signature_is_the_keys() {
        use crate::signer::{MessageSigner as _, SignerKey};
        use p256::ecdsa::signature::Verifier as _;
        let dir = scratch("sign");
        let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let socket = fake_broker(&dir, key.clone(), 2);
        let broker = RpiFwBroker::open(&socket).unwrap();
        let SignerKey::P256(spki) = broker.public_key().unwrap() else { panic!("not a P-256 key") };
        assert_eq!(spki.len(), 91, "a DER SubjectPublicKeyInfo");
        let sig = broker.sign(b"a receipt").unwrap();
        let sig = p256::ecdsa::Signature::from_der(&sig).unwrap();
        key.verifying_key().verify(b"a receipt", &sig).unwrap();
        // The node ID comes from the key, so it is the one the direct path gave.
        assert_eq!(broker.node_id().unwrap(), crate::node_id::NodeId::from_ek_public(&spki));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_broker_is_an_error_not_a_key() {
        let dir = scratch("absent");
        let e = RpiFwBroker::open(&dir.join("fwcrypto.sock")).err().expect("no socket, no key");
        assert!(e.to_string().contains("signing broker"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
