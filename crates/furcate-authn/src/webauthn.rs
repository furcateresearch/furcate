//! Passkey assertions as the approval of an order.
//!
//! A person approves an order by making a WebAuthn assertion whose challenge
//! is the order's hash. The private key never leaves their authenticator; what
//! a node holds is the public half, recorded when the credential was admitted.
//! Nothing here generates, derives, wraps or stores a private key, and nothing
//! in a browser does either.
//!
//! ## The challenge
//!
//! 56 bytes, sent to the authenticator as `publicKey.challenge` and returned
//! base64url-encoded without padding in `clientDataJSON.challenge`:
//!
//! ```text
//! bytes  0..32   SHA-256 of the canonical order (see `crate::order`)
//! bytes 32..48   a nonce issued by the node that will verify the assertion
//! bytes 48..56   the nonce's expiry, unix seconds, unsigned big-endian
//! ```
//!
//! The order hash makes the approval about one order and nothing else. The
//! nonce is issued by the target node, recorded there, and spent on first use,
//! so an assertion cannot be replayed even within the order's own lifetime.
//! The expiry is inside the signed bytes so a node can refuse a stale approval
//! without trusting anything the client says about time.
//!
//! Enrolment uses the same layout with the first 32 bytes set to
//! SHA-256(`furcate-enrol/1`), so a creation ceremony is also bound to a nonce
//! the node issued. Cancelling an admission that is still in its cancel window
//! uses SHA-256(`furcate-cancel/1\n` || credential id), so that assertion
//! cancels that one admission and nothing else.
//!
//! ## Each credential keeps its own RP ID
//!
//! A credential is verified against the RP ID it was created for, which the
//! node records at enrolment, and an assertion must come from `https://` on
//! that RP ID or a subdomain of it. The site's RP ID is only the default an
//! enrolment uses when it names none. There is no list of related origins: a
//! credential made for one RP ID never verifies for another.
//!
//! ## What a node checks
//!
//! - `rpIdHash` is SHA-256 of the credential's own RP ID.
//! - The user-present and user-verified flags are both set: a person was there
//!   and unlocked the authenticator. The backup flags are recorded, never
//!   refused: a synced passkey approves like any other.
//! - `clientDataJSON.type` is `webauthn.get` (`webauthn.create` at enrolment),
//!   `crossOrigin` is not true, and `origin` is `https://` on the credential's
//!   RP ID or a subdomain of it.
//! - The challenge is exactly the 56 bytes above.
//! - The signature over `authenticatorData || SHA-256(clientDataJSON)` verifies
//!   under the credential's COSE public key: ES256 (P-256) or EdDSA (Ed25519).
//! - The signature counter advanced, unless both the stored and the presented
//!   values are zero (authenticators that do not count report zero).
//! - The credential is past its cancel window, if it was admitted with one.
//!
//! ## Independence is read from the registration, not declared
//!
//! At enrolment the node reads the authenticator data inside the attestation
//! object, over the enrolment challenge it issued, and records the AAGUID and
//! the backup-eligible (BE) and backed-up (BS) flags. Those decide the
//! credential's independence root ([`Credential::root`]):
//!
//! - a device-bound credential (BE clear) is a root of its own;
//! - a backup-eligible credential belongs to its provider's sync account, so
//!   all of them from one AAGUID are one root. Providers that report an
//!   all-zero AAGUID therefore count once between them, which errs toward
//!   needing more approvals, never fewer.
//!
//! The attestation statement is not examined: whether to trust a credential is
//! decided by whoever admits it, not by a certificate from its manufacturer.
//! A [`Tally`] counts roots, not credentials. How many are needed per action is
//! configuration — see [`Thresholds`] — and none may be zero.
//!
//! ## Adding a passkey while a site has fewer than two roots
//!
//! A credential admitted while the site's usable credentials make fewer than
//! [`MIN_INDEPENDENT_ROOTS`] roots is not usable at once: it waits out a cancel
//! window (set by governance), during which any credential already usable can
//! cancel it with one assertion. At two or more roots, admission takes effect
//! when it is approved. The first credential on an empty roster has nobody to
//! cancel it and is usable at once. The window is kept in the roster itself,
//! so a restart does not shorten or skip it.

use crate::order::{Action, Order};
use crate::Refusal;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Length of the challenge in bytes.
pub const CHALLENGE_LEN: usize = 32 + 16 + 8;

/// What the first 32 bytes of an enrolment challenge are the hash of.
pub const ENROL_DOMAIN: &[u8] = b"furcate-enrol/1";

/// Prefix of what a cancellation challenge's first 32 bytes hash.
pub const CANCEL_DOMAIN: &[u8] = b"furcate-cancel/1\n";

/// Below this many independent roots, a new credential waits out a cancel
/// window before it is usable.
pub const MIN_INDEPENDENT_ROOTS: usize = 2;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

/// What the first 32 bytes of a challenge to cancel the pending admission of
/// `credential_id` are.
pub fn cancel_hash(credential_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CANCEL_DOMAIN);
    h.update(credential_id.trim_end_matches('=').as_bytes());
    h.finalize().into()
}

/// A challenge, before encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub order_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
}

impl Challenge {
    /// The challenge for enrolling a credential.
    pub fn enrolment(nonce: [u8; 16], expires_at: u64) -> Self {
        Self {
            order_hash: Sha256::digest(ENROL_DOMAIN).into(),
            nonce,
            expires_at,
        }
    }

    /// A challenge for cancelling the pending admission of one credential.
    pub fn cancel(credential_id: &str, nonce: [u8; 16], expires_at: u64) -> Self {
        Self {
            order_hash: cancel_hash(credential_id),
            nonce,
            expires_at,
        }
    }

    pub fn bytes(&self) -> [u8; CHALLENGE_LEN] {
        let mut out = [0u8; CHALLENGE_LEN];
        out[..32].copy_from_slice(&self.order_hash);
        out[32..48].copy_from_slice(&self.nonce);
        out[48..].copy_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// As it appears in `clientDataJSON.challenge`.
    pub fn encoded(&self) -> String {
        BASE64URL_NOPAD.encode(&self.bytes())
    }
}

/// A credential public key, as parsed from its COSE encoding.
#[derive(Clone, Debug)]
pub enum PublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    EdDsa(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// Parse a COSE_Key (RFC 9052). Only the two algorithms a node will
    /// verify are accepted; anything else is refused rather than ignored.
    pub fn from_cose(bytes: &[u8]) -> Result<Self, String> {
        use ciborium::value::Value;
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|e| format!("COSE key is not CBOR: {e}"))?;
        let Value::Map(entries) = value else {
            return Err("COSE key is not a map".into());
        };
        let int = |label: i64| -> Option<i128> {
            entries.iter().find_map(|(k, v)| match (k, v) {
                (Value::Integer(k), Value::Integer(v)) if i128::from(*k) == label as i128 => {
                    Some(i128::from(*v))
                }
                _ => None,
            })
        };
        let bytes_at = |label: i64| -> Option<&[u8]> {
            entries.iter().find_map(|(k, v)| match (k, v) {
                (Value::Integer(k), Value::Bytes(b)) if i128::from(*k) == label as i128 => {
                    Some(b.as_slice())
                }
                _ => None,
            })
        };
        match (int(1), int(3), int(-1)) {
            // kty EC2, alg ES256, crv P-256.
            (Some(2), Some(-7), Some(1)) => {
                let (Some(x), Some(y)) = (bytes_at(-2), bytes_at(-3)) else {
                    return Err("ES256 key is missing a coordinate".into());
                };
                if x.len() != 32 || y.len() != 32 {
                    return Err("ES256 coordinates must be 32 bytes".into());
                }
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..33].copy_from_slice(x);
                sec1[33..].copy_from_slice(y);
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map(PublicKey::Es256)
                    .map_err(|_| "ES256 key is not a point on P-256".into())
            }
            // kty OKP, alg EdDSA, crv Ed25519.
            (Some(1), Some(-8), Some(6)) => {
                let Some(x) = bytes_at(-2) else {
                    return Err("EdDSA key is missing its public value".into());
                };
                let arr: [u8; 32] = x
                    .try_into()
                    .map_err(|_| "Ed25519 public key must be 32 bytes".to_string())?;
                ed25519_dalek::VerifyingKey::from_bytes(&arr)
                    .map(PublicKey::EdDsa)
                    .map_err(|_| "Ed25519 public key is not valid".into())
            }
            _ => Err("only ES256 (P-256) and EdDSA (Ed25519) credentials are accepted".into()),
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            PublicKey::Es256(key) => {
                use p256::ecdsa::signature::Verifier;
                let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                // Authenticators are not required to emit low-S signatures,
                // and the curve accepts both; normalising here means one
                // authenticator's choice does not decide whether it works.
                let sig = sig.normalize_s();
                key.verify(message, &sig).is_ok()
            }
            PublicKey::EdDsa(key) => {
                use ed25519_dalek::Verifier;
                let Ok(arr) = <[u8; 64]>::try_from(signature) else {
                    return false;
                };
                key.verify(message, &ed25519_dalek::Signature::from_bytes(&arr))
                    .is_ok()
            }
        }
    }
}

/// A credential admitted to approve orders.
///
/// Everything here but the label was read from the credential's own
/// registration: nothing about its independence is declared by an operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// The WebAuthn credential id, base64url without padding.
    pub id: String,
    /// The COSE public key, lowercase hex, exactly as the authenticator
    /// reported it at enrolment.
    pub cose_key: String,
    /// The RP ID the credential was created for. Assertions are checked
    /// against this, and must come from `https://` on it or beneath it.
    pub rp_id: String,
    /// The origin the creation ceremony ran on, for the record.
    pub enrolled_origin: String,
    /// The authenticator's AAGUID, lowercase hex, from its registration data.
    pub aaguid: String,
    /// BE at registration: the key may be synced to other devices.
    pub backup_eligible: bool,
    /// BS at registration: the key was synced when it was made.
    pub backed_up: bool,
    /// When the credential may first approve. Later than `admitted_at` when
    /// it was admitted with a cancel window.
    pub usable_from: u64,
    /// The highest signature counter seen.
    #[serde(default)]
    pub sign_count: u32,
    /// What a person called it, for the roster.
    #[serde(default)]
    pub label: String,
    pub admitted_at: u64,
}

impl Credential {
    /// A credential from a verified enrolment, not yet admitted.
    pub fn from_enrolled(e: &Enrolled, label: String, now: u64) -> Self {
        Self {
            id: e.credential_id.clone(),
            cose_key: e.cose_key.clone(),
            rp_id: e.rp_id.clone(),
            enrolled_origin: e.origin.clone(),
            aaguid: e.aaguid.clone(),
            backup_eligible: e.backup_eligible,
            backed_up: e.backed_up,
            usable_from: now,
            sign_count: e.sign_count,
            label,
            admitted_at: now,
        }
    }

    /// SHA-256 of the COSE key bytes, lowercase hex: what an `admit` order
    /// names.
    pub fn key_sha256(&self) -> String {
        let bytes = hex::decode(&self.cose_key).unwrap_or_default();
        hex::encode(Sha256::digest(bytes))
    }

    /// The independence root this credential counts under. A device-bound key
    /// is its own root; a backup-eligible key is one of its provider's, and
    /// every key a provider syncs counts once between them.
    pub fn root(&self) -> String {
        if self.backup_eligible {
            format!("provider:{}", self.aaguid)
        } else {
            format!("device:{}", self.id)
        }
    }

    /// Whether the credential is past any cancel window at `now`.
    pub fn usable(&self, now: u64) -> bool {
        now >= self.usable_from
    }

    fn public_key(&self) -> Result<PublicKey, Refusal> {
        let bytes = hex::decode(&self.cose_key)
            .map_err(|_| Refusal::new("the stored credential key is not hex"))?;
        PublicKey::from_cose(&bytes).map_err(Refusal::new)
    }
}

/// One assertion, as the browser returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    /// base64url, no padding: `PublicKeyCredential.rawId`.
    pub credential_id: String,
    /// base64url, no padding: `response.authenticatorData`.
    pub authenticator_data: String,
    /// base64url, no padding: `response.clientDataJSON`.
    pub client_data_json: String,
    /// base64url, no padding: `response.signature`.
    pub signature: String,
}

/// A creation ceremony's result, as the browser returns it. Only public
/// material: the credential id, and the attestation object whose
/// authenticator data carries the public key, the AAGUID and the backup flags.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolment {
    pub credential_id: String,
    /// base64url, no padding: `response.attestationObject`.
    pub attestation_object: String,
    /// base64url, no padding: `response.clientDataJSON`.
    pub client_data_json: String,
}

/// A credential that passed the creation checks, not yet admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolled {
    pub credential_id: String,
    pub cose_key: String,
    pub key_sha256: String,
    pub sign_count: u32,
    /// The RP ID the credential was created for.
    pub rp_id: String,
    /// The origin the ceremony ran on.
    pub origin: String,
    /// Lowercase hex.
    pub aaguid: String,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

/// An assertion that verified. Only this module makes one, so a [`Tally`]
/// cannot be fed anything that did not pass the checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    credential_id: String,
    root: String,
    order_hash: [u8; 32],
    sign_count: u32,
}

impl Verified {
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// The independence root the approval counts under.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The first 32 bytes of the challenge the assertion signed.
    pub fn order_hash(&self) -> [u8; 32] {
        self.order_hash
    }

    /// The counter to store for the credential now.
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
}

fn b64(field: &str, value: &str) -> Result<Vec<u8>, Refusal> {
    BASE64URL_NOPAD
        .decode(value.trim_end_matches('=').as_bytes())
        .map_err(|_| Refusal::new(format!("`{field}` is not base64url")))
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// Whether `origin` is `https://` on the RP ID or a subdomain of it.
pub fn origin_in_zone(origin: &str, rp_id: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    if rest.contains('/') || rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return false;
    }
    let host = match rest.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        Some(_) => return false,
        None => rest,
    };
    let host = host.to_ascii_lowercase();
    let rp = rp_id.to_ascii_lowercase();
    !rp.is_empty() && (host == rp || host.ends_with(&format!(".{rp}")))
}

/// The checks shared by creation and assertion. Returns the origin.
fn check_client_data(
    raw: &[u8],
    kind: &str,
    rp_id: &str,
    challenge: &Challenge,
) -> Result<String, Refusal> {
    let cd: ClientData = serde_json::from_slice(raw)
        .map_err(|_| Refusal::new("clientDataJSON is not the JSON a browser produces"))?;
    if cd.kind != kind {
        return Err(Refusal::new(format!(
            "clientDataJSON.type is `{}`, not `{kind}`",
            cd.kind
        )));
    }
    if cd.cross_origin == Some(true) {
        return Err(Refusal::new("the ceremony ran in a cross-origin frame"));
    }
    if !origin_in_zone(&cd.origin, rp_id) {
        return Err(Refusal::new(format!(
            "origin `{}` is not https on `{rp_id}` or beneath it",
            cd.origin
        )));
    }
    let presented = b64("clientDataJSON.challenge", &cd.challenge)?;
    if presented.as_slice() != challenge.bytes().as_slice() {
        return Err(Refusal::new(
            "the challenge is not the one this node issued for this order",
        ));
    }
    Ok(cd.origin)
}

struct AuthData<'a> {
    raw: &'a [u8],
    flags: u8,
    sign_count: u32,
}

fn check_auth_data<'a>(raw: &'a [u8], rp_id: &str) -> Result<AuthData<'a>, Refusal> {
    if raw.len() < 37 {
        return Err(Refusal::new("authenticator data is too short"));
    }
    let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if raw[..32] != rp_hash {
        return Err(Refusal::new(format!(
            "the credential was not made for `{rp_id}`"
        )));
    }
    let flags = raw[32];
    if flags & FLAG_UP == 0 {
        return Err(Refusal::new(
            "the authenticator did not see a person present",
        ));
    }
    if flags & FLAG_UV == 0 {
        return Err(Refusal::new(
            "the authenticator did not verify the person (no PIN, biometric or unlock)",
        ));
    }
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(Refusal::new(
            "the authenticator data says the key is backed up but not backup-eligible, \
             which no authenticator can truthfully report",
        ));
    }
    let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);
    Ok(AuthData {
        raw,
        flags,
        sign_count,
    })
}

/// Verify one assertion over one order.
///
/// The assertion is checked against the credential's own RP ID. `challenge` is
/// what the node recorded when it issued the nonce; the caller has already
/// checked the nonce is outstanding and unexpired, and spends it whatever this
/// returns.
pub fn verify_assertion(
    credential: &Credential,
    assertion: &Assertion,
    challenge: &Challenge,
    now: u64,
) -> Result<Verified, Refusal> {
    if now >= challenge.expires_at {
        return Err(Refusal::new(format!(
            "the approval expired at {}; it is now {now}",
            challenge.expires_at
        )));
    }
    if !credential.usable(now) {
        return Err(Refusal::new(format!(
            "credential {} was added while the site had fewer than {MIN_INDEPENDENT_ROOTS} \
             independent roots and is in its cancel window until {}",
            credential.id, credential.usable_from
        )));
    }
    let presented = check_signed(credential, assertion, challenge)?;

    // Checked after the signature, so an unsigned counter cannot be used to
    // make an honest credential look cloned.
    let stored = credential.sign_count;
    if (stored != 0 || presented != 0) && presented <= stored {
        return Err(Refusal::new(format!(
            "the signature counter did not advance ({stored} stored, {presented} presented); \
             this credential may have been copied"
        )));
    }

    Ok(Verified {
        credential_id: credential.id.clone(),
        root: credential.root(),
        order_hash: challenge.order_hash,
        sign_count: presented,
    })
}

/// Check again an assertion that was counted before the node restarted.
///
/// The credential, signature, RP ID, flags, origin and challenge are checked
/// exactly as they were the first time, against the roster as it stands now, so
/// a credential revoked since no longer counts. Expiry and the signature
/// counter are not checked again: both were checked when the approval was
/// counted, the counter it carried has been stored since, and from then on the
/// approval stands or falls with the order's own expiry.
pub fn reverify_counted(
    credential: &Credential,
    assertion: &Assertion,
    challenge: &Challenge,
) -> Result<Verified, Refusal> {
    let presented = check_signed(credential, assertion, challenge)?;
    Ok(Verified {
        credential_id: credential.id.clone(),
        root: credential.root(),
        order_hash: challenge.order_hash,
        sign_count: presented,
    })
}

/// The checks that do not depend on when they run, against the credential's
/// own RP ID. Returns the counter the authenticator presented.
fn check_signed(
    credential: &Credential,
    assertion: &Assertion,
    challenge: &Challenge,
) -> Result<u32, Refusal> {
    if assertion.credential_id.trim_end_matches('=') != credential.id {
        return Err(Refusal::new("the assertion is from a different credential"));
    }
    let rp_id = credential.rp_id.as_str();
    let auth_raw = b64("authenticator_data", &assertion.authenticator_data)?;
    let client_raw = b64("client_data_json", &assertion.client_data_json)?;
    let signature = b64("signature", &assertion.signature)?;

    let auth = check_auth_data(&auth_raw, rp_id)?;
    check_client_data(&client_raw, "webauthn.get", rp_id, challenge)?;

    let mut signed = auth.raw.to_vec();
    signed.extend_from_slice(&Sha256::digest(&client_raw));
    if !credential.public_key()?.verify(&signed, &signature) {
        return Err(Refusal::new(
            "the signature does not verify under the admitted credential",
        ));
    }

    Ok(auth.sign_count)
}

/// The authenticator data inside an attestation object.
fn auth_data_of(attestation_object: &[u8]) -> Result<Vec<u8>, Refusal> {
    use ciborium::value::Value;
    let v: Value = ciborium::de::from_reader(attestation_object)
        .map_err(|_| Refusal::new("the attestation object is not CBOR"))?;
    let Value::Map(entries) = v else {
        return Err(Refusal::new("the attestation object is not a CBOR map"));
    };
    entries
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Bytes(b)) if k == "authData" => Some(b),
            _ => None,
        })
        .ok_or_else(|| Refusal::new("the attestation object carries no `authData`"))
}

/// Verify a creation ceremony and read what it made: the public key, the
/// AAGUID and the backup flags, all from the authenticator data inside the
/// attestation object, over the enrolment challenge the node issued.
///
/// `rp_id` is the RP ID the enrolment says the credential was made for. The
/// attestation statement is not examined: whether to trust this credential is
/// decided by whoever admits it, not by a certificate from its manufacturer.
pub fn verify_enrolment(
    enrolment: &Enrolment,
    rp_id: &str,
    challenge: &Challenge,
    now: u64,
) -> Result<Enrolled, Refusal> {
    if now >= challenge.expires_at {
        return Err(Refusal::new("the enrolment challenge has expired"));
    }
    let expected_domain: [u8; 32] = Sha256::digest(ENROL_DOMAIN).into();
    if challenge.order_hash != expected_domain {
        return Err(Refusal::new(
            "that challenge was issued for an order, not an enrolment",
        ));
    }
    let att_raw = b64("attestation_object", &enrolment.attestation_object)?;
    let client_raw = b64("client_data_json", &enrolment.client_data_json)?;
    let auth_raw = auth_data_of(&att_raw)?;
    let auth = check_auth_data(&auth_raw, rp_id)?;
    let origin = check_client_data(&client_raw, "webauthn.create", rp_id, challenge)?;
    if auth.flags & FLAG_AT == 0 {
        return Err(Refusal::new("the authenticator data carries no credential"));
    }
    let raw = auth.raw;
    if raw.len() < 55 {
        return Err(Refusal::new("the attested credential data is truncated"));
    }
    let aaguid = hex::encode(&raw[37..53]);
    let id_len = u16::from_be_bytes([raw[53], raw[54]]) as usize;
    let key_start = 55 + id_len;
    if raw.len() <= key_start {
        return Err(Refusal::new("the attested credential data is truncated"));
    }
    let id = BASE64URL_NOPAD.encode(&raw[55..key_start]);
    if id != enrolment.credential_id.trim_end_matches('=') {
        return Err(Refusal::new(
            "the credential id does not match the authenticator data",
        ));
    }
    // The COSE key runs to the end of the authenticator data unless extension
    // output follows it, so take exactly one CBOR item.
    let rest = &raw[key_start..];
    let mut cursor = std::io::Cursor::new(rest);
    let _: ciborium::value::Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|_| Refusal::new("the credential public key is not CBOR"))?;
    let cose = &rest[..cursor.position() as usize];
    PublicKey::from_cose(cose).map_err(Refusal::new)?;
    Ok(Enrolled {
        credential_id: id,
        cose_key: hex::encode(cose),
        key_sha256: hex::encode(Sha256::digest(cose)),
        sign_count: auth.sign_count,
        rp_id: rp_id.to_string(),
        origin,
        aaguid,
        backup_eligible: auth.flags & FLAG_BE != 0,
        backed_up: auth.flags & FLAG_BS != 0,
    })
}

/// How many independent approvals each action needs.
///
/// Configuration, set by whoever governs the site. The defaults are a
/// starting point and nothing more: one approval for everything except the
/// irreversible one and a change to who holds the site's keys, which take two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Used for any action not listed in `actions`.
    pub default: u8,
    #[serde(default)]
    pub actions: BTreeMap<Action, u8>,
}

impl Default for Thresholds {
    fn default() -> Self {
        let mut actions = BTreeMap::new();
        actions.insert(Action::CryptoErase, 2);
        actions.insert(Action::SetCustody, 2);
        Self {
            default: 1,
            actions,
        }
    }
}

impl Thresholds {
    pub fn required(&self, action: Action) -> u8 {
        self.actions.get(&action).copied().unwrap_or(self.default)
    }

    /// A threshold of zero would let an order through with no approval at
    /// all, so a configuration that says so is refused rather than obeyed.
    pub fn validate(&self) -> Result<(), String> {
        if self.default == 0 {
            return Err("the default threshold is zero".into());
        }
        if let Some((a, _)) = self.actions.iter().find(|(_, n)| **n == 0) {
            return Err(format!("the threshold for `{}` is zero", a.as_str()));
        }
        Ok(())
    }
}

/// Approvals collected for one order, counted by independence root.
#[derive(Clone, Debug)]
pub struct Tally {
    order_hash: [u8; 32],
    required: u8,
    by_root: BTreeMap<String, String>,
}

impl Tally {
    pub fn new(order: &Order, thresholds: &Thresholds) -> Result<Self, crate::order::Malformed> {
        Ok(Self {
            order_hash: order.hash()?,
            required: thresholds.required(order.action).max(1),
            by_root: BTreeMap::new(),
        })
    }

    /// Count an approval. Returns whether it added an independent one: a
    /// second credential under a root already counted adds nothing.
    pub fn add(&mut self, v: Verified) -> Result<bool, Refusal> {
        if v.order_hash != self.order_hash {
            return Err(Refusal::new("that approval is for a different order"));
        }
        if self.by_root.contains_key(&v.root) {
            return Ok(false);
        }
        self.by_root.insert(v.root, v.credential_id);
        Ok(true)
    }

    pub fn count(&self) -> usize {
        self.by_root.len()
    }

    pub fn required(&self) -> u8 {
        self.required
    }

    /// The approval, once enough independent roots have given it.
    pub fn approval(&self) -> Option<Approval> {
        (self.by_root.len() >= self.required as usize).then(|| Approval {
            order_hash: self.order_hash,
            approvers: self.by_root.values().cloned().collect(),
            roots: self.by_root.keys().cloned().collect(),
        })
    }
}

/// Proof that an order met its threshold. Made only by [`Tally::approval`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Approval {
    #[serde(with = "hex_32")]
    order_hash: [u8; 32],
    approvers: Vec<String>,
    roots: Vec<String>,
}

impl Approval {
    pub fn order_hash(&self) -> [u8; 32] {
        self.order_hash
    }

    /// The credential ids counted, one per root.
    pub fn approvers(&self) -> &[String] {
        &self.approvers
    }

    /// The independence roots counted.
    pub fn roots(&self) -> &[String] {
        &self.roots
    }
}

mod hex_32 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
}

/// A stored credential that carries no registration data, so its independence
/// cannot be read. It is kept out of the roster, with the reason, until the
/// person enrols again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unproved {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub because: String,
}

/// What became of an admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Admitted {
    /// When the credential may first approve.
    pub usable_from: u64,
    /// Whether it waits out a cancel window first.
    pub delayed: bool,
}

/// The credentials a node accepts approvals from, including any still in
/// their cancel window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "StoredRoster")]
pub struct Roster {
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// Stored credentials refused because they carry no proof of independence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unproved: Vec<Unproved>,
}

/// A roster as written to disk, read leniently so a credential admitted
/// before independence was read from registration data is reported and
/// refused rather than failing the whole file.
#[derive(Deserialize)]
struct StoredRoster {
    #[serde(default)]
    credentials: Vec<serde_json::Value>,
    #[serde(default)]
    unproved: Vec<Unproved>,
}

impl From<StoredRoster> for Roster {
    fn from(raw: StoredRoster) -> Self {
        let mut roster = Roster {
            credentials: Vec::new(),
            unproved: raw.unproved,
        };
        for v in raw.credentials {
            match serde_json::from_value::<Credential>(v.clone()) {
                Ok(c) => roster.credentials.push(c),
                Err(_) => {
                    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
                    roster.unproved.push(Unproved {
                        id: field("id").to_string(),
                        label: field("label").to_string(),
                        because: "it was admitted without its registration data (RP ID, AAGUID \
                                  and backup flags), so its independence cannot be read; enrol \
                                  it again"
                            .into(),
                    });
                }
            }
        }
        roster
    }
}

impl Roster {
    pub fn get(&self, id: &str) -> Option<&Credential> {
        let id = id.trim_end_matches('=');
        self.credentials.iter().find(|c| c.id == id)
    }

    /// As [`Self::get`], with the reason when there is no such credential.
    pub fn lookup(&self, id: &str) -> Result<&Credential, String> {
        if let Some(c) = self.get(id) {
            return Ok(c);
        }
        let id = id.trim_end_matches('=');
        match self.unproved.iter().find(|u| u.id == id) {
            Some(u) => Err(format!("credential {id} is refused: {}", u.because)),
            None => Err(format!("credential {id} is not admitted on this node")),
        }
    }

    /// The independence roots among the credentials usable at `now`.
    pub fn roots(&self, now: u64) -> std::collections::BTreeSet<String> {
        self.credentials
            .iter()
            .filter(|c| c.usable(now))
            .map(Credential::root)
            .collect()
    }

    /// Admit a credential. While the usable credentials make fewer than
    /// [`MIN_INDEPENDENT_ROOTS`] roots, it is usable only after `delay_s`, and
    /// until then any usable credential may cancel it. The first credential on
    /// an empty roster has nobody who could cancel it and is usable at once.
    pub fn admit(&mut self, mut c: Credential, now: u64, delay_s: u64) -> Result<Admitted, String> {
        PublicKey::from_cose(&hex::decode(&c.cose_key).map_err(|_| "key is not hex".to_string())?)?;
        if self.get(&c.id).is_some() {
            return Err(format!("credential {} is already admitted", c.id));
        }
        let delayed = !self.credentials.is_empty()
            && self.roots(now).len() < MIN_INDEPENDENT_ROOTS
            && delay_s > 0;
        c.admitted_at = now;
        c.usable_from = if delayed { now + delay_s } else { now };
        let admitted = Admitted {
            usable_from: c.usable_from,
            delayed,
        };
        self.unproved.retain(|u| u.id != c.id);
        self.credentials.push(c);
        Ok(admitted)
    }

    /// Cancel the pending admission of `id`, on an assertion from a usable
    /// credential over that admission's cancel challenge.
    pub fn cancel(&mut self, id: &str, by: &Verified, now: u64) -> Result<(), String> {
        let id = id.trim_end_matches('=');
        let Some(c) = self.get(id) else {
            return Err(format!("credential {id} is not admitted or pending here"));
        };
        if c.usable(now) {
            return Err(format!(
                "credential {id} is past its cancel window (it closed at {}); remove it with a \
                 `revoke` order",
                c.usable_from
            ));
        }
        if by.order_hash != cancel_hash(id) {
            return Err("that assertion was made over a different challenge".into());
        }
        if by.credential_id == id {
            return Err("a pending credential cannot cancel itself".into());
        }
        self.credentials.retain(|c| c.id != id);
        Ok(())
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.credentials.len();
        self.credentials.retain(|c| c.id != id);
        before != self.credentials.len()
    }

    /// Record the counter an accepted assertion presented.
    pub fn advance(&mut self, v: &Verified) {
        if let Some(c) = self
            .credentials
            .iter_mut()
            .find(|c| c.id == v.credential_id)
        {
            c.sign_count = c.sign_count.max(v.sign_count);
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Written to a temporary file, flushed, and renamed over the old one, so
    /// a crash leaves either roster whole, cancel windows included.
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        use std::io::Write;
        let encoded = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        let at = |p: &std::path::Path, e: std::io::Error| format!("{}: {e}", p.display());
        let mut f = std::fs::File::create(&tmp).map_err(|e| at(&tmp, e))?;
        f.write_all(&encoded).map_err(|e| at(&tmp, e))?;
        f.sync_all().map_err(|e| at(&tmp, e))?;
        std::fs::rename(&tmp, path).map_err(|e| at(path, e))?;
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

/// Test-only authenticator. Holds a P-256 private key, which exists here and
/// nowhere else: production code never makes, holds or derives one.
#[cfg(any(test, feature = "test-authenticator"))]
pub mod virtual_authenticator {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    pub struct Authenticator {
        key: SigningKey,
        pub credential_id: Vec<u8>,
        pub rp_id: String,
        pub origin: String,
        pub counter: u32,
        pub flags: u8,
        pub aaguid: [u8; 16],
    }

    impl Authenticator {
        /// A fixed key, so failures reproduce.
        pub fn new(seed: u8, rp_id: &str) -> Self {
            let key = SigningKey::from_slice(&[seed; 32]).expect("test scalar");
            Self {
                key,
                credential_id: vec![seed; 16],
                rp_id: rp_id.into(),
                origin: format!("https://{rp_id}"),
                counter: 0,
                flags: FLAG_UP | FLAG_UV,
                aaguid: [0xd0; 16],
            }
        }

        /// A synced passkey: backup-eligible and backed up, from the provider
        /// `aaguid` names.
        pub fn synced(seed: u8, rp_id: &str, aaguid: [u8; 16]) -> Self {
            let mut a = Self::new(seed, rp_id);
            a.flags |= FLAG_BE | FLAG_BS;
            a.aaguid = aaguid;
            a
        }

        pub fn id(&self) -> String {
            BASE64URL_NOPAD.encode(&self.credential_id)
        }

        pub fn cose_key(&self) -> Vec<u8> {
            use ciborium::value::{Integer, Value};
            let point = self.key.verifying_key().to_sec1_point(false);
            let point = point.as_bytes();
            let (x, y) = (point[1..33].to_vec(), point[33..65].to_vec());
            let map = Value::Map(vec![
                (
                    Value::Integer(Integer::from(1)),
                    Value::Integer(Integer::from(2)),
                ),
                (
                    Value::Integer(Integer::from(3)),
                    Value::Integer(Integer::from(-7)),
                ),
                (
                    Value::Integer(Integer::from(-1)),
                    Value::Integer(Integer::from(1)),
                ),
                (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
                (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&map, &mut out).expect("cbor");
            out
        }

        /// The credential as a node records it after a clean enrolment.
        pub fn credential(&self) -> Credential {
            Credential {
                id: self.id(),
                cose_key: hex::encode(self.cose_key()),
                rp_id: self.rp_id.clone(),
                enrolled_origin: self.origin.clone(),
                aaguid: hex::encode(self.aaguid),
                backup_eligible: self.flags & FLAG_BE != 0,
                backed_up: self.flags & FLAG_BS != 0,
                usable_from: 0,
                sign_count: 0,
                label: "test".into(),
                admitted_at: 0,
            }
        }

        fn auth_data(&self, attested: bool) -> Vec<u8> {
            let mut a = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            a.push(self.flags | if attested { FLAG_AT } else { 0 });
            a.extend_from_slice(&self.counter.to_be_bytes());
            if attested {
                a.extend_from_slice(&self.aaguid);
                a.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                a.extend_from_slice(&self.credential_id);
                a.extend_from_slice(&self.cose_key());
            }
            a
        }

        fn client_data(&self, kind: &str, challenge: &Challenge) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "type": kind,
                "challenge": challenge.encoded(),
                "origin": self.origin,
                "crossOrigin": false,
            }))
            .expect("json")
        }

        /// An attestation object of format `none`, as most passkey
        /// providers return.
        pub fn attestation_object(&self) -> Vec<u8> {
            use ciborium::value::Value;
            let map = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(Vec::new())),
                (Value::Text("authData".into()), Value::Bytes(self.auth_data(true))),
            ]);
            let mut out = Vec::new();
            ciborium::ser::into_writer(&map, &mut out).expect("cbor");
            out
        }

        pub fn create(&self, challenge: &Challenge) -> Enrolment {
            Enrolment {
                credential_id: self.id(),
                attestation_object: BASE64URL_NOPAD.encode(&self.attestation_object()),
                client_data_json: BASE64URL_NOPAD
                    .encode(&self.client_data("webauthn.create", challenge)),
            }
        }

        /// Sign, advancing the counter first as an authenticator does.
        pub fn get(&mut self, challenge: &Challenge) -> Assertion {
            self.counter += 1;
            self.get_without_counting(challenge)
        }

        pub fn get_without_counting(&self, challenge: &Challenge) -> Assertion {
            let auth = self.auth_data(false);
            let client = self.client_data("webauthn.get", challenge);
            let mut signed = auth.clone();
            signed.extend_from_slice(&Sha256::digest(&client));
            let sig: p256::ecdsa::Signature = self.key.sign(&signed);
            Assertion {
                credential_id: self.id(),
                authenticator_data: BASE64URL_NOPAD.encode(&auth),
                client_data_json: BASE64URL_NOPAD.encode(&client),
                signature: BASE64URL_NOPAD.encode(sig.to_der().as_bytes()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::virtual_authenticator::Authenticator;
    use super::*;
    use crate::order::{Bounds, Target};

    const RP: &str = "site.example";
    const NOW: u64 = 1_000;

    fn order() -> Order {
        Order {
            site: RP.into(),
            action: Action::Halt,
            target: Target::Node {
                id: "node-a".into(),
            },
            bounds: Bounds {
                max_nodes: 1,
                duration_s: None,
            },
            counter: 1,
            issued_at: NOW - 10,
            expires_at: NOW + 600,
            reason: "test".into(),
        }
    }

    fn challenge_for(o: &Order) -> Challenge {
        Challenge {
            order_hash: o.hash().unwrap(),
            nonce: [9u8; 16],
            expires_at: NOW + 120,
        }
    }

    #[test]
    fn a_good_assertion_verifies() {
        let mut a = Authenticator::new(1, RP);
        let cred = a.credential();
        let c = challenge_for(&order());
        let v = verify_assertion(&cred, &a.get(&c), &c, NOW).unwrap();
        assert_eq!(v.sign_count(), 1);
        assert_eq!(v.root(), format!("device:{}", a.id()));
    }

    #[test]
    fn the_challenge_layout_is_hash_nonce_expiry() {
        let c = Challenge {
            order_hash: [1; 32],
            nonce: [2; 16],
            expires_at: 0x0102,
        };
        let b = c.bytes();
        assert_eq!(&b[..32], &[1; 32]);
        assert_eq!(&b[32..48], &[2; 16]);
        assert_eq!(&b[48..], &[0, 0, 0, 0, 0, 0, 1, 2]);
    }

    #[test]
    fn a_wrong_origin_is_refused() {
        let mut a = Authenticator::new(1, RP);
        a.origin = "https://site.example.evil.test".into();
        let cred = a.credential();
        let c = challenge_for(&order());
        let r = verify_assertion(&cred, &a.get(&c), &c, NOW).unwrap_err();
        assert!(r.because.contains("origin"), "{}", r.because);
    }

    #[test]
    fn origins_are_matched_as_a_zone_not_a_substring() {
        assert!(origin_in_zone("https://site.example", RP));
        assert!(origin_in_zone("https://ops.site.example", RP));
        assert!(origin_in_zone("https://ops.site.example:8443", RP));
        assert!(!origin_in_zone("http://site.example", RP));
        assert!(!origin_in_zone("https://evilsite.example", RP));
        assert!(!origin_in_zone("https://site.example.attacker.test", RP));
        assert!(!origin_in_zone("https://site.example/path", RP));
    }

    #[test]
    fn each_credential_is_verified_against_its_own_rp_id() {
        let mut a = Authenticator::new(1, "a.example");
        let cred_a = a.credential();
        let c = challenge_for(&order());
        let asn = a.get(&c);
        assert!(verify_assertion(&cred_a, &asn, &c, NOW).is_ok());
        // The same assertion presented for a credential recorded under another
        // RP ID: there is no list of related origins to fall back on.
        let mut cred_b = Authenticator::new(1, "b.example").credential();
        cred_b.id = cred_a.id.clone();
        let r = verify_assertion(&cred_b, &asn, &c, NOW).unwrap_err();
        assert!(r.because.contains("not made for `b.example`"), "{}", r.because);
        // And an origin outside the credential's own RP ID is refused.
        let mut a = Authenticator::new(2, "a.example");
        a.origin = "https://b.example".into();
        let r = verify_assertion(&a.credential(), &a.get(&c), &c, NOW).unwrap_err();
        assert!(r.because.contains("origin"), "{}", r.because);
    }

    #[test]
    fn user_verification_is_required() {
        let mut a = Authenticator::new(1, RP);
        a.flags = FLAG_UP;
        let cred = a.credential();
        let c = challenge_for(&order());
        let r = verify_assertion(&cred, &a.get(&c), &c, NOW).unwrap_err();
        assert!(r.because.contains("did not verify"), "{}", r.because);
    }

    #[test]
    fn user_presence_is_required() {
        let mut a = Authenticator::new(1, RP);
        a.flags = FLAG_UV;
        let cred = a.credential();
        let c = challenge_for(&order());
        assert!(verify_assertion(&cred, &a.get(&c), &c, NOW).is_err());
    }

    #[test]
    fn a_counter_that_did_not_advance_is_refused() {
        let mut a = Authenticator::new(1, RP);
        let mut cred = a.credential();
        let c = challenge_for(&order());
        let first = a.get(&c);
        let v = verify_assertion(&cred, &first, &c, NOW).unwrap();
        cred.sign_count = v.sign_count();
        // Replaying the same assertion, or a clone that never counted.
        let r = verify_assertion(&cred, &first, &c, NOW).unwrap_err();
        assert!(r.because.contains("counter"), "{}", r.because);
    }

    #[test]
    fn authenticators_that_do_not_count_are_accepted() {
        let a = Authenticator::new(1, RP);
        let cred = a.credential();
        let c = challenge_for(&order());
        assert!(verify_assertion(&cred, &a.get_without_counting(&c), &c, NOW).is_ok());
    }

    #[test]
    fn an_expired_challenge_is_refused() {
        let mut a = Authenticator::new(1, RP);
        let cred = a.credential();
        let c = challenge_for(&order());
        let r = verify_assertion(&cred, &a.get(&c), &c, c.expires_at).unwrap_err();
        assert!(r.because.contains("expired"), "{}", r.because);
    }

    #[test]
    fn a_challenge_for_another_order_is_refused() {
        let mut a = Authenticator::new(1, RP);
        let cred = a.credential();
        let mut other = order();
        other.action = Action::PowerOff;
        let signed_for = challenge_for(&other);
        let expected = challenge_for(&order());
        let r = verify_assertion(&cred, &a.get(&signed_for), &expected, NOW).unwrap_err();
        assert!(r.because.contains("challenge"), "{}", r.because);
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let mut a = Authenticator::new(1, RP);
        let cred = a.credential();
        let c = challenge_for(&order());
        let mut asn = a.get(&c);
        let mut auth = BASE64URL_NOPAD
            .decode(asn.authenticator_data.as_bytes())
            .unwrap();
        auth[36] ^= 0x10;
        asn.authenticator_data = BASE64URL_NOPAD.encode(&auth);
        let r = verify_assertion(&cred, &asn, &c, NOW).unwrap_err();
        assert!(r.because.contains("signature"), "{}", r.because);
    }

    #[test]
    fn another_credentials_signature_is_refused() {
        let mut a = Authenticator::new(1, RP);
        let b = Authenticator::new(2, RP);
        let mut cred = b.credential();
        cred.id = a.id();
        let c = challenge_for(&order());
        assert!(verify_assertion(&cred, &a.get(&c), &c, NOW).is_err());
    }

    #[test]
    fn eddsa_credentials_verify() {
        use ciborium::value::{Integer, Value};
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let map = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(1)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-8)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(6)),
            ),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(sk.verifying_key().to_bytes().to_vec()),
            ),
        ]);
        let mut cose = Vec::new();
        ciborium::ser::into_writer(&map, &mut cose).unwrap();
        let cred = Credential {
            id: "ZWQ".into(),
            cose_key: hex::encode(&cose),
            rp_id: RP.into(),
            enrolled_origin: format!("https://{RP}"),
            aaguid: "00".repeat(16),
            backup_eligible: false,
            backed_up: false,
            usable_from: 0,
            sign_count: 0,
            label: String::new(),
            admitted_at: 0,
        };
        let c = challenge_for(&order());
        let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
        auth.push(FLAG_UP | FLAG_UV);
        auth.extend_from_slice(&3u32.to_be_bytes());
        let client = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get", "challenge": c.encoded(), "origin": format!("https://{RP}"),
        }))
        .unwrap();
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let asn = Assertion {
            credential_id: "ZWQ".into(),
            authenticator_data: BASE64URL_NOPAD.encode(&auth),
            client_data_json: BASE64URL_NOPAD.encode(&client),
            signature: BASE64URL_NOPAD.encode(&sk.sign(&signed).to_bytes()),
        };
        assert!(verify_assertion(&cred, &asn, &c, NOW).is_ok());
    }

    #[test]
    fn an_enrolment_yields_the_key_an_assertion_then_verifies_under() {
        let mut a = Authenticator::new(4, RP);
        let c = Challenge::enrolment([1; 16], NOW + 60);
        let e = verify_enrolment(&a.create(&c), RP, &c, NOW).unwrap();
        assert_eq!(e.credential_id, a.id());
        let cred = Credential::from_enrolled(&e, String::new(), NOW);
        assert_eq!(cred.key_sha256(), e.key_sha256);
        let oc = challenge_for(&order());
        assert!(verify_assertion(&cred, &a.get(&oc), &oc, NOW).is_ok());
    }

    #[test]
    fn enrolment_reads_aaguid_and_backup_flags_from_the_attestation_object() {
        let c = Challenge::enrolment([1; 16], NOW + 60);
        let synced = Authenticator::synced(5, RP, PROVIDER_A);
        let e = verify_enrolment(&synced.create(&c), RP, &c, NOW).unwrap();
        assert_eq!(e.aaguid, hex::encode(PROVIDER_A));
        assert!(e.backup_eligible && e.backed_up, "synced passkeys are not refused");
        assert_eq!(e.rp_id, RP);
        assert_eq!(e.origin, format!("https://{RP}"));
        assert_eq!(
            Credential::from_enrolled(&e, String::new(), NOW).root(),
            format!("provider:{}", hex::encode(PROVIDER_A))
        );

        let bound = Authenticator::new(6, RP);
        let e = verify_enrolment(&bound.create(&c), RP, &c, NOW).unwrap();
        assert!(!e.backup_eligible && !e.backed_up);
        assert_eq!(
            Credential::from_enrolled(&e, String::new(), NOW).root(),
            format!("device:{}", bound.id())
        );

        let mut eligible_only = Authenticator::new(7, RP);
        eligible_only.flags |= FLAG_BE;
        let e = verify_enrolment(&eligible_only.create(&c), RP, &c, NOW).unwrap();
        assert!(e.backup_eligible && !e.backed_up);

        let mut impossible = Authenticator::new(8, RP);
        impossible.flags |= FLAG_BS;
        let r = verify_enrolment(&impossible.create(&c), RP, &c, NOW).unwrap_err();
        assert!(r.because.contains("not backup-eligible"), "{}", r.because);
    }

    #[test]
    fn enrolment_needs_user_verification_and_the_attestation_object() {
        let c = Challenge::enrolment([1; 16], NOW + 60);
        let mut a = Authenticator::synced(5, RP, PROVIDER_A);
        a.flags &= !FLAG_UV;
        let r = verify_enrolment(&a.create(&c), RP, &c, NOW).unwrap_err();
        assert!(r.because.contains("did not verify"), "{}", r.because);
        let a = Authenticator::new(6, RP);
        let mut e = a.create(&c);
        e.attestation_object = BASE64URL_NOPAD.encode(&a.cose_key());
        let r = verify_enrolment(&e, RP, &c, NOW).unwrap_err();
        assert!(r.because.contains("authData"), "{}", r.because);
    }

    fn cancel_by(a: &mut Authenticator, pending: &str) -> Verified {
        let c = Challenge::cancel(pending, [3; 16], NOW + 200_000);
        verify_assertion(&a.credential(), &a.get(&c), &c, NOW).unwrap()
    }

    const DELAY: u64 = 48 * 3600;

    #[test]
    fn a_passkey_added_under_two_roots_waits_and_any_existing_one_can_cancel() {
        let mut roster = Roster::default();
        let mut first = Authenticator::new(1, RP);
        let ad = roster.admit(first.credential(), NOW, DELAY).unwrap();
        assert!(!ad.delayed, "the first credential has nobody to cancel it");

        let mut second = Authenticator::synced(2, RP, PROVIDER_A);
        let ad = roster.admit(second.credential(), NOW, DELAY).unwrap();
        assert!(ad.delayed);
        assert_eq!(ad.usable_from, NOW + DELAY);
        assert_eq!(roster.roots(NOW).len(), 1);

        // Not usable inside the window.
        let o = order();
        let c = challenge_for(&o);
        let pending = roster.get(&second.id()).unwrap().clone();
        let r = verify_assertion(&pending, &second.get(&c), &c, NOW).unwrap_err();
        assert!(r.because.contains("cancel window"), "{}", r.because);

        // A cancel signed for another credential does not count.
        let wrong = cancel_by(&mut first, "someone-else");
        assert!(roster.cancel(&second.id(), &wrong, NOW + 1).is_err());
        let by = cancel_by(&mut first, &second.id());
        roster.cancel(&second.id(), &by, NOW + 1).unwrap();
        assert!(roster.get(&second.id()).is_none());
    }

    #[test]
    fn a_window_that_passed_cannot_be_cancelled_and_the_credential_then_counts() {
        let mut roster = Roster::default();
        let mut first = Authenticator::new(1, RP);
        roster.admit(first.credential(), NOW, DELAY).unwrap();
        let second = Authenticator::new(2, RP);
        roster.admit(second.credential(), NOW, DELAY).unwrap();
        let later = NOW + DELAY;
        assert_eq!(roster.roots(later).len(), 2);
        let by = cancel_by(&mut first, &second.id());
        let r = roster.cancel(&second.id(), &by, later).unwrap_err();
        assert!(r.contains("revoke"), "{r}");
    }

    #[test]
    fn at_two_roots_admission_is_immediate() {
        let mut roster = Roster::default();
        roster.admit(Authenticator::new(1, RP).credential(), NOW, DELAY).unwrap();
        roster.admit(Authenticator::new(2, RP).credential(), NOW, 0).unwrap();
        assert_eq!(roster.roots(NOW).len(), 2);
        let ad = roster
            .admit(Authenticator::synced(3, RP, PROVIDER_A).credential(), NOW, DELAY)
            .unwrap();
        assert!(!ad.delayed);
        assert_eq!(ad.usable_from, NOW);
    }

    #[test]
    fn two_synced_copies_are_one_root_so_a_third_passkey_still_waits() {
        let mut roster = Roster::default();
        roster.admit(Authenticator::synced(1, RP, PROVIDER_A).credential(), NOW, DELAY).unwrap();
        roster.admit(Authenticator::synced(2, RP, PROVIDER_A).credential(), NOW, 0).unwrap();
        assert_eq!(roster.roots(NOW).len(), 1);
        let ad = roster.admit(Authenticator::new(3, RP).credential(), NOW, DELAY).unwrap();
        assert!(ad.delayed);
    }

    #[test]
    fn a_stored_credential_without_registration_data_is_refused_with_the_reason() {
        let a = Authenticator::new(1, RP);
        let stored = serde_json::json!({
            "credentials": [
                {
                    "id": "bGVnYWN5",
                    "cose_key": hex::encode(a.cose_key()),
                    "independence_group": "alice",
                    "sign_count": 4,
                    "label": "old",
                    "admitted_at": 1
                },
                a.credential(),
            ]
        });
        let roster: Roster = serde_json::from_value(stored).unwrap();
        assert_eq!(roster.credentials.len(), 1);
        assert!(roster.get("bGVnYWN5").is_none());
        let why = roster.lookup("bGVnYWN5").unwrap_err();
        assert!(why.contains("enrol it again"), "{why}");
        assert!(why.contains("independence"), "{why}");
        // Kept on save, so the reason survives a restart.
        let again: Roster =
            serde_json::from_slice(&serde_json::to_vec(&roster).unwrap()).unwrap();
        assert_eq!(again.unproved.len(), 1);
        // Enrolling again under the same id clears it.
        let mut again = again;
        let mut fresh = Authenticator::new(1, RP).credential();
        fresh.id = "bGVnYWN5".into();
        again.admit(fresh, NOW, DELAY).unwrap();
        assert!(again.unproved.is_empty());
    }

    #[test]
    fn an_order_challenge_cannot_enrol_and_an_assertion_cannot_enrol() {
        let a = Authenticator::new(4, RP);
        let oc = challenge_for(&order());
        assert!(verify_enrolment(&a.create(&oc), RP, &oc, NOW).is_err());
        let c = Challenge::enrolment([1; 16], NOW + 60);
        let mut e = a.create(&c);
        let get = a.get_without_counting(&c);
        e.client_data_json = get.client_data_json;
        let r = verify_enrolment(&e, RP, &c, NOW).unwrap_err();
        assert!(r.because.contains("webauthn.create"), "{}", r.because);
    }

    fn verified_by(mut a: Authenticator, o: &Order) -> Verified {
        let cred = a.credential();
        let c = challenge_for(o);
        verify_assertion(&cred, &a.get(&c), &c, NOW).unwrap()
    }

    fn verified(seed: u8, o: &Order) -> Verified {
        verified_by(Authenticator::new(seed, RP), o)
    }

    const PROVIDER_A: [u8; 16] = [0xa1; 16];
    const PROVIDER_B: [u8; 16] = [0xb2; 16];

    #[test]
    fn a_threshold_not_met_yields_no_approval() {
        let mut o = order();
        o.action = Action::CryptoErase;
        let mut t = Tally::new(&o, &Thresholds::default()).unwrap();
        assert_eq!(t.required(), 2);
        assert!(t.add(verified(1, &o)).unwrap());
        assert!(t.approval().is_none());
        assert!(t.add(verified(2, &o)).unwrap());
        let ap = t.approval().unwrap();
        assert_eq!(ap.order_hash(), o.hash().unwrap());
        assert_eq!(ap.roots().len(), 2);
    }

    #[test]
    fn two_synced_credentials_from_one_provider_count_once() {
        let mut o = order();
        o.action = Action::CryptoErase;
        let mut t = Tally::new(&o, &Thresholds::default()).unwrap();
        assert!(t.add(verified_by(Authenticator::synced(1, RP, PROVIDER_A), &o)).unwrap());
        assert!(!t.add(verified_by(Authenticator::synced(2, RP, PROVIDER_A), &o)).unwrap());
        assert_eq!(t.count(), 1);
        assert!(t.approval().is_none());
        // Another provider's sync account is another root.
        assert!(t.add(verified_by(Authenticator::synced(3, RP, PROVIDER_B), &o)).unwrap());
        assert_eq!(t.approval().unwrap().roots().len(), 2);
    }

    #[test]
    fn device_bound_credentials_count_separately_even_from_one_model() {
        let mut o = order();
        o.action = Action::CryptoErase;
        let mut t = Tally::new(&o, &Thresholds::default()).unwrap();
        // Same AAGUID (one authenticator model), BE clear: each key is its own.
        assert!(t.add(verified(1, &o)).unwrap());
        assert!(t.add(verified(2, &o)).unwrap());
        assert_eq!(t.approval().unwrap().roots().len(), 2);
        // A synced key from a provider with the same AAGUID is a third root.
        assert!(t.add(verified_by(Authenticator::synced(3, RP, [0xd0; 16]), &o)).unwrap());
        assert_eq!(t.count(), 3);
    }

    #[test]
    fn an_approval_for_one_order_does_not_count_for_another() {
        let o = order();
        let mut other = order();
        other.counter = 2;
        let mut t = Tally::new(&other, &Thresholds::default()).unwrap();
        assert!(t.add(verified(1, &o)).is_err());
    }

    #[test]
    fn a_zero_threshold_is_refused() {
        let mut t = Thresholds::default();
        assert!(t.validate().is_ok());
        t.actions.insert(Action::Halt, 0);
        assert!(t.validate().is_err());
        t.actions.clear();
        t.default = 0;
        assert!(t.validate().is_err());
    }

    #[test]
    fn a_custody_change_needs_two_groups_by_default() {
        let t = Thresholds::default();
        assert_eq!(t.required(Action::SetCustody), 2);
        assert_eq!(t.required(Action::CryptoErase), 2);
        assert_eq!(t.required(Action::Halt), 1);
        let t: Thresholds =
            serde_json::from_str(r#"{"default":1,"actions":{"set_custody":3}}"#).unwrap();
        assert_eq!(t.required(Action::SetCustody), 3);
    }

    #[test]
    fn resume_needs_one_approval_unless_governance_says_otherwise() {
        assert_eq!(Thresholds::default().required(Action::Resume), 1);
        let t: Thresholds =
            serde_json::from_str(r#"{"default":1,"actions":{"resume":2}}"#).unwrap();
        assert_eq!(t.required(Action::Resume), 2);
        assert_eq!(t.required(Action::Halt), 1);
    }

    #[test]
    fn thresholds_are_configuration() {
        let t: Thresholds =
            serde_json::from_str(r#"{"default":2,"actions":{"halt":1,"crypto_erase":3}}"#).unwrap();
        assert_eq!(t.required(Action::Halt), 1);
        assert_eq!(t.required(Action::PowerOff), 2);
        assert_eq!(t.required(Action::CryptoErase), 3);
    }
}
