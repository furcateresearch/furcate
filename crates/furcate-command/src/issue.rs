//! Signing helpers for tests and for the golden vector. The production signer is a hardware-backed key held outside
//! this repository; nothing here reads, stores or generates a key beyond what a caller hands in.

use crate::canon::{canonical, CanonError};
use crate::{domain_digest, CERT_DOMAIN, COMMAND_DOMAIN};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

pub fn key_id(k: &SigningKey) -> String {
    format!("ed25519:{}", hex::encode(k.verifying_key().to_bytes()))
}

/// Sign `v` (an object) under `domain`: the canonical bytes of the object without `signature` are what is signed.
pub fn sign_value(v: &mut Value, domain: &str, key: &SigningKey) -> Result<(), CanonError> {
    let obj = v.as_object_mut().ok_or(CanonError::Malformed)?;
    obj.remove("signature");
    let bytes = canonical(&Value::Object(obj.clone()))?;
    let sig = key.sign(&domain_digest(domain, bytes.as_bytes()));
    obj.insert("signature".into(), Value::String(hex::encode(sig.to_bytes())));
    Ok(())
}

pub fn sign_cert(cert: &mut Value, key: &SigningKey) -> Result<(), CanonError> {
    cert["signer"] = Value::String(key_id(key));
    sign_value(cert, CERT_DOMAIN, key)
}

/// Sign the command; the certificate must already be signed.
pub fn sign_command(cmd: &mut Value, key: &SigningKey) -> Result<(), CanonError> {
    cmd["signer"] = Value::String(key_id(key));
    sign_value(cmd, COMMAND_DOMAIN, key)
}

pub fn bytes(v: &Value) -> Vec<u8> {
    canonical(v).unwrap().into_bytes()
}
