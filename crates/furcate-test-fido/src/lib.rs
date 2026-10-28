//! A software FIDO authenticator for OpenSSH, loaded as a
//! `SecurityKeyProvider` by tests and by nothing else.
//!
//! It implements the middleware interface in OpenSSH's `sk-api.h` for ECDSA
//! P-256 keys. The key handle IS the private scalar, so any holder of the
//! key file can sign: the opposite of a passkey, and the reason this library
//! must never be installed or loaded outside a test.
//!
//! What it signs is what an authenticator signs, so sshd verifies it like any
//! other: SHA-256 of the application, the flags, a big-endian counter and
//! SHA-256 of the message, as one ECDSA P-256 signature.

#![allow(clippy::missing_safety_doc)]

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::ffi::{c_char, CStr};

/// The interface version this was written against (OpenSSH 8.9 to 10.x).
/// `FURCATE_TEST_SK_API` overrides it for an OpenSSH that asks for another.
const SK_API: u32 = 0x000a_0000;
const SK_ECDSA: u32 = 0;
const ERR_GENERAL: i32 = -1;
const ERR_UNSUPPORTED: i32 = -2;
const USER_PRESENCE: u8 = 0x01;
const USER_VERIFICATION: u8 = 0x04;

#[repr(C)]
pub struct EnrollResponse {
    pub flags: u8,
    pub public_key: *mut u8,
    pub public_key_len: usize,
    pub key_handle: *mut u8,
    pub key_handle_len: usize,
    pub signature: *mut u8,
    pub signature_len: usize,
    pub attestation_cert: *mut u8,
    pub attestation_cert_len: usize,
    pub authdata: *mut u8,
    pub authdata_len: usize,
}

#[repr(C)]
pub struct SignResponse {
    pub flags: u8,
    pub counter: u32,
    pub sig_r: *mut u8,
    pub sig_r_len: usize,
    pub sig_s: *mut u8,
    pub sig_s_len: usize,
}

/// Bytes in memory OpenSSH frees with `free()`.
fn malloc_copy(b: &[u8]) -> (*mut u8, usize) {
    // SAFETY: calloc of at least one byte; the copy stays inside it.
    unsafe {
        let p = libc::calloc(b.len().max(1), 1) as *mut u8;
        if !p.is_null() {
            std::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len());
        }
        (p, b.len())
    }
}

#[no_mangle]
pub extern "C" fn sk_api_version() -> u32 {
    std::env::var("FURCATE_TEST_SK_API")
        .ok()
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(SK_API)
}

/// A fresh key from the challenge, so each enrolment differs and a test can
/// make several.
fn new_key(challenge: &[u8]) -> Option<SigningKey> {
    let mut seed = Sha256::new();
    seed.update(b"furcate-test-fido");
    seed.update(challenge);
    seed.update(std::process::id().to_be_bytes());
    seed.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    SigningKey::from_slice(&seed.finalize()).ok()
}

#[no_mangle]
pub unsafe extern "C" fn sk_enroll(
    alg: u32,
    challenge: *const u8,
    challenge_len: usize,
    _application: *const c_char,
    flags: u8,
    _pin: *const c_char,
    _options: *mut *mut libc::c_void,
    response: *mut *mut EnrollResponse,
) -> i32 {
    if alg != SK_ECDSA {
        return ERR_UNSUPPORTED;
    }
    if response.is_null() {
        return ERR_GENERAL;
    }
    let ch = if challenge.is_null() { &[][..] } else { std::slice::from_raw_parts(challenge, challenge_len) };
    let Some(key) = new_key(ch) else { return ERR_GENERAL };
    let point = key.verifying_key().to_sec1_point(false);
    let r = libc::calloc(1, std::mem::size_of::<EnrollResponse>()) as *mut EnrollResponse;
    if r.is_null() {
        return ERR_GENERAL;
    }
    (*r).flags = flags;
    ((*r).public_key, (*r).public_key_len) = malloc_copy(point.as_bytes());
    ((*r).key_handle, (*r).key_handle_len) = malloc_copy(&key.to_bytes());
    ((*r).signature, (*r).signature_len) = malloc_copy(&[]);
    ((*r).attestation_cert, (*r).attestation_cert_len) = malloc_copy(&[]);
    ((*r).authdata, (*r).authdata_len) = malloc_copy(&[]);
    *response = r;
    0
}

/// What an authenticator signs for OpenSSH: the application's hash, the
/// flags, the counter and the message's hash.
pub fn signed_bytes(application: &str, flags: u8, counter: u32, message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(69);
    m.extend_from_slice(&Sha256::digest(application.as_bytes()));
    m.push(flags);
    m.extend_from_slice(&counter.to_be_bytes());
    m.extend_from_slice(&Sha256::digest(message));
    m
}

#[no_mangle]
pub unsafe extern "C" fn sk_sign(
    alg: u32,
    data: *const u8,
    data_len: usize,
    application: *const c_char,
    key_handle: *const u8,
    key_handle_len: usize,
    flags: u8,
    _pin: *const c_char,
    _options: *mut *mut libc::c_void,
    response: *mut *mut SignResponse,
) -> i32 {
    if alg != SK_ECDSA {
        return ERR_UNSUPPORTED;
    }
    if response.is_null() || key_handle.is_null() || application.is_null() {
        return ERR_GENERAL;
    }
    let Ok(key) = SigningKey::from_slice(std::slice::from_raw_parts(key_handle, key_handle_len)) else {
        return ERR_GENERAL;
    };
    let app = CStr::from_ptr(application).to_string_lossy().into_owned();
    let data = if data.is_null() { &[][..] } else { std::slice::from_raw_parts(data, data_len) };
    // Present always; verified when the caller asked for it.
    let out_flags = USER_PRESENCE | (flags & USER_VERIFICATION);
    let counter = 1;
    let sig: Signature = key.sign(&signed_bytes(&app, out_flags, counter, data));
    let rs = sig.to_bytes();
    let (rr, ss) = rs.split_at(32);
    let r = libc::calloc(1, std::mem::size_of::<SignResponse>()) as *mut SignResponse;
    if r.is_null() {
        return ERR_GENERAL;
    }
    (*r).flags = out_flags;
    (*r).counter = counter;
    ((*r).sig_r, (*r).sig_r_len) = malloc_copy(rr);
    ((*r).sig_s, (*r).sig_s_len) = malloc_copy(ss);
    *response = r;
    0
}

#[no_mangle]
pub unsafe extern "C" fn sk_load_resident_keys(
    _pin: *const c_char,
    _options: *mut *mut libc::c_void,
    _rks: *mut *mut *mut libc::c_void,
    _nrks: *mut usize,
) -> i32 {
    ERR_UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn an_enrolled_key_signs_what_sshd_verifies() {
        let mut er: *mut EnrollResponse = std::ptr::null_mut();
        let app = std::ffi::CString::new("ssh:").unwrap();
        unsafe {
            assert_eq!(sk_enroll(0, b"c".as_ptr(), 1, app.as_ptr(), 1, std::ptr::null(), std::ptr::null_mut(), &mut er), 0);
            let pk = std::slice::from_raw_parts((*er).public_key, (*er).public_key_len).to_vec();
            let kh = std::slice::from_raw_parts((*er).key_handle, (*er).key_handle_len).to_vec();
            let mut sr: *mut SignResponse = std::ptr::null_mut();
            let msg = b"session";
            assert_eq!(
                sk_sign(0, msg.as_ptr(), msg.len(), app.as_ptr(), kh.as_ptr(), kh.len(), 1, std::ptr::null(), std::ptr::null_mut(), &mut sr),
                0
            );
            let mut rs = std::slice::from_raw_parts((*sr).sig_r, 32).to_vec();
            rs.extend_from_slice(std::slice::from_raw_parts((*sr).sig_s, 32));
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk).unwrap();
            let sig = Signature::from_slice(&rs).unwrap();
            assert!(vk.verify(&signed_bytes("ssh:", (*sr).flags, (*sr).counter, msg), &sig).is_ok());
            assert_eq!((*sr).flags & USER_PRESENCE, USER_PRESENCE);
        }
    }

    #[test]
    fn ed25519_is_refused_by_name() {
        let mut er: *mut EnrollResponse = std::ptr::null_mut();
        let app = std::ffi::CString::new("ssh:").unwrap();
        let rc = unsafe { sk_enroll(1, std::ptr::null(), 0, app.as_ptr(), 1, std::ptr::null(), std::ptr::null_mut(), &mut er) };
        assert_eq!(rc, ERR_UNSUPPORTED);
    }
}
