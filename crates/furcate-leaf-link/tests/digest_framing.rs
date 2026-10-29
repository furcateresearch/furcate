//! The digest a leaf signs is SHA-256 of a message, so a P-256 signer that takes
//! the message and one that takes the digest produce the same signature input
//! (the signature-scheme rule for leaf and node keys).

use furcate_leaf_link::report::{reading_digest, unit_digest, RawReading, UnitRecord};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

const LEAF_ID: [u8; 32] = [0x5a; 32];
const MODEL: [u8; 32] = [0x77; 32];

fn reading() -> RawReading {
    RawReading { sensor: 18, value: 21.5, seq: 9, signature: [0; 64] }
}

/// The bytes `reading_digest` hashes, written out field by field.
fn reading_message() -> Vec<u8> {
    let r = reading();
    let mut m = b"furcate/leaf/sample/v2".to_vec();
    m.extend_from_slice(&LEAF_ID[..8]);
    m.extend_from_slice(&3u16.to_be_bytes());
    m.push(r.sensor);
    m.extend_from_slice(&r.value.to_be_bytes());
    m.extend_from_slice(&r.seq.to_be_bytes());
    m.extend_from_slice(&MODEL);
    m
}

fn unit() -> UnitRecord {
    UnitRecord { fingerprint: [0x11; 16], first_seq: 4, last_seq: 12, signature: [0; 64] }
}

fn unit_message() -> Vec<u8> {
    let u = unit();
    let mut m = b"furcate/leaf/unit/v1".to_vec();
    m.extend_from_slice(&LEAF_ID[..8]);
    m.extend_from_slice(&3u16.to_be_bytes());
    m.extend_from_slice(&u.fingerprint);
    m.extend_from_slice(&u.first_seq.to_be_bytes());
    m.extend_from_slice(&u.last_seq.to_be_bytes());
    m
}

fn both_modes_coincide(message: &[u8], digest: [u8; 32]) {
    assert_eq!(<[u8; 32]>::from(Sha256::digest(message)), digest, "the digest is SHA-256 of the message");
    let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
    // A part that takes a message hashes it with SHA-256 itself.
    let by_message: Signature = key.sign(message);
    // A part that takes a digest is given the SHA-256 by the host.
    let by_digest: Signature = key.sign_prehash(&digest).unwrap();
    assert_eq!(by_message.to_bytes(), by_digest.to_bytes());
    // Each verifies under the other's route, which is the route the link uses.
    key.verifying_key().verify_prehash(&digest, &by_message).unwrap();
    key.verifying_key().verify(message, &by_digest).unwrap();
}

#[test]
fn a_reading_digest_is_sha256_of_its_message_so_both_p256_modes_coincide() {
    let digest = reading_digest(&LEAF_ID, 3, &reading(), &MODEL);
    both_modes_coincide(&reading_message(), digest);
}

#[test]
fn a_unit_digest_is_sha256_of_its_message_so_both_p256_modes_coincide() {
    let digest = unit_digest(&LEAF_ID, 3, &unit());
    both_modes_coincide(&unit_message(), digest);
}

#[test]
fn the_leaf_message_is_fixed_width_and_not_the_length_prefixed_frame() {
    // Recorded so nobody reads the coincidence above as more than it is: the
    // message is a fixed-layout concatenation with the domain first and no
    // length prefixes, not `len(domain) || domain || len(msg) || msg`. Every
    // field after the domain has a fixed width, so no two readings share a
    // message; the leaf's suite is implied by its enrolled `p256:` key.
    let framed = furcate_identity::signing_digest(b"furcate/leaf/sample/v2", &reading_message()[22..]);
    assert_ne!(framed, reading_digest(&LEAF_ID, 3, &reading(), &MODEL));
}
