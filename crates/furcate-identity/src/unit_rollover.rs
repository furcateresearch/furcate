//! Identity rollover record for a leaf whose key changes ("FLI1").
//!
//! An ESP32-S3 leaf starts with a key derived from identifiers anyone with the
//! part can read, and after the owner burns an HMAC key into eFuse it has a
//! different key, so a different leaf id. The roster pins the id, so the old
//! identity authorises the new one with a record that both keys sign and the
//! operator countersigns. This is the parent-side check, a port of the
//! reference in furcate-leaf-firmware (host/fl_rollover.py); both are held to
//! the same golden vectors (tests/identity-vectors.txt). The refusal strings
//! are the reference's.
//!
//! Body, 157 bytes big-endian: `FLI1` | old public key (65) | successor public
//! key (65) | sequence u32 | not_before u64 | not_after u64 | old level u8 |
//! successor level u8 | reserved 0. Record: body | old signature (64, r||s) |
//! successor signature (64) | operator signature length u8 | operator
//! signature (DER). Each signature is ECDSA P-256 over
//! SHA-256("furcate-leaf rollover v1 " + role + "\n" + body).

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const BODY_LEN: usize = 4 + 65 + 65 + 4 + 8 + 8 + 3;
const SIGS: usize = 128;
pub const MAX_WINDOW_S: u64 = 7 * 24 * 3600;
const OPSIG_MAX: usize = 72;
const LEVEL_MAX: u8 = 5;

/// The level a leaf's reported assurance string stands for (0 when unknown).
pub fn level(assurance: &str) -> u8 {
    match assurance {
        "silicon-id/development" => 1,
        "silicon-fingerprint/development" => 2,
        "efuse-hmac/development" => 3,
        "silicon-fingerprint+secure-boot" => 4,
        "efuse-hmac+secure-boot" => 5,
        _ => 0,
    }
}

pub fn leaf_id(pubkey: &[u8]) -> [u8; 32] {
    Sha256::digest(pubkey).into()
}

fn digest(role: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"furcate-leaf rollover v1 ");
    h.update(role.as_bytes());
    h.update(b"\n");
    h.update(body);
    h.finalize().into()
}

/// Everything the parent supplies. Nothing is read from the record.
pub struct Policy<'a> {
    pub now: u64,
    pub old_id: [u8; 32],
    pub roster_old_level: u8,
    /// The level the successor proved in live, verified evidence.
    pub proven_new_level: u8,
    /// Highest sequence accepted for this old id (0 = none).
    pub last_seq: u32,
    pub old_retired: bool,
    pub retired_successor_id: [u8; 32],
    /// Every other roster leaf id: the successor may not be one of them.
    pub known_ids: &'a [[u8; 32]],
    pub operator_pubs: &'a [Vec<u8>],
    pub require_operator: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub old_pub: Vec<u8>,
    pub new_pub: Vec<u8>,
    pub seq: u32,
    pub not_before: u64,
    pub not_after: u64,
    pub old_level: u8,
    pub new_level: u8,
}

impl Accepted {
    pub fn old_id(&self) -> [u8; 32] {
        leaf_id(&self.old_pub)
    }
    pub fn new_id(&self) -> [u8; 32] {
        leaf_id(&self.new_pub)
    }
}

fn point(b: &[u8]) -> Option<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(b).ok()
}

fn verify_raw(pubkey: &[u8], h: &[u8; 32], rs: &[u8]) -> bool {
    let (Some(k), Ok(s)) = (point(pubkey), Signature::from_slice(rs)) else { return false };
    k.verify_prehash(h, &s).is_ok()
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` to the 64-byte r || s form.
fn der_to_raw(der: &[u8]) -> Option<[u8; 64]> {
    fn int(b: &[u8]) -> Option<(&[u8], &[u8])> {
        if b.len() < 2 || b[0] != 0x02 {
            return None;
        }
        let n = b[1] as usize;
        if n == 0 || n > 33 || b.len() < 2 + n {
            return None;
        }
        Some((&b[2..2 + n], &b[2 + n..]))
    }
    if der.len() < 8 || der[0] != 0x30 || der[1] as usize != der.len() - 2 {
        return None;
    }
    let (r, rest) = int(&der[2..])?;
    let (s, rest) = int(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, v) in [r, s].iter().enumerate() {
        let v = if v.len() == 33 && v[0] == 0 { &v[1..] } else { v };
        if v.len() > 32 {
            return None;
        }
        out[32 * i + 32 - v.len()..32 * (i + 1)].copy_from_slice(v);
    }
    Some(out)
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().expect("4 bytes"))
}
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().expect("8 bytes"))
}

/// Checks a record. `Ok` carries what to store: the new last sequence, retire
/// the old id, enrol the successor id (SHA-256 of its public key) at the
/// proven level. `Err` is the reference's refusal string.
pub fn verify(rec: &[u8], p: &Policy) -> Result<Accepted, &'static str> {
    const MALFORMED: &str = "malformed record";
    let base = BODY_LEN + SIGS + 1;
    if rec.len() < base || &rec[..4] != b"FLI1" {
        return Err(MALFORMED);
    }
    let ol = rec[base - 1] as usize;
    if rec.len() != base + ol || (ol != 0 && !(8..=OPSIG_MAX).contains(&ol)) {
        return Err(MALFORMED);
    }
    let (old_pub, new_pub) = (&rec[4..69], &rec[69..134]);
    let seq = be32(&rec[134..138]);
    let (nb, na) = (be64(&rec[138..146]), be64(&rec[146..154]));
    let (old_level, new_level, reserved) = (rec[154], rec[155], rec[156]);
    if reserved != 0 || point(old_pub).is_none() || point(new_pub).is_none() {
        return Err(MALFORMED);
    }
    let body = &rec[..BODY_LEN];
    if leaf_id(old_pub) != p.old_id {
        return Err("old key is not the roster leaf");
    }
    if old_pub == new_pub {
        return Err("successor equals the old key");
    }
    let nid = leaf_id(new_pub);
    if p.known_ids.contains(&nid) {
        return Err("successor is another leaf");
    }
    if p.old_retired && nid != p.retired_successor_id {
        return Err("already rolled to a different successor");
    }
    if !verify_raw(old_pub, &digest("old", body), &rec[BODY_LEN..BODY_LEN + 64]) {
        return Err("old signature invalid");
    }
    if !verify_raw(new_pub, &digest("new", body), &rec[BODY_LEN + 64..BODY_LEN + 128]) {
        return Err("successor signature invalid");
    }
    if ol != 0 {
        let raw = der_to_raw(&rec[base..]);
        let h = digest("operator", body);
        let ok = raw.is_some_and(|r| p.operator_pubs.iter().any(|op| verify_raw(op, &h, &r)));
        if !ok {
            return Err("operator approval invalid");
        }
    } else if p.require_operator {
        return Err("operator approval missing");
    }
    if seq == 0 || seq <= p.last_seq {
        return Err("replay: sequence not newer");
    }
    if na <= nb || na - nb > MAX_WINDOW_S {
        return Err("validity window too long");
    }
    if p.now < nb || p.now > na {
        return Err("outside validity window");
    }
    if !(1..=LEVEL_MAX).contains(&old_level) || !(1..=LEVEL_MAX).contains(&new_level) {
        return Err("unknown level");
    }
    if old_level != p.roster_old_level {
        return Err("old level mismatch");
    }
    if new_level > p.proven_new_level {
        return Err("successor level exceeds proven");
    }
    if new_level < old_level {
        return Err("assurance downgrade");
    }
    Ok(Accepted {
        old_pub: old_pub.to_vec(),
        new_pub: new_pub.to_vec(),
        seq,
        not_before: nb,
        not_after: na,
        old_level,
        new_level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv<'a>(t: &'a [&'a str]) -> std::collections::HashMap<&'a str, &'a str> {
        t.iter().filter_map(|x| x.split_once('=')).collect()
    }
    fn ids(s: &str) -> Vec<[u8; 32]> {
        if s == "-" { vec![] } else { s.split(',').map(|x| hex::decode(x).unwrap().try_into().unwrap()).collect() }
    }

    /// Every rollover vector of the leaf firmware repository, byte for byte.
    #[test]
    fn golden_vectors() {
        let text = include_str!("../tests/identity-vectors.txt");
        let mut n = 0;
        for line in text.lines().filter(|l| l.starts_with("rollover ")) {
            let t: Vec<&str> = line.split_whitespace().collect();
            let (name, want) = (t[1], t[2]);
            let f = kv(&t[3..]);
            let ops: Vec<Vec<u8>> = if f["ops"] == "-" { vec![] } else { f["ops"].split(',').map(|x| hex::decode(x).unwrap()).collect() };
            let known = ids(f["known"]);
            let retired = ids(f["retired"]);
            let pol = Policy {
                now: f["now"].parse().unwrap(),
                old_id: hex::decode(f["old_id"]).unwrap().try_into().unwrap(),
                roster_old_level: f["roster_old"].parse().unwrap(),
                proven_new_level: f["proven"].parse().unwrap(),
                last_seq: f["last_seq"].parse().unwrap(),
                old_retired: !retired.is_empty(),
                retired_successor_id: retired.first().copied().unwrap_or([0; 32]),
                known_ids: &known,
                operator_pubs: &ops,
                require_operator: f["reqop"] == "1",
            };
            let got = match verify(&hex::decode(f["rec"]).unwrap(), &pol) {
                Ok(_) => "ok".to_string(),
                Err(e) => e.replace(' ', "_"),
            };
            assert_eq!(got, want, "vector {name}");
            n += 1;
        }
        assert_eq!(n, 31);
    }

    #[test]
    fn levels() {
        assert_eq!(level("efuse-hmac/development"), 3);
        assert_eq!(level("nonsense"), 0);
    }
}
