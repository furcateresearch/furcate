use furcate_identity::backends::fingerprint::{Characteristic as C, Fingerprint};
use furcate_identity::{EnrolledUnit, LeafKeyCustody, UnitRoster};
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};
fn tlv(b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let (mut i, mut o) = (0, vec![]);
    while i + 3 <= b.len() { let n = u16::from_be_bytes([b[i + 1], b[i + 2]]) as usize; o.push((b[i], b[i + 3..i + 3 + n].to_vec())); i += 3 + n; }
    o
}
fn main() {
    let cap = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    let mut hellos = vec![];
    for l in cap.split(|&c| c == b'\n') {
        if let Some(r) = l.strip_prefix(b"FL1:") {
            let r: Vec<u8> = r.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect();
            if let Ok(m) = data_encoding::BASE64.decode(&r) { hellos.push(m); }
        }
    }
    println!("frames {}", hellos.len());
    let mut roster = UnitRoster::new();
    for (n, h) in hellos.iter().enumerate() {
        assert_eq!(h[0], 1);
        let f = tlv(&h[1..]);
        let get = |t: u8| f.iter().find(|x| x.0 == t).unwrap().1.clone();
        let (pubk, ev) = (get(2), tlv(&get(5)));
        let eg = |t: u8| ev.iter().find(|x| x.0 == t).unwrap().1.clone();
        let on_curve = VerifyingKey::from_sec1_bytes(&pubk).is_ok();
        let id = hex::encode(Sha256::digest(&pubk));
        let fp = Fingerprint::default().with(C::MacAddress, hex::encode(eg(1))).with(C::Otp, hex::encode(eg(20))).with(C::BoardRevision, hex::encode(eg(2)));
        let key = format!("p256:{}", hex::encode(&pubk));
        println!("frame {n}: devpub on curve {on_curve}, anchors {}, usable {}, assurance label `{}`", fp.anchors().len(), fp.is_usable(), String::from_utf8_lossy(&eg(4)));
        if n == 0 {
            let e = EnrolledUnit { unit_id: id.clone(), fingerprint: fp.clone(), key: Some(key.clone()), custody: Some(LeafKeyCustody::ReadableIdentifiers) };
            println!("enrol: {:?}", roster.enrol(e));
        }
        let v = roster.verify(&id, &fp, Some(&key));
        println!("  verify: {:?} admits={}", v, v.admits());
        if n == 1 { println!("  second live session: {:?}", roster.verify(&id, &fp, Some(&key))); }
        roster.end_session(&id);
        if n == 3 {
            let fp2 = Fingerprint::default().with(C::MacAddress, "000000000000").with(C::Otp, hex::encode(eg(20))).with(C::BoardRevision, hex::encode(eg(2)));
            println!("  swapped MAC: {:?}", roster.verify(&id, &fp2, Some(&key)));
            println!("  wrong key: {:?}", roster.verify(&id, &fp, Some("p256:00")));
        }
    }
}
