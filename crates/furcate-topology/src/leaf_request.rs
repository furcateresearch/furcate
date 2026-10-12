//! Requests a leaf signs, checked by the head of the cell it is attached to.
//!
//! A leaf holds one key, derived from its hardware, and the cell's chain names
//! that key in the link its head signed. A request it sends to a service on
//! the head is signed with the same key and checked against that link, so the
//! only thing that lets a leaf in is the attachment itself: no token is handed
//! to the leaf, and nothing a leaf stores can be copied to another device.
//!
//! The canonical request is the one every Furcate signed request uses,
//! [`furcate_authn::signing_input`]: method, request target, SHA-256 of the
//! body, nonce and expiry. The credential rides in `X-Furcate-Credential`:
//!
//! ```text
//! leaf:<holder>:<nonce>.<expires_at>.<signature hex>
//! ```
//!
//! `holder` is the key exactly as the leaf's link names it (`p256:<compressed
//! point hex>` or `ed25519:<hex>`), and the signature is ECDSA P-256 with
//! SHA-256 over the canonical request, 64 bytes of `r || s` (DER is accepted),
//! or Ed25519 for an Ed25519 leaf.
//!
//! A request is admitted when, in this order: its expiry is in the future and
//! no more than [`MAX_VALIDITY_SECS`] away; the signature verifies under the
//! named key; that key is a leaf of the cell this node heads, by a link that is
//! live and not revoked; the class the link records meets the cell's current
//! leaf floor; and the nonce has not been spent by that leaf. The nonce is
//! spent only once everything else holds, so a forged request cannot burn a
//! nonce the real leaf is about to use.

use std::collections::BTreeMap;
use std::sync::Mutex;

use furcate_authn::{Presented, Refusal};
use furcate_identity::AssuranceClass;

use crate::cell::{CellKey, CellTree};

/// The prefix of a leaf credential.
pub const SCHEME: &str = "leaf:";

/// How far ahead a leaf's signature may claim to be valid. The same bound as
/// an operator's: long enough for a slow link, short enough that a recording
/// is not a credential.
pub const MAX_VALIDITY_SECS: u64 = furcate_authn::local::MAX_VALIDITY_SECS;

/// Nonce length bounds, in characters of `[A-Za-z0-9_-]`. Eight is enough
/// for a counter; the upper bound keeps the replay guard's memory bounded.
pub const NONCE_MIN: usize = 8;
pub const NONCE_MAX: usize = 64;

/// Spent nonces kept across all leaves, and for any one leaf. A full guard
/// refuses rather than forgets: dropping old entries to make room is how a
/// captured request gets a second use. The per-leaf bound stops one leaf from
/// filling the guard for every other.
const NONCES_KEPT: usize = 8192;
const NONCES_PER_LEAF: usize = 512;

/// The parts of a leaf credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub holder: String,
    pub nonce: String,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

impl Credential {
    /// Parse `leaf:<holder>:<nonce>.<expires_at>.<sig hex>`. `None` when it is
    /// not a leaf credential or is malformed.
    pub fn parse(cred: &str) -> Option<Credential> {
        let rest = cred.strip_prefix(SCHEME)?;
        // The holder carries its own colon (`p256:...`); the signed part has none.
        let (holder, signed) = rest.rsplit_once(':')?;
        let mut parts = signed.split('.');
        let nonce = parts.next()?;
        let expires_at: u64 = parts.next()?.parse().ok()?;
        let signature = hex::decode(parts.next()?).ok()?;
        if parts.next().is_some() || holder.is_empty() || !nonce_is_well_formed(nonce) {
            return None;
        }
        Some(Credential { holder: holder.to_string(), nonce: nonce.to_string(), expires_at, signature })
    }

    /// The credential as it is carried.
    pub fn header_value(&self) -> String {
        format!("{SCHEME}{}:{}.{}.{}", self.holder, self.nonce, self.expires_at, hex::encode(&self.signature))
    }
}

fn nonce_is_well_formed(nonce: &str) -> bool {
    (NONCE_MIN..=NONCE_MAX).contains(&nonce.len())
        && nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A leaf whose request was admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedLeaf {
    /// The key its link names.
    pub holder: String,
    /// The leaf's name in its link.
    pub name: String,
    pub assurance: AssuranceClass,
    /// The cell it is attached to.
    pub cell: String,
    pub expires_at: u64,
}

/// Checks leaf requests for one head and remembers the nonces it has seen.
#[derive(Default)]
pub struct LeafRequests {
    seen: Mutex<BTreeMap<(String, String), u64>>,
}

/// What every signature failure says, whichever part did not match.
pub const NOT_SIGNED: &str = "that request is not signed by the key it names";

impl LeafRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check `presented` against the leaves of cell `cell` in `tree`, which is
    /// the tree read from this node's files with revocations applied.
    pub fn verify(&self, tree: &CellTree, cell: &str, presented: &Presented, now: u64) -> Result<AdmittedLeaf, Refusal> {
        let Some(raw) = presented.credential.as_deref() else {
            return Err(Refusal::new("no credential was presented"));
        };
        if !raw.starts_with(SCHEME) {
            return Err(Refusal::not_mine("the credential is not a leaf signature"));
        }
        let Some(c) = Credential::parse(raw) else {
            return Err(Refusal::new(format!(
                "a leaf credential is {SCHEME}<key>:<nonce>.<expires_at>.<signature hex>, with a nonce of \
                 {NONCE_MIN} to {NONCE_MAX} characters of A-Z a-z 0-9 - _"
            )));
        };

        // Expiry first: cheap, and it gives nothing away.
        if c.expires_at <= now {
            return Err(Refusal::new("that request has expired; check the leaf's clock"));
        }
        if c.expires_at.saturating_sub(now) > MAX_VALIDITY_SECS {
            return Err(Refusal::new(format!(
                "a request may not be valid for more than {MAX_VALIDITY_SECS} seconds; check the leaf's clock"
            )));
        }

        // The key the credential names, in the one spelling links use.
        let key = CellKey::parse(&c.holder).map_err(|_| Refusal::new(NOT_SIGNED))?;
        if key.id() != c.holder {
            return Err(Refusal::new(format!(
                "name the key as the leaf's link does: {}",
                key.id()
            )));
        }
        let input = furcate_authn::signing_input(&presented.method, &presented.path, &presented.body, &c.nonce, c.expires_at);
        key.verify(input.as_bytes(), &c.signature).map_err(|_| Refusal::new(NOT_SIGNED))?;

        // The signer is who it says. Now: is it a leaf of this cell, today.
        let Some(here) = tree.find(cell) else {
            return Err(Refusal::structural(format!("this node's own cell {cell} did not derive from its links")));
        };
        let Some(member) = here.leaves.iter().find(|m| m.holder == c.holder) else {
            let why = tree
                .refused
                .iter()
                .find(|r| r.holder == c.holder && r.scope.path() == Some(cell))
                .map(|r| format!(": its link is refused ({})", r.why))
                .unwrap_or_default();
            return Err(Refusal::new(format!("{} is not a leaf attached to cell {cell}{why}", c.holder)));
        };
        if member.until <= now {
            return Err(Refusal::new(format!("leaf {}'s link to cell {cell} ended at {}", member.name, member.until)));
        }
        let Some(assurance) = member.assurance else {
            return Err(Refusal::new(format!("leaf {}'s link records no class, so no floor can admit it", member.name)));
        };
        furcate_identity::leaf::admits_leaf(Some(here.leaf_min_class), assurance)
            .map_err(|why| Refusal::new(format!("leaf {} is refused by cell {cell}: {why}", member.name)))?;

        self.spend(&c.holder, &c.nonce, c.expires_at, now)?;
        Ok(AdmittedLeaf {
            holder: c.holder,
            name: member.name.clone(),
            assurance,
            cell: cell.to_string(),
            expires_at: c.expires_at.min(member.until),
        })
    }

    fn spend(&self, holder: &str, nonce: &str, expires_at: u64, now: u64) -> Result<(), Refusal> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| Refusal::new("the replay guard is not in a state that can be trusted"))?;
        seen.retain(|_, exp| *exp > now);
        let k = (holder.to_string(), nonce.to_string());
        if seen.contains_key(&k) {
            return Err(Refusal::new("that request has already been made; a signature is good once"));
        }
        if seen.len() >= NONCES_KEPT {
            return Err(Refusal::new("too many requests in flight to guard against replay"));
        }
        if seen.keys().filter(|(h, _)| h == holder).count() >= NONCES_PER_LEAF {
            return Err(Refusal::new("this leaf has too many requests in flight to guard against replay"));
        }
        seen.insert(k, expires_at);
        Ok(())
    }
}

/// Make a leaf credential with whatever holds the leaf's key. `sign` is
/// given the canonical request and returns the signature in any form
/// [`CellKey::verify`] accepts; it is kept as P-256 `r || s` low-S, or the
/// 64-byte Ed25519 signature.
pub fn credential(
    holder: &str,
    method: &str,
    target: &str,
    body: &[u8],
    nonce: &str,
    expires_at: u64,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<String, String> {
    if !nonce_is_well_formed(nonce) {
        return Err(format!("a nonce is {NONCE_MIN} to {NONCE_MAX} characters of A-Z a-z 0-9 - _"));
    }
    let key = CellKey::parse(holder)?;
    let input = furcate_authn::signing_input(method, target, body, nonce, expires_at);
    let sig = hex::decode(key.seal(input.as_bytes(), &sign(input.as_bytes())?)?).map_err(|e| e.to_string())?;
    Ok(Credential { holder: key.id(), nonce: nonce.to_string(), expires_at, signature: sig }.header_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::{ed25519_id, p256_id, CellDelegation, CellFile, CellRevocation, NodeFiles, Role, Scale, Scope};
    use ed25519_dalek::Signer as _;

    const NOW: u64 = 1_791_800_000;
    const YEAR: u64 = 365 * 86_400;
    const BODY: &[u8] = br#"{"model":"qwen3-0.6b","messages":[{"role":"user","content":"ok"}],"max_tokens":8}"#;
    const TARGET: &str = "/v1/chat/completions";

    // Test-only keys. On a leaf the key is derived from its silicon and never
    // leaves it; on a node it is in the TPM.
    fn ed(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }
    fn leaf_key(n: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap()
    }
    fn leaf_id(k: &p256::ecdsa::SigningKey) -> String {
        p256_id(k.verifying_key())
    }

    fn link(by: &ed25519_dalek::SigningKey, above: Option<&CellDelegation>, holder: String, role: Role, name: &str, class: AssuranceClass) -> CellDelegation {
        CellDelegation {
            site: "home".into(),
            issuer: ed25519_id(&by.verifying_key()),
            holder,
            role,
            scope: Scope::parse(if role == Role::Controller { "site" } else { "cell:lab" }).unwrap(),
            scale: (role == Role::Head).then_some(Scale::Other),
            assurance: Some(class),
            leaf_min_class: None,
            endpoint: String::new(),
            name: name.into(),
            parent: above.map(|a| a.digest()),
            not_before: NOW - 100,
            not_after: above.map(|a| a.not_after).unwrap_or(NOW + YEAR),
            signature: String::new(),
        }
        .signed_by(|m| Ok(by.sign(m).to_bytes().to_vec()))
        .unwrap()
    }

    /// A head's files on disk, as the gateway reads them: operator.pub, the
    /// head's anchor, and the links it signed for its leaves.
    struct Head {
        dir: std::path::PathBuf,
        files: NodeFiles,
        head_link: CellDelegation,
    }

    impl Drop for Head {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn head(tag: &str, floor: Option<AssuranceClass>, leaves: &[(String, &str, AssuranceClass)]) -> Head {
        let dir = std::env::temp_dir().join(format!("furcate-leafreq-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let op = ed(1);
        let ctl = link(&op, None, ed25519_id(&ed(2).verifying_key()), Role::Controller, "core", AssuranceClass::Device);
        let mut h = link(&ed(2), Some(&ctl), ed25519_id(&ed(3).verifying_key()), Role::Head, "pi-lab", AssuranceClass::Device);
        if floor.is_some() {
            h.leaf_min_class = floor;
            h.signature.clear();
            h = h.signed_by(|m| Ok(ed(2).sign(m).to_bytes().to_vec())).unwrap();
        }
        let mut links = vec![ctl.clone()];
        for (holder, name, class) in leaves {
            links.push(link(&ed(3), Some(&h), holder.clone(), Role::Leaf, name, *class));
        }
        std::fs::write(dir.join("operator.pub"), hex::encode(op.verifying_key().to_bytes())).unwrap();
        std::fs::write(
            dir.join("cell-anchor.json"),
            serde_json::to_string(&serde_json::json!({ "own": h, "parent_endpoint": "core:7616" })).unwrap(),
        )
        .unwrap();
        let file = CellFile { site: "home".into(), links, revoked: vec![] };
        std::fs::write(dir.join("cells-issued.json"), serde_json::to_string(&file).unwrap()).unwrap();
        let files = NodeFiles {
            anchor: dir.join("cell-anchor.json"),
            links: vec![dir.join("cells.json"), dir.join("cells-issued.json")],
            operator_pub: dir.join("operator.pub"),
        };
        Head { dir, files, head_link: h }
    }

    fn presented(method: &str, target: &str, body: &[u8], credential: String) -> Presented {
        Presented { method: method.into(), path: target.into(), body: body.to_vec(), credential: Some(credential) }
    }

    fn signed(k: &p256::ecdsa::SigningKey, nonce: &str, expires_at: u64) -> String {
        credential(&leaf_id(k), "POST", TARGET, BODY, nonce, expires_at, |m| {
            let s: p256::ecdsa::Signature = k.sign(m);
            Ok(s.to_bytes().to_vec())
        })
        .unwrap()
    }

    fn check(h: &Head, p: &Presented, guard: &LeafRequests, now: u64) -> Result<AdmittedLeaf, String> {
        let (cell, tree) = h.files.headed_tree(now)?;
        guard.verify(&tree, &cell, p, now).map_err(|r| r.because)
    }

    #[test]
    fn a_request_signed_by_an_attached_leaf_is_admitted() {
        let k = leaf_key(8);
        let h = head("ok", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let g = LeafRequests::new();
        let leaf = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-00000001", NOW + 60)), &g, NOW).unwrap();
        assert_eq!((leaf.name.as_str(), leaf.cell.as_str(), leaf.assurance), ("esp-8", "lab", AssuranceClass::Device));
    }

    #[test]
    fn a_der_signature_from_hardware_is_admitted_too() {
        let k = leaf_key(8);
        let h = head("der", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let input = furcate_authn::signing_input("POST", TARGET, BODY, "n-0000der1", NOW + 60);
        let s: p256::ecdsa::Signature = k.sign(input.as_bytes());
        let c = Credential { holder: leaf_id(&k), nonce: "n-0000der1".into(), expires_at: NOW + 60, signature: s.to_der().as_bytes().to_vec() };
        check(&h, &presented("POST", TARGET, BODY, c.header_value()), &LeafRequests::new(), NOW).unwrap();
    }

    #[test]
    fn a_signature_by_another_key_is_refused() {
        let k = leaf_key(8);
        let h = head("wrongkey", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let other = leaf_key(9);
        let input = furcate_authn::signing_input("POST", TARGET, BODY, "n-00000002", NOW + 60);
        let s: p256::ecdsa::Signature = other.sign(input.as_bytes());
        // Claims the attached leaf's key, signed by another.
        let c = Credential { holder: leaf_id(&k), nonce: "n-00000002".into(), expires_at: NOW + 60, signature: s.to_bytes().to_vec() };
        let err = check(&h, &presented("POST", TARGET, BODY, c.header_value()), &LeafRequests::new(), NOW).unwrap_err();
        assert_eq!(err, NOT_SIGNED);
        // And a key that signs for itself but is attached nowhere here.
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&other, "n-00000003", NOW + 60)), &LeafRequests::new(), NOW).unwrap_err();
        assert!(err.contains("is not a leaf attached to cell lab"), "{err}");
    }

    #[test]
    fn a_replayed_request_is_refused() {
        let k = leaf_key(8);
        let h = head("replay", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let g = LeafRequests::new();
        let p = presented("POST", TARGET, BODY, signed(&k, "n-00000004", NOW + 60));
        check(&h, &p, &g, NOW).unwrap();
        let err = check(&h, &p, &g, NOW + 1).unwrap_err();
        assert!(err.contains("already been made"), "{err}");
    }

    #[test]
    fn a_stale_or_far_future_timestamp_is_refused() {
        let k = leaf_key(8);
        let h = head("stale", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let g = LeafRequests::new();
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-00000005", NOW)), &g, NOW).unwrap_err();
        assert!(err.contains("expired"), "{err}");
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-00000006", NOW + MAX_VALIDITY_SECS + 1)), &g, NOW).unwrap_err();
        assert!(err.contains("may not be valid for more than"), "{err}");
    }

    #[test]
    fn a_tampered_body_method_or_target_is_refused() {
        let k = leaf_key(8);
        let h = head("tamper", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let g = LeafRequests::new();
        let c = signed(&k, "n-00000007", NOW + 60);
        let altered = String::from_utf8(BODY.to_vec()).unwrap().replace("\"ok\"", "\"ko\"");
        for p in [
            presented("POST", TARGET, altered.as_bytes(), c.clone()),
            presented("GET", TARGET, BODY, c.clone()),
            presented("POST", "/v1/completions", BODY, c.clone()),
            presented("POST", "/v1/chat/completions?x=1", BODY, c.clone()),
        ] {
            assert_eq!(check(&h, &p, &g, NOW).unwrap_err(), NOT_SIGNED);
        }
        // A forged attempt did not spend the leaf's nonce.
        check(&h, &presented("POST", TARGET, BODY, c), &g, NOW).unwrap();
    }

    #[test]
    fn a_leaf_below_the_cells_current_floor_is_refused() {
        // Attached as `soft` while the floor allowed it; the floor is now `device`.
        let k = leaf_key(8);
        let h = head("floor", Some(AssuranceClass::Device), &[(leaf_id(&k), "esp-8", AssuranceClass::Soft)]);
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-00000008", NOW + 60)), &LeafRequests::new(), NOW).unwrap_err();
        assert!(err.contains("below the cell's leaf floor"), "{err}");
        // The same leaf in a cell whose floor is `soft` is admitted.
        let h = head("floor-soft", Some(AssuranceClass::Soft), &[(leaf_id(&k), "esp-8", AssuranceClass::Soft)]);
        check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-00000009", NOW + 60)), &LeafRequests::new(), NOW).unwrap();
    }

    #[test]
    fn a_revoked_leaf_is_refused_with_the_operators_reason() {
        let k = leaf_key(8);
        let h = head("revoked", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        let path = h.dir.join("cells-issued.json");
        let mut file: CellFile = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let leaf_link = file.links.iter().find(|l| l.role == Role::Leaf).unwrap().digest();
        let op = ed(1);
        let r = CellRevocation {
            site: "home".into(),
            link: leaf_link,
            reason: "lost in the field".into(),
            at: NOW - 1,
            issuer: ed25519_id(&op.verifying_key()),
            signature: String::new(),
        }
        .signed_by(|m| Ok(op.sign(m).to_bytes().to_vec()))
        .unwrap();
        file.revoked.push(r);
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-0000000a", NOW + 60)), &LeafRequests::new(), NOW).unwrap_err();
        assert!(err.contains("lost in the field"), "{err}");
    }

    #[test]
    fn a_leaf_whose_link_has_ended_is_refused() {
        let k = leaf_key(8);
        let h = head("ended", None, &[(leaf_id(&k), "esp-8", AssuranceClass::Device)]);
        // Re-issue the leaf's link to end in an hour.
        let path = h.dir.join("cells-issued.json");
        let mut file: CellFile = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for l in file.links.iter_mut().filter(|l| l.role == Role::Leaf) {
            l.not_after = NOW + 3600;
            l.signature.clear();
            *l = l.clone().signed_by(|m| Ok(ed(3).sign(m).to_bytes().to_vec())).unwrap();
        }
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        let g = LeafRequests::new();
        check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-0000000b", NOW + 60)), &g, NOW).unwrap();
        let later = NOW + 3601;
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-0000000d", later + 60)), &g, later).unwrap_err();
        assert!(err.contains("is not a leaf attached to cell lab"), "{err}");
        // And when the head's own link ends, the node heads nothing.
        let after = h.head_link.not_after + 1;
        let err = check(&h, &presented("POST", TARGET, BODY, signed(&k, "n-0000000e", after + 60)), &g, after).unwrap_err();
        assert!(err.contains("is live from"), "{err}");
    }

    #[test]
    fn credentials_parse_strictly() {
        let k = leaf_key(8);
        let c = signed(&k, "n-0000000c", NOW + 60);
        let parsed = Credential::parse(&c).unwrap();
        assert_eq!(parsed.holder, leaf_id(&k));
        assert_eq!(parsed.header_value(), c);
        for bad in ["op:abc.1.00", "leaf:", "leaf:p256:02aa:short.1.00", "leaf:p256:02aa:n-0000000c.x.00", "leaf:p256:02aa:n-00000:0c.1.00", "leaf:p256:02aa:n-0000000c.1.zz", "leaf:p256:02aa:n-0000000c.1.00.0"] {
            assert!(Credential::parse(bad).is_none(), "{bad}");
        }
    }

    /// The canonical request a leaf signs, byte for byte. The reference
    /// client and the leaf firmware are held to the same vector.
    #[test]
    fn the_canonical_request_is_fixed() {
        let input = furcate_authn::signing_input("post", TARGET, BODY, "n-00000001", 1_791_800_060);
        assert_eq!(
            input,
            "furcate-request/1\nPOST\n/v1/chat/completions\n\
             7c8a1c1aca564a14f4af1c3b9b3761486bfae7f819c920489c632e929c36b0d5\n\
             n-00000001\n1791800060\n"
        );
    }
}
