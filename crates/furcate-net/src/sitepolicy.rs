//! The overlay policy as one document for the whole site, signed by an anchor.
//!
//! Each node decides which peers it carries from rules it holds, and those
//! rules used to be a file written by hand on every machine. Files written by
//! hand on every machine drift: the same site ended up with four different
//! answers to "who may join", and only one machine admitted a peer the
//! operator had approved for all of them.
//!
//! Here the rules are one document, signed by a key in the overlay's anchor
//! set — the same keys that authorize a machine onto the overlay, held where
//! the fleet is not. The coordinator stores and serves it and every node
//! verifies it, so the coordinator carries the rules without being able to
//! write them: it can withhold a newer document or offer an older one, and a
//! node refuses the older one because each document carries a version and a
//! node never goes back.
//!
//! The node keeps the last document it accepted, signature and all, and checks
//! it again whenever it reads it. A copy on disk that no longer verifies is
//! somebody's edit, and it is refused rather than obeyed.

use crate::lock::Anchors;
use furcate_policy::PolicySet;
use serde::{Deserialize, Serialize};

/// Domain separation from every other signature an anchor makes.
const CONTEXT: &[u8] = b"furcate-overlay-policy-v1";

/// One signed statement of the site's overlay rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// Increases with every document the operator signs. A node accepts a
    /// document only above the version it holds.
    pub version: u64,
    /// The rules, in the YAML an operator writes and every node parses.
    pub policy: String,
    /// The anchor that signed, named so a retired key is refused by name.
    pub key_id: String,
    /// Over [`signed_bytes`], hex: Ed25519, or P-256 for a hardware anchor.
    pub signature: String,
}

/// The bytes an anchor signs. Length-delimited, as every signed thing here is.
pub fn signed_bytes(version: u64, policy: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTEXT.len() + 12 + policy.len());
    out.extend_from_slice(CONTEXT);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(policy.len() as u32).to_be_bytes());
    out.extend_from_slice(policy.as_bytes());
    out
}

/// Sign `policy` as version `version`.
///
/// Refused unless the rules parse: a signature over rules no node can read is
/// a document every node would refuse, discovered one node at a time.
pub fn sign(
    key_id: &str,
    signing: &ed25519_dalek::SigningKey,
    version: u64,
    policy: &str,
) -> Result<SignedPolicy, String> {
    use ed25519_dalek::Signer;
    PolicySet::parse(policy).map_err(|e| format!("the policy does not parse: {e}"))?;
    if version == 0 {
        return Err("a version must be above zero".into());
    }
    Ok(SignedPolicy {
        version,
        policy: policy.to_string(),
        key_id: key_id.to_string(),
        signature: hex::encode(signing.sign(&signed_bytes(version, policy)).to_bytes()),
    })
}

/// Check a document against the anchors and return the rules it carries.
///
/// An overlay with no anchors has nothing to check a signature with, so it
/// cannot hold a signed policy at all; that is refused rather than accepted
/// unchecked.
pub fn verify(anchors: &Anchors, doc: &SignedPolicy) -> Result<PolicySet, String> {
    if anchors.is_empty() {
        return Err("this node holds no overlay anchors, so it cannot check a signed policy".into());
    }
    let key = anchors.key(&doc.key_id).ok_or_else(|| {
        format!("the policy is signed by `{}`, which is not an anchor this node holds", doc.key_id)
    })?;
    key.verify_hex(&signed_bytes(doc.version, &doc.policy), &doc.signature)
        .map_err(|_| format!("the signature on policy version {} does not verify", doc.version))?;
    PolicySet::parse(&doc.policy).map_err(|e| format!("policy version {} does not parse: {e}", doc.version))
}

/// How an offered document compares with the one held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offer {
    /// Above the held version, or nothing is held: take it.
    Newer,
    /// The document already held.
    Same,
    /// Below the held version: a replay, or a coordinator restored from an
    /// old backup. Refused.
    Older,
    /// The held version number over different rules. Two signed documents
    /// claiming one version is an operator error that must be seen.
    Conflicting,
}

pub fn compare(held: Option<&SignedPolicy>, offered: &SignedPolicy) -> Offer {
    match held {
        None => Offer::Newer,
        Some(h) if offered.version > h.version => Offer::Newer,
        Some(h) if offered.version < h.version => Offer::Older,
        Some(h) if h.policy == offered.policy => Offer::Same,
        Some(_) => Offer::Conflicting,
    }
}

/// The human-readable copy a node writes beside the signed one.
pub fn render(doc: &SignedPolicy) -> String {
    format!(
        "# The site's overlay policy, version {}, signed by {}.\n\
         # A copy for reading. The node reads the signed document beside it,\n\
         # so an edit here changes nothing; publish a new version instead\n\
         # (furcatectl overlay policy publish).\n\n{}",
        doc.version, doc.key_id, doc.policy
    )
}

/// Read a held document. Absent is `None`; present and unreadable or
/// malformed is an error, so a damaged copy is never mistaken for none.
pub fn read(path: &str) -> Result<Option<SignedPolicy>, String> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{path} exists and cannot be read: {e}")),
        Ok(t) => serde_json::from_str(&t)
            .map(Some)
            .map_err(|e| format!("{path} is not a signed policy: {e}")),
    }
}

/// Write `doc` to `path` and its rendered copy to `rendered`, each replaced
/// whole so a reader never sees half of one.
pub fn write(doc: &SignedPolicy, path: &str, rendered: Option<&str>) -> Result<(), String> {
    fn put(path: &str, body: &str) -> Result<(), String> {
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, body).map_err(|e| format!("writing {tmp}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("replacing {path}: {e}"))
    }
    let json = serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?;
    put(path, &json)?;
    if let Some(r) = rendered {
        put(r, &render(doc))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::Anchor;

    const RULES: &str = "policies:\n  - effect: allow\n    principal: \"*\"\n    action: join\n    resource: tier:platform\n    reason: test\n";

    fn op(seed: u8) -> (ed25519_dalek::SigningKey, Anchors, String) {
        let k = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let id = format!("op-{seed}");
        let mut a = Anchors::new();
        a.trust(&Anchor { key_id: id.clone(), public_key: hex::encode(k.verifying_key().to_bytes()) })
            .unwrap();
        (k, a, id)
    }

    #[test]
    fn a_document_an_anchor_signed_verifies_and_carries_its_rules() {
        let (k, anchors, id) = op(7);
        let doc = sign(&id, &k, 3, RULES).unwrap();
        let set = verify(&anchors, &doc).unwrap();
        assert_eq!(set.policies.len(), 1);
    }

    #[test]
    fn an_edited_rule_or_version_does_not_verify() {
        let (k, anchors, id) = op(7);
        let doc = sign(&id, &k, 3, RULES).unwrap();
        let widened = SignedPolicy { policy: RULES.replace("tier:platform", "tier:soft"), ..doc.clone() };
        assert!(verify(&anchors, &widened).is_err());
        let bumped = SignedPolicy { version: 4, ..doc };
        assert!(verify(&anchors, &bumped).is_err());
    }

    #[test]
    fn a_key_outside_the_anchors_is_refused_by_name() {
        let (_, anchors, _) = op(7);
        let (other, _, other_id) = op(9);
        let doc = sign(&other_id, &other, 1, RULES).unwrap();
        assert!(verify(&anchors, &doc).unwrap_err().contains("not an anchor"));
        // Claiming a held anchor's name with another key's signature fails too.
        let forged = SignedPolicy { key_id: "op-7".into(), ..doc };
        assert!(verify(&anchors, &forged).unwrap_err().contains("does not verify"));
    }

    #[test]
    fn no_anchors_means_no_signed_policy() {
        let (k, _, id) = op(7);
        let doc = sign(&id, &k, 1, RULES).unwrap();
        assert!(verify(&Anchors::new(), &doc).is_err());
    }

    #[test]
    fn rules_that_do_not_parse_are_not_signed() {
        let (k, _, id) = op(7);
        assert!(sign(&id, &k, 1, "policies: [ not a rule").is_err());
        assert!(sign(&id, &k, 0, RULES).is_err());
    }

    #[test]
    fn an_older_document_is_a_replay_and_the_same_version_must_be_the_same_rules() {
        let (k, _, id) = op(7);
        let v2 = sign(&id, &k, 2, RULES).unwrap();
        let v1 = sign(&id, &k, 1, RULES).unwrap();
        let v2b = sign(&id, &k, 2, &RULES.replace("reason: test", "reason: other")).unwrap();
        assert_eq!(compare(None, &v1), Offer::Newer);
        assert_eq!(compare(Some(&v1), &v2), Offer::Newer);
        assert_eq!(compare(Some(&v2), &v1), Offer::Older);
        assert_eq!(compare(Some(&v2), &v2.clone()), Offer::Same);
        assert_eq!(compare(Some(&v2), &v2b), Offer::Conflicting);
    }

    #[test]
    fn a_written_document_reads_back_and_its_rendering_is_marked_as_a_copy() {
        let (k, _, id) = op(7);
        let doc = sign(&id, &k, 5, RULES).unwrap();
        let dir = std::env::temp_dir().join(format!("furcate-sitepolicy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("p.json").display().to_string();
        let r = dir.join("p.yaml").display().to_string();
        assert_eq!(read(&p).unwrap(), None);
        write(&doc, &p, Some(&r)).unwrap();
        assert_eq!(read(&p).unwrap(), Some(doc));
        let rendered = std::fs::read_to_string(&r).unwrap();
        assert!(rendered.starts_with("# The site's overlay policy, version 5"));
        assert!(PolicySet::parse(&rendered).is_ok(), "the copy still parses as rules");
        std::fs::write(&p, "{").unwrap();
        assert!(read(&p).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
