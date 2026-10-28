//! The site's written authority, read once.
//!
//! The resolution order and the three outcomes — absent is ordinary, present
//! and unreadable is fatal, present and unparseable is fatal — now live in
//! `furcate_policy::file`, because `furcate deploy` rules against the same
//! file and two implementations would be two answers to "what is permitted
//! here". What stays here is this binary's response to a fatal one: a daemon
//! that cannot know what is permitted must not start.
//!
//! A node on a site holds the site's signed overlay policy
//! ([`furcate_net::sitepolicy`]) in its state directory and reads that before
//! any local file: the local file is where a site without a controller keeps
//! its rules, and where this site's rules lived before they were one signed
//! document. A held document is checked against the anchors every time it is
//! read; one that no longer verifies is refused, never skipped, because
//! skipping it would hand authority back to whatever file sits behind it.

/// The last signed overlay policy this node accepted.
pub fn signed_path() -> String {
    furcate_paths::state("overlay-policy.signed.json").display().to_string()
}

/// The readable copy written beside it. Never read back.
pub fn rendered_path() -> String {
    furcate_paths::state("overlay-policy.yaml").display().to_string()
}

/// Where the rules came from, for the one line that says so.
pub enum Origin {
    Signed { version: u64, key_id: String },
    Local(furcate_policy::file::Source),
}

/// Resolve the rules: an explicit `FURCATE_OVERLAY_POLICY` first, then the
/// held signed document, then the local file, then the compiled default.
pub fn resolve(
    anchors: impl FnOnce() -> Result<furcate_net::lock::Anchors, String>,
    signed: &str,
    config_path: &str,
) -> Result<(furcate_policy::PolicySet, Origin), String> {
    let explicit = std::env::var("FURCATE_OVERLAY_POLICY").unwrap_or_default();
    if explicit.is_empty() {
        if let Some(doc) = furcate_net::sitepolicy::read(signed)? {
            let anchors = anchors()?;
            let set = furcate_net::sitepolicy::verify(&anchors, &doc)
                .map_err(|e| format!("the held site policy {signed}: {e}"))?;
            return Ok((set, Origin::Signed { version: doc.version, key_id: doc.key_id }));
        }
    }
    let candidates = furcate_policy::file::default_candidates(config_path);
    furcate_policy::file::load_from(&candidates)
        .map(|(p, s)| (p, Origin::Local(s)))
        .map_err(|e| e.to_string())
}

pub fn load() -> furcate_policy::PolicySet {
    match resolve(
        super::overlay::anchors,
        &signed_path(),
        &furcate_paths::config("overlay-policy.yaml").display().to_string(),
    ) {
        Ok((p, Origin::Signed { version, key_id })) => {
            eprintln!(
                "furcated: policy from the site's signed overlay policy v{version} ({key_id}, {} rules)",
                p.policies.len()
            );
            p
        }
        Ok((p, Origin::Local(furcate_policy::file::Source::File(path)))) => {
            eprintln!("furcated: policy from {path} ({} rules)", p.policies.len());
            p
        }
        Ok((p, Origin::Local(furcate_policy::file::Source::CompiledDefault))) => p,
        Err(e) => {
            eprintln!("furcated: FATAL {e}");
            std::process::exit(1);
        }
    }
}

/// Take a document the coordinator offered.
///
/// Verified, compared with the one held, and kept only if newer. Returns the
/// rules when they changed, so the caller can start using them; `Ok(None)`
/// when the document is the one already held.
pub fn accept(
    anchors: &furcate_net::lock::Anchors,
    offered: &furcate_net::sitepolicy::SignedPolicy,
    signed: &str,
    rendered: &str,
) -> Result<Option<furcate_policy::PolicySet>, String> {
    use furcate_net::sitepolicy::{compare, verify, Offer};
    let set = verify(anchors, offered)?;
    // A held copy that cannot be read is not "nothing held": accepting
    // anything over it would let an older document in after a damaged file.
    let held = furcate_net::sitepolicy::read(signed)?;
    match compare(held.as_ref(), offered) {
        Offer::Same => Ok(None),
        Offer::Older => Err(format!(
            "the site offered policy v{}, older than the v{} held here; kept what is held",
            offered.version,
            held.map(|h| h.version).unwrap_or_default(),
        )),
        Offer::Conflicting => Err(format!(
            "the site offered a policy v{} whose rules differ from the v{} held here; a version is signed once",
            offered.version, offered.version
        )),
        Offer::Newer => {
            furcate_net::sitepolicy::write(offered, signed, Some(rendered))?;
            Ok(Some(set))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_net::lock::{Anchor, Anchors};
    use furcate_net::sitepolicy::sign;

    const ALLOW_PLATFORM: &str = "policies:\n  - effect: allow\n    principal: \"*\"\n    action: join\n    resource: tier:platform\n    reason: t\n";
    const LOCAL: &str = "policies:\n  - effect: allow\n    principal: operator\n    action: deploy\n    resource: \"*\"\n    reason: t\n  - effect: allow\n    principal: operator\n    action: restart\n    resource: \"*\"\n    reason: t\n";

    fn op() -> (ed25519_dalek::SigningKey, Anchors) {
        let k = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let mut a = Anchors::new();
        a.trust(&Anchor { key_id: "op-3".into(), public_key: hex::encode(k.verifying_key().to_bytes()) })
            .unwrap();
        (k, a)
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("furcated-policyfile-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_signed_document_wins_over_the_local_file_and_a_tampered_one_is_fatal() {
        let d = dir("wins");
        let (k, anchors) = op();
        let signed = d.join("s.json").display().to_string();
        let rendered = d.join("s.yaml").display().to_string();
        let local = d.join("local.yaml");
        std::fs::write(&local, LOCAL).unwrap();
        let local = local.display().to_string();

        // Nothing held: the local file, as before.
        let (p, o) = resolve(|| Ok(anchors.clone()), &signed, &local).unwrap();
        assert!(matches!(o, Origin::Local(_)));
        assert_eq!(p.policies.len(), 2);

        // Accepted from the site: now the signed rules, not the local ones.
        let v1 = sign("op-3", &k, 1, ALLOW_PLATFORM).unwrap();
        assert!(accept(&anchors, &v1, &signed, &rendered).unwrap().is_some());
        let (p, o) = resolve(|| Ok(anchors.clone()), &signed, &local).unwrap();
        assert!(matches!(o, Origin::Signed { version: 1, .. }));
        assert_eq!(p.policies.len(), 1);

        // The held copy edited by hand: refused, not skipped.
        let mut doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&signed).unwrap()).unwrap();
        doc["policy"] = serde_json::json!(ALLOW_PLATFORM.replace("tier:platform", "tier:soft"));
        std::fs::write(&signed, doc.to_string()).unwrap();
        assert!(resolve(|| Ok(anchors.clone()), &signed, &local).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_node_moves_forward_only() {
        let d = dir("forward");
        let (k, anchors) = op();
        let signed = d.join("s.json").display().to_string();
        let rendered = d.join("s.yaml").display().to_string();
        let v1 = sign("op-3", &k, 1, ALLOW_PLATFORM).unwrap();
        let v2 = sign("op-3", &k, 2, LOCAL).unwrap();
        assert!(accept(&anchors, &v2, &signed, &rendered).unwrap().is_some());
        assert!(accept(&anchors, &v2, &signed, &rendered).unwrap().is_none(), "the same document changes nothing");
        assert!(accept(&anchors, &v1, &signed, &rendered).unwrap_err().contains("older"));
        let v2b = sign("op-3", &k, 2, ALLOW_PLATFORM).unwrap();
        assert!(accept(&anchors, &v2b, &signed, &rendered).is_err());
        // An unsigned offer never reaches the disk.
        let forged = furcate_net::sitepolicy::SignedPolicy { version: 9, ..v2.clone() };
        assert!(accept(&anchors, &forged, &signed, &rendered).is_err());
        assert_eq!(furcate_net::sitepolicy::read(&signed).unwrap(), Some(v2));
        std::fs::remove_dir_all(&d).ok();
    }
}
