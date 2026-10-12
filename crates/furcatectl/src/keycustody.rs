//! The site's key custody, as `furcatectl` checks it before sealing.
//!
//! Reads the same applied record, operator key, operation chain and reviewed
//! enrolments furcated does, so a seal is refused for the same reason the
//! node would refuse to open a vault. Every enrolled peer is counted as
//! reachable: a stronger machine that is down still outranks this one, which
//! can only make a seal refuse, never make one succeed that furcated would not.

use anyhow::{anyhow, Context, Result};
use furcate_identity::custody::{elect, CustodyGrant};
use furcate_identity::AssuranceClass;
use furcate_policy::custody::{
    existing_material_grant, load, members, sign_self_custody, CustodyChange, OperatorKey,
};
use std::path::{Path, PathBuf};

/// Where custody's inputs live.
pub struct Paths {
    pub record: PathBuf,
    pub ledger: PathBuf,
    pub enrolled: PathBuf,
    pub operator_key: PathBuf,
    pub staged: PathBuf,
}

impl Paths {
    pub fn standard() -> Self {
        Self {
            record: furcate_paths::state("custody.json"),
            ledger: furcate_paths::state("ledger.json"),
            enrolled: furcate_paths::config("enrolled"),
            operator_key: furcate_paths::config("operator.pub"),
            staged: furcate_paths::state("custody-staged"),
        }
    }
}

fn operator_key(path: &Path) -> Option<OperatorKey> {
    let raw = std::fs::read_to_string(path).ok()?;
    let bytes: [u8; 32] = hex::decode(raw.trim()).ok()?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .ok()
        .map(|key| OperatorKey { key })
}

/// The grant this machine holds under the site's custody settings, or why it
/// holds none.
pub fn grant_for(paths: &Paths, site: &str, node_id: &str, class: AssuranceClass) -> Result<CustodyGrant> {
    let operator = operator_key(&paths.operator_key);
    let chain = furcate_ledger::load(&paths.ledger).ok().flatten().unwrap_or_default();
    let loaded = load(&paths.record, operator.as_ref(), site, &chain);
    if let Some(why) = &loaded.refused {
        eprintln!("custody: {why}");
    }
    let (cands, skipped) = members(node_id, class, &paths.enrolled, &|_| true);
    for s in skipped {
        eprintln!("custody: enrolment record skipped: {s}");
    }
    let custody = elect(&loaded.settings, &cands).map_err(|r| {
        anyhow!("refusing to seal: no machine may hold custody under the site's settings: {r}")
    })?;
    custody.grant(node_id).map_err(|r| {
        anyhow!(
            "refusing to seal: this machine ({node_id}, class `{class}`) is not a custody holder \
             under {} custody: {r}",
            custody.mode
        )
    })
}

/// This machine's node id and appraised class, from the root of trust the
/// identity policy selects.
pub fn this_machine() -> Result<(String, AssuranceClass)> {
    let policy = furcate_identity::backends::Policy::in_config_dir(&furcate_paths::config_dir());
    let chosen = furcate_identity::backends::select(&policy)
        .map_err(|e| anyhow!("establishing this machine's custody class: {e}"))?;
    let node_id = chosen.rot.node_id().context("reading this machine's node id")?.to_string();
    Ok((node_id, chosen.class))
}

/// The grant this machine holds to open material already sealed to its own
/// chip, or why it holds none. Asked before the chip is, on every unseal.
///
/// With no custody record the material is self-custody: this machine sealed
/// it to its own TPM before custody existed. New placement through
/// [`grant_for`] still follows the strict elected default.
pub fn unseal_grant_for(
    paths: &Paths,
    site: &str,
    node_id: &str,
    class: AssuranceClass,
) -> Result<(CustodyGrant, &'static str)> {
    let operator = operator_key(&paths.operator_key);
    let chain = furcate_ledger::load(&paths.ledger).ok().flatten().unwrap_or_default();
    let loaded = load(&paths.record, operator.as_ref(), site, &chain);
    let (cands, skipped) = members(node_id, class, &paths.enrolled, &|_| true);
    for s in skipped {
        eprintln!("custody: enrolment record skipped: {s}");
    }
    let grant = existing_material_grant(&loaded, node_id, class, &cands)
        .map_err(|r| anyhow!("refusing to unseal: {r}"))?;
    Ok((grant, loaded.settings_from(&paths.record)))
}

/// Sign a self-custody record for `site` with the operator key and write it to
/// `out`, ready to be placed at `state/custody.json` before a node upgraded
/// onto custody first runs. Refuses to overwrite.
pub fn sign_self(key: &ed25519_dalek::SigningKey, site: &str, out: &Path, reason: &str, now: u64) -> Result<String> {
    if site.trim().is_empty() {
        anyhow::bail!("refusing to sign: no site named");
    }
    if reason.trim().is_empty() {
        anyhow::bail!("refusing to sign: a custody change needs a reason, so it can be explained later");
    }
    if out.exists() {
        anyhow::bail!("{} already exists; refusing to overwrite a custody record", out.display());
    }
    // The window bounds when a change may be applied, not how long it lasts;
    // a record placed directly is checked on load by its signature alone.
    let record = sign_self_custody(key, site, now, 7 * 86_400, reason)
        .map_err(|e| anyhow!("refusing to write: the signed record does not check out: {e}"))?;
    record.save(out).with_context(|| format!("writing {}", out.display()))?;
    Ok(record.change.digest())
}

/// Stage a custody change so a `set_custody` order can name it. Prints the
/// digest the order must carry.
pub fn stage(paths: &Paths, file: &str) -> Result<String> {
    let raw = std::fs::read(file).with_context(|| format!("reading {file}"))?;
    let change: CustodyChange =
        serde_json::from_slice(&raw).with_context(|| format!("{file} is not a custody change"))?;
    change
        .settings
        .validate()
        .map_err(|r| anyhow!("refusing to stage: the custody settings are refused: {r}"))?;
    let digest = change.digest();
    std::fs::create_dir_all(&paths.staged)?;
    let out = paths.staged.join(format!("{digest}.json"));
    std::fs::write(&out, serde_json::to_vec_pretty(&change)?)?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_identity::custody::{CustodyMode, CustodySettings};

    fn scratch(name: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("ctl-custody-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("enrolled")).unwrap();
        Paths {
            record: root.join("custody.json"),
            ledger: root.join("ledger.json"),
            enrolled: root.join("enrolled"),
            operator_key: root.join("operator.pub"),
            staged: root.join("staged"),
        }
    }

    #[test]
    fn a_tpm_machine_may_seal_by_default() {
        let p = scratch("tpm");
        let g = grant_for(&p, "site-a", "node-a", AssuranceClass::Tpm).unwrap();
        assert_eq!(g.record().mode, CustodyMode::Elected);
        assert_eq!(g.record().class, AssuranceClass::Tpm);
    }

    #[test]
    fn an_enclave_machine_is_refused_by_default_with_the_reason() {
        let p = scratch("se");
        let e = grant_for(&p, "site-a", "mac", AssuranceClass::SecureElement).unwrap_err();
        let e = e.to_string();
        assert!(e.starts_with("refusing to seal") && e.contains("custody.tpm_less"), "{e}");
    }

    #[test]
    fn a_weaker_machine_is_refused_when_stronger_ones_fill_the_spread() {
        let p = scratch("peer");
        for (name, id) in [("node-a", "a"), ("node-b", "b")] {
            let peer = serde_json::json!({
                "node_id": id.repeat(64),
                "assurance": "tpm",
                "hostname": name,
                "endorsed": true,
                "evidence_digest": "00",
                "pcrs": {},
            });
            std::fs::write(p.enrolled.join(format!("{name}.json")), peer.to_string()).unwrap();
        }
        let e = grant_for(&p, "site-a", "dice-1", AssuranceClass::Dice).unwrap_err().to_string();
        assert!(e.contains("not a custody holder") && e.contains("spread"), "{e}");
    }

    #[test]
    fn with_no_record_this_machine_still_opens_what_it_sealed() {
        let p = scratch("upgrade");
        for (name, id) in [("node-a", "a"), ("node-b", "b")] {
            let peer = serde_json::json!({
                "node_id": id.repeat(64),
                "assurance": "tpm",
                "hostname": name,
                "endorsed": true,
                "evidence_digest": "00",
                "pcrs": {},
            });
            std::fs::write(p.enrolled.join(format!("{name}.json")), peer.to_string()).unwrap();
        }
        let me = "f".repeat(64);
        let (g, from) = unseal_grant_for(&p, "site-a", &me, AssuranceClass::Tpm).unwrap();
        assert_eq!((g.mode(), from), (CustodyMode::SelfCustody, "none"));
        // Sealing anything new still needs the strict election, which the
        // two peers win.
        let e = grant_for(&p, "site-a", &me, AssuranceClass::Tpm).unwrap_err().to_string();
        assert!(e.contains("not a custody holder"), "{e}");
    }

    #[test]
    fn sign_self_writes_a_record_the_node_loads_and_refuses_to_overwrite() {
        let p = scratch("sign-self");
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        std::fs::write(&p.operator_key, hex::encode(key.verifying_key().as_bytes())).unwrap();
        let digest = sign_self(&key, "site-a", &p.record, "upgrade onto custody", 1_000).unwrap();
        assert_eq!(digest.len(), 64);
        let (g, from) = unseal_grant_for(&p, "site-a", "dice-1", AssuranceClass::Dice).unwrap();
        assert_eq!((g.mode(), from), (CustodyMode::SelfCustody, "operator"));

        let again = sign_self(&key, "site-a", &p.record, "again", 1_000).unwrap_err().to_string();
        assert!(again.contains("refusing to overwrite"), "{again}");
        let no_reason = sign_self(&key, "site-a", &p.staged, " ", 1_000).unwrap_err().to_string();
        assert!(no_reason.contains("needs a reason"), "{no_reason}");

        // Signed by a key the node does not hold as its operator key: refused,
        // and the node opens its material on the strict default instead.
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        std::fs::remove_file(&p.record).unwrap();
        sign_self(&other, "site-a", &p.record, "forged", 1_000).unwrap();
        let (g, from) = unseal_grant_for(&p, "site-a", "dice-1", AssuranceClass::Dice).unwrap();
        assert_eq!((g.mode(), from), (CustodyMode::Elected, "default"));
    }

    #[test]
    fn staging_names_the_digest_an_order_must_carry() {
        let p = scratch("stage");
        let change = CustodyChange {
            site: "site-a".into(),
            epoch: 1,
            not_before: 0,
            not_after: 10,
            predecessor: None,
            settings: CustodySettings { tpm_less: true, ..Default::default() },
            reason: "enclave cluster".into(),
            signature: String::new(),
        };
        let file = p.staged.with_extension("in.json");
        std::fs::write(&file, serde_json::to_vec(&change).unwrap()).unwrap();
        let digest = stage(&p, file.to_str().unwrap()).unwrap();
        assert_eq!(digest, change.digest());
        assert!(p.staged.join(format!("{digest}.json")).exists());

        let bad = CustodyChange {
            settings: CustodySettings { allow_soft: true, ..Default::default() },
            ..change
        };
        std::fs::write(&file, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(stage(&p, file.to_str().unwrap()).unwrap_err().to_string().contains("tpm_less"));
    }
}
