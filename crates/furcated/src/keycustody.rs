//! Who holds this site's keys, as this node runs it.
//!
//! The settings in force are the applied custody record in the state
//! directory (`custody.json`), checked again on every load. A record that is
//! unreadable, unsigned, signed by anyone else, for another site, or a passkey
//! change this node's own operation chain does not show it applying, is
//! refused with the reason logged and reported, and the node runs on the
//! strict default: quote-capable machines only.
//!
//! Two ways change it, both through `furcate_policy::custody`:
//!
//! - the operator places a signed change at `custody-change.json` in the
//!   config directory, and it is applied on the next load;
//! - a `set_custody` passkey order names the digest of a change staged under
//!   `custody-staged/<digest>.json` in the state directory, and is applied
//!   when the order's threshold is met.
//!
//! The members custody is elected from are this node, at its own appraised
//! class, and the enrolment records the operator reviewed under `enrolled/` in
//! the config directory, reachable when they are alive in the membership. A
//! vault opens only on a grant from that election.

use furcate_api::custody::{CustodySource, CustodyStatus, HolderStatus};
use furcate_authn::order::{Order, Target};
use furcate_authn::webauthn::Approval;
use furcate_identity::custody::{elect, Custody, CustodyGrant, CustodyRefusal, CustodySettings};
use furcate_identity::AssuranceClass;
use furcate_ledger::chain::Chain;
use furcate_policy::custody::{
    load, members, AppliedBy, AppliedCustody, CustodyChange, Loaded, OperatorKey, PasskeyOrder,
};
use furcate_vault::Vault;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;

/// Where custody's inputs live.
#[derive(Clone, Debug)]
pub struct Paths {
    pub record: PathBuf,
    pub operator_change: PathBuf,
    pub staged: PathBuf,
    pub enrolled: PathBuf,
    pub operator_key: PathBuf,
}

impl Paths {
    pub fn standard() -> Self {
        Self {
            record: furcate_paths::state("custody.json"),
            operator_change: furcate_paths::config("custody-change.json"),
            staged: furcate_paths::state("custody-staged"),
            enrolled: furcate_paths::config("enrolled"),
            operator_key: furcate_paths::config("operator.pub"),
        }
    }
}

struct State {
    loaded: Loaded,
    settings_from: &'static str,
    election: Result<Custody, CustodyRefusal>,
    /// The election material already sealed to this node opens under; the
    /// same as `election` unless the site has no custody record.
    existing: Result<Custody, CustodyRefusal>,
    /// The last operator change refused, so a bad file is recorded once rather
    /// than on every load.
    refused_operator_change: Option<String>,
    /// The last reason logged, so a standing refusal is logged once.
    logged: Option<String>,
}

pub struct KeyCustody {
    node_id: String,
    class: AssuranceClass,
    site: String,
    paths: Paths,
    state: Mutex<State>,
}

fn operator_key(path: &std::path::Path) -> Option<OperatorKey> {
    let raw = std::fs::read_to_string(path).ok()?;
    let bytes: [u8; 32] = hex::decode(raw.trim()).ok()?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .ok()
        .map(|key| OperatorKey { key })
}

impl KeyCustody {
    /// Starts on the strict default with no holders until the first
    /// [`KeyCustody::reload`].
    pub fn new(node_id: String, class: AssuranceClass, site: String, paths: Paths) -> Self {
        Self {
            node_id,
            class,
            site,
            paths,
            state: Mutex::new(State {
                loaded: Loaded { settings: CustodySettings::default(), current: None, refused: None },
                settings_from: "default",
                election: Err(CustodyRefusal("custody has not been loaded yet".into())),
                existing: Err(CustodyRefusal("custody has not been loaded yet".into())),
                refused_operator_change: None,
                logged: None,
            }),
        }
    }

    /// Load the settings, apply a waiting operator change, and elect.
    ///
    /// Anything appended to `chain` is the caller's to persist.
    pub fn reload(&self, chain: &mut Chain, alive: &BTreeSet<String>, now_s: u64, now_ms: u64) {
        let operator = operator_key(&self.paths.operator_key);
        let mut loaded = load(&self.paths.record, operator.as_ref(), &self.site, chain);
        let mut st = self.state.lock().expect("custody lock");

        if let Ok(raw) = std::fs::read(&self.paths.operator_change) {
            match serde_json::from_slice::<CustodyChange>(&raw) {
                Err(e) => {
                    let why = format!("{} is not a custody change: {e}", self.paths.operator_change.display());
                    if st.refused_operator_change.as_deref() != Some(why.as_str()) {
                        eprintln!("furcated: custody: {why}");
                        st.refused_operator_change = Some(why);
                    }
                }
                Ok(change) => {
                    let digest = change.digest();
                    let current = loaded.current.as_ref().map(|c| c.digest());
                    if current.as_deref() != Some(digest.as_str())
                        && st.refused_operator_change.as_deref() != Some(digest.as_str())
                    {
                        let outcome = match &operator {
                            None => Err(format!(
                                "no operator key at {} to check it against",
                                self.paths.operator_key.display()
                            )),
                            Some(k) => change
                                .apply(k, &self.site, now_s, loaded.current.as_ref(), chain, now_ms)
                                .map_err(|e| e.to_string())
                                .and_then(|_| {
                                    AppliedCustody { change: change.clone(), applied_by: AppliedBy::Operator }
                                        .save(&self.paths.record)
                                        .map_err(|e| format!("could not save the applied record: {e}"))
                                }),
                        };
                        match outcome {
                            Ok(()) => {
                                eprintln!("furcated: custody: applied operator change epoch {}", change.epoch);
                                loaded = load(&self.paths.record, operator.as_ref(), &self.site, chain);
                            }
                            Err(why) => {
                                eprintln!("furcated: custody: operator change {digest} refused: {why}");
                                st.refused_operator_change = Some(digest);
                            }
                        }
                    }
                }
            }
        }

        let (members, skipped) = members(&self.node_id, self.class, &self.paths.enrolled, &|id| {
            alive.contains(id)
        });
        let election = elect(&loaded.settings, &members);
        let existing = elect(&loaded.for_existing_material(), &members);
        let mut lines: Vec<String> = loaded.refused.iter().cloned().collect();
        lines.extend(skipped.into_iter().map(|s| format!("enrolment record skipped: {s}")));
        if let Err(r) = &election {
            lines.push(format!("no custody: {r}"));
        }
        let summary = (!lines.is_empty()).then(|| lines.join("; "));
        if summary != st.logged {
            if let Some(s) = &summary {
                eprintln!("furcated: custody: {s}");
            }
            st.logged = summary;
        }
        st.settings_from = loaded.settings_from(&self.paths.record);
        st.loaded = loaded;
        st.election = election;
        st.existing = existing;
    }

    /// Carry out an approved `set_custody` order.
    ///
    /// The change it names must be staged on this node; it is applied through
    /// the same checks and ledger entry as an operator-signed change, and kept
    /// with the order so it is checked again on every load.
    pub fn apply_order(
        &self,
        order: &Order,
        approval: &Approval,
        chain: &mut Chain,
        now_s: u64,
        now_ms: u64,
    ) -> Result<Value, String> {
        let Target::Custody { change_sha256 } = &order.target else {
            return Err("a set_custody order must name a custody change".into());
        };
        let staged = self.paths.staged.join(format!("{change_sha256}.json"));
        let raw = std::fs::read(&staged).map_err(|e| {
            format!("the change {change_sha256} is not staged on this node ({}): {e}", staged.display())
        })?;
        let mut change: CustodyChange = serde_json::from_slice(&raw)
            .map_err(|e| format!("{} is not a custody change: {e}", staged.display()))?;
        if change.digest() != *change_sha256 {
            return Err(format!(
                "{} holds change {}, not the {change_sha256} the order approves",
                staged.display(),
                change.digest()
            ));
        }
        let hash = order.hash().map_err(|e| e.to_string())?;
        change.signature = hex::encode(hash);
        let current = self.state.lock().expect("custody lock").loaded.current.clone();
        let by = PasskeyOrder { order, approval };
        change
            .apply(&by, &self.site, now_s, current.as_ref(), chain, now_ms)
            .map_err(|e| e.to_string())?;
        AppliedCustody {
            change: change.clone(),
            applied_by: AppliedBy::Passkeys {
                order: order.clone(),
                approvers: approval.approvers().to_vec(),
            },
        }
        .save(&self.paths.record)
        .map_err(|e| format!("applied, but the record could not be saved: {e}"))?;
        let _ = std::fs::remove_file(&staged);
        Ok(json!({
            "custody": "applied",
            "epoch": change.epoch,
            "mode": change.settings.mode.as_str(),
            "digest": change_sha256,
        }))
    }

    /// The grant this node holds, or why it holds none.
    pub fn grant(&self) -> Result<CustodyGrant, CustodyRefusal> {
        let st = self.state.lock().expect("custody lock");
        match &st.election {
            Ok(c) => c.grant(&self.node_id),
            Err(r) => Err(r.clone()),
        }
    }

    /// The grant to open material already sealed to this node, or why it
    /// may not. With no custody record that material is self-custody; see
    /// [`Loaded::for_existing_material`].
    pub fn existing_material_grant(&self) -> Result<CustodyGrant, CustodyRefusal> {
        let st = self.state.lock().expect("custody lock");
        let custody = st.existing.as_ref().map_err(|r| r.clone())?;
        let under = if st.loaded.absent() {
            "no custody record, so material already sealed here is self-custody".to_string()
        } else {
            format!("{} custody", custody.mode)
        };
        custody
            .grant(&self.node_id)
            .map_err(|r| CustodyRefusal(format!("this node does not hold custody under {under}: {r}")))
    }

    /// Open a vault with an unsealed key, only on a grant. Every vault this
    /// node opens goes through here; nothing in furcated opens one yet.
    #[allow(dead_code)]
    pub fn open_vault(&self, key: [u8; 32]) -> Result<Vault, String> {
        let grant = self
            .grant()
            .map_err(|r| format!("this node does not hold custody, so its vault stays shut: {r}"))?;
        Vault::open(key, &grant).map_err(|e| e.to_string())
    }
}

impl CustodySource for KeyCustody {
    fn status(&self) -> CustodyStatus {
        let refused = self.grant().err().map(|r| r.0);
        let existing_refused = self.existing_material_grant().err().map(|r| r.0);
        let st = self.state.lock().expect("custody lock");
        let s = &st.loaded.settings;
        let holders = match &st.election {
            Ok(c) => c
                .holders
                .iter()
                .map(|h| HolderStatus { id: h.id.clone(), class: h.class.as_str().into() })
                .collect(),
            Err(_) => Vec::new(),
        };
        CustodyStatus {
            mode: s.mode.as_str().into(),
            node: self.node_id.clone(),
            class: self.class.as_str().into(),
            holds_custody: refused.is_none(),
            holders,
            refused,
            floor: s.floor().as_str().into(),
            tpm_less: s.tpm_less,
            allow_soft: s.allow_soft,
            settings_from: st.settings_from.into(),
            existing_material: st.loaded.for_existing_material().mode.as_str().into(),
            existing_material_refused: existing_refused,
            epoch: st.loaded.current.as_ref().filter(|_| st.loaded.refused.is_none()).map(|c| c.epoch),
            settings_refused: st.loaded.refused.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use furcate_authn::order::{Action, Bounds};
    use furcate_authn::webauthn::virtual_authenticator::Authenticator;
    use furcate_authn::webauthn::{verify_assertion, Challenge, Tally, Thresholds};
    use furcate_identity::custody::CustodyMode;

    const SITE: &str = "site-a";
    const RP: &str = "site.example";

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn scratch(name: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("keycustody-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("enrolled")).unwrap();
        std::fs::write(root.join("operator.pub"), hex::encode(operator().verifying_key().as_bytes())).unwrap();
        Paths {
            record: root.join("custody.json"),
            operator_change: root.join("custody-change.json"),
            staged: root.join("custody-staged"),
            enrolled: root.join("enrolled"),
            operator_key: root.join("operator.pub"),
        }
    }

    fn change(epoch: u64, predecessor: Option<String>, settings: CustodySettings) -> CustodyChange {
        let mut c = CustodyChange {
            site: SITE.into(),
            epoch,
            not_before: 100,
            not_after: 200,
            predecessor,
            settings,
            reason: "enclave-only cluster".into(),
            signature: String::new(),
        };
        c.signature = hex::encode(operator().sign(&c.signed_bytes()).to_bytes());
        c
    }

    fn tpm_less() -> CustodySettings {
        CustodySettings { tpm_less: true, ..Default::default() }
    }

    #[test]
    fn an_enclave_node_holds_nothing_by_default_and_says_why() {
        let k = KeyCustody::new("mac".into(), AssuranceClass::SecureElement, SITE.into(), scratch("default"));
        let mut chain = Chain::new();
        k.reload(&mut chain, &BTreeSet::new(), 150, 1);
        let s = k.status();
        assert!(!s.holds_custody);
        assert_eq!(s.settings_from, "none");
        assert_eq!(s.floor, "dice");
        assert!(s.refused.unwrap().contains("custody.tpm_less"));
        let e = k.open_vault([1; 32]).unwrap_err();
        assert!(e.contains("vault stays shut"), "{e}");
    }

    /// A production node upgraded onto custody: no record, two enrolled
    /// quote-capable peers that win the strict election, and its own key
    /// already sealed to its own TPM.
    #[test]
    fn an_upgraded_node_with_no_record_keeps_its_own_sealed_material() {
        let p = scratch("upgrade");
        let mut alive = BTreeSet::new();
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
            alive.insert(id.repeat(64));
        }
        let me = "f".repeat(64);
        let k = KeyCustody::new(me.clone(), AssuranceClass::Tpm, SITE.into(), p.clone());
        k.reload(&mut Chain::new(), &alive, 150, 1);
        let s = k.status();
        assert_eq!(s.settings_from, "none");
        assert_eq!(s.existing_material, "self");
        assert!(s.existing_material_refused.is_none(), "{s:?}");
        let g = k.existing_material_grant().unwrap();
        assert_eq!((g.mode(), g.class(), g.holder()), (CustodyMode::SelfCustody, AssuranceClass::Tpm, me.as_str()));
        // New custody placement still follows the strict elected default.
        assert_eq!(s.mode, "elected");
        assert!(!s.holds_custody);
        assert!(s.refused.unwrap().contains("spread"));

        // The operator then signs self-custody for the site; it loads as the
        // settings in force and the node holds custody outright.
        furcate_policy::custody::sign_self_custody(&operator(), SITE, 150, 86_400, "upgrade")
            .unwrap()
            .save(&p.record)
            .unwrap();
        k.reload(&mut Chain::new(), &alive, 10_000, 2);
        let s = k.status();
        assert_eq!((s.mode.as_str(), s.settings_from.as_str()), ("self", "operator"));
        assert!(s.holds_custody && s.existing_material_refused.is_none(), "{s:?}");
        assert_eq!(s.existing_material, "self");
    }

    #[test]
    fn an_operator_signed_change_is_applied_and_survives_a_restart() {
        let p = scratch("operator");
        std::fs::write(&p.operator_change, serde_json::to_vec(&change(1, None, tpm_less())).unwrap()).unwrap();
        let k = KeyCustody::new("mac".into(), AssuranceClass::SecureElement, SITE.into(), p.clone());
        let mut chain = Chain::new();
        k.reload(&mut chain, &BTreeSet::new(), 150, 1);
        let s = k.status();
        assert!(s.holds_custody, "{s:?}");
        assert_eq!((s.settings_from.as_str(), s.epoch), ("operator", Some(1)));
        assert!(k.open_vault([1; 32]).is_ok());

        // A restart reads the record, well after the change's window closed.
        std::fs::remove_file(&p.operator_change).unwrap();
        let again = KeyCustody::new("mac".into(), AssuranceClass::SecureElement, SITE.into(), p);
        again.reload(&mut chain, &BTreeSet::new(), 10_000, 2);
        assert!(again.status().holds_custody);
    }

    #[test]
    fn a_forged_or_unsigned_record_falls_back_to_strict() {
        let p = scratch("forged");
        let mut c = change(1, None, tpm_less());
        c.signature = String::new();
        AppliedCustody { change: c, applied_by: AppliedBy::Operator }.save(&p.record).unwrap();
        let k = KeyCustody::new("mac".into(), AssuranceClass::SecureElement, SITE.into(), p.clone());
        k.reload(&mut Chain::new(), &BTreeSet::new(), 150, 1);
        let s = k.status();
        assert!(!s.holds_custody && !s.tpm_less);
        assert!(s.settings_refused.unwrap().contains("strict default"));

        // An operator change signed by someone else is refused and recorded once.
        std::fs::write(&p.operator_change, b"{}").unwrap();
        let mut chain = Chain::new();
        k.reload(&mut chain, &BTreeSet::new(), 150, 1);
        let mut other = change(1, None, tpm_less());
        other.signature = hex::encode(SigningKey::from_bytes(&[9; 32]).sign(&other.signed_bytes()).to_bytes());
        std::fs::remove_file(&p.record).unwrap();
        std::fs::write(&p.operator_change, serde_json::to_vec(&other).unwrap()).unwrap();
        k.reload(&mut chain, &BTreeSet::new(), 150, 1);
        k.reload(&mut chain, &BTreeSet::new(), 150, 2);
        assert_eq!(chain.len(), 1, "a refused change is recorded once");
        assert!(!k.status().holds_custody);
    }

    #[test]
    fn peers_come_from_reviewed_enrolments_and_the_strongest_is_elected() {
        let p = scratch("peers");
        let tpm: furcate_identity::Enrollment = serde_json::from_value(json!({
            "node_id": "f".repeat(64),
            "assurance": "tpm",
            "hostname": "node-a",
            "endorsed": true,
            "evidence_digest": "00",
            "pcrs": {},
        }))
        .unwrap_or_else(|e| panic!("enrolment shape: {e}"));
        let tpm_id = tpm.node_id.to_string();
        std::fs::write(p.enrolled.join("node-a.json"), serde_json::to_vec(&tpm).unwrap()).unwrap();
        let k = KeyCustody::new("tee".into(), AssuranceClass::Tee, SITE.into(), p);
        let alive: BTreeSet<String> = [tpm_id.clone()].into();
        k.reload(&mut Chain::new(), &alive, 150, 1);
        let s = k.status();
        assert_eq!(s.holders, vec![HolderStatus { id: tpm_id, class: "tpm".into() }]);
        assert!(!s.holds_custody);
    }

    #[test]
    fn a_passkey_order_applies_a_staged_change() {
        let p = scratch("passkeys");
        let mut staged = change(1, None, CustodySettings { mode: CustodyMode::SelfCustody, ..tpm_less() });
        staged.signature = String::new();
        std::fs::create_dir_all(&p.staged).unwrap();
        std::fs::write(p.staged.join(format!("{}.json", staged.digest())), serde_json::to_vec(&staged).unwrap())
            .unwrap();
        let order = Order {
            site: RP.into(),
            action: Action::SetCustody,
            target: Target::Custody { change_sha256: staged.digest() },
            bounds: Bounds { max_nodes: 1, duration_s: None },
            counter: 1,
            issued_at: 100,
            expires_at: 200,
            reason: "self custody".into(),
        };
        let mut t = Tally::new(&order, &Thresholds::default()).unwrap();
        for i in 0..2u8 {
            let mut a = Authenticator::new(i + 1, RP);
            let cred = a.credential();
            let ch = Challenge { order_hash: order.hash().unwrap(), nonce: [0; 16], expires_at: 150 };
            t.add(verify_assertion(&cred, &a.get(&ch), &ch, 120).unwrap()).unwrap();
        }
        let approval = t.approval().unwrap();

        let k = KeyCustody::new("mac".into(), AssuranceClass::SecureElement, SITE.into(), p.clone());
        let mut chain = Chain::new();
        k.reload(&mut chain, &BTreeSet::new(), 150, 1);
        assert!(!k.status().holds_custody);
        k.apply_order(&order, &approval, &mut chain, 150, 2).unwrap();
        k.reload(&mut chain, &BTreeSet::new(), 150, 3);
        let s = k.status();
        assert_eq!((s.mode.as_str(), s.settings_from.as_str()), ("self", "passkeys"));
        assert!(s.holds_custody, "{s:?}");

        // The same record, on a node whose chain never saw it applied, is refused.
        let fresh = KeyCustody::new("mac".into(), AssuranceClass::SecureElement, SITE.into(), p);
        fresh.reload(&mut Chain::new(), &BTreeSet::new(), 150, 1);
        assert!(!fresh.status().holds_custody);
        assert!(fresh.status().settings_refused.unwrap().contains("operation chain"));
    }
}
