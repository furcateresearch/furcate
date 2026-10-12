//! Keeping a node the same node.
//!
//! Backend selection picks the strongest root of trust that answers, and each
//! root derives a different node ID. Left alone, that makes identity a
//! function of whatever devices happen to be present at start: a TPM that
//! appears (or an emulated one that is mistaken for hardware), a TPM that
//! vanishes, or a class that changes, and the machine comes up as a node
//! nobody enrolled, with its history restarted under a new name.
//!
//! So the first start records which backend and node ID the node enrolled
//! with, in [`ENROLLED`] beside the node key. Every later start must arrive at
//! that node ID: through whatever selection chooses if it agrees, otherwise
//! through the enrolled backend opened by name. If neither gets there the
//! node does not start. The only way to a different identity is an operator's
//! re-enrolment, which is signed with the operator key and keeps the
//! identities it replaced.
//!
//! Nodes enrolled before this record existed are migrated from the node-key
//! directory: `node.key` is written only for a file-backed (`Soft`) identity,
//! `seal.priv` only when the key was sealed to a TPM or an enclave.

use crate::backends::{self, host::SoftIdentity, select::Attempt, NoHardwareRoot, Policy, Selection};
use crate::rot::{AssuranceClass, RootOfTrust};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File name of the enrolment record, in the node-key directory.
pub const ENROLLED: &str = "enrolled.json";

/// The backend name a hardware-continuity identity records.
pub const SOFT_BACKEND: &str = "soft";

/// Domain separation for the operator's signature over a re-enrolment.
const REENROL_CONTEXT: &[u8] = b"furcate-identity-reenrol-v1\n";

/// The identity a node enrolled with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledIdentity {
    pub node_id: String,
    pub backend: String,
    pub class: AssuranceClass,
    pub recorded_at: u64,
    /// How this record came to be: a first start, a migration, or an
    /// operator's re-enrolment and its reason.
    pub how: String,
    /// Identities this node held before, oldest first. Only a re-enrolment
    /// adds to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous: Vec<PreviousIdentity>,
    /// Hex Ed25519 signature by the operator key over [`Self::signed_bytes`].
    /// Present on every re-enrolment; a record that carries history without
    /// one is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousIdentity {
    pub node_id: String,
    pub backend: String,
    pub class: AssuranceClass,
    pub recorded_at: u64,
    pub ended_at: u64,
    pub why: String,
}

impl EnrolledIdentity {
    fn of<R>(opened: &Opened<R>, now: u64, how: String) -> Self {
        EnrolledIdentity {
            node_id: opened.node_id.clone(),
            backend: opened.backend.clone(),
            class: opened.class,
            recorded_at: now,
            how,
            previous: Vec::new(),
            operator_signature: None,
        }
    }

    /// The record an operator's re-enrolment writes: `opened` becomes the
    /// identity, and the one it replaces is kept. Unsigned until
    /// [`Self::sign`].
    pub fn reenrol<R>(prior: Option<&EnrolledIdentity>, opened: &Opened<R>, now: u64, why: &str) -> Self {
        let mut record = Self::of(opened, now, format!("re-enrolled by the operator: {why}"));
        if let Some(p) = prior {
            record.previous = p.previous.clone();
            record.previous.push(PreviousIdentity {
                node_id: p.node_id.clone(),
                backend: p.backend.clone(),
                class: p.class,
                recorded_at: p.recorded_at,
                ended_at: now,
                why: why.to_string(),
            });
        }
        record
    }

    /// What the operator signs: the record without its signature.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let unsigned = EnrolledIdentity { operator_signature: None, ..self.clone() };
        let mut out = REENROL_CONTEXT.to_vec();
        out.extend(serde_json::to_vec(&unsigned).expect("an enrolment record serialises"));
        out
    }

    pub fn sign(&mut self, operator: &SigningKey) {
        self.operator_signature = Some(hex::encode(operator.sign(&self.signed_bytes()).to_bytes()));
    }

    /// Whether this record needs the operator's signature: it replaced an
    /// identity, or claims to have been signed.
    pub fn is_reenrolment(&self) -> bool {
        !self.previous.is_empty() || self.operator_signature.is_some()
    }

    /// Check a re-enrolment's signature against the operator key, as the hex
    /// public key in `operator.pub`.
    pub fn verify(&self, operator_pub_hex: Option<&str>) -> Result<(), String> {
        if !self.is_reenrolment() {
            return Ok(());
        }
        let Some(sig_hex) = &self.operator_signature else {
            return Err("it replaces an earlier identity but carries no operator signature".to_string());
        };
        let Some(pub_hex) = operator_pub_hex else {
            return Err("it is a re-enrolment and this node has no operator key (operator.pub) to check it against".to_string());
        };
        let key: [u8; 32] = hex::decode(pub_hex.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("operator.pub is not a 32-byte hex key")?;
        let key = VerifyingKey::from_bytes(&key).map_err(|e| format!("operator.pub is not a valid key: {e}"))?;
        let sig: [u8; 64] = hex::decode(sig_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("the operator signature is not 64 hex bytes")?;
        key.verify(&self.signed_bytes(), &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| "the operator signature does not verify against operator.pub".to_string())
    }

    /// Read the record, if there is one.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|e| format!("{} is not a valid enrolment record: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    /// Write the record, replacing any earlier one in a single rename.
    /// Readable by all: it names a public identity, not a secret.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&tmp, path)
    }
}

/// What the node-key directory shows about how the node ran before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    /// Neither form: a node starting for the first time.
    Fresh,
    /// `node.key`: a file-backed key, written only for a `Soft` identity.
    FileKey,
    /// `seal.priv`: a key sealed to a TPM or an enclave.
    Sealed,
    /// Both forms; the files alone do not say which is current.
    Both,
}

pub fn key_state(dir: &Path) -> KeyState {
    match (dir.join("node.key").exists(), dir.join("seal.priv").exists()) {
        (false, false) => KeyState::Fresh,
        (true, false) => KeyState::FileKey,
        (false, true) => KeyState::Sealed,
        (true, true) => KeyState::Both,
    }
}

/// A root of trust that opened, and the node it makes.
pub struct Opened<R> {
    pub rot: R,
    pub backend: String,
    pub class: AssuranceClass,
    pub node_id: String,
    pub reason: String,
}

impl<R> Opened<R> {
    fn describe(&self) -> String {
        format!("{} via {} ({})", self.node_id, self.backend, self.class)
    }
}

/// The outcome of a start that may proceed.
pub struct Resolved<R> {
    pub opened: Opened<R>,
    /// A record to write: the first start or a migration.
    pub record: Option<EnrolledIdentity>,
    /// Something the operator should see, when the node is not on the
    /// backend selection would have chosen.
    pub note: Option<String>,
}

/// The operator's way to change identity on purpose.
pub fn reenrol_hint() -> String {
    "If the change is intended, re-enrol deliberately with the operator key:\n\
     \n    sudo furcatectl identity re-enrol OPERATOR_KEY \"why this node changes identity\"\n\
     \nwhich records the new identity, the one it replaces and the reason, signed."
        .to_string()
}

/// Decide which identity this start uses.
///
/// `current` is what backend selection produced (or why nothing opened);
/// `open` opens one named backend. Returns `Err` with the reason when the
/// node must not start.
pub fn resolve<R>(
    enrolled: Option<&EnrolledIdentity>,
    keys: KeyState,
    current: Result<Opened<R>, String>,
    open: &mut dyn FnMut(&str) -> Result<Opened<R>, String>,
    now: u64,
) -> Result<Resolved<R>, String> {
    match enrolled {
        Some(e) => keep_enrolled(e, current, open),
        None => migrate(keys, current, open, now),
    }
}

fn keep_enrolled<R>(
    e: &EnrolledIdentity,
    current: Result<Opened<R>, String>,
    open: &mut dyn FnMut(&str) -> Result<Opened<R>, String>,
) -> Result<Resolved<R>, String> {
    let would_be = match current {
        Ok(c) if c.node_id == e.node_id => return Ok(Resolved { opened: c, record: None, note: None }),
        Ok(c) => format!("backend selection now produces {}", c.describe()),
        Err(why) => format!("backend selection now finds nothing usable: {why}"),
    };
    let refuse = |problem: String| {
        Err(format!(
            "refusing to start as a different node. This node enrolled as {} on {} ({}, recorded at {}); \
             {would_be}; {problem}. A node is always the same node, so its identity is not changed by \
             a device appearing or disappearing.\n{}",
            e.node_id,
            e.backend,
            e.how,
            e.recorded_at,
            reenrol_hint()
        ))
    };
    match open(&e.backend) {
        Ok(o) if o.node_id == e.node_id => {
            let note = format!(
                "kept the enrolled backend {} as {}; {would_be}, which would be a different node, so it is not used",
                e.backend, e.node_id
            );
            Ok(Resolved { opened: o, record: None, note: Some(note) })
        }
        Ok(o) => refuse(format!("the enrolled backend {} now answers as {}", e.backend, o.node_id)),
        Err(why) => refuse(format!("the enrolled backend {} is not available: {why}", e.backend)),
    }
}

fn migrate<R>(
    keys: KeyState,
    current: Result<Opened<R>, String>,
    open: &mut dyn FnMut(&str) -> Result<Opened<R>, String>,
    now: u64,
) -> Result<Resolved<R>, String> {
    let recorded = |o: Opened<R>, how: String| -> Result<Resolved<R>, String> {
        let record = EnrolledIdentity::of(&o, now, how);
        Ok(Resolved { opened: o, record: Some(record), note: None })
    };
    let is_soft = |c: &Result<Opened<R>, String>| matches!(c, Ok(o) if o.backend == SOFT_BACKEND);
    match keys {
        KeyState::Fresh => recorded(current?, "first start".to_string()),
        KeyState::Both => recorded(
            current?,
            "migrated: node-key holds both a file key and a sealed key; enrolled on the backend in use".to_string(),
        ),
        KeyState::FileKey if is_soft(&current) => {
            recorded(current?, "migrated: node-key/node.key shows a file-backed identity".to_string())
        }
        KeyState::FileKey => {
            // The node ran on hardware continuity; something stronger, or
            // nothing, answers now. The enrolled identity is the soft one.
            let instead = match &current {
                Ok(c) => format!("backend selection now produces {}", c.describe()),
                Err(why) => format!("backend selection finds nothing usable: {why}"),
            };
            match open(SOFT_BACKEND) {
                Ok(o) => {
                    let mut r = recorded(o, "migrated: node-key/node.key shows a file-backed identity".to_string())?;
                    r.note = Some(format!(
                        "kept the hardware-continuity identity this node ran on; {instead}, which would be a different node"
                    ));
                    Ok(r)
                }
                Err(why) => Err(format!(
                    "refusing to start as a different node. node-key/node.key shows this node ran on a \
                     hardware-continuity identity, which does not open: {why}; {instead}.\n{}",
                    reenrol_hint()
                )),
            }
        }
        KeyState::Sealed if current.is_ok() && !is_soft(&current) => recorded(
            current?,
            "migrated: node-key/seal.priv shows a key sealed to this backend".to_string(),
        ),
        KeyState::Sealed => {
            let instead = match &current {
                Ok(c) => format!("backend selection now produces {}", c.describe()),
                Err(why) => format!("backend selection finds nothing usable: {why}"),
            };
            Err(format!(
                "refusing to start as a different node. node-key/seal.priv shows this node's key was sealed \
                 to a TPM or enclave that no longer opens; {instead}.\n{}",
                reenrol_hint()
            ))
        }
    }
}

/// The shared-pointer root of trust the daemon and the CLI hold.
pub type Rot = Arc<dyn RootOfTrust + Send + Sync>;

/// A selection, with the node ID it makes.
pub fn opened_from(s: Selection) -> Result<Opened<Rot>, String> {
    let node_id = s.rot.node_id().map_err(|e| format!("{} opened but gave no node ID: {e}", s.backend))?.to_string();
    Ok(Opened { rot: s.rot, backend: s.backend.to_string(), class: s.class, node_id, reason: s.reason })
}

/// The hardware-continuity identity recorded in `soft-identity.json`, if it
/// still matches this machine.
pub fn open_soft(path: &Path) -> Result<Opened<Rot>, String> {
    if !path.exists() {
        return Err(format!("no hardware-continuity record at {}", path.display()));
    }
    let soft = SoftIdentity::load(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let drift = soft.continuity();
    if drift.needs_operator() {
        return Err(format!(
            "this machine no longer matches the identity recorded in {}: {drift:?}. A fingerprint cannot \
             tell a replaced board from something answering in its place, so this is for a person to \
             resolve. If the change was intended, re-run `furcatectl identity soft-enroll`",
            path.display()
        ));
    }
    let rot: Rot = Arc::new(soft.rot());
    let node_id = rot.node_id().map_err(|e| format!("the soft identity gave no node ID: {e}"))?.to_string();
    Ok(Opened {
        class: rot.assurance(),
        rot,
        backend: SOFT_BACKEND.to_string(),
        node_id,
        reason: format!("hardware continuity, recorded at {}: {}", soft.recorded_at, soft.reason),
    })
}

/// What this machine would be with no record to keep it: the strongest
/// hardware root, else the recorded soft identity. The attempts are the
/// backends that were passed over and why.
pub fn current(policy: &Policy, soft_path: &Path) -> (Result<Opened<Rot>, String>, Vec<Attempt>) {
    let (selected, attempts) = match backends::select(policy) {
        Ok(mut s) => {
            let attempts = std::mem::take(&mut s.attempts);
            let backend = s.backend;
            (Some(opened_from(s).map_err(|outcome| Attempt { backend, outcome })), attempts)
        }
        Err(none) => (None, none.attempts),
    };
    let soft = || open_soft(soft_path);
    settle(selected, attempts, soft_path.exists().then_some(&soft as &dyn Fn() -> Result<Opened<Rot>, String>))
}

/// What selection opened, else the recorded soft identity. A backend that
/// opened but gave no node ID is passed over like one that did not open, so
/// a device that does not answer is never fatal on its own.
fn settle<R>(
    selected: Option<Result<Opened<R>, Attempt>>,
    mut attempts: Vec<Attempt>,
    soft: Option<&dyn Fn() -> Result<Opened<R>, String>>,
) -> (Result<Opened<R>, String>, Vec<Attempt>) {
    match selected {
        Some(Ok(o)) => return (Ok(o), attempts),
        Some(Err(a)) => attempts.push(a),
        None => {}
    }
    let opened = match soft {
        Some(open) => open(),
        None => {
            let none = NoHardwareRoot { attempts };
            let why = none.to_string();
            attempts = none.attempts;
            Err(why)
        }
    };
    (opened, attempts)
}

/// Open one backend by its recorded name.
pub fn open_named(policy: &Policy, soft_path: &Path, name: &str) -> Result<Opened<Rot>, String> {
    if name == SOFT_BACKEND {
        return open_soft(soft_path);
    }
    opened_from(backends::open_backend(policy, name)?)
}

/// Where a node keeps what decides its identity.
#[derive(Clone, Debug)]
pub struct NodePaths {
    /// The configuration directory: selection policy, `operator.pub`.
    pub config_dir: PathBuf,
    /// The hardware-continuity record, `soft-identity.json`.
    pub soft_identity: PathBuf,
    /// The node-key directory, which holds [`ENROLLED`].
    pub key_dir: PathBuf,
}

impl NodePaths {
    pub fn new(config_dir: &Path, key_dir: &Path) -> Self {
        NodePaths {
            config_dir: config_dir.to_path_buf(),
            soft_identity: config_dir.join("soft-identity.json"),
            key_dir: key_dir.to_path_buf(),
        }
    }

    pub fn record(&self) -> PathBuf {
        self.key_dir.join(ENROLLED)
    }

    pub fn policy(&self) -> Policy {
        Policy::in_config_dir(&self.config_dir)
    }
}

/// This node's root of trust, chosen the one way the daemon and the CLI
/// share: the strongest backend selection opens (TPM, then TEE, then a
/// device key, else the recorded hardware-continuity identity), held to the
/// identity recorded in `node-key/enrolled.json` when there is one.
///
/// The attempts are the backends passed over and why, returned whatever the
/// outcome so the caller can show them. A record to write, on a first start
/// or a migration, is in the result; writing it is the daemon's business.
pub fn open_node(paths: &NodePaths, now: u64) -> (Result<Resolved<Rot>, String>, Vec<Attempt>) {
    let policy = paths.policy();
    let (current, attempts) = current(&policy, &paths.soft_identity);
    let mut open = |name: &str| open_named(&policy, &paths.soft_identity, name);
    (open_node_with(paths, current, &mut open, now), attempts)
}

/// [`open_node`] with selection and opening by name supplied by the caller.
pub fn open_node_with<R>(
    paths: &NodePaths,
    current: Result<Opened<R>, String>,
    open: &mut dyn FnMut(&str) -> Result<Opened<R>, String>,
    now: u64,
) -> Result<Resolved<R>, String> {
    let record_path = paths.record();
    // A node is always the same node. Selection says what this machine would
    // be today; the record says what it enrolled as, and that wins.
    let enrolled = EnrolledIdentity::load(&record_path)?;
    if let Some(e) = &enrolled {
        let operator = std::fs::read_to_string(paths.config_dir.join("operator.pub")).ok();
        e.verify(operator.as_deref())
            .map_err(|why| format!("refusing the enrolment record {}: {why}", record_path.display()))?;
    }
    let keys = key_state(&paths.key_dir);
    if enrolled.is_none() && keys == KeyState::Fresh && !paths.soft_identity.exists() {
        if let Err(none) = &current {
            return Err(format!(
                "{none}. Check /dev/tpmrm0 and the `tss` group.\n\
                 If this machine has no TPM it can be admitted on hardware continuity \
                 instead, with:\n\
                 \n    sudo furcatectl identity soft-enroll \"why this machine has no TPM\"\n\
                 \nwhich reads the board and chassis serials as root and records the \
                 decision in {}. A node admitted that way is Soft: no sealed custody, \
                 no signed quotes, no attested placement, and it may not hold the \
                 controlling role for a cluster.",
                paths.soft_identity.display()
            ));
        }
    }
    resolve(enrolled.as_ref(), keys, current, open, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(backend: &str, node: &str, class: AssuranceClass) -> Opened<()> {
        Opened { rot: (), backend: backend.into(), class, node_id: node.into(), reason: String::new() }
    }

    fn enrolled(backend: &str, node: &str, class: AssuranceClass) -> EnrolledIdentity {
        EnrolledIdentity::of(&o(backend, node, class), 100, "first start".into())
    }

    fn never(_: &str) -> Result<Opened<()>, String> {
        panic!("the enrolled backend should not have been opened")
    }

    #[test]
    fn a_tpm_that_does_not_answer_is_passed_over_for_the_soft_identity() {
        let silent = Attempt { backend: "tpm", outcome: "tpm opened but gave no node ID: permission denied".into() };
        let soft = || Ok(o("soft", "5cnau", AssuranceClass::Soft));
        let (current, attempts) = settle(Some(Err(silent)), Vec::new(), Some(&soft));
        assert_eq!(current.as_ref().unwrap().node_id, "5cnau");
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].outcome.contains("gave no node ID"));

        // The node that ran on a file key and once had a key sealed to the
        // emulated TPM keeps its soft identity, and records it.
        let r = resolve(None, KeyState::Both, current, &mut never, 300).unwrap();
        assert_eq!(r.opened.node_id, "5cnau");
        assert_eq!(r.record.unwrap().backend, "soft");

        // Pinned: the enrolled soft identity is used.
        let e = enrolled("soft", "5cnau", AssuranceClass::Soft);
        let (current, _) = settle(None, Vec::new(), Some(&soft));
        let r = resolve(Some(&e), KeyState::Both, current, &mut never, 400).unwrap();
        assert_eq!(r.opened.node_id, "5cnau");
        assert!(r.record.is_none() && r.note.is_none());
    }

    #[test]
    fn a_tpm_that_does_not_answer_with_no_soft_record_names_it() {
        let silent = Attempt { backend: "tpm", outcome: "/dev/tpmrm0 is not a usable TPM: it is not a character device".into() };
        let (current, attempts) = settle::<()>(Some(Err(silent)), Vec::new(), None);
        let why = current.err().unwrap();
        assert!(why.starts_with("no hardware root of trust opened") && why.contains("not a character device"), "{why}");
        assert_eq!(attempts.len(), 1);
    }

    #[test]
    fn an_enrolled_tpm_node_whose_tpm_is_unusable_still_refuses() {
        let e = enrolled("tpm", "N1", AssuranceClass::Tpm);
        let soft = || Ok(o("soft", "S1", AssuranceClass::Soft));
        let silent = Attempt { backend: "tpm", outcome: "/dev/tpmrm0 is not a usable TPM: it is not a character device".into() };
        let (current, _) = settle(Some(Err(silent)), Vec::new(), Some(&soft));
        let mut open = |name: &str| -> Result<Opened<()>, String> {
            assert_eq!(name, "tpm");
            Err("tpm is not available: /dev/tpmrm0 is not a usable TPM: it is not a character device".into())
        };
        let err = resolve(Some(&e), KeyState::Sealed, current, &mut open, 200).err().unwrap();
        assert!(err.starts_with("refusing to start as a different node"), "{err}");
        assert!(err.contains("not a usable TPM") && err.contains("furcatectl identity re-enrol"), "{err}");
    }

    #[test]
    fn same_node_id_proceeds_without_a_new_record() {
        let e = enrolled("tpm", "N1", AssuranceClass::Tpm);
        let r = resolve(Some(&e), KeyState::Sealed, Ok(o("tpm", "N1", AssuranceClass::Tpm)), &mut never, 200).unwrap();
        assert_eq!(r.opened.node_id, "N1");
        assert!(r.record.is_none() && r.note.is_none());
    }

    #[test]
    fn a_new_device_does_not_change_the_node() {
        // The incident: a soft node, then an emulated TPM appears and wins
        // selection. The enrolled soft backend still opens, so it is kept.
        let e = enrolled("soft", "5cnau", AssuranceClass::Soft);
        let mut open = |name: &str| {
            assert_eq!(name, "soft");
            Ok(o("soft", "5cnau", AssuranceClass::Soft))
        };
        let r = resolve(Some(&e), KeyState::Both, Ok(o("tpm", "w2zrw", AssuranceClass::Tpm)), &mut open, 200).unwrap();
        assert_eq!(r.opened.node_id, "5cnau");
        assert!(r.record.is_none());
        let note = r.note.unwrap();
        assert!(note.contains("w2zrw") && note.contains("different node"), "{note}");
    }

    #[test]
    fn a_changed_node_id_is_refused_when_the_enrolled_backend_is_gone() {
        let e = enrolled("tpm", "N1", AssuranceClass::Tpm);
        let mut open = |_: &str| -> Result<Opened<()>, String> { Err("no TPM device at /dev/tpmrm0".to_string()) };
        let err = resolve(Some(&e), KeyState::Sealed, Ok(o("soft", "N2", AssuranceClass::Soft)), &mut open, 200)
            .err()
            .unwrap();
        assert!(err.starts_with("refusing to start as a different node"), "{err}");
        assert!(err.contains("N1") && err.contains("N2") && err.contains("no TPM device"), "{err}");
        assert!(err.contains("furcatectl identity re-enrol"), "{err}");
    }

    #[test]
    fn the_enrolled_backend_answering_as_another_node_is_refused() {
        let e = enrolled("tpm", "N1", AssuranceClass::Tpm);
        let mut open = |_: &str| Ok(o("tpm", "N3", AssuranceClass::Tpm));
        let err = resolve(Some(&e), KeyState::Sealed, Ok(o("tpm", "N3", AssuranceClass::Tpm)), &mut open, 200)
            .err()
            .unwrap();
        assert!(err.contains("now answers as N3"), "{err}");
    }

    #[test]
    fn nothing_opening_is_refused_with_the_reason() {
        let e = enrolled("soft", "N1", AssuranceClass::Soft);
        let mut open = |_: &str| -> Result<Opened<()>, String> { Err("board serial changed".to_string()) };
        let err = resolve(Some(&e), KeyState::FileKey, Err("no hardware root".into()), &mut open, 200).err().unwrap();
        assert!(err.contains("no hardware root") && err.contains("board serial changed"), "{err}");
    }

    #[test]
    fn first_start_records_what_opened() {
        let r = resolve(None, KeyState::Fresh, Ok(o("tpm", "N1", AssuranceClass::Tpm)), &mut never, 300).unwrap();
        let rec = r.record.unwrap();
        assert_eq!((rec.node_id.as_str(), rec.backend.as_str(), rec.recorded_at), ("N1", "tpm", 300));
        assert_eq!(rec.how, "first start");
    }

    #[test]
    fn migration_keeps_a_soft_node_soft_when_a_tpm_appears() {
        // node.key only: the node ran on hardware continuity before this
        // record existed. A TPM now wins selection; the soft identity is kept.
        let mut open = |name: &str| {
            assert_eq!(name, SOFT_BACKEND);
            Ok(o("soft", "S1", AssuranceClass::Soft))
        };
        let r = resolve(None, KeyState::FileKey, Ok(o("tpm", "T1", AssuranceClass::Tpm)), &mut open, 300).unwrap();
        assert_eq!(r.opened.node_id, "S1");
        let rec = r.record.unwrap();
        assert_eq!((rec.backend.as_str(), rec.node_id.as_str()), ("soft", "S1"));
        assert!(rec.how.starts_with("migrated"), "{}", rec.how);
        assert!(r.note.unwrap().contains("T1"));
    }

    #[test]
    fn migration_of_a_soft_node_on_soft_records_it() {
        let r = resolve(None, KeyState::FileKey, Ok(o("soft", "S1", AssuranceClass::Soft)), &mut never, 300).unwrap();
        assert_eq!(r.record.unwrap().node_id, "S1");
        assert!(r.note.is_none());
    }

    #[test]
    fn migration_of_a_sealed_node_records_its_tpm() {
        let r = resolve(None, KeyState::Sealed, Ok(o("tpm", "T1", AssuranceClass::Tpm)), &mut never, 300).unwrap();
        assert_eq!(r.record.unwrap().backend, "tpm");
    }

    #[test]
    fn migration_refuses_a_sealed_node_whose_tpm_is_gone() {
        let err = resolve(None, KeyState::Sealed, Ok(o("soft", "S1", AssuranceClass::Soft)), &mut never, 300)
            .err()
            .unwrap();
        assert!(err.contains("seal.priv") && err.contains("S1"), "{err}");
    }

    #[test]
    fn migration_refuses_a_soft_node_whose_soft_identity_drifted() {
        let mut open = |_: &str| -> Result<Opened<()>, String> { Err("board serial changed".to_string()) };
        let err = resolve(None, KeyState::FileKey, Ok(o("tpm", "T1", AssuranceClass::Tpm)), &mut open, 300)
            .err()
            .unwrap();
        assert!(err.contains("board serial changed") && err.contains("T1"), "{err}");
    }

    #[test]
    fn key_state_reads_the_node_key_directory() {
        let dir = std::env::temp_dir().join(format!("furcate-keystate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(key_state(&dir), KeyState::Fresh);
        std::fs::write(dir.join("node.key"), "x").unwrap();
        assert_eq!(key_state(&dir), KeyState::FileKey);
        std::fs::write(dir.join("seal.priv"), "x").unwrap();
        assert_eq!(key_state(&dir), KeyState::Both);
        std::fs::remove_file(dir.join("node.key")).unwrap();
        assert_eq!(key_state(&dir), KeyState::Sealed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn operator() -> SigningKey {
        // A fixed test key; never a real operator's.
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn reenrolment_is_signed_and_keeps_history() {
        let old = enrolled("soft", "S1", AssuranceClass::Soft);
        let mut rec = EnrolledIdentity::reenrol(Some(&old), &o("tpm", "T1", AssuranceClass::Tpm), 500, "TPM fitted");
        assert_eq!(rec.previous.len(), 1);
        assert_eq!((rec.previous[0].node_id.as_str(), rec.previous[0].ended_at), ("S1", 500));
        let pub_hex = hex::encode(operator().verifying_key().to_bytes());
        assert!(rec.verify(Some(&pub_hex)).is_err(), "an unsigned re-enrolment must not verify");
        rec.sign(&operator());
        rec.verify(Some(&pub_hex)).unwrap();

        // Round-trips through the file and still verifies.
        let dir = std::env::temp_dir().join(format!("furcate-reenrol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ENROLLED);
        rec.write(&path).unwrap();
        let back = EnrolledIdentity::load(&path).unwrap().unwrap();
        assert_eq!(back, rec);
        back.verify(Some(&pub_hex)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        // And the node now starts as the new identity.
        let r = resolve(Some(&back), KeyState::Both, Ok(o("tpm", "T1", AssuranceClass::Tpm)), &mut never, 600).unwrap();
        assert_eq!(r.opened.node_id, "T1");
    }

    #[test]
    fn a_tampered_or_foreign_reenrolment_is_refused() {
        let mut rec = EnrolledIdentity::reenrol(None, &o("tpm", "T1", AssuranceClass::Tpm), 500, "why");
        rec.sign(&operator());
        let pub_hex = hex::encode(operator().verifying_key().to_bytes());
        let mut tampered = rec.clone();
        tampered.node_id = "T2".into();
        assert!(tampered.verify(Some(&pub_hex)).is_err());
        let other = hex::encode(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
        assert!(rec.verify(Some(&other)).is_err());
        assert!(rec.verify(None).is_err());
        // A self-recorded first start needs no signature.
        enrolled("tpm", "T1", AssuranceClass::Tpm).verify(None).unwrap();
    }

    #[test]
    fn a_missing_record_is_none_and_a_broken_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("furcate-enrolled-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(EnrolledIdentity::load(&dir.join(ENROLLED)).unwrap(), None);
        std::fs::write(dir.join(ENROLLED), "{").unwrap();
        assert!(EnrolledIdentity::load(&dir.join(ENROLLED)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node-key and configuration directory of its own, removed on drop.
    struct Node(PathBuf);
    impl Node {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("furcate-open-node-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("etc")).unwrap();
            std::fs::create_dir_all(dir.join("node-key")).unwrap();
            Node(dir)
        }
        fn paths(&self) -> NodePaths {
            NodePaths::new(&self.0.join("etc"), &self.0.join("node-key"))
        }
    }
    impl Drop for Node {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Backends as a machine presents them: each name opens or says why not.
    fn fixture<'a>(
        backends: &'a [(&'a str, &'a str, AssuranceClass)],
    ) -> impl FnMut(&str) -> Result<Opened<()>, String> + 'a {
        move |name: &str| {
            backends
                .iter()
                .find(|(b, _, _)| *b == name)
                .map(|(b, n, c)| o(b, n, *c))
                .ok_or_else(|| format!("{name} is not available: no such device here"))
        }
    }

    #[test]
    fn a_device_class_node_opens_its_firmware_key_not_a_tpm() {
        // A Raspberry Pi: no TPM, a firmware-held key, already enrolled on it.
        let node = Node::new("device");
        let p = node.paths();
        enrolled("rpi-fw-crypto", "c46i5", AssuranceClass::Device).write(&p.record()).unwrap();
        let pi = [("rpi-fw-crypto", "c46i5", AssuranceClass::Device)];
        let mut open = fixture(&pi);
        let current = open("rpi-fw-crypto");
        let r = open_node_with(&p, current, &mut open, 500).unwrap();
        assert_eq!((r.opened.backend.as_str(), r.opened.node_id.as_str()), ("rpi-fw-crypto", "c46i5"));
        assert_eq!(r.opened.class, AssuranceClass::Device);
        assert!(!r.opened.class.can_quote());
        assert!(r.record.is_none() && r.note.is_none());
    }

    #[test]
    fn a_first_open_offers_a_record_and_writes_nothing() {
        let node = Node::new("first");
        let p = node.paths();
        let pi = [("rpi-fw-crypto", "c46i5", AssuranceClass::Device)];
        let mut open = fixture(&pi);
        let current = open("rpi-fw-crypto");
        let r = open_node_with(&p, current, &mut open, 500).unwrap();
        assert_eq!(r.record.unwrap().backend, "rpi-fw-crypto");
        assert!(!p.record().exists(), "opening never writes the record; the daemon does");
    }

    #[test]
    fn the_enrolled_identity_wins_over_a_stronger_backend_that_appears() {
        let node = Node::new("pinned");
        let p = node.paths();
        enrolled("rpi-fw-crypto", "c46i5", AssuranceClass::Device).write(&p.record()).unwrap();
        let machine = [
            ("tpm", "t9x", AssuranceClass::Tpm),
            ("rpi-fw-crypto", "c46i5", AssuranceClass::Device),
        ];
        let mut open = fixture(&machine);
        let current = open("tpm");
        let r = open_node_with(&p, current, &mut open, 500).unwrap();
        assert_eq!(r.opened.node_id, "c46i5");
        assert!(r.note.unwrap().contains("t9x"));
    }

    #[test]
    fn nothing_opening_on_a_fresh_node_points_at_soft_enrolment() {
        let node = Node::new("fresh");
        let p = node.paths();
        let mut open = fixture(&[]);
        let err = open_node_with(&p, Err("no hardware root of trust opened".into()), &mut open, 500)
            .err()
            .unwrap();
        assert!(err.contains("furcatectl identity soft-enroll") && err.contains("soft-identity.json"), "{err}");
    }

    #[test]
    fn an_unsigned_re_enrolment_record_is_refused() {
        let node = Node::new("unsigned");
        let p = node.paths();
        let prior = enrolled("soft", "5cnau", AssuranceClass::Soft);
        let record = EnrolledIdentity::reenrol(Some(&prior), &o("rpi-fw-crypto", "c46i5", AssuranceClass::Device), 600, "board");
        record.write(&p.record()).unwrap();
        let pi = [("rpi-fw-crypto", "c46i5", AssuranceClass::Device)];
        let mut open = fixture(&pi);
        let current = open("rpi-fw-crypto");
        let err = open_node_with(&p, current, &mut open, 700).err().unwrap();
        assert!(err.starts_with("refusing the enrolment record") && err.contains("no operator signature"), "{err}");
    }
}
