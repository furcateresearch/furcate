//! Which nodes are allowed to talk, and with which keys.
//!
//! The roster is the join between attestation and transport. A node earns a
//! place by being appraised; it keeps it until its attestation result expires.
//! Nothing is revoked — entries lapse, which means a compromised node stops
//! being accepted without anyone having to reach it.

use furcate_identity::SuiteKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// One admitted node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub node_id: String,
    /// Public half of the key the node signs with, written with its suite:
    /// `ed25519:<hex>` or `p256:<hex>`. An entry stored before keys carried
    /// their suite holds a bare 64-hex string, which is an Ed25519 key.
    pub public_key: String,
    /// When this admission lapses. Short-lived by design.
    pub valid_until: u64,
    /// Whether the appraisal behind it covered the OS as well as the platform.
    pub os_measured: bool,
}

impl Entry {
    /// The enrolled key with its suite. The suite is read from the key and from
    /// nothing else.
    pub fn key(&self) -> Result<SuiteKey, String> {
        SuiteKey::parse_stored(&self.public_key)
    }
}

/// The key an admission request names.
///
/// A key written with its suite (`ed25519:<hex>`, `p256:<hex>`) must come with
/// a `suite` member that says the same; the key decides, and a missing or
/// different member is refused. A bare 64-hex key is the form that existed
/// before suites, is an Ed25519 key, and may omit the member (if it gives one
/// it must be `ed25519`). Nothing else is read.
pub fn admission_key(public_key: &str, declared_suite: Option<&str>) -> Result<SuiteKey, String> {
    let key = SuiteKey::parse_stored(public_key)?;
    let bare = !public_key.contains(':');
    if bare && declared_suite.is_none() {
        return Ok(key);
    }
    key.check_declared(declared_suite)?;
    Ok(key)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RosterError {
    NotAdmitted(String),
    Lapsed { node: String, valid_until: u64, now: u64 },
    MalformedKey(String),
}

impl fmt::Display for RosterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RosterError::NotAdmitted(n) => write!(f, "`{n}` has not been admitted to this site"),
            RosterError::Lapsed { node, valid_until, now } => write!(
                f,
                "`{node}` lapsed at {valid_until}; it is now {now}. Re-attestation readmits it"
            ),
            RosterError::MalformedKey(n) => write!(f, "`{n}` has a malformed public key"),
        }
    }
}

impl std::error::Error for RosterError {}

/// Admitted nodes and the nonces already spent.
#[derive(Default)]
pub struct Roster {
    pub(crate) entries: BTreeMap<String, Entry>,
    /// Nonces accepted, with the time they expire, so the set can be swept.
    seen: BTreeMap<String, u64>,
    dropped: Vec<String>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a node, or refresh an existing admission.
    pub fn admit(&mut self, entry: Entry) -> &mut Self {
        self.entries.insert(entry.node_id.clone(), entry);
        self
    }

    /// Admit a node under a checked key. The key is stored in its one spelling.
    pub fn admit_key(&mut self, node_id: &str, key: &SuiteKey, valid_until: u64, os_measured: bool) -> &mut Self {
        self.admit(Entry { node_id: node_id.to_string(), public_key: key.id(), valid_until, os_measured })
    }

    /// Entries read from a file whose key could not be read, by node id. They
    /// are not admitted: an entry whose key cannot be parsed could never have
    /// authenticated anything.
    pub fn dropped(&self) -> &[String] {
        &self.dropped
    }

    /// Withdraw an admission now, rather than waiting for it to lapse.
    ///
    /// Returns the entry that was removed, or None if that node was not
    /// admitted. A machine that has been decommissioned should stop being a
    /// machine this site believes on the day it is decommissioned, not
    /// whenever its term happens to run out — an admission granted for a year
    /// is a year of a key that still signs for a fleet it is no longer part of.
    ///
    /// Deliberately distinct from lapsing. An entry that expires was trusted
    /// until it was not; one withdrawn was trusted until somebody decided
    /// otherwise, and the difference is the thing an operator is asserting.
    pub fn withdraw(&mut self, node_id: &str) -> Option<Entry> {
        self.entries.remove(node_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Nodes still admitted at a given time.
    pub fn current(&self, now: u64) -> Vec<&Entry> {
        self.entries.values().filter(|e| e.valid_until > now).collect()
    }

    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.seen.len();
        self.seen.retain(|_, expires| *expires > now);
        before - self.seen.len()
    }

    pub fn outstanding_nonces(&self) -> usize {
        self.seen.len()
    }

    /// Nodes whose appraisal did not cover the OS.
    ///
    /// Surfaced because on this site that is currently every node, and a
    /// roster that hides it would imply a guarantee attestation is not making.
    pub fn platform_only(&self, now: u64) -> BTreeSet<String> {
        self.current(now)
            .into_iter()
            .filter(|e| !e.os_measured)
            .map(|e| e.node_id.clone())
            .collect()
    }
}

/// Whether a string can be one label of an overlay name, returned as-is.
///
/// Lower-case letters, digits and inner hyphens, at most 63 bytes: the
/// hostname rule (RFC 1123), which is narrower than what DNS carries and is
/// what every resolver and SSH client will accept without quoting. A name
/// outside it is refused rather than rewritten, because a rewritten name is
/// one nobody chose and two different machines can be rewritten into it.
pub fn dns_label(s: &str) -> Option<&str> {
    let ok = !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok.then_some(s)
}

/// The label a node resolves under no matter what it calls itself.
///
/// A node id is `furcate:node:` and base32 of a hash of the endorsement key —
/// 52 lower-case characters, already a valid label. It is the name an anchor's
/// signature covers, so it is the one name on the overlay that a member
/// cannot choose and nobody else can claim.
pub fn id_label(node_id: &str) -> Option<&str> {
    dns_label(node_id.strip_prefix("furcate:node:").unwrap_or(node_id))
}

/// Persist the roster.
///
/// Without this a controller restart empties the roster, and an empty roster
/// accepts unsigned reports again — the authentication hole reopens on every
/// reboot. Nonces are deliberately *not* persisted: they expire in seconds, so
/// carrying them across a restart protects nothing and only grows the file.
pub fn save(roster: &Roster, path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let entries: Vec<&Entry> = roster.entries.values().collect();
    let encoded = serde_json::to_vec_pretty(&entries)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &encoded)?;
    std::fs::rename(&tmp, path)
}

/// Load a roster, dropping admissions that have already lapsed.
///
/// Expired entries are not carried across a restart: an admission that lapsed
/// while the controller was down should not be honoured because it came back.
pub fn load(path: &std::path::Path, now: u64) -> std::io::Result<Roster> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Roster::new()),
        Err(e) => return Err(e),
    };
    let entries: Vec<Entry> = serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut r = Roster::new();
    for e in entries.into_iter().filter(|e| e.valid_until > now) {
        if e.key().is_err() {
            r.dropped.push(e.node_id);
            continue;
        }
        r.admit(e);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_is_refused_rather_than_rewritten() {
        assert_eq!(dns_label("node-a"), Some("node-a"));
        assert_eq!(dns_label("Node-a"), None, "upper case is not folded");
        assert_eq!(dns_label("-a"), None);
        assert_eq!(dns_label("a_b"), None);
        assert_eq!(dns_label(""), None);
        assert_eq!(dns_label(&"a".repeat(64)), None);
        let id = "furcate:node:mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiyteojrgm4tk";
        assert_eq!(id_label(id).map(str::len), Some(53));
        assert_eq!(id_label("furcate:node:a.b"), None);
    }

    #[test]
    fn a_withdrawn_node_stops_being_admitted_immediately() {
        let mut r = Roster::new();
        r.admit(Entry {
            node_id: "furcate:node:a".into(),
            public_key: "aa".into(),
            valid_until: 10_000,
            os_measured: false,
        });
        assert_eq!(r.current(1).len(), 1);

        // Withdrawing returns what was removed, so a caller can report which
        // admission it actually ended rather than assuming.
        let gone = r.withdraw("furcate:node:a").expect("was admitted");
        assert_eq!(gone.node_id, "furcate:node:a");
        assert!(r.current(1).is_empty(), "a withdrawn node is not admitted");

        // And withdrawing something that was never there is not an error, it
        // is simply nothing: an operator removing a node twice has not done
        // anything wrong the second time.
        assert!(r.withdraw("furcate:node:a").is_none());
    }
    use ed25519_dalek::SigningKey;

    fn roster_with(seed: u8, id: &str, valid_until: u64) -> Roster {
        let mut r = Roster::new();
        r.admit(Entry {
            node_id: id.into(),
            public_key: hex::encode(SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()),
            valid_until,
            os_measured: false,
        });
        r
    }

    #[test]
    fn a_roster_survives_a_restart() {
        // Without this the authentication hole reopens on every reboot.
        let d = std::env::temp_dir().join(format!("furcate-roster-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("roster.json");
        let r = roster_with(1, "furcate:node:a", 10_000);
        save(&r, &p).unwrap();

        let back = load(&p, 100).unwrap();
        assert_eq!(back.len(), 1);
        assert!(!back.is_empty(), "an empty roster would accept unsigned reports");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn admissions_that_lapsed_while_down_are_not_honoured_on_return() {
        let d = std::env::temp_dir().join(format!("furcate-roster-lapsed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("roster.json");
        save(&roster_with(1, "furcate:node:a", 500), &p).unwrap();

        let back = load(&p, 900).unwrap();
        assert!(back.is_empty(), "a lapsed admission must not be revived by a restart");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_roster_file_is_an_empty_roster_not_an_error() {
        let back = load(std::path::Path::new("/nonexistent/roster.json"), 100).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn platform_only_nodes_are_surfaced_rather_than_hidden() {
        let r = roster_with(1, "furcate:node:a", 1000);
        assert!(r.platform_only(100).contains("furcate:node:a"));
    }

    const ED: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const P: &str = "p256:031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e";
    const P_UNCOMPRESSED: &str = "p256:041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3";

    #[test]
    fn a_key_with_a_suite_needs_the_suite_member_and_the_key_decides() {
        let ed = format!("ed25519:{ED}");
        assert_eq!(admission_key(&ed, Some("ed25519")).unwrap().id(), ed);
        assert_eq!(admission_key(P, Some("p256")).unwrap().id(), P);
        // The uncompressed spelling is the same key, stored in the one spelling.
        assert_eq!(admission_key(P_UNCOMPRESSED, Some("p256")).unwrap().id(), P);
        // Missing member.
        assert!(admission_key(&ed, None).unwrap_err().contains("no `suite`"));
        assert!(admission_key(P, None).unwrap_err().contains("no `suite`"));
        // The member can only agree with the key: it never overrides it.
        assert!(admission_key(&ed, Some("p256")).unwrap_err().contains("enrolled key is ed25519"));
        assert!(admission_key(P, Some("ed25519")).unwrap_err().contains("enrolled key is p256"));
        assert!(admission_key(P, Some("ES256")).is_err());
    }

    #[test]
    fn the_bare_key_from_before_suites_is_ed25519_and_nothing_else_is_bare() {
        assert_eq!(admission_key(ED, None).unwrap().id(), format!("ed25519:{ED}"));
        assert!(admission_key(ED, Some("ed25519")).is_ok());
        assert!(admission_key(ED, Some("p256")).is_err());
        for bad in ["", "00", &format!("{ED}00"), "p256:02aa", "p256:zz", "rsa:00", "ed25519:00"] {
            assert!(admission_key(bad, Some("ed25519")).is_err(), "{bad}");
            assert!(admission_key(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_admitted_key_is_stored_in_one_spelling_and_survives_a_restart_with_its_suite() {
        let d = std::env::temp_dir().join(format!("furcate-roster-suite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let p = d.join("roster.json");
        let mut r = Roster::new();
        r.admit_key("furcate:node:p", &admission_key(P_UNCOMPRESSED, Some("p256")).unwrap(), 10_000, false);
        r.admit_key("furcate:node:e", &admission_key(ED, None).unwrap(), 10_000, false);
        save(&r, &p).unwrap();
        let back = load(&p, 100).unwrap();
        let by = |n: &str| back.current(100).into_iter().find(|e| e.node_id == n).unwrap().key().unwrap();
        assert_eq!(by("furcate:node:p").suite(), furcate_identity::KeySuite::P256);
        assert_eq!(by("furcate:node:p").id(), P);
        assert_eq!(by("furcate:node:e").suite(), furcate_identity::KeySuite::Ed25519);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_roster_file_from_before_suites_still_loads_and_an_unreadable_key_is_dropped_by_name() {
        let d = std::env::temp_dir().join(format!("furcate-roster-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("roster.json");
        let file = serde_json::json!([
            {"node_id": "furcate:node:old", "public_key": ED, "valid_until": 10_000, "os_measured": false},
            {"node_id": "furcate:node:junk", "public_key": "p256:02aa", "valid_until": 10_000, "os_measured": false},
        ]);
        std::fs::write(&p, file.to_string()).unwrap();
        let back = load(&p, 100).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.dropped(), ["furcate:node:junk".to_string()]);
        let old = back.current(100)[0].key().unwrap();
        assert_eq!(old.suite(), furcate_identity::KeySuite::Ed25519);
        let _ = std::fs::remove_dir_all(&d);
    }
}
