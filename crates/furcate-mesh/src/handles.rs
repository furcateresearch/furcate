//! Names an operator types.
//!
//! A machine has a node id — `furcate:node:avj3tpuj…` — which is derived from
//! its hardware and cannot be chosen. That is the right thing for a signature
//! to name and the wrong thing for a person to type, and a fleet of them is a
//! list nobody can read: four identical-looking strings where an operator
//! wanted `@node-a`.
//!
//! So a handle is a mutable label over an immutable id. The id stays what
//! authority is checked against; the handle is what a person says. Renaming a
//! machine changes nothing about what it may do.
//!
//! Handles are unique within a cluster and allocated by the controller, which
//! is the only thing that sees every machine at once. A node cannot name
//! itself: two machines from the same disk image arrive believing the same
//! thing, and the one that reports second would otherwise silently replace the
//! first on every screen that keys on a name.

use serde::{Deserialize, Serialize};

/// What a handle may be made of.
///
/// Lowercase letters, digits and hyphens: a handle is typed, appears in URLs,
/// and is compared for uniqueness, and every one of those is easier when case
/// is not a question. Leading `@` is accepted and stripped, because an
/// operator who types the sigil meant the name.
pub fn normalise(raw: &str) -> Result<String, HandleError> {
    let s = raw.trim().trim_start_matches('@').to_ascii_lowercase();
    if s.is_empty() {
        return Err(HandleError::Empty);
    }
    if s.len() > 63 {
        return Err(HandleError::TooLong);
    }
    if !s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(HandleError::BadCharacter);
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(HandleError::EdgeHyphen);
    }
    // A handle that looks like a node id would be ambiguous wherever both are
    // accepted, which is everywhere an operator names a machine.
    if s.starts_with("furcate") {
        return Err(HandleError::ReservedPrefix);
    }
    Ok(s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleError {
    Empty,
    TooLong,
    BadCharacter,
    EdgeHyphen,
    ReservedPrefix,
    Taken,
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandleError::Empty => write!(f, "a handle needs a name"),
            HandleError::TooLong => write!(f, "a handle is at most 63 characters"),
            HandleError::BadCharacter => {
                write!(f, "a handle is lowercase letters, digits and hyphens")
            }
            HandleError::EdgeHyphen => write!(f, "a handle may not start or end with a hyphen"),
            HandleError::ReservedPrefix => {
                write!(f, "`furcate` is how node ids begin; a handle may not")
            }
            HandleError::Taken => write!(f, "another machine in this cluster already answers to that"),
        }
    }
}

impl std::error::Error for HandleError {}

/// One machine's handle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handle {
    pub node_id: String,
    pub handle: String,
    pub set_at: u64,
    /// Whether an operator chose this or the controller derived it.
    ///
    /// Recorded because the two are treated differently on a clash: a derived
    /// name may be quietly adjusted, and a chosen one must not be — somebody
    /// typed it and expects it.
    pub chosen: bool,
}

/// Every handle in a cluster, and the cluster's own.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Handles {
    /// node id -> handle.
    #[serde(default)]
    pub machines: std::collections::BTreeMap<String, Handle>,
    /// What this cluster answers to, under the account that owns it.
    ///
    /// An account with several clusters needs to say which one, and "the site"
    /// is not a name. Absent until somebody chooses one.
    #[serde(default)]
    pub cluster: Option<String>,
}

impl Handles {
    pub fn new() -> Self {
        Self::default()
    }

    /// Who answers to this handle, if anybody.
    pub fn resolve(&self, raw: &str) -> Option<&Handle> {
        let want = normalise(raw).ok()?;
        self.machines.values().find(|h| h.handle == want)
    }

    pub fn handle_of(&self, node_id: &str) -> Option<&str> {
        self.machines.get(node_id).map(|h| h.handle.as_str())
    }

    /// Give a machine a handle an operator chose.
    ///
    /// Refuses a clash rather than adjusting it. Somebody typed this name and
    /// expects it; handing them `node-a-2` because another machine got there
    /// first is a surprise, and the remedy — rename the other one, or pick
    /// again — is theirs to choose.
    pub fn set(&mut self, node_id: &str, raw: &str, now: u64) -> Result<Option<Handle>, HandleError> {
        let handle = normalise(raw)?;
        if let Some(other) = self.machines.values().find(|h| h.handle == handle) {
            if other.node_id != node_id {
                return Err(HandleError::Taken);
            }
        }
        Ok(self.machines.insert(
            node_id.to_string(),
            Handle { node_id: node_id.to_string(), handle, set_at: now, chosen: true },
        ))
    }

    /// Give a machine a handle nobody chose.
    ///
    /// For what a node reports about itself at enrolment. A clash here IS
    /// adjusted — `node-a`, then `node-a-2` — because the alternative is a
    /// machine with no name at all, and two machines from one disk image
    /// arriving with the same hostname is the ordinary case rather than a
    /// mistake somebody made.
    pub fn derive(&mut self, node_id: &str, suggestion: &str, now: u64) -> String {
        let base = normalise(suggestion).unwrap_or_else(|_| "node".to_string());
        if let Some(existing) = self.machines.get(node_id) {
            // Never overwrite a name an operator chose with one a machine
            // reported: a rename would then last until the next restart.
            if existing.chosen {
                return existing.handle.clone();
            }
        }
        let mut candidate = base.clone();
        let mut n = 1;
        while self
            .machines
            .values()
            .any(|h| h.handle == candidate && h.node_id != node_id)
        {
            n += 1;
            candidate = format!("{base}-{n}");
        }
        self.machines.insert(
            node_id.to_string(),
            Handle { node_id: node_id.to_string(), handle: candidate.clone(), set_at: now, chosen: false },
        );
        candidate
    }

    pub fn forget(&mut self, node_id: &str) -> Option<Handle> {
        self.machines.remove(node_id)
    }

    /// Name the cluster.
    pub fn set_cluster(&mut self, raw: &str) -> Result<Option<String>, HandleError> {
        let name = normalise(raw)?;
        Ok(self.cluster.replace(name))
    }
}

/// Write handles out, temp-then-rename.
pub fn save(h: &Handles, path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let encoded = serde_json::to_vec_pretty(h)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &encoded)?;
    std::fs::rename(&tmp, path)
}

/// Read them back. Absent is ordinary: a cluster nobody has named yet.
pub fn load(path: &std::path::Path) -> std::io::Result<Handles> {
    match std::fs::read(path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Handles::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_is_typed_the_way_an_operator_types_it() {
        assert_eq!(normalise("@node-a").unwrap(), "node-a");
        assert_eq!(normalise("  Node-a  ").unwrap(), "node-a");
        assert_eq!(normalise("edge-01").unwrap(), "edge-01");
    }

    #[test]
    fn a_handle_cannot_be_mistaken_for_a_node_id() {
        assert_eq!(normalise("furcate-node"), Err(HandleError::ReservedPrefix));
        assert_eq!(normalise("server 1"), Err(HandleError::BadCharacter));
        assert_eq!(normalise("-lead"), Err(HandleError::EdgeHyphen));
        assert_eq!(normalise(""), Err(HandleError::Empty));
    }

    #[test]
    fn a_chosen_name_is_refused_rather_than_adjusted() {
        let mut h = Handles::new();
        h.set("node:a", "node-a", 1).unwrap();
        // Somebody typed this and expects it; silently handing back
        // "node-a-2" is a surprise they cannot see.
        assert_eq!(h.set("node:b", "node-a", 2), Err(HandleError::Taken));
        // The same machine keeping its own name is not a clash.
        assert!(h.set("node:a", "node-a", 3).is_ok());
    }

    #[test]
    fn a_derived_name_is_adjusted_rather_than_refused() {
        let mut h = Handles::new();
        assert_eq!(h.derive("node:a", "node-a", 1), "node-a");
        // Two machines from one image report the same hostname. The second
        // gets a name rather than none.
        assert_eq!(h.derive("node:b", "node-a", 2), "node-a-2");
        assert_eq!(h.derive("node:c", "node-a", 3), "node-a-3");
    }

    #[test]
    fn a_reported_name_never_overwrites_a_chosen_one() {
        let mut h = Handles::new();
        h.set("node:a", "lead", 1).unwrap();
        // The node goes on reporting its hostname on every restart. A rename
        // that lasts until the next reboot is not a rename.
        assert_eq!(h.derive("node:a", "node-a", 2), "lead");
    }

    #[test]
    fn a_handle_resolves_with_or_without_the_sigil() {
        let mut h = Handles::new();
        h.set("node:a", "node-e", 1).unwrap();
        assert_eq!(h.resolve("@node-e").map(|x| x.node_id.as_str()), Some("node:a"));
        assert_eq!(h.resolve("NODE-E").map(|x| x.node_id.as_str()), Some("node:a"));
        assert!(h.resolve("@nobody").is_none());
    }

    #[test]
    fn handles_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("furcate-handles-{}", std::process::id()));
        let path = dir.join("handles.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut h = Handles::new();
        h.set("node:a", "lead", 7).unwrap();
        h.set_cluster("@home-lab").unwrap();
        save(&h, &path).expect("saves");

        let back = load(&path).expect("loads");
        assert_eq!(back.handle_of("node:a"), Some("lead"));
        assert_eq!(back.cluster.as_deref(), Some("home-lab"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
