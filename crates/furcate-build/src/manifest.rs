//! The build manifest: the declarative form of a build action.
//!
//! The design note calls this `furcate.toml`. The workspace has one format for
//! files humans write -- `serde_norway` (YAML) -- chosen precisely because it
//! does not, for instance, read `no` as boolean false the way a policy file
//! must never do quietly. This manifest follows that convention rather than
//! adding a second config language, so it is a `furcate.build.yaml`.
//!
//! A manifest names inputs by *path*, because that is what a person can write.
//! Resolving it ingests each path into the content store and produces a
//! `BuildAction` whose inputs are digests. That resolution is where refusal
//! 6.1 bites: a path that is not a readable file is not an input, and there is
//! no field in which to write a branch name instead.

use crate::action::{BuildAction, Network};
use crate::cas::Cas;
use crate::refusal::Refusal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

/// Network posture as written by a human: `denied`, or `granted: "reason"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestNetwork {
    Denied,
    Granted { reason: String },
}

impl Default for ManifestNetwork {
    fn default() -> Self {
        ManifestNetwork::Denied
    }
}

impl From<ManifestNetwork> for Network {
    fn from(m: ManifestNetwork) -> Self {
        match m {
            ManifestNetwork::Denied => Network::Denied,
            ManifestNetwork::Granted { reason } => Network::Granted { reason },
        }
    }
}

/// One action as written in the manifest. Inputs are paths, not digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAction {
    pub command: Vec<String>,
    #[serde(default)]
    pub inputs: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub network: ManifestNetwork,
}

impl ManifestAction {
    /// Resolve into a runnable `BuildAction` by ingesting every input path into
    /// the content store. The `target` comes from the manifest it belongs to.
    pub fn resolve(&self, target: &str, cas: &Cas) -> Result<BuildAction, ResolveError> {
        let mut inputs = BTreeMap::new();
        for (name, path) in &self.inputs {
            let digest = cas.put_path(path).map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => ResolveError::Refused(Refusal::UnnamedSource {
                    detail: format!("input '{name}' -> {} is not a readable file", path.display()),
                }),
                _ => ResolveError::Io(e),
            })?;
            inputs.insert(name.clone(), digest);
        }
        let action = BuildAction {
            target: target.to_string(),
            inputs,
            command: self.command.clone(),
            env: self.env.clone(),
            outputs: self.outputs.clone(),
            network: self.network.clone().into(),
        };
        if !action.inputs_are_named() {
            return Err(ResolveError::Refused(Refusal::UnnamedSource {
                detail: "action declares no inputs".to_string(),
            }));
        }
        Ok(action)
    }
}

/// A whole manifest: a target and the actions defined for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub target: String,
    pub actions: BTreeMap<String, ManifestAction>,
}

impl Manifest {
    /// Parse a manifest from YAML text.
    pub fn parse(text: &str) -> Result<Self, ResolveError> {
        serde_norway::from_str(text).map_err(ResolveError::Parse)
    }

    /// Resolve one named action into a `BuildAction`.
    pub fn resolve(&self, action: &str, cas: &Cas) -> Result<BuildAction, ResolveError> {
        let a = self
            .actions
            .get(action)
            .ok_or_else(|| ResolveError::NoSuchAction(action.to_string()))?;
        a.resolve(&self.target, cas)
    }
}

#[derive(Debug)]
pub enum ResolveError {
    Parse(serde_norway::Error),
    NoSuchAction(String),
    Refused(Refusal),
    Io(io::Error),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Parse(e) => write!(f, "manifest parse: {e}"),
            ResolveError::NoSuchAction(a) => write!(f, "no action named '{a}' in manifest"),
            ResolveError::Refused(r) => write!(f, "{r}"),
            ResolveError::Io(e) => write!(f, "manifest io: {e}"),
        }
    }
}

impl std::error::Error for ResolveError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
target: x86_64-linux
actions:
  furcated:
    command: [cargo, build, --release, -p, furcated]
    inputs:
      lib: Cargo.toml
    outputs:
      - target/release/furcated
    network: denied
"#;

    fn temp_cas() -> Cas {
        let mut p = std::env::temp_dir();
        p.push(format!("fcbuild-manifest-{}-{:?}", std::process::id(), std::time::SystemTime::now()));
        Cas::open(p).unwrap()
    }

    #[test]
    fn parses() {
        let m = Manifest::parse(SAMPLE).unwrap();
        assert_eq!(m.target, "x86_64-linux");
        assert!(m.actions.contains_key("furcated"));
    }

    #[test]
    fn resolving_a_missing_input_is_refused() {
        let mut m = Manifest::parse(SAMPLE).unwrap();
        m.actions
            .get_mut("furcated")
            .unwrap()
            .inputs
            .insert("ghost".into(), "/no/such/file".into());
        match m.resolve("furcated", &temp_cas()) {
            Err(ResolveError::Refused(Refusal::UnnamedSource { .. })) => {}
            other => panic!("expected UnnamedSource refusal, got {other:?}"),
        }
    }

    #[test]
    fn unknown_action_is_reported() {
        let m = Manifest::parse(SAMPLE).unwrap();
        assert!(matches!(
            m.resolve("nope", &temp_cas()),
            Err(ResolveError::NoSuchAction(_))
        ));
    }
}
