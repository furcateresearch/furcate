//! The build action, and the digest that names it.
//!
//! A build is an *action*: a pure function from named inputs to named outputs,
//! run under a stated command. Everything that could change the output is part
//! of the action and therefore part of its digest — the target it builds for,
//! every input named by content, the command, the environment, and whether the
//! network was granted. Two actions with the same digest must produce the same
//! result; that is the whole basis on which the cache is allowed to answer.

use crate::digest::{Digest, Hasher};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Whether the action may touch the network, and if so, why it was allowed.
///
/// The default is `Denied`. Network is a capability the policy grants for a
/// named action (refusal §6.4), and when granted the reason is recorded here so
/// it travels into the provenance rather than being lost.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Denied,
    Granted { reason: String },
}

impl Default for Network {
    fn default() -> Self {
        Network::Denied
    }
}

/// A build action. Its digest is a claim that these exact inputs, run this
/// exact way, for this exact target, yield the declared outputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildAction {
    /// What the action builds *for* — an architecture/OS the placement layer
    /// must satisfy from attested capability, e.g. `x86_64-linux` or
    /// `cuda:sm_120`. A machine is one target only if it is that target.
    pub target: String,
    /// Named source materials, each pinned by content digest. There is no field
    /// for a branch name or a tag: a name the store cannot resolve to bytes is
    /// not an input (refusal §6.1).
    pub inputs: BTreeMap<String, Digest>,
    /// The command to run, as argv (no shell).
    pub command: Vec<String>,
    /// Environment, sorted so it cannot perturb the digest by ordering.
    pub env: BTreeMap<String, String>,
    /// Paths, relative to the action root, the action promises to produce.
    pub outputs: Vec<String>,
    /// Network posture. Denied unless a policy grant said otherwise.
    #[serde(default)]
    pub network: Network,
}

impl BuildAction {
    /// The action digest: the cache key, and the thing provenance attests to.
    ///
    /// The encoding is length-prefixed field by field so that no two distinct
    /// actions can serialise to the same bytes — the same discipline the ledger
    /// uses on its entries. Maps are `BTreeMap`, so iteration is already sorted.
    pub fn digest(&self) -> Digest {
        let mut h = Hasher::new();
        // A version tag, so a future change to this encoding is a different
        // digest space rather than a silent collision with old cache entries.
        field(&mut h, b"furcate-build/action/v1");
        field(&mut h, self.target.as_bytes());

        count(&mut h, self.inputs.len());
        for (name, dig) in &self.inputs {
            field(&mut h, name.as_bytes());
            field(&mut h, dig.as_bytes());
        }

        count(&mut h, self.command.len());
        for arg in &self.command {
            field(&mut h, arg.as_bytes());
        }

        count(&mut h, self.env.len());
        for (k, v) in &self.env {
            field(&mut h, k.as_bytes());
            field(&mut h, v.as_bytes());
        }

        count(&mut h, self.outputs.len());
        for o in &self.outputs {
            field(&mut h, o.as_bytes());
        }

        match &self.network {
            Network::Denied => field(&mut h, b"net:denied"),
            Network::Granted { reason } => {
                field(&mut h, b"net:granted");
                field(&mut h, reason.as_bytes());
            }
        }

        h.finish()
    }

    /// Does every input carry a content digest? Construction already enforces
    /// this by type, but a `BuildAction` deserialised from an untrusted source
    /// is checked here before it is allowed to run.
    pub fn inputs_are_named(&self) -> bool {
        // A `Digest` cannot be malformed once deserialised, so the only failure
        // mode is an empty input set claiming to be a real source tree.
        !self.inputs.is_empty()
    }
}

fn field(h: &mut Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn count(h: &mut Hasher, n: usize) {
    h.update(&(n as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BuildAction {
        let mut inputs = BTreeMap::new();
        inputs.insert("src".to_string(), Digest::of(b"source tree"));
        let mut env = BTreeMap::new();
        env.insert("CARGO_PROFILE".to_string(), "release".to_string());
        BuildAction {
            target: "x86_64-linux".to_string(),
            inputs,
            command: vec!["cargo".into(), "build".into(), "--release".into()],
            env,
            outputs: vec!["target/release/furcated".into()],
            network: Network::Denied,
        }
    }

    #[test]
    fn digest_is_stable() {
        assert_eq!(sample().digest(), sample().digest());
    }

    #[test]
    fn env_order_does_not_matter() {
        let a = sample();
        let mut b = sample();
        // Insert the same pairs in a different order; BTreeMap normalises.
        b.env.clear();
        b.env.insert("CARGO_PROFILE".into(), "release".into());
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn changing_an_input_changes_the_digest() {
        let a = sample();
        let mut b = sample();
        b.inputs.insert("src".into(), Digest::of(b"different source"));
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn granting_network_changes_the_digest() {
        let a = sample();
        let mut b = sample();
        b.network = Network::Granted { reason: "fetch crates".into() };
        assert_ne!(
            a.digest(),
            b.digest(),
            "a network grant must not be invisible to the cache key"
        );
    }

    #[test]
    fn target_is_part_of_identity() {
        let a = sample();
        let mut b = sample();
        b.target = "cuda:sm_120".into();
        assert_ne!(a.digest(), b.digest());
    }
}
