//! The policy an operator signs for one agent.
//!
//! An agent runtime is told what an agent may reach by this document and by
//! nothing else. It is signed by the operator's key (as [`CellKey`] names
//! keys), checked before any runtime sees it, and the digest of what was
//! checked is what the ledger records. Absent means denied: a field that is not
//! written grants nothing, and unknown fields are refused rather than ignored,
//! so a newer document is never half-applied by an older reader.
//!
//! The same document drives every runtime. A runtime that cannot honour part
//! of it must say so and refuse; it must not apply the rest.

use crate::delegation::CellKey;
use furcate_identity::MessageSigner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How much of a service an agent may use through a network rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    ReadOnly,
    ReadWrite,
    Full,
}

impl Access {
    pub fn as_str(&self) -> &'static str {
        match self {
            Access::ReadOnly => "read-only",
            Access::ReadWrite => "read-write",
            Access::Full => "full",
        }
    }
}

/// One destination an agent may connect to, and which programs may.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub name: String,
    /// An exact host name, or `*.` followed by a domain.
    pub host: String,
    pub port: u16,
    pub access: Access,
    /// Programs inside the sandbox that may use this rule. Empty means none.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// The credential provider the runtime may attach at this endpoint. The
    /// agent never holds the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// A host-mediated tool an agent may call, for runtimes that have no network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    pub name: String,
    pub url: String,
    /// Operations that may be called. Empty means none.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRules {
    #[serde(default)]
    pub read_only: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default)]
    pub vcpus: Option<u8>,
    #[serde(default)]
    pub mem_mib: Option<u32>,
    #[serde(default)]
    pub ttl_s: Option<u64>,
}

/// The document the operator signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    pub site: String,
    /// The agent name this applies to.
    pub agent: String,
    /// Rises with every reissue; a node refuses one below the floor it holds.
    pub revision: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// The signing key, as [`CellKey`] names it.
    pub issuer: String,
    #[serde(default)]
    pub filesystem: FilesystemRules,
    #[serde(default)]
    pub network: Vec<NetworkRule>,
    #[serde(default)]
    pub tools: Vec<ToolGrant>,
    #[serde(default)]
    pub limits: Limits,
    /// Hex signature by `issuer` over [`AgentPolicy::signed_bytes`].
    #[serde(default)]
    pub signature: String,
}

/// Why a policy is not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRefusal {
    Unsigned,
    /// Signed, but not by the key this node trusts.
    WrongIssuer { found: String },
    BadSignature,
    NotYetValid { not_before: u64, now: u64 },
    Expired { not_after: u64, now: u64 },
    /// Older than the revision this node already holds.
    Stale { revision: u64, floor: u64 },
    /// For another site or another agent.
    NotForThisAgent { site: String, agent: String },
    Malformed(String),
}

impl std::fmt::Display for PolicyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyRefusal::Unsigned => write!(f, "the policy is not signed"),
            PolicyRefusal::WrongIssuer { found } => write!(f, "the policy is signed by {found}, not the operator key"),
            PolicyRefusal::BadSignature => write!(f, "the policy signature does not verify"),
            PolicyRefusal::NotYetValid { not_before, now } => write!(f, "the policy is valid from {not_before}; it is {now}"),
            PolicyRefusal::Expired { not_after, now } => write!(f, "the policy expired at {not_after}; it is {now}"),
            PolicyRefusal::Stale { revision, floor } => write!(f, "revision {revision} is below the floor {floor}"),
            PolicyRefusal::NotForThisAgent { site, agent } => write!(f, "the policy is for {agent} at {site}"),
            PolicyRefusal::Malformed(why) => write!(f, "the policy is malformed: {why}"),
        }
    }
}

impl std::error::Error for PolicyRefusal {}

fn put(m: &mut Vec<u8>, f: &str) {
    m.extend_from_slice(&(f.len() as u64).to_be_bytes());
    m.extend_from_slice(f.as_bytes());
}

fn host_ok(h: &str) -> bool {
    let body = h.strip_prefix("*.").unwrap_or(h);
    !body.is_empty()
        && body.len() <= 253
        && body.contains('.') | (body == "localhost")
        && body.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') && !l.starts_with('-')
        })
}

fn path_ok(p: &str) -> bool {
    p.starts_with('/') && p.len() <= 4096 && !p.split('/').any(|c| c == "..") && !p.contains('\0')
}

impl AgentPolicy {
    /// The exact bytes the signature covers.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut m = b"furcate:agent-policy:v1\0".to_vec();
        for f in [
            &self.site,
            &self.agent,
            &self.revision.to_string(),
            &self.not_before.to_string(),
            &self.not_after.to_string(),
            &self.issuer,
        ] {
            put(&mut m, f);
        }
        for p in &self.filesystem.read_only {
            put(&mut m, &format!("fs-ro={p}"));
        }
        for p in &self.filesystem.read_write {
            put(&mut m, &format!("fs-rw={p}"));
        }
        for n in &self.network {
            put(
                &mut m,
                &format!(
                    "net={}|{}|{}|{}|{}|{}",
                    n.name,
                    n.host,
                    n.port,
                    n.access.as_str(),
                    n.binaries.join(","),
                    n.credential.clone().unwrap_or_default()
                ),
            );
        }
        for t in &self.tools {
            put(&mut m, &format!("tool={}|{}|{}|{}", t.name, t.url, t.allow.join(","), t.credential.clone().unwrap_or_default()));
        }
        put(
            &mut m,
            &format!("limits={:?}|{:?}|{:?}", self.limits.vcpus, self.limits.mem_mib, self.limits.ttl_s),
        );
        m
    }

    /// The digest the ledger records and every runtime translation names.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.signed_bytes());
        h.update(self.signature.as_bytes());
        hex::encode(h.finalize())
    }

    /// Sign with the hardware signer that holds the issuer key.
    pub fn signed_with(mut self, signer: &dyn MessageSigner) -> Result<AgentPolicy, String> {
        let me = CellKey::of(signer)?.id();
        if me != self.issuer {
            return Err(format!("the policy is issued by {}, and this signer holds {me}", self.issuer));
        }
        let m = self.signed_bytes();
        self.signature = CellKey::parse(&self.issuer)?
            .seal(&m, &signer.sign(&m).map_err(|e| format!("the signer refused: {e:#}"))?)?;
        Ok(self)
    }

    /// Whether the document is well formed, independent of who signed it.
    pub fn check_shape(&self) -> Result<(), PolicyRefusal> {
        let bad = |s: String| Err(PolicyRefusal::Malformed(s));
        if self.agent.is_empty() || self.site.is_empty() {
            return bad("site and agent are required".into());
        }
        if self.not_after <= self.not_before {
            return bad("not_after must be after not_before".into());
        }
        if self.network.len() > 256 || self.tools.len() > 64 {
            return bad("too many rules".into());
        }
        for p in self.filesystem.read_only.iter().chain(&self.filesystem.read_write) {
            if !path_ok(p) {
                return bad(format!("path `{p}` must be absolute, without `..`"));
            }
        }
        if self.filesystem.read_write.iter().any(|p| p == "/") {
            return bad("`/` cannot be writable".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for n in &self.network {
            if !names.insert(n.name.as_str()) || n.name.is_empty() || n.name.starts_with("_provider_") {
                return bad(format!("network rule name `{}` is empty, reserved or repeated", n.name));
            }
            if !host_ok(&n.host) || n.port == 0 {
                return bad(format!("network rule `{}` needs an exact host and a port", n.name));
            }
            if n.binaries.iter().any(|b| !path_ok(b) && !b.starts_with('/')) {
                return bad(format!("network rule `{}` names a program that is not an absolute path", n.name));
            }
        }
        for t in &self.tools {
            if t.name.is_empty() || !t.url.starts_with("https://") && !t.url.starts_with("http://") {
                return bad(format!("tool `{}` needs a name and an http(s) url", t.name));
            }
        }
        Ok(())
    }

    /// Everything a node checks before any runtime is told anything: signed,
    /// by the operator key, valid now, not older than the floor, for this
    /// agent and site, and well formed.
    pub fn verify(
        &self,
        operator_key: &str,
        site: &str,
        agent: &str,
        floor: u64,
        now: u64,
    ) -> Result<(), PolicyRefusal> {
        if self.signature.is_empty() {
            return Err(PolicyRefusal::Unsigned);
        }
        if self.issuer != operator_key {
            return Err(PolicyRefusal::WrongIssuer { found: self.issuer.clone() });
        }
        let key = CellKey::parse(operator_key).map_err(PolicyRefusal::Malformed)?;
        key.verify_hex(&self.signed_bytes(), &self.signature).map_err(|_| PolicyRefusal::BadSignature)?;
        if self.site != site || self.agent != agent {
            return Err(PolicyRefusal::NotForThisAgent { site: self.site.clone(), agent: self.agent.clone() });
        }
        if now < self.not_before {
            return Err(PolicyRefusal::NotYetValid { not_before: self.not_before, now });
        }
        if now >= self.not_after {
            return Err(PolicyRefusal::Expired { not_after: self.not_after, now });
        }
        if self.revision < floor {
            return Err(PolicyRefusal::Stale { revision: self.revision, floor });
        }
        self.check_shape()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_identity::Ed25519Signer;
    use std::sync::Arc;

    fn signer(b: u8) -> Ed25519Signer {
        Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[b; 32])))
    }

    fn policy(issuer: &str) -> AgentPolicy {
        AgentPolicy {
            site: "site-1".into(),
            agent: "reader".into(),
            revision: 3,
            not_before: 10,
            not_after: 1000,
            issuer: issuer.into(),
            filesystem: FilesystemRules { read_only: vec!["/usr".into()], read_write: vec!["/work".into()] },
            network: vec![NetworkRule {
                name: "docs".into(),
                host: "docs.example.com".into(),
                port: 443,
                access: Access::ReadOnly,
                binaries: vec!["/usr/bin/curl".into()],
                credential: None,
            }],
            tools: vec![],
            limits: Limits::default(),
            signature: String::new(),
        }
    }

    fn signed() -> (AgentPolicy, String) {
        let s = signer(7);
        let id = CellKey::of(&s).unwrap().id();
        (policy(&id).signed_with(&s).unwrap(), id)
    }

    #[test]
    fn a_signed_policy_verifies() {
        let (p, id) = signed();
        p.verify(&id, "site-1", "reader", 3, 20).unwrap();
    }

    #[test]
    fn unsigned_and_foreign_and_tampered_are_refused() {
        let (p, id) = signed();
        let mut u = p.clone();
        u.signature.clear();
        assert_eq!(u.verify(&id, "site-1", "reader", 0, 20), Err(PolicyRefusal::Unsigned));
        let other = CellKey::of(&signer(8)).unwrap().id();
        assert!(matches!(p.verify(&other, "site-1", "reader", 0, 20), Err(PolicyRefusal::WrongIssuer { .. })));
        let mut t = p.clone();
        t.network[0].host = "evil.example.com".into();
        assert_eq!(t.verify(&id, "site-1", "reader", 0, 20), Err(PolicyRefusal::BadSignature));
        let mut w = p.clone();
        w.network[0].access = Access::Full;
        assert_eq!(w.verify(&id, "site-1", "reader", 0, 20), Err(PolicyRefusal::BadSignature));
    }

    #[test]
    fn stale_expired_early_and_misaddressed_are_refused() {
        let (p, id) = signed();
        assert!(matches!(p.verify(&id, "site-1", "reader", 4, 20), Err(PolicyRefusal::Stale { .. })));
        assert!(matches!(p.verify(&id, "site-1", "reader", 0, 1000), Err(PolicyRefusal::Expired { .. })));
        assert!(matches!(p.verify(&id, "site-1", "reader", 0, 5), Err(PolicyRefusal::NotYetValid { .. })));
        assert!(matches!(p.verify(&id, "site-1", "other", 0, 20), Err(PolicyRefusal::NotForThisAgent { .. })));
    }

    #[test]
    fn shape_rules_hold() {
        let s = signer(7);
        let id = CellKey::of(&s).unwrap().id();
        let mut p = policy(&id);
        p.filesystem.read_write = vec!["/".into()];
        assert!(p.check_shape().is_err());
        let mut p = policy(&id);
        p.network[0].host = "*".into();
        assert!(p.check_shape().is_err());
        let mut p = policy(&id);
        p.filesystem.read_only = vec!["/a/../etc".into()];
        assert!(p.check_shape().is_err());
        assert!(policy(&id).check_shape().is_ok());
    }

    #[test]
    fn unknown_fields_are_refused_when_parsing() {
        let j = r#"{"site":"s","agent":"a","revision":1,"not_before":0,"not_after":9,"issuer":"x","grant_all":true}"#;
        assert!(serde_json::from_str::<AgentPolicy>(j).is_err());
    }

    #[test]
    fn the_digest_follows_the_content() {
        let (p, _) = signed();
        let mut q = p.clone();
        q.revision = 4;
        assert_ne!(p.digest(), q.digest());
    }
}
