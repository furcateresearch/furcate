//! Whose word this site takes, and for what.
//!
//! Identity here has two levels, and conflating them is how a site loses the
//! ability to run itself.
//!
//! **The local level is the cluster's own.** A site has a root — the operator
//! key — and everything it issues beneath that: people who administer these
//! machines, the machines themselves, agents given a task here. It is
//! self-sovereign by construction. It needs no network, no coordinator and no
//! outside service, and it keeps working when every one of those is gone.
//!
//! **The global level is the network's.** Global identities span operators who
//! do not trust each other: a counterparty renting capacity, a node from
//! another site, an agent acting for somebody who is not the operator here.
//! They are recognised through an adapter, verified against issuer keys cached
//! locally, and they are how this cluster is addressable from outside it.
//!
//! ## The rule that keeps them apart
//!
//! > **A local identity never depends on the global one. A global identity
//! > never outranks the local one.**
//!
//! The first half is sovereignty: if the network is unreachable, or the
//! identity service is down, or an operator has fallen out with the network
//! entirely, the people standing in front of these machines still administer
//! them. Nothing about running your own hardware may be contingent on somebody
//! else answering.
//!
//! The second half is the same hazard the overlay already guards. There, a
//! coordinator supplies reachability and never authority, because a coordinator
//! that could remove a node's access would be performing `isolate` — one of the
//! four things nothing may do. A global identity service that could decide who
//! administers this rack would be the same kill switch with a friendlier name.
//! So a global identity is a *claim about who somebody is*, admitted only as far
//! as local policy has already written down, and never a claim about what they
//! may do here.
//!
//! ## What is stored
//!
//! Public keys and revocations. No secrets: the operator's private half lives
//! in a TPM and the site's own machines hold their own. A trust store that held
//! a secret would be a file worth stealing, and this one is worth only reading.

use serde::{Deserialize, Serialize};

/// Which level an issuer belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// This cluster's own. Recognised with no network, and authoritative here.
    Local,
    /// The wider network's. Recognised for principals from outside this site,
    /// and never able to outrank what the local level says.
    Global,
}

impl Level {
    /// Whether this level may be relied on when nothing outside answers.
    ///
    /// Only the local one. A site whose administration depended on a reachable
    /// service would stop being the operator's the first time somebody else's
    /// server had a bad day.
    pub fn works_offline(&self) -> bool {
        matches!(self, Level::Local)
    }
}

/// An issuer this site is willing to recognise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    /// How credentials name it.
    pub id: String,
    pub level: Level,
    /// Ed25519 public key, hex.
    pub key: String,
    /// Why this site recognises it, in the operator's own words. Carried
    /// because a trust store nobody can read the reasoning of is one nobody
    /// dares remove an entry from.
    pub reason: String,
    /// What this entry is: a machine proving it is itself, or an authority that
    /// issues tokens about others.
    ///
    /// The distinction matters because they are checked differently and confer
    /// different things. A machine's key authenticates exactly one principal —
    /// itself. An issuer's key authenticates whatever it chooses to sign for,
    /// which is a great deal more authority and should never be conferred by a
    /// field somebody set by accident.
    #[serde(default)]
    pub kind: Kind,
    /// For a machine: whether its boot chain was measured when last appraised.
    /// False is the honest answer on hardware whose registers stop at the
    /// firmware, and it narrows what that machine may do.
    #[serde(default)]
    pub boot_measured: bool,
}

/// What an entry in the store is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// One machine, authenticating as itself.
    #[default]
    Machine,
    /// An authority whose signature vouches for others.
    Issuer,
}

/// The site's answer to "whose word do we take".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStore {
    pub issuers: Vec<Issuer>,
    /// Credential ids known to be withdrawn.
    ///
    /// Kept locally, so a revocation that arrived while the network was up
    /// survives the network going down. Revocations only ever narrow what is
    /// permitted, which is why it is safe to act on a stale list and never safe
    /// to ignore one.
    #[serde(default)]
    pub revoked: Vec<String>,
    /// When the revocation list was last confirmed against the network.
    #[serde(default)]
    pub revocations_checked_at: Option<u64>,
}

/// How long a revocation list may go unconfirmed before global credentials stop
/// being accepted.
///
/// Local credentials are unaffected: they are revoked by editing this file,
/// which is an act by somebody with access to the machine and needs no network
/// to be true. Global ones depend on a list that can only be refreshed from
/// outside, and a list nobody has been able to check for a day is a list that
/// may be missing the entry that matters.
pub const REVOCATION_STALE_AFTER_SECS: u64 = 86_400;

impl TrustStore {
    /// Stop recognising an issuer.
    ///
    /// Returns what was removed, or None if that id was not trusted here. A
    /// machine that has been decommissioned should stop being an issuer this
    /// site believes on the day it is decommissioned — an entry left behind is
    /// a key that still carries weight for a machine nobody is watching any
    /// more, and it goes on being advertised to anybody reading /trust.
    ///
    /// Distinct from revocation. `revoked` names credentials that were issued
    /// and must no longer be honoured; this says the issuer itself is no longer
    /// one of ours. A decommissioned node needs the second, and adding it to
    /// the first would be a growing list of dead credentials nobody can prune.
    pub fn withdraw(&mut self, id: &str) -> Option<Issuer> {
        let at = self.issuers.iter().position(|i| i.id == id)?;
        Some(self.issuers.remove(at))
    }

    /// Write the store back.
    ///
    /// Temp-then-rename, so a crash midway leaves the previous file rather than
    /// a truncated one — and a truncated trust store is fatal to load by
    /// design, which would take the site down rather than quietly trusting
    /// nobody.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &encoded)?;
        std::fs::rename(&tmp, path)
    }

    /// Read the store, or say why not.
    ///
    /// A file that exists and cannot be read or parsed is **fatal to the
    /// caller**, never a fall-through to defaults. Falling back would restore
    /// authority an operator had written down a decision to remove, and an
    /// unreadable file is not evidence they changed their mind — the same rule
    /// the overlay policy already follows, learned the same way.
    ///
    /// A file that is *absent* is a different thing and is allowed: a site that
    /// has enrolled nobody recognises nobody, which is deny-by-default doing
    /// its job rather than a failure.
    pub fn load(text: Option<&str>) -> Result<Self, String> {
        match text {
            None => Ok(Self::default()),
            Some(t) if t.trim().is_empty() => Ok(Self::default()),
            Some(t) => serde_json::from_str(t)
                .map_err(|e| format!("the trust store is present and unreadable: {e}")),
        }
    }

    /// The issuers usable right now, given what the network has confirmed.
    ///
    /// Local issuers are always usable. Global ones drop out when the
    /// revocation list has gone stale — narrowing, never widening, which is the
    /// only safe direction to fail in when you cannot tell whether a credential
    /// has been withdrawn.
    pub fn usable(&self, now: u64) -> Vec<&Issuer> {
        let stale = self.revocations_are_stale(now);
        self.issuers
            .iter()
            .filter(|i| i.level.works_offline() || !stale)
            .collect()
    }

    pub fn revocations_are_stale(&self, now: u64) -> bool {
        match self.revocations_checked_at {
            // Never checked is stale. A site that has never confirmed a
            // revocation list has no evidence about it at all.
            None => true,
            Some(t) => now.saturating_sub(t) > REVOCATION_STALE_AFTER_SECS,
        }
    }

    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revoked.iter().any(|r| r == credential_id)
    }

    /// The machines this site has appraised, ready for a verifier.
    ///
    /// Entries whose key does not parse are dropped rather than failing the
    /// whole store: one bad line should cost that one machine, not every other.
    /// Silently, though, would be wrong — the caller logs the count, and a
    /// machine missing from it fails loudly the first time it calls.
    pub fn device_keys(&self) -> Vec<(String, super::VerifyingKey, bool)> {
        self.usable_now()
            .into_iter()
            .filter(|i| i.kind == Kind::Machine)
            .filter_map(|i| parse_key(&i.key).map(|k| (i.id.clone(), k, i.boot_measured)))
            .collect()
    }

    /// The authorities whose tokens this site will read.
    pub fn issuer_keys(
        &self,
    ) -> std::collections::BTreeMap<String, (super::VerifyingKey, Level)> {
        self.usable_now()
            .into_iter()
            .filter(|i| i.kind == Kind::Issuer)
            .filter_map(|i| parse_key(&i.key).map(|k| (i.id.clone(), (k, i.level))))
            .collect()
    }

    /// Every entry, with its level carried through.
    ///
    /// Staleness is deliberately NOT applied here. These builders run once when
    /// the process starts, so narrowing at this point would answer for the
    /// moment of startup and never again. The level travels with the key and
    /// the verifier decides per request, which is the only place a clock means
    /// anything.
    fn usable_now(&self) -> Vec<&Issuer> {
        self.issuers.iter().collect()
    }

    /// Whether this site can recognise anyone at all without a network.
    ///
    /// False means every remote request refuses, whatever it carries. That is
    /// the correct state for a machine nobody has enrolled an operator on, and
    /// it should be loud rather than quiet.
    pub fn has_a_local_root(&self) -> bool {
        self.issuers.iter().any(|i| i.level == Level::Local)
    }
}

fn parse_key(hex_key: &str) -> Option<super::VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim()).ok()?.try_into().ok()?;
    super::VerifyingKey::from_bytes(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal issuer for these tests.
    ///
    /// Written out rather than derived from Default: an entry with no key and
    /// no stated reason is exactly what this type exists to make impossible,
    /// and adding Default to get it in a test would put that constructor in
    /// everybody's reach.
    fn an_issuer(id: &str) -> Issuer {
        Issuer {
            id: id.to_string(),
            level: Level::Local,
            key: "aa".repeat(32),
            reason: "for a test".into(),
            kind: Kind::Machine,
            boot_measured: false,
        }
    }

    #[test]
    fn a_withdrawn_issuer_is_no_longer_trusted_and_the_rest_are_untouched() {
        let mut t = TrustStore {
            issuers: vec![
                an_issuer("furcate:node:a"),
                an_issuer("furcate:node:b"),
            ],
            ..Default::default()
        };
        let gone = t.withdraw("furcate:node:a").expect("was trusted");
        assert_eq!(gone.id, "furcate:node:a");
        assert_eq!(t.issuers.len(), 1);
        assert_eq!(t.issuers[0].id, "furcate:node:b");
        // Twice is not an error: an operator removing a node again has not
        // done anything wrong the second time.
        assert!(t.withdraw("furcate:node:a").is_none());
    }

    #[test]
    fn a_saved_store_reads_back_the_same() {
        let dir = std::env::temp_dir().join(format!("furcate-trust-{}", std::process::id()));
        let path = dir.join("trust.json");
        let _ = std::fs::remove_dir_all(&dir);

        let t = TrustStore {
            issuers: vec![an_issuer("furcate:node:a")],
            ..Default::default()
        };
        t.save(&path).expect("saves");
        let text = std::fs::read_to_string(&path).expect("reads");
        let back = TrustStore::load(Some(&text)).expect("parses");
        assert_eq!(back.issuers.len(), 1);
        assert_eq!(back.issuers[0].id, "furcate:node:a");

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn store(checked: Option<u64>) -> TrustStore {
        TrustStore {
            issuers: vec![
                Issuer {
                    id: "site:this".into(),
                    level: Level::Local,
                    key: "aa".into(),
                    reason: "this cluster's own root".into(),
                    kind: Kind::Issuer,
                    boot_measured: false,
                },
                Issuer {
                    id: "did:example:something".into(),
                    level: Level::Global,
                    key: "bb".into(),
                    reason: "the network's identity service".into(),
                    kind: Kind::Issuer,
                    boot_measured: false,
                },
            ],
            revoked: vec!["cred:gone".into()],
            revocations_checked_at: checked,
        }
    }

    #[test]
    fn the_local_level_works_with_nothing_answering() {
        // The property being protected: losing the network must never cost an
        // operator the ability to administer their own machines.
        let s = store(None);
        let usable = s.usable(1_000_000);
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0].level, Level::Local);
        assert!(s.has_a_local_root());
    }

    #[test]
    fn a_stale_revocation_list_narrows_the_global_level_and_never_the_local() {
        let fresh = store(Some(1_000_000));
        assert_eq!(fresh.usable(1_000_000).len(), 2, "both, while the list is current");

        let stale = store(Some(1_000_000));
        let much_later = 1_000_000 + REVOCATION_STALE_AFTER_SECS + 1;
        let usable = stale.usable(much_later);
        assert_eq!(usable.len(), 1, "global drops out");
        assert_eq!(usable[0].level, Level::Local, "local never does");
    }

    #[test]
    fn never_having_checked_counts_as_stale() {
        // No evidence about a revocation list is not the same as evidence that
        // nothing is revoked.
        assert!(store(None).revocations_are_stale(0));
    }

    #[test]
    fn an_absent_store_recognises_nobody_and_is_not_an_error() {
        // Deny by default doing its job. A site that has enrolled nobody
        // recognises nobody.
        let s = TrustStore::load(None).expect("absent is allowed");
        assert!(s.issuers.is_empty());
        assert!(!s.has_a_local_root());
        assert!(TrustStore::load(Some("   ")).is_ok());
    }

    #[test]
    fn a_present_but_unreadable_store_is_fatal_rather_than_ignored() {
        // Falling through to defaults would restore authority an operator wrote
        // down a decision to remove, and an unreadable file is not evidence
        // they changed their mind.
        assert!(TrustStore::load(Some("{ not json")).is_err());
    }

    #[test]
    fn a_revoked_credential_stays_revoked_with_no_network() {
        // Revocations only narrow, which is why acting on a stale list is safe
        // and ignoring one never is.
        let s = store(None);
        assert!(s.is_revoked("cred:gone"));
        assert!(!s.is_revoked("cred:fine"));
    }

    #[test]
    fn the_store_round_trips_so_an_operator_can_read_what_they_signed_up_to() {
        let s = store(Some(5));
        let text = serde_json::to_string_pretty(&s).unwrap();
        assert_eq!(TrustStore::load(Some(&text)).unwrap(), s);
        assert!(text.contains("reason"), "the reasoning is part of the record");
    }
}
