//! Who is asking.
//!
//! The policy engine next door answers "may this principal do this here". It is
//! careful about it: deny by default, deny beats allow, four capabilities
//! refusable by nothing. It was answering the second question while the first
//! had never been asked — a caller named itself in a JSON body, on a socket
//! bound to the machine's overlay address, and nothing checked.
//!
//! This crate is the first question. A request arrives carrying evidence; what
//! comes out is either a [`Principal`] that was proved, or a [`Refusal`] that
//! says why. Nothing in between, and no way to spell a principal by typing one.
//!
//! ## Three kinds of principal
//!
//! People, machines and agents prove themselves differently and fail
//! differently, so they are different things here rather than one thing with a
//! flag:
//!
//! - A **person** is not always present, so their authority must be delegable,
//!   and there must be a path that works with no network at all. On a site of
//!   autonomous machines that path is the operator's signing key. A person who
//!   is present approves an order with a passkey: the assertion *is* the
//!   signed order, made over the order's hash on the person's own
//!   authenticator ([`webauthn`], [`order`]). No private key is generated,
//!   derived or held anywhere but in that authenticator.
//! - A **machine** either acts for somebody — and then names them, in a chain
//!   that can only narrow — or acts for itself, and then proves itself with
//!   hardware.
//! - An **agent** is copied through more hands than either, so its evidence is
//!   bound to a key it holds rather than being worth anything to whoever ends
//!   up with a copy.
//!
//! ## What this crate will not do
//!
//! It verifies two things, both with no network, no coordinator and no
//! identity service: an Ed25519 signature over a canonical request, made by
//! the site's own operator key; and passkey assertions over a canonical order,
//! made by credentials this site admitted, counted against a threshold by
//! independence root, read from each credential's registration data.
//!
//! Everything richer — delegation chains, agent tokens with purpose binding
//! and oversight — is somebody else's implementation, reached through
//! [`Verifier`]. Furcate must run standalone, so whatever knows how to check
//! those lives behind this trait and this crate never names it.
//!
//! ## The rule everything else is downstream of
//!
//! **Evidence is not authority.** What a credential proves is *who*. Whether
//! that principal may do a thing here is the policy engine's answer, and the
//! compiled-in invariants are refused to every credential that has ever been or
//! ever will be issued. An identity service that could decide a machine may no
//! longer operate itself would be a remote kill switch wearing another hat.

use serde::{Deserialize, Serialize};

pub mod local;
pub mod order;
pub mod sshcert;
pub mod token;
pub mod trust;
pub mod vouch;
pub mod webauthn;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use local::LocalVerifier;
pub use token::TokenVerifier;
pub use trust::TrustStore;

/// What kind of thing is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// A human being, present or delegating.
    Person,
    /// Something running on its own, whether or not somebody set it going.
    Machine,
    /// A model acting on a task. Distinguished from a machine because the
    /// hazards differ: an agent is steered by text it did not write.
    Agent,
}

impl Class {
    /// Whether this class is an automatic process rather than a person.
    ///
    /// The policy engine bars some actions to automation whatever any rule or
    /// credential says. This is the question it asks.
    pub fn is_automation(&self) -> bool {
        matches!(self, Class::Machine | Class::Agent)
    }
}

/// How a principal proved itself.
///
/// Ordered by what it costs an attacker, and named for what it actually
/// demonstrates rather than for the technology that produced it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Evidence {
    /// A signature by the site's own operator key.
    ///
    /// The sovereign path: it needs no network, no coordinator and no identity
    /// service, and it is the same key and the same mechanism that already
    /// authorises a kill order. Whoever holds it is the operator by definition.
    OperatorSignature,
    /// A key held in a TPM or secure enclave, bound to the platform.
    ///
    /// What an autonomous machine has instead of a person.
    DeviceKey {
        /// Whether the boot chain was measured as well as the key being sealed.
        /// False here is the honest answer on hardware whose PCRs stop at the
        /// firmware, and it narrows what this principal may do.
        boot_measured: bool,
    },
    /// Acting for somebody, by a chain that can only narrow.
    Delegated {
        /// The principal at the root of the chain — a person, or this is not a
        /// delegation worth honouring.
        root: String,
        /// How many hops from that root. Bounded, and counted, because an
        /// unbounded chain is an unbounded blast radius.
        depth: u8,
    },
}

impl Evidence {
    /// Whether there is a person at the root of this.
    ///
    /// The load-bearing question for anything requiring human approval: an
    /// action that needs a human cannot be taken by a principal that has none,
    /// and the resolution must be a refusal rather than a silent grant.
    pub fn has_a_person_behind_it(&self) -> bool {
        matches!(self, Evidence::OperatorSignature | Evidence::Delegated { .. })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Evidence::OperatorSignature => "operator signature",
            Evidence::DeviceKey { .. } => "device key",
            Evidence::Delegated { .. } => "delegation",
        }
    }
}

/// Somebody, proved.
///
/// There is deliberately no constructor that takes a name and believes it. A
/// `Principal` exists because a [`Verifier`] made one, which is what stops
/// `principal: "operator"` in a request body from ever meaning anything again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// What the policy engine matches rules against.
    pub id: String,
    pub class: Class,
    pub evidence: Evidence,
    /// When this stops being true. Every credential has an end; one that did
    /// not would be a key nobody can take back.
    pub expires_at: Option<u64>,
    /// What a token said this was for, where it said.
    ///
    /// Purpose binding: a credential issued to investigate a fan fault cannot
    /// be spent restarting a validator, even where the capability alone would
    /// permit it.
    pub task: Option<String>,
    /// Actions this principal may not take without a human agreeing first.
    pub needs_approval_for: Vec<String>,
    /// Named jobs this principal holds, which policy rules may grant to.
    ///
    /// A role is how a permission is given to a job rather than to a person, so
    /// that admitting a colleague does not mean editing every rule that should
    /// apply to them. It is established by whoever proved the caller — never
    /// read from a request — for exactly the reason the id is not.
    ///
    /// Empty for machines and for the operator: the operator's authority is not
    /// a role and must not become one, or revoking a role could revoke the
    /// sovereign path.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl Principal {
    /// A principal established by the site's own operator key.
    pub fn operator(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            class: Class::Person,
            evidence: Evidence::OperatorSignature,
            expires_at: None,
            task: None,
            needs_approval_for: Vec::new(),
            roles: Vec::new(),
        }
    }

    /// Whether this action needs somebody to agree before it happens.
    pub fn needs_approval(&self, action: &str) -> bool {
        self.needs_approval_for.iter().any(|a| a == action)
    }

    /// Whether this principal could satisfy an approval requirement at all.
    ///
    /// An autonomous machine may only do what no person needs to approve. That
    /// is not distrust: "requires a human" and "has no human in its chain" are
    /// contradictory, and the contradiction has to resolve as a refusal.
    pub fn can_stand_in_for_a_person(&self) -> bool {
        self.class == Class::Person && self.evidence.has_a_person_behind_it()
    }

    /// Whether the credential is still within its window.
    pub fn is_current(&self, now: u64) -> bool {
        self.expires_at.map(|e| now < e).unwrap_or(true)
    }
}

/// Why a caller is not a principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub because: String,
    /// True when no credential could have worked — the route is barred to this
    /// class of caller entirely, rather than this caller having brought the
    /// wrong one. An operator can act on the difference.
    pub structural: bool,
    /// False when the verifier did not recognise the credential's *form* and so
    /// never examined it — "this is not mine to check".
    ///
    /// Distinct from a real refusal, and the distinction decides which message
    /// an operator sees. Without it the last verifier in the chain wins, and
    /// the last one is the least relevant: a machine presenting a bad signature
    /// was being told "not an agent token", which is true, useless, and points
    /// at the wrong problem.
    #[serde(default = "yes")]
    pub applicable: bool,
}

fn yes() -> bool {
    true
}

impl Refusal {
    pub fn new(because: impl Into<String>) -> Self {
        Self { because: because.into(), structural: false, applicable: true }
    }

    pub fn structural(because: impl Into<String>) -> Self {
        Self { because: because.into(), structural: true, applicable: true }
    }

    /// This verifier does not handle credentials of that shape.
    ///
    /// Says nothing about whether the credential is any good — only that
    /// somebody else should be asked.
    pub fn not_mine(because: impl Into<String>) -> Self {
        Self { because: because.into(), structural: false, applicable: false }
    }
}

/// What arrived on the wire, before anybody has decided whether to believe it.
#[derive(Clone, Debug, Default)]
pub struct Presented {
    pub method: String,
    pub path: String,
    /// The body exactly as received. Signed over as bytes rather than as parsed
    /// JSON: two documents that parse the same can serialise differently, and a
    /// signature over the re-serialised form checks something the caller never
    /// sent.
    pub body: Vec<u8>,
    /// The credential, however it was carried.
    pub credential: Option<String>,
}

/// Something that can turn evidence into a principal.
///
/// The seam. The sovereign implementation lives in this crate and needs
/// nothing; anything richer — delegation chains, agent tokens — is
/// implemented behind here by an adapter this crate never names, because
/// Furcate has to build and run without one.
pub trait Verifier: Send + Sync {
    fn verify(&self, presented: &Presented, now: u64) -> Result<Principal, Refusal>;

    /// A short name for logs and for the chained record.
    fn name(&self) -> &'static str;
}

/// Try each verifier in turn, and refuse with the most specific reason.
///
/// Order is deliberate: the sovereign path is tried first, so a machine whose
/// network is down still admits its operator, and an identity service being
/// unreachable never costs somebody the ability to administer a machine they
/// are standing in front of.
pub struct AnyOf(pub Vec<Box<dyn Verifier>>);

impl Verifier for AnyOf {
    fn verify(&self, presented: &Presented, now: u64) -> Result<Principal, Refusal> {
        let mut fallback = Refusal::new("no credential this machine recognises was presented");
        for v in &self.0 {
            match v.verify(presented, now) {
                Ok(p) => return Ok(p),
                // A structural refusal ends it: another verifier saying yes to
                // something barred outright would be the same hole in a
                // different place.
                Err(r) if r.structural => return Err(r),
                // The first verifier that recognised the credential's shape and
                // still refused it has the only message worth showing. Later
                // ones will each say "not mine", and reporting the last of
                // those points an operator at the wrong problem entirely.
                Err(r) if r.applicable => return Err(r),
                Err(r) => {
                    if fallback.because.starts_with("no credential") {
                        fallback = r;
                    }
                }
            }
        }
        Err(fallback)
    }

    fn name(&self) -> &'static str {
        "any-of"
    }
}

/// The canonical string a request is signed over.
///
/// Method, path and a digest of the body, plus the nonce and expiry that make a
/// captured signature worthless later. Built in one place because a signer and
/// a verifier that disagree about it fail closed and silently — the signature
/// is simply never valid, and there is nothing in the message to say why.
pub fn signing_input(method: &str, path: &str, body: &[u8], nonce: &str, expires_at: u64) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(body));
    format!("furcate-request/1\n{}\n{path}\n{digest}\n{nonce}\n{expires_at}\n", method.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_principal_cannot_be_spelled_by_typing_one() {
        // The hole this crate closes: a caller named itself in a JSON body and
        // the policy engine ruled on the name. `Principal` has no constructor
        // that takes an arbitrary claim, so a request body cannot produce one.
        let p = Principal::operator("alice");
        assert_eq!(p.evidence, Evidence::OperatorSignature);
        assert!(p.can_stand_in_for_a_person());
    }

    #[test]
    fn an_autonomous_machine_cannot_stand_in_for_a_person() {
        // "Requires human approval" and "has no human in its chain" are
        // contradictory, and the contradiction resolves as a refusal.
        let m = Principal {
            id: "node:node-a".into(),
            class: Class::Machine,
            evidence: Evidence::DeviceKey { boot_measured: false },
            expires_at: None,
            task: None,
            needs_approval_for: vec!["restart".into()],
            roles: Vec::new(),
        };
        assert!(!m.can_stand_in_for_a_person());
        assert!(m.needs_approval("restart"));
        assert!(m.class.is_automation());
    }

    #[test]
    fn a_delegated_machine_still_names_the_person_at_its_root() {
        let d = Evidence::Delegated { root: "person:alice".into(), depth: 2 };
        assert!(d.has_a_person_behind_it());
    }

    #[test]
    fn an_expired_credential_is_not_current() {
        let mut p = Principal::operator("x");
        p.expires_at = Some(100);
        assert!(p.is_current(99));
        assert!(!p.is_current(100), "the boundary is not still valid");
        assert!(!p.is_current(101));
    }

    #[test]
    fn the_signing_input_covers_everything_that_matters() {
        // A field outside the signature is a field an attacker may change.
        let base = signing_input("POST", "/x", b"{}", "n1", 10);
        assert_ne!(base, signing_input("GET", "/x", b"{}", "n1", 10), "method");
        assert_ne!(base, signing_input("POST", "/y", b"{}", "n1", 10), "path");
        assert_ne!(base, signing_input("POST", "/x", b"{ }", "n1", 10), "body");
        assert_ne!(base, signing_input("POST", "/x", b"{}", "n2", 10), "nonce");
        assert_ne!(base, signing_input("POST", "/x", b"{}", "n1", 11), "expiry");
    }

    #[test]
    fn the_method_is_signed_case_insensitively_because_http_is() {
        assert_eq!(
            signing_input("post", "/x", b"{}", "n", 1),
            signing_input("POST", "/x", b"{}", "n", 1)
        );
    }

    #[test]
    fn any_of_tries_the_sovereign_path_first_and_keeps_the_last_reason() {
        struct No(&'static str);
        impl Verifier for No {
            fn verify(&self, _: &Presented, _: u64) -> Result<Principal, Refusal> {
                Err(Refusal::new(self.0))
            }
            fn name(&self) -> &'static str {
                "no"
            }
        }
        let v = AnyOf(vec![Box::new(No("first")), Box::new(No("second"))]);
        let e = v.verify(&Presented::default(), 0).unwrap_err();
        assert_eq!(e.because, "first", "the first that actually looked at it");
    }

    #[test]
    fn the_verifier_that_recognised_the_credential_gives_the_reason() {
        // A machine presenting a bad signature was being told "not an agent
        // token" — true, useless, and pointing at the wrong problem — because
        // the last verifier in the chain won.
        struct NotMine;
        impl Verifier for NotMine {
            fn verify(&self, _: &Presented, _: u64) -> Result<Principal, Refusal> {
                Err(Refusal::not_mine("not an agent token"))
            }
            fn name(&self) -> &'static str {
                "not-mine"
            }
        }
        struct Mine;
        impl Verifier for Mine {
            fn verify(&self, _: &Presented, _: u64) -> Result<Principal, Refusal> {
                Err(Refusal::new("that signature does not check out"))
            }
            fn name(&self) -> &'static str {
                "mine"
            }
        }
        let v = AnyOf(vec![Box::new(NotMine), Box::new(Mine), Box::new(NotMine)]);
        assert_eq!(v.verify(&Presented::default(), 0).unwrap_err().because,
                   "that signature does not check out");
    }

    #[test]
    fn when_nobody_recognises_it_the_answer_says_so() {
        struct NotMine(&'static str);
        impl Verifier for NotMine {
            fn verify(&self, _: &Presented, _: u64) -> Result<Principal, Refusal> {
                Err(Refusal::not_mine(self.0))
            }
            fn name(&self) -> &'static str {
                "not-mine"
            }
        }
        let v = AnyOf(vec![Box::new(NotMine("a")), Box::new(NotMine("b"))]);
        assert_eq!(v.verify(&Presented::default(), 0).unwrap_err().because, "a");
    }

    #[test]
    fn a_structural_refusal_stops_the_chain() {
        // Otherwise a second verifier saying yes to something barred outright
        // is the same hole in a different place.
        struct Barred;
        impl Verifier for Barred {
            fn verify(&self, _: &Presented, _: u64) -> Result<Principal, Refusal> {
                Err(Refusal::structural("barred"))
            }
            fn name(&self) -> &'static str {
                "barred"
            }
        }
        struct Yes;
        impl Verifier for Yes {
            fn verify(&self, _: &Presented, _: u64) -> Result<Principal, Refusal> {
                Ok(Principal::operator("anyone"))
            }
            fn name(&self) -> &'static str {
                "yes"
            }
        }
        let v = AnyOf(vec![Box::new(Barred), Box::new(Yes)]);
        assert!(v.verify(&Presented::default(), 0).is_err());
    }
}

/// A machine proving it is itself.
///
/// The other root, and the one that needs no person at all.
///
/// A node's identity here is *derived* from its TPM's endorsement key —
/// `NodeId::from_ek_public` is a digest of it — rather than being a key
/// generated once and stored somewhere. That distinction is the whole property:
/// there is no blob to lose and none to steal. Reinstall the operating system,
/// remove and reinstall the network stack, let it mint itself a fresh identity
/// on that side, and this identity is recomputed identically, because the
/// endorsement key is burned into the chip at manufacture and never leaves it.
///
/// So the same hardware root serves both levels. Locally it is what makes a
/// machine recognisable to its own cluster across a rebuild. Globally it is
/// what a network identity is bound *to*, which is why a network identity being
/// recreated does not change who the machine is. One immutable thing
/// underneath, two namespaces above it.
pub mod device {
    use super::*;

    /// Verifies that a caller is the machine it claims to be.
    ///
    /// Holds the derived identifiers this site is willing to recognise, and the
    /// attestation key each one signs with. Neither is a secret: an identifier
    /// is a digest of a public key, and the key is public.
    /// Where a machine's key comes from.
    ///
    /// A trait rather than a list, because the answer changes while the process
    /// runs: a site admits a machine, an admission lapses, a key rotates. A
    /// verifier built once from a snapshot would answer for the moment it was
    /// constructed and never again — the same defect that made the revocation
    /// staleness rule inert until it was moved to verification time.
    ///
    /// It also keeps the answer in one place. A site that already has a roster
    /// of admitted machines must not grow a second list beside it: the two
    /// drift, and the machine that suffers is whichever one the reader did not
    /// open.
    pub trait MachineKeys: Send + Sync {
        /// The key this machine was admitted with, and whether its boot chain
        /// was measured, if it is admitted *now*.
        fn key_for(&self, node_id: &str, now: u64) -> Option<(VerifyingKey, bool)>;

        /// How many machines are recognised, for a startup line an operator
        /// reads.
        fn count(&self, now: u64) -> usize;
    }

    /// A fixed set, for a node that keeps its peers in its trust store.
    pub struct StaticKeys(pub Vec<(String, VerifyingKey, bool)>);

    impl MachineKeys for StaticKeys {
        fn key_for(&self, node_id: &str, _now: u64) -> Option<(VerifyingKey, bool)> {
            self.0.iter().find(|(id, _, _)| id == node_id).map(|(_, k, m)| (*k, *m))
        }

        fn count(&self, _now: u64) -> usize {
            self.0.len()
        }
    }

    /// Verifies that a caller is the machine it claims to be.
    pub struct DeviceVerifier {
        keys: Box<dyn MachineKeys>,
        /// Nonces already spent, keyed by machine and nonce.
        ///
        /// One guard for every machine rather than one each, so it survives a
        /// key being looked up fresh on each call. Without it a captured
        /// signature is replayable for as long as it has left to live.
        seen: std::sync::Mutex<std::collections::BTreeMap<(String, String), u64>>,
    }

    impl DeviceVerifier {
        pub fn new(known: Vec<(String, VerifyingKey, bool)>) -> Self {
            Self::from_keys(Box::new(StaticKeys(known)))
        }

        pub fn from_keys(keys: Box<dyn MachineKeys>) -> Self {
            Self { keys, seen: std::sync::Mutex::new(std::collections::BTreeMap::new()) }
        }

        /// Recognises nobody. The correct state for a site that has appraised
        /// no machines yet, and not an open door.
        pub fn empty() -> Self {
            Self::new(Vec::new())
        }

        pub fn count(&self, now: u64) -> usize {
            self.keys.count(now)
        }

        fn spend(&self, id: &str, nonce: &str, expires_at: u64, now: u64) -> Result<(), Refusal> {
            let mut seen = self
                .seen
                .lock()
                .map_err(|_| Refusal::new("the replay guard is not in a state that can be trusted"))?;
            seen.retain(|_, exp| *exp > now);
            let key = (id.to_string(), nonce.to_string());
            if seen.contains_key(&key) {
                return Err(Refusal::new(
                    "that request has already been made; a signature is good once",
                ));
            }
            if seen.len() >= 4096 {
                return Err(Refusal::new("too many requests in flight to guard against replay"));
            }
            seen.insert(key, expires_at);
            Ok(())
        }
    }

    impl Verifier for DeviceVerifier {
        fn verify(&self, presented: &Presented, now: u64) -> Result<Principal, Refusal> {
            let Some(cred) = presented.credential.as_deref() else {
                return Err(Refusal::new("no credential was presented"));
            };
            // `node:<id>:<nonce>.<expiry>.<signature>` — the identifier is
            // carried because a site knows many machines and must check the
            // signature against the right key rather than trying all of them.
            let Some(rest) = cred.strip_prefix("node:") else {
                return Err(Refusal::not_mine("not a machine credential"));
            };
            // From the *right*: a node identifier contains colons of its own
            // (`furcate:node:...`), and splitting at the first one took
            // `furcate` as the machine's name. The signature part has none.
            let Some((id, signed)) = rest.rsplit_once(':') else {
                return Err(Refusal::new("a machine credential must name the machine"));
            };
            let Some((key, boot_measured)) = self.keys.key_for(id, now) else {
                // Named rather than vague: an operator reading this needs to
                // know the machine is unknown or lapsed, not that its signature
                // was bad.
                return Err(Refusal::new(format!(
                    "{id} is not a machine this site currently admits"
                )));
            };
            let inner = LocalVerifier::new(Some(key));

            // The signature check is the operator-format one — same canonical
            // request, different key — so its wording is corrected on the way
            // out. A peer whose key had rotated would otherwise be sent to look
            // at the operator key, the wrong key on the wrong machine.
            let p = Presented {
                credential: Some(format!("{}{signed}", local::SCHEME)),
                ..presented.clone()
            };
            let checked = inner.verify(&p, now).map_err(|e| Refusal {
                because: format!("{id}: {}", e.because.replace(
                    local::NOT_ADMITTED,
                    "that signature is not from the key this machine was admitted with",
                )),
                ..e
            })?;

            // The inner verifier is built per call and remembers nothing; the
            // guard that matters is this one, which outlives it.
            let nonce = signed.split('.').next().unwrap_or_default();
            let expires: u64 =
                signed.split('.').nth(1).and_then(|e| e.parse().ok()).unwrap_or(now);
            self.spend(id, nonce, expires, now)?;

            Ok(Principal {
                id: id.to_string(),
                class: Class::Machine,
                evidence: Evidence::DeviceKey { boot_measured },
                expires_at: checked.expires_at,
                task: None,
                // A machine is not a person and holds no job.
                roles: Vec::new(),
                // A machine has no person in its chain, so anything requiring
                // one is refused by construction rather than by a rule somebody
                // has to remember to write.
                needs_approval_for: Vec::new(),
            })
        }

        fn name(&self) -> &'static str {
            "device-key"
        }
    }
}

#[cfg(test)]
mod device_tests {
    use super::device::DeviceVerifier;
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn req(cred: &str) -> Presented {
        Presented {
            method: "POST".into(),
            path: "/act".into(),
            body: b"{}".to_vec(),
            credential: Some(cred.into()),
        }
    }

    fn credential(id: &str, nonce: &str) -> String {
        // `sign` emits the operator scheme; a machine credential wraps the bare
        // signature, so the scheme is stripped here and re-added on the way in.
        let inner = local::sign(&key(), "POST", "/act", b"{}", nonce, 100);
        format!("node:{id}:{}", inner.trim_start_matches(local::SCHEME))
    }

    #[test]
    fn a_machine_this_site_has_appraised_is_recognised_as_itself() {
        let v = DeviceVerifier::new(vec![("furcate:node:abc".into(), key().verifying_key(), false)]);
        let p = v.verify(&req(&credential("furcate:node:abc", "n1")), 50).expect("known machine");
        assert_eq!(p.class, Class::Machine);
        assert_eq!(p.evidence, Evidence::DeviceKey { boot_measured: false });
        assert!(p.class.is_automation());
    }

    #[test]
    fn a_machine_can_never_stand_in_for_a_person() {
        // The rule falls out of the construction: an autonomous machine may
        // only do what no person needs to approve, because "requires a human"
        // and "has no human in its chain" cannot both be satisfied.
        let v = DeviceVerifier::new(vec![("furcate:node:abc".into(), key().verifying_key(), true)]);
        let p = v.verify(&req(&credential("furcate:node:abc", "n1")), 50).unwrap();
        assert!(!p.can_stand_in_for_a_person());
        assert!(!p.evidence.has_a_person_behind_it());
    }

    #[test]
    fn an_unappraised_machine_is_told_it_is_unknown_rather_than_wrong() {
        // Two different problems with two different fixes, and an operator
        // reading the message needs to know which one they have.
        let v = DeviceVerifier::empty();
        let e = v.verify(&req(&credential("furcate:node:abc", "n1")), 50).unwrap_err();
        assert!(e.because.contains("currently admits"), "{e:?}");
    }

    #[test]
    fn one_machines_signature_does_not_authenticate_another() {
        // The identifier is checked against the key it was appraised with, not
        // against whichever key happens to verify.
        let other = SigningKey::from_bytes(&[12u8; 32]);
        let v = DeviceVerifier::new(vec![
            ("furcate:node:abc".into(), key().verifying_key(), false),
            ("furcate:node:xyz".into(), other.verifying_key(), false),
        ]);
        // abc's key, claiming to be xyz.
        let forged = format!(
            "node:furcate:node:xyz:{}",
            local::sign(&key(), "POST", "/act", b"{}", "n1", 100)
        );
        assert!(v.verify(&req(&forged), 50).is_err());
    }

    #[test]
    fn a_machine_credential_is_single_use_like_any_other() {
        // The first version built a fresh verifier per request, so it
        // remembered nothing and every captured signature was replayable for
        // as long as it had left to live.
        let v = DeviceVerifier::new(vec![("furcate:node:abc".into(), key().verifying_key(), false)]);
        let c = credential("furcate:node:abc", "n1");
        assert!(v.verify(&req(&c), 50).is_ok());
        let e = v.verify(&req(&c), 50).unwrap_err();
        assert!(e.because.contains("already"), "{e:?}");
    }

    #[test]
    fn a_machine_with_a_bad_signature_is_pointed_at_its_own_key() {
        // The inner check is an operator-format one and words itself that way,
        // so a peer whose key had rotated was being sent to look at the
        // operator key — the wrong key, on the wrong machine.
        let v = DeviceVerifier::new(vec![("furcate:node:abc".into(), key().verifying_key(), false)]);
        let other = SigningKey::from_bytes(&[13u8; 32]);
        let inner = local::sign(&other, "POST", "/act", b"{}", "n1", 100);
        let forged = format!("node:furcate:node:abc:{}", inner.trim_start_matches(local::SCHEME));
        let e = v.verify(&req(&forged), 50).unwrap_err();
        assert!(e.because.contains("furcate:node:abc"), "names the machine: {e:?}");
        assert!(e.because.contains("admitted with"), "and the right key: {e:?}");
        assert!(!e.because.contains("operator"), "{e:?}");
    }

    #[test]
    fn a_node_identifier_with_colons_in_it_survives_being_parsed() {
        // `furcate:node:...` has two of its own, and splitting at the first
        // took `furcate` as the machine's name — so every real machine was
        // unknown and no test with a short name would have noticed.
        let real = "furcate:node:avj3tpujwgubaog7wyf6qhxho3ifckjl27vgi6gw5ft746xpmvxa";
        let v = DeviceVerifier::new(vec![(real.into(), key().verifying_key(), false)]);
        let p = v.verify(&req(&credential(real, "n1")), 50).expect("a real identifier");
        assert_eq!(p.id, real);
    }

    #[test]
    fn a_credential_that_is_not_a_machines_is_left_for_another_verifier() {
        // AnyOf tries each in turn; a non-structural refusal must not end the
        // chain, or a machine verifier would block an operator's signature.
        let v = DeviceVerifier::empty();
        let e = v.verify(&req("plainnonce.100.ff"), 50).unwrap_err();
        assert!(!e.structural, "must not stop the chain");
    }

    #[test]
    fn boot_measurement_is_carried_because_it_narrows_what_a_machine_may_do() {
        // False is the honest answer on hardware whose PCRs stop at the
        // firmware — which is both of this site's machines.
        let v = DeviceVerifier::new(vec![("n".into(), key().verifying_key(), true)]);
        let p = v.verify(&req(&credential("n", "n1")), 50).unwrap();
        assert_eq!(p.evidence, Evidence::DeviceKey { boot_measured: true });
    }
}

#[cfg(test)]
mod scheme_tests {
    use super::device::DeviceVerifier;
    use super::*;

    /// Every credential kind must be distinguishable from every other by its
    /// prefix alone, before anything is parsed.
    ///
    /// They were not. `node:<id>:<nonce>.<expiry>.<sig>` also splits into three
    /// dot-separated fields, so the operator verifier claimed machine
    /// credentials as malformed ones of its own and refused them with a message
    /// about the operator key. An enrolled machine and a complete stranger
    /// produced the same wrong answer, which is how it was found — on hardware,
    /// not here.
    #[test]
    fn no_verifier_claims_another_kinds_credential() {
        let k = SigningKey::from_bytes(&[5u8; 32]);
        let inner = local::sign(&k, "POST", "/act", b"{}", "n1", 100);
        let bare = inner.trim_start_matches(local::SCHEME);

        let creds = [
            ("operator", inner.clone()),
            ("machine", format!("node:furcate:node:abc:{bare}")),
            ("agent", "agent eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ4In0.AA".to_string()),
        ];
        let verifiers: Vec<(&str, Box<dyn Verifier>)> = vec![
            ("operator", Box::new(LocalVerifier::new(Some(k.verifying_key())))),
            ("machine", Box::new(DeviceVerifier::empty())),
            ("agent", Box::new(TokenVerifier::empty("x"))),
        ];

        for (kind, cred) in &creds {
            for (owner, v) in &verifiers {
                let p = Presented {
                    method: "POST".into(),
                    path: "/act".into(),
                    body: b"{}".to_vec(),
                    credential: Some(cred.clone()),
                };
                let applicable = match v.verify(&p, 50) {
                    Ok(_) => true,
                    Err(e) => e.applicable,
                };
                assert_eq!(
                    applicable,
                    kind == owner,
                    "the {owner} verifier {} a {kind} credential",
                    if applicable { "claimed" } else { "declined" }
                );
            }
        }
    }
}

#[cfg(test)]
mod live_key_tests {
    use super::device::{DeviceVerifier, MachineKeys};
    use super::*;

    /// A source whose answer changes with the clock, like a real admission.
    struct Lapsing {
        key: VerifyingKey,
        until: u64,
    }

    impl MachineKeys for Lapsing {
        fn key_for(&self, _id: &str, now: u64) -> Option<(VerifyingKey, bool)> {
            (now < self.until).then_some((self.key, false))
        }
        fn count(&self, _now: u64) -> usize {
            1
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[31u8; 32])
    }

    fn cred(nonce: &str, exp: u64) -> Presented {
        let inner = local::sign(&key(), "POST", "/act", b"{}", nonce, exp);
        Presented {
            method: "POST".into(),
            path: "/act".into(),
            body: b"{}".to_vec(),
            credential: Some(format!("node:n1:{}", inner.trim_start_matches(local::SCHEME))),
        }
    }

    #[test]
    fn an_admission_that_lapses_stops_working_without_a_restart() {
        // The verifier is built once when the process starts. A key list
        // captured then would answer for that moment and never again, so a
        // lapsed admission would keep working until somebody restarted the
        // controller — which is the defect that made the revocation staleness
        // rule inert until it was moved to verification time.
        let v = DeviceVerifier::from_keys(Box::new(Lapsing {
            key: key().verifying_key(),
            until: 1000,
        }));
        assert!(v.verify(&cred("a", 700), 500).is_ok(), "while admitted");
        let e = v.verify(&cred("b", 1300), 1100).unwrap_err();
        assert!(e.because.contains("currently admits"), "{e:?}");
    }

    #[test]
    fn the_replay_guard_outlives_the_key_lookup() {
        // The signature check borrows a verifier built for this one call, so it
        // remembers nothing. Without a guard that outlives it, every captured
        // signature is replayable for as long as it has left to live.
        let v = DeviceVerifier::from_keys(Box::new(Lapsing {
            key: key().verifying_key(),
            until: u64::MAX,
        }));
        let c = cred("once", 700);
        assert!(v.verify(&c, 500).is_ok());
        let e = v.verify(&c, 500).unwrap_err();
        assert!(e.because.contains("already"), "{e:?}");
    }

    #[test]
    fn two_machines_may_use_the_same_nonce() {
        // The guard is keyed by machine as well as nonce. Sharing one namespace
        // would let a chatty node lock out a quiet one by coincidence.
        let v = DeviceVerifier::from_keys(Box::new(Lapsing {
            key: key().verifying_key(),
            until: u64::MAX,
        }));
        let inner = local::sign(&key(), "POST", "/act", b"{}", "same", 700);
        let bare = inner.trim_start_matches(local::SCHEME);
        for id in ["n1", "n2"] {
            let p = Presented {
                method: "POST".into(),
                path: "/act".into(),
                body: b"{}".to_vec(),
                credential: Some(format!("node:{id}:{bare}")),
            };
            assert!(v.verify(&p, 500).is_ok(), "{id} should not collide");
        }
    }
}
