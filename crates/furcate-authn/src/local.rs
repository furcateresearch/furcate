//! The path that works when nothing else does.
//!
//! A request signed by the site's own operator key, verified against the public
//! half this machine already holds. No network, no coordinator, no identity
//! service, no clock beyond the machine's own.
//!
//! This is deliberately the *first* thing tried and the last thing that can
//! fail. Losing the network must never cost an operator the ability to
//! administer a machine they are standing in front of — that property is the
//! product, and everything richer is a convenience layered on top of it.
//!
//! It reuses the key that already authorises a kill order. There is no second
//! operator key and no new secret on disk: a machine that can be told to stop
//! is a machine that can be told to restart a container, and inventing a
//! separate authority for the smaller act would mean two things to protect.

use crate::{Class, Evidence, Presented, Principal, Refusal, Verifier, signing_input};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// How far ahead a signature may claim to be valid.
///
/// A caller signs with an expiry; this bounds how long that may be, so a
/// signature captured off the wire is worth something for seconds rather than
/// for as long as whoever made it decided. Long enough for a slow link, short
/// enough that a recording is not a credential.
pub const MAX_VALIDITY_SECS: u64 = 300;

/// How many spent nonces to remember.
///
/// The window only has to outlive `MAX_VALIDITY_SECS`, since a signature older
/// than that is refused on its expiry alone. Bounded because an unbounded set
/// is a way to run a machine out of memory by talking to it.
const NONCES_KEPT: usize = 4096;

/// Somebody this site admits alongside the operator.
///
/// A teammate holds their OWN key and their OWN identity. They are not handed
/// the operator key and they do not act as the operator — every decision they
/// make is recorded under their own name, and withdrawing them is deleting one
/// entry rather than rotating the key the whole site depends on.
///
/// Roles are what a rule grants to, so admitting a colleague is adding a line
/// here rather than editing every rule that should apply to them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    /// What decisions are recorded under. Prefixed `person:` by convention so a
    /// name can never be confused with `operator` or with a node id.
    pub id: String,
    /// Ed25519 public key, hex. Same format as every other key this site reads.
    pub key: String,
    /// Named jobs, matched by rules written as `role:<name>`.
    #[serde(default)]
    pub roles: Vec<String>,
    /// When this admission lapses. Required, and deliberately so: the roster
    /// that went stale on this cluster did it by having entries nobody had a
    /// reason to revisit. An admission with no end is a permanent grant wearing
    /// a temporary label.
    pub valid_until: u64,
    /// Why, in the operator's words. Carried because a roster nobody can read
    /// the reasoning of is one nobody dares remove an entry from.
    #[serde(default)]
    pub reason: String,
}

impl Person {
    fn verifying_key(&self) -> Option<VerifyingKey> {
        let b: [u8; 32] = hex::decode(self.key.trim()).ok()?.try_into().ok()?;
        VerifyingKey::from_bytes(&b).ok()
    }
}

/// The people this site admits, as read from disk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct People {
    #[serde(default)]
    pub people: Vec<Person>,
}

impl People {
    /// Read a roster, dropping entries that have already lapsed.
    ///
    /// Absent is ordinary and means "nobody but the operator". Unreadable is
    /// treated the same way rather than fatally: the operator path must keep
    /// working when a convenience file is malformed, or a typo in a roster
    /// becomes an outage of the only way to fix it.
    pub fn load(text: Option<&str>, now: u64) -> Self {
        let Some(t) = text else { return Self::default() };
        match serde_json::from_str::<People>(t) {
            Ok(mut r) => {
                r.people.retain(|p| p.valid_until > now);
                r
            }
            Err(_) => Self::default(),
        }
    }
}

/// Verifies operator-signed requests against a key this machine holds.
pub struct LocalVerifier {
    operator: Option<VerifyingKey>,
    /// People this site admits alongside the operator, each with their own key.
    ///
    /// Held here rather than looked up per request: this verifier must work
    /// with no network and no directory, which is the property the whole local
    /// path exists for.
    people: Vec<Person>,
    /// Nonces already spent, with when they expire so they can be dropped.
    seen: Mutex<BTreeMap<String, u64>>,
    /// What to call whoever holds the key.
    id: String,
}

impl LocalVerifier {
    /// With the operator's public key, if this machine has one.
    ///
    /// `None` is a supported state and not an open door: it means the machine
    /// cannot recognise its operator, so every guarded route refuses. A
    /// controller that invented its own authority when the key was missing
    /// would defeat the whole guarantee — the same reasoning that already
    /// governs the kill switch.
    pub fn new(operator: Option<VerifyingKey>) -> Self {
        Self {
            operator,
            people: Vec::new(),
            seen: Mutex::new(BTreeMap::new()),
            id: "operator".into(),
        }
    }

    /// Admit people alongside the operator.
    ///
    /// Separate from `new` so the operator path is constructed the same way it
    /// always was: a site with no roster behaves exactly as before, and the
    /// sovereign path cannot be affected by anything that goes wrong here.
    pub fn with_people(mut self, people: Vec<Person>) -> Self {
        self.people = people;
        self
    }

    /// How many people this site admits, for the startup line.
    pub fn admitted(&self) -> usize {
        self.people.len()
    }

    /// Read the operator key from the path this site keeps it at.
    ///
    /// Hex-encoded 32 bytes, the same format the kill switch already reads —
    /// one file, one format, one thing to get right.
    pub fn from_key_file(path: &std::path::Path) -> Self {
        let key = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| hex::decode(raw.trim()).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok());
        Self::new(key)
    }

    /// Read a people roster from disk, dropping lapsed entries.
    ///
    /// Absent, unreadable and malformed all mean the same thing here — nobody
    /// but the operator — and none of them is fatal. The operator path has to
    /// keep working when a convenience file is wrong, or a typo in the roster
    /// takes out the only way to correct it.
    pub fn with_people_file(self, path: &std::path::Path, now: u64) -> Self {
        let text = std::fs::read_to_string(path).ok();
        let roster = People::load(text.as_deref(), now);
        if text.is_some() && roster.people.is_empty() {
            eprintln!(
                "furcate: WARNING {} exists but admits nobody — malformed, or every entry has lapsed",
                path.display()
            );
        }
        self.with_people(roster.people)
    }

    pub fn knows_its_operator(&self) -> bool {
        self.operator.is_some()
    }

    /// Record a nonce, refusing one already spent.
    fn spend(&self, nonce: &str, expires_at: u64, now: u64) -> Result<(), Refusal> {
        let mut seen = self.seen.lock().map_err(|_| {
            // A poisoned lock means a previous verification panicked. Failing
            // closed is the only safe reading of that.
            Refusal::new("the replay guard is not in a state that can be trusted")
        })?;
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(nonce) {
            return Err(Refusal::new(
                "that request has already been made; a signature is good once",
            ));
        }
        if seen.len() >= NONCES_KEPT {
            // Refuse rather than forget. Dropping the oldest to make room is
            // how an attacker with a signature and some patience gets a second
            // use out of it.
            return Err(Refusal::new("too many requests in flight to guard against replay"));
        }
        seen.insert(nonce.to_string(), expires_at);
        Ok(())
    }
}

/// The scheme every operator credential carries.
///
/// Each kind of credential names itself, because the shapes overlap otherwise.
/// A machine credential is `node:<id>:<nonce>.<expiry>.<signature>`, which also
/// splits into three dot-separated fields — so an unprefixed operator format
/// claimed machine credentials as its own and refused them with the wrong
/// message. Found on hardware, where an enrolled machine and a total stranger
/// were both told their signature was not the operator's.
pub const SCHEME: &str = "op:";

/// What this verifier says when no key it holds made the signature.
///
/// A named constant because `DeviceVerifier` rewrites it into a machine-facing
/// version, and it did so by matching the literal text. When the wording here
/// changed, that match silently stopped firing and a peer with a rotated key
/// was sent back to the generic message again — the exact bug the rewrite was
/// added to fix, reintroduced by an edit nowhere near it. Two copies of one
/// sentence is a coupling; one constant is not.
pub const NOT_ADMITTED: &str = "that signature is not from a key this site admits";

/// A credential as it is carried: `op:nonce.expiry.signature`.
///
/// Fields joined by dots rather than JSON, because this rides in a header and
/// has to survive being copied through a shell by somebody debugging.
fn split_credential(cred: &str) -> Option<(&str, u64, Vec<u8>)> {
    let mut parts = cred.strip_prefix(SCHEME)?.split('.');
    let nonce = parts.next()?;
    let expires_at: u64 = parts.next()?.parse().ok()?;
    let sig = hex::decode(parts.next()?).ok()?;
    if parts.next().is_some() || nonce.is_empty() {
        return None;
    }
    Some((nonce, expires_at, sig))
}

impl Verifier for LocalVerifier {
    fn verify(&self, presented: &Presented, now: u64) -> Result<Principal, Refusal> {
        let Some(key) = self.operator else {
            return Err(Refusal::structural(
                "this machine has no operator key, so it cannot recognise anyone; \
                 install one with `furcatectl operator enrol`",
            ));
        };
        let Some(cred) = presented.credential.as_deref() else {
            return Err(Refusal::new("no credential was presented"));
        };
        let Some((nonce, expires_at, sig)) = split_credential(cred) else {
            // Somebody else's shape, not a malformed one of ours: a machine or
            // an agent credential reaches this verifier first and must fall
            // through with its own message intact.
            return Err(Refusal::not_mine("the credential is not an operator signature"));
        };

        // Expiry before signature: a stale request should be cheap to refuse,
        // and the arithmetic gives nothing away.
        if expires_at <= now {
            return Err(Refusal::new("that request has expired"));
        }
        if expires_at.saturating_sub(now) > MAX_VALIDITY_SECS {
            return Err(Refusal::new(format!(
                "a request may not be valid for more than {MAX_VALIDITY_SECS} seconds"
            )));
        }

        let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
            return Err(Refusal::new("the signature is the wrong length"));
        };
        let input = signing_input(
            &presented.method,
            &presented.path,
            &presented.body,
            nonce,
            expires_at,
        );
        let signature = Signature::from_bytes(&sig);

        // The operator first, always. This is the path that must keep working
        // when everything else is broken, so nothing may be tried ahead of it.
        if key.verify_strict(input.as_bytes(), &signature).is_ok() {
            // Spent only after the signature checks out, so an unsigned request
            // cannot burn a nonce somebody else was about to use.
            self.spend(nonce, expires_at, now)?;
            return Ok(Principal {
                id: self.id.clone(),
                class: Class::Person,
                evidence: Evidence::OperatorSignature,
                expires_at: Some(expires_at),
                task: None,
                needs_approval_for: Vec::new(),
                // Deliberately none. The operator's authority is not a role and
                // must not become one — a role can be revoked, and revoking the
                // sovereign path is precisely what must never be possible.
                roles: Vec::new(),
            });
        }

        // Then whoever else this site admits.
        //
        // Each teammate signs with their OWN key and is recorded under their
        // OWN name — they never act as the operator. That is the difference
        // between delegation and impersonation, and it is the whole reason this
        // exists rather than handing somebody a copy of the operator key: an
        // action taken here says who took it, and withdrawing them is deleting
        // one line rather than rotating the key the site depends on.
        //
        // Linear over a handful of entries. An Ed25519 verification is tens of
        // microseconds and this list is people, not machines; indexing it by
        // key would mean the credential naming which key to try, which is a
        // caller choosing how it is authenticated.
        for person in &self.people {
            if person.valid_until <= now {
                continue;
            }
            let Some(pk) = person.verifying_key() else { continue };
            if pk.verify_strict(input.as_bytes(), &signature).is_ok() {
                self.spend(nonce, expires_at, now)?;
                return Ok(Principal {
                    id: person.id.clone(),
                    class: Class::Person,
                    // Rooted at the operator, one hop. Honest about where the
                    // authority came from, and it keeps `has_a_person_behind_it`
                    // true so a teammate can approve what needs a human.
                    evidence: Evidence::Delegated { root: "operator".into(), depth: 1 },
                    // The earlier of the request's expiry and the admission's:
                    // a credential must not outlive the roster entry behind it.
                    expires_at: Some(expires_at.min(person.valid_until)),
                    task: None,
                    needs_approval_for: Vec::new(),
                    roles: person.roles.clone(),
                });
            }
        }

        // Deliberately one message for every way this fails, whether the key
        // was wrong or simply nobody's. Which part did not match is information
        // an attacker can use to search.
        Err(Refusal::new(NOT_ADMITTED))
    }

    fn name(&self) -> &'static str {
        "operator-signature"
    }
}

/// Holds the operator's private key and signs requests with it.
///
/// Lives beside the verifier so both halves of the protocol are written in one
/// place. A signer and a verifier that disagree about the canonical form fail
/// closed and silently — the signature is simply never valid, and nothing in
/// the message says why.
pub struct Signer {
    key: ed25519_dalek::SigningKey,
    /// How long each signature is good for. Short: it only has to survive the
    /// round trip.
    validity_secs: u64,
}

impl Signer {
    pub fn new(key: ed25519_dalek::SigningKey) -> Self {
        Self { key, validity_secs: 60 }
    }

    /// Read the operator's private key from disk.
    pub fn from_key_file(path: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read_to_string(path).ok()?;
        let bytes: [u8; 32] = hex::decode(raw.trim()).ok()?.try_into().ok()?;
        Some(Self::new(ed25519_dalek::SigningKey::from_bytes(&bytes)))
    }

    /// A credential for one request, good once and briefly.
    pub fn credential(&self, method: &str, path: &str, body: &[u8], now: u64) -> String {
        // A nonce that is unique per request without needing a random source or
        // shared state: the key never signs the same (nonce, request) twice
        // because time moves, and the counter distinguishes two in one second.
        let nonce = format!("{now:x}-{:x}", COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        sign(&self.key, method, path, body, &nonce, now + self.validity_secs)
    }
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A machine signing as itself.
///
/// The same canonical request and the same signature as an operator makes; only
/// the key differs and the machine names itself, because a site knows many and
/// must check against the right key rather than trying all of them.
pub struct MachineSigner {
    id: String,
    signer: Signer,
}

impl MachineSigner {
    pub fn new(id: impl Into<String>, key: ed25519_dalek::SigningKey) -> Self {
        Self { id: id.into(), signer: Signer::new(key) }
    }

    /// A credential for one request, good once and briefly.
    pub fn credential(&self, method: &str, path: &str, body: &[u8], now: u64) -> String {
        let inner = self.signer.credential(method, path, body, now);
        format!("node:{}:{}", self.id, inner.trim_start_matches(SCHEME))
    }
}

/// Sign a request as the operator. The other half of the same rule.
pub fn sign(
    key: &ed25519_dalek::SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &str,
    expires_at: u64,
) -> String {
    use ed25519_dalek::Signer;
    let input = signing_input(method, path, body, nonce, expires_at);
    let sig = key.sign(input.as_bytes());
    format!("{SCHEME}{nonce}.{expires_at}.{}", hex::encode(sig.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An operator signature made by the CLI must verify at the site.
    ///
    /// Written because a signed call was refused with "that signature is not
    /// from a key this site admits" while the sealed key on the box derived to
    /// exactly the public key in operator.pub. Both halves were right, so the
    /// fault had to be in what the two sides sign over.
    #[test]
    fn a_signature_the_signer_made_verifies_against_the_same_key() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let signer = Signer::new(key);

        let body = br#"{"node_id":"furcate:node:probe"}"#;
        let now = 1_700_000_000;
        let cred = signer.credential("POST", "/roster/withdraw", body, now);

        let raw: [u8; 32] = hex::decode(&public).unwrap().try_into().unwrap();
        let v = LocalVerifier::new(Some(VerifyingKey::from_bytes(&raw).unwrap()));
        let presented = Presented {
            method: "POST".into(),
            path: "/roster/withdraw".into(),
            body: body.to_vec(),
            credential: Some(cred),
        };
        match v.verify(&presented, now + 1) {
            Ok(p) => assert_eq!(p.evidence, Evidence::OperatorSignature),
            Err(e) => panic!("a signature this key just made was refused: {e:?}"),
        }
    }

    use ed25519_dalek::SigningKey;

    fn keypair() -> (SigningKey, VerifyingKey) {
        // Fixed bytes: a test that generates a key tests the generator too, and
        // this one is about the protocol.
        let k = SigningKey::from_bytes(&[7u8; 32]);
        let v = k.verifying_key();
        (k, v)
    }

    fn req(body: &str) -> Presented {
        Presented {
            method: "POST".into(),
            path: "/workloads/restart".into(),
            body: body.as_bytes().to_vec(),
            credential: None,
        }
    }

    #[test]
    fn a_request_signed_by_the_operator_is_the_operator() {
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        let p = v.verify(&r, 50).expect("the operator's own signature");
        assert_eq!(p.evidence, Evidence::OperatorSignature);
        assert!(p.can_stand_in_for_a_person());
    }

    fn teammate() -> (SigningKey, Person) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let person = Person {
            id: "person:ana".into(),
            key: hex::encode(sk.verifying_key().to_bytes()),
            roles: vec!["oncall".into()],
            valid_until: 10_000,
            reason: "carries the pager this week".into(),
        };
        (sk, person)
    }

    #[test]
    fn an_admitted_person_is_recognised_under_their_own_name() {
        // The point of the whole mechanism: they act as THEMSELVES, carrying
        // their own roles — not as the operator wearing a different hat.
        let (_, vk) = keypair();
        let (sk, person) = teammate();
        let v = LocalVerifier::new(Some(vk)).with_people(vec![person]);
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        let p = v.verify(&r, 50).expect("an admitted teammate");
        assert_eq!(p.id, "person:ana");
        assert_eq!(p.roles, vec!["oncall".to_string()]);
        assert_ne!(p.evidence, Evidence::OperatorSignature, "a teammate is not the operator");
        // Still a person, so they can approve what needs a human.
        assert!(p.can_stand_in_for_a_person());
    }

    #[test]
    fn the_operator_still_works_and_still_carries_no_roles() {
        // The sovereign path must be untouched by anything above. If admitting
        // people could give the operator a role, revoking that role could take
        // away the one path that has to keep working.
        let (sk, vk) = keypair();
        let (_, person) = teammate();
        let v = LocalVerifier::new(Some(vk)).with_people(vec![person]);
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        let p = v.verify(&r, 50).expect("the operator");
        assert_eq!(p.id, "operator");
        assert_eq!(p.evidence, Evidence::OperatorSignature);
        assert!(p.roles.is_empty(), "the operator's authority is not a role");
    }

    #[test]
    fn a_lapsed_admission_recognises_nobody() {
        let (_, vk) = keypair();
        let (sk, mut person) = teammate();
        person.valid_until = 40; // already over at now=50
        let v = LocalVerifier::new(Some(vk)).with_people(vec![person]);
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        assert!(v.verify(&r, 50).is_err(), "an expired admission must not authenticate");
    }

    #[test]
    fn a_credential_cannot_outlive_the_admission_behind_it() {
        // A request may be signed valid for five minutes; if the admission ends
        // in one, the principal ends in one. Otherwise withdrawing somebody
        // leaves credentials in flight that still work.
        let (_, vk) = keypair();
        let (sk, mut person) = teammate();
        person.valid_until = 70;
        let v = LocalVerifier::new(Some(vk)).with_people(vec![person]);
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        let p = v.verify(&r, 50).expect("still admitted at 50");
        assert_eq!(p.expires_at, Some(70), "capped by the admission, not the request");
    }

    #[test]
    fn a_key_nobody_admitted_is_refused_without_saying_why() {
        let (_, vk) = keypair();
        let (_, person) = teammate();
        let stranger = SigningKey::from_bytes(&[3u8; 32]);
        let v = LocalVerifier::new(Some(vk)).with_people(vec![person]);
        let mut r = req("{}");
        r.credential = Some(sign(&stranger, &r.method, &r.path, &r.body, "n1", 100));
        let e = v.verify(&r, 50).unwrap_err();
        // One message however it failed — which key did not match is something
        // an attacker can search with.
        assert!(!e.structural, "{e:?}");
    }

    #[test]
    fn a_lapsed_entry_is_dropped_at_load() {
        let text = r#"{"people":[
            {"id":"person:ana","key":"aa","roles":["oncall"],"valid_until":10000,"reason":"here"},
            {"id":"person:bo","key":"bb","roles":[],"valid_until":10,"reason":"gone"}
        ]}"#;
        let r = People::load(Some(text), 50);
        assert_eq!(r.people.len(), 1);
        assert_eq!(r.people[0].id, "person:ana");
    }

    #[test]
    fn a_malformed_roster_is_empty_rather_than_fatal() {
        // A typo in a convenience file must not take out the only path that can
        // fix it. Absent and unreadable both mean "nobody but the operator".
        assert!(People::load(Some("{not json"), 0).people.is_empty());
        assert!(People::load(None, 0).people.is_empty());
    }

    #[test]
    fn a_machine_with_no_operator_key_recognises_nobody() {
        // Not an open door and not a soft failure: a controller that invented
        // its own authority when the key was missing would defeat the whole
        // guarantee. Structural, because no credential could have worked.
        let (sk, _) = keypair();
        let v = LocalVerifier::new(None);
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        let e = v.verify(&r, 50).unwrap_err();
        assert!(e.structural, "{e:?}");
    }

    #[test]
    fn a_signature_for_one_request_does_not_authorise_another() {
        // The whole point of signing the request rather than issuing a token: a
        // credential good for reading the inventory is not one for restarting a
        // validator.
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let signed = sign(&sk, "POST", "/workloads/restart", b"{}", "n1", 100);

        for (m, p, b) in [
            ("GET", "/workloads/restart", "{}"),
            ("POST", "/kill", "{}"),
            ("POST", "/workloads/restart", r#"{"id":"other"}"#),
        ] {
            let r = Presented {
                method: m.into(),
                path: p.into(),
                body: b.as_bytes().to_vec(),
                credential: Some(signed.clone()),
            };
            assert!(v.verify(&r, 50).is_err(), "{m} {p} {b} must not be authorised");
        }
    }

    #[test]
    fn the_same_signature_cannot_be_used_twice() {
        // Otherwise anything that can see one request can make it again.
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        assert!(v.verify(&r, 50).is_ok());
        let e = v.verify(&r, 50).unwrap_err();
        assert!(e.because.contains("already"), "{e:?}");
    }

    #[test]
    fn an_expired_request_is_refused_and_the_boundary_is_not_inclusive() {
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        assert!(v.verify(&r, 100).is_err(), "expiry is not still valid");
        assert!(v.verify(&r, 101).is_err());
    }

    #[test]
    fn a_signature_may_not_claim_to_be_valid_forever() {
        // A caller picks its own expiry, so the ceiling has to be here. Without
        // it a captured signature is a credential for as long as whoever made
        // it decided.
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let mut r = req("{}");
        let far = MAX_VALIDITY_SECS + 1000;
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", far));
        let e = v.verify(&r, 0).unwrap_err();
        assert!(e.because.contains("more than"), "{e:?}");
    }

    #[test]
    fn a_signature_from_another_key_is_nobody() {
        let (_, vk) = keypair();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let v = LocalVerifier::new(Some(vk));
        let mut r = req("{}");
        r.credential = Some(sign(&other, &r.method, &r.path, &r.body, "n1", 100));
        assert!(v.verify(&r, 50).is_err());
    }

    #[test]
    fn every_way_of_being_wrong_gives_the_same_answer() {
        // Which part failed is information an attacker can search with.
        let (sk, vk) = keypair();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let v = LocalVerifier::new(Some(vk));

        let mut wrong_key = req("{}");
        wrong_key.credential = Some(sign(&other, "POST", "/workloads/restart", b"{}", "a", 100));
        let mut wrong_body = req(r#"{"id":"x"}"#);
        wrong_body.credential = Some(sign(&sk, "POST", "/workloads/restart", b"{}", "b", 100));

        assert_eq!(
            v.verify(&wrong_key, 50).unwrap_err().because,
            v.verify(&wrong_body, 50).unwrap_err().because
        );
    }

    #[test]
    fn a_malformed_credential_is_refused_rather_than_parsed_hopefully() {
        let (_, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        for bad in [
            "", "op:", "op:no-dots", "op:a.b", "op:a.notanumber.ff", "op:.100.ff",
            "op:a.100.zz", "op:a.100.ff.extra",
            // Another kind's credential, which must fall through rather than be
            // claimed and refused with the wrong reason.
            "node:furcate:node:x:n1.100.ff",
        ] {
            let mut r = req("{}");
            r.credential = Some(bad.into());
            assert!(v.verify(&r, 50).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn an_unsigned_request_cannot_burn_somebody_elses_nonce() {
        // The nonce is spent only after the signature checks out. Otherwise
        // anyone who can reach the socket can lock out a legitimate request by
        // guessing its nonce first.
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let mut forged = req("{}");
        forged.credential = Some(format!("{SCHEME}n1.100.{}", hex::encode([0u8; 64])));
        assert!(v.verify(&forged, 50).is_err());

        let mut real = req("{}");
        real.credential = Some(sign(&sk, &real.method, &real.path, &real.body, "n1", 100));
        assert!(v.verify(&real, 50).is_ok(), "the real request still works");
    }

    #[test]
    fn spent_nonces_are_forgotten_once_nothing_could_replay_them() {
        let (sk, vk) = keypair();
        let v = LocalVerifier::new(Some(vk));
        let mut r = req("{}");
        r.credential = Some(sign(&sk, &r.method, &r.path, &r.body, "n1", 100));
        assert!(v.verify(&r, 50).is_ok());
        // Past the expiry, the record is dead weight and is dropped.
        let mut later = req("{}");
        later.credential = Some(sign(&sk, &later.method, &later.path, &later.body, "n2", 300));
        assert!(v.verify(&later, 250).is_ok());
        assert_eq!(v.seen.lock().unwrap().len(), 1, "the old nonce was dropped");
    }
}
