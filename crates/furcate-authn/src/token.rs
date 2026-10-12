//! Agent tokens, and delegation chains.
//!
//! An agent is the principal class the other two do not cover. It is steered by
//! text it did not write, it is copied through more hands than a person or a
//! machine — a client, a gateway, a tool server, a log — and the interesting
//! question about it is never only "who" but "for what, how deep, and who has
//! to agree first".
//!
//! ## What this reads, and what it deliberately is not
//!
//! The credential is a JWS with EdDSA, carrying the claims the agent
//! authorization profile defines: what the token is *for*, which actions need a
//! human, and where it sits in a delegation chain. That is a standard document
//! format, not a bespoke one, and reading it is not the same as implementing
//! cryptography — the signature check is the Ed25519 verification this crate
//! already does for everything else.
//!
//! **This is not a general JWT library and must never grow into one.** It reads
//! one algorithm, resolves keys from the site's trust store and never from the
//! token, and refuses anything it does not recognise. Every generous thing a
//! JWT library does — algorithm agility, embedded keys, unverified headers — is
//! a documented way in, and each is closed here by construction with a test
//! naming the attack.
//!
//! ## Attenuation
//!
//! A delegation may narrow and never widen. That is checked here rather than
//! trusted, because the whole value of a chain is that holding the child is
//! worth strictly less than holding the parent — and a chain nobody checks is
//! an assertion, not a constraint.

use crate::{Class, Evidence, Presented, Principal, Refusal, Verifier};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How deep a delegation chain may go, whatever a token asserts.
///
/// A bound that lives here rather than in the token, because a token that could
/// raise its own ceiling has no ceiling. Three is a person delegating to a
/// service delegating to an agent, which is as far as anything on this site has
/// a reason to go.
pub const MAX_DEPTH: u8 = 3;

/// The claims this site reads. Anything else in the token is ignored, which is
/// safe only because nothing here is decided by a claim's absence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Who the token is about.
    #[serde(default)]
    pub sub: String,
    /// Who issued it. Resolved against the trust store; a token naming an
    /// issuer this site does not know is refused rather than believed.
    #[serde(default)]
    pub iss: String,
    /// Who it is *for*. A token minted for another audience is not a token for
    /// this machine, however valid its signature.
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub exp: u64,
    #[serde(default)]
    pub nbf: Option<u64>,
    /// Unique id, so a token can be revoked by name.
    #[serde(default)]
    pub jti: Option<String>,
    /// What this token is for. Purpose binding: a credential minted to
    /// investigate a fault may not be spent restarting a validator, even where
    /// the capability alone would allow it.
    #[serde(default)]
    pub aap_task: Option<String>,
    /// Which actions need a human to agree before they happen.
    #[serde(default)]
    pub aap_oversight: Vec<String>,
    /// Where this sits in the chain that produced it.
    #[serde(default)]
    pub aap_delegation: Option<Delegation>,
    /// What the holder may ask for at all.
    #[serde(default)]
    pub aap_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Delegation {
    #[serde(default)]
    pub depth: u8,
    #[serde(default)]
    pub max_depth: u8,
    /// The chain, root first. The root is the principal everything below
    /// answers for.
    #[serde(default)]
    pub chain: Vec<String>,
    /// What the parent held, so a child can be checked against it rather than
    /// taken at its word.
    #[serde(default)]
    pub parent_capabilities: Vec<String>,
}

impl Delegation {
    /// Whether this link holds no more than the one above it.
    ///
    /// The entire value of a chain is that the child is worth strictly less
    /// than the parent. A chain nobody checks is an assertion.
    pub fn narrows(&self, capabilities: &[String]) -> bool {
        if self.parent_capabilities.is_empty() {
            // Nothing stated about the parent means nothing to check against,
            // and a subset of the unknown cannot be established. Refused, not
            // assumed.
            return self.depth == 0;
        }
        capabilities.iter().all(|c| self.parent_capabilities.contains(c))
    }
}

/// Verifies agent tokens against issuers the site already trusts.
pub struct TokenVerifier {
    /// Issuer id to key and level. Resolved from here and never from the token,
    /// which is the single most important line in this file.
    issuers: BTreeMap<String, (VerifyingKey, crate::trust::Level)>,
    /// What this machine answers to, for the audience check.
    audience: String,
    /// Tokens withdrawn by name.
    revoked: Vec<String>,
    /// When the revocation list was last confirmed.
    ///
    /// Checked at verification rather than at construction. The verifiers are
    /// built once when the process starts, so a staleness test done there would
    /// answer for the moment of startup and never again — the rule would be
    /// documented, tested in isolation, and never fire in the running system.
    revocations_checked_at: Option<u64>,
}

impl TokenVerifier {
    pub fn new(
        issuers: BTreeMap<String, (VerifyingKey, crate::trust::Level)>,
        audience: impl Into<String>,
        revoked: Vec<String>,
        revocations_checked_at: Option<u64>,
    ) -> Self {
        Self { issuers, audience: audience.into(), revoked, revocations_checked_at }
    }

    /// Recognises no issuers. The correct state for a site that has enrolled
    /// none, and not an open door.
    pub fn empty(audience: impl Into<String>) -> Self {
        Self::new(BTreeMap::new(), audience, Vec::new(), None)
    }

    /// Whether the withdrawal list is too old to rely on.
    fn revocations_are_stale(&self, now: u64) -> bool {
        match self.revocations_checked_at {
            None => true,
            Some(t) => now.saturating_sub(t) > crate::trust::REVOCATION_STALE_AFTER_SECS,
        }
    }
}

fn b64(part: &str) -> Option<Vec<u8>> {
    // URL-safe, unpadded, as JWS requires. Written out because pulling in a
    // base64 crate for forty lines is a dependency to audit for no gain.
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in part.bytes() {
        let v = T.iter().position(|t| *t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Any leftover bits must be zero, or this is not a canonical encoding and
    // two different strings would decode to the same bytes.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

impl Verifier for TokenVerifier {
    fn verify(&self, presented: &Presented, now: u64) -> Result<Principal, Refusal> {
        let Some(cred) = presented.credential.as_deref() else {
            return Err(Refusal::new("no credential was presented"));
        };
        let Some(raw) = cred.strip_prefix("agent ") else {
            return Err(Refusal::not_mine("not an agent token"));
        };

        let parts: Vec<&str> = raw.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(Refusal::new("an agent token has three parts"));
        }
        let (Some(header), Some(payload), Some(sig)) =
            (b64(parts[0]), b64(parts[1]), b64(parts[2]))
        else {
            return Err(Refusal::new("an agent token must be base64url with no padding"));
        };

        // The header decides only one thing, and it is checked against a fixed
        // expectation rather than being trusted to name an algorithm.
        //
        // This is where the two classic attacks live. `alg: none` asks to skip
        // verification entirely; algorithm confusion asks to verify an
        // asymmetric signature as a symmetric MAC using the public key as the
        // secret. Both are refused by accepting exactly one value. An embedded
        // `jwk` or `kid`-as-URL is ignored for the same reason: a token that
        // supplies the key that checks it checks nothing.
        let header: serde_json::Value = serde_json::from_slice(&header)
            .map_err(|_| Refusal::new("the token header is not readable"))?;
        if header.get("alg").and_then(|a| a.as_str()) != Some("EdDSA") {
            return Err(Refusal::new("this site accepts EdDSA agent tokens and nothing else"));
        }

        let claims: Claims = serde_json::from_slice(&payload)
            .map_err(|_| Refusal::new("the token claims are not readable"))?;

        // Resolved from the site's own store, by name, before the signature is
        // checked — so an unknown issuer costs nothing to refuse.
        let Some((key, level)) = self.issuers.get(&claims.iss) else {
            return Err(Refusal::new(format!(
                "{} is not an issuer this site recognises",
                if claims.iss.is_empty() { "an unnamed issuer" } else { &claims.iss }
            )));
        };

        // A withdrawal list nobody has been able to confirm may be missing the
        // entry that matters. Global issuers drop out; the local level never
        // does, because a local credential is withdrawn by editing the store,
        // which needs no network to be true. Narrowing, never widening — the
        // only safe direction to fail when you cannot tell whether a credential
        // has been taken back.
        if *level == crate::trust::Level::Global && self.revocations_are_stale(now) {
            return Err(Refusal::new(
                "this site has not been able to confirm withdrawals recently, so it is \
                 not accepting tokens from the wider network",
            ));
        }

        let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
            return Err(Refusal::new("the signature is the wrong length"));
        };
        let signed = format!("{}.{}", parts[0], parts[1]);
        key.verify_strict(signed.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| Refusal::new("that token was not signed by the issuer it names"))?;

        // Everything below here is claim semantics, and every one of them is a
        // way a validly-signed token still must not be honoured.
        if claims.exp <= now {
            return Err(Refusal::new("that token has expired"));
        }
        if let Some(nbf) = claims.nbf {
            if now < nbf {
                return Err(Refusal::new("that token is not valid yet"));
            }
        }
        if let Some(jti) = &claims.jti {
            if self.revoked.iter().any(|r| r == jti) {
                return Err(Refusal::new("that token has been withdrawn"));
            }
        }
        // A token minted for another audience is not a token for this machine,
        // however valid its signature. Absent is refused rather than treated as
        // "any": a token that names no audience is one somebody forgot to
        // bind, and honouring it here makes this machine the soft target.
        match claims.aud.as_deref() {
            Some(a) if a == self.audience => {}
            Some(a) => {
                return Err(Refusal::new(format!("that token was issued for {a}, not for this machine")))
            }
            None => return Err(Refusal::new("that token names no audience")),
        }

        let delegation = claims.aap_delegation.clone().unwrap_or_default();
        if delegation.depth > MAX_DEPTH {
            return Err(Refusal::new(format!(
                "that delegation is {} deep and this site allows {MAX_DEPTH}",
                delegation.depth
            )));
        }
        // A token may lower its own ceiling and never raise it.
        if delegation.max_depth > MAX_DEPTH {
            return Err(Refusal::new("a token may not raise this site's delegation ceiling"));
        }
        if !delegation.narrows(&claims.aap_capabilities) {
            return Err(Refusal::new(
                "that token claims more than the delegation above it held",
            ));
        }

        // The root of the chain is who this ultimately answers for. Without one
        // there is nobody to answer for it, and it is treated as autonomous —
        // which is not a downgrade, but it does mean anything needing a human
        // is refused.
        let root = delegation.chain.first().cloned();
        let evidence = match &root {
            Some(r) => Evidence::Delegated { root: r.clone(), depth: delegation.depth },
            None => Evidence::DeviceKey { boot_measured: false },
        };

        Ok(Principal {
            id: claims.sub.clone(),
            class: Class::Agent,
            evidence,
            expires_at: Some(claims.exp),
            task: claims.aap_task.clone(),
            needs_approval_for: claims.aap_oversight.clone(),
            // An agent holds a grant, not a job. Letting a token name its own
            // roles would let the bearer widen itself, which is the whole thing
            // delegation is built to prevent.
            roles: Vec::new(),
        })
    }

    fn name(&self) -> &'static str {
        "agent-token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn b64e(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            let take = chunk.len() + 1;
            for i in 0..take {
                out.push(T[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            }
        }
        out
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn token_with(header: serde_json::Value, claims: serde_json::Value, k: &SigningKey) -> String {
        let h = b64e(header.to_string().as_bytes());
        let p = b64e(claims.to_string().as_bytes());
        let sig = k.sign(format!("{h}.{p}").as_bytes());
        format!("agent {h}.{p}.{}", b64e(&sig.to_bytes()))
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "agent:ops",
            "iss": "site:this",
            "aud": "furcate:node:abc",
            "exp": 1000,
            "jti": "t1",
            "aap_task": "restart mainnet-nginx-1",
            "aap_oversight": ["restart"],
            "aap_capabilities": ["restart"],
            "aap_delegation": {"depth": 1, "max_depth": 2, "chain": ["person:alice"],
                               "parent_capabilities": ["restart", "drain"]}
        })
    }

    fn verifier() -> TokenVerifier {
        TokenVerifier::new(
            [("site:this".to_string(), (key().verifying_key(), crate::trust::Level::Local))].into(),
            "furcate:node:abc",
            vec!["revoked-one".into()],
            None,
        )
    }

    fn present(cred: &str) -> Presented {
        Presented {
            method: "POST".into(),
            path: "/act".into(),
            body: b"{}".to_vec(),
            credential: Some(cred.into()),
        }
    }

    fn good() -> String {
        token_with(serde_json::json!({"alg": "EdDSA", "typ": "JWT"}), claims(), &key())
    }

    #[test]
    fn a_token_from_a_known_issuer_names_an_agent_and_what_it_is_for() {
        let p = verifier().verify(&present(&good()), 500).expect("a good token");
        assert_eq!(p.class, Class::Agent);
        assert_eq!(p.id, "agent:ops");
        assert_eq!(p.task.as_deref(), Some("restart mainnet-nginx-1"));
        assert!(p.needs_approval("restart"));
        assert_eq!(p.evidence, Evidence::Delegated { root: "person:alice".into(), depth: 1 });
    }

    #[test]
    fn alg_none_does_not_skip_verification() {
        // The oldest JWT attack. Accepting exactly one algorithm closes it.
        let t = token_with(serde_json::json!({"alg": "none"}), claims(), &key());
        let e = verifier().verify(&present(&t), 500).unwrap_err();
        assert!(e.because.contains("EdDSA"), "{e:?}");
    }

    #[test]
    fn an_asymmetric_token_cannot_be_checked_as_a_symmetric_one() {
        // Algorithm confusion: verify an RSA/EdDSA signature as an HMAC using
        // the public key as the shared secret. Refused for the same reason.
        for alg in ["HS256", "RS256", "ES256", "EdDSA "] {
            let t = token_with(serde_json::json!({"alg": alg}), claims(), &key());
            assert!(verifier().verify(&present(&t), 500).is_err(), "{alg} must be refused");
        }
    }

    #[test]
    fn a_token_that_supplies_its_own_key_checks_nothing() {
        // An embedded `jwk`, or a `kid` pointing somewhere. The key is resolved
        // from this site's store by issuer name and never from the token.
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        let t = token_with(
            serde_json::json!({
                "alg": "EdDSA",
                "jwk": {"kty": "OKP", "x": b64e(attacker.verifying_key().as_bytes())},
                "kid": "https://attacker.example/key"
            }),
            claims(),
            &attacker,
        );
        assert!(verifier().verify(&present(&t), 500).is_err());
    }

    #[test]
    fn an_unknown_issuer_is_refused_before_any_signature_is_checked() {
        let mut c = claims();
        c["iss"] = serde_json::json!("site:somewhere-else");
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        let e = verifier().verify(&present(&t), 500).unwrap_err();
        assert!(e.because.contains("recognises"), "{e:?}");
    }

    #[test]
    fn a_token_for_another_machine_is_not_a_token_for_this_one() {
        let mut c = claims();
        c["aud"] = serde_json::json!("furcate:node:somebody-else");
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        assert!(verifier().verify(&present(&t), 500).is_err());
    }

    #[test]
    fn a_token_with_no_audience_is_refused_rather_than_treated_as_any() {
        // A token nobody bound is one somebody forgot to bind, and honouring it
        // makes this machine the soft target in a fleet.
        let mut c = claims();
        c["aud"] = serde_json::Value::Null;
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        let e = verifier().verify(&present(&t), 500).unwrap_err();
        assert!(e.because.contains("no audience"), "{e:?}");
    }

    #[test]
    fn expiry_and_not_before_are_both_honoured() {
        let v = verifier();
        assert!(v.verify(&present(&good()), 1000).is_err(), "the boundary is not still valid");
        assert!(v.verify(&present(&good()), 1001).is_err());

        let mut c = claims();
        c["nbf"] = serde_json::json!(900);
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        assert!(verifier().verify(&present(&t), 800).is_err(), "not yet valid");
        assert!(verifier().verify(&present(&t), 950).is_ok());
    }

    #[test]
    fn a_withdrawn_token_is_refused_by_name() {
        let mut c = claims();
        c["jti"] = serde_json::json!("revoked-one");
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        let e = verifier().verify(&present(&t), 500).unwrap_err();
        assert!(e.because.contains("withdrawn"), "{e:?}");
    }

    #[test]
    fn a_child_may_not_claim_more_than_its_parent_held() {
        // The entire value of a chain: holding the child is worth strictly less
        // than holding the parent, and a chain nobody checks is an assertion.
        let mut c = claims();
        c["aap_capabilities"] = serde_json::json!(["restart", "kill"]);
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        let e = verifier().verify(&present(&t), 500).unwrap_err();
        assert!(e.because.contains("more than"), "{e:?}");
    }

    #[test]
    fn a_token_may_not_raise_this_sites_delegation_ceiling() {
        // A ceiling a token can set is not a ceiling.
        let mut c = claims();
        c["aap_delegation"]["max_depth"] = serde_json::json!(99);
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        assert!(verifier().verify(&present(&t), 500).is_err());

        let mut deep = claims();
        deep["aap_delegation"]["depth"] = serde_json::json!(MAX_DEPTH + 1);
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), deep, &key());
        assert!(verifier().verify(&present(&t), 500).is_err());
    }

    #[test]
    fn a_chain_with_no_stated_parent_is_only_valid_at_the_root() {
        // A subset of the unknown cannot be established, so it is refused
        // rather than assumed.
        let mut c = claims();
        c["aap_delegation"] = serde_json::json!({"depth": 2, "chain": ["person:x"]});
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        assert!(verifier().verify(&present(&t), 500).is_err());
    }

    #[test]
    fn an_agent_with_nobody_behind_it_cannot_satisfy_its_own_oversight() {
        // No chain means no person to answer for it. Not a downgrade, but
        // anything needing a human is then refused by construction.
        let mut c = claims();
        c["aap_delegation"] = serde_json::json!({"depth": 0});
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        let p = verifier().verify(&present(&t), 500).unwrap();
        assert!(!p.can_stand_in_for_a_person());
        assert!(p.needs_approval("restart"), "and it still requires one");
    }

    #[test]
    fn a_tampered_payload_does_not_verify() {
        let good = good();
        let mut parts: Vec<&str> = good.trim_start_matches("agent ").split('.').collect();
        let forged = b64e(
            serde_json::json!({"sub": "agent:ops", "iss": "site:this", "aud": "furcate:node:abc",
                               "exp": 99999, "aap_capabilities": ["kill"]})
            .to_string()
            .as_bytes(),
        );
        parts[1] = &forged;
        let t = format!("agent {}", parts.join("."));
        assert!(verifier().verify(&present(&t), 500).is_err());
    }

    #[test]
    fn a_malformed_token_is_refused_rather_than_parsed_hopefully() {
        for bad in ["agent ", "agent a.b", "agent a.b.c.d", "agent !!.??.$$", "agent A.B.C"] {
            assert!(verifier().verify(&present(bad), 500).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_non_canonical_encoding_is_refused() {
        // Two strings decoding to the same bytes is a way to make one token
        // look like two, which defeats revocation by name.
        assert!(b64("QQ").is_some());
        assert!(b64("QR").is_none(), "leftover bits must be zero");
    }

    #[test]
    fn a_stale_withdrawal_list_stops_tokens_from_the_wider_network_and_not_the_local_one() {
        // Checked at verification, not at construction: the verifiers are built
        // once when the process starts, so a test done there would answer for
        // that moment and never again.
        let global = TokenVerifier::new(
            [("site:this".to_string(), (key().verifying_key(), crate::trust::Level::Global))].into(),
            "furcate:node:abc",
            vec![],
            Some(500),
        );
        assert!(global.verify(&present(&good()), 600).is_ok(), "while the list is current");
        let much_later = 500 + crate::trust::REVOCATION_STALE_AFTER_SECS + 1;
        let mut c = claims();
        c["exp"] = serde_json::json!(much_later + 100);
        let t = token_with(serde_json::json!({"alg": "EdDSA"}), c, &key());
        let e = global.verify(&present(&t), much_later).unwrap_err();
        assert!(e.because.contains("wider network"), "{e:?}");

        // The local level is unaffected, whatever the clock says.
        assert!(verifier().verify(&present(&good()), 500).is_ok());
    }

    #[test]
    fn a_site_with_no_issuers_recognises_no_agent() {
        let v = TokenVerifier::empty("furcate:node:abc");
        assert!(v.verify(&present(&good()), 500).is_err());
    }

    #[test]
    fn something_that_is_not_an_agent_token_is_left_for_another_verifier() {
        // AnyOf tries each in turn, so this must not be structural or an agent
        // verifier would block an operator's signature.
        let e = verifier().verify(&present("n1.100.ff"), 500).unwrap_err();
        assert!(!e.structural);
    }
}
