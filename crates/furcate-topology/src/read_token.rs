//! A cell manager's read of the tree, from a passkey.
//!
//! A person who manages a cell holds a passkey, not a machine key, and a
//! passkey signs only a WebAuthn assertion over a challenge. So a read is two
//! steps. The manager asks a node for a read token: who they are
//! (`passkey:<rp id>:<credential id>`), the scope to read and when the token
//! ends. The node answers a challenge whose first 32 bytes are the hash of
//! exactly that request, the manager's authenticator signs it, and the node
//! verifies the assertion against the credential the site admitted, the way
//! it verifies an order's approval. It then signs a token naming the request,
//! good for minutes, for GET `/cells` and nothing else.
//!
//! The token names the credential and is checked again at every use against
//! the credential's own manager link, so a link that lapses or is revoked
//! takes every token issued under it with it, and the token never reaches
//! further than the link.

use furcate_authn::webauthn::{verify_assertion, Assertion, Challenge, Credential};
use furcate_authn::{Class, Evidence, Presented, Principal, Refusal, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cell::{CellKey, CellTree, Scope};

/// The longest a read token lasts. A read is something somebody is doing
/// now; a token that outlived the sitting would be a standing credential.
pub const MAX_READ_SECS: u64 = 900;

/// How the token travels, in `x-furcate-credential`.
pub const SCHEME: &str = "cellread:";

/// The paths a read token reaches.
pub const READ_PATHS: [&str; 2] = ["/cells", "/cells/view"];

/// What the manager asks for, and what the challenge commits to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub site: String,
    /// `passkey:<rp id>:<credential id>`, as the manager's link names them.
    pub holder: String,
    pub scope: Scope,
    pub not_after: u64,
    /// Hex, drawn by the node, so two requests never hash alike.
    pub nonce: String,
}

impl ReadRequest {
    /// What the challenge's first 32 bytes are.
    pub fn hash(&self) -> [u8; 32] {
        let mut m = b"furcate:cell-read-request:v1\0".to_vec();
        for f in [&self.site, &self.holder, &self.scope.as_string(), &self.not_after.to_string(), &self.nonce] {
            m.extend_from_slice(&(f.len() as u64).to_be_bytes());
            m.extend_from_slice(f.as_bytes());
        }
        Sha256::digest(&m).into()
    }

    /// The credential id and RP ID the holder names.
    fn credential(&self) -> Result<(&str, &str), String> {
        let parts: Vec<&str> = self.holder.splitn(3, ':').collect();
        match parts.as_slice() {
            ["passkey", rp, id] if !rp.is_empty() && !id.is_empty() => Ok((rp, id)),
            _ => Err(format!("`{}` is not `passkey:<rp id>:<credential id>`", self.holder)),
        }
    }
}

/// A read token: the request, and this node's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadToken {
    pub request: ReadRequest,
    /// The node that verified the assertion, as [`CellKey`] names its key.
    pub issuer: String,
    pub signature: String,
}

impl ReadToken {
    fn signed_bytes(request: &ReadRequest, issuer: &str) -> Vec<u8> {
        let mut m = b"furcate:cell-read-token:v1\0".to_vec();
        m.extend_from_slice(&request.hash());
        m.extend_from_slice(issuer.as_bytes());
        m
    }

    /// As it travels: the scheme, then the token as hex JSON.
    pub fn encode(&self) -> String {
        format!("{SCHEME}{}", hex::encode(serde_json::to_vec(self).expect("a token serialises")))
    }

    pub fn decode(s: &str) -> Result<ReadToken, String> {
        let h = s.strip_prefix(SCHEME).ok_or("not a cell read token")?;
        let raw = hex::decode(h).map_err(|e| format!("the read token is not hex: {e}"))?;
        serde_json::from_slice(&raw).map_err(|e| format!("the read token does not parse: {e}"))
    }

    /// Whether `node` signed this, and it is still live at `now`.
    pub fn verify(&self, node: &str, now: u64) -> Result<(), String> {
        if self.issuer != node {
            return Err(format!("the read token was issued by {}, not this node", self.issuer));
        }
        if now >= self.request.not_after {
            return Err(format!("the read token ended at {}; ask for another", self.request.not_after));
        }
        CellKey::parse(&self.issuer)?
            .verify_hex(&Self::signed_bytes(&self.request, &self.issuer), &self.signature)
            .map_err(|_| "the read token's signature does not verify".to_string())
    }
}

/// The challenge for a request: its hash, a fresh nonce, a short expiry.
pub fn challenge_for(r: &ReadRequest, nonce: [u8; 16], expires_at: u64) -> Challenge {
    Challenge { order_hash: r.hash(), nonce, expires_at }
}

/// Verify a manager's assertion over a read request and sign the token.
///
/// `credential` is the site's admitted credential for the holder's id;
/// `challenge` is the one this node issued for `request` and has now spent.
#[allow(clippy::too_many_arguments)]
pub fn issue(
    tree: &CellTree,
    request: &ReadRequest,
    credential: &Credential,
    assertion: &Assertion,
    challenge: &Challenge,
    issuer: &str,
    now: u64,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<ReadToken, String> {
    if request.site != tree.site {
        return Err(format!("the request is for site {}, and this node's cells belong to {}", request.site, tree.site));
    }
    if request.not_after <= now || request.not_after > now + MAX_READ_SECS {
        return Err(format!("a read token lasts at most {MAX_READ_SECS} seconds from now"));
    }
    let (rp, id) = request.credential()?;
    if credential.id != id.trim_end_matches('=') || credential.rp_id != rp {
        return Err(format!("the site's credential {} is not the one the request names", credential.id));
    }
    if challenge.order_hash != request.hash() {
        return Err("the challenge was issued for another request".into());
    }
    let v = verify_assertion(credential, assertion, challenge, now).map_err(|r| r.because)?;
    if v.credential_id() != credential.id {
        return Err("the assertion is from another credential".into());
    }
    within_link(tree, &request.holder, &request.scope)?;
    let message = ReadToken::signed_bytes(request, issuer);
    let signature = CellKey::parse(issuer)?.seal(&message, &sign(&message)?)?;
    Ok(ReadToken { request: request.clone(), issuer: issuer.to_string(), signature })
}

/// The scope a holder's manager link gives, if it covers `scope`.
pub fn within_link(tree: &CellTree, holder: &str, scope: &Scope) -> Result<Scope, String> {
    let own = tree
        .scope_of(holder)
        .ok_or_else(|| format!("{holder} holds no manager link on this site, so no cell is theirs to read"))?;
    if !scope.within(&own) {
        return Err(format!("{} is outside {}, the cell {holder} manages", scope.as_string(), own.as_string()));
    }
    Ok(own)
}

/// The scope a read token's principal reaches, from its task.
pub fn principal_scope(p: &Principal) -> Option<Scope> {
    p.task.as_deref()?.strip_prefix("cells-read ").and_then(|s| Scope::parse(s).ok())
}

/// Admits a read token, on GET `/cells` and `/cells/view` only.
///
/// The principal it gives is the manager, delegated from their passkey and
/// bound to the token's scope through its task, which the tree route narrows
/// to. Any other route is refused here, so a token can never be spent on
/// something that acts.
pub struct ReadTokenVerifier {
    /// This node's key, as [`CellKey`] names it: the only issuer it believes.
    pub node: String,
}

impl Verifier for ReadTokenVerifier {
    fn verify(&self, presented: &Presented, now: u64) -> Result<Principal, Refusal> {
        let Some(cred) = presented.credential.as_deref().filter(|c| c.starts_with(SCHEME)) else {
            return Err(Refusal::not_mine("not a cell read token"));
        };
        if presented.method != "GET" || !READ_PATHS.contains(&presented.path.as_str()) {
            return Err(Refusal::new(format!(
                "a cell read token reads GET /cells and nothing else, not {} {}",
                presented.method, presented.path
            )));
        }
        let t = ReadToken::decode(cred).map_err(Refusal::new)?;
        t.verify(&self.node, now).map_err(Refusal::new)?;
        Ok(Principal {
            id: t.request.holder.clone(),
            class: Class::Person,
            evidence: Evidence::Delegated { root: t.request.holder.clone(), depth: 1 },
            expires_at: Some(t.request.not_after),
            task: Some(format!("cells-read {}", t.request.scope.as_string())),
            needs_approval_for: Vec::new(),
            roles: Vec::new(),
        })
    }

    fn name(&self) -> &'static str {
        "cell-read-token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::{ed25519_id, CellDelegation, Role, Root, Scale};
    use ed25519_dalek::{Signer, SigningKey};
    use furcate_authn::webauthn::virtual_authenticator::Authenticator;
    use furcate_identity::AssuranceClass;

    const NOW: u64 = 1_786_838_400;
    const RP: &str = "site.example";

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn link(by: &SigningKey, above: Option<&CellDelegation>, holder: String, role: Role, scope: &str) -> CellDelegation {
        CellDelegation {
            site: "s".into(),
            issuer: ed25519_id(&by.verifying_key()),
            holder,
            role,
            scope: Scope::parse(scope).unwrap(),
            scale: (role == Role::Head).then_some(Scale::Home),
            assurance: matches!(role, Role::Head).then_some(AssuranceClass::Device),
            leaf_min_class: None,
            endpoint: "10.0.0.1:7616".into(),
            name: String::new(),
            parent: above.map(|a| a.digest()),
            not_before: NOW - 10,
            not_after: NOW + 86_400,
            signature: String::new(),
        }
        .signed_by(|m| Ok(by.sign(m).to_bytes().to_vec()))
        .unwrap()
    }

    /// A site with cells home1 and home2, and a passkey managing home1.
    fn site(manager: &Authenticator) -> (CellTree, String) {
        let ctrl = link(&key(1), None, ed25519_id(&key(2).verifying_key()), Role::Controller, "site");
        let h1 = link(&key(2), Some(&ctrl), ed25519_id(&key(3).verifying_key()), Role::Head, "cell:home1");
        let h2 = link(&key(2), Some(&ctrl), ed25519_id(&key(4).verifying_key()), Role::Head, "cell:home2");
        let holder = format!("passkey:{RP}:{}", manager.id());
        let m = link(&key(3), Some(&h1), holder.clone(), Role::Manager, "cell:home1");
        let tree = CellTree::derive("s", &Root::Operator(ed25519_id(&key(1).verifying_key())), &[ctrl, h1, h2, m], NOW);
        assert!(tree.refused.is_empty(), "{:?}", tree.refused);
        (tree, holder)
    }

    fn node() -> (SigningKey, String) {
        let k = key(9);
        let id = ed25519_id(&k.verifying_key());
        (k, id)
    }

    fn request(holder: &str, scope: &str, until: u64) -> ReadRequest {
        ReadRequest { site: "s".into(), holder: holder.into(), scope: Scope::parse(scope).unwrap(), not_after: until, nonce: "ab".repeat(16) }
    }

    fn ask(
        tree: &CellTree,
        auth: &mut Authenticator,
        r: &ReadRequest,
    ) -> Result<ReadToken, String> {
        let (k, id) = node();
        let ch = challenge_for(r, [7; 16], NOW + 120);
        let assertion = auth.get(&ch);
        issue(tree, r, &auth.credential(), &assertion, &ch, &id, NOW, |m| Ok(k.sign(m).to_bytes().to_vec()))
    }

    fn presented(method: &str, path: &str, t: &ReadToken) -> Presented {
        Presented { method: method.into(), path: path.into(), body: Vec::new(), credential: Some(t.encode()) }
    }

    #[test]
    fn a_read_token_reads_its_cell_and_nothing_else() {
        let mut auth = Authenticator::new(5, RP);
        let (tree, holder) = site(&auth);
        let t = ask(&tree, &mut auth, &request(&holder, "cell:home1", NOW + 600)).unwrap();
        let v = ReadTokenVerifier { node: node().1 };
        let p = v.verify(&presented("GET", "/cells", &t), NOW + 1).unwrap();
        assert_eq!(principal_scope(&p), Some(Scope::cell("home1").unwrap()));
        assert_eq!(tree.scope_for(&p).unwrap(), Scope::cell("home1").unwrap());
        // It acts on nothing.
        let e = v.verify(&presented("POST", "/cells/enrol", &t), NOW + 1).unwrap_err();
        assert!(e.applicable && e.because.contains("nothing else"), "{}", e.because);
    }

    #[test]
    fn a_read_token_is_refused_out_of_scope() {
        let mut auth = Authenticator::new(5, RP);
        let (tree, holder) = site(&auth);
        let e = ask(&tree, &mut auth, &request(&holder, "cell:home2", NOW + 600)).unwrap_err();
        assert!(e.contains("outside cell:home1"), "{e}");
        let e = ask(&tree, &mut auth, &request(&holder, "site", NOW + 600)).unwrap_err();
        assert!(e.contains("outside"), "{e}");
        // A passkey with no manager link here reads nothing.
        let mut stranger = Authenticator::new(6, RP);
        let other = format!("passkey:{RP}:{}", stranger.id());
        let e = ask(&tree, &mut stranger, &request(&other, "cell:home1", NOW + 600)).unwrap_err();
        assert!(e.contains("no manager link"), "{e}");
    }

    #[test]
    fn a_read_token_is_refused_after_expiry_and_from_another_node() {
        let mut auth = Authenticator::new(5, RP);
        let (tree, holder) = site(&auth);
        let t = ask(&tree, &mut auth, &request(&holder, "cell:home1", NOW + 600)).unwrap();
        let v = ReadTokenVerifier { node: node().1 };
        let e = v.verify(&presented("GET", "/cells", &t), NOW + 600).unwrap_err();
        assert!(e.because.contains("ended"), "{}", e.because);
        let other = ReadTokenVerifier { node: ed25519_id(&key(8).verifying_key()) };
        assert!(other.verify(&presented("GET", "/cells", &t), NOW + 1).is_err());
        // A widened token no longer verifies.
        let mut wide = t.clone();
        wide.request.scope = Scope::Site;
        assert!(v.verify(&presented("GET", "/cells", &wide), NOW + 1).unwrap_err().because.contains("signature"));
        // Nor is one asked for to last past the ceiling issued.
        assert!(ask(&tree, &mut auth, &request(&holder, "cell:home1", NOW + MAX_READ_SECS + 1)).is_err());
    }

    #[test]
    fn the_assertion_must_be_over_this_request() {
        let mut auth = Authenticator::new(5, RP);
        let (tree, holder) = site(&auth);
        let (k, id) = node();
        let asked = request(&holder, "cell:home1", NOW + 600);
        // Signed over a challenge for a different request.
        let other = request(&holder, "cell:home1", NOW + 300);
        let ch = challenge_for(&other, [7; 16], NOW + 120);
        let a = auth.get(&ch);
        assert!(issue(&tree, &asked, &auth.credential(), &a, &ch, &id, NOW, |m| Ok(k.sign(m).to_bytes().to_vec())).is_err());
        // Or by another credential.
        let mut thief = Authenticator::new(6, RP);
        let ch = challenge_for(&asked, [7; 16], NOW + 120);
        let a = thief.get(&ch);
        assert!(issue(&tree, &asked, &auth.credential(), &a, &ch, &id, NOW, |m| Ok(k.sign(m).to_bytes().to_vec())).is_err());
    }

    #[test]
    fn other_credentials_are_left_to_other_verifiers() {
        let v = ReadTokenVerifier { node: node().1 };
        let p = Presented { method: "GET".into(), path: "/cells".into(), body: Vec::new(), credential: Some("node:x:y".into()) };
        assert!(!v.verify(&p, NOW).unwrap_err().applicable);
    }
}
