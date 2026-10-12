//! Handing an agent authority without handing it yours.
//!
//! The 2026 work on this converged on one distinction and it is worth stating
//! plainly: **delegation, not impersonation**. An agent that acts *as* the
//! operator is indistinguishable from the operator in every log, holds
//! everything the operator holds, and cannot be narrowed. An agent that
//! receives a grant keeps its own identity, holds only what the grant names,
//! and every hop stays traceable.
//!
//! A grant here is short-lived, scoped to specific actions and resources, and
//! can only ever narrow. It is the same shape as the capability tokens that
//! pattern settled on — derived per task from a longer-lived authority, with a
//! lifetime measured against the task rather than the session.
//!
//! ## What a grant cannot do
//!
//! It cannot widen. A grant issued from another grant is the intersection of
//! the two, never the union, so a delegation chain gets narrower at every step
//! and there is no sequence of hops that ends with more authority than it
//! started with.
//!
//! It cannot reach an invariant. The engine checks those first and a grant is
//! consulted afterwards, so no amount of delegation produces a halt.
//!
//! And it cannot outlive its expiry, which is required rather than optional —
//! a grant with no end is a permission change wearing a temporary label.

use crate::engine::{Decision, Request};
use crate::invariant::forbidden_to_all;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantError {
    /// A grant must say when it ends.
    NoExpiry,
    /// Already over.
    Expired { at: u64 },
    /// The grant names something no principal may do.
    ReachesInvariant { action: String },
    /// A derived grant asked for more than its parent held.
    Widens { action: String },
    /// Nothing was granted, which is a mistake rather than a very narrow grant.
    Empty,
    /// Asked to last longer than any grant may.
    ///
    /// Both numbers, because "too long" without them leaves an operator
    /// guessing what would have been accepted.
    TooLong { asked: u64, max: u64 },
}

/// Authority one principal has handed another, narrowly and for a while.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Who granted it. Kept so a chain can be walked back to a human.
    pub from: String,
    /// Who holds it. Its own identity, never the granter's.
    pub to: String,
    /// Exactly what may be done. No wildcard: a grant that says `*` is
    /// impersonation with extra steps.
    pub actions: Vec<String>,
    /// What it may be done to. `*` is permitted here — scoping by action is
    /// the part that matters, and forbidding a site-wide read would make most
    /// useful grants unexpressible.
    pub resources: Vec<String>,
    /// Unix seconds. Required.
    pub until: u64,
    /// Why, for the record a decision leaves behind.
    pub reason: String,
}

impl Grant {
    /// Longest a grant may run.
    ///
    /// A day. Long enough for any task somebody is actually supervising, short
    /// enough that a forgotten grant expires before it is forgotten about.
    pub const MAX_LIFETIME_SECS: u64 = 86_400;

    /// Check a grant is well formed at the moment it is issued.
    pub fn validate(&self, now: u64) -> Result<(), GrantError> {
        if self.actions.is_empty() {
            return Err(GrantError::Empty);
        }
        if self.until == 0 {
            return Err(GrantError::NoExpiry);
        }
        if self.until <= now {
            return Err(GrantError::Expired { at: self.until });
        }
        // The cap is checked here, not only applied by `capped()`.
        //
        // `capped()` is a builder method and had exactly one call site in the
        // whole tree. A second caller that forgot it would have produced a
        // grant good for as long as it asked for, and nothing would have said
        // so: `validate()` knew only that the expiry had not already passed.
        //
        // A ceiling that depends on the caller remembering is not a ceiling.
        if self.until.saturating_sub(now) > Self::MAX_LIFETIME_SECS {
            return Err(GrantError::TooLong {
                asked: self.until.saturating_sub(now),
                max: Self::MAX_LIFETIME_SECS,
            });
        }
        for a in &self.actions {
            if forbidden_to_all(a) {
                return Err(GrantError::ReachesInvariant { action: a.clone() });
            }
        }
        Ok(())
    }

    pub fn is_live(&self, now: u64) -> bool {
        now < self.until
    }

    /// Whether this grant covers a request.
    pub fn covers(&self, r: &Request, now: u64) -> bool {
        self.is_live(now)
            && self.to == r.principal
            && self.actions.iter().any(|a| a == &r.action)
            && self.resources.iter().any(|x| x == "*" || x == &r.resource)
    }

    /// Derive a narrower grant for a subagent.
    ///
    /// The result is the intersection, so a chain narrows at every hop and no
    /// sequence of delegations ends with more authority than it began with.
    /// The expiry is likewise the earlier of the two — a child cannot outlive
    /// the authority it came from.
    pub fn narrow(&self, to: &str, actions: &[String], until: u64, reason: &str) -> Result<Grant, GrantError> {
        for a in actions {
            if !self.actions.contains(a) {
                return Err(GrantError::Widens { action: a.clone() });
            }
        }
        let child = Grant {
            from: self.to.clone(),
            to: to.to_string(),
            actions: actions.to_vec(),
            resources: self.resources.clone(),
            until: until.min(self.until),
            reason: reason.to_string(),
        };
        if child.actions.is_empty() {
            return Err(GrantError::Empty);
        }
        Ok(child)
    }

    /// Cap a grant's lifetime at issue time.
    pub fn capped(mut self, now: u64) -> Self {
        self.until = self.until.min(now + Self::MAX_LIFETIME_SECS);
        self
    }
}

/// Evaluate a request against live grants, after the engine has had its say.
///
/// Only consulted when policy alone did not permit the request: a grant adds
/// authority for a while, it does not remove any. And it is consulted *after*
/// invariants, so no grant reaches them.
pub fn evaluate(grants: &[Grant], r: &Request, now: u64) -> Option<Decision> {
    if forbidden_to_all(&r.action) {
        return None;
    }
    grants.iter().find(|g| g.covers(r, now)).map(|g| Decision {
        allowed: true,
        because: format!(
            "granted by {} to {} until {}: {}",
            g.from, g.to, g.until, g.reason
        ),
        structural: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling holds even when nobody called `capped()`.
    ///
    /// It was a builder method with one call site, so a second caller that
    /// forgot it got a grant good for as long as it asked for and nothing said
    /// so. A ceiling that depends on being remembered is not one.
    #[test]
    fn a_grant_longer_than_the_maximum_is_refused_not_quietly_shortened() {
        let g = grant("agent:mcp", &["drain"], NOW + 400 * 86_400);
        match g.validate(NOW) {
            Err(GrantError::TooLong { max, .. }) => assert_eq!(max, Grant::MAX_LIFETIME_SECS),
            other => panic!("an uncapped grant was accepted: {other:?}"),
        }
        // The same grant, capped, passes: this refuses what is too long rather
        // than everything.
        assert!(g.capped(NOW).validate(NOW).is_ok());
    }

    const NOW: u64 = 1_786_838_400;

    fn grant(to: &str, actions: &[&str], until: u64) -> Grant {
        Grant {
            from: "operator".into(),
            to: to.into(),
            actions: actions.iter().map(|s| s.to_string()).collect(),
            resources: vec!["*".into()],
            until,
            reason: "a task somebody is watching".into(),
        }
    }

    fn req(principal: &str, action: &str, resource: &str) -> Request {
        Request {
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
            roles: Vec::new(),
        }
    }

    #[test]
    fn a_grant_must_say_when_it_ends() {
        // A grant with no end is a permission change wearing a temporary
        // label.
        let g = grant("agent:mcp", &["drain"], 0);
        assert_eq!(g.validate(NOW), Err(GrantError::NoExpiry));
    }

    #[test]
    fn a_grant_cannot_name_an_invariant() {
        let g = grant("agent:mcp", &["drain", "halt"], NOW + 600);
        assert_eq!(
            g.validate(NOW),
            Err(GrantError::ReachesInvariant { action: "halt".into() })
        );
    }

    #[test]
    fn no_grant_reaches_an_invariant_even_if_one_was_somehow_issued() {
        // Belt and braces: validation refuses to issue it, and evaluation
        // refuses to honour it.
        let bad = Grant {
            actions: vec!["halt".into()],
            ..grant("agent:mcp", &["drain"], NOW + 600)
        };
        assert!(evaluate(&[bad], &req("agent:mcp", "halt", "node:node-a"), NOW).is_none());
    }

    #[test]
    fn an_empty_grant_is_a_mistake_rather_than_a_very_narrow_one() {
        let g = grant("agent:mcp", &[], NOW + 600);
        assert_eq!(g.validate(NOW), Err(GrantError::Empty));
    }

    #[test]
    fn a_grant_covers_only_what_it_names() {
        let g = grant("agent:mcp", &["drain"], NOW + 600);
        assert!(evaluate(std::slice::from_ref(&g), &req("agent:mcp", "drain", "node:node-a"), NOW).is_some());
        assert!(evaluate(std::slice::from_ref(&g), &req("agent:mcp", "suspend", "node:node-a"), NOW).is_none());
        // And only the principal it was issued to. The agent's identity stays
        // its own, which is the difference from impersonation.
        assert!(evaluate(&[g], &req("network", "drain", "node:node-a"), NOW).is_none());
    }

    #[test]
    fn a_grant_stops_working_when_it_expires() {
        let g = grant("agent:mcp", &["drain"], NOW + 600);
        assert!(evaluate(std::slice::from_ref(&g), &req("agent:mcp", "drain", "site"), NOW).is_some());
        assert!(evaluate(&[g], &req("agent:mcp", "drain", "site"), NOW + 601).is_none());
    }

    #[test]
    fn a_derived_grant_narrows_and_cannot_widen() {
        // The property that makes a delegation chain safe: it gets narrower at
        // every hop, and no sequence ends with more than it started with.
        let parent = grant("agent:orchestrator", &["drain", "tune"], NOW + 3600);
        let child = parent
            .narrow("agent:worker", &["tune".into()], NOW + 600, "one job")
            .unwrap();
        assert_eq!(child.actions, vec!["tune"]);
        assert_eq!(child.from, "agent:orchestrator", "the chain is walkable");

        assert_eq!(
            parent.narrow("agent:worker", &["suspend".into()], NOW + 600, "more"),
            Err(GrantError::Widens { action: "suspend".into() })
        );
    }

    #[test]
    fn a_child_cannot_outlive_its_parent() {
        let parent = grant("agent:orchestrator", &["tune"], NOW + 600);
        let child = parent
            .narrow("agent:worker", &["tune".into()], NOW + 99_999, "long job")
            .unwrap();
        assert_eq!(child.until, parent.until);
    }

    #[test]
    fn a_grant_is_capped_at_a_day_however_long_it_asked_for() {
        // Long enough for any task somebody is supervising; short enough that
        // a forgotten grant expires before it is forgotten about.
        let g = grant("agent:mcp", &["drain"], NOW + 400 * 86_400).capped(NOW);
        assert_eq!(g.until, NOW + Grant::MAX_LIFETIME_SECS);
    }

    #[test]
    fn resources_may_be_wild_but_actions_may_not() {
        // Scoping by action is the part that matters. A grant that says `*`
        // for actions is impersonation with extra steps, and there is no way
        // to express it here.
        let g = grant("agent:mcp", &["*"], NOW + 600);
        assert!(evaluate(&[g], &req("agent:mcp", "drain", "site"), NOW).is_none());
    }
}

// ---------------------------------------------------------------------------
// Cell delegations
// ---------------------------------------------------------------------------
//
// A grant above is a task-sized loan of authority: a day at most, a list of
// actions, gone when the task is. A cell is the other shape of delegation, the
// structural one: an operator names a controller, the controller names the
// head of a cell, the head names its leaves and the heads of its sub-cells.
// Each link is signed by the key named in the link above it, so the tree of
// cells is not something anyone writes down. It is the chain, read back.
//
// The same rules hold as for a grant. A link narrows and never widens: a
// child's scope sits inside its parent's. A link cannot outlive its parent.
// And a link carries its own scope, so a node checks a request against the
// signature it holds rather than against what a screen chose to show.

use furcate_identity::{AssuranceClass, MessageSigner, SignerKey};
use serde::{Deserializer, Serializer};

/// How large a cell is: the view, policy and limits a cell gets follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scale {
    Home,
    Business,
    City,
    /// Anything the three do not describe. Unranked, so it nests anywhere and
    /// anything nests in it.
    Other,
}

impl Scale {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scale::Home => "home",
            Scale::Business => "business",
            Scale::City => "city",
            Scale::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Scale> {
        Some(match s {
            "home" => Scale::Home,
            "business" => Scale::Business,
            "city" => Scale::City,
            "other" => Scale::Other,
            _ => return None,
        })
    }

    fn rank(&self) -> Option<u8> {
        match self {
            Scale::Home => Some(1),
            Scale::Business => Some(2),
            Scale::City => Some(3),
            Scale::Other => None,
        }
    }

    /// Whether a cell of this scale may sit inside a cell of `outer`'s.
    ///
    /// A city may hold a business and a business a home; a home holding a
    /// city is a typing mistake, and the views and limits keyed on scale would
    /// be wrong for every cell below it.
    pub fn fits_inside(&self, outer: Scale) -> bool {
        match (self.rank(), outer.rank()) {
            (Some(inner), Some(outer)) => inner <= outer,
            _ => true,
        }
    }
}

/// What a cell delegation makes its holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A core-cluster machine that parents cells. Named by the operator.
    Controller,
    /// The gateway that runs a cell. Named by a controller, or by the head of
    /// the cell it sits inside.
    Head,
    /// A cell's edge inference machine. Named by the cell's head.
    EdgeAi,
    /// A sensor or actuator device. Named by the cell's head.
    Leaf,
    /// A person who manages a cell, holding a passkey. Named by anyone above
    /// the cell, and able to name nobody.
    Manager,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Controller => "controller",
            Role::Head => "head",
            Role::EdgeAi => "edge_ai",
            Role::Leaf => "leaf",
            Role::Manager => "manager",
        }
    }

    /// Whether a holder of this role may name a holder of `child`.
    fn may_name(&self, child: Role) -> bool {
        matches!(
            (self, child),
            (Role::Controller, Role::Head | Role::Manager)
                | (Role::Head, Role::Head | Role::EdgeAi | Role::Leaf | Role::Manager)
        )
    }
}

/// The cells a delegation reaches: one cell and every cell inside it, or the
/// whole site.
///
/// Written `site`, or `cell:<path>` where the path is the cell's segments from
/// the top, separated by `/`: `cell:berlin/mitte` is the Mitte cell inside the
/// Berlin cell, and reaches every cell inside Mitte too. The path is not a
/// label anyone picks freely: a head may only name sub-cells one segment below
/// its own, so a path is the chain that made it, and a node with no view of
/// the rest of the fleet can still tell whether one cell sits inside another.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    Site,
    Cell(String),
}

/// Deepest a cell may nest. Far past any city of districts of buildings of
/// rooms, and a bound so a crafted path cannot cost a node anything.
pub const MAX_CELL_DEPTH: usize = 16;

impl Scope {
    pub fn parse(s: &str) -> Result<Scope, String> {
        if s == "site" {
            return Ok(Scope::Site);
        }
        let Some(path) = s.strip_prefix("cell:") else {
            return Err(format!("scope `{s}` is neither `site` nor `cell:<path>`"));
        };
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() > MAX_CELL_DEPTH {
            return Err(format!(
                "scope `{s}` is {} cells deep and a cell may nest {MAX_CELL_DEPTH} deep",
                segments.len()
            ));
        }
        for seg in &segments {
            let ok = !seg.is_empty()
                && seg.len() <= 63
                && seg.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok {
                return Err(format!(
                    "scope `{s}` has the segment `{seg}`; a segment is 1 to 63 of a-z, 0-9 and -"
                ));
            }
        }
        Ok(Scope::Cell(path.to_string()))
    }

    pub fn cell(path: &str) -> Result<Scope, String> {
        Scope::parse(&format!("cell:{path}"))
    }

    pub fn as_string(&self) -> String {
        match self {
            Scope::Site => "site".into(),
            Scope::Cell(p) => format!("cell:{p}"),
        }
    }

    /// The cell path, when this names one.
    pub fn path(&self) -> Option<&str> {
        match self {
            Scope::Site => None,
            Scope::Cell(p) => Some(p),
        }
    }

    /// How many cells deep: 0 for the site.
    pub fn depth(&self) -> usize {
        match self {
            Scope::Site => 0,
            Scope::Cell(p) => p.split('/').count(),
        }
    }

    /// Whether `cell` (a path, or `None` for anything outside every cell) is
    /// this scope or inside it.
    pub fn admits_cell(&self, cell: Option<&str>) -> bool {
        match (self, cell) {
            (Scope::Site, _) => true,
            (Scope::Cell(_), None) => false,
            (Scope::Cell(p), Some(c)) => c == p || c.starts_with(&format!("{p}/")),
        }
    }

    /// Whether every cell this scope reaches is also reached by `outer`.
    pub fn within(&self, outer: &Scope) -> bool {
        match self {
            Scope::Site => *outer == Scope::Site,
            Scope::Cell(p) => outer.admits_cell(Some(p)),
        }
    }

    /// The cell directly above, for a cell scope.
    pub fn parent(&self) -> Option<Scope> {
        match self {
            Scope::Site => None,
            Scope::Cell(p) => Some(match p.rsplit_once('/') {
                Some((up, _)) => Scope::Cell(up.to_string()),
                None => Scope::Site,
            }),
        }
    }

    /// Whether a request, under a delegation of this scope, reaches only what
    /// the scope covers. `locate` gives the cell a resource sits in, or `None`
    /// for anything in no cell: the core cluster, and anything this node does
    /// not know, which a cell-scoped holder may not reach either.
    pub fn admits_request(
        &self,
        r: &Request,
        locate: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        if *self == Scope::Site {
            return Ok(());
        }
        if r.resource == "*" {
            return Err(format!(
                "`{}` asks for every resource and a delegation scoped to {} reaches only its \
                 own cells",
                r.action,
                self.as_string()
            ));
        }
        let at = locate(&r.resource);
        if self.admits_cell(at.as_deref()) {
            return Ok(());
        }
        Err(match at {
            Some(c) => format!(
                "{} is in cell:{c}, outside {}, the scope {} was delegated",
                r.resource,
                self.as_string(),
                r.principal
            ),
            None => format!(
                "{} is in no cell this node knows (the core cluster, or unknown), and {} was \
                 delegated only {}",
                r.resource,
                r.principal,
                self.as_string()
            ),
        })
    }

    /// Whether a machine order, approved under a delegation of this scope,
    /// stays inside it. A cell's manager may act on the machines of the cell
    /// and the cells inside it; the core cluster, its failure domains, the
    /// site's credentials and its custody are site authority.
    pub fn admits_order(
        &self,
        order: &furcate_authn::order::Order,
        locate: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        use furcate_authn::order::Target;
        if *self == Scope::Site {
            return Ok(());
        }
        let refuse = |what: &str| {
            Err(format!(
                "`{}` on {what} is site authority and this order was approved under {}",
                order.action.as_str(),
                self.as_string()
            ))
        };
        match &order.target {
            Target::Node { id } => {
                let at = locate(id);
                if self.admits_cell(at.as_deref()) {
                    Ok(())
                } else {
                    match at {
                        Some(c) => Err(format!(
                            "node {id} is in cell:{c}, outside {}, the scope this order was \
                             approved under",
                            self.as_string()
                        )),
                        None => Err(format!(
                            "node {id} is in no cell this node knows (the core cluster, or \
                             unknown), outside {}",
                            self.as_string()
                        )),
                    }
                }
            }
            Target::Domain { id } => refuse(&format!("failure domain {id}")),
            Target::Cluster => refuse("the whole cluster"),
            Target::Credential { id, .. } => refuse(&format!("credential {id}")),
            Target::Custody { .. } => refuse("the site's custody"),
        }
    }
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Scope::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// One signed link in the chain of cells.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellDelegation {
    /// The site this link belongs to. A link for another site is refused.
    pub site: String,
    /// The signer: a key as [`CellKey`] names it, the holder named in the
    /// link above, or the operator's key for a controller.
    pub issuer: String,
    /// Who it names: `ed25519:<hex>` or `p256:<hex>` for a machine or leaf, or
    /// `passkey:<rp id>:<credential id>` for a person, with the credential's
    /// own RP ID so a manager enrolled through another wallet provider is
    /// still exactly one credential.
    pub holder: String,
    pub role: Role,
    /// What the holder reaches.
    pub scope: Scope,
    /// The cell's scale, on a head's link and nowhere else.
    #[serde(default)]
    pub scale: Option<Scale>,
    /// How the holder's key is held, for a machine or leaf. A head must hold
    /// its key in hardware.
    #[serde(default)]
    pub assurance: Option<AssuranceClass>,
    /// The lowest class a leaf may hold to attach to this cell, on a head's
    /// link and nowhere else. Set by the operator when the head is enrolled
    /// or renewed and signed with the rest of the link, so neither the head
    /// nor anyone holding its files can lower it. `None` is `device`; see
    /// [`furcate_identity::leaf::admits_leaf`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_min_class: Option<AssuranceClass>,
    /// Where the holder answers. A controller's and a head's are what the
    /// cells below them need to reach upward.
    #[serde(default)]
    pub endpoint: String,
    /// What a person calls it.
    #[serde(default)]
    pub name: String,
    /// Digest of the issuer's own link; `None` only on a link the operator
    /// signs.
    #[serde(default)]
    pub parent: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
    /// Hex signature by `issuer` over [`CellDelegation::signed_bytes`], in the
    /// form [`CellKey::verify`] describes.
    #[serde(default)]
    pub signature: String,
}

impl CellDelegation {
    /// The exact bytes the signature covers: length-prefixed fields, so the
    /// signature does not depend on a serialiser.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut m = b"furcate:cell-delegation:v1\0".to_vec();
        let fields = [
            self.site.clone(),
            self.issuer.clone(),
            self.holder.clone(),
            self.role.as_str().to_string(),
            self.scope.as_string(),
            self.scale.map(|s| s.as_str().to_string()).unwrap_or_default(),
            self.assurance.map(|a| format!("{a:?}")).unwrap_or_default(),
            self.endpoint.clone(),
            self.name.clone(),
            self.parent.clone().unwrap_or_default(),
            self.not_before.to_string(),
            self.not_after.to_string(),
        ];
        for f in fields {
            m.extend_from_slice(&(f.len() as u64).to_be_bytes());
            m.extend_from_slice(f.as_bytes());
        }
        // Covered only when set, so every link signed before the floor
        // existed keeps its bytes and its signature.
        if let Some(floor) = self.leaf_min_class {
            let f = format!("leaf_min_class={floor:?}");
            m.extend_from_slice(&(f.len() as u64).to_be_bytes());
            m.extend_from_slice(f.as_bytes());
        }
        m
    }

    /// What a link below this one names as its `parent`.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.signed_bytes());
        h.update(self.signature.as_bytes());
        hex::encode(h.finalize())
    }

    /// Sign with whatever holds the issuer's key. The signer is handed the
    /// bytes and returns the signature; the key never passes through here.
    /// The signature is checked under `issuer` before it is kept, so a signer
    /// holding some other key is refused here rather than by every node.
    pub fn signed_by(
        mut self,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<CellDelegation, String> {
        let message = self.signed_bytes();
        self.signature = CellKey::parse(&self.issuer)?.seal(&message, &sign(&message)?)?;
        Ok(self)
    }

    /// Sign with a hardware signer, which must hold the issuer's key.
    pub fn signed_with(self, signer: &dyn MessageSigner) -> Result<CellDelegation, String> {
        let me = CellKey::of(signer)?.id();
        if me != self.issuer {
            return Err(format!("the link is issued by {}, and this signer holds {me}", self.issuer));
        }
        self.signed_by(|m| signer.sign(m).map_err(|e| format!("the signer refused: {e:#}")))
    }

    pub fn is_live(&self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }

    /// Whether the signature verifies under the issuer named in the link.
    pub fn verify_signature(&self) -> Result<(), String> {
        CellKey::parse(&self.issuer)?
            .verify_hex(&self.signed_bytes(), &self.signature)
            .map_err(|e| format!("the signature does not verify under {}: {e}", self.issuer))
    }

    /// Check this link on its own and against the link above it.
    ///
    /// `above` is the issuer's own link, or `None` when the issuer is the
    /// root this node trusts: the operator, or, on a cell's head, the key of
    /// the controller that enrolled it. `root` is that key, as [`CellKey`]
    /// names it.
    pub fn check(&self, above: Option<&CellDelegation>, root: &str, site: &str, now: u64) -> Result<(), String> {
        self.check_alone(site, now)?;
        match above {
            None => {
                if self.issuer != root {
                    return Err(format!(
                        "signed by {}, which is neither the root this node trusts nor the holder \
                         of a link it holds",
                        self.issuer
                    ));
                }
                if self.parent.is_some() {
                    return Err("the link names a parent the root does not have".into());
                }
                Ok(())
            }
            Some(up) => self.check_under(up),
        }
    }

    /// Check a head's own link as the root of everything below it.
    ///
    /// A cell's head holds its own link and the key of whatever enrolled it,
    /// and nothing else above: not the link that made its controller, not the
    /// operator's other controllers. So the link above its own cannot be
    /// presented, and its own link is checked against the one key it pinned.
    pub fn check_anchor(&self, parent_key: &str, site: &str, now: u64) -> Result<(), String> {
        self.check_alone(site, now)?;
        if self.role != Role::Head {
            return Err(format!("an anchor is a head's own link, and this one names a {}", self.role.as_str()));
        }
        if self.issuer != parent_key {
            return Err(format!(
                "signed by {}, not {parent_key}, the key this cell was enrolled under",
                self.issuer
            ));
        }
        Ok(())
    }

    fn check_alone(&self, site: &str, now: u64) -> Result<(), String> {
        if self.site != site {
            return Err(format!("the link is for site {}, not {site}", self.site));
        }
        if self.not_after <= self.not_before {
            return Err("the link ends before it begins".into());
        }
        if !self.is_live(now) {
            return Err(format!(
                "the link is live from {} until {}, and it is {now}",
                self.not_before, self.not_after
            ));
        }
        if self.issuer == self.holder {
            return Err("a link may not name its own signer".into());
        }
        self.verify_signature()?;
        self.check_shape()
    }

    fn check_under(&self, up: &CellDelegation) -> Result<(), String> {
        if self.issuer != up.holder {
            return Err(format!(
                "signed by {}, but the link above names {}",
                self.issuer, up.holder
            ));
        }
        if self.parent.as_deref() != Some(up.digest().as_str()) {
            return Err("the link names a different parent than the one presented".into());
        }
        if !up.role.may_name(self.role) {
            return Err(format!(
                "a {} may not name a {}",
                up.role.as_str(),
                self.role.as_str()
            ));
        }
        if self.not_after > up.not_after {
            return Err(format!(
                "the link runs until {} and the one above it ends at {}; a link cannot \
                 outlive its parent",
                self.not_after, up.not_after
            ));
        }
        if !self.scope.within(&up.scope) {
            return Err(format!(
                "scope {} is wider than {}, the scope above it",
                self.scope.as_string(),
                up.scope.as_string()
            ));
        }
        match self.role {
            Role::Head => {
                // A head names one cell, one segment below whatever
                // named it, so a cell's path is its place in the chain.
                if self.scope.parent().as_ref() != Some(&up.scope) {
                    return Err(format!(
                        "a head of {} must sit one cell below {}, the scope that named it",
                        self.scope.as_string(),
                        up.scope.as_string()
                    ));
                }
                if let (Some(inner), Some(outer)) = (self.scale, up.scale) {
                    if !inner.fits_inside(outer) {
                        return Err(format!(
                            "a {} cell cannot sit inside a {} cell",
                            inner.as_str(),
                            outer.as_str()
                        ));
                    }
                }
            }
            Role::EdgeAi | Role::Leaf => {
                if self.scope != up.scope {
                    return Err(format!(
                        "a {} belongs to the cell of the head that named it, {}, not {}",
                        self.role.as_str(),
                        up.scope.as_string(),
                        self.scope.as_string()
                    ));
                }
            }
            Role::Controller | Role::Manager => {}
        }
        Ok(())
    }

    /// What a link must carry for its role, whoever signed it.
    fn check_shape(&self) -> Result<(), String> {
        let person = self.holder.starts_with("passkey:");
        match self.role {
            Role::Manager => {
                let parts: Vec<&str> = self.holder.splitn(3, ':').collect();
                if !person || parts.len() != 3 || parts[1].is_empty() || parts[2].is_empty() {
                    return Err(format!(
                        "a manager is a person: `passkey:<rp id>:<credential id>`, not `{}`",
                        self.holder
                    ));
                }
                if self.scale.is_some() {
                    return Err("only a head's link carries a scale".into());
                }
            }
            _ => {
                CellKey::parse(&self.holder)?;
                if self.role == Role::Head {
                    if self.scale.is_none() {
                        return Err("a head's link must say the cell's scale".into());
                    }
                    if !matches!(self.scope, Scope::Cell(_)) {
                        return Err("a head runs one cell; its scope must be `cell:<path>`".into());
                    }
                    match self.assurance {
                        Some(a) if a >= AssuranceClass::Device => {}
                        Some(a) => {
                            return Err(format!(
                                "a cell head must hold its key in hardware; this one is {a:?}, \
                                 which can be copied off the machine"
                            ))
                        }
                        None => return Err("a head's link must say how its key is held".into()),
                    }
                } else if self.scale.is_some() {
                    return Err("only a head's link carries a scale".into());
                }
                if self.role == Role::Controller && self.scope != Scope::Site {
                    return Err("a controller sits in the core cluster; its scope is `site`".into());
                }
            }
        }
        Ok(())
    }
}

/// A key as cell links name it.
///
/// Two forms, either of which may hold or sign any link:
///
/// - `ed25519:<hex>`: the 32-byte Ed25519 public key.
/// - `p256:<hex>`: an ECDSA P-256 public key, signing the SHA-256 of the
///   message, as a Pi's firmware-held OTP key, a TPM key or a passkey does.
///   A link writes it one way only, the 33-byte compressed SEC1 point (`02`
///   or `03`, then x), so the same key is always the same string and the
///   chain can compare holders and issuers as text. [`CellKey::normalise`]
///   also takes the 65-byte uncompressed point (`04`, x, y) and the DER
///   SubjectPublicKeyInfo that `rpi-fw-crypto pubkey --outform hex` prints,
///   and rewrites either to the compressed form; a link carrying anything but
///   the compressed form is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

/// The DER SubjectPublicKeyInfo header for an uncompressed P-256 point:
/// id-ecPublicKey, prime256v1, then the BIT STRING holding the 65 bytes.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

impl CellKey {
    /// Parse a key exactly as a link must carry it.
    pub fn parse(id: &str) -> Result<CellKey, String> {
        let key = Self::read(id)?;
        if key.id() != id {
            return Err(format!("`{id}` is not written the one way a link names a key; it is {}", key.id()));
        }
        Ok(key)
    }

    /// Parse a key in any form an operator may have it in and return how a
    /// link names it. A bare 64-character hex string is taken as Ed25519, as
    /// it always has been.
    pub fn normalise(s: &str) -> Result<String, String> {
        let s = s.trim();
        let id = if s.starts_with("ed25519:") || s.starts_with("p256:") { s.to_string() } else { format!("ed25519:{s}") };
        Ok(Self::read(&id)?.id())
    }

    /// The key a hardware signer holds.
    pub fn of(signer: &dyn MessageSigner) -> Result<CellKey, String> {
        match signer.public_key().map_err(|e| format!("the signer cannot say its key: {e:#}"))? {
            SignerKey::Ed25519(b) => ed25519_dalek::VerifyingKey::from_bytes(&b)
                .map(CellKey::Ed25519)
                .map_err(|_| "the signer's Ed25519 key is not a valid key".to_string()),
            SignerKey::P256(b) => p256_from_bytes(&b).map(CellKey::P256),
        }
    }

    fn read(id: &str) -> Result<CellKey, String> {
        if id.starts_with("ed25519:") {
            return ed25519_key(id).map(CellKey::Ed25519);
        }
        let Some(h) = id.strip_prefix("p256:") else {
            return Err(format!("`{id}` is neither an `ed25519:<hex>` nor a `p256:<hex>` key"));
        };
        let raw = hex::decode(h).map_err(|e| format!("`{id}` is not hex: {e}"))?;
        p256_from_bytes(&raw).map(CellKey::P256).map_err(|e| format!("`{id}`: {e}"))
    }

    /// How a link names this key.
    pub fn id(&self) -> String {
        match self {
            CellKey::Ed25519(k) => ed25519_id(k),
            CellKey::P256(k) => p256_id(k),
        }
    }

    /// Whether `signature` is this key's over `message`.
    ///
    /// Ed25519 takes its 64 bytes. P-256 takes ECDSA over SHA-256 of
    /// `message` in either encoding hardware returns: the 64-byte `r || s`,
    /// each big-endian and zero-padded to 32 bytes (a TPM's ECDSA signature
    /// with its two halves joined), or a DER `Ecdsa-Sig-Value` (what
    /// `rpi-fw-crypto sign` and OpenSSL print, and what a passkey returns).
    /// A high-S signature is accepted, as the curve allows both.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        match self {
            CellKey::Ed25519(k) => {
                use ed25519_dalek::Verifier as _;
                let bytes: [u8; 64] = signature
                    .try_into()
                    .map_err(|_| format!("signature is {} bytes, expected 64", signature.len()))?;
                k.verify(message, &ed25519_dalek::Signature::from_bytes(&bytes))
                    .map_err(|_| "the signature is not this key's".to_string())
            }
            CellKey::P256(k) => {
                use p256::ecdsa::signature::Verifier as _;
                let sig = p256_signature(signature)?;
                k.verify(message, &sig).map_err(|_| "the signature is not this key's".to_string())
            }
        }
    }

    /// [`CellKey::verify`] on a hex signature.
    pub fn verify_hex(&self, message: &[u8], signature: &str) -> Result<(), String> {
        let raw = hex::decode(signature).map_err(|e| format!("signature is not hex: {e}"))?;
        self.verify(message, &raw)
    }

    /// Check what a signer returned for `message` and write it the way a link
    /// keeps it: hex, and for P-256 the 64-byte low-S `r || s` whatever form
    /// the hardware gave, so one signature has one spelling.
    pub fn seal(&self, message: &[u8], signature: &[u8]) -> Result<String, String> {
        self.verify(message, signature)
            .map_err(|e| format!("the signer did not sign as {}: {e}", self.id()))?;
        self.encode(signature)
    }

    /// Write a signature the way a link keeps it, without checking whose it
    /// is; [`CellKey::seal`] checks as well.
    pub fn encode(&self, signature: &[u8]) -> Result<String, String> {
        Ok(match self {
            CellKey::Ed25519(_) if signature.len() != 64 => {
                return Err(format!("the signer returned {} bytes, expected 64", signature.len()))
            }
            CellKey::Ed25519(_) => hex::encode(signature),
            CellKey::P256(_) => hex::encode(p256_signature(signature)?.normalize_s().to_bytes()),
        })
    }
}

fn p256_from_bytes(b: &[u8]) -> Result<p256::ecdsa::VerifyingKey, String> {
    let point = match b.len() {
        91 if b[..26] == P256_SPKI_PREFIX => &b[26..],
        33 | 65 => b,
        n => {
            return Err(format!(
                "a P-256 key is a 33- or 65-byte SEC1 point or a 91-byte SubjectPublicKeyInfo, not {n} bytes"
            ))
        }
    };
    p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| "not a point on P-256".to_string())
}

fn p256_signature(signature: &[u8]) -> Result<p256::ecdsa::Signature, String> {
    if signature.len() == 64 {
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| "the 64-byte r || s is out of range".to_string())
    } else {
        p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| format!("a P-256 signature is 64 bytes of r || s or DER, and this is neither ({} bytes)", signature.len()))
    }
}

/// Name a P-256 public key the way cell links do: the compressed SEC1 point.
pub fn p256_id(key: &p256::ecdsa::VerifyingKey) -> String {
    format!("p256:{}", hex::encode(key.to_sec1_point(true).as_bytes()))
}

/// How a link names the key a hardware signer holds.
pub fn signer_id(signer: &dyn MessageSigner) -> Result<String, String> {
    CellKey::of(signer).map(|k| k.id())
}

/// Parse `ed25519:<hex>`.
pub fn ed25519_key(id: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
    let Some(h) = id.strip_prefix("ed25519:") else {
        return Err(format!("`{id}` is not an `ed25519:<hex>` key"));
    };
    let raw = hex::decode(h).map_err(|e| format!("`{id}` is not hex: {e}"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("`{id}` is {} bytes, expected 32", raw.len()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| format!("`{id}` is not a valid key"))
}

/// Name an Ed25519 public key the way cell links do.
pub fn ed25519_id(key: &ed25519_dalek::VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(key.as_bytes()))
}

#[cfg(test)]
mod cell_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_786_838_400;
    const YEAR: u64 = 365 * 86_400;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn id(k: &SigningKey) -> String {
        ed25519_id(&k.verifying_key())
    }

    fn link(by: &SigningKey, above: Option<&CellDelegation>, holder: String, role: Role, scope: &str) -> CellDelegation {
        CellDelegation {
            site: "home".into(),
            issuer: id(by),
            holder,
            role,
            scope: Scope::parse(scope).unwrap(),
            scale: (role == Role::Head).then_some(Scale::Business),
            assurance: (role != Role::Manager).then_some(AssuranceClass::Device),
            leaf_min_class: None,
            endpoint: String::new(),
            name: String::new(),
            parent: above.map(|a| a.digest()),
            not_before: NOW - 10,
            not_after: above.map(|a| a.not_after).unwrap_or(NOW + YEAR),
            signature: String::new(),
        }
        .signed_by(|m| Ok(by.sign(m).to_bytes().to_vec()))
        .unwrap()
    }

    #[test]
    fn a_chain_checks_link_by_link() {
        let (op, ctl, head) = (key(1), key(2), key(3));
        let c = link(&op, None, id(&ctl), Role::Controller, "site");
        let h = link(&ctl, Some(&c), id(&head), Role::Head, "cell:berlin");
        let l = link(&head, Some(&h), id(&key(4)), Role::Leaf, "cell:berlin");
        assert_eq!(c.check(None, &id(&op), "home", NOW), Ok(()));
        assert_eq!(h.check(Some(&c), &id(&op), "home", NOW), Ok(()));
        assert_eq!(l.check(Some(&h), &id(&op), "home", NOW), Ok(()));
    }

    #[test]
    fn a_link_cannot_outlive_widen_or_skip_a_level() {
        let (op, ctl, head) = (key(1), key(2), key(3));
        let c = link(&op, None, id(&ctl), Role::Controller, "site");
        let h = link(&ctl, Some(&c), id(&head), Role::Head, "cell:berlin");

        let mut long = h.clone();
        long.not_after = c.not_after + 1;
        let long = long.signed_by(|m| Ok(ctl.sign(m).to_bytes().to_vec())).unwrap();
        assert!(long.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("outlive"));

        let deep = link(&ctl, Some(&c), id(&head), Role::Head, "cell:berlin/mitte");
        assert!(deep.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("one cell below"));

        let sideways = link(&head, Some(&h), id(&key(5)), Role::Head, "cell:paris/x");
        assert!(sideways.check(Some(&h), &id(&op), "home", NOW).unwrap_err().contains("wider"));
    }

    #[test]
    fn scale_must_nest_downwards() {
        let (op, ctl, head, sub) = (key(1), key(2), key(3), key(4));
        let c = link(&op, None, id(&ctl), Role::Controller, "site");
        let mut h = link(&ctl, Some(&c), id(&head), Role::Head, "cell:berlin");
        h.scale = Some(Scale::Home);
        let h = h.signed_by(|m| Ok(ctl.sign(m).to_bytes().to_vec())).unwrap();
        let mut s = link(&head, Some(&h), id(&sub), Role::Head, "cell:berlin/mitte");
        s.scale = Some(Scale::City);
        let s = s.signed_by(|m| Ok(head.sign(m).to_bytes().to_vec())).unwrap();
        assert!(s.check(Some(&h), &id(&op), "home", NOW).unwrap_err().contains("cannot sit inside"));
    }

    #[test]
    fn a_soft_key_cannot_head_a_cell() {
        let (op, ctl, head) = (key(1), key(2), key(3));
        let c = link(&op, None, id(&ctl), Role::Controller, "site");
        let mut h = link(&ctl, Some(&c), id(&head), Role::Head, "cell:berlin");
        h.assurance = Some(AssuranceClass::Soft);
        let h = h.signed_by(|m| Ok(ctl.sign(m).to_bytes().to_vec())).unwrap();
        assert!(h.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("hardware"));
    }

    #[test]
    fn a_tampered_scope_does_not_verify() {
        let (op, ctl) = (key(1), key(2));
        let c = link(&op, None, id(&ctl), Role::Controller, "site");
        let mut forged = link(&ctl, Some(&c), id(&key(3)), Role::Head, "cell:berlin");
        forged.scope = Scope::parse("cell:paris").unwrap();
        assert!(forged.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("does not verify"));
    }

    #[test]
    fn scope_reaches_its_cell_and_below_and_nothing_else() {
        let s = Scope::parse("cell:berlin/mitte").unwrap();
        assert!(s.admits_cell(Some("berlin/mitte")));
        assert!(s.admits_cell(Some("berlin/mitte/cafe")));
        assert!(!s.admits_cell(Some("berlin/mittel")));
        assert!(!s.admits_cell(Some("berlin")));
        assert!(!s.admits_cell(None));
        assert!(Scope::parse("cell:Berlin").is_err());
        assert!(Scope::parse("cell:a//b").is_err());
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"cell:berlin/mitte\"");
    }

    #[test]
    fn a_cell_scoped_request_is_refused_outside_its_cell() {
        let s = Scope::parse("cell:berlin").unwrap();
        let locate = |r: &str| match r {
            "pi-berlin" => Some("berlin".to_string()),
            "pi-paris" => Some("paris".to_string()),
            _ => None,
        };
        let req = |res: &str| Request {
            principal: "passkey:example.org:abc".into(),
            action: "drain".into(),
            resource: res.into(),
            roles: vec![],
        };
        assert!(s.admits_request(&req("pi-berlin"), locate).is_ok());
        assert!(s.admits_request(&req("pi-paris"), locate).unwrap_err().contains("outside"));
        assert!(s.admits_request(&req("core-1"), locate).unwrap_err().contains("core cluster"));
        assert!(s.admits_request(&req("*"), locate).is_err());
    }

    // P-256 keys below are generated inside these tests and exist only here.
    // Outside tests a P-256 key is held by hardware and signs through a
    // `MessageSigner`; nothing in the crate makes or holds one.

    /// A test-only P-256 signer, answering in DER or in raw `r || s`.
    struct TestP256 {
        key: p256::ecdsa::SigningKey,
        der: bool,
    }

    impl TestP256 {
        fn new(n: u8, der: bool) -> TestP256 {
            TestP256 { key: p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap(), der }
        }
    }

    impl MessageSigner for TestP256 {
        fn public_key(&self) -> anyhow::Result<SignerKey> {
            // As `rpi-fw-crypto pubkey` reports it: a DER SubjectPublicKeyInfo.
            let mut spki = P256_SPKI_PREFIX.to_vec();
            spki.extend_from_slice(self.key.verifying_key().to_sec1_point(false).as_bytes());
            Ok(SignerKey::P256(spki))
        }

        fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
            use p256::ecdsa::signature::Signer as _;
            let sig: p256::ecdsa::Signature = self.key.sign(message);
            Ok(if self.der { sig.to_der().as_bytes().to_vec() } else { sig.to_bytes().to_vec() })
        }
    }

    fn pid(k: &TestP256) -> String {
        signer_id(k).unwrap()
    }

    fn link_from(
        issuer: String,
        sign: &dyn MessageSigner,
        above: Option<&CellDelegation>,
        holder: String,
        role: Role,
        scope: &str,
    ) -> CellDelegation {
        CellDelegation {
            site: "home".into(),
            issuer,
            holder,
            role,
            scope: Scope::parse(scope).unwrap(),
            scale: (role == Role::Head).then_some(Scale::Business),
            assurance: (role != Role::Manager).then_some(AssuranceClass::Device),
            leaf_min_class: None,
            endpoint: String::new(),
            name: String::new(),
            parent: above.map(|a| a.digest()),
            not_before: NOW - 10,
            not_after: above.map(|a| a.not_after).unwrap_or(NOW + YEAR),
            signature: String::new(),
        }
        .signed_with(sign)
        .unwrap()
    }

    #[test]
    fn a_p256_key_is_named_one_way_whatever_form_it_arrives_in() {
        let k = TestP256::new(7, true);
        let point = k.key.verifying_key().to_sec1_point(false);
        let compressed = k.key.verifying_key().to_sec1_point(true);
        let want = format!("p256:{}", hex::encode(compressed.as_bytes()));
        assert_eq!(pid(&k), want);
        assert_eq!(CellKey::normalise(&format!("p256:{}", hex::encode(point.as_bytes()))).unwrap(), want);
        let SignerKey::P256(spki) = k.public_key().unwrap() else { unreachable!() };
        assert_eq!(CellKey::normalise(&format!("p256:{}", hex::encode(spki))).unwrap(), want);
        assert_eq!(CellKey::normalise(&want).unwrap(), want);
        assert!(CellKey::parse(&want).is_ok());
        // A link carries only the compressed form, so holders compare as text.
        let long = format!("p256:{}", hex::encode(point.as_bytes()));
        assert!(CellKey::parse(&long).unwrap_err().contains("one way"));
        assert!(CellKey::parse("p256:02").is_err());
        assert!(CellKey::parse(&format!("p256:02{}", "ff".repeat(32))).is_err());
        // A bare hex key is still Ed25519.
        let ed = hex::encode(key(1).verifying_key().as_bytes());
        assert_eq!(CellKey::normalise(&ed).unwrap(), id(&key(1)));
    }

    #[test]
    fn a_p256_signature_verifies_in_der_and_in_raw_form() {
        let (der, raw) = (TestP256::new(7, true), TestP256::new(7, false));
        let k = CellKey::parse(&pid(&der)).unwrap();
        let m = b"a message";
        let d = der.sign(m).unwrap();
        let r = raw.sign(m).unwrap();
        assert_ne!(d.len(), 64);
        assert_eq!(r.len(), 64);
        assert_eq!(k.verify(m, &d), Ok(()));
        assert_eq!(k.verify(m, &r), Ok(()));
        // Both are kept as the same 64 bytes.
        assert_eq!(k.seal(m, &d).unwrap().len(), 128);
        assert_eq!(k.seal(m, &d).unwrap(), k.seal(m, &r).unwrap());
        assert!(k.verify(b"another message", &d).is_err());
        assert!(k.verify(m, &d[..d.len() - 1]).unwrap_err().contains("neither"));
    }

    #[test]
    fn p256_holders_and_signers_round_trip() {
        for der in [true, false] {
            let op = key(1);
            let (ctl, head) = (TestP256::new(2, der), TestP256::new(3, der));
            let c = link(&op, None, pid(&ctl), Role::Controller, "site");
            let h = link_from(pid(&ctl), &ctl, Some(&c), pid(&head), Role::Head, "cell:berlin");
            let l = link_from(pid(&head), &head, Some(&h), pid(&TestP256::new(4, der)), Role::Leaf, "cell:berlin");
            assert_eq!(c.check(None, &id(&op), "home", NOW), Ok(()));
            assert_eq!(h.check(Some(&c), &id(&op), "home", NOW), Ok(()));
            assert_eq!(h.check_anchor(&pid(&ctl), "home", NOW), Ok(()));
            assert_eq!(l.check(Some(&h), &id(&op), "home", NOW), Ok(()));
            // Kept as JSON and read back, the chain still checks.
            let back: CellDelegation = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
            assert_eq!(back.check(Some(&h), &id(&op), "home", NOW), Ok(()));
            assert_eq!(back.digest(), l.digest());
        }
    }

    #[test]
    fn a_chain_may_mix_key_types() {
        // Ed25519 operator, P-256 controller, P-256 head, Ed25519 leaf.
        let op = key(1);
        let (ctl, head) = (TestP256::new(2, false), TestP256::new(3, true));
        let c = link(&op, None, pid(&ctl), Role::Controller, "site");
        let h = link_from(pid(&ctl), &ctl, Some(&c), pid(&head), Role::Head, "cell:berlin");
        let l = link_from(pid(&head), &head, Some(&h), id(&key(4)), Role::Leaf, "cell:berlin");
        assert_eq!(c.check(None, &id(&op), "home", NOW), Ok(()));
        assert_eq!(h.check(Some(&c), &id(&op), "home", NOW), Ok(()));
        assert_eq!(l.check(Some(&h), &id(&op), "home", NOW), Ok(()));

        // Narrowing, expiry and the signer chain hold for P-256 as for Ed25519.
        let mut wide = h.clone();
        wide.not_after = c.not_after + 1;
        let wide = wide.signed_with(&ctl).unwrap();
        assert!(wide.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("outlive"));
        assert!(h.check(Some(&c), &id(&op), "home", c.not_after).unwrap_err().contains("is live"));
        let stranger = TestP256::new(9, true);
        let forged = link_from(pid(&stranger), &stranger, Some(&h), id(&key(5)), Role::Leaf, "cell:berlin");
        assert!(forged.check(Some(&h), &id(&op), "home", NOW).unwrap_err().contains("but the link above names"));
    }

    #[test]
    fn a_tampered_p256_signature_is_refused() {
        let op = key(1);
        let (ctl, head) = (TestP256::new(2, true), TestP256::new(3, true));
        let c = link(&op, None, pid(&ctl), Role::Controller, "site");
        let h = link_from(pid(&ctl), &ctl, Some(&c), pid(&head), Role::Head, "cell:berlin");

        let mut flipped = h.clone();
        let mut raw = hex::decode(&flipped.signature).unwrap();
        raw[40] ^= 1;
        flipped.signature = hex::encode(raw);
        assert!(flipped.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("does not verify"));

        let mut moved = h.clone();
        moved.scope = Scope::parse("cell:paris").unwrap();
        assert!(moved.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("does not verify"));

        // A signer holding another key is refused before anything is kept.
        let mut unsigned = h.clone();
        unsigned.signature.clear();
        assert!(unsigned.clone().signed_with(&head).unwrap_err().contains("this signer holds"));
        assert!(unsigned.signed_by(|m| Ok(head.sign(m).unwrap())).unwrap_err().contains("did not sign as"));
    }

    #[test]
    fn a_p256_head_must_still_hold_its_key_in_hardware() {
        let op = key(1);
        let ctl = TestP256::new(2, true);
        let c = link(&op, None, pid(&ctl), Role::Controller, "site");
        let mut h = link_from(pid(&ctl), &ctl, Some(&c), pid(&TestP256::new(3, true)), Role::Head, "cell:berlin");
        h.assurance = Some(AssuranceClass::Soft);
        let h = h.signed_with(&ctl).unwrap();
        assert!(h.check(Some(&c), &id(&op), "home", NOW).unwrap_err().contains("hardware"));
    }
}
