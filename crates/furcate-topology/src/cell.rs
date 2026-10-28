//! Edge cells: clusters inside the site, read back from the chain that made
//! them.
//!
//! A site is a core cluster and the cells it parents. A cell is a gateway
//! head, an optional edge inference machine and the leaves attached to it,
//! and it is a cluster in its own right: its own membership, workloads,
//! registry and console, running when the link above it is down. Cells nest,
//! so a city cell holds district or business cells, each with a head of its
//! own.
//!
//! ## The tree is the chain
//!
//! Nobody writes the tree down. The operator names a controller, the
//! controller names a cell's head, the head names its leaves and the heads of
//! its sub-cells, and each of those is a [`CellDelegation`] signed by the key
//! the link above it named. [`CellTree::derive`] reads the links back and
//! keeps the ones whose whole chain checks, so the view cannot drift from the
//! trust: a cell that appears here is a cell somebody with the authority to
//! make it made. A link that does not check is listed with the reason, never
//! dropped.
//!
//! ## Control stays local, ownership rolls up
//!
//! A head holds its own link and the key and endpoint of whatever enrolled it
//! ([`Upstream`]), and nothing else about the fleet above it. Upward it sends
//! [`RollUp`]s: counts and one health line, no keys, names or readings. When
//! the link is cut, [`CellLocal`] keeps the cell running on its last known
//! good links and registry, and queues the roll-ups it could not send.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use furcate_authn::{Evidence, Principal};
use furcate_identity::AssuranceClass;
pub use furcate_policy::delegation::{
    ed25519_id, ed25519_key, p256_id, signer_id, CellDelegation, CellKey, Role, Scale, Scope,
};
use furcate_sense::leaf::Attachment;
use furcate_sense::registry::Sensor;
use serde::{Deserialize, Serialize};

/// A machine, leaf or controller as the chain names it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Member {
    /// The key the link names, `ed25519:<hex>` or `p256:<hex>`.
    pub holder: String,
    pub name: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub assurance: Option<AssuranceClass>,
    /// When the link that names it ends.
    pub until: u64,
}

impl Member {
    fn of(d: &CellDelegation) -> Member {
        Member {
            holder: d.holder.clone(),
            name: d.name.clone(),
            endpoint: d.endpoint.clone(),
            assurance: d.assurance,
            until: d.not_after,
        }
    }

    /// Whether `id` names this member, by key or by name.
    pub fn is(&self, id: &str) -> bool {
        self.holder == id || (!self.name.is_empty() && self.name == id)
    }
}

/// One cell and the cells inside it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cell {
    /// The cell's path, `berlin/mitte`.
    pub id: String,
    pub scale: Scale,
    /// 1 for a cell directly under a controller.
    pub depth: usize,
    pub head: Member,
    /// The lowest class a leaf may hold to attach here, from the head's
    /// signed link: `device` unless the operator set it otherwise.
    pub leaf_min_class: AssuranceClass,
    /// The key that enrolled the head: a controller, or the head of the cell
    /// this one sits inside.
    pub parent: String,
    pub edge_ai: Vec<Member>,
    pub leaves: Vec<Member>,
    /// Passkey holders who manage this cell and the cells inside it.
    pub managers: Vec<String>,
    pub cells: Vec<Cell>,
}

impl Cell {
    pub fn scope(&self) -> Scope {
        Scope::Cell(self.id.clone())
    }

    fn find(&self, path: &str) -> Option<&Cell> {
        if self.id == path {
            return Some(self);
        }
        self.cells.iter().find_map(|c| c.find(path))
    }

    /// Every machine and leaf in this cell itself, not its sub-cells.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        std::iter::once(&self.head).chain(self.edge_ai.iter()).chain(self.leaves.iter())
    }

    fn walk<'a>(&'a self, out: &mut Vec<&'a Cell>) {
        out.push(self);
        for c in &self.cells {
            c.walk(out);
        }
    }
}

/// A link the tree did not take, and why.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Refused {
    pub holder: String,
    pub role: Role,
    pub scope: Scope,
    pub why: String,
}

/// What the chain is checked against.
#[derive(Clone, Debug)]
pub enum Root {
    /// The operator's key: a core-cluster node sees every link from the top.
    Operator(String),
    /// A head's own link: the head sees its cell and everything below, and
    /// trusts the key that enrolled it for that one link only.
    Anchor(CellDelegation),
}

/// The site's cells as the signed chain describes them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CellTree {
    pub site: String,
    /// Shown only to a site-scoped caller.
    pub controllers: Vec<Member>,
    /// Site-wide managers: passkey holders the operator named for the site.
    pub managers: Vec<String>,
    pub cells: Vec<Cell>,
    pub refused: Vec<Refused>,
    /// The links that checked, kept for scope lookups and never sent out.
    #[serde(skip)]
    accepted: Vec<CellDelegation>,
}

impl CellTree {
    /// Read the tree back from a set of links.
    ///
    /// A link is taken only when every link from the root down to it checks:
    /// signed by the holder above, narrower in scope, no longer-lived, and of
    /// a role its parent may name. A link whose chain does not reach the root
    /// is refused, as is any chain that names one key twice.
    pub fn derive(site: &str, root: &Root, links: &[CellDelegation], now: u64) -> CellTree {
        let mut by_digest: BTreeMap<String, &CellDelegation> = BTreeMap::new();
        for l in links {
            by_digest.insert(l.digest(), l);
        }
        let anchor_digest = match root {
            Root::Anchor(a) => {
                by_digest.insert(a.digest(), a);
                Some(a.digest())
            }
            Root::Operator(_) => None,
        };

        let mut verdicts: BTreeMap<String, Result<(), String>> = BTreeMap::new();
        let mut tree = CellTree { site: site.to_string(), ..Default::default() };
        for (digest, link) in &by_digest {
            let verdict = judge(digest, site, root, anchor_digest.as_deref(), &by_digest, &mut verdicts, now);
            match verdict {
                Ok(()) => tree.accepted.push((*link).clone()),
                Err(why) => tree.refused.push(Refused {
                    holder: link.holder.clone(),
                    role: link.role,
                    scope: link.scope.clone(),
                    why,
                }),
            }
        }

        // One head per cell. A re-enrolled gateway has a newer link; the older
        // one is shown as superseded rather than quietly vanishing.
        let mut heads: BTreeMap<String, &CellDelegation> = BTreeMap::new();
        let mut superseded = Vec::new();
        for l in tree.accepted.iter().filter(|l| l.role == Role::Head) {
            let path = l.scope.path().unwrap_or_default().to_string();
            match heads.get(&path) {
                Some(cur) if (cur.not_before, cur.digest()) >= (l.not_before, l.digest()) => superseded.push((l.clone(), cur.holder.clone())),
                Some(cur) => {
                    superseded.push(((*cur).clone(), l.holder.clone()));
                    heads.insert(path, l);
                }
                None => {
                    heads.insert(path, l);
                }
            }
        }
        let mut cells: BTreeMap<String, Cell> = heads
            .iter()
            .map(|(path, h)| {
                let cell = Cell {
                    id: path.clone(),
                    scale: h.scale.unwrap_or(Scale::Other),
                    depth: h.scope.depth(),
                    head: Member::of(h),
                    leaf_min_class: h.leaf_min_class.unwrap_or(furcate_identity::leaf::DEFAULT_LEAF_FLOOR),
                    parent: h.issuer.clone(),
                    edge_ai: Vec::new(),
                    leaves: Vec::new(),
                    managers: Vec::new(),
                    cells: Vec::new(),
                };
                (path.clone(), cell)
            })
            .collect();
        for (old, by) in superseded {
            tree.refused.push(Refused {
                holder: old.holder.clone(),
                role: old.role,
                scope: old.scope.clone(),
                why: format!("superseded: the cell was enrolled again, to {by}"),
            });
        }

        let mut orphans = Vec::new();
        for l in &tree.accepted {
            match (l.role, l.scope.path()) {
                (Role::Controller, _) => tree.controllers.push(Member::of(l)),
                (Role::Manager, None) => tree.managers.push(l.holder.clone()),
                (Role::Head, _) => {}
                (role, Some(path)) => match cells.get_mut(path) {
                    Some(c) => match role {
                        Role::EdgeAi => c.edge_ai.push(Member::of(l)),
                        Role::Leaf => c.leaves.push(Member::of(l)),
                        _ => c.managers.push(l.holder.clone()),
                    },
                    None => orphans.push(l.clone()),
                },
                (_, None) => orphans.push(l.clone()),
            }
        }
        for l in orphans {
            tree.refused.push(Refused {
                holder: l.holder.clone(),
                role: l.role,
                scope: l.scope.clone(),
                why: format!("no cell {} has a head here", l.scope.as_string()),
            });
        }

        // Nest, deepest first, so every cell is complete before it moves into
        // the one above it.
        let mut paths: Vec<String> = cells.keys().cloned().collect();
        paths.sort_by_key(|p| std::cmp::Reverse(p.split('/').count()));
        for path in paths {
            let up = match path.rsplit_once('/') {
                Some((up, _)) => up.to_string(),
                None => continue,
            };
            if cells.contains_key(&up) {
                let c = cells.remove(&path).expect("present");
                cells.get_mut(&up).expect("present").cells.push(c);
            }
        }
        tree.cells = cells.into_values().collect();
        sort_cells(&mut tree.cells);
        tree.controllers.sort_by(|a, b| a.holder.cmp(&b.holder));
        tree.refused.sort_by(|a, b| (&a.scope, &a.holder).cmp(&(&b.scope, &b.holder)));
        tree
    }

    /// Every cell, outermost first.
    pub fn all(&self) -> Vec<&Cell> {
        let mut out = Vec::new();
        for c in &self.cells {
            c.walk(&mut out);
        }
        out
    }

    pub fn find(&self, path: &str) -> Option<&Cell> {
        self.cells.iter().find_map(|c| c.find(path))
    }

    /// The scope a holder's own link gives it, if it holds one here.
    pub fn scope_of(&self, holder: &str) -> Option<Scope> {
        self.accepted
            .iter()
            .filter(|l| l.holder == holder || (!l.name.is_empty() && l.name == holder))
            .map(|l| l.scope.clone())
            .min_by_key(|s| s.depth())
    }

    /// The scope a proved caller may see and act in.
    ///
    /// The operator reaches the whole site. Anyone else reaches what their
    /// own link names, and somebody with no link here reaches nothing: being
    /// able to prove who you are is not the same as having been given a cell.
    pub fn scope_for(&self, p: &Principal) -> Result<Scope, String> {
        if p.evidence == Evidence::OperatorSignature {
            return Ok(Scope::Site);
        }
        // A token delegated by a cell's manager carries that manager's reach,
        // never more: the root of its chain is the person the link names.
        let root = match &p.evidence {
            Evidence::Delegated { root, .. } => self.scope_of(root),
            _ => None,
        };
        self.scope_of(&p.id).or(root).ok_or_else(|| {
            format!("{} holds no cell link on this site, so no cell is theirs to see", p.id)
        })
    }

    /// The link that names this holder as a controller or a head.
    pub fn link_of(&self, holder: &str) -> Option<&CellDelegation> {
        self.accepted
            .iter()
            .find(|l| l.holder == holder && matches!(l.role, Role::Controller | Role::Head))
    }

    /// The scope of the manager link held by this passkey credential, if
    /// any. Credential ids are matched as the approval names them.
    pub fn scope_of_credential(&self, credential_id: &str) -> Option<Scope> {
        self.accepted
            .iter()
            .filter(|l| l.role == Role::Manager)
            .find(|l| l.holder.splitn(3, ':').nth(2) == Some(credential_id))
            .map(|l| l.scope.clone())
    }

    /// Whether an approved order stays inside the scope of every approver
    /// who holds a cell manager's link. An approver with no such link is the
    /// site's own and is not narrowed here; one who manages a cell lends the
    /// order no reach beyond that cell.
    pub fn order_within_approvers(
        &self,
        order: &furcate_authn::order::Order,
        approvers: &[String],
    ) -> Result<(), String> {
        for a in approvers {
            if let Some(scope) = self.scope_of_credential(a) {
                scope
                    .admits_order(order, |id| self.locate(id))
                    .map_err(|why| format!("approver {a} manages {}: {why}", scope.as_string()))?;
            }
        }
        Ok(())
    }

    /// Whether a grant, used for this request, stays inside every cell its
    /// granter, holder and the caller are confined to. Anyone who holds a
    /// cell link here reaches only that cell, whatever a grant says; someone
    /// with no cell link is the site's own and is not narrowed here.
    pub fn grant_within_cells(&self, g: &furcate_policy::Grant, r: &furcate_policy::Request) -> Result<(), String> {
        for who in [&g.from, &g.to, &r.principal] {
            if let Some(scope) = self.scope_of(who) {
                scope
                    .admits_request(r, |id| self.locate(id))
                    .map_err(|why| format!("{who} is confined to {}: {why}", scope.as_string()))?;
            }
        }
        Ok(())
    }

    /// The grants, as `delegation::evaluate` rules on them, with the cell
    /// check applied: only a grant that stays inside the cells of everyone it
    /// involves may permit the request. When every grant that would have
    /// covered it reaches outside a cell, the refusal says which and why.
    pub fn evaluate_grants(
        &self,
        grants: &[furcate_policy::Grant],
        r: &furcate_policy::Request,
        now: u64,
    ) -> Option<furcate_policy::Decision> {
        let mut outside = None;
        let usable: Vec<furcate_policy::Grant> = grants
            .iter()
            .filter(|g| match self.grant_within_cells(g, r) {
                Ok(()) => true,
                Err(why) => {
                    if g.covers(r, now) && outside.is_none() {
                        outside = Some(why);
                    }
                    false
                }
            })
            .cloned()
            .collect();
        furcate_policy::delegation::evaluate(&usable, r, now).or_else(|| {
            outside.map(|why| furcate_policy::Decision {
                allowed: false,
                because: format!("a grant covers this, but not here: {why}"),
                structural: false,
            })
        })
    }

    /// The cell a machine or leaf belongs to, by key or name. `None` for
    /// anything in no cell: a controller, the rest of the core cluster, or a
    /// machine this tree does not know.
    pub fn locate(&self, id: &str) -> Option<String> {
        self.all().into_iter().find(|c| c.members().any(|m| m.is(id))).map(|c| c.id.clone())
    }

    /// The part of the tree a scope may see: its cells and the cells inside
    /// them. A cell scope sees no controller, no site manager, no sibling and
    /// nothing of the core cluster.
    pub fn visible_to(&self, scope: &Scope) -> CellTree {
        let Scope::Cell(path) = scope else {
            return self.clone();
        };
        CellTree {
            site: self.site.clone(),
            controllers: Vec::new(),
            managers: Vec::new(),
            cells: self.find(path).cloned().into_iter().collect(),
            refused: self.refused.iter().filter(|r| r.scope.within(scope)).cloned().collect(),
            accepted: self.accepted.iter().filter(|l| l.scope.within(scope)).cloned().collect(),
        }
    }

}

/// The links a node holds, as stored: `{"site": ..., "links": [...]}`.
///
/// The site is named once here and every link must name the same one, since
/// each link signs its site: a link carried in from another site is refused
/// rather than grafted on.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellFile {
    pub site: String,
    pub links: Vec<CellDelegation>,
    /// Links the operator withdrew before they lapsed. Lapsing is how a link
    /// normally ends; this is for one that must end sooner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<CellRevocation>,
}

/// The operator withdrawing one link before it lapses.
///
/// Names the link by its digest, so it withdraws exactly that link and
/// nothing signed later for the same holder. Everything below a withdrawn
/// link falls with it, since its chain no longer reaches the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellRevocation {
    pub site: String,
    /// The withdrawn link's [`CellDelegation::digest`].
    pub link: String,
    pub reason: String,
    pub at: u64,
    /// `ed25519:<hex>`, the operator's key.
    pub issuer: String,
    /// Hex signature by `issuer` over [`CellRevocation::signed_bytes`].
    #[serde(default)]
    pub signature: String,
}

impl CellRevocation {
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut m = b"furcate:cell-revocation:v1\0".to_vec();
        for f in [&self.site, &self.link, &self.reason, &self.at.to_string(), &self.issuer] {
            m.extend_from_slice(&(f.len() as u64).to_be_bytes());
            m.extend_from_slice(f.as_bytes());
        }
        m
    }

    /// Sign with whatever holds the operator's key; the key never passes
    /// through here.
    pub fn signed_by(mut self, sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>) -> Result<Self, String> {
        let message = self.signed_bytes();
        self.signature = CellKey::parse(&self.issuer)?.seal(&message, &sign(&message)?)?;
        Ok(self)
    }

    /// Whether the operator, `operator` being its key, signed this for `site`.
    pub fn verify(&self, operator: &str, site: &str) -> Result<(), String> {
        if self.site != site {
            return Err(format!("the revocation is for site {}, not {site}", self.site));
        }
        if self.issuer != operator {
            return Err(format!("signed by {}, and only the operator {operator} revokes a link", self.issuer));
        }
        CellKey::parse(&self.issuer)?
            .verify_hex(&self.signed_bytes(), &self.signature)
            .map_err(|e| format!("the revocation's signature does not verify under {}: {e}", self.issuer))
    }
}

/// Take out every link the operator withdrew.
///
/// A revocation that does not verify, or that arrives where the operator's
/// key is not known, is not applied: anyone could otherwise end a cell by
/// writing a line into a file. It is reported, and the link runs on to its
/// own end.
pub fn apply_revocations(
    file: &CellFile,
    operator: Option<&str>,
) -> (Vec<CellDelegation>, Vec<Refused>, Vec<String>) {
    let mut withdrawn: BTreeMap<String, String> = BTreeMap::new();
    let mut unapplied = Vec::new();
    for r in &file.revoked {
        let checked = match operator {
            Some(op) => r.verify(op, &file.site),
            None => Err("this node does not hold the operator's key, so it cannot check it".into()),
        };
        match checked {
            Ok(()) => {
                withdrawn.insert(r.link.clone(), r.reason.clone());
            }
            Err(why) => unapplied.push(format!(
                "revocation of {} is not applied: {why}",
                &r.link[..12.min(r.link.len())]
            )),
        }
    }
    let mut kept = Vec::new();
    let mut refused = Vec::new();
    for l in &file.links {
        match withdrawn.get(&l.digest()) {
            Some(reason) => refused.push(Refused {
                holder: l.holder.clone(),
                role: l.role,
                scope: l.scope.clone(),
                why: format!("the operator revoked this link: {reason}"),
            }),
            None => kept.push(l.clone()),
        }
    }
    (kept, refused, unapplied)
}

impl CellFile {
    /// No file means no cells. A file that does not parse is an error, not an
    /// empty tree, so a damaged file is never mistaken for a site without
    /// cells.
    pub fn load(path: &Path) -> Result<Option<CellFile>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| format!("{} does not parse as cell links: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }
}

fn sort_cells(cells: &mut [Cell]) {
    cells.sort_by(|a, b| a.id.cmp(&b.id));
    for c in cells.iter_mut() {
        c.edge_ai.sort_by(|a, b| a.holder.cmp(&b.holder));
        c.leaves.sort_by(|a, b| a.holder.cmp(&b.holder));
        c.managers.sort();
        sort_cells(&mut c.cells);
    }
}

/// Walk a link's chain up to the root and check it top-down.
fn judge(
    digest: &str,
    site: &str,
    root: &Root,
    anchor: Option<&str>,
    by_digest: &BTreeMap<String, &CellDelegation>,
    verdicts: &mut BTreeMap<String, Result<(), String>>,
    now: u64,
) -> Result<(), String> {
    if let Some(v) = verdicts.get(digest) {
        return v.clone();
    }
    // Collect the chain, link first, root last.
    let mut chain: Vec<&CellDelegation> = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut cur = by_digest[digest];
    let verdict = loop {
        if !seen_keys.insert(cur.holder.clone()) {
            break Err(format!("{} appears twice in its own chain", cur.holder));
        }
        if chain.len() > furcate_policy::delegation::MAX_CELL_DEPTH + 3 {
            break Err("the chain is deeper than any cell may nest".into());
        }
        chain.push(cur);
        if anchor == Some(cur.digest().as_str()) {
            break Ok(());
        }
        match &cur.parent {
            None => break Ok(()),
            Some(p) => match by_digest.get(p) {
                Some(up) => cur = *up,
                None => {
                    break Err(match root {
                        Root::Anchor(_) => format!(
                            "its chain does not reach this cell's own link; {} is not held here",
                            &p[..12.min(p.len())]
                        ),
                        Root::Operator(_) => format!(
                            "its parent link {} is not held here",
                            &p[..12.min(p.len())]
                        ),
                    })
                }
            },
        }
    };
    let verdict = verdict.and_then(|()| {
        let top = chain[chain.len() - 1];
        match root {
            Root::Operator(k) => top.check(None, k, site, now),
            Root::Anchor(a) => {
                if top.digest() != a.digest() {
                    return Err("its chain does not pass through this cell's own link".into());
                }
                top.check_anchor(&a.issuer, site, now)
            }
        }
        .map_err(|why| if chain.len() > 1 { format!("a link above it: {why}") } else { why })?;
        for w in (0..chain.len() - 1).rev() {
            let (child, up) = (chain[w], chain[w + 1]);
            child.check(Some(up), "", site, now).map_err(|why| {
                if w > 0 {
                    format!("a link above it: {why}")
                } else {
                    why
                }
            })?;
        }
        Ok(())
    });
    verdicts.insert(digest.to_string(), verdict.clone());
    verdict
}

/// The links held across several files, which must all name one site. A
/// missing file holds nothing; an unreadable one is an error.
pub fn merge_files(paths: &[std::path::PathBuf], site: Option<&str>) -> Result<CellFile, String> {
    let mut out = CellFile { site: site.unwrap_or_default().to_string(), links: Vec::new(), revoked: Vec::new() };
    for path in paths {
        let Some(file) = CellFile::load(path)? else { continue };
        if file.links.is_empty() && file.revoked.is_empty() {
            continue;
        }
        if out.site.is_empty() {
            out.site = file.site.clone();
        }
        if file.site != out.site {
            return Err(format!(
                "{} is for site {}, and this node's cells belong to {}",
                path.display(),
                file.site,
                out.site
            ));
        }
        out.links.extend(file.links);
        out.revoked.extend(file.revoked);
    }
    Ok(out)
}

/// The operator's key as cell links name it, from the hex `operator.pub`.
pub fn operator_root(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!("{} cannot be read ({e}), so no cell link can be checked", path.display())
    })?;
    let raw = hex::decode(text.trim()).map_err(|e| format!("{} is not hex: {e}", path.display()))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{} is {} bytes, expected 32", path.display(), raw.len()))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| format!("{} is not a valid key", path.display()))?;
    Ok(ed25519_id(&key))
}

/// The tree a core node holds: the links in `files`, checked against the
/// operator's key. No links is an empty tree and needs no key.
pub fn core_tree(files: &[std::path::PathBuf], operator_pub: &Path, now: u64) -> Result<CellTree, String> {
    let file = merge_files(files, None)?;
    if file.links.is_empty() {
        return Ok(CellTree::default());
    }
    let operator = operator_root(operator_pub)?;
    Ok(derive_revoking(&file, &Root::Operator(operator.clone()), Some(&operator), now))
}

/// Why the operator withdrew the link with this digest, if a revocation it
/// verifiably signed says so.
pub fn revoked_reason(file: &CellFile, operator: Option<&str>, digest: &str) -> Option<String> {
    let op = operator?;
    file.revoked
        .iter()
        .find(|r| r.link == digest && r.verify(op, &file.site).is_ok())
        .map(|r| r.reason.clone())
}

/// Read the tree back from a file, with the operator's revocations applied:
/// a withdrawn link is listed as refused with the operator's reason, and
/// whatever sat below it falls with it.
pub fn derive_revoking(file: &CellFile, root: &Root, operator: Option<&str>, now: u64) -> CellTree {
    let (links, revoked, unapplied) = apply_revocations(file, operator);
    for why in unapplied {
        eprintln!("cells: {why}");
    }
    let mut tree = CellTree::derive(&file.site, root, &links, now);
    tree.refused.extend(revoked);
    tree
}

/// What the cells below last reported, by cell path, with when it arrived.
pub type Reported = BTreeMap<String, (RollUp, u64)>;

/// Read what a node recorded from the cells below it. Missing is nothing
/// reported yet; unreadable is an error.
pub fn load_reported(path: &Path) -> Result<Reported, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map_err(|e| format!("{} does not parse as cell reports: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Reported::new()),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

/// A gateway asking to head a cell.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeadEnrolment {
    /// The gateway's own key, `ed25519:<hex>` or `p256:<hex>`, held by its
    /// hardware: a Pi's firmware-held OTP key is `p256:` and `Device`, a TPM
    /// key `p256:` and `Tpm`.
    pub gateway: String,
    pub assurance: AssuranceClass,
    /// Where the gateway answers.
    pub endpoint: String,
    pub name: String,
    /// The new cell's last path segment; the rest is the enroller's scope.
    pub cell: String,
    pub scale: Scale,
    /// When the link should end. Never later than the enroller's own.
    pub until: u64,
    /// The cell's leaf floor, as the operator sets it; `None` is `device`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_min_class: Option<AssuranceClass>,
}

/// The link a controller, or the head of an enclosing cell, signs to make a
/// gateway the head of a new cell.
///
/// Returned unsigned: the enroller signs it with the key its hardware holds,
/// through [`CellDelegation::signed_by`]. Everything a node will later check
/// is checked here first, so an enrolment that would be refused is refused
/// before anything is signed.
pub fn enrol_head(enroller: &CellDelegation, e: &HeadEnrolment, now: u64) -> Result<CellDelegation, String> {
    if !matches!(enroller.role, Role::Controller | Role::Head) {
        return Err(format!("a {} may not enrol a cell head", enroller.role.as_str()));
    }
    let scope = match &enroller.scope {
        Scope::Site => Scope::cell(&e.cell)?,
        Scope::Cell(p) => Scope::cell(&format!("{p}/{}", e.cell))?,
    };
    CellKey::parse(&e.gateway)?;
    if e.assurance < AssuranceClass::Device {
        return Err(format!(
            "{} holds its key as {:?}; a cell head must hold its key in hardware, so a copied \
             disk cannot become the cell",
            e.name, e.assurance
        ));
    }
    if e.until > enroller.not_after {
        return Err(format!(
            "asked to run until {}, past {}, when the enroller's own link ends",
            e.until, enroller.not_after
        ));
    }
    Ok(CellDelegation {
        site: enroller.site.clone(),
        issuer: enroller.holder.clone(),
        holder: e.gateway.clone(),
        role: Role::Head,
        scope,
        scale: Some(e.scale),
        assurance: Some(e.assurance),
        leaf_min_class: e.leaf_min_class,
        endpoint: e.endpoint.clone(),
        name: e.name.clone(),
        parent: Some(enroller.digest()),
        not_before: now,
        not_after: e.until,
        signature: String::new(),
    })
}

/// The link a head signs for a leaf that attached to it through
/// `furcate-sense`.
///
/// The leaf keeps the key it attached with, Ed25519 or P-256, and the class
/// its key custody earns ([`Attachment::assurance`]), recorded as it is and
/// never raised. A leaf below the cell's leaf floor, which the operator sets
/// in the head's signed link (`device` unless set), is refused, and the
/// refusal says how the operator lowers it.
pub fn enrol_leaf(head: &CellDelegation, att: &Attachment, until: u64, now: u64) -> Result<CellDelegation, String> {
    if head.role != Role::Head {
        return Err(format!("a {} does not hold leaves; a cell's head does", head.role.as_str()));
    }
    if att.parent != head.name && att.parent != head.holder {
        return Err(format!(
            "{} attached to {}, not to this head ({})",
            att.leaf_id, att.parent, head.name
        ));
    }
    let holder = CellKey::parse(&att.public_key)?.id();
    let assurance = att.assurance();
    furcate_identity::leaf::admits_leaf(head.leaf_min_class, assurance).map_err(|why| {
        let cell = head.scope.path().unwrap_or_default();
        format!(
            "leaf {} is not admitted to cell {cell}: {why} ({}). The operator sets the cell's \
             floor in the head's signed link: furcatectl cell leaf-floor --anchor <cell-anchor.json> \
             --class {assurance} --controller <addr:port>, then install the anchor on the head",
            att.leaf_id,
            att.assurance_reason()
        )
    })?;
    Ok(CellDelegation {
        site: head.site.clone(),
        issuer: head.holder.clone(),
        holder,
        role: Role::Leaf,
        scope: head.scope.clone(),
        scale: None,
        assurance: Some(assurance),
        leaf_min_class: None,
        endpoint: String::new(),
        name: att.leaf_id.clone(),
        parent: Some(head.digest()),
        not_before: now,
        not_after: until.min(head.not_after),
        signature: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Upward: what a head knows above it, and what it sends
// ---------------------------------------------------------------------------

/// Everything a head keeps about anything above its cell.
///
/// Its own link, and the key and endpoint of whatever enrolled it. No other
/// cell, no other controller, no operator inventory: a gateway that is
/// stolen or opened gives up its own cell and the address of one parent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub own: CellDelegation,
    /// The key that signed `own`, as [`CellKey`] names it.
    pub parent_key: String,
    pub parent_endpoint: String,
}

impl Upstream {
    pub fn new(own: CellDelegation, parent_endpoint: &str, now: u64) -> Result<Upstream, String> {
        own.check_anchor(&own.issuer, &own.site, now)?;
        Ok(Upstream {
            parent_key: own.issuer.clone(),
            parent_endpoint: parent_endpoint.to_string(),
            own,
        })
    }

    pub fn cell(&self) -> &Scope {
        &self.own.scope
    }
}

/// A head's anchor as installed at enrolment: its own link and the endpoint
/// of whatever enrolled it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorFile {
    own: CellDelegation,
    parent_endpoint: String,
}

/// The anchor at `path`, checked. No file is `None`: this node heads no cell.
/// A file that does not parse or whose link does not check is an error, never
/// read as "no anchor".
pub fn load_anchor(path: &Path, now: u64) -> Result<Option<Upstream>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let a: AnchorFile = serde_json::from_str(&text)
        .map_err(|e| format!("{} does not parse as a cell anchor: {e}", path.display()))?;
    Upstream::new(a.own, &a.parent_endpoint, now).map(Some).map_err(|why| format!("{} is refused: {why}", path.display()))
}

/// Where a node keeps the files its cell tree is read from.
#[derive(Clone, Debug)]
pub struct NodeFiles {
    /// `cell-anchor.json`, present when this node heads a cell.
    pub anchor: std::path::PathBuf,
    /// The link files: the operator's `cells.json` and the links this node
    /// signed itself.
    pub links: Vec<std::path::PathBuf>,
    /// `operator.pub`, the hex Ed25519 key revocations are checked against.
    pub operator_pub: std::path::PathBuf,
}

impl NodeFiles {
    /// The tree these files describe, read fresh. A head reads it from its
    /// own link down with the operator's revocations applied, and a head whose
    /// own link the operator revoked has no tree. A node that heads no cell
    /// reads the operator's links. An unreadable file is an error.
    pub fn tree(&self, now: u64) -> Result<CellTree, String> {
        if let Some(up) = load_anchor(&self.anchor, now)? {
            let file = merge_files(&self.links, Some(&up.own.site))?;
            let operator = operator_root(&self.operator_pub).ok();
            if let Some(why) = revoked_reason(&file, operator.as_deref(), &up.own.digest()) {
                return Err(format!("the operator revoked this cell's own link: {why}"));
            }
            return Ok(derive_revoking(&file, &Root::Anchor(up.own), operator.as_deref(), now));
        }
        core_tree(&self.links, &self.operator_pub, now)
    }

    /// The path of the cell this node heads and the tree read fresh, with
    /// its leaves as the chain names them now. An error when it heads none or
    /// its own cell does not derive.
    pub fn headed_tree(&self, now: u64) -> Result<(String, CellTree), String> {
        let up = load_anchor(&self.anchor, now)?.ok_or_else(|| {
            format!("this node heads no cell: {} is not installed", self.anchor.display())
        })?;
        let path = up.own.scope.path().unwrap_or_default().to_string();
        let tree = self.tree(now)?;
        if tree.find(&path).is_none() {
            return Err(format!("this node's own cell {path} did not derive from its links"));
        }
        Ok((path, tree))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Ok,
    Degraded,
    Down,
    /// Nothing in the cell has been measured.
    Unknown,
}

impl Health {
    pub fn as_str(&self) -> &'static str {
        match self {
            Health::Ok => "ok",
            Health::Degraded => "degraded",
            Health::Down => "down",
            Health::Unknown => "unknown",
        }
    }
}

/// How a machine's power supply is holding up, from the board's own report.
///
/// Worst last, so the larger of two is the more serious. Only ever built from
/// a fresh measurement: a missing or stale report is `None` where this is
/// held, never `Ok`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyState {
    /// Measured: no undervoltage, no throttling, nothing shed.
    Ok,
    /// The CPU is throttled or frequency-capped, from heat or supply.
    Throttled,
    /// The supply is below what the board needs right now.
    Undervoltage,
    /// The board is shedding load to stay up.
    Shedding,
}

impl SupplyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SupplyState::Ok => "ok",
            SupplyState::Throttled => "throttled",
            SupplyState::Undervoltage => "undervoltage",
            SupplyState::Shedding => "shedding load",
        }
    }
}

/// What one machine said about itself. Every field is what was measured;
/// absent means not measured, never zero.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MachineReading {
    pub up: bool,
    pub cores: Option<u32>,
    pub power_w: Option<f64>,
    pub workloads: Option<u32>,
    /// Its supply, from a fresh board report; `None` is not measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supply: Option<SupplyState>,
}

/// What one leaf reported through its head.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LeafReading {
    pub models: Vec<String>,
    pub streams: Vec<String>,
    pub battery_pct: Option<f64>,
    pub signal_dbm: Option<f64>,
    /// Unix seconds of its last verified reading.
    pub last_seen: Option<u64>,
}

/// Readings by member key or name.
#[derive(Clone, Debug, Default)]
pub struct Readings {
    /// By the id the source knows a machine by: its node id, from the site
    /// view. A cell record names a machine by the key it signs links with, or
    /// by name; `aliases` joins the two.
    pub machines: BTreeMap<String, MachineReading>,
    /// The id a machine is read under, by the cell key or name it answers to.
    /// Said by the machine in its own reading, and dropped for a key or name
    /// two machines both claim: a reading must never land on the wrong cell.
    pub aliases: BTreeMap<String, String>,
    pub leaves: BTreeMap<String, LeafReading>,
    /// Sensors from the cell's registry, matched to leaves by host.
    pub sensors: Vec<Sensor>,
    /// The latest roll-up each cell below reported for itself, by cell path,
    /// with when it arrived.
    pub reported: Reported,
}

impl Readings {
    /// What this member said about itself: under its key or name directly, or
    /// under the node id that key or name is known to belong to.
    pub fn machine(&self, m: &Member) -> Option<&MachineReading> {
        let by = |id: &str| self.machines.get(id).or_else(|| self.machines.get(self.aliases.get(id)?));
        by(&m.holder).or_else(|| if m.name.is_empty() { None } else { by(&m.name) })
    }

    fn leaf(&self, m: &Member) -> Option<&LeafReading> {
        self.leaves.get(&m.holder).or_else(|| self.leaves.get(&m.name))
    }
}

/// How long a leaf may go unheard and still count as reporting.
pub const LEAF_FRESH_SECS: u64 = 300;

/// One cell, summed: the only thing a cell sends upward.
///
/// Counts and a health state. No key, no name, no reading, no address: the
/// parent learns how the cell is, not what is in it.
///
/// A parent reads the fields it knows and drops the rest, so a child running
/// a newer release that reports more is still heard. What is dropped is never
/// kept or passed further up: the parent holds and forwards only this type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RollUp {
    pub cell: String,
    pub scale: Scale,
    pub health: Health,
    pub machines: u32,
    pub machines_up: u32,
    pub leaves: u32,
    pub leaves_reporting: u32,
    /// Leaves counted by the class their key custody earned, so a parent
    /// sees how many rest on readable silicon without learning which.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub leaf_classes: BTreeMap<AssuranceClass, u32>,
    pub sub_cells: u32,
    /// Summed over the machines that report power; `None` if none do.
    pub power_w: Option<f64>,
    /// The head's supply, when it measures one. A head that is undervolted,
    /// throttled or shedding load makes the cell degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_supply: Option<SupplyState>,
    pub at: u64,
}

impl RollUp {
    /// The cell in one line.
    pub fn line(&self) -> String {
        let power = match self.power_w {
            Some(w) => format!("{w:.0} W"),
            None => "power not measured".into(),
        };
        let classes = if self.leaf_classes.is_empty() {
            String::new()
        } else {
            let each: Vec<String> = self.leaf_classes.iter().rev().map(|(c, n)| format!("{n} {c}")).collect();
            format!(" ({})", each.join(", "))
        };
        let supply = match self.head_supply {
            Some(s) => format!(", head supply {}", s.as_str()),
            None => String::new(),
        };
        format!(
            "{}: {}, {}/{} machines up, {}/{} leaves reporting{classes}, {} sub-cells, {power}{supply}",
            self.cell,
            self.health.as_str(),
            self.machines_up,
            self.machines,
            self.leaves_reporting,
            self.leaves,
            self.sub_cells
        )
    }
}

/// Sum a cell and everything inside it.
pub fn roll_up(cell: &Cell, r: &Readings, now: u64) -> RollUp {
    let mut out = RollUp {
        cell: cell.id.clone(),
        scale: cell.scale,
        health: Health::Unknown,
        machines: 0,
        machines_up: 0,
        leaves: 0,
        leaves_reporting: 0,
        leaf_classes: BTreeMap::new(),
        sub_cells: 0,
        power_w: None,
        head_supply: None,
        at: now,
    };
    let mut measured = false;
    let mut head_down = false;
    if let Some(x) = r.machine(&cell.head) {
        out.head_supply = x.supply;
    }
    for m in std::iter::once(&cell.head).chain(cell.edge_ai.iter()) {
        out.machines += 1;
        if let Some(x) = r.machine(m) {
            measured = true;
            if x.up {
                out.machines_up += 1;
            } else if m.holder == cell.head.holder {
                head_down = true;
            }
            if let Some(w) = x.power_w {
                out.power_w = Some(out.power_w.unwrap_or(0.0) + w);
            }
        }
    }
    for l in &cell.leaves {
        out.leaves += 1;
        *out.leaf_classes.entry(l.assurance.unwrap_or(AssuranceClass::Soft)).or_default() += 1;
        if let Some(seen) = r.leaf(l).and_then(|x| x.last_seen) {
            measured = true;
            if now.saturating_sub(seen) <= LEAF_FRESH_SECS {
                out.leaves_reporting += 1;
            }
        }
    }
    let mut sub_worst = None;
    for c in &cell.cells {
        let s = roll_up(c, r, now);
        out.sub_cells += 1 + s.sub_cells;
        out.machines += s.machines;
        out.machines_up += s.machines_up;
        out.leaves += s.leaves;
        out.leaves_reporting += s.leaves_reporting;
        for (c, n) in &s.leaf_classes {
            *out.leaf_classes.entry(*c).or_default() += n;
        }
        if let Some(w) = s.power_w {
            out.power_w = Some(out.power_w.unwrap_or(0.0) + w);
        }
        if s.health != Health::Unknown {
            measured = true;
        }
        if s.health != Health::Ok && s.health != Health::Unknown {
            sub_worst = Some(Health::Degraded);
        }
    }
    out.health = if head_down {
        Health::Down
    } else if !measured {
        Health::Unknown
    } else if out.machines_up == out.machines
        && out.leaves_reporting == out.leaves
        && sub_worst.is_none()
        && matches!(out.head_supply, None | Some(SupplyState::Ok))
    {
        Health::Ok
    } else {
        Health::Degraded
    };
    out
}

/// What a head sends its parent: roll-ups and nothing else. Fields a newer
/// child adds are dropped on reading, as for [`RollUp`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Upward {
    pub from: String,
    pub seq: u64,
    pub roll_ups: Vec<RollUp>,
}

/// An [`Upward`] as it travels: the exact JSON, and the head's signature over
/// it.
///
/// The parent checks the signature against the head key its own tree holds
/// for that cell, so the cell's link is what admits the report: no roster
/// entry, no shared secret. The JSON is carried as text so the signature is
/// over what was sent, not over a re-serialised copy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub head: String,
    pub upward: String,
    pub signature: String,
}

impl Upward {
    fn sealed_bytes(text: &str) -> Vec<u8> {
        let mut m = b"furcate:cell-rollup:v1\0".to_vec();
        m.extend_from_slice(text.as_bytes());
        m
    }

    /// Seal with whatever holds the head's key.
    pub fn seal(&self, head: &str, sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>) -> Result<Sealed, String> {
        let upward = serde_json::to_string(self).map_err(|e| e.to_string())?;
        let message = Self::sealed_bytes(&upward);
        let signature = CellKey::parse(head)?.encode(&sign(&message)?)?;
        Ok(Sealed { head: head.to_string(), upward, signature })
    }
}

impl Sealed {
    /// Open a report from a cell below. The sender must head a cell in
    /// `tree`, the signature must be its key's, every roll-up must be for
    /// that cell or one inside it, and `seq` must be past `last_seq`, so a
    /// replayed report is refused rather than counted twice.
    pub fn open(&self, tree: &CellTree, last_seq: Option<u64>) -> Result<Upward, String> {
        let Some(cell) = tree.all().into_iter().find(|c| c.head.holder == self.head) else {
            return Err(format!("{} heads no cell this node parents", self.head));
        };
        CellKey::parse(&self.head)?
            .verify_hex(&Upward::sealed_bytes(&self.upward), &self.signature)
            .map_err(|e| format!("the report does not verify under {}: {e}", self.head))?;
        let up: Upward = serde_json::from_str(&self.upward)
            .map_err(|e| format!("the report is malformed: {e}"))?;
        if let Some(last) = last_seq {
            if up.seq <= last {
                return Err(format!("report {} is not past {last}, the last one taken from {}", up.seq, cell.id));
            }
        }
        let scope = cell.scope();
        for r in &up.roll_ups {
            if !scope.admits_cell(Some(&r.cell)) {
                return Err(format!(
                    "the head of {} reported for {}, which is outside its cell",
                    cell.id, r.cell
                ));
            }
        }
        Ok(up)
    }
}

/// The link from a cell to its parent, as the cell sees it.
pub trait Uplink {
    fn send(&mut self, up: &Upward) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Local autonomy
// ---------------------------------------------------------------------------

/// How a cell stands with its parent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum Standing {
    Connected { since: u64 },
    /// Running on its own: last known good links, cached registry, local
    /// control. Not an error: a cell is built to do this.
    CutOff { since: u64, queued: usize, dropped: u64 },
    /// The cell's own link has ended. It still runs what it runs, and says
    /// plainly that its parent must renew it.
    LinkExpired { at: u64 },
}

/// Most roll-ups a cut-off cell keeps for its parent. Beyond it the oldest go
/// first and are counted, so a long outage costs history, not memory.
pub const MAX_QUEUED: usize = 1024;

/// A cell head's own state: everything it needs to run with nobody above it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellLocal {
    pub upstream: Upstream,
    /// The links below this head that last derived cleanly.
    pub links: Vec<CellDelegation>,
    /// The cell's sensor registry, as last known.
    pub registry: Vec<Sensor>,
    pub queued: VecDeque<Upward>,
    pub dropped: u64,
    pub connected: bool,
    pub since: u64,
    pub seq: u64,
}

impl CellLocal {
    pub fn new(upstream: Upstream, now: u64) -> CellLocal {
        CellLocal {
            upstream,
            links: Vec::new(),
            registry: Vec::new(),
            queued: VecDeque::new(),
            dropped: 0,
            connected: false,
            since: now,
            seq: 0,
        }
    }

    /// The cell as this head sees it, from its own link down. Needs nothing
    /// from above.
    pub fn tree(&self, now: u64) -> CellTree {
        CellTree::derive(
            &self.upstream.own.site,
            &Root::Anchor(self.upstream.own.clone()),
            &self.links,
            now,
        )
    }

    /// Take a new set of links if they derive cleanly; otherwise keep the
    /// last known good set and say why.
    pub fn offer_links(&mut self, links: Vec<CellDelegation>, now: u64) -> Result<(), String> {
        let t = CellTree::derive(&self.upstream.own.site, &Root::Anchor(self.upstream.own.clone()), &links, now);
        if let Some(r) = t.refused.first() {
            return Err(format!(
                "kept the last known good links: {} of the {} offered do not check, first {} ({}): {}",
                t.refused.len(),
                links.len(),
                r.holder,
                r.scope.as_string(),
                r.why
            ));
        }
        self.links = links;
        Ok(())
    }

    /// Replace the cell's own link with a renewal from the same parent key.
    pub fn renew(&mut self, own: CellDelegation, now: u64) -> Result<(), String> {
        if own.scope != self.upstream.own.scope || own.holder != self.upstream.own.holder {
            return Err("a renewal must name the same head and the same cell".into());
        }
        own.check_anchor(&self.upstream.parent_key, &own.site, now)?;
        self.upstream.own = own;
        Ok(())
    }

    pub fn cache_registry(&mut self, sensors: Vec<Sensor>) {
        self.registry = sensors;
    }

    pub fn standing(&self, now: u64) -> Standing {
        if now >= self.upstream.own.not_after {
            return Standing::LinkExpired { at: self.upstream.own.not_after };
        }
        if self.connected {
            Standing::Connected { since: self.since }
        } else {
            Standing::CutOff { since: self.since, queued: self.queued.len(), dropped: self.dropped }
        }
    }

    /// Queue this cell's roll-ups and send whatever the link will take, in
    /// order. A failed send marks the cell cut off and keeps the rest queued.
    pub fn report(&mut self, roll_ups: Vec<RollUp>, link: &mut dyn Uplink, now: u64) {
        self.seq += 1;
        if self.queued.len() >= MAX_QUEUED {
            self.queued.pop_front();
            self.dropped += 1;
        }
        self.queued.push_back(Upward {
            from: self.upstream.own.scope.path().unwrap_or_default().to_string(),
            seq: self.seq,
            roll_ups,
        });
        self.flush(link, now);
    }

    /// Send what is queued. Called on every report and whenever the link may
    /// have come back.
    pub fn flush(&mut self, link: &mut dyn Uplink, now: u64) {
        while let Some(next) = self.queued.front() {
            match link.send(next) {
                Ok(()) => {
                    self.queued.pop_front();
                    if !self.connected {
                        self.connected = true;
                        self.since = now;
                    }
                }
                Err(_) => {
                    if self.connected {
                        self.connected = false;
                        self.since = now;
                    }
                    return;
                }
            }
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(tmp, path)
    }

    pub fn load(path: &Path) -> Result<Option<CellLocal>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| format!("{} does not parse as a cell's state: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use furcate_identity::custody::CustodySettings;
    use furcate_identity::LeafKeyCustody;
    use furcate_sense::registry::{SensorKind, Unit};

    const NOW: u64 = 1_786_838_400;
    const YEAR: u64 = 365 * 86_400;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn id(k: &SigningKey) -> String {
        ed25519_id(&k.verifying_key())
    }

    fn sign(d: CellDelegation, by: &SigningKey) -> CellDelegation {
        d.signed_by(|m| Ok(by.sign(m).to_bytes().to_vec())).unwrap()
    }

    fn link(by: &SigningKey, above: Option<&CellDelegation>, holder: String, role: Role, scope: &str, name: &str) -> CellDelegation {
        sign(
            CellDelegation {
                site: "home".into(),
                issuer: id(by),
                holder,
                role,
                scope: Scope::parse(scope).unwrap(),
                scale: (role == Role::Head).then_some(Scale::City),
                assurance: (role != Role::Manager).then_some(AssuranceClass::Device),
                leaf_min_class: None,
                endpoint: format!("{name}:7616"),
                name: name.into(),
                parent: above.map(|a| a.digest()),
                not_before: NOW - 10,
                not_after: above.map(|a| a.not_after).unwrap_or(NOW + YEAR),
                signature: String::new(),
            },
            by,
        )
    }

    /// operator -> controller -> berlin (head 3) -> berlin/mitte (head 4)
    ///                        -> paris (head 5)
    struct Site {
        op: SigningKey,
        links: Vec<CellDelegation>,
        ctl: CellDelegation,
        berlin: CellDelegation,
        mitte: CellDelegation,
    }

    fn site() -> Site {
        let op = key(1);
        let ctl = link(&op, None, id(&key(2)), Role::Controller, "site", "core-1");
        let berlin = link(&key(2), Some(&ctl), id(&key(3)), Role::Head, "cell:berlin", "pi-berlin");
        let mitte = link(&key(3), Some(&berlin), id(&key(4)), Role::Head, "cell:berlin/mitte", "pi-mitte");
        let paris = link(&key(2), Some(&ctl), id(&key(5)), Role::Head, "cell:paris", "pi-paris");
        let leaf = link(&key(3), Some(&berlin), id(&key(6)), Role::Leaf, "cell:berlin", "esp-1");
        let ai = link(&key(3), Some(&berlin), id(&key(7)), Role::EdgeAi, "cell:berlin", "jetson-1");
        let mgr = link(&key(3), Some(&berlin), "passkey:example.org:cred-berlin".into(), Role::Manager, "cell:berlin", "");
        let links = vec![ctl.clone(), berlin.clone(), mitte.clone(), paris, leaf, ai, mgr];
        Site { op, links, ctl, berlin, mitte }
    }

    fn manager(id: &str) -> Principal {
        Principal {
            id: id.into(),
            class: furcate_authn::Class::Person,
            evidence: Evidence::Delegated { root: "passkey".into(), depth: 1 },
            expires_at: None,
            task: None,
            needs_approval_for: vec![],
            roles: vec![],
        }
    }

    #[test]
    fn the_tree_is_read_back_from_the_chain() {
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        assert!(t.refused.is_empty(), "{:?}", t.refused);
        assert_eq!(t.controllers.len(), 1);
        let ids: Vec<_> = t.all().iter().map(|c| (c.id.clone(), c.depth)).collect();
        assert_eq!(ids, vec![("berlin".into(), 1), ("berlin/mitte".into(), 2), ("paris".into(), 1)]);
        let berlin = t.find("berlin").unwrap();
        assert_eq!(berlin.leaves[0].name, "esp-1");
        assert_eq!(berlin.edge_ai[0].name, "jetson-1");
        assert_eq!(berlin.managers, vec!["passkey:example.org:cred-berlin".to_string()]);
        assert_eq!(t.locate("esp-1").as_deref(), Some("berlin"));
        assert_eq!(t.locate("pi-mitte").as_deref(), Some("berlin/mitte"));
        assert_eq!(t.locate("core-1"), None);
    }

    #[test]
    fn a_link_whose_chain_does_not_reach_the_root_is_listed_not_dropped() {
        let s = site();
        let stranger = key(9);
        let rogue_ctl = link(&stranger, None, id(&key(10)), Role::Controller, "site", "rogue");
        let rogue = link(&key(10), Some(&rogue_ctl), id(&key(11)), Role::Head, "cell:rome", "pi-rome");
        let mut links = s.links.clone();
        links.extend([rogue_ctl, rogue]);
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &links, NOW);
        assert!(t.find("rome").is_none());
        assert_eq!(t.refused.len(), 2);
        assert!(t.refused.iter().all(|r| r.why.contains("root")), "{:?}", t.refused);

        // A link whose parent is not held here at all.
        let mut orphan = s.links.clone();
        orphan.retain(|l| l.digest() != s.berlin.digest());
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &orphan, NOW);
        assert!(t.find("berlin/mitte").is_none());
        assert!(t.refused.iter().any(|r| r.why.contains("not held here")));
    }

    #[test]
    fn a_chain_that_names_one_key_twice_is_refused() {
        let s = site();
        // berlin's head names the controller's own key as a sub-cell head.
        let looped = link(&key(3), Some(&s.berlin), id(&key(2)), Role::Head, "cell:berlin/loop", "loop");
        let mut links = s.links.clone();
        links.push(looped);
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &links, NOW);
        assert!(t.find("berlin/loop").is_none());
        assert!(t.refused.iter().any(|r| r.why.contains("twice")), "{:?}", t.refused);
    }

    #[test]
    fn a_cell_manager_sees_only_its_cell_and_below() {
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let scope = t.scope_for(&manager("passkey:example.org:cred-berlin")).unwrap();
        let v = t.visible_to(&scope);
        let ids: Vec<_> = v.all().iter().map(|c| c.id.clone()).collect();
        assert_eq!(ids, vec!["berlin".to_string(), "berlin/mitte".into()]);
        assert!(v.controllers.is_empty());
        let json = serde_json::to_string(&v).unwrap();
        // It sees the key of the controller its cell answers to, and nothing
        // else above or beside it.
        for leak in ["paris", &id(&key(5))[8..], &id(&s.op)[8..], "core-1"] {
            assert!(!json.contains(leak), "{leak} leaked: {json}");
        }

        // And nobody without a link sees anything.
        assert!(t.scope_for(&manager("passkey:example.org:stranger")).is_err());
        assert_eq!(t.scope_for(&Principal::operator("op")).unwrap(), Scope::Site);
    }

    #[test]
    fn a_cell_manager_cannot_act_on_a_sibling_or_the_core() {
        use furcate_authn::order::{Action, Bounds, Order, Target};
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let scope = t.scope_for(&manager("passkey:example.org:cred-berlin")).unwrap();
        let order = |target| Order {
            site: "example.org".into(),
            action: Action::Halt,
            target,
            bounds: Bounds { max_nodes: 1, duration_s: None },
            counter: 1,
            issued_at: NOW,
            expires_at: NOW + 60,
            reason: "test".into(),
        };
        let locate = |id: &str| t.locate(id);
        assert!(scope.admits_order(&order(Target::Node { id: "pi-mitte".into() }), locate).is_ok());
        let sib = scope.admits_order(&order(Target::Node { id: "pi-paris".into() }), locate).unwrap_err();
        assert!(sib.contains("cell:paris"), "{sib}");
        let core = scope.admits_order(&order(Target::Node { id: "core-1".into() }), locate).unwrap_err();
        assert!(core.contains("core cluster"), "{core}");
        assert!(scope.admits_order(&order(Target::Cluster), locate).unwrap_err().contains("site authority"));

        let read = |res: &str| furcate_policy::Request {
            principal: "passkey:example.org:cred-berlin".into(),
            action: "read".into(),
            resource: res.into(),
            roles: vec![],
        };
        assert!(scope.admits_request(&read("esp-1"), locate).is_ok());
        assert!(scope.admits_request(&read("pi-paris"), locate).is_err());
        assert!(scope.admits_request(&read("core-1"), locate).is_err());
    }

    #[test]
    fn a_grant_is_refused_outside_the_callers_cell() {
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let grant = |to: &str, resources: &[&str]| furcate_policy::Grant {
            from: "operator".into(),
            to: to.into(),
            actions: vec!["restart".into()],
            resources: resources.iter().map(|r| r.to_string()).collect(),
            until: NOW + 600,
            reason: "test".into(),
        };
        let ask = |who: &str, res: &str| furcate_policy::Request {
            principal: who.into(),
            action: "restart".into(),
            resource: res.into(),
            roles: vec![],
        };
        let berlin = "passkey:example.org:cred-berlin";
        let g = [grant(berlin, &["*"])];
        // Inside the manager's cell the grant permits.
        assert!(t.evaluate_grants(&g, &ask(berlin, "esp-1"), NOW).unwrap().allowed);
        // A sibling cell and the core cluster are refused, saying why.
        let sib = t.evaluate_grants(&g, &ask(berlin, "pi-paris"), NOW).unwrap();
        assert!(!sib.allowed && sib.because.contains("cell:paris"), "{}", sib.because);
        let core = t.evaluate_grants(&g, &ask(berlin, "core-1"), NOW).unwrap();
        assert!(!core.allowed && core.because.contains("core cluster"), "{}", core.because);
        // Someone with no cell link is the site's own and not narrowed here.
        let g = [grant("job:batch", &["*"])];
        assert!(t.evaluate_grants(&g, &ask("job:batch", "core-1"), NOW).unwrap().allowed);
        // No grant covering it is no decision at all.
        assert!(t.evaluate_grants(&[], &ask(berlin, "esp-1"), NOW).is_none());
    }

    #[test]
    fn a_head_sees_its_own_cell_from_its_own_link_and_nothing_above() {
        let s = site();
        let up = Upstream::new(s.berlin.clone(), "core-1:7616", NOW).unwrap();
        let below: Vec<_> = s.links.iter().filter(|l| l.scope.within(&Scope::cell("berlin").unwrap()) && l.digest() != s.berlin.digest()).cloned().collect();
        let mut local = CellLocal::new(up, NOW);
        local.offer_links(below, NOW).unwrap();
        let t = local.tree(NOW);
        assert!(t.refused.is_empty(), "{:?}", t.refused);
        assert_eq!(t.all().iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["berlin", "berlin/mitte"]);

        // What it stores names one key above it: the controller that enrolled it.
        let stored = serde_json::to_string(&local).unwrap();
        assert!(!stored.contains(&id(&s.op)[8..]), "the operator's key leaked into the head");
        assert!(!stored.contains(&id(&key(5))[8..]) && !stored.contains("paris"), "a sibling leaked");
        assert_eq!(local.upstream.parent_key, s.ctl.holder);

        // A link from outside its cell is refused, and the old set kept.
        let paris = s.links.iter().find(|l| l.scope == Scope::cell("paris").unwrap()).unwrap().clone();
        let err = local.offer_links(vec![paris], NOW).unwrap_err();
        assert!(err.contains("last known good"), "{err}");
        assert_eq!(local.tree(NOW).all().len(), 2);
    }

    #[test]
    fn a_head_on_a_failing_supply_degrades_its_cell_and_an_unmeasured_one_does_not_pass() {
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let mitte = t.find("berlin/mitte").unwrap();
        let with = |supply| {
            let mut r = Readings::default();
            r.machines.insert(
                "pi-mitte".into(),
                MachineReading { up: true, cores: Some(4), power_w: None, workloads: Some(1), supply },
            );
            roll_up(mitte, &r, NOW)
        };
        let ok = with(Some(SupplyState::Ok));
        assert_eq!(ok.health, Health::Ok, "{}", ok.line());
        assert_eq!(ok.head_supply, Some(SupplyState::Ok));
        let low = with(Some(SupplyState::Undervoltage));
        assert_eq!(low.health, Health::Degraded);
        assert!(low.line().ends_with("head supply undervoltage"), "{}", low.line());
        // Not measured stays not measured: no supply state is invented.
        let unmeasured = with(None);
        assert_eq!(unmeasured.head_supply, None);
        assert!(!unmeasured.line().contains("supply"));
        assert!(SupplyState::Shedding > SupplyState::Undervoltage && SupplyState::Throttled > SupplyState::Ok);
    }

    #[test]
    fn the_upward_payload_is_roll_ups_only() {
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let mut r = Readings::default();
        r.machines.insert("pi-berlin".into(), MachineReading { up: true, cores: Some(4), power_w: Some(5.0), workloads: Some(2), supply: None });
        r.machines.insert("jetson-1".into(), MachineReading { up: true, cores: Some(8), power_w: Some(15.0), workloads: Some(1), supply: None });
        r.leaves.insert("esp-1".into(), LeafReading { last_seen: Some(NOW - 5), battery_pct: Some(80.0), ..Default::default() });
        let roll = roll_up(t.find("berlin").unwrap(), &r, NOW);
        assert_eq!(roll.machines, 3);
        assert_eq!(roll.machines_up, 2);
        assert_eq!(roll.sub_cells, 1);
        assert_eq!(roll.power_w, Some(20.0));
        assert_eq!(roll.health, Health::Degraded);
        assert!(roll.line().starts_with("berlin: degraded, 2/3 machines up"));

        let up = Upward { from: "berlin".into(), seq: 1, roll_ups: vec![roll] };
        let v = serde_json::to_value(&up).unwrap();
        let keys: BTreeSet<_> = v["roll_ups"][0].as_object().unwrap().keys().cloned().collect();
        let allowed: BTreeSet<String> = ["cell", "scale", "health", "machines", "machines_up", "leaves", "leaves_reporting", "leaf_classes", "sub_cells", "power_w", "at"].iter().map(|s| s.to_string()).collect();
        assert_eq!(keys, allowed);
        assert_eq!(v["roll_ups"][0]["leaf_classes"], serde_json::json!({"device": 1}), "counts by class, nothing else");
        let text = v.to_string();
        for leak in ["esp-1", "jetson", "pi-berlin", "ed25519", "passkey", "7616"] {
            assert!(!text.contains(leak), "{leak} leaked upward: {text}");
        }
        // A field a newer child adds is read past and dropped: the parent
        // keeps, and would send on, only what it knows.
        let mut extra = v.clone();
        extra["roll_ups"][0]["leaf_keys"] = serde_json::json!(["x"]);
        extra["roll_ups"][0]["battery_low"] = serde_json::json!(2);
        extra["sent_by_release"] = serde_json::json!("9.9");
        let read: Upward = serde_json::from_value(extra).unwrap();
        assert_eq!(read, up);
        let kept = serde_json::to_value(&read).unwrap();
        let keys: BTreeSet<_> = kept["roll_ups"][0].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, allowed);
        assert!(!kept.to_string().contains("leaf_keys") && !kept.to_string().contains("sent_by_release"));
    }

    #[test]
    fn a_report_from_below_is_taken_only_from_the_cells_own_head() {
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let roll = |cell: &str| RollUp { cell: cell.into(), scale: Scale::City, health: Health::Ok, machines: 1, machines_up: 1, leaves: 0, leaves_reporting: 0, leaf_classes: BTreeMap::new(), sub_cells: 0, power_w: None, head_supply: None, at: NOW };
        let up = Upward { from: "berlin".into(), seq: 7, roll_ups: vec![roll("berlin"), roll("berlin/mitte")] };
        let berlin = key(3);
        let sealed = up.seal(&id(&berlin), |m| Ok(berlin.sign(m).to_bytes().to_vec())).unwrap();
        assert_eq!(sealed.open(&t, Some(6)).unwrap(), up);
        assert!(sealed.open(&t, Some(7)).unwrap_err().contains("not past"));

        // Signed by somebody else.
        let forged = up.seal(&id(&berlin), |m| Ok(key(9).sign(m).to_bytes().to_vec())).unwrap();
        assert!(forged.open(&t, None).unwrap_err().contains("does not verify"));
        // About a cell outside its own.
        let wide = Upward { roll_ups: vec![roll("paris")], ..up.clone() };
        let wide = wide.seal(&id(&berlin), |m| Ok(berlin.sign(m).to_bytes().to_vec())).unwrap();
        assert!(wide.open(&t, None).unwrap_err().contains("outside its cell"));
        // From a newer child that reports more: taken, and the extras dropped.
        let mut v = serde_json::to_value(&up).unwrap();
        v["leaves"] = serde_json::json!(["esp-1"]);
        v["roll_ups"][0]["leaf_firmware"] = serde_json::json!({"0.1.9": 1});
        let text = v.to_string();
        let sig = berlin.sign(&Upward::sealed_bytes(&text)).to_bytes();
        let newer = Sealed { head: id(&berlin), upward: text, signature: hex::encode(sig) };
        let taken = newer.open(&t, None).unwrap();
        assert_eq!(taken, up);
        assert!(!serde_json::to_string(&taken).unwrap().contains("esp-1"));
        // Its signature still covers everything that was sent.
        let mut altered = newer.clone();
        altered.upward = altered.upward.replace("esp-1", "esp-2");
        assert!(altered.open(&t, None).unwrap_err().contains("does not verify"));
    }

    #[test]
    fn a_p256_head_signs_its_leaves_and_reports() {
        use p256::ecdsa::signature::Signer as _;
        // Test-only key; on a Pi the firmware holds it and signs.
        let lyon = p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
        let lyon_id = p256_id(lyon.verifying_key());
        let raw = |m: &[u8]| -> Result<Vec<u8>, String> {
            let sig: p256::ecdsa::Signature = lyon.sign(m);
            Ok(sig.to_bytes().to_vec())
        };
        let der = |m: &[u8]| -> Result<Vec<u8>, String> {
            let sig: p256::ecdsa::Signature = lyon.sign(m);
            Ok(sig.to_der().as_bytes().to_vec())
        };

        let s = site();
        let head = link(&key(2), Some(&s.ctl), lyon_id.clone(), Role::Head, "cell:lyon", "pi-lyon");
        let mut leaf = head.clone();
        leaf.issuer = lyon_id.clone();
        leaf.holder = id(&key(9));
        leaf.role = Role::Leaf;
        leaf.scale = None;
        leaf.name = "esp-9".into();
        leaf.parent = Some(head.digest());
        leaf.signature.clear();
        let leaf = leaf.signed_by(der).unwrap();
        let mut links = s.links.clone();
        links.extend([head.clone(), leaf.clone()]);
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &links, NOW);
        let cell = t.find("lyon").expect("the P-256 head's cell");
        assert_eq!(cell.head.holder, lyon_id);
        assert!(t.refused.is_empty(), "{:?}", t.refused);

        let roll = RollUp { cell: "lyon".into(), scale: Scale::City, health: Health::Ok, machines: 1, machines_up: 1, leaves: 1, leaves_reporting: 1, leaf_classes: BTreeMap::new(), sub_cells: 0, power_w: None, head_supply: None, at: NOW };
        let up = Upward { from: "lyon".into(), seq: 1, roll_ups: vec![roll] };
        for sign in [&raw as &dyn Fn(&[u8]) -> Result<Vec<u8>, String>, &der] {
            let sealed = up.seal(&lyon_id, sign).unwrap();
            assert_eq!(sealed.signature.len(), 128, "kept as r || s whichever form the signer gave");
            assert_eq!(sealed.open(&t, None).unwrap(), up);
            let mut tampered = sealed.clone();
            let mut sig = hex::decode(&tampered.signature).unwrap();
            sig[5] ^= 1;
            tampered.signature = hex::encode(sig);
            assert!(tampered.open(&t, None).unwrap_err().contains("does not verify"));
        }
        // Another P-256 key cannot report for the cell.
        let other = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let forged = up
            .seal(&lyon_id, |m| {
                let sig: p256::ecdsa::Signature = other.sign(m);
                Ok(sig.to_bytes().to_vec())
            })
            .unwrap();
        assert!(forged.open(&t, None).unwrap_err().contains("does not verify"));
    }

    #[test]
    fn an_order_approved_by_a_cell_manager_stays_in_their_cell() {
        use furcate_authn::order::{Action, Bounds, Order, Target};
        let s = site();
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &s.links, NOW);
        let order = |id: &str| Order {
            site: "example.org".into(),
            action: Action::Halt,
            target: Target::Node { id: id.into() },
            bounds: Bounds { max_nodes: 1, duration_s: None },
            counter: 1,
            issued_at: NOW,
            expires_at: NOW + 60,
            reason: "test".into(),
        };
        let mgr = vec!["cred-berlin".to_string()];
        assert!(t.order_within_approvers(&order("pi-mitte"), &mgr).is_ok());
        let e = t.order_within_approvers(&order("pi-paris"), &mgr).unwrap_err();
        assert!(e.starts_with("approver cred-berlin manages cell:berlin"), "{e}");
        assert!(t.order_within_approvers(&order("core-1"), &mgr).is_err());
        // The site's own approvers are not narrowed by this.
        assert!(t.order_within_approvers(&order("core-1"), &["cred-site".to_string()]).is_ok());
    }

    struct Wire {
        up: bool,
        got: Vec<u64>,
    }

    impl Uplink for Wire {
        fn send(&mut self, up: &Upward) -> Result<(), String> {
            if self.up {
                self.got.push(up.seq);
                Ok(())
            } else {
                Err("link down".into())
            }
        }
    }

    #[test]
    fn a_cut_off_cell_keeps_running_and_syncs_on_reconnect() {
        let s = site();
        let up = Upstream::new(s.berlin.clone(), "core-1:7616", NOW).unwrap();
        let mut local = CellLocal::new(up, NOW);
        local.offer_links(vec![s.mitte.clone()], NOW).unwrap();
        local.cache_registry(vec![Sensor {
            id: "temp-1".into(),
            kind: SensorKind::Temperature,
            unit: Unit::Celsius,
            host: "esp-1".into(),
            domain: None,
            interval_s: 10,
        }]);
        let mut wire = Wire { up: true, got: vec![] };
        let roll = |at| RollUp { cell: "berlin".into(), scale: Scale::City, health: Health::Ok, machines: 1, machines_up: 1, leaves: 0, leaves_reporting: 0, leaf_classes: BTreeMap::new(), sub_cells: 1, power_w: None, head_supply: None, at };
        local.report(vec![roll(NOW)], &mut wire, NOW);
        assert!(matches!(local.standing(NOW), Standing::Connected { .. }));

        // Cut.
        wire.up = false;
        for i in 1..=3 {
            local.report(vec![roll(NOW + i)], &mut wire, NOW + i);
        }
        assert_eq!(local.standing(NOW + 3), Standing::CutOff { since: NOW + 1, queued: 3, dropped: 0 });
        // Still a cell: its tree, its scope and its registry need nobody above.
        let t = local.tree(NOW + 3);
        assert_eq!(t.all().len(), 2);
        assert_eq!(t.locate("pi-mitte").as_deref(), Some("berlin/mitte"));
        assert_eq!(local.registry.len(), 1);

        // The state survives a restart while cut off.
        let dir = std::env::temp_dir().join(format!("furcate-cell-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cell.json");
        local.save(&path).unwrap();
        let mut local = CellLocal::load(&path).unwrap().unwrap();
        std::fs::remove_dir_all(&dir).ok();

        // Reconnect: everything queued goes, in order.
        wire.up = true;
        local.flush(&mut wire, NOW + 10);
        assert_eq!(wire.got, vec![1, 2, 3, 4]);
        assert!(matches!(local.standing(NOW + 10), Standing::Connected { since } if since == NOW + 10));

        // Past its own link's end it says so rather than pretending.
        assert!(matches!(local.standing(s.berlin.not_after), Standing::LinkExpired { .. }));
    }

    #[test]
    fn a_long_outage_drops_the_oldest_and_counts_them() {
        let s = site();
        let mut local = CellLocal::new(Upstream::new(s.berlin.clone(), "c", NOW).unwrap(), NOW);
        let mut wire = Wire { up: false, got: vec![] };
        for _ in 0..MAX_QUEUED + 5 {
            local.report(vec![], &mut wire, NOW);
        }
        assert_eq!(local.queued.len(), MAX_QUEUED);
        assert_eq!(local.dropped, 5);
        assert_eq!(local.queued.front().unwrap().seq, 6);
    }

    #[test]
    fn a_device_class_gateway_enrols_as_a_head_and_its_leaves_attach() {
        let s = site();
        let pi = key(20);
        let e = HeadEnrolment {
            gateway: id(&pi),
            assurance: AssuranceClass::Device,
            endpoint: "pi-garage:7616".into(),
            name: "pi-garage".into(),
            cell: "garage".into(),
            scale: Scale::Home,
            until: NOW + 30 * 86_400,
            leaf_min_class: None,
        };
        let head = sign(enrol_head(&s.ctl, &e, NOW).unwrap(), &key(2));
        assert_eq!(head.scope, Scope::cell("garage").unwrap());

        // A leaf attaches through furcate-sense, and its head names it.
        let esp = furcate_sense::leaf::Leaf::new("esp-garage", [21; 32]);
        let att = esp.attach("pi-garage", Some(LeafKeyCustody::FuseKey { lockdown: Default::default() }), NOW);
        let leaf = sign(enrol_leaf(&head, &att, NOW + YEAR, NOW).unwrap(), &pi);
        assert_eq!(leaf.not_after, head.not_after, "a leaf cannot outlive its head");

        let mut links = s.links.clone();
        links.extend([head.clone(), leaf]);
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &links, NOW);
        assert!(t.refused.is_empty(), "{:?}", t.refused);
        let garage = t.find("garage").unwrap();
        assert_eq!(garage.scale, Scale::Home);
        assert_eq!(garage.leaves[0].name, "esp-garage");
        assert_eq!(garage.leaves[0].assurance, Some(AssuranceClass::Device));

        // A soft key does not head a cell, and a leaf attached elsewhere is not this head's.
        let soft = HeadEnrolment { assurance: AssuranceClass::Soft, ..e.clone() };
        assert!(enrol_head(&s.ctl, &soft, NOW).unwrap_err().contains("hardware"));
        let elsewhere = esp.attach("pi-other", att.key_custody, NOW);
        assert!(enrol_leaf(&head, &elsewhere, NOW + 60, NOW).is_err());
        // A head cannot be enrolled for longer than its enroller holds.
        let long = HeadEnrolment { until: s.ctl.not_after + 1, ..e };
        assert!(enrol_head(&s.ctl, &long, NOW).is_err());
    }

    fn lab_head(s: &Site, pi: &SigningKey, floor: Option<AssuranceClass>) -> CellDelegation {
        let e = HeadEnrolment {
            gateway: id(pi),
            assurance: AssuranceClass::Device,
            leaf_min_class: floor,
            endpoint: "pi-lab:7616".into(),
            name: "pi-lab".into(),
            cell: "lab".into(),
            scale: Scale::Home,
            until: NOW + 30 * 86_400,
        };
        sign(enrol_head(&s.ctl, &e, NOW).unwrap(), &key(2))
    }

    #[test]
    fn the_published_esp32_record_attaches_as_a_soft_p256_leaf_only_where_the_cell_floor_is_soft() {
        let s = site();
        let pi = key(22);
        let record: serde_json::Value =
            serde_json::from_str(include_str!("../../furcate-sense/fixtures/home-lab-leaf.json")).unwrap();
        let att = Attachment::from_record(&record).unwrap();
        let custody_before = (CustodySettings::default().floor(), CustodySettings::default().admits(AssuranceClass::Soft).is_err());

        let strict = lab_head(&s, &pi, None);
        let refused = enrol_leaf(&strict, &att, NOW + YEAR, NOW).unwrap_err();
        assert!(
            refused.contains("floor `device`") && refused.contains("cell leaf-floor") && refused.contains("secure boot is off"),
            "{refused}"
        );
        assert!(!refused.contains("custody"), "the refusal is about the cell, not node custody: {refused}");
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &[s.links.clone(), vec![strict]].concat(), NOW);
        assert_eq!(t.find("lab").unwrap().leaf_min_class, AssuranceClass::Device);

        let head = lab_head(&s, &pi, Some(AssuranceClass::Soft));
        let leaf = sign(enrol_leaf(&head, &att, NOW + YEAR, NOW).unwrap(), &pi);
        assert_eq!(leaf.holder, "p256:03749d5173ee808e288b9aca1d31293c6af71d9cf83e819e562c296213e40cdc54");
        assert_eq!(leaf.assurance, Some(AssuranceClass::Soft));
        assert_eq!(
            (CustodySettings::default().floor(), CustodySettings::default().admits(AssuranceClass::Soft).is_err()),
            custody_before,
            "a cell's leaf floor leaves node custody as it was"
        );

        let mut links = s.links.clone();
        links.extend([head, leaf]);
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &links, NOW);
        assert!(t.refused.is_empty(), "{:?}", t.refused);
        let lab = t.find("lab").unwrap();
        assert_eq!(lab.leaf_min_class, AssuranceClass::Soft);
        assert_eq!(lab.leaves[0].name, "1d3d319e958177e5a4f2d8fb58c11cfe");
        assert_eq!(lab.leaves[0].assurance, Some(AssuranceClass::Soft), "recorded as earned, never promoted");
        let roll = roll_up(lab, &Readings::default(), NOW);
        assert_eq!(roll.leaf_classes.get(&AssuranceClass::Soft), Some(&1));
        assert!(roll.line().contains("0/1 leaves reporting (1 soft)"), "{}", roll.line());
        let wire = serde_json::to_string(&roll).unwrap();
        assert_eq!(serde_json::from_str::<RollUp>(&wire).unwrap(), roll);
    }

    #[test]
    fn a_cell_floor_changed_without_the_signature_is_refused() {
        let s = site();
        let pi = key(25);
        let mut head = lab_head(&s, &pi, None);
        head.leaf_min_class = Some(AssuranceClass::Soft);
        assert!(head.verify_signature().is_err(), "the floor is covered by the enroller's signature");
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &[s.links.clone(), vec![head.clone()]].concat(), NOW);
        assert!(t.find("lab").is_none());
        assert!(!t.refused.is_empty());

        // The head cannot re-sign it either: the link is the enroller's to sign.
        assert!(head.signed_by(|m| Ok(pi.sign(m).to_bytes().to_vec())).is_err());

        // A link signed before the floor existed keeps its signature.
        let old = lab_head(&s, &pi, None);
        assert!(old.verify_signature().is_ok() && old.leaf_min_class.is_none());
        assert!(!serde_json::to_string(&old).unwrap().contains("leaf_min_class"));
    }

    #[test]
    fn a_p256_leaf_on_a_locked_part_attaches_as_device_with_no_opt_in() {
        let s = site();
        let pi = key(23);
        let head = lab_head(&s, &pi, None);
        let esp = furcate_sense::leaf::Leaf::p256([24; 32]).unwrap();
        let locked = furcate_identity::Lockdown {
            secure_boot: true,
            flash_encryption: true,
            download_disabled: true,
            jtag_disabled: true,
        };
        let att = esp.attach("pi-lab", Some(LeafKeyCustody::SramFingerprint { lockdown: locked }), NOW);
        let leaf = enrol_leaf(&head, &att, NOW + YEAR, NOW).unwrap();
        assert!(leaf.holder.starts_with("p256:0"));
        assert_eq!(leaf.assurance, Some(AssuranceClass::Device));
    }

    #[test]
    fn a_re_enrolled_cell_shows_its_old_head_as_superseded() {
        let s = site();
        let mut again = link(&key(2), Some(&s.ctl), id(&key(30)), Role::Head, "cell:paris", "pi-paris-2");
        again.not_before = NOW - 1;
        let again = sign(again, &key(2));
        let mut links = s.links.clone();
        links.push(again);
        let t = CellTree::derive("home", &Root::Operator(id(&s.op)), &links, NOW);
        assert_eq!(t.find("paris").unwrap().head.name, "pi-paris-2");
        assert!(t.refused.iter().any(|r| r.why.starts_with("superseded")));
    }
}
