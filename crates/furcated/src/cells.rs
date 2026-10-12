//! This node's side of edge cells.
//!
//! A node sits in one of two places in the tree. A core node holds
//! `cells.json`, the links the operator's controllers and the cells below
//! them signed, and checks them against `operator.pub`. A cell's head holds
//! `cell-anchor.json` instead: its own link and the endpoint of whatever
//! enrolled it, and nothing else above it. Its `cells.json` holds only the
//! links it signed itself, for its leaves and its sub-cells.
//!
//! Either way the node serves `/cells` scoped to the caller, takes signed
//! roll-ups from the heads of the cells below it, and refuses a passkey order
//! a cell's manager approved for anything outside that cell. A head also
//! keeps its cell's state in `cell.json` under the state directory, so it
//! runs on its last known good links and registry while the link above it is
//! down, and sends what it queued when the link returns.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use furcate_identity::MessageSigner;
use furcate_api::{Request, Response, Router};
use furcate_sense::leaf::Attachment;
use furcate_topology::cell::{
    roll_up, signer_id, CellDelegation, CellFile, CellLocal, CellTree, HeadEnrolment, Readings,
    Sealed, Upstream, Uplink, Upward,
};
use furcate_authn::webauthn::{Assertion, Challenge, Roster};
use furcate_topology::read_token::{self, ReadRequest};
use serde::Deserialize;
use serde_json::{json, Value};

fn load_anchor(now: u64) -> Result<Option<Upstream>, String> {
    furcate_topology::cell::load_anchor(&furcate_paths::config("cell-anchor.json"), now)
}

/// The links this node holds: the operator's `cells.json` under the config
/// directory, and the links this node signed itself, kept in
/// `cells-issued.json` under the state directory.
fn link_files() -> [std::path::PathBuf; 2] {
    [furcate_paths::config("cells.json"), furcate_paths::state("cells-issued.json")]
}

fn load_file(site: Option<&str>) -> Result<CellFile, String> {
    furcate_topology::cell::merge_files(&link_files(), site)
}

/// Record a link this node signed, beside the others it issued.
fn issue(link: &CellDelegation) -> Result<(), String> {
    let path = furcate_paths::state("cells-issued.json");
    let mut file = CellFile::load(&path)?
        .unwrap_or_else(|| CellFile { site: link.site.clone(), links: Vec::new(), revoked: Vec::new() });
    if !file.links.is_empty() && file.site != link.site {
        return Err(format!("{} is for site {}, not {}", path.display(), file.site, link.site));
    }
    file.site = link.site.clone();
    file.links.push(link.clone());
    let text = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    super::actuators::write_atomically(&path, text.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// The tree as this node's files describe it, with no cached state.
///
/// What an order is checked against: read fresh, so a changed file takes
/// effect at once, and an unreadable one refuses the order rather than
/// letting it through unchecked.
pub fn tree_from_disk(now: u64) -> Result<CellTree, String> {
    node_files().tree(now)
}

/// The files this node's cell tree is read from.
fn node_files() -> furcate_topology::cell::NodeFiles {
    furcate_topology::cell::NodeFiles {
        anchor: furcate_paths::config("cell-anchor.json"),
        links: link_files().to_vec(),
        operator_pub: furcate_paths::config("operator.pub"),
    }
}

/// The operator's key when this node holds `operator.pub`. A head that does
/// not cannot check a revocation, and runs on to its link's own end.
fn operator_key() -> Option<String> {
    furcate_topology::cell::operator_root(&furcate_paths::config("operator.pub")).ok()
}

/// Whether an approved order stays inside every approving cell manager's
/// cell, by this node's own reading of the chain.
pub fn order_in_scope(order: &furcate_authn::order::Order, approvers: &[String], now: u64) -> Result<(), String> {
    let tree = tree_from_disk(now).map_err(|why| {
        format!("this node cannot check the order against its cells, so it refuses it: {why}")
    })?;
    tree.order_within_approvers(order, approvers)
}

/// The node's cell state.
pub struct Cells {
    /// Present when this node heads a cell.
    local: Mutex<Option<CellLocal>>,
    /// Why this node is not acting as a head although it holds an anchor.
    refused: Option<String>,
    /// The latest roll-up per cell reported from below, with when it came.
    reported: Mutex<BTreeMap<String, (furcate_topology::RollUp, u64)>>,
    /// Last report sequence taken per head, so a replay is refused.
    last_seq: Mutex<BTreeMap<String, u64>>,
    /// What signs this node's links, tokens and roll-ups: the hardware's
    /// own key when the root of trust signs messages, else the node key.
    key: Option<Arc<dyn MessageSigner>>,
    /// Read requests a challenge was issued for, by nonce, each spent once.
    reads: Mutex<BTreeMap<String, (ReadRequest, Challenge)>>,
}

/// How long a manager has to answer a read challenge.
const READ_CHALLENGE_SECS: u64 = 120;
/// Outstanding read challenges at most, so asking cannot fill memory.
const MAX_READS: usize = 256;

impl Cells {
    pub fn load(key: Option<Arc<dyn MessageSigner>>, now: u64) -> Cells {
        let reported = furcate_topology::cell::load_reported(&furcate_paths::state("cells-reported.json"))
            .unwrap_or_else(|why| {
                eprintln!("furcated: starting with no cell reports: {why}");
                BTreeMap::new()
            });
        let mut cells = Cells {
            local: Mutex::new(None),
            refused: None,
            reported: Mutex::new(reported),
            last_seq: Mutex::new(BTreeMap::new()),
            key,
            reads: Mutex::new(BTreeMap::new()),
        };
        let up = match load_anchor(now) {
            Ok(None) => return cells,
            Ok(Some(up)) => up,
            Err(why) => {
                eprintln!("furcated: not acting as a cell head: {why}");
                cells.refused = Some(why);
                return cells;
            }
        };
        let mine = cells.key.as_ref().and_then(|k| signer_id(k.as_ref()).ok());
        if mine.as_deref() != Some(up.own.holder.as_str()) {
            let why = format!(
                "the cell anchor names {} as head, and this node's key is {}",
                up.own.holder,
                mine.unwrap_or_else(|| "absent".into())
            );
            eprintln!("furcated: not acting as a cell head: {why}");
            cells.refused = Some(why);
            return cells;
        }
        let state = furcate_paths::state("cell.json");
        let local = match CellLocal::load(&state) {
            Ok(Some(mut l)) if l.upstream.own.scope == up.own.scope && l.upstream.own.holder == up.own.holder => {
                if l.upstream.own != up.own {
                    if let Err(why) = l.renew(up.own.clone(), now) {
                        eprintln!("furcated: keeping the cell's previous link: {why}");
                    }
                }
                l.upstream.parent_endpoint = up.parent_endpoint.clone();
                l
            }
            Ok(_) => CellLocal::new(up, now),
            Err(why) => {
                eprintln!("furcated: starting the cell's state afresh: {why}");
                CellLocal::new(up, now)
            }
        };
        eprintln!("furcated: heading cell {}", local.upstream.own.scope.as_string());
        *cells.local.lock().expect("cells lock") = Some(local);
        cells
    }

    /// The tree this node shows: from its own link down when it heads a
    /// cell, on the last known good links if the current file does not check.
    pub fn tree(&self, now: u64) -> Result<CellTree, String> {
        if let Some(why) = &self.refused {
            return Err(format!("this node holds a cell anchor it cannot use: {why}"));
        }
        let mut guard = self.local.lock().expect("cells lock");
        let Some(local) = guard.as_mut() else {
            return tree_from_disk(now);
        };
        match load_file(Some(&local.upstream.own.site)) {
            Ok(file) => {
                let operator = operator_key();
                if let Some(why) =
                    furcate_topology::cell::revoked_reason(&file, operator.as_deref(), &local.upstream.own.digest())
                {
                    return Err(format!("the operator revoked this cell's own link: {why}"));
                }
                let (links, _, _) = furcate_topology::cell::apply_revocations(&file, operator.as_deref());
                if links != local.links {
                    if let Err(why) = local.offer_links(links, now) {
                        eprintln!("furcated: {why}");
                    }
                }
            }
            Err(why) => eprintln!("furcated: keeping the last known good cell links: {why}"),
        }
        Ok(local.tree(now))
    }

    /// This node's own link: its anchor when it heads a cell, else the
    /// controller link the operator gave it.
    fn own_link(&self, tree: &CellTree) -> Result<(CellDelegation, Arc<dyn MessageSigner>), String> {
        let key = self.key.clone().ok_or("this node has no signing key, so it cannot sign a link")?;
        let me = signer_id(key.as_ref())?;
        if let Some(l) = self.local.lock().expect("cells lock").as_ref() {
            return Ok((l.upstream.own.clone(), key));
        }
        tree.link_of(&me)
            .cloned()
            .map(|l| (l, key))
            .ok_or_else(|| format!("{me} holds no controller or head link here, so it may enrol nothing"))
    }

    /// Enrol a gateway as the head of a new cell under this node, and say
    /// what the gateway installs as its anchor.
    pub fn enrol_head(&self, e: &HeadEnrolment, now: u64) -> Result<serde_json::Value, String> {
        let tree = self.tree(now)?;
        let (own, key) = self.own_link(&tree)?;
        if own.endpoint.is_empty() {
            return Err("this node's own link names no endpoint, so a head could not reach it".into());
        }
        let link = furcate_topology::cell::enrol_head(&own, e, now)?
            .signed_with(key.as_ref())?;
        link.check(Some(&own), "", &own.site, now)?;
        issue(&link)?;
        Ok(json!({
            "anchor": { "own": link, "parent_endpoint": own.endpoint },
            "install": "write `anchor` to cell-anchor.json in the gateway's config directory",
        }))
    }

    /// A challenge for a manager's read of the tree: the hash of exactly
    /// what they ask to read, for how long.
    pub fn read_challenge(&self, holder: &str, scope: &str, secs: u64, now: u64) -> Result<serde_json::Value, String> {
        let tree = self.tree(now)?;
        let scope = furcate_topology::cell::Scope::parse(scope)?;
        // Refused before the person is asked to touch their key.
        read_token::within_link(&tree, holder, &scope)?;
        let secs = secs.clamp(1, read_token::MAX_READ_SECS);
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "this node could not draw a random nonce".to_string())?;
        let request = ReadRequest {
            site: tree.site.clone(),
            holder: holder.to_string(),
            scope,
            not_after: now + secs,
            nonce: hex::encode(nonce),
        };
        let challenge = read_token::challenge_for(&request, nonce, now + READ_CHALLENGE_SECS);
        let mut reads = self.reads.lock().expect("reads lock");
        reads.retain(|_, (_, c)| c.expires_at > now);
        if reads.len() >= MAX_READS {
            return Err("too many reads are waiting on a passkey; try again shortly".into());
        }
        reads.insert(request.nonce.clone(), (request.clone(), challenge));
        Ok(json!({
            "request": request,
            "challenge": challenge.encoded(),
            "expires_at": challenge.expires_at,
        }))
    }

    /// Verify the manager's assertion over a read request and sign the
    /// token. The challenge is spent whatever the outcome.
    pub fn read_token(&self, nonce: &str, assertion: &Assertion, now: u64) -> Result<serde_json::Value, String> {
        let (request, challenge) = self
            .reads
            .lock()
            .expect("reads lock")
            .remove(nonce)
            .ok_or("no read challenge is outstanding under that nonce; ask for a new one")?;
        let key = self.key.clone().ok_or("this node has no signing key, so it cannot sign a read token")?;
        let roster = Roster::load(&furcate_paths::state("passkeys.json"))?;
        let credential = roster.lookup(&assertion.credential_id)?;
        let tree = self.tree(now)?;
        let token = read_token::issue(
            &tree,
            &request,
            credential,
            assertion,
            &challenge,
            &signer_id(key.as_ref())?,
            now,
            |m| key.sign(m).map_err(|e| format!("the signer refused: {e:#}")),
        )?;
        Ok(json!({
            "token": token.encode(),
            "header": "x-furcate-credential",
            "scope": token.request.scope,
            "not_after": token.request.not_after,
        }))
    }

    /// Name a leaf that attached to this head through furcate-sense, at the
    /// class its key custody earns, if it meets the leaf floor the operator
    /// set in this head's own signed link.
    pub fn enrol_leaf(&self, att: &Attachment, until: u64, now: u64) -> Result<CellDelegation, String> {
        if self.local.lock().expect("cells lock").is_none() {
            return Err("this node heads no cell, so it holds no leaves".into());
        }
        let tree = self.tree(now)?;
        let (own, key) = self.own_link(&tree)?;
        let link = furcate_topology::cell::enrol_leaf(&own, att, until, now)?
            .signed_with(key.as_ref())?;
        issue(&link)?;
        Ok(link)
    }

    pub fn reported(&self) -> BTreeMap<String, (furcate_topology::RollUp, u64)> {
        self.reported.lock().expect("cells lock").clone()
    }

    /// Take a signed report from the head of a cell below.
    pub fn take(&self, sealed: &Sealed, now: u64) -> Result<usize, String> {
        let tree = self.tree(now)?;
        let last = self.last_seq.lock().expect("cells lock").get(&sealed.head).copied();
        let up = sealed.open(&tree, last)?;
        self.last_seq.lock().expect("cells lock").insert(sealed.head.clone(), up.seq);
        let mut reported = self.reported.lock().expect("cells lock");
        for r in &up.roll_ups {
            reported.insert(r.cell.clone(), (r.clone(), now));
        }
        // Kept on disk too, for the ownership view and across a restart.
        let path = furcate_paths::state("cells-reported.json");
        let text = serde_json::to_string(&*reported).map_err(|e| e.to_string())?;
        if let Err(e) = super::actuators::write_atomically(&path, text.as_bytes()) {
            eprintln!("furcated: WARNING cell reports not saved to {}: {e}", path.display());
        }
        Ok(up.roll_ups.len())
    }

    /// One pass of a head's upward report: its own cell summed, plus what
    /// the cells inside it last reported, queued and sent in order.
    pub fn report_up(&self, readings: &Readings, now: u64) {
        let Some(key) = self.key.clone() else { return };
        let mut guard = self.local.lock().expect("cells lock");
        let Some(local) = guard.as_mut() else { return };
        let tree = local.tree(now);
        let Some(path) = local.upstream.own.scope.path().map(str::to_string) else { return };
        let Some(cell) = tree.find(&path) else {
            eprintln!("furcated: this head's own cell {path} did not derive; nothing to report");
            return;
        };
        let mut rolls = vec![roll_up(cell, readings, now)];
        rolls.extend(
            self.reported
                .lock()
                .expect("cells lock")
                .values()
                .filter(|(r, _)| r.cell != path)
                .map(|(r, _)| r.clone()),
        );
        let mut link = HttpUplink {
            endpoint: local.upstream.parent_endpoint.clone(),
            head: local.upstream.own.holder.clone(),
            key,
        };
        local.report(rolls, &mut link, now);
        if let Err(e) = local.save(&furcate_paths::state("cell.json")) {
            eprintln!("furcated: WARNING the cell's state was not saved: {e}");
        }
    }

    /// How this head stands with its parent, when it heads a cell.
    pub fn standing(&self, now: u64) -> Option<serde_json::Value> {
        let guard = self.local.lock().expect("cells lock");
        guard.as_ref().map(|l| {
            json!({
                "cell": l.upstream.own.scope.as_string(),
                "parent_key": l.upstream.parent_key,
                "parent_endpoint": l.upstream.parent_endpoint,
                "standing": l.standing(now),
            })
        })
    }
}

/// The upward link: a signed POST to the parent's `/cells/rollup`.
struct HttpUplink {
    endpoint: String,
    head: String,
    key: Arc<dyn MessageSigner>,
}

impl Uplink for HttpUplink {
    fn send(&mut self, up: &Upward) -> Result<(), String> {
        let key = Arc::clone(&self.key);
        let sealed = up.seal(&self.head, |m| key.sign(m).map_err(|e| format!("the signer refused: {e:#}")))?;
        let body = serde_json::to_value(&sealed).map_err(|e| e.to_string())?;
        let reply = furcate_api::post_json(&self.endpoint, "/cells/rollup", &body, 5_000)
            .map_err(|e| format!("{} did not answer: {e}", self.endpoint))?;
        match reply.get("taken") {
            Some(_) => Ok(()),
            None => Err(format!("{} refused the report: {reply}", self.endpoint)),
        }
    }
}

/// Mount `GET /cells`, `GET /cells/view`, `GET /cells/standing`,
/// `GET /cells/read-challenge`, `POST /cells/read-token`, `POST /cells/enrol`,
/// `POST /cells/leaf` and `POST /cells/rollup`.
pub fn routes(
    r: Router,
    cells: Arc<Cells>,
    readings: Arc<dyn Fn(u64) -> Readings + Send + Sync>,
) -> Router {
    let source: Arc<furcate_siteview::cells::Source> = {
        let cells = Arc::clone(&cells);
        let readings = Arc::clone(&readings);
        Arc::new(move |now| {
            let tree = cells.tree(now)?;
            let mut r = readings(now);
            r.reported = cells.reported();
            Ok((tree, r))
        })
    };
    let r = furcate_siteview::cells::routes(r, source);
    // Enrolment signs with this node's own key, so only the operator may ask
    // for it: a link is authority, and the operator is where it starts.
    let enrol = Arc::clone(&cells);
    let r = r.guarded("POST", "/cells/enrol", move |req: &Request| {
        if let Err(why) = operator_only(req) {
            return why;
        }
        let e: HeadEnrolment = match serde_json::from_value(req.body.clone()) {
            Ok(e) => e,
            Err(err) => return Response::error(400, format!("not a head enrolment: {err}")),
        };
        match enrol.enrol_head(&e, super::now_s()) {
            Ok(v) => Response::ok(v),
            Err(why) => Response::refused(why),
        }
    });
    let leaf = Arc::clone(&cells);
    let r = r.guarded("POST", "/cells/leaf", move |req: &Request| {
        if let Err(why) = operator_only(req) {
            return why;
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ask {
            attachment: Value,
            until: u64,
        }
        let ask: Ask = match serde_json::from_value(req.body.clone()) {
            Ok(a) => a,
            Err(err) => return Response::error(400, format!("not a leaf enrolment: {err}")),
        };
        let att = match Attachment::from_record(&ask.attachment) {
            Ok(a) => a,
            Err(why) => return Response::refused(format!("not a leaf attachment record: {why}")),
        };
        match leaf.enrol_leaf(&att, ask.until, super::now_s()) {
            Ok(l) => Response::ok(json!({ "link": l })),
            Err(why) => Response::refused(why),
        }
    });
    // A cell manager's read: a challenge over the request, then the token,
    // which carries its own proof, the passkey assertion.
    let ask = Arc::clone(&cells);
    let r = r.route("GET", "/cells/read-challenge", move |req: &Request| {
        let (Some(holder), Some(scope)) = (req.query_param("holder"), req.query_param("scope")) else {
            return Response::error(400, "`holder` (passkey:<rp id>:<credential id>) and `scope` are required");
        };
        let secs = req.query_param("secs").and_then(|s| s.parse().ok()).unwrap_or(read_token::MAX_READ_SECS);
        match ask.read_challenge(&holder, &scope, secs, super::now_s()) {
            Ok(v) => Response::ok(v),
            Err(why) => Response::refused(why),
        }
    });
    let issue = Arc::clone(&cells);
    let r = r.carrying_proof("POST", "/cells/read-token", move |req: &Request| {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ask {
            nonce: String,
            assertion: Assertion,
        }
        let ask: Ask = match serde_json::from_value(req.body.clone()) {
            Ok(a) => a,
            Err(err) => return Response::error(400, format!("not a read token request: {err}")),
        };
        match issue.read_token(&ask.nonce, &ask.assertion, super::now_s()) {
            Ok(v) => Response::ok(v),
            Err(why) => Response::refused(why),
        }
    });
    let standing = Arc::clone(&cells);
    r.guarded("GET", "/cells/standing", move |_: &Request| {
        match standing.standing(super::now_s()) {
            Some(v) => Response::ok(v),
            None => Response::ok(json!({ "cell": null, "note": "this node heads no cell" })),
        }
    })
    // The report carries its own proof: the head's signature, checked
    // against the head key this node's own chain holds for that cell. A
    // cell's link is what admits it; no roster entry is needed or consulted.
    .carrying_proof("POST", "/cells/rollup", move |req: &Request| {
        let sealed: Sealed = match serde_json::from_value(req.body.clone()) {
            Ok(s) => s,
            Err(e) => return Response::error(400, format!("not a sealed cell report: {e}")),
        };
        match cells.take(&sealed, super::now_s()) {
            Ok(n) => Response::ok(json!({ "taken": n })),
            Err(why) => Response::refused(why),
        }
    })
}

fn operator_only(req: &Request) -> Result<(), Response> {
    match req.principal.as_ref() {
        Some(p) if p.evidence == furcate_authn::Evidence::OperatorSignature => Ok(()),
        Some(p) => Err(Response::refused(format!(
            "{} is not the operator; enrolling signs a link, and links start with the operator",
            p.id
        ))),
        None => Err(Response::refused("enrolment is the operator's to ask for")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_authn::{Class, Evidence, Principal};

    fn ask(principal: Option<Principal>) -> Request {
        // A re-enrolment that lowers the cell's leaf floor: the floor rides in
        // the head's link, and only the operator may have a link signed.
        let body = json!({
            "gateway": "ed25519:00", "assurance": "device", "endpoint": "pi-lab:7616", "name": "pi-lab",
            "cell": "lab", "scale": "home", "until": 1, "leaf_min_class": "soft",
        });
        Request { method: "POST".into(), path: "/cells/enrol".into(), principal, body, ..Default::default() }
    }

    #[test]
    fn a_leaf_floor_change_is_the_operators_alone() {
        assert!(operator_only(&ask(Some(Principal::operator("op")))).is_ok());
        let manager = Principal {
            id: "passkey:example.org:cred-lab".into(),
            class: Class::Person,
            evidence: Evidence::Delegated { root: "passkey".into(), depth: 1 },
            expires_at: None,
            task: None,
            needs_approval_for: vec![],
            roles: vec![],
        };
        assert!(operator_only(&ask(Some(manager))).is_err());
        assert!(operator_only(&ask(None)).is_err());
    }
}
