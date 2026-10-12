//! Orders: proposed by anyone this node recognises, approved by passkeys,
//! carried out by the node they name.
//!
//! People and agents propose in the same canonical schema
//! ([`furcate_authn::order`]). Proposing changes nothing. An order takes effect
//! only when enough independent passkey credentials have approved its hash,
//! and the node it names is the one that checks that: it issued the nonces the
//! approvals are bound to, it holds the roster of credentials, and it carries
//! the order out or refuses it. A coordinator relaying an order cannot make
//! one, and an agent cannot approve one, because approval is an assertion from
//! an authenticator a person unlocked.
//!
//! Every step is handed to the [`Executor`] to append to the node's ledger. An
//! order that was refused is recorded as carefully as one that acted.
//!
//! ## What the ledger says happened
//!
//! An order that reached its threshold is recorded as one of these, and only
//! the first is written before anything acts:
//!
//! - `approved` — enough independent credentials approved it. Written to disk
//!   before the executor is called, so a node that restarts midway comes back
//!   knowing it was told, and records the order as `actuation_failed` with
//!   that reason rather than forgetting it.
//! - `planned` — authorised and planned, but nothing on this machine acted.
//! - `actuated` — an actuator reported that it acted, and the entry carries
//!   what it reported. Nothing else produces this status.
//! - `actuation_failed` — an actuator ran and reported failure, or acted only
//!   in part, or never reported. The entry carries why, and what did happen.
//! - `refused` — checked and turned down before anything acted.
//!
//! ## What survives a restart
//!
//! Outstanding nonces, nonces already spent (until they would have expired),
//! proposals, and every approval counted towards them are kept in one file in
//! the node's state directory, rewritten atomically after each change. A
//! counted approval is kept as the assertion itself and checked again on load
//! against the roster as it then stands, so what comes back from disk is still
//! only what a passkey signed.
//!
//! ## Routes
//!
//! - `GET /challenge?order=<hash>` — a fresh nonce for approving one pending
//!   order, and the challenge bytes to sign (`?purpose=enrol` for enrolment,
//!   `?purpose=cancel&credential=<id>` to cancel a pending admission).
//! - `POST /proposals` — guarded. Any proved principal, person or agent.
//! - `GET /proposals` — what is pending and what was decided.
//! - `POST /orders` — an order hash and one or more assertions. Carries its own
//!   proof, so the router establishes no principal for it.
//! - `POST /enrolments` — the public result of a creation ceremony (its
//!   attestation object), staged with the RP ID, AAGUID and backup flags read
//!   from it.
//! - `POST /credentials` — guarded, operator only: admit a staged credential
//!   directly. Once a roster exists, `admit` and `revoke` orders do the same
//!   under a threshold.
//! - `POST /credentials/cancel` — an assertion from any usable credential
//!   cancelling an admission still in its cancel window. Carries its own proof.
//! - `GET /credentials` — the roster, which is public keys only.
//! - `GET /actuation` — what this node's actuators report about it now: an
//!   isolation in force, an erase waiting to be acknowledged.
//!
//! Either way of admitting follows the same rule: while the site's usable
//! credentials make fewer than two independent roots, a new credential waits
//! out `add_passkey_delay_s` before it can approve, and any usable credential
//! can cancel it until then (see [`furcate_authn::webauthn`]).

use crate::{Request, Response, Router};
use furcate_authn::order::{Action, Bounds, Order, Target};
use furcate_authn::webauthn::{
    self, Approval, Assertion, Challenge, Credential, Enrolled, Enrolment, Roster, Tally,
    Thresholds,
};
use furcate_authn::{Class, Evidence};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Outstanding nonces a node will hold before refusing to issue more.
const MAX_NONCES: usize = 1024;
/// Proposals kept, pending and decided together.
const MAX_PROPOSALS: usize = 256;
/// Verified enrolments waiting to be admitted.
const MAX_STAGED: usize = 64;

/// What became of an approved order on this machine.
#[derive(Clone, Debug, PartialEq)]
pub enum Execution {
    /// Authorised and planned, but nothing on this machine acted.
    Planned(Value),
    /// An actuator reported that it acted; the value is what it reported.
    Actuated(Value),
    /// An actuator ran and reported failure, acted only in part, or never
    /// reported. `detail` is whatever it did report.
    Failed { why: String, detail: Value },
}

/// What the node does once an order is approved.
pub trait Executor: Send + Sync {
    /// Whether this node is one the target names. A node only takes approvals
    /// for, and only carries out, orders that name it. A credential target is
    /// about this node's own roster, so it always covers it.
    fn covers(&self, target: &Target) -> Result<(), String>;

    /// Carry out an approved machine order. The approval is the proof; the
    /// executor checks it against the order before acting. `Err` means it
    /// refused before anything acted.
    fn execute(&self, order: &Order, approval: &Approval) -> Result<Execution, String>;

    /// What this node's actuators report about it now.
    fn state(&self) -> Value {
        Value::Null
    }

    /// Append one entry to the node's ledger.
    fn record(&self, entry: &Value);
}

/// The site's settings for passkey orders.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrdersConfig {
    /// The site's name in every order, and the RP ID an enrolment uses when
    /// it names none. Each admitted credential keeps the RP ID it was created
    /// for and is verified against that.
    pub rp_id: String,
    #[serde(default)]
    pub thresholds: Thresholds,
    /// How long a nonce stays usable.
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_s: u64,
    /// The longest an order may stay open for approval.
    #[serde(default = "default_order_lifetime")]
    pub max_order_lifetime_s: u64,
    /// How long a credential added while the site has fewer than two
    /// independent roots waits before it can approve, during which any usable
    /// credential can cancel it.
    #[serde(default = "default_add_passkey_delay")]
    pub add_passkey_delay_s: u64,
}

fn default_add_passkey_delay() -> u64 {
    48 * 3600
}

fn default_challenge_ttl() -> u64 {
    300
}

fn default_order_lifetime() -> u64 {
    3600
}

fn check_rp_id(rp_id: &str) -> Result<(), String> {
    if rp_id.is_empty() || rp_id.contains('/') || rp_id.contains(':') || rp_id.contains(' ') {
        return Err(format!("`{rp_id}` is not a domain an RP ID can be"));
    }
    Ok(())
}

impl OrdersConfig {
    pub fn validate(&self) -> Result<(), String> {
        check_rp_id(&self.rp_id)?;
        if self.challenge_ttl_s == 0 || self.max_order_lifetime_s == 0 {
            return Err("lifetimes must be above zero".into());
        }
        self.thresholds.validate()
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c: Self =
            serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        c.validate()?;
        Ok(c)
    }
}

struct Proposal {
    order: Order,
    proposed_by: String,
    class: Class,
    tally: Tally,
    /// The assertions behind `tally`, kept so they can be checked again after
    /// a restart.
    counted: Vec<Counted>,
    outcome: Option<Value>,
}

#[derive(Default)]
struct State {
    roster: Roster,
    nonces: BTreeMap<String, Challenge>,
    /// Nonces already used, with the time each would have expired. Kept until
    /// then so a nonce stays single-use across a restart.
    spent: BTreeMap<String, u64>,
    proposals: BTreeMap<String, Proposal>,
    staged: BTreeMap<String, Enrolled>,
    last_counter: u64,
}

/// A challenge as it is kept on disk.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeptChallenge {
    order_hash: String,
    nonce: String,
    expires_at: u64,
}

impl KeptChallenge {
    fn of(c: &Challenge) -> Self {
        Self {
            order_hash: hex::encode(c.order_hash),
            nonce: hex::encode(c.nonce),
            expires_at: c.expires_at,
        }
    }

    fn restore(&self) -> Result<Challenge, String> {
        let mut order_hash = [0u8; 32];
        let mut nonce = [0u8; 16];
        hex::decode_to_slice(&self.order_hash, &mut order_hash).map_err(|_| {
            format!(
                "challenge for nonce {} has a malformed order hash",
                self.nonce
            )
        })?;
        hex::decode_to_slice(&self.nonce, &mut nonce)
            .map_err(|_| format!("nonce {} is malformed", self.nonce))?;
        Ok(Challenge {
            order_hash,
            nonce,
            expires_at: self.expires_at,
        })
    }
}

/// An approval that was counted: the assertion and the challenge it signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Counted {
    challenge: KeptChallenge,
    assertion: Assertion,
}

#[derive(Serialize, Deserialize)]
struct KeptProposal {
    order: Order,
    proposed_by: String,
    class: Class,
    #[serde(default)]
    counted: Vec<Counted>,
    outcome: Option<Value>,
}

/// The desk's state as it is written to disk. The roster has its own file.
#[derive(Default, Serialize, Deserialize)]
struct Kept {
    #[serde(default)]
    last_counter: u64,
    #[serde(default)]
    nonces: BTreeMap<String, KeptChallenge>,
    #[serde(default)]
    spent: BTreeMap<String, u64>,
    #[serde(default)]
    proposals: BTreeMap<String, KeptProposal>,
    #[serde(default)]
    staged: BTreeMap<String, Enrolled>,
}

impl Kept {
    fn load(path: &std::path::Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn of(st: &State, now: u64) -> Self {
        Self {
            last_counter: st.last_counter,
            nonces: st
                .nonces
                .iter()
                .filter(|(_, c)| c.expires_at > now)
                .map(|(n, c)| (n.clone(), KeptChallenge::of(c)))
                .collect(),
            spent: st
                .spent
                .iter()
                .filter(|(_, at)| **at > now)
                .map(|(n, at)| (n.clone(), *at))
                .collect(),
            proposals: st
                .proposals
                .iter()
                .map(|(h, p)| {
                    (
                        h.clone(),
                        KeptProposal {
                            order: p.order.clone(),
                            proposed_by: p.proposed_by.clone(),
                            class: p.class,
                            counted: p.counted.clone(),
                            outcome: p.outcome.clone(),
                        },
                    )
                })
                .collect(),
            staged: st.staged.clone(),
        }
    }
}

/// Write a file so that a reader sees the old contents or the new, never a
/// torn mixture, and so that the new contents are on disk when this returns.
fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(at)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(at)?;
    f.write_all(bytes).map_err(at)?;
    f.sync_all().map_err(at)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(at)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            d.sync_all().map_err(at)?;
        }
    }
    Ok(())
}

/// The node's order desk: nonces, proposals, roster.
pub struct Desk {
    config: Result<OrdersConfig, String>,
    roster_path: Option<PathBuf>,
    state_path: Option<PathBuf>,
    state: Mutex<State>,
    executor: Arc<dyn Executor>,
}

impl Desk {
    /// A desk. `config` is an error when the site has not set passkey orders
    /// up; every route then refuses and says why, rather than vanishing.
    ///
    /// `state_path` is where nonces, proposals and their approvals are kept
    /// across restarts. With no configuration nothing is read from it or
    /// written to it, so a file left by a configured run waits intact.
    pub fn new(
        config: Result<OrdersConfig, String>,
        roster_path: Option<PathBuf>,
        state_path: Option<PathBuf>,
        executor: Arc<dyn Executor>,
    ) -> Result<Self, String> {
        let roster = match &roster_path {
            Some(p) => Roster::load(p)?,
            None => Roster::default(),
        };
        for u in &roster.unproved {
            eprintln!("furcate-api: credential {} is refused: {}", u.id, u.because);
        }
        let config = config.and_then(|c| c.validate().map(|_| c));
        let mut state = State {
            roster,
            ..Default::default()
        };
        if let (Ok(cfg), Some(path)) = (&config, &state_path) {
            let kept = Kept::load(path)?;
            Self::restore(&mut state, kept, cfg, executor.as_ref());
        }
        Ok(Self {
            config,
            roster_path,
            state_path,
            state: Mutex::new(state),
            executor,
        })
    }

    /// Rebuild the state a previous run kept. Each counted approval is checked
    /// again against the roster as it now stands; one that no longer verifies
    /// is dropped and the drop recorded. An order that was approved but never
    /// reported an outcome was interrupted, and is recorded as having failed.
    fn restore(st: &mut State, kept: Kept, cfg: &OrdersConfig, executor: &dyn Executor) {
        st.last_counter = kept.last_counter;
        st.spent = kept.spent;
        st.staged = kept.staged;
        for (n, c) in kept.nonces {
            match c.restore() {
                Ok(c) => {
                    st.nonces.insert(n, c);
                }
                Err(why) => eprintln!("furcate-api: a kept nonce was dropped: {why}"),
            }
        }
        for (hash, k) in kept.proposals {
            let mut tally = match Tally::new(&k.order, &cfg.thresholds) {
                Ok(t) => t,
                Err(e) => {
                    executor.record(&json!({
                        "event": "proposal_dropped",
                        "order_hash": hash,
                        "because": e.to_string(),
                    }));
                    continue;
                }
            };
            let mut counted = Vec::new();
            for c in k.counted {
                let checked = c.challenge.restore().and_then(|challenge| {
                    let credential =
                        st.roster.get(&c.assertion.credential_id).ok_or_else(|| {
                            format!(
                                "credential {} is no longer admitted",
                                c.assertion.credential_id
                            )
                        })?;
                    webauthn::reverify_counted(credential, &c.assertion, &challenge)
                        .map_err(|r| r.because)
                });
                match checked.and_then(|v| tally.add(v).map_err(|r| r.because)) {
                    Ok(_) => counted.push(c),
                    Err(why) => executor.record(&json!({
                        "event": "approval_dropped",
                        "order_hash": hash,
                        "credential_id": c.assertion.credential_id,
                        "because": why,
                    })),
                }
            }
            let mut outcome = k.outcome;
            if outcome.as_ref().and_then(|o| o["status"].as_str()) == Some("approved") {
                let why = "the node restarted after the order was approved and before any \
                           actuator reported; whether it acted is not known";
                executor.record(&json!({
                    "event": "actuation_failed",
                    "order_hash": hash,
                    "action": k.order.action.as_str(),
                    "because": why,
                }));
                let mut o = outcome.take().unwrap_or_default();
                o["status"] = json!("actuation_failed");
                o["because"] = json!(why);
                outcome = Some(o);
            }
            st.proposals.insert(
                hash,
                Proposal {
                    order: k.order,
                    proposed_by: k.proposed_by,
                    class: k.class,
                    tally,
                    counted,
                    outcome,
                },
            );
        }
    }

    /// Write the desk's state, when it has somewhere to go.
    fn persist(&self, st: &State, now: u64) -> Result<(), String> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let encoded = serde_json::to_vec(&Kept::of(st, now)).map_err(|e| e.to_string())?;
        write_atomically(path, &encoded)
    }

    /// As [`Self::persist`], where losing the write costs nothing that matters
    /// for safety: it is said aloud and the request goes on.
    fn persist_or_warn(&self, st: &State, now: u64) {
        if let Err(e) = self.persist(st, now) {
            eprintln!("furcate-api: WARNING order state not persisted: {e}");
        }
    }

    fn config(&self) -> Result<&OrdersConfig, Response> {
        self.config.as_ref().map_err(|why| {
            Response::refused(format!(
                "passkey orders are not configured on this node: {why}"
            ))
        })
    }

    fn save_roster(&self, roster: &Roster) -> Result<(), String> {
        match &self.roster_path {
            Some(p) => roster.save(p),
            None => Ok(()),
        }
    }

    fn fresh_nonce() -> Result<[u8; 16], Response> {
        let mut n = [0u8; 16];
        getrandom::fill(&mut n)
            .map_err(|_| Response::error(500, "this node could not draw a random nonce"))?;
        Ok(n)
    }

    fn challenge(&self, req: &Request, now: u64) -> Response {
        let cfg = match self.config() {
            Ok(c) => c,
            Err(r) => return r,
        };
        let mut st = self.state.lock().expect("orders lock");
        st.nonces.retain(|_, c| c.expires_at > now);
        st.spent.retain(|_, at| *at > now);
        if st.nonces.len() >= MAX_NONCES {
            return Response::error(503, "too many approvals are outstanding; try again shortly");
        }
        let nonce = match Self::fresh_nonce() {
            Ok(n) => n,
            Err(r) => return r,
        };
        let expires_at = now + cfg.challenge_ttl_s;
        let purpose = req.query_param("purpose");
        let (challenge, order) = if purpose.as_deref() == Some("enrol") {
            (Challenge::enrolment(nonce, expires_at), Value::Null)
        } else if purpose.as_deref() == Some("cancel") {
            let Some(id) = req.query_param("credential") else {
                return Response::error(400, "`credential` (the pending credential id) is required");
            };
            let Some(c) = st.roster.get(&id) else {
                return Response::error(404, format!("no credential {id} on this node"));
            };
            if c.usable(now) {
                return Response::refused(format!(
                    "credential {id} is not in a cancel window; remove it with a `revoke` order"
                ));
            }
            let pending = json!({ "credential_id": c.id, "usable_from": c.usable_from });
            (Challenge::cancel(&id, nonce, expires_at), pending)
        } else {
            let Some(hash) = req.query_param("order") else {
                return Response::error(
                    400,
                    "`order` (the order hash), `purpose=enrol` or `purpose=cancel` is required",
                );
            };
            let Some(p) = st.proposals.get(&hash) else {
                return Response::error(404, format!("no proposal {hash} on this node"));
            };
            if p.outcome.is_some() {
                return Response::refused("that order has already been decided");
            }
            let mut order_hash = [0u8; 32];
            if hex::decode_to_slice(&hash, &mut order_hash).is_err() {
                return Response::error(400, "`order` is not a hex hash");
            }
            // An approval cannot outlive the order it approves.
            let expires_at = expires_at.min(p.order.expires_at);
            let canonical = p
                .order
                .canonical()
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            (
                Challenge {
                    order_hash,
                    nonce,
                    expires_at,
                },
                json!({ "order": p.order, "canonical": canonical.unwrap_or_default() }),
            )
        };
        st.nonces.insert(hex::encode(nonce), challenge);
        self.persist_or_warn(&st, now);
        let rp_ids: std::collections::BTreeSet<&str> = st
            .roster
            .credentials
            .iter()
            .filter(|c| c.usable(now))
            .map(|c| c.rp_id.as_str())
            .collect();
        Response::ok(json!({
            "rp_id": cfg.rp_id,
            "rp_ids": rp_ids,
            "nonce": hex::encode(nonce),
            "expires_at": challenge.expires_at,
            "challenge": challenge.encoded(),
            "order_hash": hex::encode(challenge.order_hash),
            "proposal": order,
        }))
    }

    fn propose(&self, req: &Request, now: u64) -> Response {
        let cfg = match self.config() {
            Ok(c) => c,
            Err(r) => return r,
        };
        let Some(principal) = req.principal.as_ref() else {
            return Response::refused("proposing needs a proved caller");
        };
        #[derive(Deserialize)]
        struct Body {
            action: Action,
            target: Target,
            bounds: Bounds,
            #[serde(default)]
            reason: String,
            expires_in_s: u64,
        }
        let body: Body = match serde_json::from_value(req.body.clone()) {
            Ok(b) => b,
            Err(e) => return Response::error(400, format!("not a proposal: {e}")),
        };
        if body.expires_in_s == 0 || body.expires_in_s > cfg.max_order_lifetime_s {
            return Response::error(
                400,
                format!(
                    "`expires_in_s` must be between 1 and {}",
                    cfg.max_order_lifetime_s
                ),
            );
        }
        if let Err(why) = self.executor.covers(&body.target) {
            return Response::refused(format!("this node is not the target of that order: {why}"));
        }
        let mut st = self.state.lock().expect("orders lock");
        // Strictly increasing, and above the clock, so a restarted node does
        // not hand out a counter it already carried out.
        let counter = (st.last_counter + 1).max(now);
        let order = Order {
            site: cfg.rp_id.clone(),
            action: body.action,
            target: body.target,
            bounds: body.bounds,
            counter,
            issued_at: now,
            expires_at: now + body.expires_in_s,
            reason: body.reason,
        };
        let tally = match Tally::new(&order, &cfg.thresholds) {
            Ok(t) => t,
            Err(e) => return Response::error(400, e.to_string()),
        };
        let hash = hex::encode(order.hash().expect("validated by Tally::new"));
        if st.proposals.contains_key(&hash) {
            return Response::refused("that order has already been proposed");
        }
        if st.proposals.len() >= MAX_PROPOSALS {
            let stale: Vec<String> = st
                .proposals
                .iter()
                .filter(|(_, p)| p.outcome.is_some() || p.order.expires_at <= now)
                .map(|(h, _)| h.clone())
                .collect();
            for h in stale {
                st.proposals.remove(&h);
            }
            if st.proposals.len() >= MAX_PROPOSALS {
                return Response::error(503, "too many orders are pending on this node");
            }
        }
        let previous_counter = st.last_counter;
        st.last_counter = counter;
        let required = tally.required();
        let canonical =
            String::from_utf8_lossy(&order.canonical().expect("validated")).into_owned();
        st.proposals.insert(
            hash.clone(),
            Proposal {
                order: order.clone(),
                proposed_by: principal.id.clone(),
                class: principal.class,
                tally,
                counted: Vec::new(),
                outcome: None,
            },
        );
        if let Err(e) = self.persist(&st, now) {
            st.proposals.remove(&hash);
            st.last_counter = previous_counter;
            return Response::error(
                503,
                format!("this node could not keep the proposal durably, so it holds none: {e}"),
            );
        }
        self.executor.record(&json!({
            "event": "proposed",
            "order_hash": hash,
            "action": order.action.as_str(),
            "by": principal.id,
            "class": principal.class,
        }));
        Response::ok(json!({
            "order_hash": hash,
            "order": order,
            "canonical": canonical,
            "required": required,
        }))
    }

    fn list(&self) -> Response {
        let st = self.state.lock().expect("orders lock");
        let proposals: Vec<Value> = st
            .proposals
            .iter()
            .map(|(h, p)| {
                json!({
                    "order_hash": h,
                    "order": p.order,
                    "proposed_by": p.proposed_by,
                    "class": p.class,
                    "approvals": p.tally.count(),
                    "required": p.tally.required(),
                    "outcome": p.outcome,
                })
            })
            .collect();
        Response::ok(json!({ "proposals": proposals }))
    }

    fn approve(&self, req: &Request, now: u64) -> Response {
        if let Err(r) = self.config() {
            return r;
        }
        #[derive(Deserialize)]
        struct One {
            nonce: String,
            assertion: Assertion,
        }
        #[derive(Deserialize)]
        struct Body {
            order_hash: String,
            approvals: Vec<One>,
        }
        let body: Body = match serde_json::from_value(req.body.clone()) {
            Ok(b) => b,
            Err(e) => return Response::error(400, format!("not an approval: {e}")),
        };
        if body.approvals.is_empty() {
            return Response::error(400, "at least one assertion is required");
        }
        let hash = body.order_hash.clone();
        let mut st = self.state.lock().expect("orders lock");
        let expires_at = match st.proposals.get(&hash) {
            None => return Response::error(404, format!("no proposal {hash} on this node")),
            Some(p) => {
                if let Some(outcome) = &p.outcome {
                    return Response::refused(format!(
                        "that order has already been decided: {outcome}"
                    ));
                }
                p.order.expires_at
            }
        };
        if now >= expires_at {
            return self.decide_refused(
                &mut st,
                &hash,
                format!("the order expired at {expires_at}"),
                now,
            );
        }

        let mut refusals = Vec::new();
        let mut roster_changed = false;
        {
            let State {
                roster,
                nonces,
                spent,
                proposals,
                ..
            } = &mut *st;
            let p = proposals.get_mut(&hash).expect("checked above");
            for one in body.approvals {
                // Spent whatever happens next: a nonce is good for one attempt.
                let Some(challenge) = nonces.remove(&one.nonce) else {
                    refusals.push(if spent.contains_key(&one.nonce) {
                        format!("nonce {} was already used", one.nonce)
                    } else {
                        format!("nonce {} was not issued here, or has expired", one.nonce)
                    });
                    continue;
                };
                spent.insert(one.nonce.clone(), challenge.expires_at);
                if hex::encode(challenge.order_hash) != hash {
                    refusals.push(format!(
                        "nonce {} was issued for a different order",
                        one.nonce
                    ));
                    continue;
                }
                let credential = match roster.lookup(&one.assertion.credential_id) {
                    Ok(c) => c.clone(),
                    Err(why) => {
                        refusals.push(why);
                        continue;
                    }
                };
                match webauthn::verify_assertion(&credential, &one.assertion, &challenge, now) {
                    Ok(v) => {
                        roster.advance(&v);
                        roster_changed = true;
                        match p.tally.add(v) {
                            Ok(true) => p.counted.push(Counted {
                                challenge: KeptChallenge::of(&challenge),
                                assertion: one.assertion,
                            }),
                            Ok(false) => {}
                            Err(r) => refusals.push(r.because),
                        }
                    }
                    Err(r) => refusals.push(format!("{}: {}", credential.id, r.because)),
                }
            }
        }
        if roster_changed {
            if let Err(e) = self.save_roster(&st.roster) {
                eprintln!("furcate-api: WARNING credential counters not persisted: {e}");
            }
        }
        for why in &refusals {
            self.executor.record(&json!({
                "event": "approval_refused",
                "order_hash": hash,
                "because": why,
            }));
        }

        let (order, approval) = {
            let p = &st.proposals[&hash];
            (p.order.clone(), p.tally.approval())
        };
        let Some(approval) = approval else {
            self.persist_or_warn(&st, now);
            let p = &st.proposals[&hash];
            return Response::ok(json!({
                "order_hash": hash,
                "status": "pending",
                "approvals": p.tally.count(),
                "required": p.tally.required(),
                "refused": refusals,
            }));
        };

        if let Err(why) = self.executor.covers(&order.target) {
            return self.decide_refused(
                &mut st,
                &hash,
                format!("this node is not the target: {why}"),
                now,
            );
        }

        // Written down before anything acts, so a node that dies midway comes
        // back knowing it was told. If that cannot be written, nothing acts.
        st.proposals.get_mut(&hash).expect("present").outcome = Some(json!({
            "status": "approved",
            "approvers": approval.approvers(),
            "roots": approval.roots(),
            "at": now,
        }));
        if let Err(e) = self.persist(&st, now) {
            st.proposals.get_mut(&hash).expect("present").outcome = None;
            let why = format!("the approval could not be kept durably, so nothing acted: {e}");
            self.executor.record(&json!({
                "event": "not_acted",
                "order_hash": hash,
                "action": order.action.as_str(),
                "because": why,
            }));
            return Response::error(503, why);
        }
        self.executor.record(&json!({
            "event": "approved",
            "order_hash": hash,
            "action": order.action.as_str(),
            "approvers": approval.approvers(),
            "roots": approval.roots(),
        }));

        let execution = match order.action {
            Action::Admit | Action::Revoke => self.roster_order(&mut st, &order, now),
            _ => self.executor.execute(&order, &approval),
        };
        let mut outcome = json!({
            "approvers": approval.approvers(),
            "at": now,
        });
        let mut entry = json!({
            "order_hash": hash,
            "action": order.action.as_str(),
            "approvers": approval.approvers(),
            "roots": approval.roots(),
        });
        let (status, code) = match execution {
            Ok(Execution::Planned(detail)) => {
                outcome["detail"] = detail.clone();
                entry["detail"] = detail;
                ("planned", 200)
            }
            Ok(Execution::Actuated(detail)) => {
                outcome["detail"] = detail.clone();
                entry["detail"] = detail;
                ("actuated", 200)
            }
            Ok(Execution::Failed { why, detail }) => {
                outcome["because"] = json!(why);
                outcome["detail"] = detail.clone();
                entry["because"] = json!(why);
                entry["detail"] = detail;
                ("actuation_failed", 502)
            }
            Err(why) => {
                outcome["because"] = json!(why);
                entry["because"] = json!(why);
                ("refused", 403)
            }
        };
        outcome["status"] = json!(status);
        entry["event"] = json!(status);
        self.executor.record(&entry);
        st.proposals.get_mut(&hash).expect("present").outcome = Some(outcome.clone());
        if let Err(e) = self.persist(&st, now) {
            eprintln!(
                "furcate-api: WARNING the outcome of {hash} was not persisted, and after a \
                 restart it will read as interrupted: {e}"
            );
        }
        Response {
            status: code,
            ..Response::ok(json!({ "order_hash": hash, "outcome": outcome, "refused": refusals }))
        }
    }

    /// Decide a pending proposal as refused, record it and keep it.
    fn decide_refused(&self, st: &mut State, hash: &str, why: String, now: u64) -> Response {
        let Some(p) = st.proposals.get_mut(hash) else {
            return Response::error(404, format!("no proposal {hash} on this node"));
        };
        self.executor.record(&json!({
            "event": "refused",
            "order_hash": hash,
            "action": p.order.action.as_str(),
            "because": why,
        }));
        p.outcome = Some(json!({ "status": "refused", "because": why, "at": now }));
        self.persist_or_warn(st, now);
        Response::refused(why)
    }

    /// Carry out `admit` or `revoke`. The change counts as made only once the
    /// roster file holds it; if that write fails the change is undone, so the
    /// roster in memory never says something the file does not.
    fn roster_order(&self, st: &mut State, order: &Order, now: u64) -> Result<Execution, String> {
        let roster_before = st.roster.clone();
        let staged_before = st.staged.clone();
        let State { roster, staged, .. } = st;
        let delay_s = self
            .config
            .as_ref()
            .map(|c| c.add_passkey_delay_s)
            .unwrap_or_else(|_| default_add_passkey_delay());
        let detail = Self::change_roster(roster, staged, order, delay_s, now)?;
        match self.save_roster(&st.roster) {
            Ok(()) => Ok(Execution::Actuated(detail)),
            Err(e) => {
                st.roster = roster_before;
                st.staged = staged_before;
                Ok(Execution::Failed {
                    why: format!("the roster could not be written, so the change was undone: {e}"),
                    detail: json!({ "undone": detail }),
                })
            }
        }
    }

    fn change_roster(
        roster: &mut Roster,
        staged: &mut BTreeMap<String, Enrolled>,
        order: &Order,
        delay_s: u64,
        now: u64,
    ) -> Result<Value, String> {
        let Target::Credential { id, key_sha256, rp_id } = &order.target
        else {
            return Err("a roster order must name a credential".into());
        };
        match order.action {
            Action::Admit => {
                let Some(e) = staged.get(id) else {
                    return Err(format!(
                        "credential {id} has not been enrolled on this node"
                    ));
                };
                if &e.key_sha256 != key_sha256 {
                    return Err("the enrolled key is not the one this order names".into());
                }
                if &e.rp_id != rp_id {
                    return Err(format!(
                        "the credential was made for `{}`, not the `{rp_id}` this order names",
                        e.rp_id
                    ));
                }
                let c = Credential::from_enrolled(e, order.reason.clone(), now);
                let root = c.root();
                let admitted = roster.admit(c, now, delay_s)?;
                staged.remove(id);
                Ok(json!({ "admitted": id, "root": root, "admission": admitted }))
            }
            Action::Revoke => {
                let Some(c) = roster.get(id) else {
                    return Err(format!("credential {id} is not admitted here"));
                };
                if &c.key_sha256() != key_sha256 {
                    return Err("the admitted key is not the one this order names".into());
                }
                roster.revoke(id);
                Ok(json!({ "revoked": id }))
            }
            _ => Err("not a roster order".into()),
        }
    }

    fn enrol(&self, req: &Request, now: u64) -> Response {
        let cfg = match self.config() {
            Ok(c) => c,
            Err(r) => return r,
        };
        #[derive(Deserialize)]
        struct Body {
            nonce: String,
            enrolment: Enrolment,
            /// The RP ID the credential was created for; the site's when
            /// absent.
            #[serde(default)]
            rp_id: Option<String>,
        }
        let body: Body = match serde_json::from_value(req.body.clone()) {
            Ok(b) => b,
            Err(e) => return Response::error(400, format!("not an enrolment: {e}")),
        };
        let mut st = self.state.lock().expect("orders lock");
        let Some(challenge) = st.nonces.remove(&body.nonce) else {
            return Response::refused("that nonce was not issued here, or was already used");
        };
        st.spent.insert(body.nonce.clone(), challenge.expires_at);
        let rp_id = body.rp_id.unwrap_or_else(|| cfg.rp_id.clone());
        if let Err(why) = check_rp_id(&rp_id) {
            return Response::error(400, why);
        }
        let enrolled = match webauthn::verify_enrolment(&body.enrolment, &rp_id, &challenge, now)
        {
            Ok(e) => e,
            Err(r) => return Response::refused(r.because),
        };
        if st.staged.len() >= MAX_STAGED && !st.staged.contains_key(&enrolled.credential_id) {
            return Response::error(503, "too many enrolments are waiting to be admitted");
        }
        st.staged
            .insert(enrolled.credential_id.clone(), enrolled.clone());
        self.persist_or_warn(&st, now);
        Response::ok(json!({
            "credential_id": enrolled.credential_id,
            "key_sha256": enrolled.key_sha256,
            "rp_id": enrolled.rp_id,
            "aaguid": enrolled.aaguid,
            "backup_eligible": enrolled.backup_eligible,
            "backed_up": enrolled.backed_up,
            "next": "admit it: an `admit` order naming this id, key and RP ID, approved by \
                     the roster, or POST /credentials signed by the operator key",
        }))
    }

    fn admit_by_operator(&self, req: &Request, now: u64) -> Response {
        let cfg = match self.config() {
            Ok(c) => c,
            Err(r) => return r,
        };
        let Some(p) = req.principal.as_ref() else {
            return Response::refused("admitting a credential needs a proved caller");
        };
        if p.evidence != Evidence::OperatorSignature || p.class != Class::Person {
            return Response::refused(
                "only the operator key admits a credential directly; anybody else proposes an \
                 `admit` order for the roster to approve",
            );
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            credential_id: String,
            #[serde(default)]
            label: String,
        }
        let body: Body = match serde_json::from_value(req.body.clone()) {
            Ok(b) => b,
            Err(e) => {
                return Response::error(
                    400,
                    format!(
                        "not an admission: {e}; independence is read from the enrolment, not \
                         declared"
                    ),
                )
            }
        };
        let mut st = self.state.lock().expect("orders lock");
        let Some(e) = st.staged.get(&body.credential_id).cloned() else {
            return Response::error(404, "no enrolment with that credential id is staged here");
        };
        let mut roster = st.roster.clone();
        let c = Credential::from_enrolled(&e, body.label, now);
        let root = c.root();
        // The same rule an `admit` order follows: the operator key is not a
        // way round the cancel window.
        let admitted = match roster.admit(c, now, cfg.add_passkey_delay_s) {
            Ok(a) => a,
            Err(why) => return Response::refused(why),
        };
        if let Err(why) = self.save_roster(&roster) {
            return Response::error(500, format!("the roster could not be written: {why}"));
        }
        st.roster = roster;
        st.staged.remove(&body.credential_id);
        self.persist_or_warn(&st, now);
        self.executor.record(&json!({
            "event": "admitted",
            "credential_id": e.credential_id,
            "root": root,
            "usable_from": admitted.usable_from,
            "delayed": admitted.delayed,
            "by": p.id,
        }));
        Response::ok(json!({
            "admitted": e.credential_id,
            "key_sha256": e.key_sha256,
            "root": root,
            "admission": admitted,
        }))
    }

    fn cancel_admission(&self, req: &Request, now: u64) -> Response {
        if let Err(r) = self.config() {
            return r;
        }
        #[derive(Deserialize)]
        struct Body {
            /// The credential whose admission is cancelled.
            credential_id: String,
            nonce: String,
            assertion: Assertion,
        }
        let body: Body = match serde_json::from_value(req.body.clone()) {
            Ok(b) => b,
            Err(e) => return Response::error(400, format!("not a cancellation: {e}")),
        };
        let mut st = self.state.lock().expect("orders lock");
        let Some(challenge) = st.nonces.remove(&body.nonce) else {
            return Response::refused("that nonce was not issued here, or was already used");
        };
        st.spent.insert(body.nonce.clone(), challenge.expires_at);
        self.persist_or_warn(&st, now);
        if challenge.order_hash != webauthn::cancel_hash(&body.credential_id) {
            return Response::refused(format!(
                "that nonce was not issued for cancelling {}",
                body.credential_id
            ));
        }
        let by = match st.roster.lookup(&body.assertion.credential_id) {
            Ok(c) => c.clone(),
            Err(why) => return Response::refused(why),
        };
        let v = match webauthn::verify_assertion(&by, &body.assertion, &challenge, now) {
            Ok(v) => v,
            Err(r) => return Response::refused(format!("{}: {}", by.id, r.because)),
        };
        let mut roster = st.roster.clone();
        roster.advance(&v);
        if let Err(why) = roster.cancel(&body.credential_id, &v, now) {
            return Response::refused(why);
        }
        if let Err(why) = self.save_roster(&roster) {
            return Response::error(500, format!("the roster could not be written: {why}"));
        }
        st.roster = roster;
        self.executor.record(&json!({
            "event": "admission_cancelled",
            "credential_id": body.credential_id,
            "by": v.credential_id(),
        }));
        Response::ok(json!({ "cancelled": body.credential_id, "by": v.credential_id() }))
    }

    fn roster(&self, now: u64) -> Response {
        let st = self.state.lock().expect("orders lock");
        let creds: Vec<Value> = st
            .roster
            .credentials
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "key_sha256": c.key_sha256(),
                    "rp_id": c.rp_id,
                    "aaguid": c.aaguid,
                    "backup_eligible": c.backup_eligible,
                    "backed_up": c.backed_up,
                    "root": c.root(),
                    "label": c.label,
                    "admitted_at": c.admitted_at,
                    "usable_from": c.usable_from,
                    "pending": !c.usable(now),
                })
            })
            .collect();
        Response::ok(json!({
            "credentials": creds,
            "independent_roots": st.roster.roots(now).len(),
            "unproved": st.roster.unproved,
            "staged": st.staged.keys().collect::<Vec<_>>(),
        }))
    }
}

/// Register the order routes on a router.
pub fn mount(router: Router, desk: Arc<Desk>) -> Router {
    mount_at(router, desk, crate::now_s)
}

/// As [`mount`], with the clock supplied, so tests need not wait.
pub fn mount_at(router: Router, desk: Arc<Desk>, clock: fn() -> u64) -> Router {
    let d = Arc::clone(&desk);
    let router = router.route("GET", "/challenge", move |r| d.challenge(r, clock()));
    let d = Arc::clone(&desk);
    let router = router.guarded("POST", "/proposals", move |r| d.propose(r, clock()));
    let d = Arc::clone(&desk);
    let router = router.route("GET", "/proposals", move |_| d.list());
    let d = Arc::clone(&desk);
    let router = router.carrying_order("POST", "/orders", move |r| d.approve(r, clock()));
    let d = Arc::clone(&desk);
    let router = router.carrying_order("POST", "/enrolments", move |r| d.enrol(r, clock()));
    let d = Arc::clone(&desk);
    let router = router.guarded("POST", "/credentials", move |r| {
        d.admit_by_operator(r, clock())
    });
    let d = Arc::clone(&desk);
    let router = router.carrying_order("POST", "/credentials/cancel", move |r| {
        d.cancel_admission(r, clock())
    });
    let d = Arc::clone(&desk);
    let router = router.route("GET", "/credentials", move |_| d.roster(clock()));
    let d = desk;
    router.route("GET", "/actuation", move |_| {
        Response::ok(d.executor.state())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_authn::webauthn::virtual_authenticator::Authenticator;
    use furcate_authn::{Presented, Principal, Refusal, Verifier};
    use std::cell::Cell;

    const RP: &str = "site.example";
    const DELAY: u64 = 48 * 3600;

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(10_000) };
    }

    fn clock() -> u64 {
        NOW.with(|n| n.get())
    }

    fn advance(by: u64) {
        NOW.with(|n| n.set(n.get() + by));
    }

    /// Names the caller from the credential string. Stands in for the real
    /// verifiers, which have their own tests.
    struct Named;

    impl Verifier for Named {
        fn verify(&self, p: &Presented, _now: u64) -> Result<Principal, Refusal> {
            match p.credential.as_deref() {
                Some("operator") => Ok(Principal::operator("operator")),
                Some("agent") => Ok(Principal {
                    id: "agent:planner".into(),
                    class: Class::Agent,
                    evidence: Evidence::DeviceKey {
                        boot_measured: true,
                    },
                    expires_at: None,
                    task: None,
                    needs_approval_for: Vec::new(),
                    roles: Vec::new(),
                }),
                _ => Err(Refusal::new("unknown")),
            }
        }

        fn name(&self) -> &'static str {
            "named"
        }
    }

    #[derive(Default)]
    struct Node {
        ledger: Mutex<Vec<Value>>,
        executed: Mutex<Vec<String>>,
        /// What the next execution reports, when not a plain success.
        answer: Mutex<Option<Execution>>,
        /// Refuse the next execution, before acting, for this reason.
        refuse: Mutex<Option<String>>,
    }

    impl Executor for Node {
        fn covers(&self, target: &Target) -> Result<(), String> {
            match target {
                Target::Node { id } if id == "node-a" => Ok(()),
                Target::Cluster | Target::Credential { .. } => Ok(()),
                other => Err(format!("{other:?} is not node-a")),
            }
        }

        fn execute(&self, order: &Order, approval: &Approval) -> Result<Execution, String> {
            if approval.order_hash() != order.hash().map_err(|e| e.to_string())? {
                return Err("approval is for another order".into());
            }
            if let Some(why) = self.refuse.lock().unwrap().take() {
                return Err(why);
            }
            self.executed
                .lock()
                .unwrap()
                .push(order.action.as_str().into());
            Ok(self
                .answer
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Execution::Actuated(json!({ "node": "node-a" }))))
        }

        fn state(&self) -> Value {
            json!({ "isolated": false })
        }

        fn record(&self, entry: &Value) {
            self.ledger.lock().unwrap().push(entry.clone());
        }
    }

    impl Node {
        fn events(&self) -> Vec<String> {
            self.ledger
                .lock()
                .unwrap()
                .iter()
                .map(|e| e["event"].as_str().unwrap_or_default().to_string())
                .collect()
        }
    }

    fn setup_with(rp: &str) -> (Router, Arc<Node>) {
        setup_in(rp, None)
    }

    /// A desk, keeping its roster and state in `dir` when one is given, as a
    /// node does in its state directory.
    fn setup_in(rp: &str, dir: Option<&std::path::Path>) -> (Router, Arc<Node>) {
        let node = Arc::new(Node::default());
        let cfg = OrdersConfig {
            rp_id: rp.into(),
            thresholds: Thresholds::default(),
            challenge_ttl_s: 120,
            max_order_lifetime_s: 3600,
            add_passkey_delay_s: DELAY,
        };
        let desk = Desk::new(
            Ok(cfg),
            dir.map(|d| d.join("passkeys.json")),
            dir.map(|d| d.join("orders-desk.json")),
            node.clone(),
        )
        .unwrap();
        let router = mount_at(Router::new(), Arc::new(desk), clock).verified_by(Arc::new(Named));
        (router, node)
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-desk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn call(r: &Router, method: &str, path: &str, who: Option<&str>, body: Value) -> Response {
        let (path, query) = match path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path.to_string(), None),
        };
        let raw = serde_json::to_vec(&body).unwrap();
        r.dispatch_at(
            &Request {
                method: method.into(),
                path,
                query,
                body,
                raw_body: raw,
                credential: who.map(str::to_string),
                ..Default::default()
            },
            clock(),
        )
    }

    fn challenge(r: &Router, query: &str) -> (String, Challenge) {
        let res = call(r, "GET", &format!("/challenge?{query}"), None, Value::Null);
        assert_eq!(res.status, 200, "{}", res.body);
        let mut order_hash = [0u8; 32];
        hex::decode_to_slice(res.body["order_hash"].as_str().unwrap(), &mut order_hash).unwrap();
        let mut nonce = [0u8; 16];
        hex::decode_to_slice(res.body["nonce"].as_str().unwrap(), &mut nonce).unwrap();
        let c = Challenge {
            order_hash,
            nonce,
            expires_at: res.body["expires_at"].as_u64().unwrap(),
        };
        assert_eq!(c.encoded(), res.body["challenge"].as_str().unwrap());
        (res.body["nonce"].as_str().unwrap().to_string(), c)
    }

    fn stage(r: &Router, a: &Authenticator) -> Response {
        let (nonce, c) = challenge(r, "purpose=enrol");
        let res = call(
            r,
            "POST",
            "/enrolments",
            None,
            json!({ "nonce": nonce, "enrolment": a.create(&c), "rp_id": a.rp_id }),
        );
        assert_eq!(res.status, 200, "{}", res.body);
        res
    }

    /// Enrol and admit by the operator key, as an operator does; returns
    /// whether the admission was delayed.
    fn enrol_only(r: &Router, a: &Authenticator) -> bool {
        stage(r, a);
        let res = call(
            r,
            "POST",
            "/credentials",
            Some("operator"),
            json!({ "credential_id": a.id() }),
        );
        assert_eq!(res.status, 200, "{}", res.body);
        res.body["admission"]["delayed"].as_bool().unwrap()
    }

    /// As [`enrol_only`], then let any cancel window pass.
    fn enrol(r: &Router, a: &Authenticator) {
        if enrol_only(r, a) {
            advance(DELAY);
        }
    }

    fn propose(r: &Router, who: &str, action: &str, target: Value, max_nodes: u32) -> Response {
        call(
            r,
            "POST",
            "/proposals",
            Some(who),
            json!({
                "action": action,
                "target": target,
                "bounds": { "max_nodes": max_nodes },
                "reason": "test",
                "expires_in_s": 600,
            }),
        )
    }

    fn approve(r: &Router, hash: &str, a: &mut Authenticator) -> Response {
        let (nonce, c) = challenge(r, &format!("order={hash}"));
        let assertion = a.get(&c);
        call(
            r,
            "POST",
            "/orders",
            None,
            json!({ "order_hash": hash, "approvals": [{ "nonce": nonce, "assertion": assertion }] }),
        )
    }

    fn node_a() -> Value {
        json!({ "kind": "node", "id": "node-a" })
    }

    #[test]
    fn an_agent_proposes_and_a_person_approves() {
        let (r, node) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let res = propose(&r, "agent", "halt", node_a(), 1);
        assert_eq!(res.status, 200, "{}", res.body);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        assert!(
            node.executed.lock().unwrap().is_empty(),
            "proposing changes nothing"
        );

        let res = approve(&r, &hash, &mut alice);
        assert_eq!(res.status, 200, "{}", res.body);
        assert_eq!(res.body["outcome"]["status"], "actuated");
        assert_eq!(*node.executed.lock().unwrap(), vec!["halt".to_string()]);
        assert_eq!(
            node.events(),
            ["admitted", "proposed", "approved", "actuated"]
        );
    }

    #[test]
    fn an_agent_cannot_admit_a_credential() {
        let (r, _) = setup_with(RP);
        let a = Authenticator::new(1, RP);
        let (nonce, c) = challenge(&r, "purpose=enrol");
        call(
            &r,
            "POST",
            "/enrolments",
            None,
            json!({ "nonce": nonce, "enrolment": a.create(&c) }),
        );
        let res = call(
            &r,
            "POST",
            "/credentials",
            Some("agent"),
            json!({ "credential_id": a.id() }),
        );
        assert_eq!(res.status, 403, "{}", res.body);
    }

    #[test]
    fn proposing_needs_a_proved_caller_and_approving_needs_none() {
        let (r, _) = setup_with(RP);
        assert_eq!(propose(&r, "nobody", "halt", node_a(), 1).status, 403);
        assert!(r.guarded_paths().contains(&"POST /proposals".to_string()));
        assert!(r.proof_paths().contains(&"POST /orders".to_string()));
    }

    #[test]
    fn a_threshold_counts_independent_roots_only() {
        let (r, node) = setup_with(RP);
        let mut a1 = Authenticator::synced(1, RP, [0xa1; 16]);
        let mut a2 = Authenticator::synced(2, RP, [0xa1; 16]);
        let mut b = Authenticator::new(3, RP);
        enrol(&r, &a1);
        enrol(&r, &a2);
        enrol(&r, &b);
        let res = propose(&r, "operator", "crypto_erase", node_a(), 1);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        assert_eq!(res.body["required"], 2);

        let res = approve(&r, &hash, &mut a1);
        assert_eq!(res.body["status"], "pending");
        let res = approve(&r, &hash, &mut a2);
        assert_eq!(res.body["status"], "pending", "a synced copy counts once");
        assert_eq!(res.body["approvals"], 1);
        assert!(node.executed.lock().unwrap().is_empty());

        let res = approve(&r, &hash, &mut b);
        assert_eq!(res.body["outcome"]["status"], "actuated", "{}", res.body);
        assert_eq!(
            *node.executed.lock().unwrap(),
            vec!["crypto_erase".to_string()]
        );
    }

    #[test]
    fn a_nonce_is_good_for_one_attempt() {
        let (r, _) = setup_with(RP);
        let mut a = Authenticator::new(1, RP);
        enrol(&r, &a);
        let hash = propose(&r, "operator", "crypto_erase", node_a(), 1).body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let (nonce, c) = challenge(&r, &format!("order={hash}"));
        let first = a.get(&c);
        let body =
            json!({ "order_hash": hash, "approvals": [{ "nonce": nonce, "assertion": first }] });
        assert_eq!(
            call(&r, "POST", "/orders", None, body.clone()).body["approvals"],
            1
        );
        // The same assertion again: its nonce is spent.
        let res = call(&r, "POST", "/orders", None, body);
        assert_eq!(res.body["approvals"], 1);
        assert!(res.body["refused"][0]
            .as_str()
            .unwrap()
            .contains("already used"));
        // A fresh nonce, but the authenticator signs an old counter.
        let (nonce, c2) = challenge(&r, &format!("order={hash}"));
        let stale = a.get_without_counting(&c2);
        let res = call(
            &r,
            "POST",
            "/orders",
            None,
            json!({ "order_hash": hash, "approvals": [{ "nonce": nonce, "assertion": stale }] }),
        );
        assert!(
            res.body["refused"][0].as_str().unwrap().contains("counter"),
            "{}",
            res.body
        );
    }

    #[test]
    fn an_assertion_for_another_site_is_refused() {
        let (r, node) = setup_with(RP);
        let mut a = Authenticator::new(1, RP);
        enrol(&r, &a);
        let hash = propose(&r, "operator", "halt", node_a(), 1).body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        a.origin = "https://elsewhere.example".into();
        let res = approve(&r, &hash, &mut a);
        assert_eq!(res.body["status"], "pending");
        assert!(res.body["refused"][0].as_str().unwrap().contains("origin"));
        assert!(node.events().contains(&"approval_refused".to_string()));
    }

    #[test]
    fn a_node_refuses_an_order_that_does_not_name_it() {
        let (r, _) = setup_with(RP);
        let res = propose(
            &r,
            "operator",
            "halt",
            json!({ "kind": "node", "id": "node-b" }),
            1,
        );
        assert_eq!(res.status, 403, "{}", res.body);
    }

    #[test]
    fn isolate_is_only_ever_a_node_acting_on_itself() {
        let (r, _) = setup_with(RP);
        assert_eq!(propose(&r, "operator", "isolate", node_a(), 1).status, 200);
        assert_eq!(
            propose(&r, "operator", "isolate", json!({ "kind": "cluster" }), 1).status,
            400
        );
        let res = propose(
            &r,
            "operator",
            "isolate",
            json!({ "kind": "node", "id": "node-b" }),
            1,
        );
        assert_eq!(res.status, 403, "one node may not isolate another");
    }

    #[test]
    fn an_expired_order_is_refused_and_recorded() {
        let (r, node) = setup_with(RP);
        let mut a = Authenticator::new(1, RP);
        enrol(&r, &a);
        let hash = propose(&r, "operator", "halt", node_a(), 1).body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let (nonce, c) = challenge(&r, &format!("order={hash}"));
        let assertion = a.get(&c);
        advance(601);
        let res = call(
            &r,
            "POST",
            "/orders",
            None,
            json!({ "order_hash": hash, "approvals": [{ "nonce": nonce, "assertion": assertion }] }),
        );
        assert_eq!(res.status, 403);
        assert!(node.executed.lock().unwrap().is_empty());
        assert_eq!(node.events().last().unwrap(), "refused");
    }

    /// Stage `who` and carry out an `admit` order for it approved by
    /// `approver`; returns the order's outcome.
    fn admit_by_order(r: &Router, who: &Authenticator, approver: &mut Authenticator) -> Value {
        let res = stage(r, who);
        let key = res.body["key_sha256"].as_str().unwrap().to_string();
        let res = propose(
            r,
            "agent",
            "admit",
            json!({ "kind": "credential", "id": who.id(), "key_sha256": key, "rp_id": who.rp_id }),
            1,
        );
        assert_eq!(res.status, 200, "{}", res.body);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        let res = approve(r, &hash, approver);
        assert_eq!(res.body["outcome"]["status"], "actuated", "{}", res.body);
        res.body["outcome"].clone()
    }

    fn cancel(r: &Router, pending: &str, by: &mut Authenticator) -> Response {
        let (nonce, c) = challenge(r, &format!("purpose=cancel&credential={pending}"));
        call(
            r,
            "POST",
            "/credentials/cancel",
            None,
            json!({ "credential_id": pending, "nonce": nonce, "assertion": by.get(&c) }),
        )
    }

    #[test]
    fn an_admit_under_two_roots_is_delayed_and_any_existing_passkey_can_cancel_it() {
        let (r, node) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let mut bob = Authenticator::new(2, RP);
        let outcome = admit_by_order(&r, &bob, &mut alice);
        assert_eq!(outcome["detail"]["admission"]["delayed"], true, "{outcome}");

        // Bob cannot approve anything while the window is open.
        let hash = propose(&r, "operator", "halt", node_a(), 1).body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let res = approve(&r, &hash, &mut bob);
        assert!(
            res.body["refused"][0].as_str().unwrap().contains("cancel window"),
            "{}",
            res.body
        );
        // Nor cancel himself out of it, nor be cancelled by a stranger.
        let pending = bob.id();
        assert_eq!(cancel(&r, &pending, &mut bob).status, 403);
        let mut stranger = Authenticator::new(9, RP);
        let res = cancel(&r, &pending, &mut stranger);
        assert!(res.body.to_string().contains("not admitted"), "{}", res.body);

        let res = cancel(&r, &pending, &mut alice);
        assert_eq!(res.status, 200, "{}", res.body);
        let roster = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(roster.body["credentials"].as_array().unwrap().len(), 1);
        assert!(node.events().contains(&"admission_cancelled".to_string()));
    }

    #[test]
    fn the_operator_key_follows_the_same_delay() {
        let (r, _) = setup_with(RP);
        let alice = Authenticator::new(1, RP);
        assert!(!enrol_only(&r, &alice), "the first passkey has nobody to cancel it");
        let bob = Authenticator::new(2, RP);
        assert!(enrol_only(&r, &bob), "the operator key is no way round the window");
        let roster = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(roster.body["independent_roots"], 1);
        assert_eq!(roster.body["credentials"][1]["pending"], true);
        advance(DELAY);
        let roster = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(roster.body["independent_roots"], 2);
    }

    #[test]
    fn at_two_roots_an_admit_takes_effect_when_approved() {
        let (r, _) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        enrol(&r, &Authenticator::new(2, RP));
        let carol = Authenticator::synced(3, RP, [0xc3; 16]);
        let outcome = admit_by_order(&r, &carol, &mut alice);
        assert_eq!(outcome["detail"]["admission"]["delayed"], false, "{outcome}");
        let roster = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(roster.body["independent_roots"], 3);
    }

    #[test]
    fn a_credential_answers_on_its_own_rp_id() {
        let (r, node) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        enrol(&r, &Authenticator::new(2, RP));
        let mut ops = Authenticator::synced(3, "ops.other.example", [0xc3; 16]);
        admit_by_order(&r, &ops, &mut alice);
        let res = call(&r, "GET", "/challenge?purpose=enrol", None, Value::Null);
        assert_eq!(res.body["rp_ids"], json!(["ops.other.example", RP]));
        let hash = propose(&r, "operator", "halt", node_a(), 1).body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        // Signed from the site's domain, it is not the RP ID ops was made for.
        ops.origin = format!("https://{RP}");
        let res = approve(&r, &hash, &mut ops);
        assert!(res.body["refused"][0].as_str().unwrap().contains("origin"), "{}", res.body);
        ops.origin = "https://ops.other.example".into();
        let res = approve(&r, &hash, &mut ops);
        assert_eq!(res.body["outcome"]["status"], "actuated", "{}", res.body);
        assert_eq!(*node.executed.lock().unwrap(), vec!["halt".to_string()]);
    }

    #[test]
    fn an_admit_order_names_the_rp_id_the_credential_was_made_for() {
        let (r, _) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let bob = Authenticator::new(2, RP);
        let key = stage(&r, &bob).body["key_sha256"].as_str().unwrap().to_string();
        let hash = propose(
            &r,
            "agent",
            "admit",
            json!({ "kind": "credential", "id": bob.id(), "key_sha256": key, "rp_id": "x.example" }),
            1,
        )
        .body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let res = approve(&r, &hash, &mut alice);
        assert_eq!(res.status, 403);
        assert!(res.body.to_string().contains("made for"), "{}", res.body);
    }

    #[test]
    fn a_stored_credential_without_proof_is_refused_and_must_re_enrol() {
        let dir = scratch("unproved");
        let path = dir.join("passkeys.json");
        let mut alice = Authenticator::new(1, RP);
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({ "credentials": [{
                "id": alice.id(),
                "cose_key": hex::encode(alice.cose_key()),
                "independence_group": "alice",
                "sign_count": 0,
                "label": "alice",
                "admitted_at": 1
            }] }))
            .unwrap(),
        )
        .unwrap();
        let (r, _) = setup_in(RP, Some(&dir));
        let roster = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(roster.body["credentials"].as_array().unwrap().len(), 0);
        assert!(roster.body["unproved"][0]["because"].as_str().unwrap().contains("enrol it again"));

        let hash = propose(&r, "operator", "halt", node_a(), 1).body["order_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let res = approve(&r, &hash, &mut alice);
        let why = res.body["refused"][0].as_str().unwrap();
        assert!(why.contains("independence cannot be read"), "{why}");

        // Enrolling again with registration data replaces the refusal.
        enrol(&r, &alice);
        let roster = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(roster.body["credentials"].as_array().unwrap().len(), 1);
        assert!(roster.body["unproved"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_admission_cannot_declare_its_independence() {
        let (r, _) = setup_with(RP);
        let a = Authenticator::new(1, RP);
        stage(&r, &a);
        let res = call(
            &r,
            "POST",
            "/credentials",
            Some("operator"),
            json!({ "credential_id": a.id(), "independence_group": "alice" }),
        );
        assert_eq!(res.status, 400);
        assert!(res.body.to_string().contains("read from the enrolment"), "{}", res.body);
    }

    #[test]
    fn an_unconfigured_node_refuses_and_says_why() {
        let node = Arc::new(Node::default());
        let desk = Desk::new(Err("no orders.json".into()), None, None, node).unwrap();
        let r = mount_at(Router::new(), Arc::new(desk), clock);
        let res = call(&r, "GET", "/challenge?purpose=enrol", None, Value::Null);
        assert_eq!(res.status, 403);
        assert!(res.body.to_string().contains("no orders.json"));
    }

    /// Propose, as the operator, and approve with one authenticator.
    fn decide(r: &Router, action: &str, a: &mut Authenticator) -> (String, Response) {
        let res = propose(r, "operator", action, node_a(), 1);
        assert_eq!(res.status, 200, "{}", res.body);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        let res = approve(r, &hash, a);
        (hash, res)
    }

    fn entry(node: &Node, event: &str) -> Value {
        node.ledger
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e["event"] == event)
            .cloned()
            .unwrap_or(Value::Null)
    }

    #[test]
    fn a_plan_with_nothing_acting_is_recorded_as_planned() {
        let (r, node) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        *node.answer.lock().unwrap() = Some(Execution::Planned(json!({ "steps": ["node-a"] })));
        let (_, res) = decide(&r, "halt", &mut alice);
        assert_eq!(res.status, 200, "{}", res.body);
        assert_eq!(res.body["outcome"]["status"], "planned");
        assert_eq!(
            node.events(),
            ["admitted", "proposed", "approved", "planned"]
        );
        assert!(!node.events().contains(&"actuated".to_string()));
    }

    #[test]
    fn a_failed_actuation_is_recorded_with_why_and_what_happened() {
        let (r, node) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        *node.answer.lock().unwrap() = Some(Execution::Failed {
            why: "some workloads did not stop".into(),
            detail: json!({ "stopped": ["a"], "failed": ["b"] }),
        });
        let (hash, res) = decide(&r, "halt", &mut alice);
        assert_eq!(res.status, 502, "{}", res.body);
        assert_eq!(res.body["outcome"]["status"], "actuation_failed");
        assert_eq!(
            res.body["outcome"]["because"],
            "some workloads did not stop"
        );
        let e = entry(&node, "actuation_failed");
        assert_eq!(e["order_hash"], hash);
        assert_eq!(e["detail"]["failed"][0], "b");
        assert!(!node.events().contains(&"actuated".to_string()));
        // Decided: no further approval is taken, so it does not run again.
        let again = call(
            &r,
            "GET",
            &format!("/challenge?order={hash}"),
            None,
            Value::Null,
        );
        assert_eq!(again.status, 403, "{}", again.body);
        assert_eq!(node.executed.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_refusal_by_the_executor_is_recorded_as_refused() {
        let (r, node) = setup_with(RP);
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        *node.refuse.lock().unwrap() = Some("no out-of-band path is configured".into());
        let (hash, res) = decide(&r, "power_off", &mut alice);
        assert_eq!(res.status, 403, "{}", res.body);
        assert_eq!(res.body["outcome"]["status"], "refused");
        assert_eq!(entry(&node, "refused")["order_hash"], hash);
        assert_eq!(
            node.events(),
            ["admitted", "proposed", "approved", "refused"]
        );
    }

    #[test]
    fn admit_and_revoke_are_actuated_only_once_the_roster_is_written() {
        let dir = scratch("roster");
        let (r, node) = setup_in(RP, Some(&dir));
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let bob = Authenticator::new(2, RP);
        let (nonce, c) = challenge(&r, "purpose=enrol");
        let res = call(
            &r,
            "POST",
            "/enrolments",
            None,
            json!({ "nonce": nonce, "enrolment": bob.create(&c) }),
        );
        let key = res.body["key_sha256"].as_str().unwrap().to_string();
        let target = json!({ "kind": "credential", "id": bob.id(), "key_sha256": key, "rp_id": RP });

        // The roster file cannot be written: the admission is undone, and says so.
        let roster = dir.join("passkeys.json");
        std::fs::remove_file(&roster).unwrap();
        std::fs::create_dir(&roster).unwrap();
        let res = propose(&r, "agent", "admit", target.clone(), 1);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        let res = approve(&r, &hash, &mut alice);
        assert_eq!(
            res.body["outcome"]["status"], "actuation_failed",
            "{}",
            res.body
        );
        let listed = call(&r, "GET", "/credentials", None, Value::Null);
        assert_eq!(
            listed.body["credentials"].as_array().unwrap().len(),
            1,
            "undone in memory too"
        );
        assert_eq!(entry(&node, "actuation_failed")["action"], "admit");

        // Writable again: admitted, then revoked, each recorded as actuated.
        std::fs::remove_dir(&roster).unwrap();
        advance(1);
        let res = propose(&r, "agent", "admit", target.clone(), 1);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        let res = approve(&r, &hash, &mut alice);
        assert_eq!(res.body["outcome"]["status"], "actuated", "{}", res.body);
        advance(1);
        let res = propose(&r, "agent", "revoke", target, 1);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        let res = approve(&r, &hash, &mut alice);
        assert_eq!(res.body["outcome"]["status"], "actuated", "{}", res.body);
        assert_eq!(entry(&node, "actuated")["action"], "revoke");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn proposals_approvals_and_nonces_survive_a_restart() {
        let dir = scratch("restart");
        let (r, _) = setup_in(RP, Some(&dir));
        let mut alice = Authenticator::new(1, RP);
        let mut bob = Authenticator::new(2, RP);
        enrol(&r, &alice);
        enrol(&r, &bob);
        // crypto_erase needs two groups; alice approves before the restart.
        let res = propose(&r, "operator", "crypto_erase", node_a(), 1);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        let (nonce, c) = challenge(&r, &format!("order={hash}"));
        let first = json!({ "order_hash": hash, "approvals": [{ "nonce": nonce, "assertion": alice.get(&c) }] });
        let res = call(&r, "POST", "/orders", None, first.clone());
        assert_eq!(res.body["status"], "pending", "{}", res.body);
        // A nonce issued before the restart, used after it.
        let (bob_nonce, bob_c) = challenge(&r, &format!("order={hash}"));
        drop(r);

        let (r, node) = setup_in(RP, Some(&dir));
        let listed = call(&r, "GET", "/proposals", None, Value::Null);
        let p = &listed.body["proposals"][0];
        assert_eq!(p["order_hash"], hash);
        assert_eq!(
            p["approvals"],
            1,
            "the counted approval came back: {listed:?}",
            listed = listed.body
        );
        assert!(p["outcome"].is_null());

        // The nonce alice spent stays spent.
        let res = call(&r, "POST", "/orders", None, first);
        assert!(
            res.body["refused"][0]
                .as_str()
                .unwrap()
                .contains("already used"),
            "{}",
            res.body
        );

        let res = call(
            &r,
            "POST",
            "/orders",
            None,
            json!({ "order_hash": hash, "approvals": [{ "nonce": bob_nonce, "assertion": bob.get(&bob_c) }] }),
        );
        assert_eq!(res.body["outcome"]["status"], "actuated", "{}", res.body);
        assert_eq!(*node.executed.lock().unwrap(), ["crypto_erase"]);
        drop(r);

        // And the decision itself survives.
        let (r, _) = setup_in(RP, Some(&dir));
        let listed = call(&r, "GET", "/proposals", None, Value::Null);
        assert_eq!(listed.body["proposals"][0]["outcome"]["status"], "actuated");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spent_nonces_are_forgotten_once_they_would_have_expired() {
        let dir = scratch("expiry");
        let (r, _) = setup_in(RP, Some(&dir));
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let (_, res) = decide(&r, "halt", &mut alice);
        assert_eq!(res.body["outcome"]["status"], "actuated");
        let kept: Value =
            serde_json::from_slice(&std::fs::read(dir.join("orders-desk.json")).unwrap()).unwrap();
        assert!(!kept["spent"].as_object().unwrap().is_empty());
        advance(1_000);
        let _ = challenge(&r, "purpose=enrol");
        let kept: Value =
            serde_json::from_slice(&std::fs::read(dir.join("orders-desk.json")).unwrap()).unwrap();
        assert!(kept["spent"].as_object().unwrap().is_empty(), "{kept}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_approval_from_a_credential_revoked_while_down_does_not_come_back() {
        let dir = scratch("revoked");
        let (r, _) = setup_in(RP, Some(&dir));
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let res = propose(&r, "operator", "crypto_erase", node_a(), 1);
        let hash = res.body["order_hash"].as_str().unwrap().to_string();
        assert_eq!(approve(&r, &hash, &mut alice).body["status"], "pending");
        drop(r);
        // The roster loses alice between runs.
        let path = dir.join("passkeys.json");
        let mut roster = Roster::load(&path).unwrap();
        roster.revoke(&alice.id());
        roster.save(&path).unwrap();

        let (r, node) = setup_in(RP, Some(&dir));
        let listed = call(&r, "GET", "/proposals", None, Value::Null);
        assert_eq!(listed.body["proposals"][0]["approvals"], 0);
        assert_eq!(entry(&node, "approval_dropped")["order_hash"], hash);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_order_interrupted_after_approval_is_recorded_as_failed_on_restart() {
        let dir = scratch("interrupted");
        let (r, _) = setup_in(RP, Some(&dir));
        let mut alice = Authenticator::new(1, RP);
        enrol(&r, &alice);
        let (hash, _) = decide(&r, "halt", &mut alice);
        drop(r);
        // As if the node died between writing `approved` and hearing back.
        let path = dir.join("orders-desk.json");
        let mut kept: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        kept["proposals"][&hash]["outcome"] = json!({ "status": "approved", "at": 1 });
        std::fs::write(&path, kept.to_string()).unwrap();

        let (r, node) = setup_in(RP, Some(&dir));
        let listed = call(&r, "GET", "/proposals", None, Value::Null);
        let outcome = &listed.body["proposals"][0]["outcome"];
        assert_eq!(outcome["status"], "actuation_failed");
        assert!(outcome["because"].as_str().unwrap().contains("restarted"));
        assert_eq!(entry(&node, "actuation_failed")["order_hash"], hash);
        assert!(
            node.executed.lock().unwrap().is_empty(),
            "never run again on its own"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_node_reports_its_actuation_state() {
        let (r, _) = setup_with(RP);
        let res = call(&r, "GET", "/actuation", None, Value::Null);
        assert_eq!(res.status, 200);
        assert_eq!(res.body["isolated"], false);
    }
}
