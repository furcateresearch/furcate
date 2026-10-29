//! The kill switch: signed orders to request a stop of a machine, a domain or
//! the cluster.
//!
//! For a machine that does physical work this is an advisory stop request to
//! its own safety-rated controller. It is not an emergency stop and not a safety
//! function, a missing order is not a safe state, and Furcate never resets,
//! clears or overrides an emergency stop or sends a restart.
//!
//! This is its own crate, and Apache-2.0, because of what it claims. A kill
//! switch asserts that an order was authorised by the operator key and by nobody
//! else, and that assertion is worth exactly as much as the reader's ability to
//! check it. Buried inside a power-management crate it would be a claim about
//! who can turn your hardware off that is hard to find and harder to audit.
//!
//! It was extracted from `furcate-power`, which mixes this with roughly 2,100
//! lines of thermal, RAPL and ladder logic: optimisation work with no trust
//! claim attached.
//!
//! Depends only on `furcate-topology` (for the domain tree an order is scoped
//! to), `furcate-authn` (for the approval a passkey order carries) and on
//! ed25519/sha2, so it carries none of that weight.
//!
//! ## Two ways an order is authorised
//!
//! A [`KillOrder`] signed by the operator key, as it always was. Or a canonical
//! [`Order`] whose hash enough independent passkey credentials approved, which
//! arrives here as an [`Approval`] that only verified assertions can produce.
//! Both end in the same plan, under the same expiry, replay and out-of-band
//! checks.

//! The operator kill switch.
//!
//! This is a sovereignty guarantee, not a convenience. The hardware belongs to
//! the operator, so the operator must be able to stop any machine or the whole
//! site at any time — and no remote party may be able to do the same. A remote
//! party can *request* a drain; only a key the operator holds can kill.
//!
//! Three properties make it trustworthy rather than merely present:
//!
//! - **Signed.** An order carries an operator signature over its full contents,
//!   so a compromised control plane cannot fabricate one.
//! - **Replay-proof.** Orders carry a nonce and an expiry, so a captured order
//!   cannot be re-broadcast later to take the site down a second time.
//! - **Ordered by failure domain.** Execution kills leaves before their
//!   parents and the controller last, so the site does not lose the authority
//!   it needs midway through carrying out its own instruction.

pub mod actuate;
pub mod warden;

use furcate_authn::order::{Action, Order, Target};
use furcate_authn::webauthn::Approval;
use furcate_topology::DomainTree;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// What the order applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillScope {
    /// One machine.
    Node(String),
    /// Everything under a failure domain — a rack, a supply, a circuit.
    Domain(String),
    /// The entire site.
    Cluster,
}

/// How hard to stop, in ascending severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillMode {
    /// Stop accepting work and migrate what is running. Reversible.
    Drain,
    /// Stop the workload runtimes immediately, leave the OS up. Reversible.
    Halt,
    /// Cut power at the outlet or via the BMC. Requires an out-of-band path.
    PowerOff,
    /// Disconnect from all networks but keep running, so the machine can be
    /// inspected without it talking to anything.
    Isolate,
    /// Destroy the sealed vault keys, rendering data at rest inert.
    /// Irreversible: the data is unrecoverable afterwards.
    CryptoErase,
    /// Restore the reach an `Isolate` took away, on the node named.
    Release,
    /// Restart the workloads a `Halt` stopped, as each node recorded them.
    Resume,
}

impl KillMode {
    /// Whether the effect can be undone.
    pub fn is_reversible(&self) -> bool {
        matches!(
            self,
            KillMode::Drain
                | KillMode::Halt
                | KillMode::Isolate
                | KillMode::Release
                | KillMode::Resume
        )
    }

    /// Whether an out-of-band control path is required to carry this out.
    ///
    /// Cutting power over the same network that may have just failed is not a
    /// plan, so this is checked before an order is accepted.
    pub fn needs_out_of_band(&self) -> bool {
        matches!(self, KillMode::PowerOff)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            KillMode::Drain => "drain",
            KillMode::Halt => "halt",
            KillMode::PowerOff => "power-off",
            KillMode::Isolate => "isolate",
            KillMode::CryptoErase => "crypto-erase",
            KillMode::Release => "release",
            KillMode::Resume => "resume",
        }
    }
}

/// A signed operator instruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillOrder {
    pub scope: KillScope,
    pub mode: KillMode,
    /// Single-use value defeating replay.
    pub nonce: String,
    /// Issue time and deadline, in the site's clock.
    pub issued_at: u64,
    pub expires_at: u64,
    /// Free-text justification, recorded in the ledger.
    pub reason: String,
    pub signature: Option<String>,
}

impl KillOrder {
    pub fn new(
        scope: KillScope,
        mode: KillMode,
        nonce: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            scope,
            mode,
            nonce: nonce.into(),
            issued_at,
            expires_at,
            reason: reason.into(),
            signature: None,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(format!("{:?}", self.scope).as_bytes());
        h.update(self.mode.as_str().as_bytes());
        h.update(self.nonce.as_bytes());
        h.update(self.issued_at.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        h.update(self.reason.as_bytes());
        h.finalize().to_vec()
    }

    /// Sign with the operator key.
    pub fn sign(mut self, key: &SigningKey) -> Self {
        let sig: Signature = key.sign(&self.payload());
        self.signature = Some(hex::encode(sig.to_bytes()));
        self
    }

    fn signature_valid(&self, key: &VerifyingKey) -> bool {
        let Some(hexsig) = &self.signature else {
            return false;
        };
        let Ok(bytes) = hex::decode(hexsig) else {
            return false;
        };
        let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            return false;
        };
        key.verify(&self.payload(), &Signature::from_bytes(&arr)).is_ok()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KillError {
    /// No signature, or not from the operator key.
    NotAuthorized,
    /// The order's deadline has passed.
    Expired { expires_at: u64, now: u64 },
    /// This nonce has already been executed.
    Replayed,
    /// The mode needs an out-of-band path and none was demonstrated.
    NoOutOfBandPath,
    /// The scope names something not in the tree.
    UnknownScope(String),
    /// The order is well formed but is not something the kill switch does.
    NotAKillOrder(String),
    /// The target resolved to more machines than the order's bound allows.
    TooBroad { resolved: usize, bound: u32 },
    /// The order's counter is not above the last one carried out.
    Stale { counter: u64, last: u64 },
}

impl fmt::Display for KillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KillError::NotAuthorized => write!(
                f,
                "order is not signed by the operator key. Only the operator can kill; \
                 a remote party may request a drain but never command one"
            ),
            KillError::Expired { expires_at, now } => {
                write!(f, "order expired at {expires_at}; it is now {now}")
            }
            KillError::Replayed => write!(f, "this order has already been executed"),
            KillError::NoOutOfBandPath => write!(
                f,
                "cutting power requires an out-of-band path independent of the \
                 cluster network, and none was demonstrated"
            ),
            KillError::UnknownScope(s) => write!(f, "scope `{s}` is not present in the topology"),
            KillError::NotAKillOrder(why) => write!(f, "not a kill order: {why}"),
            KillError::TooBroad { resolved, bound } => write!(
                f,
                "the target covers {resolved} machines and the order was approved for at \
                 most {bound}; nothing was done"
            ),
            KillError::Stale { counter, last } => write!(
                f,
                "order counter {counter} is not above {last}, the last one carried out"
            ),
        }
    }
}

impl std::error::Error for KillError {}

/// One step of an execution plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub target: String,
    pub mode: KillMode,
    /// Lower runs first.
    pub order: u32,
}

/// Holds the operator key and the record of executed orders.
pub struct KillSwitch {
    /// `None` on a switch that only takes passkey-approved orders.
    operator_key: Option<VerifyingKey>,
    executed: std::collections::BTreeSet<String>,
    /// The highest counter of an approved order carried out.
    last_counter: u64,
    /// Whether an out-of-band control path has been demonstrated.
    out_of_band_available: bool,
    /// The node running the site controller, killed last.
    controller: Option<String>,
}

impl KillSwitch {
    pub fn new(operator_key: VerifyingKey) -> Self {
        Self {
            operator_key: Some(operator_key),
            executed: Default::default(),
            last_counter: 0,
            out_of_band_available: false,
            controller: None,
        }
    }

    /// A switch that holds no operator key and so accepts only orders
    /// approved by passkey assertions.
    pub fn approved_only() -> Self {
        Self {
            operator_key: None,
            executed: Default::default(),
            last_counter: 0,
            out_of_band_available: false,
            controller: None,
        }
    }

    /// Carry on from the counter a previous run reached, so a restart does not
    /// make an old order new again.
    pub fn set_last_counter(&mut self, counter: u64) -> &mut Self {
        self.last_counter = self.last_counter.max(counter);
        self
    }

    pub fn last_counter(&self) -> u64 {
        self.last_counter
    }

    /// Record that an independent control path exists — a PDU or BMC reachable
    /// without the cluster network.
    pub fn set_out_of_band(&mut self, available: bool) -> &mut Self {
        self.out_of_band_available = available;
        self
    }

    pub fn set_controller(&mut self, node: impl Into<String>) -> &mut Self {
        self.controller = Some(node.into());
        self
    }

    /// Validate an order and produce an ordered execution plan.
    pub fn authorize(
        &mut self,
        order: &KillOrder,
        tree: &DomainTree,
        now: u64,
    ) -> Result<Vec<ExecutionStep>, KillError> {
        let Some(key) = &self.operator_key else {
            return Err(KillError::NotAuthorized);
        };
        if !order.signature_valid(key) {
            return Err(KillError::NotAuthorized);
        }
        if now >= order.expires_at {
            return Err(KillError::Expired {
                expires_at: order.expires_at,
                now,
            });
        }
        if self.executed.contains(&order.nonce) {
            return Err(KillError::Replayed);
        }
        if order.mode.needs_out_of_band() && !self.out_of_band_available {
            return Err(KillError::NoOutOfBandPath);
        }

        let steps = self.plan(&order.scope, order.mode, tree)?;
        self.executed.insert(order.nonce.clone());
        Ok(steps)
    }

    /// Validate a passkey-approved order and produce an ordered execution plan.
    ///
    /// The approval is checked against this exact order's hash, so approval of
    /// one order cannot be spent on another. `isolate` arrives here naming one
    /// node, and the plan it yields is that node acting on itself.
    pub fn authorize_approved(
        &mut self,
        order: &Order,
        approval: &Approval,
        tree: &DomainTree,
        now: u64,
    ) -> Result<Vec<ExecutionStep>, KillError> {
        let hash = order.hash().map_err(|e| KillError::NotAKillOrder(e.to_string()))?;
        if approval.order_hash() != hash {
            return Err(KillError::NotAuthorized);
        }
        if now >= order.expires_at {
            return Err(KillError::Expired { expires_at: order.expires_at, now });
        }
        let key = format!("order:{}", hex::encode(hash));
        if self.executed.contains(&key) {
            return Err(KillError::Replayed);
        }
        if order.counter <= self.last_counter {
            return Err(KillError::Stale { counter: order.counter, last: self.last_counter });
        }
        let mode = match order.action {
            Action::Halt => KillMode::Halt,
            Action::PowerOff => KillMode::PowerOff,
            Action::Isolate => KillMode::Isolate,
            Action::CryptoErase => KillMode::CryptoErase,
            Action::Release => KillMode::Release,
            Action::Resume => KillMode::Resume,
            Action::Admit | Action::Revoke => {
                return Err(KillError::NotAKillOrder(format!(
                    "`{}` changes who may approve, not what a machine does",
                    order.action.as_str()
                )))
            }
            Action::Login => {
                return Err(KillError::NotAKillOrder(
                    "`login` certifies an SSH key, not what a machine does".into(),
                ))
            }
            Action::SetCustody => {
                return Err(KillError::NotAKillOrder(
                    "`set_custody` changes the site's custody policy, not what a machine does"
                        .into(),
                ))
            }
        };
        let scope = match &order.target {
            Target::Node { id } => KillScope::Node(id.clone()),
            Target::Domain { id } => KillScope::Domain(id.clone()),
            Target::Cluster => KillScope::Cluster,
            Target::Credential { .. } => {
                return Err(KillError::NotAKillOrder("the target is a credential".into()))
            }
            Target::Custody { .. } => {
                return Err(KillError::NotAKillOrder("the target is a custody change".into()))
            }
            Target::Login { .. } => {
                return Err(KillError::NotAKillOrder("the target is a login".into()))
            }
        };
        if mode.needs_out_of_band() && !self.out_of_band_available {
            return Err(KillError::NoOutOfBandPath);
        }
        let steps = self.plan(&scope, mode, tree)?;
        if steps.len() > order.bounds.max_nodes as usize {
            return Err(KillError::TooBroad { resolved: steps.len(), bound: order.bounds.max_nodes });
        }
        self.executed.insert(key);
        self.last_counter = order.counter;
        Ok(steps)
    }

    /// The machines a scope covers, leaves first and the controller last.
    fn plan(
        &self,
        scope: &KillScope,
        mode: KillMode,
        tree: &DomainTree,
    ) -> Result<Vec<ExecutionStep>, KillError> {
        let targets: Vec<String> = match scope {
            KillScope::Node(n) => {
                if tree.get(n).is_none() {
                    return Err(KillError::UnknownScope(n.clone()));
                }
                vec![n.clone()]
            }
            KillScope::Domain(d) => {
                if tree.get(d).is_none() {
                    return Err(KillError::UnknownScope(d.clone()));
                }
                let members: Vec<String> = tree
                    .compute_nodes()
                    .into_iter()
                    .filter(|n| {
                        n.id == *d
                            || tree.ancestors(&n.id).iter().any(|a| a.id == *d)
                    })
                    .map(|n| n.id.clone())
                    .collect();
                if members.is_empty() {
                    return Err(KillError::UnknownScope(d.clone()));
                }
                members
            }
            KillScope::Cluster => tree
                .compute_nodes()
                .into_iter()
                .map(|n| n.id.clone())
                .collect(),
        };

        // Depth first: a node further from the site root is closer to a leaf
        // and is stopped earlier. The controller is always stopped last, so it
        // retains the authority to finish the job.
        let mut steps: Vec<ExecutionStep> = targets
            .into_iter()
            .map(|t| {
                let depth = tree.ancestors(&t).len() as u32;
                let is_controller = self.controller.as_deref() == Some(t.as_str());
                ExecutionStep {
                    order: if is_controller {
                        u32::MAX
                    } else {
                        // Deeper first.
                        u32::MAX / 2 - depth
                    },
                    target: t,
                    mode,
                }
            })
            .collect();
        steps.sort_by(|a, b| a.order.cmp(&b.order).then(a.target.cmp(&b.target)));

        Ok(steps)
    }

    /// Whether a scope is one only the operator may command.
    ///
    /// Always true. The method exists so the answer is written down where a
    /// future integration would look for an exception, and finds none.
    pub fn requires_operator_authority(_scope: &KillScope) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_topology::{DomainKind, Provenance};

    fn tree() -> DomainTree {
        let mut t = DomainTree::new();
        t.insert("home-1", DomainKind::Site, None, Provenance::Declared)
            .insert("circuit-a", DomainKind::Feed, Some("home-1"), Provenance::Declared)
            .insert("ups-1", DomainKind::Ups, Some("circuit-a"), Provenance::Declared)
            .insert("rack-1", DomainKind::Rack, Some("ups-1"), Provenance::Declared)
            .insert("node-a", DomainKind::Node, Some("rack-1"), Provenance::Discovered)
            .insert("node-b", DomainKind::Node, Some("rack-1"), Provenance::Discovered);
        t
    }

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn switch() -> KillSwitch {
        let mut k = KillSwitch::new(operator().verifying_key());
        k.set_controller("node-a");
        k
    }

    fn order(scope: KillScope, mode: KillMode, nonce: &str) -> KillOrder {
        KillOrder::new(scope, mode, nonce, 0, 100, "test").sign(&operator())
    }

    #[test]
    fn an_operator_signed_order_is_authorized() {
        let mut k = switch();
        let steps = k
            .authorize(&order(KillScope::Node("node-b".into()), KillMode::Halt, "n1"), &tree(), 1)
            .unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].target, "node-b");
    }

    #[test]
    fn an_unsigned_order_is_refused() {
        let mut k = switch();
        let unsigned = KillOrder::new(KillScope::Cluster, KillMode::Halt, "n", 0, 100, "x");
        assert_eq!(
            k.authorize(&unsigned, &tree(), 1).unwrap_err(),
            KillError::NotAuthorized
        );
    }

    #[test]
    fn an_order_signed_by_anyone_else_is_refused() {
        // This is the property that keeps the network out of the kill path.
        let mut k = switch();
        let impostor = SigningKey::from_bytes(&[99u8; 32]);
        let o = KillOrder::new(KillScope::Cluster, KillMode::PowerOff, "n", 0, 100, "remote")
            .sign(&impostor);
        assert_eq!(
            k.authorize(&o, &tree(), 1).unwrap_err(),
            KillError::NotAuthorized
        );
    }

    #[test]
    fn a_captured_order_cannot_be_replayed() {
        let mut k = switch();
        let o = order(KillScope::Cluster, KillMode::Halt, "same-nonce");
        assert!(k.authorize(&o, &tree(), 1).is_ok());
        assert_eq!(k.authorize(&o, &tree(), 2).unwrap_err(), KillError::Replayed);
    }

    #[test]
    fn an_expired_order_is_refused() {
        let mut k = switch();
        let o = order(KillScope::Cluster, KillMode::Halt, "n");
        assert_eq!(
            k.authorize(&o, &tree(), 500).unwrap_err(),
            KillError::Expired {
                expires_at: 100,
                now: 500
            }
        );
    }

    #[test]
    fn tampering_with_an_order_invalidates_it() {
        let mut k = switch();
        let mut o = order(KillScope::Node("node-b".into()), KillMode::Drain, "n");
        // Escalate the mode after signing.
        o.mode = KillMode::CryptoErase;
        assert_eq!(
            k.authorize(&o, &tree(), 1).unwrap_err(),
            KillError::NotAuthorized
        );
    }

    #[test]
    fn cutting_power_needs_an_independent_path() {
        let mut k = switch();
        let o = order(KillScope::Cluster, KillMode::PowerOff, "n");
        assert_eq!(
            k.authorize(&o, &tree(), 1).unwrap_err(),
            KillError::NoOutOfBandPath
        );
        k.set_out_of_band(true);
        let o2 = order(KillScope::Cluster, KillMode::PowerOff, "n2");
        assert!(k.authorize(&o2, &tree(), 1).is_ok());
    }

    #[test]
    fn the_controller_is_stopped_last() {
        let mut k = switch();
        let steps = k
            .authorize(&order(KillScope::Cluster, KillMode::Halt, "n"), &tree(), 1)
            .unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps.last().unwrap().target, "node-a");
    }

    #[test]
    fn a_domain_scope_covers_everything_beneath_it() {
        let mut k = switch();
        let steps = k
            .authorize(&order(KillScope::Domain("ups-1".into()), KillMode::Halt, "n"), &tree(), 1)
            .unwrap();
        let targets: Vec<&str> = steps.iter().map(|s| s.target.as_str()).collect();
        assert!(targets.contains(&"node-a"));
        assert!(targets.contains(&"node-b"));
    }

    #[test]
    fn an_unknown_scope_is_refused() {
        let mut k = switch();
        assert_eq!(
            k.authorize(&order(KillScope::Node("ghost".into()), KillMode::Halt, "n"), &tree(), 1)
                .unwrap_err(),
            KillError::UnknownScope("ghost".into())
        );
    }

    #[test]
    fn irreversible_modes_are_marked() {
        assert!(KillMode::Drain.is_reversible());
        assert!(KillMode::Isolate.is_reversible());
        assert!(!KillMode::PowerOff.is_reversible());
        assert!(!KillMode::CryptoErase.is_reversible());
    }

    mod approved {
        use super::*;
        use furcate_authn::order::Bounds;
        use furcate_authn::webauthn::virtual_authenticator::Authenticator;
        use furcate_authn::webauthn::{verify_assertion, Challenge, Tally, Thresholds};

        const RP: &str = "site.example";

        fn order(action: Action, target: Target, max_nodes: u32, counter: u64) -> Order {
            Order {
                site: RP.into(),
                action,
                target,
                bounds: Bounds { max_nodes, duration_s: None },
                counter,
                issued_at: 0,
                expires_at: 100,
                reason: "test".into(),
            }
        }

        /// One synced passkey per name, each name its own provider, so two
        /// approvals under one name are one sync account and count once.
        fn approve(o: &Order, providers: &[&str]) -> Option<Approval> {
            let mut t = Tally::new(o, &Thresholds::default()).unwrap();
            for (i, p) in providers.iter().enumerate() {
                let mut aaguid = [0u8; 16];
                aaguid[..p.len().min(16)].copy_from_slice(&p.as_bytes()[..p.len().min(16)]);
                let mut a = Authenticator::synced(i as u8 + 1, RP, aaguid);
                let cred = a.credential();
                let c = Challenge { order_hash: o.hash().unwrap(), nonce: [0; 16], expires_at: 50 };
                t.add(verify_assertion(&cred, &a.get(&c), &c, 10).unwrap()).unwrap();
            }
            t.approval()
        }

        #[test]
        fn an_approved_order_is_planned_like_a_signed_one() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::Halt, Target::Domain { id: "rack-1".into() }, 2, 1);
            let steps = k.authorize_approved(&o, &approve(&o, &["alice"]).unwrap(), &tree(), 10).unwrap();
            assert_eq!(steps.len(), 2);
            assert!(steps.iter().all(|s| s.mode == KillMode::Halt));
        }

        #[test]
        fn an_approval_for_another_order_is_refused() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::Halt, Target::Node { id: "node-a".into() }, 1, 1);
            let other = order(Action::PowerOff, Target::Node { id: "node-a".into() }, 1, 1);
            let ap = approve(&other, &["alice"]).unwrap();
            assert_eq!(k.authorize_approved(&o, &ap, &tree(), 10), Err(KillError::NotAuthorized));
        }

        #[test]
        fn a_switch_without_an_operator_key_refuses_signed_orders() {
            let mut k = KillSwitch::approved_only();
            let o = super::order(KillScope::Node("node-a".into()), KillMode::Halt, "n");
            assert_eq!(k.authorize(&o, &tree(), 10), Err(KillError::NotAuthorized));
        }

        #[test]
        fn an_order_broader_than_its_bound_is_refused_whole() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::Halt, Target::Cluster, 1, 1);
            let ap = approve(&o, &["alice"]).unwrap();
            assert_eq!(
                k.authorize_approved(&o, &ap, &tree(), 10),
                Err(KillError::TooBroad { resolved: 2, bound: 1 })
            );
        }

        #[test]
        fn an_approved_order_runs_once_and_counters_only_rise() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::Halt, Target::Node { id: "node-a".into() }, 1, 5);
            let ap = approve(&o, &["alice"]).unwrap();
            assert!(k.authorize_approved(&o, &ap, &tree(), 10).is_ok());
            assert_eq!(k.authorize_approved(&o, &ap, &tree(), 10), Err(KillError::Replayed));
            let older = order(Action::Halt, Target::Node { id: "node-b".into() }, 1, 4);
            let ap = approve(&older, &["alice"]).unwrap();
            assert_eq!(
                k.authorize_approved(&older, &ap, &tree(), 10),
                Err(KillError::Stale { counter: 4, last: 5 })
            );
        }

        #[test]
        fn an_expired_approved_order_is_refused() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::Halt, Target::Node { id: "node-a".into() }, 1, 1);
            let ap = approve(&o, &["alice"]).unwrap();
            assert!(matches!(k.authorize_approved(&o, &ap, &tree(), 100), Err(KillError::Expired { .. })));
        }

        #[test]
        fn isolate_plans_exactly_the_node_that_isolates_itself() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::Isolate, Target::Node { id: "node-b".into() }, 1, 1);
            let steps = k.authorize_approved(&o, &approve(&o, &["alice"]).unwrap(), &tree(), 10).unwrap();
            assert_eq!(steps.len(), 1);
            assert_eq!(steps[0].target, "node-b");
            assert_eq!(steps[0].mode, KillMode::Isolate);
        }

        #[test]
        fn release_is_its_own_signed_order_for_the_node_that_isolated_itself() {
            let mut k = KillSwitch::approved_only();
            let iso = order(Action::Isolate, Target::Node { id: "node-b".into() }, 1, 1);
            k.authorize_approved(&iso, &approve(&iso, &["alice"]).unwrap(), &tree(), 10).unwrap();
            let rel = order(Action::Release, Target::Node { id: "node-b".into() }, 1, 2);
            let steps = k.authorize_approved(&rel, &approve(&rel, &["alice"]).unwrap(), &tree(), 10).unwrap();
            assert_eq!(steps.len(), 1);
            assert_eq!(steps[0].target, "node-b");
            assert_eq!(steps[0].mode, KillMode::Release);
            assert!(KillMode::Release.is_reversible());
            // Replaying the release is refused like any other order.
            assert!(k.authorize_approved(&rel, &approve(&rel, &["alice"]).unwrap(), &tree(), 10).is_err());
            // A release names one node; one node may not release another's domain.
            let wide = order(Action::Release, Target::Cluster, 1, 3);
            assert!(wide.validate().is_err());
        }

        #[test]
        fn crypto_erase_needs_two_independent_approvals_by_default() {
            let o = order(Action::CryptoErase, Target::Node { id: "node-a".into() }, 1, 1);
            assert!(approve(&o, &["alice"]).is_none());
            assert!(approve(&o, &["alice", "alice"]).is_none());
            let mut k = KillSwitch::approved_only();
            let ap = approve(&o, &["alice", "bob"]).unwrap();
            assert!(k.authorize_approved(&o, &ap, &tree(), 10).is_ok());
        }

        #[test]
        fn roster_orders_are_not_kill_orders() {
            let mut k = KillSwitch::approved_only();
            let o = order(
                Action::Admit,
                Target::Credential { id: "x".into(), key_sha256: "0".repeat(64), rp_id: RP.into() },
                1,
                1,
            );
            let ap = approve(&o, &["alice"]).unwrap();
            assert!(matches!(k.authorize_approved(&o, &ap, &tree(), 10), Err(KillError::NotAKillOrder(_))));
        }

        #[test]
        fn power_off_still_needs_an_independent_path() {
            let mut k = KillSwitch::approved_only();
            let o = order(Action::PowerOff, Target::Node { id: "node-a".into() }, 1, 1);
            let ap = approve(&o, &["alice"]).unwrap();
            assert_eq!(k.authorize_approved(&o, &ap, &tree(), 10), Err(KillError::NoOutOfBandPath));
        }
    }

    #[test]
    fn every_scope_requires_operator_authority() {
        assert!(KillSwitch::requires_operator_authority(&KillScope::Cluster));
        assert!(KillSwitch::requires_operator_authority(&KillScope::Node("x".into())));
    }
}
