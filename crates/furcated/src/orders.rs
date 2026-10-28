//! This node's side of passkey orders.
//!
//! The desk in `furcate_api::orders` collects proposals and approvals; this is
//! what it hands an approved order to. The node verifies for itself: the order
//! must name it, the approval must be over this exact order, and the kill
//! switch applies the same expiry, replay, counter, bound and out-of-band
//! checks it applies to an operator-signed order.
//!
//! It knows only itself, not the site's domain tree, so it accepts orders that
//! name it or the whole cluster and refuses ones that name a domain: a node
//! that guessed which domains it sits under would be deciding its own blast
//! radius.
//!
//! A planned step is then carried out by an [`Actuator`] (see
//! `actuators`), and what the order's outcome says is what the
//! actuator reported: `actuated` only when it reported success. `power_off`
//! goes through the out-of-band path the node declares in
//! `out-of-band.json`, and is refused while there is none.
//!
//! The kill switch's counter is kept in the state directory, so a restart
//! does not make an order it already carried out new again.

use furcate_api::orders::{Execution, Executor};
use furcate_authn::order::{Action, Order, Target};
use furcate_authn::webauthn::Approval;
use furcate_killswitch::actuate::{carry_out, Actuator, OutOfBand, Report};
use furcate_killswitch::{KillError, KillSwitch};
use furcate_ledger::OpKind;
use furcate_topology::{DomainKind, DomainTree, Provenance};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct NodeOrders {
    node_id: String,
    agent: Arc<Mutex<super::Agent>>,
    kill: Mutex<KillSwitch>,
    custody: Option<Arc<super::keycustody::KeyCustody>>,
    ssh_logins: Option<Arc<super::sshlogin::LoginKeys>>,
    counter_path: Option<PathBuf>,
    actuator: Arc<dyn Actuator>,
    /// The out-of-band path, or why there is none.
    out_of_band: Result<Box<dyn OutOfBand>, String>,
}

impl NodeOrders {
    pub fn new(
        node_id: String,
        agent: Arc<Mutex<super::Agent>>,
        actuator: Arc<dyn Actuator>,
        out_of_band: Result<Box<dyn OutOfBand>, String>,
        counter_path: Option<PathBuf>,
    ) -> Self {
        let mut kill = KillSwitch::approved_only();
        // Without a declared out-of-band path `power_off` is refused here,
        // and the refusal says why there is none.
        kill.set_out_of_band(out_of_band.is_ok());
        if let Some(p) = &counter_path {
            match std::fs::read_to_string(p) {
                Ok(text) => match serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v["last_counter"].as_u64())
                {
                    Some(c) => {
                        kill.set_last_counter(c);
                    }
                    None => eprintln!(
                        "furcated: WARNING {} is unreadable; the kill switch starts from the \
                         desk's own record of decided orders",
                        p.display()
                    ),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("furcated: WARNING {}: {e}", p.display()),
            }
        }
        Self {
            node_id,
            agent,
            kill: Mutex::new(kill),
            custody: None,
            ssh_logins: None,
            counter_path,
            actuator,
            out_of_band,
        }
    }

    /// Carry out `set_custody` orders against this node's key custody.
    pub fn with_custody(mut self, custody: Arc<super::keycustody::KeyCustody>) -> Self {
        self.custody = Some(custody);
        self
    }

    /// Take `login` orders: this node holds the site's SSH CA, and the keys
    /// waiting for approval are kept in `keys`.
    pub fn with_ssh_logins(mut self, keys: Arc<super::sshlogin::LoginKeys>) -> Self {
        self.ssh_logins = Some(keys);
        self
    }

    fn set_custody(&self, order: &Order, approval: &Approval) -> Result<Value, String> {
        let Some(custody) = &self.custody else {
            return Err("this node runs no key custody, so it cannot apply a custody change".into());
        };
        if approval.order_hash() != order.hash().map_err(|e| e.to_string())? {
            return Err("the approval is for a different order".into());
        }
        let mut a = self.agent.lock().expect("agent lock");
        let alive = a.membership.alive().into_iter().map(|m| m.id.clone()).collect();
        let (now_s, now_ms) = (super::now_s(), super::now_ms());
        let applied = custody.apply_order(order, approval, &mut a.chain, now_s, now_ms);
        custody.reload(&mut a.chain, &alive, now_s, now_ms);
        a.persist_chain();
        applied
    }

    fn tree(&self) -> DomainTree {
        let mut t = DomainTree::new();
        t.insert("site", DomainKind::Site, None, Provenance::Declared)
            .insert(
                self.node_id.clone(),
                DomainKind::Node,
                Some("site"),
                Provenance::Discovered,
            );
        t
    }
}

impl Executor for NodeOrders {
    fn covers(&self, target: &Target) -> Result<(), String> {
        match target {
            Target::Node { id } if *id == self.node_id => Ok(()),
            Target::Node { id } => Err(format!("this is {}, not {id}", self.node_id)),
            Target::Cluster | Target::Credential { .. } | Target::Custody { .. } => Ok(()),
            // A login is carried out by the node holding the site's SSH CA,
            // whichever machine it opens.
            Target::Login { .. } => match &self.ssh_logins {
                Some(_) if super::sshlogin::holds_ca() => Ok(()),
                _ => Err(format!(
                    "{} does not hold the site's SSH certificate authority",
                    self.node_id
                )),
            },
            Target::Domain { id } => Err(format!(
                "{} does not hold the site's domain tree, so it cannot tell whether it is \
                 under `{id}`; name the node, or the cluster",
                self.node_id
            )),
        }
    }

    fn execute(&self, order: &Order, approval: &Approval) -> Result<Execution, String> {
        // A cell's manager approves for that cell and the cells inside it,
        // and nothing else. Checked here, by the node the order would act
        // on, against its own reading of the signed chain.
        super::cells::order_in_scope(order, approval.approvers(), super::now_s())?;
        if order.action == Action::SetCustody {
            return self.set_custody(order, approval).map(Execution::Actuated);
        }
        if order.action == Action::Login {
            let Some(keys) = &self.ssh_logins else {
                return Err(format!("{} takes no login orders", self.node_id));
            };
            return super::sshlogin::issue(order, approval, keys, &super::sshlogin::furcate_ssh_signer)
                .map(Execution::Actuated);
        }
        let now = super::now_s();
        let (steps, counter) = {
            let mut kill = self.kill.lock().expect("kill switch lock");
            let steps = kill
                .authorize_approved(order, approval, &self.tree(), now)
                .map_err(|e| match (&e, &self.out_of_band) {
                    (KillError::NoOutOfBandPath, Err(why)) => format!("{e}: {why}"),
                    _ => e.to_string(),
                })?;
            (steps, kill.last_counter())
        };
        if let Some(p) = &self.counter_path {
            let body = json!({ "last_counter": counter }).to_string();
            if let Err(e) = super::actuators::write_atomically(p, body.as_bytes()) {
                eprintln!("furcated: WARNING kill switch counter not persisted: {e}");
            }
        }
        let hash = hex::encode(approval.order_hash());
        let mine: Vec<_> = steps
            .into_iter()
            .filter(|s| s.target == self.node_id)
            .collect();
        let report = carry_out(
            &self.node_id,
            &mine,
            &hash,
            self.actuator.as_ref(),
            self.out_of_band.as_ref().ok().map(|b| b.as_ref()),
        );
        let mut detail = json!({
            "node": self.node_id,
            "action": order.action.as_str(),
            "steps": mine,
        });
        Ok(match report {
            Report::Done { what } => {
                detail["reported"] = what;
                Execution::Actuated(detail)
            }
            Report::Failed { why, partial } => {
                detail["reported"] = partial;
                Execution::Failed { why, detail }
            }
        })
    }

    fn state(&self) -> Value {
        json!({
            "node": self.node_id,
            "actuators": self.actuator.state(),
            "out_of_band": match &self.out_of_band {
                Ok(p) => p.describe(),
                Err(why) => json!({ "none": why }),
            },
        })
    }

    fn record(&self, entry: &Value) {
        let kind = match entry["action"].as_str() {
            Some(a)
                if a == Action::Halt.as_str()
                    || a == Action::Resume.as_str()
                    || a == Action::PowerOff.as_str() =>
            {
                OpKind::Power
            }
            Some(a) if a == Action::CryptoErase.as_str() || a == Action::Login.as_str() => {
                OpKind::KeyUse
            }
            Some(a)
                if a == Action::Admit.as_str()
                    || a == Action::Revoke.as_str()
                    || a == Action::SetCustody.as_str() =>
            {
                OpKind::PolicyChange
            }
            _ => OpKind::Lifecycle,
        };
        let actor = entry["by"].as_str().unwrap_or("passkey order").to_string();
        let subject = entry["order_hash"]
            .as_str()
            .or_else(|| entry["credential_id"].as_str())
            .unwrap_or_default()
            .to_string();
        let mut a = self.agent.lock().expect("agent lock");
        a.chain
            .append(super::now_ms(), kind, actor, subject, entry.to_string());
        a.persist_chain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_authn::order::Bounds;
    use furcate_authn::webauthn::virtual_authenticator::Authenticator;
    use furcate_authn::webauthn::{verify_assertion, Challenge, Tally, Thresholds};

    const RP: &str = "site.example";
    const NODE: &str = "furcate:node:test";

    /// Remembers what it was asked and answers from a script.
    #[derive(Default)]
    struct FakeActuator {
        asked: Mutex<Vec<String>>,
        fail: Option<&'static str>,
    }

    impl Actuator for FakeActuator {
        fn halt(&self, h: &str) -> Report {
            self.answer("halt", h)
        }
        fn resume(&self, h: &str) -> Report {
            self.answer("resume", h)
        }
        fn isolate(&self, h: &str) -> Report {
            self.answer("isolate", h)
        }
        fn release(&self, h: &str) -> Report {
            self.answer("release", h)
        }
        fn crypto_erase(&self, h: &str) -> Report {
            self.answer("crypto_erase", h)
        }
        fn state(&self) -> Value {
            json!({ "fake": true })
        }
    }

    impl FakeActuator {
        fn answer(&self, what: &str, _hash: &str) -> Report {
            self.asked.lock().unwrap().push(what.into());
            if self.fail == Some(what) {
                return Report::Failed {
                    why: format!("{what} did not complete"),
                    partial: json!({ "stopped": ["furcate-app-a.service"], "failed": ["furcate-app-b.service"] }),
                };
            }
            Report::Done {
                what: json!({ "did": what }),
            }
        }
    }

    struct FakeWarden(Arc<Mutex<Vec<String>>>);

    impl OutOfBand for FakeWarden {
        fn describe(&self) -> Value {
            json!({ "kind": "warden", "device": "fake" })
        }
        fn power_off(&self, h: &str) -> Report {
            self.0.lock().unwrap().push(h.into());
            Report::Done {
                what: json!({ "warden": "acknowledged" }),
            }
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcated-orders-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn node(
        actuator: Arc<FakeActuator>,
        out_of_band: Result<Box<dyn OutOfBand>, String>,
        dir: &std::path::Path,
    ) -> NodeOrders {
        let agent = Arc::new(Mutex::new(super::super::tests::agent()));
        NodeOrders::new(
            NODE.into(),
            agent,
            actuator,
            out_of_band,
            Some(dir.join("killswitch.json")),
        )
    }

    fn order(action: Action, counter: u64) -> Order {
        let now = super::super::now_s();
        Order {
            site: RP.into(),
            action,
            target: Target::Node { id: NODE.into() },
            bounds: Bounds {
                max_nodes: 1,
                duration_s: None,
            },
            counter,
            issued_at: now,
            expires_at: now + 600,
            reason: "test".into(),
        }
    }

    fn approve(o: &Order) -> Approval {
        let now = super::super::now_s();
        let mut t = Tally::new(o, &Thresholds::default()).unwrap();
        for i in 0..2u8 {
            let mut a = Authenticator::new(i + 1, RP);
            let cred = a.credential();
            let c = Challenge {
                order_hash: o.hash().unwrap(),
                nonce: [0; 16],
                expires_at: now + 60,
            };
            t.add(verify_assertion(&cred, &a.get(&c), &c, now).unwrap())
                .unwrap();
        }
        t.approval().unwrap()
    }

    #[test]
    fn each_action_is_actuated_only_on_the_actuators_word() {
        let dir = scratch("each");
        let fake = Arc::new(FakeActuator::default());
        let n = node(fake.clone(), Err("none declared".into()), &dir);
        for (i, action) in [
            Action::Halt,
            Action::Resume,
            Action::Isolate,
            Action::Release,
            Action::CryptoErase,
        ]
        .into_iter()
        .enumerate()
        {
            let o = order(action, i as u64 + 1);
            match n.execute(&o, &approve(&o)).unwrap() {
                Execution::Actuated(d) => {
                    assert_eq!(d["action"], action.as_str());
                    assert_eq!(d["reported"]["steps"][0]["what"]["did"], action.as_str());
                }
                other => panic!("{action:?}: {other:?}"),
            }
        }
        assert_eq!(
            *fake.asked.lock().unwrap(),
            ["halt", "resume", "isolate", "release", "crypto_erase"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_or_partial_actuation_is_a_failure_with_what_happened() {
        let dir = scratch("fail");
        let fake = Arc::new(FakeActuator {
            fail: Some("halt"),
            ..Default::default()
        });
        let n = node(fake, Err("none declared".into()), &dir);
        let o = order(Action::Halt, 1);
        let Execution::Failed { why, detail } = n.execute(&o, &approve(&o)).unwrap() else {
            panic!("a failed halt was not reported as failed")
        };
        assert!(why.contains("halt did not complete"), "{why}");
        assert_eq!(
            detail["reported"]["failed_step"]["failed"][0],
            "furcate-app-b.service"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn power_off_is_refused_without_a_path_and_goes_to_the_warden_with_one() {
        let dir = scratch("power");
        let fake = Arc::new(FakeActuator::default());
        let n = node(
            fake.clone(),
            Err("no out-of-band path is declared".into()),
            &dir,
        );
        let o = order(Action::PowerOff, 1);
        let why = n.execute(&o, &approve(&o)).unwrap_err();
        assert!(why.contains("no out-of-band path is declared"), "{why}");
        assert_eq!(
            n.state()["out_of_band"]["none"],
            "no out-of-band path is declared"
        );

        let sent = Arc::new(Mutex::new(Vec::new()));
        let n = node(fake.clone(), Ok(Box::new(FakeWarden(sent.clone()))), &dir);
        let o = order(Action::PowerOff, 2);
        let Execution::Actuated(d) = n.execute(&o, &approve(&o)).unwrap() else {
            panic!("the Warden acknowledged and the order did not say so")
        };
        assert_eq!(d["reported"]["steps"][0]["what"]["path"]["kind"], "warden");
        assert_eq!(*sent.lock().unwrap(), [hex::encode(o.hash().unwrap())]);
        assert!(
            fake.asked.lock().unwrap().is_empty(),
            "power off never reaches the node itself"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_counter_survives_a_restart_so_an_old_order_stays_old() {
        let dir = scratch("counter");
        let fake = Arc::new(FakeActuator::default());
        let o = order(Action::Isolate, 5);
        let n = node(fake.clone(), Err("none".into()), &dir);
        assert!(matches!(
            n.execute(&o, &approve(&o)).unwrap(),
            Execution::Actuated(_)
        ));
        drop(n);
        let n = node(fake.clone(), Err("none".into()), &dir);
        let older = order(Action::Release, 4);
        let why = n.execute(&older, &approve(&older)).unwrap_err();
        assert!(why.contains("not above"), "{why}");
        let release = order(Action::Release, 6);
        assert!(matches!(
            n.execute(&release, &approve(&release)).unwrap(),
            Execution::Actuated(_)
        ));
        assert_eq!(*fake.asked.lock().unwrap(), ["isolate", "release"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_order_naming_another_node_never_reaches_an_actuator() {
        let dir = scratch("other");
        let fake = Arc::new(FakeActuator::default());
        let n = node(fake.clone(), Err("none".into()), &dir);
        let mut o = order(Action::Halt, 1);
        o.target = Target::Node {
            id: "someone-else".into(),
        };
        assert!(n.covers(&o.target).is_err());
        assert!(n.execute(&o, &approve(&o)).is_err());
        assert!(fake.asked.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
