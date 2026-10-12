//! Carrying a planned step out on this machine.
//!
//! The kill switch decides whether an order may act and plans it; this is
//! where the plan meets the machine. Each action is one method on
//! [`Actuator`], so a node wires in the real thing and a test stands in a
//! fake, and every method answers with a [`Report`]: what the actuator says it
//! did, or why it did not. Nothing here produces success on its own account.
//! A caller that heard no report has a failure, not a success it has yet to
//! hear about.
//!
//! Cutting power is not something a node does to itself, because the node
//! may be what has failed. It goes through an [`OutOfBand`] path, and with
//! none configured it is refused before it gets here.

use crate::{ExecutionStep, KillMode};
use serde::Serialize;
use serde_json::{json, Value};

/// What an actuator says happened.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Report {
    /// The actuator reports that it did this.
    Done { what: Value },
    /// It did not, or did only part of it. `partial` is whatever it did do.
    Failed { why: String, partial: Value },
}

impl Report {
    pub fn failed(why: impl Into<String>) -> Self {
        Report::Failed {
            why: why.into(),
            partial: Value::Null,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Report::Done { .. })
    }
}

/// The node-local actions an approved order can take.
///
/// `order_hash` identifies the order to whatever carries the action out, so a
/// report can be matched to the order that asked for it.
pub trait Actuator: Send + Sync {
    /// Stop the workloads this node supervises. The OS, the agent, and the
    /// paths an operator reaches the node by stay up.
    fn halt(&self, order_hash: &str) -> Report;

    /// Restart the workloads earlier halts stopped, as they recorded them,
    /// and nothing else. `Done` means every recorded workload is running
    /// again; with no halt recorded nothing acts, and that is a failure.
    fn resume(&self, order_hash: &str) -> Report;

    /// Drop this node's own reach: its overlay interface down and a deny-all
    /// in both directions, except the out-of-band and console path. It
    /// removes no peer from anything; other nodes simply stop hearing it.
    fn isolate(&self, order_hash: &str) -> Report;

    /// Undo `isolate`.
    fn release(&self, order_hash: &str) -> Report;

    /// Destroy the node's sealed custody material and latch an erase that
    /// early boot completes. `Done` means the material is destroyed and the
    /// latch is set. It does not mean the erase has been acknowledged; that
    /// comes later, as a fresh quote from the node after it completes.
    fn crypto_erase(&self, order_hash: &str) -> Report;

    /// What the actuator can say about the node now.
    fn state(&self) -> Value {
        Value::Null
    }
}

/// A control path to the machine that does not depend on the machine.
pub trait OutOfBand: Send + Sync {
    /// What kind of path this is, and where, for the record.
    fn describe(&self) -> Value;

    fn power_off(&self, order_hash: &str) -> Report;
}

/// Carry out the steps of a plan that name `node`, in plan order.
///
/// Stops at the first step that fails, and the report says which steps ran.
/// A plan with no step for `node` is a failure: the order was approved and
/// this node did nothing.
pub fn carry_out(
    node: &str,
    steps: &[ExecutionStep],
    order_hash: &str,
    actuator: &dyn Actuator,
    out_of_band: Option<&dyn OutOfBand>,
) -> Report {
    let mine: Vec<&ExecutionStep> = steps.iter().filter(|s| s.target == node).collect();
    if mine.is_empty() {
        return Report::failed(format!("the plan has no step for {node}; nothing acted"));
    }
    let mut done = Vec::new();
    for step in mine {
        let report = match step.mode {
            KillMode::Halt => actuator.halt(order_hash),
            KillMode::Resume => actuator.resume(order_hash),
            KillMode::Isolate => actuator.isolate(order_hash),
            KillMode::Release => actuator.release(order_hash),
            KillMode::CryptoErase => actuator.crypto_erase(order_hash),
            KillMode::PowerOff => match out_of_band {
                Some(path) => match path.power_off(order_hash) {
                    Report::Done { what } => Report::Done {
                        what: json!({ "path": path.describe(), "reply": what }),
                    },
                    Report::Failed { why, partial } => Report::Failed {
                        why: format!("{why} (path: {})", path.describe()),
                        partial,
                    },
                },
                None => Report::failed("no out-of-band path is configured; nothing acted"),
            },
            KillMode::Drain => Report::failed(
                "a drain moves work between nodes and is not something a node does to itself; \
                 nothing acted",
            ),
        };
        match report {
            Report::Done { what } => done.push(json!({ "mode": step.mode, "what": what })),
            Report::Failed { why, partial } => {
                return Report::Failed {
                    why: format!("{}: {why}", step.mode.as_str()),
                    partial: json!({ "completed": done, "failed_step": partial }),
                }
            }
        }
    }
    Report::Done {
        what: json!({ "steps": done }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers each action from a script, and remembers what it was asked.
    #[derive(Default)]
    struct Fake {
        asked: Mutex<Vec<String>>,
        fail: Option<&'static str>,
        partial: bool,
    }

    impl Fake {
        fn answer(&self, what: &str, hash: &str) -> Report {
            self.asked.lock().unwrap().push(format!("{what}:{hash}"));
            if self.fail == Some(what) {
                return Report::Failed {
                    why: format!("{what} broke"),
                    partial: if self.partial {
                        json!({ "stopped": ["furcate-app-a.service"], "failed": ["furcate-app-b.service"] })
                    } else {
                        Value::Null
                    },
                };
            }
            Report::Done {
                what: json!({ "did": what }),
            }
        }
    }

    impl Actuator for Fake {
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
    }

    struct FakePath(Mutex<Vec<String>>);

    impl OutOfBand for FakePath {
        fn describe(&self) -> Value {
            json!({ "kind": "fake" })
        }
        fn power_off(&self, h: &str) -> Report {
            self.0.lock().unwrap().push(h.into());
            Report::Done { what: json!("off") }
        }
    }

    fn step(target: &str, mode: KillMode) -> ExecutionStep {
        ExecutionStep {
            target: target.into(),
            mode,
            order: 1,
        }
    }

    #[test]
    fn each_mode_reaches_its_actuator_and_reports_what_it_said() {
        let fake = Fake::default();
        for (mode, name) in [
            (KillMode::Halt, "halt"),
            (KillMode::Resume, "resume"),
            (KillMode::Isolate, "isolate"),
            (KillMode::Release, "release"),
            (KillMode::CryptoErase, "crypto_erase"),
        ] {
            let r = carry_out("n1", &[step("n1", mode)], "h", &fake, None);
            assert!(r.is_done(), "{mode:?}: {r:?}");
            let Report::Done { what } = r else {
                unreachable!()
            };
            assert_eq!(what["steps"][0]["what"]["did"], name);
        }
        assert_eq!(
            *fake.asked.lock().unwrap(),
            ["halt:h", "resume:h", "isolate:h", "release:h", "crypto_erase:h"]
        );
    }

    #[test]
    fn a_failure_is_reported_with_what_did_happen() {
        let fake = Fake {
            fail: Some("halt"),
            partial: true,
            ..Default::default()
        };
        let r = carry_out("n1", &[step("n1", KillMode::Halt)], "h", &fake, None);
        let Report::Failed { why, partial } = r else {
            panic!("a failed halt reported success")
        };
        assert!(why.contains("halt broke"), "{why}");
        assert_eq!(
            partial["failed_step"]["stopped"][0],
            "furcate-app-a.service"
        );
    }

    #[test]
    fn steps_for_other_nodes_are_not_this_nodes_to_take() {
        let fake = Fake::default();
        let r = carry_out("n1", &[step("n2", KillMode::Halt)], "h", &fake, None);
        assert!(!r.is_done());
        assert!(fake.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn power_off_needs_a_path_and_goes_through_it() {
        let fake = Fake::default();
        let r = carry_out("n1", &[step("n1", KillMode::PowerOff)], "h", &fake, None);
        assert!(!r.is_done());
        let path = FakePath(Mutex::new(Vec::new()));
        let r = carry_out(
            "n1",
            &[step("n1", KillMode::PowerOff)],
            "h",
            &fake,
            Some(&path),
        );
        assert!(r.is_done(), "{r:?}");
        assert_eq!(*path.0.lock().unwrap(), ["h"]);
        assert!(
            fake.asked.lock().unwrap().is_empty(),
            "power off is not a node-local action"
        );
    }

    #[test]
    fn a_drain_is_not_carried_out_here() {
        let fake = Fake::default();
        assert!(!carry_out("n1", &[step("n1", KillMode::Drain)], "h", &fake, None).is_done());
    }
}
