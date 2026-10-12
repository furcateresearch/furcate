//! What an agent may propose doing to a machine.
//!
//! A closed vocabulary of named operations with typed arguments, and
//! deliberately not a shell. The reason is not that a model cannot write shell
//! — it is that a shell string cannot be soundly approved. A command carrying
//! a substitution, a glob or a redirect means something that is not visible in
//! the string, so showing it to a person and taking their yes establishes
//! nothing about what they agreed to. `restart the workload named nats on
//! @node-b` can be shown, understood and agreed to. `sh -c "..."` cannot.
//!
//! Every action here already has a guarded route behind it. This adds no
//! authority: it is a vocabulary for saying which of the things an operator
//! could already do is being asked for, so that the asking can be reviewed,
//! rate-limited and recorded before the signature is spent.
//!
//! The list is short on purpose. Anything absent is not forbidden — it is
//! reached the way it always was, by an operator running the command
//! themselves. A vocabulary that grows to cover everything is a shell with
//! extra steps.

use serde::{Deserialize, Serialize};

/// One thing that can be asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Restart one workload on one machine.
    ///
    /// The narrowest useful repair, and the one an operator reaches for most.
    RestartWorkload { node: String, kind: String, id: String },
    /// Stop placing new work on a machine, leaving what runs alone.
    ///
    /// Reversible by its nature: the machine keeps serving, and the change is
    /// to what arrives next.
    DrainNode { node: String },
    /// Accept work again.
    UndrainNode { node: String },
    /// Set how much power a machine may draw.
    ///
    /// Bounded rather than free: a cap of zero is a power-off wearing another
    /// name, and the floor here is what stops that being reachable by
    /// arithmetic.
    SetPowerCap { node: String, watts: u32 },
    /// Declare how a machine should behave about noise.
    SetThermal { node: String, quiet: Option<String>, envelope: Option<String> },
}

/// Why an action was refused before anybody was asked to approve it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Names a capability no policy, grant or delegation may authorise.
    Invariant(&'static str),
    /// Outside the range this action accepts.
    OutOfRange { field: &'static str, given: String, allowed: &'static str },
    /// A required field was empty.
    Missing(&'static str),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Invariant(c) => write!(f, "`{c}` is refused to everything, always"),
            Refusal::OutOfRange { field, given, allowed } => {
                write!(f, "{field} is {given}; allowed: {allowed}")
            }
            Refusal::Missing(n) => write!(f, "{n} is required"),
        }
    }
}

impl std::error::Error for Refusal {}

/// The lowest cap that is a cap rather than an off switch.
///
/// A machine capped at nothing has been powered off by arithmetic, and
/// `power_off` is one of the four things no grant may authorise. The floor is
/// what keeps that true when the lever is a number.
pub const MIN_POWER_CAP_W: u32 = 30;
/// Above this a cap is not restraining anything on the hardware here, and a
/// number nobody checked is how a typo becomes a setting.
pub const MAX_POWER_CAP_W: u32 = 2000;

impl Action {
    /// The capability this asks for, in the policy engine's own vocabulary.
    ///
    /// Named so that a rule written about `restart` covers this without
    /// knowing the action type exists. The two must agree, which is why this
    /// is derived rather than carried alongside.
    pub fn capability(&self) -> &'static str {
        match self {
            Action::RestartWorkload { .. } => "restart",
            Action::DrainNode { .. } => "drain",
            Action::UndrainNode { .. } => "undrain",
            Action::SetPowerCap { .. } => "power_cap",
            Action::SetThermal { .. } => "thermal",
        }
    }

    /// Which machine this touches.
    pub fn node(&self) -> &str {
        match self {
            Action::RestartWorkload { node, .. }
            | Action::DrainNode { node }
            | Action::UndrainNode { node }
            | Action::SetPowerCap { node, .. }
            | Action::SetThermal { node, .. } => node,
        }
    }

    /// Whether undoing this is a matter of asking for the opposite.
    ///
    /// Reported rather than acted on here: what a caller does with it is a
    /// policy question, and the honest thing at this layer is to say which
    /// kind of change is being proposed.
    pub fn reversible(&self) -> bool {
        match self {
            Action::DrainNode { .. } | Action::UndrainNode { .. } => true,
            // A restart is not undoable: the process that was running is gone
            // whatever happens next.
            Action::RestartWorkload { .. } => false,
            // A cap can be set back, but what ran slowly while it was low
            // cannot be un-run.
            Action::SetPowerCap { .. } | Action::SetThermal { .. } => true,
        }
    }

    /// What an approval prompt should say.
    ///
    /// One sentence naming the machine and what changes, because that is what
    /// somebody is being asked to agree to. A prompt that shows a payload asks
    /// them to parse rather than to decide.
    pub fn describe(&self) -> String {
        match self {
            Action::RestartWorkload { node, kind, id } => {
                format!("restart the {kind} `{id}` on {node}")
            }
            Action::DrainNode { node } => {
                format!("stop placing new work on {node}, leaving what runs alone")
            }
            Action::UndrainNode { node } => format!("let {node} accept work again"),
            Action::SetPowerCap { node, watts } => {
                format!("cap {node} at {watts}W")
            }
            Action::SetThermal { node, quiet, envelope } => {
                let mut what = Vec::new();
                if let Some(q) = quiet {
                    what.push(format!("quiet {q}"));
                }
                if let Some(e) = envelope {
                    what.push(format!("envelope {e}"));
                }
                if what.is_empty() {
                    format!("clear {node}'s thermal declaration")
                } else {
                    format!("set {node} to {}", what.join(", "))
                }
            }
        }
    }


    /// The policy request this action makes, for the engine to rule on.
    ///
    /// Built here rather than by each caller so the capability an action asks
    /// for and the capability policy rules on cannot drift apart: a rule
    /// written about `restart` covers `RestartWorkload` because this is the
    /// only place that mapping exists.
    ///
    /// The principal and roles come from whoever proved they are asking. They
    /// are arguments rather than fields on the action, because an action a
    /// caller could name itself in would let a request body choose its own
    /// authority — which is the hole the whole signing scheme exists to close.
    pub fn request(&self, principal: &str, roles: &[String]) -> crate::engine::Request {
        crate::engine::Request {
            principal: principal.to_string(),
            action: self.capability().to_string(),
            // The machine is the resource, so a grant can be narrowed to one.
            resource: format!("node:{}", self.node()),
            roles: roles.to_vec(),
        }
    }

    /// How this would be undone, in the proposal module's own terms.
    pub fn reversal(&self) -> crate::proposal::Reversal {
        match self {
            Action::DrainNode { node } => crate::proposal::Reversal::Action {
                capability: "undrain".into(),
                resource: format!("node:{node}"),
            },
            Action::UndrainNode { node } => crate::proposal::Reversal::Action {
                capability: "drain".into(),
                resource: format!("node:{node}"),
            },
            Action::SetPowerCap { node, .. } | Action::SetThermal { node, .. } => {
                crate::proposal::Reversal::Action {
                    capability: "thermal".into(),
                    resource: format!("node:{node}"),
                }
            }
            // Said plainly, with the reason. A restart cannot be undone: the
            // process that was running is gone whatever happens next, and a
            // proposal claiming otherwise asks for a yes under false terms.
            Action::RestartWorkload { .. } => crate::proposal::Reversal::Irreversible {
                why: "the process that was running is gone; a new one takes its place".into(),
            },
        }
    }

    /// Check an action is one that could be carried out, before anybody is
    /// asked about it.
    ///
    /// Refusing here rather than at execution means a person is never shown an
    /// approval prompt for something that was going to fail anyway, and an
    /// agent's mistake costs a message rather than a signature.
    pub fn check(&self) -> Result<(), Refusal> {
        // The four absolute invariants first, always. Nothing below can
        // reintroduce them, but a capability that ever names one must be
        // refused here as well as there — two checks of a rule that must never
        // fail is not duplication.
        if crate::invariant::forbidden_to_all(self.capability()) {
            return Err(Refusal::Invariant(match self.capability() {
                "halt" => "halt",
                "power_off" => "power_off",
                "isolate" => "isolate",
                _ => "crypto_erase",
            }));
        }
        if self.node().trim().is_empty() {
            return Err(Refusal::Missing("node"));
        }
        match self {
            Action::RestartWorkload { kind, id, .. } => {
                if kind.trim().is_empty() {
                    return Err(Refusal::Missing("kind"));
                }
                if id.trim().is_empty() {
                    return Err(Refusal::Missing("id"));
                }
            }
            Action::SetPowerCap { watts, .. } => {
                if *watts < MIN_POWER_CAP_W || *watts > MAX_POWER_CAP_W {
                    return Err(Refusal::OutOfRange {
                        field: "watts",
                        given: watts.to_string(),
                        allowed: "30 to 2000",
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The guarded route that carries this out, and the body it wants.
    ///
    /// Kept here so the vocabulary and the calls cannot drift: an action that
    /// cannot say how it is performed is one nobody can perform.
    pub fn route(&self) -> (&'static str, serde_json::Value) {
        match self {
            Action::RestartWorkload { node, kind, id } => (
                "/workloads/restart",
                serde_json::json!({ "node": node, "kind": kind, "id": id }),
            ),
            Action::DrainNode { node } => (
                "/intent",
                serde_json::json!({ "intent": "drain", "node": node }),
            ),
            Action::UndrainNode { node } => (
                "/intent",
                serde_json::json!({ "intent": "undrain", "node": node }),
            ),
            Action::SetPowerCap { node, watts } => (
                "/thermal",
                serde_json::json!({ "node": node, "envelope": format!("{watts}W") }),
            ),
            Action::SetThermal { node, quiet, envelope } => {
                let mut b = serde_json::json!({ "node": node });
                if let Some(o) = b.as_object_mut() {
                    if let Some(q) = quiet {
                        o.insert("quiet".into(), serde_json::json!(q));
                    }
                    if let Some(e) = envelope {
                        o.insert("envelope".into(), serde_json::json!(e));
                    }
                }
                ("/thermal", b)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule written about a capability covers the action that asks for it.
    #[test]
    fn an_action_makes_a_request_policy_can_rule_on() {
        let a = Action::DrainNode { node: "@node-a".into() };
        let r = a.request("person:ana", &["oncall".to_string()]);
        assert_eq!(r.action, "drain");
        assert_eq!(r.resource, "node:@node-a");
        assert_eq!(r.principal, "person:ana");
        assert_eq!(r.roles, vec!["oncall".to_string()]);
    }

    /// A proposal must not promise an undo it cannot perform.
    #[test]
    fn a_restart_does_not_claim_to_be_reversible() {
        let a = Action::RestartWorkload {
            node: "@a".into(),
            kind: "unit".into(),
            id: "x".into(),
        };
        // Irreversible carries its reason, so nobody has to infer it from
        // silence.
        assert!(matches!(
            a.reversal(),
            crate::proposal::Reversal::Irreversible { .. }
        ));
        assert!(!a.reversal().is_reversible());
        let d = Action::DrainNode { node: "@a".into() }.reversal();
        assert!(d.is_reversible());
        assert!(matches!(d, crate::proposal::Reversal::Action { .. }));
    }

    #[test]
    fn a_power_cap_cannot_become_a_power_off_by_arithmetic() {
        // `power_off` is one of the four things no grant may authorise. A cap
        // of zero reaches it with a number, which is why there is a floor.
        let off = Action::SetPowerCap { node: "@node-a".into(), watts: 0 };
        assert!(matches!(off.check(), Err(Refusal::OutOfRange { .. })));
        let daft = Action::SetPowerCap { node: "@node-a".into(), watts: 9_000 };
        assert!(matches!(daft.check(), Err(Refusal::OutOfRange { .. })));
        let fine = Action::SetPowerCap { node: "@node-a".into(), watts: 120 };
        assert!(fine.check().is_ok());
    }

    #[test]
    fn every_action_names_a_machine() {
        let nameless = Action::DrainNode { node: "  ".into() };
        assert_eq!(nameless.check(), Err(Refusal::Missing("node")));
    }

    #[test]
    fn a_restart_needs_to_say_what_it_restarts() {
        let vague = Action::RestartWorkload {
            node: "@node-b".into(),
            kind: "unit".into(),
            id: "".into(),
        };
        assert_eq!(vague.check(), Err(Refusal::Missing("id")));
    }

    /// The sentence a person is asked to agree to names the machine and the
    /// change, and contains no payload to parse.
    #[test]
    fn a_description_is_a_sentence_not_a_payload() {
        let a = Action::RestartWorkload {
            node: "@node-b".into(),
            kind: "unit".into(),
            id: "nats".into(),
        };
        assert_eq!(a.describe(), "restart the unit `nats` on @node-b");
        assert!(!a.describe().contains('{'));
    }

    #[test]
    fn what_can_be_undone_says_so() {
        assert!(Action::DrainNode { node: "@a".into() }.reversible());
        // The process that was running is gone whatever happens next.
        assert!(!Action::RestartWorkload {
            node: "@a".into(),
            kind: "unit".into(),
            id: "x".into()
        }
        .reversible());
    }

    /// Every action maps to a route that already exists and is guarded.
    ///
    /// This vocabulary adds no authority: it names things an operator could
    /// already do. An action that could not say how it is performed would be
    /// one nobody can perform.
    #[test]
    fn every_action_knows_how_it_is_carried_out() {
        for a in [
            Action::RestartWorkload { node: "@a".into(), kind: "unit".into(), id: "x".into() },
            Action::DrainNode { node: "@a".into() },
            Action::UndrainNode { node: "@a".into() },
            Action::SetPowerCap { node: "@a".into(), watts: 100 },
            Action::SetThermal { node: "@a".into(), quiet: Some("22-7".into()), envelope: None },
        ] {
            let (path, body) = a.route();
            assert!(path.starts_with('/'), "{a:?} has no route");
            assert!(body.is_object(), "{a:?} has no body");
            assert!(!a.capability().is_empty());
        }
    }

    /// An action naming one of the four is refused here as well as by policy.
    ///
    /// Two checks of a rule that must never fail is not duplication.
    #[test]
    fn the_vocabulary_cannot_express_a_forbidden_capability() {
        for a in [
            Action::RestartWorkload { node: "@a".into(), kind: "unit".into(), id: "x".into() },
            Action::DrainNode { node: "@a".into() },
            Action::SetPowerCap { node: "@a".into(), watts: 100 },
        ] {
            assert!(
                !crate::invariant::forbidden_to_all(a.capability()),
                "{a:?} names a forbidden capability"
            );
        }
    }
}
