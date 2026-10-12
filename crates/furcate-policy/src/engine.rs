//! Policy as data, evaluated deny-by-default.
//!
//! Deliberately small. A general policy language is a language, and a language
//! in the authorisation path is a place for surprises — the useful comparison
//! here is Cedar, which gave up expressiveness for a domain-specific shape it
//! could reason about, rather than a Datalog derivative that can express
//! anything including things nobody meant.
//!
//! So there is no arithmetic, no negation-as-failure, no joins over external
//! data. A rule names a principal, an action, a resource pattern and a window.
//! That is enough for everything this site actually needs to say, and it fits
//! on one screen, which matters more for a file that decides what a machine
//! will do.
//!
//! ## Order of evaluation
//!
//! 1. An invariant refuses, and nothing else is consulted.
//! 2. An explicit `Deny` refuses. Deny wins over allow, always, so a narrowing
//!    rule cannot be defeated by adding a broader permit underneath it.
//! 3. An `Allow` that matches permits.
//! 4. Nothing matched, so the answer is no.
//!
//! Step four is the one that does the work. A capability nobody wrote a rule
//! for is refused rather than permitted, which means the failure mode of an
//! incomplete policy file is a system that does less than intended rather than
//! more.

use crate::invariant::forbidden_to_all;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// One rule.
///
/// `"*"` is the only wildcard, and it matches a whole field rather than part of
/// one. Prefix and suffix matching would let `node:*` and `*:node-a` mean
/// subtly different things to different readers, and a rule that reads
/// differently to two people is worse than one that cannot express the case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub effect: Effect,
    /// Who: `operator`, `loop`, `network`, `agent:mcp`, or `*`.
    pub principal: String,
    /// What: a capability name, or `*`.
    pub action: String,
    /// On what: `node:node-a`, `site`, or `*`.
    pub resource: String,
    /// Unix seconds after which this rule stops applying.
    ///
    /// Present so that a temporary permission is expressible as a temporary
    /// permission, rather than as a note in a ticket saying to remove it later.
    pub until: Option<u64>,
    /// Why this rule exists. Not evaluated; carried into the decision so an
    /// audit record says what somebody meant rather than only what happened.
    pub reason: String,
}

impl Policy {
    fn field_matches(pattern: &str, value: &str) -> bool {
        pattern == "*" || pattern == value
    }

    /// Whether this rule's principal pattern covers the caller.
    ///
    /// `*` matches anyone and a bare name matches that name, as before. A
    /// pattern of `role:<name>` matches a caller holding that role — which is
    /// what makes a permission grantable to a job rather than to a person, so
    /// that admitting a colleague does not mean editing every rule.
    ///
    /// Deliberately not the other way round: a rule naming a PERSON never
    /// matches via a role. Roles widen who a rule covers; they never widen what
    /// a named individual can do.
    fn principal_matches(&self, r: &Request) -> bool {
        if self.principal == "*" || self.principal == r.principal {
            return true;
        }
        match self.principal.strip_prefix("role:") {
            Some(role) => r.roles.iter().any(|held| held == role),
            None => false,
        }
    }

    fn applies(&self, r: &Request, now: u64) -> bool {
        if let Some(until) = self.until {
            if now >= until {
                return false;
            }
        }
        self.principal_matches(r)
            && Self::field_matches(&self.action, &r.action)
            && Self::field_matches(&self.resource, &r.resource)
    }
}

/// What is being asked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub principal: String,
    pub action: String,
    pub resource: String,
    /// Roles this principal holds, if any.
    ///
    /// Carried on the request rather than looked up here, because the engine
    /// must not need a directory to answer — the sovereign path is a machine
    /// deciding on its own with no service to ask. Whoever proved the caller
    /// knows their roles; the engine only matches them.
    ///
    /// Empty is the ordinary case and the safe one: a rule naming a role
    /// matches nobody rather than everybody.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// The answer, with enough to reconstruct why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    /// Human-readable, and the field that makes a decision auditable rather
    /// than merely recorded.
    pub because: String,
    /// True when an invariant refused, as opposed to policy.
    ///
    /// Worth distinguishing: a policy denial is something an operator can
    /// change, and an invariant denial is not, so telling somebody to "adjust
    /// the policy" would send them looking for a file that cannot help.
    pub structural: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicySet {
    pub policies: Vec<Policy>,
}

impl PolicySet {
    pub fn evaluate(&self, r: &Request, now: u64) -> Decision {
        // 1. Nothing gets past an invariant, including an explicit allow.
        // Narrower than the four invariants and just as unconditional: some
        // things a person may do and a loop may not. Checked before any rule,
        // so no policy file can grant it.
        if crate::invariant::forbidden_to_automation(&r.principal, &r.action) {
            return Decision {
                allowed: false,
                because: format!(
                    "{} is refused to automatic processes; supervision belongs to                      systemd and Docker, and a second supervisor fighting the                      first turns a flapping workload into a flapping machine.                      An operator may ask for this",
                    r.action
                ),
                structural: true,
            };
        }
        if forbidden_to_all(&r.action) {
            return Decision {
                allowed: false,
                because: format!(
                    "{} is refused to everything this engine can express; it \
                     requires a physically present operator holding the signing \
                     key",
                    r.action
                ),
                structural: true,
            };
        }

        // 2. Deny wins, so a narrowing rule cannot be defeated by adding a
        //    broader permit beneath it.
        if let Some(d) = self
            .policies
            .iter()
            .find(|p| p.effect == Effect::Deny && p.applies(r, now))
        {
            return Decision {
                allowed: false,
                because: format!("denied by policy: {}", d.reason),
                structural: false,
            };
        }

        // 3. An allow that matches.
        if let Some(a) = self
            .policies
            .iter()
            .find(|p| p.effect == Effect::Allow && p.applies(r, now))
        {
            return Decision {
                allowed: true,
                because: format!("allowed by policy: {}", a.reason),
                structural: false,
            };
        }

        // 4. Nobody wrote a rule, so the answer is no.
        Decision {
            allowed: false,
            because: format!(
                "no rule permits {} to {} on {}",
                r.principal, r.action, r.resource
            ),
            structural: false,
        }
    }

    /// Parse a policy file, in YAML or JSON.
    ///
    /// YAML because policy is written and read by people far more often than
    /// it is written by machines, and it takes comments — a rule whose reason
    /// is a field and whose *history* is a comment above it is worth more than
    /// a tidier serialisation. It is also what every tool an operator already
    /// uses for this speaks.
    ///
    /// One parser handles both, since JSON is a subset of YAML. That is not a
    /// trick to save code: it means a file generated by a machine and a file
    /// edited by a person go through exactly the same path, and neither format
    /// gets a second, subtly different implementation.
    pub fn parse(s: &str) -> Result<Self, String> {
        serde_norway::from_str(s).map_err(|e| format!("policy is not valid YAML or JSON: {e}"))
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Render as YAML, for an operator who wants a file to start from.
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_norway::to_string(self).map_err(|e| e.to_string())
    }

    /// The rules this site runs with when no file has been written.
    ///
    /// Reproduces exactly what was previously compiled in, so adopting the
    /// engine changes nothing about what is permitted until somebody
    /// deliberately writes a file. A migration that quietly widens or narrows
    /// authority is a migration nobody can review.
    pub fn compiled_default() -> Self {
        let allow = |principal: &str, action: &str, reason: &str| Policy {
            effect: Effect::Allow,
            principal: principal.into(),
            action: action.into(),
            resource: "*".into(),
            until: None,
            reason: reason.into(),
        };
        PolicySet {
            policies: vec![
                allow("loop", "tune", "the control loop may adjust levers within their floors"),
                allow("loop", "suspend", "consolidation, which the planner already refuses without a proven wake"),
                allow("loop", "resume", "the other half of consolidation"),
                allow("loop", "hold", "doing nothing is always permitted"),
                allow("loop", "escalate", "asking a human is always permitted"),
                allow("network", "drain", "a remote party may request work be moved; local policy decides"),
                allow("network", "report_capacity", "publishing what this site can do"),
                allow("network", "attest", "answering an attestation challenge"),
                allow("network", "publish_site_root", "publishing the Merkle anchor"),
                allow("operator", "*", "a signed order from the holder of the sealed key"),
                // Overlay admission, as rules rather than as an `if`. The
                // principal is `*` because a peer earns its place by the tier
                // its attestation reached, not by which machine it happens to
                // be — naming nodes here would mean editing policy every time
                // one joined.
                //
                // There is deliberately no rule for `tier:soft`. It is refused
                // by the default rather than by an explicit deny, which is the
                // correct expression: a board identified only by a chip serial
                // has not earned a place, and nobody has decided to exclude it.
                // A device-tier peer joins to carry readings and roll-ups. What
                // it may not do is originate a privileged call, and that is
                // refused where such calls arrive, not by keeping it out.
                Policy {
                    effect: Effect::Allow,
                    principal: "*".into(),
                    action: "join".into(),
                    resource: "tier:device".into(),
                    until: None,
                    reason: "a peer holding a hardware key may join the overlay to carry readings".into(),
                },
                Policy {
                    effect: Effect::Allow,
                    principal: "*".into(),
                    action: "join".into(),
                    resource: "tier:platform".into(),
                    until: None,
                    reason: "a peer holding a secret it can prove may join the overlay".into(),
                },
                Policy {
                    effect: Effect::Allow,
                    principal: "*".into(),
                    action: "join".into(),
                    resource: "tier:attested".into(),
                    until: None,
                    reason: "a peer whose boot chain was measured may join the overlay".into(),
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_786_838_400;

    #[test]
    fn a_rule_naming_a_role_covers_whoever_holds_it() {
        let p = PolicySet {
            policies: vec![Policy {
                effect: Effect::Allow,
                principal: "role:oncall".into(),
                action: "restart".into(),
                resource: "*".into(),
                until: None,
                reason: "whoever is carrying the pager may put things back".into(),
            }],
        };
        // Two different people, same job, same permission — which is the point:
        // admitting a colleague must not mean editing every rule.
        assert!(p.evaluate(&req_with_roles("person:ana", "restart", "workload:x", &["oncall"]), 0).allowed);
        assert!(p.evaluate(&req_with_roles("person:bo", "restart", "workload:x", &["oncall"]), 0).allowed);
        // Same person, not holding the role.
        assert!(!p.evaluate(&req_with_roles("person:ana", "restart", "workload:x", &["billing"]), 0).allowed);
        // Nobody holds anything.
        assert!(!p.evaluate(&req("person:ana", "restart", "workload:x"), 0).allowed);
    }

    #[test]
    fn a_rule_naming_a_person_is_never_matched_by_a_role() {
        // Roles widen who a rule covers. They must never widen what a named
        // individual can do, or holding a role would silently inherit whatever
        // was written for somebody who happens to share its name.
        let p = PolicySet {
            policies: vec![Policy {
                effect: Effect::Allow,
                principal: "person:ana".into(),
                action: "deploy".into(),
                resource: "*".into(),
                until: None,
                reason: "ana deploys".into(),
            }],
        };
        assert!(p.evaluate(&req("person:ana", "deploy", "site"), 0).allowed);
        assert!(!p
            .evaluate(&req_with_roles("person:bo", "deploy", "site", &["person:ana"]), 0)
            .allowed);
    }

    #[test]
    fn a_deny_on_a_role_beats_an_allow_on_the_person() {
        // The existing deny-wins rule has to hold across the role axis too, or
        // withdrawing a job would be defeated by any individual grant.
        let p = PolicySet {
            policies: vec![
                Policy {
                    effect: Effect::Allow,
                    principal: "person:ana".into(),
                    action: "restart".into(),
                    resource: "*".into(),
                    until: None,
                    reason: "ana restarts".into(),
                },
                Policy {
                    effect: Effect::Deny,
                    principal: "role:suspended".into(),
                    action: "*".into(),
                    resource: "*".into(),
                    until: None,
                    reason: "withdrawn pending review".into(),
                },
            ],
        };
        assert!(p.evaluate(&req("person:ana", "restart", "workload:x"), 0).allowed);
        assert!(!p
            .evaluate(&req_with_roles("person:ana", "restart", "workload:x", &["suspended"]), 0)
            .allowed);
    }

    fn req_with_roles(principal: &str, action: &str, resource: &str, roles: &[&str]) -> Request {
        Request {
            roles: roles.iter().map(|s| s.to_string()).collect(),
            ..req(principal, action, resource)
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
    fn the_default_overlay_rules_admit_by_tier_and_not_by_name() {
        // Naming nodes here would mean editing policy every time one joined.
        let set = PolicySet::compiled_default();
        assert!(set.evaluate(&req("peer:anything", "join", "tier:platform"), NOW).allowed);
        assert!(set.evaluate(&req("peer:other", "join", "tier:attested"), NOW).allowed);
        assert!(set.evaluate(&req("peer:pi", "join", "tier:device"), NOW).allowed);
    }

    #[test]
    fn a_soft_identity_is_refused_by_the_default_rather_than_by_a_deny() {
        // The correct expression: a board identified only by a chip serial has
        // not earned a place, and nobody decided to exclude it. A deny rule
        // would say the opposite and would be one edit from being removed.
        let set = PolicySet::compiled_default();
        let d = set.evaluate(&req("peer:pi", "join", "tier:soft"), NOW);
        assert!(!d.allowed);
        assert!(!d.structural, "this is deny-by-default, not an invariant");
        assert!(
            !set.policies.iter().any(|p| p.effect == Effect::Deny && p.action == "join"),
            "no explicit deny should exist for join"
        );
    }

    #[test]
    fn an_unwritten_rule_refuses() {
        // The property that makes an incomplete policy file safe: the failure
        // mode is a system that does less than intended, not more.
        let d = PolicySet::default().evaluate(&req("loop", "tune", "node:node-a"), NOW);
        assert!(!d.allowed);
        assert!(d.because.contains("no rule permits"));
    }

    #[test]
    fn the_invariants_survive_an_explicit_allow() {
        // The whole reason they are not policy. Somebody writing this rule,
        // by accident or otherwise, must not get what they asked for.
        let set = PolicySet {
            policies: vec![Policy {
                effect: Effect::Allow,
                principal: "*".into(),
                action: "halt".into(),
                resource: "*".into(),
                until: None,
                reason: "let anyone halt anything".into(),
            }],
        };
        let d = set.evaluate(&req("network", "halt", "node:node-a"), NOW);
        assert!(!d.allowed);
        assert!(d.structural, "and it is reported as structural, not policy");
    }

    #[test]
    fn a_structural_denial_is_distinguishable_from_a_policy_one() {
        // Telling somebody to adjust the policy would send them looking for a
        // file that cannot help them.
        let set = PolicySet::compiled_default();
        assert!(set.evaluate(&req("network", "halt", "site"), NOW).structural);
        assert!(!set.evaluate(&req("network", "tune", "site"), NOW).structural);
    }

    #[test]
    fn deny_beats_allow_however_they_are_ordered() {
        // So a narrowing rule cannot be defeated by adding a broader permit
        // beneath it — which is what would happen with first-match wins.
        let narrow = Policy {
            effect: Effect::Deny,
            principal: "loop".into(),
            action: "suspend".into(),
            resource: "node:node-b".into(),
            until: None,
            reason: "node-b carries the controller".into(),
        };
        let broad = Policy {
            effect: Effect::Allow,
            principal: "loop".into(),
            action: "suspend".into(),
            resource: "*".into(),
            until: None,
            reason: "consolidation".into(),
        };
        for order in [vec![narrow.clone(), broad.clone()], vec![broad, narrow]] {
            let set = PolicySet { policies: order };
            assert!(!set.evaluate(&req("loop", "suspend", "node:node-b"), NOW).allowed);
            assert!(set.evaluate(&req("loop", "suspend", "node:node-a"), NOW).allowed);
        }
    }

    #[test]
    fn a_temporary_permission_expires_on_its_own() {
        // Expressible as a temporary permission rather than as a note in a
        // ticket saying to remove it later.
        let set = PolicySet {
            policies: vec![Policy {
                effect: Effect::Allow,
                principal: "network".into(),
                action: "drain".into(),
                resource: "node:node-a".into(),
                until: Some(NOW + 3600),
                reason: "maintenance window".into(),
            }],
        };
        assert!(set.evaluate(&req("network", "drain", "node:node-a"), NOW).allowed);
        assert!(!set.evaluate(&req("network", "drain", "node:node-a"), NOW + 7200).allowed);
    }

    #[test]
    fn the_wildcard_matches_a_whole_field_and_not_part_of_one() {
        // A rule that reads differently to two people is worse than one that
        // cannot express the case.
        let set = PolicySet {
            policies: vec![Policy {
                effect: Effect::Allow,
                principal: "loop".into(),
                action: "tune".into(),
                resource: "node:node-a".into(),
                until: None,
                reason: "one node".into(),
            }],
        };
        assert!(set.evaluate(&req("loop", "tune", "node:node-a"), NOW).allowed);
        assert!(!set.evaluate(&req("loop", "tune", "node:node-a0"), NOW).allowed);
        assert!(!set.evaluate(&req("loop", "tune", "node"), NOW).allowed);
    }

    #[test]
    fn the_default_set_reproduces_what_was_compiled_in() {
        // Adopting the engine must change nothing about what is permitted
        // until somebody deliberately writes a file.
        let set = PolicySet::compiled_default();
        for a in ["tune", "suspend", "resume", "hold", "escalate"] {
            assert!(set.evaluate(&req("loop", a, "site"), NOW).allowed, "loop {a}");
        }
        for a in ["drain", "report_capacity", "attest", "publish_site_root"] {
            assert!(set.evaluate(&req("network", a, "site"), NOW).allowed, "network {a}");
        }
        // And nothing beyond those.
        assert!(!set.evaluate(&req("loop", "drain", "site"), NOW).allowed);
        assert!(!set.evaluate(&req("network", "suspend", "site"), NOW).allowed);
    }

    #[test]
    fn even_the_operator_cannot_reach_an_invariant_through_policy() {
        // The signed-order path is deliberately not this engine. An operator
        // with the sealed key can still halt a machine; what is refused is
        // reaching it through configuration.
        let set = PolicySet::compiled_default();
        let d = set.evaluate(&req("operator", "halt", "node:node-a"), NOW);
        assert!(!d.allowed);
        assert!(d.because.contains("physically present operator"));
    }

    #[test]
    fn a_policy_file_round_trips_through_yaml() {
        let set = PolicySet::compiled_default();
        let back = PolicySet::parse(&set.to_yaml().unwrap()).unwrap();
        assert_eq!(back.policies.len(), set.policies.len());
        assert_eq!(back.policies[0], set.policies[0]);
    }

    #[test]
    fn the_same_parser_accepts_json() {
        // A file a machine wrote and a file a person edited go through exactly
        // the same path, so neither format gets a second implementation that
        // is subtly different.
        let set = PolicySet::compiled_default();
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(PolicySet::parse(&json).unwrap().policies.len(), set.policies.len());
    }

    #[test]
    fn a_hand_written_yaml_policy_parses() {
        let yaml = r#"
policies:
  # Maintenance on node-a this afternoon only.
  - effect: allow
    principal: network
    action: drain
    resource: node:node-a
    until: 1786924800
    reason: scheduled maintenance window
  # node-b carries the controller and is never a consolidation candidate.
  - effect: deny
    principal: loop
    action: suspend
    resource: node:node-b
    until: null
    reason: it carries the site controller
"#;
        let set = PolicySet::parse(yaml).unwrap();
        assert_eq!(set.policies.len(), 2);
        assert_eq!(set.policies[0].effect, Effect::Allow);
        assert_eq!(set.policies[1].effect, Effect::Deny);
        assert!(set.policies[0].until.is_some());
    }

    #[test]
    fn a_malformed_file_is_refused_rather_than_partially_applied() {
        // Half a policy file is more dangerous than none: it would silently
        // drop whichever rules failed to parse, and the dropped ones are as
        // likely to be denies as allows.
        assert!(PolicySet::parse("policies: [ this is not a rule").is_err());
        assert!(PolicySet::parse("policies:
  - effect: maybe").is_err());
    }
}
