//! When an item goes to the next rung.
//!
//! The small processing node answers what it can and passes on what it cannot
//! stand behind. [`EscalationPolicy`] makes that decision for one processed
//! item. [`MarginPolicy`] is the default:
//!
//! 1. escalate when the model's margin is below a threshold, because the
//!    nearest label is not clearly nearer than the next;
//! 2. escalate every `audit_every`-th item whatever the margin, so the next rung
//!    keeps seeing a sample of what the small node was confident about and a
//!    drifting model shows up there.
//!
//! The audit sample is a fixed interval, not a random draw, and the threshold
//! is a constant the operator sets, not a calibrated bound. A gate that learns
//! its threshold from the next rung's answers, with a stated guarantee on
//! disagreement, is a documented later step; this trait is where it plugs in.

use super::model::Inference;
use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationReason {
    LowMargin,
    Audit,
    /// No model, or the model could not answer.
    NoAnswer,
    /// Passed up unprocessed because the node is configured to relay readings.
    Relay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Keep,
    Escalate(EscalationReason),
}

pub struct EscalationContext<'a> {
    pub inference: Option<&'a Inference>,
    /// The lowest class of any rung the item passed.
    pub effective: AssuranceClass,
}

pub trait EscalationPolicy: Send {
    fn decide(&mut self, ctx: &EscalationContext) -> Decision;
}

#[derive(Clone, Debug)]
pub struct MarginPolicy {
    pub threshold: f64,
    /// 0 turns the audit sample off.
    pub audit_every: u64,
    seen: u64,
}

impl Default for MarginPolicy {
    fn default() -> Self {
        Self { threshold: 0.2, audit_every: 50, seen: 0 }
    }
}

impl MarginPolicy {
    pub fn new(threshold: f64, audit_every: u64) -> Self {
        Self { threshold, audit_every, seen: 0 }
    }
}

impl EscalationPolicy for MarginPolicy {
    fn decide(&mut self, ctx: &EscalationContext) -> Decision {
        self.seen += 1;
        let Some(inf) = ctx.inference else { return Decision::Escalate(EscalationReason::NoAnswer) };
        if inf.margin.is_nan() || inf.margin < self.threshold {
            return Decision::Escalate(EscalationReason::LowMargin);
        }
        if self.audit_every > 0 && self.seen.is_multiple_of(self.audit_every) {
            return Decision::Escalate(EscalationReason::Audit);
        }
        Decision::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nicla::ModelRef;

    fn inf(margin: f64) -> Inference {
        Inference { label: "x".into(), margin, model: ModelRef { id: "m".into(), sha256: "0".repeat(64) } }
    }

    fn ctx(i: Option<&Inference>) -> EscalationContext<'_> {
        EscalationContext { inference: i, effective: AssuranceClass::Soft }
    }

    #[test]
    fn low_margin_and_no_answer_escalate_and_a_clear_answer_stays() {
        let mut p = MarginPolicy::new(0.2, 0);
        assert_eq!(p.decide(&ctx(Some(&inf(0.1)))), Decision::Escalate(EscalationReason::LowMargin));
        assert_eq!(p.decide(&ctx(Some(&inf(f64::NAN)))), Decision::Escalate(EscalationReason::LowMargin));
        assert_eq!(p.decide(&ctx(None)), Decision::Escalate(EscalationReason::NoAnswer));
        assert_eq!(p.decide(&ctx(Some(&inf(0.9)))), Decision::Keep);
    }

    #[test]
    fn every_nth_confident_item_is_audited() {
        let mut p = MarginPolicy::new(0.2, 4);
        let i = inf(0.9);
        let d: Vec<Decision> = (0..8).map(|_| p.decide(&ctx(Some(&i)))).collect();
        assert_eq!(d.iter().filter(|d| **d == Decision::Escalate(EscalationReason::Audit)).count(), 2);
        assert_eq!(d[3], Decision::Escalate(EscalationReason::Audit));
    }
}
