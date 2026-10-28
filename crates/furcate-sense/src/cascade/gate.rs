//! A teacher-labelled conformal escalation gate.
//!
//! The rung above has a larger model. Every item it answers is a label for the
//! item the rung below sent it, so each escalation also measures whether the
//! lower model agreed with the larger one. [`ConformalGate`] uses that to hold
//! one number, a threshold on the lower model's confidence score, at the level
//! where the items **not** escalated agree with the larger model at least
//! `1 - delta` of the time, and to move it when the agreement moves.
//!
//! Two things make this more than a fixed threshold:
//!
//! * a random audit: an item that clears the threshold is still escalated with
//!   probability `audit_rate`, and that sample is unbiased for the kept
//!   population whatever the data does, so the gate keeps measuring what it
//!   would otherwise stop seeing;
//! * a threshold that follows the audit result, in one of two ways. With
//!   [`Mode::Aci`] each audited, kept item moves the threshold by
//!   `step * (error - delta)`, the adaptive conformal update, which needs no
//!   buffer. With [`Mode::Buffer`] the gate keeps the last `size` labelled
//!   items, weights an audited item by `1 / audit_rate` (it stands for the kept
//!   items that were not audited) and an item escalated for a low score by 1,
//!   and every `every` items sets the threshold to the lowest score whose
//!   weighted kept-error, with the conformal `+1` correction, is within `delta`.
//!
//! What is guaranteed and what is not. Neither mode proves the long-run
//! guarantee of conformal prediction, which assumes exchangeable data; windows
//! of one wearer are autocorrelated and drift. `step` and `size` set how fast
//! the gate follows, and a gate that follows fast has a noisier realised error.
//! The guarantee here is empirical, measured in `examples/gate_eval.rs` and in
//! the synthetic-drift tests below, and is stated there with its numbers.
//!
//! The score is any number in `[0, 1]` that is larger when the lower model is
//! more sure. As an [`EscalationPolicy`] the gate reads the model's margin; the
//! agreement of an escalated item is reported with [`ConformalGate::observe`].

use super::escalate::{Decision, EscalationContext, EscalationPolicy, EscalationReason};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    /// Move the threshold by `step * (error - delta)` per audited, kept item.
    Aci { step: f64 },
    /// Recompute the threshold from the last `size` labelled items every `every` items.
    Buffer { size: usize, every: usize },
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GateConfig {
    /// Allowed disagreement among items that are not escalated.
    pub delta: f64,
    /// Probability that an item above the threshold is escalated anyway.
    pub audit_rate: f64,
    pub mode: Mode,
    pub seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateError {
    Delta,
    AuditRate,
    Mode(&'static str),
    NoCalibration,
    BadScore,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::Delta => write!(f, "delta must be in (0, 1)"),
            GateError::AuditRate => write!(f, "audit_rate must be in (0, 1]"),
            GateError::Mode(w) => write!(f, "{w}"),
            GateError::NoCalibration => write!(f, "a gate needs a calibration set"),
            GateError::BadScore => write!(f, "a score must be a number in [0, 1]"),
        }
    }
}

impl std::error::Error for GateError {}

#[derive(Clone, Copy, Debug)]
struct Labelled {
    score: f64,
    error: bool,
    weight: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GateStats {
    pub seen: u64,
    pub escalated_low: u64,
    pub audited: u64,
    pub kept: u64,
}

pub struct ConformalGate {
    cfg: GateConfig,
    tau: f64,
    buffer: VecDeque<Labelled>,
    since: usize,
    rng: u64,
    stats: GateStats,
}

fn valid(score: f64) -> bool {
    (0.0..=1.0).contains(&score)
}

/// The lowest threshold whose weighted kept-error is within `delta`, or above
/// every score when none is. Entries are `(score, error, weight)`.
fn threshold_for(entries: &[Labelled], delta: f64) -> f64 {
    let mut sorted: Vec<&Labelled> = entries.iter().collect();
    sorted.sort_by(|a, b| b.score.total_cmp(&a.score));
    let (mut w, mut e) = (0.0, 0.0);
    let mut best = None;
    let mut i = 0;
    while i < sorted.len() {
        // Take every entry tied at this score together.
        let s = sorted[i].score;
        while i < sorted.len() && sorted[i].score == s {
            w += sorted[i].weight;
            if sorted[i].error {
                e += sorted[i].weight;
            }
            i += 1;
        }
        if (e + 1.0) / (w + 1.0) <= delta {
            best = Some(s);
        }
    }
    // When nothing qualifies, escalate everything except by audit: above 1 so no score clears it.
    best.unwrap_or(1.0 + f64::EPSILON)
}

/// The threshold a frozen gate would use: the lowest score whose kept items
/// disagree with the larger model no more than `delta` of the time, with the
/// conformal `+1` correction. Above 1 when no score qualifies. This is the
/// offline baseline the adaptive gate is measured against.
pub fn calibrate_threshold(calibration: &[(f64, bool)], delta: f64) -> f64 {
    let entries: Vec<Labelled> = calibration.iter().map(|(s, ok)| Labelled { score: *s, error: !ok, weight: 1.0 }).collect();
    threshold_for(&entries, delta)
}

impl ConformalGate {
    /// `calibration` is `(score, agrees)` pairs from data the lower model was
    /// not fitted on.
    pub fn new(cfg: GateConfig, calibration: &[(f64, bool)]) -> Result<Self, GateError> {
        if !(cfg.delta > 0.0 && cfg.delta < 1.0) {
            return Err(GateError::Delta);
        }
        if !(cfg.audit_rate > 0.0 && cfg.audit_rate <= 1.0) {
            return Err(GateError::AuditRate);
        }
        match cfg.mode {
            Mode::Aci { step } if !(step.is_finite() && step > 0.0) => return Err(GateError::Mode("step must be positive")),
            Mode::Buffer { size, every } if size == 0 || every == 0 => {
                return Err(GateError::Mode("size and every must be positive"))
            }
            _ => {}
        }
        if calibration.is_empty() {
            return Err(GateError::NoCalibration);
        }
        if calibration.iter().any(|(s, _)| !valid(*s)) {
            return Err(GateError::BadScore);
        }
        let entries: Vec<Labelled> =
            calibration.iter().map(|(s, ok)| Labelled { score: *s, error: !ok, weight: 1.0 }).collect();
        let tau = threshold_for(&entries, cfg.delta);
        let mut buffer: VecDeque<Labelled> = entries.into();
        if let Mode::Buffer { size, .. } = cfg.mode {
            while buffer.len() > size {
                buffer.pop_front();
            }
        } else {
            buffer.clear();
        }
        Ok(Self { cfg, tau, buffer, since: 0, rng: cfg.seed | 1, stats: GateStats::default() })
    }

    pub fn threshold(&self) -> f64 {
        self.tau
    }

    pub fn stats(&self) -> GateStats {
        self.stats
    }

    fn uniform(&mut self) -> f64 {
        // xorshift64*; the gate's own stream so a run is repeatable from its seed.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        let x = self.rng.wrapping_mul(0x2545F4914F6CDD1D);
        (x >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Whether to escalate an item with this score. A score that is not a
    /// number in `[0, 1]` is escalated.
    pub fn decide(&mut self, score: f64) -> Decision {
        self.stats.seen += 1;
        if !valid(score) || score < self.tau {
            self.stats.escalated_low += 1;
            return Decision::Escalate(EscalationReason::LowMargin);
        }
        if self.uniform() < self.cfg.audit_rate {
            self.stats.audited += 1;
            return Decision::Escalate(EscalationReason::Audit);
        }
        self.stats.kept += 1;
        Decision::Keep
    }

    /// Report whether the lower model agreed with the rung above for an item
    /// that was escalated for `reason`.
    pub fn observe(&mut self, reason: EscalationReason, score: f64, agrees: bool) {
        if !valid(score) {
            return;
        }
        let audit = reason == EscalationReason::Audit;
        match self.cfg.mode {
            Mode::Aci { step } => {
                if audit {
                    let err = if agrees { 0.0 } else { 1.0 };
                    self.tau = (self.tau + step * (err - self.cfg.delta)).clamp(0.0, 1.0 + f64::EPSILON);
                }
            }
            Mode::Buffer { size, every } => {
                let weight = if audit { 1.0 / self.cfg.audit_rate } else { 1.0 };
                self.buffer.push_back(Labelled { score, error: !agrees, weight });
                if self.buffer.len() > size {
                    self.buffer.pop_front();
                }
                self.since += 1;
                if self.since >= every {
                    self.since = 0;
                    let entries: Vec<Labelled> = self.buffer.iter().copied().collect();
                    self.tau = threshold_for(&entries, self.cfg.delta);
                }
            }
        }
    }
}

/// The gate as the small node's policy: it reads the model's margin as the score.
impl EscalationPolicy for ConformalGate {
    fn decide(&mut self, ctx: &EscalationContext) -> Decision {
        match ctx.inference {
            None => {
                self.stats.seen += 1;
                Decision::Escalate(EscalationReason::NoAnswer)
            }
            Some(i) => ConformalGate::decide(self, i.margin),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn u(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    /// Items with score uniform on [0,1]; the lower model is wrong with
    /// probability `base * (1 - score)^power`.
    fn item(r: &mut Rng, base: f64, power: f64) -> (f64, bool) {
        let s = r.u();
        (s, r.u() >= base * (1.0 - s).powf(power))
    }

    fn calibration(n: usize, base: f64, power: f64) -> Vec<(f64, bool)> {
        let mut r = Rng(0x1234_5678_9ABC_DEF1);
        (0..n).map(|_| item(&mut r, base, power)).collect()
    }

    const DELTA: f64 = 0.05;

    struct Run {
        kept_err_pre: f64,
        kept_err_post: f64,
        esc_pre: f64,
        esc_post: f64,
    }

    /// Stream `n` items before and `n` after a drift in how the lower model errs.
    /// `gate` is None for a frozen threshold.
    fn stream(mode: Option<Mode>, seed: u64, n: usize) -> Run {
        stream_with(mode, seed, n, 0.1)
    }

    fn stream_with(mode: Option<Mode>, seed: u64, n: usize, audit: f64) -> Run {
        let cfg = GateConfig { delta: DELTA, audit_rate: audit, mode: mode.unwrap_or(Mode::Aci { step: 0.01 }), seed };
        let mut g = ConformalGate::new(cfg, &calibration(2000, 0.5, 3.0)).unwrap();
        let frozen = g.threshold();
        let mut r = Rng(seed ^ 0xDEAD_BEEF_CAFE_F00D);
        let (mut kept, mut kept_err, mut esc) = ([0usize; 2], [0usize; 2], [0usize; 2]);
        for phase in 0..2 {
            // After the drift the lower model errs much more at every score.
            let (base, power) = if phase == 0 { (0.5, 3.0) } else { (0.5, 1.0) };
            for t in 0..n {
                let (s, ok) = item(&mut r, base, power);
                let d = if mode.is_some() {
                    g.decide(s)
                } else if s < frozen {
                    Decision::Escalate(EscalationReason::LowMargin)
                } else {
                    Decision::Keep
                };
                match d {
                    Decision::Keep => {
                        // Skip the settling period when counting after the drift.
                        if phase == 0 || t >= n / 4 {
                            kept[phase] += 1;
                            kept_err[phase] += (!ok) as usize;
                        }
                    }
                    Decision::Escalate(reason) => {
                        if phase == 0 || t >= n / 4 {
                            esc[phase] += 1;
                        }
                        if mode.is_some() {
                            g.observe(reason, s, ok);
                        }
                    }
                }
            }
        }
        let m = |p: usize| (n - if p == 1 { n / 4 } else { 0 }) as f64;
        Run {
            kept_err_pre: kept_err[0] as f64 / kept[0].max(1) as f64,
            kept_err_post: kept_err[1] as f64 / kept[1].max(1) as f64,
            esc_pre: esc[0] as f64 / m(0),
            esc_post: esc[1] as f64 / m(1),
        }
    }

    fn mean(runs: &[Run], f: impl Fn(&Run) -> f64) -> f64 {
        runs.iter().map(f).sum::<f64>() / runs.len() as f64
    }

    #[test]
    fn a_frozen_threshold_breaks_after_the_drift_and_the_adaptive_gates_hold_it() {
        let n = 20_000;
        let frozen: Vec<Run> = (1..=5).map(|s| stream(None, s, n)).collect();
        let aci: Vec<Run> = (1..=5).map(|s| stream(Some(Mode::Aci { step: 0.05 }), s, n)).collect();
        let buf: Vec<Run> = (1..=5).map(|s| stream(Some(Mode::Buffer { size: 3000, every: 50 }), s, n)).collect();

        // Before the drift all three keep to the target (within sampling noise).
        for (name, runs) in [("frozen", &frozen), ("aci", &aci), ("buffer", &buf)] {
            let pre = mean(runs, |r| r.kept_err_pre);
            assert!(pre <= DELTA + 0.012, "{name} before the drift: {pre}");
        }
        // After it, the frozen threshold keeps far more errors than allowed.
        let post_frozen = mean(&frozen, |r| r.kept_err_post);
        assert!(post_frozen > 2.0 * DELTA, "frozen after the drift: {post_frozen}");
        // The adaptive gates are back within a small margin of the target, by escalating more.
        for (name, runs) in [("aci", &aci), ("buffer", &buf)] {
            let post = mean(runs, |r| r.kept_err_post);
            assert!(post <= DELTA + 0.02, "{name} after the drift: {post}");
            assert!(mean(runs, |r| r.esc_post) > mean(runs, |r| r.esc_pre), "{name} did not escalate more");
        }
        println!(
            "synthetic drift, delta {DELTA}: kept-error pre/post  frozen {:.3}/{:.3}  aci {:.3}/{:.3}  buffer {:.3}/{:.3}; escalation post  frozen {:.3}  aci {:.3}  buffer {:.3}",
            mean(&frozen, |r| r.kept_err_pre), post_frozen,
            mean(&aci, |r| r.kept_err_pre), mean(&aci, |r| r.kept_err_post),
            mean(&buf, |r| r.kept_err_pre), mean(&buf, |r| r.kept_err_post),
            mean(&frozen, |r| r.esc_post), mean(&aci, |r| r.esc_post), mean(&buf, |r| r.esc_post),
        );
    }

    #[test]
    fn the_calibration_threshold_is_the_lowest_score_within_delta() {
        // Errors only below 0.5: the gate may keep everything from 0.5 up.
        let cal: Vec<(f64, bool)> = (0..1000).map(|i| (i as f64 / 1000.0, i >= 500)).collect();
        let cfg = GateConfig { delta: 0.05, audit_rate: 0.1, mode: Mode::Aci { step: 0.01 }, seed: 1 };
        let g = ConformalGate::new(cfg, &cal).unwrap();
        assert!(g.threshold() >= 0.5 - 0.06 && g.threshold() <= 0.55, "{}", g.threshold());
        // A model that is always wrong is never kept.
        let bad: Vec<(f64, bool)> = (0..100).map(|i| (i as f64 / 100.0, false)).collect();
        assert!(ConformalGate::new(cfg, &bad).unwrap().threshold() > 1.0);
    }

    #[test]
    fn audits_escalate_a_share_of_what_would_be_kept_and_a_bad_score_is_always_escalated() {
        let cal = calibration(500, 0.5, 3.0);
        let cfg = GateConfig { delta: 0.05, audit_rate: 0.2, mode: Mode::Aci { step: 0.001 }, seed: 9 };
        let mut g = ConformalGate::new(cfg, &cal).unwrap();
        let (mut audits, mut kept) = (0, 0);
        for _ in 0..10_000 {
            match g.decide(1.0) {
                Decision::Escalate(EscalationReason::Audit) => audits += 1,
                Decision::Keep => kept += 1,
                other => panic!("{other:?}"),
            }
        }
        let share = audits as f64 / (audits + kept) as f64;
        assert!((share - 0.2).abs() < 0.02, "{share}");
        assert_eq!(g.decide(f64::NAN), Decision::Escalate(EscalationReason::LowMargin));
        assert_eq!(g.decide(1.5), Decision::Escalate(EscalationReason::LowMargin));
        // A bad score cannot move the threshold.
        let t = g.threshold();
        g.observe(EscalationReason::Audit, f64::NAN, false);
        assert_eq!(g.threshold(), t);
    }

    #[test]
    fn a_run_is_repeatable_from_its_seed() {
        let a = stream(Some(Mode::Aci { step: 0.01 }), 3, 2000);
        let b = stream(Some(Mode::Aci { step: 0.01 }), 3, 2000);
        assert_eq!((a.kept_err_post, a.esc_post), (b.kept_err_post, b.esc_post));
    }

    #[test]
    fn bad_configuration_is_an_error() {
        let cal = [(0.5, true)];
        let ok = GateConfig { delta: 0.05, audit_rate: 0.1, mode: Mode::Aci { step: 0.01 }, seed: 1 };
        assert!(ConformalGate::new(ok, &cal).is_ok());
        assert_eq!(ConformalGate::new(GateConfig { delta: 0.0, ..ok }, &cal).err(), Some(GateError::Delta));
        assert_eq!(ConformalGate::new(GateConfig { audit_rate: 0.0, ..ok }, &cal).err(), Some(GateError::AuditRate));
        assert!(ConformalGate::new(GateConfig { mode: Mode::Aci { step: 0.0 }, ..ok }, &cal).is_err());
        assert!(ConformalGate::new(GateConfig { mode: Mode::Buffer { size: 0, every: 1 }, ..ok }, &cal).is_err());
        assert_eq!(ConformalGate::new(ok, &[]).err(), Some(GateError::NoCalibration));
        assert_eq!(ConformalGate::new(ok, &[(2.0, true)]).err(), Some(GateError::BadScore));
    }

    #[test]
    fn as_a_policy_it_reads_the_margin_and_escalates_when_there_is_no_answer() {
        use super::super::model::Inference;
        use crate::nicla::ModelRef;
        use furcate_identity::AssuranceClass;
        let cfg = GateConfig { delta: 0.05, audit_rate: 0.001, mode: Mode::Aci { step: 0.01 }, seed: 5 };
        let cal: Vec<(f64, bool)> = (0..1000).map(|i| (i as f64 / 1000.0, i >= 500)).collect();
        let mut g = ConformalGate::new(cfg, &cal).unwrap();
        let inf = |margin| Inference { label: "x".into(), margin, model: ModelRef { id: "m".into(), sha256: "0".repeat(64) } };
        fn ctx(i: Option<&Inference>) -> EscalationContext<'_> {
            EscalationContext { inference: i, effective: AssuranceClass::Soft }
        }
        let (low, high) = (inf(0.1), inf(0.95));
        assert_eq!(EscalationPolicy::decide(&mut g, &ctx(Some(&low))), Decision::Escalate(EscalationReason::LowMargin));
        assert_eq!(EscalationPolicy::decide(&mut g, &ctx(Some(&high))), Decision::Keep);
        assert_eq!(EscalationPolicy::decide(&mut g, &ctx(None)), Decision::Escalate(EscalationReason::NoAnswer));
    }
}
