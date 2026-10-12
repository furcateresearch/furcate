//! Machines that compute the wrong answer without saying so.
//!
//! Every other fault in this codebase announces itself. A disk reports
//! reallocated sectors, a card emits an Xid, a link drops, a process exits
//! non-zero. Silent data corruption is the one that does not: the machine stays
//! up, the job completes, the exit status is zero, and the number is wrong.
//! At fleet scale it is not rare — the published surveys from operators large
//! enough to have looked put it near one machine in a thousand, concentrated in
//! specific cores and specific instruction mixes, and stable enough per machine
//! to be found by testing.
//!
//! It matters more here than the incident count suggests, because a corrupt
//! machine poisons everything downstream of it and nothing marks the poison. A
//! failed node loses the work it was doing; a lying node loses confidence in
//! all the work it contributed to, including the work that already finished.
//!
//! ## What can be concluded from a disagreement
//!
//! This module exists mostly to be careful about one thing, because getting it
//! wrong is how a corruption detector becomes a machine-eating loop:
//!
//! | replicas | a mismatch tells you |
//! |---|---|
//! | 2 | they disagree. Not which is wrong. |
//! | 3+ | the minority is suspect, if there is a majority |
//! | 3+ and no majority | something is wrong with the comparison itself |
//!
//! Two replicas are the common case and the trap. It is genuinely tempting to
//! blame the one that looks unusual, and there is no basis for it whatsoever —
//! [`Finding::Disagreement`] carries both names and accuses neither.
//!
//! ## A mismatch is not automatically a hardware fault
//!
//! The other way this goes wrong. Non-deterministic work disagrees between
//! replicas *by construction*: a different reduction order, an atomic that
//! landed differently, an unseeded shuffle, a timestamp in the output. A
//! detector that treats every mismatch as silicon will condemn a healthy fleet
//! running one sloppy job.
//!
//! The distinguishing evidence is not in any single comparison. It is in the
//! shape of many: a corrupt *machine* is the odd one out across unrelated
//! pieces of work, while non-deterministic *work* produces disagreements that
//! move around the fleet with no participant over-represented. [`Ledger`]
//! accumulates comparisons precisely to tell those apart, and it will say
//! [`Verdict::WorkLooksNonDeterministic`] rather than blame a machine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What one participant computed, reduced to something comparable.
///
/// A digest rather than the result itself: this has to travel, results do not,
/// and the only question asked of it is equality. How it is produced is the
/// caller's business, with one requirement — it must cover everything that
/// ought to match and nothing that is allowed to differ. A digest taken over a
/// buffer that includes a timestamp will report the whole fleet as corrupt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replica {
    pub participant: String,
    pub digest: String,
}

impl Replica {
    pub fn new(participant: impl Into<String>, digest: impl Into<String>) -> Self {
        Replica {
            participant: participant.into(),
            digest: digest.into(),
        }
    }
}

/// What one comparison of replicated work supports concluding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// Every replica agreed.
    ///
    /// Worth stating rather than implying: agreement across replicas is the
    /// only positive evidence this module ever produces, and it is what makes
    /// a later disagreement meaningful.
    Agreed { replicas: usize },
    /// Exactly two replicas, and they differ.
    ///
    /// Both names are carried and neither is accused, because there is no
    /// information here about which one is wrong. Resolving it needs a third
    /// opinion, and asking for one is the correct response.
    Disagreement { participants: Vec<String> },
    /// A majority agreed and a minority did not. The minority is suspect.
    Outlier {
        /// The participants outside the majority.
        suspects: Vec<String>,
        /// How many agreed on the majority answer.
        majority: usize,
        /// How many replicas took part.
        replicas: usize,
    },
    /// Three or more replicas and no majority for any answer.
    ///
    /// Almost never silicon. Several machines independently producing several
    /// different answers points at the work being non-deterministic or at the
    /// digest covering something it should not — and treating it as corruption
    /// would condemn most of the group at once.
    NoMajority { replicas: usize, distinct: usize },
    /// Fewer than two replicas. Nothing to compare, so nothing is claimed.
    NotComparable,
}

impl Finding {
    /// Whether this comparison implicates any specific participant.
    pub fn accuses_anyone(&self) -> bool {
        matches!(self, Finding::Outlier { .. })
    }

    /// Whether a human should be told about this comparison at all.
    ///
    /// Agreement and an uncomparable singleton are not events. Everything else
    /// is, including [`Finding::Disagreement`], which accuses nobody and still
    /// means two machines computed different answers to the same question.
    pub fn is_notable(&self) -> bool {
        !matches!(self, Finding::Agreed { .. } | Finding::NotComparable)
    }

    /// The participants this comparison puts under suspicion, if any.
    pub fn suspects(&self) -> &[String] {
        match self {
            Finding::Outlier { suspects, .. } => suspects,
            _ => &[],
        }
    }
}

/// Compare replicated work.
///
/// Attribution requires a strict majority — with four replicas split two-two
/// there is no majority and no suspect, which is [`Finding::NoMajority`] rather
/// than a guess at which pair is right.
pub fn compare(replicas: &[Replica]) -> Finding {
    if replicas.len() < 2 {
        return Finding::NotComparable;
    }

    let mut counts: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for r in replicas {
        counts
            .entry(r.digest.as_str())
            .or_default()
            .push(r.participant.as_str());
    }

    if counts.len() == 1 {
        return Finding::Agreed {
            replicas: replicas.len(),
        };
    }

    // Two replicas that differ. The trap this module exists for.
    if replicas.len() == 2 {
        let mut participants: Vec<String> =
            replicas.iter().map(|r| r.participant.clone()).collect();
        participants.sort();
        return Finding::Disagreement { participants };
    }

    let (_, winners) = counts
        .iter()
        .max_by_key(|(_, who)| who.len())
        .expect("at least one digest");
    let majority = winners.len();

    // Strict majority: more than half. Exactly half is not a majority, and
    // treating it as one is how a two-two split condemns two healthy machines.
    if majority * 2 <= replicas.len() {
        return Finding::NoMajority {
            replicas: replicas.len(),
            distinct: counts.len(),
        };
    }

    let winning: Vec<&str> = winners.clone();
    let mut suspects: Vec<String> = replicas
        .iter()
        .filter(|r| !winning.contains(&r.participant.as_str()))
        .map(|r| r.participant.clone())
        .collect();
    suspects.sort();

    Finding::Outlier {
        suspects,
        majority,
        replicas: replicas.len(),
    }
}

/// What the accumulated evidence says about a participant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Not enough disagreements anywhere to say anything.
    Quiet,
    /// One participant is the odd one out far more often than its share.
    ///
    /// The conclusion this module is for. A machine that disagrees with the
    /// majority across unrelated pieces of work is the machine, not the work.
    SuspectMachine {
        participant: String,
        /// Comparisons where this participant was the outlier.
        implicated: usize,
        /// Comparisons it took part in.
        took_part: usize,
    },
    /// Disagreements are spread across participants with none over-represented.
    ///
    /// The signature of non-deterministic work rather than bad silicon. Naming
    /// a machine here would condemn a healthy fleet for one sloppy job.
    WorkLooksNonDeterministic {
        disagreements: usize,
        participants: usize,
    },
    /// Disagreements are happening and cannot yet be attributed either way.
    Inconclusive { disagreements: usize },
}

/// Comparisons below which no verdict is offered.
///
/// Attribution is a claim about a *rate*, and a rate over two observations is
/// not a rate. A machine wrongly named here is a machine pulled from service,
/// so this is deliberately slow to speak.
pub const MIN_COMPARISONS: usize = 8;

/// The share of its own comparisons a participant must be the outlier in before
/// it is named.
///
/// Well above what chance produces. In a group of three, an innocent
/// participant caught by non-deterministic work lands in the minority about a
/// third of the time; this bar is twice that, so a machine reaches it by being
/// genuinely and repeatedly wrong rather than unlucky.
pub const IMPLICATION_SHARE: f64 = 0.6;

/// Accumulates comparisons so a machine can be told apart from a job.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    took_part: BTreeMap<String, usize>,
    implicated: BTreeMap<String, usize>,
    comparisons: usize,
    disagreements: usize,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one comparison and the replicas that took part in it.
    pub fn observe(&mut self, replicas: &[Replica], finding: &Finding) {
        if matches!(finding, Finding::NotComparable) {
            return;
        }
        self.comparisons += 1;
        for r in replicas {
            *self.took_part.entry(r.participant.clone()).or_default() += 1;
        }
        if finding.is_notable() {
            self.disagreements += 1;
        }
        for s in finding.suspects() {
            *self.implicated.entry(s.clone()).or_default() += 1;
        }
    }

    pub fn comparisons(&self) -> usize {
        self.comparisons
    }

    /// What the accumulated evidence supports.
    pub fn verdict(&self) -> Verdict {
        if self.comparisons < MIN_COMPARISONS {
            return Verdict::Inconclusive {
                disagreements: self.disagreements,
            };
        }
        if self.disagreements == 0 {
            return Verdict::Quiet;
        }

        let worst = self
            .implicated
            .iter()
            .filter_map(|(name, &count)| {
                let took_part = *self.took_part.get(name)?;
                if took_part == 0 {
                    return None;
                }
                Some((name, count, took_part, count as f64 / took_part as f64))
            })
            .max_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));

        match worst {
            Some((name, implicated, took_part, share)) if share >= IMPLICATION_SHARE => {
                Verdict::SuspectMachine {
                    participant: name.clone(),
                    implicated,
                    took_part,
                }
            }
            // Disagreements are happening, and no participant owns them. That
            // is what non-determinism looks like from here, and it is a
            // question for whoever wrote the job.
            _ if self.implicated.len() > 1 => Verdict::WorkLooksNonDeterministic {
                disagreements: self.disagreements,
                participants: self.implicated.len(),
            },
            _ => Verdict::Inconclusive {
                disagreements: self.disagreements,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(p: &str, d: &str) -> Replica {
        Replica::new(p, d)
    }

    #[test]
    fn agreement_is_stated_rather_than_implied() {
        let f = compare(&[r("a", "x"), r("b", "x"), r("c", "x")]);
        assert_eq!(f, Finding::Agreed { replicas: 3 });
        assert!(!f.is_notable());
        assert!(f.suspects().is_empty());
    }

    #[test]
    fn two_replicas_that_differ_accuse_neither() {
        // The trap. There is no information about which of two is wrong, and
        // blaming the odd-looking one is how a detector eats healthy machines.
        let f = compare(&[r("a", "x"), r("b", "y")]);
        match &f {
            Finding::Disagreement { participants } => {
                assert_eq!(participants, &["a".to_string(), "b".to_string()]);
            }
            other => panic!("expected a disagreement, got {other:?}"),
        }
        assert!(!f.accuses_anyone(), "two replicas cannot attribute");
        assert!(f.is_notable(), "and it must still be reported");
        assert!(f.suspects().is_empty());
    }

    #[test]
    fn a_majority_puts_the_minority_under_suspicion() {
        let f = compare(&[r("a", "x"), r("b", "x"), r("c", "y")]);
        assert_eq!(
            f,
            Finding::Outlier {
                suspects: vec!["c".to_string()],
                majority: 2,
                replicas: 3,
            }
        );
        assert!(f.accuses_anyone());
    }

    #[test]
    fn an_even_split_is_not_a_majority() {
        // Two against two. Calling either pair the majority would condemn two
        // healthy machines on a coin flip.
        let f = compare(&[r("a", "x"), r("b", "x"), r("c", "y"), r("d", "y")]);
        assert_eq!(
            f,
            Finding::NoMajority {
                replicas: 4,
                distinct: 2
            }
        );
        assert!(!f.accuses_anyone());
        assert!(f.is_notable());
    }

    #[test]
    fn everyone_disagreeing_is_not_everyone_being_broken() {
        // Three machines, three answers. Far more likely the work is
        // non-deterministic than that all three silicon failed at once.
        let f = compare(&[r("a", "x"), r("b", "y"), r("c", "z")]);
        assert_eq!(
            f,
            Finding::NoMajority {
                replicas: 3,
                distinct: 3
            }
        );
        assert!(!f.accuses_anyone());
    }

    #[test]
    fn one_replica_is_not_a_comparison() {
        let f = compare(&[r("a", "x")]);
        assert_eq!(f, Finding::NotComparable);
        assert!(!f.is_notable(), "nothing was asked, so nothing is claimed");
        assert_eq!(compare(&[]), Finding::NotComparable);
    }

    #[test]
    fn a_machine_wrong_across_unrelated_work_is_named() {
        // The conclusion the ledger exists for: same participant, different
        // work each time, consistently the odd one out.
        let mut led = Ledger::new();
        for i in 0..10 {
            let reps = vec![
                r("a", &format!("job{i}")),
                r("b", &format!("job{i}")),
                r("bad", &format!("wrong{i}")),
            ];
            let f = compare(&reps);
            led.observe(&reps, &f);
        }
        match led.verdict() {
            Verdict::SuspectMachine {
                participant,
                implicated,
                took_part,
            } => {
                assert_eq!(participant, "bad");
                assert_eq!(implicated, 10);
                assert_eq!(took_part, 10);
            }
            other => panic!("expected a named machine, got {other:?}"),
        }
    }

    #[test]
    fn disagreements_that_move_around_blame_the_job_not_a_machine() {
        // Non-deterministic work: a different participant is the odd one out
        // each time. Naming a machine here condemns a healthy fleet.
        let mut led = Ledger::new();
        let who = ["a", "b", "c"];
        for i in 0..12 {
            let odd = who[i % 3];
            let reps: Vec<Replica> = who
                .iter()
                .map(|p| {
                    if *p == odd {
                        r(p, &format!("other{i}"))
                    } else {
                        r(p, &format!("job{i}"))
                    }
                })
                .collect();
            let f = compare(&reps);
            led.observe(&reps, &f);
        }
        match led.verdict() {
            Verdict::WorkLooksNonDeterministic { participants, .. } => {
                assert_eq!(participants, 3, "nobody is over-represented");
            }
            other => panic!("expected the job to be blamed, got {other:?}"),
        }
    }

    #[test]
    fn too_few_comparisons_name_nobody() {
        // A rate over two observations is not a rate, and a machine wrongly
        // named is a machine pulled from service.
        let mut led = Ledger::new();
        for i in 0..3 {
            let reps = vec![
                r("a", &format!("job{i}")),
                r("b", &format!("job{i}")),
                r("bad", "wrong"),
            ];
            let f = compare(&reps);
            led.observe(&reps, &f);
        }
        assert!(
            matches!(led.verdict(), Verdict::Inconclusive { .. }),
            "{:?}",
            led.verdict()
        );
    }

    #[test]
    fn a_fleet_that_always_agrees_is_reported_as_quiet() {
        let mut led = Ledger::new();
        for i in 0..10 {
            let reps = vec![
                r("a", &format!("job{i}")),
                r("b", &format!("job{i}")),
                r("c", &format!("job{i}")),
            ];
            let f = compare(&reps);
            led.observe(&reps, &f);
        }
        assert_eq!(led.verdict(), Verdict::Quiet);
        assert_eq!(led.comparisons(), 10);
    }

    #[test]
    fn a_pair_that_keeps_disagreeing_is_recorded_without_naming_either() {
        // Two replicas, repeatedly differing. Real, worth surfacing, and still
        // not attributable — the answer is to add a third opinion, not to pick.
        let mut led = Ledger::new();
        for i in 0..10 {
            let reps = vec![r("a", &format!("job{i}")), r("b", &format!("other{i}"))];
            let f = compare(&reps);
            led.observe(&reps, &f);
        }
        match led.verdict() {
            Verdict::Inconclusive { disagreements } => assert_eq!(disagreements, 10),
            other => panic!("two replicas can never name a machine, got {other:?}"),
        }
    }
}
