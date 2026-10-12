//! Vouching for a machine that cannot attest for itself.
//!
//! A node with a TPM proves it is itself: the key is sealed to the chip and a
//! signature is evidence nobody else could have produced. A node without one
//! has no such story. Its identity is the board and chassis serials somebody
//! read at enrolment — continuity, not unforgeability.
//!
//! This is how the machines that *can* attest say something about the machine
//! that cannot, without any one of them being able to say it alone.
//!
//! ## A node signs only for itself unless it is delegated
//!
//! The rule the trust store already encodes in `Kind`: a `Machine` key
//! authenticates exactly one principal, itself. Vouching is the narrow, named
//! exception — and it is narrow in three ways at once:
//!
//! 1. **A voucher must hold a TPM.** A soft node vouching for a soft node adds
//!    nothing; it moves an unprovable claim one hop and makes it look better.
//! 2. **A voucher signs a statement about a SUBJECT, never as the subject.**
//!    The signed bytes name both parties, so a vouch cannot be replayed as the
//!    subject's own attestation.
//! 3. **No single voucher is enough.** Below the threshold the statement is
//!    not a weaker claim, it is not a claim at all.
//!
//! Without the threshold one compromised machine could admit arbitrary nodes —
//! it signs "this serial is that node", and a site that believes one signature
//! believes the attacker. Two independent TPM holders must observe the same
//! thing, so an attacker needs two chips, not one.
//!
//! ## The quorum is 2 of however many TPM machines the cluster has
//!
//! Not two named machines. The set is computed from the roster at the moment
//! of admission, so it survives a machine being added, retired or losing its
//! TPM. A cluster with fewer than two TPM holders cannot vouch at all, and
//! says so rather than lowering the bar to fit.

use serde::{Deserialize, Serialize};

/// The minimum number of independent TPM-bearing vouchers.
///
/// Two, because one is a single point of compromise and three would make a
/// three-machine cluster unable to enrol anything after one machine is down.
pub const QUORUM: usize = 2;

/// What one TPM-bearing machine says it observed about another machine.
///
/// The subject is named inside the signed bytes. A voucher is signing "I,
/// `voucher`, observed `subject` presenting `observed`" — never "I am
/// `subject`", which is the substitution this shape exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vouch {
    /// The node making the statement. Must be a TPM-bearing member.
    pub voucher: String,
    /// The node being spoken about.
    pub subject: String,
    /// What the voucher actually observed — board and chassis serials, in the
    /// order the subject reported them. Two vouchers disagreeing here is the
    /// signal that matters, so it is compared, not merely counted.
    pub observed: String,
    /// The subject's signing key at the time of observation. Carried so a
    /// vouch cannot be reused to admit a different key for the same serials.
    pub subject_key: String,
    /// Unix seconds. A vouch is evidence about a moment, not a standing fact.
    pub at: u64,
    /// Ed25519 over `signing_input()`, hex.
    pub signature: String,
}

impl Vouch {
    /// The exact bytes a voucher signs.
    ///
    /// Domain-separated and versioned so a signature made here can never be
    /// mistaken for one made over another Furcate structure, and so a later
    /// format cannot be validated by an older verifier that would ignore a
    /// field it does not know about.
    pub fn signing_input(&self) -> String {
        format!(
            "furcate-vouch/1\n{}\n{}\n{}\n{}\n{}",
            self.voucher, self.subject, self.observed, self.subject_key, self.at
        )
    }
}

/// Why a set of vouches was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VouchError {
    /// Fewer than `QUORUM` valid, independent vouches.
    NotEnough { have: usize, need: usize },
    /// One machine signed more than once. Counted as one, and refused rather
    /// than silently deduplicated: a caller submitting duplicates is either
    /// confused about the threshold or testing it.
    Duplicate { voucher: String },
    /// A voucher is not a TPM-bearing member of this cluster.
    NotEndorsed { voucher: String },
    /// A voucher signed about a different subject than the rest.
    SubjectMismatch { expected: String, found: String },
    /// Two vouchers observed different serials for the same subject. The
    /// interesting failure: it means one of them is wrong or lying, and
    /// admitting on a majority would be choosing which to believe.
    ObservationMismatch { a: String, b: String },
    /// A signature did not verify against the voucher's known key.
    BadSignature { voucher: String },
    /// The cluster has fewer than `QUORUM` TPM holders, so no quorum is
    /// reachable. Reported distinctly from "not enough vouches" because the
    /// operator's action is different: this one cannot be fixed by collecting
    /// more signatures.
    NoQuorumPossible { endorsed: usize, need: usize },
}

impl std::fmt::Display for VouchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnough { have, need } => write!(
                f,
                "{have} of {need} vouches — a machine that cannot attest for itself needs {need} that can"
            ),
            Self::Duplicate { voucher } => {
                write!(f, "{voucher} vouched more than once; one machine is one voucher")
            }
            Self::NotEndorsed { voucher } => write!(
                f,
                "{voucher} holds no TPM, so its word about another machine adds nothing"
            ),
            Self::SubjectMismatch { expected, found } => {
                write!(f, "a vouch names {found} but the others name {expected}")
            }
            Self::ObservationMismatch { a, b } => write!(
                f,
                "two vouchers saw different machines: {a} and {b}. One is wrong, and admitting \
                 on a majority would be choosing which to believe"
            ),
            Self::BadSignature { voucher } => {
                write!(f, "{voucher}'s signature does not verify against its known key")
            }
            Self::NoQuorumPossible { endorsed, need } => write!(
                f,
                "this cluster has {endorsed} machine(s) with a TPM and needs {need}; no number \
                 of signatures reaches a quorum until another attesting machine joins"
            ),
        }
    }
}

/// A machine that may vouch: a TPM-bearing member, with the key to check.
pub struct Endorser {
    pub node_id: String,
    /// Ed25519 public key, hex.
    pub key: String,
}

/// Decide whether a set of vouches admits `subject`.
///
/// `endorsers` is the set of TPM-bearing members **as of now**, so the quorum
/// follows the cluster rather than a list written once. `verify` checks one
/// signature and is injected so this stays free of a crypto dependency and can
/// be tested against a stub.
pub fn admits<F>(
    subject: &str,
    vouches: &[Vouch],
    endorsers: &[Endorser],
    verify: F,
) -> Result<Vec<String>, VouchError>
where
    F: Fn(&str, &str, &str) -> bool,
{
    if endorsers.len() < QUORUM {
        return Err(VouchError::NoQuorumPossible {
            endorsed: endorsers.len(),
            need: QUORUM,
        });
    }

    let mut accepted: Vec<String> = Vec::new();
    let mut observation: Option<&str> = None;

    for v in vouches {
        if v.subject != subject {
            return Err(VouchError::SubjectMismatch {
                expected: subject.to_string(),
                found: v.subject.clone(),
            });
        }
        // A machine cannot vouch for itself. That is not a quorum of one, it
        // is the unprovable claim restated by the party making it.
        if v.voucher == subject {
            return Err(VouchError::NotEndorsed { voucher: v.voucher.clone() });
        }
        let Some(e) = endorsers.iter().find(|e| e.node_id == v.voucher) else {
            return Err(VouchError::NotEndorsed { voucher: v.voucher.clone() });
        };
        if accepted.contains(&v.voucher) {
            return Err(VouchError::Duplicate { voucher: v.voucher.clone() });
        }
        if !verify(&e.key, &v.signing_input(), &v.signature) {
            return Err(VouchError::BadSignature { voucher: v.voucher.clone() });
        }
        // Compared, not counted. Two machines that disagree about what they
        // saw have not corroborated anything.
        match observation {
            None => observation = Some(&v.observed),
            Some(prev) if prev != v.observed => {
                return Err(VouchError::ObservationMismatch {
                    a: prev.to_string(),
                    b: v.observed.clone(),
                })
            }
            Some(_) => {}
        }
        accepted.push(v.voucher.clone());
    }

    if accepted.len() < QUORUM {
        return Err(VouchError::NotEnough { have: accepted.len(), need: QUORUM });
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(voucher: &str, subject: &str, observed: &str) -> Vouch {
        Vouch {
            voucher: voucher.into(),
            subject: subject.into(),
            observed: observed.into(),
            subject_key: "aa".into(),
            at: 1_790_000_000,
            signature: "sig".into(),
        }
    }

    fn three() -> Vec<Endorser> {
        ["s1", "s2", "sp"]
            .iter()
            .map(|n| Endorser { node_id: (*n).into(), key: format!("key-{n}") })
            .collect()
    }

    fn ok(_k: &str, _m: &str, _s: &str) -> bool {
        true
    }

    #[test]
    fn two_of_three_admits() {
        let got = admits("s3", &[v("s1", "s3", "SER1"), v("s2", "s3", "SER1")], &three(), ok);
        assert_eq!(got.unwrap().len(), 2);
    }

    #[test]
    fn any_two_tpm_machines_will_do() {
        // The quorum is not two NAMED machines.
        let got = admits("s3", &[v("s2", "s3", "SER1"), v("sp", "s3", "SER1")], &three(), ok);
        assert!(got.is_ok());
    }

    #[test]
    fn one_is_never_enough() {
        let got = admits("s3", &[v("s1", "s3", "SER1")], &three(), ok);
        assert_eq!(got, Err(VouchError::NotEnough { have: 1, need: 2 }));
    }

    #[test]
    fn one_machine_cannot_be_two_vouchers() {
        let got = admits("s3", &[v("s1", "s3", "SER1"), v("s1", "s3", "SER1")], &three(), ok);
        assert_eq!(got, Err(VouchError::Duplicate { voucher: "s1".into() }));
    }

    #[test]
    fn a_machine_cannot_vouch_for_itself() {
        let got = admits("s3", &[v("s3", "s3", "SER1"), v("s1", "s3", "SER1")], &three(), ok);
        assert_eq!(got, Err(VouchError::NotEndorsed { voucher: "s3".into() }));
    }

    #[test]
    fn a_soft_node_cannot_vouch() {
        let got = admits("s3", &[v("s1", "s3", "SER1"), v("soft", "s3", "SER1")], &three(), ok);
        assert_eq!(got, Err(VouchError::NotEndorsed { voucher: "soft".into() }));
    }

    #[test]
    fn disagreement_is_refused_not_out_voted() {
        let got = admits(
            "s3",
            &[v("s1", "s3", "SER1"), v("s2", "s3", "SER2"), v("sp", "s3", "SER1")],
            &three(),
            ok,
        );
        assert!(matches!(got, Err(VouchError::ObservationMismatch { .. })));
    }

    #[test]
    fn a_bad_signature_refuses_the_whole_set() {
        let got = admits("s3", &[v("s1", "s3", "SER1"), v("s2", "s3", "SER1")], &three(), |_, _, _| false);
        assert!(matches!(got, Err(VouchError::BadSignature { .. })));
    }

    #[test]
    fn a_cluster_with_one_tpm_says_so_plainly() {
        let one = vec![Endorser { node_id: "s1".into(), key: "k".into() }];
        let got = admits("s3", &[v("s1", "s3", "SER1")], &one, ok);
        assert_eq!(got, Err(VouchError::NoQuorumPossible { endorsed: 1, need: 2 }));
    }

    #[test]
    fn the_signed_bytes_name_both_parties() {
        // A vouch must not be replayable as the subject's own attestation.
        let s = v("s1", "s3", "SER1").signing_input();
        assert!(s.starts_with("furcate-vouch/1\n"));
        assert!(s.contains("s1") && s.contains("s3"));
    }
}
