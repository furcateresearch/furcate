//! Which machine administers a site.
//!
//! A site has exactly one administering machine. Two is not a degraded version
//! of one: two verifiers admit different peers, two Merkle roots anchor
//! different histories, and two kill switches disagree about whether something
//! is running. The site controller has described itself as "elected, one per
//! site" since it was written, and no election existed — the answer was an
//! environment variable, so two machines could both be told they were it.
//!
//! ## Why this is not an election
//!
//! Consensus belongs to the network a machine joins, not to the layer that runs
//! the machine. Furcate does not hold votes, take leases or count a quorum.
//!
//! It does not need to. Every input here is already agreed: membership comes
//! from the overlay, where a peer is admitted on a signature from an anchor its
//! operator holds, and capability comes from the attested hardware inventory
//! rather than from what a machine says about itself. Given the same members,
//! every node computes the same administrator without exchanging a message.
//! There is no protocol to disagree about, which is a stronger property than
//! agreeing quickly.
//!
//! ## What it refuses
//!
//! A node that can see fewer members than the membership declares does not
//! guess. That is the partition case, and a machine which promoted itself on a
//! partial view is precisely how a site ends up with two administrators. It
//! reports what it can see and declines to name anyone, because a refusal an
//! operator can read beats a decision nobody can check.

use crate::capability::Tier;
use furcate_identity::AssuranceClass;

/// A machine that could administer the site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The node's own name, which is its public key. Unforgeable, and stable
    /// across restarts, which is what makes it usable as a tie-break.
    pub id: String,
    pub tier: Tier,
    /// What kind of hardware holds this node's key, as the node reported and
    /// the verifier appraised.
    ///
    /// `None` means nobody has said — which is not the same as `Soft` and is
    /// treated as ineligible rather than as a weak class, because "unknown"
    /// must not quietly become an answer. Only classes that keep a key the
    /// hardware will not surrender may hold this role; see
    /// [`AssuranceClass::may_control`].
    pub assurance: Option<AssuranceClass>,
    /// Whether that tier came from the attested inventory.
    ///
    /// A machine that merely claims a GPU is not a candidate. Without this the
    /// selection would reward whichever node lied hardest, since the rule is
    /// "most capable wins".
    pub attested: bool,
    /// Whether this node is currently reachable in the overlay.
    pub reachable: bool,
}

/// The answer, or the reason there isn't one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// This node administers the site.
    Node(String),
    /// Nobody is named, and this says why in words an operator can act on.
    Refused(String),
}

impl Selection {
    pub fn node(&self) -> Option<&str> {
        match self {
            Selection::Node(id) => Some(id),
            Selection::Refused(_) => None,
        }
    }

    pub fn why(&self) -> Option<&str> {
        match self {
            Selection::Node(_) => None,
            Selection::Refused(why) => Some(why),
        }
    }
}

/// Who administers a site, given who is in it.
///
/// `declared` is how many members the signed membership says there are. Seeing
/// fewer means this node is looking at part of the site, and the whole point of
/// the refusal is that a partial view must not produce a confident answer.
pub fn administrator(candidates: &[Candidate], declared: usize) -> Selection {
    if declared == 0 {
        return Selection::Refused("the site declares no members".into());
    }
    if candidates.len() < declared {
        return Selection::Refused(format!(
            "sees {} of {declared} members; refusing to name an administrator from part of a site",
            candidates.len()
        ));
    }

    // Every member must have been appraised before anyone is named.
    //
    // Not merely "the unappraised are ineligible". An absent appraisal is an
    // input that has not arrived, and answering without it produces an answer
    // that changes when it does. This was observed: a restarted controller
    // named one machine while its attestation table was still filling and a
    // different one a moment later, from the same code and the same site. The
    // function was deterministic and the inputs were not, which looks identical
    // from the outside and is exactly the failure this whole rule exists to
    // avoid.
    let appraised = candidates.iter().filter(|c| c.attested).count();
    let unappraised = candidates.len() - appraised;
    if unappraised > 0 {
        return Selection::Refused(format!(
            "{appraised} of {} members appraised; waiting rather than naming an administrator \
             that changes when the rest arrive",
            candidates.len()
        ));
    }

    // Unreachable machines stay candidates on purpose. Reachability is a
    // property of the moment and administration is a property of the site: a
    // rule that moved the administrator whenever a link flapped would make the
    // answer depend on when it was asked.
    let eligible: Vec<&Candidate> = candidates.iter().filter(|c| c.attested).collect();
    if eligible.is_empty() {
        return Selection::Refused(
            "no member has an attested capability; a machine's own claim about itself is not enough"
                .into(),
        );
    }

    // Most capable, then lowest id. The tie-break is on a public key rather
    // than a name or an address, so it cannot be influenced by configuration.
    let best = eligible
        .iter()
        .max_by(|a, b| a.tier.cmp(&b.tier).then_with(|| b.id.cmp(&a.id)))
        .expect("eligible is not empty");
    Selection::Node(best.id.clone())
}

// ---------------------------------------------------------------------------
// Appointment
//
// Everything above is deliberately not an election and not configuration: given
// the same members, every node computes the same answer and there is no
// protocol to disagree about. An operator naming a controller is in obvious
// tension with that, and the tension is worth stating rather than hiding.
//
// It is resolved by making an appointment an INPUT TO THE SAME RULE rather than
// an override of it. An appointed node must still be a member, still be
// appraised, and still hold a key its hardware will not surrender. What the
// operator gets is the choice AMONG eligible machines — not the power to make
// an ineligible one eligible, which is the property the rule above exists to
// protect.
//
// Every node sees the same signed appointment, so they still all compute the
// same answer without exchanging a message. The guarantee is preserved; only
// the input set grew.
//
// Why an operator would want this at all: "most capable wins" optimises for
// capability, and an operator may have a reason it cannot see — a machine on a
// UPS, a machine that is not also running a validator, a machine they can
// physically reach.

/// Why an appointment was not honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppointmentError {
    /// The signature is not the operator's.
    BadSignature,
    /// Malformed: signature or key not readable as the right size.
    Malformed(String),
    /// Names a different site.
    WrongSite { named: String },
    /// Not yet, or no longer.
    NotLive { not_before: u64, not_after: u64, now: u64 },
    /// An older appointment presented after a newer one. This is the rollback
    /// case and the reason `epoch` exists.
    Stale { epoch: u64, current: u64 },
    /// Does not continue the appointment it claims to follow.
    BrokenChain { expected: Option<String>, found: Option<String> },
}

impl std::fmt::Display for AppointmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "the appointment is not signed by this site's operator"),
            Self::Malformed(w) => write!(f, "the appointment is malformed: {w}"),
            Self::WrongSite { named } => write!(f, "the appointment names site `{named}`, not this one"),
            Self::NotLive { not_before, not_after, now } => write!(
                f,
                "the appointment is not live: valid {not_before}..{not_after}, now {now}"
            ),
            Self::Stale { epoch, current } => write!(
                f,
                "the appointment is epoch {epoch} but this site has already seen {current}; \
                 refusing to roll back"
            ),
            Self::BrokenChain { expected, found } => write!(
                f,
                "the appointment claims to follow {:?} but the current one is {:?}",
                found, expected
            ),
        }
    }
}

/// An operator naming which machine administers a site.
///
/// Signed, time-bounded, and chained: `epoch` only ever increases and
/// `predecessor` is the digest of the appointment this one replaces, so an old
/// appointment cannot be replayed to move the role backwards. That pairing —
/// a monotonic counter plus a hash of what came before — is what stands in for
/// a hardware counter on machines that have none, and it works identically on a
/// TPM node and a Secure Enclave one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Appointment {
    /// Which site this speaks for. Present so an appointment cannot be lifted
    /// from one site and replayed at another that shares an operator.
    pub site: String,
    /// The node being appointed.
    pub node_id: String,
    /// Monotonic. A lower epoch than the one already held is a rollback.
    pub epoch: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// Digest of the appointment this replaces; `None` only for the first.
    pub predecessor: Option<String>,
    /// The operator's reason, kept because a role change nobody can explain is
    /// one nobody dares undo.
    pub reason: String,
    /// Hex Ed25519 signature over [`Appointment::signed_bytes`].
    pub signature: String,
}

impl Appointment {
    /// The exact bytes the signature covers.
    ///
    /// Domain-separated and field-delimited. Built by hand rather than by
    /// serialising the struct, because a signature over "whatever serde emitted
    /// that day" is a signature over a format that can change underneath it.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"furcate:appointment:v1\0");
        for field in [
            self.site.as_str(),
            self.node_id.as_str(),
            &self.epoch.to_string(),
            &self.not_before.to_string(),
            &self.not_after.to_string(),
            self.predecessor.as_deref().unwrap_or(""),
            self.reason.as_str(),
        ] {
            m.extend_from_slice(field.as_bytes());
            m.push(0);
        }
        m
    }

    /// What a successor must name as its `predecessor`.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(self.signed_bytes()))
    }

    /// Check this appointment is one this site should act on.
    ///
    /// `current` is the appointment already in force, if any. Checked in the
    /// order that fails cheapest first, and every failure names itself — an
    /// appointment that is quietly ignored is worse than one that is refused,
    /// because the operator believes they moved the role.
    pub fn verify(
        &self,
        operator_key: &ed25519_dalek::VerifyingKey,
        site: &str,
        now: u64,
        current: Option<&Appointment>,
    ) -> Result<(), AppointmentError> {
        use ed25519_dalek::{Signature, Verifier};

        if self.site != site {
            return Err(AppointmentError::WrongSite { named: self.site.clone() });
        }
        if now < self.not_before || now >= self.not_after {
            return Err(AppointmentError::NotLive {
                not_before: self.not_before,
                not_after: self.not_after,
                now,
            });
        }
        if let Some(cur) = current {
            if self.epoch <= cur.epoch {
                return Err(AppointmentError::Stale { epoch: self.epoch, current: cur.epoch });
            }
            let want = Some(cur.digest());
            if self.predecessor != want {
                return Err(AppointmentError::BrokenChain {
                    expected: want,
                    found: self.predecessor.clone(),
                });
            }
        }
        let raw = hex::decode(&self.signature)
            .map_err(|e| AppointmentError::Malformed(format!("signature is not hex: {e}")))?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| AppointmentError::Malformed(format!(
                "signature is {} bytes, expected 64",
                raw.len()
            )))?;
        operator_key
            .verify(&self.signed_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| AppointmentError::BadSignature)?;
        Ok(())
    }
}

/// Who administers a site, given who is in it and who the operator named.
///
/// With no appointment this is exactly [`administrator`]. With one, the
/// appointed node is used **if it would have been eligible anyway** — a member,
/// appraised, and holding a key its hardware will not surrender.
///
/// An appointment naming an ineligible machine does NOT fall back to the
/// computed answer. Falling back would mean an operator's decision being
/// silently replaced by a different one, which is the failure this whole file
/// is written against. It refuses, and says which requirement was missed.
pub fn administrator_appointed(
    candidates: &[Candidate],
    declared: usize,
    appointed: Option<&str>,
) -> Selection {
    let Some(want) = appointed else {
        return administrator(candidates, declared);
    };
    let Some(c) = candidates.iter().find(|c| c.id == want) else {
        return Selection::Refused(format!(
            "the operator appointed `{want}`, which is not a member of this site"
        ));
    };
    if !c.attested {
        return Selection::Refused(format!(
            "the operator appointed `{want}`, whose capability has not been appraised; \
             an appointment chooses among eligible machines, it does not make one eligible"
        ));
    }
    match c.assurance {
        None => Selection::Refused(format!(
            "the operator appointed `{want}`, which has not reported what holds its key"
        )),
        Some(a) if !a.may_control() => Selection::Refused(format!(
            "the operator appointed `{want}`, whose key is held as `{a}` — a controller must hold \
             a key its hardware will not surrender, so this cannot be honoured"
        )),
        Some(_) => Selection::Node(c.id.clone()),
    }
}

/// Whether the machine a node reports to is the one selection names.
///
/// Configuration and computation disagreeing is the condition that produces two
/// administrators, and it is silent unless something asks.
pub fn agrees(selected: &Selection, configured: Option<&str>) -> Agreement {
    match (selected.node(), configured) {
        (Some(want), Some(have)) if want == have => Agreement::Agree,
        (Some(want), Some(have)) => Agreement::Disagree {
            selected: want.to_string(),
            configured: have.to_string(),
        },
        (Some(_), None) => Agreement::Unconfigured,
        (None, _) => Agreement::Undecided,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agreement {
    Agree,
    /// The dangerous one: this node is administered by a machine that the site's
    /// own rule does not select.
    Disagree { selected: String, configured: String },
    Unconfigured,
    Undecided,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &str, tier: Tier, attested: bool) -> Candidate {
        Candidate {
            id: id.into(),
            tier,
            assurance: Some(AssuranceClass::Tpm),
            attested,
            reachable: true,
        }
    }

    fn signer() -> ed25519_dalek::SigningKey {
        // Fixed bytes: a test that generates a key tests the generator too.
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn appointment(node: &str, epoch: u64, prev: Option<&Appointment>) -> Appointment {
        use ed25519_dalek::Signer;
        let mut a = Appointment {
            site: "home-1".into(),
            node_id: node.into(),
            epoch,
            not_before: 100,
            not_after: 10_000,
            predecessor: prev.map(|p| p.digest()),
            reason: "for the test".into(),
            signature: String::new(),
        };
        a.signature = hex::encode(signer().sign(&a.signed_bytes()).to_bytes());
        a
    }

    #[test]
    fn an_appointment_chooses_among_eligible_machines() {
        // The whole point: the operator picks the LESS capable node and gets
        // it, because capability is the default rule and not the only reason.
        let m = [
            c("aaa", Tier::Compute, true),
            c("bbb", Tier::Accelerated, true),
        ];
        assert_eq!(administrator(&m, 2).node(), Some("bbb"));
        assert_eq!(administrator_appointed(&m, 2, Some("aaa")).node(), Some("aaa"));
    }

    #[test]
    fn an_appointment_cannot_make_an_ineligible_machine_eligible() {
        // Each of the three ways a machine can fail to qualify, refused
        // separately, because "it didn't work" is not a usable answer.
        let unappraised = [c("aaa", Tier::Compute, true), c("liar", Tier::Accelerated, false)];
        let s = administrator_appointed(&unappraised, 2, Some("liar"));
        assert!(s.node().is_none());
        assert!(s.why().unwrap().contains("has not been appraised"));

        let mut soft = c("soft", Tier::Compute, true);
        soft.assurance = Some(AssuranceClass::Soft);
        let s = administrator_appointed(&[soft, c("aaa", Tier::Compute, true)], 2, Some("soft"));
        assert!(s.node().is_none());
        assert!(s.why().unwrap().contains("will not surrender"));

        let mut silent = c("silent", Tier::Compute, true);
        silent.assurance = None;
        let s = administrator_appointed(&[silent, c("aaa", Tier::Compute, true)], 2, Some("silent"));
        assert!(s.node().is_none());
        assert!(s.why().unwrap().contains("has not reported"));

        let s = administrator_appointed(&[c("aaa", Tier::Compute, true)], 1, Some("ghost"));
        assert!(s.why().unwrap().contains("not a member"));
    }

    #[test]
    fn a_secure_enclave_node_may_be_appointed() {
        // An operator's Mac. Eligible because may_control() admits
        // SecureElement — and it can only report that class honestly now that
        // /attest carries the real one instead of a hardcoded `tpm`.
        let mut mac = c("mac", Tier::Compute, true);
        mac.assurance = Some(AssuranceClass::SecureElement);
        let m = [mac, c("bbb", Tier::Accelerated, true)];
        assert_eq!(administrator_appointed(&m, 2, Some("mac")).node(), Some("mac"));
    }

    #[test]
    fn no_appointment_is_the_computed_answer() {
        let m = [c("aaa", Tier::Compute, true), c("bbb", Tier::Accelerated, true)];
        assert_eq!(administrator_appointed(&m, 2, None), administrator(&m, 2));
    }

    #[test]
    fn an_appointment_verifies_only_under_the_operators_key() {
        let a = appointment("aaa", 1, None);
        assert!(a.verify(&signer().verifying_key(), "home-1", 500, None).is_ok());

        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(
            a.verify(&other.verifying_key(), "home-1", 500, None),
            Err(AppointmentError::BadSignature)
        );
    }

    #[test]
    fn an_appointment_is_bound_to_its_site_and_its_window() {
        let a = appointment("aaa", 1, None);
        let k = signer().verifying_key();
        assert!(matches!(
            a.verify(&k, "other-site", 500, None),
            Err(AppointmentError::WrongSite { .. })
        ));
        assert!(matches!(a.verify(&k, "home-1", 50, None), Err(AppointmentError::NotLive { .. })));
        assert!(matches!(a.verify(&k, "home-1", 99_999, None), Err(AppointmentError::NotLive { .. })));
    }

    #[test]
    fn an_old_appointment_cannot_be_replayed_to_move_the_role_back() {
        // The rollback case, and the reason epoch and predecessor both exist.
        let k = signer().verifying_key();
        let first = appointment("aaa", 1, None);
        let second = appointment("bbb", 2, Some(&first));
        assert!(second.verify(&k, "home-1", 500, Some(&first)).is_ok());

        // Replaying the first once the second is in force.
        assert_eq!(
            first.verify(&k, "home-1", 500, Some(&second)),
            Err(AppointmentError::Stale { epoch: 1, current: 2 })
        );

        // A higher epoch is not enough on its own — it must continue the chain.
        let forked = appointment("ccc", 3, None);
        assert!(matches!(
            forked.verify(&k, "home-1", 500, Some(&second)),
            Err(AppointmentError::BrokenChain { .. })
        ));
    }

    #[test]
    fn tampering_with_any_signed_field_invalidates_it() {
        let k = signer().verifying_key();
        let base = appointment("aaa", 1, None);
        for mutate in [
            (|a: &mut Appointment| a.node_id = "bbb".into()) as fn(&mut Appointment),
            |a: &mut Appointment| a.epoch = 99,
            |a: &mut Appointment| a.not_after = 99_999,
            |a: &mut Appointment| a.reason = "different".into(),
        ] {
            let mut a = base.clone();
            mutate(&mut a);
            assert_eq!(
                a.verify(&k, "home-1", 500, None),
                Err(AppointmentError::BadSignature),
                "a mutated field was not covered by the signature"
            );
        }
    }

    #[test]
    fn the_most_capable_machine_administers() {
        let m = [
            c("aaa", Tier::Compute, true),
            c("bbb", Tier::Accelerated, true),
            c("ccc", Tier::Constrained, true),
        ];
        assert_eq!(administrator(&m, 3).node(), Some("bbb"));
    }

    #[test]
    fn a_tie_is_broken_by_the_key_not_by_order() {
        // The same set in a different order must give the same answer, or the
        // administrator depends on how a node happened to enumerate its peers.
        let a = [c("zzz", Tier::Compute, true), c("aaa", Tier::Compute, true)];
        let b = [c("aaa", Tier::Compute, true), c("zzz", Tier::Compute, true)];
        assert_eq!(administrator(&a, 2), administrator(&b, 2));
        assert_eq!(administrator(&a, 2).node(), Some("aaa"));
    }

    #[test]
    fn a_machine_that_only_claims_capability_cannot_win() {
        // Otherwise the rule "most capable wins" rewards whichever node lies.
        // It also does not hand the job to the honest one while the liar is
        // still unappraised: that answer would change the moment an appraisal
        // arrived, which is the flapping this rule must not do.
        let m = [
            c("liar", Tier::Accelerated, false),
            c("honest", Tier::Constrained, true),
        ];
        let s = administrator(&m, 2);
        assert!(s.node().is_none());
        assert!(s.why().expect("a reason").contains("1 of 2 members appraised"));
    }

    #[test]
    fn an_incomplete_appraisal_table_names_nobody() {
        // The live failure: a restarted controller answered from a table that
        // was still filling, and its answer changed as records arrived.
        let mut m = [c("aaa", Tier::Compute, true), c("bbb", Tier::Compute, true)];
        assert_eq!(administrator(&m, 2).node(), Some("aaa"));
        m[1].attested = false;
        assert!(administrator(&m, 2).node().is_none());
    }

    #[test]
    fn a_partial_view_names_nobody() {
        // The partition case. A node seeing half a site must not promote
        // anyone, because the other half is doing the same arithmetic.
        let m = [c("aaa", Tier::Accelerated, true)];
        let s = administrator(&m, 3);
        assert!(s.node().is_none());
        assert!(s.why().expect("a reason").contains("1 of 3"));
    }

    #[test]
    fn nothing_attested_is_a_refusal_rather_than_a_guess() {
        let m = [c("aaa", Tier::Accelerated, false), c("bbb", Tier::Compute, false)];
        assert!(administrator(&m, 2).node().is_none());
    }

    #[test]
    fn an_unreachable_machine_still_administers() {
        // Administration is a property of the site, not of this second. If a
        // flapping link moved it, the answer would depend on when it was asked
        // and two nodes asking at different moments would differ.
        let mut m = [c("aaa", Tier::Accelerated, true), c("bbb", Tier::Compute, true)];
        m[0].reachable = false;
        assert_eq!(administrator(&m, 2).node(), Some("aaa"));
    }

    #[test]
    fn every_node_computes_the_same_answer() {
        // The property that removes the need for a protocol: this is a function
        // of the membership, so nodes do not have to talk to agree.
        let m = [
            c("n3", Tier::Compute, true),
            c("n1", Tier::Accelerated, true),
            c("n2", Tier::Accelerated, true),
        ];
        let from_each: Vec<_> = (0..3)
            .map(|skip| {
                let mut rotated = m.to_vec();
                rotated.rotate_left(skip);
                administrator(&rotated, 3)
            })
            .collect();
        assert!(from_each.windows(2).all(|w| w[0] == w[1]), "{from_each:?}");
    }

    #[test]
    fn configuration_disagreeing_with_the_rule_is_reported() {
        let m = [c("aaa", Tier::Accelerated, true), c("bbb", Tier::Compute, true)];
        let s = administrator(&m, 2);
        assert_eq!(agrees(&s, Some("aaa")), Agreement::Agree);
        assert_eq!(
            agrees(&s, Some("bbb")),
            Agreement::Disagree { selected: "aaa".into(), configured: "bbb".into() }
        );
    }

    #[test]
    fn an_undecided_site_does_not_report_a_disagreement() {
        // Refusing to choose and choosing differently are different states, and
        // an operator acts on them differently.
        let s = administrator(&[c("aaa", Tier::Compute, true)], 4);
        assert_eq!(agrees(&s, Some("bbb")), Agreement::Undecided);
    }
}
