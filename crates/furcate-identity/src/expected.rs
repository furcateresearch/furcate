//! Machines the operator is expecting, and what to do about one that arrives
//! without being expected.
//!
//! Furcate does not provision bare metal. It is the system being installed, not
//! an installer, and it has no PXE server, no DHCP and no imaging pipeline —
//! that is a deliberate boundary rather than an omission, and this module does
//! not cross it.
//!
//! What it closes is the hole the boundary leaves. An unattended install is an
//! open door by construction: anything that boots on that network gets an
//! image, and a moment later presents a perfectly valid enrollment.
//! [`crate::enroll`] can already prove *what* a machine is — hardware-rooted,
//! attested, endorsed by the manufacturer — and nothing anywhere said whether
//! it was **supposed to be there**. Those are different questions and only the
//! first was being asked. A machine with an impeccable TPM that nobody ordered
//! is still not yours.
//!
//! ## The identifier is a compromise, and the type says which one
//!
//! Two things could key an expectation. The endorsement key is what the
//! platform actually verifies, and an operator ordering twelve servers does not
//! have their EK digests — the vendor ships a serial number on a delivery note.
//! So the manifest is keyed on an opaque string that may be either, and
//! [`Expectation::binding`] records which, because they are not equally strong:
//! a serial is a label anyone can read off a chassis and retype, and an
//! endorsement key is a secret the silicon will not surrender.
//!
//! Recording the difference is the point. A site enrolling on serials is not
//! wrong — it is what a delivery note supports — but it should know that is
//! what it is doing.

use crate::enroll::Enrollment;
use crate::rot::AssuranceClass;
use serde::{Deserialize, Serialize};

/// What an expectation is keyed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// The endorsement key digest. The silicon proves this.
    EndorsementKey,
    /// A chassis or board serial from a delivery note. A label, not a secret:
    /// readable by anyone with physical access and retypeable by anyone at all.
    Serial,
}

impl Binding {
    /// Whether the machine itself proves the match.
    pub fn is_cryptographic(&self) -> bool {
        matches!(self, Binding::EndorsementKey)
    }
}

/// One machine the operator is expecting.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Expectation {
    /// The identifier this expectation is keyed on.
    pub identifier: String,
    pub binding: Binding,
    /// The name it is expected to take. Advisory, exactly as in the enrollment
    /// record — never used to decide identity.
    pub hostname: String,
    /// The weakest root of trust that will be accepted for this machine.
    ///
    /// Declared per machine rather than per site because a site is rarely
    /// uniform: the same estate holds TPM servers and fuse-backed edge devices,
    /// and a single site-wide floor would either exclude the second or admit
    /// something soft where a server was ordered.
    pub minimum_assurance: AssuranceClass,
    /// Who is expecting it, in their own words — a purchase order, a ticket.
    pub ordered_by: String,
}

/// What to make of a machine presenting itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arrival {
    /// Expected, and it is what was expected.
    Expected {
        hostname: String,
        ordered_by: String,
        /// False when the match rests on a serial rather than on the silicon.
        proven: bool,
    },
    /// Expected, and its root of trust is weaker than was ordered.
    ///
    /// Separate from unexpected because the remedy is different: this is
    /// probably the right machine with the wrong firmware settings, and an
    /// operator can fix it. It is still not admitted on its own.
    WeakerThanOrdered {
        hostname: String,
        required: AssuranceClass,
        offered: AssuranceClass,
    },
    /// Nobody is expecting this machine.
    Unexpected,
}

impl Arrival {
    /// Whether this machine may be enrolled without a person deciding.
    ///
    /// Only a machine that was expected, and whose match the silicon itself
    /// proved. Everything else reaches an operator — including the serial-keyed
    /// match, which is a perfectly reasonable thing to run a site on and is
    /// not, on its own, evidence of anything a person did not type.
    ///
    /// Enrollment is the one moment a node is trusted on an operator's say-so
    /// and everything afterwards derives from it, so the bar is set here rather
    /// than anywhere later.
    pub fn may_enrol_automatically(&self) -> bool {
        matches!(self, Arrival::Expected { proven: true, .. })
    }

    pub fn was_expected(&self) -> bool {
        !matches!(self, Arrival::Unexpected)
    }
}

/// Order the assurance classes by how much they rest on hardware.
///
/// Not derived from the enum's declaration order, which is a list rather than a
/// ranking, and would silently change meaning the day somebody inserts a
/// variant in the middle.
fn strength(a: AssuranceClass) -> u8 {
    match a {
        AssuranceClass::Soft => 0,
        AssuranceClass::Device => 1,
        AssuranceClass::SecureElement => 2,
        AssuranceClass::Tee => 3,
        AssuranceClass::Dice => 4,
        AssuranceClass::Tpm => 5,
    }
}

/// Place an arriving machine against the manifest.
///
/// `presented` is whatever identifier the machine offered — an endorsement key
/// digest where the platform has one, otherwise a serial read from the chassis.
/// Matching is exact: a manifest that matched loosely would be a manifest that
/// could be talked into a match.
pub fn classify(
    enrollment: &Enrollment,
    presented: &str,
    manifest: &[Expectation],
) -> Arrival {
    let Some(exp) = manifest.iter().find(|e| e.identifier == presented) else {
        return Arrival::Unexpected;
    };

    if strength(enrollment.assurance) < strength(exp.minimum_assurance) {
        return Arrival::WeakerThanOrdered {
            hostname: exp.hostname.clone(),
            required: exp.minimum_assurance,
            offered: enrollment.assurance,
        };
    }

    Arrival::Expected {
        hostname: exp.hostname.clone(),
        ordered_by: exp.ordered_by.clone(),
        proven: exp.binding.is_cryptographic(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_id::NodeId;

    fn enrollment(assurance: AssuranceClass) -> Enrollment {
        Enrollment {
            node_id: NodeId::from_ek_public(&[7u8; 32]),
            assurance,
            hostname: "whatever-it-claims".into(),
            endorsed: true,
            evidence_digest: "abc".into(),
            pcrs: Default::default(),
        }
    }

    fn ordered(binding: Binding) -> Expectation {
        Expectation {
            identifier: "ek:9f2c".into(),
            binding,
            hostname: "node-d".into(),
            minimum_assurance: AssuranceClass::Tpm,
            ordered_by: "PO-2291".into(),
        }
    }

    #[test]
    fn a_machine_nobody_ordered_is_not_admitted() {
        // The hole an unattended installer leaves: this machine's identity is
        // impeccable and it is still not ours.
        let a = classify(
            &enrollment(AssuranceClass::Tpm),
            "ek:unknown",
            &[ordered(Binding::EndorsementKey)],
        );
        assert_eq!(a, Arrival::Unexpected);
        assert!(!a.may_enrol_automatically());
        assert!(!a.was_expected());
    }

    #[test]
    fn an_expected_machine_proven_by_its_silicon_may_enrol_itself() {
        let a = classify(
            &enrollment(AssuranceClass::Tpm),
            "ek:9f2c",
            &[ordered(Binding::EndorsementKey)],
        );
        assert_eq!(
            a,
            Arrival::Expected {
                hostname: "node-d".into(),
                ordered_by: "PO-2291".into(),
                proven: true
            }
        );
        assert!(a.may_enrol_automatically());
    }

    #[test]
    fn a_serial_match_is_expected_but_not_proven() {
        // Running a site on delivery-note serials is reasonable. It is also
        // a label anybody can retype, so it reaches a person rather than
        // admitting itself.
        let a = classify(
            &enrollment(AssuranceClass::Tpm),
            "ek:9f2c",
            &[ordered(Binding::Serial)],
        );
        assert!(a.was_expected());
        assert!(!a.may_enrol_automatically());
        assert!(matches!(a, Arrival::Expected { proven: false, .. }));
    }

    #[test]
    fn the_right_machine_with_the_wrong_firmware_is_its_own_answer() {
        // Distinct from unexpected because the remedy is different: this is
        // probably the ordered server with secure boot off, and an operator
        // can fix that.
        let a = classify(
            &enrollment(AssuranceClass::Soft),
            "ek:9f2c",
            &[ordered(Binding::EndorsementKey)],
        );
        assert_eq!(
            a,
            Arrival::WeakerThanOrdered {
                hostname: "node-d".into(),
                required: AssuranceClass::Tpm,
                offered: AssuranceClass::Soft
            }
        );
        assert!(a.was_expected());
        assert!(!a.may_enrol_automatically());
    }

    #[test]
    fn a_stronger_root_of_trust_than_ordered_is_fine() {
        let mut e = ordered(Binding::EndorsementKey);
        e.minimum_assurance = AssuranceClass::Device;
        let a = classify(&enrollment(AssuranceClass::Tpm), "ek:9f2c", &[e]);
        assert!(a.may_enrol_automatically());
    }

    #[test]
    fn assurance_is_ranked_by_hardware_not_by_declaration_order() {
        assert!(strength(AssuranceClass::Tpm) > strength(AssuranceClass::Soft));
        assert!(strength(AssuranceClass::Dice) > strength(AssuranceClass::Tee));
        assert!(strength(AssuranceClass::SecureElement) > strength(AssuranceClass::Device));
    }

    #[test]
    fn matching_is_exact() {
        // A manifest that matched loosely is a manifest that can be talked
        // into a match.
        for presented in ["ek:9f2", "ek:9f2c ", "EK:9F2C", "ek:9f2cd"] {
            assert_eq!(
                classify(
                    &enrollment(AssuranceClass::Tpm),
                    presented,
                    &[ordered(Binding::EndorsementKey)]
                ),
                Arrival::Unexpected,
                "{presented} should not have matched"
            );
        }
    }
}
