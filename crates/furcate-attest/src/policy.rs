//! Reference values, coverage, and appraisal policy.

use furcate_identity::AssuranceClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Registers whose values a policy expects, and what they should be.
///
/// Reference values come from two very different places, and the distinction
/// is important enough to keep in the type. Values *derived* from a signed
/// image can be computed before the machine ever boots. Values *observed* at
/// enrollment are only a record of what happened to be there, and blessing
/// them means trusting that the machine was clean at that moment.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReferenceValues {
    /// Register index to expected digest, hex encoded.
    pub expected: BTreeMap<u32, String>,
    /// True when these were computed from a signed artifact rather than
    /// observed on a running machine.
    pub derived: bool,
}

impl ReferenceValues {
    /// Reference values computed ahead of time from a signed image.
    pub fn derived(expected: BTreeMap<u32, String>) -> Self {
        Self {
            expected,
            derived: true,
        }
    }

    /// Reference values captured from a machine believed to be clean.
    pub fn observed(expected: BTreeMap<u32, String>) -> Self {
        Self {
            expected,
            derived: false,
        }
    }
}

/// What a set of register values actually proves about a platform.
///
/// A register holding only an `EV_SEPARATOR`, or nothing at all, is not
/// evidence — and reporting it as though it were is how attestation turns into
/// false confidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Firmware and boot configuration are measured, and so is the OS.
    PlatformAndOs,
    /// Only firmware and platform configuration are measured. A swapped
    /// kernel, initrd or command line would not be detected.
    PlatformOnly,
    /// Nothing meaningful is measured.
    None,
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Coverage::PlatformAndOs => write!(f, "platform and OS"),
            Coverage::PlatformOnly => write!(f, "platform only — OS is not measured"),
            Coverage::None => write!(f, "none"),
        }
    }
}

/// The value a TPM register holds when it has been extended with nothing but
/// an `EV_SEPARATOR`. Widely known and worth naming, because four of the
/// registers on the first site hold exactly this.
pub const SEPARATOR_ONLY: &str =
    "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969";

const ALL_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Classify what a register set genuinely covers.
///
/// Registers 8, 9 and 11 carry OS measurements: 11 in particular is where a
/// unified kernel image records kernel, initrd and command line.
pub fn classify_coverage(values: &BTreeMap<u32, String>) -> Coverage {
    let meaningful = |idx: u32| -> bool {
        values
            .get(&idx)
            .map(|v| {
                let v = v.to_lowercase();
                v != ALL_ZERO && v != SEPARATOR_ONLY && !v.is_empty()
            })
            .unwrap_or(false)
    };

    let os = meaningful(8) || meaningful(9) || meaningful(11);
    let platform = meaningful(0) || meaningful(2) || meaningful(7);

    match (platform, os) {
        // OS measurements present is the strong case, whether or not the
        // firmware registers also carry values.
        (_, true) => Coverage::PlatformAndOs,
        (true, false) => Coverage::PlatformOnly,
        (false, false) => Coverage::None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyViolation {
    /// Assurance class below the minimum the policy requires.
    AssuranceTooLow {
        required: AssuranceClass,
        found: AssuranceClass,
    },
    /// The manufacturer has not vouched for this chip.
    NotEndorsed,
    /// A register does not match its reference value.
    RegisterMismatch {
        index: u32,
        expected: String,
        found: String,
    },
    /// A register the policy requires was absent from the evidence.
    RegisterMissing { index: u32 },
    /// The platform does not measure enough to satisfy the policy.
    InsufficientCoverage {
        required: Coverage,
        found: Coverage,
    },
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyViolation::AssuranceTooLow { required, found } => write!(
                f,
                "assurance class `{found}` is below the required `{required}`"
            ),
            PolicyViolation::NotEndorsed => {
                write!(f, "no vendor endorsement certificate: the manufacturer has not vouched for this chip")
            }
            PolicyViolation::RegisterMismatch {
                index,
                expected,
                found,
            } => write!(
                f,
                "PCR {index} is {} but should be {}",
                &found[..found.len().min(16)],
                &expected[..expected.len().min(16)]
            ),
            PolicyViolation::RegisterMissing { index } => {
                write!(f, "PCR {index} is required by policy but absent from the evidence")
            }
            PolicyViolation::InsufficientCoverage { required, found } => write!(
                f,
                "measurement coverage is {found}, but the policy requires {required}"
            ),
        }
    }
}

/// What a node must satisfy to be admitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppraisalPolicy {
    pub min_assurance: AssuranceClass,
    /// Whether a vendor endorsement certificate is mandatory.
    pub require_endorsement: bool,
    /// Minimum measurement coverage.
    pub require_coverage: Coverage,
    pub reference: ReferenceValues,
}

impl Default for AppraisalPolicy {
    fn default() -> Self {
        Self {
            min_assurance: AssuranceClass::Tpm,
            require_endorsement: true,
            // Deliberately not the strictest default: demanding
            // `PlatformAndOs` on hardware that does not yet produce it would
            // fail every node, which teaches operators to disable the check.
            require_coverage: Coverage::PlatformOnly,
            reference: ReferenceValues::default(),
        }
    }
}

impl AppraisalPolicy {
    /// Appraise a set of claims, returning every violation rather than the
    /// first. An operator fixing a node should see the whole list.
    pub fn appraise(
        &self,
        assurance: AssuranceClass,
        endorsed: bool,
        registers: &BTreeMap<u32, String>,
    ) -> Vec<PolicyViolation> {
        let mut out = Vec::new();

        if assurance < self.min_assurance {
            out.push(PolicyViolation::AssuranceTooLow {
                required: self.min_assurance,
                found: assurance,
            });
        }
        if self.require_endorsement && !endorsed {
            out.push(PolicyViolation::NotEndorsed);
        }

        let coverage = classify_coverage(registers);
        let rank = |c: Coverage| match c {
            Coverage::None => 0,
            Coverage::PlatformOnly => 1,
            Coverage::PlatformAndOs => 2,
        };
        if rank(coverage) < rank(self.require_coverage) {
            out.push(PolicyViolation::InsufficientCoverage {
                required: self.require_coverage,
                found: coverage,
            });
        }

        for (idx, expect) in &self.reference.expected {
            match registers.get(idx) {
                None => out.push(PolicyViolation::RegisterMissing { index: *idx }),
                Some(found) if !found.eq_ignore_ascii_case(expect) => {
                    out.push(PolicyViolation::RegisterMismatch {
                        index: *idx,
                        expected: expect.clone(),
                        found: found.clone(),
                    })
                }
                Some(_) => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registers as actually read from the first site.
    fn first_site_registers() -> BTreeMap<u32, String> {
        let mut m = BTreeMap::new();
        m.insert(0, "b48ef34fa2ce30a884e6d4b0e4ced00912800ec1eeec2616fb0ee16d7b1e319d".into());
        m.insert(1, SEPARATOR_ONLY.into());
        m.insert(2, "49b00d72c96213e48aeeaee483bd66e4ed05d2dcf4b04d081009bf3d778ef3c5".into());
        m.insert(3, SEPARATOR_ONLY.into());
        m.insert(4, SEPARATOR_ONLY.into());
        m.insert(7, "b3ea0c39179c6e705d8811bd1d57e9e1ffa1cc69845e06d5d9c58e8e55d6fda7".into());
        m.insert(8, ALL_ZERO.into());
        m.insert(9, ALL_ZERO.into());
        m.insert(11, ALL_ZERO.into());
        m
    }

    #[test]
    fn the_first_site_measures_the_platform_but_not_the_os() {
        assert_eq!(
            classify_coverage(&first_site_registers()),
            Coverage::PlatformOnly
        );
    }

    #[test]
    fn a_uki_boot_reaches_full_coverage() {
        let mut m = first_site_registers();
        m.insert(11, "aa".repeat(32));
        assert_eq!(classify_coverage(&m), Coverage::PlatformAndOs);
    }

    #[test]
    fn separator_only_registers_are_not_evidence() {
        let mut m = BTreeMap::new();
        m.insert(0, SEPARATOR_ONLY.to_string());
        m.insert(11, SEPARATOR_ONLY.to_string());
        assert_eq!(classify_coverage(&m), Coverage::None);
    }

    #[test]
    fn demanding_os_coverage_fails_on_this_hardware_today() {
        let policy = AppraisalPolicy {
            require_coverage: Coverage::PlatformAndOs,
            require_endorsement: true,
            ..Default::default()
        };
        let v = policy.appraise(AssuranceClass::Tpm, true, &first_site_registers());
        assert!(v.contains(&PolicyViolation::InsufficientCoverage {
            required: Coverage::PlatformAndOs,
            found: Coverage::PlatformOnly
        }));
    }

    #[test]
    fn the_default_policy_admits_the_first_site() {
        let policy = AppraisalPolicy::default();
        let v = policy.appraise(AssuranceClass::Tpm, true, &first_site_registers());
        assert!(v.is_empty(), "unexpected violations: {v:?}");
    }

    #[test]
    fn a_software_identity_is_refused_by_default() {
        let policy = AppraisalPolicy::default();
        let v = policy.appraise(AssuranceClass::Soft, false, &first_site_registers());
        assert!(v.contains(&PolicyViolation::AssuranceTooLow {
            required: AssuranceClass::Tpm,
            found: AssuranceClass::Soft
        }));
        assert!(v.contains(&PolicyViolation::NotEndorsed));
    }

    #[test]
    fn drift_in_a_referenced_register_is_caught() {
        let mut expected = BTreeMap::new();
        expected.insert(0, "b48ef34fa2ce30a884e6d4b0e4ced00912800ec1eeec2616fb0ee16d7b1e319d".to_string());
        let policy = AppraisalPolicy {
            reference: ReferenceValues::derived(expected),
            ..Default::default()
        };
        let mut drifted = first_site_registers();
        drifted.insert(0, "ff".repeat(32));
        let v = policy.appraise(AssuranceClass::Tpm, true, &drifted);
        assert!(matches!(v[0], PolicyViolation::RegisterMismatch { index: 0, .. }));
    }

    #[test]
    fn a_required_register_that_is_absent_is_reported() {
        let mut expected = BTreeMap::new();
        expected.insert(11, "aa".repeat(32));
        let policy = AppraisalPolicy {
            reference: ReferenceValues::derived(expected),
            ..Default::default()
        };
        let mut regs = first_site_registers();
        regs.remove(&11);
        let v = policy.appraise(AssuranceClass::Tpm, true, &regs);
        assert!(v.contains(&PolicyViolation::RegisterMissing { index: 11 }));
    }

    #[test]
    fn all_violations_are_reported_not_just_the_first() {
        let policy = AppraisalPolicy::default();
        let v = policy.appraise(AssuranceClass::Soft, false, &BTreeMap::new());
        assert!(v.len() >= 3, "expected several violations, got {v:?}");
    }

    #[test]
    fn derived_and_observed_references_are_distinguishable() {
        assert!(ReferenceValues::derived(BTreeMap::new()).derived);
        assert!(!ReferenceValues::observed(BTreeMap::new()).derived);
    }
}
