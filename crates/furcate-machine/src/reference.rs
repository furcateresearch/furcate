//! Pre-computed reference values from unified kernel images.
//!
//! This is the most useful thing the proving ground unlocks. A unified kernel
//! image bundles kernel, initrd, command line and os-release into one signed
//! binary, and the boot stub measures its sections into PCR 11 in a canonical
//! order. That means the expected register value can be computed from the
//! image itself, before the machine ever boots.
//!
//! Appraisal stops being "boot it once and bless whatever appeared" and
//! becomes "which signed images are permitted" — the difference between a
//! reference value and a rumour.

use sha2::{Digest, Sha256};

/// The measurable sections of a unified kernel image, in canonical order.
///
/// Order is fixed by the specification and matters: a register extend is a
/// hashchain, so measuring the same sections in a different order yields a
/// different value.
pub const SECTION_ORDER: &[&str] = &[
    ".linux",
    ".osrel",
    ".cmdline",
    ".initrd",
    ".splash",
    ".dtb",
    ".uname",
    ".sbat",
    ".pcrpkey",
];

/// Contents of the sections that will be measured.
#[derive(Clone, Debug, Default)]
pub struct UkiSections {
    sections: Vec<(String, Vec<u8>)>,
}

impl UkiSections {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a section. Unknown names are accepted but will not be measured,
    /// mirroring a stub that only measures the sections it knows.
    pub fn with(mut self, name: &str, content: impl Into<Vec<u8>>) -> Self {
        self.sections.push((name.to_string(), content.into()));
        self
    }

    fn get(&self, name: &str) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.as_slice())
    }

    /// Which known sections are present, in canonical order.
    pub fn measured_sections(&self) -> Vec<&'static str> {
        SECTION_ORDER
            .iter()
            .copied()
            .filter(|n| self.get(n).is_some())
            .collect()
    }
}

/// Compute the register value a UKI will produce.
///
/// Each present section is measured in canonical order, extending the register
/// exactly as the chip would: `PCR ← H(PCR ‖ H(section))`.
pub fn expected_pcr11(sections: &UkiSections) -> [u8; 32] {
    let mut pcr = [0u8; 32];
    for name in SECTION_ORDER {
        let Some(content) = sections.get(name) else {
            continue;
        };
        // The stub measures the section content; the digest of that is what
        // gets extended.
        let section_digest: [u8; 32] = Sha256::digest(content).into();
        let mut h = Sha256::new();
        h.update(pcr);
        h.update(section_digest);
        pcr = h.finalize().into();
    }
    pcr
}

/// Hex form, for comparing against what a machine reports.
pub fn expected_pcr11_hex(sections: &UkiSections) -> String {
    hex::encode(expected_pcr11(sections))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> UkiSections {
        UkiSections::new()
            .with(".linux", b"kernel-bytes".to_vec())
            .with(".osrel", b"ID=ubuntu".to_vec())
            .with(".cmdline", b"root=/dev/nvme0n1p2 ro".to_vec())
            .with(".initrd", b"initrd-bytes".to_vec())
    }

    #[test]
    fn the_same_image_always_predicts_the_same_value() {
        assert_eq!(expected_pcr11(&image()), expected_pcr11(&image()));
    }

    #[test]
    fn an_empty_image_leaves_the_register_at_zero() {
        assert_eq!(expected_pcr11(&UkiSections::new()), [0u8; 32]);
    }

    #[test]
    fn changing_the_kernel_changes_the_prediction() {
        let other = UkiSections::new()
            .with(".linux", b"different-kernel".to_vec())
            .with(".osrel", b"ID=ubuntu".to_vec())
            .with(".cmdline", b"root=/dev/nvme0n1p2 ro".to_vec())
            .with(".initrd", b"initrd-bytes".to_vec());
        assert_ne!(expected_pcr11(&image()), expected_pcr11(&other));
    }

    #[test]
    fn changing_the_command_line_changes_the_prediction() {
        // The attack this closes: same kernel, but booted with different
        // arguments.
        let tampered = UkiSections::new()
            .with(".linux", b"kernel-bytes".to_vec())
            .with(".osrel", b"ID=ubuntu".to_vec())
            .with(".cmdline", b"root=/dev/nvme0n1p2 ro init=/bin/sh".to_vec())
            .with(".initrd", b"initrd-bytes".to_vec());
        assert_ne!(expected_pcr11(&image()), expected_pcr11(&tampered));
    }

    #[test]
    fn changing_the_initrd_changes_the_prediction() {
        let tampered = UkiSections::new()
            .with(".linux", b"kernel-bytes".to_vec())
            .with(".osrel", b"ID=ubuntu".to_vec())
            .with(".cmdline", b"root=/dev/nvme0n1p2 ro".to_vec())
            .with(".initrd", b"backdoored-initrd".to_vec());
        assert_ne!(expected_pcr11(&image()), expected_pcr11(&tampered));
    }

    #[test]
    fn section_order_is_canonical_not_insertion_order() {
        // Built in a different insertion order, the prediction must match:
        // the stub measures in specification order regardless.
        let reordered = UkiSections::new()
            .with(".initrd", b"initrd-bytes".to_vec())
            .with(".cmdline", b"root=/dev/nvme0n1p2 ro".to_vec())
            .with(".linux", b"kernel-bytes".to_vec())
            .with(".osrel", b"ID=ubuntu".to_vec());
        assert_eq!(expected_pcr11(&image()), expected_pcr11(&reordered));
    }

    #[test]
    fn omitting_a_section_is_distinguishable_from_emptying_it() {
        let empty_cmdline = UkiSections::new()
            .with(".linux", b"kernel-bytes".to_vec())
            .with(".cmdline", Vec::new());
        let no_cmdline = UkiSections::new().with(".linux", b"kernel-bytes".to_vec());
        assert_ne!(
            expected_pcr11(&empty_cmdline),
            expected_pcr11(&no_cmdline)
        );
    }

    #[test]
    fn measured_sections_are_reported_in_canonical_order() {
        assert_eq!(
            image().measured_sections(),
            vec![".linux", ".osrel", ".cmdline", ".initrd"]
        );
    }

    #[test]
    fn the_prediction_is_never_a_separator_or_zero_for_a_real_image() {
        let hex = expected_pcr11_hex(&image());
        assert_ne!(hex, "00".repeat(32));
        assert_eq!(hex.len(), 64);
    }
}
