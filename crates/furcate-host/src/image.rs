//! What this machine is supposed to be.
//!
//! Everything else in this crate observes a node. This describes it: which
//! operating system it is running, how strongly that is pinned down, and
//! whether what is running still matches what was recorded. Without it Furcate
//! governs a machine that something else defines, which is the difference
//! between a monitor and an operating system.
//!
//! ## Assurance is graded, because most machines are not image-based
//!
//! The direction of travel is image-based hosts — an OCI image containing the
//! kernel, the initramfs and the whole root filesystem, updated atomically and
//! rolled back the same way. That is where this should end up. It is not where
//! most machines are, including these ones, and a module that only worked on
//! the destination would be a module that reported nothing about the fleet it
//! was written for.
//!
//! So identity is graded the same way the wake path is:
//!
//! - **Unmanaged** — a package-based system. There is an identity, it just
//!   moves whenever anything is installed, and nothing declares what it should
//!   be.
//! - **Pinned** — a baseline was recorded, so drift from it is detectable even
//!   though the OS is still assembled from packages. Reachable today, on this
//!   hardware, without reinstalling anything.
//! - **Imaged** — the running system is a content-addressed image, so identity
//!   is a digest rather than a description.
//! - **Measured** — imaged *and* the boot chain is measured into the TPM, so
//!   the identity is attested rather than self-reported.
//!
//! Each level is a claim about what a comparison would catch, and the levels
//! are ordered so nothing can accidentally report more assurance than it has.
//!
//! ## The kernel gap, stated as a state rather than a footnote
//!
//! On this hardware PCR 11 reads zero, which means the boot chain is measured
//! up to the firmware and stops. Attestation here detects a firmware change and
//! would **not** detect a swapped kernel or initramfs. That has been known and
//! recorded in prose; it is reported here as a field, because a limitation that
//! lives in a document is one that stops being read.
//!
//! What closes it is a unified kernel image measured into PCR 11 by the boot
//! stub — one piece of work that yields both an image identity and the missing
//! attestation coverage, which is why the two live in the same module.

use serde::{Deserialize, Serialize};

/// How firmly this machine's operating system is pinned down.
///
/// Ordered: each level implies the ones before it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    /// Assembled from packages, with nothing declaring what it should be.
    #[default]
    Unmanaged,
    /// A baseline exists, so drift is detectable.
    Pinned,
    /// The running system is a content-addressed image.
    Imaged,
    /// Imaged, and the boot chain is measured into the TPM.
    Measured,
}

impl Assurance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Assurance::Unmanaged => "unmanaged",
            Assurance::Pinned => "pinned",
            Assurance::Imaged => "imaged",
            Assurance::Measured => "measured",
        }
    }

    /// Whether a changed kernel would be detected.
    ///
    /// The question that matters, and the one a version string cannot answer:
    /// a machine can report the kernel it *thinks* it booted while running
    /// something else entirely, and only a measurement taken by the firmware
    /// closes that.
    pub fn detects_a_swapped_kernel(&self) -> bool {
        *self == Assurance::Measured
    }

    /// What would raise this a level.
    pub fn next_step(&self) -> Option<&'static str> {
        match self {
            Assurance::Unmanaged => Some(
                "record a baseline, so a changed kernel, command line or package set is \
                 something the machine can notice about itself",
            ),
            Assurance::Pinned => Some(
                "move to an image-based host — bootc or OSTree — so identity is a digest \
                 rather than a description that happens to match",
            ),
            Assurance::Imaged => Some(
                "boot a unified kernel image so the stub measures it into PCR 11; until then \
                 the identity is self-reported and a swapped kernel is invisible",
            ),
            Assurance::Measured => None,
        }
    }
}

/// What the machine says it is.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Image {
    /// From `/etc/os-release`.
    pub os_id: Option<String>,
    pub os_version: Option<String>,
    /// Running kernel, from `uname`.
    pub kernel: Option<String>,
    /// The kernel command line, which decides a great deal about what the
    /// machine actually is and is trivially changed.
    pub cmdline: Option<String>,
    /// Content-addressed image digest, where the host is image-based.
    pub digest: Option<String>,
    /// The image reference it was deployed from, where there is one.
    pub reference: Option<String>,
    /// Whether a rollback target exists. Image-based hosts keep the previous
    /// deployment; package-based ones do not, and the difference decides
    /// whether an update is safe to attempt unattended.
    pub rollback_available: bool,
    /// Whether the boot chain is measured past the firmware.
    pub boot_measured: bool,
    pub assurance: Assurance,
}

/// A recorded baseline, and what has moved since.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Drift {
    pub changed: Vec<Changed>,
    /// When the baseline was taken.
    pub baseline_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changed {
    pub field: String,
    pub was: String,
    pub now: String,
}

impl Drift {
    pub fn is_clean(&self) -> bool {
        self.changed.is_empty()
    }

    /// Whether anything changed that a reboot would be needed to explain.
    ///
    /// A changed kernel or command line means the machine that is running is
    /// not the machine that was recorded, whatever the package set says.
    pub fn touches_the_boot_path(&self) -> bool {
        self.changed
            .iter()
            .any(|c| c.field == "kernel" || c.field == "cmdline" || c.field == "digest")
    }
}

/// Compare a running image against a recorded one.
///
/// Field by field rather than by hashing the whole thing, because "something
/// changed" is not actionable and "the kernel command line changed" is. A
/// single digest over the lot would be cheaper and would answer the less useful
/// question.
pub fn drift(baseline: &Image, now: &Image, baseline_at: u64) -> Drift {
    let mut changed = Vec::new();
    let mut cmp = |field: &str, a: &Option<String>, b: &Option<String>| {
        if a != b {
            changed.push(Changed {
                field: field.to_string(),
                // A field that was absent and is now present is a change worth
                // reporting, so absence is rendered rather than skipped.
                was: a.clone().unwrap_or_else(|| "(absent)".into()),
                now: b.clone().unwrap_or_else(|| "(absent)".into()),
            });
        }
    };
    cmp("os_id", &baseline.os_id, &now.os_id);
    cmp("os_version", &baseline.os_version, &now.os_version);
    cmp("kernel", &baseline.kernel, &now.kernel);
    cmp("cmdline", &baseline.cmdline, &now.cmdline);
    cmp("digest", &baseline.digest, &now.digest);
    cmp("reference", &baseline.reference, &now.reference);
    Drift { changed, baseline_at }
}

/// Parse `/etc/os-release`.
pub fn parse_os_release(text: &str) -> (Option<String>, Option<String>) {
    let get = |key: &str| -> Option<String> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    };
    (get("ID"), get("VERSION_ID"))
}

/// Parse `bootc status --json`.
///
/// The shape is `{"status":{"booted":{"image":{"image":{"image":"..."},
/// "imageDigest":"sha256:..."}},"rollback":{...}}}`. Only the three fields that
/// establish identity are read; the rest is ignored rather than interpreted,
/// which is most of why reading somebody else's JSON is safe here.
pub fn parse_bootc(v: &serde_json::Value) -> Option<(String, Option<String>, bool)> {
    let status = v.get("status")?;
    let booted = status.get("booted")?;
    let image = booted.get("image")?;
    let digest = image.get("imageDigest").and_then(|d| d.as_str())?.to_string();
    let reference = image
        .get("image")
        .and_then(|i| i.get("image"))
        .and_then(|i| i.as_str())
        .map(String::from);
    // A rollback deployment is what makes an unattended update recoverable.
    let rollback = status.get("rollback").is_some_and(|r| !r.is_null());
    Some((digest, reference, rollback))
}

/// Parse `ostree admin status`.
///
/// The booted deployment is the line marked with `*`. Falling back to the first
/// line would silently describe the *other* deployment on a machine that had
/// been rolled back, which is exactly when somebody is looking.
pub fn parse_ostree(text: &str) -> Option<(String, bool)> {
    let mut booted: Option<String> = None;
    let mut deployments = 0usize;
    // A deployment header is an unindented line; its details are indented
    // beneath it. The commit is what identifies the deployment, and it lives on
    // one of those detail lines rather than on the header.
    let mut in_booted = false;

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let is_header = !line.starts_with("  ") || line.trim_start().starts_with('*');
        if is_header {
            deployments += 1;
            in_booted = line.trim_start().starts_with('*');
            continue;
        }
        if in_booted && booted.is_none() {
            if let Some(commit) = line.trim().strip_prefix("Commit:") {
                booted = Some(commit.trim().to_string());
            }
        }
    }
    booted.map(|b| (b, deployments > 1))
}

/// Decide the assurance level from what was found.
///
/// Written as one function so the ordering cannot drift between callers: a
/// machine must never be able to report `Measured` because two separate places
/// each thought the other had checked something.
pub fn assurance_of(digest: Option<&str>, boot_measured: bool, has_baseline: bool) -> Assurance {
    match (digest.is_some(), boot_measured) {
        (true, true) => Assurance::Measured,
        (true, false) => Assurance::Imaged,
        (false, _) if has_baseline => Assurance::Pinned,
        _ => Assurance::Unmanaged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ubuntu() -> Image {
        Image {
            os_id: Some("ubuntu".into()),
            os_version: Some("26.04".into()),
            kernel: Some("7.0.0-29-generic".into()),
            cmdline: Some("BOOT_IMAGE=/vmlinuz root=UUID=abc ro quiet".into()),
            assurance: Assurance::Pinned,
            ..Image::default()
        }
    }

    #[test]
    fn assurance_is_ordered_so_nothing_overstates_itself() {
        assert!(Assurance::Unmanaged < Assurance::Pinned);
        assert!(Assurance::Pinned < Assurance::Imaged);
        assert!(Assurance::Imaged < Assurance::Measured);
    }

    #[test]
    fn only_a_measured_boot_catches_a_swapped_kernel() {
        // A machine can report the kernel it thinks it booted while running
        // something else, and only a measurement taken by the firmware closes
        // that. This is the site's actual open gap.
        for a in [Assurance::Unmanaged, Assurance::Pinned, Assurance::Imaged] {
            assert!(!a.detects_a_swapped_kernel(), "{a:?}");
        }
        assert!(Assurance::Measured.detects_a_swapped_kernel());
    }

    #[test]
    fn every_level_short_of_measured_names_its_next_step() {
        for a in [Assurance::Unmanaged, Assurance::Pinned, Assurance::Imaged] {
            assert!(a.next_step().is_some(), "{a:?}");
        }
        assert!(Assurance::Measured.next_step().is_none());
    }

    #[test]
    fn an_image_without_a_measured_boot_is_imaged_and_not_measured() {
        // The distinction the whole grading exists for: a content-addressed
        // identity that the machine reports about itself is still self-reported.
        assert_eq!(assurance_of(Some("sha256:abc"), false, true), Assurance::Imaged);
        assert_eq!(assurance_of(Some("sha256:abc"), true, true), Assurance::Measured);
    }

    #[test]
    fn a_package_based_machine_with_a_baseline_is_pinned_not_unmanaged() {
        // Reachable today on ordinary hardware, and worth distinguishing: a
        // recorded baseline means a changed kernel is something the machine can
        // notice about itself.
        assert_eq!(assurance_of(None, false, true), Assurance::Pinned);
        assert_eq!(assurance_of(None, false, false), Assurance::Unmanaged);
    }

    #[test]
    fn a_measured_boot_alone_does_not_confer_an_image() {
        // Measuring a boot chain says the kernel is what was measured; it says
        // nothing about the root filesystem being a known artefact.
        assert_eq!(assurance_of(None, true, true), Assurance::Pinned);
    }

    #[test]
    fn drift_names_the_field_rather_than_saying_something_changed() {
        // "Something changed" is not actionable. "The kernel command line
        // changed" is.
        let mut now = ubuntu();
        now.kernel = Some("7.0.0-31-generic".into());
        let d = drift(&ubuntu(), &now, 1000);
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].field, "kernel");
        assert_eq!(d.changed[0].was, "7.0.0-29-generic");
        assert!(d.touches_the_boot_path());
    }

    #[test]
    fn an_unchanged_machine_reports_clean() {
        assert!(drift(&ubuntu(), &ubuntu(), 1000).is_clean());
    }

    #[test]
    fn a_field_appearing_from_nothing_is_a_change() {
        // A machine that has just become image-based has changed, and skipping
        // absent-to-present would hide the most significant transition there is.
        let mut now = ubuntu();
        now.digest = Some("sha256:abc".into());
        let d = drift(&ubuntu(), &now, 1000);
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].was, "(absent)");
        assert!(d.touches_the_boot_path());
    }

    #[test]
    fn a_package_upgrade_does_not_read_as_a_boot_change() {
        // Both matter; only one means the running machine is not the recorded
        // one, and conflating them makes every routine upgrade look alarming.
        let mut now = ubuntu();
        now.os_version = Some("26.10".into());
        let d = drift(&ubuntu(), &now, 1000);
        assert!(!d.is_clean());
        assert!(!d.touches_the_boot_path());
    }

    #[test]
    fn os_release_parses_including_the_quoting() {
        let text = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"\nID=ubuntu\nVERSION_ID=\"26.04\"\n";
        assert_eq!(parse_os_release(text), (Some("ubuntu".into()), Some("26.04".into())));
    }

    #[test]
    fn an_empty_os_release_yields_nothing_rather_than_empty_strings() {
        // An empty string would compare unequal to absent and produce drift on
        // a machine where nothing changed.
        let (id, v) = parse_os_release("ID=\nVERSION_ID=\"\"\n");
        assert!(id.is_none());
        assert!(v.is_none());
    }

    #[test]
    fn bootc_status_yields_a_digest_a_reference_and_a_rollback() {
        let v = json!({
            "status": {
                "booted": { "image": {
                    "image": { "image": "quay.io/example/node:latest" },
                    "imageDigest": "sha256:deadbeef"
                }},
                "rollback": { "image": { "imageDigest": "sha256:cafe" } }
            }
        });
        let (digest, reference, rollback) = parse_bootc(&v).unwrap();
        assert_eq!(digest, "sha256:deadbeef");
        assert_eq!(reference.as_deref(), Some("quay.io/example/node:latest"));
        assert!(rollback, "a rollback target is what makes an update recoverable");
    }

    #[test]
    fn a_bootc_host_with_no_rollback_says_so() {
        let v = json!({
            "status": { "booted": { "image": { "imageDigest": "sha256:deadbeef" } } }
        });
        let (_, _, rollback) = parse_bootc(&v).unwrap();
        assert!(!rollback);
    }

    #[test]
    fn a_non_bootc_machine_parses_to_nothing_rather_than_a_default() {
        assert!(parse_bootc(&json!({})).is_none());
        assert!(parse_bootc(&json!({ "status": {} })).is_none());
    }

    #[test]
    fn ostree_reports_the_booted_deployment_not_the_first_one() {
        // On a machine that has been rolled back these differ, and that is
        // precisely when somebody is looking.
        let text = "\
  fedora:fedora/x86_64/coreos/stable
                   Version: 41.20250101.0
                   Commit: aaaa1111
* fedora:fedora/x86_64/coreos/stable
                   Version: 40.20241201.0
                   Commit: bbbb2222";
        let (booted, has_rollback) = parse_ostree(text).unwrap();
        assert_eq!(booted, "bbbb2222");
        assert!(has_rollback, "two deployments means one to go back to");
    }

    #[test]
    fn ostree_output_with_no_booted_marker_yields_nothing() {
        assert!(parse_ostree("  some:ref\n     Version: 1").is_none());
    }
}
