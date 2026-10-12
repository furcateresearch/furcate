//! Custody of virtual TPM state.
//!
//! A virtual TPM is only as trustworthy as whatever vouches for it. swtpm
//! keeps each guest's TPM state — keys and register values — in a file on the
//! host, and that file *is* the guest's root of trust. Left in the clear it is
//! forgeable and the guest's attestation means nothing.
//!
//! So Furcate seals each guest's vTPM state to the host's physical TPM, and
//! the chain runs from real silicon, through the host's own measured boot, to
//! the vTPM, to the guest's measurements. In RATS terms the host is the lead
//! attester of a composite device, and a guest's trustworthiness depends on
//! its host's.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum VtpmError {
    /// State was not sealed to the host root of trust.
    Unsealed,
    /// The sealed state does not belong to this host.
    WrongHost { expected: String, found: String },
    /// The state file has been altered.
    Tampered,
    /// The guest was restored from a snapshot and has not re-enrolled.
    IdentityTerminated,
}

impl fmt::Display for VtpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VtpmError::Unsealed => write!(
                f,
                "vTPM state is not sealed to a host root of trust, so the guest's \
                 attestation proves nothing"
            ),
            VtpmError::WrongHost { expected, found } => write!(
                f,
                "vTPM state was sealed to host `{found}` but is being opened on `{expected}`"
            ),
            VtpmError::Tampered => write!(f, "vTPM state has been altered since it was sealed"),
            VtpmError::IdentityTerminated => write!(
                f,
                "this guest was restored from a snapshot; it must re-enrol with a fresh \
                 identity before it can attest"
            ),
        }
    }
}

impl std::error::Error for VtpmError {}

/// Sealed vTPM state belonging to one guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtpmCustody {
    pub guest_id: String,
    /// Host whose physical TPM the state is sealed to.
    pub host_node: String,
    /// Digest binding the state to the host and guest.
    pub seal_digest: String,
    /// Incremented on every restore, so a resumed guest is distinguishable
    /// from the one that was snapshotted.
    pub generation: u64,
    /// Whether the current generation has completed re-enrollment.
    pub enrolled: bool,
}

impl VtpmCustody {
    /// Seal fresh vTPM state for a guest on a host.
    pub fn seal(guest_id: &str, host_node: &str, state: &[u8], host_secret: &[u8]) -> Self {
        Self {
            guest_id: guest_id.to_string(),
            host_node: host_node.to_string(),
            seal_digest: Self::compute(guest_id, host_node, state, host_secret),
            generation: 0,
            enrolled: true,
        }
    }

    fn compute(guest_id: &str, host_node: &str, state: &[u8], host_secret: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b"furcate/machine/vtpm-seal/v1");
        h.update(host_secret);
        h.update((host_node.len() as u64).to_be_bytes());
        h.update(host_node.as_bytes());
        h.update((guest_id.len() as u64).to_be_bytes());
        h.update(guest_id.as_bytes());
        h.update(state);
        hex::encode(h.finalize())
    }

    /// Open the state on a host, checking the whole chain.
    pub fn open(
        &self,
        on_host: &str,
        state: &[u8],
        host_secret: &[u8],
    ) -> Result<(), VtpmError> {
        if self.host_node != on_host {
            return Err(VtpmError::WrongHost {
                expected: on_host.to_string(),
                found: self.host_node.clone(),
            });
        }
        if !self.enrolled {
            return Err(VtpmError::IdentityTerminated);
        }
        let expect = Self::compute(&self.guest_id, &self.host_node, state, host_secret);
        if expect != self.seal_digest {
            return Err(VtpmError::Tampered);
        }
        Ok(())
    }

    /// Mark that this guest was restored from a snapshot.
    ///
    /// Resuming a guest more than once is insecure by construction: the
    /// entropy pool is captured verbatim, so clones emit identical nonces and
    /// tokens. For attestation the consequence is worse than duplicate
    /// identifiers — a restored clone carries the same vTPM state and can
    /// replay a quote that was fresh once, so two guests answer to one
    /// identity. Restore therefore *terminates* identity: the guest gets a
    /// fresh vTPM, re-enrols, and reseeds entropy before it is admitted.
    pub fn restored_from_snapshot(&mut self) -> &mut Self {
        self.generation += 1;
        self.enrolled = false;
        self
    }

    /// Complete re-enrollment after a restore with fresh state.
    pub fn reenroll(&mut self, fresh_state: &[u8], host_secret: &[u8]) -> &mut Self {
        self.seal_digest = Self::compute(
            &self.guest_id,
            &self.host_node,
            fresh_state,
            host_secret,
        );
        self.enrolled = true;
        self
    }

    /// Whether this guest may currently attest.
    pub fn may_attest(&self) -> bool {
        self.enrolled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"host-tpm-sealed-secret";

    fn custody() -> VtpmCustody {
        VtpmCustody::seal("guest-1", "node-a", b"tpm-state-blob", SECRET)
    }

    #[test]
    fn sealed_state_opens_on_its_own_host() {
        let c = custody();
        assert_eq!(c.open("node-a", b"tpm-state-blob", SECRET), Ok(()));
    }

    #[test]
    fn state_does_not_open_on_a_different_host() {
        let c = custody();
        assert_eq!(
            c.open("node-b", b"tpm-state-blob", SECRET),
            Err(VtpmError::WrongHost {
                expected: "node-b".into(),
                found: "node-a".into()
            })
        );
    }

    #[test]
    fn altering_the_state_file_is_detected() {
        let c = custody();
        assert_eq!(
            c.open("node-a", b"tampered-blob", SECRET),
            Err(VtpmError::Tampered)
        );
    }

    #[test]
    fn a_different_host_secret_does_not_open_it() {
        let c = custody();
        assert_eq!(
            c.open("node-a", b"tpm-state-blob", b"wrong-secret"),
            Err(VtpmError::Tampered)
        );
    }

    #[test]
    fn restoring_a_snapshot_terminates_identity() {
        let mut c = custody();
        c.restored_from_snapshot();
        assert!(!c.may_attest());
        assert_eq!(
            c.open("node-a", b"tpm-state-blob", SECRET),
            Err(VtpmError::IdentityTerminated)
        );
    }

    #[test]
    fn a_restored_guest_can_attest_again_only_after_reenrolling() {
        let mut c = custody();
        c.restored_from_snapshot();
        c.reenroll(b"fresh-tpm-state", SECRET);
        assert!(c.may_attest());
        assert_eq!(c.open("node-a", b"fresh-tpm-state", SECRET), Ok(()));
    }

    #[test]
    fn reenrollment_invalidates_the_snapshotted_state() {
        // The whole point: the old blob must not still work, or the clone
        // could keep replaying quotes.
        let mut c = custody();
        c.restored_from_snapshot();
        c.reenroll(b"fresh-tpm-state", SECRET);
        assert_eq!(
            c.open("node-a", b"tpm-state-blob", SECRET),
            Err(VtpmError::Tampered)
        );
    }

    #[test]
    fn generations_distinguish_a_clone_from_its_origin() {
        let mut c = custody();
        assert_eq!(c.generation, 0);
        c.restored_from_snapshot();
        assert_eq!(c.generation, 1);
        c.restored_from_snapshot();
        assert_eq!(c.generation, 2);
    }
}
