//! Native TPM 2.0 backend over the TSS 2.0 Enhanced System API.
//!
//! The `tpm2-tools` backend spawns a process per operation, which is fine for
//! enrollment and inspection and unacceptable for continuous attestation — a
//! site re-quoting every node on an epoch tick would be forking constantly.
//! This backend holds a single ESAPI context instead.
//!
//! Both satisfy [`RootOfTrust`], so node identifiers, enrollment records and
//! everything derived from them carry over unchanged between the two.
//!
//! Requires `libtss2-dev` at build time; enable with the `tss` feature.

use crate::rot::{AssuranceClass, PcrSet, Quote, RootOfTrust};
use anyhow::{anyhow, bail, Context as _, Result};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tss_esapi::abstraction::{ak, ek};
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::abstraction::AsymmetricAlgorithmSelection;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Data, Digest, HashScheme, PcrSelectionListBuilder, PcrSlot, SignatureScheme,
};
use tss_esapi::traits::Marshall;
use tss_esapi::{Context, TctiNameConf};

/// Registers covered by default: firmware, option ROMs, boot configuration and
/// the boot loader.
const DEFAULT_SLOTS: &[PcrSlot] = &[
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
];

fn slot_index(slot: PcrSlot) -> u32 {
    match slot {
        PcrSlot::Slot0 => 0,
        PcrSlot::Slot1 => 1,
        PcrSlot::Slot2 => 2,
        PcrSlot::Slot3 => 3,
        PcrSlot::Slot4 => 4,
        PcrSlot::Slot5 => 5,
        PcrSlot::Slot6 => 6,
        PcrSlot::Slot7 => 7,
        PcrSlot::Slot8 => 8,
        PcrSlot::Slot9 => 9,
        PcrSlot::Slot10 => 10,
        PcrSlot::Slot11 => 11,
        PcrSlot::Slot12 => 12,
        PcrSlot::Slot13 => 13,
        PcrSlot::Slot14 => 14,
        PcrSlot::Slot15 => 15,
        PcrSlot::Slot16 => 16,
        _ => u32::MAX,
    }
}

/// A live ESAPI context with the endorsement and attestation keys loaded.
///
/// The context is not `Sync`, so it lives behind a mutex. Serializing TPM
/// access is required anyway: the chip processes one command at a time, and
/// transient object slots are a shared resource.
pub struct TssNative {
    ctx: Mutex<Context>,
    ek: KeyHandle,
    ak: KeyHandle,
    ak_public: Vec<u8>,
    ek_public: Vec<u8>,
    slots: Vec<PcrSlot>,
}

impl TssNative {
    /// Open the TPM through the in-kernel resource manager.
    pub fn open() -> Result<Self> {
        Self::with_device("device:/dev/tpmrm0")
    }

    pub fn with_device(tcti: &str) -> Result<Self> {
        // Parsed rather than taken from the environment so the caller controls
        // which device is used; the environment is only a fallback.
        let conf: TctiNameConf = tcti
            .parse()
            .or_else(|_| TctiNameConf::from_environment_variable())
            .context("resolving a TCTI configuration")?;
        let mut ctx = Context::new(conf).context("creating an ESAPI context")?;

        // The endorsement key is derived deterministically from the
        // endorsement seed, so this yields the same key on every call and
        // across reboots — which is what makes the node identifier stable.
        let ek = ek::create_ek_object(&mut ctx, AsymmetricAlgorithm::Rsa, None)
            .context("creating the endorsement key")?;
        // Read and marshall the EK public area, flushing the handle if either
        // step fails. See the note below on why leaked handles matter.
        let ek_public = match ctx.read_public(ek) {
            Ok((pub_area, _, _)) => match pub_area.marshall() {
                Ok(bytes) => bytes,
                Err(e) => {
                    let _ = ctx.flush_context(ek.into());
                    return Err(anyhow!("marshalling the EK public area: {e}"));
                }
            },
            Err(e) => {
                let _ = ctx.flush_context(ek.into());
                return Err(anyhow!("reading the EK public area: {e}"));
            }
        };

        // No session is set here on purpose. The endorsement key's auth
        // policy requires a policy session against the endorsement hierarchy,
        // and `create_ak` establishes that itself. Setting a password or HMAC
        // session first overrides it and the chip refuses with an auth error.
        // Everything from here can fail, and a transient handle that is not
        // flushed on the way out stays loaded in the chip. Object slots are a
        // scarce shared resource: leaking them across repeated failed attempts
        // exhausts the TPM, and an exhausted TPM can enter failure mode, which
        // no software path recovers from. So each fallible step flushes the
        // handles it owns before returning the error.
        let created = match ak::create_ak(
            &mut ctx,
            ek,
            HashingAlgorithm::Sha256,
            SignatureSchemeAlgorithm::RsaSsa,
            None,
            None,
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = ctx.flush_context(ek.into());
                return Err(anyhow!("creating the attestation key: {e}"));
            }
        };

        let ak_public = match created.out_public.marshall() {
            Ok(p) => p,
            Err(e) => {
                let _ = ctx.flush_context(ek.into());
                return Err(anyhow!("marshalling the AK public area: {e}"));
            }
        };

        let ak = match ak::load_ak(&mut ctx, ek, None, created.out_private, created.out_public) {
            Ok(h) => h,
            Err(e) => {
                let _ = ctx.flush_context(ek.into());
                return Err(anyhow!("loading the attestation key: {e}"));
            }
        };

        Ok(Self {
            ctx: Mutex::new(ctx),
            ek,
            ak,
            ak_public,
            ek_public,
            slots: DEFAULT_SLOTS.to_vec(),
        })
    }

    pub fn with_slots(mut self, slots: Vec<PcrSlot>) -> Self {
        self.slots = slots;
        self
    }

    fn read_pcrs(&self) -> Result<PcrSet> {
        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &self.slots)
            .build()
            .context("building a PCR selection")?;

        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM context poisoned"))?;
        let (_, selected, digests) = ctx
            .pcr_read(selection)
            .context("reading platform registers")?;

        let mut values = BTreeMap::new();
        // The chip may return fewer digests than requested in one call, so the
        // returned selection is zipped with the digests rather than assuming
        // they line up with what was asked for.
        let mut digests = digests.value().iter();
        for sel in selected.get_selections() {
            for slot in sel.selected() {
                if let Some(d) = digests.next() {
                    values.insert(slot_index(slot), d.value().to_vec());
                }
            }
        }
        if values.is_empty() {
            bail!("the TPM returned no register values");
        }
        Ok(PcrSet {
            bank: "sha256".to_string(),
            values,
        })
    }
}

impl RootOfTrust for TssNative {
    fn assurance(&self) -> AssuranceClass {
        AssuranceClass::Tpm
    }

    fn ek_public(&self) -> Result<Vec<u8>> {
        Ok(self.ek_public.clone())
    }

    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        // Absence is normal and must not be an error: many consumer TPMs ship
        // without a certificate, which weakens the binding rather than voiding
        // it. The verifier records that the manufacturer has not vouched for
        // this chip and appraises accordingly.
        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM context poisoned"))?;
        // The certificate lookup takes a fully-specified algorithm selection
        // rather than a bare family, so the RSA size is named explicitly.
        let selection = AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048);
        match ek::retrieve_ek_pubcert(&mut ctx, selection) {
            Ok(cert) => Ok(Some(cert)),
            Err(_) => Ok(None),
        }
    }

    fn ak_public(&self) -> Result<Vec<u8>> {
        Ok(self.ak_public.clone())
    }

    fn pcrs(&self) -> Result<PcrSet> {
        self.read_pcrs()
    }

    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        if nonce.is_empty() {
            bail!("a quote without a nonce is replayable; supply one");
        }
        let qualifying = Data::try_from(nonce.to_vec())
            .map_err(|e| anyhow!("nonce is not valid qualifying data: {e}"))?;
        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &self.slots)
            .build()
            .context("building a PCR selection")?;

        let pcrs = self.read_pcrs()?;
        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM context poisoned"))?;
        let (attest, signature) = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.quote(
                    self.ak,
                    qualifying,
                    SignatureScheme::RsaSsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    selection,
                )
            })
            .context("producing a quote")?;

        Ok(Quote {
            message: attest.marshall().context("marshalling the attestation")?,
            signature: signature.marshall().context("marshalling the signature")?,
            nonce: nonce.to_vec(),
            pcrs,
        })
    }
}

impl Drop for TssNative {
    fn drop(&mut self) {
        // Transient handles occupy scarce object slots; flushing them keeps
        // concurrent users from failing on slot exhaustion.
        if let Ok(mut ctx) = self.ctx.lock() {
            let _ = ctx.flush_context(self.ak.into());
            let _ = ctx.flush_context(self.ek.into());
        }
    }
}

/// Marker for a digest length check used by callers building policies.
pub fn is_sha256_digest(d: &Digest) -> bool {
    d.value().len() == 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_indices_map_correctly() {
        assert_eq!(slot_index(PcrSlot::Slot0), 0);
        assert_eq!(slot_index(PcrSlot::Slot7), 7);
        assert_eq!(slot_index(PcrSlot::Slot11), 11);
    }

    #[test]
    fn the_default_selection_covers_the_platform_registers() {
        assert_eq!(DEFAULT_SLOTS.len(), 8);
        assert!(DEFAULT_SLOTS.contains(&PcrSlot::Slot7));
    }

    // Opening a real TPM is exercised by `furcatectl identity show --native`
    // against hardware rather than here: a unit test that requires /dev/tpmrm0
    // and `tss` group membership would fail on any machine without a chip,
    // which is most CI.
}
