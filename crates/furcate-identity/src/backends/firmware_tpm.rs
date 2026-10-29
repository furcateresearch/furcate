//! When a firmware TPM counts as a TPM.
//!
//! Jetson AGX Thor, AGX Orin, Orin NX and Orin Nano can run a TPM 2.0 as an
//! OP-TEE trusted application (when the trusted OS is built with it, enabled
//! by fuse, paired with the device key blob and provisioned; a stock module
//! has none). Built from NVIDIA's Jetson Linux r39.2 documentation and tested
//! against fixtures; not run on a device. To Linux it is an ordinary TPM device: `tpm2-tools`
//! reads its endorsement key and it quotes registers that the boot chain
//! extends (MB2 and the trusted OS land in PCR0). Treated naively it would
//! classify [`AssuranceClass::Tpm`] like a discrete chip.
//!
//! It is not automatically one. A discrete TPM's endorsement seed lives in a
//! chip whose manufacturer certifies it; an fTPM's seed is derived inside the
//! secure world, and the secure world is only as trustworthy as the chain that
//! loaded it. Two things have to hold before it is a TPM in the sense the
//! class promises:
//!
//! 1. **Secure boot is fused.** On an unfused development module anyone with
//!    the board can flash a different trusted OS, and the "TPM" is whatever
//!    that OS says it is.
//! 2. **The EK certificate chains to a CA the operator trusts, and is for this
//!    TPM's key** ([`super::ek_bind`]). NVIDIA does
//!    not issue these; the ODM generates them at manufacture with its own CA
//!    (which needs the KDK0 fuse provisioned; `PscOemKdk0` on Thor). There is no global root to
//!    check against, so the operator names the CAs they accept in
//!    [`EK_CA_BUNDLE`] under the node's configuration directory.
//!
//! When both hold, the fTPM is [`AssuranceClass::Tpm`]. Otherwise it is
//! [`AssuranceClass::Tee`]: a key held by the secure world, which is real
//! possession, without the vouching. The reason travels with the class.
//!
//! Fuse state is read read-only by `furcate_host::tegra_fuse` (sysfs nodes,
//! then NVIDIA's `nv_fuse_read.sh`). Unknown is treated exactly like unfused,
//! because a class that is raised on an assumption is the failure this module
//! exists to prevent.

use crate::rot::{AssuranceClass, PcrSet, Quote, RootOfTrust};
use crate::NodeId;
use anyhow::Result;
use furcate_host::board::SecureBoot;
use std::path::Path;
use std::process::Command;

/// File name, under the node's configuration directory, of the PEM bundle of
/// CAs whose EK certificates the operator accepts: the TPM manufacturers'
/// roots, and for firmware TPMs the ODM's. It decides a firmware TPM's class,
/// and for every TPM whether it is reported as endorsed.
pub const EK_CA_BUNDLE: &str = "ek-trusted-ca.pem";

/// The outcome of checking an EK certificate against the operator's CAs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EkChain {
    Verified { bundle: String },
    NoCertificate,
    NoTrustedCa,
    Rejected { why: String },
}

impl EkChain {
    pub fn describe(&self) -> String {
        match self {
            EkChain::Verified { bundle } => format!("EK certificate chains to a CA in {bundle}"),
            EkChain::NoCertificate => "the TPM holds no EK certificate".to_string(),
            EkChain::NoTrustedCa => format!("no operator CA bundle ({EK_CA_BUNDLE}) is configured"),
            EkChain::Rejected { why } => format!("EK certificate did not verify: {why}"),
        }
    }
}

/// Classify a firmware TPM from the two facts above.
pub fn classify(secure_boot: &SecureBoot, chain: &EkChain) -> (AssuranceClass, String) {
    let boot = match secure_boot {
        SecureBoot::Enforced { detail } => Ok(format!("secure boot fused ({detail})")),
        SecureBoot::Off { detail } => Err(format!("unfused development part ({detail})")),
        SecureBoot::Configured { detail } => Err(format!("secure boot configured but not fused ({detail})")),
        SecureBoot::Unknown { why } => Err(format!("secure boot fuse state unknown: {why}")),
    };
    match (boot, chain) {
        (Ok(boot), EkChain::Verified { .. }) => {
            (AssuranceClass::Tpm, format!("firmware TPM: {boot}; {}", chain.describe()))
        }
        (Ok(boot), _) => (
            AssuranceClass::Tee,
            format!("firmware TPM held as TEE: {boot}, but {}", chain.describe()),
        ),
        (Err(boot), _) => (
            AssuranceClass::Tee,
            format!("firmware TPM held as TEE: {boot}; {}", chain.describe()),
        ),
    }
}

/// Verify a DER EK certificate against a PEM CA bundle with `openssl`.
///
/// `work` is a scratch directory the caller owns.
pub fn verify_ek_chain(cert_der: Option<&[u8]>, bundle: Option<&Path>, work: &Path) -> EkChain {
    let Some(bundle) = bundle.filter(|b| b.exists()) else {
        return EkChain::NoTrustedCa;
    };
    let Some(der) = cert_der.filter(|c| !c.is_empty()) else {
        return EkChain::NoCertificate;
    };
    let der_path = work.join("ek-cert.der");
    let pem_path = work.join("ek-cert.pem");
    if let Err(e) = std::fs::write(&der_path, der) {
        return EkChain::Rejected { why: format!("writing the certificate: {e}") };
    }
    let first_line = |o: &std::process::Output| {
        let text = format!("{}{}", String::from_utf8_lossy(&o.stderr), String::from_utf8_lossy(&o.stdout));
        text.lines().find(|l| !l.trim().is_empty()).unwrap_or("no output").trim().to_string()
    };
    let convert = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(&der_path)
        .arg("-out")
        .arg(&pem_path)
        .output();
    match convert {
        Ok(o) if o.status.success() => {}
        Ok(o) => return EkChain::Rejected { why: format!("not an X.509 certificate: {}", first_line(&o)) },
        Err(e) => return EkChain::Rejected { why: format!("openssl is not available: {e}") },
    }
    match Command::new("openssl").arg("verify").arg("-CAfile").arg(bundle).arg(&pem_path).output() {
        Ok(o) if o.status.success() => EkChain::Verified { bundle: bundle.display().to_string() },
        Ok(o) => EkChain::Rejected { why: first_line(&o) },
        Err(e) => EkChain::Rejected { why: format!("openssl is not available: {e}") },
    }
}

/// The issuer of a DER EK certificate, as `openssl` prints it.
///
/// `work` is a scratch directory the caller owns. `None` when the certificate
/// cannot be read; the caller treats that as "no signal", not as a verdict.
pub fn ek_issuer(cert_der: &[u8], work: &Path) -> Option<String> {
    let der_path = work.join("ek-issuer.der");
    std::fs::write(&der_path, cert_der).ok()?;
    let out = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-noout", "-issuer", "-in"])
        .arg(&der_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(text.strip_prefix("issuer=").map(str::trim).unwrap_or(&text).to_string())
}

/// Why an EK certificate's issuer marks the TPM as an emulator, if it does.
///
/// `swtpm_setup --create-ek-cert` signs the EK with `swtpm-localca`, a CA it
/// generates on the machine itself (`CN=swtpm-localca`, under
/// `CN=swtpm-localca-rootca`). No manufacturer issues under that name.
pub fn emulator_issuer(issuer: &str) -> Option<String> {
    issuer
        .to_ascii_lowercase()
        .contains("swtpm")
        .then(|| format!("its EK certificate was issued by the swtpm local CA ({issuer})"))
}

/// A root of trust whose class was decided by policy rather than by the
/// backend's own claim.
pub struct Classified<R> {
    inner: R,
    class: AssuranceClass,
    reason: String,
}

impl<R: RootOfTrust> Classified<R> {
    pub fn new(inner: R, class: AssuranceClass, reason: String) -> Self {
        // Policy may lower a backend's class, never raise it.
        let class = class.min(inner.assurance());
        Self { inner, class, reason }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl<R: RootOfTrust> RootOfTrust for Classified<R> {
    fn assurance(&self) -> AssuranceClass {
        self.class
    }
    fn ek_public(&self) -> Result<Vec<u8>> {
        self.inner.ek_public()
    }
    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        self.inner.ek_certificate()
    }
    fn ak_public(&self) -> Result<Vec<u8>> {
        self.inner.ak_public()
    }
    fn pcrs(&self) -> Result<PcrSet> {
        self.inner.pcrs()
    }
    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        self.inner.quote(nonce)
    }
    fn node_id(&self) -> Result<NodeId> {
        self.inner.node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swtpm_local_ca_is_recognised() {
        assert!(emulator_issuer("CN = swtpm-localca").is_some());
        assert!(emulator_issuer("CN=swtpm-localca-rootca").is_some());
        assert!(emulator_issuer("C = DE, O = Infineon Technologies AG, CN = Infineon OPTIGA(TM) RSA Manufacturing CA 003").is_none());
    }

    fn fused() -> SecureBoot {
        SecureBoot::Enforced { detail: "security_mode fuse is 0x1".into() }
    }

    #[test]
    fn tpm_only_when_fused_and_chain_verifies() {
        let ok = EkChain::Verified { bundle: "/etc/furcate/ek-trusted-ca.pem".into() };
        let (class, reason) = classify(&fused(), &ok);
        assert_eq!(class, AssuranceClass::Tpm);
        assert!(reason.contains("secure boot fused"));

        for chain in [EkChain::NoCertificate, EkChain::NoTrustedCa, EkChain::Rejected { why: "x".into() }] {
            assert_eq!(classify(&fused(), &chain).0, AssuranceClass::Tee, "{chain:?}");
        }
    }

    #[test]
    fn unfused_or_unknown_is_tee_even_with_a_verified_chain() {
        let ok = EkChain::Verified { bundle: "b".into() };
        let (class, reason) = classify(&SecureBoot::Off { detail: "security_mode fuse is 0".into() }, &ok);
        assert_eq!(class, AssuranceClass::Tee);
        assert!(reason.contains("unfused development part"));

        let (class, reason) = classify(&SecureBoot::Unknown { why: "not readable".into() }, &ok);
        assert_eq!(class, AssuranceClass::Tee);
        assert!(reason.contains("unknown"));
    }

    #[test]
    fn chain_without_bundle_or_certificate() {
        let work = std::env::temp_dir();
        assert_eq!(verify_ek_chain(Some(b"x"), None, &work), EkChain::NoTrustedCa);
        assert_eq!(verify_ek_chain(Some(b"x"), Some(Path::new("/nonexistent/ca.pem")), &work), EkChain::NoTrustedCa);
        let bundle = std::env::temp_dir().join(format!("furcate-ekca-{}.pem", std::process::id()));
        std::fs::write(&bundle, "").unwrap();
        assert_eq!(verify_ek_chain(None, Some(&bundle), &work), EkChain::NoCertificate);
        std::fs::remove_file(&bundle).unwrap();
    }

    struct Fake(AssuranceClass);
    impl RootOfTrust for Fake {
        fn assurance(&self) -> AssuranceClass {
            self.0
        }
        fn ek_public(&self) -> Result<Vec<u8>> {
            Ok(vec![1, 2, 3])
        }
        fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn ak_public(&self) -> Result<Vec<u8>> {
            Ok(vec![4])
        }
        fn pcrs(&self) -> Result<PcrSet> {
            Ok(PcrSet::default())
        }
        fn quote(&self, _: &[u8]) -> Result<Quote> {
            anyhow::bail!("unused")
        }
    }

    #[test]
    fn policy_lowers_but_never_raises() {
        let lowered = Classified::new(Fake(AssuranceClass::Tpm), AssuranceClass::Tee, "r".into());
        assert_eq!(lowered.assurance(), AssuranceClass::Tee);
        assert!(!lowered.assurance().can_quote());
        assert_eq!(lowered.node_id().unwrap(), Fake(AssuranceClass::Tpm).node_id().unwrap());
        let capped = Classified::new(Fake(AssuranceClass::Device), AssuranceClass::Tpm, "r".into());
        assert_eq!(capped.assurance(), AssuranceClass::Device);
    }
}
