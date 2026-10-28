//! TPM 2.0 backend driving the `tpm2-tools` command line.
//!
//! This is the first backend because it needs nothing installed beyond
//! `tpm2-tools`, which ships on the platforms Furcate targets and is already
//! present on both nodes of the first site. It exercises the real chip: the
//! endorsement key it reads is the one fused into the TPM, and the quotes it
//! produces are signed inside the chip.
//!
//! A native `tss-esapi` backend will replace it for the hot paths, since
//! spawning a process per operation is not appropriate for continuous
//! attestation. Both satisfy the same trait, so node identifiers and
//! enrollment records carry over unchanged.

use crate::rot::{AssuranceClass, PcrSet, Quote, RootOfTrust};
use anyhow::{anyhow, bail, Context as _, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// NV index holding the RSA endorsement certificate, per the TCG registry.
/// Absent on many consumer and embedded parts.
const NV_EK_RSA_CERT: &str = "0x01c00002";

/// NV index holding the ECC P-256 endorsement certificate, per the same
/// registry. Firmware TPMs provisioned by an ODM may carry only this one.
const NV_EK_ECC_CERT: &str = "0x01c0000a";

/// Registers covered by default. 0–7 span firmware, option ROMs, boot
/// configuration and the boot loader — the span that changes when the platform
/// is tampered with or reconfigured.
const DEFAULT_PCRS: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7];

/// The resource-manager device every TPM backend talks to.
pub const TPM_DEVICE: &str = "/dev/tpmrm0";

/// Where the kernel lists the TPMs it drives.
pub const TPM_SYSFS_CLASS: &str = "/sys/class/tpm";

/// Why `device` is not a TPM this node can use, if it is not.
///
/// Checked before any TPM command is sent, so that something at the device
/// path that is not a TPM (an empty file left by a bind mount, a node created
/// by hand) is passed over like an absent TPM instead of being opened and
/// found silent. A device the kernel does not list under `sysfs_class` is not
/// a TPM the kernel drives, so it is not hardware either.
pub fn unusable_device(device: &Path, sysfs_class: &Path) -> Option<String> {
    use std::os::unix::fs::FileTypeExt;
    let meta = match std::fs::metadata(device) {
        Ok(m) => m,
        Err(e) => return Some(e.to_string()),
    };
    if !meta.file_type().is_char_device() {
        return Some("it is not a character device".to_string());
    }
    if let Err(e) = std::fs::OpenOptions::new().read(true).write(true).open(device) {
        return Some(format!("it does not open: {e}"));
    }
    // The kernel names the device it registered, which a link at the usual
    // path may point elsewhere from: rebinding the driver while the first
    // chip is still held registers the same TPM as tpm1, and /dev/tpmrm0 is
    // then a link to /dev/tpmrm1. Ask sysfs about the device the path reaches.
    let real = std::fs::canonicalize(device).unwrap_or_else(|_| device.to_path_buf());
    let name = real.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let class_name = match name.strip_prefix("tpmrm") {
        Some(n) => format!("tpm{n}"),
        None => name,
    };
    let entry = sysfs_class.join(&class_name);
    if !entry.exists() {
        return Some(format!("the kernel lists no {}, so it is not a hardware TPM", entry.display()));
    }
    None
}

pub struct Tpm2Tools {
    work: PathBuf,
    tcti: String,
    pcrs: Vec<u32>,
    bank: String,
}

impl Tpm2Tools {
    /// Open the TPM through the in-kernel resource manager.
    ///
    /// `/dev/tpmrm0` is used rather than `/dev/tpm0` because the resource
    /// manager multiplexes transient object slots; talking to the raw device
    /// makes concurrent users fail on object exhaustion.
    pub fn open() -> Result<Self> {
        Self::with_device(TPM_DEVICE)
    }

    pub fn with_device(device: &str) -> Result<Self> {
        if !Path::new(device).exists() {
            bail!("no TPM device at {device}");
        }
        which("tpm2_pcrread").context(
            "tpm2-tools not found on PATH; install tpm2-tools or use a different backend",
        )?;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let work = std::env::temp_dir().join(format!("furcate-tpm-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&work)
            .with_context(|| format!("creating work directory {}", work.display()))?;

        Ok(Self {
            work,
            tcti: format!("device:{device}"),
            pcrs: DEFAULT_PCRS.to_vec(),
            bank: "sha256".to_string(),
        })
    }

    /// Who the TPM says made it: `TPM_PT_MANUFACTURER` and the vendor
    /// strings, read with `tpm2_getcap properties-fixed`.
    pub fn vendor(&self) -> Result<TpmVendor> {
        let out = self.run("tpm2_getcap", &["properties-fixed"])?;
        parse_vendor(&String::from_utf8_lossy(&out))
    }

    /// The ECC endorsement certificate, when the platform provisions one.
    /// Absence is not an error, for the same reason as the RSA certificate.
    pub fn ek_certificate_ecc(&self) -> Result<Option<Vec<u8>>> {
        match self.run("tpm2_nvread", &[NV_EK_ECC_CERT, "-o", "ek-ecc.crt"]) {
            Ok(_) => Ok(Some(self.read("ek-ecc.crt")?)),
            Err(_) => Ok(None),
        }
    }

    /// Restrict which registers are read and quoted.
    pub fn with_pcrs(mut self, pcrs: Vec<u32>) -> Self {
        self.pcrs = pcrs;
        self
    }

    fn pcr_selection(&self) -> String {
        let list = self
            .pcrs
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("{}:{}", self.bank, list)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work.join(name)
    }

    fn run(&self, tool: &str, args: &[&str]) -> Result<Vec<u8>> {
        let out = Command::new(tool)
            .args(args)
            .env("TPM2TOOLS_TCTI", &self.tcti)
            .current_dir(&self.work)
            .output()
            .with_context(|| format!("spawning {tool}"))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!(
                "{tool} {} failed: {}",
                args.join(" "),
                stderr.trim().lines().next().unwrap_or("no output")
            );
        }
        Ok(out.stdout)
    }

    /// Create the endorsement key, writing its context and public area.
    ///
    /// The EK is derived deterministically from the endorsement seed, so this
    /// yields the same key on every call and across reboots. That determinism
    /// is what makes the node identifier stable.
    fn ensure_ek(&self) -> Result<()> {
        if self.path("ek.pub").exists() && self.path("ek.ctx").exists() {
            return Ok(());
        }
        self.run(
            "tpm2_createek",
            &["-c", "ek.ctx", "-G", "rsa", "-u", "ek.pub"],
        )?;
        Ok(())
    }

    /// Create an attestation key beneath the endorsement key.
    fn ensure_ak(&self) -> Result<()> {
        if self.path("ak.pub").exists() && self.path("ak.ctx").exists() {
            return Ok(());
        }
        self.ensure_ek()?;
        self.run(
            "tpm2_createak",
            &[
                "-C", "ek.ctx", "-c", "ak.ctx", "-G", "rsa", "-g", "sha256", "-s", "rsassa", "-u",
                "ak.pub", "-n", "ak.name",
            ],
        )?;
        Ok(())
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        std::fs::read(self.path(name))
            .with_context(|| format!("reading {name} produced by tpm2-tools"))
    }
}

impl Drop for Tpm2Tools {
    fn drop(&mut self) {
        // Context files reference transient objects that the resource manager
        // reclaims anyway; the public areas are not secret. Cleaning up keeps
        // the temp directory from accumulating across invocations.
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

impl RootOfTrust for Tpm2Tools {
    fn assurance(&self) -> AssuranceClass {
        AssuranceClass::Tpm
    }

    fn ek_public(&self) -> Result<Vec<u8>> {
        self.ensure_ek()?;
        self.read("ek.pub")
    }

    fn ek_certificate(&self) -> Result<Option<Vec<u8>>> {
        // Absence is normal and must not be an error: most consumer TPMs ship
        // without a certificate. The verifier records that the manufacturer
        // has not vouched for this chip and appraises accordingly.
        match self.run("tpm2_nvread", &[NV_EK_RSA_CERT, "-o", "ek.crt"]) {
            Ok(_) => Ok(Some(self.read("ek.crt")?)),
            Err(_) => Ok(None),
        }
    }

    fn ak_public(&self) -> Result<Vec<u8>> {
        self.ensure_ak()?;
        self.read("ak.pub")
    }

    fn pcrs(&self) -> Result<PcrSet> {
        let out = self.run("tpm2_pcrread", &[&self.pcr_selection()])?;
        parse_pcrread(&String::from_utf8_lossy(&out), &self.bank)
    }

    fn quote(&self, nonce: &[u8]) -> Result<Quote> {
        if nonce.is_empty() {
            bail!("a quote without a nonce is replayable; supply one");
        }
        self.ensure_ak()?;
        let nonce_hex = hex::encode(nonce);
        self.run(
            "tpm2_quote",
            &[
                "-c",
                "ak.ctx",
                "-l",
                &self.pcr_selection(),
                "-q",
                &nonce_hex,
                "-m",
                "quote.msg",
                "-s",
                "quote.sig",
            ],
        )?;
        Ok(Quote {
            message: self.read("quote.msg")?,
            signature: self.read("quote.sig")?,
            nonce: nonce.to_vec(),
            pcrs: self.pcrs()?,
        })
    }
}

fn which(tool: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .context("checking for tpm2-tools")?;
    if status.status.success() {
        Ok(())
    } else {
        Err(anyhow!("{tool} not found"))
    }
}

/// Parse `tpm2_pcrread` output.
///
/// The tool prints a bank header followed by indented `index : 0xDIGEST`
/// lines. Anything that does not match that shape is ignored rather than
/// treated as an error, so tool version differences in banner text do not
/// break parsing.
/// A TPM's own account of its maker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmVendor {
    /// `TPM_PT_MANUFACTURER` as ASCII, e.g. `IFX`, `STM`, `NTC`, `INTC`, `AMD`.
    pub manufacturer: String,
    /// `TPM_PT_VENDOR_STRING_1` to `_4` concatenated, padding kept.
    pub vendor: String,
}

impl TpmVendor {
    /// Why these properties identify a software TPM, if they do.
    ///
    /// libtpms, the engine inside swtpm, hard-codes manufacturer `IBM` and
    /// vendor strings `"SW  "` and `" TPM"` (`VendorInfo.c`), the values of
    /// IBM's reference software TPM. Matched on the vendor string with the
    /// spacing removed, so `"SW   TPM"`, `"SW TPM"` and `"swtpm"` all count;
    /// the manufacturer alone is not used, because a TCG vendor ID says
    /// nothing about whether the thing answering is a chip.
    pub fn emulated(&self) -> Option<String> {
        let squashed: String = self.vendor.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
        (squashed.contains("swtpm") || squashed.contains("simulator")).then(|| {
            format!(
                "the TPM reports manufacturer {:?} and vendor {:?}, the reference software TPM's \
                 (libtpms, as used by swtpm)",
                self.manufacturer,
                self.vendor.trim()
            )
        })
    }
}

/// Read the manufacturer and vendor strings out of `tpm2_getcap
/// properties-fixed`, from each property's `raw:` line: a big-endian u32 of
/// four ASCII bytes, NUL-padded.
fn parse_vendor(text: &str) -> Result<TpmVendor> {
    let mut current: Option<&str> = None;
    let mut manufacturer = None;
    let mut vendor = [String::new(), String::new(), String::new(), String::new()];
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_suffix(':').filter(|n| n.starts_with("TPM2_PT_")) {
            current = Some(name);
            continue;
        }
        let Some(raw) = t.strip_prefix("raw:") else { continue };
        let Ok(v) = u32::from_str_radix(raw.trim().trim_start_matches("0x"), 16) else { continue };
        let text: String = v.to_be_bytes().iter().filter(|b| **b != 0).map(|b| *b as char).collect();
        match current {
            Some("TPM2_PT_MANUFACTURER") => manufacturer = Some(text),
            Some(n) if n.starts_with("TPM2_PT_VENDOR_STRING_") => {
                if let Some(i) = n.trim_start_matches("TPM2_PT_VENDOR_STRING_").parse::<usize>().ok().filter(|i| (1..=4).contains(i)) {
                    vendor[i - 1] = text;
                }
            }
            _ => {}
        }
    }
    let manufacturer = manufacturer.ok_or_else(|| anyhow::anyhow!("tpm2_getcap reported no TPM2_PT_MANUFACTURER"))?;
    Ok(TpmVendor { manufacturer, vendor: vendor.concat() })
}

fn parse_pcrread(text: &str, bank: &str) -> Result<PcrSet> {
    let mut values: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((idx, digest)) = line.split_once(':') else {
            continue;
        };
        let Ok(idx) = idx.trim().parse::<u32>() else {
            continue;
        };
        let digest = digest.trim().trim_start_matches("0x");
        if digest.is_empty() {
            continue;
        }
        let Ok(bytes) = hex::decode(digest) else {
            continue;
        };
        values.insert(idx, bytes);
    }
    if values.is_empty() {
        bail!("no PCR values parsed from tpm2_pcrread output");
    }
    Ok(PcrSet {
        bank: bank.to_string(),
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("furcate-tpmdev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_regular_file_at_the_device_path_is_not_a_tpm() {
        let dir = scratch("file");
        let dev = dir.join("tpmrm0");
        std::fs::write(&dev, b"").unwrap();
        std::fs::create_dir_all(dir.join("class/tpm0")).unwrap();
        let why = unusable_device(&dev, &dir.join("class")).expect("a regular file must be refused");
        assert!(why.contains("not a character device"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_device_is_not_a_tpm() {
        let dir = scratch("missing");
        assert!(unusable_device(&dir.join("tpmrm0"), &dir).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_at_the_device_path_is_judged_by_the_device_it_reaches() {
        let dir = scratch("link");
        let link = dir.join("tpmrm0");
        std::os::unix::fs::symlink("/dev/null", &link).unwrap();
        std::fs::create_dir_all(dir.join("class/tpm0")).unwrap();
        let why = unusable_device(&link, &dir.join("class")).expect("the reached device is not listed");
        assert!(why.contains("null"), "{why}");
        std::fs::create_dir_all(dir.join("class/null")).unwrap();
        assert_eq!(unusable_device(&link, &dir.join("class")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_device_the_kernel_does_not_list_is_not_hardware() {
        let dir = scratch("sysfs");
        let dev = Path::new("/dev/null");
        let why = unusable_device(dev, &dir).expect("no sysfs entry must be refused");
        assert!(why.contains("not a hardware TPM"), "{why}");
        std::fs::create_dir_all(dir.join("null")).unwrap();
        assert_eq!(unusable_device(dev, &dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_device_that_does_not_open_is_not_a_tpm() {
        // A character device this user may not open; skipped when running
        // with the privilege to open it.
        let dev = Path::new("/dev/mem");
        if std::fs::OpenOptions::new().read(true).write(true).open(dev).is_ok() || !dev.exists() {
            return;
        }
        let dir = scratch("eacces");
        std::fs::create_dir_all(dir.join("mem")).unwrap();
        let why = unusable_device(dev, &dir).expect("an unopenable device must be refused");
        assert!(why.contains("does not open"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `tpm2_getcap properties-fixed` from swtpm 0.8 / libtpms 0.9.
    const SWTPM_GETCAP: &str = "\
TPM2_PT_FAMILY_INDICATOR:
  raw: 0x322E3000
  value: \"2.0\"
TPM2_PT_MANUFACTURER:
  raw: 0x49424D00
  value: \"IBM\"
TPM2_PT_VENDOR_STRING_1:
  raw: 0x53572020
  value: \"SW\"
TPM2_PT_VENDOR_STRING_2:
  raw: 0x2054504D
  value: \"TPM\"
TPM2_PT_VENDOR_STRING_3:
  raw: 0x0
  value: \"\"
TPM2_PT_VENDOR_STRING_4:
  raw: 0x0
  value: \"\"
";

    const INFINEON_GETCAP: &str = "\
TPM2_PT_MANUFACTURER:
  raw: 0x49465800
  value: \"IFX\"
TPM2_PT_VENDOR_STRING_1:
  raw: 0x534C4239
  value: \"SLB9\"
TPM2_PT_VENDOR_STRING_2:
  raw: 0x36373000
  value: \"670\"
TPM2_PT_VENDOR_STRING_3:
  raw: 0x0
  value: \"\"
";

    #[test]
    fn swtpm_capabilities_are_emulated() {
        let v = parse_vendor(SWTPM_GETCAP).unwrap();
        assert_eq!(v.manufacturer, "IBM");
        assert_eq!(v.vendor, "SW   TPM");
        let why = v.emulated().expect("swtpm must be recognised");
        assert!(why.contains("IBM"), "{why}");
    }

    #[test]
    fn hardware_capabilities_are_not() {
        let v = parse_vendor(INFINEON_GETCAP).unwrap();
        assert_eq!(v, TpmVendor { manufacturer: "IFX".into(), vendor: "SLB9670".into() });
        assert!(v.emulated().is_none());
        // The manufacturer ID alone decides nothing.
        assert!(TpmVendor { manufacturer: "IBM".into(), vendor: "".into() }.emulated().is_none());
        assert!(TpmVendor { manufacturer: "XYZ".into(), vendor: "swtpm".into() }.emulated().is_some());
    }

    #[test]
    fn getcap_without_a_manufacturer_is_an_error() {
        assert!(parse_vendor("TPM2_PT_VENDOR_STRING_1:\n  raw: 0x53572020\n").is_err());
    }

    #[test]
    fn parses_typical_output() {
        let text = "sha256:\n  0 : 0x0102\n  1 : 0xAABB\n  7 : 0xFF00\n";
        let set = parse_pcrread(text, "sha256").unwrap();
        assert_eq!(set.bank, "sha256");
        assert_eq!(set.values.len(), 3);
        assert_eq!(set.values[&0], vec![0x01, 0x02]);
        assert_eq!(set.values[&7], vec![0xff, 0x00]);
    }

    #[test]
    fn ignores_banner_and_malformed_lines() {
        let text = "tpm2_pcrread banner\nsha256:\n  0 : 0x01\n  bad : 0xZZ\n  2 : notahex\n";
        let set = parse_pcrread(text, "sha256").unwrap();
        assert_eq!(set.values.len(), 1);
        assert!(set.values.contains_key(&0));
    }

    #[test]
    fn empty_output_is_an_error() {
        assert!(parse_pcrread("sha256:\n", "sha256").is_err());
    }
}
