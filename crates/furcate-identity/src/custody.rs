//! Who holds a cluster's keys.
//!
//! By default, custody of sealed data, the site CA roots and operator-sealed
//! material goes only to machines that can quote: a TPM
//! ([`AssuranceClass::Tpm`]) or a DICE chain ([`AssuranceClass::Dice`]). Those
//! hold a key the hardware never surrenders *and* produce evidence a verifier
//! can check without trusting a single vendor's service.
//!
//! Everything else needs the operator's opt-in. A TEE
//! ([`AssuranceClass::Tee`]) or a secure element
//! ([`AssuranceClass::SecureElement`], which includes a phone or laptop
//! enclave) holds its key well but attests only through its vendor, so it is
//! kept out of the default trust root; a fuse or PUF key
//! ([`AssuranceClass::Device`]) proves possession but nothing about what runs.
//! All three hold custody only when site policy enables TPM-less custody
//! (`custody.tpm_less`), and then the strongest of them is elected first: TEE
//! and secure element before fuse keys. Readable silicon characteristics
//! ([`AssuranceClass::Soft`]) hold custody only when the operator has also set
//! `custody.allow_soft`. Nothing is generated at random in software to fill the
//! gap.
//!
//! ## Three modes, chosen by the operator
//!
//! - [`CustodyMode::Elected`], the default: holders are elected by class, the
//!   strongest first, spread over more than one machine where the cluster has
//!   them so no single machine is a point of failure. Every node computes the
//!   same answer from the same members.
//! - [`CustodyMode::Designated`]: the operator names the holders. A name is
//!   honoured only if that machine's class is admitted by the same rules, so a
//!   designation can never place custody below the policy's floor.
//! - [`CustodyMode::SelfCustody`]: every machine holds only its own keys and
//!   sealed data, rooted in its own silicon. No machine holds anything for
//!   another.
//!
//! The settings themselves only change through a signed policy change recorded
//! in the ledger; see `furcate_policy::custody`.
//!
//! ## Persistence
//!
//! A custody key is never stored as a file of its own. On a TPM machine it
//! hangs under the owner-hierarchy primary, which the TPM re-derives from its
//! seed with the same template on every boot ([`crate::seal`]); it changes only
//! when the TPM is cleared, which happens only on a signed `crypto_erase`. On a
//! silicon-fingerprint machine it is re-derived on every boot from the silicon
//! through [`SiliconKey`], so the same chip always yields the same key. Sealed
//! objects and enrolment records live under the state directory, which an image
//! update never writes.

use crate::backends::fingerprint::FingerprintRot;
use crate::rot::{AssuranceClass, RootOfTrust};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// How custody is assigned across a cluster.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyMode {
    /// Elected by class, strongest first, spread over more than one machine.
    #[default]
    Elected,
    /// The operator names the holders.
    Designated,
    /// Every machine holds only its own material.
    #[serde(rename = "self")]
    SelfCustody,
}

impl CustodyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CustodyMode::Elected => "elected",
            CustodyMode::Designated => "designated",
            CustodyMode::SelfCustody => "self",
        }
    }
}

impl fmt::Display for CustodyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_spread() -> usize {
    2
}

/// The custody section of a site's policy.
///
/// Every field has a default and every default is the conservative one: an
/// absent section means elected custody on quote-capable machines (TPM, DICE)
/// only, over two machines where there are two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySettings {
    #[serde(default)]
    pub mode: CustodyMode,
    /// The machines named to hold custody. Only meaningful, and only accepted,
    /// in [`CustodyMode::Designated`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holders: Vec<String>,
    /// The lowest class the site will accept for custody. Raises the floor the
    /// opt-ins set; it can never lower it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<AssuranceClass>,
    /// Whether machines that cannot quote may hold custody: TEE, secure
    /// element (including a phone or laptop enclave) and fuse-key machines.
    /// Off unless the operator turns it on.
    #[serde(default)]
    pub tpm_less: bool,
    /// Whether readable silicon characteristics may hold custody once
    /// `tpm_less` is on. Off unless the operator turns it on.
    #[serde(default)]
    pub allow_soft: bool,
    /// How many machines an election aims for.
    #[serde(default = "default_spread")]
    pub spread: usize,
}

impl Default for CustodySettings {
    fn default() -> Self {
        CustodySettings {
            mode: CustodyMode::Elected,
            holders: Vec::new(),
            minimum: None,
            tpm_less: false,
            allow_soft: false,
            spread: default_spread(),
        }
    }
}

/// Why custody was not granted. Always carries the reason in words an
/// operator can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyRefusal(pub String);

impl fmt::Display for CustodyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CustodyRefusal {}

fn refuse<T>(why: impl Into<String>) -> Result<T, CustodyRefusal> {
    Err(CustodyRefusal(why.into()))
}

/// Which band a class falls in for custody. Order matters: higher is preferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Band {
    Readable,
    Silicon,
    Enclave,
    Quoting,
}

fn band(class: AssuranceClass) -> Band {
    match class {
        AssuranceClass::Tpm | AssuranceClass::Dice => Band::Quoting,
        AssuranceClass::Tee | AssuranceClass::SecureElement => Band::Enclave,
        AssuranceClass::Device => Band::Silicon,
        AssuranceClass::Soft => Band::Readable,
    }
}

/// Whether a class holds custody with no opt-in at all: it can quote.
pub fn quote_capable(class: AssuranceClass) -> bool {
    band(class) == Band::Quoting
}

impl CustodySettings {
    /// Reject settings that contradict themselves rather than guess which part
    /// the operator meant.
    pub fn validate(&self) -> Result<(), CustodyRefusal> {
        if self.allow_soft && !self.tpm_less {
            return refuse(
                "allow_soft is set but tpm_less is not; readable silicon may hold custody \
                 only once TPM-less custody is enabled",
            );
        }
        if self.spread == 0 {
            return refuse("spread is 0; an election must name at least one holder");
        }
        match self.mode {
            CustodyMode::Designated if self.holders.is_empty() => refuse(
                "custody mode is designated but no holders are named",
            ),
            CustodyMode::Elected | CustodyMode::SelfCustody if !self.holders.is_empty() => {
                refuse(format!(
                    "holders are named but custody mode is {}; holders are honoured only in \
                     designated mode",
                    self.mode
                ))
            }
            _ => Ok(()),
        }
    }

    /// The lowest class these settings admit.
    pub fn floor(&self) -> AssuranceClass {
        let opted = if self.tpm_less && self.allow_soft {
            AssuranceClass::Soft
        } else if self.tpm_less {
            AssuranceClass::Device
        } else {
            AssuranceClass::Dice
        };
        match self.minimum {
            Some(m) if m > opted => m,
            _ => opted,
        }
    }

    /// Whether a machine of `class` may hold custody under these settings, and
    /// if not, why.
    pub fn admits(&self, class: AssuranceClass) -> Result<(), CustodyRefusal> {
        if let Some(m) = self.minimum {
            if class < m {
                return refuse(format!(
                    "class `{class}` is below the site policy minimum `{m}` for custody"
                ));
            }
        }
        match band(class) {
            Band::Quoting => Ok(()),
            Band::Enclave | Band::Silicon if self.tpm_less => Ok(()),
            Band::Enclave => refuse(format!(
                "class `{class}` holds its key well but cannot quote, so it is outside the \
                 default trust root; it may hold custody only when site policy enables \
                 TPM-less custody (custody.tpm_less)"
            )),
            Band::Silicon => refuse(format!(
                "class `{class}` holds its key in silicon rather than in a TPM or DICE chain, \
                 and TPM-less custody is off in site policy (custody.tpm_less)"
            )),
            Band::Readable if self.tpm_less && self.allow_soft => Ok(()),
            Band::Readable => refuse(format!(
                "class `{class}` rests on readable characteristics that prove continuity, not \
                 possession; it may hold custody only when site policy enables both \
                 custody.tpm_less and custody.allow_soft"
            )),
        }
    }
}

/// A cluster member as custody sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    /// The appraised class. `None` means nobody has said, which is ineligible
    /// rather than a weak class.
    pub class: Option<AssuranceClass>,
    /// Whether the member is reachable now. An election skips unreachable
    /// members; a designation does not, because the operator named them.
    pub reachable: bool,
}

/// One machine holding custody, and the class it holds it with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub id: String,
    pub class: AssuranceClass,
}

/// The outcome of applying custody settings to a cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Custody {
    pub mode: CustodyMode,
    pub holders: Vec<Holder>,
    /// Members that hold nothing, and why. Reported rather than dropped.
    pub excluded: Vec<(String, String)>,
}

impl Custody {
    /// The weakest class holding any of the cluster's keys: what the cluster
    /// reports as its custody class.
    pub fn class(&self) -> Option<AssuranceClass> {
        self.holders.iter().map(|h| h.class).min()
    }

    /// Whether this custody meets a required minimum class.
    pub fn meets(&self, minimum: AssuranceClass) -> Result<(), CustodyRefusal> {
        match self.class() {
            Some(c) if c >= minimum => Ok(()),
            Some(c) => refuse(format!(
                "custody is held at class `{c}`, below the required `{minimum}`"
            )),
            None => refuse("no machine holds custody"),
        }
    }

    /// The machines that hold `owner`'s material.
    ///
    /// In self-custody that is `owner` and nobody else, and an owner whose own
    /// class is not admitted holds nothing.
    pub fn holders_for(&self, owner: &str) -> Result<Vec<Holder>, CustodyRefusal> {
        match self.mode {
            CustodyMode::SelfCustody => match self.holders.iter().find(|h| h.id == owner) {
                Some(h) => Ok(vec![h.clone()]),
                None => {
                    let why = self
                        .excluded
                        .iter()
                        .find(|(id, _)| id == owner)
                        .map(|(_, w)| w.as_str())
                        .unwrap_or("it is not a member of this cluster");
                    refuse(format!(
                        "self-custody: `{owner}` holds only its own material, and cannot: {why}"
                    ))
                }
            },
            _ => Ok(self.holders.clone()),
        }
    }

    /// A grant for `node` to open its vault, if it is a holder.
    pub fn grant(&self, node: &str) -> Result<CustodyGrant, CustodyRefusal> {
        match self.holders.iter().find(|h| h.id == node) {
            Some(h) => Ok(CustodyGrant {
                mode: self.mode,
                class: h.class,
                holder: h.id.clone(),
            }),
            None => {
                let why = self
                    .excluded
                    .iter()
                    .find(|(id, _)| id == node)
                    .map(|(_, w)| w.clone())
                    .unwrap_or_else(|| format!("custody is {} and `{node}` is not a holder", self.mode));
                refuse(why)
            }
        }
    }
}

/// Apply custody settings to the members of a cluster.
///
/// Deterministic: the same settings and members give the same holders on every
/// node, so no messages are exchanged to agree on them.
pub fn elect(settings: &CustodySettings, members: &[Candidate]) -> Result<Custody, CustodyRefusal> {
    settings.validate()?;
    let mut excluded = Vec::new();
    let mut admitted = Vec::new();
    for m in members {
        match m.class {
            None => excluded.push((
                m.id.clone(),
                "its class has not been appraised, which is not the same as a weak class".into(),
            )),
            Some(class) => match settings.admits(class) {
                Ok(()) => admitted.push((m, class)),
                Err(r) => excluded.push((m.id.clone(), r.0)),
            },
        }
    }

    match settings.mode {
        CustodyMode::SelfCustody => {
            let holders = admitted
                .iter()
                .map(|(m, class)| Holder { id: m.id.clone(), class: *class })
                .collect();
            Ok(Custody { mode: settings.mode, holders, excluded })
        }
        CustodyMode::Designated => {
            let mut holders = Vec::new();
            for name in &settings.holders {
                let Some(m) = members.iter().find(|m| &m.id == name) else {
                    return refuse(format!("designated holder `{name}` is not a member of this cluster"));
                };
                let Some(class) = m.class else {
                    return refuse(format!(
                        "designated holder `{name}` has no appraised class, so its custody class \
                         cannot be stated"
                    ));
                };
                if let Err(r) = settings.admits(class) {
                    return refuse(format!("designated holder `{name}` is refused: {r}"));
                }
                holders.push(Holder { id: name.clone(), class });
            }
            excluded.retain(|(id, _)| !settings.holders.contains(id));
            Ok(Custody { mode: settings.mode, holders, excluded })
        }
        CustodyMode::Elected => {
            let mut eligible: Vec<_> = admitted
                .into_iter()
                .filter(|(m, _)| {
                    if !m.reachable {
                        excluded.push((m.id.clone(), "unreachable at election".into()));
                    }
                    m.reachable
                })
                .collect();
            let Some(top) = eligible.iter().map(|(_, c)| band(*c)).max() else {
                let quoting_seen = members
                    .iter()
                    .any(|m| m.class.is_some_and(|c| band(c) == Band::Quoting));
                return if !quoting_seen && !settings.tpm_less {
                    refuse(
                        "no machine in this cluster can quote from a TPM or DICE chain, and \
                         TPM-less custody is off in site policy; enable custody.tpm_less to let \
                         TEE, secure element or silicon-held keys hold custody",
                    )
                } else {
                    refuse(format!(
                        "no reachable member is eligible for custody: {}",
                        excluded
                            .iter()
                            .map(|(id, w)| format!("{id}: {w}"))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ))
                };
            };
            // Custody stays in the strongest band the cluster has: a quoting
            // machine present means enclave and silicon machines hold nothing,
            // even when that leaves fewer holders than the spread asks for.
            eligible.retain(|(m, c)| {
                let keep = band(*c) == top;
                if !keep {
                    excluded.push((
                        m.id.clone(),
                        "a stronger class holds custody in this cluster".into(),
                    ));
                }
                keep
            });
            eligible.sort_by(|(a, ca), (b, cb)| cb.cmp(ca).then_with(|| a.id.cmp(&b.id)));
            let holders: Vec<Holder> = eligible
                .iter()
                .take(settings.spread)
                .map(|(m, class)| Holder { id: m.id.clone(), class: *class })
                .collect();
            for (m, _) in eligible.iter().skip(settings.spread) {
                excluded.push((m.id.clone(), format!("the election spread is {}", settings.spread)));
            }
            Ok(Custody { mode: settings.mode, holders, excluded })
        }
    }
}

/// Proof that custody was granted to a machine. Only [`Custody::grant`] makes
/// one, so a vault cannot be opened on a class the settings did not admit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyGrant {
    mode: CustodyMode,
    class: AssuranceClass,
    holder: String,
}

impl CustodyGrant {
    pub fn mode(&self) -> CustodyMode {
        self.mode
    }
    pub fn class(&self) -> AssuranceClass {
        self.class
    }
    pub fn holder(&self) -> &str {
        &self.holder
    }
    /// What every object sealed under this grant records.
    pub fn record(&self) -> CustodyRecord {
        CustodyRecord { mode: self.mode, class: self.class }
    }
}

/// The custody mode and class an object was sealed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRecord {
    pub mode: CustodyMode,
    pub class: AssuranceClass,
}

impl CustodyRecord {
    /// Bytes bound into a sealed object's authenticated data, so the record
    /// cannot be edited without the object failing to open.
    pub fn bound_bytes(&self) -> Vec<u8> {
        format!("furcate:custody:v1\0{}\0{}", self.mode.as_str(), self.class.as_str()).into_bytes()
    }

    /// Whether an object sealed under this record meets a required class.
    pub fn meets(&self, minimum: AssuranceClass) -> Result<(), CustodyRefusal> {
        if self.class >= minimum {
            Ok(())
        } else {
            refuse(format!(
                "sealed under class `{}`, below the required `{minimum}`",
                self.class
            ))
        }
    }
}

/// A secret the silicon holds, asked for a keyed digest rather than read.
///
/// For [`AssuranceClass::Device`] the secret is a fuse or PUF key that the
/// silicon uses and never reveals. For [`AssuranceClass::Soft`] it is the
/// machine's immutable readable characteristics. Either way the same chip
/// answers the same message with the same digest on every boot, which is where
/// a silicon-fingerprint machine's persistence comes from.
pub trait SiliconKey {
    fn class(&self) -> AssuranceClass;
    fn keyed_digest(&self, message: &[u8]) -> Result<[u8; 32]>;
}

/// Re-derive a custody key from the silicon for one purpose.
///
/// Refuses hardware-held classes, whose custody keys hang under the TPM
/// primary instead, and refuses a grant whose class does not match the
/// silicon answering, so a key is never derived at a class it was not granted.
pub fn custody_key(silicon: &dyn SiliconKey, grant: &CustodyGrant, purpose: &str) -> Result<[u8; 32]> {
    let class = silicon.class();
    if class != grant.class() {
        bail!(
            "custody was granted at class `{}` but the silicon answering is `{class}`",
            grant.class()
        );
    }
    if band(class) >= Band::Enclave {
        bail!(
            "class `{class}` keeps custody keys in its own hardware under the primary seed; \
             silicon derivation is for TPM-less machines"
        );
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"furcate:custody-key:v1\0");
    for field in [grant.mode().as_str(), grant.holder(), purpose] {
        message.extend_from_slice(&(field.len() as u64).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    let digest = silicon.keyed_digest(&message)?;
    Ok(Sha256::new()
        .chain_update(b"furcate:custody-key:out:v1")
        .chain_update(digest)
        .finalize()
        .into())
}

impl SiliconKey for FingerprintRot {
    fn class(&self) -> AssuranceClass {
        self.assurance()
    }

    fn keyed_digest(&self, message: &[u8]) -> Result<[u8; 32]> {
        match self.assurance() {
            AssuranceClass::Soft => {
                if !self.fingerprint.is_usable() {
                    return Err(anyhow!(
                        "fingerprint rests on {} hardware anchors, need {}",
                        self.fingerprint.anchors().len(),
                        crate::backends::Fingerprint::MIN_ANCHORS
                    ));
                }
                // Immutable characteristics only, the same set the identifier
                // is built from, so maintenance does not change the key.
                Ok(Sha256::new()
                    .chain_update(b"furcate:custody-soft:v1")
                    .chain_update(self.fingerprint.digest())
                    .chain_update(message)
                    .finalize()
                    .into())
            }
            other => bail!(
                "this machine is class `{other}` through a sealed key the fingerprint does not \
                 hold; derive custody through the backend that holds that key"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::{Characteristic, Fingerprint, SealedKey};

    fn member(id: &str, class: AssuranceClass) -> Candidate {
        Candidate { id: id.into(), class: Some(class), reachable: true }
    }

    fn tpm_less() -> CustodySettings {
        CustodySettings { tpm_less: true, ..Default::default() }
    }

    #[test]
    fn defaults_are_elected_on_quoting_machines_only() {
        let s = CustodySettings::default();
        assert_eq!(s.mode, CustodyMode::Elected);
        assert!(!s.tpm_less && !s.allow_soft);
        assert_eq!(s.floor(), AssuranceClass::Dice);
        assert!(s.admits(AssuranceClass::Tpm).is_ok());
        assert!(s.admits(AssuranceClass::Dice).is_ok());
        for c in [AssuranceClass::Tee, AssuranceClass::SecureElement] {
            let r = s.admits(c).unwrap_err();
            assert!(r.0.contains("cannot quote") && r.0.contains("custody.tpm_less"), "{r}");
        }
        assert!(s.admits(AssuranceClass::Device).is_err());
        assert!(s.admits(AssuranceClass::Soft).is_err());
        assert!(quote_capable(AssuranceClass::Dice) && !quote_capable(AssuranceClass::SecureElement));
    }

    #[test]
    fn an_enclave_only_cluster_is_refused_by_default_and_elected_with_the_opt_in() {
        let members = [
            member("mac", AssuranceClass::SecureElement),
            member("arm", AssuranceClass::Tee),
            member("pi", AssuranceClass::Device),
            member("vm", AssuranceClass::Soft),
        ];
        let r = elect(&CustodySettings::default(), &members).unwrap_err();
        assert!(r.0.contains("can quote") && r.0.contains("custody.tpm_less"), "{r}");

        let c = elect(&tpm_less(), &members).unwrap();
        let ids: Vec<_> = c.holders.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["arm", "mac"], "the strongest band, strongest class first");
        assert_eq!(c.class(), Some(AssuranceClass::SecureElement));
        assert!(c.grant("pi").unwrap_err().0.contains("stronger class"));
        assert!(c.grant("vm").unwrap_err().0.contains("allow_soft"));
    }

    #[test]
    fn the_schema_reads_as_an_operator_writes_it() {
        let s: CustodySettings = serde_json::from_str(
            r#"{"mode":"designated","holders":["hub"],"minimum":"tpm","tpm_less":false}"#,
        )
        .unwrap();
        assert_eq!(s.mode, CustodyMode::Designated);
        assert_eq!(s.minimum, Some(AssuranceClass::Tpm));
        assert_eq!(s.spread, 2);
        let own: CustodySettings = serde_json::from_str(r#"{"mode":"self"}"#).unwrap();
        assert_eq!(own.mode, CustodyMode::SelfCustody);
        assert!(serde_json::from_str::<CustodySettings>(r#"{"mode":"elected","tpmless":true}"#).is_err());
    }

    #[test]
    fn election_prefers_tpm_and_spreads_over_two_machines() {
        let members = [
            member("se-1", AssuranceClass::SecureElement),
            member("tee-1", AssuranceClass::Tee),
            member("tpm-b", AssuranceClass::Tpm),
            member("tpm-a", AssuranceClass::Tpm),
            member("pi", AssuranceClass::Device),
        ];
        let c = elect(&CustodySettings::default(), &members).unwrap();
        let ids: Vec<_> = c.holders.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["tpm-a", "tpm-b"]);
        assert_eq!(c.class(), Some(AssuranceClass::Tpm));
    }

    #[test]
    fn election_never_picks_a_class_below_the_minimum() {
        let members = [
            member("tpm", AssuranceClass::Tpm),
            member("tee", AssuranceClass::Tee),
            member("se", AssuranceClass::SecureElement),
            member("pi", AssuranceClass::Device),
            member("vm", AssuranceClass::Soft),
        ];
        let everything = CustodySettings {
            tpm_less: true,
            allow_soft: true,
            spread: 10,
            minimum: Some(AssuranceClass::Tee),
            ..Default::default()
        };
        for settings in [CustodySettings::default(), tpm_less(), everything] {
            let c = elect(&settings, &members).unwrap();
            for h in &c.holders {
                assert!(h.class >= settings.floor(), "{h:?} under {settings:?}");
                assert!(settings.admits(h.class).is_ok());
            }
        }
        let strict = CustodySettings { minimum: Some(AssuranceClass::Tpm), spread: 5, ..Default::default() };
        let c = elect(&strict, &members).unwrap();
        assert_eq!(c.holders, vec![Holder { id: "tpm".into(), class: AssuranceClass::Tpm }]);
    }

    #[test]
    fn a_tpm_less_cluster_is_refused_with_a_reason_when_the_opt_in_is_off() {
        let members = [member("pi-1", AssuranceClass::Device), member("pi-2", AssuranceClass::Device)];
        let r = elect(&CustodySettings::default(), &members).unwrap_err();
        assert!(r.0.contains("TPM-less custody is off"), "{r}");
        assert!(r.0.contains("custody.tpm_less"), "{r}");
    }

    #[test]
    fn with_the_opt_in_device_holds_before_soft() {
        let members = [member("vm", AssuranceClass::Soft), member("pi", AssuranceClass::Device)];
        let c = elect(&tpm_less(), &members).unwrap();
        assert_eq!(c.holders, vec![Holder { id: "pi".into(), class: AssuranceClass::Device }]);

        let soft_only = [member("vm", AssuranceClass::Soft)];
        let r = elect(&tpm_less(), &soft_only).unwrap_err();
        assert!(r.0.contains("allow_soft"), "{r}");
        let both = CustodySettings { allow_soft: true, ..tpm_less() };
        let c = elect(&both, &soft_only).unwrap();
        assert_eq!(c.class(), Some(AssuranceClass::Soft));
    }

    #[test]
    fn a_tpm_machine_keeps_custody_off_silicon_machines_even_with_the_opt_in() {
        let members = [member("pi", AssuranceClass::Device), member("tpm", AssuranceClass::Tpm)];
        let c = elect(&tpm_less(), &members).unwrap();
        assert_eq!(c.holders.len(), 1);
        assert_eq!(c.holders[0].id, "tpm");
    }

    #[test]
    fn allow_soft_without_tpm_less_is_refused() {
        let s = CustodySettings { allow_soft: true, ..Default::default() };
        assert!(s.validate().unwrap_err().0.contains("tpm_less"));
    }

    #[test]
    fn a_designation_below_the_minimum_is_rejected() {
        let members = [member("hub", AssuranceClass::Tpm), member("pi", AssuranceClass::Device)];
        let below_default = CustodySettings {
            mode: CustodyMode::Designated,
            holders: vec!["pi".into()],
            ..Default::default()
        };
        let r = elect(&below_default, &members).unwrap_err();
        assert!(r.0.contains("designated holder `pi` is refused"), "{r}");

        let below_minimum = CustodySettings {
            mode: CustodyMode::Designated,
            holders: vec!["pi".into()],
            minimum: Some(AssuranceClass::Tpm),
            ..tpm_less()
        };
        let r = elect(&below_minimum, &members).unwrap_err();
        assert!(r.0.contains("below the site policy minimum"), "{r}");

        let hub = CustodySettings {
            mode: CustodyMode::Designated,
            holders: vec!["hub".into()],
            ..Default::default()
        };
        let c = elect(&hub, &members).unwrap();
        assert_eq!(c.holders, vec![Holder { id: "hub".into(), class: AssuranceClass::Tpm }]);
        assert!(c.grant("pi").is_err());
    }

    #[test]
    fn a_designation_must_name_members() {
        let s = CustodySettings {
            mode: CustodyMode::Designated,
            holders: vec!["ghost".into()],
            ..Default::default()
        };
        let r = elect(&s, &[member("hub", AssuranceClass::Tpm)]).unwrap_err();
        assert!(r.0.contains("not a member"), "{r}");
    }

    #[test]
    fn self_custody_never_assigns_another_machines_material() {
        let s = CustodySettings { mode: CustodyMode::SelfCustody, ..tpm_less() };
        let members = [
            member("tpm", AssuranceClass::Tpm),
            member("pi", AssuranceClass::Device),
            member("vm", AssuranceClass::Soft),
        ];
        let c = elect(&s, &members).unwrap();
        for m in &members {
            match c.holders_for(&m.id) {
                Ok(h) => {
                    assert_eq!(h.len(), 1);
                    assert_eq!(h[0].id, m.id);
                }
                Err(r) => {
                    assert_eq!(m.id, "vm");
                    assert!(r.0.contains("allow_soft"), "{r}");
                }
            }
            if let Ok(g) = c.grant(&m.id) {
                assert_eq!(g.holder(), m.id);
            }
        }
    }

    #[test]
    fn a_grant_records_mode_and_class() {
        let c = elect(&CustodySettings::default(), &[member("tpm", AssuranceClass::Tpm)]).unwrap();
        let g = c.grant("tpm").unwrap();
        assert_eq!(
            g.record(),
            CustodyRecord { mode: CustodyMode::Elected, class: AssuranceClass::Tpm }
        );
        assert!(g.record().meets(AssuranceClass::Tee).is_ok());
        assert!(g.record().meets(AssuranceClass::Tpm).is_ok());
        let weak = CustodyRecord { mode: CustodyMode::SelfCustody, class: AssuranceClass::Device };
        assert!(weak.meets(AssuranceClass::Tpm).is_err());
    }

    fn fingerprint() -> Fingerprint {
        Fingerprint::default()
            .with(Characteristic::SocSerial, "10000000abcdef01")
            .with(Characteristic::BoardSerial, "board-7")
    }

    /// A fuse key, simulated: the secret stays inside and only keyed digests
    /// come out, as the silicon behaves.
    struct SimulatedFuse {
        fused: [u8; 32],
    }

    impl SiliconKey for SimulatedFuse {
        fn class(&self) -> AssuranceClass {
            AssuranceClass::Device
        }
        fn keyed_digest(&self, message: &[u8]) -> Result<[u8; 32]> {
            Ok(Sha256::new().chain_update(self.fused).chain_update(message).finalize().into())
        }
    }

    fn grant_for(class: AssuranceClass, settings: &CustodySettings) -> CustodyGrant {
        elect(settings, &[member("node", class)]).unwrap().grant("node").unwrap()
    }

    #[test]
    fn a_soft_fingerprint_re_derives_the_same_key_every_boot() {
        let settings = CustodySettings { allow_soft: true, ..tpm_less() };
        let grant = grant_for(AssuranceClass::Soft, &settings);
        let boot_one = FingerprintRot::new(fingerprint());
        let boot_two = FingerprintRot::new(fingerprint());
        let a = custody_key(&boot_one, &grant, "vault").unwrap();
        assert_eq!(a, custody_key(&boot_two, &grant, "vault").unwrap());
        assert_ne!(a, custody_key(&boot_one, &grant, "site-ca").unwrap());

        // A volatile characteristic changing under maintenance does not move it.
        let serviced = FingerprintRot::new(fingerprint().with(Characteristic::DiskWwn, "new-card"));
        assert_eq!(a, custody_key(&serviced, &grant, "vault").unwrap());

        // A different chip is a different key.
        let other = FingerprintRot::new(
            Fingerprint::default()
                .with(Characteristic::SocSerial, "10000000abcdef02")
                .with(Characteristic::BoardSerial, "board-7"),
        );
        assert_ne!(a, custody_key(&other, &grant, "vault").unwrap());
    }

    #[test]
    fn a_device_key_re_derives_the_same_key_every_boot() {
        let grant = grant_for(AssuranceClass::Device, &tpm_less());
        let fuse = [0x5au8; 32];
        let a = custody_key(&SimulatedFuse { fused: fuse }, &grant, "vault").unwrap();
        let b = custody_key(&SimulatedFuse { fused: fuse }, &grant, "vault").unwrap();
        assert_eq!(a, b);
        let other = custody_key(&SimulatedFuse { fused: [0xa5u8; 32] }, &grant, "vault").unwrap();
        assert_ne!(a, other);
    }

    #[test]
    fn a_fingerprint_with_a_fuse_key_does_not_derive_from_its_serials() {
        let rot = FingerprintRot::new(fingerprint()).with_sealed_key(SealedKey {
            slot: "efuse:block4".into(),
            public: None,
            readback_blocked: true,
        });
        let grant = grant_for(AssuranceClass::Device, &tpm_less());
        let e = custody_key(&rot, &grant, "vault").unwrap_err().to_string();
        assert!(e.contains("backend that holds that key"), "{e}");
    }

    #[test]
    fn a_key_is_never_derived_at_a_class_it_was_not_granted() {
        let settings = CustodySettings { allow_soft: true, ..tpm_less() };
        let soft = grant_for(AssuranceClass::Soft, &settings);
        let e = custody_key(&SimulatedFuse { fused: [1u8; 32] }, &soft, "vault").unwrap_err();
        assert!(e.to_string().contains("granted at class `soft`"), "{e}");
    }
}
