//! What this machine is, and what it will refuse.
//!
//! Every other module here reads an instrument: a temperature, a fan speed, a
//! disk's wear counter. None of them knows what the machine *is*, so none can
//! answer the question an operator or an agent actually has — not "what is the
//! fan doing" but "can I do anything about it".
//!
//! This reads the shipped registry and answers that. A machine is recognised
//! from DMI, which is world-readable and present before anything else is
//! running; the profile it matches names the parts fitted and, more usefully,
//! what each of them refuses.
//!
//! ## Why the registry is split
//!
//! A component is described once and referenced by every machine that carries
//! it, because a processor is the same processor in whatever chassis it is
//! bolted into. The machine template holds only the arrangement — how many of
//! each, in which slots — and the facts that exist only once the parts are
//! combined. Fixing a part fixes it everywhere rather than in whichever copy
//! somebody remembered.
//!
//! ## What this will not do
//!
//! It will not guess. A machine with no matching profile is reported as
//! unrecognised, and every capability question about it answers "not known"
//! rather than defaulting to yes or no. A registry that guessed would be worse
//! than none: an agent told a lever exists will try it, and an agent told one
//! does not exist will stop looking for the fault it would have found.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where the registry is installed. Overridable, because a developer wants the
/// working tree and a package wants the installed copy.
pub fn registry_dir() -> PathBuf {
    std::env::var("FURCATE_HARDWARE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/usr/share/furcate/hardware"))
}

/// How a machine identifies itself before anything is running.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dmi {
    pub sys_vendor: String,
    pub product_name: String,
    pub board_name: String,
}

impl Dmi {
    /// Read from sysfs, where it is world-readable on every machine worth
    /// running on. No privilege, no tool, no daemon.
    pub fn read() -> Self {
        let f = |n: &str| {
            std::fs::read_to_string(format!("/sys/class/dmi/id/{n}"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        Self {
            sys_vendor: f("sys_vendor"),
            product_name: f("product_name"),
            board_name: f("board_name"),
        }
    }

    /// Placeholder strings some vendors ship instead of a fact.
    ///
    /// "To be filled by O.E.M." is not a machine; treating it as one would
    /// match a profile to every unconfigured board in existence.
    pub fn is_meaningful(&self) -> bool {
        let junk = |s: &str| {
            let l = s.to_lowercase();
            s.is_empty()
                || l.contains("to be filled")
                || l.contains("default string")
                || l.contains("not specified")
                || l.contains("system product name")
        };
        !junk(&self.sys_vendor) && !junk(&self.product_name)
    }
}

/// One part, as the registry describes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Component {
    pub id: String,
    pub kind: String,
    #[serde(flatten)]
    pub rest: serde_json::Value,
}

/// A machine, and the parts it is made of.
#[derive(Clone, Debug, Serialize)]
pub struct Profile {
    pub id: String,
    pub vendor: String,
    pub product: String,
    /// Resolved, so a caller never has to chase a reference itself.
    pub components: Vec<Component>,
    /// References the registry names and does not define. Empty on a healthy
    /// registry, and reported rather than silently dropped: a blueprint
    /// pointing at nothing looks complete and resolves to less than it claims.
    pub unresolved: Vec<String>,
    pub raw: serde_json::Value,
}

impl Profile {
    /// Whether this machine can be asked to do a thing.
    ///
    /// Three answers, not two. `None` means the registry says nothing, and that
    /// is different from a refusal in the way that matters: an agent told a
    /// lever does not exist stops looking, while one told nothing is known may
    /// still go and find out.
    pub fn can(&self, what: &str) -> Option<bool> {
        self.raw
            .get("what_can_be_asked")
            .and_then(|m| m.get(what))
            .and_then(|v| v.as_bool())
    }

    /// Faults this model is known for, so an operator meets them as a known
    /// quantity rather than as a discovery at three in the morning.
    pub fn known_faults(&self) -> Vec<String> {
        self.raw
            .get("known_faults")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|f| f.get("ref").and_then(|r| r.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The temperature at which this machine's controller acts on its own.
    ///
    /// The number the software ladder has to stay below. Read from the profile
    /// rather than assumed, because a ladder positioned for the wrong hardware
    /// is not an early response — every rung fires after the controller has
    /// already taken over, which looks like a layered defence and is not one.
    pub fn controller_critical_c(&self) -> Option<i32> {
        self.components
            .iter()
            .find(|c| c.kind == "bmc")
            .and_then(|c| c.rest.get("thermal_authority"))
            .and_then(|t| t.get("critical_c"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32)
    }

    /// The fastest this machine's fans can run.
    ///
    /// Read from the profile for the same reason `controller_critical_c` is:
    /// a fan threshold positioned for the wrong hardware is not a loose
    /// threshold, it is an unreachable one. 12,000 RPM is an early warning on
    /// a machine whose fans reach 18,000 and is above the ceiling of one that
    /// reaches 9,200 — on the second, nothing can ever trip it.
    pub fn fan_max_rpm(&self) -> Option<u32> {
        self.raw
            .get("cooling")
            .and_then(|c| c.get("fan_max_rpm"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
    }

    /// Sensors this model reports but cannot read, and why.
    pub fn blind_sensors(&self) -> Vec<String> {
        self.raw
            .get("sensors")
            .and_then(|s| s.get("blind"))
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).map(String::from).collect())
            .unwrap_or_default()
    }
}

/// What this machine turned out to be.
#[derive(Clone, Debug, Serialize)]
pub enum Recognised {
    /// Matched a profile in the registry.
    Machine(Box<Profile>),
    /// The registry is present and nothing in it matches.
    ///
    /// Named rather than treated as an error: most machines in the world have
    /// no profile written for them, and that is a gap in the registry rather
    /// than a fault in the machine.
    Unknown { dmi: Dmi },
    /// No registry installed at all.
    NoRegistry { dmi: Dmi },
}

impl Recognised {
    pub fn profile(&self) -> Option<&Profile> {
        match self {
            Recognised::Machine(p) => Some(p),
            _ => None,
        }
    }

    /// The same three-valued answer as [`Profile::can`], for callers that have
    /// not matched anything.
    pub fn can(&self, what: &str) -> Option<bool> {
        self.profile().and_then(|p| p.can(what))
    }
}

fn read_json(p: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
}

/// Every component the registry defines, by id.
fn components(dir: &Path) -> BTreeMap<String, Component> {
    let mut out = BTreeMap::new();
    let Ok(kinds) = std::fs::read_dir(dir.join("components")) else {
        return out;
    };
    for kind in kinds.flatten() {
        let Ok(files) = std::fs::read_dir(kind.path()) else { continue };
        for f in files.flatten() {
            let Some(v) = read_json(&f.path()) else { continue };
            let (Some(id), Some(k)) = (
                v.get("id").and_then(|x| x.as_str()),
                v.get("kind").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            out.insert(
                id.to_string(),
                Component { id: id.to_string(), kind: k.to_string(), rest: v },
            );
        }
    }
    out
}

/// Recognise this machine against the installed registry.
pub fn recognise() -> Recognised {
    recognise_in(&registry_dir(), &Dmi::read())
}

/// Recognise a given machine against a given registry. Split out so a test can
/// exercise it without owning the filesystem or the hardware.
pub fn recognise_in(dir: &Path, dmi: &Dmi) -> Recognised {
    if !dir.join("machines").is_dir() {
        return Recognised::NoRegistry { dmi: dmi.clone() };
    }
    if !dmi.is_meaningful() {
        return Recognised::Unknown { dmi: dmi.clone() };
    }

    let parts = components(dir);
    let Ok(machines) = std::fs::read_dir(dir.join("machines")) else {
        return Recognised::Unknown { dmi: dmi.clone() };
    };

    for f in machines.flatten() {
        let Some(v) = read_json(&f.path()) else { continue };
        let m = v.get("identity").and_then(|i| i.get("_match"));
        let want = |k: &str| m.and_then(|m| m.get(k)).and_then(|x| x.as_str()).unwrap_or("");
        // Matched case-insensitively: vendors are inconsistent about it between
        // firmware releases, and a profile that stopped matching after a BIOS
        // update would be the most confusing possible failure.
        let same = |a: &str, b: &str| !b.is_empty() && a.eq_ignore_ascii_case(b);
        if !(same(&dmi.sys_vendor, want("sys_vendor")) && same(&dmi.product_name, want("product_name")))
        {
            continue;
        }

        let mut resolved = Vec::new();
        let mut unresolved = Vec::new();
        for c in v.get("components").and_then(|a| a.as_array()).into_iter().flatten() {
            let Some(r) = c.get("ref").and_then(|x| x.as_str()) else { continue };
            match parts.get(r) {
                Some(p) => resolved.push(p.clone()),
                None => unresolved.push(r.to_string()),
            }
        }

        return Recognised::Machine(Box::new(Profile {
            id: v.get("id").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
            vendor: dmi.sys_vendor.clone(),
            product: dmi.product_name.clone(),
            components: resolved,
            unresolved,
            raw: v,
        }));
    }
    Recognised::Unknown { dmi: dmi.clone() }
}

/// `deploy/hardware`, found by walking up rather than by counting `..`.
///
/// This was `CARGO_MANIFEST_DIR/../../deploy/hardware`, which encoded the
/// crate's depth in the tree. That depth changed when crates moved from
/// `crates/<crate>` to `crates/<licence-side>/<crate>` for the licence split,
/// and eight tests began failing on an assertion about DMI matching rather than
/// on anything naming a missing directory — the registry simply loaded empty and
/// recognised nothing. Searching cannot rot that way.
#[cfg(test)]
fn repo_hardware_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("deploy/hardware");
        if candidate.is_dir() {
            return candidate;
        }
        if !dir.pop() {
            panic!("deploy/hardware not found in any ancestor of the host crate");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> PathBuf {
        // The shipped one, so the tests exercise what is actually installed
        // rather than a fixture that agrees with them by construction.
        repo_hardware_dir()
    }

    fn c740() -> Dmi {
        Dmi {
            sys_vendor: "FUJITSU".into(),
            product_name: "CELSIUS C740".into(),
            board_name: "D3288-A2".into(),
        }
    }

    #[test]
    fn this_sites_machine_is_recognised_and_its_parts_resolve() {
        let r = recognise_in(&registry(), &c740());
        let p = r.profile().expect("the C740 profile");
        assert_eq!(p.id, "machine/fujitsu-celsius-c740");
        assert!(p.components.len() >= 7, "every part resolved: {}", p.components.len());
        assert!(p.unresolved.is_empty(), "dangling: {:?}", p.unresolved);
    }

    #[test]
    fn what_the_machine_refuses_is_answerable_without_trying_it() {
        // The point of the registry. An agent asking whether it can move the
        // fans gets an answer instead of finding out by issuing a command the
        // controller does not implement.
        let r = recognise_in(&registry(), &c740());
        assert_eq!(r.can("fan_speed"), Some(false));
        assert_eq!(r.can("cpu_performance"), Some(true));
        assert_eq!(r.can("measured_boot"), Some(false));
    }

    #[test]
    fn an_unwritten_capability_is_not_known_rather_than_refused() {
        // Three answers, not two. An agent told a lever does not exist stops
        // looking; one told nothing is known may still go and find out.
        let r = recognise_in(&registry(), &c740());
        assert_eq!(r.can("something-nobody-has-described"), None);
    }

    #[test]
    fn a_machine_with_no_profile_is_unknown_rather_than_guessed_at() {
        let other = Dmi {
            sys_vendor: "Some Other Vendor".into(),
            product_name: "Some Other Machine".into(),
            board_name: String::new(),
        };
        let r = recognise_in(&registry(), &other);
        assert!(matches!(r, Recognised::Unknown { .. }));
        assert_eq!(r.can("fan_speed"), None, "nothing is claimed about a machine nobody described");
    }

    #[test]
    fn placeholder_dmi_matches_nothing() {
        // "To be filled by O.E.M." is not a machine, and treating it as one
        // would match a profile to every unconfigured board in existence.
        for junk in ["To be filled by O.E.M.", "Default string", "", "System Product Name"] {
            let d = Dmi {
                sys_vendor: "FUJITSU".into(),
                product_name: junk.into(),
                board_name: String::new(),
            };
            assert!(!d.is_meaningful(), "{junk:?} should not be treated as a product");
            assert!(matches!(recognise_in(&registry(), &d), Recognised::Unknown { .. }));
        }
    }

    #[test]
    fn a_firmware_update_that_changes_the_case_does_not_lose_the_machine() {
        // Vendors are inconsistent about capitalisation between releases, and a
        // profile that stopped matching after a BIOS update would be the most
        // confusing possible failure.
        let d = Dmi {
            sys_vendor: "Fujitsu".into(),
            product_name: "Celsius C740".into(),
            board_name: String::new(),
        };
        assert!(recognise_in(&registry(), &d).profile().is_some());
    }

    #[test]
    fn no_registry_is_a_different_answer_from_no_match() {
        // One is a machine nobody has described; the other is a machine that
        // cannot be described because nothing is installed. Different fixes.
        let r = recognise_in(Path::new("/nonexistent/registry"), &c740());
        assert!(matches!(r, Recognised::NoRegistry { .. }));
    }

    #[test]
    fn the_known_faults_and_blind_sensors_come_through() {
        let r = recognise_in(&registry(), &c740());
        let p = r.profile().unwrap();
        assert!(!p.known_faults().is_empty(), "this model has a known one");
        assert!(
            p.blind_sensors().iter().any(|s| s == "RAID Controller"),
            "a sensor reporting nothing because the part is absent: {:?}",
            p.blind_sensors()
        );
    }
}

/// Which capability a lever depends on.
///
/// The bridge between "what this machine is" and "what the control loop is
/// about to try". Without it the profile is a document: the loop would still
/// reach for a lever the hardware refuses, discover it by the refusal, and do
/// so again on the next pass — for as long as the machine ran.
pub fn capability_for_lever(lever: &str) -> &'static str {
    match lever {
        "max_perf_pct" | "governor" => "cpu_performance",
        "turbo" => "cpu_turbo",
        "package_cap_watts" => "power_cap",
        "fan_speed" => "fan_speed",
        // Unknown levers map to a capability nobody has described, which
        // resolves to "not known" rather than to a refusal — the same
        // three-valued answer as everywhere else.
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

/// Whether the control loop should attempt this lever on this machine.
///
/// Three answers collapse to two here, deliberately, and toward *trying*:
/// - refused by the profile → do not attempt, and say which machine refuses.
/// - permitted, or nothing known → attempt.
///
/// Nothing known must not become a refusal. Most machines have no profile
/// written for them, and a control loop that stopped working on unfamiliar
/// hardware because nobody had described it yet would be worse than one that
/// occasionally tries something and is told no.
pub fn may_attempt(r: &Recognised, lever: &str) -> Result<(), String> {
    let cap = capability_for_lever(lever);
    match r.can(cap) {
        Some(false) => Err(match r.profile() {
            Some(p) => format!(
                "{} does not offer {lever}; the profile for {} says so, so it is not worth trying",
                p.product, p.id
            ),
            None => format!("{lever} is not available on this machine"),
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod lever_tests {
    use super::*;

    fn registry() -> PathBuf {
        repo_hardware_dir()
    }

    fn c740() -> Recognised {
        recognise_in(
            &registry(),
            &Dmi {
                sys_vendor: "FUJITSU".into(),
                product_name: "CELSIUS C740".into(),
                board_name: String::new(),
            },
        )
    }

    #[test]
    fn a_lever_the_machine_refuses_is_not_attempted() {
        // This machine's controller does not implement fan control. Without
        // this the loop would reach for it, be refused, and do so again on
        // every pass for as long as the machine ran.
        let e = may_attempt(&c740(), "fan_speed").unwrap_err();
        assert!(e.contains("CELSIUS C740"), "names the machine that refuses: {e}");
        assert!(e.contains("not worth trying"), "{e}");
    }

    #[test]
    fn the_levers_this_machine_does_offer_are_attempted() {
        for lever in ["max_perf_pct", "governor", "turbo"] {
            assert!(may_attempt(&c740(), lever).is_ok(), "{lever} should be attempted");
        }
    }

    #[test]
    fn an_undescribed_capability_is_attempted_rather_than_refused() {
        // `power_cap` is "partial" on this model, which is neither yes nor no,
        // and a lever nobody has described at all is the same case. Refusing
        // would stop the loop from ever finding out.
        assert!(may_attempt(&c740(), "package_cap_watts").is_ok());
        assert!(may_attempt(&c740(), "something-new").is_ok());
    }

    #[test]
    fn an_unrecognised_machine_is_not_prevented_from_working() {
        // Most machines in the world have no profile. A control loop that
        // stopped on unfamiliar hardware because nobody had described it would
        // be worse than one that occasionally tries and is told no.
        let unknown = Recognised::Unknown { dmi: Dmi::default() };
        for lever in ["max_perf_pct", "fan_speed", "turbo"] {
            assert!(may_attempt(&unknown, lever).is_ok(), "{lever} on unknown hardware");
        }
    }
}

#[cfg(test)]
mod thermal_tests {
    use super::*;

    #[test]
    fn the_machines_own_critical_point_comes_out_of_its_parts() {
        // Held on the controller, because that is the component that acts on
        // it — not on the machine, which would be a copy of the same fact in
        // whichever blueprint somebody remembered to update.
        let r = recognise_in(
            &repo_hardware_dir(),
            &Dmi {
                sys_vendor: "FUJITSU".into(),
                product_name: "CELSIUS C740".into(),
                board_name: String::new(),
            },
        );
        assert_eq!(r.profile().unwrap().controller_critical_c(), Some(94));
    }
}
