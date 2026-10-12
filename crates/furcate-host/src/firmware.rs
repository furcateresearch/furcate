//! The most privileged software on the machine, and how old it is.
//!
//! Firmware sits underneath everything else this system reasons about. It runs
//! before the kernel, it keeps running alongside it in the management
//! controller, it can power the chassis off, and it carries its own stream of
//! vulnerabilities on its own schedule. Until now nothing here knew a single
//! version string about any of it — that these machines run firmware from March
//! 2018 was discovered by a human, by hand, during an investigation into
//! something else.
//!
//! ## Read from the kernel, not from a vendor tool
//!
//! The SMBIOS tables are decoded by the kernel and exposed under
//! `/sys/class/dmi/id`, world-readable, on every machine. No agent, no vendor
//! utility, no privilege. Where `fwupd` is present its inventory is richer and
//! is used as well — but it is treated as an enhancement rather than a
//! requirement, because a module that needs a daemon installed is a module that
//! reports nothing on the machines most likely to have old firmware.
//!
//! ## Age is the signal, not a version string
//!
//! A version number means nothing without knowing the vendor's release history,
//! which is not machine-readable and differs per vendor. The build date is on
//! every SMBIOS table and answers the question that actually matters: is this
//! machine running firmware from an era whose vulnerabilities are now public.
//! Eight years is not a version to compare — it is a fact about exposure.

use serde::{Deserialize, Serialize};

/// Firmware as SMBIOS and, where available, `fwupd` describe it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Firmware {
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    /// As printed in the SMBIOS table, `MM/DD/YYYY`.
    pub bios_date: Option<String>,
    pub board_name: Option<String>,
    pub product_name: Option<String>,
    pub system_vendor: Option<String>,
    /// Devices `fwupd` can see, where it is installed. Empty is not a claim
    /// that none exist.
    pub components: Vec<Component>,
    /// Whether anything richer than SMBIOS answered, so a machine with no tool
    /// is distinguishable from one with nothing to update.
    pub inventory_available: bool,
}

/// One updatable component.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    /// Version available to install, where the tool knows of one.
    pub available: Option<String>,
    /// Whether the vendor flagged the update as fixing a security issue.
    pub security_update: bool,
}

/// How exposed this machine's firmware is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Age {
    /// Within the window where a vendor is still shipping fixes.
    Current { years: u32 },
    /// Old enough that fixes exist and have not been applied.
    Stale { years: u32 },
    /// Old enough that the vulnerabilities of its era are thoroughly public.
    Ancient { years: u32 },
    /// The table did not carry a date.
    Unknown,
}

impl Age {
    pub fn is_concerning(&self) -> bool {
        matches!(self, Age::Stale { .. } | Age::Ancient { .. })
    }

    pub fn years(&self) -> Option<u32> {
        match self {
            Age::Current { years } | Age::Stale { years } | Age::Ancient { years } => Some(*years),
            Age::Unknown => None,
        }
    }
}

/// Years past which firmware is called stale, then ancient.
///
/// Three is roughly a server generation and about as long as a vendor keeps
/// shipping routine updates. Six is two generations, by which point the machine
/// is running code whose flaws have been described in public for years.
pub const STALE_YEARS: u32 = 3;
pub const ANCIENT_YEARS: u32 = 6;

/// Parse an SMBIOS date and judge its age.
///
/// The format is `MM/DD/YYYY` and only the year is used. Month precision would
/// suggest an accuracy the question does not have: nothing here changes at
/// eleven months versus thirteen.
pub fn age(bios_date: Option<&str>, now_year: u32) -> Age {
    let Some(d) = bios_date else { return Age::Unknown };
    let Some(year) = d.rsplit('/').next().and_then(|y| y.trim().parse::<u32>().ok()) else {
        return Age::Unknown;
    };
    // A firmware dated in the future is a wrong clock or a corrupt table, and
    // reporting it as brand new would be the one answer that is certainly
    // wrong.
    if year > now_year || year < 1990 {
        return Age::Unknown;
    }
    let years = now_year - year;
    if years >= ANCIENT_YEARS {
        Age::Ancient { years }
    } else if years >= STALE_YEARS {
        Age::Stale { years }
    } else {
        Age::Current { years }
    }
}

/// Read one SMBIOS field.
///
/// Missing and empty are both `None`. Several of these fields are populated
/// with padding or with strings like `To be filled by O.E.M.` on boards whose
/// vendor did not bother, and a system reporting that as its product name is
/// reporting nothing.
pub fn dmi_field(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty()
        || t.eq_ignore_ascii_case("to be filled by o.e.m.")
        || t.eq_ignore_ascii_case("default string")
        || t.eq_ignore_ascii_case("not specified")
        || t.eq_ignore_ascii_case("unknown")
    {
        return None;
    }
    Some(t.to_string())
}

/// Parse `fwupdmgr get-devices --json`.
///
/// Only name, version, and whether an update is flagged as security-relevant
/// are read. `fwupd` reports a great deal more and none of it is interpreted
/// here — reading a narrow known shape out of somebody else's JSON is what
/// makes consuming it safe.
pub fn parse_fwupd(v: &serde_json::Value) -> Vec<Component> {
    let Some(devices) = v.get("Devices").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    devices
        .iter()
        .filter_map(|d| {
            let name = d.get("Name")?.as_str()?.to_string();
            let releases = d.get("Releases").and_then(|r| r.as_array());
            // The first release is the newest offered. A device with no
            // releases has nothing available, which is different from having
            // an update that happens to match the installed version.
            let newest = releases.and_then(|r| r.first());
            let available = newest
                .and_then(|r| r.get("Version"))
                .and_then(|x| x.as_str())
                .map(String::from);
            let installed = d.get("Version").and_then(|x| x.as_str()).map(String::from);
            let security_update = newest
                .and_then(|r| r.get("Flags"))
                .and_then(|f| f.as_array())
                .is_some_and(|f| f.iter().any(|x| x.as_str() == Some("is-upgrade")))
                && newest
                    .and_then(|r| r.get("Urgency"))
                    .and_then(|u| u.as_str())
                    .is_some_and(|u| matches!(u, "high" | "critical"));
            Some(Component {
                name,
                // Only offer an available version when it differs from what is
                // installed; otherwise every device looks like it has an
                // update waiting.
                available: available.filter(|a| Some(a) != installed.as_ref()),
                version: installed,
                security_update,
            })
        })
        .collect()
}

impl Firmware {
    /// Components with an update waiting.
    pub fn updatable(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.available.is_some()).collect()
    }

    /// Components whose update is flagged as fixing a security issue.
    pub fn security_updates(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.security_update).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 2026, the year this was written against.
    const NOW: u32 = 2026;

    #[test]
    fn this_sites_actual_firmware_reads_as_ancient() {
        // Verbatim from both C740s. Eight years is not a version to compare
        // against a changelog; it is a fact about exposure.
        let a = age(Some("03/14/2018"), NOW);
        assert_eq!(a, Age::Ancient { years: 8 });
        assert!(a.is_concerning());
    }

    #[test]
    fn the_thresholds_are_a_server_generation_and_two() {
        assert_eq!(age(Some("01/01/2024"), NOW), Age::Current { years: 2 });
        assert_eq!(age(Some("01/01/2023"), NOW), Age::Stale { years: 3 });
        assert_eq!(age(Some("01/01/2020"), NOW), Age::Ancient { years: 6 });
        assert!(!Age::Current { years: 2 }.is_concerning());
    }

    #[test]
    fn firmware_from_the_future_is_unknown_rather_than_brand_new() {
        // A wrong clock or a corrupt table. Reporting it as current would be
        // the one answer that is certainly wrong.
        assert_eq!(age(Some("01/01/2099"), NOW), Age::Unknown);
        assert_eq!(age(Some("01/01/1970"), NOW), Age::Unknown);
    }

    #[test]
    fn an_unparseable_date_is_unknown_and_not_ancient() {
        // Guessing old would generate an alert on every machine with an odd
        // table, and the alert would be ignored by the second one.
        assert_eq!(age(None, NOW), Age::Unknown);
        assert_eq!(age(Some(""), NOW), Age::Unknown);
        assert_eq!(age(Some("not a date"), NOW), Age::Unknown);
        assert!(!Age::Unknown.is_concerning());
    }

    #[test]
    fn placeholder_dmi_strings_are_not_facts() {
        // A system reporting "To be filled by O.E.M." as its product name is
        // reporting nothing, and storing it would put it in front of somebody
        // as though it meant something.
        assert_eq!(dmi_field("  V5.0.0.11 R1.8.0  "), Some("V5.0.0.11 R1.8.0".into()));
        for junk in ["", "   ", "To be filled by O.E.M.", "Default string", "Not Specified", "Unknown"] {
            assert!(dmi_field(junk).is_none(), "{junk:?} should not be a fact");
        }
    }

    #[test]
    fn fwupd_devices_parse_and_only_real_updates_are_offered() {
        let v = json!({ "Devices": [
            {
                "Name": "System Firmware",
                "Version": "1.2.3",
                "Releases": [ { "Version": "1.4.0", "Urgency": "high", "Flags": ["is-upgrade"] } ]
            },
            {
                "Name": "Network Adapter",
                "Version": "2.0.0",
                "Releases": [ { "Version": "2.0.0", "Urgency": "low" } ]
            },
            { "Name": "Something Fixed", "Version": "9" }
        ]});
        let c = parse_fwupd(&v);
        assert_eq!(c.len(), 3);

        assert_eq!(c[0].available.as_deref(), Some("1.4.0"));
        assert!(c[0].security_update);

        // Same version offered as installed is not an update waiting.
        assert!(c[1].available.is_none(), "an equal version is not an upgrade");
        assert!(!c[1].security_update);

        // No releases at all is not the same as an update that matches.
        assert!(c[2].available.is_none());
    }

    #[test]
    fn a_machine_without_fwupd_yields_nothing_rather_than_an_empty_claim() {
        assert!(parse_fwupd(&json!({})).is_empty());
        let f = Firmware { inventory_available: false, ..Firmware::default() };
        assert!(f.updatable().is_empty());
        // The flag is what separates "nothing to update" from "nothing asked".
        assert!(!f.inventory_available);
    }

    #[test]
    fn updates_and_security_updates_are_counted_separately() {
        // Every security update is an update; the reverse is why the two are
        // reported apart.
        let f = Firmware {
            components: vec![
                Component { name: "a".into(), available: Some("2".into()), security_update: true, ..Component::default() },
                Component { name: "b".into(), available: Some("3".into()), security_update: false, ..Component::default() },
                Component { name: "c".into(), ..Component::default() },
            ],
            inventory_available: true,
            ..Firmware::default()
        };
        assert_eq!(f.updatable().len(), 2);
        assert_eq!(f.security_updates().len(), 1);
    }
}
