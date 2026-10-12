//! Talking to a management controller the way the standard says.
//!
//! Everything here reaches the controller through `ipmitool`, and IPMI is a
//! dead end for anything past reading sensors. Its vendor extensions are
//! undocumented number-guessing — the fan investigation on this site ended at
//! `raw 0x30 0x45 → Invalid command` with no way to know whether the command
//! was wrong, the netfn was wrong, or the feature simply was not there. The
//! same settings are named objects in Redfish.
//!
//! Redfish is a DMTF standard, published openly, implemented by essentially
//! every server built since 2018 including these ones. It is HTTPS and JSON
//! against a documented schema, with real authentication and roles rather than
//! a shared cipher key.
//!
//! ## No vendor SDK, and no library
//!
//! The client here is a few hundred lines against the published schema, because
//! the alternative is a vendor SDK — proprietary, per-vendor, and the exact
//! dependency this project exists without. Redfish is a REST API returning
//! JSON; treating it as one costs less than adopting somebody's wrapper.
//!
//! ## Nothing here writes
//!
//! Redfish can reset a chassis, and that capability is why this module is
//! read-only and has no code path that could acquire it. The parts of Redfish
//! that would set a fan profile or apply firmware live behind an operator
//! signature like every other dangerous operation, and are not reachable from
//! an agent. What this adds is *sight*: firmware inventory, thermal objects and
//! structured events that IPMI cannot express.
//!
//! ## Why it is not in use on this site yet
//!
//! The controllers here have their LAN interface unconfigured — channel 2, no
//! address. Reaching them means putting a 2018-firmware BMC on a network, which
//! is a decision with real consequences and belongs to an operator rather than
//! to this code. So this is built, tested against the schema, and dormant. That
//! is stated plainly rather than left for somebody to discover.

use serde::{Deserialize, Serialize};

/// A management controller's own account of itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manager {
    pub id: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    /// Whether the controller reports itself healthy.
    pub health: Option<String>,
}

/// One entry from the firmware inventory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareEntry {
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Whether this component can be updated in place.
    pub updateable: bool,
}

/// A thermal reading, in the schema's own terms.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Thermal {
    pub temperatures: Vec<Sensor>,
    pub fans: Vec<Fan>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Sensor {
    pub name: String,
    pub celsius: Option<f64>,
    /// The vendor's own upper limit, which IPMI does not reliably expose and
    /// which is the number a thermal policy should actually be compared to.
    pub upper_critical: Option<f64>,
    pub health: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Fan {
    pub name: String,
    pub reading: Option<f64>,
    /// `RPM` or `Percent`. IPMI gives a raw number with no units, which is how
    /// a fan at 40% can be mistaken for one that has stopped.
    pub units: Option<String>,
    pub health: Option<String>,
}

/// Read the `Status.Health` field wherever it appears.
///
/// `OK`, `Warning` or `Critical` per the schema. Absent is kept as absent: a
/// component that declines to say is not a component saying it is fine.
fn health_of(v: &serde_json::Value) -> Option<String> {
    v.get("Status")?.get("Health")?.as_str().map(String::from)
}

fn str_of(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(String::from)
}

/// Parse a `/redfish/v1/Managers/{id}` document.
pub fn parse_manager(v: &serde_json::Value) -> Manager {
    Manager {
        id: str_of(v, "Id"),
        model: str_of(v, "Model"),
        firmware_version: str_of(v, "FirmwareVersion"),
        health: health_of(v),
    }
}

/// Parse a `/redfish/v1/UpdateService/FirmwareInventory` collection that has
/// been expanded, or a list of already-fetched members.
///
/// Both shapes are accepted because controllers differ on whether `$expand` is
/// honoured, and a client that only handled one would work on half the fleet.
pub fn parse_firmware_inventory(v: &serde_json::Value) -> Vec<FirmwareEntry> {
    let members = v
        .get("Members")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_else(|| v.as_array().cloned().unwrap_or_default());

    members
        .iter()
        .filter_map(|m| {
            // An unexpanded collection is a list of references with no content.
            // Skipping them is right; inventing an entry from an id would put a
            // component with no version in front of somebody.
            let id = str_of(m, "Id")?;
            Some(FirmwareEntry {
                id,
                name: str_of(m, "Name"),
                version: str_of(m, "Version"),
                updateable: m.get("Updateable").and_then(|u| u.as_bool()).unwrap_or(false),
            })
        })
        .collect()
}

/// Parse a `/redfish/v1/Chassis/{id}/Thermal` document.
pub fn parse_thermal(v: &serde_json::Value) -> Thermal {
    let temperatures = v
        .get("Temperatures")
        .and_then(|t| t.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    Some(Sensor {
                        name: str_of(t, "Name")?,
                        celsius: t.get("ReadingCelsius").and_then(|r| r.as_f64()),
                        upper_critical: t
                            .get("UpperThresholdCritical")
                            .and_then(|r| r.as_f64()),
                        health: health_of(t),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let fans = v
        .get("Fans")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    Some(Fan {
                        // The schema moved from `FanName` to `Name`; both are
                        // in the field.
                        name: str_of(f, "Name").or_else(|| str_of(f, "FanName"))?,
                        reading: f.get("Reading").and_then(|r| r.as_f64()),
                        units: str_of(f, "ReadingUnits"),
                        health: health_of(f),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Thermal { temperatures, fans }
}

impl Thermal {
    /// Fans reported as a percentage of maximum rather than in RPM.
    ///
    /// The units field is the reason to prefer this over IPMI: a raw tachometer
    /// number means nothing without knowing the fan's maximum, and a controller
    /// reporting 40 with no units has been read as both "40%" and "stopped".
    pub fn fans_at_percent(&self) -> Vec<&Fan> {
        self.fans
            .iter()
            .filter(|f| f.units.as_deref() == Some("Percent"))
            .collect()
    }

    /// Sensors at or above the vendor's own critical threshold.
    ///
    /// Compared against the controller's declared limit rather than a figure
    /// chosen here, which is the whole advantage: the vendor knows what this
    /// board tolerates and IPMI does not reliably say.
    pub fn over_critical(&self) -> Vec<&Sensor> {
        self.temperatures
            .iter()
            .filter(|s| match (s.celsius, s.upper_critical) {
                (Some(c), Some(limit)) => c >= limit,
                _ => false,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_manager_document_parses() {
        let v = json!({
            "Id": "iRMC",
            "Model": "iRMC S4",
            "FirmwareVersion": "9.62F",
            "Status": { "Health": "OK", "State": "Enabled" }
        });
        let m = parse_manager(&v);
        assert_eq!(m.model.as_deref(), Some("iRMC S4"));
        assert_eq!(m.firmware_version.as_deref(), Some("9.62F"));
        assert_eq!(m.health.as_deref(), Some("OK"));
    }

    #[test]
    fn a_component_that_declines_to_report_health_is_not_healthy() {
        // Absent and OK are different claims, and defaulting one to the other
        // is how a controller with a blind spot reads as a fleet with none.
        let m = parse_manager(&json!({ "Id": "iRMC" }));
        assert!(m.health.is_none());
    }

    #[test]
    fn firmware_inventory_parses_from_an_expanded_collection() {
        let v = json!({ "Members": [
            { "Id": "BIOS", "Name": "System BIOS", "Version": "V5.0.0.11", "Updateable": true },
            { "Id": "iRMC", "Name": "Management Controller", "Version": "9.62F", "Updateable": true }
        ]});
        let f = parse_firmware_inventory(&v);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].version.as_deref(), Some("V5.0.0.11"));
        assert!(f[0].updateable);
    }

    #[test]
    fn a_bare_array_of_members_parses_too() {
        // Controllers differ on whether $expand is honoured, and a client that
        // handled one shape would work on half a fleet.
        let v = json!([{ "Id": "BIOS", "Version": "V5.0.0.11" }]);
        assert_eq!(parse_firmware_inventory(&v).len(), 1);
    }

    #[test]
    fn unexpanded_references_are_skipped_rather_than_invented() {
        // A collection of links carries no versions. Producing an entry from
        // the id alone would put a component with no version in front of
        // somebody as though it had been read.
        let v = json!({ "Members": [
            { "@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BIOS" }
        ]});
        assert!(parse_firmware_inventory(&v).is_empty());
    }

    #[test]
    fn thermal_carries_the_vendors_own_limits() {
        // The advantage over IPMI: the vendor knows what this board tolerates.
        let v = json!({
            "Temperatures": [
                { "Name": "Ambient", "ReadingCelsius": 32.0, "UpperThresholdCritical": 45.0,
                  "Status": { "Health": "OK" } },
                { "Name": "CPU", "ReadingCelsius": 96.0, "UpperThresholdCritical": 94.0,
                  "Status": { "Health": "Critical" } }
            ],
            "Fans": [
                { "Name": "FAN1 SYS", "Reading": 18400, "ReadingUnits": "RPM",
                  "Status": { "Health": "OK" } },
                { "FanName": "FAN2 SYS", "Reading": 92, "ReadingUnits": "Percent" }
            ]
        });
        let t = parse_thermal(&v);
        assert_eq!(t.temperatures.len(), 2);
        assert_eq!(t.fans.len(), 2, "both the old and new name fields are in the field");

        let over = t.over_critical();
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].name, "CPU");
    }

    #[test]
    fn a_fan_reported_in_percent_is_distinguishable_from_one_in_rpm() {
        // A controller reporting 40 with no units has been read as both "40%"
        // and "stopped", which is the reason units are carried at all.
        let v = json!({ "Fans": [
            { "Name": "a", "Reading": 40, "ReadingUnits": "Percent" },
            { "Name": "b", "Reading": 40, "ReadingUnits": "RPM" }
        ]});
        let t = parse_thermal(&v);
        let pct = t.fans_at_percent();
        assert_eq!(pct.len(), 1);
        assert_eq!(pct[0].name, "a");
    }

    #[test]
    fn a_sensor_with_no_declared_limit_is_never_over_it() {
        // Inventing a threshold would make this module's headline advantage —
        // using the vendor's own number — quietly false.
        let v = json!({ "Temperatures": [{ "Name": "x", "ReadingCelsius": 200.0 }] });
        assert!(parse_thermal(&v).over_critical().is_empty());
    }

    #[test]
    fn an_empty_document_yields_empty_rather_than_panicking() {
        let t = parse_thermal(&json!({}));
        assert!(t.fans.is_empty() && t.temperatures.is_empty());
    }
}
