//! The kinds table the consumer of a physical batch keeps, checked against the
//! producer's catalogue. The same file is committed byte for byte in the
//! consumer's repository; a kind, unit or modality that changes here without
//! the table changing fails this test, and the consumer's test fails the other
//! way.

use furcate_sense::nicla::{Origin, CHANNELS};
use serde_json::Value;

const TABLE: &str = include_str!("fixtures/measurement-kinds.json");

fn table() -> Value {
    serde_json::from_str(TABLE).unwrap()
}

#[test]
fn every_channel_names_a_kind_with_the_unit_and_modality_the_consumer_expects() {
    let t = table();
    let kinds = t["kinds"].as_object().unwrap();
    for c in CHANNELS {
        let kind = serde_json::to_value(c.kind).unwrap();
        let unit = serde_json::to_value(c.unit).unwrap();
        let row = kinds.get(kind.as_str().unwrap()).unwrap_or_else(|| panic!("channel {} has kind {kind} that the consumer does not know", c.suffix));
        assert_eq!(row["unit"], unit, "{}", c.suffix);
        let modality = serde_json::to_value(c.kind.modality()).unwrap();
        assert_eq!(row["modality"], modality, "{}", c.suffix);
        assert_eq!(row["may_actuate_alone"], c.kind.may_actuate_alone(), "{}", c.suffix);
    }
}

#[test]
fn every_module_quantity_is_a_kind_in_the_table() {
    let t = table();
    let kinds = t["kinds"].as_object().unwrap();
    for needed in [
        "acceleration", "angular_rate", "magnetic_field", "orientation", "pressure", "temperature", "humidity",
        "gas_resistance", "air_quality_index", "gas_equivalent", "step_count", "activity_state",
    ] {
        assert!(kinds.contains_key(needed), "{needed}");
    }
    assert!(CHANNELS.iter().any(|c| c.origin == Origin::HostChip));
}

const LEAF: &str = include_str!("fixtures/nicla-leaf-channels.txt");

/// The firmware publishes the module's channels under leaf sensor indices 16 and up, named and typed in
/// its own table; the same table is checked in the firmware's host test. Here it is checked against the
/// cascade catalogue, so an index that names a channel the cascade does not know, or a kind or unit that
/// differs, fails.
#[test]
fn the_leaf_firmware_table_matches_the_cascade_catalogue() {
    let unit = |u: &str| match u {
        "m/s2" => "metres_per_second_squared",
        "rad/s" => "radians_per_second",
        "celsius" => "celsius",
        "pascal" => "pascals",
        "percent" => "percent",
        "ohm" => "ohms",
        "uT" => "microtesla",
        "unitless" => "unitless",
        "ppm" => "ppm",
        "count" => "count",
        other => panic!("unit {other}"),
    };
    let mut n = 0;
    for line in LEAF.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f.len(), 4, "{line}");
        assert_eq!(f[0].parse::<usize>().unwrap(), 16 + n, "indices run on from 16 without a gap");
        let c = CHANNELS.iter().find(|c| c.suffix == f[1]).unwrap_or_else(|| panic!("the cascade has no channel {}", f[1]));
        assert_eq!(c.origin, Origin::Module, "{}", f[1]);
        assert_eq!(serde_json::to_value(c.kind).unwrap(), f[2], "{}", f[1]);
        assert_eq!(serde_json::to_value(c.unit).unwrap(), unit(f[3]), "{}", f[1]);
        n += 1;
    }
    assert_eq!(n, CHANNELS.iter().filter(|c| c.origin == Origin::Module).count(), "every module channel has a leaf index");
}
