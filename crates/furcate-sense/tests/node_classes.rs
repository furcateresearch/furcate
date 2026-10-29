//! The node-class table against its committed file, so a change to what a position can host or reach
//! is a reviewed change. Regenerate with `UPDATE_GOLDEN=1 cargo test -p furcate-sense --test node_classes`.

use furcate_sense::cascade::classes::catalogue;

const GOLDEN: &str = include_str!("fixtures/node-classes.json");
const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/node-classes.json");

fn now() -> String {
    let mut s = serde_json::to_string_pretty(&catalogue()).unwrap();
    s.push('\n');
    s
}

#[test]
fn the_class_table_is_what_the_code_says_now() {
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(PATH, now()).unwrap();
        return;
    }
    assert!(now() == GOLDEN, "cascade::classes differs from tests/fixtures/node-classes.json; regenerate with UPDATE_GOLDEN=1");
}

#[test]
fn actuation_is_off_in_every_class() {
    let c = catalogue();
    for (name, v) in c["classes"].as_object().unwrap() {
        assert_eq!(v["actuation_enabled"], false, "{name}");
    }
}
