//! The module's frame vectors, shared byte for byte with the leaf firmware's host
//! tests (`test/host/vectors/nicla-frame-vectors.txt` there). Each frame goes
//! through the binary decoder here and the C decoder there, and both must give
//! the listed channel values, so the two decoders cannot drift apart.

use furcate_sense::bhy2::{ReadKind, Record};
use furcate_sense::nicla::{channel_values, samples_from_record, NiclaError, Ranges};

const VECTORS: &str = include_str!("fixtures/nicla-frame-vectors.txt");

fn hex(bytes: &str) -> Vec<u8> {
    bytes.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
}

fn ranges(spec: &str) -> Ranges {
    let mut r = Ranges::default();
    for kv in spec.split_whitespace() {
        let (k, v) = kv.split_once('=').unwrap();
        let v: f64 = v.parse().unwrap();
        match k {
            "accel" => r.set_accel(v).unwrap(),
            "gyro" => r.set_gyro(v).unwrap(),
            "mag" => r.set_mag(v).unwrap(),
            other => panic!("unknown range {other}"),
        }
    }
    r
}

#[test]
fn every_vector_decodes_to_the_listed_channels() {
    let mut r = Ranges::default();
    let mut checked = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        if let Some(spec) = line.strip_prefix("ranges ") {
            r = ranges(spec);
            continue;
        }
        let (frame, want) = line.strip_prefix("frame ").unwrap().split_once(" -> ").unwrap();
        let bytes = hex(frame);
        let kind = if bytes.len() == 12 { ReadKind::Short } else { ReadKind::LongLegacy };
        let rec = Record::from_wire(&bytes, kind).unwrap();
        let out: Result<Vec<(&str, f64)>, NiclaError> = samples_from_record(&rec, &r).and_then(|ss| {
            let mut v = Vec::new();
            for s in &ss {
                v.extend(channel_values(s)?);
            }
            Ok(v)
        });
        match want.trim() {
            "refused" => assert!(matches!(out, Err(NiclaError::RangeUnknown(_))), "{line}"),
            "withheld" => assert!(matches!(out, Err(NiclaError::Withheld(_))), "{line}"),
            list => {
                let got = out.unwrap_or_else(|e| panic!("{line}: {e}"));
                let want: Vec<(&str, f64)> = list.split_whitespace().map(|kv| kv.split_once('=').unwrap()).map(|(k, v)| (k, v.parse().unwrap())).collect();
                assert_eq!(got.len(), want.len(), "{line}");
                for ((gk, gv), (wk, wv)) in got.iter().zip(&want) {
                    assert_eq!(gk, wk, "{line}");
                    assert!((gv - wv).abs() <= 1e-4 * wv.abs().max(1.0), "{line}: {gk} {gv} vs {wv}");
                }
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 27);
}
