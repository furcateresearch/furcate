//! A byte-exact capture of an Arduino_BHY2 Standalone sketch, read from a
//! Nicla Sense ME over USB for 60 seconds. It starts mid-stream (the first
//! bytes are line noise) and carries no identifier of the board.
//!
//! The real sketch prints no `range of ...` lines, so counts cannot be scaled
//! until the caller states the range. The printed counts are what a +/-2 g
//! accelerometer gives at rest (about 1 g); +/-8 g would read near 4 g.

use furcate_sense::nicla::{NiclaError, Sample};
use furcate_sense::text::{LineSplitter, TextSession};

const CAPTURE: &[u8] = include_bytes!("fixtures/nicla-standalone-real-capture.bin");

fn run(mut session: TextSession) -> (Vec<Sample>, usize, TextSession) {
    let (mut samples, mut range_unknown) = (vec![], 0usize);
    for l in LineSplitter::new().push(CAPTURE) {
        match session.feed_line(&l) {
            Ok(Some(s)) => samples.push(s),
            Ok(None) => {}
            Err(NiclaError::RangeUnknown(_)) => range_unknown += 1,
            Err(_) => {}
        }
    }
    (samples, range_unknown, session)
}

#[test]
fn without_ranges_counts_are_refused_not_guessed() {
    let (samples, unknown, session) = run(TextSession::new());
    assert_eq!(unknown, 120, "60 accelerometer and 60 gyroscope lines have no range");
    assert_eq!((session.refused_accel_no_range, session.refused_gyro_no_range, session.refused_other), (60, 60, 0));
    assert_eq!(session.skipped_classes(), vec!["accelerometer", "gyroscope"]);
    assert!(session.summary().contains("60 accelerometer lines and 60 gyroscope lines"));
    assert_eq!(session.rejected, 1, "only the noisy first line is malformed");
    assert!(samples.iter().all(|s| !matches!(s, Sample::Acceleration { .. } | Sample::AngularRate { .. })));
    let gas: Vec<f64> = samples.iter().filter_map(|s| if let Sample::GasResistance(g) = s { Some(*g) } else { None }).collect();
    assert_eq!(gas.len(), 60);
    assert!(gas.iter().all(|g| (5_000.0..=500_000.0).contains(g)), "raw resistance in ohms");
    assert_eq!(samples.len(), 147, "60 gas, 27 temperature, 60 rotation");
}

#[test]
fn at_rest_the_accelerometer_reads_one_g_only_at_two_g_full_scale() {
    let magnitude = |g: f64| {
        let (samples, unknown, session) = run(TextSession::with_configured(Some(g), Some(2000.0)).unwrap());
        assert_eq!(unknown, 0);
        assert!(session.skipped_classes().is_empty());
        assert_eq!(samples.iter().filter(|s| matches!(s, Sample::AngularRate { .. })).count(), 60);
        let m: Vec<f64> = samples
            .iter()
            .filter_map(|s| if let Sample::Acceleration { x, y, z } = s { Some((x * x + y * y + z * z).sqrt() / 9.80665) } else { None })
            .collect();
        assert_eq!(m.len(), 60);
        m.iter().sum::<f64>() / m.len() as f64
    };
    let two = magnitude(2.0);
    assert!((0.97..1.03).contains(&two), "{two}");
    assert!(magnitude(8.0) > 3.5);
}
