//! The text the stock `Standalone` example prints over USB serial.
//!
//! The stock host-controlled `App` sketch keeps USB serial silent, so the only
//! stream a bare board offers without new firmware is the human-readable output
//! of the `Standalone` example, one line per sensor per second at 115200 baud:
//!
//! ```text
//! range of accel: +/-8g
//! acceleration: XYZ values - X: 5807   Y: 1622   Z: 15767
//! gyroscope: XYZ values - X: 7   Y: -4   Z: 2
//! temperature: 28.290
//! gas: 949.000
//! rotation: Quaternion values - X: 0.048   Y: -0.176   Z: 0.003   W: 0.983   Accuracy: 3.142
//! ```
//!
//! That is a debugging print, not a protocol, so the parser is strict instead
//! of forgiving. A line is accepted only if it has exactly the expected shape,
//! and floating-point fields must carry the three decimals the library always
//! prints, because a line cut off mid-number would otherwise parse as a
//! plausible smaller one. Interleaved or truncated lines are rejected and
//! counted, never repaired. For anything that has to keep running, the framed
//! format in [`crate::frame`] is the production serial path.

use crate::nicla::{NiclaError, Ranges, Sample};

/// Longest line the splitter keeps. The longest line the sketch prints is
/// under 100 bytes; anything past this is noise and is dropped to the newline.
pub const MAX_LINE: usize = 256;

/// Cuts a byte stream into lines without trusting it.
#[derive(Debug, Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    overflow: bool,
    /// Lines dropped for being too long.
    pub dropped: u64,
}

impl LineSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes; get back every line completed by them. A trailing partial
    /// line is held until its newline arrives.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\n' {
                if self.overflow {
                    self.dropped += 1;
                } else {
                    let mut line = std::mem::take(&mut self.buf);
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    out.push(line);
                }
                self.buf.clear();
                self.overflow = false;
            } else if !self.overflow {
                if self.buf.len() >= MAX_LINE {
                    self.overflow = true;
                    self.buf.clear();
                } else {
                    self.buf.push(b);
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TextEvent {
    AccelRange { g: f64 },
    GyroRange { dps: f64 },
    Acceleration { x: i16, y: i16, z: i16 },
    Gyroscope { x: i16, y: i16, z: i16 },
    Temperature(f64),
    Gas(f64),
    Rotation { x: f64, y: f64, z: f64, w: f64, accuracy: f64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    NotText,
    Unrecognised,
    Malformed(&'static str),
}

impl std::fmt::Display for TextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextError::NotText => write!(f, "line is not ASCII text"),
            TextError::Unrecognised => write!(f, "line is not one the sketch prints"),
            TextError::Malformed(why) => write!(f, "line is malformed: {why}"),
        }
    }
}

impl std::error::Error for TextError {}

/// A float as the library prints it: optional minus, digits, a point, three digits.
fn fixed3(tok: &str) -> Result<f64, TextError> {
    let body = tok.strip_prefix('-').unwrap_or(tok);
    let (int, frac) = body.split_once('.').ok_or(TextError::Malformed("number has no decimals"))?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(int) || frac.len() != 3 || !digits(frac) || int.len() > 12 {
        return Err(TextError::Malformed("number is not in the printed three-decimal form"));
    }
    tok.parse::<f64>().map_err(|_| TextError::Malformed("number does not parse"))
}

fn int16(tok: &str) -> Result<i16, TextError> {
    let body = tok.strip_prefix('-').unwrap_or(tok);
    if body.is_empty() || body.len() > 6 || !body.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TextError::Malformed("count is not an integer"));
    }
    tok.parse::<i16>().map_err(|_| TextError::Malformed("count is outside 16 bits"))
}

fn range_value(tok: &str, unit: &str) -> Result<f64, TextError> {
    let n = tok
        .strip_prefix("+/-")
        .and_then(|t| t.strip_suffix(unit))
        .ok_or(TextError::Malformed("range is not `+/-<n><unit>`"))?;
    let v: f64 = n.parse().map_err(|_| TextError::Malformed("range does not parse"))?;
    if !v.is_finite() || v <= 0.0 || v > 10_000.0 {
        return Err(TextError::Malformed("range is out of bounds"));
    }
    Ok(v)
}

/// Parse one line. `Ok(None)` is a blank line, which the sketch prints after
/// every sensor line.
pub fn parse_line(line: &[u8]) -> Result<Option<TextEvent>, TextError> {
    if !line.is_ascii() {
        return Err(TextError::NotText);
    }
    let s = std::str::from_utf8(line).map_err(|_| TextError::NotText)?;
    let t: Vec<&str> = s.split_whitespace().collect();
    if t.is_empty() {
        return Ok(None);
    }
    let xyz = |t: &[&str]| -> Result<(i16, i16, i16), TextError> {
        if t.len() != 10 || t[1..4] != ["XYZ", "values", "-"] || t[4] != "X:" || t[6] != "Y:" || t[8] != "Z:" {
            return Err(TextError::Malformed("not an XYZ line"));
        }
        Ok((int16(t[5])?, int16(t[7])?, int16(t[9])?))
    };
    let ev = match t[0] {
        "range" if t.len() == 4 && t[1] == "of" && t[2] == "accel:" => {
            TextEvent::AccelRange { g: range_value(t[3], "g")? }
        }
        "range" if t.len() == 4 && t[1] == "of" && t[2] == "gyro:" => {
            TextEvent::GyroRange { dps: range_value(t[3], "dps")? }
        }
        "acceleration:" => {
            let (x, y, z) = xyz(&t)?;
            TextEvent::Acceleration { x, y, z }
        }
        "gyroscope:" => {
            let (x, y, z) = xyz(&t)?;
            TextEvent::Gyroscope { x, y, z }
        }
        "temperature:" if t.len() == 2 => TextEvent::Temperature(fixed3(t[1])?),
        "gas:" if t.len() == 2 => TextEvent::Gas(fixed3(t[1])?),
        "rotation:" => {
            if t.len() != 14
                || t[1..4] != ["Quaternion", "values", "-"]
                || [t[4], t[6], t[8], t[10], t[12]] != ["X:", "Y:", "Z:", "W:", "Accuracy:"]
            {
                return Err(TextError::Malformed("not a quaternion line"));
            }
            TextEvent::Rotation {
                x: fixed3(t[5])?,
                y: fixed3(t[7])?,
                z: fixed3(t[9])?,
                w: fixed3(t[11])?,
                accuracy: fixed3(t[13])?,
            }
        }
        _ => return Err(TextError::Unrecognised),
    };
    Ok(Some(ev))
}

/// Turns the line stream into physical-unit samples.
///
/// The accelerometer and gyroscope print raw counts whose scale is the range
/// the sketch printed earlier, so the session remembers the latest range lines.
/// Until a range has been seen, counts are refused rather than guessed; a
/// session started mid-stream must be given the ranges explicitly.
#[derive(Debug, Default)]
pub struct TextSession {
    ranges: Ranges,
    seen_valid_temperature: bool,
    /// Lines rejected as malformed or unrecognised.
    pub rejected: u64,
    /// Acceleration lines refused because no accelerometer range is known.
    pub refused_accel_no_range: u64,
    /// Gyroscope lines refused because no gyroscope range is known.
    pub refused_gyro_no_range: u64,
    /// Valid lines refused for any other reason.
    pub refused_other: u64,
}

impl TextSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start with ranges the caller knows, for joining a stream after its
    /// startup lines. The choice is the caller's and is not inferred.
    pub fn with_ranges(accel_g: f64, gyro_dps: f64) -> Result<Self, NiclaError> {
        let mut s = Self::default();
        s.ranges.set_accel(accel_g)?;
        s.ranges.set_gyro(gyro_dps)?;
        Ok(s)
    }

    /// Start with whichever ranges the caller configured. A range left as
    /// `None` stays unknown until the stream prints one, and counts that need
    /// it are refused and counted.
    pub fn with_configured(accel_g: Option<f64>, gyro_dps: Option<f64>) -> Result<Self, NiclaError> {
        let mut s = Self::default();
        if let Some(g) = accel_g {
            s.ranges.set_accel(g)?;
        }
        if let Some(d) = gyro_dps {
            s.ranges.set_gyro(d)?;
        }
        Ok(s)
    }

    /// The sensor classes whose lines were skipped for want of a range.
    pub fn skipped_classes(&self) -> Vec<&'static str> {
        let mut v = vec![];
        if self.refused_accel_no_range > 0 {
            v.push("accelerometer");
        }
        if self.refused_gyro_no_range > 0 {
            v.push("gyroscope");
        }
        v
    }

    /// One line for a command's summary: what was refused, by reason, and what
    /// was rejected as noise.
    pub fn summary(&self) -> String {
        format!(
            "refused: {} accelerometer lines and {} gyroscope lines with no range, {} other; rejected as noise: {}",
            self.refused_accel_no_range, self.refused_gyro_no_range, self.refused_other, self.rejected
        )
    }

    pub fn ranges(&self) -> &Ranges {
        &self.ranges
    }

    /// Feed one line. `Ok(None)` means the line was valid but carries no sample
    /// (blank, a range announcement, or the sensor's pre-sample placeholder).
    pub fn feed_line(&mut self, line: &[u8]) -> Result<Option<Sample>, NiclaError> {
        let r = self.feed_inner(line);
        match &r {
            Err(NiclaError::RangeUnknown(w)) if *w == "accelerometer" => self.refused_accel_no_range += 1,
            Err(NiclaError::RangeUnknown(_)) => self.refused_gyro_no_range += 1,
            Err(NiclaError::Text(_)) => {}
            Err(_) => self.refused_other += 1,
            Ok(_) => {}
        }
        r
    }

    fn feed_inner(&mut self, line: &[u8]) -> Result<Option<Sample>, NiclaError> {
        let ev = match parse_line(line) {
            Ok(Some(ev)) => ev,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.rejected += 1;
                return Err(NiclaError::Text(e));
            }
        };
        Ok(match ev {
            TextEvent::AccelRange { g } => {
                self.ranges.set_accel(g)?;
                None
            }
            TextEvent::GyroRange { dps } => {
                self.ranges.set_gyro(dps)?;
                None
            }
            TextEvent::Acceleration { x, y, z } => Some(self.ranges.acceleration(x, y, z)?),
            TextEvent::Gyroscope { x, y, z } => Some(self.ranges.angular_rate(x, y, z)?),
            TextEvent::Temperature(c) => {
                // The library prints 0.000 until the first sample lands. Zero
                // is also a real temperature, so only the zeros before the
                // first non-zero value are treated as placeholders.
                if c == 0.0 && !self.seen_valid_temperature {
                    None
                } else {
                    self.seen_valid_temperature = true;
                    Some(Sample::Temperature(c))
                }
            }
            // Zero ohms is not a physical gas resistance: a placeholder.
            TextEvent::Gas(0.0) => None,
            TextEvent::Gas(g) => Some(Sample::GasResistance(g)),
            TextEvent::Rotation { x, y, z, w, accuracy } => Some(Sample::Rotation { x, y, z, w, accuracy: Some(accuracy) }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Representative output of the `Standalone` example on a Nicla Sense ME,
    /// from the owner session's capture: the startup range lines, the
    /// placeholder temperature, then one second's lines.
    const CAPTURE: &str = include_str!("../tests/fixtures/nicla-standalone-usb.txt");

    #[test]
    fn the_fixture_parses_line_by_line() {
        let mut sp = LineSplitter::new();
        let mut s = TextSession::new();
        let mut samples = Vec::new();
        for line in sp.push(CAPTURE.as_bytes()) {
            if let Some(x) = s.feed_line(&line).expect("fixture line") {
                samples.push(x);
            }
        }
        assert_eq!(s.rejected, 0);
        // The placeholder 0.000 temperature is skipped; the 28.290 is kept.
        assert!(samples.contains(&Sample::Temperature(28.29)));
        assert!(!samples.contains(&Sample::Temperature(0.0)));
        assert!(samples.contains(&Sample::GasResistance(949.0)));
        let Some(Sample::Acceleration { z, .. }) = samples.iter().find(|s| matches!(s, Sample::Acceleration { .. })).cloned() else {
            panic!("no acceleration");
        };
        // 15767 counts at the printed +/-8 g range.
        assert!((z - 15767.0 / 32768.0 * 8.0 * 9.80665).abs() < 1e-9);
    }

    #[test]
    fn the_printed_range_and_the_gravity_vector_disagree_in_the_fixture() {
        // At rest the vector should be one g. Taken at the printed +/-8 g the
        // fixture's acceleration is about four g; at +/-2 g it is about one.
        // The printed range line therefore cannot be trusted on its own; the
        // framed sketch reads the range back before it reports.
        let mag = |counts: [f64; 3], range_g: f64| {
            (counts.iter().map(|c| (c / 32768.0 * range_g).powi(2)).sum::<f64>()).sqrt()
        };
        let c = [5807.0, 1622.0, 15767.0];
        assert!((mag(c, 8.0) - 4.1).abs() < 0.1);
        assert!((mag(c, 2.0) - 1.03).abs() < 0.05);
    }

    #[test]
    fn counts_are_refused_until_a_range_is_known() {
        let mut s = TextSession::new();
        let e = s.feed_line(b"acceleration: XYZ values - X: 1   Y: 2   Z: 3").unwrap_err();
        assert!(matches!(e, NiclaError::RangeUnknown("accelerometer")));
        let mut s = TextSession::with_ranges(2.0, 2000.0).unwrap();
        assert!(s.feed_line(b"acceleration: XYZ values - X: 1   Y: 2   Z: 3").unwrap().is_some());
    }

    #[test]
    fn the_latest_range_line_wins() {
        let mut s = TextSession::new();
        s.feed_line(b"range of accel: +/-8g").unwrap();
        s.feed_line(b"range of accel: +/-2g").unwrap();
        let Some(Sample::Acceleration { x, .. }) = s.feed_line(b"acceleration: XYZ values - X: 16384   Y: 0   Z: 0").unwrap() else {
            panic!()
        };
        assert!((x - 0.5 * 2.0 * 9.80665).abs() < 1e-9);
    }

    #[test]
    fn a_zero_temperature_before_the_first_real_one_is_a_placeholder() {
        let mut s = TextSession::new();
        assert_eq!(s.feed_line(b"temperature: 0.000").unwrap(), None);
        assert_eq!(s.feed_line(b"temperature: 21.500").unwrap(), Some(Sample::Temperature(21.5)));
        // After a real one, zero is a measurement.
        assert_eq!(s.feed_line(b"temperature: 0.000").unwrap(), Some(Sample::Temperature(0.0)));
    }

    #[test]
    fn truncated_numbers_are_rejected_not_read_short() {
        assert!(parse_line(b"temperature: 28.2").is_err());
        assert!(parse_line(b"temperature: 28.").is_err());
        assert!(parse_line(b"temperature: 28").is_err());
        assert!(parse_line(b"acceleration: XYZ values - X: 5807   Y: 1622").is_err());
        assert!(parse_line(b"rotation: Quaternion values - X: 0.048   Y: -0.176").is_err());
    }

    #[test]
    fn interleaved_lines_are_rejected() {
        assert!(parse_line(b"acceleration: XYZ values - X: 5807   Y: 1622   Z: 157gyroscope: XYZ values").is_err());
        assert!(parse_line(b"gyroscopetemperature: 28.290").is_err());
        assert!(parse_line(b"temperature: 28.290 gas: 949.000").is_err());
    }

    #[test]
    fn non_text_and_unknown_lines_are_named() {
        assert_eq!(parse_line(&[0xFF, 0xFE, b'x']), Err(TextError::NotText));
        assert_eq!(parse_line(b"hello"), Err(TextError::Unrecognised));
        assert_eq!(parse_line(b"   "), Ok(None));
    }

    #[test]
    fn counts_outside_sixteen_bits_are_rejected() {
        assert!(parse_line(b"gyroscope: XYZ values - X: 40000   Y: 0   Z: 0").is_err());
        assert!(parse_line(b"gyroscope: XYZ values - X: -32768   Y: 0   Z: 0").is_ok());
    }

    #[test]
    fn ranges_must_be_sane() {
        assert!(parse_line(b"range of accel: +/-0g").is_err());
        assert!(parse_line(b"range of accel: +/-8dps").is_err());
        assert!(parse_line(b"range of gyro: +/-2000dps").is_ok());
        assert!(parse_line(b"range of gyro: +/-NaNdps").is_err());
    }

    #[test]
    fn the_splitter_holds_partial_lines_and_handles_crlf() {
        let mut sp = LineSplitter::new();
        assert!(sp.push(b"temper").is_empty());
        let l = sp.push(b"ature: 1.000\r\ngas");
        assert_eq!(l, vec![b"temperature: 1.000".to_vec()]);
        assert_eq!(sp.push(b": 2.000\n"), vec![b"gas: 2.000".to_vec()]);
    }

    #[test]
    fn an_overlong_line_is_dropped_to_its_newline_and_the_next_survives() {
        let mut sp = LineSplitter::new();
        let mut junk = vec![b'x'; MAX_LINE * 3];
        junk.push(b'\n');
        junk.extend_from_slice(b"gas: 1.000\n");
        assert_eq!(sp.push(&junk), vec![b"gas: 1.000".to_vec()]);
        assert_eq!(sp.dropped, 1);
    }

    #[test]
    fn random_bytes_never_panic_the_line_path() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut sp = LineSplitter::new();
        let mut s = TextSession::with_ranges(8.0, 2000.0).unwrap();
        let words: [&[u8]; 8] = [b"acceleration: ", b"XYZ values - ", b"X: ", b"-", b"rotation: ", b"0.", b"\n", b"temperature: "];
        for _ in 0..20_000 {
            let mut chunk = Vec::new();
            for _ in 0..(next() % 12) {
                if next() % 3 == 0 {
                    chunk.push(next() as u8);
                } else {
                    chunk.extend_from_slice(words[(next() % 8) as usize]);
                }
            }
            for line in sp.push(&chunk) {
                let _ = s.feed_line(&line);
            }
        }
    }
}
