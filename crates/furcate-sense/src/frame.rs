//! The framed line format for the production serial path.
//!
//! Firmware for the Nicla Sense ME that wants a stable, checkable stream over
//! USB serial emits one ASCII line per sample in this format. It is specified
//! here and implemented by whoever writes the firmware; no firmware ships in
//! this repository, because the stock sensor libraries are AGPL-3.0 and a
//! sketch linking them is AGPL-3.0 too.
//!
//! ```text
//! $FNS1,<seq>,<millis>,<tag>,<value>[,<value>...]*<HH>\n
//! ```
//!
//! * `FNS1` is the format version. A reader refuses any other version.
//! * `seq` is a `u32` counted per frame, so loss shows as a gap.
//! * `millis` is the device uptime in milliseconds. It orders frames and is not
//!   a wall clock.
//! * `HH` is two uppercase hex digits: the XOR of every byte between `$` and
//!   `*`. It catches the truncation and interleaving a bare serial line suffers.
//!
//! | tag | values | unit |
//! |---|---|---|
//! | `rng` | accel, gyro | full scale in g and in degrees per second |
//! | `acc` | x, y, z | raw counts, scaled by the latest `rng` |
//! | `gyr` | x, y, z | raw counts, scaled by the latest `rng` |
//! | `rot` | x, y, z, w, accuracy | unit quaternion, accuracy in radians |
//! | `tmp` | value | degrees Celsius |
//! | `hum` | value | percent relative humidity |
//! | `prs` | value | pascals |
//! | `gas` | value | ohms |
//! | `iaq` | index, co2 equivalent, b-voc equivalent, accuracy | index, ppm, ppm, 0 to 3 |
//! | `stp` | value | steps |
//!
//! `rng` is sent at start and repeated periodically, so a reader that joins
//! mid-stream learns the scale without guessing it.

use crate::nicla::{NiclaError, Ranges, Sample};

pub const VERSION: &str = "FNS1";
pub const MAX_VALUES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    NotText,
    NoStart,
    NoChecksum,
    BadChecksum { expected: u8, found: u8 },
    Version(String),
    Field(&'static str),
    UnknownTag(String),
    Arity { tag: &'static str, expected: usize, found: usize },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::NotText => write!(f, "frame is not ASCII"),
            FrameError::NoStart => write!(f, "frame does not start with `$`"),
            FrameError::NoChecksum => write!(f, "frame has no `*HH` checksum"),
            FrameError::BadChecksum { expected, found } => {
                write!(f, "checksum {found:02X} does not match {expected:02X}")
            }
            FrameError::Version(v) => write!(f, "frame version `{v}` is not {VERSION}"),
            FrameError::Field(w) => write!(f, "bad field: {w}"),
            FrameError::UnknownTag(t) => write!(f, "unknown tag `{t}`"),
            FrameError::Arity { tag, expected, found } => {
                write!(f, "tag `{tag}` carries {expected} values, frame has {found}")
            }
        }
    }
}

impl std::error::Error for FrameError {}

#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub seq: u32,
    pub millis: u32,
    pub tag: String,
    pub values: Vec<f64>,
}

fn checksum(body: &[u8]) -> u8 {
    body.iter().fold(0, |a, b| a ^ b)
}

/// Build a frame line, the way firmware would. Used by tests and simulators.
pub fn encode(seq: u32, millis: u32, tag: &str, values: &[f64]) -> String {
    let mut body = format!("{VERSION},{seq},{millis},{tag}");
    for v in values {
        body.push(',');
        body.push_str(&format!("{v}"));
    }
    format!("${body}*{:02X}", checksum(body.as_bytes()))
}

pub fn parse(line: &[u8]) -> Result<Frame, FrameError> {
    if !line.is_ascii() {
        return Err(FrameError::NotText);
    }
    let s = std::str::from_utf8(line).map_err(|_| FrameError::NotText)?.trim();
    let rest = s.strip_prefix('$').ok_or(FrameError::NoStart)?;
    let (body, sum) = rest.rsplit_once('*').ok_or(FrameError::NoChecksum)?;
    if sum.len() != 2 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(FrameError::Field("checksum is not two hex digits"));
    }
    let found = u8::from_str_radix(sum, 16).map_err(|_| FrameError::Field("checksum"))?;
    let expected = checksum(body.as_bytes());
    if found != expected {
        return Err(FrameError::BadChecksum { expected, found });
    }
    let mut parts = body.split(',');
    let ver = parts.next().unwrap_or("");
    if ver != VERSION {
        return Err(FrameError::Version(ver.chars().take(8).collect()));
    }
    let seq = parts.next().and_then(|p| p.parse::<u32>().ok()).ok_or(FrameError::Field("seq"))?;
    let millis = parts.next().and_then(|p| p.parse::<u32>().ok()).ok_or(FrameError::Field("millis"))?;
    let tag = parts.next().filter(|t| !t.is_empty() && t.len() <= 8).ok_or(FrameError::Field("tag"))?;
    let mut values = Vec::new();
    for p in parts {
        if values.len() == MAX_VALUES {
            return Err(FrameError::Field("too many values"));
        }
        let v: f64 = p.parse().map_err(|_| FrameError::Field("value"))?;
        if !v.is_finite() {
            return Err(FrameError::Field("value is not finite"));
        }
        values.push(v);
    }
    Ok(Frame { seq, millis, tag: tag.to_string(), values })
}

fn counts(v: f64) -> Result<i16, FrameError> {
    if v.fract() == 0.0 && v >= i16::MIN as f64 && v <= i16::MAX as f64 {
        Ok(v as i16)
    } else {
        Err(FrameError::Field("count is not a 16-bit integer"))
    }
}

/// What one frame meant.
#[derive(Clone, Debug, PartialEq)]
pub enum FrameOut {
    /// A scale announcement; nothing to publish.
    Range,
    Sample(Sample),
}

/// Frame-to-sample conversion with loss accounting.
#[derive(Debug, Default)]
pub struct FrameSession {
    ranges: Ranges,
    last_seq: Option<u32>,
    /// Frames the sequence numbers say never arrived.
    pub lost: u64,
    /// Lines rejected by [`parse`].
    pub rejected: u64,
}

fn arity(tag: &'static str, v: &[f64], n: usize) -> Result<(), FrameError> {
    if v.len() == n {
        Ok(())
    } else {
        Err(FrameError::Arity { tag, expected: n, found: v.len() })
    }
}

impl FrameSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ranges(&self) -> &Ranges {
        &self.ranges
    }

    pub fn feed_line(&mut self, line: &[u8]) -> Result<FrameOut, NiclaError> {
        let f = match parse(line) {
            Ok(f) => f,
            Err(e) => {
                self.rejected += 1;
                return Err(NiclaError::Frame(e));
            }
        };
        // Account for loss only on a frame that is itself valid, so a corrupt
        // line cannot move the counter.
        if let Some(last) = self.last_seq {
            let gap = f.seq.wrapping_sub(last).wrapping_sub(1);
            // A restart of the device resets seq; a huge "gap" is that, not loss.
            if gap > 0 && gap < 1 << 20 {
                self.lost += gap as u64;
            }
        }
        self.last_seq = Some(f.seq);
        let v = &f.values;
        let out = match f.tag.as_str() {
            "rng" => {
                arity("rng", v, 2).map_err(NiclaError::Frame)?;
                self.ranges.set_accel(v[0])?;
                self.ranges.set_gyro(v[1])?;
                return Ok(FrameOut::Range);
            }
            "acc" => {
                arity("acc", v, 3).map_err(NiclaError::Frame)?;
                let (x, y, z) = (counts(v[0]), counts(v[1]), counts(v[2]));
                self.ranges.acceleration(x.map_err(NiclaError::Frame)?, y.map_err(NiclaError::Frame)?, z.map_err(NiclaError::Frame)?)?
            }
            "gyr" => {
                arity("gyr", v, 3).map_err(NiclaError::Frame)?;
                let (x, y, z) = (counts(v[0]), counts(v[1]), counts(v[2]));
                self.ranges.angular_rate(x.map_err(NiclaError::Frame)?, y.map_err(NiclaError::Frame)?, z.map_err(NiclaError::Frame)?)?
            }
            "rot" => {
                arity("rot", v, 5).map_err(NiclaError::Frame)?;
                Sample::Rotation { x: v[0], y: v[1], z: v[2], w: v[3], accuracy: Some(v[4]) }
            }
            "tmp" => {
                arity("tmp", v, 1).map_err(NiclaError::Frame)?;
                Sample::Temperature(v[0])
            }
            "hum" => {
                arity("hum", v, 1).map_err(NiclaError::Frame)?;
                Sample::Humidity(v[0])
            }
            "prs" => {
                arity("prs", v, 1).map_err(NiclaError::Frame)?;
                Sample::Pressure(v[0])
            }
            "gas" => {
                arity("gas", v, 1).map_err(NiclaError::Frame)?;
                Sample::GasResistance(v[0])
            }
            "iaq" => {
                arity("iaq", v, 4).map_err(NiclaError::Frame)?;
                if v[3] < 0.0 || v[3] > 3.0 || v[3].fract() != 0.0 {
                    return Err(NiclaError::Frame(FrameError::Field("iaq accuracy is 0 to 3")));
                }
                Sample::AirQuality { index: v[0], co2_eq_ppm: v[1], b_voc_eq_ppm: v[2], accuracy: v[3] as u8 }
            }
            "stp" => {
                arity("stp", v, 1).map_err(NiclaError::Frame)?;
                if v[0] < 0.0 || v[0].fract() != 0.0 || v[0] > u32::MAX as f64 {
                    return Err(NiclaError::Frame(FrameError::Field("step count")));
                }
                Sample::Steps(v[0] as u32)
            }
            other => return Err(NiclaError::Frame(FrameError::UnknownTag(other.chars().take(8).collect()))),
        };
        Ok(FrameOut::Sample(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_round_trips() {
        let line = encode(7, 1234, "tmp", &[28.29]);
        let f = parse(line.as_bytes()).unwrap();
        assert_eq!((f.seq, f.millis, f.tag.as_str()), (7, 1234, "tmp"));
        assert_eq!(f.values, vec![28.29]);
    }

    #[test]
    fn the_checksum_is_the_xor_of_the_body() {
        // Worked by hand for `FNS1,0,0,stp,1`.
        let body = b"FNS1,0,0,stp,1";
        let x = body.iter().fold(0u8, |a, b| a ^ b);
        assert_eq!(encode(0, 0, "stp", &[1.0]), format!("$FNS1,0,0,stp,1*{x:02X}"));
    }

    #[test]
    fn any_single_corrupted_byte_is_caught() {
        let line = encode(1, 2, "acc", &[10.0, -20.0, 30.0]).into_bytes();
        for i in 1..line.len() {
            let mut bad = line.clone();
            bad[i] ^= 0x01;
            assert!(parse(&bad).is_err(), "flip at {i} accepted");
        }
    }

    #[test]
    fn every_truncation_is_rejected() {
        let line = encode(1, 2, "rot", &[0.1, 0.2, 0.3, 0.9, 3.0]).into_bytes();
        for cut in 0..line.len() {
            assert!(parse(&line[..cut]).is_err(), "cut at {cut} accepted");
        }
    }

    #[test]
    fn two_interleaved_frames_are_rejected() {
        let a = encode(1, 2, "tmp", &[1.0]);
        let b = encode(2, 3, "gas", &[2.0]);
        let mixed = format!("{}{}", &a[..a.len() - 3], b);
        assert!(parse(mixed.as_bytes()).is_err());
    }

    #[test]
    fn another_version_is_refused() {
        let body = "FNS2,1,2,tmp,1";
        let x = body.bytes().fold(0u8, |a, b| a ^ b);
        let line = format!("${body}*{x:02X}");
        assert!(matches!(parse(line.as_bytes()), Err(FrameError::Version(_))));
    }

    #[test]
    fn counts_are_scaled_by_the_announced_range() {
        let mut s = FrameSession::new();
        let before = s.feed_line(encode(0, 0, "acc", &[1.0, 2.0, 3.0]).as_bytes());
        assert!(matches!(before, Err(NiclaError::RangeUnknown(_))));
        assert_eq!(s.feed_line(encode(1, 1, "rng", &[2.0, 1000.0]).as_bytes()).unwrap(), FrameOut::Range);
        let FrameOut::Sample(Sample::Acceleration { z, .. }) =
            s.feed_line(encode(2, 2, "acc", &[0.0, 0.0, 16384.0]).as_bytes()).unwrap()
        else {
            panic!()
        };
        assert!((z - 9.80665).abs() < 1e-9);
    }

    #[test]
    fn lost_frames_are_counted_from_the_sequence() {
        let mut s = FrameSession::new();
        for seq in [1u32, 2, 5] {
            s.feed_line(encode(seq, seq, "tmp", &[20.0]).as_bytes()).unwrap();
        }
        assert_eq!(s.lost, 2);
    }

    #[test]
    fn a_device_restart_is_not_counted_as_loss() {
        let mut s = FrameSession::new();
        s.feed_line(encode(4_000_000_000, 1, "tmp", &[20.0]).as_bytes()).unwrap();
        s.feed_line(encode(0, 1, "tmp", &[20.0]).as_bytes()).unwrap();
        assert_eq!(s.lost, 0);
    }

    #[test]
    fn a_corrupt_line_does_not_move_the_loss_counter() {
        let mut s = FrameSession::new();
        s.feed_line(encode(1, 1, "tmp", &[20.0]).as_bytes()).unwrap();
        let mut bad = encode(9, 9, "tmp", &[20.0]).into_bytes();
        bad[5] ^= 1;
        assert!(s.feed_line(&bad).is_err());
        s.feed_line(encode(2, 2, "tmp", &[20.0]).as_bytes()).unwrap();
        assert_eq!((s.lost, s.rejected), (0, 1));
    }

    #[test]
    fn arity_and_value_rules() {
        let mut s = FrameSession::new();
        assert!(s.feed_line(encode(0, 0, "tmp", &[1.0, 2.0]).as_bytes()).is_err());
        assert!(s.feed_line(encode(1, 0, "stp", &[-1.0]).as_bytes()).is_err());
        assert!(s.feed_line(encode(2, 0, "iaq", &[1.0, 2.0, 3.0, 9.0]).as_bytes()).is_err());
        assert!(s.feed_line(encode(3, 0, "zzz", &[1.0]).as_bytes()).is_err());
        s.feed_line(encode(4, 0, "rng", &[2.0, 2000.0]).as_bytes()).unwrap();
        assert!(s.feed_line(encode(5, 0, "acc", &[1.5, 0.0, 0.0]).as_bytes()).is_err());
        assert!(s.feed_line(encode(6, 0, "acc", &[40000.0, 0.0, 0.0]).as_bytes()).is_err());
    }

    #[test]
    fn random_lines_never_panic() {
        let mut st = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut s = FrameSession::new();
        let good = encode(1, 2, "iaq", &[50.0, 600.0, 1.2, 3.0]).into_bytes();
        for _ in 0..30_000 {
            let mut l = good.clone();
            for _ in 0..(next() % 4) {
                let i = (next() % l.len() as u64) as usize;
                l[i] = next() as u8;
            }
            if next() % 5 == 0 {
                l.truncate((next() % l.len() as u64) as usize);
            }
            let _ = s.feed_line(&l);
        }
    }
}
