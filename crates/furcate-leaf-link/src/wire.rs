//! The leaf link's wire format.
//!
//! A message is one type byte followed by fields: tag (u8), length (u16, big
//! endian), value. On a serial console or a TCP stream a message travels as
//! `FL1:` + base64 + newline; every other line on the stream is the leaf's
//! log and is passed through as text.

use data_encoding::BASE64;

/// Message types.
pub mod msg {
    pub const HELLO: u8 = 0x01;
    pub const AUTH: u8 = 0x02;
    pub const FINISH: u8 = 0x03;
    pub const REFUSE: u8 = 0x04;
    pub const SEALED: u8 = 0x10;
    pub const INFO_REQ: u8 = 0x20;
    pub const RESULT: u8 = 0x22;
    pub const SENSE_REQ: u8 = 0x72;
    pub const SENSE: u8 = 0x73;
    pub const BYE: u8 = 0x7F;
}

/// Field tags.
pub mod tag {
    pub const DEV_PUB: u8 = 2;
    pub const EPH: u8 = 3;
    pub const NONCE: u8 = 4;
    pub const EVIDENCE: u8 = 5;
    pub const NODE_PUB: u8 = 6;
    pub const GRANT: u8 = 7;
    pub const GRANT_SIG: u8 = 8;
    pub const NODE_SIG: u8 = 9;
    pub const DEV_SIG: u8 = 10;
    pub const REASON: u8 = 11;
    pub const OK: u8 = 12;
    pub const COUNTER: u8 = 13;
    pub const BOX: u8 = 14;
    pub const READING: u8 = 80;
    pub const GENERATION: u8 = 81;
    pub const MODEL_SHA: u8 = 82;
    pub const SIGNER_ID: u8 = 83;
    pub const CHAIN: u8 = 85;
    pub const UNIT: u8 = 86;
}

/// The longest line the decoder keeps. A longer one is dropped whole.
pub const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    /// A field runs past the end of the message.
    Truncated,
    /// A message with no type byte.
    Empty,
    /// A field longer than a length field can say.
    TooLong,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Truncated => write!(f, "a field runs past the end of the message"),
            WireError::Empty => write!(f, "an empty message"),
            WireError::TooLong => write!(f, "a field is longer than 65535 bytes"),
        }
    }
}

impl std::error::Error for WireError {}

/// Builds one message.
pub struct Builder {
    out: Vec<u8>,
    overflow: bool,
}

impl Builder {
    pub fn new(kind: u8) -> Self {
        Self { out: vec![kind], overflow: false }
    }

    pub fn field(mut self, tag: u8, value: &[u8]) -> Self {
        match u16::try_from(value.len()) {
            Ok(n) => {
                self.out.push(tag);
                self.out.extend(n.to_be_bytes());
                self.out.extend(value);
            }
            Err(_) => self.overflow = true,
        }
        self
    }

    pub fn build(self) -> Result<Vec<u8>, WireError> {
        if self.overflow {
            Err(WireError::TooLong)
        } else {
            Ok(self.out)
        }
    }
}

/// The fields of one message, in the order they came.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields(Vec<(u8, Vec<u8>)>);

impl Fields {
    /// Reads fields strictly: a field that does not fit is an error, where a
    /// lenient reader would drop it and carry on with a half-read message.
    pub fn parse(body: &[u8]) -> Result<Fields, WireError> {
        let (mut i, mut out) = (0usize, Vec::new());
        while i < body.len() {
            let head = body.get(i..i + 3).ok_or(WireError::Truncated)?;
            let n = u16::from_be_bytes([head[1], head[2]]) as usize;
            let value = body.get(i + 3..i + 3 + n).ok_or(WireError::Truncated)?;
            out.push((head[0], value.to_vec()));
            i += 3 + n;
        }
        Ok(Fields(out))
    }

    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.0.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice())
    }

    pub fn all(&self, tag: u8) -> impl Iterator<Item = &[u8]> {
        self.0.iter().filter(move |(t, _)| *t == tag).map(|(_, v)| v.as_slice())
    }

    /// A big-endian unsigned field of up to eight bytes.
    pub fn uint(&self, tag: u8) -> Option<u64> {
        let v = self.get(tag)?;
        if v.is_empty() || v.len() > 8 {
            return None;
        }
        Some(v.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
    }
}

/// Splits a message into its type and fields.
pub fn split(message: &[u8]) -> Result<(u8, Fields), WireError> {
    let (kind, body) = message.split_first().ok_or(WireError::Empty)?;
    Ok((*kind, Fields::parse(body)?))
}

/// `FL1:` + base64 + newline.
pub fn encode_line(message: &[u8]) -> Vec<u8> {
    let mut line = b"FL1:".to_vec();
    line.extend(BASE64.encode(message).into_bytes());
    line.push(b'\n');
    line
}

/// One line off the stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A decoded message.
    Frame(Vec<u8>),
    /// Anything else the leaf printed.
    Text(String),
    /// A line that began as a frame and was not one, or was too long.
    Bad,
}

/// Turns a byte stream into lines. Holds the partial line between reads.
#[derive(Default)]
pub struct LineDecoder {
    buf: Vec<u8>,
    skipping: bool,
}

impl LineDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<Line> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\n' {
                if self.skipping {
                    self.skipping = false;
                } else {
                    out.push(Self::line(&self.buf));
                }
                self.buf.clear();
            } else if !self.skipping {
                if self.buf.len() >= MAX_LINE {
                    self.buf.clear();
                    self.skipping = true;
                    out.push(Line::Bad);
                } else {
                    self.buf.push(b);
                }
            }
        }
        out
    }

    fn line(raw: &[u8]) -> Line {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        match raw.strip_prefix(b"FL1:") {
            Some(b64) => match BASE64.decode(b64) {
                Ok(m) if !m.is_empty() => Line::Frame(m),
                _ => Line::Bad,
            },
            None => Line::Text(String::from_utf8_lossy(raw).into_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_round_trips_through_a_line() {
        let m = Builder::new(msg::HELLO).field(tag::NONCE, &[1, 2, 3]).field(tag::DEV_PUB, &[9; 65]).build().unwrap();
        let mut d = LineDecoder::new();
        // Split mid-line: the decoder keeps the partial line.
        let line = encode_line(&m);
        let (a, b) = line.split_at(10);
        assert!(d.push(a).is_empty());
        assert_eq!(d.push(b), vec![Line::Frame(m.clone())]);
        let (kind, f) = split(&m).unwrap();
        assert_eq!(kind, msg::HELLO);
        assert_eq!(f.get(tag::NONCE), Some(&[1u8, 2, 3][..]));
        assert_eq!(f.get(tag::DEV_PUB).map(<[u8]>::len), Some(65));
    }

    #[test]
    fn log_lines_pass_through_as_text_and_bad_frames_are_counted() {
        let mut d = LineDecoder::new();
        let got = d.push(b"I (123) fl-link: up\r\nFL1:!!notbase64\nFL1:\n");
        assert_eq!(got, vec![Line::Text("I (123) fl-link: up".into()), Line::Bad, Line::Bad]);
    }

    #[test]
    fn an_overlong_line_is_dropped_whole_and_the_next_one_still_reads() {
        let mut d = LineDecoder::new();
        let mut junk = vec![b'x'; MAX_LINE + 10];
        junk.push(b'\n');
        let mut got = d.push(&junk);
        got.extend(d.push(b"ok\n"));
        assert_eq!(got, vec![Line::Bad, Line::Text("ok".into())]);
    }

    #[test]
    fn a_truncated_field_is_an_error_not_a_short_read() {
        assert_eq!(Fields::parse(&[1, 0, 5, 1, 2]), Err(WireError::Truncated));
        assert_eq!(Fields::parse(&[1, 0]), Err(WireError::Truncated));
        assert_eq!(split(&[]), Err(WireError::Empty));
        assert!(Builder::new(1).field(1, &vec![0u8; 70_000]).build().is_err());
    }

    #[test]
    fn integers_read_big_endian() {
        let f = Fields::parse(&[13, 0, 4, 0, 0, 1, 2]).unwrap();
        assert_eq!(f.uint(13), Some(258));
        assert_eq!(f.uint(99), None);
    }
}
