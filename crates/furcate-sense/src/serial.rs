//! Moving bytes between a serial device and the decoders.
//!
//! Two paths. The text and framed-line paths only read, and their reader opens
//! the port read-only. The binary protocol needs to write requests, so its link
//! is generic over `Read + Write` and the caller decides how the port was
//! opened. BLE has no implementation here: [`SensorLink`] is the seam for one,
//! and the characteristic ids a BLE link would use are listed in [`ble`].

use crate::bhy2::{self, DecodeError, ReadKind, Record, SensorConfig};
use crate::nicla::NiclaError;
use std::io::{Read, Write};

/// Where a sensor hub's records come from, whatever carries them.
///
/// Implement this for BLE by subscribing to the data characteristics and
/// queueing the 12-byte and long records they notify; `configure` writes the
/// nine-byte packet from [`SensorConfig::encode_packet`] to the configuration
/// characteristic. Nothing implements it for BLE in this crate.
pub trait SensorLink {
    fn configure(&mut self, cfg: &SensorConfig) -> Result<(), NiclaError>;
    fn poll(&mut self) -> Result<Vec<Record>, NiclaError>;
}

/// Identifiers a BLE link would use, from the vendor's published service layout.
/// Not exercised against hardware.
pub mod ble {
    pub const SENSOR_SERVICE: &str = "34c2e3bb-34aa-11eb-adc1-0242ac120002";
    pub const SENSOR_DATA: &str = "34c2e3bc-34aa-11eb-adc1-0242ac120002";
    pub const SENSOR_CONFIG: &str = "34c2e3bd-34aa-11eb-adc1-0242ac120002";
    pub const SENSOR_LONG_DATA: &str = "34c2e3be-34aa-11eb-adc1-0242ac120002";
}

/// The binary protocol over a serial stream, as the vendor's passthrough host
/// speaks it. Unverified against hardware.
///
/// The stream carries no sync marker, so any short read is treated as loss of
/// framing: the caller gets an error and is expected to drop and reopen.
pub struct Bhy2Link<T: Read + Write> {
    port: T,
    kind_long: ReadKind,
}

impl<T: Read + Write> Bhy2Link<T> {
    pub fn new(port: T, long: ReadKind) -> Self {
        Self { port, kind_long: long }
    }

    fn read_exact_or_timeout(&mut self, buf: &mut [u8]) -> Result<(), NiclaError> {
        let mut got = 0;
        while got < buf.len() {
            let n = self.port.read(&mut buf[got..])?;
            if n == 0 {
                return Err(NiclaError::Decode(DecodeError::Incomplete { needed: buf.len() - got }));
            }
            got += n;
        }
        Ok(())
    }

    fn read_reply(&mut self, kind: ReadKind) -> Result<Vec<Record>, NiclaError> {
        self.port.write_all(&bhy2::encode_read(kind))?;
        let mut count = [0u8; 1];
        self.read_exact_or_timeout(&mut count)?;
        let mut buf = vec![0u8; 1 + count[0] as usize * kind.record_len()];
        buf[0] = count[0];
        self.read_exact_or_timeout(&mut buf[1..])?;
        Ok(bhy2::parse_read_reply(&buf, kind)?.records)
    }
}

impl<T: Read + Write> SensorLink for Bhy2Link<T> {
    fn configure(&mut self, cfg: &SensorConfig) -> Result<(), NiclaError> {
        self.port.write_all(&cfg.encode_request())?;
        let mut ack = [0u8; 1];
        self.read_exact_or_timeout(&mut ack)?;
        Ok(bhy2::parse_ack(ack[0])?)
    }

    fn poll(&mut self) -> Result<Vec<Record>, NiclaError> {
        let mut out = self.read_reply(ReadKind::Short)?;
        out.extend(self.read_reply(self.kind_long)?);
        Ok(out)
    }
}

/// Open a serial device for reading lines, raw and read-only. A path that is
/// not a terminal (a recorded capture) is read as it is.
#[cfg(unix)]
pub fn open_line_source(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new().read(true).open(path)?;
    let fd = f.as_raw_fd();
    // SAFETY: `termios` is plain data; tcgetattr fills it for a valid fd and
    // reports failure for a non-terminal, which is the recorded-file case.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) == 0 {
            libc::cfmakeraw(&mut t);
            libc::cfsetispeed(&mut t, libc::B115200);
            // Return after half a second with whatever arrived, so a silent
            // device is a timeout and not a hang.
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 5;
            if libc::tcsetattr(fd, libc::TCSANOW, &t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A stand-in hub: records what it is sent and answers from a script.
    struct Hub {
        sent: Vec<u8>,
        replies: VecDeque<u8>,
    }

    impl Read for Hub {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.replies.len()).min(3); // dribble
            for b in buf.iter_mut().take(n) {
                *b = self.replies.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl Write for Hub {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn rec12(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![id, payload.len() as u8 + 1];
        v.extend_from_slice(payload);
        v.resize(12, 0);
        v
    }

    #[test]
    fn configure_writes_the_request_and_waits_for_the_ack() {
        let mut l = Bhy2Link::new(Hub { sent: vec![], replies: [bhy2::ACK].into() }, ReadKind::Long);
        l.configure(&SensorConfig::new(128, 1.0, 0).unwrap()).unwrap();
        assert_eq!(l.port.sent, [3, 128, 0, 0, 0x80, 0x3F, 0, 0, 0, 0]);
    }

    #[test]
    fn a_nack_and_a_silent_hub_are_errors() {
        let mut l = Bhy2Link::new(Hub { sent: vec![], replies: [0u8].into() }, ReadKind::Long);
        assert!(l.configure(&SensorConfig::disable(1)).is_err());
        let mut l = Bhy2Link::new(Hub { sent: vec![], replies: VecDeque::new() }, ReadKind::Long);
        assert!(l.configure(&SensorConfig::disable(1)).is_err());
    }

    #[test]
    fn poll_asks_short_then_long_and_collects_records() {
        let mut replies = vec![1u8];
        replies.extend(rec12(130, &[47]));
        replies.push(0); // no long records
        let mut l = Bhy2Link::new(Hub { sent: vec![], replies: replies.into() }, ReadKind::Long);
        let recs = l.poll().unwrap();
        assert_eq!(l.port.sent, [2, 4]);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].sensor_id, 130);
    }

    #[test]
    fn a_reply_cut_short_is_an_error_not_a_partial_record() {
        let mut replies = vec![2u8];
        replies.extend(rec12(130, &[47]));
        replies.truncate(14);
        let mut l = Bhy2Link::new(Hub { sent: vec![], replies: replies.into() }, ReadKind::Long);
        assert!(l.poll().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_plain_file_opens_as_a_line_source() {
        let dir = std::env::temp_dir().join(format!("nicla-open-{}", std::process::id()));
        std::fs::write(&dir, b"temperature: 1.000\n").unwrap();
        let mut f = open_line_source(&dir).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "temperature: 1.000\n");
        std::fs::remove_file(dir).unwrap();
    }
}
