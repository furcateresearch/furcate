//! The Warden: a controller on the board that holds the power rail.
//!
//! The host reaches it over a serial line, which depends neither on the
//! cluster network nor on the host's OS staying healthy beyond one write, and
//! once it has an order it acts on its own. That makes it an out-of-band path
//! in the sense the kill switch requires before cutting power.
//!
//! ## Frames
//!
//! One line each way, ASCII, newline-terminated:
//!
//! ```text
//! host   -> warden   furcate-warden/1 power_off <order_hash>
//! warden -> host     ok <order_hash>
//! warden -> host     err <order_hash> <reason>
//! ```
//!
//! The order hash is echoed so that a reply to an earlier frame cannot be read
//! as the answer to this one. The Warden acts on the host's frame: the node
//! verified the approval before writing it, and the line is wired to that one
//! host and nothing else.
//!
//! Line settings (rate, raw mode) belong to the device, set by the rule that
//! names it; [`SerialLine`] writes and reads bytes.

use crate::actuate::{OutOfBand, Report};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub const VERSION: &str = "furcate-warden/1";

/// The longest a reply line may be. A device that sends more is not a Warden.
const MAX_REPLY: usize = 512;

fn default_timeout_ms() -> u64 {
    5_000
}

/// An out-of-band control path, as a node's configuration declares it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutOfBandPath {
    /// The board's Warden controller, on a serial device.
    Warden {
        device: PathBuf,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
}

impl OutOfBandPath {
    /// The declared path, or `None` when the file does not exist. A file that
    /// exists and does not parse is an error, not an absent path.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// The path, ready to use.
    pub fn open(&self) -> Box<dyn OutOfBand> {
        match self {
            OutOfBandPath::Warden { device, timeout_ms } => Box::new(Warden::new(
                SerialLine {
                    device: device.clone(),
                    timeout: Duration::from_millis(*timeout_ms),
                },
                json!({ "kind": "warden", "device": device }),
            )),
        }
    }
}

/// The frame that orders the Warden to cut power.
pub fn power_off_frame(order_hash: &str) -> String {
    format!("{VERSION} power_off {order_hash}\n")
}

/// Read the Warden's reply to the frame for `order_hash`.
pub fn parse_reply(line: &str, order_hash: &str) -> Result<(), String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.splitn(3, ' ');
    let verdict = parts.next().unwrap_or_default();
    let echoed = parts.next().unwrap_or_default();
    if echoed != order_hash {
        return Err(format!(
            "the Warden answered for `{echoed}`, not for this order; treating it as no answer"
        ));
    }
    match verdict {
        "ok" => Ok(()),
        "err" => Err(format!(
            "the Warden refused: {}",
            parts.next().unwrap_or("no reason given")
        )),
        other => Err(format!("the Warden sent `{other}`, which is not a reply")),
    }
}

/// One exchange over the line: a frame out, one line back.
pub trait Line: Send {
    fn exchange(&mut self, frame: &str) -> std::io::Result<String>;
}

/// A serial device.
pub struct SerialLine {
    pub device: PathBuf,
    pub timeout: Duration,
}

impl Line for SerialLine {
    fn exchange(&mut self, frame: &str) -> std::io::Result<String> {
        let mut port = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device)?;
        let reader = port.try_clone()?;
        port.write_all(frame.as_bytes())?;
        port.flush()?;
        // A read on a quiet line blocks, so it runs apart from the caller,
        // which waits only as long as the timeout allows.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let got = BufReader::new(reader.take(MAX_REPLY as u64))
                .read_line(&mut line)
                .map(|_| line);
            let _ = tx.send(got);
        });
        match rx.recv_timeout(self.timeout) {
            Ok(got) => got,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "no reply on {} within {} ms",
                    self.device.display(),
                    self.timeout.as_millis()
                ),
            )),
        }
    }
}

/// The Warden as an out-of-band path.
pub struct Warden<L: Line> {
    line: Mutex<L>,
    describe: Value,
}

impl<L: Line> Warden<L> {
    pub fn new(line: L, describe: Value) -> Self {
        Self {
            line: Mutex::new(line),
            describe,
        }
    }
}

impl<L: Line> OutOfBand for Warden<L> {
    fn describe(&self) -> Value {
        self.describe.clone()
    }

    fn power_off(&self, order_hash: &str) -> Report {
        let reply = match self
            .line
            .lock()
            .expect("warden line lock")
            .exchange(&power_off_frame(order_hash))
        {
            Ok(r) => r,
            Err(e) => {
                return Report::failed(format!(
                    "the Warden could not be reached: {e}; whether it received the frame is \
                     not known"
                ))
            }
        };
        match parse_reply(&reply, order_hash) {
            Ok(()) => Report::Done {
                what: json!({ "warden": "acknowledged", "order_hash": order_hash }),
            },
            Err(why) => Report::failed(why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Warden on the other end of a fake line.
    struct FakeLine {
        sent: std::sync::Arc<Mutex<Vec<String>>>,
        reply: Result<String, std::io::ErrorKind>,
    }

    impl Line for FakeLine {
        fn exchange(&mut self, frame: &str) -> std::io::Result<String> {
            self.sent.lock().unwrap().push(frame.into());
            self.reply.clone().map_err(std::io::Error::from)
        }
    }

    fn warden(
        reply: Result<&str, std::io::ErrorKind>,
    ) -> (Warden<FakeLine>, std::sync::Arc<Mutex<Vec<String>>>) {
        let sent = std::sync::Arc::new(Mutex::new(Vec::new()));
        let line = FakeLine {
            sent: sent.clone(),
            reply: reply.map(str::to_string),
        };
        (Warden::new(line, json!({ "kind": "warden" })), sent)
    }

    #[test]
    fn an_acknowledged_frame_is_done() {
        let (w, sent) = warden(Ok("ok abc\n"));
        assert!(w.power_off("abc").is_done());
        assert_eq!(*sent.lock().unwrap(), ["furcate-warden/1 power_off abc\n"]);
    }

    #[test]
    fn a_refusal_a_stale_reply_and_silence_are_failures() {
        for reply in [
            Ok("err abc rail interlock"),
            Ok("ok older"),
            Ok("garbage"),
            Err(std::io::ErrorKind::TimedOut),
        ] {
            let (w, _) = warden(reply);
            assert!(!w.power_off("abc").is_done(), "{reply:?}");
        }
    }

    #[test]
    fn the_path_is_declared_in_a_file_or_absent() {
        let dir = std::env::temp_dir().join(format!("furcate-oob-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("out-of-band.json");
        assert_eq!(OutOfBandPath::load(&f).unwrap(), None);
        std::fs::write(&f, br#"{"kind":"warden","device":"/dev/ttyWARDEN0"}"#).unwrap();
        assert_eq!(
            OutOfBandPath::load(&f).unwrap(),
            Some(OutOfBandPath::Warden {
                device: "/dev/ttyWARDEN0".into(),
                timeout_ms: 5_000
            })
        );
        std::fs::write(&f, br#"{"kind":"pdu"}"#).unwrap();
        assert!(
            OutOfBandPath::load(&f).is_err(),
            "an unknown path kind is not silently ignored"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
