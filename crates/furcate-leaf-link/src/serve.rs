//! Running a [`Bridge`] over a byte stream.
//!
//! Three links carry the same lines: a serial device, a TCP connection the
//! leaf dials in on (`listen://HOST:PORT`, the leaf connects out and the host
//! never connects to it), and a TCP connection to a byte relay
//! (`tcp://HOST:PORT`).

use crate::bridge::{Action, Bridge};
use crate::wire::{encode_line, Line, LineDecoder};
use furcate_sense::cascade::ingest::Frame;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A way to the leaf.
pub trait Link {
    /// Reads what is there. `Ok(0)` means nothing arrived within the link's
    /// short wait; a link that is gone is an error.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Whether the leaf redialled since the last call: its old session is over.
    fn redialled(&mut self) -> bool {
        false
    }
}

pub struct TcpClient(TcpStream);

impl TcpClient {
    pub fn connect(addr: &str) -> io::Result<Self> {
        let s = TcpStream::connect(addr)?;
        s.set_read_timeout(Some(Duration::from_millis(200)))?;
        s.set_nodelay(true)?;
        Ok(Self(s))
    }
}

fn read_stream(s: &mut TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    match s.read(buf) {
        Ok(0) => Err(io::Error::new(io::ErrorKind::ConnectionReset, "the link closed")),
        Ok(n) => Ok(n),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(0),
        Err(e) => Err(e),
    }
}

impl Link for TcpClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_stream(&mut self.0, buf)
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(bytes)
    }
}

/// The host end of the leaf's Wi-Fi link: the leaf dials this address. A
/// redial replaces the previous connection.
pub struct TcpListen {
    listener: TcpListener,
    current: Option<TcpStream>,
    redial: bool,
}

impl TcpListen {
    pub fn bind(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, current: None, redial: false })
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    fn accept(&mut self) -> io::Result<()> {
        match self.listener.accept() {
            Ok((s, _)) => {
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(Duration::from_millis(100)))?;
                self.current = Some(s);
                self.redial = true;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Link for TcpListen {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.accept()?;
        let Some(s) = self.current.as_mut() else {
            std::thread::sleep(Duration::from_millis(50));
            return Ok(0);
        };
        match read_stream(s, buf) {
            Err(_) => {
                // The leaf hung up. Wait for it to dial again.
                self.current = None;
                self.redial = true;
                Ok(0)
            }
            ok => ok,
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self.current.as_mut() {
            Some(s) => s.write_all(bytes),
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "the leaf is not connected")),
        }
    }

    fn redialled(&mut self) -> bool {
        std::mem::take(&mut self.redial)
    }
}

/// A serial device, set to raw 115200 8N1 with a short read timeout.
pub struct Tty(std::fs::File);

impl Tty {
    pub fn open(path: &str) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        // SAFETY: `t` is fully initialised by tcgetattr before use, and the fd
        // is open for the length of these calls.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(f.as_raw_fd(), &mut t) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::cfmakeraw(&mut t);
            libc::cfsetspeed(&mut t, libc::B115200);
            t.c_cc[libc::VMIN] = 0;
            t.c_cc[libc::VTIME] = 2;
            if libc::tcsetattr(f.as_raw_fd(), libc::TCSANOW, &t) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(f))
    }
}

impl Link for Tty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(bytes)
    }
}

pub fn open_link(spec: &str) -> io::Result<Box<dyn Link>> {
    if let Some(a) = spec.strip_prefix("listen://") {
        Ok(Box::new(TcpListen::bind(a)?))
    } else if let Some(a) = spec.strip_prefix("tcp://") {
        Ok(Box::new(TcpClient::connect(a)?))
    } else {
        Ok(Box::new(Tty::open(spec)?))
    }
}

/// What a run counted.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Tally {
    pub frames: u64,
    pub refused: u64,
    pub bad_lines: u64,
    pub sessions: u64,
}

/// Drives `bridge` over `link` until `stop` says to or the link fails. `sink`
/// receives each frame for the small processing node; `log` receives the
/// leaf's own log lines and what the bridge refused.
pub fn run(
    bridge: &mut Bridge,
    link: &mut dyn Link,
    sink: &mut dyn FnMut(&Frame) -> io::Result<()>,
    log: &mut dyn FnMut(&str),
    stop: &mut dyn FnMut(&Tally) -> bool,
) -> io::Result<Tally> {
    let (mut dec, mut tally, mut buf) = (LineDecoder::new(), Tally::default(), [0u8; 2048]);
    let result = loop {
        if stop(&tally) {
            break Ok(());
        }
        let n = match link.read(&mut buf) {
            Ok(n) => n,
            Err(e) => break Err(e),
        };
        // Checked after the read: a leaf that dials in is accepted inside it,
        // and what it just sent belongs to the new connection.
        if link.redialled() {
            bridge.close();
            dec = LineDecoder::new();
        }
        let mut actions = Vec::new();
        for line in dec.push(&buf[..n]) {
            match line {
                Line::Frame(m) => actions.extend(bridge.handle(&m, now_ms())),
                Line::Text(t) => log(&format!("leaf: {t}")),
                Line::Bad => tally.bad_lines += 1,
            }
        }
        actions.extend(bridge.poll(now_ms()));
        for a in actions {
            match a {
                Action::Send(m) => {
                    if let Err(e) = link.write_all(&encode_line(&m)) {
                        log(&format!("write: {e}"));
                    }
                }
                Action::Frame(f) => {
                    if let Err(e) = sink(&f) {
                        bridge.close();
                        return Err(e);
                    }
                    tally.frames += 1;
                }
                Action::Refused(r) => {
                    tally.refused += 1;
                    log(&format!("refused: {r}"));
                }
                Action::Up { leaf, class } => {
                    tally.sessions += 1;
                    log(&format!("session up with {}: {class}", &leaf[..32.min(leaf.len())]));
                }
                Action::Down(r) => log(&format!("session down: {r}")),
            }
        }
    };
    bridge.close();
    result.map(|()| tally)
}
