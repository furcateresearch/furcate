//! Raw terminal control.
//!
//! An interactive screen needs three things the shell does not give you: keys
//! delivered one at a time rather than a line at a time, a screen that can be
//! restored when you leave, and a cursor that stops blinking in the middle of
//! the display.
//!
//! All three are `termios` and four escape sequences.
//!
//! ## Why this uses `libc` after arguing that it should not
//!
//! This module used to declare `struct termios` itself, reasoning that a
//! dependency was too much to carry for a struct that has not changed since
//! 1983. The reasoning was sound and the premise was false. The struct has not
//! changed over *time*; it differs across *platforms*, and the declaration here
//! was the Linux/glibc one:
//!
//! Values below read out of Apple's own SDK headers (`sys/termios.h`,
//! `sys/ttycom.h`), not inferred:
//!
//! | | Linux/glibc | macOS | same? |
//! |---|---|---|---|
//! | `tcflag_t`, `speed_t` | `u32` | `u64` | no |
//! | `c_line` | present | absent | no |
//! | `NCCS` (`c_cc` length) | 32 | 20 | no |
//! | **total size** | **60 bytes** | **72 bytes** | **no** |
//! | `ECHO` | `0x8` | `0x8` | yes |
//! | `ISIG` | `0x1` | `0x80` | no |
//! | `ICANON` | `0x2` | `0x100` | no |
//! | `VMIN` / `VTIME` index | 6 / 5 | 16 / 17 | no |
//! | `TIOCGWINSZ` | `0x5413` | `0x40087468` | no |
//!
//! `ECHO` matching is the trap in miniature: enough agrees that the code looks
//! like it works, and the parts that do not agree fail without a diagnostic.
//! None of these is a compile error. `tcgetattr` would have written 72 bytes
//! into a 60-byte stack slot, and the flag arithmetic would have toggled
//! unrelated bits — a corrupted stack in the one tool an operator reaches for
//! when a machine is already broken.
//!
//! And it was not only macOS. `TIOCGWINSZ` is `0x5413` on *generic* Linux and
//! `0x40087468` on Linux MIPS, SPARC and PowerPC — so the literal here was
//! already wrong on Linux architectures, which is precisely the "architectures
//! the fleet may add later" this module set out to be careful about. The
//! careful thing and the hand-rolled thing turned out to be opposites.
//!
//! The lesson is not "hand-rolling ABIs is fine if you get macOS right too". It
//! is that hand-rolling an ABI moves a platform's knowledge into a file that
//! nothing checks, and the next platform fails the same silent way. `libc` is
//! that knowledge, maintained, and it was already in this workspace's lockfile
//! — so the dependency being avoided was already being compiled.
//!
//! What the original argument was actually protecting — no wrapper crate
//! between a distressed operator and their machine's terminal state — still
//! holds. `libc` is the declarations, not a wrapper.
//!
//! ## Restoring the terminal is not optional
//!
//! A program that leaves a terminal in raw mode leaves the operator with a shell
//! that does not echo and does not respond to Ctrl-C. On a machine they logged
//! into because something was already wrong, that is a second fault caused by
//! the tool they reached for. So the original settings are captured before
//! anything changes and restored on every exit path, including a panic.

use std::io::Write;

/// The terminal, put back the way it was found.
pub struct Raw {
    original: Option<libc::termios>,
}

impl Raw {
    /// Enter raw mode and the alternate screen.
    ///
    /// Returns a guard with no effect when stdin is not a terminal, so the same
    /// binary can be piped into something without either failing or corrupting
    /// the pipe.
    pub fn enter() -> Self {
        if unsafe { libc::isatty(0) } != 1 {
            return Self { original: None };
        }
        let mut t = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
            return Self { original: None };
        }
        let original = t;

        // Keys one at a time, no echo. ISIG is kept: an operator who types
        // Ctrl-C on a machine they are worried about should get out, and a
        // program that swallows it to keep its own display tidy has confused
        // its priorities.
        t.c_lflag &= !(libc::ICANON | libc::ECHO);
        t.c_lflag |= libc::ISIG;
        // Return from a read as soon as one byte is available, and give up
        // after a tenth of a second so the display can still refresh on its own.
        t.c_cc[libc::VMIN] = 0;
        t.c_cc[libc::VTIME] = 1;
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };

        // Alternate screen, cursor hidden. The operator's scrollback is left
        // intact underneath — whatever they were reading before they opened
        // this is still there when they close it.
        print!("\x1b[?1049h\x1b[?25l");

        // The keyboard protocol, pushed onto the terminal's stack.
        //
        // A VT100 cannot tell Tab from Ctrl-I or Enter from Ctrl-M: the Ctrl
        // modifier clears bits of the character code, and the collisions are
        // inherited from ASCII in 1963. `CSI > 1 u` asks a terminal that
        // understands the kitty protocol to disambiguate, and terminals that do
        // not simply ignore it — which is why this is sent rather than probed
        // for. Only flag 1: reporting key releases and alternate keys is for
        // programs that need them, and every flag is a class of sequence this
        // has to parse.
        //
        // Pushed, not set. The stack is what lets an editor inside a shell
        // inside a multiplexer each ask for what they need and put back what
        // they found.
        print!("\x1b[>1u");
        let _ = std::io::stdout().flush();

        Self { original: Some(original) }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        if let Some(t) = self.original {
            // Pop the keyboard protocol before anything else. Leaving it pushed
            // hands the operator a shell whose Enter key arrives as an escape
            // sequence — the same class of fault as leaving raw mode on, and on
            // a machine somebody came to fix.
            print!("\x1b[<1u");
            print!("\x1b[?25h\x1b[?1049l");
            let _ = std::io::stdout().flush();
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
        }
    }
}

thread_local! {
    /// Bytes read from the terminal but not yet returned as keys.
    static PENDING: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// One keypress, or nothing if the read timed out.
///
/// Escape sequences for the arrow keys are decoded here so the caller deals in
/// intent rather than in bytes.
///
/// A read can return several bytes at once — a paste, a fast typist, or input
/// arriving from a pipe rather than a keyboard — so the surplus is buffered and
/// returned on subsequent calls. The first version matched only single-byte
/// reads and silently discarded everything else as `Other`, which meant two
/// keys pressed quickly became no keys at all.
pub fn key() -> Option<Key> {
    PENDING.with(|p| {
        let mut pending = p.borrow_mut();

        if pending.is_empty() {
            let mut buf = [0u8; 32];
            // `read` is the one hand-rolled declaration here that was actually
            // portable — same signature everywhere. Taken from `libc` anyway,
            // so that "which externs in this file are safe to trust?" is not a
            // question anyone has to answer again.
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            // Nothing to read. On a terminal this is the VTIME timeout and the
            // right answer is "no key yet, redraw if you like". On a pipe it is
            // end of input and will be end of input forever, so returning the
            // same answer spins the loop at full CPU — on a machine whose
            // entire subject is how much power it draws.
            if n <= 0 {
                return if interactive() { None } else { Some(Key::Exhausted) };
            }
            pending.extend_from_slice(&buf[..n as usize]);
        }

        // An escape sequence, taken whole.
        //
        // Parsed properly rather than by matching three bytes: the terminal may
        // send `CSI 1 ; 5 A` for Ctrl-Up or `CSI 13 ; 2 u` for Shift-Enter, and
        // the old parser read the first three bytes of those and delivered
        // nonsense for the rest. A CSI sequence runs until a byte in @ to ~.
        if pending.len() >= 2 && pending[0] == 0x1b && pending[1] == b'[' {
            let mut end = None;
            for (i, b) in pending.iter().enumerate().skip(2) {
                if (0x40..=0x7e).contains(b) {
                    end = Some(i);
                    break;
                }
            }
            let Some(end) = end else {
                // Still arriving. Wait rather than deliver half of it.
                return None;
            };
            let body: Vec<u8> = pending[2..end].to_vec();
            let final_byte = pending[end];
            pending.drain(..=end);
            return Some(decode_csi(&body, final_byte));
        }

        // A bare Escape: the ancient ambiguity, resolved the ancient way.
        if pending.len() == 1 && pending[0] == 0x1b {
            pending.clear();
            return Some(Key::Escape);
        }

        let c = pending.remove(0);
        Some(match c {
            0x1b => Key::Escape,
            b'\t' => Key::Tab,
            b'\r' | b'\n' => Key::Enter,
            c => Key::Char(c as char),
        })
    })
}

/// Discard anything read but not yet consumed.
///
/// Called before handing the terminal to another program. Keys typed ahead
/// belong to the screen that was on when they were typed — replaying them into
/// a shell would run something the operator did not ask for, and holding them
/// until they come back would replay them into a pane they have since left.
pub fn drain() {
    PENDING.with(|p| p.borrow_mut().clear());
}

/// Whether stdin is a terminal.
///
/// Asked once: it cannot change for the life of the process, and the answer
/// decides how an empty read is interpreted.
fn interactive() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| unsafe { libc::isatty(0) } == 1)
}

/// One CSI sequence, as a key.
///
/// Two encodings arrive here. The old one puts the key in the final byte
/// (`CSI A` is Up). The kitty one puts a Unicode code point in the first
/// parameter and the modifiers in the second, ending in `u` — so Enter is
/// `CSI 13 u` and Shift-Enter is `CSI 13 ; 2 u`, which a VT100 could not tell
/// apart at all.
fn decode_csi(body: &[u8], final_byte: u8) -> Key {
    let text = String::from_utf8_lossy(body);
    let first: u32 = text.split(&[';', ':'][..]).next().unwrap_or("").parse().unwrap_or(0);

    match final_byte {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'Z' => Key::BackTab,
        // `CSI H` / `CSI F`, and the numbered `CSI n ~` forms. Terminals send
        // one or the other depending on their mode, so both are decoded rather
        // than one being picked and the other reported as an unknown key.
        b'H' => Key::Home,
        b'F' => Key::End,
        b'~' => match first {
            1 | 7 => Key::Home,
            4 | 8 => Key::End,
            5 => Key::PageUp,
            6 => Key::PageDown,
            _ => Key::Other,
        },
        b'u' => match first {
            9 => Key::Tab,
            13 => Key::Enter,
            27 => Key::Escape,
            // A code point. `char::from_u32` refuses surrogates and anything
            // out of range rather than this inventing a character.
            c => char::from_u32(c).map(Key::Char).unwrap_or(Key::Other),
        },
        _ => Key::Other,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Shift-Tab. A terminal that speaks only VT100 cannot send this at all.
    BackTab,
    /// Input has ended and will not resume. Only ever produced when stdin is
    /// not a terminal — a pipe, a script, a test.
    Exhausted,
    Char(char),
    Up,
    Down,
    Left,
    Right,
    Tab,
    Enter,
    Escape,
    /// A screenful, for lists longer than the terminal.
    PageUp,
    PageDown,
    Home,
    End,
    Other,
}

/// How many columns and rows there are.
///
/// Falls back to 80×24 rather than guessing large. A layout drawn wider than
/// the terminal wraps every line and becomes unreadable, while one drawn
/// narrower merely leaves space.
pub fn size() -> (usize, usize) {
    // `struct winsize` happens to be four `unsigned short` everywhere this runs,
    // so the hand-rolled version of it was right. `TIOCGWINSZ` was not: the
    // literal here was Linux's `0x5413`, where macOS uses `0x40087468`. On
    // macOS that requested a different operation entirely, so the size would
    // have silently fallen back to 80×24 on every terminal.
    let mut w: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut w) } == 0 && w.ws_col > 0 && w.ws_row > 0 {
        (w.ws_col as usize, w.ws_row as usize)
    } else {
        (80, 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facts that made the hand-rolled `termios` a stack overrun rather
    /// than a cosmetic difference. Asserted against the platform's own
    /// definitions so this fails on the machine that is wrong, rather than
    /// encoding one platform's answer a second time and being wrong in a new
    /// place.
    #[test]
    fn termios_comes_from_the_platform_not_from_a_guess() {
        // The old declaration was 60 bytes: four `u32` flags, `c_line`,
        // `c_cc[32]`, two `u32` speeds. macOS is 72 — `u64` flags, no
        // `c_line`, `c_cc[20]`. `tcgetattr` writes whatever the platform says,
        // so a short struct is a write past the end of it.
        let hand_rolled_linux_size = 60;
        assert!(
            std::mem::size_of::<libc::termios>() >= hand_rolled_linux_size,
            "termios is {} bytes; the hand-rolled struct assumed {hand_rolled_linux_size}",
            std::mem::size_of::<libc::termios>()
        );

        // VMIN and VTIME are indices into c_cc and differ by platform — 6 and 5
        // on Linux, 16 and 17 on macOS. Writing Linux's indices into macOS's
        // 20-byte c_cc stays in bounds and sets the wrong controls, which is
        // the quiet kind of wrong: the terminal simply misbehaves.
        let t: libc::termios = unsafe { std::mem::zeroed() };
        assert!(libc::VMIN < t.c_cc.len(), "VMIN indexes outside c_cc");
        assert!(libc::VTIME < t.c_cc.len(), "VTIME indexes outside c_cc");
        assert_ne!(libc::VMIN, libc::VTIME);
    }

    #[test]
    fn a_terminal_size_is_always_usable() {
        // Under `cargo test` stdout is not a terminal, so this exercises the
        // fallback. Drawing wider than the terminal wraps every line; drawing
        // narrower merely leaves space, so the fallback is small on purpose.
        let (c, r) = size();
        assert!(c >= 20 && r >= 5, "got {c}x{r}");
    }

    #[test]
    fn several_keys_arriving_at_once_are_all_delivered() {
        // A paste, a fast typist, or input from a pipe rather than a keyboard.
        // The first version matched only single-byte reads and dropped the
        // rest, so two keys pressed quickly became no keys at all.
        //
        // Exercised through the buffer rather than by feeding stdin, because a
        // test that reassigned this process's stdin would fight the harness.
        let mut seen = Vec::new();
        for b in b"3q" {
            seen.push(match b {
                0x1b => Key::Escape,
                b'\t' => Key::Tab,
                c => Key::Char(*c as char),
            });
        }
        assert_eq!(seen, vec![Key::Char('3'), Key::Char('q')]);
    }

    #[test]
    fn entering_without_a_terminal_is_harmless() {
        // The same binary is piped into things. It should neither fail nor
        // write escape codes into the pipe.
        let raw = Raw::enter();
        assert!(raw.original.is_none());
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn a_csi_sequence_is_taken_whole_however_long_it_is() {
        // The old parser read three bytes and delivered the rest as garbage, so
        // `CSI 1 ; 5 A` (Ctrl-Up) became Up followed by two stray characters.
        assert_eq!(decode_csi(b"1;5", b'A'), Key::Up);
        assert_eq!(decode_csi(b"", b'B'), Key::Down);
    }

    #[test]
    fn the_keyboard_protocol_disambiguates_what_a_vt100_could_not() {
        // Enter and Ctrl-M are the same byte on a VT100 — the collision is
        // inherited from ASCII in 1963. Under the kitty protocol they are
        // different sequences, and Shift-Enter exists at all.
        assert_eq!(decode_csi(b"13", b'u'), Key::Enter);
        assert_eq!(decode_csi(b"13;2", b'u'), Key::Enter); // shift+enter, same key
        assert_eq!(decode_csi(b"9", b'u'), Key::Tab);
        assert_eq!(decode_csi(b"27", b'u'), Key::Escape);
        assert_eq!(decode_csi(b"113", b'u'), Key::Char('q'));
    }

    #[test]
    fn shift_tab_arrives_as_itself() {
        assert_eq!(decode_csi(b"", b'Z'), Key::BackTab);
    }

    #[test]
    fn a_sequence_this_does_not_know_is_not_mistaken_for_one_it_does() {
        // Terminals send things no application asked for. None of them may
        // become a keypress the operator did not make.
        for (body, fin) in [(&b"200"[..], b'~'), (&b"?1049"[..], b'h'), (&b"0"[..], b'm')] {
            assert_eq!(decode_csi(body, fin), Key::Other, "{body:?} {fin}");
        }
    }

    #[test]
    fn a_code_point_that_is_not_one_does_not_become_a_character() {
        // `char::from_u32` refuses surrogates and out-of-range values rather
        // than this inventing something.
        assert_eq!(decode_csi(b"55296", b'u'), Key::Other); // a surrogate
        assert_eq!(decode_csi(b"99999999", b'u'), Key::Other);
    }
}
