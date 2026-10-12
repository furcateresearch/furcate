//! Furcate: how the system talks.
//!
//! A design language for a terminal, which is the only interface this system
//! has. It is not decoration — an operator reads these screens at three in the
//! morning on a machine they are worried about, and the job of the styling is to
//! make the important thing findable before they have finished reading.
//!
//! ## The reference is instrumentation, not a hacker film
//!
//! Amber, not green. Green phosphor is the cliché — every terminal in every film
//! since 1983 — and it carries the wrong association: intrusion, other people's
//! machines. Amber was what you got on the equipment that ran things, DEC's
//! VT220 among them, and it reads as a control room rather than a break-in.
//! This system's entire subject is a machine that belongs to somebody, so the
//! palette should say so.
//!
//! The greens here are the honest P31 short-persistence phosphor at `#00AA00`
//! rather than the saturated P39 of the IBM 5151. P39 is the one people
//! remember and it is unreadable for anything but a single line of text.
//!
//! ## One colour, in three weights
//!
//! Amber, and nothing beside it but red. An earlier version used phosphor green
//! for measured readings and for the network, on the argument that the two
//! systems should be distinguishable by colour. On a real screen the green and
//! the amber simply clashed — two accents on a dark ground read as two designs
//! sharing a window, and the reference this is built from is monochrome for
//! exactly that reason.
//!
//! So the separation is carried by weight instead: bright amber for a figure
//! that was measured, plain amber for the system's own voice, grey for context.
//! Red stays, alone, because a fault has to be the one thing on the screen that
//! is not amber.
//!
//! The network once had a shade of its own here. It no longer does: with the
//! palette monochrome, "this came from outside the machine" is carried by the
//! pane an operator is looking at rather than by a hue, and a colour with no
//! job is a colour that misleads the next person who reaches for it.
//!
//! ## One colour means one thing
//!
//! Amber is the system's own voice — structure, labels, the frame. Green means
//! *measured*: a number that came from an instrument. Red means a fault that a
//! human has to answer. Dim is context. Nothing else is coloured, because the
//! moment a fourth colour means "this is quite interesting" the other three stop
//! meaning anything.
//!
//! That maps onto a distinction this system already makes everywhere: measured,
//! modelled, declared. A figure in green was read off hardware. A figure in the
//! plain foreground was computed. An operator can tell which without being told.
//!
//! ## Voice
//!
//! Terse, technical, and never cheerful. No exclamation marks, no "successfully",
//! no reassurance. State what is, in as few words as carry it, and let a fault
//! look like a fault. The system says `RUNG SHED` and not `Power state has been
//! adjusted`.

/// How much colour the terminal on the other end can show.
///
/// Built in layers, which is the discipline: monochrome first — is it usable? —
/// then sixteen colours, then 256. Each tier has to work on its own, because
/// this is reached over SSH from whatever the operator happened to be sitting
/// at, including a serial console on a machine that will not boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// No escape sequences at all. Shape and layout carry everything.
    None,
    /// The sixteen colours every terminal has had since the 1970s.
    Ansi16,
    /// The 256-colour cube, where the palette is actually the palette.
    Ansi256,
}

/// What this terminal can do, asked once.
pub fn depth() -> Depth {
    static D: std::sync::OnceLock<Depth> = std::sync::OnceLock::new();
    *D.get_or_init(|| {
        if std::env::var_os("NO_COLOR").is_some() {
            return Depth::None;
        }
        let term = std::env::var("TERM").unwrap_or_default();
        if term == "dumb" || term.is_empty() {
            return Depth::None;
        }
        // Not a terminal: something is capturing this, and a log file full of
        // escape codes is a log file nobody greps.
        if !unsafe { libc_isatty() } {
            return Depth::None;
        }
        // A serial console or a very old terminal type says so in its name.
        // Claiming 256 colours there produces literal escape codes on screen,
        // on the one display an operator has for a machine that will not boot.
        if term.contains("256") || term.contains("truecolor") || std::env::var_os("COLORTERM").is_some() {
            Depth::Ansi256
        } else {
            Depth::Ansi16
        }
    })
}

/// `isatty(1)` without a dependency.
///
/// One syscall, and pulling in a crate to make it would be the sort of thing
/// this codebase spends paragraphs explaining it did not do.
unsafe fn libc_isatty() -> bool {
    unsafe extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    unsafe { isatty(1) == 1 }
}

/// Paint with the 256-colour sequence, or its nearest sixteen-colour
/// equivalent, or nothing.
///
/// Both codes are given at the call site rather than derived, because the
/// nearest ANSI colour to a palette index is a judgement about what the colour
/// is *for* — 214 is amber and its sixteen-colour stand-in is bold yellow, which
/// no arithmetic would have chosen.
fn paint2(rich: &str, plain: &str, s: &str) -> String {
    match depth() {
        Depth::None => s.to_string(),
        Depth::Ansi16 => format!("\x1b[{plain}m{s}\x1b[0m"),
        Depth::Ansi256 => format!("\x1b[{rich}m{s}\x1b[0m"),
    }
}

fn paint(code: &str, s: &str) -> String {
    paint2(code, code, s)
}

// --- the palette --------------------------------------------------------
//
// 256-colour indices rather than truecolour: every terminal worth supporting
// has had 256 colours since the 1990s, and truecolour is still not universal
// over SSH to a machine somebody is fixing.

/// This machine's own voice. DEC VT220 amber, as near as the palette reaches.
pub fn amber(s: &str) -> String {
    paint2("38;5;214", "33", s)
}

/// Amber at full weight, for the one thing on a screen that matters most.
pub fn amber_bright(s: &str) -> String {
    paint2("1;38;5;214", "1;33", s)
}

/// Measured. A number that came off an instrument rather than out of a model.
///
/// The same amber, bold — not a second colour index.
///
/// Measured in OKLCH, the base amber is hue 75.9. 220 is 95.3 and 215 is 63.9:
/// both are a *different hue*, which is why each in turn looked like a second
/// colour on the screen rather than a brighter version of the first. The
/// 256-colour cube has no lighter amber at this hue to reach for, so weight
/// carries it, which is hue-exact by construction and is what the design
/// language says hierarchy is made of anyway.
///
/// On the console this is bold, which resolves to palette slot 11 — remapped to
/// a light amber for the same reason. Leaving that slot at the terminal's stock
/// bright yellow is what made the screen look like it had two colours on it.
pub fn measured(s: &str) -> String {
    paint2("1;38;5;214", "1;33", s)
}

/// A fault a human has to answer.
pub fn fault(s: &str) -> String {
    paint2("1;38;5;160", "1;31", s)
}

/// Something moving in the wrong direction but not yet a fault.
///
/// A deeper amber, not magenta — the sixteen-colour fallback used to reach for
/// a colour with no place in this palette at all.
pub fn warn(s: &str) -> String {
    paint2("38;5;172", "33", s)
}

/// Context: units, labels, the things that are always there.
pub fn dim(s: &str) -> String {
    paint("2", s)
}



// --- structure ----------------------------------------------------------

/// Heavy rule, for the top and bottom of a screen.
pub const RULE_HEAVY: char = '━';
/// Light rule, for dividing sections within one.
pub const RULE_LIGHT: char = '─';

/// A section heading.
///
/// Rendered as a labelled rule rather than a box, because a box costs two
/// columns on every line inside it and this runs on an 80-column terminal over
/// a link somebody is troubleshooting.
pub fn heading(title: &str) -> String {
    amber_bright(title)
}

/// A heading for a group inside a pane.
///
/// A pane now stacks several things — what this machine publishes sits under
/// the network it is on, whether it is behind sits under the checks that run on
/// their own — and a bare line of amber does not separate them enough to scan.
/// A left bar gives the group an edge to follow down the screen.
///
/// The bar is amber and the label bright, which is the same pairing the section
/// rules already use. Nothing new enters the palette to say "this is a heading";
/// the existing two weights say it by being next to each other.
pub fn subheading(title: &str) -> String {
    format!("{} {}", amber("\u{258f}"), amber_bright(&title.to_uppercase()))
}

pub fn section(title: &str, width: usize) -> String {
    let t = title.to_uppercase();
    let used = t.chars().count() + 3;
    let tail = width.saturating_sub(used);
    format!(
        "{} {} {}",
        amber(&RULE_HEAVY.to_string()),
        amber_bright(&t),
        dim(&RULE_LIGHT.to_string().repeat(tail))
    )
}

/// A full-width rule.
pub fn rule(width: usize) -> String {
    dim(&RULE_LIGHT.to_string().repeat(width))
}

/// The state of one thing, as a glyph.
///
/// Shape carries the meaning as well as colour, so the screen still reads on a
/// terminal with no colour and to somebody who cannot distinguish red from
/// green — which is roughly one man in twelve, and this is an interface for
/// deciding whether to power down a machine.
pub fn mark(state: State) -> String {
    match state {
        State::Ok => measured("●"),
        State::Idle => dim("○"),
        State::Warn => warn("▲"),
        State::Fault => fault("■"),
        State::Unknown => dim("·"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Measured and within bounds.
    Ok,
    /// Present, nothing happening.
    Idle,
    /// Moving the wrong way.
    Warn,
    /// Needs a human.
    Fault,
    /// Not measured. Deliberately distinct from `Idle`, because "nothing is
    /// happening" and "nobody looked" are different claims and this system
    /// spends a great deal of effort keeping them apart.
    Unknown,
}

/// A state glyph without colour, for use inside a filled bar where the bar's
/// own colours are already set.
pub fn mark_plain(state: State) -> &'static str {
    match state {
        State::Ok => "\u{25cf}",
        State::Idle => "\u{25cb}",
        State::Warn => "\u{25b2}",
        State::Fault => "\u{25a0}",
        State::Unknown => "\u{b7}",
    }
}

/// A filled bar: a heading that reads as a surface rather than as bold text.
///
/// The device the whole language is built on. A fault takes the fault colour so
/// a bad section is visible before any of its rows are read.
pub fn bar(text: &str, state: State) -> String {
    // Background and foreground both stated, never reverse video.
    //
    // `7` swaps foreground and background, and what it swaps *in* is the
    // terminal's default foreground — grey. So a filled bar came out grey on
    // colour while every other piece of text on the screen is black on colour,
    // and the red one looked worst because grey on red is the least readable
    // pair of the three.
    match state {
        State::Fault => paint2("48;5;160;38;5;16", "41;30", text),
        State::Warn => paint2("48;5;172;38;5;16", "43;30", text),
        _ => paint2("48;5;214;38;5;16", "43;30", text),
    }
}

/// Characters a human sees, ignoring escape sequences.
///
/// Public because layout is done in more than one module and every one of them
/// needs the same answer — a width computed two ways is a grid that does not
/// line up.
pub fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            n += 1;
        }
    }
    n
}

/// Cut to a visible width, marked, with the sequence closed.
///
/// Never by bytes and never by `chars()`: escape sequences occupy no columns,
/// and a naive cut slices one in half and paints the rest of the screen wrong.
pub fn truncate(s: &str, width: usize) -> String {
    if visible_len(s) <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut shown = 0usize;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for c in chars.by_ref() {
                out.push(c);
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if shown + 1 >= width {
            out.push('\u{2026}');
            break;
        }
        out.push(c);
        shown += 1;
    }
    out.push_str("\x1b[0m");
    out
}

/// A reading with its unit, where the unit is always dimmer than the number.
pub fn reading(value: &str, unit: &str, measured_not_modelled: bool) -> String {
    let v = if measured_not_modelled { measured(value) } else { value.to_string() };
    format!("{v}{}", dim(unit))
}

/// The banner. Shown once, at the top, and never animated.
///
/// A boot sequence that pretends to be slower than it is would be a lie told
/// for atmosphere, on a screen whose entire purpose is telling the truth about
/// a machine.
pub fn banner(host: &str, session: Option<crate::session::Mux>, width: usize) -> String {
    let name = amber_bright("FURCATE");
    let h = host.to_uppercase();

    // Whether this console will survive the connection dropping. Worth one word
    // on the line an operator reads first, because it changes what they can
    // safely do next: inside a session they can walk away, and outside one,
    // closing the laptop ends whatever is running.
    let sess = session.map(|m| m.name().to_string()).unwrap_or_default();
    let tail = if sess.is_empty() { String::new() } else { format!("  {sess}") };

    let left = format!("{name}  {}{}", dim(&h), dim(&tail));
    // Padded to exactly the width, trailing rule included. Counting the rule
    // after padding to the full width overshoots by one, which shows up as a
    // ragged edge on the one line an operator reads first.
    let plain = format!("FURCATE  {h}{tail}");
    let pad = width.saturating_sub(plain.chars().count() + 1);
    format!("{left}{}{}", " ".repeat(pad.max(1)), dim(&RULE_HEAVY.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_painted_when_the_output_is_not_a_terminal() {
        // A log file full of escape codes is a log file nobody greps. Under
        // `cargo test` stdout is captured, so this exercises the real path.
        if depth() == Depth::None {
            assert_eq!(amber("x"), "x");
            assert_eq!(measured("x"), "x");
            assert!(!section("power", 40).contains('\x1b'));
        }
    }

    #[test]
    fn every_state_has_a_distinct_glyph() {
        // Shape carries the meaning as well as colour, because roughly one man
        // in twelve cannot separate red from green and this screen is used to
        // decide whether to power down a machine.
        let all = [State::Ok, State::Idle, State::Warn, State::Fault, State::Unknown];
        let marks: Vec<String> = all.iter().map(|s| mark(*s)).collect();
        let unique: std::collections::BTreeSet<&String> = marks.iter().collect();
        assert_eq!(unique.len(), all.len(), "glyphs must differ without colour");
    }

    #[test]
    fn unknown_is_not_the_same_as_idle() {
        // "Nothing is happening" and "nobody looked" are different claims, and
        // this system spends a great deal of effort keeping them apart.
        assert_ne!(mark(State::Idle), mark(State::Unknown));
    }

    #[test]
    fn a_section_heading_fills_its_width() {
        // A ragged right edge on a fixed-width screen reads as a rendering
        // fault, and an operator who thinks the display is broken stops
        // trusting what it says.
        let s = section("power", 60);
        let visible: String = strip(&s);
        assert_eq!(visible.chars().count(), 60, "got {visible:?}");
    }

    #[test]
    fn the_banner_fills_its_width_too() {
        for sess in [None, Some(crate::session::Mux::Screen)] {
            let b = banner("node-a", sess, 60);
            assert_eq!(strip(&b).chars().count(), 60, "with session {sess:?}");
        }
    }

    #[test]
    fn a_measured_reading_is_marked_and_a_modelled_one_is_not() {
        // The distinction this whole system is built on, carried into the one
        // place an operator actually looks.
        if depth() != Depth::None {
            assert!(reading("141", " W", true).contains("1;38;5;214"));
            assert!(!reading("141", " W", false).contains("1;38;5;214"));
        }
    }

    /// Remove escape sequences, so a width assertion measures what a human sees.
    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }
}
