//! Several screens, using the multiplexer that is already there.
//!
//! An operator wants more than one screen: the console on one, a shell on
//! another, a log tailing on a third, and the ability to walk away from an SSH
//! session without losing any of it.
//!
//! ## Why this drives a multiplexer instead of being one
//!
//! Doing this inside the console means a pseudo-terminal per screen and a
//! terminal emulator to interpret what the programs write into them — cursor
//! addressing, scroll regions, character sets, the parts of ECMA-48 that
//! programs actually use. That is what `tmux` and `screen` are, they have been
//! getting it right for thirty years, and a version of them living inside an
//! operations console would be a worse one that also has to be maintained.
//!
//! So the console drives whichever is present. The operator gets real screens
//! with real scrollback, and — the part that matters most here — a session that
//! outlives the connection. This is used over links that drop, on machines
//! somebody is already worried about, and a console that dies with the SSH
//! session is a console that dies exactly when it is being used.
//!
//! ## Both, not one
//!
//! `screen` is on the machines this runs on today and `tmux` is what most
//! people reach for now. Picking one would mean either shipping a dependency
//! for something already installed, or refusing to work on a machine that has
//! the other. The differences are three command lines wide.

use std::process::Command;

/// The multiplexer this process is running inside, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mux {
    Tmux,
    Screen,
}

impl Mux {
    /// What is hosting this process right now.
    ///
    /// Detected from the environment the multiplexer sets rather than from what
    /// is installed: a machine can have `tmux` on it and not be running one, and
    /// the question this answers is "can I open another window", not "is the
    /// software present".
    pub fn detect() -> Option<Mux> {
        Self::detect_in(&Env::real())
    }

    fn detect_in(env: &Env) -> Option<Mux> {
        // $TMUX is set by tmux inside its own panes and by nothing else.
        // $STY is screen's equivalent. Both are unset in a plain terminal.
        if env.get("TMUX").is_some() {
            return Some(Mux::Tmux);
        }
        if env.get("STY").is_some() {
            return Some(Mux::Screen);
        }
        None
    }

    pub fn name(&self) -> &'static str {
        match self {
            Mux::Tmux => "tmux",
            Mux::Screen => "screen",
        }
    }

    /// The command that opens a new screen running `program`.
    ///
    /// Returned rather than run, so the mapping from intent to argv can be
    /// tested without spawning anything.
    pub fn new_window_argv(&self, title: &str, program: &str) -> Vec<String> {
        let s = |x: &str| x.to_string();
        match self {
            Mux::Tmux => vec![s("tmux"), s("new-window"), s("-n"), s(title), s(program)],
            // `-X` sends a command to the session this process is already in,
            // which is why it needs no session name: screen finds it through
            // $STY, the same variable that proved we are inside one.
            Mux::Screen => {
                vec![s("screen"), s("-X"), s("screen"), s("-t"), s(title), s(program)]
            }
        }
    }

    pub fn next_argv(&self) -> Vec<String> {
        let s = |x: &str| x.to_string();
        match self {
            Mux::Tmux => vec![s("tmux"), s("next-window")],
            Mux::Screen => vec![s("screen"), s("-X"), s("next")],
        }
    }

    pub fn prev_argv(&self) -> Vec<String> {
        let s = |x: &str| x.to_string();
        match self {
            Mux::Tmux => vec![s("tmux"), s("previous-window")],
            Mux::Screen => vec![s("screen"), s("-X"), s("prev")],
        }
    }

    /// Leave the session running and return to the shell that started it.
    ///
    /// The reason this module exists. Everything on the machine keeps running;
    /// the operator gets their terminal back and can reattach from anywhere,
    /// including from a different connection after this one has dropped.
    pub fn detach_argv(&self) -> Vec<String> {
        let s = |x: &str| x.to_string();
        match self {
            Mux::Tmux => vec![s("tmux"), s("detach-client")],
            Mux::Screen => vec![s("screen"), s("-X"), s("detach")],
        }
    }

    /// How to get back in, for the line printed on the way out.
    pub fn reattach_hint(&self) -> &'static str {
        match self {
            Mux::Tmux => "tmux attach -t furcate",
            Mux::Screen => "screen -r furcate",
        }
    }

    /// Run one of the above, reporting whether it worked.
    ///
    /// A failure is returned rather than ignored: an operator who pressed a key
    /// and saw nothing happen will press it again, and then decide the console
    /// is broken.
    pub fn run(&self, argv: &[String]) -> Result<(), String> {
        let Some((cmd, args)) = argv.split_first() else {
            return Err("empty command".into());
        };
        match Command::new(cmd).args(args).status() {
            Ok(st) if st.success() => Ok(()),
            Ok(st) => Err(format!("{} exited {}", argv.join(" "), st.code().unwrap_or(-1))),
            Err(e) => Err(format!("{}: {e}", argv.join(" "))),
        }
    }
}

/// The environment, behind a seam so detection can be tested.
///
/// The alternative is setting `$TMUX` inside a test, which races every other
/// test in the binary — a mistake this codebase has made three times and now
/// designs against.
pub struct Env(Vec<(String, String)>);

impl Env {
    pub fn real() -> Self {
        Env(std::env::vars().collect())
    }
    #[cfg(test)]
    fn of(pairs: &[(&str, &str)]) -> Self {
        Env(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// Whether a multiplexer is installed, for the machine that is not in one yet.
///
/// Prefers whichever the operator is more likely to already be using, and
/// answers `None` on a machine with neither rather than pretending.
pub fn installed() -> Option<Mux> {
    for (m, bin) in [(Mux::Tmux, "tmux"), (Mux::Screen, "screen")] {
        if std::path::Path::new(&format!("/usr/bin/{bin}")).exists()
            || std::path::Path::new(&format!("/bin/{bin}")).exists()
        {
            return Some(m);
        }
    }
    None
}

/// The name of the session Furcate owns.
///
/// Fixed rather than generated, because the whole point is that an operator who
/// reconnects gets *the* session back rather than starting a second one beside
/// the first.
pub const SESSION: &str = "furcate";

/// Replace this process with a multiplexer hosting the console.
///
/// The single way in. An operator types one command and gets the console, a
/// place to put shells, and — the part that matters on these machines — a
/// session that outlives the connection they typed it over.
///
/// Returns `Err` describing why not, in which case the caller runs the console
/// on the bare terminal. That is a real fallback rather than an error path:
/// a console with one screen is worth more than a message saying it could have
/// had several.
pub fn enter(console: &std::path::Path) -> Result<std::convert::Infallible, String> {
    use std::os::unix::process::CommandExt;

    if let Some(m) = Mux::detect() {
        return Err(format!("already inside {}", m.name()));
    }
    let Some(m) = installed() else {
        return Err("neither tmux nor screen is installed".into());
    };

    let bin = console.to_string_lossy().to_string();
    // Our configuration, for this session only. The operator's own tmux.conf or
    // .screenrc is not read and not modified: Furcate brands the session it
    // starts, and does not reach into the ones it did not.
    let argv: Vec<String> = match m {
        Mux::Tmux => vec![
            "tmux".into(),
            "-f".into(),
            "/usr/share/furcate/tmux.conf".into(),
            "new-session".into(),
            // Attach to the existing session if there is one, create it if not.
            "-A".into(),
            "-s".into(),
            SESSION.into(),
            bin,
        ],
        Mux::Screen => vec![
            "screen".into(),
            "-c".into(),
            "/usr/share/furcate/screenrc".into(),
            "-S".into(),
            SESSION.into(),
            // Reattach if possible, create if not — the same behaviour as
            // tmux's -A above.
            "-R".into(),
            bin,
        ],
    };

    let Some((cmd, args)) = argv.split_first() else {
        return Err("empty command".into());
    };
    // exec rather than spawn-and-wait: there is nothing for this process to do
    // afterwards, and a parent sitting in the middle would take the signals
    // meant for the session.
    Err(format!("{}: {}", m.name(), Command::new(cmd).args(args).exec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_terminal_is_not_a_multiplexer() {
        assert_eq!(Mux::detect_in(&Env::of(&[("TERM", "xterm-256color")])), None);
    }

    #[test]
    fn each_multiplexer_is_recognised_by_the_variable_it_sets() {
        assert_eq!(Mux::detect_in(&Env::of(&[("TMUX", "/tmp/tmux-1000/default,1,0")])), Some(Mux::Tmux));
        assert_eq!(Mux::detect_in(&Env::of(&[("STY", "4242.furcate")])), Some(Mux::Screen));
    }

    #[test]
    fn being_installed_is_not_the_same_as_being_inside_one() {
        // The question the console asks is "can I open another window", which
        // is about the session, not about the software. node-a has screen
        // installed and is not running it.
        assert_eq!(Mux::detect_in(&Env::of(&[("PATH", "/usr/bin")])), None);
    }

    #[test]
    fn every_action_produces_a_runnable_command_for_both() {
        // The whole abstraction is three command lines wide; the value is that
        // neither multiplexer is special-cased at the call site.
        for m in [Mux::Tmux, Mux::Screen] {
            for argv in [
                m.new_window_argv("shell", "/bin/sh"),
                m.next_argv(),
                m.prev_argv(),
                m.detach_argv(),
            ] {
                assert!(!argv.is_empty(), "{m:?} produced no command");
                assert_eq!(argv[0], m.name(), "the command must be the multiplexer itself");
            }
        }
    }

    #[test]
    fn a_new_window_carries_the_program_it_should_run() {
        let argv = Mux::Tmux.new_window_argv("shell", "/bin/zsh");
        assert!(argv.contains(&"/bin/zsh".to_string()));
        let argv = Mux::Screen.new_window_argv("shell", "/bin/zsh");
        assert!(argv.contains(&"/bin/zsh".to_string()));
    }

    #[test]
    fn screen_addresses_the_session_it_is_already_in() {
        // -X sends to the session named by $STY. Passing a session name here
        // would target the wrong one when an operator has more than one open.
        assert!(Mux::Screen.next_argv().contains(&"-X".to_string()));
    }

    #[test]
    fn the_session_has_a_fixed_name_so_reattaching_finds_it() {
        // A generated name would give an operator a second session beside the
        // first every time they reconnected.
        assert_eq!(SESSION, "furcate");
        assert!(Mux::Tmux.reattach_hint().contains(SESSION));
        assert!(Mux::Screen.reattach_hint().contains(SESSION));
    }

    #[test]
    fn entering_from_inside_a_session_is_refused_rather_than_nested() {
        // Only checkable when the test itself is in one; harmless when not.
        if Mux::detect().is_some() {
            assert!(enter(std::path::Path::new("/bin/true")).is_err());
        }
    }

    #[test]
    fn an_empty_command_is_refused_rather_than_spawned() {
        assert!(Mux::Tmux.run(&[]).is_err());
    }
}
