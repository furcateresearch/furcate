//! The interactive surface.
//!
//! A terminal is not a worse window manager, and building one that pretends to
//! be produces something that is bad at both. What a terminal is good at is a
//! dense fixed layout that never moves, and keys that mean the same thing every
//! time. So: a rail of sections down the left, one detail pane, and a footer
//! that says what the keys do *right now*.
//!
//! ## Keys belong to contexts
//!
//! The same key does different things depending on what is focused, and the
//! help is context-sensitive rather than a manual. That is the right model for
//! an operations screen, where the useful keys in a disk view are not the
//! useful keys in a power view.
//!
//! It also means the footer is never a lie. Whatever it says are the keys that
//! work, because the same table produces both the footer and the dispatch.
//!
//! ## What it will not do
//!
//! Nothing here changes the machine. Every Furcate action needs an operator
//! signature over a nonced order, and a screen with a key that could bypass that
//! would be a hole in the authority model wearing a convenient shape. The keys
//! navigate; `furcatectl` acts.
//!
//! There is also no animation. A boot sequence that pretended to be slower than
//! it is would be a lie told for atmosphere, on a display whose entire purpose
//! is telling the truth about a machine.

use crate::session::Mux;
use crate::style::{self, State};
use crate::term::Key;

/// One thing an operator can look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    /// What this hardware is and whether it is still what it was: state,
    /// inventory, and whether the image still matches its baseline.
    Machine,
    /// What this machine has to give — disks, memory, compute, and what is
    /// already spoken for. Kept apart from Machine because the questions are
    /// different: one asks what this is, the other asks what is left.
    Resources,
    /// Everything that draws current — what it costs, and what it does to the
    /// temperature. Energy and cooling are one subject: a fan is a load and a
    /// load is heat, and splitting them meant reading two screens to answer one
    /// question.
    Power,
    /// The local cluster: the fabric this machine shares with the machines
    /// beside it, who is admitted to it, and which of them administers the site.
    Network,
    /// Everything outside the cluster — the networks this machine joins, the
    /// tunnels and passthroughs it is reached through, and the names it answers
    /// on. Kept apart from the local fabric because the questions differ: one is
    /// "who is beside me", the other is "how does the world reach me".
    Connectivity,
    /// Who may change this machine, who it is, the keys that say so, what it
    /// refused, and the checks that run on their own.
    Security,
    /// What is placed here, and where it survives a failure.
    Workloads,
    /// The machine's own facilities: what it reasons with, whether it is behind,
    /// and how it was set up.
    System,
    /// What the machine noticed about itself — findings, the loops that produce
    /// them, and the changes it is waiting on a person for. Observability, in
    /// the sense that matters here: not a graph, but the things a machine has
    /// concluded and cannot act on alone.
    Management,
}

impl Pane {
    pub const ALL: [Pane; 9] = [
        Pane::Machine,
        Pane::Resources,
        Pane::Power,
        Pane::Network,
        Pane::Connectivity,
        Pane::Security,
        Pane::Workloads,
        Pane::System,
        Pane::Management,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Pane::Machine => "machine",
            Pane::Resources => "resources",
            Pane::Power => "power",
            Pane::Network => "network",
            Pane::Connectivity => "connectivity",
            Pane::Security => "security",
            Pane::Workloads => "workloads",
            Pane::System => "system",
            Pane::Management => "management",
        }
    }

    /// The pane a name refers to, using the same spellings the footer shows.
    ///
    /// One table rather than two: the desktop launcher, the `--pane` argument
    /// and the label on screen are the same string, so a capability cannot be
    /// called one thing in the menu and another in the console.
    pub fn by_name(name: &str) -> Option<Pane> {
        Pane::ALL.into_iter().find(|p| p.title() == name)
    }

    /// Every name, for an error message that tells the operator what to type
    /// instead of only that they were wrong.
    pub fn names() -> Vec<&'static str> {
        Pane::ALL.into_iter().map(|p| p.title()).collect()
    }
}

// The app -> sections table, generated from deploy/os/arms.toml so that the
// manifest, the desktop launcher and this console cannot disagree about what
// is inside an app.
include!(concat!(env!("OUT_DIR"), "/sections.rs"));

/// One screen inside an app.
///
/// Apps are what an operator is looking for — power, network, security. A
/// section is the particular thing inside it, and the split is what gives the
/// console more than two levels: the machine, an app, a section of it, a row in
/// that section.
///
/// These were the panes before apps existed, which is why several are named for
/// what they show rather than for a category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    State,
    Storage,
    Capacity,
    Draw,
    Cooling,
    PrivateNetwork,
    Administration,
    Published,
    Authority,
    Identity,
    TheRecord,
    Custody,
    Tenants,
    Bindings,
    Inference,
    Lan,
    Tunnels,
    Routing,
    Keys,
    Findings,
    Loops,
    Proposals,
    Placed,
    /// Workloads rented on this machine by somebody who does not own it:
    /// what bounds each one, and what it has consumed. Beside `placed` rather
    /// than inside it, because the operator's question about a placed service
    /// is whether it survives a failure and the question about a box is whether
    /// a tenant is still inside their share.
    Boxes,
    Advisor,
    Updates,
}

impl Section {
    pub fn title(&self) -> &'static str {
        match self {
            Section::State => "state",
            Section::Storage => "storage",
            Section::Capacity => "capacity",
            Section::Draw => "draw",
            Section::Cooling => "cooling",
            // Not "overlay". It is the private network this machine shares with
            // the machines beside it, and an operator should not have to learn
            // a word from network engineering to find it.
            Section::PrivateNetwork => "private network",
            Section::Administration => "administration",
            Section::Published => "published",
            Section::Authority => "authority",
            Section::Identity => "identity",
            Section::TheRecord => "the record",
            Section::Custody => "custody",
            Section::Tenants => "tenants",
            Section::Bindings => "bindings",
            Section::Inference => "inference",
            Section::Lan => "lan",
            Section::Tunnels => "tunnels",
            Section::Routing => "routing",
            Section::Keys => "keys",
            Section::Findings => "findings",
            Section::Loops => "loops",
            Section::Proposals => "proposals",
            Section::Placed => "placed",
            Section::Boxes => "boxes",
            Section::Advisor => "advisor",
            Section::Updates => "updates",
        }
    }
}

/// One thing a dialog asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
    /// What a valid answer looks like, shown while the field is empty. An
    /// operator typing a WireGuard key into a box labelled only "key" is being
    /// asked to remember a format nobody should have to.
    pub hint: &'static str,
    pub required: bool,
}

/// What a dialog will do if it is submitted.
///
/// Named rather than a free-form string: every one of these ends in a signed
/// call that changes a machine, and a typo in a string that selects which
/// change is not a class of bug worth leaving open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deed {
    /// Admit a machine to the private network.
    AddPeer,
    /// Stop serving a name from this machine.
    RemoveSite,
}

impl Deed {
    pub fn title(&self) -> &'static str {
        match self {
            Deed::AddPeer => "admit a machine",
            Deed::RemoveSite => "stop serving a name",
        }
    }

    /// Whether only the machine administering the site may do this.
    ///
    /// Holding the operator key is what grants permission — authority is a file
    /// you hold, and every one of these is signed and ruled on by policy
    /// wherever it is typed. What the administrator adds is the site-wide view:
    /// admitting a peer or trusting an anchor changes who the *site* accepts,
    /// and doing that from a node with a partial picture is how two halves of a
    /// cluster end up disagreeing about who belongs.
    pub fn site_wide(&self) -> bool {
        match self {
            Deed::AddPeer => true,
            Deed::RemoveSite => false,
        }
    }

    pub fn fields(&self) -> Vec<Field> {
        let f = |label, hint, required| Field { label, value: String::new(), hint, required };
        match self {
            Deed::AddPeer => vec![
                f("node id", "furcate:node:…  the machine's own name", true),
                f("public key", "its WireGuard key, 44 characters", true),
                f("address", "10.90.0.4  its address inside the private network", true),
                f("tier", "platform or attested", true),
                f("hours", "how long the admission lasts. 2160 is ninety days", true),
            ],
            Deed::RemoveSite => vec![f("site", "the name this machine gave it", true)],
        }
    }
}

/// A form, open over the screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dialog {
    pub deed: Deed,
    pub fields: Vec<Field>,
    pub focus: usize,
    /// Why the last submission was not accepted. Kept on the dialog so the
    /// answer stays on screen beside the field that caused it, rather than
    /// closing the form and making the operator type it all again.
    pub error: Option<String>,
}

impl Dialog {
    pub fn new(deed: Deed) -> Self {
        Self { deed, fields: deed.fields(), focus: 0, error: None }
    }

    /// Everything required has an answer.
    pub fn complete(&self) -> Result<(), String> {
        for f in &self.fields {
            if f.required && f.value.trim().is_empty() {
                return Err(format!("{} is needed", f.label));
            }
        }
        Ok(())
    }

    pub fn value(&self, label: &str) -> String {
        self.fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default()
    }
}

/// What the operator is doing, which decides what the keys mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// Moving between panes.
    Browsing,
    /// Reading the key list.
    Help,
    /// Filling in a form. Keys mean text here, so nothing else may claim them.
    Dialog,
}

/// Something the operator asked for that this module cannot do itself.
///
/// Emitted rather than performed. This module knows what the keys mean and
/// nothing else — the caller owns the terminal and the session, and a module
/// that spawned processes behind its back would leave it holding a raw-mode
/// guard for a terminal it no longer controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    /// Carry out the form that is open.
    ///
    /// Supersedes the reasoning on `RevokeSelected` below: granting authority
    /// was left out because "a screen with no text entry cannot ask for" a
    /// principal, an action and a resource. There is text entry now.
    Submit,
    /// Withdraw the authority under the cursor.
    ///
    /// Revoking, and deliberately not granting: a grant needs a principal, an
    /// action, a resource, a window and a reason, and a screen with no text
    /// entry cannot ask for them. Handing out authority stays where an operator
    /// has to type it out and can read it back before pressing return; taking
    /// it away is one keystroke because that is the direction that should be
    /// easy.
    RevokeSelected,
    /// Restart the workload under the cursor. Carries nothing: the caller knows
    /// which row is selected, and a stale id in here would restart whatever it
    /// named rather than what the operator was looking at.
    RestartSelected,
    /// A shell, here, with the console standing aside until it exits.
    Shell,
    /// A shell on a screen of its own, with the console still running on this
    /// one.
    ScreenNew,
    ScreenNext,
    ScreenPrev,
    /// Leave everything running and give the terminal back.
    Detach,
}

/// What a binding needs in order to work.
///
/// The footer's whole claim is that it never lies, and half these keys need a
/// session to act on. Filtering by context alone would advertise `d detach` on
/// a machine with nothing to detach from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Needs {
    /// Works anywhere.
    Always,
    /// Only inside a multiplexer session.
    Screens,
    /// Only outside one — where the console has to stand aside for a shell
    /// rather than opening another screen.
    NoScreens,
    /// Only while a section is open. Going home from home does nothing, and a
    /// footer that offers it is a footer that has started lying.
    Detail,
}

/// Where an operator is inside a list, and which part of it is on screen.
///
/// Lists here are longer than the screen — 52 clients, 28 workloads, 24
/// firewall rules — and the previous version simply truncated to whatever fit.
/// That is worse than it sounds: the row that did not fit is as likely to be
/// the broken one as any other, so a screen that silently drops the tail can
/// show a healthy site that is not healthy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    /// Which row is selected.
    pub index: usize,
    /// The first row on screen. Kept rather than recomputed so the list does
    /// not jump under the operator when the selection moves by one.
    pub top: usize,
}

impl Cursor {
    /// Keep the selection on screen, and return the rows to draw.
    ///
    /// Scrolls by the minimum needed, so the list moves only when the selection
    /// would otherwise leave it.
    ///
    /// This is also where the selection is clamped, and deliberately the only
    /// place: the key handler moves the index freely because it does not know
    /// how long the list is, and the renderer is the one thing that does.
    /// Clamping in both would be two statements of one rule, and they would
    /// disagree the first time a list changed length between them.
    ///
    /// Clamping rather than wrapping. Wrapping is right for a ring of panes and
    /// wrong for a list: an operator holding `j` to reach the bottom of a long
    /// list does not expect to arrive back at the top, and on a list of faults
    /// that means reading the same ones twice and believing there are more.
    pub fn window(&mut self, len: usize, height: usize) -> std::ops::Range<usize> {
        if height == 0 || len == 0 {
            self.top = 0;
            return 0..0;
        }
        self.index = self.index.min(len.saturating_sub(1));
        if self.index < self.top {
            self.top = self.index;
        } else if self.index >= self.top + height {
            self.top = self.index + 1 - height;
        }
        // A list that has shrunk must not leave the window past its end.
        self.top = self.top.min(len.saturating_sub(height.min(len)));
        self.top..(self.top + height).min(len)
    }

    /// Whether there is more above or below what is on screen, so the display
    /// can say so rather than ending without explanation.
    pub fn more(&self, len: usize, height: usize) -> (bool, bool) {
        (self.top > 0, self.top + height < len)
    }
}

/// One binding, and the single source of both the dispatch and the footer.
///
/// Two lists would drift, and a footer that advertises a key which does nothing
/// is worse than no footer: it teaches an operator that the display lies.
pub struct Binding {
    pub key: &'static str,
    pub does: &'static str,
    pub context: Context,
    pub needs: Needs,
}

pub const BINDINGS: &[Binding] = &[
    Binding { key: "1-9", does: "section", context: Context::Browsing, needs: Needs::Always },
    Binding { key: "0", does: "home", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "tab", does: "panes", context: Context::Browsing, needs: Needs::Always },
    Binding { key: "h/l", does: "section", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "a", does: "admit", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "d", does: "remove", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "tab", does: "field", context: Context::Dialog, needs: Needs::Always },
    Binding { key: "enter", does: "submit", context: Context::Dialog, needs: Needs::Always },
    Binding { key: "esc", does: "cancel", context: Context::Dialog, needs: Needs::Always },
    Binding { key: "j/k", does: "row", context: Context::Browsing, needs: Needs::Always },
    Binding { key: "enter", does: "open", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "s", does: "site/node", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "R", does: "restart", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "W", does: "withdraw", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "esc", does: "back", context: Context::Browsing, needs: Needs::Detail },
    Binding { key: "r", does: "refresh", context: Context::Browsing, needs: Needs::Always },
    Binding { key: "!", does: "shell", context: Context::Browsing, needs: Needs::NoScreens },
    Binding { key: "!", does: "screen", context: Context::Browsing, needs: Needs::Screens },
    Binding { key: "n/p", does: "screens", context: Context::Browsing, needs: Needs::Screens },
    Binding { key: "d", does: "detach", context: Context::Browsing, needs: Needs::Screens },
    Binding { key: "?", does: "keys", context: Context::Browsing, needs: Needs::Always },
    Binding { key: "q", does: "quit", context: Context::Browsing, needs: Needs::Always },
    Binding { key: "esc", does: "back", context: Context::Help, needs: Needs::Always },
    Binding { key: "q", does: "quit", context: Context::Help, needs: Needs::Always },
];

/// Everything the screen needs to know about itself.
pub struct Ui {
    /// Which section is open, or none — the home screen, which shows them all.
    ///
    /// Home is the default because the question an operator arrives with is
    /// "is this all right", and that used to take seven keystrokes to answer.
    pub detail: Option<usize>,
    pub focused: usize,
    pub context: Context,
    pub running: bool,
    /// Bumped whenever something should be fetched again, so the draw loop and
    /// the input loop do not each keep their own idea of freshness.
    pub generation: u64,
    /// The multiplexer this console is running inside, if any. Decides whether
    /// a shell opens on another screen or on this one.
    pub mux: Option<Mux>,
    /// What the operator asked for that this module cannot do itself.
    intent: Option<Intent>,
    /// Something that went wrong, shown until the next keypress.
    pub notice: Option<String>,
    /// Where the operator is inside the open pane's list, one per pane so
    /// leaving a section and coming back does not lose their place.
    pub cursors: [Cursor; Pane::ALL.len()],
    /// Which section of each app is open. Per app, so moving away and back
    /// returns to what was being read rather than to the first section.
    pub sections: [usize; Pane::ALL.len()],
    /// How many rows the open pane last drew, so a page moves by a screenful
    /// of the actual list rather than by a guess.
    pub page: usize,
    /// An action asked for and not yet confirmed.
    ///
    /// Two keys, deliberately. Everything else on this screen is reversible by
    /// pressing something else; this one reaches a real machine, and a single
    /// keystroke that restarts a mainnet validator is a keystroke somebody will
    /// hit by accident. The prompt names the workload, so the confirmation is
    /// of *this* action rather than of a habit.
    pub pending: Option<String>,
    /// The form currently open, if any.
    pub dialog: Option<Dialog>,
    /// Whether a list pane is showing the site rather than this machine.
    ///
    /// "What is this machine running" and "what is the site running" are
    /// different questions with different answers, and an operator standing at
    /// one node needs both. Kept as a scope on one pane rather than a second
    /// pane, because they are the same subject seen from two distances.
    pub fleet: bool,
    /// Whether the selected row is opened in full.
    ///
    /// A list has to fit every resource on one line, so it shows the four or
    /// five fields that fit and drops the rest. Opening one is how the rest is
    /// reachable at all — otherwise the only way to see a workload's ports and
    /// restart history is to leave the console for `systemctl show`.
    pub zoom: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            detail: None,
            focused: 0,
            context: Context::Browsing,
            running: true,
            generation: 0,
            mux: Mux::detect(),
            intent: None,
            notice: None,
            cursors: [Cursor::default(); Pane::ALL.len()],
            sections: [0; Pane::ALL.len()],
            page: 1,
            pending: None,
            dialog: None,
            fleet: false,
            zoom: false,
        }
    }
}

impl Ui {
    /// The cursor for the pane currently open.
    pub fn cursor_mut(&mut self) -> &mut Cursor {
        let i = self.focused.min(Pane::ALL.len() - 1);
        &mut self.cursors[i]
    }

    pub fn cursor(&self) -> Cursor {
        self.cursors[self.focused.min(Pane::ALL.len() - 1)]
    }

    /// Open on one pane, as though its digit had been pressed.
    ///
    /// Deliberately the same three assignments the key handler makes rather
    /// than a second way in: a pane opened from the command line and a pane
    /// opened from the keyboard must leave the console in the same state, or
    /// the launcher becomes a subtly different application.
    pub fn open(&mut self, pane: Pane) {
        if let Some(i) = Pane::ALL.iter().position(|p| *p == pane) {
            self.focused = i;
            self.detail = Some(i);
            self.zoom = false;
        }
    }

    /// The section currently open in the current app.
    pub fn section(&self) -> Section {
        let p = self.pane();
        let all = p.sections();
        let i = self.sections[self.focused.min(Pane::ALL.len() - 1)];
        all[i.min(all.len() - 1)]
    }

    /// Move to the next or previous section of this app, without wrapping.
    ///
    /// Not wrapping is deliberate and matches the digits: an operator who holds
    /// a key expects to stop at the end rather than arrive somewhere they did
    /// not ask for on a screen they are reading to decide something.
    pub fn move_section(&mut self, forward: bool) -> bool {
        let i = self.focused.min(Pane::ALL.len() - 1);
        let n = Pane::ALL[i].sections().len();
        let cur = self.sections[i];
        let next = if forward { cur.saturating_add(1).min(n - 1) } else { cur.saturating_sub(1) };
        if next == cur {
            return false;
        }
        self.sections[i] = next;
        // A new section is a new list, so the row cursor cannot carry over.
        self.cursors[i] = Cursor::default();
        true
    }

    pub fn pane(&self) -> Pane {
        Pane::ALL[self.focused.min(Pane::ALL.len() - 1)]
    }

    /// Apply a keypress in the current context.
    ///
    /// Returns whether anything changed, so the caller can avoid redrawing a
    /// screen that would be identical — a display that flickers on every
    /// timeout is one people stop leaving open.
    pub fn on_key(&mut self, k: Key) -> bool {
        // A notice belongs to the action that produced it. Left up, it becomes
        // a line the operator stops reading.
        let had_notice = self.notice.take().is_some();
        self.on_key_inner(k) || had_notice
    }

    fn on_key_inner(&mut self, k: Key) -> bool {
        match (self.context, k) {
            // Confirming, or thinking better of it. Above every other binding,
            // including quit: while a confirmation is up the keys mean this and
            // nothing else, so no key can carry an operator out of the prompt
            // into something else. Only end-of-input still ends the program,
            // because there is nobody left to answer it.
            (_, Key::Char('y')) if self.pending.is_some() => {
                let what = self.pending.take();
                self.intent = Some(if what.as_deref() == Some("revoke") {
                    Intent::RevokeSelected
                } else {
                    Intent::RestartSelected
                });
                true
            }
            (_, k) if self.pending.is_some() && k != Key::Exhausted => {
                // Anything else is "no". A prompt that only accepts one
                // specific refusal is one people escape by guessing.
                self.pending = None;
                self.notice = Some("not restarted".into());
                true
            }
            (_, Key::Char('q')) | (_, Key::Exhausted) => {
                self.running = false;
                true
            }
            (Context::Help, Key::Escape) | (Context::Help, Key::Char('?')) => {
                self.context = Context::Browsing;
                true
            }
            (Context::Help, _) => false,

            (Context::Browsing, Key::Char('?')) => {
                self.context = Context::Help;
                true
            }
            // A screen an operator cannot get out of without losing it is a
            // worse terminal than the one it replaced. `!` is the shell, which
            // is the key terminal tools conventionally use for it.
            //
            // Inside a session it opens on a screen of its own and the console
            // keeps running on this one, which is the difference the operator
            // asked for: everything in one place, nothing to switch between.
            // Outside one, there is nowhere else to put it, so the console
            // stands aside and takes the terminal back when the shell exits.
            (Context::Browsing, Key::Char('!')) => {
                self.intent =
                    Some(if self.mux.is_some() { Intent::ScreenNew } else { Intent::Shell });
                true
            }
            (Context::Browsing, Key::Char('n')) if self.mux.is_some() => {
                self.intent = Some(Intent::ScreenNext);
                true
            }
            (Context::Browsing, Key::Char('p')) if self.mux.is_some() => {
                self.intent = Some(Intent::ScreenPrev);
                true
            }
            // Detaching is why the session exists. This runs over links that
            // drop, on machines somebody is already worried about, and a console
            // that dies with the connection dies exactly when it is being used.
            (Context::Browsing, Key::Char('d')) if self.mux.is_some() => {
                self.intent = Some(Intent::Detach);
                true
            }
            (Context::Browsing, Key::Char('r')) => {
                self.generation += 1;
                true
            }
            (Context::Browsing, Key::Tab) => {
                self.focused = (self.focused + 1) % Pane::ALL.len();
                self.detail = Some(self.focused);
                self.zoom = false;
                true
            }
            // Shift-Tab, which a VT100 cannot send at all: it arrives only
            // because the console asks the terminal for the keyboard protocol.
            // Cycling one way and not the other is the kind of asymmetry an
            // operator notices every time they overshoot.
            (Context::Browsing, Key::BackTab) => {
                self.focused = (self.focused + Pane::ALL.len() - 1) % Pane::ALL.len();
                self.detail = Some(self.focused);
                self.zoom = false;
                true
            }
            // j/k move *within* the open list, not between panes.
            //
            // They used to cycle panes, which left no way at all to reach row
            // 30 of a 28-row screen — the list was simply cut off. Panes are
            // still one keystroke away on tab and on their own numbers, and a
            // list is the thing an operator actually needs to move through.
            (Context::Browsing, Key::Down) | (Context::Browsing, Key::Char('j')) => {
                self.detail.get_or_insert(self.focused);
                self.cursor_mut().index += 1;
                true
            }
            (Context::Browsing, Key::Up) | (Context::Browsing, Key::Char('k')) => {
                let c = self.cursor_mut();
                c.index = c.index.saturating_sub(1);
                true
            }
            // A screenful at a time, for lists that are long enough to make
            // holding a key a poor way to travel.
            (Context::Browsing, Key::PageDown) | (Context::Browsing, Key::Char(' ')) => {
                let page = self.page.max(1);
                self.detail.get_or_insert(self.focused);
                self.cursor_mut().index += page;
                true
            }
            (Context::Browsing, Key::PageUp) => {
                let page = self.page.max(1);
                let c = self.cursor_mut();
                c.index = c.index.saturating_sub(page);
                true
            }
            (Context::Browsing, Key::Home) | (Context::Browsing, Key::Char('g')) => {
                self.cursor_mut().index = 0;
                true
            }
            // The end of a list, without holding a key to get there. Clamped by
            // the renderer against the real length, which is the only thing
            // that knows it.
            (Context::Browsing, Key::End) | (Context::Browsing, Key::Char('G')) => {
                self.cursor_mut().index = usize::MAX;
                true
            }
            // Ask to restart what is selected. Only on this machine's own
            // scope: the site view is a roll-up of services, and "restart
            // orchid-mainnet" is not a thing any single machine can be asked
            // to do.
            (Context::Browsing, Key::Char('R')) if self.detail.is_some() && !self.fleet => {
                self.pending = Some(String::new());
                true
            }
            // Withdraw, on the authority pane. Same two keys, same prompt, same
            // rule that anything other than `y` is no.
            (Context::Browsing, Key::Char('W'))
                if self.pane() == Pane::Security && self.detail.is_some() =>
            {
                self.pending = Some("revoke".into());
                true
            }
            // The same subject, from the site's distance rather than this
            // machine's. Resets the cursor: row 7 of one list is not row 7 of
            // the other, and leaving the selection where it was would open a
            // different resource than the one that was highlighted.
            (Context::Browsing, Key::Char('s')) if self.detail.is_some() => {
                self.fleet = !self.fleet;
                self.zoom = false;
                *self.cursor_mut() = Cursor::default();
                true
            }
            // Enter descends into the selected resource; escape comes back up.
            // One level, deliberately: a console an operator has to remember
            // their way out of is one they leave open at the wrong screen.
            (Context::Browsing, Key::Enter) if self.detail.is_some() => {
                self.zoom = true;
                true
            }
            // ── While a form is open, keys are text ──────────────────────
            //
            // Placed above everything else on purpose. A key that means "quit"
            // in one context and "type a q" in another must resolve to the
            // typing, or an operator filling in a public key loses the form on
            // the letter q.
            (Context::Dialog, Key::Escape) => {
                self.dialog = None;
                self.context = Context::Browsing;
                self.notice = Some("cancelled".into());
                true
            }
            (Context::Dialog, Key::Enter) => {
                let Some(d) = self.dialog.as_mut() else { return false };
                match d.complete() {
                    // Held open with the reason on it. Closing a half-filled
                    // form and asking for it again is how an operator loses a
                    // key they pasted from somewhere they no longer have.
                    Err(why) => d.error = Some(why),
                    Ok(()) => self.intent = Some(Intent::Submit),
                }
                true
            }
            (Context::Dialog, Key::Tab) | (Context::Dialog, Key::Down) => {
                if let Some(d) = self.dialog.as_mut() {
                    d.focus = (d.focus + 1) % d.fields.len();
                }
                true
            }
            (Context::Dialog, Key::BackTab) | (Context::Dialog, Key::Up) => {
                if let Some(d) = self.dialog.as_mut() {
                    d.focus = (d.focus + d.fields.len() - 1) % d.fields.len();
                }
                true
            }
            // The terminal sends DEL for backspace and some send BS. Both mean
            // the same thing to a person holding the key.
            (Context::Dialog, Key::Char('\u{7f}')) | (Context::Dialog, Key::Char('\u{8}')) => {
                if let Some(d) = self.dialog.as_mut() {
                    let i = d.focus;
                    d.fields[i].value.pop();
                    d.error = None;
                }
                true
            }
            (Context::Dialog, Key::Char(c)) if !c.is_control() => {
                if let Some(d) = self.dialog.as_mut() {
                    let i = d.focus;
                    d.fields[i].value.push(c);
                    d.error = None;
                }
                true
            }
            // Add and delete, where the section has something to add or delete.
            // Bound per section rather than globally: a key that exists
            // everywhere and works in two places teaches an operator that the
            // console ignores them.
            (Context::Browsing, Key::Char('a'))
                if self.detail.is_some() && self.section() == Section::PrivateNetwork =>
            {
                self.dialog = Some(Dialog::new(Deed::AddPeer));
                self.context = Context::Dialog;
                true
            }
            (Context::Browsing, Key::Char('d'))
                if self.detail.is_some() && self.section() == Section::Published =>
            {
                self.dialog = Some(Dialog::new(Deed::RemoveSite));
                self.context = Context::Dialog;
                true
            }
            (Context::Browsing, Key::Escape) if self.zoom => {
                self.zoom = false;
                true
            }
            // Sections, with the pair every terminal reader already has in
            // their fingers from vi. `tab` still moves between apps.
            (Context::Browsing, Key::Char('l')) if self.detail.is_some() => self.move_section(true),
            (Context::Browsing, Key::Char('h')) if self.detail.is_some() => self.move_section(false),
            (Context::Browsing, Key::Char(c)) if c.is_ascii_digit() && c != '0' => {
                let want = (c as u8 - b'1') as usize;
                if want < Pane::ALL.len() {
                    self.focused = want;
                    self.detail = Some(want);
                    self.zoom = false;
                    return true;
                }
                false
            }
            // Back to the whole machine. `0` because the sections are 1-7 and
            // home is what comes before the first of them; escape because that
            // is what escape means everywhere else on this screen.
            (Context::Browsing, Key::Char('0')) | (Context::Browsing, Key::Escape)
                if self.detail.is_some() =>
            {
                self.detail = None;
                self.zoom = false;
                true
            }
            _ => false,
        }
    }

    /// What was asked for, clearing the request.
    ///
    /// Taken rather than read: a request left set would spawn a second shell
    /// the moment the first one exited.
    pub fn take_intent(&mut self) -> Option<Intent> {
        self.intent.take()
    }

    /// Which bindings apply right now, in the order they are shown.
    fn visible(&self) -> Vec<&'static Binding> {
        let has = self.mux.is_some();
        BINDINGS
            .iter()
            .filter(|b| b.context == self.context)
            .filter(|b| match b.needs {
                Needs::Always => true,
                Needs::Screens => has,
                Needs::NoScreens => !has,
                Needs::Detail => self.detail.is_some(),
            })
            .collect()
    }

    /// The footer, built from the same table that dispatches the keys.
    ///
    /// Trimmed to the width rather than allowed to wrap. A footer that wraps
    /// costs a line of the pane above it and, worse, puts half a binding at the
    /// start of the next line where it reads as content — on a display whose
    /// layout is the navigation model, that is the one line that must not move.
    ///
    /// What gets dropped is what is least needed on screen: the keys nearest
    /// the end of the table go first. Two never go — `?`, the way to find
    /// everything that was dropped, and `q`, the way out. An operator who
    /// cannot see how to leave a full-screen program on a machine they are
    /// worried about will close the connection instead, and on a detached
    /// session that leaves it running with nobody watching.
    /// Where the operator is, in words, before the keys that move them.
    ///
    /// The footer listed keys and never said what they applied to. On a screen
    /// with three levels — the grid, a part, a row inside it — the same key
    /// does different things, and a flat list of them is a list of things that
    /// might work.
    pub fn breadcrumb(&self) -> String {
        match (self.context, self.detail) {
            (Context::Help, _) => "KEYS".to_string(),
            (_, None) => "HOME".to_string(),
            (_, Some(i)) => {
                let pane = Pane::ALL[i.min(Pane::ALL.len() - 1)];
                let mut path = format!("HOME \u{203a} {}", pane.title().to_uppercase());
                // The section is only worth a level when the app has more than
                // one; naming the only section of an app is noise.
                if pane.sections().len() > 1 {
                    path.push_str(&format!(" \u{203a} {}", self.section().title().to_uppercase()));
                }
                // A row cursor is another level and says so, because `enter` and
                // `esc` only mean anything once something is selected.
                if let Some(row) = self.cursors.get(i).map(|c| c.index).filter(|r| *r > 0) {
                    path.push_str(&format!(" \u{203a} ROW {}", row + 1));
                }
                path
            }
        }
    }

    pub fn footer(&self, width: usize) -> String {
        let sep = "   ";
        let mut items: Vec<&Binding> = self.visible();

        // The escape hatches, held back so they are never what gets cut.
        let mut kept: Vec<&Binding> = Vec::new();
        for key in ["?", "q"] {
            if let Some(i) = items.iter().position(|b| b.key == key) {
                kept.push(items.remove(i));
            }
        }

        let plain = |b: &Binding| b.key.len() + 1 + b.does.len();

        // Below about fifteen columns even the two held-back keys do not fit,
        // and the invariant that matters more than either of them is that this
        // line never wraps. `q` is the last to go: an operator who cannot see
        // how to leave will close the connection instead, and on a detached
        // session that leaves the machine running with nobody watching.
        while kept.len() > 1
            && kept.iter().map(|k| plain(k) + sep.len()).sum::<usize>() > width + sep.len()
        {
            kept.remove(0);
        }
        if let Some(k) = kept.first() {
            if plain(k) > width {
                kept.clear();
            }
        }

        let mut budget = width;
        for k in &kept {
            budget = budget.saturating_sub(plain(k) + sep.len());
        }

        let mut shown: Vec<&Binding> = Vec::new();
        let mut used = 0usize;
        for b in items {
            let cost = plain(b) + if shown.is_empty() { 0 } else { sep.len() };
            if used + cost > budget {
                break;
            }
            used += cost;
            shown.push(b);
        }
        shown.extend(kept);

        let painted: Vec<String> = shown
            .iter()
            .map(|b| format!("{} {}", style::amber(b.key), style::dim(b.does)))
            .collect();
        painted.join(style::dim(sep).as_str())
    }

    /// The sections, across the top, with the open one filled.
    ///
    /// Replaces the left rail on a detail screen. The rail cost twenty-two
    /// columns on every line of the pane beside it; a strip costs one line
    /// once, and still says where you are and what else there is.
    /// The rail: every part of the system, its state, and the key that opens it.
    ///
    /// `grouped` supplies the categories the manifest declares — About, Power,
    /// Network, Security, Workloads, System — so the terminal organises the
    /// system the same way the desktop menu does. Passing an empty grouping
    /// draws the flat rail, which is what happens on a machine where the
    /// manifest is not installed.
    pub fn strip(
        &self,
        states: &[(Pane, State)],
        grouped: &[(String, Vec<Pane>)],
        width: usize,
    ) -> String {
        let mut out = String::new();
        let draw = |out: &mut String, p: &Pane| {
            let i = Pane::ALL.iter().position(|x| x == p).unwrap_or(0);
            let st = states.iter().find(|(x, _)| x == p).map(|(_, s)| *s).unwrap_or(State::Unknown);
            let label = format!(" {} {} ", i + 1, p.title().to_uppercase());
            if Some(i) == self.detail {
                out.push_str(&style::bar(&label, st));
            } else {
                // The state glyph stays even when the section is not open, so a
                // fault elsewhere is visible from wherever you are.
                out.push_str(&format!(" {}{}", style::mark(st), style::dim(&label)));
            }
        };

        if grouped.is_empty() {
            for p in Pane::ALL.iter() {
                draw(&mut out, p);
            }
        } else {
            for (n, (_, panes)) in grouped.iter().enumerate() {
                if n > 0 {
                    // A separator rather than a heading. The category names
                    // would double the width of this line, and the grouping is
                    // legible from the gaps alone once the order is stable.
                    out.push_str(&style::dim("  \u{2502}"));
                }
                for p in panes {
                    draw(&mut out, p);
                }
            }
        }
        style::truncate(&out, width)
    }

}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn a_digit_jumps_straight_to_its_pane() {
        let mut ui = Ui::default();
        assert!(ui.on_key(Key::Char('4')));
        assert_eq!(ui.pane(), Pane::Network);
    }

    #[test]
    fn a_digit_past_the_end_does_nothing_rather_than_wrapping() {
        // Wrapping would move the operator somewhere they did not ask for, on a
        // screen they are reading to decide something.
        let mut ui = Ui::default();
        ui.on_key(Key::Char('2'));
        // One past however many panes there are — when there is such a digit.
        // With nine panes every digit names one, so there is nothing out of
        // range to press; the bound still holds and is asserted below rather
        // than by pressing a key that no longer exists.
        match char::from_digit(Pane::ALL.len() as u32 + 1, 10) {
            Some(past) => assert!(!ui.on_key(Key::Char(past))),
            None => assert!(
                Pane::ALL.len() == 9,
                "a tenth app cannot be reached by a digit and needs another way in"
            ),
        }
        // Digit two is the second app, whatever the second app happens to be.
        assert_eq!(ui.pane(), Pane::ALL[1]);
    }

    #[test]
    fn shift_tab_cycles_the_other_way() {
        // It exists only under the keyboard protocol. Cycling one way and not
        // the other is an asymmetry an operator meets every time they overshoot.
        let mut ui = bare();
        assert!(ui.on_key(Key::BackTab));
        assert_eq!(ui.focused, Pane::ALL.len() - 1);
        assert!(ui.on_key(Key::Tab));
        assert_eq!(ui.focused, 0);
    }

    #[test]
    fn j_and_k_move_through_a_list_not_through_the_panes() {
        // They used to cycle panes, which left no way to reach a row past the
        // bottom of the screen — the list was simply cut off there. Panes stay
        // one keystroke away on tab and on their own numbers.
        let mut ui = Ui::default();
        ui.on_key(Key::Char('j'));
        assert_eq!(ui.focused, 0, "j must not change pane");
        assert_eq!(ui.cursor().index, 1, "it moves down the list");
        ui.on_key(Key::Char('k'));
        assert_eq!(ui.cursor().index, 0);
        ui.on_key(Key::Char('k'));
        assert_eq!(ui.cursor().index, 0, "and stops at the top rather than wrapping");
    }

    #[test]
    fn each_pane_keeps_its_own_place_in_its_own_list() {
        // Leaving a section to check another and coming back to the top of a
        // forty-row list is how an operator loses the row they were reading.
        let mut ui = Ui::default();
        ui.on_key(Key::Char('j'));
        ui.on_key(Key::Char('j'));
        assert_eq!(ui.cursor().index, 2);
        ui.on_key(Key::Tab);
        assert_eq!(ui.cursor().index, 0, "a different pane, a different place");
        ui.on_key(Key::BackTab);
        assert_eq!(ui.cursor().index, 2, "and back where it was");
    }

    #[test]
    fn there_is_nothing_to_open_from_the_home_screen() {
        // Home shows every section at once and selects no row in any of them.
        // Opening "the selected resource" there would have to pick one.
        let mut ui = Ui::default();
        assert!(ui.detail.is_none());
        assert!(!ui.on_key(Key::Enter));
        assert!(!ui.zoom);
    }

    #[test]
    fn opening_a_resource_and_coming_back_out() {
        // One level down, and escape is the way up — the same key that leaves
        // everything else on this screen.
        let mut ui = Ui::default();
        ui.on_key(Key::Char('2'));
        assert!(!ui.zoom);
        assert!(ui.on_key(Key::Enter));
        assert!(ui.zoom, "enter opens the selected row");
        assert!(ui.on_key(Key::Escape));
        assert!(!ui.zoom, "escape closes it");
        assert!(ui.detail.is_some(), "and does not also leave the pane");
        assert!(ui.on_key(Key::Escape));
        assert!(ui.detail.is_none(), "a second escape goes home");
    }

    #[test]
    fn changing_pane_never_lands_already_opened() {
        // A pane that opened straight into somebody else's resource detail
        // would be reading one machine's row under another machine's heading.
        for k in [Key::Tab, Key::BackTab, Key::Char('3')] {
            let mut ui = Ui::default();
            ui.on_key(Key::Char('2'));
            ui.on_key(Key::Enter);
            assert!(ui.zoom);
            ui.on_key(k);
            assert!(!ui.zoom, "{k:?} must come back up first");
        }
    }

    #[test]
    fn the_footer_says_how_many_sections_there_actually_are() {
        // The label and the dispatch are two statements of one fact. This is
        // the test that keeps them agreeing, since a const cannot compute it.
        let label = BINDINGS
            .iter()
            .find(|b| b.does == "section")
            .expect("a binding for the numbered sections");
        assert_eq!(
            label.key,
            format!("1-{}", Pane::ALL.len()),
            "the advertised range must match the number of panes"
        );
    }

    #[test]
    fn the_same_key_means_different_things_in_different_contexts() {
        // The reason the footer can be trusted: `?` opens the key list and
        // then closes it.
        let mut ui = Ui::default();
        ui.on_key(Key::Char('?'));
        assert_eq!(ui.context, Context::Help);
        ui.on_key(Key::Char('?'));
        assert_eq!(ui.context, Context::Browsing);
    }

    #[test]
    fn navigation_does_nothing_while_the_key_list_is_open() {
        // Otherwise an operator reading the help scrolls the thing behind it and
        // comes back to a screen they did not leave.
        let mut ui = Ui::default();
        ui.on_key(Key::Char('?'));
        assert!(!ui.on_key(Key::Char('3')));
        assert_eq!(ui.focused, 0);
    }

    #[test]
    fn input_running_out_ends_the_session_rather_than_spinning() {
        // Only reachable when stdin is a pipe, where an empty read means end of
        // input forever. Treating it as "no key yet" burns a core until the
        // process is killed.
        let mut ui = Ui::default();
        assert!(ui.on_key(Key::Exhausted));
        assert!(!ui.running);
    }

    /// A console that believes it is inside a session, without being inside one.
    fn multiplexed() -> Ui {
        Ui { mux: Some(Mux::Screen), ..Ui::default() }
    }

    /// A console on a bare terminal, whatever this test is really running on.
    fn bare() -> Ui {
        Ui { mux: None, ..Ui::default() }
    }

    #[test]
    fn an_intent_is_taken_once_and_only_once() {
        // Taken rather than read: a request left set would spawn a second shell
        // the moment the operator exited the first.
        let mut ui = bare();
        assert!(ui.on_key(Key::Char('!')));
        assert_eq!(ui.take_intent(), Some(Intent::Shell));
        assert_eq!(ui.take_intent(), None, "the request must not survive being handled");
    }

    #[test]
    fn the_same_key_opens_a_screen_in_a_session_and_stands_aside_without_one() {
        // The difference the whole session module exists for: inside a session
        // the console keeps running while the shell opens elsewhere, so there is
        // nothing to switch between. Outside one there is nowhere else to put
        // it.
        let mut ui = multiplexed();
        ui.on_key(Key::Char('!'));
        assert_eq!(ui.take_intent(), Some(Intent::ScreenNew));

        let mut ui = bare();
        ui.on_key(Key::Char('!'));
        assert_eq!(ui.take_intent(), Some(Intent::Shell));
    }

    #[test]
    fn screen_keys_do_nothing_at_all_on_a_bare_terminal() {
        // And, more importantly, are not advertised. A footer offering `d
        // detach` on a machine with nothing to detach from is the exact failure
        // the binding table was built to prevent.
        let mut ui = bare();
        for k in ['n', 'p', 'd'] {
            assert!(!ui.on_key(Key::Char(k)), "{k} did something with no session");
            assert_eq!(ui.take_intent(), None);
        }
        let f = ui.footer(200);
        assert!(!f.contains("detach"), "footer advertises detaching: {f}");
        assert!(!f.contains("screens"));
    }

    #[test]
    fn screen_keys_are_advertised_and_work_inside_a_session() {
        let mut ui = multiplexed();
        for (k, want) in
            [('n', Intent::ScreenNext), ('p', Intent::ScreenPrev), ('d', Intent::Detach)]
        {
            assert!(ui.on_key(Key::Char(k)));
            assert_eq!(ui.take_intent(), Some(want));
        }
        let f = ui.footer(200);
        assert!(f.contains("detach") && f.contains("screens"), "got {f}");
    }

    #[test]
    fn the_footer_never_offers_both_shell_and_screen_at_once() {
        // Two bindings share `!`, distinguished only by whether there is a
        // session. Showing both would put the same key in the footer twice
        // meaning different things.
        for ui in [multiplexed(), bare()] {
            let n = ui.footer(200).matches('!').count();
            assert_eq!(n, 1, "`!` appears {n} times: {}", ui.footer(200));
        }
    }

    #[test]
    fn the_key_list_does_not_offer_a_shell_it_will_not_open() {
        // `!` is dispatched only while browsing, so the help context must not
        // advertise it — the footer's whole claim is that it never lies.
        let mut ui = Ui { context: Context::Help, ..Ui::default() };
        ui.on_key(Key::Char('!'));
        assert_eq!(ui.take_intent(), None);
        assert!(!BINDINGS.iter().any(|b| b.context == Context::Help && b.key == "!"));
    }

    #[test]
    fn a_notice_lasts_exactly_until_the_next_keypress() {
        // It belongs to the action that produced it. Left up, it becomes a line
        // the operator stops reading.
        let mut ui = multiplexed();
        ui.notice = Some("screen -X next: no such session".into());
        assert!(ui.on_key(Key::Char('z')), "clearing the notice is a redraw");
        assert!(ui.notice.is_none());
    }

    #[test]
    fn quit_works_from_every_context() {
        for setup in [Context::Browsing, Context::Help] {
            let mut ui = Ui { context: setup, ..Ui::default() };
            ui.on_key(Key::Char('q'));
            assert!(!ui.running, "q must work in {setup:?}");
        }
    }

    #[test]
    fn the_footer_only_advertises_keys_that_work() {
        // A footer promising a key that does nothing teaches an operator that
        // the display lies, which costs more than the missing key.
        //
        // Checked per configuration rather than over the whole table, because
        // half these keys need a session: `d` works inside one and is not
        // offered outside one, and a test that ignored the difference would
        // demand the wrong thing in both directions.
        for has_session in [true, false] {
            let fresh = || {
                if has_session {
                    multiplexed()
                } else {
                    bare()
                }
            };
            let advertised: Vec<char> = BINDINGS
                .iter()
                .filter(|b| b.context == Context::Browsing)
                .filter(|b| match b.needs {
                    Needs::Always => true,
                    Needs::Screens => has_session,
                    Needs::NoScreens => !has_session,
                    Needs::Detail => false,
                })
                .filter(|b| b.key.chars().count() == 1 && b.key != "q")
                .map(|b| b.key.chars().next().unwrap())
                .collect();

            for c in advertised {
                let mut ui = fresh();
                assert!(
                    ui.on_key(Key::Char(c)),
                    "with session={has_session}, the footer offers {c:?} and it does nothing"
                );
            }
        }
    }

    #[test]
    fn the_footer_fits_the_width_it_is_given() {
        // A wrapped footer costs a line of the pane above it and puts half a
        // binding at the start of the next line, where it reads as content. On
        // a display whose layout is the navigation model, this is the one line
        // that must not move.
        //
        // Found on node-a at 80 columns: with a session open there are eight
        // bindings and they did not fit.
        for w in [80usize, 60, 40, 24, 12] {
            for ui in [multiplexed(), bare()] {
                let f = strip(&ui.footer(w));
                assert!(f.chars().count() <= w, "at {w} columns the footer is {}: {f:?}", f.chars().count());
            }
        }
    }

    #[test]
    fn the_way_to_find_every_key_survives_the_narrowest_footer() {
        // A footer with room for one thing should spend it on the way to find
        // everything else, not on the first entry in the table.
        let ui = multiplexed();
        let f = strip(&ui.footer(20));
        assert!(f.contains('?'), "the key list is unreachable: {f:?}");
        assert!(f.contains('q'), "there is no visible way out: {f:?}");

        // Narrower than either pair fits: the no-wrap invariant wins, and `q`
        // is what is left.
        let f = strip(&ui.footer(8));
        assert!(f.chars().count() <= 8, "{f:?}");
        assert!(f.contains('q'), "the way out went before the key list: {f:?}");
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

    #[test]
    fn refreshing_advances_the_generation_rather_than_fetching_directly() {
        // So the draw loop and the input loop share one idea of freshness
        // instead of each keeping their own.
        let mut ui = Ui::default();
        let before = ui.generation;
        ui.on_key(Key::Char('r'));
        assert_eq!(ui.generation, before + 1);
    }

}

#[cfg(test)]
mod home_tests {
    use super::*;

    #[test]
    fn the_console_opens_on_the_whole_machine() {
        // The question an operator arrives with is "is this all right", and it
        // used to take seven keystrokes to answer.
        assert!(Ui::default().detail.is_none());
    }

    #[test]
    fn a_number_opens_a_section_and_zero_comes_back() {
        let mut ui = Ui { mux: None, ..Ui::default() };
        assert!(ui.on_key(Key::Char('3')));
        assert_eq!(ui.detail, Some(2));
        assert_eq!(ui.pane(), Pane::Power);
        assert!(ui.on_key(Key::Char('0')));
        assert!(ui.detail.is_none(), "0 returns to the whole machine");
    }

    #[test]
    fn escape_also_comes_home_but_only_from_a_section() {
        let mut ui = Ui { mux: None, ..Ui::default() };
        // At home there is nothing to escape from, and escape must not be
        // swallowed as though something happened.
        assert!(!ui.on_key(Key::Escape));
        ui.on_key(Key::Char('5'));
        assert!(ui.on_key(Key::Escape));
        assert!(ui.detail.is_none());
    }

    #[test]
    fn going_home_is_offered_only_when_there_is_somewhere_to_go() {
        let home = Ui { mux: None, ..Ui::default() };
        assert!(!home.footer(200).contains("home"), "offered at home: {}", home.footer(200));
        let mut deep = Ui { mux: None, ..Ui::default() };
        deep.on_key(Key::Char('2'));
        assert!(deep.footer(200).contains("home"), "not offered in a section");
    }

    #[test]
    fn the_strip_shows_a_fault_in_a_section_that_is_not_open() {
        // A fault elsewhere must be visible from wherever you are, or the whole
        // reason for a home screen is undone the moment somebody drills in.
        let mut ui = Ui { mux: None, ..Ui::default() };
        ui.on_key(Key::Char('1'));
        let strip = ui.strip(&[(Pane::Power, State::Fault)], &[], 200);
        assert!(strip.contains('■'), "the fault glyph is missing: {strip}");
    }
}
