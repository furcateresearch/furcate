//! One screen for the machine and the site it belongs to.
//!
//! Furcate knows what the hardware is doing — what it draws, how hot it is,
//! whether its disks are dying, who may change it. An operator holding a
//! terminal wants all of it at once, without knowing which command or which
//! address answers each question.
//!
//! Everything shown is read from the node and the site over HTTP, parsed for a
//! handful of known fields, range-checked, and displayed with its provenance —
//! a JSON number cannot carry an instruction, and a service that is not
//! answering shows a line saying so rather than stopping the screen.
//!
//! ## Why there is no TUI library
//!
//! Escape codes and a redraw loop. This runs over SSH on a machine somebody is
//! worried about, so it should have no dependencies that could fail to build on
//! an architecture the fleet later includes, and it should degrade to something
//! readable when the terminal is not what it expected.
//!
//! ## What it does not do
//!
//! It does not change anything. Every action Furcate can take requires an
//! operator signature over a nonced order, and a console that could bypass that
//! would be a hole in the authority model wearing a convenient shape. This
//! displays, and points at the commands that act.

mod grid;
pub mod extension;
mod session;
mod viz;
pub mod web;
pub mod style;
mod term;
mod ui;

use std::io::{Read, Write};
use std::time::Duration;

use style::{amber, dim, fault as red, measured as green};
use style::State;
use ui::{Intent, Pane, Ui};

const ESC: &str = "\x1b[";
const WIDTH: usize = 78;

fn clear() {
    print!("{ESC}2J{ESC}H");
}
fn at(row: u16, col: u16) {
    print!("{ESC}{row};{col}H");
}

/// A minimal HTTP GET.
///
/// Both services are on loopback and answer JSON. Anything that fails — refused
/// connection, timeout, malformed body — becomes `None`, because on this screen
/// "not running" and "not answering" are both just a line saying so, and an
/// operator looking at a machine they are worried about should not be shown a
/// stack trace.
fn get(addr: &str, path: &str, timeout_ms: u64) -> Option<serde_json::Value> {
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_millis(timeout_ms),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut body = String::new();
    stream.read_to_string(&mut body).ok()?;
    let json = body.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(json).ok()
}


/// Seconds as an operator reads them.
fn duration(n: u64) -> String {
    let (d, h, m) = (n / 86_400, (n % 86_400) / 3600, (n % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn s(v: &serde_json::Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return "—".into(),
        }
    }
    match cur {
        serde_json::Value::String(x) => x.clone(),
        serde_json::Value::Null => "—".into(),
        other => other.to_string(),
    }
}

fn num(v: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_f64()
}

/// The last few minutes of the rails that move.
///
/// The console fetches a snapshot and throws the previous one away, so every
/// figure on screen answers "what is it now" and none of them answers "which
/// way is it going" — which is the question an operator actually has when they
/// look at a power figure.
///
/// Short on purpose: this is a status screen, not a time-series database. The
/// site controller keeps the real history and forecasts from it.
#[derive(Default)]
struct History {
    wall_w: Vec<f64>,
}

impl History {
    /// Keep roughly ten minutes at the refresh interval, which is the span over
    /// which a machine's draw changing means something.
    const KEEP: usize = 150;

    fn observe(&mut self, snap: &Snapshot) {
        if let Some(e) = &snap.energy {
            if let Some(w) = num(e, &["power", "wall_w"]) {
                self.wall_w.push(w);
                if self.wall_w.len() > Self::KEEP {
                    self.wall_w.remove(0);
                }
            }
        }
    }
}

struct Addrs {
    node: String,
    site: String,
}

/// Where the machine says its own services are.
///
/// `/etc/furcate/env` is what the node and site units are configured from, so
/// it is the machine's own statement of where they listen. Reading it means the
/// console asks rather than assumes.
///
/// It has to be asked, because assuming was wrong: `furcated` on node-a binds
/// its overlay address and nothing else, so a console defaulting to loopback
/// reported "the node agent is not answering" while running on the same machine
/// as the node. A tool that says a service is down when it is up is worse than
/// one that says nothing.
///
/// Only addresses are read. The file holds no key material — that is the point
/// of it being world-readable — and on a machine where it is not readable, the
/// defaults still apply rather than the console failing.
fn declared(path: &std::path::Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(v) = line.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

impl Addrs {
    fn from_env() -> Self {
        Self::resolve(std::path::Path::new("/etc/furcate/env"))
    }

    /// The address of each service, most specific source first.
    ///
    /// An explicit variable is an operator pointing the console somewhere on
    /// purpose and always wins. Then the machine's own declaration. Then
    /// loopback, which is right on a machine that has not been configured yet
    /// and wrong on one that has — which is why it is last.
    fn resolve(env_file: &std::path::Path) -> Self {
        let from = |var: &str, keys: &[&str], fallback: &str| -> String {
            if let Ok(v) = std::env::var(var) {
                return v;
            }
            for k in keys {
                if let Some(v) = declared(env_file, k) {
                    return v;
                }
            }
            fallback.to_string()
        };

        Self {
            node: from("FURCATE_NODE_ADDR", &["FURCATE_LISTEN"], "127.0.0.1:7616"),
            // A machine running the site controller declares where it listens.
            // One that only reports to a site declares where that site is. Both
            // are the address this pane should read, so both are accepted, in
            // that order.
            site: from(
                "FURCATE_SITE_ADDR",
                &["FURCATE_SITE_LISTEN", "FURCATE_SITE"],
                "127.0.0.1:7617",
            ),
        }
    }
}

fn draw(a: &Addrs) {
    clear();
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "this machine".into());

    at(1, 1);
    println!("{}", style::banner(&host, None, WIDTH));

    let mut row = 3;
    // Filled while reading the machine, printed below it.
    let mut finding_rows: Vec<String> = Vec::new();

    // ---- the machine -------------------------------------------------------
    at(row, 1);
    println!("{}", style::section("machine", WIDTH));
    row += 1;

    match get(&a.node, "/healthz", 700) {
        None => {
            at(row, 3);
            // Not running and not answering look the same from here, and both
            // mean the same thing to somebody staring at this screen.
            println!("{}", dim("furcate node agent is not answering"));
            row += 1;
        }
        Some(h) => {
            at(row, 3);
            println!(
                "state {}   rung {}   chain {}",
                s(&h, &["state"]),
                s(&h, &["power_rung"]),
                s(&h, &["chain_length"])
            );
            row += 1;

            if let Some(hw) = get(&a.node, "/cooling", 700) {
                // The one expensive thing about this site belongs on the
                // screen somebody actually reads, not only on the pane they
                // would have to go looking for.
                let hardware = get(&a.node, "/hardware", 700);
                finding_rows = extension::get().insight(Some(&hw), hardware.as_ref());
                let fans: Vec<String> = hw
                    .get("fans")
                    .and_then(|f| f.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|f| f.get("rpm").and_then(|r| r.as_u64()))
                            .map(|r| r.to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let hottest = hw
                    .get("temperatures")
                    .and_then(|t| t.as_array())
                    .and_then(|arr| {
                        arr.iter().filter_map(|t| t.get("celsius").and_then(|c| c.as_i64())).max()
                    });
                at(row, 3);
                println!(
                    "hottest {}   fans {}",
                    hottest.map(|c| format!("{c} C")).unwrap_or_else(|| "—".into()),
                    if fans.is_empty() { "—".into() } else { fans.join(" ") }
                );
                row += 1;
            }

            if let Some(hostinfo) = get(&a.node, "/host", 900) {
                let readable = hostinfo.get("devices_readable") == Some(&serde_json::json!(true));
                let verdicts: Vec<String> = hostinfo
                    .get("devices")
                    .and_then(|d| d.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|d| {
                                let name = s(d, &["device", "name"]);
                                let v = d.get("verdict").map(|x| x.to_string()).unwrap_or_default();
                                let v = v.trim_matches('"').to_string();
                                if v.contains("healthy") {
                                    format!("{name} {}", green("ok"))
                                } else {
                                    format!("{name} {}", amber(&v))
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                at(row, 3);
                println!(
                    "disks {}",
                    if !readable {
                        dim("not readable")
                    } else if verdicts.is_empty() {
                        dim("none reported")
                    } else {
                        verdicts.join("  ")
                    }
                );
                row += 1;
            }
        }
    }

    // ---- what is worth doing about it --------------------------------------
    // Usually nothing, and then nothing is printed. A section that is always
    // present is one an operator stops reading.
    if !finding_rows.is_empty() {
        row += 1;
        for line in &finding_rows {
            at(row, 1);
            println!("{line}");
            row += 1;
        }
    }

    // ---- the site ----------------------------------------------------------
    row += 1;
    at(row, 1);
    println!("{}", style::section("site", WIDTH));
    row += 1;

    match get(&a.site, "/energy", 900) {
        None => {
            at(row, 3);
            println!("{}", dim("no site controller here — nodes run without one by design"));
            row += 1;
        }
        Some(e) => {
            let wall = num(&e, &["power", "wall_w"]);
            let basis = s(&e, &["power", "basis"]);
            at(row, 3);
            println!(
                "draw {}   basis {}",
                wall.map(|w| format!("{w:.0} W")).unwrap_or_else(|| "—".into()),
                // Whether a figure is measured or modelled is the most
                // important thing about it, so it sits beside the number
                // rather than in a footnote.
                if basis.contains("metered") { green("measured") } else { amber("modelled") }
            );
            row += 1;

            if let Some(cap) = get(&a.site, "/capacity", 900) {
                if let Some(t) = cap.get("tightest") {
                    let used = num(t, &["draw_w"]).unwrap_or(0.0);
                    let usable = num(t, &["usable_w"]);
                    at(row, 3);
                    println!(
                        "tightest {}   {}",
                        s(t, &["domain"]),
                        usable
                            .map(|u| {
                                let pct = used / u * 100.0;
                                let text = format!("{used:.0} of {u:.0} W  {pct:.0}%");
                                if pct > 80.0 { red(&text) } else { text }
                            })
                            .unwrap_or_else(|| dim("no rating declared"))
                    );
                    row += 1;
                }
            }

            if let Some(o) = get(&a.site, "/overlay", 900) {
                at(row, 3);
                println!(
                    "overlay {} peers published",
                    s(&o, &["published"])
                );
                row += 1;
            }
        }
    }

    row += 2;
    at(row, 1);
    println!("{}", style::rule(WIDTH));
    at(row + 1, 1);
    // This screen never changes anything, so it points at what does.
    println!(
        "{}",
        dim("READ ONLY   furcatectl acts   q quit   r refresh")
    );
    let _ = std::io::stdout().flush();
}

/// The console's entry point.
pub fn main() {
    // `web`: the browser terminal, a different program sharing this binary.
    let argv0: Vec<String> = std::env::args().collect();
    if argv0.get(1).map(String::as_str) == Some("web") {
        std::process::exit(web::main(&argv0[2..]));
    }
    let a = Addrs::from_env();

    // `--once` prints one screen and leaves. For a script, a log, or somebody
    // who wants the state and not an application.
    if std::env::args().any(|x| x == "--once") {
        draw(&a);
        println!();
        return;
    }

    // `--session` is how Furcate starts the console: inside a multiplexer
    // session it owns, so the operator gets screens for shells and the whole
    // thing survives the connection dropping. Falling back to a plain terminal
    // is deliberate — one screen is worth more than a message explaining there
    // could have been several.
    if std::env::args().any(|x| x == "--session") {
        if let Ok(exe) = std::env::current_exe() {
            // `enter` replaces this process when it succeeds, so returning at
            // all means it did not.
            let Err(why) = session::enter(&exe);
            eprintln!("{} {}", style::dim("furcate: one screen only —"), style::dim(&why));
        }
    }

    // The names, for anything that has to agree with this console about what
    // the parts are called — the desktop entries are generated from this rather
    // than from a second list somebody keeps in step by hand.
    if std::env::args().any(|x| x == "--panes") {
        for n in Pane::names() {
            println!("{n}");
        }
        return;
    }

    // `--pane NAME` opens on one capability instead of the overview.
    //
    // This is what makes each part of the system something a desktop can launch
    // on its own. The services are already separate — an agent, an overlay
    // manager, a power reader, an edge — and the console already has a view per
    // capability. Naming one on the command line is the missing third of that:
    // open the machine, open one part of it, or open several beside each other,
    // without any of them being a different program.
    let mut want: Option<Pane> = None;
    let argv: Vec<String> = std::env::args().collect();
    if let Some(i) = argv.iter().position(|x| x == "--pane") {
        match argv.get(i + 1).map(|s| s.as_str()) {
            Some(name) => match Pane::by_name(name) {
                Some(p) => want = Some(p),
                // Naming the alternatives rather than only the mistake: a
                // launcher entry with a stale name is fixed by knowing the
                // current ones.
                None => {
                    eprintln!("furcate: no pane called `{name}`");
                    eprintln!("try one of: {}", Pane::names().join(", "));
                    std::process::exit(2);
                }
            },
            None => {
                eprintln!("furcate: --pane needs a name");
                eprintln!("try one of: {}", Pane::names().join(", "));
                std::process::exit(2);
            }
        }
    }

    // Raw mode and the alternate screen, restored on every exit path including
    // a panic — a tool that leaves a terminal unusable has caused a second
    // fault on a machine somebody came to fix.
    let mut raw = Some(term::Raw::enter());
    let mut state = Ui::default();
    if let Some(p) = want {
        state.open(p);
    }
    let mut last_fetch = std::time::Instant::now();
    let mut snapshot = Snapshot::fetch(&a);
    let mut history = History::default();
    history.observe(&snapshot);
    let mut dirty = true;

    while state.running {
        if dirty {
            render(&mut state, &snapshot, &history);
            dirty = false;
        }

        // A tenth of a second, so a keypress feels immediate and an idle screen
        // costs nothing.
        if let Some(k) = term::key() {
            dirty = state.on_key(k);
        }

        if let Some(intent) = state.take_intent() {
            match intent {
                // No session to put a shell on, so the console gets out of the
                // way. Dropping the guard restores the terminal and leaves the
                // alternate screen, so the operator lands in the scrollback they
                // had before the console opened, with a real shell and their own
                // history — not an imitation of one.
                //
                // Taken rather than assigned away, so the restore happens here
                // and not at some point the optimiser chooses.
                Intent::Shell => {
                    drop(raw.take());
                    term::drain();
                    shell();
                    raw = Some(term::Raw::enter());
                }
                // The two things this screen can ask for. It does not do
                // either itself, and deliberately holds no key: it runs as
                // whoever opened it, and a screen left open on a rack is the
                // last thing that should carry authority to change a machine.
                //
                // So it hands the request to `furcatectl`, which can reach the
                // operator key sealed to this machine's TPM. That keeps one
                // implementation of key custody rather than a second one here,
                // and it means the console asks while something privileged
                // acts — the same shape as the actuator, one layer up.
                //
                // Raw mode goes first, because unsealing needs root and sudo
                // may want a password. A prompt drawn under a TUI that has the
                // terminal in raw mode is a prompt nobody can answer.
                other @ (Intent::RestartSelected | Intent::RevokeSelected | Intent::Submit) => {
                    let argv = match other {
                        Intent::RestartSelected => restart_argv(&snapshot, &state),
                        Intent::Submit => submit_argv(&snapshot, &state),
                        _ => revoke_argv(&addrs_site(&a), &snapshot, &state),
                    };
                    match argv {
                        Ok(argv) => {
                            drop(raw.take());
                            term::drain();
                            run_privileged(&argv);
                            raw = Some(term::Raw::enter());
                        }
                        Err(why) => state.notice = Some(why),
                    }
                    // The form goes whether it succeeded or not: it did what it
                    // was opened to do, and any failure is now on the notice
                    // line where the operator is already looking.
                    state.dialog = None;
                    state.context = ui::Context::Browsing;
                    state.generation += 1;
                }
                // Everything else is the session's business, and the console
                // keeps its own screen while it happens.
                other => {
                    if let Some(m) = state.mux {
                        let argv = match other {
                            Intent::ScreenNew => m.new_window_argv(
                                "shell",
                                &std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
                            ),
                            Intent::ScreenNext => m.next_argv(),
                            Intent::ScreenPrev => m.prev_argv(),
                            Intent::Detach => m.detach_argv(),
                            Intent::Shell
                            | Intent::RestartSelected
                            | Intent::RevokeSelected
                            | Intent::Submit => unreachable!("handled above"),
                        };
                        if let Err(e) = m.run(&argv) {
                            // Reported rather than swallowed: an operator who
                            // pressed a key and saw nothing will press it again,
                            // and then decide the console is broken.
                            state.notice = Some(e);
                        }
                    }
                }
            }
            // Whatever happened may have changed the machine.
            snapshot = Snapshot::fetch(&a);
            last_fetch = std::time::Instant::now();
            dirty = true;
        }

        // Refreshed on a timer or on demand, and the two share one path so the
        // display cannot end up showing a mixture of ages.
        let asked = state.generation;
        if last_fetch.elapsed() > Duration::from_secs(4) || asked != snapshot.generation {
            snapshot = Snapshot::fetch(&a);
            history.observe(&snapshot);
            snapshot.generation = asked;
            last_fetch = std::time::Instant::now();
            dirty = true;
        }
    }

    // Explicit, so the terminal is restored before anything this function
    // prints on the way out.
    drop(raw);
}

/// Hand the terminal to a login shell and wait for it to finish.
///
/// `$SHELL` rather than a fixed path: an operator's shell is theirs, and a tool
/// that dropped them into `sh` when they run `zsh` has made itself harder to
/// use in the moment they reached for it. The fallback is `/bin/sh`, which
/// exists on every system this will ever run on.
///
/// Interactive rather than a command runner. There is no way to type a command
/// into this screen and no plan to add one: a console with a command line is a
/// second place to act on the machine, and every Furcate action already goes
/// through a signed order. This gives an operator the shell they already know,
/// where `furcatectl` is on the path and does the acting.
fn shell() {
    let sh = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    println!("{}", style::dim("furcate: exit to return to the console"));
    let status = std::process::Command::new(&sh).status();
    if let Err(e) = status {
        // Reported rather than swallowed. An operator who pressed a key and got
        // nothing will press it again, and then conclude the console is broken.
        eprintln!("{} {sh}: {e}", style::fault("cannot start"));
        eprintln!("{}", style::dim("press enter to return to the console"));
        let mut _l = String::new();
        let _ = std::io::stdin().read_line(&mut _l);
    }
}

/// Everything the screen shows, read once per refresh.
///
/// Fetched as a set rather than per pane, so switching panes is instant and
/// every number on the screen is the same age. A display where the power figure
/// is four seconds older than the thermal one invites a comparison nobody
/// should make.
struct Snapshot {
    health: Option<serde_json::Value>,
    cooling: Option<serde_json::Value>,
    thermal: Option<serde_json::Value>,
    host: Option<serde_json::Value>,
    energy: Option<serde_json::Value>,
    capacity: Option<serde_json::Value>,
    overlay: Option<serde_json::Value>,
    policy: Option<serde_json::Value>,
    workloads: Option<serde_json::Value>,
    /// The boxes rented on this machine. A separate read from `workloads`
    /// because the two answer different questions: what this machine chose to
    /// run, and what somebody rented on it.
    boxes: Option<serde_json::Value>,
    fleet: Option<serde_json::Value>,
    roster: Option<serde_json::Value>,
    /// Grants and rules. A different endpoint from the decisions: `/policy`
    /// carries the authority, `/policy/decisions` carries what was done with
    /// it, and reading grants from the second one finds none however many
    /// exist — which is exactly what the first version of this pane did.
    grants: Option<serde_json::Value>,
    trust: Option<serde_json::Value>,
    hardware: Option<serde_json::Value>,
    netlink: Option<serde_json::Value>,
    image: Option<serde_json::Value>,
    resources: Option<serde_json::Value>,
    scheduler: Option<serde_json::Value>,
    custody: Option<serde_json::Value>,
    ledger: Option<serde_json::Value>,
    published: Option<serde_json::Value>,
    identity: Option<serde_json::Value>,
    models: Option<serde_json::Value>,
    administrator: Option<serde_json::Value>,
    keys: Option<serde_json::Value>,
    tunnels: Option<serde_json::Value>,
    lan: Option<serde_json::Value>,
    domains: Option<serde_json::Value>,
    /// Tenancy grants — distinct from `grants`, which is the site's authority.
    tenancy: Option<serde_json::Value>,
    bindings: Option<serde_json::Value>,
    proposals: Option<serde_json::Value>,
    generation: u64,
}

impl Snapshot {
    /// Nothing fetched. For tests, and for the moment before the first fetch.
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            health: None,
            cooling: None,
            thermal: None,
            host: None,
            energy: None,
            capacity: None,
            overlay: None,
            policy: None,
            workloads: None,
            boxes: None,
            fleet: None,
            roster: None,
            grants: None,
            trust: None,
            hardware: None,
            netlink: None,
            image: None,
            resources: None,
            scheduler: None,
            custody: None,
            ledger: None,
            published: None,
            identity: None,
            models: None,
            administrator: None,
            keys: None,
            tunnels: None,
            lan: None,
            domains: None,
            tenancy: None,
            bindings: None,
            proposals: None,
            generation: 0,
        }
    }

    fn fetch(a: &Addrs) -> Self {
        Self {
            health: get(&a.node, "/healthz", 700),
            cooling: get(&a.node, "/cooling", 700),
            thermal: get(&a.node, "/thermal", 700),
            host: get(&a.node, "/host", 900),
            energy: get(&a.site, "/energy", 900),
            capacity: get(&a.site, "/capacity", 900),
            overlay: get(&a.site, "/overlay", 900),
            policy: get(&a.site, "/policy/decisions", 900),
            // From this node, not the site: an operator standing at a machine
            // is asking what *this* machine is running. The site's aggregate
            // answers a different question and is a pane of its own to build.
            workloads: get(&a.node, "/workloads", 900),
            boxes: get(&a.node, "/box", 900),
            // The same subject at the site's distance. Fetched alongside rather
            // than instead: an operator switching scope should not wait for a
            // round trip, and a controller that is down must not take this
            // machine's own answer with it.
            fleet: get(&a.site, "/workloads", 900),
            // Who this site recognises, and what it has been asked to allow.
            // The pane showed decisions and nothing about the authority they
            // were decided against, so an operator could issue a grant and have
            // no way to see it on the screen they watch.
            roster: get(&a.site, "/roster", 900),
            grants: get(&a.site, "/policy", 900),
            trust: get(&a.site, "/trust", 900),
            // What this machine is. Fetched from the node rather than the site:
            // it is a fact about the box the operator is standing at.
            hardware: get(&a.node, "/hardware", 900),
            // The checks that run on their own and are only interesting when
            // they stop: a backup nobody verified, a task that has not
            // succeeded in a week, a machine whose boot no longer matches.
            custody: get(&a.node, "/custody", 900),
            // The tail, never the chain. This grows for the life of the node
            // and a console on a timer must not pull all of it — the summary
            // fields it needs are computed over the whole chain server-side.
            ledger: get(&a.node, "/ledger?tail=24", 900),
            // What this machine serves, who it is, and what it reasons with.
            // All three existed only as endpoints nothing looked at.
            published: get(&a.node, "/published", 900),
            identity: get(&a.node, "/identity", 900),
            models: get(&a.node, "/models", 900),
            keys: get(&a.node, "/keys", 900),
            tunnels: get(&a.node, "/tunnels", 900),
            lan: get(&a.node, "/lan", 900),
            domains: get(&a.node, "/domains", 900),
            tenancy: get(&a.node, "/grants", 900),
            bindings: get(&a.node, "/bindings", 900),
            scheduler: get(&a.node, "/scheduler", 900),
            resources: get(&a.node, "/resources", 900),
            image: get(&a.node, "/image", 900),
            netlink: get(&a.node, "/network", 900),
            proposals: get(&a.site, "/proposals", 900),
            // Who the site's own rule names, so the console can say whether the
            // machine this node reports to is the one that should have the job.
            administrator: get(&a.site, "/administrator", 900),
            generation: 0,
        }
    }

    /// The state of each pane, for the rail. Derived rather than stored, so the
    /// rail cannot disagree with the pane it points at.
    fn states(&self) -> Vec<(Pane, State)> {
        // Four states, and the difference between them is the whole reason the
        // rail is worth having: not answering, answering with nothing to say,
        // answering with something worth a look, and answering with a fault.
        let present = |v: &Option<serde_json::Value>| {
            if v.is_some() { State::Ok } else { State::Unknown }
        };

        // Fans at maximum against a cold machine is a cooling *control* fault,
        // and it is this site's actual one — so the rail says so without the
        // operator having to open the pane.
        let thermal = match &self.cooling {
            None => State::Unknown,
            Some(c) => {
                let faults = c.get("faults").and_then(|f| f.as_array()).map(|a| a.len()).unwrap_or(0);
                if faults > 0 { State::Fault } else { State::Ok }
            }
        };

        // A disk with a moving counter is not yet a fault and is not nothing.
        let storage = match &self.host {
            None => State::Unknown,
            Some(h) => {
                let bad = h
                    .get("devices")
                    .and_then(|d| d.as_array())
                    .map(|a| {
                        a.iter().any(|d| {
                            !d.get("verdict").map(|v| v.to_string()).unwrap_or_default().contains("healthy")
                        })
                    })
                    .unwrap_or(false);
                if bad { State::Warn } else { State::Ok }
            }
        };

        // An overlay with no peers is idle rather than broken: a node alone is
        // a supported state and should not be shown as an error.
        let overlay = match &self.overlay {
            None => State::Unknown,
            Some(o) => {
                if num(o, &["published"]).unwrap_or(0.0) > 0.0 { State::Ok } else { State::Idle }
            }
        };

        // What is running, and whether the picture is complete. A partial
        // inventory is reported as unknown rather than as good news: a source
        // that could not be read is not a machine with nothing on it.
        let workloads = match &self.workloads {
            None => State::Unknown,
            Some(w) if w.get("partial").and_then(|p| p.as_bool()).unwrap_or(false) => {
                State::Unknown
            }
            Some(w) => {
                let ws = w.get("workloads").and_then(|a| a.as_array());
                let degraded = |critical_only: bool| {
                    ws.map(|a| {
                        a.iter().any(|x| {
                            let broken = matches!(
                                x.get("state").and_then(|v| v.as_str()).unwrap_or(""),
                                "failed" | "restarting"
                            ) || x.get("health").and_then(|v| v.as_str())
                                == Some("self_reported_unhealthy");
                            let crit =
                                x.get("critical").and_then(|c| c.as_bool()).unwrap_or(false);
                            broken && (!critical_only || crit)
                        })
                    })
                    .unwrap_or(false)
                };
                // A declared load-bearing workload being down is the one thing
                // on this pane that needs a human; anything else is worth a
                // look. The distinction is the operator's own declaration.
                if degraded(true) {
                    State::Fault
                } else if degraded(false) {
                    State::Warn
                } else if ws.map(|a| a.is_empty()).unwrap_or(true) {
                    State::Idle
                } else {
                    State::Ok
                }
            }
        };

        vec![
            (Pane::Machine, present(&self.health)),
            (Pane::Power, present(&self.energy)),
            (Pane::Power, thermal),
            (Pane::Resources, storage),
            (Pane::Workloads, workloads),
            (Pane::Network, overlay),
            // The links out of this machine are what the connectivity pane is
            // about first; a node that cannot report them says so here.
            (Pane::Connectivity, present(&self.tunnels)),
            (Pane::Security, present(&self.policy)),
            // A check that has stopped checking is the fault this pane exists
            // for, so the rail says so without the operator opening it.
            (
                Pane::Management,
                // Findings are the point of this app, so a finding is what
                // makes its rail entry worth looking at.
                match &self.scheduler {
                    None => State::Unknown,
                    Some(_) => present(&self.health),
                },
            ),
            (
                Pane::System,
                match (&self.custody, &self.scheduler) {
                    (None, None) => State::Unknown,
                    (c, sc) => {
                        let bad = c
                            .as_ref()
                            .and_then(|c| c.get("kernel_faults").and_then(|a| a.as_array()))
                            .map(|a| !a.is_empty())
                            .unwrap_or(false);
                        let stalled = sc
                            .as_ref()
                            .and_then(|s| s.get("tasks").and_then(|a| a.as_array()))
                            .map(|ts| {
                                ts.iter().any(|t| {
                                    t.get("consecutive_failures")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0)
                                        > 0
                                })
                            })
                            .unwrap_or(false);
                        if bad {
                            State::Fault
                        } else if stalled {
                            State::Warn
                        } else {
                            State::Ok
                        }
                    }
                },
            ),
        ]
    }
}

/// Draw the whole screen.
/// The whole frame, as exactly `rows` lines, the last of which is the bottom bar.
///
/// Built as a vector rather than printed as it is computed. The version before
/// this printed a *variable* number of lines onto a screen it deliberately never
/// cleared — homing the cursor and erasing each line as it was written, to avoid
/// the flash a full clear causes. That works only while every frame is the same
/// height. Panes are not the same height, so moving from a long one to a short
/// one left the tail of the previous frame on screen, and the tail included its
/// bottom bar: **the bar stacked up two and three deep while navigating.**
///
/// A frame that is always exactly the height of the terminal cannot do that, and
/// the bar is genuinely in the one place that never moves rather than wherever
/// the content happened to end. The tests below assert both.
fn frame(
    state: &mut Ui,
    snap: &Snapshot,
    history: &History,
    cols: usize,
    rows: usize,
) -> Vec<String> {
    let w = cols.min(120);
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());

    // The chrome frames the content, not the terminal. On the home screen the
    // content is a fixed-width grid of panels, so a rule drawn to the terminal
    // width hangs past the block it belongs to -- ten columns of it at 120, and
    // twenty-six at 80. A detail screen does use the full width, so it keeps it.
    let chrome = match state.detail {
        None => grid::content_width(w),
        Some(_) => w,
    };

    let mut head = vec![style::banner(&host, state.mux, chrome), String::new()];

    // Everything below the content, built first because the content gets
    // whatever height is left over. Reserving after the fact is how a long help
    // block pushes the bar off the bottom of the screen.
    let mut tail = vec![String::new(), style::rule(chrome), String::new()];

    if state.context == ui::Context::Help {
        tail.push(style::amber_bright("KEYS"));
        tail.push(String::new());
        // Filtered exactly as the footer is. A key list is the one place an
        // operator goes to find out what is possible, so listing a binding this
        // session cannot perform is the worst place to do it.
        let has = state.mux.is_some();
        for b in ui::BINDINGS.iter().filter(|b| {
            b.context == ui::Context::Browsing
                && match b.needs {
                    ui::Needs::Always => true,
                    ui::Needs::Screens => has,
                    ui::Needs::NoScreens => !has,
                    ui::Needs::Detail => state.detail.is_some(),
                }
        }) {
            tail.push(format!("  {}  {}", style::amber(b.key), style::dim(b.does)));
        }
        tail.push(String::new());
        if let Some(m) = state.mux {
            // The way back in, on the screen an operator reads before walking
            // away from the terminal.
            tail.push(format!(
                "{} {}",
                style::dim("detached, get back with"),
                style::amber(m.reattach_hint())
            ));
        }
        tail.push(style::dim("this screen never changes the machine. furcatectl acts."));
        tail.push(String::new());
    }

    // A notice belongs above the footer, where the eye already is, and lasts
    // until the next keypress.
    if let Some(n) = &state.notice {
        tail.push(style::fault(n));
    }

    // The confirmation, naming what it will do. Named rather than "are you
    // sure": an operator confirming an unnamed action is confirming a habit,
    // and the one time it matters the cursor will have been somewhere else.
    // The form, over everything else. Drawn in the tail so it sits where the
    // confirmation does — an operator's eyes are already there.
    if let Some(d) = state.dialog.clone() {
        tail.push(style::subheading(d.deed.title()));
        tail.push(String::new());
        for (i, f) in d.fields.iter().enumerate() {
            let focused = i == d.focus;
            let shown = if f.value.is_empty() {
                // The hint, not a placeholder pretending to be a value. It says
                // what a valid answer looks like, which is the thing an operator
                // is actually missing when they stop and think.
                style::dim(f.hint)
            } else {
                style::measured(&f.value)
            };
            tail.push(format!(
                "  {} {}  {}{}",
                if focused { style::amber_bright("\u{25b8}") } else { style::dim(" ") },
                style::dim(&pad(f.label, 12)),
                shown,
                if focused { style::amber_bright("\u{2588}") } else { String::new() },
            ));
        }
        if let Some(why) = &d.error {
            tail.push(String::new());
            tail.push(style::warn(&format!("  {why}")));
        }
        tail.push(String::new());
        tail.push(style::dim("  tab moves   enter submits   esc cancels"));
    }

    if state.pending.is_some() {
        let on_workloads = state.detail.is_some() && state.pane() == Pane::Workloads;
        let what = snap
            .workloads
            .as_ref()
            .filter(|_| on_workloads)
            .map(workload_rows)
            .and_then(|rows| {
                rows.get(state.cursor().index)
                    .map(|r| (r.id.clone(), r.kind.clone(), r.critical))
            });
        tail.push(match what {
            Some((id, kind, _)) if kind == "pod" => style::warn(&format!(
                "{id} is a pod — kubernetes owns restarting it.  any key to dismiss"
            )),
            Some((id, _, critical)) => format!(
                "{} {} {}",
                style::warn("restart"),
                style::amber_bright(&id),
                if critical {
                    // The operator's own declaration, repeated at the moment it
                    // matters most.
                    style::fault("— declared load-bearing.  y to confirm, any other key to cancel")
                } else {
                    style::dim("?  y to confirm, any other key to cancel")
                }
            ),
            None => style::warn("nothing is selected.  any key to dismiss"),
        });
    }

    // The bottom bar: what the keys do on the left, what the machine is doing on
    // the right.
    //
    // A footer that only lists keys makes an operator look up to find out how
    // things are. Putting the state on the same line means the two questions —
    // "what can I press" and "is this machine all right" — are answered in one
    // place that never moves.
    let right = status_line(snap);
    let right_len = visible_len(&right);
    // The keys get whatever is left, and drop from the end if that is not much;
    // `?` and `q` are held back inside footer() so they are never what goes.
    // Where the operator is, then what they can press from here. The same key
    // means different things at different depths, so the depth goes first.
    let crumb = state.breadcrumb();
    let crumb_shown = format!("{} {} ", style::amber_bright(&crumb), style::dim("\u{203a}"));
    let crumb_len = visible_len(&crumb_shown);
    let left = state.footer(chrome.saturating_sub(right_len + crumb_len + 3));
    let left = format!("{crumb_shown}{left}");
    // To the block, like the rule above it: the status sits at the right edge of
    // the content, not at the right edge of the terminal, or the bar and the
    // rule disagree about where the screen ends.
    let gap = chrome.saturating_sub(visible_len(&left) + right_len);
    tail.push(format!("{left}{}{right}", " ".repeat(gap.max(1))));

    // What is left for the content, after the parts whose height is not
    // negotiable. At least one line: a terminal too short for the layout still
    // shows the machine rather than an empty screen.
    let budget = rows.saturating_sub(head.len() + tail.len()).max(1);

    // One window, for every screen. The pane says what is fixed and what is a
    // list; this decides how much of the list fits and which part of it to
    // show. Truncating instead — which is what this did — drops the row that
    // did not fit, and that row is as likely to be the broken one as any other.
    let content = match state.detail {
        // Home: every section at once. The question an operator arrives with is
        // "is this all right", and it used to take seven keystrokes to answer.
        None => Content::of(grid::render(&panels(snap), w)),
        // One section, full width, with a strip naming the others so the way
        // back is visible rather than remembered.
        Some(_) => {
            // The categories the manifest declares, so the rail groups the
            // system the same way the desktop menu does.
            // The rail is the apps themselves now — they are the categories,
            // so there is nothing left to group them into.
            let strip = state.strip(&snap.states(), &[], w);
            let pane = state.pane();
            let section = state.section();

            // The sections of this app, so the others do not disappear when one
            // is open. An operator who has to leave a screen to remember what
            // else is on it will stop looking.
            let mut bar = String::from("   ");
            for (n, sec) in pane.sections().iter().enumerate() {
                if n > 0 {
                    bar.push_str(&style::dim("  \u{b7}  "));
                }
                if *sec == section {
                    bar.push_str(&style::amber_bright(sec.title()));
                } else {
                    bar.push_str(&style::dim(sec.title()));
                }
            }
            let zoom = state.zoom;
            let cursor = state.cursor();
            let mut c = section_lines(section, snap, history, &cursor, w, zoom, state.fleet);
            // Only when there is a choice: a bar offering one thing is furniture.
            let mut fixed = if pane.sections().len() > 1 {
                vec![strip, bar, String::new()]
            } else {
                vec![strip, String::new()]
            };
            fixed.append(&mut c.fixed);
            Content { fixed, rows: c.rows }
        }
    };

    let mut cursor = state.cursor();
    // A position line only where there is something to be positioned in.
    let counted = content.rows.len() > budget.saturating_sub(content.fixed.len());
    let room = budget
        .saturating_sub(content.fixed.len() + usize::from(counted) * 2)
        .max(1);
    let window = cursor.window(content.rows.len(), room);
    let (above, below) = cursor.more(content.rows.len(), room);
    // Recorded so PageUp/PageDown move by a screenful of this pane rather than
    // by a constant that stops being true the moment a terminal is resized.
    state.page = room.max(1);
    *state.cursor_mut() = cursor;

    let mut body = content.fixed;
    body.extend(content.rows[window].iter().cloned());
    if counted {
        // Where the list continues. A list that just stops looks like the whole
        // list, which is how a fault on row 30 of 28 visible rows goes unread.
        let mut foot = format!("{} of {}", cursor.index + 1, content.rows.len());
        if above {
            foot.push_str("   ↑ more");
        }
        if below {
            foot.push_str("   ↓ more");
        }
        body.push(String::new());
        body.push(style::dim(&foot));
    }
    body.truncate(budget);
    // Pad to the budget so the bar lands on the last row whatever the pane is.
    body.resize(budget, String::new());

    head.extend(body);
    head.extend(tail);
    // A terminal shorter than the layout: keep the bar, drop from the middle.
    // The bar carries the machine's state, so it is the last thing to lose.
    if head.len() > rows {
        let bar = head.pop().expect("the tail always ends with the bar");
        head.truncate(rows.saturating_sub(1));
        head.push(bar);
    }
    head
}

fn render(state: &mut Ui, snap: &Snapshot, history: &History) {
    let (cols, rows) = term::size();

    // Home and erase each line as it is written, inside one synchronised
    // update — not a screen clear.
    //
    // `\x1b[2J` blanks the terminal and the new frame is painted into the gap,
    // which is a flash on every refresh and, on a slow link, a visibly empty
    // screen. Erasing to end-of-line as each row is drawn leaves no gap at all.
    //
    // BSU/ESU (`?2026`) asks the terminal to hold everything until the frame is
    // complete and show it at once. Terminals that do not know the sequence
    // ignore it, so it costs nothing to send and removes tearing where it is
    // understood.
    let mut out = String::from("\x1b[?2026h\x1b[H");
    let lines = frame(state, snap, history, cols, rows);
    let last = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        out.push_str("\x1b[K");
        out.push_str(line);
        // No newline on the last row. Writing one there scrolls the terminal by
        // a line, so the next frame's `\x1b[H` homes to a display that has
        // already shifted under it — another way old rows survive a repaint.
        //
        // `\n` alone, never `\r\n`. Raw mode here leaves `c_oflag` untouched, so
        // ONLCR is still on and the terminal turns the newline into a carriage
        // return and a line feed by itself. Sending the carriage return as well
        // gets it translated in turn and every line comes out doubled — which is
        // what the first version of this fix shipped.
        if i != last {
            out.push('\n');
        }
    }
    // Anything below the frame, for the moment after a terminal is made smaller.
    out.push_str("\x1b[J\x1b[?2026l");
    print!("{out}");
    let _ = std::io::stdout().flush();
}

/// Every section at once, as panels.
///
/// The same figures the detail screens show, cut to the three or four that
/// answer "is this all right". An operator who needs more presses the number.
fn panels(snap: &Snapshot) -> Vec<grid::Panel> {
    let states = snap.states();
    let st = |p: Pane| states.iter().find(|(x, _)| *x == p).map(|(_, v)| *v).unwrap_or(State::Unknown);
    let row = |k: &str, v: String| (k.to_string(), v);
    let none = || style::dim("—");

    let mut out = Vec::new();

    out.push(grid::Panel {
        title: "machine".into(),
        state: st(Pane::Machine),
        rows: match &snap.health {
            None => vec![row("agent", style::fault("not answering"))],
            Some(h) => vec![
                row("state", style::measured(&field(h, &["state"]))),
                row("rung", style::dim(&field(h, &["power_rung"]))),
                row("chain", style::measured(&field(h, &["chain_length"]))),
            ],
        },
    });

    out.push(grid::Panel {
        title: "power".into(),
        state: st(Pane::Power),
        rows: match &snap.energy {
            None => vec![row("site", none())],
            Some(e) => vec![
                row(
                    "draw",
                    num(e, &["power", "wall_w"])
                        .map(|w| format!("{}{}", style::measured(&format!("{w:.0}")), style::dim(" W")))
                        .unwrap_or_else(none),
                ),
                row("basis", style::dim(&s_field(e, &["power", "basis"]))),
                row("nodes", style::measured(&s_field(e, &["power", "metered_nodes"]))),
            ],
        },
    });

    // The home screen is every section at once, and workloads was the one
    // section it did not have — so a machine could be carrying a dead validator
    // while the screen an operator arrives at said nothing about it.
    out.push(grid::Panel {
        title: "workloads".into(),
        state: st(Pane::Workloads),
        rows: match &snap.workloads {
            None => vec![row("agent", none())],
            Some(w) => {
                let ws = w.get("workloads").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                let broken = ws
                    .iter()
                    .filter(|x| {
                        matches!(
                            x.get("state").and_then(|v| v.as_str()).unwrap_or(""),
                            "failed" | "restarting"
                        )
                    })
                    .count();
                let projects: std::collections::BTreeSet<&str> = ws
                    .iter()
                    .filter_map(|x| x.get("project").and_then(|p| p.as_str()))
                    .collect();
                vec![
                    row("running", style::measured(
                        &ws.iter()
                            .filter(|x| x.get("state").and_then(|v| v.as_str()) == Some("running"))
                            .count()
                            .to_string(),
                    )),
                    // Zero degraded is worth a line: it is the answer to the
                    // question, and a row that appears only when there is bad
                    // news reads as a screen that has stopped checking.
                    row("degraded", if broken > 0 {
                        style::fault(&broken.to_string())
                    } else {
                        style::measured("0")
                    }),
                    row("projects", style::measured(&projects.len().to_string())),
                    // An incomplete inventory is not a quiet machine, and the
                    // panel must not read as one.
                    row("source", if w.get("partial").and_then(|p| p.as_bool()).unwrap_or(false) {
                        style::warn("incomplete")
                    } else {
                        style::dim("complete")
                    }),
                ]
            }
        },
    });

    out.push(grid::Panel {
        title: "thermal".into(),
        state: st(Pane::Power),
        rows: match &snap.cooling {
            None => vec![row("bmc", none())],
            Some(c) => {
                let hottest = c
                    .get("temperatures")
                    .and_then(|t| t.as_array())
                    .and_then(|a| a.iter().filter_map(|x| num(x, &["celsius"])).fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v)))));
                let faults = c.get("faults").and_then(|f| f.as_array()).map(|a| a.len()).unwrap_or(0);
                vec![
                    row(
                        "hottest",
                        hottest
                            .map(|t| format!("{}{}", style::measured(&format!("{t:.0}")), style::dim(" C")))
                            .unwrap_or_else(none),
                    ),
                    row(
                        "faults",
                        if faults == 0 { style::dim("none") } else { style::fault(&faults.to_string()) },
                    ),
                ]
            }
        },
    });

    out.push(grid::Panel {
        title: "storage".into(),
        state: st(Pane::Resources),
        rows: match &snap.host {
            None => vec![row("disks", none())],
            Some(h) => {
                let disks = h.get("devices").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                if disks.is_empty() {
                    vec![row("disks", style::dim("not readable"))]
                } else {
                    disks
                        .iter()
                        .take(3)
                        .map(|d| {
                            let name = s(d, &["device", "name"]);
                            let label = if name == "—" { "disk".to_string() } else { name };
                            let v = s(d, &["verdict"]);
                            let shown = if v.eq_ignore_ascii_case("healthy") {
                                style::measured(&v)
                            } else {
                                style::warn(&v)
                            };
                            (label, shown)
                        })
                        .collect()
                }
            }
        },
    });

    out.push(grid::Panel {
        title: "private network".into(),
        state: st(Pane::Connectivity),
        rows: match &snap.overlay {
            None => vec![row("mesh", none())],
            Some(o) => {
                let mut rows = vec![row(
                    "peers",
                    style::measured(
                        &o.get("hints").and_then(|h| h.as_array()).map(|a| a.len()).unwrap_or(0).to_string(),
                    ),
                )];
                // A peer count on its own does not say who was allowed to
                // claim they belong here, and those are different machines on
                // a locked overlay than on an unlocked one.
                let lock = field(o, &["lock"]);
                rows.push(row(
                    "lock",
                    match lock.as_str() {
                        "locked" => style::measured(&lock),
                        "—" => none(),
                        // Not a fault — unlocked is a supported state — but it
                        // is never the state somebody should discover by
                        // reading the code.
                        _ => style::warn(&lock),
                    },
                ));
                // This machine's own standing. Shown always rather than only
                // when it is bad: a blank line here would be indistinguishable
                // from an overlay that has no lock, and the whole point is
                // that the lapse arrives without anybody acting.
                let auth = field(o, &["authorization"]);
                rows.push(row(
                    "auth",
                    match auth.as_str() {
                        "good" => style::measured(&auth),
                        "ending" => style::warn(&auth),
                        "lapsed" => style::fault(&auth),
                        _ => none(),
                    },
                ));
                rows
            }
        },
    });

    out.push(grid::Panel {
        title: "authority".into(),
        state: st(Pane::Security),
        rows: match &snap.policy {
            None => vec![row("site", none())],
            Some(p) => {
                let n = p.get("decisions").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0);
                vec![
                    row("recorded", style::measured(&n.to_string())),
                    row("refused", style::dim(&field(p, &["refused"]))),
                ]
            }
        },
    });

    out
}

/// A field as something a panel can show, never as JSON.
///
/// Values that look like scalars from the outside are not always scalars.
/// `basis` is an enum: the string "metered" when every node offers a measured
/// figure, and `{"scaled":{"factor_x100":200}}` when they do not — so a panel
/// that printed it straight showed `{"scaled":{"factor_x100…` on a real screen.
///
/// An externally tagged enum is its one key, and that key is the answer a human
/// wants: `scaled`. An array is its length. Anything else is left alone.
fn s_field(v: &serde_json::Value, path: &[&str]) -> String {
    let mut cur = v;
    for k in path {
        match cur.get(k) {
            Some(next) => cur = next,
            None => return "—".into(),
        }
    }
    scalar(cur)
}

/// One value, summarised to something that fits a panel.
fn scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(x) => x.clone(),
        serde_json::Value::Null => "—".into(),
        serde_json::Value::Array(a) => a.len().to_string(),
        serde_json::Value::Object(o) => {
            // An externally tagged enum: one key, and the key is the variant.
            if o.len() == 1 {
                o.keys().next().cloned().unwrap_or_else(|| "—".into())
            } else {
                // Several keys is a structure, not a value. Saying how many is
                // true; printing them is a panel full of punctuation.
                format!("{} fields", o.len())
            }
        }
        other => other.to_string(),
    }
}

/// The body of one pane, as lines.
///
/// Each pane answers one question and shows the figures that bear on it.
/// Provenance is carried by colour throughout — green is measured, plain is
/// computed — so an operator can tell what a number is worth without reading a
/// legend.
/// What a pane wants to draw, split by whether it scrolls.
///
/// The frame windows `rows` against the cursor and leaves `fixed` alone, so
/// every pane pages through one mechanism. The first version had the workloads
/// pane windowing its own rows while every other pane was simply truncated to
/// whatever fitted — two mechanisms for one job, and only one of them correct.
#[derive(Default)]
struct Content {
    /// A title, a column header, a warning. Always on screen.
    fixed: Vec<String>,
    /// The list. Whatever does not fit is reachable rather than dropped.
    rows: Vec<String>,
}

impl Content {
    fn of(lines: Vec<String>) -> Self {
        Self { fixed: Vec::new(), rows: lines }
    }

    /// Everything, in order. For tests, which care what a pane says rather
    /// than how the frame lays it out.
    #[cfg(test)]
    fn all(&self) -> Vec<String> {
        self.fixed.iter().chain(self.rows.iter()).cloned().collect()
    }
}

fn section_lines(
    pane: ui::Section,
    s: &Snapshot,
    history: &History,
    cursor: &ui::Cursor,
    width: usize,
    zoom: bool,
    fleet: bool,
) -> Content {
    let mut out = vec![style::subheading(pane.title()), String::new()];
    let miss = |what: &str| vec![style::dim(&format!("{what} is not answering"))];

    match pane {
        ui::Section::State => {
            match &s.health {
            None => out.extend(miss("the node agent")),
            Some(h) => {
                out.push(format!("{}  {}", style::dim("state "), field(h, &["state"])));
                out.push(format!("{}  {}", style::dim("rung  "), field(h, &["power_rung"])));
                out.push(format!("{}  {}", style::dim("chain "), field(h, &["chain_length"])));
                out.push(format!("{}  {}", style::dim("work  "), field(h, &["accepts_work"])));
                // What the machine is, and what it will not do. An operator
                // reading a fan at 19,200 RPM needs to know nothing here can
                // move it before they go looking for the control.
                if let Some(h) = &s.hardware {
                    out.push(String::new());
                    let model = h
                        .get("recognised")
                        .and_then(|r| r.get("Machine"))
                        .map(|m| s_field(m, &["product"]))
                        .filter(|p| !p.is_empty());
                    out.push(format!(
                        "{}  {}",
                        style::dim("model "),
                        match &model {
                            Some(p) => style::measured(p),
                            // Named, not blank: a machine nobody has described
                            // is a gap in the registry, and an operator can
                            // close it.
                            None => style::dim("not in the registry"),
                        }
                    ));
                    if model.is_some() {
                        let refuses: Vec<String> = h
                            .get("can")
                            .and_then(|c| c.as_object())
                            .map(|c| {
                                c.iter()
                                    .filter(|(_, v)| v.as_bool() == Some(false))
                                    .map(|(k, _)| k.replace('_', " "))
                                    .collect()
                            })
                            .unwrap_or_default();
                        out.push(format!(
                            "{}  {}",
                            style::dim("refuses"),
                            if refuses.is_empty() {
                                style::measured("nothing known")
                            } else {
                                // The useful half of a hardware profile. Worth
                                // more on screen than anything it can do.
                                style::warn(&refuses.join(", "))
                            }
                        ));
                    }
                }
                if let Some(e) = &s.energy {
                    out.push(String::new());
                    let w = num(e, &["power", "wall_w"]);
                    let metered = field(e, &["power", "basis"]).contains("metered");
                    out.push(format!(
                        "{}  {}",
                        style::dim("draw  "),
                        style::reading(&w.map(|x| format!("{x:.0}")).unwrap_or_else(|| "—".into()), " W", metered)
                    ));
                }
            }
            }
        }
        ui::Section::Placed if fleet => match &s.fleet {
            None => out.extend(miss("the site controller")),
            Some(f) => {
                let (header, rows) = fleet_lines(f, cursor, width, zoom);
                out.extend(header);
                return Content { fixed: out, rows };
            }
        },
        ui::Section::Boxes => match &s.boxes {
            // The daemon is disabled on node-c and that is the ordinary case
            // there, not a fault. The record is still readable with
            // `furcatectl box list`, and saying which is missing is the
            // difference between a gap somebody can close and one they cannot.
            None => out.extend(miss("the node agent")),
            Some(b) => {
                let items = b.get("boxes").and_then(|a| a.as_array());
                match items {
                    Some(items) if !items.is_empty() => {
                        for it in items {
                            // The boundary is named on every line, because a
                            // boundary quoted without its strength is the
                            // easiest mistake to make here and the person
                            // misled is the one who does not own the machine.
                            out.push(format!(
                                "{:<10} {:<9} {:<9} {:<9} {}",
                                field(it, &["id"]),
                                field(it, &["tenant"]),
                                field(it, &["size"]),
                                field(it, &["state"]),
                                style::dim(&field(it, &["runtime"])),
                            ));
                        }
                    }
                    // Said rather than left blank: "nothing rented here" and
                    // "this pane never loaded" must not look the same.
                    _ => out.push(style::dim("nothing is rented on this machine")),
                }
            }
        },
        ui::Section::Placed => match &s.workloads {
            None => out.extend(miss("the node agent")),
            Some(w) if zoom => out.extend(workload_detail(w, cursor.index)),
            Some(w) => {
                let (header, rows) = workload_lines(w, cursor, width);
                out.extend(header);
                return Content { fixed: out, rows };
            }
        },
        ui::Section::Draw => match &s.capacity {
            None => out.extend(miss("the site controller")),
            Some(c) => {
                // Sorted tightest first. A site average hides the one circuit
                // that is nearly full, and that circuit is the whole question.
                if let Some(ds) = c.get("domains").and_then(|d| d.as_array()) {
                    let mut rows: Vec<(f64, String)> = Vec::new();
                    for d in ds.iter() {
                        let used = num(d, &["draw_w"]).unwrap_or(0.0);
                        let usable = num(d, &["usable_w"]);
                        let name = field(d, &["domain"]);
                        match usable {
                            Some(u) if u > 0.0 => rows.push((
                                used / u,
                                format!("{:<11} {}", style::dim(&name), viz::gauge(used, u, " W", 18)),
                            )),
                            // An undeclared rating is not zero headroom. It is
                            // sorted last because it is not a measurement to
                            // compare, and drawn without a bar for the same
                            // reason.
                            _ => rows.push((
                                -1.0,
                                format!("{:<11} {}", style::dim(&name), viz::gauge(used, 0.0, " W", 18)),
                            )),
                        }
                    }
                    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
                    for (_, line) in rows.into_iter().take(8) {
                        out.push(line);
                    }

                    // Which way it is going. A single figure cannot say, and on
                    // a power reading that is usually the question.
                    if history.wall_w.len() > 1 {
                        out.push(String::new());
                        out.push(format!(
                            "{:<11} {}",
                            style::dim("site draw"),
                            viz::spark(&history.wall_w, 18)
                        ));
                    }
                }
            }
        },
        ui::Section::Cooling => match &s.cooling {
            None => out.extend(miss("the management controller")),
            Some(c) => {
                // The finding first, then the readings it was drawn from. An
                // operator who only reads the top of the pane still learns the
                // expensive thing about this site.
                out.extend(extension::get().insight(Some(c), s.hardware.as_ref()));
                if let Some(ts) = c.get("temperatures").and_then(|t| t.as_array()) {
                    for t in ts.iter().take(9) {
                        let deg = num(t, &["celsius"]).unwrap_or(0.0);
                        out.push(format!(
                            "{:<18} {}",
                            style::dim(&field(t, &["name"])),
                            style::reading(&format!("{deg:>3.0}"), " C", true)
                        ));
                    }
                }
                out.push(String::new());
                if let Some(fs) = c.get("fans").and_then(|f| f.as_array()) {
                    // Coloured from the daemon's own verdict rather than from a
                    // threshold repeated here. This used to read `r > 15000`,
                    // which is above the maximum speed of plenty of hardware --
                    // on a chassis whose fans top out near 9,200 RPM nothing
                    // could ever be coloured, so the pane showed a machine at
                    // full tilt as an ordinary row of numbers. The daemon now
                    // judges against the machine in front of it, and a console
                    // that re-derived the answer would disagree with it.
                    let control_fault = c
                        .get("faults")
                        .and_then(|f| f.as_array())
                        .is_some_and(|a| {
                            // Externally tagged: the variant is the key, as
                            // `{"running_hard_while_cold":{...}}`. Reading it
                            // as a `"fault"` field would simply never match, and
                            // the pane would quietly go back to showing a
                            // machine at full tilt as ordinary numbers.
                            a.iter()
                                .any(|f| f.get("running_hard_while_cold").is_some())
                        });
                    let rpms: Vec<String> = fs
                        .iter()
                        .filter_map(|f| f.get("rpm").and_then(|r| r.as_u64()))
                        // The control fault is about the cooling system rather
                        // than about one fan, so it colours the set.
                        .map(|r| {
                            if control_fault {
                                style::fault(&r.to_string())
                            } else {
                                style::measured(&r.to_string())
                            }
                        })
                        .collect();
                    out.push(format!("{}  {}", style::dim("fans"), rpms.join(" ")));
                }

                // What is being done about it, in the same pane as the reading
                // that prompted it. An operator asking why a machine is loud
                // should not have to find the answer somewhere else.
                if let Some(t) = &s.thermal {
                    out.push(String::new());
                    let env = t
                        .get("envelope")
                        .and_then(|e| e.get("envelope"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("unknown");
                    let disturbing = t.get("disturbing").and_then(|d| d.as_bool());
                    let where_ = t
                        .get("acoustics")
                        .and_then(|a| a.get("placement"))
                        .and_then(|p| p.as_str())
                        .unwrap_or("machine_room");
                    out.push(format!(
                        "{}  {}",
                        style::dim("envelope"),
                        style::measured(env)
                    ));
                    out.push(format!(
                        "{}  {}",
                        style::dim("placement"),
                        style::measured(where_)
                    ));
                    // Three-valued on purpose: an unsynchronised clock means no
                    // hour to judge by, and saying so beats implying the site
                    // is quiet.
                    out.push(format!(
                        "{}  {}",
                        style::dim("disturbing"),
                        match disturbing {
                            Some(true) => style::fault("yes"),
                            Some(false) => style::measured("no"),
                            None => style::dim("no local hour to judge by"),
                        }
                    ));
                    if let Some(absent) = t.get("absent").and_then(|a| a.as_array()) {
                        if !absent.is_empty() && t
                            .get("levers")
                            .and_then(|l| l.as_array())
                            .is_some_and(|l| l.is_empty())
                        {
                            out.push(style::dim(
                                "no lever on this machine can bound its draw",
                            ));
                        }
                    }
                }
            }
        },
        ui::Section::Storage => match &s.host {
            None => out.extend(miss("the node agent")),
            Some(h) => {
                if h.get("devices_readable") != Some(&serde_json::json!(true)) {
                    out.push(style::dim("device health is not readable on this machine"));
                }
                for d in h.get("devices").and_then(|d| d.as_array()).unwrap_or(&vec![]) {
                    let dev = d.get("device").cloned().unwrap_or_default();
                    let verdict = d.get("verdict").map(|v| v.to_string()).unwrap_or_default();
                    let verdict = verdict.trim_matches('"').to_string();
                    let healthy = verdict.contains("healthy");
                    out.push(format!(
                        "{} {:<12} {}",
                        style::mark(if healthy { State::Ok } else { State::Warn }),
                        style::dim(&field(&dev, &["name"])),
                        if healthy { style::measured(&verdict) } else { style::warn(&verdict) }
                    ));
                    out.push(format!(
                        "   {}  used {}  spare {}  hours {}",
                        style::dim(&field(&dev, &["model"])),
                        field(&dev, &["percentage_used"]),
                        field(&dev, &["available_spare"]),
                        field(&dev, &["power_on_hours"])
                    ));
                }
            }
        },
        ui::Section::PrivateNetwork => match &s.overlay {
            None => out.extend(miss("the coordinator")),
            Some(o) => {
                out.push(format!("{}  {}", style::dim("published"), field(o, &["published"])));
                out.push(String::new());
                for h in o.get("hints").and_then(|h| h.as_array()).unwrap_or(&vec![]) {
                    let id = field(h, &["node_id"]);
                    let short = id.chars().rev().take(12).collect::<String>().chars().rev().collect::<String>();
                    out.push(format!(
                        "{} {:<14} {:<10} {}",
                        style::mark(State::Ok),
                        style::dim(&short),
                        style::amber(&field(h, &["tier"])),
                        style::dim(&field(h, &["overlay_addr"]))
                    ));
                }
            }
        },
        ui::Section::Custody => {
            out.extend(custody_lines(s));
            out.push(String::new());
            out.extend(update_lines(s));
        }
        ui::Section::Authority => {
            match &s.policy {
                None => out.extend(miss("the site controller")),
                Some(p) => out.extend(authority_lines(p, s)),
            }
            out.push(String::new());
            out.extend(identity_lines(s));
        }
        ui::Section::Capacity => out.extend(capacity_lines(s)),
        ui::Section::Administration => out.extend(position_lines(s)),
        ui::Section::Published => out.extend(publishing_lines(s)),
        ui::Section::Identity => out.extend(identity_lines(s)),
        ui::Section::TheRecord => out.extend(record_lines(s)),
        ui::Section::Advisor => out.extend(advisor_lines(s)),
        ui::Section::Updates => out.extend(update_lines(s)),
        ui::Section::Keys => out.extend(keys_lines(s)),
        ui::Section::Tenants => out.extend(tenant_lines(s)),
        ui::Section::Bindings => out.extend(binding_lines(s)),
        ui::Section::Inference => out.extend(inference_lines(s)),
        ui::Section::Tunnels => out.extend(tunnel_lines(s)),
        ui::Section::Lan => out.extend(lan_lines(s)),
        ui::Section::Routing => out.extend(routing_lines(s)),
        ui::Section::Findings => out.extend(findings_lines(s)),
        ui::Section::Loops => out.extend(loop_lines(s)),
        ui::Section::Proposals => out.extend(proposal_lines(s)),
    }
    // The pane's own name stays put; everything under it scrolls. A title that
    // scrolls away leaves an operator reading a list with no heading.
    let rest = out.split_off(2.min(out.len()));
    Content { fixed: out, rows: rest }
}

/// The decision log, with consecutive identical decisions collapsed.
///
/// A control loop that finds nothing to do records `hold` every cycle, so an
/// uncollapsed log is eight lines all saying the same thing — and the line an
/// operator is looking for, the one time the loop did something or policy
/// refused it, is the line pushed off the bottom. Collapsing runs makes the
/// pane show a longer span in the same space and makes anything unusual the
/// only thing that stands out.
///
/// The count is shown rather than hidden: "held ×47" is a different claim from
/// "held once", and this system does not round one into the other.
fn collapse_decisions(ds: &[serde_json::Value], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let entries: Vec<&serde_json::Value> = ds.iter().rev().collect();

    while i < entries.len() && out.len() < limit {
        let d = entries[i];
        let Some(r) = d.get("request") else {
            i += 1;
            continue;
        };
        let allowed = d.get("decision").and_then(|x| x.get("allowed")) == Some(&serde_json::json!(true));
        let same = |o: &serde_json::Value| {
            o.get("request") == Some(r)
                && (o.get("decision").and_then(|x| x.get("allowed")) == Some(&serde_json::json!(true))) == allowed
        };

        let mut run = 1usize;
        while i + run < entries.len() && same(entries[i + run]) {
            run += 1;
        }

        // The newest of the run: what an operator means by "when did this last
        // happen".
        let at = d.get("at").and_then(|v| v.as_i64());
        let count = if run > 1 { format!(" {}", style::dim(&format!("x{run}"))) } else { String::new() };

        // The principal is recorded as `who via how` where the caller proved
        // itself — an operator signature, a machine's device key, an agent
        // token. Split here so the *how* shows as its own column: "operator"
        // says nothing about whether anybody checked, and after the fact that
        // is the thing somebody wants to know.
        let principal = field(r, &["principal"]);
        let (who, how) = match principal.split_once(" via ") {
            Some((w, h)) => (w.to_string(), h.to_string()),
            None => (principal, String::new()),
        };

        out.push(format!(
            "{} {} {:<10} {:<10} {:<9} {}{}",
            style::mark(if allowed { State::Ok } else { State::Warn }),
            style::dim(&clock(at)),
            style::dim(&who),
            style::amber(&field(r, &["action"])),
            // Dim, because it is provenance rather than the decision: present
            // when the caller was authenticated, blank on the older records
            // that predate anybody being asked.
            style::dim(&how),
            style::dim(&field(r, &["resource"])),
            count
        ));

        // A refusal is the reason the pane exists, so it says why. An
        // allowed decision does not: eight lines of "allowed by policy" is the
        // noise this function was written to remove.
        if !allowed {
            if let Some(why) = d.get("decision").and_then(|x| x.get("because")).and_then(|v| v.as_str()) {
                out.push(format!("    {}", style::warn(why)));
            }
        }

        i += run;
    }

    if out.is_empty() {
        out.push(style::dim("no decisions recorded").to_string());
    }
    out
}

/// Wall-clock time from a Unix timestamp, UTC.
///
/// UTC and labelled as such rather than local: the timestamp arrives from
/// another machine, and quietly rendering it in this machine's zone would
/// invent a correspondence between two clocks that has not been established.
fn clock(at: Option<i64>) -> String {
    let Some(t) = at else { return "--:--:--Z".into() };
    let s = t.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}Z", s / 3600, (s % 3600) / 60, s % 60)
}

/// What the machine is doing, in one line, for the right of the bottom bar.
///
/// Three things and no more: whether the agent is answering, which rung it is
/// on, and what the site is drawing. They are the three that change on their
/// own — everything else on this screen changes because somebody pressed a key.
fn status_line(s: &Snapshot) -> String {
    let mut parts: Vec<String> = Vec::new();

    match &s.health {
        None => parts.push(style::fault("● not answering")),
        Some(h) => {
            let st = field(h, &["state"]);
            let rung = field(h, &["power_rung"]);
            // The dot carries the state as shape and colour both, the same way
            // the rail does, so this reads without colour at all.
            let mark = if st == "active" { style::measured("●") } else { style::warn("▲") };
            parts.push(format!("{mark} {}", style::dim(&st)));
            if !rung.is_empty() && rung != "—" {
                let r = if rung == "nominal" { style::dim(&rung) } else { style::warn(&rung) };
                parts.push(r);
            }
        }
    }

    if let Some(e) = &s.energy {
        if let Some(w) = num(e, &["power", "wall_w"]) {
            parts.push(format!("{}{}", style::measured(&format!("{w:.0}")), style::dim(" W")));
        }
    }

    parts.join(&style::dim(" · "))
}


fn field(v: &serde_json::Value, path: &[&str]) -> String {
    s(v, path)
}

/// Characters a human sees, ignoring escape sequences.
fn visible_len(s: &str) -> usize {
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

#[cfg(test)]
mod authority_tests {
    use super::*;
    use serde_json::json;

    fn hold(at: i64) -> serde_json::Value {
        json!({"at": at, "decision": {"allowed": true, "because": "allowed by policy: doing nothing is always permitted"},
               "request": {"action": "hold", "principal": "loop", "resource": "site"}})
    }

    #[test]
    fn a_run_of_identical_decisions_becomes_one_line_with_its_count() {
        // The live site records `hold` every cycle. Eight lines all saying the
        // same thing push the one interesting line off the bottom of the pane.
        let ds: Vec<_> = (0..40).map(hold).collect();
        let rows = collapse_decisions(&ds, 8);
        assert_eq!(rows.len(), 1, "got {rows:#?}");
        assert!(rows[0].contains("x40"), "the count is shown, not hidden: {}", rows[0]);
    }

    #[test]
    fn something_different_is_never_collapsed_into_the_run_around_it() {
        // The whole point: the one cycle the loop acted must stay visible.
        let mut ds: Vec<_> = (0..20).map(hold).collect();
        ds.insert(10, json!({"at": 500, "decision": {"allowed": false, "because": "no signed operator order"},
                             "request": {"action": "shed", "principal": "loop", "resource": "rack-1"}}));
        let rows = collapse_decisions(&ds, 8);
        assert!(rows.iter().any(|r| r.contains("shed")), "the refusal vanished: {rows:#?}");
        assert!(rows.iter().any(|r| r.contains("no signed operator order")), "a refusal must say why");
    }

    #[test]
    fn an_allowed_decision_does_not_repeat_its_reason() {
        // Eight lines of "allowed by policy" is the noise this removes.
        let rows = collapse_decisions(&[hold(1)], 8);
        assert!(!rows.iter().any(|r| r.contains("always permitted")));
    }

    #[test]
    fn an_empty_log_says_so_rather_than_rendering_nothing() {
        // A blank pane reads as a broken display; "nobody looked" and "nothing
        // happened" are different claims.
        let rows = collapse_decisions(&[], 8);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("no decisions"));
    }

    #[test]
    fn a_missing_timestamp_renders_as_unknown_rather_than_the_epoch() {
        // Rendering a missing time as 00:00:00 would assert a fact.
        assert!(clock(None).starts_with("--"));
        // 1786796694 mod 86400 = 44694 s into the day = 12:24:54 UTC.
        assert_eq!(clock(Some(1_786_796_694)), "12:24:54Z");
    }
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    fn write(body: &str) -> std::path::PathBuf {
        // A path per test rather than a shared one, and no environment
        // variables: this codebase has raced itself on env-var tests three
        // times and now designs against it.
        // Named by a counter, not by the body: two tests whose bodies happen
        // to be the same length would otherwise share a file and race.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("furcate-console-{}-{n}.env", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn the_machines_own_declaration_beats_the_loopback_default() {
        // The defect this was written for: furcated on node-a binds its
        // overlay address and nothing else, so a console defaulting to loopback
        // reported the node as down while running on the same machine as it.
        let p = write("FURCATE_NODE_NAME=node-a\nFURCATE_LISTEN=192.0.2.28:7616\n");
        let a = Addrs::resolve(&p);
        assert_eq!(a.node, "192.0.2.28:7616");
    }

    #[test]
    fn a_machine_reporting_to_a_site_finds_it_and_one_hosting_it_prefers_its_own() {
        let reporting = write("FURCATE_SITE=192.0.2.11:7617\n");
        assert_eq!(Addrs::resolve(&reporting).site, "192.0.2.11:7617");

        let hosting = write("FURCATE_SITE_LISTEN=0.0.0.0:7617\nFURCATE_SITE=192.0.2.11:7617\n");
        assert_eq!(Addrs::resolve(&hosting).site, "0.0.0.0:7617");
    }

    #[test]
    fn an_unreadable_file_falls_back_rather_than_failing() {
        // /etc/furcate/env is root-only on node-b. A console that refused to
        // start there would be a console nobody could use on the machine that
        // needs it most.
        let a = Addrs::resolve(std::path::Path::new("/nonexistent/furcate/env"));
        assert_eq!(a.node, "127.0.0.1:7616");
        assert_eq!(a.site, "127.0.0.1:7617");
    }

    #[test]
    fn comments_and_blank_lines_are_not_values() {
        let p = write("# FURCATE_LISTEN=wrong.example:1\n\nFURCATE_LISTEN=right.example:7616\n");
        assert_eq!(Addrs::resolve(&p).node, "right.example:7616");
    }

    #[test]
    fn an_empty_declaration_is_not_a_declaration() {
        // systemd treats `KEY=` as clearing the value, and a console that read
        // it as an address would try to connect to the empty string.
        let p = write("FURCATE_LISTEN=\n");
        assert_eq!(Addrs::resolve(&p).node, "127.0.0.1:7616");
    }

    #[test]
    fn a_key_that_merely_starts_the_same_is_not_a_match() {
        let p = write("FURCATE_LISTEN_BACKUP=wrong.example:1\n");
        assert_eq!(Addrs::resolve(&p).node, "127.0.0.1:7616");
    }
}

#[cfg(test)]
mod panel_value_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_panel_never_prints_json() {
        // `basis` is an enum: the string "metered" when every node offers a
        // measured figure, and an object when they do not. The first version
        // printed `{"scaled":{"factor_x100…` onto a real screen.
        assert_eq!(scalar(&json!("metered")), "metered");
        assert_eq!(scalar(&json!({"scaled": {"factor_x100": 200}})), "scaled");
        for v in [
            json!({"scaled": {"factor_x100": 200}}),
            json!({"a": 1, "b": 2}),
            json!([1, 2, 3]),
            json!(null),
        ] {
            let out = scalar(&v);
            assert!(!out.contains('{') && !out.contains('['), "printed json: {out}");
        }
    }

    #[test]
    fn a_missing_path_says_so_rather_than_reading_as_a_value() {
        assert_eq!(s_field(&json!({"power": {}}), &["power", "basis"]), "—");
        assert_eq!(s_field(&json!({}), &["nothing", "here"]), "—");
    }

    #[test]
    fn a_list_is_its_length_because_that_is_what_fits() {
        assert_eq!(scalar(&json!(["a", "b"])), "2");
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use serde_json::json;

    fn snap_with(w: f64) -> Snapshot {
        Snapshot {
            energy: Some(json!({"power": {"wall_w": w}})),
            ..Snapshot::empty()
        }
    }

    #[test]
    fn a_rail_that_moves_is_remembered_long_enough_to_see_it_move() {
        // Every figure on screen answers "what is it now"; none answers "which
        // way is it going", which is the question an operator has when they
        // look at a power reading.
        let mut h = History::default();
        for w in [120.0, 124.0, 131.0] {
            h.observe(&snap_with(w));
        }
        assert_eq!(h.wall_w, vec![120.0, 124.0, 131.0]);
    }

    #[test]
    fn the_history_is_bounded() {
        // A status screen, not a time-series database. The site controller
        // keeps the real history and forecasts from it.
        let mut h = History::default();
        for i in 0..(History::KEEP + 50) {
            h.observe(&snap_with(i as f64));
        }
        assert_eq!(h.wall_w.len(), History::KEEP);
        // and it kept the newest, not the oldest
        assert_eq!(*h.wall_w.last().unwrap(), (History::KEEP + 49) as f64);
    }

    #[test]
    fn a_snapshot_without_a_reading_adds_nothing() {
        // A missing figure must not enter the series as a zero — a gap in the
        // data would be drawn as the machine dropping to nothing.
        let mut h = History::default();
        h.observe(&Snapshot::empty());
        h.observe(&snap_with(100.0));
        h.observe(&Snapshot::empty());
        assert_eq!(h.wall_w, vec![100.0]);
    }

    #[test]
    fn the_power_pane_shows_the_trend_once_there_is_one() {
        let mut h = History::default();
        let snap = Snapshot {
            capacity: Some(json!({"domains": [{"domain": "rack-1", "draw_w": 120.0, "usable_w": 960.0}]})),
            energy: Some(json!({"power": {"wall_w": 120.0}})),
            ..Snapshot::empty()
        };
        // One sample is a point, not a trend.
        h.observe(&snap);
        let one = section_lines(ui::Section::Draw, &snap, &h, &ui::Cursor::default(), 80, false, false).all().join("\n");
        assert!(!one.contains("site draw"), "one sample is not a trend");

        h.observe(&snap);
        let two = section_lines(ui::Section::Draw, &snap, &h, &ui::Cursor::default(), 80, false, false).all().join("\n");
        assert!(two.contains("site draw"), "two samples should draw one:\n{two}");
    }
}


#[cfg(test)]
mod frame_tests {
    use super::*;
    use serde_json::json;

    fn snap() -> Snapshot {
        Snapshot {
            capacity: Some(json!({"domains": [
                {"domain": "rack-1", "draw_w": 120.0, "usable_w": 960.0},
                {"domain": "ups-1", "draw_w": 120.0, "usable_w": 1200.0}
            ]})),
            energy: Some(json!({"power": {"wall_w": 120.0, "basis": "metered"}})),
            health: Some(json!({"state": "active", "power_rung": "nominal"})),
            ..Snapshot::empty()
        }
    }

    /// Every pane, on a range of terminal heights.
    fn every_shape() -> Vec<(Ui, usize)> {
        let mut out = Vec::new();
        for rows in [10usize, 24, 30, 50] {
            let mut home = Ui::default();
            home.detail = None;
            out.push((home, rows));
            for pane in 0..Pane::ALL.len() {
                let mut u = Ui::default();
                u.detail = Some(pane);
                u.focused = pane;
                out.push((u, rows));
            }
            let mut help = Ui::default();
            help.context = ui::Context::Help;
            out.push((help, rows));
            let mut noticed = Ui::default();
            noticed.notice = Some("something went wrong".into());
            out.push((noticed, rows));
        }
        out
    }

    #[test]
    fn a_frame_is_exactly_the_height_of_the_terminal() {
        // The whole bug in one assertion. A frame shorter than the screen leaves
        // the tail of the previous one behind, and the tail includes its bottom
        // bar — which is how the bar came to stack two and three deep while
        // moving between panes.
        let s = snap();
        let h = History::default();
        for (mut ui, rows) in every_shape() {
            let f = frame(&mut ui, &s, &h, 100, rows);
            assert_eq!(f.len(), rows, "detail {:?} at {rows} rows gave {}", ui.detail, f.len());
        }
    }

    #[test]
    fn the_bottom_bar_is_the_last_line_and_there_is_only_ever_one() {
        // It carries the machine's state, so it is the one thing that must be
        // in the same place on every screen.
        let s = snap();
        let h = History::default();
        for (mut ui, rows) in every_shape() {
            let f = frame(&mut ui, &s, &h, 100, rows);
            let bar = f.last().expect("a frame is never empty");
            assert!(!bar.trim().is_empty(), "the last line must be the bar, not padding");
            let same = f.iter().filter(|l| l == &bar).count();
            assert_eq!(same, 1, "the bar appears {same} times at {rows} rows");
        }
    }

    #[test]
    fn moving_between_panes_leaves_nothing_of_the_pane_before() {
        // The reported symptom, reproduced: a long pane followed by a short one.
        // Both frames are the full height, so the second fully overwrites the
        // first and nothing of it can survive.
        let s = snap();
        let h = History::default();
        let mut long = Ui::default();
        long.detail = Some(1); // Power
        let mut short = Ui::default();
        short.detail = Some(0); // Overview
        for rows in [24usize, 40] {
            let a = frame(&mut long, &s, &h, 100, rows);
            let b = frame(&mut short, &s, &h, 100, rows);
            assert_eq!(a.len(), b.len(), "two panes must paint the same number of rows");
            assert_eq!(a.len(), rows);
        }
    }

    #[test]
    fn a_terminal_too_short_for_the_layout_still_keeps_the_bar() {
        // Losing the machine's state is worse than losing a row of detail.
        let s = snap();
        let h = History::default();
        let mut ui = Ui::default();
        ui.context = ui::Context::Help;
        for rows in [3usize, 5, 8] {
            let f = frame(&mut ui, &s, &h, 100, rows);
            assert_eq!(f.len(), rows);
            assert!(!f.last().unwrap().trim().is_empty(), "the bar survives at {rows} rows");
        }
    }
}

/// One row of the workloads table, already flattened for paging.
///
/// Grouping by drawing a heading per project was the first shape, and it makes
/// the cursor's job ugly: a heading is not selectable, so every move has to
/// skip it and every page boundary has to know that. A project *column* groups
/// just as well to the eye, because the rows are sorted by it, and every row
/// stays selectable — which is what makes paging and Enter simple enough to be
/// correct.
struct WRow {
    project: String,
    id: String,
    kind: String,
    state: String,
    detail: String,
    broken: bool,
    critical: bool,
}

fn workload_rows(w: &serde_json::Value) -> Vec<WRow> {
    let mut rows: Vec<WRow> = w
        .get("workloads")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(|x| {
                    let st = s_field(x, &["state"]);
                    // The supervisor's own statement. A container that is not
                    // running while its policy says it should be is a fault
                    // however calmly Docker words it; one that finished a job
                    // is not, and the two are the same word without this.
                    let wanted = x.get("should_run").and_then(|v| v.as_bool());
                    let stopped_but_wanted = wanted == Some(true) && st == "stopped";
                    let restarts = x.get("recent_restarts").and_then(|v| v.as_u64());
                    let ports = x
                        .get("ports")
                        .and_then(|p| p.as_array())
                        .map(|p| {
                            p.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" ")
                        })
                        .unwrap_or_default();
                    // One column of context, whichever is worth the room. A
                    // restart that happened in this window outranks a port,
                    // because it is the thing that changed.
                    let stale = x.get("image_stale").and_then(|v| v.as_bool()) == Some(true);
                    let detail = match restarts {
                        // An update that looks applied and is not outranks a
                        // port: nothing else on the machine says so.
                        _ if stale => "running an older image than its tag".into(),
                        Some(n) if n > 0 => format!("{n} restarts this window"),
                        // Said in full, because "stopped" on its own reads as
                        // somebody's decision and this is the opposite.
                        _ if stopped_but_wanted => "should be running".into(),
                        _ if wanted == Some(false) && st == "stopped" => "finished".into(),
                        _ if !ports.is_empty() => ports,
                        _ => String::new(),
                    };
                    WRow {
                        // Unfiled is named, not blanked. A workload nobody has
                        // declared a project for is a gap in the site's
                        // description of itself, and an empty cell reads as a
                        // rendering fault rather than as a fact.
                        project: x
                            .get("project")
                            .and_then(|p| p.as_str())
                            .unwrap_or("unfiled")
                            .to_string(),
                        // A pod is one replica of something, with a suffix that
                        // changes on every rollout. Where the owning object is
                        // known, that is what an operator manages and what the
                        // row should say.
                        id: match x.get("owner") {
                            Some(o) if !o.is_null() => format!(
                                "{}/{}",
                                s_field(x, &["id"]).split('/').next().unwrap_or(""),
                                s_field(o, &["name"])
                            ),
                            _ => s_field(x, &["id"]),
                        },
                        kind: s_field(x, &["kind"]),
                        broken: matches!(st.as_str(), "failed" | "restarting")
                            || s_field(x, &["health"]) == "self_reported_unhealthy"
                            || stopped_but_wanted,
                        state: st,
                        detail,
                        critical: x.get("critical").and_then(|c| c.as_bool()).unwrap_or(false),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    // Broken first within a project, then by name. An operator opening this
    // screen during an incident should not have to scroll to find the fault.
    rows.sort_by(|a, b| {
        a.project
            .cmp(&b.project)
            .then(b.broken.cmp(&a.broken))
            .then(a.id.cmp(&b.id))
    });
    rows
}

/// One workload, in full.
///
/// The list shows what fits on a line; this shows what the node actually
/// reported. Fields it did not report are named as unreported rather than
/// omitted — a missing line reads as "there is nothing here" when the truth is
/// "nobody said", and those are the two answers this whole system exists to
/// keep apart.
fn workload_detail(w: &serde_json::Value, index: usize) -> Vec<String> {
    let items = w.get("workloads").and_then(|a| a.as_array());
    let rows = workload_rows(w);
    let Some(row) = rows.get(index) else {
        return vec![style::dim("nothing selected")];
    };
    // Back to the record itself, by the id the table sorted by — the table's
    // order is not the node's order and indexing the raw array would show a
    // different workload than the one under the cursor.
    let rec = items
        .and_then(|a| a.iter().find(|x| s_field(x, &["id"]) == row.id));
    let Some(rec) = rec else {
        return vec![style::dim("that workload is no longer reported")];
    };

    let field = |label: &str, v: String| {
        format!("{}  {}", style::dim(&pad(label, 16)), v)
    };
    let text = |k: &[&str]| {
        let v = s_field(rec, k);
        if v.is_empty() { style::dim("not reported") } else { style::measured(&v) }
    };

    let mut out = vec![
        style::amber_bright(&row.id),
        String::new(),
        field("project", if row.project == "unfiled" {
            // Actionable, and it names the fix. An operator who sees this can
            // put the workload where it belongs.
            style::dim("unfiled — declare it in FURCATE_PROJECTS")
        } else {
            style::measured(&row.project)
        }),
        field("kind", match rec.get("owner") {
            Some(o) if !o.is_null() => style::measured(&format!(
                "{} — {}",
                s_field(o, &["kind"]),
                s_field(rec, &["kind"])
            )),
            _ => text(&["kind"]),
        }),
        field("service", {
            let v = s_field(rec, &["service"]);
            if v.is_empty() { style::dim("not named by its deployment") } else { style::measured(&v) }
        }),
        field("supervisor wants", match rec.get("should_run").and_then(|v| v.as_bool()) {
            Some(true) => style::measured("it running"),
            Some(false) => style::dim("nothing — it runs when asked"),
            // A source that did not say is not a source that said no.
            None => style::dim("not stated"),
        }),
        field("supervised by", style::dim(match row.kind.as_str() {
            "unit" => "systemd",
            "container" => "docker",
            "pod" => "kubelet",
            _ => "not reported",
        })),
        field("state", if row.broken {
            style::fault(&row.state)
        } else {
            style::measured(&row.state)
        }),
        field("health", text(&["health"])),
        field("critical", if row.critical {
            style::amber_bright("declared load-bearing")
        } else {
            style::dim("not declared")
        }),
    ];

    // Restarts, with the lifetime and the window kept apart. A container that
    // has survived six host reboots carries six restarts forever; that is not
    // the same fact as three restarts in the last minute, and a screen that
    // shows one number cannot tell an operator which one they are reading.
    let lifetime = rec.get("restarts").and_then(|v| v.as_u64());
    let recent = rec.get("recent_restarts").and_then(|v| v.as_u64());
    out.push(field(
        "restarts",
        match lifetime {
            Some(n) => style::measured(&format!("{n} over its whole life")),
            None => style::dim("not reported"),
        },
    ));
    out.push(field(
        "this window",
        match recent {
            Some(n) if n > 0 => style::warn(&format!("{n}")),
            Some(_) => style::measured("0"),
            // First sight of a lifetime counter says nothing about a rate.
            None => style::dim("no previous reading to compare"),
        },
    ));
    if let Some(secs) = rec.get("since_s").and_then(|v| v.as_u64()) {
        out.push(field("in this state", style::measured(&duration(secs))));
    }

    // What it runs, and whether that is what the tag now means.
    let img = s_field(rec, &["image"]);
    if !img.is_empty() {
        out.push(field("image", style::measured(&img)));
        if rec.get("image_stale").and_then(|v| v.as_bool()) == Some(true) {
            out.push(field(
                "",
                style::warn("this tag points at a newer image — pulled, never restarted into"),
            ));
        }
    }

    // Bounded or not. `furcate-resource` asks this of every cgroup on the
    // machine; here it is answered for the workload an operator is looking at.
    out.push(field(
        "memory limit",
        match rec.get("memory_limit_bytes").and_then(|v| v.as_u64()) {
            Some(b) => style::measured(&format!("{:.1} GiB", b as f64 / 1_073_741_824.0)),
            // Not "no limit": nobody declared one, and on this fleet that has
            // meant a database growing until the machine noticed.
            None => style::warn("none declared"),
        },
    ));
    out.push(field(
        "cpu limit",
        match rec.get("cpu_limit").and_then(|v| v.as_f64()) {
            Some(c) => style::measured(&format!("{c:.2} cores")),
            None => style::dim("none declared"),
        },
    ));

    let ports: Vec<String> = rec
        .get("ports")
        .and_then(|p| p.as_array())
        .map(|p| p.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default();
    out.push(field(
        "ports",
        if ports.is_empty() {
            // Not "none open" — the supervisor was not asked, or does not say.
            style::dim("none reported")
        } else {
            style::measured(&ports.join("  "))
        },
    ));

    out.push(String::new());
    out.push(style::dim("this screen never changes the machine. furcatectl acts."));
    out
}

/// The workloads table: what this machine is running, filed by project.
fn workload_lines(
    w: &serde_json::Value,
    cursor: &ui::Cursor,
    width: usize,
) -> (Vec<String>, Vec<String>) {
    let rows = workload_rows(w);
    let mut out = Vec::new();

    // An inventory missing a source is not an empty one, and the difference
    // decides whether a quiet screen means a quiet machine.
    if w.get("partial").and_then(|p| p.as_bool()).unwrap_or(false) {
        out.push(style::warn("one source could not be read — this list is incomplete"));
        out.push(String::new());
    }
    if rows.is_empty() {
        out.push(style::dim("nothing reported"));
        return (out, Vec::new());
    }

    // The columns that have a known shape take a fixed width; the two that
    // hold names take what is left, because a project called `orchid-mainnet`
    // truncated to `orchid-mai…` is indistinguishable from `orchid-devnet`
    // truncated the same way — which is worse than a narrow screen.
    let (proj_w, kind_w, state_w) = (14usize, 10usize, 11usize);
    let fixed = 1 + proj_w + 2 + 2 + kind_w + 2 + state_w + 2;
    // Names first, detail with whatever is left over: an operator can work out
    // a port from elsewhere, and cannot work out which container this is.
    let name_w = width.saturating_sub(fixed + 10).clamp(16, 40);
    let detail_w = width.saturating_sub(fixed + name_w).min(30);

    out.push(format!(
        " {}  {}  {}  {}  {}",
        style::dim(&pad("PROJECT", proj_w)),
        style::dim(&pad("NAME", name_w)),
        style::dim(&pad("KIND", kind_w)),
        style::dim(&pad("STATE", state_w)),
        style::dim("DETAIL")
    ));

    let mut lines = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        let selected = i == cursor.index;
        let state = if r.broken {
            style::fault(&pad(&r.state, state_w))
        } else if r.state == "running" {
            style::measured(&pad(&r.state, state_w))
        } else {
            style::dim(&pad(&r.state, state_w))
        };
        // The marker, not a colour, says which row is selected: this has to
        // read on a monochrome console and to somebody who cannot separate the
        // highlight from the ground.
        let mark = if selected { style::amber("▸") } else { " ".into() };
        let name = if r.critical {
            // Declared load-bearing. Marked on the row rather than in a legend,
            // because the legend is not on screen during an incident.
            style::amber_bright(&pad(&format!("{} *", r.id), name_w))
        } else {
            style::measured(&pad(&r.id, name_w))
        };
        lines.push(format!(
            "{mark}{}  {}  {}  {}  {}",
            style::dim(&pad(&r.project, proj_w)),
            name,
            style::dim(&pad(&r.kind, kind_w)),
            state,
            style::dim(&style::truncate(&r.detail, detail_w))
        ));
    }
    (out, lines)
}

/// Pad to a display width, counting columns rather than bytes.
fn pad(s: &str, w: usize) -> String {
    let len = visible_len(s);
    if len >= w {
        return style::truncate(s, w);
    }
    format!("{s}{}", " ".repeat(w - len))
}


#[cfg(test)]
pub mod workload_tests {
    use super::*;
    use serde_json::json;

    /// Header and rows together, for tests that only care what the pane says.
    pub fn both(w: &serde_json::Value, c: &ui::Cursor, width: usize) -> String {
        let (h, r) = workload_lines(w, c, width);
        h.into_iter().chain(r).collect::<Vec<_>>().join("\n")
    }

    pub fn rows_of(w: &serde_json::Value, c: &ui::Cursor, width: usize) -> Vec<String> {
        workload_lines(w, c, width).1
    }

    /// The whole screen, as an operator would see it.
    fn screen(w: &serde_json::Value, index: usize, rows: usize) -> String {
        let snap = Snapshot { workloads: Some(w.clone()), ..Snapshot::empty() };
        let mut ui = Ui::default();
        // Open the workloads app by name rather than by digit, so the test
        // survives the apps being reordered.
        let i = Pane::ALL.iter().position(|p| *p == Pane::Workloads).expect("workloads exists");
        ui.on_key(term::Key::Char(char::from_digit(i as u32 + 1, 10).expect("a digit")));
        ui.cursor_mut().index = index;
        frame(&mut ui, &snap, &History::default(), 110, rows).join("\n")
    }

    fn inv(n: usize) -> serde_json::Value {
        json!({
            "partial": false,
            "workloads": (0..n).map(|i| json!({
                "id": format!("w{i:02}"),
                "kind": "container",
                "state": if i == 7 { "failed" } else { "running" },
                "health": "none_declared",
                "restarts": 3,
                "recent_restarts": 0,
                "critical": i == 2,
                "project": if i % 2 == 0 { serde_json::Value::from("orchid") } else { serde_json::Value::Null },
                "ports": ["5001->5001/tcp"],
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn a_list_longer_than_the_screen_is_paged_not_truncated() {
        // The bug this replaces: the pane drew what fitted and dropped the
        // rest, so a fault on row 30 of a 12-row screen was invisible and the
        // machine looked healthy.
        let w = inv(40);
        let top = screen(&w, 0, 24);
        assert!(top.contains("w00"), "the first page shows the first rows");
        assert!(top.contains("↓ more"), "and says there are more:\n{top}");

        let bottom = screen(&w, 39, 24);
        assert!(bottom.contains("w39"), "the last row is reachable:\n{bottom}");
        assert!(bottom.contains("↑ more"));
        assert!(!bottom.contains("↓ more"), "nothing below the end");
    }

    #[test]
    fn the_count_says_where_in_the_list_the_operator_is() {
        assert!(screen(&inv(40), 12, 24).contains("13 of 40"));
    }

    #[test]
    fn a_list_that_fits_is_not_given_a_position_line() {
        // "3 of 3" under three rows is noise. The count earns its line only
        // when part of the list is off screen.
        let out = screen(&inv(3), 0, 40);
        assert!(!out.contains(" of 3"), "{out}");
        assert!(!out.contains("more"));
    }

    #[test]
    fn the_pane_title_does_not_scroll_away() {
        // A list with no heading is a list an operator has to remember the
        // shape of.
        for index in [0usize, 20, 39] {
            let out = screen(&inv(40), index, 24);
            assert!(out.contains("WORKLOADS"), "at row {index}:\n{out}");
            assert!(out.contains("PROJECT"), "the column header stays too");
        }
    }

    #[test]
    fn a_cursor_does_not_wrap_or_run_past_the_end() {
        // Wrapping is right for a ring of panes and wrong for a list: an
        // operator holding j to reach the bottom would arrive back at the top
        // and read the same faults twice believing there were more.
        //
        // The key handler moves the index freely — it cannot know how long the
        // list is — so this is the clamp that matters, and it is the only one.
        let mut c = ui::Cursor { index: usize::MAX, top: 0 };
        let w = c.window(40, 10);
        assert_eq!(c.index, 39, "G lands on the last row, not past it");
        assert_eq!(w, 30..40);
    }

    #[test]
    fn an_empty_list_never_panics_and_never_claims_a_row() {
        let mut c = ui::Cursor { index: 9, top: 5 };
        assert_eq!(c.window(0, 10), 0..0);
        let out = workload_lines(&json!({"workloads": [], "partial": false}), &c, 100).0;
        assert!(out.join("\n").contains("nothing reported"));
    }

    #[test]
    fn a_list_that_shrinks_does_not_leave_the_window_past_its_end() {
        // Workloads come and go between refreshes. A window left where a longer
        // list put it draws blank rows and reads as a machine that lost them.
        let mut c = ui::Cursor { index: 38, top: 30 };
        let _ = c.window(40, 10);
        let w = c.window(5, 10);
        assert!(w.end <= 5, "window {w:?} past the end of a 5-row list");
        assert!(c.index < 5, "the selection came back with it");
    }

    #[test]
    fn an_unfiled_workload_is_named_rather_than_blanked() {
        // A blank cell reads as a rendering fault. "unfiled" is a fact about
        // the site's own description of itself.
        let w = inv(4);
        let c = ui::Cursor::default();
        let out = both(&w, &c, 100);
        assert!(out.contains("unfiled"), "{out}");
    }

    #[test]
    fn what_is_broken_sorts_above_what_is_not() {
        // An operator opening this during an incident should not have to page
        // to find the fault.
        let rows = workload_rows(&inv(10));
        let orchid: Vec<&WRow> = rows.iter().filter(|r| r.project == "orchid").collect();
        assert!(!orchid.is_empty());
        let first_ok = orchid.iter().position(|r| !r.broken).unwrap_or(0);
        assert!(
            orchid.iter().take(first_ok).all(|r| r.broken),
            "broken rows must come first within a project"
        );
    }

    #[test]
    fn opening_one_shows_what_the_line_had_no_room_for() {
        let w = inv(5);
        let out = workload_detail(&w, 0).join("\n");
        assert!(out.contains("ports"), "{out}");
        assert!(out.contains("5001"), "{out}");
        assert!(out.contains("whole life"), "lifetime restarts are labelled as such");
        assert!(out.contains("this window"), "and kept apart from the rate");
    }

    #[test]
    fn opening_a_row_that_has_gone_says_so_rather_than_showing_another() {
        // The table is sorted; the raw array is not. Indexing the array would
        // quietly show a different workload than the one under the cursor.
        let out = workload_detail(&inv(3), 99).join("\n");
        assert!(out.contains("nothing selected"), "{out}");
    }

    #[test]
    fn a_partial_inventory_says_so_before_it_lists_anything() {
        // A missing source is not an empty one, and the difference decides
        // whether a quiet screen means a quiet machine.
        let mut w = inv(3);
        w["partial"] = json!(true);
        let c = ui::Cursor::default();
        let out = both(&w, &c, 100);
        assert!(out.contains("incomplete"), "{out}");
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use super::workload_tests::{both, rows_of};
    use serde_json::json;

    fn two_projects() -> serde_json::Value {
        json!({"partial": false, "workloads": [
            {"id": "mainnet-participant-1", "kind": "container", "state": "running",
             "health": "none_declared", "restarts": 0, "critical": true,
             "project": "orchid-mainnet", "ports": ["5001-5002/tcp"]},
            {"id": "sentry-validator-participant-1", "kind": "container", "state": "running",
             "health": "none_declared", "restarts": 0, "critical": false,
             "project": "orchid-devnet", "ports": []}
        ]})
    }

    #[test]
    fn two_projects_that_share_a_prefix_stay_distinguishable() {
        // `orchid-mainnet` and `orchid-devnet` both truncate to `orchid-…`,
        // and two rows that read identically are worse than a narrow screen —
        // an operator cannot tell which validator they are looking at.
        let c = ui::Cursor::default();
        let out = both(&two_projects(), &c, 110);
        assert!(out.contains("orchid-mainnet"), "{out}");
        assert!(out.contains("orchid-devnet"), "{out}");
    }

    #[test]
    fn every_row_fits_the_terminal_it_was_drawn_for() {
        // A row wider than the terminal wraps, and one wrapped row pushes every
        // row below it out of alignment for the rest of the screen.
        for width in [80usize, 100, 120] {
            let c = ui::Cursor::default();
            for line in rows_of(&two_projects(), &c, width) {
                assert!(
                    visible_len(&line) <= width,
                    "a {}-column row on a {width}-column terminal: {line:?}",
                    visible_len(&line)
                );
            }
        }
    }

    #[test]
    fn the_narrowest_terminal_still_shows_which_workload_a_row_is() {
        // Names win the space over the detail column: a port can be found
        // elsewhere, and which container this is cannot.
        let c = ui::Cursor::default();
        let out = both(&two_projects(), &c, 80);
        assert!(out.contains("mainnet-particip"), "the name survives 80 columns:\n{out}");
    }
}

#[cfg(test)]
mod rail_tests {
    use super::*;
    use serde_json::json;

    fn with(state: &str, critical: bool, partial: bool) -> Snapshot {
        Snapshot {
            workloads: Some(json!({
                "partial": partial,
                "workloads": [{
                    "id": "mainnet-validator-1", "kind": "container", "state": state,
                    "health": "none_declared", "restarts": 0, "critical": critical,
                    "project": "orchid-mainnet", "ports": []
                }]
            })),
            ..Snapshot::empty()
        }
    }

    fn rail(s: &Snapshot) -> State {
        s.states().into_iter().find(|(p, _)| *p == Pane::Workloads).map(|(_, v)| v).unwrap()
    }

    #[test]
    fn every_pane_has_a_state_on_the_rail() {
        // Workloads was added to the panes and not to this list, so the rail
        // drew its name with no mark beside it — a section the rail could say
        // nothing about, which is exactly what the rail is for.
        let states = Snapshot::empty().states();
        for p in Pane::ALL {
            assert!(
                states.iter().any(|(x, _)| *x == p),
                "{} has no state on the rail",
                p.title()
            );
        }
    }

    #[test]
    fn a_declared_load_bearing_workload_being_down_needs_a_human() {
        // The distinction is the operator's own declaration; nothing in a
        // process table says which of these the site cannot do without.
        assert_eq!(rail(&with("failed", true, false)), State::Fault);
        assert_eq!(rail(&with("failed", false, false)), State::Warn);
        assert_eq!(rail(&with("running", true, false)), State::Ok);
    }

    #[test]
    fn an_incomplete_inventory_is_not_reported_as_good_news() {
        // A source that could not be read is not a machine with nothing wrong
        // on it, and a green mark there would be the screen lying.
        assert_eq!(rail(&with("running", true, true)), State::Unknown);
        assert_eq!(rail(&Snapshot::empty()), State::Unknown);
    }

    #[test]
    fn the_home_screen_carries_every_section_the_rail_does() {
        // Home is "every section at once". A section missing from it is one an
        // operator has to know to go and look for.
        let snap = with("running", true, false);
        let titles: Vec<String> = panels(&snap).iter().map(|p| p.title.clone()).collect();
        assert!(
            titles.iter().any(|t| t == "workloads"),
            "no workloads panel on the home screen: {titles:?}"
        );
    }

    #[test]
    fn the_home_panel_says_zero_degraded_rather_than_going_quiet() {
        // A row that appears only when there is bad news reads as a screen that
        // has stopped checking.
        let snap = with("running", true, false);
        let p = panels(&snap);
        let w = p.iter().find(|p| p.title == "workloads").unwrap();
        let degraded = w.rows.iter().find(|(k, _)| k == "degraded").expect("a degraded row");
        assert!(degraded.1.contains('0'), "{:?}", degraded);
    }
}

/// One project across the whole site.
struct FRow {
    project: String,
    nodes: String,
    total: u64,
    running: u64,
    degraded: u64,
    critical_degraded: u64,
}

fn fleet_rows(f: &serde_json::Value) -> Vec<FRow> {
    let mut rows: Vec<FRow> = f
        .get("projects")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(|p| {
                    let n = |k: &str| p.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
                    FRow {
                        project: s_field(p, &["project"]),
                        nodes: p
                            .get("nodes")
                            .and_then(|a| a.as_array())
                            .map(|a| {
                                a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")
                            })
                            .unwrap_or_default(),
                        total: n("total"),
                        running: n("running"),
                        degraded: n("degraded"),
                        critical_degraded: n("critical_degraded"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    // What needs a human first, then what is worth a look, then the rest. The
    // site view exists to be read during an incident.
    rows.sort_by(|a, b| {
        b.critical_degraded
            .cmp(&a.critical_degraded)
            .then(b.degraded.cmp(&a.degraded))
            .then(a.project.cmp(&b.project))
    });
    rows
}

/// The site's services, and where they run.
///
/// Deliberately by project rather than by process. A fleet view listing every
/// container on every machine makes an operator do the arithmetic in their head
/// — the question at this distance is "is orchid-mainnet all right", and the
/// individual processes are one keystroke away on the node's own scope.
fn fleet_lines(
    f: &serde_json::Value,
    cursor: &ui::Cursor,
    width: usize,
    zoom: bool,
) -> (Vec<String>, Vec<String>) {
    let rows = fleet_rows(f);
    if zoom {
        return (fleet_detail(f, cursor.index, &rows), Vec::new());
    }

    let mut head = Vec::new();
    // Whether the picture is whole. A site view assembled from a node that did
    // not answer is a site view with a machine missing from it, and it must not
    // read as a quiet site.
    let missing: Vec<String> = f
        .get("nodes")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter(|n| n.get("partial").and_then(|p| p.as_bool()).unwrap_or(false))
                .map(|n| s_field(n, &["topology_id"]))
                .collect()
        })
        .unwrap_or_default();
    if !missing.is_empty() {
        head.push(style::warn(&format!(
            "incomplete on {} — this is not the whole site",
            missing.join(", ")
        )));
        head.push(String::new());
    }
    if rows.is_empty() {
        head.push(style::dim("no node has reported yet"));
        return (head, Vec::new());
    }

    let (proj_w, num_w) = (18usize, 9usize);
    let fixed = 1 + proj_w + 2 + num_w * 3 + 6;
    let nodes_w = width.saturating_sub(fixed).clamp(10, 40);

    head.push(format!(
        " {}  {}  {}  {}  {}",
        style::dim(&pad("PROJECT", proj_w)),
        style::dim(&pad("RUNNING", num_w)),
        style::dim(&pad("DEGRADED", num_w)),
        style::dim(&pad("TOTAL", num_w)),
        style::dim(&pad("NODES", nodes_w))
    ));

    let lines = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mark = if i == cursor.index { style::amber("▸") } else { " ".into() };
            // A load-bearing service down needs a human; anything else down is
            // worth a look. The difference is the operator's own declaration,
            // and it is the only thing this column is allowed to say.
            let degraded = if r.critical_degraded > 0 {
                style::fault(&pad(&format!("{} !", r.degraded), num_w))
            } else if r.degraded > 0 {
                style::warn(&pad(&r.degraded.to_string(), num_w))
            } else {
                style::measured(&pad("0", num_w))
            };
            format!(
                "{mark}{}  {}  {}  {}  {}",
                style::amber_bright(&pad(&r.project, proj_w)),
                style::measured(&pad(&r.running.to_string(), num_w)),
                degraded,
                style::dim(&pad(&r.total.to_string(), num_w)),
                style::dim(&style::truncate(&r.nodes, nodes_w))
            )
        })
        .collect();
    (head, lines)
}

/// One project, opened: which machines carry it and what is wrong where.
fn fleet_detail(f: &serde_json::Value, index: usize, rows: &[FRow]) -> Vec<String> {
    let Some(row) = rows.get(index) else {
        return vec![style::dim("nothing selected")];
    };
    let mut out = vec![
        style::amber_bright(&row.project),
        String::new(),
        format!(
            "{}  {} of {} running on {}",
            style::dim(&pad("across the site", 18)),
            style::measured(&row.running.to_string()),
            style::dim(&row.total.to_string()),
            style::measured(&row.nodes)
        ),
        String::new(),
    ];

    // Per node, and only what is wrong. A list of everything that is fine is
    // one an operator scrolls past to find the line that is not.
    let mut any = false;
    for n in f.get("nodes").and_then(|a| a.as_array()).into_iter().flatten() {
        let node = s_field(n, &["topology_id"]);
        let here: Vec<&serde_json::Value> = n
            .get("degraded")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter(|w| {
                        w.get("project").and_then(|p| p.as_str()).unwrap_or("unfiled")
                            == row.project
                    })
                    .collect()
            })
            .unwrap_or_default();
        for w in here {
            any = true;
            let id = s_field(w, &["id"]);
            let critical = w.get("critical").and_then(|c| c.as_bool()).unwrap_or(false);
            out.push(format!(
                "{}  {}  {}{}",
                style::dim(&pad(&node, 12)),
                style::fault(&pad(&s_field(w, &["state"]), 11)),
                style::measured(&id),
                if critical { style::amber_bright("  * load-bearing") } else { String::new() }
            ));
        }
    }
    if !any {
        // Named rather than left blank: "nothing is wrong" is an answer, and an
        // empty area is not.
        out.push(style::measured("nothing degraded"));
    }

    out.push(String::new());
    out.push(style::dim("s returns to this machine. this screen never changes the site."));
    out
}


#[cfg(test)]
mod action_tests {
    use super::*;
    use serde_json::json;
    use term::Key;

    fn snap() -> Snapshot {
        Snapshot {
            workloads: Some(json!({"partial": false, "workloads": [
                {"id": "mainnet-nginx-1", "kind": "container", "state": "running",
                 "health": "none_declared", "restarts": 0, "critical": true,
                 "project": "orchid-mainnet", "ports": []}
            ]})),
            ..Snapshot::empty()
        }
    }

    fn on_workloads() -> Ui {
        let mut ui = Ui::default();
        let i = Pane::ALL.iter().position(|p| *p == Pane::Workloads).expect("workloads exists");
        ui.on_key(Key::Char(char::from_digit(i as u32 + 1, 10).expect("a digit")));
        ui
    }

    #[test]
    fn asking_to_restart_does_not_restart_anything_on_its_own() {
        // One key that reaches a real machine is one somebody hits by accident.
        let mut ui = on_workloads();
        assert!(ui.on_key(Key::Char('R')));
        assert!(ui.pending.is_some(), "it asks first");
        assert!(ui.take_intent().is_none(), "and nothing has been asked for yet");
    }

    #[test]
    fn confirming_is_the_only_thing_that_asks_for_it() {
        let mut ui = on_workloads();
        ui.on_key(Key::Char('R'));
        ui.on_key(Key::Char('y'));
        assert!(matches!(ui.take_intent(), Some(ui::Intent::RestartSelected)));
        assert!(ui.pending.is_none(), "and the prompt is gone");
    }

    #[test]
    fn anything_other_than_yes_is_no() {
        // A prompt that accepts only one specific refusal is one people escape
        // by guessing, and guessing at a confirmation is how it gets confirmed.
        for k in [Key::Char('n'), Key::Escape, Key::Char('q'), Key::Char('j'), Key::Tab] {
            let mut ui = on_workloads();
            ui.on_key(Key::Char('R'));
            ui.on_key(k);
            assert!(ui.take_intent().is_none(), "{k:?} must not confirm");
            assert!(ui.pending.is_none());
            assert!(ui.running, "{k:?} must not quit either, while a prompt is up");
        }
    }

    #[test]
    fn the_prompt_names_what_it_will_restart_and_says_if_it_is_load_bearing() {
        // An operator confirming an unnamed action is confirming a habit, and
        // the one time it matters the cursor will have been somewhere else.
        let mut ui = on_workloads();
        ui.on_key(Key::Char('R'));
        let out = frame(&mut ui, &snap(), &History::default(), 110, 30).join("\n");
        assert!(out.contains("mainnet-nginx-1"), "{out}");
        assert!(out.contains("load-bearing"), "the declaration is repeated here:\n{out}");
        assert!(out.contains("y to confirm"), "{out}");
    }

    #[test]
    fn the_site_view_offers_no_restart() {
        // The fleet scope is a roll-up of services. "Restart orchid-mainnet" is
        // not something one machine can be asked to do, and offering it would
        // be a key that does nothing or does the wrong thing.
        let mut ui = on_workloads();
        ui.on_key(Key::Char('s'));
        assert!(ui.fleet);
        assert!(!ui.on_key(Key::Char('R')));
        assert!(ui.pending.is_none());
    }

    #[test]
    fn switching_scope_puts_the_cursor_back_to_the_top() {
        // Row 7 of one list is not row 7 of the other, and leaving the
        // selection where it was would open — or restart — a different
        // resource than the one that was highlighted.
        let mut ui = on_workloads();
        ui.cursor_mut().index = 7;
        ui.on_key(Key::Char('s'));
        assert_eq!(ui.cursor().index, 0);
    }
}

/// Who this site recognises, what it has been asked to allow, and what it
/// decided.
///
/// The pane showed decisions and nothing about the authority they were decided
/// against. An operator could issue a grant with `furcatectl` and have no way
/// to see it on the screen they watch — which is the same failure as collecting
/// workloads nobody could look at, one layer up and rather more serious,
/// because this is the layer that says who may act.
fn authority_lines(policy: &serde_json::Value, s: &Snapshot) -> Vec<String> {
    authority_rows(policy, s).0
}

/// The pane's rows, and which of them is a grant.
///
/// Both come out of one pass because they are one fact. Working out where the
/// grants sit by re-deriving the layout somewhere else would be a second
/// implementation of the same arithmetic, and the two would disagree the first
/// time a section grew a line — with the consequence that withdrawing authority
/// took away something other than what the operator had highlighted.
fn authority_rows(
    policy: &serde_json::Value,
    s: &Snapshot,
) -> (Vec<String>, Vec<(usize, String)>) {
    let mut grant_at: Vec<(usize, String)> = Vec::new();
    let mut out = Vec::new();
    let head = |t: &str| style::amber_bright(t);

    // Whose word this site takes at all. Before the machines, because an
    // issuer being absent or a withdrawal list having gone stale explains a
    // whole class of refusals that otherwise look like a broken credential.
    out.push(head("RECOGNISES"));
    match &s.trust {
        None => out.push(style::dim("  the site controller is not answering")),
        Some(t) => {
            let issuers = t.get("issuers").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            if issuers.is_empty() {
                out.push(format!(
                    "  {}",
                    style::dim("its own operator only — no issuers enrolled")
                ));
            } else {
                for i in issuers.iter().take(4) {
                    out.push(format!(
                        "  {}  {}  {}",
                        style::amber(&pad(&s_field(i, &["id"]), 26)),
                        style::dim(&pad(&s_field(i, &["level"]), 7)),
                        style::dim(&style::truncate(&s_field(i, &["reason"]), 34))
                    ));
                }
            }
            // A narrowing nobody can observe looks exactly like a credential
            // being wrong, so it is said rather than left to be inferred.
            if t.get("revocations_stale").and_then(|v| v.as_bool()) == Some(true) {
                out.push(format!(
                    "  {}",
                    style::warn("withdrawals unconfirmed — refusing credentials from the network")
                ));
            }
        }
    }
    out.push(String::new());

    // Machines: an admission is the thing that lets a node take part at all,
    // and one lapsing is the likeliest reason something stopped working.
    out.push(head("MACHINES"));
    match &s.roster {
        None => out.push(style::dim("  the site controller is not answering")),
        Some(r) => {
            let admitted = r.get("admitted").and_then(|v| v.as_u64()).unwrap_or(0);
            out.push(format!(
                "  {}  {}",
                style::dim(&pad("admitted", 14)),
                if admitted == 0 {
                    // Not a quiet site: nothing may report until somebody is
                    // admitted, so zero is a state an operator must act on.
                    style::warn("none — nothing may report until one is admitted")
                } else {
                    style::measured(&admitted.to_string())
                }
            ));
            if let Some(refused) = r.get("rejected_calls").and_then(|v| v.as_u64()) {
                out.push(format!(
                    "  {}  {}",
                    style::dim(&pad("refused calls", 14)),
                    if refused > 0 { style::warn(&refused.to_string()) } else { style::measured("0") }
                ));
            }
        }
    }

    // Then what has been handed out. A grant is authority somebody added on
    // purpose, and the whole point of it having an expiry is that an operator
    // can see it and know when it goes.
    out.push(String::new());
    out.push(head("GRANTS"));
    let grants = s
        .grants
        .as_ref()
        .and_then(|g| g.get("grants").and_then(|a| a.as_array()).cloned())
        .unwrap_or_default();
    if grants.is_empty() {
        out.push(style::dim("  none outstanding"));
    } else {
        for g in grants.iter().take(6) {
            // Recorded against the row it is drawn on. `pane_lines` keeps the
            // title and its blank line fixed and scrolls the rest, so the
            // cursor counts from two lines below the top.
            grant_at.push((out.len().saturating_sub(2), s_field(g, &["to"])));
            out.push(format!(
                "  {}  {} {}",
                style::amber(&pad(&s_field(g, &["to"]), 18)),
                style::measured(
                    &g.get("actions")
                        .and_then(|a| a.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                        .unwrap_or_default()
                ),
                style::dim(
                    &g.get("resources")
                        .and_then(|a| a.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                        .unwrap_or_default()
                ),
            ));
            let why = s_field(g, &["reason"]);
            if !why.is_empty() {
                // Carried because a grant nobody can read the reasoning of is
                // one nobody dares revoke.
                out.push(format!("  {}", style::dim(&style::truncate(&why, 60))));
            }
        }
    }

    // Anything waiting on a person. A proposal that nobody sees is a proposal
    // that expires unanswered, which reads to the asker as a refusal.
    out.push(String::new());
    out.push(head("AWAITING A HUMAN"));
    let pending = s
        .proposals
        .as_ref()
        .and_then(|p| p.get("proposals").and_then(|a| a.as_array()).cloned())
        .unwrap_or_default();
    let open: Vec<&serde_json::Value> = pending
        .iter()
        .filter(|p| {
            let st = s_field(p, &["status"]);
            st.is_empty() || st == "pending" || st == "proposed"
        })
        .collect();
    if open.is_empty() {
        out.push(style::dim("  nothing"));
    } else {
        for p in open.iter().take(4) {
            out.push(format!(
                "  {}  {}",
                style::amber(&pad(&s_field(p, &["id"]), 14)),
                style::measured(&style::truncate(&s_field(p, &["rationale"]), 52))
            ));
        }
    }

    // Decisions last: they are the record, and the record is what somebody
    // reads after the fact rather than the thing they act on now.
    out.push(String::new());
    out.push(head("DECISIONS"));
    let ds = policy.get("decisions").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    out.push(format!(
        "  {}  {}   {}  {}",
        style::dim("recorded"),
        style::measured(&ds.len().to_string()),
        style::dim("refused"),
        field(policy, &["refused"])
    ));
    out.extend(collapse_decisions(&ds, 8));

    out.push(String::new());
    out.extend(record_lines(s));
    (out, grant_at)
}

#[cfg(test)]
mod authority_pane_tests {
    use super::*;
    use serde_json::json;

    fn snap(grants: serde_json::Value, admitted: u64, proposals: serde_json::Value) -> Snapshot {
        Snapshot {
            policy: Some(json!({"decisions": [], "refused": 0})),
            grants: Some(json!({"grants": grants})),
            roster: Some(json!({"admitted": admitted, "rejected_calls": 0})),
            proposals: Some(json!({"proposals": proposals})),
            ..Snapshot::empty()
        }
    }

    #[test]
    fn a_grant_is_visible_on_the_screen_an_operator_watches() {
        // It was not. An operator could issue one with furcatectl and had no
        // way to see it here, which is the same failure as collecting workloads
        // nobody could look at — one layer up, and worse, because this layer
        // says who may act.
        let s = snap(
            json!([{"to": "agent:ops", "actions": ["restart"],
                    "resources": ["workload:acme-*"], "reason": "on call tonight"}]),
            2,
            json!([]),
        );
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("agent:ops"), "{out}");
        assert!(out.contains("restart"));
        assert!(out.contains("on call tonight"), "the reasoning is shown, or nobody dares revoke it");
    }

    #[test]
    fn an_empty_roster_is_reported_as_something_to_act_on() {
        // Nothing may report until a machine is admitted, so zero is not a
        // quiet site — it is a site where nothing can join.
        let s = snap(json!([]), 0, json!([]));
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("nothing may report"), "{out}");
    }

    #[test]
    fn a_proposal_waiting_on_a_person_is_surfaced() {
        // One nobody sees expires unanswered, which reads to the asker as a
        // refusal it never actually got.
        let s = snap(
            json!([]),
            2,
            json!([{"id": "p-1", "status": "pending", "rationale": "restart the stuck exporter"}]),
        );
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("p-1"), "{out}");
        assert!(out.contains("stuck exporter"));
    }

    #[test]
    fn an_answered_proposal_is_not_still_waiting() {
        let s = snap(json!([]), 2, json!([{"id": "p-9", "status": "approved"}]));
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(!out.contains("p-9"), "answered proposals are not pending:\n{out}");
    }

    #[test]
    fn nothing_outstanding_says_so_rather_than_leaving_a_blank() {
        // An empty area reads as a screen that has not loaded. "None" is an
        // answer; whitespace is not.
        let s = snap(json!([]), 2, json!([]));
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("none outstanding"));
        assert!(out.contains("nothing"));
    }

    #[test]
    fn the_controller_being_absent_is_said_rather_than_shown_as_zero() {
        // Zero admitted machines and an unreachable controller are different
        // facts with different fixes.
        let s = Snapshot {
            policy: Some(json!({"decisions": [], "refused": 0})),
            ..Snapshot::empty()
        };
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("not answering"), "{out}");
    }
}

#[cfg(test)]
mod trust_pane_tests {
    use super::*;
    use serde_json::json;

    fn with_trust(t: serde_json::Value) -> Snapshot {
        Snapshot {
            policy: Some(json!({"decisions": [], "refused": 0})),
            grants: Some(json!({"grants": []})),
            roster: Some(json!({"admitted": 2, "rejected_calls": 0})),
            proposals: Some(json!({"proposals": []})),
            trust: Some(t),
            ..Snapshot::empty()
        }
    }

    #[test]
    fn a_site_with_no_issuers_says_so_rather_than_showing_nothing() {
        // Deny by default is the correct state, and an operator should be able
        // to see that it is the state they are in.
        let s = with_trust(json!({"issuers": [], "revocations_stale": false}));
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("no issuers enrolled"), "{out}");
    }

    #[test]
    fn a_stale_withdrawal_list_is_reported_with_its_consequence() {
        // The narrowing is invisible otherwise: credentials from the network
        // simply start being refused, which looks exactly like a credential
        // being wrong rather than a list being old.
        let s = with_trust(json!({"issuers": [], "revocations_stale": true}));
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("withdrawals unconfirmed"), "{out}");
        assert!(out.contains("refusing"), "and what it costs: {out}");
    }

    #[test]
    fn an_enrolled_issuer_is_shown_with_its_level_and_reason() {
        let s = with_trust(json!({
            "issuers": [{"id": "did:example:x", "level": "global", "reason": "the network"}],
            "revocations_stale": false
        }));
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("did:example:x"));
        assert!(out.contains("global"), "the level decides how far it is trusted");
        assert!(out.contains("the network"), "and why this site takes its word");
    }

    #[test]
    fn a_controller_that_is_not_answering_is_not_reported_as_trusting_nobody() {
        // Two different facts with two different fixes.
        let s = Snapshot {
            policy: Some(json!({"decisions": [], "refused": 0})),
            ..Snapshot::empty()
        };
        let out = authority_lines(s.policy.as_ref().unwrap(), &s).join("\n");
        assert!(out.contains("not answering"), "{out}");
    }
}


/// Where the operator's sealed key lives, so a signed request can be made.
///
/// Configurable because a site may keep it elsewhere, and defaulted because
/// most will not. Not read here — only handed to `furcatectl`, which is the one
/// thing that knows how to unseal it.
fn operator_key_path() -> String {
    std::env::var("FURCATE_OPERATOR_KEY")
        .unwrap_or_else(|_| "/var/lib/furcate/operator-key".into())
}

fn addrs_site(a: &Addrs) -> String {
    a.site.clone()
}

/// The command that restarts what is selected.
/// The command a submitted form runs.
///
/// Every one of these ends in `furcatectl`, signing with the operator key and
/// letting the policy engine rule on it — the same path the restart and
/// withdraw keys already take. The console never changes a machine itself; it
/// asks something that can, and that split is why a read-only screen can carry
/// write actions without becoming a second authority.
fn submit_argv(snap: &Snapshot, state: &Ui) -> Result<Vec<String>, String> {
    let d = state.dialog.as_ref().ok_or("no form is open")?;

    // Site-wide deeds need the machine that administers the site. Holding the
    // operator key is what grants permission, and it is checked at the far end
    // regardless — but admitting a peer from a node with a partial view of the
    // membership is how two halves of a cluster come to disagree about who
    // belongs, so the console declines to be the place that starts it.
    if d.deed.site_wide() {
        let here = std::env::var("FURCATE_LISTEN").unwrap_or_default();
        let admin = snap
            .administrator
            .as_ref()
            .and_then(|a| a.get("administrator"))
            .and_then(|v| v.as_str());
        let site = std::env::var("FURCATE_SITE").unwrap_or_default();
        let host = |a: &str| a.split(':').next().unwrap_or("").to_string();
        let is_admin_machine = !site.is_empty() && !here.is_empty() && host(&site) == host(&here);
        if !is_admin_machine {
            return Err(match admin {
                Some(_) => format!("{} is a site-wide change; run it on the machine that administers the site", d.deed.title()),
                None => format!("{} is a site-wide change and no machine currently administers this site", d.deed.title()),
            });
        }
    }

    match d.deed {
        ui::Deed::AddPeer => Ok(vec![
            "overlay".into(),
            "authorize".into(),
            operator_key_path(),
            d.value("node id"),
            d.value("public key"),
            d.value("tier"),
            d.value("hours"),
        ]),
        ui::Deed::RemoveSite => Ok(vec!["deploy".into(), "remove".into(), d.value("site")]),
    }
}

fn restart_argv(snap: &Snapshot, state: &Ui) -> Result<Vec<String>, String> {
    let w = snap.workloads.as_ref().ok_or("the node agent is not answering")?;
    let rows = workload_rows(w);
    let row = rows.get(state.cursor().index).ok_or("nothing is selected")?;
    if row.kind == "pod" {
        return Err(format!("{} is a pod — kubernetes owns restarting it", row.id));
    }
    Ok(vec![
        "workload".into(),
        "restart".into(),
        operator_key_path(),
        std::env::var("FURCATE_NODE_ADDR").unwrap_or_else(|_| "127.0.0.1:7616".into()),
        row.kind.clone(),
        row.id.clone(),
    ])
}

/// The command that withdraws the grant at the top of the pane.
fn revoke_argv(site: &str, snap: &Snapshot, state: &Ui) -> Result<Vec<String>, String> {
    let policy = snap.policy.as_ref().ok_or("the site controller is not answering")?;
    let (_, grants) = authority_rows(policy, snap);
    if grants.is_empty() {
        return Err("there is nothing to withdraw".into());
    }
    // The row the cursor is actually on. Taking the first regardless was the
    // first version, which is unambiguous with one grant and quietly wrong with
    // several — it would withdraw something other than what was highlighted.
    let to = grants
        .iter()
        .find(|(row, _)| *row == state.cursor().index)
        .map(|(_, to)| to.clone())
        .ok_or("put the cursor on a grant to withdraw it")?;
    if to.is_empty() {
        return Err("that grant names nobody".into());
    }
    Ok(vec!["policy".into(), "revoke".into(), operator_key_path(), site.to_string(), to])
}

/// Run `furcatectl` with the terminal handed back, and wait to be read.
///
/// Under `sudo`, because unsealing the operator key needs root. The output is
/// left on screen until a key is pressed: an action that reported its result
/// into a frame the console immediately repainted would be an action whose
/// result nobody ever saw.
fn run_privileged(argv: &[String]) {
    use std::io::Read as _;
    println!("\n$ sudo furcatectl {}\n", argv.join(" "));
    let status = std::process::Command::new("sudo")
        .arg("furcatectl")
        .args(argv)
        .status();
    match status {
        Ok(s) if s.success() => println!("\ndone."),
        Ok(s) => println!("\nfurcatectl exited {}.", s.code().unwrap_or(-1)),
        Err(e) => println!("\ncould not run furcatectl: {e}"),
    }
    println!("press any key to return to the console");
    let _ = std::io::stdin().read(&mut [0u8; 1]);
}

#[cfg(test)]
mod withdraw_tests {
    use super::*;
    use serde_json::json;

    fn snap(n: usize) -> Snapshot {
        Snapshot {
            policy: Some(json!({"decisions": [], "refused": 0})),
            grants: Some(json!({"grants": (0..n).map(|i| json!({
                "to": format!("agent:{i}"), "actions": ["restart"],
                "resources": ["workload:*"], "reason": "r"
            })).collect::<Vec<_>>()})),
            roster: Some(json!({"admitted": 2, "rejected_calls": 0})),
            proposals: Some(json!({"proposals": []})),
            trust: Some(json!({"issuers": [], "revocations_stale": false})),
            ..Snapshot::empty()
        }
    }

    fn at(index: usize) -> Ui {
        let mut ui = Ui::default();
        ui.on_key(term::Key::Char('8'));
        ui.cursor_mut().index = index;
        ui
    }

    #[test]
    fn withdrawing_takes_the_grant_the_cursor_is_on() {
        // Taking the first regardless is unambiguous with one grant and quietly
        // wrong with several: it withdraws something other than what the
        // operator had highlighted.
        let s = snap(3);
        let (_, rows) = authority_rows(s.policy.as_ref().unwrap(), &s);
        assert_eq!(rows.len(), 3, "one entry per grant");

        for (row, expected) in rows.clone() {
            let argv = revoke_argv("site:1", &s, &at(row)).expect("a grant is under the cursor");
            assert_eq!(argv.last().unwrap(), &expected, "row {row} should withdraw {expected}");
        }
        // And the three are genuinely different, or the test above proves
        // nothing.
        assert_eq!(rows.iter().map(|(_, t)| t.clone()).collect::<std::collections::BTreeSet<_>>().len(), 3);
    }

    #[test]
    fn a_cursor_that_is_not_on_a_grant_withdraws_nothing() {
        // Every other row in this pane is a heading, a machine count or a
        // decision. Acting on one of those would be acting on something the
        // operator was only reading.
        let s = snap(2);
        let (_, rows) = authority_rows(s.policy.as_ref().unwrap(), &s);
        let grant_rows: Vec<usize> = rows.iter().map(|(r, _)| *r).collect();
        let elsewhere = (0..30).find(|i| !grant_rows.contains(i)).unwrap();
        let e = revoke_argv("site:1", &s, &at(elsewhere)).unwrap_err();
        assert!(e.contains("put the cursor on a grant"), "{e}");
    }

    #[test]
    fn nothing_to_withdraw_says_so() {
        let s = snap(0);
        let e = revoke_argv("site:1", &s, &at(0)).unwrap_err();
        assert!(e.contains("nothing to withdraw"), "{e}");
    }

    #[test]
    fn the_row_map_follows_the_layout_rather_than_being_guessed() {
        // The mapping and the rendering come out of one pass. If a section
        // above the grants grows a line, both move together — which is the
        // whole reason they are not computed twice.
        let s = snap(1);
        let (lines, rows) = authority_rows(s.policy.as_ref().unwrap(), &s);
        let (row, to) = rows[0].clone();
        // `pane_lines` keeps two fixed lines above the scrolling rows.
        assert!(lines[row + 2].contains(&to), "row {row} should draw {to}: {:?}", lines[row + 2]);
    }
}

#[cfg(test)]
mod hardware_pane_tests {
    use super::*;
    use serde_json::json;

    fn snap(hw: Option<serde_json::Value>) -> Snapshot {
        Snapshot {
            health: Some(json!({"state": "active", "power_rung": "nominal"})),
            hardware: hw,
            ..Snapshot::empty()
        }
    }

    fn overview(s: &Snapshot) -> String {
        section_lines(ui::Section::State, s, &History::default(), &ui::Cursor::default(), 100, false, false)
            .all()
            .join("\n")
    }

    #[test]
    fn the_machine_says_what_it_is_and_what_it_will_not_do() {
        // An operator reading a fan at 19,200 RPM needs to know nothing here
        // can move it before they go looking for the control.
        let s = snap(Some(json!({
            "recognised": {"Machine": {"product": "CELSIUS C740"}},
            "can": {"cpu_performance": true, "fan_speed": false, "measured_boot": false}
        })));
        let out = overview(&s);
        assert!(out.contains("CELSIUS C740"), "{out}");
        assert!(out.contains("fan speed"), "what it refuses is the useful half: {out}");
        assert!(out.contains("measured boot"));
        assert!(!out.contains("cpu performance"), "what it can do is not news");
    }

    #[test]
    fn an_undescribed_machine_is_named_rather_than_left_blank() {
        // A gap in the registry is something an operator can close, and they
        // cannot close one they were never shown.
        let s = snap(Some(json!({"recognised": {"Unknown": {"dmi": {}}}, "can": {}})));
        let out = overview(&s);
        assert!(out.contains("not in the registry"), "{out}");
    }

    #[test]
    fn a_machine_that_refuses_nothing_says_so_rather_than_showing_an_empty_line() {
        let s = snap(Some(json!({
            "recognised": {"Machine": {"product": "Some Box"}},
            "can": {"cpu_performance": true}
        })));
        assert!(overview(&s).contains("nothing known"));
    }

    #[test]
    fn an_agent_that_is_not_answering_does_not_invent_a_machine() {
        let out = overview(&snap(None));
        assert!(!out.contains("model"), "nothing claimed with nothing to claim it from");
    }
}

/// The checks that run on their own, and are only interesting when they stop.
///
/// A backup nobody has verified, a scheduled task that has not *succeeded* in a
/// week, a boot that no longer matches what was recorded, a machine under
/// memory pressure. Each of these was collected and none was on any screen, so
/// the only way to meet one was to go looking for it — which nobody does until
/// something else has already gone wrong.
/// Whether this machine's own record still holds.
///
/// The pane above already reports what policy allowed and refused. What it
/// cannot say is whether that account can still be believed: every hash here
/// is recomputed from the entry's own contents and its predecessor, so
/// altering any field invalidates that entry and everything after it. A record
/// nobody recomputes is a claim, not evidence.
fn record_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);
    match &s.ledger {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(l) => {
            let len = l.get("length").and_then(|v| v.as_u64()).unwrap_or(0);
            match l.get("verified").and_then(|v| v.as_bool()) {
                Some(true) => out.push(row(
                    "chain",
                    style::measured(&format!("{len} entries, recomputed and intact")),
                )),
                // Nothing else on this screen outranks this.
                Some(false) => out.push(row(
                    "chain",
                    style::fault("RECOMPUTATION FAILED — this record has been altered"),
                )),
                None => out.push(row("chain", style::warn("cannot tell"))),
            }
            if let Some(h) = l.get("head").and_then(|v| v.as_str()) {
                out.push(row("head", style::dim(&h.chars().take(16).collect::<String>())));
            }
            let entries = l.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            for e in entries.iter().rev().take(5) {
                out.push(format!(
                    "  {}  {}  {}",
                    style::dim(&pad(&s_field(e, &["kind"]), 12)),
                    style::dim(&pad(&s_field(e, &["actor"]), 12)),
                    s_field(e, &["subject"])
                ));
            }
            if entries.is_empty() {
                out.push(style::dim("  no entries yet"));
            }
        }
    }
    out
}


/// A node id, short enough to sit in a row.
///
/// An id is a public key and prints at sixty-five characters, which is wider
/// than the row it goes in and pushes the line past eighty columns. Operators
/// compare these by eye rather than reading them, so enough to tell two
/// machines apart is enough — and the full value is one `furcatectl identity`
/// away when it is actually needed.
fn short_id(id: &str) -> String {
    match id.strip_prefix("furcate:node:") {
        Some(key) if key.len() > 14 => format!("furcate:node:{}\u{2026}", &key[..14]),
        _ => id.to_string(),
    }
}

/// Who has been given what.
fn tenant_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    match &s.tenancy {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(g) => {
            let list = g.get("grants").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if list.is_empty() {
                out.push(style::dim("  nothing has been granted to anyone"));
            }
            let mut tenant = String::new();
            for x in list.iter() {
                let t = s_field(x, &["tenant"]);
                if t != tenant {
                    if !tenant.is_empty() {
                        out.push(String::new());
                    }
                    out.push(style::subheading(&t));
                    tenant = t;
                }
                let shape = s_field(x, &["shape"]);
                let ext = x.get("extension").and_then(|e| e.as_str()).unwrap_or("");
                out.push(row(
                    &s_field(x, &["name"]),
                    style::measured(&if ext.is_empty() {
                        shape.clone()
                    } else {
                        format!("{shape} — {} with {ext}", s_field(x, &["engine"]))
                    }),
                ));
                // The caveat, where the isolation has one. An operator who
                // chose a denser isolation should keep being told what it cost.
                if let Some(c) = x.get("caveat").and_then(|c| c.as_str()) {
                    out.push(row("", style::warn(c)));
                }
                out.push(row("", style::dim(&format!("leaving: {}", s_field(x, &["leaving"])))));
            }
        }
    }
    out
}

/// Which workloads reach which resources.
fn binding_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    match &s.bindings {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(b) => {
            let list = b.get("bindings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if list.is_empty() {
                out.push(style::dim("  no workload has been bound to anything"));
            }
            for x in list.iter() {
                out.push(style::subheading(&s_field(x, &["workload"])));
                for v in x.get("variables").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                    let name = s_field(&v, &["name"]);
                    let secret = v.get("secret").and_then(|s| s.as_bool()).unwrap_or(false);
                    out.push(row(
                        &name,
                        if secret {
                            // Named, never shown. An operator needs to know the
                            // variable exists; nothing needs its value here.
                            style::dim("set, and not shown")
                        } else {
                            style::dim(v.get("means").and_then(|m| m.as_str()).unwrap_or(""))
                        },
                    ));
                }
            }
        }
    }
    out
}

/// Models a workload can ask.
fn inference_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    let bound: Vec<serde_json::Value> = s
        .bindings
        .as_ref()
        .and_then(|b| b.get("bindings").and_then(|v| v.as_array()).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|x| x.get("need").and_then(|n| n.get("Model")).is_some())
        .collect();

    if bound.is_empty() {
        out.push(style::dim("  no workload here asks a model"));
    }
    for x in bound.iter() {
        let need = x.get("need").and_then(|n| n.get("Model"));
        let model = need.map(|n| s_field(n, &["model"])).unwrap_or_default();
        let from = need.map(|n| s_field(n, &["from"])).unwrap_or_default();
        out.push(row(
            &s_field(x, &["workload"]),
            style::measured(&format!("{model} — answered {}", match from.as_str() {
                // Stated plainly, because it is the difference between a
                // request that leaves the building and one that does not.
                "local" => "here",
                _ => "by the network",
            })),
        ));
    }

    out.push(String::new());
    out.push(style::subheading("resident here"));
    match &s.models {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(m) => {
            let loaded = m.get("models").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if loaded.is_empty() {
                out.push(style::dim("  none — a local binding cannot be answered on this machine"));
            }
            for model in loaded.iter().take(6) {
                out.push(row(&s_field(model, &["id"]), style::measured(&s_field(model, &["state"]))));
            }
        }
    }
    out
}

/// The key material this machine holds, and what lapses first.
fn keys_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    match &s.keys {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(k) => {
            if let Some(held) = k.get("held").and_then(|h| h.as_object()) {
                for (what, present) in held {
                    out.push(row(
                        what,
                        if present.as_bool().unwrap_or(false) {
                            style::measured("held")
                        } else {
                            // Absent is not always wrong — only the machine
                            // administering the site holds a verifier — so this
                            // is dim rather than a fault.
                            style::dim("not on this machine")
                        },
                    ));
                }
            }
            let anchors = k.get("anchors").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            out.push(row(
                "anchors trusted",
                if anchors.is_empty() {
                    // An overlay with no anchors admits nobody, which is a
                    // stronger statement than "none configured".
                    style::warn("none — no signature can admit a peer")
                } else {
                    style::measured(
                        &anchors.iter().map(|a| s_field(a, &["key_id"])).collect::<Vec<_>>().join(" "),
                    )
                },
            ));

            let certs = k.get("certificates").and_then(|c| c.as_array()).cloned().unwrap_or_default();
            out.push(String::new());
            out.push(style::subheading("certificates"));
            if certs.is_empty() {
                out.push(style::dim("  none held here"));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            for c in certs.iter().take(8) {
                let name = s_field(c, &["name"]);
                match c.get("expires").and_then(|v| v.as_i64()) {
                    None => out.push(row(&name, style::dim("cannot read its date"))),
                    Some(at) => {
                        let days = (at - now) / 86_400;
                        out.push(row(
                            &name,
                            // Renewal is automatic and usually works. The case
                            // worth showing is the one where it has not, and
                            // that is invisible until a browser refuses.
                            if days < 0 {
                                style::fault(&format!("expired {} days ago", -days))
                            } else if days < 14 {
                                style::warn(&format!("{days} days left — renewal has not happened"))
                            } else {
                                style::dim(&format!("{days} days left"))
                            },
                        ));
                    }
                }
            }
        }
    }
    out
}

/// Encrypted links out of this machine, and when each last spoke.
fn tunnel_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    match &s.tunnels {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(t) => {
            let tunnels = t.get("tunnels").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if tunnels.is_empty() {
                out.push(style::dim("  no tunnel is being managed here"));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            for tun in tunnels.iter() {
                let iface = s_field(tun, &["iface"]);
                let peers = tun.get("peers").and_then(|p| p.as_u64()).unwrap_or(0);
                out.push(row(&iface, style::measured(&format!("{peers} peers"))));
                match tun.get("latest_handshake").and_then(|v| v.as_i64()).filter(|v| *v > 0) {
                    None => out.push(row("", style::warn("never completed a handshake"))),
                    Some(at) => {
                        let ago = now - at;
                        out.push(row(
                            "",
                            // A keepalive runs every twenty-five seconds, so a
                            // healthy peer speaks every couple of minutes. Ten
                            // is the point past which something is wrong rather
                            // than quiet.
                            if ago > 600 {
                                style::fault(&format!("silent for {} minutes", ago / 60))
                            } else {
                                style::dim(&format!("last spoke {ago}s ago"))
                            },
                        ));
                    }
                }
            }
            let loose = t.get("unmanaged").and_then(|u| u.as_array()).cloned().unwrap_or_default();
            if !loose.is_empty() {
                out.push(String::new());
                out.push(style::subheading("not managed here"));
                for u in loose {
                    // Made by hand or by something else. Shown because a link
                    // nothing is responsible for is the one that disappears at
                    // the next reboot with nobody expecting it to.
                    out.push(row(u.as_str().unwrap_or(""), style::warn("no plan covers this")));
                }
            }
        }
    }
    out
}

/// The network this machine is actually on.
fn lan_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    match &s.lan {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(l) => {
            for link in l.get("links").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
                let name = s_field(&link, &["name"]);
                let state = s_field(&link, &["state"]);
                let carrier = link.get("carrier").and_then(|c| c.as_bool()).unwrap_or(false);
                out.push(row(
                    &name,
                    match (state.as_str(), carrier) {
                        ("up", true) => style::measured("up"),
                        // The diagnosis, not the status: configured and plugged
                        // in are different facts and this is where they differ.
                        ("up", false) => style::warn("up, nothing on the wire"),
                        (other, _) => style::dim(other),
                    },
                ));
            }
            out.push(String::new());
            out.push(style::subheading("neighbours"));
            let n = l.get("neighbours").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if n.is_empty() {
                out.push(style::dim("  none seen — this machine has spoken to nobody on the wire"));
            }
            for nb in n.iter().take(8) {
                out.push(row(&s_field(nb, &["address"]), style::dim(&s_field(nb, &["mac"]))));
            }
        }
    }
    out
}

/// How the outside reaches the names this machine serves.
fn routing_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 18)), v);
    let names: Vec<String> = s
        .published
        .as_ref()
        .and_then(|p| p.get("placed").and_then(|v| v.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .flat_map(|p| {
            p.get("domains")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|d| d.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .collect();

    // Names on their way, before the ones already serving. A name that is
    // half-added is the one somebody is actually working on.
    if let Some(dm) = &s.domains {
        let pending = dm
            .get("domains")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !pending.is_empty() {
            for d in pending.iter().take(8) {
                let step = s_field(d, &["step"]);
                out.push(row(
                    &s_field(d, &["name"]),
                    match step.as_str() {
                        "mapped" => style::measured("serving"),
                        "verified" => style::dim("verified — map it to a site"),
                        // The next action, not the state. An operator reading
                        // this is stuck and the useful half is what to do.
                        _ => style::warn(&s_field(d, &["next"])),
                    },
                ));
                if let Some(why) = d.get("last_check").and_then(|v| v.as_str()) {
                    if step != "mapped" {
                        out.push(row("", style::dim(why)));
                    }
                }
            }
            out.push(String::new());
        }
    }

    if names.is_empty() {
        out.push(style::dim("  this machine serves no names, so nothing has to reach it"));
        return out;
    }
    out.push(row("names served", style::measured(&names.len().to_string())));
    for n in names.iter().take(6) {
        out.push(row("", style::dim(n)));
    }
    out.push(String::new());
    // Stated rather than measured. The console cannot see the gateway, and
    // claiming a route it has not observed would be the one place on this
    // screen where a green line means somebody's intention rather than a fact.
    out.push(style::dim("  a name reaches this machine when a passthrough forwards it here by"));
    out.push(style::dim("  server name. `furcatectl routing` prints the map that does it."));
    out
}

/// What the machine noticed about itself.
fn findings_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    match &s.health {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(_) => {
            let f = extension::get().insight(s.cooling.as_ref(), s.hardware.as_ref());
            if f.is_empty() {
                // Nothing found is not the same as nothing wrong, and the
                // wording keeps that distinction where an operator can see it.
                out.push(style::dim("  nothing has been noticed since the last look"));
            }
            for line in f {
                out.push(format!("  {line}"));
            }
        }
    }
    out
}

/// The loops that run on their own.
fn loop_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 22)), v);
    match &s.scheduler {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(sc) => {
            let tasks = sc.get("tasks").and_then(|t| t.as_array()).cloned().unwrap_or_default();
            if tasks.is_empty() {
                out.push(style::dim("  nothing is scheduled"));
            }
            for t in tasks.iter().take(12) {
                let name = s_field(t, &["name"]);
                let last = s_field(t, &["last"]);
                out.push(row(
                    &name,
                    // A check that has stopped checking is the fault this view
                    // exists for; a check that ran and failed is the other one.
                    if last.contains("failed") {
                        style::fault(&last)
                    } else if last.is_empty() {
                        style::warn("has not run")
                    } else {
                        style::dim(&last)
                    },
                ));
            }
        }
    }
    out
}

/// Changes the machine proposed and is waiting on a person for.
fn proposal_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    match &s.proposals {
        None => out.push(style::dim("  the site controller is not answering")),
        Some(p) => {
            let list = p.get("proposals").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if list.is_empty() {
                out.push(style::dim("  nothing is waiting on a person"));
            }
            for pr in list.iter().take(8) {
                out.push(format!(
                    "  {}  {}",
                    style::dim(&pad(&s_field(pr, &["action"]), 18)),
                    style::warn(&s_field(pr, &["reason"]))
                ));
            }
        }
    }
    out
}

/// What this machine publishes.
///
/// The edge has been able to serve since it shipped, and nothing on the console
/// said what it was serving. An operator could deploy a site and then have no
/// way to see it from the machine that holds it.
fn publishing_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    match &s.published {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(p) => {
            let sites = p.get("placed").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if sites.is_empty() {
                // Not a fault. A machine that publishes nothing is the normal
                // case, and saying so is different from saying nothing.
                out.push(style::dim("  nothing placed on this machine"));
            }
            for site in sites.iter().take(6) {
                let name = s_field(site, &["name"]);
                let release = site.get("release").and_then(|v| v.as_str()).unwrap_or("");
                let domains: Vec<String> = site
                    .get("domains")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|d| d.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                out.push(format!(
                    "  {}  {}",
                    style::dim(&pad(&name, 14)),
                    if domains.is_empty() {
                        style::warn("no name declared")
                    } else {
                        style::measured(&domains.join(" "))
                    }
                ));
                out.push(format!(
                    "  {}  {}",
                    style::dim(&pad("", 14)),
                    if release.is_empty() {
                        // The pointer is what is served; a site whose pointer
                        // does not resolve is placed and not serving.
                        style::fault("current does not resolve — nothing is being served")
                    } else {
                        style::dim(release)
                    }
                ));
            }
        }
    }
    out
}

/// Who this machine is, and what it has been allowed to be.
///
/// Identity was one line on this pane. What was missing is the half that
/// expires: a delegation that lapses stops this machine being a peer, and the
/// console said nothing until it had already happened.
fn identity_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);
    match &s.identity {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(i) => {
            let id = s_field(i, &["node_id"]);
            out.push(row("this machine", style::measured(&short_id(&id))));
            let assurance = s_field(i, &["assurance"]);
            let endorsed = i.get("endorsed").and_then(|v| v.as_bool()).unwrap_or(false);
            out.push(row(
                "assurance",
                if endorsed {
                    style::measured(&format!("{assurance}, endorsed"))
                } else {
                    // Asserted and endorsed are different claims, and the
                    // difference decides which tier this machine may join at.
                    style::warn(&format!("{assurance}, not endorsed"))
                },
            ));
        }
    }
    // The delegation, from the overlay the machine already reports.
    if let Some(o) = &s.overlay {
        if let Some(auth) = o.get("authorization") {
            let standing = auth
                .as_object()
                .and_then(|m| m.keys().next().cloned())
                .unwrap_or_else(|| "unknown".into());
            let left = auth
                .get(&standing)
                .and_then(|v| v.get("seconds_left"))
                .and_then(|v| v.as_u64());
            let text = match left {
                Some(sec) => format!("{standing}, {} days left", sec / 86_400),
                None => standing.clone(),
            };
            out.push(row(
                "delegation",
                match standing.as_str() {
                    "good" => style::measured(&text),
                    "ending" => style::warn(&text),
                    _ => style::fault(&text),
                },
            ));
        }
    }
    out
}

/// Which machine administers this site.
fn position_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);

    let administers = std::env::var("FURCATE_SITE").unwrap_or_default();
    let listen = std::env::var("FURCATE_LISTEN").unwrap_or_default();
    if administers.is_empty() {
        out.push(row("site", style::warn("this machine reports to no site")));
    } else {
        // Compared by host so that a machine pointing at itself is recognised
        // as the administrator rather than as one more node reporting in.
        let host = |a: &str| a.split(':').next().unwrap_or("").to_string();
        let is_self = !listen.is_empty() && host(&administers) == host(&listen);
        out.push(row(
            "administered by",
            if is_self {
                style::measured(&format!("{administers} — this machine"))
            } else {
                style::dim(&administers)
            },
        ));
    }
    // Configured against computed. A disagreement here is the condition that
    // produces two administrators, and it is silent unless something asks.
    match &s.administrator {
        None => out.push(row("chosen by", style::dim("configuration — the site is not answering"))),
        Some(a) => match a.get("administrator").and_then(|v| v.as_str()) {
            None => {
                let why = a.get("refused").and_then(|v| v.as_str()).unwrap_or("no reason given");
                out.push(row("should be", style::warn(why)));
            }
            Some(want) => {
                let seen = a.get("seen").and_then(|v| v.as_u64()).unwrap_or(0);
                let declared = a.get("declared").and_then(|v| v.as_u64()).unwrap_or(0);
                out.push(row("should be", style::measured(&short_id(want))));
                out.push(row(
                    "chosen by",
                    style::dim(&format!("attested capability, {seen} of {declared} members seen")),
                ));
            }
        },
    }
    out
}

/// What this machine reasons with about itself.
fn advisor_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);
    match &s.models {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(m) => {
            let loaded = m.get("models").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if loaded.is_empty() {
                out.push(row("model", style::dim("none loaded — the advisor cannot answer")));
            }
            for model in loaded.iter().take(4) {
                out.push(row(&s_field(model, &["id"]), style::measured(&s_field(model, &["state"]))));
            }
        }
    }
    out
}

/// What this machine has left to give.
fn capacity_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);
    match &s.resources {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(r) => {
            for key in ["cpu", "memory", "vram", "disk"] {
                if r.get(key).is_some() {
                    out.push(row(key, style::measured(&s_field(r, &[key]))));
                }
            }
            if out.is_empty() {
                out.push(style::dim("  nothing reported"));
            }
        }
    }
    out
}

/// Whether this machine is behind.
///
/// Firmware age and image drift are both already measured and neither was on
/// the screen, so a machine falling behind did it silently.
fn update_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);
    match &s.image {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(i) => {
            match i.get("drift").and_then(|d| d.as_array()).map(|a| a.len()) {
                Some(0) | None => out.push(row("image", style::measured("matches its baseline"))),
                Some(n) => out.push(row("image", style::fault(&format!("{n} differences from its baseline")))),
            }
            if let Some(age) = i.get("firmware_age").and_then(|v| v.as_u64()) {
                let days = age / 86_400;
                out.push(row(
                    "firmware",
                    if days > 365 {
                        style::warn(&format!("{days} days old"))
                    } else {
                        style::dim(&format!("{days} days old"))
                    },
                ));
            }
            let a = s_field(i, &["assurance"]);
            if !a.is_empty() {
                out.push(row("boot assurance", style::dim(&a)));
            }
        }
    }
    out
}

fn custody_lines(s: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();
    let head = |t: &str| style::amber_bright(t);
    let row = |k: &str, v: String| format!("  {}  {}", style::dim(&pad(k, 16)), v);

    out.push(head("BACKUPS"));
    match &s.custody {
        None => out.push(style::dim("  the node agent is not answering")),
        Some(c) => {
            let bs = c.get("backups").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            if bs.is_empty() {
                // Not reassurance. Nobody declared one, which is a different
                // thing from a backup that was checked and found good.
                out.push(row("declared", style::warn("none")));
            }
            for b in bs.iter().take(4) {
                let v = s_field(b, &["verdict"]);
                let ok = v.contains("intact") || v.contains("present");
                out.push(row(
                    &s_field(b, &["name"]),
                    if ok { style::measured(&v) } else { style::fault(&v) },
                ));
            }
            // Said once, plainly: none of this proves a restore works. Only a
            // restore proves that, and nothing here performs one.
            out.push(format!("  {}", style::dim("none of this proves a restore works")));

            let faults = c.get("kernel_faults").and_then(|a| a.as_array()).map(|a| a.len());
            out.push(String::new());
            out.push(head("KERNEL"));
            out.push(row(
                "faults",
                match faults {
                    Some(0) | None => style::measured("0"),
                    Some(n) => style::fault(&n.to_string()),
                },
            ));

            let drift = c.get("drift").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0);
            out.push(row(
                "config drift",
                if drift > 0 { style::warn(&drift.to_string()) } else { style::measured("0") },
            ));
        }
    }

    out.push(String::new());
    out.push(head("SCHEDULED WORK"));
    match &s.scheduler {
        None => out.push(style::dim("  not answering")),
        Some(sc) => {
            let ts = sc.get("tasks").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            // Last run and last success are different fields for a reason: a
            // task failing every minute has a very recent last run, and
            // reporting only that is how a broken loop passes for healthy.
            let stalled: Vec<&serde_json::Value> = ts
                .iter()
                .filter(|t| {
                    t.get("last_success").map(|v| v.is_null()).unwrap_or(true)
                        || t.get("consecutive_failures")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                            > 0
                })
                .collect();
            out.push(row("tasks", style::measured(&ts.len().to_string())));
            if stalled.is_empty() {
                out.push(row("not succeeding", style::measured("none")));
            } else {
                for t in stalled.iter().take(4) {
                    out.push(row(
                        &s_field(t, &["name"]),
                        style::warn(
                            &(if t.get("last_success").map(|v| v.is_null()).unwrap_or(true) {
                                "has never succeeded".to_string()
                            } else {
                                format!("{} failures running", s_field(t, &["consecutive_failures"]))
                            }),
                        ),
                    ));
                }
            }
        }
    }

    out.push(String::new());
    out.push(head("THIS MACHINE"));
    match &s.image {
        None => out.push(style::dim("  boot assurance not reported")),
        Some(i) => {
            let grade = s_field(i, &["assurance"]);
            out.push(row(
                "boot assurance",
                if grade == "measured" {
                    style::measured(&grade)
                } else {
                    // Graded rather than claimed. `pinned` detects a firmware
                    // change and is blind to a swapped kernel, and an operator
                    // should know which of those they have.
                    style::dim(&format!("{grade} — {}", s_field(i, &["next_step"])))
                },
            ));
        }
    }
    if let Some(n) = &s.netlink {
        // Reach, not throughput. A link that is up and cannot reach anything is
        // the fault an operator is actually looking for.
        let reach = s_field(n, &["reach", "reachability"]);
        if !reach.is_empty() {
            out.push(row(
                "reach",
                if reach.contains("internet") || reach == "ok" {
                    style::measured(&reach)
                } else {
                    style::warn(&reach)
                },
            ));
        }
    }
    if let Some(r) = &s.resources {
        // Pressure, not utilisation. A machine at 100% with nothing waiting is
        // working; one at 40% with tasks stalled is not.
        let p = |k: &[&str]| num(r, k).map(|v| format!("{v:.2}")).unwrap_or_else(|| "—".into());
        out.push(row("cpu pressure", style::measured(&p(&["pressure", "cpu", "some_avg60"]))));
        out.push(row("memory pressure", style::measured(&p(&["pressure", "memory", "full_avg60"]))));
    }
    out
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use serde_json::json;

    fn snap(verified: bool) -> Snapshot {
        Snapshot {
            policy: Some(json!({"decisions": [], "refused": 0})),
            ledger: Some(json!({
                "length": 2951, "returned": 2,
                "head": "292325cfe0edd3504d650e46687e211e9035c62d3a86f9d47ffe9d0635b2af95",
                "verified": verified,
                "entries": [
                    {"seq": 2949, "kind": "quote", "actor": "checkpoint",
                     "subject": "pcr16", "result": "extended and quoted"},
                    {"seq": 2950, "kind": "deploy", "actor": "operator",
                     "subject": "org verify", "result": "serving the release that was approved"}
                ]
            })),
            ..Snapshot::empty()
        }
    }

    #[test]
    fn the_record_says_whether_the_chain_still_recomputes() {
        // Security reports what was allowed and refused. Without this it cannot
        // say whether that account can still be believed, which is the claim
        // the whole ledger exists to support.
        //
        // The heading is no longer asserted: the record became a section of its
        // own, and the section draws its own title, so a renderer printing one
        // too was drawing the same line twice.
        let text = record_lines(&snap(true)).join("\n");
        assert!(text.contains("2951"), "the length is over the whole chain, not the excerpt");
        assert!(text.contains("recomputed and intact"));
    }

    #[test]
    fn a_record_that_fails_to_recompute_is_stated_as_a_fault() {
        // Softening this would be the one place in the console where a failure
        // is easier to read than it should be.
        let out = authority_lines(&json!({"decisions": [], "refused": 0}), &snap(false));
        let text = out.join("\n");
        assert!(text.contains("RECOMPUTATION FAILED"), "an altered record must say so plainly");
    }

    #[test]
    fn a_silent_agent_is_not_reported_as_an_intact_record() {
        // Absence of an answer and an answer of "intact" are different facts,
        // and conflating them is how a console reassures about a node it cannot
        // reach.
        let out = record_lines(&Snapshot::empty());
        let text = out.join("\n");
        assert!(!text.contains("intact"));
        assert!(text.contains("not answering"));
    }
}
