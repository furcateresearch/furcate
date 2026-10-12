//! Turning a rung into something the hardware notices.
//!
//! The ladder has been correct and inert. It observed supply and heat, moved
//! `Nominal -> Shed -> Capture`, chained the transition, printed it — and the
//! CPU carried on at 100%. A power ladder that logs is a power ladder that
//! does not exist; the whole argument for descending early is that the early
//! steps buy time, and they only buy time if they happen.
//!
//! This is the bridge. It writes an intent file that the privileged actuator
//! picks up, then reads back what was actually applied.
//!
//! ## Why an intent file rather than a write
//!
//! The agent's unit sets `ProtectKernelTunables=true`. Relaxing that to let it
//! write `max_perf_pct` would hand it write access to a whole class of kernel
//! knobs to gain three. So it states an intent and something privileged
//! decides. The floors live on the privileged side and are re-derived there
//! independently — a limit that exists in only one place stops existing when
//! that place is compromised.
//!
//! ## Why the levers are fixed per rung
//!
//! Not computed, not adaptive, not learned. When the supply is failing or the
//! package is at 82 °C is the worst possible moment to run a novel calculation,
//! and a bug in it is indistinguishable from the emergency it was supposed to
//! handle. Two constants, chosen once, reviewable by reading four lines.
//!
//! ## What this will not do
//!
//! It will not act on `Halt`. Descending to `Halt` is an ordered shutdown
//! sequence with a signing key behind it, not a lever, and the only thing worse
//! than a machine that will not stop is one that stops because a thermistor was
//! misread.

use furcate_power::actuator::Lever;
use furcate_power::Rung;

/// Where the intent is written. The privileged actuator watches this path.
pub fn intent_path() -> String {
    std::env::var("FURCATE_INTENT")
        .unwrap_or_else(|_| furcate_paths::state("actuate").display().to_string())
}

/// Where this agent posts proof of life.
///
/// The privileged actuator reverts to a safe power level when this stops being
/// refreshed. That is the whole mechanism: without it, a node throttled to 40%
/// stayed there forever if this process died, and every health check reported a
/// healthy machine because from the outside it was one — just a slow one.
///
/// Beside the intent file rather than under `/run/furcate`, because that
/// directory is root-owned so the privileged half can publish into it, and the
/// heartbeat has to come from the unprivileged side by definition.
pub fn heartbeat_path() -> String {
    std::env::var("FURCATE_HEARTBEAT").unwrap_or_else(|_| format!("{}.heartbeat", intent_path()))
}

/// Post proof of life.
///
/// Called on every pass of the power loop, including passes where nothing
/// happened — an agent that only signalled when it had something to say would
/// be indistinguishable from one that had died with something outstanding.
pub fn beat() -> std::io::Result<()> {
    let path = heartbeat_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Content is irrelevant; the modification time is the signal. Written
    // rather than touched so the file appears on the first beat.
    std::fs::write(&path, b"alive\n")
}

/// Where the actuator reports what it did.
pub fn result_path() -> String {
    std::env::var("FURCATE_ACTUATED").unwrap_or_else(|_| "/run/furcate/actuated.json".into())
}

/// The lever a rung asks for, if any.
///
/// `Nominal` restores rather than doing nothing: coming back up the ladder has
/// to undo what going down did, or the first brownout of the year leaves the
/// machine at 60% until somebody notices the throughput.
pub fn lever_for(rung: Rung) -> Option<Lever> {
    match rung {
        Rung::Nominal => Some(Lever::MaxPerfPct(100)),
        Rung::Shed => Some(Lever::MaxPerfPct(60)),
        Rung::Capture => Some(Lever::MaxPerfPct(40)),
        // Quiesce is about flushing state, not about frequency, and the flush
        // finishes sooner at speed. Capture's cap stays in force.
        Rung::Quiesce => None,
        // Never. See the module note.
        Rung::Halt => None,
    }
}

/// Render an intent. Separated from writing it so the format is testable
/// without a filesystem.
pub fn render(lever: Lever, nonce: &str) -> String {
    let (name, value) = match lever {
        Lever::MaxPerfPct(p) => ("max_perf_pct", p.to_string()),
        Lever::PackageCapWatts(w) => ("package_cap_watts", w.to_string()),
        Lever::Governor(g) => ("governor", g.as_str().to_string()),
        // Sent as the thing an operator means, not as the kernel's flag. The
        // kernel spells this `no_turbo` and inverts it, and an inversion
        // carried across a process boundary in a text file is a bug waiting for
        // whoever reads the intent and believes it. The privileged side does
        // the inversion at the point of the write.
        Lever::Turbo(on) => ("turbo", if on { "on".into() } else { "off".into() }),
    };
    format!("lever={name}\nvalue={value}\nnonce={nonce}\n")
}

/// Render a workload restart, in the same shape the actuator already parses.
///
/// A separate verb rather than another `Lever`, because a lever is a position
/// something is held in and this is not: it happens once and leaves nothing
/// behind. The dead-man switch has nothing to revert here, which is the
/// difference that decides where each belongs.
pub fn render_restart(kind: &str, id: &str, nonce: &str) -> String {
    format!("action=restart\nkind={kind}\nid={id}\nnonce={nonce}\n")
}

/// Render a shed, in the same shape the actuator already parses.
///
/// A distinct verb from `restart`, and the difference is not cosmetic. The
/// privileged half refuses a shed for anything not on the operator's root-owned
/// preemptible list, and applies no such check to a restart — because a restart
/// can only put something back, while a stop is the one action here that can
/// take something away. Sending a shed as a restart, or the reverse, would ask
/// for the wrong check.
pub fn render_shed(kind: &str, id: &str, nonce: &str) -> String {
    format!("action=shed
kind={kind}
id={id}
nonce={nonce}
")
}

/// Whether an id may cross the privilege boundary as an argument.
///
/// Checked here *and* in the actuator. A defence that exists only on the
/// unprivileged side of a boundary is not a defence — but the caller should
/// still be told no by something that can explain itself, rather than by a
/// shell refusing a pattern.
pub fn id_is_safe(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

/// Ask the privileged half to restart one workload.
pub fn write_restart(kind: &str, id: &str, nonce: &str) -> std::io::Result<()> {
    let path = intent_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, render_restart(kind, id, nonce))?;
    std::fs::rename(&tmp, &path)
}

/// Ask the privileged half to stop one workload the operator called disposable.
///
/// It may refuse, and the refusal is the point: the list it checks against
/// lives on its side of the boundary, so this cannot widen its own reach by
/// naming something new. A caller should read the result rather than assume the
/// workload stopped.
pub fn write_shed(kind: &str, id: &str, nonce: &str) -> std::io::Result<()> {
    let path = intent_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, render_shed(kind, id, nonce))?;
    std::fs::rename(&tmp, &path)
}

/// Ask the privileged half to reset one accelerator.
///
/// The remedy for a card carrying a queued repair — a recorded row remap, or
/// firmware that stopped answering — which only a reset applies.
///
/// The privileged half refuses a card with compute processes on it and says so.
/// That refusal is the drain requirement, and it is deliberately not a drain:
/// nothing here can decide whose work to stop, and a reset that quietly killed
/// running jobs to repair a card would be the worst possible way to find out
/// the card had a fault.
pub fn write_reset(index: u32, nonce: &str) -> std::io::Result<()> {
    let path = intent_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, render_reset(index, nonce))?;
    std::fs::rename(&tmp, &path)
}

/// Render an accelerator reset.
pub fn render_reset(index: u32, nonce: &str) -> String {
    format!("action=reset_accelerator
id={index}
nonce={nonce}
")
}

/// Write an intent atomically.
///
/// Atomically because the actuator reads the whole file and compares it to the
/// last one it saw. A torn write would be read as a distinct intent with a
/// missing value, and the actuator's own parse would have to be the thing that
/// catches it.
pub fn write(lever: Lever, nonce: &str) -> std::io::Result<()> {
    let path = intent_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, render(lever, nonce))?;
    std::fs::rename(&tmp, &path)
}

/// What the actuator reported for a given nonce, if it has caught up.
///
/// The nonce is matched rather than trusted-latest. Reading whatever is in the
/// file would mean a stale result from the previous rung reads as confirmation
/// of this one, which is exactly the case where being wrong matters.
pub fn confirm(nonce: &str) -> Option<serde_json::Value> {
    confirm_in(&result_path(), nonce)
}

/// The same, against a named file.
///
/// Split from `confirm` so it can be tested without an environment variable.
/// Two tests setting one variable in the same binary race, which is a lesson
/// this codebase has now learned twice.
pub fn confirm_in(path: &str, nonce: &str) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    (v.get("nonce").and_then(|n| n.as_str()) == Some(nonce)).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use furcate_power::actuator::Governor;

    #[test]
    fn every_reversible_rung_has_a_lever_and_halt_does_not() {
        assert!(lever_for(Rung::Shed).is_some());
        assert!(lever_for(Rung::Capture).is_some());
        // The only thing worse than a machine that will not stop is one that
        // stops because a thermistor was misread.
        assert!(lever_for(Rung::Halt).is_none());
    }

    #[test]
    fn coming_back_up_restores_rather_than_doing_nothing() {
        // Otherwise the first brownout of the year leaves the machine at 60%
        // until somebody notices the throughput.
        assert_eq!(lever_for(Rung::Nominal), Some(Lever::MaxPerfPct(100)));
    }


    #[test]
    fn a_reset_names_the_card_by_index() {
        let r = render_reset(3, "n9");
        assert!(r.starts_with("action=reset_accelerator
"), "{r}");
        assert!(r.contains("id=3
"));
        assert!(r.contains("nonce=n9
"));
    }

    #[test]
    fn a_shed_is_a_different_verb_from_a_restart() {
        // The privileged half checks a shed against the operator's list and
        // does not check a restart at all, because a restart can only put
        // something back. Sending one as the other asks for the wrong check.
        let shed = render_shed("unit", "batch.service", "n1");
        assert!(shed.starts_with("action=shed
"), "{shed}");
        assert!(shed.contains("kind=unit
"));
        assert!(shed.contains("id=batch.service
"));
        assert!(shed.contains("nonce=n1
"));
        assert!(!render_restart("unit", "batch.service", "n1").contains("action=shed"));
    }

    #[test]
    fn descending_never_asks_for_more_performance_than_the_rung_above() {
        let seq = [Rung::Nominal, Rung::Shed, Rung::Capture];
        let pcts: Vec<u8> = seq
            .iter()
            .filter_map(|r| match lever_for(*r) {
                Some(Lever::MaxPerfPct(p)) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(pcts.len(), 3);
        assert!(pcts.windows(2).all(|w| w[1] < w[0]), "got {pcts:?}");
    }

    #[test]
    fn the_intent_is_what_the_actuator_parses() {
        // The actuator greps `^lever=`, `^value=`, `^nonce=`. This test is the
        // only thing holding the two halves to the same format, since they are
        // in different languages and neither imports the other.
        let s = render(Lever::MaxPerfPct(60), "abc123");
        assert_eq!(s, "lever=max_perf_pct\nvalue=60\nnonce=abc123\n");

        let g = render(Lever::Governor(Governor::Powersave), "n");
        assert!(g.starts_with("lever=governor\nvalue=powersave\n"), "got {g:?}");

        let w = render(Lever::PackageCapWatts(50), "n");
        assert!(w.starts_with("lever=package_cap_watts\nvalue=50\n"), "got {w:?}");

        // Semantic, not the kernel's inverted `no_turbo`. Off means off.
        assert!(render(Lever::Turbo(false), "n").starts_with("lever=turbo\nvalue=off\n"));
        assert!(render(Lever::Turbo(true), "n").starts_with("lever=turbo\nvalue=on\n"));
    }

    #[test]
    fn every_line_is_a_key_equals_value_with_no_stray_whitespace() {
        let s = render(Lever::MaxPerfPct(100), "x");
        for line in s.lines() {
            assert!(line.contains('='), "{line:?} is not a key=value");
            assert_eq!(line.trim(), line, "{line:?} has stray whitespace");
        }
    }

    #[test]
    fn the_heartbeat_sits_beside_the_intent_not_under_run() {
        // /run/furcate is root-owned so the privileged half can publish there.
        // A heartbeat the agent cannot write is a dead man's switch that fires
        // immediately and permanently.
        let h = heartbeat_path();
        assert!(h.starts_with(&intent_path()), "got {h}");
        assert!(!h.starts_with("/run/"), "the agent cannot write there");
    }

    #[test]
    fn a_result_for_a_different_request_is_not_confirmation() {
        // The case where being wrong matters: a stale result from the previous
        // rung reading as confirmation of this one.
        let dir = std::env::temp_dir().join("furcate-actuate-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("actuated.json");
        std::fs::write(&p, r#"{"ok":true,"nonce":"old"}"#).unwrap();
        let p = p.to_str().unwrap();
        assert!(confirm_in(p, "new").is_none());
        assert!(confirm_in(p, "old").is_some());
    }

    #[test]
    fn a_missing_result_file_is_not_confirmation_either() {
        assert!(confirm_in("/nonexistent/furcate/actuated.json", "any").is_none());
    }

    #[test]
    fn a_truncated_result_is_not_confirmation_either() {
        // The actuator writes atomically, but a half-written file read as
        // confirmation would be the worst possible failure of this function.
        let dir = std::env::temp_dir().join("furcate-actuate-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("torn.json");
        std::fs::write(&p, r#"{"ok":true,"non"#).unwrap();
        assert!(confirm_in(p.to_str().unwrap(), "any").is_none());
    }
}


#[cfg(test)]
mod restart_tests {
    use super::*;

    #[test]
    fn the_restart_intent_is_what_the_actuator_greps_for() {
        // The actuator reads `^action=`, `^kind=`, `^id=`, `^nonce=` with sed.
        // This test is the thing that keeps the two halves agreeing across a
        // language boundary they cannot share code over.
        assert_eq!(
            render_restart("container", "mainnet-nginx-1", "abc123"),
            "action=restart\nkind=container\nid=mainnet-nginx-1\nnonce=abc123\n"
        );
    }

    #[test]
    fn an_id_that_could_become_a_flag_or_a_command_is_refused() {
        // It is about to be an argument on the other side of a privilege
        // boundary. The actuator checks this too; both are meant.
        for bad in [
            "",
            "-rf",
            "--now",
            "a;rm -rf /",
            "a b",
            "a$(id)",
            "a`id`",
            "a|b",
            "a\nb",
            "a'b",
        ] {
            assert!(!id_is_safe(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_ids_this_fleet_actually_has_are_accepted() {
        // Refusing real names would make the feature useless in the one place
        // it has to work.
        for ok in [
            "mainnet-participant-1",
            "api-node.service",
            "furcated.service",
            "kube-system/traefik-59b7647586-p2k7j",
            "sentry_validator_1",
        ] {
            assert!(id_is_safe(ok), "{ok:?} should be accepted");
        }
    }
}
