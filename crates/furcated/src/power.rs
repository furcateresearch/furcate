//! Power telemetry, read from the privileged helper.
//!
//! The agent runs unprivileged under a hardened unit and RAPL counters are
//! root-only, so the counter arrives through a file the helper publishes
//! rather than being read directly. Two consecutive readings give power; one
//! gives nothing, which is why this keeps the previous sample.

use furcate_power::rapl::{self, Sample, Scope};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Where the privileged reader publishes.
///
/// `/run/furcate` is the Linux answer and was hardcoded, which meant a macOS
/// node looked for a directory it does not have and reported no power however
/// well its reader was working. Resolved through `furcate_paths` so it follows
/// `FURCATE_RUNTIME_DIR` like everything else this daemon reads.
fn published() -> std::path::PathBuf {
    furcate_paths::runtime_dir().join("power.json")
}

#[derive(Clone, Debug, Deserialize)]
struct Published {
    available: bool,
    #[serde(default)]
    energy_uj: u64,
    #[serde(default)]
    max_range_uj: u64,
    #[serde(default)]
    at_ms: u64,
    #[serde(default)]
    reason: Option<String>,
    /// A reading the publisher already resolved to watts.
    ///
    /// RAPL exposes a cumulative energy counter, so the usual path takes two
    /// samples and divides. Some platforms have no such counter and report
    /// power directly — a GB10 has no package domain at all, and nvidia-smi
    /// reports the board draw instead. Carrying both shapes keeps the
    /// differentiation where it belongs rather than inventing a fake counter
    /// to feed it.
    #[serde(default)]
    watts: Option<f64>,
    /// What the figure covers, when the publisher knows better than this
    /// module does. Absent means the package.
    #[serde(default)]
    scope: Option<String>,
    /// Whole-machine draw, where the platform can measure it.
    ///
    /// A package counter and a wall figure are different questions and the
    /// gap is large — about 2 W against 6 W at idle on an M2, because the
    /// display and the peripherals are not on the SoC. Carried separately
    /// rather than replacing `watts`, so a fleet comparing package figures
    /// still compares like with like.
    #[serde(default)]
    wall_w: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Reading {
    pub available: bool,
    /// Average package power since the previous reading, in watts.
    pub watts: Option<f64>,
    pub scope: String,
    /// Whether this came from hardware. Always true when available: this
    /// module never models a figure.
    pub measured: bool,
    /// Whole-machine draw, when the platform reports one. None on hosts whose
    /// only counter is the processor package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wall_w: Option<f64>,
    pub note: String,
}

static PREVIOUS: Mutex<Option<Sample>> = Mutex::new(None);

/// Read current package power, if the helper is publishing.
pub fn read() -> Reading {
    let raw = match std::fs::read_to_string(published()) {
        Ok(r) => r,
        Err(_) => {
            return Reading {
                available: false,
                watts: None,
                scope: Scope::Package.as_str().into(),
                measured: false,
                wall_w: None,
                // Accurate on Linux and misleading on macOS, where the
                // counters are not root-only — there simply is no RAPL, and
                // the reader that replaces it is furcate-power-macos.
                note: "no reader publishing power here".into(),
            }
        }
    };
    let Ok(p) = serde_json::from_str::<Published>(&raw) else {
        return Reading {
            available: false,
            watts: None,
            scope: Scope::Package.as_str().into(),
            measured: false,
            wall_w: None,
            note: "reader output could not be parsed".into(),
        };
    };
    if !p.available {
        return Reading {
            available: false,
            watts: None,
            scope: Scope::Package.as_str().into(),
            measured: false,
            wall_w: None,
            note: p.reason.unwrap_or_else(|| "platform exposes no RAPL domain".into()),
        };
    }

    // A publisher that already measured watts is trusted with the figure and
    // with naming its own scope. The alternative — synthesising an energy
    // counter so the code below has something to differentiate — would report
    // a number nothing measured.
    if let Some(w) = p.watts.filter(|w| *w > 0.0) {
        let scope = p.scope.unwrap_or_else(|| Scope::Package.as_str().into());
        let note = if scope == "accelerator" {
            "accelerator board draw; this platform exposes no package counter, \
             and on a shared-package part it is close to the whole machine"
                .into()
        } else {
            "reported directly by the platform reader".to_string()
        };
        return Reading { available: true, watts: Some(w), scope, measured: true,
                         wall_w: p.wall_w, note };
    }

    let now = Sample { microjoules: p.energy_uj, at_ms: p.at_ms };
    let mut prev = PREVIOUS.lock().expect("power sample lock");
    let watts = prev
        .and_then(|a| rapl::power_between(a, now, p.max_range_uj, Scope::Package).ok())
        .map(|pw| pw.watts);
    *prev = Some(now);

    Reading {
        available: true,
        watts,
        scope: Scope::Package.as_str().into(),
        measured: true,
        wall_w: None,
        note: match watts {
            // Stated on every reading, because a package figure quoted as
            // machine draw is the easiest mistake to make here.
            Some(_) => "processor package only; excludes disks, fans and power supply loss".into(),
            None => "first sample; power needs two readings".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_reader_is_reported_rather_than_guessed() {
        // With no helper running this is what every machine sees, and it must
        // not invent a number.
        let r = read();
        if !r.available {
            assert!(r.watts.is_none());
            assert!(!r.measured);
        }
    }

    #[test]
    fn the_scope_caveat_is_never_omitted() {
        let r = read();
        assert!(!r.note.is_empty(), "a power figure without its scope is misleading");
    }
}
