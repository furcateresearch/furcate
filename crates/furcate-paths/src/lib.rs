//! Where everything lives.
//!
//! Until now this was answered fifteen times in five crates, each by reaching
//! for `$HOME`. That is the right answer for a tool somebody runs and the wrong
//! one for a system service: a daemon's home is whatever its unit says, which is
//! how a node's identity key ends up somewhere nobody thinks to back up, and how
//! a privileged helper ends up with `/home/alice/.furcate/actuate` compiled in
//! as a default.
//!
//! So it is answered once, here, and every other site calls into it.
//!
//! ## The rule the layout follows
//!
//! Packaging has one hard rule and every path question answers to it: some
//! files belong to the package and are replaced wholesale on upgrade, and some
//! belong to the machine and must never be touched. Furcate has a sharp version
//! of this, because the machine's side includes a key sealed to its TPM that no
//! reinstall can regenerate. Overwriting it would not be an inconvenience; it
//! would permanently unmake the node's identity.
//!
//! - **`/etc/furcate`** — configuration. The operator's, marked as conffiles so
//!   the package manager asks before replacing.
//! - **`/var/lib/furcate`** — state. Identity, the operation chain, the peer set,
//!   the image baseline. Survives upgrade, reinstall and removal.
//! - **`/run/furcate`** — runtime. Gone at boot, by design: everything in it is
//!   a fact about this boot.
//!
//! ## Precedence, and why systemd wins
//!
//! An explicit environment variable beats everything, so a developer can run the
//! whole system out of a scratch directory. Failing that, the variables systemd
//! sets when a unit declares `StateDirectory=`, `RuntimeDirectory=` or
//! `ConfigurationDirectory=` are used — because in production the unit file
//! should be the single source of truth, and having the binary disagree with its
//! own unit is a class of bug nobody enjoys. Only then does the compiled-in
//! default apply.
//!
//! Nothing here reads `$HOME`, and that is the point.

use std::path::PathBuf;

/// Compiled-in defaults. FHS, and the same on every machine.
const STATE: &str = "/var/lib/furcate";
const CONFIG: &str = "/etc/furcate";
const RUNTIME: &str = "/run/furcate";

/// Resolve a directory by precedence: explicit override, then what systemd
/// declared, then the default.
///
/// `systemd_var` holds a colon-separated list when a unit declares several
/// directories; the first is the one named after the unit, which is the one
/// meant here.
fn resolve(override_var: &str, systemd_var: &str, default: &str) -> PathBuf {
    if let Ok(v) = std::env::var(override_var) {
        if !v.trim().is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var(systemd_var) {
        if let Some(first) = v.split(':').next().filter(|s| !s.trim().is_empty()) {
            return PathBuf::from(first);
        }
    }
    PathBuf::from(default)
}

/// Durable state: identity, chain, peer set, baselines.
///
/// The directory an upgrade must never touch. `StateDirectory=furcate` in the
/// unit makes systemd create it with the right ownership before the process
/// starts, which is why this is preferred over creating it here.
pub fn state_dir() -> PathBuf {
    resolve("FURCATE_STATE_DIR", "STATE_DIRECTORY", STATE)
}

/// Configuration the operator owns.
pub fn config_dir() -> PathBuf {
    resolve("FURCATE_CONFIG_DIR", "CONFIGURATION_DIRECTORY", CONFIG)
}

/// This boot's runtime files, including everything the privileged helpers
/// publish for the unprivileged agent to read.
pub fn runtime_dir() -> PathBuf {
    resolve("FURCATE_RUNTIME_DIR", "RUNTIME_DIRECTORY", RUNTIME)
}

/// A named file in the state directory.
pub fn state(name: &str) -> PathBuf {
    state_dir().join(name)
}

/// A named file in the configuration directory.
pub fn config(name: &str) -> PathBuf {
    config_dir().join(name)
}

/// A named file in the runtime directory.
pub fn runtime(name: &str) -> PathBuf {
    runtime_dir().join(name)
}

/// Create the state directory if it is missing.
///
/// A fallback for running outside systemd — under a unit the directory already
/// exists with the right ownership and this does nothing. It deliberately does
/// not create the configuration directory: a missing `/etc/furcate` means the
/// package is not installed, and quietly conjuring an empty one would turn that
/// into a system with no rules rather than an obvious mistake.
pub fn ensure_state() -> std::io::Result<PathBuf> {
    let d = state_dir();
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// Everything resolved, for a diagnostic that answers "where is it actually
/// looking" without anybody having to reason about precedence.
pub fn describe() -> Vec<(&'static str, String)> {
    vec![
        ("state", state_dir().display().to_string()),
        ("config", config_dir().display().to_string()),
        ("runtime", runtime_dir().display().to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test here mutates the process environment, so they share one lock
    /// rather than racing. This codebase has learned that three times by
    /// shipping tests that passed alone and failed together.
    fn guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn clear() {
        for v in [
            "FURCATE_STATE_DIR",
            "FURCATE_CONFIG_DIR",
            "FURCATE_RUNTIME_DIR",
            "STATE_DIRECTORY",
            "CONFIGURATION_DIRECTORY",
            "RUNTIME_DIRECTORY",
        ] {
            // SAFETY: guarded by the mutex above; no other thread reads the
            // environment while a test holds it.
            unsafe { std::env::remove_var(v) };
        }
    }

    #[test]
    fn the_defaults_are_fhs_and_contain_no_home() {
        let _g = guard();
        clear();
        assert_eq!(state_dir(), PathBuf::from("/var/lib/furcate"));
        assert_eq!(config_dir(), PathBuf::from("/etc/furcate"));
        assert_eq!(runtime_dir(), PathBuf::from("/run/furcate"));
        for (_, p) in describe() {
            assert!(!p.contains("/home/"), "{p} looks like somebody's home");
        }
    }

    #[test]
    fn systemd_beats_the_compiled_default() {
        // In production the unit file should be the single source of truth. A
        // binary that disagreed with its own unit about where state lives is a
        // bug nobody enjoys finding.
        let _g = guard();
        clear();
        unsafe { std::env::set_var("STATE_DIRECTORY", "/var/lib/somewhere-else") };
        assert_eq!(state_dir(), PathBuf::from("/var/lib/somewhere-else"));
        clear();
    }

    #[test]
    fn an_explicit_override_beats_systemd() {
        // So the whole system can be run out of a scratch directory without
        // root, which is the only way the tests below this one work at all.
        let _g = guard();
        clear();
        unsafe {
            std::env::set_var("STATE_DIRECTORY", "/var/lib/from-systemd");
            std::env::set_var("FURCATE_STATE_DIR", "/tmp/from-operator");
        }
        assert_eq!(state_dir(), PathBuf::from("/tmp/from-operator"));
        clear();
    }

    #[test]
    fn a_list_of_directories_takes_the_first() {
        // systemd sets a colon-separated list when a unit declares several.
        // The first is the one named after the unit, which is the one meant.
        let _g = guard();
        clear();
        unsafe { std::env::set_var("RUNTIME_DIRECTORY", "/run/furcate:/run/furcate-extra") };
        assert_eq!(runtime_dir(), PathBuf::from("/run/furcate"));
        clear();
    }

    #[test]
    fn an_empty_variable_is_not_a_path() {
        // An unset variable and one set to nothing look identical to a shell
        // and would otherwise resolve every path to the filesystem root.
        let _g = guard();
        clear();
        unsafe {
            std::env::set_var("FURCATE_STATE_DIR", "   ");
            std::env::set_var("STATE_DIRECTORY", "");
        }
        assert_eq!(state_dir(), PathBuf::from("/var/lib/furcate"));
        clear();
    }

    #[test]
    fn named_files_land_under_the_right_directory() {
        let _g = guard();
        clear();
        assert_eq!(state("ledger.json"), PathBuf::from("/var/lib/furcate/ledger.json"));
        assert_eq!(config("policy.yaml"), PathBuf::from("/etc/furcate/policy.yaml"));
        assert_eq!(runtime("wg.json"), PathBuf::from("/run/furcate/wg.json"));
    }

    #[test]
    fn state_and_config_are_never_the_same_place() {
        // One is replaced by the package manager and one must never be. A
        // layout that merged them would eventually lose an identity key to an
        // upgrade.
        let _g = guard();
        clear();
        assert_ne!(state_dir(), config_dir());
        assert_ne!(state_dir(), runtime_dir());
    }

    #[test]
    fn ensuring_state_does_not_conjure_a_config_directory() {
        // A missing /etc/furcate means the package is not installed. Creating
        // an empty one would turn that into a system with no rules rather than
        // an obvious mistake.
        let _g = guard();
        clear();
        let tmp = std::env::temp_dir().join("furcate-paths-test/state");
        let cfg = std::env::temp_dir().join("furcate-paths-test/config-should-not-appear");
        let _ = std::fs::remove_dir_all(tmp.parent().unwrap());
        unsafe {
            std::env::set_var("FURCATE_STATE_DIR", &tmp);
            std::env::set_var("FURCATE_CONFIG_DIR", &cfg);
        }
        ensure_state().expect("state directory is created");
        assert!(tmp.exists());
        assert!(!cfg.exists(), "config must not be created implicitly");
        clear();
    }
}
