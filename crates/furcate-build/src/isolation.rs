//! Isolation: running the action, and collecting what it produced.
//!
//! Two backends behind one trait. The distinction the design note draws is that
//! a container is not a sandbox: a fresh microVM per action, destroyed after,
//! is what makes running code on your own metal defensible. That backend is a
//! seam here -- it belongs to step 4 and needs Linux and KVM -- and until it is
//! wired, `MicroVm::run` refuses rather than pretending a weaker boundary is
//! the strong one.
//!
//! `ProcessSandbox` is the runnable backend used to prove the earlier steps:
//! the action runs as a child process, in the work directory, with only the
//! environment the action declared, and every declared output is collected into
//! the content store by digest. A declared output the action did not produce is
//! an error, not a silently empty artifact.

use crate::action::BuildAction;
use crate::cas::Cas;
use crate::digest::Digest;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::process::Command;

/// What a run produced.
#[derive(Debug)]
pub struct RunReport {
    /// Whether the command exited successfully.
    pub ok: bool,
    /// Declared output path -> content digest, ingested into the store.
    pub outputs: BTreeMap<String, Digest>,
}

/// A way to run a build action under some isolation.
pub trait Isolation {
    fn run(
        &self,
        action: &BuildAction,
        work_dir: &Path,
        cas: &Cas,
    ) -> Result<RunReport, IsolationError>;
}

/// Runs the action as a child process with a scrubbed environment.
///
/// This does not give a kernel boundary; it is the backend for proving the
/// stores and cache are correct. The hard network and filesystem boundary is
/// the microVM's job, which is why network denial here is advisory: the action
/// still carries its network posture into the provenance, but the guarantee
/// that a denied action truly could not reach the network is `MicroVm`'s.
pub struct ProcessSandbox;

impl Isolation for ProcessSandbox {
    fn run(
        &self,
        action: &BuildAction,
        work_dir: &Path,
        cas: &Cas,
    ) -> Result<RunReport, IsolationError> {
        let (program, args) = action
            .command
            .split_first()
            .ok_or(IsolationError::EmptyCommand)?;

        let status = Command::new(program)
            .args(args)
            .current_dir(work_dir)
            .env_clear()
            .envs(&action.env)
            .status()
            .map_err(IsolationError::Spawn)?;

        // Collect declared outputs into the store, whatever the exit status --
        // a failed build has no outputs to collect, which the caller sees as an
        // empty set alongside `ok = false`.
        let mut outputs = BTreeMap::new();
        if status.success() {
            for rel in &action.outputs {
                let path = work_dir.join(rel);
                let digest = cas.put_path(&path).map_err(|e| match e.kind() {
                    io::ErrorKind::NotFound => IsolationError::MissingOutput(rel.clone()),
                    _ => IsolationError::Io(e),
                })?;
                outputs.insert(rel.clone(), digest);
            }
        }

        Ok(RunReport {
            ok: status.success(),
            outputs,
        })
    }
}

/// The microVM backend -- one fresh VM per action, destroyed afterward.
///
/// This is the seam for design-note step 4. It is not wired to a hypervisor
/// yet, and it refuses rather than falling back to a weaker boundary, because a
/// build that thinks it ran isolated when it did not is worse than one that
/// declined to run.
pub struct MicroVm;

impl Isolation for MicroVm {
    fn run(
        &self,
        _action: &BuildAction,
        _work_dir: &Path,
        _cas: &Cas,
    ) -> Result<RunReport, IsolationError> {
        Err(IsolationError::Unsupported(
            "microVM backend not yet wired; run on a KVM host or use ProcessSandbox",
        ))
    }
}

#[derive(Debug)]
pub enum IsolationError {
    EmptyCommand,
    Spawn(io::Error),
    MissingOutput(String),
    Io(io::Error),
    Unsupported(&'static str),
}

impl std::fmt::Display for IsolationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationError::EmptyCommand => write!(f, "action has no command"),
            IsolationError::Spawn(e) => write!(f, "could not start the action: {e}"),
            IsolationError::MissingOutput(o) => {
                write!(f, "action did not produce declared output '{o}'")
            }
            IsolationError::Io(e) => write!(f, "isolation io: {e}"),
            IsolationError::Unsupported(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for IsolationError {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::action::Network;
    use std::fs;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fcbuild-iso-{tag}-{}-{:?}", std::process::id(), std::time::SystemTime::now()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn action(cmd: Vec<&str>, outputs: Vec<&str>) -> BuildAction {
        let mut inputs = BTreeMap::new();
        inputs.insert("src".to_string(), Digest::of(b"src"));
        BuildAction {
            target: "x86_64-linux".into(),
            inputs,
            command: cmd.into_iter().map(String::from).collect(),
            env: BTreeMap::new(),
            outputs: outputs.into_iter().map(String::from).collect(),
            network: Network::Denied,
        }
    }

    #[test]
    fn runs_and_collects_output() {
        let work = temp_dir("run");
        let cas = Cas::open(temp_dir("cas")).unwrap();
        // Write a file named `artifact` containing a known string.
        let a = action(vec!["sh", "-c", "printf hello > artifact"], vec!["artifact"]);
        let report = ProcessSandbox.run(&a, &work, &cas).unwrap();
        assert!(report.ok);
        let d = report.outputs.get("artifact").unwrap();
        assert_eq!(*d, Digest::of(b"hello"));
        assert_eq!(cas.get(d).unwrap(), b"hello");
    }

    #[test]
    fn a_missing_declared_output_is_an_error() {
        let work = temp_dir("miss");
        let cas = Cas::open(temp_dir("cas2")).unwrap();
        let a = action(vec!["true"], vec!["never-written"]);
        assert!(matches!(
            ProcessSandbox.run(&a, &work, &cas),
            Err(IsolationError::MissingOutput(_))
        ));
    }

    #[test]
    fn microvm_refuses_rather_than_weakening() {
        let work = temp_dir("vm");
        let cas = Cas::open(temp_dir("cas3")).unwrap();
        let a = action(vec!["true"], vec![]);
        assert!(matches!(
            MicroVm.run(&a, &work, &cas),
            Err(IsolationError::Unsupported(_))
        ));
    }
}
