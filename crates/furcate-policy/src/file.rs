//! Where the site's written authority is read from.
//!
//! This lives in the library rather than in one binary because more than one
//! program now rules a request against it: the agent admits overlay peers,
//! and `furcate deploy` asks whether a site may be placed. Two copies of the
//! resolution order would be two answers to "what is permitted here", and the
//! one that loses is whichever file the reader did not open.
//!
//! The rules the callers must not soften, and the reason each exists:
//!
//! - **Absent is ordinary.** A machine with no policy file falls through to
//!   the compiled defaults, which is a supported way to run.
//! - **Present and unreadable is fatal.** Falling back to defaults would
//!   restore authority an operator had written down a decision to remove, and
//!   a file this process cannot read is not evidence they changed their mind.
//!   A directory mode of 0700 is enough to cause it, and did on node-b.
//! - **Present and unparseable is fatal**, for the same reason.

use crate::PolicySet;

/// Why a policy file could not be turned into a decision.
#[derive(Debug)]
pub enum LoadError {
    Unreadable { path: String, why: String },
    Unparseable { path: String, why: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Unreadable { path, why } => {
                write!(f, "policy {path} exists and cannot be read: {why}")
            }
            LoadError::Unparseable { path, why } => {
                write!(f, "policy {path} is unparseable: {why}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// What was used, so a caller can say so rather than leaving an operator to
/// guess which of the candidates answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    File(String),
    CompiledDefault,
}

/// Read the first policy file that exists, in order.
///
/// `candidates` is passed in so this function has no opinion about the
/// filesystem and can be tested; [`default_candidates`] supplies the real
/// order.
pub fn load_from(candidates: &[String]) -> Result<(PolicySet, Source), LoadError> {
    for path in candidates {
        if path.is_empty() {
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(LoadError::Unreadable {
                    path: path.clone(),
                    why: e.to_string(),
                })
            }
        };
        return match PolicySet::parse(&text) {
            Ok(p) => Ok((p, Source::File(path.clone()))),
            Err(e) => Err(LoadError::Unparseable {
                path: path.clone(),
                why: e,
            }),
        };
    }
    Ok((PolicySet::compiled_default(), Source::CompiledDefault))
}

/// The real resolution order.
pub fn default_candidates(config_path: &str) -> Vec<String> {
    vec![
        std::env::var("FURCATE_OVERLAY_POLICY").unwrap_or_default(),
        config_path.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_candidate_present_falls_through_to_the_compiled_default() {
        let (_, src) = load_from(&["/nonexistent/furcate/policy.yaml".into()]).unwrap();
        assert_eq!(src, Source::CompiledDefault);
    }

    #[test]
    fn an_empty_candidate_is_skipped_rather_than_treated_as_a_path() {
        // The env var is empty when unset, and reading "" must not become an
        // error that stops a machine with no override configured.
        let (_, src) = load_from(&[String::new(), "/nonexistent/x.yaml".into()]).unwrap();
        assert_eq!(src, Source::CompiledDefault);
    }

    #[test]
    fn an_unparseable_file_is_fatal_rather_than_falling_back() {
        let dir = std::env::temp_dir().join(format!("furcate-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.yaml");
        std::fs::write(&p, "policies: [ this is not a rule").unwrap();
        let e = load_from(&[p.display().to_string()]).unwrap_err();
        assert!(matches!(e, LoadError::Unparseable { .. }));
        // Falling back here would restore authority somebody removed.
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_first_candidate_that_exists_wins() {
        let dir = std::env::temp_dir().join(format!("furcate-policy-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("first.yaml");
        std::fs::write(
            &first,
            "policies:\n  - effect: allow\n    principal: operator\n    action: deploy\n    resource: '*'\n    reason: test\n",
        )
        .unwrap();
        let (set, src) = load_from(&[
            first.display().to_string(),
            "/nonexistent/second.yaml".into(),
        ])
        .unwrap();
        assert_eq!(set.policies.len(), 1);
        assert_eq!(src, Source::File(first.display().to_string()));
        std::fs::remove_dir_all(&dir).ok();
    }
}
