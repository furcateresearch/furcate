//! The site's written authority, read once.
//!
//! The resolution order and the three outcomes — absent is ordinary, present
//! and unreadable is fatal, present and unparseable is fatal — now live in
//! `furcate_policy::file`, because `furcate deploy` rules against the same
//! file and two implementations would be two answers to "what is permitted
//! here". What stays here is this binary's response to a fatal one: a daemon
//! that cannot know what is permitted must not start.

pub fn load() -> furcate_policy::PolicySet {
    let candidates = furcate_policy::file::default_candidates(
        &furcate_paths::config("overlay-policy.yaml").display().to_string(),
    );
    match furcate_policy::file::load_from(&candidates) {
        Ok((p, furcate_policy::file::Source::File(path))) => {
            eprintln!("furcated: policy from {path} ({} rules)", p.policies.len());
            p
        }
        Ok((p, furcate_policy::file::Source::CompiledDefault)) => p,
        Err(e) => {
            eprintln!("furcated: FATAL {e}");
            std::process::exit(1);
        }
    }
}
