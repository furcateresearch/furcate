//! What somebody did while they held authority.
//!
//! `furcate-policy` decides who may act, `furcate-breakglass` covers acting
//! when the deciding machinery is unreachable, and neither leaves any account
//! of what was actually done afterwards. For ordinary work that is tolerable.
//! For an emergency grant taken at 3am by one person with nobody watching, the
//! record *is* the control — it is the only reason the person taking it behaves
//! as though someone is looking, and the only way anybody can answer "what
//! happened" the next morning.
//!
//! ## Commands, not keystrokes
//!
//! The obvious implementation records the terminal. It is the wrong one, and
//! not for storage reasons.
//!
//! A keystroke or PTY recorder captures the password typed at a `sudo` prompt,
//! the passphrase for a key, and the token pasted from a password manager. The
//! recording then holds live credentials, which means it needs the protection
//! of a secret store while being read by exactly the people an audit exists to
//! examine. Every system that has tried this has ended up either redacting so
//! aggressively the record says nothing, or quietly holding a file full of
//! passwords.
//!
//! Recording *actions* avoids the problem at the source rather than cleaning up
//! after it. "Ran `systemctl restart furcate-edge`, exit 0" answers the audit
//! question completely and never had the password in it to begin with.
//! [`redact`] exists as a second line for arguments that carry secrets anyway,
//! and it is explicitly not the primary defence.
//!
//! ## A chain detects edits. It does not detect truncation.
//!
//! The property worth being precise about, because it is where session
//! recording is usually oversold.
//!
//! Hash-chaining every event means no entry can be altered, reordered or
//! removed from the middle without breaking every hash after it. What it cannot
//! catch on its own is somebody dropping the *last* few entries: a chain with
//! its tail cut off is a perfectly valid shorter chain, and the interesting
//! entries are always at the end.
//!
//! The only fix is to publish the head somewhere the recorded party cannot
//! reach, and then compare. So [`Session::anchor`] hands out that head, and
//! [`Recording::verify_against`] is the check that actually detects truncation
//! — while [`Recording::verify`] alone honestly reports only that what remains
//! is internally consistent. Two different assurances, and collapsing them into
//! one "verified" is how a truncated recording passes an audit.
//!
//! ## Recording that fails has to stop the session
//!
//! If events cannot be committed, the choice is to carry on unrecorded or to
//! end the session. Carrying on is worse: it produces a record that looks
//! complete, covers part of the work, and gives false confidence precisely
//! where confidence matters most. [`Session::broken`] latches, and
//! [`Session::must_stop`] says so.

pub mod ssh;

use furcate_ledger::{Chain, ChainError, OpKind};
use serde::{Deserialize, Serialize};

/// One thing that was done.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// What was invoked, already redacted.
    pub command: String,
    /// What it was done to — a host, a unit, a file — where that is separable.
    pub target: Option<String>,
    /// How it ended, in the caller's vocabulary. An exit status, "refused",
    /// "timed out".
    pub outcome: String,
}

impl Action {
    pub fn new(command: impl Into<String>, outcome: impl Into<String>) -> Self {
        Action {
            command: redact(&command.into()),
            target: None,
            outcome: outcome.into(),
        }
    }

    pub fn on(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

/// Flags whose *value* is a secret.
///
/// Deliberately short and lowercase-compared. A long list invites the belief
/// that this is the defence, and it is not — recording commands rather than
/// keystrokes is. This catches the cases where a secret was passed as an
/// argument anyway, which is a mistake in the command rather than in the
/// recorder.
const SECRET_FLAGS: &[&str] = &[
    "--password",
    "--passwd",
    "--token",
    "--secret",
    "--api-key",
    "--apikey",
    "--private-key",
    "-p",
];

/// Environment-style assignments whose value is a secret.
const SECRET_ASSIGNMENTS: &[&str] = &[
    "password=",
    "passwd=",
    "token=",
    "secret=",
    "api_key=",
    "apikey=",
    "pgpassword=",
];

/// The placeholder left in a redacted position.
///
/// Something is left behind rather than the text being deleted, because a
/// record that silently omits an argument reads as a command that did not have
/// one — and reconstructing what was actually run is the whole point.
pub const REDACTED: &str = "[redacted]";

/// Remove argument values that carry secrets.
///
/// A second line of defence, not the first. See the module header: the reason
/// this can be modest is that a command recorder never had the password from
/// the `sudo` prompt in the first place.
pub fn redact(command: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redact_next = false;
    for word in command.split_whitespace() {
        if redact_next {
            out.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }
        let lower = word.to_ascii_lowercase();

        // `--token=abc` and `PGPASSWORD=abc`, where the value is attached.
        if let Some(eq) = word.find('=') {
            let (key, _) = word.split_at(eq + 1);
            let key_lower = key.to_ascii_lowercase();
            let is_secret = SECRET_ASSIGNMENTS.iter().any(|a| key_lower.ends_with(a))
                || SECRET_FLAGS
                    .iter()
                    .any(|f| key_lower.starts_with(&format!("{f}=")));
            if is_secret {
                out.push(format!("{key}{REDACTED}"));
                continue;
            }
        }

        // `--token abc`, where the value is the next word.
        if SECRET_FLAGS.iter().any(|f| lower == *f) {
            out.push(word.to_string());
            redact_next = true;
            continue;
        }

        out.push(word.to_string());
    }
    // A trailing secret flag with nothing after it. Recorded as redacted rather
    // than dropped, so the record does not imply the flag took no value.
    if redact_next {
        out.push(REDACTED.to_string());
    }
    out.join(" ")
}

/// Why a session can no longer be trusted to be recording.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Broken {
    /// An action could not be committed to the chain.
    NotCommitted { at: u64 },
    /// Something was attempted after the session was closed.
    AlreadyClosed { closed_at: u64 },
}

/// A session being recorded.
#[derive(Clone, Debug)]
pub struct Session {
    id: String,
    actor: String,
    authority: String,
    opened_at: u64,
    chain: Chain,
    closed_at: Option<u64>,
    broken: Option<Broken>,
}

impl Session {
    /// Open a session under a named authority.
    ///
    /// `authority` is the grant or break-glass nonce this runs under, committed
    /// as the first entry so the record cannot later be attached to a different
    /// permission than the one it was taken with.
    pub fn open(
        id: impl Into<String>,
        actor: impl Into<String>,
        authority: impl Into<String>,
        at: u64,
    ) -> Self {
        let (id, actor, authority) = (id.into(), actor.into(), authority.into());
        let mut chain = Chain::new();
        chain.append(
            at,
            OpKind::Session,
            actor.clone(),
            format!("session:{id}"),
            format!("opened under {authority}"),
        );
        Session {
            id,
            actor,
            authority,
            opened_at: at,
            chain,
            closed_at: None,
            broken: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The current head, to be published where the recorded party cannot reach.
    ///
    /// The only thing that makes truncation detectable. Worth publishing more
    /// than once during a long session: an anchor taken at the start proves
    /// only that the session began.
    pub fn anchor(&self) -> Option<[u8; 32]> {
        self.chain.head()
    }

    /// Whether recording has failed, and the session must therefore end.
    ///
    /// Carrying on unrecorded produces a record that looks complete and covers
    /// part of the work, which is worse than no record at all in the one place
    /// it matters.
    pub fn must_stop(&self) -> bool {
        self.broken.is_some()
    }

    pub fn broken(&self) -> Option<&Broken> {
        self.broken.as_ref()
    }

    /// Commit one action.
    pub fn record(&mut self, at: u64, action: Action) -> Result<(), Broken> {
        if let Some(b) = &self.broken {
            return Err(b.clone());
        }
        if let Some(closed_at) = self.closed_at {
            let b = Broken::AlreadyClosed { closed_at };
            self.broken = Some(b.clone());
            return Err(b);
        }
        let subject = match &action.target {
            Some(t) => format!("{} :: {}", action.command, t),
            None => action.command.clone(),
        };
        self.chain
            .append(at, OpKind::Session, self.actor.clone(), subject, action.outcome);
        Ok(())
    }

    /// Close the session and produce the recording.
    pub fn close(mut self, at: u64) -> Recording {
        if self.closed_at.is_none() {
            self.chain.append(
                at,
                OpKind::Session,
                self.actor.clone(),
                format!("session:{}", self.id),
                "closed",
            );
            self.closed_at = Some(at);
        }
        Recording {
            id: self.id,
            actor: self.actor,
            authority: self.authority,
            opened_at: self.opened_at,
            closed_at: self.closed_at,
            broken: self.broken,
            chain: self.chain,
        }
    }
}

/// A finished session.
#[derive(Clone, Debug)]
pub struct Recording {
    pub id: String,
    pub actor: String,
    pub authority: String,
    pub opened_at: u64,
    /// `None` when the session ended without being closed — a crash, a dropped
    /// connection, or a recorder that broke. Distinct from a closed session
    /// with no actions, and it is the more suspicious of the two.
    pub closed_at: Option<u64>,
    pub broken: Option<Broken>,
    chain: Chain,
}

/// What a verification established, or failed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Untrusted {
    /// The chain itself does not hold together.
    Altered(String),
    /// The chain is internally consistent and does not end where it should.
    ///
    /// The truncation case. Everything that remains is genuine; entries have
    /// been removed from the end.
    Truncated,
    /// Recording had already failed while the session was still running, so
    /// the record is known to be incomplete regardless of what it contains.
    Incomplete(Broken),
}

impl Recording {
    /// How many actions were committed, not counting open and close.
    pub fn actions(&self) -> usize {
        self.chain.len().saturating_sub(if self.closed_at.is_some() { 2 } else { 1 })
    }

    pub fn entries(&self) -> &[furcate_ledger::Op] {
        self.chain.entries()
    }

    pub fn head(&self) -> Option<[u8; 32]> {
        self.chain.head()
    }

    /// Check the record is internally consistent.
    ///
    /// This is the weaker of the two checks and says so in its name-adjacent
    /// documentation rather than in its result: passing here means nothing was
    /// altered or reordered, and says **nothing** about whether entries were
    /// removed from the end. Use [`Self::verify_against`] wherever an anchor
    /// exists.
    pub fn verify(&self) -> Result<(), Untrusted> {
        if let Some(b) = &self.broken {
            return Err(Untrusted::Incomplete(b.clone()));
        }
        self.chain
            .verify()
            .map_err(|e: ChainError| Untrusted::Altered(format!("{e:?}")))
    }

    /// Check the record against a head published elsewhere.
    ///
    /// The check that detects a tail being cut off. An anchor taken partway
    /// through a session proves everything up to that point survived; the
    /// entries after it are still only as trustworthy as the storage.
    pub fn verify_against(&self, anchor: &[u8; 32]) -> Result<(), Untrusted> {
        self.verify()?;
        if self.chain.entries().iter().any(|op| &op.hash == anchor) {
            Ok(())
        } else {
            Err(Untrusted::Truncated)
        }
    }
}

/// Persist a session so it survives the process that is recording it.
///
/// The chain is the whole record. Identity, actor and authority are recovered
/// from its first entry rather than stored beside it, so there is no second
/// copy of those facts that could disagree with the one that is hashed — a
/// sidecar naming a different authority than the chain commits to would be
/// exactly the kind of discrepancy an audit cannot resolve.
pub fn save(session: &Session, path: &std::path::Path) -> Result<(), furcate_ledger::StoreError> {
    furcate_ledger::store::save(&session.chain, path)
}

/// Persist a finished recording, including its closing entry.
///
/// Separate from [`save`] because closing consumes the session — the closing
/// entry is part of the record, and a caller that saved before closing would
/// leave a session that looks abandoned rather than finished.
pub fn save_recording(
    recording: &Recording,
    path: &std::path::Path,
) -> Result<(), furcate_ledger::StoreError> {
    furcate_ledger::store::save(&recording.chain, path)
}

/// Resume a session from disk, or `None` when there is nothing there.
///
/// The load verifies the chain, so a record altered on disk fails here rather
/// than being appended to — continuing a tampered session would launder the
/// tampering behind genuine later entries.
///
/// A session that was already closed comes back closed and refuses further
/// actions, rather than silently reopening.
pub fn resume(path: &std::path::Path) -> Result<Option<Session>, furcate_ledger::StoreError> {
    let Some(chain) = furcate_ledger::store::load(path)? else {
        return Ok(None);
    };
    let entries = chain.entries();
    let Some(first) = entries.first() else {
        return Ok(None);
    };
    let id = first.subject.strip_prefix("session:").unwrap_or(&first.subject).to_string();
    let authority = first
        .result
        .strip_prefix("opened under ")
        .unwrap_or(&first.result)
        .to_string();
    let closed_at = entries
        .iter()
        .rev()
        .find(|e| e.result == "closed")
        .map(|e| e.ts_ms);
    Ok(Some(Session {
        id,
        actor: first.actor.clone(),
        authority,
        opened_at: first.ts_ms,
        chain,
        closed_at,
        broken: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::open("s1", "oncall", "breakglass:n1", 1_000)
    }

    #[test]
    fn a_session_survives_the_process_recording_it() {
        let dir = std::env::temp_dir().join(format!("furcate-session-{}", std::process::id()));
        let path = dir.join("s1.json");
        let _ = std::fs::remove_file(&path);

        let mut s = session();
        s.record(1_010, Action::new("systemctl restart edge", "exit 0").on("node-a"))
            .expect("recorded");
        save(&s, &path).expect("saved");

        let mut back = resume(&path).expect("readable").expect("present");
        // Recovered from the chain itself, not from anything stored beside it.
        assert_eq!(back.id(), "s1");
        assert_eq!(back.actor(), "oncall");
        assert_eq!(back.authority(), "breakglass:n1");

        back.record(1_020, Action::new("journalctl -u edge", "exit 0"))
            .expect("still recording");
        let r = back.close(1_030);
        assert_eq!(r.actions(), 2, "the earlier action survived the round trip");
        assert!(r.verify().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_closed_session_does_not_silently_reopen() {
        let dir = std::env::temp_dir().join(format!("furcate-session-c-{}", std::process::id()));
        let path = dir.join("s2.json");
        let _ = std::fs::remove_file(&path);

        let mut s = session();
        s.record(1_010, Action::new("step", "exit 0")).expect("recorded");
        let closed = s.close(1_020);
        furcate_ledger::store::save(&closed.chain, &path).expect("saved");

        let mut back = resume(&path).expect("readable").expect("present");
        assert!(
            back.record(1_030, Action::new("after", "exit 0")).is_err(),
            "a closed session must not accept more"
        );
        assert!(back.must_stop());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn nothing_on_disk_is_not_an_error() {
        let path = std::env::temp_dir().join("furcate-session-absent-does-not-exist.json");
        assert!(resume(&path).expect("readable").is_none());
    }

    #[test]
    fn a_session_commits_what_was_done() {
        let mut s = session();
        s.record(1_010, Action::new("systemctl restart furcate-edge", "exit 0").on("node-a"))
            .expect("recorded");
        s.record(1_020, Action::new("journalctl -u furcate-edge", "exit 0"))
            .expect("recorded");
        let r = s.close(1_030);
        assert_eq!(r.actions(), 2);
        assert!(r.verify().is_ok());
        assert_eq!(r.closed_at, Some(1_030));
    }

    #[test]
    fn the_authority_is_committed_so_a_record_cannot_be_reattached() {
        let r = session().close(1_100);
        let opened = &r.entries()[0];
        assert!(opened.result.contains("breakglass:n1"), "{:?}", opened);
        assert_eq!(r.authority, "breakglass:n1");
    }

    #[test]
    fn a_password_typed_at_a_prompt_was_never_in_the_record() {
        // The reason this records actions rather than keystrokes. There is no
        // redaction step here at all — the secret never entered.
        let mut s = session();
        s.record(1_010, Action::new("sudo -k systemctl restart nginx", "exit 0"))
            .expect("recorded");
        let r = s.close(1_020);
        let all: String = r.entries().iter().map(|e| e.subject.clone()).collect();
        assert!(!all.contains("hunter2"));
    }

    #[test]
    fn a_secret_passed_as_an_argument_is_redacted_anyway() {
        // The second line of defence, for a mistake in the command rather than
        // in the recorder.
        assert_eq!(
            redact("psql --password hunter2 --host db"),
            "psql --password [redacted] --host db"
        );
        assert_eq!(
            redact("curl --token=abc123 https://example"),
            "curl --token=[redacted] https://example"
        );
        assert_eq!(
            redact("PGPASSWORD=hunter2 psql"),
            "PGPASSWORD=[redacted] psql"
        );
    }

    #[test]
    fn redaction_leaves_a_placeholder_rather_than_deleting_the_argument() {
        // A record that silently omits a value reads as a command that did not
        // take one, and reconstructing what was run is the whole point.
        let out = redact("app --secret");
        assert_eq!(out, "app --secret [redacted]", "trailing flag still shows");
        assert!(redact("ls -la /var/log").contains("-la"), "ordinary flags survive");
    }

    #[test]
    fn an_action_is_redacted_when_it_is_constructed() {
        // So a caller cannot forget to.
        let a = Action::new("psql --password hunter2", "exit 0");
        assert!(!a.command.contains("hunter2"));
    }

    #[test]
    fn every_action_is_linked_to_the_one_before_it() {
        // What makes an edit detectable at all: each entry commits to its
        // predecessor's hash, so altering or reordering one breaks every hash
        // after it. That the chain enforces this is furcate-ledger's own
        // property and is tested there; what is checked here is that a session
        // actually builds one rather than keeping a plain list beside it.
        let mut s = session();
        for i in 0..4 {
            s.record(1_010 + i, Action::new(format!("step{i}"), "exit 0"))
                .expect("recorded");
        }
        let r = s.close(1_100);

        let entries = r.entries();
        assert_eq!(entries.len(), 6, "open, four actions, close");
        for pair in entries.windows(2) {
            assert_eq!(pair[1].prev, pair[0].hash, "each entry commits to the last");
        }
        assert!(r.verify().is_ok());
    }

    #[test]
    fn an_anchor_from_a_different_session_proves_nothing() {
        // verify_against must not accept just any hash. A recording checked
        // against somebody else's anchor would pass while having been
        // truncated to nothing.
        let mut mine = session();
        mine.record(1_010, Action::new("step", "exit 0")).expect("recorded");
        let mine = mine.close(1_100);

        let mut other = Session::open("s2", "someone-else", "grant:g9", 2_000);
        other.record(2_010, Action::new("step", "exit 0")).expect("recorded");
        let foreign = other.anchor().expect("head");

        assert_eq!(mine.verify_against(&foreign), Err(Untrusted::Truncated));
        assert!(mine.verify_against(&mine.head().expect("head")).is_ok());
    }

    #[test]
    fn a_chain_alone_cannot_prove_the_end_was_not_cut_off() {
        // The property this module is careful about. A truncated chain is a
        // valid shorter chain, and the interesting entries are at the end.
        let mut s = session();
        let early = s.anchor().expect("head after opening");
        for i in 0..4 {
            s.record(1_010 + i, Action::new(format!("step{i}"), "exit 0"))
                .expect("recorded");
        }
        let late = s.anchor().expect("head");
        let full = s.close(1_100);

        // Everything present: both anchors are found.
        assert!(full.verify().is_ok());
        assert!(full.verify_against(&early).is_ok());
        assert!(full.verify_against(&late).is_ok());

        // Now cut the tail off. The remainder still verifies on its own — which
        // is exactly why `verify` alone must not be read as "nothing was
        // removed".
        let mut short = Session::open("s1", "oncall", "breakglass:n1", 1_000);
        short.record(1_010, Action::new("step0", "exit 0")).expect("recorded");
        let cut = short.close(1_100);
        assert!(cut.verify().is_ok(), "a truncated record is internally consistent");
        assert_eq!(
            cut.verify_against(&late),
            Err(Untrusted::Truncated),
            "and only an external anchor catches it"
        );
    }

    #[test]
    fn a_broken_recorder_stops_the_session() {
        // Carrying on unrecorded produces a record that looks complete and
        // covers part of the work.
        let r = session().close(1_050);
        assert!(r.verify().is_ok());

        let mut s2 = session();
        s2.closed_at = Some(1_040);
        let err = s2
            .record(1_050, Action::new("late", "exit 0"))
            .expect_err("after close");
        assert_eq!(err, Broken::AlreadyClosed { closed_at: 1_040 });
        assert!(s2.must_stop(), "and it latches");
        assert!(
            s2.record(1_060, Action::new("later", "exit 0")).is_err(),
            "it does not recover on its own"
        );
    }

    #[test]
    fn a_known_incomplete_record_never_verifies() {
        let mut s = session();
        s.closed_at = Some(1_040);
        let _ = s.record(1_050, Action::new("late", "exit 0"));
        let r = s.close(1_100);
        assert!(
            matches!(r.verify(), Err(Untrusted::Incomplete(_))),
            "{:?}",
            r.verify()
        );
    }

    #[test]
    fn a_session_that_was_never_closed_is_distinguishable_from_an_empty_one() {
        // The more suspicious of the two.
        let s = session();
        assert_eq!(s.closed_at, None);
        let closed = session().close(1_010);
        assert_eq!(closed.closed_at, Some(1_010));
        assert_eq!(closed.actions(), 0);
    }
}
