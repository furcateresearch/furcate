//! Adding a domain, from a name somebody typed to a name that serves.
//!
//! Deploying assumed the DNS already pointed here and the name was yours. Both
//! were true because the same person had done it by hand five minutes earlier,
//! and neither was recorded anywhere. A name that does not resolve looked
//! exactly like a name that was never added.
//!
//! ## The steps, and why each one exists
//!
//! **Added.** The intent, written down. A domain somebody meant to serve and
//! has not finished setting up is a real state, and the only alternative to
//! recording it is remembering it.
//!
//! **Records issued.** What to create, and where to point it. The answer
//! depends on how this cluster is reached and an operator should not have to
//! derive it — most of the failures here are a record pointing at the wrong
//! address, made by somebody guessing.
//!
//! **Verified.** The name resolves to somewhere that reaches this cluster.
//! Checked rather than asserted: control of a name is the one claim that
//! decides whether a certificate should ever be requested for it, and a
//! certificate authority will check it too, less forgivingly and with a rate
//! limit attached.
//!
//! **Mapped.** Which site serves it. A verified name with nothing behind it
//! answers nothing, so this is the step that makes it real.
//!
//! ## Why the gate reads this rather than the deploy
//!
//! `/tls/allow` decides whether a certificate may be requested. Asking it to
//! consult a name's verification state means an unverified name is refused
//! *with a reason* instead of failing at the certificate authority, where the
//! error arrives as a rate limit and a stranger's log line.

use serde::{Deserialize, Serialize};

/// How far along a domain is.
///
/// Ordered, and every transition is forward: a name does not become unverified
/// because a check failed once, because a resolver having a bad minute is not
/// evidence that somebody lost control of a domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Somebody said they want this name here.
    Added,
    /// The records to create have been worked out and shown.
    RecordsIssued,
    /// The name resolves somewhere that reaches this cluster.
    Verified,
    /// A site on this machine answers for it.
    Mapped,
}

impl Step {
    pub fn as_str(&self) -> &'static str {
        match self {
            Step::Added => "added",
            Step::RecordsIssued => "records issued",
            Step::Verified => "verified",
            Step::Mapped => "mapped",
        }
    }

    /// What the operator has to do next, in words they can act on.
    pub fn next(&self) -> &'static str {
        match self {
            Step::Added => "work out the records this name needs",
            Step::RecordsIssued => "create the records, then verify",
            Step::Verified => "map it to a site on this machine",
            Step::Mapped => "nothing — it is serving",
        }
    }
}

/// A domain on its way to serving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    pub name: String,
    pub step: Step,
    /// The site that answers for it, once mapped.
    #[serde(default)]
    pub site: Option<String>,
    /// What verification last saw, kept whether it passed or failed. A failure
    /// nobody can read is a failure somebody will retry unchanged.
    #[serde(default)]
    pub last_check: Option<String>,
}

/// A record an operator has to create.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Record {
    pub kind: &'static str,
    pub name: String,
    pub value: String,
    pub why: &'static str,
}

/// The records a name needs to reach this cluster.
///
/// `reached_at` is the address the outside uses — a gateway's address where one
/// is in front, or this machine's own where it is directly reachable. Passed in
/// rather than discovered, because a machine behind a NAT cannot tell the
/// difference between "my address" and "the address anybody can use", and
/// guessing produces a record that points somewhere unreachable.
pub fn records(name: &str, reached_at: &str) -> Vec<Record> {
    let apex = name.matches('.').count() <= 1;
    // Both are A records; the difference an apex makes is the www CNAME below,
    // not the kind of this one.
    let mut out = vec![Record {
        kind: "A",
        name: name.to_string(),
        value: reached_at.to_string(),
        why: "points the name at whatever forwards traffic to this cluster",
    }];
    // The `www` form, only for an apex. Adding it for a subdomain would produce
    // www.app.example.com, which nobody wants and somebody would create anyway
    // because a tool told them to.
    if apex {
        out.push(Record {
            kind: "CNAME",
            name: format!("www.{name}"),
            value: name.to_string(),
            why: "so the www form reaches the same place",
        });
    }
    out
}

/// Whether what a name resolves to reaches this cluster.
///
/// The addresses are supplied by the caller so this stays a pure decision: the
/// resolving belongs to the part of the system that is allowed to touch the
/// network, and the judgement belongs here where it can be tested.
pub fn verdict(resolved: &[String], expected: &[String]) -> Result<(), String> {
    if resolved.is_empty() {
        return Err("the name does not resolve yet".into());
    }
    if expected.is_empty() {
        return Err("this cluster does not know its own reachable address".into());
    }
    if resolved.iter().any(|r| expected.iter().any(|e| e == r)) {
        return Ok(());
    }
    Err(format!(
        "resolves to {} — expected {}",
        resolved.join(", "),
        expected.join(", ")
    ))
}

/// Move a domain forward, or say why it cannot move.
///
/// Refusing to skip is the point. A name mapped before it was verified is a
/// certificate request for a domain somebody may not control, and that is the
/// mistake with consequences outside this machine.
pub fn advance(d: &Domain, to: Step) -> Result<Domain, String> {
    if to <= d.step {
        return Err(format!("{} is already {}", d.name, d.step.as_str()));
    }
    let expected = match d.step {
        Step::Added => Step::RecordsIssued,
        Step::RecordsIssued => Step::Verified,
        Step::Verified => Step::Mapped,
        Step::Mapped => return Err(format!("{} is already serving", d.name)),
    };
    if to != expected {
        return Err(format!(
            "{} is {} and the next step is {} — it cannot skip to {}",
            d.name,
            d.step.as_str(),
            expected.as_str(),
            to.as_str()
        ));
    }
    Ok(Domain { step: to, ..d.clone() })
}

/// Whether a certificate may be requested for this name.
///
/// The gate. An unverified name is refused here, with a reason, rather than at
/// the certificate authority — where the same refusal arrives as a rate limit
/// that also blocks the names that were fine.
pub fn may_have_certificate(d: &Domain) -> Result<(), String> {
    match d.step {
        Step::Verified | Step::Mapped => Ok(()),
        _ => Err(format!(
            "{} is {} — a certificate is only requested once a name is verified",
            d.name,
            d.step.as_str()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(name: &str, step: Step) -> Domain {
        Domain { name: name.into(), step, site: None, last_check: None }
    }

    #[test]
    fn an_apex_gets_a_www_record_and_a_subdomain_does_not() {
        let apex = records("example.com", "203.0.113.9");
        assert_eq!(apex.len(), 2);
        assert_eq!(apex[1].name, "www.example.com");
        // www.app.example.com is a record nobody wants, and a tool that asks
        // for it will get it created.
        let sub = records("app.example.com", "203.0.113.9");
        assert_eq!(sub.len(), 1);
    }

    #[test]
    fn a_record_points_at_what_reaches_the_cluster() {
        let r = records("example.com", "203.0.113.9");
        assert_eq!(r[0].value, "203.0.113.9");
    }

    #[test]
    fn verification_needs_the_name_to_resolve_somewhere_we_reach() {
        assert!(verdict(&["203.0.113.9".into()], &["203.0.113.9".into()]).is_ok());
        let wrong = verdict(&["198.51.100.1".into()], &["203.0.113.9".into()]);
        // The reason names both, because "verification failed" tells an
        // operator nothing about which half is wrong.
        assert!(wrong.expect_err("wrong address").contains("198.51.100.1"));
        assert!(verdict(&[], &["203.0.113.9".into()]).is_err());
    }

    #[test]
    fn a_cluster_that_does_not_know_its_own_address_says_so() {
        // Rather than reporting the name as broken, which would send an
        // operator to fix DNS that is already correct.
        let e = verdict(&["203.0.113.9".into()], &[]).expect_err("no expectation");
        assert!(e.contains("does not know its own"));
    }

    #[test]
    fn steps_cannot_be_skipped() {
        let added = d("example.com", Step::Added);
        assert!(advance(&added, Step::Mapped).is_err());
        assert!(advance(&added, Step::Verified).is_err());
        let issued = advance(&added, Step::RecordsIssued).expect("one step");
        assert_eq!(issued.step, Step::RecordsIssued);
    }

    #[test]
    fn a_name_cannot_go_backwards() {
        // A resolver having a bad minute is not evidence that somebody lost
        // control of a domain, so nothing here demotes a verified name.
        let v = d("example.com", Step::Verified);
        assert!(advance(&v, Step::Added).is_err());
        assert!(advance(&v, Step::RecordsIssued).is_err());
    }

    #[test]
    fn no_certificate_before_verification() {
        assert!(may_have_certificate(&d("x.com", Step::Added)).is_err());
        assert!(may_have_certificate(&d("x.com", Step::RecordsIssued)).is_err());
        assert!(may_have_certificate(&d("x.com", Step::Verified)).is_ok());
        assert!(may_have_certificate(&d("x.com", Step::Mapped)).is_ok());
    }

    #[test]
    fn the_refusal_says_what_to_do_next() {
        // An operator reading this is stuck, and the useful thing is the next
        // action rather than the name of the state they are in.
        let e = may_have_certificate(&d("x.com", Step::Added)).expect_err("refused");
        assert!(e.contains("added"));
        assert_eq!(Step::Added.next(), "work out the records this name needs");
    }
}
