//! How a workload gets hold of a resource.
//!
//! A backend needs a database. Something has to create it, produce credentials
//! for it, and put those where the process can read them. The established shape
//! for that is a *binding*: the workload declares what it needs, the platform
//! produces a connection — host, port, name, credentials — and injects it as
//! environment variables. Kubernetes' Service Binding specification and
//! Crossplane's connection secrets are both this, and application frameworks
//! already expect to be configured this way.
//!
//! Furcate uses the same shape for one more thing: inference. A backend that
//! wants a model gets an endpoint and a token in exactly the way it gets a
//! database URL, whether the model is answered by a private node in the same
//! rack or by the wider network. That is the whole reason to model it as a
//! binding — the application does not have to know which, and the operator can
//! change the answer without the application being rebuilt.
//!
//! ## What is deliberately not here
//!
//! Secrets. This module decides the *shape* of a connection — which variables a
//! workload will receive and what each one means — and nothing in it ever holds
//! a password. Filling them in is the job of the part that already holds
//! credentials, and keeping the two apart means the decision about what a
//! workload can see is testable without a single secret in a test fixture.

use crate::tenancy::{Engine, Shape};
use serde::{Deserialize, Serialize};

/// Where inference comes from.
///
/// Kept as a property of the binding rather than of the application, so an
/// operator can move a workload from the network to a machine they own without
/// the workload knowing. That is the sovereignty claim made operational: the
/// same code runs either way, and where it runs is the operator's to change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Inference {
    /// A node this operator runs, on a machine capable of holding the model.
    Local,
    /// The wider network.
    Network,
}

/// What a workload is asking for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Need {
    /// A database or bucket the operator has granted.
    Resource { name: String, shape: Shape },
    /// A model to answer with.
    Model { model: String, from: Inference },
}

/// A workload's claim on something.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The workload that will receive it.
    pub workload: String,
    /// The prefix its variables take, so one workload can hold several. A
    /// backend with a cache and a database has `CACHE_URL` and `DATABASE_URL`,
    /// and neither has to be the "default" one.
    pub prefix: String,
    pub need: Need,
}

/// One variable a workload will receive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Var {
    pub name: String,
    /// What it holds, for an operator reading the binding rather than the code.
    pub means: &'static str,
    /// Whether the value is a secret, which decides whether it may ever be
    /// shown on a screen or written to a log.
    pub secret: bool,
}

fn var(prefix: &str, suffix: &str, means: &'static str, secret: bool) -> Var {
    Var { name: format!("{prefix}_{suffix}"), means, secret }
}

/// The variables a binding produces.
///
/// A URL *and* its parts. Frameworks disagree about which they want — some take
/// a single connection string, some take a host and a port — and providing one
/// forces every application to parse or assemble the other, which is where
/// escaping bugs in passwords come from.
pub fn vars(b: &Binding) -> Vec<Var> {
    let p = b.prefix.to_uppercase();
    match &b.need {
        Need::Resource { shape, .. } => match shape.engine() {
            Engine::ObjectStore => vec![
                var(&p, "ENDPOINT", "where the object store answers", false),
                var(&p, "BUCKET", "the bucket this workload was given", false),
                var(&p, "REGION", "the region name the S3 client needs", false),
                var(&p, "ACCESS_KEY_ID", "the key this workload uses", false),
                var(&p, "SECRET_ACCESS_KEY", "its secret", true),
            ],
            Engine::Postgres => vec![
                var(&p, "URL", "the whole connection string", true),
                var(&p, "HOST", "where the database answers", false),
                var(&p, "PORT", "its port", false),
                var(&p, "NAME", "the database this workload was given", false),
                var(&p, "USER", "the role it connects as", false),
                var(&p, "PASSWORD", "that role's password", true),
            ],
            Engine::Valkey => vec![
                var(&p, "URL", "the whole connection string", true),
                var(&p, "HOST", "where the key-value store answers", false),
                var(&p, "PORT", "its port", false),
                var(&p, "PASSWORD", "its password", true),
            ],
        },
        Need::Model { .. } => vec![
            var(&p, "URL", "where to send inference requests", false),
            var(&p, "MODEL", "the model to ask for", false),
            var(&p, "TOKEN", "what authorises this workload to ask", true),
        ],
    }
}

/// The connection string a binding implies, with the secret left out.
///
/// For showing an operator what a workload will see. The password is elided
/// rather than omitted, because a connection string with no gap in it looks
/// like one that needs no password.
pub fn redacted_url(b: &Binding, host: &str, port: u16, name: &str, user: &str) -> Option<String> {
    match &b.need {
        Need::Resource { shape, .. } => match shape.engine() {
            Engine::Postgres => Some(format!("postgres://{user}:••••@{host}:{port}/{name}")),
            Engine::Valkey => Some(format!("valkey://:••••@{host}:{port}")),
            Engine::ObjectStore => None,
        },
        Need::Model { .. } => None,
    }
}

/// Whether a binding may be made.
///
/// The refusals worth having are about capability and reach, not spelling: a
/// workload bound to a model no machine here can hold will start, run, and fail
/// on its first request, which is the worst moment to discover it.
pub fn admits(b: &Binding, granted: &[String], can_serve_locally: bool) -> Result<(), String> {
    if b.workload.trim().is_empty() {
        return Err("a binding needs a workload".into());
    }
    if b.prefix.trim().is_empty() {
        return Err("a binding needs a prefix, so its variables have names".into());
    }
    if !b
        .prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("a prefix becomes part of a variable name, so it holds letters, digits and underscores".into());
    }
    match &b.need {
        Need::Resource { name, .. } => {
            if !granted.iter().any(|g| g == name) {
                // Bound before granted is the ordering mistake that produces a
                // container which starts and cannot connect.
                return Err(format!(
                    "`{name}` has not been granted to anyone yet, so nothing can be bound to it"
                ));
            }
            Ok(())
        }
        Need::Model { model, from } => {
            if *from == Inference::Local && !can_serve_locally {
                return Err(format!(
                    "no machine here can hold `{model}`, so this can only be answered by the network"
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(prefix: &str, need: Need) -> Binding {
        Binding { workload: "api".into(), prefix: prefix.into(), need }
    }

    fn db(name: &str) -> Need {
        Need::Resource { name: name.into(), shape: Shape::Relational }
    }

    #[test]
    fn a_binding_gives_both_a_url_and_its_parts() {
        // Frameworks disagree about which they want, and providing one forces
        // every application to assemble the other — which is where passwords
        // with punctuation in them start breaking.
        let v = vars(&b("database", db("orders")));
        let names: Vec<&str> = v.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&"DATABASE_URL"));
        assert!(names.contains(&"DATABASE_HOST"));
        assert!(names.contains(&"DATABASE_PASSWORD"));
    }

    #[test]
    fn the_prefix_lets_one_workload_hold_several() {
        let cache = vars(&b("cache", Need::Resource { name: "sessions".into(), shape: Shape::KeyValue }));
        assert!(cache.iter().any(|v| v.name == "CACHE_URL"));
        let main = vars(&b("database", db("orders")));
        assert!(main.iter().any(|v| v.name == "DATABASE_URL"));
        // Neither has to be the default one, which is what makes a backend with
        // two datastores expressible at all.
        assert_ne!(cache[0].name, main[0].name);
    }

    #[test]
    fn every_secret_variable_is_marked_as_one() {
        // Read by anything deciding what may be printed. A password that is not
        // marked is a password in a log.
        for v in vars(&b("database", db("orders"))) {
            if v.name.ends_with("PASSWORD") || v.name.ends_with("URL") {
                assert!(v.secret, "{} should be secret", v.name);
            }
        }
        let obj = vars(&b("files", Need::Resource { name: "photos".into(), shape: Shape::Objects }));
        assert!(obj.iter().find(|v| v.name == "FILES_SECRET_ACCESS_KEY").expect("a key").secret);
        // The bucket name is not a secret and marking it as one would hide
        // something an operator needs to read.
        assert!(!obj.iter().find(|v| v.name == "FILES_BUCKET").expect("a bucket").secret);
    }

    #[test]
    fn a_model_binding_looks_like_any_other() {
        // The point: an application asks for a model the way it asks for a
        // database, and cannot tell whether it is answered locally.
        let local = vars(&b("ai", Need::Model { model: "muse".into(), from: Inference::Local }));
        let network = vars(&b("ai", Need::Model { model: "muse".into(), from: Inference::Network }));
        assert_eq!(
            local.iter().map(|v| v.name.clone()).collect::<Vec<_>>(),
            network.iter().map(|v| v.name.clone()).collect::<Vec<_>>()
        );
        assert!(local.iter().any(|v| v.name == "AI_URL"));
    }

    #[test]
    fn a_local_model_is_refused_where_no_machine_can_hold_it() {
        // Otherwise the container starts, runs, and fails on its first request
        // — the worst moment to find out.
        let want = b("ai", Need::Model { model: "muse".into(), from: Inference::Local });
        let e = admits(&want, &[], false).expect_err("refused");
        assert!(e.contains("only be answered by the network"));
        assert!(admits(&want, &[], true).is_ok());
        // The network is always an option, so it is never refused for capacity.
        let net = b("ai", Need::Model { model: "muse".into(), from: Inference::Network });
        assert!(admits(&net, &[], false).is_ok());
    }

    #[test]
    fn nothing_can_be_bound_to_a_resource_that_was_never_granted() {
        let want = b("database", db("orders"));
        assert!(admits(&want, &[], true).is_err());
        assert!(admits(&want, &["orders".to_string()], true).is_ok());
    }

    #[test]
    fn a_prefix_has_to_survive_being_a_variable_name() {
        let bad = b("my database", db("orders"));
        assert!(admits(&bad, &["orders".to_string()], true).is_err());
    }

    #[test]
    fn a_shown_connection_string_has_a_visible_gap_where_the_secret_is() {
        // A string with no gap in it reads as one that needs no password, and
        // somebody will copy it and wonder why it fails.
        let u = redacted_url(&b("database", db("orders")), "10.90.0.10", 5432, "orders", "api")
            .expect("a url");
        assert!(u.contains("••••"));
        assert!(!u.contains("password"));
    }
}
