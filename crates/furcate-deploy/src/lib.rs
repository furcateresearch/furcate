//! Building a site from source and placing it on machines the operator owns.
//!
//! The shape of this is borrowed deliberately rather than invented. Vercel's
//! Build Output API is a *filesystem* specification — static assets, functions
//! and a routing config — published so that framework authors can target it.
//! Consuming that shape is what turns "does Furcate support framework X" into
//! "does X emit this directory", a question the framework ecosystem is already
//! answering. Nothing here needs to understand Next, Astro or SvelteKit
//! individually beyond working out which of them is present.
//!
//! ## What makes this Furcate and not another PaaS
//!
//! Every comparable tool — Coolify, Dokploy, Dokku, CapRover — treats a deploy
//! as a push: source goes in, a container comes out, and the record of it is a
//! log line. This system has machinery that says a deploy is something else. A
//! deploy is **an action on a site**, so it goes to the policy engine as a
//! request, and the answer — permitted *or refused* — is chained into the
//! tamper-evident record next to power transitions and key use. That produces
//! the thing no hosting platform offers: who deployed what, when, under whose
//! authority, and what the machine refused.
//!
//! The rest follows the same grain as everything else here. Builds run on the
//! operator's own machines. The edge configuration is rendered whole rather
//! than appended to. Nothing in this crate performs I/O — it decides, and
//! `furcatectl` acts — which is why all of it is testable without a network,
//! a filesystem or a web server.
//!
//! ## The stages
//!
//! [`detect`] reads a tree and says how to build it, or refuses.
//! [`release`] gives the built output an identity — the hash of the bytes that
//! will be served, never a version string.
//! [`edge`] renders the serving configuration for every placed site.
//! [`verify`] answers whether the bytes now being served are the ones that
//! were approved, because placing is not serving.

pub mod certs;
pub mod domain;
pub mod detect;
pub mod edge;
pub mod placed;
pub mod release;
pub mod verify;

pub use detect::{Framework, Plan, Tier};
pub use release::{Device, Redirect, Release, Site};
pub use verify::Verdict;

/// The capability name a deploy asks policy for.
///
/// One constant rather than a literal at each call site: the string appears in
/// the request, in the policy file an operator writes, and in the record, and
/// three copies of it is how a rule silently stops matching.
pub const ACTION: &str = "deploy";

/// What the policy engine is asked, for a deploy of `site`.
pub fn request(principal: &str, site: &str) -> String {
    let _ = principal;
    format!("site:{site}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resource_names_the_site_so_a_rule_can_be_scoped_to_one() {
        // A policy that could only say "may deploy" or "may not" would force
        // an operator to grant every site to grant one.
        assert_eq!(request("operator", "furcate-xyz"), "site:furcate-xyz");
        assert_ne!(request("operator", "a"), request("operator", "b"));
    }
}
