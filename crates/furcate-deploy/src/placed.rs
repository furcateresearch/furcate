//! What a machine is actually serving, read from where the deploy put it.
//!
//! One implementation, because two things ask this question and they must not
//! disagree. The node agent answers it for the edge — *may this name have a
//! certificate* — and the site controller answers it for a screen. If those
//! two read the deploy root differently, an operator sees a site the edge will
//! not issue for, or the reverse.
//!
//! ## Why the agent, and not only the controller
//!
//! The question is **"does this machine serve that name"**, and only this
//! machine can answer it. A site deployed on one node is not deployed on
//! another: the release directory, the symlink and the edge are all local.
//! Asking the controller means asking a machine that knows what *it* was told
//! to place, which is a different question and gives the wrong answer as soon
//! as a cluster has more than one node — certificates refused for names that
//! are genuinely served, with the refusal looking exactly like the one that
//! stops abuse.

use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    domains: Vec<String>,
}

/// The platform zone, if this edge has one: every placed site also answers on
/// `NAME.<zone>`, whether or not anyone attached a domain to it.
///
/// `<root>/edge/zone` holds the zone, written by `furcatectl edge zone`. A
/// file rather than an environment variable because three different processes
/// need the same answer — the deploy that renders, the timer that re-renders,
/// and the daemon that decides what may have a certificate — and an
/// environment variable reaches whichever of them happened to be started with
/// it. The wildcard certificate for the zone lives beside it under
/// `edge/wildcards/<zone>/`; without that certificate the zone is not used,
/// because sixty names asked of a public CA in one render is a rate limit,
/// not a platform.
pub fn zone(root: &str) -> Option<String> {
    let z = std::fs::read_to_string(std::path::Path::new(root).join("edge").join("zone")).ok()?;
    let z = z.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
    (!z.is_empty() && z.contains('.')).then_some(z)
}

/// Whether the zone's wildcard certificate is on disk, both halves.
pub fn zone_has_wildcard(root: &str, zone: &str) -> bool {
    let d = std::path::Path::new(root).join("edge").join("wildcards").join(zone);
    d.join("fullchain.pem").is_file() && d.join("privkey.pem").is_file()
}

/// The platform address of a site under the zone.
pub fn zone_name(name: &str, zone: &str) -> String {
    format!("{}.{}", name.to_lowercase(), zone)
}

/// The zone for agent applications, if this edge has one.
///
/// A second file rather than a second line in the first, so everything that
/// already reads `edge/zone` keeps working untouched: the daemon answering
/// `/tls/allow`, the timer that re-renders, and every caller written before
/// there was more than one zone. A missing file means "no agent zone", which
/// is the state every existing cluster is already in.
///
/// Why two zones at all: an app is opened in a browser and an agent is called
/// by other software. `NAME.app.example` and `NAME.mcp.example` are different
/// promises about what answers there, and one platform zone cannot make both.
pub fn zone_mcp(root: &str) -> Option<String> {
    let z = std::fs::read_to_string(std::path::Path::new(root).join("edge").join("zone-mcp")).ok()?;
    let z = z.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
    (!z.is_empty() && z.contains('.')).then_some(z)
}

/// The zone a site belongs in, given the framework recorded in its manifest.
///
/// An agent application goes under the agent zone when the cluster has one,
/// and everything else — including an agent app on a cluster with only a
/// platform zone — goes under the platform zone. Both are gated on the
/// wildcard being on disk, because a zone without one turns the next render
/// into one certificate request per name against a single registered domain.
///
/// The framework string is the one already in `site.json`
/// (`detect::Framework::as_str`), not a new concept. The renderer runs long
/// after the deploy that detected it, and re-detecting from a release tree
/// could give a different answer from the one the deploy printed.
pub fn zone_for(root: &str, framework: Option<&str>) -> Option<String> {
    if matches!(framework, Some("praecise (agent app)")) {
        if let Some(z) = zone_mcp(root).filter(|z| zone_has_wildcard(root, z)) {
            return Some(z);
        }
    }
    zone(root).filter(|z| zone_has_wildcard(root, z))
}

/// Every domain a site placed under `root` answers on, including each site's
/// platform address when the edge has a zone with its certificate in place.
///
/// Sorted and deduplicated so callers can compare two machines' answers
/// without sorting first, and so a rendered list is stable between runs.
pub fn domains(root: &str) -> Vec<String> {
    let dir = std::path::Path::new(root).join("sites");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    let zone = zone(root).filter(|z| zone_has_wildcard(root, z));
    let mut out: Vec<String> = Vec::new();
    for e in entries.filter_map(|e| e.ok()) {
        let Ok(text) = std::fs::read_to_string(e.path().join("site.json")) else { continue };
        let Ok(m) = serde_json::from_str::<Manifest>(&text) else { continue };
        out.extend(m.domains.iter().map(|d| d.to_lowercase()));
        if let Some(z) = &zone {
            out.push(zone_name(&e.file_name().to_string_lossy(), z));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether this machine serves `domain`.
///
/// Case-insensitive, because a name arrives from a TLS handshake or a query
/// string in whatever case the asker used, and DNS does not distinguish.
pub fn serves(root: &str, domain: &str) -> bool {
    let want = domain.trim().to_lowercase();
    !want.is_empty() && domains(root).contains(&want)
}

/// What each placed site is: its name, the release it currently points at, and
/// the names it answers on.
///
/// `domains()` answers "may this machine hold a certificate for X", which is a
/// yes-or-no for the TLS gate. An operator needs the other question — what is
/// this machine publishing, and at which release — and that has had no answer
/// anywhere, which is why nothing on the console could show it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Placed {
    pub name: String,
    pub domains: Vec<String>,
    /// The release the `current` pointer resolves to, if it resolves.
    pub release: Option<String>,
}

pub fn placed(root: &str) -> Vec<Placed> {
    let dir = std::path::Path::new(root).join("sites");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    let mut out: Vec<Placed> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().to_string();
            let manifest: Manifest =
                serde_json::from_str(&std::fs::read_to_string(path.join("site.json")).ok()?).ok()?;
            // The pointer, not a directory listing: a release that exists on
            // disk but is not pointed at is not what this machine is serving.
            let release = std::fs::read_link(path.join("current"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
            Some(Placed {
                name,
                domains: manifest.domains.into_iter().map(|d| d.to_lowercase()).collect(),
                release,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str, site: &str, domains: &[&str]) -> String {
        let root = std::env::temp_dir().join(format!("furcate-placed-{tag}-{}", std::process::id()));
        let d = root.join("sites").join(site);
        std::fs::create_dir_all(&d).unwrap();
        let json = serde_json::json!({
            "name": site,
            "domains": domains,
            "tier": "static",
        });
        std::fs::write(d.join("site.json"), json.to_string()).unwrap();
        root.display().to_string()
    }

    #[test]
    fn a_placed_site_is_served_under_every_name_it_declares() {
        let root = fixture("a", "s", &["furcate.xyz", "www.furcate.xyz"]);
        assert!(serves(&root, "furcate.xyz"));
        assert!(serves(&root, "www.furcate.xyz"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_name_nobody_placed_is_not_served() {
        // The whole point when this answers a certificate request: a wildcard
        // record means every name under the zone reaches this edge, and only
        // the deployed ones may be issued for.
        let root = fixture("b", "s", &["furcate.xyz"]);
        assert!(!serves(&root, "evil.example.com"));
        assert!(!serves(&root, ""));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_comparison_ignores_case_as_dns_does() {
        let root = fixture("c", "s", &["furcate.xyz"]);
        assert!(serves(&root, "FURCATE.XYZ"));
        assert!(serves(&root, " Furcate.Xyz "));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_machine_with_nothing_placed_serves_nothing_rather_than_failing() {
        // A node that has never hosted anything is an ordinary state, not an
        // error, and must answer "no" rather than refusing to answer.
        assert!(domains("/nonexistent/furcate/deploy").is_empty());
        assert!(!serves("/nonexistent/furcate/deploy", "anything.example"));
    }
}
