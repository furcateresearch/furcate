//! What a release *is*, and where it goes.
//!
//! ## The identity of a deploy is its output, not its version
//!
//! The sysext updater learned this the expensive way: two different images
//! wore one version, a machine compared labels, decided it was current, and
//! never took the fix. A commit is not an identity either — the same commit
//! builds differently on a different toolchain, and an uncommitted tree builds
//! at all. So a release is named by the **hash of the bytes that will be
//! served**, and two builds that produce identical output are the same
//! release however they were made.
//!
//! ## Rollback is a pointer move
//!
//! Releases are immutable directories that accumulate; `current` is a symlink.
//! Deploying is placing a directory and moving the link; rolling back is
//! moving the link to one already on disk. Nothing is rebuilt to go
//! backwards, which matters because the reason you are rolling back is
//! usually that building is what broke.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One file in a built site, as the hash sees it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// Path relative to the output root, with `/` separators on every
    /// platform so the same tree hashes the same everywhere.
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Hash a built tree into a release id.
///
/// Sorted first, because a filesystem hands back directory entries in
/// whatever order it likes and a hash that depended on that would make the
/// same build produce different releases on consecutive runs.
///
/// Path and contents are both length-delimited. Without that, a file named
/// `ab` containing `c` and a file named `a` containing `bc` hash identically,
/// and an attacker who can name a file can collide a release — the same
/// length-delimiting the overlay lock's signed claims use, for the same
/// reason.
pub fn hash(entries: &mut [Entry]) -> String {
    entries.sort();
    let mut h = Sha256::new();
    h.update(b"furcate-release-v1");
    h.update((entries.len() as u64).to_be_bytes());
    for e in entries.iter() {
        h.update((e.path.len() as u64).to_be_bytes());
        h.update(e.path.as_bytes());
        h.update((e.bytes.len() as u64).to_be_bytes());
        h.update(&e.bytes);
    }
    hex::encode(h.finalize())
}

/// The short form used in paths and on screens.
///
/// Twelve hex characters. Long enough that a collision is not a practical
/// worry across the releases one site will ever have, short enough to read
/// out loud and to fit in a table.
pub fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

/// A site as the serving layer knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    /// The name used for directories and units. Not the domain: a site can
    /// answer on several, and a directory named after one of them would be a
    /// lie the day a second is added.
    pub name: String,
    pub domains: Vec<String>,
    pub tier: crate::detect::Tier,
    /// What the detector decided the tree was — "next (static export)",
    /// "praecise (agent app)", "fastapi" — recorded so anything reading the
    /// manifest afterwards (the console, an operator) sees the same answer the
    /// deploy acted on, instead of re-deriving it from the release. Absent on
    /// manifests written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// Never put on the edge: no domain, no platform address. The site answers
    /// only on its loopback port, for whoever is on the machine. For a service
    /// that must be tried with real credentials before it is given a name --
    /// a signing authority, say -- where publishing it to try it is the risk.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local: bool,
}

/// A permanent redirect the framework declared and a static export dropped.
///
/// Next's `redirects()` does not survive `output: 'export'`, so anything
/// declared there has to be re-stated in the serving layer or the links break
/// silently — which is the failure mode nobody notices, because the pages
/// still exist and only the old paths stop reaching them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redirect {
    pub from: String,
    pub to: String,
    pub permanent: bool,
}

/// A path on a site that is served by something other than its files.
///
/// This is what makes a front end and its back end one site rather than two
/// deployments that have to find each other. The front end asks `/api/...`
/// on its own origin, so there is no second hostname, no CORS, and no URL of
/// the back end baked into the front end at build time — which is the thing
/// that makes a static build environment-specific.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// A path matcher, e.g. `/api/*`.
    pub path: String,
    /// Where it goes. An `Upstream`, so a control surface cannot be the
    /// target of one of these either.
    pub upstream: crate::edge::Upstream,
}

/// A response header a site needs the edge to set.
///
/// The edge configuration is rendered whole on every deploy of every site, so
/// anything added to it by hand lasts until somebody deploys something else.
/// The landing page's `Cache-Control: no-cache` was wiped that way three times
/// in one evening: without it a browser invents a freshness window from
/// Last-Modified, and a deploy that landed stays invisible to a returning
/// visitor for twenty-odd minutes. It was then re-applied by a script after
/// every deploy. A header the site declares travels with the site instead, and
/// every render carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// A path matcher, as for a route: `/assets/*`. Absent means every
    /// response the site gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub name: String,
    pub value: String,
}

impl Header {
    /// Refuse anything that could end a token in the rendered configuration.
    ///
    /// The value is written inside double quotes, so a quote or a backslash
    /// would close or escape them, and a brace is a placeholder or a block to
    /// the server that reads the file. The name is held to the characters header
    /// names are actually made of, which is narrower than the RFC's token and
    /// wide enough for every header anybody sets.
    pub fn check(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self.name.len() > 64
            || self.name.starts_with('-')
            || !self.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(format!("`{}` is not a header name this will write into a config", self.name));
        }
        if self.value.len() > 1024
            || self
                .value
                .chars()
                .any(|c| c.is_control() || matches!(c, '"' | '\\' | '{' | '}'))
        {
            return Err(format!(
                "the value for `{}` contains a quote, backslash, brace or control character",
                self.name
            ));
        }
        if let Some(p) = &self.path {
            if !valid_path(p) {
                return Err(format!("`{p}` is not a usable header path; it must start with `/`"));
            }
        }
        Ok(())
    }
}

/// How much memory one supervised site may take.
///
/// Every site used to run with MemoryHigh and MemoryMax at infinity, so one
/// runaway process could take all of a machine's memory and sshd with it, which
/// is how a node ends up needing a physical visit: node-e went dark on 25 August
/// 2026 with no way back in. The bound was then added by hand, as a drop-in, to
/// the sites somebody remembered, with a comment saying the generator should
/// learn to emit it. This is that.
///
/// Two limits, and the order matters. `high` throttles: systemd reclaims hard
/// and slows the site, and nothing dies, so a leak becomes a symptom somebody
/// can see. `max` kills, but only inside the site's own cgroup. The choice it
/// makes is not "kill the site or not", it is "kill the site, or let the site
/// kill the machine".
///
/// It bounds one site, not the sum: thirty sites at ten gigabytes each is more
/// than any of these machines has. Bounding the total needs the sites moved
/// into a shared slice, which is a deliberate change to every running unit and
/// not something a deploy should do as a side effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryBound {
    /// `MemoryHigh`, as systemd spells a size: `6G`, `512M`.
    pub high: String,
    /// `MemoryMax`.
    pub max: String,
}

impl Default for MemoryBound {
    /// Sized against measured use, not guessed. The two real consumers on the
    /// machine this was written for were acme-ml at 4.5 GB and beacon-ml at
    /// 3.8 GB, and every other site sat under 200 MB. 6G leaves the ML services
    /// their working set and headroom before they feel anything; 10G is far
    /// past anything legitimate. For a 60 MB site the numbers are irrelevant,
    /// which is fine: a ceiling nobody reaches costs nothing, and one default
    /// is one thing to reason about.
    fn default() -> Self {
        MemoryBound { high: "6G".into(), max: "10G".into() }
    }
}

impl MemoryBound {
    /// Refuse a bound that would be written into a unit and mean something
    /// other than what it says.
    ///
    /// `infinity` is refused by name. It is a valid systemd value and it is the
    /// state this type exists to end; a site that genuinely needs more asks for
    /// a larger number, which is still a number somebody chose.
    pub fn check(&self) -> Result<(), String> {
        for (what, v) in [("high", &self.high), ("max", &self.max)] {
            if v.trim().eq_ignore_ascii_case("infinity") {
                return Err(format!(
                    "memory.{what} is `infinity`, which is an unbounded site; name a size instead"
                ));
            }
        }
        let high = memory_bytes(&self.high)
            .ok_or_else(|| format!("memory.high `{}` is not a size like 6G or 512M", self.high))?;
        let max = memory_bytes(&self.max)
            .ok_or_else(|| format!("memory.max `{}` is not a size like 10G or 1024M", self.max))?;
        if high == 0 || max == 0 {
            return Err("a memory bound of zero would stop the site from starting at all".into());
        }
        // The throttle has to come before the kill. The other way round, the
        // kernel kills the site before reclaim has had a chance to save it, and
        // the one limit that is meant to be survivable never runs.
        if high > max {
            return Err(format!(
                "memory.high ({}) is above memory.max ({}); the throttle must come before the kill",
                self.high, self.max
            ));
        }
        Ok(())
    }
}

/// Hardware a site may reach, beyond the network and its own files.
///
/// A closed set, on purpose. Every entry is something this platform knows how
/// to grant narrowly: the device node and the one group that owns it, nothing
/// adjacent. A name that is not here is refused at deploy, never passed
/// through, because `DeviceAllow` written from a manifest string would let one
/// site's JSON reach any device on the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Device {
    /// The TPM, through the kernel resource manager. `/dev/tpmrm0` serialises
    /// access between the services that share one TPM; the raw `/dev/tpm0`
    /// does not, and is never granted.
    Tpm,
}

impl Device {
    /// The unit lines that grant this device and nothing more.
    ///
    /// `DeviceAllow=` alone turns on systemd's device policy for the unit, so
    /// naming one device closes every other one, which is the point.
    pub fn unit_lines(&self) -> &'static str {
        match self {
            Device::Tpm => "DeviceAllow=/dev/tpmrm0 rw\nSupplementaryGroups=tss\n",
        }
    }

    /// Parse the `devices` a manifest declares, refusing any name not known.
    pub fn parse_list(v: &serde_json::Value) -> Result<Vec<Device>, String> {
        let list = v
            .as_array()
            .ok_or_else(|| "`devices` must be an array, e.g. [\"tpm\"]".to_string())?;
        let mut out = Vec::with_capacity(list.len());
        for d in list {
            let name = d.as_str().ok_or("every element of `devices` must be a string")?;
            let dev: Device = serde_json::from_value(serde_json::Value::String(name.into()))
                .map_err(|_| format!("`{name}` is not a device this platform grants; known: tpm"))?;
            if !out.contains(&dev) {
                out.push(dev);
            }
        }
        out.sort();
        Ok(out)
    }
}

/// A systemd size in bytes: digits, then optionally K, M, G or T (powers of
/// 1024, as systemd reads them).
///
/// Deliberately narrower than systemd. Percentages and fractional values are
/// valid there and refused here: the value is written into a unit file, and the
/// forms a deploy manifest needs are the ones an operator can compare at a
/// glance.
pub fn memory_bytes(v: &str) -> Option<u64> {
    let v = v.trim();
    let (digits, unit) = match v.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => v.split_at(i),
        None => (v, ""),
    };
    if digits.is_empty() {
        return None;
    }
    let shift = match unit {
        "" => 0,
        "K" => 10,
        "M" => 20,
        "G" => 30,
        "T" => 40,
        _ => return None,
    };
    digits.parse::<u64>().ok()?.checked_mul(1u64 << shift)
}

/// Names a path matcher may take.
///
/// Absolute, and no whitespace or braces — the same care the domains get,
/// because this string is written into a server configuration.
pub fn valid_path(p: &str) -> bool {
    p.starts_with('/')
        && !p.chars().any(|c| c.is_whitespace() || c == '{' || c == '}')
        && p.len() <= 256
}

/// The address a site is given under the deploy zone.
///
/// One place that decides what a site is called, so the name the deploy
/// prints, the name the certificate is issued for and the name the edge
/// matches on cannot drift apart.
pub fn zone_domain(name: &str, zone: &str) -> String {
    format!("{}.{}", name, zone.trim_start_matches('.'))
}

/// The domains a site answers on once it is called `new` instead of `old`.
///
/// A domain that is exactly `old.<zone>` for one of `zones` was derived from
/// the name — by a deploy that assigned the platform or agent address — and is
/// rewritten to `new.<zone>`. Every other domain was typed by somebody and is
/// kept as it is: a custom domain names the site to the outside world, and a
/// rename on this machine is not a decision about that.
///
/// The second list is the kept domains whose first label is still the old name.
/// They are not rewritten, because `shop.example.com` on a site called `shop`
/// may be the business's real address rather than a derivation, but a rename
/// that silently leaves the old name answering is the bridge it exists to
/// avoid, so the caller says them out loud.
///
/// Order is kept and duplicates dropped, so a site that already answered on
/// both a derived and an explicit spelling of the new name does not get two.
pub fn renamed_domains(
    domains: &[String],
    old: &str,
    new: &str,
    zones: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut out: Vec<String> = Vec::new();
    let mut still_old = Vec::new();
    for d in domains {
        let lower = d.to_lowercase();
        let derived = zones.iter().find_map(|z| {
            let z = z.trim().trim_start_matches('.').to_lowercase();
            (!z.is_empty() && lower == format!("{old}.{z}")).then(|| format!("{new}.{z}"))
        });
        let next = match derived {
            Some(n) => n,
            None => {
                if lower.split('.').next() == Some(old) {
                    still_old.push(lower.clone());
                }
                lower
            }
        };
        if !out.contains(&next) {
            out.push(next);
        }
    }
    (out, still_old)
}

/// A release that has been placed, or is about to be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub site: String,
    pub id: String,
    pub tier: crate::detect::Tier,
    pub files: usize,
    pub bytes: u64,
    /// Unix seconds. Advisory, as in the ledger: ordering comes from what is
    /// linked, not from what a clock said.
    pub at: u64,
}

/// Where a site's releases live under a root.
pub fn site_dir(root: &str, site: &str) -> String {
    format!("{}/sites/{}", root.trim_end_matches('/'), site)
}

/// Where one release's files live. Immutable once written.
pub fn release_dir(root: &str, site: &str, id: &str) -> String {
    format!("{}/releases/{}", site_dir(root, site), short(id))
}

/// The symlink the server reads.
pub fn current_link(root: &str, site: &str) -> String {
    format!("{}/current", site_dir(root, site))
}

/// How many releases a site keeps: the live one plus this many older ones.
///
/// Two is what a rollback actually needs — the one before, and one behind that
/// in case the one before is the reason you are rolling back.
pub const KEEP_RELEASES: usize = 2;

/// Delete a site's releases beyond `current` plus the newest `keep` others.
///
/// Nothing pruned them until 2026-09-17, when this machine filled twice: the
/// deploy tree had reached 188G across 413 stale trees, one site holding 79
/// releases, and a full root takes Postgres and every site with it. Reclaiming
/// it by hand is not a fix, because the next deploy starts refilling it.
///
/// Safety is the whole design here:
///
/// * `current` is resolved first and never removed, whatever its age.
/// * A site whose `current` cannot be resolved is left **entirely** alone. That
///   is either a site mid-deploy or one already broken, and neither is improved
///   by deleting its history.
/// * Ordering is by modification time, not by name — release ids are content
///   hashes, so their names sort arbitrarily.
/// * Failure to remove one directory does not abort the rest, and never fails
///   the deploy. A deploy that served traffic has succeeded; housekeeping that
///   could not finish is a warning, not a rollback.
///
/// Returns the ids removed and the bytes reclaimed.
pub fn prune(root: &str, site: &str, keep: usize) -> (Vec<String>, u64) {
    let dir = std::path::PathBuf::from(format!("{}/releases", site_dir(root, site)));

    // Resolve `current` before reading the directory. Without it we cannot tell
    // what is live, and a guess here deletes the running release.
    let live = match std::fs::canonicalize(current_link(root, site)) {
        Ok(p) => p,
        Err(_) => return (Vec::new(), 0),
    };

    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| {
                let at = e.metadata().and_then(|m| m.modified()).ok()?;
                Some((at, e.path()))
            })
            .collect(),
        Err(_) => return (Vec::new(), 0),
    };

    // Newest first.
    entries.sort_by(|a, b| b.0.cmp(&a.0));

    let mut removed = Vec::new();
    let mut freed = 0u64;
    let mut kept = 0usize;

    for (_, path) in entries {
        // The live release is not a candidate and does not count against `keep`,
        // so a site keeps `keep` rollback targets whether or not `current`
        // happens to be the newest directory on disk.
        if std::fs::canonicalize(&path).map(|p| p == live).unwrap_or(false) {
            continue;
        }
        if kept < keep {
            kept += 1;
            continue;
        }
        let bytes = dir_bytes(&path);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                freed += bytes;
                if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
                    removed.push(n.to_string());
                }
            }
            Err(e) => eprintln!("prune     could not remove {}: {e}", path.display()),
        }
    }

    (removed, freed)
}

/// Bytes under a directory. Best effort — used only to report what was freed,
/// so an unreadable corner is worth skipping rather than failing over.
fn dir_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0;
    let Ok(rd) = std::fs::read_dir(path) else {
        return 0;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        // symlink_metadata, not metadata: a release tree can contain links, and
        // following them would count the target's bytes or walk out of the tree.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            total += dir_bytes(&path);
        } else {
            total += meta.len();
        }
    }
    total
}

/// Names that are safe as a directory and a unit name.
///
/// Refused rather than sanitised: silently rewriting `../etc` into something
/// else gives an operator a site whose name is not the name they typed, and
/// the interesting cases here are exactly the ones somebody chose on purpose.
pub fn valid_name(name: &str) -> bool {
    // 63, not 64: a site name becomes a DNS label under the deploy zone
    // (`<name>.cloud.example.com`), and 63 octets is the hard limit on a
    // label. Allowing 64 would let somebody name a site that cannot be given
    // the address the system promises it — a refusal at deploy time is far
    // better than a name that resolves nowhere.
    !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Domains this will accept.
///
/// Deliberately strict. A domain string flows into the serving layer's
/// configuration, so anything that could terminate a token there is refused
/// here instead of quoted there.
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').count() >= 2
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(path: &str, bytes: &str) -> Entry {
        Entry {
            path: path.into(),
            bytes: bytes.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_same_files_hash_the_same_whatever_order_they_arrive_in() {
        let mut a = vec![e("a.html", "one"), e("b/c.css", "two")];
        let mut b = vec![e("b/c.css", "two"), e("a.html", "one")];
        assert_eq!(hash(&mut a), hash(&mut b));
    }

    #[test]
    fn changing_one_byte_changes_the_release() {
        let mut a = vec![e("a.html", "one")];
        let mut b = vec![e("a.html", "onf")];
        assert_ne!(hash(&mut a), hash(&mut b));
    }

    #[test]
    fn renaming_a_file_changes_the_release_even_with_identical_bytes() {
        let mut a = vec![e("a.html", "x")];
        let mut b = vec![e("b.html", "x")];
        assert_ne!(hash(&mut a), hash(&mut b));
    }

    #[test]
    fn a_name_cannot_be_shifted_into_the_contents() {
        // Without length-delimiting these two trees hash identically, and a
        // release id somebody can collide by choosing a filename is not an
        // identity.
        let mut a = vec![e("ab", "c")];
        let mut b = vec![e("a", "bc")];
        assert_ne!(hash(&mut a), hash(&mut b));
    }

    #[test]
    fn an_empty_build_still_has_an_id_and_it_is_not_a_fixed_string() {
        let mut none: Vec<Entry> = vec![];
        let id = hash(&mut none);
        assert_eq!(id.len(), 64);
        let mut one = vec![e("a", "")];
        assert_ne!(id, hash(&mut one));
    }

    #[test]
    fn paths_are_built_from_the_short_id() {
        let id = "abcdef0123456789aaaa";
        assert_eq!(
            release_dir("/var/lib/furcate/deploy", "furcate-xyz", id),
            "/var/lib/furcate/deploy/sites/furcate-xyz/releases/abcdef012345"
        );
        assert_eq!(
            current_link("/var/lib/furcate/deploy", "furcate-xyz"),
            "/var/lib/furcate/deploy/sites/furcate-xyz/current"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_root_does_not_double_up() {
        assert_eq!(
            current_link("/srv/deploy/", "s"),
            "/srv/deploy/sites/s/current"
        );
    }

    #[test]
    fn a_name_too_long_to_be_a_dns_label_is_refused() {
        // The system promises every site an address under the deploy zone. A
        // 64-character name could be a directory and could not be a label, so
        // it would deploy and then resolve nowhere.
        assert!(valid_name(&"a".repeat(63)));
        assert!(!valid_name(&"a".repeat(64)));
    }

    #[test]
    fn a_site_is_addressed_under_the_zone_in_one_place() {
        assert_eq!(zone_domain("app", "cloud.example.com"), "app.cloud.example.com");
        // A leading dot on the zone is the obvious way to write it and would
        // otherwise produce `app..cloud...`.
        assert_eq!(zone_domain("app", ".cloud.example.com"), "app.cloud.example.com");
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_rename_rewrites_the_addresses_derived_from_the_name_and_keeps_custom_ones() {
        let zones = names(&["app.example.net", "mcp.example.net", "local"]);
        let (d, still) = renamed_domains(
            &names(&["shop-rs.local", "shop-rs.app.example.net", "shop.example.com"]),
            "shop-rs",
            "shop",
            &zones,
        );
        assert_eq!(d, names(&["shop.local", "shop.app.example.net", "shop.example.com"]));
        assert!(still.is_empty());
    }

    #[test]
    fn a_kept_domain_that_still_carries_the_old_name_is_reported_not_rewritten() {
        let zones = names(&["app.example.net"]);
        let (d, still) =
            renamed_domains(&names(&["shop.example.com", "shop.app.example.net"]), "shop", "store", &zones);
        assert_eq!(d, names(&["shop.example.com", "store.app.example.net"]));
        assert_eq!(still, names(&["shop.example.com"]));
    }

    #[test]
    fn a_name_that_merely_starts_like_the_old_one_is_not_derived_from_it() {
        // `shop-rs-web.<zone>` belongs to another site's name, not this one's.
        let zones = names(&["app.example.net"]);
        let (d, still) =
            renamed_domains(&names(&["shop-rs-web.app.example.net"]), "shop-rs", "shop", &zones);
        assert_eq!(d, names(&["shop-rs-web.app.example.net"]));
        assert!(still.is_empty());
    }

    #[test]
    fn a_site_already_answering_on_the_new_name_does_not_get_it_twice() {
        let zones = names(&["app.example.com"]);
        let (d, _) = renamed_domains(
            &names(&["old.app.example.com", "new.app.example.com"]),
            "old",
            "new",
            &zones,
        );
        assert_eq!(d, names(&["new.app.example.com"]));
    }

    fn header(path: Option<&str>, name: &str, value: &str) -> Header {
        Header { path: path.map(String::from), name: name.into(), value: value.into() }
    }

    #[test]
    fn the_headers_sites_actually_set_are_accepted() {
        for h in [
            header(None, "Cache-Control", "no-cache"),
            header(Some("/assets/*"), "Cache-Control", "public, max-age=31536000, immutable"),
            header(None, "X-Frame-Options", "DENY"),
            header(None, "Content-Security-Policy", "default-src 'self'; img-src * data:"),
        ] {
            assert!(h.check().is_ok(), "{h:?}");
        }
    }

    #[test]
    fn a_header_cannot_break_out_of_its_quotes_or_its_line() {
        for h in [
            header(None, "Cache-Control", "no-cache\"\n\trespond 200"),
            header(None, "Cache-Control", "a\\"),
            header(None, "X-Thing", "{http.request.host}"),
            header(None, "X-Thing", "}"),
            header(None, "Bad Name", "x"),
            header(None, "", "x"),
            header(None, "-Leading", "x"),
            header(Some("no-slash"), "Cache-Control", "no-cache"),
            header(Some("/a b"), "Cache-Control", "no-cache"),
        ] {
            assert!(h.check().is_err(), "{h:?} should be refused");
        }
    }

    #[test]
    fn every_site_is_bounded_by_default() {
        let m = MemoryBound::default();
        assert_eq!((m.high.as_str(), m.max.as_str()), ("6G", "10G"));
        assert!(m.check().is_ok());
    }

    #[test]
    fn sizes_are_read_the_way_systemd_reads_them() {
        assert_eq!(memory_bytes("6G"), Some(6 << 30));
        assert_eq!(memory_bytes("512M"), Some(512 << 20));
        assert_eq!(memory_bytes("1024"), Some(1024));
        assert_eq!(memory_bytes(" 2T "), Some(2 << 40));
        for bad in ["", "G", "6g", "6.5G", "50%", "6 G", "-1G", "6GB"] {
            assert_eq!(memory_bytes(bad), None, "{bad:?}");
        }
        // Overflow is a refusal, not a wrap to a tiny limit.
        assert_eq!(memory_bytes("99999999999T"), None);
    }

    #[test]
    fn an_unbounded_site_cannot_be_declared() {
        let m = MemoryBound { high: "6G".into(), max: "infinity".into() };
        assert!(m.check().unwrap_err().contains("infinity"));
    }

    #[test]
    fn the_throttle_must_come_before_the_kill() {
        let m = MemoryBound { high: "12G".into(), max: "10G".into() };
        assert!(m.check().is_err());
        let ok = MemoryBound { high: "12G".into(), max: "20G".into() };
        assert!(ok.check().is_ok());
        let zero = MemoryBound { high: "0".into(), max: "1G".into() };
        assert!(zero.check().is_err());
    }

    #[test]
    fn a_route_path_cannot_break_out_of_the_config() {
        for good in ["/api/*", "/", "/v1/users"] {
            assert!(valid_path(good), "{good}");
        }
        for bad in ["api/*", "/a b", "/x}", "/y{"] {
            assert!(!valid_path(bad), "{bad}");
        }
    }

    #[test]
    fn names_that_would_escape_their_directory_are_refused() {
        for bad in ["../etc", "a/b", "", "-lead", "trail-", "Upper", "a b"] {
            assert!(!valid_name(bad), "{bad} should be refused");
        }
        for good in ["furcate-xyz", "site1", "a"] {
            assert!(valid_name(good), "{good} should be accepted");
        }
    }

    #[test]
    fn domains_that_could_break_out_of_a_config_token_are_refused() {
        for bad in [
            "furcate",             // no dot: not a domain
            "furcate.xyz {",       // a brace would open a block in the config
            "a..b",                // empty label
            "-x.com",
            "x-.com",
            "a.com\nb.com",
        ] {
            assert!(!valid_domain(bad), "{bad:?} should be refused");
        }
        for good in ["furcate.xyz", "www.furcate.xyz", "furcate.computer"] {
            assert!(valid_domain(good), "{good} should be accepted");
        }
    }
}

/// Bytes as an operator reads them. Only ever used in deploy output, so one
/// decimal place and binary units is the whole requirement.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
