//! The canonical order: one schema for what a person or an agent asks a
//! machine to do to itself.
//!
//! An agent and a person ask in exactly the same words. What differs is what
//! happens next: anybody the site recognises may *propose* an order, and only
//! passkey assertions made by people the site has admitted can *approve* one.
//! The assertion is made over the hash of the bytes below, so what a person
//! approved on their own device is, byte for byte, what the machine carries
//! out. There is no second representation to drift from the first.
//!
//! ## The canonical bytes
//!
//! A fixed sequence of `key=value` lines, each ending in a single `\n`, in
//! exactly this order:
//!
//! ```text
//! furcate-order/1
//! site=<rp id>
//! action=<halt|resume|power_off|isolate|release|crypto_erase|admit|revoke|set_custody|login>
//! target=<node|domain|cluster|credential|custody|login>
//! target.id=<id, or <user>@<node> for login; empty for cluster and custody>
//! target.key_sha256=<lowercase hex: the credential key, the custody change, or the SSH key; else empty>
//! target.rp_id=<the credential's own RP ID, empty unless credential>
//! bounds.max_nodes=<decimal u32>
//! bounds.duration_s=<decimal u64, or "none">
//! counter=<decimal u64>
//! issued_at=<decimal u64, unix seconds>
//! expires_at=<decimal u64, unix seconds>
//! reason=<utf-8 text>
//! ```
//!
//! No string field may contain a carriage return or a line feed, so no value
//! can forge the line after it; an order that has one is refused rather than
//! escaped. The order hash is SHA-256 over these bytes.
//!
//! ## `set_custody` approves one exact custody change
//!
//! A `set_custody` order names the SHA-256 of a custody change's signed bytes
//! (`furcate_policy::custody::CustodyChange::digest`): the site, epoch,
//! validity window, predecessor, mode, holders, minimum, opt-ins and reason.
//! The approvers therefore approve those settings and nothing else, and the
//! node applies them through the same checks and ledger entries as an
//! operator-signed change. The line layout is unchanged; the digest travels in
//! `target.key_sha256`.
//!
//! ## `login` approves one SSH key, as one user, on one machine, for a while
//!
//! A `login` order names the SHA-256 of an SSH public key's wire encoding (the
//! base64 field of its OpenSSH line, decoded), the login user and the machine,
//! as `target.id=<user>@<node>`, and how long the access lasts in
//! `bounds.duration_s`. The node that holds the site's SSH certificate
//! authority carries it out by signing a certificate for exactly that key,
//! with the single principal `<user>@<node>`, valid for no longer than the
//! order says. The key must be a FIDO key (`sk-ecdsa` or `sk-ed25519`), so
//! what logs in is an authenticator, not a file.
//!
//! ## `isolate` is something a node does to itself
//!
//! An isolated node drops its own reach: it stops initiating and accepting
//! traffic beyond what an operator needs to inspect it. It never removes a
//! peer from the overlay, and no order can make one node cut another off —
//! that act is refused to every principal by `furcate_policy::invariant`, and
//! the overlay is built so that no coordinator can do it either. So `isolate`
//! may only name a single node, and only that node carries it out.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// The version line every canonical order starts with.
pub const CANONICAL_HEADER: &str = "furcate-order/1";

/// What the order does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Stop the workload runtimes, leave the OS up.
    Halt,
    /// Restart the workloads a `halt` stopped on each node named, as that
    /// node recorded them. Nothing a halt did not stop is started.
    Resume,
    /// Cut power at the outlet or the BMC.
    PowerOff,
    /// The named node drops its own reach. Acts on itself only; see the module
    /// documentation.
    Isolate,
    /// The named node restores the reach `isolate` took away. Acts on itself
    /// only, like `isolate`.
    Release,
    /// Destroy the node's sealed vault keys. Irreversible.
    CryptoErase,
    /// Admit a passkey credential as one that may approve orders.
    Admit,
    /// Withdraw a credential's standing to approve orders.
    Revoke,
    /// Apply one custody change to the site's policy: who holds its keys.
    SetCustody,
    /// Certify one FIDO-held SSH key as one user on one machine, for a while.
    Login,
}

impl Action {
    pub const ALL: [Action; 10] = [
        Action::Halt,
        Action::Resume,
        Action::PowerOff,
        Action::Isolate,
        Action::Release,
        Action::CryptoErase,
        Action::Admit,
        Action::Revoke,
        Action::SetCustody,
        Action::Login,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Halt => "halt",
            Action::Resume => "resume",
            Action::PowerOff => "power_off",
            Action::Isolate => "isolate",
            Action::Release => "release",
            Action::CryptoErase => "crypto_erase",
            Action::Admit => "admit",
            Action::Revoke => "revoke",
            Action::SetCustody => "set_custody",
            Action::Login => "login",
        }
    }

    /// Whether this acts on machines rather than on the roster of approvers
    /// or the site's custody policy.
    pub fn acts_on_machines(&self) -> bool {
        !matches!(
            self,
            Action::Admit | Action::Revoke | Action::SetCustody | Action::Login
        )
    }
}

/// What the order applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Target {
    /// One machine, by its node id.
    Node { id: String },
    /// Every machine under a failure domain.
    Domain { id: String },
    /// Every machine on the site.
    Cluster,
    /// A passkey credential, for `admit` and `revoke`.
    ///
    /// The key digest is part of what is approved, so an approval to admit one
    /// credential cannot be spent admitting a different key under the same id.
    Credential {
        /// The WebAuthn credential id, base64url without padding.
        id: String,
        /// SHA-256 of the credential's COSE public key, lowercase hex.
        key_sha256: String,
        /// The RP ID the credential was created for, so an approval names the
        /// domain the new credential will answer on.
        rp_id: String,
    },
    /// One custody change, for `set_custody`.
    Custody {
        /// SHA-256 of the change's signed bytes, lowercase hex.
        change_sha256: String,
    },
    /// One SSH key, as one user, on one machine.
    Login {
        user: String,
        node: String,
        /// SHA-256 of the SSH public key's wire encoding, lowercase hex.
        key_sha256: String,
    },
}

impl Target {
    fn kind(&self) -> &'static str {
        match self {
            Target::Node { .. } => "node",
            Target::Domain { .. } => "domain",
            Target::Cluster => "cluster",
            Target::Credential { .. } => "credential",
            Target::Custody { .. } => "custody",
            Target::Login { .. } => "login",
        }
    }
}

/// Limits on what an order may touch and for how long.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bounds {
    /// The most machines this order may resolve to. An order that turns out
    /// to cover more is refused rather than carried out in part: the person
    /// approving it was told a blast radius, and that is the one they agreed
    /// to.
    pub max_nodes: u32,
    /// How long the effect lasts before the node undoes it, where the action
    /// can be undone. `None` means until a further order.
    #[serde(default)]
    pub duration_s: Option<u64>,
}

/// One order, as proposed and as approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// The site's WebAuthn RP ID. Binds the order to one site, so an approval
    /// collected for one cannot be replayed at another.
    pub site: String,
    pub action: Action,
    pub target: Target,
    pub bounds: Bounds,
    /// Strictly increasing per node. A node refuses an order whose counter is
    /// not above the last one it carried out.
    pub counter: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Why, in the proposer's words. Recorded in the ledger.
    pub reason: String,
}

/// Why an order is not well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Malformed(pub String);

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed order: {}", self.0)
    }
}

impl std::error::Error for Malformed {}

fn lower_hex_digest(value: &str) -> Result<(), Malformed> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Malformed(
            "`target.key_sha256` must be 64 lowercase hex digits".into(),
        ));
    }
    Ok(())
}

/// The longest a `login` order may grant, in seconds: one working day. A
/// site's SSH policy may cap it lower; nothing may raise it.
pub const MAX_LOGIN_S: u64 = 24 * 3600;

/// A login user or machine name: letters, digits, `.`, `_` and `-`, starting
/// with a letter or digit, so neither can carry an `@`, a comma (a second
/// principal) or a line break.
fn login_name(what: &str, value: &str) -> Result<(), Malformed> {
    let ok = !value.is_empty()
        && value.len() <= 253
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(Malformed(format!(
            "the {what} must be letters, digits, `.`, `_` or `-`"
        )))
    }
}

/// The SSH key types a `login` order may certify: keys held by a FIDO
/// authenticator. A browser passkey's key is an `sk-ecdsa` key whose
/// application is the passkey's RP ID.
pub const FIDO_SSH_KEY_TYPES: [&str; 2] = [
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
];

/// SHA-256 of an SSH public key's wire encoding, from its OpenSSH line
/// (`<type> <base64> [comment]`): the digest a `login` order names. Returns
/// the key type with it, so a caller can refuse a key that is not a FIDO key.
pub fn ssh_key_sha256(openssh_line: &str) -> Result<(String, String), Malformed> {
    use data_encoding::BASE64;
    let mut parts = openssh_line.split_whitespace();
    let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
        return Err(Malformed("not an OpenSSH public key line".into()));
    };
    let blob = BASE64
        .decode(b64.as_bytes())
        .map_err(|_| Malformed("the public key is not base64".into()))?;
    // The blob starts with its own type name; one that disagrees with the
    // line's first field is not a key anybody meant.
    let named = blob
        .get(..4)
        .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
        .and_then(|n| blob.get(4..4usize.saturating_add(n)));
    if named != Some(kind.as_bytes()) {
        return Err(Malformed("the key's type does not match its encoding".into()));
    }
    Ok((kind.to_string(), hex::encode(Sha256::digest(&blob))))
}

fn one_line(name: &str, value: &str) -> Result<(), Malformed> {
    if value.contains('\n') || value.contains('\r') {
        return Err(Malformed(format!("`{name}` may not contain a line break")));
    }
    Ok(())
}

impl Order {
    /// Check the order is something a node could carry out as written.
    pub fn validate(&self) -> Result<(), Malformed> {
        one_line("site", &self.site)?;
        one_line("reason", &self.reason)?;
        if self.site.is_empty() {
            return Err(Malformed("`site` is empty".into()));
        }
        if self.expires_at <= self.issued_at {
            return Err(Malformed("`expires_at` is not after `issued_at`".into()));
        }
        if self.bounds.max_nodes == 0 {
            return Err(Malformed(
                "`bounds.max_nodes` is zero, so nothing could be carried out".into(),
            ));
        }
        match &self.target {
            Target::Node { id } | Target::Domain { id } => {
                one_line("target.id", id)?;
                if id.is_empty() {
                    return Err(Malformed("`target.id` is empty".into()));
                }
            }
            Target::Cluster => {}
            Target::Credential {
                id,
                key_sha256,
                rp_id,
            } => {
                one_line("target.id", id)?;
                one_line("target.rp_id", rp_id)?;
                if id.is_empty() || rp_id.is_empty() {
                    return Err(Malformed(
                        "a credential target needs an id and an RP ID".into(),
                    ));
                }
                lower_hex_digest(key_sha256)?;
            }
            Target::Custody { change_sha256 } => lower_hex_digest(change_sha256)?,
            Target::Login {
                user,
                node,
                key_sha256,
            } => {
                login_name("target user", user)?;
                login_name("target node", node)?;
                lower_hex_digest(key_sha256)?;
            }
        }
        match (self.action, &self.target) {
            (Action::Login, Target::Login { .. }) => {
                if self.bounds.max_nodes != 1 {
                    return Err(Malformed("`login` is for exactly one machine".into()));
                }
                match self.bounds.duration_s {
                    Some(d) if (1..=MAX_LOGIN_S).contains(&d) => Ok(()),
                    _ => Err(Malformed(format!(
                        "`login` needs `bounds.duration_s` between 1 and {MAX_LOGIN_S}"
                    ))),
                }
            }
            (Action::Login, _) => Err(Malformed(
                "`login` names one SSH key, user and machine".into(),
            )),
            (_, Target::Login { .. }) => Err(Malformed(format!(
                "`{}` does not grant a login",
                self.action.as_str()
            ))),
            (Action::Admit | Action::Revoke, Target::Credential { .. }) => Ok(()),
            (Action::SetCustody, Target::Custody { .. }) => Ok(()),
            (Action::SetCustody, _) => Err(Malformed(
                "`set_custody` names the custody change it applies, not a machine or a credential"
                    .into(),
            )),
            (_, Target::Custody { .. }) => Err(Malformed(format!(
                "`{}` does not apply a custody change",
                self.action.as_str()
            ))),
            (Action::Admit | Action::Revoke, _) => Err(Malformed(format!(
                "`{}` names a credential, not a machine",
                self.action.as_str()
            ))),
            (_, Target::Credential { .. }) => Err(Malformed(format!(
                "`{}` names machines, not a credential",
                self.action.as_str()
            ))),
            // A node isolates itself. An order that would have one node cut
            // off another, or a domain, is the act the policy invariant
            // refuses, so it is not expressible here either.
            (Action::Isolate | Action::Release, Target::Node { .. }) => {
                if self.bounds.max_nodes != 1 {
                    return Err(Malformed(format!(
                        "`{}` acts on exactly one node",
                        self.action.as_str()
                    )));
                }
                Ok(())
            }
            (Action::Isolate | Action::Release, _) => Err(Malformed(format!(
                "`{}` names the single node that acts on its own reach; it never removes \
                 anything from the overlay",
                self.action.as_str()
            ))),
            _ => Ok(()),
        }
    }

    /// The bytes an approval is made over. See the module documentation for
    /// the exact layout.
    pub fn canonical(&self) -> Result<Vec<u8>, Malformed> {
        self.validate()?;
        let login_id;
        let (id, key, rp_id) = match &self.target {
            Target::Login {
                user,
                node,
                key_sha256,
            } => {
                login_id = format!("{user}@{node}");
                (login_id.as_str(), key_sha256.as_str(), "")
            }
            Target::Node { id } | Target::Domain { id } => (id.as_str(), "", ""),
            Target::Cluster => ("", "", ""),
            Target::Credential {
                id,
                key_sha256,
                rp_id,
            } => (id.as_str(), key_sha256.as_str(), rp_id.as_str()),
            Target::Custody { change_sha256 } => ("", change_sha256.as_str(), ""),
        };
        let duration = self
            .bounds
            .duration_s
            .map(|d| d.to_string())
            .unwrap_or_else(|| "none".into());
        let text = format!(
            "{CANONICAL_HEADER}\n\
             site={}\n\
             action={}\n\
             target={}\n\
             target.id={id}\n\
             target.key_sha256={key}\n\
             target.rp_id={rp_id}\n\
             bounds.max_nodes={}\n\
             bounds.duration_s={duration}\n\
             counter={}\n\
             issued_at={}\n\
             expires_at={}\n\
             reason={}\n",
            self.site,
            self.action.as_str(),
            self.target.kind(),
            self.bounds.max_nodes,
            self.counter,
            self.issued_at,
            self.expires_at,
            self.reason,
        );
        Ok(text.into_bytes())
    }

    /// SHA-256 of the canonical bytes.
    pub fn hash(&self) -> Result<[u8; 32], Malformed> {
        Ok(Sha256::digest(self.canonical()?).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn halt(target: Target) -> Order {
        Order {
            site: "example.org".into(),
            action: Action::Halt,
            target,
            bounds: Bounds {
                max_nodes: 4,
                duration_s: None,
            },
            counter: 7,
            issued_at: 100,
            expires_at: 400,
            reason: "smoke from rack 1".into(),
        }
    }

    #[test]
    fn the_canonical_form_is_exactly_the_documented_one() {
        let o = halt(Target::Node {
            id: "node-a".into(),
        });
        let text = String::from_utf8(o.canonical().unwrap()).unwrap();
        assert_eq!(
            text,
            "furcate-order/1\nsite=example.org\naction=halt\ntarget=node\ntarget.id=node-a\n\
             target.key_sha256=\ntarget.rp_id=\nbounds.max_nodes=4\nbounds.duration_s=none\n\
             counter=7\nissued_at=100\nexpires_at=400\nreason=smoke from rack 1\n"
        );
    }

    #[test]
    fn every_field_changes_the_hash() {
        let base = halt(Target::Node {
            id: "node-a".into(),
        });
        let h = base.hash().unwrap();
        let mut variants = Vec::new();
        let mut o = base.clone();
        o.site = "other.org".into();
        variants.push(o);
        let mut o = base.clone();
        o.action = Action::PowerOff;
        variants.push(o);
        let mut o = base.clone();
        o.target = Target::Domain {
            id: "node-a".into(),
        };
        variants.push(o);
        let mut o = base.clone();
        o.bounds.max_nodes = 5;
        variants.push(o);
        let mut o = base.clone();
        o.bounds.duration_s = Some(60);
        variants.push(o);
        let mut o = base.clone();
        o.counter = 8;
        variants.push(o);
        let mut o = base.clone();
        o.expires_at = 401;
        variants.push(o);
        let mut o = base.clone();
        o.reason.push('.');
        variants.push(o);
        for v in variants {
            assert_ne!(v.hash().unwrap(), h, "{v:?}");
        }
    }

    #[test]
    fn a_line_break_cannot_forge_the_next_field() {
        let mut o = halt(Target::Node {
            id: "node-a".into(),
        });
        o.reason = "fine\ncounter=999".into();
        assert!(o.canonical().is_err());
        let o = halt(Target::Node { id: "a\rb".into() });
        assert!(o.validate().is_err());
    }

    #[test]
    fn isolate_names_exactly_one_node_and_nothing_else() {
        let mut o = halt(Target::Node {
            id: "node-a".into(),
        });
        o.action = Action::Isolate;
        o.bounds.max_nodes = 1;
        assert!(o.validate().is_ok());
        o.bounds.max_nodes = 2;
        assert!(o.validate().is_err());
        for t in [
            Target::Domain {
                id: "rack-1".into(),
            },
            Target::Cluster,
        ] {
            let mut o = halt(t);
            o.action = Action::Isolate;
            o.bounds.max_nodes = 1;
            assert!(
                o.validate().is_err(),
                "isolate must not reach past one node"
            );
        }
    }

    #[test]
    fn resume_reaches_what_halt_reaches_and_nothing_else() {
        for t in [
            Target::Node { id: "node-a".into() },
            Target::Domain { id: "rack-1".into() },
            Target::Cluster,
        ] {
            let mut o = halt(t);
            o.action = Action::Resume;
            o.validate().unwrap();
            assert!(String::from_utf8(o.canonical().unwrap()).unwrap().contains("\naction=resume\n"));
        }
        let mut o = halt(Target::Custody { change_sha256: "ab".repeat(32) });
        o.action = Action::Resume;
        assert!(o.validate().is_err());
        assert!(Action::Resume.acts_on_machines());
        assert!(Action::ALL.contains(&Action::Resume));
    }

    #[test]
    fn roster_actions_and_machine_actions_do_not_mix() {
        let cred = Target::Credential {
            id: "abc".into(),
            key_sha256: "0".repeat(64),
            rp_id: "site.example".into(),
        };
        let mut o = halt(cred.clone());
        assert!(o.validate().is_err());
        o.action = Action::Admit;
        assert!(o.validate().is_ok());
        let mut o = halt(Target::Cluster);
        o.action = Action::Revoke;
        assert!(o.validate().is_err());
    }

    #[test]
    fn set_custody_carries_the_change_digest_and_nothing_else() {
        let digest = "ab".repeat(32);
        let mut o = halt(Target::Custody { change_sha256: digest.clone() });
        assert!(o.validate().is_err(), "halt cannot name a custody change");
        o.action = Action::SetCustody;
        let text = String::from_utf8(o.canonical().unwrap()).unwrap();
        assert!(text.contains("action=set_custody\ntarget=custody\ntarget.id=\n"));
        assert!(text.contains(&format!("target.key_sha256={digest}\n")));
        let other = halt(Target::Custody { change_sha256: "cd".repeat(32) });
        let mut other = Order { action: Action::SetCustody, ..other };
        assert_ne!(o.hash().unwrap(), other.hash().unwrap());
        other.target = Target::Cluster;
        assert!(other.validate().is_err());
        other.target = Target::Custody { change_sha256: "AB".repeat(32) };
        assert!(other.validate().is_err(), "upper-case hex is refused");
        assert!(!Action::SetCustody.acts_on_machines());
    }

    #[test]
    fn an_order_that_ends_before_it_starts_is_refused() {
        let mut o = halt(Target::Cluster);
        o.expires_at = o.issued_at;
        assert!(o.validate().is_err());
    }

    const SK_KEY: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBI05E5HOabGO4jichqpkg3Kem8Kfzcfga3U30iHnyuIMcsdXWdPzImdPvN6ZJibBMw4a99t1yQbXeC6GU71JvuIAAAAUY29uc29sZS5leGFtcGxlLnRlc3Q= test";

    fn login(user: &str, node: &str, duration_s: Option<u64>) -> Order {
        Order {
            site: "example.org".into(),
            action: Action::Login,
            target: Target::Login {
                user: user.into(),
                node: node.into(),
                key_sha256: ssh_key_sha256(SK_KEY).unwrap().1,
            },
            bounds: Bounds { max_nodes: 1, duration_s },
            counter: 9,
            issued_at: 100,
            expires_at: 220,
            reason: "look at the disks".into(),
        }
    }

    #[test]
    fn a_login_order_names_user_at_node_and_the_key() {
        let o = login("root", "node-a", Some(3600));
        let text = String::from_utf8(o.canonical().unwrap()).unwrap();
        assert!(text.contains("action=login\ntarget=login\ntarget.id=root@node-a\n"), "{text}");
        assert!(text.contains(&format!("target.key_sha256={}\n", ssh_key_sha256(SK_KEY).unwrap().1)));
        assert!(text.contains("bounds.max_nodes=1\nbounds.duration_s=3600\n"));
    }

    #[test]
    fn a_login_order_is_bounded_in_time_and_to_one_machine() {
        assert!(login("root", "node-a", None).validate().is_err());
        assert!(login("root", "node-a", Some(0)).validate().is_err());
        assert!(login("root", "node-a", Some(MAX_LOGIN_S + 1)).validate().is_err());
        let mut o = login("root", "node-a", Some(60));
        o.bounds.max_nodes = 2;
        assert!(o.validate().is_err());
    }

    #[test]
    fn a_login_name_cannot_smuggle_a_second_principal() {
        for bad in ["root,admin", "root@x", "", "-root", "ro ot", "root\n"] {
            assert!(login(bad, "node-a", Some(60)).validate().is_err(), "{bad:?}");
            assert!(login("root", bad, Some(60)).validate().is_err(), "{bad:?}");
        }
        assert!(login("furcate-ops", "node-a.example.internal", Some(60)).validate().is_ok());
    }

    #[test]
    fn login_and_its_target_go_together() {
        let mut o = login("root", "node-a", Some(60));
        o.action = Action::Halt;
        assert!(o.validate().is_err());
        let mut o = halt(Target::Node { id: "node-a".into() });
        o.action = Action::Login;
        o.bounds = Bounds { max_nodes: 1, duration_s: Some(60) };
        assert!(o.validate().is_err());
    }

    #[test]
    fn the_ssh_key_digest_is_over_the_wire_blob_and_checks_the_type() {
        let (kind, digest) = ssh_key_sha256(SK_KEY).unwrap();
        assert_eq!(kind, FIDO_SSH_KEY_TYPES[0]);
        let blob = data_encoding::BASE64.decode(SK_KEY.split(' ').nth(1).unwrap().as_bytes()).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(&blob)));
        let lying = SK_KEY.replacen("sk-ecdsa-sha2-nistp256@openssh.com", "ssh-ed25519", 1);
        assert!(ssh_key_sha256(&lying).is_err());
        assert!(ssh_key_sha256("sk-ecdsa-sha2-nistp256@openssh.com !!!").is_err());
        assert!(ssh_key_sha256("").is_err());
    }
}
