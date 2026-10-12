//! Who owns a machine.
//!
//! Distinct from every relationship Furcate already has, which is why it needed
//! its own primitive rather than a reuse of one. The ROSTER says a machine may
//! report and act, earned by attestation -- a fact about the hardware. A GRANT
//! says somebody may do something for a while, capped at a day, because a
//! delegation that outlives the task it was issued for is the thing delegation
//! is meant to avoid. PEOPLE says somebody's key is recognised here.
//!
//! None of those say whose machine it is. Ownership is durable -- it does not
//! lapse in a day, and a machine that fails attestation is still yours -- and
//! it answers a question the others cannot: which machines should a person see
//! when they sign in.
//!
//! Recorded here rather than in a console, so there is one answer. Two
//! registries is not merely duplication: they can disagree about who owns a
//! machine, and the one that says yes is the one an attacker uses. It also
//! means `furcatectl` answers it with no console running at all, which is the
//! test of whether something is really a platform primitive.
//!
//! An account is a free-form string, deliberately. Furcate does not run the
//! identity provider and must not pretend to: it records the name its operator
//! gave, and whoever signs somebody in decides what that name means. Binding
//! this to an email shape would break the first fleet that uses staff numbers.

use serde::{Deserialize, Serialize};


/// What an account may do with a fleet it belongs to.
///
/// Ordered, and compared as an order, so a check reads "Admin or better" and
/// keeps working when a role is added between. The alternative is a match arm
/// somewhere that silently omits the new one and quietly denies everybody in
/// it -- or worse, silently allows them.
///
/// Three roles rather than a permission matrix. This is a fleet of machines,
/// not a document system: the real distinctions are "can give the fleet away",
/// "can change what the machines do", and "can look". Anything finer belongs in
/// `policy grant`, which already exists, is time-bounded, and is the right tool
/// for "Priya may restart this one service until Friday".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Can see the fleet. Cannot change it.
    Member,
    /// Can operate the machines: services, resources, workloads. Cannot change
    /// who else is in the fleet, because an admin who can appoint admins is an
    /// owner with extra steps.
    Admin,
    /// Can do anything here, including adding and removing people and handing
    /// the fleet to somebody else.
    Owner,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Member => "member",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "member" => Role::Member,
            "admin" => Role::Admin,
            "owner" => Role::Owner,
            _ => return None,
        })
    }

    /// The policy roles this fleet role carries.
    ///
    /// The bridge between two layers that must not become two answers to one
    /// question. Fleet membership is AUTHORISATION -- what an account is
    /// entitled to here. `people.json` is AUTHENTICATION -- which key is
    /// admitted, and what roles the principal behind it holds. The policy
    /// engine matches rules against those roles (`role:admin`), and it is the
    /// only thing that actually gates a request.
    ///
    /// So membership does not check anything at the point of use. It decides
    /// what goes INTO an admission, once, when somebody is admitted. A second
    /// gate consulted at request time would be a second opinion about the same
    /// question, and the two would eventually disagree -- at which point the
    /// one that says yes is the one that matters.
    ///
    /// Cumulative: a rule written for `role:member` must keep covering an
    /// owner, or promoting somebody would take away access they had.
    pub fn policy_roles(self) -> Vec<&'static str> {
        match self {
            Role::Member => vec!["fleet-member"],
            Role::Admin => vec!["fleet-member", "fleet-admin"],
            Role::Owner => vec!["fleet-member", "fleet-admin", "fleet-owner"],
        }
    }

    /// The identifier this account is admitted under.
    ///
    /// `person:<account>` because `furcatectl people admit` requires that
    /// prefix, so an id can never be confused with `operator` or a node id.
    /// Built here rather than at each call site: three places spelling one
    /// convention is how a person ends up admitted under a name nothing else
    /// looks up.
    pub fn person_id(account: &str) -> String {
        format!("person:{account}")
    }

    /// Whether this role may operate machines.
    pub fn may_operate(self) -> bool {
        self >= Role::Admin
    }

    /// Whether this role may change who belongs to the fleet.
    pub fn may_administer_people(self) -> bool {
        self >= Role::Owner
    }
}

/// An account that belongs to this fleet, and what it may do.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub account: String,
    pub role: Role,
    pub added_at: u64,
    /// Who added them. An account that appeared with nobody accountable for it
    /// is the thing worth being able to ask about later.
    pub added_by: String,
}

/// One machine, and who owns it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub node_id: String,
    /// The account this machine belongs to, as the operator named it.
    pub account: String,
    /// When the claim was made, so a disputed one can be read in order.
    pub claimed_at: u64,
    /// Why. An unexplained claim is one nobody can review, which is the same
    /// standard `/policy/grant` already holds itself to.
    pub reason: String,
}

/// Every claim this site holds.
///
/// A map rather than a list, keyed by node: a machine has exactly one owner at
/// a time. Transfer is a claim that replaces the previous one, and is visible
/// as such, rather than an append that leaves two live claims and a rule
/// somewhere about which wins.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Owners {
    #[serde(default)]
    pub claims: std::collections::BTreeMap<String, Claim>,
    /// Accounts that belong to this fleet, by account name.
    ///
    /// Separate from the claims: a fleet has people, and a machine has an
    /// owner, and those are different questions. An admin who owns no machine
    /// personally still operates the fleet, and a machine claimed by somebody
    /// who has since left is still claimed -- releasing it is a decision, not
    /// a side effect of removing them.
    #[serde(default)]
    pub members: std::collections::BTreeMap<String, Member>,
}

impl Owners {
    pub fn new() -> Self {
        Self::default()
    }


    /// Add somebody to the fleet, or change the role they hold.
    ///
    /// Returns what they held before, so a change of role is reportable rather
    /// than silent -- being quietly demoted is confusing, and being quietly
    /// promoted is a security event.
    pub fn admit(&mut self, account: &str, role: Role, by: &str, now: u64) -> Option<Member> {
        self.members.insert(
            account.to_string(),
            Member {
                account: account.to_string(),
                role,
                added_at: now,
                added_by: by.to_string(),
            },
        )
    }

    /// Remove somebody.
    ///
    /// Refuses to remove the last owner: a fleet with no owner is one nobody
    /// can add an owner to, and the only remedy left is the operator key on the
    /// controller itself. Locking a customer out of their own fleet is not an
    /// acceptable outcome of a mis-click.
    pub fn withdraw(&mut self, account: &str) -> Result<Member, WithdrawError> {
        let Some(m) = self.members.get(account).cloned() else {
            return Err(WithdrawError::NotAMember);
        };
        if m.role == Role::Owner && self.owners_remaining() <= 1 {
            return Err(WithdrawError::LastOwner);
        }
        self.members.remove(account);
        Ok(m)
    }

    fn owners_remaining(&self) -> usize {
        self.members.values().filter(|m| m.role == Role::Owner).count()
    }

    pub fn role_of(&self, account: &str) -> Option<Role> {
        self.members.get(account).map(|m| m.role)
    }

    /// Whether this account may see this fleet at all.
    pub fn may_see(&self, account: &str) -> bool {
        self.members.contains_key(account)
    }

    /// Everybody in the fleet, by role then name, which is the order a list of
    /// people is useful in.
    pub fn roll(&self) -> Vec<&Member> {
        let mut v: Vec<&Member> = self.members.values().collect();
        v.sort_by(|a, b| b.role.cmp(&a.role).then(a.account.cmp(&b.account)));
        v
    }

    /// Record ownership, replacing any previous claim on that machine.
    ///
    /// Returns the claim it displaced, so a transfer can be reported rather
    /// than silently overwriting. A handover nobody is told about is how a
    /// machine ends up on somebody's screen without them knowing why.
    pub fn claim(&mut self, node_id: &str, account: &str, reason: &str, now: u64) -> Option<Claim> {
        self.claims.insert(
            node_id.to_string(),
            Claim {
                node_id: node_id.to_string(),
                account: account.to_string(),
                claimed_at: now,
                reason: reason.to_string(),
            },
        )
    }

    /// Give up a machine. Returns what was released, if anything.
    pub fn release(&mut self, node_id: &str) -> Option<Claim> {
        self.claims.remove(node_id)
    }

    pub fn owner_of(&self, node_id: &str) -> Option<&Claim> {
        self.claims.get(node_id)
    }

    /// Machines belonging to one account.
    ///
    /// Sorted, because this drives a list somebody reads and an order that
    /// changes between page loads for no reason is a bug in the screen.
    pub fn owned_by(&self, account: &str) -> Vec<&Claim> {
        let mut v: Vec<&Claim> = self.claims.values().filter(|c| c.account == account).collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    /// Every account that owns anything here.
    pub fn accounts(&self) -> Vec<String> {
        let mut v: Vec<String> = self.claims.values().map(|c| c.account.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Machines with no owner recorded.
    ///
    /// Reported rather than hidden. A fleet where some machines are claimed and
    /// others are not is the ordinary state during adoption, and a console that
    /// showed only claimed ones would make the rest look like they had stopped
    /// existing.
    pub fn unclaimed<'a>(&self, known: impl Iterator<Item = &'a String>) -> Vec<String> {
        let mut v: Vec<String> = known
            .filter(|n| !self.claims.contains_key(*n))
            .cloned()
            .collect();
        v.sort();
        v
    }
}


/// Why somebody could not be removed from a fleet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawError {
    NotAMember,
    /// The last owner. Removing them would leave a fleet nobody can administer.
    LastOwner,
}

impl std::fmt::Display for WithdrawError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WithdrawError::NotAMember => write!(f, "that account does not belong to this fleet"),
            WithdrawError::LastOwner => write!(
                f,
                "that is the last owner; appoint another owner first, or the fleet is left with nobody who can"
            ),
        }
    }
}

/// Write the claims out.
///
/// Temp-then-rename, the same shape the roster uses: a crash midway through
/// leaves the previous file intact rather than a truncated one, and a
/// half-written ownership record is a fleet that belongs to nobody.
pub fn save(owners: &Owners, path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let encoded = serde_json::to_vec_pretty(owners)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &encoded)?;
    std::fs::rename(&tmp, path)
}

/// Read the claims back.
///
/// Absent is ordinary and means nobody has claimed anything yet. Unlike the
/// roster nothing is dropped on load: ownership has no term, so there is no
/// such thing as a claim that lapsed while the controller was down.
pub fn load(path: &std::path::Path) -> std::io::Result<Owners> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Owners::new()),
        Err(e) => return Err(e),
    };
    serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_roles_are_cumulative_so_a_promotion_never_removes_access() {
        for (lower, higher) in [(Role::Member, Role::Admin), (Role::Admin, Role::Owner)] {
            for r in lower.policy_roles() {
                assert!(
                    higher.policy_roles().contains(&r),
                    "{} loses {r} that {} had",
                    higher.as_str(),
                    lower.as_str()
                );
            }
        }
        // And the id is the one `people admit` will accept.
        assert_eq!(Role::person_id("priya@example"), "person:priya@example");
    }

    #[test]
    fn roles_are_ordered_so_a_check_can_say_admin_or_better() {
        assert!(Role::Owner > Role::Admin);
        assert!(Role::Admin > Role::Member);
        assert!(Role::Admin.may_operate());
        assert!(!Role::Member.may_operate());
        // An admin who can appoint admins is an owner with extra steps.
        assert!(!Role::Admin.may_administer_people());
        assert!(Role::Owner.may_administer_people());
    }

    #[test]
    fn the_last_owner_cannot_be_removed() {
        let mut o = Owners::new();
        o.admit("alice@example", Role::Owner, "operator", 1);
        o.admit("bob@example", Role::Admin, "alice@example", 2);

        // An admin is not an owner, so removing the only owner is refused even
        // though somebody else remains.
        assert_eq!(o.withdraw("alice@example"), Err(WithdrawError::LastOwner));
        assert!(o.may_see("alice@example"));

        // With a second owner it is allowed.
        o.admit("carol@example", Role::Owner, "alice@example", 3);
        assert!(o.withdraw("alice@example").is_ok());
        assert!(!o.may_see("alice@example"));

        // And now carol is the last one.
        assert_eq!(o.withdraw("carol@example"), Err(WithdrawError::LastOwner));
    }

    #[test]
    fn a_role_change_reports_what_was_held_before() {
        let mut o = Owners::new();
        assert!(o.admit("bob@example", Role::Member, "alice@example", 1).is_none());
        let before = o.admit("bob@example", Role::Admin, "alice@example", 2);
        assert_eq!(before.map(|m| m.role), Some(Role::Member));
        assert_eq!(o.role_of("bob@example"), Some(Role::Admin));
    }

    #[test]
    fn removing_somebody_does_not_release_their_machines() {
        // Deliberate: a machine claimed by somebody who has left is still
        // claimed, and releasing it is a decision rather than a side effect.
        let mut o = Owners::new();
        o.admit("alice@example", Role::Owner, "operator", 1);
        o.admit("bob@example", Role::Admin, "alice@example", 1);
        o.claim("node:a", "bob@example", "his desk machine", 1);
        o.withdraw("bob@example").expect("not the last owner");
        assert!(!o.may_see("bob@example"));
        assert_eq!(o.owner_of("node:a").map(|c| c.account.as_str()), Some("bob@example"));
    }

    #[test]
    fn members_and_claims_both_survive_a_save() {
        let dir = std::env::temp_dir().join(format!("furcate-owners-roles-{}", std::process::id()));
        let path = dir.join("owners.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut o = Owners::new();
        o.admit("alice@example", Role::Owner, "operator", 7);
        o.claim("node:a", "alice@example", "hers", 7);
        save(&o, &path).expect("saves");

        let back = load(&path).expect("loads");
        assert_eq!(back.role_of("alice@example"), Some(Role::Owner));
        assert_eq!(back.owner_of("node:a").map(|c| c.reason.as_str()), Some("hers"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_machine_has_one_owner_and_a_transfer_says_what_it_displaced() {
        let mut o = Owners::new();
        assert!(o.claim("node:a", "alice@example", "hers", 100).is_none());
        let previous = o.claim("node:a", "bob@example", "sold", 200);
        assert_eq!(previous.map(|c| c.account), Some("alice@example".into()));
        // One live claim, not two.
        assert_eq!(o.claims.len(), 1);
        assert_eq!(o.owner_of("node:a").map(|c| c.account.as_str()), Some("bob@example"));
        assert!(o.owned_by("alice@example").is_empty());
    }

    #[test]
    fn owned_by_returns_only_that_accounts_machines() {
        let mut o = Owners::new();
        o.claim("node:b", "alice@example", "", 1);
        o.claim("node:a", "alice@example", "", 1);
        o.claim("node:c", "bob@example", "", 1);
        let hers: Vec<&str> = o.owned_by("alice@example").iter().map(|c| c.node_id.as_str()).collect();
        // Sorted, so a list somebody reads does not reshuffle between loads.
        assert_eq!(hers, vec!["node:a", "node:b"]);
        assert_eq!(o.accounts(), vec!["alice@example", "bob@example"]);
    }

    #[test]
    fn machines_nobody_has_claimed_are_reported_not_hidden() {
        let mut o = Owners::new();
        o.claim("node:a", "alice@example", "", 1);
        let known = vec!["node:a".to_string(), "node:b".to_string(), "node:c".to_string()];
        assert_eq!(o.unclaimed(known.iter()), vec!["node:b", "node:c"]);
    }

    #[test]
    fn releasing_returns_what_was_given_up() {
        let mut o = Owners::new();
        o.claim("node:a", "alice@example", "", 1);
        assert_eq!(o.release("node:a").map(|c| c.account), Some("alice@example".into()));
        assert!(o.release("node:a").is_none());
        assert!(o.owner_of("node:a").is_none());
    }

    #[test]
    fn a_saved_file_reads_back_the_same() {
        let dir = std::env::temp_dir().join(format!("furcate-owners-{}", std::process::id()));
        let path = dir.join("owners.json");
        let _ = std::fs::remove_dir_all(&dir);

        // Absent is not an error: nobody has claimed anything yet.
        assert!(load(&path).expect("absent loads").claims.is_empty());

        let mut o = Owners::new();
        o.claim("node:a", "alice@example", "the workstation", 42);
        save(&o, &path).expect("saves");
        let back = load(&path).expect("loads");
        assert_eq!(back.owner_of("node:a"), o.owner_of("node:a"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
