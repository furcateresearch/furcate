//! Signed statements that travel with membership gossip.
//!
//! Some facts about a member have to reach its peers when nothing else can
//! carry them. The case this exists for is a node that rebooted with a new
//! overlay key while the coordinator was down: the coordinator is a hint, and
//! a node that can reach the rebooted one, or one of its neighbours, should
//! learn the new key without it.
//!
//! This holds what members say about themselves and passes it on. It does not
//! judge: a statement is offered here only after the caller has checked its
//! signature, and every receiver checks again before offering it on, so a
//! member relaying something it was told adds no trust to it. What this does
//! decide is which of two checked statements from one origin is current — the
//! later version — and that nothing past its expiry is held or repeated.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One origin's statement about itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rumour {
    /// The member the statement is about, and from.
    pub origin: String,
    /// Higher replaces lower. For an overlay lease, its expiry: a later lease
    /// is always the newer key.
    pub version: u64,
    /// Seconds since the epoch after which this is dropped and not repeated.
    pub expires: u64,
    /// The statement, carried as received.
    pub body: serde_json::Value,
}

/// What happened to an offered statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// First statement held from this origin.
    New,
    /// Replaced an older one.
    Newer,
    /// Not newer than what is held; nothing changed.
    Stale,
    /// Already over.
    Expired,
    /// The store is at its limit with live statements from other origins.
    Full,
}

impl Taken {
    pub fn changed(&self) -> bool {
        matches!(self, Taken::New | Taken::Newer)
    }
}

/// The statements a member currently holds, one per origin.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Rumours {
    held: BTreeMap<String, Rumour>,
}

impl Rumours {
    /// Origins held at once. Gossip from a member that invents origins must
    /// not grow this without bound; a site is far smaller than this.
    pub const LIMIT: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    /// Hold a statement the caller has already verified.
    pub fn offer(&mut self, r: Rumour, now: u64) -> Taken {
        if r.expires <= now {
            return Taken::Expired;
        }
        match self.held.get(&r.origin) {
            Some(have) if have.version >= r.version && have.expires > now => return Taken::Stale,
            Some(_) => {
                self.held.insert(r.origin.clone(), r);
                return Taken::Newer;
            }
            None => {}
        }
        if self.held.len() >= Self::LIMIT {
            self.sweep(now);
            if self.held.len() >= Self::LIMIT {
                return Taken::Full;
            }
        }
        self.held.insert(r.origin.clone(), r);
        Taken::New
    }

    /// Replace the statement held for this origin by another of the same
    /// version, for a caller that has verified the new body is the origin's
    /// own and later than the one held. Returns whether anything was held to
    /// replace; a different version goes through [`Rumours::offer`].
    pub fn replace_same_version(&mut self, r: Rumour, now: u64) -> bool {
        match self.held.get_mut(&r.origin) {
            Some(have) if have.version == r.version && have.expires > now && r.expires > now => {
                *have = r;
                true
            }
            _ => false,
        }
    }

    pub fn get(&self, origin: &str) -> Option<&Rumour> {
        self.held.get(origin)
    }

    /// Everything still live, to repeat to the next member pinged.
    pub fn current(&self, now: u64) -> Vec<&Rumour> {
        self.held.values().filter(|r| r.expires > now).collect()
    }

    /// Drop what has expired. Returns how many went.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.held.len();
        self.held.retain(|_, r| r.expires > now);
        before - self.held.len()
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn r(origin: &str, version: u64, key: &str) -> Rumour {
        Rumour { origin: origin.into(), version, expires: version, body: json!({ "public_key": key }) }
    }

    #[test]
    fn a_rotated_key_replaces_the_one_before_it() {
        let mut g = Rumours::new();
        assert_eq!(g.offer(r("pi", 1_000, "old"), 10), Taken::New);
        assert_eq!(g.offer(r("pi", 2_000, "new"), 10), Taken::Newer);
        assert_eq!(g.get("pi").unwrap().body["public_key"], "new");
        // Hearing the old one again from a slower neighbour changes nothing.
        assert_eq!(g.offer(r("pi", 1_000, "old"), 10), Taken::Stale);
        assert_eq!(g.get("pi").unwrap().body["public_key"], "new");
    }

    #[test]
    fn an_expired_statement_is_neither_held_nor_repeated() {
        let mut g = Rumours::new();
        assert_eq!(g.offer(r("pi", 100, "k"), 100), Taken::Expired);
        assert_eq!(g.offer(r("pi", 200, "k"), 100), Taken::New);
        assert_eq!(g.current(150).len(), 1);
        assert!(g.current(200).is_empty());
        assert_eq!(g.sweep(200), 1);
        assert!(g.is_empty());
    }

    #[test]
    fn rotated_keys_spread_member_to_member() {
        // Three members; the coordinator plays no part. The rebooted node
        // tells one neighbour, which tells the next.
        let (mut a, mut b, mut c) = (Rumours::new(), Rumours::new(), Rumours::new());
        a.offer(r("pi", 1_000, "old"), 0);
        for x in a.current(0) {
            b.offer(x.clone(), 0);
        }
        for x in b.current(0) {
            c.offer(x.clone(), 0);
        }
        a.offer(r("pi", 2_000, "new"), 0);
        for x in a.current(0) {
            b.offer(x.clone(), 0);
        }
        for x in b.current(0) {
            c.offer(x.clone(), 0);
        }
        assert_eq!(c.get("pi").unwrap().body["public_key"], "new");
    }

    #[test]
    fn invented_origins_cannot_grow_the_store_without_bound() {
        let mut g = Rumours::new();
        for i in 0..Rumours::LIMIT {
            assert!(g.offer(r(&format!("n{i}"), 1_000, "k"), 0).changed());
        }
        assert_eq!(g.offer(r("one-more", 1_000, "k"), 0), Taken::Full);
        // Expired entries make room.
        assert_eq!(g.offer(r("one-more", 5_000, "k"), 1_000), Taken::New);
    }
}
