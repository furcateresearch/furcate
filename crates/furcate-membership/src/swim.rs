//! SWIM membership state with Lifeguard local health awareness.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Refutation counter. A member increments its own incarnation to overrule a
/// stale suspicion about itself, which is what stops a false accusation from
/// being sticky.
pub type Incarnation = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberState {
    Alive,
    /// Suspected but not yet confirmed. The grace period before this becomes
    /// `Dead` is what Lifeguard stretches when the local node is unhealthy.
    Suspect,
    Dead,
    /// Voluntarily departed. Distinguished from `Dead` because a clean leave
    /// needs no rebalancing panic.
    Left,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub state: MemberState,
    pub incarnation: Incarnation,
    /// When the member entered `Suspect`, in logical ticks.
    pub suspect_since: Option<u64>,
}

/// What changed as a result of applying an update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    Added(String),
    /// A suspicion was raised.
    Suspected(String),
    /// The member refuted a suspicion with a higher incarnation.
    Refuted(String),
    /// Confirmed dead after the grace period elapsed.
    Confirmed(String),
    Departed(String),
    /// The update was stale or redundant.
    Ignored,
}

/// Lifeguard's local health multiplier.
///
/// Starts at the healthiest value and rises when this node observes evidence
/// that it, rather than its peers, is struggling. Timeouts are multiplied by
/// it, so an unhealthy node waits longer before declaring anyone dead.
#[derive(Clone, Debug)]
pub struct LocalHealth {
    score: u32,
    max: u32,
}

impl Default for LocalHealth {
    fn default() -> Self {
        // The paper's default: awareness in [1, 8].
        Self { score: 1, max: 8 }
    }
}

impl LocalHealth {
    pub fn score(&self) -> u32 {
        self.score
    }

    /// This node failed to do something it should have managed — a probe it
    /// sent went unanswered, or it noticed it was slow.
    pub fn punish(&mut self) {
        self.score = (self.score + 1).min(self.max);
    }

    /// This node did something successfully.
    pub fn reward(&mut self) {
        self.score = self.score.saturating_sub(1).max(1);
    }

    /// Scale a base timeout by current self-assessed health.
    pub fn scale(&self, base: u64) -> u64 {
        base * self.score as u64
    }
}

pub struct Membership {
    me: String,
    members: BTreeMap<String, Member>,
    /// Base ticks a member may remain suspect before being confirmed dead.
    suspicion_base: u64,
    health: LocalHealth,
    my_incarnation: Incarnation,
    /// Signed statements members make about themselves, carried on the same
    /// exchanges as membership (see [`crate::rumour`]).
    rumours: crate::rumour::Rumours,
}

impl Membership {
    pub fn new(me: impl Into<String>, suspicion_base: u64) -> Self {
        let me = me.into();
        let mut members = BTreeMap::new();
        members.insert(
            me.clone(),
            Member {
                id: me.clone(),
                state: MemberState::Alive,
                incarnation: 0,
                suspect_since: None,
            },
        );
        Self {
            me,
            members,
            suspicion_base,
            health: LocalHealth::default(),
            my_incarnation: 0,
            rumours: crate::rumour::Rumours::new(),
        }
    }

    pub fn rumours(&self) -> &crate::rumour::Rumours {
        &self.rumours
    }

    pub fn rumours_mut(&mut self) -> &mut crate::rumour::Rumours {
        &mut self.rumours
    }

    pub fn health(&mut self) -> &mut LocalHealth {
        &mut self.health
    }

    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    pub fn get(&self, id: &str) -> Option<&Member> {
        self.members.get(id)
    }

    /// Members currently considered reachable.
    pub fn alive(&self) -> Vec<&Member> {
        self.members
            .values()
            .filter(|m| m.state == MemberState::Alive)
            .collect()
    }

    pub fn join(&mut self, id: impl Into<String>) -> Transition {
        let id = id.into();
        if self.members.contains_key(&id) {
            return Transition::Ignored;
        }
        self.members.insert(
            id.clone(),
            Member {
                id: id.clone(),
                state: MemberState::Alive,
                incarnation: 0,
                suspect_since: None,
            },
        );
        Transition::Added(id)
    }

    /// Raise a suspicion about a member.
    ///
    /// A suspicion about *this* node is refuted immediately by bumping our own
    /// incarnation — we have first-hand evidence we are alive, and that
    /// evidence outranks a peer's inference.
    pub fn suspect(&mut self, id: &str, incarnation: Incarnation, now: u64) -> Transition {
        if id == self.me {
            self.my_incarnation = self.my_incarnation.max(incarnation) + 1;
            if let Some(m) = self.members.get_mut(&self.me) {
                m.incarnation = self.my_incarnation;
                m.state = MemberState::Alive;
                m.suspect_since = None;
            }
            // Being suspected is evidence this node may be the slow one.
            self.health.punish();
            return Transition::Refuted(self.me.clone());
        }

        let Some(m) = self.members.get_mut(id) else {
            return Transition::Ignored;
        };
        if matches!(m.state, MemberState::Dead | MemberState::Left) {
            return Transition::Ignored;
        }
        if incarnation < m.incarnation {
            return Transition::Ignored;
        }
        if m.state == MemberState::Suspect {
            return Transition::Ignored;
        }
        m.state = MemberState::Suspect;
        m.incarnation = incarnation;
        m.suspect_since = Some(now);
        Transition::Suspected(id.to_string())
    }

    /// A member proved it is alive, at a given incarnation.
    pub fn alive_update(&mut self, id: &str, incarnation: Incarnation) -> Transition {
        let Some(m) = self.members.get_mut(id) else {
            return self.join(id.to_string());
        };
        if incarnation < m.incarnation || m.state == MemberState::Left {
            return Transition::Ignored;
        }
        let was_suspect = m.state == MemberState::Suspect;
        m.state = MemberState::Alive;
        m.incarnation = incarnation;
        m.suspect_since = None;
        if was_suspect {
            Transition::Refuted(id.to_string())
        } else {
            Transition::Ignored
        }
    }

    pub fn leave(&mut self, id: &str) -> Transition {
        match self.members.get_mut(id) {
            Some(m) => {
                m.state = MemberState::Left;
                m.suspect_since = None;
                Transition::Departed(id.to_string())
            }
            None => Transition::Ignored,
        }
    }

    /// Advance time, confirming suspects whose grace period has elapsed.
    ///
    /// The grace period is scaled by local health, so a struggling node is
    /// slower to condemn its peers.
    pub fn tick(&mut self, now: u64) -> Vec<Transition> {
        let deadline = self.health.scale(self.suspicion_base);
        let mut out = Vec::new();
        for m in self.members.values_mut() {
            if m.state != MemberState::Suspect {
                continue;
            }
            if let Some(since) = m.suspect_since {
                if now.saturating_sub(since) >= deadline {
                    m.state = MemberState::Dead;
                    m.suspect_since = None;
                    out.push(Transition::Confirmed(m.id.clone()));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster() -> Membership {
        let mut m = Membership::new("node-a", 10);
        m.join("node-b");
        m
    }

    #[test]
    fn a_new_member_is_added_once() {
        let mut m = cluster();
        assert_eq!(m.join("node-c"), Transition::Added("node-c".into()));
        assert_eq!(m.join("node-c"), Transition::Ignored);
    }

    #[test]
    fn suspicion_becomes_death_only_after_the_grace_period() {
        let mut m = cluster();
        assert_eq!(
            m.suspect("node-b", 0, 100),
            Transition::Suspected("node-b".into())
        );
        assert!(m.tick(105).is_empty(), "must not condemn early");
        assert_eq!(
            m.tick(110),
            vec![Transition::Confirmed("node-b".into())]
        );
        assert_eq!(m.get("node-b").unwrap().state, MemberState::Dead);
    }

    #[test]
    fn an_unhealthy_node_waits_longer_before_condemning() {
        let mut m = cluster();
        m.health().punish();
        m.health().punish(); // score 3, so 30 ticks rather than 10
        m.suspect("node-b", 0, 0);
        assert!(m.tick(10).is_empty());
        assert!(m.tick(29).is_empty());
        assert_eq!(m.tick(30), vec![Transition::Confirmed("node-b".into())]);
    }

    #[test]
    fn health_recovers_and_shortens_the_wait_again() {
        let mut m = cluster();
        m.health().punish();
        m.health().punish();
        assert_eq!(m.health().score(), 3);
        m.health().reward();
        m.health().reward();
        assert_eq!(m.health().score(), 1, "floor is one, never zero");
    }

    #[test]
    fn a_higher_incarnation_refutes_a_suspicion() {
        let mut m = cluster();
        m.suspect("node-b", 0, 0);
        assert_eq!(
            m.alive_update("node-b", 1),
            Transition::Refuted("node-b".into())
        );
        assert_eq!(m.get("node-b").unwrap().state, MemberState::Alive);
    }

    #[test]
    fn a_stale_update_cannot_resurrect_an_old_view() {
        let mut m = cluster();
        m.alive_update("node-b", 5);
        assert_eq!(m.suspect("node-b", 3, 0), Transition::Ignored);
        assert_eq!(m.get("node-b").unwrap().state, MemberState::Alive);
    }

    #[test]
    fn suspecting_ourselves_refutes_and_punishes_local_health() {
        let mut m = cluster();
        let before = m.health().score();
        assert_eq!(
            m.suspect("node-a", 4, 0),
            Transition::Refuted("node-a".into())
        );
        assert_eq!(m.get("node-a").unwrap().state, MemberState::Alive);
        assert!(m.get("node-a").unwrap().incarnation > 4);
        assert!(m.health().score() > before, "being suspected is a signal about us");
    }

    #[test]
    fn a_clean_leave_is_not_a_failure() {
        let mut m = cluster();
        assert_eq!(m.leave("node-b"), Transition::Departed("node-b".into()));
        assert_eq!(m.get("node-b").unwrap().state, MemberState::Left);
        // And cannot be dragged back by a late suspicion.
        assert_eq!(m.suspect("node-b", 9, 0), Transition::Ignored);
    }

    #[test]
    fn alive_set_reflects_state() {
        let mut m = cluster();
        assert_eq!(m.alive().len(), 2);
        m.suspect("node-b", 0, 0);
        m.tick(100);
        assert_eq!(m.alive().len(), 1);
    }
}
