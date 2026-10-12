//! Whether a change happened when somebody said it could.
//!
//! The policy engine can already express a maintenance window: a grant with an
//! `until`, which permits an action for a period and then stops. What was
//! missing is the other half — nothing anywhere recorded that a change
//! *actually happened*, or whether it happened inside the window that was
//! agreed. A window with no record against it is a calendar, not an audit
//! trail, and the difference only becomes apparent at the moment somebody asks
//! what changed before the outage.
//!
//! ## An unapproved change is recorded, not refused
//!
//! This is the design decision worth stating plainly, because the obvious
//! alternative is worse. It would be easy to make an out-of-window change
//! impossible, and every operator who has been paged at 3 a.m. knows what
//! happens next: the change is made anyway, by hand, around whatever refused
//! it, and now it is both unapproved *and* invisible. Emergency changes are
//! legitimate. Unrecorded ones are not.
//!
//! So nothing here blocks anything. [`classify`] returns where a change stands
//! against the windows that were open, and an [`Standing::OutsideWindow`]
//! result is a fact to be written down beside the change — the record an
//! operator will want when they are asked, six weeks later, why the
//! configuration is not what the change board approved.
//!
//! Authority is a separate question and is answered by [`crate::engine`]: a
//! principal who may not perform an action at all is refused there, in-window
//! or not. This is only about *when*.

use serde::{Deserialize, Serialize};

/// A period in which a class of change was agreed to be acceptable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Window {
    /// Free-form identifier, as an operator would refer to it.
    pub id: String,
    /// Unix seconds, inclusive.
    pub starts_at: u64,
    /// Unix seconds, exclusive — a change at exactly `ends_at` is outside.
    /// A window that ends "at 02:00" is over at 02:00.
    pub ends_at: u64,
    /// What the window covers. Matched against a change's `action` with the
    /// same wildcard rule the policy engine uses: `*` is a whole field and
    /// never part of one.
    pub action: String,
    /// What the window covers, as a resource. `*` for the whole estate.
    pub resource: String,
    /// Who agreed to it. Not verified here — this records what was claimed,
    /// and the signature that backs it lives with the grant.
    pub approved_by: String,
}

impl Window {
    pub fn is_open_at(&self, now: u64) -> bool {
        now >= self.starts_at && now < self.ends_at
    }

    /// Whether this window covers a given action on a given resource.
    fn covers(&self, action: &str, resource: &str) -> bool {
        field_matches(&self.action, action) && field_matches(&self.resource, resource)
    }
}

/// `*` matches a whole field and never part of one.
///
/// The same rule the policy engine settled on, and for the same reason: a
/// pattern that reads differently to two people is worse than one that cannot
/// express the case. `node:*` covers `node:node-a` and not `nodenode-a`.
fn field_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

/// Something that was done to the estate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Change {
    /// Unix seconds at which it happened.
    pub at: u64,
    /// Who did it.
    pub actor: String,
    /// What was done, e.g. `deploy`, `drain`, `policy_change`.
    pub action: String,
    /// What it was done to, e.g. `node:node-a`.
    pub resource: String,
    /// What the actor said they were doing, in their own words.
    pub reason: String,
}

/// Where a change stands against the windows that were open.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// Made inside a window that covered it.
    InsideWindow { window: String, approved_by: String },
    /// Made when no window covered it.
    ///
    /// Not an error and not a refusal. It is the fact that has to survive to
    /// the review, and the near-miss reason is carried so the reviewer is not
    /// left guessing: a change made four minutes after its window closed is a
    /// different conversation from one made with no window at all.
    OutsideWindow { nearest: Option<NearMiss> },
}

/// The window that most nearly covered a change, and by how much it missed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NearMiss {
    pub window: String,
    /// Seconds between the change and the window. Negative before it opened,
    /// positive after it closed.
    pub off_by_secs: i64,
}

impl Standing {
    pub fn is_approved(&self) -> bool {
        matches!(self, Standing::InsideWindow { .. })
    }
}

/// Place a change against the windows that existed.
///
/// A window only counts if it covers the action *and* the resource: a window
/// opened to drain one node does not authorise a deploy across the estate, and
/// treating any open window as blanket cover would make the record worthless
/// precisely when it is being relied on.
pub fn classify(change: &Change, windows: &[Window]) -> Standing {
    for w in windows {
        if w.is_open_at(change.at) && w.covers(&change.action, &change.resource) {
            return Standing::InsideWindow {
                window: w.id.clone(),
                approved_by: w.approved_by.clone(),
            };
        }
    }

    // Nothing covered it. Find the closest window that *would* have, so the
    // record distinguishes "ran over by four minutes" from "no window at all".
    let nearest = windows
        .iter()
        .filter(|w| w.covers(&change.action, &change.resource))
        .map(|w| {
            let off = if change.at < w.starts_at {
                change.at as i64 - w.starts_at as i64
            } else {
                change.at as i64 - w.ends_at as i64 + 1
            };
            NearMiss {
                window: w.id.clone(),
                off_by_secs: off,
            }
        })
        .min_by_key(|n| n.off_by_secs.abs());

    Standing::OutsideWindow { nearest }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: u64 = 1_000_000;
    const CLOSE: u64 = 1_003_600; // one hour

    fn window() -> Window {
        Window {
            id: "cab-114".into(),
            starts_at: OPEN,
            ends_at: CLOSE,
            action: "deploy".into(),
            resource: "node:*".into(),
            approved_by: "operator".into(),
        }
    }

    fn change_at(at: u64) -> Change {
        Change {
            at,
            actor: "alice".into(),
            action: "deploy".into(),
            resource: "node:node-a".into(),
            reason: "ship the edge fix".into(),
        }
    }

    #[test]
    fn a_change_inside_its_window_carries_who_approved_it() {
        let s = classify(&change_at(OPEN + 60), &[window()]);
        assert_eq!(
            s,
            Standing::InsideWindow {
                window: "cab-114".into(),
                approved_by: "operator".into()
            }
        );
        assert!(s.is_approved());
    }

    #[test]
    fn the_window_is_over_at_the_moment_it_says() {
        // A window that ends at 02:00 is over at 02:00, not one second later.
        assert!(window().is_open_at(CLOSE - 1));
        assert!(!window().is_open_at(CLOSE));
    }

    #[test]
    fn a_change_that_ran_over_records_by_how_much() {
        // The distinction a reviewer actually needs: four minutes late is a
        // different conversation from no window at all.
        let s = classify(&change_at(CLOSE + 240), &[window()]);
        match s {
            Standing::OutsideWindow {
                nearest: Some(near),
            } => {
                assert_eq!(near.window, "cab-114");
                assert_eq!(near.off_by_secs, 241);
            }
            other => panic!("expected a near miss, got {other:?}"),
        }
    }

    #[test]
    fn a_change_with_no_window_at_all_says_so() {
        let s = classify(&change_at(OPEN + 60), &[]);
        assert_eq!(s, Standing::OutsideWindow { nearest: None });
        assert!(!s.is_approved());
    }

    #[test]
    fn a_window_for_one_thing_does_not_authorise_another() {
        // A window opened to drain one node is not blanket cover for a deploy
        // across the estate. Treating it as such would make the record
        // worthless exactly when it is being relied on.
        let drain_only = Window {
            action: "drain".into(),
            resource: "node:node-b".into(),
            ..window()
        };
        let s = classify(&change_at(OPEN + 60), &[drain_only]);
        // Not even a near miss: the window never covered this change, so it is
        // not a candidate for one.
        assert_eq!(s, Standing::OutsideWindow { nearest: None });
    }

    #[test]
    fn a_wildcard_matches_a_whole_field_and_not_part_of_one() {
        let w = window();
        assert!(w.covers("deploy", "node:node-a"));
        assert!(w.covers("deploy", "node:"));
        assert!(!w.covers("deploy", "nodenode-a"));
        assert!(!w.covers("drain", "node:node-a"));
    }

    #[test]
    fn an_emergency_change_is_recorded_rather_than_refused() {
        // Nothing here returns an error or a refusal. The 3 a.m. change is
        // going to happen; the only question is whether it is written down.
        let s = classify(&change_at(CLOSE + 86_400), &[window()]);
        assert!(!s.is_approved());
        assert!(matches!(s, Standing::OutsideWindow { nearest: Some(_) }));
    }

    #[test]
    fn the_nearest_window_is_the_one_reported() {
        let earlier = Window {
            id: "cab-113".into(),
            starts_at: OPEN - 100_000,
            ends_at: OPEN - 90_000,
            ..window()
        };
        let s = classify(&change_at(CLOSE + 60), &[earlier, window()]);
        match s {
            Standing::OutsideWindow {
                nearest: Some(near),
            } => assert_eq!(near.window, "cab-114"),
            other => panic!("expected the closer window, got {other:?}"),
        }
    }
}
