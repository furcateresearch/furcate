//! Where a machine sits relative to people, and what that costs.
//!
//! Every other judgement in this crate asks whether the hardware is well. This
//! one asks whether it is tolerable, which is a different question with a
//! different answer, and one no thermal threshold can reach.
//!
//! ## Why this exists
//!
//! A machine in a rack in a hall can run its fans flat out at three in the
//! morning and the only cost is electricity. The same machine in a cupboard in
//! someone's home at three in the morning is a person not sleeping. Nothing in
//! the hardware can tell those apart — the sensors read identically — so the
//! difference has to be declared.
//!
//! Furcate is built to operate nano data centres, and a nano data centre is
//! very often in a building people live in. Treating acoustics as somebody
//! else's problem is a choice to be unusable in the place the product is aimed
//! at.
//!
//! ## What it changes
//!
//! [`crate::cooling::Fault::RunningHardWhileCold`] is, on its own, a low
//! priority: nothing is breaking, and `is_thermal` correctly says it does not
//! warrant waking anyone. That reasoning holds in a machine room and inverts in
//! a bedroom. The fans are loud *for no reason* — no heat justifies them — and
//! the person who has to listen to it cannot fix it by waiting for a weekday.
//!
//! So placement and quiet hours are declared per machine, and a control fault
//! that lands inside them is urgent. The fault is the same; who it is costing
//! is not.
//!
//! ## Work somebody chose to start
//!
//! Fans on the machine this was measured on step from 4,000 to 9,200 RPM
//! between four and eight concurrent threads at an unchanged temperature, and a
//! power cap changed the noise not at all (see `furcate_resource::toolchain`).
//! So the envelope bounds what heat demands, but it cannot keep a build quiet;
//! only the width of the build can, or not running it.
//!
//! [`Builds`] declares which. `narrow` runs work at the chassis's measured
//! quiet width during the window. `refuse` does not start it until the window
//! ends — for a machine where "quieter" has been tried and the person it woke
//! still said no. The rule has to be declared rather than judged per build,
//! because the judgement "this one is small enough to be an exception" is
//! exactly the one that keeps being wrong at 22:00.
//!
//! ## What it deliberately does not do
//!
//! It does not set a fan speed, for the reasons [`crate::cooling`] gives, and
//! it does not act on anything by itself. A loud machine with a cold core is a
//! controller that has lost confidence in a reading, and the fix is to find out
//! which one — replacing its judgement with software's would convert a noise
//! problem into a thermal one. This module declares; the daemon reports and
//! publishes, and the privileged side enforces.

use serde::{Deserialize, Serialize};

/// Where this machine sits relative to people who are not operating it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// A room built for machines. Nobody is trying to sleep here.
    #[default]
    MachineRoom,
    /// An office, a workshop, a lab — people are present in working hours and
    /// noise is a nuisance rather than a harm.
    SharedSpace,
    /// A home, or close enough to one that noise reaches somebody's bedroom.
    ///
    /// The case Furcate is most often deployed into and the one every default
    /// in this crate was written against the grain of.
    LivingSpace,
}

impl Placement {
    /// Whether noise here reaches somebody who did not choose to hear it.
    pub fn is_occupied(self) -> bool {
        matches!(self, Placement::SharedSpace | Placement::LivingSpace)
    }
}

/// A daily window during which noise is not acceptable at this site.
///
/// Local hours, inclusive of `from` and exclusive of `to`, and it wraps: the
/// interesting window is the one that crosses midnight, so a type that could
/// not express `22..07` would be useless for the only case it is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietHours {
    /// Hour the window opens, 0–23 local.
    pub from: u8,
    /// Hour the window closes, 0–23 local.
    pub to: u8,
}

impl Default for QuietHours {
    /// Ten at night until seven in the morning.
    ///
    /// Not a guess at one household's habits — it is roughly where night-time
    /// noise limits sit in residential ordinance across most of Europe, which
    /// makes it a defensible starting point rather than a preference.
    fn default() -> Self {
        Self { from: 22, to: 7 }
    }
}

impl QuietHours {
    /// Whether `local_hour` falls inside the window.
    ///
    /// Returns `false` for an hour outside 0–23 rather than panicking or
    /// wrapping it: a bad clock reading should not silently be treated as
    /// quiet, because that is the direction that stays quiet about a problem.
    pub fn contains(&self, local_hour: u8) -> bool {
        if local_hour > 23 || self.from > 23 || self.to > 23 {
            return false;
        }
        if self.from == self.to {
            // A zero-width window is nobody's intent; read it as "always",
            // which is the safe reading — it can only make a report louder.
            return true;
        }
        if self.from < self.to {
            local_hour >= self.from && local_hour < self.to
        } else {
            // Wraps midnight.
            local_hour >= self.from || local_hour < self.to
        }
    }
}

/// What a quiet window does to work somebody chose to start — a build, above
/// all, since that is the work whose noise nobody can argue is necessary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Builds {
    /// Run, but no wider than the chassis's measured quiet width.
    ///
    /// The default, because it is the weaker claim and because it is what the
    /// build arm already did before this was declarable: a declaration written
    /// before this field existed means exactly what it meant then.
    #[default]
    Narrow,
    /// Do not start until the window ends.
    Refuse,
}

impl Builds {
    /// The spelling used on the wire and in the published declaration.
    pub fn as_str(self) -> &'static str {
        match self {
            Builds::Narrow => "narrow",
            Builds::Refuse => "refuse",
        }
    }
}

/// What this machine's declaration says about starting work now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildVerdict {
    /// Nobody is disturbed now. Width is the machine's business, not the clock's.
    Unrestricted,
    /// Inside a narrowing window: run at the quiet width.
    Narrow,
    /// Inside a refusing window: do not start.
    Refuse,
}

impl BuildVerdict {
    /// Whether work may start at all.
    pub fn permits_start(self) -> bool {
        !matches!(self, BuildVerdict::Refuse)
    }

    /// Whether work that runs must stay at the quiet width. This is what the
    /// `quiet` argument of `furcate_resource::Shape::size` should be.
    pub fn requires_quiet_width(self) -> bool {
        matches!(self, BuildVerdict::Narrow)
    }
}

/// This machine's acoustic situation, as the operator declared it.
///
/// Declared, never inferred. There is no measurement a machine can take of
/// itself that distinguishes a hall from a hallway, and guessing would be
/// wrong in whichever direction it guessed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acoustics {
    pub placement: Placement,
    /// When noise is unacceptable here. `None` means no window was declared.
    ///
    /// For a machine room that is the honest answer and costs nothing. For an
    /// occupied space it means the operator has not said, and
    /// [`Acoustics::disturbing`] falls back to the default window rather than
    /// concluding that every hour is fine — a missing declaration should not
    /// read as permission.
    pub quiet_hours: Option<QuietHours>,
    /// What the window does to builds. See [`Builds`].
    ///
    /// `#[serde(default)]` so every declaration written before this existed
    /// still loads, and loads as `narrow` — which is what it meant.
    #[serde(default)]
    pub builds: Builds,
}

impl Acoustics {
    /// A machine in a rack, where noise costs only electricity.
    pub fn machine_room() -> Self {
        Self {
            placement: Placement::MachineRoom,
            quiet_hours: None,
            builds: Builds::Narrow,
        }
    }

    /// A machine in a home, with the default night window.
    pub fn living_space() -> Self {
        Self {
            placement: Placement::LivingSpace,
            quiet_hours: Some(QuietHours::default()),
            builds: Builds::Narrow,
        }
    }

    /// The window in force here, which is not always the one declared.
    pub fn window(&self) -> Option<QuietHours> {
        match (self.quiet_hours, self.placement.is_occupied()) {
            (Some(w), _) => Some(w),
            // Declared occupied but no window given: assume there is one. The
            // alternative reading — "they did not say, so any hour is fine" —
            // turns an omission into consent on the operator's behalf.
            (None, true) => Some(QuietHours::default()),
            (None, false) => None,
        }
    }

    /// Whether noise from this machine is reaching somebody right now.
    ///
    /// `local_hour` is the hour at the *machine's* site. A fleet spans time
    /// zones, and judging a machine in one place by the clock in another is
    /// how a night-time alert arrives at lunchtime and is ignored.
    pub fn disturbing(&self, local_hour: u8) -> bool {
        self.placement.is_occupied() && self.window().is_some_and(|w| w.contains(local_hour))
    }

    /// Whether work may start now, and how wide.
    ///
    /// `None` is a clock nobody can vouch for, and on an occupied site it is
    /// read as *inside* the window. That is the opposite of how a bad hour is
    /// read for reporting, and deliberately: a report that stays quiet about a
    /// problem is the failure there, whereas here the failure is a build that
    /// starts at night because the machine was unsure what time it was. A
    /// refused build at noon on a broken clock is visible and costs a delay;
    /// the other mistake costs somebody's sleep.
    pub fn builds_at(&self, local_hour: Option<u8>) -> BuildVerdict {
        if !self.placement.is_occupied() {
            return BuildVerdict::Unrestricted;
        }
        let Some(window) = self.window() else {
            return BuildVerdict::Unrestricted;
        };
        let inside = match local_hour {
            Some(h) => window.contains(h),
            None => true,
        };
        if !inside {
            return BuildVerdict::Unrestricted;
        }
        match self.builds {
            Builds::Narrow => BuildVerdict::Narrow,
            Builds::Refuse => BuildVerdict::Refuse,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window that crosses midnight is the only one that matters, and a
    /// naive range check gets it exactly backwards — it would call 23:00 quiet
    /// hours' *opposite* and report nothing on the night this was written.
    #[test]
    fn a_window_that_wraps_midnight_covers_the_night() {
        let w = QuietHours { from: 22, to: 7 };
        for h in [22, 23, 0, 1, 3, 6] {
            assert!(w.contains(h), "{h}:00 should be inside 22..07");
        }
        for h in [7, 8, 12, 17, 21] {
            assert!(!w.contains(h), "{h}:00 should be outside 22..07");
        }
    }

    /// A window inside one day still works.
    #[test]
    fn a_window_inside_one_day_behaves_normally() {
        let w = QuietHours { from: 1, to: 5 };
        assert!(w.contains(1));
        assert!(w.contains(4));
        assert!(!w.contains(5));
        assert!(!w.contains(0));
    }

    /// A nonsense hour must not read as quiet. Silence is the failure mode
    /// this whole module exists to prevent, so an unreadable clock has to fall
    /// on the side of reporting.
    #[test]
    fn an_impossible_hour_is_not_treated_as_quiet() {
        assert!(!QuietHours::default().contains(24));
        assert!(!QuietHours { from: 99, to: 7 }.contains(23));
    }

    /// A rack in a hall is never disturbing anybody, at any hour. Without
    /// this, every machine in the fleet would escalate every night.
    #[test]
    fn a_machine_room_is_never_disturbing() {
        let a = Acoustics::machine_room();
        for h in 0..24u8 {
            assert!(!a.disturbing(h));
        }
    }

    /// A home at three in the morning is, which is the case that prompted
    /// this.
    #[test]
    fn a_home_at_night_is_disturbing() {
        let a = Acoustics::living_space();
        assert!(a.disturbing(0));
        assert!(a.disturbing(3));
        assert!(!a.disturbing(14));
    }

    /// **An omission is not consent.** A site declared as occupied with no
    /// window stated still gets one, because the reading "they did not say, so
    /// every hour is fine" decides something on the operator's behalf that
    /// they never said.
    #[test]
    fn an_occupied_site_without_a_declared_window_still_has_one() {
        let a = Acoustics {
            placement: Placement::LivingSpace,
            quiet_hours: None,
            builds: Builds::Narrow,
        };
        assert!(a.window().is_some());
        assert!(a.disturbing(2));
        assert!(!a.disturbing(13));
    }

    /// And a machine room without one does not acquire a window it does not
    /// need.
    #[test]
    fn a_machine_room_without_a_window_gets_none() {
        assert!(Acoustics::machine_room().window().is_none());
    }

    /// A declaration written before `builds` existed must still load, and
    /// mean what it meant: narrow, not refuse and not a parse error that
    /// silently resets the machine to a machine room.
    #[test]
    fn a_declaration_from_before_builds_existed_loads_as_narrow() {
        let a: Acoustics =
            serde_json::from_str(r#"{"placement":"living_space","quiet_hours":{"from":22,"to":7}}"#)
                .expect("an existing thermal.json must still parse");
        assert_eq!(a.builds, Builds::Narrow);
        assert_eq!(a.builds_at(Some(23)), BuildVerdict::Narrow);
    }

    /// The case this was added for: a machine in a home that does not build
    /// at night at all.
    #[test]
    fn a_refusing_home_does_not_start_builds_inside_its_window() {
        let a = Acoustics {
            placement: Placement::LivingSpace,
            quiet_hours: Some(QuietHours { from: 18, to: 8 }),
            builds: Builds::Refuse,
        };
        for h in [18, 22, 0, 1, 7] {
            assert!(!a.builds_at(Some(h)).permits_start(), "{h}:00 must refuse");
        }
        for h in [8, 12, 17] {
            assert_eq!(a.builds_at(Some(h)), BuildVerdict::Unrestricted, "{h}:00 is the working day");
        }
    }

    /// Refusing is not narrowing dressed up: asking whether to narrow must not
    /// accidentally admit the work.
    #[test]
    fn a_refusal_is_not_a_narrowing() {
        let v = Acoustics { builds: Builds::Refuse, ..Acoustics::living_space() }.builds_at(Some(1));
        assert!(!v.permits_start());
        assert!(!v.requires_quiet_width());
    }

    /// A narrowing home runs builds at night, quietly.
    #[test]
    fn a_narrowing_home_asks_for_the_quiet_width_at_night_only() {
        let a = Acoustics::living_space();
        assert!(a.builds_at(Some(1)).permits_start());
        assert!(a.builds_at(Some(1)).requires_quiet_width());
        assert!(!a.builds_at(Some(13)).requires_quiet_width());
    }

    /// A machine room is never restricted, whatever it declares about builds
    /// and whatever the clock says — including a clock nobody trusts.
    #[test]
    fn a_machine_room_never_restricts_builds() {
        let a = Acoustics { builds: Builds::Refuse, ..Acoustics::machine_room() };
        for h in 0..24u8 {
            assert_eq!(a.builds_at(Some(h)), BuildVerdict::Unrestricted);
        }
        assert_eq!(a.builds_at(None), BuildVerdict::Unrestricted);
    }

    /// An untrustworthy clock on an occupied site reads as inside the window,
    /// because the build that starts at night on a guess is the mistake that
    /// costs somebody else.
    #[test]
    fn an_unknown_hour_on_an_occupied_site_is_treated_as_night() {
        let a = Acoustics { builds: Builds::Refuse, ..Acoustics::living_space() };
        assert_eq!(a.builds_at(None), BuildVerdict::Refuse);
    }
}
