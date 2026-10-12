//! Pressure, which is not utilisation.
//!
//! The instinct is to watch CPU percentage and memory used, and both are close
//! to useless for deciding whether a machine is in trouble. A processor at a
//! hundred percent with nothing queued behind it is a processor doing its job.
//! A processor at forty percent with tasks stalled waiting on memory reclaim is
//! a machine falling over, and the utilisation graph will look calm the whole
//! way down.
//!
//! Pressure Stall Information measures the thing that actually matters: the
//! percentage of wall time during which work *could not proceed* because it was
//! waiting for CPU, for memory to be reclaimed, or for I/O. It is in the kernel
//! already, it costs nothing to read, and it is available per control group as
//! well as per machine — so the same number that says "this host is struggling"
//! also says which workload is doing it.
//!
//! The distinction between `some` and `full` carries most of the diagnostic
//! weight. `some` means at least one task was stalled while others ran, which
//! is ordinary contention. `full` means *nothing* ran — every task was blocked
//! at once — and on memory that is the signature of a machine about to spend
//! several minutes thrashing before the OOM killer resolves it.

use serde::{Deserialize, Serialize};

/// What a task can stall on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Cpu,
    Memory,
    Io,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Cpu => "cpu",
            Kind::Memory => "memory",
            Kind::Io => "io",
        }
    }

    /// Whether total stall on this resource means the machine has stopped.
    ///
    /// CPU has no `full` line in the kernel's own accounting at the system
    /// level, because a runnable task always eventually runs. Memory and I/O
    /// do, and full stall there is the shape of a machine that has stopped
    /// making progress rather than one that is merely busy.
    pub fn has_full(&self) -> bool {
        !matches!(self, Kind::Cpu)
    }
}

/// One pressure line: the share of time spent stalled, over three windows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Share {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    /// Microseconds of stall since boot. The only monotonic figure here, and
    /// the one to difference if a longer window than five minutes is wanted.
    pub total_us: u64,
}

/// Pressure on one resource.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Pressure {
    /// At least one task stalled while others made progress.
    pub some: Share,
    /// Every task stalled at once — nothing progressed.
    pub full: Share,
}

impl Pressure {
    /// Parse the two-line format the kernel writes.
    ///
    /// ```text
    /// some avg10=0.00 avg60=0.00 avg300=0.00 total=203640025
    /// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
    /// ```
    pub fn parse(text: &str) -> Option<Self> {
        let mut p = Pressure::default();
        let mut saw_any = false;
        for line in text.lines() {
            let mut f = line.split_whitespace();
            let which = f.next()?;
            let mut s = Share::default();
            for kv in f {
                let (k, v) = kv.split_once('=')?;
                match k {
                    "avg10" => s.avg10 = v.parse().ok()?,
                    "avg60" => s.avg60 = v.parse().ok()?,
                    "avg300" => s.avg300 = v.parse().ok()?,
                    "total" => s.total_us = v.parse().ok()?,
                    _ => {}
                }
            }
            match which {
                "some" => {
                    p.some = s;
                    saw_any = true;
                }
                "full" => p.full = s,
                _ => return None,
            }
        }
        saw_any.then_some(p)
    }
}

/// How bad the pressure is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Work is proceeding.
    Clear,
    /// Some contention. Normal on a busy machine and not a fault.
    Contended,
    /// Sustained stalling. Something is being starved.
    Starved,
    /// Total stall. The machine has stopped making progress.
    Stalled,
}

impl Level {
    /// Whether this warrants doing something rather than noting it.
    pub fn is_actionable(&self) -> bool {
        *self >= Level::Starved
    }
}

/// Thresholds, as percentages of wall time spent stalled.
///
/// Deliberately asymmetric between `some` and `full`. Ten percent of time with
/// one task waiting is a normal busy machine; ten percent with *everything*
/// waiting is a machine that has effectively lost a tenth of its existence, and
/// on memory it usually keeps getting worse on its own.
pub struct Thresholds {
    pub some_contended: f64,
    pub some_starved: f64,
    pub full_stalled: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            some_contended: 5.0,
            some_starved: 20.0,
            full_stalled: 10.0,
        }
    }
}

impl Thresholds {
    /// Judge a pressure reading over the one-minute window.
    ///
    /// The sixty-second average rather than the ten-second one: a ten-second
    /// spike is a compile finishing, and acting on it would make the system
    /// twitch at every burst of ordinary work.
    pub fn judge(&self, p: &Pressure, kind: Kind) -> Level {
        if kind.has_full() && p.full.avg60 >= self.full_stalled {
            return Level::Stalled;
        }
        if p.some.avg60 >= self.some_starved {
            Level::Starved
        } else if p.some.avg60 >= self.some_contended {
            Level::Contended
        } else {
            Level::Clear
        }
    }
}

/// Pressure across all three resources, for one machine or one control group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Psi {
    pub cpu: Pressure,
    pub memory: Pressure,
    pub io: Pressure,
}

impl Psi {
    pub fn of(&self, kind: Kind) -> &Pressure {
        match kind {
            Kind::Cpu => &self.cpu,
            Kind::Memory => &self.memory,
            Kind::Io => &self.io,
        }
    }

    /// The worst level across the three, and what caused it.
    pub fn worst(&self, t: &Thresholds) -> (Kind, Level) {
        [Kind::Memory, Kind::Io, Kind::Cpu]
            .into_iter()
            .map(|k| (k, t.judge(self.of(k), k)))
            .max_by_key(|(_, l)| *l)
            .unwrap_or((Kind::Cpu, Level::Clear))
    }

    /// Whether this machine should be given more work.
    ///
    /// The question a scheduler actually asks, and the one utilisation answers
    /// badly in both directions: a fully-loaded machine with no stalling has
    /// capacity to spare, and a half-loaded one that is thrashing does not.
    pub fn can_take_more(&self, t: &Thresholds) -> bool {
        !t.judge(&self.memory, Kind::Memory).is_actionable()
            && !t.judge(&self.io, Kind::Io).is_actionable()
            && t.judge(&self.cpu, Kind::Cpu) < Level::Starved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Pressure {
        Pressure::parse(
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=203640025\n\
             full avg10=0.00 avg60=0.00 avg300=0.00 total=0",
        )
        .unwrap()
    }

    fn at(some60: f64, full60: f64) -> Pressure {
        Pressure {
            some: Share { avg10: some60, avg60: some60, avg300: some60, total_us: 1 },
            full: Share { avg10: full60, avg60: full60, avg300: full60, total_us: 1 },
        }
    }

    #[test]
    fn the_kernels_own_format_parses() {
        let p = quiet();
        assert_eq!(p.some.total_us, 203_640_025);
        assert_eq!(p.full.total_us, 0);
        assert_eq!(p.some.avg10, 0.0);
    }

    #[test]
    fn a_single_line_file_still_parses() {
        // The CPU file on some kernels carries only `some`.
        let p = Pressure::parse("some avg10=1.50 avg60=2.25 avg300=0.75 total=5").unwrap();
        assert_eq!(p.some.avg60, 2.25);
        assert_eq!(p.full, Share::default());
    }

    #[test]
    fn garbage_does_not_parse_into_a_zero_reading() {
        // A failed parse returning a clear reading would report a struggling
        // machine as healthy, which is the worst direction to be wrong in.
        assert!(Pressure::parse("").is_none());
        assert!(Pressure::parse("nonsense here").is_none());
    }

    #[test]
    fn a_busy_machine_with_nothing_waiting_is_not_under_pressure() {
        // The inversion this module exists for: utilisation would read a
        // hundred percent and pressure reads zero, and pressure is right.
        let psi = Psi { cpu: quiet(), memory: quiet(), io: quiet() };
        assert_eq!(psi.worst(&Thresholds::default()).1, Level::Clear);
        assert!(psi.can_take_more(&Thresholds::default()));
    }

    #[test]
    fn a_half_loaded_machine_that_is_thrashing_is() {
        // And utilisation would call it half idle.
        let psi = Psi { cpu: quiet(), memory: at(45.0, 22.0), io: quiet() };
        let (kind, level) = psi.worst(&Thresholds::default());
        assert_eq!(kind, Kind::Memory);
        assert_eq!(level, Level::Stalled);
        assert!(!psi.can_take_more(&Thresholds::default()));
    }

    #[test]
    fn ordinary_contention_is_not_a_fault() {
        // Otherwise every busy machine raises an alarm and everyone stops
        // reading them.
        let psi = Psi { cpu: at(8.0, 0.0), memory: quiet(), io: quiet() };
        assert_eq!(psi.worst(&Thresholds::default()).1, Level::Contended);
        assert!(!Level::Contended.is_actionable());
        assert!(psi.can_take_more(&Thresholds::default()));
    }

    #[test]
    fn full_stall_outranks_partial_stall_on_the_same_resource() {
        // Everything waiting at once is a different condition from one thing
        // waiting a lot, and the memory case usually gets worse by itself.
        let t = Thresholds::default();
        assert_eq!(t.judge(&at(25.0, 0.0), Kind::Memory), Level::Starved);
        assert_eq!(t.judge(&at(25.0, 12.0), Kind::Memory), Level::Stalled);
    }

    #[test]
    fn cpu_has_no_full_stall_and_is_not_judged_on_one() {
        // A runnable task always eventually runs, so the kernel does not
        // report full CPU stall at the machine level; reading it as one would
        // invent a condition that cannot happen.
        assert!(!Kind::Cpu.has_full());
        assert_eq!(Thresholds::default().judge(&at(1.0, 99.0), Kind::Cpu), Level::Clear);
    }

    #[test]
    fn the_minute_window_decides_rather_than_the_ten_second_one() {
        // A ten-second spike is a compile finishing. Acting on it would make
        // the system twitch at every burst of ordinary work.
        let spike = Pressure {
            some: Share { avg10: 80.0, avg60: 1.0, avg300: 0.2, total_us: 1 },
            full: Share::default(),
        };
        assert_eq!(Thresholds::default().judge(&spike, Kind::Cpu), Level::Clear);
    }

    #[test]
    fn memory_outranks_io_and_cpu_when_all_three_are_bad() {
        let psi = Psi {
            cpu: at(30.0, 0.0),
            memory: at(30.0, 15.0),
            io: at(30.0, 5.0),
        };
        assert_eq!(psi.worst(&Thresholds::default()).0, Kind::Memory);
    }
}
