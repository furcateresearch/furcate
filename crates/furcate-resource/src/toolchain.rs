//! Sizing a build to the machine it runs on.
//!
//! [`crate::psi`] answers whether a machine is coping and [`crate::cgroup`]
//! bounds what one workload may take. This answers the question before either:
//! how large should the work have been in the first place.
//!
//! # Why a build needs its own primitive
//!
//! Most workloads are sized by someone who knows what they are. A build is
//! sized by a default — `cargo` uses the logical CPU count for `-j`, and that
//! default is about *cores* on a machine whose real constraint is usually
//! *memory*. On a 56-thread machine it starts 56 compiler processes, and if
//! each needs four gigabytes it has asked for 224 GB on a box that has 121.
//!
//! That is not hypothetical. A single `rustc` compiling one large crate was
//! measured at 4.0 GB resident on the machine this was written for. The
//! machine had 121 GB and the default would have asked for nearly twice that.
//!
//! The failure is also the *worst* shape of failure: it arrives at the end of a
//! long build, it takes the machine rather than the build, and because the
//! default came from the core count it looks like the machine is too small
//! rather than the job too wide.
//!
//! # What is specific to Rust, and why `-j` is the right knob
//!
//! A Rust build is not steadily parallel. Each crate runs a largely **serial
//! front-end** — parse, type-check, borrow-check, MIR — then a **parallel
//! back-end** where the compiler converts MIR to LLVM IR one codegen unit at a
//! time and hands each to an LLVM thread, then a **serial link**. The parallel
//! front-end exists but is opt-in and nightly, and the Cargo book recommends at
//! most eight threads for it.
//!
//! So a build alternates between one core and all of them, which is why
//! watching average load tells you almost nothing about a build machine. It is
//! also why `-j` is the correct control rather than per-process thread counts:
//! Cargo's compiler processes coordinate through the GNU Make jobserver, so
//! bounding the number of processes bounds the total threads. Setting both
//! would bound it twice and starve the back-end.
//!
//! # What this does not do
//!
//! It does not measure. The peak resident size of a compiler process depends on
//! the crate, and a number invented here would be exactly the kind of plausible
//! default that caused the problem. [`Observed`] carries it when somebody has
//! watched a real build, and [`Shape::bounded_by`] says plainly when nobody
//! has — a caller that cannot tell "sized against measurement" from "sized
//! against core count" will eventually report the second as the first.

use serde::{Deserialize, Serialize};

/// A build system whose shape is known.
///
/// One variant, because one is what has been studied. Adding a toolchain means
/// establishing how it parallelises and what it holds in memory, not adding a
/// name to a list — a `Go` arm guessing at Rust's numbers would be worse than
/// its absence, because absence is visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Toolchain {
    /// Cargo and rustc.
    Rust,
}

/// What the machine offers a build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Machine {
    /// Logical CPUs, which is what `cargo` would use for `-j` unaided.
    pub logical_cpus: u32,
    /// Memory a build may actually use, in bytes.
    ///
    /// Not total RAM. What is left after everything else the machine is for —
    /// on a node that also serves, the serving is not spare capacity.
    pub usable_bytes: u64,
    /// The widest this machine runs without its fans becoming audible.
    ///
    /// Measured, and it has to be, because it is a property of the chassis
    /// rather than of the processor and no specification states it. On the
    /// machine this was written for the fans step from 4,000 to 9,200 RPM
    /// between four and eight concurrent threads, at a constant 45–50 °C —
    /// so it is a response to concurrency, not to heat or to package power.
    ///
    /// That is why this is a separate number from anything thermal. Capping
    /// power on that machine cut package draw by 29% and the core temperature
    /// by 11 °C and changed the fan speed not at all; only running narrower
    /// did. A site that tried to buy quiet with a power limit would slow its
    /// builds and stay just as loud.
    ///
    /// `None` where nobody has measured it, which means noise is not
    /// considered rather than assumed absent.
    pub quiet_jobs: Option<u32>,
}

/// What somebody has actually seen a build do here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    /// The largest resident set one compiler process reached, in bytes.
    ///
    /// `None` when nobody has watched. Never defaulted: see the module note.
    pub peak_job_bytes: Option<u64>,
}

/// Which constraint decided the width of the build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bound {
    /// The machine's cores. What `cargo` would have chosen anyway.
    Cores,
    /// Memory, from a measured peak. The case the default gets wrong.
    Memory,
    /// The floor of one job. A machine that cannot fit a single compiler
    /// process will fail either way; it fails faster and more legibly with one.
    Floor,
    /// Nobody has measured a build here, so this is the core count and is
    /// *not* evidence the machine can take it.
    Unmeasured,
    /// Noise. The machine could run wider and somebody would hear it.
    Acoustic,
}

impl Bound {
    /// Whether this width rests on a measurement rather than on a default.
    pub fn is_measured(self) -> bool {
        matches!(self, Bound::Memory | Bound::Floor | Bound::Acoustic)
    }
}

/// How wide a build should run here, and what decided it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shape {
    /// Concurrent compiler processes — `cargo -j`.
    pub jobs: u32,
    /// What that number came from.
    pub bounded_by: Bound,
    /// One line an operator can read, naming the arithmetic.
    pub because: String,
}

impl Shape {
    /// Size a build of `toolchain` for `machine`, given what has been seen.
    ///
    /// `quiet` asks for a width that will not be heard. It only ever narrows:
    /// a machine that must stay quiet runs no wider than its measured quiet
    /// width, and a machine already narrower than that for memory reasons is
    /// left alone.
    pub fn size(
        toolchain: Toolchain,
        machine: &Machine,
        observed: &Observed,
        quiet: bool,
    ) -> Self {
        let shape = match toolchain {
            Toolchain::Rust => Self::size_rust(machine, observed),
        };
        match (quiet, machine.quiet_jobs) {
            (true, Some(q)) if q < shape.jobs => Shape {
                jobs: q.max(1),
                bounded_by: Bound::Acoustic,
                because: format!(
                    "{} jobs to stay quiet, down from {}. This machine's fans step to \
                     maximum above {} concurrent jobs at an unchanged temperature, so the \
                     only lever that reaches the noise is running narrower — a power limit \
                     does not.",
                    q.max(1),
                    shape.jobs,
                    q
                ),
            },
            _ => shape,
        }
    }

    fn size_rust(machine: &Machine, observed: &Observed) -> Self {
        let cpus = machine.logical_cpus.max(1);

        let Some(peak) = observed.peak_job_bytes.filter(|b| *b > 0) else {
            return Shape {
                jobs: cpus,
                bounded_by: Bound::Unmeasured,
                because: format!(
                    "{cpus} jobs, the core count, because no compiler process has been \
                     measured here. This is what cargo would do unaided and it is not \
                     evidence the machine can take it."
                ),
            };
        };

        let by_memory = machine.usable_bytes / peak;
        if by_memory == 0 {
            return Shape {
                jobs: 1,
                bounded_by: Bound::Floor,
                because: format!(
                    "1 job, and even that may not fit: a compiler process peaked at {} and \
                     only {} is usable. A build here will fail; it will fail sooner and more \
                     clearly at one job than at {cpus}.",
                    human(peak),
                    human(machine.usable_bytes)
                ),
            };
        }

        let by_memory = u32::try_from(by_memory).unwrap_or(u32::MAX);
        if by_memory < cpus {
            Shape {
                jobs: by_memory,
                bounded_by: Bound::Memory,
                because: format!(
                    "{by_memory} jobs: {} usable divided by a measured {} peak per compiler \
                     process. The core count would have been {cpus}, which asks for {} and \
                     takes the machine rather than the build.",
                    human(machine.usable_bytes),
                    human(peak),
                    human(u64::from(cpus) * peak)
                ),
            }
        } else {
            Shape {
                jobs: cpus,
                bounded_by: Bound::Cores,
                because: format!(
                    "{cpus} jobs, the core count: {} usable fits {by_memory} processes at a \
                     measured {} peak, so memory is not the constraint here.",
                    human(machine.usable_bytes),
                    human(peak)
                ),
            }
        }
    }
}

/// Bytes as an operator would say them. Deliberately coarse: the figure is an
/// order of magnitude and rendering it to three decimals would imply otherwise.
fn human(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{} MB", bytes / MB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GB: u64 = 1024 * 1024 * 1024;

    fn node_c() -> Machine {
        Machine {
            logical_cpus: 56,
            usable_bytes: 121 * GB,
            // Measured on that machine: quiet at four concurrent jobs, at
            // maximum by eight.
            quiet_jobs: Some(4),
        }
    }

    /// **The case that takes a machine.** Measured on the box this was written
    /// for: one `rustc` at 4.0 GB resident, 56 logical CPUs, 121 GB of RAM.
    /// Cargo's default asks for 56 processes — 224 GB — and the machine has
    /// 121. The width has to come from memory, not cores.
    #[test]
    fn a_large_rust_build_is_bounded_by_memory_and_not_by_cores() {
        let s = Shape::size(
            Toolchain::Rust,
            &node_c(),
            &Observed {
                peak_job_bytes: Some(4 * GB),
            }, false,
        );
        assert_eq!(s.jobs, 30, "121 / 4");
        assert_eq!(s.bounded_by, Bound::Memory);
        assert!(s.because.contains("224.0 GB"), "{}", s.because);
    }

    /// **The measurement that redirected this.** On node-c the fans step from
    /// 4,000 to 9,200 RPM between four and eight concurrent threads, at a
    /// constant 45-50 C. Capping package power on that machine cut draw by 29%
    /// and core temperature by 11 C and moved the fans not at all. Width is the
    /// only lever that reaches the noise.
    #[test]
    fn a_quiet_build_is_narrowed_to_the_measured_quiet_width() {
        let s = Shape::size(
            Toolchain::Rust,
            &node_c(),
            &Observed { peak_job_bytes: Some(256 * 1024 * 1024) },
            true,
        );
        assert_eq!(s.jobs, 4, "56 cores and memory to spare, but four is what is quiet");
        assert_eq!(s.bounded_by, Bound::Acoustic);
        assert!(s.because.contains("a power limit"), "{}", s.because);
    }

    /// It only ever narrows. A build already down to one job for memory
    /// reasons is not widened back up to the quiet width.
    #[test]
    fn the_acoustic_bound_never_widens_a_build() {
        let tiny = Machine { logical_cpus: 8, usable_bytes: 2 * GB, quiet_jobs: Some(4) };
        let s = Shape::size(
            Toolchain::Rust,
            &tiny,
            &Observed { peak_job_bytes: Some(4 * GB) },
            true,
        );
        assert_eq!(s.jobs, 1, "memory still decides");
        assert_eq!(s.bounded_by, Bound::Floor);
    }

    /// A machine whose quiet width nobody has measured is not silently
    /// throttled. Noise is then not considered, which is different from
    /// assuming there is none.
    #[test]
    fn an_unmeasured_quiet_width_does_not_narrow_anything() {
        let m = Machine { logical_cpus: 56, usable_bytes: 121 * GB, quiet_jobs: None };
        let s = Shape::size(
            Toolchain::Rust,
            &m,
            &Observed { peak_job_bytes: Some(256 * 1024 * 1024) },
            true,
        );
        assert_eq!(s.jobs, 56);
        assert_ne!(s.bounded_by, Bound::Acoustic);
    }

    /// And asking for quiet outside quiet hours changes nothing.
    #[test]
    fn a_build_that_need_not_be_quiet_runs_at_full_width() {
        let s = Shape::size(
            Toolchain::Rust,
            &node_c(),
            &Observed { peak_job_bytes: Some(256 * 1024 * 1024) },
            false,
        );
        assert_eq!(s.jobs, 56);
    }

    /// A small build on the same machine is not artificially narrowed. The
    /// point is to stop asking for more than exists, not to run everything at
    /// half speed.
    #[test]
    fn a_small_rust_build_uses_every_core() {
        let s = Shape::size(
            Toolchain::Rust,
            &node_c(),
            &Observed {
                peak_job_bytes: Some(256 * 1024 * 1024),
            }, false,
        );
        assert_eq!(s.jobs, 56);
        assert_eq!(s.bounded_by, Bound::Cores);
    }

    /// **Unmeasured is said out loud.** Falling back to the core count is the
    /// only thing available, and a caller must be able to tell that apart from
    /// a width that was actually computed — otherwise the fallback gets
    /// reported as a decision.
    #[test]
    fn an_unmeasured_machine_says_so_rather_than_inventing_a_peak() {
        let s = Shape::size(Toolchain::Rust, &node_c(), &Observed::default(), false);
        assert_eq!(s.jobs, 56);
        assert_eq!(s.bounded_by, Bound::Unmeasured);
        assert!(!s.bounded_by.is_measured());
        assert!(s.because.contains("not evidence"), "{}", s.because);
    }

    /// A machine too small for one compiler process fails either way. It
    /// should fail at one job, where the error is about the machine, rather
    /// than at fifty-six, where it looks like a stampede.
    #[test]
    fn a_machine_that_cannot_fit_one_job_is_told_plainly() {
        let tiny = Machine {
            logical_cpus: 8,
            usable_bytes: 2 * GB,
            quiet_jobs: None,
        };
        let s = Shape::size(
            Toolchain::Rust,
            &tiny,
            &Observed {
                peak_job_bytes: Some(4 * GB),
            }, false,
        );
        assert_eq!(s.jobs, 1);
        assert_eq!(s.bounded_by, Bound::Floor);
        assert!(s.because.contains("will fail"), "{}", s.because);
    }

    /// Never zero. A width of zero would be read by cargo as "use the default",
    /// which is the exact number this exists to replace.
    #[test]
    fn the_width_is_never_zero() {
        for usable in [0u64, 1, 1024, GB] {
            for cpus in [0u32, 1, 56] {
                let s = Shape::size(
                    Toolchain::Rust,
                    &Machine {
                        logical_cpus: cpus,
                        usable_bytes: usable,
                        quiet_jobs: None,
                    },
                    &Observed {
                        peak_job_bytes: Some(4 * GB),
                    },
                    false,
                );
                assert!(s.jobs >= 1, "usable={usable} cpus={cpus} gave {}", s.jobs);
            }
        }
    }

    /// A zero measurement is not a measurement. Dividing by it would panic,
    /// and treating it as "very small" would give an unbounded width.
    #[test]
    fn a_zero_peak_is_treated_as_no_measurement() {
        let s = Shape::size(
            Toolchain::Rust,
            &node_c(),
            &Observed {
                peak_job_bytes: Some(0),
            }, false,
        );
        assert_eq!(s.bounded_by, Bound::Unmeasured);
    }

    /// The sentence is for a person. A width with no arithmetic behind it
    /// sends somebody to guess at why their build got narrower.
    #[test]
    fn every_shape_explains_itself() {
        for observed in [
            Observed::default(),
            Observed {
                peak_job_bytes: Some(4 * GB),
            },
            Observed {
                peak_job_bytes: Some(256 * 1024 * 1024),
            },
        ] {
            let s = Shape::size(Toolchain::Rust, &node_c(), &observed, false);
            assert!(s.because.len() > 40, "too terse: {}", s.because);
            assert!(
                s.because.starts_with(&s.jobs.to_string()),
                "the sentence should lead with the number: {}",
                s.because
            );
        }
    }
}
