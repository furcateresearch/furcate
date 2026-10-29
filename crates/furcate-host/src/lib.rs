//! The host itself, as distinct from what runs on it.
//!
//! Workloads, pressure, power and network were already covered. What was left
//! is the boring layer underneath — the disks, the clock, and whether the
//! machine is waiting for a restart — which is where most real outages come
//! from and which nothing here was watching.
//!
//! Two of the three are more consequential for this system than they would be
//! for most. A filesystem that fills stops writes, and a validator that cannot
//! write is a validator that is down. A clock that drifts makes four separate
//! parts of this codebase confidently wrong at once — tariff windows, sun
//! position, attestation freshness and chain ordering — and none of them
//! announce it.
//!
//! ## Single-board computers
//!
//! Raspberry Pi and Jetson boards have no SMBIOS, no RAPL and, on Orin, no
//! NVML for their GPU. [`board`] recognises them from the device tree and
//! reports secure boot and measured boot as two separate facts; [`inventory`]
//! finds the Jetson GPU, Hailo parts and `accel` NPUs and refuses to call any
//! of them schedulable without its runtime. Every value they report is a
//! [`reading::Reading`]: measured, with the interface it came from, or not
//! measured. Never a zero standing in for an absent source.

pub mod accelerator;
pub mod acoustics;
pub mod board;
pub mod cooling;
pub mod custody;
pub mod filesystem;
pub mod firmware;
pub mod hardware;
pub mod image;
pub mod inventory;
pub mod journal;
pub mod mig;
pub mod platform;
pub mod reading;
pub mod redfish;
pub mod storage;
pub mod tegra_fuse;
pub mod thermal;
pub mod wall;
pub mod xid;

pub use cooling::{parse_sdr, Cooling, Fan, Fault, Limits, Temperature};
pub use custody::{drift, judge, Backup, Certificate, Drift, Expectation, Verdict, Watched};
pub use filesystem::{assess, Concern, Mount, Trend};
pub use journal::{classify, Event, JournalSize};
pub use platform::{Build, Clock, Reboot, TimeSource};
pub use reading::{Reading, Source};
