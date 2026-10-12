//! Machine-class guests and the boot-cycle proving ground.
//!
//! Every claim elsewhere in Furcate rests on measured boot, and measured boot
//! is the one thing you cannot test by running it once. You need to boot a
//! machine hundreds of times, break it deliberately, and watch the verifier
//! catch it — impossible on production servers, trivial on a hypervisor.
//!
//! The subsystem earns its place twice: as a proving ground for the lifecycle,
//! and as a runtime substrate where each guest is a sub-attester underneath
//! its host rather than a process the host merely promises to have started.

pub mod guest;
pub mod proving;
pub mod reference;
pub mod vtpm;

pub use guest::{Guest, GuestError, GuestState, Vmm};
pub use proving::{boot, qemu_args, BootRequest, Firmware, Sandbox, Swtpm};
pub use reference::{UkiSections, expected_pcr11};
pub use vtpm::{VtpmCustody, VtpmError};
