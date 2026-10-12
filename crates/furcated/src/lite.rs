//! `furcated-lite` — the node agent for constrained hardware.
//!
//! A Pi, a Jetson or a NAS is a worker: it attests, reports capability,
//! carries sensors and takes work. It never hosts the site controller and it
//! does not run the proving ground.
//!
//! It is the same agent rather than a reimplementation, so identity, the
//! operation chain and the power ladder behave identically. What differs is
//! what is compiled in.

fn main() -> anyhow::Result<()> {
    eprintln!(
        "furcated-lite: worker profile — attestation, capability, sensors and power.\n\
         No site controller, no proving ground. Use `furcated` on a machine that \
         should be eligible to run the controller."
    );
    // Deferring to the full agent keeps one code path. The lite profile is a
    // deployment decision, not a second implementation to keep in sync.
    furcated::run()
}
