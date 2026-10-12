//! `furcate-prove` — run the machine-class boot cycle.
//!
//! Boots a guest with a virtual TPM and reports whether the chip was actually
//! exercised. This is the harness the attestation work is developed against,
//! because a production server cannot be rebooted three hundred times.

use anyhow::Result;
use furcate_machine::proving::{state_written, Firmware};
use furcate_machine::{boot, qemu_args, BootRequest, Sandbox};

fn main() -> Result<()> {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/furcate-proving".to_string());
    let sandbox = Sandbox::new(&root)?;

    let firmware = Firmware::discover()?;
    println!("firmware    {}", firmware.code.display());
    println!("sandbox     {root}");

    sandbox.reset()?;
    println!("state       cleared");

    let request = BootRequest::default();
    let args = qemu_args(
        &firmware,
        &sandbox.root.join("OVMF_VARS.fd"),
        &sandbox.socket(),
        &request,
    );
    println!("qemu args   {} tokens, tpm-crb attached", args.len());

    println!("booting     (timeout {}s)", request.timeout_s);
    boot(&sandbox, &request)?;

    if state_written(&sandbox) {
        println!("result      vTPM state written — the firmware measured into the chip");
        Ok(())
    } else {
        anyhow::bail!("vTPM state was not written: the guest did not reach the chip")
    }
}
