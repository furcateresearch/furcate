//! `furcate-leaf` — host-side simulator for the leaf firmware.
//!
//! The firmware core is `no_std` and cannot be exercised on a workstation, so
//! this binary drives the same logic against a real parent port. It is how the
//! attachment and replay rules are checked without flashing a device.

use anyhow::Result;
use furcate_identity::{AssuranceClass, LeafKeyCustody, Lockdown};
use furcate_leaf_core::{Batch, LeafState, Sample};
use furcate_sense::leaf::ParentPort;
use furcate_sense::Leaf;

fn main() -> Result<()> {
    let device_id = b"esp32-01";
    let mut state = LeafState::default();
    let mut batch = Batch::new();
    let mut leaf = Leaf::new("esp32-01", [5u8; 32]);

    // A key in a read-protected eFuse block: the class the parent derives
    // from that is `device`. The leaf only describes its key.
    let custody = LeafKeyCustody::FuseKey { lockdown: Lockdown::default() };
    let attachment = leaf.attach("node-a", Some(custody), 0);
    println!("attached esp32-01 to node-a as `{}`: {}", attachment.assurance(), attachment.assurance_reason());
    let mut parent = ParentPort::new();
    parent.accept(attachment);

    for i in 0..10u32 {
        let Some(seq) = state.next_seq() else {
            eprintln!("sequence exhausted; re-attachment required");
            break;
        };
        let sample = Sample { sensor: 0, value: 20.0 + i as f32 * 0.5, seq };
        if let Some(dropped) = batch.push(sample) {
            println!("  batch full, dropped oldest sample seq={}", dropped.seq);
        }
        let payload = state.payload(device_id, &sample);
        let reading = leaf.publish("rack-temp", sample.value as f64, 100 + i as u64);
        match parent.verify(&reading, AssuranceClass::Device) {
            Ok(()) => println!(
                "  seq={seq} value={:.1} payload={} accepted",
                sample.value,
                &hex::encode(payload)[..12]
            ),
            Err(e) => println!("  seq={seq} REJECTED: {e}"),
        }
    }

    // Demonstrate the replay rule the parent enforces.
    let replay = leaf.publish("rack-temp", 21.0, 200);
    parent.verify(&replay, AssuranceClass::Device).ok();
    match parent.verify(&replay, AssuranceClass::Device) {
        Err(e) => println!("replay correctly refused: {e}"),
        Ok(()) => println!("replay ACCEPTED — this is a bug"),
    }

    println!("batched {} samples, generation {}", batch.len(), state.generation());
    Ok(())
}
