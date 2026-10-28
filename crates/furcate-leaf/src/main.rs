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

/// `furcate-leaf nicla <capture-or-tty> <usb-serial>`: attach a sensing node
/// behind this simulated processing node and verify what it publishes.
///
/// The path is a recorded capture or a serial device carrying the text lines
/// of the stock example; it is opened read-only and nothing is written to it.
/// The signing key is the simulator's fixed one, as in the run below; a real
/// processing node derives it from its own identity.
fn nicla(path: &str, usb_serial: &str, accel_g: Option<f64>, gyro_dps: Option<f64>) -> Result<()> {
    use furcate_sense::identity::{enrol, fingerprint_of};
    use furcate_sense::nicla::{verify_bridged, NiclaAdapter, NodeRole, Transport};
    use furcate_sense::text::{LineSplitter, TextSession};
    use furcate_sense::SensorRegistry;
    use std::io::Read;

    let identity = enrol(fingerprint_of(usb_serial, None)?, usb_serial, b"furcate-leaf-sim")?;
    let mut adapter = NiclaAdapter::new(
        Leaf::new(identity.node_id.as_str(), [5u8; 32]),
        &identity,
        "esp32-01",
        NodeRole::MicroProcessing,
        AssuranceClass::Device,
        Transport::UsbText,
        1,
    )?;
    let mut parent = ParentPort::new();
    let attached = adapter.attach(0);
    parent.accept(attached.attachment.clone());
    let mut registry = SensorRegistry::new();
    adapter.register_sensors(&mut registry);
    println!("sensing node {}", identity.node_id.as_str());
    println!("assurance    {}", attached.attachment.assurance());
    println!("statement    {}", attached.attestation.statement);

    let mut file = furcate_sense::serial::open_line_source(std::path::Path::new(path))?;
    let (mut lines, mut session) = (LineSplitter::new(), TextSession::with_configured(accel_g, gyro_dps)?);
    let (mut accepted, mut refused, mut buf) = (0u64, 0u64, [0u8; 512]);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for line in lines.push(&buf[..n]) {
            // Every refusal is tallied by the session and reported below.
            let Ok(Some(sample)) = session.feed_line(&line) else { continue };
            for b in adapter.ingest(&sample, accepted)? {
                match verify_bridged(&mut parent, &b, AssuranceClass::Soft) {
                    Ok(()) => accepted += 1,
                    Err(e) => {
                        refused += 1;
                        eprintln!("refused {}: {e}", b.reading.sensor_id);
                    }
                }
            }
        }
    }
    println!(
        "{accepted} readings verified, {refused} refused, {} lines rejected, {} sensors in the catalogue",
        session.rejected,
        registry.len()
    );
    println!("{}", session.summary());
    let floor = parent.verify(&adapter.ingest(&furcate_sense::nicla::Sample::Temperature(0.0), 0)?[0].reading, AssuranceClass::Device);
    println!("a parent requiring `device` would answer: {}", floor.err().map(|e| e.to_string()).unwrap_or_default());
    let skipped = session.skipped_classes();
    if !skipped.is_empty() {
        eprintln!("WARNING: no readings from the {}: no range was configured and the stream printed none", skipped.join(" and "));
        anyhow::bail!("sensor classes skipped; pass --accel-g and --gyro-dps");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("nicla") {
        const USAGE: &str = "usage: furcate-leaf nicla <capture-or-tty> <usb-serial> [--accel-g N] [--gyro-dps N]";
        let (Some(path), Some(serial)) = (args.get(2), args.get(3)) else {
            anyhow::bail!(USAGE);
        };
        let (mut accel, mut gyro) = (None, None);
        let mut rest = args[4..].iter();
        while let Some(flag) = rest.next() {
            let val = rest.next().and_then(|v| v.parse::<f64>().ok());
            match (flag.as_str(), val) {
                ("--accel-g", Some(v)) => accel = Some(v),
                ("--gyro-dps", Some(v)) => gyro = Some(v),
                _ => anyhow::bail!(USAGE),
            }
        }
        return nicla(path, serial, accel, gyro);
    }
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
