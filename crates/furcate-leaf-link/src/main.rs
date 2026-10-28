//! `furcate-leaf-link` -- the host end of a micro processing node's link.
//!
//! ```text
//! furcate-leaf-link serve     --config FILE --grant FILE --link LINK
//!                             [--backend NAME] [--config-dir DIR]
//!                             [--out -|FILE|unix:PATH] [--poll-ms N]
//! furcate-leaf-link enrol     --link LINK [--wait-s N]
//! furcate-leaf-link directory --config FILE [--backend NAME] [--config-dir DIR]
//! furcate-leaf-link unit-fingerprint --i2c-addr 0x55 --serial S --device-id HEX16 --device-addr HEX12
//! ```
//!
//! LINK is a serial device, `listen://HOST:PORT` (the leaf dials this
//! address) or `tcp://HOST:PORT` (a byte relay).
//!
//! `serve` keeps the session with each enrolled leaf, checks what it signs, and
//! writes one JSON frame per line for `furcate-small serve --listen`. It
//! signs with the hardware root of trust of the machine it runs on and has no
//! fallback and no key file.
//!
//! `enrol` only listens: it waits for one HELLO and prints the entry the
//! operator would review and add to the config file. It sends nothing to the
//! leaf, and a leaf is never enrolled by appearing.
//!
//! `unit-fingerprint` prints the fingerprint a leaf gives a sensing module on
//! its I2C bus from the identifiers configured on the leaf: the value to write
//! as `unit_fingerprint` in the config file.
//!
//! `directory` prints the part of the small processing node's directory file
//! that names this bridge as the processing node of record.

use anyhow::{bail, Context, Result};
use furcate_identity::backends::select::{open_backend, select, Policy, Selection};
use furcate_identity::RootOfTrustSigner;
use furcate_leaf_link::bridge::{Bridge, BridgeConfig};
use furcate_leaf_link::config::{self, Loaded};
use furcate_leaf_link::serve::{open_link, run};
use furcate_leaf_link::session::{Hello, HardwareNodeSigner, NodeGrant};
use furcate_leaf_link::wire::{Line, LineDecoder};
use furcate_sense::cascade::ingest::Frame;
use furcate_sense::relay::Relay;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

struct Args(Vec<String>);

impl Args {
    fn value(&self, flag: &str) -> Option<&str> {
        self.0.iter().position(|a| a == flag).and_then(|i| self.0.get(i + 1)).map(String::as_str)
    }

    fn need(&self, flag: &str) -> Result<&str> {
        self.value(flag).with_context(|| format!("{flag} is required"))
    }

    fn num<T: std::str::FromStr>(&self, flag: &str, default: T) -> Result<T> {
        match self.value(flag) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| anyhow::anyhow!("{flag} takes a number, not `{v}`")),
        }
    }
}

fn open_root(args: &Args) -> Result<Selection> {
    let dir = PathBuf::from(args.value("--config-dir").unwrap_or("/etc/furcate"));
    let policy = Policy::in_config_dir(&dir);
    match args.value("--backend") {
        Some(name) => open_backend(&policy, name).map_err(|e| anyhow::anyhow!("{e}")),
        None => Ok(select(&policy)?),
    }
}

fn read_json(path: &str) -> Result<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(path).with_context(|| format!("read {path}"))?).with_context(|| format!("{path} is not JSON"))
}

fn load(args: &Args) -> Result<Loaded> {
    config::load(&read_json(args.need("--config")?)?).map_err(anyhow::Error::msg)
}

/// Where frames go.
enum Out {
    Stdout,
    File(std::fs::File),
    Unix { path: PathBuf, stream: Option<std::os::unix::net::UnixStream> },
}

impl Out {
    fn open(spec: &str) -> Result<Self> {
        Ok(match spec {
            "-" => Out::Stdout,
            s if s.starts_with("unix:") => Out::Unix { path: PathBuf::from(&s[5..]), stream: None },
            s => Out::File(std::fs::OpenOptions::new().create(true).append(true).open(s).with_context(|| format!("open {s}"))?),
        })
    }

    fn put(&mut self, f: &Frame) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(f).map_err(std::io::Error::other)?;
        line.push(b'\n');
        match self {
            Out::Stdout => {
                let mut o = std::io::stdout().lock();
                o.write_all(&line)?;
                o.flush()
            }
            Out::File(f) => f.write_all(&line),
            Out::Unix { path, stream } => {
                // Reconnect when the small node restarts; a frame that finds no
                // listener is reported, not dropped quietly.
                if stream.is_none() {
                    *stream = Some(std::os::unix::net::UnixStream::connect(&*path)?);
                }
                let r = stream.as_mut().map(|s| s.write_all(&line).and_then(|_| s.flush()));
                match r {
                    Some(Ok(())) => Ok(()),
                    Some(Err(e)) => {
                        *stream = None;
                        Err(e)
                    }
                    None => Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
                }
            }
        }
    }
}

fn serve(args: &Args) -> Result<()> {
    let cfg = load(args)?;
    let sel = open_root(args)?;
    let hw = Arc::new(RootOfTrustSigner::of(sel.rot.clone()).context("this root of trust does not sign messages")?);
    let node = Arc::new(HardwareNodeSigner::new(hw.clone()).map_err(anyhow::Error::msg)?);
    let relay = Relay::new(cfg.bridge_id.clone(), hw).map_err(anyhow::Error::msg)?;
    let grant = NodeGrant::from_json(&read_json(args.need("--grant")?)?).map_err(anyhow::Error::msg)?;
    eprintln!("furcate-leaf-link: {} ({}), bridge {} key {}", sel.backend, sel.class, cfg.bridge_id, relay.public_key());
    let mut out = Out::open(args.value("--out").unwrap_or("-"))?;
    let mut bridge = Bridge::new(BridgeConfig {
        signer: node,
        grant,
        roster: cfg.roster,
        sources: cfg.sources,
        relay,
        ceiling: cfg.ceiling,
        poll_ms: args.num("--poll-ms", 5_000)?,
        auth_wait_ms: 20_000,
        reply_wait_ms: 30_000,
    });
    let mut link = open_link(args.need("--link")?).context("open the link")?;
    let tally = run(
        &mut bridge,
        &mut *link,
        &mut |f| out.put(f),
        &mut |l| eprintln!("furcate-leaf-link: {l}"),
        &mut |_| false,
    )?;
    eprintln!("furcate-leaf-link: stopped after {} frames", tally.frames);
    Ok(())
}

fn enrol(args: &Args) -> Result<()> {
    let wait: u64 = args.num("--wait-s", 60)?;
    let mut link = open_link(args.need("--link")?).context("open the link")?;
    let (mut dec, mut buf) = (LineDecoder::new(), [0u8; 2048]);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(wait);
    while std::time::Instant::now() < end {
        let n = link.read(&mut buf)?;
        for l in dec.push(&buf[..n]) {
            let Line::Frame(m) = l else { continue };
            let Ok(h) = Hello::parse(&m) else { continue };
            let ev = |t: u8| h.evidence.get(t).map(hex::encode).unwrap_or_default();
            let label = h.evidence.get(4).map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": "REVIEW-AND-NAME-ME",
                    "key": h.key(),
                    "custody": {"kind": "readable-identifiers"},
                    "mac": ev(1), "otp": ev(20), "revision": ev(2),
                    "channels": {"0": "tmp"},
                    "note": format!("the leaf's own label is `{label}`; set `custody` from what the operator knows of how its key is held, not from this label")
                }))?
            );
            return Ok(());
        }
    }
    bail!("no HELLO within {wait} seconds")
}

fn directory(args: &Args) -> Result<()> {
    let cfg = load(args)?;
    let sel = open_root(args)?;
    let hw = Arc::new(RootOfTrustSigner::of(sel.rot.clone()).context("this root of trust does not sign messages")?);
    let relay = Relay::new(cfg.bridge_id.clone(), hw).map_err(anyhow::Error::msg)?;
    let sensing: Vec<_> = cfg
        .sources
        .iter()
        .flat_map(|s| std::iter::once(&s.chip).chain(s.module.iter().map(|m| &m.source)))
        .map(|r| serde_json::json!({"sensing_node": r.identity.node_id.as_str(), "gateway": relay.node_id()}))
        .collect();
    let custody = cfg.bridge_custody.map(|c| serde_json::to_value(c)).transpose()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "nodes": [{"role": "micro_processing", "attachment": {
                "leaf_id": relay.node_id(), "parent": "small", "public_key": relay.public_key(),
                "attached_at": 0, "key_custody": custody }}],
            "sensing": sensing
        }))?
    );
    Ok(())
}

fn unit_fingerprint(args: &Args) -> Result<()> {
    let addr = args.need("--i2c-addr")?;
    let addr = u8::from_str_radix(addr.trim_start_matches("0x"), 16).context("--i2c-addr is a hex byte such as 0x55")?;
    let id: [u8; 8] = hex::decode(args.need("--device-id")?)?.try_into().map_err(|_| anyhow::anyhow!("--device-id is 16 hex digits"))?;
    let da: [u8; 6] = hex::decode(args.need("--device-addr")?)?.try_into().map_err(|_| anyhow::anyhow!("--device-addr is 12 hex digits"))?;
    println!("{}", hex::encode(furcate_leaf_link::report::i2c_unit_fingerprint(addr, args.need("--serial")?, &id, &da)));
    Ok(())
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = Args(argv.clone());
    match argv.first().map(String::as_str) {
        Some("serve") => serve(&args),
        Some("enrol") => enrol(&args),
        Some("directory") => directory(&args),
        Some("unit-fingerprint") => unit_fingerprint(&args),
        _ => bail!("usage: furcate-leaf-link serve|enrol|directory|unit-fingerprint ... (see the crate documentation)"),
    }
}
