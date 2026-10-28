//! `furcate-small` -- the small processing node of the sensing cascade.
//!
//! ```text
//! furcate-small serve  --directory FILE --state-dir DIR
//!                      [--backend NAME] [--config-dir DIR]
//!                      [--listen stdin|unix:PATH] [--forward -|FILE|unix:PATH]
//!                      [--model FILE] [--margin F] [--audit-every N]
//!                      [--min-level CLASS] [--max-delay-ms N] [--forward-readings]
//! furcate-small replay CAPTURE [USB-SERIAL] [--accel-g N] [--gyro-dps N]
//! furcate-small identity [--backend NAME] [--config-dir DIR]
//! ```
//!
//! `serve` reads one JSON frame per line from a micro processing node's link,
//! verifies it, journals what it did under the state directory, and forwards
//! what its policy escalates. It signs with the hardware root of trust of the
//! machine it runs on and refuses to start without one; there is no fallback
//! signer and no key file. `replay` runs a recorded capture through the whole
//! path in memory with simulated keys, to check an installation or a build
//! without a board. `identity` opens the root of trust and prints who this node
//! is; it signs nothing.

use anyhow::{bail, Context, Result};
use furcate_identity::backends::select::{open_backend, select, Policy, Selection};
use furcate_identity::{AssuranceClass, RootOfTrustSigner};
use furcate_sense::cascade::directory::Directory;
use furcate_sense::cascade::escalate::MarginPolicy;
use furcate_sense::cascade::binding::BindingRegistry;
use furcate_sense::cascade::coherence::{CoherenceConfig, CoherenceMonitor};
use furcate_sense::cascade::ingest::{Frame, Ingest, IngestPolicy, Refusal, RefusalSink};
use furcate_sense::cascade::micro::{window_features, MicroSim};
use furcate_sense::cascade::model::{CentroidFile, NearestCentroid, WindowModel};
use furcate_sense::cascade::signer::{CascadeSigner, HardwareSigner};
use furcate_sense::cascade::small::{
    verify_forwarded, Forwarded, Forwarder, JsonLinesForwarder, MemoryForwarder, Outcome, SmallNode,
};
use furcate_sense::cascade::witness::LogEntry;
use furcate_sense::nicla::{NodeRole, Sample};
use furcate_sense::text::{LineSplitter, TextSession};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn level(s: &str) -> Result<AssuranceClass> {
    Ok(match s {
        "soft" => AssuranceClass::Soft,
        "device" => AssuranceClass::Device,
        "secure-element" | "secureelement" => AssuranceClass::SecureElement,
        "tee" => AssuranceClass::Tee,
        "dice" => AssuranceClass::Dice,
        "tpm" => AssuranceClass::Tpm,
        other => bail!("unknown class `{other}`"),
    })
}

struct Args(Vec<String>);

impl Args {
    fn value(&self, flag: &str) -> Option<&str> {
        self.0.iter().position(|a| a == flag).and_then(|i| self.0.get(i + 1)).map(String::as_str)
    }

    fn has(&self, flag: &str) -> bool {
        self.0.iter().any(|a| a == flag)
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

fn identity(args: &Args) -> Result<()> {
    let sel = open_root(args)?;
    println!("backend   {}", sel.backend);
    println!("class     {}", sel.class);
    println!("node id   {}", sel.rot.node_id()?.as_str());
    println!("reason    {}", sel.reason);
    Ok(())
}

/// Appends refusals to a journal as they happen.
struct JournalSink(std::fs::File);

impl RefusalSink for JournalSink {
    fn record(&mut self, r: &Refusal) {
        if let Ok(mut line) = serde_json::to_vec(r) {
            line.push(b'\n');
            // A journal that cannot be written is reported where an operator
            // looks; it does not change what was refused.
            if let Err(e) = self.0.write_all(&line) {
                eprintln!("furcate-small: refusal journal: {e}");
            }
        }
    }
}

fn append(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new().create(true).append(true).open(path).with_context(|| format!("open {}", path.display()))
}

/// Forwards over a unix socket, reconnecting when the peer goes away.
struct UnixForwarder {
    path: PathBuf,
    stream: Option<std::os::unix::net::UnixStream>,
}

impl Forwarder for UnixForwarder {
    fn forward(&mut self, f: &Forwarded) -> Result<(), String> {
        if self.stream.is_none() {
            self.stream = Some(std::os::unix::net::UnixStream::connect(&self.path).map_err(|e| e.to_string())?);
        }
        let mut line = serde_json::to_vec(f).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let r = self.stream.as_mut().map(|s| s.write_all(&line).and_then(|_| s.flush()));
        match r {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => {
                self.stream = None;
                Err(e.to_string())
            }
            None => Err("no connection".into()),
        }
    }
}

fn forwarder(spec: &str) -> Result<Box<dyn Forwarder>> {
    Ok(match spec {
        "-" => Box::new(JsonLinesForwarder(std::io::stdout())),
        s if s.starts_with("unix:") => Box::new(UnixForwarder { path: PathBuf::from(&s[5..]), stream: None }),
        file => Box::new(JsonLinesForwarder(append(Path::new(file))?)),
    })
}

struct App {
    node: SmallNode,
    witness_journal: std::fs::File,
    results: std::fs::File,
}

impl App {
    fn frame(&mut self, line: &str) {
        let frame: Frame = match serde_json::from_str(line) {
            Ok(f) => f,
            Err(e) => {
                // A line that is not a frame is not silently skipped either.
                eprintln!("furcate-small: malformed frame: {e}");
                let _ = writeln!(self.results, "{}", serde_json::json!({"at_ms": now_ms(), "outcome": "malformed", "detail": e.to_string()}));
                return;
            }
        };
        let (leaf, entry) = match &frame {
            Frame::Reading { item, entry } => (Some(item.reading.leaf_id.clone()), Some(entry.clone())),
            Frame::Embedding { item, entry } => (Some(item.window.leaf_id.clone()), Some(entry.clone())),
            Frame::Checkpoint { .. } => (None, None),
        };
        let size = |app: &App, l: &Option<String>| l.as_ref().and_then(|l| app.node.ingest().witness().state(l)).map_or(0, |s| s.0);
        let before = size(self, &leaf);
        let at = now_ms();
        let outcome = self.node.handle(&frame, at);
        // The entry joins the journal exactly when the witness took it.
        if let (Some(l), Some(e)) = (&leaf, &entry) {
            if size(self, &leaf) > before {
                let _ = writeln!(self.witness_journal, "{}", serde_json::json!({"leaf": l, "entry": e}));
            }
        }
        let record = match &outcome {
            Outcome::Refused(r) => {
                eprintln!("furcate-small: refused {} {}: {}", r.source, r.item, r.detail);
                serde_json::json!({"at_ms": at, "outcome": "refused", "code": r.code, "item": r.item})
            }
            Outcome::Kept { inference } => serde_json::json!({"at_ms": at, "outcome": "kept", "inference": inference}),
            Outcome::Escalated { reason, inference } => {
                serde_json::json!({"at_ms": at, "outcome": "escalated", "reason": reason, "inference": inference})
            }
            Outcome::ForwardFailed { reason, error } => {
                eprintln!("furcate-small: forward failed: {error}");
                serde_json::json!({"at_ms": at, "outcome": "forward_failed", "reason": reason, "error": error})
            }
            Outcome::Cosigned(c) => serde_json::json!({"at_ms": at, "outcome": "cosigned", "cosigned": c}),
            Outcome::Stored => serde_json::json!({"at_ms": at, "outcome": "stored"}),
        };
        let _ = writeln!(self.results, "{record}");
    }
}

fn serve(args: &Args) -> Result<()> {
    let directory = args.value("--directory").context("--directory FILE is required")?;
    let state = PathBuf::from(args.value("--state-dir").context("--state-dir DIR is required")?);
    std::fs::create_dir_all(&state)?;

    let dir = Directory::from_json(&serde_json::from_slice(&std::fs::read(directory).with_context(|| directory.to_string())?)?)?;
    let sel = open_root(args)?;
    let id = sel.rot.node_id()?.as_str().to_string();
    let hw = RootOfTrustSigner::of(sel.rot.clone()).context("this root of trust does not sign messages")?;
    let signer: Arc<dyn CascadeSigner> = Arc::new(HardwareSigner::new(id.clone(), Arc::new(hw)).map_err(anyhow::Error::msg)?);
    eprintln!("furcate-small: {id} ({} class, {})", sel.class, sel.backend);

    let policy = IngestPolicy {
        min_effective: level(args.value("--min-level").unwrap_or("soft"))?,
        max_delay_ms: args.num("--max-delay-ms", 5_000)?,
        bindings: match args.value("--bindings") {
            Some(p) => {
                let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).with_context(|| p.to_string())?)?;
                Some(BindingRegistry::from_json(&v).map_err(|e| anyhow::anyhow!("{p}: {e}"))?)
            }
            None => {
                eprintln!("furcate-small: no --bindings: the model, epoch and calibration items state are not checked");
                None
            }
        },
        ..IngestPolicy::default()
    };
    let mut ingest = Ingest::new(dir, signer.clone(), policy).with_sink(Box::new(JournalSink(append(&state.join("refusals.jsonl"))?)));

    // Rebuild the witnessed logs. A journal that does not chain is a stop, not a reset.
    let wj = state.join("witness.jsonl");
    if wj.exists() {
        for (n, line) in BufReader::new(std::fs::File::open(&wj)?).lines().enumerate() {
            let v: serde_json::Value = serde_json::from_str(&line?)?;
            let entry: LogEntry = serde_json::from_value(v["entry"].clone())?;
            let leaf = v["leaf"].as_str().context("journal line without a leaf")?;
            ingest.restore_entry(leaf, &entry).map_err(|e| anyhow::anyhow!("{}: line {}: {e}", wj.display(), n + 1))?;
        }
    }

    let model: Option<Box<dyn WindowModel>> = match args.value("--model") {
        Some(p) => {
            let f: CentroidFile = serde_json::from_slice(&std::fs::read(p).with_context(|| p.to_string())?)?;
            Some(Box::new(NearestCentroid::from_file(f).map_err(|e| anyhow::anyhow!("{e}"))?))
        }
        None => {
            eprintln!("furcate-small: no --model: every embedding is escalated with no answer");
            None
        }
    };
    let fwd = forwarder(args.value("--forward").unwrap_or("-"))?;
    let margin = MarginPolicy::new(args.num("--margin", 0.2)?, args.num("--audit-every", 50)?);
    let node = SmallNode::new(ingest, signer, sel.class, model, Box::new(margin), fwd).forward_readings(args.has("--forward-readings"));
    let app = Arc::new(Mutex::new(App {
        node,
        witness_journal: append(&wj)?,
        results: append(&state.join("results.jsonl"))?,
    }));

    match args.value("--listen").unwrap_or("stdin") {
        "stdin" => {
            for line in std::io::stdin().lock().lines() {
                app.lock().unwrap().frame(&line?);
            }
        }
        s if s.starts_with("unix:") => {
            let path = PathBuf::from(&s[5..]);
            let _ = std::fs::remove_file(&path);
            let listener = std::os::unix::net::UnixListener::bind(&path).with_context(|| path.display().to_string())?;
            eprintln!("furcate-small: listening on {}", path.display());
            for conn in listener.incoming() {
                let conn = conn?;
                let app = app.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(conn).lines().map_while(Result::ok) {
                        app.lock().unwrap().frame(&line);
                    }
                });
            }
        }
        other => bail!("--listen takes `stdin` or `unix:PATH`, not `{other}`"),
    }
    let s = app.lock().unwrap().node.stats();
    eprintln!("furcate-small: {}", serde_json::to_string(&s)?);
    Ok(())
}

/// A recorded capture through every rung, in memory, with simulated keys.
fn replay(capture: &str, serial: &str, accel_g: Option<f64>, gyro_dps: Option<f64>) -> Result<()> {
    use furcate_identity::{LeafKeyCustody, Lockdown};
    let text = std::fs::read(capture).with_context(|| capture.to_string())?;
    let mut session = TextSession::with_configured(accel_g, gyro_dps)?;
    let samples: Vec<Sample> =
        LineSplitter::new().push(&text).into_iter().filter_map(|l| session.feed_line(&l).ok().flatten()).collect();
    println!("{}", session.summary());
    if !session.skipped_classes().is_empty() {
        bail!(
            "no readings from the {}: no range was configured and the capture printed none; pass --accel-g and --gyro-dps",
            session.skipped_classes().join(" and ")
        );
    }
    if samples.is_empty() {
        bail!("no samples in {capture}");
    }
    println!("simulated keys: this checks the path, it does not attest anything");

    // The capture has no timestamps, so samples are placed 100 ms apart.
    let mut monitor = CoherenceMonitor::new(CoherenceConfig::default());
    let mut flagged = 0;
    for (i, s) in samples.iter().enumerate() {
        for f in monitor.observe(s, i as f64 * 0.1) {
            println!("  coherence: {f}");
            flagged += 1;
        }
    }
    println!("coherence: {flagged} flag(s); a flag is a hint to look at the sensing node, not a refusal");

    let fused = Some(LeafKeyCustody::FuseKey { lockdown: Lockdown { secure_boot: true, flash_encryption: true, download_disabled: true, jtag_disabled: true } });
    let mut micro = MicroSim::new(serial, [9u8; 32], "furcate:node:micro-sim");
    let small = furcate_sense::Leaf::new("furcate:node:small-sim", [3u8; 32]);
    let mut dir = Directory::new();
    dir.add_node(&micro.gateway_attachment(fused), NodeRole::MicroProcessing)?;
    dir.bind_sensing(micro.sensing_id(), "furcate:node:micro-sim")?;
    let mut next = dir.clone();
    next.add_node(&small.attach("next", fused, 0), NodeRole::SmallProcessing)?;

    let near = window_features(&samples);
    let far: Vec<i8> = near.iter().map(|v| v.wrapping_neg().clamp(-100, 100)).collect();
    let model = NearestCentroid::fit("replay-centroid", &[("capture".into(), near.clone()), ("elsewhere".into(), far)])
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let signer: Arc<dyn CascadeSigner> = Arc::new(furcate_sense::Leaf::new("furcate:node:small-sim", [3u8; 32]));
    let sent = Arc::new(Mutex::new(MemoryForwarder::default()));
    struct Tee(Arc<Mutex<MemoryForwarder>>);
    impl Forwarder for Tee {
        fn forward(&mut self, f: &Forwarded) -> Result<(), String> {
            self.0.lock().unwrap().forward(f)
        }
    }
    let ingest = Ingest::new(dir, signer.clone(), IngestPolicy::default());
    let mut node = SmallNode::new(ingest, signer, AssuranceClass::Device, Some(Box::new(model)), Box::new(MarginPolicy::new(0.2, 2)), Box::new(Tee(sent.clone())));

    let mut t = 1_000u64;
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut run = |node: &mut SmallNode, f: &Frame, t: u64| {
        let k = match node.handle(f, t + 5) {
            Outcome::Refused(r) => {
                println!("  refused: {}", r.detail);
                "refused"
            }
            Outcome::Kept { .. } => "kept",
            Outcome::Escalated { .. } => "escalated",
            Outcome::ForwardFailed { .. } => "forward failed",
            Outcome::Cosigned(_) => "checkpoints cosigned",
            Outcome::Stored => "readings verified",
        };
        *counts.entry(k).or_default() += 1;
    };
    for s in &samples {
        for f in micro.reading_frames(s, t)? {
            run(&mut node, &f, t);
            t += 10;
        }
    }
    for v in [near.clone(), near.clone(), vec![0; near.len()]] {
        let f = micro.embedding_frame(&v, t);
        run(&mut node, &f, t);
        t += 100;
    }
    run(&mut node, &micro.checkpoint_frame(t), t);
    println!("a tampered embedding:");
    let mut bad = micro.embedding_frame(&near, t + 10);
    if let Frame::Embedding { item, .. } = &mut bad {
        item.window.values[0] = item.window.values[0].wrapping_add(1);
    }
    run(&mut node, &bad, t + 10);

    for (k, n) in &counts {
        println!("{n:>4} {k}");
    }
    let sent = sent.lock().unwrap();
    for f in &sent.0 {
        let r = verify_forwarded(f, &next, AssuranceClass::Soft).map_err(|e| anyhow::anyhow!("next rung refused: {e}"))?;
        println!(
            "next rung accepts an escalated item: {} rungs, treated as `{}` (limited by {})",
            r.hops.len(),
            r.effective,
            r.limiting
        );
    }
    if counts.get("refused") != Some(&1) || sent.0.len() != 2 {
        bail!("replay did not behave as expected");
    }
    Ok(())
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = Args(argv.iter().skip(1).cloned().collect());
    match argv.first().map(String::as_str) {
        Some("serve") => serve(&args),
        Some("replay") => {
            const USAGE: &str = "usage: furcate-small replay CAPTURE [USB-SERIAL] [--accel-g N] [--gyro-dps N]";
            let Some(capture) = argv.get(1) else { bail!(USAGE) };
            let mut rest: Vec<&String> = argv.iter().skip(2).collect();
            let serial = if rest.first().is_some_and(|a| !a.starts_with("--")) { rest.remove(0).as_str() } else { "SYNTH-0001" };
            let (mut accel, mut gyro) = (None, None);
            let mut it = rest.into_iter();
            while let Some(flag) = it.next() {
                let val = it.next().and_then(|v| v.parse::<f64>().ok());
                match (flag.as_str(), val) {
                    ("--accel-g", Some(v)) => accel = Some(v),
                    ("--gyro-dps", Some(v)) => gyro = Some(v),
                    _ => bail!(USAGE),
                }
            }
            replay(capture, serial, accel, gyro)
        }
        Some("identity") => identity(&args),
        _ => bail!("usage: furcate-small serve|replay|identity (see the header of this file)"),
    }
}
