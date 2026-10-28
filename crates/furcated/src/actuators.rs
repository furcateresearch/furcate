//! The actuators behind passkey orders on this node.
//!
//! The agent runs unprivileged, so it does not stop units, change the packet
//! filter, take an interface down or destroy sealed material itself. It
//! writes an order intent that the privileged actuator
//! (`deploy/furcate-order-actuator.sh`) carries out, and reads back what that
//! reported for the same order hash. The intent and result are their own pair
//! of files, apart from the power loop's, so a lever written every cycle
//! cannot overwrite an order before it is read.
//!
//! No report within the wait is a failure, and is recorded as one with the
//! reason. The intent stays posted, so the actuator may still apply it; the
//! record says that rather than guessing either way.
//!
//! ## Erase is pending until acknowledged
//!
//! `crypto_erase` latches `erase-pending.json` in the state directory before
//! anything is destroyed, so from that moment the node reports an erase it has
//! not yet finished. The privileged half destroys the sealed blobs and TPM
//! keyslots the node declares and arms early boot to complete the erase. Early
//! boot writes `erase-done` (the order hash it completed) when it has. The
//! next start of the agent then quotes over a nonce bound to that order and
//! that record, and the quote is the acknowledgment; only then is the latch
//! cleared.

use furcate_killswitch::actuate::{Actuator, Report};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What the acknowledgment nonce is the hash of, ahead of the order and the
/// completion record.
const ERASE_ACK_DOMAIN: &[u8] = b"furcate-erase-ack/1\n";

/// The actuator that hands orders to the privileged half.
pub struct IntentActuator {
    pub intent: PathBuf,
    pub result: PathBuf,
    pub wait: Duration,
    pub poll: Duration,
    /// The overlay interface `isolate` takes down.
    pub overlay: String,
    /// Written by the privileged half while an isolation is in force.
    pub isolated: PathBuf,
    /// The workloads halts stopped and no resume has yet restarted, one unit
    /// per line, kept by the privileged half.
    pub halted: PathBuf,
    pub erase: EraseLatch,
}

impl IntentActuator {
    pub fn from_env() -> Self {
        let wait = std::env::var("FURCATE_ORDER_WAIT_S")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        Self {
            intent: std::env::var("FURCATE_ORDER_INTENT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| furcate_paths::state("order")),
            result: std::env::var("FURCATE_ORDER_RESULT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/run/furcate/order-result.json")),
            wait: Duration::from_secs(wait),
            poll: Duration::from_millis(250),
            overlay: std::env::var("FURCATE_WG_IFACE").unwrap_or_else(|_| "fur0".into()),
            isolated: furcate_paths::state("isolated"),
            halted: furcate_paths::state("halted"),
            erase: EraseLatch::in_dir(&furcate_paths::state_dir()),
        }
    }

    /// Post one intent and wait for the report that names the same order.
    fn post(&self, body: String, order_hash: &str) -> Report {
        if let Err(e) = write_atomically(&self.intent, body.as_bytes()) {
            return Report::failed(format!(
                "the order intent could not be written to {}: {e}; nothing acted",
                self.intent.display()
            ));
        }
        let deadline = Instant::now() + self.wait;
        loop {
            if let Some(v) = super::actuate::confirm_in(&self.result.to_string_lossy(), order_hash)
            {
                return if v["ok"] == json!(true) {
                    Report::Done { what: v }
                } else {
                    Report::Failed {
                        why: v["why"]
                            .as_str()
                            .unwrap_or("the actuator reported failure without a reason")
                            .to_string(),
                        partial: v,
                    }
                };
            }
            if Instant::now() >= deadline {
                return Report::failed(format!(
                    "the privileged actuator did not report within {} s; the intent is still \
                     posted at {} and may yet be applied",
                    self.wait.as_secs(),
                    self.intent.display()
                ));
            }
            std::thread::sleep(self.poll);
        }
    }

    fn safe_overlay(&self) -> Result<&str, Report> {
        if super::actuate::id_is_safe(&self.overlay) && !self.overlay.contains('/') {
            Ok(&self.overlay)
        } else {
            Err(Report::failed(format!(
                "`{}` is not an interface name this node will pass to the actuator; nothing acted",
                self.overlay
            )))
        }
    }
}

impl Actuator for IntentActuator {
    fn halt(&self, order_hash: &str) -> Report {
        self.post(render("halt", &[], order_hash), order_hash)
    }

    fn resume(&self, order_hash: &str) -> Report {
        self.post(render("resume", &[], order_hash), order_hash)
    }

    fn isolate(&self, order_hash: &str) -> Report {
        match self.safe_overlay() {
            Ok(iface) => self.post(
                render("isolate", &[("iface", iface)], order_hash),
                order_hash,
            ),
            Err(r) => r,
        }
    }

    fn release(&self, order_hash: &str) -> Report {
        match self.safe_overlay() {
            Ok(iface) => self.post(
                render("release", &[("iface", iface)], order_hash),
                order_hash,
            ),
            Err(r) => r,
        }
    }

    fn crypto_erase(&self, order_hash: &str) -> Report {
        // Latched before anything is destroyed: from here on the node says an
        // erase is pending, whatever happens next.
        if let Err(e) = self.erase.latch(order_hash) {
            return Report::failed(format!(
                "the erase could not be latched: {e}; nothing acted"
            ));
        }
        match self.post(render("crypto_erase", &[], order_hash), order_hash) {
            Report::Done { what } => Report::Done {
                what: json!({ "reported": what, "erase_pending": true, "acknowledged": false }),
            },
            Report::Failed { why, partial } => Report::Failed {
                why: format!("{why}; the erase stays latched as pending"),
                partial,
            },
        }
    }

    fn state(&self) -> Value {
        json!({
            "isolated": self.isolated.exists(),
            "halted": std::fs::read_to_string(&self.halted)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect::<Vec<_>>())
                .unwrap_or_default(),
            "erase_pending": self.erase.pending(),
        })
    }
}

/// An order intent, in the key=value shape the actuator parses.
pub fn render(action: &str, fields: &[(&str, &str)], order_hash: &str) -> String {
    let mut s = format!("action={action}\n");
    for (k, v) in fields {
        s.push_str(&format!("{k}={v}\n"));
    }
    s.push_str(&format!("nonce={order_hash}\n"));
    s
}

/// The erase latch and its completion record.
pub struct EraseLatch {
    pub pending: PathBuf,
    pub done: PathBuf,
}

impl EraseLatch {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            pending: dir.join("erase-pending.json"),
            done: dir.join("erase-done"),
        }
    }

    pub fn latch(&self, order_hash: &str) -> Result<(), String> {
        let body = json!({ "order_hash": order_hash, "latched_at": super::now_s() });
        write_atomically(&self.pending, body.to_string().as_bytes())
    }

    /// The latched erase, if one is pending.
    pub fn pending(&self) -> Option<Value> {
        let raw = std::fs::read(&self.pending).ok()?;
        Some(
            serde_json::from_slice(&raw)
                .unwrap_or_else(|_| json!({ "unreadable": self.pending.display().to_string() })),
        )
    }

    /// The nonce an acknowledging quote must be made over.
    pub fn ack_nonce(order_hash: &str, done: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ERASE_ACK_DOMAIN);
        h.update(order_hash.as_bytes());
        h.update(b"\n");
        h.update(done);
        h.finalize().into()
    }

    /// Acknowledge a completed erase with a fresh quote.
    ///
    /// `Ok(None)` while nothing is pending, or while early boot has not yet
    /// recorded completion. A completion record for a different order, or a
    /// quote that is not over the nonce asked for, is an error and leaves the
    /// erase pending. The latch is not cleared here: the caller records the
    /// acknowledgment first and then calls [`Self::clear`].
    pub fn acknowledge(
        &self,
        quote: &dyn Fn(&[u8]) -> Result<Value, String>,
    ) -> Result<Option<Value>, String> {
        let Some(latched) = self.pending() else {
            return Ok(None);
        };
        let Some(order_hash) = latched["order_hash"].as_str() else {
            return Err(format!("{} names no order", self.pending.display()));
        };
        let done = match std::fs::read(&self.done) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", self.done.display())),
        };
        let record: Value =
            serde_json::from_slice(&done).map_err(|e| format!("{}: {e}", self.done.display()))?;
        if record["order_hash"].as_str() != Some(order_hash) {
            return Err(format!(
                "early boot recorded completing {}, but the erase latched here is {order_hash}",
                record["order_hash"]
            ));
        }
        let nonce = Self::ack_nonce(order_hash, &done);
        let q = quote(&nonce)?;
        if q["nonce"].as_str() != Some(hex::encode(nonce).as_str()) {
            return Err("the quote is not over the acknowledgment nonce".into());
        }
        Ok(Some(json!({
            "order_hash": order_hash,
            "completed": record,
            "nonce": hex::encode(nonce),
            "quote": q,
        })))
    }

    pub fn clear(&self) -> Result<(), String> {
        for p in [&self.done, &self.pending] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", p.display())),
            }
            if p.exists() {
                return Err(format!("{} is still present after removal", p.display()));
            }
        }
        Ok(())
    }
}

/// Write a file whole, durably, or not at all.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(at)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(at)?;
    f.write_all(bytes).map_err(at)?;
    f.sync_all().map_err(at)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own for one test, removed when the test ends.
    struct Scratch(PathBuf);

    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let d =
            std::env::temp_dir().join(format!("furcate-actuators-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }

    fn actuator(dir: &Path, wait_ms: u64) -> IntentActuator {
        IntentActuator {
            intent: dir.join("order"),
            result: dir.join("order-result.json"),
            wait: Duration::from_millis(wait_ms),
            poll: Duration::from_millis(10),
            overlay: "fur0".into(),
            isolated: dir.join("isolated"),
            halted: dir.join("halted"),
            erase: EraseLatch::in_dir(dir),
        }
    }

    /// Stands in for the privileged half: reads the intent once it appears
    /// and writes the given report for its nonce.
    fn privileged(dir: &Path, report: impl Fn(&str, &str) -> Value + Send + 'static) {
        let intent = dir.join("order");
        let result = dir.join("order-result.json");
        std::thread::spawn(move || {
            for _ in 0..500 {
                if let Ok(body) = std::fs::read_to_string(&intent) {
                    let get = |k: &str| {
                        body.lines()
                            .find_map(|l| l.strip_prefix(&format!("{k}=")).map(str::to_string))
                            .unwrap_or_default()
                    };
                    let v = report(&get("action"), &get("nonce"));
                    std::fs::write(&result, v.to_string()).unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
    }

    #[test]
    fn a_reported_success_is_done_and_names_what_happened() {
        let d = scratch("ok");
        privileged(
            &d,
            |action, nonce| json!({ "ok": true, "action": action, "stopped": ["furcate-app-a.service"], "nonce": nonce }),
        );
        let r = actuator(&d, 5_000).halt("h1");
        let Report::Done { what } = r else {
            panic!("{r:?}")
        };
        assert_eq!(what["action"], "halt");
        assert_eq!(what["stopped"][0], "furcate-app-a.service");
        assert_eq!(
            std::fs::read_to_string(d.join("order")).unwrap(),
            "action=halt\nnonce=h1\n"
        );
    }

    #[test]
    fn a_partial_halt_is_a_failure_carrying_what_did_stop() {
        let d = scratch("partial");
        privileged(&d, |_, nonce| {
            json!({ "ok": false, "why": "some workloads did not stop",
                    "stopped": ["furcate-app-a.service"], "failed": ["furcate-app-b.service"],
                    "nonce": nonce })
        });
        let r = actuator(&d, 5_000).halt("h2");
        let Report::Failed { why, partial } = r else {
            panic!("{r:?}")
        };
        assert_eq!(why, "some workloads did not stop");
        assert_eq!(partial["failed"][0], "furcate-app-b.service");
    }

    #[test]
    fn silence_is_a_failure_and_a_stale_report_is_not_an_answer() {
        let d = scratch("silent");
        std::fs::write(
            d.join("order-result.json"),
            json!({ "ok": true, "nonce": "an-earlier-order" }).to_string(),
        )
        .unwrap();
        let r = actuator(&d, 50).isolate("h3");
        let Report::Failed { why, .. } = r else {
            panic!("{r:?}")
        };
        assert!(why.contains("did not report"), "{why}");
        assert_eq!(
            std::fs::read_to_string(d.join("order")).unwrap(),
            "action=isolate\niface=fur0\nnonce=h3\n"
        );
    }

    #[test]
    fn isolate_then_release_reach_the_actuator_with_the_overlay() {
        let d = scratch("isolate");
        let a = actuator(&d, 5_000);
        privileged(
            &d,
            |action, nonce| json!({ "ok": true, "action": action, "nonce": nonce }),
        );
        assert!(a.isolate("i1").is_done());
        std::fs::remove_file(d.join("order")).unwrap();
        privileged(
            &d,
            |action, nonce| json!({ "ok": true, "action": action, "nonce": nonce }),
        );
        let r = a.release("r1");
        let Report::Done { what } = r else {
            panic!("{r:?}")
        };
        assert_eq!(what["action"], "release");
    }

    #[test]
    fn resume_reaches_the_actuator_and_its_report_is_what_counts() {
        let d = scratch("resume");
        std::fs::write(d.join("halted"), "furcate-app-a.service\nfurcate-app-b.service\n").unwrap();
        let a = actuator(&d, 5_000);
        assert_eq!(a.state()["halted"], json!(["furcate-app-a.service", "furcate-app-b.service"]));
        privileged(&d, |action, nonce| {
            json!({ "ok": false, "why": "some workloads did not start", "action": action,
                    "started": ["furcate-app-a.service"], "failed": ["furcate-app-b.service"],
                    "nonce": nonce })
        });
        let r = a.resume("u1");
        let Report::Failed { why, partial } = r else {
            panic!("{r:?}")
        };
        assert_eq!(why, "some workloads did not start");
        assert_eq!(partial["started"][0], "furcate-app-a.service");
        assert_eq!(
            std::fs::read_to_string(d.join("order")).unwrap(),
            "action=resume\nnonce=u1\n"
        );

        std::fs::remove_file(d.join("order")).unwrap();
        privileged(&d, |action, nonce| {
            json!({ "ok": false, "why": "no halt is recorded on this node; nothing was restarted",
                    "action": action, "nonce": nonce })
        });
        let r = a.resume("u2");
        assert!(matches!(&r, Report::Failed { why, .. } if why.contains("no halt is recorded")), "{r:?}");
    }

    /// Runs the privileged helper's halt and resume against a stand-in
    /// `systemctl`, so what the helper records and restarts is checked by
    /// running it rather than by reading it.
    #[test]
    fn the_helper_resumes_exactly_what_its_halts_stopped() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = scratch("helper");
        // Found by walking up from the crate, not by counting `..`: the crate sits one
        // level deeper here than in the published tree.
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|a| a.join("deploy/furcate-order-actuator.sh"))
            .find(|p| p.is_file())
            .expect("deploy/furcate-order-actuator.sh above the crate");
        let text = std::fs::read_to_string(&script).unwrap();
        // The functions only: everything from the start-up re-isolation on is
        // the service loop.
        let cut = text.find("# An isolation outlives").expect("the helper's loop marker");
        std::fs::write(d.join("helper.sh"), &text[..cut]).unwrap();

        let bin = d.join("bin");
        let units = d.join("units");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(units.join("active")).unwrap();
        std::fs::create_dir_all(units.join("broken")).unwrap();
        let fake = format!(
            r#"#!/bin/sh
U={u}
case "$1" in
  list-units) for f in "$U"/active/furcate-app-*.service; do [ -e "$f" ] && echo "$(basename "$f") loaded active running x"; done; exit 0 ;;
  stop) touch "$U/stopped-$3"; rm -f "$U/active/$3"; exit 0 ;;
  start) [ -e "$U/broken/$3" ] && exit 1; touch "$U/active/$3"; exit 0 ;;
  is-active) [ -e "$U/active/$4" ] ;;
  *) exit 1 ;;
esac
"#,
            u = units.display()
        );
        std::fs::write(bin.join("systemctl"), fake).unwrap();
        std::fs::set_permissions(bin.join("systemctl"), std::fs::Permissions::from_mode(0o755)).unwrap();
        for u in ["furcate-app-a.service", "furcate-app-b.service"] {
            std::fs::write(units.join("active").join(u), "").unwrap();
        }

        let run = |call: &str| -> Value {
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(". {}/helper.sh; {call}", d.display()))
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("FURCATE_STATE_DIR", &*d)
                .env("FURCATE_ORDER_RESULT", d.join("result.json"))
                .env("FURCATE_ORDER_INTENT", d.join("order"))
                .status()
                .unwrap();
            assert!(status.success(), "{call}");
            serde_json::from_str(&std::fs::read_to_string(d.join("result.json")).unwrap()).unwrap()
        };
        let halted = || std::fs::read_to_string(d.join("halted")).ok();

        let r = run("resume r0");
        assert_eq!(r["ok"], false);
        assert!(r["why"].as_str().unwrap().contains("no halt is recorded"), "{r}");

        let r = run("halt h1");
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["stopped"], json!(["furcate-app-a.service", "furcate-app-b.service"]));
        assert_eq!(halted().unwrap(), "furcate-app-a.service\nfurcate-app-b.service\n");

        // Started by hand after the halt: never in the record, never touched.
        std::fs::write(units.join("active").join("furcate-app-c.service"), "").unwrap();
        std::fs::write(units.join("broken").join("furcate-app-b.service"), "").unwrap();
        let r = run("resume r1");
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(r["why"], "some workloads did not start");
        assert_eq!(r["started"], json!(["furcate-app-a.service"]));
        assert_eq!(r["failed"], json!(["furcate-app-b.service"]));
        assert_eq!(halted().unwrap(), "furcate-app-b.service\n", "what failed stays recorded");

        std::fs::remove_file(units.join("broken").join("furcate-app-b.service")).unwrap();
        let r = run("resume r2");
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["started"], json!(["furcate-app-b.service"]));
        assert!(halted().is_none(), "a complete resume clears the record");
        assert!(!units.join("stopped-furcate-app-c.service").exists());
    }

    #[test]
    fn an_unsafe_overlay_name_never_reaches_the_actuator() {
        let d = scratch("unsafe");
        let mut a = actuator(&d, 50);
        a.overlay = "-x;rm".into();
        assert!(!a.isolate("i2").is_done());
        assert!(!d.join("order").exists());
    }

    #[test]
    fn an_erase_is_pending_until_a_quote_acknowledges_it() {
        let d = scratch("erase");
        let a = actuator(&d, 5_000);
        privileged(
            &d,
            |_, nonce| json!({ "ok": true, "destroyed": ["seal.priv"], "nonce": nonce }),
        );
        let r = a.crypto_erase("e1");
        let Report::Done { what } = r else {
            panic!("{r:?}")
        };
        assert_eq!(what["erase_pending"], true);
        assert_eq!(a.state()["erase_pending"]["order_hash"], "e1");

        let quoter = |n: &[u8]| -> Result<Value, String> { Ok(json!({ "nonce": hex::encode(n) })) };
        // Early boot has not completed it yet.
        assert_eq!(a.erase.acknowledge(&quoter).unwrap(), None);
        assert!(a.state()["erase_pending"].is_object());

        // A completion record for another order does not acknowledge this one.
        std::fs::write(d.join("erase-done"), br#"{"order_hash":"other"}"#).unwrap();
        assert!(a.erase.acknowledge(&quoter).is_err());
        assert!(a.state()["erase_pending"].is_object());

        // A quote over the wrong nonce does not either.
        let done = br#"{"order_hash":"e1","completed":"tpm2_clear"}"#;
        std::fs::write(d.join("erase-done"), done).unwrap();
        let wrong = |_: &[u8]| -> Result<Value, String> { Ok(json!({ "nonce": "00" })) };
        assert!(a.erase.acknowledge(&wrong).is_err());

        let ack = a.erase.acknowledge(&quoter).unwrap().expect("acknowledged");
        assert_eq!(ack["nonce"], hex::encode(EraseLatch::ack_nonce("e1", done)));
        a.erase.clear().unwrap();
        assert!(a.state()["erase_pending"].is_null());
    }

    #[test]
    fn a_failed_erase_stays_pending() {
        let d = scratch("erase-fail");
        let a = actuator(&d, 5_000);
        privileged(
            &d,
            |_, nonce| json!({ "ok": false, "why": "keyslot wipe refused", "destroyed": ["seal.priv"], "nonce": nonce }),
        );
        let r = a.crypto_erase("e2");
        let Report::Failed { why, partial } = r else {
            panic!("{r:?}")
        };
        assert!(why.contains("stays latched"), "{why}");
        assert_eq!(partial["destroyed"][0], "seal.priv");
        assert_eq!(a.state()["erase_pending"]["order_hash"], "e2");
    }
}
