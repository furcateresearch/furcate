//! Fetching model weights over HTTPS, in process.
//!
//! The node's base image carries no download tool, and it should not have to:
//! a CLI that shells out to `curl` works on a workstation and fails on the
//! machine it ships to. So the transfer is done here, with a TLS stack linked
//! into the binary and the Mozilla root set compiled in, which means a base
//! without a CA bundle can still verify the source.
//!
//! The contract is the one `model pull` always had:
//!
//! - the source must advertise a SHA-256 for the file, or nothing is fetched;
//! - the bytes go to `<dest>.part` beside the target and are renamed into place
//!   only after the digest matches, so an interrupted or wrong download never
//!   sits in the store looking like a model;
//! - an interrupted transfer resumes from what is on disk (an HTTP range
//!   request), and a failed run keeps the partial file for the next one.
//!
//! Proxies come from the standard environment variables (`HTTPS_PROXY`,
//! `HTTP_PROXY`, `ALL_PROXY`, upper or lower case).

use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How a fetch behaves on a bad link. The defaults are for a real network;
/// tests shrink them.
pub(crate) struct Opts {
    /// Attempts in a row that may end without a single new byte before the
    /// download is given up. An attempt that made progress resets the count:
    /// the failure this is built for is a long transfer that keeps dropping,
    /// not a server that is down.
    pub max_idle_attempts: u32,
    /// A hard ceiling on attempts of any kind, so a link that trickles a few
    /// bytes per connection cannot keep the command running forever.
    pub max_attempts: u32,
    pub retry_delay: Duration,
    /// No byte at all for this long and the connection is treated as dead.
    pub read_timeout: Duration,
    /// Below `stall_bytes_per_sec` averaged over `stall_window` and the attempt
    /// is abandoned and retried: the transfer has stopped moving, whatever the
    /// socket believes.
    pub stall_bytes_per_sec: u64,
    pub stall_window: Duration,
    pub proxy_from_env: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            max_idle_attempts: 5,
            max_attempts: 30,
            retry_delay: Duration::from_secs(3),
            read_timeout: Duration::from_secs(60),
            stall_bytes_per_sec: 30_000,
            stall_window: Duration::from_secs(60),
            proxy_from_env: true,
        }
    }
}

const MAX_REDIRECTS: u32 = 10;
const GIB: f64 = 1_073_741_824.0;

fn agent(o: &Opts) -> ureq::Agent {
    ureq::AgentBuilder::new()
        // Redirects are followed by hand: the digest header is on an early hop
        // (the repository's answer), not on the CDN that serves the bytes.
        .redirects(0)
        .try_proxy_from_env(o.proxy_from_env)
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(o.read_timeout)
        .timeout_write(Duration::from_secs(60))
        .user_agent(concat!("furcatectl/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// What the source says about the file before any of it is fetched.
pub(crate) struct Advertised {
    pub sha256: Option<String>,
    pub size: Option<u64>,
}

fn sha256_hex(v: &str) -> Option<String> {
    let v = v.trim().trim_matches('"');
    // A SHA-256, or nothing: a git blob id (what a non-LFS file carries in the
    // same header) names the bytes but is not the digest checked here.
    (v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())).then(|| v.to_ascii_lowercase())
}

/// One request, following redirects by hand. Every hop is handed to `seen`
/// so the caller can read headers from the hop that carries them.
fn send(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    range_from: Option<u64>,
    mut seen: impl FnMut(&ureq::Response),
) -> Result<ureq::Response> {
    let mut at = url::Url::parse(url).with_context(|| format!("not a URL: {url}"))?;
    for _ in 0..=MAX_REDIRECTS {
        let mut req = agent.request_url(method, &at);
        if let Some(n) = range_from {
            req = req.set("Range", &format!("bytes={n}-"));
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                return Err(anyhow::Error::new(t).context(format!("{method} {} failed", host(&at))))
            }
        };
        seen(&resp);
        if !(300..400).contains(&resp.status()) {
            return Ok(resp);
        }
        let loc = resp
            .header("location")
            .with_context(|| format!("{} answered HTTP {} with no Location", host(&at), resp.status()))?;
        at = at.join(loc).with_context(|| format!("unusable redirect target `{loc}`"))?;
    }
    bail!("more than {MAX_REDIRECTS} redirects from {url}")
}

fn host(u: &url::Url) -> String {
    u.host_str().unwrap_or("?").to_string()
}

/// Read the digest and size the source advertises (`x-linked-etag`, which for
/// a HuggingFace LFS object is its SHA-256, and `x-linked-size`). The LAST hop
/// that carries one wins: it is the one closest to the bytes.
pub(crate) fn advertised(url: &str, o: &Opts) -> Result<Advertised> {
    let a = agent(o);
    let (mut sha256, mut linked_size) = (None, None);
    let resp = send(&a, "HEAD", url, None, |r| {
        if let Some(v) = r.header("x-linked-etag").and_then(sha256_hex) {
            sha256 = Some(v);
        }
        if let Some(n) = r.header("x-linked-size").and_then(|v| v.trim().parse::<u64>().ok()) {
            linked_size = Some(n);
        }
    })
    .context("reading the model's headers")?;
    if !(200..300).contains(&resp.status()) {
        bail!("{url} answered HTTP {} {}", resp.status(), resp.status_text());
    }
    let size = linked_size.or_else(|| resp.header("content-length").and_then(|v| v.trim().parse().ok()));
    Ok(Advertised { sha256, size })
}

/// The temporary file a fetch into `dest` writes to.
pub(crate) fn part_path(dest: &Path) -> PathBuf {
    dest.with_extension("part")
}

/// Fetch `url` into `dest`, verified against the SHA-256 the source advertises.
/// Refuses before downloading anything when no SHA-256 is advertised.
pub(crate) fn fetch_verified(url: &str, dest: &Path, label: &str, o: &Opts) -> Result<u64> {
    let ad = advertised(url, o)?;
    // Weights reach a node only with a digest to check them against.
    let Some(want) = ad.sha256 else {
        bail!(
            "refusing to pull {label}: {url} advertised no SHA-256 (x-linked-etag), so the\n\
             weights could not be verified. Nothing was downloaded."
        );
    };
    let part = part_path(dest);
    download(url, &part, ad.size, o).map_err(|e| {
        // The partial file is KEPT. It is most of a model, and the next run
        // continues from it; deleting it is how a flaky link turns into a
        // download that can never finish.
        let have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        e.context(format!(
            "download failed for {label}. {:.2} GiB is kept at {}; run the same command again to continue from there",
            have as f64 / GIB,
            part.display()
        ))
    })?;

    let got = crate::model::sha256_file(&part)?;
    if !got.eq_ignore_ascii_case(&want) {
        let _ = std::fs::remove_file(&part);
        bail!("digest mismatch for {label}\n  expected {want}\n  got      {got}\nThe file was removed.");
    }
    println!("  digest verified: {}", &got[..16]);
    std::fs::rename(&part, dest).with_context(|| format!("moving {} into place", part.display()))?;
    Ok(std::fs::metadata(dest)?.len())
}

/// Why one attempt ended without the whole file.
enum Attempt {
    /// Worth another try: a dropped connection, a stall, a 5xx.
    Retry(anyhow::Error),
    /// Not: a 404 or a 403 does not change by asking again.
    Fatal(anyhow::Error),
}

fn download(url: &str, part: &Path, size: Option<u64>, o: &Opts) -> Result<()> {
    let a = agent(o);
    let mut idle = 0;
    let mut last_err = None;
    for attempt in 1..=o.max_attempts {
        let before = len(part);
        if let Some(total) = size {
            if before == total {
                return Ok(());
            }
            if before > total {
                // Longer than the source says the file is: not a prefix of it.
                std::fs::File::create(part)?;
            }
        }
        if attempt > 1 {
            println!(
                "  interrupted at {:.2} GiB ({}) — resuming (attempt {attempt})",
                len(part) as f64 / GIB,
                last_err.as_ref().map(|e: &anyhow::Error| format!("{e:#}")).unwrap_or_default()
            );
            std::thread::sleep(o.retry_delay);
        }
        match one_attempt(&a, url, part, size, o) {
            Ok(()) => return Ok(()),
            Err(Attempt::Fatal(e)) => return Err(e),
            Err(Attempt::Retry(e)) => last_err = Some(e),
        }
        if len(part) > before {
            idle = 0;
        } else {
            idle += 1;
            if idle >= o.max_idle_attempts {
                break;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no attempt was made")))
        .context("the transfer kept failing")
}

fn len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

fn one_attempt(a: &ureq::Agent, url: &str, part: &Path, size: Option<u64>, o: &Opts) -> Result<(), Attempt> {
    let have = len(part);
    let resp = send(a, "GET", url, (have > 0).then_some(have), |_| {}).map_err(Attempt::Retry)?;
    let status = resp.status();
    let (mut file, start) = match status {
        206 => {
            // Content-Range: bytes <start>-<end>/<total>. Appending anything
            // other than the byte after what is on disk would corrupt the file
            // in a way only the digest would catch, so check it here.
            let cr = resp.header("content-range").unwrap_or("").to_string();
            let start = cr
                .trim()
                .strip_prefix("bytes ")
                .and_then(|r| r.split('-').next())
                .and_then(|s| s.parse::<u64>().ok());
            if start != Some(have) {
                let _ = std::fs::File::create(part);
                return Err(Attempt::Retry(anyhow::anyhow!(
                    "the source resumed at the wrong offset ({cr:?}, wanted {have}); starting over"
                )));
            }
            let f = std::fs::OpenOptions::new().append(true).open(part).map_err(|e| Attempt::Fatal(e.into()))?;
            (f, have)
        }
        200 => {
            if have > 0 {
                println!("  the source does not resume; starting from zero");
            }
            (std::fs::File::create(part).map_err(|e| Attempt::Fatal(e.into()))?, 0)
        }
        416 if size == Some(have) || size.is_none() => {
            // Nothing past what is on disk: the file is complete, and the digest
            // decides whether it is the right one.
            return Ok(());
        }
        416 => {
            let _ = std::fs::File::create(part);
            return Err(Attempt::Retry(anyhow::anyhow!("the source refused the resume range; starting over")));
        }
        s if s >= 500 || s == 429 || s == 408 => {
            return Err(Attempt::Retry(anyhow::anyhow!("the source answered HTTP {s} {}", resp.status_text())))
        }
        s => {
            return Err(Attempt::Fatal(anyhow::anyhow!(
                "the source answered HTTP {s} {} for {url}",
                resp.status_text()
            )))
        }
    };
    let total = size.or_else(|| {
        resp.header("content-length").and_then(|v| v.trim().parse::<u64>().ok()).map(|n| n + start)
    });

    let mut body = resp.into_reader();
    let mut buf = vec![0u8; 1 << 16];
    let mut done = start;
    let mut progress = Progress::new(start, total);
    let (mut window_at, mut window_bytes) = (Instant::now(), 0u64);
    let result = loop {
        let n = match body.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(Attempt::Retry(anyhow::Error::new(e).context("the connection dropped"))),
        };
        if let Err(e) = file.write_all(&buf[..n]) {
            break Err(Attempt::Fatal(anyhow::Error::new(e).context(format!("writing {}", part.display()))));
        }
        done += n as u64;
        window_bytes += n as u64;
        progress.update(done);
        let w = window_at.elapsed();
        if w >= o.stall_window {
            if window_bytes < o.stall_bytes_per_sec.saturating_mul(w.as_secs().max(1)) {
                break Err(Attempt::Retry(anyhow::anyhow!(
                    "stalled: {} bytes in {}s",
                    window_bytes,
                    w.as_secs()
                )));
            }
            (window_at, window_bytes) = (Instant::now(), 0);
        }
    };
    progress.finish();
    let _ = file.flush();
    drop(file);
    result?;
    if let Some(t) = total {
        if done < t {
            return Err(Attempt::Retry(anyhow::anyhow!("the body ended at {done} of {t} bytes")));
        }
    }
    Ok(())
}

/// Progress on stderr: a live line on a terminal, a line every tenth of the
/// file in a log.
struct Progress {
    total: Option<u64>,
    tty: bool,
    started: Instant,
    from: u64,
    last: Instant,
    last_decile: u64,
    printed: bool,
}

impl Progress {
    fn new(from: u64, total: Option<u64>) -> Self {
        let now = Instant::now();
        Progress {
            total,
            tty: std::io::stderr().is_terminal(),
            started: now,
            from,
            last: now,
            last_decile: total.map(|t| from * 10 / t.max(1)).unwrap_or(0),
            printed: false,
        }
    }

    fn line(&self, done: u64) -> String {
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = (done - self.from) as f64 / secs / 1_000_000.0;
        match self.total {
            Some(t) => format!(
                "  {:5.1}%  {:.2} / {:.2} GiB  {rate:.1} MB/s",
                done as f64 * 100.0 / t.max(1) as f64,
                done as f64 / GIB,
                t as f64 / GIB
            ),
            None => format!("  {:.2} GiB  {rate:.1} MB/s", done as f64 / GIB),
        }
    }

    fn update(&mut self, done: u64) {
        if self.tty {
            if self.last.elapsed() >= Duration::from_millis(250) {
                eprint!("\r{}   ", self.line(done));
                self.last = Instant::now();
                self.printed = true;
            }
        } else if let Some(t) = self.total {
            let d = done * 10 / t.max(1);
            if d > self.last_decile {
                self.last_decile = d;
                eprintln!("{}", self.line(done));
            }
        } else if self.last.elapsed() >= Duration::from_secs(30) {
            eprintln!("{}", self.line(done));
            self.last = Instant::now();
        }
    }

    fn finish(&mut self) {
        if self.tty && self.printed {
            eprintln!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::BufRead;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    /// A small HTTP/1.1 origin: `/resolve` answers with a redirect carrying the
    /// digest header (as the repository does), `/blob` serves the bytes with
    /// range support. The first `cut` GETs send only part of the body and then
    /// close the connection, which is what an interrupted transfer looks like.
    struct Origin {
        url: String,
        log: Arc<Mutex<Vec<String>>>,
    }

    fn origin(body: Vec<u8>, etag: Option<String>, cut: usize) -> Origin {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let (log2, cuts) = (log.clone(), Arc::new(Mutex::new(cut)));
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { continue };
                serve(s, &body, etag.as_deref(), &log2, &cuts);
            }
        });
        Origin { url: format!("http://127.0.0.1:{port}/resolve"), log }
    }

    fn serve(mut s: TcpStream, body: &[u8], etag: Option<&str>, log: &Mutex<Vec<String>>, cuts: &Mutex<usize>) {
        let mut r = std::io::BufReader::new(s.try_clone().unwrap());
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        let mut range = None;
        loop {
            let mut h = String::new();
            r.read_line(&mut h).unwrap();
            if h.trim().is_empty() {
                break;
            }
            if let Some(v) = h.to_ascii_lowercase().strip_prefix("range: bytes=") {
                range = v.trim().trim_end_matches('-').parse::<usize>().ok();
            }
        }
        let mut parts = first.split_whitespace();
        let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
        log.lock().unwrap().push(format!("{method} {path} {}", range.map(|n| n.to_string()).unwrap_or("-".into())));
        if path == "/resolve" {
            let tag = etag.map(|e| format!("x-linked-etag: \"{e}\"\r\nx-linked-size: {}\r\n", body.len())).unwrap_or_default();
            let _ = write!(s, "HTTP/1.1 302 Found\r\nlocation: /blob\r\n{tag}content-length: 0\r\nconnection: close\r\n\r\n");
            return;
        }
        if path != "/blob" {
            let _ = write!(s, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            return;
        }
        let from = range.unwrap_or(0).min(body.len());
        let rest = &body[from..];
        let head = if range.is_some() {
            format!(
                "HTTP/1.1 206 Partial Content\r\ncontent-range: bytes {from}-{}/{}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len() - 1,
                body.len(),
                rest.len()
            )
        } else {
            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", rest.len())
        };
        let _ = s.write_all(head.as_bytes());
        if method == "HEAD" {
            return;
        }
        let mut c = cuts.lock().unwrap();
        if *c > 0 {
            *c -= 1;
            let _ = s.write_all(&rest[..rest.len() / 3]);
            let _ = s.flush();
            return; // dropped mid-body
        }
        drop(c);
        let _ = s.write_all(rest);
    }

    fn opts() -> Opts {
        Opts {
            max_idle_attempts: 2,
            max_attempts: 6,
            retry_delay: Duration::ZERO,
            read_timeout: Duration::from_secs(5),
            stall_bytes_per_sec: 0,
            stall_window: Duration::from_secs(60),
            proxy_from_env: false,
        }
    }

    fn body() -> Vec<u8> {
        (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("furcate-fetch-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("m.gguf")
    }

    #[test]
    fn success_follows_the_redirect_verifies_and_moves_into_place() {
        let b = body();
        let o = origin(b.clone(), Some(sha(&b)), 0);
        let dest = tmp("ok");
        let n = fetch_verified(&o.url, &dest, "m", &opts()).unwrap();
        assert_eq!(n, b.len() as u64);
        assert_eq!(std::fs::read(&dest).unwrap(), b);
        assert!(!part_path(&dest).exists());
    }

    #[test]
    fn digest_mismatch_is_refused_and_nothing_enters_the_store() {
        let b = body();
        let o = origin(b, Some("ab".repeat(32)), 0);
        let dest = tmp("bad");
        let e = format!("{:#}", fetch_verified(&o.url, &dest, "m", &opts()).unwrap_err());
        assert!(e.contains("digest mismatch"), "{e}");
        assert!(!dest.exists());
        assert!(!part_path(&dest).exists(), "a wrong file must not be kept to resume from");
    }

    #[test]
    fn a_source_with_no_sha256_is_refused_before_any_byte_is_fetched() {
        let o = origin(body(), None, 0);
        let dest = tmp("none");
        let e = format!("{:#}", fetch_verified(&o.url, &dest, "m", &opts()).unwrap_err());
        assert!(e.contains("advertised no SHA-256"), "{e}");
        assert!(!dest.exists() && !part_path(&dest).exists());
        assert!(o.log.lock().unwrap().iter().all(|l| !l.starts_with("GET")), "{:?}", o.log.lock().unwrap());
    }

    #[test]
    fn an_interrupted_transfer_resumes_from_what_is_on_disk() {
        let b = body();
        let o = origin(b.clone(), Some(sha(&b)), 2);
        let dest = tmp("resume");
        fetch_verified(&o.url, &dest, "m", &opts()).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b);
        let log = o.log.lock().unwrap();
        let gets: Vec<_> = log.iter().filter(|l| l.starts_with("GET /blob")).collect();
        assert_eq!(gets.len(), 3, "{log:?}");
        assert!(gets[0].ends_with(" -"), "first GET asks for everything: {log:?}");
        assert!(gets[1..].iter().all(|l| !l.ends_with(" -")), "later GETs resume with a range: {log:?}");
    }

    #[test]
    fn a_transfer_that_keeps_dropping_keeps_the_partial_file_for_the_next_run() {
        let b = body();
        let o = origin(b.clone(), Some(sha(&b)), usize::MAX);
        let dest = tmp("keep");
        let mut op = opts();
        op.max_attempts = 2;
        let e = format!("{:#}", fetch_verified(&o.url, &dest, "m", &op).unwrap_err());
        assert!(e.contains("run the same command again"), "{e}");
        assert!(!dest.exists());
        let part = std::fs::read(part_path(&dest)).unwrap();
        assert!(!part.is_empty() && part.len() < b.len());
        assert_eq!(&b[..part.len()], &part[..], "what is kept is a prefix of the file");

        // The next run, against a source that now completes, finishes it.
        let o2 = origin(b.clone(), Some(sha(&b)), 0);
        fetch_verified(&o2.url, &dest, "m", &opts()).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b);
        assert!(o2.log.lock().unwrap().iter().any(|l| l.starts_with("GET /blob") && !l.ends_with(" -")));
    }

    #[test]
    fn a_missing_file_is_a_clear_error_and_not_retried() {
        let o = origin(body(), Some(sha(&body())), 0);
        let dest = tmp("404");
        let e = format!("{:#}", fetch_verified(&o.url.replace("/resolve", "/nope"), &dest, "m", &opts()).unwrap_err());
        assert!(e.contains("HTTP 404"), "{e}");
        assert_eq!(o.log.lock().unwrap().len(), 1, "{:?}", o.log.lock().unwrap());
    }

    #[test]
    fn an_unreachable_source_names_the_host() {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/resolve", dead.local_addr().unwrap().port());
        drop(dead);
        let e = format!("{:#}", fetch_verified(&url, &tmp("dead"), "m", &opts()).unwrap_err());
        assert!(e.contains("127.0.0.1"), "{e}");
    }
}
