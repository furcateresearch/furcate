//! An uninterruptible supply, read over NUT's network protocol.
//!
//! The supply is attached to one machine, which runs `upsd`. Every other node
//! asks that daemon over the overlay with NUT's text protocol, so a node needs
//! no NUT software, no USB access and no privilege to know whether the building
//! has lost mains. This is read only: the client sends `LIST VAR` and nothing
//! that sets a variable or runs a command, and the daemon is never asked to
//! power anything off.
//!
//! What it reports is what upsd said, with the variable each figure came from.
//! A variable the driver does not publish (the Green Cell reports no runtime)
//! is "not measured", never zero, and a status that is neither `OL` nor `OB` is
//! an unknown state rather than "on line". A supply that cannot be reached is
//! [`UpsSource::NotMeasured`] with the reason; callers decide what to do about
//! that, this module does not guess.
//!
//! The monitor credential, when upsd asks for one, is a systemd credential:
//! it is read from `$CREDENTIALS_DIRECTORY`, never from argv, the environment
//! or a file in a repository, and it is never written to a log.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

/// NUT's registered port.
pub const DEFAULT_PORT: u16 = 3493;

/// Where the node's UPS settings live. Not a secret: it names the daemon to
/// ask and the credential to present, never the credential itself.
pub const CONFIG_PATH: &str = "/etc/furcate/ups.json";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
/// A reply is a few dozen short lines; one larger than this is not upsd.
const MAX_REPLY_BYTES: u64 = 256 * 1024;
const MAX_LINES: usize = 2048;

/// Which daemon to ask, and for which supply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// The name of the supply in upsd.conf.
    pub ups: String,
    /// The systemd credential holding the monitor user, when upsd wants one.
    /// Absent means the read is anonymous; named but missing is an error, not
    /// an anonymous read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// The file at [`CONFIG_PATH`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsConfig {
    pub source: Source,
    /// Thresholds for the ladder; whatever is left out keeps its default.
    #[serde(default)]
    pub triggers: crate::ladder::Triggers,
}

impl UpsConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        let c: UpsConfig = serde_json::from_str(text).map_err(|e| format!("not a UPS configuration: {e}"))?;
        c.source.validate()?;
        c.triggers.validate()?;
        Ok(c)
    }
}

/// What reading the configuration found.
#[derive(Clone, Debug, PartialEq)]
pub enum Configured {
    /// No file: this machine has no supply configured, which is a statement
    /// about the machine and not a fault.
    None,
    /// A file that is wrong. Reported loudly; never read as "no supply".
    Invalid(String),
    Some(UpsConfig),
}

pub fn load_config(path: &Path) -> Configured {
    match std::fs::read_to_string(path) {
        Ok(t) => match UpsConfig::parse(&t) {
            Ok(c) => Configured::Some(c),
            Err(e) => Configured::Invalid(format!("{}: {e}", path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Configured::None,
        Err(e) => Configured::Invalid(format!("{} cannot be read: {e}", path.display())),
    }
}

impl Source {
    pub fn validate(&self) -> Result<(), String> {
        if self.host.is_empty() || self.host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("source.host is empty or has whitespace".into());
        }
        if !token_ok(&self.ups) {
            return Err("source.ups must be a plain name (letters, digits, . _ -)".into());
        }
        if let Some(c) = &self.credential {
            if c.is_empty() || c.contains('/') || c.starts_with('.') || c.chars().any(|c| c.is_control()) {
                return Err("source.credential must be a bare credential name".into());
            }
        }
        Ok(())
    }

    /// `host:port`, for a message.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn token_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The monitor user. Debug prints no secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    user: String,
    password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials {{ user: {:?}, password: <redacted> }}", self.user)
    }
}

impl Credentials {
    /// `user` on the first line and the password on the second.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        let user = lines.next().unwrap_or("").trim_end_matches('\r').to_string();
        let password = lines.next().unwrap_or("").trim_end_matches('\r').to_string();
        // The protocol is line based and splits on spaces: a value that carried
        // either would let a stored secret inject a command.
        for (what, v) in [("user", &user), ("password", &password)] {
            if v.is_empty() {
                return Err(format!("the credential has no {what}"));
            }
            if v.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\') {
                return Err(format!("the credential's {what} has a character the protocol cannot carry"));
            }
        }
        Ok(Self { user, password })
    }

    /// The credential `name` from the service's credentials directory.
    pub fn load(dir: Option<&Path>, name: &str) -> Result<Self, String> {
        let dir = dir.ok_or_else(|| {
            format!("credential {name} is named but this service was given no credentials directory")
        })?;
        let text = std::fs::read_to_string(dir.join(name))
            .map_err(|e| format!("credential {name} cannot be read: {e}"))?;
        Self::parse(&text)
    }
}

/// A figure and the variable it was read from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Figure<T> {
    pub value: T,
    pub from: String,
}

/// What the status flags say about the mains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mains {
    OnLine,
    OnBattery,
    /// Neither `OL` nor `OB`: calibrating, bypass, off, or something this
    /// build has no word for. Not on line, and not on battery.
    Unknown,
}

/// One reading of the supply.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpsReading {
    /// Unix seconds when this node took it.
    pub ts: u64,
    /// Which daemon and supply answered.
    pub source: String,
    pub status: Figure<String>,
    pub mains: Mains,
    /// The driver's `LB` flag. Recorded whether or not it is trusted; the
    /// Green Cell's is unproven, so the ladder decides.
    pub low_battery_flag: bool,
    pub charge_pct: Option<Figure<f64>>,
    pub runtime_secs: Option<Figure<u64>>,
    pub input_voltage: Option<Figure<f64>>,
    /// Variables the supply published and this could not read as a number.
    pub unreadable: Vec<String>,
}

/// What asking the supply found.
#[derive(Clone, Debug, PartialEq)]
pub enum UpsSource {
    Measured(UpsReading),
    NotMeasured(String),
}

impl UpsReading {
    /// Build a reading from the variables upsd listed. `None` when the one
    /// variable that decides everything, `ups.status`, is absent.
    pub fn from_vars(vars: &[(String, String)], src: &Source, now: u64) -> Option<Self> {
        let get = |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let status = get("ups.status")?.trim().to_string();
        let source = format!("nut {} ups {}", src.addr(), src.ups);
        let from = |k: &str| format!("{source} {k}");
        let flags: Vec<&str> = status.split_whitespace().collect();
        let mains = if flags.contains(&"OB") {
            Mains::OnBattery
        } else if flags.contains(&"OL") {
            Mains::OnLine
        } else {
            Mains::Unknown
        };
        let mut unreadable = Vec::new();
        let mut number = |k: &str, lo: f64, hi: f64| -> Option<Figure<f64>> {
            let raw = get(k)?;
            match raw.trim().parse::<f64>() {
                Ok(v) if v.is_finite() && v >= lo && v <= hi => Some(Figure { value: v, from: from(k) }),
                _ => {
                    unreadable.push(k.to_string());
                    None
                }
            }
        };
        let charge_pct = number("battery.charge", 0.0, 100.0);
        let input_voltage = number("input.voltage", 0.0, 1000.0);
        let runtime = number("battery.runtime", 0.0, 1.0e7);
        Some(UpsReading {
            ts: now,
            low_battery_flag: flags.contains(&"LB"),
            status: Figure { value: status.clone(), from: from("ups.status") },
            mains,
            charge_pct,
            input_voltage,
            runtime_secs: runtime.map(|f| Figure { value: f.value as u64, from: f.from }),
            unreadable,
            source,
        })
    }
}

impl UpsSource {
    pub fn reading(&self) -> Option<&UpsReading> {
        match self {
            UpsSource::Measured(r) => Some(r),
            UpsSource::NotMeasured(_) => None,
        }
    }

    /// For /healthz: each figure with where it came from, or "not measured".
    pub fn to_json(&self, now: u64) -> serde_json::Value {
        use serde_json::json;
        let fig = |f: &Option<Figure<f64>>| match f {
            Some(f) => json!({"value": f.value, "from": f.from}),
            None => json!("not measured"),
        };
        match self {
            UpsSource::NotMeasured(why) => json!({"present": true, "measured": false, "why": why}),
            UpsSource::Measured(r) => json!({
                "present": true,
                "measured": true,
                "source": r.source,
                "age_secs": now.saturating_sub(r.ts),
                "mains": r.mains,
                "status": {"value": r.status.value, "from": r.status.from},
                "low_battery_flag": r.low_battery_flag,
                "charge_pct": fig(&r.charge_pct),
                "runtime_secs": match &r.runtime_secs {
                    Some(f) => json!({"value": f.value, "from": f.from}),
                    None => json!("not measured"),
                },
                "input_voltage": fig(&r.input_voltage),
                "unreadable": r.unreadable,
            }),
        }
    }
}

/// Why asking failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpsError {
    Unreachable(String),
    AuthFailed(String),
    Refused(String),
    Protocol(String),
}

impl std::fmt::Display for UpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpsError::Unreachable(s) => write!(f, "upsd unreachable: {s}"),
            UpsError::AuthFailed(s) => write!(f, "upsd refused the monitor credential: {s}"),
            UpsError::Refused(s) => write!(f, "upsd refused the request: {s}"),
            UpsError::Protocol(s) => write!(f, "upsd did not speak NUT: {s}"),
        }
    }
}

/// Undo NUT's quoting of a value: `\"` and `\\`.
fn unquote(v: &str) -> Option<String> {
    let inner = v.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            out.push(it.next()?);
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn read_line<R: BufRead>(r: &mut R) -> Result<String, UpsError> {
    let mut line = String::new();
    match r.read_line(&mut line) {
        Ok(0) => Err(UpsError::Protocol("the connection closed mid-reply".into())),
        Ok(_) => Ok(line.trim_end_matches(['\r', '\n']).to_string()),
        Err(e) => Err(UpsError::Unreachable(format!("reading the reply: {e}"))),
    }
}

fn err_of(line: &str) -> UpsError {
    let rest = line.strip_prefix("ERR").unwrap_or(line).trim();
    let code = rest.split_whitespace().next().unwrap_or("");
    match code {
        "ACCESS-DENIED" | "INVALID-PASSWORD" | "INVALID-USERNAME" | "PASSWORD-REQUIRED" | "USERNAME-REQUIRED" => {
            UpsError::AuthFailed(rest.to_string())
        }
        _ => UpsError::Refused(rest.to_string()),
    }
}

/// Speak NUT over a reader and a writer. Split from the socket so a test can
/// drive it. Sends `USERNAME`/`PASSWORD` when a credential is given, then
/// `LIST VAR`, then `LOGOUT`; nothing else.
pub fn converse<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    ups: &str,
    creds: Option<&Credentials>,
) -> Result<Vec<(String, String)>, UpsError> {
    let send = |w: &mut W, line: String| -> Result<(), UpsError> {
        w.write_all(line.as_bytes())
            .and_then(|_| w.flush())
            .map_err(|e| UpsError::Unreachable(format!("writing the request: {e}")))
    };
    if let Some(c) = creds {
        for line in [format!("USERNAME {}\n", c.user), format!("PASSWORD {}\n", c.password)] {
            send(writer, line)?;
            let r = read_line(reader)?;
            if r != "OK" {
                return Err(if r.starts_with("ERR") { err_of(&r) } else { UpsError::Protocol("no OK to the credential".into()) });
            }
        }
    }
    send(writer, format!("LIST VAR {ups}\n"))?;
    let head = read_line(reader)?;
    if head.starts_with("ERR") {
        return Err(err_of(&head));
    }
    if head != format!("BEGIN LIST VAR {ups}") {
        return Err(UpsError::Protocol("the reply to LIST VAR did not begin a list".into()));
    }
    let prefix = format!("VAR {ups} ");
    let end = format!("END LIST VAR {ups}");
    let mut vars = Vec::new();
    for _ in 0..MAX_LINES {
        let l = read_line(reader)?;
        if l == end {
            let _ = send(writer, "LOGOUT\n".into());
            return Ok(vars);
        }
        let Some(rest) = l.strip_prefix(&prefix) else {
            return Err(UpsError::Protocol("a line in the list was not a VAR".into()));
        };
        let Some((name, val)) = rest.split_once(' ') else {
            return Err(UpsError::Protocol("a VAR line had no value".into()));
        };
        let Some(val) = unquote(val) else {
            return Err(UpsError::Protocol("a VAR value was not quoted".into()));
        };
        vars.push((name.to_string(), val));
    }
    Err(UpsError::Protocol("the list never ended".into()))
}

/// Ask the daemon at `src` about its supply.
pub fn query(src: &Source, creds: Option<&Credentials>, now: u64) -> UpsSource {
    match query_vars(src, creds) {
        Err(e) => UpsSource::NotMeasured(e.to_string()),
        Ok(vars) => match UpsReading::from_vars(&vars, src, now) {
            Some(r) => UpsSource::Measured(r),
            None => UpsSource::NotMeasured(format!(
                "upsd {} listed no ups.status for {}; the driver is not publishing",
                src.addr(),
                src.ups
            )),
        },
    }
}

fn query_vars(src: &Source, creds: Option<&Credentials>) -> Result<Vec<(String, String)>, UpsError> {
    let addr = src
        .addr()
        .to_socket_addrs()
        .map_err(|e| UpsError::Unreachable(format!("{} does not resolve: {e}", src.host)))?
        .next()
        .ok_or_else(|| UpsError::Unreachable(format!("{} resolves to nothing", src.host)))?;
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| UpsError::Unreachable(format!("{}: {e}", src.addr())))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut writer = stream.try_clone().map_err(|e| UpsError::Unreachable(e.to_string()))?;
    let mut reader = BufReader::new(stream.take(MAX_REPLY_BYTES));
    converse(&mut reader, &mut writer, &src.ups, creds)
}

/// The full pass a node makes: the credential if one is named (a named one
/// that cannot be read is a failure, not an anonymous read), then the query.
pub fn fetch(cfg: &UpsConfig, credentials_dir: Option<&Path>, now: u64) -> UpsSource {
    let creds = match &cfg.source.credential {
        None => None,
        Some(name) => match Credentials::load(credentials_dir, name) {
            Ok(c) => Some(c),
            Err(e) => return UpsSource::NotMeasured(e),
        },
    };
    query(&cfg.source, creds.as_ref(), now)
}

#[cfg(test)]
pub(crate) mod fake {
    //! A fake upsd on loopback.
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    /// Serves one connection: replies to each request line with `script`'s
    /// answer for it. Returns the port and a handle yielding the lines seen.
    pub fn serve(script: fn(&str) -> String) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut w = s.try_clone().unwrap();
            let mut r = BufReader::new(s);
            let mut seen = Vec::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                let reply = script(&line);
                seen.push(line.clone());
                if !reply.is_empty() {
                    let _ = w.write_all(reply.as_bytes());
                }
                if line == "LOGOUT" || reply == "CLOSE" {
                    break;
                }
            }
            seen
        });
        (port, h)
    }

    pub fn list(vars: &[(&str, &str)]) -> String {
        let mut s = String::from("BEGIN LIST VAR ups\n");
        for (k, v) in vars {
            s.push_str(&format!("VAR ups {k} \"{v}\"\n"));
        }
        s.push_str("END LIST VAR ups\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    fn src(port: u16) -> Source {
        Source { host: "127.0.0.1".into(), port, ups: "ups".into(), credential: None }
    }

    fn ask(script: fn(&str) -> String, creds: Option<&Credentials>) -> (UpsSource, Vec<String>) {
        let (port, h) = serve(script);
        let r = query(&src(port), creds, 1000);
        (r, h.join().unwrap())
    }

    fn on_line(l: &str) -> String {
        if l.starts_with("LIST VAR") {
            list(&[("ups.status", "OL CHRG"), ("battery.charge", "100"), ("input.voltage", "231.0")])
        } else {
            String::new()
        }
    }
    fn on_battery(l: &str) -> String {
        if l.starts_with("LIST VAR") {
            list(&[("ups.status", "OB DISCHRG"), ("battery.charge", "73"), ("battery.runtime", "840")])
        } else {
            String::new()
        }
    }
    fn low(l: &str) -> String {
        if l.starts_with("LIST VAR") {
            list(&[("ups.status", "OB LB"), ("battery.charge", "12")])
        } else {
            String::new()
        }
    }
    fn sparse(l: &str) -> String {
        if l.starts_with("LIST VAR") {
            list(&[("ups.status", "OL"), ("battery.charge", "lots"), ("input.voltage", "-5")])
        } else {
            String::new()
        }
    }
    fn no_status(l: &str) -> String {
        if l.starts_with("LIST VAR") { list(&[("battery.charge", "90")]) } else { String::new() }
    }
    fn garbage(_: &str) -> String {
        "hello there\n".into()
    }
    fn unknown_ups(_: &str) -> String {
        "ERR UNKNOWN-UPS\n".into()
    }
    fn stale(_: &str) -> String {
        "ERR DATA-STALE\n".into()
    }
    fn needs_auth(l: &str) -> String {
        if l.starts_with("USERNAME") { "OK\n".into() }
        else if l.starts_with("PASSWORD") { "ERR INVALID-PASSWORD\n".into() }
        else { String::new() }
    }
    fn auth_ok(l: &str) -> String {
        if l.starts_with("USERNAME") || l.starts_with("PASSWORD") { "OK\n".into() } else { on_line(l) }
    }
    fn truncated(l: &str) -> String {
        if l.starts_with("LIST VAR") { "BEGIN LIST VAR ups\nVAR ups ups.status \"OL\"\n".into() } else { String::new() }
    }

    #[test]
    fn on_line_is_read_with_where_each_figure_came_from() {
        let (r, seen) = ask(on_line, None);
        let r = r.reading().cloned().expect("measured");
        assert_eq!(r.mains, Mains::OnLine);
        assert!(!r.low_battery_flag);
        assert_eq!(r.charge_pct.as_ref().unwrap().value, 100.0);
        assert!(r.charge_pct.as_ref().unwrap().from.ends_with("battery.charge"));
        assert!(r.runtime_secs.is_none(), "a runtime the supply does not report is not measured");
        assert_eq!(seen, vec!["LIST VAR ups", "LOGOUT"], "read only, and nothing else is sent");
    }

    #[test]
    fn on_battery_and_low_battery_are_told_apart() {
        let (r, _) = ask(on_battery, None);
        let r = r.reading().cloned().unwrap();
        assert_eq!(r.mains, Mains::OnBattery);
        assert_eq!(r.runtime_secs.unwrap().value, 840);
        let (r, _) = ask(low, None);
        let r = r.reading().cloned().unwrap();
        assert_eq!((r.mains, r.low_battery_flag), (Mains::OnBattery, true));
    }

    #[test]
    fn a_figure_that_is_not_a_number_is_not_measured_and_says_so() {
        let (r, _) = ask(sparse, None);
        let r = r.reading().cloned().unwrap();
        assert!(r.charge_pct.is_none() && r.input_voltage.is_none());
        assert_eq!(r.unreadable, vec!["battery.charge", "input.voltage"]);
        let j = UpsSource::Measured(r).to_json(1000);
        assert_eq!(j["charge_pct"], "not measured");
        assert_eq!(j["runtime_secs"], "not measured");
    }

    #[test]
    fn a_status_that_is_neither_ol_nor_ob_is_unknown_not_on_line() {
        let vars = vec![("ups.status".to_string(), "CAL".to_string())];
        let r = UpsReading::from_vars(&vars, &src(1), 5).unwrap();
        assert_eq!(r.mains, Mains::Unknown);
    }

    #[test]
    fn missing_status_garbage_and_refusals_are_not_measured_with_a_reason() {
        let (r, _) = ask(no_status, None);
        assert!(matches!(r, UpsSource::NotMeasured(w) if w.contains("ups.status")));
        let (r, _) = ask(garbage, None);
        assert!(matches!(r, UpsSource::NotMeasured(w) if w.contains("did not speak NUT")));
        let (r, _) = ask(unknown_ups, None);
        assert!(matches!(r, UpsSource::NotMeasured(w) if w.contains("UNKNOWN-UPS")));
        let (r, _) = ask(stale, None);
        assert!(matches!(r, UpsSource::NotMeasured(w) if w.contains("DATA-STALE")));
        let (r, _) = ask(truncated, None);
        assert!(matches!(r, UpsSource::NotMeasured(_)));
    }

    #[test]
    fn nothing_listening_is_unreachable() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let r = query(&src(port), None, 1);
        assert!(matches!(r, UpsSource::NotMeasured(w) if w.contains("unreachable")));
    }

    #[test]
    fn a_refused_credential_is_an_auth_failure_and_a_good_one_reads() {
        let c = Credentials::parse("monitor\nsecret-pass\n").unwrap();
        let (r, _) = ask(needs_auth, Some(&c));
        assert!(matches!(r, UpsSource::NotMeasured(w) if w.contains("refused the monitor credential")));
        let (r, seen) = ask(auth_ok, Some(&c));
        assert!(r.reading().is_some());
        assert_eq!(seen[0], "USERNAME monitor");
        assert!(!format!("{c:?}").contains("secret-pass"), "Debug must not print the password");
    }

    #[test]
    fn credentials_that_could_inject_a_command_are_refused() {
        assert!(Credentials::parse("user\npass word\n").is_err());
        assert!(Credentials::parse("user\n").is_err());
        assert!(Credentials::parse("\npw\n").is_err());
        assert!(Credentials::parse("us\"er\npw\n").is_err());
    }

    #[test]
    fn a_named_credential_that_cannot_be_read_is_not_an_anonymous_read() {
        let mut cfg = UpsConfig::parse(r#"{"source":{"host":"192.0.2.9","ups":"ups","credential":"furcate.ups-monitor"}}"#).unwrap();
        assert!(matches!(fetch(&cfg, None, 1), UpsSource::NotMeasured(w) if w.contains("no credentials directory")));
        let d = std::env::temp_dir().join(format!("furcate-ups-cred-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(matches!(fetch(&cfg, Some(&d), 1), UpsSource::NotMeasured(w) if w.contains("cannot be read")));
        cfg.source.credential = None;
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn configuration_is_strict_and_a_missing_file_is_no_supply() {
        assert!(UpsConfig::parse(r#"{"source":{"host":"192.0.2.9","ups":"ups"}}"#).is_ok());
        assert!(UpsConfig::parse(r#"{"source":{"host":"192.0.2.9","ups":"bad name"}}"#).is_err());
        assert!(UpsConfig::parse(r#"{"source":{"host":"192.0.2.9","ups":"u"},"extra":1}"#).is_err());
        let p = std::env::temp_dir().join(format!("furcate-ups-none-{}", std::process::id()));
        assert_eq!(load_config(&p), Configured::None);
        std::fs::write(&p, "{").unwrap();
        assert!(matches!(load_config(&p), Configured::Invalid(_)));
        let _ = std::fs::remove_file(p);
    }
}
