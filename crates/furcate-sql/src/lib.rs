//! A small, synchronous PostgreSQL client.
//!
//! ## Why this exists rather than a crate
//!
//! Furcate's daemons are synchronous and have no async runtime. Every published
//! PostgreSQL client for Rust is built on `tokio`, so using one means adding an
//! async runtime to a binary that has none, for the sake of writing a few rows.
//! That is a large change to the shape of the process in exchange for something
//! this file does in a few hundred lines.
//!
//! It is also the shape the rest of this codebase already has: its own TPM
//! client, its own HTTP handling, its own protocol work. The wire protocol here
//! is stable, documented, and older than most of the crates that wrap it.
//!
//! ## What it does and does not do
//!
//! Simple query protocol only — no prepared statements, no binary results, no
//! pipelining, no connection pool, no `COPY`, no notifications. Values come back
//! as text, because that is what the server sends when nobody asks otherwise and
//! this is not a data plane.
//!
//! **This is a mirror writer, not a database layer.** If something starts
//! needing types, prepared statements or transactions across calls, that is the
//! signal to take the dependency rather than to grow this.
//!
//! Authentication is **SCRAM-SHA-256** (RFC 5802/7677), which is what a
//! PostgreSQL 14+ server asks for over a network. `trust` and `cleartext` are
//! also handled; **`md5` is deliberately refused** rather than implemented — a
//! server still asking for it should be reconfigured, not accommodated.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PROTOCOL_V3: i32 = 196_608;

/// Where to connect, and as whom.
#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

impl Config {
    /// Parse a `postgresql://user:password@host:port/database` URL.
    ///
    /// Percent-decoding is applied to the user and password, because a generated
    /// password may legitimately contain `@` or `/` and a URL that was assembled
    /// correctly must not be taken apart incorrectly.
    pub fn from_url(url: &str) -> Result<Config> {
        let rest = url
            .strip_prefix("postgresql://")
            .or_else(|| url.strip_prefix("postgres://"))
            .context("a connection url must start with postgresql://")?;
        // Split off ?sslmode=... and friends; this client speaks plain TCP and
        // says so rather than silently ignoring a request for TLS.
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, Some(q)),
            None => (rest, None),
        };
        if let Some(q) = query {
            for kv in q.split('&') {
                if let Some(v) = kv.strip_prefix("sslmode=") {
                    if matches!(v, "require" | "verify-ca" | "verify-full") {
                        bail!(
                            "sslmode={v} was asked for and this client speaks plain TCP only. \
                             Use a loopback or overlay address, or take a TLS-capable client."
                        );
                    }
                }
            }
        }
        let (creds, hostpart) = rest
            .rsplit_once('@')
            .context("a connection url needs user:password@host")?;
        let (user, password) = creds.split_once(':').unwrap_or((creds, ""));
        let (hostport, database) = hostpart
            .split_once('/')
            .context("a connection url needs a database name")?;
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().context("port must be a number")?),
            None => (hostport, 5432u16),
        };
        Ok(Config {
            host: host.to_string(),
            port,
            user: pct(user),
            password: pct(password),
            database: database.to_string(),
        })
    }
}

fn pct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One connection. Closed when dropped.
pub struct Client {
    sock: TcpStream,
}

/// What a query returned.
#[derive(Debug, Default)]
pub struct Rows {
    pub columns: Vec<String>,
    /// Text values. `None` is SQL NULL, which is not the same as an empty
    /// string and must not be flattened into one.
    pub rows: Vec<Vec<Option<String>>>,
}

impl Client {
    /// How long to wait for the TCP handshake.
    ///
    /// `TcpStream::connect` has **no timeout** — it waits as long as the
    /// operating system will, which for an address that does not answer is
    /// tens of seconds. A caller that treats this client as best-effort has to
    /// be able to rely on it failing quickly, or "best effort" turns into
    /// "blocks the thing that called it".
    pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

    pub fn connect(cfg: &Config) -> Result<Client> {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let resolved = addr
            .to_socket_addrs()
            .with_context(|| format!("resolving {addr}"))?
            .next()
            .with_context(|| format!("{addr} resolved to nothing"))?;
        let sock = TcpStream::connect_timeout(&resolved, Client::CONNECT_TIMEOUT)
            .with_context(|| format!("connecting to {addr}"))?;
        sock.set_read_timeout(Some(Duration::from_secs(15)))?;
        sock.set_write_timeout(Some(Duration::from_secs(15)))?;
        sock.set_nodelay(true)?;
        let mut c = Client { sock };
        c.startup(cfg)?;
        Ok(c)
    }

    pub fn connect_url(url: &str) -> Result<Client> {
        Client::connect(&Config::from_url(url)?)
    }

    // --- wire helpers ----------------------------------------------------

    fn send(&mut self, tag: u8, body: &[u8]) -> Result<()> {
        let mut m = Vec::with_capacity(body.len() + 5);
        m.push(tag);
        m.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        m.extend_from_slice(body);
        self.sock.write_all(&m)?;
        Ok(())
    }

    /// Read one backend message: its tag and its body.
    fn recv(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut head = [0u8; 5];
        self.sock.read_exact(&mut head)?;
        let len = i32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        if !(4..=1_073_741_824).contains(&len) {
            bail!("the server sent a message of implausible length {len}");
        }
        let mut body = vec![0u8; (len - 4) as usize];
        self.sock.read_exact(&mut body)?;
        Ok((head[0], body))
    }

    // --- startup and authentication --------------------------------------

    fn startup(&mut self, cfg: &Config) -> Result<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&PROTOCOL_V3.to_be_bytes());
        for (k, v) in [
            ("user", cfg.user.as_str()),
            ("database", cfg.database.as_str()),
            // Named so a connection from Furcate is identifiable in
            // pg_stat_activity. An unexplained session is a thing somebody has
            // to chase down later.
            ("application_name", "furcate"),
        ] {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        // The startup packet carries no tag, only a length.
        let mut m = Vec::with_capacity(body.len() + 4);
        m.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        m.extend_from_slice(&body);
        self.sock.write_all(&m)?;

        loop {
            let (tag, body) = self.recv()?;
            match tag {
                b'R' => {
                    let kind = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    match kind {
                        0 => continue, // authentication ok
                        3 => {
                            // cleartext
                            let mut p = cfg.password.clone().into_bytes();
                            p.push(0);
                            self.send(b'p', &p)?;
                        }
                        5 => bail!(
                            "the server asked for md5 authentication. This client does not \
                             implement it: md5 has been superseded since PostgreSQL 10 and a \
                             server still requesting it should be moved to scram-sha-256."
                        ),
                        10 => self.scram(cfg, &body[4..])?,
                        other => bail!("unsupported authentication request {other}"),
                    }
                }
                b'E' => bail!("{}", pg_error(&body)),
                b'Z' => return Ok(()), // ready for query
                // Parameter status, backend key data, notices: all fine to skip.
                b'S' | b'K' | b'N' => continue,
                other => bail!("unexpected message `{}` during startup", other as char),
            }
        }
    }

    /// SCRAM-SHA-256, RFC 5802 with the SHA-256 profile of RFC 7677.
    fn scram(&mut self, cfg: &Config, mechanisms: &[u8]) -> Result<()> {
        let offered = String::from_utf8_lossy(mechanisms);
        if !offered.contains("SCRAM-SHA-256") {
            bail!("the server offered no SCRAM-SHA-256; it advertised: {}", offered.trim_matches('\0'));
        }

        let mut raw = [0u8; 18];
        getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("no randomness for a nonce: {e}"))?;
        let nonce = data_encoding::BASE64.encode(&raw);

        // `n,,` is the GS2 header: no channel binding, no authzid. The username
        // is empty because PostgreSQL takes it from the startup packet, and
        // sending it twice is how you get an authentication failure that reads
        // like a wrong password.
        let first_bare = format!("n=,r={nonce}");
        let client_first = format!("n,,{first_bare}");

        let mut msg = Vec::new();
        msg.extend_from_slice(b"SCRAM-SHA-256\0");
        msg.extend_from_slice(&(client_first.len() as i32).to_be_bytes());
        msg.extend_from_slice(client_first.as_bytes());
        self.send(b'p', &msg)?;

        // server-first
        let (tag, body) = self.recv()?;
        if tag == b'E' {
            bail!("{}", pg_error(&body));
        }
        if tag != b'R' {
            bail!("expected a SASL continue, got `{}`", tag as char);
        }
        let server_first = String::from_utf8_lossy(&body[4..]).to_string();
        let (mut sn, mut salt_b64, mut iters) = (String::new(), String::new(), 0u32);
        for part in server_first.split(',') {
            match part.split_once('=') {
                Some(("r", v)) => sn = v.to_string(),
                Some(("s", v)) => salt_b64 = v.to_string(),
                Some(("i", v)) => iters = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        if !sn.starts_with(&nonce) {
            bail!("the server's nonce does not extend ours — refusing to continue");
        }
        if iters == 0 || iters > 1_000_000 {
            bail!("implausible SCRAM iteration count {iters}");
        }
        let salt = data_encoding::BASE64
            .decode(salt_b64.as_bytes())
            .context("the server's salt is not valid base64")?;

        let salted = pbkdf2_sha256(cfg.password.as_bytes(), &salt, iters);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);

        let final_bare = format!("c=biws,r={sn}");
        let auth_message = format!("{first_bare},{server_first},{final_bare}");
        let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(client_sig.iter()).map(|(a, b)| a ^ b).collect();
        let client_final = format!("{final_bare},p={}", data_encoding::BASE64.encode(&proof));
        self.send(b'p', client_final.as_bytes())?;

        // server-final. The server's signature is verified rather than skipped:
        // without it, anything that can complete a handshake is trusted, and
        // mutual authentication is the entire reason SCRAM exists.
        let (tag, body) = self.recv()?;
        if tag == b'E' {
            bail!("{}", pg_error(&body));
        }
        let server_final = String::from_utf8_lossy(&body[4..]).to_string();
        let v = server_final
            .split(',')
            .find_map(|p| p.strip_prefix("v="))
            .context("the server sent no signature in its final SCRAM message")?;
        let server_key = hmac_sha256(&salted, b"Server Key");
        let expect = hmac_sha256(&server_key, auth_message.as_bytes());
        let got = data_encoding::BASE64
            .decode(v.as_bytes())
            .context("the server's signature is not valid base64")?;
        if got != expect {
            bail!("the server's SCRAM signature did not verify — this is not the server it claims");
        }
        Ok(())
    }

    // --- queries ----------------------------------------------------------

    /// Run one statement and read its result.
    ///
    /// The simple query protocol allows several statements separated by `;`, and
    /// this does not stop you — but it also means a value interpolated into
    /// `sql` can end the statement and begin another. **Escape with
    /// [`literal`] rather than formatting values in raw.**
    pub fn query(&mut self, sql: &str) -> Result<Rows> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        self.send(b'Q', &body)?;

        let mut out = Rows::default();
        let mut failure: Option<String> = None;
        loop {
            let (tag, body) = self.recv()?;
            match tag {
                b'T' => {
                    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                    let mut at = 2;
                    out.columns.clear();
                    for _ in 0..n {
                        let end = body[at..].iter().position(|b| *b == 0).unwrap_or(0) + at;
                        out.columns.push(String::from_utf8_lossy(&body[at..end]).into_owned());
                        // name, then 18 bytes of table/type metadata this client
                        // does not use.
                        at = end + 1 + 18;
                    }
                }
                b'D' => {
                    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                    let mut at = 2;
                    let mut row = Vec::with_capacity(n);
                    for _ in 0..n {
                        let len = i32::from_be_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
                        at += 4;
                        if len < 0 {
                            row.push(None);
                        } else {
                            let end = at + len as usize;
                            row.push(Some(String::from_utf8_lossy(&body[at..end]).into_owned()));
                            at = end;
                        }
                    }
                    out.rows.push(row);
                }
                // Keep reading to the ready-for-query marker even after an
                // error, so the connection is left usable instead of holding a
                // half-read response that corrupts the next call.
                b'E' => failure = Some(pg_error(&body)),
                b'Z' => break,
                _ => continue,
            }
        }
        match failure {
            Some(e) => bail!("{e}"),
            None => Ok(out),
        }
    }

    /// Run a statement whose result is not wanted.
    pub fn execute(&mut self, sql: &str) -> Result<()> {
        self.query(sql).map(|_| ())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Say goodbye, so the server logs a clean disconnect rather than an
        // unexpected EOF for every connection this process ever makes.
        let _ = self.send(b'X', &[]);
    }
}

/// Quote a value for the simple query protocol.
///
/// PostgreSQL doubles a quote to escape it. `E'...'` is used when the value
/// contains a backslash, because with `standard_conforming_strings` off a
/// backslash would otherwise begin an escape.
pub fn literal(v: &str) -> String {
    if v.contains('\\') {
        format!("E'{}'", v.replace('\\', "\\\\").replace('\'', "''"))
    } else {
        format!("'{}'", v.replace('\'', "''"))
    }
}

fn pg_error(body: &[u8]) -> String {
    let mut msg = String::new();
    let mut code = String::new();
    let mut at = 0;
    while at < body.len() && body[at] != 0 {
        let field = body[at];
        let end = body[at + 1..].iter().position(|b| *b == 0).map(|p| p + at + 1).unwrap_or(body.len());
        let value = String::from_utf8_lossy(&body[at + 1..end]).into_owned();
        match field {
            b'M' => msg = value,
            b'C' => code = value,
            _ => {}
        }
        at = end + 1;
    }
    if code.is_empty() {
        msg
    } else {
        format!("{msg} (SQLSTATE {code})")
    }
}

// --- crypto ---------------------------------------------------------------

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// HMAC-SHA-256, RFC 2104.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK { sha256(key) } else { key.to_vec() };
    k.resize(BLOCK, 0);
    let mut ipad = Vec::with_capacity(BLOCK + data.len());
    let mut opad = Vec::with_capacity(BLOCK + 32);
    ipad.extend(k.iter().map(|b| b ^ 0x36));
    opad.extend(k.iter().map(|b| b ^ 0x5c));
    ipad.extend_from_slice(data);
    let inner = sha256(&ipad);
    opad.extend_from_slice(&inner);
    sha256(&opad)
}

/// PBKDF2-HMAC-SHA-256 with a 32-byte output, which is the only shape SCRAM
/// needs — so the block loop of the general algorithm collapses to one block.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &block);
    let mut out = u.clone();
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_the_published_vectors() {
        // RFC 4231 case 1.
        let got = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(got),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 case 2.
        let got = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(got),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn pbkdf2_matches_the_published_vector() {
        // RFC 7677 section 3: password "pencil", salt "W22ZaJ0SNY7soEsUEjb6gQ==", 4096.
        let salt = data_encoding::BASE64.decode(b"W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let got = pbkdf2_sha256(b"pencil", &salt, 4096);
        let key = hmac_sha256(&got, b"Client Key");
        let stored = sha256(&key);
        assert_eq!(
            data_encoding::BASE64.encode(&stored),
            "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="
        );
    }

    #[test]
    fn a_url_survives_a_password_that_contains_punctuation() {
        let c = Config::from_url("postgresql://t_x:pa%40ss%2Fword@10.0.0.1:5433/db_x").unwrap();
        assert_eq!(c.user, "t_x");
        assert_eq!(c.password, "pa@ss/word");
        assert_eq!(c.host, "10.0.0.1");
        assert_eq!(c.port, 5433);
        assert_eq!(c.database, "db_x");
    }

    #[test]
    fn a_url_asking_for_tls_is_refused_rather_than_downgraded() {
        // Silently connecting in the clear because the client cannot do better
        // is the failure worth preventing.
        let e = Config::from_url("postgresql://u:p@h/d?sslmode=require").unwrap_err();
        assert!(e.to_string().contains("plain TCP"), "{e}");
        // The permissive modes are what the provisioner emits, and mean
        // "encrypt if you can" — not a promise this client is breaking.
        assert!(Config::from_url("postgresql://u:p@h/d?sslmode=prefer").is_ok());
    }

    #[test]
    fn a_quote_cannot_end_the_statement() {
        assert_eq!(literal("it's"), "'it''s'");
        assert_eq!(literal("a\\b"), "E'a\\\\b'");
    }
}
