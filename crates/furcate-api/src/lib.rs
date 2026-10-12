//! The local API surface.
//!
//! Deliberately a small blocking HTTP/JSON server on the standard library
//! rather than an async runtime. A daemon that also controls power should have
//! as little machinery underneath it as possible, and the request rate here is
//! measured in tens per second, not tens of thousands.
//!
//! The API is the only way in. Subsystems are reached through handlers
//! registered on a [`Router`], so a caller cannot bypass policy by touching a
//! subsystem directly.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;

pub type Handler = Box<dyn Fn(&Request) -> Response + Send + Sync>;

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Value,
    /// The credential the caller presented, if any. Verified by the router
    /// before a guarded handler ever runs.
    #[doc(hidden)]
    pub credential: Option<String>,
    /// The headers the request arrived with, names as sent. Read by an
    /// [`Admission`] that decides on something the caller presented beside
    /// the body; handlers have no need of them.
    #[doc(hidden)]
    pub headers: Vec<(String, String)>,
    /// Everything after `?` in the request line, undecoded.
    ///
    /// Kept off `path` so route matching is unchanged: a route is a path, and
    /// a handler that wants an argument asks for it. Present because a
    /// certificate-permission endpoint is asked about one host at a time, and
    /// the asker puts the host in the query.
    pub query: Option<String>,
    /// The body exactly as it arrived.
    ///
    /// Kept because a signature is over what was sent, not over what a parser
    /// produced: two documents that parse the same can serialise differently,
    /// and checking a re-serialised form checks something the caller never
    /// sent.
    #[doc(hidden)]
    pub raw_body: Vec<u8>,
    /// Who this was proved to be. `None` on an open route, where nobody asked.
    ///
    /// A handler cannot construct one, and there is no way to name a principal
    /// in a request body — which is the whole point.
    pub principal: Option<furcate_authn::Principal>,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub body: Value,
    /// A non-JSON body, used instead of `body` when present.
    ///
    /// Exists for two reasons now: Prometheus exposition is a line format,
    /// not JSON, and returning it as a JSON string would need every scraper in
    /// the ecosystem to be told about this one endpoint — and the site's own
    /// front page is HTML, which a browser will not render if it is labelled
    /// as anything else.
    pub text: Option<String>,
    /// What `text` is. `None` keeps the metrics content type, which is what
    /// every existing caller of `Response::text` expects.
    pub text_type: Option<&'static str>,
    /// Extra response headers.
    ///
    /// Present because a refusal from an [`Admission`] may need to carry
    /// what the caller should present next, and a body-only refusal would
    /// tell a machine client nothing it can act on.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// The first header with this name, compared without regard to case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// One query argument, by name.
    ///
    /// Percent-decoding is deliberately limited to `%XX` and `+`: the values
    /// this reads are hostnames, and a decoder that accepted more would be
    /// accepting more than a hostname can be.
    pub fn query_param(&self, name: &str) -> Option<String> {
        let q = self.query.as_deref()?;
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=')?;
            if k != name {
                continue;
            }
            let v = v.replace('+', " ");
            let bytes = v.as_bytes();
            let mut out = Vec::with_capacity(bytes.len());
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    if let Ok(b) = u8::from_str_radix(&v[i + 1..i + 3], 16) {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                }
                out.push(bytes[i]);
                i += 1;
            }
            return String::from_utf8(out).ok();
        }
        None
    }
}

impl Response {
    pub fn ok(body: Value) -> Self {
        Self { status: 200, body, text: None, text_type: None, headers: Vec::new() }
    }

    /// A plain-text body, served as `text/plain`.
    pub fn text(body: &str) -> Self {
        Self {
            status: 200,
            body: Value::Null,
            text: Some(body.to_string()),
            text_type: None,
            headers: Vec::new(),
        }
    }

    /// An HTML page.
    ///
    /// Labelled `text/html` rather than reusing the metrics type: a browser
    /// handed a page as `text/plain` shows the markup instead of the page,
    /// which reads as a broken site rather than a mislabelled one.
    pub fn html(body: String) -> Self {
        Self {
            status: 200,
            body: Value::Null,
            text: Some(body),
            text_type: Some("text/html; charset=utf-8"),
            headers: Vec::new(),
        }
    }

    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": message.into() }),
            text: None,
            text_type: None,
            headers: Vec::new(),
        }
    }

    /// Refused because the caller lacks authority, as distinct from a bad
    /// request. Kept separate so audit logs can tell the two apart.
    pub fn refused(message: impl Into<String>) -> Self {
        Self::error(403, message)
    }
}

/// Whether a route requires a proved caller.
///
/// Declared per route rather than checked inside each handler, because a
/// handler that forgets is indistinguishable from one that decided — and the
/// forgetting is silent. The same reasoning put the policy check in the MAPE
/// path rather than in every action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Anyone who can reach the socket. Observation only: these routes report
    /// what the machine already is and change nothing.
    Open,
    /// A principal must be proved before the handler runs.
    Guarded,
    /// The route's [`Admission`] must admit the request before the handler
    /// runs. Orthogonal to `Guarded`: what an admission checks is not who the
    /// caller is.
    Admitted,
    /// The body carries its own proof, and the handler checks it: passkey
    /// assertions over a canonical order, or the public result of enrolling a
    /// credential. There is no caller for the router to establish — a person
    /// approving from a browser holds no key a request signature could be
    /// checked against, and needs none, because what is proved is the order
    /// rather than the request.
    CarriesProof,
}

/// What decides whether a request reaches an admitted route's handler.
///
/// Implemented outside this crate by whatever a route asks of its caller beyond
/// a proved identity. `Err` carries the response the caller gets instead of the
/// handler's.
pub trait Admission: Send + Sync + 'static {
    fn admit(&self, req: &Request) -> Result<(), Response>;
}

#[derive(Default)]
pub struct Router {
    routes: BTreeMap<(String, String), (Handler, Access)>,
    verifier: Option<std::sync::Arc<dyn furcate_authn::Verifier>>,
    /// What admits a request to each admitted route. Held beside the route
    /// rather than inside the handler so the router can refuse without
    /// running it.
    admissions: BTreeMap<(String, String), Arc<dyn Admission>>,
    /// Routes whose body carries its own proof and that still act: an
    /// approved order rather than a reading. Held to the origin check as a
    /// guarded route is.
    orders: std::collections::BTreeSet<(String, String)>,
    /// Who may originate a privileged call, judged from where the connection
    /// came from and who the credential proved. See [`Router::originating`].
    origin: Option<OriginCheck>,
}

/// Whether a privileged call may come from this origin: the address the
/// connection arrived from, if known, and the principal its credential
/// proved, if it presented one. `Err` carries the reason it may not.
pub type OriginCheck = Arc<
    dyn Fn(Option<std::net::IpAddr>, Option<&furcate_authn::Principal>) -> Result<(), String>
        + Send
        + Sync,
>;

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// An open route: observation, changing nothing.
    pub fn route(
        self,
        method: &str,
        path: &str,
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.route_with(method, path, Access::Open, handler)
    }

    /// A route that requires a proved caller.
    pub fn guarded(
        self,
        method: &str,
        path: &str,
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.route_with(method, path, Access::Guarded, handler)
    }

    /// A route the handler of which runs only once `admission` admits the
    /// request. A refusal is answered with the response the admission gives.
    pub fn admitted(
        mut self,
        method: &str,
        path: &str,
        admission: impl Admission,
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.admissions.insert((method.to_uppercase(), path.to_string()), Arc::new(admission));
        self.route_with(method, path, Access::Admitted, handler)
    }

    /// A route whose body carries its own proof. See [`Access::CarriesProof`].
    pub fn carrying_proof(
        self,
        method: &str,
        path: &str,
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.route_with(method, path, Access::CarriesProof, handler)
    }

    /// A route whose body carries its own proof and that acts: an approved
    /// order. Checked as [`Router::carrying_proof`] is, and its origin as a
    /// guarded route's is.
    pub fn carrying_order(
        mut self,
        method: &str,
        path: &str,
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.orders.insert((method.to_uppercase(), path.to_string()));
        self.route_with(method, path, Access::CarriesProof, handler)
    }

    /// Who may originate a privileged call, asked of every guarded route
    /// once its caller is proved and of every order route before it runs.
    ///
    /// A proved credential says who signed. It does not say the machine that
    /// signed may act, and a member admitted only to carry readings must not
    /// become the origin of a privileged call by holding a key.
    pub fn originating(mut self, check: OriginCheck) -> Self {
        self.origin = Some(check);
        self
    }

    /// The order routes, for the same reason as `guarded_paths`.
    pub fn order_paths(&self) -> Vec<String> {
        self.orders.iter().map(|(m, p)| format!("{m} {p}")).collect()
    }

    pub fn route_with(
        mut self,
        method: &str,
        path: &str,
        access: Access,
        handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.routes.insert(
            (method.to_uppercase(), path.to_string()),
            (Box::new(handler), access),
        );
        self
    }

    /// Who this router believes. Without one, every guarded route refuses —
    /// which is the correct state for a machine that cannot recognise anyone.
    pub fn verified_by(mut self, v: std::sync::Arc<dyn furcate_authn::Verifier>) -> Self {
        self.verifier = Some(v);
        self
    }

    /// The guarded routes, so a test can assert what is protected rather than
    /// trusting that whoever added the last one remembered.
    pub fn guarded_paths(&self) -> Vec<String> {
        self.routes
            .iter()
            .filter(|(_, (_, a))| *a == Access::Guarded)
            .map(|((m, p), _)| format!("{m} {p}"))
            .collect()
    }

    /// The admitted routes, for the same reason `guarded_paths` exists: a test
    /// should be able to assert which routes an admission stands in front of.
    pub fn admitted_paths(&self) -> Vec<String> {
        self.routes
            .iter()
            .filter(|(_, (_, a))| *a == Access::Admitted)
            .map(|((m, p), _)| format!("{m} {p}"))
            .collect()
    }

    /// The routes that check a proof carried in the body, so a test can assert
    /// that nothing else was registered that way.
    pub fn proof_paths(&self) -> Vec<String> {
        self.routes
            .iter()
            .filter(|(_, (_, a))| *a == Access::CarriesProof)
            .map(|((m, p), _)| format!("{m} {p}"))
            .collect()
    }

    pub fn paths(&self) -> Vec<String> {
        self.routes
            .keys()
            .map(|(m, p)| format!("{m} {p}"))
            .collect()
    }

    pub fn dispatch(&self, req: &Request) -> Response {
        self.dispatch_from(req, None, now_s())
    }

    /// Dispatch at a given time, so the guard can be tested without waiting.
    pub fn dispatch_at(&self, req: &Request, now: u64) -> Response {
        self.dispatch_from(req, None, now)
    }

    /// Dispatch a request that arrived from `from`.
    pub fn dispatch_from(&self, req: &Request, from: Option<std::net::IpAddr>, now: u64) -> Response {
        let key = (req.method.to_uppercase(), req.path.clone());
        let Some((handler, access)) = self.routes.get(&key) else {
            return Response::error(404, format!("no route for {} {}", req.method, req.path));
        };

        if *access == Access::CarriesProof && self.orders.contains(&key) {
            if let Err(why) = self.origin_allows(from, None) {
                return Response::refused(why);
            }
        }

        if *access == Access::Open || *access == Access::CarriesProof {
            return handler(req);
        }

        if *access == Access::Admitted {
            // A route marked admitted with nothing to admit it is a
            // configuration error, and serving it unchecked is the wrong way
            // to resolve one.
            let Some(admission) = self.admissions.get(&key) else {
                return Response::error(
                    500,
                    "this route is marked admitted but has nothing to admit a request",
                );
            };
            if let Err(refusal) = admission.admit(req) {
                return refusal;
            }
            return handler(req);
        }

        // Guarded. An unauthenticated caller is not a caller with fewer rights;
        // it is not a caller, and the handler never runs.
        let Some(v) = &self.verifier else {
            return Response::refused(
                "this machine cannot recognise anyone, so it will not act on anyone's \
                 word; enrol an operator key first",
            );
        };
        let presented = furcate_authn::Presented {
            method: req.method.clone(),
            path: req.path.clone(),
            body: req.raw_body.clone(),
            credential: req.credential.clone(),
        };
        match v.verify(&presented, now) {
            Ok(principal) => {
                if let Err(why) = self.origin_allows(from, Some(&principal)) {
                    return Response::refused(why);
                }
                let mut req = req.clone();
                req.principal = Some(principal);
                handler(&req)
            }
            Err(r) => {
                let mut res = Response::refused(r.because);
                res.body["structural"] = Value::Bool(r.structural);
                res
            }
        }
    }
}

impl Router {
    fn origin_allows(
        &self,
        from: Option<std::net::IpAddr>,
        principal: Option<&furcate_authn::Principal>,
    ) -> Result<(), String> {
        match &self.origin {
            Some(check) => check(from, principal),
            None => Ok(()),
        }
    }
}

/// Parse a request from a stream.
///
/// Bodies are bounded: an unbounded read on a socket is a denial of service
/// waiting to happen, and nothing this API accepts is large.
pub const MAX_BODY: usize = 256 * 1024;

/// The most headers a request keeps. Past this they are read and dropped, so a
/// caller cannot grow a request without bound by sending more of them.
pub const MAX_HEADERS: usize = 64;

pub fn parse_request(stream: &mut impl Read) -> Option<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let raw_path = parts.next()?.to_string();
    let path = raw_path.split('?').next().unwrap_or(&raw_path).to_string();

    let mut content_length = 0usize;
    // The credential rides in a header rather than the body, so it is not part
    // of what it signs over and a handler cannot mistake it for input.
    let mut credential: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
            if name.eq_ignore_ascii_case("x-furcate-credential") {
                credential = Some(value.trim().to_string());
            }
            if headers.len() < MAX_HEADERS {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
    }

    let raw_body = if content_length == 0 {
        Vec::new()
    } else {
        let capped = content_length.min(MAX_BODY);
        let mut buf = vec![0u8; capped];
        reader.read_exact(&mut buf).ok()?;
        buf
    };
    let body = if raw_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&raw_body).unwrap_or(Value::Null)
    };

    let query = raw_path.split_once('?').map(|(_, q)| q.to_string());
    Some(Request { method, path, query, body, credential, headers, raw_body, principal: None })
}

fn write_response(stream: &mut TcpStream, response: &Response) {
    let (body, content_type) = match &response.text {
        // Prometheus scrapers require the version marker in the content type.
        Some(t) => (
            t.clone().into_bytes(),
            response
                .text_type
                .unwrap_or("text/plain; version=0.0.4; charset=utf-8"),
        ),
        None => (
            serde_json::to_vec_pretty(&response.body).unwrap_or_default(),
            "application/json",
        ),
    };
    let extra: String = response
        .headers
        .iter()
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .collect();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        match response.status {
            200 => "OK",
            400 => "Bad Request",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Error",
        },
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

/// Tell the service manager the socket is up, if one is listening.
///
/// This exists because of a specific way the site controller lied. It unseals
/// its verifier key from the TPM before it binds, which on the hardware here
/// takes about 47 seconds — and for those 47 seconds `systemctl is-active`
/// answered `active` while every request was refused. An operator watching a
/// restart saw a healthy unit and an unreachable service and had nothing to
/// connect the two.
///
/// With `Type=notify`, systemd holds the unit in `activating` until this line
/// runs, so the state it reports is the state the socket is in. Ordering
/// (`After=`) on other units becomes true rather than approximately true.
///
/// The protocol is one datagram to the socket named in `$NOTIFY_SOCKET`, so it
/// is written here directly rather than through a crate. A leading `@` means
/// the abstract namespace, which Rust spells as a leading NUL.
///
/// Absence of the variable is the normal case — run from a shell, there is
/// nobody to tell — so every failure here is silent by design. A daemon that
/// refused to serve because it could not find its service manager would be
/// worse than one that serves quietly.
fn notify_ready() {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    let addr = if let Some(rest) = path.strip_prefix('@') {
        format!("\0{rest}")
    } else {
        path
    };
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(b"READY=1\n", &addr);
    }
}

/// Serve until the process is stopped.
///
/// Each connection is handled on its own thread. With a handful of nodes and
/// an operator CLI as the only clients, a thread per connection costs less
/// than the complexity of avoiding it.
pub fn serve(addr: impl ToSocketAddrs, router: Router) -> std::io::Result<()> {
    serve_also(addr, &[], router)
}

/// The addresses in a `*_LISTEN_ALSO` setting: comma-separated, blanks dropped.
///
/// One reader for every daemon that takes further addresses, so furcated and
/// the site controller cannot come to disagree about what the same setting
/// means. An address listed twice, or repeating the primary, is the
/// operator's to fix; binding it again fails and is logged.
pub fn listen_also(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect()
}

/// How long an extra address waits before trying to bind again.
const RETRY_EXTRA: std::time::Duration = std::time::Duration::from_secs(30);

/// Serve on `addr`, and on each of `also` with the same routes.
///
/// `addr` is the one that matters: if it cannot be bound, this returns the
/// error and nothing is served. The others are only further ways in, such as
/// an overlay interface, and that interface may come up after the daemon
/// does. So an extra address that cannot be bound is reported and tried again
/// on its own thread, and never holds up or stops the primary.
pub fn serve_also(
    addr: impl ToSocketAddrs,
    also: &[String],
    router: Router,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    notify_ready();
    serve_on(listener, also, Arc::new(router), RETRY_EXTRA);
    Ok(())
}

fn serve_on(
    listener: TcpListener,
    also: &[String],
    router: Arc<Router>,
    retry: std::time::Duration,
) {
    for extra in also {
        listen_when_possible(extra.clone(), Arc::clone(&router), retry);
    }
    accept(listener, router);
}

/// Bind `addr` on a thread of its own, retrying until it succeeds.
///
/// The reason is logged when it first fails and again whenever it changes,
/// rather than every attempt: an interface that stays down should leave one
/// line in the journal, not one every thirty seconds.
fn listen_when_possible(
    addr: String,
    router: Arc<Router>,
    retry: std::time::Duration,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last = String::new();
        loop {
            match TcpListener::bind(addr.as_str()) {
                Ok(listener) => {
                    eprintln!("furcate-api: also listening on {addr}");
                    accept(listener, router);
                    return;
                }
                Err(e) => {
                    let reason = e.to_string();
                    if reason != last {
                        eprintln!(
                            "furcate-api: cannot listen on {addr}: {reason}; trying again every {}s",
                            retry.as_secs().max(1)
                        );
                        last = reason;
                    }
                    std::thread::sleep(retry);
                }
            }
        }
    })
}

fn accept(listener: TcpListener, router: Arc<Router>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let router = Arc::clone(&router);
        std::thread::spawn(move || {
            let from = stream.peer_addr().ok().map(|a| a.ip());
            let response = match parse_request(&mut stream) {
                Some(req) => router.dispatch_from(&req, from, now_s()),
                None => Response::error(400, "malformed request"),
            };
            write_response(&mut stream, &response);
        });
    }
}


/// A minimal blocking JSON POST client.
///
/// Enough for a node to report to its site controller and no more. A daemon
/// that controls power should not carry a general-purpose HTTP stack it does
/// not need.
/// Fetch JSON over GET.
///
/// The read half of the same tiny client. Most of what this system exposes is
/// observation, and until now every reader had to POST to it.
/// Open a connection, giving the handshake the same deadline as the exchange.
///
/// `TcpStream::connect` has **no timeout**: `set_read_timeout` applies only
/// once a connection exists, so a caller passing `timeout_ms` gets it honoured
/// for the reply and not for the connect. Against a host that refuses, that is
/// invisible — the RST arrives at once. Against one that is simply gone, the
/// kernel retries the SYN on its own schedule (`tcp_syn_retries`, ~127s by
/// default) and the call blocks for two minutes per request while the caller
/// believes it asked for four seconds.
///
/// That is not theoretical: it made the fleet poller take ~255s per pass
/// against a 30s cadence, and since the pass was slower than the 120s
/// staleness threshold, every node was reported stale no matter how healthy —
/// one unplugged machine blanking the view of every other one.
fn connect_by(addr: &str, timeout_ms: u64) -> std::io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    let resolved = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("{addr} resolved to nothing")))?;
    std::net::TcpStream::connect_timeout(&resolved, std::time::Duration::from_millis(timeout_ms))
}

pub fn get_json(addr: &str, path: &str, timeout_ms: u64) -> std::io::Result<Value> {
    get_signed(addr, path, timeout_ms, None)
}

/// GET, optionally proving who is asking.
///
/// A guarded GET is checked the same way a guarded POST is: the credential
/// signs the method, the route and the body. A GET has no body, and the route
/// is the path without its query, because that is what the router matches and
/// verifies against.
pub fn get_signed(
    addr: &str,
    path: &str,
    timeout_ms: u64,
    credentialler: Option<Credentialler<'_>>,
) -> std::io::Result<Value> {
    use std::io::Write as _;
    use std::time::Duration;

    let mut stream = connect_by(addr, timeout_ms)?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let route = path.split_once('?').map_or(path, |(r, _)| r);
    let credential = credentialler
        .map(|f| f("GET", route, &[]))
        .map(|c| format!("X-Furcate-Credential: {c}\r\n"))
        .unwrap_or_default();
    let head = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{credential}Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut raw)?;
    let body = http_body(&raw);
    let body = body.as_str();
    Ok(serde_json::from_str(body).unwrap_or(Value::Null))
}

pub fn post_json(addr: &str, path: &str, body: &Value, timeout_ms: u64) -> std::io::Result<Value> {
    post_signed(addr, path, body, timeout_ms, None)
}

/// Anything that can produce a credential for a request about to be sent.
///
/// Takes the payload rather than returning a fixed string, because a signature
/// covers the bytes that go on the wire. A caller cannot build the credential
/// before the body is serialised, and serialising twice risks signing something
/// other than what is sent.
pub type Credentialler<'a> = &'a dyn Fn(&str, &str, &[u8]) -> String;

/// POST, optionally proving who is asking.
///
/// The signature is over the bytes actually sent, which is why the payload is
/// serialised once and both signed and written. Signing a re-serialised form
/// would check something the machine on the other end never received.
/// The body of an HTTP reply, decoding `Transfer-Encoding: chunked`.
///
/// This client splits headers from body on the blank line and parsed whatever
/// followed as JSON. That is right for a reply with a Content-Length and wrong
/// for a chunked one, where the body is a sequence of `<hex size>\r\n<bytes>`
/// frames: the size lines land inside what is handed to the parser, it fails,
/// and the caller is told the server returned nothing.
///
/// llama.cpp answers chunked, so a node asking another node to reason got
/// "runtime returned no content: null" from a server that had in fact
/// answered — the content was in the reply the whole time, behind two hex
/// digits.
fn http_body(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let Some(split) = text.find("\r\n\r\n") else {
        return String::new();
    };
    let head = &text[..split];
    let body = &text[split + 4..];

    let chunked = head
        .lines()
        .any(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("transfer-encoding:") && l.contains("chunked")
        });
    if !chunked {
        return body.to_string();
    }

    // Reassemble the frames. A malformed length ends the body rather than
    // aborting: a partial answer is more useful to a caller than none, and the
    // JSON parse downstream is what decides whether it was enough.
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    loop {
        let Some(eol) = rest.find("\r\n") else { break };
        let size = match usize::from_str_radix(rest[..eol].trim(), 16) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let start = eol + 2;
        let end = start + size;
        if end > rest.len() {
            out.push_str(&rest[start..]);
            break;
        }
        out.push_str(&rest[start..end]);
        // Skip the CRLF that terminates the frame.
        rest = &rest[(end + 2).min(rest.len())..];
    }
    out
}

/// POST JSON with an `Authorization: Bearer` header.
///
/// Separate from `post_signed` because the two carry different kinds of proof
/// to different kinds of listener. `X-Furcate-Credential` is a signature over
/// the bytes, checked by this system's own router. A bearer token is what an
/// OpenAI-compatible model server understands, and such a server knows nothing
/// about Furcate signatures -- sending it one gets a 401 and a control loop
/// that quietly loses its reasoner.
pub fn post_bearer(
    addr: &str,
    path: &str,
    body: &Value,
    timeout_ms: u64,
    token: Option<Credentialler<'_>>,
) -> std::io::Result<Value> {
    use std::io::Write as _;
    use std::time::Duration;

    let mut stream = connect_by(addr, timeout_ms)?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let payload = serde_json::to_vec(body).unwrap_or_default();
    let auth = token
        .map(|f| f("POST", path, &payload))
        .filter(|t| !t.is_empty())
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;

    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut raw)?;
    let body = http_body(&raw);
    let body = body.as_str();
    Ok(serde_json::from_str(body).unwrap_or(Value::Null))
}

pub fn post_signed(
    addr: &str,
    path: &str,
    body: &Value,
    timeout_ms: u64,
    credentialler: Option<Credentialler<'_>>,
) -> std::io::Result<Value> {
    use std::io::Write as _;
    use std::time::Duration;

    let mut stream = connect_by(addr, timeout_ms)?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let payload = serde_json::to_vec(body).unwrap_or_default();
    let credential = credentialler
        .map(|f| f("POST", path, &payload))
        .map(|c| format!("X-Furcate-Credential: {c}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{credential}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;

    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut raw)?;
    // Split headers from body; a malformed reply yields Null rather than an
    // error, because a controller being briefly odd must not crash a node.
    let body = http_body(&raw);
    let body = body.as_str();
    Ok(serde_json::from_str(body).unwrap_or(Value::Null))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        Router::new()
            .route("GET", "/healthz", |_| Response::ok(json!({"ok": true})))
            .route("POST", "/kill", |_| {
                Response::refused("only the operator may kill")
            })
    }

    fn request(method: &str, path: &str) -> Request {
        Request {
            query: None,
            method: method.into(),
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_registered_route_dispatches() {
        let r = router().dispatch(&request("GET", "/healthz"));
        assert_eq!(r.status, 200);
    }

    #[test]
    fn an_unknown_route_is_a_404_not_a_panic() {
        let r = router().dispatch(&request("GET", "/nope"));
        assert_eq!(r.status, 404);
    }

    #[test]
    fn method_is_part_of_the_route() {
        assert_eq!(router().dispatch(&request("POST", "/healthz")).status, 404);
    }

    #[test]
    fn methods_are_matched_case_insensitively() {
        assert_eq!(router().dispatch(&request("get", "/healthz")).status, 200);
    }

    #[test]
    fn refusal_is_distinguishable_from_a_bad_request() {
        let r = router().dispatch(&request("POST", "/kill"));
        assert_eq!(r.status, 403);
        assert_eq!(
            r.body["error"].as_str().unwrap(),
            "only the operator may kill"
        );
    }

    #[test]
    fn a_query_argument_is_readable_without_becoming_part_of_the_route() {
        let mut r = std::io::Cursor::new(
            "GET /tls/allow?domain=furcate.xyz HTTP/1.1\r\n\r\n".as_bytes().to_vec(),
        );
        let req = parse_request(&mut r).expect("parses");
        // The route is still the path: matching must not change because a
        // caller appended an argument.
        assert_eq!(req.path, "/tls/allow");
        assert_eq!(req.query_param("domain").as_deref(), Some("furcate.xyz"));
        assert_eq!(req.query_param("other"), None);
    }

    #[test]
    fn a_percent_encoded_hostname_comes_back_decoded() {
        // The asker encodes; a comparison against a deployed domain has to be
        // made on the decoded form or an encoded name would never match and
        // certificates would silently never issue.
        let mut r = std::io::Cursor::new(
            "GET /tls/allow?domain=a%2Db.example.com&x=1 HTTP/1.1\r\n\r\n".as_bytes().to_vec(),
        );
        let req = parse_request(&mut r).expect("parses");
        assert_eq!(req.query_param("domain").as_deref(), Some("a-b.example.com"));
    }

    #[test]
    fn a_request_with_no_query_has_none_rather_than_an_empty_string() {
        let mut r = std::io::Cursor::new("GET /healthz HTTP/1.1\r\n\r\n".as_bytes().to_vec());
        let req = parse_request(&mut r).expect("parses");
        assert!(req.query.is_none());
        assert_eq!(req.query_param("domain"), None);
    }

    #[test]
    fn a_query_string_does_not_break_matching() {
        let mut raw = std::io::Cursor::new(b"GET /healthz?verbose=1 HTTP/1.1\r\n\r\n".to_vec());
        let req = parse_request(&mut raw).unwrap();
        assert_eq!(req.path, "/healthz");
    }

    #[test]
    fn a_json_body_is_parsed() {
        let payload = b"POST /x HTTP/1.1\r\nContent-Length: 14\r\n\r\n{\"nonce\":\"ab\"}";
        let mut raw = std::io::Cursor::new(payload.to_vec());
        let req = parse_request(&mut raw).unwrap();
        assert_eq!(req.body["nonce"], "ab");
    }

    #[test]
    fn a_malformed_body_becomes_null_rather_than_failing_the_request() {
        let payload = b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nnot";
        let mut raw = std::io::Cursor::new(payload.to_vec());
        let req = parse_request(&mut raw).unwrap();
        assert_eq!(req.body, Value::Null);
    }

    #[test]
    fn an_oversized_content_length_is_capped() {
        // A header claiming gigabytes must not cause a gigabyte allocation.
        let payload = b"POST /x HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n{}";
        let mut raw = std::io::Cursor::new(payload.to_vec());
        // Read fails cleanly because the body is shorter than claimed.
        assert!(parse_request(&mut raw).is_none());
    }

    #[test]
    fn routes_are_enumerable_for_discovery() {
        let paths = router().paths();
        assert!(paths.contains(&"GET /healthz".to_string()));
    }

    /// A loopback address with nothing on it, found by binding and letting go.
    fn free_addr() -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    }

    /// Ask until it answers or `ms` runs out.
    fn healthz_within(addr: &str, ms: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            if let Ok(v) = get_json(addr, "/healthz", 500) {
                if v["ok"] == json!(true) {
                    return true;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    fn start(also: Vec<String>, retry_ms: u64) -> String {
        let primary = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = primary.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            serve_on(
                primary,
                &also,
                Arc::new(router()),
                std::time::Duration::from_millis(retry_ms),
            )
        });
        addr
    }

    #[test]
    fn listen_also_is_a_comma_separated_list() {
        assert!(listen_also("").is_empty());
        assert_eq!(
            listen_also(" 10.90.0.20:7616, ,[fd00::20]:7616,"),
            vec!["10.90.0.20:7616".to_string(), "[fd00::20]:7616".to_string()]
        );
    }

    #[test]
    fn a_signed_get_carries_a_credential_over_the_route_without_its_query() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let echo = Router::new().route("GET", "/cells/standing", |req: &Request| {
            Response::ok(json!({ "credential": req.credential, "query": req.query }))
        });
        std::thread::spawn(move || accept(listener, Arc::new(echo)));
        let seen = std::sync::Mutex::new(Vec::new());
        let sign = |m: &str, p: &str, b: &[u8]| {
            seen.lock().unwrap().push((m.to_string(), p.to_string(), b.len()));
            "furcate-test-credential".to_string()
        };
        let v = get_signed(&addr, "/cells/standing?x=1", 3_000, Some(&sign)).unwrap();
        assert_eq!(v["credential"], json!("furcate-test-credential"));
        assert_eq!(v["query"], json!("x=1"));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![("GET".to_string(), "/cells/standing".to_string(), 0)]
        );
        let plain = get_json(&addr, "/cells/standing", 3_000).unwrap();
        assert_eq!(plain["credential"], Value::Null);
    }

    #[test]
    fn an_extra_address_serves_the_same_routes() {
        let extra = free_addr();
        let primary = start(vec![extra.clone()], 50);
        assert!(healthz_within(&primary, 3000));
        assert!(healthz_within(&extra, 3000));
    }

    #[test]
    fn an_extra_address_that_cannot_be_bound_leaves_the_primary_serving() {
        // TEST-NET-1: never assigned to this machine, so binding it fails.
        let primary = start(vec!["192.0.2.1:7616".into(), "not an address".into()], 50);
        assert!(healthz_within(&primary, 3000));
    }

    #[test]
    fn an_extra_address_is_taken_once_it_becomes_available() {
        let holder = TcpListener::bind("127.0.0.1:0").unwrap();
        let extra = holder.local_addr().unwrap().to_string();
        let primary = start(vec![extra.clone()], 50);
        assert!(healthz_within(&primary, 3000));
        // Held by someone else, so the first attempts fail.
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(holder);
        assert!(healthz_within(&extra, 5000));
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use furcate_authn::local::{sign, Signer};
    use furcate_authn::LocalVerifier;
    use std::sync::Arc;

    fn key() -> furcate_authn::SigningKey {
        furcate_authn::SigningKey::from_bytes(&[3u8; 32])
    }

    fn router_with_guard() -> Router {
        Router::new()
            .route("GET", "/healthz", |_| Response::ok(json!({"ok": true})))
            .guarded("POST", "/act", |req| {
                // A guarded handler always has one; the router cannot reach it
                // otherwise.
                Response::ok(json!({"who": req.principal.as_ref().map(|p| p.id.clone())}))
            })
            .verified_by(Arc::new(LocalVerifier::new(Some(key().verifying_key()))))
    }

    fn signed(path: &str, body: &[u8], nonce: &str) -> Request {
        Request {
            query: None,
            method: "POST".into(),
            path: path.into(),
            body: serde_json::from_slice(body).unwrap_or(Value::Null),
            raw_body: body.to_vec(),
            credential: Some(sign(&key(), "POST", path, body, nonce, 100)),
            headers: Vec::new(),
            principal: None,
        }
    }

    #[test]
    fn an_origin_that_may_not_act_is_refused_on_guarded_and_order_routes_only() {
        let pi: std::net::IpAddr = "10.90.0.30".parse().unwrap();
        let other: std::net::IpAddr = "10.90.0.10".parse().unwrap();
        let r = router_with_guard()
            .carrying_order("POST", "/orders", |_| Response::ok(json!({"ran": "order"})))
            .carrying_proof("POST", "/rollup", |_| Response::ok(json!({"ran": "rollup"})))
            .originating(Arc::new(move |from, _| {
                if from == Some(pi) { Err("pi is a device-tier member".into()) } else { Ok(()) }
            }));
        assert_eq!(r.order_paths(), vec!["POST /orders".to_string()]);

        // Proved, and still refused: the key is not the question.
        let res = r.dispatch_from(&signed("/act", b"{}", "n1"), Some(pi), 50);
        assert_eq!(res.status, 403);
        assert!(res.body.to_string().contains("device-tier"), "{}", res.body);
        assert_eq!(r.dispatch_from(&signed("/act", b"{}", "n2"), Some(other), 50).status, 200);

        let post = |path: &str| Request { method: "POST".into(), path: path.into(), ..Default::default() };
        assert_eq!(r.dispatch_from(&post("/orders"), Some(pi), 50).status, 403);
        assert_eq!(r.dispatch_from(&post("/orders"), Some(other), 50).status, 200);
        // Roll-ups and readings are what such a member is for.
        assert_eq!(r.dispatch_from(&post("/rollup"), Some(pi), 50).status, 200);
        let get = Request { method: "GET".into(), path: "/healthz".into(), ..Default::default() };
        assert_eq!(r.dispatch_from(&get, Some(pi), 50).status, 200);
    }

    #[test]
    fn a_guarded_route_refuses_a_caller_that_proved_nothing() {
        // The hole this closes: the handler used to run and read the caller's
        // own claim about who it was out of the request body.
        let r = router_with_guard();
        let req = Request { method: "POST".into(), path: "/act".into(), ..Default::default() };
        assert_eq!(r.dispatch_at(&req, 50).status, 403);
    }

    #[test]
    fn a_guarded_route_runs_for_a_proved_caller_and_hands_it_the_principal() {
        let r = router_with_guard();
        let res = r.dispatch_at(&signed("/act", b"{}", "n1"), 50);
        assert_eq!(res.status, 200);
        assert_eq!(res.body["who"], json!("operator"));
    }

    #[test]
    fn an_open_route_is_still_open() {
        // Observation changes nothing and must not need a credential, or the
        // console cannot draw a screen.
        let r = router_with_guard();
        let req = Request { method: "GET".into(), path: "/healthz".into(), ..Default::default() };
        assert_eq!(r.dispatch_at(&req, 50).status, 200);
    }

    #[test]
    fn a_router_that_cannot_recognise_anyone_refuses_every_guarded_route() {
        // Correct failure, not an open door: a machine that invented its own
        // authority when it had no key would defeat the whole guarantee.
        let r = Router::new()
            .guarded("POST", "/act", |_| Response::ok(json!({"ran": true})))
            .verified_by(Arc::new(LocalVerifier::new(None)));
        let res = r.dispatch_at(&signed("/act", b"{}", "n1"), 50);
        assert_eq!(res.status, 403);
        assert_eq!(res.body["structural"], json!(true), "no credential could have worked");
    }

    #[test]
    fn a_router_with_no_verifier_at_all_refuses_rather_than_defaults_open() {
        let r = Router::new().guarded("POST", "/act", |_| Response::ok(json!({"ran": true})));
        assert_eq!(r.dispatch_at(&signed("/act", b"{}", "n1"), 50).status, 403);
    }

    #[test]
    fn a_signature_for_one_route_does_not_open_another() {
        let r = Router::new()
            .guarded("POST", "/act", |_| Response::ok(json!({"ran": "act"})))
            .guarded("POST", "/other", |_| Response::ok(json!({"ran": "other"})))
            .verified_by(Arc::new(LocalVerifier::new(Some(key().verifying_key()))));
        let mut req = signed("/act", b"{}", "n1");
        req.path = "/other".into();
        assert_eq!(r.dispatch_at(&req, 50).status, 403);
    }

    #[test]
    fn the_signature_covers_the_bytes_that_arrived_not_the_reparsed_body() {
        // Two documents that parse the same can serialise differently, so a
        // signature checked against a re-serialised body checks something the
        // caller never sent.
        let r = router_with_guard();
        let mut req = signed("/act", br#"{"a":1}"#, "n1");
        // Same meaning, different bytes.
        req.raw_body = br#"{ "a" : 1 }"#.to_vec();
        assert_eq!(r.dispatch_at(&req, 50).status, 403);
    }

    #[test]
    fn the_guarded_set_is_enumerable_so_a_test_can_assert_what_is_protected() {
        // Rather than trusting that whoever adds the next mutating route
        // remembers to guard it.
        let r = router_with_guard();
        assert_eq!(r.guarded_paths(), vec!["POST /act".to_string()]);
        assert_eq!(r.paths().len(), 2, "both routes still dispatch");
    }

    #[test]
    fn the_signer_and_the_verifier_agree() {
        // The two halves of the protocol, exercised together. They fail closed
        // and silently when they disagree — the signature is simply never
        // valid, and nothing in the message says why.
        let s = Signer::new(key());
        let body = br#"{"id":"x"}"#;
        let cred = s.credential("POST", "/act", body, 40);
        let req = Request {
            query: None,
            method: "POST".into(),
            path: "/act".into(),
            body: serde_json::from_slice(body).unwrap(),
            raw_body: body.to_vec(),
            credential: Some(cred),
            headers: Vec::new(),
            principal: None,
        };
        assert_eq!(router_with_guard().dispatch_at(&req, 41).status, 200);
    }

    #[test]
    fn two_credentials_made_in_the_same_second_are_still_distinct() {
        // A nonce that collided would make the second request look like a
        // replay of the first, and the operator would see a refusal they could
        // not explain.
        let s = Signer::new(key());
        let a = s.credential("POST", "/act", b"{}", 40);
        let b = s.credential("POST", "/act", b"{}", 40);
        assert_ne!(a, b);
    }
}

pub mod custody;
pub mod orders;

#[cfg(test)]
mod admitted_route_tests {
    use super::*;

    struct NeedsHeader;

    impl Admission for NeedsHeader {
        fn admit(&self, req: &Request) -> Result<(), Response> {
            match req.header("x-ticket") {
                Some("ok") => Ok(()),
                _ => Err(Response::refused("no ticket")),
            }
        }
    }

    fn router() -> Router {
        Router::new().admitted("POST", "/work", NeedsHeader, |_| Response::ok(json!({"served": true})))
    }

    fn req(ticket: Option<&str>) -> Request {
        Request {
            method: "POST".into(),
            path: "/work".into(),
            headers: ticket.map(|t| vec![("X-Ticket".to_string(), t.to_string())]).unwrap_or_default(),
            ..Default::default()
        }
    }

    #[test]
    fn an_admitted_route_answers_with_the_refusal_when_not_admitted() {
        assert_eq!(router().dispatch_at(&req(None), 100).status, 403);
        assert_eq!(router().dispatch_at(&req(Some("bad")), 100).status, 403);
    }

    #[test]
    fn an_admitted_route_runs_its_handler_once_admitted() {
        let r = router().dispatch_at(&req(Some("ok")), 100);
        assert_eq!(r.status, 200, "{:?}", r.body);
    }

    #[test]
    fn admitted_routes_are_enumerable_and_not_also_guarded() {
        assert_eq!(router().admitted_paths(), vec!["POST /work".to_string()]);
        assert!(router().guarded_paths().is_empty());
    }
}

#[cfg(test)]
mod connect_timeout_tests {
    /// A host that never answers must cost the timeout that was asked for.
    ///
    /// 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation and
    /// routed nowhere, so the SYN is dropped rather than refused. That is the
    /// case this guards — a refused connection returns instantly and would pass
    /// even against the bug, whereas a dropped one exposes it, because the
    /// kernel's own retry schedule takes about two minutes.
    ///
    /// Asserted as an upper bound and not an equality: what matters is that the
    /// caller's deadline is the one in force, not the operating system's.
    #[test]
    fn an_address_that_never_answers_gives_up_when_told_to() {
        let began = std::time::Instant::now();
        let err = super::get_json("192.0.2.1:7616", "/healthz", 500).unwrap_err();
        let took = began.elapsed();
        assert!(
            took < std::time::Duration::from_secs(5),
            "waited {took:?} for a 500ms timeout -- the connect is unbounded ({err})"
        );
    }
}

#[cfg(test)]
mod chunked_tests {
    use super::http_body;

    /// A chunked reply is the body, not the frames around it.
    ///
    /// llama.cpp answers `Transfer-Encoding: chunked`, and this client used to
    /// split on the blank line and parse whatever followed. The hex size lines
    /// went to the JSON parser, the parse failed, and the caller was told the
    /// server returned nothing — from a server that had answered.
    #[test]
    fn a_chunked_reply_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n{\"a\": 1,\r\n8\r\n \"b\": 2}\r\n0\r\n\r\n";
        assert_eq!(http_body(raw), "{\"a\": 1, \"b\": 2}");
    }

    /// The ordinary case still works.
    #[test]
    fn a_content_length_reply_is_untouched() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        assert_eq!(http_body(raw), "{\"a\":1}");
    }

    /// A truncated frame yields what arrived rather than nothing: the JSON
    /// parse downstream decides whether it was enough, and a partial answer is
    /// more useful to a caller than a silent empty one.
    #[test]
    fn a_truncated_chunk_yields_what_arrived() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\n{\"a\":1}";
        assert_eq!(http_body(raw), "{\"a\":1}");
    }

    #[test]
    fn a_reply_with_no_body_is_empty_not_a_panic() {
        assert_eq!(http_body(b"HTTP/1.1 204 No Content\r\n"), "");
    }
}
