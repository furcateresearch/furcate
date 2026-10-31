//! Turning the set of deployed sites into a server configuration.
//!
//! One file, rendered whole from the site list, rather than fragments appended
//! per deploy. A configuration assembled by appending drifts from the state it
//! claims to describe the first time a deploy half-fails, and then nobody can
//! tell by reading it which sites are actually served.
//!
//! Caddy is the target because it is already installed on the machine and
//! answers the two questions that otherwise need solving separately: routing
//! by host, and certificates. Nothing here is Caddy-specific beyond the
//! rendering function itself — the inputs are the deploy's own types.

use crate::release::{Redirect, Site};

/// How the edge should reach a site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Serve {
    /// Files on disk, at this path.
    Files { root: String },
    /// A process behind this edge.
    Proxy { upstream: Upstream },
}

/// Somewhere the edge is willing to send traffic.
///
/// A type rather than a `String` so the refusal below cannot be skipped: the
/// only way to obtain one is through [`Upstream::new`], which checks. A
/// free-standing `is_control_surface` that callers were expected to remember
/// would be a rule that holds until somebody adds a call site and forgets —
/// which is the same as not having it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Upstream(String);

impl TryFrom<String> for Upstream {
    type Error = Refused;
    fn try_from(v: String) -> Result<Self, Refused> {
        Upstream::new(&v)
    }
}

impl From<Upstream> for String {
    fn from(u: Upstream) -> String {
        u.0
    }
}

/// Why an upstream was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    ControlSurface(String),
    Malformed(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::ControlSurface(a) => write!(
                f,
                "`{a}` is a Furcate control surface, and this edge will not publish one. \
                 The front page states node names, measured draw, workload counts and \
                 whether peers are verified — that is an inventory of the site. Reach it \
                 over the overlay, where being able to ask already required being admitted"
            ),
            Refused::Malformed(a) => {
                write!(f, "`{a}` is not a `host:port` this will put into a server configuration")
            }
        }
    }
}

impl std::error::Error for Refused {}

impl Upstream {
    pub fn new(addr: &str) -> Result<Self, Refused> {
        let Some((host, port)) = addr.rsplit_once(':') else {
            return Err(Refused::Malformed(addr.to_string()));
        };
        if host.is_empty() || port.parse::<u16>().is_err() {
            return Err(Refused::Malformed(addr.to_string()));
        }
        // Anything that could terminate a token in the rendered config, for
        // the same reason domains are checked.
        if addr.chars().any(|c| c.is_whitespace() || c == '{' || c == '}') {
            return Err(Refused::Malformed(addr.to_string()));
        }
        if CONTROL_PORTS.contains(&port) {
            return Err(Refused::ControlSurface(addr.to_string()));
        }
        Ok(Upstream(addr.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One site as the edge sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vhost {
    pub site: Site,
    pub serve: Serve,
    pub redirects: Vec<Redirect>,
    /// Paths served by something else — a back end inside this site's own
    /// origin.
    pub routes: Vec<crate::release::Route>,
    /// Response headers the site declared. Carried on every render, which is
    /// the only way a header survives a file that is rewritten whole.
    pub headers: Vec<crate::release::Header>,
}

/// Where the edge listens, and whether it may obtain certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// Bind address for the site blocks. A port other than 443 means plain
    /// HTTP on that port, which is what a machine with no public front door
    /// can actually serve.
    pub bind: String,
    /// Ask for certificates. False while the site is only reachable on an
    /// overlay, because a public certificate authority cannot validate a name
    /// that does not resolve publicly, and asking anyway earns a rate limit.
    pub tls: bool,
    /// Where the server writes its own logs and state.
    pub data_dir: String,
    /// Where the edge asks whether a hostname may have a certificate.
    ///
    /// `Some` turns on **on-demand issuance**: a certificate is obtained
    /// during the first handshake for a name, instead of at startup for a
    /// list. That is what makes a wildcard DNS record enough — every
    /// `<site>.cloud.example.com` gets its own certificate over HTTP-01, and
    /// nothing needs API access to the DNS zone.
    ///
    /// It is `Option` rather than a default because Caddy **refuses** to
    /// enable on-demand without somewhere to ask, and it is right to: an open
    /// on-demand edge lets anyone who points a DNS record at it burn the
    /// certificate authority's rate limit. No ask endpoint, no on-demand.
    pub ask: Option<String>,
    /// The port this edge answers ACME HTTP challenges on, when it cannot
    /// have port 80.
    ///
    /// A certificate authority **always** validates on external port 80; that
    /// is not configurable and never will be. What is configurable is where
    /// port 80 is forwarded to, and this is that port.
    ///
    /// It exists because on these machines port 80 is unusable: k3s ServiceLB
    /// installs a DNAT rule with **no destination-address match**, so `:80` on
    /// every host address is redirected into a cluster pod before any listener
    /// sees it. A process can bind :80, report success, and never receive a
    /// packet — which is what happened here, and what broke a database before it.
    /// Forwarding external 80 to a different local port steps around the rule
    /// entirely, because the packet then arrives with a different dport.
    pub challenge_port: Option<String>,
    /// Wildcard certificates available on this machine. See [`Wildcard`].
    pub wildcards: Vec<Wildcard>,
    /// Addresses of the front door that forwards connections here, as CIDRs.
    ///
    /// A front door that passes TLS through untouched (SNI routing) is the
    /// only peer the edge ever sees, so every request looks as if it came from
    /// it: rate limits and logs lose the client. A front door that prefixes
    /// each connection with a PROXY protocol header carries the client's
    /// address across, and the edge reads that header from these addresses
    /// only. From anywhere else a header is ignored, so nobody can claim an
    /// address by sending one. Empty: no header is read from anyone.
    pub trusted_proxies: Vec<String>,
    /// Whether UDP reaches this edge from outside, so HTTP/3 can be offered.
    ///
    /// Every response advertises HTTP/3 (`Alt-Svc`) when it is on, and a
    /// browser told that tries QUIC on UDP. Behind a front door that forwards
    /// TCP only, that path goes nowhere: some browsers fall back, others fail
    /// the request. Off unless the front door is known to carry UDP.
    pub http3: bool,
}

/// A certificate for `*.zone`, obtained outside the edge and kept on disk.
///
/// On-demand issuance asks the CA for one certificate per name, and a public
/// CA counts those against the registered domain: Let's Encrypt allows fifty
/// new certificates per registered domain per week. A site that answers on a
/// hundred and forty subdomains of one zone therefore cannot come up on
/// on-demand issuance at all — the first fifty names get certificates and the
/// rest are refused for a week, which is what happened to workshop.example.
///
/// A wildcard is one certificate for every name under the zone. The CA will
/// only issue it against a DNS challenge, which the edge cannot answer (it has
/// no DNS credentials and should not), so the certificate is obtained by a
/// separate, scheduled process and placed where `furcatectl` looks for it.
/// The renderer's part is only to use it: a site whose every name is a direct
/// child of the zone is given the wildcard and never asks the CA for anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wildcard {
    /// The zone, without the `*.` — `workshop.example`.
    pub zone: String,
    /// Full chain, PEM.
    pub cert: String,
    /// Private key, PEM.
    pub key: String,
}

impl Wildcard {
    /// Whether every one of these names is a direct child of the zone.
    ///
    /// A wildcard covers exactly one label: `*.example.com` matches
    /// `a.example.com` and neither `example.com` nor `a.b.example.com`. A site
    /// that mixes the apex in with its subdomains is not covered, and falls
    /// back to on-demand issuance for the whole block rather than being served
    /// a certificate that is wrong for one of its names.
    pub fn covers_all(&self, names: &[String]) -> bool {
        !names.is_empty()
            && names.iter().all(|n| {
                n.strip_suffix(&format!(".{}", self.zone))
                    .is_some_and(|label| !label.is_empty() && !label.contains('.'))
            })
    }
}

/// A site's names grouped by the certificate that covers them, in the order the
/// names were declared, with the index of the wildcard for each group — `None`
/// for names no wildcard covers, which are the only ones this edge ever asks a
/// CA about.
///
/// Every placed site also answers on `NAME.<zone>` (`furcatectl edge zone`), so
/// a site with a custom domain carries names under two zones and no single
/// wildcard covers all of them. One block for the site therefore meant on-demand
/// issuance for every name in it, including names whose wildcard was already on
/// disk — and the CA's fifty certificates a week per registered domain are then
/// spent on certificates nobody needed. Grouped, each block is served by the
/// certificate that actually covers it.
fn cert_groups(edge: &Edge, domains: &[String]) -> Vec<(Vec<String>, Option<usize>)> {
    // With no TLS there is nothing to group by, and splitting would only make
    // two identical blocks out of one.
    if !edge.tls {
        return vec![(domains.to_vec(), None)];
    }
    let mut groups: Vec<(Vec<String>, Option<usize>)> = Vec::new();
    for name in domains {
        let wildcard = edge
            .wildcards
            .iter()
            .position(|w| w.covers_all(std::slice::from_ref(name)));
        match groups.iter_mut().find(|(_, w)| *w == wildcard) {
            Some((names, _)) => names.push(name.clone()),
            None => groups.push((vec![name.clone()], wildcard)),
        }
    }
    groups
}

/// Addresses this edge will not publish, whatever it is asked to.
///
/// Furcate's own control surfaces. The site controller answers on 7617 and
/// the node agent on 7616, and both are read-only-by-design *for an operator
/// on the overlay* — the front page states node names, measured draw,
/// workload counts and whether peers are verified. That is an inventory of
/// the site, and the current consensus on control planes is unambiguous: do
/// not put them on the public internet, broker access through something that
/// knows who is asking.
///
/// So this is a refusal rather than a warning. A proxy line is one word in a
/// config file, and the day somebody adds it to make the dashboard reachable
/// from a phone is the day the site's inventory is public. The operator
/// surface stays on the overlay, where reaching it already required being
/// admitted.
pub const CONTROL_PORTS: &[&str] = &["7616", "7617"];

/// Render the whole configuration.
///
/// Returns the file contents. Writing it, and reloading the server, belong to
/// the caller — the same split the advisor uses, so this stays a pure
/// function that a test can read.
/// What a site tells browsers about TLS when it declares nothing of its own: one year.
pub const DEFAULT_HSTS: &str = "max-age=31536000";

pub fn render(edge: &Edge, hosts: &[Vhost]) -> String {
    let mut out = String::new();
    out.push_str("# Rendered by `furcate deploy`. Do not edit.\n");
    out.push_str("# Every site served by this machine is below; this file is\n");
    out.push_str("# written whole on each deploy, so it cannot drift from the\n");
    out.push_str("# set of sites that are actually placed.\n\n");

    out.push_str("{\n");
    out.push_str(&format!("\tstorage file_system {}\n", edge.data_dir));
    // Where this edge actually listens, when the standard ports are not
    // available to it. The outside world still speaks 80 and 443; the router
    // is what makes these the same conversation.
    if edge.tls && !edge.bind.is_empty() && edge.bind != "443" {
        out.push_str(&format!("\thttps_port {}\n", edge.bind));
    }
    if let Some(c) = &edge.challenge_port {
        out.push_str(&format!("\thttp_port {c}\n"));
    }
    if let Some(ask) = &edge.ask {
        // `ask` and nothing else. The rate-limit options that used to sit here
        // — `interval` and `burst` — were **removed**, and Caddy 2.11 refuses
        // to load a config containing them rather than ignoring them. Guidance
        // written before that removal still shows them, which is how they got
        // here; the running server is what said otherwise.
        //
        // Losing them is not losing the protection. They were a second limit
        // behind the permission check, and the permission check is the real
        // one: a name nobody deployed here is refused before issuance is ever
        // attempted.
        out.push_str("\ton_demand_tls {\n");
        out.push_str(&format!("\t\task {ask}\n"));
        out.push_str("\t}\n");
    }
    if !edge.tls {
        // Explicit, and stated in the file, because "no certificates" is a
        // deliberate state while there is no public front door — not an
        // oversight somebody should quietly correct.
        out.push_str("\tauto_https off\n");
    }
    if !edge.trusted_proxies.is_empty() || !edge.http3 {
        out.push_str("\tservers {\n");
        if !edge.trusted_proxies.is_empty() {
            // The client's address from the front door's PROXY protocol header,
            // read before TLS and only from the front door. A connection from one
            // of these addresses without a header is served as it arrives.
            out.push_str("\t\tlistener_wrappers {\n\t\t\tproxy_protocol {\n\t\t\t\ttimeout 5s\n");
            out.push_str(&format!("\t\t\t\tallow {}\n", edge.trusted_proxies.join(" ")));
            out.push_str("\t\t\t}\n\t\t\ttls\n\t\t}\n");
        }
        if !edge.http3 {
            // Offer only what reaches this edge, so no browser is sent to QUIC.
            out.push_str("\t\tprotocols h1 h2\n");
        }
        out.push_str("\t}\n");
    }
    out.push_str("}\n\n");

    // A name this machine does not serve is refused, out loud.
    //
    // Without this the server falls through to an empty `200 OK`, which is
    // the wrong answer twice over: it tells anyone who points a DNS record at
    // this edge that their name is served here, and it makes a genuinely
    // broken deploy — a site placed under a name nobody configured — look
    // like a working one returning an empty page.
    let listen = if edge.bind.is_empty() {
        String::new()
    } else {
        format!(":{}", edge.bind)
    };
    out.push_str(&format!(
        "{}{} {{\n\trespond \"no site is served for this name\" 404\n}}\n\n",
        if edge.tls { "" } else { "http://" },
        listen
    ));

    for h in hosts {
      for (group, wildcard) in cert_groups(edge, &h.site.domains) {
        let names: Vec<String> = group
            .iter()
            .map(|d| match (edge.tls, edge.bind.is_empty()) {
                // No port: the domain alone, which is what makes the server
                // take 443 and obtain a certificate for it.
                (_, true) => d.clone(),
                (true, false) => format!("{}:{}", d, edge.bind),
                // `http://` stated outright. Without the scheme, a site
                // address carrying any port other than 80 is treated as TLS
                // even with automatic HTTPS switched off, and every plaintext
                // request is answered "Client sent an HTTP request to an
                // HTTPS server" — a 400 that looks like a broken site rather
                // than a protocol mismatch.
                (false, false) => format!("http://{}:{}", d, edge.bind),
            })
            .collect();
        out.push_str(&format!("{} {{\n", names.join(", ")));

        // Redirects first. They have to win over the file server, or a path
        // that also exists as a file would be served instead of redirected
        // and the redirect would look like it had been ignored.
        for r in &h.redirects {
            out.push_str(&format!(
                "\tredir {} {} {}\n",
                r.from,
                r.to,
                if r.permanent { "permanent" } else { "temporary" }
            ));
        }

        // A wildcard that covers every name here means no certificate is ever
        // requested for this site — the one on disk is the certificate. Only
        // when there is no such wildcard does the site ask before issuing, per
        // name, so a name that reaches the edge but is not deployed here never
        // becomes a certificate request.
        if edge.tls {
            if let Some(w) = wildcard.map(|i| &edge.wildcards[i]) {
                out.push_str(&format!("\t# every name here is under *.{}; issuance is off\n", w.zone));
                out.push_str(&format!("\ttls {} {}\n", w.cert, w.key));
            } else if edge.ask.is_some() {
                out.push_str("\ttls {\n\t\ton_demand\n\t}\n");
            }
        }

        // Headers the site declared, at the site level so they apply whether
        // the answer comes from a back end, the files or a proxied process.
        //
        // `defer`, because without it the header is set before the handler
        // runs and a proxied application's own header of the same name is
        // added beside it, so the response carries two answers and the browser
        // picks one. Deferred, the declared value is applied as the response is
        // written, and it is the one the site asked for.
        //
        // Checked again here even though the deploy checked it: this function
        // writes the file, and a hand-edited headers.json is exactly the input
        // nobody re-validated.
        // Every site answers over TLS, so every site tells browsers to keep it so. A site that declares its own
        // Strict-Transport-Security for all its paths replaces this one. No `includeSubDomains` and no `preload`:
        // the first covers names the site does not own, the second cannot be taken back.
        let declares_hsts = h.headers.iter().any(|hd| {
            hd.path.is_none() && hd.name.eq_ignore_ascii_case("Strict-Transport-Security") && hd.check().is_ok()
        });
        if !declares_hsts {
            out.push_str(&format!("\theader {{\n\t\tStrict-Transport-Security \"{DEFAULT_HSTS}\"\n\t\tdefer\n\t}}\n"));
        }
        for hd in h.headers.iter().filter(|hd| hd.check().is_ok()) {
            let matcher = hd.path.as_deref().map(|p| format!(" {p}")).unwrap_or_default();
            out.push_str(&format!(
                "\theader{matcher} {{\n\t\t{} \"{}\"\n\t\tdefer\n\t}}\n",
                hd.name, hd.value
            ));
        }

        // Back ends first, each in its own `handle`, so a path that also
        // exists as a file goes to the back end rather than being served from
        // disk. `handle` blocks are mutually exclusive and matched in written
        // order, which makes this independent of the server's own directive
        // ordering — a subtlety that is easy to get wrong once and never
        // notice, because the wrong answer is a stale file rather than an
        // error.
        for r in &h.routes {
            out.push_str(&format!("\thandle {} {{\n", r.path));
            out.push_str(&format!("\t\treverse_proxy {}\n", r.upstream.as_str()));
            out.push_str("\t}\n");
        }

        let open = if h.routes.is_empty() { "" } else { "\thandle {\n\t" };
        let close = if h.routes.is_empty() { "" } else { "\t}\n" };
        match &h.serve {
            Serve::Files { root } => {
                out.push_str(open);
                out.push_str(&format!("\troot * {root}\n"));
                // Next's static export writes `about.html`, and the links in
                // it point at `/about`. Without this the site builds, deploys,
                // serves its front page and 404s on every internal link.
                out.push_str(if h.routes.is_empty() { "\ttry_files {path} {path}.html {path}/index.html\n" } else { "\t\ttry_files {path} {path}.html {path}/index.html\n" });
                out.push_str(if h.routes.is_empty() { "\tfile_server\n" } else { "\t\tfile_server\n" });
                out.push_str(close);
            }
            Serve::Proxy { upstream } => {
                out.push_str(&format!("\treverse_proxy {}\n", upstream.as_str()));
            }
        }
        out.push_str("}\n\n");
      }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Tier;

    fn site(name: &str, domains: &[&str], tier: Tier) -> Site {
        Site {
            local: false,
            name: name.into(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            tier,
            // What the detector decided is not an input to any edge rendering
            // decision, and `None` is the value the field documents for a
            // manifest that predates it.
            framework: None,
        }
    }

    fn static_host() -> Vhost {
        Vhost {
            site: site("furcate-xyz", &["furcate.xyz", "www.furcate.xyz"], Tier::Static),
            serve: Serve::Files {
                root: "/var/lib/furcate/deploy/sites/furcate-xyz/current".into(),
            },
            redirects: vec![Redirect {
                from: "/hardware/micro".into(),
                to: "/hardware/sensor".into(),
                permanent: true,
            }],
            routes: vec![],
            headers: vec![],
        }
    }

    fn edge() -> Edge {
        Edge {
            bind: "8443".into(),
            tls: false,
            data_dir: "/var/lib/furcate/deploy/edge".into(),
            ask: None,
            challenge_port: None,
            wildcards: vec![],
            trusted_proxies: vec![],
            http3: false,
        }
    }

    #[test]
    fn http3_is_offered_only_when_udp_reaches_the_edge() {
        let tcp_only = render(&edge(), &[]);
        let global = &tcp_only[tcp_only.find("{\n").unwrap()..tcp_only.find("}\n\n").unwrap()];
        assert!(global.contains("protocols h1 h2"), "behind a TCP-only front door, no Alt-Svc for h3");

        let udp = render(&Edge { http3: true, ..edge() }, &[]);
        assert!(!udp.contains("protocols"), "Caddy's default offers h3 when UDP reaches it");
        assert!(!udp.contains("servers {"));
    }

    #[test]
    fn a_trusted_front_door_passes_the_client_address_through() {
        let plain = render(&edge(), &[]);
        assert!(!plain.contains("proxy_protocol"), "no front door named, no header read");

        let e = Edge { trusted_proxies: vec!["192.0.2.1/32".into()], ..edge() };
        let c = render(&e, &[]);
        let global = &c[c.find("{\n").unwrap()..c.find("}\n\n").unwrap()];
        assert!(global.contains("listener_wrappers {"));
        assert!(global.contains("allow 192.0.2.1/32"));
        // The header is read before TLS, so the wrapper order matters.
        assert!(global.find("proxy_protocol").unwrap() < global.find("\t\t\ttls").unwrap());
    }

    fn wildcard() -> Wildcard {
        Wildcard {
            zone: "workshop.example".into(),
            cert: "/var/lib/furcate/deploy/edge/wildcards/workshop.example/fullchain.pem".into(),
            key: "/var/lib/furcate/deploy/edge/wildcards/workshop.example/privkey.pem".into(),
        }
    }

    fn selves_host() -> Vhost {
        Vhost {
            site: site(
                "marketer-rs",
                &["marketer.workshop.example", "philosopher.workshop.example", "welder.workshop.example"],
                Tier::Node,
            ),
            serve: Serve::Proxy { upstream: Upstream::new("127.0.0.1:8629").unwrap() },
            redirects: vec![],
            routes: vec![],
            headers: vec![],
        }
    }

    #[test]
    fn a_wildcard_covers_direct_children_of_the_zone_and_nothing_else() {
        let w = wildcard();
        assert!(w.covers_all(&["a.workshop.example".into(), "b.workshop.example".into()]));
        // The apex is not under the wildcard.
        assert!(!w.covers_all(&["workshop.example".into()]));
        // Neither is a second level.
        assert!(!w.covers_all(&["a.b.workshop.example".into()]));
        // Nor a different zone that merely ends the same way.
        assert!(!w.covers_all(&["a.notworkshop.example".into()]));
        // An empty site is not "covered", it is nothing.
        assert!(!w.covers_all(&[]));
    }

    #[test]
    fn a_site_wholly_under_a_wildcard_is_served_that_certificate_and_never_asks() {
        let e = Edge {
            tls: true,
            bind: String::new(),
            ask: Some("http://192.0.2.11:7617/tls/allow".into()),
            wildcards: vec![wildcard()],
            ..edge()
        };
        let c = render(&e, &[selves_host()]);
        assert!(c.contains(
            "\ttls /var/lib/furcate/deploy/edge/wildcards/workshop.example/fullchain.pem \
             /var/lib/furcate/deploy/edge/wildcards/workshop.example/privkey.pem\n"
        ));
        // The site block must not also enable on-demand issuance: that would
        // be a second certificate request per name, which is the whole thing
        // the wildcard exists to stop.
        assert!(!c.contains("\t\ton_demand\n"));
        // The global ask stays: other sites on this edge still need it.
        assert!(c.contains("on_demand_tls {"));
    }

    #[test]
    fn a_site_that_mixes_the_apex_with_subdomains_gives_the_wildcard_to_the_subdomains() {
        // The apex is not covered by *.zone and asks for itself; the names that
        // ARE covered keep the certificate on disk rather than being dragged
        // into issuance beside it.
        let mut e = edge();
        e.tls = true;
        e.ask = Some("http://127.0.0.1:7616/ask".into());
        e.wildcards = vec![Wildcard {
            zone: "workshop.example".into(),
            cert: "/var/lib/w/fullchain.pem".into(),
            key: "/var/lib/w/privkey.pem".into(),
        }];
        let mut h = static_host();
        h.site.domains = vec!["workshop.example".into(), "www.workshop.example".into()];

        let c = render(&e, &[h]);

        assert!(c.contains("\ttls /var/lib/w/fullchain.pem /var/lib/w/privkey.pem"), "{c}");
        assert_eq!(c.matches("\t\ton_demand\n").count(), 1, "only the apex asks:\n{c}");
        let asked = c.split("\n\n").find(|b| b.contains("\t\ton_demand\n")).expect("a block that asks");
        assert!(!asked.contains("www.workshop.example"), "{asked}");
    }

    #[test]
    fn a_wildcard_is_ignored_while_the_edge_is_plaintext() {
        let e = Edge { wildcards: vec![wildcard()], ..edge() };
        let c = render(&e, &[selves_host()]);
        assert!(c.contains("auto_https off"));
        assert!(!c.contains("\ttls "));
    }

    #[test]
    fn every_domain_a_site_answers_on_appears() {
        let c = render(&edge(), &[static_host()]);
        assert!(c.contains("furcate.xyz:8443"));
        assert!(c.contains("www.furcate.xyz:8443"));
    }

    #[test]
    fn a_plaintext_edge_says_http_outright() {
        // Found by serving it: a site address with any port other than 80 is
        // treated as TLS even with automatic HTTPS off, so every request came
        // back 400 "Client sent an HTTP request to an HTTPS server". The
        // scheme has to be stated.
        let c = render(&edge(), &[static_host()]);
        assert!(
            c.contains("http://furcate.xyz:8443"),
            "without the scheme the edge answers 400 to every plaintext request"
        );
    }

    #[test]
    fn a_tls_edge_on_a_nonstandard_port_does_not_get_the_http_scheme() {
        let e = Edge {
            tls: true,
            bind: "8443".into(),
            ..edge()
        };
        let c = render(&e, &[static_host()]);
        assert!(c.contains("furcate.xyz:8443"));
        assert!(!c.contains("http://furcate.xyz"));
    }

    #[test]
    fn redirects_are_emitted_before_the_file_server() {
        let c = render(&edge(), &[static_host()]);
        let r = c.find("redir /hardware/micro").expect("redirect present");
        let f = c.find("file_server").expect("file server present");
        assert!(r < f, "a redirect that loses to the file server does nothing");
    }

    #[test]
    fn a_static_site_resolves_extensionless_links() {
        // The failure this prevents: the site deploys, the front page works,
        // and every internal link 404s because the export wrote `about.html`
        // while the links say `/about`.
        let c = render(&edge(), &[static_host()]);
        assert!(c.contains("try_files {path} {path}.html {path}/index.html"));
    }

    #[test]
    fn certificates_are_refused_out_loud_when_there_is_no_public_name() {
        let c = render(&edge(), &[static_host()]);
        assert!(
            c.contains("auto_https off"),
            "asking a public CA to validate a name that does not resolve earns a rate limit"
        );
    }

    #[test]
    fn certificates_are_requested_once_tls_is_on() {
        let e = Edge {
            tls: true,
            bind: String::new(),
            ..edge()
        };
        let c = render(&e, &[static_host()]);
        assert!(!c.contains("auto_https off"));
        // With no explicit port the domain stands alone, which is what makes
        // Caddy serve it on 443 and obtain a certificate for it.
        assert!(c.contains("furcate.xyz, www.furcate.xyz {"));
    }

    #[test]
    fn on_demand_issuance_is_off_unless_there_is_somewhere_to_ask() {
        // Caddy refuses on-demand without an ask endpoint, and it is right to:
        // an open on-demand edge lets anyone who points a DNS record at it
        // spend the certificate authority's rate limit. Making `ask` an
        // Option means the unsafe configuration cannot be rendered at all.
        let e = Edge { tls: true, bind: String::new(), ask: None, ..edge() };
        let c = render(&e, &[static_host()]);
        assert!(!c.contains("on_demand"));
    }

    #[test]
    fn an_ask_endpoint_turns_on_demand_on_globally_and_per_site() {
        let e = Edge {
            tls: true,
            bind: String::new(),
            ask: Some("http://192.0.2.11:7617/tls/allow".into()),
            ..edge()
        };
        let c = render(&e, &[static_host()]);
        assert!(c.contains("ask http://192.0.2.11:7617/tls/allow"));
        // Both halves are needed: the global block says where to ask, and the
        // site block is what actually enables issuance for that site.
        assert!(c.contains("on_demand_tls {"));
        assert!(c.contains("tls {\n\t\ton_demand\n\t}"));
        // `interval` and `burst` were removed from Caddy and a config that
        // contains them is refused outright — the error is at load time, so
        // the edge does not start at all. Found by running it.
        assert!(!c.contains("interval"));
        assert!(!c.contains("burst"));
    }

    #[test]
    fn a_plaintext_edge_never_asks_for_certificates_even_with_an_ask_url() {
        // While there is no public front door the edge serves plain HTTP. A
        // certificate authority cannot validate a name that does not resolve
        // publicly, so asking would earn a rate limit for nothing.
        let e = Edge { ask: Some("http://x/tls/allow".into()), ..edge() };
        let c = render(&e, &[static_host()]);
        assert!(c.contains("auto_https off"));
        assert!(!c.contains("\ttls {"));
    }

    #[test]
    fn an_edge_that_cannot_have_port_80_says_where_it_listens_instead() {
        // Not a preference: on these machines k3s ServiceLB DNATs :80 on every
        // host address into a pod, so a listener on :80 is bound and never
        // reached. External 80 and 443 are forwarded to these ports instead,
        // and the certificate authority still validates on 80 as it always
        // does.
        let e = Edge {
            tls: true,
            bind: "8443".into(),
            challenge_port: Some("8080".into()),
            ask: Some("http://c/tls/allow".into()),
            ..edge()
        };
        let c = render(&e, &[static_host()]);
        assert!(c.contains("https_port 8443"));
        assert!(c.contains("http_port 8080"));
    }

    #[test]
    fn an_edge_on_the_standard_port_does_not_restate_it() {
        // `https_port 443` is the default; writing it would be one more place
        // the number is stated.
        let e = Edge { tls: true, bind: "443".into(), ..edge() };
        let c = render(&e, &[static_host()]);
        assert!(!c.contains("https_port"));
    }

    fn route(path: &str, up: &str) -> crate::release::Route {
        crate::release::Route { path: path.into(), upstream: Upstream::new(up).unwrap() }
    }

    #[test]
    fn a_back_end_is_reached_on_the_front_ends_own_origin() {
        // The point of this: the front end asks `/api/...` on its own
        // hostname, so there is no second origin, no CORS, and no back-end URL
        // compiled into a static build.
        let mut h = static_host();
        h.routes = vec![route("/api/*", "192.0.2.28:18086")];
        let c = render(&edge(), &[h]);
        assert!(c.contains("handle /api/* {"));
        assert!(c.contains("reverse_proxy 192.0.2.28:18086"));
    }

    #[test]
    fn a_path_that_is_also_a_file_still_goes_to_the_back_end() {
        // The failure this prevents is quiet: a stale file served in place of
        // a live API, with no error anywhere. `handle` blocks are mutually
        // exclusive and matched in written order, so the back end wins by
        // being written first rather than by depending on the server's own
        // directive ordering.
        let mut h = static_host();
        h.routes = vec![route("/api/*", "10.0.0.5:3000")];
        let c = render(&edge(), &[h]);
        let api = c.find("handle /api/*").expect("route present");
        let files = c.find("file_server").expect("file server present");
        assert!(api < files);
        // And the file server is itself inside a handle, or it would match
        // every path including the ones just routed away.
        assert!(c.contains("handle {"));
    }

    #[test]
    fn a_site_with_no_back_end_is_rendered_exactly_as_before() {
        // Sites without routes are the common case and must not acquire an
        // extra nesting level that changes their behaviour.
        let c = render(&edge(), &[static_host()]);
        assert!(!c.contains("handle {"));
        assert!(c.contains("\troot * "));
    }

    #[test]
    fn a_back_end_cannot_be_a_control_surface_either() {
        // The same refusal as a proxied site: `Route` carries an `Upstream`,
        // so there is no path to writing 7617 into a config through routes.
        assert!(Upstream::new("192.0.2.11:7617").is_err());
    }

    #[test]
    fn a_node_site_is_proxied_rather_than_served_from_disk() {
        let h = Vhost {
            site: site("app", &["app.furcate.xyz"], Tier::Node),
            serve: Serve::Proxy { upstream: Upstream::new("127.0.0.1:8081").unwrap() },
            redirects: vec![],
            routes: vec![],
            headers: vec![],
        };
        let c = render(&edge(), &[h]);
        assert!(c.contains("reverse_proxy 127.0.0.1:8081"));
        assert!(!c.contains("file_server"));
    }

    #[test]
    fn an_app_can_be_proxied_to_another_machine() {
        // The edge and the app are routinely on different boxes. A
        // loopback-only upstream would have limited every site to the machine
        // its edge happens to run on, without ever saying so.
        let h = Vhost {
            site: site("app", &["app.furcate.xyz"], Tier::Node),
            serve: Serve::Proxy { upstream: Upstream::new("192.0.2.11:8081").unwrap() },
            redirects: vec![],
            routes: vec![],
            headers: vec![],
        };
        assert!(render(&edge(), &[h]).contains("reverse_proxy 192.0.2.11:8081"));
    }

    #[test]
    fn a_control_surface_cannot_be_made_into_an_upstream_at_all() {
        // The consensus on control planes is not to put them on the public
        // internet. Making this a constructor rather than a check callers
        // remember means the unsafe config cannot be built, not merely that
        // it is discouraged.
        for a in ["192.0.2.11:7617", "127.0.0.1:7616"] {
            assert_eq!(Upstream::new(a), Err(Refused::ControlSurface(a.into())));
        }
        assert!(Upstream::new("192.0.2.11:7617")
            .unwrap_err()
            .to_string()
            .contains("inventory of the site"));
    }

    #[test]
    fn an_ordinary_app_is_accepted_however_it_is_addressed() {
        for a in ["192.0.2.11:8081", "app.internal:3000", "127.0.0.1:8080"] {
            assert!(Upstream::new(a).is_ok(), "{a} should be allowed");
        }
    }

    #[test]
    fn an_address_that_could_break_the_config_is_refused_rather_than_quoted() {
        for a in ["somehost", "host:notaport", ":8080", "a b:80", "x:80 }"] {
            assert!(matches!(Upstream::new(a), Err(Refused::Malformed(_))), "{a:?}");
        }
    }

    #[test]
    fn the_file_says_it_is_generated() {
        // Somebody will find this file before they find the command that
        // writes it, and an edit they make by hand will vanish on the next
        // deploy without explanation.
        let c = render(&edge(), &[static_host()]);
        assert!(c.starts_with("# Rendered by `furcate deploy`. Do not edit."));
    }

    #[test]
    fn a_name_this_machine_does_not_serve_is_refused() {
        // Found by serving it: the fall-through is an empty `200 OK`, which
        // tells anyone who points DNS at this edge that their name is served
        // here.
        let c = render(&edge(), &[static_host()]);
        assert!(c.contains("respond \"no site is served for this name\" 404"));
        // And it must not shadow the real site: the catch-all is the less
        // specific address, so the site block still has to be present.
        assert!(c.contains("http://furcate.xyz:8443"));
    }

    fn header(path: Option<&str>, name: &str, value: &str) -> crate::release::Header {
        crate::release::Header { path: path.map(String::from), name: name.into(), value: value.into() }
    }

    /// The block of the rendered file that belongs to the first site named.
    fn block_of<'a>(c: &'a str, first_name: &str) -> &'a str {
        let start = c.find(first_name).expect("site present");
        let rest = &c[start..];
        let end = rest.find("\n}\n").expect("site block closed");
        &rest[..end]
    }

    #[test]
    fn a_declared_header_is_carried_by_every_render() {
        // The landing page's Cache-Control, which the renderer used to drop on
        // every deploy of every site and a script put back afterwards.
        let mut h = static_host();
        h.headers = vec![header(None, "Cache-Control", "no-cache")];
        let c = render(&edge(), &[h]);
        let site = block_of(&c, "http://furcate.xyz:8443");
        assert!(
            site.contains("\theader {\n\t\tCache-Control \"no-cache\"\n\t\tdefer\n\t}\n"),
            "{site}"
        );
        // Inside the site it belongs to, and before the files are served.
        assert!(site.find("header {").unwrap() < site.find("file_server").unwrap());
    }

    #[test]
    fn a_header_reaches_a_proxied_site_and_wins_over_the_applications_own() {
        // `defer` is what makes the declared value the one sent, rather than a
        // second value beside whatever the upstream set.
        let mut h = selves_host();
        h.headers = vec![header(Some("/assets/*"), "Cache-Control", "public, max-age=31536000")];
        let c = render(&edge(), &[h]);
        assert!(c.contains(
            "\theader /assets/* {\n\t\tCache-Control \"public, max-age=31536000\"\n\t\tdefer\n\t}\n"
        ));
        assert!(c.contains("reverse_proxy 127.0.0.1:8629"));
    }

    #[test]
    fn a_header_that_could_break_the_config_is_not_rendered_even_if_it_was_placed() {
        let mut h = static_host();
        h.headers = vec![
            header(None, "Cache-Control", "no-cache\"\n\trespond 200"),
            header(None, "X-Ok", "yes"),
        ];
        let c = render(&edge(), &[h]);
        assert!(!c.contains("respond 200"));
        assert!(c.contains("X-Ok \"yes\""), "one bad header must not take the others with it");
    }

    #[test]
    fn a_site_that_declares_no_headers_renders_only_the_default_transport_security() {
        let c = render(&edge(), &[static_host(), selves_host()]);
        assert_eq!(c.matches("Strict-Transport-Security \"max-age=31536000\"").count(), 2, "one per site");
        assert!(!c.contains("Cache-Control"));
        assert!(!c.contains("includeSubDomains") && !c.contains("preload"));
    }

    #[test]
    fn a_site_that_declares_its_own_transport_security_is_not_given_a_second() {
        let mut h = static_host();
        h.headers = vec![header(None, "strict-transport-security", "max-age=63072000")];
        let c = render(&edge(), &[h]);
        assert_eq!(c.matches("max-age=").count(), 1);
        assert!(c.contains("max-age=63072000") && !c.contains("max-age=31536000"));
    }

    #[test]
    fn a_header_declared_for_one_path_does_not_stand_in_for_the_site_wide_one() {
        let mut h = static_host();
        h.headers = vec![header(Some("/assets/*"), "Strict-Transport-Security", "max-age=1")];
        let c = render(&edge(), &[h]);
        assert!(c.contains("max-age=31536000") && c.contains("max-age=1"));
    }

    /// The defect this guards: a site with a custom domain also answers on
    /// NAME.<zone>, so its names span two zones. Rendered as one block, no
    /// wildcard covered all of them and the whole site fell back to on-demand
    /// issuance — which is how a zone with a wildcard on disk spent the CA's
    /// fifty-a-week limit and a new site could not get a certificate at all.
    #[test]
    fn a_site_spanning_two_zones_uses_both_wildcards_and_asks_for_nothing() {
        let mut e = edge();
        e.tls = true;
        e.ask = Some("http://127.0.0.1:7616/ask".into());
        e.wildcards = vec![
            Wildcard {
                zone: "workshop.example".into(),
                cert: "/w/rs/fullchain.pem".into(),
                key: "/w/rs/privkey.pem".into(),
            },
            Wildcard {
                zone: "app.example.net".into(),
                cert: "/w/cloud/fullchain.pem".into(),
                key: "/w/cloud/privkey.pem".into(),
            },
        ];
        let mut h = static_host();
        h.site.domains = vec![
            "platform.workshop.example".into(),
            "workshop-platform.app.example.net".into(),
        ];

        let out = render(&e, &[h]);

        assert!(!out.contains("\t\ton_demand\n"), "no name here needs the CA:\n{out}");
        assert!(out.contains("platform.workshop.example:8443 {"), "{out}");
        assert!(out.contains("workshop-platform.app.example.net:8443 {"), "{out}");
        assert!(out.contains("tls /w/rs/fullchain.pem /w/rs/privkey.pem"), "{out}");
        assert!(out.contains("tls /w/cloud/fullchain.pem /w/cloud/privkey.pem"), "{out}");
    }

    /// And a name no wildcard covers is still asked for, in its own block,
    /// without dragging the covered names into issuance with it.
    #[test]
    fn a_name_with_no_wildcard_is_the_only_one_asked_for() {
        let mut e = edge();
        e.tls = true;
        e.ask = Some("http://127.0.0.1:7616/ask".into());
        e.wildcards = vec![Wildcard {
            zone: "workshop.example".into(),
            cert: "/w/rs/fullchain.pem".into(),
            key: "/w/rs/privkey.pem".into(),
        }];
        let mut h = static_host();
        h.site.domains = vec!["platform.workshop.example".into(), "example.org".into()];

        let out = render(&e, &[h]);

        assert_eq!(out.matches("\t\ton_demand\n").count(), 1, "{out}");
        let asked = out
            .split("\n\n")
            .find(|b| b.contains("		on_demand
"))
            .expect("a block that asks");
        assert!(asked.contains("example.org"), "{asked}");
        assert!(!asked.contains("platform.workshop.example"), "the covered name must not be asked for:\n{asked}");
    }

    #[test]
    fn rendering_no_sites_is_still_a_valid_configuration() {
        // A machine with nothing deployed must produce a file the server will
        // load, not a truncated one that stops it starting.
        let c = render(&edge(), &[]);
        assert!(c.contains("storage file_system"));
        assert!(!c.contains("file_server"));
    }
}
