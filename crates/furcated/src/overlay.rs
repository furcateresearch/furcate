//! This node's side of the mesh.
//!
//! Three jobs, and a fourth it deliberately does not have.
//!
//! It reads what the privileged half published — this node's overlay public key
//! and how the interface is doing. It resolves a peer set from the hints the
//! coordinator supplied, the peers it already held, and the policy it holds
//! locally. It writes the plan for the privileged half to apply.
//!
//! What it does not do is decide that a peer is allowed. That decision belongs
//! to the policy engine, and it is passed in rather than made here so the
//! separation between *where a peer is* and *whether it may speak* stays visible
//! in the shape of the code and not only in a comment.
//!
//! ## Held peers are persisted
//!
//! The last resolved peer set is written to disk, because the property this
//! whole design exists for — a coordinator outage is not an outage — has to
//! survive the agent restarting as well as the coordinator going quiet. An
//! in-memory-only peer set would mean a node that rebooted during a coordinator
//! outage came back with no mesh at all, which is the failure being prevented,
//! arriving by a different door.

use furcate_net::overlay::{resolve, Hint, Peer, Resolution, Source, Tier};
use furcate_net::wg;
use serde::{Deserialize, Serialize};

/// Where the agent writes the plan for the privileged half.
/// Where the agent writes the plan for the privileged half.
///
/// `/var/lib/furcate` rather than the agent's home, because the privileged half
/// holds `CAP_NET_ADMIN` and nothing else — which costs root its
/// `CAP_DAC_OVERRIDE`, so a home directory at mode 750 is one it genuinely
/// cannot traverse. Granting the ability to ignore every permission on the
/// system in order to read one file would be an absurd trade; moving the file
/// costs nothing.
pub fn plan_path() -> String {
    std::env::var("FURCATE_WG_PLAN")
        .unwrap_or_else(|_| furcate_paths::state("wg-plan").display().to_string())
}

/// Where the privileged half reports what it did.
const STATE_PATH: &str = "/run/furcate/wg.json";

/// Where the resolved peer set is kept across restarts.
fn held_path_for(plan: &str) -> String {
    format!("{plan}-peers.json")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OverlayReport {
    /// This node's overlay public key, once the privileged half has generated
    /// one. `None` means the mesh is not up yet, which is different from being
    /// up with no peers.
    pub public_key: Option<String>,
    pub interface: Option<String>,
    pub address: Option<String>,
    /// Peers currently carried, and where each came from.
    pub peers: Vec<Peer>,
    /// Hints local policy declined, kept because a coordinator offering peers
    /// this node will not carry is worth seeing.
    pub refused: Vec<furcate_net::overlay::Refused>,
    /// How many peers survive only because they were already held. The number
    /// that says whether the coordinator is being useful.
    pub retained: usize,
    /// Seconds since the most recent handshake with any peer. `None` when
    /// nothing has ever completed one.
    pub last_handshake_secs: Option<u64>,
    /// Whether the tooling this needs is installed at all.
    pub available: bool,
    pub why_unavailable: Option<String>,
    /// How far this overlay's traffic travels, and therefore whether a
    /// post-quantum key exchange is yet worth its daemon.
    pub exposure: furcate_net::overlay::Exposure,
}

/// What signs this node's overlay leases: the root of trust's message signer
/// where it has one (a Pi's firmware-held P-256 key), else the node key. Set
/// once at start, by the same choice that picks the cell signer.
static LEASE_SIGNER: std::sync::OnceLock<std::sync::Arc<dyn furcate_identity::MessageSigner>> =
    std::sync::OnceLock::new();

/// The binding for the key the kernel holds now, so hardware is asked once
/// per lease rather than on every report.
static LEASE_HELD: std::sync::Mutex<Option<(String, String, u64, furcate_net::lease::Binding)>> =
    std::sync::Mutex::new(None);

static GOSSIP_REFUSED: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Whether the privileged half reports a leased key on this node.
pub fn leased_here() -> bool {
    read_state().as_ref().and_then(reported_lease).is_some()
}

pub fn set_lease_signer(s: std::sync::Arc<dyn furcate_identity::MessageSigner>) {
    let _ = LEASE_SIGNER.set(s);
}

/// The furthest ahead this node accepts a peer's lease. Configurable because
/// it is a site's choice; defaulted so a node that says nothing still refuses
/// a lease long enough to be a standing credential.
pub fn lease_ceiling() -> u64 {
    std::env::var("FURCATE_OVERLAY_LEASE_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &u64| *v > 0)
        .unwrap_or(furcate_net::lease::DEFAULT_CEILING)
}

/// The lease the privileged half reports, if this node runs one.
///
/// `ephemeral` is set by the privileged half's own configuration, never by
/// this agent: the agent cannot switch a node between a key that lives for
/// one lease and a key on disk. The expiry is the key's birth plus its lease,
/// both as the privileged half reports them, so a restarted agent signs the
/// same expiry again rather than a fresh one, and a key the privileged half
/// failed to replace lapses rather than being extended.
pub fn reported_lease(state: &serde_json::Value) -> Option<u64> {
    if state.get("ephemeral").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let born = state.get("key_born_at")?.as_u64()?;
    let lease = state.get("lease")?.as_u64().filter(|l| *l > 0)?;
    Some(born.saturating_add(lease))
}

/// Bind the kernel's current key for this lease, or reuse the binding made
/// for it already.
pub fn lease_binding(
    signer: &dyn furcate_identity::MessageSigner,
    node_id: &str,
    key: &str,
    tier: Tier,
    not_after: u64,
    now: u64,
) -> Option<furcate_net::lease::Binding> {
    if not_after <= now {
        eprintln!(
            "furcated: WARNING overlay: the leased key ran out at {not_after} and the privileged half has not replaced it; nothing is signed for it"
        );
        return None;
    }
    let mut held = LEASE_HELD.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((k, t, n, b)) = held.as_ref() {
        if k == key && t == tier.as_str() && *n == not_after {
            return Some(b.clone());
        }
    }
    let terms = furcate_net::lease::Terms {
        node_id,
        wg_pub: key,
        tier: tier.as_str(),
        not_after,
        quote_digest: None,
    };
    match furcate_net::lease::bind(signer, &terms) {
        Ok(b) => {
            *held = Some((key.to_string(), tier.as_str().to_string(), not_after, b.clone()));
            Some(b)
        }
        Err(e) => {
            eprintln!("furcated: WARNING overlay: cannot bind this lease's key: {e}; peers will refuse it");
            None
        }
    }
}

/// Statements from other members' gossip, checked and held.
///
/// Each is a leased hint. It is held only if [`furcate_net::lease::verify_carried`]
/// accepts it, so what this node repeats is what it could check itself.
/// Returns how many were new or newer.
pub fn gossip_in(
    m: &mut furcate_membership::Membership,
    me: &str,
    leases: Option<&serde_json::Value>,
    anchors: &furcate_net::lock::Anchors,
    trusted_key: &dyn Fn(&str) -> Option<String>,
    now: u64,
) -> usize {
    let Some(list) = leases.and_then(|v| v.as_array()) else { return 0 };
    let ceiling = lease_ceiling();
    let mut changed = 0;
    for v in list.iter().take(furcate_membership::Rumours::LIMIT) {
        let Ok(h) = serde_json::from_value::<Hint>(v.clone()) else { continue };
        if h.node_id == me {
            continue;
        }
        let known = trusted_key(&h.node_id);
        if let Err(why) = furcate_net::lease::verify_carried(anchors, known.as_deref(), &h, now, ceiling) {
            // Once per distinct refusal: a neighbour repeats what it holds on
            // every exchange, and the reason does not change between them.
            let mut seen = GOSSIP_REFUSED.lock().unwrap_or_else(|p| p.into_inner());
            if seen.len() > 1024 {
                seen.clear();
            }
            if seen.insert(why.clone()) {
                eprintln!("furcated: overlay gossip refused: {why}");
            }
            continue;
        }
        if hold(m, &h, now) {
            changed += 1;
        }
    }
    changed
}

/// Hold a leased hint as this node's current statement for its origin.
pub fn hold(m: &mut furcate_membership::Membership, h: &Hint, now: u64) -> bool {
    let Some(b) = &h.lease else { return false };
    let Ok(body) = serde_json::to_value(h) else { return false };
    m.rumours_mut()
        .offer(
            furcate_membership::Rumour { origin: h.node_id.clone(), version: b.not_after, expires: b.not_after, body },
            now,
        )
        .changed()
}

/// What holding an announced hint did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// A lease not held before: a new key.
    Key,
    /// The same lease, from a new underlay address.
    Moved,
    /// The same lease, the same addresses, a later statement.
    Same,
    /// Nothing held: not leased, expired, or older than what is held.
    Nothing,
}

/// Hold a hint that arrived in a verified, replay-checked announcement.
///
/// Gossip carries a lease and nothing that orders two statements of it, so a
/// gossiped hint with the lease already held changes nothing. An announcement
/// is signed over its hint and send time and taken only in increasing order of
/// that time, so the hint inside it is the origin's own, current statement:
/// the same lease with a later `seen_at` replaces the held body, which is how
/// a node that changed underlay address tells its peers where it is now
/// without a newer lease.
pub fn hold_announced(m: &mut furcate_membership::Membership, h: &Hint, now: u64) -> Held {
    if hold(m, h, now) {
        return Held::Key;
    }
    let Some(b) = &h.lease else { return Held::Nothing };
    let Some(held) = m.rumours().get(&h.node_id).and_then(|r| serde_json::from_value::<Hint>(r.body.clone()).ok()) else {
        return Held::Nothing;
    };
    let same_lease = held.public_key == h.public_key && held.lease.as_ref().is_some_and(|l| l.not_after == b.not_after);
    if !same_lease || h.seen_at <= held.seen_at {
        return Held::Nothing;
    }
    let Ok(body) = serde_json::to_value(h) else { return Held::Nothing };
    let moved = held.endpoints != h.endpoints || held.observed != h.observed;
    let r = furcate_membership::Rumour { origin: h.node_id.clone(), version: b.not_after, expires: b.not_after, body };
    match m.rumours_mut().replace_same_version(r, now) {
        true if moved => Held::Moved,
        true => Held::Same,
        false => Held::Nothing,
    }
}

/// The generation of the last request that this node's WireGuard peers be
/// re-applied, written into the plan. See [`request_refresh`].
static REFRESH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Ask the privileged half to apply every peer again, now.
///
/// WireGuard keeps, per peer, the local address it last sent from; after this
/// node's own underlay address changed that cached source is one the node no
/// longer has, and packets to the peer keep leaving from it. Setting the
/// peer's endpoint clears it and the next keepalive handshakes from the
/// address the kernel picks now. The helper applies the plan when its body
/// changes, so a `refresh=` line carrying the time of the request is enough;
/// it is written into the plan file as it stands, and into every plan this
/// process renders after.
pub fn request_refresh(now: u64) {
    REFRESH.store(now, std::sync::atomic::Ordering::SeqCst);
    refresh_plan_file(&plan_path(), now);
}

/// Put `refresh=<now>` into the plan at `path`, replacing an earlier one.
fn refresh_plan_file(path: &str, now: u64) {
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    if text.is_empty() {
        return;
    }
    let mut out: String = text.lines().filter(|l| !l.starts_with("refresh=")).map(|l| format!("{l}\n")).collect();
    out.push_str(&format!("refresh={now}\n"));
    let tmp = format!("{path}.tmp");
    if std::fs::write(&tmp, out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// The machine key an anchor admitted for `node`, read from the leased hint
/// held for it.
///
/// This is how a node whose trust store was written once, at install —
/// a device-tier board, typically — comes to recognise a server enrolled
/// after it: the server's lease is bound by its hardware key, and an anchor's
/// authorization admits that key for that node at that tier. Both are checked
/// again here, at the moment of use, not only when the lease arrived. Only on
/// a locked overlay: without anchors nothing but the trust store vouches for a
/// machine. Ed25519 only, because that is what a membership ping is signed
/// with.
pub fn admitted_key(
    m: &furcate_membership::Membership,
    anchors: &furcate_net::lock::Anchors,
    node: &str,
    now: u64,
) -> Option<ed25519_dalek::VerifyingKey> {
    if !anchors.state().is_locked() {
        return None;
    }
    let h: Hint = m
        .rumours()
        .current(now)
        .into_iter()
        .find(|r| r.origin == node)
        .and_then(|r| serde_json::from_value(r.body.clone()).ok())?;
    if h.node_id != node {
        return None;
    }
    furcate_net::lease::verify_hint(anchors, &h, now, lease_ceiling()).ok()?;
    let hexkey = h.lease.as_ref()?.node_key.strip_prefix("ed25519:")?.to_string();
    let bytes: [u8; 32] = hex::decode(hexkey).ok()?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

/// What this node repeats to the next member it talks to.
pub fn gossip_out(m: &furcate_membership::Membership, now: u64) -> serde_json::Value {
    serde_json::Value::Array(m.rumours().current(now).into_iter().map(|r| r.body.clone()).collect())
}

/// Leased hints held from gossip, for the overlay to merge with the
/// coordinator's.
pub fn gossip_hints(m: &furcate_membership::Membership, me: &str, now: u64) -> Vec<Hint> {
    m.rumours()
        .current(now)
        .into_iter()
        .filter(|r| r.origin != me)
        .filter_map(|r| serde_json::from_value(r.body.clone()).ok())
        .collect()
}

fn read_state() -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(STATE_PATH).ok()?).ok()
}

fn load_held_from(path: &str) -> Vec<Peer> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_held(peers: &[Peer], path: &str) {
    if let Some(d) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Ok(t) = serde_json::to_string_pretty(peers) {
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, t).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// Whether a privileged call may come from this origin, judged by the tiers
/// of the peers this node carries now.
///
/// Read from the held peer set per call: privileged calls are rare, and a
/// cached copy would keep refusing or admitting a peer after its tier changed.
pub fn may_originate(
    from: Option<std::net::IpAddr>,
    principal: Option<&furcate_authn::Principal>,
) -> Result<(), String> {
    may_originate_among(&load_held_from(&held_path_for(&plan_path())), from, principal)
}

pub fn may_originate_among(
    peers: &[Peer],
    from: Option<std::net::IpAddr>,
    principal: Option<&furcate_authn::Principal>,
) -> Result<(), String> {
    let machine = principal
        .filter(|p| p.class == furcate_authn::Class::Machine)
        .map(|p| p.id.as_str());
    match furcate_net::overlay::refuse_privileged(peers, from, machine) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

/// Render the plan the privileged half applies.
///
/// Separated from writing it so the format is testable without a filesystem,
/// and because this file is the entire contract between two halves that are in
/// different languages and neither of which imports the other.
pub fn render_plan(iface: &str, address: &str, port: u16, current: &wg::Interface) -> String {
    let mut s = format!("iface={iface}\naddress={address}\nport={port}\n");
    for p in &current.peers {
        // A single line per peer, positional, with `-` standing in for an
        // absent endpoint. An empty field would shift every later value along
        // by one and silently set a keepalive as an address.
        s.push_str(&format!(
            "peer={} {} {} {}\n",
            p.public_key,
            p.allowed_ips,
            p.endpoint.as_deref().unwrap_or("-"),
            p.keepalive_secs
        ));
    }
    let refresh = REFRESH.load(std::sync::atomic::Ordering::SeqCst);
    if refresh > 0 {
        s.push_str(&format!("refresh={refresh}\n"));
    }
    s
}

/// Resolve, persist and publish a peer set.
///
/// `admits` is the local authorisation decision. It is a closure so this
/// function cannot accidentally acquire the ability to make it.
pub fn reconcile<F>(hints: &[Hint], address: &str, now: u64, admits: F) -> OverlayReport
where
    F: FnMut(&Hint) -> Result<(), String>,
{
    reconcile_at(&plan_path(), hints, address, now, admits)
}

/// The same, against a named plan file.
///
/// Split from [`reconcile`] so tests can use their own paths. Two tests setting
/// one environment variable in the same binary race, and this codebase has now
/// learned that three times — once for backup specs, once for actuation
/// results, and once here, where the race made a read look like it was writing.
pub fn reconcile_at<F>(
    plan: &str,
    hints: &[Hint],
    address: &str,
    now: u64,
    admits: F,
) -> OverlayReport
where
    F: FnMut(&Hint) -> Result<(), String>,
{
    let iface = std::env::var("FURCATE_WG_IFACE").unwrap_or_else(|_| "fur0".into());
    let port = std::env::var("FURCATE_WG_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(wg::DEFAULT_PORT);

    let held = load_held_from(&held_path_for(plan));
    let Resolution { peers, refused, retained } = resolve(hints, &held, now, admits);
    let state = read_state();
    let peers = if punching_enabled() {
        steer(peers, state.as_ref(), &relays(), now)
    } else {
        peers
    };
    let for_exposure = peers.clone();

    let desired = wg::interface_for(&iface, address, port, &peers);
    let body = render_plan(&iface, address, port, &desired);

    // Written even when nothing changed: the privileged half compares the whole
    // body and does nothing when it matches, and a plan that disappeared would
    // read as an instruction to tear the interface down.
    if let Some(d) = std::path::Path::new(plan).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = format!("{plan}.tmp");
    if std::fs::write(&tmp, &body).is_ok() {
        let _ = std::fs::rename(&tmp, plan);
    }
    save_held(&peers, &held_path_for(plan));

    let available = state
        .as_ref()
        .and_then(|s| s.get("ok"))
        .and_then(|o| o.as_bool())
        .unwrap_or(false);
    let last_handshake_secs = state
        .as_ref()
        .and_then(|s| s.get("latest_handshake"))
        .and_then(|h| h.as_u64())
        .filter(|h| *h > 0)
        .map(|h| now.saturating_sub(h));

    OverlayReport {
        public_key: state
            .as_ref()
            .and_then(|s| s.get("public_key"))
            .and_then(|k| k.as_str())
            .map(String::from)
            .filter(|k| wg::is_key(k)),
        interface: Some(iface),
        address: Some(address.to_string()),
        peers,
        refused,
        retained,
        last_handshake_secs,
        why_unavailable: (!available)
            .then(|| {
                state
                    .as_ref()
                    .and_then(|s| s.get("why"))
                    .and_then(|w| w.as_str())
                    .unwrap_or("the privileged overlay helper has not reported yet")
                    .to_string()
            }),
        available,
        exposure: local_segment()
            .map(|seg| furcate_net::overlay::exposure(&for_exposure, &seg))
            .unwrap_or(furcate_net::overlay::Exposure::Unknown),
    }
}

/// What the overlay currently looks like, without changing it.
///
/// Split from [`reconcile`] because the observation endpoint was calling that
/// with an empty hint set — which rewrote the plan, rewrote the held peer file,
/// bypassed policy through a permissive closure, and reported every peer as
/// `retained` because none had been supplied. A read that mutates is bad
/// enough; one that mutates toward looking like a coordinator outage is worse,
/// since that is the exact state an operator would be checking for.
pub fn status() -> OverlayReport {
    status_at(&plan_path())
}

/// The same, against a named plan file.
pub fn status_at(plan: &str) -> OverlayReport {
    let held = load_held_from(&held_path_for(plan));
    let held_for_exposure = held.clone();
    let state = read_state();
    let available = state
        .as_ref()
        .and_then(|s| s.get("ok"))
        .and_then(|o| o.as_bool())
        .unwrap_or(false);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    OverlayReport {
        public_key: state
            .as_ref()
            .and_then(|s| s.get("public_key"))
            .and_then(|k| k.as_str())
            .map(String::from)
            .filter(|k| wg::is_key(k)),
        interface: Some(std::env::var("FURCATE_WG_IFACE").unwrap_or_else(|_| "fur0".into())),
        address: std::env::var("FURCATE_OVERLAY_ADDR").ok(),
        // Reported as held, because that is what they are. Whether each came
        // from a hint or was retained is a property of the last reconciliation,
        // and it is preserved rather than recomputed from nothing.
        retained: held.iter().filter(|p| p.source == Source::Retained).count(),
        peers: held,
        refused: Vec::new(),
        last_handshake_secs: state
            .as_ref()
            .and_then(|s| s.get("latest_handshake"))
            .and_then(|h| h.as_u64())
            .filter(|h| *h > 0)
            .map(|h| now.saturating_sub(h)),
        why_unavailable: (!available).then(|| {
            state
                .as_ref()
                .and_then(|s| s.get("why"))
                .and_then(|w| w.as_str())
                .unwrap_or("the privileged overlay helper has not reported yet")
                .to_string()
        }),
        available,
        exposure: local_segment()
            .map(|seg| furcate_net::overlay::exposure(&held_for_exposure, &seg))
            .unwrap_or(furcate_net::overlay::Exposure::Unknown),
    }
}

/// The rules this node uses to decide which peers it will carry.
///
/// This is the half of the design that the coordinator does not get to
/// influence, so it is loaded the same way every other authority decision on
/// this site is: deny-by-default rules as data, from a file the operator owns.
///
/// A node with no policy file falls back to the compiled defaults rather than
/// admitting everything. An overlay that opened up when its configuration went
/// missing would have the failure mode this whole arrangement exists to avoid.
pub fn load_policy() -> furcate_policy::PolicySet {
    // `super::`, not `crate::`: the lite binary includes this whole tree as a
    // module, so a crate-root path resolves to a different place in each build.
    super::policyfile::load()
}

/// Turn a hint into a policy question and ask it.
///
/// The capability is `join` and the resource is the tier the peer was admitted
/// at, so a rule can say *this site carries platform and attested peers and not
/// soft ones* in the same vocabulary as everything else — rather than that
/// distinction living in an `if` somewhere, which is where it started.
/// Where a node keeps the keys it will accept an admission from.
///
/// Not written by the coordinator and not fetched from it. A trust set the
/// coordinator can add to is one it can add itself to.
pub const ANCHORS_PATH: &str = "/etc/furcate/overlay-anchors.json";

/// Load the anchors, or hold none.
///
/// A missing file is an unlocked overlay, which is a supported state that says
/// so on the screen. A file that is present and unreadable is **not** treated
/// as absent: silently downgrading to unlocked because a parse failed is how a
/// site ends up believing in a check that stopped running.
pub fn anchors() -> Result<furcate_net::lock::Anchors, String> {
    furcate_net::lock::Anchors::read(ANCHORS_PATH)
}

/// Where this machine keeps the authorization an operator issued it.
pub const AUTHORIZATION_PATH: &str = "/etc/furcate/overlay-authorization.json";

/// The authorization this machine publishes about itself, if it has one.
///
/// A missing file is the ordinary case on an unlocked overlay and is not an
/// error here — the refusal belongs on the receiving side, where the anchors
/// are, because that is the only place that knows whether one was required.
pub fn self_authorization() -> Option<furcate_net::lock::Authorization> {
    let text = std::fs::read_to_string(AUTHORIZATION_PATH).ok()?;
    match serde_json::from_str(&text) {
        Ok(a) => Some(a),
        Err(e) => {
            // Loud, because the machine will silently stop being admitted
            // everywhere and the cause is one malformed file.
            eprintln!("furcated: {AUTHORIZATION_PATH} is present and unreadable ({e}); this machine will publish no authorization");
            None
        }
    }
}

/// How much life is left in this machine's own authorization.
///
/// Read from the file rather than from what the coordinator echoes back, so
/// this stays true on a machine that has stopped being admitted — which is
/// exactly when somebody needs to know why.
pub fn self_standing(now: u64) -> Option<furcate_net::lock::Standing> {
    self_authorization()
        .map(|a| furcate_net::lock::standing(a.not_after, now, furcate_net::lock::NOTICE))
}

pub fn admits(
    policy: &furcate_policy::PolicySet,
    anchors: &furcate_net::lock::Anchors,
    me: &str,
    h: &Hint,
    now: u64,
) -> Result<(), String> {
    // A node never carries itself: it would configure its own key as a peer and
    // the interface would refuse to load. Structural, so it is checked before
    // policy rather than expressed as a rule somebody could delete.
    if h.node_id == me {
        return Err("that is this node".into());
    }
    if !wg::is_key(&h.public_key) {
        return Err("not a wireguard key".into());
    }

    // Before policy, because policy decides on the strength of `tier` and the
    // coordinator is the one asserting it. Checking afterwards would mean the
    // decision had already been made on an unverified claim.
    //
    // A leased hint is checked through its hardware key; any other exactly as
    // it always was. One function, shared with gossip and the allocator.
    furcate_net::lease::verify_hint(anchors, h, now, lease_ceiling())?;

    let ask = furcate_policy::Request {
        principal: format!("peer:{}", h.node_id),
        action: "join".into(),
        resource: format!("tier:{}", h.tier.as_str()),
        // A peer asking to join is a machine, not a person, and holds no roles.
        // Its authority comes from the tier it proved, which is the resource.
        roles: Vec::new(),
    };
    let d = policy.evaluate(&ask, now);
    if d.allowed {
        Ok(())
    } else {
        Err(d.because)
    }
}

/// The local segment, for judging exposure.
///
/// Read from the interface the default route uses rather than declared, so a
/// machine that is moved onto a different network reassesses on its own.
fn local_segment() -> Option<String> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    let iface = route
        .lines()
        .skip(1)
        .find_map(|l| {
            let mut f = l.split_whitespace();
            let i = f.next()?;
            (f.next()? == "00000000").then(|| i.to_string())
        })?;
    let addr = local_endpoint_addr("192.0.2.1")?;
    // The prefix is not in /proc/net/route in a form worth decoding for this,
    // and the question is coarse. A /24 is the overwhelmingly common case on a
    // rack segment, and anything else answers `Unknown` rather than guessing.
    let _ = iface;
    Some(format!("{addr}/24"))
}

/// The address a peer should dial to reach this machine.
///
/// Found by opening a UDP socket toward the site and asking the kernel which
/// local address it chose. Nothing is sent — `connect` on a datagram socket
/// only sets a default destination — so this costs one syscall and no traffic.
///
/// The alternative is enumerating interfaces, which means netlink, which the
/// agent's sandbox blocks: `RestrictAddressFamilies` does not include
/// `AF_NETLINK`, and widening it to learn one address would be the trade this
/// codebase has already declined four times. It also answers a worse question.
/// What a peer needs is not every address this machine holds; it is the one the
/// kernel would actually use, which is exactly what this returns.
pub fn local_endpoint_addr(toward: &str) -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect((toward, 9)).ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

/// Whether this node steers peer endpoints through hole punching and relays.
///
/// Off unless `FURCATE_OVERLAY_PUNCH=1`: it changes which address WireGuard
/// sends to, which is a change to the host's networking, and that is enabled
/// per host by an operator rather than by installing a package. Off, every
/// peer's endpoint is its first listening address, exactly as before.
fn punching_enabled() -> bool {
    std::env::var("FURCATE_OVERLAY_PUNCH").map(|v| v == "1").unwrap_or(false)
}

/// Where this node's relay allocations are kept: peer node id to the relay
/// endpoint allocated for reaching it (`furcate-egress allocate|join` prints
/// it). This node's own choice — the relay was picked by its own measurements
/// — so it lives in this node's configuration, not in any hint.
pub const RELAYS_PATH: &str = "/etc/furcate/overlay-relays.json";

fn relays() -> std::collections::BTreeMap<String, String> {
    match std::fs::read(RELAYS_PATH) {
        Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|e| {
            eprintln!("{RELAYS_PATH} is not a map of node id to relay endpoint ({e}); no relays used");
            Default::default()
        }),
        Err(_) => Default::default(),
    }
}

/// Choose each peer's endpoint for this round. See `furcate_net::punch`.
///
/// Per-peer handshake times and current endpoints come from the privileged
/// half's report. A peer it has not reported on is treated as never having
/// answered, which starts the rotation from its first candidate — the address
/// it would have had anyway.
pub fn steer(
    mut peers: Vec<Peer>,
    state: Option<&serde_json::Value>,
    relays: &std::collections::BTreeMap<String, String>,
    now: u64,
) -> Vec<Peer> {
    use furcate_net::punch::{decide, Decision};
    let per = |field: &str, key: &str| state.and_then(|s| s.get(field)).and_then(|m| m.get(key)).cloned();
    for p in &mut peers {
        let age = per("handshakes", &p.public_key)
            .and_then(|v| v.as_u64())
            .filter(|t| *t > 0)
            .map(|t| now.saturating_sub(t));
        let current = per("endpoints", &p.public_key).and_then(|v| v.as_str().map(String::from));
        let candidates = if p.candidates.is_empty() {
            p.endpoint.iter().cloned().collect()
        } else {
            p.candidates.clone()
        };
        match decide(&candidates, relays.get(&p.node_id).map(String::as_str), age, current.as_deref(), now) {
            Decision::NoPath(_) => {}
            d => p.endpoint = d.endpoint().map(String::from),
        }
    }
    peers
}

/// Addresses reflectors see this node at, paired with WireGuard's port.
///
/// Asked of the reflectors in `FURCATE_OVERLAY_REFLECTORS` (comma-separated
/// HOST:PORT), at most every five minutes; none configured, none asked. A
/// reflector that does not answer is logged and skipped, and an empty answer
/// publishes nothing rather than a guess.
pub fn observed_endpoints(wg_port: u16, now: u64) -> Vec<String> {
    use std::net::ToSocketAddrs;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(u64, Vec<String>)>> = Mutex::new(None);
    let list = std::env::var("FURCATE_OVERLAY_REFLECTORS").unwrap_or_default();
    if list.trim().is_empty() {
        return Vec::new();
    }
    if let Ok(c) = CACHE.lock() {
        if let Some((at, v)) = c.as_ref() {
            if now.saturating_sub(*at) < 300 {
                return v.clone();
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for r in list.split(',').map(str::trim).filter(|r| !r.is_empty()) {
        let Some(target) = r.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
            eprintln!("overlay: reflector {r} does not resolve");
            continue;
        };
        let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        match std::net::UdpSocket::bind(bind)
            .and_then(|s| furcate_net::punch::observe(&s, target, std::time::Duration::from_secs(2)))
        {
            Ok(seen) => {
                let e = furcate_net::punch::observed_endpoint(seen, wg_port);
                if !out.contains(&e) {
                    out.push(e);
                }
            }
            Err(e) => eprintln!("overlay: reflector {r}: {e}"),
        }
    }
    if let Ok(mut c) = CACHE.lock() {
        *c = Some((now, out.clone()));
    }
    out
}

/// The name this machine gives itself on the overlay.
///
/// `FURCATE_NODE_NAME` when it is set — the name the operator gave this node,
/// and the one everything else here already calls it — and the short host
/// name only when it is not. A configured name that is not a usable label is
/// refused with the reason and the node publishes no name, rather than
/// quietly publishing the host name instead: a node answering to a name
/// nobody configured is how a lookup reaches the wrong machine. Either way the
/// node still resolves under its id-derived label, which is the one a
/// signature covers.
pub fn local_name() -> Option<String> {
    let configured = std::env::var("FURCATE_NODE_NAME").ok();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").ok();
    match choose_name(configured.as_deref(), host.as_deref()) {
        Ok(n) => n,
        Err(why) => {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("overlay: publishing no name: {why}"));
            None
        }
    }
}

/// The decision behind [`local_name`], without the environment.
pub fn choose_name(configured: Option<&str>, hostname: Option<&str>) -> Result<Option<String>, String> {
    match configured.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => furcate_net::names::node_name(c)
            .map(Some)
            .map_err(|e| format!("FURCATE_NODE_NAME {e}")),
        None => Ok(hostname
            .and_then(|h| h.trim().split('.').next())
            .and_then(|s| furcate_net::names::node_name(s).ok())),
    }
}

/// Record what this node publishes about itself beside the peer set, for the
/// names service. Written only when it changes.
pub fn save_own(h: &Hint) {
    save_own_at(&held_path_for(&plan_path()), h)
}

pub fn save_own_at(peers_path: &str, h: &Hint) {
    let own = furcate_net::names::Own { node_id: h.node_id.clone(), name: h.name.clone() };
    let path = furcate_net::names::own_path_for(peers_path);
    let Ok(body) = serde_json::to_vec_pretty(&own) else { return };
    if std::fs::read(&path).ok().as_deref() == Some(body.as_slice()) {
        return;
    }
    let tmp = format!("{path}.tmp");
    if let Err(e) = std::fs::write(&tmp, &body).and_then(|_| std::fs::rename(&tmp, &path)) {
        eprintln!("overlay: cannot record this node's own entry at {path}: {e}");
    }
}

/// This node's own hint, for the coordinator to pass on.
///
/// Published rather than discovered: a node knows its own key and the addresses
/// it listens on, and having the coordinator infer them from connection source
/// addresses would make the mesh depend on the coordinator being on the same
/// path as the peers.
pub fn self_hint(
    node_id: &str,
    address: &str,
    endpoints: Vec<String>,
    observed: Vec<String>,
    tier: Tier,
    now: u64,
) -> Option<Hint> {
    let state = read_state()?;
    let key = state.get("public_key")?.as_str()?;
    // Only on a node whose privileged half runs leased keys. Every other node
    // publishes exactly what it did before.
    let lease = match (reported_lease(&state), LEASE_SIGNER.get()) {
        (None, _) => None,
        (Some(until), Some(s)) => lease_binding(s.as_ref(), node_id, key, tier, until, now),
        (Some(_), None) => {
            eprintln!("furcated: WARNING overlay: the overlay key is leased and this node has no signer to bind it; peers will refuse it");
            None
        }
    };
    wg::is_key(key).then(|| Hint {
        node_id: node_id.to_string(),
        public_key: key.to_string(),
        endpoints,
        overlay_addr: address.to_string(),
        tier,
        seen_at: now, lease, authorization: None,
        name: local_name(),
        observed,
    })
}

/// The WireGuard public key the kernel holds now, as the privileged half
/// last reported it.
pub fn kernel_key() -> Option<String> {
    read_state()?.get("public_key")?.as_str().filter(|k| wg::is_key(k)).map(str::to_string)
}

/// The port leased nodes announce a new key on, over the underlay.
///
/// `FURCATE_OVERLAY_ANNOUNCE_PORT`, the same on every node of a site, because
/// a node announces to its peers' host addresses on this port. `0` turns the
/// path off on this node: it neither listens nor announces, and a leased key
/// that changes then reaches peers only through the coordinator or gossip.
/// A value that is not a port is refused rather than guessed at.
pub fn announce_port() -> Result<Option<u16>, String> {
    match std::env::var("FURCATE_OVERLAY_ANNOUNCE_PORT") {
        Err(_) => Ok(Some(furcate_net::announce::DEFAULT_PORT)),
        Ok(v) => match v.trim().parse::<u16>() {
            Ok(0) => Ok(None),
            Ok(p) => Ok(Some(p)),
            Err(_) => Err(format!(
                "FURCATE_OVERLAY_ANNOUNCE_PORT is `{v}`; it must be a port, or 0 to turn announcements off"
            )),
        },
    }
}

/// The longest wait between announcements to a peer that does not handshake,
/// from `FURCATE_OVERLAY_ANNOUNCE_MAX` (seconds), else one minute. A value
/// that is not a number is reported and the default used: this only paces a
/// retry, and refusing to announce at all would be the worse failure.
pub fn announce_max_interval() -> u64 {
    match std::env::var("FURCATE_OVERLAY_ANNOUNCE_MAX") {
        Err(_) => furcate_net::announce::DEFAULT_MAX_INTERVAL,
        Ok(v) => v.trim().parse::<u64>().unwrap_or_else(|_| {
            eprintln!(
                "furcated: WARNING FURCATE_OVERLAY_ANNOUNCE_MAX is `{v}`, not a number of seconds; using {}",
                furcate_net::announce::DEFAULT_MAX_INTERVAL
            );
            furcate_net::announce::DEFAULT_MAX_INTERVAL
        }),
    }
}

/// How often this node looks for a change of its own underlay address, from
/// `FURCATE_OVERLAY_LINK_POLL` (seconds, 1 to 60), else 5.
pub fn link_poll_interval() -> u64 {
    match std::env::var("FURCATE_OVERLAY_LINK_POLL") {
        Err(_) => 5,
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(n) => n.clamp(1, 60),
            Err(_) => {
                eprintln!("furcated: WARNING FURCATE_OVERLAY_LINK_POLL is `{v}`, not a number of seconds; using 5");
                5
            }
        },
    }
}

/// Where to announce this node's key: the host of each peer this node holds
/// that has not handshaken recently, from the kernel's live endpoints and the
/// held peer set (which came from the coordinator's plan or a peer's lease).
pub fn announce_targets(port: u16, now: u64) -> Vec<std::net::SocketAddr> {
    announce_targets_from(read_state().as_ref(), &load_held_from(&held_path_for(&plan_path())), port, now)
}

pub fn announce_targets_from(
    state: Option<&serde_json::Value>,
    held: &[Peer],
    port: u16,
    now: u64,
) -> Vec<std::net::SocketAddr> {
    let map = |k: &str| -> std::collections::BTreeMap<String, serde_json::Value> {
        state
            .and_then(|s| s.get(k))
            .and_then(|v| v.as_object())
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    };
    let handshakes: std::collections::BTreeMap<String, u64> =
        map("handshakes").into_iter().filter_map(|(k, v)| v.as_u64().map(|t| (k, t))).collect();
    let live: Vec<(String, String)> = map("endpoints")
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|e| (k, e.to_string())))
        .collect();
    let pairs: Vec<(&str, &str)> = live
        .iter()
        .map(|(k, e)| (k.as_str(), e.as_str()))
        .chain(held.iter().filter_map(|p| p.endpoint.as_deref().map(|e| (p.public_key.as_str(), e))))
        .collect();
    // Only handshakes under the current key count; one made under the key
    // before it is what a peer still holding the old key would show.
    let born = state.and_then(|s| s.get("key_born_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    furcate_net::announce::targets(pairs, &handshakes, born, port, now)
}

/// This node's leased hint, signed for announcing, by the key that bound its
/// lease. Refused when the key is not leased or the signer is not set.
pub fn announcement(h: &Hint, now: u64) -> Result<Vec<u8>, String> {
    let signer = LEASE_SIGNER
        .get()
        .ok_or_else(|| "this node has no signer for its lease, so it has nothing to announce with".to_string())?;
    furcate_net::announce::seal(signer.as_ref(), h, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_tier_peer_is_refused_on_privileged_routes_and_orders() {
        use furcate_api::{Request, Response, Router};
        use furcate_authn::local::MachineSigner;
        use std::sync::Arc;

        let pi_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
        let peer = |id: &str, addr: &str, tier: Tier| Hint {
            node_id: id.into(),
            public_key: format!("{id}-pubkey"),
            endpoints: vec![],
            overlay_addr: addr.into(),
            tier,
            seen_at: 0,
            lease: None,
            authorization: None,
            name: None,
            observed: vec![],
        };
        let peers = resolve(
            &[peer("pi-gw", "10.90.0.40/32", Tier::Device), peer("node-a", "10.90.0.10/32", Tier::Platform)],
            &[],
            0,
            |_| Ok(()),
        )
        .peers;
        assert_eq!(peers.len(), 2, "a device-tier peer is still carried");

        let devices = furcate_authn::device::DeviceVerifier::new(vec![
            ("pi-gw".into(), pi_key.verifying_key(), false),
            ("node-a".into(), server_key.verifying_key(), false),
        ]);
        let held = peers.clone();
        let ran = |what: &'static str| move |_: &Request| Response::ok(serde_json::json!({ "ran": what }));
        let r = Router::new()
            .verified_by(Arc::new(devices))
            .originating(Arc::new(move |from, p| may_originate_among(&held, from, p)))
            .guarded("POST", "/workloads/restart", ran("restart"))
            .carrying_order("POST", "/orders", ran("order"))
            .carrying_proof("POST", "/cells/rollup", ran("rollup"))
            .reporting("POST", "/health/signal", ran("reading"));

        let now = 1_000;
        let call = |who: &str, key: &ed25519_dalek::SigningKey, path: &str| Request {
            method: "POST".into(),
            path: path.into(),
            raw_body: b"{}".to_vec(),
            credential: Some(MachineSigner::new(who, key.clone()).credential("POST", path, b"{}", now)),
            ..Default::default()
        };
        let pi_addr = Some("10.90.0.40".parse().unwrap());
        let lan = Some("192.168.1.20".parse().unwrap());
        let server_addr = Some("10.90.0.10".parse().unwrap());

        // Its own valid credential, over the overlay or from anywhere else.
        let res = r.dispatch_from(&call("pi-gw", &pi_key, "/workloads/restart"), pi_addr, now);
        assert_eq!(res.status, 403, "{}", res.body);
        assert!(res.body.to_string().contains("device-tier"), "{}", res.body);
        assert_eq!(r.dispatch_from(&call("pi-gw", &pi_key, "/workloads/restart"), lan, now).status, 403);
        // An order relayed from its overlay address.
        assert_eq!(r.dispatch_from(&call("pi-gw", &pi_key, "/orders"), pi_addr, now).status, 403);

        // What it is for still goes through.
        assert_eq!(r.dispatch_from(&call("pi-gw", &pi_key, "/cells/rollup"), pi_addr, now).status, 200);
        assert_eq!(r.dispatch_from(&call("pi-gw", &pi_key, "/health/signal"), pi_addr, now).status, 200);

        // A platform-tier peer is unchanged.
        assert_eq!(r.dispatch_from(&call("node-a", &server_key, "/workloads/restart"), server_addr, now).status, 200);
        assert_eq!(r.dispatch_from(&call("node-a", &server_key, "/orders"), server_addr, now).status, 200);
    }

    /// The overlay these tests are about: no anchors, so admission turns on
    /// policy alone. The locked path is exercised in `furcate_net::lock`.
    fn unlocked() -> furcate_net::lock::Anchors {
        furcate_net::lock::Anchors::new()
    }

    #[test]
    fn a_locked_overlay_refuses_a_hint_the_coordinator_made_up() {
        // The integration assertion. `furcate_net::lock` proves the signature
        // check; this proves the check sits in the path a hint actually
        // travels, ahead of the policy that would otherwise decide on the
        // coordinator's unverified word.
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut anchors = furcate_net::lock::Anchors::new();
        anchors
            .trust(&furcate_net::lock::Anchor {
                key_id: "operator".into(),
                public_key: hex::encode(signing.verifying_key().to_bytes()),
            })
            .unwrap();

        let policy = furcate_policy::PolicySet::compiled_default();
        let mut h = Hint {
            node_id: "other".into(),
            public_key: KEY.into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.40/32".into(),
            tier: Tier::Attested,
            seen_at: 0, lease: None,
            authorization: None,
            name: None,
            observed: vec![],
        };

        // Unsigned. Policy would have admitted this exact hint — and it never
        // reaches policy.
        assert!(admits(&policy, &unlocked(), "me", &h, 1_000).is_ok(), "unlocked admits it");
        let refused = admits(&policy, &anchors, "me", &h, 1_000).expect_err("locked must refuse");
        assert!(refused.contains("no authorization"), "{refused}");

        // Signed by the operator, for this key on this tier.
        h.authorization = Some(furcate_net::lock::authorize(
            "operator",
            &signing,
            &furcate_net::lock::Claim {
                node_id: &h.node_id,
                public_key: &h.public_key,
                tier: h.tier.as_str(),
                not_after: 9_999,
            },
        ));
        assert!(admits(&policy, &anchors, "me", &h, 1_000).is_ok());

        // The same authorization, reused on a different tier.
        h.tier = Tier::Soft;
        assert!(admits(&policy, &anchors, "me", &h, 1_000).is_err(), "a tier swap must not verify");
    }

    const KEY: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";

    fn peer(id: &str, endpoint: Option<&str>) -> wg::WgPeer {
        wg::WgPeer {
            public_key: KEY.into(),
            endpoint: endpoint.map(String::from),
            allowed_ips: format!("10.90.0.{}/32", id.len() * 10),
            keepalive_secs: 25,
        }
    }

    fn iface(peers: Vec<wg::WgPeer>) -> wg::Interface {
        wg::Interface {
            name: "fur0".into(),
            address: "10.90.0.10/16".into(),
            listen_port: 51820,
            peers,
        }
    }

    #[test]
    fn the_plan_is_what_the_shell_half_parses() {
        // The only thing holding two halves in different languages to one
        // format, neither of which imports the other.
        let p = render_plan("fur0", "10.90.0.10/16", 51820, &iface(vec![peer("a", Some("1.2.3.4:51820"))]));
        assert!(p.starts_with("iface=fur0\naddress=10.90.0.10/16\nport=51820\n"));
        assert!(p.contains(&format!("peer={KEY} 10.90.0.10/32 1.2.3.4:51820 25\n")));
    }

    #[test]
    fn an_absent_endpoint_is_a_placeholder_not_an_empty_field() {
        // An empty field would shift every later value along by one and set a
        // keepalive as an address.
        let p = render_plan("fur0", "10.90.0.10/16", 51820, &iface(vec![peer("a", None)]));
        let line = p.lines().find(|l| l.starts_with("peer=")).unwrap();
        assert_eq!(line.split_whitespace().count(), 4, "got {line:?}");
        assert!(line.contains(" - "));
    }

    #[test]
    fn every_plan_line_is_a_directive_the_other_half_knows() {
        let p = render_plan("fur0", "10.90.0.10/16", 51820, &iface(vec![peer("a", None)]));
        for line in p.lines() {
            let key = line.split('=').next().unwrap();
            assert!(
                matches!(key, "iface" | "address" | "port" | "peer" | "remove"),
                "{line:?} is not a directive"
            );
        }
    }

    #[test]
    fn reading_the_status_does_not_change_it() {
        // The endpoint used to reconcile with an empty hint set, which rewrote
        // the plan and reported every peer as retained — the exact state an
        // operator checking it would be looking for.
        let dir = std::env::temp_dir().join("furcate-overlay-status-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wg-plan");
        let _ = std::fs::remove_file(&path);

        status_at(path.to_str().unwrap());
        assert!(!path.exists(), "reading must not write a plan");
    }

    #[test]
    fn steering_keeps_a_live_path_and_rotates_a_dead_one() {
        let mut p = Peer {
            node_id: "far".into(),
            public_key: KEY.into(),
            endpoint: Some("192.168.1.9:51820".into()),
            overlay_addr: "10.90.0.40/32".into(),
            tier: Tier::Platform,
            source: Source::Hint,
            resolved_at: 0,
            name: None,
            valid_until: None,
            lease_until: None,
            candidates: vec!["192.168.1.9:51820".into(), "203.0.113.4:51820".into()],
        };
        let now = 999_990; // the start of a 30 s cycle: two candidates, 15 s each
        let live = serde_json::json!({
            "handshakes": { KEY: now - 10 },
            "endpoints": { KEY: "198.51.100.3:40000" },
        });
        let out = steer(vec![p.clone()], Some(&live), &Default::default(), now);
        assert_eq!(out[0].endpoint.as_deref(), Some("198.51.100.3:40000"), "the roamed address is kept");

        let dead = serde_json::json!({ "handshakes": { KEY: now - 600 } });
        let out = steer(vec![p.clone()], Some(&dead), &Default::default(), now + 15);
        assert_eq!(out[0].endpoint.as_deref(), Some("203.0.113.4:51820"), "the next candidate gets its window");

        p.candidates.clear();
        p.endpoint = None;
        let out = steer(vec![p], None, &Default::default(), now);
        assert_eq!(out[0].endpoint, None, "no address and no relay is left unset, not invented");
    }

    #[test]
    fn admission_refuses_a_peer_no_rule_covers() {
        // Deny by default, from the engine rather than from an `if`.
        let p = furcate_policy::PolicySet { policies: vec![] };
        let h = Hint {
            node_id: "other".into(),
            public_key: KEY.into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.40/32".into(),
            tier: Tier::Attested,
            seen_at: 0, lease: None, authorization: None, name: None, observed: vec![],
        };
        assert!(admits(&p, &unlocked(), "me", &h, 0).is_err());
        assert!(admits(&furcate_policy::PolicySet::compiled_default(), &unlocked(), "me", &h, 0).is_ok());
    }

    #[test]
    fn a_node_never_carries_itself() {
        // It would configure its own key as a peer and the interface would
        // refuse to load. Checked before policy, so it is not a rule somebody
        // could delete.
        let h = Hint {
            node_id: "me".into(),
            public_key: KEY.into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.10/32".into(),
            tier: Tier::Attested,
            seen_at: 0, lease: None, authorization: None, name: None, observed: vec![],
        };
        assert!(admits(&furcate_policy::PolicySet::compiled_default(), &unlocked(), "me", &h, 0).is_err());
    }

    #[test]
    fn a_soft_peer_is_refused_by_the_default_rules() {
        let h = Hint {
            node_id: "pi".into(),
            public_key: KEY.into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.40/32".into(),
            tier: Tier::Soft,
            seen_at: 0, lease: None, authorization: None, name: None, observed: vec![],
        };
        let e = admits(&furcate_policy::PolicySet::compiled_default(), &unlocked(), "me", &h, 0).unwrap_err();
        assert!(e.contains("no rule permits"), "got {e}");
    }

    #[test]
    fn a_node_with_no_privileged_half_reports_unavailable_rather_than_empty() {
        // "No peers" and "the helper has never run" are different states, and
        // conflating them makes a broken deployment look like a quiet one.
        //
        // ⚠ reconcile_at, NOT reconcile. The bare form resolves plan_path(),
        // which on a real node is /var/lib/furcate/wg-plan -- so this test used
        // to REWRITE THE LIVE OVERLAY PLAN of whatever machine ran `cargo test`,
        // handing it the 10.90.0.10/16 written below. On node-b that is
        // node-a's address: the node took its neighbour's identity, traffic to
        // it routed to loopback, SeaweedFS replication silently fell to one
        // copy, and a database dump "succeeded" without leaving the disk. A test
        // must not be able to reconfigure the machine it runs on.
        let dir = std::env::temp_dir().join("furcate-overlay-unavailable-test");
        std::fs::create_dir_all(&dir).unwrap();
        let plan = dir.join("wg-plan");
        let plan = plan.to_str().unwrap();
        let r = reconcile_at(plan, &[], "10.90.0.10/16", 0, |_| Ok(()));
        if !r.available {
            assert!(r.why_unavailable.is_some());
            assert!(r.public_key.is_none());
        }
    }

    #[test]
    fn a_plan_is_written_even_when_nothing_changed() {
        // The privileged half compares the whole body and does nothing when it
        // matches. A plan that vanished would read as an instruction to tear
        // the interface down.
        let dir = std::env::temp_dir().join("furcate-overlay-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("wg-plan");
        let p = p.to_str().unwrap();
        reconcile_at(p, &[], "10.90.0.10/16", 0, |_| Ok(()));
        assert!(std::path::Path::new(p).exists());
        let first = std::fs::read_to_string(p).unwrap();
        reconcile_at(p, &[], "10.90.0.10/16", 0, |_| Ok(()));
        assert_eq!(first, std::fs::read_to_string(p).unwrap());
    }

    #[test]
    fn the_endpoint_is_the_address_the_kernel_would_actually_use() {
        // Not every address the machine holds — the one it would pick to reach
        // the peer, which is what the peer needs to dial back.
        let a = local_endpoint_addr("192.0.2.1").expect("a route to somewhere exists");
        assert!(a.parse::<std::net::Ipv4Addr>().is_ok(), "got {a}");
        assert_ne!(a, "0.0.0.0", "an unspecified address is not an endpoint");
    }

    #[test]
    fn an_unreachable_target_yields_no_endpoint_rather_than_a_wrong_one() {
        assert!(local_endpoint_addr("not a host").is_none());
    }

    #[test]
    fn the_configured_node_name_wins_over_the_host_name() {
        assert_eq!(choose_name(Some("node-e"), Some("node-e-c05d\n")).unwrap().as_deref(), Some("node-e"));
        assert_eq!(choose_name(Some("Node-a"), Some("alice-workstation")).unwrap().as_deref(), Some("node-a"));
        // Unset or empty: the short host name, as before.
        assert_eq!(choose_name(None, Some("node-c.lan\n")).unwrap().as_deref(), Some("node-c"));
        assert_eq!(choose_name(Some("  "), Some("node-c")).unwrap().as_deref(), Some("node-c"));
        assert_eq!(choose_name(None, Some("bad_host")).unwrap(), None);
    }

    #[test]
    fn a_configured_name_that_is_not_a_label_publishes_none_and_says_why() {
        // Not the host name in its place: refused, with the reason.
        let why = choose_name(Some("server_1"), Some("node-c")).unwrap_err();
        assert!(why.contains("FURCATE_NODE_NAME") && why.contains("not a DNS label"), "{why}");
    }

    #[test]
    fn the_own_entry_is_written_beside_the_peer_set_and_names_the_signed_id() {
        let dir = std::env::temp_dir().join(format!("furcate-own-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let peers = dir.join("wg-plan-peers.json").display().to_string();
        let h = Hint {
            node_id: "furcate:node:me".into(),
            public_key: KEY.into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.30/16".into(),
            tier: Tier::Platform,
            seen_at: 0, lease: None,
            authorization: None,
            name: Some("node-e".into()),
            observed: vec![],
        };
        save_own_at(&peers, &h);
        let own: furcate_net::names::Own =
            serde_json::from_slice(&std::fs::read(dir.join("wg-plan-self.json")).unwrap()).unwrap();
        assert_eq!(own, furcate_net::names::Own { node_id: "furcate:node:me".into(), name: Some("node-e".into()) });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_published_name_reaches_the_peer_and_never_changes_its_key() {
        // The name rides along with the hint into the peer; the key and the id
        // are the hint's, whatever the name says.
        let h = Hint {
            node_id: "furcate:node:other".into(),
            public_key: KEY.into(),
            endpoints: vec![],
            overlay_addr: "10.90.0.10/16".into(),
            tier: Tier::Platform,
            seen_at: 0, lease: None,
            authorization: None,
            name: Some("node-a".into()),
            observed: vec![],
        };
        let r = resolve(&[h], &[], 0, |_| Ok(()));
        assert_eq!(r.peers[0].name.as_deref(), Some("node-a"));
        assert_eq!(r.peers[0].public_key, KEY);
        assert_eq!(r.peers[0].node_id, "furcate:node:other");
    }

    #[test]
    fn a_node_that_cannot_read_its_own_key_publishes_no_hint() {
        // Publishing a hint with a missing or malformed key would put an entry
        // in every peer's configuration that fails to load.
        assert!(self_hint("n", "10.90.0.10/32", vec![], vec![], Tier::Platform, 0).is_none()
            || wg::is_key(&self_hint("n", "10.90.0.10/32", vec![], vec![], Tier::Platform, 0).unwrap().public_key));
    }
    const WG_A: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const WG_B: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn node_signer(seed: u8) -> furcate_identity::Ed25519Signer {
        furcate_identity::Ed25519Signer(std::sync::Arc::new(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])))
    }

    fn leased(signer: &dyn furcate_identity::MessageSigner, node: &str, key: &str, until: u64) -> Hint {
        let b = furcate_net::lease::bind(
            signer,
            &furcate_net::lease::Terms { node_id: node, wg_pub: key, tier: "platform", not_after: until, quote_digest: None },
        )
        .expect("signed");
        Hint {
            node_id: node.into(),
            public_key: key.into(),
            endpoints: vec!["192.0.2.9:51820".into()],
            overlay_addr: "10.90.0.40/32".into(),
            tier: Tier::Platform,
            seen_at: 0,
            lease: Some(b),
            authorization: None,
            name: None,
            observed: vec![],
        }
    }

    #[test]
    fn a_node_whose_privileged_half_keeps_its_key_publishes_no_lease() {
        // What every existing node reports: no `ephemeral` at all.
        let today = serde_json::json!({"ok": true, "public_key": WG_A, "peers": 0});
        assert_eq!(reported_lease(&today), None);
        let off = serde_json::json!({"ok": true, "public_key": WG_A, "ephemeral": false, "key_born_at": 10, "lease": 10});
        assert_eq!(reported_lease(&off), None);
        let on = serde_json::json!({"ok": true, "public_key": WG_A, "ephemeral": true, "key_born_at": 1000, "lease": 43200});
        assert_eq!(reported_lease(&on), Some(44_200));
    }

    #[test]
    fn a_lease_is_bound_once_and_a_lapsed_one_not_at_all() {
        let s = node_signer(5);
        let a = lease_binding(&s, "n1", WG_A, Tier::Platform, 5_000, 1_000).expect("bound");
        let again = lease_binding(&s, "n1", WG_A, Tier::Platform, 5_000, 2_000).expect("bound");
        assert_eq!(a, again);
        assert!(furcate_net::lease::check(&a, "n1", WG_A, "platform", 1_000, 86_400).is_ok());
        // A rotated key is bound afresh.
        let b = lease_binding(&s, "n1", WG_B, Tier::Platform, 9_000, 6_000).expect("bound");
        assert_ne!(a.signature, b.signature);
        // The privileged half did not rotate in time: nothing is signed.
        assert!(lease_binding(&s, "n1", WG_B, Tier::Platform, 9_000, 9_000).is_none());
    }

    #[test]
    fn gossip_carries_a_rotated_key_without_the_coordinator() {
        let pi = node_signer(7);
        let pi_key = furcate_policy::delegation::CellKey::of(&pi).unwrap().id();
        let trusted = |id: &str| (id == "pi").then(|| pi_key.clone());
        let open = furcate_net::lock::Anchors::new();
        let (mut a, mut b) = (
            furcate_membership::Membership::new("a", 3),
            furcate_membership::Membership::new("b", 3),
        );

        // The Pi rebooted with a new key and told `a`; `a` tells `b`.
        assert!(hold(&mut a, &leased(&pi, "pi", WG_A, 5_000), 100));
        assert_eq!(gossip_in(&mut b, "b", Some(&gossip_out(&a, 100)), &open, &trusted, 100), 1);
        assert_eq!(gossip_hints(&b, "b", 100)[0].public_key, WG_A);

        // Next lease, next key: replaces the first everywhere it travels.
        assert!(hold(&mut a, &leased(&pi, "pi", WG_B, 9_000), 4_000));
        assert_eq!(gossip_in(&mut b, "b", Some(&gossip_out(&a, 4_000)), &open, &trusted, 4_000), 1);
        let merged = furcate_net::overlay::merge(&[leased(&pi, "pi", WG_A, 5_000)], &gossip_hints(&b, "b", 4_000));
        assert_eq!(merged[0].public_key, WG_B);
    }

    #[test]
    fn gossip_from_an_unknown_or_tampered_source_is_not_held() {
        let pi = node_signer(7);
        let stranger = node_signer(8);
        let pi_key = furcate_policy::delegation::CellKey::of(&pi).unwrap().id();
        let trusted = |id: &str| (id == "pi").then(|| pi_key.clone());
        let open = furcate_net::lock::Anchors::new();
        let mut b = furcate_membership::Membership::new("b", 3);

        // Another machine's hardware claiming to be the Pi.
        let forged = serde_json::json!([leased(&stranger, "pi", WG_B, 5_000)]);
        assert_eq!(gossip_in(&mut b, "b", Some(&forged), &open, &trusted, 100), 0);
        // The Pi's real binding moved onto a different WireGuard key.
        let mut moved = leased(&pi, "pi", WG_A, 5_000);
        moved.public_key = WG_B.into();
        assert_eq!(gossip_in(&mut b, "b", Some(&serde_json::json!([moved])), &open, &trusted, 100), 0);
        // Expired.
        let old = serde_json::json!([leased(&pi, "pi", WG_A, 50)]);
        assert_eq!(gossip_in(&mut b, "b", Some(&old), &open, &trusted, 100), 0);
        assert!(b.rumours().is_empty());
    }

    /// A leased node restarts with a new key while its peer still carries the
    /// old one, and the only route it has to that peer is the underlay: its
    /// configured peers and site are overlay addresses, which need the new key
    /// first. It announces to the endpoint its own peer set holds, the peer
    /// takes the signed lease and carries the new key, with nothing typed by
    /// anyone and no overlay traffic at all.
    #[test]
    fn a_restarted_leased_node_rejoins_over_the_underlay_alone() {
        use furcate_identity::Ed25519Signer;
        use std::sync::Arc;

        const OLD: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        const NEW: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
        const NODE_B: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let operator = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let mut anchors = furcate_net::lock::Anchors::new();
        anchors
            .trust(&furcate_net::lock::Anchor {
                key_id: "op".into(),
                public_key: hex::encode(operator.verifying_key().to_bytes()),
            })
            .expect("an anchor");
        let node = Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])));
        let leased = |wg: &str, lease_end: u64| {
            let b = furcate_net::lease::bind(
                &node,
                &furcate_net::lease::Terms {
                    node_id: "edge-1",
                    wg_pub: wg,
                    tier: "platform",
                    not_after: lease_end,
                    quote_digest: None,
                },
            )
            .expect("bound");
            let auth = furcate_net::lock::authorize(
                "op",
                &operator,
                &furcate_net::lock::Claim {
                    node_id: "edge-1",
                    public_key: &b.node_key,
                    tier: "platform",
                    not_after: now + 30 * 86_400,
                },
            );
            Hint {
                node_id: "edge-1".into(),
                public_key: wg.into(),
                endpoints: vec!["127.0.0.1:51820".into()],
                overlay_addr: "10.90.0.40/32".into(),
                tier: Tier::Platform,
                seen_at: now,
                lease: Some(b),
                authorization: Some(auth),
                name: None,
                observed: vec![],
            }
        };
        let admit = |h: &Hint| furcate_net::lease::verify_hint(&anchors, h, now, lease_ceiling()).map(|_| ());

        let dir = std::env::temp_dir().join(format!("furcate-rejoin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plan = dir.join("wg-plan").display().to_string();

        // Before the restart: the coordinator's plan, and the peer, hold the
        // old key.
        let before = leased(OLD, now + 3_600);
        let coordinator = vec![before.clone()];
        let r = reconcile_at(&plan, &coordinator, "10.90.0.20/16", now, admit);
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].public_key, OLD);

        // The restart: a new key and a new lease. The coordinator cannot be
        // reached, so it goes on serving the old key.
        let after = leased(NEW, now + 43_200);

        // The restarted node's own view: the server it peers with, at the
        // endpoint its peer set holds, has not handshaken since the restart.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let port = peer.local_addr().unwrap().port();
        let state = serde_json::json!({
            "public_key": NEW,
            "handshakes": { NODE_B: 0 },
            "endpoints": { NODE_B: "127.0.0.1:51820" },
        });
        let targets = announce_targets_from(Some(&state), &[], port, now);
        assert_eq!(targets, vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))]);

        let datagram = furcate_net::announce::seal(&node, &after, now).expect("sealed by the node's key");
        let out = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for t in &targets {
            out.send_to(&datagram, t).unwrap();
        }
        // Resent, as the sender does in case the first was lost.
        out.send_to(&datagram, targets[0]).unwrap();

        // The peer's side.
        let mut m = furcate_membership::Membership::new("node-b", 10);
        let mut replay = furcate_net::announce::Replay::new();
        let none = |_: &str| None;
        let mut buf = vec![0u8; furcate_net::announce::MAX_DATAGRAM + 1];
        let (n, _) = peer.recv_from(&mut buf).expect("the announcement arrives");
        let h = furcate_net::announce::open(&buf[..n], "node-b", &anchors, &none, &mut replay, now, lease_ceiling())
            .expect("a signed lease is taken");
        assert!(hold(&mut m, &h, now));
        let (n, _) = peer.recv_from(&mut buf).expect("the resend arrives");
        assert!(matches!(
            furcate_net::announce::open(&buf[..n], "node-b", &anchors, &none, &mut replay, now, lease_ceiling()),
            Err(furcate_net::announce::Refusal::Replay { .. })
        ));

        let hints = furcate_net::overlay::merge(&coordinator, &gossip_hints(&m, "node-b", now));
        let r = reconcile_at(&plan, &hints, "10.90.0.20/16", now, admit);
        assert_eq!(r.peers.len(), 1);
        assert_eq!(r.peers[0].public_key, NEW, "the peer now carries the key the node has");
        let written = std::fs::read_to_string(&plan).unwrap();
        assert!(written.contains(NEW) && !written.contains(OLD), "{written}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A leased node's wired cable comes out and it carries on over Wi-Fi: the
    /// same lease, another underlay address. The signed announcement from the
    /// new address updates the peer's WireGuard endpoint with no newer lease,
    /// while the same datagram sent again stays refused.
    #[test]
    fn a_node_that_moved_underlay_address_is_followed_without_a_new_lease() {
        use furcate_identity::Ed25519Signer;
        use std::sync::Arc;

        const WG: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
        let now = 1_786_838_400u64;
        let operator = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let mut anchors = furcate_net::lock::Anchors::new();
        anchors
            .trust(&furcate_net::lock::Anchor {
                key_id: "op".into(),
                public_key: hex::encode(operator.verifying_key().to_bytes()),
            })
            .expect("an anchor");
        let node = Ed25519Signer(Arc::new(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32])));
        let b = furcate_net::lease::bind(
            &node,
            &furcate_net::lease::Terms { node_id: "edge-1", wg_pub: WG, tier: "platform", not_after: now + 3_600, quote_digest: None },
        )
        .expect("bound");
        let auth = furcate_net::lock::authorize(
            "op",
            &operator,
            &furcate_net::lock::Claim { node_id: "edge-1", public_key: &b.node_key, tier: "platform", not_after: now + 86_400 },
        );
        let at = |endpoint: &str, seen: u64| Hint {
            node_id: "edge-1".into(),
            public_key: WG.into(),
            endpoints: vec![endpoint.into()],
            overlay_addr: "10.90.0.9/32".into(),
            tier: Tier::Platform,
            seen_at: seen,
            lease: Some(b.clone()),
            authorization: Some(auth.clone()),
            name: None,
            observed: vec![],
        };
        let wired = at("192.168.1.102:51820", now);
        let wifi = at("192.0.2.61:51820", now + 900);

        let mut m = furcate_membership::Membership::new("node-b", 10);
        let mut replay = furcate_net::announce::Replay::new();
        let none = |_: &str| None;
        let ceiling = lease_ceiling();

        let first = furcate_net::announce::seal(&node, &wired, now).unwrap();
        let h = furcate_net::announce::open(&first, "node-b", &anchors, &none, &mut replay, now, ceiling).unwrap();
        assert_eq!(hold_announced(&mut m, &h, now), Held::Key);

        // The same datagram again, from anywhere: a replay, refused.
        assert!(matches!(
            furcate_net::announce::open(&first, "node-b", &anchors, &none, &mut replay, now, ceiling),
            Err(furcate_net::announce::Refusal::Replay { .. })
        ));

        // The new address, signed later, same lease: taken, and the endpoint moves.
        let second = furcate_net::announce::seal(&node, &wifi, now + 900).unwrap();
        let h = furcate_net::announce::open(&second, "node-b", &anchors, &none, &mut replay, now + 900, ceiling).unwrap();
        assert_eq!(hold_announced(&mut m, &h, now + 900), Held::Moved);
        // And that one resent is refused too.
        assert!(matches!(
            furcate_net::announce::open(&second, "node-b", &anchors, &none, &mut replay, now + 900, ceiling),
            Err(furcate_net::announce::Refusal::Replay { .. })
        ));

        // The coordinator still says the old address; the peer set follows the announcement.
        let hints = furcate_net::overlay::merge(&[wired.clone()], &gossip_hints(&m, "node-b", now + 900));
        let dir = std::env::temp_dir().join(format!("furcate-moved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plan = dir.join("wg-plan").display().to_string();
        let admit = |h: &Hint| furcate_net::lease::verify_hint(&anchors, h, now + 900, lease_ceiling()).map(|_| ());
        let r = reconcile_at(&plan, &hints, "10.90.0.1/16", now + 900, admit);
        assert_eq!(r.peers[0].endpoint.as_deref(), Some("192.0.2.61:51820"));
        let written = std::fs::read_to_string(&plan).unwrap();
        assert!(written.contains("192.0.2.61:51820") && !written.contains("192.168.1.102"), "{written}");

        // An older statement of the same lease does not move it back.
        let mut stale = wired.clone();
        stale.seen_at = now + 10;
        assert_eq!(hold_announced(&mut m, &stale, now + 900), Held::Nothing);

        // The privileged half is told to apply every peer again.
        refresh_plan_file(&plan, now + 901);
        refresh_plan_file(&plan, now + 902);
        let written = std::fs::read_to_string(&plan).unwrap();
        assert_eq!(written.matches("refresh=").count(), 1);
        assert!(written.ends_with(&format!("refresh={}\n", now + 902)), "{written}");
        assert!(written.contains("192.0.2.61:51820"), "the peers stay in the plan");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn announce_targets_take_held_peers_when_the_kernel_has_none() {
        let held = vec![Peer {
            node_id: "node-b".into(),
            public_key: "k2".into(),
            endpoint: Some("192.0.2.2:51820".into()),
            overlay_addr: "10.90.0.20/32".into(),
            tier: Tier::Platform,
            source: Source::Retained,
            resolved_at: 0,
            name: None,
            valid_until: None,
            lease_until: None,
            candidates: vec![],
        }];
        assert_eq!(
            announce_targets_from(None, &held, 51821, 1_000),
            vec!["192.0.2.2:51821".parse::<std::net::SocketAddr>().unwrap()]
        );
        let state = serde_json::json!({ "handshakes": { "k2": 990 } });
        assert!(announce_targets_from(Some(&state), &held, 51821, 1_000).is_empty(), "a handshaking peer has the key");
        // The key was replaced after that handshake: the peer may hold the old one.
        let state = serde_json::json!({ "handshakes": { "k2": 990 }, "key_born_at": 995 });
        assert_eq!(announce_targets_from(Some(&state), &held, 51821, 1_000).len(), 1);
    }

    /// A device-tier node's trust store names only the machines it was
    /// installed with. A server enrolled later is recognised through the
    /// anchor that admitted its hardware key, carried on its lease — and only
    /// that key, only while the authorization holds.
    #[test]
    fn a_machine_the_trust_store_never_named_is_recognised_by_its_anchor_admitted_lease() {
        let now = 1_000_000u64;
        let operator = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let mut anchors = furcate_net::lock::Anchors::new();
        anchors
            .trust(&furcate_net::lock::Anchor {
                key_id: "op".into(),
                public_key: hex::encode(operator.verifying_key().to_bytes()),
            })
            .unwrap();
        let server = node_signer(4);
        let mut h = leased(&server, "node-b", WG_A, now + 3_600);
        let admit_until = now + 86_400;
        h.authorization = Some(furcate_net::lock::authorize(
            "op",
            &operator,
            &furcate_net::lock::Claim {
                node_id: "node-b",
                public_key: &h.lease.as_ref().unwrap().node_key,
                tier: "platform",
                not_after: admit_until,
            },
        ));
        let mut pi = furcate_membership::Membership::new("pi", 3);
        assert!(admitted_key(&pi, &anchors, "node-b", now).is_none(), "nothing held yet");
        assert!(hold(&mut pi, &h, now));
        let k = admitted_key(&pi, &anchors, "node-b", now).expect("admitted by the anchor");
        assert_eq!(k, server.0.verifying_key());
        // Not for another node id, not on an overlay with no anchors, and not
        // once the operator's authorization has lapsed.
        assert!(admitted_key(&pi, &anchors, "node-c", now).is_none());
        assert!(admitted_key(&pi, &furcate_net::lock::Anchors::new(), "node-b", now).is_none());
        assert!(admitted_key(&pi, &anchors, "node-b", admit_until + 1).is_none());
        // A lease nobody admitted vouches for nothing.
        let mut stranger = furcate_membership::Membership::new("pi", 3);
        assert!(hold(&mut stranger, &leased(&node_signer(9), "node-b", WG_B, now + 3_600), now));
        assert!(admitted_key(&stranger, &anchors, "node-b", now).is_none());
    }
}
