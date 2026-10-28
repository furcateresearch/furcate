//! From a leaf's session to the small processing node's input.
//!
//! The bridge is the host-side end of a micro processing node's link. It runs
//! the session ([`crate::session`]), asks the leaf for its readings, checks
//! each reading's signature against the leaf's enrolled identity, and signs
//! the frame the rung above reads with the host's own hardware key
//! ([`furcate_sense::relay::Relay`]). The class it claims is the lower of its
//! own key's class and what the roster says the leaf's key earns, so a bridge
//! on strong hardware cannot lift a weakly held leaf.
//!
//! It does no I/O: bytes in as messages, [`Action`]s out. [`crate::serve`]
//! drives it over a stream.

use crate::report::{self, ReplayGuard, MODULE_BASE};
use crate::session::{answer, ephemeral, Hello, LinkError, NodeGrant, NodeSigner, Pending, Session};
use crate::wire::{msg, Builder};
use furcate_identity::{AssuranceClass, UnitRoster, Verdict};
use furcate_sense::cascade::ingest::Frame;
use furcate_sense::relay::{Relay, RelaySource};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A leaf the operator enrolled, and the sensing nodes behind it.
pub struct Source {
    /// The leaf's id in the roster: hex SHA-256 of its public key.
    pub leaf_unit: String,
    /// The leaf's own sensors (indices below 16).
    pub chip: RelaySource,
    /// Sensor index to the cascade's channel name.
    pub chip_channels: BTreeMap<u8, String>,
    pub module: Option<ModuleSource>,
}

/// A sensing module behind the leaf (indices 16 and up). It holds no key, so
/// the leaf names it by a fingerprint of the identifiers the operator enrolled,
/// and anything repeating those identifiers matches: identified, not
/// authenticated.
pub struct ModuleSource {
    /// The fingerprint the leaf reports for this module in its signed unit record.
    pub unit_fingerprint: [u8; 16],
    pub source: RelaySource,
    pub channels: BTreeMap<u8, String>,
}

pub struct BridgeConfig {
    pub signer: Arc<dyn NodeSigner>,
    pub grant: NodeGrant,
    pub roster: UnitRoster,
    pub sources: Vec<Source>,
    pub relay: Relay,
    /// The class of the bridge's own key, as the rung above enrols it.
    pub ceiling: AssuranceClass,
    /// Between a SENSE reply and the next request.
    pub poll_ms: u64,
    /// How long an AUTH waits for the leaf's FINISH.
    pub auth_wait_ms: u64,
    /// How long a SENSE_REQ waits for its reply.
    pub reply_wait_ms: u64,
}

#[derive(Debug)]
pub enum Action {
    /// A message for the leaf (not yet in a line).
    Send(Vec<u8>),
    /// A frame for the small processing node.
    Frame(Box<Frame>),
    /// Something refused, with the reason. The link stays as it was unless a
    /// `Down` follows.
    Refused(String),
    /// A session is up with this leaf, at this class.
    Up { leaf: String, class: AssuranceClass },
    /// The session is over.
    Down(String),
}

enum Phase {
    Idle,
    Pending { pending: Pending, since: u64, source: usize, class: AssuranceClass },
    Up { session: Session, source: usize, class: AssuranceClass, next_poll: u64, asked_at: Option<u64> },
}

pub struct Bridge {
    cfg: BridgeConfig,
    phase: Phase,
    guards: Vec<ReplayGuard>,
}

fn class_of(v: &Verdict) -> Option<AssuranceClass> {
    match v {
        Verdict::Verified { class } | Verdict::PeripheralChanged { class, .. } => Some(*class),
        _ => None,
    }
}

impl Bridge {
    pub fn new(cfg: BridgeConfig) -> Self {
        let guards = cfg.sources.iter().map(|_| ReplayGuard::new()).collect();
        Self { cfg, phase: Phase::Idle, guards }
    }

    pub fn relay(&self) -> &Relay {
        &self.cfg.relay
    }

    pub fn sources(&self) -> &[Source] {
        &self.cfg.sources
    }

    pub fn is_up(&self) -> bool {
        matches!(self.phase, Phase::Up { .. })
    }

    fn drop_session(&mut self) {
        let leaf = match &self.phase {
            Phase::Pending { source, .. } | Phase::Up { source, .. } => Some(self.cfg.sources[*source].leaf_unit.clone()),
            Phase::Idle => None,
        };
        if let Some(l) = leaf {
            self.cfg.roster.end_session(&l);
        }
        self.phase = Phase::Idle;
    }

    /// Ends whatever is open. Call when the stream goes away.
    pub fn close(&mut self) {
        self.drop_session();
    }

    fn sealed_request(session: &mut Session) -> Result<Vec<u8>, LinkError> {
        let plain = Builder::new(msg::SENSE_REQ).build()?;
        session.seal(&plain)
    }

    /// One message from the leaf.
    pub fn handle(&mut self, message: &[u8], now_ms: u64) -> Vec<Action> {
        let Some(&kind) = message.first() else { return vec![Action::Refused("an empty message".into())] };
        match kind {
            msg::HELLO => self.on_hello(message, now_ms),
            msg::FINISH | msg::REFUSE => self.on_finish(message, now_ms),
            msg::SEALED => self.on_sealed(message, now_ms),
            other => vec![Action::Refused(format!("unexpected message type 0x{other:02x}"))],
        }
    }

    fn on_hello(&mut self, raw: &[u8], now_ms: u64) -> Vec<Action> {
        // A HELLO that crossed our AUTH is the same attempt; ignore it until the
        // AUTH window has run out, after which the leaf has given up and a new
        // HELLO is a new attempt.
        if let Phase::Pending { since, .. } = &self.phase {
            if now_ms.saturating_sub(*since) < self.cfg.auth_wait_ms {
                return Vec::new();
            }
        }
        self.drop_session();
        let hello = match Hello::parse(raw) {
            Ok(h) => h,
            Err(e) => return vec![Action::Refused(format!("HELLO: {e}"))],
        };
        let unit = hello.unit_id();
        let Some(source) = self.cfg.sources.iter().position(|s| s.leaf_unit == unit) else {
            return vec![Action::Refused(format!("leaf {} is not enrolled; enrolling is the operator's decision", &unit[..32]))];
        };
        let verdict = self.cfg.roster.verify(&unit, &hello.fingerprint(), Some(&hello.key()));
        let Some(class) = class_of(&verdict) else {
            return vec![Action::Refused(format!("leaf {} refused by its enrolment: {verdict:?}", &unit[..32]))];
        };
        let eph = match ephemeral() {
            Ok(e) => e,
            Err(e) => {
                self.cfg.roster.end_session(&unit);
                return vec![Action::Refused(e.to_string())];
            }
        };
        match answer(&hello, &*self.cfg.signer, &self.cfg.grant, &eph) {
            Ok((pending, auth)) => {
                self.phase = Phase::Pending { pending, since: now_ms, source, class };
                vec![Action::Send(auth)]
            }
            Err(e) => {
                self.cfg.roster.end_session(&unit);
                vec![Action::Refused(format!("AUTH: {e}"))]
            }
        }
    }

    fn on_finish(&mut self, message: &[u8], now_ms: u64) -> Vec<Action> {
        if !matches!(self.phase, Phase::Pending { .. }) {
            return vec![Action::Refused("a handshake message with no handshake open".into())];
        }
        let Phase::Pending { pending, source, class, .. } = std::mem::replace(&mut self.phase, Phase::Idle) else { return Vec::new() };
        match pending.finish(message) {
            Ok(mut session) => {
                let first = match Self::sealed_request(&mut session) {
                    Ok(m) => m,
                    Err(e) => {
                        self.cfg.roster.end_session(&self.cfg.sources[source].leaf_unit);
                        return vec![Action::Down(e.to_string())];
                    }
                };
                let leaf = self.cfg.sources[source].leaf_unit.clone();
                self.phase = Phase::Up { session, source, class, next_poll: now_ms, asked_at: Some(now_ms) };
                vec![Action::Up { leaf, class }, Action::Send(first)]
            }
            Err(e) => {
                self.cfg.roster.end_session(&self.cfg.sources[source].leaf_unit);
                vec![Action::Refused(format!("handshake: {e}"))]
            }
        }
    }

    fn on_sealed(&mut self, message: &[u8], now_ms: u64) -> Vec<Action> {
        let Phase::Up { session, .. } = &mut self.phase else {
            return vec![Action::Refused("a sealed record with no session".into())];
        };
        let plain = match session.open(message) {
            Ok(p) => p,
            Err(e) => {
                self.drop_session();
                return vec![Action::Down(e.to_string())];
            }
        };
        let report = match report::parse_sense(&plain) {
            Ok(r) => r,
            Err(e) => {
                if let Phase::Up { next_poll, asked_at, .. } = &mut self.phase {
                    *asked_at = None;
                    *next_poll = now_ms + self.cfg.poll_ms;
                }
                return vec![Action::Refused(format!("SENSE: {e}"))];
            }
        };
        self.on_report(report, now_ms)
    }

    fn on_report(&mut self, rep: report::SenseReport, now_ms: u64) -> Vec<Action> {
        let Phase::Up { session, source, class, next_poll, asked_at } = &mut self.phase else { return Vec::new() };
        *asked_at = None;
        *next_poll = now_ms + self.cfg.poll_ms;
        let (source, class) = (*source, *class);
        let leaf_pub = session.leaf_pub;
        let mut out = Vec::new();
        let src = &self.cfg.sources[source];

        // What the leaf says about the module behind it, for this reply: the unit
        // record is signed by the leaf, names the module by its fingerprint and
        // bounds the sequence numbers issued for the module's readings. The module
        // is trusted for these readings only if the fingerprint is the enrolled
        // one and the chain lists it as a sensing signer.
        let unit = match (&rep.unit, &src.module) {
            (Some(u), Some(m)) => {
                let listed = rep.chain.iter().any(|(id, role)| *id == u.fingerprint && role == "sensing");
                if !report::verify_unit(&leaf_pub, rep.generation, u) {
                    out.push(Action::Refused("the unit record is not signed by the leaf".into()));
                    None
                } else if u.fingerprint != m.unit_fingerprint {
                    out.push(Action::Refused(format!("the module behind the leaf is {}, which is not enrolled", hex::encode(u.fingerprint))));
                    None
                } else if !listed {
                    out.push(Action::Refused("the chain does not list the module as a sensing signer".into()));
                    None
                } else {
                    Some(u)
                }
            }
            (Some(_), None) => {
                out.push(Action::Refused("the leaf reports a module and none is enrolled behind it".into()));
                None
            }
            _ => None,
        };

        let model = if rep.model_sha == [0u8; 32] { "none".to_string() } else { hex::encode(rep.model_sha) };
        let claim = class.min(self.cfg.ceiling);
        let verdicts = report::verify_report(&leaf_pub, &rep, &mut self.guards[source]);
        for (raw, v) in rep.readings.iter().zip(verdicts) {
            let ok = match v {
                Ok(ok) => ok,
                Err(e) => {
                    out.push(Action::Refused(format!("sensor {}: {e}", raw.sensor)));
                    continue;
                }
            };
            let (rs, channels) = if ok.sensor < MODULE_BASE {
                (&src.chip, &src.chip_channels)
            } else {
                match (&src.module, unit) {
                    // The sequence range ties the reading to the unit the leaf named.
                    (Some(m), Some(u)) if (u.first_seq..=u.last_seq).contains(&ok.seq) => (&m.source, &m.channels),
                    _ => {
                        out.push(Action::Refused(format!("sensor {}: no verified module record covers this reading", ok.sensor)));
                        continue;
                    }
                }
            };
            let Some(channel) = channels.get(&ok.sensor) else {
                out.push(Action::Refused(format!("sensor {} has no channel mapped", ok.sensor)));
                continue;
            };
            let mut rs = rs.clone();
            rs.statement = format!("{} Leaf generation {}, model {model}.", rs.statement, ok.generation);
            let seq = ((ok.generation as u64) << 32) | ok.seq as u64;
            match self.cfg.relay.frame(&rs, channel, ok.value as f64, seq, now_ms / 1000, claim, now_ms) {
                Ok(f) => out.push(Action::Frame(Box::new(f))),
                Err(e) => out.push(Action::Refused(format!("sensor {}: {e}", ok.sensor))),
            }
        }
        out
    }

    /// Time passing: the next request, or giving up on one that is unanswered.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Action> {
        match &mut self.phase {
            Phase::Idle => Vec::new(),
            Phase::Pending { since, .. } => {
                if now_ms.saturating_sub(*since) > self.cfg.auth_wait_ms {
                    self.drop_session();
                    vec![Action::Down("the leaf did not finish the handshake".into())]
                } else {
                    Vec::new()
                }
            }
            Phase::Up { session, next_poll, asked_at, .. } => {
                if let Some(t) = *asked_at {
                    if now_ms.saturating_sub(t) > self.cfg.reply_wait_ms {
                        self.drop_session();
                        return vec![Action::Down("the leaf did not answer a request".into())];
                    }
                    return Vec::new();
                }
                if now_ms < *next_poll {
                    return Vec::new();
                }
                match Self::sealed_request(session) {
                    Ok(m) => {
                        *asked_at = Some(now_ms);
                        vec![Action::Send(m)]
                    }
                    Err(e) => {
                        self.drop_session();
                        vec![Action::Down(e.to_string())]
                    }
                }
            }
        }
    }
}
