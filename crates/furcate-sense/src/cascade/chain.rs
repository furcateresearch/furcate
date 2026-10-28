//! Validating the rungs a reading claims to have passed through.
//!
//! The level that matters to the next consumer is computed here, from the
//! verifier's own directory, as the lowest class of any rung. It is never read
//! from a field a sender wrote. A rung may claim a class at or below what its
//! enrolment earns and never above it, the sensing node is capped at `soft`
//! because it holds no secret, and an aggregate class stated in the provenance
//! may not exceed the computed one. There is no function in this module that
//! returns a level while a lower rung exists.
//!
//! This checks structure and claims. The signatures that make the hop list
//! unalterable are checked by the caller (`ingest`), because they need the
//! envelope.

use super::directory::Directory;
use crate::nicla::{Countersignature, Derivation, Hop, NodeRole, Provenance};
use furcate_identity::AssuranceClass;

/// The most a sensing node can ever claim: it holds no secret.
pub const SENSING_CEILING: AssuranceClass = AssuranceClass::Soft;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainRefusal {
    NoRungs,
    /// The chain does not start at the enrolled sensing node.
    FirstRungNotTheSensingNode,
    NoProcessingRung,
    /// A rung that is not enrolled with this verifier.
    UnknownNode(String),
    /// The sensing node is not bound to the rung that signed for it.
    NotTheGatewayOfRecord { sensing_node: String, claimed: String },
    RoleMismatch { node_id: String, claimed: NodeRole, enrolled: NodeRole },
    /// A rung appears out of order: rungs run from sensing outward.
    RoleOrder { node_id: String },
    DuplicateRung(String),
    /// A rung claims a class above what its enrolment earns.
    LevelRaised { node_id: String, claimed: AssuranceClass, ceiling: AssuranceClass },
    /// The provenance states an aggregate class above the computed one.
    AggregateRaised { claimed: AssuranceClass, computed: AssuranceClass },
    /// The attestation record disagrees with the chain it travels with.
    RecordDisagrees(&'static str),
    /// Only a sensing node measures; a later rung that says it did is lying.
    MeasuredBeyondTheSensor(String),
    /// A value produced by a model must say so.
    ModalityUnderstated,
    /// The policy requires a rung that is absent.
    MissingRung(NodeRole),
}

impl std::fmt::Display for ChainRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ChainRefusal::*;
        match self {
            NoRungs => write!(f, "the provenance lists no rungs"),
            FirstRungNotTheSensingNode => write!(f, "the first rung is not the sensing node"),
            NoProcessingRung => write!(f, "no processing rung signed for the sensing node"),
            UnknownNode(n) => write!(f, "rung `{n}` is not enrolled"),
            NotTheGatewayOfRecord { sensing_node, claimed } => {
                write!(f, "`{claimed}` is not the processing node of record for `{sensing_node}`")
            }
            RoleMismatch { node_id, claimed, enrolled } => {
                write!(f, "`{node_id}` claims role {claimed:?} but is enrolled as {enrolled:?}")
            }
            RoleOrder { node_id } => write!(f, "rung `{node_id}` is out of order"),
            DuplicateRung(n) => write!(f, "rung `{n}` appears twice"),
            LevelRaised { node_id, claimed, ceiling } => {
                write!(f, "`{node_id}` claims `{claimed}`, above the `{ceiling}` its enrolment earns")
            }
            AggregateRaised { claimed, computed } => {
                write!(f, "the provenance states `{claimed}` but the lowest rung is `{computed}`")
            }
            RecordDisagrees(w) => write!(f, "the attestation record disagrees with the chain: {w}"),
            MeasuredBeyondTheSensor(n) => write!(f, "rung `{n}` claims to have measured"),
            ModalityUnderstated => write!(f, "a model-produced value is stated as direct"),
            MissingRung(r) => write!(f, "no {r:?} rung in the chain"),
        }
    }
}

impl std::error::Error for ChainRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopReport {
    pub node_id: String,
    pub role: NodeRole,
    pub claimed: AssuranceClass,
    /// The class this rung is held to: the lower of what it claimed and what
    /// its enrolment earns.
    pub held: AssuranceClass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainReport {
    /// The lowest class of any rung.
    pub effective: AssuranceClass,
    /// The first rung at that class.
    pub limiting: String,
    pub hops: Vec<HopReport>,
}

impl ChainReport {
    pub fn has_role(&self, role: NodeRole) -> bool {
        self.hops.iter().any(|h| h.role == role)
    }
}

/// Validate the rungs of one item. `sensing_node` is the id the item is signed
/// as; `counters` are the rungs added after the signing node.
pub fn validate(
    p: &Provenance,
    counters: &[Countersignature],
    dir: &Directory,
    sensing_node: &str,
    required: Option<NodeRole>,
) -> Result<ChainReport, ChainRefusal> {
    let hops: Vec<&Hop> = p.chain.iter().chain(counters.iter().map(|c| &c.hop)).collect();
    let first = hops.first().ok_or(ChainRefusal::NoRungs)?;
    if first.role != NodeRole::Sensing || first.node_id != sensing_node {
        return Err(ChainRefusal::FirstRungNotTheSensingNode);
    }
    if hops.len() < 2 {
        return Err(ChainRefusal::NoProcessingRung);
    }
    if p.attestation.sensing_node != sensing_node || p.source_module != sensing_node {
        return Err(ChainRefusal::RecordDisagrees("sensing node"));
    }
    // The aggregate and the record may not be above what a sensing node can be.
    if p.attestation.sensor_assurance > SENSING_CEILING {
        return Err(ChainRefusal::LevelRaised {
            node_id: sensing_node.to_string(),
            claimed: p.attestation.sensor_assurance,
            ceiling: SENSING_CEILING,
        });
    }

    let gateway = dir.gateway_of(sensing_node).ok_or_else(|| ChainRefusal::NotTheGatewayOfRecord {
        sensing_node: sensing_node.to_string(),
        claimed: hops[1].node_id.clone(),
    })?;
    if hops[1].node_id != gateway.node_id || p.attestation.gateway != gateway.node_id {
        return Err(ChainRefusal::NotTheGatewayOfRecord {
            sensing_node: sensing_node.to_string(),
            claimed: hops[1].node_id.clone(),
        });
    }
    if p.attestation.gateway_assurance != hops[1].attestation_level {
        return Err(ChainRefusal::RecordDisagrees("gateway class"));
    }

    let mut report = Vec::with_capacity(hops.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut last_role = NodeRole::Sensing;
    for (i, h) in hops.iter().enumerate() {
        if !seen.insert(h.node_id.as_str()) {
            return Err(ChainRefusal::DuplicateRung(h.node_id.clone()));
        }
        let ceiling = if i == 0 {
            SENSING_CEILING
        } else {
            if h.role == NodeRole::Sensing || h.role < last_role {
                return Err(ChainRefusal::RoleOrder { node_id: h.node_id.clone() });
            }
            let rec = dir.node(&h.node_id).ok_or_else(|| ChainRefusal::UnknownNode(h.node_id.clone()))?;
            if rec.role != h.role {
                return Err(ChainRefusal::RoleMismatch {
                    node_id: h.node_id.clone(),
                    claimed: h.role,
                    enrolled: rec.role,
                });
            }
            if matches!(h.derivation, Derivation::Measured | Derivation::OnSensor { .. }) {
                return Err(ChainRefusal::MeasuredBeyondTheSensor(h.node_id.clone()));
            }
            last_role = h.role;
            rec.assurance
        };
        if h.attestation_level > ceiling {
            return Err(ChainRefusal::LevelRaised {
                node_id: h.node_id.clone(),
                claimed: h.attestation_level,
                ceiling,
            });
        }
        report.push(HopReport {
            node_id: h.node_id.clone(),
            role: h.role,
            claimed: h.attestation_level,
            held: h.attestation_level.min(ceiling),
        });
    }

    let mut effective = report[0].held;
    let mut limiting = report[0].node_id.clone();
    for h in &report[1..] {
        if h.held < effective {
            effective = h.held;
            limiting = h.node_id.clone();
        }
    }
    if p.attestation_level > effective {
        return Err(ChainRefusal::AggregateRaised { claimed: p.attestation_level, computed: effective });
    }
    if p.chain.iter().any(|h| matches!(h.derivation, Derivation::Model(_)))
        && p.modality == crate::registry::Modality::Direct
    {
        return Err(ChainRefusal::ModalityUnderstated);
    }
    if let Some(role) = required {
        if !report.iter().any(|h| h.role == role) {
            return Err(ChainRefusal::MissingRung(role));
        }
    }
    Ok(ChainReport { effective, limiting, hops: report })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cascade::micro::MicroSim;
    use crate::cascade::signer::CascadeSigner;
    use crate::leaf::Leaf;
    use crate::nicla::{countersign_list, ModelRef};
    use furcate_identity::{LeafKeyCustody, Lockdown};

    const FUSED: Option<LeafKeyCustody> = Some(LeafKeyCustody::FuseKey { lockdown: Lockdown { secure_boot: true, flash_encryption: true, download_disabled: true, jtag_disabled: true } });

    /// A sensing node behind a device-class micro node, a soft small node and a
    /// tpm-class large node, all enrolled.
    fn world() -> (MicroSim, Directory, Leaf, Leaf) {
        let micro = MicroSim::new("bench-unit", [9u8; 32], "furcate:node:micro1");
        let small = Leaf::new("furcate:node:small1", [3u8; 32]);
        let large = Leaf::new("furcate:node:large1", [4u8; 32]);
        let mut d = Directory::new();
        d.add_node(&micro.gateway_attachment(FUSED), NodeRole::MicroProcessing).unwrap();
        d.add_node(&small.attach("p", None, 0), NodeRole::SmallProcessing).unwrap();
        let tpm = Some(LeafKeyCustody::FuseKey { lockdown: Lockdown::default() });
        d.add_node(&large.attach("p", tpm, 0), NodeRole::LargeProcessing).unwrap();
        d.bind_sensing(micro.sensing_id(), "furcate:node:micro1").unwrap();
        (micro, d, small, large)
    }

    fn hop(l: &Leaf, role: NodeRole, level: AssuranceClass) -> Hop {
        Hop { role, node_id: l.id.clone(), attestation_level: level, derivation: Derivation::Relayed }
    }

    #[test]
    fn the_effective_level_is_the_lowest_rung_and_the_sensor_caps_it() {
        let (mut m, d, small, _) = world();
        let mut e = m.embedding(&[1, 2, 3], 1);
        let r = validate(&e.provenance, &e.countersignatures, &d, m.sensing_id(), None).unwrap();
        assert_eq!(r.effective, AssuranceClass::Soft);
        assert_eq!(r.limiting, m.sensing_id());
        countersign_list(&e.envelope_signature, &mut e.countersignatures, &small, hop(&small, NodeRole::SmallProcessing, AssuranceClass::Soft)).unwrap();
        let r = validate(&e.provenance, &e.countersignatures, &d, m.sensing_id(), Some(NodeRole::SmallProcessing)).unwrap();
        assert_eq!(r.hops.len(), 3);
        assert!(r.has_role(NodeRole::MicroProcessing));
    }

    #[test]
    fn each_kind_of_tampering_is_refused() {
        let (mut m, d, small, large) = world();
        let e = m.embedding(&[1, 2, 3], 1);
        let id = m.sensing_id().to_string();
        let check = |p: &Provenance, c: &[Countersignature]| validate(p, c, &d, &id, None);

        // A sensing node claiming a hardware class.
        let mut p = e.provenance.clone();
        p.chain[0].attestation_level = AssuranceClass::Device;
        assert!(matches!(check(&p, &[]), Err(ChainRefusal::LevelRaised { .. })));
        // The aggregate raised above the computed minimum.
        let mut p = e.provenance.clone();
        p.attestation_level = AssuranceClass::Tpm;
        assert!(matches!(check(&p, &[]), Err(ChainRefusal::LevelRaised { .. } | ChainRefusal::AggregateRaised { .. })));
        // The sensing rung dropped.
        let mut p = e.provenance.clone();
        p.chain.remove(0);
        assert!(check(&p, &[]).is_err());
        // The processing rung dropped.
        let mut p = e.provenance.clone();
        p.chain.remove(1);
        assert_eq!(check(&p, &[]), Err(ChainRefusal::NoProcessingRung));
        // Reordered.
        let mut p = e.provenance.clone();
        p.chain.swap(0, 1);
        assert_eq!(check(&p, &[]), Err(ChainRefusal::FirstRungNotTheSensingNode));
        // Duplicated rung.
        let mut p = e.provenance.clone();
        let again = p.chain[1].clone();
        p.chain.push(again);
        assert!(matches!(check(&p, &[]), Err(ChainRefusal::DuplicateRung(_))));
        // A later rung that is not enrolled.
        let stranger = Leaf::new("furcate:node:stranger", [7; 32]);
        let mut c = Vec::new();
        countersign_list(&e.envelope_signature, &mut c, &stranger, hop(&stranger, NodeRole::LargeProcessing, AssuranceClass::Tpm)).unwrap();
        assert!(matches!(check(&e.provenance, &c), Err(ChainRefusal::UnknownNode(_))));
        // A small node claiming the class of the large one; a large one before a small one.
        let mut c = Vec::new();
        countersign_list(&e.envelope_signature, &mut c, &large, hop(&large, NodeRole::LargeProcessing, AssuranceClass::Device)).unwrap();
        countersign_list(&e.envelope_signature, &mut c, &small, hop(&small, NodeRole::SmallProcessing, AssuranceClass::Soft)).unwrap();
        assert!(matches!(check(&e.provenance, &c), Err(ChainRefusal::RoleOrder { .. })));
        let mut c = Vec::new();
        countersign_list(&e.envelope_signature, &mut c, &small, hop(&small, NodeRole::SmallProcessing, AssuranceClass::Device)).unwrap();
        assert!(matches!(check(&e.provenance, &c), Err(ChainRefusal::LevelRaised { .. })));
        // Wrong role for the enrolled node.
        let mut c = Vec::new();
        countersign_list(&e.envelope_signature, &mut c, &small, hop(&small, NodeRole::MediumProcessing, AssuranceClass::Soft)).unwrap();
        assert!(matches!(check(&e.provenance, &c), Err(ChainRefusal::RoleMismatch { .. })));
        // A later rung that says it measured.
        let mut c = Vec::new();
        let mut h = hop(&small, NodeRole::SmallProcessing, AssuranceClass::Soft);
        h.derivation = Derivation::Measured;
        countersign_list(&e.envelope_signature, &mut c, &small, h).unwrap();
        assert!(matches!(check(&e.provenance, &c), Err(ChainRefusal::MeasuredBeyondTheSensor(_))));
        // A model-produced value stated as direct.
        let mut p = e.provenance.clone();
        p.modality = crate::registry::Modality::Direct;
        p.chain[1].derivation = Derivation::Model(ModelRef { id: "m".into(), sha256: "00".repeat(32) });
        assert_eq!(check(&p, &[]), Err(ChainRefusal::ModalityUnderstated));
        // A required rung that is absent.
        assert_eq!(
            validate(&e.provenance, &[], &d, &id, Some(NodeRole::SmallProcessing)),
            Err(ChainRefusal::MissingRung(NodeRole::SmallProcessing))
        );
        // The wrong processing node for this sensing node.
        let mut p = e.provenance.clone();
        p.chain[1].node_id = small.id.clone();
        assert!(matches!(check(&p, &[]), Err(ChainRefusal::NotTheGatewayOfRecord { .. })));
    }

    /// A xorshift generator, so the fuzz is repeatable without a dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const LEVELS: [AssuranceClass; 6] = [
        AssuranceClass::Soft,
        AssuranceClass::Device,
        AssuranceClass::SecureElement,
        AssuranceClass::Tee,
        AssuranceClass::Dice,
        AssuranceClass::Tpm,
    ];

    /// Mutate the hop lists at random: drop, reorder, duplicate, raise, lower,
    /// retag. Whatever the validator accepts must never be above the true
    /// minimum of the unmutated chain.
    #[test]
    fn fuzzed_chains_are_never_accepted_above_the_true_minimum() {
        let (mut m, d, small, large) = world();
        let mut e = m.embedding(&[1, 2, 3], 1);
        countersign_list(&e.envelope_signature, &mut e.countersignatures, &small, hop(&small, NodeRole::SmallProcessing, AssuranceClass::Soft)).unwrap();
        countersign_list(&e.envelope_signature, &mut e.countersignatures, &large, hop(&large, NodeRole::LargeProcessing, AssuranceClass::Device)).unwrap();
        let id = m.sensing_id().to_string();
        let truth = validate(&e.provenance, &e.countersignatures, &d, &id, None).unwrap();
        assert_eq!(truth.effective, AssuranceClass::Soft);

        let mut rng = Rng(0x9E3779B97F4A7C15);
        let (mut accepted, mut refused) = (0u32, 0u32);
        let original: Vec<Hop> = e.provenance.chain.iter().chain(e.countersignatures.iter().map(|c| &c.hop)).cloned().collect();
        let split0 = e.provenance.chain.len();
        for _ in 0..200_000 {
            let mut all = original.clone();
            let mut p = e.provenance.clone();
            for _ in 0..1 + rng.below(3) {
                if all.is_empty() {
                    break;
                }
                let i = rng.below(all.len());
                match rng.below(7) {
                    0 => {
                        all.remove(i);
                    }
                    1 => {
                        let j = rng.below(all.len());
                        all.swap(i, j);
                    }
                    2 => {
                        let h = all[i].clone();
                        all.push(h);
                    }
                    3 => all[i].attestation_level = LEVELS[rng.below(6)],
                    4 => all[i].node_id = format!("furcate:node:{}", ["micro1", "small1", "large1", "x"][rng.below(4)]),
                    5 => p.attestation_level = LEVELS[rng.below(6)],
                    _ => all[i].role = [NodeRole::Sensing, NodeRole::MicroProcessing, NodeRole::SmallProcessing, NodeRole::LargeProcessing][rng.below(4)],
                }
            }
            let split = split0.min(all.len());
            p.chain = all[..split].to_vec();
            let c: Vec<Countersignature> =
                all[split..].iter().map(|h| Countersignature { hop: h.clone(), signature: String::new() }).collect();
            match validate(&p, &c, &d, &id, None) {
                Ok(r) => {
                    accepted += 1;
                    assert!(r.effective <= truth.effective, "accepted above the true minimum: {r:?}");
                    assert!(p.attestation_level <= r.effective);
                    assert!(r.hops.iter().all(|h| h.held <= h.claimed));
                }
                Err(_) => refused += 1,
            }
        }
        assert!(refused > accepted, "the mutations should mostly be refused ({refused} refused, {accepted} accepted)");
    }

    #[test]
    fn a_signer_trait_object_works_for_a_rung() {
        let l = Leaf::new("n", [1; 32]);
        let s: &dyn CascadeSigner = &l;
        assert_eq!(s.node_id(), "n");
    }
}
