//! Site definition loading and inspection.
//!
//! A site file records the physical facts Furcate cannot discover on its own —
//! which supply feeds which rack, which breaker feeds which supply. Everything
//! declared here is marked as such, so a reader can see which parts of their
//! blast radius rest on someone having typed the truth.

use anyhow::{Context, Result};
use furcate_topology::{place, DomainKind, DomainTree, PlacementRequest, Provenance};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub parent: Option<String>,
    /// `discovered` when learned from hardware, otherwise `declared`.
    #[serde(default = "default_provenance")]
    pub provenance: String,
}

fn default_provenance() -> String {
    "declared".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteFile {
    pub site: String,
    pub entries: Vec<Entry>,
}

fn parse_kind(s: &str) -> Result<DomainKind> {
    Ok(match s {
        "site" => DomainKind::Site,
        "feed" => DomainKind::Feed,
        "ups" => DomainKind::Ups,
        "rack" => DomainKind::Rack,
        "chassis" => DomainKind::Chassis,
        "node" => DomainKind::Node,
        "device" => DomainKind::Device,
        other => anyhow::bail!(
            "unknown domain kind `{other}` (site|feed|ups|rack|chassis|node|device)"
        ),
    })
}

impl SiteFile {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading site file {path}"))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing site file {path}"))
    }

    pub fn tree(&self) -> Result<DomainTree> {
        let mut t = DomainTree::new();
        for e in &self.entries {
            let provenance = match e.provenance.as_str() {
                "discovered" => Provenance::Discovered,
                _ => Provenance::Declared,
            };
            t.insert(e.id.clone(), parse_kind(&e.kind)?, e.parent.as_deref(), provenance);
        }
        Ok(t)
    }

    /// The site as first built: two machines, one rack, one supply, one
    /// breaker. Written out by `site init` so an operator edits reality rather
    /// than inventing a schema.
    pub fn starter() -> Self {
        SiteFile {
            site: "home-1".into(),
            entries: vec![
                Entry { id: "home-1".into(), kind: "site".into(), parent: None, provenance: "declared".into() },
                Entry { id: "circuit-a".into(), kind: "feed".into(), parent: Some("home-1".into()), provenance: "declared".into() },
                Entry { id: "ups-1".into(), kind: "ups".into(), parent: Some("circuit-a".into()), provenance: "declared".into() },
                Entry { id: "rack-1".into(), kind: "rack".into(), parent: Some("ups-1".into()), provenance: "declared".into() },
                Entry { id: "node-a".into(), kind: "node".into(), parent: Some("rack-1".into()), provenance: "discovered".into() },
                Entry { id: "node-b".into(), kind: "node".into(), parent: Some("rack-1".into()), provenance: "discovered".into() },
            ],
        }
    }
}

/// Report which isolation levels this site can actually satisfy.
///
/// The useful output is usually the failures: they are true statements about
/// where the site would lose data.
pub fn report_isolation(tree: &DomainTree) -> Vec<(DomainKind, usize, Result<usize, String>)> {
    let nodes: Vec<String> = tree.compute_nodes().into_iter().map(|n| n.id.clone()).collect();
    let mut out = Vec::new();
    for kind in [DomainKind::Node, DomainKind::Chassis, DomainKind::Rack, DomainKind::Ups, DomainKind::Feed] {
        for replicas in [2usize, 3] {
            let req = PlacementRequest {
                replicas,
                spread_across: kind,
                candidates: nodes.clone(),
            };
            let result = place(tree, &req)
                .map(|r| r.achieved_domains)
                .map_err(|e| e.to_string());
            out.push((kind, replicas, result));
        }
    }
    out
}
