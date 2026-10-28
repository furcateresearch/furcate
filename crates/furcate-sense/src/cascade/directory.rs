//! What a rung has enrolled.
//!
//! A verifying rung holds, for each node it has enrolled, the public key, the
//! role and the class the node's key custody earns. The class is derived by
//! [`Attachment::assurance`] from the custody record and never read from a
//! field the node states about itself. The rung also holds which processing
//! node signs for which sensing node.

use crate::leaf::Attachment;
use crate::nicla::NodeRole;
use furcate_identity::AssuranceClass;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub public_key: String,
    /// The class the node's key custody earns.
    pub assurance: AssuranceClass,
    pub role: NodeRole,
}

#[derive(Clone, Debug, Default)]
pub struct Directory {
    nodes: BTreeMap<String, NodeRecord>,
    /// Sensing node id to the processing node that signs for it.
    sensing: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryError {
    /// A sensing node is not a signer and is bound, not enrolled as a key.
    NotAProcessingRole(NodeRole),
    UnknownGateway(String),
    Record(String),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::NotAProcessingRole(r) => write!(f, "role {r:?} does not sign"),
            DirectoryError::UnknownGateway(g) => write!(f, "gateway `{g}` is not enrolled"),
            DirectoryError::Record(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrol a processing node from its attachment record.
    pub fn add_node(&mut self, attachment: &Attachment, role: NodeRole) -> Result<(), DirectoryError> {
        if role == NodeRole::Sensing {
            return Err(DirectoryError::NotAProcessingRole(role));
        }
        self.nodes.insert(
            attachment.leaf_id.clone(),
            NodeRecord {
                node_id: attachment.leaf_id.clone(),
                public_key: attachment.public_key.clone(),
                assurance: attachment.assurance(),
                role,
            },
        );
        Ok(())
    }

    /// Record that `gateway` signs for `sensing_node`.
    pub fn bind_sensing(&mut self, sensing_node: &str, gateway: &str) -> Result<(), DirectoryError> {
        if !self.nodes.contains_key(gateway) {
            return Err(DirectoryError::UnknownGateway(gateway.to_string()));
        }
        self.sensing.insert(sensing_node.to_string(), gateway.to_string());
        Ok(())
    }

    pub fn node(&self, id: &str) -> Option<&NodeRecord> {
        self.nodes.get(id)
    }

    pub fn gateway_of(&self, sensing_node: &str) -> Option<&NodeRecord> {
        self.sensing.get(sensing_node).and_then(|g| self.nodes.get(g))
    }

    pub fn sensing_nodes(&self) -> impl Iterator<Item = (&str, &NodeRecord)> {
        self.sensing.iter().filter_map(|(s, g)| self.nodes.get(g).map(|n| (s.as_str(), n)))
    }

    pub fn key_of(&self, id: &str) -> Option<String> {
        self.nodes.get(id).map(|n| n.public_key.clone())
    }

    /// Read the operator's directory file:
    /// `{"nodes":[{"role":"micro_processing","attachment":{...}}],
    ///   "sensing":[{"sensing_node":"...","gateway":"..."}]}`
    /// where each attachment is the record [`Attachment::from_record`] reads.
    pub fn from_json(v: &Value) -> Result<Self, DirectoryError> {
        #[derive(Deserialize)]
        struct Node {
            role: NodeRole,
            attachment: Value,
        }
        #[derive(Deserialize)]
        struct Bind {
            sensing_node: String,
            gateway: String,
        }
        #[derive(Deserialize)]
        struct File {
            nodes: Vec<Node>,
            #[serde(default)]
            sensing: Vec<Bind>,
        }
        let f: File = serde_json::from_value(v.clone()).map_err(|e| DirectoryError::Record(e.to_string()))?;
        let mut d = Directory::new();
        for n in f.nodes {
            let att = Attachment::from_record(&n.attachment).map_err(DirectoryError::Record)?;
            d.add_node(&att, n.role)?;
        }
        for b in f.sensing {
            d.bind_sensing(&b.sensing_node, &b.gateway)?;
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::Leaf;
    use furcate_identity::{LeafKeyCustody, Lockdown};

    #[test]
    fn the_class_comes_from_custody_not_from_a_statement() {
        let l = Leaf::new("furcate:node:micro1", [1; 32]);
        let mut d = Directory::new();
        d.add_node(&l.attach("p", None, 0), NodeRole::MicroProcessing).unwrap();
        assert_eq!(d.node("furcate:node:micro1").unwrap().assurance, AssuranceClass::Soft);
        let fused = Some(LeafKeyCustody::FuseKey { lockdown: Lockdown::default() });
        d.add_node(&l.attach("p", fused, 0), NodeRole::MicroProcessing).unwrap();
        assert_eq!(d.node("furcate:node:micro1").unwrap().assurance, AssuranceClass::Device);
    }

    #[test]
    fn a_sensing_node_is_bound_not_enrolled_and_needs_an_enrolled_gateway() {
        let l = Leaf::new("g", [1; 32]);
        let mut d = Directory::new();
        assert!(d.add_node(&l.attach("p", None, 0), NodeRole::Sensing).is_err());
        assert_eq!(d.bind_sensing("s", "g"), Err(DirectoryError::UnknownGateway("g".into())));
        d.add_node(&l.attach("p", None, 0), NodeRole::MicroProcessing).unwrap();
        d.bind_sensing("s", "g").unwrap();
        assert_eq!(d.gateway_of("s").unwrap().node_id, "g");
        assert!(d.gateway_of("t").is_none());
    }

    #[test]
    fn a_directory_file_reads() {
        let l = Leaf::new("g", [1; 32]);
        let v = serde_json::json!({
            "nodes": [{"role": "micro_processing", "attachment": {
                "leaf_id": "g", "parent": "p", "public_key": l.public_key(), "attached_at": 1,
                "key_custody": {"kind": "fuse-key"}}}],
            "sensing": [{"sensing_node": "s", "gateway": "g"}]
        });
        let d = Directory::from_json(&v).unwrap();
        assert_eq!(d.node("g").unwrap().assurance, AssuranceClass::Device);
        assert_eq!(d.gateway_of("s").unwrap().public_key, l.public_key());
        assert!(Directory::from_json(&serde_json::json!({"nodes": [{"role": "sensing", "attachment": {}}]})).is_err());
    }
}
