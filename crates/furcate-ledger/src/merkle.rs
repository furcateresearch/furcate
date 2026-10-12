//! Merkle aggregation of node chain heads into a site root.
//!
//! One anchored root covers every node's full operational history, and any
//! individual head can be proven against it with a path of log(n) digests.
//! That is what makes external anchoring affordable: a site publishes one
//! value per epoch rather than one per node.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation tags, so a leaf digest can never be reinterpreted as an
/// interior node. Without these an attacker could present an interior hash as
/// though it were a leaf and forge an inclusion proof.
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update(data);
    h.finalize().into()
}

fn hash_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// A binary Merkle tree over leaves held in insertion order.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
}

/// A path proving one leaf belongs to a root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    pub index: usize,
    pub leaf: String,
    /// Sibling digests from the leaf upward, with a flag for which side the
    /// sibling sits on.
    pub path: Vec<(bool, String)>,
}

impl MerkleTree {
    /// Build a tree over the given leaf payloads.
    ///
    /// An odd node at any level is promoted rather than duplicated. Duplicating
    /// it would make two distinct leaf sets produce the same root, which is a
    /// well-known way to break inclusion proofs.
    pub fn build(payloads: &[Vec<u8>]) -> Option<Self> {
        if payloads.is_empty() {
            return None;
        }
        let leaves: Vec<[u8; 32]> = payloads.iter().map(|p| hash_leaf(p)).collect();
        let mut levels = vec![leaves.clone()];
        while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                if i + 1 < prev.len() {
                    next.push(hash_node(&prev[i], &prev[i + 1]));
                } else {
                    next.push(prev[i]);
                }
                i += 2;
            }
            levels.push(next);
        }
        Some(Self { leaves, levels })
    }

    pub fn root(&self) -> [u8; 32] {
        *self.levels.last().and_then(|l| l.first()).expect("non-empty")
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Produce an inclusion proof for the leaf at `index`.
    pub fn prove(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut path = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            if sibling < level.len() {
                // `true` means the sibling is on the right.
                path.push((idx.is_multiple_of(2), hex::encode(level[sibling])));
            }
            idx /= 2;
        }
        Some(InclusionProof {
            index,
            leaf: hex::encode(self.leaves[index]),
            path,
        })
    }

    /// Check a proof against a root without needing the tree.
    pub fn verify(proof: &InclusionProof, root_hex: &str) -> bool {
        let Ok(leaf) = hex::decode(&proof.leaf) else {
            return false;
        };
        let Ok(mut acc) = <[u8; 32]>::try_from(leaf.as_slice()) else {
            return false;
        };
        for (sibling_on_right, sib_hex) in &proof.path {
            let Ok(sib) = hex::decode(sib_hex) else {
                return false;
            };
            let Ok(sib) = <[u8; 32]>::try_from(sib.as_slice()) else {
                return false;
            };
            acc = if *sibling_on_right {
                hash_node(&acc, &sib)
            } else {
                hash_node(&sib, &acc)
            };
        }
        hex::encode(acc) == root_hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payloads(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("node-head-{i}").into_bytes()).collect()
    }

    #[test]
    fn empty_input_has_no_tree() {
        assert!(MerkleTree::build(&[]).is_none());
    }

    #[test]
    fn every_leaf_proves_against_the_root() {
        for n in [1usize, 2, 3, 4, 5, 8, 9, 17] {
            let t = MerkleTree::build(&payloads(n)).unwrap();
            let root = t.root_hex();
            for i in 0..n {
                let p = t.prove(i).unwrap();
                assert!(MerkleTree::verify(&p, &root), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn a_proof_for_the_wrong_root_fails() {
        let t = MerkleTree::build(&payloads(5)).unwrap();
        let other = MerkleTree::build(&payloads(6)).unwrap();
        let p = t.prove(2).unwrap();
        assert!(!MerkleTree::verify(&p, &other.root_hex()));
    }

    #[test]
    fn tampering_with_a_leaf_changes_the_root() {
        let a = MerkleTree::build(&payloads(4)).unwrap();
        let mut altered = payloads(4);
        altered[2] = b"tampered".to_vec();
        let b = MerkleTree::build(&altered).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn leaves_and_interior_nodes_are_domain_separated() {
        // A single leaf's root must not equal the raw hash of its payload,
        // or an interior digest could be replayed as a leaf.
        let t = MerkleTree::build(&[b"x".to_vec()]).unwrap();
        let naive: [u8; 32] = Sha256::digest(b"x").into();
        assert_ne!(t.root(), naive);
    }

    #[test]
    fn odd_leaf_promotion_keeps_sets_distinct() {
        // Three leaves must not collide with the four-leaf set that would
        // result from duplicating the last one.
        let three = MerkleTree::build(&payloads(3)).unwrap();
        let mut dup = payloads(3);
        dup.push(dup[2].clone());
        let four = MerkleTree::build(&dup).unwrap();
        assert_ne!(three.root(), four.root());
    }

    #[test]
    fn out_of_range_index_has_no_proof() {
        let t = MerkleTree::build(&payloads(3)).unwrap();
        assert!(t.prove(3).is_none());
    }
}
