use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Empty Merkle tree constant root: SHA-256("CIPHERVAULT_EMPTY_TREE_ROOT")
pub const EMPTY_TREE_ROOT: [u8; 32] = [
    0x56, 0xe4, 0xf6, 0xf5, 0x9f, 0xb8, 0xfe, 0xae, 0x32, 0x4e, 0xab, 0xa4, 0x59, 0xf4, 0x52, 0x1b,
    0x0f, 0xc0, 0x18, 0xcd, 0xbe, 0xcd, 0x16, 0xf8, 0x19, 0x66, 0x7a, 0x5c, 0x1d, 0x7e, 0x1f, 0x57,
];

/// Computes the domain-separated leaf hash for raw leaf data: SHA-256(0x00 || data).
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Computes an internal node hash from left and right children: SHA-256(0x01 || left || right).
pub fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Audit step in an inclusion proof.
/// `sibling`: 32-byte hash of the sibling node.
/// `is_left`: true if the sibling is to the left of the current node, false if on the right.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub is_left: bool,
}

/// Self-contained cryptographic Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_hash: [u8; 32],
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub steps: Vec<ProofStep>,
}

impl InclusionProof {
    /// Computes the calculated Merkle root by traversing the audit steps from leaf to root.
    pub fn calculate_root(&self) -> [u8; 32] {
        let mut current = self.leaf_hash;
        for step in &self.steps {
            if step.is_left {
                current = hash_nodes(&step.sibling, &current);
            } else {
                current = hash_nodes(&current, &step.sibling);
            }
        }
        current
    }

    /// Verifies that this inclusion proof links `self.leaf_hash` to the provided `expected_root`.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        &self.calculate_root() == expected_root
    }
}

/// Binary Merkle tree implementation with RFC 6962 domain separation.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaf_hashes: Vec<[u8; 32]>,
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Builds a Merkle tree from raw leaf hashes.
    pub fn new(leaf_hashes: Vec<[u8; 32]>) -> Self {
        if leaf_hashes.is_empty() {
            return Self {
                leaf_hashes: Vec::new(),
                layers: Vec::new(),
            };
        }

        let mut layers = Vec::new();
        layers.push(leaf_hashes.clone());

        let mut current_layer = leaf_hashes.clone();
        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity(current_layer.len().div_ceil(2));
            for chunk in current_layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(hash_nodes(&chunk[0], &chunk[1]));
                } else {
                    // Odd leaf: duplicate to balance tree
                    next_layer.push(hash_nodes(&chunk[0], &chunk[0]));
                }
            }
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        Self {
            leaf_hashes,
            layers,
        }
    }

    /// Returns the 32-byte Merkle root.
    pub fn root(&self) -> [u8; 32] {
        if self.leaf_hashes.is_empty() {
            return EMPTY_TREE_ROOT;
        }
        if let Some(top_layer) = self.layers.last() {
            if let Some(root) = top_layer.first() {
                return *root;
            }
        }
        EMPTY_TREE_ROOT
    }

    /// Generates an inclusion proof for the leaf at `index`.
    pub fn generate_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaf_hashes.len() {
            return None;
        }

        let leaf_hash = self.leaf_hashes[index];
        let mut steps = Vec::new();
        let mut idx = index;

        // Traverse layers except the root layer
        for layer in self.layers.iter().take(self.layers.len().saturating_sub(1)) {
            let is_right_child = idx % 2 == 1;
            let sibling_idx = if is_right_child {
                idx - 1
            } else if idx + 1 < layer.len() {
                idx + 1
            } else {
                // Sibling was duplicated self
                idx
            };

            let sibling = layer[sibling_idx];
            steps.push(ProofStep {
                sibling,
                is_left: is_right_child,
            });

            idx /= 2;
        }

        Some(InclusionProof {
            leaf_hash,
            leaf_index: index,
            total_leaves: self.leaf_hashes.len(),
            steps,
        })
    }

    /// Total number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_merkle_tree() {
        let tree = MerkleTree::new(vec![]);
        assert_eq!(tree.root(), EMPTY_TREE_ROOT);
        assert!(tree.is_empty());
        assert_eq!(tree.generate_proof(0), None);
    }

    #[test]
    fn test_single_leaf_merkle_tree() {
        let leaf = hash_leaf(b"vault_state_genesis");
        let tree = MerkleTree::new(vec![leaf]);
        assert_eq!(tree.root(), leaf);
        assert_eq!(tree.len(), 1);

        let proof = tree.generate_proof(0).expect("proof exists");
        assert_eq!(proof.leaf_hash, leaf);
        assert_eq!(proof.steps.len(), 0);
        assert!(proof.verify(&leaf));
    }

    #[test]
    fn test_multi_leaf_merkle_tree_and_proofs() {
        let leaves: Vec<[u8; 32]> = (0..7)
            .map(|i| hash_leaf(format!("commitment_tx_{}", i).as_bytes()))
            .collect();

        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();
        assert_ne!(root, EMPTY_TREE_ROOT);

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(idx).expect("proof must exist");
            assert_eq!(&proof.leaf_hash, leaf);
            assert!(proof.verify(&root), "Proof for leaf {} must verify", idx);

            // Tamper test: modifying leaf must fail
            let mut tampered_proof = proof.clone();
            tampered_proof.leaf_hash[0] ^= 0xff;
            assert!(!tampered_proof.verify(&root));

            // Tamper test: wrong root must fail
            let mut fake_root = root;
            fake_root[31] ^= 0x01;
            assert!(!proof.verify(&fake_root));
        }
    }
}
