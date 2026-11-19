//! RFC 9162 inclusion proofs (§2.1.3) and consistency proofs (§2.1.4).
//!
//! Generation follows the recursive `PATH` and `PROOF`/`SUBPROOF`
//! definitions of the RFC over a slice of leaf hashes, which costs O(n)
//! hashing per proof. Verification follows the iterative algorithms of
//! §2.1.3.2 and §2.1.4.2 and costs O(log n).
//!
//! Hashes appear in a proof bottom-up: the first one is the sibling closest
//! to the leaf (or to the old tree), the last one is a child of the root.
//!
//! The RFC leaves some inputs open. This module rejects them, matching the
//! transparency-dev/merkle reference implementation and its test probes:
//!
//! * an inclusion proof for an index at or past the tree size;
//! * a consistency proof from the empty tree (size 0), since every tree
//!   trivially extends it;
//! * a non-empty consistency proof between equal sizes (an empty one
//!   verifies only if the two roots are equal).
//!
//! A proof binds the leaf index, and binds the tree size together with the
//! root it is checked against. A verifier must therefore take the size and
//! the root from the same signed checkpoint, never one from the proof
//! sender and the other from somewhere else.

use crate::hash::{node_hash, root_from_leaf_hashes, split_point, Hash};

/// The most hashes an inclusion proof can have: one per level of a tree of
/// at most 2^64 - 1 leaves.
pub const MAX_INCLUSION_PROOF_LEN: usize = 64;

/// The most hashes a consistency proof can have: `ceil(log2(n)) + 1` for
/// `n < 2^64` (RFC 9162 §2.1.4.1).
pub const MAX_CONSISTENCY_PROOF_LEN: usize = 65;

/// Why a proof could not be generated or did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The leaf index is not inside the tree.
    #[error("leaf index {index} is outside a tree of size {tree_size}")]
    IndexOutOfRange {
        /// The requested leaf index.
        index: u64,
        /// The size of the tree.
        tree_size: u64,
    },
    /// The old tree is larger than the new tree.
    #[error("old tree size {old_size} is larger than new tree size {new_size}")]
    SizeOrder {
        /// The size of the old tree.
        old_size: u64,
        /// The size of the new tree.
        new_size: u64,
    },
    /// A consistency proof from the empty tree proves nothing.
    #[error("a consistency proof from the empty tree is meaningless")]
    EmptyOldTree,
    /// The proof has the wrong number of hashes for the claimed position.
    #[error("proof has the wrong number of hashes")]
    WrongLength,
    /// The proof is well-formed but does not lead to the expected root.
    #[error("proof does not match the expected root hash")]
    RootMismatch,
}

/// `PATH(index, D_n)`: the inclusion proof for leaf `index` in the tree
/// whose leaf hashes are `leaf_hashes` (so `n = leaf_hashes.len()`).
///
/// To prove inclusion in an older tree of size `m`, pass
/// `&leaf_hashes[..m]`.
pub fn inclusion_proof(leaf_hashes: &[Hash], index: u64) -> Result<Vec<Hash>, ProofError> {
    let tree_size = leaf_hashes.len() as u64;
    if index >= tree_size {
        return Err(ProofError::IndexOutOfRange { index, tree_size });
    }
    let mut proof = Vec::new();
    // index < leaf_hashes.len(), so it fits in usize.
    path(index as usize, leaf_hashes, &mut proof);
    Ok(proof)
}

fn path(m: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split_point(leaves.len());
    let (left, right) = leaves.split_at(k);
    if m < k {
        path(m, left, out);
        out.push(root_from_leaf_hashes(right));
    } else {
        path(m - k, right, out);
        out.push(root_from_leaf_hashes(left));
    }
}

/// `PROOF(old_size, D_n)`: the consistency proof from the tree of the
/// first `old_size` leaves to the tree of all of `leaf_hashes`.
///
/// `old_size` must be in `1..=n`. For `old_size == n` the proof is empty.
pub fn consistency_proof(leaf_hashes: &[Hash], old_size: u64) -> Result<Vec<Hash>, ProofError> {
    let new_size = leaf_hashes.len() as u64;
    if old_size > new_size {
        return Err(ProofError::SizeOrder { old_size, new_size });
    }
    if old_size == 0 {
        return Err(ProofError::EmptyOldTree);
    }
    let mut proof = Vec::new();
    // old_size <= leaf_hashes.len(), so it fits in usize.
    subproof(old_size as usize, leaf_hashes, true, &mut proof);
    Ok(proof)
}

/// `SUBPROOF(m, D_n, complete)`, appending to `out`. Requires `1 <= m <= n`.
fn subproof(m: usize, leaves: &[Hash], complete: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !complete {
            out.push(root_from_leaf_hashes(leaves));
        }
        return;
    }
    // Here 1 <= m < n, so n >= 2.
    let k = split_point(n);
    let (left, right) = leaves.split_at(k);
    if m <= k {
        subproof(m, left, complete, out);
        out.push(root_from_leaf_hashes(right));
    } else {
        subproof(m - k, right, false, out);
        out.push(root_from_leaf_hashes(left));
    }
}

/// Recomputes the root of a tree of `tree_size` leaves from the hash of
/// leaf `index` and its inclusion proof (RFC 9162 §2.1.3.2, steps 1 to 4).
///
/// The result is only meaningful once compared with a trusted root; use
/// [`verify_inclusion`] unless you need the root itself.
pub fn root_from_inclusion_proof(
    leaf_hash: &Hash,
    index: u64,
    tree_size: u64,
    proof: &[Hash],
) -> Result<Hash, ProofError> {
    if index >= tree_size {
        return Err(ProofError::IndexOutOfRange { index, tree_size });
    }
    if proof.len() > MAX_INCLUSION_PROOF_LEN {
        return Err(ProofError::WrongLength);
    }
    let mut f_n = index;
    let mut s_n = tree_size - 1;
    let mut r = *leaf_hash;
    for p in proof {
        if s_n == 0 {
            // More hashes than levels on the path.
            return Err(ProofError::WrongLength);
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node_hash(p, &r);
            if f_n & 1 == 0 {
                // Right border of the tree: skip the levels where this node
                // was promoted without a sibling.
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if s_n != 0 {
        // Fewer hashes than levels on the path.
        return Err(ProofError::WrongLength);
    }
    Ok(r)
}

/// Verifies that `leaf_hash` is leaf `index` of the tree of `tree_size`
/// leaves whose root is `root` (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(
    leaf_hash: &Hash,
    index: u64,
    tree_size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), ProofError> {
    let computed = root_from_inclusion_proof(leaf_hash, index, tree_size, proof)?;
    if computed == *root {
        Ok(())
    } else {
        Err(ProofError::RootMismatch)
    }
}

/// Verifies that the tree of `old_size` leaves with root `old_root` is a
/// prefix of the tree of `new_size` leaves with root `new_root`
/// (RFC 9162 §2.1.4.2).
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    proof: &[Hash],
    old_root: &Hash,
    new_root: &Hash,
) -> Result<(), ProofError> {
    if old_size > new_size {
        return Err(ProofError::SizeOrder { old_size, new_size });
    }
    if old_size == 0 {
        return Err(ProofError::EmptyOldTree);
    }
    if old_size == new_size {
        if !proof.is_empty() {
            return Err(ProofError::WrongLength);
        }
        return if old_root == new_root {
            Ok(())
        } else {
            Err(ProofError::RootMismatch)
        };
    }

    // Step 1.
    if proof.is_empty() || proof.len() > MAX_CONSISTENCY_PROOF_LEN {
        return Err(ProofError::WrongLength);
    }
    // Step 2: if the old tree is complete, its root is the first node of
    // the path and the proof does not repeat it.
    let (first, rest) = if old_size.is_power_of_two() {
        (old_root, proof)
    } else {
        (&proof[0], &proof[1..])
    };
    // Steps 3 and 4.
    let mut f_n = old_size - 1;
    let mut s_n = new_size - 1;
    while f_n & 1 == 1 {
        f_n >>= 1;
        s_n >>= 1;
    }
    // Step 5.
    let mut f_r = *first;
    let mut s_r = *first;
    // Step 6.
    for c in rest {
        if s_n == 0 {
            return Err(ProofError::WrongLength);
        }
        if f_n & 1 == 1 || f_n == s_n {
            f_r = node_hash(c, &f_r);
            s_r = node_hash(c, &s_r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            s_r = node_hash(&s_r, c);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    // Step 7.
    if s_n != 0 {
        return Err(ProofError::WrongLength);
    }
    if f_r == *old_root && s_r == *new_root {
        Ok(())
    } else {
        Err(ProofError::RootMismatch)
    }
}
