//! RFC 9162 §2.1.1 Merkle Tree Hash over SHA-256.
//!
//! A leaf is hashed as `SHA-256(0x00 || entry)` and an interior node as
//! `SHA-256(0x01 || left || right)`. A list of `n > 1` entries splits at
//! the largest power of two `k < n`: the left subtree holds the first `k`
//! entries and the right subtree the rest. A node without a sibling is
//! promoted unchanged, never paired with a copy of itself, so the shape of
//! the tree depends only on `n`.

use sha2::{Digest, Sha256};

/// Size in bytes of every hash in the tree.
pub const HASH_SIZE: usize = 32;

/// A SHA-256 Merkle tree hash: a leaf hash, an interior node or a root.
pub type Hash = [u8; HASH_SIZE];

/// Domain-separation prefix of a leaf hash.
pub const LEAF_HASH_PREFIX: u8 = 0x00;

/// Domain-separation prefix of an interior node hash.
pub const NODE_HASH_PREFIX: u8 = 0x01;

/// `MTH({})`: the root of the empty tree, `SHA-256("")`.
pub fn empty_root() -> Hash {
    Sha256::digest(b"").into()
}

/// `MTH({entry})`: the leaf hash of one entry, `SHA-256(0x00 || entry)`.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_HASH_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

/// The hash of an interior node, `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_HASH_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// `MTH(D_n)` from the leaf hashes of `D_n`.
///
/// This is the stack algorithm of RFC 9162 §2.1.2: O(n) time and
/// O(log n) memory. An empty slice gives [`empty_root`].
pub fn root_from_leaf_hashes(leaf_hashes: &[Hash]) -> Hash {
    let mut stack: Vec<Hash> = Vec::with_capacity(64);
    for (i, leaf) in leaf_hashes.iter().enumerate() {
        stack.push(*leaf);
        // Merge once for every trailing 1 bit of i: each one closes a
        // complete subtree that ends at leaf i.
        for _ in 0..i.trailing_ones() {
            merge_top(&mut stack);
        }
    }
    // Fold the remaining complete subtrees from right to left.
    while stack.len() > 1 {
        merge_top(&mut stack);
    }
    stack.pop().unwrap_or_else(empty_root)
}

/// Replaces the top two stack entries (left below right) with their parent.
fn merge_top(stack: &mut Vec<Hash>) {
    let len = stack.len();
    if len < 2 {
        return;
    }
    let parent = node_hash(&stack[len - 2], &stack[len - 1]);
    stack.truncate(len - 2);
    stack.push(parent);
}

/// The largest power of two strictly less than `n`, for `n >= 2`: the
/// size of the left subtree of a tree with `n` leaves.
pub(crate) fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2, "only trees of two or more leaves split");
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_point_is_largest_power_of_two_below_n() {
        for n in 2usize..=4097 {
            let k = split_point(n);
            assert!(k.is_power_of_two(), "n={n}");
            assert!(k < n && n <= 2 * k, "n={n} k={k}");
        }
        assert_eq!(split_point(usize::MAX), 1 << (usize::BITS - 1));
    }

    #[test]
    fn merge_top_ignores_short_stacks() {
        let mut stack = vec![[7u8; 32]];
        merge_top(&mut stack);
        assert_eq!(stack, vec![[7u8; 32]]);
    }
}
