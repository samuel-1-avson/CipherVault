//! Compact ranges: O(log n) appends and the root of a growing tree.
//!
//! The compact range of the leaves `[begin, end)` is the minimal list of
//! complete subtrees that exactly covers those leaves, ordered left to
//! right. It holds at most two hashes per tree level, so appending a leaf
//! or reading the root of `[0, n)` costs O(log n) hashes and needs no
//! other part of the tree (ADR-014, CC-14).
//!
//! Two adjacent ranges merge into one, which lets a sequencer hash batches
//! of leaves independently and join the results.

use crate::hash::{empty_root, node_hash, Hash};

/// A node of the tree: the complete subtree of `2^level` leaves starting
/// at leaf `index * 2^level`. Level 0 holds the leaf hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    /// Height of the node above the leaves.
    pub level: u8,
    /// Position of the node among the nodes of its level.
    pub index: u64,
}

/// Why a compact range operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CompactRangeError {
    /// `begin` is after `end`.
    #[error("range begin {begin} is after range end {end}")]
    InvalidRange {
        /// First leaf of the range.
        begin: u64,
        /// One past the last leaf of the range.
        end: u64,
    },
    /// The hash list does not match the shape of the range.
    #[error("range [{begin}, {end}) needs {expected} hashes, got {got}")]
    WrongHashCount {
        /// First leaf of the range.
        begin: u64,
        /// One past the last leaf of the range.
        end: u64,
        /// Number of hashes the range needs.
        expected: usize,
        /// Number of hashes supplied.
        got: usize,
    },
    /// The ranges do not touch.
    #[error("a range ending at {end} cannot be extended by a range beginning at {other_begin}")]
    NotAdjacent {
        /// End of the range being extended.
        end: u64,
        /// Begin of the range that was supposed to follow it.
        other_begin: u64,
    },
    /// The range would grow past 2^64 - 1 leaves.
    #[error("the tree cannot grow past 2^64 - 1 leaves")]
    Full,
    /// Only a range that starts at leaf 0 describes a whole tree.
    #[error("a range beginning at leaf {begin} has no tree root")]
    NotFromZero {
        /// First leaf of the range.
        begin: u64,
    },
}

/// The compact range of the leaves `[begin, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactRange {
    begin: u64,
    end: u64,
    hashes: Vec<Hash>,
}

impl CompactRange {
    /// An empty range positioned at leaf `begin`.
    pub fn new(begin: u64) -> Self {
        Self {
            begin,
            end: begin,
            hashes: Vec::new(),
        }
    }

    /// Rebuilds a range from stored parts, checking that the number of
    /// hashes matches the shape of `[begin, end)`.
    pub fn from_parts(begin: u64, end: u64, hashes: Vec<Hash>) -> Result<Self, CompactRangeError> {
        if begin > end {
            return Err(CompactRangeError::InvalidRange { begin, end });
        }
        let (left, right) = decompose(begin, end);
        let expected = (left.count_ones() + right.count_ones()) as usize;
        if hashes.len() != expected {
            return Err(CompactRangeError::WrongHashCount {
                begin,
                end,
                expected,
                got: hashes.len(),
            });
        }
        Ok(Self { begin, end, hashes })
    }

    /// First leaf of the range.
    pub fn begin(&self) -> u64 {
        self.begin
    }

    /// One past the last leaf of the range.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Number of leaves in the range.
    pub fn len(&self) -> u64 {
        self.end - self.begin
    }

    /// Whether the range covers no leaves.
    pub fn is_empty(&self) -> bool {
        self.begin == self.end
    }

    /// The subtree hashes, left to right.
    pub fn hashes(&self) -> &[Hash] {
        &self.hashes
    }

    /// Appends one leaf hash.
    pub fn append(&mut self, leaf_hash: Hash) -> Result<(), CompactRangeError> {
        self.append_with(leaf_hash, |_, _| {})
    }

    /// Appends one leaf hash, calling `visit` for the leaf and for every
    /// interior node the append completes, lowest level first.
    ///
    /// Together the visits of successive appends from leaf 0 cover every
    /// complete subtree exactly once, which is what a tile writer needs.
    pub fn append_with<F>(&mut self, leaf_hash: Hash, mut visit: F) -> Result<(), CompactRangeError>
    where
        F: FnMut(NodeId, &Hash),
    {
        if self.end == u64::MAX {
            return Err(CompactRangeError::Full);
        }
        visit(
            NodeId {
                level: 0,
                index: self.end,
            },
            &leaf_hash,
        );
        self.push(0, leaf_hash, &mut visit)
    }

    /// Appends the adjacent range `other`, which must begin where this
    /// range ends.
    pub fn extend(&mut self, other: &CompactRange) -> Result<(), CompactRangeError> {
        if other.begin != self.end {
            return Err(CompactRangeError::NotAdjacent {
                end: self.end,
                other_begin: other.begin,
            });
        }
        // other.end fits in u64, so no push below can overflow, and each
        // node of `other` is aligned to its own size at the position where
        // it is pushed.
        let mut ignore = |_: NodeId, _: &Hash| {};
        for (level, hash) in node_levels(other.begin, other.end).zip(&other.hashes) {
            self.push(level, *hash, &mut ignore)?;
        }
        Ok(())
    }

    /// The root of the tree of leaves `[0, end)`. The range must begin at
    /// leaf 0. An empty range gives [`empty_root`].
    pub fn root(&self) -> Result<Hash, CompactRangeError> {
        if self.begin != 0 {
            return Err(CompactRangeError::NotFromZero { begin: self.begin });
        }
        let mut from_right = self.hashes.iter().rev();
        let Some(last) = from_right.next() else {
            return Ok(empty_root());
        };
        Ok(from_right.fold(*last, |acc, left| node_hash(left, &acc)))
    }

    /// Pushes the root of a complete subtree of `2^level` leaves that
    /// starts at `self.end`, merging it with every left sibling already
    /// in the range.
    fn push(
        &mut self,
        level: u32,
        hash: Hash,
        visit: &mut dyn FnMut(NodeId, &Hash),
    ) -> Result<(), CompactRangeError> {
        let width = 1u64.checked_shl(level).ok_or(CompactRangeError::Full)?;
        let new_end = self.end.checked_add(width).ok_or(CompactRangeError::Full)?;

        let mut level = level;
        let mut hash = hash;
        let mut start = self.end;
        // A node at level 63 cannot be a right child here: its left sibling
        // would make the range 2^64 leaves long, which new_end rules out.
        while level < 63 {
            let index = start >> level;
            if index & 1 == 0 {
                break; // a left child: its sibling is not in the range yet
            }
            let sibling_start = start - (1u64 << level);
            if sibling_start < self.begin {
                break; // the sibling starts before the range
            }
            // The left sibling is a complete subtree inside the range and
            // ends where this node starts, so it is the last hash held.
            let Some(left) = self.hashes.pop() else {
                break;
            };
            hash = node_hash(&left, &hash);
            start = sibling_start;
            level += 1;
            visit(
                NodeId {
                    level: level as u8,
                    index: start >> level,
                },
                &hash,
            );
        }
        self.hashes.push(hash);
        self.end = new_end;
        Ok(())
    }
}

/// Splits `[begin, end)` into its left and right parts. The compact range
/// holds one node at level `i` for each set bit `i` of the left mask, in
/// ascending order, followed by one node at level `i` for each set bit of
/// the right mask, in descending order.
fn decompose(begin: u64, end: u64) -> (u64, u64) {
    if begin == 0 {
        return (0, end);
    }
    // The paths from the root to leaf begin-1 and to leaf end diverge at
    // the highest differing bit. Every node of the range sits strictly
    // below that point: right of the begin-1 path where begin-1 has a 0
    // bit, and left of the end path where end has a 1 bit.
    let before = begin - 1;
    let diverge = 63 - (before ^ end).leading_zeros();
    let mask = (1u64 << diverge) - 1;
    (!before & mask, end & mask)
}

/// The level of each node of `[begin, end)`, left to right.
fn node_levels(begin: u64, end: u64) -> impl Iterator<Item = u32> {
    let (left, right) = decompose(begin, end);
    let ascending = (0..64u32).filter(move |bit| (left >> bit) & 1 == 1);
    let descending = (0..64u32).rev().filter(move |bit| (right >> bit) & 1 == 1);
    ascending.chain(descending)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_examples() {
        // [1, 7): leaf 1, [2, 4) | [4, 6), leaf 6.
        assert_eq!(decompose(1, 7), (0b011, 0b011));
        // [4, 8) is one node at level 2.
        assert_eq!(decompose(4, 8), (0b100, 0));
        // [2, 8): [2, 4) at level 1, [4, 8) at level 2.
        assert_eq!(decompose(2, 8), (0b110, 0));
        // Empty ranges hold nothing.
        assert_eq!(decompose(4, 4), (0, 0));
        assert_eq!(decompose(5, 5), (0, 0));
        // From zero, the right part is the binary expansion of end.
        assert_eq!(decompose(0, 13), (0, 13));
        assert_eq!(node_levels(1, 7).collect::<Vec<_>>(), vec![0, 1, 1, 0]);
        assert_eq!(node_levels(0, 13).collect::<Vec<_>>(), vec![3, 2, 0]);
    }

    #[test]
    fn decompose_extremes() {
        let (left, right) = decompose(1, u64::MAX);
        let count = (left.count_ones() + right.count_ones()) as usize;
        assert!(count <= 2 * 64);
        assert_eq!(decompose(u64::MAX, u64::MAX), (0, 0));
    }
}
