//! Property tests over exhaustive small trees and random larger ones.
//!
//! Every honest inclusion and consistency proof must verify. Every proof
//! with a flipped bit, a missing, extra or reordered hash, a wrong leaf, a
//! wrong root or a wrong index must fail.
//!
//! Sizes need care. RFC 9162 verification binds the tree size together
//! with the root: the size only decides the path shape, and the root
//! decides the hashes. So the tests check two things:
//!
//! * against the honest root of another size (another signed checkpoint
//!   of the same log), a proof verifies only if it is that size's own
//!   proof;
//! * against the original root, a proof for a wrong size verifies exactly
//!   when both sizes give the same path shape. That (size, root) pair is a
//!   claim no log signs, which is why callers must take the size and the
//!   root from one signed checkpoint.

mod common;

use std::collections::HashMap;

use ciphervault_translog::compact::{CompactRange, CompactRangeError, NodeId};
use ciphervault_translog::proof::{
    consistency_proof, inclusion_proof, verify_consistency, verify_inclusion, ProofError,
    MAX_CONSISTENCY_PROOF_LEN, MAX_INCLUSION_PROOF_LEN,
};
use ciphervault_translog::{root_from_leaf_hashes, Hash};
use common::{flip_bit, iterations, random_leaves, reference_root, rng};
use rand::rngs::StdRng;
use rand::Rng;

/// The shape of `PATH(m, D_n)` from the recursive definition, bottom-up:
/// `true` where the proof hash is a right sibling. `None` if `m >= n`.
fn path_shape(m: u64, n: u64) -> Option<Vec<bool>> {
    fn walk(m: u64, n: u64, out: &mut Vec<bool>) {
        if n <= 1 {
            return;
        }
        let mut k = 1u64;
        while k * 2 < n {
            k *= 2;
        }
        if m < k {
            walk(m, k, out);
            out.push(true);
        } else {
            walk(m - k, n - k, out);
            out.push(false);
        }
    }
    if m >= n {
        return None;
    }
    let mut out = Vec::new();
    walk(m, n, &mut out);
    Some(out)
}

/// Roots of every prefix of `leaves`, from the reference definition.
fn prefix_roots(leaves: &[Hash]) -> Vec<Hash> {
    (0..=leaves.len())
        .map(|n| reference_root(&leaves[..n]))
        .collect()
}

/// Proofs with one hash changed, removed, added or moved.
fn structural_mutations(
    proof: &[Hash],
    extras: &[Hash],
    rng: &mut StdRng,
) -> Vec<(&'static str, Vec<Hash>)> {
    let mut out = Vec::new();
    for i in 0..proof.len() {
        let mut p = proof.to_vec();
        p[i] = flip_bit(&p[i], rng.gen_range(0..256));
        out.push(("flipped proof hash", p));
    }
    if !proof.is_empty() {
        out.push(("dropped last hash", proof[..proof.len() - 1].to_vec()));
        out.push(("dropped first hash", proof[1..].to_vec()));
    }
    for extra in extras {
        let mut appended = proof.to_vec();
        appended.push(*extra);
        out.push(("appended hash", appended));
        let mut prepended = vec![*extra];
        prepended.extend_from_slice(proof);
        out.push(("prepended hash", prepended));
    }
    if proof.len() >= 2 {
        let i = rng.gen_range(0..proof.len());
        let j = (i + rng.gen_range(1..proof.len())) % proof.len();
        if proof[i] != proof[j] {
            let mut swapped = proof.to_vec();
            swapped.swap(i, j);
            out.push(("swapped hashes", swapped));
        }
    }
    out
}

/// Checks one inclusion proof and its mutations. `ext` extends the tree
/// past `n` leaves so that larger honest trees exist.
fn check_inclusion(
    ext: &[Hash],
    roots: &[Hash],
    n: usize,
    m: usize,
    size_checks: bool,
    rng: &mut StdRng,
    seed: u64,
) {
    let ctx = format!("seed {seed}, inclusion of {m} in {n}");
    let (size, index) = (n as u64, m as u64);
    let leaves = &ext[..n];
    let root = roots[n];
    let leaf = leaves[m];
    let proof = inclusion_proof(leaves, index).unwrap();
    assert!(proof.len() <= MAX_INCLUSION_PROOF_LEN, "{ctx}");
    assert_eq!(
        Some(proof.len()),
        path_shape(index, size).map(|s| s.len()),
        "{ctx}"
    );
    if let Err(err) = verify_inclusion(&leaf, index, size, &proof, &root) {
        panic!("{ctx}: honest proof rejected: {err}");
    }

    let rejects = |what: &str, leaf: &Hash, index: u64, size: u64, proof: &[Hash], root: &Hash| {
        assert!(
            verify_inclusion(leaf, index, size, proof, root).is_err(),
            "{ctx}: accepted {what}"
        );
    };
    for bit in [0, 255, rng.gen_range(0..256)] {
        rejects(
            "flipped leaf",
            &flip_bit(&leaf, bit),
            index,
            size,
            &proof,
            &root,
        );
        rejects(
            "flipped root",
            &leaf,
            index,
            size,
            &proof,
            &flip_bit(&root, bit),
        );
    }
    for (what, mutated) in structural_mutations(&proof, &[root, leaf, rng.gen()], rng) {
        rejects(what, &leaf, index, size, &mutated, &root);
    }
    for other in [
        index ^ 1,
        index ^ 2,
        index.wrapping_add(1),
        index.wrapping_sub(1),
        rng.gen_range(0..size),
        u64::MAX,
    ] {
        if other != index {
            rejects("other index", &leaf, other, size, &proof, &root);
        }
    }

    if !size_checks {
        return;
    }
    for other in [
        size + 1,
        size - 1,
        size * 2,
        size / 2,
        size + rng.gen_range(1..=size),
    ] {
        if other == size || other as usize >= roots.len() {
            continue;
        }
        let other_leaves = &ext[..other as usize];
        let honest_other = (index < other).then(|| inclusion_proof(other_leaves, index).unwrap());
        assert_eq!(
            verify_inclusion(&leaf, index, other, &proof, &roots[other as usize]).is_ok(),
            honest_other.as_deref() == Some(proof.as_slice()),
            "{ctx}: against the checkpoint of size {other}"
        );
        assert_eq!(
            verify_inclusion(&leaf, index, other, &proof, &root).is_ok(),
            path_shape(index, other) == path_shape(index, size),
            "{ctx}: size {other} with the size-{n} root"
        );
    }
}

/// Checks one consistency proof and its mutations.
fn check_consistency(
    ext: &[Hash],
    roots: &[Hash],
    m: usize,
    n: usize,
    size_checks: bool,
    rng: &mut StdRng,
    seed: u64,
) {
    let ctx = format!("seed {seed}, consistency {m} -> {n}");
    let (old_size, new_size) = (m as u64, n as u64);
    let (old_root, new_root) = (roots[m], roots[n]);
    let proof = consistency_proof(&ext[..n], old_size).unwrap();
    assert!(proof.len() <= MAX_CONSISTENCY_PROOF_LEN, "{ctx}");
    assert_eq!(m == n, proof.is_empty(), "{ctx}");
    if let Err(err) = verify_consistency(old_size, new_size, &proof, &old_root, &new_root) {
        panic!("{ctx}: honest proof rejected: {err}");
    }

    let rejects = |what: &str,
                   old_size: u64,
                   new_size: u64,
                   proof: &[Hash],
                   old_root: &Hash,
                   new_root: &Hash| {
        assert!(
            verify_consistency(old_size, new_size, proof, old_root, new_root).is_err(),
            "{ctx}: accepted {what}"
        );
    };
    for bit in [0, 255, rng.gen_range(0..256)] {
        rejects(
            "flipped old root",
            old_size,
            new_size,
            &proof,
            &flip_bit(&old_root, bit),
            &new_root,
        );
        rejects(
            "flipped new root",
            old_size,
            new_size,
            &proof,
            &old_root,
            &flip_bit(&new_root, bit),
        );
    }
    if old_root != new_root {
        rejects(
            "swapped roots",
            old_size,
            new_size,
            &proof,
            &new_root,
            &old_root,
        );
    }
    for (what, mutated) in structural_mutations(&proof, &[old_root, new_root, rng.gen()], rng) {
        rejects(what, old_size, new_size, &mutated, &old_root, &new_root);
    }

    if !size_checks {
        return;
    }
    let (r1, r2) = (rng.gen_range(1..=m.max(1)), rng.gen_range(1..=n));
    for (m2, n2) in [
        (m + 1, n),
        (m - 1, n),
        (m * 2, n),
        (m / 2, n),
        (m, n + 1),
        (m, n - 1),
        (m, n * 2),
        (m, n + r2),
        (r1, n),
    ] {
        if (m2, n2) == (m, n) || n2 >= roots.len() || m2 >= roots.len() {
            continue;
        }
        let honest_other =
            (m2 >= 1 && m2 <= n2).then(|| consistency_proof(&ext[..n2], m2 as u64).unwrap());
        assert_eq!(
            verify_consistency(m2 as u64, n2 as u64, &proof, &roots[m2], &roots[n2]).is_ok(),
            honest_other.as_deref() == Some(proof.as_slice()),
            "{ctx}: against the checkpoints of sizes {m2} and {n2}"
        );
    }
}

#[test]
fn roots_agree_with_the_reference_definition() {
    let (mut rng, _) = rng(1);
    let leaves = random_leaves(&mut rng, 300);
    let mut range = CompactRange::new(0);
    for n in 0..=leaves.len() {
        let expected = reference_root(&leaves[..n]);
        assert_eq!(root_from_leaf_hashes(&leaves[..n]), expected, "size {n}");
        assert_eq!(range.root().unwrap(), expected, "compact range at size {n}");
        assert_eq!(
            range.hashes().len() as u32,
            (n as u64).count_ones(),
            "size {n}"
        );
        if n < leaves.len() {
            range.append(leaves[n]).unwrap();
        }
    }
}

#[test]
fn every_inclusion_proof_in_small_trees() {
    let (mut rng, seed) = rng(2);
    for n in 1..=48 {
        let ext = random_leaves(&mut rng, 2 * n + 2);
        let roots = prefix_roots(&ext);
        for m in 0..n {
            check_inclusion(&ext, &roots, n, m, true, &mut rng, seed);
        }
    }
}

#[test]
fn every_consistency_proof_in_small_trees() {
    let (mut rng, seed) = rng(3);
    for n in 1..=40 {
        let ext = random_leaves(&mut rng, 2 * n + 2);
        let roots = prefix_roots(&ext);
        for m in 1..=n {
            check_consistency(&ext, &roots, m, n, true, &mut rng, seed);
        }
    }
}

#[test]
fn proofs_in_random_larger_trees() {
    let (mut rng, seed) = rng(4);
    for _ in 0..iterations(40) {
        let n = rng.gen_range(1..=2500);
        let leaves = random_leaves(&mut rng, n);
        let mut roots = Vec::with_capacity(n + 1);
        let mut range = CompactRange::new(0);
        roots.push(range.root().unwrap());
        for leaf in &leaves {
            range.append(*leaf).unwrap();
            roots.push(range.root().unwrap());
        }
        assert_eq!(roots[n], reference_root(&leaves));
        for _ in 0..4 {
            let m = rng.gen_range(0..n);
            check_inclusion(&leaves, &roots, n, m, false, &mut rng, seed);
            let old = rng.gen_range(1..=n);
            check_consistency(&leaves, &roots, old, n, false, &mut rng, seed);
        }
    }
}

#[test]
fn forked_histories_are_inconsistent() {
    let (mut rng, seed) = rng(5);
    for _ in 0..iterations(300) {
        let n = rng.gen_range(2..=200);
        let m = rng.gen_range(1..n);
        let honest = random_leaves(&mut rng, n);

        // A fork that rewrites a leaf the old tree already had.
        let mut rewritten = honest.clone();
        let j = rng.gen_range(0..m);
        rewritten[j] = rng.gen();
        let old_root = root_from_leaf_hashes(&honest[..m]);
        let forked_root = root_from_leaf_hashes(&rewritten);
        for proof in [
            consistency_proof(&honest, m as u64).unwrap(),
            consistency_proof(&rewritten, m as u64).unwrap(),
        ] {
            assert!(
                verify_consistency(m as u64, n as u64, &proof, &old_root, &forked_root).is_err(),
                "seed {seed}: fork at leaf {j} of {m} -> {n} accepted"
            );
        }

        // A different extension of the same old tree is consistent with it,
        // but only under its own proof.
        let mut extended = honest.clone();
        let j = rng.gen_range(m..n);
        extended[j] = rng.gen();
        let extended_root = root_from_leaf_hashes(&extended);
        verify_consistency(
            m as u64,
            n as u64,
            &consistency_proof(&extended, m as u64).unwrap(),
            &old_root,
            &extended_root,
        )
        .unwrap();
        assert!(verify_consistency(
            m as u64,
            n as u64,
            &consistency_proof(&honest, m as u64).unwrap(),
            &old_root,
            &extended_root
        )
        .is_err());
    }
}

#[test]
fn proof_generation_rejects_bad_positions() {
    let (mut rng, _) = rng(6);
    let leaves = random_leaves(&mut rng, 5);
    assert_eq!(
        inclusion_proof(&leaves, 5),
        Err(ProofError::IndexOutOfRange {
            index: 5,
            tree_size: 5
        })
    );
    assert!(inclusion_proof(&[], 0).is_err());
    assert_eq!(
        consistency_proof(&leaves, 6),
        Err(ProofError::SizeOrder {
            old_size: 6,
            new_size: 5
        })
    );
    assert_eq!(consistency_proof(&leaves, 0), Err(ProofError::EmptyOldTree));
    assert_eq!(consistency_proof(&leaves, 5), Ok(Vec::new()));
    assert_eq!(inclusion_proof(&leaves[..1], 0), Ok(Vec::new()));
}

#[test]
fn compact_ranges_merge_like_direct_builds() {
    let (mut rng, seed) = rng(7);
    for _ in 0..iterations(300) {
        let n = rng.gen_range(0..=600);
        let leaves = random_leaves(&mut rng, n);
        let begin = rng.gen_range(0..=n);
        let mid = rng.gen_range(begin..=n);
        let end = rng.gen_range(mid..=n);
        let build = |from: usize, to: usize| {
            let mut range = CompactRange::new(from as u64);
            for leaf in &leaves[from..to] {
                range.append(*leaf).unwrap();
            }
            range
        };
        let ctx = format!("seed {seed}, [{begin}, {mid}) + [{mid}, {end})");

        let mut merged = build(begin, mid);
        merged.extend(&build(mid, end)).unwrap();
        let direct = build(begin, end);
        assert_eq!(merged, direct, "{ctx}");

        let rebuilt =
            CompactRange::from_parts(direct.begin(), direct.end(), direct.hashes().to_vec())
                .unwrap();
        assert_eq!(rebuilt, direct, "{ctx}");
        let mut extra = direct.hashes().to_vec();
        extra.push(rng.gen());
        assert!(
            matches!(
                CompactRange::from_parts(direct.begin(), direct.end(), extra),
                Err(CompactRangeError::WrongHashCount { .. })
            ),
            "{ctx}"
        );
        if !direct.hashes().is_empty() {
            let fewer = direct.hashes()[1..].to_vec();
            assert!(
                CompactRange::from_parts(direct.begin(), direct.end(), fewer).is_err(),
                "{ctx}"
            );
        }

        let mut from_zero = build(0, begin);
        from_zero.extend(&direct).unwrap();
        assert_eq!(
            from_zero.root().unwrap(),
            reference_root(&leaves[..end]),
            "{ctx}"
        );
        if begin > 0 {
            assert_eq!(
                direct.root(),
                Err(CompactRangeError::NotFromZero {
                    begin: begin as u64
                }),
                "{ctx}"
            );
        }
    }
}

#[test]
fn compact_ranges_near_the_top_of_the_index_space() {
    let (mut rng, seed) = rng(8);
    let leaves = random_leaves(&mut rng, 700);
    for _ in 0..iterations(60) {
        let begin = u64::MAX - 700 + rng.gen_range(0..=700u64);
        let count = (u64::MAX - begin) as usize;
        let split = rng.gen_range(0..=count);
        let build = |from: u64, hashes: &[Hash]| {
            let mut range = CompactRange::new(from);
            for leaf in hashes {
                range.append(*leaf).unwrap();
            }
            range
        };
        let direct = build(begin, &leaves[..count]);
        assert_eq!(direct.end(), u64::MAX, "seed {seed}");
        let mut merged = build(begin, &leaves[..split]);
        merged
            .extend(&build(begin + split as u64, &leaves[split..count]))
            .unwrap();
        assert_eq!(merged, direct, "seed {seed}, begin {begin}, split {split}");
        let mut full = direct.clone();
        assert_eq!(full.append(rng.gen()), Err(CompactRangeError::Full));
        assert_eq!(full, direct, "a failed append changes nothing");
    }
    // The full tree of 2^64 - 1 leaves holds one hash per level.
    let mut full = CompactRange::from_parts(0, u64::MAX, vec![[0; 32]; 64]).unwrap();
    assert_eq!(full.append([1; 32]), Err(CompactRangeError::Full));
}

#[test]
fn compact_range_errors() {
    let mut range = CompactRange::new(0);
    assert_eq!(
        range.extend(&CompactRange::new(1)),
        Err(CompactRangeError::NotAdjacent {
            end: 0,
            other_begin: 1
        })
    );
    assert_eq!(
        CompactRange::from_parts(5, 4, Vec::new()),
        Err(CompactRangeError::InvalidRange { begin: 5, end: 4 })
    );
    assert!(range.is_empty());
    range.append([3; 32]).unwrap();
    assert_eq!((range.len(), range.is_empty()), (1, false));
}

#[test]
fn compact_range_visits_every_complete_subtree_once() {
    let (mut rng, seed) = rng(9);
    let n = 777usize;
    let leaves = random_leaves(&mut rng, n);
    let mut visited: HashMap<NodeId, Hash> = HashMap::new();
    let mut range = CompactRange::new(0);
    for leaf in &leaves {
        range
            .append_with(*leaf, |id, hash| {
                assert!(
                    visited.insert(id, *hash).is_none(),
                    "seed {seed}: {id:?} visited twice"
                );
            })
            .unwrap();
    }
    let mut expected_count = 0;
    for level in 0..u64::BITS {
        expected_count += ((n as u64) >> level) as usize;
    }
    assert_eq!(visited.len(), expected_count);
    for (id, hash) in &visited {
        let begin = (id.index as usize) << id.level;
        let end = (id.index as usize + 1) << id.level;
        assert!(end <= n, "{id:?} reaches past the tree");
        assert_eq!(*hash, reference_root(&leaves[begin..end]), "{id:?}");
    }
}
