# D7 Erasure-Coding Spike Report (2026-09-18)

**Verdict: DECLINE for the 3-operator fleet. Keep 3x full replication.**
The codec is fast and clean, but no Reed-Solomon parameters beat 3x
replication on durability-per-byte at equal durability on 3 placement
homes, and EC substantially complicates repair — failing D7's explicit
gate ("without complicating repair").

## 1. What was measured

Standalone harness `spikes/d7-erasure/` (own workspace; main gates
untouched) driving `reed-solomon-simd` 3.1.0 (MIT AND BSD-3-Clause,
pure-Rust deps: fixedbitset + once_cell; builds on Windows with no C
toolchain). Release mode, this box. Encode is end-to-end incl. allocation;
recovery drops the first D shards (data-first, adversarial) and asserts
byte-identity.

### Encode throughput (MB/s) and wire overhead

| (k, m) | 4 KiB | 64 KiB | 1 MiB | overhead |
|---|---|---|---|---|
| (2, 1) | 9811 | 2436 | 3365 | 1.500x |
| (3, 1) | 8428 | 2809 | 3565 | 1.333x |
| (4, 2) | 6220 | 2961 | 2817 | 1.500x |
| (8, 4) | 4216 | 3006 | 2526 | 1.500x |
| (10, 4) | 3720 | 4311 | 2801 | 1.400x |

### Reconstruction (64 KiB, worst-case drops, all byte-identical)

| (k, m) | dropped | decode | repair read | amplification |
|---|---|---|---|---|
| (2, 1) | 1 | 0.5 ms | 64 KiB (k shards) | 2.00x |
| (4, 2) | 2 | 0.2 ms | 64 KiB (k shards) | 4.00x |
| (10, 4) | 4 | 0.2 ms | 64 KiB (k shards) | 10.00x |

Codec speed is a non-issue (GB/s). The decision turns on placement math
and repair cost, not codec throughput.

## 2. Why EC loses on 3 homes (placement counting)

Baseline 3x replication tolerates **any 2 node failures** (1 survivor
suffices). For EC(k, m) to match that, any single surviving node must hold
>= k fragments (any 2 of 3 nodes may die). So each node holds >= k
fragments, total >= 3k fragments, wire overhead >= 3k/k = **3x** — equal
bytes to replication, strictly more machinery. There is no (k, m) with
sub-3x overhead at equal durability on 3 homes. QED.

The sub-3x options are all durability downgrades: (2,1)/(3,1) tolerate 1
failure, not 2. Trading durability for bytes is the wrong direction for a
backup product.

## 3. Why EC complicates repair (measured)

Rebuilding one lost fragment reads k fragments (measured amplification =
k: 2x/4x/10x above); replication repairs with a 1x copy from one
survivor. Adopting EC would require fragment placement tracking,
stripe-aware partial repair, and small-object padding/CID fan-out (a 4 KiB
blob at k=10 becomes 410 B shards x 14 fragments = 14 CIDs per blob) —
against a repair lane (Phase 4 slice 2) that today pushes whole objects
with one plan, one pusher, one budget. Fails the D7 gate.

## 4. Revisit conditions (all required)

1. >= 5 placement homes (5+ nodes or multi-disk operators), where (k, m)
   with m >= 2 can survive 2 failures below 3x overhead.
2. A large-blob tier (>= 1 MiB objects) where padding and per-fragment
   metadata amortize; keep small FastCDC chunks replicated.
3. Placement-aware repair (fragment tracking + partial-stripe rebuild).

Candidate stays `reed-solomon-simd` (measured here, licensed, portable).
Shamir sharing in `crates/crypto` (recovery kits, tiny payloads) is a
separate purpose and unaffected by this verdict.
