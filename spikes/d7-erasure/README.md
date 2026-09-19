# D7 erasure-coding spike

Standalone harness measuring Reed-Solomon (`reed-solomon-simd` 3.1.0) for
CipherVault's large-blob durability question. Deliberately NOT a workspace
member (it has its own `[workspace]`), so the main gates never build its
deps. Full results and the recommendation live in
[`docs/D7_ERASURE_SPIKE.md`](../../docs/D7_ERASURE_SPIKE.md).

## Commands

```sh
# Throughput + overhead at one (k, m, blob) point (greppable RESULT line):
cargo run --release --manifest-path spikes/d7-erasure/Cargo.toml -- \
  encode --data 4 --parity 2 --blob-bytes 65536 --iters 200

# Reconstruction correctness (drops the first D shards, data-first):
cargo run --release --manifest-path spikes/d7-erasure/Cargo.toml -- \
  recover --data 4 --parity 2 --blob-bytes 65536 --drop 2

# Full sweep: (2,1) (3,1) (4,2) (8,4) (10,4) x 4KiB/64KiB/1MiB + recovers:
cargo run --release --manifest-path spikes/d7-erasure/Cargo.toml -- sweep
```

## Workload semantics

Blobs are deterministic splitmix64 bytes, sharded into `k` equal
last-padded shards. `encode` times end-to-end parity generation including
allocation. `recover` drops the first `D` shards (adversarial: data shards
first), reconstructs, and asserts byte-identity with the original; it also
reports single-fragment repair cost (`k` shard reads).
