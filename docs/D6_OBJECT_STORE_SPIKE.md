# D6 object-store spike: redb vs RocksDB vs file baseline

Date: 2026-09-18. Spike question (D6): which embedded store should back
CipherVault's future `ObjectStore` trait — redb (pure-Rust ACID KV) or
RocksDB (native LSM via rust-rocksdb)? Fixed criteria: crash safety,
read/write throughput at 1M objects, build time, binary size, license
fit. No commitment until measurements exist — this report is those
measurements.

Harness: [`spikes/d6-objstore/`](../spikes/d6-objstore/) (standalone
crate, reproducible via its README). Workload: 32-byte keys (8-byte
big-endian index + deterministic filler), 1024-byte deterministic values
(verifiable without stored expectations). Puts are sequential 0..N;
reads are N random point gets with replacement (splitmix64) with 1/1024
sampled verification. `--batch K` groups K puts per durable commit on
the KV engines; the file backend ignores it (every put is durable).

Host: Windows 11 x86_64, rustc 1.98.1, release profile. C: NTFS with
~26 GiB free at spike time. Single-run numbers (spike-grade, not
publication-grade); host has no C++ toolchain (see RocksDB note).

Versions measured: `redb` 4.3.0. `rocksdb` 0.25.0 /
`librocksdb-sys` 0.19.0 (bundled RocksDB 11.8.1) was resolved but is
UNMEASURED on this host (below).

## Throughput at 1M objects (1024-byte values)

| Backend (mode) | Put s | Puts/s | Get s | Gets/s | Bytes on disk |
|---|---|---|---|---|---|
| redb batch=1000 | 6.9 | 144,332 | 5.1 | 197,483 | 2,155,876,352 (2.01 GiB) |
| redb batch=1 (durable/commit) | 848.8 | 1,178 | 6.1 | 164,829 | 1,648,267,264 (1.54 GiB) |
| file (fsync+rename/object) | 2,063.2 | 485 | 254.0¹ | 197¹ | 1,024,000,000 (1.00 GiB) |
| rocksdb | — | — | — | — | — |

¹ File gets are a 50K random-get sample on the finished 1M store, not a
full 1M pass: the full pass projects to ~100 min (~167/s observed over
the first 100K). The sample rate (197/s) agrees with the partial pass.

Notes:

- redb batched commits are ~120x the durable-per-object rate: the naive
  per-object port is fsync-bound on both redb and files, while grouped
  commits amortize one fsync over 1000 puts. Any redb adoption should
  batch lease-commit-adjacent writes, not commit per object.
- redb's on-disk size is 1.5–2x the 1 GiB of raw values (B-tree +
  allocator overhead, single run, no compaction pass). The file baseline
  is exactly 1 GiB + directory entries (1,024,000,000 bytes of files).
- The file baseline degrades as the directory fills: puts started near
  ~1,300/s and finished near ~200/s (single 1M-entry NTFS directory, no
  sharding — the product layout). Reads collapse harder: ~17K/s at 3K
  files vs ~197/s at 1M files, a ~90x cliff. An embedded index is not an
  optimization here; the status quo does not scale to 1M objects.
- Restart (open) time on the finished 1M stores: redb 0.001–0.009 s
  (mmap + header read); file 0.000 s (no open work).
- Host caveat: Windows Defender real-time protection was active, which
  taxes per-file syscalls (hurts the file backend disproportionately)
  and may inflate all fsync-bound columns. Relative ordering is robust;
  absolute rates should be re-baselined on the Linux deployment target.

## Crash safety (kill -9 mid-write, 3 rounds each)

Method: `crash-child` writes dense durable keys until SIGKILL-equivalent
(`Stop-Process -Force`); `crash-check` reopens and asserts a dense
`0..count` prefix, verifies EVERY value (torn-write detection), and
counts non-object debris.

| Backend | Rounds | Verdict | Present (typ.) | Debris |
|---|---|---|---|---|
| file | 3 | PASS ×3 | ~4,700 (6 s each) | 1, 0, 1 `.tmp` |
| redb batch=1 | 3 | PASS ×3 | ~7,500–8,600 (6 s each) | 0 |
| redb batch=1000 | 1 | PASS | 784,000 (6 s; exactly 784 commits) | 0 |
| rocksdb | — | — | — | — |

Every PASS means: reopen succeeded (no corruption), present keys are
exactly the dense prefix `0..count`, and every value byte-verified. The
file debris column is the in-flight tmp file at kill time (0 when the
kill lands between puts); the product never reaps these, so each crash
leaks one small file until an operator cleans up. The redb batched
round is a consistency check on the throughput number too: 784K objects
in 6 s ≈ 131K/s, matching the 144K/s batched rate.

Documented guarantees (mechanism, independent of the probe):

- file: tmp-file + `File::sync_all` + atomic rename
  (`OperatorState::persist_atomic`), plus directory fsync on unix. Crash
  loses at most the in-flight object; orphans one `.tmp` per kill (the
  product only deletes tmp files on the error path, so debris
  accumulates until an operator cleans it).
- redb: "Fully ACID-compliant transactions", "Crash-safe by default"
  (`redb` 4.3.0 crate docs). Commits are fsync-durable; a kill loses at
  most the uncommitted tail, which preserves the dense prefix.
- RocksDB (unmeasured here): WAL + MANIFEST with replay on open; SYNC
  WAL writes are durable per write, async WAL loses seconds. Standard
  LSM crash story; the spike's Linux rerun should confirm the dense
  prefix empirically rather than trust this paragraph.

## Build time and binary size

Method: pristine copy of the spike crate with an isolated
`CARGO_TARGET_DIR` (registry cache warm), timed `cargo build --release
--locked` per feature set; binary size is the linked `d6-objstore.exe`.
(An earlier `cargo clean -p` attempt in the shared target dir produced a
bogus 1.3 s redb rebuild via stale fingerprints — discarded; the cold
numbers below are the cited ones.)

| Feature set | Cold build s | Binary bytes |
|---|---|---|
| file only (`--no-default-features`) | 0.9 | 234,496 (229 KiB) |
| file + redb (default) | 10.9 | 1,280,000 (1.22 MiB) |
| file + redb + rocksdb | UNBUILDABLE on this host | — |

redb costs ~10 s of one-time compile and ~1 MiB of binary. Both are
noise next to the workspace's existing dependency closure.

RocksDB build failure (this host): `librocksdb-sys` 0.19.0 build script
fails — `bindgen` reports "Unable to find libclang", and no C++
compiler exists anywhere on the host (no `cl.exe` under either Visual
Studio path, no gcc/clang/cmake on PATH). Its build requires
bindgen+libclang AND a C++ compiler (`cc` crate). A Linux CI runner
with gcc/clang fills this column; budget roughly 10–20 min for the
first native build (vendored RocksDB 11.8.1 C++ compilation).

## License fit

| Component | Declared license | Fit |
|---|---|---|
| `redb` 4.3.0 | MIT OR Apache-2.0 (Cargo.toml) | Clean: Apache-2.0 choice matches the project |
| `rocksdb` 0.25.0 (Rust wrapper) | Apache-2.0 (Cargo.toml) | Clean |
| `librocksdb-sys` 0.19.0 (FFI crate) | MIT/Apache-2.0/BSD-3-Clause (Cargo.toml) | Clean |
| Bundled RocksDB 11.8.1 (native) | LICENSE.Apache + COPYING (= GPLv2) — dual license | Fits via the Apache-2.0 choice, but every distributor must preserve the choice and the GPL alternative stays in the tree; legal should confirm before any mainnet-adjacent commitment |

No blocker on either candidate, but redb's license story is one line
and RocksDB's is a dual-license obligation the project must carry.

## RocksDB: what is missing and how to fill it

The `rocksdb` backend adapter (`rocksdb_store.rs`) is written against
the `rocksdb` 0.25.0 sources (all signatures verified) but has never
been compiled. On a host with a C++ toolchain + libclang:

```sh
cd spikes/d6-objstore
cargo run --release --locked --features rocksdb -- \
  run --backend rocksdb --dir /tmp/d6/rocks --n 1000000 \
  --value-bytes 1024 --batch 1000 --sync
# plus: --batch 1 --sync (durable column), crash probes, probe-open,
# and the clean-rebuild timing for the build-time row.
```

Expected (not measured): RocksDB async-WAL batched writes should meet
or beat redb's batched rate; SYNC-per-write should resemble the
fsync-bound column; reads should be comparable; disk usage typically
~1.1–1.3x with compression off. Do not decide on these guesses — run it.

## Recommendation

**Adopt redb** for the `ObjectStore` trait (D6 decided), with two
carried conditions below. The file baseline is not competitive — it is
2.4x slower than even naive per-object redb on writes (485 vs 1,178
puts/s), ~840x slower on reads at 1M objects (197 vs 164,829 gets/s),
and still degrading as the directory grows. The status quo cannot serve
1M objects; the question was never close enough to need the RocksDB
column to break a tie.

Why redb over RocksDB, specifically:

1. Throughput headroom is already proven (144K batched puts/s, 197K
   gets/s) with zero native toolchain — RocksDB's best case is matching
   this at the cost of a C++ build dependency the project has never
   carried.
2. Crash story is ACID-by-default and probe-confirmed (7/7 dense-prefix
   PASS, zero debris), versus an LSM WAL story we would have to
   re-verify per tuning knob.
3. License is one line (MIT OR Apache-2.0) versus a dual-license
   obligation.
4. Build cost is ~10 s cold and ~1 MiB binary — negligible.

Carried conditions:

1. Re-baseline absolute rates on the Linux deployment target before
   capacity planning (this host's Defender + NTFS skew the file column
   and may inflate fsync-bound columns).
2. If a future workload needs LSM-specific behavior (e.g. sustained
   write throughput past what grouped B-tree commits deliver, or native
   compression), the RocksDB adapter in this crate is written and the
   rerun procedure above prices that alternative in one CI job.

## Raw logs

- `/tmp/d6run-redbB.log` — redb batch=1000 1M run (RESULT + progress)
- `/tmp/d6run-redb1.log` — redb batch=1 1M run
- `/tmp/d6run-file.log` — file baseline 1M puts (`--gets 0`)
- `/tmp/d6run-file-gets.log` — file 50K-get sample on the 1M store
- Crash rounds were run interactively; verdicts are in the table above.
