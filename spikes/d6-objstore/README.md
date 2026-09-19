# D6 object-store spike

Standalone harness comparing embedded-KV candidates for CipherVault's
future `ObjectStore` trait. Deliberately NOT a workspace member (it has
its own `[workspace]`), so the main gates never build its deps. Full
results and the recommendation live in
[`docs/D6_OBJECT_STORE_SPIKE.md`](../../docs/D6_OBJECT_STORE_SPIKE.md).

## Backends

- `file` — faithful model of today's store: one file per object at
  `objects/<64-hex>`, tmp-file + write + fsync + atomic rename (mirrors
  `OperatorState::persist_atomic`; digest validation and metrics omitted
  as engine-orthogonal).
- `redb` (feature `redb`, default) — redb 4.3.0, one table, commit every
  `--batch` puts. Commits are fsync-durable by default.
- `rocksdb` (feature `rocksdb`) — rust-rocksdb 0.25.0 over bundled
  RocksDB 11.8.1, `WriteBatch` per `--batch` puts, WAL fsync iff `--sync`.
  Needs a C++ toolchain + libclang; unbuildable on hosts without one.

## Commands

```sh
# Throughput at N objects (prints one greppable RESULT line):
cargo run --release --locked -- \
  run --backend redb --dir /tmp/d6/redb --n 1000000 --value-bytes 1024 --batch 1000

# Split phases (puts and reads measured separately; --gets M reads a
# M-get sample, --skip-puts reads an existing store):
cargo run --release --locked -- \
  run --backend file --dir /tmp/d6/file --n 1000000 --value-bytes 1024 --gets 0
cargo run --release --locked -- \
  run --backend file --dir /tmp/d6/file --n 1000000 --value-bytes 1024 \
  --skip-puts --gets 50000

# Kill-restart crash probe (POSIX sh; see below for PowerShell):
cargo build --release --locked
BIN=./target/release/d6-objstore  # or the configured target-dir
rm -rf /tmp/d6/crash && $BIN crash-child --backend redb --dir /tmp/d6/crash --value-bytes 1024 &
CHILD=$!; sleep 6; kill -9 $CHILD; wait
$BIN crash-check --backend redb --dir /tmp/d6/crash --value-bytes 1024

# Restart (open) time on an existing store:
cargo run --release --locked -- probe-open --backend redb --dir /tmp/d6/crash
```

PowerShell crash probe:

```powershell
$b = '<target-dir>\release\d6-objstore.exe'
Remove-Item -Recurse -Force /tmp/d6/crash -ErrorAction SilentlyContinue
$c = Start-Process $b -ArgumentList 'crash-child --backend redb --dir /tmp/d6/crash --value-bytes 1024' -PassThru -NoNewWindow
Start-Sleep 6; Stop-Process -Id $c.Id -Force; Start-Sleep 1
& $b crash-check --backend redb --dir /tmp/d6/crash --value-bytes 1024
```

RocksDB column (Linux/macOS host with gcc/clang + libclang):

```sh
cargo run --release --locked --features rocksdb -- \
  run --backend rocksdb --dir /tmp/d6/rocks --n 1000000 --value-bytes 1024 --batch 1000 --sync
```

## Workload semantics

Keys are 32 bytes (8-byte big-endian index + deterministic filler);
values are deterministic bytes of the index, so every read is verifiable
without storing expectations. The read phase is N random point gets with
replacement (splitmix64 stream) with 1/1024 sampled verification.
`--batch K` groups K puts per durable commit (file backend ignores it:
every put is durable). `--sync` enables WAL fsync on RocksDB writes.
