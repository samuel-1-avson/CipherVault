# Load + Soak Validation (Track 3)

How replication load and soak are validated, what passed locally, and how
to run the approval-gated live soak. Live fleet runs need explicit
approval: soak iterations write real objects to real operators.

## Harness

`apps/cli/tests/push_bench.rs` (ignored by default): sequential vs
concurrent quorum replication plus sustained soak iterations against 3
in-process loopback operators, with readback verification every batch.

```powershell
# Timings are meaningful in release; soak correctness also runs in debug.
cargo test -p ciphervault-cli --release --test push_bench -- --ignored --nocapture
```

Knobs: `CIPHERVAULT_BENCH_OBJECTS` (48), `CIPHERVAULT_BENCH_OBJECT_KB`
(16), `CIPHERVAULT_BENCH_SOAK_ITERS` (2), `CIPHERVAULT_BENCH_ASSERT=1`
(fail unless concurrent speedup >= 2.0x).

Harness fixes (2026-09-26):

- Soak seeds stride by object count. `bench_objects` mixes `seed +
  index`, so the old stride-1 seeds re-pushed the same CIDs every
  iteration, violating the bench's own fresh-CID contract.
- Soak operators run with `CIPHERVAULT_HTTP_RATE_LIMIT_PER_MIN=120000`.
  One loopback client fires ~150 requests per batch per operator; the
  default 600/min limiter tripped mid-soak and readback challenges fail
  closed on 429, which surfaced as quorum deficits. The limiter and the
  fail-closed readback behaved correctly; the harness was at fault.

## Local evidence (2026-09-26, debug build)

- 6 soak iters x 48 x 16 KiB: pass, quorum 3/3, `sqlite_busy_retries: 0`.
- 12 soak iters x 48 x 16 KiB: pass, quorum 3/3, `sqlite_busy_retries:
  0`, 29.4 s. Debug speedup 1.08x is not meaningful; release timings
  come from CI (`cargo test --locked -p ciphervault-cli --release
  --test push_bench -- --ignored`).

## Live evidence (2026-09-26, approved run)

- 10 rounds x (push 4 KiB fresh snapshot + pull-overwrite + pull-restore
  with SHA-256 byte comparison) against op1/op2/op3: 10/10 pass, ~9 s
  per round, no failures, no slowdown trend, no 429s at paced load.
- Local temp vault and recovery kit removed after the run; soak objects
  persist on the fleet under their lease terms (accepted residue).

## Live soak procedure (approval-gated)

1. Get explicit approval for live writes and a target window.
2. Point a canary client at the fleet; keep the fleet's 600/min limiter
   untouched so the soak validates production posture.
3. Size the load under the limiter: small object counts, paced batches.
   Sustained 429s during soak are a harness-sizing failure, not a
   product failure — readback fails closed by design.
4. Pass criteria: every batch reaches quorum, zero readback failures
   outside rate-limit windows, no operator restart, no SQLite busy
   errors in operator logs.
5. Residue: soak objects persist under their lease terms (bench uses
   90-day leases). Prefer a canary operator, or accept the residue.

## Related suites

CHAOS_LOG.md fallback flow (Docker engine unavailable on the
workstation), `chaos_federation_drill`, `swarm_dos`, operator chaos
gates in CI.

## Account-service load gate (T-903)

`secret_routes::tests::scoped_load_gate` (ignored by default): seeds
N secrets, then hammers value reads with C concurrent workers over
the in-process router and asserts zero failures, p99 under budget,
and zero `sqlite_busy_retries` (durability stays FULL).

```powershell
cargo test -p ciphervault-account --release --lib -- --ignored --nocapture scoped_load_gate
```

Knobs: `CIPHERVAULT_LOAD_SECRETS` (50), `CIPHERVAULT_LOAD_READS`
(200), `CIPHERVAULT_LOAD_CONCURRENCY` (8),
`CIPHERVAULT_LOAD_P99_MS` (250). Knobs must respect quotas
(read-value 300/60s, api 1000/60s): a 429 fails the gate by design —
harness-sizing failure, not product failure.

Local evidence (2026-09-27, workstation):

- Debug: 200 reads / 50 secrets / 8 workers in 509ms (393 reads/s);
  p50=19ms p99=36ms, failures=0, `sqlite_busy_retries: 0`.
- Release: 200 reads / 50 secrets / 8 workers in 348ms (574
  reads/s); p50=11ms p99=36ms, failures=0, `sqlite_busy_retries: 0`.

The p99 floor is the per-read audit append (fsync at FULL sync) plus
quota writes under one global mutex — the intended durability
posture at SQLite scale (see runbook §20 scale ceiling).
