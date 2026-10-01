# Capacity validation

The bounded TCP harness in [scripts/capacity-validation.cjs](../scripts/capacity-validation.cjs) starts its own account and operator services against new synthetic data. It measures latency distributions, successful throughput, explicit rejection rates, unexpected errors, memory and disk growth, with account rotation, materialization, audit exports and online backups running under contention. It never accepts a remote service URL. Current measured results and qualifications are in [the October 1 report](../report/CAPACITY_VALIDATION_2026-10-01.md).

## Repeatable local run

Use Node 24 or later, which supplies the SQLite fixture client. No npm package or private service configuration is required. Build fresh binaries so the evidence describes the source being reviewed:

```powershell
cargo build --locked -p ciphervault-account -p ciphervault-operator
node --test tests/capacity_harness.cjs
node scripts/capacity-validation.cjs `
  --account-bin C:/Users/samue/.cargo-targets/ciphervault/debug/ciphervault-account.exe `
  --operator-bin C:/Users/samue/.cargo-targets/ciphervault/debug/ciphervault-operator.exe `
  --output report/capacity-local-new-run.json
```

Those binary paths match the current workstation's ignored Cargo configuration. On another host use its actual build directory, normally `target/debug/` (add `.exe` on Windows). For performance estimates build with `--release` and use `target/release/` or the configured target directory. The JSON records the actual binary SHA-256, version, profile hint, OS, CPU count, memory and Node version. The version number alone does not establish which source changes were measured.

The output must be a new filename; previous evidence is never overwritten. Runtime data resides in a newly created OS temporary directory outside the project. Exact executable bytes are copied into that directory before launch, preventing a concurrent build from changing the measured program or holding the original Windows build output open. Keys and credentials are generated for the invocation, omitted from results, and destroyed with that directory after the services stop. The cleanup checks the exact temporary parent and generated directory name. If cleanup fails, results disclose the retained path. Review and remove that exact synthetic directory manually after its processes exit. Inherited CipherVault settings and the Google credentials-file environment variable are removed from the service environment.

The current operator accepts `--bind-address 127.0.0.1`. For comparisons with older binaries, the harness detects the absent flag and records that their HTTP listener binds `0.0.0.0`; traffic remains loopback with strict enrollment and random credentials. New assurance runs should use the current binary with explicit loopback binding.

## Workload and gates

Default phases are 240 requests each at concurrency 1, 8, 32 and 64. Each worker issues its next request only after its previous response is consumed. This is a closed-loop burst test, not a constant-arrival-rate model; queue collapse and coordinated omission remain possible at production arrival rates.

The account fixture contains one tenant, one project, a tier-2 environment, 16 accounts and 50 secrets initially containing 1 KiB synthetic values. Account creation and Ed25519 challenge login use the real HTTP ceremony. Direct SQLite inserts only provision the fixture's project hierarchy and memberships; measured operations use the actual authenticated HTTP routes. The mixed phases retain optional MFA policy for comparison with the earlier binaries.

With an MFA-capable binary, a separate phase exercises account-signed device enrollment, device-key login, offline recovery-code generation, real authenticator enrollment/confirmation, the next current time-step's TOTP code, session-bound second-factor verification and explicit required-policy enablement. It then measures 120 value reads at concurrency 8 through that verified session and proves a real new device-key login without the second factor cannot read a value. No MFA policy or proof rows are inserted by the harness. The secret seed, codes, private keys and credentials stay in the synthetic invocation's memory and are omitted from evidence. Waiting for the next code can take up to 30 seconds and is recorded separately from request latency. `--require-enforced-mfa` makes a missing MFA capability fail the run; it is enabled in the manual CI workflow. This small phase validates active MFA authorization under load, not passkey throughput or large-scale enrollment.

The account request mix is:

- 40% individually audited plaintext reads;
- 25% atomic five-value materialization (each value consumes its normal quota);
- 20% manual secret rotations with unique idempotency keys;
- 10% metadata lists with revision verification;
- 5% tenant-wide audit exports with a distinct authorized secondary scope-token principal.

Each account phase starts a separate process running the supported SQLite online-backup CLI after a measured prefix has completed. The backup verifies database integrity and the audit chain. Results record backup duration, row counts and the number of requests completed when it finished, so actual overlap can be assessed. The original service uses one SQLite connection under a global mutex. WAL and SQLite's default `FULL` synchronous durability remain intact; the harness never sets `NORMAL` or disables fsync. The observer's reported `PRAGMA synchronous` value belongs to its own connection. Service-connection durability is established from source configuration, not claimed as direct live telemetry.

Operator phases mix one-third new 64 KiB immutable object writes with two-thirds byte-verified reads of seeded objects. A separate overload phase submits 128 unique 1 MiB objects simultaneously. All object files are checked against their SHA-256 CIDs after the writes complete. Strict operator sessions and enrollment remain enabled. The capacity process has an explicit 100,000/minute HTTP limiter setting to keep the cumulative probe below that limiter; this is a test setting only. A fresh operator process then runs with the normal 600/minute limit and a 640-request metadata burst must receive HTTP 429 without unexpected failures.

Successful HTTP admission and correctness are separate measurements. A documented capacity-exhausted HTTP 503 or rate-limit HTTP 429 is reported as a rejection. Transport errors, wrong bytes, invalid response contracts and other non-success statuses are failures. Account phases reject any quota failure; user counts and the default request mix keep the normal quotas active. The default p99 budget is 2,000 ms, a bounded regression budget rather than a promised product SLO. It includes rejected and failed requests; operation-specific distributions and success/rejection counts are retained so fast rejections cannot hide the workload's outcome.

Exit status is nonzero if unexpected failures, account rejections, integrity failures, backup chain-check failure or the configured p99 budget occurs. `--require-overload-rejection` additionally requires a rejection during the overload phase. Disk speed and scheduling determine whether a burst saturates a particular host; the deterministic operator admission regression remains the proof that the seventeenth running operation cannot enter an unbounded wait queue.

Optional bounded knobs are `--requests`, `--secrets`, `--concurrency`, `--object-bytes`, `--p99-ms`, `--overload` and `--overload-bytes`. Larger values can intentionally hit intact account quotas or the five-minute primary-authentication freshness window. Do not interpret those rejections as database capacity or increase production quotas to hide them.

## CI and deeper qualification

[Isolated Capacity Validation](../.github/workflows/capacity-validation.yml) is manually dispatched. It builds Linux release binaries, uses no cloud secrets, grants only repository read permission, requires both real enforced-MFA validation and at least one overload rejection, and uploads the measured JSON even when a gate fails. A machine that drains the entire bounded burst without saturation can fail the rejection gate without a correctness fault; investigate its measured results alongside the deterministic admission test. Adding the workflow is not evidence that it has run. Dispatch it on the intended review commit before relying on Linux release timings.

Continue using the existing [load and soak procedures](LOAD_SOAK_VALIDATION.md), the ignored account `scoped_load_gate`, CLI `push_bench`, P2P saturation tests, and the ten-node chaos drill. Those suites exercise different failure models. This TCP harness does not replace recovery, quorum, failover or chaos verification.

Before setting production limits or widening deployment:

1. Run the Linux release workflow on an isolated canary with production-equivalent disk, CPU and memory limits; retain exact source and image identities.
2. Use an open-loop arrival-rate driver with a measured successful-operation SLO, retry budgets and arrival/queue telemetry. Keep credential and value quotas enabled.
3. Grow histories to at least the expected retention horizon, measure audit-chain scans/export latency and WAL/checkpoint behavior, and run several hours of sustained writes plus scheduled backup overlap.
4. Exercise independent writers, full disk/inode exhaustion, slow fsync, restart and loss of a node; prove acknowledged writes and authorized recovery remain correct.
5. Measure MFA-enforced accounts, dashboard/SSE traffic, KMS/provider latency once configured, P2P replication/repair and multi-region paths separately.

The current harness provides reproducible evidence and a regression surface. Its small workstation run cannot certify a production capacity ceiling.
