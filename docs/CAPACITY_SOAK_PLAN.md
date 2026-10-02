# Production-equivalent capacity and soak qualification plan

## Why the CI results are not qualification

The isolated capacity workflow passed 7/7 gates, but it cannot qualify
production: 240-request closed-loop phases lasting seconds, fixed small audit
history, no disk pressure, no multi-hour behavior. Worse, its 4-vCPU/15.6 GiB
runner is far larger than production: `cv-web-ui` is an `e2-micro`. CI
over-provisions the exact resource under test.

The known bottleneck is structural: `AccountState` holds one global
`Arc<Mutex<Connection>>` (`services/account/src/state.rs`) and every request
holds the mutex across its whole transaction. Mixed-workload p99 already
degrades with concurrency (CI: 5.69 ms at c1 to 275.73 ms at c64; longer local
runs reached 1,137 ms). Keep SQLite `FULL` durability throughout.

## Step 0: instrument lock wait (done)

`AccountState::connection()` now records every mutex acquisition:
`db_lock_wait_stats()` returns (acquisitions, total wait micros, max wait
micros), waits at or above 10 ms also log one stderr line each, and the
secret-routes load test prints per-run lock deltas next to
`sqlite_busy_retries`. Re-run the CI harness once to confirm the new metric
moves with concurrency. Do not redesign the database yet.

## Canary setup (isolated, production-shaped)

- One `e2-micro` canary in a non-production project, release binaries, no
  production data or credentials. Same container images as the release.
- Seed: account/secret counts at least 10x current production, audit history
  pre-grown to a realistic size, then left growing for the whole run.
- Resource capture every 10 s: CPU steal, memory, disk used/free, WAL and
  `-shm` sizes, checkpoint counts, lock-wait histogram, per-route latency.

## Load profile (open-loop arrival rate, not closed-loop)

Drive Poisson arrivals at fixed rates (e.g., 50/150/400 rps) across a
production-plausible mix: value reads, five-value materialization, rotations,
audit-chain exports, and overlapping consistent backups. Hold each rate for at
least 30 minutes; then run the selected rate for a 4-hour soak. Separately:

- Disk pressure: fill the data disk to 85% and 95%, verify behavior and
  recovery (no unbounded queue growth; operator keeps rejecting excess work).
- Backup overlap: run scheduled backup + MFA step-up traffic concurrently and
  confirm p99 stays in budget.
- Required-MFA accounts included in the mix at the production ratio.

## Pass criteria (set before running; suggested)

- p99 per route within the agreed SLO at the declared rate (start from the
  CI 2 s budget only if the product accepts it; otherwise set a real SLO).
- Zero unexpected failures; rejections only with capacity responses.
- Lock-wait p99 bounded and flat across the soak (no growth with history size).
- WAL size bounded; checkpoints keep up; SQLite `integrity_check` ok after.
- Disk-pressure phases recover without manual repair.

## Decisions the soak unblocks

- If lock wait grows with history or rate: profile first, then choose between
  bounded database worker(s), read/write splitting, or a different storage
  architecture. The soak numbers size that choice.
- If the canary holds: declare the qualified ceiling (rate, mix, history
  size) in the deployment report and alert on approach in production.

Do not describe any release as capacity-qualified until this plan, or a
reviewed equivalent, has passing evidence.
