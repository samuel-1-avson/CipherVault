# CipherVault capacity validation — October 1, 2026

## Assessment

The project now has a repeatable isolated TCP capacity harness, documented gates and a manual Linux release CI workflow. The final rebuilt services passed every local gate. Their networked overload run demonstrated the new operator admission behavior: 102 of 128 simultaneous 1 MiB writes received the documented capacity HTTP 503, while 26 were accepted and persisted correctly. The earlier operator accepted all 128 requests through its waiting queue. This closes the specific unbounded operator I/O wait-queue finding; it does not establish a production throughput ceiling or bound every HTTP connection/body buffer.

Account capacity is still a measured limitation. In the final debug run, increasing mixed-workload concurrency from 8 to 64 reduced successful throughput from 165.72 to 119.57 requests/second while p99 latency increased from 110.05 to 1,137.56 ms. The workload included value reads, five-value materialization, rotations, audit-chain exports and concurrent consistent backups. The single account SQLite connection/global mutex remains a scaling bottleneck. Preserve `FULL` durability and validate larger production-equivalent workloads before replacing that architecture.

## Evidence and scope

- [Valid legacy baseline JSON](capacity-legacy-baseline-2026-10-01.json): October 1, 08:57–08:58 UTC; existing September 30 debug binaries.
- [New HTTP admission JSON](capacity-http-admission-2026-10-01.json): October 1, completed 09:05 UTC; freshly built operator with the new admission and loopback binding, existing account binary.
- [Fresh MFA account and operator JSON](capacity-fresh-mfa-2026-10-01.json): October 1, completed 09:40 UTC; actual device enrollment, TOTP second factor and policy ceremony followed by active-policy reads and a proofless-session denial.
- [Final rebuilt account and operator JSON](capacity-final-2026-10-01.json): October 1, 09:50–09:51 UTC; includes the final account mutation guard revalidation source and repeats the full real-MFA ceremony.
- [Repeatable procedure](../docs/CAPACITY_VALIDATION.md) and [harness](../scripts/capacity-validation.cjs).
- [Manual Linux release workflow](../.github/workflows/capacity-validation.yml): added, not dispatched as part of this local validation.

All four local runs used Windows_NT 10.0.26220, x64, 16 logical CPUs, approximately 15.23 GiB physical memory and Node 24.20.0. The temporary databases and object stores were outside the repository and were removed after the processes stopped. No production or cloud requests were sent. These are unoptimized workstation results; other development activity, OS caches and process sampling influence timings. Compare outcomes and broad contention trends; do not treat differences of a few milliseconds as a stable speedup.

Both binaries identify themselves as version 1.0.26; their actual byte identities distinguish the changes:

| Binary | SHA-256 | Qualification |
|---|---|---|
| Original account | `7fcc5b7fd48e727f783210096d0917dd242622630c0030ebf8a2ca5457e5f159` | September 30 debug binary; optional-MFA fixture |
| Original operator | `d545ade034b924645a1816a81033a6df5ba1844827bbebf1ef353240a09ea221` | September 30 debug binary; waiting I/O admission |
| New operator | `0f28d4773719a7c9787444914f20d74903c2c9410efb4c1f6ff68f6db0c697fd` | October 1 debug build; immediate admission and explicit loopback binding |
| New MFA account | `4d980006f41c86824e30c87e685b515a9b7d4373d6bc966266d68f06263c9c3f` | October 1 debug build; session-bound MFA policy and verification |
| Final account | `26c2f1371ef22ada389dde0bea0eeb47ca3f42b46e7a4c632d7a23889d48f02b` | October 1 debug build; final account mutation guard revalidation |

The final account binary supersedes the earlier MFA account for account-policy runtime validation. Each result remains tied to its recorded binary hash. Subsequent integrated testing added bounded HTTP 503 retries to the Rust client's immutable object PUT; the Node harness reports raw admission responses and does not exercise that client retry. Actual Rust TCP and concurrent-replication regressions validate that addition separately. The original mixed-workload numbers must not be presented as measurements of MFA-enforced accounts.

## Account mixed workload

Each row contains 240 requests, 50 initial secrets, 16 authenticated accounts and an online backup started during the measured requests. Request mix: 40% value reads, 25% five-value materialization, 20% manual rotation, 10% metadata lists and 5% dual-principal audit export. Production-tier fresh-key authorization and normal account quotas were retained.

| Concurrency | Legacy throughput (successful requests/s) | p50 ms | p95 ms | p99 ms | Unexpected failures |
|---:|---:|---:|---:|---:|---:|
| 1 | 65.38 | 15.41 | 26.21 | 42.66 | 0 |
| 8 | 120.08 | 55.37 | 126.94 | 142.17 | 0 |
| 32 | 104.12 | 266.75 | 505.72 | 595.75 | 0 |
| 64 | 79.83 | 726.65 | 1,249.74 | 1,461.45 | 0 |

The repeat with the updated operator also had zero account failures across 960 measured account requests, with account p99 at concurrency 1/8/32/64 of 56.51/187.68/612.33/1,229.28 ms. The account binary was unchanged. The repeat supports the contention trend; it is not a controlled account optimization comparison.

The new MFA account binary also passed all 960 comparable optional-policy mixed requests: concurrency 1/8/32/64 successful throughput was 72.64/163.71/137.97/118.47 requests/second, with p99 of 35.97/104.38/449.69/1,179.64 ms. Background activity and caches changed between runs, so these are repeat observations rather than an account optimization claim.

Its separate enforced-policy phase performed real account-signed device enrollment, device-key login, recovery-code generation, TOTP enrollment and confirmation, waited 22,346 ms for the next current code, verified the session's second factor and enabled required MFA through the API. All 120 value reads at concurrency 8 succeeded: p50 24.51 ms, p95 30.59 ms, p99 39.40 ms and 313.62 successful requests/second. A new real device-key login with no second-factor proof returned the uniform HTTP 404 and no plaintext value. This proves that the tested enforced account does not inherit another session's proof; it does not establish fleet-wide policy deployment or passkey/enrollment capacity.

The final rebuilt account repeated the entire ceremony and passed all 1,080 measured account requests, with zero failures or rejections:

| Final account phase | Requests | Successful requests/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| Mixed, concurrency 1 | 240 | 67.90 | 15.19 | 22.28 | 33.34 |
| Mixed, concurrency 8 | 240 | 165.72 | 39.86 | 86.29 | 110.05 |
| Mixed, concurrency 32 | 240 | 137.57 | 225.26 | 383.80 | 454.07 |
| Mixed, concurrency 64 | 240 | 119.57 | 472.81 | 882.49 | 1,137.56 |
| Required MFA reads, concurrency 8 | 120 | 325.54 | 23.59 | 32.39 | 39.38 |

It waited 19,107 ms for the next current TOTP code during fixture setup. A new primary-authenticated session without a second factor received HTTP 404 and no value. Four backups overlapped account requests, completed in 76.55/94.94/113.82/131.22 ms after 12/25/22/34 requests, and each verified one audit chain. Final integrity was `ok`, retaining 242 versions and 1,948 access events. The sampled account process peak was 37,289,984 bytes (35.56 MiB).

Four online backups in the updated-operator run completed in 98.76, 112.11, 120.87 and 137.14 ms. They finished after 14, 19, 16 and 30 of the respective 240 requests, confirming overlap. Each backup verified one tenant audit chain. Final account integrity check returned `ok`, with 242 retained secret versions and 1,828 access events. The service retained WAL and default SQLite `FULL` synchronous durability. The reported observer `PRAGMA synchronous=2` applies to the observer connection; source configuration supplies the service durability evidence.

This dataset remains small. Audit history and database size also grow across phases, so concurrency and history size are not isolated experimental variables. The fixture's maximum observed account peak working set in the new-operator run was 38,735,872 bytes (36.94 MiB); there is no several-hour memory-leak or checkpoint-soak conclusion.

## Operator network overload

| New operator phase | Requests | Successes | Capacity rejections | Failure count | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Mixed, concurrency 1 | 240 | 240 | 0 | 0 | 14.41 | 22.29 | 25.90 |
| Mixed, concurrency 8 | 240 | 240 | 0 | 0 | 5.45 | 12.92 | 15.00 |
| Mixed, concurrency 32 | 240 | 240 | 0 | 0 | 25.45 | 46.01 | 54.57 |
| Mixed, concurrency 64 | 240 | 227 | 13 (5.42%) | 0 | 41.24 | 67.28 | 70.96 |
| 128 simultaneous 1 MiB writes | 128 | 20 | 108 (84.38%) | 0 | 214.62 | 337.78 | 346.45 |

The mixed phases use one-third new 64 KiB writes and two-thirds byte-verified reads. The new operator had 349 stored objects at the end of the overload phase; every file's SHA-256 matched its CID. Operator storage was 42,534,537 bytes including control state. The post-overload process peak working set was 70,561,792 bytes (67.29 MiB). This captures body ingestion and local runtime overhead as well as the 16 admitted I/O operations.

The original operator accepted all 128 overload writes, storing approximately 156.24 MB of total test data after the full probe; its overload p99 was 553.01 ms. This result showed queue acceptance, not a failure. The new rejection outcome is intentional bounded admission, not an error-rate regression. Clients must handle capacity 503 with bounded retries/backoff. A p99 improvement that includes fast rejections is not proof of higher accepted-work throughput.

The fresh MFA-account repeat used the same new operator bytes and accepted 38 of 128 overload writes while rejecting 90 (70.31%) with capacity HTTP 503, with p99 345.21 ms and zero unexpected errors. Its 368 stored objects all matched their CIDs. Account integrity remained `ok`, with 242 secret versions and 1,948 access events. The four consistent backups overlapped requests and took 74.08/101.53/110.66/129.19 ms. Both overload repetitions demonstrate admission under saturation; exact rejection counts depend on scheduling and write completion speed.

The final operator run also had zero unexpected failures. At concurrency 32 and 64, 6 of 240 (2.50%) and 15 of 240 (6.25%) mixed requests received capacity HTTP 503, with p99 33.04 and 48.85 ms. The 128-write overload accepted 26 and rejected 102 (79.69%), with p50 190.31 ms, p95 280.71 ms and p99 287.94 ms. Every one of its 349 stored objects matched its CID. The post-overload operator peak working set was 65,343,488 bytes (62.32 MiB). These rejection rates describe this burst and are not promised steady-state operating limits.

Capacity phases used an explicit 100,000/minute test HTTP limiter so the cumulative synthetic workload did not conflate the request quota with I/O admission. A separate fresh process ran with the unmodified default 600/minute limiter: 599 of 640 metadata requests succeeded and 41 returned HTTP 429, with zero unexpected errors. The readiness request consumed the other allowed slot. Production limiter configuration was not changed.

## Completed verification

- `node --test tests/capacity_harness.cjs`: 3 tests passed; validates accounting of rejections versus semantic/transport failures, latency tails, workload bounds, rejected remote URLs, preservation of existing evidence and independent RFC6238 SHA1 fixture code vectors.
- `node --check scripts/capacity-validation.cjs`: passed.
- `cargo build --locked -p ciphervault-operator` with compact development/test debug settings: passed.
- Four complete networked local runs: legacy baseline passed its regression budget; new operator passed the explicit overload-rejection gate; both fresh MFA account builds passed the real second-factor/policy ceremony and concurrent authorized reads. Four backups and the unmodified default limiter gate passed in each valid run. The final runtime build passed all seven gates, with both MFA and overload rejection required.
- An initial harness diagnostic misread the metadata envelope as a bare array. Service responses were correct; the validator was corrected before the valid runs above. That diagnostic is excluded from project capacity evidence.

No current Linux release workflow execution, production-canary run, multi-region stress test or long-duration soak is claimed in this report.

## Remaining acceptance work

1. Expand the enforced-account test to policy refresh/revocation races, passkeys and sustained proof-refresh cycles; retain exact executable identities for each repeat.
2. Dispatch the manual Linux release workflow on the intended review commit and record runner/image limits. Repeat on an isolated production-equivalent canary disk, CPU and memory budget.
3. Define a successful-operation SLO and expected request mix, then drive open-loop arrival rates with queue and rejected-work telemetry. Current closed-loop bursts do not establish behavior at a sustained arrival rate.
4. Run several-hour rotation/materialization/backup overlap and expand audit histories to expected retention size. Measure WAL/checkpoints, p95/p99, fsync, disk and inode growth, and recovery after restart/full disk.
5. Measure account lock wait time separately from SQLite busy retries. The existing SQLite counter can remain zero while requests queue behind the in-process global mutex.
6. Consider bounded blocking database execution, bounded admission, short transactions and indexed/bounded audit access first; choose sharding or a different database only after measurements justify it. Never substitute reduced durability for capacity work.
7. Add MFA, dashboard/SSE, P2P replication/repair, hardware/KMS latency and independent-writer scenarios. Full body/connection resource bounds need their own validation beyond the operator's I/O semaphore.

These results advance the capacity gap from an unmeasured concern to reproducible evidence with a concrete operator admission fix. Production capacity qualification remains open.
