# 06 — Operations, performance and costs

All numbers below are provisional engineering targets or explicit hypothetical inputs. None is a measured product result, provider quote or contractual SLA. Validate them with the actual operators and supported client hardware before beta.

## Performance model and SLOs

Measure capture, encryption, local fsync, upload, operator persistence, readback, head publication and anchoring independently. The network path includes three uploads and verification reads; background queuing is fast because it finishes less work, not because remote durability is instantaneous.

| Measure | Proposed target | Measurement conditions |
|---|---|---|
| Local snapshot acknowledgement | p95 ≤ 1 second for 1 MiB changed content | Reference laptop SSD, warm agent, no key-unlock interaction, 100 files maximum |
| Remote-durable acknowledgement | p95 ≤ 10 seconds for a 1 MiB total recovery closure | All three operators healthy, client ≥ 20 Mbit/s upload/download, ≤ 150 ms RTT to each; complete closure readback included |
| First restored file | p95 ≤ 5 seconds after unlocking | Small file, authenticated metadata already fetched; exclude human kit entry |
| Full 100 MiB restore | p95 ≤ 120 seconds | ≥ 20 Mbit/s download, one intact healthy operator, clean local SSD; include integrity verification and staging |
| Remote retrieval success | ≥ 99.9% of scheduled synthetic restore attempts per 30 days | Independently located probes, retained and paid vaults; count operator/coordinator failure scenarios separately |
| Replica degradation detection | ≤ 1 hour | Hourly availability checks, continuous lease tracking |
| Repair start / completion | ≤ 1 hour / ≤ 24 hours after detection for 1 GiB | At least one intact source, funded replacement capacity, healthy network |
| Recovery drill success | 100% of release-gate scenarios | This is a gate, not a statistically proven population reliability rate |
| Anchor queue age | p95 ≤ 1 hour to L2 inclusion | Healthy chain, fee under configured cap; exceptions visible |

Track p50/p95/p99 and sample count by file-size class, platform, region and degraded scenario. The remote-durable target above applies to a small total closure, not a 1 MiB change inside a large snapshot: full readback grows with the referenced closure. Relaxing that policy to sampled or cached verification requires a separately named status and measured policy review. Do not remove failures from latency statistics without reporting their count and error budget. A 99.9% attempt-based SLI is not a durability probability and cannot be converted into “nines” of data survival. A synthetic dataset may underrepresent real filesystem and user-recovery errors.

The recovery point objective is the last fully committed remote snapshot: zero additional loss relative to that acknowledged snapshot, conditional on surviving intact storage. A five-second watcher debounce does not establish a five-second RPO during outages. Display oldest queued change age. The recovery time objective includes human kit retrieval, client installation and network setup; the automated 120-second target excludes those human steps and is not the total RTO.

## Optimization order

Begin with full copies, fixed chunks, bounded parallel I/O and no compression. Reuse unchanged immutable file versions within a vault, but create a fresh key for every changed file version. Re-upload only changed objects while checking that reused objects remain leased. Avoid cross-user deduplication. Larger files may eventually justify content-defined chunking, but its leakage, memory use and invalidation rules need explicit review.

Keep the plaintext capture pipeline bounded; do not load the entire vault into memory. Cache encrypted objects and verified metadata. Use resumable chunk requests with exponential backoff, jitter, deadlines and cancellation. Limit retries to avoid billing explosions. A speculative second download can improve tail latency but costs egress; enable only after measurement and cap duplicate bytes.

Measure Windows antivirus scanning, path normalization, TLS establishment, operator fsync and key-unlock costs. An existing L2's subsecond sequencer confirmation cannot remove these costs. No blockchain operation belongs on the local file-save critical path.

## Operations responsibilities

| Role | Responsibilities | Privilege boundary |
|---|---|---|
| Client maintainer | Signed releases, format compatibility, recovery UX | Build infrastructure must not receive user secrets |
| Operator | Durable objects, retention enforcement, direct recovery, receipts | No decryption keys; separate storage and admin credentials |
| Maintenance service | Audit ciphertext, renew leases, repair deficits | Capped spend, append placement only, no early delete |
| Coordinator | Account support, schedules, billing ledger, optional relayer | Replaceable; no recovery private key |
| Security owner | Incident response, threat-model maintenance, independent review | Cannot reset user encryption keys through support |

Use distinct operator domains and service accounts; do not share a privileged cloud login across all replicas. Rotate TLS and operator signing keys through signed continuity records. Preserve old verification keys for receipts. Changes to operator identity need recovery-policy verification rather than silently trusting a changed certificate or DNS response.

## Service backups and disaster recovery

PostgreSQL coordinator backups include the encrypted/opaque placement catalog, lease ledger, job outbox and signed records. Proposed target: continuous WAL archiving with ≤ 15-minute service-state RPO, daily snapshots and a quarterly rebuild drill. Protect service credentials separately with restricted access and documented break-glass custody. These backups improve service recovery but must not be the user's only metadata copy.

Each operator backs up its pin/lease/recovery-log databases consistently with its object inventory. On restart, reconcile receipts with real objects and pin state before reporting health. A restored database may list missing objects; receipt presence is not evidence that disks survived. Kubo garbage collection must never run from an incomplete reconstructed pin set. Freeze collection during recovery until all active lease references are reconciled.

Keep standalone restore packages, protocol specifications and synthetic verification vectors on multiple independently controlled distribution routes. Archive exact readers needed for older format versions. A binary signature requires a known trust root; preserve that root in the kit and document key-transition verification. Test platform dependency availability on a genuinely clean machine.

## Incident runbooks

| Incident | Immediate action | Recovery / closure evidence |
|---|---|---|
| One operator disappears | Mark degraded; keep surviving leases; start replacement | Full closure readback from replacement, updated signed placement and kit-route overlap |
| Ciphertext corruption | Quarantine response, retry another operator, retain evidence | Known digest match, repaired copy, operator root-cause review |
| Coordinator database lost | Pause billing mutations; restore ledger or rebuild signed records | Reconcile paid terms and jobs; prove direct user restore still works |
| All coordinator endpoints blocked | Client uses kit-listed operators | Clean-machine restore report without coordinator traffic |
| Funding below runway | Notify owner, stop optional anchoring first, request renewal action | Recorded funding/lease extension or explicit expiration warning |
| Storage exhausted | Reject new durability claims; preserve retained versions | Capacity added and queued closures verified; never evict protected history silently |
| Chain/RPC outage | Queue checkpoint; continue storage and restore | Independent canonical inclusion check after recovery |
| Chain reorg | Downgrade anchor evidence and resubmit if required | New canonical evidence; do not roll back stored files automatically |
| Suspected device theft | Revoke device, rotate future epoch, retain history | Clean-machine recovery, issuer-side credential rotation as applicable |
| Recovery kit stolen | Treat history as exposed; migrate authority and keys | New kit and recovery drill; no claim that old ciphertext is safe |
| All copies unavailable | Preserve evidence and remaining metadata; try documented exports | Explicit unavailable outcome; do not promise reconstruction |
| Malicious client release | Halt distribution, disclose affected versions, independent investigation | Reviewed replacement and credential-exposure response |

Operational alerts contain opaque incident IDs and status only. Detailed CIDs/locators may be needed in restricted diagnostic records, but default telemetry and support exports omit them. Never request real `.env` files or recovery phrases for support reproduction; use synthetic fixtures.

## Cost model

Let `H` be retained unique ciphertext GiB including history, padding and manifests; `r = 3` full replicas; `U` newly uploaded ciphertext GiB/month before replication; `A` audit/readback GiB/month; `E` user-restore plus repair-source egress GiB/month; `N` checkpoint transactions/month. Let per-operator storage rate be `s_i`, monthly minimum `m_i`, request cost `q_i`, and egress rate `e_i`.

Approximate monthly cost is:

```text
storage = sum over operators i of max(m_i, H * s_i)
network = charged upload + sum of charged audit/restore/repair egress
requests = sum of metered API request charges
chain = sum of actual checkpoint fees + relayer/RPC overhead
total = storage + network + requests + chain + service operations
        + support/security-review allocation + contingency
```

Do not multiply a provider's already-redundant advertised rate by three without understanding what that quote includes. Conversely, one provider's internal replication is not three independent product operators. Arbitrum charges for execution and parent-chain data contributions; estimate from actual payloads and current network conditions using its [gas and fee documentation](https://docs.arbitrum.io/how-arbitrum-works/deep-dives/gas-and-fees), not a fixed cents-per-transaction claim.

### Worked planning example — hypothetical prices

Assume a 100 MiB active vault adds 5 MiB of unique encrypted versions daily for 90 days. Ignoring padding/manifests, retained content is approximately `(100 + 5 × 90) / 1024 = 0.537 GiB`. Add a hypothetical 10% format/padding allowance: `H ≈ 0.591 GiB`, or `1.772 GiB` across three copies. Actual padding overhead can be much higher for many tiny files and must be measured.

At an **assumed** `$0.05/GiB-month` with no minimum, storage is about `$0.089/month`. At an **assumed** `$5/operator/month` minimum, storage instead costs `$15/month`. These illustrate why small-vault economics are dominated by minimums and operations, not raw disk capacity. They are not observed market prices.

Daily full auditing of all three copies transfers about `0.591 × 3 × 30 = 53.2 GiB/month`; at an **assumed** `$0.05/GiB` charged egress, that is `$2.66/month`. Weekly full audits would be roughly `7.1 GiB/month` using four rounds, plus small hourly probes and initial commit readbacks. Choose audit frequency explicitly; low byte storage prices can conceal substantial verification traffic.

For 30 checkpoints/month and an **assumed** fee of `$0.01` each, chain fees are `$0.30`; at `$0.10` each they are `$3`. No fee estimate is promised. Use a per-transaction cap and monthly budget; queue when over cap. Adding a dedicated rollup adds fixed chain operations and parent-chain publication costs that this model currently avoids.

For 1,000 such vaults, raw three-copy history is about 1.73 TiB before service backups. Do not extrapolate the single-vault minimum blindly: shared capacity contracts may change unit economics, but concentrating all vaults under one provider harms independence. Include request count, support, emergency retrieval, independent operators, security review, taxes where applicable and a proposed 30% contingency in a real business budget.

## Procurement evidence before pricing the product

Obtain written quotes from three independently administered operators covering storage minimums, egress, readback, emergency recovery, retention lock, lease extension, account suspension, termination, data export and liability limits. Verify shared subcontractors and the availability of the custom recovery API. Record quote dates and validity periods. No operators were contracted or funds spent in this documentation task.
