# Repair protocol (Phase 4)

How the mesh detects dead peers, agrees who repairs what, and backfills
without storms. Control plane is new; the data plane is a dedicated
mesh-internal `RepairPush` RPC (P2P-only, no HTTP route): operator-signed,
verified against the peer routing table, digest-checked, and paced by a
dedicated receiver repair budget (429 + sender backoff). Client
voucher/quota enforcement does NOT apply to repair traffic — repair is
authorized by mesh membership (known sender + valid signature), not by
client write vouchers.

## 1. Liveness: signed heartbeats (slice 1, landed)

Every swarm node publishes a signed heartbeat on the gossipsub control
topic every `heartbeat_interval` (default 5 s):

```json
{"Heartbeat": {"version": 1, "operator_id": "...", "peer_id": "<base58>",
 "seq": 42, "wall_time_ms": 1758..., "signer_pk_hex": "...",
 "signature_hex": "..."}}
```

- Signature domain is `ciphervault_heartbeat_v1` over
  `version || operator_id || peer_id || seq || wall_time_ms || signer_pk`.
  Same ed25519 operator keys as peer gossip (D5).
- The envelope is an externally-tagged `ControlMessage` enum so future
  control kinds (repair claims, erasure manifests) ride the same topic.
- Authorship comes ONLY from the inner signature. The gossipsub
  `propagation_source` is the forwarder, never the author — relays
  forward other nodes' heartbeats, so attributing to the forwarder
  would be a spoofing hole.

Verification order on receipt (fail closed, first failure wins):

1. Envelope parses as `ControlMessage`, `version == 1`.
2. `wall_time_ms` within ±60 s of local time (replay window bound).
3. Sender known: `operator_id` resolves in the peer routing table AND
   `signer_pk_hex` equals the announced descriptor key (binds the
   heartbeat key to the D5-verified announced key; the claimed `peer_id`
   is then trusted-by-signature).
4. Signature verifies.
5. `seq` strictly increases per sender (first-seen baselines; equal or
   lower is a replay).

Verdict → gossipsub `MessageAcceptance` (Strict validation mode):

| Verdict | Acceptance | Rationale |
|---|---|---|
| valid heartbeat | Accept | |
| bad envelope/version/skew/signature/stale seq | Reject | sender is faulty or Byzantine; penalize |
| unknown sender / unknown message kind | Ignore | not misbehavior; forward-compatible with upgrades |

Failure detection is purely local: a peer is live while a valid
heartbeat arrived within `heartbeat_timeout` (default 15 s). There are
NO death claims on the wire — anonymous or otherwise — so there is
nothing to forge; every node computes liveness from the same heartbeat
stream plus local timeouts, and views converge without trust.

## 2. Repair assignment: rendezvous hashing (slice 2)

Any holder may notice under-replication: it lists providers for a CID
(DHT provider records, Phase 2), intersects with its locally-live set,
and triggers repair when live holders < replication target (3x default).

Given holder set H (live) and target T, all observers compute the same
plan with rendezvous hashing (`score = H(candidate || cid)`, lowest
wins):

- pusher = lowest-score member of H (exactly one node pushes — no
  duplicate backfills from convergent views);
- recipients = lowest `T - |H|` scores among live non-holders.

Membership churn reassigns minimally (rendezvous property). A failed
push excludes that recipient and recomputes next round; a per-CID
cooldown suppresses re-triggers while the mesh converges.

Convergence assumption (documented; chaos proof pending slice 4):
assignment inputs (live set, provider records) converge across nodes
because heartbeats and DHT records converge. Divergent inputs can only
cause a duplicate push or a skipped round, never data loss or a storm
(see §3). The slice-4 chaos gate will inject partitions and forged
gossip to prove the storm-resistance bound.

## 3. Backfill: paced sender, enforced receiver (slice 2)

- Sender: token bucket (configurable bytes/s + max concurrent pushes).
  Repair traffic never exceeds its budget however far behind the mesh
  is — this is what makes repair O(budget) instead of O(debt).
- Receiver: repair pushes arrive as signed `RepairPush` RPCs (P2P-only,
  no HTTP route). The receiver verifies the sender against its peer
  routing table, checks the ed25519 signature and the digest, then
  spends dedicated repair budget — over-budget pushes get a plain 429
  (no voucher/quota path is involved). A 429 (or any failure) makes
  the sender back off exponentially with jitter and re-queue; the
  per-CID cooldown prevents hot-looping.
- Known limitation (carried, not fixed in Phase 4): repair has no
  priority lane relative to client writes — on an exhausted repair
  budget, repair waits like any other paced traffic. A priority lane
  is future work with its own abuse analysis.

Storm resistance, by construction: one deterministic pusher per object
(no N-holder fan-out), sender token bucket (bounded bandwidth), 429
backoff (receiver backpressure), per-CID cooldown (no hot rounds),
and no death-claim amplification (forged gossip cannot declare peers
dead — the slice-4 chaos gate will inject forgeries to prove it).

## 4. Telemetry (slices 1–2)

Rendered Prometheus series (all new; static exposition unchanged):

- `ciphervault_swarm_heartbeats_sent_total` /
  `ciphervault_swarm_heartbeats_received_total`
- `ciphervault_swarm_heartbeats_dropped_<reason>_total`
  (`bad_envelope`, `bad_version`, `clock_skew`, `unknown_sender`,
  `bad_signature`, `stale_seq`)
- `ciphervault_swarm_control_unknown_kind_ignored_total`
- `ciphervault_swarm_peers_live` (gauge, set by the swarm loop)
- Slice 2 (landed): `ciphervault_swarm_repair_checks_total`,
  `ciphervault_swarm_repair_jobs_started_total`,
  `ciphervault_swarm_repair_jobs_completed_total`,
  `ciphervault_swarm_repair_jobs_failed_total`,
  `ciphervault_swarm_repair_backoff_total`,
  `ciphervault_swarm_repair_cooldown_suppressed_total`,
  `ciphervault_swarm_repair_bucket_deferred_total`,
  `ciphervault_swarm_repair_budget_exhausted_total`,
  `ciphervault_swarm_repair_bytes_total`.

## 5. Chaos gates (slice 4)

Containerized 10-node mesh (extends the NAT drill script pattern;
slice 4, pending):
kill 3/10 mid-write, partition the mesh, inject forged gossip. Assert:
full replication recovery without client involvement, bounded repair
bandwidth (token-bucket ceiling holds on the wire), and zero repair
storm under forgery. Gate: green three consecutive runs.

## 6. D7 erasure coding (slice 3, separate spike)

Evaluate Reed-Solomon (leading candidate reed-solomon-simd) for large
blobs on durability-per-byte vs repair complexity; default stays 3x
full replication unless the spike proves a win. Follows the D6 spike
pattern (standalone crate, attached report, no commitment without data).
