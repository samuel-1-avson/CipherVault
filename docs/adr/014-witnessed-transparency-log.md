# ADR-014: CipherChain becomes a witnessed transparency log

Date: 2026-11-19 · Status: Accepted (direction chosen; implementation not started)

## Context

CipherChain anchors a vault head to a ledger so anyone can later check
that the head existed, unaltered, by some time. The
[2026-11-19 review](../audit/CIPHERCHAIN_REVIEW_2026-11-19.md) found the
verification layer broken (CC-01 to CC-03, since fixed). It also found
that the multi-validator design was never finished:

- **No consensus.** No code casts votes (CC-04).
- **Forks.** Honest nodes would fork with 4 or more validators, because
  a block's hash depends on which quorum signed it (CC-06).
- **No fault tolerance.** Three validators tolerate zero failures
  (CC-07).
- **Unbounded rotation.** A quorum can rotate the validator set to
  anything (CC-13).

Today only solo chains commit, and a solo chain is tamper-evident only
against parties without the device's key.

The review set out two options. **A** finishes BFT consensus: voting,
leader rotation, view change, certificate-independent block identity, a
client submission path and at least 4 validators. **B** re-scopes the
chain as a witnessed transparency log. This record chooses **B**.

Anchoring never needed agreement on *one* global order. It needs:

1. an **append-only** record that cannot be rewritten or forked
   undetectably;
2. **inclusion proofs** a client can check offline;
3. **independent parties** vouching for what the record contained and
   when.

Transparency logs provide exactly that, with designs proven at scale in
Certificate Transparency, Sigstore Rekor and the Go checksum database.

## Decision

1. **One log per operator.** Each operator runs an append-only Merkle log
   with its own signing key and origin, built on the RFC 9162
   (Certificate Transparency v2) tree.
2. **Client submission.** Vault devices submit commitments over an
   authenticated device session. Devices are never validators.
3. **Signed checkpoints.** A log periodically signs a checkpoint (origin,
   tree size, root hash) in the C2SP `tlog-checkpoint` / `signed-note`
   format.
4. **Witnesses.** Independent witnesses cosign a checkpoint only after
   verifying a consistency proof from the last checkpoint they cosigned.
   They use the C2SP `tlog-witness` protocol and `cosignature/v1`, which
   signs a timestamp.
5. **Offline verification.** A client verifies an anchor offline from:
   - an inclusion proof;
   - a checkpoint signed by the log;
   - cosignatures from a policy-defined quorum of witnesses;
   all against keys it pinned in advance.
6. **CipherChain consensus is retired.** Existing CipherChain evidence
   stays verifiable read-only.

## Design

### What an anchor proves

| Claim | How it holds |
|---|---|
| Commitment C is in log L at index i of a tree of size n | Inclusion proof (RFC 9162) to the root in a checkpoint signed by L's pinned key. Size and index are bound by the proof, which also fixes CC-18. |
| L can never show a version of history without C | Witnesses cosign only checkpoints consistent with every one they cosigned before. A split view requires the witness quorum to collude. |
| C existed by time T | T is the latest timestamp among the policy quorum's `cosignature/v1` signatures, so backdating needs the whole quorum to lie. |
| The vault owner authorized the anchor | Not a log property. Submission is authenticated by device session; the commitment's preimage stays local. |

**Not provided:**

- a global order across logs;
- availability if every configured log is down (anchoring then fails
  closed);
- by itself, discovery of a vault's latest head after total device loss
  (see *Vault monitor tags*).

### Entries

The leaf is `0x01 ‖ commitment (32 B) ‖ monitor_tag (32 B)`:

- `commitment` is today's
  `SHA-256("CIPHERVAULT-ANCHOR-V1" ‖ salt ‖ head_cid)`, with `salt`
  derived from the epoch key. The preimage never leaves the vault, so
  every entry is private by default (CC-10).
- `monitor_tag` is all zeros until Phase 5. It is reserved now so that
  adding it later is not a format change.
- There is no device key and no signature in the leaf, so entries from
  one vault cannot be linked to each other.

### Tree and proofs

- **Hashing:** RFC 9162 Merkle tree hash with `0x00`/`0x01` leaf/node
  prefixes. An odd node is promoted, not duplicated, so the CC-08
  mutation class cannot arise.
- **Proofs:** inclusion and consistency proofs exactly as RFC 9162
  defines them, verified against the published test vectors.
- **Appends:** an incremental compact range gives O(log n) appends and
  needs no full-tree rebuild (CC-14).

### Checkpoints, signatures and witnesses

- **Checkpoint format:** `<origin>\n<tree size>\n<base64 root>\n`, signed
  as a C2SP signed note with Ed25519. The origin is a stable per-log
  string, for example `cipherchain.op1.cipherv.online/log`. Signed-note
  text is canonical, so there is no JSON re-serialization (CC-15).
- **Witness protocol:** C2SP `tlog-witness`. The log sends the new
  checkpoint plus a consistency proof from the witness's last-seen size.
  The witness verifies it, stores the new checkpoint, and returns a
  `cosignature/v1` (Ed25519 over a timestamp and the checkpoint body).
  The log publishes the checkpoint with its collected cosignatures.
- **Default topology:** every operator also witnesses every other
  operator's log. A client policy may add external C2SP-compatible
  witnesses, and requires cosignatures from witnesses run by someone
  other than the log's own operator.

### Submission and sequencing

- **Endpoint:** `POST /v1/log/add`, authenticated by the existing
  operator device session (`/v1/challenges`, `/v1/sessions`) and
  rate-limited per device.
- **Sequencing:** the log batches entries (for example every second or
  every 256 entries), assigns indices, extends the tree, signs a
  checkpoint and starts witnessing.
- **Responses:** the client receives its index at once and polls `GET`
  endpoints for a cosigned checkpoint covering it.
- **Serving:** C2SP `tlog-tiles` (static, cacheable tiles and checkpoint
  files) plus a convenience proof endpoint. Tiles live beside the
  operator's existing redb store (ADR-004).

### Client policy and verification

**Policy.** A versioned policy file in the vault directory pins:

- each log's origin and public key;
- each witness's public key;
- `logs_required`: on how many logs each anchor must land (default 2);
- `witnesses_required`: how many independent cosignatures each
  checkpoint needs (default 2).

The policy is the trust root. This replaces the CipherChain
genesis-record and rotation machinery (CC-12, CC-13), and changing it
is an explicit, local, auditable act.

**Anchoring.** `ciphervault anchor`:

- submits to the configured logs;
- waits until `logs_required` of them return a cosigned checkpoint
  meeting policy;
- verifies each inclusion proof;
- saves evidence v2 per log: origin, index, tree size, the cosigned
  checkpoint and the inclusion proof.

**Verification.** `ciphervault verify-anchor` re-verifies all of it
offline and exits non-zero on any failure, as today.

**Consistency.** The client keeps the latest checkpoint it verified per
log. Every later fetch must come with a consistency proof from that
checkpoint, so a log that forks or rewrites history is caught the next
time the client talks to it.

### Monitoring and misbehavior

- **Evidence of a lying log:** two signed checkpoints of the same size
  with different roots, or a checkpoint inconsistent with an earlier
  one. Witnesses, clients and `ciphervault doctor` keep any such pair;
  it is self-verifying, unlike today's in-memory vote evidence (CC-16).
- **Doctor checks:** `ciphervault doctor` checks log reachability,
  checkpoint freshness and witness quorum, and gossips the latest
  checkpoints it has seen with other configured witnesses (simple
  checkpoint exchange, no consensus).
- **Vault monitor tags (Phase 5):** the tag for the k-th anchor of a
  vault is `HMAC-SHA256(k_monitor, "CIPHERVAULT-LOG-TAG-V1" ‖ k)`, where
  `k_monitor` derives from the recovery secret. A clean-machine
  recovery recomputes the tags and scans the logs' tiles for them, so
  it can find the newest anchored head without trusting a storage
  operator. That closes the "operator serves an old snapshot" gap.
  Scanning tiles locally reveals nothing to the log.

### Keys

- Log and witness signing keys start as owner-only key files.
- They can move to PIV or TPM (CC-17), reusing the existing YubiKey PIV
  path.
- Rotating a log key means starting a new log (new origin), which is
  the standard transparency-log practice. Clients learn about it by
  policy update, never in-band.

## How this resolves the open review findings

| Finding | Outcome |
|---|---|
| CC-04 no votes, clients must be validators | **Gone.** No voting. Devices submit over a session. |
| CC-06 non-deterministic certificates | **Gone.** No certificates. A checkpoint is a deterministic function of the tree. |
| CC-07 3 validators, no fault tolerance | **Replaced.** Availability comes from `logs_required`-of-N independent logs; integrity comes from witnesses, not a validator quorum. |
| CC-09 proposal flooding | **Gone.** No proposals. Submission is rate-limited per device. |
| CC-10 public preimage by default | **Fixed by design.** Leaves carry only the commitment. |
| CC-12 trust anchor not pinned | **Fixed.** Pinned origins and keys in the client policy. |
| CC-13 unbounded rotation | **Gone.** No in-band rotation. Key changes are policy updates. |
| CC-14 scalability | **Fixed.** O(log n) appends, tiles, and no full replay. |
| CC-15 JSON re-serialization | **Fixed.** Canonical signed-note text. |
| CC-16 ephemeral equivocation evidence | **Fixed.** Persisted, self-verifying misbehavior proofs. |
| CC-17 raw key files | **Planned** (Phase 6). |
| CC-18 unauthenticated proof positions | **Fixed.** RFC 9162 proofs bind index and size, and the size is in the signed checkpoint. |
| CC-19 dead anchor client | **Replaced** by the log client. |

## Migration

- **Existing anchors.** The review fixes cover existing CipherChain
  anchors (solo chains, block versions 1 to 4). `verify-anchor` keeps
  verifying that evidence read-only, indefinitely.
- **The switch.** Once a policy file with at least `logs_required` logs
  exists, `ciphervault anchor` writes to the logs. Until then it keeps
  writing solo CipherChain blocks and says so.
  `ciphervault anchor --migrate` re-anchors the current head into the
  logs; the old evidence is kept.
- **Operators.** Operators gain the log, witness and tile endpoints.
  `/v1/chain/publish`, chain gossip and the chain-sync hub are removed
  in Phase 6, once no supported CLI uses them.
- **Agent log.** The agent audit log's fleet checkpoints (`agent-log
  anchor`) move into the transparency log in Phase 5. Tail truncation
  then becomes detectable against witnessed history rather than a
  single operator's copy.

## Implementation plan

Each phase is one PR, or a few, with its own tests. Phases 2 and 3 can
run in parallel once Phase 1 lands.

| Phase | Deliverable | Done when | Size |
|---|---|---|---|
| **1. Log core** | New crate `crates/translog`: RFC 9162 hashing, inclusion and consistency proofs (generate and verify), compact-range appends, C2SP checkpoint / signed-note / `cosignature/v1` encode and verify, tile paths | Passes RFC 9162 and C2SP test vectors; property tests show random trees verify every inclusion and consistency proof and reject mutated ones; fuzzing of parsers and proof verifiers | M |
| **2. Operator log** | Log storage (tiles plus entry bundles) and sequencer; `POST /v1/log/add` with session auth and per-device rate limits; checkpoint signing; tile and checkpoint `GET` endpoints; crash-safe writes | A 3-operator test fleet accepts submissions, serves proofs that verify with the Phase 1 client, survives crash and restart with no lost or reordered entries, and rejects unauthenticated or over-limit submissions | L |
| **3. Witness** | `tlog-witness` server mode in the operator (and a standalone binary); per-log state; logs push checkpoints to witnesses and collect cosignatures | Cross-witnessing works across the 3 operators; a witness refuses an inconsistent checkpoint and keeps the evidence pair; a published checkpoint carries a quorum of cosignatures | M |
| **4. CLI** | Policy file and `ciphervault log policy` commands; `anchor` to N logs; evidence v2; `verify-anchor` for both v2 and legacy evidence; `doctor` checks; `anchor --migrate` | End-to-end: anchor on the test fleet, verify offline, tamper with any field and fail, take one log down and still anchor with 2 of 3, and legacy evidence still verifies | M |
| **5. Monitoring** | Persistent per-log consistency tracking in the CLI; checkpoint gossip in `doctor`; vault monitor tags and recovery-time scanning; agent-log checkpoints moved into the log | A forked log is detected by client and witness and reported; a clean-machine recovery finds the newest anchored head from tags alone | M |
| **6. Retire CipherChain** | Remove the chain-sync hub, `/v1/chain/publish`, chain gossip and the genesis ceremony; keep the read-only verifier; optional PIV/TPM log and witness keys; optional RFC 3161 timestamps on checkpoints; update docs and the audit pack (C9) | No consensus code ships; docs and the audit pack describe the log; the log protocol goes to external review | M |

Rough order of effort: Phases 1 to 4 deliver the new guarantee, and the
rest hardens it. The review's rating estimate rises to about 8/10 after
Phase 4, and higher after an external review.

## Risks and open questions

- **Spec drift.** C2SP specs are stable but versioned. Pin versions,
  vendor their test vectors, and keep the formats behind one module.
- **Witness independence.** With only the three founding operators
  cross-witnessing, "independent" means "a different operator". The
  policy should allow external witnesses from day one.
  *Open question for the owner:* should defaults include any external
  witness?
- **Tag scanning cost.** Recovery-time scanning downloads tiles, which
  costs bandwidth for large logs. Acceptable at current scale; revisit
  with an index or private lookup if logs grow large.
- **Availability versus safety.** A client requiring 2 of 3 logs cannot
  anchor if two operators are down. It fails closed, which is
  acceptable for anchoring because the vault itself is unaffected.
- **Keeping CipherChain code.** Phase 6 deletes the consensus code.
  *Open question:* should it stay behind a feature flag for a release
  first?

## Consequences

- Anchoring gains a guarantee that third parties can check, without a
  consensus protocol to build, operate or audit.
- Most of the review's open findings close by construction rather than
  one patch at a time.
- Operators run three small services instead of a consensus hub: log,
  witness and tiles.
- Solo CipherChain anchors remain valid evidence, but new anchors
  require at least `logs_required` reachable logs.
