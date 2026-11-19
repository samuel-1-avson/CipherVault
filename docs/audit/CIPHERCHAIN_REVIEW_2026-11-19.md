# CipherChain review (2026-11-19)

Internal review of the sovereign anchoring chain at `main` @ `ed9ce30`
(v1.0.37).

**Scope:** all of `crates/chain`, plus the code that uses it:

- the CLI anchor and verify commands (`apps/cli/src/commands/anchor.rs`)
- the storage-crate anchor client (`crates/storage/src/chain.rs`)
- the operator's chain admission, sync, backfill and publish paths
  (`services/operator/src/state/methods_chain.rs`,
  `services/operator/src/swarm/mod.rs`,
  `services/operator/src/handlers.rs`)

**Method note:** this is an AI-assisted *internal* review based on
reading the source only. No tests were run and no finding was
demonstrated with a working exploit. Each finding states its
preconditions so it can be confirmed with a targeted test before it
is fixed. This is **not** the external audit, which is still open
([`README.md`](./README.md)).

**Not reviewed in depth:** the genesis ceremony CLI (`genesis.rs`),
libp2p peer admission and transport, and `swarm/serve.rs`.

## Summary

The cryptographic building blocks are sound. At review time, the
verification layer and the multi-node consensus were not:

- The light client accepted proofs that did not prove the commitment
  it was asked about. *(Fixed: CC-01.)*
- Block timestamps were not covered by any signature. *(Fixed for
  block v4 and later: CC-02.)*
- `verify-anchor` reported success when verification failed. *(Fixed:
  CC-03.)*
- No production code casts votes, so multi-validator anchoring cannot
  commit. **Solo mode, a chain signed only by the local device, is the
  only path that commits blocks today.** *(Open: CC-04.)*

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 4 |
| Medium | 6 |
| Low | 6 |

CC-01, CC-02, CC-03, CC-05, CC-08, CC-09 and CC-11 are **fixed**, and
CC-12 and CC-18 are partly fixed. Every other finding is **open**.

## Fixed since the review

The critical fixes (CC-01 to CC-03) landed first, in
`fix/cipherchain-critical-cc01-03`; CC-05, CC-08 and CC-11 followed.

| ID | Sev | Fix |
|---|---|---|
| CC-01 | CRITICAL | `AnchorProofResponse` now carries the committed `CommitmentTx`. The light client: recomputes the commitment from its own preimage; requires the carried transaction to be for that commitment (and, for v0/v1 transactions, to carry the same preimage); verifies the transaction's signature; recomputes its Merkle leaf; and requires that leaf to be the audit path's leaf at `tx_index`. |
| CC-02 | CRITICAL | Block **version 4** (`SIGNED_TIME_VERSION`): every signature carries and signs the signer's observed time (`BlockHeader::vote_bytes_v4`). `verify_header_signatures` and the light client require `timestamp_ms` to equal the median of the verified signers' samples. Votes must sign the time they report. A block's version can never drop below its parent's. The light client takes the time from the header, rejects a proof whose copy differs, and reports `timestamp_signed: false` for v2/v3 blocks. |
| CC-03 | CRITICAL | `verify-anchor` now runs `verify_anchor_evidence` and exits non-zero on every failure: tampered evidence, legacy EVM evidence, a missing or non-reverifying ledger, a commitment not on-chain, evidence naming a different block, or a failed light-client check. It verifies against the set that certified genesis, walked forward through certified rotations. Private (v2) anchors verify through the local preimage. |
| CC-05 | HIGH | `ChainSyncHub::backfill` treats the served history and genesis set as untrusted. It rebuilds the history in memory and accepts it only if it contains the replica's own tip (same hash at the same height) and derives the same validator set at that tip. Only then is anything written. A peer can extend a replica's chain but can no longer replace it or narrow who signs it. An adopted tip that carries a rotation now applies it, and operator admission follows. |
| CC-08 | MEDIUM | `check_block` and `propose_block` reject a block that repeats a transaction, and require each client's nonces to increase strictly within a block as well as across committed state. Every block mutated by duplicating its tail repeats a transaction, so it is rejected even though its roots and hash match the genuine block. The Merkle tree's doc comment now states the odd-node behavior instead of claiming RFC 6962. |
| CC-11 | MEDIUM | Block files, `tip.json` and `genesis_validators.json` are written to a temp file, fsynced and renamed into place, and `open` ignores leftover `.tmp` files. A backfill writes every block and the genesis set before removing `tip.json`. While `tip.json` exists, `open` reopens the directory as the tip replica and ignores partial history below the tip, so an interrupted backfill no longer stops the node from starting. |
| CC-09 | MEDIUM | `ChainSyncHub::ingest_proposal` keeps at most one proposal per proposer per height, replacing the 16-slot pool shared by all validators. A second, different, validly signed proposal from the same proposer is recorded as equivocation evidence and relayed once; further ones are refused. Re-proposing at a stalled height now needs a different validator, until the view change in ADR-013 exists. |
| CC-12 (part) | MEDIUM | `advance_to_rotation` verifies the rotation header's quorum under the current trusted set before switching trust. `verify-anchor` also requires the configured validator set (`validators.json`) to be the chain's genesis set or the set active at the proof's height, so a replaced genesis record can't become its trust root. Genesis-hash pinning is still open, and `SovereignLedger::open` still prefers the on-disk genesis file. |
| CC-18 (part) | LOW | The light client uses `InclusionProof::verify_bound`: each step's direction comes from `leaf_index`, the step count must match `total_leaves`, and a lone right-edge node must be paired with itself. A path can no longer be relabelled with another position. The tree size itself is still not committed in block headers. |

**PR #59 review hardening** (Sourcery review, commit `f22519f`):

- The light client rejects block versions outside `1..=PROTOCOL_VERSION`, and requires the proposer to be trusted, as the ledger does.
- Private (v2) transactions must carry zero `salt`/`head_cid`, since neither field is signed or hashed. Unknown transaction versions are rejected.
- Proofs carry `format_version`. Legacy proofs still parse, and are refused with `UnsupportedProofFormat`.
- Rolling upgrades: multi-validator chains keep their parent's block version until the operator activates the latest one (`CIPHERVAULT_CHAIN_ACTIVATE_LATEST=1`). Single-validator chains use it at once.

**Compatibility:**

- **Upgrade order.** Block v4 is a format change. Upgrade every node
  that verifies chain data (operators and CLIs) before a v4 block
  reaches it, because older builds reject v4 signatures.
- **Existing chains.** This build appends v4 blocks to existing local
  v1-v3 chains. Existing v2/v3 blocks keep verifying under their old
  rules, but their times remain unauthenticated (`verify-anchor` says
  so); re-anchor to get a signed time.
- **Proofs.** Proof JSON now requires `tx`, so proofs produced by
  older builds fail to parse (closed, not open).
- **Exit codes.** `verify-anchor` now exits non-zero for legacy EVM
  evidence.
- **Blocks with repeated transactions** (CC-08) are now invalid. Honest
  proposers never produce them, so no format change is involved.
- **Backfill** (CC-05) now refuses history that doesn't contain the
  replica's tip, so a replica on a different chain than its peers
  (for example, after a manual re-genesis) stays put instead of being
  overwritten.
- **Reopening** (CC-11): while `tip.json` exists, a chain directory
  reopens as the tip replica even if full history files are present,
  because the snapshot is removed only once that history is complete.

**Regression tests added:**

- `light_client_rejects_relabelled_and_retimed_proofs`
  (`crates/chain/tests/sovereign_tests.rs`)
- `test_v4_header_time_must_be_signed_median`, plus the unsigned-rotation
  case in `test_advance_to_rotation_rekeys_trust`
  (`crates/chain/src/light_client.rs`)
- `test_v4_vote_must_sign_its_reported_time`,
  `test_v4_rewritten_block_time_is_rejected` and
  `test_downgrade_to_unsigned_time_version_is_rejected`
  (`crates/chain/src/sync.rs`)
- `verify_anchor_evidence_accepts_legacy_and_private_anchors` and
  `verify_anchor_evidence_fails_closed`
  (`apps/cli/src/commands/anchor.rs`)
- `test_mutated_block_with_duplicated_tail_is_rejected` and
  `test_in_block_nonce_replay_is_rejected` (CC-08, `sync.rs`)
- `test_backfill_rejects_foreign_history_and_keeps_replica` and
  `test_backfill_rejects_history_deriving_another_validator_set`
  (CC-05, `sync.rs`)
- `test_interrupted_backfill_reopens_as_tip_replica` (CC-11, `sync.rs`)
- `test_one_proposal_per_proposer_per_height` (CC-09, `sync.rs`)

## Verified sound

- Ed25519 signatures are verified with `verify_strict` everywhere:
  blocks, transactions, gossip envelopes and endorsements.
- Each signed or hashed payload has its own domain label:
  - `CIPHERVAULT_BLOCK_V1:` for blocks
  - `CIPHERVAULT_TX_V1:` for transactions
  - `CIPHERVAULT_SYNC_V1:` for gossip envelopes
  - `CIPHERVAULT-ANCHOR-V1` for commitments
  - `CIPHERVAULT-VAULT-PSEUDONYM-V1` for v2 pseudonyms
- Merkle leaf and node hashes are domain-separated in the RFC 6962
  style (`0x00` leaf prefix, `0x01` node prefix).
- Transaction signatures bind the chain ID.
- Each client nonce must strictly increase across blocks (replay
  protection), and the nonce table survives a restart.
- The commitment `SHA-256(domain ‖ salt ‖ head_cid)` uses fixed-width
  inputs, so it binds its inputs and hides them while the salt stays
  secret.
- The anchor salt is derived from the epoch key through the
  domain-separated legacy KDF (`CTX_ANCHOR_SALT`); pack item C1 covers
  that KDF.
- Gossip admission requires validator membership and a valid envelope
  signature. Relayed votes are refused.
- Conflicting votes from one validator are detected, and conflicting
  certified blocks are rejected.
- A replica that adopted a recent block refuses to validate or commit
  until it is backfilled from genesis.
- A consensus key file of the wrong length is rejected and never
  overwritten. New key files get owner-only permissions on Unix and
  Windows.
- With a multi-validator set, the CLI publishes the proposal before
  any local commit and honestly reports `PROPOSED — awaiting fleet
  quorum`.

## Findings

| ID | Sev | Status | Finding |
|---|---|---|---|
| CC-01 | CRITICAL | Fixed | The light client never checks that the Merkle proof's leaf is the commitment being verified |
| CC-02 | CRITICAL | Fixed | Block timestamps (header v2+) are covered by no signature, and the light client reports an unchecked proof field |
| CC-03 | CRITICAL | Fixed | `verify-anchor` fails open, trusts only the block's proposer, and can never verify private (v2) anchors |
| CC-04 | HIGH | Open | Multi-validator anchoring cannot commit: nothing casts votes, clients must be validators, and there is no transaction submission or CLI sync |
| CC-05 | HIGH | Fixed | Backfill takes the genesis validator set from the serving peer and replaces the local chain with no continuity check |
| CC-06 | HIGH | Open | Certificates are non-deterministic, so honest replicas fork with 4 or more validators |
| CC-07 | HIGH | Open | The default 3-validator fleet tolerates zero failures (quorum is 3 of 3) |
| CC-08 | MEDIUM | Fixed | Duplicating the last Merkle node lets a block be mutated with an unchanged hash; nonces are not checked within a block |
| CC-09 | MEDIUM | Fixed | The per-height proposal cap is shared by all validators, so one validator can block the rest |
| CC-10 | MEDIUM | Open | The default v1 transactions publish the salt, snapshot ID and vault ID on-chain |
| CC-11 | MEDIUM | Fixed | Ledger files are written non-atomically, so a crash can stop a replica from starting |
| CC-12 | MEDIUM | Partly fixed | No pinned genesis hash, the on-disk genesis file overrides the caller, and light-client rotation is unsigned |
| CC-13 | MEDIUM | Open | A quorum can rotate the validator set to anything, instantly |
| CC-14 | LOW | Open | Scalability: O(n) rebuild per commit, all blocks held in memory, unbounded `certified` set |
| CC-15 | LOW | Open | Gossip signatures cover re-serialized JSON rather than canonical bytes |
| CC-16 | LOW | Open | Evidence of conflicting votes is in-memory only, capped, and has no consequence |
| CC-17 | LOW | Open | Validator keys are raw seed files with no hardware option |
| CC-18 | LOW | Partly fixed | Proof position fields are unauthenticated, and the RFC 6962 claim is inaccurate |
| CC-19 | LOW | Open | A dead anchor client targets endpoints that don't exist, and the vault ID silently defaults to zero |

### CC-01 — CRITICAL: the inclusion proof is not bound to the commitment

**Where:**
[`light_client.rs:142`](../../crates/chain/src/light_client.rs#L142)

**What:**
- `verify_anchor` checks that `proof.tx_proof.leaf_hash` sits under
  `header.tx_root`.
- But `leaf_hash` is taken from the proof itself. Nothing recomputes
  it from the commitment.
- The response does not even carry the transaction fields needed to
  recompute the leaf (`vault_id`, `client_pubkey`, `signature`,
  `nonce`).
- So the verified Merkle path and the `commitment`, `head_cid` and
  `salt` fields are unrelated.

**Impact:** a valid proof for *any* transaction in *any* genuine,
quorum-signed block can be relabelled with the verifier's own
commitment, and it passes. With v1 transactions the salt and snapshot
ID are public on-chain, and are sent to every operator in the
proposal. So a single operator can "prove" that a proposal which
never committed was anchored, or move a real anchor to an earlier
block.

**Preconditions:** the verifier receives the proof from an untrusted
source. Today the CLI builds proofs from its own local ledger, so the
exposure is:
- the public light-client API;
- `SovereignAnchorClient`, which fetches remote proofs (CC-19);
- any future remote verification.

**Fix:**
- Put the full `CommitmentTx` in `AnchorProofResponse`.
- Recompute `tx_leaf_hash()` on the verifier and require it to equal
  `tx_proof.leaf_hash`.
- Require `tx.commitment` to equal the expected commitment and
  `tx_proof.leaf_index` to equal `tx_index`.
- Verify the transaction's signature.

### CC-02 — CRITICAL: anchor time is unauthenticated

**Where:**
- [`types.rs:159`](../../crates/chain/src/types.rs#L159): `vote_bytes`
  omits the timestamp.
- [`sync.rs:542`](../../crates/chain/src/sync.rs#L542): the median
  time is substituted after voting.
- [`light_client.rs:182`](../../crates/chain/src/light_client.rs#L182):
  the light client reports `proof.timestamp_ms`.

**What:**
- From header version 2 onward, validators sign everything except
  `timestamp_ms`.
- The node that assembles the block writes the median of the
  validators' observed times into the header. Those observed times
  are not kept in the certificate, so nobody else can recompute the
  median.
- `check_block` only checks that the timestamp is later than the
  parent block's.
- Separately, the light client returns `proof.timestamp_ms`, which it
  never compares with `proof.header.timestamp_ms`.

**Impact:** the anchor's main claim, "this state existed at time T",
can be backdated or postdated by:
- the node that assembles the block;
- anyone who stores the block (rewrite the header and recompute
  `block_hash`; every signature stays valid);
- anyone who serves a proof (edit the top-level field alone).

The documented claim of validator-voted time that is "robust to
f < quorum/3 liars" holds only inside the hub that assembled the
block, never for a verifier.

**Fix:**
- Each vote signs `vote_bytes ‖ observed_ms`.
- `BlockSignature` carries `observed_ms`.
- Verifiers recompute the median from the signed samples and require
  it to equal `header.timestamp_ms`.
- The light client reads the time from the header only and drops the
  top-level field.
- This changes the block format, so it needs a block version bump.

### CC-03 — CRITICAL: `verify-anchor` fails open and verifies against itself

**Where:**
- [`anchor.rs:369`](../../apps/cli/src/commands/anchor.rs#L369): the
  trusted set
- [`anchor.rs:408`](../../apps/cli/src/commands/anchor.rs#L408): the
  fallthrough

**What:**
- **Circular trust.** The light client is built with
  `vec![proof.header.proposer]` as its only trusted key, so it checks
  that the proposer signed and prints "1/1 Operator Signatures
  Verified" whatever the real validator set is.
- **Fails open.** If the chain directory is missing, the ledger fails
  to open, the proof lookup fails, or light-client verification
  fails, the command falls through. It prints **"Cryptographic
  Checkpoint Verified"** in green and returns `Ok(())`, exit code 0.
  It does this even after printing `TAMPERED / INVALID` for the
  commitment preimage.
- **Private anchors always fall through.** For private (v2)
  transactions the ledger record holds a zeroed salt and snapshot ID
  ([`ledger.rs:627`](../../crates/chain/src/ledger.rs#L627)). The
  light client compares those zeros with the expected values
  ([`light_client.rs:105`](../../crates/chain/src/light_client.rs#L105))
  and always fails, so every private anchor reaches the green
  fallthrough.

**Impact:** scripts and CI that rely on the exit code are told that
missing, tampered or unverifiable anchors are verified. This is the
same class of bug as B-F1 in the
[2026-11-10 pass](./INDEPENDENT_REVIEW_2026-11-10.md), where
`agent-log verify-remote` printed a divergence but exited 0.

**Fix:**
- Exit non-zero on every failure path, and print the reason.
- Verify against the real validator set, walking rotations from the
  genesis set.
- For v2 transactions, verify against the local preimage in the
  checkpoint evidence instead of the zeroed on-chain fields. This
  depends on CC-01's transaction-in-proof change.

### CC-04 — HIGH: multi-validator anchoring cannot commit in production

**Where:**
- [`anchor.rs:152`](../../apps/cli/src/commands/anchor.rs#L152) and
  [`anchor.rs:183`](../../apps/cli/src/commands/anchor.rs#L183)
- [`methods_chain.rs`](../../services/operator/src/state/methods_chain.rs)

**What:**
- **No votes.** No production code builds a `VoteMsg` or calls
  `proposal_time_acceptable` or `vote_observed_ms`. Only tests craft
  votes, by hand.
- **No proposals or submissions from operators.** Operators never
  propose blocks. The only chain endpoint, `/v1/chain/publish`,
  accepts sealed *validator* envelopes; there is no way for a client
  to submit a transaction.
- **Clients must be validators.** `propose_block` and envelope
  admission both require the proposer to be a validator. A vault
  device can therefore only anchor to a fleet if it is itself in the
  fleet's validator set, which also lets it sign blocks and rotate
  the set.
- **No sync in the CLI.** The CLI never downloads fleet blocks.
- **No evidence for fleet anchors.** Checkpoint evidence is saved only
  after a local commit, so a fleet anchor never gets evidence and
  `verify-anchor` stops with "No on-chain checkpoint evidence".

**Impact:**
- With more than one validator, anchors never commit.
- In solo mode the chain is a file signed by `device.key` on the same
  machine. Anyone who can read that key can rewrite it, so it gives no
  tamper-evidence beyond local signing.
- Several docs claim otherwise ("Operators vote through the chain sync
  hub", "IMMUTABLY ANCHORED", "Deterministic Sovereign Finality"); see
  [Docs that overclaim](#docs-that-overclaim).

**Fix:** choose between the two designs under
[Strategic decision](#strategic-decision) before building voting.
Correct the docs either way.

### CC-05 — HIGH: backfill trusts the serving peer's genesis set

**Where:**
- [`swarm/mod.rs:1700`](../../services/operator/src/swarm/mod.rs#L1700):
  the trigger
- [`swarm/mod.rs:1041`](../../services/operator/src/swarm/mod.rs#L1041):
  the genesis set is taken from the response
- [`methods_chain.rs:178`](../../services/operator/src/state/methods_chain.rs#L178):
  the replacement

**What:**
- A `NeedCatchup` outcome starts a backfill from the gossip
  `propagation_source`. That is the peer that *forwarded* the message,
  not necessarily its signer, and the request carries no
  authentication (`P2pAuth::default()`).
- The first chunk's `genesis_validators` is used to verify block 0.
- `hub.backfill` then replaces the replica wholesale, **even when the
  replica was already complete**. It never checks that the new history
  contains the current tip.
- Admission (`slot.validators`) then switches to the set derived from
  the new history.

**Impact:** a mesh peer can mint a chain under its own keys, have it
adopted, and take over the victim's chain view and gossip admission.
Real validators' traffic is rejected afterwards, so the victim is cut
off from the real chain.

**Preconditions:** the attacker is a gossip mesh peer. Mesh
membership is not the same as being a validator.

**Fix:**
- Pin the genesis block hash in config, compared during the ceremony,
  and pin the genesis set.
- Never accept the genesis set from a peer.
- Require backfilled history to contain the current tip at its
  height.
- Only backfill a replica that is actually incomplete.
- Fetch from the validator that signed the envelope, not from the
  relaying peer.

### CC-06 — HIGH: non-deterministic certificates fork honest replicas

**Where:**
- [`types.rs:137`](../../crates/chain/src/types.rs#L137): `block_hash`
  covers the signatures and the median time
- [`sync.rs:514`](../../crates/chain/src/sync.rs#L514)

**What:**
- Each hub commits as soon as *its* collected votes reach quorum,
  using exactly the votes it has received.
- With n ≥ 4 the quorum is smaller than n, so two honest hubs can
  commit the same proposal with different signer subsets and
  different medians.
- That produces different block hashes. Each hub rejects the other's
  certified block as a fork (`ForkRejected`), and the next proposal's
  `prev_block_hash` divides the fleet.

**Impact:** a permanent split with no Byzantine node involved. This is
latent because nothing votes yet (CC-04). Sorting signatures by
validator does not help, because the subsets differ.

**Fix:** block identity must exclude the certificate. Hash the header
content, and carry block H's signatures inside block H+1 (as
Tendermint does with its last-commit record). Combine this with
CC-02's signed vote times.

### CC-07 — HIGH: the default fleet has no fault tolerance

**Where:** [`consensus.rs:59`](../../crates/chain/src/consensus.rs#L59)

**What:** the quorum is ⌊2n/3⌋ + 1. For n = 3 that is 3 of 3, and for
n ≤ 2 it is n. The documented default fleet has 3 operators.

**Impact:** once voting exists, any single operator being offline
halts the chain.

**Fix:** document 4 validators as the minimum that tolerates one
failure (n = 3f + 1). Have `doctor` and the genesis ceremony warn when
n < 4.

### CC-08 — MEDIUM: blocks can be mutated without changing their hash

**Where:**
- [`merkle.rs:100`](../../crates/chain/src/merkle.rs#L100): an odd
  node is paired with itself
- [`ledger.rs:544`](../../crates/chain/src/ledger.rs#L544): nonces are
  checked only against committed state

**What:**
- In `[x1 … xm]` with m odd and m ≥ 3, the last node is hashed with a
  copy of itself. So appending a copy of `xm` gives the same root. The
  same holds for suffix duplication at higher levels.
- `check_block` checks each transaction's nonce against the
  *committed* table only. Two transactions with the same client and
  nonce in one block both pass.
- So a block with a duplicated tail can keep both `tx_root` and
  `state_root` unchanged, keeping the same block hash and valid
  signatures, and it passes `check_block`.

This is the same class of bug as Bitcoin's CVE-2012-2459.

**Impact:**
- Two different blocks share one hash.
- A replica that accepts the mutated copy gains extra leaves in its
  cumulative state. It then rejects every later honest proposal
  (`InvalidStateRoot`) and stalls.
- A mutated block file on disk also passes `open()`.

This is latent today because production blocks carry one transaction,
and a single-leaf root is the leaf itself.

**Fix:**
- Use RFC 6962 tree construction: split at the largest power of two
  and promote the odd node without duplicating it.
- Commit the leaf count in the header.
- Reject duplicate transactions and track nonces within a block.

### CC-09 — MEDIUM: one validator can exhaust the proposal cap

**Where:** [`sync.rs:460`](../../crates/chain/src/sync.rs#L460)

**What:** the cap of 16 proposals per height and 256 in total is
shared by all validators. One validator can fill the next height with
16 distinct valid proposals, and every honest proposal is then
refused with "capacity reached".

**Fix:** allow one proposal per proposer per height. Treat a second
proposal from the same proposer at the same height as evidence of
equivocation.

### CC-10 — MEDIUM: anchors are not private by default

**Where:**
- [`anchor.rs:121`](../../apps/cli/src/commands/anchor.rs#L121)
- [`types.rs:206`](../../crates/chain/src/types.rs#L206)

**What:** v1 transactions are the default. They put the salt,
snapshot ID and vault ID on-chain in plaintext, so the "opaque
commitment" is not opaque. Every anchor from a vault is linked by its
vault ID, and the snapshot IDs are public. The CLI also prints the
salt.

**Fix:** make v2 the default once CC-01 and CC-03 make v2 anchors
verifiable.

### CC-11 — MEDIUM: ledger files are written non-atomically

**Where:**
- [`ledger.rs:654`](../../crates/chain/src/ledger.rs#L654)
- `tip.json` and `genesis_validators.json` writes in `ledger.rs`

**What:** blocks are written with a plain `fs::write`: no temp file,
no fsync, no rename. A crash mid-write leaves truncated JSON, `open()`
then fails to parse it, and the replica cannot start.

**Fix:** write to a temp file, fsync, rename, then fsync the
directory. Alternatively move the ledger into SQLite, which the
project already uses.

### CC-12 — MEDIUM: the genesis trust anchor is not pinned

**Where:**
- [`ledger.rs:186`](../../crates/chain/src/ledger.rs#L186)
- [`light_client.rs:57`](../../crates/chain/src/light_client.rs#L57)

**What:**
- `open()` prefers `genesis_validators.json` on disk over the set the
  caller passes in.
- No genesis block hash is pinned anywhere in the code, even though
  the ceremony runbook asks participants to compare it out of band.
- `advance_to_rotation` switches the trusted set without verifying
  the rotation block's signatures. The doc comment asks callers to
  verify first.

**Fix:**
- Pin the genesis hash and fail when the on-disk genesis or its set
  disagrees with it.
- Make `advance_to_rotation` verify the header's quorum under the
  current set itself.

### CC-13 — MEDIUM: rotation is unbounded

**Where:** [`ledger.rs:647`](../../crates/chain/src/ledger.rs#L647)

**What:** a quorum can replace the whole validator set, or shrink it
to a single key, in one block, effective at the next height. There is
no minimum size, no cap on how much changes per step, and no delay.

**Fix:**
- Enforce a minimum size (4).
- Cap how much of the set can change per rotation (for example, less
  than a third).
- Add an activation delay of a few blocks, so watchers and light
  clients can see and contest a rotation before it takes effect.

### CC-14 — LOW: scalability

**What:**
- `commit_block_internal` clones the cumulative commitment list and
  rebuilds the whole state tree on every commit
  ([`ledger.rs:616`](../../crates/chain/src/ledger.rs#L616)).
- All blocks are held in memory, and `block_at_height` is a linear
  search.
- `VoteCollector.certified` is never pruned and is scanned on every
  vote ([`sync.rs:219`](../../crates/chain/src/sync.rs#L219)).
- `open()` replays and re-verifies the chain from genesis on every
  start.

**Fix:**
- Append to the tree incrementally.
- Index blocks by height.
- Prune `certified` the way `proposals` is already pruned.
- Store periodic signed checkpoints so startup can resume from one.

### CC-15 — LOW: gossip signatures cover re-serialized JSON

**Where:** [`sync.rs:109`](../../crates/chain/src/sync.rs#L109)

**What:** envelope signatures are checked against `serde_json` output
re-encoded from the parsed message, not against the bytes received.
This is correct only while serialization stays deterministic across
versions.

**Fix:** sign canonical CBOR, which `crates/format` already provides,
or sign and verify the exact received bytes.

### CC-16 — LOW: evidence of conflicting votes is ephemeral

**Where:** [`sync.rs:247`](../../crates/chain/src/sync.rs#L247)

**What:** evidence is kept in memory, capped at 256 entries, and
leads to nothing: it is not persisted, not published, does not
exclude the validator, and raises no operator alert.

**Fix:** persist the evidence, which is two signed headers. Expose it
in the explorer. Optionally add an evidence transaction type that
feeds rotation.

### CC-17 — LOW: validator keys are raw seed files

**Where:** [`consensus.rs:195`](../../crates/chain/src/consensus.rs#L195)

**What:** keys are 32-byte seed files with owner-only permissions:
unencrypted and with no hardware option. The seed is read into a
plain `Vec` that is not zeroized. The YubiKey PIV path already exists
for snapshot signing but is not offered for chain keys.

**Fix:** support PIV or TPM for validator and device chain keys, and
zeroize the seed buffer.

### CC-18 — LOW: proof position fields are unauthenticated

**Where:** [`merkle.rs:47`](../../crates/chain/src/merkle.rs#L47)

**What:**
- `InclusionProof.verify` ignores `leaf_index` and `total_leaves`. The
  left/right direction of each step comes from the proof, not from
  the index.
- `AnchorProofResponse.tx_index` is never checked.
- The tree's doc comment claims RFC 6962, but the tree duplicates odd
  nodes (CC-08).

**Fix:**
- Derive each step's direction from `leaf_index` and `total_leaves`.
- Check the proof length against the tree size.
- Check `tx_index`.
- Correct the comment.

### CC-19 — LOW: dead client code and a silent fallback

**What:**
- `SovereignAnchorClient`
  ([`storage/src/chain.rs:82`](../../crates/storage/src/chain.rs#L82))
  calls `/v1/chain/commitments` and `/v1/chain/proofs/{commitment}`.
  No operator serves either endpoint, and nothing in the workspace
  calls the client.
- If it had been wired up as written, CC-01 and CC-02 would have been
  remotely exploitable by any operator. Both are now fixed in the
  light client it uses, but the endpoints still don't exist.
- Separately, `cmd_anchor` falls back to a zero vault ID without
  warning (`unwrap_or([0u8; 32])`,
  [`anchor.rs:85`](../../apps/cli/src/commands/anchor.rs#L85)).

**Fix:** delete the client or rebuild it on the fixed light client.
Fail when the vault ID cannot be read.

## Missing tests

Tests for every fixed finding now exist (listed under
[Fixed since the review](#fixed-since-the-review)). Each remaining test
would confirm, and then guard, an open finding:

- **CC-06:** four hubs receiving votes in different orders must commit
  identical block hashes.

## Docs that overclaim

All of these were corrected after the review:

- **Root [`README.md`](../../README.md):**
  - "Immutable Ledger Proofs" and "Byzantine fault tolerant quorum
    signatures" are replaced by a description of what verifies and what
    a solo anchor proves.
  - The architecture diagram no longer says "Immutable" or "BFT".
  - The Project Status table now has a CipherChain row.
- **[`SYSTEM_WORKFLOW.md`](../SYSTEM_WORKFLOW.md):**
  - No more "deterministic finality".
  - Workflow 3 states that operators don't vote yet, so fleet anchors
    stay `PROPOSED`.
  - The block-time note says only v1 and v4+ times are signed.
- **[`CURRENT_SECURITY_GUARANTEES.md`](../CURRENT_SECURITY_GUARANTEES.md):**
  a new CipherChain anchoring section states the current guarantees and
  limits.
- **CLI output in `anchor.rs`:** "Deterministic Sovereign Finality" is
  replaced by a `Trust:` line ("solo chain signed by this device…").
  The `verify-anchor` claims "IMMUTABLY ANCHORED" and "Cryptographic
  Checkpoint Verified" were removed with the CC-03 fix.
- **This engagement pack ([`README.md`](./README.md)):** §3 now has a
  **C9** row for the chain protocol.

## Strategic decision

Voting is not implemented yet (CC-04), so this is the cheapest point
to choose what CipherChain should be.

**Option A: finish BFT consensus.** This needs:

- vote casting with a one-vote-per-height rule
- deterministic proposer rotation and view change (ADR-013)
- certificate-independent block identity (CC-06)
- signed vote times (CC-02)
- a client transaction submission path, so vault devices are not
  validators (CC-04)
- at least 4 validators (CC-07)

It is a large, safety-critical piece of work.

**Option B: a witnessed transparency log (recommended).** Re-scope
CipherChain as an append-only Merkle log of commitments, in the style
of RFC 9162 / Certificate Transparency, Sigstore Rekor and the Go
checksum database:

- **Log.** Operators append client-signed commitments to an RFC 6962
  tree.
- **Signed tree heads.** Operators periodically sign `(size, root,
  time)`.
- **Inclusion and consistency proofs.** Anyone can verify that a
  commitment is in the log, and that a later tree head extends an
  earlier one without rewriting it. The existing `state_root`
  accumulator becomes this log. No verifier uses it today.
- **Witness cosigning.** Independent witnesses, which can be other
  operators or third parties, countersign tree heads after checking
  consistency. "N parties saw the same history" then comes from
  cosignatures, with no consensus rounds and none of their liveness
  problems.
- **Optional external timestamping.** Anchor tree heads to RFC 3161
  timestamp authorities or OpenTimestamps for time evidence a third
  party can verify, without reintroducing gas fees.

Option B delivers the guarantee anchoring exists for: tamper-evident,
append-only, time-bounded history. It reuses the existing Ed25519 and
Merkle code and avoids the consensus-safety findings (CC-06, CC-07,
CC-09, CC-13) entirely.

## Enhancement roadmap

1. **Client submission API** with per-client rate limits. Vault
   devices submit signed commitments and are never validators.
   Needed by both options.
2. **Private anchors by default** (v2), after CC-01 and CC-03.
3. **Hardware-backed validator and device chain keys** (PIV or TPM).
4. **Threshold signatures** (FROST over Ed25519, RFC 9591). One compact
   signature per tree head or block, still Ed25519-verifiable.
5. **Post-quantum readiness for long-lived evidence.** Version the
   signature scheme so hybrid Ed25519 + ML-DSA (FIPS 204) can be added
   for tree heads. SHA-256 needs no change.
6. **Transparency in the explorer.** Show validator and witness set
   history, signed tree heads, and the evidence feed for conflicting
   votes (CC-16).
7. **Assurance.**
   - Fuzz Merkle proofs, block decoding and `ChainSyncHub::ingest`.
   - Add property tests for tree append and consistency.
   - Write a TLA+ model if Option A is chosen.

## Recommended order

1. **Verification holes:** CC-01, CC-02, CC-03, CC-08 and CC-11 are
   done.
2. **Operator safety:** CC-05 and CC-09 are done.
3. **Documentation:** done (see [Docs that overclaim](#docs-that-overclaim)).
4. **Design:** decide between Option A and Option B, then implement
   CC-04 (and, if A, CC-06, CC-07 and CC-13) under the chosen design.
