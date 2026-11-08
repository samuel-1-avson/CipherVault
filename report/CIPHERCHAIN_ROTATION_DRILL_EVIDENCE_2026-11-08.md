# CipherChain Genesis Ceremony & Validator Rotation Drill Evidence

**Date:** 2026-11-08  
**Workstream:** P6 — Sovereign Chain Hardening  
**Target:** Sovereign CipherChain PoA Ledger (`crates/chain`, `services/operator`, `apps/cli`)  
**Commit/Version:** `v1.0.29`  
**Verdict: P6 DRILL PASS**

---

## 1. Executive Summary

As part of the final sovereign chain hardening workstream (P6), full-spectrum drill testing was conducted across the genesis ceremony, multi-party device key signing, validator set rotation, partition/quorum rollback, and peer catch-up backfill over libp2p.

All required suites passed with zero failures:
1. **Genesis Ceremony Suite (`apps/cli::commands::genesis`):** 4/4 passed.
2. **Sovereign Chain Integration Suite (`crates/chain::tests::sovereign_tests`):** 5/5 passed.
3. **Sovereign Consensus Unit Suite (`crates/chain::sync` & `merkle`):** 18/18 passed.
4. **Operator Chain Publication Suite (`services/operator::chain_publish`):** 2/2 passed.
5. **Operator Swarm Propagation & Backfill (`services/operator::swarm_chain`):** 4/4 passed.

Total: **33 sovereign chain tests passing cleanly.**

---

## 2. Genesis Ceremony Verification

Tested via `apps/cli/src/commands/genesis.rs`:

* **Proposal Determinism (`test_propose_is_deterministic_and_sorted`):**
  * Multiple executions with inverted validator key orders produce byte-for-byte identical `genesis_proposal.json`.
  * Public keys are sorted ascending in lexicographical order; member at index 0 is designated as block proposer.
* **Input Sanitization (`test_parse_pubkey_list_rejects_garbage`):**
  * Rejects non-hex characters, truncated keys (<32 bytes), and empty inputs.
  * Collapses redundant duplicate keys into a single entry.
* **Device-Key Authentication & Membership Refusal (`test_sign_uses_device_key_and_enforces_membership`):**
  * Signing automatically binds to the local operator's hardware/OS device key (`~/.ciphervault/device.key`).
  * If a proposal does not list the local node's public key as an authorized validator, signing **fails closed with a membership refusal error**.
* **Quorum Threshold Enforcement (`test_assemble_combines_quorum_and_persists`):**
  * Assembly with $N=3$ requires $Q=3$.
  * Tested sub-quorum attempt with 2 valid signatures: Assembly **fails and rejects genesis creation**.
  * Provision of the 3rd valid signature completes quorum; block `000000000000.json` and `genesis_validators.json` are committed to disk.

---

## 3. Validator Set Rotation Drill

Tested via `crates/chain/src/sync.rs`:

* **Live 3-Node Rotation (`test_rotation_applies_on_commit_and_rekeys_voting`):**
  * A 3-node validator cluster (Set A) proposes a Version 3 block containing `next_validators: Some(Set B)`.
  * Set A reaches quorum consensus, signs, and commits the rotation block at height $H=1$.
  * At the exact commit boundary, `ledger.validator_set()` transitions to Set B.
  * Subsequent block proposals at height $H=2$ require signatures from Set B. Any signature from deprecated Set A members is rejected as invalid/foreign.
* **Reopen Persistence (`test_reopen_lands_on_rotated_set`):**
  * Node restart after rotation reads block history and initializes with Set B active from genesis.
* **Malformed & Hostile Rotation Rejection (`test_rotation_rejects_malformed_payloads`):**
  * Proposals with empty rotation lists fail with `ChainError::InvalidRotation`.
  * Attempts to smuggle rotation payloads into pre-v3 headers fail.
  * Conflicting certified blocks at the same height are detected and rejected as forks (`test_conflicting_certified_block_is_rejected_as_fork`).

---

## 4. Replication, Gossip & Catch-Up Backfill

Tested via `services/operator/tests/swarm_chain.rs` and `services/operator/tests/chain_publish.rs`:

* **HTTP Publication & Hub Replica Sync (`publish_certified_tip_commits_then_duplicates`):**
  * Valid envelopes posted to `/v1/chain/publish` commit immediately to the local hub replica.
  * Duplicate submissions are safely de-duplicated without re-execution.
  * Tampered headers and uncertified proposals are rejected with HTTP 400 (`publish_rejects_tampered_and_foreign_envelopes`).
* **Swarm Gossip Propagation (`chain_envelope_propagates_and_admits`):**
  * Certified blocks broadcast across libp2p Gossipsub mesh are received and validated by connected operators.
  * Forged signatures from non-member keys trigger Byzantine penalties and immediate drop (`chain_forgeries_rejected_and_disabled_ignored`).
  * Oversized payload attacks are rejected at the transport boundary (`chain_oversize_publish_rejected`).
* **Lagging Replica Backfill (`chain_backfill_brings_lagging_node_to_tip`):**
  * A lagging node (height 0) receiving a certified block at tip (height $N$) triggers the `GetChainBlocks` RPC.
  * Successfully downloads, verifies, and backfills 256-block chunks backwards to genesis, restoring synchronization without operator intervention.

---

## 5. Artifacts & Reference

* Genesis Runbook: [`docs/GENESIS_CEREMONY_RUNBOOK.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/docs/GENESIS_CEREMONY_RUNBOOK.md)
* Architectural Model: [`report/CIPHERVAULT_SOVEREIGN_CHAIN_ARCHITECTURE.html`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/report/CIPHERVAULT_SOVEREIGN_CHAIN_ARCHITECTURE.html)
* Audit Analysis: [`report/CIPHERVAULT_SOVEREIGN_CHAIN_AUDIT_2026-11-07.md`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/report/CIPHERVAULT_SOVEREIGN_CHAIN_AUDIT_2026-11-07.md)

**Exit Criteria Met:** All P6 requirements satisfied. Ready to archive obsolete EVM components and proceed to external review.
