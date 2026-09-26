# Mainnet Promotion Evidence (Blocker 5)

**Status:** `BLOCKED — EXTERNAL DEPENDENCY` (entry gates red). No mainnet
transaction has been sent; anchoring remains on Arbitrum Sepolia
(chain 421614). This file records gate status and the preparation
completed — it is not a promotion record.

## Entry-gate status (`docs/MAINNET_ANCHOR_PROMOTION.md`)

| Gate | Status | Evidence / blocker |
|---|---|---|
| 1. External audit of anchor path, findings closed | RED | Blocker 1 `BLOCKED — EXTERNAL AUDIT PENDING` |
| 2. Live soak vs fleet, CI release timings | RED | Soak procedure exists (Track 3); no passing soak record at promotion rev |
| 3. Key ceremonies recorded (deployer/payer custody, publisher rotation drilled) | AMBER | Publisher rotation drilled 2026-09-26 (`docs/KEY_ROTATION_DRILLS.md`); deployer/payer custody ceremony not yet recorded |
| 4. Feed freshly reissued (< 7 days) | NOT STARTED | Must be done at promotion time |

Promotion is therefore NOT authorized. Per the plan, `TESTNET → MAINNET`
must be a deliberate controlled promotion (fresh deployer, Sourcify
verification, node-by-node rewire, canary ceremony, 24 h finality watch),
never an env-only flip. The full step list and rollback (keep Sepolia
registry + RPC for 30 days) stand as written in the promotion plan.

## Preparation completed this session

- Anchor path re-verified unchanged: immutable constructor-free
  `CipherVaultRegistry` (same bytecode deploys anywhere), `chain_id`
  plumbed end to end (CLI, dashboard, feed).
- Publisher rotation — a promotion prerequisite — executed and evidenced.
- Release authenticity upgraded (Blocker 4), so the promoted binaries
  will be signature-verified installs.
- This gate table: the honest, checkable record of what remains.

## Required evidence to close (to be appended here at promotion)

Promotion checklist with sign-offs; ceremony record; deploy tx hash +
block; new registry address; chain id 42161 everywhere; funding record;
per-node rewire confirmations (`/healthz` + chain id); canary publish +
`verify-anchor` bound receipt; feed `publisher_signed` on mainnet head;
24 h finality watch (no `reorg_suspected`, canary ok); monitoring +
rollback references. Only then does this file (and Blocker 5) flip to
`VERIFIED`.
