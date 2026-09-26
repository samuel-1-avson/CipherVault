# Mainnet Anchor Promotion Plan (Track 6)

Promoting checkpoint anchoring from Arbitrum Sepolia (chain 421614,
current) to Arbitrum One (chain 42161). This is a plan, not an
execution: deployment needs the payer-held key ceremony and the gates
below. No mainnet transaction has been sent.

## Current state (verified)

- Registry `CipherVaultRegistry.sol` is immutable and constructor-free:
  the same bytecode deploys anywhere; only the address changes.
- Sepolia anchor live and verified (registry + feed canary ok).
- CLI, dashboard, and feed already carry `chain_id` end to end; no
  code changes are expected for the new chain id.

## Entry gates (all must be green)

1. External audit of the anchor path (registry + `chain.rs` verify +
   feed sign/verify) complete with findings closed.
2. Live soak passed against the fleet (Track 3 procedure), release
   timings from CI.
3. Key ceremonies recorded: deployer/payer custody (Track 4), feed
   publisher rotation drilled.
4. Feed freshly reissued (< 7 days) so the promotion starts from a
   known-good signed head.

## Promotion steps

1. Fund a FRESH deployer address on Arbitrum One with a small balance
   (deployment only; it holds no other role afterward).
2. `forge script script/DeployRegistry.s.sol --broadcast` against
   Arbitrum One from the contracts dir; record the address, tx, and
   block. Verify source on Sourcify.
3. Rewire fleet env (`CIPHERVAULT_ARBITRUM_RPC_URL`,
   `ARBITRUM_CHAIN_ID=42161`, `ARBITRUM_CONTRACT_ADDRESS=<new>`) and
   dashboard collectors; promote node by node (R5 script), confirming
   each node reports chain id 42161 and `/healthz` stays green.
4. Run one full anchor ceremony on mainnet: publish a canary
   commitment, record with `anchor --tx-hash`, confirm
   `verify-anchor` reports bound receipt + inclusion, and the feed
   carries it with `publisher_signed`.
5. Watch finality for 24 h: receipts advancing, no `reorg_suspected`,
   canary `ok`. Only then announce.

## Rollback

Keep the Sepolia registry address, feed history, and one Sepolia RPC
endpoint recorded for 30 days. Rollback = rewire env back to Sepolia
values, re-promote, re-verify; the immutable Sepolia registry is
never deleted. No client data migrates: anchors are append-only
commitments, and old evidence stays verifiable against its own chain.

## Risks

- Wrong-chain wiring (testnet address on mainnet RPC or vice versa):
  the CLI errors on chain-id/contract mismatch fail closed; the
  ceremony step catches the rest.
- Payer key exposure: payer-held, small balance, never in CI/chat.
- L1-settlement language: dashboard labels stay L2-honest
  (`L2Confirmed`/`DeeplyConfirmed`) on both chains.
