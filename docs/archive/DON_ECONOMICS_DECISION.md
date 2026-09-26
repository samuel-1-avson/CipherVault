# DON Economics Decision Packet (D3)

Decision required before Phase 5 (contract escrow work). Transport, DHT,
repair, and authorization work proceeds identically under either option.

## Option A — Barter / permissioned fleet first (recommended)

- Operators join by allow-list or off-chain stake attestation; no on-chain
  payments. Storage is mutual: run a node, use the mesh.
- Abuse control is technical, not economic: capability vouchers, per-key
  quotas, rate limits, block-lists (all planned in Phase 3 regardless).
- Gas costs: zero. Operational cost: bootstrap/rendezvous nodes plus
  dashboards, same as today.
- Downgrade path: none needed — this is the starting state.
- Limitation: no permissionless open enrollment and no paid durability tiers
  until Option B (or a subset) lands.

## Option B — Staking plus lease escrow on Arbitrum One

Mechanism sketch (each bullet is a design deliverable, not a claim):

1. **Registry**: `registerOperator` bonds collateral; unbonding delay exceeds
   the challenge window. Payer of registration gas: the operator.
2. **Batch anchoring**: an elected batcher aggregates snapshot commitments into
   one Merkle root per epoch. Payer of batch gas: TBD — options are protocol
   subsidy, batcher rotation with fee capture, or client-paid inclusion fees.
   The packet MUST name the payer before implementation.
3. **Challenges**: any watcher may open a PoS challenge against an operator by
   posting a bond. Operator responds with a proof within N blocks.
4. **Adjudication**: successful defense returns both bonds; failed/missed
   defense slashes operator collateral, pays the watcher from the slash, and
   records a reputation strike.
5. **Griefing analysis required**: false-challenge cost to the attacker versus
   defense cost to the operator; challenge rate limits per operator per epoch;
   appeal path for liveness failures (operator online but censored).

## Recommendation

Ship Option A for the first public testnet. It needs no audit, no token
decisions, and no gas sponsorship, and every Phase 3 abuse control transfers
unchanged to Option B later. Revisit Option B only with a named gas payer, a
completed griefing analysis, and an external audit gate.

## Decision record

- [x] D3 decided: **Option A — barter / permissioned fleet first**, 2026-09-18 (pre-Phase 3 D3/D4 review).
- Voucher issuer model follows: each operator self-issues vouchers against its own disk quota; no fleet authority. Option B revisit criteria unchanged (named gas payer, griefing analysis, external audit).
