# CipherVault Public Testnet

**Status:** DRAFT — opens after CI green on tip + genesis tag (see §6).
**Mode at genesis:** static HTTP + verified community join.
P2P mesh seeds come later (fleet runs HTTP-only today).

---

## 1. Fleet endpoints (genesis set)

| Node | Client endpoint | Operator |
|---|---|---|
| `cv-operator-1` | `https://vault.cipherv.online/op/1` | CipherVault team (Iowa, `us-central1-a`) |
| `cv-operator-2` | `https://vault.cipherv.online/op/2` | CipherVault team (Iowa, `us-central1-b`) |
| `cv-operator-3` | `https://vault.cipherv.online/op/3` | CipherVault team (S. Carolina, `us-east1-b`) |

- Client quickstart:
  `ciphervault init --operators https://vault.cipherv.online/op/1 https://vault.cipherv.online/op/2 https://vault.cipherv.online/op/3`
- Dashboard / explorer: `https://vault.cipherv.online`
  (object CIDs, anchor receipts, operator telemetry — vault data stays private).
- Genesis build: workspace `v1.0.7-beta.7` (exact commit + image digests
  recorded in the genesis tag annotation).

## 2. Join as an operator

Anyone can join; the fleet treats your node as untrusted by design.
Full ceremony: operator playbook §10 (`docs/OPERATOR_PLAYBOOKS.md`)
and [WORKFLOW_GUIDE §Part 3](./WORKFLOW_GUIDE.md).

1. Install the release binary, then print your identity:
   `ciphervault-operator --print-identity --operator-id <id> --data-dir ./operator-data`
2. Send your 64-hex node public key to a fleet admin; receive
   `ticket.json` out of band.
3. Present it (no service token needed):
   `ciphervault invite join ticket.json --node http://127.0.0.1:8101 --via <fleet endpoints>`
4. You land in **probation**: you store data, but new replicas go only to
   graduated members. Graduation needs 24h of fleet-visible life + recent
   liveness (`ciphervault invite refresh …` periodically until P2P
   heartbeats count automatically). If your entry lapses (>24h without
   refresh), rejoin with your ORIGINAL ticket — no admin round-trip
   needed while it is valid (ask the admin for 7-day tickets).
5. Harden: `CIPHERVAULT_OPERATOR_STRICT_AUTH=true`, a 32-byte service
   token from your own secret manager, enrolled client device keys, and
   backups of the data dir + `operator.key`.

Scale cap at genesis: **10–25 community nodes**. Tickets are rate-limited
by admin availability — this is intentional while restart behavior (§5)
is under observation. Ticket SLA: TBD — the fleet admin commits to a
turnaround here before genesis (testnet target: first response
within 48 h).

## 3. P2P mesh (not at genesis)

The fleet VMs run HTTP-only (no `--enable-p2p` in the deploy templates).
Until a P2P fleet rollout lands, there are **no seed multiaddrs and no
signed bootstrap list to publish**. Community nodes may still run
`--enable-p2p` among themselves with mutual `--p2p-bootstrap` addrs;
fleet-anchored rendezvous/relay comes in a later rollout.

## 4. Wipe-and-rebootstrap note (testnet reset path)

Testnet state is disposable. Full reset, fleet-admin side:

1. Stop all three VMs' stacks; wipe each data dir
   (`operator-data/`, incl. `operator.key` only if the fleet identity
   itself rotates — otherwise keep keys and wipe data).
2. Re-provision from the pinned genesis images
   (`scripts/gcp/deploy-operators.ps1`), re-pin `CIPHERVAULT_FLEET_KEY`
   from Secret Manager on every node.
3. Re-mesh routing tables (playbook §2), re-run `scripts/verify-cluster.ps1`
   equivalents against the live endpoints.
4. Community nodes: wipe data dir, request a fresh ticket, rejoin (old
   tickets die with the fleet seed if it rotates).

Client-side: testnet vaults are throwaway — `init` fresh against the new
genesis; never point a vault holding real secrets at the testnet.

## 5. Known issues at genesis

- **Quorum writes can fail during single-node restarts.** The fleet is 3
  nodes; a restart narrows quorum. Retry after the node returns; if you run
  maintenance, tell the admin channel first.
- **File-backed object store** (redb decided, migration pending). Fine at
  testnet scale; do not benchmark capacity against it.
- **Manual promotion** — releases reach the fleet via the verified
  promotion script, run by a human. Expect hours, not minutes, for fleet
  upgrades.
- **Self-audited crypto** — no external audit or pen test yet. Testnet
  data must be worthless-by-assumption.
- **Economics deferred** — barter/permissioned fleet; no staking, payouts,
  or dispute loop on testnet.

## 6. Genesis checklist (all must hold before announcing)

- [ ] CI green on tip (ubuntu + macOS + Windows).
- [ ] Genesis tag pushed (annotated: commit, image digests, fleet seed id).
- [ ] External join rehearsal passed from a non-fleet machine, rehearsal
      node graduated, then killed to observe probation/repair under churn.
- [ ] Fleet seed backed up outside Secret Manager (testnet trust root).
- [ ] This file updated: status OPEN, real image digests, rehearsal date.
