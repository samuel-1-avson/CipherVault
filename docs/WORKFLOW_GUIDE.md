# CipherVault System Workflow (v1.0.7+)

Practical guide to how the whole system runs: the decentralized operator
network, the day-to-day user flow, and how to run a node and contribute.
For the cryptographic architecture spec, see
[SYSTEM_WORKFLOW.md](./SYSTEM_WORKFLOW.md); for HTTP/P2P details, see
[API_REFERENCE.md](./API_REFERENCE.md).

---

## Part 1 — How the decentralized operator network runs

### The big picture

```text
Your machine                              Operator network (untrusted storage)
────────────────────────────              ─────────────────────────────────────
CLI / TUI / dashboard
  │ encrypt (client-side)                 ┌────────────┐  ┌────────────┐  ┌────────────┐
  │ FastCDC chunk +                       │ Operator 1 │  │ Operator 2 │  │ Operator 3 │
  │ XChaCha20-Poly1305                    │ :8201      │  │ :8202      │  │ :8203      │
  ▼                                       └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
opaque ciphertext                             │  PoS readback  │             │
chunks (by content                            │  quorum 3/3    │             │
hash, CID) ───────────────────────────────────┴────────────────┴─────────────┘
                                                        ▲
Maintenance daemon ── heartbeats, quorum audits, ───────┘
                        PoS re-checks, self-repair

Control plane (hosted): dashboard + account service ── passkeys, devices,
  revocation propagation. Never sees vault plaintext or private keys.

Optional settlement: Arbitrum L2 head-state anchors (tamper-evident history).
```

### What each piece does

- **Client (CLI/TUI/agent)** — everything secret happens here: key
  derivation, FastCDC chunking, authenticated encryption, dedup. Operators
  only ever see ciphertext addressed by SHA-256 content hash (CID).
- **Storage operators** (`ciphervault-operator`) — independent daemons
  holding opaque chunks, answering proof-of-storage (PoS) challenges, and
  storing recovery envelopes. Each has a persistent Ed25519 identity
  (`operator.key`, mode 0600) and a file-backed data dir.
- **Quorum + PoS** — every push replicates each object to 3 operators
  (default; configurable via `--replicas`). A replica counts only after a
  PoS challenge readback proves the bytes are durably stored. Unchanged
  chunks skip upload entirely (challenge proves the copy already exists).
- **Maintenance daemon** — continuously probes operator health, audits
  replica quorums, re-verifies PoS, and drives self-repair when a node
  misses chunks. No HTTP surface; internal census only.
- **P2P swarm (dual mode)** — operators can also run a libp2p swarm next
  to the HTTP API (`--enable-p2p`): Kademlia DHT peer records,
  rendezvous-based discovery, relay circuits + DCUTR hole-punching for
  NAT'd peers, gossip liveness, and a budgeted repair lane. First contact
  uses repeatable `--p2p-bootstrap` multiaddrs or a fleet-signed
  bootstrap list (`sign-bootstrap-list`).
- **Write governance** — strict deployments require challenge sessions
  plus enrolled device identities; mesh/testnet policy can additionally
  require write vouchers (`--require-write-vouchers`), with leases and
  barter quotas. See [REPAIR_PROTOCOL.md](./REPAIR_PROTOCOL.md) and
  [OPERATOR_PLAYBOOKS.md](./OPERATOR_PLAYBOOKS.md).
- **Control plane** — the hosted dashboard (public explorer) and account
  service (passkeys/MFA, device enrollment, revocation propagation) run
  as digest-pinned immutable images, promoted only through the signed
  release pipeline (`scripts/gcp/promote-immutable-web.ps1`).

### Production topology (reference)

Three geographically spread operators plus one web host (`cv-web-ui`)
serving `https://vault.cipherv.online`. Every production image is built
by the release workflow from a `v*` tag, scanned, cosign-signed, and
promoted by digest — never by mutable tag, never built on the VM.

---

## Part 2 — Day-to-day user flow

### Install (one minute)

1. Download the `ciphervault-<version>-<platform>` archive from the
   [GitHub Releases](https://github.com/samuel-1-avson/CipherVault/releases)
   page and unzip it.
2. Run `ciphervault`. With no arguments it opens the interactive terminal
   UI (TUI) instead of exiting, so double-clicking the binary just works.
3. Afterwards, `ciphervault update` checks for and installs newer signed
   releases in place.

### First vault (five minutes)

```bash
ciphervault init --operators http://op1:8201 http://op2:8202 http://op3:8203
```

- Generates the 32-byte master secret, device identity, and epoch keys.
- Prints the **paper recovery kit** — write it down. It is the only copy
  of the master secret in existence; confirmation is required to proceed.
- Scans `.gitignore` and offers to track discovered secrets.
- Run `ciphervault doctor` any time to verify keys, store, operators,
  and recovery coverage.

### Daily work — two modes

**Deliberate (git-style):**

```bash
ciphervault track .env config/credentials.json   # register secrets (auto-gitignored)
ciphervault status                               # what changed
ciphervault diff                                 # masked revision preview
ciphervault push -m "rotate DB credentials"      # chunk, encrypt, replicate (quorum 3)
ciphervault pull                                 # fetch + decrypt latest on another machine
```

**Autonomous (dropbox-style):**

```bash
ciphervault watch --sync                         # daemon: snapshot on every save
ciphervault tui                                  # live overview: files, snapshots,
                                                 # operators, FastCDC stats, token (1-6 tabs, ? help, q quit)
ciphervault ui                                   # production web dashboard (or --local inspector)
```

### Network Explorer (blockchain-style browsing)

The dashboard's public **Explorer** tab works like a chain explorer:
search a 64-hex object CID to see its PoS-proven replicas, sizes, and
quorum badge; search a `0x` receipt hash to inspect an anchor; search an
operator id to jump to its telemetry. Overview cards show reachable
operators and the anchor head. Two read-only APIs back it
(`GET /api/explorer/overview`, `GET /api/explorer/object/:cid`); object
bytes are never fetched — possession is proven by PoS challenge, and
vault identities, files, and snapshots stay private by design.

### Recovery and safety nets

- **New machine:** install the binary, then
  `ciphervault recover --kit printed_kit.txt --to ./restored/` — no
  account, no password, no coordinator needed.
- **Rotation:** `ciphervault rekey` starts a new epoch; old chunks stay
  readable, new writes use the new key.
- **Teams:** `auth` (account login), `device list|revoke`, and guardian
  ceremonies (`recovery`) share recovery power without sharing secrets.
- **Auditability:** `ciphervault anchor` commits head state to Arbitrum;
  `ciphervault verify-anchor` re-checks it. `audit` and `repair` inspect
  and heal replica health.

---

## Part 3 — Run a node and contribute to the network

Anyone can run an operator: you store only opaque ciphertext, never
plaintext, and the fleet treats your node as untrusted by design.

### Option A — single node from the release binary (fastest)

```bash
ciphervault-operator --port 8101 --data-dir ./operator-data --operator-id my-node
curl http://localhost:8101/healthz   # {"status":"ready",...}
```

- First boot generates the persistent Ed25519 identity
  (`operator-data/operator.key`, 0600). Back it up: it is your node's
  long-term identity.
- `--print-identity` shows your registry entry without binding; publish
  it so clients can pin you via trusted identities.
- `--rotate-key` retires a compromised key to a timestamped backup.

### Option B — local 3-node cluster with Docker

```bash
docker compose up -d        # operators on 127.0.0.1:8201-8203 + maintenance
docker compose ps           # all healthy? then:
powershell -ExecutionPolicy Bypass -File scripts/verify-cluster.ps1
```

This mirrors the production quorum on your machine. Point a CLI at it
with `ciphervault init --operators http://127.0.0.1:8201 ...`.

### Option C — join the P2P mesh (dual mode)

```bash
ciphervault-operator --port 8101 --data-dir ./operator-data \
  --operator-id my-node --enable-p2p \
  --p2p-tcp-port 9101 --p2p-quic-port 9102 \
  --p2p-bootstrap /dns4/<seed>/tcp/9101/p2p/<peer-id> \
  --p2p-advertise-addr /dns4/<your-host>/tcp/9101
```

- Your node registers rendezvous records, answers DHT lookups, relays
  hole-punched traffic (with `--p2p-relay-server` on dedicated seeds),
  and serves the budgeted repair lane.
- Fleet deployments should use a signed bootstrap list instead of bare
  multiaddrs: `--p2p-bootstrap-list fleet.json --p2p-bootstrap-signer
  <hex-fleet-key>` (generate with `sign-bootstrap-list`).

### Hardening a public node

- Set `CIPHERVAULT_OPERATOR_STRICT_AUTH=true` and a 32-byte hex
  `CIPHERVAULT_OPERATOR_SERVICE_TOKEN` from your secret manager (never
  commit it); enroll client device keys via `POST /v1/identities`.
- Keep the data volume backed up; chunk storage is content-addressed,
  so rsync-style copies are safe while the node is stopped.
- Watch `/healthz` (readiness) and the maintenance census; rotate keys
  with `--rotate-key` and re-publish your identity afterward.
- Resource profile: idle nodes are tiny (HTTP + SQLite-scale state);
  budget disk for the ciphertext you volunteer and bandwidth for PoS +
  repair traffic. Mesh economics (vouchers/leases) are defined in
  [DON_ECONOMICS_DECISION.md](./DON_ECONOMICS_DECISION.md).

### Contributing beyond storage

- Run the maintenance daemon against the fleet to donate audit/repair
  capacity, run a relay/rendezvous seed (`--p2p-relay-server`,
  `--p2p-rendezvous-server`) to donate connectivity, or open PRs against
  this repo — CI enforces fmt, strict clippy, and the full test suite.
