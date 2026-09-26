# The CipherVault Decentralized Operator Network (DON): 2026-09-24

Current state of the operator network and how outside contributors can join
it, run nodes, and contribute. Companion to DEPLOYMENT_RUNBOOK.md (fleet
procedures) and OPERATOR_PLAYBOOKS.md (day-2 operations).

## What the network is today

Three project-run storage operators (cv-operator-1/2/3 on GCP e2-micro,
us-central1 + us-east1) serve the public TLS endpoints op1/op2/op3 at
cipherv.online, plus a dashboard/account UI at vault.cipherv.online.
Operators store **opaque ciphertext only** — chunks and manifests
addressed by content digest, authenticated end to end by client keys.
An operator cannot read file contents, vault identities, or file names;
the fleet treats every node, including its own, as untrusted by design.

Two planes exist:

- **HTTP federation (live):** object store, leases, recovery records,
  vouchers, challenges, peer directory. This is what serves users today.
- **libp2p mesh (built, tested, not enabled on the fleet):** Kademlia
  provider records, heartbeat liveness, gossip, rendezvous repair with
  deterministic single-pusher backfill, NAT traversal (AutoNAT, DCUTR,
  relay). Covered by swarm/repair/DoS/liveness suites and 10-node chaos
  gates. Fleet nodes currently boot HTTP-only, so mesh behavior is proven
  in CI, not in production.

## Trust and membership model

- **Admission is ticket-gated (permissioned).** A fleet signing key issues
  offline join invites bound to a node public key (`ciphervault invite
  issue --fleet-key-file ...`, TTL 24 h default). Anyone can run the
  software, but joining *this* fleet's routing table requires an invite
  from whoever holds the fleet key (today: the project).
- **Join is public and self-serve once invited:** `ciphervault invite join
  --ticket ... --node <own-endpoint>` presents the ticket; the fleet
  verifies the fleet signature, expiry, and key match, then admits the
  node into **probation**. Tickets are single-use (spent nonces persisted;
  grace rejoin allowed for the same admission within TTL).
- **Probation → graduation:** probation lasts 24 h by default
  (`CIPHERVAULT_PROBATION_SECS`, floor 60 s). Probationers count as
  holders and may push repairs, but repair backfills are never entrusted
  *to* them until they graduate. Graduation is automatic on proof of life
  (refresh RPC or P2P heartbeat) once time is served, or immediate via
  the admin graduate route.
- **Ongoing standing:** nodes re-present fresh descriptors
  (`join/refresh`); liveness grace is 2 h. Membership lists are
  control-plane (service-token) reads; join/refresh are public by design.
- **No incentives yet.** There is no payment, staking, or reward protocol.
  Operators contribute disk/bandwidth voluntarily (or commercially,
  out of band). Voucher quotas bound *client* writes, not operator
  compensation.

## How to run a node (contributor path)

Prerequisites: Docker, a public HTTPS endpoint (or LAN for a private mesh),
~1 GB RAM minimum (the fleet runs e2-micro), and a join ticket from the
fleet operator.

1. **Get the software.** Pull the signed release image
   `ghcr.io/samuel-1-avson/ciphervault-operator:<version>` (multi-arch
   amd64/arm64, SLSA + SBOM + keyless cosign signature) or build from
   source (`deploy/docker/Dockerfile.operator`).
2. **Generate identity.** First boot mints the Ed25519 operator key
   (persisted in the data dir); back it up — rotation is a re-announce
   ceremony (runbook §8).
3. **Start the node.** `ciphervault node setup` (guided) or compose:
   `docker compose -f deploy/docker-compose.prod.yml up -d`, then
   `ciphervault node status` / `doctor` for a plain-language report.
4. **Join the fleet.** Obtain a ticket, then
   `ciphervault invite join --ticket ticket.json --node https://<you>`.
   You enter probation; serve 24 h of uptime and you graduate
   automatically. Use `invite refresh` to keep the entry alive across
   restarts/rekeys.
5. **Operate.** Health: `/healthz`. Metrics: `/metrics`. Quarantine and
   blocklists are covered in OPERATOR_PLAYBOOKS.md §4. Upgrades: pull the
   new signed digest and recreate (the R5 script automates this for the
   project's fleet; adapt `-Nodes` for your own).

Private meshes: skip the ticket flow and mesh routing tables directly
(`ciphervault peers --mesh`), pinning `CIPHERVAULT_FLEET_KEY` to your own
fleet key. The VPC runbook (§5) covers fully private deployments.

## How else to contribute

- **Code:** client, operator, P2P mesh, dashboard, and packaging all live
  in one workspace with mirrored CI gates. High-value gaps: P2P fleet
  enablement, web release train, package-manager submissions, Windows UX
  polish.
- **Docs and verification:** the project treats "docs with proof" as the
  bar — walkthrough steps must run green, not just read well.
- **Security review:** crypto review surface is small and explicit
  (ChaCha20-Poly1305, Ed25519, X25519, Shamir sharing, FastCDC chunking);
  the threat model rewards adversarial readers.
- **Running infrastructure:** independent operators are the scarcest
  resource — the first third-party join is an explicit milestone.

## Honest limitations (2026-09-24)

1. The fleet key is project-held: membership is permissioned, not
   permissionless. Decentralization here means *no central data plane*,
   not *open validator set*.
2. The P2P mesh is dark in production; a contributor joining today gets
   HTTP federation plus tested-but-idle mesh code.
3. No operator incentives, no SLA framework, no abuse process beyond
   blocklists and quotas.
4. Fleet observability is first-party (dashboard + probes); there is no
   public status page or external monitoring yet.
