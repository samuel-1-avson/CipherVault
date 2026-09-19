# NAT Hole-Punch Drill (DON Phase 2)

How to prove two operators behind separate NATs find each other and exchange
data: the automated regression harness, a manual two-host drill, and the
containerized chaos drill used as the Phase 2 exit gate.

## Background: the NAT ladder

1. **First contact** — the joiner dials a seed from its signed bootstrap
   list (`--p2p-bootstrap-list` + `--p2p-bootstrap-signer`), or discovers
   seeds via rendezvous (`ciphervault/1` namespace).
2. **Relayed fallback** — if the peer is unreachable directly, both sides
   reserve a circuit on a relay (`--p2p-relay-server` seed) and talk over
   `/p2p-circuit`. Always works; costs relay bandwidth.
3. **DCUtR upgrade** — either side coordinates a direct hole-punch; on
   success the relayed connection is replaced by a direct one.
4. **AutoNAT confirmation** — each node learns whether its listen address is
   publicly dialable, which feeds rendezvous advertisement and relay need.

Static HTTP mode is unaffected by all of this: the drill runs with
`--enable-p2p` dual mode, and rollback is removing the P2P flags.

## 1. Automated harness (regression)

```powershell
cargo test -p ciphervault-operator --locked --test nat
```

Three tests, all on loopback with ephemeral ports (`services/operator/tests/nat.rs`):

| Test | Proves |
|---|---|
| `rpc_flows_over_relayed_circuit` | Reservation + circuit dial + operator RPC through the relay (DCUtR pinned off, so bytes provably traverse the circuit) |
| `dcutr_upgrades_relayed_connection` | DCUtR coordination fires and the upgrade outcome is observed |
| `autonat_confirms_loopback_reachability` | AutoNAT v2 dial-back confirms reachability |

Caveat (also stated in the harness header): loopback cannot simulate a real
NAT — everything is directly dialable. The harness exercises every protocol
message of the ladder; drills 2 and 3 below prove it across real network
boundaries. Set `CIPHERVAULT_SWARM_DEBUG=1` for swarm event lines
(`swarm: connected to …`, `swarm: dcutr upgrade to …`,
`swarm: external address confirmed: …`, `swarm: autonat probe of …`).

## 2. Manual two-host drill

Prerequisites: a reachable seed host `S`, two joiner hosts `A` and `B` on
different networks (each NATted is the point; same-LAN works as a smoke
test but proves less).

On `S` — seed with relay + rendezvous servers, fixed P2P ports:

```sh
ciphervault-operator --operator-id seed-1 --data-dir ./seed-data \
  --port 8201 --enable-p2p --p2p-tcp-port 9101 --p2p-quic-port 9102 \
  --p2p-relay-server --p2p-rendezvous-server \
  --p2p-advertise-addr /dns/seed.example/tcp/9101
```

Note the printed `P2P Peer ID`. Fleet ops signs the first-contact list:

```sh
ciphervault-operator sign-bootstrap-list --key-file ./fleet.seed \
  "/dns/seed.example/tcp/9101/p2p/<seed-peer-id>" > bootstrap.json
```

Distribute `bootstrap.json` plus the fleet public key to `A` and `B` (any
trusted channel — the signature, not the channel, carries trust).

On `A` and `B`:

```sh
ciphervault-operator --operator-id op-a --data-dir ./op-data \
  --port 8201 --enable-p2p \
  --p2p-bootstrap-list ./bootstrap.json \
  --p2p-bootstrap-signer <fleet-pk-hex>
```

Expected evidence (with `CIPHERVAULT_SWARM_DEBUG=1`):

- Both joiners log `swarm: connected to <seed-peer-id>`.
- Each joiner reserves a relay circuit (relay `NewListenAddr` with a
  `/p2p-circuit` suffix in `P2P Listening`, or `swarm: relay client event`).
- Joiners discover each other via rendezvous and attempt DCUtR:
  `swarm: dcutr upgrade to <peer>: Ok(())` on success.
- At least one side logs `swarm: external address confirmed: …` (the
  publicly dialable side; the NATted side stays relay-reachable, which is
  the correct outcome, not a failure).

Drill **fails** if either joiner cannot reach the other even via relay
(check relay reservation first), or if a joiner boots from a tampered
`bootstrap.json` (it must refuse — see `services/operator/tests/bootstrap.rs`).

## 3. Containerized chaos drill (Phase 2 exit gate)

One command on any docker host (first run compiles the release image, so
allow ~15 min):

```sh
bash scripts/drill/nat-holepunch.sh [--keep]
```

The script builds `ciphervault-operator:drill` from
`deploy/docker/Dockerfile.operator`, creates isolated `op-net-a`/`op-net-b`
bridge networks, boots a relay+rendezvous seed on both, boots operator B
with a relay reservation, boots operator A against B's circuit address with
a probe, and asserts every pass criterion below. Exit 0 prints `DRILL
PASS`; any failure prints `DRILL FAIL: <step>` plus the last 30 log lines.
`--keep` leaves containers and networks behind for debugging (default:
clean up). Its orchestration logic (log polling/parsing, both failure
branches) is verified without a daemon via a fake-`docker` shim; the only
unverified-on-this-machine parts are engine behaviors (build on Linux,
bridge isolation, embedded DNS).

What the script proves, in order:

1. **Isolation first** — from inside A, the seed's HTTP answers and B's
   container IP does not (`curl -m 5` must fail). An unisolated drill
   fails immediately: it would prove nothing about the relay path.
2. **Relayed RPC gate** — A's log shows `P2P probe <b-peer>: OK
   operator=drill-b`, and the seed logged `ReservationReqAccepted` for B.
3. **DCUtR observation** — an upgrade is attempted when a relayed path
   exists; success depends on NAT behavior (Docker masquerade usually
   permits it, a symmetric NAT may not). Recorded, not gated.
4. **Seed kill** — after `docker kill drill-seed`, both operators keep
   serving static HTTP (in-flight P2P RPCs error, never hang past the 30 s
   RPC timeout).

The script uses two diagnostics flags (covered by
`services/operator/tests/drill_flags.rs`):

- `--p2p-relay-reserve <peer-qualified relay addr>`: dial the relay if
  needed, reserve a circuit, print `P2P relay circuit: <addr>`. The relay
  server only serves HOP once it knows an external address — via
  `--p2p-advertise-addr` or AutoNAT confirmation (`StatusChanged { Enable }`
  in debug logs).
- `--p2p-probe-peer <peer-id>`: wait for a connection, run a GetInfo RPC,
  print `P2P probe <peer>: OK operator=<id>`.

This drill becomes the Phase 5 chaos-net template: add latency/loss with
`tc`, kill -9 operators, and assert repair without client involvement.

## 4. Execution evidence (2026-09-18)

No container runtime exists on the dev machine (no Docker/Podman/WSL
daemon), so the containerized run is pending a docker host. What WAS
executed: the exact drill above as **three separate OS processes** (real
daemon binary, separate data dirs/ports, loopback). Observed transcript:

- Seed: `P2P Peer ID: 12D3KooWKjoM…` + `StatusChanged { status: Enable }`
  (via `--p2p-advertise-addr`) + `ReservationReqAccepted` for B.
- B: `P2P relay circuit: /ip4/127.0.0.1/tcp/19301/p2p/<seed>/p2p-circuit/p2p/<b>`.
- A: `P2P probe <b-peer>: OK operator=drill-b`.

This proves the drill mechanics end to end (reserve → circuit dial →
operator RPC across processes). It does NOT prove relay exclusivity on its
own: loopback/LAN runs also form direct connections (mDNS is on in the
daemon), and several `connected to` lines appeared. Exclusivity — bytes
provably traversing the circuit with no direct path — is proven at the
protocol level by `rpc_flows_over_relayed_circuit` (DCUtR pinned off).
The containerized run will compose both: the isolation probe plus this
same transcript.

Docker-host readiness verified without a daemon: the Dockerfile's exact
build command (`cargo build --release --locked --bin ciphervault-operator`)
exits 0 and the release artifact carries the drill flags; the drill
script is `bash -n` clean, LF-only, and passes a fake-`docker` shim in all
three modes (pass exit 0, missing-probe and broken-isolation exit 1 with
the right `DRILL FAIL` line).

## Rollback

Every drill step is additive to static mode. To roll back: restart operators
without `--enable-p2p` (and ignore the P2P flags/files). No data migration,
no `vault.db` changes, no contract changes — the static suite
(`cargo test --workspace --locked`, clippy, `forge test`) stays green
throughout.
