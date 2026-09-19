# CipherVault Operator Playbooks

For humans running `ciphervault-operator`. Companion to
`docs/DEPLOYMENT_RUNBOOK.md` (provisioning) and `docs/API_REFERENCE.md`.

## 1. Restart

`systemctl restart ciphervault-operator` (or restart the container).
What resets:

- **Voucher spend ledger** (memory-only): every voucher may be
  re-spent up to its quota after the restart. Bounded (≤1 quota per
  boot), requires restart access, and vouchers are opt-in
  (`--require-write-vouchers`, default off). No action needed; do not
  treat post-restart quota reuse as an attack signal.
- **Repair budget** (memory-only token bucket): refills to full
  (8 MiB burst). No action needed.
- **Sessions/challenges/identities/routing/approvals/checkpoints**:
  persisted (fsync + atomic rename, secret stores 0600); they survive.

Verify: `curl $OP/healthz` → `{"status":"ready",...}`, then
`ciphervault doctor` from a linked workstation.

## 2. Mesh the routing tables

New or replaced nodes must be announced to every peer, or heartbeats
from unknown senders are ignored and repair cannot push:

```sh
ciphervault peers --mesh
```

This fetches each operator's public `/v1/peers/self` descriptor
(fresh same-second signature) and POSTs it to every other node's
`/v1/peers/announce`. Re-run after any membership change.

## 3. Issue a write voucher

```sh
export CIPHERVAULT_OPERATOR_SERVICE_TOKEN=<token from the vault>
ciphervault voucher issue <64-hex holder pk> <quota-bytes> --ttl 3600 \
  --operator https://op1:8201
```

Output is the signed JSON voucher; hand it to the holder out of band.
Vouchers are Bearer [REDACTED] (ADR-002): possession authorizes up to the
quota until expiry.

## 4. Quarantine a misbehaving peer

1. Add its PeerId to `blocked_peers` (boot config) and restart, or call
   `block_peer` on a live node: refused dials, bootstrap/mDNS skip,
   live-drop of existing connections.
2. Confirm `is_blocked` and watch
   `ciphervault_swarm_repair_bytes_total` for the drop.
3. `unblock_peer` to release. libp2p-swarm 0.48 has no `ban_peer_id`,
   so this is our own layer — verify drops in metrics, not in
   connection state alone.

## 5. Run the chaos gates (Phase 4 exit)

```sh
bash scripts/drill/chaos-10node.sh        # ~10 min, needs docker
```

Boots 10 nodes, meshes routing, then Gate A (kill 3/10 mid-write →
full recovery), Gate B (45 s partition-heal → reconverge), Gate C
(repair bytes under cap, zero 429s at defaults). PASS requires all
three; `--keep` leaves containers for forensics. The Phase 4 gate is
three consecutive green runs.

## 6. Back up / restore the data dir

Back up the whole `--data-dir`: `objects/`, `leases/`, `recovery/`,
`sessions.json`, `challenges.json`, `identities.json`,
routing/approval/checkpoint stores, `operator.key`, `swarm.key`.
Secret stores are 0600 on unix — preserve modes on restore
(`cp -a` / `rsync -p`). Never copy a live dir without stopping the
node first; per-file atomics do not make a directory snapshot
crash-consistent.
