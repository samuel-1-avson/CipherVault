# CipherVault Operator Playbooks

For humans running `ciphervault-operator`. Companion to
`docs/DEPLOYMENT_RUNBOOK.md` (provisioning) and `docs/API_REFERENCE.md`.

## 1. Restart

`systemctl restart ciphervault-operator` (or restart the container).
What resets:

- **Voucher spend ledger**: persisted (`voucher-ledger.json`, atomic +
  fsync, ADR-007). Spend survives restarts — post-restart quota reuse
  is NOT expected. If vouchers re-spend after a restart, look for a
  corrupt-ledger backup (`voucher-ledger.corrupt-*` in the data dir)
  and the `operator voucher ledger ... is corrupt` stderr line; the
  node starts empty in that case and vouchers re-pin terms on next use.
- **Repair budget** (memory-only token bucket): refills to full
  (8 MiB burst). No action needed — rate limiters reset by design.
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
`voucher-ledger.json`, routing/approval/checkpoint stores,
`operator.key`, `swarm.key`. Secret stores are 0600 on unix —
preserve modes on restore (`cp -a` / `rsync -p`). Never copy a live
dir without stopping the node first; per-file atomics do not make a
directory snapshot crash-consistent. `voucher-ledger.corrupt-*` files
are forensic copies of unparseable ledgers: archive them with the
backup, do not restore them over the live file.

## 7. Rotate keys

Epoch (vault data) keys:

```sh
ciphervault rekey --check                # report ages (warn past --warn-days, default 90)
ciphervault rekey                        # mint epoch N+1 for new snapshots
```

Old epoch keys are retained so existing snapshots stay readable.
Pre-migration keys report unknown age: rotate once to baseline.
(Runbook R13. Device-key rotation stays manual: new device
certificate ceremony.)

Operator signing keys: stop the node, then boot once with the flag:

```sh
ciphervault-operator --rotate-key --data-dir <dir> [other flags...]
```

The old `operator.key` moves to
`operator.key.previous-<UTC timestamp>` and a fresh key is generated;
the node serves the new identity immediately. Then re-mesh routing
(§2), update any pinned fleet keys (`CIPHERVAULT_TRUSTED_PEER_KEYS`),
and re-issue vouchers — grants under the old issuer key fail closed
(403 issuer mismatch), and old-key leases no longer renew. Verify the
live identity offline any time (binds nothing, exit 0):

```sh
ciphervault-operator --print-identity --operator-id <id> --data-dir <dir>
# <id>=<64-hex pk>
```

TOTP/account keys follow the Secret Manager cutover in runbook R3;
apply the same record-old / cut-over / verify / delete-old discipline
to operator keys.

## 8. Recover a vault on a clean machine

Prepare before disaster:

```sh
ciphervault recovery export                  # view/print the offline kit
ciphervault recovery split -t 2 -s 3 -o ./guardians
ciphervault recovery test --kit <kit> --to <isolated-dir>
```

Restore on the bare machine (reads need no session — ADR-006 — so
only the paper kit is required):

```sh
ciphervault recover --kit <kit> --to <dir>
# or: ciphervault recover --shares g1.txt g2.txt --to <dir>
```

Team restores add `--require-approval`: the command prints an
`EmergencyRecovery` challenge ID (600 s TTL) and broadcasts it to the
federation; a guardian signs with
`ciphervault approve sign <challenge-id> --name <lead>` (see
`ciphervault approve list` / `ciphervault approve status <id>`), and
the restore proceeds once accepted.

## 9. Incident response

- Panic contained: a 500 `{"code":500,"error":"INTERNAL_PANIC_CAUGHT"}`
  (operator) or `"code":"INTERNAL_PANIC_CAUGHT"` (account) means one
  request panicked and was contained — the process stays up. Capture
  the stderr backtrace, file it with route + build version; no restart
  needed for availability.
- Lock poison recovered: `operator lock <name> poisoned; recovering
  ...` (operator) or `account database lock poisoned; ...` (account)
  on stderr follows a contained panic; service continues from
  pre-panic state. Investigate the first panic, not the recovery line.
- 429 flood on writes: voucher quotas exhausting (mesh policy) or the
  repair budget tripping (backfill/storm). Check
  `ciphervault_swarm_repair_bytes_total` against the 8 MiB/s budget
  before touching quotas; do not raise limits mid-backfill.
- Suspected voucher leak: vouchers are Bearer [REDACTED] expiry with no
  revocation list — keep TTLs short (default 3600 s). A leaked voucher
  authorizes up to its quota until expiry; let it expire, then
  re-issue tighter. Restart does NOT clear spend (the ledger is
  durable, §1).
- Bad web deploy: promotion probes (`/api/context` version,
  `/api/operators`, `/api/explorer/overview`) roll back automatically
  on mismatch. For a manual deploy, re-run promotion with the recorded
  rollback digests (runbook R4) and confirm the live `/api/context`
  `build_version`.
- Compromised node: quarantine (§4), rotate its operator key (§7),
  re-mesh (§2); treat its old-key leases and vouchers as untrusted
  until re-issued under the new key.

## 10. Admit a community operator (verified join)

Anyone with spare disk and bandwidth can run a node; the fleet admits
them by ticket, not by token handoff (ADR-008). Prerequisites on every
fleet node: `CIPHERVAULT_FLEET_KEY` pinned to the fleet public key (hex).
Without the pin, `/v1/peers/join` fails closed (403) and static fleets
are unaffected.

Joiner (on the new machine):

```sh
ciphervault-operator --operator-id <id> --data-dir ./operator-data \
  --port 8301 --enable-p2p --p2p-bootstrap <fleet-bootstrap-addr> &
ciphervault-operator --print-identity --operator-id <id> \
  --data-dir ./operator-data
# <id>=<64-hex node pk>  -> send the pk to a fleet admin
```

Admin (fully offline; the seed never leaves this machine):

```sh
ciphervault invite issue <node-pk> --ttl 86400 \
  --fleet-key-file /secure/fleet.seed > ticket.json
# hand ticket.json to the joiner out of band
```

Joiner (present the ticket to each fleet node):

```sh
ciphervault invite join ticket.json --node http://127.0.0.1:8301 \
  --via https://fleet-node-1:8201 https://fleet-node-2:8201
# status "probation": admitted, repair replicas withheld for now
```

Probation and graduation:

- Probationers count as holders and may push repair, but are never
  chosen as repair recipients. Standing is per node: check it with
  `GET /v1/peers/membership` (service token).
- Graduation needs time served (`CIPHERVAULT_PROBATION_SECS`, default
  24 h) plus recent liveness: P2P heartbeats count automatically in
  dual mode; HTTP-only joiners re-run `ciphervault invite refresh
  --node ... --via ...` periodically (cron-worthy) until graduated.
- After graduation, promote the node to a full mesh citizen: add its
  key to `CIPHERVAULT_TRUSTED_PEER_KEYS` where the allowlist is used
  and include its endpoint in `ciphervault peers --mesh`.
- Shortcuts: a service-token announce of the joiner's descriptor, or
  `POST /v1/peers/<id>/graduate`, confers full standing immediately.

Failure hints: 403 = bad/expired ticket or key mismatch (re-issue);
409 = ticket already spent (each ticket admits once — issue a fresh
one); 404 on refresh = routing entry expired before the first refresh
(re-join with a new ticket, then refresh on a schedule).
