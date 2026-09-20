# External Rehearsal Proof — Live Fleet Join + Seed Rotation

**Date:** 2026-09-20 ~20:30–20:45 UTC
**Fleet:** cv-operator-1 (us-central1-a), cv-operator-2 (us-central1-b), cv-operator-3 (us-east1-b)
**Gateway:** https://vault.cipherv.online (/op/1, /op/2, /op/3)
**Rehearsal node:** `rehearsal` = `32c31e25…707509`, local port 8104, data dir `C:\Users\samue\cv-rehearse`
**Result: PASS** — live join, probation, refresh, standing, and single-admission all proven against the production fleet.

No secrets in this file: only the fleet *public* key fingerprint and node pubkeys appear. The seed
(`$HOME\fleet.seed`) and ticket (`$HOME\rehearsal-ticket.json`) stay on the admin workstation + KeePass.

## 1. Fleet seed rotation (lost-seed recovery)

Old fleet key `5f0e49e5…` was pinned on all 3 VMs but the seed was lost, so no new tickets could be
issued. Recovery: generated a fresh 32-byte seed locally, derived its pubkey offline, and rolled it
across the fleet one node at a time (rolling restart, each node verified `ready` before the next).

- New fleet pubkey pinned: `d65367650242f352f35c6844ef1bfcc71d4889bfcb0a4c43731b6932b1eac528`
- op-1: container recreated, `/healthz` → `ready`, key confirmed via container env — OK
- op-2: same — OK
- op-3: same — OK (note: op-3 lives in **us-east1-b**, not us-central1-c as assumed)
- Rotation was secret-safe: the operator service token was read into a remote shell variable and
  never printed; strict-auth mode preserved on all nodes.

## 2. Ticket issuance (offline, 7-day TTL)

```powershell
ciphervault invite issue 32c31e25f7eddae10fde760a16479d45129ef1d909447cc031f70e65ba707509 `
  --ttl 604800 --fleet-key-file "$HOME\fleet.seed" > "$HOME\rehearsal-ticket.json"
```

Gotcha hit: PowerShell `>` writes UTF-16LE (bytes `FF FE 7B 00`), which the CLI rejects with
`Error: read ticket file …`. Fixed by transcoding to UTF-8 no-BOM; join then succeeded.
Recommendation: document `--out` file flag or UTF-8 note in the playbook (open).

## 3. Live join — admitted 3/3 into probation

```powershell
ciphervault invite join "$HOME\rehearsal-ticket.json" --node http://127.0.0.1:8104 `
  --via https://vault.cipherv.online/op/1 https://vault.cipherv.online/op/2 https://vault.cipherv.online/op/3
```

Output:

```text
✓ rehearsal admitted by https://vault.cipherv.online/op/1 (probation of 1 peers)
✓ rehearsal admitted by https://vault.cipherv.online/op/2 (probation of 1 peers)
✓ rehearsal admitted by https://vault.cipherv.online/op/3 (probation of 1 peers)
```

## 4. Liveness refresh — accepted 3/3

```powershell
ciphervault invite refresh --node http://127.0.0.1:8104 --via <op/1 op/2 op/3>
```

```text
✓ rehearsal refreshed by https://vault.cipherv.online/op/1 (probation)
✓ rehearsal refreshed by https://vault.cipherv.online/op/2 (probation)
✓ rehearsal refreshed by https://vault.cipherv.online/op/3 (probation)
```

## 5. Standing (B1 plain-language view)

```powershell
ciphervault node standing --data-dir C:\Users\samue\cv-rehearse
```

```text
Fleet standing for "rehearsal" (public fleet):
  https://vault.cipherv.online/op/1: in probation (stores data; full trust after a day of uptime)
  https://vault.cipherv.online/op/2: in probation (stores data; full trust after a day of uptime)
  https://vault.cipherv.online/op/3: in probation (stores data; full trust after a day of uptime)
```

Note: fleet-side `/v1/peers` requires the operator service token (401 without it, even on VM
localhost) — standing was verified from the node side, which reports each fleet node's signed answer.

## 6. Single-admission enforcement (negative test)

Re-presenting the same ticket while the admission is active is correctly rejected:

```text
ticket already spent (each ticket admits once) — ask your fleet admin for a fresh ticket
```

This is consistent with B2: the *grace* path (re-present the original ticket) applies after a lapse
(>24h without refresh), not while admitted.

## 7. Not proven tonight (time-bound)

- **Graduation** (probation → full after ~24h fleet-visible life + liveness). The clock started at
  join (~20:42 UTC 2026-09-20). Requires the rehearsal node to stay up and a `refresh` at least
  every 24h; earliest graduation check ~20:45 UTC 2026-09-21.
- **Grace rejoin after lapse** with the original ticket (needs a >24h lapse to test; would delay
  graduation — test on a second rehearsal identity instead).

## 8. Operator follow-ups

1. Back up `$HOME\fleet.seed` into KeePass (you already saved `rehearsal-ticket.json` — same treatment).
2. Keep the rehearsal node running (PID 26364, port 8104) and refresh at least daily until graduation:
   `ciphervault invite refresh --node http://127.0.0.1:8104 --via https://vault.cipherv.online/op/1 https://vault.cipherv.online/op/2 https://vault.cipherv.online/op/3`
3. Check graduation tomorrow: `ciphervault node standing --data-dir C:\Users\samue\cv-rehearse`
4. ~~Playbook fix: warn that PowerShell `>` emits UTF-16; prefer an `--out` flag or transcode step.~~
   DONE 2026-09-20: `invite issue --out` writes UTF-8 directly (playbook §10 updated to bless it),
   and ticket/keys-file reads now accept BOM-marked UTF-16, proven live against op/1 (reached the
   fleet 403 path instead of failing local decode).
